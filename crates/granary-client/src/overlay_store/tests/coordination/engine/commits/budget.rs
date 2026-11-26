// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::retained_submission::{self as retained, Phase, Submission};

mod outage_window;

#[derive(Default)]
struct CeilingDelay(Vec<Duration>);
impl RecoveryDelay for CeilingDelay {
    fn jitter(&mut self, ceiling: Duration) -> Duration {
        ceiling
    }
    fn wait(&mut self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.0.push(duration);
        Box::pin(async {})
    }
}

#[expect(
    clippy::used_underscore_binding,
    reason = "the fixture retains its control root for the engine lifetime; evidence reads use that exact root"
)]
fn paths(f: &Fixture) -> (std::path::PathBuf, std::path::PathBuf) {
    let local = f.store.lock().unwrap();
    let scope = local.snapshot().scope.digest().unwrap();
    let volume = local.snapshot().volume.as_str();
    (
        f._scratch
            .0
            .join("overlay")
            .join(&scope)
            .join(volume)
            .join("journal"),
        f._scratch
            .0
            .join("publications")
            .join(scope)
            .join(format!("{volume}.sub")),
    )
}

#[expect(
    clippy::disallowed_methods,
    reason = "test evidence reads the exact durable retained record in the owned fixture"
)]
pub(super) fn saved(f: &Fixture) -> Submission {
    retained::decode(&std::fs::read(paths(f).1).unwrap()).unwrap()
}

fn journal(f: &Fixture) -> codec::JournalScan {
    codec::scan_journal(&f.io.bytes(&paths(f).0)).unwrap()
}

pub(super) fn publication_hex(publication: [u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(32);
    for byte in publication {
        write!(encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn outcome(result: &crate::PublicationResult) -> String {
    match &result.outcome {
        PublicationOutcome::Landed(_) => "Landed".to_owned(),
        other => format!("{other:?}"),
    }
}

pub(super) async fn drive(
    f: &Fixture,
    lane: &crate::RetainedCommit,
    delay: &mut (dyn RecoveryDelay + Send),
) -> crate::PublicationResult {
    Box::pin(f.engine.drive_commit(
        lane,
        &mut Entropy(80),
        delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await
    .unwrap()
}

#[tokio::test]
async fn live_commit_future_stays_small_on_worker_stack() {
    let fixture = Fixture::new().await;
    let future = Arc::clone(&fixture.engine).drive_live(SyncOptions::default(), Entropy(90));
    let live = std::mem::size_of_val(&future);
    drop(future);

    let engine = Arc::clone(&fixture.engine);
    let task = async move {
        let end = engine
            .clone()
            .drive_live(SyncOptions::default(), Entropy(91))
            .await;
        engine.report_live_end(end);
    };
    let task = std::mem::size_of_val(&task);

    fixture.create("file", b"retained");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let mut secure = Entropy(80);
    let mut delay = Delay;
    let future = fixture.engine.drive_commit(
        &lane,
        &mut secure,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    );
    let commit = std::mem::size_of_val(&future);
    assert_eq!(
        (live <= 4_096, task <= 4_096, commit <= 12_288),
        (true, true, true),
        "worker-stack futures: live={live}, task={task}, commit={commit}"
    );
}

async fn drive_unavailable_window_then_healthy(unavailable: usize) {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    // The lane must outlive the simulated outage as well as each drive's bound.
    let lane = f
        .engine
        .construct_commit(
            SyncOptions {
                resolution_bound: Duration::from_mins(30),
                ..SyncOptions::default()
            },
            &mut Entropy(70),
        )
        .await
        .unwrap();
    let record = saved(&f);
    {
        let mut plan = f.remote.publication_plan.lock().unwrap();
        plan.extend(std::iter::repeat_n(PublishPlan::Unavailable, unavailable));
        plan.push_back(PublishPlan::Land);
    }

    let mut result = drive(&f, &lane, &mut Delay).await;
    for exemption in 1..=unavailable {
        if result.outcome != PublicationOutcome::Pending
            || f.store.lock().unwrap().sync_admission_open().is_err()
        {
            break;
        }
        assert_eq!(usize::from(saved(&f).unavailable_exemptions), exemption);
        advance_outage(Duration::from_mins(1)).await;
        result = drive(&f, &lane, &mut Delay).await;
    }
    let candidate = record.candidates.first().unwrap();
    let (sends, exact_sends) = {
        let sends = f.remote.publication_sends.lock().unwrap();
        (
            sends.len(),
            sends.iter().all(|bytes| bytes == &candidate.root),
        )
    };
    let exact_stored_root =
        f.remote.published.lock().unwrap().get(&candidate.seq) == Some(&candidate.root);
    assert_eq!(
        (
            outcome(&result),
            sends,
            f.store
                .lock()
                .unwrap()
                .sync_admission_open()
                .map_err(|e| e.to_string()),
            exact_sends,
            exact_stored_root,
            matches!(&result.outcome, PublicationOutcome::Landed(done) if done.root == candidate.root),
        ),
        (
            "Landed".to_owned(),
            unavailable + 1,
            Ok(true),
            true,
            true,
            true
        ),
        "(outcome, physical sends, admission open, exact sends, exact stored root, exact landed root)"
    );
    assert_file(&f, &candidate.root, "dirty", b"uncommitted");
}

pub(super) async fn advance_outage(duration: Duration) {
    tokio::time::pause();
    tokio::time::advance(duration).await;
    tokio::time::resume();
}

#[tokio::test]
async fn commit_short_unavailable_windows_land_the_same_candidate() {
    for unavailable in [1, 3, 7] {
        drive_unavailable_window_then_healthy(unavailable).await;
    }
}

#[tokio::test]
async fn commit_live_loop_survives_an_intake_window_of_eight_503s() {
    drive_unavailable_window_then_healthy(8).await;
}

#[tokio::test]
async fn commit_unavailable_window_longer_than_budget_then_healthy() {
    drive_unavailable_window_then_healthy(9).await;
}

#[tokio::test]
async fn commit_unavailable_window_of_twenty_503s_then_healthy() {
    drive_unavailable_window_then_healthy(20).await;
}

#[tokio::test]
async fn commit_outage_window_gates_repeated_published_fsync_and_shutdown_takeover() {
    let f = Fixture::new().await;
    let stage = f.create("dirty", b"uncommitted");
    let options = SyncOptions::default();
    let lane = f
        .engine
        .construct_commit(
            super::published::bounded(Duration::from_mins(2)),
            &mut Entropy(70),
        )
        .await
        .unwrap();
    *f.content.jitter_word.lock().unwrap() = Some(u64::MAX);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 2]);
    let first = drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (first.outcome, saved(&f).unavailable_exemptions),
        (PublicationOutcome::Pending, 1)
    );
    let generation = saved(&f).generation;
    let probes = f.remote.probes.load(Ordering::Relaxed);
    advance_outage(Duration::from_secs(20)).await;
    for seed in [90, 100, 110] {
        let result = super::published::published(&f, SyncTarget::Stage(stage), seed, options).await;
        assert_eq!(
            (
                result.as_ref().err().map(ToString::to_string),
                f.remote.publication_sends.lock().unwrap().len(),
                saved(&f).generation,
                f.remote.probes.load(Ordering::Relaxed)
            ),
            (
                Some("intent refused: SyncCommitUnresolved".into()),
                1,
                generation,
                probes
            ),
            "published fsync inside the poll interval"
        );
    }
    advance_outage(Duration::from_secs(40)).await;
    let second = drive(&f, &lane.clone(), &mut Delay).await;
    assert_eq!(
        (
            second.outcome,
            saved(&f).unavailable_exemptions,
            f.engine.commit_retry_reasons()
        ),
        (
            PublicationOutcome::Pending,
            2,
            vec![crate::RetryReason::Unavailable]
        ),
        "the upper-end poll and its physical retry"
    );
    f.store.lock().unwrap().close_mutations();
    let record = saved(&f);
    for since_last_poll in [Duration::ZERO, Duration::from_secs(61)] {
        advance_outage(since_last_poll).await;
        let started = TokioSyncRuntime.now();
        let deadline = started + Duration::from_secs(1);
        let shutdown = f
            .engine
            .take_over(
                SyncOptions {
                    deadline: Some(deadline),
                    ..options
                },
                deadline,
                crate::sync::CommitDrive::Mount(RecoveryIntent::ExplicitRecovery),
                &mut Entropy(120),
            )
            .await;
        assert_eq!(
            (
                shutdown.as_ref().err().map(crate::sync::failure_class),
                TokioSyncRuntime.now() < deadline,
                f.remote.publication_sends.lock().unwrap().len(),
                journal(&f).state.commit_progress(&record.publication_id)
            ),
            (
                Some(crate::FailureClass::Unavailable),
                true,
                2,
                Some(codec::CommitProgress {
                    attempts: 2,
                    fenced: false
                })
            ),
            "shutdown's retained-lane step after advancing {since_last_poll:?}: {shutdown:?}"
        );
    }
}

#[tokio::test]
async fn commit_outage_window_expires_across_takeover_and_reaches_charged_fence() {
    let f = Fixture::new().await;
    let options = super::published::bounded(Duration::from_mins(40));
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 17]);
    for _ in 0..8 {
        let result = drive(&f, &lane, &mut Delay).await;
        assert_eq!(result.outcome, PublicationOutcome::Pending);
        advance_outage(Duration::from_mins(1)).await;
    }
    advance_outage(Duration::from_mins(23)).await;
    let mut delay = CeilingDelay::default();
    let result = drive(&f, &lane.clone(), &mut delay).await;
    let record = saved(&f);
    assert_eq!(
        (
            outcome(&result),
            record.unavailable_exemptions,
            f.remote.publication_sends.lock().unwrap().len(),
            delay.0.len(),
            journal(&f).state.commit_progress(&record.publication_id)
        ),
        (
            "Exhausted".to_owned(),
            8,
            16,
            7,
            Some(codec::CommitProgress {
                attempts: 16,
                fenced: true
            })
        ),
        "expiry checked on the cloned lane after eight exempt sends"
    );
}

#[tokio::test]
async fn commit_unavailable_answer_past_window_closure_is_charged() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(
            super::published::bounded(Duration::from_mins(40)),
            &mut Entropy(70),
        )
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Unavailable);
    assert_eq!(
        drive(&f, &lane, &mut Delay).await.outcome,
        PublicationOutcome::Pending
    );
    advance_outage(Duration::from_mins(30)).await;
    {
        let mut plan = f.remote.publication_plan.lock().unwrap();
        plan.push_back(PublishPlan::UnavailableAfterDelay(Duration::from_secs(90)));
        plan.extend([PublishPlan::Unavailable; 7]);
    }
    let dispatch = Arc::new(Notify::new());
    let signal = dispatch.clone();
    *f.remote.publication_observer.lock().unwrap() = Some(Box::new(move || signal.notify_one()));
    let mut delay = Delay;
    let mut secure = Entropy(80);
    let mut driving = Box::pin(f.engine.drive_commit(
        &lane,
        &mut secure,
        &mut delay,
        RecoveryIntent::Continue,
        super::published::bounded(Duration::from_mins(3)),
    ));
    let mut dispatched = Box::pin(dispatch.notified());
    std::future::poll_fn(|cx| {
        assert!(
            driving.as_mut().poll(cx).is_pending(),
            "send finished before its delayed answer"
        );
        dispatched.as_mut().poll(cx)
    })
    .await;
    advance_outage(Duration::from_secs(91)).await;
    let result = driving.await.unwrap();
    assert_eq!(
        (
            outcome(&result),
            saved(&f).unavailable_exemptions,
            f.remote.publication_sends.lock().unwrap().len()
        ),
        ("Exhausted".to_owned(), 1, 9),
        "the dispatch began inside the window and its checked answer arrived outside it"
    );
}

#[tokio::test]
async fn commit_outage_exemption_cap_survives_reopening_the_lane() {
    let f = Fixture::new().await;
    let options = SyncOptions::default();
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    let mut record = saved(&f);
    // Model 63 durable exempt answers from previous processes, then send the
    // last eligible request through the real driver before reopening.
    {
        let mut local = f.store.lock().unwrap();
        local
            .overlay_transaction(|t| {
                for attempt in 1..=63 {
                    t.record_commit_attempt(lane.boundary_seq(), record.publication_id, attempt)?;
                    record.candidates[0].evidence.start().unwrap();
                    record.candidates[0]
                        .evidence
                        .answer(attempt, false, false)
                        .unwrap();
                }
                Ok(())
            })
            .unwrap();
        let generation = record.generation;
        record.generation += 1;
        record.unavailable_exemptions = 63;
        local
            .publication_transaction(|j| j.replace(generation, &record))
            .unwrap();
    }
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 9]);
    let result = drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (result.outcome, saved(&f).unavailable_exemptions),
        (PublicationOutcome::Pending, 64)
    );
    let f = f.restart().await;
    let lane = f.engine.recover_commit(options).unwrap();
    let mut delay = CeilingDelay::default();
    let result = drive(&f, &lane, &mut delay).await;
    assert_eq!(
        (
            outcome(&result),
            saved(&f).unavailable_exemptions,
            f.remote.publication_sends.lock().unwrap().len(),
            delay.0.len(),
            journal(&f).state.commit_progress(&record.publication_id)
        ),
        (
            "Exhausted".to_owned(),
            64,
            9,
            7,
            Some(codec::CommitProgress {
                attempts: 72,
                fenced: true
            })
        ),
        "reopening grants a fresh window but the 65th 503 is charged"
    );
    let next = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        options,
    ))
    .await;
    assert!(
        matches!(next, Err(CoordinationError::CommitFenced { publication }) if publication == record.publication_id),
        "a capped answer must not arm a poll that hides the fence: {next:?}"
    );
}

#[tokio::test]
async fn commit_unavailable_without_an_answer_save_stays_charged() {
    let f = Fixture::new().await;
    let options = super::published::bounded(Duration::from_mins(2));
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 2]);
    assert_eq!(
        drive(&f, &lane, &mut Delay).await.outcome,
        PublicationOutcome::Pending
    );
    advance_outage(Duration::from_mins(1)).await;
    let local = Arc::downgrade(&f.store);
    *f.remote.publication_observer.lock().unwrap() = Some(Box::new(move || {
        local
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .fail_publication_file_sync_for_test(true);
    }));
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        options,
    ))
    .await;
    let f = f.restart().await;
    let record = saved(&f);
    assert_eq!(
        (
            result.is_err(),
            f.remote.publication_sends.lock().unwrap().len(),
            record.phase,
            record.last_response,
            record.unavailable_exemptions,
            journal(&f).state.commit_progress(&record.publication_id)
        ),
        (
            true,
            2,
            Phase::AwaitingAnswer {
                candidate: 1,
                attempt: 2
            },
            None,
            1,
            Some(codec::CommitProgress {
                attempts: 2,
                fenced: false
            })
        ),
        "fault after the physical send and before its exemption can persist: {result:?}"
    );
}

#[cfg(feature = "publish-restart-tests")]
#[tokio::test]
async fn commit_unavailable_poll_is_armed_when_the_drive_errors_after_answer_save() {
    let f = Fixture::new().await;
    let options = SyncOptions::default();
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 2]);

    crate::publish_restart::fail_once_for_test("answer-save", "after");
    let first = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        options,
    ))
    .await;
    let record = saved(&f);
    assert_eq!(
        (
            first.as_ref().err().is_some_and(|error| error
                .to_string()
                .contains("restart rendezvous injected failure")),
            record.unavailable_exemptions,
            record
                .last_response
                .as_ref()
                .map(|answer| (answer.status, answer.token.as_slice())),
            f.remote.publication_sends.lock().unwrap().len(),
        ),
        (true, 1, Some((503, b"unavailable".as_slice())), 1),
        "drive failed after saving an exempt answer: {first:?}"
    );

    let second = drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            second.outcome,
            f.remote.publication_sends.lock().unwrap().len(),
        ),
        (PublicationOutcome::Pending, 1),
        "an error after the answer save must still gate the next send"
    );
}

#[tokio::test]
async fn commit_outage_attempt_frame_capacity_refuses_without_a_send_or_fence() {
    let f = Fixture::new().await;
    let options = super::published::bounded(Duration::from_mins(20));
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 9]);
    for _ in 0..8 {
        assert_eq!(
            drive(&f, &lane, &mut Delay).await.outcome,
            PublicationOutcome::Pending
        );
        advance_outage(Duration::from_mins(1)).await;
    }
    {
        let mut local = f.store.lock().unwrap();
        let summary = local.overlay_transaction(|t| Ok(t.summary())).unwrap();
        local.cap_for_test(summary.charged_bytes + summary.reserved_bytes + summary.captured_bytes);
    }
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        options,
    ))
    .await;
    let error = result.as_ref().err();
    let record = saved(&f);
    let scan = journal(&f);
    assert_eq!(
        (
            error.map(crate::sync::failure_class),
            error.is_some_and(|e| e.to_string().contains("overlay cap exhausted (ENOSPC)")),
            f.remote.publication_sends.lock().unwrap().len(),
            record.unavailable_exemptions,
            scan.state.commit_progress(&record.publication_id),
            scan.state.open_boundaries().collect::<Vec<_>>()
        ),
        (
            Some(crate::FailureClass::Io),
            true,
            8,
            8,
            Some(codec::CommitProgress {
                attempts: 8,
                fenced: false
            }),
            vec![lane.boundary_seq()]
        ),
        "the ninth attempt frame was refused for room: {result:?}"
    );
}

#[tokio::test]
async fn commit_definitive_rule8_refusal_is_terminal_like_invalid_candidate() {
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (plan, status, token) in [
        (PublishPlan::Reject, 400, "invalid-candidate"),
        (PublishPlan::InvalidReference, 400, "invalid-reference"),
        (PublishPlan::WorkLimit, 413, "publish-work-limit"),
    ] {
        let f = Fixture::new().await;
        f.create("dirty", b"uncommitted");
        let options = SyncOptions::default();
        let lane = f
            .engine
            .construct_commit(options, &mut Entropy(70))
            .await
            .unwrap();
        f.remote.publication_plan.lock().unwrap().extend([plan; 2]);
        let first = drive(&f, &lane, &mut Delay).await;
        let boundary_open = journal(&f)
            .state
            .open_boundaries()
            .any(|b| b == lane.boundary_seq());
        let workspace_held = f.engine.workspace_held_for_test() != 0;
        let again = f
            .engine
            .take_over_latched(
                options,
                TokioSyncRuntime.now() + options.resolution_bound,
                &mut Entropy(90),
            )
            .await;
        actual.push((
            token,
            outcome(&first),
            first.response.as_ref().map(PublishResponse::identification),
            boundary_open,
            workspace_held,
            matches!(again, Err(CoordinationError::Fenced { .. })),
            f.remote.publication_sends.lock().unwrap().len(),
        ));
        expected.push((
            token,
            "Refused".to_owned(),
            Some((status, Some(token))),
            false,
            false,
            true,
            1,
        ));
    }
    assert_eq!(actual.len(), 3);
    assert_eq!(
        actual, expected,
        "(token, first outcome, response, boundary open, workspace held, conflict fence on takeover, total sends)"
    );
}

#[tokio::test]
async fn commit_missing_reference_stops_sending_and_keeps_the_boundary_unfenced() {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let publication = saved(&f).publication_id;
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::MissingReference; 8]);

    let mut outcomes = Vec::new();
    for _ in 0..8 {
        let result = drive(&f, &lane, &mut Delay).await;
        outcomes.push(outcome(&result));
        if !matches!(f.store.lock().unwrap().sync_admission_open(), Ok(false)) {
            break;
        }
    }
    let scan = journal(&f);
    assert_eq!(
        (
            outcomes,
            f.remote.publication_sends.lock().unwrap().len(),
            scan.state.open_boundaries().collect::<Vec<_>>(),
            scan.state.commit_progress(&publication),
            f.store
                .lock()
                .unwrap()
                .sync_admission_open()
                .map_err(|e| e.to_string()),
        ),
        (
            vec!["Refused".to_owned(); 8],
            1,
            vec![lane.boundary_seq()],
            Some(codec::CommitProgress {
                attempts: 1,
                fenced: false
            }),
            Ok(false),
        ),
        "(drive outcomes, total sends, open boundaries, journal progress, admission open)"
    );
    assert!(f.engine.commit_retry_reasons().is_empty());
}

#[tokio::test]
async fn commit_live_loop_reports_rule8_refusal_as_refusal_not_outage() {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let options = published::bounded(Duration::from_mins(2));
    f.engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::MissingReference);
    let result = f
        .engine
        .take_over_latched(
            options,
            TokioSyncRuntime.now() + options.resolution_bound,
            &mut Entropy(80),
        )
        .await;
    let error = result.as_ref().err();
    assert_eq!(
        (
            error.map(crate::sync::failure_class),
            error.and_then(|e| f.engine.live_refusal_pause_for_test(e)),
            f.remote.publication_sends.lock().unwrap().len(),
        ),
        (
            Some(crate::FailureClass::Refused),
            Some(Duration::from_millis(40)),
            1
        ),
        "live takeover: {result:?}"
    );
}

async fn assert_commit_exhausts_at_eight_attempts(plan: PublishPlan) {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.remote.publication_plan.lock().unwrap().extend([plan; 9]);
    let result = drive(&f, &lane, &mut CeilingDelay::default()).await;
    let record = saved(&f);
    let progress = journal(&f).state.commit_progress(&record.publication_id);
    assert_eq!(
        (
            outcome(&result),
            f.remote.publication_sends.lock().unwrap().len(),
            progress
        ),
        (
            "Exhausted".to_owned(),
            8,
            Some(codec::CommitProgress {
                attempts: 8,
                fenced: true
            })
        ),
        "(outcome, physical sends, journal progress)"
    );
}

#[tokio::test]
async fn commit_outage_window_control_rate_limited_exhausts_at_eight_attempts() {
    assert_commit_exhausts_at_eight_attempts(PublishPlan::RateLimited).await;
}

#[tokio::test]
async fn commit_outage_window_control_bare_503_exhausts_at_eight_attempts() {
    assert_commit_exhausts_at_eight_attempts(PublishPlan::BareUnavailable).await;
}

#[tokio::test]
async fn commit_outage_window_control_enrollment_unavailable_exhausts_at_eight_attempts() {
    assert_commit_exhausts_at_eight_attempts(PublishPlan::OtherUnavailable(
        "enrollment-unavailable",
    ))
    .await;
}

#[tokio::test]
async fn commit_outage_window_control_503_fenced_exhausts_at_eight_attempts() {
    assert_commit_exhausts_at_eight_attempts(PublishPlan::OtherUnavailable("fenced")).await;
}

#[tokio::test]
async fn commit_outage_window_control_503_stopped_exhausts_at_eight_attempts() {
    assert_commit_exhausts_at_eight_attempts(PublishPlan::OtherUnavailable("stopped")).await;
}

#[tokio::test]
async fn commit_outage_window_control_transport_error_exhausts_at_eight_attempts() {
    assert_commit_exhausts_at_eight_attempts(PublishPlan::Transport).await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one paired table checks retained evidence, the shared budget and the durable mount fence"
)]
async fn commit_retry_stops_at_exact_eight_attempts_and_surfaces_exhaustion() {
    let cases = [
        (
            "rate limited keeps evidence",
            PublishPlan::RateLimited,
            true,
        ),
        (
            "typed unavailable keeps evidence",
            PublishPlan::Unavailable,
            false,
        ),
        (
            "bare unavailable keeps evidence",
            PublishPlan::BareUnavailable,
            false,
        ),
        ("internal keeps evidence", PublishPlan::Internal, false),
        ("transport keeps evidence", PublishPlan::Transport, false),
        ("deadline keeps evidence", PublishPlan::Timeout, false),
        ("accepted keeps evidence", PublishPlan::Accepted, false),
    ];
    let mut count = 0;
    for (label, answer, never_decided) in cases {
        let f = Fixture::new().await;
        let stage = f.create("dirty", b"uncommitted");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([answer; 9]);
        let mut delay = CeilingDelay::default();
        let result = drive(&f, &lane, &mut delay).await;
        let record = saved(&f);
        let scan = journal(&f);
        let progress = scan.state.commit_progress(&record.publication_id);
        let fenced = matches!(
            f.store.lock().unwrap().overlay_transaction(|_| Ok(())),
            Err(CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. })
        );
        let exempt = matches!(answer, PublishPlan::Unavailable);
        let attempts = if exempt { 1 } else { 8 };
        assert_eq!(
            (
                f.remote.publication_sends.lock().unwrap().len(),
                delay.0.iter().sum::<Duration>().as_millis(),
                outcome(&result),
                progress,
                scan.state.open_boundaries().collect::<Vec<_>>(),
                record.candidates.len(),
                record.candidates.iter().all(|c| c.evidence.never_decided()),
                record.candidates[0].evidence.started,
                fenced,
                record.unavailable_exemptions,
            ),
            (
                attempts,
                if exempt { 0 } else { 10_040 },
                if exempt { "Pending" } else { "Exhausted" }.to_owned(),
                Some(codec::CommitProgress {
                    attempts: attempts.try_into().unwrap(),
                    fenced: !exempt,
                }),
                vec![lane.boundary_seq()],
                1,
                never_decided,
                attempts.try_into().unwrap(),
                !exempt,
                u16::from(exempt),
            ),
            "{label}"
        );
        count += 1;
        if exempt {
            continue;
        }
        let sync = f
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await;
        assert_eq!(
            sync.as_ref().err().map(crate::sync_mount_error),
            Some(granary_fuse::MountSyncError::Backend(
                granary_fuse::MountError::Stale
            )),
            "{label}: exhausted fsync: {sync:?}"
        );
        let again = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(90),
            &mut Delay,
            RecoveryIntent::ExplicitRecovery,
            SyncOptions::default(),
        ))
        .await;
        assert_eq!(
            (
                matches!(
                    again,
                    Err(CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. })
                ),
                f.remote.publication_sends.lock().unwrap().len()
            ),
            (true, 8),
            "{label}: repeated drive: {again:?}"
        );
        assert_eq!(
            f.engine.commit_retry_reasons(),
            vec![crate::RetryReason::Transient; 7],
            "{label}: retry reasons"
        );
    }
    assert_eq!(count, 7);
}

#[tokio::test]
async fn commit_stale_base_retry_stops_at_exact_eight_attempts_with_backoff() {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let operation = saved(&f).current.unwrap().operation;
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::StaleForeign; 9]);
    let mut delay = CeilingDelay::default();
    let log = TimingLog::default();
    let result = {
        let _guard = tracing::subscriber::set_default(crate::observe::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
        ));
        drive(&f, &lane, &mut delay).await
    };
    let record = saved(&f);
    let progress = journal(&f).state.commit_progress(&record.publication_id);
    let fenced = matches!(
        f.store.lock().unwrap().overlay_transaction(|_| Ok(())),
        Err(CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. })
    );
    assert_eq!(
        (
            f.remote.publication_sends.lock().unwrap().len(),
            delay.0.iter().sum::<Duration>().as_millis(),
            outcome(&result),
            progress,
            fenced,
            f.engine.commit_retry_reasons()
        ),
        (
            8,
            10_040,
            "Exhausted".to_owned(),
            Some(codec::CommitProgress {
                attempts: 8,
                fenced: true,
            }),
            true,
            vec![crate::RetryReason::Conflict; 7]
        )
    );

    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let events = |name| {
        let event = format!(r#""event":"{name}""#);
        text.lines()
            .filter(move |line| line.contains(&event))
            .collect::<Vec<_>>()
    };
    let correlation = r#""op":"cor-4848484848484848""#;
    let retries = events("op.retry");
    assert_eq!(retries.len(), 7, "{text}");
    for (attempt, line) in (2..=8).zip(retries) {
        assert!(
            line.contains(correlation)
                && line.contains(r#""kind":"commit""#)
                && line.contains(r#""reason":"conflict""#)
                && line.contains(&format!(r#""attempt":{attempt},"#)),
            "stale-base retry {attempt}: {line}"
        );
    }
    for name in ["op.begin", "op.publish_bound", "op.failed", "op.end"] {
        let lines = events(name);
        assert_eq!(lines.len(), 1, "{name}: {text}");
        assert!(lines[0].contains(correlation), "{name}: {}", lines[0]);
    }
    assert!(events("op.publish_bound")[0].contains(&format!(
        r#""publish_operation":"{}""#,
        publication_hex(operation)
    )));
    assert_eq!(
        *f.remote.publication_operations.lock().unwrap(),
        vec![operation.to_vec(); 8]
    );
    assert!(events("op.conflict").is_empty(), "{text}");
    let metrics = f.metrics();
    for sample in [
        r#"granary_client_commit_retries_total{reason="conflict"} 7"#,
        "granary_client_rebase_conflicts_total 0",
        r#"granary_client_commits_total{result="exhausted"} 1"#,
    ] {
        assert!(metrics.lines().any(|line| line == sample), "{sample}");
    }
}

#[tokio::test]
async fn commit_budget_checks_resumed_awaiting_answer_before_any_dispatch_or_save() {
    let mut count = 0;
    for charged in [8, 9] {
        for label in ["awaiting answer", "interrupted probe", "unresolved probe"] {
            let f = Fixture::new().await;
            let lane = f
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70))
                .await
                .unwrap();
            let mut record = saved(&f);
            let attempt = record.candidates[0].evidence.start().unwrap();
            let probe = retained::Probe {
                cycle: record.generation,
                seq: record.candidates[0].seq,
                reason: retained::ProbeReason::Started,
            };
            record.phase = match label {
                "awaiting answer" => Phase::AwaitingAnswer {
                    candidate: 1,
                    attempt,
                },
                "interrupted probe" => Phase::ProbeStarted(probe),
                _ => Phase::Unresolved(retained::Probe {
                    reason: retained::ProbeReason::Transport,
                    ..probe
                }),
            };
            let generation = record.generation;
            record.generation += 1;
            f.store
                .lock()
                .unwrap()
                .publication_transaction(|j| j.replace(generation, &record))
                .unwrap();
            let publication = record.publication_id;
            for n in 1..=charged {
                f.store
                    .lock()
                    .unwrap()
                    .overlay_transaction(|t| {
                        t.record_commit_attempt(lane.boundary_seq(), publication, n)
                    })
                    .unwrap();
            }
            let result = drive(&f, &lane, &mut CeilingDelay::default()).await;
            let after = saved(&f);
            assert_eq!(
                (
                    f.remote.publication_sends.lock().unwrap().len(),
                    outcome(&result),
                    after.phase == record.phase,
                    after.candidates == record.candidates
                ),
                (0, "Exhausted".to_owned(), true, true),
                "{label}, charged={charged}: exhausted resume must preserve the saved phase"
            );
            count += 1;
        }
    }
    assert_eq!(count, 6);
}

#[tokio::test]
async fn commit_charge_is_durable_before_retained_attempt_save_and_send() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("overlay.journal.post_sync", "after", 1, FaultAction::Fail);
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    f.io.crash();
    assert_eq!(
        (
            journal(&f)
                .state
                .commit_progress(&saved(&f).publication_id)
                .map(|p| p.attempts),
            saved(&f).candidates[0].evidence.started,
            f.remote.publication_sends.lock().unwrap().len(),
            result.is_err()
        ),
        (Some(1), 0, 0, true),
        "charge sync failure: {result:?}"
    );
}

#[tokio::test]
async fn commit_malformed_answer_is_terminal_without_a_retry() {
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
        .extend([PublishPlan::Malformed, PublishPlan::Land]);
    let mut delay = CeilingDelay::default();
    let result = drive(&f, &lane, &mut delay).await;
    assert_eq!(
        (
            f.remote.publication_sends.lock().unwrap().len(),
            outcome(&result),
            delay.0.len(),
            journal(&f).state.commit_progress(&saved(&f).publication_id)
        ),
        (
            1,
            "BackendError".to_owned(),
            0,
            Some(codec::CommitProgress {
                attempts: 1,
                fenced: false
            })
        )
    );
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "the fixture installs a v1 record or removes its publication before restart"
)]
async fn commit_exhaustion_fence_survives_restart_without_a_send() {
    let mut count = 0;
    for (answer, never_decided) in [
        (PublishPlan::RateLimited, true),
        (PublishPlan::BareUnavailable, false),
    ] {
        for missing_record in [false, true] {
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
                .extend([answer; 8]);
            let result = drive(&f, &lane, &mut CeilingDelay::default()).await;
            assert_eq!(outcome(&result), "Exhausted");
            let before = saved(&f);
            assert_eq!(
                (
                    before.candidates[0].evidence.started,
                    before.candidates[0].evidence.never_decided()
                ),
                (8, never_decided)
            );
            if missing_record {
                std::fs::remove_file(paths(&f).1).unwrap();
            } else {
                let v1 = granary_core::testkit::retained_submission_v1_fixture(&before);
                assert_eq!(
                    (v1.get(8..10), retained::decode(&v1)),
                    (Some(&[0, 1][..]), Ok(before.clone()))
                );
                std::fs::write(paths(&f).1, v1).unwrap();
            }
            let remote = f.remote.clone();
            let result = f.try_restart_over(vec![]).await;
            let fenced = matches!(
                result,
                Err(CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. })
            );
            let error = result.err();
            let publication = publication_hex(before.publication_id);
            assert_eq!(
                (
                    fenced,
                    error
                        .as_ref()
                        .is_some_and(|e| e.to_string().contains(&publication)),
                    remote.publication_sends.lock().unwrap().len()
                ),
                (true, true, 8),
                "fenced commit admitted a new driver: {error:?}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 4);
}

#[tokio::test]
async fn commit_no_write_rejection_uses_the_fresh_store_record() {
    let mut count = 0;
    for stale in [false, true] {
        let f = Fixture::new().await;
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let mut record = saved(&f);
        let attempt = record.candidates[0].evidence.start().unwrap();
        record.candidates[0]
            .evidence
            .answer(attempt, true, false)
            .unwrap();
        if stale {
            record.candidates[0].evidence.start().unwrap();
        }
        let generation = record.generation;
        record.generation += 1;
        f.store
            .lock()
            .unwrap()
            .publication_transaction(|j| j.replace(generation, &record))
            .unwrap();
        f.store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.record_commit_attempt(lane.boundary_seq(), record.publication_id, 1)
            })
            .unwrap();
        let before = f.io.bytes(&paths(&f).0);
        let result = f.store.lock().unwrap().finish_non_landing(
            1,
            lane.boundary_seq(),
            record.publication_id,
        );
        let unchanged = f.io.bytes(&paths(&f).0) == before;
        assert_eq!(
            (result.map_err(|e| e.to_string()), unchanged),
            if stale {
                (Err("intent refused: SyncCommitUnresolved".to_owned()), true)
            } else {
                (Ok(()), false)
            },
            "fresh saved answers, stale={stale}"
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn commit_retry_restart_before_fifth_attempt_save_preserves_budget_and_backoff() {
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
        .extend([PublishPlan::RateLimited; 8]);
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "before_submit", 5, FaultAction::Fail);
    let mut delay = CeilingDelay::default();
    let mut entropy = Entropy(80);
    let interrupted = Box::pin(f.engine.drive_commit(
        &lane,
        &mut entropy,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            interrupted.is_err(),
            faults
                .sync_fired()
                .iter()
                .map(|e| (e.name, e.phase, e.occurrence))
                .collect::<Vec<_>>()
        ),
        (true, vec![("sync.commit", "before_submit", 5)]),
        "fifth attempt-save cut: {interrupted:?}"
    );
    let retained = saved(&f);
    assert_eq!(
        (
            retained.candidates[0].evidence.started,
            journal(&f)
                .state
                .commit_progress(&retained.publication_id)
                .unwrap()
                .attempts,
            f.remote.publication_sends.lock().unwrap().len(),
            delay.0.iter().sum::<Duration>().as_millis()
        ),
        (4, 4, 4, 1_200)
    );
    let mut reasons = f.engine.commit_retry_reasons();
    let f = f.restart().await;
    let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
    let result = drive(&f, &lane, &mut delay).await;
    assert_eq!(
        (
            f.remote.publication_sends.lock().unwrap().len(),
            outcome(&result),
            delay.0.iter().sum::<Duration>().as_millis(),
            journal(&f).state.commit_progress(&retained.publication_id)
        ),
        (
            8,
            "Exhausted".to_owned(),
            10_040,
            Some(codec::CommitProgress {
                attempts: 8,
                fenced: true
            })
        )
    );
    reasons.extend(f.engine.commit_retry_reasons());
    assert_eq!(reasons, vec![crate::RetryReason::Transient; 7]);
}

#[tokio::test]
async fn commit_no_write_exhaustion_generic_resume_and_recover_never_land_or_send() {
    let mut count = 0;
    for intent in [RecoveryIntent::Continue, RecoveryIntent::ExplicitRecovery] {
        let f = Fixture::new().await;
        f.create("dirty", b"uncommitted");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::RateLimited; 8]);
        let exhausted = drive(&f, &lane, &mut CeilingDelay::default()).await;
        assert_eq!(outcome(&exhausted), "Exhausted");
        let record = saved(&f);
        let journal_path = paths(&f).0;
        let Fixture {
            _scratch: scratch,
            io,
            store,
            engine,
            remote,
            ..
        } = f;
        drop(engine);
        drop(
            Arc::into_inner(store)
                .expect("fixture still has a client job")
                .into_inner()
                .unwrap(),
        );
        io.crash();
        // The simulator's durable journal and the disk publication store must
        // reopen together through native generic recovery.
        let bytes = io.bytes(&journal_path);
        let mut store = Store::open(&scratch.0).unwrap();
        let euid = config(&scratch.0).euid;
        let area =
            crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
        let scope = area.parent().unwrap();
        let mut disk = crate::OverlayDisk::new(&scratch.0, euid);
        for directory in [scope.parent().unwrap(), scope, area.as_path()] {
            disk.create_directory(directory).unwrap();
        }
        disk.create_directory(&area.join("staging")).unwrap();
        let journal = area.join("journal");
        disk.create(&journal).unwrap();
        disk.write_at(&journal, 0, &bytes).unwrap();
        disk.sync(&journal).unwrap();
        disk.sync_directory(&area).unwrap();
        let mut publications = store.publications(euid).unwrap();
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let keys = TrustedKeys::new([*key.public_key()]).unwrap();
        let before = remote.publication_sends.lock().unwrap().len();
        let roots = remote.published.lock().unwrap().clone();
        let result = Box::pin(crate::resume_publication(
            crate::RecoveryParts {
                transport: remote.as_ref(),
                journal: &mut publications,
                publisher_keys: &keys,
                signer: &key,
                secure: &mut Entropy(90),
                clock: &Tick(1_000_000),
                delay: &mut CeilingDelay::default(),
            },
            &exhausted.handle,
            intent,
        ))
        .await;
        let expected = format!(
            "commit publication {} fenced (ESTALE)",
            publication_hex(record.publication_id)
        );
        assert_eq!(
            (
                result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.to_string().contains(&expected)),
                matches!(
                    result.as_ref().map(|r| &r.outcome),
                    Ok(PublicationOutcome::Landed(_))
                ),
                remote.publication_sends.lock().unwrap().len() - before,
                *remote.published.lock().unwrap() == roots,
            ),
            (true, false, 0, true),
            "generic {intent:?} after exhaustion: refusal={:?}",
            result.as_ref().err().map(ToString::to_string)
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn commit_retry_classification_separates_transient_from_malformed_answers() {
    let cases = [
        ("typed rate limited", PublishPlan::RateLimited, true),
        ("bare rate limited", PublishPlan::BareRateLimited, true),
        ("typed unavailable", PublishPlan::Unavailable, true),
        ("bare unavailable", PublishPlan::BareUnavailable, true),
        (
            "reworded unavailable",
            PublishPlan::RewordedUnavailable,
            true,
        ),
        ("internal", PublishPlan::Internal, true),
        ("transport", PublishPlan::Transport, true),
        ("deadline", PublishPlan::Timeout, true),
        ("malformed success", PublishPlan::Malformed, false),
        (
            "malformed unavailable",
            PublishPlan::MalformedUnavailable,
            false,
        ),
    ];
    let mut count = 0;
    for (label, answer, transient) in cases {
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
            .extend([answer, PublishPlan::Land]);
        let mut delay = CeilingDelay::default();
        let result = drive(&f, &lane, &mut delay).await;
        assert_eq!(
            (
                outcome(&result),
                f.remote.publication_sends.lock().unwrap().len(),
                delay.0,
                f.engine.commit_retry_reasons()
            ),
            if matches!(answer, PublishPlan::Unavailable) {
                ("Pending".to_owned(), 1, vec![], vec![])
            } else if transient {
                (
                    "Landed".to_owned(),
                    2,
                    vec![Duration::from_millis(80)],
                    vec![crate::RetryReason::Transient],
                )
            } else {
                ("BackendError".to_owned(), 1, vec![], vec![])
            },
            "{label}"
        );
        count += 1;
    }
    assert_eq!(count, 10);
}

#[tokio::test]
async fn commit_budget_preserves_recovery_epoch_and_candidates_when_exhausted() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let mut record = saved(&f);
    record.current = None;
    record.phase = Phase::EpochRecovery { epoch: [5; 16] };
    let c = &mut record.candidates[0];
    c.role = retained::Role::Retired;
    let attempt = c.evidence.start().unwrap();
    c.evidence.answer(attempt, true, false).unwrap();
    let generation = record.generation;
    record.generation += 1;
    retained::validate(&record).unwrap();
    f.store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(generation, &record))
        .unwrap();
    for attempt in 1..=8 {
        f.store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.record_commit_attempt(lane.boundary_seq(), record.publication_id, attempt)
            })
            .unwrap();
    }
    let result = drive(&f, &lane, &mut Delay).await;
    let after = saved(&f);
    assert_eq!(
        (
            outcome(&result),
            after.phase,
            after.candidates,
            after.current,
            after.last_response
        ),
        (
            "Exhausted".to_owned(),
            record.phase,
            record.candidates,
            record.current,
            record.last_response
        )
    );
}

#[tokio::test]
async fn deferred_eighth_answer_is_classified_before_commit_exhaustion() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let publication = saved(&f).publication_id;
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::RateLimited; 7]);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::StaleForeignUnreadable);

    let first = drive(&f, &lane, &mut CeilingDelay::default()).await;
    let deferred = saved(&f);
    assert!(
        matches!(
            deferred.phase,
            Phase::Unresolved(ref probe)
                if probe.reason
                    == granary_core::retained_submission::ProbeReason::ContentUnavailable
        ),
        "the eighth answer did not retain its classification marker: {:?}",
        deferred.phase
    );
    assert_eq!(
        (
            outcome(&first),
            deferred.last_response.is_some(),
            journal(&f).state.commit_progress(&publication),
            f.remote.publication_sends.lock().unwrap().len(),
        ),
        (
            "Unresolved".to_owned(),
            true,
            Some(codec::CommitProgress {
                attempts: 8,
                fenced: false,
            }),
            8,
        ),
        "the answered eighth attempt remains live while classification is owed"
    );

    let second = drive(&f, &lane, &mut CeilingDelay::default()).await;
    let applied = saved(&f);
    assert_eq!(
        (
            outcome(&second),
            applied.phase,
            applied.last_response.is_some(),
            journal(&f).state.commit_progress(&publication),
            f.remote.publication_sends.lock().unwrap().len(),
        ),
        (
            "Exhausted".to_owned(),
            Phase::Rebase,
            true,
            Some(codec::CommitProgress {
                attempts: 8,
                fenced: true,
            }),
            8,
        ),
        "healthy replay must install the ordinary stale answer before exhaustion without a ninth send"
    );
}

#[tokio::test]
async fn commit_eighth_terminal_answer_still_exhausts_the_logical_commit() {
    let mut count = 0;
    for (label, answer) in [
        ("terminal no-write refusal", PublishPlan::Reject),
        ("malformed answer", PublishPlan::Malformed),
    ] {
        let f = Fixture::new().await;
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let publication = saved(&f).publication_id;
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::RateLimited; 7]);
        f.remote.publication_plan.lock().unwrap().push_back(answer);
        let result = drive(&f, &lane, &mut CeilingDelay::default()).await;
        let fenced = matches!(
            f.store.lock().unwrap().overlay_transaction(|_| Ok(())),
            Err(CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. })
        );
        assert_eq!(
            (
                outcome(&result),
                f.remote.publication_sends.lock().unwrap().len(),
                journal(&f).state.commit_progress(&publication),
                fenced
            ),
            (
                "Exhausted".to_owned(),
                8,
                Some(codec::CommitProgress {
                    attempts: 8,
                    fenced: true,
                }),
                true
            ),
            "{label}"
        );
        let remote = f.remote.clone();
        let restarted = f.try_restart_over(vec![]).await;
        assert_eq!(
            (
                matches!(restarted, Err(CoordinationError::CommitFenced { publication: p }) if p == publication),
                remote.publication_sends.lock().unwrap().len()
            ),
            (true, 8),
            "{label}: restart refusal: {:?}",
            restarted.err()
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn commit_fenced_progress_names_the_publication_and_stays_stale() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let publication = saved(&f).publication_id;
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.record_commit_fence(lane.boundary_seq(), publication))
        .unwrap();
    let error = f
        .store
        .lock()
        .unwrap()
        .commit_progress(1, publication)
        .unwrap_err();
    let expected = format!(
        "commit publication {} fenced (ESTALE)",
        publication_hex(publication)
    );
    let sticky = f.store.lock().unwrap().sync_admission_open().unwrap_err();
    assert_eq!(
        (
            error.to_string(),
            sticky.to_string(),
            crate::WritableStartError::from(error).to_string(),
            f.remote.publication_sends.lock().unwrap().len()
        ),
        (expected.clone(), expected.clone(), expected, 0)
    );
    assert_eq!(
        crate::sync_mount_error(&sticky),
        granary_fuse::MountSyncError::Backend(granary_fuse::MountError::Stale)
    );
}
