// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
//! Outage window, budget and gate rows driven through the live loop.

use super::*;

type Times = Arc<Mutex<Vec<tokio::time::Instant>>>;

fn watch_sends(remote: &Arc<Remote>, times: &Times) {
    let weak = Arc::downgrade(remote);
    let times = times.clone();
    *remote.publication_observer.lock().unwrap() = Some(Box::new(move || {
        times.lock().unwrap().push(TokioSyncRuntime.now());
        if let Some(remote) = weak.upgrade() {
            watch_sends(&remote, &times);
        }
    }));
}

/// The real live loop, polled on the test task beside a virtual-time tick.
struct Live {
    future: Pin<Box<dyn Future<Output = crate::sync::LiveEnd>>>,
    ended: bool,
}
impl Live {
    fn new(f: &Fixture) -> Self {
        Self {
            future: Box::pin(Arc::clone(&f.engine).drive_live(SyncOptions::default(), Entropy(90))),
            ended: false,
        }
    }
    async fn run(&mut self, duration: Duration) {
        let mut tick = Box::pin(TokioSyncRuntime.sleep(duration));
        std::future::poll_fn(|cx| {
            if !self.ended && self.future.as_mut().poll(cx).is_ready() {
                self.ended = true;
            }
            tick.as_mut().poll(cx)
        })
        .await;
    }
}

async fn live_loop_window(unavailable: usize) {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let roots = f.remote.published.lock().unwrap().len();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend(std::iter::repeat_n(PublishPlan::Unavailable, unavailable));
    let times: Times = Arc::default();
    watch_sends(&f.remote, &times);
    let started = TokioSyncRuntime.now();
    let mut live = Live::new(&f);
    while f.remote.published.lock().unwrap().len() == roots
        && !live.ended
        && started.elapsed() < Duration::from_hours(3)
    {
        live.run(Duration::from_millis(250)).await;
    }
    live.run(Duration::from_secs(5)).await;
    let times = times.lock().unwrap().clone();
    let gaps: Vec<u64> = times
        .windows(2)
        .map(|pair| u64::try_from(pair[1].duration_since(pair[0]).as_millis()).unwrap())
        .collect();
    let admission = f
        .store
        .lock()
        .unwrap()
        .sync_admission_open()
        .map_err(|e| e.to_string());
    println!(
        "OBS live n={unavailable} sends={} elapsed={:?} finished={} admission={admission:?} gaps_ms={gaps:?} retries={:?}",
        times.len(),
        started.elapsed(),
        live.ended,
        f.engine.commit_retry_reasons(),
    );
    assert_eq!(
        (
            f.remote.published.lock().unwrap().len(),
            times.len(),
            live.ended,
            admission,
        ),
        (roots + 1, unavailable + 1, false, Ok(true)),
        "(published roots, physical sends, live loop ended, admission open)"
    );
    // Sends answered after the 31-minute window closed are charged and use
    // the in-drive backoff, so only gaps inside the window are held to 30 s.
    let mut at = Duration::ZERO;
    for gap in gaps.iter().take(unavailable) {
        at += Duration::from_millis(*gap);
        assert!(
            *gap >= 30_000 || at >= Duration::from_mins(31),
            "a send inside the 30 s poll floor while the window was open: {gaps:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn outage_live_loop_8() {
    live_loop_window(8).await;
}
#[tokio::test(start_paused = true)]
async fn outage_live_loop_9() {
    live_loop_window(9).await;
}
#[tokio::test(start_paused = true)]
async fn outage_live_loop_20() {
    live_loop_window(20).await;
}

/// Replace the durable record through the store's own transaction.
fn rewrite(f: &Fixture, edit: impl FnOnce(&mut Submission)) {
    let mut record = saved(f);
    let generation = record.generation;
    record.generation += 1;
    edit(&mut record);
    f.store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(generation, &record))
        .unwrap();
}

fn progress(f: &Fixture) -> Option<codec::CommitProgress> {
    journal(f).state.commit_progress(&saved(f).publication_id)
}

fn record_attempts(
    f: &Fixture,
    lane: &crate::RetainedCommit,
    numbers: std::ops::RangeInclusive<u64>,
) {
    let publication = saved(f).publication_id;
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            for attempt in numbers {
                t.record_commit_attempt(lane.boundary_seq(), publication, attempt)?;
            }
            Ok(())
        })
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn start_dispatch_rechecks_budget_after_probe() {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let options = super::published::bounded(Duration::from_secs(55));
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    let now = TokioSyncRuntime.now();
    let floor =
        crate::http_store::seam_deadline(saved(&f).candidates.first().unwrap().root.len() as u64);
    let probe_delay = Duration::from_secs(20);
    let after_probe = options.resolution_bound.checked_sub(probe_delay);
    assert!(
        options.resolution_bound >= floor
            && after_probe.is_some_and(|remaining| !remaining.is_zero() && remaining < floor),
        "premise: a {probe_delay:?} probe consumes the dispatch allowance of {options:?}, floor={floor:?}"
    );
    let probes = f.remote.probes.load(Ordering::Relaxed);
    *f.remote.probe_delay.lock().unwrap() = Some(probe_delay);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Unavailable);
    let result = Box::pin(f.engine.drive_commit_for(
        &lane.with_deadline(now + options.resolution_bound),
        &mut Entropy(80),
        &mut Delay,
        crate::sync::CommitDrive::Start(RecoveryIntent::ExplicitRecovery),
        options,
    ))
    .await;
    let elapsed = now.elapsed();
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string).as_deref(),
            f.remote.probes.load(Ordering::Relaxed) - probes,
            elapsed >= probe_delay && elapsed < options.resolution_bound,
            f.remote.publication_sends.lock().unwrap().len(),
            progress(&f),
        ),
        (
            Some("intent refused: SyncDeadline"),
            1,
            true,
            0,
            Some(codec::CommitProgress {
                attempts: 0,
                fenced: false
            }),
        ),
        "the completed probe left too little time to dispatch: elapsed={elapsed:?}, {result:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn start_dispatch_keeps_a_save_margin_after_probe() {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let options = super::published::bounded(Duration::from_secs(85));
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    let record = saved(&f);
    let before = (progress(&f), record.unavailable_exemptions);
    let seam =
        crate::http_store::seam_deadline(record.candidates.first().unwrap().root.len() as u64);
    let floor = seam + Duration::from_secs(30);
    assert!(
        options.resolution_bound >= floor,
        "premise: the entry budget {options:?} covers the dispatch floor {floor:?}"
    );
    let probes = f.remote.probes.load(Ordering::Relaxed);
    let probe_delay = Duration::from_secs(25);
    *f.remote.probe_delay.lock().unwrap() = Some(probe_delay);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Unavailable);
    let now = TokioSyncRuntime.now();
    let result = Box::pin(f.engine.drive_commit_for(
        &lane.with_deadline(now + options.resolution_bound),
        &mut Entropy(80),
        &mut Delay,
        crate::sync::CommitDrive::Start(RecoveryIntent::ExplicitRecovery),
        options,
    ))
    .await;
    let elapsed = now.elapsed();
    let remaining = options.resolution_bound.saturating_sub(elapsed);
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string).as_deref(),
            f.remote.probes.load(Ordering::Relaxed) - probes,
            elapsed >= probe_delay && seam < remaining && remaining < floor,
            f.remote.publication_sends.lock().unwrap().len(),
            (progress(&f), saved(&f).unavailable_exemptions),
        ),
        (Some("intent refused: SyncDeadline"), 1, true, 0, before),
        "(refusal, probes, budget between seam and floor after probe, sends, (durable progress, exemptions)): elapsed={elapsed:?}, remaining={remaining:?}, seam={seam:?}, floor={floor:?}, {result:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn start_saves_slow_503_exemptions_and_fences_at_eight_charged_attempts() {
    let mut f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let cap = 64_u64;
    let exempt_drives = 9;
    let charged_drives = 8;
    let fence_at = cap + charged_drives;
    let options = super::published::bounded(crate::sync::commit_send_budget());
    let mut lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend(std::iter::repeat_n(
            PublishPlan::UnavailableAfterDelay(Duration::from_secs(40)),
            usize::try_from(exempt_drives + charged_drives).unwrap(),
        ));
    for (sent, attempt) in (1..=exempt_drives).chain(cap + 1..=fence_at).enumerate() {
        if attempt == cap + 1 {
            record_attempts(&f, &lane, exempt_drives + 1..=cap);
            rewrite(&f, |record| {
                record.unavailable_exemptions = u16::try_from(cap).unwrap();
            });
            assert_eq!(
                (saved(&f).unavailable_exemptions, progress(&f)),
                (
                    64,
                    Some(codec::CommitProgress {
                        attempts: cap,
                        fenced: false
                    }),
                ),
                "premise: the cap has matching durable attempt frames"
            );
        }
        let under_cap = attempt <= cap;
        let fenced = attempt == fence_at;
        // After the cap, allow one send and its saves. The 503 leaves too little
        // time for another send.
        let options = if under_cap {
            options
        } else {
            super::published::bounded(Duration::from_secs(80))
        };
        let result = Box::pin(f.engine.drive_commit_for(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            crate::sync::CommitDrive::Start(RecoveryIntent::ExplicitRecovery),
            options,
        ))
        .await;
        let expected = if under_cap {
            Ok("Pending".to_owned())
        } else if fenced {
            Ok("Exhausted".to_owned())
        } else {
            Err("intent refused: SyncDeadline".to_owned())
        };
        assert_eq!(
            (
                result.as_ref().map(outcome).map_err(ToString::to_string),
                f.remote.publication_sends.lock().unwrap().len(),
                saved(&f).unavailable_exemptions,
                progress(&f),
                f.store.lock().unwrap().sync_admission_open().is_ok(),
            ),
            (
                expected,
                sent + 1,
                u16::try_from(attempt.min(cap)).unwrap(),
                Some(codec::CommitProgress {
                    attempts: attempt,
                    fenced
                }),
                !fenced,
            ),
            "fresh drive {attempt}: {result:?}"
        );
        if !fenced {
            f = f.restart().await;
            lane = f.engine.recover_commit(options).unwrap();
        }
    }
}

/// A format-valid record (count <= 1024) whose count exceeds the policy cap.
#[tokio::test]
async fn outage_format_valid_count_above_policy_cap() {
    let waits = [80, 160, 320, 640, 1280, 2560, 5000].map(Duration::from_millis);
    for (count, attempts_at_start, expected_waits) in [
        (65, 0, &waits[..]),
        (1024, 0, &waits[..]),
        (65, 68, &waits[4..]),
    ] {
        let f = Fixture::new().await;
        f.create("dirty", b"uncommitted");
        let options = SyncOptions::default();
        let lane = f
            .engine
            .construct_commit(options, &mut Entropy(70))
            .await
            .unwrap();
        rewrite(&f, |record| record.unavailable_exemptions = count);
        record_attempts(&f, &lane, 1..=attempts_at_start);
        assert_eq!(
            (saved(&f).unavailable_exemptions, progress(&f)),
            (
                count,
                Some(codec::CommitProgress {
                    attempts: attempts_at_start,
                    fenced: false,
                }),
            ),
            "retained count and journal progress before the drive"
        );
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::Unavailable; 40]);
        let mut delay = CeilingDelay::default();
        let result = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut delay,
            RecoveryIntent::ExplicitRecovery,
            options,
        ))
        .await;
        let expected_sends = expected_waits.len() + 1;
        assert_eq!(
            (
                result
                    .as_ref()
                    .map(|r| &r.outcome)
                    .map_err(ToString::to_string),
                f.remote.publication_sends.lock().unwrap().len(),
                delay.0.as_slice(),
                progress(&f),
            ),
            (
                Ok(&PublicationOutcome::Exhausted),
                expected_sends,
                expected_waits,
                Some(codec::CommitProgress {
                    attempts: attempts_at_start + u64::try_from(expected_sends).unwrap(),
                    fenced: true,
                }),
            ),
            "count={count}, attempts_at_start={attempts_at_start}: outcome, sends, waits and progress"
        );
    }
}

#[cfg(feature = "publish-restart-tests")]
#[tokio::test]
async fn outage_crash_cut_matrix() {
    for (cut, side) in [
        ("attempt-save", "before"),
        ("attempt-save", "after"),
        // The answer arrives and its save fails: the cut between send and answer save.
        ("send", "answer-lost"),
        ("answer-save", "before"),
        ("answer-save", "after"),
    ] {
        let mut f = Fixture::new().await;
        f.create("dirty", b"uncommitted");
        let options = super::published::bounded(Duration::from_mins(50));
        let mut lane = f
            .engine
            .construct_commit(options, &mut Entropy(70))
            .await
            .unwrap();
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::Unavailable; 200]);
        let mut saved_503 = 0_u16;
        let mut errors = 0;
        // Twelve crash cycles: each cuts one drive and reopens the lane.
        for cycle in 0..12 {
            if cut == "send" {
                let local = Arc::downgrade(&f.store);
                *f.remote.publication_observer.lock().unwrap() = Some(Box::new(move || {
                    local
                        .upgrade()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .fail_publication_file_sync_for_test(true);
                }));
            } else {
                crate::publish_restart::fail_once_for_test(cut, side);
            }
            let result = Box::pin(f.engine.drive_commit(
                &lane,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::ExplicitRecovery,
                options,
            ))
            .await;
            if result.is_err() {
                errors += 1;
            }
            let before = saved(&f);
            if before
                .last_response
                .as_ref()
                .is_some_and(|a| a.status == 503 && a.token == b"unavailable")
                && (cut, side) == ("answer-save", "after")
            {
                saved_503 += 1;
            }
            let fenced = f.store.lock().unwrap().sync_admission_open().is_err();
            if cycle < 3 || fenced {
                println!(
                    "OBS cut={cut}/{side} cycle={cycle} result={:?} sends={} progress={:?} exemptions={} phase={:?} last={:?}",
                    result.as_ref().map(outcome).map_err(ToString::to_string),
                    f.remote.publication_sends.lock().unwrap().len(),
                    progress(&f),
                    before.unavailable_exemptions,
                    before.phase,
                    before.last_response.as_ref().map(|a| a.status),
                );
            }
            if fenced {
                break;
            }
            f = f.restart().await;
            lane = match f.engine.recover_commit(options) {
                Ok(lane) => lane,
                Err(error) => {
                    println!("OBS cut={cut}/{side} recover_commit: {error}");
                    break;
                }
            };
        }
        let record = saved(&f);
        let sends = f.remote.publication_sends.lock().unwrap().len() as u64;
        let attempts = progress(&f).map_or(0, |p| p.attempts);
        println!(
            "OBS cut={cut}/{side} END errors={errors} sends={sends} attempts={attempts} exemptions={} saved_503={saved_503}",
            record.unavailable_exemptions
        );
        assert!(attempts >= sends, "{cut}/{side}: a send without a frame");
        assert!(
            u64::from(record.unavailable_exemptions) <= sends,
            "{cut}/{side}: more exemptions than sends"
        );
        if (cut, side) != ("answer-save", "after") {
            assert_eq!(
                record.unavailable_exemptions, 0,
                "{cut}/{side}: an exemption without a saved answer"
            );
            assert!(sends <= 8, "{cut}/{side}: charged budget exceeded");
        }
    }
}

/// Item 4 on the live path: an earlier uncertain send that landed must win
/// over the saved refusal on the next drive.
#[tokio::test]
async fn outage_live_refusal_then_landing_revealed() {
    for refusal in [
        PublishPlan::MissingReference,
        PublishPlan::InvalidReference,
        PublishPlan::WorkLimit,
    ] {
        for uncertain in [
            PublishPlan::Timeout,
            PublishPlan::Transport,
            PublishPlan::Unavailable,
        ] {
            let f = Fixture::new().await;
            f.create("dirty", b"uncommitted");
            let options = super::published::bounded(Duration::from_mins(50));
            let lane = f
                .engine
                .construct_commit(options, &mut Entropy(70))
                .await
                .unwrap();
            f.remote
                .publication_plan
                .lock()
                .unwrap()
                .extend([uncertain, refusal]);
            let mut first = drive(&f, &lane, &mut Delay).await;
            if matches!(uncertain, PublishPlan::Unavailable) {
                advance_outage(Duration::from_secs(61)).await;
                first = drive(&f, &lane, &mut Delay).await;
            }
            let record = saved(&f);
            let candidate = record.candidates.first().unwrap().clone();
            let sends = f.remote.publication_sends.lock().unwrap().len();
            f.remote
                .published
                .lock()
                .unwrap()
                .insert(candidate.seq, candidate.root.clone());
            let second = Box::pin(f.engine.drive_commit(
                &lane,
                &mut Entropy(81),
                &mut Delay,
                RecoveryIntent::ExplicitRecovery,
                options,
            ))
            .await;
            let diagnostic = format!(
                "first={} uncertain={} sends={sends} second={:?} sends_after={} admission={:?}",
                outcome(&first),
                first.uncertain,
                second.as_ref().map(outcome).map_err(ToString::to_string),
                f.remote.publication_sends.lock().unwrap().len(),
                f.store
                    .lock()
                    .unwrap()
                    .sync_admission_open()
                    .map_err(|e| e.to_string()),
            );
            println!("OBS item4 {diagnostic}");
            assert!(
                matches!(&second, Ok(result) if matches!(&result.outcome, PublicationOutcome::Landed(done) if done.root == candidate.root))
                    && f.remote.publication_sends.lock().unwrap().len() == sends,
                "landing lost behind the saved refusal: {diagnostic}"
            );
        }
    }
}

/// Item 2: the persisted count caps exempt sends across restarts, each of
/// which forgets the window and the poll gate.
#[tokio::test]
async fn outage_restart_loop_cannot_pass_sixty_four_exemptions() {
    let mut f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let options = SyncOptions::default();
    let mut lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 200]);
    let mut cycles = 0;
    let mut last = String::new();
    for _ in 0..90 {
        cycles += 1;
        let result = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::ExplicitRecovery,
            options,
        ))
        .await;
        last = format!(
            "{:?}",
            result.as_ref().map(outcome).map_err(ToString::to_string)
        );
        if f.store.lock().unwrap().sync_admission_open().is_err() || result.is_err() {
            break;
        }
        f = f.restart().await;
        lane = f.engine.recover_commit(options).unwrap();
    }
    let diagnostic = format!(
        "cycles={cycles} last={last} sends={} exemptions={} progress={:?}",
        f.remote.publication_sends.lock().unwrap().len(),
        saved(&f).unavailable_exemptions,
        progress(&f),
    );
    println!("OBS restart-loop {diagnostic}");
    assert_eq!(
        (
            f.remote.publication_sends.lock().unwrap().len(),
            saved(&f).unavailable_exemptions,
            progress(&f).map(|p| (p.attempts, p.fenced)),
        ),
        (72, 64, Some((72, true))),
        "{diagnostic}"
    );
}

/// Item 3: answers slower than the caller's bound. Each published fsync is
/// cut before the 503 arrives, so no poll is armed and no exemption is saved.
#[tokio::test(start_paused = true)]
async fn outage_slow_503_under_repeated_fsync() {
    let f = Fixture::new().await;
    let stage = f.create("dirty", b"uncommitted");
    let options = SyncOptions::default();
    let lane = f
        .engine
        .construct_commit(
            super::published::bounded(Duration::from_mins(50)),
            &mut Entropy(70),
        )
        .await
        .unwrap();
    {
        let mut plan = f.remote.publication_plan.lock().unwrap();
        plan.push_back(PublishPlan::Unavailable);
        plan.extend([PublishPlan::UnavailableAfterDelay(Duration::from_secs(45)); 12]);
    }
    let times: Times = Arc::default();
    watch_sends(&f.remote, &times);
    let first = drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (first.outcome, saved(&f).unavailable_exemptions),
        (PublicationOutcome::Pending, 1)
    );
    let opened = TokioSyncRuntime.now();
    TokioSyncRuntime.sleep(Duration::from_secs(61)).await;
    let mut results = Vec::new();
    for seed in 0..10_u8 {
        let result =
            super::published::published(&f, SyncTarget::Stage(stage), 90 + seed, options).await;
        results.push(result.err().map(|e| e.to_string()));
        if f.store.lock().unwrap().sync_admission_open().is_err() {
            break;
        }
    }
    let times = times.lock().unwrap().clone();
    let gaps: Vec<u64> = times
        .windows(2)
        .map(|pair| u64::try_from(pair[1].duration_since(pair[0]).as_millis()).unwrap())
        .collect();
    println!(
        "OBS slow-503 window_age={:?} sends={} gaps_ms={gaps:?} exemptions={} progress={:?} admission={:?} results={results:?}",
        opened.elapsed(),
        times.len(),
        saved(&f).unavailable_exemptions,
        progress(&f),
        f.store
            .lock()
            .unwrap()
            .sync_admission_open()
            .map_err(|e| e.to_string()),
    );
    assert!(
        f.store.lock().unwrap().sync_admission_open().is_ok(),
        "the mount fenced {:?} into an open 31-minute window on answers that were all 503 unavailable",
        opened.elapsed()
    );
    assert_eq!(
        (times.len(), results),
        (
            1,
            vec![Some("intent refused: SyncCommitUnresolved".into()); 10]
        ),
        "published fsyncs after the poll time must leave the retained send count unchanged"
    );
}

/// Item 3 on the real live loop: published fsyncs every few seconds during
/// the window must not add sends.
#[tokio::test(start_paused = true)]
async fn outage_live_loop_with_fsync_pressure() {
    let f = Fixture::new().await;
    let stage = f.create("dirty", b"uncommitted");
    let roots = f.remote.published.lock().unwrap().len();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Unavailable; 12]);
    let times: Times = Arc::default();
    watch_sends(&f.remote, &times);
    let started = TokioSyncRuntime.now();
    let mut live = Live::new(&f);
    let mut fsyncs = 0_u32;
    let mut seed = 0_u8;
    while f.remote.published.lock().unwrap().len() == roots
        && !live.ended
        && started.elapsed() < Duration::from_hours(3)
    {
        live.run(Duration::from_secs(3)).await;
        if times.lock().unwrap().is_empty() {
            continue;
        }
        seed = seed.wrapping_add(1);
        let mut fsync = Box::pin(super::published::published(
            &f,
            SyncTarget::Stage(stage),
            seed,
            SyncOptions::default(),
        ));
        let mut done = false;
        std::future::poll_fn(|cx| {
            if !live.ended && live.future.as_mut().poll(cx).is_ready() {
                live.ended = true;
            }
            if !done && fsync.as_mut().poll(cx).is_ready() {
                done = true;
            }
            if done {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        fsyncs += 1;
    }
    live.run(Duration::from_secs(5)).await;
    let times = times.lock().unwrap().clone();
    let gaps: Vec<u64> = times
        .windows(2)
        .map(|pair| u64::try_from(pair[1].duration_since(pair[0]).as_millis()).unwrap())
        .collect();
    let admission = f
        .store
        .lock()
        .unwrap()
        .sync_admission_open()
        .map_err(|e| e.to_string());
    println!(
        "OBS live+fsync fsyncs={fsyncs} sends={} elapsed={:?} ended={} admission={admission:?} gaps_ms={gaps:?}",
        times.len(),
        started.elapsed(),
        live.ended,
    );
    assert_eq!(
        (
            f.remote.published.lock().unwrap().len(),
            times.len(),
            admission
        ),
        (roots + 1, 13, Ok(true))
    );
    assert!(
        gaps.iter().all(|gap| *gap >= 30_000),
        "a send inside the poll floor: {gaps:?}"
    );
}

/// Claim 1 on the real live loop when the authority answers `503 unavailable`
/// later than the loop's own 30 s drive bound (the transport's seam deadline
/// is 45 s): every drive is cut before its answer, so nothing is exempt.
#[tokio::test(start_paused = true)]
async fn outage_live_loop_slow_503_window() {
    let f = Fixture::new().await;
    f.create("dirty", b"uncommitted");
    let roots = f.remote.published.lock().unwrap().len();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::UnavailableAfterDelay(Duration::from_secs(40)); 9]);
    let times: Times = Arc::default();
    watch_sends(&f.remote, &times);
    let started = TokioSyncRuntime.now();
    let mut live = Live::new(&f);
    while f.remote.published.lock().unwrap().len() == roots
        && !live.ended
        && started.elapsed() < Duration::from_hours(3)
    {
        live.run(Duration::from_millis(250)).await;
    }
    let times = times.lock().unwrap().clone();
    let first = times.first().copied().unwrap_or(started);
    let admission = f
        .store
        .lock()
        .unwrap()
        .sync_admission_open()
        .map_err(|e| e.to_string());
    println!(
        "OBS live slow-503 sends={} since_first_send={:?} ended={} admission={admission:?} exemptions={:?} progress={:?}",
        times.len(),
        first.elapsed(),
        live.ended,
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || saved(&f).unavailable_exemptions
        ))
        .ok(),
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| progress(&f))).ok(),
    );
    assert_eq!(
        (
            f.remote.published.lock().unwrap().len(),
            live.ended,
            admission
        ),
        (roots + 1, false, Ok(true)),
        "(published roots, live loop ended, admission open): nine 503 unavailable answers, each 40 s after its send"
    );
}

#[tokio::test(start_paused = true)]
async fn outage_free_live_commit_lands_with_custom_resolution_bounds() {
    let mut rows = Vec::new();
    for seconds in [3, 40] {
        let f = Fixture::new().await;
        f.create("dirty", b"uncommitted");
        let options = SyncOptions {
            resolution_bound: Duration::from_secs(seconds),
            ..SyncOptions::default()
        };
        let mut live = Live {
            future: Box::pin(Arc::clone(&f.engine).drive_live(options, Entropy(90))),
            ended: false,
        };
        live.run(Duration::from_secs(15)).await;
        let base = f.store.lock().unwrap().shutdown_base();
        let published = f.remote.published.lock().unwrap().get(&2).cloned();
        rows.push((
            seconds,
            f.remote.publication_sends.lock().unwrap().len(),
            published.as_ref().is_some_and(|root| {
                assert_file(&f, root, "dirty", b"uncommitted");
                base == Some((GrainId::of(root), 2))
            }),
        ));
    }
    assert_eq!(
        rows,
        [(3, 1, true), (40, 1, true)],
        "(resolution bound in seconds, physical sends, published root installed as base)"
    );
}

#[tokio::test(start_paused = true)]
async fn outage_background_dispatch_rechecks_budget_after_probe() {
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
        .push_back(PublishPlan::Unavailable);
    let first = drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            first.outcome,
            saved(&f).unavailable_exemptions,
            f.remote.publication_sends.lock().unwrap().len(),
        ),
        (PublicationOutcome::Pending, 1, 1),
        "(outcome, saved exemptions, physical sends) before the live retry"
    );
    TokioSyncRuntime.sleep(Duration::from_secs(61)).await;

    let probes_before = f.remote.probes.load(Ordering::Relaxed);
    *f.remote.probe_delay.lock().unwrap() = Some(Duration::from_secs(20));
    let options = SyncOptions {
        deadline: Some(TokioSyncRuntime.now() + Duration::from_secs(55)),
        ..SyncOptions::default()
    };
    let mut live = Live {
        future: Box::pin(Arc::clone(&f.engine).drive_live(options, Entropy(90))),
        ended: false,
    };
    let started = TokioSyncRuntime.now();
    while f.engine.live_pauses_for_test().is_empty()
        && f.remote.publication_sends.lock().unwrap().len() == 1
        && !live.ended
        && started.elapsed() < Duration::from_secs(54)
    {
        live.run(Duration::from_millis(250)).await;
    }
    assert_eq!(
        (
            f.remote.probes.load(Ordering::Relaxed),
            !f.engine.live_pauses_for_test().is_empty(),
            f.remote.publication_sends.lock().unwrap().len(),
            progress(&f).map(|progress| progress.attempts),
        ),
        (probes_before + 1, true, 1, Some(1)),
        "a completed probe spent the publish allowance during the open outage window"
    );
}

/// Claim 1 for refusals on the real live loop: one send over three hours of
/// loop time and repeated fsyncs, and every fsync reports class refused.
#[tokio::test(start_paused = true)]
async fn outage_live_loop_refusals_send_once() {
    for refusal in [
        PublishPlan::MissingReference,
        PublishPlan::InvalidReference,
        PublishPlan::WorkLimit,
    ] {
        let f = Fixture::new().await;
        let stage = f.create("dirty", b"uncommitted");
        f.remote.publication_plan.lock().unwrap().push_back(refusal);
        let times: Times = Arc::default();
        watch_sends(&f.remote, &times);
        let started = TokioSyncRuntime.now();
        let mut live = Live::new(&f);
        let mut classes = Vec::new();
        let mut seed = 0_u8;
        while started.elapsed() < Duration::from_hours(3) {
            live.run(Duration::from_mins(7)).await;
            if times.lock().unwrap().is_empty() || classes.len() >= 6 {
                continue;
            }
            seed = seed.wrapping_add(1);
            let mut fsync = Box::pin(super::published::published(
                &f,
                SyncTarget::Stage(stage),
                seed,
                SyncOptions::default(),
            ));
            let mut done = None;
            std::future::poll_fn(|cx| {
                if !live.ended && live.future.as_mut().poll(cx).is_ready() {
                    live.ended = true;
                }
                if done.is_none()
                    && let std::task::Poll::Ready(result) = fsync.as_mut().poll(cx)
                {
                    done = Some(result);
                }
                if done.is_some() {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            classes.push(
                done.unwrap()
                    .err()
                    .map(|e| (crate::sync::failure_class(&e), e.to_string())),
            );
        }
        let admission = f
            .store
            .lock()
            .unwrap()
            .sync_admission_open()
            .map_err(|e| e.to_string());
        println!(
            "OBS live refusal sends={} ended={} admission={admission:?} retries={:?} pauses={:?} fsync={classes:?}",
            times.lock().unwrap().len(),
            live.ended,
            f.engine.commit_retry_reasons(),
            f.engine
                .live_pauses_for_test()
                .iter()
                .map(|(base, _)| base.as_millis())
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            times.lock().unwrap().len(),
            1,
            "a refused request was sent again"
        );
        assert!(
            classes
                .iter()
                .flatten()
                .all(|(class, _)| *class != crate::FailureClass::Unavailable),
            "a refusal reported as an outage: {classes:?}"
        );
    }
}
