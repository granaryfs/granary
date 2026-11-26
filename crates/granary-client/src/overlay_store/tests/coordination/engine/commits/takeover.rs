// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A published sync takes over a lane retained before it: under its own
//! deadline, recovering whatever probe the lane was left in, and waiting
//! without locks while another driver holds it.

use super::budget::saved;
use super::projected::{lane_closed, seal};
use super::published::{bounded, head_file, published, settle_disk, write};
use super::*;

/// Whether `done` holds within ten seconds, polled on the runtime clock.
async fn eventually(done: impl Fn() -> bool) -> bool {
    let deadline = TokioSyncRuntime.now() + Duration::from_secs(10);
    while !done() {
        if TokioSyncRuntime.now() >= deadline {
            return false;
        }
        TokioSyncRuntime.sleep(Duration::from_millis(2)).await;
    }
    true
}

/// Wait until `count` sends in all have entered the authority's hold;
/// false if they do not.
async fn entered_hold(f: &Fixture, count: usize) -> bool {
    tokio::time::timeout(
        Duration::from_secs(10),
        f.remote.publish_hold.entered(count),
    )
    .await
    .is_ok()
}

fn sends(f: &Fixture) -> usize {
    f.remote.publication_sends.lock().unwrap().len()
}

fn record_terminal_refusal(f: &Fixture, lane: &crate::RetainedCommit) {
    let mut record = saved(f);
    let attempt = record.candidates[0].evidence.start().unwrap();
    record.candidates[0]
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    let generation = record.generation;
    record.generation += 1;
    let mut local = f.store.lock().unwrap();
    local
        .publication_transaction(|journal| journal.replace(generation, &record))
        .unwrap();
    local
        .overlay_transaction(|overlay| {
            overlay.record_commit_attempt(lane.boundary_seq(), record.publication_id, 1)
        })
        .unwrap();
}

/// The live wait subscribes before reading: a floor wake after a clean read is
/// retained, so the next read sees the lane, and the latch's wake ends the
/// wait. Case count 2.
#[tokio::test]
async fn live_wait_rereads_floor_changes_and_stops_at_the_latch() {
    let mut observed = Vec::new();
    for latched in [false, true] {
        let f = Fixture::new().await;
        let store = f.store.clone();
        let floor = f.engine.floor_changed_for_test();
        if !latched {
            f.engine
                .before_live_read_for_test(move || floor.notify_waiters());
        }
        let floor = f.engine.floor_changed_for_test();
        f.engine.after_live_read_for_test(move || {
            let mut local = store.lock().unwrap();
            if latched {
                local.close_mutations();
                floor.notify_waiters();
            } else {
                local.close_sync_admission().unwrap();
            }
        });
        let answer = tokio::time::timeout(
            Duration::from_secs(2),
            f.engine.live_wait_for_test(SyncOptions::default()),
        )
        .await
        .map_err(|_| "timeout".to_owned())
        .and_then(|answer| answer.map(str::to_owned).map_err(|error| error.to_string()));
        if !latched {
            let serial = f
                .store
                .lock()
                .unwrap()
                .live_admission()
                .and_then(|admission| match admission {
                    crate::writable_store::sync_engine::LiveAdmission::Held { serial, .. } => {
                        Ok(serial)
                    }
                    _ => Err(crate::sync::refused("LiveWaitPremise")),
                })
                .unwrap();
            f.store
                .lock()
                .unwrap()
                .cancel_unsent_commit(serial, None, 0)
                .unwrap();
        }
        observed.push(answer);
    }
    assert_eq!(
        observed,
        [Ok("lane_retained".to_owned()), Ok("latched".to_owned())],
        "the valid controls exercised two live-wait wake cases"
    );
}

/// A newer lane that appears after recovery of the observed lane failed is
/// not charged with that older lane's error. Both takeover entries compare
/// the serial they read. Case count 2.
#[tokio::test]
async fn takeover_does_not_return_an_older_lanes_recovery_error_for_a_newer_lane() {
    let mut observed = Vec::new();
    for latched in [false, true] {
        let f = Fixture::new().await;
        f.create("x", b"retained lane");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(60))
            .await
            .unwrap();
        record_terminal_refusal(&f, &lane);
        f.engine.forget_commit_for_test();
        let store = f.store.clone();
        let newer = Arc::new(AtomicU64::new(0));
        let recorded = newer.clone();
        f.engine.after_recover_error_for_test(move || {
            let mut local = store.lock().unwrap();
            let (serial, boundary, _, _, record) = local.recovered_commit().unwrap();
            local
                .finish_non_landing(serial, boundary, record.publication_id)
                .unwrap();
            recorded.store(local.close_sync_admission().unwrap(), Ordering::Release);
        });
        let options = SyncOptions {
            workspace_bytes: 0,
            ..SyncOptions::default()
        };
        let deadline = TokioSyncRuntime.now() + Duration::from_secs(2);
        let result = if latched {
            f.engine
                .take_over_latched(options, deadline, &mut Entropy(70))
                .await
                .map(|answer| format!("{answer:?}"))
        } else {
            f.engine
                .take_over(
                    options,
                    deadline,
                    crate::sync::CommitDrive::Mount(RecoveryIntent::ExplicitRecovery),
                    &mut Entropy(70),
                )
                .await
                .map(|()| "ended".to_owned())
        };
        let serial = newer.load(Ordering::Acquire);
        assert!(
            serial > 0,
            "premise: a newer lane replaced the failed lane: {serial}"
        );
        f.store
            .lock()
            .unwrap()
            .cancel_unsent_commit(serial, None, 0)
            .unwrap();
        observed.push(result.map_err(|error| error.to_string()));
    }
    assert_eq!(
        observed,
        [
            Err("intent refused: SyncCommitNotRetained".to_owned()),
            Err("intent refused: SyncCommitNotRetained".to_owned()),
        ],
        "a changed serial continues past the stale no-space error"
    );
}

/// A latch-aware takeover reports a lane another driver landed, distinguishes
/// terminal non-landings even if an adoption moves the base, and reports open
/// when no lane was held. Case count 4.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the landing, terminal non-landings and open control share one tuple oracle"
)]
async fn take_over_latched_reports_whether_a_held_lane_landed() {
    let landed = {
        let f = Fixture::new().await;
        f.create("landed", b"another driver");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(60))
            .await
            .unwrap();
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Hold);
        let (mut drive_entropy, mut delay) = (Entropy(61), Delay);
        let mut driving = Box::pin(f.engine.drive_commit(
            &lane,
            &mut drive_entropy,
            &mut delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ));
        let drive_finished = std::future::poll_fn(|context| {
            std::task::Poll::Ready(std::future::Future::poll(driving.as_mut(), context).is_ready())
        })
        .await;
        assert!(!drive_finished, "premise: another driver remains held");
        let mut entered = Box::pin(entered_hold(&f, 1));
        let held = std::future::poll_fn(|context| {
            if let std::task::Poll::Ready(result) =
                std::future::Future::poll(driving.as_mut(), context)
            {
                panic!("driver ended before its hold: {result:?}");
            }
            std::future::Future::poll(entered.as_mut(), context)
        })
        .await;
        assert!(held, "premise: another driver holds the lane");
        let deadline = TokioSyncRuntime.now() + Duration::from_secs(5);
        let mut takeover_entropy = Entropy(70);
        let mut taking_over = Box::pin(f.engine.take_over_latched(
            SyncOptions::default(),
            deadline,
            &mut takeover_entropy,
        ));
        let takeover_finished = std::future::poll_fn(|context| {
            std::task::Poll::Ready(
                std::future::Future::poll(taking_over.as_mut(), context).is_ready(),
            )
        })
        .await;
        assert!(!takeover_finished, "premise: takeover waits for the driver");
        f.remote.publish_hold.release();
        driving.await.unwrap();
        format!("{:?}", taking_over.await.unwrap())
    };

    let non_landing = {
        let f = Fixture::new().await;
        f.create("refused", b"terminal answer");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(80))
            .await
            .unwrap();
        record_terminal_refusal(&f, &lane);
        f.engine.forget_commit_for_test();
        let store = f.store.clone();
        f.engine.after_recover_error_for_test(move || {
            let mut local = store.lock().unwrap();
            let (serial, boundary, _, _, record) = local.recovered_commit().unwrap();
            local
                .finish_non_landing(serial, boundary, record.publication_id)
                .unwrap();
        });
        let options = SyncOptions {
            workspace_bytes: 0,
            ..SyncOptions::default()
        };
        let deadline = TokioSyncRuntime.now() + Duration::from_secs(2);
        format!(
            "{:?}",
            f.engine
                .take_over_latched(options, deadline, &mut Entropy(81))
                .await
                .unwrap()
        )
    };

    let adopted_after_non_landing = {
        let f = Fixture::new().await;
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(82))
            .await
            .unwrap();
        record_terminal_refusal(&f, &lane);
        f.engine.forget_commit_for_test();
        let before = f.store.lock().unwrap().mount_base().unwrap();
        let adopted = GrainId::of(b"another writer's head");
        let store = f.store.clone();
        f.engine.after_recover_error_for_test(move || {
            let mut local = store.lock().unwrap();
            let (serial, boundary, _, _, record) = local.recovered_commit().unwrap();
            local
                .finish_non_landing(serial, boundary, record.publication_id)
                .unwrap();
            local
                .replace_adopted(adopted, before.1 + 1, Vec::new())
                .unwrap();
        });
        let options = SyncOptions {
            workspace_bytes: 0,
            ..SyncOptions::default()
        };
        let deadline = TokioSyncRuntime.now() + Duration::from_secs(2);
        let answer = format!(
            "{:?}",
            f.engine
                .take_over_latched(options, deadline, &mut Entropy(83))
                .await
                .unwrap()
        );
        let base_moved = f.store.lock().unwrap().mount_base().unwrap() != before;
        (answer, base_moved)
    };

    let open = {
        let f = Fixture::new().await;
        let deadline = TokioSyncRuntime.now() + Duration::from_secs(2);
        format!(
            "{:?}",
            f.engine
                .take_over_latched(SyncOptions::default(), deadline, &mut Entropy(90))
                .await
                .unwrap()
        )
    };
    assert_eq!(
        (landed, non_landing, adopted_after_non_landing, open),
        (
            "Ended { landed: true }".to_owned(),
            "Ended { landed: false }".to_owned(),
            ("Ended { landed: false }".to_owned(), true),
            "Open".to_owned(),
        ),
        "(another driver's landing, finish_non_landing, (finish_non_landing followed by adoption, base moved), no held lane)"
    );
}

/// Leave x's lane retained past its own deadline: its one send is held
/// until that deadline drops it unanswered. A projected lane is a published
/// sync's; otherwise it is a whole-tree commit's.
async fn expired_lane(f: &Fixture, projected: bool) -> Result<String, String> {
    let x = f.create("x", b"first lane");
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Hold);
    let options = bounded(Duration::from_secs(2));
    if projected {
        return published(f, SyncTarget::Stage(x), 60, options)
            .await
            .map(|()| String::new())
            .map_err(|error| error.to_string());
    }
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(60))
        .await
        .unwrap();
    Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(61),
        &mut Delay,
        RecoveryIntent::Continue,
        options,
    ))
    .await
    .map(|result| format!("{:?}", result.outcome))
    .map_err(|error| error.to_string())
}

/// A lane whose own deadline has passed is driven to its landing under the
/// next published caller's fresh deadline, before that caller's own
/// capture lands: a projected or a whole-tree first lane, live or after a
/// restart.
#[tokio::test]
async fn projected_takeover_uses_caller_deadline() {
    let mut outcomes = Vec::new();
    for (projected, restart) in [(true, false), (false, false), (true, true), (false, true)] {
        let f = Fixture::new().await;
        let first = expired_lane(&f, projected).await;
        // Written after the first lane's capture: a reopened mount refuses
        // writes until that lane lands.
        let y = f.create("y", b"second caller");
        let f = if restart {
            settle_disk(&f.io);
            f.restart().await
        } else {
            f
        };
        let second = published(&f, SyncTarget::Stage(y), 80, SyncOptions::default())
            .await
            .map_err(|error| error.to_string());
        outcomes.push((
            (projected, restart),
            first,
            second,
            head_file(&f, "x"),
            head_file(&f, "y"),
            lane_closed(&f),
            sends(&f),
        ));
    }
    let deadline = Err("intent refused: SyncDeadline".to_owned());
    let row = |key, sent| {
        (
            key,
            deadline.clone(),
            Ok(()),
            Some(b"first lane".to_vec()),
            Some(b"second caller".to_vec()),
            false,
            sent,
        )
    };
    assert_eq!(
        outcomes,
        [
            row((true, false), 3),
            row((false, false), 3),
            row((true, true), 3),
            row((false, true), 3),
        ],
        "the expired lane lands under the second caller's deadline, then its own capture"
    );
}

/// The retained record's candidate count, every candidate's manifest root
/// and the lane's charged attempts.
fn retained_evidence(f: &Fixture) -> (usize, BTreeSet<GrainId>, Option<u64>) {
    let record = saved(f);
    let manifests = record
        .candidates
        .iter()
        .map(|c| {
            granary_core::root::decode_root(&c.root)
                .unwrap()
                .manifest_root
        })
        .collect();
    let attempts = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.commit_progress(record.publication_id))
        .unwrap()
        .map(|progress| progress.attempts);
    (record.candidates.len(), manifests, attempts)
}

/// A first send whose answer never came, then a probe whose one GET fails:
/// the first caller ends unresolved, before exhausting its budget. The next
/// published caller re-probes under its own deadline, finds nothing landed
/// at the unchanged parent, and retains exactly one more candidate over the
/// same frozen manifest, its attempts still charged, before that lane lands
/// and then its own capture does.
#[tokio::test]
async fn projected_takeover_reprobes_failed_read_cycle() {
    let mut outcomes = Vec::new();
    for (projected, restart) in [(true, false), (false, false), (true, true)] {
        let f = Fixture::new().await;
        let x = f.create("x", b"first lane");
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Timeout);
        // The probe before the first send finds nothing; the one after it fails.
        f.remote.failed_probe.store(2, Ordering::Relaxed);
        let first = if projected {
            published(&f, SyncTarget::Stage(x), 60, SyncOptions::default())
                .await
                .map(|()| String::new())
                .map_err(|error| error.to_string())
        } else {
            let lane = f
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(60))
                .await
                .unwrap();
            Box::pin(f.engine.drive_commit(
                &lane,
                &mut Entropy(61),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            ))
            .await
            .map(|result| format!("{:?}", result.outcome))
            .map_err(|error| error.to_string())
        };
        let before = retained_evidence(&f);
        let y = f.create("y", b"second caller");
        let f = if restart {
            settle_disk(&f.io);
            f.restart().await
        } else {
            f
        };
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Hold);
        let second = f.engine.sync_published(
            seal(SyncTarget::Stage(y)),
            SyncOptions::default(),
            Entropy(80),
        );
        // The first lane sent nothing it held.
        let held = entered_hold(&f, 1).await;
        let during = held.then(|| retained_evidence(&f));
        f.remote.publish_hold.release();
        let second = second.wait().await.map_err(|error| error.to_string());
        outcomes.push((
            (projected, restart),
            first,
            before.0,
            before.2,
            during
                .as_ref()
                .map(|d| (d.0, d.1.len(), d.1 == before.1, d.2)),
            second,
            head_file(&f, "x"),
            head_file(&f, "y"),
            sends(&f),
        ));
    }
    let row = |key, first: Result<&str, &str>| {
        (
            key,
            first.map(str::to_owned).map_err(str::to_owned),
            1,
            Some(1),
            Some((2, 1, true, Some(2))),
            Ok(()),
            Some(b"first lane".to_vec()),
            Some(b"second caller".to_vec()),
            3,
        )
    };
    let unresolved = Err("intent refused: SyncCommitUnresolved");
    assert_eq!(
        outcomes,
        [
            row((true, false), unresolved),
            row((false, false), Ok("Unresolved")),
            row((true, true), unresolved),
        ],
        "a failed probe is re-probed under the next caller's deadline, one candidate more"
    );
}

/// Start a published sync of a new file `name`.
fn start(f: &Fixture, name: &str, seed: u8, options: SyncOptions) -> crate::SyncWaiter {
    let stage = f.create(name, name.as_bytes());
    f.engine
        .sync_published(seal(SyncTarget::Stage(stage)), options, Entropy(seed))
}

/// Two callers meet one retained lane whose takeover send is held. The
/// loser waits holding nothing: admission and engine state stay free, a
/// write proceeds, and only one send is made. Released, both land their
/// own captures. A third waiting caller that is cancelled still has its
/// capture published by its supervisor.
#[tokio::test]
async fn projected_driver_race_waits_without_locks() {
    let f = Fixture::new().await;
    let first = expired_lane(&f, true).await;
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Hold);
    let racing = start(&f, "a", 80, SyncOptions::default());
    let racing_too = start(&f, "b", 90, SyncOptions::default());
    // The first lane's held send, and one takeover send.
    let held = entered_hold(&f, 2).await;
    let cancelled = start(&f, "c", 100, SyncOptions::default());
    // Every caller has reached the lane before it is released.
    TokioSyncRuntime.sleep(Duration::from_millis(200)).await;
    let x = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.query_path(&[name("x")]))
        .map(|query| match query {
            crate::OverlayQuery::Found(found) => found.entry.and_then(|e| e.stage_id),
            _ => None,
        })
        .unwrap();
    let paused = (
        held,
        sends(&f),
        f.engine.admission_free_for_test(),
        f.engine.state_free_for_test(),
        x.map(|x| write(&f, x, 0, b"FIRST")).is_some(),
    );
    drop(cancelled);
    f.remote.publish_hold.release();
    let landed = (
        racing.wait().await.map_err(|error| error.to_string()),
        racing_too.wait().await.map_err(|error| error.to_string()),
    );
    let published_anyway = eventually(|| head_file(&f, "c").is_some()).await;
    assert_eq!(
        (
            first,
            paused,
            landed,
            published_anyway,
            (head_file(&f, "a"), head_file(&f, "b")),
            sends(&f),
        ),
        (
            Err("intent refused: SyncDeadline".to_owned()),
            (true, 2, true, true, true),
            (Ok(()), Ok(())),
            true,
            (Some(b"a".to_vec()), Some(b"b".to_vec())),
            5,
        ),
        "the loser waits without locks, then every caller lands its own capture"
    );
}

/// The driver's own caller reaches its deadline while its send is held: a
/// waiting caller is woken by that drive's end, takes the lane over and
/// lands it and then its own capture. A caller overtaken until its
/// deadline answers that deadline, with no authority refusal, fence or
/// send of its own.
#[tokio::test]
async fn projected_driver_race_survives_the_drivers_deadline() {
    let f = Fixture::new().await;
    let first = expired_lane(&f, true).await;
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Hold);
    let driver = start(&f, "a", 80, bounded(Duration::from_secs(3)));
    let held = entered_hold(&f, 2).await;
    let overtaken = start(&f, "o", 85, bounded(Duration::from_secs(1)));
    let waiting = start(&f, "b", 90, SyncOptions::default());
    let overtaken = overtaken.wait().await.map_err(|error| error.to_string());
    let after_overtaken = (sends(&f), lane_closed(&f));
    let driver = driver.wait().await.map_err(|error| error.to_string());
    let waiting = waiting.wait().await.map_err(|error| error.to_string());
    let unfenced = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|_| Ok(()))
        .is_ok();
    assert_eq!(
        (
            first,
            held,
            overtaken,
            after_overtaken,
            driver,
            waiting,
            (head_file(&f, "x"), head_file(&f, "b")),
            unfenced,
        ),
        (
            Err("intent refused: SyncDeadline".to_owned()),
            true,
            Err("intent refused: SyncDeadline".to_owned()),
            (2, true),
            Err("intent refused: SyncDeadline".to_owned()),
            Ok(()),
            (Some(b"first lane".to_vec()), Some(b"b".to_vec())),
            true,
        ),
        "a driver's deadline wakes the waiting caller; an overtaken one answers its deadline"
    );
}

/// Edits to x: a write at an offset, or a truncation when the bytes are empty.
type Edits = &'static [(u64, &'static [u8])];

/// `len` bytes no chunk boundary repeats.
fn patterned(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            state.to_be_bytes()[1]
        })
        .collect()
}

/// x as `seed` bytes; `edits` applied in order: a write at an offset, or a
/// truncation when the bytes are empty.
fn applied(seed: &[u8], edits: &[(u64, &[u8])]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    for (offset, edit) in edits {
        let offset = usize::try_from(*offset).unwrap();
        if edit.is_empty() {
            bytes.truncate(offset);
        } else {
            if bytes.len() < offset + edit.len() {
                bytes.resize(offset + edit.len(), 0);
            }
            bytes[offset..offset + edit.len()].copy_from_slice(edit);
        }
    }
    bytes
}

fn edit(f: &Fixture, stage: u64, edits: &[(u64, &[u8])]) {
    for (offset, bytes) in edits {
        f.store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                if bytes.is_empty() {
                    t.truncate(stage, *offset)
                } else {
                    t.write(stage, *offset, bytes).map(|_| ())
                }
            })
            .unwrap();
    }
}

/// x, held open, is synced: its mark M1 checkpoints the seed. `pre` edits
/// after M1 are captured by a whole-tree lane whose send is held until its
/// deadline, so the lane stays retained; `post` edits after the lane's
/// capture keep x dirty. Answers the fixture, x's stage and its seed.
async fn retained_tree_lane(
    pre: &[(u64, &[u8])],
    post: &[(u64, &[u8])],
) -> (Fixture, u64, Vec<u8>) {
    let f = Fixture::new().await;
    let seed = patterned(96 * 1024, 7);
    let x = f.create("x", &seed);
    super::published::hold(&f, "x");
    f.engine
        .sync(SyncTarget::Stage(x), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    edit(&f, x, pre);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Hold);
    let options = bounded(Duration::from_secs(2));
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(60))
        .await
        .unwrap();
    let expired = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(61),
        &mut Delay,
        RecoveryIntent::Continue,
        options,
    ))
    .await;
    assert!(expired.is_err(), "the whole-tree lane must stay retained");
    edit(&f, x, post);
    (f, x, seed)
}

/// Land a whole-tree commit of everything dirty, answering its refusal.
pub(super) async fn tree_commit(f: &Fixture, seed: u8) -> Result<(), String> {
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(seed))
        .await;
    match lane {
        Ok(lane) => Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(seed.wrapping_add(1)),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .map(|_| ()),
        Err(error) => Err(error),
    }
    .map_err(|error| error.to_string())
}

/// A retained whole-tree lane over x lands only through the next published
/// caller's takeover, which rebinds x at that lane's landing L.
/// The published sync of `synced` then lands, and a sync of another file
/// is followed by a whole-tree commit. Answers that sync, the head's x,
/// and the x every landed and later edit makes.
async fn stale_mark(
    pre: &[(u64, &[u8])],
    post: &[(u64, &[u8])],
    synced: &str,
) -> (Result<(), String>, Option<Vec<u8>>, Vec<u8>) {
    let (f, x, seed) = retained_tree_lane(pre, post).await;
    let target = if synced == "x" {
        x
    } else {
        f.create(synced, b"another file")
    };
    let mut result = published(&f, SyncTarget::Stage(target), 80, SyncOptions::default())
        .await
        .map_err(|error| error.to_string());
    if synced != "x" && result.is_ok() {
        // The next whole-tree commit captures x clean against L.
        f.create("z", b"dirty elsewhere");
        result = tree_commit(&f, 90).await;
    }
    (
        result,
        head_file(&f, "x"),
        applied(&applied(&seed, pre), post),
    )
}

/// A whole-tree lane that a published caller takes over rebinds x at its
/// landing L, and x's older mark M1 does not checkpoint L: x's next
/// published sync carries L's edits outside its own dirty ranges, at L's
/// size, grown or shrunk from M1's, and a clean x in the next whole-tree
/// commit names L, never M1.
#[tokio::test]
async fn projected_kind11_takeover_ignores_stale_mark() {
    let mut outcomes = Vec::new();
    let arms: [(&str, Edits, Edits, &str); 4] = [
        (
            "same size",
            &[(10, b"landed edit")],
            &[(60_000, b"post edit")],
            "x",
        ),
        (
            "grown",
            &[(10, b"landed edit"), (98_304, b"grown tail")],
            &[(60_000, b"post edit")],
            "x",
        ),
        (
            "shrunk",
            &[(10, b"landed edit"), (80_000, b"")],
            &[(60_000, b"post edit")],
            "x",
        ),
        ("clean", &[(10, b"landed edit")], &[], "y"),
    ];
    for (arm, pre, post, synced) in arms {
        let (result, head, expected) = stale_mark(pre, post, synced).await;
        outcomes.push((
            arm,
            result,
            head.as_ref().map(Vec::len),
            head == Some(expected),
        ));
    }
    assert_eq!(
        outcomes,
        [
            ("same size", Ok(()), Some(96 * 1024), true),
            ("grown", Ok(()), Some(98_304 + 10), true),
            ("shrunk", Ok(()), Some(80_000), true),
            ("clean", Ok(()), Some(96 * 1024), true),
        ],
        "a rebound stage's next capture keeps every landed edit at the landing's size"
    );
}

/// The takeover installs L, then the client crashes and reopens before x's
/// next sync: the reopened stage must not fold M1 back from its header.
/// x's published sync lands L's edits and its own; a clean x in the next
/// whole-tree commit names L.
#[tokio::test]
async fn projected_kind11_takeover_ignores_stale_mark_after_reopen() {
    let mut outcomes = Vec::new();
    for dirty in [true, false] {
        let pre: Edits = &[(10, b"landed edit")];
        let post: Edits = if dirty {
            &[(60_000, b"post edit")]
        } else {
            &[]
        };
        let (f, x, seed) = retained_tree_lane(pre, post).await;
        let other = f.create("t", b"takes the lane over");
        let takeover = published(&f, SyncTarget::Stage(other), 80, SyncOptions::default())
            .await
            .map_err(|error| error.to_string());
        settle_disk(&f.io);
        let f = f.restart_at_head().await;
        let result = if dirty {
            published(&f, SyncTarget::Stage(x), 90, SyncOptions::default())
                .await
                .map_err(|error| error.to_string())
        } else {
            f.create("z", b"dirty elsewhere");
            tree_commit(&f, 90).await
        };
        let expected = applied(&applied(&seed, pre), post);
        outcomes.push((
            dirty,
            takeover,
            result,
            head_file(&f, "x") == Some(expected),
        ));
    }
    assert_eq!(
        outcomes,
        [(true, Ok(()), Ok(()), true), (false, Ok(()), Ok(()), true)],
        "(x dirty, takeover, next capture, head x holds every landed edit)"
    );
}

/// The dirty ages the coalescer schedules from: the first contributing
/// span's first write and the last span's last write, each an hour on.
fn dirty_ages(f: &Fixture) -> (Option<tokio::time::Instant>, Option<tokio::time::Instant>) {
    let due = |quiesce_delay, max_coalesce_delay| {
        let options = SyncOptions {
            quiesce_delay,
            max_coalesce_delay,
            ..SyncOptions::default()
        };
        match f
            .store
            .lock()
            .unwrap()
            .coalesce_state(&options, TokioSyncRuntime.now())
            .unwrap()
        {
            crate::writable_store::sync_engine::CoalesceState::WaitUntil(at) => at,
            _ => None,
        }
    };
    let (hour, day) = (Duration::from_hours(1), Duration::from_hours(24));
    (due(day, hour), due(hour, day))
}

/// Create `name`, recording when it was written in `writes`.
fn timed(
    f: &Fixture,
    name: &str,
    writes: &mut Vec<(String, tokio::time::Instant, tokio::time::Instant)>,
) -> u64 {
    let before = TokioSyncRuntime.now();
    let stage = f.create(name, name.as_bytes());
    writes.push((name.to_owned(), before, TokioSyncRuntime.now()));
    stage
}

/// A published sync of x whose dirty spans can straddle its boundary: y
/// before the seal and z after it, before the boundary is recorded, when
/// `straddle`; w after the boundary always. Answers the sync, which writes
/// the residual's first and last ages are, a coalesced commit's landing,
/// and which of y, z and w the head then holds.
async fn straddled(straddle: bool) -> (Result<(), String>, [Option<String>; 2], bool, Vec<bool>) {
    let f = Fixture::new().await;
    let mut writes = Vec::new();
    let pause = || TokioSyncRuntime.sleep(Duration::from_millis(100));
    if straddle {
        timed(&f, "y", &mut writes);
        pause().await;
    }
    let x = timed(&f, "x", &mut writes);
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.capture", "after", 1, FaultAction::Block);
    let _resume = super::published::ResumeOnDrop(&faults);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Hold);
    let publishing = f.engine.sync_published(
        seal(SyncTarget::Stage(x)),
        SyncOptions::default(),
        Entropy(70),
    );
    fired(&faults, "sync.capture", "after").await;
    pause().await;
    if straddle {
        timed(&f, "z", &mut writes);
    }
    faults.resume();
    assert!(entered_hold(&f, 1).await, "the published send was not held");
    pause().await;
    timed(&f, "w", &mut writes);
    f.remote.publish_hold.release();
    let result = publishing.wait().await.map_err(|error| error.to_string());
    let hour = Duration::from_hours(1);
    let (first, last) = dirty_ages(&f);
    let written = |at: Option<tokio::time::Instant>| {
        let at = at?.checked_sub(hour)?;
        writes
            .iter()
            .find(|(_, before, after)| *before <= at && at <= *after)
            .map(|(name, _, _)| name.clone())
    };
    let ages = [written(first), written(last)];
    let options = SyncOptions {
        quiesce_delay: Duration::from_millis(1),
        max_coalesce_delay: Duration::from_millis(1),
        ..SyncOptions::default()
    };
    let coalesced = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(f.engine.coalesce_commit(options, &mut Entropy(72))),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|r| matches!(r.outcome, PublicationOutcome::Landed(_))));
    let head = ["y", "z", "w"]
        .iter()
        .map(|name| head_file(&f, name).is_some())
        .collect();
    (result, ages, coalesced, head)
}

/// Spans on both sides of a published sync's boundary stay whole for its
/// residual: regrouped, they keep the first contributing write's age and
/// the last one's, and the real coalescer commits the residual. A span
/// holding only writes the sync published contributes nothing: a write
/// after the boundary starts a span of its own, and the residual's age is
/// that write's.
#[tokio::test]
async fn projected_multispan_residual_stays_dirty() {
    let some = |name: &str| Some(name.to_owned());
    assert_eq!(
        [straddled(true).await, straddled(false).await],
        [
            (Ok(()), [some("y"), some("w")], true, vec![true, true, true]),
            (
                Ok(()),
                [some("w"), some("w")],
                true,
                vec![false, false, true]
            ),
        ],
        "the residual keeps its contributing spans' ages, and only theirs"
    );
}

/// A mount view that refuses every install; the first only once the test
/// releases it.
#[derive(Default)]
struct HeldRefusal {
    release: Notify,
    installs: AtomicU64,
}
impl crate::sync::MountViewHook for HeldRefusal {
    fn install(
        &self,
        _: crate::sync::PublishedRoot,
        _: tokio::time::Instant,
        _: crate::sync::LandedCommit,
    ) -> crate::sync::ViewInstall<'_> {
        Box::pin(async move {
            if self.installs.fetch_add(1, Ordering::AcqRel) == 0 {
                self.release.notified().await;
            }
            (
                Err(crate::sync::refused("ViewRefused")),
                crate::sync::Revocation::none(),
            )
        })
    }
    fn adopt(
        &self,
        _: crate::sync::PublishedRoot,
        _: tokio::time::Instant,
        _: crate::sync::AdoptionCommit,
    ) -> crate::sync::ViewInstall<'_, crate::sync::Adopted> {
        Box::pin(async {
            (
                Err(crate::sync::refused("ViewRefused")),
                crate::sync::Revocation::none(),
            )
        })
    }
    fn close(
        &self,
        _: crate::CoordinationError,
        _: tokio::time::Instant,
    ) -> crate::sync::ViewInstall<'_> {
        Box::pin(async {
            (
                Err(crate::sync::refused("ViewRefused")),
                crate::sync::Revocation::none(),
            )
        })
    }
}

/// The driver's caller leaves at its deadline while the install it started
/// keeps the driver. When that install ends without switching the view,
/// releasing the driver is the only change: it wakes the waiting caller,
/// whose own drive meets the view's refusal well before its deadline.
#[tokio::test]
async fn projected_driver_race_wakes_on_the_last_drivers_release() {
    let f = Fixture::new().await;
    let first = expired_lane(&f, true).await;
    let hook = Arc::new(HeldRefusal::default());
    f.engine.set_view_hook(hook.clone()).unwrap();
    let driver = start(&f, "a", 80, bounded(Duration::from_secs(2)));
    let driver = driver.wait().await.map_err(|error| error.to_string());
    let installing = hook.installs.load(Ordering::Acquire);
    let started = TokioSyncRuntime.now();
    let waiting = start(&f, "b", 90, bounded(Duration::from_secs(20)));
    TokioSyncRuntime.sleep(Duration::from_millis(300)).await;
    hook.release.notify_one();
    let waiting = waiting.wait().await.map_err(|error| error.to_string());
    assert_eq!(
        (
            first,
            driver,
            installing,
            waiting,
            hook.installs.load(Ordering::Acquire),
            TokioSyncRuntime.now() < started + Duration::from_secs(10),
        ),
        (
            Err("intent refused: SyncDeadline".to_owned()),
            Err("intent refused: SyncDeadline".to_owned()),
            1,
            Err("intent refused: ViewRefused".to_owned()),
            2,
            true,
        ),
        "the last driver's release wakes the waiting caller"
    );
}

/// A whole-tree construction whose caller stopped waiting is still
/// retained by its supervisor, and nobody drives it. A published caller
/// that met it under construction waits for its retention, then takes it
/// over and lands it and its own capture, well before its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn projected_takeover_waits_for_an_unattended_construction() {
    let f = Fixture::new().await;
    f.create("x", b"constructed");
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    let _resume = super::published::ResumeOnDrop(&faults);
    let mut constructing = Box::pin(
        f.engine
            .construct_commit(SyncOptions::default(), &mut Entropy(60)),
    );
    hold_at_seam(&mut constructing, &faults, "sync.commit", "captured").await;
    drop(constructing);
    let started = TokioSyncRuntime.now();
    let caller = start(&f, "y", 80, bounded(Duration::from_secs(20)));
    TokioSyncRuntime.sleep(Duration::from_millis(300)).await;
    faults.resume();
    let caller = caller.wait().await.map_err(|error| error.to_string());
    assert_eq!(
        (
            caller,
            head_file(&f, "x"),
            head_file(&f, "y"),
            TokioSyncRuntime.now() < started + Duration::from_secs(10),
        ),
        (
            Ok(()),
            Some(b"constructed".to_vec()),
            Some(b"y".to_vec()),
            true,
        ),
        "a retained construction wakes the caller waiting for it"
    );
}
