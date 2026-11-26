// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A failed engine caller's retained Register owes reconciliation, not
//! capture work: it neither holds the drain nor closes the admitted view,
//! while a Register no engine caller tracks still does.

use super::*;
use crate::writable_store::ViewContext;

/// Fail one sync caller at a registration seam: before its Register is
/// sent, or after the authority answered it but before the answer is
/// applied. Either leaves that exact request retained, nonterminal and with
/// its context cleared.
async fn fail_one_caller(f: &Fixture, phase: &'static str) -> u64 {
    let stage = f.create("failed", b"failed caller");
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.registration", phase, 1, FaultAction::Fail);
    let failed = f
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await;
    let retained = f.pending_registrations();
    assert_eq!(
        (
            failed.is_err(),
            faults.sync_fired().len(),
            retained.len(),
            retained.iter().all(|pending| pending.context.is_empty()),
            f.remote.attempts.lock().unwrap().len(),
        ),
        (true, 1, 1, true, usize::from(phase == "after_response")),
        "premise: one failed caller retaining its request at {phase}: {failed:?}"
    );
    stage
}

/// Every Register still carrying context is queued, and every other
/// nonterminal one belongs to a failed caller or, with a lane closed, is the
/// lane's own single refresh. The drain's context term rests on this.
fn provenance(f: &Fixture) -> Result<(), String> {
    let local = f.store.lock().unwrap();
    let (queued, failed, lane) = local.sync_provenance_for_test();
    let registers: Vec<_> = local
        .snapshot()
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Register)
        .map(|pending| {
            (
                pending.generation().unwrap(),
                pending.terminal,
                pending.context.is_empty(),
            )
        })
        .collect();
    let unqueued_context = registers
        .iter()
        .filter(|(generation, _, empty)| !empty && !queued.contains(generation))
        .count();
    let untracked = registers
        .iter()
        .filter(|(generation, terminal, empty)| !terminal && *empty && !failed.contains(generation))
        .count();
    if unqueued_context == 0 && untracked <= usize::from(lane) {
        Ok(())
    } else {
        Err(format!(
            "registers={registers:?}, queued={queued:?}, failed={failed:?}, lane={lane}"
        ))
    }
}

fn assert_provenance(f: &Fixture, state: &str) {
    if let Err(found) = provenance(f) {
        panic!("{state}: {found}");
    }
}

/// The names at the top of the authority's registered root.
fn registered_names(f: &Fixture) -> Vec<Vec<u8>> {
    let root = f.remote.authority.lock().unwrap().root.clone();
    let doc = granary_core::root::decode_root(&root).unwrap();
    crate::writable_store::capture::entries(f.content.as_ref(), doc.manifest_root, 1)
        .unwrap()
        .iter()
        .map(|entry| entry.name.as_bytes().to_vec())
        .collect()
}

/// The drain, readiness and every view check delegating to it, as one tuple.
fn gates(f: &Fixture) -> (bool, Result<(), String>, bool, Result<(), String>) {
    let mut local = f.store.lock().unwrap();
    let receipt = intent::decode_receipt(&local.snapshot().current).unwrap();
    let owner = (local.writer_uuid(), receipt.epoch, receipt.instance);
    let text = |error: CoordinationError| error.to_string();
    (
        local.sync_queue_empty(),
        local.check_readiness().map_err(text),
        local.mount_view_context().is_ok(),
        local.check_mount_binding(owner).map(|_| ()).map_err(text),
    )
}

/// Bind a mount pin at the fixture's base, so the binding check compares
/// the admitted base with it.
fn bind_pin(f: &Fixture) {
    f.store.lock().unwrap().bind_mount(Arc::new(ViewContext {
        base_id: f.base,
        base_seq: 1,
        base_bytes: vec![],
        bins: Arc::from([]),
        entries: BTreeMap::new(),
        pin_files: BTreeMap::new(),
        pin_nodes: BTreeMap::new(),
    }));
}

fn release_refused(f: &Fixture) -> Option<String> {
    f.store
        .lock()
        .unwrap()
        .prepare_release(&Tick(4), Duration::from_secs(1), None)
        .err()
        .map(|error| error.to_string())
}

const OPEN: (bool, Result<(), String>, bool, Result<(), String>) = (true, Ok(()), true, Ok(()));

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one row sets the failed-caller, queued-capture and lane-refresh Registers against the same gates"
)]
async fn commit_drains_failed_register_contexts() {
    let drain_pending = Some("intent refused: IntentDrainPending".to_owned());

    // A failed caller, its Register unsent or its answer lost: drain,
    // readiness and view stay open, release does not, and nothing is sent or
    // retired to open them. A covering receipt then retires the failed
    // request. An unrelated file's covering sync publishes only that file,
    // since the failed caller acknowledged nothing; retrying the failed file
    // publishes its bytes.
    for (phase, sent) in [("before_dispatch", 0), ("after_response", 1)] {
        let f = Fixture::new().await;
        bind_pin(&f);
        let stage = fail_one_caller(&f, phase).await;
        assert_provenance(&f, "failed caller");
        assert_eq!(
            (
                gates(&f),
                release_refused(&f),
                f.pending_registrations().len(),
                f.remote.attempts.lock().unwrap().len(),
            ),
            (OPEN, drain_pending.clone(), 1, sent),
            "{phase}: a failed caller's empty-context Register must not hold the drain or the view"
        );
        let covering = if sent == 0 {
            f.create("other", b"covering")
        } else {
            stage
        };
        f.engine
            .sync(SyncTarget::Stage(covering), SyncOptions::default())
            .wait()
            .await
            .unwrap();
        assert_provenance(&f, "covered");
        let names = registered_names(&f);
        assert_eq!(
            (f.pending_registrations().len(), gates(&f), names),
            (
                0,
                OPEN,
                vec![if sent == 0 {
                    b"other".to_vec()
                } else {
                    b"failed".to_vec()
                }]
            ),
            "{phase}: a covering receipt must retire the failed request"
        );
        if sent == 1 {
            let root = f.remote.authority.lock().unwrap().root.clone();
            assert_file(&f, &root, "failed", b"failed caller");
        }
    }

    // A sync in flight: its queued capture and context hold the drain, while
    // its Register still passes readiness, the check attached writes make.
    let f = Fixture::new().await;
    bind_pin(&f);
    let stage = f.create("queued", b"in flight");
    f.remote.hold_first.store(true, Ordering::Relaxed);
    let waiter = f
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    f.remote.entered.notified().await;
    let queued = (
        f.pending_registrations()
            .iter()
            .map(|pending| pending.context.is_empty())
            .collect::<Vec<_>>(),
        gates(&f),
    );
    assert_provenance(&f, "queued");
    f.remote.release.notify_one();
    waiter.wait().await.unwrap();
    assert_eq!(
        queued,
        (vec![false], (false, Ok(()), true, Ok(()))),
        "a queued capture must hold the drain but not the view"
    );

    // An ordinary commit drains past a failed caller. Its closed lane keeps
    // the view admitted before the publication settles; its landed refresh,
    // a Register the finish is driving, keeps the view admitted and holds
    // release until the authority answers it.
    let f = Fixture::new().await;
    bind_pin(&f);
    fail_one_caller(&f, "before_dispatch").await;
    f.create("committed", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let (unsettled, sync_open) = {
        let mut local = f.store.lock().unwrap();
        let (scope, volume) = (
            local.snapshot().scope.clone(),
            local.snapshot().volume.clone(),
        );
        (
            local
                .publication_transaction(|j| j.load(&scope, &volume))
                .unwrap()
                .is_some_and(|record| !record.is_complete()),
            local.sync_admission_open().unwrap(),
        )
    };
    assert_provenance(&f, "closed lane");
    assert_eq!(
        (
            unsettled,
            sync_open,
            gates(&f),
            f.remote.attempts.lock().unwrap().len(),
            f.pending_registrations().len(),
        ),
        (true, false, OPEN, 0, 1),
        "a closed lane must keep the view admitted while its publication is unsettled, \
         with the failed request neither sent nor retired to open the drain"
    );
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Block);
    let engine = f.engine.clone();
    let mut driving = Box::pin(async move {
        Box::pin(engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
    });
    hold_at_seam(&mut driving, &faults, "sync.commit", "landed_refresh").await;
    // Observed before the assertion, so a failing window still releases the drive.
    let window = (gates(&f), release_refused(&f));
    let held = provenance(&f);
    faults.resume();
    let landed = driving.await;
    assert_eq!(
        window,
        ((true, Ok(()), true, Ok(())), drain_pending),
        "the refresh Register its finish is driving keeps the view admitted, \
         and release still waits for the drain"
    );
    assert_eq!(held, Ok(()), "refresh window provenance");
    let landed = landed.unwrap();
    assert_provenance(&f, "landed");
    let ready = f.store.lock().unwrap().check_readiness().is_ok();
    assert_eq!(
        (
            matches!(landed.outcome, PublicationOutcome::Landed(_)),
            ready,
            f.remote.attempts.lock().unwrap().len(),
            f.pending_registrations().len(),
        ),
        (true, true, 1, 0),
        "the answered refresh must reopen readiness; it is the only Register sent, \
         and its covering receipt is what retires the failed request"
    );
}

/// The drain's backoff ceilings, in ms: 40 doubling per attempt, capped at
/// 5000 for the eighth. Each backoff is drawn from half its ceiling to it.
const CEILINGS: [u64; 8] = [40, 80, 160, 320, 640, 1280, 2560, 5000];

/// Restart the fixture's jitter stream at `seed`, or pin every draw to
/// `word`, and clear the runtime's sleep record, just before a drain. A
/// constant word of 0 would spin `Rng::below` forever; 1 and `u64::MAX` are
/// accepted at the first draw, as its smallest and largest results.
fn jitter_from(f: &Fixture, seed: u64, word: Option<u64>) {
    debug_assert!(word != Some(0), "a constant zero draw never settles");
    *f.content.jitter.lock().unwrap() = Some(SeededRng::new(seed));
    *f.content.jitter_word.lock().unwrap() = word;
    f.content.sleeps.lock().unwrap().clear();
}

/// The eight backoffs a drain draws from a stream seeded with `seed`.
fn seeded_backoffs(seed: u64) -> Vec<Duration> {
    let mut rng = SeededRng::new(seed);
    CEILINGS
        .iter()
        .map(|ceiling| Duration::from_millis(ceiling / 2 + rng.below(ceiling - ceiling / 2 + 1)))
        .collect()
}

/// A drain that never empties, jittered as `jitter_from(seed, word)`, with
/// its outcome, virtual elapsed time and every backoff it slept.
async fn unresolved_drain(
    f: &Fixture,
    seed: u64,
    word: Option<u64>,
) -> (Result<(), String>, Duration, Vec<Duration>) {
    let stage = f.create("held", b"unanswered through the drain");
    f.remote.hold_first.store(true, Ordering::Relaxed);
    let waiter = f
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    f.remote.entered.notified().await;
    jitter_from(f, seed, word);
    let start = TokioSyncRuntime.now();
    let refusal = f.engine.begin_commit(SyncOptions::default()).await;
    let elapsed = TokioSyncRuntime.now() - start;
    let sleeps = f.content.sleeps.lock().unwrap().clone();
    f.remote.release.notify_one();
    waiter.wait().await.unwrap();
    (
        refusal.map(|_| ()).map_err(|error| error.to_string()),
        elapsed,
        sleeps,
    )
}

/// The drain's last backoff interval is still a wait for the queue: a
/// registration answered after the final poll, while its backoff sleeps, is
/// captured when that sleep ends rather than refused as unresolved. Under
/// the seeded stream the polls fall after each drawn backoff, and the
/// eighth backoff ends at their sum.
#[tokio::test(start_paused = true)]
async fn commit_drain_polls_again_after_its_last_backoff() {
    let f = Fixture::new().await;
    let stage = f.create("late", b"answered in the last interval");
    f.remote.hold_first.store(true, Ordering::Relaxed);
    let waiter = f
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    f.remote.entered.notified().await;
    let backoffs = seeded_backoffs(0);
    let last_poll: Duration = backoffs[..7].iter().sum();
    assert!(
        backoffs[7] > Duration::from_millis(1),
        "premise: the eighth backoff outlasts the release: {backoffs:?}"
    );
    jitter_from(&f, 0, None);
    let start = TokioSyncRuntime.now();
    let remote = f.remote.clone();
    let release = TokioSyncRuntime.spawn(async move {
        TokioSyncRuntime
            .sleep(last_poll + Duration::from_millis(1))
            .await;
        remote.release.notify_one();
    });
    let capture = f.engine.begin_commit(SyncOptions::default()).await;
    let elapsed = TokioSyncRuntime.now() - start;
    let sleeps = f.content.sleeps.lock().unwrap().clone();
    release.await.unwrap();
    waiter.wait().await.unwrap();
    assert_eq!(
        (
            capture.map(|_| ()).map_err(|error| error.to_string()),
            elapsed,
            sleeps,
        ),
        (Ok(()), backoffs.iter().sum(), backoffs),
        "a registration answered during the last backoff must be captured when it ends"
    );
}

/// A registration still unanswered at the drain's last poll is refused as
/// unresolved when the eighth backoff ends, at the seeded backoffs' sum:
/// that poll is the last, so no further backoff follows it before the
/// refusal.
#[tokio::test(start_paused = true)]
async fn commit_drain_refuses_when_its_last_backoff_ends() {
    let f = Fixture::new().await;
    let backoffs = seeded_backoffs(0);
    assert_eq!(
        unresolved_drain(&f, 0, None).await,
        (
            Err("intent refused: SyncCommitUnresolved".to_owned()),
            backoffs.iter().sum(),
            backoffs,
        ),
        "a drain that never empties must refuse when its eighth backoff ends"
    );
}

/// Jitter keeps each backoff in the upper half of its ceiling: the smallest
/// draw sleeps each half, so the drain refuses no sooner than their 5040 ms
/// sum, and the largest sleeps each ceiling, refusing at their 10080 ms sum
/// and never later.
#[tokio::test(start_paused = true)]
async fn commit_drain_jitter_stays_within_its_ceilings() {
    let mut drains = Vec::new();
    for word in [1, u64::MAX] {
        let f = Fixture::new().await;
        drains.push(unresolved_drain(&f, 0, Some(word)).await);
    }
    let unresolved = || Err("intent refused: SyncCommitUnresolved".to_owned());
    let ceilings: Vec<_> = CEILINGS
        .iter()
        .map(|&ms| Duration::from_millis(ms))
        .collect();
    let halves = [20, 40, 80, 160, 320, 640, 1280, 2500].map(Duration::from_millis);
    assert_eq!(
        drains,
        [
            (unresolved(), Duration::from_millis(5_040), halves.to_vec()),
            (unresolved(), Duration::from_millis(10_080), ceilings),
        ],
        "every backoff must be drawn from half its ceiling to the ceiling"
    );
}
