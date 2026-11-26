// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A published sync: its candidate is the signed projection its sync
//! registered, retained under a projected boundary, and it succeeds only on
//! its own landing, installed before its deadline.

use super::projected::{lane_closed, reservations, seal};
use super::*;

/// Resumes every blocked fault point, so a failing row never leaves one held.
pub(super) struct ResumeOnDrop<'a>(pub(super) &'a FaultControl);
impl Drop for ResumeOnDrop<'_> {
    fn drop(&mut self) {
        self.0.resume();
    }
}

pub(super) async fn published(
    f: &Fixture,
    target: SyncTarget,
    seed: u8,
    options: SyncOptions,
) -> Result<(), CoordinationError> {
    f.engine
        .sync_published(seal(target), options, Entropy(seed))
        .wait()
        .await
}

pub(super) fn bounded(resolution_bound: Duration) -> SyncOptions {
    SyncOptions {
        resolution_bound,
        ..SyncOptions::default()
    }
}

/// The published head's file `name`, if it has one.
pub(super) fn head_file(f: &Fixture, name: &str) -> Option<Vec<u8>> {
    let head = f
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    let doc = granary_core::root::decode_root(&head).unwrap();
    let entries =
        crate::writable_store::capture::entries(f.content.as_ref(), doc.manifest_root, 1).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.name.as_bytes() == name.as_bytes())?;
    let EntryKind::File { size, grains, .. } = &entry.kind else {
        return None;
    };
    let payload = manifest::node::file_payload(*size, grains).unwrap();
    Some(
        f.content
            .read_content(GrainId::of(&payload), 0, usize::try_from(*size).unwrap())
            .unwrap(),
    )
}

/// What the mount reads at `name`, staged or clean: none if it has no such
/// file or cannot serve it.
pub(super) fn local_file(f: &Fixture, name: &str) -> Option<Vec<u8>> {
    let path = [granary_core::manifest::Name::new(name.as_bytes().to_vec()).unwrap()];
    let mut local = f.store.lock().unwrap();
    let crate::OverlayQuery::Found(found) =
        local.overlay_transaction(|t| t.query_path(&path)).ok()?
    else {
        return None;
    };
    let entry = found.entry?;
    let length = usize::try_from(entry.size).unwrap();
    Some(
        local
            .overlay_transaction(|t| match entry.stage_id {
                Some(stage) => t.read_stage(stage, 0, length),
                None => t.read_base(&path, 0, length),
            })
            .unwrap(),
    )
}

/// Make every name and byte durable, as a clean shutdown would.
pub(super) fn settle_disk(io: &SimIo) {
    let mut model = io.0.lock().unwrap();
    model.durable_names = model.names.clone();
    model.durable_directories = model.directories.clone();
    for (live, durable) in model.files.values_mut() {
        durable.clone_from(live);
    }
}

/// Hold `path`'s stage open, so a landing carries it rather than retiring it.
pub(super) fn hold(f: &Fixture, path: &str) {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.open_stage(&[granary_core::manifest::Name::new(path.as_bytes().to_vec()).unwrap()])
        })
        .unwrap();
}

pub(super) fn write(f: &Fixture, stage: u64, offset: u64, bytes: &[u8]) {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, offset, bytes).map(|_| ()))
        .unwrap();
}

/// Land a whole-tree commit of everything written so far.
pub(super) async fn commit_all(f: &Fixture, seed: u8) {
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(seed))
        .await
        .unwrap();
    let landed = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(seed + 1),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    assert!(matches!(landed.outcome, PublicationOutcome::Landed(_)));
}

pub(super) fn fsyncs(f: &Fixture, result: &str) -> String {
    let label = format!("granary_client_syncs_total{{outcome=\"{result}\"}}");
    f.metrics()
        .lines()
        .find(|line| line.starts_with(&label))
        .map_or_else(|| "absent".to_owned(), ToOwned::to_owned)
}

/// The durable journal's projected boundaries, by their selection.
fn projected_selections(
    io: &SimIo,
) -> Vec<Option<granary_core::overlay_journal::ProjectedSelection>> {
    let model = io.0.lock().unwrap();
    let id = model
        .names
        .iter()
        .find(|(path, _)| path.file_name().unwrap() == "journal")
        .unwrap()
        .1;
    let mut selections = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&model.files[id].1, |_, record| {
        if let Record::ProjectedBoundary { selection, .. } = record {
            selections.push(*selection);
        }
    })
    .unwrap();
    selections
}

/// A published sync of x publishes x's captured bytes and y's durable ones,
/// never y's later local bytes, longer than A, or a file never synced: the
/// head has y=A while the mount keeps y=B and z. The residual stays dirty,
/// so the coalescer's ordinary commit later publishes them.
#[tokio::test]
async fn projected_candidate_excludes_older_unsynced_bytes() {
    let f = Fixture::new().await;
    let y = f.create("y", b"durable A");
    hold(&f, "y");
    commit_all(&f, 60).await;
    write(&f, y, 0, b"local B, and longer");
    f.create("z", b"never synced");
    let x = f.create("x", b"selected");
    let result = published(&f, SyncTarget::Stage(x), 70, SyncOptions::default())
        .await
        .map_err(|error| error.to_string());
    let observed = |f: &Fixture| {
        (
            head_file(f, "x"),
            head_file(f, "y"),
            head_file(f, "z"),
            local_file(f, "y"),
            local_file(f, "z"),
        )
    };
    let landed = observed(&f);
    let options = SyncOptions {
        quiesce_delay: Duration::from_millis(1),
        max_coalesce_delay: Duration::from_millis(1),
        ..SyncOptions::default()
    };
    let scheduled = f
        .store
        .lock()
        .unwrap()
        .coalesce_state(&options, TokioSyncRuntime.now())
        .map(|state| state != crate::writable_store::sync_engine::CoalesceState::Clean)
        .map_err(|error| error.to_string());
    let coalesced = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(f.engine.coalesce_commit(options, &mut Entropy(72))),
    )
    .await
    .map(|result| result.map(|r| matches!(r.outcome, PublicationOutcome::Landed(_))));
    let later = (head_file(&f, "y"), head_file(&f, "z"));
    let some = |bytes: &[u8]| Some(bytes.to_vec());
    let expected = (
        some(b"selected"),
        some(b"durable A"),
        None,
        some(b"local B, and longer"),
        some(b"never synced"),
    );
    assert_eq!(
        (
            result,
            landed,
            scheduled,
            coalesced.as_ref().map(|r| r.as_ref().ok().copied()).ok(),
            later,
        ),
        (
            Ok(()),
            expected,
            Ok(true),
            Some(Some(true)),
            (some(b"local B, and longer"), some(b"never synced")),
        ),
        "the head holds only x's capture and durable bytes; the residual stays local and scheduled"
    );
}

/// Writes after the seal, while the sync uploads, stay local: the head has
/// x's captured bytes, y's durable ones and no z, and the mount has the
/// later bytes and z.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn projected_capture_keeps_writes_during_sync() {
    let f = Fixture::new().await;
    let y = f.create("y", b"durable y");
    hold(&f, "y");
    commit_all(&f, 60).await;
    let x = f.create("x", b"captured x");
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.capture", "after", 1, FaultAction::Block);
    let _resume = ResumeOnDrop(&faults);
    let mut publishing = Box::pin(published(
        &f,
        SyncTarget::Stage(x),
        70,
        SyncOptions::default(),
    ));
    hold_at_seam(&mut publishing, &faults, "sync.capture", "after").await;
    write(&f, x, 0, b"LATER X");
    write(&f, y, 0, b"LATER Y");
    f.create("z", b"created during the sync");
    faults.resume();
    let result = publishing.await.map_err(|error| error.to_string());
    let mounted = (
        local_file(&f, "x"),
        local_file(&f, "y"),
        local_file(&f, "z"),
    );
    let head = (head_file(&f, "x"), head_file(&f, "y"), head_file(&f, "z"));
    let some = |bytes: &[u8]| Some(bytes.to_vec());
    assert_eq!(
        (result, head, mounted),
        (
            Ok(()),
            (some(b"captured x"), some(b"durable y"), None),
            (
                some(b"LATER Xd x"),
                some(b"LATER Y y"),
                some(b"created during the sync"),
            ),
        ),
        "writes after the seal stay local and out of the published candidate"
    );
}

/// The engine itself records the projected boundary: a file sync selects its
/// stage at the captured payload, a directory sync selects nothing. After a
/// send whose answer never came, x is overwritten in place and the engine
/// restarts: the recovered lane lands the captured bytes, and the mount keeps
/// the overwrite.
#[tokio::test]
async fn projected_boundary_restart_binds_selection() {
    use granary_core::overlay_journal::ProjectedSelection;
    let mut outcomes = Vec::new();
    for directory in [false, true] {
        let f = Fixture::new().await;
        let x = f.create("x", b"captured");
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::LandAfterDelay(Duration::from_mins(1)));
        let target = if directory {
            SyncTarget::Directory(None)
        } else {
            SyncTarget::Stage(x)
        };
        let unanswered = published(&f, target, 70, bounded(Duration::from_secs(5)))
            .await
            .map_err(|error| error.to_string());
        // Premise: the stalled send was made; nothing else is scripted.
        let sent = f.remote.publication_sends.lock().unwrap().len();
        f.remote.publication_plan.lock().unwrap().clear();
        let captured = f
            .content
            .payloads
            .lock()
            .unwrap()
            .iter()
            .find_map(|(id, (size, _))| (*size == 8).then_some(*id));
        let selections = projected_selections(&f.io);
        write(&f, x, 0, b"CAPTURED");
        settle_disk(&f.io);
        let f = f.restart().await;
        let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
        let landed = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(90),
            &mut Delay,
            RecoveryIntent::ExplicitRecovery,
            SyncOptions::default(),
        ))
        .await
        .map(|result| matches!(result.outcome, PublicationOutcome::Landed(_)))
        .map_err(|error| error.to_string());
        let expected_selection = if directory {
            None
        } else {
            captured.map(|content| ProjectedSelection {
                stage_id: x,
                content,
                size: 8,
            })
        };
        outcomes.push((
            directory,
            unanswered,
            sent,
            selections == vec![expected_selection],
            landed,
            head_file(&f, "x"),
            local_file(&f, "x"),
            f.remote.publication_sends.lock().unwrap().len(),
        ));
    }
    let deadline = Err("intent refused: SyncDeadline".to_owned());
    let overwrite = Some(b"CAPTURED".to_vec());
    assert_eq!(
        outcomes,
        [
            (
                false,
                deadline.clone(),
                1,
                true,
                Ok(true),
                Some(b"captured".to_vec()),
                overwrite.clone(),
                2
            ),
            // A never-synced file is outside a directory's projection.
            (true, deadline, 1, true, Ok(true), None, overwrite, 2),
        ],
        "a restarted projected lane lands its recorded selection, never the overwrite"
    );
}

/// A published sync of a clean, unchanged file publishes once, its boundary
/// selecting no stage: its bytes come from the base.
#[tokio::test]
async fn projected_clean_file_selects_no_stage() {
    let f = Fixture::new().await;
    f.create("x", b"committed x");
    commit_all(&f, 60).await;
    f.create("y", b"never synced");
    let path = [granary_core::manifest::Name::new(b"x".to_vec()).unwrap()];
    let entry = {
        let mut local = f.store.lock().unwrap();
        let crate::OverlayQuery::Found(found) =
            local.overlay_transaction(|t| t.query_path(&path)).unwrap()
        else {
            panic!("x is present");
        };
        found.entry.unwrap()
    };
    let before = f.remote.publication_sends.lock().unwrap().len();
    let result = published(
        &f,
        SyncTarget::File(entry.inode),
        70,
        SyncOptions::default(),
    )
    .await
    .map_err(|error| error.to_string());
    assert_eq!(
        (
            entry.stage_id,
            result,
            f.remote.publication_sends.lock().unwrap().len() - before,
            head_file(&f, "x"),
            head_file(&f, "y"),
        ),
        (None, Ok(()), 1, Some(b"committed x".to_vec()), None),
        "a clean file's published sync lands with no selected stage"
    );
}

/// After its projected boundary is durable, a refused or unresolved
/// published sync keeps its lane and exactly the lane charge its candidate's
/// entries cost, as a restart charges it; only a proven non-landing strip
/// or a landing releases it, once.
#[tokio::test]
async fn projected_seal_refusal_balances_graphs_after_its_boundary() {
    // x is selected; w was never synced, so the live namespace costs more
    // than the candidate's entries.
    let lane_charge = crate::overlay_store::commit_graph_charge_of(&[OverlayEntry {
        path: vec![name("x")],
        inode: 0,
        kind: OverlayKind::File { content: None },
        stage_id: None,
        size: 0,
        exec: false,
    }])
    .unwrap();
    // The eligibility queue keeps its one file's charge, as after any sync,
    // until the next seal or a landing discards it.
    let queue = 256 + 512;
    let setup = || async {
        let f = Fixture::new().await;
        let x = f.create("x", b"projected");
        f.create("w", b"never synced");
        (f, x)
    };

    // Refused once its boundary is durable, before its submission is retained.
    let (f, x) = setup().await;
    let initial = reservations(&f);
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "boundary_recorded", 1, FaultAction::Fail);
    let refused = published(&f, SyncTarget::Stage(x), 70, SyncOptions::default())
        .await
        .map_err(|error| error.to_string());
    let unsubmitted = (refused, lane_closed(&f), reservations(&f).0 - initial.0);
    settle_disk(&f.io);
    let f = f.restart().await;
    let reconciled = (lane_closed(&f), reservations(&f).0 == initial.0);

    // Unresolved after a send: one definite non-acceptance, then a local
    // refusal before the second send is journaled. The lane and its charge
    // stay, as a restart computes them; a proven refusal then strips the
    // lane and releases it.
    let (f, x) = setup().await;
    let initial = reservations(&f);
    *f.content.jitter_word.lock().unwrap() = Some(1);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::RateLimited);
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "before_submit", 2, FaultAction::Fail);
    let unresolved = published(&f, SyncTarget::Stage(x), 70, SyncOptions::default())
        .await
        .map_err(|error| error.to_string());
    let held = reservations(&f);
    let live = f
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap()
        .charge();
    settle_disk(&f.io);
    let f = f.restart().await;
    let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
    let restarted = lane.charge();
    {
        let mut plan = f.remote.publication_plan.lock().unwrap();
        plan.clear();
        plan.push_back(PublishPlan::Reject);
    }
    let stripped = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(90),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await
    .map(|result| format!("{:?}", result.outcome))
    .map_err(|error| error.to_string());
    let after_strip = f.store.lock().unwrap().overlay_captured_for_test();

    // The landing is the other release.
    let (f, x) = setup().await;
    let initial_landing = reservations(&f);
    let landed = published(&f, SyncTarget::Stage(x), 70, SyncOptions::default())
        .await
        .map_err(|error| error.to_string());

    assert_eq!(
        (
            unsubmitted,
            reconciled,
            unresolved,
            held.0 - initial.0,
            (live, restarted),
            stripped,
            after_strip,
            landed,
            reservations(&f).0,
        ),
        (
            (
                Err("intent refused: SyncInjectedFault".to_owned()),
                true,
                queue + lane_charge,
            ),
            (false, true),
            Err("publication journal: journal: intent refused: SyncInjectedFault".to_owned()),
            queue + lane_charge,
            (lane_charge, lane_charge),
            Ok("Refused".to_owned()),
            Some(initial.0),
            Ok(()),
            initial_landing.0,
        ),
        "the lane charge is its candidate's, kept after the boundary and released once"
    );
}

/// Neither a receipt, an accepted or stalled publication, nor a landing
/// whose readback, refresh or switch fails is this call's success: each
/// returns its own error, keeps the lane, and records no successful fsync.
#[tokio::test]
async fn projected_pending_and_install_are_not_success() {
    let mut outcomes = Vec::new();
    for case in ["accepted", "stalled", "readback", "refresh", "switch"] {
        let f = Fixture::new().await;
        let x = f.create("x", b"published");
        let faults = f.store.lock().unwrap().fault_control();
        match case {
            "accepted" => f.remote.publication_plan.lock().unwrap().extend([
                PublishPlan::Accepted,
                PublishPlan::LandAfterDelay(Duration::from_mins(1)),
            ]),
            "stalled" => f
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .push_back(PublishPlan::LandAfterDelay(Duration::from_mins(1))),
            "readback" => faults.arm("sync.commit", "landed_readback", 1, FaultAction::Fail),
            "refresh" => faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Fail),
            _ => faults.arm("sync.commit", "before_replace", 1, FaultAction::Fail),
        }
        // A stall waits for the deadline; a refused step must not meet it.
        let bound = if matches!(case, "accepted" | "stalled") {
            3
        } else {
            30
        };
        let result = published(
            &f,
            SyncTarget::Stage(x),
            70,
            bounded(Duration::from_secs(bound)),
        )
        .await;
        faults.resume();
        outcomes.push((
            case,
            result.as_ref().err().map(crate::sync_mount_error),
            lane_closed(&f),
            fsyncs(&f, "ok"),
            fsyncs(&f, "failed"),
        ));
    }
    let unavailable = Some(granary_fuse::MountSyncError::Backend(
        granary_fuse::MountError::Unavailable,
    ));
    let io = Some(granary_fuse::MountSyncError::Backend(
        granary_fuse::MountError::Io,
    ));
    let row = |case, errno: &Option<_>| {
        (
            case,
            *errno,
            true,
            r#"granary_client_syncs_total{outcome="ok"} 0"#.to_owned(),
            r#"granary_client_syncs_total{outcome="failed"} 1"#.to_owned(),
        )
    };
    assert_eq!(
        outcomes,
        [
            row("accepted", &unavailable),
            row("stalled", &unavailable),
            row("readback", &io),
            row("refresh", &io),
            row("switch", &io),
        ],
        "no outcome short of this call's installed landing is its success"
    );
}

/// A landing whose install completes only after the call's deadline is not
/// its success, though the install, once started, finishes and keeps it.
#[test]
fn projected_install_observed_after_the_deadline_is_not_success() {
    // Wide enough that the call reaches the switch inside its bound even
    // when its durable syncs are contended full-device flushes (F_FULLFSYNC
    // on Apple); the row then holds the switch past the call's deadline.
    const CALL_BOUND: Duration = Duration::from_secs(10);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let f = runtime.block_on(Fixture::new());
    let x = f.create("x", b"late");
    let faults = f.store.lock().unwrap().fault_control();
    // Held inside the switch, on the thread that drives the publication.
    faults.arm("sync.commit", "before_replace", 1, FaultAction::Block);
    let engine = f.engine.clone();
    let start = TokioSyncRuntime.now();
    let publishing = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                engine
                    .sync_published(seal(SyncTarget::Stage(x)), bounded(CALL_BOUND), Entropy(70))
                    .wait()
                    .await
                    .map_err(|error| error.to_string())
            })
    });
    // The switch must be held, not merely waited for: a seam reached after
    // the wait gives up would run unheld and answer inside its bound.
    while faults.sync_fired().is_empty() && TokioSyncRuntime.now() < start + CALL_BOUND {
        runtime.block_on(async { TokioSyncRuntime.sleep(Duration::from_millis(1)).await });
    }
    let held_before_deadline = TokioSyncRuntime.now() < start + CALL_BOUND
        && faults
            .sync_fired()
            .iter()
            .any(|event| (event.name, event.phase) == ("sync.commit", "before_replace"));
    // The call's deadline is no later than its own start plus the bound,
    // and it started before the switch fired.
    runtime.block_on(async {
        TokioSyncRuntime
            .sleep(CALL_BOUND + Duration::from_millis(200))
            .await;
    });
    faults.resume();
    let result = publishing.join().unwrap();
    assert_eq!(
        (
            held_before_deadline,
            result,
            lane_closed(&f),
            head_file(&f, "x"),
        ),
        (
            true,
            Err("intent refused: SyncDeadline".to_owned()),
            false,
            Some(b"late".to_vec()),
        ),
        "an install observed after the deadline must not answer success"
    );
}

/// Script `case`'s sends: eight refusals, or a stall at the first or the
/// eighth attempt. Answers the deadline in seconds: a stall waits for it, and
/// quick refusals must not meet it.
fn script_exhaustion(f: &Fixture, case: &str) -> u64 {
    let held_send = PublishPlan::LandAfterDelay(Duration::from_mins(1));
    let mut plan = f.remote.publication_plan.lock().unwrap();
    match case {
        "exhausted" => {
            plan.extend([PublishPlan::RateLimited; 8]);
            30
        }
        "stalled first" => {
            plan.push_back(held_send);
            2
        }
        _ => {
            plan.extend([PublishPlan::RateLimited; 7]);
            plan.push_back(held_send);
            10
        }
    }
}

/// Eight quickly refused attempts exhaust the publication: this call, the
/// next mutation and a reopen all meet its fence. A stall that reaches the
/// deadline at the first or the eighth attempt is unresolved, invents no
/// fence, and a later resume sends no ninth attempt.
#[tokio::test]
async fn projected_exhaustion_is_sticky_estale() {
    let stale = Some(granary_fuse::MountSyncError::Backend(
        granary_fuse::MountError::Stale,
    ));
    let unavailable = Some(granary_fuse::MountSyncError::Backend(
        granary_fuse::MountError::Unavailable,
    ));
    let mut outcomes = Vec::new();
    for case in ["exhausted", "stalled first", "stalled eighth"] {
        let f = Fixture::new().await;
        let x = f.create("x", b"exhausted");
        // Every backoff draws its shortest delay.
        *f.content.jitter_word.lock().unwrap() = Some(1);
        let bound = script_exhaustion(&f, case);
        let result = published(
            &f,
            SyncTarget::Stage(x),
            70,
            bounded(Duration::from_secs(bound)),
        )
        .await;
        let errno = result.as_ref().err().map(crate::sync_mount_error);
        let mutation = f
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.write(x, 0, b"E").map(|_| ()))
            .err()
            .map(|error| crate::sync_mount_error(&error));
        let sends = f.remote.publication_sends.lock().unwrap().len();
        settle_disk(&f.io);
        // A permitted resume, after the restart, reads the durable charges
        // before any send.
        let (resumed, resent, reopened) = match f.try_restart_over(vec![]).await {
            Ok(f) if case == "stalled eighth" => {
                let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
                let resumed = Box::pin(f.engine.drive_commit(
                    &lane,
                    &mut Entropy(90),
                    &mut Delay,
                    RecoveryIntent::ExplicitRecovery,
                    SyncOptions::default(),
                ))
                .await
                .map(|result| format!("{:?}", result.outcome))
                .map_err(|error| error.to_string());
                (
                    resumed,
                    f.remote.publication_sends.lock().unwrap().len(),
                    None,
                )
            }
            Ok(f) => (
                Ok(String::new()),
                f.remote.publication_sends.lock().unwrap().len(),
                None,
            ),
            Err(error) => (
                Ok(String::new()),
                sends,
                Some(crate::sync_mount_error(&error)),
            ),
        };
        outcomes.push((case, errno, mutation, sends, resumed, resent, reopened));
    }
    assert_eq!(
        outcomes,
        [
            ("exhausted", stale, stale, 8, Ok(String::new()), 8, stale),
            (
                "stalled first",
                unavailable,
                None,
                1,
                Ok(String::new()),
                1,
                None
            ),
            (
                "stalled eighth",
                unavailable,
                None,
                8,
                Ok("Exhausted".to_owned()),
                8,
                None
            ),
        ],
        "exhaustion fences stickily; a deadline invents no fence and no ninth send"
    );
}

/// A stall at the eighth attempt that reaches the deadline, then a later
/// published caller in the same process: its takeover under its own
/// deadline sends no ninth attempt and meets the exhaustion's fence.
#[tokio::test]
async fn projected_exhaustion_takeover_sends_no_ninth() {
    let f = Fixture::new().await;
    let x = f.create("x", b"exhausted");
    *f.content.jitter_word.lock().unwrap() = Some(1);
    let bound = script_exhaustion(&f, "stalled eighth");
    let first = published(
        &f,
        SyncTarget::Stage(x),
        70,
        bounded(Duration::from_secs(bound)),
    )
    .await
    .map_err(|error| crate::sync_mount_error(&error));
    let sent = f.remote.publication_sends.lock().unwrap().len();
    let y = f.create("y", b"later caller");
    let later = published(&f, SyncTarget::Stage(y), 80, SyncOptions::default())
        .await
        .map_err(|error| crate::sync_mount_error(&error));
    let stale = Err(granary_fuse::MountSyncError::Backend(
        granary_fuse::MountError::Stale,
    ));
    assert_eq!(
        (
            first,
            sent,
            later,
            f.remote.publication_sends.lock().unwrap().len(),
            head_file(&f, "y"),
        ),
        (
            Err(granary_fuse::MountSyncError::Backend(
                granary_fuse::MountError::Unavailable,
            )),
            8,
            stale,
            8,
            None,
        ),
        "a takeover after the eighth attempt sends no ninth and meets the fence"
    );
}

/// A publication whose operation panics while its seal is prepared, while
/// its registration settles under the lane it closed, or while its
/// candidate's submission is built under that lane, answers that its
/// supervisor was lost and owns nothing after: no preparation, registration
/// or closed lane is left, every reservation but the queue's volatile
/// carry-forward charge (256 per file plus 512, which the next seal
/// releases) is released and admission is open, so the next published sync
/// lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panicked_publication_releases_what_it_owned() {
    for (seam, held, carried) in [
        (
            Some(("sync.capture", "after")),
            Some(((true, 0, false), false)),
            0,
        ),
        (
            Some(("sync.registration", "before_dispatch")),
            Some(((false, 1, true), true)),
            768,
        ),
        // The status read that bootstraps the candidate's submission: its
        // failure is the control.
        (None, None, 0),
    ] {
        let expected = if seam.is_some() {
            None
        } else {
            let control = Fixture::new().await;
            let x = control.create("x", b"panicked");
            control.remote.fail_status.store(true, Ordering::Release);
            let refused = published(&control, SyncTarget::Stage(x), 70, SyncOptions::default())
                .await
                .is_err();
            assert!(refused, "the status control did not refuse");
            Some(reservations(&control))
        };
        let f = Fixture::new().await;
        let x = f.create("x", b"panicked");
        let initial = reservations(&f);
        let expected = expected.unwrap_or((initial.0 + carried, initial.1));
        let faults = f.store.lock().unwrap().fault_control();
        let _resume = ResumeOnDrop(&faults);
        let mut publishing = Box::pin(published(
            &f,
            SyncTarget::Stage(x),
            70,
            SyncOptions::default(),
        ));
        let at_seam = if let Some((name, phase)) = seam {
            faults.arm(name, phase, 1, FaultAction::Block);
            hold_at_seam(&mut publishing, &faults, name, phase).await;
            let at_seam = (f.engine.owned_for_test(), lane_closed(&f));
            f.content.panic_blocking.store(true, Ordering::Release);
            faults.resume();
            Some(at_seam)
        } else {
            f.remote.panic_status.store(true, Ordering::Release);
            None
        };
        let result = publishing.await.map_err(|error| error.to_string());
        let after = (
            f.content.panic_blocking.load(Ordering::Acquire)
                || f.remote.panic_status.load(Ordering::Acquire),
            f.engine.owned_for_test(),
            lane_closed(&f),
            f.engine.admission_free_for_test(),
            reservations(&f),
        );
        let later = published(&f, SyncTarget::Stage(x), 80, SyncOptions::default())
            .await
            .map_err(|error| error.to_string());
        assert_eq!(
            (at_seam, result, after, later, head_file(&f, "x")),
            (
                held,
                Err(CoordinationError::Refused("SyncSupervisorLost").to_string()),
                (false, (false, 0, false), false, true, expected),
                Ok(()),
                Some(b"panicked".to_vec()),
            ),
            "a publication panicked at {seam:?} left state without an owner"
        );
    }
}

/// A published sync whose retention closure is lost before its boundary is
/// recorded releases its projected lane once, as a refusal before retention
/// does: no projected record is left for its supervisor to release again,
/// admission reopens, and the next published sync lands.
#[tokio::test]
async fn a_lost_projected_retention_releases_its_lane_once() {
    let control = Fixture::new().await;
    let x = control.create("x", b"lost");
    control.remote.fail_status.store(true, Ordering::Release);
    let refused = published(&control, SyncTarget::Stage(x), 70, SyncOptions::default())
        .await
        .is_err();
    let expected = reservations(&control);
    let f = Fixture::new().await;
    let x = f.create("x", b"lost");
    f.engine
        .panic_retention_for_test(crate::sync::RetentionPanic::BeforeRetain);
    let lost = published(&f, SyncTarget::Stage(x), 70, SyncOptions::default())
        .await
        .map_err(|error| error.to_string());
    let after = (
        f.engine.owned_for_test(),
        f.engine.commit_lane_for_test(),
        lane_closed(&f),
        f.engine.admission_free_for_test(),
        reservations(&f),
    );
    let later = published(
        &f,
        SyncTarget::Stage(x),
        80,
        bounded(Duration::from_secs(5)),
    )
    .await
    .map_err(|error| error.to_string());
    assert_eq!(
        (refused, lost, after, later, head_file(&f, "x")),
        (
            true,
            Err(CoordinationError::Refused("SyncMaterializationLost").to_string()),
            ((false, 0, false), (false, false), false, true, expected),
            Ok(()),
            Some(b"lost".to_vec()),
        ),
        "a lost projected retention must release its lane exactly once"
    );
}

/// A publication that panics while its seal is prepared drops admission as
/// it unwinds, before its supervisor releases that seal's reservations.
/// Another publication waiting for admission is admitted only once they are
/// released: held in its uploads, it never reaches them while the lost
/// supervisor is held, then lands, and every reservation balances after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panicked_preparation_releases_only_its_own_seal() {
    // The control publishes b alone, with a left dirty as a disposed
    // preparation leaves it.
    let control = Fixture::new().await;
    control.create("a", b"panicked");
    let b = control.create("b", b"admitted after");
    published(&control, SyncTarget::Stage(b), 80, SyncOptions::default())
        .await
        .unwrap();
    let expected = reservations(&control);
    let f = Fixture::new().await;
    let a = f.create("a", b"panicked");
    let b = f.create("b", b"admitted after");
    let faults = f.store.lock().unwrap().fault_control();
    let _resume = ResumeOnDrop(&faults);
    faults.arm("sync.capture", "after", 1, FaultAction::Block);
    let mut first = Box::pin(
        f.engine
            .sync_published(
                seal(SyncTarget::Stage(a)),
                SyncOptions::default(),
                Entropy(70),
            )
            .wait(),
    );
    hold_at_seam(&mut first, &faults, "sync.capture", "after").await;
    f.remote.hold_upload.store(true, Ordering::Release);
    let second = f.engine.sync_published(
        seal(SyncTarget::Stage(b)),
        SyncOptions::default(),
        Entropy(80),
    );
    f.content.hold_lost.store(true, Ordering::Release);
    f.content.panic_blocking.store(true, Ordering::Release);
    faults.resume();
    let uploads = || {
        TokioSyncRuntime.timeout_at(
            TokioSyncRuntime.now() + Duration::from_secs(1),
            f.remote.upload_entered.notified(),
        )
    };
    // Before the lost supervisor runs, the other publication must not reach
    // the uploads its own reservation precedes.
    let early = uploads().await.is_ok();
    f.content.lost_release.notify_one();
    if !early {
        TokioSyncRuntime
            .timeout_at(
                TokioSyncRuntime.now() + Duration::from_secs(10),
                f.remote.upload_entered.notified(),
            )
            .await
            .unwrap();
    }
    f.remote.hold_upload.store(false, Ordering::Release);
    f.remote.upload_release.notify_one();
    let lost = first.await.map_err(|error| error.to_string());
    let landed = second.wait().await.map_err(|error| error.to_string());
    assert_eq!(
        (
            early,
            lost,
            landed,
            head_file(&f, "b"),
            f.engine.owned_for_test(),
            lane_closed(&f),
            reservations(&f),
        ),
        (
            false,
            Err(CoordinationError::Refused("SyncSupervisorLost").to_string()),
            Ok(()),
            Some(b"admitted after".to_vec()),
            (false, 0, false),
            false,
            expected,
        ),
        "a lost preparation's cleanup released another publication's seal"
    );
}
