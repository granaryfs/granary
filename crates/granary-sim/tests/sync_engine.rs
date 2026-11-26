// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#[path = "sync_engine/commit_faults.rs"]
mod commit_faults;
#[path = "sync_engine/cuts.rs"]
mod cuts;
#[path = "sync_engine/rebase.rs"]
mod rebase;
#[path = "sync_engine/recovery.rs"]
mod recovery;
#[path = "sync_engine/shards.rs"]
mod shards;
#[path = "sync_engine/support.rs"]
mod support;
use granary_client::{FaultAction, SyncOptions, SyncRuntime, SyncTarget};
use granary_core::hash::GrainId;
use granary_sim::sched::yield_once;
use std::sync::atomic::Ordering;
use support::{Fixture, oracle_root};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one schedule builds a tree, lands it, adopts it and compares the next root with a from-scratch build"
)]
fn fsync_after_landed_refresh_reuses_landed_subtrees() {
    use granary_client::{PublicationOutcome, RecoveryIntent};
    use granary_core::grainsource::GrainSource as _;
    use granary_core::manifest::{self, EntryKind, Name};
    use granary_core::overlay_journal::{CreateKind, Location, Parent, Record};
    use granary_sim::secure_random::SeededSecureRandom;
    use support::{Delay, PublishPlan};
    let name = |s: &str| Name::new(s.as_bytes().to_vec()).unwrap();
    let place = |dir: Option<&str>, leaf: &str| Location {
        parent: Parent::new(dir.map(name).into_iter().collect()).unwrap(),
        name: name(leaf),
    };
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        let put = |dir: Option<&str>, leaf: &str, bytes: &[u8]| {
            fixture
                .store
                .lock()
                .unwrap()
                .overlay_transaction(|t| {
                    let stage = t.create_file(place(dir, leaf), false)?;
                    t.write(stage, 0, bytes)?;
                    Ok(stage)
                })
                .unwrap()
        };
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                for dir in ["d", "e"] {
                    t.namespace_record(Record::Create {
                        at: place(None, dir),
                        kind: CreateKind::Dir,
                    })?;
                }
                Ok(())
            })
            .unwrap();
        put(Some("d"), "a", b"first of d");
        put(Some("d"), "b", b"second of d");
        put(Some("e"), "c", b"only of e");
        put(None, "top", b"top level");
        // Commit the whole tree, land it, and let the refresh adopt it as the base.
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::Land]);
        let engine = fixture.engine.clone();
        let (landed, _) = fixture
            .runtime
            .run(seed, 100_000, async move {
                let lane = engine
                    .construct_commit(
                        SyncOptions::default(),
                        &mut SeededSecureRandom::for_incarnation(44, 0),
                    )
                    .await
                    .unwrap();
                engine
                    .drive_commit(
                        &lane,
                        &mut SeededSecureRandom::for_incarnation(45, 0),
                        &mut Delay,
                        RecoveryIntent::Continue,
                        SyncOptions::default(),
                    )
                    .await
                    .unwrap()
            })
            .unwrap();
        let PublicationOutcome::Landed(done) = landed.outcome else {
            panic!("the commit did not land");
        };
        let landed_root = granary_core::root::decode_root(&done.root)
            .unwrap()
            .manifest_root;
        // The subtree `e` must be reused from the landed base, never read.
        let top = fixture.content.get(&landed_root).unwrap();
        let (_, cursor) = granary_core::encoding::open_envelope(&top).unwrap();
        let e = manifest::decode_dir_leaf(cursor)
            .unwrap()
            .into_iter()
            .find_map(|entry| match entry.kind {
                EntryKind::Dir { child } if entry.name.as_bytes() == b"e" => Some(child),
                _ => None,
            })
            .unwrap();
        fixture.content.reads.lock().unwrap().clear();
        let stage = put(Some("d"), "new", b"after the refresh");
        assert!(fixture.sync(seed, stage).0.is_ok(), "seed {seed}");
        assert!(
            !fixture.content.reads.lock().unwrap().contains(&e),
            "seed {seed}: the fsync read a landed subtree it did not change"
        );
        let expected = oracle_root(&[
            ("d/a", b"first of d"),
            ("d/b", b"second of d"),
            ("d/new", b"after the refresh"),
            ("e/c", b"only of e"),
            ("top", b"top level"),
        ]);
        assert_eq!(
            granary_core::root::decode_root(&fixture.registered())
                .unwrap()
                .manifest_root,
            expected,
            "seed {seed}: the root differs from a from-scratch build"
        );
    }
}

#[test]
fn sync_fault_matrix() {
    let rows = [
        ("sync.capture", "after", false),
        ("sync.upload", "before", false),
        ("sync.upload", "accepted", false),
        ("sync.node_upload", "before", false),
        ("sync.node_upload", "accepted", false),
        ("sync.registration", "before_dispatch", false),
        ("sync.registration", "after_response", true),
        ("sync.reply", "before", true),
    ];
    let mut cases = 0;
    for seed in [1, 42, 43] {
        for (name, phase, advanced) in rows {
            let fixture = Fixture::new();
            let stage = fixture.create("file", b"captured bytes");
            let before = fixture.registered();
            let faults = fixture.store.lock().unwrap().fault_control();
            faults.arm(name, phase, 1, FaultAction::Fail);
            let (result, trace) = fixture.sync(seed, stage);
            assert!(result.is_err(), "fault acknowledged caller");
            assert!(!trace.is_empty(), "empty engine schedule");
            let events = faults.sync_fired();
            assert_eq!(events.len(), 1, "SyncFaultMissing");
            let event = &events[0];
            assert_eq!(
                (event.name, event.phase, event.occurrence),
                (name, phase, 1),
                "SyncFaultIdentity"
            );
            if name == "sync.registration" || name == "sync.reply" {
                let id = event.request.unwrap();
                assert!(
                    fixture
                        .store
                        .lock()
                        .unwrap()
                        .retained_requests()
                        .iter()
                        .any(|r| GrainId::of(r.bytes()) == id)
                        || fixture
                            .remote
                            .attempts
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|bytes| GrainId::of(bytes) == id),
                    "SyncFaultRequestIdentity"
                );
            } else {
                assert_eq!(event.capture, 1, "SyncFaultCaptureIdentity");
            }
            assert_eq!(fixture.registered() != before, advanced);
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
            );
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"failed\"} 1\n")
            );
            if advanced {
                fixture.assert_file(&fixture.registered(), "file", b"captured bytes");
            }
            let control = Fixture::new();
            let stage = control.create("file", b"captured bytes");
            assert!(
                control.sync(seed, stage).0.is_ok(),
                "disarmed control failed"
            );
            control.assert_file(&control.registered(), "file", b"captured bytes");
            assert_eq!(
                granary_core::root::decode_root(&control.registered())
                    .unwrap()
                    .parent,
                Some(GrainId::of(&control.base))
            );
            assert!(
                control
                    .store
                    .lock()
                    .unwrap()
                    .fault_control()
                    .sync_fired()
                    .is_empty()
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 24, "SyncFaultEmptySelection");
}

#[test]
fn write_after_capture_survives_upload_and_reply_schedules() {
    for seed in 0..16 {
        for at_reply in [false, true] {
            let fixture = Fixture::new();
            let stage = fixture.create("file", b"boundary");
            fixture
                .remote
                .hold_upload
                .store(!at_reply, Ordering::Release);
            fixture.remote.hold_reply.store(at_reply, Ordering::Release);
            let engine = fixture.engine.clone();
            let remote = fixture.remote.clone();
            let store = fixture.store.clone();
            let waiter = engine.sync(SyncTarget::Stage(stage), SyncOptions::default());
            let writer = fixture.runtime.spawn(async move {
                while !(if at_reply {
                    remote.reply_entered.load(Ordering::Acquire)
                } else {
                    remote.upload_entered.load(Ordering::Acquire)
                }) {
                    yield_once().await;
                }
                store
                    .lock()
                    .unwrap()
                    .overlay_transaction(|t| t.write(stage, 0, b"later!!!").map(|_| ()))
                    .unwrap();
                remote.hold_upload.store(false, Ordering::Release);
                remote.hold_reply.store(false, Ordering::Release);
            });
            drop(writer);
            let (result, trace) = fixture
                .runtime
                .run(seed, 100_000, async move { waiter.wait().await })
                .unwrap();
            assert!(result.is_ok());
            assert!(
                trace.windows(2).any(|p| p[0] != p[1]),
                "schedule had no handoff"
            );
            fixture.assert_file(&fixture.registered(), "file", b"boundary");
            assert!(fixture.sync(seed, stage).0.is_ok());
            fixture.assert_file(&fixture.registered(), "file", b"later!!!");
        }
    }
}

#[test]
fn cancellation_during_upload_and_reply_releases_exact_capture() {
    for seed in 0..8 {
        for at_reply in [false, true] {
            let fixture = Fixture::new();
            let stage = fixture.create("file", b"captured");
            fixture
                .remote
                .hold_upload
                .store(!at_reply, Ordering::Release);
            fixture.remote.hold_reply.store(at_reply, Ordering::Release);
            let waiter = fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default());
            let remote = fixture.remote.clone();
            let ((), _) = fixture
                .runtime
                .run(seed, 100_000, async move {
                    while !(if at_reply {
                        remote.reply_entered.load(Ordering::Acquire)
                    } else {
                        remote.upload_entered.load(Ordering::Acquire)
                    }) {
                        yield_once().await;
                    }
                    drop(waiter);
                    remote.hold_upload.store(false, Ordering::Release);
                    remote.hold_reply.store(false, Ordering::Release);
                })
                .unwrap();
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
            );
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"cancelled\"} 1\n")
            );
            if !at_reply {
                assert!(fixture.remote.attempts.lock().unwrap().is_empty());
            }
            fixture
                .store
                .lock()
                .unwrap()
                .overlay_transaction(|t| t.truncate(stage, 0))
                .unwrap();
        }
    }
}

#[test]
fn sync_and_commit_admission_preserve_both_causal_orders() {
    use granary_client::CoordinationError;
    use granary_sim::secure_random::SeededSecureRandom;
    use std::time::Duration;
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        let stage = fixture.create("file", b"acknowledged prefix");
        assert!(fixture.sync(seed, stage).0.is_ok());
        let engine = fixture.engine.clone();
        let (lane, _) = fixture
            .runtime
            .run(seed, 100_000, async move {
                engine
                    .construct_commit(
                        SyncOptions::default(),
                        &mut SeededSecureRandom::for_incarnation(44, 0),
                    )
                    .await
                    .unwrap()
            })
            .unwrap();
        assert!(lane.boundary_seq() > 0);
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.write(stage, 0, b"later").map(|_| ()))
            .unwrap();
        let registered = fixture.registered();
        let sends = fixture.remote.attempts.lock().unwrap().len();
        let faults = fixture.store.lock().unwrap().fault_control();
        faults.arm("sync.commit_wait", "before", 1, FaultAction::Fail);
        let (failed, _) = fixture.sync(seed, stage);
        assert!(failed.is_err());
        let event = faults.sync_fired();
        assert_eq!(event.len(), 1);
        assert_eq!(event[0].name, "sync.commit_wait");
        let engine = fixture.engine.clone();
        let (result, _) = fixture
            .runtime
            .run(seed, 100_000, async move {
                engine
                    .sync(
                        SyncTarget::Stage(stage),
                        SyncOptions {
                            resolution_bound: Duration::from_millis(20),
                            ..SyncOptions::default()
                        },
                    )
                    .wait()
                    .await
            })
            .unwrap();
        assert!(matches!(
            result,
            Err(CoordinationError::Refused(
                "SyncDeadline" | "SyncCommitUnresolved"
            ))
        ));
        assert_eq!(fixture.registered(), registered);
        assert_eq!(fixture.remote.attempts.lock().unwrap().len(), sends);
        assert!(
            fixture
                .engine
                .recover_commit(SyncOptions::default())
                .is_ok()
        );
    }
}

#[test]
fn metadata_kind_and_occurrence_fault_matrix() {
    use std::collections::BTreeSet;
    let bytes = support::spill_bytes();
    let discovery = Fixture::new();
    let stage = discovery.create("file", &bytes);
    let trace = discovery.store.lock().unwrap().fault_control();
    trace.trace_sync();
    let result = discovery.sync(42, stage).0;
    assert!(result.is_ok(), "metadata control: {result:?}");
    let rows: Vec<_> = trace
        .sync_fired()
        .into_iter()
        .filter(|e| matches!(e.name, "sync.node_upload" | "sync.upload"))
        .collect();
    let kinds: BTreeSet<_> = rows
        .iter()
        .filter(|e| e.name == "sync.node_upload")
        .map(|e| e.object_kind)
        .collect();
    assert_eq!(
        kinds,
        ["manifest", "grain_list", "binmap", "sheaf"]
            .into_iter()
            .collect(),
        "metadata fixture omitted a kind"
    );
    assert!(rows.iter().all(|e| e.capture > 0 && e.occurrence > 0));
    let control_root = discovery.registered();
    discovery.assert_file(&control_root, "file", &bytes);
    let mut cases = 0;
    for expected in &rows {
        let fixture = Fixture::new();
        let stage = fixture.create("file", &bytes);
        let before = fixture.registered();
        let faults = fixture.store.lock().unwrap().fault_control();
        faults.arm(
            expected.name,
            expected.phase,
            expected.occurrence,
            FaultAction::Fail,
        );
        assert!(
            fixture.sync(42, stage).0.is_err(),
            "metadata fault acknowledged"
        );
        let events = faults.sync_fired();
        assert_eq!(events.len(), 1, "SyncMetadataFaultMissing");
        let actual = &events[0];
        assert_eq!(
            actual.capture, expected.capture,
            "SyncMetadataCaptureIdentity"
        );
        assert_eq!(
            actual.request, expected.request,
            "SyncMetadataRequestIdentity"
        );
        assert_eq!(
            (
                actual.name,
                actual.phase,
                actual.occurrence,
                actual.object_kind
            ),
            (
                expected.name,
                expected.phase,
                expected.occurrence,
                expected.object_kind
            ),
            "SyncMetadataFaultIdentity"
        );
        assert_eq!(
            fixture.registered(),
            before,
            "metadata failure registered incomplete closure"
        );
        assert!(fixture.remote.attempts.lock().unwrap().is_empty());
        assert!(
            fixture
                .metrics()
                .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
        );
        cases += 1;
    }
    assert_eq!(cases, rows.len());
    assert!(cases >= 8, "SyncMetadataEmptySelection");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "complete fault/state/control matrix kept in one oracle"
)]
fn fsync_waits_for_inflight_commit() {
    use granary_client::{CoordinationError, PublicationOutcome, RecoveryIntent};
    use granary_sim::secure_random::SeededSecureRandom;
    use support::{Delay, PublishPlan};
    let plans = [
        ("landing", vec![PublishPlan::Land]),
        (
            "accepted then timeout",
            vec![
                PublishPlan::Accepted,
                PublishPlan::Timeout,
                PublishPlan::Land,
            ],
        ),
        (
            "accepted then backend error",
            vec![
                PublishPlan::Accepted,
                PublishPlan::Internal,
                PublishPlan::Land,
            ],
        ),
        (
            "accepted then rate limit",
            vec![
                PublishPlan::Accepted,
                PublishPlan::RateLimited,
                PublishPlan::Land,
            ],
        ),
        (
            "disjoint rebase",
            vec![PublishPlan::StaleForeign, PublishPlan::Land],
        ),
        ("permanent refusal", vec![PublishPlan::Reject]),
        (
            "replaced epoch",
            vec![PublishPlan::EpochMismatch, PublishPlan::Land],
        ),
    ];
    for (label, plan) in plans {
        let refuses = plan
            .iter()
            .any(|answer| matches!(answer, PublishPlan::Reject));
        for seed in [1, 42, 43] {
            let fixture = Fixture::new();
            let stage = fixture.create("file", b"before");
            let engine = fixture.engine.clone();
            let (lane, _) = fixture
                .runtime
                .run(seed, 100_000, async move {
                    engine
                        .construct_commit(
                            SyncOptions::default(),
                            &mut SeededSecureRandom::for_incarnation(44, 0),
                        )
                        .await
                        .unwrap()
                })
                .unwrap();
            fixture
                .store
                .lock()
                .unwrap()
                .overlay_transaction(|t| t.write(stage, 0, b"after!").map(|_| ()))
                .unwrap();
            let registered_before = fixture.registered();
            let faults = fixture.store.lock().unwrap().fault_control();
            faults.trace_sync();
            fixture
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .extend(plan.iter().map(|p| match p {
                    PublishPlan::Land => PublishPlan::Land,
                    PublishPlan::Accepted => PublishPlan::Accepted,
                    PublishPlan::Timeout => PublishPlan::Timeout,
                    PublishPlan::DelayedLand => PublishPlan::DelayedLand,
                    PublishPlan::Internal => PublishPlan::Internal,
                    PublishPlan::RateLimited => PublishPlan::RateLimited,
                    PublishPlan::Reject => PublishPlan::Reject,
                    PublishPlan::StaleForeign => PublishPlan::StaleForeign,
                    PublishPlan::StaleForeignUnreadable => PublishPlan::StaleForeignUnreadable,
                    PublishPlan::StaleRoot(root) => PublishPlan::StaleRoot(root.clone()),
                    PublishPlan::StaleCurrent => PublishPlan::StaleCurrent,
                    PublishPlan::EpochMismatch => PublishPlan::EpochMismatch,
                }));
            let waiter = fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default());
            let engine = fixture.engine.clone();
            let store = fixture.store.clone();
            let remote = fixture.remote.clone();
            let check = faults.clone();
            let (result, _) = fixture
                .runtime
                .run(seed, 100_000, async move {
                    while !check
                        .sync_fired()
                        .iter()
                        .any(|e| e.name == "sync.commit_wait")
                    {
                        yield_once().await;
                    }
                    assert!(
                        remote.attempts.lock().unwrap().is_empty(),
                        "sync registered before C settled"
                    );
                    // Ordinary writers progress even while admission is closed.
                    store
                        .lock()
                        .unwrap()
                        .overlay_transaction(|t| t.write(stage, 6, b"+").map(|_| ()))
                        .unwrap();
                    let mut result = engine
                        .drive_commit(
                            &lane,
                            &mut SeededSecureRandom::for_incarnation(45, 0),
                            &mut Delay,
                            RecoveryIntent::Continue,
                            SyncOptions::default(),
                        )
                        .await
                        .unwrap();
                    for _ in 0..8 {
                        if !matches!(result.outcome, PublicationOutcome::Pending) {
                            break;
                        }
                        result = engine
                            .drive_commit(
                                &lane,
                                &mut SeededSecureRandom::for_incarnation(46, 0),
                                &mut Delay,
                                RecoveryIntent::Continue,
                                SyncOptions::default(),
                            )
                            .await
                            .unwrap();
                    }
                    (waiter.wait().await, result)
                })
                .unwrap();
            let (sync_result, result) = result;
            if refuses {
                assert_eq!(
                    (
                        matches!(sync_result, Err(CoordinationError::Fenced { .. })),
                        matches!(&result.outcome, PublicationOutcome::Refused),
                        fixture.registered() == registered_before,
                        fixture.remote.attempts.lock().unwrap().is_empty(),
                    ),
                    (true, true, true, true),
                    "{label} seed {seed}: sync {sync_result:?}, commit {result:?}"
                );
            } else {
                assert!(
                    sync_result.is_ok(),
                    "{label} seed {seed}: sync {sync_result:?}, commit {result:?}"
                );
                let PublicationOutcome::Landed(done) = result.outcome else {
                    panic!("commit did not land");
                };
                fixture.assert_file(&done.root, "file", b"before");
                assert_eq!(
                    granary_core::root::decode_root(&fixture.registered())
                        .unwrap()
                        .parent,
                    Some(GrainId::of(&done.root))
                );
                fixture.assert_file(&fixture.registered(), "file", b"after!+");
            }
            let events = faults.sync_fired();
            assert!(events.iter().any(|e| e.name == "sync.commit_wait"));
            if !refuses {
                assert!(
                    events
                        .iter()
                        .any(|e| e.name == "sync.commit" && e.phase == "landed_readback")
                );
                assert!(events.iter().any(|e| e.name == "sync.commit"
                    && e.phase == "landed_refresh"
                    && e.request.is_some()));
            }
        }
    }
}

/// The store is lost after its commit landed, then again after an
/// acknowledged sync registered a child of that landing. A fresh store's
/// explicit recovery subsumes the landing by step zero and publishes nothing;
/// over the sync it publishes the registered child exactly, so the synced
/// bytes survive the lost disk. Either way the row ends released.
#[test]
fn step_zero_on_a_destroyed_store_after_a_landed_commit_and_an_acknowledged_sync() {
    use granary_client::{PublicationOutcome, RecoveryIntent, SelectedPublication};
    use granary_core::intent::ReceiptState;
    use granary_sim::secure_random::SeededSecureRandom;
    use support::Delay;
    let mut cases = 0;
    for seed in [1, 42, 43] {
        for synced in [false, true] {
            let fixture = Fixture::new();
            fixture.create("file", b"landed");
            let engine = fixture.engine.clone();
            let (result, _) = fixture
                .runtime
                .run(seed, 100_000, async move {
                    let lane = engine
                        .construct_commit(
                            SyncOptions::default(),
                            &mut SeededSecureRandom::for_incarnation(44, 0),
                        )
                        .await
                        .unwrap();
                    engine
                        .drive_commit(
                            &lane,
                            &mut SeededSecureRandom::for_incarnation(45, 0),
                            &mut Delay,
                            RecoveryIntent::Continue,
                            SyncOptions::default(),
                        )
                        .await
                        .unwrap()
                })
                .unwrap();
            let PublicationOutcome::Landed(landed) = result.outcome else {
                panic!("seed {seed}: the commit did not land: {result:?}")
            };
            if synced {
                let stage = fixture.create("synced", b"acknowledged");
                let (synced, _) = fixture.sync(seed, stage);
                assert!(synced.is_ok(), "seed {seed}: the sync was acknowledged");
            }
            let registered = fixture.registered();
            let (outcome, row, sends) = fixture.recover_destroyed(seed);
            let published = match &outcome {
                SelectedPublication::Driven(driven) => match &driven.outcome {
                    PublicationOutcome::Landed(done) => Some(done.root.clone()),
                    _ => None,
                },
                _ => None,
            };
            if let Some(root) = &published {
                fixture.assert_file(root, "file", b"landed");
                fixture.assert_file(root, "synced", b"acknowledged");
            }
            assert_eq!(
                (
                    matches!(
                        outcome,
                        SelectedPublication::Subsumed { by_seq: 2, by_root }
                            if by_root == GrainId::of(&landed.root)
                    ),
                    published.as_deref() == Some(registered.as_slice()),
                    row,
                    sends,
                ),
                if synced {
                    (false, true, Some(ReceiptState::Released), 1)
                } else {
                    (true, false, Some(ReceiptState::Released), 0)
                },
                "seed {seed} synced={synced}: (subsumed by the landing, registered child \
                 published exactly, authority row, publication sends): {outcome:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "bounded process rendezvous observer, outside the simulated schedule"
)]
#[expect(
    clippy::too_many_lines,
    reason = "complete fault/state/control matrix kept in one oracle"
)]
#[ignore = "harness child; requires an explicit selection"]
fn sync_process_child() {
    use std::io::Write;
    use std::time::Duration;
    if let Ok(seed) = std::env::var("GRANARY_SYNC_REPLAY_SEED") {
        support::replay_child(seed.parse().unwrap());
        return;
    }
    if let Ok(mode) = std::env::var("GRANARY_SUBMISSION_MODE") {
        support::submission_child(&mode);
        return;
    }
    let selection = std::env::var("GRANARY_SYNC_CUT").expect("SyncCutSelectionMissing");
    let root = std::env::var_os("GRANARY_SYNC_SCRATCH").unwrap();
    let fields: Vec<_> = selection.split(',').collect();
    assert_eq!(fields.len(), 4);
    let name = match fields[0] {
        "capture" => "sync.capture",
        "upload" => "sync.upload",
        "node" => "sync.node_upload",
        "registration" => "sync.registration",
        "reply" => "sync.reply",
        "wait" => "sync.commit_wait",
        "commit" => "sync.commit",
        "truncate" => "overlay.stage.truncate",
        _ => panic!("SyncCutUnknownPoint"),
    };
    let phase = match fields[1] {
        "after" => "after",
        "before" => "before",
        "accepted" => "accepted",
        "before_dispatch" => "before_dispatch",
        "after_response" => "after_response",
        "captured" => "captured",
        "landed_readback" => "landed_readback",
        "landed_refresh" => "landed_refresh",
        _ => panic!("SyncCutUnknownPhase"),
    };
    let occurrence: u64 = fields[2].parse().unwrap();
    let armed = fields[3] == "armed";
    let case = std::env::var("GRANARY_SYNC_SHARD_CASE").unwrap_or_else(|_| "plain".into());
    let fixture = Fixture::with_scratch_case(support::Scratch(root.into()), &case);
    let bytes = if std::env::var_os("GRANARY_SYNC_SPILL").is_some() {
        support::spill_bytes()
    } else {
        b"process boundary".to_vec()
    };
    let stage = if case == "dedup" {
        0
    } else {
        fixture.create("file", &bytes)
    };
    if name == "overlay.stage.truncate" {
        fixture.sync(42, stage).0.unwrap();
    }
    let faults = fixture.store.lock().unwrap().fault_control();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observer = if armed {
        faults.arm(name, phase, occurrence, FaultAction::Block);
        let faults = faults.clone();
        let stop = stop.clone();
        let store = fixture.store.clone();
        let remote = fixture.remote.clone();
        Some(std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let events = faults.sync_fired();
                if let Some(event) = events.first() {
                    if let Some(id) = event.request {
                        let retained = store.lock().unwrap().retained_requests();
                        assert!(
                            retained
                                .iter()
                                .any(|request| GrainId::of(request.bytes()) == id)
                                || remote
                                    .attempts
                                    .lock()
                                    .unwrap()
                                    .iter()
                                    .any(|bytes| GrainId::of(bytes) == id),
                            "SyncCutRequestIdentity"
                        );
                    }
                    println!(
                        "FIRED,{},{},{},{},{},{}",
                        event.name,
                        event.phase,
                        event.occurrence,
                        event.capture,
                        event
                            .request
                            .map_or_else(|| "none".into(), |id| id.to_string()),
                        event.object_kind
                    );
                    std::io::stdout().flush().unwrap();
                    return;
                }
                if name == "overlay.stage.truncate"
                    && let Some(event) = faults.fired().first()
                {
                    println!(
                        "FIRED,{},{},{},{},none,stage",
                        event.name, event.phase, event.occurrence, event.record_index
                    );
                    std::io::stdout().flush().unwrap();
                    return;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }))
    } else {
        None
    };
    if name == "overlay.stage.truncate" {
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.truncate(stage, 1))
            .unwrap();
    } else if name == "sync.commit" || name == "sync.commit_wait" {
        use granary_client::RecoveryIntent;
        use granary_sim::secure_random::SeededSecureRandom;
        let engine = fixture.engine.clone();
        let (lane, _) = fixture
            .runtime
            .run(42, 100_000, async move {
                engine
                    .construct_commit(
                        SyncOptions::default(),
                        &mut SeededSecureRandom::for_incarnation(44, 0),
                    )
                    .await
                    .unwrap()
            })
            .unwrap();
        if name == "sync.commit_wait" {
            fixture
                .store
                .lock()
                .unwrap()
                .overlay_transaction(|t| t.write(stage, 0, b"process boundary").map(|_| ()))
                .unwrap();
            let waiter = fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default());
            if armed {
                fixture
                    .runtime
                    .run(42, 100_000, waiter.wait())
                    .unwrap()
                    .0
                    .unwrap();
            } else {
                fixture
                    .runtime
                    .run(42, 100_000, async {
                        fixture
                            .engine
                            .drive_commit(
                                &lane,
                                &mut SeededSecureRandom::for_incarnation(45, 0),
                                &mut support::Delay,
                                RecoveryIntent::Continue,
                                SyncOptions::default(),
                            )
                            .await
                            .unwrap();
                        waiter.wait().await.unwrap();
                    })
                    .unwrap();
            }
        } else {
            fixture
                .runtime
                .run(42, 100_000, async {
                    fixture
                        .engine
                        .drive_commit(
                            &lane,
                            &mut SeededSecureRandom::for_incarnation(45, 0),
                            &mut support::Delay,
                            RecoveryIntent::Continue,
                            SyncOptions::default(),
                        )
                        .await
                        .unwrap();
                })
                .unwrap();
        }
    } else if case == "dedup" {
        fixture.sync_tree(42).0.unwrap();
    } else {
        fixture.sync(42, stage).0.unwrap();
    }
    stop.store(true, Ordering::Release);
    if let Some(observer) = observer {
        observer.join().unwrap();
        panic!("SyncCutDidNotFire");
    }
    if case != "dedup" {
        fixture.assert_file(&fixture.registered(), "file", &bytes);
    }
    println!(
        "CONTROL,{name},{phase},{occurrence},{}",
        GrainId::of(&fixture.registered())
    );
    std::io::stdout().flush().unwrap();
}

#[test]
fn engine_process_cuts_require_fired_identity_and_disarmed_success() {
    let rows = [
        ("capture", "sync.capture", "after"),
        ("upload", "sync.upload", "before"),
        ("upload", "sync.upload", "accepted"),
        ("node", "sync.node_upload", "before"),
        ("node", "sync.node_upload", "accepted"),
        ("registration", "sync.registration", "before_dispatch"),
        ("registration", "sync.registration", "after_response"),
        ("reply", "sync.reply", "before"),
        ("wait", "sync.commit_wait", "before"),
        ("commit", "sync.commit", "captured"),
        ("commit", "sync.commit", "landed_readback"),
        ("commit", "sync.commit", "landed_refresh"),
        ("truncate", "overlay.stage.truncate", "before"),
        ("truncate", "overlay.stage.truncate", "after"),
    ];
    let mut cases = 0;
    for (argument, name, phase) in rows {
        for armed in [false, true] {
            cuts::run(argument, name, phase, 1, None, false, armed);
            cases += 1;
        }
    }
    assert_eq!(cases, 28, "SyncCutEmptySelection");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "complete fault/state/control matrix kept in one oracle"
)]
fn diagnostic_class_and_result_matrix() {
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
    for class in [
        "conflict",
        "corrupt",
        "io",
        "refused",
        "unavailable",
        "internal",
        "ok",
        "cancelled",
    ] {
        let fixture = Fixture::new();
        let stage = fixture.create("file", b"diagnostic boundary");
        let before = fixture.registered();
        match class {
            "conflict" => fixture.remote.fenced.store(true, Ordering::Release),
            "corrupt" => fixture.content.corrupt_get.store(true, Ordering::Release),
            "io" => fixture.content.fail_put.store(true, Ordering::Release),
            "unavailable" => fixture.remote.fail_upload.store(true, Ordering::Release),
            "internal" => fixture.content.panic_put.store(true, Ordering::Release),
            _ => {}
        }
        let output = Capture::default();
        let dispatch = granary_client::subscriber(
            granary_client::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            output.clone(),
        );
        let (result, trace) = tracing::subscriber::with_default(dispatch, || {
            if class == "cancelled" {
                fixture.remote.hold_upload.store(true, Ordering::Release);
                let waiter = fixture
                    .engine
                    .sync(SyncTarget::Stage(stage), SyncOptions::default());
                fixture
                    .runtime
                    .run(42, 100_000, async {
                        while !fixture.remote.upload_entered.load(Ordering::Acquire) {
                            yield_once().await;
                        }
                        drop(waiter);
                        fixture.remote.hold_upload.store(false, Ordering::Release);
                        None
                    })
                    .unwrap()
            } else {
                let (result, trace) =
                    fixture.sync(42, if class == "refused" { u64::MAX } else { stage });
                (Some(result), trace)
            }
        });
        assert!(!trace.is_empty());
        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let fsync: Vec<_> = text
            .lines()
            .filter(|line| line.contains("\"kind\":\"fsync\""))
            .collect();
        assert_eq!(
            fsync
                .iter()
                .filter(|line| line.contains("\"event\":\"op.begin\""))
                .count(),
            1
        );
        assert_eq!(
            fsync
                .iter()
                .filter(|line| line.contains("\"event\":\"op.end\""))
                .count(),
            1
        );
        if class == "cancelled" {
            assert!(result.is_none(), "cancelled waiter delivered a result");
            assert!(
                !fsync
                    .iter()
                    .any(|line| line.contains("\"event\":\"op.failed\""))
            );
            assert!(
                fsync
                    .iter()
                    .any(|line| line.contains("\"outcome\":\"cancelled\""))
            );
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"cancelled\"} 1\n")
            );
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
            );
            assert_eq!(fixture.registered(), before);
        } else if class == "ok" {
            result.unwrap().unwrap();
            assert!(
                !fsync
                    .iter()
                    .any(|line| line.contains("\"event\":\"op.failed\""))
            );
            fixture.assert_file(&fixture.registered(), "file", b"diagnostic boundary");
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"ok\"} 1\n")
            );
        } else {
            let result = result.unwrap();
            assert!(
                result.is_err(),
                "failed diagnostic call acknowledged: {class}"
            );
            let failed: Vec<_> = fsync
                .iter()
                .filter(|line| line.contains("\"event\":\"op.failed\""))
                .collect();
            assert_eq!(
                failed.len(),
                1,
                "wrong fsync failure count: {class}: {text}"
            );
            assert!(
                failed[0].contains(&format!("\"class\":\"{class}\"")),
                "wrong class {class}: {result:?}: {text}"
            );
            assert_eq!(fixture.registered(), before);
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
            );
            assert!(
                fixture
                    .metrics()
                    .contains("granary_client_syncs_total{outcome=\"failed\"} 1\n")
            );
        }
        assert_eq!(
            fixture.remote.published.lock().unwrap().len(),
            1,
            "sync changed published head"
        );
        for line in fsync {
            assert!(!line.contains("diagnostic boundary"));
            assert!(!line.contains("fixture.invalid"));
            assert!(
                !line.contains("writer") && !line.contains("root") && !line.contains("request")
            );
        }
    }
}

#[test]
fn truncation_fault_matrix() {
    for phase in ["before", "after"] {
        for armed in [false, true] {
            let fixture = Fixture::new();
            let stage = fixture.create("file", b"captured bytes");
            assert!(fixture.sync(42, stage).0.is_ok());
            let registered = fixture.registered();
            let faults = fixture.store.lock().unwrap().fault_control();
            if armed {
                faults.arm("overlay.stage.truncate", phase, 1, FaultAction::Fail);
            }
            let result = fixture
                .store
                .lock()
                .unwrap()
                .overlay_transaction(|t| t.truncate(stage, 1));
            assert_eq!(result.is_err(), armed);
            let events = faults.fired();
            if armed {
                assert_eq!(events.len(), 1);
                assert_eq!(
                    (events[0].name, events[0].phase, events[0].occurrence),
                    ("overlay.stage.truncate", phase, 1)
                );
            } else {
                assert!(events.is_empty());
            }
            assert_eq!(
                fixture.registered(),
                registered,
                "truncate changed acknowledged P"
            );
            fixture.assert_file(&registered, "file", b"captured bytes");
            assert_eq!(fixture.remote.published.lock().unwrap().len(), 1);
        }
    }
}

#[test]
#[ignore = "requires Unix-domain socket binding in an unrestricted venue"]
#[expect(
    clippy::disallowed_methods,
    reason = "bounded rendezvous polling for exclusively harness-owned subprocesses"
)]
#[expect(
    clippy::too_many_lines,
    reason = "provider cut, fail and disarmed controls share one identity oracle"
)]
fn submission_fault_and_process_cut_matrix() {
    use std::os::unix::fs::PermissionsExt;
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            if self.0.try_wait().unwrap().is_none() {
                self.0.kill().unwrap();
            }
            self.0.wait().unwrap();
        }
    }
    let cuts: Vec<_> = [
        "load",
        "probe-save",
        "probe-result",
        "attempt-save",
        "dispatch",
        "answer-save",
        "complete-save",
        "epoch-save",
        "operation-save",
        "replacement-save",
    ]
    .into_iter()
    .chain(
        granary_client::publish_restart::PHYSICAL_CUTS
            .iter()
            .copied(),
    )
    .collect();
    assert_eq!(cuts.len(), 22, "SubmissionFaultEmptySelection");
    let mut cases = 0;
    for cut in cuts {
        for side in ["before", "after"] {
            for mode in ["control", "kill", "fail"] {
                if mode == "fail" && cut == "dispatch" {
                    continue;
                }
                let scratch = support::Scratch::new();
                let socket = scratch.0.join("control");
                let listener = UnixListener::bind(&socket).unwrap();
                listener.set_nonblocking(true).unwrap();
                let store = scratch.0.join("store");
                std::fs::create_dir(&store).unwrap();
                std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", "sync_process_child", "--ignored", "--nocapture"])
                    .env("GRANARY_SUBMISSION_MODE", mode)
                    .env("GRANARY_SUBMISSION_TRANSITION", cut)
                    .env("GRANARY_SYNC_SCRATCH", &store)
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped());
                if mode == "control" {
                    command.env_remove("GRANARY_RESTART_SOCKET");
                } else {
                    command
                        .env("GRANARY_RESTART_SOCKET", &socket)
                        .env("GRANARY_RESTART_CUT", cut)
                        .env("GRANARY_RESTART_SIDE", side)
                        .env("GRANARY_RESTART_OCCURRENCE", "1");
                }
                let mut child = Owned(command.spawn().unwrap());
                if mode == "control" {
                    assert!(
                        child.0.wait().unwrap().success(),
                        "SubmissionDisarmedControlFailed"
                    );
                } else {
                    let deadline = Instant::now() + Duration::from_secs(15);
                    let stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(e) => panic!("SubmissionRendezvousUnavailable: {e}"),
                        }
                        assert!(Instant::now() < deadline, "SubmissionRendezvousTimeout");
                        assert!(
                            child.0.try_wait().unwrap().is_none(),
                            "SubmissionChildExited"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(15)))
                        .unwrap();
                    let mut stream = BufReader::new(stream);
                    let mut report = String::new();
                    stream.read_line(&mut report).unwrap();
                    let fields: Vec<_> = report.split_whitespace().collect();
                    assert_eq!(fields.len(), 7, "SubmissionReportMalformed");
                    assert_eq!(
                        &fields[..4],
                        &["REACHED", cut, side, "1"],
                        "SubmissionFaultIdentity"
                    );
                    assert_eq!(fields[4].len(), 32, "SubmissionPublicationUnbound");
                    assert!(fields[4].bytes().all(|b| b.is_ascii_hexdigit()));
                    assert!(
                        fields[6].parse::<u64>().unwrap() > 0,
                        "SubmissionGenerationUnbound"
                    );
                    if mode == "kill" {
                        assert!(
                            child.0.try_wait().unwrap().is_none(),
                            "SubmissionExitedBeforeKill"
                        );
                        child.0.kill().unwrap();
                        assert!(!child.0.wait().unwrap().success());
                    } else {
                        stream.get_mut().write_all(b"fail\n").unwrap();
                        assert!(
                            child.0.wait().unwrap().success(),
                            "SubmissionFailureControlFailed"
                        );
                    }
                }
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 130, "SubmissionFaultCaseCount");
}

macro_rules! metadata_process_cuts {
    ($exhaustive:expr) => {{
        use std::collections::{BTreeMap, BTreeSet};
        let exhaustive: bool = $exhaustive;
        let discovery = Fixture::new();
        let bytes = support::spill_bytes();
        let stage = discovery.create("file", &bytes);
        let faults = discovery.store.lock().unwrap().fault_control();
        faults.trace_sync();
        discovery.sync(42, stage).0.unwrap();
        let rows: Vec<_> = faults
            .sync_fired()
            .into_iter()
            .filter(|e| matches!(e.name, "sync.node_upload" | "sync.upload"))
            .collect();
        assert_eq!(
            rows.iter()
                .filter(|e| e.name == "sync.node_upload")
                .map(|e| e.object_kind)
                .collect::<BTreeSet<_>>(),
            ["manifest", "grain_list", "binmap", "sheaf"]
                .into_iter()
                .collect()
        );
        // Every disarmed selector runs this same fixture and seed. Compare the
        // exact prepared bytes from the child to the independently executed run.
        let control =
            cuts::run("node", "sync.node_upload", "before", 1, None, true, false).unwrap();
        assert_eq!(control, GrainId::of(&discovery.registered()));
        // Representative arm: the last "before" occurrence of every (selector,
        // object kind), which exercises each kind at its highest occurrence, plus
        // the first "accepted" row. The ignored sweep runs every row.
        let mut last: BTreeMap<_, u64> = BTreeMap::new();
        for row in rows.iter().filter(|row| row.phase == "before") {
            let at = last.entry((row.name, row.object_kind)).or_insert(0);
            *at = (*at).max(row.occurrence);
        }
        let accepted = rows.iter().position(|row| row.phase == "accepted");
        let selected: Vec<_> = rows
            .iter()
            .enumerate()
            .filter(|(at, row)| {
                exhaustive
                    || Some(*at) == accepted
                    || (row.phase == "before"
                        && last.get(&(row.name, row.object_kind)) == Some(&row.occurrence))
            })
            .map(|(_, row)| row)
            .collect();
        assert!(
            exhaustive || selected.len() >= 5,
            "SyncCutRepresentativeSelection"
        );
        for row in selected {
            cuts::run(
                if row.name == "sync.upload" {
                    "upload"
                } else {
                    "node"
                },
                row.name,
                row.phase,
                row.occurrence,
                Some(row.object_kind),
                true,
                true,
            );
        }
        assert!(rows.len() >= 8, "SyncCutEmptySelection");
    }};
}

/// Default suite: a representative arm covering every object kind and the
/// occurrence counter; the exhaustive sweep below is ignored by default.
#[test]
fn metadata_process_cuts_require_kind_and_occurrence() {
    metadata_process_cuts!(false);
}

/// Every discovered occurrence, one child process each. Run on demand with
/// `--run-ignored only`.
#[test]
#[ignore = "exhaustive sweep: one child process per discovered occurrence"]
fn metadata_process_cuts_exhaustive_sweep() {
    metadata_process_cuts!(true);
}

#[test]
fn process_cut_reports_refuse_missing_wrong_and_unbound_identity() {
    let valid = "FIRED,sync.node_upload,before,3,1,none,grain_list";
    assert_eq!(
        cuts::verify(valid, "sync.node_upload", "before", 3, Some("grain_list")),
        Ok(())
    );
    for (line, name, phase, occurrence, kind, error) in [
        (
            "",
            "sync.node_upload",
            "before",
            3,
            Some("grain_list"),
            "SyncCutReportMalformed",
        ),
        (
            valid,
            "sync.upload",
            "before",
            3,
            Some("grain_list"),
            "SyncCutFaultIdentity",
        ),
        (
            valid,
            "sync.node_upload",
            "accepted",
            3,
            Some("grain_list"),
            "SyncCutFaultIdentity",
        ),
        (
            valid,
            "sync.node_upload",
            "before",
            2,
            Some("grain_list"),
            "SyncCutFaultIdentity",
        ),
        (
            valid,
            "sync.node_upload",
            "before",
            0,
            Some("grain_list"),
            "SyncCutEmptySelection",
        ),
        (
            valid,
            "sync.node_upload",
            "before",
            3,
            Some("manifest"),
            "SyncCutObjectKind",
        ),
        (
            "FIRED,sync.capture,after,1,0,none,none",
            "sync.capture",
            "after",
            1,
            None,
            "SyncCutCaptureUnbound",
        ),
        (
            "FIRED,sync.reply,before,1,1,none,none",
            "sync.reply",
            "before",
            1,
            None,
            "SyncCutRequestUnbound",
        ),
    ] {
        assert_eq!(
            cuts::verify(line, name, phase, occurrence, kind),
            Err(error)
        );
    }
}

#[test]
fn sync_covers_other_handle_and_preserves_post_seal_writes_and_rename() {
    use granary_client::{CoordinationError, OverlayError};
    use granary_core::{manifest::Name, overlay_journal::Record};
    for seed in 0..8 {
        for cancel in [false, true] {
            let fixture = Fixture::new();
            let stage = fixture.create("file", b"abcdefgh");
            let second = fixture
                .store
                .lock()
                .unwrap()
                .overlay_transaction(|t| {
                    let second = t.open_stage(&[Name::new(b"file".to_vec()).unwrap()])?;
                    t.write(stage, 0, b"AA")?;
                    t.write(second, 2, b"BB")?;
                    t.write(second, 1, b"Z")?;
                    Ok(second)
                })
                .unwrap();
            assert_eq!(stage, second);
            let faults = fixture.store.lock().unwrap().fault_control();
            faults.trace_sync();
            // Attach walks once; sync admits seal, capture seam, then materialization.
            // The fired-seal premise below refuses a changed ordering.
            assert!(fixture.runtime.pause_blocking_at(0).is_err());
            let pause = fixture.runtime.pause_blocking_at(4).unwrap();
            assert!(fixture.runtime.pause_blocking_at(5).is_err());
            let waiter = fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default());
            let (reply, _) = fixture
                .runtime
                .run(seed, 100_000, async {
                    while !pause.entered() {
                        yield_once().await;
                    }
                    assert!(
                        faults.sync_fired().iter().any(|e| e.name == "sync.capture"
                            && e.phase == "after"
                            && e.capture > 0),
                        "SyncMaterializationPauseWrongPhase"
                    );
                    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
                    assert!(matches!(
                        fixture
                            .store
                            .lock()
                            .unwrap()
                            .overlay_transaction(|t| t.truncate(second, 0)),
                        Err(CoordinationError::Overlay(OverlayError::PendingShrink))
                    ));
                    fixture
                        .store
                        .lock()
                        .unwrap()
                        .overlay_transaction(|t| {
                            t.write(second, 0, b"later!!!")?;
                            t.write(second, 8, b"+")?;
                            t.namespace_record(Record::Move {
                                from: support::at("file"),
                                to: support::at("renamed"),
                            })?;
                            let unrelated = t.create_file(support::at("unrelated"), false)?;
                            t.write(unrelated, 0, b"ordinary writer progressed")?;
                            Ok(())
                        })
                        .unwrap();
                    if cancel {
                        drop(waiter);
                        pause.resume();
                        None
                    } else {
                        pause.resume();
                        Some(waiter.wait().await)
                    }
                })
                .unwrap();
            if cancel {
                assert!(reply.is_none());
                assert!(fixture.remote.attempts.lock().unwrap().is_empty());
                assert!(
                    fixture
                        .metrics()
                        .contains("granary_client_syncs_total{outcome=\"cancelled\"} 1\n")
                );
            } else {
                reply.unwrap().unwrap();
                fixture.assert_file(&fixture.registered(), "file", b"AZBBefgh");
            }
            fixture.sync(seed, stage).0.unwrap();
            fixture.assert_file(&fixture.registered(), "renamed", b"later!!!+");
            fixture
                .store
                .lock()
                .unwrap()
                .overlay_transaction(|t| t.truncate(second, 0))
                .unwrap();
        }
    }
}

#[test]
fn engine_replay_across_processes_includes_retry_jitter() {
    use std::process::{Command, Stdio};
    let replay = |seed: u64| {
        let scratch = support::Scratch::new();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sync_process_child", "--ignored", "--nocapture"])
            .env("GRANARY_SYNC_REPLAY_SEED", seed.to_string())
            .env("GRANARY_SYNC_SCRATCH", &scratch.0)
            .env_remove("GRANARY_RESTART_SOCKET")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "engine replay child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let artifact = stdout
            .lines()
            .find(|line| line.starts_with("REPLAY,"))
            .expect("SyncReplayArtifactMissing")
            .to_owned();
        let fields: Vec<_> = artifact.split(',').collect();
        assert_eq!(fields.len(), 3);
        assert!(fields[1].parse::<GrainId>().is_ok());
        assert!(
            fields[2].split(':').count() > 120,
            "SyncReplayEmptySchedule"
        );
        artifact
    };
    assert_eq!(
        replay(42_u64),
        replay(42_u64),
        "engine replay changed across processes"
    );
    assert_ne!(
        replay(42_u64),
        replay(43_u64),
        "engine replay ignored the seed"
    );
}

#[test]
fn hundred_writes_and_closes_coalesce_into_single_commit_attempt() {
    use granary_client::{DEFAULT_MAX_COALESCE_DELAY, DEFAULT_QUIESCE_DELAY, PublicationOutcome};
    use granary_core::manifest::Name;
    use granary_sim::secure_random::SeededSecureRandom;
    use std::sync::{Arc, atomic::AtomicBool};
    let run = |seed: u64| {
        let fixture = Fixture::new();
        let writer_done = Arc::new(AtomicBool::new(false));
        let engine = fixture.engine.clone();
        let writer_store = fixture.store.clone();
        let writer_remote = fixture.remote.clone();
        let done_flag = writer_done.clone();
        let writer = fixture.runtime.spawn(async move {
            let path = vec![Name::new(b"file".to_vec()).unwrap()];
            for i in 0..100_u32 {
                let payload = format!("write-{i:03}");
                let sends_before = writer_remote.publication_sends.lock().unwrap().len();
                writer_store
                    .lock()
                    .unwrap()
                    .overlay_transaction(|t| {
                        if i == 0 {
                            t.create_file(support::at("file"), false)?;
                        }
                        let stage = t.open_stage(&path)?;
                        t.write(stage, 0, payload.as_bytes())?;
                        t.close_stage(stage)
                    })
                    .unwrap();
                let sends_after = writer_remote.publication_sends.lock().unwrap().len();
                assert_eq!(
                    sends_after, sends_before,
                    "close_stage performed an inline commit on iteration {i}"
                );
                yield_once().await;
            }
            done_flag.store(true, Ordering::Release);
        });
        let (results, trace) = fixture
            .runtime
            .run(seed, 100_000, async move {
                let mut secure = SeededSecureRandom::for_incarnation(44, 0);
                let mut results = Vec::new();
                loop {
                    let result = engine
                        .coalesce_commit(SyncOptions::default(), &mut secure)
                        .await
                        .unwrap();
                    results.push(result);
                    if writer_done.load(Ordering::Acquire) {
                        break;
                    }
                }
                writer.await.unwrap();
                results
            })
            .unwrap();
        let elapsed = fixture.runtime.elapsed();
        let sends = fixture.remote.publication_sends.lock().unwrap().len();
        assert_eq!(
            (
                results.len(),
                sends,
                elapsed >= DEFAULT_QUIESCE_DELAY,
                elapsed < DEFAULT_MAX_COALESCE_DELAY,
            ),
            (1, 1, true, true),
            "100 writes and closes must coalesce into 1 commit after quiesce_delay: results={}, sends={sends}, elapsed={elapsed:?}",
            results.len(),
        );
        let PublicationOutcome::Landed(done) = &results[0].outcome else {
            panic!("expected landed commit, got {:?}", results[0].outcome);
        };
        fixture.assert_file(&done.root, "file", b"write-099");
        (GrainId::of(&done.root), trace)
    };
    for seed in [1, 42, 43] {
        run(seed);
    }
    assert_eq!(run(42), run(42), "coalescer replay must be deterministic");
    assert!(!run(42).1.is_empty(), "trace must be non-empty");
}

/// `DelayedLand` proves that the live loop resumes a retained lane after its
/// deadline cut and observes an authority landing recorded before that cut.
/// It does not prove that the cancelled publication attempt stays live, nor
/// that recovery needs a second publication dispatch.
#[test]
fn live_driver_resumes_a_retained_lane_instead_of_failing() {
    use granary_sim::secure_random::SeededSecureRandom;
    use std::time::Duration;
    use support::PublishPlan;

    let run = |seed: u64| {
        let fixture = Fixture::new();
        fixture.create("file", b"retained-live-lane");
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::DelayedLand]);
        let engine = fixture.engine.clone();
        let runner = fixture.runtime.clone();
        let ((pauses, constructions, sends, published, installed), trace) = runner
            .run(seed, 100_000, async move {
                let live = engine.clone().drive_live(
                    SyncOptions {
                        resolution_bound: Duration::from_secs(5),
                        quiesce_delay: Duration::ZERO,
                        max_coalesce_delay: Duration::ZERO,
                        ..SyncOptions::default()
                    },
                    SeededSecureRandom::for_incarnation(47, 0),
                );
                tokio::pin!(live);
                let observed = async {
                    while engine.live_pauses_for_test().is_empty()
                        || engine.live_lane_held_for_test().unwrap()
                    {
                        yield_once().await;
                    }
                    for _ in 0..20 {
                        yield_once().await;
                    }
                    (
                        engine.live_pauses_for_test(),
                        engine.live_constructions_for_test(),
                        fixture.remote.publication_sends.lock().unwrap().len(),
                        fixture.remote.published.lock().unwrap().contains_key(&2),
                        granary_core::root::decode_root(
                            &fixture.store.lock().unwrap().snapshot().root,
                        )
                        .unwrap()
                        .seq,
                    )
                };
                tokio::pin!(observed);
                // The loop is polled first, then the observer, in a fixed
                // order the sim can replay.
                std::future::poll_fn(|cx| {
                    if let std::task::Poll::Ready(end) = live.as_mut().poll(cx) {
                        panic!("live driver ended before landing: {end:?}");
                    }
                    observed.as_mut().poll(cx)
                })
                .await
            })
            .unwrap();
        assert_eq!(
            (
                constructions,
                pauses.first().map(|(base, _)| *base),
                sends,
                published,
                installed,
            ),
            (1, Some(Duration::from_secs(1)), 1, true, 2),
            "(constructions, first outage base, publication sends, authority landing, installed sequence)"
        );
        let drawn = pauses.first().unwrap().1;
        assert!(
            (Duration::from_millis(800)..=Duration::from_millis(1_200)).contains(&drawn),
            "outage draw {drawn:?} is outside ±20%"
        );
        (drawn, trace)
    };
    for seed in [1, 42, 43] {
        run(seed);
    }
    assert_eq!(run(42), run(42), "live-driver replay must be deterministic");
}

#[test]
fn quiescence_fires_after_delay_and_not_before() {
    use granary_client::{DEFAULT_MAX_COALESCE_DELAY, DEFAULT_QUIESCE_DELAY, PublicationOutcome};
    use granary_core::manifest::Name;
    use granary_sim::secure_random::SeededSecureRandom;
    use std::time::Duration;
    let run = |seed: u64| {
        let fixture = Fixture::new();
        let stage = fixture.create("file", b"open-handle");
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.open_stage(&[Name::new(b"file".to_vec()).unwrap()]))
            .unwrap();
        let engine = fixture.engine.clone();
        let store = fixture.store.clone();
        let remote = fixture.remote.clone();
        let runtime = fixture.runtime.clone();
        let writer = fixture.runtime.spawn(async move {
            // Hold the write handle open past DEFAULT_QUIESCE_DELAY (500 ms).
            runtime.sleep(Duration::from_millis(700)).await;
            let sends_while_open = remote.publication_sends.lock().unwrap().len();
            // Mutate again at 700 ms and close the write handle; the quiescence
            // window (500 ms) must measure from this last mutation and close.
            store
                .lock()
                .unwrap()
                .overlay_transaction(|t| {
                    t.write(stage, 0, b"final-bytes")?;
                    t.close_stage(stage)
                })
                .unwrap();
            let sends_on_close = remote.publication_sends.lock().unwrap().len();
            runtime.sleep(Duration::from_millis(300)).await;
            let sends_before_delay = remote.publication_sends.lock().unwrap().len();
            (sends_while_open, sends_on_close, sends_before_delay)
        });
        let ((landed, (sends_while_open, sends_on_close, sends_before_delay)), trace) = fixture
            .runtime
            .run(seed, 100_000, async move {
                let mut secure = SeededSecureRandom::for_incarnation(44, 0);
                let landed = engine
                    .coalesce_commit(SyncOptions::default(), &mut secure)
                    .await
                    .unwrap();
                let checks = writer.await.unwrap();
                (landed, checks)
            })
            .unwrap();
        let elapsed = fixture.runtime.elapsed();
        let sends_total = fixture.remote.publication_sends.lock().unwrap().len();
        assert_eq!(
            (
                sends_while_open,
                sends_on_close,
                sends_before_delay,
                sends_total,
                elapsed >= Duration::from_millis(700) + DEFAULT_QUIESCE_DELAY,
                elapsed < DEFAULT_MAX_COALESCE_DELAY,
            ),
            (0, 0, 0, 1, true, true),
            "quiescence must wait for handle close and full quiesce_delay: open={sends_while_open}, close={sends_on_close}, before={sends_before_delay}, total={sends_total}, elapsed={elapsed:?}",
        );
        let PublicationOutcome::Landed(done) = landed.outcome else {
            panic!("expected landed commit, got {:?}", landed.outcome);
        };
        fixture.assert_file(&done.root, "file", b"final-bytes");
        (GrainId::of(&done.root), trace)
    };
    for seed in [1, 42, 43] {
        run(seed);
    }
    assert_eq!(
        run(42),
        run(42),
        "quiescence schedule must be deterministic"
    );
}

#[test]
fn max_age_fires_for_steady_writer_that_never_quiesces() {
    use granary_client::{DEFAULT_MAX_COALESCE_DELAY, PublicationOutcome};
    use granary_core::manifest::Name;
    use granary_sim::secure_random::SeededSecureRandom;
    use std::time::Duration;
    let run = |seed: u64| {
        let fixture = Fixture::new();
        let _stage = fixture.create("file", b"step-00");
        let engine = fixture.engine.clone();
        let store = fixture.store.clone();
        let remote = fixture.remote.clone();
        let runtime = fixture.runtime.clone();
        let writer = fixture.runtime.spawn(async move {
            let path = vec![Name::new(b"file".to_vec()).unwrap()];
            let mut sends_before_max_age = 0;
            for step in 1..=60_u32 {
                runtime.sleep(Duration::from_millis(150)).await;
                if step == 20 {
                    sends_before_max_age = remote.publication_sends.lock().unwrap().len();
                }
                if !remote.publication_sends.lock().unwrap().is_empty() {
                    break;
                }
                let payload = format!("step-{step:02}");
                store
                    .lock()
                    .unwrap()
                    .overlay_transaction(|t| {
                        let s = t.open_stage(&path)?;
                        t.write(s, 0, payload.as_bytes())?;
                        t.close_stage(s)
                    })
                    .unwrap();
            }
            sends_before_max_age
        });
        let ((landed, sends_before_max_age), trace) = fixture
            .runtime
            .run(seed, 200_000, async move {
                let mut secure = SeededSecureRandom::for_incarnation(44, 0);
                let landed = engine
                    .coalesce_commit(SyncOptions::default(), &mut secure)
                    .await
                    .unwrap();
                let before = writer.await.unwrap();
                (landed, before)
            })
            .unwrap();
        let elapsed = fixture.runtime.elapsed();
        let sends_total = fixture.remote.publication_sends.lock().unwrap().len();
        assert_eq!(
            (
                sends_before_max_age,
                sends_total,
                elapsed >= DEFAULT_MAX_COALESCE_DELAY,
                elapsed < Duration::from_millis(5_500),
            ),
            (0, 1, true, true),
            "max-age must fire at max_coalesce_delay from first dirty record for a steady writer: before={sends_before_max_age}, total={sends_total}, elapsed={elapsed:?}",
        );
        let PublicationOutcome::Landed(done) = landed.outcome else {
            panic!("expected landed commit, got {:?}", landed.outcome);
        };
        (GrainId::of(&done.root), trace)
    };
    for seed in [1, 42, 43] {
        run(seed);
    }
    assert_eq!(run(42), run(42), "max-age schedule must be deterministic");
}

#[test]
fn pressure_wakes_coalescer_immediately() {
    use granary_client::{DEFAULT_MAX_COALESCE_DELAY, DEFAULT_QUIESCE_DELAY, PublicationOutcome};
    use granary_core::{
        manifest::Name,
        overlay_journal::{DeleteKind, Record},
    };
    use granary_sim::secure_random::SeededSecureRandom;
    use std::time::Duration;
    let run = |seed: u64| {
        let fixture = Fixture::with_case("pressure");
        let keep = fixture.create("file", b"pressure-commit");
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.open_stage(&[Name::new(b"file".to_vec()).unwrap()]))
            .unwrap();
        let engine = fixture.engine.clone();
        let store = fixture.store.clone();
        let remote = fixture.remote.clone();
        let runtime = fixture.runtime.clone();
        let writer = fixture.runtime.spawn(async move {
            // Hold `keep` open past quiesce_delay (500 ms) without pressure;
            // the coalescer must stay asleep until pressure arrives at 600 ms.
            runtime.sleep(Duration::from_millis(600)).await;
            let sends_before_pressure = remote.publication_sends.lock().unwrap().len();
            let requested = store
                .lock()
                .unwrap()
                .overlay_transaction(|t| {
                    let scratch = t.create_file(support::at("scratch"), false)?;
                    t.truncate(scratch, 165_000_000)?;
                    t.namespace_record(Record::Delete {
                        at: support::at("scratch"),
                        kind: DeleteKind::File {
                            stage_id: Some(scratch),
                        },
                    })?;
                    let _ = keep;
                    // Leave `keep` open: staging pressure on `scratch` must
                    // wake the coalescer immediately without waiting for
                    // `keep`'s handle to close or `max_coalesce_delay`.
                    Ok(t.summary().commit_requested)
                })
                .unwrap();
            (sends_before_pressure, requested)
        });
        let ((landed, (sends_before_pressure, requested)), trace) = fixture
            .runtime
            .run(seed, 100_000, async move {
                let mut secure = SeededSecureRandom::for_incarnation(44, 0);
                let landed = engine
                    .coalesce_commit(SyncOptions::default(), &mut secure)
                    .await
                    .unwrap();
                let checks = writer.await.unwrap();
                (landed, checks)
            })
            .unwrap();
        let elapsed = fixture.runtime.elapsed();
        let sends_total = fixture.remote.publication_sends.lock().unwrap().len();
        assert_eq!(
            (
                sends_before_pressure,
                requested,
                sends_total,
                elapsed >= Duration::from_millis(600),
                elapsed < Duration::from_millis(600) + DEFAULT_QUIESCE_DELAY,
                elapsed < DEFAULT_MAX_COALESCE_DELAY,
            ),
            (0, true, 1, true, true, true),
            "staging/journal pressure must wake coalescer immediately upon crossing threshold: before={sends_before_pressure}, requested={requested}, total={sends_total}, elapsed={elapsed:?}",
        );
        let PublicationOutcome::Landed(done) = landed.outcome else {
            panic!("expected landed commit, got {:?}", landed.outcome);
        };
        (GrainId::of(&done.root), trace)
    };
    for seed in [1, 42, 43] {
        run(seed);
    }
    assert_eq!(
        run(42),
        run(42),
        "pressure wakeup schedule must be deterministic"
    );
}

#[test]
fn coalesce_commit_cycles_draw_distinct_publication_ids() {
    use granary_client::PublicationOutcome;
    use granary_sim::secure_random::SeededSecureRandom;
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        let mut secure = SeededSecureRandom::for_incarnation(44, 0);
        fixture.create("first", b"cycle-one");
        let engine = fixture.engine.clone();
        let (first, _) = fixture
            .runtime
            .run(seed, 100_000, async {
                engine
                    .coalesce_commit(SyncOptions::default(), &mut secure)
                    .await
                    .unwrap()
            })
            .unwrap();
        fixture.create("second", b"cycle-two");
        let engine = fixture.engine.clone();
        let (second, _) = fixture
            .runtime
            .run(seed, 100_000, async {
                engine
                    .coalesce_commit(SyncOptions::default(), &mut secure)
                    .await
            })
            .unwrap();
        assert_eq!(
            (
                matches!(first.outcome, PublicationOutcome::Landed(_)),
                second
                    .as_ref()
                    .map(|second| (
                        matches!(second.outcome, PublicationOutcome::Landed(_)),
                        second.handle.publication_id != first.handle.publication_id,
                    ))
                    .map_err(ToString::to_string),
            ),
            (true, Ok((true, true))),
            "seed {seed}: two coalesced commit cycles in one fixture repeated publication_id {:?}: {second:?}",
            first.handle.publication_id,
        );
    }
}
