// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{HeadRelation, OwnedCandidate, VerifiedBase, classify_head};
use granary_core::root;

type HeldDrive = Pin<Box<dyn Future<Output = Result<crate::PublicationResult, CoordinationError>>>>;

/// Drive a fresh commit to its landed refresh: the landing is journaled and the
/// refresh is signed, but not yet sent. The drive is held there until the
/// caller resumes the fault and awaits it.
async fn drive_to_refresh(fixture: &Fixture) -> HeldDrive {
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Block);
    let engine = fixture.engine.clone();
    let mut driving: HeldDrive = Box::pin(async move {
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
    driving
}

/// The journal and every stage file a crash right now would leave.
fn overlay_disk(io: &SimIo) -> (Vec<u8>, BTreeMap<String, Vec<u8>>) {
    let journal = io
        .recovered_bytes("journal")
        .expect("the journal's name must be durable");
    let model = io.0.lock().unwrap();
    let (_, names) = model.recovered();
    let stages = names
        .iter()
        .filter(|(path, _)| {
            path.parent()
                .and_then(std::path::Path::file_name)
                .is_some_and(|directory| directory == "staging")
        })
        .map(|(path, id)| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                model.files[id].1.clone(),
            )
        })
        .collect();
    (journal, stages)
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one row carries the fault and exhaustion schedules through their common finish checks"
)]
async fn commit_lane_refresh_admission_ends_with_its_finish() {
    let mut cases = 0;
    for (route, expected) in [
        ("fault", "intent refused: SyncInjectedFault"),
        (
            "exhausted",
            "intent refused: IntentStartupAttemptsExhausted",
        ),
    ] {
        let fixture = Fixture::new().await;
        fixture.create("local", b"sealed");
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let faults = fixture.store.lock().unwrap().fault_control();
        if route == "fault" {
            faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Block);
        } else {
            fixture.remote.hold_first.store(true, Ordering::Relaxed);
            fixture.remote.unknown.store(true, Ordering::Relaxed);
        }
        let engine = fixture.engine.clone();
        let mut secure = Entropy(80);
        let mut delay = Delay;
        let mut driving = Box::pin(engine.drive_commit(
            &lane,
            &mut secure,
            &mut delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ));
        if route == "fault" {
            hold_at_seam(&mut driving, &faults, "sync.commit", "landed_refresh").await;
            let active = {
                let store = fixture.store.lock().unwrap();
                (
                    store.landing_refresh_for_test(),
                    store
                        .snapshot()
                        .pending
                        .iter()
                        .find(|pending| {
                            pending.operation == Operation::Register && !pending.terminal
                        })
                        .and_then(|pending| pending.generation().ok()),
                )
            };
            let Some(prepared) = active.1 else {
                faults.resume();
                panic!("premise: the held fault route must retain a Register: {active:?}")
            };
            if active.0 != Some(prepared) {
                faults.resume();
            }
            assert_eq!(
                active,
                (Some(prepared), Some(prepared)),
                "the held fault route must admit its retained Register: {active:?}"
            );
            faults.arm("sync.registration", "before_dispatch", 1, FaultAction::Fail);
            faults.resume();
        } else {
            let mut entered = Box::pin(fixture.remote.entered.notified());
            std::future::poll_fn(|context| {
                assert!(
                    driving.as_mut().poll(context).is_pending(),
                    "premise: the refresh drive must wait for its first unknown answer"
                );
                entered.as_mut().poll(context)
            })
            .await;
            let active = {
                let store = fixture.store.lock().unwrap();
                (
                    store.landing_refresh_for_test(),
                    store
                        .snapshot()
                        .pending
                        .iter()
                        .find(|pending| {
                            pending.operation == Operation::Register && !pending.terminal
                        })
                        .and_then(|pending| pending.generation().ok()),
                )
            };
            assert_eq!(
                active.0, active.1,
                "the live refresh field must name its retained Register: {active:?}"
            );
            tokio::time::pause();
            fixture.remote.release.notify_one();
        }
        let result = driving.await;
        let observed = {
            let mut store = fixture.store.lock().unwrap();
            (
                store.check_readiness().err().map(|error| error.to_string()),
                store.landing_refresh_for_test(),
            )
        };
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                observed.0,
                observed.1,
            ),
            (
                Some(expected.to_owned()),
                Some("intent refused: WritableRecoveryRequired".to_owned()),
                None,
            ),
            "route={route}: (finish error, readiness refusal, refresh admission)"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one schedule carries the fence, the restart refusal and the authority chain the displacing writer walks"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "test runs synchronous recovery on its own runtime while the asynchronous refresh fixture remains live"
)]
async fn superseded_landed_refresh_fences_and_coalesced_selection_is_subsumed() {
    let f = Fixture::new().await;
    f.create("local", b"sealed");
    // The prepared root this writer registered before the commit.
    f.engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let prepared = f.remote.authority.lock().unwrap().root.clone();
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let driving = drive_to_refresh(&f).await;
    let (commit, disk, sent) = (
        durable_commit_state(&f),
        overlay_disk(&f.io),
        f.remote.attempts.lock().unwrap().len(),
    );
    assert_eq!(
        (commit, disk.1.is_empty(), sent),
        ((Some(("complete", 1)), (true, false)), false, 1),
        "the seam must hold a journaled landing, no refresh, a stage on disk and the sync's one registration"
    );
    // A takeover under a new instance displaces this one before its refresh
    // arrives. Its generation differs from this writer's last receipt, so the
    // fence can only report it by recording the displacing row.
    let displacing = {
        let mut authority = f.remote.authority.lock().unwrap();
        let row = authority.row.unwrap();
        authority.cursor += 1;
        authority.row = Some(Receipt {
            epoch: authority.cursor,
            instance: [99; 16],
            generation: row.generation + 2,
            ..row
        });
        authority.row.unwrap()
    };
    f.store.lock().unwrap().fault_control().resume();
    let result = driving.await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            result.err().map(|error| error.to_string()),
            f.store.lock().unwrap().snapshot().phase,
            text.lines()
                .filter(|line| line
                    .contains("\"event\":\"op.failed\",\"kind\":\"commit\",\"class\":\"conflict\""))
                .count(),
        ),
        (
            Some(format!(
                "intent fenced (ESTALE), recorded generation Some({})",
                displacing.generation
            )),
            Phase::Fenced,
            1
        ),
        "{text}"
    );
    // A fenced store refuses to read its retained submission, so only the disk
    // and the authority's request count are compared: the refresh is the one
    // registration sent since the seam.
    assert_eq!(
        (
            overlay_disk(&f.io) == disk,
            f.remote.attempts.lock().unwrap().len()
        ),
        (true, sent + 1),
        "a refused refresh must not journal, replace the base or touch a stage"
    );
    // The acknowledged selection made no content change over its parent;
    // that verified parent's equal manifest proves it published.
    let landed = f.remote.published.lock().unwrap().get(&2).cloned().unwrap();
    assert_ne!(
        landed, prepared,
        "the landing must not be the prepared root"
    );
    let trusted =
        TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
    let head = VerifiedBase::attach(
        landed.clone(),
        "v",
        &trusted,
        f.content.as_ref(),
        f.remote.as_ref(),
    )
    .await
    .unwrap();
    let base = f.remote.published.lock().unwrap().get(&1).cloned().unwrap();
    f.content.put_object(GrainId::of(&base), &base).unwrap();
    assert_eq!(
        classify_head(
            &OwnedCandidate::new("v", prepared.clone().into()).unwrap(),
            &head,
            f.content.as_ref(),
            &trusted
        ),
        HeadRelation::Subsumed {
            by_seq: root::decode_root(&base).unwrap().seq,
            by_root: GrainId::of(&base),
        }
    );
    // A restart on the same disk reloads the fenced carrier and runs startup's
    // first step against it, which refuses on the recorded fence: nothing reaches
    // the authority and the overlay is left as the crash found it.
    let (io, remote) = (f.io.clone(), f.remote.clone());
    let before_restart = remote.attempts.lock().unwrap().len();
    let (_scratch, _io, _remote, mut local) = f.reload_carrier();
    let refused = local
        .settle_expired_release(&Tick(1_000_000))
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        (
            refused,
            remote.attempts.lock().unwrap().len(),
            overlay_disk(&io) == disk
        ),
        (
            Some(format!(
                "intent fenced (ESTALE), recorded generation Some({})",
                displacing.generation
            )),
            before_restart,
            true
        ),
        "restart must refuse, send nothing and preserve the overlay"
    );
    let writer = root::decode_root(&prepared).unwrap().writer_uuid;
    let sends = remote.publication_sends.lock().unwrap().len();
    let recovering = remote.clone();
    let recovered = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        selected::command_on(&Scratch::new(), &recovering, &runtime, writer, Some(writer))
    })
    .await
    .unwrap();
    assert_eq!(
        (
            recovered,
            remote.publication_sends.lock().unwrap().len(),
            remote.authority.lock().unwrap().row.unwrap().state
        ),
        (Ok(()), sends, ReceiptState::Released),
        "the coalesced selection is proved by its verified parent before any diff"
    );
}

/// The authority exposes a different signature envelope while the retained
/// completion continues to name exactly the submitted candidate.
async fn stored_refresh_cut(variant: bool, phase: &'static str) -> Fixture {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    if variant {
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::LandVariant);
    }
    fixture
        .store
        .lock()
        .unwrap()
        .fault_control()
        .arm("sync.commit", phase, 1, FaultAction::Fail);
    let error = first_commit_fault(&fixture, phase)
        .await
        .map(|e| e.to_string());
    assert_eq!(
        error,
        Some("intent refused: SyncInjectedFault".to_owned()),
        "phase={phase}: cut result"
    );
    let stored = fixture.remote.published.lock().unwrap()[&2].clone();
    let record = retained(&fixture);
    let granary_core::retained_submission::Phase::Complete(done) = &record.phase else {
        panic!(
            "premise: expected completion at {phase}, got {:?}",
            record.phase
        );
    };
    assert_eq!(
        (
            done.seq,
            done.id == GrainId::of(&stored),
            done.root == stored,
            done.receipt.is_some()
        ),
        (2, !variant, !variant, true),
        "phase={phase}: candidate/stored premise"
    );
    fixture
}

#[expect(
    clippy::used_underscore_binding,
    reason = "evidence reads use the scratch root retained for the fixture lifetime"
)]
fn retained(fixture: &Fixture) -> granary_core::retained_submission::Submission {
    let (_, _, _, bytes) = publication_files(&fixture._scratch.0)
        .into_iter()
        .find(|file| file.0.extension().is_some_and(|e| e == "sub"))
        .unwrap();
    granary_core::retained_submission::decode(&bytes).unwrap()
}

#[tokio::test]
async fn stored_landing_restart_cuts_replay_exactly_and_consume_a_fresh_grant_witness() {
    let mut cases = 0;
    for variant in [false, true] {
        for phase in ["landed_readback", "landed_refresh", "before_replace"] {
            let fixture = stored_refresh_cut(variant, phase).await;
            let original = retained(&fixture);
            let stored = fixture.remote.published.lock().unwrap()[&2].clone();
            let request = fixture
                .pending_registrations()
                .last()
                .map(|p| p.body.clone());
            let fixture = fixture.restart().await;
            let lane = fixture
                .engine
                .recover_commit(SyncOptions::default())
                .unwrap();
            let installed = Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut Entropy(82),
                &mut Delay,
                RecoveryIntent::ExplicitRecovery,
                SyncOptions::default(),
            ))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string());
            assert_eq!(
                installed,
                Ok(()),
                "variant={variant}, phase={phase}: stored-root refresh must finish without DirectorySync reconciliation"
            );
            let journal = fixture.io.recovered_bytes("journal").unwrap();
            let mut directory_syncs = 0;
            let scan = granary_core::overlay_journal::scan_journal_with(&journal, |_, record| {
                if matches!(
                    record,
                    Record::IntentRegistered {
                        cause: granary_core::overlay_journal::IntentCause::DirectorySync,
                        ..
                    }
                ) {
                    directory_syncs += 1;
                }
            })
            .unwrap();
            let carrier = fixture.store.lock().unwrap().snapshot().clone();
            let receipt = intent::decode_receipt(&carrier.current).unwrap();
            let attempts = fixture.remote.attempts.lock().unwrap();
            let exact = request
                .as_ref()
                .is_none_or(|request| attempts.iter().all(|sent| sent == request));
            assert_eq!(
                (
                    fixture.remote.publication_sends.lock().unwrap().len(),
                    attempts.len(),
                    exact,
                    scan.header.base_root,
                    scan.header.base_seq,
                    (
                        scan.header.receipt_generation,
                        scan.state.highest_generation()
                    ),
                    carrier.root == stored,
                    directory_syncs,
                    retained(&fixture).phase == original.phase,
                ),
                (
                    1,
                    1,
                    true,
                    GrainId::of(&stored),
                    2,
                    (1, receipt.generation),
                    true,
                    0,
                    true
                ),
                "variant={variant}, phase={phase}: sends/replay/header/ceiling/carrier/bookkeeping/completion"
            );
            assert_file(&fixture, &stored, "local", b"sealed");
            cases += 1;
        }
        for cut in [RestartCut::AfterReceipt, RestartCut::AfterGrant] {
            let fixture = stored_refresh_cut(variant, "landed_refresh").await;
            let request = fixture.pending_registrations().last().unwrap().body.clone();
            let fixture = fixture.restart_twice_at(cut).await;
            restart_drives_the_lane(&fixture, "landed_refresh", RecoveryIntent::ExplicitRecovery)
                .await;
            let attempts = fixture.remote.attempts.lock().unwrap();
            assert_eq!(
                (
                    attempts.len(),
                    attempts.iter().all(|sent| sent == &request),
                    fixture.remote.publication_sends.lock().unwrap().len()
                ),
                (1, true, 1)
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 10);
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "replace or remove retained evidence only in the test-owned scratch store"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one paired table binds replay and succession to missing, incomplete and malformed landing evidence"
)]
#[expect(
    clippy::used_underscore_binding,
    reason = "evidence changes use the scratch root retained for the fixture lifetime"
)]
async fn stored_landing_replay_uses_the_journal_even_without_completion_material() {
    let mut cases = 0;
    for variant in [false, true] {
        for material in [
            "complete",
            "wrong-seq",
            "incomplete",
            "missing",
            "foreign-prefix",
        ] {
            let fixture = stored_refresh_cut(variant, "landed_refresh").await;
            let path = publication_files(&fixture._scratch.0)
                .into_iter()
                .map(|file| file.0)
                .find(|path| path.extension().is_some_and(|e| e == "sub"))
                .unwrap();
            let mut record = retained(&fixture);
            if material == "wrong-seq" {
                fixture.io.mutate_recovered("journal", |bytes| {
                    let header = granary_core::overlay_journal::scan_journal(bytes)
                        .unwrap()
                        .header;
                    let mut rebuilt = header.encode().unwrap();
                    granary_core::overlay_journal::scan_journal_with(bytes, |seq, record| {
                        let mut record = record.clone();
                        if let Record::LandedCommit { landed_seq, .. } = &mut record {
                            *landed_seq += 1;
                        }
                        rebuilt.extend(
                            granary_core::overlay_journal::encode_record(&header, seq, &record)
                                .unwrap(),
                        );
                    })
                    .unwrap();
                    *bytes = rebuilt;
                });
            } else if material == "missing" {
                std::fs::remove_file(path).unwrap();
            } else if material != "complete" {
                record.current = record.candidates.last().map(|c| c.request);
                record.phase = granary_core::retained_submission::Phase::Ready;
                if material == "incomplete" {
                    record.candidates[0].evidence =
                        granary_core::retained_submission::Evidence::default();
                    record.last_response = None;
                }
                if material == "foreign-prefix" {
                    let mut candidate = record.candidates[0].clone();
                    let mut doc = root::decode_root(&candidate.root).unwrap();
                    doc.timestamp.secs += 1;
                    doc.sigs.clear();
                    let key = SigningKey::from_seed(&[39; 32]).unwrap();
                    doc.sigs.push(RootSig {
                        key_id: key.key_id(),
                        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
                    });
                    candidate.root = root::encode_root(&doc).unwrap();
                    candidate.id = GrainId::of(&candidate.root);
                    candidate.number = 2;
                    record.candidates[0].role = granary_core::retained_submission::Role::History;
                    record.phase = granary_core::retained_submission::Phase::Complete(
                        granary_core::retained_submission::Completion {
                            seq: candidate.seq,
                            id: candidate.id,
                            root: candidate.root.clone(),
                            receipt: None,
                        },
                    );
                    record.current = None;
                    record.candidates.push(candidate);
                }
                std::fs::write(
                    path,
                    granary_core::retained_submission::encode(&record).unwrap(),
                )
                .unwrap();
            }
            let (_scratch, _io, _remote, mut local) = fixture.reload_carrier();
            let replay = local
                .landed_replay()
                .map(|r| r.map(|r| r.request().bytes().to_vec()))
                .map_err(|e| e.to_string());
            let expected = (material != "foreign-prefix").then(|| {
                local
                    .snapshot()
                    .pending
                    .iter()
                    .find(|p| p.operation == Operation::Register && !p.terminal)
                    .unwrap()
                    .body
                    .clone()
            });
            assert_eq!(
                (
                    replay,
                    local
                        .prepare_succession(&Tick(2_000_000))
                        .err()
                        .map(|e| e.to_string())
                ),
                (
                    if material == "wrong-seq" {
                        Err("intent refused: IntentLandedReplayInvalid".to_owned())
                    } else {
                        Ok(expected)
                    },
                    if material == "wrong-seq" {
                        Some("intent refused: IntentLandedReplayInvalid".to_owned())
                    } else {
                        (material != "foreign-prefix")
                            .then(|| "intent refused: IntentReplayPending".to_owned())
                    }
                ),
                "variant={variant}, material={material}: replay and succession binding"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 10);
}

#[test]
fn stored_landing_recovery_prologue_replays_before_succession_or_reports_ownership_loss() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut cases = 0;
    for variant in [false, true] {
        for (displaced, expired) in [(false, false), (true, false), (false, true)] {
            let fixture = runtime.block_on(stored_refresh_cut(variant, "landed_refresh"));
            let stored = fixture.remote.published.lock().unwrap()[&2].clone();
            let request = fixture.pending_registrations().last().unwrap().body.clone();
            let (_scratch, _io, remote, mut local) = fixture.reload_carrier();
            if displaced {
                let mut authority = remote.authority.lock().unwrap();
                authority.row = authority.row.map(|row| Receipt {
                    epoch: row.epoch + 1,
                    ..row
                });
            }
            let scope = local.snapshot().scope.clone();
            let key = SigningKey::from_seed(&[39; 32]).unwrap();
            let pending = local
                .snapshot()
                .pending
                .iter()
                .find(|p| p.body == request)
                .unwrap();
            let replay_at = if expired {
                pending.expires
            } else {
                pending.eligible + 1_000
            };
            assert_eq!(
                (pending.eligible < replay_at, replay_at >= pending.expires),
                (true, expired),
                "variant={variant}, expired={expired}: (eligible, replay time, expiry) = {:?}",
                (pending.eligible, replay_at, pending.expires)
            );
            if expired {
                let replay = local.landed_replay().unwrap().unwrap();
                remote.authority.lock().unwrap().send(replay.request());
            }
            let sent_before = remote.authority.lock().unwrap().sends.len();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::recovery_prologue(
                    &mut local,
                    remote.as_ref(),
                    &runtime,
                    &scope,
                    key.public_key(),
                    &Tick(replay_at),
                    &mut SeededRng::new(1),
                )
            }))
            .map_err(|_| "prologue panicked".to_owned())
            .and_then(|result| result.map_err(|error| error.to_string()));
            let rule = local.recovery_rule().unwrap();
            let sends = remote.authority.lock().unwrap().sends.clone();
            let prologue_sends = &sends[sent_before..];
            assert_eq!(
                (
                    result,
                    (
                        prologue_sends.len(),
                        prologue_sends.iter().all(|sent| sent == &request)
                    ),
                    local.snapshot().root == stored,
                    rule,
                    remote.publication_sends.lock().unwrap().len()
                ),
                (
                    Ok(()),
                    (usize::from(!expired), true),
                    !displaced,
                    if displaced {
                        crate::RecoveryRule::LandedUnowned
                    } else {
                        crate::RecoveryRule::LandedUnrefreshed
                    },
                    1
                ),
                "variant={variant}, displaced={displaced}, expired={expired}: prologue replays before expiry and reads back at expiry"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6);
}

/// Leave Completion durable but remove the later journal append, modelling
/// a crash before stored bytes had any local witness.
fn remove_landing(io: &SimIo) {
    io.mutate_recovered("journal", |bytes| {
        let mut end = 0;
        for prefix in 1..=bytes.len() {
            let mut landed = false;
            if granary_core::overlay_journal::scan_journal_with(&bytes[..prefix], |_, record| {
                landed |= matches!(record, Record::LandedCommit { .. });
            })
            .is_ok_and(|scan| scan.valid_len == prefix && !landed)
            {
                end = prefix;
            }
        }
        assert!(
            end > 0,
            "the boundary must survive before its landing: end={end}"
        );
        bytes.truncate(end);
    });
}

#[tokio::test]
async fn stored_landing_refetch_failure_preserves_both_restart_cuts_without_sends() {
    let mut cases = 0;
    for variant in [false, true] {
        for journalled in [false, true] {
            let fixture = stored_refresh_cut(variant, "landed_readback").await;
            if !journalled {
                remove_landing(&fixture.io);
            }
            let fixture = fixture.restart().await;
            let before = (overlay_disk(&fixture.io), retained(&fixture));
            let lane = fixture
                .engine
                .recover_commit(SyncOptions::default())
                .unwrap();
            fixture.remote.offline.store(true, Ordering::Relaxed);
            let error = Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::ExplicitRecovery,
                SyncOptions::default(),
            ))
            .await
            .err()
            .map(|e| e.to_string());
            fixture.remote.offline.store(false, Ordering::Relaxed);
            assert_eq!(
                (
                    error,
                    overlay_disk(&fixture.io) == before.0,
                    retained(&fixture).phase == before.1.phase,
                    fixture.remote.publication_sends.lock().unwrap().len(),
                    fixture.remote.attempts.lock().unwrap().len()
                ),
                (
                    Some("intent refused: ViewRootUnavailable".to_owned()),
                    true,
                    true,
                    1,
                    0
                ),
                "variant={variant}, journalled={journalled}: failed read must preserve completion/journal and send nothing"
            );
            restart_drives_the_lane(
                &fixture,
                "landed_readback",
                RecoveryIntent::ExplicitRecovery,
            )
            .await;
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[tokio::test]
async fn stored_landing_refetch_distinguishes_unresolved_missing_integrity_and_binding() {
    let mut cases = 0;
    for variant in [false, true] {
        for fault in [
            "none", "empty", "stale", "missing", "head", "ancestry", "binding",
        ] {
            let fixture = stored_refresh_cut(variant, "landed_readback").await;
            let fixture = fixture.restart().await;
            let before = (overlay_disk(&fixture.io), retained(&fixture));
            let lane = fixture
                .engine
                .recover_commit(SyncOptions::default())
                .unwrap();
            {
                let mut roots = fixture.remote.published.lock().unwrap();
                let mut doc = root::decode_root(&roots[&2]).unwrap();
                match fault {
                    "empty" => roots.clear(),
                    "stale" => {
                        roots.remove(&2);
                    }
                    "head" => {
                        roots.insert(2, vec![0]);
                    }
                    "missing" | "ancestry" | "binding" => {
                        if fault == "binding" {
                            doc.timestamp.secs += 1;
                        } else {
                            doc.seq = 3;
                            doc.parent = Some(if fault == "missing" {
                                GrainId::of(&roots[&2])
                            } else {
                                GrainId::of(b"foreign parent")
                            });
                        }
                        let key = SigningKey::from_seed(&[39; 32]).unwrap();
                        doc.sigs.clear();
                        let prefix = root::signing_prefix_of(&doc).unwrap();
                        doc.sigs.push(RootSig {
                            key_id: key.key_id(),
                            sig: key.sign(&prefix),
                        });
                        roots.insert(doc.seq, root::encode_root(&doc).unwrap());
                        if fault == "missing" {
                            roots.remove(&2);
                        }
                    }
                    "none" => (),
                    _ => unreachable!(),
                }
            }
            let error = Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::ExplicitRecovery,
                SyncOptions::default(),
            ))
            .await
            .err();
            let expected = match fault {
                "none" => None,
                "empty" | "stale" => Some((
                    "intent refused: SyncCommitUnresolved",
                    crate::FailureClass::Unavailable,
                )),
                "missing" => Some((
                    "intent refused: ViewRootUnpublished",
                    crate::FailureClass::Refused,
                )),
                "head" => Some(("untrusted probe head", crate::FailureClass::Corrupt)),
                "ancestry" => Some(("probe ancestry mismatch", crate::FailureClass::Corrupt)),
                "binding" => Some((
                    "intent refused: SyncCommitLandingBinding",
                    crate::FailureClass::Refused,
                )),
                _ => unreachable!(),
            }
            .map(|(reason, class)| (reason.to_owned(), class));
            assert_eq!(
                (
                    error
                        .as_ref()
                        .map(|error| (error.to_string(), crate::sync::failure_class(error))),
                    fault == "none"
                        || (overlay_disk(&fixture.io) == before.0
                            && retained(&fixture).phase == before.1.phase),
                    fixture.remote.publication_sends.lock().unwrap().len(),
                    fixture.remote.attempts.lock().unwrap().len(),
                ),
                (expected, true, 1, usize::from(fault == "none")),
                "variant={variant}, fault={fault}: refetch keeps its failure class and failed reads preserve evidence without sends"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 14);
}

#[tokio::test]
async fn stored_landing_witness_needs_the_recovering_instances_grant() {
    let mut cases = 0;
    for variant in [false, true] {
        let fixture = stored_refresh_cut(variant, "before_replace").await;
        let stored = fixture.remote.published.lock().unwrap()[&2].clone();
        let (_scratch, _io, remote, mut local) = fixture.reload_carrier();
        let before = local.landed_refresh_registered(&stored, false).unwrap();
        let request = local.prepare_succession(&Tick(2_000_000)).unwrap();
        local.dispatch(&request, &Tick(2_000_000)).unwrap();
        let answer = remote.authority.lock().unwrap().send(&request);
        local
            .complete(
                &request,
                Ok(&answer),
                &Tick(2_000_001),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        assert_eq!(
            (
                before,
                local.landed_refresh_registered(&stored, false).unwrap(),
                remote.attempts.lock().unwrap().len()
            ),
            (false, true, 1),
            "variant={variant}: only the fresh instance may consume the durable witness"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn stored_landing_lost_refresh_answer_replays_the_old_owner_bytes_after_restart() {
    let mut cases = 0;
    for variant in [false, true] {
        let fixture = stored_refresh_cut(variant, "landed_refresh").await;
        let body = {
            let mut local = fixture.store.lock().unwrap();
            let request = local
                .retained_requests()
                .into_iter()
                .find(|r| r.operation() == Operation::Register)
                .unwrap();
            local
                .dispatch_landed_replay(&request, &Tick(1_900_000))
                .unwrap();
            fixture.remote.authority.lock().unwrap().send(&request);
            local
                .complete_landed_replay(
                    &request,
                    Err(IntentTransportError::Transport),
                    &Tick(1_900_001),
                    &mut SeededRng::new(1),
                    0,
                    None,
                )
                .unwrap();
            request.bytes().to_vec()
        };
        fixture.remote.attempts.lock().unwrap().push(body.clone());
        let restarted = fixture.try_restart_over(vec![]).await;
        assert_eq!(
            restarted
                .as_ref()
                .map(|_| ())
                .map_err(std::string::ToString::to_string),
            Ok(()),
            "variant={variant}: the lost answer must replay before conditional succession"
        );
        let fixture = restarted.unwrap();
        let lane = fixture
            .engine
            .recover_commit(SyncOptions::default())
            .unwrap();
        let installed = Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(82),
            &mut Delay,
            RecoveryIntent::ExplicitRecovery,
            SyncOptions::default(),
        ))
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
        let attempts = fixture.remote.attempts.lock().unwrap();
        assert_eq!(
            (
                installed,
                attempts.len(),
                attempts.iter().all(|sent| sent == &body),
                fixture.remote.publication_sends.lock().unwrap().len()
            ),
            (Ok(()), 2, true, 1),
            "variant={variant}: a lost answer replays exactly before ownership transfer"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}
