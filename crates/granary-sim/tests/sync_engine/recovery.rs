// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![expect(clippy::unwrap_used, reason = "checked simulator fixture invariants")]

use super::support::{
    BinRangeRead, Delay, Fixture, PublishPlan, TakeoverChange, bin_extent, prepared_root,
};
use granary_client::{
    PublicationOutcome, RecoveryIntent, RecoveryRule, SelectedPublication, SyncOptions,
};
use granary_core::{
    hash::GrainId,
    manifest,
    overlay_ownership::Phase,
    retained_submission::{Phase as SubmissionPhase, ProbeReason},
    root::{RootSig, signing_prefix_of},
};
use granary_sim::secure_random::SeededSecureRandom;
use granary_store::crypto::SigningKey;

const FOREIGN: [u8; 16] = [77; 16];

#[path = "recovery/journal.rs"]
mod journal;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "proof archives and matched integrity faults share the same local evidence assertions"
)]
fn archived_proof_rederivation_distinguishes_integrity_from_abandonment() {
    use granary_client::{
        AbandonAcknowledgement, FaultControl, MayLandAcknowledgement, NoWriteProof, ProbeOutcome,
        RejectionProof,
    };
    use granary_store::crypto::TrustedKeys;
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for fenced in [false, true] {
        for ending in [
            "no-write",
            "never-landed",
            "contradiction-exact",
            "contradiction-variant",
            "acknowledged",
            "interrupted-promotion",
            "interrupted-promotion-aliases",
            "missing",
            "missing-chain",
        ] {
            let fixture = Fixture::new();
            fixture.create("local", b"sealed");
            fixture
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .extend((0..8).map(|_| {
                    if ending == "no-write" {
                        PublishPlan::RateLimited
                    } else {
                        PublishPlan::Timeout
                    }
                }));
            let (lane, _) = fixture
                .runtime
                .run(
                    19,
                    100_000,
                    fixture.engine.construct_commit(
                        SyncOptions::default(),
                        &mut SeededSecureRandom::for_incarnation(44, 0),
                    ),
                )
                .unwrap();
            let lane = lane.unwrap();
            if fenced {
                let (result, _) = fixture
                    .runtime
                    .run(
                        20,
                        100_000,
                        fixture.engine.drive_commit(
                            &lane,
                            &mut SeededSecureRandom::for_incarnation(45, 0),
                            &mut Delay,
                            RecoveryIntent::Continue,
                            SyncOptions::default(),
                        ),
                    )
                    .unwrap();
                assert_eq!(
                    result.unwrap().outcome,
                    PublicationOutcome::Exhausted,
                    "{ending}: exhausted premise"
                );
            }
            let foreign = prepare(&fixture, 21, &[("other", b"foreign")], FOREIGN);
            let higher = if ending == "missing-chain" {
                let seq = granary_core::root::decode_root(&foreign).unwrap().seq;
                fixture
                    .remote
                    .published
                    .lock()
                    .unwrap()
                    .insert(seq, foreign.clone());
                let higher = prepare(&fixture, 22, &[("higher", b"head")], [88; 16]);
                fixture.remote.published.lock().unwrap().remove(&seq);
                Some(higher)
            } else {
                None
            };
            let (scratch, remote, runtime, mut local, mut record) = fixture.into_recovery_store();
            if !fenced && ending != "no-write" {
                let attempt = record.candidates[0].evidence.start().unwrap();
                record.phase = SubmissionPhase::AwaitingAnswer {
                    candidate: 1,
                    attempt,
                };
                record.generation += 1;
                local
                    .overlay_transaction(|t| {
                        t.record_commit_attempt(lane.boundary_seq(), record.publication_id, 1)
                    })
                    .unwrap();
                local
                    .publication_transaction(|j| j.replace(record.generation - 1, &record))
                    .unwrap();
            }
            let attempts = if fenced {
                8
            } else {
                u64::from(ending != "no-write")
            };
            let candidate = record.candidates[0].clone();
            assert_eq!(
                granary_core::root::decode_root(&foreign).unwrap().seq,
                candidate.seq,
                "foreign sequence premise"
            );
            if ending != "no-write" {
                remote
                    .published
                    .lock()
                    .unwrap()
                    .insert(candidate.seq, foreign.clone());
            }
            let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()])
                .unwrap();
            let proof = if ending == "no-write" {
                Some(RejectionProof::NoWrite(
                    NoWriteProof::from_submission(&record, attempts).unwrap(),
                ))
            } else if ending == "acknowledged" {
                None
            } else {
                let (probe, _) = runtime
                    .run(
                        22,
                        100_000,
                        granary_client::probe_submission(remote.as_ref(), &record, attempts, &keys),
                    )
                    .unwrap();
                let probe = probe.unwrap();
                let ProbeOutcome::NeverLanded(proof) = probe else {
                    panic!("foreign proof premise: {probe:?}")
                };
                Some(RejectionProof::NeverLanded(proof))
            };
            let faults = FaultControl::default();
            let abandonment = local
                .publication_transaction(|j| {
                    if matches!(
                        ending,
                        "interrupted-promotion" | "interrupted-promotion-aliases"
                    ) {
                        j.abandon(
                            &record.scope,
                            &record.volume,
                            record.publication_id,
                            MayLandAcknowledgement::Acknowledged,
                        )?;
                    }
                    j.abandon(
                        &record.scope,
                        &record.volume,
                        record.publication_id,
                        match &proof {
                            Some(proof) => AbandonAcknowledgement::Proven(proof, &faults),
                            None => AbandonAcknowledgement::MayLand(
                                MayLandAcknowledgement::Acknowledged,
                            ),
                        },
                    )
                })
                .unwrap();
            if ending.starts_with("interrupted-promotion") {
                assert!(
                    abandonment.archive.settled,
                    "proof-checked promotion premise"
                );
                let plain = abandonment.archive.path.with_file_name(
                    granary_core::retained_archive::ArchiveName {
                        volume: record.volume.clone(),
                        publication_id: record.publication_id,
                        settled: false,
                    }
                    .file_name(),
                );
                if ending == "interrupted-promotion" {
                    std::fs::rename(abandonment.archive.path, plain).unwrap();
                } else {
                    std::fs::hard_link(abandonment.archive.path, plain).unwrap();
                }
            }
            let archive = local
                .publication_transaction(|j| {
                    j.inspect_archive(
                        &record.scope.digest().unwrap(),
                        &record.volume,
                        record.publication_id,
                    )
                })
                .unwrap();
            assert_eq!(
                (archive.settled, archive.submission.phase == record.phase),
                (proof.is_some() && ending != "interrupted-promotion", true,),
                "{ending}: archive premise {archive:?}"
            );
            let mut replacements = 0;
            if ending.starts_with("contradiction")
                || matches!(
                    ending,
                    "acknowledged" | "interrupted-promotion" | "interrupted-promotion-aliases"
                )
            {
                let mut doc = granary_core::root::decode_root(&candidate.root).unwrap();
                if ending.ends_with("variant") {
                    doc.sigs.push(RootSig {
                        key_id: [98; 32],
                        sig: [0; 64],
                    });
                }
                let bytes = granary_core::root::encode_root(&doc).unwrap();
                if ending.starts_with("contradiction") {
                    replacements = remote.replace_published_head_for_test(
                        candidate.seq,
                        GrainId::of(&foreign),
                        bytes,
                    );
                } else {
                    remote
                        .published
                        .lock()
                        .unwrap()
                        .insert(candidate.seq, bytes);
                }
            }
            if ending == "missing" {
                remote.published.lock().unwrap().remove(&candidate.seq);
            } else if let Some(higher) = higher {
                let seq = granary_core::root::decode_root(&higher).unwrap().seq;
                remote.published.lock().unwrap().remove(&candidate.seq);
                remote.published.lock().unwrap().insert(seq, higher);
            }
            let before = scratch.evidence();
            let output = super::commit_faults::Capture::default();
            let dispatch = granary_client::subscriber(
                granary_client::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                output.clone(),
            );
            let (result, _) = tracing::subscriber::with_default(dispatch, || {
                runtime.run(
                    23,
                    100_000,
                    granary_client::settle_recovery_boundary(
                        &mut local,
                        remote.as_ref(),
                        &keys,
                        None,
                    ),
                )
            })
            .unwrap();
            let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
            let after = scratch.evidence();
            let changed = before != after;
            let staging = |(path, _): &(&std::path::PathBuf, &Vec<u8>)| {
                path.components().any(|part| part.as_os_str() == "staging")
            };
            let staged = (
                before.iter().filter(staging).count() > 0,
                before
                    .iter()
                    .filter(staging)
                    .eq(after.iter().filter(staging)),
            );
            let refusal = result.err().map(|error| error.to_string());
            actual.push((
                fenced,
                ending,
                refusal,
                local.recovery_rule().unwrap(),
                text.lines()
                    .filter(|line| {
                        line.contains("\"event\":\"recover.archived_landed\"")
                            && line.contains(&format!("\"seq\":{}", candidate.seq))
                    })
                    .count(),
                text.matches("\"event\":\"recover.fence_settled\"").count(),
                changed,
                remote.publication_sends.lock().unwrap().len(),
                replacements,
                staged,
                text.matches("\"event\":\"recover.unresolved\"").count(),
            ));
            let matched = ending.starts_with("contradiction")
                || matches!(
                    ending,
                    "acknowledged" | "interrupted-promotion" | "interrupted-promotion-aliases"
                );
            let pending = ending == "missing";
            let integrity = ending == "missing-chain";
            expected.push((
                fenced,
                ending,
                if pending {
                    Some("intent refused: RecoveryArchivedUnresolved".to_owned())
                } else if integrity {
                    Some("RecoveryRemoteIntegrity: probe chain root missing".to_owned())
                } else if matched {
                    Some(
                        if matches!(ending, "acknowledged" | "interrupted-promotion") {
                            "intent refused: RecoveryArchivedLanded"
                        } else {
                            "RecoveryRemoteIntegrity: archived non-landing contradicted"
                        }
                        .to_owned(),
                    )
                } else {
                    None
                },
                if matched || pending || integrity {
                    RecoveryRule::BoundaryArchived
                } else {
                    RecoveryRule::DirtyJournal
                },
                usize::from(matched),
                usize::from(!matched && !pending && !integrity),
                !matched && !pending && !integrity,
                if fenced { 8 } else { 0 },
                usize::from(ending.starts_with("contradiction")),
                (true, true),
                usize::from(pending),
            ));
        }
    }
    assert_eq!(actual.len(), 18);
    assert_eq!(
        actual, expected,
        "archive provenance/refusal/classifier/events/evidence/sends/fault count"
    );
}

#[test]
fn archived_deferred_probe_failure_refuses_without_changing_evidence() {
    use granary_client::MayLandAcknowledgement;
    use granary_store::crypto::TrustedKeys;

    let fixture = Fixture::new();
    fixture.create("local", b"sealed");
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::StaleForeignUnreadable);
    let (result, _) = fixture
        .runtime
        .run(61, 100_000, async {
            let lane = fixture
                .engine
                .construct_commit(
                    SyncOptions::default(),
                    &mut SeededSecureRandom::for_incarnation(44, 0),
                )
                .await
                .unwrap();
            fixture
                .engine
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
    let (scratch, remote, runtime, mut local, mut record) = fixture.into_recovery_store();
    assert!(
        matches!(
            &record.phase,
            SubmissionPhase::Unresolved(probe)
                if probe.reason == ProbeReason::ContentUnavailable
        ) && record
            .last_response
            .as_ref()
            .is_some_and(|response| !response.answer.is_empty()),
        "deferred answer premise: {record:?}"
    );
    assert_eq!(result.outcome, PublicationOutcome::Unresolved);
    let generation = record.generation;
    record.candidates[0].evidence.proved_no_write = 0;
    record.generation += 1;
    granary_core::retained_submission::validate(&record).unwrap();
    local
        .publication_transaction(|j| j.replace(generation, &record))
        .unwrap();
    local
        .publication_transaction(|j| {
            j.abandon(
                &record.scope,
                &record.volume,
                record.publication_id,
                MayLandAcknowledgement::Acknowledged,
            )
        })
        .unwrap();
    let before = scratch.evidence();
    remote.fail_next_probe_for_test();
    let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
    let (result, _) = runtime
        .run(
            62,
            100_000,
            granary_client::settle_recovery_boundary(&mut local, remote.as_ref(), &keys, None),
        )
        .unwrap();
    assert_eq!(
        (
            result.err().map(|error| error.to_string()),
            local.recovery_rule().unwrap(),
            before == scratch.evidence(),
        ),
        (
            Some("intent refused: RecoveryArchivedUnresolved".to_owned()),
            RecoveryRule::BoundaryArchived,
            true,
        ),
        "transient probe refusal/classifier/exact slot bytes"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the restart row keeps the retained and recovered states in one timeline"
)]
fn sync_driver_keeps_deferred_stale_base_live() {
    let fixture = Fixture::new();
    fixture.create("local", b"sealed");
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::StaleForeignUnreadable);
    let (first, _) = fixture
        .runtime
        .run(61, 100_000, async {
            let lane = fixture
                .engine
                .construct_commit(
                    SyncOptions::default(),
                    &mut SeededSecureRandom::for_incarnation(44, 0),
                )
                .await
                .unwrap();
            fixture
                .engine
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
    let (phase, answer, boundaries) = fixture.retained_answer_state();
    assert!(
        matches!(
            &phase,
            SubmissionPhase::Unresolved(probe)
                if probe.reason == ProbeReason::ContentUnavailable
        ),
        "deferred answer phase: {phase:?}"
    );
    assert_eq!(
        (
            first.outcome,
            answer,
            boundaries,
            fixture.remote.publication_sends.lock().unwrap().len(),
        ),
        (PublicationOutcome::Unresolved, true, 1, 1),
        "the answered lane must remain unresolved, retained and unsent"
    );

    let fixture = fixture.restart();
    let lane = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    let (continued, _) = fixture
        .runtime
        .run(62, 100_000, async {
            fixture
                .engine
                .drive_commit(
                    &lane,
                    &mut SeededSecureRandom::for_incarnation(46, 0),
                    &mut Delay,
                    RecoveryIntent::Continue,
                    SyncOptions::default(),
                )
                .await
                .unwrap()
        })
        .unwrap();
    assert_eq!(
        (
            continued.outcome,
            fixture.retained_answer_state(),
            fixture.remote.publication_sends.lock().unwrap().len(),
        ),
        (PublicationOutcome::Unresolved, (phase, true, 1), 1,),
        "restart and ordinary continuation must preserve the live marker"
    );

    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Land);
    let (recovered, _) = fixture
        .runtime
        .run(63, 100_000, async {
            fixture
                .engine
                .drive_commit(
                    &lane,
                    &mut SeededSecureRandom::for_incarnation(47, 0),
                    &mut Delay,
                    RecoveryIntent::ExplicitRecovery,
                    SyncOptions::default(),
                )
                .await
                .unwrap()
        })
        .unwrap();
    assert_eq!(
        (
            matches!(recovered.outcome, PublicationOutcome::Landed(_)),
            fixture.remote.publication_sends.lock().unwrap().len(),
        ),
        (true, 2),
        "healthy recovery must classify the old answer before one fresh candidate send"
    );
}

#[test]
fn b1_b2_fences_require_evidence_or_one_explicit_resend() {
    let mut cases = 0;
    for ending in ["no-write", "foreign", "landed", "empty", "ack"] {
        let fixture = Fixture::new();
        fixture.create("local", b"sealed");
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend((0..8).map(|_| {
                if ending == "no-write" {
                    PublishPlan::RateLimited
                } else {
                    PublishPlan::Timeout
                }
            }));
        let (result, _) = fixture
            .runtime
            .run(19, 100_000, async {
                let lane = fixture
                    .engine
                    .construct_commit(
                        SyncOptions::default(),
                        &mut SeededSecureRandom::for_incarnation(44, 0),
                    )
                    .await
                    .unwrap();
                fixture
                    .engine
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
        assert!(
            matches!(result.outcome, PublicationOutcome::Exhausted),
            "{ending}: exhaustion premise: {result:?}"
        );
        if ending == "foreign" {
            fixture.publish_root(prepare(&fixture, 20, &[("other", b"foreign")], FOREIGN));
        }
        if ending == "landed" {
            let bytes = fixture.remote.publication_sends.lock().unwrap()[0].clone();
            fixture.publish_root(bytes);
        }
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Timeout);
        let observed = fixture.settle_fence(21, ending == "ack");
        let expected = match ending {
            "empty" => (
                Some("intent refused: RecoveryUnresolved".to_owned()),
                8,
                RecoveryRule::BoundaryRecorded,
            ),
            "ack" => (
                Some("intent refused: RecoveryResendUnanswered".to_owned()),
                9,
                RecoveryRule::BoundaryRecorded,
            ),
            "landed" => (None, 8, RecoveryRule::LandedUnrefreshed),
            _ => (None, 8, RecoveryRule::DirtyJournal),
        };
        assert_eq!(
            observed, expected,
            "{ending}: publication_sends must not grow without exact acknowledgement"
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

fn prepare(fixture: &Fixture, seed: u64, files: &[(&str, &[u8])], writer: [u8; 16]) -> Vec<u8> {
    fixture
        .runtime
        .run(seed, 100_000, prepared_root(fixture, files, writer))
        .unwrap()
        .0
}

fn land_overlay(fixture: &Fixture, seed: u64) -> Vec<u8> {
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
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("fixture commit did not land: {result:?}")
    };
    done.root
}

fn landed(outcome: &SelectedPublication) -> Option<&[u8]> {
    match outcome {
        SelectedPublication::Driven(result) => match &result.outcome {
            PublicationOutcome::Landed(done) => Some(&done.root),
            _ => None,
        },
        SelectedPublication::Subsumed { .. } | SelectedPublication::Stale => None,
    }
}

fn fetched(trace: &[BinRangeRead], extent: ([u8; 32], u64, u32)) -> bool {
    trace
        .iter()
        .any(|read| !read.bytes.is_empty() && (read.digest, read.offset, read.length) == extent)
}

fn contains_bytes(trace: &[BinRangeRead], body: &[u8]) -> bool {
    trace
        .iter()
        .any(|read| read.bytes.windows(body.len()).any(|window| window == body))
}

fn remote_names(fixture: &Fixture, seed: u64, root: &[u8]) -> Vec<Vec<u8>> {
    let seq = granary_core::root::decode_root(root).unwrap().seq;
    let (_, objects) = fixture
        .runtime
        .run(
            seed,
            100_000,
            granary_client::resolve_at_collecting(fixture.remote.as_ref(), "v", seq),
        )
        .unwrap()
        .0
        .unwrap();
    let doc = granary_core::root::decode_root(root).unwrap();
    let (_, cursor) =
        granary_core::encoding::open_envelope(objects.get(&doc.manifest_root).unwrap()).unwrap();
    manifest::decode_dir_leaf(cursor)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name.as_bytes().to_vec())
        .collect()
}

#[test]
fn a0_readback_selects_exactly_one_writer_among_zero_one_or_more_live_rows() {
    let fixture = Fixture::new();
    let selected = fixture.writer();
    let selected_root = fixture.registered();
    let singleton = fixture
        .select_from_readback(selected)
        .map(|selection| GrainId::of(selection.root_bytes()))
        .map_err(|error| error.to_string());
    let other_root = prepare(&fixture, 1, &[("other", b"other writer")], FOREIGN);
    fixture.add_live_writer(FOREIGN, 17, 3, other_root);
    let multiple = fixture
        .select_from_readback(selected)
        .map(|selection| GrainId::of(selection.root_bytes()))
        .map_err(|error| error.to_string());
    fixture.remove_writer(selected);
    let missing = fixture
        .select_from_readback(selected)
        .map(|selection| GrainId::of(selection.root_bytes()))
        .map_err(|error| error.to_string());
    fixture.remove_writer(FOREIGN);
    let empty = fixture
        .select_from_readback(selected)
        .map(|selection| GrainId::of(selection.root_bytes()))
        .map_err(|error| error.to_string());
    let rows = [singleton, multiple, missing, empty];
    assert_eq!(
        rows,
        [
            Ok(GrainId::of(&selected_root)),
            Ok(GrainId::of(&selected_root)),
            Err("intent refused: IntentSelectedWriterMissing".to_owned()),
            Err("intent refused: IntentSelectedWriterMissing".to_owned())
        ],
        "(one live row, two live rows, one unrelated row, zero live rows); four readbacks ran"
    );
    assert_eq!(rows.len(), 4, "all readback controls ran");
    assert!(!rows.is_empty());
}

#[test]
fn a1_a9_conflict_while_a2_a3_have_published_ancestry() {
    let mut cases = 0;
    for seed in [1, 42, 43] {
        for row in ["A1", "A2", "A3", "A9"] {
            let fixture = Fixture::new();
            let writer = fixture.writer();
            let prepared = prepare(&fixture, seed, &[("a", b"selected")], writer);
            let (expected_seq, expected_root) = match row {
                "A2" => {
                    fixture.publish_root(prepared.clone());
                    (2, GrainId::of(&prepared))
                }
                "A3" => {
                    fixture.publish_root(prepared.clone());
                    let head = prepare(&fixture, seed + 100, &[("b", b"foreign")], FOREIGN);
                    fixture.publish_root(head);
                    (2, GrainId::of(&prepared))
                }
                "A1" | "A9" => {
                    let later = prepare(
                        &fixture,
                        seed + 200,
                        &[("a", if row == "A9" { b"landed" } else { b"later" })],
                        writer,
                    );
                    let id = GrainId::of(&later);
                    fixture.publish_root(later);
                    (2, id)
                }
                _ => unreachable!(),
            };
            let selected_id = GrainId::of(&prepared);
            fixture.select_registered(prepared);
            let (outcome, authority, sends) = fixture.try_recover_destroyed(seed);
            // Same-writer siblings are log-identical across displacement;
            // only an ancestry or content witness authorizes subsumption.
            let expected = if matches!(row, "A1" | "A9") {
                (
                    false,
                    true,
                    Some(granary_core::intent::ReceiptState::Live {
                        prepared_root_id: selected_id,
                    }),
                    0,
                )
            } else {
                (
                    true,
                    false,
                    Some(granary_core::intent::ReceiptState::Released),
                    0,
                )
            };
            assert_eq!(
                (
                    matches!(&outcome, Ok(SelectedPublication::Subsumed { by_seq, by_root })
                    if *by_seq == expected_seq && *by_root == expected_root),
                    outcome
                        .as_ref()
                        .is_err_and(|error| error.to_string().contains("rebase conflict")),
                    authority,
                    sends
                ),
                expected,
                "seed {seed} {row}: {outcome:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 12, "every row and seed ran");
}

#[test]
fn a4_stale_and_a7_conflict_keep_the_row_and_publish_nothing() {
    let mut cases = 0;
    for seed in [1, 42, 43] {
        for row in ["A4", "A7"] {
            let fixture = Fixture::new();
            let writer = fixture.writer();
            let prepared = prepare(&fixture, seed, &[("a", b"selected")], writer);
            if row == "A4" {
                let mut divergent = granary_core::root::decode_root(&fixture.base).unwrap();
                divergent.writer_uuid = FOREIGN;
                divergent.sigs.clear();
                let key = SigningKey::from_seed(&[39; 32]).unwrap();
                divergent.sigs.push(RootSig {
                    key_id: key.key_id(),
                    sig: key.sign(&signing_prefix_of(&divergent).unwrap()),
                });
                fixture
                    .remote
                    .published
                    .lock()
                    .unwrap()
                    .insert(1, granary_core::root::encode_root(&divergent).unwrap());
            } else {
                let conflicting = prepare(&fixture, seed + 300, &[("a", b"foreign")], FOREIGN);
                fixture.publish_root(conflicting);
            }
            fixture.select_registered(prepared);
            let (outcome, authority, sends) = fixture.try_recover_destroyed(seed);
            let stopped = if row == "A4" {
                matches!(outcome, Ok(SelectedPublication::Stale))
            } else {
                outcome
                    .as_ref()
                    .is_err_and(|error| error.to_string().contains("rebase conflict"))
            };
            assert!(
                stopped
                    && matches!(
                        authority,
                        Some(granary_core::intent::ReceiptState::Live { .. })
                    )
                    && sends == 0,
                "seed {seed} {row}: (outcome, row, sends) = ({outcome:?}, {authority:?}, {sends})"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6, "every refusal row and seed ran");
}

#[test]
fn a5_exact_recovery_fetches_structure_but_no_file_grains() {
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        let writer = fixture.writer();
        fixture.create("unchanged", b"parent bytes");
        let parent = land_overlay(&fixture, seed);
        let prepared = prepare(
            &fixture,
            seed + 400,
            &[("a", b"selected bytes"), ("unchanged", b"parent bytes")],
            writer,
        );
        let novel = fixture
            .runtime
            .run(
                seed,
                100_000,
                bin_extent(&fixture, &prepared, GrainId::of(b"selected bytes")),
            )
            .unwrap()
            .0;
        let unchanged = fixture
            .runtime
            .run(
                seed,
                100_000,
                bin_extent(&fixture, &parent, GrainId::of(b"parent bytes")),
            )
            .unwrap()
            .0;
        fixture.select_registered(prepared.clone());
        fixture.clear_bin_ranges();
        let (outcome, _, sends) = fixture.recover_destroyed(seed);
        let trace = fixture.bin_ranges();
        assert_eq!(
            (
                landed(&outcome) == Some(prepared.as_slice()),
                sends,
                fetched(&trace, novel),
                fetched(&trace, unchanged),
                contains_bytes(&trace, b"selected bytes"),
                contains_bytes(&trace, b"parent bytes"),
            ),
            (true, 1, false, false, false, false),
            "seed {seed}: (P landed exactly, sends, exact P/parent extents fetched, \
             P/parent bytes fetched); trace={trace:?}"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one A6 run pairs the first rebase's trace with the stale-base retry's, across seeds"
)]
fn a6_verified_set_rebase_and_stale_base_retry_fetch_only_structure_and_novel_grains() {
    let mut cases = 0;
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        let writer = fixture.writer();
        fixture.create("unchanged", b"parent bytes");
        let parent = land_overlay(&fixture, seed);
        let prepared = prepare(
            &fixture,
            seed + 500,
            &[("a", b"selected bytes"), ("unchanged", b"parent bytes")],
            writer,
        );
        let foreign = prepare(
            &fixture,
            seed + 600,
            &[("b", b"foreign bytes"), ("unchanged", b"parent bytes")],
            FOREIGN,
        );
        fixture.publish_root(foreign.clone());
        let novel = fixture
            .runtime
            .run(
                seed,
                100_000,
                bin_extent(&fixture, &prepared, GrainId::of(b"selected bytes")),
            )
            .unwrap()
            .0;
        let unchanged = fixture
            .runtime
            .run(
                seed,
                100_000,
                bin_extent(&fixture, &parent, GrainId::of(b"parent bytes")),
            )
            .unwrap()
            .0;
        let foreign_grain = fixture
            .runtime
            .run(
                seed,
                100_000,
                bin_extent(&fixture, &foreign, GrainId::of(b"foreign bytes")),
            )
            .unwrap()
            .0;
        let retry_head = prepare(
            &fixture,
            seed + 700,
            &[
                ("b", b"foreign bytes"),
                ("c", b"retry bytes"),
                ("unchanged", b"parent bytes"),
            ],
            FOREIGN,
        );
        let retry_manifest = granary_core::root::decode_root(&retry_head)
            .unwrap()
            .manifest_root;
        assert_ne!(
            retry_manifest,
            granary_core::root::decode_root(&foreign)
                .unwrap()
                .manifest_root,
            "retry head must introduce new structure: {retry_head:?}"
        );
        let retry_grain = fixture
            .runtime
            .run(
                seed,
                100_000,
                bin_extent(&fixture, &retry_head, GrainId::of(b"retry bytes")),
            )
            .unwrap()
            .0;
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::StaleRoot(retry_head), PublishPlan::Land]);
        fixture.select_registered(prepared);
        fixture.clear_bin_ranges();
        let prior_sends = fixture.remote.publication_sends.lock().unwrap().len();
        let (outcome, _, sends) = fixture.recover_destroyed(seed);
        let trace = fixture.bin_ranges();
        let retry_trace = trace
            .iter()
            .filter(|read| read.publication_sends == prior_sends + 1)
            .cloned()
            .collect::<Vec<_>>();
        let names = landed(&outcome)
            .map(|root| remote_names(&fixture, seed, root))
            .unwrap_or_default();
        let diagnostic = match &outcome {
            SelectedPublication::Driven(result) => result.diagnostic.as_deref(),
            _ => None,
        };
        let retry_head = fixture
            .remote
            .published
            .lock()
            .unwrap()
            .get(&4)
            .unwrap()
            .clone();
        let retry_node = fixture
            .runtime
            .run(
                seed,
                100_000,
                bin_extent(
                    &fixture,
                    &retry_head,
                    granary_core::root::decode_root(&retry_head)
                        .unwrap()
                        .manifest_root,
                ),
            )
            .unwrap()
            .0;
        assert_eq!(
            (
                sends,
                names,
                fetched(&trace, novel),
                fetched(&trace, unchanged),
                fetched(&trace, foreign_grain),
                fetched(&retry_trace, retry_node),
                fetched(&trace, retry_grain),
                contains_bytes(&trace, b"retry bytes"),
                contains_bytes(&trace, b"parent bytes"),
                contains_bytes(&trace, b"foreign bytes"),
            ),
            (
                2,
                vec![
                    b"a".to_vec(),
                    b"b".to_vec(),
                    b"c".to_vec(),
                    b"unchanged".to_vec()
                ],
                true,
                false,
                false,
                true,
                false,
                false,
                false,
                false,
            ),
            "seed {seed}: (sends, names, P novel, exact parent/head file extents, retry-head node, retry file extent/bytes, parent/head bytes fetched); diagnostic={diagnostic:?}; trace={trace:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3, "every retry seed ran");
}

#[test]
fn a8_each_changed_takeover_compare_limb_stops_after_one_send() {
    let mut cases = 0;
    for seed in [1, 42, 43] {
        for change in [
            TakeoverChange::Epoch,
            TakeoverChange::Generation,
            TakeoverChange::State,
            TakeoverChange::Absent,
        ] {
            let fixture = Fixture::new();
            let (status, phase, error, sends, retained) = fixture.changed_takeover(seed, change);
            let exact_stop = match change {
                TakeoverChange::Epoch | TakeoverChange::Absent => {
                    phase == Phase::Fenced
                        && error
                            .as_deref()
                            .is_some_and(|error| error.contains("intent fenced"))
                }
                TakeoverChange::Generation | TakeoverChange::State => {
                    phase == Phase::Unowned
                        && error
                            .as_deref()
                            .is_some_and(|error| error.contains("IntentSelectionChanged"))
                }
            };
            assert!(
                status == 409 && exact_stop && (sends, retained) == (1, 0),
                "seed {seed} {change:?}: (status, phase, error, sends, retained) = ({status}, {phase:?}, {error:?}, {sends}, {retained})"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 12, "each compare limb and seed ran");
}

#[test]
fn a10_intact_clean_store_succeeds_to_a_fresh_instance_then_publishes_p() {
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        let writer = fixture.writer();
        let prepared = prepare(&fixture, seed, &[("a", b"intact unpublished")], writer);
        fixture.register_root(seed, &prepared);
        let before = fixture.store.lock().unwrap().recovery_rule().unwrap();
        let (early, early_sends, after_succession, outcome, row, sends) =
            fixture.recover_intact(seed);
        assert_eq!(
            (
                before,
                early
                    .as_deref()
                    .is_some_and(|error| error.contains("IntentFreshInstanceRequired")),
                early_sends,
                after_succession,
                landed(&outcome) == Some(prepared.as_slice()),
                row,
                sends,
            ),
            (
                RecoveryRule::Classify,
                true,
                0,
                RecoveryRule::Classify,
                true,
                Some(granary_core::intent::ReceiptState::Released),
                1,
            ),
            "seed {seed}: (rule before restart, early ownership refusal, early sends, \
             after succession, P landed, row, sends): early={early:?}"
        );
    }
}
