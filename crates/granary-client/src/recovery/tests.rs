// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{CoordinationError, OverlayError, WritableStartError};
use granary_core::retained_submission::{
    Candidate, Evidence, FrozenIntent, RequestIdentity, Scope,
};
use granary_core::root::{self, RootDoc, RootSig, Timestamp, VolumeName};
use granary_store::crypto::SigningKey;
use std::collections::BTreeMap;

fn root_bytes(stamp: i64) -> Vec<u8> {
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    let mut doc = RootDoc {
        volume: VolumeName::new("recovery-vol".into()).unwrap(),
        seq: 1,
        parent: None,
        writer_uuid: [3; 16],
        epoch: 1,
        timestamp: Timestamp {
            secs: stamp,
            nanos: 0,
        },
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(b"frozen"),
        binmap_index: GrainId::of(b"index"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: Vec::new(),
    };
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    root::encode_root(&doc).unwrap()
}

fn candidate(number: u64, epoch: u8, root: Vec<u8>) -> Candidate {
    Candidate {
        number,
        role: Role::Active,
        request: RequestIdentity {
            epoch: [epoch; 16],
            operation: [epoch; 16],
        },
        seq: 1,
        id: GrainId::of(&root),
        root,
        evidence: Evidence {
            started: 1,
            ..Evidence::default()
        },
    }
}

pub(crate) fn record() -> Submission {
    let a = candidate(1, 1, root_bytes(1));
    Submission {
        generation: 1,
        publication_id: [7; 16],
        scope: Scope {
            authority_base: b"https://authority".to_vec(),
            pins: vec![],
            credential_context: b"writer".to_vec(),
        },
        volume: VolumeName::new("recovery-vol".into()).unwrap(),
        frozen: FrozenIntent {
            writer_identity: [3; 16],
            min_prefix_bits: 0,
            initial_root: a.root.clone(),
        },
        current: Some(a.request),
        candidates: vec![a],
        phase: Phase::Ready,
        last_response: None,
        unavailable_exemptions: 0,
    }
}

#[test]
fn named_overlay_capacity_refusal_is_a_recovery_limit() {
    let rows = [
        (
            RecoveryCommandError::Coordination(CoordinationError::Overlay(OverlayError::Refused(
                "OverlayCapacityExhausted",
            ))),
            true,
        ),
        (
            RecoveryCommandError::Start(WritableStartError::Coordination(
                CoordinationError::Overlay(OverlayError::Refused("OverlayCapacityExhausted")),
            )),
            true,
        ),
        (
            RecoveryCommandError::Coordination(CoordinationError::Refused(
                "SyncWorkspaceExhausted",
            )),
            false,
        ),
    ];
    assert_eq!(rows.len(), 3);
    for (error, expected) in rows {
        assert_eq!(command::recovery_at_limit(&error), expected, "{error:?}");
    }
}

#[test]
fn two_reinitialisations_keep_a_and_b_when_a_lands_late() {
    let seed = 19307;
    let mut record = record();
    let a = record.candidates.first().unwrap().clone();
    // Acceptance and reply loss leave a surviving, delayed create-only write.
    let mut held = vec![a.clone()];
    let mut roots = BTreeMap::new();
    retire(&mut record, [2; 16]);
    assert!(!roots.contains_key(&1), "seed {seed}");
    let b = candidate(2, 2, root_bytes(2));
    assert_ne!(a.id, b.id, "seed {seed}");
    record.current = Some(b.request);
    record.candidates.push(b.clone());
    record.phase = Phase::Ready;
    held.push(b);
    retire(&mut record, [3; 16]);
    // A arrives only after B has retired; B subsequently loses the same slot.
    for write in held {
        roots.entry(write.seq).or_insert(write.root);
    }
    let occupant = GrainId::of(roots.get(&1).unwrap());
    let winner = record
        .candidates
        .iter()
        .find(|candidate| (candidate.seq, candidate.id) == (1, occupant))
        .cloned();
    compare(&mut record, winner.as_ref(), [(1, occupant)]);
    assert!(
        matches!(&record.phase, Phase::Complete(done) if done.id == a.id && done.root == a.root),
        "seed {seed}: earliest owned candidate must complete"
    );
    assert_eq!(roots.len(), 1, "seed {seed}");
    assert!(
        !roots.contains_key(&2),
        "seed {seed}: no successor publication"
    );
}

mod admission;
mod lost;
mod mount_owned;
mod probe;
pub(crate) mod support;
mod workspace;
use crate::{Policy, PublishResponse, ServiceReason, StatusResponse};
use granary_core::authlog::Epoch;
use granary_core::authority_answer::{Bound, Position, PublishAnswer};
use support::*;

#[test]
fn recovery_entry_futures_stay_small_on_worker_stack() {
    let clock = FixedClock(1);
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let retained = record();
    let publication = handle(&retained);
    let future = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &clock,
            &mut delay,
        ),
        &publication,
        RecoveryIntent::ExplicitRecovery,
    );
    let resume = std::mem::size_of_val(&future);
    drop(future);

    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let retained = record();
    let publication = handle(&retained);
    let future = coordinator::resume_store_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &clock,
            &mut delay,
        ),
        &publication,
        RecoveryIntent::ExplicitRecovery,
        retained.frozen.writer_identity,
    );
    let store_resume = std::mem::size_of_val(&future);
    drop(future);

    let (transport, mut journal, _, keys, _, _) = setup();
    let mut retained = record();
    retained.phase = Phase::Unresolved(granary_core::retained_submission::Probe {
        cycle: retained.generation,
        seq: retained.candidates[0].seq,
        reason: ProbeReason::ContentUnavailable,
    });
    let future =
        coordinator::replay_deferred_answer(&transport, &mut journal, &mut retained, &keys);
    let deferred = std::mem::size_of_val(&future);
    assert_eq!(
        (resume <= 2_048, store_resume <= 2_048, deferred <= 1_024),
        (true, true, true),
        "worker-stack futures: resume={resume}, store_resume={store_resume}, deferred={deferred}"
    );
}

#[tokio::test]
async fn lost_store_exact_recovery_reads_structure_nodes_and_never_file_grains() {
    for recovered in [false, true] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let tree = journal.tree();
        let grain = GrainId::of(b"frozen grain");
        let prepared = crate::publish::prepare_from_state(
            &transport,
            &journal,
            tree,
            crate::HarvestStats::default(),
            &record().volume,
            &key,
            &granary_core::identity::WriterIdentity::from_bytes([7; 16]),
            Timestamp { secs: 1, nanos: 0 },
            Policy::default(),
            crate::publish::RemoteState::empty(),
        )
        .await
        .unwrap();
        let mut doc = root::decode_root(&prepared.root_bytes).unwrap();
        doc.writer_uuid = [31; 16];
        doc.sigs.clear();
        let prefix = root::signing_prefix_of(&doc).unwrap();
        doc.sigs.push(RootSig {
            key_id: key.key_id(),
            sig: key.sign(&prefix),
        });
        let bytes = root::encode_root(&doc).unwrap();
        // The disk is lost: nothing local survives.
        let mut lost = Journal::new(transport.durable.clone());
        lost.recovered = recovered.then(crate::RecoveredObjects::default);
        transport.remote.lock().unwrap().range_reads = 0;
        transport.remote.lock().unwrap().plans.push_back(Plan::Land);
        let done = begin_exact_publication(
            parts(
                &transport,
                &mut lost,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            record().scope,
            record().volume,
            [31; 16],
            bytes.clone(),
        )
        .await
        .unwrap();
        let PublicationOutcome::Landed(done) = done.outcome else {
            panic!("recovered={recovered}: exact P did not land")
        };
        assert_eq!(done.root, bytes);
        let verified: Vec<_> = lost
            .recovered
            .as_ref()
            .map(|r| r.verified.keys().copied().collect())
            .unwrap_or_default();
        assert_eq!(
            (
                transport.remote.lock().unwrap().range_reads,
                lost.objects.contains_key(&tree),
                lost.objects.contains_key(&grain),
                verified,
            ),
            if recovered {
                (1, true, false, vec![tree])
            } else {
                (2, false, false, vec![])
            },
            "recovered={recovered}: (range reads, node stored, grain stored, verified set)"
        );
    }
}

#[test]
fn merged_manifest_admits_only_head_mapped_or_verified_references() {
    let (_transport, mut journal, ..) = setup();
    let tree = journal.tree();
    let grain = GrainId::of(b"frozen grain");
    let outside = Some("merged manifest outside the verified set".to_owned());
    let cases = [
        ("node and grain verified", vec![tree, grain], None),
        (
            "grain present in the store, outside the verified set",
            vec![tree],
            outside.clone(),
        ),
        (
            "node present in the store, outside the verified set",
            vec![grain],
            outside,
        ),
    ];
    for (row, verified, refusal) in cases {
        let mut recovered = crate::RecoveredObjects::default();
        for id in verified {
            recovered.verified.insert(id, journal.objects[&id].len());
        }
        journal.recovered = Some(recovered);
        let result =
            super::preparation::check_recovered(&mut journal, &BTreeMap::new(), tree).err();
        assert_eq!(result.map(|e| e.to_string()), refusal, "{row}");
    }
}

#[tokio::test]
async fn exact_prepared_candidate_preserves_bytes_writer_and_retention() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    let prepared = crate::publish::prepare_from_state(
        &transport,
        &journal,
        tree,
        crate::HarvestStats::default(),
        &record().volume,
        &key,
        &granary_core::identity::WriterIdentity::from_bytes([7; 16]),
        Timestamp { secs: 1, nanos: 0 },
        Policy::default(),
        crate::publish::RemoteState::empty(),
    )
    .await
    .unwrap();
    let mut doc = root::decode_root(&prepared.root_bytes).unwrap();
    doc.writer_uuid = [31; 16];
    doc.sigs.clear();
    let prefix = root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    let bytes = root::encode_root(&doc).unwrap();
    assert!(matches!(
        begin_exact_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay
            ),
            record().scope,
            record().volume,
            [32; 16],
            bytes.clone()
        )
        .await,
        Err(RecoveryError::Invalid("exact prepared writer"))
    ));
    assert!(transport.remote.lock().unwrap().sends.is_empty());
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let pending = begin_exact_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        [31; 16],
        bytes.clone(),
    )
    .await
    .unwrap();
    assert_eq!(pending.outcome, PublicationOutcome::Pending);
    let retained = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(retained.frozen.initial_root, bytes);
    assert_eq!(retained.candidates[0].root, bytes);
    let encoded = granary_core::retained_submission::encode(&retained).unwrap();
    assert_eq!(
        granary_core::retained_submission::decode(&encoded).unwrap(),
        retained,
        "retention changed the exact prepared candidate"
    );
    transport.remote.lock().unwrap().plans.push_back(Plan::Land);
    let done = resume_exact_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        &pending.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    let PublicationOutcome::Landed(done) = done.outcome else {
        panic!("exact candidate did not land")
    };
    assert_eq!(done.root, bytes, "exact retry rebuilt selected P");
    assert_eq!(transport.remote.lock().unwrap().sends.len(), 2);
}

#[test]
fn all_submissions_control_retirement() {
    use super::coordinator::apply_answer;
    for earlier in [
        None,
        Some(PublishResponse::RateLimited),
        Some(PublishResponse::ServiceUnavailable(
            ServiceReason::EnrollmentUnavailable,
        )),
        Some(PublishResponse::ServiceUnavailable(
            ServiceReason::Unavailable,
        )),
        Some(PublishResponse::Internal),
    ] {
        let mut r = record();
        // Attempt one was already durably started. Unanswered means uncertain.
        if let Some(answer) = earlier {
            apply_answer(&mut r, 1, 1, answer).unwrap();
        }
        let attempt = r.candidates.first_mut().unwrap().evidence.start().unwrap();
        apply_answer(&mut r, 1, attempt, PublishResponse::RateLimited).unwrap();
        retire(&mut r, [2; 16]);
        let released = matches!(
            earlier,
            Some(
                PublishResponse::RateLimited
                    | PublishResponse::ServiceUnavailable(ServiceReason::EnrollmentUnavailable)
            )
        );
        assert_eq!(r.candidates.is_empty(), released, "earlier={earlier:?}");
    }
}

#[test]
fn decision_and_all_conflict_histories_use_exact_no_write_predicate() {
    for seen in [false, true] {
        let mut r = record();
        r.candidates
            .first_mut()
            .unwrap()
            .evidence
            .answer(1, true, seen)
            .unwrap();
        retire(&mut r, [2; 16]);
        assert_eq!(r.candidates.len(), usize::from(seen));
    }
    let mut r = record();
    r.candidates
        .first_mut()
        .unwrap()
        .evidence
        .answer(1, false, true)
        .unwrap();
    let attempt = r.candidates.first_mut().unwrap().evidence.start().unwrap();
    r.candidates
        .first_mut()
        .unwrap()
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    retire(&mut r, [2; 16]);
    assert_eq!(r.candidates.len(), 1);
}

#[test]
fn same_manifest_is_not_landing_proof_and_empty_releases_nothing() {
    let mut r = record();
    retire(&mut r, [2; 16]);
    let before = r.candidates.clone();
    // Empty has no occupant to compare and leaves the full catalogue intact.
    assert_eq!(r.candidates, before);
    compare(&mut r, None, [(1, GrainId::of(&root_bytes(99)))]);
    assert!(!r.is_complete());
    assert!(r.candidates.is_empty());
}

#[tokio::test]
async fn durable_exact_resend_and_terminal_completion_with_differing_log_seq() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let begun = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    transport.remote.lock().unwrap().plans.push_back(Plan::Land);
    let done = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(99),
            &mut delay,
        ),
        &begun.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    let PublicationOutcome::Landed(completion) = done.outcome else {
        panic!("not complete")
    };
    assert_eq!(completion.receipt.unwrap().position.entry_seq, 91);
    assert_eq!(completion.seq, 1);
    let sends = transport.remote.lock().unwrap().sends.clone();
    assert_eq!(sends.len(), 2);
    assert_eq!(sends.first(), sends.get(1));
    let probes = transport.remote.lock().unwrap().probes;
    let again = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(100),
            &mut delay,
        ),
        &begun.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(again.outcome, PublicationOutcome::Landed(completion));
    assert_eq!(transport.remote.lock().unwrap().sends.len(), 2);
    assert_eq!(transport.remote.lock().unwrap().probes, probes);
}

#[tokio::test]
async fn bound_open_swaps_roles_preserving_candidate_attempt_numbers() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let mut r = record();
    let a = r.candidates.first_mut().unwrap();
    a.role = Role::History;
    a.evidence.started = 3;
    let a = a.clone();
    let mut b = candidate(2, 1, root_bytes(2));
    b.request = a.request;
    b.evidence.started = 0;
    r.candidates.push(b);
    *transport.durable.lock().unwrap() = Some(r.clone());
    transport.remote.lock().unwrap().plans.extend([
        Plan::Wire(PublishAnswer::OperationBound(Bound::Open {
            position: Position {
                epoch: Epoch::from_bytes([1; 16]),
                entry_seq: 88,
            },
            candidate_id: a.id,
        })),
        Plan::LostReply,
    ]);
    let out = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(3),
            &mut delay,
        ),
        &handle(&r),
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::Pending);
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    let a2 = durable.candidates.first().unwrap();
    let b2 = durable.candidates.get(1).unwrap();
    assert_eq!(a2.role, Role::Active);
    assert!(a2.evidence.decision_seen);
    assert_eq!(a2.evidence.started, 4);
    assert_eq!(a2.evidence.last_answered_attempt, 0);
    assert_eq!(b2.role, Role::History);
    assert_eq!(b2.evidence.started, 1);
    assert_eq!(b2.evidence.proved_no_write, 1);
    assert_eq!(
        transport.remote.lock().unwrap().sends.get(1).unwrap().3,
        a.root
    );
}

#[tokio::test]
async fn failed_interrupted_and_loaded_rebase_require_explicit_recovery() {
    for phase in [
        Phase::Ready,
        Phase::ProbeStarted(granary_core::retained_submission::Probe {
            cycle: 1,
            seq: 1,
            reason: granary_core::retained_submission::ProbeReason::Started,
        }),
        Phase::Rebase,
    ] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let mut r = record();
        r.phase = phase.clone();
        *transport.durable.lock().unwrap() = Some(r.clone());
        transport.remote.lock().unwrap().fail_probe = true;
        let out = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::Continue,
        )
        .await
        .unwrap();
        assert_eq!(out.outcome, PublicationOutcome::Unresolved);
        let probes = transport.remote.lock().unwrap().probes;
        assert_eq!(probes, usize::from(matches!(phase, Phase::Ready)));
        let again = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::Continue,
        )
        .await
        .unwrap();
        assert_eq!(again.outcome, PublicationOutcome::Unresolved);
        assert_eq!(transport.remote.lock().unwrap().probes, probes);
        resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::ExplicitRecovery,
        )
        .await
        .unwrap();
        assert_eq!(transport.remote.lock().unwrap().probes, probes + 1);
        assert!(transport.remote.lock().unwrap().sends.is_empty());
    }
}

#[tokio::test]
async fn persistence_faults_stop_network_and_fresh_handle_resumes() {
    for cut in 1..=5 {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let r = record();
        *transport.durable.lock().unwrap() = Some(r.clone());
        journal.fail_at = Some(cut);
        transport
            .remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::LostReply);
        let out = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::Continue,
        )
        .await;
        assert!(out.is_err(), "cut {cut}");
        assert!(journal.poisoned);
        let sends = transport.remote.lock().unwrap().sends.len();
        let probes = transport.remote.lock().unwrap().probes;
        assert!(
            resume_publication(
                parts(
                    &transport,
                    &mut journal,
                    &key,
                    &keys,
                    &mut entropy,
                    &FixedClock(1),
                    &mut delay
                ),
                &handle(&r),
                RecoveryIntent::Continue
            )
            .await
            .is_err()
        );
        assert_eq!(transport.remote.lock().unwrap().sends.len(), sends);
        assert_eq!(transport.remote.lock().unwrap().probes, probes);
        let mut fresh = Journal::new(transport.durable.clone());
        transport
            .remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::LostReply);
        resume_publication(
            parts(
                &transport,
                &mut fresh,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::ExplicitRecovery,
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn bootstrap_ignores_status_head_and_never_falls_back() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport.remote.lock().unwrap().plans.push_back(Plan::Land);
    let out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    assert!(matches!(out.outcome,PublicationOutcome::Landed(c) if c.seq==1));
    for refusal in [
        crate::StatusRefusal::NoLog,
        crate::StatusRefusal::UnknownVolume,
        crate::StatusRefusal::UnknownTarget,
    ] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let tree = journal.tree();
        transport.remote.lock().unwrap().status = Some(StatusResponse::Refused(refusal));
        let out = begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await;
        assert!(
            matches!(out,Err(RecoveryError::Bootstrap(r)) if *r==StatusResponse::Refused(refusal))
        );
        assert!(transport.durable.lock().unwrap().is_none());
        assert!(transport.remote.lock().unwrap().sends.is_empty());
    }
}

#[tokio::test]
async fn epoch_transition_draws_full_fresh_operation_and_preserves_writer() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .extend([Plan::LostReply]);
    let first = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    let before = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        before.publication_id,
        (1..=16).collect::<Vec<u8>>().as_slice()
    );
    assert_eq!(
        before.frozen.writer_identity,
        (33..=48).collect::<Vec<u8>>().as_slice()
    );
    assert_eq!(
        before.current.unwrap().operation,
        (65..=80).collect::<Vec<u8>>().as_slice()
    );
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .extend([mismatch(2), Plan::LostReply]);
    resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &first.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    let after = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(after.current.unwrap().epoch, [2; 16]);
    assert_eq!(
        after.current.unwrap().operation,
        (97..=112).collect::<Vec<u8>>().as_slice()
    );
    assert_eq!(after.frozen, before.frozen);
    assert_eq!(after.candidates.first().unwrap().role, Role::Retired);
    assert_eq!(transport.remote.lock().unwrap().status_calls, 1);
}

#[tokio::test]
async fn epoch_retry_after_unsaved_answer_preserves_third_attempt_and_retired_tuple() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let old = record();
    granary_core::retained_submission::validate(&old).unwrap();
    *transport.durable.lock().unwrap() = Some(old.clone());
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(mismatch(2));
    // Fresh load, probe start/result, attempt, then the unsaved epoch answer.
    journal.fail_at = Some(5);
    let result = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &handle(&old),
        RecoveryIntent::Continue,
    )
    .await;
    assert!(matches!(result, Err(RecoveryError::Journal(_))));
    let interrupted = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        interrupted.phase,
        Phase::AwaitingAnswer {
            candidate: 1,
            attempt: 2
        }
    );
    assert_eq!(interrupted.candidates[0].evidence.last_answered_attempt, 0);
    let mut journal = Journal::new(transport.durable.clone());
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(mismatch(2));
    // Stop at the next probe save, after both epoch and new operation are durable.
    journal.fail_at = Some(8);
    let result = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(3),
            &mut delay,
        ),
        &handle(&old),
        RecoveryIntent::Continue,
    )
    .await;
    assert!(matches!(result, Err(RecoveryError::Journal(_))));
    let rebased = transport.durable.lock().unwrap().clone().unwrap();
    let mut expected = old.candidates[0].clone();
    expected.role = Role::Retired;
    expected.evidence.started = 3;
    expected.evidence.last_answered_attempt = 3;
    expected.evidence.proved_no_write = 1;
    assert_eq!(rebased.candidates, [expected]);
    assert_eq!(rebased.phase, Phase::Rebase);
    assert_eq!(rebased.current.unwrap().epoch, [2; 16]);
    assert_ne!(
        rebased.current.unwrap().operation,
        old.current.unwrap().operation
    );
    assert_eq!(rebased.publication_id, old.publication_id);
    assert_eq!(rebased.scope, old.scope);
    assert_eq!(rebased.frozen, old.frozen);
    let remote = transport.remote.lock().unwrap();
    assert_eq!(remote.sends.len(), 2);
    assert_eq!(
        remote.sends[0], remote.sends[1],
        "unsaved answer must retry the old exact tuple"
    );
    assert_eq!(remote.attempts, [2, 3]);
}

#[tokio::test]
async fn failed_entropy_never_supplies_partial_or_zero_identity() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    entropy.fail = true;
    let out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await;
    assert!(matches!(out, Err(RecoveryError::Entropy(_))));
    assert!(transport.durable.lock().unwrap().is_none());
    assert!(transport.remote.lock().unwrap().sends.is_empty());
}

#[tokio::test]
async fn empty_retired_slot_blocks_a_different_target() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let mut r = record();
    let mut retired = candidate(2, 2, root_bytes(2));
    retired.role = Role::Retired;
    // Root identity/seq remain valid; catalogue comparison must not erase it on empty.
    let mut doc = root::decode_root(&retired.root).unwrap();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(b"missing parent"));
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    retired.root = root::encode_root(&doc).unwrap();
    retired.seq = 2;
    retired.id = GrainId::of(&retired.root);
    r.candidates.push(retired);
    *transport.durable.lock().unwrap() = Some(r.clone());
    let out = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        &handle(&r),
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(
        transport
            .durable
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .candidates,
        r.candidates,
        "empty probe released candidate catalogue"
    );
    assert_eq!(out.outcome, PublicationOutcome::Unresolved);
    assert!(transport.remote.lock().unwrap().sends.is_empty());
}

#[tokio::test]
async fn over_cap_and_invalid_answers_retain_without_release() {
    for invalid_answer in [false, true] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let r = record();
        *transport.durable.lock().unwrap() = Some(r.clone());
        if invalid_answer {
            transport
                .remote
                .lock()
                .unwrap()
                .plans
                .push_back(Plan::Invalid);
        } else {
            transport.remote.lock().unwrap().oversized_probe = true;
        }
        let out = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::Continue,
        )
        .await
        .unwrap();
        assert_eq!(
            out.outcome,
            if invalid_answer {
                PublicationOutcome::BackendError
            } else {
                PublicationOutcome::Unresolved
            }
        );
        if !invalid_answer {
            assert!(matches!(
                transport.durable.lock().unwrap().as_ref().unwrap().phase,
                Phase::Unresolved(granary_core::retained_submission::Probe {
                    reason: granary_core::retained_submission::ProbeReason::Malformed,
                    ..
                })
            ));
            assert_eq!(transport.remote.lock().unwrap().probes, 1);
        }
        assert_eq!(
            transport
                .durable
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .candidates
                .len(),
            1
        );
        assert!(
            transport
                .durable
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .last_response
                .is_none()
        );
    }
}

#[tokio::test]
async fn frozen_closure_recovers_missing_and_corrupt_local_objects() {
    for corrupt in [false, true] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let tree = journal.tree();
        transport
            .remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::LostReply);
        let out = begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await
        .unwrap();
        let frozen = transport
            .durable
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .frozen
            .clone();
        let ids: Vec<_> = journal.objects.keys().copied().collect();
        if corrupt {
            for b in journal.objects.values_mut() {
                b.fill(0);
            }
        } else {
            journal.objects.clear();
        }
        transport
            .remote
            .lock()
            .unwrap()
            .plans
            .extend([mismatch(2), Plan::Land]);
        let done = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            &out.handle,
            RecoveryIntent::Continue,
        )
        .await
        .unwrap();
        let PublicationOutcome::Landed(done) = done.outcome else {
            panic!("content not reconstructed: {done:?}")
        };
        assert_eq!(
            root::decode_root(&done.root).unwrap().manifest_root,
            root::decode_root(&frozen.initial_root)
                .unwrap()
                .manifest_root
        );
        if corrupt {
            assert!(
                ids.iter()
                    .all(|id| journal.objects.get(id).unwrap().iter().all(|b| *b == 0))
            );
        } else {
            assert!(journal.objects.is_empty());
        }
    }
}

#[tokio::test]
async fn reconstruction_refuses_corrupt_metadata_and_short_or_corrupt_ranges() {
    for fault in 0..3 {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let tree = journal.tree();
        transport
            .remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::LostReply);
        let out = begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await
        .unwrap();
        journal.objects.clear();
        {
            let mut r = transport.remote.lock().unwrap();
            r.meta_corrupt = fault == 0;
            r.range_short = fault == 1;
            r.range_corrupt = fault == 2;
            r.plans.push_back(mismatch(2));
        }
        let done = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            &out.handle,
            RecoveryIntent::Continue,
        )
        .await
        .unwrap();
        assert_eq!(
            done.outcome,
            PublicationOutcome::Unresolved,
            "fault {fault}"
        );
        if fault == 1 {
            assert_eq!(done.diagnostic.as_deref(), Some("short frozen extent"));
        }
        assert_eq!(transport.remote.lock().unwrap().sends.len(), 2);
        assert_eq!(
            transport
                .durable
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .candidates
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn pending_scope_handle_and_capacity_refuse_before_network() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    let mut r = record();
    *transport.durable.lock().unwrap() = Some(r.clone());
    assert!(
        begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay
            ),
            r.scope.clone(),
            r.volume.clone(),
            tree,
            Policy::default()
        )
        .await
        .is_err()
    );
    let mut wrong = handle(&r);
    wrong.publication_id = [0; 16];
    assert!(
        resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay
            ),
            &wrong,
            RecoveryIntent::Continue
        )
        .await
        .is_err()
    );
    assert_eq!(transport.remote.lock().unwrap().status_calls, 0);
    assert_eq!(transport.remote.lock().unwrap().probes, 0);
    for number in 2..=128 {
        let mut c = candidate(number, 1, root_bytes(i64::try_from(number).unwrap()));
        c.role = Role::History;
        r.candidates.push(c);
    }
    r.phase = Phase::Rebase;
    *transport.durable.lock().unwrap() = Some(r.clone());
    let out = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &handle(&r),
        RecoveryIntent::ExplicitRecovery,
    )
    .await
    .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::Unresolved);
    assert_eq!(
        out.diagnostic.as_deref(),
        Some("candidate capacity exhausted")
    );
    assert_eq!(
        transport
            .durable
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .candidates
            .len(),
        128
    );
    assert_eq!(
        transport
            .durable
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .candidates,
        r.candidates,
        "capacity must preserve every catalogue entry"
    );
    assert!(transport.remote.lock().unwrap().sends.is_empty());
}

pub(crate) fn sign_doc(mut doc: RootDoc, key: &SigningKey) -> Vec<u8> {
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    root::encode_root(&doc).unwrap()
}

#[expect(
    clippy::too_many_lines,
    reason = "trust overlap and the two chain counterexamples share a real signed fixture"
)]
#[tokio::test]
async fn rebase_requires_publisher_trust_overlap_and_root_and_sheaf_ancestry() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport.remote.lock().unwrap().plans.push_back(Plan::Land);
    begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    let other = SigningKey::from_seed(&[8; 32]).unwrap();
    let only_other = granary_store::crypto::TrustedKeys::new([*other.public_key()]).unwrap();
    let denied = begin_publication(
        parts(
            &transport,
            &mut journal,
            &other,
            &only_other,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await;
    assert!(denied.is_err());
    let overlap =
        granary_store::crypto::TrustedKeys::new([*key.public_key(), *other.public_key()]).unwrap();
    transport.remote.lock().unwrap().plans.push_back(Plan::Land);
    let accepted = begin_publication(
        parts(
            &transport,
            &mut journal,
            &other,
            &overlap,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    assert!(matches!(accepted.outcome,PublicationOutcome::Landed(c) if c.seq==2));
    let original = transport
        .remote
        .lock()
        .unwrap()
        .roots
        .get(&2)
        .unwrap()
        .clone();
    // A validly signed head cannot give an unrelated parent trust by naming it.
    let mut head = root::decode_root(&original).unwrap();
    head.parent = Some(GrainId::of(b"unrelated parent"));
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .insert(2, sign_doc(head, &other));
    assert!(
        super::preparation::verify_base(&transport, &record().volume, &overlap)
            .await
            .is_err()
    );
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .insert(2, original.clone());
    let mut head = root::decode_root(&original).unwrap();
    let commit_bytes = transport
        .remote
        .lock()
        .unwrap()
        .meta
        .get(&head.sheaf_head)
        .unwrap()
        .clone();
    let mut commit = granary_core::sheaf::decode_sheaf(&commit_bytes).unwrap();
    commit.parent = Some(GrainId::of(b"unrelated sheaf"));
    let bytes = granary_core::sheaf::encode_sheaf(&commit).unwrap();
    let id = GrainId::of(&bytes);
    transport.remote.lock().unwrap().meta.insert(id, bytes);
    head.sheaf_head = id;
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .insert(2, sign_doc(head, &other));
    assert!(
        super::preparation::verify_base(&transport, &record().volume, &overlap)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn terminal_head_never_prepares_a_reserved_candidate() {
    let (transport, _, key, keys, _, _) = setup();
    let mut doc = root::decode_root(&root_bytes(1)).unwrap();
    doc.seq = u64::MAX - 2;
    doc.parent = Some(GrainId::of(b"parent"));
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .insert(doc.seq, sign_doc(doc, &key));
    assert!(
        super::preparation::verify_base(&transport, &record().volume, &keys)
            .await
            .is_err()
    );
    assert_eq!(transport.remote.lock().unwrap().probes, 0);
}

#[tokio::test]
async fn frozen_grains_require_exact_declared_length_even_when_local_hash_is_valid() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let id = journal.put(b"short".to_vec());
    let manifest = granary_core::manifest::encode_dir_leaf(&[granary_core::manifest::DirEntry {
        name: granary_core::manifest::Name::new(b"file".to_vec()).unwrap(),
        kind: granary_core::manifest::EntryKind::File {
            exec: false,
            size: 6,
            grains: granary_core::manifest::FileGrains::Inline(vec![
                granary_core::manifest::GrainRef {
                    id,
                    unpacked_len: 6,
                },
            ]),
        },
    }])
    .unwrap();
    let tree = journal.put(manifest);
    let out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await;
    assert!(out.is_err());
    assert!(transport.remote.lock().unwrap().sends.is_empty());
}

#[tokio::test]
async fn automatic_posts_are_bounded_and_each_is_durable() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let r = record();
    *transport.durable.lock().unwrap() = Some(r.clone());
    let out = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        &handle(&r),
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::Pending);
    assert_eq!(transport.remote.lock().unwrap().sends.len(), 8);
    assert_eq!(transport.remote.lock().unwrap().probes, 8);
    assert_eq!(delay.waits.len(), 7);
    assert!(
        delay
            .waits
            .iter()
            .all(|d| *d <= std::time::Duration::from_secs(5))
    );
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(durable.candidates.first().unwrap().evidence.started, 9);
    assert_eq!(
        durable.candidates.first().unwrap().evidence.proved_no_write,
        8
    );
}

#[tokio::test]
async fn overlay_reads_local_grains_without_retaining_them() {
    use granary_core::grainsource::GrainSource as _;
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    let grain = GrainId::of(b"frozen grain");
    let mut p = parts(
        &transport,
        &mut journal,
        &key,
        &keys,
        &mut entropy,
        &FixedClock(1),
        &mut delay,
    );
    let objects = preparation::closure(&mut p, &record().volume, tree, None)
        .await
        .unwrap();
    assert!(objects.retained.contains_key(&tree));
    assert!(
        !objects.retained.contains_key(&grain),
        "local grain retained in RAM"
    );
    let overlay = objects.overlay(&*p.journal);
    assert!(overlay.has(&grain));
    assert_eq!(overlay.get(&grain).unwrap(), b"frozen grain");
    assert_eq!(transport.remote.lock().unwrap().range_reads, 0);
}

#[tokio::test]
async fn recovered_grain_overlay_is_verified_and_prefers_retained_copy() {
    use granary_core::grainsource::GrainSource as _;
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    let frozen = transport
        .durable
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .frozen
        .clone();
    let grain = GrainId::of(b"frozen grain");
    journal.objects.remove(&grain);
    let objects = preparation::reconstruct(
        &mut parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &record().volume,
        &frozen,
    )
    .await
    .unwrap();
    assert_eq!(objects.retained.get(&grain).unwrap(), b"frozen grain");
    assert_eq!(
        objects.overlay(&journal).get(&grain).unwrap(),
        b"frozen grain"
    );
    journal.objects.insert(grain, vec![0; 12]);
    assert_eq!(
        objects.overlay(&journal).get(&grain).unwrap(),
        b"frozen grain"
    );
    journal.put(b"frozen grain".to_vec());
    // A backend failure cannot shadow the already verified recovered copy.
    journal.read_fault = Some((grain, ReadFault::Backend));
    let reads = journal.reads.lock().unwrap().get(&grain).copied().unwrap();
    assert_eq!(
        objects.overlay(&journal).get(&grain).unwrap(),
        b"frozen grain"
    );
    assert_eq!(journal.reads.lock().unwrap().get(&grain), Some(&reads));
    journal.read_fault = None;
    journal.objects.remove(&grain);
    transport.remote.lock().unwrap().range_wrong_hash = true;
    let error = preparation::reconstruct(
        &mut parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &record().volume,
        &frozen,
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "frozen object hash or cap mismatch");
}

#[tokio::test]
async fn stale_base_contested_history_stays_below_capacity() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    let rounds = granary_core::retained_submission::MAX_CANDIDATES / 8 + 1;
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .extend((0..rounds * 8).map(|_| Plan::StaleContest));
    let mut out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    for round in 1..rounds {
        out = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(i64::try_from(round + 1).unwrap()),
                &mut delay,
            ),
            &out.handle,
            RecoveryIntent::ExplicitRecovery,
        )
        .await
        .unwrap();
        let durable = transport.durable.lock().unwrap();
        assert!(
            durable.as_ref().unwrap().candidates.len()
                < granary_core::retained_submission::MAX_CANDIDATES,
            "round {round}: catalogue reached capacity: {}",
            durable.as_ref().unwrap().candidates.len()
        );
        assert_eq!(
            out.outcome,
            PublicationOutcome::Pending,
            "round {round}: {out:?}"
        );
    }
    assert_eq!(transport.remote.lock().unwrap().sends.len(), rounds * 8);
    assert!(
        transport
            .durable
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .candidates
            .len()
            <= 2
    );
}

#[test]
fn history_pruning_requires_all_answers_and_no_decision() {
    for (unanswered, decision_seen) in [(false, false), (true, false), (false, true)] {
        let mut r = record();
        let mut history = candidate(2, 1, root_bytes(2));
        history.role = Role::History;
        history.evidence.answer(1, true, false).unwrap();
        if unanswered {
            history.evidence.start().unwrap();
        }
        history.evidence.decision_seen = decision_seen;
        r.candidates.push(history);
        granary_core::retained_submission::validate(&r).unwrap();
        // The phase is Ready, as it is in every production comparison caller.
        compare(&mut r, None, [(1, GrainId::of(b"foreign wedge"))]);
        assert_eq!(
            r.candidates.len(),
            1 + usize::from(unanswered || decision_seen),
            "unanswered={unanswered}, decision_seen={decision_seen}"
        );
        granary_core::retained_submission::validate(&r).unwrap();
    }
}

#[test]
fn wedged_history_accepts_later_bound_open_and_landed() {
    use granary_core::authority_answer::Receipt;
    for landed in [false, true] {
        let mut r = record();
        let history = r.candidates.first_mut().unwrap();
        history.role = Role::History;
        history.evidence.answer(1, false, true).unwrap();
        let history = history.clone();
        r.candidates.push(candidate(2, 1, root_bytes(2)));
        let owned = r
            .candidates
            .iter()
            .map(|c| crate::OwnedCandidate::new(r.volume.as_str(), c.root.clone().into()).unwrap())
            .collect::<Vec<_>>();
        let req = crate::PublishRequest::new(
            r.volume.as_str(),
            Epoch::from_bytes([1; 16]),
            &[1; 16],
            owned.get(1).unwrap().clone(),
            owned,
        )
        .unwrap();
        let position = Position {
            epoch: req.epoch(),
            entry_seq: 91,
        };
        let bound = if landed {
            Bound::Landed(Receipt {
                position,
                root_seq: history.seq,
                stored_id: history.id,
            })
        } else {
            Bound::Open {
                position,
                candidate_id: history.id,
            }
        };
        let answer = crate::validate_publish_answer(
            &req,
            409,
            Some("operation-bound"),
            &granary_core::authority_answer::encode(PublishAnswer::OperationBound(bound)).unwrap(),
        )
        .unwrap();
        // Undecodable foreign bytes wedge the authority entry; they do not close it.
        compare(
            &mut r,
            None,
            [(history.seq, GrainId::of(b"undecodable occupant"))],
        );
        assert!(r.candidates.iter().any(|c| c.id == history.id));
        coordinator::apply_answer(&mut r, 2, 1, answer).unwrap();
        if landed {
            assert!(
                matches!(&r.phase, Phase::Complete(done) if done.id == history.id && done.root == history.root)
            );
        } else {
            assert!(
                r.candidates
                    .iter()
                    .any(|c| c.id == history.id && c.role == Role::Active)
            );
        }
        granary_core::retained_submission::validate(&r).unwrap();
    }
}

#[tokio::test]
async fn overlay_wrong_ok_grain_is_never_uploaded() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    let objects = preparation::closure(
        &mut parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        &record().volume,
        tree,
        None,
    )
    .await
    .unwrap();
    let grain = GrainId::of(b"frozen grain");
    journal.read_fault = Some((grain, ReadFault::WrongOk));
    let prepared = crate::publish::prepare_from_state(
        &transport,
        &objects.overlay(&journal),
        tree,
        crate::HarvestStats::default(),
        &record().volume,
        &key,
        &granary_core::identity::WriterIdentity::from_bytes([3; 16]),
        Timestamp { secs: 1, nanos: 0 },
        Policy::default(),
        crate::publish::RemoteState::empty(),
    )
    .await;
    assert!(prepared.is_err(), "mismatched Ok bytes reached preparation");
    let remote = transport.remote.lock().unwrap();
    assert_eq!(
        remote.bin_uploads, 0,
        "wrong grain uploaded under its declared id"
    );
    assert_eq!(remote.meta_uploads, 0);
}

#[tokio::test]
async fn closure_reads_shared_grain_once_and_checks_each_declared_length() {
    use granary_core::manifest;
    for bad_length in [None, Some(11), Some(13)] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let grain = journal.put(b"frozen grain".to_vec());
        let refs = (0..16)
            .map(|n| manifest::GrainRef {
                id: grain,
                unpacked_len: if n == 0 { bad_length.unwrap_or(12) } else { 12 },
            })
            .collect::<Vec<_>>();
        let size = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
        let tree = journal.put(
            manifest::encode_dir_leaf(&[manifest::DirEntry {
                name: manifest::Name::new(b"repeated".to_vec()).unwrap(),
                kind: manifest::EntryKind::File {
                    exec: false,
                    size,
                    grains: manifest::FileGrains::Inline(refs),
                },
            }])
            .unwrap(),
        );
        let result = preparation::closure(
            &mut parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            &record().volume,
            tree,
            None,
        )
        .await;
        if bad_length.is_some() {
            assert_eq!(
                result.unwrap_err().to_string(),
                "frozen grain length mismatch"
            );
        } else {
            assert!(result.is_ok());
        }
        assert_eq!(journal.reads.lock().unwrap().get(&grain), Some(&1));
    }
}

#[tokio::test]
async fn retained_completion_status_refuses_before_uploads() {
    for status in [
        StatusResponse::Refused(crate::StatusRefusal::NoLog),
        StatusResponse::Refused(crate::StatusRefusal::UnknownVolume),
        StatusResponse::Refused(crate::StatusRefusal::UnknownTarget),
        StatusResponse::ServiceUnavailable(crate::StatusServiceReason::Unavailable),
        StatusResponse::Internal,
    ] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let tree = journal.tree();
        transport.remote.lock().unwrap().plans.push_back(Plan::Land);
        begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await
        .unwrap();
        let before = {
            let mut remote = transport.remote.lock().unwrap();
            remote.status = Some(status);
            (
                remote.bin_uploads,
                remote.meta_uploads,
                remote.probes,
                remote.sends.len(),
            )
        };
        let result = begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await;
        assert!(matches!(result, Err(RecoveryError::Bootstrap(observed)) if *observed == status));
        let remote = transport.remote.lock().unwrap();
        assert_eq!(
            (
                remote.bin_uploads,
                remote.meta_uploads,
                remote.probes,
                remote.sends.len()
            ),
            before
        );
        assert_eq!(remote.status_calls, 2);
    }
}

#[tokio::test]
async fn inconsistent_bound_answer_is_durably_uncertain_and_ready() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let r = record();
    let owned =
        crate::OwnedCandidate::new(r.volume.as_str(), r.candidates[0].root.clone().into()).unwrap();
    let foreign = crate::OwnedCandidate::new(r.volume.as_str(), root_bytes(99).into()).unwrap();
    let bound_id = foreign.id();
    let request = crate::PublishRequest::new(
        r.volume.as_str(),
        Epoch::from_bytes([1; 16]),
        &[1; 16],
        owned.clone(),
        vec![owned, foreign],
    )
    .unwrap();
    let answer = crate::validate_publish_answer(
        &request,
        409,
        Some("operation-bound"),
        &granary_core::authority_answer::encode(PublishAnswer::OperationBound(Bound::Open {
            position: Position {
                epoch: request.epoch(),
                entry_seq: 91,
            },
            candidate_id: bound_id,
        }))
        .unwrap(),
    )
    .unwrap();
    *transport.durable.lock().unwrap() = Some(r.clone());
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::Reply(answer));
    let out = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        &handle(&r),
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::BackendError);
    assert!(out.uncertain);
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(durable.phase, Phase::Ready);
    assert_eq!(journal.cuts, 5, "answer must use one durable replace");
    assert_eq!(durable.candidates.len(), r.candidates.len());
    assert_eq!(durable.candidates[0].evidence.last_answered_attempt, 2);
    assert_eq!(durable.candidates[0].evidence.proved_no_write, 0);
    assert!(durable.candidates[0].evidence.decision_seen);
    assert!(durable.last_response.is_none());
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let resumed = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &out.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(resumed.outcome, PublicationOutcome::Pending);
}

#[tokio::test]
async fn eighth_answer_does_no_more_barrier_reconstruction_or_uploads() {
    for eighth in [
        Plan::Wire(PublishAnswer::StaleBase(
            granary_core::authority_answer::Head::new(None),
        )),
        mismatch(2),
    ] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let r = record();
        *transport.durable.lock().unwrap() = Some(r.clone());
        transport
            .remote
            .lock()
            .unwrap()
            .plans
            .extend((0..7).map(|_| Plan::Reply(PublishResponse::RateLimited)));
        transport.remote.lock().unwrap().plans.push_back(eighth);
        let out = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::Continue,
        )
        .await
        .unwrap();
        assert_eq!(out.outcome, PublicationOutcome::Pending);
        let remote = transport.remote.lock().unwrap();
        assert_eq!(remote.sends.len(), 8);
        assert_eq!(remote.probes, 8);
        assert_eq!(remote.max_seq_calls, 8);
        assert_eq!(remote.meta_reads, 0);
        assert_eq!(remote.range_reads, 0);
        assert_eq!(remote.bin_uploads, 0);
        assert_eq!(remote.meta_uploads, 0);
    }
}

#[tokio::test]
async fn completion_epoch_wins_and_receiptless_completion_bootstraps() {
    for receiptless in [false, true] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let tree = journal.tree();
        transport.remote.lock().unwrap().plans.push_back(Plan::Land);
        begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await
        .unwrap();
        if receiptless {
            let mut durable = transport.durable.lock().unwrap();
            let Phase::Complete(done) = &mut durable.as_mut().unwrap().phase else {
                panic!("not complete")
            };
            done.receipt = None;
        }
        let status = crate::validate_status_observation(
            &granary_core::authority_answer::encode_status(
                granary_core::authority_answer::VolumeStatus {
                    epoch: Epoch::from_bytes([9; 16]),
                    head: None,
                    open: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        transport.remote.lock().unwrap().status = Some(status);
        transport
            .remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::LostReply);
        begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await
        .unwrap();
        let remote = transport.remote.lock().unwrap();
        assert_eq!(remote.status_calls, 2);
        assert_eq!(remote.sends[1].1, [if receiptless { 9 } else { 1 }; 16]);
    }
}

#[tokio::test]
async fn reused_retired_epoch_stops_before_building_an_invalid_generation() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let begun = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .extend([mismatch(2), Plan::LostReply]);
    resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &begun.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    let before = transport.durable.lock().unwrap().clone().unwrap();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(mismatch(1));
    let out = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(3),
            &mut delay,
        ),
        &begun.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::BackendError);
    assert!(
        out.diagnostic
            .unwrap()
            .contains("reused a retired epoch: Epoch([1,")
    );
    let after = transport.durable.lock().unwrap().clone().unwrap();
    granary_core::retained_submission::validate(&after).unwrap();
    assert_eq!(after.current, before.current);
    assert_eq!(after.phase, Phase::Ready);
    assert_eq!(after.candidates.len(), before.candidates.len());
    assert_eq!(after.candidates[0], before.candidates[0]);
}

#[tokio::test]
async fn send_barrier_is_fresh_after_replacement_uploads() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    let a = transport
        .durable
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .candidates
        .first()
        .unwrap()
        .clone();
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.land_on_upload = Some((a.seq, a.root.clone()));
        remote.plans.push_back(mismatch(2));
    }
    let done = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &out.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert!(matches!(done.outcome,PublicationOutcome::Landed(c) if c.id==a.id));
    assert_eq!(
        transport.remote.lock().unwrap().sends.len(),
        2,
        "A lands during re-preparation, so B must not send"
    );
}

#[tokio::test]
async fn verified_rebase_also_blocks_a_different_retired_target() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    let mut submission = transport.durable.lock().unwrap().clone().unwrap();
    let mut doc = root::decode_root(&submission.frozen.initial_root).unwrap();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(b"parent"));
    let mut retired = candidate(2, 2, sign_doc(doc, &key));
    retired.role = Role::Retired;
    retired.seq = 2;
    submission.candidates.push(retired);
    submission.phase = Phase::Rebase;
    *transport.durable.lock().unwrap() = Some(submission.clone());
    let done = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &out.handle,
        RecoveryIntent::ExplicitRecovery,
    )
    .await
    .unwrap();
    assert_eq!(done.outcome, PublicationOutcome::Unresolved);
    assert!(done.diagnostic.unwrap().contains("not at target"));
    assert_eq!(
        transport
            .durable
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .candidates
            .len(),
        2
    );
    assert_eq!(transport.remote.lock().unwrap().sends.len(), 1);
}

#[test]
fn bound_helper_refuses_unknown_retired_and_unsubmitted_bindings_without_changes() {
    let mut submission = record();
    let original = submission.clone();
    assert!(submission.activate_bound(GrainId::of(b"unknown")).is_err());
    assert_eq!(submission, original);
    submission.candidates.first_mut().unwrap().evidence = Evidence::default();
    let original = submission.clone();
    assert!(
        submission
            .activate_bound(submission.candidates.first().unwrap().id)
            .is_err()
    );
    assert_eq!(submission, original);
    let mut submission = record();
    retire(&mut submission, [2; 16]);
    let original = submission.clone();
    assert!(
        submission
            .activate_bound(submission.candidates.first().unwrap().id)
            .is_err()
    );
    assert_eq!(submission, original);
}

#[tokio::test]
async fn remote_reconstruction_hash_check_refuses_validly_compressed_foreign_bytes() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    // Keep the manifest local so the foreign frame is a grain, whose bytes
    // would otherwise decode and pass its declared length.
    journal.objects.retain(|id, _| *id == tree);
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.range_wrong_hash = true;
        remote.plans.push_back(mismatch(2));
    }
    let done = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &out.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(done.outcome, PublicationOutcome::Unresolved);
    let diagnostic = done.diagnostic.unwrap();
    assert!(diagnostic.contains("hash or cap"), "{diagnostic}");
}

#[tokio::test]
async fn remote_frame_declaration_is_checked_before_decompression() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    let out = begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    journal.objects.retain(|id, _| *id == tree);
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.range_overdeclared = true;
        remote.plans.push_back(mismatch(2));
    }
    let done = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &out.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(done.outcome, PublicationOutcome::Unresolved);
    let diagnostic = done.diagnostic.unwrap();
    assert!(diagnostic.contains("exceeds declaration"), "{diagnostic}");
}

#[test]
fn all_conflict_and_enrollment_histories_can_release_but_accepted_candidates_cannot() {
    for decision in [false, true] {
        for reply in 0..3 {
            let mut submission = record();
            let c = submission.candidates.first().unwrap().clone();
            if decision {
                let request = crate::PublishRequest::new(
                    submission.volume.as_str(),
                    Epoch::from_bytes(c.request.epoch),
                    &c.request.operation,
                    crate::OwnedCandidate::new(submission.volume.as_str(), c.root.clone().into())
                        .unwrap(),
                    vec![
                        crate::OwnedCandidate::new(
                            submission.volume.as_str(),
                            c.root.clone().into(),
                        )
                        .unwrap(),
                    ],
                )
                .unwrap();
                let answer = crate::validate_publish_answer(
                    &request,
                    202,
                    None,
                    &granary_core::authority_answer::encode(PublishAnswer::Accepted {
                        position: Position {
                            epoch: request.epoch(),
                            entry_seq: 67,
                        },
                        candidate_id: c.id,
                    })
                    .unwrap(),
                )
                .unwrap();
                super::coordinator::apply_answer(&mut submission, 1, 1, answer).unwrap();
                submission
                    .candidates
                    .first_mut()
                    .unwrap()
                    .evidence
                    .start()
                    .unwrap();
            }
            let attempt = submission.candidates.first().unwrap().evidence.started;
            let answer = match reply {
                0 => PublishResponse::Conflict(crate::CheckedConflict::VolumeDamaged),
                1 => PublishResponse::Conflict(crate::CheckedConflict::StaleBase(
                    granary_core::authority_answer::Head::new(None),
                )),
                _ => PublishResponse::ServiceUnavailable(ServiceReason::EnrollmentUnavailable),
            };
            super::coordinator::apply_answer(&mut submission, 1, attempt, answer).unwrap();
            if reply == 1 {
                assert_eq!(submission.phase, Phase::Rebase);
                assert_eq!(submission.candidates[0].role, Role::Active);
                assert_eq!(submission.candidates[0].evidence.decision_seen, decision);
            }
            retire(&mut submission, [2; 16]);
            assert_eq!(
                submission.candidates.len(),
                usize::from(decision),
                "decision {decision}, reply {reply}"
            );
        }
    }
}

#[test]
fn recovery_contract_states_release_proof_and_operator_limits() {
    let docs = include_str!("../recovery.rs")
        .lines()
        .filter_map(|line| line.strip_prefix("//!"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ");
    for requirement in [
        "Every accepted exact tuple replays before stale-base can answer",
        "Same-epoch log restoration from a backup, a second authority process, and out-of-band deletion break these premises",
        "An open entry behind witnessed foreign occupancy ends the invocation pending possible out-of-band repair",
    ] {
        assert!(
            docs.contains(requirement),
            "missing recovery contract: {requirement}"
        );
    }
}

#[tokio::test]
async fn verified_base_checks_sheaf_hash_metadata_and_first_parent() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    for stamp in 1..=2 {
        transport.remote.lock().unwrap().plans.push_back(Plan::Land);
        begin_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(stamp),
                &mut delay,
            ),
            record().scope,
            record().volume,
            tree,
            Policy::default(),
        )
        .await
        .unwrap();
    }
    assert!(
        super::preparation::verify_base(&transport, &record().volume, &keys)
            .await
            .is_ok()
    );
    let (roots, meta) = {
        let r = transport.remote.lock().unwrap();
        (r.roots.clone(), r.meta.clone())
    };
    for fault in 0..6 {
        {
            let mut r = transport.remote.lock().unwrap();
            r.roots.clone_from(&roots);
            r.meta.clone_from(&meta);
            let seq = if matches!(fault, 0 | 1 | 5) { 2 } else { 1 };
            let mut doc = root::decode_root(r.roots.get(&seq).unwrap()).unwrap();
            if fault == 5 {
                r.meta.insert(doc.sheaf_head, vec![0]);
            } else {
                let mut commit =
                    granary_core::sheaf::decode_sheaf(r.meta.get(&doc.sheaf_head).unwrap())
                        .unwrap();
                match fault {
                    0 | 2 => commit.manifest_root = GrainId::of(b"foreign tree"),
                    1 | 3 => commit.timestamp.secs += 1,
                    _ => commit.parent = Some(GrainId::of(b"nonexistent first parent")),
                }
                let bytes = granary_core::sheaf::encode_sheaf(&commit).unwrap();
                let id = GrainId::of(&bytes);
                r.meta.insert(id, bytes);
                doc.sheaf_head = id;
                let bytes = sign_doc(doc, &key);
                let parent = GrainId::of(&bytes);
                r.roots.insert(seq, bytes);
                if seq == 1 {
                    // Keep the head's exact-byte and sheaf links valid so only
                    // the ancestor metadata or first-parent check can refuse.
                    let mut head = root::decode_root(r.roots.get(&2).unwrap()).unwrap();
                    head.parent = Some(parent);
                    let mut commit =
                        granary_core::sheaf::decode_sheaf(r.meta.get(&head.sheaf_head).unwrap())
                            .unwrap();
                    commit.parent = Some(id);
                    let bytes = granary_core::sheaf::encode_sheaf(&commit).unwrap();
                    head.sheaf_head = GrainId::of(&bytes);
                    r.meta.insert(head.sheaf_head, bytes);
                    r.roots.insert(2, sign_doc(head, &key));
                }
            }
        }
        let error = super::preparation::verify_base(&transport, &record().volume, &keys)
            .await
            .unwrap_err();
        assert!(
            matches!(error, RecoveryError::RemoteIntegrity(_)),
            "fault {fault}: remote history failures are not local state: {error:?}"
        );
        assert_eq!(
            error.to_string(),
            match fault {
                0 | 1 => "head sheaf mismatch",
                2 | 3 => "ancestor sheaf mismatch",
                4 => "first sheaf has parent",
                _ => "sheaf hash mismatch",
            },
            "fault {fault}"
        );
    }
}

#[tokio::test]
async fn frozen_root_requires_publisher_trust_even_with_all_content_local() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::LostReply);
    begin_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(1),
            &mut delay,
        ),
        record().scope,
        record().volume,
        tree,
        Policy::default(),
    )
    .await
    .unwrap();
    let frozen = transport
        .durable
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .frozen
        .clone();
    let other = SigningKey::from_seed(&[8; 32]).unwrap();
    let other_keys = granary_store::crypto::TrustedKeys::new([*other.public_key()]).unwrap();
    let error = super::preparation::reconstruct(
        &mut parts(
            &transport,
            &mut journal,
            &key,
            &other_keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &record().volume,
        &frozen,
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "untrusted frozen root");
}

#[test]
fn pure_answer_validation_ignores_error_text_but_caps_binary_answers() {
    let r = record();
    let c = r.candidates.first().unwrap();
    let owned = crate::OwnedCandidate::new(r.volume.as_str(), c.root.clone().into()).unwrap();
    let request = crate::PublishRequest::new(
        r.volume.as_str(),
        Epoch::from_bytes(c.request.epoch),
        &c.request.operation,
        owned.clone(),
        vec![owned],
    )
    .unwrap();
    let bytes = vec![0; granary_core::authority_answer::MAX_BYTES + 1];
    assert_eq!(
        crate::validate_publish_answer(&request, 503, Some("enrollment-unavailable"), &bytes)
            .unwrap(),
        PublishResponse::ServiceUnavailable(ServiceReason::EnrollmentUnavailable)
    );
    assert!(
        crate::validate_publish_answer(&request, 200, None, &bytes)
            .unwrap_err()
            .to_string()
            .contains("answer exceeds cap")
    );
}

#[test]
fn binding_prefers_submitted_history_among_duplicate_owned_ids() {
    let mut r = record();
    let mut unsent = r.candidates.first().unwrap().clone();
    unsent.role = Role::History;
    unsent.evidence = Evidence::default();
    let mut submitted = unsent.clone();
    submitted.number = 2;
    submitted.evidence.started = 3;
    let active = candidate(3, 1, root_bytes(2));
    let id = submitted.id;
    r.candidates = vec![unsent.clone(), submitted, active];
    granary_core::retained_submission::validate(&r).unwrap();
    r.activate_bound(id).unwrap();
    assert_eq!(r.candidates.first().unwrap(), &unsent);
    let bound = r.candidates.get(1).unwrap();
    assert_eq!(bound.role, Role::Active);
    assert!(bound.evidence.decision_seen);
    assert_eq!(bound.evidence.started, 3);
    assert_eq!(r.candidates.get(2).unwrap().role, Role::History);
    assert_eq!(
        r.candidates.get_mut(1).unwrap().evidence.start().unwrap(),
        4
    );
}

#[tokio::test]
async fn generic_recovery_keeps_the_frozen_manifest_before_send() {
    let mut cases = 0;
    for changed in [false, true] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let mut retained = record();
        let initial = retained.frozen.initial_root.clone();
        let mut doc = root::decode_root(&initial).unwrap();
        doc.seq = 2;
        doc.parent = Some(GrainId::of(&initial));
        if changed {
            doc.manifest_root = GrainId::of(b"different retained target");
        }
        doc.sigs.clear();
        doc.sigs.push(RootSig {
            key_id: key.key_id(),
            sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
        });
        let bytes = root::encode_root(&doc).unwrap();
        granary_store::crypto::check_head(&bytes, retained.volume.as_str(), 2, &keys).unwrap();
        let candidate = retained.candidates.first_mut().unwrap();
        candidate.number = 2;
        candidate.seq = 2;
        candidate.id = GrainId::of(&bytes);
        candidate.root = bytes;
        candidate.evidence = Evidence::default();
        granary_core::retained_submission::validate(&retained).unwrap();
        *journal.durable.lock().unwrap() = Some(retained.clone());
        transport.remote.lock().unwrap().roots.insert(1, initial);
        transport.remote.lock().unwrap().plans.push_back(Plan::Land);
        let result = resume_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(1),
                &mut delay,
            ),
            &handle(&retained),
            RecoveryIntent::Continue,
        )
        .await;
        let sends = transport.remote.lock().unwrap().sends.len();
        if changed {
            assert_eq!(
                (result.as_ref().err().map(ToString::to_string), sends),
                (
                    Some(
                        "retained publication: invalid retained submission: frozen manifest".into()
                    ),
                    0
                ),
                "a structurally valid changed manifest needs the store-commit guard: {result:?}"
            );
        } else {
            assert_eq!(
                (
                    matches!(
                        &result,
                        Ok(PublicationResult {
                            outcome: PublicationOutcome::Landed(_),
                            ..
                        })
                    ),
                    sends
                ),
                (true, 1),
                "an unchanged frozen manifest remains publishable: {result:?}"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}
