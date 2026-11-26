// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{OwnedCandidate, PublishRequest, validate_publish_answer};
use granary_core::authority_answer::{self, Head, Receipt};
use granary_core::retained_submission::{self, MAX_CANDIDATES, Probe, ProbeReason};

fn request_for(r: &Submission, number: u64) -> PublishRequest {
    let c = r.candidates.iter().find(|c| c.number == number).unwrap();
    let owned = OwnedCandidate::new(r.volume.as_str(), c.root.clone().into()).unwrap();
    let mut history = Vec::new();
    for entry in r
        .candidates
        .iter()
        .filter(|entry| entry.request == c.request)
    {
        let candidate = OwnedCandidate::new(r.volume.as_str(), entry.root.clone().into()).unwrap();
        if !history
            .iter()
            .any(|c: &OwnedCandidate| c.id() == candidate.id())
        {
            history.push(candidate);
        }
    }
    PublishRequest::new(
        r.volume.as_str(),
        Epoch::from_bytes(c.request.epoch),
        &c.request.operation,
        owned,
        history,
    )
    .unwrap()
}

fn lost_answer(r: &Submission, number: u64, occupant: GrainId) -> PublishResponse {
    let req = request_for(r, number);
    validate_publish_answer(
        &req,
        200,
        None,
        &authority_answer::encode(PublishAnswer::Lost {
            position: Position {
                epoch: req.epoch(),
                entry_seq: 91,
            },
            candidate_id: req.candidate().id(),
            occupant,
            head: None,
        })
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn lost_releases_every_matching_current_entry_with_unanswered_attempts() {
    let mut r = record();
    r.candidates.first_mut().unwrap().evidence.started = 3;
    let mut twin = r.candidates.first().unwrap().clone();
    twin.number = 2;
    twin.role = Role::History;
    r.candidates.push(twin);
    let mut other = candidate(3, 1, root_bytes(3));
    other.role = Role::History;
    r.candidates.push(other.clone());
    retained_submission::validate(&r).unwrap();
    let current = r.current;
    let answer = lost_answer(&r, 1, GrainId::of(b"foreign occupant"));
    coordinator::apply_answer(&mut r, 1, 3, answer).unwrap();
    assert_eq!(r.candidates, vec![other]);
    assert_eq!(r.current, current);
    assert_eq!(r.phase, Phase::Rebase);
    assert!(r.last_response.is_none());
    retained_submission::validate(&r).unwrap();
}

#[test]
fn lost_release_requires_the_current_request_identity() {
    for current in [
        Some(RequestIdentity {
            epoch: [2; 16],
            operation: [2; 16],
        }),
        Some(RequestIdentity {
            epoch: [1; 16],
            operation: [2; 16],
        }),
        None,
    ] {
        let mut r = record();
        let answer = lost_answer(&r, 1, GrainId::of(b"foreign occupant"));
        let c = r.candidates.first_mut().unwrap();
        c.role = Role::History;
        let id = c.id;
        // Exercise the private transition's identity guard independently of the
        // codec, which refuses non-retired entries under a different current identity.
        r.current = current;
        coordinator::apply_answer(&mut r, 1, 1, answer).unwrap();
        assert!(
            r.candidates.iter().any(|c| c.id == id),
            "current={current:?}"
        );
        assert!(r.last_response.is_some());
    }
}

#[test]
fn lost_release_excludes_retired_entries_independently_of_identity() {
    let mut r = record();
    let answer = lost_answer(&r, 1, GrainId::of(b"foreign occupant"));
    let mut twin = r.candidates.first().unwrap().clone();
    twin.number = 2;
    twin.role = Role::Retired;
    // Isolate the role guard from compare's slot retirement and the codec's
    // retired-epoch rule. This synthetic value is never persisted.
    twin.seq = 2;
    r.candidates.push(twin.clone());
    coordinator::apply_answer(&mut r, 1, 1, answer).unwrap();
    assert_eq!(r.candidates, vec![twin]);
    assert!(r.last_response.is_none());
}

#[test]
fn lost_compares_owned_occupants_before_release_and_keeps_retired_twins() {
    let mut r = record();
    let lost = r.candidates.first().unwrap().clone();
    let mut retired = lost.clone();
    retired.number = 2;
    retired.role = Role::Retired;
    retired.request = RequestIdentity {
        epoch: [2; 16],
        operation: [2; 16],
    };
    r.candidates.push(retired.clone());
    let mut winner = candidate(3, 1, root_bytes(3));
    winner.role = Role::History;
    r.candidates.push(winner.clone());
    retained_submission::validate(&r).unwrap();
    let answer = lost_answer(&r, 1, winner.id);
    coordinator::apply_answer(&mut r, 1, 1, answer).unwrap();
    assert!(matches!(&r.phase, Phase::Complete(done)
        if done.id == winner.id && done.root == winner.root && done.receipt.is_none()));
    assert!(r.candidates.iter().any(|c| c.number == lost.number));
    assert!(r.candidates.contains(&retired));
    assert!(r.last_response.is_some());
    assert_eq!(r.current, None);
    retained_submission::validate(&r).unwrap();
}

#[test]
fn accepted_and_open_history_survives_foreign_occupancy() {
    for open in [false, true] {
        let mut r = record();
        let req = request_for(&r, 1);
        let position = Position {
            epoch: req.epoch(),
            entry_seq: 91,
        };
        let candidate_id = req.candidate().id();
        let wire = if open {
            PublishAnswer::Open {
                position,
                candidate_id,
            }
        } else {
            PublishAnswer::Accepted {
                position,
                candidate_id,
            }
        };
        let answer =
            validate_publish_answer(&req, 202, None, &authority_answer::encode(wire).unwrap())
                .unwrap();
        coordinator::apply_answer(&mut r, 1, 1, answer).unwrap();
        let c = r.candidates.first_mut().unwrap();
        c.role = Role::History;
        let history = c.clone();
        r.candidates.push(candidate(2, 1, root_bytes(2)));
        compare(&mut r, None, [(1, GrainId::of(b"foreign wedge"))]);
        assert!(r.candidates.contains(&history), "open={open}");
        retained_submission::validate(&r).unwrap();
    }
}

#[test]
fn never_decided_history_releases_at_a_different_slot() {
    let mut r = record();
    let mut doc = root::decode_root(&root_bytes(2)).unwrap();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(b"parent"));
    let mut history = candidate(
        2,
        1,
        sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap()),
    );
    history.seq = 2;
    history.role = Role::History;
    history.evidence.answer(1, true, false).unwrap();
    r.candidates.push(history);
    retained_submission::validate(&r).unwrap();
    compare(&mut r, None, [(1, GrainId::of(b"foreign occupant"))]);
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates.first().unwrap().number, 1);
    retained_submission::validate(&r).unwrap();
}

#[test]
fn bound_open_and_landed_activate_retained_history_after_a_lost_release() {
    for landed in [false, true] {
        let mut r = record();
        let history = r.candidates.first_mut().unwrap();
        history.role = Role::History;
        history.evidence.answer(1, false, true).unwrap();
        let history = history.clone();
        r.candidates.push(candidate(2, 1, root_bytes(2)));
        let answer = lost_answer(&r, 2, GrainId::of(b"foreign occupant"));
        coordinator::apply_answer(&mut r, 2, 1, answer).unwrap();
        assert_eq!(r.candidates, vec![history.clone()]);
        assert!(r.last_response.is_none());
        retained_submission::validate(&r).unwrap();
        r.candidates.push(candidate(3, 1, root_bytes(3)));
        r.phase = Phase::Ready;
        let req = request_for(&r, 3);
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
        let answer = validate_publish_answer(
            &req,
            409,
            Some("operation-bound"),
            &authority_answer::encode(PublishAnswer::OperationBound(bound)).unwrap(),
        )
        .unwrap();
        coordinator::apply_answer(&mut r, 3, 1, answer).unwrap();
        assert!(
            r.candidates
                .iter()
                .any(|c| c.id == history.id && c.role == Role::Active)
        );
        if landed {
            assert!(
                matches!(&r.phase, Phase::Complete(done) if done.id == history.id && done.receipt.is_some())
            );
        } else {
            assert_eq!(r.phase, Phase::Ready);
        }
        retained_submission::validate(&r).unwrap();
    }
}

#[tokio::test]
async fn lost_contention_stays_below_capacity() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    let rounds = MAX_CANDIDATES / 8 + 1;
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .extend((0..rounds * 8).map(|_| Plan::LostContest));
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
    let current = transport.durable.lock().unwrap().as_ref().unwrap().current;
    for round in 0..rounds {
        if round != 0 {
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
        }
        assert_eq!(
            out.outcome,
            PublicationOutcome::Pending,
            "round {round}: {out:?}"
        );
        assert!(matches!(out.response, Some(PublishResponse::Lost(_))));
        let durable = transport.durable.lock().unwrap().clone().unwrap();
        assert!(
            durable.candidates.len() < MAX_CANDIDATES,
            "round {round}: catalogue reached capacity"
        );
        assert_eq!(durable.current, current);
        assert_eq!(durable.phase, Phase::Rebase);
        // The unchanged persistent codec accepts Rebase without an active entry.
        let encoded = retained_submission::encode(&durable).unwrap();
        assert_eq!(retained_submission::decode(&encoded).unwrap(), durable);
    }
    let remote = transport.remote.lock().unwrap();
    assert_eq!(remote.sends.len(), rounds * 8);
    assert!(remote.sends.iter().all(|send| Some(RequestIdentity {
        epoch: send.1,
        operation: send.2.as_slice().try_into().unwrap(),
    }) == current));
    assert!(
        transport
            .durable
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .candidates
            .is_empty()
    );
}

#[tokio::test]
async fn lost_release_clears_uncertainty_and_the_pruned_response() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let tree = journal.tree();
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .extend((0..8).map(|_| Plan::LostContest));
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
    assert_eq!(out.outcome, PublicationOutcome::Pending);
    assert!(!out.uncertain);
    assert!(matches!(out.response, Some(PublishResponse::Lost(_))));
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    assert!(durable.candidates.is_empty());
    assert_eq!(durable.phase, Phase::Rebase);
    assert!(durable.last_response.is_none());
    retained_submission::validate(&durable).unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one crash/restart scenario pins repeated unsaved replay and durable release"
)]
async fn unsaved_lost_answers_retry_the_exact_tuple_until_release_is_durable() {
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
    let r = transport.durable.lock().unwrap().clone().unwrap();
    let c = r.candidates.first().unwrap().clone();
    let mut foreign = root::decode_root(&c.root).unwrap();
    foreign.writer_uuid = [99; 16];
    let foreign = sign_doc(foreign, &key);
    let occupant = GrainId::of(&foreign);
    let wire = PublishAnswer::Lost {
        position: Position {
            epoch: Epoch::from_bytes(c.request.epoch),
            entry_seq: 91,
        },
        candidate_id: c.id,
        occupant,
        head: None,
    };
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::Wire(wire));
    // Load, probe-start, probe-end, attempt, then the lost answer's save.
    journal.fail_at = Some(journal.cuts + 5);
    let failed = resume_publication(
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
    .await;
    assert!(matches!(failed, Err(RecoveryError::Journal(_))));
    assert!(journal.poisoned);
    let awaiting = transport.durable.lock().unwrap().clone().unwrap();
    assert!(matches!(
        awaiting.phase,
        Phase::AwaitingAnswer {
            candidate: 1,
            attempt: 2
        }
    ));
    assert_eq!(awaiting.candidates.first().unwrap().root, c.root);
    let sends_before = transport.remote.lock().unwrap().sends.len();
    let probes_before = transport.remote.lock().unwrap().probes;
    assert_eq!(sends_before, 2);
    assert_eq!(probes_before, 3);
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .insert(c.seq, foreign.clone());
    // A second answer-save interruption must keep the same exact tuple.
    journal = Journal::new(transport.durable.clone());
    journal.fail_at = Some(6); // load, normalize, probe start/end, send, answer
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::Wire(wire));
    let failed = resume_publication(
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
    .await;
    assert!(matches!(failed, Err(RecoveryError::Journal(_))));
    assert!(journal.poisoned);
    let awaiting = transport.durable.lock().unwrap().clone().unwrap();
    assert!(matches!(
        awaiting.phase,
        Phase::AwaitingAnswer {
            candidate: 1,
            attempt: 3
        }
    ));
    assert_eq!(awaiting.candidates.len(), 1);
    assert_eq!(awaiting.candidates[0].evidence.last_answered_attempt, 0);
    assert_eq!(transport.remote.lock().unwrap().sends.len(), 3);
    assert_eq!(transport.remote.lock().unwrap().probes, 5);
    assert_eq!(transport.remote.lock().unwrap().max_seq_calls, 5);
    journal = Journal::new(transport.durable.clone());
    transport.remote.lock().unwrap().plans.extend([
        Plan::Wire(wire),
        Plan::Reply(PublishResponse::Refused(crate::PublishRefusal::NotEnrolled)),
    ]);
    let out = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(4),
            &mut delay,
        ),
        &begun.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::Refused);
    assert!(!out.uncertain);
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(durable.candidates.len(), 1);
    let rebased = durable.candidates.first().unwrap();
    assert_eq!(rebased.role, Role::Active);
    assert_eq!(rebased.seq, c.seq + 1);
    assert_ne!(rebased.id, c.id);
    assert_eq!(rebased.request, c.request);
    assert_eq!(
        root::decode_root(&rebased.root).unwrap().parent,
        Some(occupant)
    );
    assert_eq!(durable.current, r.current);
    retained_submission::validate(&durable).unwrap();
    let remote = transport.remote.lock().unwrap();
    assert_eq!(remote.sends.len(), 5);
    assert!(
        remote
            .sends
            .iter()
            .take(4)
            .all(|send| send == &remote.sends[0])
    );
    assert_eq!(remote.attempts, vec![1, 2, 3, 4, 1]);
    assert_eq!(remote.sends[4].3, rebased.root);
    assert_eq!(remote.roots, BTreeMap::from([(c.seq, foreign)]));
}

async fn resume(
    t: &Transport,
    j: &mut Journal,
    r: &Submission,
    intent: RecoveryIntent,
    delay: &mut Delay,
) -> Result<PublicationResult, RecoveryError> {
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
    resume_publication(
        parts(
            t,
            j,
            &key,
            &keys,
            &mut Entropy::default(),
            &FixedClock(2),
            delay,
        ),
        &handle(r),
        intent,
    )
    .await
}
fn foreign(t: &Transport, r: &Submission) -> GrainId {
    let c = r
        .candidates
        .iter()
        .find(|c| c.role == Role::Active)
        .unwrap();
    let mut doc = root::decode_root(&c.root).unwrap();
    doc.writer_uuid = [99; 16];
    let bytes = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
    let id = GrainId::of(&bytes);
    t.remote.lock().unwrap().roots.insert(c.seq, bytes);
    id
}
fn at_seq(number: u64, seq: u64) -> Candidate {
    let mut doc = root::decode_root(&root_bytes(i64::try_from(number).unwrap())).unwrap();
    doc.seq = seq;
    doc.parent = (seq != 1).then(|| GrainId::of(b"parent"));
    let mut c = candidate(
        number,
        1,
        sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap()),
    );
    c.seq = seq;
    c
}

fn linked_root(seq: u64, parent: Option<GrainId>, stamp: i64) -> Vec<u8> {
    let mut doc = root::decode_root(&root_bytes(stamp)).unwrap();
    doc.seq = seq;
    doc.parent = parent;
    sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap())
}

fn slot_variant(bytes: &[u8], slot: u8) -> Vec<u8> {
    let mut doc = root::decode_root(bytes).unwrap();
    doc.sigs.push(RootSig {
        key_id: [slot; 32],
        sig: [0; 64],
    });
    root::encode_root(&doc).unwrap()
}

fn candidate_shape(record: &Submission) -> Vec<(u64, Role, u64, GrainId, Vec<u8>)> {
    record
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.number,
                candidate.role,
                candidate.seq,
                candidate.id,
                candidate.root.clone(),
            )
        })
        .collect()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the highest-match row includes its exact, variant, ancestor and foreign controls"
)]
async fn live_barrier_selects_highest_variant_before_dispatch() {
    let (transport, mut journal, _, _, _, mut delay) = setup();
    let mut chain = BTreeMap::new();
    let mut parent = None;
    let mut candidate_five = None;
    let mut candidate_seven = None;
    let mut stored_seven = None;
    for seq in 1..=7 {
        let candidate = linked_root(seq, parent, i64::try_from(seq).unwrap());
        let stored = if seq == 5 || seq == 7 {
            slot_variant(&candidate, u8::try_from(90 + seq).unwrap())
        } else {
            candidate.clone()
        };
        if seq == 5 {
            candidate_five = Some(candidate);
        } else if seq == 7 {
            candidate_seven = Some(candidate);
            stored_seven = Some(stored.clone());
        }
        parent = Some(GrainId::of(&stored));
        chain.insert(seq, stored);
    }
    let candidate_five = candidate_five.unwrap();
    let candidate_seven = candidate_seven.unwrap();
    let stored_seven = stored_seven.unwrap();
    let mut submission = record();
    submission.frozen.initial_root.clone_from(&candidate_five);
    submission.candidates = vec![
        Candidate {
            role: Role::History,
            seq: 5,
            root: candidate_five.clone(),
            id: GrainId::of(&candidate_five),
            ..candidate(1, 1, candidate_five)
        },
        Candidate {
            seq: 7,
            root: candidate_seven.clone(),
            id: GrainId::of(&candidate_seven),
            ..candidate(2, 1, candidate_seven.clone())
        },
    ];
    submission.current = Some(submission.candidates[1].request);
    granary_core::retained_submission::validate(&submission).unwrap();
    *transport.durable.lock().unwrap() = Some(submission.clone());
    transport.remote.lock().unwrap().roots = chain;

    let out = resume(
        &transport,
        &mut journal,
        &submission,
        RecoveryIntent::Continue,
        &mut delay,
    )
    .await
    .unwrap();
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    let actual = match (&out.outcome, &durable.phase) {
        (PublicationOutcome::Landed(done), Phase::Complete(_)) => {
            let remote = transport.remote.lock().unwrap();
            Some((
                done.id,
                remote.roots.get(&done.seq).map(|bytes| GrainId::of(bytes)),
                remote.sends.len(),
            ))
        }
        _ => None,
    };
    let mut controls = 0;
    for (name, ancestor, envelope) in [
        ("exact-head", false, "exact"),
        ("exact-ancestor", true, "exact"),
        ("foreign", false, "foreign"),
        ("extra-head", false, "extra"),
        ("extra-ancestor", true, "extra"),
        ("reordered-head", false, "reordered"),
        ("reordered-ancestor", true, "reordered"),
    ] {
        let (transport, mut journal, key, _, _, mut delay) = setup();
        let record = record();
        let mut doc = root::decode_root(&record.candidates[0].root).unwrap();
        let stored = match envelope {
            "exact" => record.candidates[0].root.clone(),
            "extra" => slot_variant(&record.candidates[0].root, 96),
            "reordered" => {
                doc.sigs.push(RootSig {
                    key_id: [96; 32],
                    sig: [0; 64],
                });
                doc.sigs.swap(0, 1);
                root::encode_root(&doc).unwrap()
            }
            _ => {
                doc.writer_uuid = [99; 16];
                sign_doc(doc, &key)
            }
        };
        let mut roots = BTreeMap::from([(1, stored.clone())]);
        if ancestor {
            roots.insert(2, linked_root(2, Some(GrainId::of(&stored)), 2));
        }
        *transport.durable.lock().unwrap() = Some(record.clone());
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.roots = roots;
            if envelope == "foreign" {
                remote.plans.push_back(Plan::Reply(PublishResponse::Refused(
                    crate::PublishRefusal::NotEnrolled,
                )));
            }
        }
        let out = resume(
            &transport,
            &mut journal,
            &record,
            RecoveryIntent::Continue,
            &mut delay,
        )
        .await
        .unwrap();
        let sends = transport.remote.lock().unwrap().sends.len();
        if envelope == "foreign" {
            assert_eq!(
                (out.outcome, sends),
                (PublicationOutcome::Refused, 1),
                "{name}"
            );
        } else {
            assert!(
                matches!(&out.outcome, PublicationOutcome::Landed(done) if done.id == record.candidates[0].id),
                "{name}: {out:?}"
            );
            assert_eq!(sends, 0, "{name}");
        }
        controls += 1;
    }
    assert_eq!(controls, 7);
    assert_eq!(
        actual,
        Some((
            GrainId::of(&candidate_seven),
            Some(GrainId::of(&stored_seven)),
            0
        )),
        "the highest candidate identity and stored variant must complete before dispatch; outcome={:?}, phase={:?}; {controls} exact/foreign controls passed",
        out.outcome,
        durable.phase
    );
}

#[tokio::test]
async fn candidate_landing_during_probe_is_classified_before_dispatch() {
    let (transport, mut journal, _, _, _, mut delay) = setup();
    let record = record();
    let stored = slot_variant(&record.candidates[0].root, 94);
    let stored_id = GrainId::of(&stored);
    *transport.durable.lock().unwrap() = Some(record.clone());
    transport
        .remote
        .lock()
        .unwrap()
        .roots_on_probe
        .push((record.candidates[0].seq, stored));

    let out = resume(
        &transport,
        &mut journal,
        &record,
        RecoveryIntent::Continue,
        &mut delay,
    )
    .await
    .unwrap();
    let remote = transport.remote.lock().unwrap();
    assert_eq!(
        (
            out.outcome,
            remote
                .roots
                .get(&record.candidates[0].seq)
                .map(|bytes| GrainId::of(bytes)),
            remote.sends.len(),
            remote.max_seq_calls,
        ),
        (
            PublicationOutcome::Landed(Completion {
                seq: record.candidates[0].seq,
                id: record.candidates[0].id,
                root: record.candidates[0].root.clone(),
                receipt: None,
            }),
            Some(stored_id),
            0,
            1,
        ),
        "a landing exposed by the slot probe must be included in the following head walk"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "valid and mismatched Lost/StaleBase cases share one durable classification row"
)]
async fn deferred_answers_reclassify_before_phase_rewrite_or_dispatch() {
    for stale in [false, true] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let mut record = record();
        let foreign = linked_root(1, None, 51 + i64::from(stale));
        let foreign_id = GrainId::of(&foreign);
        if stale {
            let mut doc = root::decode_root(&record.candidates[0].root).unwrap();
            doc.seq = 2;
            doc.parent = Some(foreign_id);
            let root = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
            record.candidates[0].seq = 2;
            record.candidates[0].id = GrainId::of(&root);
            record.candidates[0].root = root;
        }
        granary_core::retained_submission::validate(&record).unwrap();
        let original = record.candidates[0].root.clone();
        *transport.durable.lock().unwrap() = Some(record.clone());
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.roots_on_send.push((1, foreign));
            remote.fail_probe_at = Some(2);
            if stale {
                remote
                    .plans
                    .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                        1, foreign_id,
                    ))))));
            } else {
                remote
                    .plans
                    .push_back(Plan::Reply(lost_answer(&record, 1, foreign_id)));
            }
        }

        let first = resume(
            &transport,
            &mut journal,
            &record,
            RecoveryIntent::Continue,
            &mut delay,
        )
        .await
        .unwrap();
        let deferred = transport.durable.lock().unwrap().clone().unwrap();
        assert_eq!(
            (
                first.outcome,
                deferred.phase.clone(),
                deferred.last_response.is_some(),
                transport.remote.lock().unwrap().sends.len(),
            ),
            (
                PublicationOutcome::Unresolved,
                Phase::Unresolved(Probe {
                    cycle: deferred.generation - 1,
                    seq: record.candidates[0].seq,
                    reason: ProbeReason::ContentUnavailable,
                }),
                true,
                1,
            ),
            "stale={stale}: the unavailable answer read must retain accounting and stop"
        );
        let continued = resume(
            &transport,
            &mut journal,
            &record,
            RecoveryIntent::Continue,
            &mut delay,
        )
        .await
        .unwrap();
        assert_eq!(
            continued.outcome,
            PublicationOutcome::Unresolved,
            "stale={stale}: ordinary continuation must leave explicit recovery owed"
        );
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.fail_probe_at = None;
        }
        let classified = resume_exact_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(3),
                &mut delay,
            ),
            &handle(&record),
            RecoveryIntent::ExplicitRecovery,
        )
        .await
        .unwrap();
        let applied = transport.durable.lock().unwrap().clone().unwrap();
        let remote = transport.remote.lock().unwrap();
        assert_eq!(
            (
                classified.outcome,
                applied.phase,
                applied.last_response.is_some(),
                remote.sends.len(),
                remote
                    .sends
                    .iter()
                    .filter(|send| send.3 == original)
                    .count(),
            ),
            (PublicationOutcome::Unresolved, Phase::Rebase, stale, 1, 1,),
            "stale={stale}: explicit recovery must classify before phase rewrite or dispatch"
        );
    }
}

fn deferred_stale_release_case(
    decision_seen: bool,
) -> (Submission, Vec<(u64, Vec<u8>)>, u64, GrainId) {
    let foreign_seq = if decision_seen { 2 } else { 1 };
    let ancestor = decision_seen.then(|| linked_root(1, None, 60));
    let ancestor_id = ancestor.as_ref().map(|bytes| GrainId::of(bytes));
    let foreign = linked_root(foreign_seq, ancestor_id, 61 + i64::from(decision_seen));
    let foreign_id = GrainId::of(&foreign);
    let mut record = record();
    let mut doc = root::decode_root(&record.candidates[0].root).unwrap();
    doc.seq = 2;
    doc.parent = Some(if decision_seen {
        ancestor_id.unwrap()
    } else {
        foreign_id
    });
    let candidate = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
    record.candidates[0].seq = 2;
    record.candidates[0].id = GrainId::of(&candidate);
    record.candidates[0].root = candidate;
    record.candidates[0].evidence.decision_seen = decision_seen;
    retained_submission::validate(&record).unwrap();
    let mut roots = Vec::new();
    if let Some(ancestor) = ancestor {
        roots.push((1, ancestor));
    }
    roots.push((foreign_seq, foreign));
    (record, roots, foreign_seq, foreign_id)
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "applied and deferred StaleBase controls share one retained-answer row"
)]
async fn stored_stale_answer_does_not_bypass_live_release_rules() {
    let mut applied = record();
    let applied_occupant = GrainId::of(b"applied stale occupant");
    let request = request_for(&applied, 1);
    let answer = validate_publish_answer(
        &request,
        409,
        Some("stale-base"),
        &authority_answer::encode(PublishAnswer::StaleBase(Head::new(Some((
            1,
            applied_occupant,
        )))))
        .unwrap(),
    )
    .unwrap();
    coordinator::apply_answer(&mut applied, 1, 1, answer).unwrap();
    assert_eq!(
        (applied.phase.clone(), applied.last_response.is_none()),
        (Phase::Rebase, false),
        "an applied StaleBase marker must remain ineligible for deferred classification"
    );
    let (transport, mut journal, _, _, _, mut delay) = setup();
    *transport.durable.lock().unwrap() = Some(applied.clone());
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .insert(2, linked_root(2, Some(applied_occupant), 62));
    let error = resume(
        &transport,
        &mut journal,
        &applied,
        RecoveryIntent::ExplicitRecovery,
        &mut delay,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error,
            RecoveryError::RemoteIntegrity("probe chain root missing")
        ),
        "an applied answer must not turn a missing chain root into deferral: {error:?}"
    );

    let mut cases = 1;
    for decision_seen in [false, true] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let (record, roots, foreign_seq, foreign_id) = deferred_stale_release_case(decision_seen);
        *transport.durable.lock().unwrap() = Some(record.clone());
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.roots_on_send = roots;
            remote.fail_probe_at = Some(2);
            remote
                .plans
                .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                    foreign_seq,
                    foreign_id,
                ))))));
        }
        let first = resume(
            &transport,
            &mut journal,
            &record,
            RecoveryIntent::Continue,
            &mut delay,
        )
        .await
        .unwrap();
        assert_eq!(first.outcome, PublicationOutcome::Unresolved);
        transport.remote.lock().unwrap().fail_probe_at = None;
        let second = resume_exact_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            &handle(&record),
            RecoveryIntent::ExplicitRecovery,
        )
        .await
        .unwrap();
        let durable = transport.durable.lock().unwrap().clone().unwrap();
        assert_eq!(
            (
                second.outcome,
                durable.phase,
                durable.candidates[0].role,
                durable.candidates[0].evidence.decision_seen,
                durable.last_response.is_some(),
                transport.remote.lock().unwrap().sends.len(),
            ),
            if decision_seen {
                (
                    PublicationOutcome::BackendError,
                    Phase::Ready,
                    Role::Active,
                    true,
                    false,
                    1,
                )
            } else {
                (
                    PublicationOutcome::Unresolved,
                    Phase::Rebase,
                    Role::Active,
                    false,
                    true,
                    1,
                )
            },
            "decision_seen={decision_seen}: deferred StaleBase must reapply the live release rules without resending"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the contradiction row keeps classification and terminal replay in one timeline"
)]
async fn deferred_stale_decision_contradiction_ends_once() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let (record, roots, foreign_seq, foreign_id) = deferred_stale_release_case(true);
    *transport.durable.lock().unwrap() = Some(record.clone());
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.roots_on_send = roots;
        remote.fail_probe_at = Some(2);
        remote
            .plans
            .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                foreign_seq,
                foreign_id,
            ))))));
    }
    let first = resume(
        &transport,
        &mut journal,
        &record,
        RecoveryIntent::Continue,
        &mut delay,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            first.outcome,
            transport
                .durable
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .last_response
                .is_some(),
            transport.remote.lock().unwrap().sends.len(),
        ),
        (PublicationOutcome::Unresolved, true, 1),
        "the decision-bearing answer must first reach the deferred marker"
    );

    transport.remote.lock().unwrap().fail_probe_at = None;
    let second = resume_exact_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &handle(&record),
        RecoveryIntent::ExplicitRecovery,
    )
    .await
    .unwrap();
    let consumed = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            second.outcome,
            second.diagnostic.as_deref(),
            consumed.phase.clone(),
            consumed.last_response.is_some(),
            transport.remote.lock().unwrap().sends.len(),
        ),
        (
            PublicationOutcome::BackendError,
            Some("stale answer contradicts decision evidence"),
            Phase::Ready,
            false,
            1,
        ),
        "the contradiction must consume the marker without another send"
    );

    {
        let mut remote = transport.remote.lock().unwrap();
        remote.roots.clear();
        remote.fail_probe_at = Some(remote.probes + 1);
    }
    let third = resume_exact_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(3),
            &mut delay,
        ),
        &handle(&record),
        RecoveryIntent::ExplicitRecovery,
    )
    .await
    .unwrap();
    let after = transport.durable.lock().unwrap().clone().unwrap();
    assert!(
        matches!(
            after.phase,
            Phase::Unresolved(Probe {
                reason: ProbeReason::Transport,
                ..
            })
        ),
        "the next run must take the ordinary fresh barrier: outcome={:?}, record={after:?}",
        third.outcome
    );
    assert_eq!(
        (
            after.last_response.is_some(),
            transport.remote.lock().unwrap().sends.len(),
        ),
        (false, 1),
        "the consumed answer must not replay or resend"
    );
}

#[tokio::test]
async fn applied_stale_answer_is_not_deferred() {
    let (transport, mut journal, _, _, _, mut delay) = setup();
    let root_one = linked_root(1, None, 71);
    let root_one_id = GrainId::of(&root_one);
    let mut record = record();
    let mut doc = root::decode_root(&record.candidates[0].root).unwrap();
    doc.seq = 2;
    doc.parent = Some(root_one_id);
    let candidate = sign_doc(doc.clone(), &SigningKey::from_seed(&[9; 32]).unwrap());
    doc.writer_uuid = [99; 16];
    let foreign = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
    record.candidates[0].seq = 2;
    record.candidates[0].id = GrainId::of(&candidate);
    record.candidates[0].root = candidate;
    record.candidates[0].evidence.started = 1;
    retained_submission::validate(&record).unwrap();
    *transport.durable.lock().unwrap() = Some(record.clone());
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.roots = BTreeMap::from([(1, root_one), (2, foreign)]);
        remote
            .plans
            .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                1,
                root_one_id,
            ))))));
    }

    let first = resume(
        &transport,
        &mut journal,
        &record,
        RecoveryIntent::Continue,
        &mut delay,
    )
    .await
    .unwrap();
    let applied = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            first.outcome,
            applied.phase,
            applied.last_response.is_some(),
            transport.remote.lock().unwrap().sends.len(),
        ),
        (PublicationOutcome::Unresolved, Phase::Ready, true, 1),
        "the low-head exact-retry answer must remain an applied Ready response"
    );
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.fail_probe_at = Some(remote.probes + 2);
        remote.plans.push_back(Plan::Reply(PublishResponse::Refused(
            crate::PublishRefusal::NotEnrolled,
        )));
    }
    let second = resume(
        &transport,
        &mut journal,
        &record,
        RecoveryIntent::ExplicitRecovery,
        &mut delay,
    )
    .await
    .unwrap();
    assert_eq!(
        (second.outcome, transport.remote.lock().unwrap().sends.len(),),
        (PublicationOutcome::Refused, 2),
        "an applied answer must take the ordinary candidate-floor barrier and dispatch path"
    );
}

#[tokio::test]
async fn deferred_low_head_stale_retry_applies_once() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let root_one = linked_root(1, None, 72);
    let root_one_id = GrainId::of(&root_one);
    let mut record = record();
    let mut doc = root::decode_root(&record.candidates[0].root).unwrap();
    doc.seq = 2;
    doc.parent = Some(root_one_id);
    let candidate = sign_doc(doc.clone(), &SigningKey::from_seed(&[9; 32]).unwrap());
    doc.writer_uuid = [99; 16];
    let foreign = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
    record.candidates[0].seq = 2;
    record.candidates[0].id = GrainId::of(&candidate);
    record.candidates[0].root = candidate;
    retained_submission::validate(&record).unwrap();
    *transport.durable.lock().unwrap() = Some(record.clone());
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.roots = BTreeMap::from([(1, root_one), (2, foreign)]);
        remote.fail_probe_at = Some(2);
        remote
            .plans
            .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                1,
                root_one_id,
            ))))));
    }

    let first = resume(
        &transport,
        &mut journal,
        &record,
        RecoveryIntent::Continue,
        &mut delay,
    )
    .await
    .unwrap();
    let deferred = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            first.outcome,
            deferred_answer_pending(&deferred),
            transport.remote.lock().unwrap().sends.len(),
        ),
        (PublicationOutcome::Unresolved, true, 1),
        "the unavailable low-head answer must become one durable owed classification"
    );
    transport.remote.lock().unwrap().fail_probe_at = None;

    let second = resume_exact_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(3),
            &mut delay,
        ),
        &handle(&record),
        RecoveryIntent::ExplicitRecovery,
    )
    .await
    .unwrap();
    let applied = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            second.outcome,
            second.diagnostic.as_deref(),
            applied.phase.clone(),
            applied.last_response.is_some(),
            deferred_answer_pending(&applied),
            transport.remote.lock().unwrap().sends.len(),
        ),
        (
            PublicationOutcome::Unresolved,
            Some("stale retry release was not proven"),
            Phase::Ready,
            true,
            false,
            1,
        ),
        "healthy replay must consume the marker into the ordinary applied destination without resending"
    );
}

#[tokio::test]
async fn deferred_stale_integrity_does_not_prove_no_write() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let (mut record, roots, answer_id) = answer_integrity_case("id-mismatch");
    record.candidates[0].evidence = retained_submission::Evidence::default();
    retained_submission::validate(&record).unwrap();
    *transport.durable.lock().unwrap() = Some(record.clone());
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.roots_on_send = roots;
        remote.fail_probe_at = Some(2);
        remote
            .plans
            .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                1, answer_id,
            ))))));
    }

    let first = resume(
        &transport,
        &mut journal,
        &record,
        RecoveryIntent::Continue,
        &mut delay,
    )
    .await
    .unwrap();
    let deferred = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            first.outcome,
            deferred.candidates[0].evidence.proved_no_write,
            deferred_answer_pending(&deferred),
        ),
        (PublicationOutcome::Unresolved, 1, true),
        "deferral must retain the checked stale-base accounting"
    );
    transport.remote.lock().unwrap().fail_probe_at = None;

    let second = resume_exact_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(3),
            &mut delay,
        ),
        &handle(&record),
        RecoveryIntent::ExplicitRecovery,
    )
    .await
    .unwrap();
    let ended = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            second.outcome,
            second.diagnostic.as_deref(),
            ended.phase.clone(),
            ended.last_response.is_some(),
            ended.candidates[0].evidence.proved_no_write,
            crate::NoWriteProof::from_submission(&ended, 1).is_some(),
        ),
        (
            PublicationOutcome::BackendError,
            Some("stored landing mismatch"),
            Phase::Ready,
            false,
            0,
            false,
        ),
        "an invalid replay must not turn its stale-base answer into release proof"
    );
}

#[tokio::test]
async fn occupied_barrier_defers_when_head_read_is_unavailable() {
    let (transport, mut journal, _, _, _, mut delay) = setup();
    let record = record();
    let stored = slot_variant(&record.candidates[0].root, 95);
    *transport.durable.lock().unwrap() = Some(record.clone());
    {
        let mut remote = transport.remote.lock().unwrap();
        remote.roots.insert(1, stored);
        remote.fail_max_seq = true;
    }

    let out = resume(
        &transport,
        &mut journal,
        &record,
        RecoveryIntent::Continue,
        &mut delay,
    )
    .await
    .unwrap();
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            out.outcome,
            out.diagnostic.as_deref(),
            candidate_shape(&durable),
            transport.remote.lock().unwrap().sends.len(),
        ),
        (
            PublicationOutcome::Unresolved,
            Some("probe unresolved"),
            candidate_shape(&record),
            0,
        ),
        "an unavailable head read must preserve the occupied catalogue without dispatch"
    );
    assert!(matches!(durable.phase, Phase::Unresolved(_)));
}

fn answer_integrity_case(name: &str) -> (Submission, Vec<(u64, Vec<u8>)>, GrainId) {
    let mut record = record();
    let stored = slot_variant(&record.candidates[0].root, 97);
    let mut answer_id = GrainId::of(&stored);
    let mut roots = vec![(1, stored.clone())];
    if name == "id-mismatch" {
        answer_id = GrainId::of(b"different answer occupant");
    } else if name == "off-chain" {
        roots.push((
            2,
            linked_root(2, Some(GrainId::of(b"different ancestor")), 2),
        ));
    } else if name == "ambiguous" || name == "exact-alias" {
        let alias_root = if name == "exact-alias" {
            stored
        } else {
            slot_variant(&record.candidates[0].root, 96)
        };
        let mut alias = Candidate {
            number: 2,
            role: Role::History,
            id: GrainId::of(&alias_root),
            root: alias_root,
            ..record.candidates[0].clone()
        };
        alias.evidence.started = 1;
        record.candidates.push(alias);
    }
    granary_core::retained_submission::validate(&record).unwrap();
    (record, roots, answer_id)
}

#[tokio::test]
async fn live_answer_occupancy_requires_the_exact_verified_chain() {
    let mut cases = 0;
    for name in [
        "valid",
        "id-mismatch",
        "off-chain",
        "missing",
        "ambiguous",
        "exact-alias",
    ] {
        let (transport, mut journal, _, _, _, mut delay) = setup();
        let (record, mut roots, answer_id) = answer_integrity_case(name);
        if name == "missing" {
            roots.clear();
        }
        let answer = lost_answer(&record, 1, answer_id);
        *transport.durable.lock().unwrap() = Some(record.clone());
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.roots_on_send = roots;
            remote.plans.push_back(Plan::Reply(answer));
        }

        let out = resume(
            &transport,
            &mut journal,
            &record,
            RecoveryIntent::Continue,
            &mut delay,
        )
        .await
        .unwrap();
        let durable = transport.durable.lock().unwrap().clone().unwrap();
        let sends = transport.remote.lock().unwrap().sends.len();
        let expected_error = match name {
            "id-mismatch" => Some((PublicationOutcome::BackendError, "stored landing mismatch")),
            "off-chain" => Some((PublicationOutcome::BackendError, "probe ancestry mismatch")),
            "missing" => Some((PublicationOutcome::Unresolved, "probe chain root missing")),
            "ambiguous" => Some((
                PublicationOutcome::BackendError,
                "ambiguous probe candidate",
            )),
            _ => None,
        };
        if let Some((outcome, diagnostic)) = expected_error {
            assert_eq!(
                (
                    out.outcome,
                    out.diagnostic.as_deref(),
                    candidate_shape(&durable),
                    durable.phase.clone(),
                    durable.last_response.is_some(),
                    sends,
                ),
                (
                    outcome,
                    Some(diagnostic),
                    candidate_shape(&record),
                    if name == "missing" {
                        Phase::Unresolved(Probe {
                            cycle: durable.generation - 1,
                            seq: record.candidates[0].seq,
                            reason: ProbeReason::ContentUnavailable,
                        })
                    } else {
                        Phase::Ready
                    },
                    name == "missing",
                    1,
                ),
                "{name}: answer occupancy refusal must preserve the catalogue and stop after one send"
            );
        } else {
            let expected = if name == "exact-alias" {
                record.candidates[1].id
            } else {
                record.candidates[0].id
            };
            assert!(
                matches!(&out.outcome, PublicationOutcome::Landed(done) if done.id == expected && done.receipt.is_none()),
                "{name}: expected candidate completion, got outcome={:?}, phase={:?}, sends={sends}",
                out.outcome,
                durable.phase
            );
            assert_eq!(sends, 1, "{name}");
        }
        cases += 1;
    }
    assert_eq!(cases, 6);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "three integrity endings and a linked control share the same deferred replay setup"
)]
async fn deferred_replay_integrity_errors_end_once() {
    let mut cases = 0;
    for name in [
        "id-mismatch",
        "off-chain",
        "ambiguous",
        "over-cap",
        "over-cap-behind-listing",
        "valid",
    ] {
        let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
        let (record, roots, answer_id) = answer_integrity_case(name);
        *transport.durable.lock().unwrap() = Some(record.clone());
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.roots_on_send = roots;
            remote.fail_probe_at = Some(2);
            remote
                .plans
                .push_back(Plan::Reply(lost_answer(&record, 1, answer_id)));
        }
        let first = resume(
            &transport,
            &mut journal,
            &record,
            RecoveryIntent::Continue,
            &mut delay,
        )
        .await
        .unwrap();
        let deferred = transport.durable.lock().unwrap().clone().unwrap();
        assert_eq!(
            (
                first.outcome,
                deferred.last_response.is_some(),
                transport.remote.lock().unwrap().sends.len(),
            ),
            (PublicationOutcome::Unresolved, true, 1),
            "{name}: checked answer must first reach the durable deferred marker"
        );
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.fail_probe_at = None;
            if name.starts_with("over-cap") {
                remote.over_cap_probe_at = Some(remote.probes + 1);
            }
            remote.fail_max_seq = name == "over-cap-behind-listing";
        }
        let second = resume_exact_publication(
            parts(
                &transport,
                &mut journal,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(7),
                &mut delay,
            ),
            &handle(&record),
            RecoveryIntent::ExplicitRecovery,
        )
        .await
        .unwrap();
        let durable = transport.durable.lock().unwrap().clone().unwrap();
        if name == "valid" {
            assert!(
                matches!(second.outcome, PublicationOutcome::Landed(_)),
                "valid linked replay did not complete: {second:?}"
            );
            assert!(
                durable.last_response.is_some(),
                "valid linked replay discarded the ordinary landed response"
            );
        } else {
            let diagnostic = match name {
                "id-mismatch" => "stored landing mismatch",
                "off-chain" => "probe ancestry mismatch",
                "ambiguous" => "ambiguous probe candidate",
                "over-cap" | "over-cap-behind-listing" => "untrusted probe head",
                _ => unreachable!(),
            };
            assert_eq!(
                (
                    second.outcome,
                    second.diagnostic.as_deref(),
                    durable.phase.clone(),
                    durable.last_response.is_some(),
                    transport.remote.lock().unwrap().sends.len(),
                ),
                (
                    PublicationOutcome::BackendError,
                    Some(diagnostic),
                    Phase::Ready,
                    false,
                    1,
                ),
                "{name}: permanent replay failure must consume its marker once"
            );

            {
                let mut remote = transport.remote.lock().unwrap();
                remote.roots.clear();
                remote.fail_probe_at = Some(remote.probes + 1);
            }
            let third = resume_exact_publication(
                parts(
                    &transport,
                    &mut journal,
                    &key,
                    &keys,
                    &mut entropy,
                    &FixedClock(8),
                    &mut delay,
                ),
                &handle(&record),
                RecoveryIntent::ExplicitRecovery,
            )
            .await
            .unwrap();
            let after = transport.durable.lock().unwrap().clone().unwrap();
            assert!(
                matches!(
                    after.phase,
                    Phase::Unresolved(Probe {
                        reason: ProbeReason::Transport,
                        ..
                    })
                ),
                "{name}: later ordinary probe must not re-enter deferred replay: outcome={:?}, record={after:?}",
                third.outcome
            );
            assert!(
                after.last_response.is_none(),
                "{name}: marker replayed twice"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 6);
}

fn wire_open(r: &Submission, open: bool) -> PublishAnswer {
    let c = r
        .candidates
        .iter()
        .find(|c| c.role == Role::Active)
        .unwrap();
    let position = Position {
        epoch: Epoch::from_bytes(c.request.epoch),
        entry_seq: 91,
    };
    if open {
        PublishAnswer::Open {
            position,
            candidate_id: c.id,
        }
    } else {
        PublishAnswer::Accepted {
            position,
            candidate_id: c.id,
        }
    }
}

#[tokio::test]
async fn foreign_uncertain_active_retries_exactly_at_capacity_even_from_rebase() {
    for rebase in [false, true] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let mut r = record();
        for number in 2..=u64::try_from(MAX_CANDIDATES).unwrap() {
            let mut c = candidate(number, 1, root_bytes(i64::try_from(number).unwrap()));
            c.role = Role::History;
            r.candidates.push(c);
        }
        if rebase {
            r.phase = Phase::Rebase;
        }
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        t.remote.lock().unwrap().plans.push_back(Plan::LostReply);
        let out = resume(&t, &mut j, &r, RecoveryIntent::ExplicitRecovery, &mut delay)
            .await
            .unwrap();
        assert_eq!(out.outcome, PublicationOutcome::Pending);
        let remote = t.remote.lock().unwrap();
        assert_eq!(remote.sends.len(), 1);
        assert_eq!(remote.sends[0].3, r.candidates[0].root);
        assert_eq!(remote.sends[0].1, r.current.unwrap().epoch);
        assert_eq!(remote.sends[0].2, r.current.unwrap().operation);
        assert_eq!(remote.attempts, vec![2]);
        assert_eq!(
            (
                remote.max_seq_calls,
                remote.meta_uploads,
                remote.bin_uploads
            ),
            (1, 0, 0)
        );
        assert_eq!(
            t.durable.lock().unwrap().as_ref().unwrap().candidates.len(),
            MAX_CANDIDATES
        );
    }
}

#[tokio::test]
async fn retry_checks_later_owned_slots_and_failed_probes_before_sending() {
    for owned in [false, true] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let mut r = record();
        let mut later = at_seq(2, 2);
        later.role = Role::History;
        r.candidates.push(later.clone());
        let foreign = foreign(&t, &r);
        if owned {
            let mut doc = root::decode_root(&later.root).unwrap();
            doc.parent = Some(foreign);
            later.root = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
            later.id = GrainId::of(&later.root);
            r.candidates[1] = later.clone();
            t.remote.lock().unwrap().roots.insert(2, later.root.clone());
        } else {
            t.remote.lock().unwrap().fail_probe_at = Some(2);
        }
        *t.durable.lock().unwrap() = Some(r.clone());
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        if owned {
            assert!(matches!(out.outcome, PublicationOutcome::Landed(done) if done.id == later.id));
        } else {
            assert_eq!(out.outcome, PublicationOutcome::Unresolved);
        }
        assert_eq!(t.remote.lock().unwrap().probes, 2);
        assert!(t.remote.lock().unwrap().sends.is_empty());
    }
}

#[tokio::test]
async fn exact_retry_is_blocked_by_an_empty_retired_slot_above_the_head() {
    for seq in [2, 3] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let mut r = record();
        let mut retired = at_seq(2, seq);
        retired.role = Role::Retired;
        retired.request = RequestIdentity {
            epoch: [2; 16],
            operation: [2; 16],
        };
        r.candidates.push(retired);
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        assert_eq!(out.outcome, PublicationOutcome::Unresolved);
        assert!(t.remote.lock().unwrap().sends.is_empty());
        assert_eq!(t.remote.lock().unwrap().max_seq_calls, 1);
    }
}

#[tokio::test]
async fn later_refusal_service_and_invalid_answers_keep_the_original_retry() {
    for plan in [
        Plan::Reply(PublishResponse::Refused(crate::PublishRefusal::NotEnrolled)),
        Plan::Reply(PublishResponse::RateLimited),
        Plan::Reply(PublishResponse::ServiceUnavailable(
            ServiceReason::EnrollmentUnavailable,
        )),
        Plan::Reply(PublishResponse::ServiceUnavailable(
            ServiceReason::Unavailable,
        )),
        Plan::Reply(PublishResponse::Internal),
        Plan::Invalid,
    ] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let r = record();
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .extend([plan, Plan::LostReply]);
        resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        t.remote.lock().unwrap().plans.clear();
        t.remote.lock().unwrap().plans.push_back(Plan::LostReply);
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        assert_eq!(out.outcome, PublicationOutcome::Pending);
        let remote = t.remote.lock().unwrap();
        assert!(remote.sends.iter().all(|s| s == &remote.sends[0]));
        assert_eq!(remote.max_seq_calls, remote.probes);
        assert_eq!(
            t.durable.lock().unwrap().as_ref().unwrap().candidates.len(),
            1
        );
    }
}

#[tokio::test]
async fn witnessed_foreign_open_stops_after_one_durable_send() {
    for open in [false, true] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let r = record();
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .extend((0..8).map(|_| Plan::Wire(wire_open(&r, open))));
        for invocation in 0..2 {
            let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
                .await
                .unwrap();
            assert_eq!(out.outcome, PublicationOutcome::Pending);
            assert_eq!(
                out.diagnostic.as_deref(),
                Some("open entry under foreign occupancy: possible wedge, repaired out of band")
            );
            assert_eq!(t.remote.lock().unwrap().sends.len(), invocation + 1);
            let durable = t.durable.lock().unwrap().clone().unwrap();
            assert_eq!(durable.phase, Phase::Ready);
            assert_eq!(
                j.cuts,
                5 * (invocation + 1),
                "answer accounting and destination must save one successor"
            );
            assert_eq!(
                durable.generation,
                r.generation + 5 * u64::try_from(invocation + 1).unwrap()
            );
            assert_eq!(
                durable.last_response.as_ref().unwrap().attempt,
                durable.candidates[0].evidence.started
            );
            assert_eq!(
                durable.last_response.as_ref().unwrap().answer,
                authority_answer::encode(wire_open(&r, open)).unwrap()
            );
            assert!(durable.candidates[0].evidence.decision_seen);
            assert_eq!(durable.candidates[0].root, r.candidates[0].root);
            assert!(delay.waits.is_empty());
        }
    }
}

#[tokio::test]
async fn bound_open_activates_history_before_the_next_exact_send() {
    let (t, mut j, _, _, _, mut delay) = setup();
    let mut r = record();
    let mut history = candidate(2, 1, root_bytes(2));
    history.role = Role::History;
    history.evidence.started = 3;
    history.evidence.answer(2, false, true).unwrap();
    r.candidates.push(history.clone());
    *t.durable.lock().unwrap() = Some(r.clone());
    foreign(&t, &r);
    t.remote.lock().unwrap().plans.extend([
        Plan::Wire(PublishAnswer::OperationBound(Bound::Open {
            position: Position {
                epoch: Epoch::from_bytes([1; 16]),
                entry_seq: 91,
            },
            candidate_id: history.id,
        })),
        Plan::LostReply,
    ]);
    let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
        .await
        .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::Pending);
    let remote = t.remote.lock().unwrap();
    assert_eq!(remote.sends[0].3, r.candidates[0].root);
    assert_eq!(remote.sends[1].3, history.root);
    assert_eq!(remote.attempts, vec![2, 4]);
    let durable = t.durable.lock().unwrap().clone().unwrap();
    let active = durable
        .candidates
        .iter()
        .find(|c| c.role == Role::Active)
        .unwrap();
    assert_eq!(active.evidence.last_answered_attempt, 2);
    assert!(active.evidence.decision_seen);
    assert_eq!(
        active.evidence.proved_no_write,
        history.evidence.proved_no_write
    );
}

#[tokio::test]
async fn forward_stale_releases_unanswered_current_twins_atomically() {
    let (t, mut j, _, _, _, mut delay) = setup();
    let mut r = record();
    r.candidates[0].evidence.started = 3;
    let mut twin = r.candidates[0].clone();
    twin.number = 2;
    twin.role = Role::History;
    r.candidates.push(twin);
    let mut other = candidate(3, 1, root_bytes(3));
    other.role = Role::History;
    r.candidates.push(other.clone());
    *t.durable.lock().unwrap() = Some(r.clone());
    let id = foreign(&t, &r);
    t.remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
            1, id,
        ))))));
    resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
        .await
        .unwrap();
    let durable = t.durable.lock().unwrap().clone().unwrap();
    assert_eq!(durable.candidates, vec![other]);
    assert_eq!(durable.current, r.current);
    assert_eq!(durable.frozen, r.frozen);
    assert_eq!(durable.phase, Phase::Rebase);
    assert!(durable.last_response.is_none());
    let bytes = retained_submission::encode(&durable).unwrap();
    assert_eq!(retained_submission::decode(&bytes).unwrap(), durable);
    assert_eq!(t.remote.lock().unwrap().sends.len(), 1);
}

#[tokio::test]
async fn stale_release_requires_a_witness_and_forward_consistent_head() {
    for head_case in 0..5 {
        let (t, mut j, _, _, _, mut delay) = setup();
        let mut r = record();
        r.candidates = vec![at_seq(1, 2)];
        *t.durable.lock().unwrap() = Some(r.clone());
        let id = if head_case == 4 {
            GrainId::of(b"foreign")
        } else {
            foreign(&t, &r)
        };
        let forward = (head_case == 3).then(|| linked_root(3, Some(id), 3));
        let head = Head::new(match head_case {
            0 => None,
            1 => Some((1, id)),
            2 => Some((2, GrainId::of(b"different occupant"))),
            3 => forward.as_ref().map(|bytes| (3, GrainId::of(bytes))),
            _ => Some((2, id)),
        });
        {
            let mut remote = t.remote.lock().unwrap();
            if let Some(bytes) = forward {
                remote.roots_on_send.push((3, bytes));
            }
            remote
                .plans
                .push_back(Plan::Wire(PublishAnswer::StaleBase(head)));
        }
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        let durable = t.durable.lock().unwrap().clone().unwrap();
        assert_eq!(
            durable.candidates.is_empty(),
            head_case == 3,
            "case={head_case}"
        );
        if head_case < 3 {
            assert_eq!(
                out.outcome,
                if head_case == 2 {
                    PublicationOutcome::BackendError
                } else {
                    PublicationOutcome::Unresolved
                }
            );
            if head_case == 1 {
                assert_eq!(
                    durable.phase,
                    Phase::Unresolved(Probe {
                        cycle: 5,
                        seq: 2,
                        reason: ProbeReason::ContentUnavailable,
                    }),
                    "case={head_case}"
                );
                assert!(durable.last_response.is_some(), "case={head_case}");
            } else {
                assert_eq!(durable.phase, Phase::Ready, "case={head_case}");
            }
            assert!(t.remote.lock().unwrap().max_seq_calls >= 1);
        }
    }
}

#[tokio::test]
async fn witnessed_lost_rejects_conflicting_occupants_before_owned_compare() {
    for owned in [false, true] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let mut r = record();
        let mut history = candidate(2, 1, root_bytes(2));
        history.role = Role::History;
        let occupant = if owned {
            history.id
        } else {
            GrainId::of(b"another foreign root")
        };
        r.candidates.push(history);
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::Reply(lost_answer(&r, 1, occupant)));
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        assert_eq!(
            out.outcome,
            PublicationOutcome::BackendError,
            "owned={owned}"
        );
        assert_eq!(
            out.diagnostic.as_deref(),
            Some("lost occupant contradicts foreign occupancy")
        );
        let durable = t.durable.lock().unwrap().clone().unwrap();
        assert_eq!(durable.phase, Phase::Ready);
        assert_eq!(durable.candidates.len(), r.candidates.len());
        assert!(durable.last_response.is_none());
        assert_eq!(t.remote.lock().unwrap().sends.len(), 1);
    }
}

#[tokio::test]
async fn witnessed_stale_rejects_conflicting_same_slot_heads_before_owned_compare() {
    for case in 0..4 {
        let (t, mut j, _, _, _, mut delay) = setup();
        let mut r = record();
        let mut history = at_seq(2, if case == 3 { 2 } else { 1 });
        history.role = Role::History;
        let foreign = foreign(&t, &r);
        if case == 3 {
            let mut doc = root::decode_root(&history.root).unwrap();
            doc.parent = Some(foreign);
            history.root = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
            history.id = GrainId::of(&history.root);
        }
        let head = match case {
            0 => (1, r.candidates[0].id),
            1 | 3 => (history.seq, history.id),
            _ => (1, GrainId::of(b"another foreign root")),
        };
        r.candidates.push(history.clone());
        *t.durable.lock().unwrap() = Some(r.clone());
        {
            let mut remote = t.remote.lock().unwrap();
            if case == 3 {
                remote.roots_on_send.push((2, history.root.clone()));
            }
            remote
                .plans
                .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some(head)))));
        }
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        let durable = t.durable.lock().unwrap().clone().unwrap();
        if case == 3 {
            assert!(matches!(out.outcome, PublicationOutcome::Landed(c) if c.id == history.id));
        } else {
            assert_eq!(out.outcome, PublicationOutcome::BackendError, "case={case}");
            assert_eq!(
                out.diagnostic.as_deref(),
                Some("stale head contradicts foreign occupancy")
            );
            assert_eq!(durable.phase, Phase::Ready);
            assert_eq!(durable.candidates.len(), r.candidates.len());
            assert!(durable.last_response.is_none());
        }
        assert_eq!(t.remote.lock().unwrap().sends.len(), 1);
    }
}

#[tokio::test]
async fn rejected_decision_answers_block_later_stale_release() {
    for case in 0..4 {
        let (t, mut j, _, _, _, mut delay) = setup();
        let r = record();
        let c = &r.candidates[0];
        let position = Position {
            epoch: Epoch::from_bytes(c.request.epoch),
            entry_seq: 91,
        };
        let unknown = OwnedCandidate::new(r.volume.as_str(), root_bytes(99).into()).unwrap();
        let owned = OwnedCandidate::new(r.volume.as_str(), c.root.clone().into()).unwrap();
        let req = PublishRequest::new(
            r.volume.as_str(),
            position.epoch,
            &c.request.operation,
            owned.clone(),
            vec![owned, unknown.clone()],
        )
        .unwrap();
        let receipt = Receipt {
            position,
            root_seq: c.seq,
            stored_id: if case < 2 { c.id } else { unknown.id() },
        };
        let (status, token, wire) = match case {
            0 => (
                200,
                None,
                PublishAnswer::Landed {
                    receipt,
                    head: None,
                },
            ),
            1 => (
                200,
                None,
                PublishAnswer::Lost {
                    position,
                    candidate_id: c.id,
                    occupant: unknown.id(),
                    head: None,
                },
            ),
            2 => (
                409,
                Some("operation-bound"),
                PublishAnswer::OperationBound(Bound::Open {
                    position,
                    candidate_id: unknown.id(),
                }),
            ),
            _ => (
                409,
                Some("operation-bound"),
                PublishAnswer::OperationBound(Bound::Landed(receipt)),
            ),
        };
        let answer = validate_publish_answer(
            &req,
            status,
            token,
            &authority_answer::encode(wire).unwrap(),
        )
        .unwrap();
        *t.durable.lock().unwrap() = Some(r.clone());
        let id = foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::Reply(answer));
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        assert_eq!(out.outcome, PublicationOutcome::BackendError, "case={case}");
        let durable = t.durable.lock().unwrap().clone().unwrap();
        assert!(durable.candidates[0].evidence.decision_seen, "case={case}");
        assert!(!durable.candidates[0].evidence.never_decided());
        assert_eq!(durable.candidates[0].evidence.last_answered_attempt, 2);
        assert_eq!(durable.candidates[0].evidence.proved_no_write, 0);
        t.remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                c.seq, id,
            ))))));
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        assert_eq!(
            out.outcome,
            PublicationOutcome::BackendError,
            "later stale case={case}"
        );
        assert_eq!(
            t.durable.lock().unwrap().as_ref().unwrap().candidates.len(),
            1
        );
    }
}

#[tokio::test]
async fn non_retry_stale_rebases_with_decided_candidate_as_uncertain_history() {
    let (t, mut j, key, keys, mut entropy, mut delay) = setup();
    let tree = j.tree();
    t.remote.lock().unwrap().plans.push_back(Plan::LostReply);
    begin_publication(
        parts(
            &t,
            &mut j,
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
    let mut r = t.durable.lock().unwrap().clone().unwrap();
    r.candidates[0].evidence.decision_seen = true;
    let original = r.candidates[0].clone();
    *t.durable.lock().unwrap() = Some(r.clone());
    t.remote.lock().unwrap().plans.extend([
        Plan::Wire(PublishAnswer::StaleBase(Head::new(None))),
        Plan::LostReply,
    ]);
    let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
        .await
        .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::Pending);
    assert!(out.uncertain);
    let durable = t.durable.lock().unwrap().clone().unwrap();
    let history = durable
        .candidates
        .iter()
        .find(|c| c.id == original.id)
        .unwrap();
    assert_eq!(history.role, Role::History);
    assert!(history.evidence.decision_seen);
    assert_eq!(history.root, original.root);
    assert_eq!(durable.current, r.current);
    let remote = t.remote.lock().unwrap();
    assert_ne!(remote.sends[1].3, remote.sends[2].3);
}

#[tokio::test]
async fn retry_stale_rejects_prior_decision_evidence() {
    let (t, mut j, _, _, _, mut delay) = setup();
    let mut r = record();
    r.candidates[0].evidence.decision_seen = true;
    *t.durable.lock().unwrap() = Some(r.clone());
    let id = foreign(&t, &r);
    t.remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
            1, id,
        ))))));
    let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
        .await
        .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::BackendError);
    assert_eq!(
        out.diagnostic.as_deref(),
        Some("stale answer contradicts decision evidence")
    );
    let durable = t.durable.lock().unwrap().clone().unwrap();
    assert_eq!(durable.phase, Phase::Ready);
    assert_eq!(durable.candidates.len(), 1);
    assert!(durable.candidates[0].evidence.decision_seen);
}

#[tokio::test]
async fn exclusion_matrix_keeps_earlier_uncertainty_without_stale_proof() {
    let r = record();
    for plan in [
        Plan::Reply(PublishResponse::Refused(crate::PublishRefusal::NotEnrolled)),
        Plan::Reply(PublishResponse::RateLimited),
        Plan::Reply(PublishResponse::ServiceUnavailable(
            ServiceReason::EnrollmentUnavailable,
        )),
        Plan::Reply(PublishResponse::ServiceUnavailable(
            ServiceReason::Unavailable,
        )),
        Plan::Reply(PublishResponse::Internal),
        Plan::Wire(PublishAnswer::NotDecided {
            position: Position {
                epoch: Epoch::from_bytes([1; 16]),
                entry_seq: 91,
            },
            candidate_id: r.candidates[0].id,
        }),
        Plan::Wire(PublishAnswer::VolumeDamaged),
        mismatch(2),
        Plan::Invalid,
        Plan::LostReply,
    ] {
        let (t, mut j, _, _, _, mut delay) = setup();
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        t.remote.lock().unwrap().fail_probe_at = Some(2);
        t.remote
            .lock()
            .unwrap()
            .plans
            .extend([plan, Plan::LostReply]);
        resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        let durable = t.durable.lock().unwrap().clone().unwrap();
        assert!(
            durable
                .candidates
                .iter()
                .any(|c| c.id == r.candidates[0].id)
        );
        assert_eq!(durable.frozen, r.frozen);
    }
}

#[tokio::test]
async fn decision_seen_or_direct_landed_contradictions_retain_the_tuple() {
    for twin in [false, true] {
        for stale in [false, true] {
            let (t, mut j, _, _, _, mut delay) = setup();
            let mut r = record();
            if stale {
                if twin {
                    let mut c = r.candidates[0].clone();
                    c.number = 2;
                    c.role = Role::History;
                    c.evidence.decision_seen = true;
                    r.candidates.push(c);
                } else {
                    r.candidates[0].evidence.decision_seen = true;
                }
            }
            *t.durable.lock().unwrap() = Some(r.clone());
            let id = foreign(&t, &r);
            t.remote
                .lock()
                .unwrap()
                .plans
                .push_back(Plan::Wire(if stale {
                    PublishAnswer::StaleBase(Head::new(Some((1, id))))
                } else {
                    PublishAnswer::Landed {
                        receipt: Receipt {
                            position: Position {
                                epoch: Epoch::from_bytes([1; 16]),
                                entry_seq: 91,
                            },
                            root_seq: 1,
                            stored_id: r.candidates[0].id,
                        },
                        head: None,
                    }
                }));
            let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
                .await
                .unwrap();
            assert_eq!(out.outcome, PublicationOutcome::BackendError);
            let durable = t.durable.lock().unwrap().clone().unwrap();
            assert_eq!(durable.candidates.len(), r.candidates.len());
            assert_eq!(durable.phase, Phase::Ready);
            assert_eq!(durable.candidates[0].evidence.proved_no_write, 0);
            assert!(durable.last_response.is_none());
        }
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one row pins every foreign-witness transition and the shared retry cadence"
)]
async fn verified_foreign_occupancy_keeps_live_retry_contracts() {
    let mut cases = 0;
    {
        let (t, mut j, key, keys, mut entropy, mut delay) = setup();
        let mut r = record();
        r.candidates[0].evidence.answer(1, true, false).unwrap();
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        let out = resume_exact_publication(
            parts(
                &t,
                &mut j,
                &key,
                &keys,
                &mut entropy,
                &FixedClock(2),
                &mut delay,
            ),
            &handle(&r),
            RecoveryIntent::Continue,
        )
        .await
        .unwrap();
        let durable = t.durable.lock().unwrap().clone().unwrap();
        assert_eq!(
            (
                out.outcome,
                durable.candidates.len(),
                durable.phase,
                t.remote.lock().unwrap().sends.len(),
            ),
            (PublicationOutcome::Unresolved, 1, Phase::Rebase, 0),
            "never-decided foreign occupancy must rebase without a retry"
        );
        cases += 1;
    }
    {
        let (t, mut j, _, _, _, mut delay) = setup();
        let r = record();
        *t.durable.lock().unwrap() = Some(r.clone());
        let occupant = foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::Reply(lost_answer(&r, 1, occupant)));
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        let durable = t.durable.lock().unwrap().clone().unwrap();
        assert_eq!(
            (
                out.outcome,
                durable.candidates.len(),
                durable.phase,
                t.remote.lock().unwrap().sends.len(),
            ),
            (PublicationOutcome::Unresolved, 0, Phase::Rebase, 1),
            "possibly-written occupancy must retry once and matching Lost must prune/rebase"
        );
        cases += 1;
    }
    for open in [false, true] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let r = record();
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::Wire(wire_open(&r, open)));
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        assert_eq!(
            (
                out.outcome,
                out.diagnostic.as_deref(),
                t.durable.lock().unwrap().as_ref().unwrap().phase.clone(),
                t.remote.lock().unwrap().sends.len(),
            ),
            (
                PublicationOutcome::Pending,
                Some("open entry under foreign occupancy: possible wedge, repaired out of band"),
                Phase::Ready,
                1,
            ),
            "open={open}: Accepted/Open must keep the existing wedge ending"
        );
        cases += 1;
    }
    {
        let (t, mut j, _, _, _, mut delay) = setup();
        let r = record();
        let c = r.candidates[0].clone();
        *t.durable.lock().unwrap() = Some(r.clone());
        foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::Wire(PublishAnswer::Landed {
                receipt: Receipt {
                    position: Position {
                        epoch: Epoch::from_bytes(c.request.epoch),
                        entry_seq: 91,
                    },
                    root_seq: c.seq,
                    stored_id: c.id,
                },
                head: None,
            }));
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
            .await
            .unwrap();
        assert_eq!(
            (
                out.outcome,
                out.diagnostic.as_deref(),
                t.durable.lock().unwrap().as_ref().unwrap().phase.clone(),
                t.remote.lock().unwrap().sends.len(),
            ),
            (
                PublicationOutcome::BackendError,
                Some("landed receipt contradicts foreign occupancy"),
                Phase::Ready,
                1,
            )
        );
        cases += 1;
    }
    let (t, mut j, _, _, _, mut delay) = setup();
    let r = record();
    *t.durable.lock().unwrap() = Some(r.clone());
    foreign(&t, &r);
    t.remote
        .lock()
        .unwrap()
        .plans
        .extend((0..8).map(|_| Plan::Reply(PublishResponse::RateLimited)));
    let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay)
        .await
        .unwrap();
    assert_eq!(out.outcome, PublicationOutcome::Pending);
    let remote = t.remote.lock().unwrap();
    assert_eq!(remote.sends.len(), 8);
    assert_eq!(remote.probes, 8);
    assert!(remote.sends.iter().all(|s| s == &remote.sends[0]));
    assert_eq!(remote.attempts, (2..=9).collect::<Vec<_>>());
    assert_eq!(
        (
            remote.max_seq_calls,
            remote.meta_uploads,
            remote.bin_uploads
        ),
        (8, 0, 0)
    );
    assert_eq!(delay.waits.len(), 7);
    assert_eq!(delay.waits.last(), Some(&std::time::Duration::from_secs(5)));
    assert!(
        delay
            .waits
            .iter()
            .all(|d| *d <= std::time::Duration::from_secs(5))
    );
    cases += 1;
    assert_eq!(cases, 6);
}

#[tokio::test]
async fn retry_journal_failures_stop_before_further_work_and_keep_unsaved_release() {
    for cut in [2, 4, 5] {
        let (t, mut j, _, _, _, mut delay) = setup();
        let r = record();
        *t.durable.lock().unwrap() = Some(r.clone());
        let id = foreign(&t, &r);
        t.remote
            .lock()
            .unwrap()
            .plans
            .push_back(Plan::Wire(PublishAnswer::StaleBase(Head::new(Some((
                1, id,
            ))))));
        j.fail_at = Some(cut);
        let out = resume(&t, &mut j, &r, RecoveryIntent::Continue, &mut delay).await;
        assert!(matches!(out, Err(RecoveryError::Journal(_))));
        assert!(j.poisoned);
        let durable = t.durable.lock().unwrap().clone().unwrap();
        assert_eq!(
            durable.candidates,
            if cut == 5 {
                let mut c = r.candidates[0].clone();
                c.evidence.started = 2;
                vec![c]
            } else {
                r.candidates.clone()
            }
        );
        assert_eq!(t.remote.lock().unwrap().sends.len(), usize::from(cut == 5));
        assert_eq!(
            t.remote.lock().unwrap().max_seq_calls,
            usize::from(cut >= 4) + usize::from(cut == 5)
        );
    }
}

#[tokio::test]
async fn repeated_lost_and_undecided_races_release_without_catalogue_growth() {
    for accepted in [false, true] {
        let (t, mut j, key, keys, mut entropy, mut delay) = setup();
        let tree = j.tree();
        let rounds = MAX_CANDIDATES + 2;
        t.remote.lock().unwrap().plans.extend((0..rounds).map(|_| {
            if accepted {
                Plan::LostContestAndLose
            } else {
                Plan::StaleContestAndLose
            }
        }));
        let mut out = begin_publication(
            parts(
                &t,
                &mut j,
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
        let current = t.durable.lock().unwrap().as_ref().unwrap().current;
        for round in 0..rounds {
            assert_eq!(out.outcome, PublicationOutcome::Pending);
            let durable = t.durable.lock().unwrap().clone().unwrap();
            assert_eq!(durable.candidates.len(), 1, "round={round}");
            assert_eq!(durable.current, current);
            t.remote.lock().unwrap().plans.push_front(Plan::LostReply);
            let interrupted = resume(&t, &mut j, &durable, RecoveryIntent::Continue, &mut delay)
                .await
                .unwrap();
            assert_eq!(interrupted.outcome, PublicationOutcome::Pending);
            let retried = t.durable.lock().unwrap().clone().unwrap();
            assert_eq!(retried.candidates.len(), 1);
            assert_eq!(retried.candidates[0].root, durable.candidates[0].root);
            assert_eq!(retried.candidates[0].request, durable.candidates[0].request);
            assert_eq!(retried.candidates[0].evidence.started, 2);
            if round + 1 == rounds {
                t.remote.lock().unwrap().plans.push_back(Plan::Land);
            }
            out = resume_publication(
                parts(
                    &t,
                    &mut j,
                    &key,
                    &keys,
                    &mut entropy,
                    &FixedClock(i64::try_from(round + 2).unwrap()),
                    &mut delay,
                ),
                &out.handle,
                RecoveryIntent::Continue,
            )
            .await
            .unwrap();
        }
        assert!(matches!(out.outcome, PublicationOutcome::Landed(_)));
        assert_eq!(t.remote.lock().unwrap().sends.len(), rounds * 3 + 1);
    }
}
