// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_client::{OwnedCandidate, PublishRequest};
use granary_core::retained_submission::{
    Candidate, Evidence, FrozenIntent, RequestIdentity, Role, Scope,
};
use granary_core::root::{self, RootDoc, RootSig};

fn fixture() -> Submission {
    let key = crate::scenario::key();
    let mut root = RootDoc {
        volume: crate::scenario::volume(),
        seq: 1,
        parent: None,
        writer_uuid: [1; 16],
        epoch: 1,
        timestamp: crate::scenario::now(),
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(b"tree"),
        binmap_index: GrainId::of(b"index"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![],
    };
    root.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&root).unwrap()),
    });
    let bytes = root::encode_root(&root).unwrap();
    let identity = RequestIdentity {
        epoch: [1; 16],
        operation: [2; 16],
    };
    Submission {
        generation: 1,
        publication_id: [3; 16],
        scope: Scope {
            authority_base: b"https://sim".to_vec(),
            pins: vec![],
            credential_context: b"writer".to_vec(),
        },
        volume: root.volume,
        frozen: FrozenIntent {
            writer_identity: [4; 16],
            min_prefix_bits: 0,
            initial_root: bytes.clone(),
        },
        current: Some(identity),
        candidates: vec![Candidate {
            number: 1,
            role: Role::Active,
            request: identity,
            seq: 1,
            id: GrainId::of(&bytes),
            root: bytes,
            evidence: Evidence {
                started: 1,
                ..Evidence::default()
            },
        }],
        phase: Phase::AwaitingAnswer {
            candidate: 1,
            attempt: 1,
        },
        last_response: None,
        unavailable_exemptions: 0,
    }
}
fn request(record: &Submission) -> PublishRequest {
    let c = record.candidates.first().unwrap();
    let owned = OwnedCandidate::new(record.volume.as_str(), c.root.clone().into()).unwrap();
    PublishRequest::new(
        record.volume.as_str(),
        granary_core::authlog::Epoch::from_bytes(c.request.epoch),
        &c.request.operation,
        owned.clone(),
        vec![owned],
    )
    .unwrap()
}
#[test]
fn oracle_refuses_send_without_durable_exact_tuple_or_new_attempt() {
    let r = fixture();
    let req = request(&r);
    let mut oracle = Oracle::default();
    assert!(oracle.send(None, &req).is_some());
    let mut wrong = r.clone();
    wrong.phase = Phase::Ready;
    assert!(oracle.send(Some(&wrong), &req).is_some());
    let mut wrong = r.clone();
    wrong.candidates.first_mut().unwrap().request.operation = [9; 16];
    assert!(oracle.send(Some(&wrong), &req).is_some());
    assert!(oracle.send(Some(&r), &req).is_none());
    assert!(oracle.send(Some(&r), &req).is_some());
}
#[test]
fn oracle_refuses_send_past_unresolved_retired_candidate() {
    let mut r = fixture();
    let mut retired = r.candidates.first().unwrap().clone();
    retired.number = 2;
    retired.role = Role::Retired;
    retired.seq = 0;
    r.candidates.push(retired);
    assert!(Oracle::default().send(Some(&r), &request(&r)).is_some());
}
#[test]
fn oracle_refutes_premature_release_false_completion_and_cross_epoch_reuse() {
    let mut oracle = Oracle::default();
    let mut r = fixture();
    let roots = BTreeMap::new();
    assert!(oracle.check(Some(&r), &roots).is_empty());
    let c = r.candidates.pop().unwrap();
    assert!(
        oracle
            .check(Some(&r), &roots)
            .iter()
            .any(|e| e.contains("released"))
    );
    r.candidates.push(c.clone());
    r.phase = Phase::Complete(granary_core::retained_submission::Completion {
        seq: c.seq,
        id: c.id,
        root: c.root,
        receipt: None,
    });
    assert!(
        oracle
            .check(Some(&r), &roots)
            .iter()
            .any(|e| e.contains("completion"))
    );
    r.current.as_mut().unwrap().epoch = [9; 16];
    assert!(
        oracle
            .check(Some(&r), &roots)
            .iter()
            .any(|e| e.contains("crosses epochs"))
    );
}
#[test]
fn oracle_requires_new_explicit_invocation_after_failed_probe() {
    let mut oracle = Oracle::default();
    assert!(oracle.probe(1, false, true, 1, false).is_none());
    assert!(oracle.probe(1, false, false, 2, false).is_some());
    assert!(oracle.probe(1, false, false, 1, true).is_some());
    assert!(oracle.probe(1, false, false, 2, true).is_none());
}

#[test]
fn oracle_requires_actual_own_completion_and_single_landing() {
    let mut oracle = Oracle::default();
    let mut r = fixture();
    let mut roots = BTreeMap::new();
    let c = r.candidates.first().unwrap().clone();
    roots.insert((r.volume.as_str().to_owned(), c.seq), c.root.clone());
    assert!(oracle.check(Some(&r), &roots).is_empty());
    let foreign = b"actual foreign bytes".to_vec();
    roots.insert((r.volume.as_str().to_owned(), 2), foreign.clone());
    r.phase = Phase::Complete(granary_core::retained_submission::Completion {
        seq: 2,
        id: GrainId::of(&foreign),
        root: foreign,
        receipt: None,
    });
    assert!(
        oracle
            .check(Some(&r), &roots)
            .iter()
            .any(|e| e.contains("completion"))
    );
    let mut other = c;
    other.number = 2;
    other.seq = 2;
    other.id = GrainId::of(b"second own root");
    other.root = b"second own root".to_vec();
    roots.insert(
        (r.volume.as_str().to_owned(), other.seq),
        other.root.clone(),
    );
    r.candidates.push(other);
    r.phase = Phase::Ready;
    assert!(
        oracle
            .check(Some(&r), &roots)
            .iter()
            .any(|e| e.contains("more than one landing"))
    );
}

#[test]
fn oracle_separates_evidence_and_attempts_when_numbers_are_reused() {
    let mut oracle = Oracle::default();
    let old = fixture();
    let roots = BTreeMap::new();
    assert!(oracle.check(Some(&old), &roots).is_empty());
    assert!(oracle.send(Some(&old), &request(&old)).is_none());
    oracle.no_write(&old, 1);
    let mut r = old;
    let identity = RequestIdentity {
        epoch: [9; 16],
        operation: [8; 16],
    };
    r.current = Some(identity);
    r.candidates.first_mut().unwrap().request = identity;
    assert!(oracle.check(Some(&r), &roots).is_empty());
    assert!(oracle.send(Some(&r), &request(&r)).is_none());
    r.candidates.clear();
    r.current = None;
    r.phase = Phase::EpochRecovery { epoch: [10; 16] };
    assert!(
        oracle
            .check(Some(&r), &roots)
            .iter()
            .any(|e| e.contains("released")),
        "the prior identity's no-write proof cannot close this attempt"
    );
}

fn checked_lost(req: &PublishRequest) -> granary_client::CheckedLost {
    use granary_core::authority_answer::{self, Position, PublishAnswer};
    let response = granary_client::validate_publish_answer(
        req,
        200,
        None,
        &authority_answer::encode(PublishAnswer::Lost {
            position: Position {
                epoch: req.epoch(),
                entry_seq: 91,
            },
            candidate_id: req.candidate().id(),
            occupant: GrainId::of(b"foreign occupant"),
            head: None,
        })
        .unwrap(),
    )
    .unwrap();
    let granary_client::PublishResponse::Lost(lost) = response else {
        panic!("not lost")
    };
    lost
}

#[test]
fn oracle_accepts_checked_lost_release_of_current_twins_without_an_occupancy_probe() {
    let mut oracle = Oracle::default();
    let mut r = fixture();
    let mut twin = r.candidates.first().unwrap().clone();
    twin.number = 2;
    twin.role = Role::History;
    r.candidates.push(twin);
    let roots = BTreeMap::new();
    assert!(oracle.check(Some(&r), &roots).is_empty());
    let req = request(&r);
    oracle.decided(req.candidate().id());
    let mut released = r.clone();
    released.candidates.clear();
    released.phase = Phase::Rebase;
    assert_eq!(
        oracle
            .check(Some(&released), &roots)
            .iter()
            .filter(|e| e.contains("released"))
            .count(),
        2,
        "a decision alone cannot authorize either twin's release"
    );
    oracle.checked_lost(&r, 1, &req, checked_lost(&req));
    r.candidates.clear();
    r.phase = Phase::Rebase;
    assert!(oracle.check(Some(&r), &roots).is_empty());
}

#[test]
fn oracle_lost_proof_is_specific_to_catalogued_publication_request_and_bytes() {
    for field in 0..4 {
        let mut oracle = Oracle::default();
        let old = fixture();
        let req = request(&old);
        let roots = BTreeMap::new();
        assert!(oracle.check(Some(&old), &roots).is_empty());
        oracle.decided(req.candidate().id());
        oracle.checked_lost(&old, 1, &req, checked_lost(&req));
        let mut r = old;
        let c = r.candidates.first_mut().unwrap();
        match field {
            0 => r.publication_id = [9; 16],
            1 => {
                c.request.epoch = [9; 16];
                c.request.operation = [8; 16];
            }
            2 => c.request.operation = [8; 16],
            _ => {
                let mut doc = root::decode_root(&c.root).unwrap();
                doc.timestamp.secs += 1;
                let key = crate::scenario::key();
                doc.sigs.clear();
                doc.sigs.push(RootSig {
                    key_id: key.key_id(),
                    sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
                });
                c.root = root::encode_root(&doc).unwrap();
                c.id = GrainId::of(&c.root);
            }
        }
        r.current = Some(c.request);
        r.phase = Phase::AwaitingAnswer {
            candidate: c.number,
            attempt: 1,
        };
        assert!(oracle.check(Some(&r), &roots).is_empty(), "field={field}");
        assert!(
            oracle.send(Some(&r), &request(&r)).is_none(),
            "field={field}"
        );
        r.candidates.clear();
        r.phase = Phase::Rebase;
        assert!(
            oracle
                .check(Some(&r), &roots)
                .iter()
                .any(|e| e.contains("released")),
            "field={field}: an old lost proof must not authorize this release"
        );
    }
}

#[test]
fn oracle_lost_proof_does_not_release_an_identical_retired_twin() {
    for same_identity in [false, true] {
        let mut oracle = Oracle::default();
        let mut r = fixture();
        let mut twin = r.candidates.first().unwrap().clone();
        twin.number = 2;
        twin.role = Role::Retired;
        if !same_identity {
            twin.request = RequestIdentity {
                epoch: [8; 16],
                operation: [9; 16],
            };
        }
        // The same-identity case isolates the role guard in a synthetic record.
        r.candidates.push(twin.clone());
        let roots = BTreeMap::new();
        assert!(oracle.check(Some(&r), &roots).is_empty());
        let req = request(&r);
        oracle.decided(req.candidate().id());
        oracle.checked_lost(&r, 1, &req, checked_lost(&req));
        r.candidates = vec![twin];
        r.phase = Phase::Rebase;
        assert!(oracle.check(Some(&r), &roots).is_empty());
        r.candidates.clear();
        assert!(
            oracle
                .check(Some(&r), &roots)
                .iter()
                .any(|e| e.contains("released")),
            "same_identity={same_identity}"
        );
    }
}

#[test]
fn oracle_lost_proof_requires_the_delivered_request_tuple() {
    for field in 0..4 {
        let mut oracle = Oracle::default();
        let original = fixture();
        let req = request(&original);
        let lost = checked_lost(&req);
        let mut r = original;
        let c = r.candidates.first_mut().unwrap();
        match field {
            0 => c.request.operation = [9; 16],
            1 => {
                c.request.epoch = [9; 16];
            }
            2 => c.id = GrainId::of(b"different bytes"),
            _ => c.number = 2,
        }
        r.current = Some(c.request);
        let roots = BTreeMap::new();
        assert!(oracle.check(Some(&r), &roots).is_empty());
        oracle.checked_lost(&r, 1, &req, lost);
        r.candidates.clear();
        r.phase = Phase::Rebase;
        assert!(
            oracle
                .check(Some(&r), &roots)
                .iter()
                .any(|e| e.contains("released")),
            "field={field}"
        );
    }
}

#[test]
fn oracle_occupancy_alone_cannot_release_current_open_entries() {
    for role in [Role::Active, Role::History, Role::Retired] {
        let mut oracle = Oracle::default();
        let mut r = fixture();
        r.candidates[0].role = role;
        let req = request(&r);
        oracle.decided_request(&req);
        let roots = BTreeMap::new();
        assert!(oracle.check(Some(&r), &roots).is_empty());
        oracle.probe(1, true, false, 1, false);
        r.candidates.clear();
        r.phase = Phase::Rebase;
        let errors = oracle.check(Some(&r), &roots);
        assert_eq!(errors.is_empty(), role == Role::Retired, "role={role:?}");
    }
}

#[test]
fn oracle_forward_stale_release_requires_independent_absence_progress_and_delivery() {
    use granary_core::authority_answer::Head;
    for case in 0..10 {
        let mut oracle = Oracle::default();
        let mut r = fixture();
        let req = request(&r);
        let foreign = GrainId::of(b"foreign");
        let roots = BTreeMap::new();
        assert!(oracle.check(Some(&r), &roots).is_empty());
        if case != 1 {
            oracle.occupancy(&r, 1, foreign, 1);
        }
        if case == 9 {
            oracle.begin_invocation(2);
        }
        assert!(oracle.send(Some(&r), &req).is_none());
        if case == 2 {
            oracle.decided_request(&req);
        }
        let head = Head::new(match case {
            3 => None,
            4 => Some((0, foreign)),
            5 => Some((1, GrainId::of(b"different"))),
            _ => Some((1, foreign)),
        });
        if case != 6 {
            oracle.forward_stale(&r, &req, head, case != 2 && case != 8);
        }
        if case == 7 {
            oracle.decided_request(&req);
        }
        // Exact release permission is independent of catalogue numbering.
        r.candidates[0].number = 9;
        assert!(oracle.check(Some(&r), &roots).is_empty() || case != 0);
        r.candidates.clear();
        r.phase = Phase::Rebase;
        let errors = oracle.check(Some(&r), &roots);
        assert_eq!(errors.is_empty(), case == 0, "case={case}: {errors:?}");
    }
}

#[test]
fn oracle_rejects_retired_send_on_either_side_of_the_target() {
    for seq in [0, 2] {
        let mut r = fixture();
        let mut retired = r.candidates[0].clone();
        retired.number = 2;
        retired.role = Role::Retired;
        retired.seq = seq;
        r.candidates.push(retired);
        assert!(Oracle::default().send(Some(&r), &request(&r)).is_some());
    }
}
