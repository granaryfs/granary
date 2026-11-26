// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The state machine alone: what each record does, what it refuses, and
//! that replay restores outcomes exactly as they were recorded.

use granary_core::hash::GrainId;

use super::*;
use crate::authority::tests::{attestation, candidate_id, decision, envelope, landed, lost, vol};

fn volume() -> granary_core::root::VolumeName {
    vol("vol-state")
}

const fn refused(seq: u64, rule: GrammarRule) -> ApplyError {
    ApplyError { seq, rule }
}

fn key(d: &Record) -> OperationKey {
    operation_key(d.body().identity())
}

/// A decision opens an entry and binds its operation; the attestation
/// marks the entry attested; landed closes it, and both the binding and
/// the recorded answer take the outcome.
#[test]
fn a_decision_attestation_and_landed_close_one_entry() {
    let d = decision(&volume(), 1, 1, 1, None, 0);
    let mut state = VolumeState::new(envelope(&volume(), 1));
    assert_eq!(state.owed_attestation(), Ok(None));
    state.apply(&d).unwrap();
    assert_eq!(state.owed_attestation(), Ok(Some(attestation(&d))));
    state.apply(&attestation(&d)).unwrap();
    assert_eq!(state.owed_attestation(), Ok(None));
    state.apply(&landed(&d)).unwrap();

    assert_eq!(state.open, None);
    assert_eq!(state.grammar.highest_seq(), 1);
    assert_eq!(
        state.bindings.get(&key(&d)),
        Some(&Binding {
            candidate_id: candidate_id(&d),
            seq: 1,
            root_seq: 1,
            outcome: Outcome::Landed,
        })
    );
    assert_eq!(
        state.recorded.get(d.body().identity()),
        Some(&Recorded {
            seq: 1,
            root_seq: 1,
            outcome: Outcome::Landed,
        })
    );
}

/// Replay restores a committed lost exactly as written: the state holds
/// no store to consult, and the outcome is the record's.
#[test]
fn replay_restores_a_lost_outcome_as_recorded() {
    let d = decision(&volume(), 1, 1, 1, None, 0);
    let occupant = GrainId::of(b"the occupant");
    let records = [d.clone(), attestation(&d), lost(&d, occupant)];
    let state = VolumeState::replay(envelope(&volume(), 1), &records).unwrap();
    assert_eq!(
        state.bindings.get(&key(&d)).map(|b| b.outcome),
        Some(Outcome::Lost { occupant })
    );
    assert_eq!(
        state.recorded.get(d.body().identity()),
        Some(&Recorded {
            seq: 1,
            root_seq: 1,
            outcome: Outcome::Lost { occupant },
        })
    );
    assert_eq!(state.open, None);
}

/// Every grammar break is refused, and a refused record changes nothing.
#[test]
fn a_record_out_of_grammar_is_refused_and_changes_nothing() {
    let v = volume();
    let d1 = decision(&v, 1, 1, 1, None, 0);
    let fresh = VolumeState::new(envelope(&v, 1));
    let mut open = fresh.clone();
    open.apply(&d1).unwrap();
    let mut attested = open.clone();
    attested.apply(&attestation(&d1)).unwrap();
    let mut landed_state = attested.clone();
    landed_state.apply(&landed(&d1)).unwrap();

    let other_bytes = RootBytes::new(b"other bytes".to_vec()).unwrap();
    let wrong_final = Record::new(
        1,
        RecordBody::Attestation {
            identity: d1.body().identity().clone(),
            stored_id: GrainId::of(other_bytes.as_bytes()),
            final_root: other_bytes,
        },
    )
    .unwrap();

    let cases: Vec<(&VolumeState, Record, ApplyError)> = vec![
        (
            &fresh,
            decision(&v, 2, 1, 1, None, 0),
            refused(2, GrammarRule::Rule1SequencePosition),
        ),
        (
            &fresh,
            attestation(&d1),
            refused(1, GrammarRule::Rule3AttestationPreconditions),
        ),
        (
            &fresh,
            landed(&d1),
            refused(1, GrammarRule::Rule4OutcomePreconditions),
        ),
        (
            &open,
            decision(&v, 2, 2, 2, Some(candidate_id(&d1)), 0),
            refused(2, GrammarRule::Rule2ConcurrentEntry),
        ),
        (
            &open,
            landed(&d1),
            refused(1, GrammarRule::Rule4OutcomePreconditions),
        ),
        (
            &open,
            wrong_final,
            refused(1, GrammarRule::Rule5IdentityMismatch),
        ),
        (
            &open,
            attestation(&decision(&v, 1, 3, 1, None, 2)),
            refused(1, GrammarRule::Rule5IdentityMismatch),
        ),
        (
            &attested,
            attestation(&d1),
            refused(1, GrammarRule::Rule3AttestationPreconditions),
        ),
        (
            &attested,
            lost(&d1, candidate_id(&d1)),
            refused(1, GrammarRule::Rule5IdentityMismatch),
        ),
        (
            &landed_state,
            decision(&v, 2, 1, 2, Some(candidate_id(&d1)), 1),
            refused(2, GrammarRule::Rule6LandedOperationReplay),
        ),
    ];
    for (n, (state, record, expected)) in cases.into_iter().enumerate() {
        let mut after = state.clone();
        assert_eq!(after.apply(&record), Err(expected), "case {n}");
        assert_eq!(&after, state, "case {n}: a refused record changes nothing");
    }

    // A submission identity decided once is never decided again, even
    // after its candidate lost.
    let mut lost_once = attested;
    lost_once.apply(&lost(&d1, GrainId::of(b"x"))).unwrap();
    let again = Record::new(2, d1.body().clone()).unwrap();
    assert_eq!(
        lost_once.apply(&again),
        Err(refused(2, GrammarRule::Rule7DuplicateAnswer))
    );
}
