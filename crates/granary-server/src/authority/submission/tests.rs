// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule 2's well-formedness, and the report's age and flag, alone.

use std::time::Duration;

use granary_core::authlog::{EPOCH_LEN, Envelope};

use super::*;
use crate::authority::tests::{good_root, publisher, signed_root, stranger, vol};

fn volume() -> VolumeName {
    vol("vol-submit")
}

fn keys() -> TrustedKeys {
    TrustedKeys::new([*publisher().public_key()]).unwrap()
}

fn sub(candidate: Vec<u8>) -> Submission {
    Submission::new(
        Tenant::new(vec![1]).unwrap(),
        Principal::new(vec![2]).unwrap(),
        volume(),
        state().envelope().epoch(),
        Operation::new(vec![3]).unwrap(),
        candidate,
    )
}

fn state() -> VolumeState {
    VolumeState::new(Envelope::new(volume(), Epoch::from_bytes([1; EPOCH_LEN])))
}

fn early(candidate: Vec<u8>) -> Early {
    rules_1_to_4(Some(&state()), &keys(), &sub(candidate))
}

/// A well-formed candidate passes rule 2 with its seq, its parent, its
/// bytes and its identity.
#[test]
fn a_publisher_signed_root_of_the_volume_is_well_formed() {
    let parent = Some(GrainId::of(b"parent"));
    let bytes = good_root(&volume(), 5, parent, 1);
    let Early::Eligible(candidate) = early(bytes.clone()) else {
        panic!("not eligible");
    };
    assert_eq!((candidate.seq, candidate.parent), (5, parent));
    assert_eq!(candidate.candidate.as_bytes(), bytes.as_slice());
    assert_eq!(candidate.identity.candidate_id(), GrainId::of(&bytes));
}

/// Undecodable bytes, another volume, a stranger's signature, a bad
/// signature from the publisher beside a good one from a stranger, and
/// the seqs past the bound are all rule 2's.
#[test]
fn rule_2_refuses_what_is_not_well_formed() {
    let mut bad_sig = good_root(&volume(), 1, None, 2);
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0x80;
    let refused = |bytes: Vec<u8>| match early(bytes) {
        Early::Answer(Answer::InvalidCandidate(invalid)) => invalid,
        other => panic!("not refused by rule 2: {other:?}"),
    };
    assert!(matches!(
        refused(b"junk".to_vec()),
        InvalidCandidate::Root(HeadError::Identity(_))
    ));
    assert!(matches!(
        refused(good_root(&vol("vol-other"), 1, None, 1)),
        InvalidCandidate::Root(HeadError::Identity(_))
    ));
    assert_eq!(
        refused(signed_root(&volume(), 1, None, 1, &[&stranger()])),
        InvalidCandidate::Root(HeadError::NoTrustedSlot)
    );
    assert!(matches!(
        refused(bad_sig),
        InvalidCandidate::Root(HeadError::BadSignature { .. })
    ));
    let p = Some(GrainId::of(b"p"));
    assert_eq!(
        refused(good_root(&volume(), u64::MAX - 1, p, 1)),
        InvalidCandidate::SeqOutOfRange { seq: u64::MAX - 1 }
    );
    assert!(matches!(
        early(good_root(&volume(), u64::MAX - 2, p, 1)),
        Early::Eligible(_)
    ));
}

/// Rule 1 answers before rule 2 looks at the candidate.
#[test]
fn no_log_answers_before_the_candidate_is_read() {
    assert_eq!(
        rules_1_to_4(None, &keys(), &sub(b"junk".to_vec())),
        Early::Answer(Answer::NoLog)
    );
}

// ------------------------------------------------ the report's age and flag

fn at(secs: i64, nanos: u32) -> Timestamp {
    Timestamp { secs, nanos }
}

/// The age is the exact difference, a sub-second borrow included, at the
/// extremes of the seconds range too; equal readings are age zero.
#[test]
fn age_is_the_exact_difference() {
    assert_eq!(age(at(10, 0), at(10, 0)), Some(Duration::ZERO));
    assert_eq!(age(at(12, 500), at(10, 200)), Some(Duration::new(2, 300)));
    // A borrow: 10.1s - 9.9s is 0.2s, not 1.2s.
    assert_eq!(
        age(at(10, 100_000_000), at(9, 900_000_000)),
        Some(Duration::from_millis(200))
    );
    // A borrow within one second's worth of difference: 1ns.
    assert_eq!(
        age(at(10, 0), at(9, 999_999_999)),
        Some(Duration::from_nanos(1))
    );
    // The widest difference two readings can have, with no overflow.
    assert_eq!(
        age(at(i64::MAX, 0), at(i64::MIN, 0)),
        Some(Duration::new(u64::MAX, 0))
    );
    // The same, with a borrow.
    assert_eq!(
        age(at(i64::MAX, 0), at(i64::MIN, 1)),
        Some(Duration::new(u64::MAX - 1, 999_999_999))
    );
}

/// A clock behind the recorded reading, by a nanosecond or by seconds,
/// and a reading that is not a valid timestamp, are unknown, never zero.
#[test]
fn an_age_behind_or_from_an_invalid_reading_is_unknown() {
    assert_eq!(age(at(10, 0), at(10, 1)), None);
    assert_eq!(age(at(9, 999_999_999), at(10, 0)), None);
    assert_eq!(age(at(i64::MIN, 0), at(i64::MAX, 0)), None);
    assert_eq!(age(at(11, 1_200_000_000), at(10, 0)), None);
    assert_eq!(age(at(10, 1_500_000_000), at(11, 0)), None);
}

/// Unknown is always clock behind; a known age is flagged only when it is
/// strictly greater than the bound.
#[test]
fn the_flag_follows_the_age_and_the_bound() {
    let bound = Duration::from_secs(30);
    assert_eq!(flag(None, bound), Some(StuckFlag::ClockBehind));
    assert_eq!(flag(Some(bound), bound), None);
    assert_eq!(
        flag(Some(bound + Duration::from_nanos(1)), bound),
        Some(StuckFlag::PastBound)
    );
    assert_eq!(flag(Some(Duration::ZERO), Duration::ZERO), None);
}
