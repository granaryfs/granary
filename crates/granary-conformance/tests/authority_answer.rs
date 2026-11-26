// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Wire properties live outside core so the generator's I/O dependencies
//! cannot enter core's pure dependency closure.
use granary_core::authlog::Epoch;
use granary_core::authority_answer::*;
use granary_core::hash::GrainId;
use proptest::prelude::*;

proptest! {
    #[test]
    fn publish_answer_round_trip(epoch in any::<[u8;16]>(), entry_seq in 1..=u64::MAX,
        root_seq in 1..u64::MAX, seed in any::<[u8;32]>(), present in any::<bool>(), empty in any::<bool>()) {
        let id=GrainId::of(&seed);
        let occupant=GrainId::of(&[seed.as_slice(), &[1]].concat());
        let position=Position {epoch:Epoch::from_bytes(epoch),entry_seq};
        let receipt=Receipt {position,root_seq,stored_id:id};
        let h=Head::new(if empty {None} else {Some((root_seq,id))});
        let head=present.then_some(h);
        for value in [
            PublishAnswer::Landed {receipt,head},
            PublishAnswer::Lost {position,candidate_id:id,occupant,head},
            PublishAnswer::Accepted {position,candidate_id:id},
            PublishAnswer::Open {position,candidate_id:id},
            PublishAnswer::StaleBase(h),
            PublishAnswer::OperationBound(Bound::Open {position,candidate_id:id}),
            PublishAnswer::OperationBound(Bound::Landed(receipt)),
            PublishAnswer::NotDecided {position,candidate_id:id},
            PublishAnswer::EpochMismatch {epoch:position.epoch,head},
            PublishAnswer::VolumeDamaged,
        ] {
            let bytes=encode(value).unwrap();
            prop_assert_eq!(decode(&bytes),Ok(value));
            prop_assert_eq!(encode(decode(&bytes).unwrap()).unwrap(),bytes);
        }
    }
    #[test]
    fn volume_status_round_trip(epoch in any::<[u8;16]>(), entry_seq in 1..=u64::MAX,
        root_seq in 1..u64::MAX, seed in any::<[u8;32]>(), present in any::<bool>(),
        empty in any::<bool>(), opened in any::<bool>()) {
        let id = GrainId::of(&seed);
        let value = VolumeStatus {
            epoch: Epoch::from_bytes(epoch),
            head: present.then(|| Head::new(if empty { None } else { Some((root_seq,id)) })),
            open: opened.then_some(OpenPosition { entry_seq, candidate_id: id }),
        };
        let bytes = encode_status(value).unwrap();
        prop_assert!(bytes.len() <= STATUS_V1_MAX);
        prop_assert_eq!(decode_status(&bytes), Ok(value));
        prop_assert_eq!(encode_status(decode_status(&bytes).unwrap()).unwrap(), bytes);
    }
    #[test]
    fn volume_status_decode_is_canonical(bytes in prop::collection::vec(any::<u8>(),0..200)) {
        if let Ok(value)=decode_status(&bytes) { prop_assert_eq!(encode_status(value).unwrap(),bytes); }
    }
    #[test]
    fn publish_answer_decode_is_canonical(bytes in prop::collection::vec(any::<u8>(),0..200)) {
        if let Ok(value)=decode(&bytes) { prop_assert_eq!(encode(value).unwrap(),bytes); }
    }
}
