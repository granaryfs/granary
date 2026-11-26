// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_core::retained_submission::{self as r, Phase, Probe, ProbeReason};
use proptest::prelude::*;

proptest! {
    #[test]
    fn rebased_submission_round_trips(seq in 2u64..=u64::MAX-2, manifest in any::<[u8;32]>(),
        exemptions in 0u16..=1024) {
        let mut value=r::decode(include_bytes!("../../granary-core/tests/vectors/retained-submission/ready.bin")).unwrap();
        value.unavailable_exemptions=exemptions;
        let candidate=&mut value.candidates[0];
        let mut doc=granary_core::root::decode_root(&candidate.root).unwrap();
        doc.seq=seq;
        doc.parent=Some(granary_core::hash::GrainId::of(b"candidate parent"));
        doc.manifest_root=granary_core::hash::GrainId::of(&manifest);
        candidate.number=2;
        candidate.seq=seq;
        candidate.root=granary_core::root::encode_root(&doc).unwrap();
        candidate.id=granary_core::hash::GrainId::of(&candidate.root);
        let bytes=r::encode(&value).unwrap();
        granary_core::testkit::retained_submission_decode_probe(&bytes);
        prop_assert_eq!(r::decode(&bytes),Ok(value));
        prop_assert_eq!(r::encode(&r::decode(&bytes).unwrap()).unwrap(),bytes);
    }
    #[test]
    fn retained_submission_round_trips(generation in 1..=u64::MAX, publication in any::<[u8;16]>(),
        epoch in any::<[u8;16]>(), operation in any::<[u8;16]>(), started in 1..=u64::MAX,
        context in prop::collection::vec(any::<u8>(),1..=255), phase in 1u8..=6,
        exemptions in 0u16..=1024) {
        let fixture=include_bytes!("../../granary-core/tests/vectors/retained-submission/ready.bin");
        let mut value=r::decode(fixture).unwrap();
        value.unavailable_exemptions=exemptions;
        value.generation=generation; value.publication_id=publication;
        value.scope.credential_context=context;
        let identity=r::RequestIdentity {epoch,operation};
        value.current=Some(identity);
        value.candidates[0].request=identity;
        value.candidates[0].evidence.started=started;
        value.phase=match phase {
            2=>Phase::AwaitingAnswer {candidate:1,attempt:started},
            3=>Phase::Rebase,
            4=> { value.current=None; value.candidates[0].role=r::Role::Retired; Phase::EpochRecovery{epoch:[5;16]} },
            5=>Phase::ProbeStarted(Probe{cycle:generation,seq:1,reason:ProbeReason::Started}),
            6=>Phase::Unresolved(Probe{cycle:generation,seq:1,reason:ProbeReason::Interrupted}),
            _=>Phase::Ready,
        };
        let bytes=r::encode(&value).unwrap();
        prop_assert_eq!(r::decode(&bytes),Ok(value));
        prop_assert_eq!(r::encode(&r::decode(&bytes).unwrap()).unwrap(),bytes);
    }
    #[test]
    fn retained_arbitrary_decode_is_canonical(bytes in prop::collection::vec(any::<u8>(),0..20000)) {
        granary_core::testkit::retained_submission_decode_probe(&bytes);
        if let Ok(value)=r::decode(&bytes) {
            let canonical=r::encode(&value).unwrap();
            if bytes.get(8..10) == Some(&[0, 1]) {
                prop_assert_eq!(value.unavailable_exemptions, 0);
                prop_assert_eq!(r::decode(&canonical),Ok(value));
            } else {
                prop_assert_eq!(canonical,bytes);
            }
        }
    }
}
