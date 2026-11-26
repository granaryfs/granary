// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::sync::CommitWalk;
use granary_core::{
    grainsource::GrainSourceError,
    root::{self, RootDoc, RootSig, VolumeName},
    sheaf::Timestamp,
};
use granary_store::crypto::SigningKey;
use std::collections::BTreeMap;

mod diff;

#[derive(Default)]
struct Roots(BTreeMap<GrainId, Vec<u8>>);
impl GrainSource for Roots {
    fn has(&self, id: &GrainId) -> bool {
        self.0.contains_key(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }
}

fn signed(seq: u64, parent: Option<GrainId>, writer: u8, key: &SigningKey) -> Vec<u8> {
    let mut doc = RootDoc {
        volume: VolumeName::new("rebase-test".to_owned()).unwrap(),
        seq,
        parent,
        writer_uuid: [writer; 16],
        epoch: 1,
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(&[writer, u8::try_from(seq).unwrap()]),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![],
    };
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    root::encode_root(&doc).unwrap()
}

fn head(bytes: Vec<u8>, keys: &TrustedKeys) -> VerifiedBase {
    let manifest = root::decode_root(&bytes).unwrap().manifest_root;
    VerifiedBase::landed(bytes, "rebase-test", keys, &CommitWalk::new(manifest)).unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "named recovery cases share one signed ancestry fixture"
)]
fn selected_root_requires_ancestry_or_equal_manifest() {
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let parent = signed(1, None, 7, &key);
    let parent_id = GrainId::of(&parent);
    let prepared_bytes = signed(2, Some(parent_id), 7, &key);
    let prepared = OwnedCandidate::new("rebase-test", prepared_bytes.clone().into()).unwrap();
    let remote = signed(2, Some(parent_id), 8, &key);
    let remote_id = GrainId::of(&remote);
    let later = signed(3, Some(remote_id), 7, &key);
    let later_id = GrainId::of(&later);
    let roots = Roots(BTreeMap::from([
        (parent_id, parent.clone()),
        (remote_id, remote.clone()),
        (prepared.id(), prepared_bytes.clone()),
    ]));
    // A store-stable writer alone does not prove publication of durable work.
    let cases = [
        (
            "head equals parent: empty chain publishes prepared unchanged without merge",
            parent.clone(),
            HeadRelation::NeedsRebase { chain: vec![] },
        ),
        (
            "parent is ancestor",
            remote,
            HeadRelation::NeedsRebase {
                chain: vec![(2, remote_id)],
            },
        ),
        (
            "matching writer with a different tree needs rebase",
            later,
            HeadRelation::NeedsRebase {
                chain: vec![(3, later_id), (2, remote_id)],
            },
        ),
        (
            "head equals prepared",
            prepared_bytes,
            HeadRelation::Subsumed {
                by_seq: 2,
                by_root: prepared.id(),
            },
        ),
        (
            "head descends from prepared",
            signed(3, Some(prepared.id()), 8, &key),
            HeadRelation::Subsumed {
                by_seq: 2,
                by_root: prepared.id(),
            },
        ),
        (
            "foreign parent",
            signed(2, Some(GrainId::of(b"foreign")), 8, &key),
            HeadRelation::Corrupt,
        ),
        (
            "writer match does not excuse missing parent",
            signed(2, Some(GrainId::of(b"foreign")), 7, &key),
            HeadRelation::Corrupt,
        ),
        (
            "same sequence is not ancestry: another root holds the parent's sequence",
            signed(1, None, 8, &key),
            HeadRelation::Stale,
        ),
        (
            "link skips a sequence",
            signed(3, Some(parent_id), 8, &key),
            HeadRelation::Corrupt,
        ),
    ];
    for (row, bytes, expected) in cases {
        assert_eq!(
            classify_head(&prepared, &head(bytes, &keys), &roots, &keys),
            expected,
            "{row}"
        );
    }
    let stale =
        OwnedCandidate::new("rebase-test", signed(3, Some(remote_id), 7, &key).into()).unwrap();
    assert_eq!(
        classify_head(&stale, &head(parent.clone(), &keys), &roots, &keys),
        HeadRelation::Stale,
        "parent is ahead of head"
    );
    assert_eq!(
        classify_head(
            &prepared,
            &head(signed(3, Some(remote_id), 7, &key), &keys),
            &Roots::default(),
            &keys
        ),
        HeadRelation::Corrupt,
        "missing link before a matching writer"
    );
    let mut corrupt = roots;
    corrupt.0.insert(parent_id, signed(1, None, 8, &key));
    let foreign_head = head(signed(2, Some(parent_id), 8, &key), &keys);
    assert_ne!(
        foreign_head.id(),
        prepared.id(),
        "corrupt-source fixture must walk ancestry"
    );
    assert_eq!(
        classify_head(&prepared, &foreign_head, &corrupt, &keys),
        HeadRelation::Corrupt,
        "wrong bytes at requested parent id"
    );
    let untrusted_key = SigningKey::from_seed(&[8; 32]).unwrap();
    let untrusted = OwnedCandidate::new(
        "rebase-test",
        signed(2, Some(parent_id), 7, &untrusted_key).into(),
    )
    .unwrap();
    assert_eq!(
        classify_head(&untrusted, &head(parent, &keys), &corrupt, &keys),
        HeadRelation::Corrupt,
        "prepared signature is not trusted"
    );
}

#[test]
fn parentless_registered_prepared_root_and_its_descendants_are_subsumed() {
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let genesis = signed(1, None, 7, &key);
    let prepared = OwnedCandidate::new("rebase-test", genesis.clone().into()).unwrap();
    let volume = VolumeName::new("rebase-test".to_owned()).unwrap();
    let body = granary_core::intent::encode_register(&[7; 16], 1, &[1; 16], 1, &genesis).unwrap();
    let registered = granary_core::intent::decode_register(&body, &volume, |doc, prefix| {
        granary_store::crypto::check_signatures(doc, prefix, &keys).is_ok()
    })
    .unwrap_or_else(|error| panic!("parentless signed root registration refused: {error}"));
    assert_eq!(
        (
            registered.root_id(),
            root::decode_root(registered.root).unwrap().parent
        ),
        (prepared.id(), None),
        "registration must accept the exact parentless root"
    );
    let second = signed(2, Some(prepared.id()), 8, &key);
    let second_id = GrainId::of(&second);
    let own_later = signed(3, Some(second_id), 7, &key);
    let foreign = signed(1, None, 8, &key);
    let foreign_id = GrainId::of(&foreign);
    let roots = Roots(BTreeMap::from([
        (prepared.id(), genesis.clone()),
        (second_id, second),
        (foreign_id, foreign.clone()),
    ]));
    let cases = [
        (
            "parentless prepared descendant",
            signed(3, Some(second_id), 9, &key),
            HeadRelation::Subsumed {
                by_seq: 1,
                by_root: prepared.id(),
            },
        ),
        (
            "parentless prepared equals head",
            genesis,
            HeadRelation::Subsumed {
                by_seq: 1,
                by_root: prepared.id(),
            },
        ),
        (
            "parentless prepared with later matching writer",
            own_later,
            HeadRelation::Subsumed {
                by_seq: 1,
                by_root: prepared.id(),
            },
        ),
        (
            "parentless prepared on a foreign genesis",
            foreign,
            HeadRelation::Stale,
        ),
        (
            "matching writer cannot excuse a foreign genesis",
            signed(2, Some(foreign_id), 7, &key),
            HeadRelation::Stale,
        ),
        (
            "matching writer cannot excuse a missing link",
            signed(3, Some(GrainId::of(b"missing")), 7, &key),
            HeadRelation::Corrupt,
        ),
        (
            "parentless chain cannot skip a sequence",
            signed(3, Some(prepared.id()), 7, &key),
            HeadRelation::Corrupt,
        ),
    ];
    for (row, bytes, expected) in cases {
        assert_eq!(
            classify_head(&prepared, &head(bytes, &keys), &roots, &keys),
            expected,
            "{row}"
        );
    }
}

#[test]
fn equal_manifest_witnesses_include_intermediate_parent_and_coalesced_head() {
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let manifest = GrainId::of(b"selected namespace");
    let equal_tree = |bytes: Vec<u8>| {
        let mut doc = root::decode_root(&bytes).unwrap();
        doc.manifest_root = manifest;
        doc.sigs.clear();
        doc.sigs.push(RootSig {
            key_id: key.key_id(),
            sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
        });
        root::encode_root(&doc).unwrap()
    };
    let mut cases = 0;
    for position in ["head", "intermediate", "parent", "coalesced"] {
        let parent = signed(1, None, 8, &key);
        let parent = if matches!(position, "parent" | "coalesced") {
            equal_tree(parent)
        } else {
            parent
        };
        let parent_id = GrainId::of(&parent);
        let selected = equal_tree(signed(2, Some(parent_id), 7, &key));
        let prepared = OwnedCandidate::new("rebase-test", selected.into()).unwrap();
        let witness = equal_tree(signed(2, Some(parent_id), 9, &key));
        let witness_id = GrainId::of(&witness);
        let last = match position {
            "head" => witness.clone(),
            "intermediate" => signed(3, Some(witness_id), 10, &key),
            "parent" => signed(2, Some(parent_id), 10, &key),
            _ => parent.clone(),
        };
        let roots = Roots(BTreeMap::from([(parent_id, parent), (witness_id, witness)]));
        let expected = if matches!(position, "parent" | "coalesced") {
            HeadRelation::Subsumed {
                by_seq: 1,
                by_root: parent_id,
            }
        } else {
            HeadRelation::Subsumed {
                by_seq: 2,
                by_root: witness_id,
            }
        };
        assert_eq!(
            classify_head(&prepared, &head(last.clone(), &keys), &roots, &keys),
            expected,
            "{position}"
        );
        if position != "coalesced" {
            assert_eq!(
                classify_head(&prepared, &head(last, &keys), &Roots::default(), &keys),
                HeadRelation::Corrupt,
                "{position}: a witness never excuses unavailable ancestry"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 4);
}
