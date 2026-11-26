// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Wire properties of the writer-intent bodies. They live outside core so the
//! generator's I/O dependencies cannot enter core's pure dependency closure.
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code (standards rule 3)"
)]

use granary_core::hash::GrainId;
use granary_core::intent::*;
use granary_core::root::{
    ED25519_SIG_LEN, KEY_ID_LEN, RootDoc, RootSig, Timestamp, VolumeName, encode_root,
};
use proptest::prelude::*;
use std::collections::BTreeSet;

fn volume() -> VolumeName {
    VolumeName::new("granary-test".to_owned()).unwrap()
}

fn root_of(seed: [u8; 8]) -> Vec<u8> {
    encode_root(&RootDoc {
        volume: volume(),
        seq: 1,
        parent: None,
        writer_uuid: [seed[0]; 16],
        epoch: u64::from_be_bytes(seed),
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(&seed),
        binmap_index: GrainId::of(&[seed.as_slice(), &[1]].concat()),
        sheaf_head: GrainId::of(&[seed.as_slice(), &[2]].concat()),
        sigs: vec![RootSig {
            key_id: [seed[1]; KEY_ID_LEN],
            sig: [seed[2]; ED25519_SIG_LEN],
        }],
    })
    .unwrap()
}

fn accept(_: &RootDoc, _: &[u8]) -> bool {
    true
}

/// Every proper prefix of a body refuses.
fn prefixes_refuse(body: &[u8], decode: impl Fn(&[u8]) -> bool) -> bool {
    (0..body.len()).all(|n| !decode(&body[..n]))
}

fn receipt_of(
    w: [u8; 16],
    epoch: u64,
    i: [u8; 16],
    generation: u64,
    seed: [u8; 8],
    is_live: bool,
) -> Receipt {
    let generation = if is_live && generation == 0 {
        1
    } else {
        generation
    };
    let state = if is_live {
        ReceiptState::Live {
            prepared_root_id: GrainId::of(&seed),
        }
    } else {
        ReceiptState::Released
    };
    Receipt {
        epoch,
        writer: w,
        instance: i,
        generation,
        state,
    }
}

/// A readback of up to the live-row ceiling: ascending distinct writers, a
/// distinct generation and a distinct root for every row, so a row's fields
/// cannot be confused with a neighbour's without a property noticing.
fn readback_rows(
    writers: &BTreeSet<[u8; 16]>,
    generations: &BTreeSet<u64>,
    roots: &[Vec<u8>],
) -> Vec<(([u8; 16], u64), usize)> {
    writers
        .iter()
        .copied()
        .zip(generations.iter().copied())
        .zip(0..roots.len())
        .collect()
}

proptest! {
    #[test]
    fn register_round_trip(w in any::<[u8; 16]>(), i in any::<[u8; 16]>(), epoch in 1..=u64::MAX, generation in 1..u64::MAX, seed in any::<[u8; 8]>()) {
        let root = root_of(seed);
        let bytes = encode_register(&w, epoch, &i, generation, &root).unwrap();
        prop_assert!(bytes.len() <= REGISTER_MAX_BYTES);
        let got = decode_register(&bytes, &volume(), accept).unwrap();
        prop_assert_eq!((got.writer, got.epoch, got.instance, got.generation, got.root), (w, epoch, i, generation, root.as_slice()));
        prop_assert_eq!(got.root_id(), GrainId::of(&root));
        prop_assert_eq!(encode_register(&got.writer, got.epoch, &got.instance, got.generation, got.root).unwrap(), bytes.clone());
        prop_assert!(prefixes_refuse(&bytes, |b| decode_register(b, &volume(), accept).is_ok()));
    }

    #[test]
    fn release_round_trip(w in any::<[u8; 16]>(), i in any::<[u8; 16]>(), epoch in 1..=u64::MAX, generation in 1..u64::MAX) {
        let value = Release { epoch,  writer: w, instance: i, generation };
        let bytes = encode_release(value).unwrap();
        prop_assert_eq!(bytes.len(), RELEASE_BYTES);
        prop_assert_eq!(decode_release(&bytes), Ok(value));
        prop_assert!(prefixes_refuse(&bytes, |b| decode_release(b).is_ok()));
    }

    #[test]
    fn receipt_round_trip(w in any::<[u8; 16]>(), i in any::<[u8; 16]>(), epoch in 1..=u64::MAX, generation in 0..u64::MAX, seed in any::<[u8; 8]>(), is_live in any::<bool>()) {
        let value = receipt_of(w, epoch, i, generation, seed, is_live);
        let bytes = encode_receipt(value).unwrap();
        prop_assert!(bytes.len() <= RECEIPT_MAX_BYTES);
        prop_assert_eq!(decode_receipt(&bytes), Ok(value));
        prop_assert_eq!(encode_receipt(decode_receipt(&bytes).unwrap()).unwrap(), bytes.clone());
        prop_assert!(prefixes_refuse(&bytes, |b| decode_receipt(b).is_ok()));
    }

    #[test]
    fn readback_round_trip(
        cursor in 1..=u64::MAX,
        writers in prop::collection::btree_set(any::<[u8; 16]>(), 0..=MAX_LIVE_ROWS),
        generations in prop::collection::btree_set(1..u64::MAX, MAX_LIVE_ROWS..=MAX_LIVE_ROWS),
        seeds in prop::collection::btree_set(any::<[u8; 8]>(), MAX_LIVE_ROWS..=MAX_LIVE_ROWS),
    ) {
        let roots: Vec<Vec<u8>> = seeds.iter().map(|s| root_of(*s)).collect();
        let rows: Vec<ReadbackRow<'_>> = readback_rows(&writers, &generations, &roots)
            .into_iter()
            .map(|((writer, generation), n)| ReadbackRow { epoch: 1 + generation % cursor,  writer, generation, root: &roots[n] })
            .collect();
        prop_assert_eq!(rows.len(), writers.len());
        let bytes = encode_readback(cursor, &rows).unwrap();
        prop_assert!(bytes.len() <= READBACK_MAX_BYTES);
        let got = decode_readback(&bytes, &volume(), accept).unwrap();
        prop_assert_eq!(got.cursor, cursor);
        prop_assert_eq!(&got.rows, &rows);
        prop_assert_eq!(encode_readback(got.cursor, &got.rows).unwrap(), bytes.clone());
        prop_assert!(prefixes_refuse(&bytes, |b| decode_readback(b, &volume(), accept).is_ok()));
    }

    /// Whatever a decoder accepts, its encoder reproduces byte for byte.
    #[test]
    fn decode_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(v) = decode_ownership(&bytes) { prop_assert_eq!(encode_ownership(v).unwrap(), bytes.clone()); }
        if let Ok(v) = decode_grant(&bytes) { prop_assert_eq!(encode_grant(v).unwrap(), bytes.clone()); }
        if let Ok(v) = decode_release(&bytes) { prop_assert_eq!(encode_release(v).unwrap(), bytes.clone()); }
        if let Ok(v) = decode_receipt(&bytes) { prop_assert_eq!(encode_receipt(v).unwrap(), bytes.clone()); }
        if let Ok(v) = decode_readback(&bytes, &volume(), accept) { prop_assert_eq!(encode_readback(v.cursor, &v.rows).unwrap(), bytes.clone()); }
        if let Ok(v) = decode_register(&bytes, &volume(), accept) {
            prop_assert_eq!(encode_register(&v.writer, v.epoch, &v.instance, v.generation, v.root).unwrap(), bytes.clone());
        }
    }

    /// One byte of a valid registration changed: it is refused or it re-encodes to the mutated bytes.
    #[test]
    fn a_mutated_registration_is_refused_or_canonical(w in any::<[u8; 16]>(), i in any::<[u8; 16]>(), epoch in 1..=u64::MAX, generation in 1..u64::MAX, seed in any::<[u8; 8]>(), at in any::<usize>(), xor in 1..=u8::MAX) {
        let root = root_of(seed);
        let mut bytes = encode_register(&w, epoch, &i, generation, &root).unwrap();
        let n = at % bytes.len();
        bytes[n] ^= xor;
        if let Ok(v) = decode_register(&bytes, &volume(), accept) {
            prop_assert_eq!(encode_register(&v.writer, v.epoch, &v.instance, v.generation, v.root).unwrap(), bytes);
        }
    }

}

/// Every single-bit flip of `bytes`, each as a fresh body.
fn bit_flips(bytes: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    (0..bytes.len()).flat_map(move |i| {
        (0..8).map(move |bit| {
            let mut flipped = bytes.to_vec();
            flipped[i] ^= 1 << bit;
            flipped
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Each single-bit flip of a valid release is refused or re-encodes to the
    /// flipped bytes: no field of the body is ignored by the decoder.
    #[test]
    fn a_mutated_release_is_refused_or_canonical(w in any::<[u8; 16]>(), i in any::<[u8; 16]>(), epoch in 1..=u64::MAX, generation in 1..u64::MAX) {
        let bytes = encode_release(Release { epoch,  writer: w, instance: i, generation }).unwrap();
        for flipped in bit_flips(&bytes) {
            if let Ok(v) = decode_release(&flipped) {
                prop_assert_eq!(encode_release(v).unwrap(), flipped);
            }
        }
    }

    /// The same for a receipt, live or released: a flipped state, token, id or
    /// generation bit is refused or re-encodes to the flipped bytes.
    #[test]
    fn a_mutated_receipt_is_refused_or_canonical(w in any::<[u8; 16]>(), i in any::<[u8; 16]>(), epoch in 1..=u64::MAX, generation in 0..u64::MAX, seed in any::<[u8; 8]>(), is_live in any::<bool>()) {
        let bytes = encode_receipt(receipt_of(w, epoch, i, generation, seed, is_live)).unwrap();
        for flipped in bit_flips(&bytes) {
            if let Ok(v) = decode_receipt(&flipped) {
                prop_assert_eq!(encode_receipt(v).unwrap(), flipped);
            }
        }
    }

    /// The same for a readback of several rows, including a flipped count,
    /// writer, generation, length or root bit.
    #[test]
    fn a_mutated_readback_is_refused_or_canonical(
        cursor in 1..=u64::MAX,
        writers in prop::collection::btree_set(any::<[u8; 16]>(), 1..=3),
        generations in prop::collection::btree_set(1..u64::MAX, MAX_LIVE_ROWS..=MAX_LIVE_ROWS),
        seeds in prop::collection::btree_set(any::<[u8; 8]>(), MAX_LIVE_ROWS..=MAX_LIVE_ROWS),
    ) {
        let roots: Vec<Vec<u8>> = seeds.iter().map(|s| root_of(*s)).collect();
        let rows: Vec<ReadbackRow<'_>> = readback_rows(&writers, &generations, &roots)
            .into_iter()
            .map(|((writer, generation), n)| ReadbackRow { epoch: 1 + generation % cursor,  writer, generation, root: &roots[n] })
            .collect();
        let bytes = encode_readback(cursor, &rows).unwrap();
        for flipped in bit_flips(&bytes) {
            if let Ok(v) = decode_readback(&flipped, &volume(), accept) {
                prop_assert_eq!(encode_readback(v.cursor, &v.rows).unwrap(), flipped);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn ownership_and_grant_round_trip(w in any::<[u8;16]>(), t in any::<[u8;16]>(), h in any::<u64>(), e in 1..=u64::MAX, g in 0..u64::MAX, live in any::<bool>(), ack in any::<bool>(), seed in any::<[u8;8]>()) {
        let state = if live { ReceiptState::Live { prepared_root_id: GrainId::of(&seed) } } else { ReceiptState::Released };
        let g = if live && g == 0 { 1 } else { g };
        for mode in [OwnershipMode::Acquire { observed_cursor: h }, OwnershipMode::Takeover { expected_epoch: e, generation: g, state, recovery_ack: ack }] {
            let value = Ownership { writer: w, instance: t, mode };
            let bytes = encode_ownership(value).unwrap();
            prop_assert_eq!(decode_ownership(&bytes), Ok(value));
            prop_assert!(prefixes_refuse(&bytes, |b| decode_ownership(b).is_ok()));
            for flipped in bit_flips(&bytes) {
                if let Ok(v) = decode_ownership(&flipped) { prop_assert_eq!(encode_ownership(v).unwrap(), flipped); }
            }
            let grant = Grant { request_id: GrainId::of(&bytes), receipt: Receipt { writer:w, epoch:e, instance:t, generation:g, state } };
            let bytes = encode_grant(grant).unwrap();
            prop_assert_eq!(decode_grant(&bytes), Ok(grant));
            prop_assert!(prefixes_refuse(&bytes, |b| decode_grant(b).is_ok()));
            for flipped in bit_flips(&bytes) {
                if let Ok(v) = decode_grant(&flipped) { prop_assert_eq!(encode_grant(v).unwrap(), flipped); }
            }
        }
    }
}
