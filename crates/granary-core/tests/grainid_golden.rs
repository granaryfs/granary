// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `GrainId` golden encoding vectors (format-object skill). These bytes
//! are a consensus surface: a red here after a code change means the
//! FORMAT moved, and that is a deliberate versioned event, never a
//! refactor side effect.

use granary_core::hash::{GRAIN_ID_BINARY_LEN, GrainId, HashAlgorithm};

mod common;

#[test]
fn golden_text_form() {
    // blake3 of empty input — the canonical smoke vector.
    assert_eq!(
        GrainId::of(b"").to_string(),
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

#[test]
fn golden_binary_form() {
    let id = GrainId::of(b"");
    let bytes = id.to_bytes();
    let mut expected = vec![0x01u8]; // HashAlgorithm::Blake3 tag
    expected.extend_from_slice(id.digest());
    assert_eq!(bytes.as_slice(), expected.as_slice());
    assert_eq!(bytes.len(), GRAIN_ID_BINARY_LEN);
}

#[test]
fn golden_parts() {
    // from_parts is the decode path manifests use — pin its
    // equivalence to of() now.
    let id = GrainId::of(b"granary");
    let rebuilt = GrainId::from_parts(HashAlgorithm::Blake3, *id.digest());
    assert_eq!(rebuilt, id);
}

// Canonical ordering is a format property:
// in-memory Ord MUST equal lexicographic order of the canonical binary
// encoding, or manifest sort order diverges from encoded order.
#[test]
fn ord_matches_binary_encoding_order() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    for (lo, hi) in [(0u8, 1u8), (1, 255), (7, 7), (255, 0)] {
        a[0] = lo;
        b[0] = hi;
        a[31] = hi;
        b[31] = lo;
        let ga = GrainId::from_parts(HashAlgorithm::Blake3, a);
        let gb = GrainId::from_parts(HashAlgorithm::Blake3, b);
        assert_eq!(ga.cmp(&gb), ga.to_bytes().cmp(&gb.to_bytes()));
    }
}

// Golden vectors file rendered through the shared regen helper: text
// + binary forms for fixed inputs.
// Regenerate DELIBERATELY:
// `GRANARY_REGEN_VECTORS=1 cargo test -p granary-core --test grainid_golden`
#[test]
fn matches_committed_vectors() {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "# granary grainid golden vectors v1").unwrap();
    let zeros = vec![0u8; 1024 * 1024];
    for (name, input) in [
        ("empty", b"".as_slice()),
        ("granary", b"granary".as_slice()),
        ("zeros-1mib", zeros.as_slice()),
    ] {
        let id = GrainId::of(input);
        let mut hex = String::new();
        for b in id.to_bytes() {
            write!(hex, "{b:02x}").unwrap();
        }
        writeln!(out, "case {name} text={id} binary={hex}").unwrap();
    }
    common::assert_golden(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/grainid_v1.txt"),
        &out,
    );
}
