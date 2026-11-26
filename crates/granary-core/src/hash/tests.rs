// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::hash` — grain identity — algorithm-tagged content hashes (spec §4).
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use core::fmt::Write as _;

/// Official BLAKE3 test-vector input: the byte sequence
/// 0,1,2,...,249,250 repeating, truncated to `len`.
fn official_input(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

fn hex(id: &GrainId) -> String {
    id.to_string()
}

// Expected values from the official test_vectors.json
// (BLAKE3-team/BLAKE3, fetched + verified against both default and
// pure configs).
#[test]
fn official_vectors() {
    assert_eq!(
        hex(&GrainId::of(&official_input(0))),
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert_eq!(
        hex(&GrainId::of(&official_input(1))),
        "blake3:2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
    );
    assert_eq!(
        hex(&GrainId::of(&official_input(1024))),
        "blake3:42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"
    );
    assert_eq!(
        hex(&GrainId::of(&official_input(102_400))),
        "blake3:bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"
    );
}

#[test]
fn streaming_matches_one_shot_for_every_algorithm() {
    let input = official_input(102_401);
    let mut rows = 0;
    for &algorithm in HashAlgorithm::ALL {
        let expected = match algorithm {
            HashAlgorithm::Blake3 => GrainId::of(&input),
        };
        let mut hasher = GrainIdHasher::new(algorithm);
        for chunk in input.chunks(997) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), expected, "algorithm {algorithm:?}");
        rows += 1;
    }
    assert_eq!(rows, HashAlgorithm::ALL.len());
}

#[test]
fn text_roundtrip() {
    let id = GrainId::of(b"granary");
    let back: Result<GrainId, _> = id.to_string().parse();
    assert_eq!(back, Ok(id));
}

#[test]
fn binary_roundtrip_and_shape() {
    let id = GrainId::of(b"granary");
    let bytes = id.to_bytes();
    assert_eq!(bytes.len(), GRAIN_ID_BINARY_LEN);
    assert_eq!(bytes.first(), Some(&0x01));
    assert_eq!(GrainId::from_bytes(&bytes), Ok(id));
}

#[test]
fn strict_parse_rejections() {
    let good = GrainId::of(b"granary").to_string();
    // uppercase hex rejected (canonical form is lowercase)
    assert_eq!(
        good.to_uppercase().parse::<GrainId>(),
        Err(ParseGrainIdError::UnknownAlgorithm)
    );
    let upper_hex = format!(
        "blake3:{}",
        good.trim_start_matches("blake3:").to_uppercase()
    );
    assert_eq!(upper_hex.parse::<GrainId>(), Err(ParseGrainIdError::BadHex));
    assert_eq!(
        "blake3".parse::<GrainId>(),
        Err(ParseGrainIdError::MissingSeparator)
    );
    assert_eq!(
        "sha256:00".parse::<GrainId>(),
        Err(ParseGrainIdError::UnknownAlgorithm)
    );
    assert_eq!(
        "blake3:abcd".parse::<GrainId>(),
        Err(ParseGrainIdError::BadLength)
    );
    let bad_char = format!("blake3:zz{}", &good["blake3:".len() + 2..]);
    assert_eq!(bad_char.parse::<GrainId>(), Err(ParseGrainIdError::BadHex));
}

#[test]
fn binary_rejections() {
    assert_eq!(GrainId::from_bytes(&[]), Err(ParseGrainIdError::BadLength));
    assert_eq!(
        GrainId::from_bytes(&[0x01; 32]),
        Err(ParseGrainIdError::BadLength)
    );
    assert_eq!(
        GrainId::from_bytes(&[0x01; 34]),
        Err(ParseGrainIdError::BadLength)
    );
    assert_eq!(
        GrainId::from_bytes(&[0x00; 33]),
        Err(ParseGrainIdError::UnknownAlgorithm)
    );
    assert_eq!(
        GrainId::from_bytes(&[0x02; 33]),
        Err(ParseGrainIdError::UnknownAlgorithm)
    );
}

/// [`GrainId::digest_hex`]: 64 lowercase hex chars of the digest
/// ALONE — no algorithm tag byte (the store marker pins the
/// algorithm; the fanout path is digest-only).
#[test]
fn digest_hex_is_64_lowercase_hex_no_tag() {
    let id = GrainId::of(b"granary");
    let hex = id.digest_hex();
    assert_eq!(hex.len(), DIGEST_LEN * 2);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    let mut expected = String::new();
    for b in id.digest() {
        write!(expected, "{b:02x}").unwrap_or_else(|e| panic!("{e}"));
    }
    assert_eq!(hex, expected);
}

#[test]
fn debug_is_text_form() {
    let id = GrainId::of(b"x");
    assert_eq!(format!("{id:?}"), format!("GrainId({id})"));
}

/// A new variant fails the match below at compile time until its arm
/// is added; the arm's assertions then force `ALL`/`from_tag`/parse
/// coverage — closing the three-table drift hole.
#[test]
fn registry_closed() {
    for &a in HashAlgorithm::ALL {
        match a {
            HashAlgorithm::Blake3 => {
                assert!(HashAlgorithm::ALL.contains(&a));
            }
        }
        assert_eq!(HashAlgorithm::from_tag(a as u8), Some(a));
        let id = GrainId::from_parts(a, [7; DIGEST_LEN]);
        assert_eq!(id.to_string().parse::<GrainId>(), Ok(id));
        assert_eq!(GrainId::from_bytes(&id.to_bytes()), Ok(id));
    }
}
