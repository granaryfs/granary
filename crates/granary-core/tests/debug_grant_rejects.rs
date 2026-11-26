// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Exact-error reject corpus and paired controls for each consequential rule.

use std::path::Path;

use granary_core::debug_grant::{
    GrantDecodeError as D, GrantValidationError as V, LabelField, TimestampField, decode_grant,
    encode_grant,
};

const PRINCIPAL: &[u8] = include_bytes!("vectors/debug-grant/golden-principal");

fn vector(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/debug-grant")
        .join(format!("{name}.bin"));
    std::fs::read(path).unwrap_or_else(|e| panic!("{e}"))
}

#[track_caller]
fn refuse(name: &str, expected: D) {
    let control = decode_grant(PRINCIPAL).unwrap_or_else(|e| panic!("positive control: {e}"));
    assert_eq!(encode_grant(&control).as_bytes(), PRINCIPAL);
    assert_eq!(
        decode_grant(&vector(name)),
        Err(expected),
        "reject row {name}"
    );
}

#[test]
fn debug_grant_reject_corpus() {
    let rows: Vec<_> = include_str!("vectors/debug-grant/rejects.tsv")
        .lines()
        .collect();
    assert_eq!(rows.len(), 99, "complete reject domain");
    for row in rows {
        let (name, expected) = row
            .split_once('\t')
            .unwrap_or_else(|| panic!("complete reject row"));
        let result = decode_grant(&vector(name));
        let error = result.unwrap_err();
        assert_eq!(format!("{error:?}"), expected, "reject row {name}");
    }
}

#[test]
fn debug_grant_reject_check() {
    for name in ["check", "check-context", "check-unkeyed"] {
        refuse(name, D::BadCheck);
    }
}

#[test]
fn debug_grant_reject_oversize_before_check() {
    refuse("oversize-bad-check", D::TooLong { len: 524 });
}

#[test]
fn debug_grant_reject_trailing_bytes() {
    refuse("trailing", D::TrailingData { len: 1 });
}

#[test]
fn debug_grant_reject_duration_bound() {
    for name in [
        "duration-zero",
        "duration-negative",
        "duration-negative-nano",
        "duration-901",
        "duration-900-plus-nano",
        "duration-extreme-positive",
        "duration-extreme-negative",
    ] {
        refuse(name, D::InvalidValue(V::InvalidDuration));
    }
}

#[test]
fn debug_grant_reject_generation_revision_relation() {
    refuse("revision-zero", D::InvalidValue(V::InvalidFileRevision));
    for generation in [0u64, 2, u64::MAX] {
        refuse(
            &format!("generation-{generation}"),
            D::InvalidValue(V::InvalidGeneration {
                generation,
                revision: 1,
            }),
        );
    }
}

#[test]
fn debug_grant_reject_reason_charset() {
    for byte in [0u8, 0x1f, 0x20, 0x7f, 0x80, 0xff] {
        refuse(
            &format!("reason-byte-{byte:02x}"),
            D::InvalidValue(V::BadLabelByte {
                field: LabelField::Reason,
                byte,
            }),
        );
    }
}

#[test]
fn debug_grant_reject_nanosecond_bound() {
    for (name, field) in [
        ("issued", TimestampField::IssuedAt),
        ("expires", TimestampField::ExpiresAt),
    ] {
        for nanos in [1_000_000_000u32, u32::MAX] {
            refuse(
                &format!("{name}-nanos-{nanos}"),
                D::InvalidValue(V::InvalidNanoseconds { field, nanos }),
            );
        }
    }
}

#[test]
fn debug_grant_rejects_every_truncation_and_byte_flip() {
    for len in 0..PRINCIPAL.len() {
        let expected = if len < 42 {
            D::TooShort { len }
        } else {
            D::BadCheck
        };
        assert_eq!(
            decode_grant(PRINCIPAL.get(..len).unwrap_or_else(|| panic!("prefix"))),
            Err(expected),
            "truncation {len}"
        );
    }
    for offset in 0..PRINCIPAL.len() {
        let mut damaged = PRINCIPAL.to_vec();
        *damaged.get_mut(offset).unwrap_or_else(|| panic!("byte")) ^= 1;
        let expected = if offset < 8 { D::BadMagic } else { D::BadCheck };
        assert_eq!(decode_grant(&damaged), Err(expected), "byte flip {offset}");
    }
}

fn checked(body: &[u8]) -> Vec<u8> {
    let mut bytes = body.to_vec();
    bytes.extend_from_slice(&blake3::derive_key("granary debug grant v1", body));
    bytes
}

#[test]
fn debug_grant_rejection_order() {
    let (body, _) = PRINCIPAL
        .split_last_chunk::<32>()
        .unwrap_or_else(|| panic!("check"));
    let mut changed = body.to_vec();
    changed
        .get_mut(8..10)
        .unwrap_or_else(|| panic!("version"))
        .copy_from_slice(&2u16.to_be_bytes());
    changed
        .get_mut(26..34)
        .unwrap_or_else(|| panic!("revision"))
        .copy_from_slice(&0u64.to_be_bytes());
    let mut broken_check = changed.clone();
    broken_check.extend_from_slice(&[0; 32]);
    assert_eq!(decode_grant(&broken_check), Err(D::BadCheck));
    assert_eq!(
        decode_grant(&checked(&changed)),
        Err(D::UnknownVersion { version: 2 })
    );
    changed.resize(492, 0);
    assert_eq!(
        decode_grant(&checked(&changed)),
        Err(D::TooLong { len: 524 })
    );
    *changed.first_mut().unwrap_or_else(|| panic!("magic")) = 0;
    assert_eq!(decode_grant(&checked(&changed)), Err(D::BadMagic));
    let mut changed = body.to_vec();
    changed
        .get_mut(68..72)
        .unwrap_or_else(|| panic!("issued nanos"))
        .copy_from_slice(&1_000_000_000u32.to_be_bytes());
    changed
        .get_mut(80..84)
        .unwrap_or_else(|| panic!("expires nanos"))
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        decode_grant(&checked(&changed)),
        Err(D::InvalidValue(V::InvalidNanoseconds {
            field: TimestampField::IssuedAt,
            nanos: 1_000_000_000
        }))
    );
}
