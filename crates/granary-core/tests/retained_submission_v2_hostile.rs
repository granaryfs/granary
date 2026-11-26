// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
//! Retained-submission
//! v2 hostile bytes and v1 read-back, built from the golden vectors.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "vector helpers below sit outside #[test] fns (test code, standards rule 3)"
)]

use granary_core::retained_submission::{self as r, CHECK_CONTEXT, Error};

fn vectors() -> Vec<(String, Vec<u8>)> {
    let dir = format!(
        "{}/tests/vectors/retained-submission",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "bin"))
        .map(|p| {
            (
                p.file_stem().unwrap().to_str().unwrap().to_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn repair(bytes: &mut [u8]) {
    let len = u32::try_from(bytes.len()).unwrap();
    bytes[10..14].copy_from_slice(&len.to_be_bytes());
    let end = bytes.len() - 32;
    let check = blake3::derive_key(CHECK_CONTEXT, &bytes[..end]);
    bytes[end..].copy_from_slice(&check);
}

/// Splice the body (everything before the check) and repair length and check.
fn edit(bytes: &[u8], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = bytes[..bytes.len() - 32].to_vec();
    f(&mut body);
    body.extend_from_slice(&[0; 32]);
    repair(&mut body);
    body
}

#[test]
fn retained_v2_v1_reads_back_with_zero_exemptions_and_upgrades() {
    let mut seen = 0;
    for (name, bytes) in vectors().into_iter().filter(|(n, _)| !n.starts_with("v2-")) {
        assert_eq!(&bytes[8..10], &[0, 1], "{name}: not a v1 vector");
        let value = r::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(value.unavailable_exemptions, 0, "{name}");
        let upgraded = r::encode(&value).unwrap();
        assert_eq!(&upgraded[8..10], &[0, 2], "{name}");
        assert_eq!(upgraded.len(), bytes.len() + 2, "{name}");
        assert_eq!(r::decode(&upgraded).unwrap(), value, "{name}");
        seen += 1;
    }
    assert!(seen >= 16, "v1 vectors seen: {seen}");
}

#[test]
fn retained_v2_v2_hostile_bytes_refuse() {
    let mut seen = 0;
    for (name, bytes) in vectors() {
        let v2 = name.starts_with("v2-");
        let field = bytes.len() - 34..bytes.len() - 32;
        // Unsupported versions, with a valid check.
        for version in [0_u16, 3, 4, 0x0102, 0x0200, 0xffff] {
            let hostile = edit(&bytes, |b| b[8..10].copy_from_slice(&version.to_be_bytes()));
            assert_eq!(
                r::decode(&hostile),
                Err(Error::Version(version)),
                "{name} v{version}"
            );
        }
        // Trailing bytes, either version.
        for extra in [1_usize, 2, 3, 34] {
            let hostile = edit(&bytes, |b| b.extend(std::iter::repeat_n(0, extra)));
            assert!(
                r::decode(&hostile).is_err(),
                "{name}: {extra} trailing bytes accepted"
            );
        }
        // Truncation at every length without a repaired check, and of the tail with one.
        for len in 0..bytes.len() {
            assert!(
                r::decode(&bytes[..len]).is_err(),
                "{name}: prefix {len} accepted"
            );
        }
        for cut in [1_usize, 2, 3] {
            let hostile = edit(&bytes, |b| b.truncate(b.len() - cut));
            assert!(
                r::decode(&hostile).is_err(),
                "{name}: tail cut {cut} accepted"
            );
        }
        if v2 {
            let honest = r::decode(&bytes).unwrap();
            for count in [1025_u16, 1026, 2048, 0x8000, 0xffff] {
                let hostile = edit(&bytes, |b| {
                    let at = b.len() - 2;
                    b[at..].copy_from_slice(&count.to_be_bytes());
                });
                assert!(
                    r::decode(&hostile).is_err(),
                    "{name}: count {count} accepted"
                );
            }
            // The count changed without the check must not decode.
            let mut unchecked = bytes.clone();
            unchecked[field.clone()].copy_from_slice(&7_u16.to_be_bytes());
            if honest.unavailable_exemptions != 7 {
                assert_eq!(r::decode(&unchecked), Err(Error::BadCheck), "{name}");
            }
            // A v2 payload relabelled v1 must not drop its count silently.
            let relabelled = edit(&bytes, |b| b[8..10].copy_from_slice(&[0, 1]));
            assert!(
                r::decode(&relabelled).is_err(),
                "{name}: v2 body accepted as v1"
            );
            // v2 without its field.
            let stripped = edit(&bytes, |b| b.truncate(b.len() - 2));
            assert!(
                r::decode(&stripped).is_err(),
                "{name}: v2 without the field accepted"
            );
        } else {
            // A v1 payload relabelled v2 has no field to read.
            let relabelled = edit(&bytes, |b| b[8..10].copy_from_slice(&[0, 2]));
            assert!(
                r::decode(&relabelled).is_err(),
                "{name}: v1 body accepted as v2"
            );
            // v1 carrying a count.
            for count in [0_u16, 1, 64] {
                let hostile = edit(&bytes, |b| b.extend_from_slice(&count.to_be_bytes()));
                assert!(
                    r::decode(&hostile).is_err(),
                    "{name}: v1 with count {count} accepted"
                );
            }
        }
        seen += 1;
    }
    assert!(seen >= 34, "vectors seen: {seen}");
}
