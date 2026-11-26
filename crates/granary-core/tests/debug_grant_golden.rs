// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Complete portable debug-grant vectors, checked in both directions.

use std::fmt::Write as _;
use std::path::Path;

use granary_core::debug_grant::{
    DEBUG_GRANT_MAGIC, DEBUG_GRANT_VERSION, decode_grant, encode_grant,
};

mod debug_grant_support;

#[test]
fn debug_grant_goldens_match() {
    assert_eq!(DEBUG_GRANT_MAGIC, *b"GRNDEBUG");
    assert_eq!(DEBUG_GRANT_VERSION, 1);
    let mut rendered = String::from("# granary debug grant golden vectors v1\n");
    for (name, grant) in debug_grant_support::goldens() {
        let bytes = encode_grant(&grant);
        let (covered, check) = bytes
            .as_bytes()
            .split_last_chunk::<32>()
            .unwrap_or_else(|| panic!("check present"));
        assert_eq!(
            *check,
            blake3::derive_key("granary debug grant v1", covered)
        );
        assert_ne!(*check, *blake3::hash(covered).as_bytes());
        writeln!(
            rendered,
            "case {name} size={} check={} bytes={}",
            bytes.as_bytes().len(),
            debug_grant_support::hex(check),
            debug_grant_support::hex(bytes.as_bytes())
        )
        .unwrap_or_else(|e| panic!("{e}"));
    }
    assert_eq!(rendered, include_str!("vectors/debug_grant_v1.txt"));
}

#[test]
fn debug_grant_committed_vectors_decode_and_reencode() {
    let cases = debug_grant_support::goldens();
    let sizes = [149, 139, 155, 155, 155, 523];
    let rows: Vec<_> = include_str!("vectors/debug_grant_v1.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(rows.len(), cases.len());
    for ((row, (expected_name, expected_grant)), expected_size) in rows.iter().zip(cases).zip(sizes)
    {
        let columns: Vec<_> = row.split_whitespace().collect();
        let ["case", name, size, check, bytes] = columns.as_slice() else {
            panic!("complete golden row: {row}");
        };
        assert_eq!(*name, expected_name);
        let size: usize = size
            .strip_prefix("size=")
            .unwrap_or_else(|| panic!("size"))
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        let check = debug_grant_support::unhex(
            check
                .strip_prefix("check=")
                .unwrap_or_else(|| panic!("check")),
        );
        let bytes = debug_grant_support::unhex(
            bytes
                .strip_prefix("bytes=")
                .unwrap_or_else(|| panic!("bytes")),
        );
        assert_eq!(size, expected_size);
        assert_eq!(bytes.len(), expected_size);
        let (covered, received_check) = bytes
            .split_last_chunk::<32>()
            .unwrap_or_else(|| panic!("check"));
        assert_eq!(received_check.as_slice(), check);
        assert_eq!(
            *received_check,
            blake3::derive_key("granary debug grant v1", covered)
        );
        assert_eq!(decode_grant(&bytes), Ok(expected_grant.clone()));
        assert_eq!(encode_grant(&expected_grant).as_bytes(), bytes);
        let vector = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/debug-grant")
            .join(format!("golden-{name}"));
        assert_eq!(
            std::fs::read(&vector)
                .unwrap_or_else(|e| panic!("immutable fixture {}: {e}", vector.display())),
            bytes
        );
    }
}

#[test]
fn debug_grant_reject_vector_bytes_are_pinned() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut index = String::new();
    let rows = debug_grant_support::rejects();
    assert!(!rows.is_empty());
    for (name, bytes, expected) in rows {
        writeln!(index, "{name}\t{expected:?}").unwrap_or_else(|e| panic!("{e}"));
        let vector = root
            .join("tests/vectors/debug-grant")
            .join(format!("{name}.bin"));
        assert_eq!(
            std::fs::read(vector).unwrap_or_else(|e| panic!("{e}")),
            bytes,
            "{name}"
        );
    }
    assert_eq!(index, include_str!("vectors/debug-grant/rejects.tsv"));
}
