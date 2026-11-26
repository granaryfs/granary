// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::escape` — the dump row's path/target escaper: the
//! injective byte-to-ASCII codec.
//!
//! Out-of-line: `granary-conformance`'s non-test artifact
//! has its own `[[bin]]` (`granconf`) and its own `tests/`
//! directory (`crates/granary-conformance/tests/cli.rs`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::{decode, escape};
use proptest::prelude::*;

/// The task's own minimum case: a literal `\x2f` (four ASCII bytes:
/// backslash, x, 2, f) inside a name, a real `/` separator, a
/// space, a newline, a tab, and byte 0xff must all render
/// DISTINCTLY and decode back to the original bytes.
#[test]
fn the_escaper_is_injective_and_round_trips_the_required_set() {
    let cases: Vec<Vec<u8>> = vec![
        b"has\\x2fliteral".to_vec(),
        b"real/separator".to_vec(),
        b"a space".to_vec(),
        b"a\nnewline".to_vec(),
        b"a\ttab".to_vec(),
        vec![0xffu8],
        b"plain".to_vec(),
    ];
    let mut rendered = Vec::new();
    for case in &cases {
        let text = escape(case);
        let back = decode(&text).unwrap_or_else(|e| panic!("decode({text:?}) failed: {e}"));
        assert_eq!(&back, case, "round-trip broke for {case:?} -> {text:?}");
        rendered.push(text);
    }
    for i in 0..rendered.len() {
        for j in (i + 1)..rendered.len() {
            assert_ne!(
                rendered[i], rendered[j],
                "cases {:?} and {:?} rendered identically: {:?}",
                cases[i], cases[j], rendered[i]
            );
        }
    }
}

#[test]
fn a_backslash_always_escapes_even_when_followed_by_x() {
    // A literal backslash immediately followed by 'x' must not be
    // mistaken for the start of ITS OWN escape by the encoder: the
    // encoder always emits `\x5c` for the backslash byte itself,
    // so the two-hex-digit rule stays exact from the reader's side.
    let raw = b"\\xNOPE".to_vec();
    let text = escape(&raw);
    assert_eq!(text, "\\x5cxNOPE");
    assert_eq!(decode(&text).unwrap(), raw);
}

#[test]
fn exactly_two_hex_digits_disambiguates_adjacent_bytes() {
    // Byte 0x07 followed by literal ASCII 'f' must not render as
    // anything that could be misread as byte 0x7f: `\x7` (one
    // digit) would be exactly that ambiguity.
    let raw = vec![0x07u8, b'f'];
    let text = escape(&raw);
    assert_eq!(text, "\\x07f");
    assert_ne!(text, escape(&[0x7fu8]));
    assert_eq!(decode(&text).unwrap(), raw);
}

#[test]
fn decode_refuses_uppercase_hex_so_one_path_has_exactly_one_rendering() {
    // `\xFF` and `\xff` must not both decode to byte 0xff: two texts
    // decoding to one path defeats the injectivity the whole format
    // rests on, and the emit-time duplicate refusal cannot see it
    // because only ONE of the two is ever emitted.
    assert!(decode("a\\xFFb").is_err(), "uppercase hex must be refused");
    assert!(decode("a\\xAb").is_err());
    assert_eq!(
        decode("a\\xffb").expect("lowercase is the canonical form"),
        b"a\xffb".to_vec()
    );
}

#[test]
fn decode_refuses_escapes_that_manufacture_passthrough_bytes() {
    assert!(decode("\\x61").is_err(), "ASCII letters must be literal");
    assert!(decode("\\x2f").is_err(), "path separators must be literal");
}

proptest! {
    #[test]
    fn every_accepted_text_is_already_the_canonical_escape(
        pieces in proptest::collection::vec((any::<u8>(), any::<bool>()), 0..128)
    ) {
        let mut text = String::new();
        for (byte, escaped) in pieces {
            if escaped {
                use std::fmt::Write as _;
                let _ = write!(text, "\\x{byte:02x}");
            } else {
                text.push(char::from(byte & 0x7f));
            }
        }
        if let Ok(decoded) = decode(&text) {
            prop_assert_eq!(escape(&decoded), text);
        }
    }
}

#[test]
fn every_byte_value_round_trips_alone() {
    for b in 0u16..=255 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "b is bounded to 0..=255 by the range"
        )]
        let raw = vec![b as u8];
        let text = escape(&raw);
        assert_eq!(
            decode(&text).unwrap(),
            raw,
            "byte {b:#04x} did not round-trip"
        );
    }
}

#[test]
fn decode_refuses_a_malformed_escape() {
    assert!(decode("\\xzz").is_err());
    assert!(decode("\\x").is_err());
    assert!(decode("trailing\\").is_err());
}

#[test]
fn the_empty_path_round_trips() {
    assert_eq!(escape(&[]), "");
    assert_eq!(decode("").unwrap(), Vec::<u8>::new());
}
