// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::b64` — the fixed-width RFC 4648 §4 base64
//! codec for a 32-byte SPKI pin digest: the canonical 44-character
//! rendering, and refusal of every non-canonical form (URL-safe,
//! unpadded, or a final quantum with nonzero low bits).
//!
//! Out-of-line: `granary-net`'s non-test artifact has
//! workspace consumers (`granary-client`,
//! `granary-server`), so the module's own tests move out
//! of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{ALPHABET, B64Error, PIN_B64_LEN, decode_pin, encode_pin};

/// The §9a golden body. Chosen for the property a random digest does
/// not have: it renders with BOTH non-alphanumeric characters, `+`
/// (62) and `/` (63), so a codec that quietly used the URL-safe
/// alphabet cannot round-trip it.
const GOLDEN_B64: &str = "9cvkMbAwLn9O0YZS/Gm+J7KptTwLK+jY+u5x0eCHPZE=";

/// The 32 bytes `GOLDEN_B64` renders.
const GOLDEN_BYTES: [u8; 32] = [
    0xf5, 0xcb, 0xe4, 0x31, 0xb0, 0x30, 0x2e, 0x7f, 0x4e, 0xd1, 0x86, 0x52, 0xfc, 0x69, 0xbe, 0x27,
    0xb2, 0xa9, 0xb5, 0x3c, 0x0b, 0x2b, 0xe8, 0xd8, 0xfa, 0xee, 0x71, 0xd1, 0xe0, 0x87, 0x3d, 0x91,
];

/// **The encoder and the decoder are one table, spelled twice.**
///
/// `ALPHABET` drives `encode_pin` and a `match` drives `decode_pin`,
/// so nothing but this row stops the two from disagreeing — and a
/// disagreement is not a compile error, it is a codec that decodes a
/// character it would never emit, which is a second rendering of a
/// pin. Both directions, over all 256 bytes: every alphabet position
/// decodes to its own index, and every byte outside the alphabet is
/// refused.
#[test]
fn the_decoder_is_exactly_the_alphabets_inverse() {
    for (index, byte) in ALPHABET.iter().enumerate() {
        assert_eq!(
            super::sixbit(*byte).ok().map(usize::from),
            Some(index),
            "alphabet position {index} ({:?}) must decode to itself",
            char::from(*byte)
        );
    }
    for byte in 0..=u8::MAX {
        let inside = ALPHABET.contains(&byte);
        assert_eq!(
            super::sixbit(byte).is_ok(),
            inside,
            "byte {byte:#04x} ({:?}): accepted={}, in the alphabet={inside}",
            char::from(byte),
            super::sixbit(byte).is_ok()
        );
    }
}

/// A POSITIVE parse, and it is what stops an Err-on-everything codec
/// passing the eight rejection rows below.
#[test]
fn golden_decodes_and_round_trips() {
    assert_eq!(
        decode_pin(GOLDEN_B64),
        Ok(GOLDEN_BYTES),
        "the §9a golden must decode to its digest"
    );
    assert_eq!(
        encode_pin(&GOLDEN_BYTES),
        GOLDEN_B64,
        "encoding the digest must reproduce the one canonical rendering"
    );
    assert!(
        GOLDEN_B64.contains('+') && GOLDEN_B64.contains('/'),
        "the golden must exercise alphabet positions 62 and 63, or a \
         URL-safe codec passes it"
    );
}

/// The accept-set-blindness case: the SAME digest rendered URL-safe.
/// Decoding it would mean two renderings name one pin, and a paste
/// of the second form past a gate keyed on the first.
#[test]
fn url_safe_body_is_rejected() {
    let url_safe = GOLDEN_B64.replace('+', "-").replace('/', "_");
    assert_ne!(url_safe, GOLDEN_B64, "the substitution must change it");
    assert_eq!(
        decode_pin(&url_safe),
        Err(B64Error::Char { byte: b'_' }),
        "URL-safe `-`/`_` are not §4 alphabet bytes"
    );
    assert_eq!(
        decode_pin(&GOLDEN_B64.replace('+', "-")),
        Err(B64Error::Char { byte: b'-' }),
        "`-` alone is still outside the alphabet"
    );
}

/// The unpadded rendering of the same digest: 43 characters.
#[test]
fn unpadded_body_is_rejected() {
    let unpadded = GOLDEN_B64.trim_end_matches('=');
    assert_eq!(unpadded.len(), 43);
    assert_eq!(
        decode_pin(unpadded),
        Err(B64Error::Length { got: 43 }),
        "the unpadded form is a second rendering and must not decode"
    );
}

/// The malleability §9a closes: the last quantum's low two bits
/// contribute nothing to the 32nd byte, so four characters at index
/// 42 decode to one digest unless the trailing bits are pinned.
#[test]
fn non_canonical_trailing_bits_is_rejected() {
    let last = GOLDEN_B64.as_bytes().get(42).copied().unwrap_or(b'A');
    let six = ALPHABET.iter().position(|c| *c == last).unwrap_or(0);
    let mutant = ALPHABET.get((six & 0xFC) | 0x01).copied().unwrap_or(b'A');
    let mut mutated = GOLDEN_B64.to_owned();
    mutated.replace_range(42..43, char::from(mutant).encode_utf8(&mut [0_u8; 4]));

    assert_ne!(mutated, GOLDEN_B64, "the mutation must change the string");
    assert_eq!(
        decode_pin(&mutated),
        Err(B64Error::NonCanonical),
        "a second string decoding to the golden's bytes must be refused"
    );
}

/// Length is checked before anything else, on both sides of 44 and
/// on the empty string.
#[test]
fn wrong_length_is_rejected() {
    let short = GOLDEN_B64.get(..43).unwrap_or_default();
    let long = format!("{GOLDEN_B64}=");
    for value in ["", "=", short, long.as_str()] {
        assert_eq!(
            decode_pin(value),
            Err(B64Error::Length { got: value.len() }),
            "{value:?} is not {PIN_B64_LEN} characters"
        );
    }
}

/// A pad inside the body is not a pad. Two forms: the final quantum
/// carrying `==`, and a `=` in the middle of the string.
#[test]
fn interior_equals_is_rejected() {
    let mut two_pads = GOLDEN_B64.to_owned();
    two_pads.replace_range(42..43, "=");
    assert_eq!(
        decode_pin(&two_pads),
        Err(B64Error::Char { byte: b'=' }),
        "a 32-byte quantum takes exactly one pad"
    );

    let mut middle = GOLDEN_B64.to_owned();
    middle.replace_range(4..5, "=");
    assert_eq!(
        decode_pin(&middle),
        Err(B64Error::Char { byte: b'=' }),
        "a pad in the interior is not an alphabet byte"
    );
}

/// Every output bit is reachable: a codec that dropped a byte, or
/// masked a bit, would still pass the golden row if the golden
/// happened not to exercise the bit.
#[test]
fn every_output_bit_survives() {
    let mut counting = [0_u8; 32];
    for (i, slot) in counting.iter_mut().enumerate() {
        *slot = u8::try_from(i).unwrap_or(0);
    }
    for bytes in [[0_u8; 32], [0xFF_u8; 32], counting] {
        let rendered = encode_pin(&bytes);
        assert_eq!(
            rendered.len(),
            PIN_B64_LEN,
            "every rendering is {PIN_B64_LEN} characters"
        );
        assert_eq!(
            decode_pin(&rendered),
            Ok(bytes),
            "{rendered:?} must round-trip to the bytes it renders"
        );
    }
    assert_eq!(
        encode_pin(&[0_u8; 32]),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "the all-zero digest's rendering is pinned, not merely round-tripped"
    );
    assert_eq!(
        encode_pin(&[0xFF_u8; 32]),
        "//////////////////////////////////////////8=",
        "the all-ones digest's rendering is pinned too"
    );
}
