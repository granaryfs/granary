// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A FIXED-WIDTH RFC 4648 §4 base64 codec for a 32-byte SPKI pin digest —
//! exactly 32 bytes in, exactly 44 characters out, and nothing else. A
//! general crate would carry alphabets/streaming/padding modes this surface
//! must REFUSE — URL-safe and unpadded forms are accept-set-blindness hazards
//! here (a second rendering decoding to the same 32 bytes slips a paste past a
//! gate). Fixing the width, the alphabet (§4 standard, `+`/`/`) and requiring
//! padding collapses the accept set to the one canonical rendering §9a names.
//! The final quantum's low 2 bits MUST be zero (else up to four strings decode
//! to one digest — the malleability §9a closes); `non_canonical_trailing_bits`
//! pins it.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The one width this codec accepts: 32 bytes rendered §4-canonically.
pub const PIN_B64_LEN: usize = 44;

/// Why a rendering is not the one canonical rendering of a 32-byte digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B64Error {
    /// Not exactly [`PIN_B64_LEN`] characters.
    Length {
        /// How many bytes the value held.
        got: usize,
    },
    /// The single trailing `=` a 32-byte quantum requires is absent.
    Padding,
    /// A byte outside the §4 standard alphabet — URL-safe `-`/`_`
    /// included, which is the accept-set-blindness case.
    Char {
        /// The offending byte.
        byte: u8,
    },
    /// The final quantum's low two bits are not zero, so this is one of
    /// up to four renderings of the same digest.
    NonCanonical,
    /// An internal invariant of this fixed-width codec did not hold: a
    /// quantum `chunks_exact(4)` did not produce four bytes for, or a
    /// write past the 32-byte output.
    ///
    /// **Unreachable, and REFUSED rather than skipped.** The length
    /// check makes a short quantum impossible. Refusing an invariant
    /// failure prevents returning a partially written digest as `Ok`.
    Invariant,
}

impl core::fmt::Display for B64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Length { got } => write!(f, "base64 pin must be {PIN_B64_LEN} chars, got {got}"),
            Self::Padding => f.write_str("base64 pin must end in a single '=' pad"),
            Self::Char { byte } => write!(f, "base64 pin has a non-alphabet byte {byte:#04x}"),
            Self::NonCanonical => {
                f.write_str("base64 pin has non-zero trailing bits (non-canonical)")
            }
            Self::Invariant => f.write_str("base64 pin codec invariant violated"),
        }
    }
}

impl std::error::Error for B64Error {}

/// The §4 alphabet's inverse, spelled as a MATCH rather than built as a
/// 256-entry table.
///
/// The table is the usual shape and it cannot be written in this
/// workspace: constructing it needs `t[ALPHABET[i] as usize] = i` —
/// three `clippy::indexing_slicing` sites — and reading it needs a
/// fourth, and that lint is `deny` here precisely because this function
/// takes untrusted config bytes. The match is the same accept set,
/// exhaustively spelled, with no index anywhere;
/// `the_decoder_is_exactly_the_alphabets_inverse` is what holds the two
/// halves in step.
fn sixbit(c: u8) -> Result<u8, B64Error> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(B64Error::Char { byte: c }),
    }
}

/// Write one output byte, refusing an index the invariant forbids.
///
/// The error is [`B64Error::Invariant`] and NOT
/// `B64Error::Length { got: i }`: `i` is an OUTPUT INDEX and `Length`
/// means the length of the input string, so that variant would have
/// rendered "base64 pin must be 44 chars, got 30" about a 44-character
/// string. An error that misreports which quantity was wrong is worse
/// than no error, because it sends whoever reads it to the wrong input.
fn set(out: &mut [u8; 32], i: usize, v: u8) -> Result<(), B64Error> {
    match out.get_mut(i) {
        Some(s) => {
            *s = v;
            Ok(())
        }
        None => Err(B64Error::Invariant),
    }
}

/// Decode exactly 44 canonical base64 characters into 32 bytes.
///
/// # Errors
/// [`B64Error`] for wrong length, missing pad, non-alphabet byte (URL-safe
/// `-`/`_` included), or non-canonical trailing bits.
pub fn decode_pin(s: &str) -> Result<[u8; 32], B64Error> {
    let b = s.as_bytes();
    if b.len() != PIN_B64_LEN {
        return Err(B64Error::Length { got: b.len() });
    }
    if b.get(PIN_B64_LEN - 1) != Some(&b'=') {
        return Err(B64Error::Padding);
    }
    let mut out = [0_u8; 32];
    let mut oi = 0_usize;
    for (qi, quantum) in b.chunks_exact(4).enumerate() {
        let (Some(&c0), Some(&c1), Some(&c2), Some(&c3)) = (
            quantum.first(),
            quantum.get(1),
            quantum.get(2),
            quantum.get(3),
        ) else {
            // NOT `continue`: skipping the quantum skips `oi += 3` too,
            // which shifts the tail and leaves three bytes zero — an
            // `Ok` carrying a DIFFERENT digest. See
            // [`B64Error::Invariant`].
            return Err(B64Error::Invariant);
        };
        let (v0, v1, v2) = (sixbit(c0)?, sixbit(c1)?, sixbit(c2)?);
        set(&mut out, oi, (v0 << 2) | (v1 >> 4))?;
        set(&mut out, oi + 1, ((v1 & 0x0F) << 4) | (v2 >> 2))?;
        if qi == 10 {
            if v2 & 0x03 != 0 {
                return Err(B64Error::NonCanonical);
            }
        } else {
            set(&mut out, oi + 2, ((v2 & 0x03) << 6) | sixbit(c3)?)?;
        }
        oi += 3;
    }
    Ok(out)
}

fn push6(s: &mut String, six: u32) {
    if let Some(&c) = ALPHABET.get((six & 0x3F) as usize) {
        s.push(char::from(c));
    }
}

/// Encode 32 bytes as 44 canonical base64 characters (renders the golden).
///
/// **The loop is a SLICE PATTERN, so the unreachable arm is gone rather
/// than refused.** The decoder's equivalent branch became
/// [`B64Error::Invariant`] because it has a `Result` to return; this
/// function does not, and a fallible `encode_pin` would put a
/// "cannot happen" arm at every call site. Consuming three bytes at a
/// time by pattern removes the branch instead: the `while let` ends
/// when fewer than three remain, and 32 = 10*3 + 2 makes that remainder
/// exactly the two bytes the tail below expects. Nothing can silently
/// skip a triple, because there is no arm left to take.
#[must_use]
pub fn encode_pin(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(PIN_B64_LEN);
    let mut rest: &[u8] = bytes;
    while let [high, mid, low, tail @ ..] = rest {
        let packed = (u32::from(*high) << 16) | (u32::from(*mid) << 8) | u32::from(*low);
        push6(&mut out, packed >> 18);
        push6(&mut out, packed >> 12);
        push6(&mut out, packed >> 6);
        push6(&mut out, packed);
        rest = tail;
    }
    // The 32nd byte leaves a two-byte remainder: three characters and
    // one pad, with the last character's low two bits necessarily zero.
    if let [high, mid] = rest {
        let packed = (u32::from(*high) << 16) | (u32::from(*mid) << 8);
        push6(&mut out, packed >> 18);
        push6(&mut out, packed >> 12);
        push6(&mut out, packed >> 6);
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests;
