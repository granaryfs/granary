// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The two pinned-key parsers and the distinct
//! config-key NAMES. A TLS pin is `sha256/`+base64; a root-signing PUBLIC KEY
//! is `ed25519:`+64hex; a `key_id` LOCATOR is `keyid:`+64hex. The two hex
//! forms differ only by prefix, so the prefix is the ENTIRE defence — a parser
//! that infers from shape reopens the paste hazard. The
//! config holds a PUBLIC KEY, never a `key_id`: [`parse_signing_key`] rejecting
//! `keyid:` is the load-bearing case (accepting it leaves the reader unable to
//! check any signature while every rejection-only test passes).
//!
//! **What is NOT here.** The pin-set COUNT cap and the all-zero-digest
//! refusal live in [`crate::pin::PinnedServerVerifier::new`], where a pin
//! set assembled by any route — not only this parser — has to pass them.
//! A duplicate check here would be a second accept set to keep in step.

use crate::b64::{self, B64Error};
use crate::pin::{PIN_LEN, SpkiPin};

/// Width of a raw Ed25519 public key, in bytes.
pub const SIGNING_KEY_LEN: usize = 32;

/// Where the client TLS verifier's pin set is configured.
pub const ENV_TLS_PINS: &str = "GRANARY_TLS_PINS";

/// Where the reader's root-signing trust anchors are configured.
///
/// A DIFFERENT name from [`ENV_TLS_PINS`], and neither is a prefix of the
/// other: the TLS and root-signing consumers must not be reachable from one another's
/// configuration by a typo or a prefix match.
pub const ENV_ROOT_KEYS: &str = "GRANARY_ROOT_KEYS";

/// Why a value is not a `sha256/`-prefixed TLS pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinParseError {
    /// The value does not start with `sha256/` — an `ed25519:`, a
    /// `keyid:`, or an unprefixed digest all land here.
    Prefix,
    /// The prefix was right and the body is not the one canonical
    /// rendering of 32 bytes.
    Base64(B64Error),
}

impl core::fmt::Display for PinParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Prefix => f.write_str("a TLS pin is `sha256/` followed by 44 base64 characters"),
            Self::Base64(source) => write!(f, "TLS pin body: {source}"),
        }
    }
}

impl std::error::Error for PinParseError {}

/// Why a value is not an `ed25519:`-prefixed root-signing public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyParseError {
    /// The value does not start with `ed25519:` — a `sha256/`, a
    /// `keyid:` LOCATOR, or bare hex all land here. The `keyid:` case is
    /// the load-bearing one: a locator is not a key, and a reader
    /// configured with one can verify nothing.
    Prefix,
    /// The prefix was right and the body is not 64 hex digits.
    HexLength {
        /// How many bytes the body held.
        got: usize,
    },
    /// A byte outside `0-9a-f`. Uppercase is refused here: the canonical
    /// rendering is lowercase, and a second rendering of one key is the
    /// accept-set-blindness hazard §9a closes.
    HexChar {
        /// The offending byte.
        byte: u8,
    },
    /// An internal invariant of the hex decoder did not hold: a pair
    /// `chunks_exact(2)` did not produce two bytes for.
    ///
    /// **Unreachable, and REFUSED rather than skipped.** The length
    /// check makes a short pair impossible. Refusing an invariant
    /// failure prevents returning a partially written key as `Ok`.
    Invariant,
}

impl core::fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Prefix => f.write_str(
                "a root signing key is `ed25519:` followed by 64 lowercase hex digits \
                 (a `keyid:` locator is not a key)",
            ),
            Self::HexLength { got } => write!(
                f,
                "a root signing key body is {} hex digits, got {got}",
                SIGNING_KEY_LEN * 2
            ),
            Self::HexChar { byte } => write!(
                f,
                "a root signing key body has a non-lowercase-hex byte {byte:#04x}"
            ),
            Self::Invariant => f.write_str("root signing key hex codec invariant violated"),
        }
    }
}

impl std::error::Error for KeyParseError {}

/// Parse ONE TLS SPKI pin: `sha256/` + 44 canonical base64 → 32 bytes.
///
/// Rejects `ed25519:`, `keyid:` and any unprefixed value at the prefix.
///
/// # Errors
/// [`PinParseError`].
pub fn parse_tls_pin(s: &str) -> Result<SpkiPin, PinParseError> {
    // `strip_prefix` removes ONLY the leading `sha256/`; the base64 body
    // may itself contain `/` (alphabet position 63), which is not a
    // prefix match and must survive into the codec.
    let body = s.strip_prefix("sha256/").ok_or(PinParseError::Prefix)?;
    let bytes = b64::decode_pin(body).map_err(PinParseError::Base64)?;
    let pin: SpkiPin = bytes;
    debug_assert_eq!(pin.len(), PIN_LEN);
    Ok(pin)
}

/// Render one TLS pin in the EXACT form [`parse_tls_pin`] accepts.
///
/// **Here rather than at the caller, because the prefix is the entire
/// defence.** This module's own header says a parser that infers a key's
/// kind from its shape reopens the paste hazard; a renderer that spelled
/// `sha256/` somewhere else is the same hazard from the other side — one
/// site drifts, and a diagnostic starts printing something an operator
/// cannot paste back into [`ENV_TLS_PINS`]. The round trip is the test.
#[must_use]
pub fn render_tls_pin(pin: &SpkiPin) -> String {
    format!("sha256/{}", b64::encode_pin(pin))
}

/// A comma-separated pin SET.
///
/// Empty/whitespace → empty set (refuses every cert, so "unset" fails
/// closed); a non-empty list rejects an empty token so a typo cannot
/// silently drop a pin. The count cap and the zero-digest refusal live
/// in the verifier.
///
/// # Errors
/// [`PinParseError`] on the first token that does not parse.
pub fn parse_pin_set(list: &str) -> Result<Vec<SpkiPin>, PinParseError> {
    if list.trim().is_empty() {
        return Ok(Vec::new());
    }
    list.split(',').map(|t| parse_tls_pin(t.trim())).collect()
}

/// Parse ONE root-signing public key: `ed25519:` + 64 lowercase hex → 32
/// bytes.
///
/// Rejects `sha256/`, `keyid:`, bare, and uppercase hex.
///
/// # Errors
/// [`KeyParseError`].
pub fn parse_signing_key(s: &str) -> Result<[u8; SIGNING_KEY_LEN], KeyParseError> {
    let body = s.strip_prefix("ed25519:").ok_or(KeyParseError::Prefix)?;
    decode_hex32(body)
}

/// A comma-separated root-signing-key SET, on [`parse_pin_set`]'s rules.
///
/// # Errors
/// [`KeyParseError`] on the first token that does not parse.
pub fn parse_key_set(list: &str) -> Result<Vec<[u8; SIGNING_KEY_LEN]>, KeyParseError> {
    if list.trim().is_empty() {
        return Ok(Vec::new());
    }
    list.split(',')
        .map(|t| parse_signing_key(t.trim()))
        .collect()
}

pub(crate) fn decode_hex32(s: &str) -> Result<[u8; SIGNING_KEY_LEN], KeyParseError> {
    let b = s.as_bytes();
    if b.len() != SIGNING_KEY_LEN * 2 {
        return Err(KeyParseError::HexLength { got: b.len() });
    }
    let mut out = [0_u8; SIGNING_KEY_LEN];
    for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let (Some(&h), Some(&l)) = (pair.first(), pair.get(1)) else {
            // NOT `continue`: the zipped slot would stay at its
            // initialised zero and the walk would carry on, so this
            // would return `Ok` with a DIFFERENT KEY. See
            // [`KeyParseError::Invariant`].
            return Err(KeyParseError::Invariant);
        };
        *slot = (nibble(h)? << 4) | nibble(l)?;
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, KeyParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        // Uppercase is NOT here: the canonical rendering is lowercase,
        // and a second rendering of one anchor is accept-set blindness.
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(KeyParseError::HexChar { byte: c }),
    }
}

#[cfg(test)]
mod tests;
