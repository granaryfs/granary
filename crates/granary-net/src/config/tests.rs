// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::config` — the two pinned-key parsers and
//! the distinct config-key names: a TLS pin, a root-signing public
//! key, and a `key_id` locator, kept apart by their prefix
//! alone.
//!
//! Out-of-line: `granary-net`'s non-test artifact has
//! workspace consumers (`granary-client`,
//! `granary-server`), so the module's own tests move out
//! of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{
    ENV_ROOT_KEYS, ENV_TLS_PINS, KeyParseError, PinParseError, SIGNING_KEY_LEN, parse_key_set,
    parse_pin_set, parse_signing_key, parse_tls_pin, render_tls_pin,
};
use crate::b64::B64Error;
use crate::pin::PIN_LEN;

/// The §9a golden TLS pin, prefix and all.
const GOLDEN_PIN: &str = "sha256/9cvkMbAwLn9O0YZS/Gm+J7KptTwLK+jY+u5x0eCHPZE=";

/// What `GOLDEN_PIN` names.
const GOLDEN_PIN_BYTES: [u8; PIN_LEN] = [
    0xf5, 0xcb, 0xe4, 0x31, 0xb0, 0x30, 0x2e, 0x7f, 0x4e, 0xd1, 0x86, 0x52, 0xfc, 0x69, 0xbe, 0x27,
    0xb2, 0xa9, 0xb5, 0x3c, 0x0b, 0x2b, 0xe8, 0xd8, 0xfa, 0xee, 0x71, 0xd1, 0xe0, 0x87, 0x3d, 0x91,
];

/// The renderer produces the GOLDEN spelling, and the parser takes it
/// back — so a pin printed in a diagnostic is a value the operator can
/// paste into `GRANARY_TLS_PINS` unedited.
///
/// Both directions, deliberately: `render_tls_pin` alone against
/// `parse_tls_pin` would be satisfied by a pair that agreed on a
/// spelling §9a does not define.
#[test]
fn a_rendered_pin_is_the_golden_spelling_and_parses_back() {
    assert_eq!(render_tls_pin(&GOLDEN_PIN_BYTES), GOLDEN_PIN);
    assert_eq!(
        parse_tls_pin(&render_tls_pin(&GOLDEN_PIN_BYTES)),
        Ok(GOLDEN_PIN_BYTES)
    );
}

/// RFC 8032 §7.1 TEST 1's public key — the literal `granary-store`'s
/// `crypto.rs` already pins, so the two sites name one key.
const TV1_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// The same 32 bytes rendered as a root-signing PUBLIC KEY.
const GOLDEN_KEY: &str = "ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// The same 32 bytes rendered as a `key_id` LOCATOR — indistinguishable
/// from `GOLDEN_KEY` by shape, and a different thing entirely.
const GOLDEN_KEYID: &str = "keyid:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// The TV1 bytes.
const TV1_BYTES: [u8; SIGNING_KEY_LEN] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

#[test]
fn tls_pin_golden_parses() {
    assert_eq!(
        parse_tls_pin(GOLDEN_PIN),
        Ok(GOLDEN_PIN_BYTES),
        "the §9a golden pin must parse to its digest"
    );
}

#[test]
fn tls_pin_rejects_ed25519() {
    assert_eq!(
        parse_tls_pin(GOLDEN_KEY),
        Err(PinParseError::Prefix),
        "a signing key is not a TLS pin"
    );
}

#[test]
fn tls_pin_rejects_keyid() {
    assert_eq!(
        parse_tls_pin(GOLDEN_KEYID),
        Err(PinParseError::Prefix),
        "a key_id locator is not a TLS pin"
    );
}

#[test]
fn tls_pin_rejects_bare() {
    assert_eq!(
        parse_tls_pin("9cvkMbAwLn9O0YZS/Gm+J7KptTwLK+jY+u5x0eCHPZE="),
        Err(PinParseError::Prefix),
        "the prefix is the whole defence; an unprefixed body is not a pin"
    );
    assert_eq!(
        parse_tls_pin(TV1_HEX),
        Err(PinParseError::Prefix),
        "bare hex is not a pin either"
    );
}

/// The prefix is stripped ONCE, from the front. The body's own `/`
/// (alphabet position 63) is not a prefix match, and a parser that
/// stripped every `sha256/` or split on `/` would mangle it.
#[test]
fn tls_pin_prefix_is_stripped_once_and_the_body_may_contain_a_slash() {
    assert!(
        GOLDEN_PIN.matches('/').count() >= 2,
        "the golden must carry a `/` beyond the prefix's"
    );
    assert_eq!(parse_tls_pin(GOLDEN_PIN), Ok(GOLDEN_PIN_BYTES));
}

/// Degenerate bodies behind a correct prefix: the parse must reach
/// the codec and fail THERE, not succeed and not panic.
#[test]
fn tls_pin_degenerate_bodies_are_refused() {
    assert_eq!(
        parse_tls_pin("sha256/"),
        Err(PinParseError::Base64(B64Error::Length { got: 0 })),
        "an empty body is a length refusal, not a pin"
    );
    let all_pad = format!("sha256/{}", "=".repeat(44));
    assert_eq!(
        parse_tls_pin(&all_pad),
        Err(PinParseError::Base64(B64Error::Char { byte: b'=' })),
        "44 pads is not a rendering of anything"
    );
    // A DOUBLED prefix. `strip_prefix` removes one `sha256/` and the
    // rest is the body — every byte of `sha256/` is itself in the §4
    // alphabet, so nothing but the fixed WIDTH refuses this.
    let doubled = format!("sha256/{GOLDEN_PIN}");
    assert_eq!(
        parse_tls_pin(&doubled),
        Err(PinParseError::Base64(B64Error::Length { got: 51 })),
        "a doubled prefix leaves a body of the wrong width"
    );
}

#[test]
fn signing_key_golden_parses() {
    assert_eq!(
        parse_signing_key(GOLDEN_KEY),
        Ok(TV1_BYTES),
        "RFC 8032 TEST 1's public key must parse to its 32 bytes"
    );
}

#[test]
fn signing_key_rejects_sha256() {
    assert_eq!(
        parse_signing_key(GOLDEN_PIN),
        Err(KeyParseError::Prefix),
        "a TLS pin is not a signing key"
    );
}

/// A `key_id` is the SHA-256
/// of a public key, not the key: it is the same width, the same
/// alphabet, and pasting one here leaves a reader that can check no
/// signature at all — while every rejection-only test still passes.
#[test]
fn signing_key_rejects_keyid() {
    assert_eq!(
        parse_signing_key(GOLDEN_KEYID),
        Err(KeyParseError::Prefix),
        "a key_id locator is not a public key"
    );
}

#[test]
fn signing_key_rejects_bare() {
    assert_eq!(
        parse_signing_key(TV1_HEX),
        Err(KeyParseError::Prefix),
        "the prefix is the whole defence; bare hex is not a key"
    );
}

/// A deliberate tightening (R11-h): uppercase hex renders the same
/// key a second way, and two renderings of one anchor is exactly the
/// accept-set blindness §9a closes.
#[test]
fn signing_key_rejects_uppercase() {
    let shouted = format!("ed25519:{}", TV1_HEX.to_uppercase());
    assert_eq!(
        parse_signing_key(&shouted),
        Err(KeyParseError::HexChar { byte: b'D' }),
        "uppercase hex is a second rendering and is refused"
    );
}

#[test]
fn signing_key_rejects_wrong_length() {
    assert_eq!(
        parse_signing_key("ed25519:"),
        Err(KeyParseError::HexLength { got: 0 }),
        "an empty body is not a key"
    );
    assert_eq!(
        parse_signing_key(&format!("ed25519:{TV1_HEX}00")),
        Err(KeyParseError::HexLength { got: 66 }),
        "66 digits is not a key"
    );
    let short = TV1_HEX.get(..63).unwrap_or_default();
    assert_eq!(
        parse_signing_key(&format!("ed25519:{short}")),
        Err(KeyParseError::HexLength { got: 63 }),
        "an odd body length is refused before any nibble is read"
    );
}

/// **The parsers' pairwise matrix.** One 32-byte value, rendered four ways,
/// fed to BOTH parsers: exactly two of the eight calls succeed, and
/// they are the two on the diagonal.
#[test]
fn distinct_consumers_reject_each_others_forms() {
    let pin_form = GOLDEN_PIN;
    let key_form = GOLDEN_KEY;
    let keyid_form = GOLDEN_KEYID;
    let bare_form = TV1_HEX;

    assert!(parse_tls_pin(pin_form).is_ok(), "sha256/ -> pin parser");
    assert!(parse_tls_pin(key_form).is_err(), "ed25519: -> pin parser");
    assert!(parse_tls_pin(keyid_form).is_err(), "keyid: -> pin parser");
    assert!(parse_tls_pin(bare_form).is_err(), "bare -> pin parser");

    assert!(
        parse_signing_key(pin_form).is_err(),
        "sha256/ -> key parser"
    );
    assert!(
        parse_signing_key(key_form).is_ok(),
        "ed25519: -> key parser"
    );
    assert!(
        parse_signing_key(keyid_form).is_err(),
        "keyid: -> key parser"
    );
    assert!(parse_signing_key(bare_form).is_err(), "bare -> key parser");

    // The NAMES are distinct too, and neither is reachable from the
    // other by a prefix match.
    assert_ne!(ENV_TLS_PINS, ENV_ROOT_KEYS);
    assert!(!ENV_TLS_PINS.starts_with(ENV_ROOT_KEYS));
    assert!(!ENV_ROOT_KEYS.starts_with(ENV_TLS_PINS));
}

#[test]
fn pin_set_splits_and_refuses_an_empty_token() {
    assert_eq!(
        parse_pin_set(""),
        Ok(Vec::new()),
        "unset is the empty set, which refuses every certificate"
    );
    assert_eq!(
        parse_pin_set("   \t "),
        Ok(Vec::new()),
        "whitespace is unset too"
    );
    assert_eq!(
        parse_pin_set(&format!(" {GOLDEN_PIN} , {GOLDEN_PIN} ")),
        Ok(vec![GOLDEN_PIN_BYTES, GOLDEN_PIN_BYTES]),
        "tokens are trimmed and both are parsed"
    );
    assert_eq!(
        parse_pin_set(","),
        Err(PinParseError::Prefix),
        "a lone comma is two empty tokens, not an empty set"
    );
    assert_eq!(
        parse_pin_set(&format!("{GOLDEN_PIN},")),
        Err(PinParseError::Prefix),
        "a trailing comma would silently drop a pin"
    );
}

#[test]
fn key_set_splits_and_refuses_an_empty_token() {
    assert_eq!(parse_key_set(""), Ok(Vec::new()));
    assert_eq!(parse_key_set("  "), Ok(Vec::new()));
    assert_eq!(
        parse_key_set(&format!("{GOLDEN_KEY} , {GOLDEN_KEY}")),
        Ok(vec![TV1_BYTES, TV1_BYTES])
    );
    assert_eq!(
        parse_key_set(","),
        Err(KeyParseError::Prefix),
        "a lone comma is two empty tokens"
    );
    assert_eq!(
        parse_key_set(&format!("{GOLDEN_KEY},{GOLDEN_KEYID}")),
        Err(KeyParseError::Prefix),
        "one bad token refuses the whole set"
    );
}
