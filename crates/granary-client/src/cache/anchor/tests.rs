// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::cache::anchor` — the anchor file's field
//! grammars, its whole-file parser and the renderer that inverts it.
//!
//! Out-of-line, beside its child. It carries the
//! file-scoped `#![cfg(test)]` shield the fsguard
//! scanner needs at this depth, and NO `#![expect]`:
//! the one row the caller map gives this child
//! parses a byte string and touches no filesystem.

#![cfg(test)]

use super::*;

/// The stamp field's canonical-form rule: a leading zero (other than
/// the bare digit `"0"` itself) is refused, not silently
/// normalized. `render_anchor_bytes` writes the stamp as a plain
/// `{i64}` with no zero-padding, so an accepting parser would let
/// `"05"` and `"5"` both decode to `5` while only `"5"` re-renders —
/// a canonical-form violation `fuzz_probe::anchor_decode_probe`'s
/// own assertion exists to catch.
#[test]
fn a_leading_zero_stamp_is_refused_not_silently_normalized() {
    let bytes = b"seq 00000000000000000007\nhint 00000000000000000007 t 0500000000\n";
    assert_eq!(
        parse_anchor_bytes(bytes),
        None,
        "a leading-zero stamp must degrade the whole file to absent, not decode to a \
         different value than what was written"
    );

    // The canonical single-digit "0" stamp is still legal.
    let bytes_zero = b"seq 00000000000000000007\nhint 00000000000000000007 t 0\n";
    let anchor = parse_anchor_bytes(bytes_zero)
        .unwrap_or_else(|| panic!("a bare \"0\" stamp must still parse"));
    assert_eq!(anchor.hint.map(|h| h.stamp_secs), Some(0));
}
