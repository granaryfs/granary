// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::cache::marker` — cache identity: the marker's
//! render, its two checkers, the tuple and origin-line grammars, and the
//! orphaned-txn sweep.
//!
//! Out-of-line, beside its child. It carries the file-scoped
//! `#![cfg(test)]` shield the fsguard scanner needs at this
//! depth, and NO `#![expect]`: the one row the caller map gives
//! this child renders a marker string and touches no filesystem,
//! so it fulfils no `clippy::disallowed_methods` licence.

#![cfg(test)]

use super::*;

#[test]
fn marker_contents_render_the_tuple_and_origin_lines() {
    let o = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0xAB; 32],
        root_key_id: None,
    };
    let rendered = marker_contents(&o);
    assert_eq!(
        rendered,
        format!(
            "granary-cache-version 1\nchunker {CHUNKER_SPEC}\nhash blake3\n\
             origin https://example.invalid/ {}\n",
            hex32(&[0xAB; 32])
        )
    );

    let with_key = CacheOrigin {
        root_key_id: Some([0xCD; 32]),
        ..o
    };
    let rendered_with_key = marker_contents(&with_key);
    let expected_with_key = format!(
        "{} {}\n",
        rendered.trim_end_matches('\n'),
        hex32(&[0xCD; 32])
    );
    assert_eq!(rendered_with_key, expected_with_key);
    // The field COUNT differs, not just the content — a 3-field and
    // a 4-field origin line are different values, never one another
    // with a placeholder.
    assert_ne!(rendered, rendered_with_key);
}
