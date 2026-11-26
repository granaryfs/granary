// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::identity` — the writer identity seam.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

#[test]
fn a_writer_identity_is_exactly_sixteen_bytes_and_round_trips_them() {
    assert_eq!(WRITER_IDENTITY_LEN, 16);
    let bytes = *b"granary-test-id!";
    let id = WriterIdentity::from_bytes(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

/// The bytes are the WHOLE of the value: two identities built from
/// the same bytes are equal and two built from different bytes are
/// not. No ambient input, no construction counter, no interior
/// state — which is what lets a replay hand the same identity in
/// twice and get the same signed root back.
#[test]
fn identity_is_determined_by_its_bytes_and_nothing_else() {
    let a = WriterIdentity::from_bytes(*b"granary-test-id!");
    let b = WriterIdentity::from_bytes(*b"granary-test-id!");
    let c = WriterIdentity::from_bytes(*b"granary-test-id?");
    assert_eq!(a, b);
    assert_ne!(a, c);
}
