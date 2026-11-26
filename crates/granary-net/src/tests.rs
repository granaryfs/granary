// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate` (the crate root) — HTTP transport plumbing
//! for the grain protocol: TLS config for both sides.
//!
//! Out-of-line: `granary-net`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-server`),
//! so the module's own tests move out of the parent file while
//! it keeps its path and declares `#[cfg(test)] mod tests;` —
//! the sibling-directory form. A crate root's children live
//! directly in `src/`, not in `src/lib/`, so this file sits at
//! `src/tests.rs` rather than under a module directory.

#[test]
fn provider_has_suites() {
    assert!(!super::crypto_provider().cipher_suites.is_empty());
}
