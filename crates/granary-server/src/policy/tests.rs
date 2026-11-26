// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::policy` — which admission policy the server
//! applies to an ingested bin (§13.5).
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::VerifyPolicy;

/// The two profiles are two answers, and the SHIPPED one verifies.
///
/// A tautology to read and not one to run: it is the row that fails
/// if `verifying()` ever grows a parameter or stops hardcoding, and
/// §5.1 permits nothing else on a shipped server.
#[test]
fn the_only_public_constructor_verifies() {
    assert!(VerifyPolicy::verifying().verifies());
    assert!(!VerifyPolicy::seam_only().verifies());
    assert_ne!(VerifyPolicy::verifying(), VerifyPolicy::seam_only());
}
