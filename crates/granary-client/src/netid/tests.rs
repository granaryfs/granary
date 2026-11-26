// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::netid` — the client's
//! `NetworkIdentity` source, a stated
//! placeholder.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

/// It satisfies the seam through `&dyn`, which is the shape a caller
/// that does not want to be generic will hold.
#[test]
fn ambient_network_satisfies_the_seam() {
    let source: &dyn NetworkIdentity = &AmbientNetwork;
    let _: NetworkId = source.current();
}

/// It is STABLE within a process: a source that varied per call would
/// invalidate every cache on every read, which is the same as having
/// no cache at all.
#[test]
fn ambient_network_is_stable() {
    assert_eq!(AmbientNetwork.current(), AmbientNetwork.current());
    let held = AmbientNetwork;
    assert_eq!(held.current(), AmbientNetwork.current());
}

/// It is NOT the all-zero value.
///
/// The all-zero id is what an unset, zeroed field looks like, and both
/// halves of the pinned-key configuration refuse it for that reason
/// (`PinSetError::ZeroPin`, `AnchorError::ZeroKey`). A placeholder that
/// returned it would be a fail-open sentinel wearing a seam's clothes:
/// the first real implementation lands beside code comparing against
/// zero to mean "no network known".
#[test]
fn ambient_network_is_not_the_zero_sentinel() {
    assert_ne!(
        AmbientNetwork.current(),
        NetworkId::from_bytes([0_u8; 32]),
        "the zero id is the unset-configuration sentinel, not a placeholder"
    );
}

/// The value is a COMMITTED CONSTANT, not the implementation's own
/// expression evaluated a second time.
///
/// Asserting `current() == GrainId::of(PLACEHOLDER_LABEL)` would
/// restate what `current()` is: it holds for every value the label
/// could take, including one that
/// changed by accident, and it is the shape of test that passes
/// whatever the code says. The literal below is what makes a change to
/// EITHER half visible — edit the label, edit the derivation, or swap
/// `GrainId::of` for anything else, and this fails.
///
/// That is the property `PLACEHOLDER_LABEL` promises in its own doc:
/// when a real source lands its value must not silently equal this
/// one. Regenerate by printing `AmbientNetwork.current().as_bytes()`
/// as hex — deliberately a manual step, because a constant that
/// regenerates itself is the tautology again.
#[test]
fn ambient_network_is_a_committed_constant() {
    const EXPECTED: &str = "966bfb2189bab93503ac9638fa21e4188c4df57e99639adb48bf1e3a4e532d20";
    use core::fmt::Write as _;
    let got = AmbientNetwork.current().as_bytes().iter().fold(
        String::with_capacity(EXPECTED.len()),
        |mut acc, b| {
            // Infallible on a String, and discarded rather than
            // unwrapped — the same way `bin_url` renders a digest.
            let _ = write!(acc, "{b:02x}");
            acc
        },
    );
    assert_eq!(
        got, EXPECTED,
        "the phase-1 placeholder identity changed value; see PLACEHOLDER_LABEL"
    );
}
