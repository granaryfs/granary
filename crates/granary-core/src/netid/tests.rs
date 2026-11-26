// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::netid` — the network-identity seam.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

/// An identity the caller pins. Nothing ambient — the same shape the
/// `Clock` suite uses, and for the same reason.
struct Pinned(NetworkId);

impl NetworkIdentity for Pinned {
    fn current(&self) -> NetworkId {
        self.0
    }
}

#[test]
fn a_pinned_source_answers_what_it_was_built_from() {
    let id = NetworkId::from_bytes([7_u8; NETWORK_ID_LEN]);
    let source = Pinned(id);
    assert_eq!(source.current(), id);
    assert_eq!(source.current(), source.current(), "twice must agree");
    assert_eq!(source.current().as_bytes(), &[7_u8; NETWORK_ID_LEN]);
}

/// The trait is dyn-compatible, and this is the test that keeps it so.
///
/// Adding a generic method or an `async fn` would break `&dyn` at the
/// call site rather than here, in whichever crate happened to hold one
/// — the storage seams are dyn-INcompatible for exactly that reason
/// (RPITIT), and the difference is worth pinning where the trait lives.
#[test]
fn the_seam_is_dyn_compatible() {
    let id = NetworkId::from_bytes([1_u8; NETWORK_ID_LEN]);
    let source: &dyn NetworkIdentity = &Pinned(id);
    assert_eq!(source.current(), id);
}

/// Distinct networks are distinct identities: equality is the whole
/// operation this type supports, so a comparison that read a prefix
/// would leave the seam unable to answer the only question it is for.
#[test]
fn different_bytes_are_different_networks() {
    let a = NetworkId::from_bytes([0xAB_u8; NETWORK_ID_LEN]);
    let mut raw = [0xAB_u8; NETWORK_ID_LEN];
    raw[NETWORK_ID_LEN - 1] ^= 1;
    assert_ne!(a, NetworkId::from_bytes(raw));
}
