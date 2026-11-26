// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client's [`NetworkIdentity`] source.
//!
//! **A PLACEHOLDER, and it says so.** std exposes no portable network
//! identity — no gateway MAC, no SSID, no link id — and inventing one out
//! of a hostname or an interface list would be a per-platform guess that
//! reads *wrong* to every future caller comparing two of them. So the value
//! here is a constant derived from a stated label, and nothing in Phase 1
//! reads it: `gran` is a per-command process, so there is no cache for a
//! network change to invalidate (see `granary_core::netid`).
//!
//! **What the placeholder is NOT is the all-zero id.** That value is what
//! an unset, zeroed configuration field looks like, and both halves of
//! the pinned-key pair refuse it for exactly that reason
//! (`granary_net::pin::PinSetError::ZeroPin`, [`crate::AnchorError`]'s
//! `ZeroKey`). Returning it here would plant the same fail-open sentinel a
//! third time — the first real implementation would land beside code
//! comparing against zero to mean "no network known", and a source that
//! could not answer would then compare EQUAL to one that could.
//!
//! **Read once, at `HttpStore::new`, and not cached.** Reading it is what
//! makes the seam reachable rather than dead code under `-D warnings`;
//! caching it would be the Phase-2 mechanism this deliberately does not
//! build.

use granary_core::hash::GrainId;
use granary_core::netid::{NetworkId, NetworkIdentity};

/// The label the placeholder identity is derived from.
///
/// Versioned in its own text: when a real source lands, its value must not
/// silently equal this one, and a reader comparing two persisted ids should
/// be able to see which era each came from.
const PLACEHOLDER_LABEL: &[u8] = b"granary-network-identity-v1/phase1-unknown";

/// The identity source the shipped client uses.
#[derive(Debug, Clone, Copy, Default)]
pub struct AmbientNetwork;

impl NetworkIdentity for AmbientNetwork {
    /// The digest of `PLACEHOLDER_LABEL`, WRAPPED as a [`NetworkId`].
    ///
    /// The wrap is not ceremony: `GrainId` is a content address — the
    /// identity of some bytes — and a network is not bytes. Handing a
    /// `GrainId` back would invite a caller to compare it against a real
    /// object id, and the two name spaces are unrelated.
    fn current(&self) -> NetworkId {
        NetworkId::from_bytes(*GrainId::of(PLACEHOLDER_LABEL).digest())
    }
}

#[cfg(test)]
mod tests;
