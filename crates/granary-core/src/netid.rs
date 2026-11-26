// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The network-identity seam: the one way logic in this workspace
//! learns *which network it is on*. PURE — a newtype and a trait, so core
//! keeps its no-I/O property while the caller that can actually answer the
//! question implements it at the edge.
//!
//! **What the seam is for.** A long-lived client caches
//! things learned from a server, and a cache is only sound while the client
//! is still on the network it learned them on: move a laptop from an office
//! LAN to a café and a cached answer can be about a different host behind
//! the same name. The remedy is to key the cache on a network identity and
//! drop it when the identity changes — which is what this trait exists to
//! supply.
//!
//! **Phase 1 has no cache, and so this seam has nothing to invalidate.**
//! `gran` is a PER-COMMAND process: it starts, publishes or resolves, and
//! exits. Nothing it learns outlives the command, so there is no window in
//! which a network change could be observed at all — and a pin failure is
//! TERMINAL, so the one class of answer
//! that could be wrong across a network change fails the connection outright
//! rather than being cached. The seam is NAMED here anyway, so the
//! obligation is a compile-time fact rather than a note in a document, and
//! the CACHE arrives with the first long-lived client, which is when there
//! is something for it to guard.
//!
//! **ONE METHOD, AND NO TIMERS** — the [`crate::clock::Clock`] shape, for
//! the same reason. A seam with no caller cannot be tested for the property
//! that matters, so it stays at the smallest thing a caller can use:
//! "which network am I on, right now".

/// An opaque identifier for the network a client is attached to.
///
/// **Opaque, and deliberately not a structure.** No caller may read a
/// gateway address, an SSID, a link identifier or a hash preimage out of
/// this: the only operation the seam needs is EQUALITY — "is this the same
/// network as the one that answer was learned on" — and every field a
/// caller could branch on is a field an implementation would then owe
/// forever. The width is 32 bytes because every stable identifier this
/// workspace already mints is 32 bytes wide, so an implementation that has
/// only a name to work with can hash it and one that has a real identifier
/// can carry it.
///
/// It is NOT a secret and NOT an authenticator: a network identity says
/// where a client is, never who a server is. The SPKI pin is what
/// binds a client to the server it intended, and nothing here weakens or
/// substitutes for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId([u8; NETWORK_ID_LEN]);

/// Width of a [`NetworkId`], in bytes.
pub const NETWORK_ID_LEN: usize = 32;

impl NetworkId {
    /// Wrap 32 bytes as a network identity.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NETWORK_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes, for an implementation that must persist or compare them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NETWORK_ID_LEN] {
        &self.0
    }
}

/// The network-identity seam: which network is this client on?
///
/// `Send + Sync` because one identity source is shared by reference across
/// whatever tasks a client runs; the trait is dyn-compatible (no `async`,
/// no generics), like [`crate::clock::Clock`] and unlike the storage seams,
/// so a caller may hold `&dyn NetworkIdentity` when it does not want to be
/// generic.
pub trait NetworkIdentity: Send + Sync {
    /// The network this client is attached to now.
    ///
    /// Implementations must be free of side effects a caller can observe,
    /// and two calls with nothing changing underneath must answer equal:
    /// a source that varied per call would invalidate every cache on every
    /// read, which is indistinguishable from having no cache at all.
    fn current(&self) -> NetworkId;
}

#[cfg(test)]
mod tests;
