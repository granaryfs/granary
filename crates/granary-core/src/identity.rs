// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Who is publishing, as a value the caller supplies.
//! It feeds the `writer_uuid` preimage in
//! `granary-client`'s publish path.
//!
//! Its own module rather than a corner of [`crate::clock`]: the two
//! land together because both replace an ambient read, but the
//! normative statement each carries is about a different object — one
//! fixes the SHAPE OF A TRAIT, this one fixes the WIDTH OF A VALUE —
//! and a module doc is where a normative statement lives.
//!
//! **SIXTEEN BYTES, NOT A PID.** A pid is small (typically well under
//! 2^22) and carries no host component, so it collides freely across
//! machines: two hosts publishing the same tree to the same volume in
//! the same second would derive the SAME `writer_uuid` — exactly the
//! multi-writer case the field exists to disambiguate.
//! Sixteen bytes leave room for a host
//! component, and the type refuses to be anything narrower.
//! This is a one-time behaviour change
//! in the derivation of a SIGNED
//! field. Doing it twice would cost more than doing it right, which is
//! why the width is chosen for the multi-writer case now rather than
//! for the single-host case in front of us.
//!
//! **Freshness is the CALLER's contract, not the format's.**
//! A caller meets it by drawing the identity's
//! sixteen bytes from [`crate::secure_random::SecureRandom`], once per
//! new publication, and keeping every byte; a retransmission of bytes
//! already prepared reuses the identity it was prepared with and never
//! draws again. Two publishes that deliberately share every input — a
//! replay, or a re-run with the same randomness stream at the same
//! position and a pinned clock — deliberately share a `writer_uuid`, and
//! that is what makes re-run convergence a testable property: a test
//! gets it from a local [`crate::secure_random::SecureRandom`] that
//! returns known bytes.

/// Bytes in a [`WriterIdentity`]. Independent of
/// [`crate::root::WRITER_UUID_LEN`], which happens to be the same
/// number: one is the width of an input, the other the width of a
/// FORMAT FIELD, and only the second is frozen by the format.
pub const WRITER_IDENTITY_LEN: usize = 16;

/// Sixteen opaque bytes naming the writer of a publish.
///
/// The CLI fills all sixteen from the operating system's entropy,
/// through [`crate::secure_random::SecureRandom`], once per new
/// publication: nothing two
/// publishers can share — a host, a pid, a clock reading, a count —
/// enters them. The simulator uses its node id, which is injective per
/// node. Neither is this type's business: it carries the bytes and
/// nothing else, so that whoever builds them owns the uniqueness claim
/// and it can be stated honestly at the one place it is made.
///
/// Not a secret and not a capability — the derived `writer_uuid` is
/// published in the clear inside every signed root — so `Debug` prints
/// the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriterIdentity([u8; WRITER_IDENTITY_LEN]);

impl WriterIdentity {
    /// Take the bytes as given. Total: every 16-byte value is a legal
    /// identity, including all-zero — this type validates a WIDTH, and
    /// inventing a content rule here would only push the real
    /// uniqueness question out of sight.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; WRITER_IDENTITY_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes, in the order they will enter a hash preimage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WRITER_IDENTITY_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests;
