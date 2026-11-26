// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which admission policy this server applies to an ingested bin
//! (§13.5).
//!
//! **A type with two constructors, one of which a `cargo build` cannot
//! reach.** §13.5 states its rule over REACHABILITY rather than over
//! configuration — "no code path reachable from the production binary's
//! composition root may construct the seam-only policy" — because a
//! configuration key is only one of at least four doors, the others
//! being a public constructor, a cargo feature, and a seam-only
//! default. Naming the invariant instead of the door is what closes all
//! four.
//!
//! §13.5 offers two ways to satisfy it and this takes the FIRST:
//! `#[cfg(test)]`, which a build of the binary does not compile at all.
//! So rule 2 — assert the feature's absence, and gate the assertion —
//! is not engaged, which is why rule 2 is written conditionally. It is
//! the same shape, for the same reason, as `admit_declaring`'s
//! non-enforcing extent profile.
//!
//! **The seam-only profile is not optional and is not a loophole.**
//! §13.4 and §13.5 require BOTH profiles of a conforming
//! implementation: the shared conformance bodies store a 100-byte
//! non-bin under its own digest and require `Ok(true)`, which a
//! verifying server cannot serve, and §5.1 permits nothing but the
//! verifying profile on anything shipped. The corpus then sends the same
//! request under both and demands a different POSITIVE answer in each,
//! so declaring a profile is asserting a fact the next row checks.

/// The ingest admission policy: does this server verify a bin's grains
/// before storing it?
///
/// The field is private and there is no `bool` constructor, so a policy
/// cannot be assembled from a value someone computed — it is one of
/// exactly two named things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyPolicy {
    verifying: bool,
}

impl VerifyPolicy {
    /// §5.1's policy: unpack the bin, verify every grain hash, enforce
    /// the layout invariants.
    ///
    /// **It hardcodes ON, and takes no argument.** A constructor that
    /// took the flag would make the accept set the caller's to pick,
    /// which is the defect this whole shape exists to close — the same
    /// one `admit` closes by naming `DECLARED_MAX_EXTENT` rather than
    /// receiving it.
    #[must_use]
    pub const fn verifying() -> Self {
        Self { verifying: true }
    }

    /// The §13.5 seam-only profile: `BinStore::put_bin`'s contract and
    /// nothing above it.
    ///
    /// `#[cfg(test)]`, and that is the whole of the reachability
    /// argument — see the module doc.
    #[cfg(test)]
    pub(crate) const fn seam_only() -> Self {
        Self { verifying: false }
    }

    /// Does this policy verify?
    #[must_use]
    pub const fn verifies(self) -> bool {
        self.verifying
    }
}

#[cfg(test)]
mod tests;
