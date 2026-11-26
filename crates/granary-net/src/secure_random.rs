// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The production implementation of the cryptographic-randomness seam,
//! [`granary_core::secure_random::SecureRandom`]: the operating system's
//! entropy, read through aws-lc, the TLS provider's own backend.
//!
//! **The one sanctioned construction.** [`OsSecureRandom::fill`] is the
//! only site in the workspace allowed to name aws-lc's generator and draw
//! raw bytes from it. aws-lc's own key-generation APIs
//! (`Ed25519KeyPair::generate`, ECDSA and agreement key pairs,
//! `RandomizedNonceKey`) draw from the same OS-seeded generator internally
//! without naming a banned item; that is outside what this seam governs,
//! since they return keys, never raw bytes kept as an identity or epoch.
//! `clippy.toml` bans its type (`aws_lc_rs::rand::SystemRandom`, which
//! covers `new`, `default` and every other construction), aws-lc's free
//! `aws_lc_rs::rand::fill`, and `rustls::crypto::SecureRandom::fill`, the
//! route through the TLS provider's `secure_random`. The method bans
//! bind every crate; the type ban binds where a crate root denies
//! `clippy::disallowed_types`: the libraries of `granary-core`,
//! `granary-net`, `granary-store`, `granary-client`, `granary-server` and
//! `granary-sim`, and the `granary-server` and `gran` (`granary-cli`)
//! binaries. `granary-client` and `granary-cli` read their own
//! `clippy.toml`, which carries the same rows. The rule: the type ban
//! holds in a compilation target only if that target's own crate root
//! denies the lint, and every other root is not held to it. That covers
//! the crates whose roots do not deny it (`granary-fuse`, `granary-vfs`,
//! `granary-conformance`, `granary-bench`), and, in every crate, the
//! targets that are roots of their own and do not deny it: the simulator's
//! replay binary (`granary-sim`'s `src/bin`), integration tests under
//! `tests/`, and benches.
//!
//! **Failure is fatal in production, and that is accepted.** aws-lc's
//! `RAND_bytes` aborts the process when it cannot obtain randomness, so
//! [`SecureRandom::fill`] here returns `Err` only if a future backend
//! reports instead of aborting. An abort is a fail-stop that never yields
//! a weak value; an authority that aborts is an unclean exit, which its
//! run marker treats as a crash. On Linux an initialised `getrandom`
//! pool does not run dry, though a sandbox that refuses the call (a
//! seccomp filter returning an error, for one) still can, and takes the
//! same fatal path.
//!
//! **Independence.** aws-lc's generator is per thread and reseeds from
//! the operating system; it uses fork detection where the platform
//! supports it, with a reseeding fallback otherwise. A *live* snapshot
//! of a running process or virtual machine restored into several running
//! copies can repeat their next outputs where the platform offers neither
//! clone detection nor prediction resistance, so a granary process is
//! never cloned live. Cloning a cold image is fine: each boot seeds from
//! the operating system.
//!
//! **FIPS.** With this crate's `fips` feature, rustls selects aws-lc's
//! FIPS backend and this type reads that backend's generator. No
//! certification claim is made either way.

use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

/// The operating system's entropy (module docs). Holds nothing: each fill
/// reads aws-lc's generator afresh, so a value of this type carries no
/// state that a copy could repeat.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct OsSecureRandom;

impl OsSecureRandom {
    /// A handle on the operating system's entropy.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SecureRandom for OsSecureRandom {
    #[expect(
        clippy::disallowed_types,
        reason = "the cryptographic-randomness seam's production implementation is the one \
                  sanctioned construction of aws-lc's generator; clippy.toml bans it everywhere \
                  else"
    )]
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        aws_lc_rs::rand::SecureRandom::fill(&aws_lc_rs::rand::SystemRandom::new(), dest)
            .map_err(|_| EntropyUnavailable)
    }
}

#[cfg(test)]
mod tests;
