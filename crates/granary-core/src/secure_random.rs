// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The cryptographic-randomness seam: the only source of the raw random
//! bytes of a value that must not collide with another drawn anywhere
//! else. [`crate::rng::Rng`] is not that source and never becomes it: its production implementation
//! holds 64 bits of state, so any number of draws from it give at most
//! 2^64 distinct values, and it exists for jitter and tie-breaking.
//!
//! What draws here: an authority log's epoch (a new log for a volume
//! always takes a new one), a publisher's caller-supplied writer
//! identity, and an enrolled
//! principal's id, minted by the local enrollment verb.
//! Each is 16 bytes,
//! and the property each needs is a collision bound: two values drawn
//! by different processes, on one host or on many, are equal only with
//! the birthday probability on 128 bits. That needs two things, and the
//! seam can promise only the first:
//!
//! - **every byte of the value comes from the draw.** A caller fills the
//!   whole value and keeps all of it: no truncation, no masking, and no
//!   counter, clock, host or pid mixed in or substituted;
//! - **independent streams per process.** The production implementation
//!   reads the operating system's entropy, which is independent per boot
//!   of a host. A running process or virtual machine that is cloned live
//!   (a memory snapshot restored into several running copies) can repeat
//!   its next outputs where the platform cannot detect the clone, so a
//!   granary process is never cloned live. Cloning a cold image is fine:
//!   each boot seeds afresh from the operating system.
//!
//! **Where each implementation lives.** This crate holds the trait only.
//! The production implementation, `granary_net::secure_random::OsSecureRandom`,
//! is the one place in the workspace allowed to draw raw bytes from the
//! operating system's generator; `clippy.toml` bans every other route to
//! those bytes. What this seam does not govern: key generation inside
//! aws-lc's own APIs (`Ed25519KeyPair::generate`, which `gran` uses to
//! create its signing key, ECDSA and agreement key pairs,
//! `RandomizedNonceKey`) draws from aws-lc's generator without naming a
//! banned item. Those draws are still seeded from the operating system,
//! at the same strength, but they produce keys inside aws-lc, never raw
//! bytes a caller keeps as a collision-relevant value. The
//! simulator's seeded implementation lives in `granary-sim`, which no
//! production crate takes as a normal or build dependency (the
//! resolved-graph gate, `scripts/check-licence-resolved.py`, refuses
//! one). A unit test that
//! needs known bytes implements the trait locally.

/// The operating system's entropy could not be read, so no value was
/// drawn. A caller refuses the operation that needed the value: it never
/// falls back to [`crate::rng::Rng`], to zeros or to a counter, and it
/// never keeps the bytes a failed fill left in its buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyUnavailable;

impl std::fmt::Display for EntropyUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no cryptographic randomness was available")
    }
}

impl std::error::Error for EntropyUnavailable {}

/// A source of cryptographic randomness (module docs): the only source of
/// the raw bytes of a value whose uniqueness rests on its randomness.
///
/// Successive fills continue one stream; an implementation never repeats
/// output it has already given.
///
/// Deliberately neither `Send`- nor `Sync`-bounded, like
/// [`crate::rng::Rng`]: a draw borrows the source exclusively, and a
/// consumer that moves one across threads states the bound where it
/// does.
pub trait SecureRandom {
    /// Fill all of `dest` with random bytes.
    ///
    /// # Errors
    /// [`EntropyUnavailable`] when no randomness could be drawn. `dest`
    /// may then hold anything, some of it written by this call; the
    /// caller discards it.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable>;
}
