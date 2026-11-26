// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The second determinism seam: randomness. [`crate::clock::Clock`] is
//! the first — this module is its exact counterpart in shape: one
//! trait, a production implementation that touches the outside world,
//! and a deterministic implementation a caller can replay. Retry
//! jitter is this seam's first production consumer.
//!
//! **NOT a CSPRNG, and the trait says so.** [`Rng`] exists for jitter
//! and tie-breaking. Nothing security-relevant reads from it, because
//! nothing security-relevant is allowed to: a value that must not
//! collide — an authority log's epoch, a writer identity — is drawn
//! through [`crate::secure_random::SecureRandom`], the deliberate door
//! for cryptographic randomness. Two draws from this seam's 64-bit
//! state give at most 2^64 values, never the 2^128 a 16-byte identity
//! needs.
//!
//! **`RandomState` may appear in exactly one place: here.**
//! `clippy.toml` names `std::hash::RandomState` in `disallowed-types`
//! for the same reason it names `HashMap`/`HashSet` — ambient
//! per-process state is nondeterministic input the sim cannot seed.
//! The lint is opted into PER CRATE ROOT (`disallowed_types` is
//! "allow" on the workspace lints line): the core, sim, client and
//! server lib roots deny it, which covers this seam's home and its
//! first consumer's; the remaining lib crates and the bin roots do not
//! currently enable it. [`ProcessRng::new`] is the one
//! sanctioned site where ambient entropy is allowed to enter production
//! code, gated behind an `#[expect]` that documents why. Two independent
//! `RandomState` draws seed a splitmix64 counter rather than being
//! consumed directly — the seam's *mixing* algorithm is identical
//! between [`ProcessRng`] and [`SeededRng`], and only the *seed* differs
//! between "ambient" and "replayable", which is what makes the seeded
//! path a faithful stand-in for the process path in tests.
//!
//! **This module does not hand granary-sim a second source of
//! randomness.** `granary-sim` already owns a PCG-XSH-RR generator
//! (`granary_sim::rng::Rng`) that must remain the
//! sim's *only* source of this seam's randomness — introducing a second
//! one here would let a sim-driven scenario draw bits the seed does not
//! control, breaking replay from that seed. Instead,
//! `granary-sim` implements this crate's [`Rng`] trait directly on its
//! own PCG type (see that crate's `rng` module for the composition), so
//! sim-driven client code draws through the seam from the sim's own
//! generator. [`SeededRng`] here is for unit tests that run outside the
//! sim harness — nothing the sim schedules should construct one.

#[expect(
    clippy::disallowed_types,
    reason = "the Rng seam IS the sanctioned door: ambient process \
              entropy enters production here and only here (clippy.toml \
              bans RandomState everywhere else for exactly that reason)"
)]
use std::hash::RandomState;
use std::hash::{BuildHasher, Hasher};

/// The randomness determinism seam. Production code never reaches for
/// ambient entropy; it takes an `&mut dyn Rng` (or generic `R: Rng`)
/// from its caller, and the binary's composition root decides which
/// implementation exists. NOT cryptographic — jitter and tie-breaking
/// only. Anything security-relevant draws from
/// [`crate::secure_random::SecureRandom`] instead.
///
/// Implementors owe **approximately uniform bits**: [`Rng::below`]'s
/// rejection loop terminates (with overwhelming probability) only
/// because `next_u64`'s outputs spread over the whole space. A
/// degenerate constant stream can make `below` spin forever — an
/// always-0 implementation does, for every non-power-of-two bound
/// ≥ 3 — so a test double must script a FINITE draw sequence, never a
/// constant.
///
/// Deliberately neither `Send`- nor `Sync`-bounded (contrast
/// [`crate::clock::Clock`], which states why it is both): an `Rng` is
/// exclusively borrowed (`&mut`), never shared, and Phase 1's client
/// runs a current-thread runtime, so no cross-thread obligation
/// exists to state. If a spawned task ever holds a draw across an
/// `.await`, add the bound at that call site, not here by precaution.
pub trait Rng {
    /// The next 64 random bits.
    fn next_u64(&mut self) -> u64;

    /// A value in `[0, bound)`. `bound == 0` answers 0. Rejection
    /// sampling over the widened product — no modulo bias.
    ///
    /// Lemire's method: widen one draw to 128 bits, multiply by
    /// `bound`, and take the high 64 bits as the candidate answer — that
    /// candidate is always `< bound` by construction (`x < 2^64` and
    /// `bound <= 2^64`, so `x * bound < bound * 2^64`, so
    /// `(x * bound) >> 64 < bound`). The low 64 bits decide whether to
    /// keep it: `2^64 mod bound` values at the bottom of the output
    /// range would otherwise be favoured by a plain `% bound` reduction,
    /// so those are rejected and redrawn. See this module's
    /// `below_never_spins_forever_because_acceptance_never_drops_below_half`
    /// test for why the redraw loop terminates.
    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        // Lemire's multiply-shift with a rejection zone.
        loop {
            let x = self.next_u64();
            let m = u128::from(x) * u128::from(bound);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the low half is the deliberate truncation the \
                          rejection test needs"
            )]
            let low = m as u64;
            if low >= bound.wrapping_neg() % bound {
                // The high half of a u64*u64 product fits u64 by
                // construction; clippy proves the cast lossless, so an
                // expect here would itself fail as
                // unfulfilled.
                return (m >> 64) as u64;
            }
        }
    }
}

/// Process-entropy implementation: two independent `RandomState`s
/// (each draws fresh process-random `SipHash` keys) feed a splitmix64
/// counter stream. Not cryptographic; stated in the trait docs.
#[derive(Debug)]
pub struct ProcessRng {
    state: u64,
}

impl ProcessRng {
    /// Seeds from two [`RandomState`] hashes, `XOR`ed together with
    /// the second rotated 32 bits so shared structure between the two
    /// draws cannot cancel out in either half alone. std documents
    /// only that each `RandomState` is "initialized with random keys";
    /// the long-standing implementation draws OS entropy once PER
    /// THREAD and derives per-instance keys from a counter, so the two
    /// finishes here are distinct-by-construction while their
    /// independence is computational (`SipHash` as a PRF), not two
    /// separate OS draws. That documented promise, twice, is this
    /// seam's entire contact with the ambient world; everything
    /// downstream ([`Rng::next_u64`], [`Rng::below`]) is the same
    /// deterministic splitmix64 step [`SeededRng`] runs from a
    /// caller-chosen seed instead.
    #[must_use]
    #[expect(
        clippy::disallowed_types,
        reason = "the seam's production constructor is the one sanctioned \
                  entry for ambient entropy"
    )]
    pub fn new() -> Self {
        let a = RandomState::new().build_hasher().finish();
        let b = RandomState::new().build_hasher().finish();
        Self {
            state: a ^ b.rotate_left(32),
        }
    }
}

impl Default for ProcessRng {
    fn default() -> Self {
        Self::new()
    }
}

impl Rng for ProcessRng {
    fn next_u64(&mut self) -> u64 {
        // splitmix64 step.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Seeded, deterministic — the sim/test implementation.
///
/// Same splitmix64 step as [`ProcessRng`], seeded from a caller-chosen
/// `u64` instead of ambient entropy — a replay needs only the seed, not
/// a process to have run first. This is what a unit test outside the
/// sim harness reaches for; sim-scheduled code draws through [`Rng`]
/// from `granary_sim::rng::Rng`'s own PCG stream instead,
/// so this type has no business appearing on that path.
#[derive(Debug)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    /// XORs the seed with splitmix64's golden-ratio constant γ before
    /// the first step. NOT to keep zero bits away from the mixer —
    /// [`Rng::next_u64`] adds γ before mixing, so seed 0 would reach
    /// the mixer as γ regardless — but a deliberate de-alignment from
    /// the raw splitmix64 counter convention: `new(s)` emits the
    /// reference stream for `s ^ γ`, so `new(γ)` ≡ the reference's
    /// seed-0 stream, which is exactly the handle
    /// `seeded_rng_matches_the_splitmix64_reference_vector` uses.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }
}

impl Rng for SeededRng {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests;
