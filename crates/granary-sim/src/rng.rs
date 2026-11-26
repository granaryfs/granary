// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! PCG-XSH-RR 64/32 — the sim's source of jitter, scheduling and
//! tie-breaking randomness, owned here. The replay seed is the sim's sole
//! source of randomness: this generator is seeded from it, and so is
//! every cryptographic-randomness stream
//! ([`crate::secure_random::SeededSecureRandom::for_incarnation`]).
//!
//! **Value-stable by construction, because we own it.** The sim's whole
//! claim is that one seed replays one byte-identical run, which means the
//! generator's output stream is part of the harness's contract. `rand`
//! will not make that promise: the Rand Book's reproducibility chapter
//! declares `StdRng` and `SmallRng` *non-portable* — opted out of every
//! reproducibility guarantee — and as of rand 0.10 a non-portable item
//! may change values in a **patch** release. Even items rand calls
//! *portable* may break values in a **minor** release, and the policy
//! covers **distributions** as well as raw streams: rand 0.9.0 shipped a
//! changelog section titled "Reproducibility-breaking changes" that
//! re-based `Uniform` on Canon's/Lemire's method and gave `shuffle`,
//! `choose` and friends new algorithms. So `gen_range`/`random_range` is
//! unusable here whatever generator backs it — which is why [`Rng::below`]
//! is our own documented reduction rather than a distribution.
//!
//! **The field pins or hand-rolls, and the project that does not is the
//! cautionary case.** madsim holds a `Xoshiro256PlusPlus`; shuttle (AWS)
//! holds a `Pcg64Mcg`; `TigerBeetle` hand-rolls `src/stdx/prng.zig` rather
//! than use Zig's stdlib, saying in the file that the reason is to
//! isolate itself from stdlib and PRNG-algorithm churn. turmoil uses
//! `rand::rngs::SmallRng` — exactly the type the book declares
//! non-portable, and the risk pattern this module avoids.
//!
//! **PCG-XSH-RR rather than xoshiro256\*\* because it has an OFFICIAL
//! published known-answer vector.** Vigna's xoshiro page publishes no
//! example output, and `rand_xoshiro`'s in-tree vector cites the 128-bit
//! reference inside the 256-bit generator's test — an upstream labelling
//! inconsistency. A generator whose correctness cannot be pinned against
//! its author's own output is a generator whose transcription errors are
//! invisible. `pcg32_matches_the_reference_vector` is that pin, and it is
//! the reason to prefer this algorithm at all: if it ever fails, this
//! file is wrong.

/// The PCG-XSH-RR 64/32 multiplier (`PCG_DEFAULT_MULTIPLIER_64`).
const MULT: u64 = 6_364_136_223_846_793_005;

/// A seeded PCG-XSH-RR 64/32 generator: 64 bits of state, a 32-bit
/// output, and a per-instance odd increment selecting the stream.
///
/// Transcribed from `pcg32_random_r` / `pcg32_srandom_r` in
/// `imneme/pcg-c` and pinned by this module's golden test.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
    inc: u64,
}

impl Rng {
    /// Seed the generator, exactly as `pcg32_srandom_r` does: zero the
    /// state, take the odd increment from `initseq`, step, add
    /// `initstate`, step again.
    ///
    /// The two steps are not decoration — they are what mixes a
    /// low-entropy seed such as `0` into the state, and dropping either
    /// one produces a generator that still *looks* random while
    /// disagreeing with every published vector.
    ///
    /// ```
    /// use granary_sim::rng::Rng;
    ///
    /// // The upstream known-answer vector: `imneme/pcg-c`,
    /// // `test-high/expected/check-pcg32.out`.
    /// let mut rng = Rng::seeded(42, 54);
    /// let stream: Vec<u32> = (0..6).map(|_| rng.next_u32()).collect();
    /// assert_eq!(
    ///     stream,
    ///     [0xa15c_02b7, 0x7b47_f409, 0xba1d_3330, 0x83d2_f293, 0xbfa4_784b, 0xcbed_606e],
    /// );
    /// ```
    #[must_use]
    pub fn seeded(initstate: u64, initseq: u64) -> Self {
        // `<< 1` deliberately drops `initseq`'s top bit: the increment
        // must be ODD (it is added to the state each step, and an even
        // increment halves the period), which is what `| 1` guarantees.
        let mut rng = Self {
            state: 0,
            inc: (initseq << 1) | 1,
        };
        let _ = rng.next_u32();
        rng.state = rng.state.wrapping_add(initstate);
        let _ = rng.next_u32();
        rng
    }

    /// The next 32 bits of the stream (`pcg32_random_r`).
    ///
    /// The LCG step advances the state; the output function (`XSH RR`)
    /// xorshifts the high bits down, truncates to 32, and rotates by a
    /// further-up slice of the *old* state. Wrapping arithmetic is the
    /// algorithm, not an overflow escape: an LCG is defined modulo 2^64.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "XSH takes the low 32 bits of the xorshifted state; RR's rotate uses the top 5 bits, so both casts are the algorithm's definition"
    )]
    pub fn next_u32(&mut self) -> u32 {
        let old = self.state;
        self.state = old.wrapping_mul(MULT).wrapping_add(self.inc);
        let xorshifted = (((old >> 18) ^ old) >> 27) as u32;
        let rot = (old >> 59) as u32;
        xorshifted.rotate_right(rot)
    }

    /// A uniform value in `0..n`, by explicit rejection sampling
    /// (`pcg32_boundedrand_r`).
    ///
    /// **Our own reduction, never a `rand` distribution** — see the
    /// module doc: rand's distributions are explicitly permitted to
    /// change values in a minor release, and did so in 0.9.0.
    ///
    /// A bare `next_u32() % n` is biased whenever `n` does not divide
    /// 2^32: the first `2^32 % n` values of the output range would be
    /// drawn one time too many. So the low `2^32 % n` outputs are
    /// *rejected* and redrawn, leaving a range whose length is an exact
    /// multiple of `n`. The loop is unbounded but its expected iteration
    /// count is under 2 for every `n` (the rejection zone is always
    /// smaller than the accepted one).
    ///
    /// `n == 0` answers 0. An empty range has no valid index, so there
    /// is no correct value to return and no untrusted caller to protect
    /// — the alternative is a division by zero, and a panic in the
    /// scheduler's inner loop is worse than a documented total answer.
    /// The scheduler never reaches it: it only draws when at least one
    /// task is runnable.
    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        // `(2^32 - n) mod n` == `2^32 mod n`, computed without a 64-bit
        // widening: the size of the rejection zone at the bottom of the
        // output range.
        let threshold = n.wrapping_neg() % n;
        loop {
            let r = self.next_u32();
            if r >= threshold {
                return r % n;
            }
        }
    }
}

/// granary-sim's PCG stream is the sim's only source of
/// `granary_core::rng::Rng` randomness, so that trait is implemented
/// directly on this type rather than introducing a second generator.
/// Sim-driven code that draws through the `granary_core::rng::Rng` seam
/// therefore still draws from this file's PCG stream and nowhere else:
/// using the core trait must not introduce a source of randomness the
/// replay seed does not fix.
///
/// **Composition order is LOW WORD FIRST**, pinned by
/// `next_u64_composes_low_word_first_against_the_pcg_reference` against
/// the same upstream known-answer vector `next_u32` is pinned against:
/// the FIRST `next_u32` draw becomes the low 32 bits of the `u64`, the
/// SECOND becomes the high 32 bits. Either order would be an equally
/// valid composition of two independent 32-bit draws — nothing in
/// PCG-XSH-RR prefers one — so the order is a choice this impl commits
/// to and the pinned test exists specifically so that choice cannot
/// silently flip under a later edit.
///
/// **Two same-named reductions now coexist on this type**, and they
/// are NOT the same function: the inherent [`Rng::below`] (`u32`,
/// mod-reject, one `next_u32` per iteration) and the trait's default
/// `below` (`u64`, Lemire multiply-shift, one composed two-draw `u64`
/// per iteration). Inherent methods win name resolution, so
/// `rng.below(n)` is the `u32` form; only a call through
/// `dyn`/`impl granary_core::rng::Rng` reaches Lemire's. Different
/// algorithms, different draw consumption — both deterministic under
/// the seed, neither replaces the other.
impl granary_core::rng::Rng for Rng {
    fn next_u64(&mut self) -> u64 {
        let lo = u64::from(self.next_u32());
        let hi = u64::from(self.next_u32());
        (hi << 32) | lo
    }
}

#[cfg(test)]
mod tests;
