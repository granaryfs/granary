// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::rng` — the randomness seam — the `Rng` trait and its production and deterministic implementations.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{ProcessRng, Rng, SeededRng};

#[test]
fn seeded_rng_reproduces_its_stream() {
    let mut a = SeededRng::new(12345);
    let mut b = SeededRng::new(12345);
    let sa: Vec<u64> = (0..64).map(|_| a.next_u64()).collect();
    let sb: Vec<u64> = (0..64).map(|_| b.next_u64()).collect();
    assert_eq!(sa, sb);
    // Equality of two constant streams would satisfy the assertion
    // above without generating anything; rule that out too.
    assert!(sa.windows(2).any(|w| w[0] != w[1]), "stream is constant");
}

/// proptest cannot pass core's purity gate: deny.core.toml denies
/// getrandom by name and permits build scripts only for blake3 =1.8.7
/// and libc; the purity script also forbids proc-macros. Its dependency
/// closure exceeds those permissions — this test keeps its original
/// name and property (`below(bound) < bound`, `below(0) == 0`,
/// `below(1) == 0`) via a deterministic sweep instead of proptest.
#[test]
fn below_is_in_range_and_unbiased_at_the_boundary() {
    const BOUNDS: [u64; 8] = [
        0,
        1,
        2,
        3,
        (1u64 << 63) - 1,
        1u64 << 63,
        (1u64 << 63) + 1,
        u64::MAX,
    ];
    const SEEDS: [u64; 5] = [0, 1, 42, 0xDEAD_BEEF, u64::MAX];
    const DRAWS_PER_PAIR: usize = 200;

    for &bound in &BOUNDS {
        for &seed in &SEEDS {
            let mut rng = SeededRng::new(seed);
            for _ in 0..DRAWS_PER_PAIR {
                let v = rng.below(bound);
                match bound {
                    0 => assert_eq!(v, 0, "below(0) must be total"),
                    1 => assert_eq!(v, 0, "below(1) must be total"),
                    _ => assert!(v < bound, "below({bound}) produced {v} (seed {seed})"),
                }
            }
        }
    }
}

/// Probabilistic, and the bound is stated here — honestly.
/// splitmix64's output function is a BIJECTION of the state
/// (xorshifts invert, both multipliers are odd), so draw `i` is an
/// injective image of `state + (i + 1)·γ`: two streams collide at
/// EVERY position (equal seeds) or at NONE (different seeds), and
/// checking 4 draws buys nothing over checking 1. The failure
/// probability is P(the two seeds collide) ≈ `2^-64` under the
/// assumption that std's `SipHash`-keyed finishes behave as a PRF —
/// NOT `(2^-64)^4`; the per-draw collisions are perfectly
/// dependent. ≈`5·10^-20` cannot flake, and this stays the only
/// ambient-entropy-dependent test in this module (ambient entropy is
/// permitted only through this one seam).
#[test]
fn process_rng_streams_differ() {
    let mut a = ProcessRng::new();
    let mut b = ProcessRng::new();
    let mut differed = false;
    for _ in 0..4 {
        if a.next_u64() != b.next_u64() {
            differed = true;
            break;
        }
    }
    assert!(differed, "two ProcessRngs agreed on 4 consecutive draws");
}

/// One method (plus a default-provided second) and no `async`:
/// `dyn Rng` compiles, unlike the storage seams whose desugared
/// futures are not object-safe. Asserted because it is the
/// mechanical consequence of the shape this module fixes.
#[test]
fn the_trait_is_object_safe() {
    fn assert_object_safe(_: &mut dyn Rng) {}
    let mut rng = SeededRng::new(1);
    assert_object_safe(&mut rng);
    let _ = rng.next_u64();
}

/// `below`'s termination, made executable — with the TRUE
/// invariant. Termination compares the rejection zone to the DRAW
/// SPACE, never to `bound`: the loop redraws while
/// `low < threshold` where `threshold = 2^64 mod bound`, so
/// acceptance per draw is `(2^64 − threshold) / 2^64 > 1/2`
/// exactly when `threshold < 2^63`. That holds for every
/// `bound ≥ 1`, both cases: `bound <= 2^63` ⇒
/// `threshold < bound <= 2^63`; `bound > 2^63` ⇒ the quotient is
/// 1, so `threshold = 2^64 − bound < 2^63`. (The tempting form
/// `threshold <= bound / 2` is FALSE — bound 6 has threshold 4 >
/// 3, bound `2^62 + 1` has threshold `2^62 − 3` ≈ double its half
/// — and a sweep can dodge every counterexample; those
/// counterexamples are IN this sweep, so a regression to that form
/// fails loudly.) Expected draws per call `< 2`. This test mirrors
/// the threshold formula; the production rejection BRANCH is
/// pinned by
/// `below_rejects_the_low_zone_and_returns_the_high_half`.
#[test]
fn below_never_spins_forever_because_acceptance_never_drops_below_half() {
    for bound in [
        1u64,
        2,
        3,
        6,
        10,
        (1u64 << 62) + 1,
        (1u64 << 63) - 1,
        1u64 << 63,
        (1u64 << 63) + 1,
        u64::MAX,
    ] {
        let threshold = bound.wrapping_neg() % bound;
        assert!(
            threshold < (1u64 << 63),
            "bound {bound}: threshold {threshold} reaches half the draw space"
        );
    }
}

/// The production rejection branch, pinned deterministically: a
/// scripted `Rng` feeds exactly `[0, 2^63]`, and `below(2^63 + 1)`
/// must reject the first draw (`m = 0`, low half `0 <` threshold
/// `2^63 − 1`), accept the second (low half `2^63 >=` threshold)
/// and return the high half `m >> 64 = 2^62` — consuming BOTH
/// draws. Zeroing the threshold (the plain biased multiply-shift
/// this loop exists to not be) returns 0 from the first draw and
/// fails both assertions. No statistical test can see that
/// mutation at `u64` width — Lemire's bias is a few parts in
/// `2^64` — so this branch pin is the coverage, not a bucket test.
#[test]
fn below_rejects_the_low_zone_and_returns_the_high_half() {
    struct Scripted(Vec<u64>, usize);
    impl Rng for Scripted {
        fn next_u64(&mut self) -> u64 {
            let v = self.0[self.1];
            self.1 += 1;
            v
        }
    }
    let mut rng = Scripted(vec![0, 1u64 << 63], 0);
    assert_eq!(rng.below((1u64 << 63) + 1), 1u64 << 62);
    assert_eq!(rng.1, 2, "the rejection must consume the first draw");
}

/// The module doc's faithful-stand-in claim, executable:
/// `ProcessRng` and `SeededRng` share ONE mixing algorithm and
/// differ only in where the seed comes from. Struct-literal
/// construction (same module tree, private fields reachable), so
/// no ambient entropy is involved and a divergent edit to either
/// copy of the splitmix64 body fails here.
#[test]
fn process_and_seeded_rng_share_the_mixer() {
    let mut p = ProcessRng {
        state: 0xDEAD_BEEF_CAFE_F00D,
    };
    let mut s = SeededRng {
        state: 0xDEAD_BEEF_CAFE_F00D,
    };
    for _ in 0..16 {
        assert_eq!(p.next_u64(), s.next_u64());
    }
}

/// splitmix64 pinned against its published reference (Vigna,
/// `splitmix64.c`, seed 0) — the sim rng module's own doctrine: a
/// generator whose correctness cannot be pinned against its
/// author's output has invisible transcription errors.
/// `SeededRng::new(γ)` holds internal state `γ ^ γ = 0`, i.e. the
/// reference's seed-0 stream, whose first three outputs are below.
#[test]
fn seeded_rng_matches_the_splitmix64_reference_vector() {
    let mut rng = SeededRng::new(0x9E37_79B9_7F4A_7C15);
    assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
    assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
    assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
}
