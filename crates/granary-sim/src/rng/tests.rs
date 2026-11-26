// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::rng` — the sim's own PCG-XSH-RR 64/32
//! generator: the upstream known-answer vector and the
//! value-stability the sim's whole replay claim rests on.
//!
//! Out-of-line: `granary-sim`'s non-test artifact has its
//! own `tests/` directory
//! (`crates/granary-sim/tests/replay_across_processes.rs`,
//! `scenarios.rs`) and its own `[[bin]]`
//! (`src/bin/sim-replay.rs`) — either alone is enough. What
//! does NOT apply: nothing in the workspace depends on
//! `granary-sim`; `granary-sim` depends on `granary-client`,
//! not the reverse. So the module's own tests move out of
//! the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::Rng;

/// The upstream known-answer vector: `imneme/pcg-c`,
/// `test-high/expected/check-pcg32.out`, from
/// `pcg32_srandom_r(&rng, 42u, 54u)`.
const REFERENCE: [u32; 6] = [
    0xa15c_02b7,
    0x7b47_f409,
    0xba1d_3330,
    0x83d2_f293,
    0xbfa4_784b,
    0xcbed_606e,
];

#[test]
fn pcg32_matches_the_reference_vector() {
    let mut rng = Rng::seeded(42, 54);
    let got: Vec<u32> = (0..6).map(|_| rng.next_u32()).collect();
    assert_eq!(got, REFERENCE.to_vec(), "got {got:08x?}");
}

#[test]
fn the_same_seed_replays_the_same_stream() {
    let mut a = Rng::seeded(7, 1);
    let mut b = Rng::seeded(7, 1);
    let sa: Vec<u32> = (0..16).map(|_| a.next_u32()).collect();
    let sb: Vec<u32> = (0..16).map(|_| b.next_u32()).collect();
    assert_eq!(sa, sb);
    // A stream of one repeated value would satisfy the equality
    // above while generating nothing.
    assert!(sa.windows(2).any(|w| w[0] != w[1]), "stream is constant");
}

#[test]
fn a_different_sequence_selector_gives_a_different_stream() {
    let mut a = Rng::seeded(7, 1);
    let mut b = Rng::seeded(7, 2);
    let sa: Vec<u32> = (0..16).map(|_| a.next_u32()).collect();
    let sb: Vec<u32> = (0..16).map(|_| b.next_u32()).collect();
    assert_ne!(sa, sb);
}

#[test]
fn below_stays_in_range_including_non_powers_of_two() {
    for n in [1u32, 2, 3, 5, 7, 10, 100, 1000, u32::MAX] {
        let mut rng = Rng::seeded(u64::from(n), 54);
        let draws: Vec<u32> = (0..1000).map(|_| rng.below(n)).collect();
        for v in &draws {
            assert!(*v < n, "below({n}) produced {v}");
        }
        // `v < n` alone is satisfied by a generator that always
        // answers 0, so the range assertion above cannot stand on
        // its own for n > 1.
        if n > 1 {
            assert!(
                draws.windows(2).any(|w| w[0] != w[1]),
                "below({n}) is constant"
            );
        }
    }
}

#[test]
fn below_reaches_every_value_in_a_non_power_of_two_range() {
    let mut rng = Rng::seeded(42, 54);
    let mut seen = [false; 7];
    for _ in 0..1000 {
        let v = rng.below(7);
        if let Some(slot) = seen.get_mut(v as usize) {
            *slot = true;
        }
    }
    assert!(
        seen.iter().all(|s| *s),
        "below(7) never produced some values: {seen:?}"
    );
}

/// The rejection zone is the part of `below` a bare `%` would skip,
/// so a bound whose zone is large is the one worth exercising: for
/// `n = 3` it is `2^32 % 3 == 1`, and for a bound just over a power
/// of two the accepted range is barely half the output range.
#[test]
fn below_is_uniform_enough_that_no_bucket_is_starved() {
    const N: u32 = 3;
    const DRAWS: u32 = 30_000;
    let mut rng = Rng::seeded(42, 54);
    let mut counts = [0u32; N as usize];
    for _ in 0..DRAWS {
        let v = rng.below(N);
        if let Some(c) = counts.get_mut(v as usize) {
            *c = c.saturating_add(1);
        }
    }
    assert_eq!(counts.iter().sum::<u32>(), DRAWS, "a draw escaped 0..3");
    // A crude band: a biased-by-construction reduction over this
    // many draws lands far outside it, and true uniformity lands
    // far inside.
    for (v, c) in counts.iter().enumerate() {
        assert!(
            (9_000..11_000).contains(c),
            "bucket {v} got {c} of {DRAWS}: {counts:?}"
        );
    }
}

#[test]
fn below_zero_is_total() {
    let mut rng = Rng::seeded(42, 54);
    assert_eq!(rng.below(0), 0);
}

/// Pins the `granary_core::rng::Rng` composition against
/// `REFERENCE` so the low/high word order documented on the `impl`
/// above can never silently flip: the FIRST `next_u32` draw is the
/// low half, the SECOND is the high half (the same low-first order
/// `rand_core`'s `impls::next_u64_via_u32` helper uses — a helper,
/// not a trait default — for what it's worth; this impl owes
/// nothing to that crate, see the module doc).
#[test]
fn next_u64_composes_low_word_first_against_the_pcg_reference() {
    use granary_core::rng::Rng as _;

    let mut rng = Rng::seeded(42, 54);
    let got = rng.next_u64();
    let expected = (u64::from(REFERENCE[1]) << 32) | u64::from(REFERENCE[0]);
    assert_eq!(got, expected, "got {got:016x}, want {expected:016x}");

    let got2 = rng.next_u64();
    let expected2 = (u64::from(REFERENCE[3]) << 32) | u64::from(REFERENCE[2]);
    assert_eq!(got2, expected2, "got {got2:016x}, want {expected2:016x}");
}
