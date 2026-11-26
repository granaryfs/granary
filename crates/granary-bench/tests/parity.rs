// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The parity gate. If the sweep's chunker is not granary's chunker at
//! granary's tuple, every number in the milestone is about a different
//! filesystem.

use granary_bench::chunk::Arm;
use granary_bench::tuple::{GrainTuple, SHIPPED_NORMALIZATION};
use granary_core::testkit;
use granary_core::thresh::{self, CHUNKER_SPEC};

fn bench_cuts(arm: Arm, data: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    arm.cut_into(data, &mut spans);
    spans.iter().map(|s| (s.offset, s.len)).collect()
}

fn core_cuts(data: &[u8]) -> Vec<(usize, usize)> {
    thresh::grains(data).map(|g| (g.offset, g.length)).collect()
}

#[test]
fn the_shipped_tuple_mirrors_chunker_spec() {
    let t = GrainTuple::shipped();
    assert_eq!(t.min, CHUNKER_SPEC.min);
    assert_eq!(t.avg, CHUNKER_SPEC.avg);
    assert_eq!(t.max, CHUNKER_SPEC.max);
    assert_eq!(t.normalization, SHIPPED_NORMALIZATION);
    assert_eq!(t.normalization.as_u8(), CHUNKER_SPEC.normalization);
}

#[test]
fn bench_cdc_equals_core_grains_at_the_shipped_tuple() {
    // Large enough to cut many times at the shipped 256 KiB average,
    // and not a multiple of anything.
    let data = testkit::fill(0x_5eed, 24 * 1024 * 1024 + 4321);
    assert!(core_cuts(&data).len() > 8, "input must cut many times");
    assert_eq!(
        bench_cuts(Arm::Cdc(GrainTuple::shipped()), &data),
        core_cuts(&data),
        "the sweep chunker drifted from granary_core::thresh"
    );
}

#[test]
fn parity_holds_on_sub_minimum_and_empty_inputs() {
    for len in [0usize, 1, 1000, thresh::MIN_GRAIN - 1] {
        let data = testkit::fill(3, len);
        assert_eq!(
            bench_cuts(Arm::Cdc(GrainTuple::shipped()), &data),
            core_cuts(&data),
            "len {len}"
        );
    }
}

/// NEGATIVE: the gate must be capable of failing. A tuple one octave
/// off produces different cuts on the same bytes — proof that the
/// equality above is a measurement, not a tautology.
#[test]
fn a_different_tuple_does_not_match_core() {
    let data = testkit::fill(0x_5eed, 24 * 1024 * 1024 + 4321);
    let off_by_one_octave = GrainTuple::from_avg(512 * 1024).expect("grid point");
    assert_ne!(
        bench_cuts(Arm::Cdc(off_by_one_octave), &data),
        core_cuts(&data),
        "the parity check cannot distinguish tuples"
    );
}

/// SIBLING gate, not a replacement: `bench_cdc_equals_core_grains_at_
/// the_shipped_tuple`'s pseudorandom corpus cuts 23 grains and never
/// binds `max` — a mutation that swaps `t.max` for any other value in
/// {2, 4, 8, 16} MiB still produces byte-identical cuts on it, which
/// means that gate cannot see a broken `max`. `max` only binds on a
/// long uniform run, so this test chunks 40 MiB of zeros instead: a
/// content-defined chunker never finds a boundary in a run of
/// identical bytes, so every cut past the first is forced by the
/// `max` ceiling. Both gates stand; deleting either drops coverage.
#[test]
fn bench_cdc_equals_core_grains_and_the_max_clamp_binds() {
    let data = vec![0u8; 40 * 1024 * 1024];
    let bench = bench_cuts(Arm::Cdc(GrainTuple::shipped()), &data);
    let core = core_cuts(&data);
    assert_eq!(
        bench, core,
        "the sweep chunker drifted from granary_core::thresh on a max-clamped corpus"
    );
    assert!(
        bench.iter().any(|&(_, len)| len == thresh::MAX_GRAIN),
        "the low-entropy corpus must actually exercise the MAX_GRAIN clamp, \
         or this gate is blind to `max` just like the sibling it backs up: got {bench:?}"
    );
}
