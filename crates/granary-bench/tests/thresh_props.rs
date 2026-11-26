// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Chunker invariants. Strategy shape per the seed+len idiom:
//! generate (seed, len) and fill deterministically — a direct
//! multi-MiB Vec<u8> strategy is ~32x slower and shrinks uselessly.
//! Failing cases persist to sibling *.proptest-regressions files —
//! COMMIT those.

use granary_core::testkit;
use granary_core::thresh::{self, Grain};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Contiguity, coverage, bounds, small-input-unsplit — the probe
    /// asserts them all (shared with the fuzz target).
    #[test]
    fn chunk_invariants(seed in any::<u64>(), len in 0usize..=32 * 1024 * 1024) {
        let data = testkit::fill(seed, len);
        testkit::chunk_probe(&data);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// The slice and stream APIs cut identically (golden vectors pin the
    /// fixed cases; this covers the space between them).
    #[test]
    fn stream_equals_slice(seed in any::<u64>(), len in 0usize..=4 * 1024 * 1024) {
        let data = testkit::fill(seed, len);
        let slice: Vec<Grain> = thresh::grains(&data).collect();
        let stream: Result<Vec<Grain>, _> =
            thresh::grains_streaming(std::io::Cursor::new(&data))
                .map(|r| r.map(|g| Grain {
                    offset: usize::try_from(g.offset).unwrap_or(usize::MAX),
                    length: g.length,
                }))
                .collect();
        prop_assert_eq!(slice, stream.map_err(|e| TestCaseError::fail(e.to_string()))?);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn sub_minimum_never_splits(seed in any::<u64>(), len in 1usize..thresh::MIN_GRAIN) {
        let data = testkit::fill(seed, len);
        let all: Vec<Grain> = thresh::grains(&data).collect();
        prop_assert_eq!(all.len(), 1);
    }
}
