// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::thresh` — content-defined chunking — the `FastCDC` v2020 wrapper (spec §4).
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::testkit;

#[test]
fn empty_input_yields_nothing() {
    assert_eq!(grains(&[]).count(), 0);
}

#[test]
fn sub_minimum_inputs_stay_whole() {
    for len in [1usize, 100, MIN_GRAIN - 1] {
        let data = testkit::fill(7, len);
        let all: Vec<Grain> = grains(&data).collect();
        assert_eq!(all.len(), 1, "len {len} split");
        assert_eq!(
            all.first(),
            Some(&Grain {
                offset: 0,
                length: len
            })
        );
    }
}

#[test]
fn multi_grain_coverage_and_bounds() {
    let data = testkit::fill(42, 20 * 1024 * 1024);
    testkit::chunk_probe(&data); // contiguity, coverage, bounds
    assert!(
        grains(&data).count() > 1,
        "20 MiB should cut more than once"
    );
}

#[test]
fn stream_matches_slice() {
    let data = testkit::fill(9, 3 * 1024 * 1024 + 12_345);
    let slice: Vec<Grain> = grains(&data).collect();
    let stream: Vec<Grain> = grains_streaming(std::io::Cursor::new(&data))
        .map(|r| {
            let g = r.unwrap_or_else(|e| panic!("stream error: {e}"));
            Grain {
                offset: usize::try_from(g.offset).unwrap_or(usize::MAX),
                length: g.length,
            }
        })
        .collect();
    assert_eq!(slice, stream);
}

/// Version-pin tripwire: the tuple's recorded crate version must match the
/// workspace pin — a bump that forgets [`CHUNKER_SPEC`] (or vice
/// versa) goes red here.
#[test]
fn chunker_spec_matches_workspace_pin() {
    let manifest = include_str!("../../../../Cargo.toml");
    let pin = format!("fastcdc = \"={}\"", CHUNKER_SPEC.crate_version);
    assert!(
        manifest.contains(&pin),
        "workspace Cargo.toml fastcdc pin does not match CHUNKER_SPEC.crate_version ({})",
        CHUNKER_SPEC.crate_version
    );
}
