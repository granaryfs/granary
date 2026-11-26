// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::compress` — the per-grain zstd compression
//! accounting, and the pins on its level and vendored library version.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use granary_core::testkit;

#[test]
fn compressible_input_shrinks_and_random_input_does_not() {
    let mut c = GrainCompressor::new().expect("compressor");
    let zeros = vec![0u8; 1 << 20];
    let random = testkit::fill(5, 1 << 20);
    let zlen = c.compressed_len(&zeros).expect("compress zeros");
    let rlen = c.compressed_len(&random).expect("compress random");
    assert!(zlen < 1024, "zeros compressed to {zlen}");
    assert!(rlen > (1 << 20), "xorshift output should not compress");
}

#[test]
fn empty_grain_is_a_bare_frame() {
    let mut c = GrainCompressor::new().expect("compressor");
    let len = c.compressed_len(&[]).expect("compress empty");
    assert!(len > 0 && len < 32, "empty frame was {len} bytes");
}

#[test]
fn compression_is_deterministic_across_compressor_instances() {
    let data = testkit::fill(6, 300_000);
    let mut a = GrainCompressor::new().expect("compressor a");
    let mut b = GrainCompressor::new().expect("compressor b");
    assert_eq!(
        a.compressed_len(&data).expect("a"),
        b.compressed_len(&data).expect("b")
    );
}

#[test]
fn one_stream_beats_independent_frames_on_repetitive_input() {
    let unit = testkit::fill(7, 8192);
    let grains: Vec<&[u8]> = (0..64).map(|_| unit.as_slice()).collect();
    let stream = single_stream_len(grains.iter().copied()).expect("stream");
    let mut c = GrainCompressor::new().expect("compressor");
    let mut independent = 0u64;
    for g in &grains {
        independent += c.compressed_len(g).expect("grain") as u64;
    }
    assert!(
        stream < independent,
        "stream {stream} should beat independent {independent}"
    );
}

/// Tripwire: the recorded crate version must match the workspace pin.
#[test]
fn crate_version_matches_the_workspace_pin() {
    let manifest = include_str!("../../../../Cargo.toml");
    let pin = format!("zstd = {{ version = \"={ZSTD_CRATE_VERSION}\"");
    assert!(
        manifest.contains(&pin),
        "workspace zstd pin does not match ZSTD_CRATE_VERSION ({ZSTD_CRATE_VERSION})"
    );
}

/// Sibling to `crate_version_matches_the_workspace_pin` above (do not
/// modify that test): dependency-policy rule 2/3 mitigation requires
/// `default-features = false` on the zstd pin, or the `legacy`
/// feature (zstd C v0.1-v0.7 decoder support — more vendored C
/// compiled by the same sharp build script) and `arrays` come along
/// for free. This is a substring check on the raw manifest text, so
/// it is brittle to TOML key reordering — that is the accepted
/// trade: it fails safe and loud (red) rather than silently passing
/// on a manifest that dropped the flag.
#[test]
fn zstd_pin_disables_default_features() {
    let manifest = include_str!("../../../../Cargo.toml");
    let pin = format!("zstd = {{ version = \"={ZSTD_CRATE_VERSION}\", default-features = false");
    assert!(
        manifest.contains(&pin),
        "workspace zstd pin no longer disables default features (dependency-policy rule 2/3)"
    );
}

#[test]
fn library_version_is_the_vendored_one() {
    assert_eq!(library_version(), "1.5.7");
}

/// Pins the pre-registered compression level (fixed before the
/// objective was computed for any dataset). This test's whole
/// purpose is pinning that literal number: a 2.5x swing was measured
/// in the dominant objective term on realistic
/// 8 KiB data (4618 bytes at L1 vs 1842 bytes at L3), so drifting off
/// level 3 silently would move every downstream number. Same
/// sanctioned-literal idiom as `library_version_is_the_vendored_one`
/// above: compare the constant to a bare literal, not a derived
/// expression.
#[test]
fn zstd_level_is_pinned_at_three() {
    assert_eq!(ZSTD_LEVEL, 3);
}

/// `ZSTD_API` claims `zstd::bulk`, but nothing bound that string to
/// the code path `compressed_len` actually runs. This pins the
/// literal, then proves the binding: `compressed_len` must equal
/// `zstd::bulk::compress` exactly, and — so the equality above isn't
/// a tautology at a size where bulk and stream happen to agree — that
/// value must genuinely differ from `zstd::stream::encode_all` on the
/// same bytes. The input is `testkit::fill` (the module's existing
/// deterministic generator) with each byte masked to 5 bits: a
/// reduced, 32-symbol alphabet gives level-3 zstd enough redundancy
/// to be "semi-compressible" (~63% of input size here) without being
/// so redundant that the srcSize-driven window/chain/hash-log
/// differences between bulk and stream wash out. Measured for this
/// exact input: bulk = 5168 bytes, stream = 5161 bytes.
#[test]
fn zstd_api_is_bound_to_bulk_compress() {
    assert_eq!(ZSTD_API, "zstd::bulk");

    let base = testkit::fill(11, 8192);
    let semi: Vec<u8> = base.iter().map(|b| b & 0x1F).collect();

    let mut c = GrainCompressor::new().expect("compressor");
    let via_compressor = c
        .compressed_len(&semi)
        .expect("compress via GrainCompressor");

    let via_bulk = zstd::bulk::compress(&semi, ZSTD_LEVEL)
        .expect("bulk compress")
        .len();
    let via_stream = zstd::stream::encode_all(&semi[..], ZSTD_LEVEL)
        .expect("stream compress")
        .len();

    assert_eq!(via_compressor, via_bulk);
    assert_ne!(
        via_bulk, via_stream,
        "bulk and stream must genuinely diverge here, or the equality above is a tautology"
    );
}

/// Framing overhead on incompressible input. The empty-grain test
/// above only exercises the degenerate zero-length case; a regression
/// that stopped counting frame bytes for real payloads (e.g.
/// subtracting them back out) would sail through everything else.
/// The exact byte count (10) is version-pinned on purpose: the zstd
/// crate/library versions are exact-pinned and gated by
/// `deny.toml`, so a version bump that changes the frame envelope
/// should re-open this review, not silently redefine it.
#[test]
fn framing_overhead_on_incompressible_input_is_ten_bytes() {
    let mut c = GrainCompressor::new().expect("compressor");
    let raw = testkit::fill(13, 8192);
    let len = c.compressed_len(&raw).expect("compress");
    assert!(
        len > raw.len(),
        "compressed {len} should exceed raw {} on incompressible input",
        raw.len()
    );
    assert_eq!(
        len - raw.len(),
        10,
        "frame envelope drifted from the pinned zstd version"
    );
}

/// Sibling to `compression_is_deterministic_across_compressor_instances`
/// above (do not modify that test): it builds two FRESH compressors
/// and calls each ONCE, so it cannot detect reuse-dependence — but the
/// module doc says the compressor is reused across a whole run, and
/// that reuse is exactly the property the sweep relies on. This test
/// pushes several varied deterministic grains through ONE reused
/// compressor and checks the resulting sequence of lengths against
/// compressing each grain with its own fresh compressor.
#[test]
fn reused_compressor_matches_fresh_compressor_per_grain() {
    let grains: Vec<Vec<u8>> = vec![
        testkit::fill(21, 1024),
        testkit::fill(22, 4096),
        testkit::fill(23, 512),
        vec![0u8; 2048],
        testkit::fill(24, 8192),
    ];

    let mut reused = GrainCompressor::new().expect("reused compressor");
    let reused_lens: Vec<usize> = grains
        .iter()
        .map(|g| reused.compressed_len(g).expect("compress via reused"))
        .collect();

    let fresh_lens: Vec<usize> = grains
        .iter()
        .map(|g| {
            let mut c = GrainCompressor::new().expect("fresh compressor");
            c.compressed_len(g).expect("compress via fresh")
        })
        .collect();

    assert_eq!(reused_lens, fresh_lens);
}
