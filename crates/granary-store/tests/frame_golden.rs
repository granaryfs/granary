// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

// This file uses `granary_store::codec`, which does not exist
// without the `codec` feature — `cargo check -p granary-store
// --no-default-features --all-targets` otherwise fails to compile this
// test TARGET (the library itself compiles fine under every feature
// selection; only the unconditional test targets did not).
#![cfg(feature = "codec")]

//! Full-frame golden vectors — REAL zstd bytes. Core pins
//! structure with synthetic payloads; the cross-platform determinism
//! proof for actual compressed output lives HERE, where the codec
//! exists. These vectors are the granary-side evidence that a given
//! (input, level, libzstd version) produces identical bytes on macOS
//! and Linux — upstream's own cross-hardware determinism CI postdates
//! the vendored 1.5.7, so this file, cross-checked in CI on both
//! platforms, is the proof, not an inherited guarantee.
//!
//! A red here means either the FORMAT moved or the
//! vendored libzstd changed under the pin chain (Cargo.lock +
//! deny.toml's version-exact allowance + codec.rs's runtime tripwire)
//! — both are deliberate events, never casual test updates.
//!
//! Regenerate DELIBERATELY:
//! `GRANARY_REGEN_VECTORS=1 cargo nextest run -p granary-store --test frame_golden`

use std::fmt::Write as _;
use std::path::Path;

use granary_core::hash::GrainId;
use granary_core::testkit;
use granary_store::codec::GrainCodec;

/// Duplicated from granary-core's tests/common (15 lines; test-support
/// code cannot be shared across crates without a dev-crate; adding one
/// is not justified for this much code). Keep byte-identical semantics: regen
/// refused under CI, exact string equality otherwise.
fn assert_golden(path: &Path, actual: &str) {
    if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
        assert!(
            std::env::var_os("CI").is_none(),
            "refusing to regenerate golden vectors under CI — regen is a deliberate local format event"
        );
        std::fs::write(path, actual).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        eprintln!("regenerated {}", path.display());
    }
    let committed = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {} (regen locally first?): {e}", path.display()));
    assert_eq!(
        actual, committed,
        "golden vectors drifted — a FORMAT EVENT or a libzstd change, never casual"
    );
}

/// Deterministic, seeded generator of COMPRESSIBLE bytes — consecutive
/// little-endian `u32` counters starting at `seed`. Same spirit as
/// `testkit::fill` (no ambient entropy, caller supplies the seed,
/// always reproducible), but the opposite shape: `testkit::fill`'s
/// xorshift64 stream is specifically INCOMPRESSIBLE, which is exactly
/// why none of the three cases above exercise the compressor for real
/// (see the fourth case below). Consecutive counters share
/// enough structure — long runs of repeated low bytes, a slowly
/// incrementing high byte — for zstd's match finder to find real
/// matches and its entropy coders to see a real, non-uniform symbol
/// distribution, without being SO redundant that they trivially
/// stored-block away like all-zeros would.
fn compressible(seed: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut i = seed;
    while out.len() < len {
        out.extend_from_slice(&i.to_le_bytes());
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// Compress, roundtrip-verify, and append one case's golden line.
/// Factored out so the compressible case (below) shares byte-for-byte
/// identical rendering with the three original cases — this is a pure
/// extraction, not a behavior change: the three original cases' output
/// lines are unchanged (verified via `git diff` on the committed
/// vector file, which only gains a fourth line).
fn render_case(codec: &mut GrainCodec, out: &mut String, name: &str, grain: &[u8]) {
    let frame = codec
        .compress_grain(grain)
        .unwrap_or_else(|e| panic!("{e}"));
    // Roundtrip before pinning: a vector of a broken frame would
    // freeze the defect.
    let back = codec
        .decompress_frame(&frame)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, grain);
    let mut hex = String::new();
    for b in &frame {
        write!(hex, "{b:02x}").unwrap_or_else(|e| panic!("{e}"));
    }
    writeln!(
        out,
        "case {name} grain_id={} frame_len={} bytes={hex}",
        GrainId::of(grain),
        frame.len()
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn zstd_frame_golden_vectors() {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut out = String::new();
    // Three grain shapes: tiny, the measured median novel grain
    // (4,301 B), and a 128 KiB mixed buffer. Deterministic inputs via
    // testkit::fill; frames rendered whole (header + zstd payload).
    for (name, seed, len) in [
        ("frame/tiny", 21u64, 5usize),
        ("frame/median", 22, 4301),
        ("frame/128k", 23, 128 * 1024),
    ] {
        let grain = testkit::fill(seed, len);
        render_case(&mut codec, &mut out, name, &grain);
    }
    // The three cases above are all
    // `testkit::fill` (xorshift64) output — incompressible, so zstd
    // emits STORED blocks and the frame bytes are byte-identical at
    // levels 1, 3, 4 and 19 (measured). They pin the 9-byte granary
    // header and the STORED-block framing only; the match finder, the
    // sequence encoder and the FSE/Huffman entropy coders never run —
    // and those are exactly the stages whose output could vary with
    // SIMD dispatch across x86-64 vs aarch64, which is the whole point
    // of this file (module doc: "the cross-platform determinism proof
    // for actual compressed output"). `compressible` above is the ONLY
    // generator in this file that produces bytes those stages actually
    // process, so this fourth case is the ONLY vector here that can
    // detect a compression-level change or a cross-platform
    // codepath difference in the real compressor — the other three
    // would stay byte-identical either way.
    let grain = compressible(24, 80 * 1024);
    render_case(&mut codec, &mut out, "frame/compressible", &grain);
    assert_golden(
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/frame_v1.txt"
        )),
        &out,
    );
}
