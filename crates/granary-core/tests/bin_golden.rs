// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bin object golden vectors.
//! Core pins STRUCTURE with synthetic payloads: a frame's
//! payload is opaque here — real-zstd full-bin vectors live in
//! granary-store, where the codec exists. A red here after a code
//! change means the FORMAT moved bytes — a deliberate versioned event,
//! never a refactor side effect.
//!
//! Regenerate DELIBERATELY:
//! `GRANARY_REGEN_VECTORS=1 cargo nextest run -p granary-core --test bin_golden`

#![expect(
    clippy::unwrap_used,
    reason = "render/build helpers below sit outside #[test] fns (test code, standards rule 3)"
)]

use std::fmt::Write as _;
use std::path::Path;

use granary_core::binfmt::{
    FramePlan, PackedFrame, decode_bin, encode_bin, encode_frame_header, frame_bytes, plan_bins,
};
use granary_core::hash::GrainId;
use granary_core::testkit;

mod common;

/// A synthetic frame: a valid v1 header declaring `unpacked_len`, then
/// `payload_len` bytes of deterministic filler standing in for zstd
/// output (never decompressed by core). The two lengths are
/// INDEPENDENT by design — compressed size has no fixed relation to
/// unpacked size (expansion is legal).
fn synth_frame(seed: u64, unpacked_len: u32, payload_len: usize) -> PackedFrame {
    let mut frame = encode_frame_header(unpacked_len).unwrap().to_vec();
    frame.extend_from_slice(&testkit::fill(seed, payload_len));
    PackedFrame {
        id: GrainId::of(&frame),
        frame,
    }
}

fn render(out: &mut String, case: &str, bytes: &[u8]) {
    let id = GrainId::of(bytes);
    let mut hex = String::new();
    for b in bytes {
        write!(hex, "{b:02x}").unwrap();
    }
    writeln!(out, "case {case} id={id} bytes={hex}").unwrap();
}

/// Closes the same hole `committed_vectors_decode_and_reencode` closes in
/// `binmap_golden.rs` for the binmap goldens: this file only
/// string-compares the ENCODER's output against the committed vector file
/// and never calls `decode_bin` — so a decoder that started REFUSING a
/// committed bin would be indistinguishable from one that still accepts it.
/// `decode_bin` returns index entries, not frame bytes, so re-encoding
/// round-trips through `frame_bytes` to recover each frame — the same
/// shape `binfmt::bin_roundtrip_is_canonical` already uses in-crate.
fn assert_decodes_and_reencodes(bin: &[u8]) {
    let entries = decode_bin(bin).unwrap_or_else(|e| panic!("{e}"));
    let frames: Vec<PackedFrame> = entries
        .iter()
        .map(|e| PackedFrame {
            id: e.id,
            frame: frame_bytes(bin, e)
                .unwrap_or_else(|e| panic!("{e}"))
                .to_vec(),
        })
        .collect();
    let re = encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        re, bin,
        "decode→re-encode must reproduce the golden bytes exactly"
    );
}

#[test]
fn bin_golden_vectors() {
    let mut out = String::new();

    // One frame: the smallest legal bin (1-byte declared, 1-byte payload).
    let single = encode_bin(&[synth_frame(1, 1, 1)]).unwrap();
    render(&mut out, "bin/single", &single);
    assert_decodes_and_reencodes(&single);

    // Three frames, varied declared/payload sizes including a payload
    // LARGER than its declaration (compressed expansion is legal) and
    // the max declarable length.
    let multi = encode_bin(&[
        synth_frame(2, 100, 40),
        synth_frame(3, 8 * 1024 * 1024, 64), // max unpacked, tiny payload
        synth_frame(4, 5, 12),               // payload > declared: legal
    ])
    .unwrap();
    render(&mut out, "bin/multi", &multi);
    assert_decodes_and_reencodes(&multi);

    // The planner is part of the packing contract: pin its split
    // arithmetic on a representative sequence that actually CROSSES
    // BIN_TARGET_BYTES (eight near-max frames plus one more push the
    // running total over the 64 MiB target, sandwiched by tiny frames on
    // both sides) — the plan text is part of the vector so a
    // split-point regression, not just a policy change, is a visible
    // diff. The vector's total exceeds the target, so it must split.
    let lens = [
        10_u32, 8_421_385, 8_421_385, 8_421_385, 8_421_385, 8_421_385, 8_421_385, 8_421_385,
        8_421_385, 10, 10,
    ];
    // `FramePlan` carries both lengths; the vector pins the SPLIT
    // arithmetic over the compressed dimension, so the declared
    // decompressed length rides along at the frame's own compressed
    // length — far under `BIN_UNPACKED_TARGET_BYTES` in total, which is
    // what keeps these split points the compressed target's.
    let planned: Vec<FramePlan> = lens
        .iter()
        .map(|&comp_len| FramePlan {
            comp_len,
            unpacked_len: comp_len,
        })
        .collect();
    let plans = plan_bins(&planned).unwrap();
    writeln!(out, "plan lens={lens:?} ranges={plans:?}").unwrap();

    common::assert_golden(
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/bin_v1.txt"
        )),
        &out,
    );
}
