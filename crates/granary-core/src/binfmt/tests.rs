// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::binfmt` — the bin format v1 encoder/planner and frame layout.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::testkit;

/// One planner input, both lengths spelled.
fn plan_frame(comp_len: u32, unpacked_len: u32) -> FramePlan {
    FramePlan {
        comp_len,
        unpacked_len,
    }
}

fn frame(seed: u64, payload_len: u32) -> Vec<u8> {
    let mut f = encode_frame_header(payload_len)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_vec();
    f.extend_from_slice(&testkit::fill(seed, payload_len as usize));
    f
}

fn packed(seed: u64, payload_len: u32) -> PackedFrame {
    let f = frame(seed, payload_len);
    PackedFrame {
        id: GrainId::of(&f),
        frame: f,
    }
}

#[test]
fn caps_are_the_frozen_relations() {
    // ZSTD_COMPRESSBOUND(8 MiB) — the compressed side EXPANDS;
    // the small-input term is zero at 8 MiB.
    assert_eq!(GRAIN_UNPACKED_MAX, 8 * 1024 * 1024);
    assert_eq!(ZSTD_PAYLOAD_MAX, 8_421_376);
    assert_eq!(FRAME_COMP_MAX, 8_421_385);
    assert_eq!(BIN_INDEX_ENTRY_LEN, 45);
    assert_eq!(BIN_FIXED_HEADER_LEN, 14);
    // Frozen caps, pinned ABSOLUTELY: every other test refers to
    // these two relatively, so either could be set to any value with
    // the whole workspace green.
    assert_eq!(MAX_GRAINS_PER_BIN, 65_536);
    assert_eq!(BIN_MAX_BYTES, 256 * 1024 * 1024);
}

#[test]
fn frame_header_roundtrip_and_rejects() {
    let h = encode_frame_header(1).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(h, [0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(decode_frame_header(&h), Ok(FrameHeader { unpacked_len: 1 }));
    // Encoder refuses what the decoder rejects,
    // BY NAME — zero and over-cap are distinct refusals, so an
    // `is_err()` here would not prove which one fires.
    assert_eq!(
        encode_frame_header(0),
        Err(DecodeError::Invalid {
            what: "frame unpacked_len zero"
        })
    );
    assert_eq!(
        encode_frame_header(GRAIN_UNPACKED_MAX + 1),
        Err(DecodeError::CapExceeded {
            what: "frame unpacked_len",
            got: u64::from(GRAIN_UNPACKED_MAX + 1),
            cap: u64::from(GRAIN_UNPACKED_MAX),
        })
    );
    // Refuse-nonzero BY NAME: framing…
    assert_eq!(
        decode_frame_header(&[1, 0, 0, 0, 0, 0, 0, 0, 1]),
        Err(DecodeError::UnsupportedFraming { framing: 1 })
    );
    // …and dict_id.
    assert_eq!(
        decode_frame_header(&[0, 0, 0, 0, 7, 0, 0, 0, 1]),
        Err(DecodeError::UnsupportedDictId { dict_id: 7 })
    );
    // Zero declared length names Invalid — not a fabricated
    // CapExceeded ("unpacked_len = 0 exceeds cap 8388608").
    assert_eq!(
        decode_frame_header(&[0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(DecodeError::Invalid {
            what: "frame unpacked_len zero"
        })
    );
    // Over-cap declared length stays CapExceeded.
    let mut over = [0u8; FRAME_HEADER_LEN];
    over[5..9].copy_from_slice(&(GRAIN_UNPACKED_MAX + 1).to_be_bytes());
    assert_eq!(
        decode_frame_header(&over),
        Err(DecodeError::CapExceeded {
            what: "frame unpacked_len",
            got: u64::from(GRAIN_UNPACKED_MAX + 1),
            cap: u64::from(GRAIN_UNPACKED_MAX),
        })
    );
    assert_eq!(decode_frame_header(&[0, 0]), Err(DecodeError::Truncated));
}

#[test]
fn bin_roundtrip_is_canonical() {
    let frames = vec![packed(1, 100), packed(2, 1), packed(3, 4096)];
    let bin = encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"));
    let entries = decode_bin(&bin).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(entries.len(), 3);
    // decode(encode) reproduces ids, extents slice back to frames…
    for (e, f) in entries.iter().zip(&frames) {
        assert_eq!(e.id, f.id);
        let fb = frame_bytes(&bin, e).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(fb, f.frame.as_slice());
    }
    // …and encode(decode) is byte-identical (canonical form).
    let re = encode_bin(
        &entries
            .iter()
            .map(|e| PackedFrame {
                id: e.id,
                frame: frame_bytes(&bin, e)
                    .unwrap_or_else(|e| panic!("{e}"))
                    .to_vec(),
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bin);
}

#[test]
fn bin_reserves_exact_total_without_changing_bytes() {
    let frames = vec![packed(1, 100), packed(2, 101), packed(3, 102)];
    let bin = encode_bin(&frames).unwrap();
    let mut expected = encoding::envelope(ObjectType::Bin);
    expected.extend_from_slice(&3_u32.to_be_bytes());
    let mut offset = 149_u64;
    for frame in &frames {
        expected.extend_from_slice(&frame.id.to_bytes());
        expected.extend_from_slice(&offset.to_be_bytes());
        expected.extend_from_slice(&u32::try_from(frame.frame.len()).unwrap().to_be_bytes());
        offset += frame.frame.len() as u64;
    }
    for frame in &frames {
        expected.extend_from_slice(&frame.frame);
    }
    assert_eq!((bin == expected, bin.capacity()), (true, 479));
}

#[test]
fn bin_rejects_each_rule() {
    // Empty.
    assert_eq!(encode_bin(&[]), Err(EncodeBinError::Empty));
    // Encoder refuses a frame of exactly FRAME_HEADER_LEN bytes (no
    // payload at all) BY NAME: check_frame has two length refusals
    // (Truncated, CapExceeded), and a bare is_err() passes on either.
    let header_only = encode_frame_header(1)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_vec();
    assert_eq!(header_only.len(), FRAME_HEADER_LEN);
    let header_only_pf = PackedFrame {
        id: GrainId::of(&header_only),
        frame: header_only,
    };
    assert_eq!(
        encode_bin(&[header_only_pf]),
        Err(EncodeBinError::BadFrame {
            index: 0,
            why: DecodeError::Truncated,
        })
    );
    // …and a frame one byte over FRAME_COMP_MAX, BY NAME.
    let mut over_max = encode_frame_header(1)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_vec();
    over_max.resize(FRAME_COMP_MAX as usize + 1, 0);
    let over_max_pf = PackedFrame {
        id: GrainId::of(&over_max),
        frame: over_max,
    };
    assert_eq!(
        encode_bin(&[over_max_pf]),
        Err(EncodeBinError::BadFrame {
            index: 0,
            why: DecodeError::CapExceeded {
                what: "frame comp_len",
                got: u64::from(FRAME_COMP_MAX) + 1,
                cap: u64::from(FRAME_COMP_MAX),
            },
        })
    );
    // Duplicate id.
    let f = packed(9, 64);
    assert!(matches!(
        encode_bin(&[f.clone(), f.clone()]),
        Err(EncodeBinError::DuplicateGrain { .. })
    ));
    // Decoder: zero count.
    let bin = encode_bin(std::slice::from_ref(&f)).unwrap_or_else(|e| panic!("{e}"));
    let mut zero = bin.clone();
    zero[10..14].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        decode_bin(&zero),
        Err(DecodeError::Invalid {
            what: "bin grain_count zero"
        })
    ));
    // Decoder: broken contiguity (offset bumped by 1).
    let mut gap = bin.clone();
    let off_pos = BIN_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN;
    let old = u64::from_be_bytes(
        gap[off_pos..off_pos + 8]
            .try_into()
            .unwrap_or_else(|_| panic!("slice")),
    );
    gap[off_pos..off_pos + 8].copy_from_slice(&(old + 1).to_be_bytes());
    assert!(matches!(
        decode_bin(&gap),
        Err(DecodeError::Invalid {
            what: "bin extent contiguity"
        })
    ));
    // Decoder: total length off by one (truncated frame region), by
    // NAME — an is_err() here would still pass with the truncation
    // reported under the wrong name.
    let mut short = bin.clone();
    short.pop();
    assert_eq!(decode_bin(&short), Err(DecodeError::Truncated));
    // Decoder: trailing byte after the last frame, by name AND the
    // right surplus (one byte pushed, so `remaining` must be 1 —
    // not `..`, which would also pass a decoder that miscounted).
    let mut long = bin.clone();
    long.push(0xAA);
    assert_eq!(
        decode_bin(&long),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
    // Decoder: frame with nonzero framing inside an otherwise-valid
    // bin (the refusal survives embedding).
    let mut framed = bin;
    let frames_start = BIN_FIXED_HEADER_LEN + BIN_INDEX_ENTRY_LEN;
    framed[frames_start] = 1;
    assert!(matches!(
        decode_bin(&framed),
        Err(DecodeError::UnsupportedFraming { framing: 1 })
    ));
}

#[test]
fn planner_splits_on_target_and_count() {
    // Nine maximal frames: eight cross the 64 MiB target, so the
    // ninth starts bin 2 (a frame can never exceed FRAME_COMP_MAX,
    // so multi-frame accumulation is the ONLY way to reach target).
    let maxed = vec![plan_frame(FRAME_COMP_MAX, 1); 9];
    let plans = plan_bins(&maxed).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plans, vec![0..8, 8..9]);
    // Count cap closes a bin of tiny frames.
    // header 9 + 1 payload byte
    let tiny = vec![plan_frame(10, 1); MAX_GRAINS_PER_BIN as usize + 1];
    let plans = plan_bins(&tiny).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plans.len(), 2);
    assert_eq!(
        plans.first().map(std::ops::Range::len),
        Some(MAX_GRAINS_PER_BIN as usize)
    );
    // Planner refuses an illegal length up front, BY NAME — mirrors
    // check_frame exactly; it has two distinct length refusals, and
    // `is_err()` would not prove which one fired.
    assert_eq!(
        plan_bins(&[plan_frame(9, 1)]), // == header, no payload
        Err(EncodeBinError::BadFrame {
            index: 0,
            why: DecodeError::Truncated,
        })
    );
    assert_eq!(
        plan_bins(&[plan_frame(FRAME_COMP_MAX + 1, 1)]),
        Err(EncodeBinError::BadFrame {
            index: 0,
            why: DecodeError::CapExceeded {
                what: "frame comp_len",
                got: u64::from(FRAME_COMP_MAX + 1),
                cap: u64::from(FRAME_COMP_MAX),
            },
        })
    );
    // Empty input plans zero bins (a publish with no novel objects
    // uploads nothing — a dedup-only publish).
    assert_eq!(plan_bins(&[]), Ok(vec![]));
}

/// The THIRD close condition, and its boundary — the one that keeps
/// a conforming publish under a verifying server's ingest ceiling.
///
/// **Look-ahead, so a planned bin never declares more than the
/// target.** The post-add form the other two conditions use admits
/// the frame that crosses and closes afterwards, which emits a bin
/// declaring up to `target + unpacked_len` — measurably over, and
/// over is the only direction that matters here, because the number
/// this target exists to stay under belongs to somebody else's
/// server.
///
/// **The grain size deliberately does NOT divide the target**, and
/// that is the whole discriminating power of this row. On a size
/// that divides it, the two forms agree exactly: the accumulated
/// total lands ON the boundary, where a post-add close and a
/// look-ahead close fire at the same frame — so a witness built from
/// maximal grains would pass against the implementation it exists to
/// refuse. One byte under maximal is enough to separate them.
#[test]
fn planner_closes_on_the_declared_decompressed_target() {
    // One byte under maximal: 128 of these are 128 bytes under the
    // target and 129 are 8 MiB over it, so the target falls strictly
    // between two frame counts.
    const UNPACKED: u32 = GRAIN_UNPACKED_MAX - 1;
    let per_bin =
        usize::try_from(BIN_UNPACKED_TARGET_BYTES / u64::from(UNPACKED)).unwrap_or(usize::MAX);
    assert!(per_bin > 1, "the target must hold more than one grain");
    let fits = per_bin as u64 * u64::from(UNPACKED);
    assert!(
        fits < BIN_UNPACKED_TARGET_BYTES,
        "the row needs a size the target does not divide, or the \
         post-add form it exists to refuse fires at the same frame"
    );
    let grain = plan_frame(200, UNPACKED);

    // As many as fit: ONE bin.
    let at = vec![grain; per_bin];
    let one_bin = plan_bins(&at).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(one_bin.len(), 1, "a publish that fits is one bin");
    assert_eq!(one_bin.first(), Some(&(0..per_bin)));

    // One grain more: the look-ahead closes BEFORE the crossing
    // frame, so the first bin still declares only what fits.
    let over = vec![grain; per_bin + 1];
    assert_eq!(
        plan_bins(&over),
        Ok(vec![0..per_bin, per_bin..per_bin + 1]),
        "the grain that would cross the target opens the next bin \
         rather than closing this one"
    );

    // The property, stated over every emitted bin rather than over
    // the split points: no plan declares more than the target.
    let many = vec![grain; per_bin * 3 + 1];
    let plans = plan_bins(&many).unwrap_or_else(|e| panic!("{e}"));
    for plan in &plans {
        let declared = plan.len() as u64 * u64::from(UNPACKED);
        assert!(
            declared <= BIN_UNPACKED_TARGET_BYTES,
            "a planned bin declares {declared} bytes, past the \
             {BIN_UNPACKED_TARGET_BYTES}-byte target"
        );
    }

    // The condition is over the DECLARED length and not the
    // compressed one: the same frames with a tiny declaration plan
    // into one bin, so this row cannot pass on the compressed
    // target by accident.
    let tiny_declaration = vec![plan_frame(200, 1); per_bin * 3];
    let undivided = plan_bins(&tiny_declaration).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        undivided.len(),
        1,
        "nothing but the declared sum may close these bins"
    );
    assert_eq!(undivided.first(), Some(&(0..per_bin * 3)));
}

#[test]
fn max_count_bin_is_accepted() {
    // The grain-count cap BOUNDARY is legal, not just refused past
    // it: exactly MAX_GRAINS_PER_BIN frames must encode and decode
    // back to exactly that many entries. Flipping `>` to `>=` at the
    // cap would silently narrow what the fleet accepts and ship
    // green — this pins the accept side.
    //
    // Payload is the loop index's 8 big-endian bytes: content must
    // be UNIQUE per frame (encode_bin refuses duplicate ids), and a
    // 1-byte payload from testkit::fill would collide constantly
    // across 65_536 frames (only 256 distinct byte values).
    let frames: Vec<PackedFrame> = (0..u64::from(MAX_GRAINS_PER_BIN))
        .map(|i| {
            let mut f = encode_frame_header(1)
                .unwrap_or_else(|e| panic!("{e}"))
                .to_vec();
            f.extend_from_slice(&i.to_be_bytes());
            PackedFrame {
                id: GrainId::of(&f),
                frame: f,
            }
        })
        .collect();
    let bin = encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"));
    // frame len = 9 (header) + 8 (index) = 17 B; total ≈ 14 +
    // 65_536×45 (index) + 65_536×17 (frames) ≈ 3.88 MB.
    assert_eq!(
        bin.len(),
        BIN_FIXED_HEADER_LEN
            + MAX_GRAINS_PER_BIN as usize * BIN_INDEX_ENTRY_LEN
            + MAX_GRAINS_PER_BIN as usize * (FRAME_HEADER_LEN + 8)
    );
    let entries = decode_bin(&bin).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(entries.len(), MAX_GRAINS_PER_BIN as usize);
}

#[test]
fn maximal_frame_is_accepted() {
    // The comp_len cap BOUNDARY is legal: a frame of exactly
    // FRAME_COMP_MAX bytes must pass check_frame (via encode_bin)
    // and decode back out of a bin — the accept-side pin for this cap,
    // mirroring max_count_bin_is_accepted for the OTHER cap.
    let mut frame = encode_frame_header(GRAIN_UNPACKED_MAX)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_vec();
    frame.resize(FRAME_COMP_MAX as usize, 0);
    assert_eq!(frame.len(), FRAME_COMP_MAX as usize);
    assert_eq!(check_frame(0, &frame), Ok(()));
    let pf = PackedFrame {
        id: GrainId::of(&frame),
        frame: frame.clone(),
    };
    let bin = encode_bin(&[pf]).unwrap_or_else(|e| panic!("{e}"));
    let entries = decode_bin(&bin).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].comp_len, FRAME_COMP_MAX);
    let sliced = frame_bytes(&bin, &entries[0]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(sliced, frame.as_slice());
}
