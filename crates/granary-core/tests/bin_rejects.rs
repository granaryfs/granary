// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bin rejects corpus.
//! Object-level red vectors, each
//! asserting the SPECIFIC error
//! variant; corruption is applied to encoder-produced valid bytes
//! where possible, hand-built where the encoder refuses to produce
//! the shape at all (the `manifest_rejects` technique).

use granary_core::binfmt::{
    BIN_FIXED_HEADER_LEN, BIN_INDEX_ENTRY_LEN, BIN_MAX_BYTES, FRAME_COMP_MAX, MAX_GRAINS_PER_BIN,
    PackedFrame, decode_bin, encode_bin, encode_frame_header,
};
use granary_core::encoding::{self, DecodeError, ObjectType};
use granary_core::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use granary_core::testkit;

fn synth_frame(seed: u64, unpacked_len: u32, payload_len: usize) -> PackedFrame {
    let mut frame = encode_frame_header(unpacked_len)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_vec();
    frame.extend_from_slice(&testkit::fill(seed, payload_len));
    PackedFrame {
        id: GrainId::of(&frame),
        frame,
    }
}

fn valid_bin() -> Vec<u8> {
    encode_bin(&[synth_frame(1, 64, 32), synth_frame(2, 64, 32)]).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn wrong_object_type_is_refused() {
    // A structurally-plausible body behind a DirLeaf tag: decode_bin
    // dispatches on the envelope and must refuse before reading any
    // index bytes.
    let mut bytes = encoding::envelope(ObjectType::DirLeaf);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        decode_bin(&bytes),
        Err(DecodeError::Invalid {
            what: "object type (want bin)"
        })
    ));
}

#[test]
fn zero_grain_count_is_refused() {
    let mut bin = valid_bin();
    bin[10..14].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        decode_bin(&bin),
        Err(DecodeError::Invalid {
            what: "bin grain_count zero"
        })
    ));
}

#[test]
fn over_cap_grain_count_is_refused_before_allocation() {
    // Hand-built: 10-byte envelope + a count over cap and NOTHING else.
    // The cap check must fire before any index allocation is attempted
    // — a Truncated error here would mean the count was
    // trusted first.
    let mut bytes = encoding::envelope(ObjectType::Bin);
    bytes.extend_from_slice(&(MAX_GRAINS_PER_BIN + 1).to_be_bytes());
    assert!(matches!(
        decode_bin(&bytes),
        Err(DecodeError::CapExceeded {
            what: "bin grain_count",
            ..
        })
    ));
}

#[test]
fn extent_gap_and_overlap_are_refused() {
    let bin = valid_bin();
    let off_pos = BIN_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN;
    for delta in [1i64, -1] {
        let mut bad = bin.clone();
        let old = u64::from_be_bytes(
            bad[off_pos..off_pos + 8]
                .try_into()
                .unwrap_or_else(|_| panic!("slice")),
        );
        let new = old
            .checked_add_signed(delta)
            .unwrap_or_else(|| panic!("overflow"));
        bad[off_pos..off_pos + 8].copy_from_slice(&new.to_be_bytes());
        assert!(
            matches!(
                decode_bin(&bad),
                Err(DecodeError::Invalid {
                    what: "bin extent contiguity"
                })
            ),
            "delta {delta}"
        );
    }
}

#[test]
fn comp_len_floor_and_cap_are_refused() {
    let bin = valid_bin();
    let len_pos = BIN_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN + 8;
    let mut floor = bin.clone();
    floor[len_pos..len_pos + 4].copy_from_slice(&9u32.to_be_bytes());
    assert!(matches!(
        decode_bin(&floor),
        Err(DecodeError::Invalid {
            what: "frame comp_len under header"
        })
    ));
    let mut cap = bin;
    cap[len_pos..len_pos + 4].copy_from_slice(&(FRAME_COMP_MAX + 1).to_be_bytes());
    assert!(matches!(
        decode_bin(&cap),
        Err(DecodeError::CapExceeded {
            what: "frame comp_len",
            ..
        })
    ));
}

#[test]
fn duplicate_grain_id_is_refused_by_decoder() {
    // The encoder refuses duplicates, so hand-build: two entries with
    // identical ids and contiguous extents over identical frames.
    let f = synth_frame(3, 64, 32);
    let mut bytes = encoding::envelope(ObjectType::Bin);
    bytes.extend_from_slice(&2u32.to_be_bytes());
    let frames_start = (BIN_FIXED_HEADER_LEN + 2 * BIN_INDEX_ENTRY_LEN) as u64;
    #[expect(clippy::cast_possible_truncation, reason = "test frame is 41 bytes")]
    let flen = f.frame.len() as u32;
    for i in 0..2u64 {
        bytes.extend_from_slice(&f.id.to_bytes());
        bytes.extend_from_slice(&(frames_start + i * u64::from(flen)).to_be_bytes());
        bytes.extend_from_slice(&flen.to_be_bytes());
    }
    bytes.extend_from_slice(&f.frame);
    bytes.extend_from_slice(&f.frame);
    assert!(matches!(
        decode_bin(&bytes),
        Err(DecodeError::Invalid {
            what: "duplicate grain id in bin"
        })
    ));
}

#[test]
fn truncated_and_trailing_are_refused() {
    // Short and long are DISTINCT rejects; an is_err()/`..` on
    // either side is exactly the shape
    // that hid the original truncation-naming defect, so both sides
    // are pinned by name and by value here.
    let bin = valid_bin();
    let mut short = bin.clone();
    short.pop();
    assert_eq!(decode_bin(&short), Err(DecodeError::Truncated));
    let mut long = bin;
    long.push(0);
    assert_eq!(
        decode_bin(&long),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn reserved_nonzero_framing_and_dict_id_are_refused_by_name() {
    // Nonzero framing and dict_id must be refused by name even inside an
    // otherwise-valid bin — this is the fleet-safety property the
    // fields exist for.
    let bin = valid_bin();
    let frames_start = BIN_FIXED_HEADER_LEN + 2 * BIN_INDEX_ENTRY_LEN;
    let mut framed = bin.clone();
    framed[frames_start] = 0x02;
    assert!(matches!(
        decode_bin(&framed),
        Err(DecodeError::UnsupportedFraming { framing: 0x02 })
    ));
    let mut dicted = bin;
    dicted[frames_start + 4] = 0x01; // low byte of dict_id
    assert!(matches!(
        decode_bin(&dicted),
        Err(DecodeError::UnsupportedDictId { dict_id: 1 })
    ));
}

#[test]
fn over_cap_total_len_is_refused() {
    // BIN_MAX_BYTES is otherwise dead code as far as the suite knows —
    // every other decode test's buffer is small. A 256 MiB zeroed
    // buffer is lazily mapped on both macOS and Linux, so this is
    // cheaper than the byte count suggests.
    let bytes = vec![0u8; usize::try_from(BIN_MAX_BYTES).unwrap_or_else(|e| panic!("{e}")) + 1];
    assert_eq!(
        decode_bin(&bytes),
        Err(DecodeError::CapExceeded {
            what: "bin total_len",
            got: 268_435_457,
            cap: 268_435_456,
        })
    );
}

#[test]
fn bin_max_bytes_accept_boundary_is_not_capped() {
    // Companion to `over_cap_total_len_is_refused`, pinning the ACCEPT
    // side of the same `bytes.len() as u64 > BIN_MAX_BYTES` guard:
    // tightening `>` to `>=` would wrongly refuse a legal maximal-size
    // bin while the suite above (and everything else in this file)
    // stays green, since none of those buffers get anywhere near the
    // cap. Deliberately does NOT build a valid 256 MiB bin — far too
    // expensive to construct and hash. A zeroed buffer of EXACTLY
    // BIN_MAX_BYTES bytes has no valid envelope, so decode_bin still
    // fails, but for an unrelated reason (bad magic); the only thing
    // pinned here is that it is not the total-length guard that fired.
    let bytes = vec![0u8; usize::try_from(BIN_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"))];
    assert!(
        !matches!(
            decode_bin(&bytes),
            Err(DecodeError::CapExceeded {
                what: "bin total_len",
                ..
            })
        ),
        "the total-length guard must not fire at exactly BIN_MAX_BYTES"
    );
}

#[test]
fn unknown_version_in_envelope_is_refused() {
    let mut bin = valid_bin();
    bin[9] = 0x02; // envelope version byte
    assert!(matches!(
        decode_bin(&bin),
        Err(DecodeError::UnknownVersion { version: 0x02 })
    ));
}
