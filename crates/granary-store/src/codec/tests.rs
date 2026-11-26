// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::codec` — the grain codec: one zstd frame
//! per grain, the vendored-libzstd version pin, and the roundtrip and
//! corruption-detection battery.
//!
//! Out-of-line: `granary-store`'s non-test artifact has workspace
//! consumers (`granary-client`, `granary-server`, `granary-sim`),
//! so the module's own tests move out of the parent file while it
//! keeps its path and declares `#[cfg(test)] mod tests;` — the
//! sibling-directory form. This file also declares `recompress`,
//! the module's second test body: a leaf nested under `tests`, not a
//! second sibling declaration in the parent.

use super::*;
use granary_core::binfmt::FRAME_COMP_MAX;
use granary_core::testkit;

fn codec() -> GrainCodec {
    GrainCodec::new().unwrap_or_else(|e| panic!("{e}"))
}

/// The C-library pin (module doc): determinism holds only within a
/// libzstd version, and the crate pin does not transitively pin the
/// C source — this test is the runtime tripwire.
#[test]
fn vendored_libzstd_version_is_pinned() {
    assert_eq!(zstd::zstd_safe::version_number(), ZSTD_C_VERSION_NUMBER);
}

/// Pins the production compression level to [`ZSTD_LEVEL`], which the
/// frozen bin format's canonical bytes assume. Same idiom as
/// `vendored_libzstd_version_is_pinned` above and as
/// `granary-bench/src/compress.rs`'s `zstd_level_is_pinned_at_three`
/// (whose comment gives the reason: "drifting off level 3 silently
/// would move every downstream number") — that sibling pins the
/// level the BENCHMARK measures; this pins the level PRODUCTION
/// actually compresses with. Before this test, this crate's
/// `ZSTD_LEVEL` — a second, independent constant the bench tripwire
/// cannot see — could drift from 3 to 4 with every one of this
/// crate's other tests still green, including the golden vectors
/// (until `frame_golden`'s compressible case, which this level pin
/// complements: that case shows drift IN THE BYTES, this one names
/// the CAUSE directly).
#[test]
fn zstd_level_is_pinned_at_three() {
    assert_eq!(ZSTD_LEVEL, 3);
}

#[test]
fn roundtrip_one_byte_and_max_grain() {
    let mut c = codec();
    for data in [
        testkit::fill(1, 1),
        testkit::fill(2, 4301), // the measured median novel grain
        testkit::fill(3, GRAIN_UNPACKED_MAX as usize),
    ] {
        let frame = c.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));
        assert!(frame.len() > FRAME_HEADER_LEN);
        assert!(frame.len() <= FRAME_COMP_MAX as usize);
        let back = c.decompress_frame(&frame).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back, data);
    }
}

#[test]
fn compress_refuses_illegal_grains() {
    let mut c = codec();
    assert!(matches!(c.compress_grain(&[]), Err(CodecError::EmptyGrain)));
    let over = testkit::fill(4, GRAIN_UNPACKED_MAX as usize + 1);
    assert!(matches!(
        c.compress_grain(&over),
        Err(CodecError::GrainTooLarge { .. })
    ));
}

#[test]
fn determinism_across_contexts_and_reuse() {
    let data = testkit::fill(5, 100_000);
    let mut c1 = codec();
    let a = c1.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));
    // Reuse after unrelated work (state-leak probe).
    let _ = c1
        .compress_grain(&testkit::fill(6, 50_000))
        .unwrap_or_else(|e| panic!("{e}"));
    let b = c1.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));
    let c = codec()
        .compress_grain(&data)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn refuse_nonzero_framing_and_dict_id() {
    let mut c = codec();
    let data = testkit::fill(7, 64);
    let mut frame = c.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));
    frame[0] = 1; // framing
    assert!(matches!(
        c.decompress_frame(&frame),
        Err(CodecError::Header(DecodeError::UnsupportedFraming {
            framing: 1
        }))
    ));
    frame[0] = 0;
    frame[4] = 9; // low byte of dict_id
    assert!(matches!(
        c.decompress_frame(&frame),
        Err(CodecError::Header(DecodeError::UnsupportedDictId {
            dict_id: 9
        }))
    ));
}

/// The declared length is the only trusted length. Under-declare:
/// zstd refuses at exact capacity (opaque `FrameInvalid`). Over-
/// declare: output falls short — the typed mismatch.
#[test]
fn declared_length_lies_are_rejected_both_directions() {
    let mut c = codec();
    let data = testkit::fill(8, 100);
    let good = c.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));
    let mut under = good.clone();
    under[5..9].copy_from_slice(&99u32.to_be_bytes());
    assert!(matches!(
        c.decompress_frame(&under),
        Err(CodecError::FrameInvalid)
    ));
    let mut over = good;
    over[5..9].copy_from_slice(&101u32.to_be_bytes());
    assert!(matches!(
        c.decompress_frame(&over),
        Err(CodecError::DeclaredLengthMismatch {
            declared: 101,
            actual: 100
        })
    ));
}

/// Multi-frame concatenation of two OUTPUT-PRODUCING frames,
/// refused structurally by law 2. (Were law 2 removed, exact capacity
/// would still refuse THIS case — the summed output overruns the
/// declaration — so this row cannot show that law 2 is NEEDED; the
/// variants in
/// `multi_frame_and_skippable_encodings_of_one_grain_are_rejected`
/// whose summed output fits the declaration are the ones capacity
/// alone cannot refuse.)
#[test]
fn concatenated_frames_are_rejected() {
    let mut c = codec();
    let a = testkit::fill(9, 3000);
    let fa = c.compress_grain(&a).unwrap_or_else(|e| panic!("{e}"));
    let fb = c.compress_grain(&a).unwrap_or_else(|e| panic!("{e}"));
    // Header declares 3000 but the payload is TWO zstd frames.
    let mut spliced = fa.clone();
    spliced.extend_from_slice(&fb[FRAME_HEADER_LEN..]);
    assert!(matches!(
        c.decompress_frame(&spliced),
        Err(CodecError::PayloadNotSingleFrame { .. })
    ));
}

/// NON-CANONICALITY vectors: the MULTI-FRAME
/// and SKIPPABLE alternative encodings of ONE logical grain, every
/// one of which must be refused. Golden vectors pin the canonical
/// encoding; reject corpora enumerate refusals; NEITHER can see a
/// second encoding that decodes Ok to the same value — that is what
/// this test exists to probe, by CONSTRUCTING the alternatives.
///
/// NAMED FOR ITS TRUE SCOPE: it covers the multi-frame and
/// skippable class only, not the whole canonicality property, and a
/// test named for a property while covering one input class would
/// claim more than it checks. The
/// single-frame alternatives law 2 CANNOT reject are pinned as
/// accepted, deliberately, by
/// [`single_frame_alternatives_are_accepted_and_bounded`] below.
#[test]
fn multi_frame_and_skippable_encodings_of_one_grain_are_rejected() {
    let mut c = codec();
    let data = testkit::fill(12, 4096);
    let canonical = c.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));
    let payload = canonical[FRAME_HEADER_LEN..].to_vec();
    let frame_with = |p: &[u8]| {
        let mut f = canonical[..FRAME_HEADER_LEN].to_vec();
        f.extend_from_slice(p);
        f
    };

    // A valid zstd frame decoding to ZERO bytes.
    let empty_frame = zstd::bulk::compress(&[], ZSTD_LEVEL).unwrap_or_else(|e| panic!("{e}"));
    // A skippable frame (magic 0x184D2A50 LE) carrying 8 junk bytes.
    let mut skippable = vec![0x50, 0x2A, 0x4D, 0x18];
    skippable.extend_from_slice(&8u32.to_le_bytes());
    skippable.extend_from_slice(&[0xDE; 8]);
    // The SAME grain, compressed as two concatenated frames.
    let (lo, hi) = data.split_at(2048);
    let split_a = zstd::bulk::compress(lo, ZSTD_LEVEL).unwrap_or_else(|e| panic!("{e}"));
    let split_b = zstd::bulk::compress(hi, ZSTD_LEVEL).unwrap_or_else(|e| panic!("{e}"));

    let mut appended_empty = payload.clone();
    appended_empty.extend_from_slice(&empty_frame);
    let mut appended_skippable = payload.clone();
    appended_skippable.extend_from_slice(&skippable);
    let mut prepended_skippable = skippable.clone();
    prepended_skippable.extend_from_slice(&payload);
    let mut split_pair = split_a;
    split_pair.extend_from_slice(&split_b);

    for (name, alt) in [
        ("appended empty zstd frame", appended_empty),
        ("appended skippable frame", appended_skippable),
        ("prepended skippable frame", prepended_skippable),
        ("grain split into two frames", split_pair),
    ] {
        let got = c.decompress_frame(&frame_with(&alt));
        // The TYPED variant, not just any Err: proves the
        // single-frame law fired, not that zstd happened to choke
        // (the over-cap test below records why the variant is the
        // evidence). With the single-frame check disabled, all four
        // inputs decoded successfully to the same 4,096 bytes as `data`.
        assert!(
            matches!(got, Err(CodecError::PayloadNotSingleFrame { .. })),
            "{name}: want PayloadNotSingleFrame, got {got:?}"
        );
    }

    // A payload that is ONLY a skippable frame IS a single frame
    // in law 2's terms — law 4 (exact declared length) refuses its
    // zero bytes of output. Recorded here so the division of
    // labour between the two laws is pinned by a test.
    let lone_skippable = frame_with(&skippable);
    assert!(matches!(
        c.decompress_frame(&lone_skippable),
        Err(CodecError::DeclaredLengthMismatch {
            declared: 4096,
            actual: 0
        })
    ));
}

/// THE ACCEPT-SET LEDGER for grain frames: what the decoder accepts
/// BEYOND the canonical encoder's image, pinned as a test so the
/// difference is visible rather than implied.
///
/// Law 2 makes the payload exactly one zstd frame, which ends the
/// UNBOUNDED padding channel law 2 closed (skippable frames
/// carry arbitrary junk to ~8.4 MiB under no coding constraint).
/// It does NOT make the accept set one encoding per grain: any
/// valid single zstd frame decoding to G is still accepted, and
/// the frame header's optional fields are the cheapest witness —
/// a checksum-flagged frame is 4 bytes longer and decodes to the
/// identical grain. Also in this class, not separately constructed:
/// another compression level, another block split, another window
/// size. All are BOUNDED (they cannot pad toward the cap) and all
/// are content-determined.
///
/// Where the remaining multiplicity WOULD be closed: the canonical
/// bytes are the pinned encoder's output (level 3 —
/// `zstd_level_is_pinned_at_three`; libzstd 1.5.7 —
/// `vendored_libzstd_version_is_pinned`; the golden vectors pin the
/// bytes), and byte-canonicality is checkable where re-derivation
/// happens — at ingest, by [`GrainCodec::recompress_matches`], which
/// recompresses the grain and compares the frame BYTES. Never grain
/// DIGESTS: a grain id hashes the uncompressed bytes, so it is
/// identical for every valid compression and would detect none of
/// this. Law 2 is what makes the byte comparison meaningful —
/// without it, a re-derived frame could never match a padded one.
///
/// **The primitive exists; ingest does not INVOKE it
/// (deferred).** So the alternatives below are accepted at ingest, and
/// nothing narrows the set yet.
///
#[test]
fn single_frame_alternatives_are_accepted_and_bounded() {
    let mut c = codec();
    let data = testkit::fill(13, 4096);
    let canonical = c.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));

    // The same grain through a compressor with the content-checksum
    // flag ON — one frame, so law 2 admits it.
    let mut checksummed = zstd::bulk::Compressor::new(ZSTD_LEVEL).unwrap_or_else(|e| panic!("{e}"));
    checksummed
        .set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(true))
        .unwrap_or_else(|e| panic!("{e}"));
    let alt_payload = checksummed
        .compress(&data)
        .unwrap_or_else(|e| panic!("{e}"));
    let mut alt = canonical[..FRAME_HEADER_LEN].to_vec();
    alt.extend_from_slice(&alt_payload);

    // DIFFERENT BYTES, SAME GRAIN, ACCEPTED — the honest statement
    // of the accept set. If a future change makes this Err, that is
    // a NARROWING of the accept set (a reject-more flag day), not a
    // bug fix: come here first.
    assert_ne!(alt, canonical, "the alternative must be distinct bytes");
    let back = c.decompress_frame(&alt).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, data);
    // Bounded, not a padding channel: the checksum costs exactly 4
    // bytes over the canonical frame.
    assert_eq!(alt.len(), canonical.len() + 4);
    // And the canonical encoder never emits it — the writer's image
    // stays single: this crate's compressor leaves the flag off
    // (module doc), so the frames granary WRITES are the pinned
    // ones the golden vectors carry.
    assert_eq!(
        c.compress_grain(&data).unwrap_or_else(|e| panic!("{e}")),
        canonical
    );
}

#[test]
fn truncated_and_garbage_payloads_are_frame_invalid() {
    let mut c = codec();
    let good = c
        .compress_grain(&testkit::fill(10, 5000))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut short = good.clone();
    short.truncate(good.len() - 5);
    assert!(matches!(
        c.decompress_frame(&short),
        Err(CodecError::FrameInvalid)
    ));
    // Trailing garbage after a complete frame: the first frame
    // parses but does not span the payload — law 2's typed
    // refusal (before the single-frame check this reached zstd and
    // came back FrameInvalid; now it never reaches zstd at all).
    let mut trailing = good;
    trailing.push(0xAB);
    assert!(matches!(
        c.decompress_frame(&trailing),
        Err(CodecError::PayloadNotSingleFrame { .. })
    ));
    // Header-only (payload empty): no zstd frame at all — law 2's
    // structural parse refuses it opaquely. (Before that check,
    // zstd yielded 0 bytes and the length mismatch caught it one
    // law later.)
    let header_only = encode_frame_header(1).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        c.decompress_frame(&header_only),
        Err(CodecError::FrameInvalid)
    ));
}

/// Store-side coverage for decompress law 1 (module doc): the
/// header's `unpacked_len` is validated against the
/// [`GRAIN_UNPACKED_MAX`] cap BEFORE any allocation. Before this
/// test, only granary-core's OWN suite exercised the over-cap
/// direction (`binfmt::tests::frame_header_roundtrip_and_rejects`);
/// this crate's `declared_length_lies_are_rejected_both_directions`
/// above uses 99 and 101, both comfortably under the cap, so
/// removing core's over-cap check left granary-store's own 15
/// tests green. This constructs a frame whose HEADER declares
/// `GRAIN_UNPACKED_MAX + 1` behind a one-byte payload — deliberately
/// far too small to satisfy ANY declared length, let alone one over
/// 8 MiB — so if the refusal ever came from `decompress` instead of
/// the header parse, this test would fail with `FrameInvalid` or
/// `DeclaredLengthMismatch`, not the `Header(CapExceeded)` asserted
/// below: getting the right ERROR VARIANT is what proves the cap
/// check fired before `declared` was ever used to size an
/// allocation, not merely that decompression eventually failed.
#[test]
fn over_cap_declared_length_is_refused_before_decompression() {
    let mut c = codec();
    let mut frame = encode_frame_header(1)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_vec();
    frame[5..9].copy_from_slice(&(GRAIN_UNPACKED_MAX + 1).to_be_bytes());
    frame.push(0xAB); // payload: one byte, nowhere near any legal declared length
    assert!(matches!(
        c.decompress_frame(&frame),
        Err(CodecError::Header(DecodeError::CapExceeded {
            what: "frame unpacked_len",
            got,
            cap,
        })) if got == u64::from(GRAIN_UNPACKED_MAX + 1) && cap == u64::from(GRAIN_UNPACKED_MAX)
    ));
}

/// zstd Ok is NOT integrity — measured: ~99% of mid-frame
/// corruptions decompress silently. This test
/// documents the contract the caller must honour: a corrupted
/// frame CAN decompress Ok with wrong bytes — blake3 against the
/// grain id is the integrity layer.
#[test]
fn silent_corruption_is_the_callers_problem_by_contract() {
    let mut c = codec();
    let data = testkit::fill(11, 1_000_000);
    let frame = c.compress_grain(&data).unwrap_or_else(|e| panic!("{e}"));
    let mut hits = 0u32;
    for i in 0..200usize {
        let mut bad = frame.clone();
        let pos = FRAME_HEADER_LEN + 20 + (i * 4801) % (frame.len() - 40 - FRAME_HEADER_LEN);
        bad[pos] ^= 0x01;
        if let Ok(out) = c.decompress_frame(&bad) {
            assert_eq!(out.len(), data.len());
            if out != data {
                hits += 1; // silently wrong bytes — the documented hazard
            }
        }
    }
    assert!(
        hits > 0,
        "expected at least one silent corruption in 200 flips"
    );
}

mod recompress;
