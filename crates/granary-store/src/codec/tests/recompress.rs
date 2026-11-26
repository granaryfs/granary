// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The frame byte-canonicality primitive's own rows, in a module of their
//! own so the byte-compare question is filterable apart from the
//! codec's roundtrip battery (`cargo nextest run -p granary-store
//! codec::tests::recompress`).
//!
//! Out-of-line, because a module's second conforming test body
//! becomes a leaf under `tests`, declared by `codec/tests.rs`'s
//! `mod recompress;` rather than a second sibling declaration
//! in the parent (`codec.rs`). Nesting one level deeper under
//! `tests` changes what the `super` keyword reaches here, so
//! the one such path in this file carries one extra `super`
//! segment relative to the same body inline in the parent.

use super::super::{CodecError, GrainCodec, ZSTD_LEVEL};
use granary_core::binfmt::FRAME_HEADER_LEN;
use granary_core::hash::GrainId;
use granary_core::testkit;

/// **The row that separates a byte compare from a digest compare**:
/// the
/// witness is a frame with the SAME grain and therefore the SAME
/// grain id as the canonical one, and different bytes.
///
/// A digest compare answers `true` here — it is comparing
/// `blake3(grain)` with itself — so it detects no non-canonical
/// framing at all. The accept-set ledger in the PARENT module
/// (`codec/tests.rs`, which declares this one — hence the two `super`
/// segments in this file's import)
/// (`single_frame_alternatives_are_accepted_and_bounded`) is where
/// that alternative is pinned as accepted; this is where it is
/// pinned as NOT canonical.
#[test]
fn recompress_matches_compares_frame_bytes_and_not_grain_digests() {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let data = testkit::fill(13, 4096);
    let canonical = codec
        .compress_grain(&data)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        codec
            .recompress_matches(&data, &canonical)
            .unwrap_or_else(|e| panic!("{e}")),
        "the encoder's own output must match"
    );

    // The same grain through a compressor with the content-checksum
    // flag ON: one zstd frame (law 2 admits it), four bytes longer,
    // and it decompresses to exactly the same grain.
    let mut checksummed = zstd::bulk::Compressor::new(ZSTD_LEVEL).unwrap_or_else(|e| panic!("{e}"));
    checksummed
        .set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(true))
        .unwrap_or_else(|e| panic!("{e}"));
    let alt_payload = checksummed
        .compress(&data)
        .unwrap_or_else(|e| panic!("{e}"));
    let mut alt = canonical
        .get(..FRAME_HEADER_LEN)
        .unwrap_or_default()
        .to_vec();
    alt.extend_from_slice(&alt_payload);

    assert_ne!(alt, canonical, "the alternative must be distinct bytes");
    let decoded = codec
        .decompress_frame(&alt)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decoded, data, "the alternative holds the same grain");
    assert_eq!(
        GrainId::of(&decoded),
        GrainId::of(&data),
        "and therefore the same grain id — which is why a digest \
         compare cannot tell these two frames apart"
    );

    assert!(
        !codec
            .recompress_matches(&data, &alt)
            .unwrap_or_else(|e| panic!("{e}")),
        "a hash-valid frame this encoder would not have written is \
         NOT canonical; a digest compare answers true here"
    );

    // A frame holding an entirely different grain, so the row is not
    // passing on the framing flag alone.
    let other = codec
        .compress_grain(&testkit::fill(14, 4096))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !codec
            .recompress_matches(&data, &other)
            .unwrap_or_else(|e| panic!("{e}"))
    );

    // The error arm is about the PLAINTEXT, which is the only input
    // this primitive re-derives from. A `stored_frame` that is not a
    // frame at all is simply not a match.
    assert!(matches!(
        codec.recompress_matches(&[], &canonical),
        Err(CodecError::EmptyGrain)
    ));
    assert!(
        !codec
            .recompress_matches(&data, b"not a frame")
            .unwrap_or_else(|e| panic!("{e}"))
    );
}
