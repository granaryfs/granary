// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Binmap rejects corpus.
//! Every decode rule gets its own dedicated red vector asserting the
//! SPECIFIC error variant.
//!
//!
//! Bodies that the real encoder cannot produce (unsorted entries, a
//! duplicate digest, an over-cap count, `prefix_bits` 13) are hand-built
//! byte-by-byte, the technique `manifest_rejects` uses for the same
//! reason. Where the encoder CAN be pointed at the violation it is
//! asserted too: the canonical encoder must refuse everything the
//! decoder rejects, and an encoder that emits a
//! body no reader accepts is the same bug seen from the other side.

use granary_core::binfmt::{BIN_FIXED_HEADER_LEN, BIN_MAX_BYTES, FRAME_COMP_MAX, FRAME_HEADER_LEN};
use granary_core::binmap::{
    BIN_TABLE_MAX_BINS, BINMAP_INDEX_FIXED_HEADER_LEN, EncodeBinmapError, PREFIX_BITS_MAX,
    SHARD_MAX_ENTRIES, ShardEntry, decode_bin_table, decode_binmap_index, decode_shard,
    encode_bin_table, encode_binmap_index, encode_shard, validate_ordinals,
};
use granary_core::encoding::{self, DecodeError, ObjectType};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::testkit;

/// The frame-header length in the width the extent fields use. One
/// cast, named once, rather than four `as` sites the pedantic lints
/// would each need excusing (the `binfmt::FRAME_COMP_MAX` precedent).
#[expect(
    clippy::cast_possible_truncation,
    reason = "FRAME_HEADER_LEN = 9 fits any integer type"
)]
const FRAME_HEADER_LEN_U32: u32 = FRAME_HEADER_LEN as u32;

fn synth_id(seed: u64) -> GrainId {
    GrainId::of(&testkit::fill(seed, 8))
}

fn synth_bin_digest(seed: u64) -> [u8; DIGEST_LEN] {
    *GrainId::of(&testkit::fill(seed, 16)).digest()
}

fn entry(seed: u64) -> ShardEntry {
    ShardEntry {
        id: synth_id(seed),
        bin_ordinal: 0,
        offset: BIN_FIXED_HEADER_LEN as u64,
        comp_len: FRAME_HEADER_LEN_U32 + 1,
    }
}

/// Raw shard entry bytes: `grain_id 33 | bin_ordinal u32 | offset u64 |
/// comp_len u32` — UNVALIDATED, the point being to embed values the
/// encoder refuses to emit.
fn push_raw_entry(out: &mut Vec<u8>, id: &GrainId, bin_ordinal: u32, offset: u64, comp_len: u32) {
    out.extend_from_slice(&id.to_bytes());
    out.extend_from_slice(&bin_ordinal.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&comp_len.to_be_bytes());
}

/// A hand-built shard object: envelope + `entry_count` + raw entries.
/// `count` is written verbatim (it need not match `entries`).
fn raw_shard(count: u32, entries: &[u8]) -> Vec<u8> {
    let mut out = encoding::envelope(ObjectType::BinmapShard);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(entries);
    out
}

fn raw_bin_table(count: u32, digests: &[u8]) -> Vec<u8> {
    let mut out = encoding::envelope(ObjectType::BinTable);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(digests);
    out
}

fn raw_binmap_index(prefix_bits: u8, table: &GrainId, shards: &[GrainId]) -> Vec<u8> {
    let mut out = encoding::envelope(ObjectType::BinmapIndex);
    out.push(prefix_bits);
    out.extend_from_slice(&table.to_bytes());
    for s in shards {
        out.extend_from_slice(&s.to_bytes());
    }
    out
}

// ================================================================= shard

/// Duplicates and descending order are ONE rule (strict memcmp ascent),
/// exactly as in the manifest leaf: a duplicate id is a non-strict
/// step, so both vectors assert the order variant.
#[test]
fn decode_shard_rejects_unsorted_entries() {
    let (a, b) = (synth_id(1), synth_id(2));
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut body = Vec::new();
    push_raw_entry(&mut body, &hi, 0, BIN_FIXED_HEADER_LEN as u64, 10);
    push_raw_entry(&mut body, &lo, 0, BIN_FIXED_HEADER_LEN as u64, 10);
    assert_eq!(
        decode_shard(&raw_shard(2, &body)),
        Err(DecodeError::Invalid {
            what: "shard entry order (strict memcmp)",
        })
    );
}

#[test]
fn decode_shard_rejects_duplicate_entry() {
    let id = synth_id(1);
    let mut body = Vec::new();
    push_raw_entry(&mut body, &id, 0, BIN_FIXED_HEADER_LEN as u64, 10);
    push_raw_entry(&mut body, &id, 1, BIN_FIXED_HEADER_LEN as u64, 10);
    assert_eq!(
        decode_shard(&raw_shard(2, &body)),
        Err(DecodeError::Invalid {
            what: "shard entry order (strict memcmp)",
        })
    );
}

#[test]
fn encode_shard_rejects_unsorted_and_duplicate() {
    let (a, b) = (entry(1), entry(2));
    let (lo, hi) = if a.id < b.id { (a, b) } else { (b, a) };
    assert_eq!(
        encode_shard(&[hi, lo]),
        Err(EncodeBinmapError::NotStrictlySorted)
    );
    assert_eq!(
        encode_shard(&[lo, lo]),
        Err(EncodeBinmapError::NotStrictlySorted)
    );
}

#[test]
fn decode_shard_rejects_entry_count_over_cap() {
    let body = raw_shard(SHARD_MAX_ENTRIES + 1, &[]);
    assert_eq!(
        decode_shard(&body),
        Err(DecodeError::CapExceeded {
            what: "binmap shard entry_count",
            got: u64::from(SHARD_MAX_ENTRIES) + 1,
            cap: u64::from(SHARD_MAX_ENTRIES),
        })
    );
}

#[test]
fn encode_shard_rejects_entry_count_over_cap() {
    // The count check precedes the order check, so identical entries
    // are a legitimate (and cheap) way to overflow the cap.
    let too_many = vec![entry(1); SHARD_MAX_ENTRIES as usize + 1];
    assert_eq!(
        encode_shard(&too_many),
        Err(EncodeBinmapError::TooManyEntries {
            count: too_many.len(),
        })
    );
}

#[test]
fn decode_shard_rejects_comp_len_at_frame_header() {
    // comp_len must exceed the 9-byte frame header: an extent covering
    // a header and nothing else decompresses to nothing.
    let mut body = Vec::new();
    push_raw_entry(
        &mut body,
        &synth_id(1),
        0,
        BIN_FIXED_HEADER_LEN as u64,
        FRAME_HEADER_LEN_U32,
    );
    assert_eq!(
        decode_shard(&raw_shard(1, &body)),
        Err(DecodeError::Invalid {
            what: "shard comp_len under frame header",
        })
    );
}

#[test]
fn decode_shard_rejects_comp_len_over_frame_cap() {
    let mut body = Vec::new();
    push_raw_entry(
        &mut body,
        &synth_id(1),
        0,
        BIN_FIXED_HEADER_LEN as u64,
        FRAME_COMP_MAX + 1,
    );
    assert_eq!(
        decode_shard(&raw_shard(1, &body)),
        Err(DecodeError::CapExceeded {
            what: "shard comp_len",
            got: u64::from(FRAME_COMP_MAX) + 1,
            cap: u64::from(FRAME_COMP_MAX),
        })
    );
}

#[test]
fn decode_shard_rejects_offset_inside_bin_header() {
    // A frame can never start before the bin's own fixed header (10-byte
    // envelope + grain_count): such an extent overlaps the bin index.
    let mut body = Vec::new();
    push_raw_entry(
        &mut body,
        &synth_id(1),
        0,
        BIN_FIXED_HEADER_LEN as u64 - 1,
        10,
    );
    assert_eq!(
        decode_shard(&raw_shard(1, &body)),
        Err(DecodeError::Invalid {
            what: "shard offset inside bin header",
        })
    );
}

#[test]
fn encode_shard_rejects_bad_extents() {
    let mut e = entry(1);
    e.comp_len = FRAME_HEADER_LEN_U32;
    assert_eq!(
        encode_shard(&[e]),
        Err(EncodeBinmapError::BadCompLen {
            index: 0,
            comp_len: FRAME_HEADER_LEN_U32,
        })
    );
    let mut e = entry(1);
    e.comp_len = FRAME_COMP_MAX + 1;
    assert_eq!(
        encode_shard(&[e]),
        Err(EncodeBinmapError::BadCompLen {
            index: 0,
            comp_len: FRAME_COMP_MAX + 1,
        })
    );
    let mut e = entry(1);
    e.offset = BIN_FIXED_HEADER_LEN as u64 - 1;
    assert_eq!(
        encode_shard(&[e]),
        Err(EncodeBinmapError::BadOffset {
            index: 0,
            offset: BIN_FIXED_HEADER_LEN as u64 - 1,
        })
    );
}

#[test]
fn decode_shard_rejects_trailing_bytes() {
    let mut bytes = encode_shard(&[entry(1)]).unwrap_or_else(|e| panic!("{e}"));
    bytes.push(0xFF);
    assert_eq!(
        decode_shard(&bytes),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn decode_shard_rejects_truncated_entry_array() {
    // count says 2, one entry follows.
    let mut body = Vec::new();
    push_raw_entry(&mut body, &synth_id(1), 0, BIN_FIXED_HEADER_LEN as u64, 10);
    assert_eq!(
        decode_shard(&raw_shard(2, &body)),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn decode_shard_rejects_unknown_grain_id_tag() {
    let mut body = Vec::new();
    push_raw_entry(&mut body, &synth_id(1), 0, BIN_FIXED_HEADER_LEN as u64, 10);
    let tag = body.first_mut().unwrap_or_else(|| panic!("nonempty body"));
    *tag = 0x02; // unregistered hash algorithm
    assert_eq!(
        decode_shard(&raw_shard(1, &body)),
        Err(DecodeError::Invalid { what: "grain id" })
    );
}

// ============================================================= bin table

#[test]
fn decode_bin_table_rejects_bin_count_zero() {
    assert_eq!(
        decode_bin_table(&raw_bin_table(0, &[])),
        Err(DecodeError::Invalid {
            what: "bin table bin_count zero",
        })
    );
}

#[test]
fn decode_bin_table_rejects_bin_count_over_cap() {
    assert_eq!(
        decode_bin_table(&raw_bin_table(BIN_TABLE_MAX_BINS + 1, &[])),
        Err(DecodeError::CapExceeded {
            what: "bin table bin_count",
            got: u64::from(BIN_TABLE_MAX_BINS) + 1,
            cap: u64::from(BIN_TABLE_MAX_BINS),
        })
    );
}

#[test]
fn encode_bin_table_rejects_count_bounds() {
    assert_eq!(encode_bin_table(&[]), Err(EncodeBinmapError::EmptyTable));
    let too_many = vec![[0u8; DIGEST_LEN]; BIN_TABLE_MAX_BINS as usize + 1];
    assert_eq!(
        encode_bin_table(&too_many),
        Err(EncodeBinmapError::TooManyBins {
            count: too_many.len(),
        })
    );
}

/// A bin appears in the table exactly once: bins are content-addressed,
/// so a repeated digest is the same bin claiming two ordinals — which
/// would make the ordinal→bin mapping ambiguous and defeat the
/// append-only ordinal contract.
#[test]
fn decode_bin_table_rejects_duplicate_digest() {
    let d = synth_bin_digest(11);
    let mut body = Vec::new();
    body.extend_from_slice(&d);
    body.extend_from_slice(&d);
    assert_eq!(
        decode_bin_table(&raw_bin_table(2, &body)),
        Err(DecodeError::Invalid {
            what: "duplicate bin digest in table",
        })
    );
}

#[test]
fn encode_bin_table_rejects_duplicate_digest() {
    let d = synth_bin_digest(11);
    assert_eq!(
        encode_bin_table(&[d, d]),
        Err(EncodeBinmapError::DuplicateBin { index: 1 })
    );
}

#[test]
fn decode_bin_table_rejects_trailing_bytes() {
    let mut bytes = encode_bin_table(&[synth_bin_digest(11)]).unwrap_or_else(|e| panic!("{e}"));
    bytes.push(0xFF);
    assert_eq!(
        decode_bin_table(&bytes),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn decode_bin_table_rejects_truncated_digest_array() {
    assert_eq!(
        decode_bin_table(&raw_bin_table(2, &synth_bin_digest(11))),
        Err(DecodeError::Truncated)
    );
}

// =========================================================== binmap index

/// `prefix_bits` 13 is refused BY NAME, not clamped: routing width is
/// the one field a reader cannot renegotiate, and widening the accepted
/// domain later is a reader flag-day.
#[test]
fn decode_binmap_index_rejects_prefix_bits_13() {
    let table = synth_id(1);
    let shards = vec![synth_id(2); 1 << 13];
    assert_eq!(
        decode_binmap_index(&raw_binmap_index(PREFIX_BITS_MAX + 1, &table, &shards)),
        Err(DecodeError::CapExceeded {
            what: "binmap prefix_bits",
            got: u64::from(PREFIX_BITS_MAX) + 1,
            cap: u64::from(PREFIX_BITS_MAX),
        })
    );
}

#[test]
fn encode_binmap_index_rejects_prefix_bits_13() {
    let table = synth_id(1);
    let shards = vec![synth_id(2); 1 << 13];
    assert_eq!(
        encode_binmap_index(PREFIX_BITS_MAX + 1, table, &shards),
        Err(EncodeBinmapError::PrefixBitsTooWide {
            prefix_bits: PREFIX_BITS_MAX + 1,
        })
    );
}

/// The shard array is exactly `1 << prefix_bits` long and carries NO
/// count field of its own (the width derives it — a second length
/// source is forbidden), so a short array truncates and a long one
/// trails. Both directions get a vector.
#[test]
fn decode_binmap_index_rejects_short_shard_array() {
    let table = synth_id(1);
    let shards = vec![synth_id(2), synth_id(3), synth_id(4)]; // 3, want 4
    assert_eq!(
        decode_binmap_index(&raw_binmap_index(2, &table, &shards)),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn decode_binmap_index_rejects_long_shard_array() {
    let table = synth_id(1);
    let shards = vec![
        synth_id(2),
        synth_id(3),
        synth_id(4),
        synth_id(5),
        synth_id(6),
    ]; // 5, want 4
    assert_eq!(
        decode_binmap_index(&raw_binmap_index(2, &table, &shards)),
        Err(DecodeError::TrailingBytes { remaining: 33 })
    );
}

#[test]
fn encode_binmap_index_rejects_shard_count_mismatch() {
    let table = synth_id(1);
    let shards = vec![synth_id(2), synth_id(3), synth_id(4)];
    assert_eq!(
        encode_binmap_index(2, table, &shards),
        Err(EncodeBinmapError::ShardCountMismatch { got: 3, want: 4 })
    );
}

#[test]
fn decode_binmap_index_rejects_trailing_bytes() {
    let table = synth_id(1);
    let mut bytes = encode_binmap_index(0, table, &[synth_id(2)]).unwrap_or_else(|e| panic!("{e}"));
    bytes.push(0xFF);
    assert_eq!(
        decode_binmap_index(&bytes),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

// ==================================================== cross-object rules

/// `bin_ordinal` is the one shard field a shard cannot check alone: it
/// indexes the bin TABLE, so the bound arrives from the other object.
#[test]
fn validate_ordinals_rejects_ordinal_past_table() {
    let mut e = entry(1);
    e.bin_ordinal = 2;
    assert_eq!(
        validate_ordinals(&[e], 2),
        Err(DecodeError::Invalid {
            what: "shard bin_ordinal past bin table",
        })
    );
    assert_eq!(validate_ordinals(&[e], 3), Ok(()));
    // An empty table bounds nothing: every ordinal is past it.
    assert_eq!(
        validate_ordinals(&[entry(1)], 0),
        Err(DecodeError::Invalid {
            what: "shard bin_ordinal past bin table",
        })
    );
}

// ======================================================== type confusion

/// Each decoder checks the envelope's type tag: the three binmap
/// objects share a body shape family (count + fixed-stride array), so a
/// decoder that trusted the tag its caller expected would happily read
/// a shard as a bin table.
#[test]
fn each_decoder_rejects_the_other_object_types() {
    let table = encode_bin_table(&[synth_bin_digest(11)]).unwrap_or_else(|e| panic!("{e}"));
    let shard = encode_shard(&[entry(1)]).unwrap_or_else(|e| panic!("{e}"));
    let index =
        encode_binmap_index(0, synth_id(9), &[synth_id(8)]).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        decode_binmap_index(&shard),
        Err(DecodeError::Invalid {
            what: "object type (want binmap index)",
        })
    );
    assert_eq!(
        decode_binmap_index(&table),
        Err(DecodeError::Invalid {
            what: "object type (want binmap index)",
        })
    );
    assert_eq!(
        decode_shard(&table),
        Err(DecodeError::Invalid {
            what: "object type (want binmap shard)",
        })
    );
    assert_eq!(
        decode_shard(&index),
        Err(DecodeError::Invalid {
            what: "object type (want binmap shard)",
        })
    );
    assert_eq!(
        decode_bin_table(&shard),
        Err(DecodeError::Invalid {
            what: "object type (want bin table)",
        })
    );
    assert_eq!(
        decode_bin_table(&index),
        Err(DecodeError::Invalid {
            what: "object type (want bin table)",
        })
    );
}

/// A manifest object (a foreign but REGISTERED tag) reaches the same
/// refusal — the type check is a whitelist of one, not a blacklist of
/// the sibling binmap tags.
#[test]
fn decoders_reject_a_foreign_registered_object_type() {
    let mut dir_leaf = encoding::envelope(ObjectType::DirLeaf);
    dir_leaf.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        decode_shard(&dir_leaf),
        Err(DecodeError::Invalid {
            what: "object type (want binmap shard)",
        })
    );
    assert_eq!(
        decode_bin_table(&dir_leaf),
        Err(DecodeError::Invalid {
            what: "object type (want bin table)",
        })
    );
    assert_eq!(
        decode_binmap_index(&dir_leaf),
        Err(DecodeError::Invalid {
            what: "object type (want binmap index)",
        })
    );
}

#[test]
fn decoders_reject_bad_envelope() {
    // `b"XXXXXXXX\x08\x01"`: 8 bytes of wrong magic, then a valid tag
    // and version — the magic check runs first, so this is BadMagic for
    // all three decoders, never a bare is_err() (an is_err() here
    // cannot tell a decoder that started refusing bad magic apart from
    // one that never checked it at all).
    let bad_magic = b"XXXXXXXX\x08\x01".as_slice();
    assert_eq!(decode_shard(bad_magic), Err(DecodeError::BadMagic));
    assert_eq!(decode_bin_table(bad_magic), Err(DecodeError::BadMagic));
    assert_eq!(decode_binmap_index(bad_magic), Err(DecodeError::BadMagic));

    // `b"GRANARY"`: 7 bytes, one short of the 8-byte magic read —
    // Truncated, not BadMagic (the magic comparison never runs).
    let short = b"GRANARY".as_slice();
    assert_eq!(decode_shard(short), Err(DecodeError::Truncated));
    assert_eq!(decode_bin_table(short), Err(DecodeError::Truncated));
    assert_eq!(decode_binmap_index(short), Err(DecodeError::Truncated));
    let mut wrong_version = encoding::MAGIC.to_vec();
    wrong_version.push(ObjectType::BinmapShard.tag());
    wrong_version.push(0x02);
    // The version check inside `open_envelope` runs before the
    // caller-specific object-type check, so all three decoders see the
    // same UnknownVersion regardless of which tag the bytes carry.
    assert_eq!(
        decode_shard(&wrong_version),
        Err(DecodeError::UnknownVersion { version: 0x02 })
    );
    assert_eq!(
        decode_bin_table(&wrong_version),
        Err(DecodeError::UnknownVersion { version: 0x02 })
    );
    assert_eq!(
        decode_binmap_index(&wrong_version),
        Err(DecodeError::UnknownVersion { version: 0x02 })
    );
}

/// The one binmap-index vector that was left unpinned: an
/// unregistered grain-id tag on the bin-table reference. `get_grain_id`
/// validates every id it reads exactly the way `decode_shard`'s own
/// `decode_shard_rejects_unknown_grain_id_tag` already pins for a shard
/// entry.
#[test]
fn decode_binmap_index_rejects_unregistered_grain_id_tag() {
    let table = synth_id(1);
    let shards = vec![synth_id(2)]; // prefix_bits = 0 -> exactly one shard
    let mut bytes = raw_binmap_index(0, &table, &shards);
    let tag = bytes
        .get_mut(BINMAP_INDEX_FIXED_HEADER_LEN)
        .unwrap_or_else(|| panic!("bin_table tag byte present"));
    *tag = 0x02; // unregistered hash algorithm
    assert_eq!(
        decode_binmap_index(&bytes),
        Err(DecodeError::Invalid { what: "grain id" })
    );
}

// ------------------------------------- pre-freeze accept-set bounds

/// The extent must fit inside a legal bin. `BIN_MAX_BYTES` is
/// FROZEN, so this is checkable shard-locally — the module doc's old
/// claim that only "the bin it points into" carries the bound was
/// wrong, and `offset = 2^63` with a maximal `comp_len` round-tripped.
/// Both directions asserted: the hand-built body the decoder must
/// refuse, AND the encoder refusing to emit it.
#[test]
fn an_extent_past_bin_max_is_refused() {
    let mut body = encoding::envelope(ObjectType::BinmapShard);
    body.extend_from_slice(&1u32.to_be_bytes());
    // Just past the frozen ceiling: end = BIN_MAX_BYTES + 1.
    let comp_len = FRAME_HEADER_LEN_U32 + 1;
    let offset = BIN_MAX_BYTES - u64::from(comp_len) + 1;
    push_raw_entry(&mut body, &synth_id(1), 0, offset, comp_len);
    assert!(
        matches!(
            decode_shard(&body),
            Err(DecodeError::CapExceeded {
                what: "shard extent end",
                ..
            })
        ),
        "an extent running past BIN_MAX_BYTES must be refused"
    );

    // The end-of-range case: the addition itself overflows u64.
    let mut overflow = encoding::envelope(ObjectType::BinmapShard);
    overflow.extend_from_slice(&1u32.to_be_bytes());
    push_raw_entry(&mut overflow, &synth_id(2), 0, u64::MAX, comp_len);
    assert!(
        matches!(
            decode_shard(&overflow),
            Err(DecodeError::Invalid {
                what: "shard extent end overflows u64"
            })
        ),
        "an overflowing extent must be refused, never wrapped or panicked on"
    );

    // Exactly at the ceiling is LEGAL — the bound is inclusive, and a
    // frame ending on the last byte of a maximal bin is a real extent.
    let mut at_cap = encoding::envelope(ObjectType::BinmapShard);
    at_cap.extend_from_slice(&1u32.to_be_bytes());
    push_raw_entry(
        &mut at_cap,
        &synth_id(3),
        0,
        BIN_MAX_BYTES - u64::from(comp_len),
        comp_len,
    );
    assert!(
        decode_shard(&at_cap).is_ok(),
        "an extent ending exactly at BIN_MAX_BYTES is legal"
    );

    // The encoder mirrors the decoder.
    let mut e = entry(1);
    e.offset = BIN_MAX_BYTES;
    assert!(matches!(
        encode_shard(&[e]),
        Err(EncodeBinmapError::ExtentPastBinMax { index: 0, .. })
    ));
}

/// The ordinal bound: `bin_ordinal` is bounded at decode against the
/// frozen `BIN_TABLE_MAX_BINS`, independently of the separate
/// `validate_ordinals` call — that call checks against the ACTUAL
/// table, which only a caller holding the table can do.
#[test]
fn an_ordinal_past_the_frozen_table_ceiling_is_refused() {
    let mut body = encoding::envelope(ObjectType::BinmapShard);
    body.extend_from_slice(&1u32.to_be_bytes());
    push_raw_entry(
        &mut body,
        &synth_id(4),
        BIN_TABLE_MAX_BINS,
        BIN_FIXED_HEADER_LEN as u64,
        FRAME_HEADER_LEN_U32 + 1,
    );
    assert!(
        matches!(
            decode_shard(&body),
            Err(DecodeError::CapExceeded {
                what: "shard bin_ordinal",
                ..
            })
        ),
        "an ordinal no legal table could hold must be refused at decode"
    );

    // The last legal ordinal still decodes.
    let mut legal = encoding::envelope(ObjectType::BinmapShard);
    legal.extend_from_slice(&1u32.to_be_bytes());
    push_raw_entry(
        &mut legal,
        &synth_id(5),
        BIN_TABLE_MAX_BINS - 1,
        BIN_FIXED_HEADER_LEN as u64,
        FRAME_HEADER_LEN_U32 + 1,
    );
    assert!(decode_shard(&legal).is_ok(), "the last slot is legal");

    // The encoder mirrors the decoder.
    let mut e = entry(2);
    e.bin_ordinal = BIN_TABLE_MAX_BINS;
    assert!(matches!(
        encode_shard(&[e]),
        Err(EncodeBinmapError::BadOrdinal { index: 0, .. })
    ));
}
