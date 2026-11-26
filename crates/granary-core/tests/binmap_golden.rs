// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Binmap object golden vectors. Every OBJECT emitted by the cases
//! below is
//! a consensus surface — the binmap is how a reader turns a grain id
//! into a byte range, so a red here after a code change means the
//! FORMAT moved bytes: a deliberate versioned event, never a
//! refactor side effect.
//!
//! The `binmap-bits2` case pins ROUTING as well as layout: its entries
//! are placed by [`shard_for`], so a change to the digest-bit
//! extraction moves entries between shards and every shard id (and the
//! index that names them) changes.
//!
//! Regenerate DELIBERATELY:
//! `GRANARY_REGEN_VECTORS=1 cargo nextest run -p granary-core --test binmap_golden`

#![expect(
    clippy::unwrap_used,
    reason = "render/build helpers below sit outside #[test] fns (test code, standards rule 3)"
)]

use std::fmt::Write as _;
use std::path::Path;

use granary_core::binfmt::{BIN_FIXED_HEADER_LEN, FRAME_COMP_MAX};
use granary_core::binmap::{
    ShardEntry, decode_bin_table, decode_binmap_index, decode_shard, encode_bin_table,
    encode_binmap_index, encode_shard, shard_for,
};
use granary_core::encoding::{self, ObjectType};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::testkit;

mod common;

/// A synthetic grain id, reproducible from `seed` alone
/// (`testkit::fill`) — the cases below care about the id's DIGEST BITS
/// (routing) and its order, never about what it addresses.
fn synth_id(seed: u64) -> GrainId {
    GrainId::of(&testkit::fill(seed, 8))
}

/// A synthetic RAW bin digest. Untagged on purpose: a bin table stores
/// bare 32-byte digests, and the volume's hash algorithm is pinned by
/// the root's TAGGED ids.
fn synth_bin_digest(seed: u64) -> [u8; DIGEST_LEN] {
    *GrainId::of(&testkit::fill(seed, 16)).digest()
}

/// An entry whose extent fields are legal but otherwise arbitrary:
/// `offset` clears the bin's fixed header, `comp_len` clears the frame
/// header.
fn entry(seed: u64, bin_ordinal: u32, offset: u64, comp_len: u32) -> ShardEntry {
    ShardEntry {
        id: synth_id(seed),
        bin_ordinal,
        offset,
        comp_len,
    }
}

fn obj(bytes: Vec<u8>) -> (GrainId, Vec<u8>) {
    (GrainId::of(&bytes), bytes)
}

/// One line per object: `case <name>/<i> id=<GrainId text> bytes=<hex
/// of full object>` — the `manifest_golden` rendering, so both vector
/// files read the same way.
fn render(out: &mut String, case: &str, objects: &[(GrainId, Vec<u8>)]) {
    for (i, (id, bytes)) in objects.iter().enumerate() {
        let mut hex = String::new();
        for b in bytes {
            write!(hex, "{b:02x}").unwrap();
        }
        writeln!(out, "case {case}/{i} id={id} bytes={hex}").unwrap();
    }
}

// bin-table-2: two bins. Ordinal 0 and 1 are the append order — the
// table is append-only within an epoch, so these ordinals are what the
// shard entries below point at.
fn case_bin_table_2() -> Vec<(GrainId, Vec<u8>)> {
    let bins = [synth_bin_digest(11), synth_bin_digest(12)];
    vec![obj(encode_bin_table(&bins).unwrap())]
}

// shard-empty: entry_count 0. Legal and canonical — a sparse prefix
// still gets its shard object (one canonical index layout, no sparse
// encoding), so this is the most-published binmap object there is.
fn case_shard_empty() -> Vec<(GrainId, Vec<u8>)> {
    vec![obj(encode_shard(&[]).unwrap())]
}

// shard-3: three entries, sorted by id (the canonical order), spread
// over both bins of bin-table-2.
fn case_shard_3() -> Vec<(GrainId, Vec<u8>)> {
    let mut entries = vec![
        entry(1, 0, BIN_FIXED_HEADER_LEN as u64, 10),
        // comp_len AT the cap: the boundary is imported, not
        // re-literalled, so if the frame cap ever moves this vector
        // goes red — the shard's accepted entry domain moved with it.
        entry(2, 1, 4096, FRAME_COMP_MAX),
        entry(3, 0, 1_000_000, 100),
    ];
    entries.sort_by_key(|e| e.id);
    vec![obj(encode_shard(&entries).unwrap())]
}

// binmap-bits0: the degenerate-but-legal routing width — one shard
// holding everything, over a one-bin table. This is what a fresh small
// volume publishes.
fn case_binmap_bits0() -> Vec<(GrainId, Vec<u8>)> {
    let table = obj(encode_bin_table(&[synth_bin_digest(11)]).unwrap());
    let mut entries: Vec<ShardEntry> = (1..=3)
        .map(|s| entry(s, 0, BIN_FIXED_HEADER_LEN as u64 + s * 64, 64))
        .collect();
    entries.sort_by_key(|e| e.id);
    let shard = obj(encode_shard(&entries).unwrap());
    let index = obj(encode_binmap_index(0, table.0, &[shard.0]).unwrap());
    vec![table, shard, index]
}

// binmap-bits2: four shards, entries placed BY shard_for over the first
// two digest bits, plus the index naming all four. Six ids over four
// shards leave one EMPTY (asserted below, so a seed change cannot
// quietly drop the case's whole point): the index is dense, so the
// empty shard still has an object and still has a slot.
fn case_binmap_bits2() -> Vec<(GrainId, Vec<u8>)> {
    let bits = 2u8;
    let table = obj(encode_bin_table(&[synth_bin_digest(11), synth_bin_digest(12)]).unwrap());
    let mut buckets: Vec<Vec<ShardEntry>> = vec![Vec::new(); 1 << bits];
    for seed in 20..26u64 {
        let e = entry(
            seed,
            u32::try_from(seed % 2).unwrap(),
            BIN_FIXED_HEADER_LEN as u64 + seed * 128,
            128,
        );
        let which = shard_for(&e.id, bits);
        buckets.get_mut(which).unwrap().push(e);
    }
    assert!(
        buckets.iter().any(Vec::is_empty),
        "the bits=2 case must keep at least one EMPTY shard"
    );
    let mut objects = vec![table];
    let mut shard_ids = Vec::new();
    for b in &mut buckets {
        b.sort_by_key(|e| e.id);
        let shard = obj(encode_shard(b).unwrap());
        shard_ids.push(shard.0);
        objects.push(shard);
    }
    let table_id = objects.first().unwrap().0;
    objects.push(obj(encode_binmap_index(bits, table_id, &shard_ids).unwrap()));
    objects
}

fn build_vectors() -> String {
    let mut out = String::new();
    writeln!(out, "# granary binmap golden vectors v1").unwrap();
    render(&mut out, "bin-table-2", &case_bin_table_2());
    render(&mut out, "shard-empty", &case_shard_empty());
    render(&mut out, "shard-3", &case_shard_3());
    render(&mut out, "binmap-bits0", &case_binmap_bits0());
    render(&mut out, "binmap-bits2", &case_binmap_bits2());
    out
}

#[test]
fn matches_committed_vectors() {
    common::assert_golden(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/binmap_v1.txt"),
        &build_vectors(),
    );
}

/// Dispatch on the envelope's object type, exactly as a real reader
/// would (it cannot know in advance which of the three binmap objects
/// a given id resolves to), then re-encode the decoded value and check
/// it reproduces the identical bytes.
fn assert_decodes_and_reencodes(bytes: &[u8]) {
    let (ty, _) = encoding::open_envelope(bytes).unwrap_or_else(|e| panic!("{e}"));
    let re = match ty {
        ObjectType::BinTable => {
            let bins = decode_bin_table(bytes).unwrap_or_else(|e| panic!("{e}"));
            encode_bin_table(&bins).unwrap_or_else(|e| panic!("{e}"))
        }
        ObjectType::BinmapShard => {
            let entries = decode_shard(bytes).unwrap_or_else(|e| panic!("{e}"));
            encode_shard(&entries).unwrap_or_else(|e| panic!("{e}"))
        }
        ObjectType::BinmapIndex => {
            let doc = decode_binmap_index(bytes).unwrap_or_else(|e| panic!("{e}"));
            encode_binmap_index(doc.prefix_bits, doc.bin_table, &doc.shards)
                .unwrap_or_else(|e| panic!("{e}"))
        }
        other => panic!("unexpected object type in binmap goldens: {other:?}"),
    };
    assert_eq!(
        re, bytes,
        "decode→re-encode must reproduce the golden bytes exactly"
    );
}

/// Closes a hole in EVERY case above: `matches_committed_vectors` only
/// string-compares the ENCODER's output against the committed file — it
/// never calls a decoder, so a decoder that started REFUSING a committed
/// vector would be indistinguishable from one that still accepts it
/// (this is exactly how a `>` narrowed to `>=` at a decode boundary
/// would slip through undetected). Every object emitted by every case
/// here must decode successfully and re-encode to the identical bytes;
/// goldens pin the ENCODER's output, but the decoder's accept set is
/// what must hold forever, and the encoder comparison alone
/// does not pin it.
#[test]
fn committed_vectors_decode_and_reencode() {
    for (_, bytes) in case_bin_table_2()
        .into_iter()
        .chain(case_shard_empty())
        .chain(case_shard_3())
        .chain(case_binmap_bits0())
        .chain(case_binmap_bits2())
    {
        assert_decodes_and_reencodes(&bytes);
    }
}

/// The empty shard's id is the binmap's best-known constant: 14 bytes
/// hashed (envelope 10 + `entry_count` = 0), published by every volume
/// with a sparse prefix. Once filled it never changes again (barring a
/// format event), and it is pinned INDEPENDENTLY of the vector file so
/// a regen cannot quietly bless a moved envelope.
///
/// The BYTES are written out here from the format doc rather than taken
/// from the encoder — a pinned digest is only worth its input, and the
/// digest below is `blake3` (whose own official vectors are pinned in
/// `hash.rs`) over exactly these fourteen.
#[test]
fn empty_shard_id_is_pinned() {
    let bytes = encode_shard(&[]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        bytes,
        vec![
            0x47, 0x52, 0x41, 0x4E, 0x41, 0x52, 0x59, 0x00, // "GRANARY\0"
            0x08, // ObjectType::BinmapShard
            0x01, // version 1
            0x00, 0x00, 0x00, 0x00, // entry_count = 0
        ]
    );
    assert_eq!(
        GrainId::of(&bytes).to_string(),
        "blake3:55fb987cfb474218b304f1372e285e05de56e8e7a2b9747e39a54288f95c860e"
    );
}
