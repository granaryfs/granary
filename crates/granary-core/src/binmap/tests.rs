// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::binmap` — the binmap format v1 index/table/shard encode-decode contract.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::testkit;

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
        comp_len: 10,
    }
}

fn sorted(seeds: std::ops::Range<u64>) -> Vec<ShardEntry> {
    let mut v: Vec<ShardEntry> = seeds.map(entry).collect();
    v.sort_by_key(|e| e.id);
    v
}

/// The first `bits` bits of the digest, computed one bit at a time —
/// deliberately NOT the shift-and-mask the implementation uses, so
/// an off-by-one in either is visible.
fn reference_route(digest: &[u8; DIGEST_LEN], bits: u8) -> usize {
    let mut acc = 0usize;
    for i in 0..usize::from(bits) {
        let byte = digest.get(i / 8).copied().unwrap_or(0);
        let bit = (byte >> (7 - (i % 8))) & 1;
        acc = (acc << 1) | usize::from(bit);
    }
    acc
}

#[test]
fn caps_are_the_frozen_relations() {
    assert_eq!(SHARD_ENTRY_LEN, 49);
    assert_eq!(BINMAP_FIXED_HEADER_LEN, 14);
    assert_eq!(BINMAP_INDEX_FIXED_HEADER_LEN, 11);
    assert_eq!(SHARD_MAX_ENTRIES, 171_195);
    assert_eq!(BIN_TABLE_MAX_BINS, 262_144);
    assert_eq!(PREFIX_BITS_MAX, 12);
    assert_eq!(SHARD_MAX_BYTES, 8 * 1024 * 1024);
    assert_eq!(SHARD_TARGET_BYTES, 1024 * 1024);
}

/// Routing is over digest bits. Two properties over `testkit`-
/// generated ids at every legal width: the result is in range, and
/// it equals a bit-by-bit reference extraction.
#[test]
fn shard_for_is_the_first_digest_bits() {
    for seed in 0..512u64 {
        let id = synth_id(seed);
        for bits in 0..=PREFIX_BITS_MAX {
            let got = shard_for(&id, bits);
            assert!(got < (1usize << bits), "seed {seed} bits {bits}: {got}");
            assert_eq!(
                got,
                reference_route(id.digest(), bits),
                "seed {seed} bits {bits}"
            );
        }
    }
}

/// Routing over the ENCODED id would key on the algorithm tag byte
/// and put every grain in shard 0 — the mistake this pins against
/// At bits = 8 a 512-id sample must reach many
/// shards; the encoded-id version would reach exactly one.
#[test]
fn shard_for_spreads_across_shards() {
    let mut seen = std::collections::BTreeSet::new();
    for seed in 0..512u64 {
        seen.insert(shard_for(&synth_id(seed), 8));
    }
    assert!(seen.len() > 100, "only {} distinct shards", seen.len());
    // Every id's first encoded byte is the SAME algorithm tag: any
    // routing that consumed it would collapse to one shard.
    let tags: std::collections::BTreeSet<u8> = (0..512u64)
        .filter_map(|s| synth_id(s).to_bytes().first().copied())
        .collect();
    assert_eq!(tags.len(), 1);
}

/// bits = 0 is the one-shard volume; a width past the cap clamps
/// rather than shifting out of range (the function is total).
#[test]
fn shard_for_edges_are_total() {
    let id = synth_id(7);
    assert_eq!(shard_for(&id, 0), 0);
    assert_eq!(
        shard_for(&id, PREFIX_BITS_MAX + 1),
        shard_for(&id, PREFIX_BITS_MAX)
    );
    assert_eq!(shard_for(&id, u8::MAX), shard_for(&id, PREFIX_BITS_MAX));
}

/// `check_strictly_sorted` compares by `GrainId`'s derived `Ord`;
/// the FORMAT rule is memcmp of the 33-byte encoding. They agree
/// because the algorithm tag leads both — pinned here so a registry
/// addition that broke declaration order would be caught in the
/// module that depends on it.
#[test]
fn id_ord_is_encoded_memcmp() {
    let ids: Vec<GrainId> = (0..64u64).map(synth_id).collect();
    for a in &ids {
        for b in &ids {
            assert_eq!(a.cmp(b), a.to_bytes().cmp(&b.to_bytes()));
        }
    }
    // WHAT THIS TEST CANNOT SEE, stated so nobody mistakes it for
    // the guarantee. Every id above is Blake3,
    // so the ALGORITHM half of the derived `Ord` is constant and
    // never exercised: the comparison degenerates to the digests.
    // The hazard it is named for — derived `Ord` diverging from
    // encoded memcmp — needs a SECOND algorithm, and it would
    // arrive the moment one is registered out of tag order (a
    // `Sha256 = 0x02` declared BEFORE `Blake3 = 0x01` in the enum
    // would order Sha256 first by derivation and second by wire
    // byte). That is a consensus split — shard order IS canonical
    // form — and it would ship green past this test.
    //
    // It cannot be probed here without a second tag to construct,
    // so the obligation is recorded where the split would be
    // introduced rather than faked with a fixture: registering any
    // new hash algorithm requires re-proving this property across
    // tags, and the enum's discriminants must stay ascending in
    // declaration order. Pinned below as far as one tag allows:
    // the tag is the FIRST encoded byte, so memcmp reaches it
    // before any digest byte.
    let id = synth_id(7);
    let encoded = id.to_bytes();
    assert_eq!(
        encoded.first(),
        Some(&0x01),
        "Blake3's tag is 0x01 and leads the encoding — a second \
         algorithm's tag orders ahead of or behind every digest, \
         which is why declaration order must match tag order"
    );
}

#[test]
fn shard_roundtrip_is_canonical() {
    for entries in [sorted(0..0), sorted(1..2), sorted(1..64)] {
        let bytes = encode_shard(&entries).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            bytes.len(),
            BINMAP_FIXED_HEADER_LEN + entries.len() * SHARD_ENTRY_LEN
        );
        let decoded = decode_shard(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(decoded, entries);
        let re = encode_shard(&decoded).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(re, bytes);
    }
}

/// Every field survives the round trip in its own right: an entry
/// whose four values are pairwise distinct catches a swapped
/// `offset`/`comp_len` write that identical placeholders would hide.
#[test]
fn shard_entry_fields_are_distinct_positions() {
    // Position-distinguishing values that are also LEGAL under the
    // pre-freeze bounds: the
    // originals — ordinal 0x0102_0304 and offset 0x1112… — now
    // exceed BIN_TABLE_MAX_BINS and BIN_MAX_BYTES respectively.
    // Each field still carries a distinct byte pattern, which is
    // all this test needs: a swapped pair shows up in the tail
    // comparison below.
    let e = ShardEntry {
        id: synth_id(3),
        bin_ordinal: 0x0003_0201,
        offset: 0x0000_0000_0102_0304,
        comp_len: 0x0021_2223,
    };
    let bytes = encode_shard(&[e]).unwrap_or_else(|err| panic!("{err}"));
    let decoded = decode_shard(&bytes).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(decoded.first(), Some(&e));
    // The tail of the object, field by field, big-endian.
    let tail = bytes
        .get(BINMAP_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN..)
        .unwrap_or_else(|| panic!("entry tail present"));
    assert_eq!(
        tail,
        [
            0x00, 0x03, 0x02, 0x01, // bin_ordinal
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, // offset
            0x00, 0x21, 0x22, 0x23, // comp_len
        ]
    );
}

#[test]
fn bin_table_roundtrip_is_canonical() {
    let bins: Vec<[u8; DIGEST_LEN]> = (0..8u64).map(synth_bin_digest).collect();
    let bytes = encode_bin_table(&bins).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        bytes.len(),
        BINMAP_FIXED_HEADER_LEN + bins.len() * DIGEST_LEN
    );
    let decoded = decode_bin_table(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decoded, bins);
    let re = encode_bin_table(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);
    // Order is meaning: the table is positional, so a sorted table
    // is a DIFFERENT table (and these digests are not in order).
    let mut shuffled = bins.clone();
    shuffled.sort_unstable();
    assert_ne!(shuffled, bins, "fixture must not be pre-sorted");
    let other = encode_bin_table(&shuffled).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(other, bytes);
}

#[test]
fn binmap_index_roundtrip_is_canonical() {
    for bits in 0..=PREFIX_BITS_MAX {
        let shards: Vec<GrainId> = (0..(1u64 << bits)).map(synth_id).collect();
        let table = synth_id(9999);
        let bytes = encode_binmap_index(bits, table, &shards).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            bytes.len(),
            BINMAP_INDEX_FIXED_HEADER_LEN + (shards.len() + 1) * GRAIN_ID_BINARY_LEN
        );
        let doc = decode_binmap_index(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(doc.prefix_bits, bits);
        assert_eq!(doc.bin_table, table);
        assert_eq!(doc.shards, shards);
        let re = encode_binmap_index(doc.prefix_bits, doc.bin_table, &doc.shards)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(re, bytes);
    }
}

#[test]
fn find_entry_finds_every_member_and_no_stranger() {
    let entries = sorted(1..64);
    for e in &entries {
        assert_eq!(find_entry(&entries, &e.id), Some(e));
    }
    assert_eq!(find_entry(&entries, &synth_id(1000)), None);
    assert_eq!(find_entry(&[], &synth_id(1)), None);
}

/// The publisher's routing contract end to end: entries land in the
/// shard `shard_for` names, and a lookup that routes first finds
/// them there.
#[test]
fn routed_entries_are_found_in_their_own_shard() {
    let bits = 3u8;
    let mut buckets: Vec<Vec<ShardEntry>> = vec![Vec::new(); 1 << bits];
    let all = sorted(1..200);
    for e in &all {
        let at = shard_for(&e.id, bits);
        buckets
            .get_mut(at)
            .unwrap_or_else(|| panic!("route {at} in range"))
            .push(*e);
    }
    let shards: Vec<Vec<ShardEntry>> = buckets
        .iter()
        .map(|b| {
            let bytes = encode_shard(b).unwrap_or_else(|e| panic!("{e}"));
            decode_shard(&bytes).unwrap_or_else(|e| panic!("{e}"))
        })
        .collect();
    assert_eq!(shards.iter().map(Vec::len).sum::<usize>(), all.len());
    for e in &all {
        let shard = shards
            .get(shard_for(&e.id, bits))
            .unwrap_or_else(|| panic!("shard present"));
        assert_eq!(find_entry(shard, &e.id), Some(e));
    }
}

#[test]
fn validate_ordinals_is_the_cross_object_bound() {
    let mut e = entry(1);
    e.bin_ordinal = 3;
    assert_eq!(validate_ordinals(&[e], 4), Ok(()));
    assert!(validate_ordinals(&[e], 3).is_err());
    assert_eq!(validate_ordinals(&[], 0), Ok(()));
}

/// `validate_routing` end to end: correct routing accepted, a
/// misrouted entry refused by name, its two range refusals
/// (over-cap `prefix_bits`, out-of-range `shard_index`) each
/// refused by name, and an empty shard accepted at any in-range
/// index — the decided-not-overlooked vacuous case its doc
/// comment states explicitly.
#[test]
fn validate_routing_is_the_cross_object_bound() {
    let bits = 3u8;
    let all = sorted(1..200);
    let first = all.first().unwrap_or_else(|| panic!("nonempty fixture"));
    let target = shard_for(&first.id, bits);
    let target_entries: Vec<ShardEntry> = all
        .iter()
        .copied()
        .filter(|e| shard_for(&e.id, bits) == target)
        .collect();
    let foreign = all
        .iter()
        .copied()
        .find(|e| shard_for(&e.id, bits) != target)
        .unwrap_or_else(|| panic!("need an entry outside the target shard"));

    // Correct routing accepted.
    assert_eq!(validate_routing(&target_entries, bits, target), Ok(()));

    // A misrouted entry refused by name.
    let mut bad = target_entries.clone();
    bad.push(foreign);
    assert_eq!(
        validate_routing(&bad, bits, target),
        Err(DecodeError::Invalid {
            what: "shard entry routed to the wrong shard",
        })
    );

    // An over-cap prefix_bits refused by name — the identical
    // variant and "what" string that decode_binmap_index uses
    // for the same rule (two spellings for one rule is its own
    // defect).
    assert_eq!(
        validate_routing(&[], PREFIX_BITS_MAX + 1, 0),
        Err(DecodeError::CapExceeded {
            what: "binmap prefix_bits",
            got: u64::from(PREFIX_BITS_MAX) + 1,
            cap: u64::from(PREFIX_BITS_MAX),
        })
    );

    // An out-of-range shard_index refused by name.
    assert_eq!(
        validate_routing(&[], bits, 1usize << bits),
        Err(DecodeError::Invalid {
            what: "shard_index past routing width",
        })
    );

    // An EMPTY shard is valid at any IN-RANGE index — decided, not
    // overlooked.
    assert_eq!(validate_routing(&[], bits, target), Ok(()));
    assert_eq!(validate_routing(&[], bits, (1usize << bits) - 1), Ok(()));
}

/// The entry-count cap BOUNDARY is legal, not just refused past it:
/// exactly `SHARD_MAX_ENTRIES` entries must encode and decode back to
/// exactly that many. Flipping `>` to `>=` in either `encode_shard`'s
/// or `decode_shard`'s cap check would silently narrow the fleet's
/// accepted set and ship green.
#[test]
fn max_entries_shard_is_accepted() {
    let entries = sorted(0..u64::from(SHARD_MAX_ENTRIES));
    assert_eq!(entries.len(), SHARD_MAX_ENTRIES as usize);
    let bytes = encode_shard(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        bytes.len(),
        BINMAP_FIXED_HEADER_LEN + SHARD_MAX_ENTRIES as usize * SHARD_ENTRY_LEN
    );
    let decoded = decode_shard(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decoded.len(), SHARD_MAX_ENTRIES as usize);
    assert_eq!(decoded, entries);
}

/// The bin-count cap BOUNDARY is legal, not just refused past it —
/// mirrors `max_entries_shard_is_accepted` for the OTHER binmap
/// object; a `>` loosened to `>=` in `decode_bin_table`'s cap check
/// would silently narrow the fleet's accepted set and ship green.
#[test]
fn max_bins_table_is_accepted() {
    let bins: Vec<[u8; DIGEST_LEN]> = (0..u64::from(BIN_TABLE_MAX_BINS))
        .map(synth_bin_digest)
        .collect();
    let bytes = encode_bin_table(&bins).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        bytes.len(),
        BINMAP_FIXED_HEADER_LEN + BIN_TABLE_MAX_BINS as usize * DIGEST_LEN
    );
    let decoded = decode_bin_table(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decoded.len(), BIN_TABLE_MAX_BINS as usize);
    assert_eq!(decoded, bins);
}

/// The `comp_len` cap BOUNDARY is legal on the DECODE side too — these
/// exact bytes already sit inside the committed shard-3 golden
/// vector and fuzz corpus seed seed-shard-3-0: a `>` loosened to
/// `>=` in `decode_shard`'s `comp_len` check would make every reader
/// refuse already-committed, already-signed artefacts while the
/// whole suite still ships green.
#[test]
fn max_comp_len_entry_is_accepted() {
    let e = ShardEntry {
        id: synth_id(1),
        bin_ordinal: 0,
        offset: BIN_FIXED_HEADER_LEN as u64,
        comp_len: FRAME_COMP_MAX,
    };
    let bytes = encode_shard(&[e]).unwrap_or_else(|err| panic!("{err}"));
    let decoded = decode_shard(&bytes).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(decoded, vec![e]);
}

/// The fifth cap-accept boundary this surface has:
/// `validate_routing`'s OWN `prefix_bits > PREFIX_BITS_MAX` check, a
/// code site distinct from `decode_binmap_index`'s —
/// `binmap_index_roundtrip_is_canonical` proves THAT one's accept
/// side at bits = `PREFIX_BITS_MAX`, but it never calls
/// `validate_routing`, so it proves nothing about this site. A `>`
/// tightened to `>=` here would wrongly refuse a legal
/// maximal-width volume's own routing check while the rest of the
/// suite ships green. This row pins that guard's accept side
/// in-crate: an empty shard at bits = `PREFIX_BITS_MAX`, shard
/// index 0, is accepted.
#[test]
fn validate_routing_prefix_bits_accept_boundary_is_not_capped() {
    assert_eq!(validate_routing(&[], PREFIX_BITS_MAX, 0), Ok(()));
}
