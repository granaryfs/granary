// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Transfer caps for the two object kinds a store read bounds: a root,
//! whose aggregate cap `granary-core` defines ([`ROOT_MAX_BYTES`]), and a
//! metadata object, which `granary-core` bounds only by FIELD, so its
//! aggregate cap is derived here.
//!
//! **This module is deliberately NOT feature-gated**, and the reason is
//! not tidiness. Both constants are plain `u64`s — nothing in either
//! reaches an `object_store` type — while [`crate::backend`] sits behind
//! the `backend` feature and drags `object_store`, `reqwest`, `hyper` and
//! tokio in with it. A consumer that needs only these two numbers, such
//! as the server's `413` decision,
//! would otherwise pay for that whole closure to name them. They are
//! re-exported from [`crate::backend`] so callers that already take the
//! feature keep their existing paths.

use granary_core::binmap::{
    BIN_TABLE_MAX_BINS, BINMAP_FIXED_HEADER_LEN, BINMAP_INDEX_FIXED_HEADER_LEN, PREFIX_BITS_MAX,
    SHARD_ENTRY_LEN, SHARD_MAX_BYTES, SHARD_MAX_ENTRIES,
};
use granary_core::hash::{DIGEST_LEN, GRAIN_ID_BINARY_LEN};
use granary_core::sheaf::{SHEAF_FIXED_HEADER_LEN, SHEAF_MAX_OPS};

/// Transfer cap for one root object — the root format's own reader
/// ceiling ([`granary_core::root::ROOT_MAX_BYTES`]), re-exported here so
/// every transfer cap a store read uses is named in this one module,
/// alongside [`META_MAX_BYTES`]. The derivation and its bracketing
/// assertions live with the format fields they are built from, in
/// `granary_core::root`.
pub use granary_core::root::ROOT_MAX_BYTES;

/// Transfer cap for one metadata object. `get_meta` reads FOUR object
/// kinds — binmap index, bin table, binmap shard, sheaf — so the cap is
/// derived from the largest of the four, with headroom, exactly as
/// [`ROOT_MAX_BYTES`] is.
///
/// It is NOT `SHARD_MAX_BYTES`, and the difference is not cosmetic.
/// `SHARD_MAX_BYTES` is the OBJECT budget core hands a shard, and core
/// spends that budget on the bin table's DIGEST ARRAY ALONE
/// (`BIN_TABLE_MAX_BINS × DIGEST_LEN == SHARD_MAX_BYTES`); the table's
/// 14-byte fixed header sits outside it. A cap of `SHARD_MAX_BYTES`
/// therefore refuses a legal maximal bin table by 14 bytes — and does it
/// only once a volume reaches the ceiling the format declares
/// (262,144 bins), which is the worst possible time to discover a cap.
///
/// The derivation, one line per kind `get_meta` can be handed:
///
/// ```text
/// binmap index      135,212   envelope 10 + prefix_bits u8 1
///                             + (1<<PREFIX_BITS_MAX 4,096 shard ids
///                             + 1 table id) × GRAIN_ID_BINARY_LEN 33
/// binmap shard    8,388,569   envelope 10 + entry_count u32 4
///                             + SHARD_MAX_ENTRIES 171,195
///                             × SHARD_ENTRY_LEN 49
/// bin table       8,388,622   envelope 10 + bin_count u32 4
///                             + BIN_TABLE_MAX_BINS 262,144
///                             × DIGEST_LEN 32
/// sheaf               1,117   SHEAF_FIXED_HEADER_LEN 60 (envelope 10
///                             + parent presence 1 + manifest_root 33
///                             + timestamp 12 + op_count 4)
///                             + GRAIN_ID_BINARY_LEN 33, the parent id
///                             a PRESENT parent adds after that
///                             presence byte
///                             + SHEAF_MAX_OPS 1,024 × 1 tag byte
///                 ---------
/// largest meta    8,388,622   the bin table
/// ```
///
/// **The sheaf earns its row by being READ HERE, not by being large.** It
/// is a DIRECTLY-ADDRESSED meta object — `publish` writes it with
/// `put_meta`, `resolve` reads it back with `get_meta`, exactly as they
/// do the binmap index — and at ~1 KiB it clears this cap by four orders
/// of magnitude. Leaving it out of the block below would therefore cost
/// nothing today and everything later: a widened `SHEAF_MAX_OPS`, or a
/// payload-carrying op, moves a number no assertion here reads, so the
/// build stays green while `get_meta` starts refusing legal sheaves at
/// run time. That is the failure this cap prevents for the bin table,
/// and an omitted kind would admit it for the sheaf.
/// (`granary-core/src/sheaf.rs`'s grain-size assertion bounds the
/// sheaf's encoding, not this read.)
///
/// 16 MiB is ~2× the bin table. The headroom is deliberate and carries the same
/// argument [`ROOT_MAX_BYTES`] makes: this cap is a denial-of-service
/// bound, not a format rule — the binmap decoders are the authority on
/// what a metadata object may contain, and a cap that tracked the
/// derivation exactly would turn every future field addition into a
/// silent read failure at this layer before the decoder could name it.
/// It also keeps the read cap above anything the ENCODERS can emit, so
/// the write path needs no matching cap to stay readable.
///
/// The measured half is `get_meta_returns_a_maximal_bin_table`, which
/// encodes a maximal table rather than deriving 8,388,622 a second time.
///
/// The headroom is bracketed from BOTH sides below, for the reason
/// [`ROOT_MAX_BYTES`] spells out: the `<= META_MAX_BYTES` assertions pin
/// only the floor, and this constant could be widened SIXTYFOUR-fold to
/// 1 GiB with every one of them and every test still green (measured).
/// The boundary test cannot catch it either — it derives its expectation
/// from this constant, so it follows a mutation instead of refusing it.
pub const META_MAX_BYTES: u64 = 16 * 1024 * 1024;

const _: () = {
    // Built from core's own constants, so widening any of the four
    // kinds (a wider routing prefix, more bins per table, a longer shard
    // entry, more ops per sheaf) breaks the build here instead of
    // silently eating the headroom — or, as this cap's predecessor did,
    // silently losing it.
    let index = BINMAP_INDEX_FIXED_HEADER_LEN as u64
        + ((1u64 << PREFIX_BITS_MAX) + 1) * GRAIN_ID_BINARY_LEN as u64;
    let shard = BINMAP_FIXED_HEADER_LEN as u64 + SHARD_MAX_ENTRIES as u64 * SHARD_ENTRY_LEN as u64;
    let table = BINMAP_FIXED_HEADER_LEN as u64 + BIN_TABLE_MAX_BINS as u64 * DIGEST_LEN as u64;
    // The parent id is NOT in the fixed header — that header carries the
    // presence byte, and a present parent adds the id after it — so a
    // maximal sheaf is the header, plus one id, plus one tag byte per op.
    let sheaf = SHEAF_FIXED_HEADER_LEN as u64 + GRAIN_ID_BINARY_LEN as u64 + SHEAF_MAX_OPS as u64;
    assert!(index == 135_212);
    assert!(shard == 8_388_569);
    assert!(table == 8_388_622);
    assert!(sheaf == 1_117);
    // The bin table is the largest of the four, and the cap clears it.
    // Each kind is asserted SEPARATELY: a single check against the
    // maximum would go quiet if a different kind became the largest —
    // which is precisely the sheaf's position, four orders of magnitude
    // under the table and so invisible to any check written against the
    // maximum alone.
    assert!(index <= META_MAX_BYTES);
    assert!(shard <= META_MAX_BYTES);
    assert!(table <= META_MAX_BYTES);
    assert!(sheaf <= META_MAX_BYTES);
    // The tight fit this cap exists to avoid, pinned as a relation: a
    // maximal bin table does NOT fit the shard budget, so anyone
    // tempted to reuse SHARD_MAX_BYTES here fails the build.
    assert!(table > SHARD_MAX_BYTES);
    // The CEILING, against the largest kind. The documented ~2× is what
    // this cap costs a reader per metadata object; widening past it is a
    // decision, and this is where it has to be made.
    assert!(META_MAX_BYTES <= 2 * table);
};
