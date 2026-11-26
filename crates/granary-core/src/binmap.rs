// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Binmap format v1.
//!
//! The binmap answers the one question a reader asks between the
//! manifest and the object store: given a grain id, WHICH bin holds it
//! and at what byte range. It is three object types, not one, because a
//! whole-volume map is rewritten on every publish otherwise:
//!
//! ```text
//! BinmapIndex (0x06)  prefix_bits, bin-table ref, 1<<prefix_bits shard refs
//! BinTable    (0x07)  the bin ids, positionally numbered (the ordinals)
//! BinmapShard (0x08)  sorted grain -> {bin ordinal, offset, comp_len}
//! ```
//!
//! A grain routes to its shard by the first `prefix_bits` bits of its
//! DIGEST — never the 33-byte encoded id, whose leading algorithm tag is
//! identical for every grain and would route the whole volume into shard
//! 0 (the local-store digest-fanout precedent). Publishing
//! rewrites only the shards it touched; unchanged shards are
//! content-addressed and dedup.
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! shard:      envelope (10), entry_count u32 (0 ..= SHARD_MAX_ENTRIES),
//!             entries × 49 { grain_id 33, bin_ordinal u32, offset u64,
//!             comp_len u32 }, strictly memcmp-ascending by grain_id
//! bin table:  envelope (10), bin_count u32 (1 ..= BIN_TABLE_MAX_BINS),
//!             bin_count × 32-byte RAW digest, no duplicates
//! index:      envelope (10), prefix_bits u8 (0 ..= PREFIX_BITS_MAX),
//!             bin_table id 33, exactly 1<<prefix_bits shard ids × 33
//! ```
//!
//! **Bin digests are UNTAGGED.** A bin is content-addressed by the bare
//! blake3 digest of its full bytes; the table stores the 32 digest bytes
//! and nothing else. The volume's hash algorithm is pinned by the root's
//! TAGGED [`GrainId`]s, so a per-bin tag would be a quarter-million
//! bytes of restating it (same reasoning as the local store's
//! digest-only fanout). Shard entries, in contrast, carry FULL tagged
//! ids: they are grain ids, the same 33 bytes the manifest holds, and
//! comparing them against manifest ids must not require re-tagging.
//!
//! **The bin table is APPEND-ONLY within an epoch.** An ordinal is a
//! position in this array, so a published shard entry stays meaningful
//! only while positions do not move: every publish appends its new bins
//! and rewrites nothing. Renumbering is a REPACK event whose cost
//! includes rewriting every shard. This is not
//! enforceable inside one object's codec — a table is just a list, and
//! nothing in these bytes records what the previous epoch's table held —
//! so it is a publisher obligation stated here and in the format doc,
//! checked where two epochs meet, not here.
//!
//! **`prefix_bits` accepts 0 ..= [`PREFIX_BITS_MAX`] and refuses wider
//! BY NAME.** Widening the domain later is a reader flag-day (old
//! readers cannot route what they cannot address), so the ceiling is set
//! once, high enough for the measured volume bound in the format doc.
//! [`SHARD_TARGET_BYTES`] is the publisher's SPLIT TRIGGER — packing
//! policy, deliberately decoupled from the frozen refuse cap
//! [`SHARD_MAX_BYTES`] (the decoupling cuts publish-time shard-rewrite
//! amplification ~8×). A publisher chooses `prefix_bits`
//! so the EXPECTED shard lands near the target; the cap is what a reader
//! refuses, and the two must never be conflated.
//!
//! What a shard can check ALONE: entry order and uniqueness, the extent
//! bounds ([`crate::binfmt::FRAME_COMP_MAX`], the bin's fixed header), its own
//! exact length. Both `bin_ordinal` and the extent are ALSO bounded
//! here, against the frozen ceilings, as an accept-set decision taken
//! before the bin format froze:
//! `offset + comp_len <= BIN_MAX_BYTES` and
//! `bin_ordinal < BIN_TABLE_MAX_BINS`. The extent bound is checkable
//! shard-locally with no cross-object information; without it an entry
//! could round-trip with `offset = 2^63`.
//!
//! What still cannot be checked locally is each ordinal against the
//! ACTUAL table length — [`validate_ordinals`] remains that
//! cross-object step, now narrowed to "does this table have that many
//! bins" rather than standing alone against an unbounded index.
//! Readers still slice extents with checked arithmetic, as
//! [`crate::binfmt::frame_bytes`] does; the decode bound removes the
//! adversarial case rather than the discipline.

use crate::binfmt::{BIN_FIXED_HEADER_LEN, BIN_MAX_BYTES, FRAME_COMP_MAX, FRAME_HEADER_LEN};
use crate::encoding::{self, Cursor, DecodeError, ObjectType};
use crate::hash::{DIGEST_LEN, GRAIN_ID_BINARY_LEN, GrainId};
use crate::manifest::node::check_strictly_sorted;

/// Widest routing prefix v1 accepts. Wider is refused by name: reading
/// a volume published at a wider width would require a reader that
/// already understands it (a flag-day), and the ceiling costs nothing
/// today.
pub const PREFIX_BITS_MAX: u8 = 12;

/// One shard entry: grain id + bin ordinal + extent. The registered
/// per-grain binmap cost (`granary-bench` `cost.rs` `BINMAP_ENTRY_BYTES`)
/// is this number, field for field.
pub const SHARD_ENTRY_LEN: usize = GRAIN_ID_BINARY_LEN + 4 + 8 + 4;

/// Envelope + the u32 count — the fixed prefix of a shard and of a bin
/// table (both are a counted, fixed-stride array).
pub const BINMAP_FIXED_HEADER_LEN: usize = 10 + 4;

/// Envelope + `prefix_bits` — the fixed prefix of a binmap index.
pub const BINMAP_INDEX_FIXED_HEADER_LEN: usize = 10 + 1;

/// Hard cap on one shard object — a FROZEN decode cap (caps must be
/// validated before allocation), NOT a packing target.
/// (The resident cost of a decoded shard exceeds this: entries are
/// 56-byte `ShardEntry` STRUCTS against a 49-byte wire stride, plus the
/// decoder's dedup set. Bounded either way — recorded because this
/// comment documents the resident allocation bound and the wire figure alone
/// understates it.)
pub const SHARD_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Packing TARGET — policy, not format: the publisher picks
/// `prefix_bits` so the expected shard lands near this, and re-shards
/// when it drifts. Decoupled from [`SHARD_MAX_BYTES`] on purpose: the
/// trigger controls rewrite amplification, the cap controls what a
/// reader will allocate, and moving one must never silently move the
/// other.
pub const SHARD_TARGET_BYTES: u64 = 1024 * 1024;

/// Hard cap on entries per shard — a FROZEN decode cap, DERIVED from
/// [`SHARD_MAX_BYTES`] so the two cannot drift independently (the
/// alternative would require a consistency assertion). Bounds the
/// entry allocation at `171_195 × 49 B ≈ 8 MiB` before a single entry
/// byte is trusted.
#[expect(
    clippy::cast_possible_truncation,
    reason = "8 MiB / 49 = 171_195 — orders below u32::MAX; the static assertions below re-derive it"
)]
pub const SHARD_MAX_ENTRIES: u32 =
    ((SHARD_MAX_BYTES - BINMAP_FIXED_HEADER_LEN as u64) / SHARD_ENTRY_LEN as u64) as u32;

/// Hard cap on bins per table — a FROZEN decode cap. The digest array
/// of a maximal table is exactly [`SHARD_MAX_BYTES`], the same object
/// budget a shard gets; at [`crate::binfmt::BIN_TARGET_BYTES`] that is a 16 TiB
/// volume, the same ceiling the routing width implies (format doc).
pub const BIN_TABLE_MAX_BINS: u32 = 262_144;

const _: () = {
    // The registered cost model is 49 B/grain:
    // pin the entry width to that number.
    assert!(SHARD_ENTRY_LEN == 49);
    // A maximal shard fits its frozen object cap...
    assert!(
        BINMAP_FIXED_HEADER_LEN as u64 + SHARD_MAX_ENTRIES as u64 * SHARD_ENTRY_LEN as u64
            <= SHARD_MAX_BYTES
    );
    // ...and one more entry would not: the count cap is TIGHT against
    // the byte cap, so widening the entry without re-deriving the count
    // (or vice versa) fails to compile rather than shipping a shard a
    // conforming reader refuses.
    assert!(
        BINMAP_FIXED_HEADER_LEN as u64 + (SHARD_MAX_ENTRIES as u64 + 1) * SHARD_ENTRY_LEN as u64
            > SHARD_MAX_BYTES
    );
    // Policy sits strictly inside the frozen cap.
    assert!(SHARD_TARGET_BYTES < SHARD_MAX_BYTES);
    // The table's digest array is exactly the shard's object budget.
    assert!(BIN_TABLE_MAX_BINS as u64 * DIGEST_LEN as u64 == SHARD_MAX_BYTES);
    // The widest legal index object stays inside that budget too:
    // raising PREFIX_BITS_MAX without re-pricing the index trips here
    // (it holds 1<<bits shard ids plus the table id).
    assert!(
        BINMAP_INDEX_FIXED_HEADER_LEN as u64
            + ((1u64 << PREFIX_BITS_MAX) + 1) * GRAIN_ID_BINARY_LEN as u64
            <= SHARD_MAX_BYTES
    );
    // Routing must be expressible from the first two digest bytes.
    assert!(PREFIX_BITS_MAX as u32 <= 16);
};

/// One decoded shard entry: grain id → the bin holding it and the
/// extent inside that bin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardEntry {
    pub id: GrainId,
    /// Position in the bin table (0-based). Bounded only by the table —
    /// see [`validate_ordinals`].
    pub bin_ordinal: u32,
    /// Absolute offset of the grain FRAME HEADER inside that bin — the
    /// same extent convention the bin index uses (binfmt).
    pub offset: u64,
    /// Frame length: header + zstd payload.
    pub comp_len: u32,
}

/// A decoded binmap index: the routing width and the object ids the
/// rest of the map hangs off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinmapIndexDoc {
    pub prefix_bits: u8,
    pub bin_table: GrainId,
    /// Exactly `1 << prefix_bits` ids, in shard order — dense, empty
    /// shards included. One canonical layout; there is no sparse form.
    pub shards: Vec<GrainId>,
}

/// Encode error — the canonical encoder refuses what the decoder
/// rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeBinmapError {
    TooManyEntries {
        count: usize,
    },
    /// Entries are not strictly memcmp-ascending by grain id (a
    /// duplicate id is a non-strict step and lands here too).
    NotStrictlySorted,
    BadCompLen {
        index: usize,
        comp_len: u32,
    },
    BadOffset {
        index: usize,
        offset: u64,
    },
    /// The extent runs past a legal bin's maximum size, or its end
    /// overflows `u64`. Checkable shard-locally because
    /// `BIN_MAX_BYTES` is frozen.
    ExtentPastBinMax {
        index: usize,
        offset: u64,
        comp_len: u32,
    },
    /// The ordinal names a slot no legal bin table could hold.
    BadOrdinal {
        index: usize,
        bin_ordinal: u32,
    },
    /// A bin table holds at least one bin.
    EmptyTable,
    TooManyBins {
        count: usize,
    },
    /// The same bin digest appears twice — one bin, one ordinal.
    DuplicateBin {
        index: usize,
    },
    PrefixBitsTooWide {
        prefix_bits: u8,
    },
    ShardCountMismatch {
        got: usize,
        want: usize,
    },
}

impl std::fmt::Display for EncodeBinmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyEntries { count } => {
                write!(
                    f,
                    "{count} entries exceeds SHARD_MAX_ENTRIES {SHARD_MAX_ENTRIES}"
                )
            }
            Self::NotStrictlySorted => write!(f, "shard entries not strictly memcmp-ascending"),
            Self::BadCompLen { index, comp_len } => write!(
                f,
                "entry {index}: comp_len {comp_len} outside {}..={FRAME_COMP_MAX}",
                FRAME_HEADER_LEN + 1
            ),
            Self::BadOffset { index, offset } => write!(
                f,
                "entry {index}: offset {offset} inside the bin header (< {BIN_FIXED_HEADER_LEN})"
            ),
            Self::ExtentPastBinMax {
                index,
                offset,
                comp_len,
            } => write!(
                f,
                "entry {index}: extent {offset}+{comp_len} runs past BIN_MAX_BYTES {BIN_MAX_BYTES}"
            ),
            Self::BadOrdinal { index, bin_ordinal } => write!(
                f,
                "entry {index}: bin_ordinal {bin_ordinal} exceeds BIN_TABLE_MAX_BINS \
                 {BIN_TABLE_MAX_BINS}"
            ),
            Self::EmptyTable => write!(f, "a bin table holds at least one bin"),
            Self::TooManyBins { count } => {
                write!(
                    f,
                    "{count} bins exceeds BIN_TABLE_MAX_BINS {BIN_TABLE_MAX_BINS}"
                )
            }
            Self::DuplicateBin { index } => write!(f, "duplicate bin digest at ordinal {index}"),
            Self::PrefixBitsTooWide { prefix_bits } => {
                write!(
                    f,
                    "prefix_bits {prefix_bits} exceeds PREFIX_BITS_MAX {PREFIX_BITS_MAX}"
                )
            }
            Self::ShardCountMismatch { got, want } => {
                write!(f, "{got} shard ids for a {want}-shard index")
            }
        }
    }
}

impl std::error::Error for EncodeBinmapError {}

/// Route a grain to its shard: the first `prefix_bits` bits of the
/// DIGEST, most-significant first — routing over the 33-byte encoded
/// id would key every grain on the same algorithm tag byte.
/// `prefix_bits` 0 is the one-shard volume and routes everything to 0.
///
/// Total and panic-free: a digest is always [`DIGEST_LEN`] bytes, and a
/// width past [`PREFIX_BITS_MAX`] — which encode and decode both refuse
/// — is clamped rather than shifted out of range, so an unvalidated
/// caller gets a legal shard index instead of an overflow.
#[must_use]
pub fn shard_for(id: &GrainId, prefix_bits: u8) -> usize {
    let bits = if prefix_bits > PREFIX_BITS_MAX {
        PREFIX_BITS_MAX
    } else {
        prefix_bits
    };
    if bits == 0 {
        return 0;
    }
    // Irrefutable destructure of a fixed-width array: no indexing, no
    // bounds check to get wrong.
    let [hi, lo, ..] = *id.digest();
    usize::from(u16::from_be_bytes([hi, lo]) >> (16 - u32::from(bits)))
}

fn check_extent(index: usize, e: &ShardEntry) -> Result<(), EncodeBinmapError> {
    if e.comp_len as usize <= FRAME_HEADER_LEN || e.comp_len > FRAME_COMP_MAX {
        return Err(EncodeBinmapError::BadCompLen {
            index,
            comp_len: e.comp_len,
        });
    }
    if e.offset < BIN_FIXED_HEADER_LEN as u64 {
        return Err(EncodeBinmapError::BadOffset {
            index,
            offset: e.offset,
        });
    }
    // The encoder refuses what the decoder rejects. Both
    // bounds below were added to `decode_shard` before the freeze
    // as an accept-set decision; without the mirror here
    // the writer could mint a shard no reader would accept.
    if e.offset
        .checked_add(u64::from(e.comp_len))
        .is_none_or(|end| end > BIN_MAX_BYTES)
    {
        return Err(EncodeBinmapError::ExtentPastBinMax {
            index,
            offset: e.offset,
            comp_len: e.comp_len,
        });
    }
    if e.bin_ordinal >= BIN_TABLE_MAX_BINS {
        return Err(EncodeBinmapError::BadOrdinal {
            index,
            bin_ordinal: e.bin_ordinal,
        });
    }
    Ok(())
}

/// Encode one binmap shard. `entries` must be strictly memcmp-ascending
/// by grain id; an EMPTY shard is legal and canonical (a sparse prefix
/// still gets its object — the index is dense).
///
/// # Errors
/// The [`EncodeBinmapError`] naming the violated canonical-form rule.
pub fn encode_shard(entries: &[ShardEntry]) -> Result<Vec<u8>, EncodeBinmapError> {
    if entries.len() > SHARD_MAX_ENTRIES as usize {
        return Err(EncodeBinmapError::TooManyEntries {
            count: entries.len(),
        });
    }
    for (i, e) in entries.iter().enumerate() {
        check_extent(i, e)?;
    }
    if !check_strictly_sorted(entries, |e| &e.id) {
        return Err(EncodeBinmapError::NotStrictlySorted);
    }
    let mut out = encoding::envelope(ObjectType::BinmapShard);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "len <= SHARD_MAX_ENTRIES = 171_195 checked above"
    )]
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        out.extend_from_slice(&e.id.to_bytes());
        out.extend_from_slice(&e.bin_ordinal.to_be_bytes());
        out.extend_from_slice(&e.offset.to_be_bytes());
        out.extend_from_slice(&e.comp_len.to_be_bytes());
    }
    Ok(out)
}

/// Decode a binmap shard from the full object bytes.
///
/// # Errors
/// The [`DecodeError`] naming the violated rule; strict decode (type
/// tag, cap before allocation, exact length, valid extents, strict
/// order). `bin_ordinal` IS bounded here against the frozen
/// [`BIN_TABLE_MAX_BINS`] (the pre-freeze accept-set decision); what is
/// still not shard-local is the ordinal against the ACTUAL table
/// length — see [`validate_ordinals`]. This sentence claimed no
/// ordinal check at all, which the accept-set commit made untrue.
pub fn decode_shard(bytes: &[u8]) -> Result<Vec<ShardEntry>, DecodeError> {
    let (ty, mut c) = encoding::open_envelope(bytes)?;
    if ty != ObjectType::BinmapShard {
        return Err(DecodeError::Invalid {
            what: "object type (want binmap shard)",
        });
    }
    let count = c.u32()?;
    if count > SHARD_MAX_ENTRIES {
        return Err(DecodeError::CapExceeded {
            what: "binmap shard entry_count",
            got: u64::from(count),
            cap: u64::from(SHARD_MAX_ENTRIES),
        });
    }
    exact_len(bytes, BINMAP_FIXED_HEADER_LEN, count, SHARD_ENTRY_LEN)?;
    // The cap above bounds this at ≈8 MiB, and the exact-length check
    // above means the bytes to fill it are already present.
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let raw = c.take(GRAIN_ID_BINARY_LEN)?;
        let id = GrainId::from_bytes(raw).map_err(|_| DecodeError::Invalid { what: "grain id" })?;
        let bin_ordinal = c.u32()?;
        // BOUNDED AT DECODE against the frozen table ceiling (exit
        // battery, LOW — same accept-set decision as the extent above).
        // `validate_ordinals` still checks each ordinal against the
        // ACTUAL table length, which only a caller holding the table
        // can do; this independently refuses an ordinal no legal table
        // could ever contain.
        if bin_ordinal >= BIN_TABLE_MAX_BINS {
            return Err(DecodeError::CapExceeded {
                what: "shard bin_ordinal",
                got: u64::from(bin_ordinal),
                cap: u64::from(BIN_TABLE_MAX_BINS),
            });
        }
        let offset = c.u64()?;
        let comp_len = c.u32()?;
        if comp_len as usize <= FRAME_HEADER_LEN {
            return Err(DecodeError::Invalid {
                what: "shard comp_len under frame header",
            });
        }
        if comp_len > FRAME_COMP_MAX {
            return Err(DecodeError::CapExceeded {
                what: "shard comp_len",
                got: u64::from(comp_len),
                cap: u64::from(FRAME_COMP_MAX),
            });
        }
        if offset < BIN_FIXED_HEADER_LEN as u64 {
            return Err(DecodeError::Invalid {
                what: "shard offset inside bin header",
            });
        }
        // THE EXTENT MUST FIT A LEGAL BIN (an accept-set decision
        // taken before the freeze). `BIN_MAX_BYTES`
        // is FROZEN, so `offset + comp_len <= BIN_MAX_BYTES` is
        // checkable SHARD-LOCALLY with no cross-object information —
        // the module doc's old justification ("the bin it points into
        // carries that") was wrong, and without this an entry could
        // round-trip with `offset = 2^63` and a maximal `comp_len`.
        // `RootStoreError::RangeOverflow` exists in granary-store
        // precisely because this bound was missing here: the store had
        // to defend with checked arithmetic against extents this
        // decoder accepted. Tightening is FREE now and a reject-more
        // flag day after the freeze, so it lands now.
        //
        // Checked addition, not `offset + comp_len`: the sum overflows
        // u64 for offsets near the top of the range, and
        // `overflow-checks = true` makes that a panic on untrusted
        // input rather than a wrap.
        let end = offset
            .checked_add(u64::from(comp_len))
            .ok_or(DecodeError::Invalid {
                what: "shard extent end overflows u64",
            })?;
        if end > BIN_MAX_BYTES {
            return Err(DecodeError::CapExceeded {
                what: "shard extent end",
                got: end,
                cap: BIN_MAX_BYTES,
            });
        }
        entries.push(ShardEntry {
            id,
            bin_ordinal,
            offset,
            comp_len,
        });
    }
    if !check_strictly_sorted(&entries, |e| &e.id) {
        return Err(DecodeError::Invalid {
            what: "shard entry order (strict memcmp)",
        });
    }
    c.finish()?;
    Ok(entries)
}

/// Encode a bin table: the bin ids in ordinal order, each a RAW 32-byte
/// digest. Append-only across publishes within an epoch — this codec
/// sees one table and cannot check that; see the module docs.
///
/// # Errors
/// The [`EncodeBinmapError`] naming the violated rule (count bounds,
/// duplicate digest).
pub fn encode_bin_table(bins: &[[u8; DIGEST_LEN]]) -> Result<Vec<u8>, EncodeBinmapError> {
    if bins.is_empty() {
        return Err(EncodeBinmapError::EmptyTable);
    }
    if bins.len() > BIN_TABLE_MAX_BINS as usize {
        return Err(EncodeBinmapError::TooManyBins { count: bins.len() });
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, d) in bins.iter().enumerate() {
        if !seen.insert(d) {
            return Err(EncodeBinmapError::DuplicateBin { index: i });
        }
    }
    let mut out = encoding::envelope(ObjectType::BinTable);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "len <= BIN_TABLE_MAX_BINS = 262_144 checked above"
    )]
    out.extend_from_slice(&(bins.len() as u32).to_be_bytes());
    for d in bins {
        out.extend_from_slice(d);
    }
    Ok(out)
}

/// Decode a bin table from the full object bytes. The returned vector's
/// INDEX is the ordinal shard entries point at.
///
/// # Errors
/// The [`DecodeError`] naming the violated rule; strict decode (type
/// tag, cap before allocation, exact length, no duplicate digest).
pub fn decode_bin_table(bytes: &[u8]) -> Result<Vec<[u8; DIGEST_LEN]>, DecodeError> {
    let (ty, mut c) = encoding::open_envelope(bytes)?;
    if ty != ObjectType::BinTable {
        return Err(DecodeError::Invalid {
            what: "object type (want bin table)",
        });
    }
    let count = c.u32()?;
    if count == 0 {
        return Err(DecodeError::Invalid {
            what: "bin table bin_count zero",
        });
    }
    if count > BIN_TABLE_MAX_BINS {
        return Err(DecodeError::CapExceeded {
            what: "bin table bin_count",
            got: u64::from(count),
            cap: u64::from(BIN_TABLE_MAX_BINS),
        });
    }
    exact_len(bytes, BINMAP_FIXED_HEADER_LEN, count, DIGEST_LEN)?;
    let mut bins = Vec::with_capacity(count as usize);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..count {
        let digest: [u8; DIGEST_LEN] = c
            .take(DIGEST_LEN)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        if !seen.insert(digest) {
            return Err(DecodeError::Invalid {
                what: "duplicate bin digest in table",
            });
        }
        bins.push(digest);
    }
    c.finish()?;
    Ok(bins)
}

/// Encode a binmap index. `shards` is dense: exactly `1 << prefix_bits`
/// ids in shard order, empty shards included.
///
/// # Errors
/// [`EncodeBinmapError::PrefixBitsTooWide`] past [`PREFIX_BITS_MAX`];
/// [`EncodeBinmapError::ShardCountMismatch`] if the array is not the
/// dense length the width implies.
pub fn encode_binmap_index(
    prefix_bits: u8,
    bin_table: GrainId,
    shards: &[GrainId],
) -> Result<Vec<u8>, EncodeBinmapError> {
    if prefix_bits > PREFIX_BITS_MAX {
        return Err(EncodeBinmapError::PrefixBitsTooWide { prefix_bits });
    }
    let want = 1usize << prefix_bits;
    if shards.len() != want {
        return Err(EncodeBinmapError::ShardCountMismatch {
            got: shards.len(),
            want,
        });
    }
    let mut out = encoding::envelope(ObjectType::BinmapIndex);
    out.push(prefix_bits);
    out.extend_from_slice(&bin_table.to_bytes());
    for s in shards {
        out.extend_from_slice(&s.to_bytes());
    }
    Ok(out)
}

/// Decode a binmap index from the full object bytes.
///
/// # Errors
/// The [`DecodeError`] naming the violated rule. A `prefix_bits` past
/// [`PREFIX_BITS_MAX`] is refused by name (`CapExceeded` on
/// `"binmap prefix_bits"`), never clamped: routing width is not
/// something a reader may guess at.
pub fn decode_binmap_index(bytes: &[u8]) -> Result<BinmapIndexDoc, DecodeError> {
    let (ty, mut c) = encoding::open_envelope(bytes)?;
    if ty != ObjectType::BinmapIndex {
        return Err(DecodeError::Invalid {
            what: "object type (want binmap index)",
        });
    }
    let prefix_bits = c.u8()?;
    if prefix_bits > PREFIX_BITS_MAX {
        return Err(DecodeError::CapExceeded {
            what: "binmap prefix_bits",
            got: u64::from(prefix_bits),
            cap: u64::from(PREFIX_BITS_MAX),
        });
    }
    let bin_table = get_grain_id(&mut c)?;
    // The shard count is DERIVED from prefix_bits and is deliberately
    // not stored a second time (redundant length sources are
    // forbidden), so a short array truncates and a long one trails. That
    // width cap alone still bounds the allocation below at 4096 × 33 B
    // ≈ 135 KiB, but a length pre-check — the same one both sibling
    // decoders (`decode_shard`, `decode_bin_table`) already run before
    // their own count-sized allocation — catches a short object before
    // even that much is reserved: a 44-byte object declaring
    // `prefix_bits = 12` would otherwise buy the full 135 KiB before
    // the first shard id is read.
    let count = 1usize << prefix_bits;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "count = 1 << prefix_bits <= 1 << PREFIX_BITS_MAX = 4096, checked above"
    )]
    exact_len(
        bytes,
        BINMAP_INDEX_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN,
        count as u32,
        GRAIN_ID_BINARY_LEN,
    )?;
    let mut shards = Vec::with_capacity(count);
    for _ in 0..count {
        shards.push(get_grain_id(&mut c)?);
    }
    c.finish()?;
    Ok(BinmapIndexDoc {
        prefix_bits,
        bin_table,
        shards,
    })
}

/// The cross-object check a shard cannot do alone: every `bin_ordinal`
/// must address a real row of the bin table decoded alongside it.
///
/// # Errors
/// [`DecodeError::Invalid`] naming the first out-of-range ordinal's
/// rule. `bin_count` 0 bounds nothing, so any entry fails against it.
pub fn validate_ordinals(entries: &[ShardEntry], bin_count: u32) -> Result<(), DecodeError> {
    if entries.iter().any(|e| e.bin_ordinal >= bin_count) {
        return Err(DecodeError::Invalid {
            what: "shard bin_ordinal past bin table",
        });
    }
    Ok(())
}

/// The OTHER cross-object bound a shard cannot check alone: every
/// entry must ROUTE to the shard that holds it. A locally valid,
/// correctly hashed and signed but misrouted binmap would otherwise be
/// accepted as remote state while ordinary routed readers cannot
/// resolve its entries — the check once existed only in test helpers;
/// production readers run this.
///
/// Total and honest — three refusals, not one: `prefix_bits` past
/// [`PREFIX_BITS_MAX`] is refused BY NAME, the identical variant and
/// `what` string [`decode_binmap_index`] uses for the same rule (two
/// spellings of one rule is its own defect); `shard_index` outside
/// `0..1 << prefix_bits` is refused BY NAME; only then is routing
/// itself checked. An EMPTY shard is valid at any IN-RANGE
/// `shard_index` — vacuously, since there is nothing in it to
/// misroute — and that is a decided case, not an oversight: an empty
/// shard object is legal and canonical (see [`encode_shard`]).
///
/// # Errors
/// [`DecodeError::CapExceeded`] on `"binmap prefix_bits"` past
/// [`PREFIX_BITS_MAX`]; [`DecodeError::Invalid`] naming an
/// out-of-range `shard_index`, or naming the routing violation.
pub fn validate_routing(
    entries: &[ShardEntry],
    prefix_bits: u8,
    shard_index: usize,
) -> Result<(), DecodeError> {
    if prefix_bits > PREFIX_BITS_MAX {
        return Err(DecodeError::CapExceeded {
            what: "binmap prefix_bits",
            got: u64::from(prefix_bits),
            cap: u64::from(PREFIX_BITS_MAX),
        });
    }
    if shard_index >= 1usize << prefix_bits {
        return Err(DecodeError::Invalid {
            what: "shard_index past routing width",
        });
    }
    if entries
        .iter()
        .any(|e| shard_for(&e.id, prefix_bits) != shard_index)
    {
        return Err(DecodeError::Invalid {
            what: "shard entry routed to the wrong shard",
        });
    }
    Ok(())
}

/// Look one grain up in a decoded shard. Binary search — entries are
/// strictly sorted by id, which the decoder has already enforced.
#[must_use]
pub fn find_entry<'a>(entries: &'a [ShardEntry], id: &GrainId) -> Option<&'a ShardEntry> {
    let at = entries.binary_search_by(|e| e.id.cmp(id)).ok()?;
    entries.get(at)
}

fn get_grain_id(c: &mut Cursor<'_>) -> Result<GrainId, DecodeError> {
    let raw = c.take(GRAIN_ID_BINARY_LEN)?;
    GrainId::from_bytes(raw).map_err(|_| DecodeError::Invalid { what: "grain id" })
}

/// Fixed-stride bodies have an EXACT length implied by their count.
/// Checking it before the count-sized allocation is what stops a 14-byte
/// object from buying an 8 MiB `Vec`; the errors are exactly the ones
/// the cursor would raise later (which `finish` still re-proves).
fn exact_len(
    bytes: &[u8],
    header_len: usize,
    count: u32,
    stride: usize,
) -> Result<(), DecodeError> {
    let want = header_len as u64 + u64::from(count) * stride as u64;
    let got = bytes.len() as u64;
    if got < want {
        return Err(DecodeError::Truncated);
    }
    if got > want {
        return Err(DecodeError::TrailingBytes {
            remaining: usize::try_from(got - want).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
