// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bin format v1.
//!
//! A bin is the grain container uploaded to the object store: an
//! index-first layout so ingest verification walks one contiguous
//! header, followed by the grain frames in the packer's locality order.
//! Core owns the BYTES ONLY — frames arrive here already compressed
//! (opaque payloads); zstd itself lives in granary-store's `codec`
//! (zstd-sys carries a build script and cannot enter core).
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! envelope (10)      GRANARY\0, type 0x05, version 1
//! grain_count u32    1 ..= MAX_GRAINS_PER_BIN
//! index              grain_count × { grain_id 33, offset u64, comp_len u32 }
//! frames             concatenated, contiguous, in index order
//! ```
//!
//! Extent convention (frozen): an index entry's
//! `offset` points at the first byte of the granary FRAME HEADER and
//! `comp_len` covers header + zstd payload — a range GET of one entry
//! yields a complete decodable frame. Offsets are ABSOLUTE within the
//! bin and strictly contiguous: `entries[0].offset` is the first byte
//! after the index, each next offset is `offset + comp_len` of its
//! predecessor, and the final frame ends exactly at the bin's last
//! byte. Contiguity IS the canonical form — no gaps, no overlaps, no
//! second encoding of the same frame set.
//!
//! The frame header is 9 bytes: `framing u8` (0 = one whole-grain zstd
//! frame — the ONLY v1 value, refused nonzero BY NAME), `dict_id u32`
//! (0 in v1, refused nonzero by name; the dictionary lever),
//! `unpacked_len u32` (1 ..= [`GRAIN_UNPACKED_MAX`]). `comp_len` lives
//! in the index ONLY — a frame carries no second copy (redundant
//! length sources are forbidden), no grain id (the index maps ids to
//! extents) and no magic (the bin envelope versions its frames).
//!
//! A bin with a corrupt index is recoverable by sequential frame walk
//! (fixed-width headers + self-delimiting zstd frames): the index is
//! the FAST PATH, not the only path. Bins are content-addressed
//! (`GrainId::of(bin_bytes)`); integrity of any decompressed grain is
//! blake3 verification against its grain id — never the zstd return
//! status (zstd passes ~99% of corruptions silently).

use crate::encoding::{self, Cursor, DecodeError, ObjectType};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use crate::manifest::GRAIN_UNPACKED_MAX;

/// Grain frame header length: `framing u8` + `dict_id u32` + `unpacked_len u32`.
pub const FRAME_HEADER_LEN: usize = 9;

/// The only framing v1 writes or accepts: one whole-grain zstd frame.
pub const FRAMING_ZSTD_WHOLE_GRAIN: u8 = 0;

/// The only `dict_id` v1 writes or accepts: no dictionary.
pub const DICT_ID_NONE: u32 = 0;

/// Upper bound on a frame's zstd payload: `ZSTD_COMPRESSBOUND` of the
/// grain cap. Incompressible input EXPANDS under zstd (measured: an
/// 8 MiB random grain gains 202 bytes; the bound formula adds
/// `src >> 8` = 32 KiB at 8 MiB), so the compressed-side
/// cap must exceed the unpacked cap. The formula is written out from
/// `GRAIN_UNPACKED_MAX` so the two caps cannot drift independently —
/// deriving the bound avoids needing a separate consistency assertion.
/// (The `(128 KiB - src) >> 11` small-input term is zero at 8 MiB.)
pub const ZSTD_PAYLOAD_MAX: u32 = GRAIN_UNPACKED_MAX + (GRAIN_UNPACKED_MAX >> 8);

/// Upper bound on an index entry's `comp_len` (header + payload).
#[expect(
    clippy::cast_possible_truncation,
    reason = "FRAME_HEADER_LEN = 9 fits any integer type"
)]
pub const FRAME_COMP_MAX: u32 = FRAME_HEADER_LEN as u32 + ZSTD_PAYLOAD_MAX;

/// Hard cap on total bin size — a FROZEN decode cap (caps must be
/// validated before allocation), not a packing target.
/// TWO FORMATS DEPEND ON THIS VALUE. Besides bounding a bin's own
/// total length, it is a BINMAP SHARD accept-set bound — `decode_shard`
/// refuses `offset + comp_len > BIN_MAX_BYTES`, which is checkable
/// shard-locally precisely because this
/// constant is frozen. Raising it is therefore a flag day for BOTH
/// readers, not just bin readers: every already-published shard would
/// keep its narrower accept set while new writers could emit extents
/// old readers refuse. The static asserts below and
/// `caps_are_the_frozen_relations` force a STOP on any edit here; this
/// note is what tells the editor what the stop is about.
pub const BIN_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on grains per bin — a FROZEN decode cap. Bounds the index
/// allocation before a single frame byte is trusted: `65_536` entries
/// at the 45-byte WIRE stride is ≈2.9 MiB of input, but the `Vec` the
/// decoder pre-allocates holds `BinIndexEntry` STRUCTS at 48 B each
/// (padding to the `u64` alignment), so the resident cost is ≈3.1 MiB
/// — plus the dedup `BTreeSet` the decoder builds alongside it. Both
/// are bounded; the point of stating both numbers is that this comment
/// documents the resident allocation bound, and quoting only the wire stride
/// understates what the cap actually admits. Bins
/// full of tiny metadata frames close on this cap long before
/// [`BIN_MAX_BYTES`].
pub const MAX_GRAINS_PER_BIN: u32 = 65_536;

/// Packing TARGET — policy, not format: the packer closes a bin once it
/// would exceed this. Chosen against S3 request cost and the fsync
/// amortisation motive: harvest measured ~4.8 ms of fsync per object,
/// the dominant share of its wall clock, so bins pay that per bin,
/// not per grain. A policy change re-packs; it does not touch the reader.
pub const BIN_TARGET_BYTES: u64 = 64 * 1024 * 1024;

/// A PACKER TARGET — client packing policy, never a server cap. 4× under the
/// server's ingest limit for the same reason `BIN_TARGET_BYTES` sits 4× under
/// `BIN_MAX_BYTES`: the trigger and the cap move independently.
pub const BIN_UNPACKED_TARGET_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

const _: () = {
    // A one-grain bin is emitted even when it alone exceeds the target
    // (the `count > 0` guard), so the target must admit a maximal grain.
    assert!(BIN_UNPACKED_TARGET_BYTES >= GRAIN_UNPACKED_MAX as u64);
};

/// One index entry: grain id → absolute extent inside this bin.
pub const BIN_INDEX_ENTRY_LEN: usize = GRAIN_ID_BINARY_LEN + 8 + 4;

/// Envelope + `grain_count` — the fixed prefix before the index.
pub const BIN_FIXED_HEADER_LEN: usize = 10 + 4;

const _: () = {
    // MAX_GRAIN (what the chunker cuts) must be frame-encodable: the
    // frame's unpacked_len cap is GRAIN_UNPACKED_MAX (thresh.rs asserts
    // MAX_GRAIN <= GRAIN_UNPACKED_MAX). The index math below must never
    // overflow u32 arithmetic on a decoded comp_len.
    // A one-grain bin — fixed header + ONE index entry + one maximal
    // frame — must fit the frozen cap. The index entry was missing
    // from this relation, so the assert did not prove the single-frame
    // statement its comment describes.
    assert!(
        BIN_FIXED_HEADER_LEN as u64 + BIN_INDEX_ENTRY_LEN as u64 + FRAME_COMP_MAX as u64
            <= BIN_MAX_BYTES
    );
    // The full index of a max-count bin must itself fit a bin.
    assert!(
        BIN_FIXED_HEADER_LEN as u64 + MAX_GRAINS_PER_BIN as u64 * BIN_INDEX_ENTRY_LEN as u64
            <= BIN_MAX_BYTES
    );
    // The packing target is inside the frozen cap with headroom for a
    // max-count bin's OWN index plus one maximal closing frame (the
    // packer closes AFTER the frame that crosses the target, so
    // fixed header + max index + target + one max frame — the planner's
    // full reachable worst case, not just the frame — must stay legal:
    // 14 + 65_536×45 + 64 MiB + 8_421_385 ≈ 78.48 MB, well inside the
    // 256 MiB cap).
    assert!(
        BIN_FIXED_HEADER_LEN as u64
            + MAX_GRAINS_PER_BIN as u64 * BIN_INDEX_ENTRY_LEN as u64
            + BIN_TARGET_BYTES
            + FRAME_COMP_MAX as u64
            <= BIN_MAX_BYTES
    );
};

/// Decoded grain-frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Declared UNCOMPRESSED length. The decompress allocation bound
    /// and the only length granary trusts — the inner zstd content
    /// size is never read; the manifest's `GrainRef`
    /// carries the same value in a different hash domain, and a
    /// mismatch ANYWHERE rejects the grain (no source ever wins).
    pub unpacked_len: u32,
}

/// One decoded bin-index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinIndexEntry {
    pub id: GrainId,
    /// Absolute offset of the frame header inside the bin.
    pub offset: u64,
    /// Frame length: header + zstd payload.
    pub comp_len: u32,
}

/// A frame ready for packing: the grain id and the COMPLETE frame
/// bytes (header + zstd payload), as produced by granary-store's codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedFrame {
    pub id: GrainId,
    pub frame: Vec<u8>,
}

/// What [`plan_bins`] needs to know about one frame: BOTH lengths, in
/// one value.
///
/// **One slice of a struct rather than two parallel slices, and that is
/// the whole reason this type exists.** The planner closes a bin on the
/// compressed total and on the DECLARED decompressed total, and two
/// arrays indexed in lockstep are one insertion away from pairing frame
/// `i`'s compressed length with frame `j`'s decompressed one — a
/// desynchronisation nothing in the signature could refuse. Bundled,
/// the pairing is the caller's single push and the planner cannot see
/// a mismatched pair at all.
///
/// `unpacked_len` is the value the frame's own 9-byte header declares
/// (`FrameHeader::unpacked_len`), which is the same number a reader
/// decompresses against. The planner does not re-derive it and does not
/// validate it: it is packing POLICY input, and a caller that declares
/// something other than what it framed has already broken
/// [`encode_bin`]'s own `check_frame`, which reads the header bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePlan {
    /// Complete frame length: header + zstd payload.
    pub comp_len: u32,
    /// The frame header's declared UNCOMPRESSED length.
    pub unpacked_len: u32,
}

/// Encode error — the canonical encoder refuses what the decoder
/// rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeBinError {
    Empty,
    TooManyGrains {
        count: usize,
    },
    /// Frame fails header validation or its length bounds.
    BadFrame {
        index: usize,
        why: DecodeError,
    },
    /// The same grain id appears twice — a packer never emits it.
    DuplicateGrain {
        id: GrainId,
    },
    /// Total would exceed the frozen [`BIN_MAX_BYTES`] cap.
    TooLarge {
        total: u64,
    },
}

impl std::fmt::Display for EncodeBinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "a bin holds at least one grain"),
            Self::TooManyGrains { count } => {
                write!(
                    f,
                    "{count} grains exceeds MAX_GRAINS_PER_BIN {MAX_GRAINS_PER_BIN}"
                )
            }
            Self::BadFrame { index, why } => write!(f, "frame {index}: {why}"),
            Self::DuplicateGrain { id } => write!(f, "duplicate grain {id} in one bin"),
            Self::TooLarge { total } => {
                write!(f, "bin total {total} exceeds BIN_MAX_BYTES {BIN_MAX_BYTES}")
            }
        }
    }
}

impl std::error::Error for EncodeBinError {}

/// Encode a v1 grain-frame HEADER for a payload of `unpacked_len`
/// uncompressed bytes. Always framing 0 / `dict_id` 0 — v1 has no other
/// legal values, so the encoder does not offer them.
///
/// # Errors
/// [`DecodeError::Invalid`] for `unpacked_len` zero;
/// [`DecodeError::CapExceeded`] for `unpacked_len` over the grain cap
/// (encoder refuses what the decoder rejects).
pub fn encode_frame_header(unpacked_len: u32) -> Result<[u8; FRAME_HEADER_LEN], DecodeError> {
    if unpacked_len == 0 {
        return Err(DecodeError::Invalid {
            what: "frame unpacked_len zero",
        });
    }
    if unpacked_len > GRAIN_UNPACKED_MAX {
        return Err(DecodeError::CapExceeded {
            what: "frame unpacked_len",
            got: u64::from(unpacked_len),
            cap: u64::from(GRAIN_UNPACKED_MAX),
        });
    }
    let mut out = [0u8; FRAME_HEADER_LEN];
    out[0] = FRAMING_ZSTD_WHOLE_GRAIN;
    // bytes 1..5 stay DICT_ID_NONE = 0
    out[5..9].copy_from_slice(&unpacked_len.to_be_bytes());
    Ok(out)
}

/// Decode and validate a v1 frame header from the start of `frame`.
/// Refuses reserved-nonzero `framing` and `dict_id` BY NAME
/// — never skip, never guess.
///
/// # Errors
/// [`DecodeError::Truncated`], [`DecodeError::UnsupportedFraming`],
/// [`DecodeError::UnsupportedDictId`], [`DecodeError::Invalid`] on a
/// zero declared length, or [`DecodeError::CapExceeded`] over cap.
pub fn decode_frame_header(frame: &[u8]) -> Result<FrameHeader, DecodeError> {
    let mut c = Cursor::new(frame);
    let framing = c.u8()?;
    if framing != FRAMING_ZSTD_WHOLE_GRAIN {
        return Err(DecodeError::UnsupportedFraming { framing });
    }
    let dict_id = c.u32()?;
    if dict_id != DICT_ID_NONE {
        return Err(DecodeError::UnsupportedDictId { dict_id });
    }
    let unpacked_len = c.u32()?;
    if unpacked_len == 0 {
        return Err(DecodeError::Invalid {
            what: "frame unpacked_len zero",
        });
    }
    if unpacked_len > GRAIN_UNPACKED_MAX {
        return Err(DecodeError::CapExceeded {
            what: "frame unpacked_len",
            got: u64::from(unpacked_len),
            cap: u64::from(GRAIN_UNPACKED_MAX),
        });
    }
    // Deliberately NO finish(): a frame header is a prefix of a frame,
    // not a whole object; the payload follows.
    Ok(FrameHeader { unpacked_len })
}

fn check_frame(index: usize, frame: &[u8]) -> Result<(), EncodeBinError> {
    let bad = |why| EncodeBinError::BadFrame { index, why };
    if frame.len() <= FRAME_HEADER_LEN {
        return Err(bad(DecodeError::Truncated));
    }
    if frame.len() > FRAME_COMP_MAX as usize {
        return Err(bad(DecodeError::CapExceeded {
            what: "frame comp_len",
            got: frame.len() as u64,
            cap: u64::from(FRAME_COMP_MAX),
        }));
    }
    decode_frame_header(frame).map(|_| ()).map_err(bad)
}

/// Encode a bin from complete frames in the caller's (locality) order.
///
/// # Errors
/// [`EncodeBinError`] naming the violated canonical-form rule.
pub fn encode_bin(frames: &[PackedFrame]) -> Result<Vec<u8>, EncodeBinError> {
    if frames.is_empty() {
        return Err(EncodeBinError::Empty);
    }
    if frames.len() > MAX_GRAINS_PER_BIN as usize {
        return Err(EncodeBinError::TooManyGrains {
            count: frames.len(),
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut total = BIN_FIXED_HEADER_LEN as u64 + frames.len() as u64 * BIN_INDEX_ENTRY_LEN as u64;
    for (i, f) in frames.iter().enumerate() {
        check_frame(i, &f.frame)?;
        if !seen.insert(f.id) {
            return Err(EncodeBinError::DuplicateGrain { id: f.id });
        }
        total += f.frame.len() as u64;
    }
    if total > BIN_MAX_BYTES {
        return Err(EncodeBinError::TooLarge { total });
    }
    let mut out = encoding::envelope(ObjectType::Bin);
    let capacity = usize::try_from(total).map_err(|_| EncodeBinError::TooLarge { total })?;
    out.reserve_exact(capacity.saturating_sub(out.len()));
    #[expect(
        clippy::cast_possible_truncation,
        reason = "count <= MAX_GRAINS_PER_BIN = 65_536 checked above"
    )]
    out.extend_from_slice(&(frames.len() as u32).to_be_bytes());
    let mut offset = (BIN_FIXED_HEADER_LEN + frames.len() * BIN_INDEX_ENTRY_LEN) as u64;
    for f in frames {
        out.extend_from_slice(&f.id.to_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        #[expect(
            clippy::cast_possible_truncation,
            reason = "frame.len() <= FRAME_COMP_MAX (u32) checked in check_frame"
        )]
        out.extend_from_slice(&(f.frame.len() as u32).to_be_bytes());
        offset += f.frame.len() as u64;
    }
    for f in frames {
        out.extend_from_slice(&f.frame);
    }
    Ok(out)
}

/// Decode a bin's index, validating every canonical-form rule and every
/// frame HEADER (cheap — no decompression, no hashing). `bytes` is the
/// full bin object.
///
/// # Errors
/// The [`DecodeError`] naming the violated rule; strict decode (caps
/// before allocation, contiguous extents, exact total length, unique
/// ids, valid frame headers).
pub fn decode_bin(bytes: &[u8]) -> Result<Vec<BinIndexEntry>, DecodeError> {
    if bytes.len() as u64 > BIN_MAX_BYTES {
        return Err(DecodeError::CapExceeded {
            what: "bin total_len",
            got: bytes.len() as u64,
            cap: BIN_MAX_BYTES,
        });
    }
    let (entries, expected_offset) = read_bin_index(bytes, false)?;
    // The frames region must end exactly at the bin's last byte: SHORTER
    // is a truncated bin (bytes missing), LONGER is trailing bytes after
    // the last frame (bytes extra) — distinct rejects, so the two
    // directions get two names rather than one
    // `abs_diff` that would report a short bin as "N trailing bytes" when
    // N bytes are in fact MISSING. Every frame HEADER must also validate
    // (framing/dict_id/len caps).
    let actual_len = bytes.len() as u64;
    if actual_len < expected_offset {
        return Err(DecodeError::Truncated);
    }
    if actual_len > expected_offset {
        return Err(DecodeError::TrailingBytes {
            remaining: usize::try_from(actual_len - expected_offset).unwrap_or(usize::MAX),
        });
    }
    for e in &entries {
        let frame = frame_bytes(bytes, e)?;
        decode_frame_header(frame)?;
    }
    // c intentionally not finish()ed against the index cursor: the
    // frames region was length-checked absolutely above; the index
    // cursor stopped at the frames boundary by construction.
    Ok(entries)
}

/// Decode the header and index prefix of a bin. Callers must authenticate the
/// prefix against evidence from a full [`decode_bin`] before trusting it.
///
/// # Errors
/// A malformed index, truncated prefix, or trailing bytes after the index.
pub fn decode_bin_index(bytes: &[u8]) -> Result<Vec<BinIndexEntry>, DecodeError> {
    read_bin_index(bytes, true).map(|(entries, _)| entries)
}

fn read_bin_index(
    bytes: &[u8],
    index_only: bool,
) -> Result<(Vec<BinIndexEntry>, u64), DecodeError> {
    let (ty, mut c) = encoding::open_envelope(bytes)?;
    if ty != ObjectType::Bin {
        return Err(DecodeError::Invalid {
            what: "object type (want bin)",
        });
    }
    let count = c.u32()?;
    if count == 0 {
        return Err(DecodeError::Invalid {
            what: "bin grain_count zero",
        });
    }
    if count > MAX_GRAINS_PER_BIN {
        return Err(DecodeError::CapExceeded {
            what: "bin grain_count",
            got: u64::from(count),
            cap: u64::from(MAX_GRAINS_PER_BIN),
        });
    }
    // Index size is bounded by the count cap (≈2.9 MiB) BEFORE this
    // allocation. The strictly stronger check is free: refuse
    // up front when the buffer could not possibly hold `count` index
    // entries, rather than allocating first and finding out from the
    // strict cursor moments later. This refusal is byte-identical to what
    // that cursor would raise — defense-in-depth, deliberately
    // unobservable by a portable test (the same residual class as
    // the binmap shard decoder's pre-allocation
    // guard).
    if bytes.len() < BIN_FIXED_HEADER_LEN + count as usize * BIN_INDEX_ENTRY_LEN {
        return Err(DecodeError::Truncated);
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut seen = std::collections::BTreeSet::new();
    let mut expected_offset = (BIN_FIXED_HEADER_LEN + count as usize * BIN_INDEX_ENTRY_LEN) as u64;
    for _ in 0..count {
        let raw = c.take(GRAIN_ID_BINARY_LEN)?;
        let id = GrainId::from_bytes(raw).map_err(|_| DecodeError::Invalid { what: "grain id" })?;
        let offset = c.u64()?;
        let comp_len = c.u32()?;
        if offset != expected_offset {
            return Err(DecodeError::Invalid {
                what: "bin extent contiguity",
            });
        }
        if comp_len as usize <= FRAME_HEADER_LEN {
            return Err(DecodeError::Invalid {
                what: "frame comp_len under header",
            });
        }
        if comp_len > FRAME_COMP_MAX {
            return Err(DecodeError::CapExceeded {
                what: "frame comp_len",
                got: u64::from(comp_len),
                cap: u64::from(FRAME_COMP_MAX),
            });
        }
        if !seen.insert(id) {
            return Err(DecodeError::Invalid {
                what: "duplicate grain id in bin",
            });
        }
        expected_offset += u64::from(comp_len);
        entries.push(BinIndexEntry {
            id,
            offset,
            comp_len,
        });
    }
    if index_only {
        c.finish()?;
    }
    Ok((entries, expected_offset))
}

/// Slice one frame (header + payload) out of a bin by its index entry.
///
/// # Errors
/// [`DecodeError::Truncated`] if the extent escapes the buffer — only
/// possible when `entry` did not come from [`decode_bin`] of these
/// same bytes.
pub fn frame_bytes<'a>(bin: &'a [u8], entry: &BinIndexEntry) -> Result<&'a [u8], DecodeError> {
    let start = usize::try_from(entry.offset).map_err(|_| DecodeError::Truncated)?;
    let end = start
        .checked_add(entry.comp_len as usize)
        .ok_or(DecodeError::Truncated)?;
    bin.get(start..end).ok_or(DecodeError::Truncated)
}

/// Pure packing planner: packing is a pure function of the publish
/// set. Splits `frames` — the frames' two lengths in the caller's
/// locality order — into consecutive bins, closing a bin once it holds
/// [`MAX_GRAINS_PER_BIN`] frames, once its byte total has reached
/// [`BIN_TARGET_BYTES`], or once its frames' DECLARED decompressed total
/// would pass [`BIN_UNPACKED_TARGET_BYTES`]. Order is never reordered
/// here: locality policy (v0: manifest traversal order) is the CALLER's,
/// split points are ours.
///
/// **The third condition is LOOK-AHEAD, and the first two are not.** The
/// two byte/count conditions close AFTER the frame that crossed them, a
/// soft target that overshoots by at most one frame and has always been
/// this planner's shape. The decompressed condition closes BEFORE
/// adding, so a planned bin's declared total never exceeds the target at
/// all. The difference is that this target's whole job is to keep a
/// conforming publish under a *server's* ingest ceiling: an overshoot
/// here is a bin some verifying server refuses `413`, which the soft
/// form cannot rule out — one maximal grain past a target set at the
/// ceiling is a refused bin, and setting the target under the ceiling to
/// absorb the overshoot would make the relation between them arithmetic
/// nobody could read off either constant.
///
/// A frame whose declared length alone exceeds the target is still
/// emitted, in a bin of its own: the `count > 0` guard means the first
/// frame of a bin is never the one that closes it, so no input plans an
/// empty range. The `const _` block beside
/// [`BIN_UNPACKED_TARGET_BYTES`] is what keeps that case unreachable
/// rather than merely handled — the target admits a maximal grain.
///
/// # Errors
/// [`EncodeBinError::BadFrame`] if any length is structurally illegal
/// (≤ header, > [`FRAME_COMP_MAX`]) — the planner refuses what the encoder
/// would refuse, before any bytes move.
pub fn plan_bins(frames: &[FramePlan]) -> Result<Vec<std::ops::Range<usize>>, EncodeBinError> {
    let mut plans = Vec::new();
    let mut start = 0usize;
    let mut bytes: u64 = 0;
    let mut unpacked: u64 = 0;
    for (i, frame) in frames.iter().enumerate() {
        let len = frame.comp_len;
        // Mirrors `check_frame` exactly: a length that could not possibly
        // hold a frame header is Truncated, not a fabricated CapExceeded
        // (the planner refuses what the encoder would refuse — same name,
        // not just the same verdict).
        if len as usize <= FRAME_HEADER_LEN {
            return Err(EncodeBinError::BadFrame {
                index: i,
                why: DecodeError::Truncated,
            });
        }
        if len > FRAME_COMP_MAX {
            return Err(EncodeBinError::BadFrame {
                index: i,
                why: DecodeError::CapExceeded {
                    what: "frame comp_len",
                    got: u64::from(len),
                    cap: u64::from(FRAME_COMP_MAX),
                },
            });
        }
        // On `count > 0`, which reads as a DEAD guard — and is only
        // PARTLY so, which is why the reasoning is recorded here
        // rather than acted on. `count` IS zero on a
        // real path: at `i == start`, the first frame of every bin
        // (asserting otherwise fails
        // `planner_splits_on_target_and_count` immediately). What is
        // true is weaker: at `i == start`, `bytes` was just reset to 0
        // and `count` is 0, so both split conditions are already false
        // and the guard never changes the OUTCOME — given
        // `MAX_GRAINS_PER_BIN >= 1` and `BIN_TARGET_BYTES >= 1`, which
        // the static asserts above pin. It stays: it is the only
        // in-code statement that an empty plan range must never be
        // pushed, and `plan_bins` promises non-empty plans to a caller
        // that indexes with them.
        let count = i - start;
        // The look-ahead term: what this bin WOULD declare with this
        // frame in it. `saturating_add` and not a bare `+` — the sum is
        // bounded by the target plus one maximal grain on every path
        // that reaches here, so the saturation is unreachable, and the
        // direction it fails in is the safe one: a saturated total is
        // over the target and closes the bin.
        let would_declare = unpacked.saturating_add(u64::from(frame.unpacked_len));
        if count > 0
            && (count >= MAX_GRAINS_PER_BIN as usize
                || bytes >= BIN_TARGET_BYTES
                || would_declare > BIN_UNPACKED_TARGET_BYTES)
        {
            plans.push(start..i);
            start = i;
            bytes = 0;
            unpacked = 0;
        }
        bytes += u64::from(len);
        unpacked = unpacked.saturating_add(u64::from(frame.unpacked_len));
    }
    if start < frames.len() {
        plans.push(start..frames.len());
    }
    Ok(plans)
}

#[cfg(test)]
mod tests;
