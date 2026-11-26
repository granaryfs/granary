// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Sheaf format v1.
//!
//! A sheaf is the commit record: a content-addressed, hash-chained
//! object naming its parent sheaf, the manifest root the commit
//! resulted in, when the commit happened, and what it did. The chain is
//! what spec §11's tally needs from v1 — an append-only history that a
//! later transparency log can prove consistency over — so the chain
//! ships now even though nothing reads it yet.
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! envelope (10)      GRANARY\0, type 0x0A, version 1
//! parent             presence u8: 0x00 = none | 0x01 + grain_id 33
//! manifest_root      grain_id 33
//! timestamp          secs i64 + nanos u32   (Unix epoch, UTC; nanos < 1e9; leap seconds ignored)
//! op_count           u32  1 ..= SHEAF_MAX_OPS
//! ops                op_count × { tag u8 }  (registry below)
//! ```
//!
//! **No all-zeros sentinel**: the first commit writes
//! presence `0x00` and NOTHING follows it — the next field starts at the
//! very next byte. A sentinel id would make "no parent" indistinguishable
//! from "parent whose digest happens to be zero", and would silently
//! bless a hash the format can never verify.
//!
//! Op registry (tags never reused or renumbered,
//! 0x00 invalid forever): `0x01 = PublishTree`, carrying NO payload. The
//! resulting manifest root already lives in the header field, and
//! a second source for the same value is forbidden. v1's
//! publish path emits exactly one `PublishTree` per commit; the DECODER
//! accepts `1 ..= SHEAF_MAX_OPS` registered ops so a later multi-op
//! commit (the shape spec §6 anticipates) is a writer change, not a
//! reader flag-day. The encoder mirrors the decoder's acceptance
//! exactly — `encode(decode(b)) == b` for every accepted `b`, which a
//! one-op-only encoder would break for bytes the decoder accepts.
//! Any unregistered tag is refused BY NAME; a reader never skips an op
//! it does not understand (an unknown op means unknown effects).
//!
//! ACCEPT-SET LEDGER for that choice, recorded before the sheaf froze
//! (pre-freeze research Q1). Because `PublishTree` is payload-less and
//! the decoder accepts `1 ..= SHEAF_MAX_OPS`, N repetitions of it are N
//! DISTINCT decoded values with IDENTICAL commit semantics — so a
//! hostile publisher can pad a sheaf by up to `SHEAF_MAX_OPS - 1`
//! bytes (≤1023) that every reader still validates. This is NOT a
//! canonicality hole in the encoding sense: distinct byte strings
//! decode to distinct `SheafDoc` values, `encode(decode(b)) == b`
//! holds for every accepted `b`, and the sheaf's own content address
//! covers the padding. It is an accept set WIDER than the writer's
//! image, which is a different property and the one that bit the grain
//! frame's single-frame law.
//!
//! Kept rather than narrowed to `op_count == 1`, deliberately: the
//! width IS the forward-compatibility mechanism — narrowing it now
//! would make the multi-op commit the shape spec anticipates a reader
//! flag day, which is exactly what accepting the range buys. The cost
//! is bounded at ≤1023 bytes and cannot grow, so it is priced.
//!
//! THE RE-DERIVATION CONTRACT this creates, stated because it is not
//! inferable from the format: a verifier that re-derives a sheaf and
//! compares digests must know the v1 WRITER RULE — exactly one
//! `PublishTree` per commit — because the format alone permits many.
//! Server ingest is the first such verifier.

use crate::encoding::{self, Cursor, DecodeError, ObjectType};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};

/// Presence byte for an absent optional id (parent of the first commit).
pub const PRESENCE_ABSENT: u8 = 0x00;
/// Presence byte for a present optional id, followed by the 33-byte id.
pub const PRESENCE_PRESENT: u8 = 0x01;

/// Nanoseconds per second — the parse bound (`nanos >= 1e9`
/// rejected; leap seconds are ignored, the POSIX convention).
pub const NANOS_PER_SEC: u32 = 1_000_000_000;

/// Frozen decode cap on ops in one sheaf (caps must be validated
/// before allocation). v1 emits one; the cap bounds a hostile
/// `op_count` at `1024 × 1 B` before any op byte is trusted.
pub const SHEAF_MAX_OPS: u32 = 1024;

/// Op registry: publish a manifest tree. Payload-less — the resulting
/// root is the header's `manifest_root` field.
pub const OP_TAG_PUBLISH_TREE: u8 = 0x01;

/// Envelope + presence + `manifest_root` + timestamp + `op_count` — the
/// fixed prefix of a parentless sheaf, before the ops.
pub const SHEAF_FIXED_HEADER_LEN: usize = 10 + 1 + GRAIN_ID_BINARY_LEN + 12 + 4;

const _: () = {
    // The op region of a maximal sheaf is bounded by the cap, and the whole
    // object is held under one grain's unpacked size: a bound on the
    // encoding, tighter than granary-store's `META_MAX_BYTES` on the read.
    assert!(
        SHEAF_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN + SHEAF_MAX_OPS as usize
            <= crate::manifest::GRAIN_UNPACKED_MAX as usize
    );
};

/// A persistent timestamp: `i64` seconds + `u32` nanoseconds,
/// Unix epoch, UTC, leap seconds ignored. The on-disk type is OURS —
/// never derived from `SystemTime`'s platform shape, and never packed
/// into a single i64 of nanoseconds (that alternative dies in 2262; a
/// newborn format does not ship a 236-year fuse to save 4 bytes).
///
/// Fields are public and unvalidated at construction: `nanos >= 1e9` is
/// refused by both the encoders and the decoders (the encoder-refuses
/// rule), so an invalid value can never reach bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Timestamp {
    /// Timestamp validity: `nanos` strictly under one second.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.nanos < NANOS_PER_SEC
    }
}

/// One sheaf op. A closed registry — every variant is a registered tag,
/// so an op value that exists cannot be unencodable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SheafOp {
    /// `0x01` — publish the manifest tree named by the header's
    /// `manifest_root`.
    PublishTree,
}

impl SheafOp {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::PublishTree => OP_TAG_PUBLISH_TREE,
        }
    }

    /// # Errors
    /// [`DecodeError::Invalid`] naming the field for any unregistered
    /// tag — never skipped, never guessed.
    pub fn from_tag(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            OP_TAG_PUBLISH_TREE => Ok(Self::PublishTree),
            _ => Err(DecodeError::Invalid {
                what: "sheaf op tag (unregistered)",
            }),
        }
    }
}

/// A decoded sheaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SheafDoc {
    /// Previous sheaf's id; `None` only for a volume's first commit.
    pub parent: Option<GrainId>,
    /// Manifest root this commit resulted in.
    pub manifest_root: GrainId,
    pub timestamp: Timestamp,
    /// 1 ..= [`SHEAF_MAX_OPS`] ops.
    pub ops: Vec<SheafOp>,
}

/// Encode error — the canonical encoder refuses what the decoder
/// rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeSheafError {
    NoOps,
    TooManyOps {
        count: usize,
    },
    /// Invalid timestamp: `nanos` at or above one second.
    NanosOverflow {
        nanos: u32,
    },
}

impl std::fmt::Display for EncodeSheafError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoOps => write!(f, "a sheaf carries at least one op"),
            Self::TooManyOps { count } => {
                write!(f, "{count} ops exceeds SHEAF_MAX_OPS {SHEAF_MAX_OPS}")
            }
            Self::NanosOverflow { nanos } => {
                write!(f, "timestamp nanos {nanos} >= {NANOS_PER_SEC}")
            }
        }
    }
}

impl std::error::Error for EncodeSheafError {}

/// Append an optional id in the presence-byte form (no sentinel).
pub(crate) fn push_optional_id(out: &mut Vec<u8>, id: Option<&GrainId>) {
    match id {
        None => out.push(PRESENCE_ABSENT),
        Some(id) => {
            out.push(PRESENCE_PRESENT);
            out.extend_from_slice(&id.to_bytes());
        }
    }
}

/// Read an optional id: presence byte, then the id iff present. A
/// presence byte outside {0x00, 0x01} is refused by name — it is not a
/// "reserved" value a reader may treat as absent.
pub(crate) fn take_optional_id(
    c: &mut Cursor<'_>,
    what_presence: &'static str,
    what_id: &'static str,
) -> Result<Option<GrainId>, DecodeError> {
    match c.u8()? {
        PRESENCE_ABSENT => Ok(None),
        PRESENCE_PRESENT => take_id(c, what_id).map(Some),
        _ => Err(DecodeError::Invalid {
            what: what_presence,
        }),
    }
}

pub(crate) fn take_id(c: &mut Cursor<'_>, what: &'static str) -> Result<GrainId, DecodeError> {
    let raw = c.take(GRAIN_ID_BINARY_LEN)?;
    GrainId::from_bytes(raw).map_err(|_| DecodeError::Invalid { what })
}

pub(crate) fn push_timestamp(out: &mut Vec<u8>, ts: Timestamp) {
    out.extend_from_slice(&ts.secs.to_be_bytes());
    out.extend_from_slice(&ts.nanos.to_be_bytes());
}

/// Read a timestamp, refusing `nanos >= 1e9` AT PARSE.
pub(crate) fn take_timestamp(c: &mut Cursor<'_>) -> Result<Timestamp, DecodeError> {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "two's-complement reinterpretation IS the i64 BE encoding"
    )]
    let secs = c.u64()? as i64;
    let nanos = c.u32()?;
    let ts = Timestamp { secs, nanos };
    if !ts.is_valid() {
        return Err(DecodeError::Invalid {
            what: "timestamp nanos (>= 1e9)",
        });
    }
    Ok(ts)
}

/// Encode a sheaf in canonical form.
///
/// # Errors
/// [`EncodeSheafError`] naming the violated rule (no ops, over-cap ops,
/// invalid timestamp).
pub fn encode_sheaf(doc: &SheafDoc) -> Result<Vec<u8>, EncodeSheafError> {
    if doc.ops.is_empty() {
        return Err(EncodeSheafError::NoOps);
    }
    if doc.ops.len() > SHEAF_MAX_OPS as usize {
        return Err(EncodeSheafError::TooManyOps {
            count: doc.ops.len(),
        });
    }
    if !doc.timestamp.is_valid() {
        return Err(EncodeSheafError::NanosOverflow {
            nanos: doc.timestamp.nanos,
        });
    }
    let mut out = encoding::envelope(ObjectType::Sheaf);
    push_optional_id(&mut out, doc.parent.as_ref());
    out.extend_from_slice(&doc.manifest_root.to_bytes());
    push_timestamp(&mut out, doc.timestamp);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ops.len() <= SHEAF_MAX_OPS = 1024 checked above"
    )]
    out.extend_from_slice(&(doc.ops.len() as u32).to_be_bytes());
    for op in &doc.ops {
        out.push(op.tag());
    }
    Ok(out)
}

/// Decode a sheaf from the full object bytes. Strict: exact length, every
/// count capped before allocation, every registry value named.
///
/// # Errors
/// The [`DecodeError`] naming the violated rule.
pub fn decode_sheaf(bytes: &[u8]) -> Result<SheafDoc, DecodeError> {
    let (ty, mut c) = encoding::open_envelope(bytes)?;
    if ty != ObjectType::Sheaf {
        return Err(DecodeError::Invalid {
            what: "object type (want sheaf)",
        });
    }
    let parent = take_optional_id(
        &mut c,
        "sheaf parent presence byte",
        "sheaf parent grain id",
    )?;
    let manifest_root = take_id(&mut c, "sheaf manifest_root grain id")?;
    let timestamp = take_timestamp(&mut c)?;
    let op_count = c.u32()?;
    if op_count == 0 {
        return Err(DecodeError::Invalid {
            what: "sheaf op_count zero",
        });
    }
    if op_count > SHEAF_MAX_OPS {
        return Err(DecodeError::CapExceeded {
            what: "sheaf op_count",
            got: u64::from(op_count),
            cap: u64::from(SHEAF_MAX_OPS),
        });
    }
    // Cap validated above: this allocation is bounded by 1024 entries.
    let mut ops = Vec::with_capacity(op_count as usize);
    for _ in 0..op_count {
        ops.push(SheafOp::from_tag(c.u8()?)?);
    }
    c.finish()?;
    Ok(SheafDoc {
        parent,
        manifest_root,
        timestamp,
        ops,
    })
}

#[cfg(test)]
mod tests;
