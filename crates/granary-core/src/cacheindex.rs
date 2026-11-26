// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Client-cache index format v1.
//! Pure encode/decode/replay
//! logic — no I/O; the cache's file handling (`index/snapshot`,
//! `index/journal`, group-commit, compaction order) is
//! `granary-client`'s.
//!
//! **NON-consensus, held to the consensus discipline anyway.**
//! Nothing here is hash-relevant — a
//! cache dir may be discarded and rebuilt from the server at will. It
//! still gets the `format-object` skill's full treatment (canonical
//! encoding, version field, golden vectors, fuzz target, encoding house
//! style: big-endian, fixed-width, enveloped, strictly canonical)
//! because the index is untrusted input the moment a second process — or
//! an attacker with disk access — can write to the cache directory.
//!
//! # The shared envelope
//!
//! Two file kinds share one envelope:
//!
//! ```text
//! magic    4 bytes   b"GRNI"   (DELIBERATELY 4-byte magic for
//!                               this format, not encoding::MAGIC's 8)
//! version  u16 BE    1
//! kind     u8         1 = snapshot, 2 = journal
//! ```
//!
//! Any other magic, version or kind is refused ([`CacheIndexError`]),
//! never adopted — [`open_index_envelope`] is the shared check both
//! [`decode_snapshot`] and [`decode_journal`] run.
//!
//! # Snapshot body
//!
//! ```text
//! entry_count u64 BE
//! entries: entry_count × { grain_digest 32 bytes, object_size u32 BE }
//! ```
//!
//! Entries are strictly ascending by grain id; a duplicate id is a
//! non-strict step and is refused the same way an out-of-order pair is.
//! Trailing bytes are refused. **The declared count is validated
//! against the remaining input length BEFORE any allocation**:
//! `entry_count * 36` must equal exactly the bytes remaining after the
//! count field, or the object is refused outright
//! ([`CacheIndexError::CountMismatch`]) — a declared count of
//! `u64::MAX / 36` over a 100-byte object is refused in the same
//! constant-time check a legitimate object passes, never by attempting
//! (and failing) a huge allocation. The snapshot's entry order is
//! CANONICAL (id order); it deliberately does NOT encode recency —
//! recency is the journal's job, and a snapshot is always immediately
//! followed by replaying the journal written after it.
//!
//!
//! **Grain ids are DIGEST-ONLY (32 bytes), a DELIBERATE divergence**
//! from the 33-byte tagged [`GrainId`] encoding the consensus formats
//! use (binmap, manifest, root, sheaf). The index is
//! keyed like the `objects/` directory itself (digest-leaf CAS
//! fanout), and repeating a constant algorithm tag on every one of
//! ~400,000 entries (the estimated cache scale) buys nothing a
//! single marker-file line does not already state. **v1 reconstruction
//! PINS the Blake3 tag**: [`decode_snapshot`] always rebuilds a
//! [`GrainId`] via `GrainId::from_parts(HashAlgorithm::Blake3, digest)`.
//! [`crate::hash::HashAlgorithm`] registers exactly one variant today,
//! so this is lossless — a second algorithm would need this format to
//! version forward (a v2 kind or an explicit tag field), not silently
//! reinterpret existing bytes. `entry_count × 36` is the normative
//! identity for this reason: it is the wire stride this exact
//! reconstruction relies on. The encode side enforces the same
//! single-algorithm assumption by construction, not by convention: see
//! `digest_only`.
//!
//! # Journal body
//!
//! A record stream, each record:
//!
//! ```text
//! tag u8    1 = insert: grain_digest 32, object_size u32 BE
//!           2 = touch:  grain_digest 32
//!           3 = evict:  grain_digest 32
//! check u32 BE   first 4 bytes of blake3(tag || body-above)
//! ```
//!
//! **Torn-tail rule.** [`replay_journal`] parses records front to back
//! until end of input; a record whose bytes are INCOMPLETE, whose TAG
//! is unrecognized (its length cannot even be determined), or whose
//! CHECK mismatches truncates the journal AT THAT RECORD'S START — the
//! valid prefix stands, the rest is ignored and reported as
//! [`JournalTail::TruncatedAt`] (a BODY-relative offset). A clean end is
//! [`JournalTail::CleanEof`]. **`replay_journal` never returns an
//! error** — a torn tail is the ordinary, expected shape of a
//! group-committed journal crossing a crash, not a parse
//! failure; a genuinely wrong
//! FILE (bad magic/version/kind) is a
//! DIFFERENT, harder failure class, refused by [`decode_journal`]'s
//! envelope guard before a caller ever reaches `replay_journal` at all.
//!
//! **The check is a tear/corruption detector, not authentication — the
//! residual is acknowledged, not hidden.** An attacker who can write
//! these files at all can forge a WHOLE, check-valid file from scratch
//! (the check is a public, keyless blake3 truncation, not a MAC), so
//! passing it never gates TRUST. Content safety comes from the object
//! re-hash on every read and from root verification; quota safety comes
//! from the free-space precheck — never from this check, whose only job
//! is to keep an ORDINARY crash from adopting a torn write.
//!
//! # Fold / replay semantics
//!
//! [`fold`] is deterministic and total: start from the snapshot's
//! entries in id order with UNKNOWN-COLD relative recency, then fold
//! journal records in order — `insert` adds or updates (size replaced,
//! entry moved to most-recent), `touch` moves to most-recent (an id
//! absent from the index is a valid no-op, never an error), `evict`
//! removes (an absent id is a valid no-op, never an error). The output
//! orders LEAST → MOST recent. `total_bytes` is the fold's own sum of
//! live entries' sizes — never a directory measurement (the free-space
//! precheck deliberately never trusts it, cvmfs#2948; it bounds the
//! QUOTA, not the disk).
//!
//! # Golden vectors and fuzzing
//!
//! Golden vectors are committed hex fixtures inline in this module's own
//! `#[cfg(test)]` block (below), not a separate `tests/*_golden.rs` file
//! — this is a lighter, non-consensus format and does not need the
//! external regen-script machinery the consensus objects use. The fuzz
//! target is `fuzz/fuzz_targets/cacheindex_decode.rs`, sharing its probe
//! body (`testkit::cacheindex_decode_probe`) with the stable
//! corpus-replay test per this crate's usual pattern.

use crate::encoding::{self, Cursor};
use crate::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use crate::manifest::node::check_strictly_sorted;

/// 4-byte envelope magic — DELIBERATELY narrower than the 8-byte
/// consensus [`crate::encoding::MAGIC`]: this is a non-consensus format
/// with its own fixed magic, `GRNI`.
pub const MAGIC: [u8; 4] = *b"GRNI";
/// Every v1 object of either kind carries this version.
pub const VERSION: u16 = 1;

const KIND_SNAPSHOT: u8 = 1;
const KIND_JOURNAL: u8 = 2;
/// magic(4) + version(2) + kind(1) — the shared envelope's fixed
/// length. `pub`: a caller converting a
/// [`JournalTail::TruncatedAt`] BODY-relative offset into a
/// FILE-relative one for diagnostics needs this constant, not just the
/// internal arithmetic that produces it.
pub const ENVELOPE_LEN: usize = 4 + 2 + 1;
/// The snapshot body's own count field.
const COUNT_FIELD_LEN: usize = 8;
/// One snapshot entry on the wire: 32-byte digest + 4-byte size.
const SNAPSHOT_ENTRY_LEN: usize = DIGEST_LEN + 4;

const RECORD_TAG_INSERT: u8 = 1;
const RECORD_TAG_TOUCH: u8 = 2;
const RECORD_TAG_EVICT: u8 = 3;
/// Tear/corruption-detection width: the first 4 bytes of a blake3
/// digest, checked per record. NOT authentication — the journal file
/// is attacker-writable (module doc's threat model); real integrity
/// comes from the object re-hash on every content read and from root
/// verification, never from this 32-bit per-record check alone.
const CHECK_LEN: usize = 4;
/// insert record: tag(1) + digest(32) + size(4) + check(4).
const INSERT_RECORD_LEN: usize = 1 + DIGEST_LEN + 4 + CHECK_LEN;
/// touch/evict record: tag(1) + digest(32) + check(4).
const TOUCH_EVICT_RECORD_LEN: usize = 1 + DIGEST_LEN + CHECK_LEN;

/// The two file kinds the shared envelope names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Snapshot,
    Journal,
}

/// Cache-index decode failure. Every variant names the violated rule;
/// this is untrusted input the moment a second process (or an attacker
/// with disk access) can write to the cache directory.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheIndexError {
    /// Input shorter than a fixed-size field required.
    Truncated,
    /// Bytes remained after the body was fully consumed.
    TrailingBytes { remaining: usize },
    /// The 4-byte magic was not `GRNI`.
    BadMagic,
    /// The version field was not [`VERSION`].
    UnknownVersion { version: u16 },
    /// The kind byte was neither 1 (snapshot) nor 2 (journal).
    UnknownKind { kind: u8 },
    /// A well-formed envelope of the WRONG kind for the call that opened
    /// it (e.g. handing `decode_snapshot` a journal-kind object, or
    /// [`decode_journal`] a snapshot-kind one).
    WrongKind { want: FileKind, got: FileKind },
    /// Snapshot entries are not strictly ascending by grain id — a
    /// duplicate id is a non-strict step and lands here too.
    NotStrictlyAscending,
    /// The declared entry count times `SNAPSHOT_ENTRY_LEN` does not
    /// equal the bytes actually remaining — checked BEFORE any
    /// count-sized allocation (the bomb gate).
    CountMismatch { declared: u64, remaining: usize },
    /// `entries.len()` is so large that even computing the encoded body
    /// length overflows `usize` — unreachable in practice (it would
    /// need a slice already resident at an impossible size) but
    /// checked anyway, matching the decode side's own checked
    /// arithmetic.
    TooManyEntries { count: usize },
}

impl std::fmt::Display for CacheIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated cache-index object"),
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing bytes after cache-index body")
            }
            Self::BadMagic => write!(f, "bad magic (not a GRNI cache-index object)"),
            Self::UnknownVersion { version } => {
                write!(f, "unknown cache-index format version {version}")
            }
            Self::UnknownKind { kind } => write!(f, "unknown cache-index kind 0x{kind:02x}"),
            Self::WrongKind { want, got } => {
                write!(f, "expected a {want:?} envelope, got {got:?}")
            }
            Self::NotStrictlyAscending => {
                write!(f, "snapshot entries not strictly ascending by grain id")
            }
            Self::CountMismatch {
                declared,
                remaining,
            } => write!(
                f,
                "declared entry count {declared} at stride {SNAPSHOT_ENTRY_LEN} does not match \
                 {remaining} remaining bytes"
            ),
            Self::TooManyEntries { count } => {
                write!(f, "{count} entries overflow the encoded snapshot length")
            }
        }
    }
}

impl std::error::Error for CacheIndexError {}

/// One journal record — the recency-affecting events a cache write
/// path emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    Insert { id: GrainId, size: u32 },
    Touch { id: GrainId },
    Evict { id: GrainId },
}

/// Where [`replay_journal`] stopped. A torn tail is a CLEAN, TRUSTED
/// outcome under this format's own rule — never an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalTail {
    /// Every byte was consumed by a complete, check-verified record.
    CleanEof,
    /// Parsing stopped at this BODY-relative byte offset (into the
    /// bytes handed to `replay_journal`, NOT counting the shared
    /// 7-byte envelope — add [`ENVELOPE_LEN`] for a file-relative
    /// offset in caller diagnostics): the record starting there was
    /// incomplete, had an unrecognized tag, or failed its check.
    /// Everything before the offset is a trusted, adopted prefix.
    TruncatedAt(usize),
}

/// The folded index state: LRU order plus the fold's own byte total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexState {
    /// Least → most recently used.
    pub entries: Vec<(GrainId, u32)>,
    /// Sum of `entries`' sizes — the fold's own arithmetic, never a
    /// directory measurement.
    pub total_bytes: u64,
}

/// The digest-only write every encode path shares — DELIBERATE (module
/// doc), but only for exactly the one registered algorithm. The
/// exhaustive match is the forcing function: adding a second
/// `HashAlgorithm` variant fails to compile HERE, at the one shared
/// spot that would otherwise silently keep dropping its tag and having
/// every decode reconstruct it as Blake3 regardless. If this ever
/// fails to compile, the fix is a version-forward format change (a v2
/// kind or an explicit tag field), never deleting the match.
#[must_use]
fn digest_only(id: &GrainId) -> &[u8; DIGEST_LEN] {
    match id.algorithm() {
        HashAlgorithm::Blake3 => {}
    }
    id.digest()
}

/// `Cursor::finish` can only ever return `Ok(())` or `TrailingBytes`
/// (see its own impl) — mapped here rather than assumed with an
/// `unreachable!()` a future `Cursor` change could silently falsify.
fn finish_err(e: &encoding::DecodeError) -> CacheIndexError {
    match e {
        encoding::DecodeError::TrailingBytes { remaining } => CacheIndexError::TrailingBytes {
            remaining: *remaining,
        },
        _ => CacheIndexError::Truncated,
    }
}

/// Open the shared `GRNI` envelope: magic, version, kind. Returns the
/// kind and the remaining BODY bytes.
///
/// # Errors
/// [`CacheIndexError::Truncated`] on an input shorter than the 7-byte
/// envelope; [`CacheIndexError::BadMagic`] on a foreign magic;
/// [`CacheIndexError::UnknownVersion`] on any version other than
/// [`VERSION`]; [`CacheIndexError::UnknownKind`] on any kind byte other
/// than 1 (snapshot) or 2 (journal).
pub fn open_index_envelope(bytes: &[u8]) -> Result<(FileKind, &[u8]), CacheIndexError> {
    let mut c = Cursor::new(bytes);
    let magic = c.take(4).map_err(|_| CacheIndexError::Truncated)?;
    if magic != MAGIC {
        return Err(CacheIndexError::BadMagic);
    }
    let version = c.u16().map_err(|_| CacheIndexError::Truncated)?;
    if version != VERSION {
        return Err(CacheIndexError::UnknownVersion { version });
    }
    let kind_byte = c.u8().map_err(|_| CacheIndexError::Truncated)?;
    let kind = match kind_byte {
        KIND_SNAPSHOT => FileKind::Snapshot,
        KIND_JOURNAL => FileKind::Journal,
        other => return Err(CacheIndexError::UnknownKind { kind: other }),
    };
    // Everything left in `c` IS the body; `take(remaining())` can never
    // fail (the length is the cursor's own), so this is the safe way to
    // hand the caller the rest of the slice.
    let body = c
        .take(c.remaining())
        .map_err(|_| CacheIndexError::Truncated)?;
    Ok((kind, body))
}

/// Encode a snapshot: `entries` must be strictly ascending by grain id
/// (a duplicate id is a non-strict step and is refused the same way).
///
/// # Errors
/// [`CacheIndexError::NotStrictlyAscending`] when the order rule is
/// violated — the encoder refuses what the decoder rejects.
/// [`CacheIndexError::TooManyEntries`] if the encoded body
/// length would overflow `usize` (unreachable in practice, checked
/// anyway).
pub fn encode_snapshot(entries: &[(GrainId, u32)]) -> Result<Vec<u8>, CacheIndexError> {
    if !check_strictly_sorted(entries, |e| &e.0) {
        return Err(CacheIndexError::NotStrictlyAscending);
    }
    let count = entries.len() as u64; // usize -> u64: always widening on real targets
    let body_len = entries
        .len()
        .checked_mul(SNAPSHOT_ENTRY_LEN)
        .and_then(|n| n.checked_add(ENVELOPE_LEN + COUNT_FIELD_LEN))
        .ok_or(CacheIndexError::TooManyEntries {
            count: entries.len(),
        })?;
    let mut out = Vec::with_capacity(body_len);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(KIND_SNAPSHOT);
    out.extend_from_slice(&count.to_be_bytes());
    for (id, size) in entries {
        out.extend_from_slice(digest_only(id));
        out.extend_from_slice(&size.to_be_bytes());
    }
    Ok(out)
}

/// Decode a snapshot from the full object bytes (envelope + body).
///
/// # Errors
/// [`CacheIndexError`] naming the violated rule: envelope failures from
/// [`open_index_envelope`] (including [`CacheIndexError::WrongKind`] if
/// handed a journal-kind object); [`CacheIndexError::CountMismatch`] —
/// checked BEFORE any count-sized allocation, the bomb gate; per-entry
/// [`CacheIndexError::Truncated`]; [`CacheIndexError::NotStrictlyAscending`]
/// on a duplicate or out-of-order id, checked INLINE as each entry is
/// read (fail-fast, no second pass). [`CacheIndexError::TrailingBytes`]
/// is UNREACHABLE here by the count × `SNAPSHOT_ENTRY_LEN` ==
/// `remaining` identity the bomb gate already proved: the entry loop
/// consumes exactly that many bytes, so the cursor is always empty when
/// the loop completes. The check is kept anyway as defense-in-depth
/// against a future change to this function's own body, not because
/// today's bytes can trip it.
pub fn decode_snapshot(bytes: &[u8]) -> Result<Vec<(GrainId, u32)>, CacheIndexError> {
    let (kind, body) = open_index_envelope(bytes)?;
    if kind != FileKind::Snapshot {
        return Err(CacheIndexError::WrongKind {
            want: FileKind::Snapshot,
            got: kind,
        });
    }
    let mut c = Cursor::new(body);
    let count = c.u64().map_err(|_| CacheIndexError::Truncated)?;

    // THE BOMB GATE. `count * SNAPSHOT_ENTRY_LEN` is checked against the
    // bytes ACTUALLY remaining (a real, already-in-memory length) BEFORE
    // any count-sized allocation — `checked_mul` so a declared count
    // near u64::MAX cannot even overflow the comparison itself into a
    // false accept. A declared count of `u64::MAX / 36` over a
    // near-empty body fails this single comparison and returns
    // immediately; the class of bug this closes is allocating
    // proportionally to a DECLARED length instead of the bytes present.
    let remaining = c.remaining();
    let implied = count.checked_mul(SNAPSHOT_ENTRY_LEN as u64);
    if implied != Some(remaining as u64) {
        return Err(CacheIndexError::CountMismatch {
            declared: count,
            remaining,
        });
    }
    // `count` is now KNOWN to satisfy `count * SNAPSHOT_ENTRY_LEN ==
    // remaining`, and `remaining` is a real `usize` — so `count` itself
    // numerically fits `usize` (it is at most `remaining`). `try_from`
    // stays the mechanism rather than an `as` cast: a future 32-bit
    // target proves the bound at runtime instead of by this comment.
    let count_usize = usize::try_from(count).map_err(|_| CacheIndexError::CountMismatch {
        declared: count,
        remaining,
    })?;

    let mut out = Vec::with_capacity(count_usize);
    let mut prev: Option<GrainId> = None;
    for _ in 0..count_usize {
        let digest_bytes = c.take(DIGEST_LEN).map_err(|_| CacheIndexError::Truncated)?;
        let digest: [u8; DIGEST_LEN] = digest_bytes
            .try_into()
            .map_err(|_| CacheIndexError::Truncated)?;
        let size = c.u32().map_err(|_| CacheIndexError::Truncated)?;
        let id = GrainId::from_parts(HashAlgorithm::Blake3, digest);
        // Inline, fail-fast order check: compare
        // against the PREVIOUS entry as each one is read, instead of
        // building the whole Vec and re-scanning it afterward.
        if let Some(p) = prev
            && p >= id
        {
            return Err(CacheIndexError::NotStrictlyAscending);
        }
        prev = Some(id);
        out.push((id, size));
    }
    c.finish().map_err(|e| finish_err(&e))?;
    Ok(out)
}

/// The first 4 bytes of `blake3(preimage)` — `preimage` is `tag ||
/// body` per the journal record's own definition.
fn record_check(preimage: &[u8]) -> [u8; CHECK_LEN] {
    let full = *blake3::hash(preimage).as_bytes();
    // Irrefutable destructure of a fixed-width array: no indexing, no
    // bounds check to get wrong (the `binmap::shard_for` precedent).
    let [c0, c1, c2, c3, ..] = full;
    [c0, c1, c2, c3]
}

/// Encode one journal record directly onto the end of `out`: `tag ||
/// body || check`, appended — `out` is not cleared first. Building a
/// whole journal body from many records with this avoids the
/// intermediate per-record `Vec` [`encode_record`] (which delegates to
/// this) allocates. Total over every [`Record`] value — there is no
/// failure mode (every id is Blake3, the only registered algorithm, so
/// nothing is lost writing the digest alone — see `digest_only`).
pub fn encode_record_into(out: &mut Vec<u8>, record: &Record) {
    let start = out.len();
    match record {
        Record::Insert { id, size } => {
            out.push(RECORD_TAG_INSERT);
            out.extend_from_slice(digest_only(id));
            out.extend_from_slice(&size.to_be_bytes());
        }
        Record::Touch { id } => {
            out.push(RECORD_TAG_TOUCH);
            out.extend_from_slice(digest_only(id));
        }
        Record::Evict { id } => {
            out.push(RECORD_TAG_EVICT);
            out.extend_from_slice(digest_only(id));
        }
    }
    // `out.get(start..)` can never be `None`: `start` was `out.len()`
    // before the match above appended at least a tag and a digest.
    let check = record_check(out.get(start..).unwrap_or_default());
    out.extend_from_slice(&check);
}

/// Encode one journal record: `tag || body || check`. See
/// [`encode_record_into`], which this delegates to — prefer that form
/// when building a whole journal body from many records.
#[must_use]
pub fn encode_record(record: &Record) -> Vec<u8> {
    let mut out = Vec::with_capacity(INSERT_RECORD_LEN);
    encode_record_into(&mut out, record);
    out
}

/// Read a grain digest via `c` — the first shared step of both
/// `parse_one_record` arms, right after the tag.
fn read_digest(c: &mut Cursor<'_>) -> Option<[u8; DIGEST_LEN]> {
    c.take(DIGEST_LEN).ok()?.try_into().ok()
}

/// Read and verify the trailing check via `c` against
/// `blake3(chunk[..preimage_len])` — the second shared step of both
/// `parse_one_record` arms, run after the caller has read any
/// tag-specific fields between the id and the check (insert's `size`).
fn verify_check(c: &mut Cursor<'_>, chunk: &[u8], preimage_len: usize) -> Option<()> {
    let check_bytes = c.take(CHECK_LEN).ok()?;
    let preimage = chunk.get(..preimage_len)?;
    let expected = record_check(preimage);
    let actual: [u8; CHECK_LEN] = check_bytes.try_into().ok()?;
    (expected == actual).then_some(())
}

/// Parse exactly one record from the FRONT of `chunk`. `None` means the
/// chunk is too short for the shape its tag declares, the tag itself is
/// unrecognized (so no shape can even be determined), or the check
/// mismatches — every one of those is a torn-tail truncation site to
/// [`replay_journal`], never a hard error.
fn parse_one_record(chunk: &[u8]) -> Option<(Record, usize)> {
    let mut c = Cursor::new(chunk);
    let tag = c.u8().ok()?;
    match tag {
        RECORD_TAG_INSERT => {
            let digest = read_digest(&mut c)?;
            let size = c.u32().ok()?;
            verify_check(&mut c, chunk, 1 + DIGEST_LEN + 4)?;
            let id = GrainId::from_parts(HashAlgorithm::Blake3, digest);
            Some((Record::Insert { id, size }, INSERT_RECORD_LEN))
        }
        RECORD_TAG_TOUCH | RECORD_TAG_EVICT => {
            let digest = read_digest(&mut c)?;
            verify_check(&mut c, chunk, 1 + DIGEST_LEN)?;
            let id = GrainId::from_parts(HashAlgorithm::Blake3, digest);
            let record = if tag == RECORD_TAG_TOUCH {
                Record::Touch { id }
            } else {
                Record::Evict { id }
            };
            Some((record, TOUCH_EVICT_RECORD_LEN))
        }
        _ => None,
    }
}

/// Replay a journal BODY (post-envelope bytes): parse records front to
/// back until end of input. **Never returns an error** — a torn tail is
/// a CLEAN, TRUSTED outcome by this format's own rule, not a parse
/// failure; see the module doc's "Torn-tail rule". Most callers want
/// [`decode_journal`], which adds the envelope/kind guard this function
/// deliberately omits: handed non-journal bytes directly (a snapshot
/// body, say), this still parses whatever the bytes happen to look
/// like as a record stream rather than refusing outright — that guard
/// lives at the envelope layer, not here.
#[must_use]
pub fn replay_journal(bytes: &[u8]) -> (Vec<Record>, JournalTail) {
    let mut records = Vec::new();
    let mut rest = bytes;
    let mut offset = 0usize;
    while !rest.is_empty() {
        let Some((record, consumed)) = parse_one_record(rest) else {
            return (records, JournalTail::TruncatedAt(offset));
        };
        records.push(record);
        offset += consumed;
        // `consumed <= rest.len()` by construction (`parse_one_record`
        // only returns `Some` after reading exactly that many bytes
        // FROM `rest`), so this can never actually fall back to empty.
        rest = rest.get(consumed..).unwrap_or_default();
    }
    (records, JournalTail::CleanEof)
}

/// Decode a journal from the full object bytes (envelope + body): the
/// guarded entry point, mirroring [`decode_snapshot`]'s envelope guard
/// for the other kind. Handing this SNAPSHOT-kind bytes is refused BY
/// NAME ([`CacheIndexError::WrongKind`]) rather than silently replaying
/// zero records from a body [`replay_journal`] alone has no kind to
/// check against — a snapshot body fed to `replay_journal` directly
/// parses as an empty, all-torn journal instead of being refused,
/// which is exactly the trap this function closes.
///
/// # Errors
/// Envelope failures from [`open_index_envelope`] (bad magic, unknown
/// version, unknown kind byte); [`CacheIndexError::WrongKind`] if
/// handed a snapshot-kind object.
pub fn decode_journal(bytes: &[u8]) -> Result<(Vec<Record>, JournalTail), CacheIndexError> {
    let (kind, body) = open_index_envelope(bytes)?;
    if kind != FileKind::Journal {
        return Err(CacheIndexError::WrongKind {
            want: FileKind::Journal,
            got: kind,
        });
    }
    Ok(replay_journal(body))
}

/// Fold a snapshot plus a journal's records into the live index state.
/// Deterministic and TOTAL — no record sequence panics: an absent id
/// under `touch` or `evict` is a valid no-op, never an error, and a
/// (malformed, duplicate-id) input `snapshot` Vec is de-duplicated
/// deterministically (first occurrence keeps its position, later ones
/// only update its size) rather than producing two entries for one id.
///
/// O((n+m) log n) — a `BTreeMap<GrainId, (u64, u32)>` (seq, size) plus
/// a monotone `u64` counter, not the previous `Vec<GrainId>` + `retain`
/// shape, whose per-event O(live entries) scan made a crafted journal
/// against a large index (~400k entries) an attacker-cheap
/// CPU burn on cache open (the journal has no decode-time record cap
/// and is attacker-writable). Snapshot entries seed with `seq` = their
/// position (0..n, id order — preserving the cold least→most =
/// ascending-id semantics); every `insert`/`touch` draws a FRESH,
/// strictly larger `seq` from the same counter, so a touched/inserted
/// id always outranks every untouched cold entry. Every `seq` is
/// assigned at most once and never reused, so the final sort-by-`seq`
/// needs no tie rule.
#[must_use]
pub fn fold(snapshot: Vec<(GrainId, u32)>, records: &[Record]) -> IndexState {
    use std::collections::btree_map::Entry;

    let mut live: std::collections::BTreeMap<GrainId, (u64, u32)> =
        std::collections::BTreeMap::new();
    let mut next_seq: u64 = 0;

    // Seed from the snapshot, in the order given (canonically
    // id-ascending). A duplicate id in a malformed input Vec updates
    // the size but KEEPS the FIRST occurrence's seq — the documented
    // dedup contract
    // (`fold_duplicate_id_snapshot_keeps_first_position_and_last_size`
    // pins this).
    for (id, size) in snapshot {
        match live.entry(id) {
            Entry::Vacant(v) => {
                v.insert((next_seq, size));
                next_seq += 1;
            }
            Entry::Occupied(mut o) => {
                o.get_mut().1 = size;
            }
        }
    }

    for record in records {
        match *record {
            Record::Insert { id, size } => {
                let seq = next_seq;
                next_seq += 1;
                live.insert(id, (seq, size));
            }
            Record::Touch { id } => {
                if let Some(entry) = live.get_mut(&id) {
                    entry.0 = next_seq;
                    next_seq += 1;
                }
            }
            Record::Evict { id } => {
                live.remove(&id);
            }
        }
    }

    let mut ordered: Vec<(GrainId, u64, u32)> = live
        .into_iter()
        .map(|(id, (seq, size))| (id, seq, size))
        .collect();
    ordered.sort_unstable_by_key(|&(_, seq, _)| seq);

    let mut total_bytes: u64 = 0;
    let entries: Vec<(GrainId, u32)> = ordered
        .into_iter()
        .map(|(id, _, size)| {
            // `saturating_add`, not `+`: this crate's release profile
            // runs `overflow-checks = true` (coding-standards rule 4),
            // so a wrapping `+` on untrusted-input-derived sizes would
            // be a PANIC path, not a silent wrap. Reaching `u64::MAX`
            // from `u32` sizes needs ~2^32 maximal entries, each
            // costing >= 36 real wire bytes under the pre-allocation
            // count identity — >= 144 GiB resident before the sum can
            // saturate. Unreachable in practice; defended regardless.
            total_bytes = total_bytes.saturating_add(u64::from(size));
            (id, size)
        })
        .collect();

    IndexState {
        entries,
        total_bytes,
    }
}

#[cfg(test)]
mod tests;
