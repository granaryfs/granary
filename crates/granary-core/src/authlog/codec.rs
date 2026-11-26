// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The wire codec: [`encode_envelope`], [`encode_append`], and the
//! decode primitives `classify` drives (envelope, one record+mark
//! pair, one record body). Pure byte layout — the committed log's
//! grammar lives in `super::classify`.

use crate::encoding::{Cursor, DecodeError};
use crate::hash::GrainId;
use crate::root::VolumeName;
use crate::sheaf::{push_optional_id, push_timestamp, take_id, take_optional_id, take_timestamp};

use super::record::{
    RecordBody, TAG_ATTESTATION, TAG_DECISION, TAG_LANDED, TAG_LOST, TAG_RESERVED_05,
};
use super::submission::{
    HexFieldError, Operation, Principal, RootBytes, SubmissionIdentity, Tenant, decode_hex16,
    decode_hex32, encode_hex16, encode_hex32,
};
use super::{
    ENVELOPE_CONTEXT, ENVELOPE_LENGTH_MAX, ENVELOPE_LENGTH_MIN, ENVELOPE_OUTER_LEN, Envelope,
    Epoch, MARK_CONTEXT, MARK_LEN, MARK_MAGIC, RECORD_BODY_MAX, RECORD_CONTEXT, RECORD_FIXED_LEN,
    Record,
};

// -------------------------------------------------------------- encode

/// An encoded envelope's wire bytes — opaque so a caller can never split
/// or reassemble them by hand (spec §8's "values are the codec's types,
/// never raw slices"). The only way to reach the bytes is
/// [`EncodedEnvelope::as_bytes`], and the only way to build one is
/// [`encode_envelope`].
///
/// **Carries the volume it was encoded against** ([`Self::volume`]),
/// exactly the [`Envelope`] passed to [`encode_envelope`] named.
/// [`DecisionLog::initialise`](crate::decisionlog::DecisionLog::initialise)
/// takes this value alone, with no separate volume parameter, so an
/// adapter derives the log it creates from the value itself: there is no
/// second, independently-supplied name that could name a different one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedEnvelope {
    bytes: Vec<u8>,
    volume: VolumeName,
}

impl EncodedEnvelope {
    /// The envelope's wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The volume this envelope names.
    #[must_use]
    pub fn volume(&self) -> &VolumeName {
        &self.volume
    }
}

/// Encode the envelope. Infallible: [`Envelope`]'s fields are already
/// validated by construction ([`VolumeName`], [`Epoch`]), so every
/// value this module can build encodes.
#[must_use]
pub fn encode_envelope(envelope: &Envelope) -> EncodedEnvelope {
    let mut body = Vec::with_capacity(1 + envelope.volume().as_str().len() + super::EPOCH_LEN);
    body.push(envelope.volume().wire_len());
    body.extend_from_slice(envelope.volume().as_str().as_bytes());
    body.extend_from_slice(&envelope.epoch().to_bytes());

    let length = ENVELOPE_OUTER_LEN + body.len();
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&super::ENVELOPE_MAGIC);
    out.extend_from_slice(&envelope.version().to_be_bytes());
    // `length` is at most `ENVELOPE_V1_MAX` (124, `VolumeName`'s own
    // 63-byte cap), far inside u16 and inside [ENVELOPE_LENGTH_MIN,
    // ENVELOPE_LENGTH_MAX].
    #[expect(
        clippy::cast_possible_truncation,
        reason = "length <= ENVELOPE_V1_MAX = 124, far under u16::MAX"
    )]
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.extend_from_slice(&body);
    let check = blake3::derive_key(ENVELOPE_CONTEXT, &out);
    out.extend_from_slice(&check);
    EncodedEnvelope {
        bytes: out,
        volume: envelope.volume().clone(),
    }
}

/// Encoding a record's field-level rules — the same rules
/// classification enforces on decode, refused here so a caller
/// can never write what a reader would refuse.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeRecordError {
    /// A decision's `identity.candidate_id` is not `GrainId::of(candidate)`.
    CandidateIdMismatch,
    /// `root_seq` is outside 1–18446744073709551613.
    RootSeqOutOfRange { root_seq: u64 },
    /// `base` is present iff `root_seq != 1`.
    ParentSeqMismatch { root_seq: u64, has_base: bool },
    /// `decided_at.nanos >= 1_000_000_000`.
    NanosOverflow { nanos: u32 },
    /// A decision's `candidate` does not decode as a root at all.
    CandidateNotARoot,
    /// The decoded candidate root names another volume.
    CandidateVolumeMismatch,
    /// The decoded candidate root's `seq` is not `root_seq`.
    CandidateSeqMismatch,
    /// The decoded candidate root's `parent` is not `base`.
    CandidateParentMismatch,
    /// An attestation's `stored_id` is not `GrainId::of(final_root)`.
    StoredIdMismatch,
}

impl std::fmt::Display for EncodeRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CandidateIdMismatch => write!(f, "candidate_id is not GrainId::of(candidate)"),
            Self::RootSeqOutOfRange { root_seq } => {
                write!(
                    f,
                    "root_seq {root_seq} is out of range 1..=18446744073709551613"
                )
            }
            Self::ParentSeqMismatch { root_seq, has_base } => write!(
                f,
                "root_seq {root_seq} with base present = {has_base}: base is absent iff \
                 root_seq == 1"
            ),
            Self::NanosOverflow { nanos } => write!(f, "decided_at nanos {nanos} >= 1e9"),
            Self::CandidateNotARoot => write!(f, "candidate does not decode as a root"),
            Self::CandidateVolumeMismatch => {
                write!(f, "candidate root names another volume")
            }
            Self::CandidateSeqMismatch => write!(f, "candidate root seq is not root_seq"),
            Self::CandidateParentMismatch => write!(f, "candidate root parent is not base"),
            Self::StoredIdMismatch => write!(f, "stored_id is not GrainId::of(final_root)"),
        }
    }
}

impl std::error::Error for EncodeRecordError {}

fn encode_submission_identity(out: &mut Vec<u8>, identity: &SubmissionIdentity) {
    encode_hex16(out, identity.tenant().as_bytes());
    encode_hex16(out, identity.principal().as_bytes());
    encode_hex16(out, identity.operation().as_bytes());
    out.extend_from_slice(&identity.candidate_id().to_bytes());
}

pub(crate) fn encode_record_body(
    out: &mut Vec<u8>,
    body: &RecordBody,
    volume: &VolumeName,
) -> Result<(), EncodeRecordError> {
    match body {
        RecordBody::Decision {
            identity,
            root_seq,
            base,
            decided_at,
            candidate,
        } => {
            if *root_seq == 0 || *root_seq > crate::authority_answer::LAST_CANDIDATE_SEQ {
                return Err(EncodeRecordError::RootSeqOutOfRange {
                    root_seq: *root_seq,
                });
            }
            if (*root_seq == 1) != base.is_none() {
                return Err(EncodeRecordError::ParentSeqMismatch {
                    root_seq: *root_seq,
                    has_base: base.is_some(),
                });
            }
            if identity.candidate_id() != GrainId::of(candidate.as_bytes()) {
                return Err(EncodeRecordError::CandidateIdMismatch);
            }
            if !decided_at.is_valid() {
                return Err(EncodeRecordError::NanosOverflow {
                    nanos: decided_at.nanos,
                });
            }
            let root = crate::root::decode_root(candidate.as_bytes())
                .map_err(|_| EncodeRecordError::CandidateNotARoot)?;
            if root.volume != *volume {
                return Err(EncodeRecordError::CandidateVolumeMismatch);
            }
            if root.seq != *root_seq {
                return Err(EncodeRecordError::CandidateSeqMismatch);
            }
            if root.parent != *base {
                return Err(EncodeRecordError::CandidateParentMismatch);
            }

            encode_submission_identity(out, identity);
            out.extend_from_slice(&root_seq.to_be_bytes());
            push_optional_id(out, base.as_ref());
            push_timestamp(out, *decided_at);
            encode_hex32(out, candidate.as_bytes());
        }
        RecordBody::Attestation {
            identity,
            stored_id,
            final_root,
        } => {
            if *stored_id != GrainId::of(final_root.as_bytes()) {
                return Err(EncodeRecordError::StoredIdMismatch);
            }
            encode_submission_identity(out, identity);
            out.extend_from_slice(&stored_id.to_bytes());
            encode_hex32(out, final_root.as_bytes());
        }
        RecordBody::Landed { identity } => {
            encode_submission_identity(out, identity);
        }
        RecordBody::Lost {
            identity,
            occupant_id,
        } => {
            encode_submission_identity(out, identity);
            out.extend_from_slice(&occupant_id.to_bytes());
        }
    }
    Ok(())
}

/// Build a mark from its four named fields. `pub(crate)` rather than
/// private: the unit tests reuse it to re-sign a deliberately mutated
/// record body with a self-consistent mark (the "planted mark" and
/// non-canonical-reject scenarios need a mark that genuinely commits
/// bytes the format would otherwise refuse for an unrelated reason).
pub(crate) fn build_mark(
    epoch: Epoch,
    seq: u64,
    tag: u8,
    record_check: [u8; 32],
) -> [u8; MARK_LEN] {
    let mut preimage = [0u8; 65];
    let (magic_dst, rest) = preimage.split_at_mut(8);
    magic_dst.copy_from_slice(&MARK_MAGIC);
    let (epoch_dst, rest) = rest.split_at_mut(super::EPOCH_LEN);
    epoch_dst.copy_from_slice(&epoch.to_bytes());
    let (seq_dst, rest) = rest.split_at_mut(8);
    seq_dst.copy_from_slice(&seq.to_be_bytes());
    let (tag_dst, record_check_dst) = rest.split_at_mut(1);
    tag_dst.copy_from_slice(&[tag]);
    record_check_dst.copy_from_slice(&record_check);

    let check = blake3::derive_key(MARK_CONTEXT, &preimage);

    let mut out = [0u8; MARK_LEN];
    let (head, tail) = out.split_at_mut(65);
    head.copy_from_slice(&preimage);
    tail.copy_from_slice(&check);
    out
}

/// One record's wire bytes, plus its 97-byte mark, as a single opaque
/// value — spec §8's "values are the codec's types, never raw slices".
/// Only [`encode_append`] builds one, and its `record`/`mark` fields are
/// private so a caller cannot move bytes across the record/mark boundary
/// (a raw `(Vec<u8>, [u8; MARK_LEN])` tuple lets a caller pass
/// `record||mark` as the record and an empty mark, writing evidence
/// before the record's own sync has returned).
///
/// **Carries the volume and epoch it was encoded against**
/// ([`Self::volume`], [`Self::epoch`]), exactly the [`Envelope`] passed
/// to [`encode_append`]. [`DecisionLog::append`] (`crate::decisionlog`)
/// takes one by reference, with no separate volume parameter, so an
/// adapter derives the log it writes to from the value itself — there is
/// no second, independently-supplied name that could name a different
/// one. The adapter writes [`Self::record`], syncs it, then writes
/// [`Self::mark`] and syncs that — the two must never be concatenated or
/// reordered.
///
/// **This seam does not check the epoch against the log it addresses.**
/// A value built against a stale epoch (an old envelope, from before a
/// log loss and re-`initialise`) is still a value this trait accepts —
/// avoiding that is the engine's own responsibility, never this type's.
///
/// [`DecisionLog::append`]: crate::decisionlog::DecisionLog::append
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Append {
    record: Vec<u8>,
    mark: [u8; MARK_LEN],
    volume: VolumeName,
    epoch: Epoch,
}

impl Append {
    /// The record's wire bytes, without its mark.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }

    /// The record's 97-byte mark.
    #[must_use]
    pub fn mark(&self) -> &[u8; MARK_LEN] {
        &self.mark
    }

    /// The volume this append targets.
    #[must_use]
    pub fn volume(&self) -> &VolumeName {
        &self.volume
    }

    /// The epoch this append was encoded against.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// Encode one record for [`DecisionLog::append`] (`crate::decisionlog`):
/// its wire bytes and its mark, bound together with `envelope`'s volume
/// and epoch in an opaque [`Append`] so a caller cannot split or reorder
/// the bytes, or write them to a log other than the one `envelope` names
/// (see [`Append`]'s docs).
///
/// # Errors
/// [`EncodeRecordError`] naming the violated field rule — the encoder
/// refuses every value the decoder would refuse.
///
/// [`DecisionLog::append`]: crate::decisionlog::DecisionLog::append
pub fn encode_append(envelope: &Envelope, record: &Record) -> Result<Append, EncodeRecordError> {
    let tag = record.body().tag();
    let mut body = Vec::new();
    encode_record_body(&mut body, record.body(), envelope.volume())?;

    let mut out = Vec::with_capacity(RECORD_FIXED_LEN + body.len());
    out.push(tag);
    out.extend_from_slice(&envelope.version().to_be_bytes());
    out.extend_from_slice(&envelope.epoch().to_bytes());
    out.extend_from_slice(&record.seq().to_be_bytes());
    // `body.len()` is bounded well under `u32::MAX` by every field's own
    // cap (the const assertion beside `RECORD_BODY_MAX`); a body that
    // somehow exceeded it would still not overflow this cast on any
    // real target, but the classifier's own `RECORD_BODY_MAX` check is
    // what a caller-visible bound would be — this module trusts the
    // types it was handed, the same as every other encoder in this
    // crate.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "body.len() is bounded by each field's own cap, far under u32::MAX"
    )]
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    let check = blake3::derive_key(RECORD_CONTEXT, &out);
    out.extend_from_slice(&check);

    let mark = build_mark(envelope.epoch(), record.seq(), tag, check);
    Ok(Append {
        record: out,
        mark,
        volume: envelope.volume().clone(),
        epoch: envelope.epoch(),
    })
}

// -------------------------------------------------------------- decode
//
// Internal (`pub(crate)`/private): `classify` folds every failure here
// into "this pair is not accepted" — the classifier does not explain
// why a candidate record was bad, only whether a mark commits it.
// The detailed errors remain available as a real enum rather than
// `Option` for the unit tests exercising these
// paths directly (typed, not string, per the house rule on checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordFieldReason {
    Truncated,
    TrailingBytes,
    Hex(HexFieldError),
    InvalidPresence,
    /// A tag the registry reserves and v1 never writes (`0x05`).
    ReservedTag,
    UnknownTag,
    CandidateIdMismatch,
    RootSeqOutOfRange,
    ParentSeqMismatch,
    NanosOverflow,
    CandidateNotARoot,
    CandidateVolumeMismatch,
    CandidateSeqMismatch,
    CandidateParentMismatch,
    StoredIdMismatch,
}

/// `crate::sheaf`'s id readers return `DecodeError`, which this module
/// collapses to the two things any caller here ever does with it: a
/// presence byte outside `{0x00, 0x01}` is [`RecordFieldReason::InvalidPresence`];
/// anything else (a short read, or an unregistered hash algorithm tag)
/// is [`RecordFieldReason::Truncated`]. Either way `classify` only ever
/// asks "was this pair accepted", never which reason fired (module
/// doc), so one mapping site is enough.
fn map_id_decode_error(e: &DecodeError) -> RecordFieldReason {
    match e {
        DecodeError::Invalid { .. } => RecordFieldReason::InvalidPresence,
        _ => RecordFieldReason::Truncated,
    }
}

fn decode_id(c: &mut Cursor<'_>) -> Result<GrainId, RecordFieldReason> {
    take_id(c, "authlog record id").map_err(|e| map_id_decode_error(&e))
}

fn decode_optional_id(c: &mut Cursor<'_>) -> Result<Option<GrainId>, RecordFieldReason> {
    take_optional_id(
        c,
        "authlog optional id presence byte",
        "authlog optional id",
    )
    .map_err(|e| map_id_decode_error(&e))
}

fn decode_decided_at(c: &mut Cursor<'_>) -> Result<crate::sheaf::Timestamp, RecordFieldReason> {
    take_timestamp(c).map_err(|e| match e {
        DecodeError::Invalid { .. } => RecordFieldReason::NanosOverflow,
        _ => RecordFieldReason::Truncated,
    })
}

fn decode_submission_identity(c: &mut Cursor<'_>) -> Result<SubmissionIdentity, RecordFieldReason> {
    let tenant_bytes = decode_hex16(c, super::TENANT_MAX).map_err(RecordFieldReason::Hex)?;
    let principal_bytes = decode_hex16(c, super::PRINCIPAL_MAX).map_err(RecordFieldReason::Hex)?;
    let operation_bytes = decode_hex16(c, super::OPERATION_MAX).map_err(RecordFieldReason::Hex)?;
    let candidate_id = decode_id(c)?;
    // Every `decode_hexN` call above already checked its raw length
    // against the same cap `Tenant`/`Principal`/`Operation::new` would
    // enforce, so the `Err` arms below are unreachable in practice —
    // mapped anyway rather than assumed with an `unwrap`, the same
    // discipline `cacheindex::finish_err` documents for its own
    // can-only-return-one-variant case.
    let tenant = Tenant::new(tenant_bytes).map_err(|_| RecordFieldReason::Truncated)?;
    let principal = Principal::new(principal_bytes).map_err(|_| RecordFieldReason::Truncated)?;
    let operation = Operation::new(operation_bytes).map_err(|_| RecordFieldReason::Truncated)?;
    Ok(SubmissionIdentity::new(
        tenant,
        principal,
        operation,
        candidate_id,
    ))
}

/// Decode one record body given its already-length-bounded `body`
/// bytes (the caller has already checked `body.len() <=
/// RECORD_BODY_MAX` against the record header's `body_len`). Strict:
/// the decoder checks the fields for the record's tag and refuses
/// trailing bytes after the last field.
pub(crate) fn decode_record_body(
    tag: u8,
    body: &[u8],
    volume: &VolumeName,
) -> Result<RecordBody, RecordFieldReason> {
    // A reserved tag refuses before any of its body is read: no v1 body
    // is laid out under it.
    if tag == TAG_RESERVED_05 {
        return Err(RecordFieldReason::ReservedTag);
    }
    let mut c = Cursor::new(body);
    let identity = decode_submission_identity(&mut c)?;
    let record_body = match tag {
        TAG_DECISION => {
            let root_seq = c.u64().map_err(|_| RecordFieldReason::Truncated)?;
            if root_seq == 0 || root_seq > crate::authority_answer::LAST_CANDIDATE_SEQ {
                return Err(RecordFieldReason::RootSeqOutOfRange);
            }
            let base = decode_optional_id(&mut c)?;
            if (root_seq == 1) != base.is_none() {
                return Err(RecordFieldReason::ParentSeqMismatch);
            }
            let decided_at = decode_decided_at(&mut c)?;
            let candidate_bytes =
                decode_hex32(&mut c, super::ROOT_BYTES_MAX).map_err(RecordFieldReason::Hex)?;
            if identity.candidate_id() != GrainId::of(&candidate_bytes) {
                return Err(RecordFieldReason::CandidateIdMismatch);
            }
            let root = crate::root::decode_root(&candidate_bytes)
                .map_err(|_| RecordFieldReason::CandidateNotARoot)?;
            if root.volume != *volume {
                return Err(RecordFieldReason::CandidateVolumeMismatch);
            }
            if root.seq != root_seq {
                return Err(RecordFieldReason::CandidateSeqMismatch);
            }
            if root.parent != base {
                return Err(RecordFieldReason::CandidateParentMismatch);
            }
            let candidate =
                RootBytes::new(candidate_bytes).map_err(|_| RecordFieldReason::Truncated)?;
            RecordBody::Decision {
                identity,
                root_seq,
                base,
                decided_at,
                candidate,
            }
        }
        TAG_ATTESTATION => {
            let stored_id = decode_id(&mut c)?;
            let final_bytes =
                decode_hex32(&mut c, super::ROOT_BYTES_MAX).map_err(RecordFieldReason::Hex)?;
            if stored_id != GrainId::of(&final_bytes) {
                return Err(RecordFieldReason::StoredIdMismatch);
            }
            let final_root =
                RootBytes::new(final_bytes).map_err(|_| RecordFieldReason::Truncated)?;
            RecordBody::Attestation {
                identity,
                stored_id,
                final_root,
            }
        }
        TAG_LANDED => RecordBody::Landed { identity },
        TAG_LOST => {
            let occupant_id = decode_id(&mut c)?;
            RecordBody::Lost {
                identity,
                occupant_id,
            }
        }
        _ => return Err(RecordFieldReason::UnknownTag),
    };
    c.finish().map_err(|_| RecordFieldReason::TrailingBytes)?;
    Ok(record_body)
}

/// One record parsed from raw record bytes, before its mark is even
/// considered. `check` is the record's own trailing 32 bytes, returned
/// separately so the caller can compare it against a mark's
/// `record_check` without recomputing it.
pub(crate) struct DecodedRecord {
    pub(crate) record: Record,
    pub(crate) version: u16,
    pub(crate) epoch: Epoch,
    pub(crate) check: [u8; 32],
    /// Total bytes consumed from the record's start (header + body +
    /// check) — NOT including the mark that must immediately follow.
    pub(crate) consumed: usize,
}

/// Parse one record — header, body, check — from the front of `bytes`.
/// `None` covers every way a pair can fail to be "accepted": too
/// short, an over-cap `body_len`, a check mismatch, or a body that
/// does not decode strictly. The caller (`classify`) still owes
/// the version/epoch-match and the following-mark checks.
///
pub(crate) fn decode_record(bytes: &[u8], volume: &VolumeName) -> Option<DecodedRecord> {
    if bytes.len() < RECORD_FIXED_LEN {
        return None;
    }
    let mut c = Cursor::new(bytes);
    let tag = c.u8().ok()?;
    let version = c.u16().ok()?;
    let epoch_bytes = c.take(super::EPOCH_LEN).ok()?;
    let epoch = Epoch::from_bytes(epoch_bytes.try_into().ok()?);
    let seq = c.u64().ok()?;
    let body_len_u32 = c.u32().ok()?;
    let body_len = usize::try_from(body_len_u32).ok()?;
    if body_len > RECORD_BODY_MAX {
        return None;
    }
    let body = c.take(body_len).ok()?;
    let check_bytes = c.take(32).ok()?;
    let check: [u8; 32] = check_bytes.try_into().ok()?;

    // preimage = tag .. body, i.e. everything except the trailing check.
    let preimage_len = RECORD_FIXED_LEN.checked_sub(32)?.checked_add(body_len)?;
    let preimage = bytes.get(..preimage_len)?;
    let expected = blake3::derive_key(RECORD_CONTEXT, preimage);
    if check != expected {
        return None;
    }

    let body = decode_record_body(tag, body, volume).ok()?;
    let record = Record::new(seq, body).ok()?;
    let consumed = preimage_len.checked_add(32)?;
    Some(DecodedRecord {
        record,
        version,
        epoch,
        check,
        consumed,
    })
}

/// One decoded mark, before it is checked against any particular
/// record.
pub(crate) struct DecodedMark {
    pub(crate) epoch: Epoch,
    pub(crate) seq: u64,
    pub(crate) tag: u8,
    pub(crate) record_check: [u8; 32],
}

/// Decode a mark from exactly [`MARK_LEN`] bytes: `None` unless the
/// magic and the check both hold — "self-identifying" per the format
/// doc, so this is also the primitive the tail scan uses to search for
/// *any* valid mark regardless of what it names.
pub(crate) fn decode_mark(mark: &[u8]) -> Option<DecodedMark> {
    if mark.len() != MARK_LEN {
        return None;
    }
    let mut c = Cursor::new(mark);
    let magic = c.take(8).ok()?;
    if magic != MARK_MAGIC {
        return None;
    }
    let epoch_bytes = c.take(super::EPOCH_LEN).ok()?;
    let epoch = Epoch::from_bytes(epoch_bytes.try_into().ok()?);
    let seq = c.u64().ok()?;
    let tag = c.u8().ok()?;
    let record_check_bytes = c.take(32).ok()?;
    let record_check: [u8; 32] = record_check_bytes.try_into().ok()?;
    let check_bytes = c.take(32).ok()?;
    let check_arr: [u8; 32] = check_bytes.try_into().ok()?;

    let preimage = mark.get(..65)?;
    let expected = blake3::derive_key(MARK_CONTEXT, preimage);
    if check_arr != expected {
        return None;
    }
    Some(DecodedMark {
        epoch,
        seq,
        tag,
        record_check,
    })
}

/// Does a valid mark — magic and check alone, whatever it names —
/// begin anywhere in `haystack`? The classifier uses this scan on the
/// remaining tail. It also checks for a mark before accepting a short
/// file with no complete envelope as an interrupted initial write.
/// Lengths inside `haystack` are never used, only a byte-by-byte
/// scan for the mark's own self-identifying shape.
pub(crate) fn contains_valid_mark(haystack: &[u8]) -> bool {
    if haystack.len() < MARK_LEN {
        return false;
    }
    // `haystack.len() - MARK_LEN` cannot underflow: the guard above
    // proved `haystack.len() >= MARK_LEN`.
    let last_start = haystack.len() - MARK_LEN;
    (0..=last_start).any(|start| {
        start
            .checked_add(MARK_LEN)
            .and_then(|end| haystack.get(start..end))
            .is_some_and(|window| decode_mark(window).is_some())
    })
}

/// A whole envelope's parse outcome that is *not* "not whole at all" —
/// `classify` still needs to tell "unknown version" and "malformed v1
/// body" apart from a genuinely absent/torn envelope.
pub(crate) enum WholeEnvelope {
    Ok { envelope: Envelope, len: usize },
    UnknownVersion { version: u16 },
    Malformed,
}

fn decode_v1_body(body: &[u8]) -> Option<(VolumeName, Epoch)> {
    let mut c = Cursor::new(body);
    let name_len = usize::from(c.u8().ok()?);
    let name_bytes = c.take(name_len).ok()?;
    let volume = VolumeName::from_bytes(name_bytes).ok()?;
    let epoch_bytes = c.take(super::EPOCH_LEN).ok()?;
    let epoch = Epoch::from_bytes(epoch_bytes.try_into().ok()?);
    c.finish().ok()?;
    Some((volume, epoch))
}

/// Try to read a **whole** envelope from the front of `bytes`: magic, a
/// `length` in bounds, at least `length` bytes, and a check that holds.
/// `None` means not whole at all — the caller decides "no envelope"
/// vs. "damaged" from there.
///
pub(crate) fn try_whole_envelope(bytes: &[u8]) -> Option<WholeEnvelope> {
    let magic = bytes.get(..8)?;
    if magic != super::ENVELOPE_MAGIC {
        return None;
    }
    let version_bytes = bytes.get(8..10)?;
    let version = u16::from_be_bytes(version_bytes.try_into().ok()?);
    let length_bytes = bytes.get(10..12)?;
    let length = u16::from_be_bytes(length_bytes.try_into().ok()?);
    if !(ENVELOPE_LENGTH_MIN..=ENVELOPE_LENGTH_MAX).contains(&length) {
        return None;
    }
    let length = usize::from(length);
    let whole = bytes.get(..length)?;
    let split_at = length.checked_sub(32)?;
    let (signed, check_bytes) = whole.split_at(split_at);
    let check_arr: [u8; 32] = check_bytes.try_into().ok()?;
    let expected = blake3::derive_key(ENVELOPE_CONTEXT, signed);
    if check_arr != expected {
        return None;
    }

    // WHOLE. Interpret version and body from here on.
    if version != super::VERSION {
        return Some(WholeEnvelope::UnknownVersion { version });
    }
    let body = whole.get(12..split_at)?;
    match decode_v1_body(body) {
        Some((volume, epoch)) => Some(WholeEnvelope::Ok {
            envelope: Envelope::new(volume, epoch),
            len: length,
        }),
        None => Some(WholeEnvelope::Malformed),
    }
}
