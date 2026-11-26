// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical publish answers and volume statuses.
//! These values describe wire evidence, not server authority or HTTP policy.

use crate::authlog::Epoch;
use crate::encoding::{Cursor, DecodeError};
use crate::hash::GrainId;

/// Publish answer magic.
pub const MAGIC: [u8; 8] = *b"GRNANSWR";
/// The wire version.
pub const VERSION: u16 = 1;
/// Largest publish answer, including its header.
pub const MAX_BYTES: usize = 153;

/// Volume status magic.
pub const STATUS_MAGIC: [u8; 8] = *b"GRNVSTAT";
/// Largest volume status, including its header.
pub const STATUS_V1_MAX: usize = 120;

/// An open decision in the enclosing volume status's epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenPosition {
    /// Nonzero log entry sequence, not a root sequence.
    pub entry_seq: u64,
    /// Identifier of the candidate bytes.
    pub candidate_id: GrainId,
}

/// The public volume status. An absent head is unknown, not verified empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeStatus {
    /// The recovered or successfully initialised log's epoch.
    pub epoch: Epoch,
    /// Last completed head verification, absent after failure or before any verification.
    pub head: Option<Head>,
    /// The committed open decision, if any.
    pub open: Option<OpenPosition>,
}

/// The highest candidate sequence (publication-authority spec §3 rule 2).
/// Its successor, `u64::MAX - 1`, is the highest publishable root sequence;
/// no store selects `u64::MAX` as a head.
pub const LAST_CANDIDATE_SEQ: u64 = u64::MAX - 2;

/// The candidate sequence above `head`: 1 for an empty chain, or its
/// successor while that sequence is at most [`LAST_CANDIDATE_SEQ`].
#[must_use]
pub fn next_seq(head: Option<u64>) -> Option<u64> {
    match head {
        None => Some(1),
        Some(head) => head
            .checked_add(1)
            .filter(|next| *next <= LAST_CANDIDATE_SEQ),
    }
}

/// A decision's location in a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// Opaque log epoch.
    pub epoch: Epoch,
    /// Nonzero entry sequence.
    pub entry_seq: u64,
}

/// A landed candidate's receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    /// Decision location.
    pub position: Position,
    /// Published sequence, in `1..u64::MAX`.
    pub root_seq: u64,
    /// Identifier of the stored bytes.
    pub stored_id: GrainId,
}

/// A verified chain head and its explicitly encoded successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// Sequence and stored identifier; absent for a verified empty chain.
    pub root: Option<(u64, GrainId)>,
    /// Candidate sequence, constrained by the head.
    pub next_seq: Option<u64>,
}

impl Head {
    /// Construct the successor dictated by `root`.
    #[must_use]
    pub fn new(root: Option<(u64, GrainId)>) -> Self {
        Self {
            root,
            next_seq: next_seq(root.map(|(seq, _)| seq)),
        }
    }
}

/// The candidate to which an operation is bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// A durable decision whose publication is open.
    Open {
        /// Decision location.
        position: Position,
        /// Candidate identifier.
        candidate_id: GrainId,
    },
    /// A published candidate.
    Landed(Receipt),
}

/// The nine registered publish answer kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishAnswer {
    /// Kind 1: published, with optional current verified head.
    Landed {
        receipt: Receipt,
        head: Option<Head>,
    },
    /// Kind 2: another valid root took the candidate's sequence.
    Lost {
        position: Position,
        candidate_id: GrainId,
        occupant: GrainId,
        head: Option<Head>,
    },
    /// Kind 3: a new durable decision.
    Accepted {
        position: Position,
        candidate_id: GrainId,
    },
    /// Kind 4: this candidate's publication is open.
    Open {
        position: Position,
        candidate_id: GrainId,
    },
    /// Kind 5: the candidate does not extend this verified head.
    StaleBase(Head),
    /// Kind 6: the operation is bound to another candidate.
    OperationBound(Bound),
    /// Kind 7: another operation is open.
    NotDecided {
        position: Position,
        candidate_id: GrainId,
    },
    /// Kind 8: the current epoch differs from the submitted epoch.
    EpochMismatch { epoch: Epoch, head: Option<Head> },
    /// Kind 9: the chain did not verify.
    VolumeDamaged,
}

impl PublishAnswer {
    /// The stable kind discriminant.
    #[must_use]
    pub const fn kind(self) -> u8 {
        match self {
            Self::Landed { .. } => 1,
            Self::Lost { .. } => 2,
            Self::Accepted { .. } => 3,
            Self::Open { .. } => 4,
            Self::StaleBase(_) => 5,
            Self::OperationBound(_) => 6,
            Self::NotDecided { .. } => 7,
            Self::EpochMismatch { .. } => 8,
            Self::VolumeDamaged => 9,
        }
    }
}

/// A strict answer decoding or encoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No complete matching eight-byte magic.
    BadMagic,
    /// Unsupported wire version, distinct from malformed fields.
    UnknownVersion(u16),
    /// Unregistered publish kind.
    UnknownKind(u8),
    /// Truncation, invalid fields or trailing bytes.
    Fields(DecodeError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => f.write_str("bad authority answer magic"),
            Self::UnknownVersion(v) => write!(f, "unknown authority answer version {v}"),
            Self::UnknownKind(k) => write!(f, "unknown authority answer kind {k}"),
            Self::Fields(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Self::Fields(e)
    }
}

fn invalid(what: &'static str) -> DecodeError {
    DecodeError::Invalid { what }
}
fn root_seq(seq: u64) -> Result<u64, DecodeError> {
    if seq == 0 || seq == u64::MAX {
        return Err(invalid("root sequence"));
    }
    Ok(seq)
}
fn presence(c: &mut Cursor<'_>) -> Result<bool, DecodeError> {
    match c.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("presence")),
    }
}
fn epoch(c: &mut Cursor<'_>) -> Result<Epoch, DecodeError> {
    Ok(Epoch::from_bytes(
        c.take(16)?.try_into().map_err(|_| DecodeError::Truncated)?,
    ))
}
fn id(c: &mut Cursor<'_>) -> Result<GrainId, DecodeError> {
    GrainId::from_bytes(c.take(33)?).map_err(|_| invalid("grain id"))
}
fn position(c: &mut Cursor<'_>) -> Result<Position, DecodeError> {
    let epoch = epoch(c)?;
    let entry_seq = c.u64()?;
    Ok(Position { epoch, entry_seq })
}
fn receipt(c: &mut Cursor<'_>) -> Result<Receipt, DecodeError> {
    Ok(Receipt {
        position: position(c)?,
        root_seq: c.u64()?,
        stored_id: id(c)?,
    })
}
fn head(c: &mut Cursor<'_>) -> Result<Head, DecodeError> {
    let root = if presence(c)? {
        Some((c.u64()?, id(c)?))
    } else {
        None
    };
    let next_seq = if presence(c)? { Some(c.u64()?) } else { None };
    let value = Head { root, next_seq };
    Ok(value)
}
fn optional_head(c: &mut Cursor<'_>) -> Result<Option<Head>, DecodeError> {
    if presence(c)? {
        Ok(Some(head(c)?))
    } else {
        Ok(None)
    }
}

/// Decode exactly one bounded canonical answer. No allocation is required.
///
/// # Errors
/// Refuses unknown magic, version, kind, presence, bound or hash tags,
/// illegal sequences or successors, truncation, excess size and trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<PublishAnswer, Error> {
    let mut c = Cursor::new(bytes);
    if c.take(8).ok() != Some(MAGIC.as_slice()) {
        return Err(Error::BadMagic);
    }
    let version = c.u16()?;
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }
    let answer = match c.u8()? {
        1 => PublishAnswer::Landed {
            receipt: receipt(&mut c)?,
            head: optional_head(&mut c)?,
        },
        2 => PublishAnswer::Lost {
            position: position(&mut c)?,
            candidate_id: id(&mut c)?,
            occupant: id(&mut c)?,
            head: optional_head(&mut c)?,
        },
        3 => PublishAnswer::Accepted {
            position: position(&mut c)?,
            candidate_id: id(&mut c)?,
        },
        4 => PublishAnswer::Open {
            position: position(&mut c)?,
            candidate_id: id(&mut c)?,
        },
        5 => PublishAnswer::StaleBase(head(&mut c)?),
        6 => PublishAnswer::OperationBound(match c.u8()? {
            1 => Bound::Open {
                position: position(&mut c)?,
                candidate_id: id(&mut c)?,
            },
            2 => Bound::Landed(receipt(&mut c)?),
            _ => return Err(invalid("bound kind").into()),
        }),
        7 => PublishAnswer::NotDecided {
            position: position(&mut c)?,
            candidate_id: id(&mut c)?,
        },
        8 => PublishAnswer::EpochMismatch {
            epoch: epoch(&mut c)?,
            head: optional_head(&mut c)?,
        },
        9 => PublishAnswer::VolumeDamaged,
        kind => return Err(Error::UnknownKind(kind)),
    };
    validate(answer)?;
    c.finish()?;
    Ok(answer)
}

fn validate_position(p: Position) -> Result<(), DecodeError> {
    if p.entry_seq == 0 {
        return Err(invalid("entry sequence"));
    }
    Ok(())
}
fn validate_receipt(r: Receipt) -> Result<(), DecodeError> {
    validate_position(r.position)?;
    root_seq(r.root_seq)?;
    Ok(())
}
fn validate_head(h: Head) -> Result<(), DecodeError> {
    if let Some((seq, _)) = h.root {
        root_seq(seq)?;
    }
    if h != Head::new(h.root) {
        return Err(invalid("head successor"));
    }
    Ok(())
}
fn validate_optional(h: Option<Head>) -> Result<(), DecodeError> {
    h.map_or(Ok(()), validate_head)
}
fn validate(answer: PublishAnswer) -> Result<(), DecodeError> {
    match answer {
        PublishAnswer::Landed { receipt, head } => {
            validate_receipt(receipt)?;
            validate_optional(head)
        }
        PublishAnswer::Lost {
            position,
            candidate_id,
            occupant,
            head,
        } => {
            validate_position(position)?;
            validate_optional(head)?;
            if occupant == candidate_id {
                return Err(invalid("lost occupant"));
            }
            Ok(())
        }
        PublishAnswer::Accepted { position, .. }
        | PublishAnswer::Open { position, .. }
        | PublishAnswer::NotDecided { position, .. }
        | PublishAnswer::OperationBound(Bound::Open { position, .. }) => {
            validate_position(position)
        }
        PublishAnswer::OperationBound(Bound::Landed(receipt)) => validate_receipt(receipt),
        PublishAnswer::StaleBase(head) => validate_head(head),
        PublishAnswer::EpochMismatch { head, .. } => validate_optional(head),
        PublishAnswer::VolumeDamaged => Ok(()),
    }
}

fn put_position(out: &mut Vec<u8>, p: Position) {
    out.extend_from_slice(&p.epoch.to_bytes());
    out.extend_from_slice(&p.entry_seq.to_be_bytes());
}
fn put_receipt(out: &mut Vec<u8>, r: Receipt) {
    put_position(out, r.position);
    out.extend_from_slice(&r.root_seq.to_be_bytes());
    out.extend_from_slice(&r.stored_id.to_bytes());
}
fn put_head(out: &mut Vec<u8>, h: Head) {
    out.push(u8::from(h.root.is_some()));
    if let Some((seq, id)) = h.root {
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&id.to_bytes());
    }
    out.push(u8::from(h.next_seq.is_some()));
    if let Some(seq) = h.next_seq {
        out.extend_from_slice(&seq.to_be_bytes());
    }
}
fn put_optional_head(out: &mut Vec<u8>, h: Option<Head>) {
    out.push(u8::from(h.is_some()));
    if let Some(h) = h {
        put_head(out, h);
    }
}

/// Encode an answer using the same validation as the decoder.
///
/// # Errors
/// Refuses zero entry sequences, illegal root sequences and inconsistent
/// head successors. No invalid value can be emitted.
pub fn encode(answer: PublishAnswer) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(MAX_BYTES);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(answer.kind());
    match answer {
        PublishAnswer::Landed { receipt, head } => {
            put_receipt(&mut out, receipt);
            put_optional_head(&mut out, head);
        }
        PublishAnswer::Lost {
            position,
            candidate_id,
            occupant,
            head,
        } => {
            put_position(&mut out, position);
            out.extend_from_slice(&candidate_id.to_bytes());
            out.extend_from_slice(&occupant.to_bytes());
            put_optional_head(&mut out, head);
        }
        PublishAnswer::Accepted {
            position,
            candidate_id,
        }
        | PublishAnswer::Open {
            position,
            candidate_id,
        }
        | PublishAnswer::NotDecided {
            position,
            candidate_id,
        } => {
            put_position(&mut out, position);
            out.extend_from_slice(&candidate_id.to_bytes());
        }
        PublishAnswer::StaleBase(head) => put_head(&mut out, head),
        PublishAnswer::OperationBound(bound) => match bound {
            Bound::Open {
                position,
                candidate_id,
            } => {
                out.push(1);
                put_position(&mut out, position);
                out.extend_from_slice(&candidate_id.to_bytes());
            }
            Bound::Landed(receipt) => {
                out.push(2);
                put_receipt(&mut out, receipt);
            }
        },
        PublishAnswer::EpochMismatch { epoch, head } => {
            out.extend_from_slice(&epoch.to_bytes());
            put_optional_head(&mut out, head);
        }
        PublishAnswer::VolumeDamaged => {}
    }
    decode(&out)?;
    Ok(out)
}

fn validate_status(status: VolumeStatus) -> Result<(), DecodeError> {
    validate_optional(status.head)?;
    if let Some(open) = status.open {
        validate_position(Position {
            epoch: status.epoch,
            entry_seq: open.entry_seq,
        })?;
    }
    Ok(())
}

/// Decode exactly one volume status without allocation.
///
/// # Errors
/// Refuses wrong magic, unsupported versions, truncation, invalid presence or
/// identifier tags, invalid sequences or successors, and any trailing bytes.
pub fn decode_status(bytes: &[u8]) -> Result<VolumeStatus, Error> {
    let mut c = Cursor::new(bytes);
    if c.take(8).ok() != Some(STATUS_MAGIC.as_slice()) {
        return Err(Error::BadMagic);
    }
    let version = c.u16()?;
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }
    let epoch = epoch(&mut c)?;
    let head = optional_head(&mut c)?;
    let open = if presence(&mut c)? {
        Some(OpenPosition {
            entry_seq: c.u64()?,
            candidate_id: id(&mut c)?,
        })
    } else {
        None
    };
    let status = VolumeStatus { epoch, head, open };
    validate_status(status)?;
    c.finish()?;
    Ok(status)
}

/// Encode a volume status with the same field checks as the decoder.
///
/// # Errors
/// Refuses zero entry sequences, invalid head sequences and inconsistent successors.
pub fn encode_status(status: VolumeStatus) -> Result<Vec<u8>, Error> {
    validate_status(status)?;
    let mut out = Vec::with_capacity(STATUS_V1_MAX);
    out.extend_from_slice(&STATUS_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&status.epoch.to_bytes());
    put_optional_head(&mut out, status.head);
    out.push(u8::from(status.open.is_some()));
    if let Some(open) = status.open {
        out.extend_from_slice(&open.entry_seq.to_be_bytes());
        out.extend_from_slice(&open.candidate_id.to_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
