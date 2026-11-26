// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The recovery classifier checks an authority log's committed records
//! and any bytes that follow the last committed pair.
//! `classify` gives exactly one verdict for any byte string: no
//! envelope, a log (with its committed records and any tail to
//! discard), or a typed refusal. Linear in the input; never a panic.

use crate::root::VolumeName;

use super::codec::{
    DecodedMark, DecodedRecord, WholeEnvelope, contains_valid_mark, decode_mark, decode_record,
    try_whole_envelope,
};
use super::grammar::{Grammar, GrammarRule};
use super::record::Record;
use super::{ENVELOPE_V1_MAX, Envelope, MARK_LEN, RECORD_V1_MAX};

/// Where a [`LogError`] occurred: the byte offset into the input
/// `classify` was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogError {
    pub offset: usize,
    pub reason: LogErrorReason,
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "authority log refused at offset {}: {}",
            self.offset, self.reason
        )
    }
}

impl std::error::Error for LogError {}

/// Why `classify` refused. Every variant is a format-doc-named
/// refusal; a bad record's OWN reason (a reserved or unknown tag,
/// non-canonical hex, a cross-field mismatch, ...) is never
/// distinguished here — it is
/// folded into whichever of these applies once the surrounding
/// commit-evidence question ("does a mark commit it?") is answered.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogErrorReason {
    /// A whole envelope named a version other than [`super::VERSION`].
    UnknownVersion { version: u16 },
    /// A whole, version-1 envelope's body did not decode strictly.
    EnvelopeMalformed,
    /// A whole, valid v1 envelope named a different volume.
    WrongVolume,
    /// Bytes at or after `offset` are committed history a correct
    /// writer could not have left damaged: the file is longer than a
    /// v1 envelope can ever be and starts with no whole envelope
    /// (offset 0); or, at the tail's start, a valid mark exists in what
    /// would otherwise be a discarded tail, the tail leads with a
    /// check-valid record of this epoch that is not the legal next
    /// record, or the tail is longer than one interrupted append can
    /// leave.
    DamagedCommittedHistory,
    /// The committed log broke one of the seven grammar rules.
    Grammar(GrammarRule),
}

impl std::fmt::Display for LogErrorReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVersion { version } => write!(f, "unknown envelope version {version}"),
            Self::EnvelopeMalformed => write!(f, "envelope body does not decode strictly"),
            Self::WrongVolume => write!(f, "envelope names a different volume"),
            Self::DamagedCommittedHistory => write!(f, "damaged committed history"),
            Self::Grammar(rule) => write!(f, "grammar violation: {rule}"),
        }
    }
}

/// `classify`'s verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// The file holds no whole envelope and no valid mark, and is no
    /// longer than a v1 envelope can ever be — what an interrupted
    /// initialise can leave. Does not prove nothing was ever committed.
    NoEnvelope,
    /// A valid envelope for the asked-for volume, its committed records
    /// in order, and the split between the committed prefix and a tail
    /// to discard. `committed_len + tail_len` always equals the input's
    /// length.
    Log {
        envelope: Envelope,
        records: Vec<Record>,
        committed_len: usize,
        tail_len: usize,
    },
}

fn grammar_err(offset: usize, rule: GrammarRule) -> LogError {
    LogError {
        offset,
        reason: LogErrorReason::Grammar(rule),
    }
}

struct PairAccepted {
    record: Record,
    consumed: usize,
}

/// Try to accept one record+mark pair starting at `pos`.
/// Return `None` whenever the pair cannot be accepted: a torn or
/// damaged record, a version/epoch mismatch,
/// a body that fails to decode strictly, an
/// absent/torn mark, or a mark that does not name this exact record —
/// and `pos` becomes the tail's start.
fn try_pair(bytes: &[u8], pos: usize, envelope: &Envelope) -> Option<PairAccepted> {
    let rest = bytes.get(pos..)?;
    let decoded = decode_record(rest, envelope.volume())?;
    if decoded.version != envelope.version() || decoded.epoch != envelope.epoch() {
        return None;
    }
    let mark_start = pos.checked_add(decoded.consumed)?;
    let mark_end = mark_start.checked_add(MARK_LEN)?;
    let mark_bytes = bytes.get(mark_start..mark_end)?;
    let DecodedMark {
        epoch: mark_epoch,
        seq: mark_seq,
        tag: mark_tag,
        record_check,
    } = decode_mark(mark_bytes)?;
    if mark_epoch != envelope.epoch()
        || mark_seq != decoded.record.seq()
        || mark_tag != decoded.record.body().tag()
        || record_check != decoded.check
    {
        return None;
    }
    let consumed = decoded.consumed.checked_add(MARK_LEN)?;
    Some(PairAccepted {
        record: decoded.record,
        consumed,
    })
}

/// Does the tail begin with a COMPLETE record
/// of this log's own version and epoch,
/// whose check holds and whose body
/// decodes strictly by its tag? `None` covers every way it does not —
/// short, a check mismatch, a body that fails to decode, or a version
/// or epoch that differs — the same "not accepted" shape [`try_pair`]
/// uses for a pair, reused here because a record this decodes was
/// synced before any mark byte could follow it, whatever the mark
/// search finds or fails to find.
fn tail_leads_with_same_epoch_record(
    bytes: &[u8],
    pos: usize,
    envelope: &Envelope,
) -> Option<DecodedRecord> {
    let rest = bytes.get(pos..)?;
    let decoded = decode_record(rest, envelope.volume())?;
    if decoded.version != envelope.version() || decoded.epoch != envelope.epoch() {
        return None;
    }
    Some(decoded)
}

/// Bound what one interrupted append can leave in a mark-free tail.
/// Use the committed records to decide whether its leading record could
/// legally follow them. `state` is the committed prefix's
/// grammar state after every accepted pair — exactly what a genuine
/// next record must satisfy. The candidate is only checked against it,
/// never applied: it is not a committed record, whichever way this
/// returns.
///
/// - A tail leading with a complete record of this version and epoch
///   must be the LEGAL NEXT record under the grammar, and the tail must be no
///   longer than that record's own length plus [`MARK_LEN`]. Either
///   failing refuses; there is no fallback to the bound below.
/// - Otherwise the tail must be no longer than [`RECORD_V1_MAX`], the
///   largest record legal under the v1 grammar.
fn check_tail_bound(
    bytes: &[u8],
    pos: usize,
    envelope: &Envelope,
    state: &Grammar,
) -> Result<(), LogError> {
    let tail_len = bytes.len().saturating_sub(pos);
    let bound = match tail_leads_with_same_epoch_record(bytes, pos, envelope) {
        Some(decoded) => {
            if state.check(&decoded.record).is_err() {
                return Err(LogError {
                    offset: pos,
                    reason: LogErrorReason::DamagedCommittedHistory,
                });
            }
            decoded.consumed.checked_add(MARK_LEN)
        }
        None => Some(RECORD_V1_MAX),
    };
    if bound.is_some_and(|bound| tail_len <= bound) {
        Ok(())
    } else {
        Err(LogError {
            offset: pos,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    }
}

fn parse_envelope(bytes: &[u8], want: &VolumeName) -> Result<Option<(Envelope, usize)>, LogError> {
    match try_whole_envelope(bytes) {
        Some(WholeEnvelope::Ok { envelope, len }) => {
            if envelope.volume() != want {
                return Err(LogError {
                    offset: 0,
                    reason: LogErrorReason::WrongVolume,
                });
            }
            Ok(Some((envelope, len)))
        }
        Some(WholeEnvelope::UnknownVersion { version }) => Err(LogError {
            offset: 0,
            reason: LogErrorReason::UnknownVersion { version },
        }),
        Some(WholeEnvelope::Malformed) => Err(LogError {
            offset: 0,
            reason: LogErrorReason::EnvelopeMalformed,
        }),
        None => {
            if bytes.len() <= ENVELOPE_V1_MAX && !contains_valid_mark(bytes) {
                Ok(None)
            } else {
                Err(LogError {
                    offset: 0,
                    reason: LogErrorReason::DamagedCommittedHistory,
                })
            }
        }
    }
}

/// `classify(bytes, volume)`: exactly one verdict for any byte string.
/// Linear in `bytes.len()` — one pass over the pairs, at most one tail
/// scan — and never panics.
///
/// # Errors
/// [`LogError`] naming the violated rule and the byte offset it was
/// found at.
pub fn classify(bytes: &[u8], volume: &VolumeName) -> Result<Classified, LogError> {
    let Some((envelope, env_len)) = parse_envelope(bytes, volume)? else {
        return Ok(Classified::NoEnvelope);
    };

    let mut pos = env_len;
    let mut records = Vec::new();
    let mut state = Grammar::new();
    while let Some(pair) = try_pair(bytes, pos, &envelope) {
        state
            .apply(&pair.record)
            .map_err(|rule| grammar_err(pos, rule))?;
        records.push(pair.record);
        let Some(next) = pos.checked_add(pair.consumed) else {
            break;
        };
        pos = next;
    }

    let tail = bytes.get(pos..).unwrap_or_default();
    if contains_valid_mark(tail) {
        return Err(LogError {
            offset: pos,
            reason: LogErrorReason::DamagedCommittedHistory,
        });
    }
    check_tail_bound(bytes, pos, &envelope, &state)?;

    let committed_len = pos;
    // `bytes.len() >= pos` always: `pos` only ever advances by bytes
    // `try_pair` proved present in `bytes`, starting from `env_len <=
    // bytes.len()` (the envelope parse already proved that much).
    let tail_len = bytes.len().saturating_sub(committed_len);
    Ok(Classified::Log {
        envelope,
        records,
        committed_len,
        tail_len,
    })
}
