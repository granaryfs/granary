// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Publish field parsing and the exhaustive engine-to-wire conversion.

use crate::ValidationError;
use crate::authority::{self, Answer, InvalidCandidate};
use crate::wire::{Outcome, PublishConflict, PublishRefusal};
use granary_core::authlog::{Epoch, Operation};
use granary_core::authority_answer::{self as codec, PublishAnswer};
use hyper::HeaderMap;

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn field(headers: &HeaderMap, name: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    let mut values = headers.get_all(name).iter();
    let raw = values.next()?.as_bytes();
    let start = raw
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(raw.len());
    let value = raw.get(start..)?;
    let end = value
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(0, |n| n.saturating_add(1));
    let value = value.get(..end)?;
    if values.next().is_some() || value.len() < min || value.len() > max || value.len() % 2 != 0 {
        return None;
    }

    value
        .chunks_exact(2)
        .map(|pair| {
            let [a, b] = pair else {
                return None;
            };
            Some(nibble(*a)? * 16 + nibble(*b)?)
        })
        .collect()
}

pub(super) fn fields(headers: &HeaderMap) -> Option<(Epoch, Operation)> {
    let operation = Operation::new(field(headers, "granary-operation", 2, 510)?).ok()?;
    let epoch = Epoch::from_bytes(field(headers, "granary-epoch", 32, 32)?.try_into().ok()?);
    Some((epoch, operation))
}

fn position(p: authority::Position) -> codec::Position {
    codec::Position {
        epoch: p.epoch,
        entry_seq: p.seq,
    }
}
fn receipt(r: authority::Receipt) -> codec::Receipt {
    codec::Receipt {
        position: position(r.position),
        root_seq: r.seq,
        stored_id: r.stored_id,
    }
}
fn head(h: authority::VerifiedHead) -> codec::Head {
    codec::Head {
        root: h.head.map(|h| (h.head_seq, h.head_id)),
        next_seq: h.next_seq,
    }
}

pub(crate) fn outcome(answer: &Answer) -> Outcome {
    let typed = match answer {
        Answer::Landed {
            receipt: r,
            head: h,
        } => PublishAnswer::Landed {
            receipt: receipt(*r),
            head: h.map(head),
        },
        Answer::Lost {
            position: p,
            candidate_id,
            occupant,
            head: h,
        } => PublishAnswer::Lost {
            position: position(*p),
            candidate_id: *candidate_id,
            occupant: *occupant,
            head: h.map(head),
        },
        Answer::Accepted {
            position: p,
            candidate_id,
        } => PublishAnswer::Accepted {
            position: position(*p),
            candidate_id: *candidate_id,
        },
        Answer::Open {
            position: p,
            candidate_id,
        } => PublishAnswer::Open {
            position: position(*p),
            candidate_id: *candidate_id,
        },
        Answer::StaleBase { head: h } => PublishAnswer::StaleBase(head(*h)),
        Answer::OperationBound(bound) => PublishAnswer::OperationBound(match bound {
            authority::Bound::Open {
                position: p,
                candidate_id,
            } => codec::Bound::Open {
                position: position(*p),
                candidate_id: *candidate_id,
            },
            authority::Bound::Landed(r) => codec::Bound::Landed(receipt(*r)),
        }),
        Answer::NotDecided {
            position: p,
            candidate_id,
        } => PublishAnswer::NotDecided {
            position: position(*p),
            candidate_id: *candidate_id,
        },
        Answer::EpochMismatch { epoch, head: h } => PublishAnswer::EpochMismatch {
            epoch: *epoch,
            head: h.map(head),
        },
        Answer::VolumeDamaged => PublishAnswer::VolumeDamaged,
        Answer::Validation(error) => return Outcome::publish_refused(validation_refusal(*error)),
        Answer::InvalidCandidate(
            InvalidCandidate::Root(_) | InvalidCandidate::SeqOutOfRange { .. },
        ) => return Outcome::publish_refused(PublishRefusal::InvalidCandidate),
        Answer::InvalidCandidate(InvalidCandidate::TooLong) => {
            return Outcome::publish_refused(PublishRefusal::TooLarge);
        }
        Answer::NoLog => return Outcome::publish_refused(PublishRefusal::NoLog),
        Answer::UnconfiguredVolume => {
            return Outcome::publish_refused(PublishRefusal::UnknownVolume);
        }
        Answer::Fenced => return Outcome::publish_refused(PublishRefusal::Fenced),
        Answer::Stopped => return Outcome::publish_refused(PublishRefusal::Stopped),
    };
    let Ok(bytes) = codec::encode(typed) else {
        return Outcome::publish_refused(PublishRefusal::Internal);
    };
    match typed {
        PublishAnswer::Landed { .. } | PublishAnswer::Lost { .. } => {
            Outcome::publish_settled(bytes)
        }
        PublishAnswer::Accepted { .. } | PublishAnswer::Open { .. } => {
            Outcome::publish_pending(bytes)
        }
        PublishAnswer::StaleBase(_) => Outcome::publish_conflict(PublishConflict::StaleBase, bytes),
        PublishAnswer::OperationBound(_) => {
            Outcome::publish_conflict(PublishConflict::OperationBound, bytes)
        }
        PublishAnswer::NotDecided { .. } => {
            Outcome::publish_conflict(PublishConflict::NotDecided, bytes)
        }
        PublishAnswer::EpochMismatch { .. } => {
            Outcome::publish_conflict(PublishConflict::EpochMismatch, bytes)
        }
        PublishAnswer::VolumeDamaged => {
            Outcome::publish_conflict(PublishConflict::VolumeDamaged, bytes)
        }
    }
}

fn validation_refusal(error: ValidationError) -> PublishRefusal {
    match error {
        ValidationError::MissingReference => PublishRefusal::MissingReference,
        ValidationError::InvalidReference => PublishRefusal::InvalidReference,
        ValidationError::WorkLimit | ValidationError::LengthLimit => {
            PublishRefusal::PublishWorkLimit
        }
        ValidationError::Unavailable => PublishRefusal::Unavailable,
    }
}
