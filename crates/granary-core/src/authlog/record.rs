// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The v1 record registry defines the four record bodies,
//! the reserved tag that v1 rejects, and the record that attaches
//! a sequence position to each body.
//!
//! Every variant's extra fields (beyond [`SubmissionIdentity`]) are
//! `pub`, following the codebase's own precedent for a cross-field-
//! validated wire structure ([`crate::root::RootDoc`],
//! [`crate::sheaf::SheafDoc`], [`crate::sheaf::Timestamp`]): Rust gives
//! a `pub enum`'s variant fields no separate visibility, so a body that
//! is genuinely writable by a caller cannot also keep them private.
//! Validity is carried by the encoder/decoder pair instead — "the
//! encoder refuses every value the decoder would refuse."

use crate::hash::GrainId;
use crate::sheaf::Timestamp;

use super::submission::{RootBytes, SubmissionIdentity};

/// `0x01` — a decision.
pub(crate) const TAG_DECISION: u8 = 0x01;
/// `0x02` — an attestation.
pub(crate) const TAG_ATTESTATION: u8 = 0x02;
/// `0x03` — a landed outcome.
pub(crate) const TAG_LANDED: u8 = 0x03;
/// `0x04` — a lost outcome.
pub(crate) const TAG_LOST: u8 = 0x04;
/// `0x05` — reserved, never written by v1. Tags are never reused, so
/// no v1 body takes it, and a log holding it is committed history no
/// correct writer produces: the decoder refuses it.
///
pub(crate) const TAG_RESERVED_05: u8 = 0x05;

/// One record's body. Every variant carries the shared
/// [`SubmissionIdentity`] prefix; [`RecordBody::identity`] reaches
/// it without a match at every call site.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordBody {
    /// `0x01`. `candidate_id` (in `identity`) must be
    /// `GrainId::of(candidate)`, and `candidate` must decode as a root
    /// naming this volume, `root_seq` and `base` — enforced by both
    /// [`super::codec::encode_append`] and classification, never left
    /// to a caller.
    Decision {
        identity: SubmissionIdentity,
        /// 1–18446744073709551613.
        root_seq: u64,
        /// Absent iff `root_seq == 1`.
        base: Option<GrainId>,
        decided_at: Timestamp,
        candidate: RootBytes,
    },
    /// `0x02`. `stored_id` must be `GrainId::of(final_root)`.
    Attestation {
        identity: SubmissionIdentity,
        stored_id: GrainId,
        /// Wire field name `final` (a reserved word in Rust).
        final_root: RootBytes,
    },
    /// `0x03`. No payload beyond the identity.
    Landed { identity: SubmissionIdentity },
    /// `0x04`. `occupant_id` is the stored id of the valid root the
    /// classification read found.
    Lost {
        identity: SubmissionIdentity,
        occupant_id: GrainId,
    },
}

impl RecordBody {
    #[must_use]
    pub(crate) const fn tag(&self) -> u8 {
        match self {
            Self::Decision { .. } => TAG_DECISION,
            Self::Attestation { .. } => TAG_ATTESTATION,
            Self::Landed { .. } => TAG_LANDED,
            Self::Lost { .. } => TAG_LOST,
        }
    }

    /// Every variant's shared prefix.
    #[must_use]
    pub fn identity(&self) -> &SubmissionIdentity {
        match self {
            Self::Decision { identity, .. }
            | Self::Attestation { identity, .. }
            | Self::Landed { identity }
            | Self::Lost { identity, .. } => identity,
        }
    }
}

/// Why a [`Record`] could not be built. Sequence positions
/// start at 1. [`Record::new`] is the only constructor and
/// returns this error for position zero, so every constructed
/// record carries `seq >= 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqZeroError;

impl std::fmt::Display for SeqZeroError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "record seq is 0 (the entry sequence starts at 1)")
    }
}

impl std::error::Error for SeqZeroError {}

/// A committed log entry: a position's sequence number plus its body
/// (the epoch half of the position lives on the [`super::Envelope`]
/// shared by every record in the file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    seq: u64,
    body: RecordBody,
}

impl Record {
    /// # Errors
    /// [`SeqZeroError`] if `seq == 0`.
    pub fn new(seq: u64, body: RecordBody) -> Result<Self, SeqZeroError> {
        if seq == 0 {
            return Err(SeqZeroError);
        }
        Ok(Self { seq, body })
    }

    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub const fn body(&self) -> &RecordBody {
        &self.body
    }
}
