// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Authority log format v1: the
//! authority's durable order of decisions, attestations and outcomes
//! for one volume's one epoch. Pure encode/decode/classify logic — no
//! I/O, no clock, no tokio. The server adapter implements
//! [`crate::decisionlog::DecisionLog`] and handles file I/O,
//! syncing and truncation.
//!
//! V1 uses fixed-width big-endian integers without varints or sentinels.
//! Decoding is strict, and the encoder refuses every value the decoder
//! would refuse. For unambiguous recovery,
//! every submitter-chosen byte string is stored as lowercase hex text,
//! which keeps a mark from ever being plantable inside a
//! record.
//!
//! # The file
//!
//! ```text
//! envelope
//! { record  mark }*          the committed log
//! tail                       bytes after the last complete pair, if any
//! ```
//!
//! [`classify`] is the recovery classifier: `bytes in, verdict out`,
//! never a panic, linear in the input.
//!
//! # Module layout
//!
//! - the hex canonical encoding and the bounded byte-string newtypes
//!   ([`Tenant`], [`Principal`], [`Operation`], [`RootBytes`]) plus
//!   [`SubmissionIdentity`], the record bodies' shared prefix.
//! - the record registry ([`RecordBody`], [`Record`]).
//! - the wire codec: [`encode_envelope`] and [`encode_append`], plus
//!   the decode primitives [`classify`] drives.
//! - the committed log's grammar ([`Grammar`]), shared by the recovery
//!   classifier and the authority engine.
//! - the recovery classifier.

mod classify;
mod codec;
mod grammar;
mod record;
mod submission;

#[cfg(test)]
mod tests;

pub use classify::{Classified, LogError, LogErrorReason, classify};
/// The pieces a hand-built committed pair needs, exposed to the crate's
/// test kit only: it builds a pair under the reserved tag, which
/// [`encode_append`] never writes.
pub(crate) use codec::build_mark;
pub use codec::{Append, EncodeRecordError, EncodedEnvelope, encode_append, encode_envelope};
/// The body codec, exposed to the crate's fuzz probe only: random bytes
/// almost never carry two valid checks and a valid root, so the probe
/// also drives the body decoder directly.
pub(crate) use codec::{decode_record_body, encode_record_body};
pub use grammar::{Grammar, GrammarRule};
pub use record::{Record, RecordBody, SeqZeroError};
pub(crate) use submission::encode_hex16;
pub use submission::{
    BoundedBytesError, OPERATION_MAX, Operation, PRINCIPAL_MAX, Principal, ROOT_BYTES_MAX,
    RootBytes, SubmissionIdentity, TENANT_MAX, Tenant,
};

use crate::hash::GRAIN_ID_BINARY_LEN;
use crate::root::VolumeName;

/// The format version every object this module writes carries.
pub const VERSION: u16 = 1;

/// The envelope's outer-frame magic.
pub const ENVELOPE_MAGIC: [u8; 8] = *b"GRNALOG\0";
/// A mark's magic.
pub const MARK_MAGIC: [u8; 8] = *b"GRNCOMIT";

/// The envelope outer frame's fixed length: magic(8) + version(2) +
/// length(2) + check(32).
pub(crate) const ENVELOPE_OUTER_LEN: usize = 8 + 2 + 2 + 32;
/// `length`'s own bound — generic across every version the outer frame
/// could ever carry, not just v1's.
pub(crate) const ENVELOPE_LENGTH_MIN: u16 = 44;
pub(crate) const ENVELOPE_LENGTH_MAX: u16 = 4096;
/// 16-byte epoch field length.
pub const EPOCH_LEN: usize = 16;
/// A v1 envelope's widest legal length: `44 + 1 + 63 + 16`.
pub const ENVELOPE_V1_MAX: usize = ENVELOPE_OUTER_LEN + 1 + 63 + EPOCH_LEN;

/// A record's fixed (non-body) length: tag(1) + version(2) + epoch(16)
/// + seq(8) + `body_len(4)` + check(32).
pub(crate) const RECORD_FIXED_LEN: usize = 1 + 2 + EPOCH_LEN + 8 + 4 + 32;
/// A defensive 262,144-byte body cap, checked before allocation.
/// The largest field-valid attestation body is 134,216 bytes: identity
/// (3,107), stored id (33), and final hex32 (4 + 131,072). The grammar
/// requires final bytes to equal the decision's root candidate, so
/// [`RECORD_V1_MAX`] bounds the largest grammar-valid whole record at
/// 4,642 bytes. Neither maximum reaches this defensive cap.
pub const RECORD_BODY_MAX: usize = 262_144;
/// A mark's fixed length: magic(8) + epoch(16) + seq(8) + tag(1) +
/// `record_check(32)` + check(32).
pub const MARK_LEN: usize = 8 + EPOCH_LEN + 8 + 1 + 32 + 32;

/// The three BLAKE3 derive-key contexts the format names.
pub(crate) const ENVELOPE_CONTEXT: &str = "granary authority-log envelope";
pub(crate) const RECORD_CONTEXT: &str = "granary authority-log record v1";
pub(crate) const MARK_CONTEXT: &str = "granary authority-log mark v1";

const _: () = assert!(MARK_LEN == 97);

/// The submission identity's length at every field's cap: three hex16
/// fields (`tenant`, `principal`, `operation`) plus `candidate_id`.
/// Shared by [`RECORD_BODY_MAX`]'s own bound and by [`RECORD_V1_MAX`],
/// so the two never derive it twice and drift apart.
const IDENTITY_V1_MAX: usize = (2 + 2 * submission::TENANT_MAX)
    + (2 + 2 * submission::PRINCIPAL_MAX)
    + (2 + 2 * submission::OPERATION_MAX)
    + GRAIN_ID_BINARY_LEN;

/// A conservative allocation-size calculation: a decision-shaped body
/// with every identity field at its cap and a root field at
/// [`submission::ROOT_BYTES_MAX`] still fits [`RECORD_BODY_MAX`]. This
/// shape is not field-valid: a decision's candidate must decode as a
/// root. The largest field-valid body is the 134,216-byte attestation;
/// [`RECORD_V1_MAX`] bounds the largest grammar-valid whole record.
const _: () = {
    let decision_extra = 8 // root_seq
        + (1 + GRAIN_ID_BINARY_LEN) // base, present
        + 12 // decided_at
        + (4 + 2 * submission::ROOT_BYTES_MAX); // candidate, hex32
    let max_decision_body = IDENTITY_V1_MAX + decision_extra;
    assert!(max_decision_body <= RECORD_BODY_MAX);
};

/// The largest record legal under the v1 grammar. [`classify()`] uses
/// this size to bound a mark-free tail when it cannot decode a complete
/// record of this version and epoch at the start of the tail. The maximum is a
/// decision whose identity fields are all at their caps and whose
/// candidate is the largest bytes a v1 root ever decodes from —
/// [`crate::root::ROOT_V1_MAX_ENCODABLE`] bytes, as a `hex32` field (a
/// length plus twice as many hex characters). Every other legal record
/// is shorter: an attestation's final bytes may encode up to
/// `ROOT_BYTES_MAX`, but the grammar requires them to be the decision's
/// candidate, so the decision bounds them all. `RECORD_FIXED_LEN`
/// (63) + identity (3,107) + `root_seq` (8) + `base` present (34) +
/// `decided_at` (12) + `candidate` hex32 (4 + 2 ×
/// `ROOT_V1_MAX_ENCODABLE`) = 4,642, pinned by the assertion below and
/// by a test that encodes this exact record and asserts its length. A new root algorithm or a longer signature slot moves
/// [`crate::root::ROOT_V1_MAX_ENCODABLE`] and this constant with it — a
/// reader older than the writer then refuses a crashed tail it cannot
/// bound rather than discard one it should not.
pub const RECORD_V1_MAX: usize = RECORD_FIXED_LEN
    + IDENTITY_V1_MAX
    + 8 // root_seq
    + (1 + GRAIN_ID_BINARY_LEN) // base, present
    + 12 // decided_at
    + (4 + 2 * crate::root::ROOT_V1_MAX_ENCODABLE); // candidate, hex32

const _: () = assert!(RECORD_V1_MAX == 4642);

/// A 128-bit opaque epoch: "a value naming one continuous life of a
/// volume's log" (spec §2), drawn from the engine's cryptographic-
/// randomness seam ([`crate::secure_random::SecureRandom`]) when
/// initialise creates a missing log. Format-opaque — this module compares epochs for
/// equality and carries them, never interprets their bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch([u8; EPOCH_LEN]);

impl Epoch {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EPOCH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; EPOCH_LEN] {
        self.0
    }
}

/// The envelope identifies the version, volume and epoch.
/// Every v1 value carries [`VERSION`] — there is no other
/// version to construct, so the field is not stored redundantly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    volume: VolumeName,
    epoch: Epoch,
}

/// The volume a whole, valid v1 envelope at the front of `bytes`
/// names, if it has one — independent of any particular volume a
/// caller might classify against. `testkit::authlog_classify_probe`
/// uses this to also run [`classify`] against the input's own declared
/// volume, not only a fixed one, so a fuzzer's mutation of the volume
/// name field is exercised on the path where it actually matches.
/// `pub(crate)`: the crate's own fuzz probe is its only consumer.
#[must_use]
pub(crate) fn envelope_volume(bytes: &[u8]) -> Option<VolumeName> {
    match codec::try_whole_envelope(bytes) {
        Some(codec::WholeEnvelope::Ok { envelope, .. }) => Some(envelope.volume().clone()),
        _ => None,
    }
}

impl Envelope {
    #[must_use]
    pub const fn new(volume: VolumeName, epoch: Epoch) -> Self {
        Self { volume, epoch }
    }

    #[must_use]
    pub const fn volume(&self) -> &VolumeName {
        &self.volume
    }

    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        VERSION
    }
}
