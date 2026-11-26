// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The submission identity and the hex canonical encoding.
//!
//!
//! Every variable-length byte string a submitter can choose — tenant,
//! principal, operation identity, and a root's candidate/final bytes —
//! is stored as lowercase hex text, never raw. This is the guard that
//! keeps a mark from ever being plantable inside a record (the format
//! doc's own threat-model section): outside these fields, no run of
//! bytes a submitter can choose reaches a mark's 97 — the longest is a
//! decision's root seq, base presence byte and base id, 42 bytes, and
//! the rest are hashes or the engine's own values — and every byte of
//! the mark magic lies outside the hex alphabet.
//!
//! The four bounded byte-string newtypes below cannot be built out of
//! bounds: their only constructor validates the length cap, so a value
//! that exists is already a value the wire encoding can carry.

use crate::encoding::Cursor;
use crate::hash::GrainId;

/// Raw-byte cap for [`Tenant`] (hex16-encoded).
pub const TENANT_MAX: usize = 255;
/// Raw-byte cap for [`Principal`] (hex16-encoded).
pub const PRINCIPAL_MAX: usize = 1024;
/// Raw-byte cap for [`Operation`] (hex16-encoded).
pub const OPERATION_MAX: usize = 255;
/// Raw-byte cap for [`RootBytes`] (hex32-encoded).
/// This is the log format's own ceiling for both a decision's
/// `candidate` and an attestation's `final`.
pub const ROOT_BYTES_MAX: usize = 65_536;

/// Every root a store's reader accepts must still be loggable: a widening
/// of [`crate::root::ROOT_MAX_BYTES`] past [`ROOT_BYTES_MAX`] would admit
/// roots this log format's root field could not carry. The direction is
/// ONE-WAY — this constant is free to sit above the root reader's
/// ceiling with room to spare — so widening the root reader's ceiling
/// past this constant is ALSO a change to this log format's accept set,
/// not something this assertion alone makes safe.
const _: () = assert!(crate::root::ROOT_MAX_BYTES <= ROOT_BYTES_MAX as u64);

/// The lowercase hex digit for one nibble (`0..=15`). Arithmetic rather
/// than a lookup table, so there is no array index to prove in bounds.
const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

/// Why a bounded byte-string field could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedBytesError {
    /// The raw byte string was empty (every field's minimum is 1 byte).
    Empty,
    /// The raw byte string was longer than the field's cap.
    TooLong { len: usize, max: usize },
}

impl std::fmt::Display for BoundedBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty field (minimum 1 byte)"),
            Self::TooLong { len, max } => write!(f, "{len} bytes exceeds the {max}-byte cap"),
        }
    }
}

impl std::error::Error for BoundedBytesError {}

fn check_bounds(len: usize, max: usize) -> Result<(), BoundedBytesError> {
    if len == 0 {
        return Err(BoundedBytesError::Empty);
    }
    if len > max {
        return Err(BoundedBytesError::TooLong { len, max });
    }
    Ok(())
}

/// The submitting tenant's bytes (hex16 on the wire, 1..=255 raw).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tenant(Vec<u8>);

/// The authenticated principal's bytes (hex16 on the wire, 1..=1024 raw).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal(Vec<u8>);

/// The client-chosen operation identity's bytes (hex16 on the wire, 1..=255 raw).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Operation(Vec<u8>);

/// A root's exact bytes carried by value — a decision's `candidate` or
/// an attestation's `final` (hex32 on the wire, 1..=[`ROOT_BYTES_MAX`]
/// raw).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootBytes(Vec<u8>);

impl Tenant {
    /// # Errors
    /// [`BoundedBytesError`] if `raw` is empty or over [`TENANT_MAX`].
    pub fn new(raw: Vec<u8>) -> Result<Self, BoundedBytesError> {
        check_bounds(raw.len(), TENANT_MAX)?;
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Principal {
    /// # Errors
    /// [`BoundedBytesError`] if `raw` is empty or over [`PRINCIPAL_MAX`].
    pub fn new(raw: Vec<u8>) -> Result<Self, BoundedBytesError> {
        check_bounds(raw.len(), PRINCIPAL_MAX)?;
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Operation {
    /// # Errors
    /// [`BoundedBytesError`] if `raw` is empty or over [`OPERATION_MAX`].
    pub fn new(raw: Vec<u8>) -> Result<Self, BoundedBytesError> {
        check_bounds(raw.len(), OPERATION_MAX)?;
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl RootBytes {
    /// # Errors
    /// [`BoundedBytesError`] if `raw` is empty or over [`ROOT_BYTES_MAX`].
    pub fn new(raw: Vec<u8>) -> Result<Self, BoundedBytesError> {
        check_bounds(raw.len(), ROOT_BYTES_MAX)?;
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The prefix shared by every record body includes the submitter's
/// tenant, principal and operation
/// identity, plus the id of the candidate's exact bytes. Present in
/// every record type — a decision's own field-level tie to its
/// `candidate` bytes is [`crate::authlog::RecordBody::Decision`]'s
/// concern, not this type's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubmissionIdentity {
    tenant: Tenant,
    principal: Principal,
    operation: Operation,
    candidate_id: GrainId,
}

impl SubmissionIdentity {
    #[must_use]
    pub const fn new(
        tenant: Tenant,
        principal: Principal,
        operation: Operation,
        candidate_id: GrainId,
    ) -> Self {
        Self {
            tenant,
            principal,
            operation,
            candidate_id,
        }
    }

    #[must_use]
    pub const fn tenant(&self) -> &Tenant {
        &self.tenant
    }

    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    #[must_use]
    pub const fn candidate_id(&self) -> GrainId {
        self.candidate_id
    }
}

/// Why a hex field's wire bytes could not be decoded.
/// These reasons are internal. On any such error, `classify`
/// cannot accept this record+mark pair. The recovery verdict
/// reports whether the mark commits the record, without exposing
/// the underlying hex-field error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HexFieldError {
    Truncated,
    /// The hex length field was 0 (every field's raw minimum is 1 byte,
    /// i.e. 2 hex characters).
    ZeroLength,
    /// The hex length field was odd (a hex byte is two characters).
    OddLength,
    /// The decoded raw length violated the field's cap.
    Bounded(BoundedBytesError),
    /// A character outside `0-9a-f` (uppercase hex included).
    NotLowerHex,
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn decode_hex_body(
    c: &mut Cursor<'_>,
    hex_len: usize,
    max_raw: usize,
) -> Result<Vec<u8>, HexFieldError> {
    if hex_len == 0 {
        return Err(HexFieldError::ZeroLength);
    }
    if !hex_len.is_multiple_of(2) {
        return Err(HexFieldError::OddLength);
    }
    let raw_len = hex_len / 2;
    // Checked against the field's cap BEFORE any allocation or read of
    // the (potentially much larger, attacker-declared) hex text itself.
    check_bounds(raw_len, max_raw).map_err(HexFieldError::Bounded)?;
    let text = c.take(hex_len).map_err(|_| HexFieldError::Truncated)?;
    let mut out = Vec::with_capacity(raw_len);
    for pair in text.chunks_exact(2) {
        let &[hi, lo] = pair else {
            // Unreachable: `chunks_exact(2)` over an even-length slice
            // always yields length-2 chunks.
            return Err(HexFieldError::NotLowerHex);
        };
        let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) else {
            return Err(HexFieldError::NotLowerHex);
        };
        out.push((h << 4) | l);
    }
    Ok(out)
}

/// Decode a `hex16` field: `len u16` (hex character count), then the
/// characters. `max_raw` is the field's own cap (checked before the
/// text is read).
pub(crate) fn decode_hex16(c: &mut Cursor<'_>, max_raw: usize) -> Result<Vec<u8>, HexFieldError> {
    let hex_len = usize::from(c.u16().map_err(|_| HexFieldError::Truncated)?);
    decode_hex_body(c, hex_len, max_raw)
}

/// Decode a `hex32` field: `len u32` (hex character count), then the
/// characters.
pub(crate) fn decode_hex32(c: &mut Cursor<'_>, max_raw: usize) -> Result<Vec<u8>, HexFieldError> {
    let hex_len_u32 = c.u32().map_err(|_| HexFieldError::Truncated)?;
    // `usize::try_from` rather than `as`: exact on every target this
    // crate ever builds for, and a 32-bit target proves the bound at
    // runtime instead of by comment.
    let hex_len = usize::try_from(hex_len_u32).map_err(|_| HexFieldError::Truncated)?;
    decode_hex_body(c, hex_len, max_raw)
}

fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    for b in bytes {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0F));
    }
}

/// Encode a `hex16` field. `bytes.len()` must already be within the
/// field's cap (every [`Tenant`]/[`Principal`]/[`Operation`] value is,
/// by construction) — `2 * PRINCIPAL_MAX` (2048) is far inside `u16`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "bytes.len() <= PRINCIPAL_MAX = 1024 for every caller (bounded newtype), so \
              2 * bytes.len() <= 2048 fits u16"
)]
pub(crate) fn encode_hex16(out: &mut Vec<u8>, bytes: &[u8]) {
    let hex_len = (bytes.len() * 2) as u16;
    out.extend_from_slice(&hex_len.to_be_bytes());
    push_hex(out, bytes);
}

/// Encode a `hex32` field. `2 * ROOT_BYTES_MAX` is far inside `u32`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "bytes.len() <= ROOT_BYTES_MAX for every caller (bounded newtype), so \
              2 * bytes.len() fits u32"
)]
pub(crate) fn encode_hex32(out: &mut Vec<u8>, bytes: &[u8]) {
    let hex_len = (bytes.len() * 2) as u32;
    out.extend_from_slice(&hex_len.to_be_bytes());
    push_hex(out, bytes);
}
