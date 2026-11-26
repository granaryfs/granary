// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Persistent debug grants, format v1.
//! Pure validated values and canonical bytes: no I/O, clock or randomness.
//! Verification hashes received bytes before interpreting version or fields.
//! The caller compares incarnation after decoding and owns issuance policy.

use crate::enrollment::PrincipalId;
use crate::root::{VOLUME_NAME_MAX, VolumeName, VolumeNameError};
use crate::sheaf::Timestamp;

/// The format's magic.
pub const DEBUG_GRANT_MAGIC: [u8; 8] = *b"GRNDEBUG";
/// The supported format version.
pub const DEBUG_GRANT_VERSION: u16 = 1;
/// Maximum encoded record size, including the check.
pub const ENCODED_MAX: usize = 523;
/// Maximum owner length in bytes.
pub const OWNER_MAX: usize = 64;
/// Maximum reason length in bytes.
pub const REASON_MAX: usize = 256;
/// Maximum line ceiling; zero is legal.
pub const LINE_CEILING_MAX: u64 = 1024;
/// Maximum byte ceiling; zero is legal.
pub const BYTE_CEILING_MAX: u64 = 1_048_576;
/// Maximum duration in seconds, including fractional seconds.
pub const DURATION_MAX_SECS: i64 = 900;

pub(crate) const CHECK_CONTEXT: &str = "granary debug grant v1";
pub(crate) const CHECK_LEN: usize = 32;
/// Magic, version and check; incomplete fields report truncation after verification.
pub(crate) const MIN_LEN: usize = 8 + 2 + CHECK_LEN;
const NANOS_PER_SEC: i128 = 1_000_000_000;

const _: () = assert!(
    ENCODED_MAX
        == 8 + 2
            + 16
            + 8
            + 8
            + 1
            + 4
            + 1
            + OWNER_MAX
            + 2
            + REASON_MAX
            + 12
            + 12
            + 1
            + 16
            + 1
            + VOLUME_NAME_MAX
            + 8
            + 8
            + CHECK_LEN
);

/// An opaque server-incarnation marker. Every 16-byte value is encodable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incarnation([u8; 16]);

impl Incarnation {
    /// Construct from opaque bytes; the codec does not mint or compare markers.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The exact marker bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The label whose validation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelField {
    /// Original operator owner label.
    Owner,
    /// Original operator reason label.
    Reason,
}

/// The timestamp whose validation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampField {
    /// Original issuance time.
    IssuedAt,
    /// Absolute expiration time.
    ExpiresAt,
}

/// The budget ceiling whose validation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetField {
    /// Lines.
    Lines,
    /// Bytes.
    Bytes,
}

/// A value outside the persistent format's accept set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantValidationError {
    /// Revision zero is invalid.
    InvalidFileRevision,
    /// Generation must be nonzero and no greater than revision.
    InvalidGeneration { generation: u64, revision: u64 },
    /// An empty or oversized label.
    BadLabelLength { field: LabelField, len: usize },
    /// A label byte outside printable ASCII excluding space.
    BadLabelByte { field: LabelField, byte: u8 },
    /// Nanoseconds must be below one billion.
    InvalidNanoseconds { field: TimestampField, nanos: u32 },
    /// Expiry minus issuance must be in (0, 900] seconds.
    InvalidDuration,
    /// A budget ceiling exceeds the format maximum.
    BudgetOverBound { field: BudgetField, value: u64 },
}

impl std::fmt::Display for GrantValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFileRevision => write!(f, "debug grant revision is zero"),
            Self::InvalidGeneration {
                generation,
                revision,
            } => write!(
                f,
                "debug grant generation {generation} is outside 1..={revision}"
            ),
            Self::BadLabelLength { field, len } => {
                write!(f, "debug grant {field:?} length {len} is outside its bound")
            }
            Self::BadLabelByte { field, byte } => write!(
                f,
                "debug grant {field:?} byte 0x{byte:02x} is outside the charset"
            ),
            Self::InvalidNanoseconds { field, nanos } => {
                write!(f, "debug grant {field:?} nanoseconds {nanos} >= 1e9")
            }
            Self::InvalidDuration => write!(f, "debug grant duration is outside (0, 900] seconds"),
            Self::BudgetOverBound { field, value } => {
                write!(f, "debug grant {field:?} ceiling {value} exceeds its bound")
            }
        }
    }
}

impl std::error::Error for GrantValidationError {}

fn validate_label_length(len: usize, field: LabelField) -> Result<(), GrantValidationError> {
    let max = match field {
        LabelField::Owner => OWNER_MAX,
        LabelField::Reason => REASON_MAX,
    };
    if len == 0 || len > max {
        return Err(GrantValidationError::BadLabelLength { field, len });
    }
    Ok(())
}

fn validate_label(raw: &[u8], field: LabelField) -> Result<(), GrantValidationError> {
    validate_label_length(raw.len(), field)?;
    if let Some(&byte) = raw.iter().find(|&&byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(GrantValidationError::BadLabelByte { field, byte });
    }
    Ok(())
}

/// A nonsecret printable ASCII owner, 1..=64 bytes without space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner(Vec<u8>);

impl Owner {
    /// Validate exact label bytes before allocating.
    ///
    /// # Errors
    /// [`GrantValidationError`] for an invalid owner length or byte.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, GrantValidationError> {
        validate_label(raw, LabelField::Owner)?;
        Ok(Self(raw.to_vec()))
    }

    /// Exact label bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "owner construction bounds length to 64"
    )]
    fn wire_len(&self) -> u8 {
        self.0.len() as u8
    }
}

/// A nonsecret printable ASCII reason, 1..=256 bytes without space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(Vec<u8>);

impl Reason {
    /// Validate exact label bytes before allocating.
    ///
    /// # Errors
    /// [`GrantValidationError`] for an invalid reason length or byte.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, GrantValidationError> {
        validate_label(raw, LabelField::Reason)?;
        Ok(Self(raw.to_vec()))
    }

    /// Exact label bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "reason construction bounds length to 256"
    )]
    fn wire_len(&self) -> u16 {
        self.0.len() as u16
    }
}

/// The last local mutation represented by a complete grant record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAction {
    /// Issue a generation.
    Issue,
    /// Narrow a generation.
    Narrow,
    /// Revoke a generation, retaining its metadata.
    Revoke,
}

/// A complete scope; conjunction is principal AND volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantScope {
    /// All matching requests by this principal.
    Principal(PrincipalId),
    /// All matching requests for this volume.
    Volume(VolumeName),
    /// Requests matching both identifiers.
    Conjunction {
        principal: PrincipalId,
        volume: VolumeName,
    },
}

/// Construction fields, not yet validated as a complete record.
/// [`DebugGrant::new`] checks revision, generation, timestamps, duration and budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantFields {
    /// Opaque marker, compared by the caller after decoding.
    pub incarnation: Incarnation,
    /// Nonzero file revision.
    pub file_revision: u64,
    /// Nonzero generation, at most the file revision.
    pub grant_generation: u64,
    /// Last mutation action.
    pub action: GrantAction,
    /// Original issuing effective uid.
    pub issuer_uid: u32,
    /// Original owner label.
    pub owner: Owner,
    /// Original reason label.
    pub reason: Reason,
    /// Original issuance time in UTC.
    pub issued_at: Timestamp,
    /// Expiration time in UTC.
    pub expires_at: Timestamp,
    /// Complete selectors.
    pub scope: GrantScope,
    /// Line budget ceiling, including zero.
    pub line_ceiling: u64,
    /// Byte budget ceiling, including zero.
    pub byte_ceiling: u64,
}

/// A validated immutable record with exactly one legal encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugGrant(GrantFields);

impl DebugGrant {
    /// Validate a complete record. Issuance minimums and history are caller policy.
    ///
    /// # Errors
    /// [`GrantValidationError`] naming the first invalid value, in field order.
    pub fn new(fields: GrantFields) -> Result<Self, GrantValidationError> {
        validate_generation(fields.file_revision, fields.grant_generation)?;
        validate_timestamp(fields.issued_at, TimestampField::IssuedAt)?;
        validate_timestamp(fields.expires_at, TimestampField::ExpiresAt)?;
        validate_duration(fields.issued_at, fields.expires_at)?;
        validate_budget(fields.line_ceiling, BudgetField::Lines)?;
        validate_budget(fields.byte_ceiling, BudgetField::Bytes)?;
        Ok(Self(fields))
    }

    /// Immutable validated fields. Clone them to construct a replacement.
    #[must_use]
    pub const fn fields(&self) -> &GrantFields {
        &self.0
    }
}

fn validate_generation(revision: u64, generation: u64) -> Result<(), GrantValidationError> {
    if revision == 0 {
        return Err(GrantValidationError::InvalidFileRevision);
    }
    if generation == 0 || generation > revision {
        return Err(GrantValidationError::InvalidGeneration {
            generation,
            revision,
        });
    }
    Ok(())
}

fn validate_timestamp(time: Timestamp, field: TimestampField) -> Result<(), GrantValidationError> {
    if !time.is_valid() {
        return Err(GrantValidationError::InvalidNanoseconds {
            field,
            nanos: time.nanos,
        });
    }
    Ok(())
}

fn validate_duration(issued: Timestamp, expires: Timestamp) -> Result<(), GrantValidationError> {
    // The full i64 seconds difference scaled to nanoseconds fits in i128.
    let duration = (i128::from(expires.secs) - i128::from(issued.secs)) * NANOS_PER_SEC
        + i128::from(expires.nanos)
        - i128::from(issued.nanos);
    if duration <= 0 || duration > i128::from(DURATION_MAX_SECS) * NANOS_PER_SEC {
        return Err(GrantValidationError::InvalidDuration);
    }
    Ok(())
}

fn validate_budget(value: u64, field: BudgetField) -> Result<(), GrantValidationError> {
    let max = match field {
        BudgetField::Lines => LINE_CEILING_MAX,
        BudgetField::Bytes => BYTE_CEILING_MAX,
    };
    if value > max {
        return Err(GrantValidationError::BudgetOverBound { field, value });
    }
    Ok(())
}

/// The encoded record, including its check and bounded by [`ENCODED_MAX`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedGrant(Vec<u8>);

impl EncodedGrant {
    /// Complete canonical bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Encode a validated grant. Total: construction enforces every decode rule.
#[must_use]
pub fn encode_grant(grant: &DebugGrant) -> EncodedGrant {
    let fields = grant.fields();
    let mut out = Vec::with_capacity(ENCODED_MAX);
    out.extend_from_slice(&DEBUG_GRANT_MAGIC);
    out.extend_from_slice(&DEBUG_GRANT_VERSION.to_be_bytes());
    out.extend_from_slice(fields.incarnation.as_bytes());
    out.extend_from_slice(&fields.file_revision.to_be_bytes());
    out.extend_from_slice(&fields.grant_generation.to_be_bytes());
    out.push(match fields.action {
        GrantAction::Issue => 1,
        GrantAction::Narrow => 2,
        GrantAction::Revoke => 3,
    });
    out.extend_from_slice(&fields.issuer_uid.to_be_bytes());
    out.push(fields.owner.wire_len());
    out.extend_from_slice(fields.owner.as_bytes());
    out.extend_from_slice(&fields.reason.wire_len().to_be_bytes());
    out.extend_from_slice(fields.reason.as_bytes());
    for time in [fields.issued_at, fields.expires_at] {
        out.extend_from_slice(&time.secs.to_be_bytes());
        out.extend_from_slice(&time.nanos.to_be_bytes());
    }
    match &fields.scope {
        GrantScope::Principal(principal) => {
            out.push(1);
            out.extend_from_slice(principal.as_bytes());
        }
        GrantScope::Volume(volume) => {
            out.push(2);
            push_volume(&mut out, volume);
        }
        GrantScope::Conjunction { principal, volume } => {
            out.push(3);
            out.extend_from_slice(principal.as_bytes());
            push_volume(&mut out, volume);
        }
    }
    out.extend_from_slice(&fields.line_ceiling.to_be_bytes());
    out.extend_from_slice(&fields.byte_ceiling.to_be_bytes());
    let check = blake3::derive_key(CHECK_CONTEXT, &out);
    out.extend_from_slice(&check);
    EncodedGrant(out)
}

fn push_volume(out: &mut Vec<u8>, volume: &VolumeName) {
    out.push(volume.wire_len());
    out.extend_from_slice(volume.as_str().as_bytes());
}

/// The first strict-decode refusal, in the order documented by [`decode_grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantDecodeError {
    /// Wrong magic.
    BadMagic,
    /// Fewer than magic, version and check bytes.
    TooShort { len: usize },
    /// More than [`ENCODED_MAX`] bytes.
    TooLong { len: usize },
    /// The check of the received bytes does not match.
    BadCheck,
    /// An unsupported version.
    UnknownVersion { version: u16 },
    /// A field overruns the checked prefix.
    Truncated,
    /// An unknown action tag.
    InvalidAction { tag: u8 },
    /// An unknown scope tag.
    InvalidScope { tag: u8 },
    /// An invalid volume label.
    InvalidVolume(VolumeNameError),
    /// A value outside the format's bounds.
    InvalidValue(GrantValidationError),
    /// Extra bytes before the check.
    TrailingData { len: usize },
}

impl std::fmt::Display for GrantDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad debug grant magic"),
            Self::TooShort { len } => write!(f, "debug grant of {len} bytes is too short"),
            Self::TooLong { len } => write!(f, "debug grant of {len} bytes exceeds its bound"),
            Self::BadCheck => write!(f, "debug grant check does not match"),
            Self::UnknownVersion { version } => write!(f, "unknown debug grant version {version}"),
            Self::Truncated => write!(f, "debug grant field overruns the checked prefix"),
            Self::InvalidAction { tag } => write!(f, "debug grant has invalid action 0x{tag:02x}"),
            Self::InvalidScope { tag } => write!(f, "debug grant has invalid scope 0x{tag:02x}"),
            Self::InvalidVolume(error) => write!(f, "debug grant {error}"),
            Self::InvalidValue(error) => error.fmt(f),
            Self::TrailingData { len } => write!(f, "debug grant has {len} bytes after its fields"),
        }
    }
}

impl std::error::Error for GrantDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidValue(error) => Some(error),
            Self::InvalidVolume(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GrantValidationError> for GrantDecodeError {
    fn from(error: GrantValidationError) -> Self {
        Self::InvalidValue(error)
    }
}

fn take<'a, const N: usize>(rest: &mut &'a [u8]) -> Result<&'a [u8; N], GrantDecodeError> {
    let (head, tail) = rest
        .split_first_chunk::<N>()
        .ok_or(GrantDecodeError::Truncated)?;
    *rest = tail;
    Ok(head)
}

fn take_bytes<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8], GrantDecodeError> {
    let (head, tail) = rest
        .split_at_checked(len)
        .ok_or(GrantDecodeError::Truncated)?;
    *rest = tail;
    Ok(head)
}

fn take_timestamp(rest: &mut &[u8], field: TimestampField) -> Result<Timestamp, GrantDecodeError> {
    let time = Timestamp {
        secs: i64::from_be_bytes(*take::<8>(rest)?),
        nanos: u32::from_be_bytes(*take::<4>(rest)?),
    };
    validate_timestamp(time, field)?;
    Ok(time)
}

fn take_volume(rest: &mut &[u8]) -> Result<VolumeName, GrantDecodeError> {
    let &[len] = take::<1>(rest)?;
    if len == 0 {
        return Err(GrantDecodeError::InvalidVolume(VolumeNameError::Empty));
    }
    if usize::from(len) > VOLUME_NAME_MAX {
        return Err(GrantDecodeError::InvalidVolume(VolumeNameError::TooLong {
            len: usize::from(len),
        }));
    }
    VolumeName::from_bytes(take_bytes(rest, usize::from(len))?)
        .map_err(GrantDecodeError::InvalidVolume)
}

/// Decode the entire input strictly: magic, length bound, received-byte
/// check, version, then fields in layout order, then no trailing bytes.
/// Lengths are checked before allocation. The incarnation is only decoded.
///
/// # Errors
/// [`GrantDecodeError`] naming the first failed rule.
pub fn decode_grant(bytes: &[u8]) -> Result<DebugGrant, GrantDecodeError> {
    if bytes
        .get(..DEBUG_GRANT_MAGIC.len())
        .is_some_and(|magic| magic != DEBUG_GRANT_MAGIC)
    {
        return Err(GrantDecodeError::BadMagic);
    }
    if bytes.len() < MIN_LEN {
        return Err(GrantDecodeError::TooShort { len: bytes.len() });
    }
    if bytes.len() > ENCODED_MAX {
        return Err(GrantDecodeError::TooLong { len: bytes.len() });
    }
    let (covered, check) = bytes
        .split_last_chunk::<CHECK_LEN>()
        .ok_or(GrantDecodeError::Truncated)?;
    if *check != blake3::derive_key(CHECK_CONTEXT, covered) {
        return Err(GrantDecodeError::BadCheck);
    }
    let mut rest = covered;
    take::<8>(&mut rest)?;
    let version = u16::from_be_bytes(*take::<2>(&mut rest)?);
    if version != DEBUG_GRANT_VERSION {
        return Err(GrantDecodeError::UnknownVersion { version });
    }
    let incarnation = Incarnation::from_bytes(*take::<16>(&mut rest)?);
    let file_revision = u64::from_be_bytes(*take::<8>(&mut rest)?);
    let grant_generation = u64::from_be_bytes(*take::<8>(&mut rest)?);
    validate_generation(file_revision, grant_generation)?;
    let &[tag] = take::<1>(&mut rest)?;
    let action = match tag {
        1 => GrantAction::Issue,
        2 => GrantAction::Narrow,
        3 => GrantAction::Revoke,
        _ => return Err(GrantDecodeError::InvalidAction { tag }),
    };
    let issuer_uid = u32::from_be_bytes(*take::<4>(&mut rest)?);
    let &[owner_len] = take::<1>(&mut rest)?;
    validate_label_length(usize::from(owner_len), LabelField::Owner)?;
    let owner = Owner::from_bytes(take_bytes(&mut rest, usize::from(owner_len))?)?;
    let reason_len = usize::from(u16::from_be_bytes(*take::<2>(&mut rest)?));
    validate_label_length(reason_len, LabelField::Reason)?;
    let reason = Reason::from_bytes(take_bytes(&mut rest, reason_len)?)?;
    let issued_at = take_timestamp(&mut rest, TimestampField::IssuedAt)?;
    let expires_at = take_timestamp(&mut rest, TimestampField::ExpiresAt)?;
    validate_duration(issued_at, expires_at)?;
    let &[tag] = take::<1>(&mut rest)?;
    let scope = match tag {
        1 => GrantScope::Principal(PrincipalId::from_bytes(*take::<16>(&mut rest)?)),
        2 => GrantScope::Volume(take_volume(&mut rest)?),
        3 => GrantScope::Conjunction {
            principal: PrincipalId::from_bytes(*take::<16>(&mut rest)?),
            volume: take_volume(&mut rest)?,
        },
        _ => return Err(GrantDecodeError::InvalidScope { tag }),
    };
    let line_ceiling = u64::from_be_bytes(*take::<8>(&mut rest)?);
    validate_budget(line_ceiling, BudgetField::Lines)?;
    let byte_ceiling = u64::from_be_bytes(*take::<8>(&mut rest)?);
    validate_budget(byte_ceiling, BudgetField::Bytes)?;
    if !rest.is_empty() {
        return Err(GrantDecodeError::TrailingData { len: rest.len() });
    }
    // The field-order validations above already enforce the constructor's rules.
    Ok(DebugGrant(GrantFields {
        incarnation,
        file_revision,
        grant_generation,
        action,
        issuer_uid,
        owner,
        reason,
        issued_at,
        expires_at,
        scope,
        line_ceiling,
        byte_ceiling,
    }))
}

#[cfg(test)]
mod tests;
