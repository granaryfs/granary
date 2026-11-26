// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The writable mount's overlay area, format v1: the writer identity
//! file, the write
//! journal, the staging file header and unmerged path listings. Pure
//! bytes-to-value and value-to-bytes: no I/O, no clock, no randomness; opening files, custody,
//! appending and syncing are the client's.
//!
//! Everything is big-endian and fixed-width. Every file carries its own
//! magic and a BLAKE3 derive-key check. The codec is strict: a decoder
//! accepts a byte string only if the encoder writes it back unchanged, and
//! the encoder refuses what the decoder rejects.
//!
//! * [`WriterRecord`]: the store's writer identity and generation ceiling.
//! * [`JournalHeader`] and [`Record`]: the journal's header and its seventeen
//!   record kinds; [`scan_journal_with`] visits admitted records without
//!   retaining paths, returning a clean or provisional torn end, or a [`Fence`].
//! * [`StagingHeader`]: the header of a staging file, with the mirrored
//!   synced mark; [`ExtentHasher`] computes the check a `write-extent`
//!   record carries over the bytes it claims.
//!
//! The scan keeps a stage table and a generation cursor, because the value
//! rules need them (an extent names a bound stage; a synced size is at most
//! the accounted size; generations never decrease). It keeps no paths and
//! builds no overlay tree: folding the records into a tree is the replay's.
//!
//! No allocation is sized by a declared length: a frame's `len` is range
//! checked against [`LEN_MAX`] before any read, names and paths are bounded
//! before they are collected, and the scan refuses a journal above
//! [`JOURNAL_MAX`] outright.

mod record;
mod scan;
mod unmerged;

#[cfg(test)]
mod tests;

pub use record::{
    BindCause, CreateKind, DeleteKind, IntentCause, Location, Parent, ProjectedSelection, Record,
    RecordError, RecreateAnchor, ResidualDisposition, ResidualFile, ResidualMode,
    residual_inventory_check,
};
pub use scan::{
    CommitProgress, EncodeError, Fence, FenceReason, HeaderError, JournalEnd, JournalHeader,
    JournalScan, JournalState, StageState, StagingDisposition, TornCause, ValueError,
    WriterBindError, encode_journal, encode_record, scan_journal, scan_journal_with,
};
pub use unmerged::{UNMERGED_PATH_MAX, UnmergedPath, UnmergedPathError};

pub(crate) use scan::{encode_record_checked, refresh_frame_check};

use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use crate::root::{VOLUME_NAME_MAX, VolumeName, VolumeNameError};

/// The writer file's magic.
pub const WRITER_MAGIC: [u8; 8] = *b"GRNOVWID";
/// The journal's magic.
pub const JOURNAL_MAGIC: [u8; 8] = *b"GRNOVJRN";
/// The staging file's magic.
pub const STAGING_MAGIC: [u8; 8] = *b"GRNOVSTG";
/// The format version this module reads and writes, for all four files.
pub const VERSION: u16 = 1;

/// A writer identity's length in bytes.
pub const WRITER_ID_LEN: usize = 16;
/// A check's length in bytes.
pub const CHECK_LEN: usize = 32;

/// Bytes of the journal header.
pub const JOURNAL_HEADER_LEN: usize = 117;
/// Smallest `len` field: kind, seq and check around an empty payload.
pub const LEN_MIN: u32 = 41;
/// Largest payload of one record.
pub const PAYLOAD_MAX: usize = 16384;
/// Largest `len` field: [`LEN_MIN`] plus [`PAYLOAD_MAX`].
pub const LEN_MAX: u32 = 16425;
/// Largest journal file; a larger one is refused, never read as a tail.
pub const JOURNAL_MAX: usize = 64 * 1024 * 1024;
/// Most names in a parent path.
pub const PATH_DEPTH_MAX: usize = 128;
/// Most name bytes in a parent path, all names together.
pub const PATH_BYTES_MAX: usize = 4096;
/// Largest size, offset or `offset + length`: 2^63 - 1.
pub const SIZE_MAX: u64 = i64::MAX as u64;
/// Largest stage id: 2^63 - 1.
pub const STAGE_ID_MAX: u64 = i64::MAX as u64;
/// Largest extent a `write-extent` record claims: one grain.
pub const EXTENT_LEN_MAX: u64 = 8 * 1024 * 1024;
/// Largest generation: `u64::MAX` would leave no successor.
pub const GENERATION_MAX: u64 = u64::MAX - 1;

/// Bytes of a staging file's header; file byte `i` is at offset `160 + i`.
pub const STAGING_HEADER_LEN: usize = 160;
/// Bytes of the synced-mark block inside the staging header.
pub const STAGING_MARK_LEN: usize = 8 + GRAIN_ID_BINARY_LEN + 8 + CHECK_LEN;

const WRITER_FIXED_LEN: usize = 8 + 2 + 2 + WRITER_ID_LEN + 8 + 1 + CHECK_LEN;
pub(crate) const STAGING_IDENTITY_LEN: usize = 8 + 2 + 2 + WRITER_ID_LEN + 8;
pub(crate) const MARK_OFFSET: usize = STAGING_IDENTITY_LEN + CHECK_LEN;

pub(crate) const WRITER_CONTEXT: &str = "granary overlay writer v1";
pub(crate) const HEADER_CONTEXT: &str = "granary overlay journal header v1";
pub(crate) const RECORD_CONTEXT: &str = "granary overlay journal record v1";
pub(crate) const STAGING_CONTEXT: &str = "granary overlay staging v1";
pub(crate) const MARK_CONTEXT: &str = "granary overlay staging mark v1";
pub(crate) const EXTENT_CONTEXT: &str = "granary overlay extent v1";

const _: () = assert!(JOURNAL_HEADER_LEN == 8 + 2 + 2 + 16 + 33 + 8 + 8 + 8 + 32);
const _: () = assert!(LEN_MAX as usize == LEN_MIN as usize + PAYLOAD_MAX);
const _: () = assert!(STAGING_MARK_LEN == 81);
const _: () = assert!(MARK_OFFSET + STAGING_MARK_LEN <= STAGING_HEADER_LEN);
const _: () = assert!(VOLUME_NAME_MAX == 63);

/// A bounds-checked reader over a byte slice; every read is `None` when the
/// bytes are short, so no decode path indexes or panics. This adapts the
/// shared encoding cursor to the format codecs' ordered, typed refusals.
pub(crate) struct Reader<'a>(crate::encoding::Cursor<'a>);

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self(crate::encoding::Cursor::new(bytes))
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        self.0.take(n).ok()
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    pub(crate) fn grain_id(&mut self) -> Option<Result<GrainId, ()>> {
        let bytes = self.take(GRAIN_ID_BINARY_LEN)?;
        Some(GrainId::from_bytes(bytes).map_err(|_| ()))
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.0.remaining() == 0
    }
}

/// The store's writer identity and generation ceiling for one volume
/// (`writer`, magic `GRNOVWID`).
///
/// ```text
/// magic    8   "GRNOVWID"
/// version  u16 1          flags u16 0
/// writer   16  opaque; all-zero is legal
/// ceiling  u64 0, or 1..=u64::MAX-1
/// volume   u8 length 1..=63, then the VolumeName bytes
/// check    32  derive-key "granary overlay writer v1" over every byte before it
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterRecord {
    /// The writer identity, compared for equality only.
    pub writer: [u8; WRITER_ID_LEN],
    /// The highest generation this store may ever have sent; 0 for none.
    pub ceiling: u64,
    /// The volume this overlay belongs to; the directory name is bound to it.
    pub volume: VolumeName,
}

/// Why a byte string is not a writer record. [`WriterRecord::decode`]
/// reports the first of these, in declaration order, that the input fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterError {
    /// The first eight bytes are not [`WRITER_MAGIC`].
    BadMagic,
    /// Shorter than the fixed part or longer than any record can be.
    BadLength { len: usize },
    /// The check does not match the bytes before it.
    BadCheck,
    /// A version other than [`VERSION`].
    UnknownVersion { version: u16 },
    /// The reserved flags are not zero.
    NonZeroFlags { flags: u16 },
    /// A ceiling of `u64::MAX`.
    CeilingOutOfRange { ceiling: u64 },
    /// The volume length byte disagrees with the bytes present.
    VolumeLengthMismatch { declared: usize, present: usize },
    /// The volume is not a volume name.
    BadVolume(VolumeNameError),
}

impl std::fmt::Display for WriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad overlay writer magic"),
            Self::BadLength { len } => write!(f, "overlay writer record has a bad length of {len}"),
            Self::BadCheck => write!(f, "overlay writer check does not match"),
            Self::UnknownVersion { version } => {
                write!(f, "unknown overlay writer version {version}")
            }
            Self::NonZeroFlags { flags } => {
                write!(f, "overlay writer flags 0x{flags:04x} are reserved")
            }
            Self::CeilingOutOfRange { ceiling } => {
                write!(f, "overlay writer ceiling {ceiling} is out of range")
            }
            Self::VolumeLengthMismatch { declared, present } => write!(
                f,
                "overlay writer volume length {declared} but {present} bytes present"
            ),
            Self::BadVolume(e) => write!(f, "overlay writer volume: {e}"),
        }
    }
}

impl std::error::Error for WriterError {}

impl WriterRecord {
    /// The record's canonical bytes.
    ///
    /// # Errors
    /// [`WriterError::CeilingOutOfRange`] for `u64::MAX`; the volume is
    /// already valid by construction.
    pub fn encode(&self) -> Result<Vec<u8>, WriterError> {
        if self.ceiling > GENERATION_MAX {
            return Err(WriterError::CeilingOutOfRange {
                ceiling: self.ceiling,
            });
        }
        let volume = self.volume.as_str().as_bytes();
        let volume_len =
            u8::try_from(volume.len()).map_err(|_| WriterError::BadLength { len: volume.len() })?;
        let mut out = Vec::with_capacity(WRITER_FIXED_LEN + volume.len());
        out.extend_from_slice(&WRITER_MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.writer);
        out.extend_from_slice(&self.ceiling.to_be_bytes());
        out.push(volume_len);
        out.extend_from_slice(volume);
        let check = blake3::derive_key(WRITER_CONTEXT, &out);
        out.extend_from_slice(&check);
        Ok(out)
    }

    /// Decode a writer record, strictly: the whole input is the record.
    ///
    /// The checks run in this order and the first failure is the error:
    /// magic, length, the check over every byte before it, version, flags,
    /// ceiling, the volume length against the bytes present, the volume
    /// grammar.
    ///
    /// # Errors
    /// [`WriterError`] naming the first check the input fails.
    pub fn decode(bytes: &[u8]) -> Result<Self, WriterError> {
        if bytes
            .get(..WRITER_MAGIC.len())
            .is_some_and(|magic| magic != WRITER_MAGIC)
        {
            return Err(WriterError::BadMagic);
        }
        let bad_length = WriterError::BadLength { len: bytes.len() };
        if bytes.len() < WRITER_FIXED_LEN || bytes.len() > WRITER_FIXED_LEN + usize::from(u8::MAX) {
            return Err(bad_length);
        }
        let (covered, check) = bytes.split_last_chunk::<CHECK_LEN>().ok_or(bad_length)?;
        if *check != blake3::derive_key(WRITER_CONTEXT, covered) {
            return Err(WriterError::BadCheck);
        }
        let mut r = Reader::new(covered);
        if r.take(WRITER_MAGIC.len()).is_none() {
            return Err(bad_length);
        }
        let (Some(version), Some(flags), Some(writer), Some(ceiling), Some(declared)) =
            (r.u16(), r.u16(), r.array(), r.u64(), r.u8())
        else {
            return Err(bad_length);
        };
        if version != VERSION {
            return Err(WriterError::UnknownVersion { version });
        }
        if flags != 0 {
            return Err(WriterError::NonZeroFlags { flags });
        }
        if ceiling > GENERATION_MAX {
            return Err(WriterError::CeilingOutOfRange { ceiling });
        }
        let declared = usize::from(declared);
        let rest = r.take(declared).filter(|_| r.is_empty());
        let Some(volume) = rest else {
            return Err(WriterError::VolumeLengthMismatch {
                declared,
                present: covered.len().saturating_sub(WRITER_FIXED_LEN - CHECK_LEN),
            });
        };
        let volume = VolumeName::from_bytes(volume).map_err(WriterError::BadVolume)?;
        Ok(Self {
            writer,
            ceiling,
            volume,
        })
    }
}

/// The synced mark mirrored into a staging file's header: the durable
/// version of the file as the registered prepared root names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncedMark {
    /// Bytes of the file that are durable on the authority.
    pub synced_size: u64,
    /// The content id the prepared root names for those bytes.
    pub content: GrainId,
    /// The generation of the registration that made the mark true.
    pub generation: u64,
}

/// What a staging header's mark block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkState {
    /// All zero: no mark was ever written.
    Absent,
    /// Not zero and its check does not match: a torn or damaged write. The
    /// mark before it is still in the journal. Not encodable.
    Damaged,
    /// A mark whose check matches.
    Present(SyncedMark),
}

/// A staging file's header (magic `GRNOVSTG`), [`STAGING_HEADER_LEN`] bytes:
///
/// ```text
/// magic 8  "GRNOVSTG"   version u16 1   flags u16 0
/// writer 16             stage id u64 (1..=2^63-1)
/// identity check 32     derive-key "granary overlay staging v1" over the 36 bytes before it
/// mark 81               all zero, or: synced size u64, content id 33, generation u64,
///                       check 32 (derive-key "granary overlay staging mark v1" over
///                       the identity check and the three fields)
/// zero padding to 160
/// ```
///
/// The identity part is written once; the mark is rewritten in place. The
/// mark's check covers the identity check, so a mark cannot be moved to
/// another staging file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagingHeader {
    /// The writer identity of the journal that names this file.
    pub writer: [u8; WRITER_ID_LEN],
    /// The stage id this file backs.
    pub stage_id: u64,
    /// The mirrored synced mark.
    pub mark: MarkState,
}

/// Why a byte string is not a staging header. [`StagingHeader::decode`]
/// reports the first of these, in declaration order, that the input fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingError {
    /// The first eight bytes are not [`STAGING_MAGIC`].
    BadMagic,
    /// Not exactly [`STAGING_HEADER_LEN`] bytes.
    BadLength { len: usize },
    /// The identity check does not match.
    BadIdentityCheck,
    /// A version other than [`VERSION`].
    UnknownVersion { version: u16 },
    /// The reserved flags are not zero.
    NonZeroFlags { flags: u16 },
    /// A stage id of 0 or above [`STAGE_ID_MAX`].
    StageIdOutOfRange { stage_id: u64 },
    /// The padding after the mark block is not zero.
    NonZeroPadding,
    /// A mark whose check matches but whose fields are out of range.
    MarkOutOfRange,
    /// A [`MarkState::Damaged`] mark was passed to the encoder.
    DamagedMarkNotEncodable,
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad staging header magic"),
            Self::BadLength { len } => write!(f, "staging header has a bad length of {len}"),
            Self::BadIdentityCheck => write!(f, "staging header identity check does not match"),
            Self::UnknownVersion { version } => {
                write!(f, "unknown staging header version {version}")
            }
            Self::NonZeroFlags { flags } => {
                write!(f, "staging header flags 0x{flags:04x} are reserved")
            }
            Self::StageIdOutOfRange { stage_id } => {
                write!(f, "staging header stage id {stage_id} is out of range")
            }
            Self::NonZeroPadding => write!(f, "staging header padding is not zero"),
            Self::MarkOutOfRange => write!(f, "staging header mark fields are out of range"),
            Self::DamagedMarkNotEncodable => write!(f, "a damaged mark cannot be encoded"),
        }
    }
}

impl std::error::Error for StagingError {}

/// Why a staging header does not belong to the journal that names its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// The header's writer is not the journal's.
    WriterMismatch,
    /// The header's stage id is not the id the file is named by.
    StageIdMismatch,
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriterMismatch => write!(f, "staging header names another writer"),
            Self::StageIdMismatch => write!(f, "staging header names another stage id"),
        }
    }
}

impl std::error::Error for BindingError {}

impl StagingHeader {
    fn identity_bytes(writer: &[u8; WRITER_ID_LEN], stage_id: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(STAGING_HEADER_LEN);
        out.extend_from_slice(&STAGING_MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(writer);
        out.extend_from_slice(&stage_id.to_be_bytes());
        out
    }

    fn mark_check(identity_check: &[u8; CHECK_LEN], fields: &[u8]) -> [u8; CHECK_LEN] {
        let mut hasher = blake3::Hasher::new_derive_key(MARK_CONTEXT);
        hasher.update(identity_check);
        hasher.update(fields);
        *hasher.finalize().as_bytes()
    }

    /// The header's canonical bytes, [`STAGING_HEADER_LEN`] of them.
    ///
    /// # Errors
    /// [`StagingError::StageIdOutOfRange`], [`StagingError::MarkOutOfRange`]
    /// and [`StagingError::DamagedMarkNotEncodable`].
    pub fn encode(&self) -> Result<Vec<u8>, StagingError> {
        if self.stage_id == 0 || self.stage_id > STAGE_ID_MAX {
            return Err(StagingError::StageIdOutOfRange {
                stage_id: self.stage_id,
            });
        }
        let mut out = Self::identity_bytes(&self.writer, self.stage_id);
        let identity_check = blake3::derive_key(STAGING_CONTEXT, &out);
        out.extend_from_slice(&identity_check);
        match self.mark {
            MarkState::Absent => out.resize(STAGING_HEADER_LEN, 0),
            MarkState::Damaged => return Err(StagingError::DamagedMarkNotEncodable),
            MarkState::Present(mark) => {
                if mark.synced_size > SIZE_MAX
                    || mark.generation == 0
                    || mark.generation > GENERATION_MAX
                {
                    return Err(StagingError::MarkOutOfRange);
                }
                let mut fields = Vec::with_capacity(STAGING_MARK_LEN - CHECK_LEN);
                fields.extend_from_slice(&mark.synced_size.to_be_bytes());
                fields.extend_from_slice(&mark.content.to_bytes());
                fields.extend_from_slice(&mark.generation.to_be_bytes());
                let check = Self::mark_check(&identity_check, &fields);
                out.extend_from_slice(&fields);
                out.extend_from_slice(&check);
                out.resize(STAGING_HEADER_LEN, 0);
            }
        }
        Ok(out)
    }

    /// Decode a staging header from exactly [`STAGING_HEADER_LEN`] bytes.
    ///
    /// The checks run in this order and the first failure is the error:
    /// magic, length, identity check, version, flags, stage id, padding. A
    /// mark block that is not zero and whose check fails is not an error: it
    /// decodes as [`MarkState::Damaged`].
    ///
    /// # Errors
    /// [`StagingError`] naming the first check the input fails.
    pub fn decode(bytes: &[u8]) -> Result<Self, StagingError> {
        if bytes
            .get(..STAGING_MAGIC.len())
            .is_some_and(|magic| magic != STAGING_MAGIC)
        {
            return Err(StagingError::BadMagic);
        }
        let bad_length = StagingError::BadLength { len: bytes.len() };
        if bytes.len() != STAGING_HEADER_LEN {
            return Err(bad_length);
        }
        let mut r = Reader::new(bytes);
        let (Some(_), Some(version), Some(flags), Some(writer), Some(stage_id)) = (
            r.take(STAGING_MAGIC.len()),
            r.u16(),
            r.u16(),
            r.array::<WRITER_ID_LEN>(),
            r.u64(),
        ) else {
            return Err(bad_length);
        };
        let (Some(identity), Some(identity_check)) =
            (bytes.get(..STAGING_IDENTITY_LEN), r.array::<CHECK_LEN>())
        else {
            return Err(bad_length);
        };
        if identity_check != blake3::derive_key(STAGING_CONTEXT, identity) {
            return Err(StagingError::BadIdentityCheck);
        }
        if version != VERSION {
            return Err(StagingError::UnknownVersion { version });
        }
        if flags != 0 {
            return Err(StagingError::NonZeroFlags { flags });
        }
        if stage_id == 0 || stage_id > STAGE_ID_MAX {
            return Err(StagingError::StageIdOutOfRange { stage_id });
        }
        let (Some(block), Some(padding)) = (
            r.take(STAGING_MARK_LEN),
            r.take(STAGING_HEADER_LEN - MARK_OFFSET - STAGING_MARK_LEN),
        ) else {
            return Err(bad_length);
        };
        if padding.iter().any(|&b| b != 0) {
            return Err(StagingError::NonZeroPadding);
        }
        let mark = Self::decode_mark(&identity_check, block)?;
        Ok(Self {
            writer,
            stage_id,
            mark,
        })
    }

    fn decode_mark(
        identity_check: &[u8; CHECK_LEN],
        block: &[u8],
    ) -> Result<MarkState, StagingError> {
        if block.iter().all(|&b| b == 0) {
            return Ok(MarkState::Absent);
        }
        let Some((fields, check)) = block.split_last_chunk::<CHECK_LEN>() else {
            return Ok(MarkState::Damaged);
        };
        if *check != Self::mark_check(identity_check, fields) {
            return Ok(MarkState::Damaged);
        }
        let mut r = Reader::new(fields);
        let (Some(synced_size), Some(content), Some(generation)) = (r.u64(), r.grain_id(), r.u64())
        else {
            return Ok(MarkState::Damaged);
        };
        let Ok(content) = content else {
            return Err(StagingError::MarkOutOfRange);
        };
        if synced_size > SIZE_MAX || generation == 0 || generation > GENERATION_MAX {
            return Err(StagingError::MarkOutOfRange);
        }
        Ok(MarkState::Present(SyncedMark {
            synced_size,
            content,
            generation,
        }))
    }

    /// Check that this header belongs to `writer` and names `stage_id`: the
    /// staging file names the journal as the journal names the file.
    ///
    /// # Errors
    /// [`BindingError`] naming which of the two differs.
    pub fn check_binding(
        &self,
        writer: &[u8; WRITER_ID_LEN],
        stage_id: u64,
    ) -> Result<(), BindingError> {
        if self.writer != *writer {
            return Err(BindingError::WriterMismatch);
        }
        if self.stage_id != stage_id {
            return Err(BindingError::StageIdMismatch);
        }
        Ok(())
    }
}

/// The check a `write-extent` record carries over the bytes it claims,
/// computed incrementally so a caller can stream an extent of up to
/// [`EXTENT_LEN_MAX`] bytes from a file without holding it. The check covers
/// the stage id, offset and length as well as the bytes, so an extent cannot
/// be verified against another place.
#[derive(Debug, Clone)]
pub struct ExtentHasher(blake3::Hasher);

impl ExtentHasher {
    /// Start the check for `length` bytes at `offset` of stage `stage_id`.
    #[must_use]
    pub fn new(stage_id: u64, offset: u64, length: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(EXTENT_CONTEXT);
        hasher.update(&stage_id.to_be_bytes());
        hasher.update(&offset.to_be_bytes());
        hasher.update(&length.to_be_bytes());
        Self(hasher)
    }

    /// Feed the next bytes of the extent.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The check, once exactly `length` bytes were fed.
    #[must_use]
    pub fn finalize(&self) -> [u8; CHECK_LEN] {
        *self.0.finalize().as_bytes()
    }
}

/// The check over one extent held in memory.
#[must_use]
pub fn extent_check(stage_id: u64, offset: u64, bytes: &[u8]) -> [u8; CHECK_LEN] {
    let mut hasher = ExtentHasher::new(
        stage_id,
        offset,
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    );
    hasher.update(bytes);
    hasher.finalize()
}

/// Streaming check over a residual stage's identity, size and complete payload.
/// The staging header is excluded; callers feed exactly the logical file bytes.
#[derive(Debug, Clone)]
pub struct ResidualPayloadHasher(blake3::Hasher);

impl ResidualPayloadHasher {
    /// Start the check for `local_size` bytes of `stage_id`.
    #[must_use]
    pub fn new(stage_id: u64, local_size: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("granary residual payload v1");
        hasher.update(&stage_id.to_be_bytes());
        hasher.update(&local_size.to_be_bytes());
        Self(hasher)
    }

    /// Feed the next logical payload bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The check, once exactly `local_size` bytes were fed.
    #[must_use]
    pub fn finalize(&self) -> [u8; CHECK_LEN] {
        *self.0.finalize().as_bytes()
    }
}
