// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Permanent path mappings bound to an authenticated residual inventory.

use super::{Reader, Record, RecordError, ResidualDisposition, ResidualFile, ResidualMode};

/// Maximum encoded listing length, including its check.
pub const UNMERGED_PATH_MAX: usize = 4701;
const CONTEXT: &str = "granary unmerged path v1";

/// A canonical path mapping for one exported stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmergedPath {
    /// Original writer identity.
    pub writer: [u8; 16],
    /// Exact durable choice.
    pub record: ResidualDisposition,
    /// One member of its complete authenticated inventory.
    pub file: ResidualFile,
}

/// Why a listing cannot be used as recovery evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmergedPathError {
    /// The listing is outside its encoded length bounds.
    Length,
    /// The listing magic is not GRNOVUMP.
    Magic,
    /// The version is not one.
    Version,
    /// Reserved flags are nonzero.
    Flags,
    /// The received-byte check does not match.
    Check,
    /// The embedded disposition payload is invalid.
    Record(RecordError),
    /// The exported stage descriptor is invalid.
    Descriptor(RecordError),
    /// Only keep-remote dispositions have path listings.
    Disposition,
    /// The filename or independently supplied source disagrees.
    SourceMismatch,
}
impl std::fmt::Display for UnmergedPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Length => "unmerged path length",
            Self::Magic => "unmerged path magic",
            Self::Version => "unmerged path version",
            Self::Flags => "unmerged path flags",
            Self::Check => "unmerged path check",
            Self::Record(_) => "unmerged path record",
            Self::Descriptor(_) => "unmerged path descriptor",
            Self::Disposition => "unmerged path disposition",
            Self::SourceMismatch => "unmerged path source mismatch",
        })
    }
}
impl std::error::Error for UnmergedPathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Record(error) | Self::Descriptor(error) => Some(error),
            _ => None,
        }
    }
}

impl UnmergedPath {
    /// Encode the exact disposition payload and canonical descriptor.
    /// # Errors
    /// Invalid record, descriptor or listing length.
    pub fn encode(&self) -> Result<Vec<u8>, UnmergedPathError> {
        let mut bytes = b"GRNOVUMP\0\x01\0\0".to_vec();
        bytes.extend_from_slice(&self.writer);
        bytes.extend_from_slice(
            &Record::ResidualDisposition(self.record)
                .encode_payload()
                .map_err(UnmergedPathError::Record)?,
        );
        bytes.extend_from_slice(&self.file.encode().map_err(UnmergedPathError::Descriptor)?);
        bytes.extend_from_slice(&blake3::derive_key(CONTEXT, &bytes));
        Self::decode(&bytes)?;
        Ok(bytes)
    }

    /// Decode received bytes without deriving authority from their own checks.
    /// # Errors
    /// Invalid framing, check, record or descriptor.
    pub fn decode(bytes: &[u8]) -> Result<Self, UnmergedPathError> {
        let bad = UnmergedPathError::Length;
        if !(223..=UNMERGED_PATH_MAX).contains(&bytes.len()) {
            return Err(bad);
        }
        let covered = bytes.get(..bytes.len().saturating_sub(32)).ok_or(bad)?;
        let mut r = Reader::new(covered);
        if r.take(8) != Some(b"GRNOVUMP") {
            return Err(UnmergedPathError::Magic);
        }
        if r.u16() != Some(1) {
            return Err(UnmergedPathError::Version);
        }
        if r.u16() != Some(0) {
            return Err(UnmergedPathError::Flags);
        }
        if bytes.get(covered.len()..) != Some(blake3::derive_key(CONTEXT, covered).as_slice()) {
            return Err(UnmergedPathError::Check);
        }
        let writer = r.array().ok_or(bad)?;
        let Record::ResidualDisposition(record) =
            Record::decode_payload(17, r.take(110).ok_or(bad)?)
                .map_err(UnmergedPathError::Record)?
        else {
            return Err(bad);
        };
        if record.disposition != ResidualMode::KeepRemote {
            return Err(UnmergedPathError::Disposition);
        }
        let file = ResidualFile::decode(r.take(covered.len().saturating_sub(138)).ok_or(bad)?)
            .map_err(UnmergedPathError::Descriptor)?;
        Ok(Self {
            writer,
            record,
            file,
        })
    }

    /// Bind a listing to its canonical filename and independently authenticated source.
    /// # Errors
    /// Any disagreement with the source writer, record or descriptor.
    pub fn check_binding(
        &self,
        filename: &str,
        writer: &[u8; 16],
        record: &ResidualDisposition,
        file: &ResidualFile,
    ) -> Result<(), UnmergedPathError> {
        if filename != format!("{:016x}.path", file.stage_id)
            || &self.writer != writer
            || &self.record != record
            || &self.file != file
        {
            return Err(UnmergedPathError::SourceMismatch);
        }
        Ok(())
    }
}
