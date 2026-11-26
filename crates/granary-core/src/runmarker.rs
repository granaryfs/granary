// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The authority's run marker, format v1: one
//! small self-checking file that says whether the authority is running, under
//! which boot, or stopped cleanly. Pure bytes-to-value and value-to-bytes: no
//! I/O, no clock, no randomness; reading the boot id from the host and
//! writing the file are the server adapter's.
//!
//! Big-endian, no varints. The state decides the length:
//!
//! ```text
//! magic     8    "GRNRUNMK"
//! version   u16  1
//! state     u8   0x01 running, 0x02 clean; 0x00 and every other value invalid
//! boot_id   16   present if and only if the state is running
//! check     32   BLAKE3 derive-key "granary authority run marker v1"
//!                over every byte before it
//! ```
//!
//! A running marker is [`RUNNING_LEN`] (59) bytes and a clean one
//! [`CLEAN_LEN`] (43).
//!
//! The codec is strict: [`decode_marker`] accepts a byte string only if
//! [`encode_marker`] of the value it returns is that same byte string, and it
//! verifies the check before it interprets the version or the state, so a
//! damaged byte reads as [`MarkerDecodeError::BadCheck`] rather than as a
//! nonsense version. What a marker *means* is the engine's; this
//! module only turns bytes into a value, and every failure it reports
//! is "malformed" to the engine.
//!
//!
//! [`encode_marker`] is the only way to build an [`EncodedMarker`], the value
//! `DecisionLog::write_marker` takes, so the file's bytes cannot come from
//! anywhere but this codec.

/// The marker's magic.
pub const MARKER_MAGIC: [u8; 8] = *b"GRNRUNMK";
/// The format version this module reads and writes.
pub const MARKER_VERSION: u16 = 1;
/// A boot id's length in bytes.
pub const BOOT_ID_LEN: usize = 16;
/// A running marker's length: header, boot id, check.
pub const RUNNING_LEN: usize = HEADER_LEN + BOOT_ID_LEN + CHECK_LEN;
/// A clean marker's length: header, check.
pub const CLEAN_LEN: usize = HEADER_LEN + CHECK_LEN;

/// magic(8) + version(2) + state(1).
const HEADER_LEN: usize = 8 + 2 + 1;
pub(crate) const CHECK_LEN: usize = 32;
pub(crate) const CHECK_CONTEXT: &str = "granary authority run marker v1";
const STATE_RUNNING: u8 = 0x01;
const STATE_CLEAN: u8 = 0x02;

const _: () = assert!(RUNNING_LEN == 59);
const _: () = assert!(CLEAN_LEN == 43);

/// The identity of one host boot, as the host supplies it. Format-opaque:
/// this module carries it and compares it for equality, never interprets its
/// bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootId([u8; BOOT_ID_LEN]);

impl BootId {
    /// A boot id from the host's [`BOOT_ID_LEN`] bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; BOOT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The boot id's [`BOOT_ID_LEN`] bytes, as the host supplied them.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; BOOT_ID_LEN] {
        self.0
    }
}

/// What a valid marker says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunMarker {
    /// The authority is running, or died without stopping, under this boot.
    Running(BootId),
    /// The authority stopped unfenced and quiescent.
    Clean,
}

/// Why a byte string is not a marker. Every variant is "malformed" to the
/// engine's startup table. [`decode_marker`] reports the first of these, in
/// declaration order, that the input fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerDecodeError {
    /// The first eight bytes are not [`MARKER_MAGIC`].
    BadMagic,
    /// The input is neither [`CLEAN_LEN`] nor [`RUNNING_LEN`] bytes; `len` is
    /// the input's length.
    BadLength { len: usize },
    /// The check does not match the bytes before it.
    BadCheck,
    /// A version other than [`MARKER_VERSION`].
    UnknownVersion { version: u16 },
    /// A state byte that is neither running nor clean, 0x00 included.
    InvalidState { tag: u8 },
    /// A valid state on the other state's length: running without a boot id,
    /// or clean with one. `len` is the input's length.
    StateLengthMismatch { tag: u8, len: usize },
}

impl std::fmt::Display for MarkerDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad run marker magic"),
            Self::BadLength { len } => write!(f, "run marker has a bad length of {len} bytes"),
            Self::BadCheck => write!(f, "run marker check does not match"),
            Self::UnknownVersion { version } => {
                write!(f, "unknown run marker version {version}")
            }
            Self::InvalidState { tag } => write!(f, "invalid run marker state 0x{tag:02x}"),
            Self::StateLengthMismatch { tag, len } => {
                write!(f, "run marker state 0x{tag:02x} does not fit {len} bytes")
            }
        }
    }
}

impl std::error::Error for MarkerDecodeError {}

/// A marker's canonical bytes, as [`encode_marker`] builds them: the only
/// value `DecisionLog::write_marker` accepts. The bytes are private, so a
/// caller cannot hand the seam bytes this codec did not produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMarker(Vec<u8>);

impl EncodedMarker {
    /// The marker's bytes: [`RUNNING_LEN`] for a running marker,
    /// [`CLEAN_LEN`] for a clean one.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Encode a marker: [`RUNNING_LEN`] bytes for a running one, [`CLEAN_LEN`]
/// for a clean one. Infallible: every value has exactly one encoding.
#[must_use]
pub fn encode_marker(marker: &RunMarker) -> EncodedMarker {
    let mut out = Vec::with_capacity(RUNNING_LEN);
    out.extend_from_slice(&MARKER_MAGIC);
    out.extend_from_slice(&MARKER_VERSION.to_be_bytes());
    match marker {
        RunMarker::Running(boot_id) => {
            out.push(STATE_RUNNING);
            out.extend_from_slice(&boot_id.to_bytes());
        }
        RunMarker::Clean => out.push(STATE_CLEAN),
    }
    let check = blake3::derive_key(CHECK_CONTEXT, &out);
    out.extend_from_slice(&check);
    EncodedMarker(out)
}

/// Decode a marker, strictly: the whole input is the marker.
///
/// The checks run in this order, and the first failure is the error: magic,
/// then the exact length, then the check over every byte before it, then the
/// version, the state, and last that the state agrees with the length. The
/// check comes before the version and the state so that damage to any byte
/// after the magic reads as a bad check, not as an unknown version.
///
/// # Errors
/// [`MarkerDecodeError`] naming the first check the input fails.
pub fn decode_marker(bytes: &[u8]) -> Result<RunMarker, MarkerDecodeError> {
    let bad_length = MarkerDecodeError::BadLength { len: bytes.len() };
    if bytes
        .get(..MARKER_MAGIC.len())
        .is_some_and(|magic| magic != MARKER_MAGIC)
    {
        return Err(MarkerDecodeError::BadMagic);
    }
    if !matches!(bytes.len(), CLEAN_LEN | RUNNING_LEN) {
        return Err(bad_length);
    }
    // Only the exact lengths reach here, so the split cannot fail; it is one
    // `None` arm rather than a scatter of them.
    let (covered, check, header, boot) = bytes
        .split_last_chunk::<CHECK_LEN>()
        .and_then(|(covered, check)| {
            let (header, boot) = covered.split_first_chunk::<HEADER_LEN>()?;
            Some((covered, check, header, boot))
        })
        .ok_or(bad_length)?;
    if *check != blake3::derive_key(CHECK_CONTEXT, covered) {
        return Err(MarkerDecodeError::BadCheck);
    }
    let [.., v0, v1, tag] = *header;
    let version = u16::from_be_bytes([v0, v1]);
    if version != MARKER_VERSION {
        return Err(MarkerDecodeError::UnknownVersion { version });
    }
    match (tag, <[u8; BOOT_ID_LEN]>::try_from(boot)) {
        (STATE_RUNNING, Ok(id)) => Ok(RunMarker::Running(BootId::from_bytes(id))),
        (STATE_CLEAN, Err(_)) if boot.is_empty() => Ok(RunMarker::Clean),
        (STATE_RUNNING | STATE_CLEAN, _) => Err(MarkerDecodeError::StateLengthMismatch {
            tag,
            len: bytes.len(),
        }),
        _ => Err(MarkerDecodeError::InvalidState { tag }),
    }
}

#[cfg(test)]
mod tests;
