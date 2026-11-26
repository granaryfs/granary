// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Grain identity: algorithm-tagged content hashes (spec §4).
//!
//! `GrainId` is a format object (format-object skill): canonical binary
//! and text encodings below are consensus surfaces. Golden vectors live
//! in `tests/grainid_golden.rs`; the fuzz target is
//! `fuzz/fuzz_targets/grainid_decode.rs`.
//!

use core::fmt;
use core::str::FromStr;

/// Digest width in bytes. Hashes are stored full-width; truncation is
/// never a format feature.
pub const DIGEST_LEN: usize = 32;

/// Canonical binary encoding length: 1 algorithm-tag byte + digest.
pub const GRAIN_ID_BINARY_LEN: usize = 1 + DIGEST_LEN;

/// Hash algorithm tag. The `u8` discriminant IS the on-disk/wire value —
/// a format contract: tags are never reused or renumbered, 0x00 is
/// invalid forever. Multihash codes were rejected (blake3's multicodec
/// entry is still draft); this registry is ours.
///
/// Variant declaration order MUST match tag-numeric order — derived
/// `Ord` is part of the canonical-ordering contract (format doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// BLAKE3, 32-byte digest (spec §4).
    Blake3 = 0x01,
}

impl HashAlgorithm {
    /// Canonical lowercase name used in the text form (OCI-digest-style
    /// `algorithm:hex`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::Blake3),
            _ => None,
        }
    }

    /// Every registered algorithm. The `registry_closed` test's exhaustive
    /// match forces this list to grow with the enum.
    pub const ALL: &'static [Self] = &[Self::Blake3];

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.name() == name)
    }
}

/// A grain's content address: `{algorithm, digest}`.
///
/// ```
/// use granary_core::hash::GrainId;
/// let id = GrainId::of(b"hello granary");
/// let text = id.to_string();
/// assert!(text.starts_with("blake3:"));
/// assert_eq!(text.len(), "blake3:".len() + 64);
/// let bytes = id.to_bytes();
/// assert!(GrainId::from_bytes(&bytes).is_ok_and(|back| back == id));
/// assert!(text.parse::<GrainId>().is_ok_and(|back| back == id));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrainId {
    algorithm: HashAlgorithm,
    digest: [u8; DIGEST_LEN],
}

/// Incremental grain content hasher.
///
/// Feed the grain bytes in order with [`GrainIdHasher::update`], then consume
/// the hasher with [`GrainIdHasher::finalize`].
#[derive(Debug, Clone)]
pub struct GrainIdHasher {
    algorithm: HashAlgorithm,
    state: blake3::Hasher,
}

impl GrainIdHasher {
    /// Start an incremental hash using `algorithm`.
    #[must_use]
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Blake3 => Self {
                algorithm,
                state: blake3::Hasher::new(),
            },
        }
    }

    /// Add the next contiguous bytes of the grain.
    pub fn update(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
    }

    /// Finish the hash and return its algorithm-tagged content id.
    #[must_use]
    pub fn finalize(self) -> GrainId {
        match self.algorithm {
            HashAlgorithm::Blake3 => {
                GrainId::from_parts(HashAlgorithm::Blake3, *self.state.finalize().as_bytes())
            }
        }
    }
}

impl GrainId {
    /// Hash `data` with the current default algorithm (BLAKE3).
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        Self {
            algorithm: HashAlgorithm::Blake3,
            digest: *blake3::hash(data).as_bytes(),
        }
    }

    /// Assemble from parts (decode paths, manifest readers).
    ///
    /// Does not verify that `digest` addresses any content; write paths
    /// obtain ids via [`GrainId::of`].
    #[must_use]
    pub const fn from_parts(algorithm: HashAlgorithm, digest: [u8; DIGEST_LEN]) -> Self {
        Self { algorithm, digest }
    }

    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; DIGEST_LEN] {
        &self.digest
    }

    /// Lowercase hex of the digest alone (64 chars) — local-store
    /// path material. The algorithm tag
    /// is NOT included; the store marker pins the algorithm.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(DIGEST_LEN * 2);
        for b in self.digest() {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Canonical binary form: tag byte, then the digest bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; GRAIN_ID_BINARY_LEN] {
        let mut out = [0u8; GRAIN_ID_BINARY_LEN];
        if let Some((tag, digest)) = out.split_first_mut() {
            *tag = self.algorithm as u8;
            digest.copy_from_slice(&self.digest);
        }
        out
    }

    /// Strict decode of the canonical binary form: exactly
    /// [`GRAIN_ID_BINARY_LEN`] bytes, known tag. Untrusted-input safe:
    /// no panics, no allocation.
    ///
    /// # Errors
    ///
    /// [`ParseGrainIdError::BadLength`] on any length other than
    /// [`GRAIN_ID_BINARY_LEN`]; [`ParseGrainIdError::UnknownAlgorithm`]
    /// on an unregistered tag byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseGrainIdError> {
        let (&tag, digest_bytes) = bytes.split_first().ok_or(ParseGrainIdError::BadLength)?;
        let algorithm = HashAlgorithm::from_tag(tag).ok_or(ParseGrainIdError::UnknownAlgorithm)?;
        let digest: [u8; DIGEST_LEN] = digest_bytes
            .try_into()
            .map_err(|_| ParseGrainIdError::BadLength)?;
        Ok(Self { algorithm, digest })
    }
}

/// Canonical text form: `<algorithm-name>:<lowercase-hex>`.
impl fmt::Display for GrainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.algorithm.name())?;
        for b in self.digest {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Debug prints the canonical text form — a digest dump helps nobody.
impl fmt::Debug for GrainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrainId({self})")
    }
}

/// Strict parse of the canonical text form. Uppercase hex is rejected:
/// the canonical form is lowercase-only (OCI digest grammar precedent).
impl FromStr for GrainId {
    type Err = ParseGrainIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, hex) = s
            .split_once(':')
            .ok_or(ParseGrainIdError::MissingSeparator)?;
        let algorithm =
            HashAlgorithm::from_name(name).ok_or(ParseGrainIdError::UnknownAlgorithm)?;
        if hex.len() != 2 * DIGEST_LEN {
            return Err(ParseGrainIdError::BadLength);
        }
        let mut digest = [0u8; DIGEST_LEN];
        for (out, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let [hi, lo] = pair else {
                return Err(ParseGrainIdError::BadHex); // unreachable: chunks_exact(2)
            };
            *out = (hex_val(*hi)? << 4) | hex_val(*lo)?;
        }
        Ok(Self { algorithm, digest })
    }
}

const fn hex_val(b: u8) -> Result<u8, ParseGrainIdError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(ParseGrainIdError::BadHex),
    }
}

/// Why a `GrainId` failed to parse/decode. Deliberately coarse — parse
/// errors on untrusted input must not leak content details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseGrainIdError {
    /// No `:` separator in the text form.
    MissingSeparator,
    /// Algorithm name or tag byte not in the registry.
    UnknownAlgorithm,
    /// Wrong digest/text/buffer length.
    BadLength,
    /// Non-lowercase-hex character in the digest part.
    BadHex,
}

impl fmt::Display for ParseGrainIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::MissingSeparator => "missing ':' separator",
            Self::UnknownAlgorithm => "unknown hash algorithm",
            Self::BadLength => "wrong length",
            Self::BadHex => "invalid lowercase-hex digest",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for ParseGrainIdError {}

#[cfg(test)]
mod tests;
