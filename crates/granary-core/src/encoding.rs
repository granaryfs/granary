// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Object envelope + strict decode cursor for hashed formats.
//! Big-endian fixed-width
//! integers only; every read is bounds-checked; no allocation before
//! its length is validated against a cap.

/// 8-byte object magic (`GRANARY\0`; renamed from the pre-naming
/// `ANA\x01` at the v1 envelope freeze). Eight bytes ending in NUL
/// rather than four: a bare `GRAN` also matches ordinary text.
pub const MAGIC: [u8; 8] = *b"GRANARY\0";
/// The version byte every object this crate writes carries.
pub const VERSION_V1: u8 = 0x01;

/// Fixed prefix every hashed object starts with: [`MAGIC`] + type tag +
/// version byte. New object-size ceilings derive from this rather than
/// re-literalling `10`; the older fixed-header constants (`binfmt.rs`,
/// `binmap.rs`, `sheaf.rs`) predate it and still spell the `10` out,
/// each pinned by its own frozen-value assert.
pub(crate) const HASHED_OBJECT_ENVELOPE_LEN: usize = MAGIC.len() + 2;

/// Hashed-object type registry: 0x00 invalid forever; tags
/// never reused or renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    DirLeaf = 0x01,
    DirInterior = 0x02,
    GrainListLeaf = 0x03,
    GrainListIndex = 0x04,
    /// Grain container: index-first frames.
    Bin = 0x05,
    /// Binmap root: `prefix_bits` + bin-table ref + shard refs.
    BinmapIndex = 0x06,
    /// Append-only bin-id table the shard entries' ordinals point into.
    BinTable = 0x07,
    /// One binmap shard: sorted grain→extent entries (49 B/entry).
    BinmapShard = 0x08,
    /// Signed volume root (spec §11). The one signed object type.
    Root = 0x09,
    /// Commit record: ops + parent pointer + resulting root (spec §6).
    Sheaf = 0x0A,
}

impl ObjectType {
    /// Registry closure — the exhaustive-match test forces every new
    /// variant through tag/parse coverage in one place.
    pub const ALL: &'static [Self] = &[
        Self::DirLeaf,
        Self::DirInterior,
        Self::GrainListLeaf,
        Self::GrainListIndex,
        Self::Bin,
        Self::BinmapIndex,
        Self::BinTable,
        Self::BinmapShard,
        Self::Root,
        Self::Sheaf,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// # Errors
    /// [`DecodeError::UnknownObjectType`] for any unregistered tag.
    pub fn from_tag(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            0x01 => Ok(Self::DirLeaf),
            0x02 => Ok(Self::DirInterior),
            0x03 => Ok(Self::GrainListLeaf),
            0x04 => Ok(Self::GrainListIndex),
            0x05 => Ok(Self::Bin),
            0x06 => Ok(Self::BinmapIndex),
            0x07 => Ok(Self::BinTable),
            0x08 => Ok(Self::BinmapShard),
            0x09 => Ok(Self::Root),
            0x0A => Ok(Self::Sheaf),
            other => Err(DecodeError::UnknownObjectType { tag: other }),
        }
    }
}

/// Decode failure. Every variant names what was violated — an unknown
/// object type or version fails resolution of that object and its subtree,
/// and the distinct error propagates to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input shorter than a fixed-size read required.
    Truncated,
    /// Bytes remained after the body — strict decode forbids it.
    TrailingBytes {
        remaining: usize,
    },
    BadMagic,
    UnknownObjectType {
        tag: u8,
    },
    UnknownVersion {
        version: u8,
    },
    /// A count or length field exceeded its frozen cap.
    CapExceeded {
        what: &'static str,
        got: u64,
        cap: u64,
    },
    /// A value field violated its validation rule.
    Invalid {
        what: &'static str,
    },
    /// Grain-frame `framing` discriminator is reserved-nonzero: a v1
    /// reader MUST refuse it by name — never skip, never guess
    /// (a reader that skips unknown framing
    /// silently corrupts the one guarantee the field versions).
    UnsupportedFraming {
        framing: u8,
    },
    /// Grain-frame `dict_id` is reserved-nonzero in v1: dictionaries
    /// deploy later via this field; readers
    /// ship dict support BEFORE any writer emits nonzero (F5 fleet
    /// rule), so today nonzero is refused by name.
    UnsupportedDictId {
        dict_id: u32,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated object"),
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing bytes after object body")
            }
            Self::BadMagic => write!(f, "bad magic (not a granary object)"),
            Self::UnknownObjectType { tag } => write!(f, "unknown object type 0x{tag:02x}"),
            Self::UnknownVersion { version } => write!(f, "unknown format version {version}"),
            Self::CapExceeded { what, got, cap } => {
                write!(f, "{what} = {got} exceeds cap {cap}")
            }
            Self::Invalid { what } => write!(f, "invalid {what}"),
            Self::UnsupportedFraming { framing } => {
                write!(f, "unsupported grain framing {framing} (v1 accepts only 0)")
            }
            Self::UnsupportedDictId { dict_id } => {
                write!(f, "unsupported dict_id {dict_id} (v1 accepts only 0)")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Strict big-endian read cursor. Never panics; never reads past the
/// end; the caller asserts emptiness at the end (`finish`).
#[derive(Debug)]
pub struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(DecodeError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    /// # Errors
    /// [`DecodeError::Truncated`] if the input is exhausted.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        self.take(1)?.first().copied().ok_or(DecodeError::Truncated)
    }

    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than 2 bytes remain.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let b: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u16::from_be_bytes(b))
    }

    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than 4 bytes remain.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than 8 bytes remain.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u64::from_be_bytes(b))
    }

    /// Strict-decode terminator: fails unless every byte was consumed.
    ///
    /// # Errors
    /// [`DecodeError::TrailingBytes`] if any input remains.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                remaining: self.rest.len(),
            })
        }
    }

    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.rest.len()
    }
}

/// Encode-side helper: the envelope prefix for an object body.
#[must_use]
pub fn envelope(object_type: ObjectType) -> Vec<u8> {
    let mut out = Vec::with_capacity(HASHED_OBJECT_ENVELOPE_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(object_type.tag());
    out.push(VERSION_V1);
    out
}

/// Decode-side: check magic/type/version, return (type, body cursor).
///
/// # Errors
/// [`DecodeError::Truncated`] on inputs shorter than the envelope;
/// [`DecodeError::BadMagic`], [`DecodeError::UnknownObjectType`], or
/// [`DecodeError::UnknownVersion`] when the respective field is wrong.
pub fn open_envelope(bytes: &[u8]) -> Result<(ObjectType, Cursor<'_>), DecodeError> {
    let mut c = Cursor::new(bytes);
    if c.take(8)? != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let ty = ObjectType::from_tag(c.u8()?)?;
    let version = c.u8()?;
    if version != VERSION_V1 {
        return Err(DecodeError::UnknownVersion { version });
    }
    Ok((ty, c))
}

#[cfg(test)]
mod tests;
