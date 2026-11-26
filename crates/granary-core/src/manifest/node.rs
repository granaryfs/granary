// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Encode/decode for the four manifest object types.
//! Strict, canonical, bounded: every
//! count is validated against its frozen cap before allocation;
//! `encode(decode(b)) == b` for every accepted `b`.

use crate::encoding::{self, Cursor, DecodeError, ObjectType};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use crate::manifest::{
    DIR_INTERIOR_MAX_CHILDREN, DIR_LEAF_MAX_ENTRIES, FILE_INLINE_MAX_REFS, GRAIN_UNPACKED_MAX,
    GRAINLIST_INDEX_MAX_CHILDREN, GRAINLIST_LEAF_MAX_REFS, Name, SymlinkTarget,
};

/// Entry-type registry (0x00 invalid forever).
pub const ENTRY_TAG_DIR: u8 = 0x01;
pub const ENTRY_TAG_FILE: u8 = 0x02;
pub const ENTRY_TAG_EXEC_FILE: u8 = 0x03;
pub const ENTRY_TAG_SYMLINK: u8 = 0x04;
pub const ENTRY_TAG_FIFO: u8 = 0x05; // reserved, never emitted in v1
pub const ENTRY_TAG_SOCKET: u8 = 0x06; // reserved, never emitted in v1

/// One grain reference: id + unpacked length (Xet-extent precedent —
/// bare ids cannot answer byte-offset→grain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrainRef {
    pub id: GrainId,
    pub unpacked_len: u32,
}

/// File grain storage: inline iff count <= K (canonical-form rule,
/// locally checkable because Spill carries the total count).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileGrains {
    Inline(Vec<GrainRef>),
    Spill { grain_count: u32, root: GrainId },
}

impl FileGrains {
    #[must_use]
    pub fn grain_count(&self) -> u32 {
        match self {
            #[expect(clippy::cast_possible_truncation, reason = "inline len <= K = 128")]
            Self::Inline(refs) => refs.len() as u32,
            Self::Spill { grain_count, .. } => *grain_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Dir {
        child: GrainId,
    },
    File {
        exec: bool,
        size: u64,
        grains: FileGrains,
    },
    Symlink {
        target: SymlinkTarget,
    },
    /// Reserved tags — decodable (payload-less), never emitted in v1.
    Fifo,
    Socket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Name,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteriorChild {
    pub first_key: Name,
    pub child: GrainId,
    pub subtree_entry_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrainListIndexChild {
    pub child: GrainId,
    pub cum_unpacked_len: u64,
    pub cum_ref_count: u64,
}

/// Encode error — the canonical encoder refuses to emit format
/// violations (the decoder alone is not the contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeNodeError {
    TooManyEntries { count: usize, cap: u32 },
    NotStrictlySorted,
    InlineOverK { count: usize },
    SpillUnderK { count: u32 },
    SizeMismatch { size: u64, sum: u64 },
    BadGrainLen { len: u32 },
    EmptyList,
    TooFewChildren { count: usize },
    CumulativeNotIncreasing,
    ZeroSubtreeCount,
}

impl std::fmt::Display for EncodeNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyEntries { count, cap } => write!(f, "{count} entries exceeds cap {cap}"),
            Self::NotStrictlySorted => write!(f, "entries not strictly memcmp-ascending"),
            Self::InlineOverK { count } => write!(f, "{count} inline refs exceeds K"),
            Self::SpillUnderK { count } => {
                write!(f, "spill with {count} grains (<= K must inline)")
            }
            Self::SizeMismatch { size, sum } => write!(f, "size {size} != grain sum {sum}"),
            Self::BadGrainLen { len } => write!(f, "grain unpacked_len {len} out of 1..=8MiB"),
            Self::EmptyList => write!(f, "empty grain-list object"),
            Self::TooFewChildren { count } => {
                write!(f, "interior/index with {count} children (< 2)")
            }
            Self::CumulativeNotIncreasing => {
                write!(f, "cumulative fields not strictly increasing")
            }
            Self::ZeroSubtreeCount => {
                write!(f, "interior child claims 0 subtree entries (>= 1 required)")
            }
        }
    }
}

impl std::error::Error for EncodeNodeError {}

fn put_grain_ref(out: &mut Vec<u8>, r: &GrainRef) {
    out.extend_from_slice(&r.id.to_bytes());
    out.extend_from_slice(&r.unpacked_len.to_be_bytes());
}

fn get_grain_id(c: &mut Cursor<'_>) -> Result<GrainId, DecodeError> {
    let raw = c.take(GRAIN_ID_BINARY_LEN)?;
    GrainId::from_bytes(raw).map_err(|_| DecodeError::Invalid { what: "grain id" })
}

fn get_grain_ref(c: &mut Cursor<'_>) -> Result<GrainRef, DecodeError> {
    let id = get_grain_id(c)?;
    let unpacked_len = c.u32()?;
    if unpacked_len == 0 || unpacked_len > GRAIN_UNPACKED_MAX {
        return Err(DecodeError::CapExceeded {
            what: "grain unpacked_len",
            got: u64::from(unpacked_len),
            cap: u64::from(GRAIN_UNPACKED_MAX),
        });
    }
    Ok(GrainRef { id, unpacked_len })
}

fn get_name(c: &mut Cursor<'_>) -> Result<Name, DecodeError> {
    let len = c.u8()?;
    let bytes = c.take(usize::from(len))?;
    Name::new(bytes.to_vec()).map_err(|_| DecodeError::Invalid { what: "name" })
}

/// No-indexing window check (`indexing_slicing` is denied): the
/// `matches!` slice pattern binds both window elements. `pub(crate)`
/// so the bulk-load in `tree` checks strict order with the SAME
/// predicate the codecs enforce — one definition of canonical order per
/// format, no second implementation to drift.
pub(crate) fn check_strictly_sorted<T, K: Ord>(items: &[T], key: impl Fn(&T) -> &K) -> bool {
    items
        .windows(2)
        .all(|w| matches!(w, [a, b] if key(a) < key(b)))
}

// ---------------------------------------------------------------- dir leaf

/// Encode a directory leaf (type 0x01). `entries` must be strictly
/// memcmp-sorted; canonical-form rules enforced here as well as at
/// decode.
///
/// # Errors
/// The [`EncodeNodeError`] variant naming the violated canonical-form
/// rule (cap, sort order, file payload consistency).
pub fn encode_dir_leaf(entries: &[DirEntry]) -> Result<Vec<u8>, EncodeNodeError> {
    if entries.len() > DIR_LEAF_MAX_ENTRIES as usize {
        return Err(EncodeNodeError::TooManyEntries {
            count: entries.len(),
            cap: DIR_LEAF_MAX_ENTRIES,
        });
    }
    if !check_strictly_sorted(entries, |e| &e.name) {
        return Err(EncodeNodeError::NotStrictlySorted);
    }
    let mut out = encoding::envelope(ObjectType::DirLeaf);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "count <= 256 checked above"
    )]
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        out.push(e.name.wire_len());
        out.extend_from_slice(e.name.as_bytes());
        match &e.kind {
            EntryKind::Dir { child } => {
                out.push(ENTRY_TAG_DIR);
                out.extend_from_slice(&child.to_bytes());
            }
            EntryKind::File { exec, size, grains } => {
                out.push(if *exec {
                    ENTRY_TAG_EXEC_FILE
                } else {
                    ENTRY_TAG_FILE
                });
                encode_file_payload(&mut out, *size, grains)?;
            }
            EntryKind::Symlink { target } => {
                out.push(ENTRY_TAG_SYMLINK);
                out.extend_from_slice(&target.wire_len().to_be_bytes());
                out.extend_from_slice(target.as_bytes());
            }
            EntryKind::Fifo => out.push(ENTRY_TAG_FIFO),
            EntryKind::Socket => out.push(ENTRY_TAG_SOCKET),
        }
    }
    Ok(out)
}

/// Canonical file payload, excluding the entry name and executable tag.
/// # Errors
/// Refuses noncanonical grain storage, lengths or size sums.
pub fn file_payload(size: u64, grains: &FileGrains) -> Result<Vec<u8>, EncodeNodeError> {
    let mut bytes = Vec::new();
    encode_file_payload(&mut bytes, size, grains)?;
    Ok(bytes)
}

fn encode_file_payload(
    out: &mut Vec<u8>,
    size: u64,
    grains: &FileGrains,
) -> Result<(), EncodeNodeError> {
    match grains {
        FileGrains::Inline(refs) => {
            if refs.len() > FILE_INLINE_MAX_REFS as usize {
                return Err(EncodeNodeError::InlineOverK { count: refs.len() });
            }
            let mut sum: u64 = 0;
            for r in refs {
                if r.unpacked_len == 0 || r.unpacked_len > GRAIN_UNPACKED_MAX {
                    return Err(EncodeNodeError::BadGrainLen {
                        len: r.unpacked_len,
                    });
                }
                sum += u64::from(r.unpacked_len);
            }
            if sum != size {
                return Err(EncodeNodeError::SizeMismatch { size, sum });
            }
            out.extend_from_slice(&size.to_be_bytes());
            #[expect(
                clippy::cast_possible_truncation,
                reason = "refs.len() <= K = 128 checked above"
            )]
            out.extend_from_slice(&(refs.len() as u32).to_be_bytes());
            for r in refs {
                put_grain_ref(out, r);
            }
        }
        FileGrains::Spill { grain_count, root } => {
            if *grain_count <= FILE_INLINE_MAX_REFS {
                return Err(EncodeNodeError::SpillUnderK {
                    count: *grain_count,
                });
            }
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&grain_count.to_be_bytes());
            out.extend_from_slice(&root.to_bytes());
        }
    }
    Ok(())
}

/// Decode a directory leaf. The caller has already gone through
/// `encoding::open_envelope` and dispatched on type.
///
/// # Errors
/// The [`DecodeError`] variant naming the violated rule; strict decode
/// (caps before allocation, exact length, canonical order).
pub fn decode_dir_leaf(mut c: Cursor<'_>) -> Result<Vec<DirEntry>, DecodeError> {
    let count = c.u32()?;
    if count > DIR_LEAF_MAX_ENTRIES {
        return Err(DecodeError::CapExceeded {
            what: "dir leaf entry_count",
            got: u64::from(count),
            cap: u64::from(DIR_LEAF_MAX_ENTRIES),
        });
    }
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name = get_name(&mut c)?;
        let tag = c.u8()?;
        let kind = match tag {
            ENTRY_TAG_DIR => EntryKind::Dir {
                child: get_grain_id(&mut c)?,
            },
            ENTRY_TAG_FILE | ENTRY_TAG_EXEC_FILE => {
                let size = c.u64()?;
                let grain_count = c.u32()?;
                let grains = if grain_count <= FILE_INLINE_MAX_REFS {
                    let mut refs = Vec::with_capacity(grain_count as usize);
                    let mut sum: u64 = 0;
                    for _ in 0..grain_count {
                        let r = get_grain_ref(&mut c)?;
                        sum += u64::from(r.unpacked_len);
                        refs.push(r);
                    }
                    if sum != size {
                        return Err(DecodeError::Invalid {
                            what: "file size vs grain sum",
                        });
                    }
                    FileGrains::Inline(refs)
                } else {
                    FileGrains::Spill {
                        grain_count,
                        root: get_grain_id(&mut c)?,
                    }
                };
                EntryKind::File {
                    exec: tag == ENTRY_TAG_EXEC_FILE,
                    size,
                    grains,
                }
            }
            ENTRY_TAG_SYMLINK => {
                let len = c.u16()?;
                let bytes = c.take(usize::from(len))?;
                let target =
                    SymlinkTarget::new(bytes.to_vec()).map_err(|_| DecodeError::Invalid {
                        what: "symlink target",
                    })?;
                EntryKind::Symlink { target }
            }
            ENTRY_TAG_FIFO => EntryKind::Fifo,
            ENTRY_TAG_SOCKET => EntryKind::Socket,
            _ => return Err(DecodeError::Invalid { what: "entry type" }),
        };
        entries.push(DirEntry { name, kind });
    }
    if !check_strictly_sorted(&entries, |e| &e.name) {
        return Err(DecodeError::Invalid {
            what: "entry order (strict memcmp)",
        });
    }
    c.finish()?;
    Ok(entries)
}

// ------------------------------------------------------------ dir interior

/// Encode a directory interior node (type 0x02).
///
/// # Errors
/// The [`EncodeNodeError`] variant naming the violated rule (child
/// count bounds, strict `first_key` order, zero `subtree_entry_count`).
pub fn encode_dir_interior(children: &[InteriorChild]) -> Result<Vec<u8>, EncodeNodeError> {
    if children.len() < 2 {
        return Err(EncodeNodeError::TooFewChildren {
            count: children.len(),
        });
    }
    if children.len() > DIR_INTERIOR_MAX_CHILDREN as usize {
        return Err(EncodeNodeError::TooManyEntries {
            count: children.len(),
            cap: DIR_INTERIOR_MAX_CHILDREN,
        });
    }
    if !check_strictly_sorted(children, |ch| &ch.first_key) {
        return Err(EncodeNodeError::NotStrictlySorted);
    }
    if children.iter().any(|ch| ch.subtree_entry_count == 0) {
        return Err(EncodeNodeError::ZeroSubtreeCount);
    }
    let mut out = encoding::envelope(ObjectType::DirInterior);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "count <= 256 checked above"
    )]
    out.extend_from_slice(&(children.len() as u32).to_be_bytes());
    for ch in children {
        out.push(ch.first_key.wire_len());
        out.extend_from_slice(ch.first_key.as_bytes());
        out.extend_from_slice(&ch.child.to_bytes());
        out.extend_from_slice(&ch.subtree_entry_count.to_be_bytes());
    }
    Ok(out)
}

/// Decode a directory interior node.
///
/// # Errors
/// The [`DecodeError`] variant naming the violated rule.
pub fn decode_dir_interior(mut c: Cursor<'_>) -> Result<Vec<InteriorChild>, DecodeError> {
    let count = c.u32()?;
    if count < 2 {
        return Err(DecodeError::Invalid {
            what: "interior child_count (< 2)",
        });
    }
    if count > DIR_INTERIOR_MAX_CHILDREN {
        return Err(DecodeError::CapExceeded {
            what: "interior child_count",
            got: u64::from(count),
            cap: u64::from(DIR_INTERIOR_MAX_CHILDREN),
        });
    }
    let mut children = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let first_key = get_name(&mut c)?;
        let child = get_grain_id(&mut c)?;
        let subtree_entry_count = c.u64()?;
        if subtree_entry_count == 0 {
            return Err(DecodeError::Invalid {
                what: "subtree_entry_count (0)",
            });
        }
        children.push(InteriorChild {
            first_key,
            child,
            subtree_entry_count,
        });
    }
    if !check_strictly_sorted(&children, |ch| &ch.first_key) {
        return Err(DecodeError::Invalid {
            what: "interior key order",
        });
    }
    c.finish()?;
    Ok(children)
}

// ------------------------------------------------------------- grain lists

/// Encode a grain-list leaf (type 0x03).
///
/// # Errors
/// The [`EncodeNodeError`] variant naming the violated rule (empty
/// list, cap, grain length bounds).
pub fn encode_grain_list_leaf(refs: &[GrainRef]) -> Result<Vec<u8>, EncodeNodeError> {
    if refs.is_empty() {
        return Err(EncodeNodeError::EmptyList);
    }
    if refs.len() > GRAINLIST_LEAF_MAX_REFS as usize {
        return Err(EncodeNodeError::TooManyEntries {
            count: refs.len(),
            cap: GRAINLIST_LEAF_MAX_REFS,
        });
    }
    for r in refs {
        if r.unpacked_len == 0 || r.unpacked_len > GRAIN_UNPACKED_MAX {
            return Err(EncodeNodeError::BadGrainLen {
                len: r.unpacked_len,
            });
        }
    }
    let mut out = encoding::envelope(ObjectType::GrainListLeaf);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "refs.len() <= N checked above"
    )]
    out.extend_from_slice(&(refs.len() as u32).to_be_bytes());
    for r in refs {
        put_grain_ref(&mut out, r);
    }
    Ok(out)
}

/// Decode a grain-list leaf.
///
/// # Errors
/// The [`DecodeError`] variant naming the violated rule.
pub fn decode_grain_list_leaf(mut c: Cursor<'_>) -> Result<Vec<GrainRef>, DecodeError> {
    let count = c.u32()?;
    if count == 0 {
        return Err(DecodeError::Invalid {
            what: "empty grain-list leaf",
        });
    }
    if count > GRAINLIST_LEAF_MAX_REFS {
        return Err(DecodeError::CapExceeded {
            what: "grain-list ref_count",
            got: u64::from(count),
            cap: u64::from(GRAINLIST_LEAF_MAX_REFS),
        });
    }
    let mut refs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        refs.push(get_grain_ref(&mut c)?);
    }
    c.finish()?;
    Ok(refs)
}

/// Encode a grain-list index (type 0x04).
///
/// # Errors
/// The [`EncodeNodeError`] variant naming the violated rule (child
/// count bounds, strictly increasing cumulative fields).
pub fn encode_grain_list_index(
    children: &[GrainListIndexChild],
) -> Result<Vec<u8>, EncodeNodeError> {
    if children.len() < 2 {
        return Err(EncodeNodeError::TooFewChildren {
            count: children.len(),
        });
    }
    if children.len() > GRAINLIST_INDEX_MAX_CHILDREN as usize {
        return Err(EncodeNodeError::TooManyEntries {
            count: children.len(),
            cap: GRAINLIST_INDEX_MAX_CHILDREN,
        });
    }
    let increasing = children.windows(2).all(|w| {
        matches!(w, [a, b] if a.cum_unpacked_len < b.cum_unpacked_len && a.cum_ref_count < b.cum_ref_count)
    });
    if !increasing {
        return Err(EncodeNodeError::CumulativeNotIncreasing);
    }
    let mut out = encoding::envelope(ObjectType::GrainListIndex);
    #[expect(clippy::cast_possible_truncation, reason = "count <= N checked above")]
    out.extend_from_slice(&(children.len() as u32).to_be_bytes());
    for ch in children {
        out.extend_from_slice(&ch.child.to_bytes());
        out.extend_from_slice(&ch.cum_unpacked_len.to_be_bytes());
        out.extend_from_slice(&ch.cum_ref_count.to_be_bytes());
    }
    Ok(out)
}

/// Decode a grain-list index.
///
/// # Errors
/// The [`DecodeError`] variant naming the violated rule.
pub fn decode_grain_list_index(mut c: Cursor<'_>) -> Result<Vec<GrainListIndexChild>, DecodeError> {
    let count = c.u32()?;
    if count < 2 {
        return Err(DecodeError::Invalid {
            what: "index child_count (< 2)",
        });
    }
    if count > GRAINLIST_INDEX_MAX_CHILDREN {
        return Err(DecodeError::CapExceeded {
            what: "index child_count",
            got: u64::from(count),
            cap: u64::from(GRAINLIST_INDEX_MAX_CHILDREN),
        });
    }
    let mut children = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let child = get_grain_id(&mut c)?;
        let cum_unpacked_len = c.u64()?;
        let cum_ref_count = c.u64()?;
        children.push(GrainListIndexChild {
            child,
            cum_unpacked_len,
            cum_ref_count,
        });
    }
    let increasing = children.windows(2).all(|w| {
        matches!(w, [a, b] if a.cum_unpacked_len < b.cum_unpacked_len && a.cum_ref_count < b.cum_ref_count)
    });
    if !increasing {
        return Err(DecodeError::Invalid {
            what: "cumulative order",
        });
    }
    c.finish()?;
    Ok(children)
}

#[cfg(test)]
mod tests;
