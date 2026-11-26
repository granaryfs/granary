// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Manifest content tree v1.
//! Pure encode/decode/build/validate — no I/O.

use crate::encoding::HASHED_OBJECT_ENVELOPE_LEN;
use crate::hash::GRAIN_ID_BINARY_LEN;

pub mod name;
pub use name::{Name, NameError, SymlinkTarget, SymlinkTargetError};

pub mod node;
// Named exports satisfy `warn-on-all-wildcard-imports`.
// `pub mod node;` also exposes the module itself.
pub use node::{
    DirEntry, ENTRY_TAG_DIR, ENTRY_TAG_EXEC_FILE, ENTRY_TAG_FIFO, ENTRY_TAG_FILE, ENTRY_TAG_SOCKET,
    ENTRY_TAG_SYMLINK, EncodeNodeError, EntryKind, FileGrains, GrainListIndexChild, GrainRef,
    InteriorChild, decode_dir_interior, decode_dir_leaf, decode_grain_list_index,
    decode_grain_list_leaf, encode_dir_interior, encode_dir_leaf, encode_grain_list_index,
    encode_grain_list_leaf,
};

pub mod tree;
// Named, not `pub use tree::*;` — same reason as node's, above.
pub use tree::{
    BuiltTree, HINT_WORK_MAX, Hints, PREFETCH_HINT_MAX, Step, TreeCursor, TreeSource, TreeStats,
    ValidateError, build_dir, build_grain_list, validate_dir_btree, validate_dir_btree_seeded,
    validate_dir_tree,
};

/// Max entries per directory leaf (`C`). Format constant —
/// changing it is a format event.
pub const DIR_LEAF_MAX_ENTRIES: u32 = 256;
/// Max children per directory interior node (`F`).
pub const DIR_INTERIOR_MAX_CHILDREN: u32 = 256;
/// Inline grain refs per file payload; more spills (`K`).
pub const FILE_INLINE_MAX_REFS: u32 = 128;
/// Refs per grain-list leaf (`N`).
pub const GRAINLIST_LEAF_MAX_REFS: u32 = 131_072;
/// Children per grain-list index node.
pub const GRAINLIST_INDEX_MAX_CHILDREN: u32 = 131_072;
/// Max tree depth, directory and grain-list trees.
pub const DEPTH_MAX: u32 = 16;
/// Grain unpacked length ceiling: the FROZEN v1 manifest bound.
/// It is the format's own limit, not a mirror of [`crate::thresh`] —
/// when the grain-ceiling event moved `MAX_GRAIN` from 8 MiB to 2 MiB this
/// did NOT follow, because a v1 reader must keep accepting every grain
/// v1 could ever have encoded. The shipped chunker now sits strictly
/// inside this ceiling.
pub const GRAIN_UNPACKED_MAX: u32 = 8 * 1024 * 1024;

/// Widest byte length ANY legal manifest STRUCTURE node — dir leaf, dir
/// interior, grain-list leaf, grain-list index — can ever encode to. The
/// maximal grain-list INDEX is the dominant term: envelope, plus count
/// field, plus `GRAINLIST_INDEX_MAX_CHILDREN` children at
/// `GRAIN_ID_BINARY_LEN + 8 + 8` bytes each. A maximal grain-list LEAF
/// comes in under it (~4.85 MB), a maximal dir leaf at roughly a fifth
/// of it (~1.28 MB — 256 entries of max-length names holding
/// `FILE_INLINE_MAX_REFS` inline refs each), a maximal dir interior far
/// below that; the per-shape encode pins in `node.rs`'s tests hold each
/// STRICTLY under the index, so a cap change that flipped dominance
/// goes red instead of silently shrinking the reader's acceptance.
///
/// Derived from the v1 format caps, which are FROZEN
/// (`constants_are_frozen`): this ceiling moves only with a format
/// event, never independently — a derived-but-frozen constant, so a
/// hypothetical narrowing of a cap for new writers could not silently
/// make old legal volumes unreadable without the freeze test going red
/// first.
///
/// A structure-node reader that does not yet know an object's true size
/// (no manifest field declares one, unlike a content grain's own
/// `GrainRef.unpacked_len`) charges and declares its fetch at this
/// ceiling — `fetch_tree_structure` in `granary-client` is the one
/// caller. No legal encoder output is ever wider than this, so a fetch
/// that decodes wider is refused as over-declared: the bytes are
/// corrupt or hostile, never a legitimate manifest node.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the const block asserts the u64 value fits before the cast"
)]
pub const MANIFEST_NODE_MAX_BYTES: u32 = {
    let v: u64 = HASHED_OBJECT_ENVELOPE_LEN as u64
        + 4
        + GRAINLIST_INDEX_MAX_CHILDREN as u64 * (GRAIN_ID_BINARY_LEN as u64 + 8 + 8);
    // A compile-time stop, not a runtime one: a future cap change that
    // pushed the true ceiling past u32 would otherwise TRUNCATE here —
    // a silently tiny ceiling refusing every legal node is exactly the
    // failure class this constant exists to close.
    assert!(v <= u32::MAX as u64);
    v as u32
};

// Keeps the fetcher's one-in-flight-decompress residency ceiling
// argument intact: a structure-node fetch must never charge/declare
// more than a content-grain fetch ever could.
const _: () = assert!(MANIFEST_NODE_MAX_BYTES <= GRAIN_UNPACKED_MAX);

#[cfg(test)]
mod tests;
