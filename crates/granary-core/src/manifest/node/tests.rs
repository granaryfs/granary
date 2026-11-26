// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::manifest::node` — encode/decode for the four manifest object types.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::encoding::{Cursor, DecodeError, ObjectType};
use crate::hash::GrainId;
use crate::manifest::name::SYMLINK_TARGET_MAX;
use crate::manifest::{
    DIR_INTERIOR_MAX_CHILDREN, DIR_LEAF_MAX_ENTRIES, FILE_INLINE_MAX_REFS, GRAIN_UNPACKED_MAX,
    GRAINLIST_INDEX_MAX_CHILDREN, GRAINLIST_LEAF_MAX_REFS, MANIFEST_NODE_MAX_BYTES, Name,
    SymlinkTarget,
};

fn name(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).unwrap_or_else(|e| panic!("{e}"))
}

fn gid(s: &str) -> GrainId {
    GrainId::of(s.as_bytes())
}

fn gref(seed: &str, len: u32) -> GrainRef {
    GrainRef {
        id: gid(seed),
        unpacked_len: len,
    }
}

fn push_name(out: &mut Vec<u8>, n: &Name) {
    out.push(n.wire_len());
    out.extend_from_slice(n.as_bytes());
}

/// Raw interior child bytes: `first_key_len | first_key | child_id
/// | subtree_entry_count` — for hand-built decode-reject bodies.
fn push_interior_child_raw(out: &mut Vec<u8>, key: &Name, child: &GrainId, subtree_count: u64) {
    push_name(out, key);
    out.extend_from_slice(&child.to_bytes());
    out.extend_from_slice(&subtree_count.to_be_bytes());
}

// ------------------------------------------------------ roundtrips

#[test]
fn dir_leaf_roundtrip_empty() {
    let entries: Vec<DirEntry> = vec![];
    let bytes = encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirLeaf);
    let decoded = decode_dir_leaf(c).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decoded, entries);
    let re = encode_dir_leaf(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);
}

#[test]
fn dir_leaf_roundtrip_all_entry_kinds() {
    let entries = vec![
        DirEntry {
            name: name("a"),
            kind: EntryKind::Dir {
                child: gid("a-child"),
            },
        },
        DirEntry {
            name: name("b"),
            kind: EntryKind::File {
                exec: false,
                size: 30,
                grains: FileGrains::Inline(vec![gref("b1", 10), gref("b2", 20)]),
            },
        },
        DirEntry {
            name: name("c"),
            kind: EntryKind::File {
                exec: true,
                size: 5,
                grains: FileGrains::Inline(vec![gref("c1", 5)]),
            },
        },
        DirEntry {
            name: name("d"),
            kind: EntryKind::File {
                exec: false,
                size: 999,
                grains: FileGrains::Spill {
                    grain_count: 200,
                    root: gid("d-root"),
                },
            },
        },
        DirEntry {
            name: name("e"),
            kind: EntryKind::Symlink {
                target: SymlinkTarget::new(b"../target".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            },
        },
        DirEntry {
            name: name("f"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("g"),
            kind: EntryKind::Socket,
        },
    ];
    let bytes = encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirLeaf);
    let decoded = decode_dir_leaf(c).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decoded, entries);
    let re = encode_dir_leaf(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);
}

/// Pins the inline/spill K boundary ON THE DECODE PATH: exactly K
/// grains must decode as `Inline` with K refs, K+1 must decode as
/// `Spill` — a `<=` -> `<` (or `<` -> `<=`) flip in the decoder's
/// branch would route the K case to `Spill` (or vice versa) and
/// this test would fail on the `FileGrains` match, not merely on
/// count.
#[test]
fn dir_leaf_file_pins_inline_spill_decode_boundary() {
    let inline_refs: Vec<GrainRef> = (0..FILE_INLINE_MAX_REFS)
        .map(|i| gref(&format!("k{i}"), 1))
        .collect();
    let entries = vec![DirEntry {
        name: name("at-k"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(FILE_INLINE_MAX_REFS),
            grains: FileGrains::Inline(inline_refs),
        },
    }];
    let bytes = encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirLeaf);
    let decoded = decode_dir_leaf(c).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decoded, entries);
    let [entry] = decoded.as_slice() else {
        panic!("expected exactly one decoded entry");
    };
    match &entry.kind {
        EntryKind::File { grains, .. } => match grains {
            FileGrains::Inline(refs) => {
                assert_eq!(refs.len(), FILE_INLINE_MAX_REFS as usize);
            }
            FileGrains::Spill { .. } => panic!("K grains must decode as Inline, not Spill"),
        },
        other => panic!("expected File entry, got {other:?}"),
    }
    let re = encode_dir_leaf(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);

    let entries = vec![DirEntry {
        name: name("over-k"),
        kind: EntryKind::File {
            exec: false,
            size: 12345,
            grains: FileGrains::Spill {
                grain_count: FILE_INLINE_MAX_REFS + 1,
                root: gid("over-k-root"),
            },
        },
    }];
    let bytes = encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirLeaf);
    let decoded = decode_dir_leaf(c).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decoded, entries);
    let [entry] = decoded.as_slice() else {
        panic!("expected exactly one decoded entry");
    };
    match &entry.kind {
        EntryKind::File { grains, .. } => match grains {
            FileGrains::Spill { grain_count, .. } => {
                assert_eq!(*grain_count, FILE_INLINE_MAX_REFS + 1);
            }
            FileGrains::Inline(refs) => {
                panic!(
                    "K+1 grains must decode as Spill, not Inline({})",
                    refs.len()
                )
            }
        },
        other => panic!("expected File entry, got {other:?}"),
    }
    let re = encode_dir_leaf(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);
}

#[test]
fn dir_interior_roundtrip() {
    let children = vec![
        InteriorChild {
            first_key: name("a"),
            child: gid("child-a"),
            subtree_entry_count: 5,
        },
        InteriorChild {
            first_key: name("m"),
            child: gid("child-m"),
            subtree_entry_count: 7,
        },
        InteriorChild {
            first_key: name("z"),
            child: gid("child-z"),
            subtree_entry_count: 1,
        },
    ];
    let bytes = encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirInterior);
    let decoded = decode_dir_interior(c).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decoded, children);
    let re = encode_dir_interior(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);
}

#[test]
fn grain_list_leaf_roundtrip() {
    let refs = vec![gref("r1", 10), gref("r2", 20), gref("r3", 30)];
    let bytes = encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::GrainListLeaf);
    let decoded = decode_grain_list_leaf(c).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decoded, refs);
    let re = encode_grain_list_leaf(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);
}

#[test]
fn grain_list_index_roundtrip() {
    let children = vec![
        GrainListIndexChild {
            child: gid("idx-a"),
            cum_unpacked_len: 100,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: gid("idx-b"),
            cum_unpacked_len: 250,
            cum_ref_count: 25,
        },
    ];
    let bytes = encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::GrainListIndex);
    let decoded = decode_grain_list_index(c).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decoded, children);
    let re = encode_grain_list_index(&decoded).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(re, bytes);
}

/// Test-local wrapper: `open_envelope` returning an owned-lifetime
/// friendly pair for the roundtrip tests above.
fn encoding_open(bytes: &[u8]) -> (ObjectType, Cursor<'_>) {
    crate::encoding::open_envelope(bytes).unwrap_or_else(|e| panic!("{e}"))
}

// -------------------------------------------------------- max sizes

/// The maximal grain-list INDEX is the widest legal manifest
/// STRUCTURE node — [`MANIFEST_NODE_MAX_BYTES`]'s own doc names it
/// the dominant term. Pinned by actually ENCODING one, not by
/// re-deriving the arithmetic a second time, so encoder drift away
/// from the const expression shows up as a length mismatch here
/// instead of staying silent (N and the index fanout are both far
/// too large to materialize as a literal vector to compare against).
#[test]
fn a_maximal_grain_list_index_is_exactly_manifest_node_max_bytes() {
    let child = gid("c");
    let children: Vec<GrainListIndexChild> = (1..=u64::from(GRAINLIST_INDEX_MAX_CHILDREN))
        .map(|i| GrainListIndexChild {
            child,
            cum_unpacked_len: i,
            cum_ref_count: i,
        })
        .collect();
    let bytes = encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(bytes.len(), MANIFEST_NODE_MAX_BYTES as usize);
}

/// The other structure-node shape a fetch can encounter, against the
/// same ceiling: a maximal grain-list LEAF stays STRICTLY under it —
/// the index above, not this one, is the dominant term, and `<`
/// (never `<=`) is what pins that dominance claim.
#[test]
fn a_maximal_grain_list_leaf_fits_under_manifest_node_max_bytes() {
    let refs = vec![gref("g", 1); GRAINLIST_LEAF_MAX_REFS as usize];
    let bytes = encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
    assert!(bytes.len() < MANIFEST_NODE_MAX_BYTES as usize);
}

/// The dir shapes against the same ceiling, built FROM the caps so a
/// future cap change re-sizes the fixture with it: a maximal dir
/// LEAF is 256 entries of maximal names, each a file holding
/// `FILE_INLINE_MAX_REFS` inline refs (the widest entry kind —
/// wider than a maximal symlink). If a cap bump ever pushed this
/// past the grain-list index, dominance would flip and the ceiling
/// would silently under-declare dir fetches — this row goes red
/// instead.
#[test]
fn a_maximal_dir_leaf_fits_under_manifest_node_max_bytes() {
    let entries: Vec<DirEntry> = (0..DIR_LEAF_MAX_ENTRIES)
        .map(|i| {
            let mut raw = vec![b'a'; 253];
            raw.push(b'a' + u8::try_from(i / 16).unwrap_or_else(|e| panic!("{e}")));
            raw.push(b'a' + u8::try_from(i % 16).unwrap_or_else(|e| panic!("{e}")));
            DirEntry {
                name: Name::new(raw).unwrap_or_else(|e| panic!("{e}")),
                kind: EntryKind::File {
                    exec: false,
                    size: u64::from(FILE_INLINE_MAX_REFS),
                    grains: FileGrains::Inline(vec![gref("g", 1); FILE_INLINE_MAX_REFS as usize]),
                },
            }
        })
        .collect();
    let bytes = encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert!(bytes.len() < MANIFEST_NODE_MAX_BYTES as usize);
}

/// A maximal dir INTERIOR (256 children, maximal first keys) — the
/// smallest of the four shapes, pinned anyway so every shape the
/// ceiling's doc names has an executed bound.
#[test]
fn a_maximal_dir_interior_fits_under_manifest_node_max_bytes() {
    let children: Vec<InteriorChild> = (0..DIR_INTERIOR_MAX_CHILDREN)
        .map(|i| {
            let mut raw = vec![b'a'; 253];
            raw.push(b'a' + u8::try_from(i / 16).unwrap_or_else(|e| panic!("{e}")));
            raw.push(b'a' + u8::try_from(i % 16).unwrap_or_else(|e| panic!("{e}")));
            InteriorChild {
                first_key: Name::new(raw).unwrap_or_else(|e| panic!("{e}")),
                child: gid("c"),
                subtree_entry_count: 1,
            }
        })
        .collect();
    let bytes = encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
    assert!(bytes.len() < MANIFEST_NODE_MAX_BYTES as usize);
}

// ---------------------------------------------------- encode rejects

#[test]
fn encode_dir_leaf_rejects_too_many_entries() {
    let entries: Vec<DirEntry> = (0..=DIR_LEAF_MAX_ENTRIES)
        .map(|i| DirEntry {
            name: name(&format!("n{i:05}")),
            kind: EntryKind::Fifo,
        })
        .collect();
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::TooManyEntries {
            count: entries.len(),
            cap: DIR_LEAF_MAX_ENTRIES,
        })
    );
}

#[test]
fn encode_dir_leaf_rejects_unsorted_and_duplicate() {
    let unsorted = vec![
        DirEntry {
            name: name("b"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("a"),
            kind: EntryKind::Fifo,
        },
    ];
    assert_eq!(
        encode_dir_leaf(&unsorted),
        Err(EncodeNodeError::NotStrictlySorted)
    );
    let duplicate = vec![
        DirEntry {
            name: name("a"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("a"),
            kind: EntryKind::Fifo,
        },
    ];
    assert_eq!(
        encode_dir_leaf(&duplicate),
        Err(EncodeNodeError::NotStrictlySorted)
    );
}

#[test]
fn encode_file_payload_rejects_inline_over_k_and_spill_under_k() {
    let too_many_inline: Vec<GrainRef> = (0..=FILE_INLINE_MAX_REFS)
        .map(|i| gref(&format!("s{i}"), 1))
        .collect();
    let entries = vec![DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(FILE_INLINE_MAX_REFS) + 1,
            grains: FileGrains::Inline(too_many_inline.clone()),
        },
    }];
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::InlineOverK {
            count: too_many_inline.len(),
        })
    );

    let entries = vec![DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: 10,
            grains: FileGrains::Spill {
                grain_count: FILE_INLINE_MAX_REFS,
                root: gid("root"),
            },
        },
    }];
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::SpillUnderK {
            count: FILE_INLINE_MAX_REFS,
        })
    );
}

#[test]
fn encode_file_payload_rejects_size_mismatch_and_bad_grain_len() {
    let entries = vec![DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: 100,
            grains: FileGrains::Inline(vec![gref("g1", 30)]),
        },
    }];
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::SizeMismatch { size: 100, sum: 30 })
    );

    let entries = vec![DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(vec![gref("g1", 0)]),
        },
    }];
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::BadGrainLen { len: 0 })
    );

    let entries = vec![DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(GRAIN_UNPACKED_MAX) + 1,
            grains: FileGrains::Inline(vec![gref("g1", GRAIN_UNPACKED_MAX + 1)]),
        },
    }];
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::BadGrainLen {
            len: GRAIN_UNPACKED_MAX + 1,
        })
    );
}

#[test]
fn encode_grain_list_leaf_rejects_empty_too_many_and_bad_len() {
    assert_eq!(encode_grain_list_leaf(&[]), Err(EncodeNodeError::EmptyList));

    let too_many: Vec<GrainRef> = vec![gref("x", 1); (GRAINLIST_LEAF_MAX_REFS + 1) as usize];
    assert_eq!(
        encode_grain_list_leaf(&too_many),
        Err(EncodeNodeError::TooManyEntries {
            count: too_many.len(),
            cap: GRAINLIST_LEAF_MAX_REFS,
        })
    );

    assert_eq!(
        encode_grain_list_leaf(&[gref("x", 0)]),
        Err(EncodeNodeError::BadGrainLen { len: 0 })
    );
}

#[test]
fn encode_dir_interior_rejects_child_count_bounds() {
    assert_eq!(
        encode_dir_interior(&[]),
        Err(EncodeNodeError::TooFewChildren { count: 0 })
    );
    let one = vec![InteriorChild {
        first_key: name("a"),
        child: gid("a"),
        subtree_entry_count: 1,
    }];
    assert_eq!(
        encode_dir_interior(&one),
        Err(EncodeNodeError::TooFewChildren { count: 1 })
    );

    let too_many: Vec<InteriorChild> = (0..=DIR_INTERIOR_MAX_CHILDREN)
        .map(|i| InteriorChild {
            first_key: name(&format!("n{i:05}")),
            child: gid("x"),
            subtree_entry_count: 1,
        })
        .collect();
    assert_eq!(
        encode_dir_interior(&too_many),
        Err(EncodeNodeError::TooManyEntries {
            count: too_many.len(),
            cap: DIR_INTERIOR_MAX_CHILDREN,
        })
    );
}

#[test]
fn encode_dir_interior_rejects_unsorted() {
    let children = vec![
        InteriorChild {
            first_key: name("b"),
            child: gid("b"),
            subtree_entry_count: 1,
        },
        InteriorChild {
            first_key: name("a"),
            child: gid("a"),
            subtree_entry_count: 1,
        },
    ];
    assert_eq!(
        encode_dir_interior(&children),
        Err(EncodeNodeError::NotStrictlySorted)
    );
}

#[test]
fn encode_dir_interior_rejects_zero_subtree_count() {
    let children = vec![
        InteriorChild {
            first_key: name("a"),
            child: gid("a"),
            subtree_entry_count: 1,
        },
        InteriorChild {
            first_key: name("b"),
            child: gid("b"),
            subtree_entry_count: 0,
        },
    ];
    assert_eq!(
        encode_dir_interior(&children),
        Err(EncodeNodeError::ZeroSubtreeCount)
    );
}

#[test]
fn encode_grain_list_index_rejects_child_count_bounds() {
    assert_eq!(
        encode_grain_list_index(&[]),
        Err(EncodeNodeError::TooFewChildren { count: 0 })
    );
    let one = vec![GrainListIndexChild {
        child: gid("a"),
        cum_unpacked_len: 10,
        cum_ref_count: 1,
    }];
    assert_eq!(
        encode_grain_list_index(&one),
        Err(EncodeNodeError::TooFewChildren { count: 1 })
    );

    let too_many: Vec<GrainListIndexChild> = (0..=GRAINLIST_INDEX_MAX_CHILDREN)
        .map(|i| GrainListIndexChild {
            child: gid("x"),
            cum_unpacked_len: u64::from(i) + 1,
            cum_ref_count: u64::from(i) + 1,
        })
        .collect();
    assert_eq!(
        encode_grain_list_index(&too_many),
        Err(EncodeNodeError::TooManyEntries {
            count: too_many.len(),
            cap: GRAINLIST_INDEX_MAX_CHILDREN,
        })
    );
}

#[test]
fn encode_grain_list_index_rejects_non_increasing() {
    let children = vec![
        GrainListIndexChild {
            child: gid("a"),
            cum_unpacked_len: 100,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: gid("b"),
            cum_unpacked_len: 100,
            cum_ref_count: 20,
        },
    ];
    assert_eq!(
        encode_grain_list_index(&children),
        Err(EncodeNodeError::CumulativeNotIncreasing)
    );
}

// ---------------------------------------------------- decode rejects

#[test]
fn decode_rejects_trailing_byte_all_four_types() {
    let mut dir_leaf = encode_dir_leaf(&[]).unwrap_or_else(|e| panic!("{e}"));
    dir_leaf.push(0xFF);
    let (_, c) = encoding_open(&dir_leaf);
    assert_eq!(
        decode_dir_leaf(c),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );

    let children = vec![
        InteriorChild {
            first_key: name("a"),
            child: gid("a"),
            subtree_entry_count: 1,
        },
        InteriorChild {
            first_key: name("b"),
            child: gid("b"),
            subtree_entry_count: 1,
        },
    ];
    let mut dir_interior = encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
    dir_interior.push(0xFF);
    let (_, c) = encoding_open(&dir_interior);
    assert_eq!(
        decode_dir_interior(c),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );

    let mut leaf = encode_grain_list_leaf(&[gref("a", 1)]).unwrap_or_else(|e| panic!("{e}"));
    leaf.push(0xFF);
    let (_, c) = encoding_open(&leaf);
    assert_eq!(
        decode_grain_list_leaf(c),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );

    let idx_children = vec![
        GrainListIndexChild {
            child: gid("a"),
            cum_unpacked_len: 10,
            cum_ref_count: 1,
        },
        GrainListIndexChild {
            child: gid("b"),
            cum_unpacked_len: 20,
            cum_ref_count: 2,
        },
    ];
    let mut index = encode_grain_list_index(&idx_children).unwrap_or_else(|e| panic!("{e}"));
    index.push(0xFF);
    let (_, c) = encoding_open(&index);
    assert_eq!(
        decode_grain_list_index(c),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn decode_dir_leaf_rejects_count_over_cap() {
    let mut body = Vec::new();
    body.extend_from_slice(&(DIR_LEAF_MAX_ENTRIES + 1).to_be_bytes());
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::CapExceeded {
            what: "dir leaf entry_count",
            got: u64::from(DIR_LEAF_MAX_ENTRIES) + 1,
            cap: u64::from(DIR_LEAF_MAX_ENTRIES),
        })
    );
}

#[test]
fn decode_dir_leaf_rejects_unsorted_and_duplicate_entries() {
    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    push_name(&mut body, &name("b"));
    body.push(ENTRY_TAG_DIR);
    body.extend_from_slice(&gid("b").to_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_DIR);
    body.extend_from_slice(&gid("a").to_bytes());
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "entry order (strict memcmp)",
        })
    );

    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_DIR);
    body.extend_from_slice(&gid("a").to_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_DIR);
    body.extend_from_slice(&gid("a2").to_bytes());
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "entry order (strict memcmp)",
        })
    );
}

#[test]
fn decode_dir_leaf_rejects_unknown_entry_tag() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_name(&mut body, &name("a"));
    body.push(0x07);
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid { what: "entry type" })
    );
}

#[test]
fn decode_dir_leaf_file_rejects_size_mismatch() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_FILE);
    body.extend_from_slice(&100u64.to_be_bytes()); // size
    body.extend_from_slice(&1u32.to_be_bytes()); // grain_count
    body.extend_from_slice(&gid("g").to_bytes());
    body.extend_from_slice(&50u32.to_be_bytes()); // unpacked_len (mismatch)
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "file size vs grain sum",
        })
    );
}

#[test]
fn decode_dir_leaf_file_rejects_bad_grain_len() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_FILE);
    body.extend_from_slice(&0u64.to_be_bytes()); // size
    body.extend_from_slice(&1u32.to_be_bytes()); // grain_count
    body.extend_from_slice(&gid("g").to_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // unpacked_len = 0
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::CapExceeded {
            what: "grain unpacked_len",
            got: 0,
            cap: u64::from(GRAIN_UNPACKED_MAX),
        })
    );

    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_FILE);
    body.extend_from_slice(&0u64.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&gid("g").to_bytes());
    body.extend_from_slice(&(GRAIN_UNPACKED_MAX + 1).to_be_bytes());
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::CapExceeded {
            what: "grain unpacked_len",
            got: u64::from(GRAIN_UNPACKED_MAX) + 1,
            cap: u64::from(GRAIN_UNPACKED_MAX),
        })
    );
}

#[test]
fn decode_dir_leaf_symlink_rejects_bad_len() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_SYMLINK);
    body.extend_from_slice(&0u16.to_be_bytes()); // len 0, no bytes follow
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "symlink target",
        })
    );

    let over_cap_len = SYMLINK_TARGET_MAX + 1;
    let over_cap_len_u16 = u16::try_from(over_cap_len).unwrap_or_else(|e| panic!("{e}"));
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_name(&mut body, &name("a"));
    body.push(ENTRY_TAG_SYMLINK);
    body.extend_from_slice(&over_cap_len_u16.to_be_bytes());
    body.extend_from_slice(&vec![b'x'; over_cap_len]);
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "symlink target",
        })
    );
}

#[test]
fn decode_dir_interior_rejects_child_count_bounds() {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        decode_dir_interior(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "interior child_count (< 2)",
        })
    );

    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        decode_dir_interior(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "interior child_count (< 2)",
        })
    );

    let mut body = Vec::new();
    body.extend_from_slice(&(DIR_INTERIOR_MAX_CHILDREN + 1).to_be_bytes());
    assert_eq!(
        decode_dir_interior(Cursor::new(&body)),
        Err(DecodeError::CapExceeded {
            what: "interior child_count",
            got: u64::from(DIR_INTERIOR_MAX_CHILDREN) + 1,
            cap: u64::from(DIR_INTERIOR_MAX_CHILDREN),
        })
    );
}

#[test]
fn decode_dir_interior_rejects_key_order() {
    // Descending: "b" then "a".
    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    push_interior_child_raw(&mut body, &name("b"), &gid("b"), 1);
    push_interior_child_raw(&mut body, &name("a"), &gid("a"), 1);
    assert_eq!(
        decode_dir_interior(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "interior key order",
        })
    );

    // Duplicate key: "a" then "a".
    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    push_interior_child_raw(&mut body, &name("a"), &gid("a"), 1);
    push_interior_child_raw(&mut body, &name("a"), &gid("a2"), 1);
    assert_eq!(
        decode_dir_interior(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "interior key order",
        })
    );
}

#[test]
fn decode_dir_interior_rejects_zero_subtree_count() {
    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    push_interior_child_raw(&mut body, &name("a"), &gid("a"), 1);
    push_interior_child_raw(&mut body, &name("b"), &gid("b"), 0);
    assert_eq!(
        decode_dir_interior(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "subtree_entry_count (0)",
        })
    );
}

#[test]
fn decode_grain_list_leaf_rejects_count_bounds() {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        decode_grain_list_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "empty grain-list leaf",
        })
    );

    let mut body = Vec::new();
    body.extend_from_slice(&(GRAINLIST_LEAF_MAX_REFS + 1).to_be_bytes());
    assert_eq!(
        decode_grain_list_leaf(Cursor::new(&body)),
        Err(DecodeError::CapExceeded {
            what: "grain-list ref_count",
            got: u64::from(GRAINLIST_LEAF_MAX_REFS) + 1,
            cap: u64::from(GRAINLIST_LEAF_MAX_REFS),
        })
    );
}

#[test]
fn decode_grain_list_index_rejects_child_count_bounds() {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        decode_grain_list_index(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "index child_count (< 2)",
        })
    );

    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        decode_grain_list_index(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "index child_count (< 2)",
        })
    );

    let mut body = Vec::new();
    body.extend_from_slice(&(GRAINLIST_INDEX_MAX_CHILDREN + 1).to_be_bytes());
    assert_eq!(
        decode_grain_list_index(Cursor::new(&body)),
        Err(DecodeError::CapExceeded {
            what: "index child_count",
            got: u64::from(GRAINLIST_INDEX_MAX_CHILDREN) + 1,
            cap: u64::from(GRAINLIST_INDEX_MAX_CHILDREN),
        })
    );
}

#[test]
fn decode_grain_list_index_rejects_non_increasing_cumulative() {
    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&gid("a").to_bytes());
    body.extend_from_slice(&100u64.to_be_bytes());
    body.extend_from_slice(&10u64.to_be_bytes());
    body.extend_from_slice(&gid("b").to_bytes());
    body.extend_from_slice(&100u64.to_be_bytes()); // not strictly increasing
    body.extend_from_slice(&20u64.to_be_bytes());
    assert_eq!(
        decode_grain_list_index(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "cumulative order",
        })
    );
}
