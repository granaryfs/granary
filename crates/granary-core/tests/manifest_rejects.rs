// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Manifest rejects corpus.
//! Every tree-walk rule and decode rule gets its own dedicated red vector,
//! asserting the SPECIFIC error variant.
//!
//!
//! OBJECT-level (per-node) rejects build valid bytes via the real
//! encoder and corrupt them where that is possible; several canonical-
//! form violations (duplicate names, `/` or `.gran` in a name, an
//! unregistered entry tag, an over-cap `entry_count`) cannot be produced
//! by the encoder at all — those bodies are hand-built directly, the
//! same technique `manifest::node`'s own decode-reject tests use.
//!
//! Tree-level rejects go through [`manifest::validate_dir_tree`] with a
//! fetch map keyed by each (possibly corrupted) object's REAL id
//! (`GrainId::of(&bytes)`) — the walker hash-verifies every fetch, so
//! keying by an intended-but-wrong id trips `CorruptObject` before the
//! rule under test is ever reached (see
//! `manifest::tree`'s own tests for the same discipline).

use std::collections::BTreeMap;

use granary_core::encoding::{self, Cursor, DecodeError, ObjectType};
use granary_core::hash::GrainId;
use granary_core::manifest::name::SYMLINK_TARGET_MAX;
use granary_core::manifest::{
    DEPTH_MAX, DIR_LEAF_MAX_ENTRIES, DirEntry, ENTRY_TAG_FIFO, ENTRY_TAG_SYMLINK, EncodeNodeError,
    EntryKind, FILE_INLINE_MAX_REFS, FileGrains, GrainListIndexChild, GrainRef, InteriorChild,
    Name, ValidateError, decode_dir_leaf, encode_dir_interior, encode_dir_leaf,
    encode_grain_list_index, encode_grain_list_leaf, validate_dir_tree,
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

/// Raw name field: length-prefixed bytes, UNVALIDATED — the whole point
/// is to embed byte sequences `Name::new` would reject.
fn push_raw_name(out: &mut Vec<u8>, raw: &[u8]) {
    let len = u8::try_from(raw.len()).unwrap_or_else(|e| panic!("name too long for u8 len: {e}"));
    out.push(len);
    out.extend_from_slice(raw);
}

/// One hand-built dir-leaf ENTRY with a Fifo (payload-less) tag — the
/// minimal shape for pinning name-field and ordering rules without
/// dragging in file/dir payload concerns.
fn raw_fifo_entry(raw_name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_raw_name(&mut out, raw_name);
    out.push(ENTRY_TAG_FIFO);
    out
}

fn encoding_open(bytes: &[u8]) -> (ObjectType, Cursor<'_>) {
    encoding::open_envelope(bytes).unwrap_or_else(|e| panic!("{e}"))
}

/// A one-entry directory whose single file has a SPILL payload rooted
/// at `spill_root` — the shortest live path from `validate_dir_tree`
/// into `walk_grain_list`. Returns the directory root id and a fetch
/// map seeded with the leaf (keyed by its real id). `grain_count` is K+1,
/// the smallest count for which spill is the canonical representation.
fn dir_with_spill_file(spill_root: GrainId) -> (GrainId, BTreeMap<GrainId, Vec<u8>>) {
    let grain_count = FILE_INLINE_MAX_REFS + 1;
    let leaf = encode_dir_leaf(&[DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(grain_count),
            grains: FileGrains::Spill {
                grain_count,
                root: spill_root,
            },
        },
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let id = GrainId::of(&leaf);
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(id, leaf);
    (id, map)
}

// ============================================================ object level

#[test]
fn decode_dir_leaf_rejects_unsorted_leaf() {
    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&raw_fifo_entry(b"b"));
    body.extend_from_slice(&raw_fifo_entry(b"a"));
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "entry order (strict memcmp)",
        })
    );
}

#[test]
fn decode_dir_leaf_rejects_duplicate_name_in_one_leaf() {
    let mut body = Vec::new();
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&raw_fifo_entry(b"a"));
    body.extend_from_slice(&raw_fifo_entry(b"a"));
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "entry order (strict memcmp)",
        })
    );
}

#[test]
fn decode_dir_leaf_rejects_entry_count_257() {
    let body = (DIR_LEAF_MAX_ENTRIES + 1).to_be_bytes().to_vec();
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
fn decode_dir_leaf_rejects_name_with_slash_in_stored_bytes() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&raw_fifo_entry(b"a/b"));
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid { what: "name" })
    );
}

#[test]
fn decode_dir_leaf_rejects_gran_prefix_name_in_stored_bytes() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&raw_fifo_entry(b".gran-quirk"));
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid { what: "name" })
    );
}

#[test]
fn decode_dir_leaf_rejects_symlink_target_4097() {
    let over_len = u16::try_from(SYMLINK_TARGET_MAX + 1).unwrap_or_else(|e| panic!("{e}"));
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_raw_name(&mut body, b"s");
    body.push(ENTRY_TAG_SYMLINK);
    body.extend_from_slice(&over_len.to_be_bytes());
    body.extend_from_slice(&vec![b'x'; usize::from(over_len)]);
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid {
            what: "symlink target",
        })
    );
}

#[test]
fn encode_dir_leaf_rejects_inline_129_refs() {
    let refs: Vec<GrainRef> = (0..=FILE_INLINE_MAX_REFS)
        .map(|i| gref(&format!("g{i}"), 1))
        .collect();
    let entries = vec![DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(FILE_INLINE_MAX_REFS) + 1,
            grains: FileGrains::Inline(refs),
        },
    }];
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::InlineOverK {
            count: (FILE_INLINE_MAX_REFS + 1) as usize,
        })
    );
}

#[test]
fn encode_dir_leaf_rejects_spill_count_100() {
    let entries = vec![DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: 100,
            grains: FileGrains::Spill {
                grain_count: 100,
                root: gid("root"),
            },
        },
    }];
    assert_eq!(
        encode_dir_leaf(&entries),
        Err(EncodeNodeError::SpillUnderK { count: 100 })
    );
}

#[test]
fn encode_dir_leaf_rejects_size_ne_sum() {
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
}

/// The decode-side counterpart to `encode_dir_leaf_rejects_size_ne_sum`
/// above: `encode_dir_leaf` refuses to EMIT a size/sum mismatch, but a
/// hostile or corrupted store can still hand a walker bytes where they
/// disagree, and `decode_dir_leaf` has its own explicit check for
/// exactly that (`node.rs`'s `file size vs grain sum` branch) — not
/// redundant with the encode-side test, a genuinely different code
/// path. Build valid `one-file`-shaped bytes on the INLINE path
/// (`grain_count` <= K, so the check is actually reached, not routed to
/// Spill), then corrupt ONLY the 8-byte `size` field in place — the
/// grain ref bytes and overall object length are untouched, so the
/// failure is the size/sum variant, not `Truncated`/`TrailingBytes`.
#[test]
fn decode_dir_leaf_rejects_size_ne_sum() {
    let file_name = name("a");
    let entries = vec![DirEntry {
        name: file_name.clone(),
        kind: EntryKind::File {
            exec: false,
            size: 30,
            grains: FileGrains::Inline(vec![gref("g1", 30)]),
        },
    }];
    let mut bytes = encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));

    // Layout up to the `size` field: envelope(10) + entry_count(4) +
    // name_len(1) + name bytes + tag(1).
    let size_offset = 10 + 4 + 1 + file_name.as_bytes().len() + 1;
    let corrupted_size: u64 = 999; // != the real sum (30)
    let size_field = bytes
        .get_mut(size_offset..size_offset + 8)
        .unwrap_or_else(|| panic!("size field in range"));
    size_field.copy_from_slice(&corrupted_size.to_be_bytes());

    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirLeaf);
    assert_eq!(
        decode_dir_leaf(c),
        Err(DecodeError::Invalid {
            what: "file size vs grain sum",
        })
    );
}

#[test]
fn decode_dir_leaf_rejects_unknown_entry_tag_0x07() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_raw_name(&mut body, b"a");
    body.push(0x07);
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid { what: "entry type" })
    );
}

/// 0x00 is "invalid forever" in the entry-tag registry: it is not
/// an unassigned tag a later version may claim, it is permanently
/// unusable, so a decoder must reject it exactly as it rejects an
/// unknown tag — the sibling of the 0x07 vector above at the other end
/// of the registry.
#[test]
fn decode_dir_leaf_rejects_entry_tag_0x00() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    push_raw_name(&mut body, b"a");
    body.push(0x00);
    assert_eq!(
        decode_dir_leaf(Cursor::new(&body)),
        Err(DecodeError::Invalid { what: "entry type" })
    );
}

#[test]
fn open_envelope_rejects_unknown_object_type_0x0b() {
    // 0x0B is the first tag past the registry (0x05-0x0A landed with
    // the bin, root and sheaf tags — this vector moved off 0x05 when Bin took it, the
    // registry edge following the registry).
    let mut bytes = encoding::MAGIC.to_vec();
    bytes.push(0x0B);
    bytes.push(encoding::VERSION_V1);
    assert_eq!(
        encoding::open_envelope(&bytes).map(|_| ()),
        Err(DecodeError::UnknownObjectType { tag: 0x0B })
    );
}

#[test]
fn open_envelope_rejects_version_0x02() {
    let mut bytes = encoding::MAGIC.to_vec();
    bytes.push(ObjectType::DirLeaf.tag());
    bytes.push(0x02);
    assert_eq!(
        encoding::open_envelope(&bytes).map(|_| ()),
        Err(DecodeError::UnknownVersion { version: 0x02 })
    );
}

#[test]
fn decode_dir_leaf_rejects_trailing_byte() {
    let mut bytes = encode_dir_leaf(&[]).unwrap_or_else(|e| panic!("{e}"));
    bytes.push(0xFF);
    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirLeaf);
    assert_eq!(
        decode_dir_leaf(c),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

/// Totality sweep: `one-file` (the golden case's own shape — name "a",
/// one inline 3-byte grain) truncated at EVERY prefix length must
/// decode Err, never panic and never accidentally succeed on a byte
/// boundary that happens to look like a shorter valid object.
///
/// The buffer swept is `encode_dir_leaf`'s output EXACTLY — the encoder
/// already emits the envelope. Prepending a second one makes
/// `open_envelope` eat the outer header and the decoder read the INNER
/// magic as `entry_count`, so every prefix past the header fails
/// `CapExceeded` on that bogus count and the sweep
/// never reaches a single real field boundary: vacuously green, and
/// green even against a decoder that tolerates mid-entry truncation.
/// The two assertions below are what keep it non-vacuous: the
/// untruncated buffer must decode Ok (so the sweep is over a VALID
/// object), and every prefix past the fixed-size envelope must reach
/// the leaf body (so the boundaries actually exercised are the body's:
/// `entry_count`, name length, name bytes, entry tag, size, grain
/// count, grain id, `unpacked_len`).
#[test]
fn decode_totality_sweep_truncates_one_file_at_every_boundary() {
    let bytes = encode_dir_leaf(&[DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: 3,
            grains: FileGrains::Inline(vec![GrainRef {
                id: GrainId::of(b"abc"),
                unpacked_len: 3,
            }]),
        },
    }])
    .unwrap_or_else(|e| panic!("{e}"));

    let (ty, c) = encoding_open(&bytes);
    assert_eq!(ty, ObjectType::DirLeaf);
    let decoded = decode_dir_leaf(c).unwrap_or_else(|e| panic!("full object must decode: {e}"));
    assert_eq!(
        decoded.len(),
        1,
        "sweep must run over a valid one-file leaf"
    );

    let envelope_len = encoding::envelope(ObjectType::DirLeaf).len();
    let mut reached_body = 0usize;
    for i in 1..bytes.len() {
        let prefix = bytes
            .get(..i)
            .unwrap_or_else(|| panic!("prefix {i} within buffer"));
        let opened = encoding::open_envelope(prefix);
        reached_body += usize::from(opened.is_ok());
        assert!(
            opened.and_then(|(_, c)| decode_dir_leaf(c)).is_err(),
            "prefix length {i} decoded Ok, expected Err"
        );
    }
    assert_eq!(
        reached_body,
        bytes.len() - envelope_len,
        "every prefix past the envelope must truncate inside the leaf body"
    );
}

// ============================================================== tree level

#[test]
fn validate_dir_tree_rejects_cross_leaf_duplicate_name() {
    // C+1 entries in the CANONICAL [129, 128] split, with ONE name
    // straddling the leaf boundary: leaf 2's first entry repeats leaf
    // 1's last. Each leaf is strictly sorted on its own, the interior's
    // first_keys ascend, both subtree counts are truthful, and the fill
    // is exactly the balanced split the builder emits — so rules 1, 3
    // and 5 all pass and ONLY rule 2 (cross-node order, `prev_last >=
    // first`) can reject this. That exactness is the point: a smaller
    // fixture (2 leaves of 2 and 1 entries) is itself non-canonical, so
    // relaxing rule 2 there is masked by rule 3 firing instead, and the
    // vector passes for the wrong reason. Here, relaxing rule 2 to `>`
    // flips this test Err -> Ok.
    let total = DIR_LEAF_MAX_ENTRIES + 1;
    // Canonical split arithmetic, derived not re-literalled:
    // L = ceil(n/C) slices, the first sized ceil(n/L).
    let slices = total.div_ceil(DIR_LEAF_MAX_ENTRIES);
    let first_len = total.div_ceil(slices);
    let second_len = total - first_len;
    let entries: Vec<DirEntry> = (0..total)
        .map(|i| {
            // Index `first_len` is leaf 2's first entry; give it leaf
            // 1's last name.
            let n = if i == first_len { first_len - 1 } else { i };
            DirEntry {
                name: name(&format!("n{n:05}")),
                kind: EntryKind::Fifo,
            }
        })
        .collect();
    let (part_1, part_2) = entries.split_at(first_len as usize);
    assert_eq!(part_1.len(), first_len as usize);
    assert_eq!(part_2.len(), second_len as usize);
    assert_eq!(
        part_1.last().map(|e| &e.name),
        part_2.first().map(|e| &e.name),
        "the duplicate must straddle the leaf boundary",
    );

    let leaf1 = encode_dir_leaf(part_1).unwrap_or_else(|e| panic!("{e}"));
    let leaf1_id = GrainId::of(&leaf1);
    let leaf2 = encode_dir_leaf(part_2).unwrap_or_else(|e| panic!("{e}"));
    let leaf2_id = GrainId::of(&leaf2);

    let first_key_of = |part: &[DirEntry]| {
        part.first()
            .unwrap_or_else(|| panic!("part nonempty"))
            .name
            .clone()
    };
    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: first_key_of(part_1),
            child: leaf1_id,
            subtree_entry_count: u64::from(first_len),
        },
        InteriorChild {
            first_key: first_key_of(part_2),
            child: leaf2_id,
            subtree_entry_count: u64::from(second_len),
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&interior);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(leaf1_id, leaf1);
    map.insert(leaf2_id, leaf2);
    map.insert(root_id, interior);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::CrossNodeOrder);
}

#[test]
fn validate_dir_tree_rejects_separator_mismatch() {
    let leaf1 = encode_dir_leaf(&[
        DirEntry {
            name: name("a"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("b"),
            kind: EntryKind::Fifo,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let leaf1_id = GrainId::of(&leaf1);
    let leaf2 = encode_dir_leaf(&[DirEntry {
        name: name("z"),
        kind: EntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let leaf2_id = GrainId::of(&leaf2);

    // Interior CLAIMS leaf2's first entry is "y" — leaf2's real first
    // (and only) entry is "z". "y" < "z" keeps the interior's own
    // strictly-ascending check happy, so this is caught only at
    // tree-walk (rule 1), not at decode.
    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: name("a"),
            child: leaf1_id,
            subtree_entry_count: 2,
        },
        InteriorChild {
            first_key: name("y"),
            child: leaf2_id,
            subtree_entry_count: 1,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&interior);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(leaf1_id, leaf1);
    map.insert(leaf2_id, leaf2);
    map.insert(root_id, interior);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::SeparatorMismatch);
}

#[test]
fn validate_dir_tree_rejects_count_mismatch() {
    let leaf1 = encode_dir_leaf(&[
        DirEntry {
            name: name("a"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("b"),
            kind: EntryKind::Fifo,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let leaf1_id = GrainId::of(&leaf1);
    let leaf2 = encode_dir_leaf(&[DirEntry {
        name: name("z"),
        kind: EntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let leaf2_id = GrainId::of(&leaf2);

    // Interior claims leaf1 covers 3 entries; it really covers 2.
    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: name("a"),
            child: leaf1_id,
            subtree_entry_count: 3,
        },
        InteriorChild {
            first_key: name("z"),
            child: leaf2_id,
            subtree_entry_count: 1,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&interior);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(leaf1_id, leaf1);
    map.insert(leaf2_id, leaf2);
    map.insert(root_id, interior);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::CountMismatch);
}

#[test]
fn validate_dir_tree_rejects_17_deep_chain() {
    // DEPTH_MAX = 16: a chain of 16 interiors wrapping a MISSING leaf
    // (never resolved — depth is exceeded on the would-be 17th
    // descent, before the walker ever needs to fetch it).
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut next_child = gid("past-the-cap-unreachable");
    for level in (1..=DEPTH_MAX).rev() {
        let children = vec![
            InteriorChild {
                first_key: name("a"),
                child: next_child,
                subtree_entry_count: 1,
            },
            InteriorChild {
                first_key: name("b"),
                child: gid(&format!("sibling-{level}")),
                subtree_entry_count: 1,
            },
        ];
        let bytes = encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
        let id = GrainId::of(&bytes);
        map.insert(id, bytes);
        next_child = id;
    }
    let root = next_child;

    let err = validate_dir_tree(&root, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::DepthExceeded);
}

/// The grain-list twin of the 17-deep chain above: `walk_grain_list`
/// carries its OWN depth budget (a spill tree is its own tree, rule 4),
/// and its cap needs its own vector — the dir-side test cannot reach
/// it. Sixteen indexes wrapping a MISSING leaf: depth is exceeded on
/// the would-be 17th descent, before that leaf is ever fetched, and
/// before the cumulative check on the way back up.
#[test]
fn validate_dir_tree_rejects_17_deep_grain_list_chain() {
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut next_child = gid("past-the-cap-unreachable-grain-list");
    for level in (1..=DEPTH_MAX).rev() {
        let children = vec![
            GrainListIndexChild {
                child: next_child,
                cum_unpacked_len: 1,
                cum_ref_count: 1,
            },
            GrainListIndexChild {
                child: gid(&format!("gl-sibling-{level}")),
                cum_unpacked_len: 2,
                cum_ref_count: 2,
            },
        ];
        let bytes = encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
        let id = GrainId::of(&bytes);
        map.insert(id, bytes);
        next_child = id;
    }

    let (root_id, dir_nodes) = dir_with_spill_file(next_child);
    map.extend(dir_nodes);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::DepthExceeded);
}

/// `WrongObjectType`, dir direction: a GRAIN-LIST object hung under a
/// directory interior as if it were a directory node. The object is
/// well-formed and keyed by its real id, so neither `MissingObject` nor
/// `CorruptObject` fires first — the walk gets as far as dispatching on
/// the envelope's type tag, which is the arm under test.
#[test]
fn validate_dir_tree_rejects_grain_list_object_where_dir_node_expected() {
    let grain_list =
        encode_grain_list_leaf(&[gref("g0", 1), gref("g1", 1)]).unwrap_or_else(|e| panic!("{e}"));
    let grain_list_id = GrainId::of(&grain_list);

    let sibling = encode_dir_leaf(&[DirEntry {
        name: name("z"),
        kind: EntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let sibling_id = GrainId::of(&sibling);

    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: name("a"),
            child: grain_list_id,
            subtree_entry_count: 1,
        },
        InteriorChild {
            first_key: name("z"),
            child: sibling_id,
            subtree_entry_count: 1,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&interior);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(grain_list_id, grain_list);
    map.insert(sibling_id, sibling);
    map.insert(root_id, interior);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::WrongObjectType { id: grain_list_id });
}

/// `WrongObjectType`, grain-list direction: a file's spill root
/// resolves to a DIRECTORY object. Same discipline as its twin above —
/// the object is well-formed and keyed by its real id, so the type
/// dispatch in `walk_grain_list` is what rejects it.
#[test]
fn validate_dir_tree_rejects_dir_object_where_grain_list_node_expected() {
    let stray_dir = encode_dir_leaf(&[DirEntry {
        name: name("x"),
        kind: EntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let stray_dir_id = GrainId::of(&stray_dir);

    let (root_id, mut map) = dir_with_spill_file(stray_dir_id);
    map.insert(stray_dir_id, stray_dir);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::WrongObjectType { id: stray_dir_id });
}

/// `MissingObject` on a LIVE path: the 17-deep chain above never
/// reaches its absent leaf (depth stops it first), so nothing pinned
/// this variant. Here the walk descends into a subdirectory whose id is
/// simply not in the store.
#[test]
fn validate_dir_tree_rejects_missing_object() {
    let absent = gid("no-such-object");
    let leaf = encode_dir_leaf(&[DirEntry {
        name: name("d"),
        kind: EntryKind::Dir { child: absent },
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let leaf_id = GrainId::of(&leaf);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(leaf_id, leaf);

    let err = validate_dir_tree(&leaf_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::MissingObject { id: absent });
}

#[test]
#[expect(
    clippy::similar_names,
    reason = "leaf_a/leaf_b naming is intentionally parallel (tree.rs precedent)"
)]
fn validate_dir_tree_rejects_non_canonical_fill_130_127_split() {
    // C+1 entries (C = DIR_LEAF_MAX_ENTRIES); canonical split is
    // [129, 128]. Hand-build a WRONG-but-internally-consistent
    // [130, 127] split instead: separators/counts are individually
    // correct for THIS split (so rules 1/2/5 all pass), only rule 3
    // (fill canonicity) can catch it — Warning 2's non-canonical-fill
    // vector. 130 and 127 are deliberately the WRONG split (chosen to
    // differ from the canonical [129, 128]), not frozen constants —
    // they stay literal on purpose; only the total is derived.
    let total = DIR_LEAF_MAX_ENTRIES + 1;
    let entries: Vec<DirEntry> = (0..total)
        .map(|i| DirEntry {
            name: name(&format!("n{i:05}")),
            kind: EntryKind::Fifo,
        })
        .collect();
    let (part_a, part_b) = entries.split_at(130);
    assert_eq!(part_a.len(), 130);
    assert_eq!(part_b.len(), 127);

    let leaf_a = encode_dir_leaf(part_a).unwrap_or_else(|e| panic!("{e}"));
    let leaf_a_id = GrainId::of(&leaf_a);
    let leaf_b = encode_dir_leaf(part_b).unwrap_or_else(|e| panic!("{e}"));
    let leaf_b_id = GrainId::of(&leaf_b);

    let first_a = part_a
        .first()
        .unwrap_or_else(|| panic!("part_a nonempty"))
        .name
        .clone();
    let first_b = part_b
        .first()
        .unwrap_or_else(|| panic!("part_b nonempty"))
        .name
        .clone();

    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: first_a,
            child: leaf_a_id,
            subtree_entry_count: 130,
        },
        InteriorChild {
            first_key: first_b,
            child: leaf_b_id,
            subtree_entry_count: 127,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&interior);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(leaf_a_id, leaf_a);
    map.insert(leaf_b_id, leaf_b);
    map.insert(root_id, interior);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::FillNotCanonical);

    // Consensus split, not a cosmetic one: the canonical build of the
    // SAME entry set hashes to a DIFFERENT root ([129, 128]).
    let canonical = granary_core::manifest::build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(canonical.root, root_id);
}
