// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]

//! Unit tests for `crate::manifest::tree` — the balanced bulk-load
//! encoder and the tree-walk validation contract,
//! including the differential harness run against the retained
//! `legacy_validate_dir_tree` oracle.
//!
//! Out-of-line: `granary-core`'s non-test artifact has
//! workspace consumers — nine of the other ten crates,
//! every one except `granary-net`. (This header listed
//! seven when it was first written, which was correct then:
//! `granary-vfs` did not yet exist. Derive the set from
//! `cargo metadata`, not from a sibling header — the same
//! list is restated in nineteen files here and nothing
//! checks any of them.) So the module's own tests move out
//! of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::encoding::{self, DecodeError, ObjectType};
use crate::hash::GrainId;
use crate::manifest::node::{
    self, DirEntry, EntryKind, FileGrains, GrainListIndexChild, GrainRef, InteriorChild,
};
use crate::manifest::{
    DEPTH_MAX, DIR_LEAF_MAX_ENTRIES, EncodeNodeError, FILE_INLINE_MAX_REFS,
    GRAINLIST_LEAF_MAX_REFS, Name, SymlinkTarget,
};
use std::collections::BTreeMap;

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

/// `n` sorted directory entries with no payload (Fifo) — enough to
/// pin structure/validation without dragging in file/dir payload
/// concerns.
fn fifo_entries(n: u32) -> Vec<DirEntry> {
    (0..n)
        .map(|i| DirEntry {
            name: name(&format!("n{i:05}")),
            kind: EntryKind::Fifo,
        })
        .collect()
}

fn dir_leaves(nodes: &[(GrainId, Vec<u8>)]) -> Vec<(GrainId, Vec<u8>)> {
    nodes
        .iter()
        .filter(|(_, b)| {
            let (ty, _) = encoding::open_envelope(b).unwrap_or_else(|e| panic!("{e:?}"));
            ty == ObjectType::DirLeaf
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------- split_counts

#[test]
fn split_counts_matches_worked_examples() {
    assert_eq!(split_counts(257, 256), vec![129, 128]);
    assert_eq!(split_counts(512, 256), vec![256, 256]);

    let big = split_counts(100_000, 256);
    assert_eq!(big.iter().sum::<usize>(), 100_000);
    assert!(big.iter().all(|&x| x == 255 || x == 256));
    let count_256 = big.iter().filter(|&&x| x == 256).count();
    let count_255 = big.iter().filter(|&&x| x == 255).count();
    assert_eq!(count_256, 295);
    assert_eq!(count_255, 96);
    let max = big.iter().copied().max().unwrap_or(0);
    let min = big.iter().copied().min().unwrap_or(0);
    assert!(max - min <= 1);
}

// -------------------------------------------------------- build_dir

#[test]
fn build_dir_empty_yields_single_canonical_leaf() {
    let built = build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built.nodes.len(), 1);
    let (id, bytes) = &built.nodes[0];
    assert_eq!(built.root, *id);
    let mut expected = encoding::envelope(ObjectType::DirLeaf);
    expected.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(bytes, &expected);
}

#[test]
fn build_dir_257_entries_two_leaves_one_interior_and_validates() {
    let n = DIR_LEAF_MAX_ENTRIES + 1;
    let entries = fifo_entries(n);
    let built = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built.nodes.len(), 3);
    let leaves = dir_leaves(&built.nodes);
    assert_eq!(leaves.len(), 2);

    let map: BTreeMap<GrainId, Vec<u8>> = built.nodes.iter().cloned().collect();
    let stats = validate_dir_tree(&built.root, &|id| map.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.entries, u64::from(n));
    assert_eq!(stats.dirs, 1);
}

/// Globally-unsorted input must be rejected UP FRONT, by
/// `build_dir`, not waved through to become bytes. The fixture is
/// the one that exposed the gap: C+1 entries whose canonical
/// [129, 128] split puts a duplicated name on the boundary, so
/// every leaf is strictly sorted ON ITS OWN and `encode_dir_leaf`
/// (which only ever sees one slice) has nothing to object to. Before
/// the up-front check this built a tree, and only
/// `validate_dir_tree` rejected it, with `CrossNodeOrder` — the red
/// vector for that walk rule stays in `tests/manifest_rejects.rs`,
/// hand-building the same tree; this one pins the ENCODE side.
#[test]
fn build_dir_rejects_globally_unsorted_across_leaf_boundary() {
    let total = DIR_LEAF_MAX_ENTRIES + 1;
    // Canonical split arithmetic, derived not literalled.
    let first_len = total.div_ceil(total.div_ceil(DIR_LEAF_MAX_ENTRIES));
    let entries: Vec<DirEntry> = (0..total)
        .map(|i| {
            // Leaf 2's first entry repeats leaf 1's last.
            let n = if i == first_len { first_len - 1 } else { i };
            DirEntry {
                name: name(&format!("n{n:05}")),
                kind: EntryKind::Fifo,
            }
        })
        .collect();

    // Each leaf-sized slice on its own is acceptable to the codec —
    // the violation exists only across the boundary.
    let (part_1, part_2) = entries.split_at(first_len as usize);
    assert!(node::encode_dir_leaf(part_1).is_ok());
    assert!(node::encode_dir_leaf(part_2).is_ok());

    assert_eq!(build_dir(&entries), Err(EncodeNodeError::NotStrictlySorted));
}

/// The small case: a descending pair, well inside one leaf. Here
/// `encode_dir_leaf` would also have caught it — the point is that
/// `build_dir` now reports the SAME variant for both shapes of
/// unsorted input, whichever level notices.
#[test]
fn build_dir_rejects_two_entry_descending_slice() {
    let entries = vec![
        DirEntry {
            name: name("b"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("a"),
            kind: EntryKind::Fifo,
        },
    ];
    assert_eq!(build_dir(&entries), Err(EncodeNodeError::NotStrictlySorted));
}

// ------------------------------------------------------------ tamper

#[test]
fn validate_dir_tree_detects_wrong_separator_key() {
    // A wrong `first_key` on an otherwise-untouched, correctly
    // hashed child: swapping raw leaf BYTES under the wrong ids
    // is caught earlier, by the `GrainId::of` hash check
    // (CorruptObject), so this row tampers only the
    // interior's own claim about its child's first entry, leaving
    // every fetched object's bytes matching its id.
    let n = DIR_LEAF_MAX_ENTRIES + 1;
    let entries = fifo_entries(n);
    let built = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    let map: BTreeMap<GrainId, Vec<u8>> = built.nodes.iter().cloned().collect();

    let (_, root_bytes) = built
        .nodes
        .iter()
        .find(|(id, _)| *id == built.root)
        .unwrap_or_else(|| panic!("root present"));
    let (_, cursor) = encoding::open_envelope(root_bytes).unwrap_or_else(|e| panic!("{e:?}"));
    let mut children = node::decode_dir_interior(cursor).unwrap_or_else(|e| panic!("{e:?}"));
    let first_child = children
        .first_mut()
        .unwrap_or_else(|| panic!("first child"));
    let leaf_bytes = map
        .get(&first_child.child)
        .unwrap_or_else(|| panic!("first leaf present"));
    let (_, leaf_cursor) = encoding::open_envelope(leaf_bytes).unwrap_or_else(|e| panic!("{e:?}"));
    let leaf_entries = node::decode_dir_leaf(leaf_cursor).unwrap_or_else(|e| panic!("{e:?}"));
    // The leaf's SECOND entry name: still inside the leaf's own
    // sorted range (so it stays strictly less than the sibling's
    // first_key, satisfying encode_dir_interior's own sort check),
    // but wrong as a claim about the leaf's actual first entry.
    let wrong_key = leaf_entries
        .get(1)
        .unwrap_or_else(|| panic!("leaf has >= 2 entries"))
        .name
        .clone();
    first_child.first_key = wrong_key;
    let tampered_root = node::encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
    let tampered_root_id = GrainId::of(&tampered_root);

    let mut map = map;
    map.insert(tampered_root_id, tampered_root);

    let err =
        validate_dir_tree(&tampered_root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::SeparatorMismatch);
}

#[test]
fn validate_dir_tree_detects_wrong_subtree_entry_count() {
    let n = DIR_LEAF_MAX_ENTRIES + 1;
    let entries = fifo_entries(n);
    let built = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    let mut map: BTreeMap<GrainId, Vec<u8>> = built.nodes.iter().cloned().collect();

    let (_, interior_bytes) = built.nodes.last().unwrap_or_else(|| panic!("root node"));
    let (_, cursor) = encoding::open_envelope(interior_bytes).unwrap_or_else(|e| panic!("{e:?}"));
    let mut children = node::decode_dir_interior(cursor).unwrap_or_else(|e| panic!("{e:?}"));
    if let Some(first) = children.first_mut() {
        first.subtree_entry_count += 1;
    }
    let tampered = node::encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
    let tampered_id = GrainId::of(&tampered);
    map.insert(tampered_id, tampered);

    let err = validate_dir_tree(&tampered_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::CountMismatch);
}

#[test]
fn validate_dir_tree_surfaces_decode_error_for_one_child_interior() {
    let mut body = encoding::envelope(ObjectType::DirInterior);
    body.extend_from_slice(&1u32.to_be_bytes());
    let key = name("a");
    body.push(key.wire_len());
    body.extend_from_slice(key.as_bytes());
    body.extend_from_slice(&gid("only-child").to_bytes());
    body.extend_from_slice(&1u64.to_be_bytes());
    let id = GrainId::of(&body);
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(id, body);

    let err = validate_dir_tree(&id, &|k| map.get(k).cloned()).expect_err("must reject");
    assert_eq!(
        err,
        ValidateError::Decode(DecodeError::Invalid {
            what: "interior child_count (< 2)",
        })
    );
}

#[test]
fn validate_dir_tree_rejects_depth_exceeded() {
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut next_child = gid("past-the-cap");
    for level in (1..=DEPTH_MAX).rev() {
        let children = vec![
            InteriorChild {
                first_key: name("a"),
                child: next_child,
                subtree_entry_count: 1,
            },
            InteriorChild {
                first_key: name("b"),
                child: gid(&format!("dummy-{level}")),
                subtree_entry_count: 1,
            },
        ];
        let bytes = node::encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
        let id = GrainId::of(&bytes);
        map.insert(id, bytes);
        next_child = id;
    }
    let root = next_child;

    let err = validate_dir_tree(&root, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::DepthExceeded);
}

// -------------------------------------------------------------- spill

#[test]
fn build_grain_list_129_refs_roundtrip_validates_via_file_entry() {
    let n = FILE_INLINE_MAX_REFS + 1;
    let refs: Vec<GrainRef> = (0..n).map(|i| gref(&format!("g{i}"), 1)).collect();
    let built = build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built.nodes.len(), 1);

    let file_entry = DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(n),
            grains: FileGrains::Spill {
                grain_count: n,
                root: built.root,
            },
        },
    };
    let dir = build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let mut map: BTreeMap<GrainId, Vec<u8>> = dir.nodes.iter().cloned().collect();
    map.extend(built.nodes.iter().cloned());

    let stats =
        validate_dir_tree(&dir.root, &|id| map.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 1);
    assert_eq!(stats.grains, u64::from(n));
    assert_eq!(stats.bytes, u64::from(n));
}

#[test]
fn build_dir_propagates_spill_under_k_encode_error() {
    let entry = DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size: 10,
            grains: FileGrains::Spill {
                grain_count: FILE_INLINE_MAX_REFS,
                root: gid("root"),
            },
        },
    };
    assert_eq!(
        build_dir(&[entry]),
        Err(EncodeNodeError::SpillUnderK {
            count: FILE_INLINE_MAX_REFS,
        })
    );
}

#[test]
fn validate_dir_tree_rejects_lying_spill_grain_count() {
    let n = FILE_INLINE_MAX_REFS + 1;
    let refs: Vec<GrainRef> = (0..n).map(|i| gref(&format!("g{i}"), 1)).collect();
    let built = build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}"));

    let lied_count = n + FILE_INLINE_MAX_REFS; // > K, still decodes as Spill; wrong
    let file_entry = DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(n),
            grains: FileGrains::Spill {
                grain_count: lied_count,
                root: built.root,
            },
        },
    };
    let dir = build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let mut map: BTreeMap<GrainId, Vec<u8>> = dir.nodes.iter().cloned().collect();
    map.extend(built.nodes.iter().cloned());

    let err = validate_dir_tree(&dir.root, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::CountMismatch);
}

/// A lying declared file size must be REJECTED, not panic the
/// walker: `stats.bytes` accumulates the declared u64 before
/// `validate_file_grains` can refute it, so the accumulation must
/// saturate — overflow-checks are on in release, so an unchecked
/// add aborts on a hostile manifest.
#[test]
fn validate_dir_tree_rejects_lying_file_size_without_overflow() {
    let entries = vec![
        DirEntry {
            name: name("a"),
            kind: EntryKind::File {
                exec: false,
                size: 1,
                grains: FileGrains::Inline(vec![gref("g", 1)]),
            },
        },
        DirEntry {
            name: name("b"),
            kind: EntryKind::File {
                exec: false,
                size: u64::MAX,
                grains: FileGrains::Spill {
                    grain_count: FILE_INLINE_MAX_REFS + 1,
                    root: gid("missing"),
                },
            },
        },
    ];
    let dir = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    let map: BTreeMap<GrainId, Vec<u8>> = dir.nodes.iter().cloned().collect();
    let err = validate_dir_tree(&dir.root, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::MissingObject { id: gid("missing") });
}

/// Rule-3 recompute must be bounded by the WALKED shape: an
/// astronomical claimed total is rejected by counting, never by
/// first materializing `total/cap` expected leaf sizes (the
/// `Vec::with_capacity` would abort).
#[test]
fn fill_canonical_rejects_astronomical_total_without_allocating() {
    let mut shape = Shape::default();
    shape.leaves.push((1, 5));
    let err = check_fill_canonical(&shape, u64::MAX, 131_072, 131_072).expect_err("must reject");
    assert_eq!(err, ValidateError::FillNotCanonical);
}

#[test]
fn validate_rejects_gratuitous_index_over_le_n_refs() {
    let n = FILE_INLINE_MAX_REFS + 1; // 129
    let refs: Vec<GrainRef> = (0..n).map(|i| gref(&format!("g{i}"), 1)).collect();
    let split = n / 2 + 1; // 65
    let (refs_a, refs_b) = refs.split_at(split as usize);
    assert_eq!(refs_a.len(), split as usize);
    assert_eq!(refs_b.len(), (n - split) as usize);

    let leaf_a = node::encode_grain_list_leaf(refs_a).unwrap_or_else(|e| panic!("{e}"));
    let leaf_b = node::encode_grain_list_leaf(refs_b).unwrap_or_else(|e| panic!("{e}"));
    let id_a = GrainId::of(&leaf_a);
    let id_b = GrainId::of(&leaf_b);

    let index_children = vec![
        GrainListIndexChild {
            child: id_a,
            cum_unpacked_len: u64::from(split),
            cum_ref_count: u64::from(split),
        },
        GrainListIndexChild {
            child: id_b,
            cum_unpacked_len: u64::from(n),
            cum_ref_count: u64::from(n),
        },
    ];
    let index_bytes =
        node::encode_grain_list_index(&index_children).unwrap_or_else(|e| panic!("{e}"));
    let index_id = GrainId::of(&index_bytes);

    let file_entry = DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(n),
            grains: FileGrains::Spill {
                grain_count: n,
                root: index_id,
            },
        },
    };
    let dir = build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));

    let mut map: BTreeMap<GrainId, Vec<u8>> = dir.nodes.iter().cloned().collect();
    map.insert(id_a, leaf_a);
    map.insert(id_b, leaf_b);
    map.insert(index_id, index_bytes);

    let err = validate_dir_tree(&dir.root, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::FillNotCanonical);
}

#[test]
#[expect(
    clippy::similar_names,
    reason = "a/b group and 1/2 leaf naming is intentionally parallel"
)]
fn validate_rejects_nested_index_over_indexes_of_canonical_leaves() {
    let group = FILE_INLINE_MAX_REFS + 1; // 129
    let total = group * 2; // 258
    let refs: Vec<GrainRef> = (0..total).map(|i| gref(&format!("g{i}"), 1)).collect();
    let split = group / 2 + 1; // 65

    let (group_a, group_b) = refs.split_at(group as usize);
    let (a1, a2) = group_a.split_at(split as usize);
    let (b1, b2) = group_b.split_at(split as usize);

    let leaf_a1 = node::encode_grain_list_leaf(a1).unwrap_or_else(|e| panic!("{e}"));
    let leaf_a2 = node::encode_grain_list_leaf(a2).unwrap_or_else(|e| panic!("{e}"));
    let leaf_b1 = node::encode_grain_list_leaf(b1).unwrap_or_else(|e| panic!("{e}"));
    let leaf_b2 = node::encode_grain_list_leaf(b2).unwrap_or_else(|e| panic!("{e}"));
    let id_a1 = GrainId::of(&leaf_a1);
    let id_a2 = GrainId::of(&leaf_a2);
    let id_b1 = GrainId::of(&leaf_b1);
    let id_b2 = GrainId::of(&leaf_b2);

    let sub_a_children = vec![
        GrainListIndexChild {
            child: id_a1,
            cum_unpacked_len: u64::from(split),
            cum_ref_count: u64::from(split),
        },
        GrainListIndexChild {
            child: id_a2,
            cum_unpacked_len: u64::from(group),
            cum_ref_count: u64::from(group),
        },
    ];
    let sub_b_children = vec![
        GrainListIndexChild {
            child: id_b1,
            cum_unpacked_len: u64::from(split),
            cum_ref_count: u64::from(split),
        },
        GrainListIndexChild {
            child: id_b2,
            cum_unpacked_len: u64::from(group),
            cum_ref_count: u64::from(group),
        },
    ];
    let sub_a_bytes =
        node::encode_grain_list_index(&sub_a_children).unwrap_or_else(|e| panic!("{e}"));
    let sub_b_bytes =
        node::encode_grain_list_index(&sub_b_children).unwrap_or_else(|e| panic!("{e}"));
    let sub_a_id = GrainId::of(&sub_a_bytes);
    let sub_b_id = GrainId::of(&sub_b_bytes);

    let top_children = vec![
        GrainListIndexChild {
            child: sub_a_id,
            cum_unpacked_len: u64::from(group),
            cum_ref_count: u64::from(group),
        },
        GrainListIndexChild {
            child: sub_b_id,
            cum_unpacked_len: u64::from(total),
            cum_ref_count: u64::from(total),
        },
    ];
    let top_bytes = node::encode_grain_list_index(&top_children).unwrap_or_else(|e| panic!("{e}"));
    let top_id = GrainId::of(&top_bytes);

    let file_entry = DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(total),
            grains: FileGrains::Spill {
                grain_count: total,
                root: top_id,
            },
        },
    };
    let dir = build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));

    let mut map: BTreeMap<GrainId, Vec<u8>> = dir.nodes.iter().cloned().collect();
    for (id, bytes) in [
        (id_a1, leaf_a1),
        (id_a2, leaf_a2),
        (id_b1, leaf_b1),
        (id_b2, leaf_b2),
        (sub_a_id, sub_a_bytes),
        (sub_b_id, sub_b_bytes),
        (top_id, top_bytes),
    ] {
        map.insert(id, bytes);
    }

    let err = validate_dir_tree(&dir.root, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::FillNotCanonical);
}

// -----------------------------------------------------------------------

/// The regression vector: a depth-lopsided tree over
/// 257 x 256 = `65_792` entries that reproduces the CANONICAL width
/// sequence ([129, 128] then [2]) exactly, but is not uniform
/// height. A flat, depth-sorted width comparison is insufficient:
/// every leaf must be at the SAME depth, which this construction
/// violates by design:
///   root (depth 1, width 2) -> { Y, last-leaf }
///   Y    (depth 2, width 128) = 127 direct leaves + X
///   X    (depth 3, width 129) = the remaining 129 leaves (depth 4)
/// Every separator/count value is set from the REAL, contiguous
/// partition of one canonically sorted entry set, so the walk
/// reaches the fill check rather than failing earlier.
#[test]
fn validate_rejects_depth_lopsided_shape() {
    let c = DIR_LEAF_MAX_ENTRIES as usize; // leaf cap C
    let leaves_needed = c + 1; // 257
    let n_total = c * leaves_needed; // 65_792 = 257 x 256, divides evenly
    let entries = fifo_entries(u32::try_from(n_total).unwrap_or_else(|e| panic!("{e}")));

    // n_total divides evenly by c, so every leaf is exactly c
    // entries -- the same leaf-level partition build_dir itself
    // would produce.
    let mut leaf_infos: Vec<(GrainId, Vec<u8>, Vec<u8>, u64)> = Vec::new();
    for chunk in entries.chunks(c) {
        let bytes = node::encode_dir_leaf(chunk).unwrap_or_else(|e| panic!("{e}"));
        let id = GrainId::of(&bytes);
        let first = chunk.first().unwrap_or_else(|| panic!("chunk nonempty"));
        leaf_infos.push((
            id,
            bytes,
            first.name.as_bytes().to_vec(),
            chunk.len() as u64,
        ));
    }
    assert_eq!(leaf_infos.len(), leaves_needed);

    // Canonical widths for `leaves_needed` leaf-nodes under fanout
    // c: [s1, s2] (s1 = 129, s2 = 128 numerically, derived here
    // rather than re-literalled).
    let split = split_counts(leaves_needed, c);
    let s1 = *split.first().unwrap_or_else(|| panic!("split nonempty"));
    let s2 = *split
        .get(1)
        .unwrap_or_else(|| panic!("split has 2 entries"));
    let y_direct_count = s2 - 1; // X takes over the seat of one direct leaf
    let x_count = s1; // X's own width equals the canonical first width

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    for (id, bytes, ..) in &leaf_infos {
        map.insert(*id, bytes.clone());
    }

    let make_child = |(id, _, first, count): &(GrainId, Vec<u8>, Vec<u8>, u64)| InteriorChild {
        first_key: Name::new(first.clone()).unwrap_or_else(|e| panic!("{e}")),
        child: *id,
        subtree_entry_count: *count,
    };

    // X: interior over the middle x_count leaves (depth 3 under
    // root, its own leaves land at depth 4).
    let x_children: Vec<InteriorChild> = leaf_infos[y_direct_count..y_direct_count + x_count]
        .iter()
        .map(make_child)
        .collect();
    let x_bytes = node::encode_dir_interior(&x_children).unwrap_or_else(|e| panic!("{e}"));
    let x_id = GrainId::of(&x_bytes);
    map.insert(x_id, x_bytes);
    let x_total: u64 = x_children.iter().map(|ch| ch.subtree_entry_count).sum();
    let x_first_key = x_children
        .first()
        .unwrap_or_else(|| panic!("x nonempty"))
        .first_key
        .clone();

    // Y: interior over the first y_direct_count leaves PLUS X as
    // its highest-sort child -- own width y_direct_count + 1 = s2.
    let mut y_children: Vec<InteriorChild> = leaf_infos[..y_direct_count]
        .iter()
        .map(make_child)
        .collect();
    y_children.push(InteriorChild {
        first_key: x_first_key,
        child: x_id,
        subtree_entry_count: x_total,
    });
    let y_bytes = node::encode_dir_interior(&y_children).unwrap_or_else(|e| panic!("{e}"));
    let y_id = GrainId::of(&y_bytes);
    map.insert(y_id, y_bytes);
    let y_total: u64 = y_children.iter().map(|ch| ch.subtree_entry_count).sum();
    let y_first_key = y_children
        .first()
        .unwrap_or_else(|| panic!("y nonempty"))
        .first_key
        .clone();

    // Root: { Y, last leaf }.
    let last = leaf_infos
        .last()
        .unwrap_or_else(|| panic!("leaves nonempty"));
    let root_children = vec![
        InteriorChild {
            first_key: y_first_key,
            child: y_id,
            subtree_entry_count: y_total,
        },
        make_child(last),
    ];
    let root_bytes = node::encode_dir_interior(&root_children).unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&root_bytes);
    map.insert(root_id, root_bytes);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err(
        "the lopsided impostor must be rejected by rule 3 (fill canonicity), not accepted",
    );
    assert_eq!(err, ValidateError::FillNotCanonical);

    // Consensus split, not a cosmetic one: the canonical build of
    // the SAME entry set hashes to a DIFFERENT root.
    let canonical = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(canonical.root, root_id);
}

/// Two interior levels in one tree: this row both accepts the
/// canonical two-level shape and pins it (257 leaves, mid
/// interiors [129, 128], root width 2) —
/// the positive counterpart to the lopsided-impostor regression.
#[test]
fn validate_accepts_two_interior_level_dir() {
    let n = DIR_LEAF_MAX_ENTRIES * (DIR_LEAF_MAX_ENTRIES + 1); // 65_792 = 257 x 256
    let entries = fifo_entries(n);
    let built = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    let map: BTreeMap<GrainId, Vec<u8>> = built.nodes.iter().cloned().collect();

    let leaves = dir_leaves(&built.nodes);
    assert_eq!(leaves.len(), (DIR_LEAF_MAX_ENTRIES + 1) as usize);

    let root_bytes = map
        .get(&built.root)
        .unwrap_or_else(|| panic!("root present"));
    let (_, cursor) = encoding::open_envelope(root_bytes).unwrap_or_else(|e| panic!("{e:?}"));
    let root_children = node::decode_dir_interior(cursor).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(root_children.len(), 2);
    let mut mid_widths = Vec::new();
    for ch in &root_children {
        let bytes = map
            .get(&ch.child)
            .unwrap_or_else(|| panic!("mid interior present"));
        let (_, cursor) = encoding::open_envelope(bytes).unwrap_or_else(|e| panic!("{e:?}"));
        let children = node::decode_dir_interior(cursor).unwrap_or_else(|e| panic!("{e:?}"));
        mid_widths.push(children.len());
    }
    let expected_mid_widths = split_counts(
        (DIR_LEAF_MAX_ENTRIES + 1) as usize,
        DIR_LEAF_MAX_ENTRIES as usize,
    );
    assert_eq!(mid_widths, expected_mid_widths);

    let stats = validate_dir_tree(&built.root, &|id| map.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.entries, u64::from(n));
    assert_eq!(stats.dirs, 1);
}

/// A tampered `cum_unpacked_len`/`cum_ref_count` on a grain-list
/// index child must be caught during the walk (rule 5), not waved
/// through to the fill-canonicity check.
#[test]
fn validate_dir_tree_rejects_tampered_grain_list_cumulative() {
    let n = FILE_INLINE_MAX_REFS + 1; // 129
    let refs: Vec<GrainRef> = (0..n).map(|i| gref(&format!("g{i}"), 1)).collect();
    let split = n / 2 + 1; // 65
    let (refs_a, refs_b) = refs.split_at(split as usize);

    let leaf_a = node::encode_grain_list_leaf(refs_a).unwrap_or_else(|e| panic!("{e}"));
    let leaf_b = node::encode_grain_list_leaf(refs_b).unwrap_or_else(|e| panic!("{e}"));
    let id_a = GrainId::of(&leaf_a);
    let id_b = GrainId::of(&leaf_b);

    // Real cumulative for child a is (split, split); off by one.
    let index_children = vec![
        GrainListIndexChild {
            child: id_a,
            cum_unpacked_len: u64::from(split) + 1,
            cum_ref_count: u64::from(split) + 1,
        },
        GrainListIndexChild {
            child: id_b,
            cum_unpacked_len: u64::from(n) + 1,
            cum_ref_count: u64::from(n) + 1,
        },
    ];
    let index_bytes =
        node::encode_grain_list_index(&index_children).unwrap_or_else(|e| panic!("{e}"));
    let index_id = GrainId::of(&index_bytes);

    let file_entry = DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(n),
            grains: FileGrains::Spill {
                grain_count: n,
                root: index_id,
            },
        },
    };
    let dir = build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));

    let mut map: BTreeMap<GrainId, Vec<u8>> = dir.nodes.iter().cloned().collect();
    map.insert(id_a, leaf_a);
    map.insert(id_b, leaf_b);
    map.insert(index_id, index_bytes);

    let err = validate_dir_tree(&dir.root, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::CumulativeMismatch);
}

/// A store that returns bytes not matching the id they were fetched
/// under is caught immediately (the `GrainId::of` hash check) — this
/// is also the property that makes object cycles infeasible.
#[test]
fn validate_dir_tree_rejects_object_not_matching_its_id() {
    let n = DIR_LEAF_MAX_ENTRIES + 1;
    let entries = fifo_entries(n);
    let built = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    let (_, root_bytes) = built
        .nodes
        .iter()
        .find(|(id, _)| *id == built.root)
        .unwrap_or_else(|| panic!("root present"));

    let wrong_id = gid("not-the-real-id");
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(wrong_id, root_bytes.clone());

    let err = validate_dir_tree(&wrong_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::CorruptObject { id: wrong_id });
}

/// `build_grain_list` at or below K must be a real error, not a
/// debug-only assertion that silently produces a non-canonical
/// one-leaf spill in release builds.
#[test]
fn build_grain_list_rejects_refs_at_or_below_k() {
    let refs: Vec<GrainRef> = (0..FILE_INLINE_MAX_REFS)
        .map(|i| gref(&format!("g{i}"), 1))
        .collect();
    assert_eq!(
        build_grain_list(&refs),
        Err(EncodeNodeError::SpillUnderK {
            count: FILE_INLINE_MAX_REFS,
        })
    );
}

// --------------------------- unbounded-axis regressions
//
// `gran cat` made `validate_dir_tree` a walker over a manifest
// fetched from an untrusted PEER. Every test below pins one axis
// that a locally-built tree could never reach.

/// A fetch closure that counts its calls, so a test can pin the
/// WORK a walk does and not only its verdict. Pure — a `Cell` over
/// an in-memory map, no clock and no I/O.
struct CountingFetch<'a> {
    map: &'a BTreeMap<GrainId, Vec<u8>>,
    calls: std::cell::Cell<u64>,
}

impl<'a> CountingFetch<'a> {
    fn new(map: &'a BTreeMap<GrainId, Vec<u8>>) -> Self {
        Self {
            map,
            calls: std::cell::Cell::new(0),
        }
    }

    fn get(&self, id: &GrainId) -> Option<Vec<u8>> {
        self.calls.set(self.calls.get().saturating_add(1));
        self.map.get(id).cloned()
    }

    fn calls(&self) -> u64 {
        self.calls.get()
    }
}

/// One dir leaf holding `kids` subdirectory entries that ALL name
/// the same child. The names differ (a leaf's entries are strictly
/// sorted); the child id does not, so `kids` entries cost one
/// object.
fn dir_of_repeated_child(kids: u32, child: GrainId) -> (GrainId, Vec<u8>) {
    let entries: Vec<DirEntry> = (0..kids)
        .map(|i| DirEntry {
            name: name(&format!("n{i:05}")),
            kind: EntryKind::Dir { child },
        })
        .collect();
    let bytes = node::encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    (GrainId::of(&bytes), bytes)
}

/// A chain of `levels` nested directories over `levels + 1`
/// objects, plus the deepest (empty) directory. Returns the
/// outermost id and the object map.
fn nested_chain(levels: u32) -> (GrainId, BTreeMap<GrainId, Vec<u8>>) {
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let empty = node::encode_dir_leaf(&[]).unwrap_or_else(|e| panic!("{e}"));
    let mut child = GrainId::of(&empty);
    map.insert(child, empty);
    for _ in 0..levels {
        let bytes = node::encode_dir_leaf(&[DirEntry {
            name: name("d"),
            kind: EntryKind::Dir { child },
        }])
        .unwrap_or_else(|e| panic!("{e}"));
        child = GrainId::of(&bytes);
        map.insert(child, bytes);
    }
    (child, map)
}

/// One dir leaf naming ONE file whose grains spill to `root`.
fn dir_with_spill(size: u64, grain_count: u32, root: GrainId) -> (GrainId, Vec<u8>) {
    let bytes = node::encode_dir_leaf(&[DirEntry {
        name: name("f"),
        kind: EntryKind::File {
            exec: false,
            size,
            grains: FileGrains::Spill { grain_count, root },
        },
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    (GrainId::of(&bytes), bytes)
}

/// The grain-list leaf ids among `nodes`, in emission order.
fn leaf_ids_of(nodes: &[(GrainId, Vec<u8>)]) -> Vec<GrainId> {
    nodes
        .iter()
        .filter(|(_, b)| {
            matches!(
                encoding::open_envelope(b),
                Ok((ObjectType::GrainListLeaf, _))
            )
        })
        .map(|(id, _)| *id)
        .collect()
}

/// An index whose `children` entries ALL name `leaf_id`, each
/// contributing `GRAINLIST_LEAF_MAX_REFS` refs, with honest
/// strictly-increasing cumulative fields — the repeated-leaf shape
/// the leaf-memo tests share.
fn repeated_leaf_index(leaf_id: GrainId, children: u64) -> (GrainId, Vec<u8>) {
    let index_children: Vec<GrainListIndexChild> = (1..=children)
        .map(|i| GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: i * u64::from(GRAINLIST_LEAF_MAX_REFS),
            cum_ref_count: i * u64::from(GRAINLIST_LEAF_MAX_REFS),
        })
        .collect();
    let bytes = node::encode_grain_list_index(&index_children).unwrap_or_else(|e| panic!("{e}"));
    (GrainId::of(&bytes), bytes)
}

/// **Nesting is walked, not recursed.** Directory NESTING is
/// deliberately uncapped by the format. A walker charging nested
/// subdirectories against a single budget would reject valid manifests,
/// so the walker has to be TOTAL on a chain of any length — and a
/// verdict, not a bound, is the only accept-set-neutral way to get
/// there. Native-stack recursion is
/// not total: a probe of it measured `fatal runtime error: stack overflow`
/// — SIGABRT, uncatchable, not an `Err` — at roughly 500 levels in
/// debug and 3000-5000 in release. Ten thousand levels is
/// twenty times
/// past the debug figure.
#[test]
fn validate_dir_tree_walks_ten_thousand_nesting_levels_without_a_stack_abort() {
    const LEVELS: u32 = 10_000;
    let (root, map) = nested_chain(LEVELS);
    let stats =
        validate_dir_tree(&root, &|id| map.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.entries, u64::from(LEVELS));
    assert_eq!(stats.dirs, u64::from(LEVELS) + 1);
}

/// **Repeated-leaf guard.** A grain-list index whose two children are the SAME
/// leaf id is CANONICAL — `build_grain_list` emits exactly this for
/// a file whose two halves are byte-identical — so it must keep
/// validating. This is the vector that fails if anyone memoizes
/// `walk_grain_list`'s own RESULT by node id —
/// skipping the per-visit `(depth, width)` push: a walk result is
/// not a function of id alone, because both walkers push into the
/// shared `Shape` that `check_fill_canonical` then compares against
/// a recomputed uniform height. The leaf-facts memo passes here
/// precisely because a hit still performs that push.
#[test]
fn validate_dir_tree_accepts_a_grain_list_index_over_two_identical_leaves() {
    let half: Vec<GrainRef> = vec![gref("g", 1); GRAINLIST_LEAF_MAX_REFS as usize];
    let mut refs = half.clone();
    refs.extend(half);
    let total = refs.len() as u64;
    let built = build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}"));
    // Two leaves and one index, and the two leaves are ONE object.
    assert_eq!(built.nodes.len(), 3);
    let leaf_ids: Vec<GrainId> = built
        .nodes
        .iter()
        .filter(|(_, b)| {
            matches!(
                encoding::open_envelope(b),
                Ok((ObjectType::GrainListLeaf, _))
            )
        })
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(leaf_ids.len(), 2);
    assert_eq!(leaf_ids.first(), leaf_ids.last());

    let mut map: BTreeMap<GrainId, Vec<u8>> = built.nodes.into_iter().collect();
    assert_eq!(map.len(), 2, "the shared leaf is stored once");
    let count = u32::try_from(total).unwrap_or_else(|e| panic!("{e}"));
    let (dir_root, dir_bytes) = dir_with_spill(total, count, built.root);
    map.insert(dir_root, dir_bytes);

    let stats =
        validate_dir_tree(&dir_root, &|id| map.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 1);
    assert_eq!(stats.grains, total);
    assert_eq!(stats.bytes, total);
}

/// **The leaf memo.** Same shape as the repeated-leaf guard above — a
/// grain-list index whose two children are the SAME leaf id, which
/// `build_grain_list` legitimately emits for a file whose two
/// halves are byte-identical — but this one counts fetches PER id
/// rather than only checking the verdict. A leaf's bytes are fetched,
/// hashed and decoded once no matter how many times its id appears
/// under an index; verdict and stats are unaffected either way.
#[test]
fn a_legitimately_repeated_leaf_still_validates() {
    let half: Vec<GrainRef> = vec![gref("g", 1); GRAINLIST_LEAF_MAX_REFS as usize];
    let mut refs = half.clone();
    refs.extend(half);
    let total = refs.len() as u64;
    let built = build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}"));
    let root = built.root;
    let leaf_ids = leaf_ids_of(&built.nodes);
    assert_eq!(leaf_ids.len(), 2);
    // Pin the premise, not just the count: the whole test is about a
    // REPEATED id, and a future `build_grain_list` change that made
    // the halves encode distinctly would otherwise green this test
    // without a single memo hit.
    assert_eq!(leaf_ids.first(), leaf_ids.last());
    let leaf_id = *leaf_ids.first().unwrap_or_else(|| panic!("leaf present"));

    let mut map: BTreeMap<GrainId, Vec<u8>> = built.nodes.into_iter().collect();
    let count = u32::try_from(total).unwrap_or_else(|e| panic!("{e}"));
    let (dir_root, dir_bytes) = dir_with_spill(total, count, root);
    map.insert(dir_root, dir_bytes);

    let calls: std::cell::RefCell<BTreeMap<GrainId, u32>> =
        std::cell::RefCell::new(BTreeMap::new());
    let fetch = |id: &GrainId| {
        *calls.borrow_mut().entry(*id).or_insert(0) += 1;
        map.get(id).cloned()
    };

    let stats = validate_dir_tree(&dir_root, &fetch).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 1);
    assert_eq!(stats.grains, total);
    assert_eq!(stats.bytes, total);
    assert_eq!(
        calls.borrow().get(&leaf_id).copied().unwrap_or(0),
        1,
        "the shared leaf must be fetched once, not once per index child"
    );
}

/// **The leaf-memo bound.** One maximal leaf (131 072 refs), and one
/// index whose 32 767 children ALL name that leaf's id with
/// strictly increasing cumulative fields — the same repeated-child
/// shape as the test above, scaled to the point where an unmemoized
/// walk clone+hash+decodes the leaf 32 767 times instead of once.
/// Bytes-on-the-wire stay tiny (one leaf, one index); it is the
/// PER-VISIT work that the memo collapses to a single fetch. This
/// is GREEN-ONLY: without the leaf memo this test does not fail, it
/// hangs (on the order of tens of minutes of repeated decode), so it
/// is never run against the unmemoized walker.
#[test]
fn the_repeated_leaf_manifest_completes_in_bounded_bytes() {
    const CHILDREN: u64 = 32_767;
    let refs: Vec<GrainRef> = vec![gref("g", 1); GRAINLIST_LEAF_MAX_REFS as usize];
    let leaf_bytes = node::encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
    let leaf_id = GrainId::of(&leaf_bytes);
    let (index_id, index_bytes) = repeated_leaf_index(leaf_id, CHILDREN);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(leaf_id, leaf_bytes);
    map.insert(index_id, index_bytes);

    let total = CHILDREN * u64::from(GRAINLIST_LEAF_MAX_REFS);
    assert_eq!(total, 4_294_836_224, "32_767 x 131_072, fits u32");
    let count = u32::try_from(total).unwrap_or_else(|e| panic!("{e}"));
    let (dir_root, dir_bytes) = dir_with_spill(total, count, index_id);
    map.insert(dir_root, dir_bytes);

    let calls: std::cell::RefCell<BTreeMap<GrainId, u32>> =
        std::cell::RefCell::new(BTreeMap::new());
    let fetch = |id: &GrainId| {
        let mut calls = calls.borrow_mut();
        let n = calls.entry(*id).or_insert(0);
        *n += 1;
        // Self-bounding: on a memo regression this test would not
        // fail, it would grind through 32_767 slow decode visits —
        // minutes under any runner, and unreported under plain
        // `cargo test`, which has no slow-timeout at all. The cap
        // turns that into a fast, named failure everywhere; the
        // nextest terminate-after stays as the backstop for hangs
        // this closure cannot see.
        assert!(*n <= 1, "memo regression: a node was fetched {n} times");
        map.get(id).cloned()
    };

    let stats = validate_dir_tree(&dir_root, &fetch).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 1);
    assert_eq!(stats.grains, total);
    assert_eq!(stats.bytes, total);
    assert_eq!(
        calls.borrow().get(&leaf_id).copied().unwrap_or(0),
        1,
        "one fetch/decode of the leaf for all 32_767 visits"
    );
}

/// Every other repeated-leaf fixture in this file uses per-ref
/// `unpacked_len = 1`, so a leaf's byte len EQUALS its ref count and
/// a width/len swap in the memo-hit push (or in the memo-hit return
/// pair) would be invisible to them. This leaf's refs carry
/// `unpacked_len = 2`, so the two numbers diverge and the swap is
/// caught (as `FillNotCanonical` on the push side, as
/// `CumulativeMismatch` on the return side).
#[test]
fn a_repeated_leaf_with_wide_refs_distinguishes_len_from_count() {
    let half: Vec<GrainRef> = vec![gref("g", 2); GRAINLIST_LEAF_MAX_REFS as usize];
    let mut refs = half.clone();
    refs.extend(half);
    let grains = refs.len() as u64;
    let bytes_total = 2 * grains;
    let built = build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}"));

    let mut map: BTreeMap<GrainId, Vec<u8>> = built.nodes.into_iter().collect();
    let count = u32::try_from(grains).unwrap_or_else(|e| panic!("{e}"));
    let (dir_root, dir_bytes) = dir_with_spill(bytes_total, count, built.root);
    map.insert(dir_root, dir_bytes);

    let stats =
        validate_dir_tree(&dir_root, &|id| map.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 1);
    assert_eq!(stats.grains, grains);
    assert_eq!(stats.bytes, bytes_total, "bytes are 2x grains here");
}

/// One leaf id occurs at TWO DIFFERENT depths across two files' grain
/// lists: file `a` (`131_072` refs) IS the bare leaf — depth 1 — and file
/// `b` (`262_144` refs) is an index over two copies of that byte-identical
/// leaf — depth 2. The walk-wide memo is populated at depth
/// 1 by `a` and hit at depth 2 by `b`; the hit must push the CALLER's
/// depth, never a remembered one — the axis that
/// `validate_dir_tree_stats_are_unchanged_by_sharing_at_two_depths` pins for
/// the cursor's subtree-totals memo (not for `walk_dir`).
#[test]
fn a_shared_leaf_at_two_depths_pushes_the_callers_depth() {
    let half: Vec<GrainRef> = vec![gref("g", 1); GRAINLIST_LEAF_MAX_REFS as usize];
    let built_a = build_grain_list(&half).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built_a.nodes.len(), 1, "file a's list is the bare leaf");

    let mut refs_b = half.clone();
    refs_b.extend(half);
    let built_b = build_grain_list(&refs_b).unwrap_or_else(|e| panic!("{e}"));
    let b_leaf_ids = leaf_ids_of(&built_b.nodes);
    assert_eq!(
        b_leaf_ids,
        vec![built_a.root, built_a.root],
        "b's two leaves are byte-identical to a's bare leaf"
    );

    let size_a = u64::from(GRAINLIST_LEAF_MAX_REFS);
    let size_b = 2 * size_a;
    let dir_bytes = node::encode_dir_leaf(&[
        DirEntry {
            name: name("a"),
            kind: EntryKind::File {
                exec: false,
                size: size_a,
                grains: FileGrains::Spill {
                    grain_count: GRAINLIST_LEAF_MAX_REFS,
                    root: built_a.root,
                },
            },
        },
        DirEntry {
            name: name("b"),
            kind: EntryKind::File {
                exec: false,
                size: size_b,
                grains: FileGrains::Spill {
                    grain_count: 2 * GRAINLIST_LEAF_MAX_REFS,
                    root: built_b.root,
                },
            },
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let dir_root = GrainId::of(&dir_bytes);

    let mut map: BTreeMap<GrainId, Vec<u8>> = built_a.nodes.into_iter().collect();
    map.extend(built_b.nodes);
    map.insert(dir_root, dir_bytes);

    let stats =
        validate_dir_tree(&dir_root, &|id| map.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 2);
    assert_eq!(stats.grains, size_a + size_b);
    assert_eq!(stats.bytes, size_a + size_b);
}

/// Budget 2 (declared `262_144`), three index children all naming one maximal leaf with
/// honest strictly-increasing cums: visit 1 is the miss, visit 2 a hit under budget,
/// visit 3 a hit AT budget and must die `FillNotCanonical` before any `CountMismatch` can
/// be computed — the budget refusal lives on the memo-hit path itself, not only behind a
/// fetch. Without this pin the only thing catching a dropped hit-path budget check is a
/// runner-configured timeout on
/// `validate_dir_tree_refuses_a_shared_child_grain_list_without_walking_it`, which under
/// plain `cargo test` is a hang.
#[test]
fn a_repeated_leaf_crossing_the_budget_is_refused_on_the_hit_path() {
    let refs: Vec<GrainRef> = vec![gref("g", 1); GRAINLIST_LEAF_MAX_REFS as usize];
    let leaf_bytes = node::encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
    let leaf_id = GrainId::of(&leaf_bytes);
    let (index_id, index_bytes) = repeated_leaf_index(leaf_id, 3);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(leaf_id, leaf_bytes);
    map.insert(index_id, index_bytes);

    let declared = 2 * u64::from(GRAINLIST_LEAF_MAX_REFS);
    let count = u32::try_from(declared).unwrap_or_else(|e| panic!("{e}"));
    let (dir_root, dir_bytes) = dir_with_spill(declared, count, index_id);
    map.insert(dir_root, dir_bytes);

    let err = validate_dir_tree(&dir_root, &|id| map.get(id).cloned())
        .expect_err("a third visit past the declared budget must be refused");
    assert_eq!(err, ValidateError::FillNotCanonical);
}

/// **Directory-memo depth guard.** `TreeStats` over a DAG whose shared
/// subtree hangs at TWO DIFFERENT nesting depths: `S` sits directly
/// under the root AND one level further down under `M`. Same-depth
/// sharing would not catch a depth-sensitive memo. The expected numbers
/// are the ones a plain recursive walker, without the worklist or the
/// memo, produced; memoization is only sound if they do not move.
#[test]
fn validate_dir_tree_stats_are_unchanged_by_sharing_at_two_depths() {
    let s = node::encode_dir_leaf(&[
        DirEntry {
            name: name("f"),
            kind: EntryKind::File {
                exec: false,
                size: 3,
                grains: FileGrains::Inline(vec![gref("g0", 1), gref("g1", 2)]),
            },
        },
        DirEntry {
            name: name("l"),
            kind: EntryKind::Symlink {
                target: SymlinkTarget::new(b"../t".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            },
        },
        DirEntry {
            name: name("p"),
            kind: EntryKind::Fifo,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let s_id = GrainId::of(&s);

    let m = node::encode_dir_leaf(&[DirEntry {
        name: name("s"),
        kind: EntryKind::Dir { child: s_id },
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let m_id = GrainId::of(&m);

    let root = node::encode_dir_leaf(&[
        DirEntry {
            name: name("a"),
            kind: EntryKind::Dir { child: s_id },
        },
        DirEntry {
            name: name("b"),
            kind: EntryKind::Dir { child: m_id },
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&root);

    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    map.insert(s_id, s);
    map.insert(m_id, m);
    map.insert(root_id, root);

    let stats =
        validate_dir_tree(&root_id, &|id| map.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        stats,
        TreeStats {
            dirs: 4,
            files: 2,
            symlinks: 2,
            entries: 9,
            grains: 4,
            bytes: 6,
        }
    );
}

/// **The `validate_file_grains` memo key.** `size` and
/// `grain_count` come from the dir ENTRY, not from the spill tree,
/// and `validate_file_grains` refutes them against what the walk
/// actually found. Two entries may therefore share ONE grain-list
/// root while declaring different sizes — the first passes and the
/// second must still be refused. Keying a memo on `root` alone
/// would hand the second entry the first one's `Ok` and ACCEPT a
/// tree that is refused today.
#[test]
fn validate_dir_tree_refuses_a_second_entry_lying_about_a_shared_spill_root() {
    let count = FILE_INLINE_MAX_REFS + 1;
    let refs: Vec<GrainRef> = vec![gref("g", 1); count as usize];
    let built = build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}"));
    let truth = u64::from(count);

    let leaf = node::encode_dir_leaf(&[
        DirEntry {
            name: name("f1"),
            kind: EntryKind::File {
                exec: false,
                size: truth,
                grains: FileGrains::Spill {
                    grain_count: count,
                    root: built.root,
                },
            },
        },
        DirEntry {
            name: name("f2"),
            kind: EntryKind::File {
                exec: false,
                // Same root, same count, DIFFERENT declared size.
                size: truth + 1,
                grains: FileGrains::Spill {
                    grain_count: count,
                    root: built.root,
                },
            },
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&leaf);

    let mut map: BTreeMap<GrainId, Vec<u8>> = built.nodes.into_iter().collect();
    map.insert(root_id, leaf);

    let err = validate_dir_tree(&root_id, &|id| map.get(id).cloned()).expect_err("must reject");
    assert_eq!(err, ValidateError::CountMismatch);
}

/// **The grain-list leaf budget.** `walk_grain_list` is
/// `DEPTH_MAX`-bounded, but depth does not bound LEAF VISITS, and
/// an index's children are ordered by their declared cumulative
/// fields — which a repeated child satisfies, because each repeat's
/// true contribution is added again. Fifteen index levels of
/// fanout 4, every level naming the level below FOUR TIMES, is
/// sixteen objects and about 3.5 KB of manifest, and asks for
/// `4^15 = 1_073_741_824` leaf visits with `shape.leaves` growing
/// one entry per VISIT (about 17 GB) before any verdict lands.
///
/// The budget is `grain_count`'s own leaf count, which
/// `check_fill_canonical` already demands EQUALITY against
/// ("`shape.leaves.len() != total.div_ceil(leaf_cap)` =>
/// `FillNotCanonical`"), so anything the bail refuses was certain
/// to be refused anyway — accept-set neutral by construction, same
/// verdict, just sooner.
#[test]
fn validate_dir_tree_refuses_a_shared_child_grain_list_without_walking_it() {
    const LEVELS: u32 = 15;
    const FANOUT: u64 = 4;
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let leaf = node::encode_grain_list_leaf(&[gref("g", 1)]).unwrap_or_else(|e| panic!("{e}"));
    let mut child = GrainId::of(&leaf);
    map.insert(child, leaf);
    // (unpacked_len, ref_count) the subtree under `child` reports.
    let mut sub: u64 = 1;
    for _ in 0..LEVELS {
        let children: Vec<GrainListIndexChild> = (1..=FANOUT)
            .map(|k| GrainListIndexChild {
                child,
                cum_unpacked_len: sub * k,
                cum_ref_count: sub * k,
            })
            .collect();
        let bytes = node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
        child = GrainId::of(&bytes);
        map.insert(child, bytes);
        sub *= FANOUT;
    }
    assert_eq!(sub, 1_073_741_824, "4^15 leaf visits are what it asks for");
    assert_eq!(map.len(), LEVELS as usize + 1, "sixteen objects");
    let manifest_bytes: usize = map.values().map(Vec::len).sum();
    assert!(manifest_bytes < 4096, "{manifest_bytes} bytes of manifest");

    let count = u32::try_from(sub).unwrap_or_else(|e| panic!("{e}"));
    let (root_id, dir_bytes) = dir_with_spill(sub, count, child);
    map.insert(root_id, dir_bytes);

    let fetch = CountingFetch::new(&map);
    let err = validate_dir_tree(&root_id, &|id| fetch.get(id)).expect_err("must reject");
    assert_eq!(err, ValidateError::FillNotCanonical);
    // The declared count buys 8192 leaves; the walk stops there
    // instead of running a billion of them — the refusal variant
    // above is the budget's pin. The fetch count does not carry
    // the leaf-visit term (the leaf-facts memo answers repeat
    // visits without a fetch), so this bound measures INDEX
    // visits plus one fetch per distinct leaf; the budget's own
    // hit-path refusal is pinned separately by
    // `a_repeated_leaf_crossing_the_budget_is_refused_on_the_hit_path`.
    let budget = sub.div_ceil(u64::from(GRAINLIST_LEAF_MAX_REFS));
    assert_eq!(budget, 8192);
    assert!(
        fetch.calls() < 4_000,
        "{} fetches for a budget of {budget}",
        fetch.calls()
    );
}

/// **The memo work proof.** Four entries per directory, all
/// naming the same child, nested twelve deep: thirteen objects
/// describing `4^12 = 16_777_216` node visits. Without
/// memoization this walk is infeasible; with it the fetch count is
/// the number of DISTINCT nodes and nothing more.
#[test]
fn validate_dir_tree_visits_a_shared_child_tree_once_per_distinct_node() {
    const LEVELS: u32 = 12;
    const KIDS: u32 = 4;
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let empty = node::encode_dir_leaf(&[]).unwrap_or_else(|e| panic!("{e}"));
    let mut child = GrainId::of(&empty);
    map.insert(child, empty);
    for _ in 0..LEVELS {
        let (id, bytes) = dir_of_repeated_child(KIDS, child);
        child = id;
        map.insert(child, bytes);
    }
    assert_eq!(map.len(), LEVELS as usize + 1);

    let fetch = CountingFetch::new(&map);
    let stats = validate_dir_tree(&child, &|id| fetch.get(id)).unwrap_or_else(|e| panic!("{e}"));
    // entries(k) = KIDS + KIDS * entries(k-1), entries(0) = 0.
    let expected = (0..LEVELS).fold(0u64, |acc, _| u64::from(KIDS) * (acc + 1));
    assert_eq!(expected, 22_369_620);
    assert_eq!(stats.entries, expected);
    assert_eq!(stats.dirs, expected + 1);
    assert_eq!(
        fetch.calls(),
        map.len() as u64,
        "one fetch per distinct node"
    );
}

/// **The counting fields are reachable.** `stats.grains`/`bytes`
/// saturate because a lying declared `u64` reaches them before
/// it is refuted. The four COUNTING fields are reachable only
/// through memo replay: without it, overflowing them would mean
/// walking `u64::MAX` entries. With it, 256 entries all naming
/// the same child, nested eight deep, is NINE objects and
/// `entries = 256 * (256^8 - 1) / 255`, which is past
/// `u64::MAX`. Release builds run with `overflow-checks = true`
/// (workspace `Cargo.toml`), so a plain `+=` here is an abort,
/// not a wrap.
#[test]
fn validate_dir_tree_saturates_the_counting_stats_under_memo_replay() {
    const LEVELS: u32 = 8;
    let mut map: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let empty = node::encode_dir_leaf(&[]).unwrap_or_else(|e| panic!("{e}"));
    let mut child = GrainId::of(&empty);
    map.insert(child, empty);
    for _ in 0..LEVELS {
        let (id, bytes) = dir_of_repeated_child(DIR_LEAF_MAX_ENTRIES, child);
        child = id;
        map.insert(child, bytes);
    }
    assert_eq!(map.len(), LEVELS as usize + 1, "nine objects");

    let fetch = CountingFetch::new(&map);
    let stats = validate_dir_tree(&child, &|id| fetch.get(id)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.entries, u64::MAX);
    assert_eq!(stats.dirs, u64::MAX);
    assert_eq!(fetch.calls(), map.len() as u64);
}

// LEGACY-ORACLE-BEGIN
/// The PRE-CURSOR validator, retained as the differential's
/// independent oracle. NEVER edit it to track the production
/// function: its whole value is that it is not the code under test.
fn legacy_validate_dir_tree(
    root: &GrainId,
    fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
) -> Result<TreeStats, ValidateError> {
    // Subtree delta per directory id. Cycles would need a hash
    // preimage (see `CorruptObject`), so the reachable object graph is
    // a DAG and this post-order drain terminates.
    let mut memo: BTreeMap<GrainId, TreeStats> = BTreeMap::new();
    let mut spill_seen: BTreeSet<(GrainId, u64, u32)> = BTreeSet::new();
    let mut leaf_facts: BTreeMap<GrainId, LeafFacts> = BTreeMap::new();
    // `frame` is always a live directory and `stack` holds only its
    // ancestors, so no arm below can observe an empty worklist.
    let mut frame = validate_one_dir(root, fetch, &mut spill_seen, &mut leaf_facts)?;
    let mut stack: Vec<DirFrame> = Vec::new();
    loop {
        if let Some(child) = frame.todo.pop() {
            if let Some(sub) = memo.get(&child).copied() {
                frame.acc = frame.acc.saturating_sum(sub);
            } else {
                stack.push(frame);
                frame = validate_one_dir(&child, fetch, &mut spill_seen, &mut leaf_facts)?;
            }
            continue;
        }
        // `todo` drained: this directory's whole subtree is verified.
        let subtree = frame.acc;
        memo.insert(frame.id, subtree);
        if let Some(mut parent) = stack.pop() {
            parent.acc = parent.acc.saturating_sum(subtree);
            frame = parent;
        } else {
            let mut total = subtree;
            total.dirs = total.dirs.saturating_add(1); // the root itself
            return Ok(total);
        }
    }
}
// LEGACY-ORACLE-END

// ---- the differential driver ---------------------------------------
//
// `Cell` and `RefCell` are what the driver and the work rows need, and
// nothing else in this module imports them, so the driver imports
// them here.

use std::cell::{Cell, RefCell};

/// The universe every drive fetches from, and the ids resident before
/// the first resume. A store missing an object is a legitimate case:
/// every drive must then report the SAME `MissingObject`.
struct Scenario<'a> {
    root: GrainId,
    store: &'a BTreeMap<GrainId, Vec<u8>>,
    initial: BTreeSet<GrainId>,
}

#[derive(Clone, Copy, Debug)]
enum Drive {
    /// `validate_dir_tree` over the whole store — the reference.
    OneShot,
    /// The pre-cursor body, retained verbatim — the INDEPENDENT reference.
    Legacy,
    /// Today's `fetch_tree_structure` shape: restart the legacy walk from
    /// the root on every miss, fetching one object per restart.
    Restart,
    /// The cursor, one `Need` per round, nothing else fetched.
    Cursor,

    /// The cursor, plus every hint the pass names after each `Need`.
    CursorHints,
}

fn run_drive(drive: Drive, s: &Scenario<'_>) -> Result<TreeStats, ValidateError> {
    let full = |id: &GrainId| s.store.get(id).cloned();
    match drive {
        Drive::OneShot => validate_dir_tree(&s.root, &full),
        Drive::Legacy => legacy_validate_dir_tree(&s.root, &full),
        Drive::Restart => {
            let resident: RefCell<BTreeMap<GrainId, Vec<u8>>> = RefCell::new(
                s.initial
                    .iter()
                    .filter_map(|id| s.store.get(id).map(|b| (*id, b.clone())))
                    .collect(),
            );
            loop {
                let outcome =
                    legacy_validate_dir_tree(&s.root, &|id| resident.borrow().get(id).cloned());
                match outcome {
                    Err(ValidateError::MissingObject { id })
                        if !resident.borrow().contains_key(&id) =>
                    {
                        match s.store.get(&id) {
                            Some(bytes) => {
                                resident.borrow_mut().insert(id, bytes.clone());
                            }
                            None => return Err(ValidateError::MissingObject { id }),
                        }
                    }
                    other => return other,
                }
            }
        }
        Drive::Cursor => {
            let resident: RefCell<BTreeMap<GrainId, Vec<u8>>> = RefCell::new(
                s.initial
                    .iter()
                    .filter_map(|id| s.store.get(id).map(|b| (*id, b.clone())))
                    .collect(),
            );
            let mut cursor = TreeCursor::new(s.root);
            loop {
                let step = cursor.resume(&|id| resident.borrow().get(id).cloned())?;
                match step {
                    Step::Done(stats) => return Ok(stats),
                    Step::Need(id) => {
                        assert!(
                            !resident.borrow().contains_key(&id),
                            "a Need for a resident id is an unstable fetch"
                        );
                        match s.store.get(&id) {
                            Some(bytes) => {
                                resident.borrow_mut().insert(id, bytes.clone());
                            }
                            None => return Err(ValidateError::MissingObject { id }),
                        }
                    }
                }
            }
        }

        Drive::CursorHints => {
            let resident: RefCell<BTreeMap<GrainId, Vec<u8>>> = RefCell::new(
                s.initial
                    .iter()
                    .filter_map(|id| s.store.get(id).map(|b| (*id, b.clone())))
                    .collect(),
            );
            let mut cursor = TreeCursor::new(s.root);
            loop {
                let step = cursor.resume(&|id| resident.borrow().get(id).cloned())?;
                match step {
                    Step::Done(stats) => return Ok(stats),
                    Step::Need(id) => {
                        assert!(
                            !resident.borrow().contains_key(&id),
                            "a Need for a resident id is an unstable fetch"
                        );
                        match s.store.get(&id) {
                            Some(bytes) => {
                                resident.borrow_mut().insert(id, bytes.clone());
                            }
                            None => return Err(ValidateError::MissingObject { id }),
                        }
                        let hints = cursor.prefetch_hints(
                            &|id| resident.borrow().get(id).cloned(),
                            PREFETCH_HINT_MAX,
                        );
                        // A hint the store cannot serve is SKIPPED, which
                        // is what a real caller does with a fetch that
                        // fails — several fixtures name a child that is
                        // absent from `store` on purpose, so this arm
                        // cannot demand that every hint resolve.
                        //
                        // WHAT THIS SWEEP THEREFORE ATTESTS, exactly: that
                        // hints do not change the VERDICT. It does NOT
                        // attest that any hint was USEFUL or even
                        // well-formed — a pass emitting nothing but
                        // garbage ids would leave this arm behaving
                        // identically to `Drive::Cursor` and would pass
                        // every fixture in the sweep. Emission itself is
                        // pinned by the dedicated oracle rows (the
                        // spend/emission tuples, the wide-directory and
                        // wide-spill round counts, and the 4,094-leaf
                        // cliff row), never by this differential. Read
                        // both before concluding the hint pass is
                        // covered. The separate round-count and cliff
                        // rows remain necessary because this differential
                        // checks verdict agreement, not those performance
                        // boundaries.
                        let mut r = resident.borrow_mut();
                        for h in hints.entering.into_iter().chain(hints.queued_roots) {
                            if let Some(bytes) = s.store.get(&h) {
                                r.entry(h).or_insert_with(|| bytes.clone());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Every drive agrees with the one-shot, and the legacy oracle agrees
/// with it too (the sanity half: if the legacy copy ever drifts from
/// the production one-shot on the FULL store, this is where it shows).
fn differential(label: &str, s: &Scenario<'_>, drives: &[Drive]) {
    let reference = run_drive(Drive::OneShot, s);
    assert_eq!(
        run_drive(Drive::Legacy, s),
        reference,
        "{label}: legacy oracle vs one-shot"
    );
    for &d in drives {
        assert_eq!(run_drive(d, s), reference, "{label}: {d:?} vs one-shot");
    }
}

/// Every subset of `ids` as an initial residency, for fixtures small
/// enough to enumerate (≤ 12 objects); larger ones use `seeded_orders`.
fn exhaustive_residency(
    label: &str,
    root: GrainId,
    store: &BTreeMap<GrainId, Vec<u8>>,
    drives: &[Drive],
) {
    let ids: Vec<GrainId> = store.keys().copied().collect();
    assert!(
        ids.len() <= 12,
        "{label}: use seeded_orders above 12 objects"
    );
    for mask in 0u32..(1u32 << ids.len()) {
        let initial: BTreeSet<GrainId> = ids
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, id)| *id)
            .collect();
        differential(
            &format!("{label} mask={mask:b}"),
            &Scenario {
                root,
                store,
                initial: initial.clone(),
            },
            drives,
        );
        // The same subset with ONE object deleted from the store: a
        // `MissingObject` can then land anywhere.
        for victim in &ids {
            let mut reduced = store.clone();
            reduced.remove(victim);
            let initial: BTreeSet<GrainId> =
                initial.iter().copied().filter(|i| i != victim).collect();
            differential(
                &format!("{label} mask={mask:b} minus {victim:?}"),
                &Scenario {
                    root,
                    store: &reduced,
                    initial,
                },
                drives,
            );
        }
    }
}

/// 24 seeded initial residencies (a linear-congruential walk over the
/// id list), odd seeds also deleting one random object from the store.
fn seeded_orders(label: &str, root: GrainId, store: &BTreeMap<GrainId, Vec<u8>>, drives: &[Drive]) {
    let ids: Vec<GrainId> = store.keys().copied().collect();
    // The `Restart` drive re-runs the WHOLE walk once per missing
    // object, so a sweep costs O(seeds x objects^2) node walks. At 24
    // seeds the 260-object `depth_lopsided_impostor` alone is ~50 s;
    // the wide fixtures get 6 seeds, which still crosses every arm of
    // every drive. (Measured.)
    let seeds = if ids.len() > 64 { 6 } else { 24 };
    for seed in 0u64..seeds {
        let mut x = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut initial = BTreeSet::new();
        for id in &ids {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            if (x >> 33) & 1 == 1 {
                initial.insert(*id);
            }
        }
        let mut reduced = store.clone();
        if seed % 2 == 1 {
            let victim = ids[(x >> 40) as usize % ids.len()];
            reduced.remove(&victim);
            initial.remove(&victim);
        }
        differential(
            &format!("{label} seed={seed}"),
            &Scenario {
                root,
                store: &reduced,
                initial,
            },
            drives,
        );
    }
}

// ---- the test-module toolkit and fixtures --------------------------
//
// The test-module helpers the differential rows compile against, in one
// place so an implementer never has to invent one. `name`/`gid`/`gref`/
// `fifo_entries` ALREADY EXIST in the module and are not re-added.
// `fifo_entries6`/`wide_directory` are defined with the hint tests below.

// ---- fixtures -----------------------------------------------------

type Store = BTreeMap<GrainId, Vec<u8>>;

fn inline_file(n: &str, grain_seed: &str, len: u32) -> DirEntry {
    DirEntry {
        name: name(n),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(len),
            grains: FileGrains::Inline(vec![gref(grain_seed, len)]),
        },
    }
}

fn dir_entry(n: &str, child: GrainId) -> DirEntry {
    DirEntry {
        name: name(n),
        kind: EntryKind::Dir { child },
    }
}

fn built_into(store: &mut Store, built: BuiltTree) -> GrainId {
    for (id, bytes) in built.nodes {
        store.insert(id, bytes);
    }
    built.root
}

fn dir_into(store: &mut Store, entries: &[DirEntry]) -> GrainId {
    built_into(store, build_dir(entries).unwrap_or_else(|e| panic!("{e}")))
}

fn spill_entry(n: &str, size: u64, grain_count: u32, root: GrainId) -> DirEntry {
    DirEntry {
        name: name(n),
        kind: EntryKind::File {
            exec: false,
            size,
            grains: FileGrains::Spill { grain_count, root },
        },
    }
}

/// root leaf of 12 directories, each 5 inline files (13 objects).
fn v_shape_12x5() -> (GrainId, Store) {
    let mut store = Store::new();
    let mut dirs = Vec::new();
    for d in 0..12u32 {
        let files: Vec<DirEntry> = (0..5u32)
            .map(|f| inline_file(&format!("f{f}"), &format!("v{d}-{f}"), 1 + f))
            .collect();
        let child = dir_into(&mut store, &files);
        dirs.push(dir_entry(&format!("d{d:02}"), child));
    }
    let root = dir_into(&mut store, &dirs);
    (root, store)
}

/// `n` nested one-child directories, innermost holds one file.
fn chain(n: usize) -> (GrainId, Store) {
    let mut store = Store::new();
    let mut child = dir_into(&mut store, &[inline_file("leaf", "chain-leaf", 7)]);
    for level in 0..n - 1 {
        child = dir_into(&mut store, &[dir_entry(&format!("d{level}"), child)]);
    }
    assert_eq!(store.len(), n);
    (child, store)
}

fn chain_40() -> (GrainId, Store) {
    chain(40)
}

/// 6 dirs × 4 dirs × 3 files (31 objects).
fn nested_6x4x3() -> (GrainId, Store) {
    let mut store = Store::new();
    let mut top = Vec::new();
    for a in 0..6u32 {
        let mut mid = Vec::new();
        for b in 0..4u32 {
            let files: Vec<DirEntry> = (0..3u32)
                .map(|c| inline_file(&format!("f{c}"), &format!("n{a}-{b}-{c}"), 1 + c))
                .collect();
            let child = dir_into(&mut store, &files);
            mid.push(dir_entry(&format!("m{b}"), child));
        }
        let child = dir_into(&mut store, &mid);
        top.push(dir_entry(&format!("t{a}"), child));
    }
    let root = dir_into(&mut store, &top);
    assert_eq!(store.len(), 31);
    (root, store)
}

/// One directory of THREE entries — `a` and `b` in one leaf, `z` in a
/// second, both under one interior — with the interior's second
/// `first_key` tampered, so the walk refuses `SeparatorMismatch`.
/// Nothing here is shared with `two_faults_two_dirs`, which is a
/// different fault in a different shape: count this fixture's
/// entries against the builder below, not against a sibling's doc.
fn separator_fault() -> (GrainId, Store) {
    let leaf1 = node::encode_dir_leaf(&[
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
    let leaf2 = node::encode_dir_leaf(&[DirEntry {
        name: name("z"),
        kind: EntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let leaf2_id = GrainId::of(&leaf2);
    let interior = node::encode_dir_interior(&[
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
    let mut store = Store::new();
    store.insert(leaf1_id, leaf1);
    store.insert(leaf2_id, leaf2);
    store.insert(root_id, interior);
    (root_id, store)
}

/// root leaf with two entries naming the SAME child directory (2 objects).
fn shared_subtree_dag() -> (GrainId, Store) {
    let mut store = Store::new();
    let s = dir_into(&mut store, &[inline_file("f", "dag-f", 3)]);
    let root = dir_into(&mut store, &[dir_entry("a", s), dir_entry("b", s)]);
    assert_eq!(store.len(), 2);
    (root, store)
}

/// two files naming one spill root with the SAME (size, count) (2 objects).
fn spill_seen_across_a_resume() -> (GrainId, Store) {
    let mut store = Store::new();
    let refs: Vec<GrainRef> = (0..129u32).map(|i| gref(&format!("ss-{i}"), 1)).collect();
    let gl_root = built_into(
        &mut store,
        build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}")),
    );
    let root = dir_into(
        &mut store,
        &[
            spill_entry("f1", 129, 129, gl_root),
            spill_entry("f2", 129, 129, gl_root),
        ],
    );
    assert_eq!(store.len(), 2);
    (root, store)
}

/// a file whose declared size disagrees with a spill root ABSENT from
/// the store (1 object).
fn lying_size_missing_spill_root() -> (GrainId, Store) {
    let mut store = Store::new();
    let root = dir_into(
        &mut store,
        &[spill_entry(
            "f",
            5,
            129,
            gid("lying-size-absent-spill-root"),
        )],
    );
    (root, store)
}

/// One maximal leaf; `f1` spills to an index naming it twice (budget 2,
/// canonical), `f2` to an index naming it three times (the third visit
/// crosses the budget). With the second index withheld, `f1`'s walk
/// fills `leaf_facts` in one resume and the crossing lands on a MEMO
/// HIT in the next. 4 objects.
fn budget_refusal_on_a_hit() -> (GrainId, Store) {
    let refs: Vec<GrainRef> = vec![gref("g", 1); GRAINLIST_LEAF_MAX_REFS as usize];
    let leaf_bytes = node::encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
    let leaf_id = GrainId::of(&leaf_bytes);
    let (index2_id, index2_bytes) = repeated_leaf_index(leaf_id, 2);
    let (index3_id, index3_bytes) = repeated_leaf_index(leaf_id, 3);
    let two = 2 * u64::from(GRAINLIST_LEAF_MAX_REFS);
    let two_count = u32::try_from(two).unwrap_or_else(|e| panic!("{e}"));
    let mut store = Store::new();
    store.insert(leaf_id, leaf_bytes);
    store.insert(index2_id, index2_bytes);
    store.insert(index3_id, index3_bytes);
    let root = dir_into(
        &mut store,
        &[
            spill_entry("f1", two, two_count, index2_id),
            spill_entry("f2", two, two_count, index3_id),
        ],
    );
    assert_eq!(store.len(), 4);
    (root, store)
}

const T2_DRIVES: &[Drive] = &[Drive::Restart, Drive::Cursor];

fn all_fixtures() -> Vec<(&'static str, bool, GrainId, Store)> {
    let mut v: Vec<(&'static str, bool, GrainId, Store)> = Vec::new();
    for (label, exhaustive, (root, store)) in [
        ("v_shape_12x5", false, v_shape_12x5()),
        ("chain_40", false, chain_40()),
        ("nested_6x4x3", false, nested_6x4x3()),
        ("two_faults_two_dirs", true, two_faults_two_dirs()),
        ("separator_fault", true, separator_fault()),
        ("shared_subtree_dag", true, shared_subtree_dag()),
        (
            "spill_seen_across_a_resume",
            true,
            spill_seen_across_a_resume(),
        ),
        (
            "lying_size_missing_spill_root",
            true,
            lying_size_missing_spill_root(),
        ),
        ("budget_refusal_on_a_hit", true, budget_refusal_on_a_hit()),
        ("wide_spill_64", false, wide_spill_64()),
        ("honest_spill_2_leaves", true, honest_spill_2_leaves()),
        (
            "spill_seen_index_root_across_a_stop",
            true,
            spill_seen_index_root_across_a_stop(),
        ),
        ("leaf_facts_at_two_depths", true, leaf_facts_at_two_depths()),
        ("leaf_budget_attack", false, leaf_budget_attack()),
        ("depth_lopsided_impostor", false, depth_lopsided_impostor()),
        ("chain_17_deep", false, chain_17_deep()),
        ("grain_list_17_deep", false, grain_list_17_deep()),
    ] {
        v.push((label, exhaustive, root, store));
    }
    v
}

fn sweep(label: &str, exhaustive: bool, root: GrainId, store: &Store, drives: &[Drive]) {
    if exhaustive {
        exhaustive_residency(label, root, store, drives);
    } else {
        seeded_orders(label, root, store, drives);
    }
}

// ---- contract rows -------------------------------------------------

/// The same LCG subset `seeded_orders` uses, exposed for the rows.
fn seeded_initial(seed: u64, ids: &[GrainId]) -> BTreeSet<GrainId> {
    let mut x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let mut initial = BTreeSet::new();
    for id in ids {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        if (x >> 33) & 1 == 1 {
            initial.insert(*id);
        }
    }
    initial
}

/// root leaf names `a` then `b`; `a`'s single file spills to an
/// honest 129-ref grain list while the ENTRY declares 130 refs
/// (`CountMismatch` on `a`); `b` is a chain whose innermost object is
/// absent from the store. 5 present objects.
fn two_faults_two_dirs() -> (GrainId, Store) {
    let mut store = Store::new();
    let refs: Vec<GrainRef> = (0..129u32).map(|i| gref(&format!("tf-{i}"), 1)).collect();
    let gl_root = built_into(
        &mut store,
        build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}")),
    );
    let a = dir_into(&mut store, &[spill_entry("f", 129, 130, gl_root)]);
    let absent = gid("two-faults-absent-innermost");
    let b1 = dir_into(&mut store, &[dir_entry("inner", absent)]);
    let b = dir_into(&mut store, &[dir_entry("mid", b1)]);
    let root = dir_into(&mut store, &[dir_entry("a", a), dir_entry("b", b)]);
    assert_eq!(store.len(), 5);
    (root, store)
}

/// One file spilling to an index over `leaves` DISTINCT one-ref
/// leaves. A CANONICAL n-leaf spill needs more than
/// (n − 1) × `GRAINLIST_LEAF_MAX_REFS` refs (64 leaves ≈ 305 MB of
/// leaves), so the only wide spill a unit test can build is this
/// HOSTILE one: one-ref leaves under an index whose cumulative
/// fields are honest, and a file entry declaring
/// (n − 1) × cap + 1 refs — so the leaf budget admits every leaf,
/// the walk visits all of them, and the verdict is `CountMismatch`
/// after the FULL walk, not `Ok`.
fn wide_spill(leaves: u64) -> (GrainId, Store) {
    let mut store = Store::new();
    let mut children = Vec::new();
    for i in 1..=leaves {
        let leaf = node::encode_grain_list_leaf(&[gref(&format!("ws-{i}"), 1)])
            .unwrap_or_else(|e| panic!("{e}"));
        let id = GrainId::of(&leaf);
        store.insert(id, leaf);
        children.push(GrainListIndexChild {
            child: id,
            cum_unpacked_len: i,
            cum_ref_count: i,
        });
    }
    let index = node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
    let index_id = GrainId::of(&index);
    store.insert(index_id, index);
    let declared = (leaves - 1) * u64::from(GRAINLIST_LEAF_MAX_REFS) + 1;
    let root = dir_into(
        &mut store,
        &[spill_entry(
            "f",
            leaves,
            u32::try_from(declared).unwrap_or_else(|e| panic!("{e}")),
            index_id,
        )],
    );
    (root, store)
}

/// The fixture-table row: 64 leaves, 66 objects.
fn wide_spill_64() -> (GrainId, Store) {
    let (root, store) = wide_spill(64);
    assert_eq!(store.len(), 66);
    (root, store)
}

/// One-off writer for the `manifest_walk` fuzz seeds. Each fixture is
/// serialised in `manifest_walk_probe`'s own framing — `n` (one byte),
/// then `n` blobs each behind a little-endian `u16` length, then a
/// little-endian `u32` residency mask of 0 — with the ROOT blob FIRST:
/// the probe roots its walk at the first blob, and a `Store` iterates
/// in id order, not root order. The probe's caps (32 objects, 4,096
/// bytes per blob) are asserted here, so a seed that would be
/// truncated fails loudly instead of driving nothing. Printed as hex
/// on stdout rather than written: file I/O stays out of the lib crate
/// (`tests/common/mod.rs` states the rule); the shell decodes and
/// names each seed by its sha1, which core does not have. Regenerate
/// when the format moves.
#[test]
#[ignore = "prints the manifest_walk fuzz seeds as hex; run by hand"]
fn write_manifest_walk_seeds() {
    use std::fmt::Write as _;
    let flat_3 = {
        let mut store = Store::new();
        let root = dir_into(
            &mut store,
            &[
                inline_file("a", "seed-a", 1),
                inline_file("b", "seed-b", 2),
                inline_file("c", "seed-c", 3),
            ],
        );
        (root, store)
    };
    for (label, (root, store)) in [
        ("flat_3", flat_3),
        ("nested_6x4x3", nested_6x4x3()),
        ("wide_spill_16", wide_spill(16)),
    ] {
        assert!(store.len() <= 32, "{label}: {} objects", store.len());
        let root_bytes = store
            .get(&root)
            .unwrap_or_else(|| panic!("{label}: no root"));
        let mut out = vec![u8::try_from(store.len()).unwrap_or_else(|e| panic!("{e}"))];
        let rest = store.iter().filter(|(id, _)| **id != root);
        for (id, bytes) in std::iter::once((&root, root_bytes)).chain(rest) {
            assert!(
                bytes.len() <= 4096,
                "{label}: {id} is {} bytes",
                bytes.len()
            );
            let len = u16::try_from(bytes.len()).unwrap_or_else(|e| panic!("{e}"));
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        let mut hex = String::with_capacity(out.len() * 2);
        for b in &out {
            write!(hex, "{b:02x}").unwrap_or_else(|e| panic!("{e}"));
        }
        println!("{label} {hex}");
    }
}

/// One file spilling to an index over TWO distinct HONEST leaves
/// (131,073 refs: the smallest canonical multi-leaf spill, ~5 MB).
/// With the second leaf withheld, the first leaf's facts land in
/// `leaf_facts` during an ABANDONED walk and the re-run visits it
/// as a HIT where the one-shot visits it as a MISS — the only shape
/// on which skipping a hit-path `Shape` push can make the cursor and the
/// one-shot disagree.
/// That makes the withheld second leaf load-bearing test setup.
fn honest_spill_2_leaves() -> (GrainId, Store) {
    let mut store = Store::new();
    let n = GRAINLIST_LEAF_MAX_REFS + 1;
    let refs: Vec<GrainRef> = (0..n).map(|i| gref(&format!("h2-{i}"), 1)).collect();
    let built = build_grain_list(&refs).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built.nodes.len(), 3, "two leaves and one index");
    let gl_root = built_into(&mut store, built);
    let root = dir_into(&mut store, &[spill_entry("f", u64::from(n), n, gl_root)]);
    assert_eq!(store.len(), 4);
    (root, store)
}

// ---- the fixture table's remaining five -------------------------

/// ONE grain-list leaf reached at spill-tree depth 1 AND depth 2, by
/// two different spilled files in the same directory: `a` names the
/// leaf directly, `b` an index over it twice. The leaf's facts are
/// memoized by `a`'s visit, so BOTH of `b`'s visits are memo HITS —
/// at a DIFFERENT depth than the visit that filled the memo. That is
/// the repeated-leaf property: a hit must still push `(depth, width)` into the
/// `Shape`, or `check_fill_canonical` sees no leaf where the
/// declaration says two.
///
/// Verdict `Ok`, and that is what makes it discriminating. The mutant that
/// skips the memo-hit push leaves `b`'s shape with zero leaves where two
/// are declared, so the walk answers `FillNotCanonical` where it should
/// answer `Ok`. Depth 3 is deliberately NOT here: a canonical grain list
/// over at most `GRAINLIST_INDEX_MAX_CHILDREN` leaves is exactly two
/// levels, so a third level is `FillNotCanonical` on its own — and a
/// fixture whose honest verdict is already `FillNotCanonical` cannot tell
/// the mutant apart from itself, since the differential and the premise
/// compare only the `ValidateError` variant. (A three-depth version was
/// measured GREEN under that same mutant.)
///
/// Distinct from `honest_spill_2_leaves`, which is a memo hit across
/// a RESUME on ONE file; this is a hit across FILES within one
/// directory walk, and it holds for the one-shot too. 3 objects.
fn leaf_facts_at_two_depths() -> (GrainId, Store) {
    let cap = GRAINLIST_LEAF_MAX_REFS;
    let cap64 = u64::from(cap);
    let refs: Vec<GrainRef> = vec![gref("lf-g", 1); cap as usize];
    let leaf = node::encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
    let leaf_id = GrainId::of(&leaf);
    let i2 = node::encode_grain_list_index(&[
        GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: cap64,
            cum_ref_count: cap64,
        },
        GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: 2 * cap64,
            cum_ref_count: 2 * cap64,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let i2_id = GrainId::of(&i2);
    let mut store = Store::new();
    store.insert(leaf_id, leaf);
    store.insert(i2_id, i2);
    let root = dir_into(
        &mut store,
        &[
            spill_entry("a", cap64, cap, leaf_id),
            spill_entry("b", 2 * cap64, 2 * cap, i2_id),
        ],
    );
    assert_eq!(store.len(), 3, "the leaf, one index, one dir leaf");
    (root, store)
}

/// Two file entries in two DIRECTORIES naming ONE spill root that is
/// an INDEX: `a` in the root directory and `b` in the subdirectory
/// `s`, both declaring (131,074 bytes, 131,074 grains) over an index
/// that names one 65,537-ref leaf twice — the canonical shape for
/// 131,074 refs is two leaves of 65,537, and a repeated child is two
/// visits of one object, so this is the smallest canonical
/// index-rooted spill in DISTINCT bytes (half of
/// `honest_spill_2_leaves`). `a`'s success lands the entry in
/// `spill_seen` during the root directory's walk; the cursor then
/// stops on the absent subdirectory, so `b` is met in a LATER resume.
/// Index ids are never `leaf_facts` keys, so the only thing that can
/// spare `b` a re-fetch of the index is `spill_seen` surviving that
/// stop — the one component of retained cursor state that the bytes
/// pin over the other two spill fixtures cannot see (confirmed by
/// mutation: it stayed green under a `spill_seen`-only reset). Four
/// objects: the leaf (2,424,883 bytes), the index (112), the
/// subdirectory leaf (62), the root leaf (98).
fn spill_seen_index_root_across_a_stop() -> (GrainId, Store) {
    let width: u32 = 65_537;
    let refs: Vec<GrainRef> = vec![gref("si-g", 1); width as usize];
    let leaf = node::encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
    let leaf_id = GrainId::of(&leaf);
    let one = u64::from(width);
    let index = node::encode_grain_list_index(&[
        GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: one,
            cum_ref_count: one,
        },
        GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: 2 * one,
            cum_ref_count: 2 * one,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let index_id = GrainId::of(&index);
    let sizes = (leaf.len(), index.len());
    assert_eq!(sizes, (2_424_883, 112), "leaf and index bytes");
    let mut store = Store::new();
    store.insert(leaf_id, leaf);
    store.insert(index_id, index);
    let total = 2 * one;
    let count = 2 * width;
    let sub = dir_into(&mut store, &[spill_entry("b", total, count, index_id)]);
    let root = dir_into(
        &mut store,
        &[
            spill_entry("a", total, count, index_id),
            dir_entry("s", sub),
        ],
    );
    let sub_len = store.get(&sub).map_or(0, Vec::len);
    let root_len = store.get(&root).map_or(0, Vec::len);
    assert_eq!((sub_len, root_len), (62, 98), "the two dir leaves' bytes");
    assert_eq!(store.len(), 4, "the leaf, the index, two dir leaves");
    (root, store)
}

/// Leaf-budget attack shape: fifteen fanout-4 grain-list index levels
/// over ONE leaf, so a naive walk would visit 4^15 ≈ 1.07 billion
/// leaves. The leaf budget refuses it after `declared / cap`
/// visits. 17 objects.
fn leaf_budget_attack() -> (GrainId, Store) {
    let mut store = Store::new();
    let leaf = node::encode_grain_list_leaf(&[gref("lb-g", 1)]).unwrap_or_else(|e| panic!("{e}"));
    let mut child = GrainId::of(&leaf);
    store.insert(child, leaf);
    let mut sub: u64 = 1;
    for _ in 0..15 {
        let children: Vec<GrainListIndexChild> = (1..=4)
            .map(|k| GrainListIndexChild {
                child,
                cum_unpacked_len: sub * k,
                cum_ref_count: sub * k,
            })
            .collect();
        let bytes = node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
        child = GrainId::of(&bytes);
        store.insert(child, bytes);
        sub *= 4;
    }
    let count = u32::try_from(sub).unwrap_or_else(|e| panic!("{e}"));
    let root = dir_into(&mut store, &[spill_entry("f", sub, count, child)]);
    assert_eq!(store.len(), 17, "one leaf, fifteen indexes, one dir leaf");
    (root, store)
}

/// The depth-lopsided impostor of `validate_rejects_depth_lopsided_shape`,
/// factored out so the differential can drive it: 257 leaves of 256
/// FIFO entries reproducing the CANONICAL width sequence ([129, 128]
/// then [2]) while NOT being uniform height —
///   root (depth 1, width 2) -> { Y, last leaf }
///   Y    (depth 2, width 128) = 127 direct leaves + X
///   X    (depth 3, width 129) = the remaining 129 leaves (depth 4)
/// Every separator and count comes from the real contiguous
/// partition, so the walk reaches the fill check rather than failing
/// earlier. 260 objects.
fn depth_lopsided_impostor() -> (GrainId, Store) {
    let c = DIR_LEAF_MAX_ENTRIES as usize;
    let leaves_needed = c + 1;
    let n_total = c * leaves_needed;
    let entries = fifo_entries(u32::try_from(n_total).unwrap_or_else(|e| panic!("{e}")));
    let mut leaf_infos: Vec<(GrainId, Vec<u8>, Vec<u8>, u64)> = Vec::new();
    for chunk in entries.chunks(c) {
        let bytes = node::encode_dir_leaf(chunk).unwrap_or_else(|e| panic!("{e}"));
        let id = GrainId::of(&bytes);
        let first = chunk.first().unwrap_or_else(|| panic!("chunk nonempty"));
        leaf_infos.push((
            id,
            bytes,
            first.name.as_bytes().to_vec(),
            chunk.len() as u64,
        ));
    }
    let split = split_counts(leaves_needed, c);
    let s1 = *split.first().unwrap_or_else(|| panic!("split nonempty"));
    let s2 = *split
        .get(1)
        .unwrap_or_else(|| panic!("split has 2 entries"));
    let y_direct_count = s2 - 1;
    let x_count = s1;
    let mut store = Store::new();
    for (id, bytes, ..) in &leaf_infos {
        store.insert(*id, bytes.clone());
    }
    let make_child = |(id, _, first, count): &(GrainId, Vec<u8>, Vec<u8>, u64)| InteriorChild {
        first_key: Name::new(first.clone()).unwrap_or_else(|e| panic!("{e}")),
        child: *id,
        subtree_entry_count: *count,
    };
    let x_children: Vec<InteriorChild> = leaf_infos
        .get(y_direct_count..y_direct_count + x_count)
        .unwrap_or_else(|| panic!("x slice"))
        .iter()
        .map(make_child)
        .collect();
    let x_bytes = node::encode_dir_interior(&x_children).unwrap_or_else(|e| panic!("{e}"));
    let x_id = GrainId::of(&x_bytes);
    store.insert(x_id, x_bytes);
    let x_total: u64 = x_children.iter().map(|ch| ch.subtree_entry_count).sum();
    let x_first_key = x_children
        .first()
        .unwrap_or_else(|| panic!("x nonempty"))
        .first_key
        .clone();
    let mut y_children: Vec<InteriorChild> = leaf_infos
        .get(..y_direct_count)
        .unwrap_or_else(|| panic!("y slice"))
        .iter()
        .map(make_child)
        .collect();
    y_children.push(InteriorChild {
        first_key: x_first_key,
        child: x_id,
        subtree_entry_count: x_total,
    });
    let y_bytes = node::encode_dir_interior(&y_children).unwrap_or_else(|e| panic!("{e}"));
    let y_id = GrainId::of(&y_bytes);
    store.insert(y_id, y_bytes);
    let y_total: u64 = y_children.iter().map(|ch| ch.subtree_entry_count).sum();
    let y_first_key = y_children
        .first()
        .unwrap_or_else(|| panic!("y nonempty"))
        .first_key
        .clone();
    let last = leaf_infos
        .last()
        .unwrap_or_else(|| panic!("leaves nonempty"));
    let root_bytes = node::encode_dir_interior(&[
        InteriorChild {
            first_key: y_first_key,
            child: y_id,
            subtree_entry_count: y_total,
        },
        make_child(last),
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root_id = GrainId::of(&root_bytes);
    store.insert(root_id, root_bytes);
    assert_eq!(store.len(), leaves_needed + 3, "257 leaves, X, Y, root");
    (root_id, store)
}

/// `tests/manifest_rejects.rs`'s `validate_dir_tree_rejects_17_deep_chain`,
/// rebuilt here so the cursor drives can be run over it: sixteen
/// directory interiors wrapping a MISSING leaf. Depth is exceeded on
/// the would-be 17th descent, before the walker ever needs to fetch
/// it. 16 objects.
fn chain_17_deep() -> (GrainId, Store) {
    let mut store = Store::new();
    let mut next_child = gid("past-the-cap-unreachable");
    for level in (1..=DEPTH_MAX).rev() {
        let bytes = node::encode_dir_interior(&[
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
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        next_child = GrainId::of(&bytes);
        store.insert(next_child, bytes);
    }
    assert_eq!(store.len(), DEPTH_MAX as usize);
    (next_child, store)
}

/// The grain-list twin, from the same file: sixteen grain-list
/// indexes wrapping a MISSING leaf, under a one-file directory that
/// spills to them. `walk_grain_list` carries its OWN depth budget
/// (a spill tree is its own tree, rule 4), so the dir-side chain
/// above cannot reach this cap. 17 objects.
fn grain_list_17_deep() -> (GrainId, Store) {
    let mut store = Store::new();
    let mut next_child = gid("past-the-cap-unreachable-grain-list");
    for level in (1..=DEPTH_MAX).rev() {
        let bytes = node::encode_grain_list_index(&[
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
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        next_child = GrainId::of(&bytes);
        store.insert(next_child, bytes);
    }
    let grain_count = FILE_INLINE_MAX_REFS + 1;
    let root = dir_into(
        &mut store,
        &[spill_entry(
            "f",
            u64::from(grain_count),
            grain_count,
            next_child,
        )],
    );
    assert_eq!(store.len(), DEPTH_MAX as usize + 1);
    (root, store)
}

// --------------------------- the legacy oracle's source pin --------

/// The digest of `legacy_validate_dir_tree`'s body, over the text
/// strictly BETWEEN the two marker lines. The oracle's whole value
/// is that it is not the code under test, and its "NEVER edit it"
/// doc comment had no gate; this is the gate. An intentional edit
/// updates the constant — deliberately, in the same commit — and the
/// message prints the digest that was computed, so an accidental one
/// names its own replacement.
///
/// The digest covers exact source bytes, including leading indentation.
/// Any logic or whitespace edit inside the markers therefore requires a
/// deliberate update to this constant.
const LEGACY_ORACLE_DIGEST: &str =
    "blake3:d728d91a20a04b95fb89f5c5d6f549e8c98b4bf782f8a7b49a37ffffaea365bb";

#[test]
fn legacy_oracle_body_is_pinned() {
    // The markers are assembled rather than written out, so the
    // literals below are not themselves found by the search.
    let begin = concat!("// LEGACY-", "ORACLE-BEGIN\n");
    let end = concat!("// LEGACY-", "ORACLE-END");
    let text = include_str!("tests.rs");
    let from = text
        .find(begin)
        .unwrap_or_else(|| panic!("the LEGACY-ORACLE-BEGIN marker is gone"))
        + begin.len();
    let to = text[from..]
        .find(end)
        .unwrap_or_else(|| panic!("the LEGACY-ORACLE-END marker is gone"))
        + from;
    let body = text
        .get(from..to)
        .unwrap_or_else(|| panic!("markers out of order"));
    let digest = GrainId::of(body.as_bytes());
    assert_eq!(
        digest.to_string(),
        LEGACY_ORACLE_DIGEST,
        "legacy_validate_dir_tree's body moved ({} bytes). It is the \
         differential's INDEPENDENT oracle and must never be edited to \
         track the production walker. If the edit is deliberate, set \
         LEGACY_ORACLE_DIGEST to the `left` digest in the same commit.",
        body.len()
    );
}

// The SIXTEEN `cursor_differential_*`
// rows and the THREE contract rows. Every POSITIVE premise now binds the
// verdict and prints it — a bare `is_ok()` red says only that it was not
// Ok, and which error it became is the finding (the negative
// premises, `assert_eq!(.., Err(..))` and `matches!(.., Err(..))`,
// already name their side).
//
// `T2_DRIVES`-ONLY and grep-clean: no identifier from the hint pass
// appears below. Every row drives `T2_DRIVES` (`[Restart, Cursor]`).

// ---- one differential row per fixture -----------------------------

#[test]
fn cursor_differential_v_shape_12x5() {
    let (root, store) = v_shape_12x5();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "twelve directories of five inline files each, canonical throughout: {verdict:?}"
    );
    sweep("v_shape_12x5", false, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_chain_40() {
    let (root, store) = chain_40();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "forty nested one-child directories, canonical throughout: {verdict:?}"
    );
    sweep("chain_40", false, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_nested_6x4x3() {
    let (root, store) = nested_6x4x3();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "six by four directories over three inline files each, canonical throughout: {verdict:?}"
    );
    sweep("nested_6x4x3", false, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_two_faults_two_dirs() {
    let (root, store) = two_faults_two_dirs();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::CountMismatch)
    );
    sweep("two_faults_two_dirs", true, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_separator_fault() {
    let (root, store) = separator_fault();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::SeparatorMismatch)
    );
    sweep("separator_fault", true, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_shared_subtree_dag() {
    let (root, store) = shared_subtree_dag();
    let stats =
        validate_dir_tree(&root, &|id| store.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.dirs, 3, "counted once per path as today");
    sweep("shared_subtree_dag", true, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_spill_seen_across_a_resume() {
    let (root, store) = spill_seen_across_a_resume();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "two files naming ONE spill root with the same (size, count), so the \
         second is a `spill_seen` hit and both are canonical: {verdict:?}"
    );
    sweep("spill_seen_across_a_resume", true, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_lying_size_missing_spill_root() {
    let (root, store) = lying_size_missing_spill_root();
    assert!(matches!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::MissingObject { .. })
    ));
    sweep(
        "lying_size_missing_spill_root",
        true,
        root,
        &store,
        T2_DRIVES,
    );
}

#[test]
fn cursor_differential_budget_refusal_on_a_hit() {
    let (root, store) = budget_refusal_on_a_hit();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::FillNotCanonical)
    );
    sweep("budget_refusal_on_a_hit", true, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_honest_spill_2_leaves() {
    let (root, store) = honest_spill_2_leaves();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "131,073 refs over two distinct honest leaves — the smallest \
         canonical multi-leaf spill: {verdict:?}"
    );
    sweep("honest_spill_2_leaves", true, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_spill_seen_index_root_across_a_stop() {
    let (root, store) = spill_seen_index_root_across_a_stop();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "two files in two directories naming one INDEX-rooted spill twice, canonical \
         throughout: {verdict:?}"
    );
    sweep(
        "spill_seen_index_root_across_a_stop",
        true,
        root,
        &store,
        T2_DRIVES,
    );
}

#[test]
fn cursor_differential_wide_spill_64() {
    let (root, store) = wide_spill_64();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::CountMismatch),
        "a canonical 64-leaf spill is ~305 MB; this is the hostile shape walked in full"
    );
    sweep("wide_spill_64", false, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_leaf_facts_at_two_depths() {
    let (root, store) = leaf_facts_at_two_depths();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the whole
    // finding (skipping the hit-path push makes it `FillNotCanonical`).
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "both files are canonical, so a memo HIT must leave the same \
         `Shape` trace an unmemoized visit would: {verdict:?}"
    );
    sweep("leaf_facts_at_two_depths", true, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_leaf_budget_attack() {
    let (root, store) = leaf_budget_attack();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::FillNotCanonical)
    );
    sweep("leaf_budget_attack", false, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_depth_lopsided_impostor() {
    let (root, store) = depth_lopsided_impostor();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::FillNotCanonical)
    );
    sweep("depth_lopsided_impostor", false, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_chain_17_deep() {
    let (root, store) = chain_17_deep();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::DepthExceeded)
    );
    sweep("chain_17_deep", false, root, &store, T2_DRIVES);
}

#[test]
fn cursor_differential_grain_list_17_deep() {
    let (root, store) = grain_list_17_deep();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::DepthExceeded)
    );
    sweep("grain_list_17_deep", false, root, &store, T2_DRIVES);
}

// ---- the three contract rows --------------------------------------

#[test]
fn cursor_need_matches_the_legacy_first_missing_object() {
    let mut stops = 0u64;
    for (label, _, root, store) in all_fixtures() {
        let ids: Vec<GrainId> = store.keys().copied().collect();
        // Same scaling as `seeded_orders`, for the same reason: this
        // row runs a LEGACY walk at every stop, and a wide fixture
        // stops once per object.
        let seeds = if ids.len() > 64 { 6 } else { 24 };
        for seed in 0..seeds {
            let resident: RefCell<Store> = RefCell::new(
                seeded_initial(seed, &ids)
                    .iter()
                    .filter_map(|id| store.get(id).map(|b| (*id, b.clone())))
                    .collect(),
            );
            let mut cursor = TreeCursor::new(root);
            loop {
                let step = cursor.resume(&|id| resident.borrow().get(id).cloned());
                match step {
                    Ok(Step::Need(id)) => {
                        stops += 1;
                        let legacy = legacy_validate_dir_tree(&root, &|id| {
                            resident.borrow().get(id).cloned()
                        });
                        assert_eq!(
                            legacy,
                            Err(ValidateError::MissingObject { id }),
                            "{label} seed={seed}: Need vs the legacy first MissingObject"
                        );
                        match store.get(&id) {
                            Some(bytes) => {
                                resident.borrow_mut().insert(id, bytes.clone());
                            }
                            None => break,
                        }
                    }
                    Ok(Step::Done(_)) | Err(_) => break,
                }
            }
        }
    }
    assert!(stops > 1000, "the row must actually stop: {stops}");
}

#[test]
fn cursor_is_idempotent_at_a_stop_and_after_finishing() {
    // At a stop: nothing resident, the same Need twice.
    let (root, store) = chain_40();
    let empty: Store = Store::new();
    let mut cursor = TreeCursor::new(root);
    let first = cursor.resume(&|id| empty.get(id).cloned());
    let second = cursor.resume(&|id| empty.get(id).cloned());
    assert_eq!(first, Ok(Step::Need(root)));
    assert_eq!(second, first);
    // After Done: Done again with equal stats.
    let mut cursor = TreeCursor::new(root);
    let done = cursor.resume(&|id| store.get(id).cloned());
    let Ok(Step::Done(stats)) = done else {
        panic!("{done:?}");
    };
    assert_eq!(
        cursor.resume(&|id| store.get(id).cloned()),
        Ok(Step::Done(stats))
    );
    assert_eq!(
        cursor.resume(&|id| empty.get(id).cloned()),
        Ok(Step::Done(stats))
    );
    // After an error: the same error, twice, even over an emptied store.
    let (root, store) = two_faults_two_dirs();
    let mut cursor = TreeCursor::new(root);
    let err = cursor.resume(&|id| store.get(id).cloned());
    assert_eq!(err, Err(ValidateError::CountMismatch));
    assert_eq!(cursor.resume(&|id| store.get(id).cloned()), err);
    assert_eq!(cursor.resume(&|id| empty.get(id).cloned()), err);
}

#[test]
fn cursor_is_idempotent_below_the_root_at_a_nested_stop() {
    // `cursor_is_idempotent_at_a_stop_and_after_finishing`'s first
    // case stops at the ROOT itself (nothing resident, empty stack):
    // `Position::Entering(root)` fails before any `Draining` frame
    // is ever pushed. Here `root` is resident but its one child
    // directory is withheld, so the cursor validates `root`, pushes
    // its frame onto `stack`, and only THEN stops on the missing
    // child — a stop below the root with a NON-EMPTY frame stack.
    // A stop changes no verdict state, so
    // resuming without making the object resident returns the same
    // `Need`. No other row exercises a repeated stop below the
    // root.
    let (root, store) = chain(2);
    let child = *store
        .keys()
        .find(|&&id| id != root)
        .unwrap_or_else(|| panic!("chain(2) must have a second object"));
    let resident: Store = std::iter::once((root, store[&root].clone())).collect();
    let mut cursor = TreeCursor::new(root);
    let first = cursor.resume(&|id| resident.get(id).cloned());
    let second = cursor.resume(&|id| resident.get(id).cloned());
    // ONE tuple: proves the stop actually lands below the root
    // (`first` names the child, not `root`) AND that repeating the
    // resume without fetching repeats it — so the second still
    // prints when the first fails, and `{outcome:?}` shows what was
    // actually returned rather than a bare pass/fail.
    assert_eq!(
        (first.clone(), second.clone()),
        (Ok(Step::Need(child)), Ok(Step::Need(child))),
        "first={first:?} second={second:?}: repeated resume below the root must repeat the same Need"
    );
}

#[test]
fn cursor_visits_are_linear_on_the_chain_where_the_pump_is_quadratic() {
    let n = 300u64;
    let (root, store) = chain(300);
    // The restart pump over the legacy walker.
    let visits = Cell::new(0u64);
    let resident: RefCell<Store> = RefCell::new(Store::new());
    loop {
        let outcome = legacy_validate_dir_tree(&root, &|id| {
            visits.set(visits.get() + 1);
            resident.borrow().get(id).cloned()
        });
        match outcome {
            Err(ValidateError::MissingObject { id }) => {
                let bytes = store.get(&id).unwrap_or_else(|| panic!("{id}")).clone();
                resident.borrow_mut().insert(id, bytes);
            }
            other => {
                other.unwrap_or_else(|e| panic!("{e}"));
                break;
            }
        }
    }
    assert_eq!(visits.get(), n * (n + 1) / 2 + n, "restart visits");
    // The cursor.
    let visits = Cell::new(0u64);
    let resident: RefCell<Store> = RefCell::new(Store::new());
    let mut cursor = TreeCursor::new(root);
    loop {
        let step = cursor
            .resume(&|id| {
                visits.set(visits.get() + 1);
                resident.borrow().get(id).cloned()
            })
            .unwrap_or_else(|e| panic!("{e}"));
        match step {
            Step::Need(id) => {
                let bytes = store.get(&id).unwrap_or_else(|| panic!("{id}")).clone();
                resident.borrow_mut().insert(id, bytes);
            }
            Step::Done(_) => break,
        }
    }
    // BOTH counts in ONE assertion: asserted in sequence, the first
    // red hides the second.
    assert_eq!(
        (visits.get(), cursor.dir_walks()),
        (2 * n, 2 * n),
        "cursor (visits, dir_walks): one miss + one hit per level"
    );
}

/// Drives a cursor from an EMPTY store, fetching exactly the object
/// each `Need` names and nothing else, and sums the bytes and call
/// count of every underlying fetch across the WHOLE drive. The work
/// oracle for retaining spill state: `spill_seen` and `leaf_facts`
/// surviving a stop is what lets a later resume skip re-walking (and
/// re-fetching) a spilled file's already-verified leaves.
fn drive_counting_bytes(root: GrainId, store: &Store) -> (u64, u64) {
    let total_bytes = Cell::new(0u64);
    let calls = Cell::new(0u64);
    let resident: RefCell<Store> = RefCell::new(Store::new());
    let mut cursor = TreeCursor::new(root);
    loop {
        let step = cursor
            .resume(&|id| {
                calls.set(calls.get().saturating_add(1));
                let found = resident.borrow().get(id).cloned();
                if let Some(bytes) = &found {
                    total_bytes.set(total_bytes.get().saturating_add(bytes.len() as u64));
                }
                found
            })
            .unwrap_or_else(|e| panic!("{e}"));
        match step {
            Step::Need(id) => {
                let bytes = store.get(&id).unwrap_or_else(|| panic!("{id}")).clone();
                resident.borrow_mut().insert(id, bytes);
            }
            Step::Done(_) => break,
        }
    }
    (total_bytes.get(), calls.get())
}

#[test]
fn cursor_spill_state_survives_a_stop_bytes_pinned() {
    // What survives a stop is exactly the
    // directory memo, `spill_seen`, `leaf_facts` and the nesting
    // worklist. The only other work pin
    // (`cursor_visits_are_linear_on_the_chain_where_the_pump_is_quadratic`)
    // drives `chain(300)`, a fixture with no spills at all — it pins
    // the directory memo and the worklist, not these two. A mutant
    // that clears `spill_seen`/`leaf_facts` at the top of every
    // `resume` still answers every VERDICT correctly (a cleared memo
    // just re-walks and re-inserts the same facts), so only a WORK
    // pin — bytes actually fetched, driving the cursor with
    // everything withheld and fetching one `Need` at a time — can
    // catch it.
    for (label, (root, store), want_bytes, want_calls) in [
        (
            "leaf_facts_at_two_depths",
            leaf_facts_at_two_depths(),
            4_850_120u64,
            8u64,
        ),
        (
            "honest_spill_2_leaves",
            honest_spill_2_leaves(),
            4_850_313u64,
            13u64,
        ),
    ] {
        let (bytes, calls) = drive_counting_bytes(root, &store);
        // ONE tuple: a byte-count regression without a call-count
        // regression (or vice versa) must still show both.
        assert_eq!(
            (bytes, calls),
            (want_bytes, want_calls),
            "{label}: (bytes, calls) fetching one Need at a time from empty"
        );
    }
}

/// The companion of `cursor_spill_state_survives_a_stop_bytes_pinned`
/// for the ONE component that row cannot see. On both of its fixtures
/// every byte a stop could cost is saved by `leaf_facts`, so a cursor
/// that discards `spill_seen` at every resume stays green there —
/// EXECUTED. Here the shared spill root is an INDEX —
/// never a `leaf_facts` key — and the second entry is met in the
/// resume AFTER the one that recorded the first: with `spill_seen`
/// surviving, `b` costs nothing; without it, `b` re-fetches the
/// 112-byte index (its leaf is still a `leaf_facts` hit), so the pin
/// moves by exactly one index fetch.
#[test]
fn cursor_spill_seen_survives_a_stop_on_an_index_root_bytes_pinned() {
    let (root, store) = spill_seen_index_root_across_a_stop();
    let (bytes, calls) = drive_counting_bytes(root, &store);
    // From empty, one `Need` per round. The 98-byte root leaf is
    // re-fetched on the three re-entries after the stops on the root
    // itself, on the index and on the leaf; the 112-byte index on the
    // two after the stops on the index and on the leaf; the
    // 2,424,883-byte leaf once; the 62-byte subdirectory leaf once —
    // eleven calls, four of them misses. The stop on the SUBDIRECTORY
    // costs no index fetch at all: the next resume enters `s`, and
    // `b` is answered from `spill_seen`. That non-fetch is what this
    // row pins. Under a `spill_seen` reset it becomes a THIRD index
    // fetch, for `b`: (2_425_575, 12).
    assert_eq!(
        (bytes, calls),
        (2_425_463u64, 11u64),
        "(bytes, calls) from empty, one Need per round; +112/+1 is `b` re-fetching the index"
    );
}

const T3_DRIVES: &[Drive] = &[Drive::Restart, Drive::Cursor, Drive::CursorHints];

/// Six-digit fifo names: `fifo_entries`' five-digit names stop
/// sorting past 99,999.
fn fifo_entries6(n: u32) -> Vec<DirEntry> {
    (0..n)
        .map(|i| DirEntry {
            name: name(&format!("n{i:06}")),
            kind: EntryKind::Fifo,
        })
        .collect()
}

/// ONE directory of `n` entries (about 787 nodes at 200,000).
fn wide_directory(n: u32) -> (GrainId, Store) {
    let mut store = Store::new();
    let root = dir_into(&mut store, &fifo_entries6(n));
    (root, store)
}

/// Drive the cursor over `store` from `initial`, fetching every Need
/// and (optionally) every hint under `max`; returns (verdict, rounds,
/// objects fetched, validation-closure visits, hint-closure visits).
fn drive_counted(
    root: GrainId,
    store: &Store,
    initial: &Store,
    hints_max: Option<usize>,
) -> (Result<TreeStats, ValidateError>, u64, u64, u64, u64, u64) {
    let resident: RefCell<Store> = RefCell::new(initial.clone());
    let visits = Cell::new(0u64);
    let hint_visits = Cell::new(0u64);
    let mut rounds = 0u64;
    let mut fetched = 0u64;
    let mut cursor = TreeCursor::new(root);
    let verdict = loop {
        rounds += 1;
        let step = cursor.resume(&|id| {
            visits.set(visits.get() + 1);
            resident.borrow().get(id).cloned()
        });
        match step {
            Err(e) => break Err(e),
            Ok(Step::Done(s)) => break Ok(s),
            Ok(Step::Need(id)) => {
                let Some(bytes) = store.get(&id) else {
                    break Err(ValidateError::MissingObject { id });
                };
                resident.borrow_mut().insert(id, bytes.clone());
                fetched += 1;
                if let Some(max) = hints_max {
                    let wanted = cursor.prefetch_hints(
                        &|id| {
                            hint_visits.set(hint_visits.get() + 1);
                            resident.borrow().get(id).cloned()
                        },
                        max,
                    );
                    let mut r = resident.borrow_mut();
                    for h in wanted.entering.into_iter().chain(wanted.queued_roots) {
                        if let Some(b) = store.get(&h)
                            && !r.contains_key(&h)
                        {
                            r.insert(h, b.clone());
                            fetched += 1;
                        }
                    }
                }
            }
        }
    };
    (
        verdict,
        rounds,
        fetched,
        visits.get(),
        hint_visits.get(),
        cursor.dir_walks(),
    )
}

// ---- the CursorHints differential, ONE ROW PER FIXTURE ------------
//
// One row per fixture, not one row sweeping them all: a single row
// sweeping sixteen fixtures measured 61.6 s, 51 % of the `ci`
// profile's 120 s `terminate-after`, and a sweep grows per fixture.
// One row per fixture keeps every sweep, lets nextest run them in
// parallel, and makes a slow fixture NAME itself.
// Each mirrors its `T2_DRIVES` sibling exactly — same one-shot verdict
// asserted as a premise, same sweep — differing only in `T3_DRIVES`,
// which adds the `CursorHints` arm.

#[test]
fn cursor_hints_differential_v_shape_12x5() {
    let (root, store) = v_shape_12x5();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "twelve directories of five inline files each, canonical throughout: {verdict:?}"
    );
    sweep("v_shape_12x5", false, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_chain_40() {
    let (root, store) = chain_40();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "forty nested one-child directories, canonical throughout: {verdict:?}"
    );
    sweep("chain_40", false, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_nested_6x4x3() {
    let (root, store) = nested_6x4x3();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "six by four directories over three inline files each, canonical throughout: {verdict:?}"
    );
    sweep("nested_6x4x3", false, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_two_faults_two_dirs() {
    let (root, store) = two_faults_two_dirs();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::CountMismatch)
    );
    sweep("two_faults_two_dirs", true, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_separator_fault() {
    let (root, store) = separator_fault();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::SeparatorMismatch)
    );
    sweep("separator_fault", true, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_shared_subtree_dag() {
    let (root, store) = shared_subtree_dag();
    let stats =
        validate_dir_tree(&root, &|id| store.get(id).cloned()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.dirs, 3, "counted once per path as today");
    sweep("shared_subtree_dag", true, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_spill_seen_across_a_resume() {
    let (root, store) = spill_seen_across_a_resume();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "two files naming ONE spill root with the same (size, count), so the \
         second is a `spill_seen` hit and both are canonical: {verdict:?}"
    );
    sweep("spill_seen_across_a_resume", true, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_lying_size_missing_spill_root() {
    let (root, store) = lying_size_missing_spill_root();
    assert!(matches!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::MissingObject { .. })
    ));
    sweep(
        "lying_size_missing_spill_root",
        true,
        root,
        &store,
        T3_DRIVES,
    );
}

#[test]
fn cursor_hints_differential_budget_refusal_on_a_hit() {
    let (root, store) = budget_refusal_on_a_hit();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::FillNotCanonical)
    );
    sweep("budget_refusal_on_a_hit", true, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_honest_spill_2_leaves() {
    let (root, store) = honest_spill_2_leaves();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "131,073 refs over two distinct honest leaves — the smallest \
         canonical multi-leaf spill: {verdict:?}"
    );
    sweep("honest_spill_2_leaves", true, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_spill_seen_index_root_across_a_stop() {
    let (root, store) = spill_seen_index_root_across_a_stop();
    // The verdict is IN the message: a bare `is_ok()` red says only
    // that it was not Ok, and which error it became is the finding.
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "two files in two directories naming one INDEX-rooted spill twice, canonical \
         throughout: {verdict:?}"
    );
    sweep(
        "spill_seen_index_root_across_a_stop",
        true,
        root,
        &store,
        T3_DRIVES,
    );
}

#[test]
fn cursor_hints_differential_wide_spill_64() {
    let (root, store) = wide_spill_64();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::CountMismatch),
        "a canonical 64-leaf spill is ~305 MB; this is the hostile shape walked in full"
    );
    sweep("wide_spill_64", false, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_leaf_facts_at_two_depths() {
    let (root, store) = leaf_facts_at_two_depths();
    let verdict = validate_dir_tree(&root, &|id| store.get(id).cloned());
    assert!(
        verdict.is_ok(),
        "both files are canonical, so a memo HIT must leave the same \
         `Shape` trace an unmemoized visit would: {verdict:?}"
    );
    sweep("leaf_facts_at_two_depths", true, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_leaf_budget_attack() {
    let (root, store) = leaf_budget_attack();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::FillNotCanonical)
    );
    sweep("leaf_budget_attack", false, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_depth_lopsided_impostor() {
    let (root, store) = depth_lopsided_impostor();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::FillNotCanonical)
    );
    sweep("depth_lopsided_impostor", false, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_chain_17_deep() {
    let (root, store) = chain_17_deep();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::DepthExceeded)
    );
    sweep("chain_17_deep", false, root, &store, T3_DRIVES);
}

#[test]
fn cursor_hints_differential_grain_list_17_deep() {
    let (root, store) = grain_list_17_deep();
    assert_eq!(
        validate_dir_tree(&root, &|id| store.get(id).cloned()),
        Err(ValidateError::DepthExceeded)
    );
    sweep("grain_list_17_deep", false, root, &store, T3_DRIVES);
}

#[test]
fn hints_batch_a_wide_directory_into_a_handful_of_rounds() {
    let (root, store) = wide_directory(200_000);
    let nodes = store.len() as u64;
    assert!((780..=800).contains(&nodes), "about 787 nodes: {nodes}");
    let empty = Store::new();
    let (plain, rounds, fetched, _, _, walks) = drive_counted(root, &store, &empty, None);
    assert!(plain.is_ok());
    assert_eq!(
        rounds,
        nodes + 1,
        "plain cursor: one Need per node, then Done"
    );
    assert_eq!(fetched, nodes);
    assert_eq!(walks, nodes + 1, "plain dir_walks == nodes + 1");
    let (hinted, rounds, fetched, _, _, walks) =
        drive_counted(root, &store, &empty, Some(PREFETCH_HINT_MAX));
    assert_eq!(hinted, plain);
    assert!(rounds <= 3, "hinted rounds: {rounds}");
    assert!(walks <= 5, "hinted dir_walks: {walks}");
    assert_eq!(fetched, nodes);
}

#[test]
fn a_binding_hint_cap_keeps_the_verdict() {
    // The 200,000-entry directory is used ONLY for the claim that
    // needs its size — the exact round count under a binding cap.
    // The caps that merely have to leave the verdict alone run on a
    // 20,000-entry directory instead: a drive at cap 0, 1 or 2 takes
    // ROUNDS PROPORTIONAL TO NODES (that is the point of a binding
    // cap), so four of them over 787 nodes cost 106 s — inside a
    // hair of the `ci` profile's 120 s `terminate-after`, which a
    // loaded machine then crosses. Measured.
    let (root, store) = wide_directory(20_000);
    let nodes = store.len() as u64;
    let empty = Store::new();
    let reference = validate_dir_tree(&root, &|id| store.get(id).cloned());
    let (plain, plain_rounds, ..) = drive_counted(root, &store, &empty, None);
    assert_eq!(plain, reference);
    for max in [0usize, 1, 2] {
        let (got, rounds, fetched, ..) = drive_counted(root, &store, &empty, Some(max));
        assert_eq!(got, reference, "max={max}");
        assert_eq!(
            fetched, nodes,
            "max={max}: everything is fetched exactly once"
        );
        if max == 0 {
            assert_eq!(rounds, plain_rounds, "cap 0 degenerates to the plain drive");
        }
    }

    // The binding cap, on the 200,000-entry directory, EXACT: round 1
    // reaches only the root's four interiors, so the cap binds from
    // round 2 on and the drive takes 15 rounds for 787 nodes.
    // Cheap, because 15 rounds is all it is.
    let (root, store) = wide_directory(200_000);
    let nodes = store.len() as u64;
    let reference = validate_dir_tree(&root, &|id| store.get(id).cloned());
    let (got, rounds, fetched, ..) = drive_counted(root, &store, &empty, Some(64));
    assert_eq!(got, reference, "max=64");
    assert_eq!(
        (rounds, fetched),
        (15, nodes),
        "max=64: {fetched} objects over {rounds} rounds"
    );
}

#[test]
fn hints_batch_a_wide_spill_into_a_handful_of_rounds() {
    let leaves = 3_000u64;
    let (root, store) = wide_spill(leaves);
    // The root directory leaf resident from the start, so a round is a
    // spill-tree object.
    let mut initial = Store::new();
    initial.insert(
        root,
        store.get(&root).unwrap_or_else(|| panic!("root")).clone(),
    );
    let (plain, rounds, _, _, _, walks) = drive_counted(root, &store, &initial, None);
    assert_eq!(
        plain,
        Err(ValidateError::CountMismatch),
        "the hostile declared count"
    );
    assert_eq!(
        rounds,
        leaves + 2,
        "plain: the index, every leaf, then the verdict"
    );
    assert_eq!(walks, leaves + 2, "plain dir_walks");
    let (hinted, rounds, _, _, _, walks) =
        drive_counted(root, &store, &initial, Some(PREFETCH_HINT_MAX));
    assert_eq!(hinted, plain);
    assert!(rounds <= 3, "hinted rounds: {rounds}");
    assert!(walks <= 5, "hinted dir_walks: {walks}");
}

/// The hint pass goes BLIND — permanently, for that directory — once
/// the RESIDENT structure-node prefix every pass re-examines reaches
/// [`HINT_WORK_MAX`], with a store that serves every hint and a
/// caller that admits every one. The prefix for `wide_spill` is TWO
/// nodes (the root directory's own leaf, then the spill index), so
/// the cliff sits at `HINT_WORK_MAX - 2` = 4,094 leaves and each
/// leaf past it costs exactly one more round and one more full
/// re-walk.
///
/// That OFFSET is also the evidence that the WORK budget is what
/// binds and not [`PREFETCH_HINT_MAX`], which is the same 4,096: on
/// the 4,096-leaf shape every leaf is absent and 4,096 ≤
/// `PREFETCH_HINT_MAX`, so a pass capped only on EMISSIONS would
/// still finish in two rounds. It takes four.
///
/// This is the DISTINCT-node special case, where every dispatched
/// child is a distinct resident leaf so dispatches and resident
/// nodes coincide. That coincidence is why this row alone cannot tell
/// a precondition stated in the WRONG quantity from the right one — see its
/// companion `hints_go_blind_with_three_resident_nodes_via_a_repeated_leaf`,
/// which reaches the same blindness with three resident nodes.
///
/// Pins, together with `hints_go_blind_with_three_resident_nodes_via_a_repeated_leaf`,
/// the precondition in [`TreeCursor`]'s `# Cost` section: the re-walk bound is
/// independent of node count ONLY while the dispatches the directory's hint pass makes
/// before reaching its first absent node stay below [`HINT_WORK_MAX`]. A successor that
/// builds the exact-frontier machine turns this row RED.
#[test]
fn hints_go_blind_when_the_resident_prefix_reaches_the_work_budget() {
    // The root directory's own leaf, then the spill index: the two
    // nodes every pass re-examines before it reaches a leaf.
    const PREFIX_NODES: u64 = 2;
    let budget = u64::try_from(HINT_WORK_MAX).unwrap_or_else(|e| panic!("{e}"));
    let cliff = budget - PREFIX_NODES;
    // The doc comments above state this
    // cliff as a concrete 4,094 leaves. Pin it, so that retuning
    // [`HINT_WORK_MAX`] cannot leave the prose behind: without this
    // the row is written in terms of the constant and moves with it,
    // which makes any new value an equivalent mutant.
    assert_eq!(cliff, 4_094, "the cliff the prose states");
    for leaves in [cliff - 1, cliff, cliff + 1, cliff + 2, cliff + 6] {
        let (root, store) = wide_spill(leaves);
        let mut initial = Store::new();
        initial.insert(
            root,
            store.get(&root).unwrap_or_else(|| panic!("root")).clone(),
        );
        if leaves == cliff {
            // The prose's `wide_spill` figures at the cliff: resident
            // objects and resident bytes. Its repeated-leaf figures are
            // pinned by
            // `a_legal_repeated_leaf_manifest_blinds_the_hint_pass` below.
            assert_eq!(store.len(), 4_096, "resident objects at the cliff");
            assert_eq!(
                store.values().map(Vec::len).sum::<usize>(),
                409_476,
                "resident bytes at the cliff — the prose says so"
            );
        }
        let (verdict, rounds, _, _, _, walks) =
            drive_counted(root, &store, &initial, Some(PREFETCH_HINT_MAX));
        assert_eq!(
            verdict,
            Err(ValidateError::CountMismatch),
            "the hostile declared count, leaves={leaves}"
        );
        assert_eq!(
            rounds,
            2 + leaves.saturating_sub(cliff),
            "one round per leaf past the cliff, leaves={leaves}"
        );
        assert_eq!(
            walks, rounds,
            "and every one of those rounds re-walks, leaves={leaves}"
        );
    }
}

/// The COMPANION row, and the one that keeps the prose above honest:
/// the pass goes blind with only **three resident nodes**. This row
/// drives the hint pass DIRECTLY, on a shape whose spill declaration
/// is not canonical — the walk would refuse it — so what it pins is
/// the CHARGE MODEL and the emission boundary, cheaply, at the two
/// shapes. That the same blindness is reachable on a manifest the
/// walk ACCEPTS is a separate claim, and it is pinned separately by
/// `a_legal_repeated_leaf_manifest_blinds_the_hint_pass` below —
/// which is where the attacker-cost figures in the prose come from.
/// Do not read this row as the security claim; read it as the
/// mechanism. The budget
/// bounds DISPATCHES, and `decode_grain_list_index` bounds an index's
/// child count and requires strictly increasing cumulatives but never
/// requires the children to be DISTINCT — so one legal index naming a
/// single resident leaf 4,094 times drains the whole budget while the
/// entire resident structure-node set is {dir leaf, index, leaf}.
///
/// `wide_spill` cannot see this: there every dispatched child is a
/// distinct resident leaf, so dispatches == resident nodes and the
/// two models coincide. On that shape a bound stated in the wrong
/// quantity passes just as the right one does, so this row separates
/// them. A successor that states or implements the bound in
/// resident-NODE terms goes RED here while the sister row still
/// passes.
///
/// EXECUTED sweep over 4,092..4,096 repeats (three objects, ~196 KiB
/// of manifest in every case):
///
/// | repeats | spent | hints | |
/// |---|---|---|---|
/// | 4,092 | 4,095 | 1 | sighted |
/// | 4,093 | 4,096 | 1 | sighted — the budget's LAST unit reached the absent child |
/// | 4,094 | 4,096 | 0 | BLIND |
/// | 4,095 | 4,096 | 0 | blind |
/// | 4,096 | 4,096 | 0 | blind |
///
/// **`spent == HINT_WORK_MAX` is therefore NOT the blindness
/// predicate** — 4,093 spends every unit and still sees. The predicate
/// is EMISSION, so this row asserts the emitted set on BOTH sides of
/// the boundary; a row that asserted only the spend would pass at
/// 4,093 and prove nothing about blindness.
///
/// The sweep above is the RECORD of what was measured; the row asserts
/// the two shapes that straddle the boundary, which is what discriminates.
#[test]
fn hints_go_blind_with_three_resident_nodes_via_a_repeated_leaf() {
    let k = u64::from(GRAINLIST_LEAF_MAX_REFS);
    // Literals on purpose. Deriving these from `HINT_WORK_MAX` would
    // move fixtures and expectations together and make any retune an
    // equivalent mutant — the trap the sister row above had to close.
    for (repeats, want_hints) in [(4_093_u64, 1_usize), (4_094, 0)] {
        let leaf_bytes = node::encode_grain_list_leaf(&[gref("blind3-leaf", 1)])
            .unwrap_or_else(|e| panic!("{e}"));
        let leaf_id = GrainId::of(&leaf_bytes);
        // Placed AFTER the repeats, so it is reached — and emitted —
        // only while the pass can still spend on it.
        let absent = gid("blind3-absent-leaf");
        let mut children: Vec<GrainListIndexChild> = (1..=repeats)
            .map(|i| GrainListIndexChild {
                child: leaf_id,
                cum_unpacked_len: i * k,
                cum_ref_count: i * k,
            })
            .collect();
        children.push(GrainListIndexChild {
            child: absent,
            cum_unpacked_len: (repeats + 1) * k,
            cum_ref_count: (repeats + 1) * k,
        });
        let index_bytes =
            node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
        let index_id = GrainId::of(&index_bytes);
        let mut store = Store::new();
        store.insert(leaf_id, leaf_bytes);
        store.insert(index_id, index_bytes);
        let root = dir_into(
            &mut store,
            &[spill_entry(
                "f",
                k + 1,
                u32::try_from(k + 1).unwrap_or_else(|e| panic!("{e}")),
                index_id,
            )],
        );
        // The load-bearing contrast with the sister row.
        assert_eq!(
            store.len(),
            3,
            "dir leaf, index, leaf — three resident nodes, repeats={repeats}"
        );
        let (spent, hints) = hint_pass_from_entering(root, &store);
        assert_eq!(
            spent, HINT_WORK_MAX,
            "the budget is spent, repeats={repeats}"
        );
        assert_eq!(
            hints.entering.len(),
            want_hints,
            "emission is the predicate, not the spend, repeats={repeats}"
        );
    }
}

#[test]
fn the_chain_stays_linear_and_batching_buys_nothing_there() {
    let n = 300u64;
    let (root, store) = chain(300);
    let empty = Store::new();
    let (got, rounds, fetched, visits, hint_visits, walks) =
        drive_counted(root, &store, &empty, Some(PREFETCH_HINT_MAX));
    assert!(got.is_ok());
    assert_eq!(rounds, n + 1, "one Need per level, then Done");
    assert_eq!(fetched, n);
    assert_eq!(
        visits,
        2 * n,
        "validation closure: one miss + one hit per level"
    );
    assert_eq!(
        hint_visits, n,
        "one probe of the entered directory per round"
    );
    assert_eq!(visits + hint_visits, 3 * n, "three visits per level in all");
    assert_eq!(walks, 2 * n);
}

/// A one-child chain `depth` deep whose ROOT leaf also names `zz`, a
/// resident-but-unvalidated directory queued in the root frame.
fn chain_with_queued_root(depth: usize) -> (GrainId, Store, GrainId) {
    let mut store = Store::new();
    let (inner, inner_store) = chain(depth - 1);
    store.extend(inner_store);
    let zz = dir_into(&mut store, &[inline_file("zf", "zz-file", 9)]);
    let root = dir_into(
        &mut store,
        &[dir_entry("a-chain", inner), dir_entry("zz", zz)],
    );
    (root, store, zz)
}

/// Feed exactly `needs` Needs from `store`, then return the cursor
/// positioned on the next Need (the directory at that depth absent).
fn descend_needs_only(root: GrainId, store: &Store, needs: usize) -> (TreeCursor, Store) {
    let mut resident = Store::new();
    let mut cursor = TreeCursor::new(root);
    for _ in 0..needs {
        let step = cursor
            .resume(&|id| resident.get(id).cloned())
            .unwrap_or_else(|e| panic!("{e}"));
        let Step::Need(id) = step else {
            panic!("finished early: {step:?}");
        };
        resident.insert(id, store.get(&id).unwrap_or_else(|| panic!("{id}")).clone());
    }
    let step = cursor
        .resume(&|id| resident.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(step, Step::Need(_)));
    (cursor, resident)
}

#[test]
fn the_work_budget_charges_frames_on_a_deep_chain() {
    let (root, store, zz) = chain_with_queued_root(5_000);
    // At depth 4,500 the innermost 4,096 frames spend the budget
    // before the root frame is reached.
    let (cursor, resident) = descend_needs_only(root, &store, 4_500);
    let (hints, spent) =
        cursor.prefetch_hints_counted(&|id| resident.get(id).cloned(), PREFETCH_HINT_MAX);
    // The spend AND the consequence in ONE assertion: asserted in
    // sequence, the spend's red hides the `zz` claim
    // entirely.
    let reached_zz = hints.queued_roots.contains(&zz) || hints.entering.contains(&zz);
    assert_eq!(
        (spent, reached_zz),
        (HINT_WORK_MAX, false),
        "the budget must be spent on FRAMES before the root frame is \
         reached, so zz is never emitted at depth 4,500"
    );
    // Positive control: at depth 100 the root frame is reached and zz emitted.
    let (cursor, resident) = descend_needs_only(root, &store, 100);
    let (hints, spent) =
        cursor.prefetch_hints_counted(&|id| resident.get(id).cloned(), PREFETCH_HINT_MAX);
    assert!(spent < HINT_WORK_MAX, "spent {spent}");
    assert_eq!(hints.queued_roots, vec![zz], "zz is the one queued root");
    assert_eq!(
        hints.entering.len(),
        1,
        "the missing directory being entered"
    );
}

// ---- the two remaining work oracles ------------------------------

/// A directory whose entries are: one subdirectory `x` (walked and
/// MEMOIZED first — names sort, and the walk enters children in name
/// order), one one-child chain, and `repeats` further entries ALL
/// naming `x`'s id. Once the cursor is inside the chain, the root
/// frame's `todo` still holds `repeats` slots, every one of them a
/// memo hit that emits nothing — which is exactly the shape a
/// pass that charged only what it EMITS would scan for free.
fn repeated_child_with_a_chain(repeats: u32, chain_depth: usize) -> (GrainId, Store, GrainId) {
    let mut store = Store::new();
    let x = dir_into(&mut store, &[inline_file("xf", "rc-x-file", 3)]);
    let (chain_root, chain_store) = chain(chain_depth);
    store.extend(chain_store);
    let mut entries = vec![dir_entry("a00000", x), dir_entry("b00000", chain_root)];
    for i in 0..repeats {
        entries.push(dir_entry(&format!("c{i:05}"), x));
    }
    let root = dir_into(&mut store, &entries);
    (root, store, chain_root)
}

/// Feed `Need`s from `store` until the cursor stops ON `target`
/// (`Entering(target)`), then report the pass's work and the frames
/// and slots it had to consider.
fn spend_at(root: GrainId, store: &Store, target: GrainId) -> (usize, usize, usize) {
    let mut resident = Store::new();
    let mut cursor = TreeCursor::new(root);
    loop {
        let step = cursor
            .resume(&|id| resident.get(id).cloned())
            .unwrap_or_else(|e| panic!("{e}"));
        let Step::Need(id) = step else {
            panic!("finished before reaching the target: {step:?}");
        };
        if id == target {
            let frames = cursor.stack.len();
            let slots: usize = cursor.stack.iter().map(|f| f.todo.len()).sum();
            let (_, spent) =
                cursor.prefetch_hints_counted(&|i| resident.get(i).cloned(), PREFETCH_HINT_MAX);
            return (spent, frames, slots);
        }
        resident.insert(id, store.get(&id).unwrap_or_else(|| panic!("{id}")).clone());
    }
}

/// THE SLOT CHARGE. Every `todo` SLOT the pass considers costs one
/// unit, charged BEFORE the memo/seen check — so a directory that
/// names one already-validated child thousands of times cannot make
/// the pass iterate for free.
///
/// The arithmetic, stated. A pass at `Entering(d)` spends one unit
/// for the entering directory's own probe (one node unit, then
/// `fetch(d)` answers `None` and it returns), plus, over every
/// stacked frame, one unit for the FRAME and one per `todo` SLOT —
/// the whole capped at `HINT_WORK_MAX`. With the cursor one level
/// into the chain the stack is just the root frame, so the spend is
/// `1 + 1 + slots`.
#[test]
fn the_work_budget_charges_slots_on_a_repeated_child() {
    // Small shape: the arithmetic pinned EXACTLY, uncapped.
    let (root, store, chain_root) = repeated_child_with_a_chain(100, 3);
    let (spent, frames, slots) = spend_at(root, &store, chain_root);
    assert_eq!(
        (frames, slots),
        (1, 100),
        "the root frame, 100 repeats left"
    );
    assert_eq!(spent, 1 + frames + slots, "probe + frames + slots");
    assert_eq!(spent, 102);
    // 5,000 repeats spend the whole budget.
    let (root, store, chain_root) = repeated_child_with_a_chain(5_000, 3);
    let (spent, frames, slots) = spend_at(root, &store, chain_root);
    assert_eq!((frames, slots), (1, 5_000));
    assert_eq!(
        spent,
        HINT_WORK_MAX.min(1 + frames + slots),
        "capped: 1 + 1 + 5000 > HINT_WORK_MAX"
    );
    assert_eq!(spent, HINT_WORK_MAX);
}

/// A directory B-tree 16 levels deep whose deepest leaf carries a
/// file whose SPILL tree is another 16 levels deep — the worst case
/// the design's "rounds per directory ≤ 2 × `DEPTH_MAX` + 1" bound
/// describes, hand-built because no canonical bulk-load reaches
/// those heights. Each round makes one more level resident, so the
/// un-hinted cursor takes exactly 33 `validate_one_dir` runs for the
/// ONE directory this tree is; every legal shape takes 3.
fn deep_dir_with_deep_spill() -> (GrainId, Store) {
    let mut store = Store::new();
    let leaf = node::encode_grain_list_leaf(&[gref("deep-g", 1)]).unwrap_or_else(|e| panic!("{e}"));
    let mut gl = GrainId::of(&leaf);
    store.insert(gl, leaf);
    for i in 0..DEPTH_MAX {
        let bytes = node::encode_grain_list_index(&[
            GrainListIndexChild {
                child: gl,
                cum_unpacked_len: 1,
                cum_ref_count: 1,
            },
            GrainListIndexChild {
                child: gid(&format!("gl-sib-{i}")),
                cum_unpacked_len: 2,
                cum_ref_count: 2,
            },
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        gl = GrainId::of(&bytes);
        store.insert(gl, bytes);
    }
    let dir_leaf = node::encode_dir_leaf(&[spill_entry("aaa", 1, FILE_INLINE_MAX_REFS + 1, gl)])
        .unwrap_or_else(|e| panic!("{e}"));
    let mut child = GrainId::of(&dir_leaf);
    store.insert(child, dir_leaf);
    for i in 0..(DEPTH_MAX - 1) {
        let bytes = node::encode_dir_interior(&[
            InteriorChild {
                first_key: name("aaa"),
                child,
                subtree_entry_count: 1,
            },
            InteriorChild {
                first_key: name(&format!("b{i:03}")),
                child: gid(&format!("dir-sib-{i}")),
                subtree_entry_count: 1,
            },
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        child = GrainId::of(&bytes);
        store.insert(child, bytes);
    }
    (child, store)
}

#[test]
fn rounds_per_directory_are_bounded_by_the_tree_height() {
    let (root, store) = deep_dir_with_deep_spill();
    assert_eq!(
        store.len(),
        33,
        "16 dir levels + 16 spill levels + one leaf"
    );
    let empty = Store::new();
    let (_, _, _, _, _, walks) = drive_counted(root, &store, &empty, None);
    assert_eq!(walks, 33, "exactly 2 * DEPTH_MAX + 1 — the bound is TIGHT");
    // …and every legal shape is far under it. `v_shape_12x5` is 13
    // directories; hinted, the whole drive spends 3 per directory at
    // the very most.
    let (root, store) = v_shape_12x5();
    let (verdict, _, _, _, _, walks) = drive_counted(root, &store, &empty, Some(PREFETCH_HINT_MAX));
    assert!(verdict.is_ok());
    assert!(
        walks <= 3 * 13,
        "legal shape: {walks} walks over 13 directories"
    );
}

/// Does a resident `DirLeaf` cost the
/// hint pass one unit per ENTRY? It does not — and it does not need
/// to. The entry loop in `missing_in_dir_tree`'s `DirLeaf` arm
/// carries no `work.charge()` of its own, and `node::decode_dir_leaf`
/// refuses a `count` over `DIR_LEAF_MAX_ENTRIES` (256) BEFORE it
/// allocates, so ONE charged node buys at most 256 iterations of a
/// loop whose body is empty unless the entry is a SPILL — and a
/// spill recurses into `missing_in_grain_list`, which charges one
/// unit per NODE on entry, before any check. The per-entry work is
/// therefore bounded by `DIR_LEAF_MAX_ENTRIES` and every byte the
/// pass FETCHES is metered.
#[test]
fn a_resident_dir_leaf_charges_per_node_not_per_entry() {
    // (a) A maximal leaf of INLINE files: one node, one unit.
    let mut store = Store::new();
    let entries: Vec<DirEntry> = (0..DIR_LEAF_MAX_ENTRIES)
        .map(|i| inline_file(&format!("f{i:03}"), &format!("pe-inline-{i}"), 1))
        .collect();
    let root = dir_into(&mut store, &entries);
    assert_eq!(store.len(), 1, "256 entries is exactly ONE dir leaf");
    let (spent, fetches, hints) = probe_one_pass(root, &store);
    assert_eq!(
        (spent, fetches),
        (1, 1),
        "one charged node, one fetch, 256 entries iterated for free"
    );
    assert!(hints.entering.is_empty() && hints.queued_roots.is_empty());

    // (b) The same leaf, every entry a SPILL to its own resident
    // grain-list leaf: one unit for the directory node plus one per
    // spill root the pass walks into.
    let mut store = Store::new();
    let entries: Vec<DirEntry> = (0..DIR_LEAF_MAX_ENTRIES)
        .map(|i| {
            let leaf = node::encode_grain_list_leaf(&[gref(&format!("pe-spill-{i}"), 1)])
                .unwrap_or_else(|e| panic!("{e}"));
            let id = GrainId::of(&leaf);
            store.insert(id, leaf);
            spill_entry(&format!("f{i:03}"), 1, FILE_INLINE_MAX_REFS + 1, id)
        })
        .collect();
    let root = dir_into(&mut store, &entries);
    assert_eq!(store.len(), 1 + DIR_LEAF_MAX_ENTRIES as usize);
    let (spent, fetches, hints) = probe_one_pass(root, &store);
    assert_eq!(
        (spent, fetches),
        (
            1 + DIR_LEAF_MAX_ENTRIES as usize,
            1 + u64::from(DIR_LEAF_MAX_ENTRIES)
        ),
        "one unit and one fetch for the leaf, and one of each per spill root"
    );
    assert!(hints.entering.is_empty(), "every spill root is resident");
}

/// Stop the cursor at `Entering(root)` (its first `Need`), then run
/// ONE hint pass over a closure that DOES serve `root` — the round
/// loop's own shape, since it fetches the need before asking for
/// hints. Returns (units spent, `fetch` calls, the hints).
fn probe_one_pass(root: GrainId, store: &Store) -> (usize, u64, Hints) {
    let empty = Store::new();
    let mut cursor = TreeCursor::new(root);
    let step = cursor
        .resume(&|id| empty.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(step, Step::Need(root));
    let fetches = Cell::new(0u64);
    let (hints, spent) = cursor.prefetch_hints_counted(
        &|id| {
            fetches.set(fetches.get() + 1);
            store.get(id).cloned()
        },
        PREFETCH_HINT_MAX,
    );
    (spent, fetches.get(), hints)
}

// ---- node charge under a repeated child ---------------------------

/// One `DirInterior` naming `child` `DIR_INTERIOR_MAX_CHILDREN`
/// times — the format fact `decode_dir_interior` leaves open:
/// `first_key`s must be strictly sorted, children need not be
/// distinct.
fn interior_of_one_child(child: GrainId) -> Vec<u8> {
    let children: Vec<InteriorChild> = (0..DIR_INTERIOR_MAX_CHILDREN)
        .map(|i| InteriorChild {
            first_key: name(&format!("k{i:05}")),
            child,
            subtree_entry_count: 1,
        })
        .collect();
    node::encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"))
}

/// `depth` `DirInterior` levels, each naming the next
/// `DIR_INTERIOR_MAX_CHILDREN` times, the deepest level's repeated
/// child ABSENT from the store — closes the `missing_in_dir_tree`
/// charge-order gap: a node named more than once by its OWN parent,
/// which no shipped row before this one built.
fn dir_diamond(depth: u32) -> (GrainId, Store) {
    let mut store = Store::new();
    let mut child = gid("dir-diamond-absent-leaf");
    for _ in 0..depth {
        let bytes = interior_of_one_child(child);
        child = GrainId::of(&bytes);
        store.insert(child, bytes);
    }
    (child, store)
}

/// One `GrainListIndex` naming `child` `width` times — the same
/// format fact as `interior_of_one_child`, for
/// `decode_grain_list_index`: only the cumulative fields must
/// strictly increase, never the children.
fn grain_list_index_of_one_child(child: GrainId, width: u64) -> Vec<u8> {
    let children: Vec<GrainListIndexChild> = (1..=width)
        .map(|k| GrainListIndexChild {
            child,
            cum_unpacked_len: k,
            cum_ref_count: k,
        })
        .collect();
    node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"))
}

/// `depth` `GrainListIndex` levels, each naming the next `width`
/// times, the deepest level's repeated child ABSENT — the same gap
/// as `dir_diamond`, at the `missing_in_grain_list` site, wrapped
/// under one spill entry whose declared `grain_count` is chosen so
/// the leaf budget it buys is exactly `width` — an EXACT
/// multiple of `GRAINLIST_LEAF_MAX_REFS`, so `div_ceil` lands on
/// `width` precisely and the per-node fan-out cap never truncates
/// any of the `depth` levels.
fn grain_list_diamond(depth: u32, width: u64) -> (GrainId, Store) {
    let mut gl_store = Store::new();
    let mut child = gid("grain-list-diamond-absent-leaf");
    for _ in 0..depth {
        let bytes = grain_list_index_of_one_child(child, width);
        child = GrainId::of(&bytes);
        gl_store.insert(child, bytes);
    }
    let mut store = Store::new();
    store.extend(gl_store);
    let leaf_cap = u64::from(GRAINLIST_LEAF_MAX_REFS);
    let declared = width * leaf_cap;
    let count = u32::try_from(declared).unwrap_or_else(|e| panic!("{e}"));
    let root = dir_into(&mut store, &[spill_entry("f", declared, count, child)]);
    (root, store)
}

/// The SECURITY claim, executed: a manifest the walk ACCEPTS, served
/// by a store that withholds one object, blinds the hint pass with
/// THREE resident nodes.
///
/// A `GrainListIndex` may name the same child repeatedly —
/// `decode_grain_list_index` bounds the child count and requires
/// strictly increasing cumulatives, and requires nothing about
/// distinctness — so an index of 4,094 copies of ONE maximum-width
/// leaf plus one further leaf is canonical when every cumulative is
/// truthful. Executed here: `validate_dir_tree` over the full store
/// returns `Ok` with 536,739,840 grains, from four objects and
/// 9,900,087 published bytes.
///
/// Withhold only the last leaf — a COOPERATING store that has served
/// everything else — and the entering directory's pass dispatches
/// 1 (dir leaf) + 1 (index) + 4,094 (the repeats) = 4,096 units and
/// exhausts before it ever reaches the one absent child. It returns
/// EMPTY, from 3 resident objects and 5,050,409 resident bytes.
///
/// The contrast with `wide_spill` is what the prose states, and it
/// runs in only ONE direction: resident nodes collapse from 4,096 to
/// 3, while the byte cost goes the other way, 409,476 -> 5,050,409.
/// These figures are measured. The ~196 KiB of manifest in
/// `hints_go_blind_with_three_resident_nodes_via_a_repeated_leaf` is not
/// this manifest's figure: that row's shape is one the walk refuses.
#[test]
fn a_legal_repeated_leaf_manifest_blinds_the_hint_pass() {
    const REPEATS: u64 = 4_094;
    let k = GRAINLIST_LEAF_MAX_REFS;
    let build = |tag: &str| {
        let refs: Vec<GrainRef> = (0..k).map(|i| gref(&format!("{tag}-{i}"), 1)).collect();
        let bytes = node::encode_grain_list_leaf(&refs).unwrap_or_else(|e| panic!("{e}"));
        (GrainId::of(&bytes), bytes)
    };
    let (repeated, repeated_bytes) = build("lrl-a");
    let (withheld, withheld_bytes) = build("lrl-b");
    let kk = u64::from(k);
    let mut children: Vec<GrainListIndexChild> = (1..=REPEATS)
        .map(|i| GrainListIndexChild {
            child: repeated,
            cum_unpacked_len: i * kk,
            cum_ref_count: i * kk,
        })
        .collect();
    children.push(GrainListIndexChild {
        child: withheld,
        cum_unpacked_len: (REPEATS + 1) * kk,
        cum_ref_count: (REPEATS + 1) * kk,
    });
    let index = node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
    let index_id = GrainId::of(&index);
    let total = (REPEATS + 1) * kk;
    let count = u32::try_from(total).unwrap_or_else(|e| panic!("{e}"));

    let mut full = Store::new();
    full.insert(repeated, repeated_bytes.clone());
    full.insert(withheld, withheld_bytes);
    full.insert(index_id, index.clone());
    let root = dir_into(&mut full, &[spill_entry("f", total, count, index_id)]);

    // LEGAL: the walk accepts it. Without this the row below would
    // only describe a shape nobody can publish.
    let stats = validate_dir_tree(&root, &|id| full.get(id).cloned())
        .unwrap_or_else(|e| panic!("the repeated-leaf manifest must be ACCEPTED: {e}"));
    assert_eq!(stats.grains, 536_739_840, "the accepted grain count");
    assert_eq!(full.len(), 4, "leaf a, leaf b, the index, the dir leaf");
    assert_eq!(
        full.values().map(Vec::len).sum::<usize>(),
        9_900_087,
        "published bytes"
    );

    // The cooperating store has served everything but leaf B.
    let mut resident = Store::new();
    resident.insert(repeated, repeated_bytes);
    resident.insert(index_id, index);
    resident.insert(
        root,
        full.get(&root).unwrap_or_else(|| panic!("root")).clone(),
    );
    assert_eq!(resident.len(), 3, "THREE resident nodes");
    assert_eq!(
        resident.values().map(Vec::len).sum::<usize>(),
        5_050_409,
        "resident bytes"
    );
    let (spent, hints) = hint_pass_from_entering(root, &resident);
    assert_eq!(spent, HINT_WORK_MAX, "the whole budget, on the repeats");
    assert!(
        hints.entering.is_empty() && hints.queued_roots.is_empty(),
        "BLIND: the absent child is never reached"
    );
}

/// The hint pass from a fresh cursor's own initial `Entering(root)`
/// — no `resume()` first: `TreeCursor::new` already starts there,
/// and `dir_diamond`/`grain_list_diamond` are not meant to pass real
/// validation (their only job is driving the hint pass's own
/// node-charge sites).
fn hint_pass_from_entering(root: GrainId, store: &Store) -> (usize, Hints) {
    let cursor = TreeCursor::new(root);
    let (hints, spent) =
        cursor.prefetch_hints_counted(&|id| store.get(id).cloned(), PREFETCH_HINT_MAX);
    (spent, hints)
}

/// THE NODE CHARGE at both sites, under a REPEATED child — the gap
/// no shipped row before this one closed. `decode_dir_interior` and
/// `decode_grain_list_index` each enforce an ORDER constraint
/// (sorted `first_key`s / increasing cumulative fields) but never
/// DISTINCTNESS, so a node may legally name the same child up to
/// `DIR_INTERIOR_MAX_CHILDREN` (256) or `GRAINLIST_INDEX_MAX_CHILDREN`
/// (131,072) times. Both charge sites (`missing_in_dir_tree`,
/// `missing_in_grain_list`) charge BEFORE the `seen.insert` check —
/// so a REPEATED dispatch still costs a unit before being turned
/// away. A mutant that moves either charge past `seen.insert`
/// charges once per DISTINCT id REACHED instead of once per
/// DISPATCH — invisible on every existing row, since none of them
/// ever names the same child twice from the same parent, and it
/// would still pass all of them.
///
/// Each row asserts its spend alongside what got EMITTED (the one
/// absent leaf, reported once) as a SINGLE tuple, so a divergence in
/// either half still prints both: spend is what a charge-order
/// mutant breaks, emission is what the exhaustion peek added
/// alongside it must NOT break.
#[test]
fn the_node_charge_survives_a_repeated_child() {
    // (a) `missing_in_dir_tree`'s site.
    let (root, store) = dir_diamond(3);
    assert_eq!(
        store.len(),
        3,
        "three interiors, the absent leaf never stored"
    );
    let (spent, hints) = hint_pass_from_entering(root, &store);
    assert_eq!(
        (spent, hints.entering.len()),
        (769, 1),
        "1 + 3 * DIR_INTERIOR_MAX_CHILDREN ({DIR_INTERIOR_MAX_CHILDREN}); \
         the absent leaf reported once"
    );

    // (b) `missing_in_grain_list`'s site, under a spill entry whose
    // declared leaf budget exactly covers the width (the
    // emission budget), so nothing truncates a level.
    let (root, store) = grain_list_diamond(3, 1_000);
    assert_eq!(store.len(), 4, "three indexes plus the dir leaf");
    let (spent, hints) = hint_pass_from_entering(root, &store);
    assert_eq!(
        (spent, hints.entering.len()),
        (3_002, 1),
        "1 (dir leaf) + 1 (spill root) + 3 * 1000; the absent leaf reported once"
    );
}

// ---- an EMISSION budget, not a per-node cap ----------------------

/// One `GrainListIndex` naming `width` DISTINCT absent children,
/// each cumulative field strictly increasing (the only order
/// `decode_grain_list_index` demands) — a wide, single-level spill
/// index with more real children than any `leaf_budget` in these
/// rows ever buys.
fn index_of_distinct_absent(width: u64, seed: &str) -> (GrainId, Store) {
    let mut store = Store::new();
    let children: Vec<GrainListIndexChild> = (1..=width)
        .map(|k| GrainListIndexChild {
            child: gid(&format!("{seed}-{k}")),
            cum_unpacked_len: k,
            cum_ref_count: k,
        })
        .collect();
    let bytes = node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"));
    let id = GrainId::of(&bytes);
    store.insert(id, bytes);
    (id, store)
}

/// One `GrainListIndex` naming exactly two DISTINCT children —
/// `grain_list_diamond`'s helper repeats ONE child; this pairs two,
/// which is what lets `binary_index_tree` build a tree of genuinely
/// distinct nodes rather than one node revisited under memoization.
fn index_of_two_children(a: GrainId, b: GrainId) -> Vec<u8> {
    let children = vec![
        GrainListIndexChild {
            child: a,
            cum_unpacked_len: 1,
            cum_ref_count: 1,
        },
        GrainListIndexChild {
            child: b,
            cum_unpacked_len: 2,
            cum_ref_count: 2,
        },
    ];
    node::encode_grain_list_index(&children).unwrap_or_else(|e| panic!("{e}"))
}

/// A complete binary tree of `depth` levels of DISTINCT resident
/// `GrainListIndex` nodes, each naming exactly two children. Every
/// node's own fan-out is 2, so a cap reset at each level
/// (`i as u64 >= leaf_budget` with `leaf_budget >= 2`)
/// NEVER fires anywhere in the
/// tree, yet the frontier at depth `depth` holds `2^depth` distinct
/// absent leaves — unboundedly more than `leaf_budget` as `depth`
/// grows, with every intermediate node individually compliant.
fn binary_index_tree(depth: u32) -> (GrainId, Store) {
    let mut store = Store::new();
    let mut level: Vec<GrainId> = (0..(1u64 << depth))
        .map(|i| gid(&format!("row2-leaf-{i:04}")))
        .collect();
    for _ in 0..depth {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut it = level.into_iter();
        while let (Some(a), Some(b)) = (it.next(), it.next()) {
            let bytes = index_of_two_children(a, b);
            let id = GrainId::of(&bytes);
            store.insert(id, bytes);
            next.push(id);
        }
        level = next;
    }
    let root = level
        .pop()
        .unwrap_or_else(|| panic!("binary_index_tree: empty root level"));
    (root, store)
}

/// Wraps a resident grain-list root under one dir-leaf spill entry
/// whose declared `grain_count` buys EXACTLY `leaf_budget` — the
/// same closed form the `DirLeaf` call site computes, inverted.
fn spill_root_with_budget(
    mut store: Store,
    index_root: GrainId,
    leaf_budget: u64,
) -> (GrainId, Store) {
    let leaf_cap = u64::from(GRAINLIST_LEAF_MAX_REFS);
    let declared = (leaf_budget - 1) * leaf_cap + 1;
    let count = u32::try_from(declared).unwrap_or_else(|e| panic!("{e}"));
    let root = dir_into(&mut store, &[spill_entry("f", declared, count, index_root)]);
    (root, store)
}

/// The flat-wide case: 5,000 distinct absent children under one
/// resident index, a `leaf_budget` of 5 — proving the cap is on
/// total EMISSIONS, not on anything about the node's own width.
#[test]
fn emission_budget_caps_a_flat_wide_index() {
    let (index_root, store) = index_of_distinct_absent(5_000, "row1-absent");
    assert_eq!(store.len(), 1, "one resident index, nothing else");
    let (root, store) = spill_root_with_budget(store, index_root, 5);
    assert_eq!(store.len(), 2, "the index plus the dir leaf naming it");
    let (spent, hints) = hint_pass_from_entering(root, &store);
    assert_eq!(
        (spent, hints.entering.len()),
        (7, 5),
        "1 (dir leaf) + 1 (index node) + 5 (budgeted children); \
         5,000 available, leaf_budget 5: got spent={spent} emitted={}",
        hints.entering.len()
    );
}

/// THE DELIVERABLE. Binary tree of resident indexes, `leaf_budget`
/// 2 — every node names exactly 2 children, so a per-node cap
/// (`i as u64 >= leaf_budget`, `leaf_budget` = 2) never fires at ANY
/// of the 3 levels (`i` only ever reaches 0 and 1) and would let
/// all 8 distinct absent leaves through. The shared emission
/// budget must cap emission at 2 regardless: this row goes RED the
/// moment the budget stops being spent (see the mutation proof).
#[test]
fn emission_budget_survives_a_branching_defeat_of_the_old_per_node_cap() {
    let (index_root, store) = binary_index_tree(3);
    assert_eq!(
        store.len(),
        7,
        "a complete binary tree of 3 levels: 4 + 2 + 1 resident indexes"
    );
    let (root, store) = spill_root_with_budget(store, index_root, 2);
    assert_eq!(
        store.len(),
        8,
        "the 7 indexes plus the dir leaf naming the root"
    );
    let (spent, hints) = hint_pass_from_entering(root, &store);
    assert_eq!(
        (spent, hints.entering.len()),
        (6, 2),
        "8 distinct absent leaves reachable, but leaf_budget is 2 and \
         every node's own fan-out (2) fits a per-node cap of 2: \
         got spent={spent} emitted={}",
        hints.entering.len()
    );
}

/// A valid canonical spill: one index over EXACTLY `leaf_budget`
/// leaves. Proves the emission budget does not truncate a legitimate
/// frontier — every one of the 3 available children is reported,
/// none dropped by an off-by-one in the budget arithmetic.
#[test]
fn emission_budget_does_not_truncate_a_canonical_frontier() {
    let (index_root, store) = index_of_distinct_absent(3, "row3-absent");
    let (root, store) = spill_root_with_budget(store, index_root, 3);
    let (spent, hints) = hint_pass_from_entering(root, &store);
    assert_eq!(
        (spent, hints.entering.len()),
        (5, 3),
        "one index over exactly leaf_budget (3) leaves, all real: \
         got spent={spent} emitted={}",
        hints.entering.len()
    );
}

/// `work.charge()` is the FIRST operand of both walkers' entry
/// guards, and that ORDER is what makes
/// [`HintWork::dispatches_left`] an exact bound: a dispatch made
/// while `out` is already full must still cost a unit, or a
/// projection truncated at `left` would drop children the pass could
/// still have reached.
///
/// Swapping the two operands passed all 93 `manifest::tree` rows
/// without a test that distinguishes charging a dispatch from
/// emitting its result. The
/// shape that sees it needs `out` to FILL while dispatches remain:
/// 50 distinct absent children under a `max` of 3. Correct, every
/// one of the 50 is charged even though only 3 emit; swapped, the 47
/// that find `out` full return without charging.
#[test]
fn a_dispatch_is_charged_even_once_the_emission_cap_is_full() {
    let (index_root, store) = index_of_distinct_absent(50, "charge-first");
    let (root, store) = spill_root_with_budget(store, index_root, 5);
    let cursor = TreeCursor::new(root);
    let (hints, spent) = cursor.prefetch_hints_counted(&|id| store.get(id).cloned(), 3);
    assert_eq!(
        (spent, hints.entering.len()),
        (52, 3),
        "1 (dir leaf) + 1 (index) + 50 dispatched children, of which only \
         3 emit under max=3. Charging AFTER the `out.len() >= max` test \
         gives 5: got spent={spent} emitted={}",
        hints.entering.len()
    );
    // The SAME property in the other walker, because the truncation
    // reads `dispatches_left` on both sides and one row pinning one
    // walker leaves the other free: a `DirInterior` of 50 absent
    // children under the same cap.
    let children: Vec<InteriorChild> = (0..50u32)
        .map(|i| InteriorChild {
            first_key: name(&format!("k{i:03}")),
            child: gid(&format!("charge-first-dir-{i}")),
            subtree_entry_count: 1,
        })
        .collect();
    let bytes = node::encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
    let id = GrainId::of(&bytes);
    let mut dir_store = Store::new();
    dir_store.insert(id, bytes);
    let cursor = TreeCursor::new(id);
    let (hints, spent) = cursor.prefetch_hints_counted(&|i| dir_store.get(i).cloned(), 3);
    assert_eq!(
        (spent, hints.entering.len()),
        (51, 3),
        "1 (the interior) + 50 dispatched children, only 3 emitting \
         under max=3; charging after the cap test gives 4: got \
         spent={spent} emitted={}",
        hints.entering.len()
    );
}

/// Register row 219: the guard lives INSIDE the hint pass, not only
/// in its caller.
///
/// [`MANIFEST_NODE_MAX_BYTES`] is the widest byte length ANY legal
/// manifest structure node encodes to, so bytes wider than it are
/// corrupt or hostile and never a manifest node.
/// `prefetch_hints` takes an arbitrary `Fn(&GrainId) ->
/// Option<Vec<u8>>`: before this guard the widest object the pass
/// would hash, decode and retain was whatever that closure chose to
/// return, and the pass's stated heap ceiling was a claim about the
/// caller rather than about this file.
///
/// Both blobs are named by their OWN hash, so the hash check cannot
/// be what refuses either — the only difference between them is one
/// byte of length. The positive control is what stops this row
/// passing by refusing everything, and it pins the boundary to the
/// byte: `>=` in place of `>` fails it.
#[test]
fn a_structure_node_wider_than_any_legal_node_is_refused() {
    let mut at_cap = encoding::envelope(ObjectType::DirInterior);
    at_cap.resize(MANIFEST_NODE_MAX_BYTES as usize, 0);
    assert_eq!(
        at_cap.len(),
        MANIFEST_NODE_MAX_BYTES as usize,
        "fixture: the positive control must sit exactly ON the ceiling"
    );
    let mut over_cap = at_cap.clone();
    over_cap.push(0);
    let at_id = GrainId::of(&at_cap);
    let over_id = GrainId::of(&over_cap);
    assert!(
        matches!(
            open_structure_node(&at_id, &at_cap),
            Some((ObjectType::DirInterior, _))
        ),
        "positive control: bytes AT the ceiling are still opened"
    );
    assert!(
        open_structure_node(&over_id, &over_cap).is_none(),
        "one byte past the widest legal structure node must be refused"
    );
}

/// Register row 218's projection, pinned where it can be seen. A
/// frame keeps only the children the pass could still DISPATCH:
/// every dispatch charges a work unit at the callee's first line,
/// and nothing charges between a node's own `charge()` and its child
/// loop, so [`HintWork::dispatches_left`] read at the projection is
/// EXACT rather than conservative. The ids past that prefix can
/// never be visited, and
/// holding them is what put one full decoded index vector on every
/// live frame.
#[test]
fn the_index_projection_keeps_only_what_the_pass_can_still_dispatch() {
    let (index_root, store) = index_of_distinct_absent(300, "proj-absent");
    let bytes = store
        .get(&index_root)
        .cloned()
        .unwrap_or_else(|| panic!("fixture: the index must be resident"));
    // The expected list is derived from the FIXTURE BUILDER, not from
    // the function under test. Taking `all` from the projection
    // itself and comparing a prefix of it pins count and
    // prefix-consistency but NOT ORDER — a mutation inserting
    // `.rev()` inside the projection was run against that form and
    // passed it.
    let all: Vec<GrainId> = (1..=300)
        .map(|k| gid(&format!("proj-absent-{k}")))
        .collect();
    assert_eq!(
        project_grain_list_children(&index_root, bytes.clone(), &HintWork { left: usize::MAX }),
        all,
        "the whole index, in canonical order — independently derived"
    );
    let kept = project_grain_list_children(&index_root, bytes.clone(), &HintWork { left: 5 });
    assert_eq!(
        kept.as_slice(),
        &all[..5],
        "the first 5 in canonical order, and no more"
    );
    assert!(
        project_grain_list_children(&index_root, bytes, &HintWork { left: 0 }).is_empty(),
        "a frame with nothing left to spend retains nothing"
    );
}

/// The `DirInterior` arm truncates on the same budget as the index
/// arm. Narrower — a directory interior holds at most
/// `DIR_INTERIOR_MAX_CHILDREN` (256) children, against 131,072 for a
/// grain-list index — but unpinned it is a projection that could
/// silently stop truncating, and the two arms are edited together.
#[test]
fn the_dir_interior_projection_keeps_only_what_the_pass_can_still_dispatch() {
    let children: Vec<InteriorChild> = (0..6u32)
        .map(|i| InteriorChild {
            first_key: name(&format!("k{i:03}")),
            child: gid(&format!("interior-child-{i}")),
            subtree_entry_count: 1,
        })
        .collect();
    let bytes = node::encode_dir_interior(&children).unwrap_or_else(|e| panic!("{e}"));
    let id = GrainId::of(&bytes);
    let ids = |left: usize| match project_dir_node(
        &id,
        bytes.clone(),
        &BTreeSet::new(),
        &HintWork { left },
    ) {
        DirProjection::Children(c) => c,
        DirProjection::Spills(_) | DirProjection::Nothing => {
            panic!("fixture: the node is a DirInterior of six children")
        }
    };
    let all = ids(usize::MAX);
    // ASSERT THE FIXTURE: six children, so "kept 2" is visibly
    // different from "kept everything".
    assert_eq!(
        all,
        children.iter().map(|ch| ch.child).collect::<Vec<_>>(),
        "fixture: all six children, in canonical key order"
    );
    assert_eq!(ids(2).as_slice(), &all[..2], "the first 2, and no more");
    assert!(ids(0).is_empty(), "nothing left to spend retains nothing");
}

/// The `spill_seen` filter runs BEFORE the truncation, and this row
/// is what makes the order load-bearing rather than incidental. A
/// hit costs the caller nothing at all — it never reaches a dispatch
/// and charges no work — so a projection that truncated first and
/// filtered after would retain entries it is about to drop and DROP
/// entries the pass can still afford: with two hits in front and one
/// dispatch left, the wrong order projects nothing at all.
#[test]
fn the_dir_leaf_projection_filters_spill_seen_before_it_truncates() {
    let roots = [
        gid("proj-spill-a"),
        gid("proj-spill-b"),
        gid("proj-spill-c"),
    ];
    let entries: Vec<DirEntry> = roots
        .iter()
        .enumerate()
        .map(|(i, r)| spill_entry(&format!("f{i}"), 1_000, 200, *r))
        .collect();
    let bytes = node::encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    let id = GrainId::of(&bytes);
    let key = |r: GrainId| (r, 1_000u64, 200u32);
    let spills = |seen: &BTreeSet<(GrainId, u64, u32)>, left: usize| match project_dir_node(
        &id,
        bytes.clone(),
        seen,
        &HintWork { left },
    ) {
        DirProjection::Spills(s) => s,
        DirProjection::Children(_) | DirProjection::Nothing => {
            panic!("fixture: the node is a DirLeaf of three spill entries")
        }
    };
    let none = BTreeSet::new();
    // ASSERT THE FIXTURE: three spill entries in canonical order.
    assert_eq!(
        spills(&none, usize::MAX),
        vec![key(roots[0]), key(roots[1]), key(roots[2])],
        "fixture: three spill entries, canonical order"
    );
    assert_eq!(
        spills(&none, 2),
        vec![key(roots[0]), key(roots[1])],
        "with nothing memoized, the truncation is the only thing that cuts"
    );
    let mut seen: BTreeSet<(GrainId, u64, u32)> = BTreeSet::new();
    seen.insert(key(roots[0]));
    seen.insert(key(roots[1]));
    assert_eq!(
        spills(&seen, 1),
        vec![key(roots[2])],
        "two memoized entries cost no dispatch, so the one dispatch left \
         belongs to the third — truncating first would project nothing"
    );
    assert!(
        spills(&none, 0).is_empty(),
        "nothing left to spend retains nothing"
    );
    // The memo key is the TRIPLE, and two of its three fields were
    // dead in this fixture until this assertion: every entry above
    // declares the same `(1_000, 200)`, so a projection that
    // filtered on the ROOT alone passed the whole suite. A
    // re-declared root — same id, different size — is a different
    // key, is not memoized, and must still be projected.
    for wrong in [(roots[0], 1_001, 200), (roots[0], 1_000, 201)] {
        let mut redeclared: BTreeSet<(GrainId, u64, u32)> = BTreeSet::new();
        redeclared.insert(wrong);
        assert_eq!(
            spills(&redeclared, usize::MAX),
            vec![key(roots[0]), key(roots[1]), key(roots[2])],
            "a memo entry for the same root under a different size OR a \
             different grain_count is a DIFFERENT key and filters \
             nothing: {wrong:?}"
        );
    }
    // The projection does NOT dedup within a leaf, and that is the
    // contract `HINT_WORK_MAX` states: a repeated child costs a work
    // unit each time. The index arm is pinned against this by three
    // rows; the leaf arm had none until this one.
    let twice = [
        spill_entry("g0", 1_000, 200, roots[0]),
        spill_entry("g1", 1_000, 200, roots[0]),
    ];
    let twice_bytes = node::encode_dir_leaf(&twice).unwrap_or_else(|e| panic!("{e}"));
    let twice_id = GrainId::of(&twice_bytes);
    match project_dir_node(
        &twice_id,
        twice_bytes,
        &BTreeSet::new(),
        &HintWork { left: usize::MAX },
    ) {
        DirProjection::Spills(s) => assert_eq!(
            s,
            vec![key(roots[0]), key(roots[0])],
            "one leaf naming the same spill twice projects it twice"
        ),
        DirProjection::Children(_) | DirProjection::Nothing => {
            panic!("fixture: two spill entries over one root")
        }
    }
}

// ------------------------------------------------ validate_dir_btree

/// A directory of `n` files and `dirs` subdirectories, as the leaf-sorted list.
fn mixed_entries(n: u32, dirs: u32) -> Vec<DirEntry> {
    let mut out: Vec<DirEntry> = (0..n)
        .map(|i| DirEntry {
            name: name(&format!("f{i:05}")),
            kind: EntryKind::Fifo,
        })
        .collect();
    out.extend((0..dirs).map(|i| DirEntry {
        name: name(&format!("g{i:05}")),
        kind: EntryKind::Dir {
            child: gid(&format!("child{i}")),
        },
    }));
    out
}

#[test]
fn validate_dir_btree_returns_the_entries_and_child_ids_without_descending() {
    for (n, dirs) in [(0, 0), (3, 2), (300, 5), (600, 40)] {
        let entries = mixed_entries(n, dirs);
        let tree = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
        let nodes: BTreeMap<_, _> = tree.nodes.iter().cloned().collect();
        let fetched = RefCell::new(Vec::new());
        let (got, children) = validate_dir_btree(&tree.root, &|id| {
            fetched.borrow_mut().push(*id);
            nodes.get(id).cloned()
        })
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, entries, "the entries differ at {n} files, {dirs} dirs");
        let expected: Vec<_> = (0..dirs).map(|i| gid(&format!("child{i}"))).collect();
        assert_eq!(children, expected, "child ids or their order differ");
        assert!(
            fetched.borrow().iter().all(|id| nodes.contains_key(id)),
            "validation fetched an object outside this directory's own tree"
        );
    }
}

#[test]
fn validate_dir_btree_agrees_with_the_whole_tree_walk_on_a_refusal() {
    // A duplicate name straddling two leaves is refused by cross-node ordering.
    let a = vec![
        DirEntry {
            name: name("a"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("m"),
            kind: EntryKind::Fifo,
        },
    ];
    let b = vec![
        DirEntry {
            name: name("m"),
            kind: EntryKind::Fifo,
        },
        DirEntry {
            name: name("z"),
            kind: EntryKind::Fifo,
        },
    ];
    let left = node::encode_dir_leaf(&a).unwrap_or_else(|e| panic!("{e}"));
    let right = node::encode_dir_leaf(&b).unwrap_or_else(|e| panic!("{e}"));
    let (lid, rid) = (GrainId::of(&left), GrainId::of(&right));
    let interior = node::encode_dir_interior(&[
        InteriorChild {
            first_key: name("a"),
            child: lid,
            subtree_entry_count: 2,
        },
        InteriorChild {
            first_key: name("m"),
            child: rid,
            subtree_entry_count: 2,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let root = GrainId::of(&interior);
    let nodes = BTreeMap::from([(lid, left), (rid, right), (root, interior)]);
    let fetch = |id: &GrainId| nodes.get(id).cloned();
    let whole = validate_dir_tree(&root, &fetch).unwrap_err();
    let one = validate_dir_btree(&root, &fetch).unwrap_err();
    assert_eq!(one, whole);
    assert_eq!(one, ValidateError::CrossNodeOrder);
}

#[test]
fn validate_dir_btree_reports_a_missing_node_and_checks_file_grain_lists() {
    let entries = mixed_entries(3, 0);
    let tree = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        validate_dir_btree(&tree.root, &|_| None),
        Err(ValidateError::MissingObject { id: tree.root })
    );
    // A spilled file whose grain list is absent is refused by the same call.
    let lying = vec![DirEntry {
        name: name("spill"),
        kind: EntryKind::File {
            exec: false,
            size: 129,
            grains: FileGrains::Spill {
                grain_count: 129,
                root: gid("absent"),
            },
        },
    }];
    let tree = build_dir(&lying).unwrap_or_else(|e| panic!("{e}"));
    let nodes: BTreeMap<_, _> = tree.nodes.iter().cloned().collect();
    assert_eq!(
        validate_dir_btree(&tree.root, &|id| nodes.get(id).cloned()),
        Err(ValidateError::MissingObject { id: gid("absent") })
    );
}

#[test]
fn a_seeded_spill_claim_is_not_walked_again_and_nothing_else_is_skipped() {
    let lying = vec![DirEntry {
        name: name("spill"),
        kind: EntryKind::File {
            exec: false,
            size: 129,
            grains: FileGrains::Spill {
                grain_count: 129,
                root: gid("absent"),
            },
        },
    }];
    let tree = build_dir(&lying).unwrap_or_else(|e| panic!("{e}"));
    let nodes: BTreeMap<_, _> = tree.nodes.iter().cloned().collect();
    let claim = (gid("absent"), 129, 129);
    let vouched = BTreeSet::from([claim]);
    assert!(
        validate_dir_btree_seeded(&tree.root, &|id| nodes.get(id).cloned(), &vouched).is_ok(),
        "a vouched claim was walked again"
    );
    // A claim that differs in any field is not vouched for.
    for other in [
        (gid("absent"), 128, 129),
        (gid("absent"), 129, 130),
        (gid("other"), 129, 129),
    ] {
        assert!(
            validate_dir_btree_seeded(
                &tree.root,
                &|id| nodes.get(id).cloned(),
                &BTreeSet::from([other])
            )
            .is_err(),
            "a claim for a different entry vouched for this one"
        );
    }
}
