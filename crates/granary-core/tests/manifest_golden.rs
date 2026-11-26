// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Manifest object golden vectors. Every OBJECT emitted by the ten
//! pinned
//! cases below is a consensus surface: a red here after a code change
//! means the FORMAT moved bytes — a deliberate versioned event,
//! never a refactor side effect.
//!
//! Regenerate DELIBERATELY:
//! `GRANARY_REGEN_VECTORS=1 cargo nextest run -p granary-core --test manifest_golden`

#![expect(
    clippy::unwrap_used,
    reason = "render/build helpers below sit outside #[test] fns (test code, standards rule 3)"
)]

use std::fmt::Write as _;
use std::path::Path;

use granary_core::hash::GrainId;
use granary_core::manifest::{
    BuiltTree, DIR_LEAF_MAX_ENTRIES, DirEntry, EntryKind, FILE_INLINE_MAX_REFS, FileGrains,
    GrainListIndexChild, GrainRef, Name, SymlinkTarget, build_dir, build_grain_list,
    encode_grain_list_index,
};
use granary_core::testkit;

mod common;

fn nm(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).unwrap()
}

/// A synthetic 1-byte grain ref, reproducible from `seed` alone
/// (`testkit::fill`) — used where a case needs many grains without
/// caring about their content.
fn synth_gref(seed: u64) -> GrainRef {
    GrainRef {
        id: GrainId::of(&testkit::fill(seed, 1)),
        unpacked_len: 1,
    }
}

/// One line per node: `case <name>/<i> id=<GrainId text> bytes=<hex of
/// full object>`. `nodes` is in the tree builder's own post-order
/// (children before the parent that references them) — the only
/// deterministic order the library exposes, and the one used
/// consistently below for every multi-node case.
fn render_nodes(out: &mut String, case: &str, nodes: &[(GrainId, Vec<u8>)]) {
    for (i, (id, bytes)) in nodes.iter().enumerate() {
        let mut hex = String::new();
        for b in bytes {
            write!(hex, "{b:02x}").unwrap();
        }
        writeln!(out, "case {case}/{i} id={id} bytes={hex}").unwrap();
    }
}

fn one_file_entry(exec: bool) -> DirEntry {
    DirEntry {
        name: nm("a"),
        kind: EntryKind::File {
            exec,
            size: 3,
            grains: FileGrains::Inline(vec![GrainRef {
                id: GrainId::of(b"abc"),
                unpacked_len: 3,
            }]),
        },
    }
}

fn empty_file_entry(name: &str) -> DirEntry {
    DirEntry {
        name: nm(name),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(vec![]),
        },
    }
}

// one-symlink: "s" -> "target".
fn case_one_symlink() -> BuiltTree {
    build_dir(&[DirEntry {
        name: nm("s"),
        kind: EntryKind::Symlink {
            target: SymlinkTarget::new(b"target".to_vec()).unwrap(),
        },
    }])
    .unwrap()
}

// git-quirk-order: foo (dir -> empty-dir id) sorts FIRST, ahead of
// foo-x and foo.txt — the opposite of git's trailing-slash quirk (git
// would sort a directory 'foo' AFTER 'foo-x').
fn case_git_quirk_order(empty_dir_id: GrainId) -> BuiltTree {
    build_dir(&[
        DirEntry {
            name: nm("foo"),
            kind: EntryKind::Dir {
                child: empty_dir_id,
            },
        },
        empty_file_entry("foo-x"),
        empty_file_entry("foo.txt"),
    ])
    .unwrap()
}

// inline-k-exact: exactly K 1-byte grains (K = FILE_INLINE_MAX_REFS),
// synthesized via testkit::fill for reproducibility.
fn case_inline_k_exact() -> BuiltTree {
    let k_refs: Vec<GrainRef> = (0..u64::from(FILE_INLINE_MAX_REFS))
        .map(synth_gref)
        .collect();
    build_dir(&[DirEntry {
        name: nm("k"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(FILE_INLINE_MAX_REFS),
            grains: FileGrains::Inline(k_refs),
        },
    }])
    .unwrap()
}

// two-leaf-257: C+1 empty-file entries e000..e256 (C = DIR_LEAF_MAX_ENTRIES)
// — leaf split [129, 128] + one interior (3 nodes, post order: leaf,
// leaf, interior).
fn case_two_leaf_257() -> BuiltTree {
    let count = DIR_LEAF_MAX_ENTRIES + 1;
    let entries: Vec<DirEntry> = (0..count)
        .map(|i| empty_file_entry(&format!("e{i:03}")))
        .collect();
    build_dir(&entries).unwrap()
}

// spill-boundary: K+1 refs (K = FILE_INLINE_MAX_REFS) -> file entry
// bytes carrying Spill, plus the one grain-list leaf object (K+1 <= N
// so no index level). Child (grain-list leaf) emitted before parent
// (dir leaf), same post-order convention as two-leaf-257.
fn case_spill_boundary() -> Vec<(GrainId, Vec<u8>)> {
    let count = FILE_INLINE_MAX_REFS + 1;
    let spill_refs: Vec<GrainRef> = (0..u64::from(count)).map(synth_gref).collect();
    let spill_list = build_grain_list(&spill_refs).unwrap();
    let spill_dir = build_dir(&[DirEntry {
        name: nm("f"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(count),
            grains: FileGrains::Spill {
                grain_count: count,
                root: spill_list.root,
            },
        },
    }])
    .unwrap();
    let mut nodes = spill_list.nodes;
    nodes.extend(spill_dir.nodes);
    nodes
}

// grainlist-index-synthetic: encode_grain_list_index over two
// hand-built children — pins the INDEX byte layout without
// materializing >131_072 refs (the in-file tests cover semantics).
fn case_grainlist_index_synthetic() -> (GrainId, Vec<u8>) {
    let index_children = vec![
        GrainListIndexChild {
            child: GrainId::of(b"gl-a"),
            cum_unpacked_len: 1000,
            cum_ref_count: 1,
        },
        GrainListIndexChild {
            child: GrainId::of(b"gl-b"),
            cum_unpacked_len: 2500,
            cum_ref_count: 3,
        },
    ];
    let bytes = encode_grain_list_index(&index_children).unwrap();
    let id = GrainId::of(&bytes);
    (id, bytes)
}

/// Builds the full golden text and returns it alongside the pinned
/// empty-dir id (the format's best-known constant, asserted literally
/// below).
fn build_vectors() -> (String, GrainId) {
    let mut out = String::new();
    writeln!(out, "# granary manifest golden vectors v1").unwrap();

    // empty-dir: the canonical fixed empty leaf. Referenced BY ID from
    // git-quirk-order below, never re-emitted there.
    let empty_dir = build_dir(&[]).unwrap();
    render_nodes(&mut out, "empty-dir", &empty_dir.nodes);
    let empty_dir_id = empty_dir.root;

    let one_file = build_dir(&[one_file_entry(false)]).unwrap();
    render_nodes(&mut out, "one-file", &one_file.nodes);

    // one-exec: same file content, exec bit set — the entry TAG differs
    // (0x03 vs 0x02), a genuinely distinct object.
    let one_exec = build_dir(&[one_file_entry(true)]).unwrap();
    render_nodes(&mut out, "one-exec", &one_exec.nodes);

    render_nodes(&mut out, "one-symlink", &case_one_symlink().nodes);
    render_nodes(
        &mut out,
        "git-quirk-order",
        &case_git_quirk_order(empty_dir_id).nodes,
    );

    // empty-file: size 0, 0 grains — inline, canonical (format doc
    // explicitly calls this out as belonging in the golden vectors).
    let empty_file = build_dir(&[empty_file_entry("e")]).unwrap();
    render_nodes(&mut out, "empty-file", &empty_file.nodes);

    render_nodes(&mut out, "inline-k-exact", &case_inline_k_exact().nodes);
    render_nodes(&mut out, "two-leaf-257", &case_two_leaf_257().nodes);
    render_nodes(&mut out, "spill-boundary", &case_spill_boundary());

    let (index_id, index_bytes) = case_grainlist_index_synthetic();
    render_nodes(
        &mut out,
        "grainlist-index-synthetic",
        &[(index_id, index_bytes)],
    );

    (out, empty_dir_id)
}

#[test]
fn matches_committed_vectors() {
    let (out, _empty_dir_id) = build_vectors();
    common::assert_golden(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/manifest_v1.txt"),
        &out,
    );
}

/// The empty-dir id is the format's best-known constant: once filled,
/// it never changes again (barring a format event). `envelope(DirLeaf)`
/// (10 bytes) + `entry_count = 0` (4 bytes) = 14 bytes hashed.
#[test]
fn empty_dir_id_is_pinned() {
    let (_, empty_dir_id) = build_vectors();
    assert_eq!(
        empty_dir_id.to_string(),
        "blake3:9afb106e58b2813a85ce5e29c0715cf86d5fdccc9673eb252d39d9117462ca14"
    );
}
