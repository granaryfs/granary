// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::listing` — the `dir_and_parent`
//! directory-descent primitive that `readdir`/`readdirplus`/`opendir`
//! share.
//!
//! Out-of-line: `granary-vfs`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-fuse`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::dir_and_parent;
use crate::{InodeTable, NodeKind, ReaderError, Snapshot};
use granary_core::hash::GrainId;
use granary_core::manifest::{DirEntry, EntryKind, FileGrains, Name, TreeStats, build_dir};
use granary_core::sheaf::Timestamp;
use std::collections::BTreeMap;

// Shared with `granary-fuse::listing`'s own test module — COPIED, not
// moved: the twenty tests that stay there need these too.
fn file(name: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(Vec::new()),
        },
    }
}

fn dir(name: &[u8], child: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Dir { child },
    }
}

// The one place that calls `Snapshot::new` with this fixture's six
// arguments — `snapshot` and the multi-level tests below all go
// through this, rather than each rebuilding the identical call
// inline.
fn snapshot_from_nodes(nodes: BTreeMap<GrainId, Vec<u8>>, root: GrainId) -> Snapshot {
    Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        crate::AttrPolicy { uid: 3, gid: 4 },
        crate::ServeLimits::UNBOUNDED,
    )
    .expect("fixture snapshot indexes")
}

fn snapshot(entries: &[DirEntry]) -> (Snapshot, GrainId) {
    let built = build_dir(entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let snapshot = snapshot_from_nodes(nodes, root);
    (snapshot, root)
}

#[test]
fn dir_and_parent_of_the_root_is_the_root_twice() {
    let (snapshot, root) = snapshot(&[file(b"f")]);
    let table = InodeTable::new(root, 1, 1);
    assert_eq!(
        dir_and_parent(&table, &snapshot, 1),
        Ok((root, root)),
        "the root is its own parent"
    );
}

#[test]
fn dir_and_parent_descends_three_levels_of_disjoint_names() {
    // root -> "a" -> "b" -> "c" (a leaf file), every level's own
    // entries are DISJOINT from its ancestors', so listing the wrong
    // (parent's) node is visible rather than accidentally correct.
    let leaf_dir = build_dir(&[file(b"only-in-c")]).expect("leaf dir builds");
    let middle_entries = [dir(b"c", leaf_dir.root)];
    let middle_dir = build_dir(&middle_entries).expect("middle dir builds");
    let top_entries = [dir(b"b", middle_dir.root), file(b"only-in-a")];
    let top_dir = build_dir(&top_entries).expect("top dir builds");
    let root_entries = [dir(b"a", top_dir.root), file(b"only-in-root")];
    let root_tree = build_dir(&root_entries).expect("root builds");
    let mut nodes = leaf_dir.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(middle_dir.nodes);
    nodes.extend(top_dir.nodes);
    nodes.extend(root_tree.nodes);
    let snap = snapshot_from_nodes(nodes, root_tree.root);

    let mut table = InodeTable::new(root_tree.root, 1, 1);
    let (a_ino, _) = table
        .lookup(vec![b"a".to_vec()], root_tree.root, NodeKind::Dir)
        .expect("a resolves");
    let (b_ino, _) = table
        .lookup(
            vec![b"a".to_vec(), b"b".to_vec()],
            top_dir.root,
            NodeKind::Dir,
        )
        .expect("b resolves");

    assert_eq!(
        dir_and_parent(&table, &snap, a_ino),
        Ok((top_dir.root, root_tree.root)),
        "a's own node and root as parent"
    );
    assert_eq!(
        dir_and_parent(&table, &snap, b_ino),
        Ok((middle_dir.root, top_dir.root)),
        "b's own node (not a's!) and a as parent"
    );
}

#[test]
fn dir_and_parent_distinguishes_identical_content_by_path() {
    // Two distinct paths, "x/shared" and "y/shared", point at
    // byte-identical (and therefore GrainId-identical) empty
    // directories. dir_and_parent must still report the correct,
    // DIFFERENT parent for each, even though `dir` is the same value
    // for both.
    let shared = build_dir(&[]).expect("shared child builds");
    let x_entries = [dir(b"shared", shared.root)];
    let x = build_dir(&x_entries).expect("x builds");
    let y_entries = [dir(b"shared", shared.root)];
    let y = build_dir(&y_entries).expect("y builds");
    let root_entries = [dir(b"x", x.root), dir(b"y", y.root)];
    let root_tree = build_dir(&root_entries).expect("root builds");
    let mut nodes = shared.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(x.nodes);
    nodes.extend(y.nodes);
    nodes.extend(root_tree.nodes);
    let snap = snapshot_from_nodes(nodes, root_tree.root);

    let mut table = InodeTable::new(root_tree.root, 1, 1);
    let (x_shared_ino, _) = table
        .lookup(
            vec![b"x".to_vec(), b"shared".to_vec()],
            x.root,
            NodeKind::Dir,
        )
        .expect("x/shared resolves");
    let (y_shared_ino, _) = table
        .lookup(
            vec![b"y".to_vec(), b"shared".to_vec()],
            y.root,
            NodeKind::Dir,
        )
        .expect("y/shared resolves");

    assert_eq!(
        dir_and_parent(&table, &snap, x_shared_ino),
        Ok((shared.root, x.root))
    );
    assert_eq!(
        dir_and_parent(&table, &snap, y_shared_ino),
        Ok((shared.root, y.root)),
        "identical content must not blur per-path parent identity"
    );
}

#[test]
fn dir_and_parent_refuses_a_path_whose_entry_is_not_actually_a_directory() {
    // A24: the `_ => Err(Inconsistent)` fallback arm (any entry kind
    // other than Dir) collapsed to `_ => Ok((parent, parent))`. This
    // constructs the mismatch directly: the table records `f`'s row as
    // a Dir, but the manifest entry at that path is a File.
    let (snap, root) = snapshot(&[file(b"f")]);
    let mut table = InodeTable::new(root, 1, 1);
    let (f_ino, _) = table
        .lookup(vec![b"f".to_vec()], root, NodeKind::Dir)
        .expect("lookup itself does not validate the kind it is told");
    assert_eq!(
        dir_and_parent(&table, &snap, f_ino),
        Err(ReaderError::Inconsistent),
        "A24: a path whose manifest entry is not a directory must be refused, not treated \
         as its own parent"
    );
}
