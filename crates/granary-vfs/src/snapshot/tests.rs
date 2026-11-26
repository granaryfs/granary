// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::snapshot` — synchronous reads over an
//! already-validated manifest structure map (`Snapshot`, `AttrPolicy`,
//! `ServeLimits`): indexing, readdir/lookup/getattr semantics and their
//! error paths.
//!
//! Out-of-line: `granary-vfs`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-fuse`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form. This file also
//! declares `probes`, the module's second conforming test
//! body: a leaf nested under `tests`, not a second sibling
//! declaration in the parent.

use granary_core::encoding::{self, ObjectType};
use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, Name, SymlinkTarget, TreeStats, build_dir, decode_dir_leaf,
};
use granary_core::sheaf::Timestamp;
use std::collections::BTreeMap;

/// The byte this file's readlink-bound tests test, derived from the
/// FORMAT constant (not the adapter's own servable-ceiling constant) so
/// these tests keep testing the same byte once this module travels to
/// `granary-vfs`, which cannot name anything in `granary-fuse`.
const TEST_READLINK_BOUND: usize = granary_core::manifest::name::SYMLINK_TARGET_MAX - 1;

fn file(name: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("test name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(Vec::new()),
        },
    }
}

fn symlink(name: &[u8], target: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("test name is valid"),
        kind: EntryKind::Symlink {
            target: SymlinkTarget::new(target.to_vec()).expect("fixture target is valid"),
        },
    }
}

fn snapshot(entries: &[DirEntry]) -> (super::Snapshot, GrainId) {
    let built = build_dir(entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let snapshot = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits::UNBOUNDED,
    )
    .expect("fixture snapshot indexes");
    (snapshot, root)
}

#[test]
fn lookup_finds_single_leaf_entry_and_reports_not_found() {
    let (snapshot, root) = snapshot(&[file(b"alpha"), file(b"omega")]);

    let found = snapshot.lookup(&root, b"alpha").expect("alpha exists");
    assert_eq!(found.name.as_bytes(), b"alpha");
    assert!(matches!(found.kind, EntryKind::File { .. }));
    assert_eq!(
        snapshot.lookup(&root, b"missing"),
        Err(super::ReaderError::NotFound)
    );
}

#[test]
fn lookup_descends_a_multi_level_directory_tree() {
    let entries = (0..600)
        .map(|number| file(format!("entry-{number:04}").as_bytes()))
        .collect::<Vec<_>>();
    let built = build_dir(&entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let constructed = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits::UNBOUNDED,
    );
    assert!(
        constructed.is_ok(),
        "a valid interior-rooted directory must index: {constructed:?}"
    );
    let indexed = constructed.expect("asserted successful construction");

    let found = indexed
        .lookup(&root, b"entry-0513")
        .expect("entry behind an interior node exists");
    assert_eq!(found.name.as_bytes(), b"entry-0513");
}

#[test]
fn non_utf8_name_is_reachable_and_listed() {
    let raw_name = b"\xffentry";
    let (snapshot, root) = snapshot(&[file(raw_name)]);

    let found = snapshot
        .lookup(&root, raw_name)
        .expect("raw byte name exists");
    assert_eq!(found.name.as_bytes(), raw_name);

    let mut listed = Vec::new();
    snapshot
        .readdir(&root, &root, 2, |entry| {
            listed.push(entry.name);
            false
        })
        .expect("directory lists");
    assert!(
        listed.iter().any(|name| name.as_slice() == raw_name),
        "readdir omitted the non-UTF-8 name: {listed:?}"
    );
}

#[test]
fn readdir_resume_sweep_is_exact_across_leaf_boundaries() {
    let entries = (0..600)
        .map(|number| file(format!("entry-{number:04}").as_bytes()))
        .collect::<Vec<_>>();
    let expected = entries
        .iter()
        .map(|entry| entry.name.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let (snapshot, root) = snapshot(&entries);

    for capacity in 1..=entries.len() {
        let mut cursor = 2_u64;
        let mut got = Vec::new();
        while got.len() < entries.len() {
            let before = got.len();
            let previous_cursor = cursor;
            let mut returned_cursor = None;
            let result = snapshot.readdir(&root, &root, cursor, |entry| {
                returned_cursor = Some(entry.next);
                got.push(entry.name);
                got.len().saturating_sub(before) >= capacity
            });
            assert!(
                result.is_ok(),
                "capacity {capacity}, cursor {cursor}: {result:?}"
            );
            cursor = returned_cursor.expect("a nonempty remainder emits an entry");
            assert!(cursor > previous_cursor, "the resume cursor must advance");
        }
        assert_eq!(got, expected, "capacity {capacity}");
    }
}

#[test]
fn dot_and_dotdot_are_first_and_root_is_its_own_parent() {
    let (snapshot, root) = snapshot(&[file(b"file")]);
    let mut listed = Vec::new();
    let result = snapshot.readdir(&root, &root, 0, |entry| {
        listed.push(entry);
        false
    });
    assert!(result.is_ok(), "root directory lists: {result:?}");

    let mut entries = listed.iter();
    let dot = entries.next();
    let dotdot = entries.next();
    assert_eq!(
        dot.map(|entry| entry.name.as_slice()),
        Some(b".".as_slice())
    );
    assert_eq!(dot.map(|entry| entry.next), Some(1));
    assert_eq!(
        dotdot.map(|entry| entry.name.as_slice()),
        Some(b"..".as_slice())
    );
    assert_eq!(dotdot.map(|entry| entry.next), Some(2));
    assert!(matches!(
        dotdot.map(|entry| &entry.kind),
        Some(EntryKind::Dir { child }) if *child == root
    ));
}

#[test]
fn readdir_from_past_end_is_empty_success() {
    let (snapshot, root) = snapshot(&[file(b"file")]);
    let mut emitted = false;

    let result = snapshot.readdir(&root, &root, 99, |_entry| {
        emitted = true;
        false
    });

    assert_eq!(result, Ok(()));
    assert!(!emitted, "past-end readdir must emit nothing");
}

#[test]
fn directory_facts_count_entries_and_subdirectories() {
    let child = build_dir(&[]).expect("empty child builds");
    let child_root = child.root;
    let mut entries = (0..3)
        .map(|number| DirEntry {
            name: Name::new(format!("dir-{number}").into_bytes()).expect("valid name"),
            kind: EntryKind::Dir { child: child_root },
        })
        .collect::<Vec<_>>();
    entries.extend((0..5).map(|number| file(format!("file-{number}").as_bytes())));
    let root_tree = build_dir(&entries).expect("root builds");
    let root = root_tree.root;
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);
    let snapshot = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");

    assert_eq!(
        snapshot.dirs.get(&root).copied(),
        Some(super::DirFacts {
            entries: 8,
            subdirs: 3,
        })
    );
}

#[test]
fn shared_directory_is_indexed_once_by_grain_id() {
    let shared = build_dir(&[file(b"inside")]).expect("shared child builds");
    let shared_root = shared.root;
    let root_tree = build_dir(&[
        DirEntry {
            name: Name::new(b"first".to_vec()).expect("valid name"),
            kind: EntryKind::Dir { child: shared_root },
        },
        DirEntry {
            name: Name::new(b"second".to_vec()).expect("valid name"),
            kind: EntryKind::Dir { child: shared_root },
        },
    ])
    .expect("root builds");
    let root = root_tree.root;
    let mut nodes = shared.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);

    let snapshot = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");

    assert_eq!(snapshot.dirs.len(), 2, "root plus one memoised child");
}

#[test]
fn missing_interior_node_refuses_a_partial_snapshot() {
    let entries = (0..600)
        .map(|number| file(format!("entry-{number:04}").as_bytes()))
        .collect::<Vec<_>>();
    let built = build_dir(&entries).expect("fixture directory builds");
    let root = built.root;
    let mut nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let _removed = nodes.remove(&root).expect("the interior root is present");

    let result = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits::UNBOUNDED,
    );

    assert!(
        matches!(result, Err(super::SnapshotError::MissingNode { id }) if id == root),
        "missing interior must be named, not partially indexed: {result:?}"
    );
}

/// The decode-time refusal for a reserved entry, enforced where the walk
/// already visits every entry. Both reserved tags are exercised — the check
/// must not merely fire on one of the two `EntryKind` arms it guards.
#[test]
fn a_reserved_entry_is_refused_at_construction_naming_dir_name_and_kind() {
    for (reserved, expected_kind) in [
        (EntryKind::Fifo, super::ReservedEntryKind::Fifo),
        (EntryKind::Socket, super::ReservedEntryKind::Socket),
    ] {
        // `build_dir` requires strict memcmp order: "alpha" < "omega" <
        // "reserved".
        let reserved_name = Name::new(b"reserved".to_vec()).expect("fixture name is valid");
        let entries = [
            file(b"alpha"),
            file(b"omega"),
            DirEntry {
                name: reserved_name.clone(),
                kind: reserved,
            },
        ];
        let built = build_dir(&entries).expect("fixture directory builds");
        let root = built.root;
        let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();

        let result = super::Snapshot::new(
            nodes,
            root,
            Timestamp { secs: 1, nanos: 2 },
            TreeStats::default(),
            super::AttrPolicy { uid: 3, gid: 4 },
            super::ServeLimits::UNBOUNDED,
        );

        let refusal = result.expect_err(&format!(
            "a manifest carrying a {expected_kind} must be refused at construction"
        ));
        assert_eq!(
            refusal,
            super::SnapshotError::ReservedEntry {
                dir: root,
                name: reserved_name,
                kind: expected_kind,
            },
            "the refusal must name the directory, the entry, and its kind"
        );
    }
}

/// The POSITIVE CONTROL for the refusal above. Without it, a mutation
/// that refuses every snapshot outright would pass the negative test
/// just as well as the real, entry-kind-gated check.
#[test]
fn ordinary_entries_beside_the_reserved_entry_gate_still_construct() {
    let (snapshot, root) = snapshot(&[file(b"alpha"), file(b"omega")]);
    assert_eq!(snapshot.dir_entries(&root), Ok(2));
}

/// The rule for a format-valid value this mount's `readlink`
/// reply cannot carry: refused at construction, by name,
/// rather than surfacing later as an opaque `EIO` on one `readlink`
/// call. `SYMLINK_TARGET_MAX` stays 4096 — the target built here is
/// still format-valid, `TEST_READLINK_BOUND + 1` (4096) bytes, one over
/// the SERVE-layer limit this snapshot is built to admit.
#[test]
fn a_symlink_target_over_the_readlink_limit_is_refused_at_construction() {
    let target = vec![b'x'; TEST_READLINK_BOUND + 1];
    let entries = [symlink(b"link", &target)];
    let built = build_dir(&entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();

    let result = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits {
            readlink_target_max_bytes: TEST_READLINK_BOUND,
        },
    );

    assert!(
        matches!(
            result,
            Err(super::SnapshotError::UnrepresentableSymlinkTarget { len: 4096, .. })
        ),
        "an over-limit symlink target must be refused at construction, naming its length: {result:?}"
    );
}

/// The POSITIVE CONTROL for the refusal above. Without it, a mutation
/// that refused EVERY symlink would pass the negative test just as
/// well as the real, length-gated check.
#[test]
fn a_symlink_target_at_exactly_the_readlink_limit_is_accepted_and_reads_back_whole() {
    let target = vec![b'x'; TEST_READLINK_BOUND];
    let entries = [symlink(b"link", &target)];
    let built = build_dir(&entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let snapshot = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits {
            readlink_target_max_bytes: TEST_READLINK_BOUND,
        },
    )
    .expect("a target exactly at the bound must be admitted");

    let entry = snapshot
        .lookup(&root, b"link")
        .expect("symlink entry exists");
    let read_back = snapshot
        .readlink(&entry)
        .expect("symlink target reads back");
    assert_eq!(read_back, target.as_slice());
    assert_eq!(read_back.len(), TEST_READLINK_BOUND);
}

/// Closes three gaps a mutation run found in the two symlink tests
/// above, whose shared fixture is a single-leaf, single-entry
/// directory: the reported `id` was never pinned against anything
/// OTHER than `manifest_root/dir_root` (both wildcarded with `..` and,
/// in that fixture, equal to each other and to the leaf), and the
/// guard was never forced through a real B-TREE INTERIOR node.
///
/// The fixture is a MANIFEST ROOT holding one entry, `Dir { child:
/// dir_root }`, pointing at a 601-entry WIDE subdirectory whose own
/// B-tree root is therefore a `DirInterior` (601 > `DIR_LEAF_MAX_ENTRIES`
/// = 256, so `build_dir_level` splits it into three leaves under one
/// interior). The over-long target sits in the LAST of those three
/// leaves. This makes `manifest_root`, `dir_root`, and the leaf that
/// actually holds the entry three DIFFERENT grains, so a mutant that
/// reports `manifest_root` or `dir_root` instead of the containing
/// leaf is distinguishable from the real check, and a mutant that
/// only fires at `depth == 1` misses this leaf (reached at depth 2:
/// the worklist calls `scan_dir_node` on `dir_root` at depth 1, which
/// is `DirInterior` and recurses into this leaf at depth 2).
///
/// A nested `SUBdirectory` alone would not force `depth > 1`: the
/// worklist restarts every directory's OWN scan at depth 1
/// (`Snapshot::new`'s `scan_dir_node(&nodes, &dir_root, 1, ...)`), so
/// depth only grows from a real interior/leaf split within one
/// directory's tree, which is why the wide subdirectory itself (not
/// just its nesting under the manifest root) is load-bearing here.
#[test]
fn an_over_long_symlink_reached_through_a_btree_interior_names_its_own_leaf_not_a_root() {
    let target = vec![b'x'; TEST_READLINK_BOUND + 1];
    let mut wide_entries = (0..600)
        .map(|number| file(format!("entry-{number:04}").as_bytes()))
        .collect::<Vec<_>>();
    wide_entries.push(symlink(b"entry-0600", &target));
    let wide = build_dir(&wide_entries).expect("wide subdirectory builds");
    let dir_root = wide.root;

    // Fixture sanity: the wide subdirectory's own root must be a
    // DirInterior node, or depth > 1 is never reached and Gap 3 is
    // not actually exercised.
    let (dir_root_type, _) = encoding::open_envelope(
        wide.nodes
            .iter()
            .find(|(id, _)| *id == dir_root)
            .map(|(_, bytes)| bytes.as_slice())
            .expect("wide subdirectory root node is present"),
    )
    .expect("wide subdirectory root decodes");
    assert_eq!(
        dir_root_type,
        ObjectType::DirInterior,
        "fixture must force a B-tree interior root, or this probe proves nothing about depth > 1"
    );

    // Determine which LEAF actually holds the over-long entry by
    // decoding `wide.nodes` -- not by assuming which slot
    // `build_dir_level`'s balanced split put it in.
    let mut containing_leaf = None;
    for (id, bytes) in &wide.nodes {
        let Ok((ObjectType::DirLeaf, cursor)) = encoding::open_envelope(bytes) else {
            continue;
        };
        let Ok(decoded) = decode_dir_leaf(cursor) else {
            continue;
        };
        if decoded
            .iter()
            .any(|decoded_entry| decoded_entry.name.as_bytes() == b"entry-0600")
        {
            containing_leaf = Some(*id);
            break;
        }
    }
    let containing_leaf = containing_leaf
        .expect("the over-long entry must live in some leaf of the wide subdirectory");

    let top = build_dir(&[DirEntry {
        name: Name::new(b"wide".to_vec()).expect("valid name"),
        kind: EntryKind::Dir { child: dir_root },
    }])
    .expect("manifest-root directory builds");
    let manifest_root = top.root;

    // Fixture sanity: the three grains a wrong-grain mutant could
    // report are pairwise distinct, so a match against any of the
    // wrong two is distinguishable from a match against the right one.
    assert_ne!(
        containing_leaf, dir_root,
        "fixture sanity: the containing leaf must differ from the wide subdirectory's own root"
    );
    assert_ne!(
        containing_leaf, manifest_root,
        "fixture sanity: the containing leaf must differ from the manifest root"
    );
    assert_ne!(
        dir_root, manifest_root,
        "fixture sanity: the wide subdirectory's root must differ from the manifest root"
    );

    let mut nodes = wide.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(top.nodes);

    let result = super::Snapshot::new(
        nodes,
        manifest_root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits {
            readlink_target_max_bytes: TEST_READLINK_BOUND,
        },
    );

    match result {
        Err(super::SnapshotError::UnrepresentableSymlinkTarget { id, name, len }) => {
            assert_eq!(len, 4096);
            assert_eq!(
                id, containing_leaf,
                "must name the LEAF holding the entry ({containing_leaf}), not the manifest root ({manifest_root}) or the wide subdirectory's own B-tree root ({dir_root})"
            );
            // The name is what an operator actually has to go on: a grain
            // id and a byte count alone locate nothing. Pinned to the
            // offending entry, not to any of the 600 siblings.
            assert_eq!(
                name.as_bytes(),
                b"entry-0600",
                "must name the offending entry, not a sibling"
            );
        }
        other => panic!(
            "an over-limit symlink target reached through a B-tree interior must still be refused, naming the leaf that holds it: {other:?}"
        ),
    }
}

/// Closes the fourth gap: both symlink tests above use a single-entry
/// leaf, so a guard that inspects only the FIRST entry of a leaf, or
/// only the LAST, survives them. An over-long target sitting in the
/// MIDDLE of a leaf would be admitted by either such guard and only
/// fail later, as an opaque `EIO`, on that one `readlink` call.
#[test]
fn an_over_long_symlink_target_in_the_middle_of_a_leaf_is_refused() {
    let target = vec![b'x'; TEST_READLINK_BOUND + 1];
    let entries = [
        file(b"a_first"),
        symlink(b"m_middle", &target),
        file(b"z_last"),
    ];
    let built = build_dir(&entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();

    let result = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits {
            readlink_target_max_bytes: TEST_READLINK_BOUND,
        },
    );

    assert!(
        matches!(
            result,
            Err(super::SnapshotError::UnrepresentableSymlinkTarget { len: 4096, .. })
        ),
        "an over-limit target in the MIDDLE of a leaf must be refused too, not just at the first or last entry: {result:?}"
    );
}

#[test]
fn grain_list_leaf_at_directory_root_is_wrong_type() {
    let bytes =
        granary_core::manifest::encode_grain_list_leaf(&[granary_core::manifest::GrainRef {
            id: GrainId::of(b"content grain"),
            unpacked_len: 1,
        }])
        .expect("grain-list leaf encodes");
    let root = GrainId::of(&bytes);
    let nodes = [(root, bytes)].into_iter().collect::<BTreeMap<_, _>>();

    let result = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits::UNBOUNDED,
    );

    assert!(
        matches!(result, Err(super::SnapshotError::WrongType { id }) if id == root),
        "decoded non-directory object must be refused by type: {result:?}"
    );
}

#[test]
fn five_thousand_nested_directories_use_the_worklist() {
    let empty = build_dir(&[]).expect("empty leaf builds");
    let mut root = empty.root;
    let mut nodes = empty.nodes.into_iter().collect::<BTreeMap<_, _>>();
    for _level in 0..5_000 {
        let parent = build_dir(&[DirEntry {
            name: Name::new(b"next".to_vec()).expect("valid name"),
            kind: EntryKind::Dir { child: root },
        }])
        .expect("parent builds");
        root = parent.root;
        nodes.extend(parent.nodes);
    }

    let result = super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::AttrPolicy { uid: 3, gid: 4 },
        super::ServeLimits::UNBOUNDED,
    );
    assert!(
        result.is_ok(),
        "directory nesting is deliberately uncapped: {result:?}"
    );
    assert_eq!(result.expect("asserted success").dirs.len(), 5_001);
}

mod probes;
