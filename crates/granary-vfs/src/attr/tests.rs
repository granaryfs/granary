// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::attr` — deterministic attribute construction
//! from a manifest entry (size, block count, timestamps, symlink target
//! handling).
//!
//! Out-of-line: `granary-vfs`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-fuse`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use crate::{AttrPolicy, Entry, ServeLimits, Snapshot};
use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, GrainRef, Name, SymlinkTarget, TreeStats, build_dir,
};
use granary_core::sheaf::Timestamp;
use std::collections::BTreeMap;

fn directory_entry(name: &[u8], child: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Dir { child },
    }
}

fn reader_entry(entry: &DirEntry, leaf: GrainId) -> Entry {
    Entry {
        name: entry.name.clone(),
        kind: entry.kind.clone(),
        leaf,
    }
}

fn file_entry(name: &[u8], exec: bool, size: u64) -> DirEntry {
    let grains = if size == 0 {
        Vec::new()
    } else {
        vec![GrainRef {
            id: GrainId::of(name),
            unpacked_len: u32::try_from(size).expect("fixture size fits u32"),
        }]
    };
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec,
            size,
            grains: FileGrains::Inline(grains),
        },
    }
}

fn symlink_entry(name: &[u8], target: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Symlink {
            target: SymlinkTarget::new(target.to_vec()).expect("fixture target is valid"),
        },
    }
}

#[test]
fn directory_nlink_counts_subdirectories() {
    let empty = build_dir(&[]).expect("empty child builds");
    let child = empty.root;
    let entries = [
        directory_entry(b"one", child),
        directory_entry(b"three", child),
        directory_entry(b"two", child),
    ];
    let root_tree = build_dir(&entries).expect("root builds");
    let root = root_tree.root;
    let mut nodes = empty.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);
    let snapshot = Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");

    let root_entry = directory_entry(b"root", root);
    let child_entry = directory_entry(b"child", child);
    let root_attr = snapshot
        .attr_for(&reader_entry(&root_entry, root), 1, 0)
        .expect("root attributes exist");
    let child_attr = snapshot
        .attr_for(&reader_entry(&child_entry, child), 2, 0)
        .expect("child attributes exist");
    assert_eq!(root_attr.nlink, 5);
    assert_eq!(child_attr.nlink, 2);
    assert_eq!(root_attr.size, super::DIRECTORY_SIZE);
    assert_eq!(root_attr.blocks, 8);
}

#[test]
fn find_leaf_optimisation_regression_descends_into_subdirectories() {
    let empty = build_dir(&[]).expect("empty child builds");
    let child = empty.root;
    let entries = [directory_entry(b"nested", child)];
    let root_tree = build_dir(&entries).expect("root builds");
    let root = root_tree.root;
    let mut nodes = empty.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);
    let snapshot = Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");
    let root_entry = directory_entry(b"root", root);
    let nlink = snapshot
        .attr_for(&reader_entry(&root_entry, root), 1, 0)
        .expect("root attributes exist")
        .nlink;

    // GNU find's leaf optimisation derives its subdirectory budget as
    // `nlink - 2`; a directory with any subdirectory must leave a budget.
    assert!(nlink >= 3, "find must descend, but nlink was {nlink}");
}

#[test]
fn modes_follow_entry_type_and_signed_exec_bit() {
    let empty = build_dir(&[]).expect("empty child builds");
    let child = empty.root;
    let entries = [
        directory_entry(b"dir", child),
        file_entry(b"exec", true, 0),
        symlink_entry(b"link", b"target"),
        file_entry(b"plain", false, 0),
    ];
    let root_tree = build_dir(&entries).expect("root builds");
    let root = root_tree.root;
    let mut nodes = empty.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);
    let snapshot = Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");

    let expected = [
        (super::NodeKind::Dir, 0o555, 2, super::DIRECTORY_SIZE),
        (super::NodeKind::File, 0o555, 1, 0),
        (super::NodeKind::Symlink, 0o777, 1, 6),
        (super::NodeKind::File, 0o444, 1, 0),
    ];
    for (entry, (kind, perm, nlink, size)) in entries.iter().zip(expected) {
        let attr = snapshot
            .attr_for(&reader_entry(entry, root), 2, 0)
            .expect("entry attributes exist");
        assert_eq!(attr.kind, kind, "entry {:?}", entry.name.as_bytes());
        assert_eq!(attr.perm, perm, "entry {:?}", entry.name.as_bytes());
        assert_eq!(attr.nlink, nlink, "entry {:?}", entry.name.as_bytes());
        assert_eq!(attr.size, size, "entry {:?}", entry.name.as_bytes());
    }
}

#[test]
fn blocks_are_always_counted_in_512_byte_units() {
    let entries = [
        file_entry(b"empty", false, 0),
        file_entry(b"full-block", false, 4096),
        file_entry(b"one-byte", false, 1),
    ];
    let tree = build_dir(&entries).expect("root builds");
    let root = tree.root;
    let snapshot = Snapshot::new(
        tree.nodes.into_iter().collect(),
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");

    let expected = [0, 8, 1];
    for (entry, blocks) in entries.iter().zip(expected) {
        let attr = snapshot
            .attr_for(&reader_entry(entry, root), 2, 0)
            .expect("file attributes exist");
        assert_eq!(attr.blocks, blocks, "file size is {:?}", entry.kind);
        assert_eq!(attr.blksize, super::ATTR_BLOCK_SIZE);
    }
}

#[test]
fn attr_time_is_the_root_timestamp_passed_through_unconverted() {
    let timestamp = Timestamp {
        secs: -123,
        nanos: 456_789,
    };
    let entries = [file_entry(b"file", false, 0)];
    let tree = build_dir(&entries).expect("root builds");
    let root = tree.root;
    let snapshot = Snapshot::new(
        tree.nodes.into_iter().collect(),
        root,
        timestamp,
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");
    let attr = snapshot
        .attr_for(&reader_entry(&entries[0], root), 22, 33)
        .expect("file attributes exist");

    // There is ONE field, so fanning it into an array and comparing four
    // copies would constrain nothing — the fanout to atime, mtime,
    // ctime and crtime is over the adapter's own kernel-facing
    // attribute type, and belongs to the adapter's own tests. What this
    // builder owes is narrower: pass the format's `Timestamp` through
    // UNCONVERTED.
    assert_eq!(attr.time, timestamp);
    assert_eq!((attr.uid, attr.gid), (9, 10));
    assert_eq!((attr.ino, attr.generation), (22, 33));
}

/// A reserved FIFO/socket entry refuses the whole directory at snapshot
/// construction, before it can reach `readdir` or `attr_for`. This test
/// pins the construction refusal, naming the FIFO entry.
#[test]
fn fifo_is_refused_at_snapshot_construction_naming_the_entry() {
    let fifo_name = Name::new(b"pipe".to_vec()).expect("fixture name is valid");
    let entries = [DirEntry {
        name: fifo_name.clone(),
        kind: EntryKind::Fifo,
    }];
    let tree = build_dir(&entries).expect("root builds");
    let root = tree.root;

    let result = Snapshot::new(
        tree.nodes.into_iter().collect(),
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    );

    let refusal = result.expect_err("a snapshot carrying a FIFO must be refused, not indexed");
    assert_eq!(
        refusal,
        crate::SnapshotError::ReservedEntry {
            dir: root,
            name: fifo_name,
            kind: crate::ReservedEntryKind::Fifo,
        }
    );
}

/// `attr_for`'s own FIFO/socket refusal, kept as a DIRECT unit test and
/// still live as defence in depth even though `Snapshot::new` now
/// refuses any manifest that could produce one of these `Entry` values
/// through `lookup`/`readdir` — no fixture can carry a reserved entry
/// past construction any more, so this builds the `Entry` by hand
/// instead (the same technique `list_dir_plus` already uses to
/// fabricate `.`/`..` entries) against an otherwise-ordinary,
/// successfully-indexed snapshot.
#[test]
fn attr_for_refuses_a_hand_built_reserved_entry_directly() {
    let entries = [file_entry(b"plain", false, 0)];
    let tree = build_dir(&entries).expect("root builds");
    let root = tree.root;
    let snapshot = Snapshot::new(
        tree.nodes.into_iter().collect(),
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("an ordinary snapshot indexes");

    for reserved in [EntryKind::Fifo, EntryKind::Socket] {
        let entry = Entry {
            name: Name::new(b"reserved".to_vec()).expect("fixture name is valid"),
            kind: reserved.clone(),
            leaf: root,
        };
        assert_eq!(
            snapshot.attr_for(&entry, 2, 0),
            Err(crate::ReaderError::UnsupportedEntry),
            "attr_for must refuse {reserved:?} directly"
        );
    }
}

#[test]
fn readlink_returns_non_utf8_and_absolute_targets_byte_identically() {
    let absolute = b"/outside/../target";
    let non_utf8 = b"../opaque-\xff\xfe";
    let entries = [
        symlink_entry(b"absolute", absolute),
        symlink_entry(b"non-utf8", non_utf8),
    ];
    let tree = build_dir(&entries).expect("root builds");
    let root = tree.root;
    let snapshot = Snapshot::new(
        tree.nodes.into_iter().collect(),
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");
    let absolute_entry = snapshot
        .lookup(&root, b"absolute")
        .expect("absolute symlink exists");
    let non_utf8_entry = snapshot
        .lookup(&root, b"non-utf8")
        .expect("non-UTF-8 symlink exists");

    assert_eq!(snapshot.readlink(&absolute_entry), Ok(absolute.as_slice()));
    assert_eq!(snapshot.readlink(&non_utf8_entry), Ok(non_utf8.as_slice()));
    assert_eq!(
        snapshot
            .attr_for(&absolute_entry, 2, 0)
            .map(|attr| attr.size),
        Ok(u64::try_from(absolute.len()).expect("fixture length fits"))
    );
    assert_eq!(
        snapshot
            .attr_for(&non_utf8_entry, 3, 0)
            .map(|attr| attr.size),
        Ok(u64::try_from(non_utf8.len()).expect("fixture length fits"))
    );
}

#[test]
fn nlink_counts_subdirectories_not_entries() {
    // Every committed fixture happens to make a directory's ENTRY count
    // and its SUBDIRECTORY count equal, so `2 + entries` passes the whole
    // suite. This fixture separates them.
    let empty = build_dir(&[]).expect("empty child builds");
    let child = empty.root;
    let entries = [
        file_entry(b"a", false, 0),
        file_entry(b"b", false, 0),
        file_entry(b"c", false, 0),
        directory_entry(b"sub", child),
    ];
    let root_tree = build_dir(&entries).expect("root builds");
    let root = root_tree.root;
    let mut nodes = empty.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);
    let snapshot = Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");
    let root_entry = directory_entry(b"root", root);
    let attr = snapshot
        .attr_for(&reader_entry(&root_entry, root), 1, 0)
        .expect("root attributes exist");
    assert_eq!(snapshot.dir_entries(&root), Ok(4));
    assert_eq!(snapshot.dir_subdirs(&root), Ok(1));
    assert_eq!(
        attr.nlink, 3,
        "nlink is 2 + SUBDIRECTORIES, not 2 + entries"
    );
}

#[test]
fn blksize_and_directory_size_are_pinned_to_literals() {
    // The committed assertion compares the field against the CONSTANT that
    // produced it, which is a tautology: `ATTR_BLOCK_SIZE = 0` survives it.
    // `st_blksize` is the I/O buffer size callers derive their read size
    // from, and 0 is a divide-by-zero for any caller that trusts it.
    let entries = [file_entry(b"f", false, 0)];
    let tree = build_dir(&entries).expect("root builds");
    let root = tree.root;
    let snapshot = Snapshot::new(
        tree.nodes.into_iter().collect(),
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");
    let attr = snapshot
        .attr_for(&reader_entry(&entries[0], root), 2, 0)
        .expect("file attributes exist");
    assert_eq!(attr.blksize, 4096, "st_blksize is the advertised I/O unit");
    assert!(
        attr.blksize > 0,
        "st_blksize = 0 divides by zero in callers"
    );
    assert_eq!(super::DIRECTORY_SIZE, 4096, "the stated directory size");
}

#[test]
fn readlink_refuses_a_non_symlink() {
    let empty = build_dir(&[]).expect("empty child builds");
    let child = empty.root;
    let entries = [
        directory_entry(b"dir", child),
        file_entry(b"file", false, 3),
    ];
    let root_tree = build_dir(&entries).expect("root builds");
    let root = root_tree.root;
    let mut nodes = empty.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);
    let snapshot = Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 7, nanos: 8 },
        TreeStats::default(),
        AttrPolicy { uid: 9, gid: 10 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes");
    for name in [b"dir".as_slice(), b"file".as_slice()] {
        let entry = snapshot.lookup(&root, name).expect("entry exists");
        assert_eq!(
            snapshot.readlink(&entry),
            Err(crate::ReaderError::Inconsistent),
            "readlink must refuse {name:?}, not report an empty target"
        );
    }
}

#[test]
fn writable_permission_mode_matrix_has_no_dirty_state_input() {
    let mut cases = 0;
    for (writable, expected) in [
        (false, [0o555, 0o555, 0o444, 0o555, 0o777, 0o777]),
        (true, [0o755, 0o755, 0o644, 0o755, 0o777, 0o777]),
    ] {
        for ((kind, exec), expected) in [
            (super::NodeKind::Dir, false),
            (super::NodeKind::Dir, true),
            (super::NodeKind::File, false),
            (super::NodeKind::File, true),
            (super::NodeKind::Symlink, false),
            (super::NodeKind::Symlink, true),
        ]
        .into_iter()
        .zip(expected)
        {
            assert_eq!(super::permission_mode(writable, kind, exec), expected);
            cases += 1;
        }
    }
    assert_eq!(cases, 12);
}
