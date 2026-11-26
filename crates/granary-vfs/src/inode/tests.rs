// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::inode` — per-path inode identity and kernel
//! reference accounting.
//!
//! Out-of-line: `granary-vfs`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-fuse`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use granary_core::hash::GrainId;

use crate::NodeKind;

use super::InodeTable;

fn path(parts: &[&[u8]]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.to_vec()).collect()
}

/// The oracle for the root number being an ARGUMENT rather than a
/// constant, and the only test in this module that does not pass 1.
///
/// Every other test here — and every one of the other 26
/// `InodeTable::new` sites in this crate (re-counted after the
/// engine's own extraction) — supplies the FUSE root id,
/// because they assert FUSE behaviour and a different number would make
/// their expectations meaningless. That is correct for them and leaves
/// this parameterisation completely unasserted: a mutation check proved it
/// by reverting `next` to the literal `2`, both root guards to
/// `ino == 1`, and `root_ino()`'s body to `1` — the whole suite stayed
/// green on all three. This test is what those mutations have to fail.
///
/// `2` is not an arbitrary second value: it is ext4's and APFS's real
/// root inode, so this is the shape the first non-FUSE adapter will
/// construct.
#[test]
fn the_root_number_is_the_argument_and_not_a_constant() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 7, 2);

    assert_eq!(table.root_ino(), 2, "the accessor reports what was given");

    // The root row is keyed at 2 on BOTH maps, and 1 is just a free
    // number — the mutation `next: 2` would hand it out below.
    assert_eq!(table.by_path.get(&Vec::new()), Some(&2));
    assert!(table.by_ino.contains_key(&2), "the root row is keyed at 2");
    assert!(!table.by_ino.contains_key(&1), "1 is not this table's root");

    // Allocation starts ABOVE the root, so no allocated inode can
    // collide with it. `next: 2` would return 2 here and alias the root.
    let (first, _) = table
        .lookup(path(&[b"a"]), file, NodeKind::File)
        .expect("first lookup succeeds");
    assert_eq!(first, 3, "allocation starts at root_ino + 1, not at 2");

    // The permanence guard reads the table's number, not the constant.
    // With `ino == 1` in `forget`, inode 2 would be reclaimable.
    table.forget(2, 1);
    assert!(
        table.by_ino.contains_key(&2),
        "the root is permanent at whatever number it was given"
    );
    // …and the guard must not have become "never reclaim anything":
    // 3 is an ordinary inode and forgetting it does reclaim it.
    table.forget(first, 1);
    assert!(
        !table.by_ino.contains_key(&first),
        "control: a non-root inode is still reclaimed"
    );
}

#[test]
fn identity_is_per_path_for_shared_directories_and_identical_files() {
    let root = GrainId::of(b"root");
    let shared_directory = GrainId::of(b"shared directory bytes");
    let identical_file = GrainId::of(b"identical file bytes");
    let mut table = InodeTable::new(root, 7, 1);

    let (left_dir, _) = table
        .lookup(path(&[b"left"]), shared_directory, NodeKind::Dir)
        .expect("left directory gets an inode");
    let (right_dir, _) = table
        .lookup(path(&[b"right"]), shared_directory, NodeKind::Dir)
        .expect("right directory gets an inode");
    let (left_file, _) = table
        .lookup(path(&[b"left", b"same"]), identical_file, NodeKind::File)
        .expect("left file gets an inode");
    let (right_file, _) = table
        .lookup(path(&[b"right", b"same"]), identical_file, NodeKind::File)
        .expect("right file gets an inode");

    assert_ne!(left_dir, right_dir, "shared content is not shared identity");
    assert_ne!(left_file, right_file, "equal bytes are not hard links");
}

#[test]
fn same_path_is_stable_while_referenced() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 11, 1);
    let key = path(&[b"stable"]);

    let first = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("first lookup succeeds");
    let second = table
        .lookup(key, file, NodeKind::File)
        .expect("second lookup succeeds");

    assert_eq!(first, second);
}

#[test]
fn lookup_after_forget_to_zero_gets_a_fresh_inode() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 13, 1);
    let key = path(&[b"fresh"]);
    let (first_ino, first_generation) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("first lookup succeeds");

    table.forget(first_ino, 1);
    let (second_ino, second_generation) = table
        .lookup(key, file, NodeKind::File)
        .expect("lookup after forget succeeds");

    assert_ne!(first_ino, second_ino, "inode numbers are never recycled");
    assert_eq!(first_generation, second_generation);
}

#[test]
fn open_handle_defers_reclamation_until_release() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 17, 1);
    let key = path(&[b"held"]);
    let (ino, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("lookup succeeds");
    table.open(ino).expect("open succeeds");

    table.forget(ino, 1);
    assert!(
        table.by_ino.contains_key(&ino),
        "a live handle keeps the inode resident"
    );
    assert_eq!(table.by_path.get(&key), Some(&ino));

    table.release(ino);
    assert!(!table.by_ino.contains_key(&ino));
    assert!(!table.by_path.contains_key(&key));
}

#[test]
fn unknown_and_excess_forget_are_safe_and_excess_reclaims() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 19, 1);
    let key = path(&[b"over-forgotten"]);
    let (ino, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("lookup succeeds");

    table.forget(u64::MAX, u64::MAX);
    table.forget(ino, 99);

    assert!(!table.by_ino.contains_key(&ino));
    assert!(!table.by_path.contains_key(&key));
}

#[test]
fn batch_forget_matches_sequential_forget() {
    fn populated() -> (InodeTable, [(u64, u64); 5]) {
        let root = GrainId::of(b"root");
        let file = GrainId::of(b"file");
        let mut table = InodeTable::new(root, 23, 1);
        let (twice, _) = table
            .lookup(path(&[b"twice"]), file, NodeKind::File)
            .expect("first lookup succeeds");
        table
            .lookup(path(&[b"twice"]), file, NodeKind::File)
            .expect("second lookup succeeds");
        let (held, _) = table
            .lookup(path(&[b"held"]), file, NodeKind::File)
            .expect("held lookup succeeds");
        table.open(held).expect("held inode opens");
        let (excess, _) = table
            .lookup(path(&[b"excess"]), file, NodeKind::File)
            .expect("excess lookup succeeds");
        (
            table,
            [
                (twice, 1),
                (u64::MAX, 9),
                (held, 1),
                (twice, 1),
                (excess, 99),
            ],
        )
    }

    let (mut sequential, forgets) = populated();
    let (mut batched, _) = populated();
    for &(ino, nlookup) in &forgets {
        sequential.forget(ino, nlookup);
    }
    batched.batch_forget(&forgets);

    assert_eq!(batched.by_path, sequential.by_path);
    assert_eq!(batched.by_ino.len(), sequential.by_ino.len());
    for (ino, expected) in &sequential.by_ino {
        let actual = batched.by_ino.get(ino).expect("same inode survives");
        assert_eq!(actual.path, expected.path);
        assert_eq!(actual.nlookup, expected.nlookup);
        assert_eq!(actual.handles, expected.handles);
    }
}

#[test]
fn working_set_is_bounded_but_open_handles_keep_entries_resident() {
    fn assert_only_root(table: &InodeTable, root: GrainId) {
        let root_ino = 1_u64;
        assert_eq!(table.by_ino.len(), 1, "only the root inode survives");
        assert_eq!(table.by_path.len(), 1, "only the root path survives");
        let root_entry = table.by_ino.get(&root_ino).expect("root survives");
        assert!(root_entry.path.is_empty(), "root path is empty");
        assert_eq!(root_entry.dir, root);
        assert_eq!(root_entry.kind, NodeKind::Dir);
        assert_eq!(table.by_path.get(&Vec::new()), Some(&root_ino));
    }

    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut reclaimed = InodeTable::new(root, 29, 1);
    let mut reclaimed_inos = Vec::new();
    for number in 0..10_000_u32 {
        let key = vec![format!("walk-{number}").into_bytes()];
        let (ino, _) = reclaimed
            .lookup(key, file, NodeKind::File)
            .expect("walk lookup succeeds");
        reclaimed_inos.push(ino);
    }
    for ino in reclaimed_inos {
        reclaimed.forget(ino, 1);
    }
    assert_only_root(&reclaimed, root);

    let mut held = InodeTable::new(root, 29, 1);
    let mut held_inos = Vec::new();
    for number in 0..10_000_u32 {
        let key = vec![format!("held-{number}").into_bytes()];
        let (ino, _) = held
            .lookup(key, file, NodeKind::File)
            .expect("held lookup succeeds");
        held.open(ino).expect("held inode opens");
        held.forget(ino, 1);
        held_inos.push(ino);
    }
    assert_eq!(held.by_ino.len(), 10_001);
    assert_eq!(held.by_path.len(), 10_001);
    for ino in held_inos {
        held.release(ino);
    }
    assert_only_root(&held, root);
}

#[test]
fn inode_number_exhaustion_is_a_hard_error_without_wrap() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 31, 1);
    table.next = u64::MAX - 1;

    assert_eq!(table.remaining_inodes(), 1);
    let penultimate = table.lookup(path(&[b"penultimate"]), file, NodeKind::File);
    assert_eq!(penultimate, Ok((u64::MAX - 1, 31)));
    let exhausted = table.lookup(path(&[b"exhausted"]), file, NodeKind::File);

    assert_eq!(exhausted, Err(crate::ReaderError::InodeNumberExhausted));
    assert_eq!((table.next, table.remaining_inodes()), (u64::MAX, 0));
    assert!(!table.by_ino.contains_key(&0));
    assert!(!table.by_path.contains_key(&path(&[b"exhausted"])));
}

#[test]
fn lookup_count_overflow_is_reported_without_making_an_inode_unforgettable() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 37, 1);
    let key = path(&[b"overflow"]);
    let (ino, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("initial lookup succeeds");
    table.by_ino.get_mut(&ino).expect("inode exists").nlookup = u64::MAX;

    let overflow = table.lookup(key.clone(), file, NodeKind::File);
    assert_eq!(overflow, Err(crate::ReaderError::LookupCountOverflow));
    assert_eq!(
        table.by_ino.get(&ino).map(|entry| entry.nlookup),
        Some(u64::MAX)
    );

    table.forget(ino, u64::MAX);
    assert!(!table.by_ino.contains_key(&ino));
    assert!(!table.by_path.contains_key(&key));
}

#[test]
fn handle_count_checks_open_overflow_and_release_underflow_is_safe() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 41, 1);
    let key = path(&[b"handles"]);
    let (ino, _) = table
        .lookup(key, file, NodeKind::File)
        .expect("lookup succeeds");
    table.by_ino.get_mut(&ino).expect("inode exists").handles = u32::MAX;

    assert_eq!(
        table.open(ino),
        Err(crate::ReaderError::HandleCountOverflow)
    );
    assert_eq!(
        table.by_ino.get(&ino).map(|entry| entry.handles),
        Some(u32::MAX)
    );

    table.by_ino.get_mut(&ino).expect("inode exists").handles = 0;
    table.release(u64::MAX);
    table.release(ino);
    assert_eq!(table.by_ino.get(&ino).map(|entry| entry.handles), Some(0));
    table.forget(ino, 1);
    assert!(!table.by_ino.contains_key(&ino));
}

// ---- QUALITY-LANE EXTENSION TESTS (from review) --------------------
// Each of the eight below was verified to FAIL against a named
// degenerate that the committed 64-test suite could not kill.

#[test]
fn the_root_is_never_reclaimed_and_its_count_is_never_decremented() {
    let root = GrainId::of(b"root");
    let mut table = InodeTable::new(root, 43, 1);
    let root_ino = 1_u64;

    // Everything the kernel can aim at inode 1.
    table.forget(root_ino, u64::MAX);
    table.batch_forget(&[(root_ino, u64::MAX), (root_ino, 1)]);
    table.release(root_ino);
    assert_eq!(
        table.by_ino.get(&root_ino).map(|entry| entry.nlookup),
        Some(1),
        "the root's lookup count is never decremented"
    );
    {
        let (path, dir, kind) = table.resolve(root_ino).expect("root still resolves");
        assert!(path.is_empty(), "the root's key is the empty path");
        assert_eq!(dir, root);
        assert_eq!(kind, NodeKind::Dir);
    }
    assert_eq!(table.by_ino.len(), 1);
    assert_eq!(table.by_path.get(&Vec::new()), Some(&root_ino));

    // And the reclaim guard holds INDEPENDENTLY of the forget guard:
    // drive the count to zero directly and release.
    table
        .by_ino
        .get_mut(&root_ino)
        .expect("root exists")
        .nlookup = 0;
    table.release(root_ino);
    assert!(
        table.by_ino.contains_key(&root_ino),
        "reclaim refuses the root even at nlookup == 0"
    );
    assert_eq!(table.by_path.get(&Vec::new()), Some(&root_ino));
}

#[test]
fn resolve_returns_the_recorded_path_dir_and_kind_and_refuses_the_unknown() {
    let root = GrainId::of(b"root");
    let parent = GrainId::of(b"parent directory");
    let mut table = InodeTable::new(root, 47, 1);
    let key = path(&[b"a", b"b"]);
    let (ino, _) = table
        .lookup(key.clone(), parent, NodeKind::File)
        .expect("lookup succeeds");

    {
        let (got_path, got_dir, got_kind) = table.resolve(ino).expect("resolve succeeds");
        assert_eq!(got_path, &key, "resolve returns the path it was keyed by");
        assert_eq!(got_dir, parent, "resolve returns the resident directory");
        assert_eq!(
            got_kind,
            NodeKind::File,
            "resolve returns the recorded kind"
        );
    }
    assert!(
        table.resolve(u64::MAX).is_err(),
        "an inode the mount never handed out does not resolve"
    );

    table.forget(ino, 1);
    assert!(
        table.resolve(ino).is_err(),
        "a reclaimed inode stops resolving"
    );
}

#[test]
fn a_partial_forget_leaves_a_still_referenced_inode_resident() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 53, 1);
    let key = path(&[b"three-references"]);
    let (ino, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("first lookup succeeds");
    table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("second lookup succeeds");
    table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("third lookup succeeds");

    table.forget(ino, 1);
    assert_eq!(
        table.by_ino.get(&ino).map(|entry| entry.nlookup),
        Some(2),
        "a forget of 1 against a count of 3 leaves 2"
    );
    assert_eq!(
        table.by_path.get(&key),
        Some(&ino),
        "an inode the kernel still references is NOT reclaimed"
    );
    let (again, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("fourth lookup succeeds");
    assert_eq!(again, ino, "a still-referenced path keeps its inode number");

    table.forget(ino, 3);
    assert!(!table.by_ino.contains_key(&ino));
    assert!(!table.by_path.contains_key(&key));
}

#[test]
fn batch_forget_applies_each_notification_exactly_once() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 71, 1);
    let key = path(&[b"counted"]);
    let (ino, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("first lookup succeeds");
    for _ in 0..4 {
        table
            .lookup(key.clone(), file, NodeKind::File)
            .expect("repeat lookup succeeds");
    }
    assert_eq!(table.by_ino.get(&ino).map(|entry| entry.nlookup), Some(5));

    table.batch_forget(&[(ino, 1), (ino, 2)]);
    assert_eq!(
        table.by_ino.get(&ino).map(|entry| entry.nlookup),
        Some(2),
        "5 - 1 - 2 = 2: each notification lands once, no more and no less"
    );
}

#[test]
fn releasing_one_of_two_handles_keeps_the_inode_resident() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 59, 1);
    let key = path(&[b"two-handles"]);
    let (ino, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("lookup succeeds");
    table.open(ino).expect("first open succeeds");
    table.open(ino).expect("second open succeeds");

    table.forget(ino, 1);
    table.release(ino);
    assert_eq!(
        table.by_ino.get(&ino).map(|entry| entry.handles),
        Some(1),
        "one handle is still open"
    );
    assert!(
        table.by_path.contains_key(&key),
        "the second descriptor still pins the inode"
    );

    table.release(ino);
    assert!(!table.by_ino.contains_key(&ino));
    assert!(!table.by_path.contains_key(&key));
}

#[test]
fn a_relookup_while_a_handle_is_open_returns_the_same_inode() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 61, 1);
    let key = path(&[b"held-then-relooked"]);
    let (first, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("lookup succeeds");
    table.open(first).expect("open succeeds");
    table.forget(first, 1);
    assert_eq!(table.by_ino.get(&first).map(|entry| entry.nlookup), Some(0));

    let (second, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("relookup succeeds");
    assert_eq!(
        second, first,
        "an open descriptor pins the path's identity — no-fd-invalidation"
    );
    assert_eq!(table.by_ino.get(&first).map(|entry| entry.nlookup), Some(1));

    table.release(first);
    assert!(
        table.by_ino.contains_key(&first),
        "the new lookup re-referenced the inode"
    );
}

#[test]
fn structurally_distinct_paths_never_share_an_inode() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 67, 1);

    // A flattened key — joined with a separator, or concatenated — would
    // alias at least one of these pairs. `Vec<Vec<u8>>` cannot.
    let keys = [
        path(&[b"a/b"]),
        path(&[b"a", b"b"]),
        path(&[b"a", b"", b"b"]),
        path(&[b"ab"]),
        path(&[b"a"]),
        path(&[b""]),
    ];
    let mut allocated = Vec::new();
    for key in &keys {
        let (ino, _) = table
            .lookup(key.clone(), file, NodeKind::File)
            .expect("lookup succeeds");
        allocated.push(ino);
    }
    let mut unique = allocated.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        keys.len(),
        "six structurally distinct paths get six inodes: {allocated:?}"
    );
    let root_ino = 1_u64;
    assert!(
        !allocated.contains(&root_ino),
        "a path of one empty component is not the root's empty path"
    );
}

#[test]
fn peek_reads_an_allocated_ino_without_crediting_or_allocating() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 91, 1);
    let key = path(&[b"peeked"]);

    assert_eq!(
        table.peek(&key),
        None,
        "an unallocated path has nothing to peek"
    );
    assert_eq!(table.resident_count(), 1, "peek must not allocate a row");

    let (ino, _) = table
        .lookup(key.clone(), file, NodeKind::File)
        .expect("lookup succeeds");
    assert_eq!(table.peek(&key), Some(ino));

    // Peeking again and again must not touch nlookup: a single forget
    // of 1 must still reclaim it, proving peek took no credit.
    let _ = table.peek(&key);
    let _ = table.peek(&key);
    table.forget(ino, 1);
    assert_eq!(
        table.peek(&key),
        None,
        "peek must not have credited nlookup — one forget(1) reclaims"
    );
}

#[test]
fn generation_is_the_constant_new_was_given() {
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut table = InodeTable::new(root, 12345, 1);
    assert_eq!(table.generation(), 12345);

    let (_, looked_up_generation) = table
        .lookup(path(&[b"a"]), file, NodeKind::File)
        .expect("lookup succeeds");
    assert_eq!(
        looked_up_generation,
        table.generation(),
        "lookup's own returned generation must agree with the getter"
    );
}

#[test]
fn open_of_an_unknown_inode_is_refused_and_changes_nothing() {
    let root = GrainId::of(b"root");
    let mut table = InodeTable::new(root, 73, 1);

    assert_eq!(
        table.open(u64::MAX),
        Err(crate::ReaderError::Inconsistent),
        "the kernel cannot open an inode this mount never handed out"
    );
    assert_eq!(table.by_ino.len(), 1, "no entry is conjured by an open");
    assert_eq!(table.by_path.len(), 1);
}

#[test]
fn moved_subtree_preserves_identity_and_displaced_target_holds() {
    let root = GrainId::of(b"root");
    let mut table = InodeTable::new(root, 7, 1);
    let source = path(&[b"src"]);
    let descendant = path(&[b"src", b"child"]);
    let target = path(&[b"dst"]);
    let (src, _) = table.lookup(source.clone(), root, NodeKind::Dir).unwrap();
    let (child, _) = table.lookup(descendant, root, NodeKind::File).unwrap();
    let (dst, _) = table.lookup(target.clone(), root, NodeKind::Dir).unwrap();
    table.open(dst).unwrap();
    table.move_path(&source, &target);
    assert_eq!(
        (
            table.peek(&source),
            table.peek(&target),
            table.peek(&path(&[b"dst", b"child"])),
            table.resolve(child).unwrap().0
        ),
        (None, Some(src), Some(child), &path(&[b"dst", b"child"]))
    );
    table.forget(dst, 1);
    table.release(dst);
    assert_eq!(
        table.peek(&target),
        Some(src),
        "reclaim of displaced inode must not erase the source's new path"
    );
    assert_eq!(table.generation(), 7);
}

// Selecting resident inodes by recorded path would return `earlier` again.
#[test]
fn detach_path_returns_only_the_associations_it_removed() {
    let root = GrainId::of(b"root");
    let mut table = InodeTable::new(root, 3, 1);
    let (dir, _) = table.lookup(path(&[b"a"]), root, NodeKind::Dir).unwrap();
    let (earlier, _) = table
        .lookup(path(&[b"a", b"b"]), root, NodeKind::File)
        .unwrap();
    let (sibling, _) = table.lookup(path(&[b"ab"]), root, NodeKind::File).unwrap();
    let first = table.detach_path(&path(&[b"a", b"b"]));
    let (later, _) = table
        .lookup(path(&[b"a", b"b"]), root, NodeKind::File)
        .unwrap();
    let second = table.detach_path(&path(&[b"a"]));
    assert_eq!(
        (first, second, table.attached(sibling)),
        (
            vec![(path(&[b"a", b"b"]), earlier)],
            vec![(path(&[b"a"]), dir), (path(&[b"a", b"b"]), later)],
            true
        )
    );
}

#[test]
fn detached_name_recreation_never_reuses_or_erases_a_live_inode() {
    let root = GrainId::of(b"root");
    let name = path(&[b"file"]);
    let mut table = InodeTable::new(root, 3, 1);
    let (old, _) = table.lookup(name.clone(), root, NodeKind::File).unwrap();
    table.open(old).unwrap();
    table.detach_path(&name);
    let (new, _) = table.lookup(name.clone(), root, NodeKind::File).unwrap();
    assert_ne!(old, new);
    table.forget(old, 1);
    table.release(old);
    assert_eq!((table.peek(&name), table.resident_count()), (Some(new), 2));
}

#[test]
fn allocation_preflight_refuses_exhaustion_without_consuming_identity() {
    let root = GrainId::of(b"root");
    let name = path(&[b"file"]);
    let mut table = InodeTable::new(root, 3, 1);
    table.next = u64::MAX;
    assert_eq!(
        table.preflight_lookup(&name),
        Err(crate::ReaderError::InodeNumberExhausted)
    );
    assert_eq!((table.next, table.resident_count()), (u64::MAX, 1));
    table.next = 2;
    let (ino, _) = table.lookup(name.clone(), root, NodeKind::File).unwrap();
    table.by_ino.get_mut(&ino).unwrap().nlookup = u64::MAX;
    assert_eq!(
        table.preflight_lookup(&name),
        Err(crate::ReaderError::LookupCountOverflow)
    );
    assert_eq!((table.next, table.peek(&name)), (3, Some(ino)));
}

#[test]
fn detached_attachment_checks_owner_after_recreate_and_move() {
    let mut table = InodeTable::new(GrainId::of(b"root"), 17, 1);
    let path = vec![b"name".to_vec()];
    let moved = vec![b"moved".to_vec()];
    let (old, _) = table
        .lookup(path.clone(), GrainId::of(b"dir"), NodeKind::File)
        .unwrap();
    table.open(old).unwrap();
    table.detach_path(&path);
    let (replacement, _) = table
        .lookup(path.clone(), GrainId::of(b"dir"), NodeKind::File)
        .unwrap();
    assert_eq!(
        (table.attached(old), table.attached(replacement)),
        (false, true)
    );
    table.move_path(&path, &moved);
    assert_eq!(
        (table.attached(old), table.attached(replacement)),
        (false, true)
    );
    table.forget(old, 1);
    table.release(old);
    assert_eq!(table.peek(&moved), Some(replacement));
}

#[test]
fn open_preflight_refuses_unknown_and_exhausted_inode_holds_without_mutation() {
    let mut table = InodeTable::new(GrainId::of(b"root"), 17, 1);
    let (ino, _) = table
        .lookup(vec![b"file".to_vec()], GrainId::of(b"dir"), NodeKind::File)
        .unwrap();
    assert_eq!(table.preflight_open(ino), Ok(()));
    table.by_ino.get_mut(&ino).unwrap().handles = u32::MAX;
    assert_eq!(
        table.preflight_open(ino),
        Err(crate::ReaderError::HandleCountOverflow)
    );
    assert_eq!(table.by_ino.get(&ino).unwrap().handles, u32::MAX);
    assert_eq!(
        table.preflight_open(u64::MAX),
        Err(crate::ReaderError::Inconsistent)
    );
}
