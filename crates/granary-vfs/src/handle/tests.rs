// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::handle` — the monotonic FUSE handle table
//! and its exactly-one-release-per-open guarantee.
//!
//! Out-of-line: `granary-vfs`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-fuse`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::{HandleKind, HandleTable};
use crate::{InodeTable, NodeKind, ReaderError};
use granary_core::hash::GrainId;

fn path(parts: &[&[u8]]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.to_vec()).collect()
}

#[test]
fn a_duplicate_release_does_not_reclaim_a_still_open_inode() {
    // Duplicate-release regression test, driven through both tables: two
    // live handles on ONE inode, so releasing one twice (a duplicate)
    // must not touch the second, still-open handle's claim on it.
    let root = GrainId::of(b"root");
    let file = GrainId::of(b"file");
    let mut inodes = InodeTable::new(root, 5, 1);
    let mut handles = HandleTable::new();
    let (ino, _) = inodes
        .lookup(path(&[b"f"]), file, NodeKind::File)
        .expect("lookup succeeds");
    inodes.open(ino).expect("first inode-table open succeeds");
    inodes.open(ino).expect("second inode-table open succeeds");
    let fh1 = handles
        .open(ino, HandleKind::File)
        .expect("first handle opens");
    let _fh2 = handles
        .open(ino, HandleKind::File)
        .expect("second handle opens");
    inodes.forget(ino, 1); // nlookup -> 0; two live handles keep it resident
    assert!(
        inodes.resolve(ino).is_ok(),
        "two open handles must keep the inode resident at nlookup == 0"
    );

    // Genuine RELEASE of fh1: the gate finds it, so InodeTable::release
    // runs. One handle remains, so the inode must stay resident.
    if let Some(released_ino) = handles.release(fh1, HandleKind::File) {
        inodes.release(released_ino);
    }
    assert!(
        inodes.resolve(ino).is_ok(),
        "one of two handles released — the second must still keep it resident"
    );

    // DUPLICATE RELEASE of fh1 — must be a no-op at the HandleTable
    // level, which must therefore mean InodeTable::release is never
    // called a second time for it.
    let duplicate = handles.release(fh1, HandleKind::File);
    assert_eq!(duplicate, None, "a duplicate RELEASE finds nothing");
    if let Some(released_ino) = duplicate {
        inodes.release(released_ino);
    }
    assert!(
        inodes.resolve(ino).is_ok(),
        "a duplicate RELEASE must not reclaim an inode the second handle still uses"
    );
}

#[test]
fn release_of_an_unknown_handle_is_a_no_op() {
    let mut handles = HandleTable::new();
    assert_eq!(handles.release(999, HandleKind::File), None);
    assert_eq!(handles.release(0, HandleKind::Directory), None);
}

#[test]
fn releasedir_naming_a_file_handle_does_not_release_it_and_vice_versa() {
    let mut handles = HandleTable::new();
    let file_fh = handles.open(1, HandleKind::File).expect("file opens");
    let dir_fh = handles.open(2, HandleKind::Directory).expect("dir opens");

    assert_eq!(
        handles.release(file_fh, HandleKind::Directory),
        None,
        "a RELEASEDIR must not release a file handle"
    );
    assert_eq!(
        handles.release(dir_fh, HandleKind::File),
        None,
        "a RELEASE must not release a directory handle"
    );

    // The handles are still live and release correctly under the right kind.
    assert_eq!(handles.release(file_fh, HandleKind::File), Some(1));
    assert_eq!(handles.release(dir_fh, HandleKind::Directory), Some(2));
}

#[test]
fn two_opens_of_one_inode_release_independently() {
    // The existing InodeTable suite never opened one inode twice
    // through a handle table, so this property was only ever exercised
    // at a handle count of one.
    let mut handles = HandleTable::new();
    let fh1 = handles.open(7, HandleKind::File).expect("first opens");
    let fh2 = handles.open(7, HandleKind::File).expect("second opens");
    assert_ne!(fh1, fh2, "two opens of one inode get distinct handles");

    assert_eq!(handles.release(fh1, HandleKind::File), Some(7));
    // fh2 is unaffected by fh1's release.
    assert_eq!(handles.release(fh2, HandleKind::File), Some(7));
}

#[test]
fn handles_are_never_reused_after_release() {
    let mut handles = HandleTable::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut previous: Option<u64> = None;
    for ino in 0_u64..50 {
        let fh = handles.open(ino, HandleKind::File).expect("opens");
        assert!(seen.insert(fh), "handle {fh} reused");
        if let Some(prev) = previous {
            assert!(fh > prev, "handles must be monotonic");
        }
        previous = Some(fh);
        handles.release(fh, HandleKind::File);
    }
}

#[test]
fn handle_counter_overflow_is_a_hard_error_without_wrap() {
    let mut handles = HandleTable::new();
    handles.next = u64::MAX - 1;
    let penultimate = handles.open(1, HandleKind::File);
    assert_eq!(penultimate, Ok(u64::MAX - 1));
    let overflowed = handles.open(1, HandleKind::File);
    assert_eq!(overflowed, Err(ReaderError::HandleCountOverflow));
    assert_eq!(handles.next, u64::MAX, "the counter must not wrap");
}

#[test]
fn handle_preflight_and_exact_binding_never_consume_an_exhausted_number() {
    let mut handles = super::HandleTable::new();
    handles.preflight_open().unwrap();
    let handle = handles.open(19, super::HandleKind::File).unwrap();
    assert!(handles.matches(handle, 19, super::HandleKind::File));
    assert!(!handles.matches(handle, 20, super::HandleKind::File));
    assert!(!handles.matches(handle, 19, super::HandleKind::Directory));
    handles.next = u64::MAX;
    assert_eq!(
        handles.preflight_open(),
        Err(crate::ReaderError::HandleCountOverflow)
    );
    assert_eq!(handles.next, u64::MAX);
    assert!(handles.matches(handle, 19, super::HandleKind::File));
}

// A per-handle list would name `shared` twice and send it twice.
#[test]
fn open_inodes_names_each_held_inode_once() {
    let mut handles = HandleTable::new();
    handles.open(9, HandleKind::File).unwrap();
    handles.open(4, HandleKind::Directory).unwrap();
    let released = handles.open(7, HandleKind::File).unwrap();
    handles.open(9, HandleKind::File).unwrap();
    handles.release(released, HandleKind::File);
    assert_eq!(handles.open_inodes().collect::<Vec<_>>(), vec![4, 9]);
}
