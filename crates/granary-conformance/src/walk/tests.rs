// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::walk` — `granconf dump`'s walker: the one place this
//! crate touches a real filesystem to build rows.
//!
//! Out-of-line: `granary-conformance`'s non-test artifact
//! has its own `[[bin]]` (`granconf`) and its own `tests/`
//! directory (`crates/granary-conformance/tests/cli.rs`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::{
    check_dot_entries, classify_child, open_root, read_bounded_payload,
    refuse_duplicate_escaped_paths, refuse_entry_name_with_slash, walk, walk_opened_root,
};
use std::ffi::OsStr;
use std::fs;
use std::io::Cursor;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        // Test-name-scoped, not pid-scoped (`std::process::id` is a
        // banned ambient-input seam workspace-wide). Distinct test names
        // isolate concurrent cases, and `Drop` cleans even after panic.
        let dir = std::env::temp_dir().join(format!("granconf-walk-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }
}

impl std::ops::Deref for ScratchDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn walk_refuses_a_root_that_is_not_a_directory() {
    let dir = ScratchDir::new("not-a-dir");
    let file = dir.join("f");
    fs::write(&file, b"x").unwrap();
    let err = walk(&file).expect_err("a plain file root must be refused");
    assert!(matches!(err, super::WalkError::NotADirectory { .. }));
}

#[test]
fn walk_sorts_rows_by_raw_path_bytes_independent_of_creation_order() {
    let dir = ScratchDir::new("sort-order");
    // Created in an order that disagrees with byte-sort order, on
    // purpose: 'z', '9', 'M' — byte order is '9' (0x39) < 'M'
    // (0x4d) < 'z' (0x7a). Three names that are byte-DISTINCT under
    // any case-folding, unlike an 'A'/'a' pair, which this crate's
    // own case-fold-siblings predicate deliberately makes collide
    // on APFS (this test's host filesystem) — that collision is
    // real and correct behaviour, just not what THIS test probes.
    fs::write(dir.join("z9file"), b"1").unwrap();
    fs::write(dir.join("9zfile"), b"1").unwrap();
    fs::write(dir.join("Mzfile"), b"1").unwrap();
    let rows = walk(&dir).expect("walk succeeds");
    let paths: Vec<Vec<u8>> = rows.iter().map(|r| r.path.clone()).collect();
    assert_eq!(
        paths,
        vec![b"9zfile".to_vec(), b"Mzfile".to_vec(), b"z9file".to_vec()]
    );
}

#[test]
fn walk_records_the_exec_bit_and_dir_and_symlink_kinds() {
    let dir = ScratchDir::new("kinds");
    let exe = dir.join("exe");
    fs::write(&exe, b"#!").unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    let non_owner_executable = dir.join("non-owner-executable");
    fs::write(&non_owner_executable, b"#!").unwrap();
    fs::set_permissions(&non_owner_executable, fs::Permissions::from_mode(0o411)).unwrap();
    let plain = dir.join("plain");
    fs::write(&plain, b"hi").unwrap();
    fs::create_dir(dir.join("sub")).unwrap();
    std::os::unix::fs::symlink("plain", dir.join("link")).unwrap();

    let rows = walk(&dir).expect("walk succeeds");
    let by_name = |n: &[u8]| rows.iter().find(|r| r.path == n).expect("row present");

    assert!(by_name(b"exe").exec);
    assert!(
        by_name(b"non-owner-executable").exec,
        "group/other execute bits must not be reduced to the owner-execute bit"
    );
    assert!(!by_name(b"plain").exec);
    assert_eq!(by_name(b"sub").kind, super::Kind::Dir);
    assert_eq!(by_name(b"link").kind, super::Kind::Symlink);
    match &by_name(b"link").payload {
        super::Payload::Target(t) => assert_eq!(t, b"plain"),
        other => panic!("expected a Target payload, got {other:?}"),
    }
}

#[test]
fn classify_child_records_raw_dtype_even_when_lstat_disagrees() {
    let dir = ScratchDir::new("raw-dtype");
    let file = dir.join("file");
    fs::write(&file, b"payload").expect("create file");
    let parent = open_root(&dir).expect("open parent directory");
    let (row, child_dir) = classify_child(
        &parent,
        OsStr::new("file"),
        b"file".to_vec(),
        &file,
        super::DType::Symlink,
    )
    .expect("classify regular file");
    assert_eq!(row.kind, super::Kind::File);
    assert_eq!(row.dtype, super::DType::Symlink);
    assert!(child_dir.is_none());
}

#[test]
fn dot_entry_check_accepts_both_and_refuses_every_missing_polarity() {
    let path = Path::new("tree/dir");
    assert!(check_dot_entries(true, true, path).is_ok());
    for (saw_dot, saw_dotdot) in [(false, true), (true, false), (false, false)] {
        let error = check_dot_entries(saw_dot, saw_dotdot, path)
            .expect_err("missing either structural entry must be refused");
        assert!(
            matches!(error, super::WalkError::MissingDotEntries { path: ref p } if p == path),
            "unexpected error: {error}"
        );
    }
}

/// The emit-time refusal, driven directly: two rows sharing the
/// same raw path — the only way it can ever fire, since the
/// escaper is injective (see `crate::escape`'s tests) and no real
/// `readdir` stream reports one name twice. Distinct rows with
/// distinct paths must NOT trip it, which the second assertion
/// checks so this is not merely "any two rows refuse".
#[test]
fn a_file_over_the_payload_bound_is_refused_by_name_not_by_an_oom() {
    // Sparse: `set_len` costs no blocks, so this asserts the BOUND
    // rather than spending 64 MiB to reach it.
    let dir = ScratchDir::new("payload-bound");
    let big = dir.join("huge.bin");
    let f = fs::File::create(&big).expect("create the sparse file");
    f.set_len(super::PAYLOAD_MAX_BYTES + 1)
        .expect("extend it past the bound");
    drop(f);
    let err = walk(&dir).expect_err("a file past the bound must be refused");
    assert!(
        matches!(err, super::WalkError::FileTooLarge { .. }),
        "expected FileTooLarge, got {err:?}"
    );
}

#[test]
fn a_file_at_exactly_the_payload_bound_is_still_read() {
    // The boundary itself is legal -- an off-by-one here would refuse a
    // file the contract accepts, which is the quieter of the two errors.
    let dir = ScratchDir::new("payload-bound-edge");
    let f = fs::File::create(dir.join("edge.bin")).expect("create");
    f.set_len(super::PAYLOAD_MAX_BYTES)
        .expect("extend to the bound");
    drop(f);
    assert!(walk(&dir).is_ok(), "a file AT the bound must be accepted");
}

#[test]
fn delivered_byte_bound_refuses_an_overlong_stream() {
    // A stable ordinary file on this filesystem cannot report a length
    // smaller than its content. Drive the exact production read helper
    // with an overlong stream instead: its bound must be on delivered
    // bytes, independent of any stat value.
    let path = Path::new("tree/lying-file");
    let error = read_bounded_payload(Cursor::new(b"four"), path, 3)
        .expect_err("four delivered bytes must exceed a three-byte bound");
    assert!(
        matches!(
            error,
            super::WalkError::FileTooLarge { path: ref p, len: 4 } if p == path
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn opened_ancestor_fd_cannot_be_steered_by_a_symlink_swap() {
    let scratch = ScratchDir::new("ancestor-symlink-swap");
    let tree = scratch.join("tree");
    let ancestor = tree.join("ancestor");
    let walked_root = ancestor.join("walked");
    fs::create_dir_all(walked_root.join("sub")).expect("create in-root tree");
    fs::write(walked_root.join("safe.txt"), b"safe").expect("write in-root file");
    fs::write(walked_root.join("sub/deep.txt"), b"deep").expect("write nested file");

    let ordinary_rows = walk(&walked_root).expect("walk ordinary tree");
    assert!(ordinary_rows.iter().all(|row| {
        walked_root
            .join(OsStr::from_bytes(&row.path))
            .starts_with(&walked_root)
    }));

    // Pin `tree/ancestor/walked`, then replace the non-final `ancestor`
    // component with a symlink. Re-resolving the diagnostic path now lands
    // in `outside/walked`; continuing through the fd must stay on the
    // directory that was actually opened.
    let opened = open_root(&walked_root).expect("pin walked root");
    let outside = scratch.join("outside");
    fs::create_dir_all(outside.join("walked")).expect("create outside shape");
    fs::write(outside.join("walked/cert.pem"), b"outside").expect("write out-of-root lure");
    fs::rename(&ancestor, tree.join("parked-ancestor")).expect("park original ancestor");
    std::os::unix::fs::symlink(&outside, &ancestor).expect("install ancestor symlink");

    let rows = walk_opened_root(&walked_root, opened).expect("walk pinned directory fd");
    let paths: Vec<Vec<u8>> = rows.iter().map(|row| row.path.clone()).collect();
    assert_eq!(
        paths,
        vec![
            b"safe.txt".to_vec(),
            b"sub".to_vec(),
            b"sub/deep.txt".to_vec()
        ]
    );
    assert!(rows.iter().all(|row| row.path != b"cert.pem"));
}

#[test]
fn a_slash_in_a_raw_directory_entry_name_is_refused() {
    let directory = Path::new("tree/directory");
    let error = refuse_entry_name_with_slash(directory, b"a/b")
        .expect_err("a raw name must be exactly one path component");
    assert!(
        matches!(
            error,
            super::WalkError::EntryNameContainsSlash {
                directory: ref d,
                name: ref n,
            } if d == directory && n == b"a/b"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn refuse_duplicate_escaped_paths_fires_on_a_shared_raw_path_and_only_then() {
    use crate::row::{DType, Kind, Payload, new_row};

    let a = new_row(
        b"same/path".to_vec(),
        Kind::File,
        DType::File,
        Some(1),
        false,
        Payload::Content("a".repeat(64)),
    )
    .expect("valid row");
    let b = new_row(
        b"same/path".to_vec(), // the identical raw path, from a second (hypothetical) source
        Kind::File,
        DType::File,
        Some(2), // even a DIFFERENT size doesn't matter — this check is on the path alone
        false,
        Payload::Content("b".repeat(64)),
    )
    .expect("valid row");
    let err = refuse_duplicate_escaped_paths(&[a.clone(), b])
        .expect_err("two rows sharing a raw path must be refused");
    assert!(matches!(err, super::WalkError::DuplicateEscapedPath { .. }));

    let mut distinct = a.clone();
    distinct.path = b"a-genuinely-different-path".to_vec();
    assert!(
        refuse_duplicate_escaped_paths(&[a, distinct]).is_ok(),
        "two rows with distinct paths must not be refused"
    );
}
