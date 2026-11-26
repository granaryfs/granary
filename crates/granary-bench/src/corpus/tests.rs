// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::corpus` — deterministic corpus loading, and the
//! walker's refuse-rather-than-skip and empty-directory rules.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use std::os::unix::fs::symlink;

fn scratch(name: &str) -> PathBuf {
    // Process-unique: two `cargo nextest` runs in two worktrees would
    // otherwise delete each other's fixtures.
    let dir = std::env::temp_dir().join(format!(
        "granary-bench-corpus-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

#[test]
fn walk_is_memcmp_sorted_depth_first() {
    let root = scratch("order");
    fs::create_dir(root.join("a")).expect("mkdir");
    fs::write(root.join("a/b"), b"x").expect("write");
    fs::write(root.join("a.txt"), b"y").expect("write");
    fs::write(root.join("Z"), b"z").expect("write");
    let c = load(&root).expect("load");
    let paths: Vec<String> = c
        .nodes
        .iter()
        .map(|n| {
            n.components
                .iter()
                .map(|p| String::from_utf8_lossy(p.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    assert_eq!(paths, vec!["Z", "a/b", "a.txt"]);
    let mut sorted = c.nodes.clone();
    sorted.sort_by(|x, y| x.components.cmp(&y.components));
    assert_eq!(sorted, c.nodes, "walk order != component order");
    fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
fn empty_directories_are_nodes() {
    let root = scratch("emptydir");
    fs::create_dir(root.join("hollow")).expect("mkdir");
    let c = load(&root).expect("load");
    assert_eq!(c.nodes.len(), 1);
    assert_eq!(c.nodes[0].kind, NodeKind::EmptyDir);
    fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
fn symlinks_are_recorded_not_followed() {
    let root = scratch("symlink");
    fs::write(root.join("real"), b"content").expect("write");
    symlink("real", root.join("link")).expect("symlink");
    let c = load(&root).expect("load");
    assert_eq!(c.file_count, 1, "the symlink must not be read as a file");
    let link = c
        .nodes
        .iter()
        .find(|n| n.components.last().map(Name::as_bytes) == Some(b"link".as_slice()))
        .expect("link node");
    assert!(matches!(link.kind, NodeKind::Symlink { .. }));
    fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
fn exec_bit_uses_any_exec_bit() {
    let root = scratch("exec");
    fs::write(root.join("prog"), b"#!/bin/sh\n").expect("write");
    fs::set_permissions(root.join("prog"), fs::Permissions::from_mode(0o711)).expect("chmod");
    fs::write(root.join("data"), b"plain").expect("write");
    fs::set_permissions(root.join("data"), fs::Permissions::from_mode(0o644)).expect("chmod");
    let c = load(&root).expect("load");
    let exec: Vec<bool> = c
        .nodes
        .iter()
        .map(|n| matches!(n.kind, NodeKind::File { exec: true, .. }))
        .collect();
    assert_eq!(exec, vec![false, true], "data then prog in memcmp order");
    fs::remove_dir_all(&root).expect("cleanup");
}

/// NEGATIVE: an unrepresentable entry stops the run instead of
/// quietly shrinking the corpus.
#[test]
fn unsupported_types_are_refused() {
    let root = scratch("fifo");
    let fifo = root.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed");
    let err = load(&root).expect_err("fifo must be refused");
    assert!(matches!(err, CorpusError::Unsupported { .. }), "{err}");
    fs::remove_dir_all(&root).expect("cleanup");
}

/// NEGATIVE: `.gran*` is an ordinary file APFS will create;
/// the frozen name format reserves the byte prefix and
/// `BadName` must surface it, not skip it.
#[test]
fn dot_gran_prefix_is_refused_as_bad_name() {
    let root = scratch("badname");
    fs::write(root.join(".granary"), b"x").expect("write");
    let err = load(&root).expect_err(".gran-prefixed name must be refused");
    match err {
        CorpusError::BadName { source, .. } => {
            assert_eq!(source, NameError::GranPrefix, "{source}");
        }
        other => panic!("expected BadName, got: {other}"),
    }
    fs::remove_dir_all(&root).expect("cleanup");
}

/// NEGATIVE: `symlink("", path)` is accepted by APFS;
/// `readlink` reads back zero bytes, which the frozen target
/// format rejects (empty is invalid, not merely over-long).
///
/// **macOS only, and the reason is the fixture, not the behaviour.** Linux
/// refuses to create the input at all: `symlink("")` returns `ENOENT` (`Os
/// { code: 2, kind: NotFound }`), so the bad state this test drives
/// through `load` is unconstructible there.
///
/// The refusal itself stays covered on every platform: the validator
/// arm is pinned by `granary-core`'s own
/// `SymlinkTarget::new(vec![]) == Err(SymlinkTargetError::Empty)`
/// (`manifest/name.rs`), and this test adds only the end-to-end
/// mapping from a real on-disk symlink to `CorpusError::BadTarget`.
/// On Linux the kernel enforces the same invariant one layer earlier,
/// so there is no gap — only a fixture that cannot exist.
#[cfg(target_os = "macos")]
#[test]
fn empty_symlink_target_is_refused_as_bad_target() {
    let root = scratch("badtarget");
    symlink("", root.join("void")).expect("symlink with empty target");
    let err = load(&root).expect_err("empty symlink target must be refused");
    match err {
        CorpusError::BadTarget { source, .. } => {
            assert_eq!(source, SymlinkTargetError::Empty, "{source}");
        }
        other => panic!("expected BadTarget, got: {other}"),
    }
    fs::remove_dir_all(&root).expect("cleanup");
}

/// NEGATIVE: an unreadable directory is refused, not
/// silently treated as empty. `chmod 000` does not block root (or
/// any process with permission-override privileges), so this
/// probes the very syscall the walker uses (`fs::read_dir`)
/// before asserting anything, and skips — rather than asserts —
/// if the probe itself succeeds. That keeps the test honest under
/// a root CI runner instead of asserting a refusal the
/// environment cannot produce.
#[test]
fn unreadable_directory_is_refused_as_io() {
    let root = scratch("unreadable");
    let locked = root.join("locked");
    fs::create_dir(&locked).expect("mkdir");
    fs::write(locked.join("secret"), b"x").expect("write");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");

    if fs::read_dir(&locked).is_ok() {
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("restore");
        fs::remove_dir_all(&root).expect("cleanup");
        eprintln!(
            "unreadable_directory_is_refused_as_io: skipped — read_dir \
             succeeded despite chmod 000, so this process can bypass \
             permissions (root or equivalent); the refusal path cannot \
             be exercised here"
        );
        return;
    }

    let err = load(&root).expect_err("an unreadable directory must be refused");
    assert!(matches!(err, CorpusError::Io { .. }), "{err}");

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("restore");
    fs::remove_dir_all(&root).expect("cleanup");
}

/// A leading `.` is not by itself a reason to skip; only the
/// format's own rules (the reserved `.gran` prefix) refuse a name.
#[test]
fn dotfiles_are_walked_not_skipped() {
    let root = scratch("dotfile");
    fs::write(root.join(".hidden"), b"secret").expect("write");
    fs::write(root.join("visible"), b"public").expect("write");
    let c = load(&root).expect("load");
    let names: Vec<String> = c
        .nodes
        .iter()
        .map(|n| String::from_utf8_lossy(n.components.last().unwrap().as_bytes()).into_owned())
        .collect();
    assert!(names.contains(&".hidden".to_string()), "{names:?}");
    assert_eq!(c.file_count, 2, "both files, dotfile included");
    fs::remove_dir_all(&root).expect("cleanup");
}

/// NEGATIVE: refusal is not depth-1-only — the fifo here is
/// nested two levels down.
#[test]
fn unsupported_types_are_refused_at_any_depth() {
    let root = scratch("deepfifo");
    fs::create_dir_all(root.join("a/b")).expect("mkdir");
    let fifo = root.join("a/b/pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed");
    let err = load(&root).expect_err("nested fifo must be refused");
    assert!(matches!(err, CorpusError::Unsupported { .. }), "{err}");
    fs::remove_dir_all(&root).expect("cleanup");
}

/// Group-only and other-only exec bits, neither of which the
/// owner bit alone (`0o100`) would catch.
#[test]
fn exec_bit_is_set_by_any_of_the_three_bits() {
    let root = scratch("execbits");
    fs::write(root.join("group_only"), b"g").expect("write");
    fs::set_permissions(root.join("group_only"), fs::Permissions::from_mode(0o610)).expect("chmod");
    fs::write(root.join("other_only"), b"o").expect("write");
    fs::set_permissions(root.join("other_only"), fs::Permissions::from_mode(0o601)).expect("chmod");
    let c = load(&root).expect("load");
    for name in ["group_only", "other_only"] {
        let node = c
            .nodes
            .iter()
            .find(|n| n.components.last().map(Name::as_bytes) == Some(name.as_bytes()))
            .unwrap_or_else(|| panic!("{name} node"));
        assert!(
            matches!(node.kind, NodeKind::File { exec: true, .. }),
            "{name}: expected exec=true, got {:?}",
            node.kind
        );
    }
    fs::remove_dir_all(&root).expect("cleanup");
}

/// The target bytes, not merely the `Symlink` variant, reach the manifest
/// measurement.
#[test]
fn symlink_target_bytes_are_recorded_exactly() {
    let root = scratch("symtarget");
    fs::write(root.join("real"), b"content").expect("write");
    symlink("real", root.join("link")).expect("symlink");
    let c = load(&root).expect("load");
    let link = c
        .nodes
        .iter()
        .find(|n| n.components.last().map(Name::as_bytes) == Some(b"link".as_slice()))
        .expect("link node");
    match &link.kind {
        NodeKind::Symlink { target } => assert_eq!(target.as_bytes(), b"real"),
        other => panic!("expected Symlink, got {other:?}"),
    }
    fs::remove_dir_all(&root).expect("cleanup");
}

/// Pins `file_bytes` and every file node's `len` to exact
/// values, not merely nonzero ones. A zero-byte file
/// pins "exclude zero-byte files" and an off-by-one on
/// `file_count` too.
#[test]
fn file_bytes_file_count_and_node_len_are_pinned() {
    let root = scratch("bytecounts");
    fs::write(root.join("a"), b"12345").expect("write");
    fs::write(root.join("b"), b"12").expect("write");
    fs::write(root.join("empty"), b"").expect("write");
    let c = load(&root).expect("load");
    assert_eq!(
        c.file_count, 3,
        "three regular files, the zero-byte one included"
    );
    assert_eq!(c.file_bytes, 7, "5 + 2 + 0");
    let mut lens: Vec<(String, u64)> = c
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::File { len, .. } => Some((
                String::from_utf8_lossy(n.components.last().unwrap().as_bytes()).into_owned(),
                *len,
            )),
            NodeKind::Symlink { .. } | NodeKind::EmptyDir => None,
        })
        .collect();
    lens.sort();
    assert_eq!(
        lens,
        vec![
            ("a".to_string(), 5),
            ("b".to_string(), 2),
            ("empty".to_string(), 0),
        ]
    );
    fs::remove_dir_all(&root).expect("cleanup");
}

/// Created in reverse-sorted order, with enough entries that
/// this volume's `read_dir` returning them in creation or hash
/// order — not sorted order — is not something this test could
/// pass by luck (confirmed empirically: raw `read_dir` order for
/// ten single-letter names created in reverse is neither creation
/// order nor sorted order on this volume). Deleting
/// `names.sort_unstable()` in `walk` must turn this test red on
/// its own, independent of `exec_bit_is_set_by_any_of_the_three_bits`'s
/// incidental catch.
///
/// Not attempted here: a memcmp-vs-UTF-8-collation distinction.
/// APFS refuses invalid UTF-8 filenames ("Illegal byte sequence"),
/// and Rust's `str` ordering on valid UTF-8 IS byte-lexicographic,
/// so `to_string_lossy` order is memcmp order on this platform —
/// a proven equivalent mutant, not a coverage gap.
#[test]
fn walk_order_defeats_unsorted_read_dir() {
    let root = scratch("orderstrong");
    let created = ["j", "i", "h", "g", "f", "e", "d", "c", "b", "a"];
    for n in created {
        fs::write(root.join(n), b"x").expect("write");
    }
    let c = load(&root).expect("load");
    let got: Vec<String> = c
        .nodes
        .iter()
        .map(|n| String::from_utf8_lossy(n.components.last().unwrap().as_bytes()).into_owned())
        .collect();
    let mut expected: Vec<String> = created.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    assert_eq!(got, expected);
    fs::remove_dir_all(&root).expect("cleanup");
}

/// A one-node corpus (`empty_directories_are_nodes`) cannot
/// show an empty dir's position among siblings; this one sorts an
/// empty dir between two files.
#[test]
fn empty_dir_position_is_preserved_among_siblings() {
    let root = scratch("emptydirpos");
    fs::create_dir(root.join("m_empty")).expect("mkdir");
    fs::write(root.join("a_file"), b"x").expect("write");
    fs::write(root.join("z_file"), b"y").expect("write");
    let c = load(&root).expect("load");
    let names: Vec<String> = c
        .nodes
        .iter()
        .map(|n| String::from_utf8_lossy(n.components.last().unwrap().as_bytes()).into_owned())
        .collect();
    assert_eq!(names, vec!["a_file", "m_empty", "z_file"]);
    fs::remove_dir_all(&root).expect("cleanup");
}

/// `path_of` and `read` are both on the measurement's hot path (`corpus.read(node)`); a
/// wrong `path_of` reads the wrong file's bytes into the dedup
/// measurement.
#[test]
fn path_of_and_read_round_trip_the_right_file() {
    let root = scratch("pathread");
    fs::create_dir(root.join("sub")).expect("mkdir");
    fs::write(root.join("sub/leaf.txt"), b"payload-bytes").expect("write");
    let c = load(&root).expect("load");
    let node = c
        .nodes
        .iter()
        .find(|n| n.components.last().map(Name::as_bytes) == Some(b"leaf.txt".as_slice()))
        .expect("leaf node");
    assert_eq!(c.path_of(node), root.join("sub").join("leaf.txt"));
    assert_eq!(c.read(node).expect("read"), b"payload-bytes");
    fs::remove_dir_all(&root).expect("cleanup");
}

/// NEGATIVE: sockets are constructible without root, unlike
/// device nodes, and must be refused the same as fifos.
#[test]
fn sockets_are_refused_same_as_fifos() {
    let root = scratch("socket");
    let sock_path = root.join("sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind unix socket");
    let err = load(&root).expect_err("socket must be refused");
    assert!(matches!(err, CorpusError::Unsupported { .. }), "{err}");
    drop(listener);
    fs::remove_dir_all(&root).expect("cleanup");
}

/// Counting each hard link as its own file is correct for a
/// tree-shaped corpus; pinned so an inode-dedup "optimization" cannot shrink one invisibly.
#[test]
fn hardlinks_are_each_counted_as_separate_files() {
    let root = scratch("hardlink");
    fs::write(root.join("first"), b"shared").expect("write");
    fs::hard_link(root.join("first"), root.join("second")).expect("hardlink");
    let c = load(&root).expect("load");
    assert_eq!(
        c.file_count, 2,
        "a tree-shaped corpus counts hardlinks twice"
    );
    assert_eq!(c.file_bytes, 12, "6 bytes, twice");
    fs::remove_dir_all(&root).expect("cleanup");
}
