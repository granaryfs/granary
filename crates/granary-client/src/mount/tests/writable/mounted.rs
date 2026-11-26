// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Real syscall, live-state and captured-record pairs on admitted mounts.

use super::*;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::FileExt as _;
use std::process::Command;

mod indexed;
mod sync;

fn journal_path(paths: &Paths, input: &WritableStart<'_>) -> std::path::PathBuf {
    paths
        .store
        .join("overlay")
        .join(input.scope.as_ref().unwrap().digest().unwrap())
        .join(input.volume.as_str())
        .join("journal")
}

fn names(root: &Path) -> Vec<std::ffi::OsString> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    names
}

/// Python supplies syscall drivers absent from the client's safe Rust interfaces.
/// Arguments are separate argv elements; request names never become shell code.
fn python(root: &Path, script: &str) -> io::Result<Vec<u8>> {
    let output = Command::new("python3").arg("-c").arg(format!(
        "import os,sys,stat,ctypes\nr=sys.argv[1]\ntry:\n{}\nexcept OSError as e:\n print(e.errno)\n sys.exit(1)\n", 
        script.lines().map(|line| format!(" {line}")).collect::<Vec<_>>().join("\n")
    )).arg(root).output()?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let text = String::from_utf8_lossy(&output.stdout);
        let errno = text.trim().parse::<i32>().unwrap_or_else(|_| {
            panic!(
                "syscall driver failed: status={:?}, stdout={text}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
        Err(io::Error::from_raw_os_error(errno))
    }
}

fn refused<T: std::fmt::Debug>(result: io::Result<T>, errno: i32, case: &str) {
    assert_eq!(
        result.as_ref().err().and_then(io::Error::raw_os_error),
        Some(errno),
        "{case}: {result:?}"
    );
    drop(result);
}

fn pair(case: &str, drive: fn(&Path, bool) -> Vec<&'static str>) {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("SKIPPED-NO-DEV-FUSE {case}");
        return;
    }
    let tree = mounted_operation_tree();
    let mut cases = 0;
    for writable in [true, false] {
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let journal = journal_path(&paths, &input);
        let (mut mount, before, state) =
            mount_refusal_pair(&tree, &paths, &input, &journal, writable);
        let initial_names = names(&paths.mountpoint);
        let attrs = std::fs::metadata(paths.mountpoint.join("f.txt")).unwrap();
        assert_eq!(
            (attrs.uid(), attrs.gid()),
            (input.policy.uid, input.policy.gid)
        );
        let initial = before.as_ref().map(|bytes| {
            assert_eq!(
                &std::fs::read(&journal).unwrap(),
                bytes,
                "readiness probes captured an operation"
            );
            captured_records(&paths, &input).1.len()
        });
        let expected = drive(&paths.mountpoint, writable);
        assert_eq!(attrs.mode() & 0o777, if writable { 0o644 } else { 0o444 });
        if !writable {
            assert_eq!(
                names(&paths.mountpoint),
                initial_names,
                "RO namespace changed: {case}"
            );
            assert_eq!(
                std::fs::read(paths.mountpoint.join("f.txt")).unwrap(),
                FILE_CONTENT
            );
            assert_eq!(
                std::fs::read(paths.mountpoint.join("sub/g.txt")).unwrap(),
                FILE_CONTENT
            );
        }
        mount.finish().unwrap();
        if let Some(before) = before {
            let (_, records) = captured_records(&paths, &input);
            assert_eq!(
                capture_kinds(&records[initial.unwrap()..]),
                expected,
                "wrong or missing capture: {case}"
            );
            if expected.is_empty() {
                assert_eq!(
                    std::fs::read(&journal).unwrap(),
                    before,
                    "refusal/no-op captured: {case}"
                );
            }
            assert_eq!(
                state.lock().unwrap().calls[3],
                0,
                "ordinary operations uploaded: {case}"
            );
        } else {
            assert!(!journal.exists());
            assert_eq!(
                state.lock().unwrap().calls,
                [0; 4],
                "RO mediator dispatch: {case}"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2, "both admitted policies must execute: {case}");
}

fn creation(root: &Path, writable: bool) -> Vec<&'static str> {
    let new = root.join("new");
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&new);
    if !writable {
        refused(result, 30, "create RO");
        return vec![];
    }
    let file = result.unwrap();
    assert_eq!(
        (
            file.metadata().unwrap().mode() & 0o777,
            file.metadata().unwrap().len()
        ),
        (0o644, 0)
    );
    drop(file);
    assert_eq!(std::fs::read(&new).unwrap(), b"");
    assert!(names(root).contains(&"new".into()));
    vec!["file"]
}

fn regular_node(root: &Path, writable: bool) -> Vec<&'static str> {
    let result = python(root, "os.mknod(r+'/new', stat.S_IFREG|0o644)");
    if !writable {
        refused(result, 30, "regular mknod RO");
        return vec![];
    }
    result.unwrap();
    assert_eq!(
        (
            std::fs::metadata(root.join("new")).unwrap().mode() & 0o777,
            std::fs::read(root.join("new")).unwrap()
        ),
        (0o644, vec![])
    );
    vec!["file"]
}

fn directories(root: &Path, writable: bool) -> Vec<&'static str> {
    let new = root.join("new");
    let result = std::fs::create_dir(&new);
    if !writable {
        refused(result, 30, "mkdir RO");
        refused(
            std::fs::remove_dir(root.join("empty")),
            30,
            "empty rmdir RO",
        );
        refused(std::fs::remove_dir(root.join("sub")), 30, "rmdir RO");
        return vec![];
    }
    result.unwrap();
    std::fs::remove_dir(root.join("empty")).unwrap();
    assert_eq!(std::fs::metadata(&new).unwrap().mode() & 0o777, 0o755);
    refused(std::fs::remove_dir(root.join("sub")), 39, "nonempty rmdir");
    assert_eq!(std::fs::read(root.join("sub/g.txt")).unwrap(), FILE_CONTENT);
    std::fs::remove_dir(&new).unwrap();
    assert!(!new.exists());
    vec!["directory", "rmdir", "rmdir"]
}

fn symlinks(root: &Path, writable: bool) -> Vec<&'static str> {
    let new = root.join("new");
    let result = std::os::unix::fs::symlink("f.txt", &new);
    if !writable {
        refused(result, 30, "symlink RO");
        refused(
            std::fs::remove_file(root.join("original-link")),
            30,
            "symlink unlink RO",
        );
        return vec![];
    }
    result.unwrap();
    let attrs = std::fs::symlink_metadata(&new).unwrap();
    assert_eq!(
        (
            attrs.mode() & 0o777,
            attrs.len(),
            std::fs::read_link(&new).unwrap()
        ),
        (0o777, 5, std::path::PathBuf::from("f.txt"))
    );
    assert_eq!(std::fs::read(&new).unwrap(), FILE_CONTENT);
    std::fs::remove_file(&new).unwrap();
    std::fs::remove_file(root.join("original-link")).unwrap();
    assert!(std::fs::symlink_metadata(&new).is_err());
    vec!["symlink", "unlink", "unlink"]
}

fn writes(root: &Path, writable: bool) -> Vec<&'static str> {
    let path = root.join("f.txt");
    let result = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path);
    if !writable {
        refused(result, 30, "write-open RO");
        refused(
            std::fs::OpenOptions::new().append(true).open(&path),
            30,
            "append-open RO",
        );
        return vec![];
    }
    let first = result.unwrap_or_else(|error| {
        panic!("owner-matching ordinary write-open must succeed: {error:?}")
    });
    let second = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    first.write_all_at(b"Z", 1).unwrap();
    second.write_all_at(b"Y", 2).unwrap();
    let mut append = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    append.write_all(b"!").unwrap();
    let mut expected = FILE_CONTENT.to_vec();
    expected[1] = b'Z';
    expected[2] = b'Y';
    expected.push(b'!');
    let mut held = vec![0; expected.len()];
    first.read_exact_at(&mut held, 0).unwrap();
    assert_eq!(
        (std::fs::read(path).unwrap(), held),
        (expected.clone(), expected)
    );
    vec!["bind", "write", "write", "write"]
}

fn sizes(root: &Path, writable: bool) -> Vec<&'static str> {
    let path = root.join("f.txt");
    let result = std::fs::OpenOptions::new().write(true).open(&path);
    if !writable {
        refused(result, 30, "size writable descriptor RO");
        refused(
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path),
            30,
            "O_TRUNC RO",
        );
        refused(
            python(root, "os.truncate(r+'/f.txt',2)"),
            30,
            "path truncate RO",
        );
        return vec![];
    }
    let file = result.unwrap();
    file.set_len(2).unwrap();
    file.set_len(6).unwrap();
    assert_eq!(
        (
            file.metadata().unwrap().len(),
            std::fs::read(&path).unwrap()
        ),
        (6, vec![FILE_CONTENT[0], FILE_CONTENT[1], 0, 0, 0, 0])
    );
    python(root, "os.truncate(r+'/f.txt',1)").unwrap();
    let truncated = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    assert_eq!(
        (
            truncated.metadata().unwrap().len(),
            std::fs::read(&path).unwrap()
        ),
        (0, vec![])
    );
    vec!["bind", "truncate", "truncate", "truncate", "truncate"]
}

fn orphans(root: &Path, writable: bool) -> Vec<&'static str> {
    let path = root.join("f.txt");
    let mut held = std::fs::File::open(&path).unwrap();
    let old = held.metadata().unwrap().ino();
    let result = std::fs::remove_file(&path);
    if !writable {
        refused(result, 30, "unlink RO");
        return vec![];
    }
    result.unwrap();
    assert!(!path.exists());
    let replacement = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    assert_ne!(replacement.metadata().unwrap().ino(), old);
    let mut bytes = Vec::new();
    held.read_to_end(&mut bytes).unwrap();
    assert_eq!(
        (
            held.metadata().unwrap().ino(),
            bytes,
            std::fs::read(&path).unwrap()
        ),
        (old, FILE_CONTENT.to_vec(), vec![])
    );
    drop(held);
    drop(replacement);
    vec!["bind", "unlink", "file"]
}

fn dirty_orphans(root: &Path, writable: bool) -> Vec<&'static str> {
    let path = root.join("f.txt");
    let result = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path);
    if !writable {
        refused(result, 30, "dirty orphan write-open RO");
        refused(std::fs::remove_file(&path), 30, "dirty orphan unlink RO");
        return vec![];
    }
    let mut held = result.unwrap();
    held.write_all_at(b"Z", 0).unwrap();
    let old = held.metadata().unwrap().ino();
    std::fs::remove_file(&path).unwrap();
    held.set_len(2).unwrap();
    held.write_all_at(b"!", 2).unwrap();
    let replacement = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    assert_ne!(replacement.metadata().unwrap().ino(), old);
    python(root, "fd=os.open(r+'/f.txt',os.O_RDONLY)\nos.close(fd)").unwrap();
    held.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    held.read_to_end(&mut bytes).unwrap();
    assert_eq!(
        (bytes, std::fs::read(&path).unwrap()),
        (vec![b'Z', FILE_CONTENT[1], b'!'], vec![])
    );
    vec!["bind", "write", "unlink", "truncate", "write", "file"]
}

fn renames(root: &Path, writable: bool) -> Vec<&'static str> {
    let file = root.join("f.txt");
    let new = root.join("new");
    let held = std::fs::File::open(&file).unwrap();
    let old = held.metadata().unwrap().ino();
    let result = std::fs::rename(&file, &new);
    if !writable {
        refused(result, 30, "rename RO");
        refused(std::fs::rename(&file, &file), 30, "same-path rename RO");
        refused(
            std::fs::rename(root.join("sub"), &new),
            30,
            "subtree rename RO",
        );
        return vec![];
    }
    result.unwrap();
    assert!(!file.exists());
    assert_eq!(
        (
            std::fs::metadata(&new).unwrap().ino(),
            std::fs::read(&new).unwrap()
        ),
        (old, FILE_CONTENT.to_vec())
    );
    std::fs::rename(&new, &new).unwrap();
    refused(std::fs::rename(&file, &file), 2, "missing same-path rename");
    let child = std::fs::File::open(root.join("sub/g.txt")).unwrap();
    let child_ino = child.metadata().unwrap().ino();
    std::fs::rename(root.join("sub"), root.join("moved")).unwrap();
    assert_eq!(
        std::fs::metadata(root.join("moved/g.txt")).unwrap().ino(),
        child_ino
    );
    assert_eq!(
        std::fs::read(root.join("moved/g.txt")).unwrap(),
        FILE_CONTENT
    );
    vec!["move", "move"]
}

fn replacement(root: &Path, writable: bool) -> Vec<&'static str> {
    let target = root.join("sub/g.txt");
    let mut held = std::fs::File::open(&target).unwrap();
    let old = held.metadata().unwrap().ino();
    let source = std::fs::metadata(root.join("f.txt")).unwrap().ino();
    let result = std::fs::rename(root.join("f.txt"), &target);
    if !writable {
        refused(result, 30, "replace RO");
        return vec![];
    }
    result.unwrap();
    let mut bytes = Vec::new();
    held.read_to_end(&mut bytes).unwrap();
    assert_eq!(
        (
            std::fs::metadata(&target).unwrap().ino(),
            held.metadata().unwrap().ino(),
            bytes
        ),
        (source, old, FILE_CONTENT.to_vec())
    );
    assert_ne!(source, old, "equal content must have distinct identity");
    assert!(!root.join("f.txt").exists());
    vec!["bind", "replace"]
}

fn exec_modes(root: &Path, writable: bool) -> Vec<&'static str> {
    let file = root.join("f.txt");
    if !writable {
        for mode in [0o755, 0o644] {
            refused(
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)),
                30,
                "exec chmod RO",
            );
        }
        return vec![];
    }
    for mode in [0o755, 0o755, 0o644] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, mode);
        assert!(names(root).contains(&"f.txt".into()));
    }
    vec!["exec", "exec"]
}

#[test]
fn writable_linux_create_state_capture_and_ro_pair() {
    pair(
        stringify!(writable_linux_create_state_capture_and_ro_pair),
        creation,
    );
}

#[test]
fn writable_linux_regular_mknod_state_capture_and_ro_pair() {
    pair(
        stringify!(writable_linux_regular_mknod_state_capture_and_ro_pair),
        regular_node,
    );
}

#[test]
fn writable_linux_mkdir_rmdir_state_capture_and_ro_pairs() {
    pair(
        stringify!(writable_linux_mkdir_rmdir_state_capture_and_ro_pairs),
        directories,
    );
}

#[test]
fn writable_linux_symlink_unlink_state_capture_and_ro_pairs() {
    pair(
        stringify!(writable_linux_symlink_unlink_state_capture_and_ro_pairs),
        symlinks,
    );
}

#[test]
fn writable_linux_clean_dirty_append_shared_handles_and_ro_pairs() {
    pair(
        stringify!(writable_linux_clean_dirty_append_shared_handles_and_ro_pairs),
        writes,
    );
}

#[test]
fn writable_linux_dense_sizes_and_open_truncate_capture_and_ro_pairs() {
    pair(
        stringify!(writable_linux_dense_sizes_and_open_truncate_capture_and_ro_pairs),
        sizes,
    );
}

#[test]
fn writable_linux_clean_unlink_recreate_identity_and_ro_pair() {
    pair(
        stringify!(writable_linux_clean_unlink_recreate_identity_and_ro_pair),
        orphans,
    );
}

#[test]
fn writable_linux_dirty_orphan_write_truncate_and_ro_pairs() {
    pair(
        stringify!(writable_linux_dirty_orphan_write_truncate_and_ro_pairs),
        dirty_orphans,
    );
}

#[test]
fn writable_linux_rename_subtree_same_path_identity_and_ro_pairs() {
    pair(
        stringify!(writable_linux_rename_subtree_same_path_identity_and_ro_pairs),
        renames,
    );
}

#[test]
fn writable_linux_replace_held_target_identity_and_ro_pair() {
    pair(
        stringify!(writable_linux_replace_held_target_identity_and_ro_pair),
        replacement,
    );
}

#[test]
fn writable_linux_exec_modes_capture_noop_and_ro_pairs() {
    pair(
        stringify!(writable_linux_exec_modes_capture_noop_and_ro_pairs),
        exec_modes,
    );
}

#[test]
fn writable_linux_remaining_refusals_preserve_state_and_ro_pairs() {
    pair(
        stringify!(writable_linux_remaining_refusals_preserve_state_and_ro_pairs),
        refusals,
    );
}

#[test]
fn writable_linux_detached_chmod_noop_and_refusal_ro_pairs() {
    pair(
        stringify!(writable_linux_detached_chmod_noop_and_refusal_ro_pairs),
        detached_modes,
    );
}

#[test]
fn writable_linux_rename_noreplace_and_flags_state_ro_pairs() {
    pair(
        stringify!(writable_linux_rename_noreplace_and_flags_state_ro_pairs),
        rename_flags,
    );
}

#[test]
fn writable_linux_dense_gap_and_cap_refusal_ro_pairs() {
    pair(
        stringify!(writable_linux_dense_gap_and_cap_refusal_ro_pairs),
        gap_and_cap,
    );
}

fn refusals(root: &Path, writable: bool) -> Vec<&'static str> {
    let mut cases = 0;
    for script in [
        "os.link(r+'/f.txt',r+'/new')",
        "os.chmod(r+'/f.txt',0o600)",
        "os.chmod(r+'/f.txt',0o700)",
        "os.chown(r+'/f.txt',os.geteuid(),os.getegid())",
        "os.utime(r+'/f.txt',None)",
        "os.utime(r+'/f.txt',ns=(1000000000,2000000000))",
        "s=os.stat(r+'/f.txt')\nos.utime(r+'/f.txt',ns=(s.st_atime_ns,s.st_mtime_ns))",
        "os.setxattr(r+'/f.txt','user.x',b'v',os.XATTR_CREATE)",
        "os.removexattr(r+'/f.txt','user.x')",
        "os.mknod(r+'/new',stat.S_IFIFO|0o644)",
        "os.mknod(r+'/new',stat.S_IFSOCK|0o644)",
    ] {
        refused(python(root, script), if writable { 95 } else { 30 }, script);
        cases += 1;
    }
    for kind in ["stat.S_IFBLK", "stat.S_IFCHR"] {
        let script = format!("os.mknod(r+'/new',{kind}|0o644,os.makedev(1,3))");
        let expected = if writable {
            if input_uid_is_root() { 95 } else { 1 }
        } else {
            30
        };
        refused(python(root, &script), expected, &script);
        cases += 1;
    }
    if writable {
        for script in [
            "os.getxattr(r+'/f.txt','user.x')",
            "os.listxattr(r+'/f.txt')",
        ] {
            refused(python(root, script), 95, script);
            cases += 1;
        }
        for mode in [0, 1, 3, 8, 16, 32, 64] {
            let script = format!(
                "fd=os.open(r+'/f.txt',os.O_RDWR)\nc=ctypes.CDLL(None,use_errno=True)\nx=c.fallocate(fd,{mode},ctypes.c_longlong(0),ctypes.c_longlong(4096))\nif x: raise OSError(ctypes.get_errno(),'fallocate')\nos.close(fd)"
            );
            refused(python(root, &script), 95, "fallocate");
            cases += 1;
        }
    } else {
        refused(
            std::fs::OpenOptions::new()
                .write(true)
                .open(root.join("f.txt")),
            30,
            "fallocate write-open RO",
        );
        for mode in [0, 1, 3, 8, 16, 32, 64] {
            let script = format!(
                "fd=os.open(r+'/f.txt',os.O_RDONLY)\nc=ctypes.CDLL(None,use_errno=True)\nx=c.fallocate(fd,{mode},ctypes.c_longlong(0),ctypes.c_longlong(4096))\nif x: raise OSError(ctypes.get_errno(),'fallocate')\nos.close(fd)"
            );
            refused(
                python(root, &script),
                9,
                "fallocate RO read descriptor precedence",
            );
            cases += 1;
        }
    }
    assert_eq!(cases, if writable { 22 } else { 20 });
    assert!(!root.join("new").exists());
    assert_eq!(
        std::fs::metadata(root.join("f.txt")).unwrap().mode() & 0o777,
        if writable { 0o644 } else { 0o444 }
    );
    assert_eq!(std::fs::read(root.join("f.txt")).unwrap(), FILE_CONTENT);
    vec![]
}

fn input_uid_is_root() -> bool {
    // Scratch is created by this caller, so ownership measures the real actor.
    Paths::new().scratch.metadata().unwrap().uid() == 0
}

fn detached_modes(root: &Path, writable: bool) -> Vec<&'static str> {
    let path = root.join("f.txt");
    let held = std::fs::File::open(&path).unwrap();
    if !writable {
        refused(
            held.set_permissions(std::fs::Permissions::from_mode(0o755)),
            30,
            "fchmod exec RO",
        );
        refused(
            held.set_permissions(std::fs::Permissions::from_mode(0o444)),
            30,
            "fchmod canonical RO",
        );
        refused(std::fs::remove_file(&path), 30, "detach RO");
        return vec![];
    }
    std::fs::remove_file(&path).unwrap();
    let replacement = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    refused(
        held.set_permissions(std::fs::Permissions::from_mode(0o755)),
        95,
        "detached exec must not retarget",
    );
    held.set_permissions(std::fs::Permissions::from_mode(0o644))
        .unwrap();
    assert_eq!(
        (
            held.metadata().unwrap().mode() & 0o777,
            replacement.metadata().unwrap().mode() & 0o777
        ),
        (0o644, 0o644)
    );
    vec!["bind", "unlink", "file"]
}

fn rename_call(root: &Path, from: &str, to: &str, flags: u32) -> io::Result<Vec<u8>> {
    python(
        root,
        &format!(
            "c=ctypes.CDLL(None,use_errno=True)\nx=c.renameat2(-100,os.fsencode(r+'/{from}'),-100,os.fsencode(r+'/{to}'),{flags})\nif x: raise OSError(ctypes.get_errno(),'renameat2')"
        ),
    )
}

fn rename_flags(root: &Path, writable: bool) -> Vec<&'static str> {
    for _ in 0..2 {
        refused(
            rename_call(root, "f.txt", "sub/g.txt", 1),
            if writable { 17 } else { 30 },
            "NOREPLACE existing target",
        );
    }
    for flags in [2, 4] {
        let expected = if writable { 95 } else { 30 };
        refused(
            rename_call(root, "f.txt", "sub/g.txt", flags),
            expected,
            "unsupported rename flag",
        );
    }
    for flags in [3, 8] {
        refused(
            rename_call(root, "f.txt", "sub/g.txt", flags),
            22,
            "kernel invalid flag precedence",
        );
    }
    if !writable {
        refused(rename_call(root, "f.txt", "new", 1), 30, "NOREPLACE new RO");
        return vec![];
    }
    let ino = std::fs::metadata(root.join("f.txt")).unwrap().ino();
    rename_call(root, "f.txt", "new", 1).unwrap();
    rename_call(root, "new", "f.txt", 1).unwrap();
    assert_eq!(std::fs::metadata(root.join("f.txt")).unwrap().ino(), ino);
    assert_eq!(std::fs::read(root.join("sub/g.txt")).unwrap(), FILE_CONTENT);
    vec!["move", "move"]
}

fn gap_and_cap(root: &Path, writable: bool) -> Vec<&'static str> {
    let path = root.join("f.txt");
    let result = std::fs::OpenOptions::new().write(true).open(&path);
    if !writable {
        refused(result, 30, "gap write-open RO");
        refused(
            python(root, "os.truncate(r+'/f.txt',134217728)"),
            30,
            "cap size RO",
        );
        return vec![];
    }
    let held = result.unwrap();
    held.write_all_at(b"!", 128).unwrap();
    let mut expected = FILE_CONTENT.to_vec();
    expected.resize(128, 0);
    expected.push(b'!');
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    refused(
        held.set_len(134_217_728),
        28,
        "cap extension must be ENOSPC",
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        expected,
        "refused extent altered accepted prefix"
    );
    vec!["bind", "write"]
}

fn statfs(root: &Path) -> Vec<u64> {
    let bytes = python(root, "s=os.statvfs(r)\nprint(s.f_blocks,s.f_bfree,s.f_bavail,s.f_files,s.f_ffree,s.f_frsize,s.f_namemax)").unwrap();
    let values: Vec<_> = std::str::from_utf8(&bytes)
        .unwrap()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    assert_eq!(values.len(), 7);
    values
}

#[test]
fn writable_linux_statfs_live_charge_orphan_and_ro_pair() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("SKIPPED-NO-DEV-FUSE writable_linux_statfs_live_charge_orphan_and_ro_pair");
        return;
    }
    let tree = PublishedTree::publish("v");
    let mut cases = 0;
    for writable in [true, false] {
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let journal = journal_path(&paths, &input);
        let (mut mount, before, state) =
            mount_refusal_pair(&tree, &paths, &input, &journal, writable);
        let initial = statfs(&paths.mountpoint);
        assert_eq!((initial[5], initial[6]), (4096, 255));
        let result = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(paths.mountpoint.join("new"));
        if writable {
            assert_eq!(initial[0], 32768);
            assert_eq!(
                (initial[1] > 0, initial[1], initial[3]),
                (true, initial[2], 2)
            );
            let held = result.unwrap();
            held.set_len(65536).unwrap();
            let grown = statfs(&paths.mountpoint);
            assert_eq!(
                (
                    grown[0],
                    grown[3],
                    grown[1] < initial[1],
                    grown[4] <= initial[4]
                ),
                (32768, 3, true, true)
            );
            std::fs::remove_file(paths.mountpoint.join("new")).unwrap();
            let orphan = statfs(&paths.mountpoint);
            assert_eq!((orphan[3], orphan[1] <= grown[1]), (2, true));
            drop(held);
            let closed = statfs(&paths.mountpoint);
            assert_eq!(
                (closed[3], closed[1] <= orphan[1]),
                (2, true),
                "last close cannot free retained evidence"
            );
        } else {
            refused(result, 30, "statfs growth RO");
            assert_eq!((initial[1], initial[2], initial[4]), (0, 0, 0));
            assert_eq!(statfs(&paths.mountpoint), initial);
        }
        mount.finish().unwrap();
        if before.is_none() {
            assert!(!journal.exists());
            assert_eq!(state.lock().unwrap().calls, [0; 4]);
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_owner_matching_nonroot_dac_write_and_chmod() {
    use std::os::unix::process::CommandExt as _;
    if !Path::new("/dev/fuse").exists() {
        eprintln!("SKIPPED-NO-DEV-FUSE writable_linux_owner_matching_nonroot_dac_write_and_chmod");
        return;
    }
    if std::env::var_os("GRANARY_DAC_CHILD").is_some() || !input_uid_is_root() {
        assert!(
            !input_uid_is_root(),
            "DAC witness must execute without root override"
        );
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert_eq!(writable_dac_permissions(&status), Ok(()));
        pair("nonroot write", writes);
        pair("nonroot chmod", exec_modes);
        return;
    }
    let (base, home) = dac_child_paths();
    std::fs::create_dir_all(&base).unwrap();
    // Use the owner of a private workspace ancestor when available. A root-only
    // private ancestor cannot support a nonroot witness beneath this target.
    let (uid, gid) = base
        .ancestors()
        .find_map(|ancestor| {
            let metadata = ancestor.metadata().unwrap();
            (metadata.uid() != 0).then_some((metadata.uid(), metadata.gid()))
        })
        .unwrap_or((65534, 65534));
    assert!(
        dac_chain_traversable(&base, uid, gid),
        "DAC target scratch has a nontraversable ancestor"
    );
    std::fs::create_dir(&home).unwrap();
    let home = ScratchDir(home);
    std::os::unix::fs::chown(&home.0, Some(uid), Some(gid)).unwrap();
    std::fs::set_permissions(&home.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(dac_chain_traversable(&home.0, uid, gid));
    let executable = home.0.join("dac-witness");
    // Link rather than copy: the test binary is hundreds of MiB, and CI's
    // run directory is a 1 GiB tmpfs that already holds one copy of it.
    let current = std::env::current_exe().unwrap();
    if std::fs::hard_link(&current, &executable).is_err() {
        std::fs::copy(&current, &executable).unwrap();
    }
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(&executable)
        .args(["--exact", "mount::tests::writable::mounted::writable_linux_owner_matching_nonroot_dac_write_and_chmod", "--nocapture"])
        .current_dir(&home.0)
        .env("GRANARY_DAC_CHILD", "1").env("HOME", &home.0).uid(uid).gid(gid).output().unwrap();
    assert!(
        output.status.success(),
        "nonroot child: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "child selected no DAC witness"
    );
}

fn current_write_flags(root: &Path, writable: bool) -> Vec<&'static str> {
    let result = python(
        root,
        "import fcntl\np=r+'/f.txt'\nf=os.open(p,os.O_RDWR|os.O_APPEND)\nfcntl.fcntl(f,fcntl.F_SETFL,fcntl.fcntl(f,fcntl.F_GETFL)&~os.O_APPEND)\nos.pwrite(f,b'X',0)\nfcntl.fcntl(f,fcntl.F_SETFL,fcntl.fcntl(f,fcntl.F_GETFL)|os.O_APPEND)\nos.pwrite(f,b'Y',0)\nos.close(f)",
    );
    if !writable {
        refused(result, 30, "current write flags RO");
        return vec![];
    }
    result.unwrap();
    let mut expected = FILE_CONTENT.to_vec();
    expected[0] = b'X';
    expected.push(b'Y');
    assert_eq!(std::fs::read(root.join("f.txt")).unwrap(), expected);
    vec!["bind", "write", "write"]
}
#[test]
fn writable_linux_current_append_and_dsync_refusal_ro_pair() {
    pair(
        "writable_linux_current_append_and_dsync_refusal_ro_pair",
        current_write_flags,
    );
}

#[test]
fn writable_linux_panic_unmounts_and_releases_connection_ro_pair() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!(
            "SKIPPED-NO-DEV-FUSE writable_linux_panic_unmounts_and_releases_connection_ro_pair"
        );
        return;
    }
    let case = "writable_linux_panic_unmounts_and_releases_connection_ro_pair";
    if !session_guard::require_control_fs(case) {
        return;
    }
    let tree = PublishedTree::publish("v");
    for writable in [true, false] {
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let journal = journal_path(&paths, &input);
        let (mount, _, _) = mount_refusal_pair(&tree, &paths, &input, &journal, writable);
        if !abort::require_available(mount.abort_available, case) {
            return;
        }
        assert!(mount.daemon_alive());
        let connection = mount.connection.unwrap();
        assert!(
            crate::overlay_test_support::mount_connection(&paths.mountpoint)
                .unwrap()
                .is_some()
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _mount = mount;
            panic!("exercise mounted client cleanup during unwind");
        }));
        assert!(result.is_err());
        cleanup_wait::assert_gone(Some(connection), "mount", || {
            crate::overlay_test_support::mount_connection(&paths.mountpoint)
                .unwrap()
                .is_none()
        });
        cleanup_wait::assert_gone(Some(connection), "connection directory", || {
            !session_guard::connection_path(connection)
                .try_exists()
                .unwrap()
        });
        assert!(names(&paths.mountpoint).is_empty());
    }
}
