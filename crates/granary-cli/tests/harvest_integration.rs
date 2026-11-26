// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `gran harvest`. What is under test here is the
//! CLI — argument handling, exit codes, the printed stats — so these
//! tests drive the compiled BINARY via
//! `env!("CARGO_BIN_EXE_gran")` + `std::process::Command`, parse its
//! stdout, and validate the resulting store by reading
//! `objects/<2hex>/<64hex>` files directly and feeding
//! `granary_core::manifest::validate_dir_tree` a read-from-disk fetch
//! closure.

#![cfg(unix)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use granary_core::encoding;
use granary_core::hash::GrainId;
use granary_core::manifest::{DirEntry, EntryKind, decode_dir_leaf, validate_dir_tree};

// ------------------------------------------------------------- scratch dir

/// Test-only scratch dir: unique per test, removed on drop. 0444 store
/// object files resist removal of their PARENT on some systems — chmod
/// the tree writable first if the plain remove fails.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
                      hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
                      and nothing else (`granary-harvest-it-<pid>-<counter>` under the temp dir, created and removed \
                      by this fixture), and it is load-bearing for correctness there: the counter beside it is \
                      per-process, and every test binary runs in its own process, so without the pid two concurrent \
                      runs generate the same name and share one directory. It reaches no hashed or signed value, and \
                      nothing this file compares is derived from it: the row asserts a harvested root's shape, which \
                      is content-addressed and carries no path"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-harvest-it-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.0).is_err() {
            make_tree_writable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn make_tree_writable(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o755));
            if path.is_dir() {
                make_tree_writable(&path);
            }
        }
    }
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
}

// ------------------------------------------------------------- fixtures

/// A basic source tree: 2 dirs (`a`, `b`), 3 files (one empty, one
/// exec), 1 symlink.
///
/// ```text
/// <root>/
///   a/
///     file1.txt   ("hello")
///     empty.txt   (0 bytes)
///   b/
///     exec.sh     (0o755, "#!/bin/sh\necho hi\n")
///   link -> a/file1.txt
/// ```
fn write_basic_tree(root: &Path) {
    fs::create_dir_all(root.join("a")).unwrap_or_else(|e| panic!("{e}"));
    fs::create_dir_all(root.join("b")).unwrap_or_else(|e| panic!("{e}"));
    fs::write(root.join("a/file1.txt"), b"hello").unwrap_or_else(|e| panic!("{e}"));
    fs::write(root.join("a/empty.txt"), b"").unwrap_or_else(|e| panic!("{e}"));
    let exec_path = root.join("b/exec.sh");
    fs::write(&exec_path, b"#!/bin/sh\necho hi\n").unwrap_or_else(|e| panic!("{e}"));
    fs::set_permissions(&exec_path, fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink("a/file1.txt", root.join("link")).unwrap_or_else(|e| panic!("{e}"));
}

// ------------------------------------------------------------- binary driver

struct HarvestOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_harvest(source: &Path, store: &Path) -> HarvestOutput {
    let out = Command::new(env!("CARGO_BIN_EXE_gran"))
        .arg("harvest")
        .arg(source)
        .arg(store)
        .output()
        .unwrap_or_else(|e| panic!("spawn gran harvest: {e}"));
    HarvestOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Parsed stdout of a successful `gran harvest` run.
#[derive(Debug)]
struct HarvestReport {
    manifest_root: String,
    dirs: u64,
    files: u64,
    symlinks: u64,
    grains_total: u64,
    grains_novel: u64,
    bytes_total: u64,
    bytes_novel: u64,
    nodes_total: u64,
    nodes_novel: u64,
}

fn parse_report(stdout: &str) -> HarvestReport {
    let mut lines = stdout.lines();
    let root_line = lines
        .next()
        .unwrap_or_else(|| panic!("missing manifest line in stdout: {stdout:?}"));
    let manifest_root = root_line
        .strip_prefix("manifest-root ")
        .unwrap_or_else(|| panic!("malformed manifest line: {root_line:?}"))
        .to_owned();

    let counts_line = lines
        .next()
        .unwrap_or_else(|| panic!("missing dirs/files/symlinks line"));
    // "dirs D files F symlinks S"
    let counts: Vec<&str> = counts_line.split_whitespace().collect();
    let dirs = parse_field(&counts, "dirs", counts_line);
    let files = parse_field(&counts, "files", counts_line);
    let symlinks = parse_field(&counts, "symlinks", counts_line);

    let grains_line = lines
        .next()
        .unwrap_or_else(|| panic!("missing grains/bytes line"));
    // "grains G novel N bytes B novel BN"
    let grain_fields: Vec<&str> = grains_line.split_whitespace().collect();
    let grains_total = parse_field(&grain_fields, "grains", grains_line);
    let grains_novel = parse_nth_field_after(&grain_fields, "novel", 0, grains_line);
    let bytes_total = parse_field(&grain_fields, "bytes", grains_line);
    let bytes_novel = parse_nth_field_after(&grain_fields, "novel", 1, grains_line);

    let nodes_line = lines
        .next()
        .unwrap_or_else(|| panic!("missing manifest nodes line"));
    // "manifest nodes M novel MN"
    let node_fields: Vec<&str> = nodes_line.split_whitespace().collect();
    let nodes_total = parse_field(&node_fields, "nodes", nodes_line);
    let nodes_novel = parse_nth_field_after(&node_fields, "novel", 0, nodes_line);

    HarvestReport {
        manifest_root,
        dirs,
        files,
        symlinks,
        grains_total,
        grains_novel,
        bytes_total,
        bytes_novel,
        nodes_total,
        nodes_novel,
    }
}

fn parse_field(fields: &[&str], label: &str, whole_line: &str) -> u64 {
    let idx = fields
        .iter()
        .position(|&f| f == label)
        .unwrap_or_else(|| panic!("field {label:?} not found in {whole_line:?}"));
    fields
        .get(idx + 1)
        .unwrap_or_else(|| panic!("field {label:?} has no value in {whole_line:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("field {label:?} not a number in {whole_line:?}: {e}"))
}

/// The stats lines repeat the label "novel" twice (grains/bytes); `occurrence`
/// selects the 0-indexed occurrence.
fn parse_nth_field_after(fields: &[&str], label: &str, occurrence: usize, whole_line: &str) -> u64 {
    let idx = fields
        .iter()
        .enumerate()
        .filter(|&(_, &f)| f == label)
        .nth(occurrence)
        .unwrap_or_else(|| {
            panic!("occurrence {occurrence} of {label:?} not found in {whole_line:?}")
        })
        .0;
    fields
        .get(idx + 1)
        .unwrap_or_else(|| panic!("field {label:?} has no value in {whole_line:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("field {label:?} not a number in {whole_line:?}: {e}"))
}

// ------------------------------------------------------------- store reader

/// Reads a store object straight off disk: `objects/<2hex>/<64hex>`.
/// This IS the fetch closure `validate_dir_tree` wants — since the
/// path is the digest, an honest read verifies fine (execution
/// amendment: `validate_dir_tree` hash-verifies every fetched object).
fn disk_fetch(store: &Path) -> impl Fn(&GrainId) -> Option<Vec<u8>> {
    let store = store.to_owned();
    move |id: &GrainId| {
        let hex = id.digest_hex();
        let (fanout, _) = hex.split_at(2);
        fs::read(store.join("objects").join(fanout).join(&hex)).ok()
    }
}

/// Decode a store object's bytes as a directory leaf (asserts the
/// object type, since a wrong-type object here means the test fixture
/// is broken, not that exec-bit detection is).
fn decode_dir_leaf_bytes(bytes: &[u8]) -> Vec<DirEntry> {
    let (ty, cursor) =
        encoding::open_envelope(bytes).unwrap_or_else(|e| panic!("open_envelope: {e:?}"));
    assert_eq!(
        ty,
        encoding::ObjectType::DirLeaf,
        "expected a dir leaf object"
    );
    decode_dir_leaf(cursor).unwrap_or_else(|e| panic!("decode_dir_leaf: {e:?}"))
}

fn find_dir_child(entries: &[DirEntry], name: &[u8]) -> GrainId {
    let entry = entries
        .iter()
        .find(|e| e.name.as_bytes() == name)
        .unwrap_or_else(|| panic!("entry {:?} not found", String::from_utf8_lossy(name)));
    match &entry.kind {
        EntryKind::Dir { child } => *child,
        other => panic!(
            "expected Dir entry for {:?}, got {other:?}",
            String::from_utf8_lossy(name)
        ),
    }
}

fn find_entry_kind<'a>(entries: &'a [DirEntry], name: &[u8]) -> &'a EntryKind {
    &entries
        .iter()
        .find(|e| e.name.as_bytes() == name)
        .unwrap_or_else(|| panic!("entry {:?} not found", String::from_utf8_lossy(name)))
        .kind
}

// ------------------------------------------------------------------ tests

/// Removing exec-bit detection entirely left the rest of the suite
/// green, so this test pins it: it decodes the actual store
/// objects and asserts `exec.sh` (0o755) is recorded as the exec-file
/// entry kind, AND that its non-exec sibling `file1.txt` is recorded
/// as the plain-file kind, so the assertion discriminates in both
/// directions rather than merely checking "some bit is set somewhere".
#[test]
fn exec_bit_recorded_correctly_in_both_directions() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let store = ScratchDir::new();
    let store_dir = store.path().join("store");

    let out = run_harvest(source.path(), &store_dir);
    assert!(out.success, "harvest failed: {}", out.stderr);
    let report = parse_report(&out.stdout);

    let root: GrainId = report.manifest_root.parse().unwrap_or_else(|e| {
        panic!(
            "manifest root id {:?} did not parse: {e:?}",
            report.manifest_root
        )
    });
    let fetch = disk_fetch(&store_dir);

    let root_bytes = fetch(&root).unwrap_or_else(|| panic!("root object present"));
    let root_entries = decode_dir_leaf_bytes(&root_bytes);

    let b_child = find_dir_child(&root_entries, b"b");
    let b_bytes = fetch(&b_child).unwrap_or_else(|| panic!("dir b object present"));
    let b_entries = decode_dir_leaf_bytes(&b_bytes);
    match find_entry_kind(&b_entries, b"exec.sh") {
        EntryKind::File { exec, .. } => {
            assert!(*exec, "exec.sh (mode 0o755) must be recorded as executable");
        }
        other => panic!("expected a File entry for exec.sh, got {other:?}"),
    }

    let a_child = find_dir_child(&root_entries, b"a");
    let a_bytes = fetch(&a_child).unwrap_or_else(|| panic!("dir a object present"));
    let a_entries = decode_dir_leaf_bytes(&a_bytes);
    match find_entry_kind(&a_entries, b"file1.txt") {
        EntryKind::File { exec, .. } => {
            assert!(
                !*exec,
                "file1.txt (mode 0o644) must NOT be recorded as executable"
            );
        }
        other => panic!("expected a File entry for file1.txt, got {other:?}"),
    }
}

/// The exec rule was corrected from owner-only
/// (`mode & 0o100`) to any-exec (`mode & 0o111`, "git's actual rule");
/// `exec_bit_recorded_correctly_in_both_directions`'s only executable
/// fixture is `exec.sh` at 0o755, where both rules agree, so it does
/// NOT discriminate the correction. This test does: a file whose mode
/// grants execute to GROUP only (owner gets rw-, no x) is recorded as
/// executable under the any-exec rule but would NOT be under an
/// owner-only rule.
#[test]
fn group_only_exec_bit_is_recorded_as_executable() {
    let source = ScratchDir::new();
    let file_path = source.path().join("group-exec-only");
    fs::write(&file_path, b"group exec only\n").unwrap_or_else(|e| panic!("{e}"));
    // rw- for owner, --x for group, --- for other. The default umask
    // would not grant group-exec on its own, so this is explicit.
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o610))
        .unwrap_or_else(|e| panic!("{e}"));
    // Verify the mode actually stuck on this filesystem before
    // asserting anything downstream of it — otherwise a filesystem
    // that silently clamped the mode would make this test pass
    // vacuously (it would just be re-testing exec.sh's owner-exec
    // case under a different name).
    let stuck_mode = fs::metadata(&file_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        stuck_mode, 0o610,
        "set_permissions(0o610) must actually persist on this filesystem; got {stuck_mode:o}"
    );

    let store = ScratchDir::new();
    let store_dir = store.path().join("store");
    let out = run_harvest(source.path(), &store_dir);
    assert!(out.success, "harvest failed: {}", out.stderr);
    let report = parse_report(&out.stdout);

    let root: GrainId = report.manifest_root.parse().unwrap_or_else(|e| {
        panic!(
            "manifest root id {:?} did not parse: {e:?}",
            report.manifest_root
        )
    });
    let fetch = disk_fetch(&store_dir);
    let root_bytes = fetch(&root).unwrap_or_else(|| panic!("root object present"));
    let root_entries = decode_dir_leaf_bytes(&root_bytes);

    match find_entry_kind(&root_entries, b"group-exec-only") {
        EntryKind::File { exec, .. } => {
            assert!(
                *exec,
                "mode 0o610 (group-exec, no owner-exec) must be recorded as executable under \
                 the any-exec-bit rule (mode & 0o111), not just an owner-exec rule"
            );
        }
        other => panic!("expected a File entry for group-exec-only, got {other:?}"),
    }
}

#[test]
fn root_id_stable_across_fresh_stores() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());

    let store_a = ScratchDir::new();
    let out_a = run_harvest(source.path(), &store_a.path().join("store"));
    assert!(out_a.success, "harvest 1 failed: {}", out_a.stderr);
    let report_a = parse_report(&out_a.stdout);

    let store_b = ScratchDir::new();
    let out_b = run_harvest(source.path(), &store_b.path().join("store"));
    assert!(out_b.success, "harvest 2 failed: {}", out_b.stderr);
    let report_b = parse_report(&out_b.stdout);

    assert_eq!(
        report_a.manifest_root, report_b.manifest_root,
        "same source tree must produce the same root id across independent fresh stores"
    );
    assert_eq!(report_a.dirs, 3, "root + a + b");
    assert_eq!(report_a.files, 3);
    assert_eq!(report_a.symlinks, 1);
}

#[test]
fn reharvest_same_tree_into_same_store_is_all_dedup() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let store = ScratchDir::new();
    let store_dir = store.path().join("store");

    let first = run_harvest(source.path(), &store_dir);
    assert!(first.success, "first harvest failed: {}", first.stderr);
    let first_report = parse_report(&first.stdout);
    assert!(first_report.grains_novel > 0);
    assert!(first_report.nodes_novel > 0);
    assert_eq!(first_report.grains_novel, first_report.grains_total);
    assert_eq!(first_report.bytes_novel, first_report.bytes_total);
    assert_eq!(first_report.nodes_novel, first_report.nodes_total);

    let second = run_harvest(source.path(), &store_dir);
    assert!(second.success, "second harvest failed: {}", second.stderr);
    let second_report = parse_report(&second.stdout);

    assert_eq!(second_report.manifest_root, first_report.manifest_root);
    assert_eq!(
        second_report.grains_total, first_report.grains_total,
        "the same tree must chunk into the same grain count"
    );
    assert_eq!(
        second_report.grains_novel, 0,
        "re-harvesting the identical tree must find zero novel grains"
    );
    assert_eq!(second_report.bytes_novel, 0);
    assert_eq!(
        second_report.nodes_novel, 0,
        "re-harvesting the identical tree must find zero novel manifest nodes"
    );
}

#[test]
fn modifying_one_file_novelizes_only_its_grains_and_ancestor_chain() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let store = ScratchDir::new();
    let store_dir = store.path().join("store");

    let first = run_harvest(source.path(), &store_dir);
    assert!(first.success, "first harvest failed: {}", first.stderr);
    let first_report = parse_report(&first.stdout);

    // Modify one byte of a/file1.txt ("hello" -> "hellO").
    fs::write(source.path().join("a/file1.txt"), b"hellO").unwrap_or_else(|e| panic!("{e}"));

    let second = run_harvest(source.path(), &store_dir);
    assert!(second.success, "second harvest failed: {}", second.stderr);
    let report = parse_report(&second.stdout);

    assert_ne!(
        report.manifest_root, first_report.manifest_root,
        "the manifest root must change when file content changes"
    );
    assert!(
        report.grains_novel >= 1,
        "the changed file's grain(s) must be novel"
    );
    // Ancestor node chain: dir `a`'s leaf + root dir's leaf reference
    // the changed hash — depth from root to the file is 2 (root, a).
    let depth = 2;
    assert!(
        report.nodes_novel <= depth + 1,
        "only the ancestor chain's nodes should be novel, got {}",
        report.nodes_novel
    );
    assert!(report.nodes_novel >= 1);
}

#[test]
fn gran_prefixed_name_in_source_fails_loudly() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let bad_path = source.path().join(".granjunk");
    fs::write(&bad_path, b"nope").unwrap_or_else(|e| panic!("{e}"));

    let store = ScratchDir::new();
    let out = run_harvest(source.path(), &store.path().join("store"));

    assert!(!out.success, "harvest of a .gran-prefixed name must fail");
    assert!(
        out.stderr.contains(&bad_path.display().to_string()),
        "stderr must name the offending path: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains("gran"),
        "stderr must name the violated rule: {}",
        out.stderr
    );
}

/// A symlink-to-dir or plain-file source
/// (the ROOT call) is a stable condition, not a race — it must be
/// reported as `NotADirectory`, never the TOCTOU `ChangedDuringHarvest`
/// diagnosis (which would mislead real users: on macOS `/tmp` and many
/// user paths are themselves symlinks).
#[test]
fn non_directory_source_reports_not_a_directory_not_a_race() {
    let base = ScratchDir::new();
    let real_dir = base.path().join("realdir");
    fs::create_dir_all(&real_dir).unwrap_or_else(|e| panic!("{e}"));
    fs::write(real_dir.join("f.txt"), b"hi").unwrap_or_else(|e| panic!("{e}"));
    let link_dir = base.path().join("linkdir");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap_or_else(|e| panic!("{e}"));
    let plain_file = base.path().join("plainfile");
    fs::write(&plain_file, b"plain").unwrap_or_else(|e| panic!("{e}"));

    for source in [&link_dir, &plain_file] {
        let store = ScratchDir::new();
        let out = run_harvest(source, &store.path().join("store"));
        assert!(
            !out.success,
            "harvest of non-directory source {source:?} must fail"
        );
        assert!(
            out.stderr.contains("not a directory"),
            "stderr for {source:?} must say 'not a directory': {}",
            out.stderr
        );
        assert!(
            !out.stderr.contains("changed during harvest"),
            "a stable non-directory source must NOT be reported as a race: {}",
            out.stderr
        );
    }
}

/// A store nested inside its own source
/// (either direction) must be rejected loudly, not harvested into
/// itself (silent wrongness — a nondeterministic root with the
/// marker/lock/objects baked into the manifest).
#[test]
fn nested_store_and_source_are_rejected_both_directions() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());

    // store INSIDE source.
    let out = run_harvest(source.path(), &source.path().join("store"));
    assert!(!out.success, "store nested inside source must be rejected");
    assert!(
        out.stderr.contains("must not nest"),
        "stderr must name the nesting violation: {}",
        out.stderr
    );
    // The rejection must precede ANY store scaffolding: residue left in
    // the source would be silently baked into the next correct
    // harvest's manifest — the exact wrongness the guard exists for.
    assert!(
        !source.path().join("store").exists(),
        "a rejected nested harvest must leave no store residue in the source"
    );

    // source INSIDE store.
    let store = ScratchDir::new();
    let nested_source = store.path().join("src");
    write_basic_tree(&nested_source);
    let out = run_harvest(&nested_source, store.path());
    assert!(!out.success, "source nested inside store must be rejected");
    assert!(
        out.stderr.contains("must not nest"),
        "stderr must name the nesting violation: {}",
        out.stderr
    );
    assert!(
        !store.path().join("granary-store").exists() && !store.path().join("txn").exists(),
        "a rejected nested harvest must not scaffold a store"
    );
}

/// A trailing argument is a usage error (exit 2), not silently
/// dropped: `gran harvest src store extra` must not run a harvest.
#[test]
fn extra_argument_is_a_usage_error() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let store = ScratchDir::new();
    let store_dir = store.path().join("store");

    let out = Command::new(env!("CARGO_BIN_EXE_gran"))
        .arg("harvest")
        .arg(source.path())
        .arg(&store_dir)
        .arg("--extra")
        .output()
        .unwrap_or_else(|e| panic!("spawn gran harvest: {e}"));
    assert_eq!(
        out.status.code(),
        Some(2),
        "extra argument must be a usage error, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !store_dir.exists(),
        "a usage error must not create the store"
    );
}

/// The normal shape (store OUTSIDE source, e.g. sibling directories) —
/// what `determinism_fixture.rs` and the recorded toolchain-harvest demo
/// both use — must be unaffected by the nesting guard.
#[test]
fn sibling_store_and_source_are_not_nested() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let store = ScratchDir::new();

    let out = run_harvest(source.path(), &store.path().join("store"));
    assert!(
        out.success,
        "store outside source (sibling dirs) must still work: {}",
        out.stderr
    );
}

#[test]
fn fifo_in_source_fails_as_special_file() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let fifo_path = source.path().join("a-fifo");
    let status = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .unwrap_or_else(|e| panic!("spawn mkfifo: {e}"));
    assert!(status.success(), "mkfifo must succeed to set up the test");

    let store = ScratchDir::new();
    let out = run_harvest(source.path(), &store.path().join("store"));

    assert!(!out.success, "harvest of a fifo must fail");
    assert!(
        out.stderr.contains("special file"),
        "stderr must name the special-file rule: {}",
        out.stderr
    );
}

#[test]
fn validate_dir_tree_over_the_store_matches_binary_stats() {
    let source = ScratchDir::new();
    write_basic_tree(source.path());
    let store = ScratchDir::new();
    let store_dir = store.path().join("store");

    let out = run_harvest(source.path(), &store_dir);
    assert!(out.success, "harvest failed: {}", out.stderr);
    let report = parse_report(&out.stdout);

    let root: GrainId = report.manifest_root.parse().unwrap_or_else(|e| {
        panic!(
            "manifest root id {:?} did not parse: {e:?}",
            report.manifest_root
        )
    });
    let fetch = disk_fetch(&store_dir);
    let stats =
        validate_dir_tree(&root, &fetch).unwrap_or_else(|e| panic!("validate_dir_tree: {e}"));

    assert_eq!(stats.dirs, report.dirs);
    assert_eq!(stats.files, report.files);
    assert_eq!(stats.symlinks, report.symlinks);
}

// -------------------------------------------------- non-UTF-8 name lanes

/// Linux: byte-string filenames accept an arbitrary non-UTF-8 byte
/// sequence built at RUNTIME (never a committed literal path — the
/// source name bytes come from a `&[u8]` array, not an embedded
/// non-UTF-8 path in this file). Harvest must succeed and
/// the name must round-trip through the manifest decode.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_name_harvests_on_linux() {
    use std::ffi::OsStr;

    let source = ScratchDir::new();
    let raw_name: &[u8] = &[0xff, 0xfe];
    let name = OsStr::from_bytes(raw_name);
    fs::write(source.path().join(name), b"non-utf8 name contents")
        .unwrap_or_else(|e| panic!("{e}"));

    let store = ScratchDir::new();
    let store_dir = store.path().join("store");
    let out = run_harvest(source.path(), &store_dir);
    assert!(
        out.success,
        "harvest must accept non-UTF-8 names on Linux: {}",
        out.stderr
    );
    let report = parse_report(&out.stdout);

    let root: GrainId = report
        .manifest_root
        .parse()
        .unwrap_or_else(|e| panic!("root id did not parse: {e:?}"));
    let fetch = disk_fetch(&store_dir);
    // Fetch the root dir leaf directly and confirm the raw name bytes
    // are present verbatim (round-tripped through decode).
    let bytes = fetch(&root).unwrap_or_else(|| panic!("root object present"));
    assert!(
        bytes.windows(raw_name.len()).any(|w| w == raw_name),
        "non-UTF-8 name bytes must round-trip verbatim through the manifest"
    );
}

/// macOS: the filesystem itself rejects invalid-UTF-8 filenames with
/// EILSEQ — a platform fact, not a granary decision. Documented
/// behaviour, verified rather than silently skipped.
#[cfg(target_os = "macos")]
#[test]
fn non_utf8_name_rejected_by_filesystem_on_macos() {
    use std::ffi::OsStr;

    let source = ScratchDir::new();
    let raw_name: &[u8] = &[0xff, 0xfe];
    let name = OsStr::from_bytes(raw_name);
    let err = fs::write(source.path().join(name), b"non-utf8 name contents")
        .expect_err("macOS must reject a non-UTF-8 filename");
    assert_eq!(
        err.raw_os_error(),
        Some(92),
        "expected EILSEQ (92) creating a non-UTF-8 name on macOS, got {err:?}"
    );
}

// --------------------------------------------- deep dir NESTING

/// The nesting depth this row harvests — 400 levels, and
/// very nearly the deepest a harvest can be driven at all on macOS.
/// Harvest builds absolute paths, so a source tree is capped by
/// `PATH_MAX`: 1024 over one-byte names is about 510 levels, less the
/// scratch-dir prefix, which lands near 470. Linux's 4096 allows
/// roughly four times that.
const DEEP_NESTING_LEVELS: usize = 400;

/// The producer-side contract, EXECUTED: harvest walks 400 levels
/// of directory nesting and returns a root, and THIS is the tree it
/// builds.
///
/// **What this pins that nothing else does.** The nesting
/// descent moved off the native stack and onto an explicit worklist, in
/// `harvest_tree` as well as in the reader's `validate_dir_tree`. The
/// reader half got a committed row (10 000 levels, in `granary-core`);
/// the producer half initially had only a prose claim. The other "nesting"
/// rows in this file are store-vs-source PATH nesting — a different
/// property entirely — so nothing at all exercised a deeply nested
/// SOURCE tree, and a refactor of the descent that dropped, duplicated
/// or reordered a level would have left the suite green: the result is
/// still a perfectly valid manifest, just one naming a different tree.
/// That is what the pinned root catches, and the bottom file is there
/// so the deepest level's content has to reach the root's preimage.
///
/// This row pins the manifest root for the fixture below. It does not
/// establish a general stack-depth bound.
///
/// **On the digest.** `blake3:297397fc…`, quoted for "harvest at 400
/// levels" with no recorded fixture, is not this row's digest and is not
/// reproducible: a sweep over the obvious shapes (fixed and per-level
/// naming schemes, depths 1..=1200, empty and single-file innermost
/// directories) reproduces no such root. The constant below is measured
/// HERE, on the fixture this test builds and describes, which is the only
/// kind of digest a row can honestly assert.
#[test]
fn harvest_at_400_levels_of_nesting_returns_a_root_not_a_stack_overflow() {
    let source = ScratchDir::new();
    // <source>/a/a/a/… (400 levels), with one 13-byte file at the
    // bottom so the deepest directory has content that must reach the
    // root's preimage — a walk that stops short still produces a
    // manifest, just not this one.
    let mut deep = source.path().to_path_buf();
    for _ in 0..DEEP_NESTING_LEVELS {
        deep.push("a");
    }
    fs::create_dir_all(&deep)
        .unwrap_or_else(|e| panic!("create {DEEP_NESTING_LEVELS} levels: {e}"));
    fs::write(deep.join("deep.txt"), b"granary d-58\n").unwrap_or_else(|e| panic!("{e}"));

    let store = ScratchDir::new();
    let out = run_harvest(source.path(), &store.path().join("store"));
    assert!(
        out.success,
        "harvest of {DEEP_NESTING_LEVELS} nesting levels failed: {}",
        out.stderr
    );
    let report = parse_report(&out.stdout);

    // The shape, so a root mismatch below can be read as "the tree
    // moved" rather than "the fixture moved".
    assert_eq!(
        report.dirs,
        DEEP_NESTING_LEVELS as u64 + 1,
        "the source root plus every nested level"
    );
    assert_eq!(report.files, 1);
    assert_eq!(report.symlinks, 0);
    assert_eq!(report.grains_total, 1);
    assert_eq!(
        report.nodes_total,
        DEEP_NESTING_LEVELS as u64 + 1,
        "one dir leaf per level: no level was skipped or built twice"
    );

    assert_eq!(
        report.manifest_root,
        "blake3:998fda95335fe245d193e2de84488fb609c2aff2758e31440dba609e5f90d9d3",
        "the manifest a 400-level harvest builds"
    );
}
