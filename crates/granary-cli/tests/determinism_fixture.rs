// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A `DoD` centerpiece: the committed fixture tar, extracted
//! and harvested, must produce the committed golden root — on
//! every platform in the CI matrix (`[ubuntu-24.04,
//! ubuntu-24.04-arm, macos-15]`, per `ci.yml`) and locally. No
//! cross-job plumbing: each platform independently extracts the
//! same committed bytes and asserts against the same committed
//! `.root` line, so the golden itself is the drift tripwire.
//!
//! The property is CROSS-PROCESS reproducibility, so this test drives
//! the compiled binary (`env!("CARGO_BIN_EXE_gran")`) the same way
//! `harvest_integration.rs` does — an in-process call through the lib
//! would prove strictly less.
//!
//! Extraction uses the `tar` BINARY (`-xpf`), not a Rust tar crate —
//! this is deliberately the same tool CI's runners provide (bsdtar on
//! macOS, GNU tar on Linux) so byte-exact name restoration is verified
//! against the platform's own tar, not a third implementation. `-p`
//! (preserve permissions) removes any tail risk from the exec bit
//! surviving a stray umask: the root hash depends
//! only on whether any of `0o111` is set, which is umask-immune for
//! any sane extraction, but `-p` makes that argument moot.
//!
//! Execution amendment: `gran harvest` now rejects a store nested
//! inside its source (or vice versa), so the extracted tree and the
//! store MUST be sibling directories under the scratch root, never one
//! inside the other.

#![cfg(unix)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use granary_core::hash::GrainId;

/// The committed fixture tar's content hash — a tar-bytes pin. Guards
/// against silent regeneration drift: if `determinism_v1.tar` is ever
/// regenerated (even byte-identically in intent), this must still
/// match, or the change was NOT byte-identical and needs review.
///
/// Magic-independent: the tar holds source files, not granary objects,
/// so the `GRANARY\0` magic rename does not affect this value.
const FIXTURE_TAR_ID: &str =
    "blake3:1d475457f2b6dafc3e3baeb92f2514fb21967dbbbc41bf5d517ecf13731f42eb";

const FIXTURE_TAR_BYTES: &[u8] = include_bytes!("fixtures/determinism_v1.tar");
const GOLDEN_ROOT_FILE: &str = include_str!("fixtures/determinism_v1.root");

// ------------------------------------------------------------- scratch dir

/// Test-only scratch dir: unique per test, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
                      hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
                      and nothing else (`granary-determinism-fixture-<pid>-<counter>` under the temp dir, created and \
                      removed by this fixture), and it is load-bearing for correctness there: the counter beside it is \
                      per-process, and every test binary runs in its own process, so without the pid two concurrent \
                      runs generate the same name and share one directory. It reaches no hashed or signed value, and \
                      it is deliberately OUTSIDE the bytes this file pins: the golden root is compared byte-for-byte \
                      against a committed fixture, so a pid that reached the preimage would make the comparison fail \
                      on every run rather than pass wrongly — the scratch NAME is not an input to anything hashed here"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-determinism-fixture-{}-{}",
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ------------------------------------------------------------- helpers

/// Parses just the `manifest-root <id>` first line of `gran harvest`'s
/// stdout (full grammar is exercised by `harvest_integration.rs`; this
/// test only needs the tree's manifest id).
fn parse_manifest_root_line(stdout: &str) -> &str {
    let root_line = stdout
        .lines()
        .next()
        .unwrap_or_else(|| panic!("missing manifest line in stdout: {stdout:?}"));
    root_line
        .strip_prefix("manifest-root ")
        .unwrap_or_else(|| panic!("malformed manifest line: {root_line:?}"))
}

fn run_harvest(source: &Path, store: &Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_gran"))
        .arg("harvest")
        .arg(source)
        .arg(store)
        .output()
        .unwrap_or_else(|e| panic!("spawn gran harvest: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The golden root file is one line: `blake3:<hex>`, possibly with a
/// trailing newline from the editor that filled it in.
fn golden_root() -> &'static str {
    GOLDEN_ROOT_FILE.trim()
}

// ------------------------------------------------------------------ test

#[test]
fn fixture_tar_extracts_and_harvests_to_the_golden_root() {
    // --- tar-bytes pin: catches silent regen drift before we even
    // extract anything.
    let tar_id = GrainId::of(FIXTURE_TAR_BYTES).to_string();
    assert_eq!(
        tar_id, FIXTURE_TAR_ID,
        "actual-tar-id {tar_id} (expected {FIXTURE_TAR_ID}) — the committed tar's bytes \
         changed; if this generator run intentionally regenerated the fixture, this is a \
         cross-build determinism finding, not something to paper over by updating the literal"
    );

    let scratch = ScratchDir::new();
    // Extraction dir and store dir are SIBLINGS under scratch, never
    // nested — `gran harvest` rejects a store nested inside its source
    // (execution amendment).
    let tree_dir = scratch.path().join("tree");
    let store_dir = scratch.path().join("store");
    fs::create_dir_all(&tree_dir).unwrap_or_else(|e| panic!("{e}"));

    let tar_path = scratch.path().join("determinism_v1.tar");
    fs::write(&tar_path, FIXTURE_TAR_BYTES).unwrap_or_else(|e| panic!("{e}"));

    // Same extraction CI does: the platform's own `tar` binary
    // (bsdtar on macOS, GNU tar on Linux), `-p` to preserve
    // permissions exactly.
    let status = Command::new("tar")
        .args(["-xpf"])
        .arg(&tar_path)
        .arg("-C")
        .arg(&tree_dir)
        .status()
        .unwrap_or_else(|e| panic!("spawn tar -xpf: {e}"));
    assert!(status.success(), "tar -xpf extraction failed");

    let source = tree_dir.join("fixture");
    assert!(
        source.is_dir(),
        "extracted fixture/ directory must exist at {source:?}"
    );

    // --- first harvest: must match the committed golden root.
    let (success, stdout, stderr) = run_harvest(&source, &store_dir);
    assert!(success, "harvest failed: {stderr}");
    let root = parse_manifest_root_line(&stdout);
    let expected_root = golden_root();
    assert_eq!(
        root, expected_root,
        "actual-root {root} (expected {expected_root}) — the fixture tree's root hash no \
         longer matches the committed golden `determinism_v1.root`; this is either a \
         cross-platform determinism regression or (if intentional) the golden needs \
         regenerating"
    );

    // --- re-harvest into the SAME store: full dedup,
    // zero novel grains or manifest nodes (DoD).
    let (success2, stdout2, stderr2) = run_harvest(&source, &store_dir);
    assert!(success2, "second harvest failed: {stderr2}");
    let root2 = parse_manifest_root_line(&stdout2);
    assert_eq!(
        root2, expected_root,
        "root must be stable across re-harvest"
    );

    // stdout has 4 lines: root / dirs-files-symlinks / "grains G novel N
    // bytes B novel BN" / "manifest nodes M novel MN" — "novel" appears
    // 3 times total across the whole blob (grains, bytes, nodes in that
    // order), so grains-novel is occurrence 0 and nodes-novel is
    // occurrence 2.
    let grains_novel = field_after(&stdout2, "novel", 0);
    let nodes_novel = field_after(&stdout2, "novel", 2);
    assert_eq!(
        grains_novel, 0,
        "re-harvesting the identical fixture tree must find zero novel grains, got {grains_novel} \
         (stdout: {stdout2:?})"
    );
    assert_eq!(
        nodes_novel, 0,
        "re-harvesting the identical fixture tree must find zero novel manifest nodes, got \
         {nodes_novel} (stdout: {stdout2:?})"
    );
}

/// Finds the 0-indexed `occurrence`-th appearance of `label` in
/// whitespace-split `stdout` and parses the following token as `u64`.
/// `stdout`'s "grains G novel N bytes B novel BN" / "manifest nodes M
/// novel MN" lines repeat the label "novel" — occurrence 0 is the
/// grains-novel count, occurrence 1 is the bytes-novel count, occurrence
/// 2 is the manifest-nodes-novel count.
fn field_after(stdout: &str, label: &str, occurrence: usize) -> u64 {
    let fields: Vec<&str> = stdout.split_whitespace().collect();
    let idx = fields
        .iter()
        .enumerate()
        .filter(|&(_, &f)| f == label)
        .nth(occurrence)
        .unwrap_or_else(|| panic!("occurrence {occurrence} of {label:?} not found in {stdout:?}"))
        .0;
    fields
        .get(idx + 1)
        .unwrap_or_else(|| panic!("field {label:?} has no value in {stdout:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("field {label:?} not a number in {stdout:?}: {e}"))
}
