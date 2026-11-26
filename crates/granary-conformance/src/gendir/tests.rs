// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::gendir` — `granconf gendir`'s seeded,
//! adversarial-but-legal source tree: the pure plan and the
//! materializer that writes it to disk with `create_new`
//! semantics.
//!
//! Out-of-line: `granary-conformance`'s non-test artifact
//! has its own `[[bin]]` (`granconf`) and its own `tests/`
//! directory (`crates/granary-conformance/tests/cli.rs`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::{Plan, PlannedEntry, PlannedNode, build_plan, materialize, summarize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt as _;

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        // Test-name-scoped, not pid-scoped (`std::process::id` is a
        // banned ambient-input seam workspace-wide). Distinct test names
        // isolate concurrent cases, and `Drop` cleans even after panic.
        let dir = std::env::temp_dir().join(format!("granconf-gendir-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
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
fn the_same_seed_produces_a_byte_identical_plan() {
    let a = build_plan(42);
    let b = build_plan(42);
    let render = |p: &Plan| {
        p.entries
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
    };
    assert_eq!(render(&a), render(&b));
}

#[test]
fn different_seeds_produce_different_file_content() {
    let a = build_plan(1);
    let b = build_plan(2);
    let content_of = |p: &Plan, path: &[u8]| {
        p.entries.iter().find_map(|e| {
            if e.path == path
                && let PlannedNode::File { content, .. } = &e.node
            {
                return Some(content.clone());
            }
            None
        })
    };
    assert_ne!(content_of(&a, b"names/a"), content_of(&b, b"names/a"));
}

#[test]
fn the_dup_pair_is_byte_identical_after_stripping_the_prefix() {
    let plan = build_plan(7);
    let strip = |prefix: &[u8]| -> Vec<(Vec<u8>, String)> {
        let mut out: Vec<(Vec<u8>, String)> = plan
            .entries
            .iter()
            .filter(|e| e.path.starts_with(prefix) && e.path.len() > prefix.len())
            .map(|e| {
                let suffix = e.path[prefix.len()..].to_vec();
                let desc = match &e.node {
                    PlannedNode::Dir => "dir".to_owned(),
                    PlannedNode::File {
                        size,
                        exec,
                        content,
                    } => {
                        format!("file:{size}:{exec}:{}", content.len())
                    }
                    PlannedNode::Symlink { target } => format!("symlink:{target:?}"),
                };
                (suffix, desc)
            })
            .collect();
        out.sort();
        out
    };
    let one = strip(b"dup/one");
    let two = strip(b"dup/two");
    assert_eq!(one, two);
    assert!(
        !one.is_empty(),
        "the dup pair must actually contain entries"
    );
    // And the CONTENT bytes themselves, not just their length:
    let content_at = |suffix: &[u8]| -> Vec<u8> {
        plan.entries
            .iter()
            .find(|e| e.path == suffix)
            .and_then(|e| match &e.node {
                PlannedNode::File { content, .. } => Some(content.clone()),
                _ => None,
            })
            .expect("entry present")
    };
    assert_eq!(content_at(b"dup/one/f0"), content_at(b"dup/two/f0"));
}

#[test]
fn build_plan_lists_every_directory_before_its_children() {
    let plan = build_plan(3);
    let mut created: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for entry in &plan.entries {
        if let Some(slash) = entry.path.iter().rposition(|&b| b == b'/') {
            let parent = &entry.path[..slash];
            assert!(
                created.contains(parent),
                "{:?} appears before its parent {:?}",
                entry.path,
                parent
            );
        }
        if matches!(entry.node, PlannedNode::Dir) {
            created.insert(entry.path.clone());
        }
    }
}

#[test]
fn build_plan_contains_every_named_symlink_case_by_path() {
    let plan = build_plan(3);
    let actual: BTreeSet<Vec<u8>> = plan
        .entries
        .iter()
        .filter(|entry| entry.path.starts_with(b"symlinks/"))
        .map(|entry| entry.path.clone())
        .collect();
    let expected: BTreeSet<Vec<u8>> = [
        b"symlinks/abs".to_vec(),
        b"symlinks/dotdot".to_vec(),
        b"symlinks/dangling".to_vec(),
        b"symlinks/to-dir".to_vec(),
        b"symlinks/sibling.txt".to_vec(),
        b"symlinks/to-sibling".to_vec(),
    ]
    .into_iter()
    .collect();
    assert_eq!(actual, expected);
}

#[test]
fn materialize_uses_create_new_semantics_so_a_repeat_run_collides() {
    let dir = ScratchDir::new("collision");
    let small = Plan {
        entries: vec![
            PlannedEntry {
                path: b"a".to_vec(),
                node: PlannedNode::Dir,
            },
            PlannedEntry {
                path: b"a/f".to_vec(),
                node: PlannedNode::File {
                    size: 3,
                    exec: false,
                    content: vec![1, 2, 3],
                },
            },
        ],
    };
    materialize(&small, &dir).expect("first materialize succeeds");
    let err = materialize(&small, &dir)
        .expect_err("a second materialize into the same out-dir must collide");
    let msg = err.to_string();
    assert!(
        msg.contains("exists") || msg.to_lowercase().contains("exists"),
        "expected an already-exists error, got: {msg}"
    );
}

#[test]
fn a_portable_materialized_subplan_walks_every_planned_path() {
    let dir = ScratchDir::new("portable-subplan");
    let plan = Plan {
        entries: build_plan(11)
            .entries
            .into_iter()
            .filter(|entry| entry.path == b"wide" || entry.path.starts_with(b"wide/"))
            .collect(),
    };
    materialize(&plan, &dir).expect("the portable subplan materializes");
    let rows = crate::walk::walk(&dir).expect("walk the portable subplan");
    assert_eq!(
        rows.len(),
        plan.entries.len(),
        "the walker must return one row per planned entry"
    );
    let planned_paths: BTreeSet<&[u8]> = plan
        .entries
        .iter()
        .map(|entry| entry.path.as_slice())
        .collect();
    let walked_paths: BTreeSet<&[u8]> = rows.iter().map(|row| row.path.as_slice()).collect();
    assert_eq!(walked_paths, planned_paths);
}

/// Materialisation is FILESYSTEM-DEPENDENT, so this asserts the
/// property the running filesystem actually has rather than the one
/// the development machine happens to have. Gating the macOS case out
/// on Linux would leave materialisation untested on the ONLY platform
/// where the oracle runs, which is the wrong half to drop.
///
/// APFS case-folds `names/CaseA` against `names/casea` and refuses the
/// byte-0xff name outright, so `materialize` must return an Err there —
/// never panic, never silently drop the offending entry. ext4 holds
/// both, so it must SUCCEED, and then the tree it produced must satisfy
/// every `verify_cases` predicate when read back through a real walk.
/// The required claim is not merely that the plan is adversarial,
/// but that the plan remains so after materialisation and walking.
#[test]
fn materializing_the_full_adversarial_plan_matches_this_filesystem() {
    let dir = ScratchDir::new("full-plan-materialize");
    let plan = build_plan(9);
    let result = materialize(&plan, &dir);

    #[cfg(target_os = "macos")]
    {
        let Err(super::GenDirError::Io {
            path: error_path, ..
        }) = &result
        else {
            panic!(
                "materializing the full plan unexpectedly succeeded on a \
                 filesystem expected to refuse a required name"
            );
        };
        let raw = error_path.as_os_str().as_bytes();
        assert!(
            raw.ends_with(b"names/casea") || raw.ends_with(b"names/xff\xff"),
            "the full plan failed outside the two filesystem-dependent \
             names: {error_path:?}"
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        assert!(
            result.is_ok(),
            "materializing the full plan failed on a filesystem that can \
             hold every case: {result:?}"
        );
        let rows = crate::walk::walk(&dir).expect("walk the materialised tree");
        let outcomes =
            crate::verify_cases::verify_all(&rows).expect("the walked tree is not empty");
        let unmet: Vec<&str> = outcomes
            .iter()
            .filter(|o| o.outcome.is_err())
            .map(|o| o.name)
            .collect();
        assert!(
            unmet.is_empty(),
            "the MATERIALISED tree fails these required cases: {unmet:?}"
        );
    }
}

#[test]
fn summarize_is_a_plain_string_never_consumed_by_verify_cases() {
    let plan = build_plan(1);
    let text = summarize(&plan);
    assert!(text.contains("informational only"));
}

/// An HONEST reader's rows for this plan — never touching a real
/// filesystem, so it runs the same on every platform including
/// this one, where [`materialize`] itself cannot finish — must
/// satisfy every `verify_cases` predicate. This is what actually
/// proves `build_plan` generates every required case; the
/// per-predicate unit tests in `verify_cases.rs` prove the
/// predicates are correct in isolation, not that this plan meets
/// them all AT ONCE.
#[test]
fn the_plan_satisfies_every_verify_cases_predicate_without_touching_a_filesystem() {
    use crate::row::{DType, Kind, Payload, new_row};
    use granary_core::hash::GrainId;

    let plan = build_plan(2024);
    let rows: Vec<crate::row::Row> = plan
        .entries
        .iter()
        .map(|e| {
            let (kind, dtype, size, exec, payload) = match &e.node {
                PlannedNode::Dir => (Kind::Dir, DType::Dir, None, false, Payload::None),
                PlannedNode::File {
                    size,
                    exec,
                    content,
                } => (
                    Kind::File,
                    DType::File,
                    Some(*size),
                    *exec,
                    Payload::Content(GrainId::of(content).digest_hex()),
                ),
                PlannedNode::Symlink { target } => (
                    Kind::Symlink,
                    DType::Symlink,
                    None,
                    false,
                    Payload::Target(target.clone()),
                ),
            };
            new_row(e.path.clone(), kind, dtype, size, exec, payload)
                .expect("plan entry is a valid row")
        })
        .collect();

    let results = crate::verify_cases::verify_all(&rows).expect("plan is non-empty");
    let failed: Vec<String> = results
        .iter()
        .filter_map(|c| {
            c.outcome
                .as_ref()
                .err()
                .map(|why| format!("{}: {why}", c.name))
        })
        .collect();
    assert!(
        failed.is_empty(),
        "gendir's own plan failed verify-cases: {failed:#?}"
    );
}
