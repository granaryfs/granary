// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Stable-toolchain replay of the committed fuzz corpus — PR CI runs no
//! nightly; the scheduled fuzz lane does the open-ended
//! fuzzing. Same probe bodies as the libFuzzer targets.
//!
//! Fails CLOSED: the registry below must
//! stay in 4-way set equality with `fuzz_targets/*.rs`, the fuzz
//! `Cargo.toml` `[[bin]]` list, the corpus directories, and `fuzz.yml`'s
//! run lines **for this crate**. Adding a fuzz target without
//! registering it here is a red test, not silence.
//!
//! One workflow, several fuzz workspaces: granary-store and granary-client
//! each check their own run lines, and each reads only its own crate's
//! lines (here, `RUN_LINE_SCOPE` below).
//! Without that, each reads the other crate's targets as unregistered
//! ones — which is what this test did until the `bin_ingest` line was
//! added, turning it red.

#![expect(clippy::unwrap_used, reason = "test code (standards rule 3)")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// One registered probe body (also keeps `REGISTRY` below
/// `clippy::type_complexity`-clean).
type Probe = fn(&[u8]);

/// The ONE list. Probe bodies are the same `testkit` functions the
/// libFuzzer targets call — keep that invariant when adding entries.
const REGISTRY: &[(&str, Probe)] = &[
    (
        "mount_control_decode",
        granary_core::testkit::mount_control_decode_probe,
    ),
    (
        "support_trigger_decode",
        granary_core::testkit::support_trigger_decode_probe,
    ),
    (
        "overlay_discard_decode",
        granary_core::testkit::overlay_discard_decode_probe,
    ),
    (
        "overlay_ownership_decode",
        granary_core::testkit::overlay_ownership_decode_probe,
    ),
    (
        "support_manifest_decode",
        granary_core::testkit::support_manifest_decode_probe,
    ),
    (
        "support_archive_decode",
        granary_core::testkit::support_archive_decode_probe,
    ),
    (
        "debug_grant_decode",
        granary_core::testkit::debug_grant_decode_probe,
    ),
    (
        "support_snapshot_decode",
        granary_core::testkit::support_snapshot_decode_probe,
    ),
    (
        "support_configuration_decode",
        granary_core::testkit::support_configuration_decode_probe,
    ),
    (
        "support_bundle_decode",
        granary_core::testkit::support_bundle_decode_probe,
    ),
    ("archive_name", granary_core::testkit::archive_name_probe),
    (
        "retained_submission_decode",
        granary_core::testkit::retained_submission_decode_probe,
    ),
    (
        "authority_answer_decode",
        granary_core::testkit::authority_answer_decode_probe,
    ),
    ("intent_decode", granary_core::testkit::intent_decode_probe),
    ("thresh_chunk", granary_core::testkit::chunk_probe),
    (
        "grainid_decode",
        granary_core::testkit::grainid_decode_probe,
    ),
    (
        "manifest_decode",
        granary_core::testkit::manifest_decode_probe,
    ),
    ("bin_decode", granary_core::testkit::bin_decode_probe),
    ("binmap_decode", granary_core::testkit::binmap_decode_probe),
    ("root_decode", granary_core::testkit::root_decode_probe),
    ("sheaf_decode", granary_core::testkit::sheaf_decode_probe),
    (
        "cacheindex_decode",
        granary_core::testkit::cacheindex_decode_probe,
    ),
    ("manifest_walk", granary_core::testkit::manifest_walk_probe),
    (
        "authlog_classify",
        granary_core::testkit::authlog_classify_probe,
    ),
    (
        "runmarker_decode",
        granary_core::testkit::runmarker_decode_probe,
    ),
    (
        "enrollment_decode",
        granary_core::testkit::enrollment_decode_probe,
    ),
    (
        "overlay_journal_decode",
        granary_core::testkit::overlay_journal_decode_probe,
    ),
];

/// How THIS crate's `cargo fuzz run` lines are told apart from the other
/// fuzz workspaces' in the ONE shared workflow (granary-store's and
/// granary-client's tests scope theirs the same way).
const RUN_LINE_SCOPE: &str = "cd crates/granary-core";

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz")
}

fn registry_names() -> BTreeSet<String> {
    REGISTRY.iter().map(|(n, _)| (*n).to_owned()).collect()
}

fn dir_stems(dir: &Path, want_ext: Option<&str>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        match want_ext {
            Some(ext) => {
                if path.extension().and_then(|e| e.to_str()) == Some(ext) {
                    out.insert(path.file_stem().unwrap().to_str().unwrap().to_owned());
                }
            }
            None => {
                if path.is_dir() {
                    out.insert(path.file_name().unwrap().to_str().unwrap().to_owned());
                }
            }
        }
    }
    out
}

#[test]
fn registry_matches_fuzz_targets_bins_and_corpus() {
    let registry = registry_names();
    let target_files = dir_stems(&fuzz_dir().join("fuzz_targets"), Some("rs"));
    let corpus_dirs = dir_stems(&fuzz_dir().join("corpus"), None);
    let manifest = std::fs::read_to_string(fuzz_dir().join("Cargo.toml")).unwrap();
    let bins: BTreeSet<String> = manifest
        .lines()
        .filter_map(|l| l.trim().strip_prefix("name = \""))
        .filter_map(|l| l.strip_suffix('"'))
        .map(str::to_owned)
        .filter(|n| n != "granary-core-fuzz")
        .collect();
    assert_eq!(registry, target_files, "registry vs fuzz_targets/*.rs");
    assert_eq!(registry, bins, "registry vs fuzz/Cargo.toml [[bin]] names");
    assert_eq!(registry, corpus_dirs, "registry vs fuzz/corpus/ dirs");
}

#[test]
fn fuzz_workflow_runs_every_registered_target() {
    let workflow = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/fuzz.yml"),
    )
    .unwrap();
    let all: Vec<&str> = workflow
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter(|l| l.contains("cargo fuzz run "))
        .collect();
    // DIRECTORY-SCOPED, and it has to be: this one workflow carries other
    // crates' fuzz lines too, and an unscoped collector reads
    // that crate's targets as unregistered ones — which is exactly what
    // this test did, and how it went red the moment something added the
    // `bin_ingest` line. `cargo fuzz` takes its workspace from the
    // working directory, so the `cd` IS the scope; there is no per-line
    // manifest flag to key on instead.
    let (ours, theirs): (Vec<&str>, Vec<&str>) =
        all.iter().partition(|l| l.contains(RUN_LINE_SCOPE));
    // POSITIVE CONTROL for the scope. A filter that excluded nothing
    // would be doing no scoping at all, and this gate would go back to
    // claiming the other workspace's targets while still reporting
    // green.
    assert!(
        !theirs.is_empty(),
        "the `{RUN_LINE_SCOPE}` filter excluded none of the {} run lines in fuzz.yml, so \
         it is scoping nothing. Either every other workspace's lines were removed — \
         then this control has no subject left and should go — or the `cd` spelling moved and \
         both twins are now claiming each other's targets",
        all.len()
    );
    let ran: BTreeSet<String> = ours
        .iter()
        .filter_map(|l| {
            l.find("cargo fuzz run ").map(|i| {
                l[i + "cargo fuzz run ".len()..]
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_owned()
            })
        })
        .collect();
    assert_eq!(
        registry_names(),
        ran,
        "fuzz.yml `{RUN_LINE_SCOPE}` run lines vs registry"
    );
}

#[test]
fn archive_name_replay_and_fuzz_use_shared_probe() {
    let (_, probe) = REGISTRY
        .iter()
        .find(|(name, _)| *name == "archive_name")
        .unwrap();
    assert!(std::ptr::fn_addr_eq(
        *probe,
        granary_core::testkit::archive_name_probe as Probe
    ));
    let target = std::fs::read_to_string(fuzz_dir().join("fuzz_targets/archive_name.rs")).unwrap();
    assert!(target.contains("granary_core::testkit::archive_name_probe(data)"));
}

#[test]
fn mount_control_replay_and_fuzz_use_shared_probe() {
    let (_, probe) = REGISTRY
        .iter()
        .find(|(name, _)| *name == "mount_control_decode")
        .unwrap();
    let source = std::fs::read_to_string(fuzz_dir().join("fuzz_targets/mount_control_decode.rs"))
        .unwrap_or_else(|error| panic!("could not read mount_control_decode target: {error}"));
    assert!(
        source.contains("granary_core::testkit::mount_control_decode_probe(data)"),
        "mount_control_decode target must call the shared probe"
    );
    let mut cases = (0, 0);
    for entry in std::fs::read_dir(fuzz_dir().join("corpus/mount_control_decode")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        probe(&bytes);
        if granary_core::mount_control::decode(&bytes).is_ok() {
            cases.0 += 1;
        } else {
            cases.1 += 1;
        }
    }
    assert!(
        cases.0 > 0 && cases.1 > 0,
        "valid/rejected corpus counts={cases:?}"
    );
}

#[test]
fn replay_committed_corpus() {
    for (target, probe) in REGISTRY {
        let dir = fuzz_dir().join("corpus").join(target);
        let mut n = 0usize;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            probe(&std::fs::read(&path).unwrap());
            n += 1;
        }
        assert!(
            n > 0,
            "empty corpus for {target} — replay would be vacuously green"
        );
    }
}

/// Check this target's registration and replay only its own corpus.
#[test]
fn fuzz_corpus_debug_grant_registration_and_replay() {
    let registered: Vec<_> = REGISTRY
        .iter()
        .filter(|(name, _)| *name == "debug_grant_decode")
        .collect();
    assert_eq!(registered.len(), 1, "one debug grant probe registration");
    let (_, probe) = registered.first().unwrap();
    assert!(std::ptr::fn_addr_eq(
        *probe,
        granary_core::testkit::debug_grant_decode_probe as Probe
    ));
    let source =
        std::fs::read_to_string(fuzz_dir().join("fuzz_targets/debug_grant_decode.rs")).unwrap();
    assert!(source.contains("granary_core::testkit::debug_grant_decode_probe(data)"));
    let manifest = std::fs::read_to_string(fuzz_dir().join("Cargo.toml")).unwrap();
    let bins: Vec<_> = manifest
        .split("[[bin]]")
        .filter(|bin| {
            bin.lines()
                .any(|line| line.trim() == "name = \"debug_grant_decode\"")
        })
        .collect();
    assert_eq!(bins.len(), 1, "one debug grant fuzz binary registration");
    assert!(
        bins.first()
            .unwrap()
            .contains("path = \"fuzz_targets/debug_grant_decode.rs\"")
    );
    let workflow = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/fuzz.yml"),
    )
    .unwrap();
    assert_eq!(
        workflow
            .lines()
            .filter(|line| {
                line.trim().starts_with(
                    "- run: cd crates/granary-core && cargo fuzz run debug_grant_decode ",
                )
            })
            .count(),
        1,
        "one debug grant fuzz run registration"
    );
    let mut count = 0;
    for entry in std::fs::read_dir(fuzz_dir().join("corpus/debug_grant_decode")).unwrap() {
        probe(&std::fs::read(entry.unwrap().path()).unwrap());
        count += 1;
    }
    assert!(count > 0, "debug grant corpus must be nonempty");
}

/// Semantic fixtures keep their names independently of corpus minimisation.
#[test]
fn replay_immutable_format_vectors() {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    for (target, directory) in [
        ("debug_grant_decode", "debug-grant"),
        ("authlog_classify", "authlog"),
        ("retained_submission_decode", "retained-submission"),
        ("authority_answer_decode", "authority-answer-rejects"),
        ("intent_decode", "intent"),
        ("intent_decode", "intent-rejects"),
        ("archive_name", "archive-name"),
        ("support_manifest_decode", "support-inventory-manifests"),
        ("support_archive_decode", "support-inventory-archives"),
        ("support_snapshot_decode", "support-enrollment-states"),
    ] {
        let (_, probe) = REGISTRY.iter().find(|(name, _)| *name == target).unwrap();
        let mut count = 0;
        for entry in std::fs::read_dir(vectors.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("tsv" | "hash")
            ) {
                continue;
            }
            probe(&std::fs::read(path).unwrap());
            count += 1;
        }
        assert!(count > 0, "empty immutable vector set for {target}");
    }
    for (target, file) in [
        (
            "support_configuration_decode",
            "support-configuration-sentinels.bin",
        ),
        ("support_snapshot_decode", "support-snapshot-sentinels.bin"),
        (
            "support_archive_decode",
            "support-valid-projections-archive.bin",
        ),
    ] {
        let (_, probe) = REGISTRY.iter().find(|(name, _)| *name == target).unwrap();
        probe(&std::fs::read(vectors.join(file)).unwrap());
    }
}
