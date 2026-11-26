// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Stable-toolchain replay of every committed fuse fuzz corpus. The registry
//! must match the manifest, target files, corpus directories and weekly lane.
//! The weekly lane's total budget is checked by the store's corpus replay suite.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// A commented-out line satisfies a plain `contains` while doing
/// nothing, so check workflow commands on live lines.
fn contains_uncommented(body: &str, needle: &str) -> bool {
    body.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| l.contains(needle))
}

/// Every fuzz target this workspace registers, with the probe its libFuzzer
/// target calls. The lane row holds this list equal to the `[[bin]]` names,
/// the target files, the corpus directories and `fuzz.yml`'s run lines, and
/// the replay below walks every entry's corpus through its own probe.
/// Registered parser probe bodies.
type Probe = fn(&[u8]);

const REGISTRY: &[(&str, Probe)] = &[(
    "mountinfo_body",
    granary_fuse::fuzz_probe::mountinfo_body_probe,
)];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
}

/// The entries of `dir` that satisfy `keep`, by name.
/// An unreadable entry or a name that is not UTF-8 fails the row: skipping
/// either would hide a corpus file from the replay.
fn names_in(dir: &Path, keep: fn(&Path) -> bool) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| {
            e.unwrap_or_else(|e| panic!("an entry of {}: {e}", dir.display()))
                .path()
        })
        .filter(|p| keep(p))
        .map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_else(|| panic!("a name that is not UTF-8: {}", p.display()))
                .to_owned()
        })
        .collect()
}

/// The fuzz target file and the `Cargo.toml` `[[bin]]` entry must both
/// still name this probe — a rename on one side that missed the other
/// would leave `cargo fuzz run` building a binary this test's own
/// registry no longer describes, silently.
#[test]
fn the_fuzz_target_and_manifest_still_name_the_probe() {
    let manifest =
        std::fs::read_to_string(repo_root().join("crates/granary-fuse/fuzz/Cargo.toml")).unwrap();
    for (name, _) in REGISTRY {
        let target_src = std::fs::read_to_string(
            repo_root().join(format!("crates/granary-fuse/fuzz/fuzz_targets/{name}.rs")),
        )
        .unwrap();
        let probe = format!("granary_fuse::fuzz_probe::{name}_probe");
        assert!(
            target_src.contains(&probe),
            "fuzz_targets/{name}.rs must call {probe}: the probe named for this target, by the naming contract the core and store fuzz tests also use"
        );
        assert!(
            manifest.contains(&format!("name = \"{name}\"")),
            "fuzz/Cargo.toml must declare the {name} [[bin]]"
        );
        assert!(
            manifest.contains(&format!("path = \"fuzz_targets/{name}.rs\"")),
            "fuzz/Cargo.toml's {name} [[bin]] must point at the target file"
        );
    }
}

/// PR CI lints the independent fuzz workspace using its own Clippy configuration.
#[test]
fn the_fuse_fuzz_workspace_is_wired_into_ci() {
    let ci = read(".github/workflows/ci.yml");
    for workspace in ["granary-core", "granary-fuse"] {
        let command = format!(
            "cargo clippy --manifest-path crates/{workspace}/fuzz/Cargo.toml --all-targets --locked"
        );
        assert!(
            contains_uncommented(&ci, &command),
            "ci.yml is missing the fuzz lint command for {workspace}: {command}"
        );
    }
}

/// Every independent fuzz lock needs its own dependency-update entry.
#[test]
fn the_fuse_fuzz_workspace_is_wired_into_dependabot() {
    let dependabot = read(".github/dependabot.yml");
    for directory in [
        "directory: /crates/granary-core/fuzz",
        "directory: /crates/granary-fuse/fuzz",
    ] {
        assert!(
            contains_uncommented(&dependabot, directory),
            "dependabot.yml is missing `{directory}` on a live line"
        );
    }
}

/// The weekly lane's three pieces for this workspace, each read from a
/// live line of `fuzz.yml`: exactly the registered targets run; rust-cache
/// knows the workspace; and a crash's
/// reproducer, written under THIS workspace, has an upload step of its
/// own. Each has the granary-core form as its positive control: if that
/// is missing too, the spelling moved and this gate is blind, not
/// satisfied.
#[test]
fn the_fuse_fuzz_target_runs_in_the_weekly_lane() {
    let fuzz_yml = read(".github/workflows/fuzz.yml");
    let run_lines: Vec<&str> = fuzz_yml
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && l.contains("cargo fuzz run "))
        .collect();
    let core = run_lines
        .iter()
        .filter(|l| l.contains("cd crates/granary-core "))
        .count();
    assert!(
        core > 0,
        "POSITIVE CONTROL FAILED: no granary-core run line matched `cd crates/granary-core `, \
         so the scoping below is blind"
    );
    let ours: Vec<&str> = run_lines
        .iter()
        .copied()
        .filter(|l| l.contains("cd crates/granary-fuse "))
        .collect();
    let ran: std::collections::BTreeSet<&str> = ours
        .iter()
        .filter_map(|l| l.split("cargo fuzz run ").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .collect();
    // What this workspace registers: its `[[bin]]` names (the package's own
    // `name` line filtered out) and its target files. Both must equal what runs.
    let manifest = read("crates/granary-fuse/fuzz/Cargo.toml");
    let bins: std::collections::BTreeSet<String> = manifest
        .lines()
        .filter_map(|l| l.trim().strip_prefix("name = \""))
        .filter_map(|v| v.strip_suffix('"'))
        .filter(|n| *n != "granary-fuse-fuzz")
        .map(str::to_owned)
        .collect();
    let files: std::collections::BTreeSet<String> = names_in(
        &repo_root().join("crates/granary-fuse/fuzz/fuzz_targets"),
        |p| p.extension().is_some_and(|e| e == "rs"),
    )
    .into_iter()
    .filter_map(|f| f.strip_suffix(".rs").map(str::to_owned))
    .collect();
    let corpora = names_in(&corpus_root(), Path::is_dir);
    let registered: std::collections::BTreeSet<String> = REGISTRY
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let ran_owned: std::collections::BTreeSet<String> =
        ran.iter().map(|t| (*t).to_owned()).collect();
    assert!(
        !bins.is_empty(),
        "no [[bin]] was read from the fuzz manifest"
    );
    for (what, set) in [
        ("fuzz/Cargo.toml [[bin]] names", &bins),
        ("fuzz_targets/*.rs", &files),
        ("fuzz/corpus/ directories", &corpora),
        ("fuzz.yml's granary-fuse run lines", &ran_owned),
    ] {
        assert_eq!(set, &registered, "{what} vs this test's REGISTRY");
    }
    // The store suite checks every target's flags and the total lane budget.
    for (core_form, fuse_form, why) in [
        (
            "crates/granary-core/fuzz -> target",
            "crates/granary-fuse/fuzz -> target",
            "rust-cache must know the workspace or the lane rebuilds its whole graph every week",
        ),
        (
            "path: crates/granary-core/fuzz/artifacts/",
            "path: crates/granary-fuse/fuzz/artifacts/",
            "a fuse crash writes its reproducer under the FUSE workspace; an upload step \
             pointed elsewhere silently discards it",
        ),
    ] {
        assert!(
            contains_uncommented(&fuzz_yml, core_form),
            "POSITIVE CONTROL FAILED: fuzz.yml does not carry `{core_form}` on a live line"
        );
        assert!(
            contains_uncommented(&fuzz_yml, fuse_form),
            "fuzz.yml is missing `{fuse_form}` on a live line — {why}"
        );
    }
}

/// Every corpus file must replay through the SAME probe the libFuzzer
/// target calls — panic-free. The probe repeats the selector's decoder, so
/// its equality assertion is not an independent correctness oracle. Expected
/// selection counts and refusals are checked separately below.
#[test]
fn the_committed_corpus_replays_clean() {
    for (name, probe) in REGISTRY {
        let dir = corpus_root().join(name);
        let files = names_in(&dir, Path::is_file);
        for file in &files {
            let path = dir.join(file);
            let bytes =
                std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            probe(&bytes);
        }
        assert!(
            !files.is_empty(),
            "the corpus dir {} is empty — a positive control with nothing to replay verifies \
             nothing",
            dir.display()
        );
    }
}

/// Check matching, absent and refused outcomes for the parser test fixtures.
#[test]
fn corpus_covers_selected_rows_and_refusals() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    let expected = [
        ("escaped-space", Some(1)),
        ("escaped-controls", Some(1)),
        ("non-utf8", Some(1)),
        ("absent", Some(0)),
        ("torn-final-line", None),
        ("bad-octal", None),
        ("trailing-backslash", None),
        ("octal-overflow", None),
        ("non-numeric-id", None),
        ("bad-device", None),
    ];
    let dir = corpus_root().join("mountinfo_body");
    let files = names_in(&dir, Path::is_file);
    let registered = expected
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    assert_eq!(files, registered, "every seed needs an expected outcome");
    for (name, count) in expected {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let separator = bytes.iter().position(|&b| b == 0).unwrap();
        let (wanted, rest) = bytes.split_at(separator);
        let body = rest.strip_prefix(&[0]).unwrap();
        let rows = granary_fuse::mountinfo_rows_at(body, Path::new(OsStr::from_bytes(wanted)));
        assert_eq!(rows.as_ref().ok().map(Vec::len), count, "seed {name}");
    }
}

#[test]
fn adversarial_shapes_never_panic() {
    for bytes in [b"".as_slice(), b"\xff\xfe", b"\0", b"/tmp/mine\0"] {
        granary_fuse::fuzz_probe::mountinfo_body_probe(bytes);
    }
}
