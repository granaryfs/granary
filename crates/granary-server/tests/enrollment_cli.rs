// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The shipped binary's command line: no arguments serves and requires
//! configuration, an unknown argument is a usage exit, and enrollment verbs
//! round-trip through the process.
//!
//! Every verb passes `--accept-unsupported-filesystem`: macOS, where this
//! runs first, has no filesystem type table, and the type check is the
//! library's tests' subject.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test code (standards rule 3): the helpers' failures are the test's"
)]

#[path = "process/output.rs"]
mod output;
mod process;
use output::CommandExt as _;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use granary_server::{EXIT_REFUSED, EXIT_STARTUP_FAILED, EXIT_USAGE, EXIT_VERB_DONE};

/// A fresh enrollment directory, mode 0o700, under the canonical temporary
/// directory (on macOS `/var` is a link, which the walk refuses).
fn enrollment_dir(tag: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    #[expect(
        clippy::disallowed_methods,
        reason = "`std::process::id` names a scratch directory so two test binaries do not share \
                  one; nothing under test reads it"
    )]
    let pid = std::process::id();
    let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "granary-enrollment-cli-{tag}-{pid}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = base.join("enroll");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// Run the binary with `args` and a clean environment.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_granary-server"))
        .env_clear()
        .args(args)
        .guarded_output()
        .unwrap()
}

fn verb(dir: &Path, words: &[&str]) -> Output {
    let mut args = vec!["enrollment"];
    args.extend_from_slice(words);
    args.extend_from_slice(&[
        "--dir",
        dir.to_str().unwrap(),
        "--accept-unsupported-filesystem",
    ]);
    run(&args)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[track_caller]
fn assert_exit(out: &Output, code: i32) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

const DIGEST_A: &str =
    "clientspki-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str =
    "clientspki-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn no_arguments_still_serves_and_refuses_without_its_configuration() {
    let out = run(&[]);
    assert_exit(&out, EXIT_STARTUP_FAILED);
    assert!(
        text(&out.stderr).contains("GRANARY_LISTEN"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn an_unknown_first_argument_is_a_usage_exit() {
    for args in [
        vec!["serve"],
        vec!["--help"],
        vec!["enrollment"],
        vec!["enrollment", "nope"],
    ] {
        let out = run(&args);
        assert_exit(&out, EXIT_USAGE);
        let err = text(&out.stderr);
        assert!(err.contains("usage:"), "{args:?}");
        assert!(err.contains("granary-server enrollment"), "{args:?}");
        assert!(err.contains("granary-server debug-grant"), "{args:?}");
        if args.first().is_some_and(|command| *command != "enrollment") {
            assert!(
                err.contains("the commands are `enrollment`, `debug-grant`, `support-export`, `initialise` and `unfence`"),
                "{args:?}"
            );
        }
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn a_mutating_verb_succeeds_without_acknowledgement() {
    let dir = enrollment_dir("mint");
    let out = verb(
        &dir,
        &["mint", "--tenant", "acme", "--credential", DIGEST_A],
    );
    assert_exit(&out, EXIT_VERB_DONE);
    assert_eq!(entries(&dir), vec!["ENROLLMENT"]);
}

#[test]
fn the_verbs_round_trip_through_the_binary() {
    let dir = enrollment_dir("round");

    let out = verb(&dir, &["list"]);
    assert_exit(&out, EXIT_REFUSED);
    assert!(text(&out.stdout).starts_with("unavailable missing"));

    let out = verb(
        &dir,
        &["mint", "--tenant", "acme", "--credential", DIGEST_A],
    );
    assert_exit(&out, EXIT_VERB_DONE);
    let line = text(&out.stdout);
    let (principal, digest) = line.trim_end().split_once(' ').unwrap();
    assert!(
        principal.starts_with("principal:") && principal.len() == 42,
        "{line}"
    );
    assert_eq!(digest, DIGEST_A);

    let out = verb(
        &dir,
        &["attach", "--principal", principal, "--credential", DIGEST_B],
    );
    assert_exit(&out, EXIT_VERB_DONE);
    let out = verb(&dir, &["revoke", "--credential", DIGEST_A]);
    assert_exit(&out, EXIT_VERB_DONE);
    assert_eq!(text(&out.stdout), format!("{principal} {DIGEST_A}\n"));

    let out = verb(&dir, &["retire", "--principal", principal]);
    assert_exit(&out, EXIT_REFUSED);
    assert!(text(&out.stderr).contains("revoke it first"));
    let out = verb(&dir, &["revoke", "--credential", DIGEST_B]);
    assert_exit(&out, EXIT_VERB_DONE);
    let out = verb(&dir, &["retire", "--principal", principal]);
    assert_exit(&out, EXIT_VERB_DONE);
    assert_eq!(text(&out.stdout), format!("{principal}\n"));

    let out = verb(&dir, &["list"]);
    assert_exit(&out, EXIT_VERB_DONE);
    assert_eq!(
        text(&out.stdout),
        format!("ok principals=1 credentials=0\nprincipal {principal} retired acme\n")
    );
    assert_eq!(entries(&dir), vec!["ENROLLMENT"], "no lock file");
}
