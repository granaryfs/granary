// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, exit};

const USAGE: &str =
    "Usage: cargo run --quiet --locked --package xtask -- <task>\nTasks: check  check-full  --help";
const WORKSPACE_MARKERS: &[&str] = &[
    "Cargo.toml",
    "xtask/Cargo.toml",
    "crates/granary-core/Cargo.toml",
    "crates/granary-vfs/Cargo.toml",
];
const REQUIRED_MEMBERS: &[(&str, &str)] = &[
    ("xtask/Cargo.toml", "xtask"),
    ("crates/granary-core/Cargo.toml", "granary-core"),
    ("crates/granary-vfs/Cargo.toml", "granary-vfs"),
];
fn cargo_executable() -> PathBuf {
    // Cargo sets CARGO to its absolute executable path for `cargo run`. Reuse it
    // when relative PATH entries would change meaning after changing directory.
    let has_relative_path = env::var_os("PATH")
        .is_some_and(|path| env::split_paths(&path).any(|entry| !entry.is_absolute()));
    if let Some(cargo) =
        env::var_os("CARGO").filter(|cargo| has_relative_path && Path::new(cargo).is_absolute())
    {
        return PathBuf::from(cargo);
    }
    PathBuf::from("cargo")
}

fn cargo_output(cwd: &Path, args: &[&str], cargo_executable: &Path) -> Option<String> {
    let output = Command::new(cargo_executable)
        .args(args)
        .current_dir(cwd)
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|err| {
            eprintln!("could not launch cargo {}: {err}", args.join(" "));
            exit(if err.kind() == ErrorKind::NotFound {
                127
            } else {
                1
            });
        });
    if !output.status.success() {
        #[cfg(unix)]
        if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&output.status) {
            eprintln!("cargo {} terminated by signal {signal}", args.join(" "));
            exit(128 + signal);
        }
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}
fn is_granary_workspace(root: &Path, manifest: &Path, cargo_executable: &Path) -> bool {
    if !WORKSPACE_MARKERS
        .iter()
        .all(|marker| root.join(marker).is_file())
    {
        return false;
    }
    for &(marker, name) in REQUIRED_MEMBERS {
        let member_manifest = root.join(marker);
        let Some(member_manifest) = member_manifest.to_str() else {
            return false;
        };
        let member_root = cargo_output(
            root,
            &[
                "locate-project",
                "--workspace",
                "--message-format",
                "plain",
                "--manifest-path",
                member_manifest,
            ],
            cargo_executable,
        );
        if member_root.as_deref() != manifest.to_str() {
            return false;
        }
        let Some(at_marker) = cargo_output(
            root,
            &["pkgid", "--locked", "--manifest-path", member_manifest],
            cargo_executable,
        ) else {
            return false;
        };
        let by_name = cargo_output(
            root,
            &[
                "pkgid",
                "--locked",
                "--manifest-path",
                member_manifest,
                "-p",
                name,
            ],
            cargo_executable,
        );
        if by_name.as_ref() != Some(&at_marker) {
            return false;
        }
    }
    true
}
fn cargo(root: &Path, args: &[&str], cargo_executable: &Path) {
    let status = Command::new(cargo_executable)
        .args(args)
        .current_dir(root)
        .env("CARGO_BUILD_WARNINGS", "deny")
        .status()
        .unwrap_or_else(|err| {
            eprintln!("could not launch cargo {}: {err}", args.join(" "));
            exit(if err.kind() == ErrorKind::NotFound {
                127
            } else {
                1
            });
        });
    if !status.success() {
        eprintln!("cargo {} failed: {status}", args.join(" "));
        #[cfg(unix)]
        if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
            exit(128 + signal);
        }
        exit(status.code().unwrap_or(1));
    }
}

#[expect(
    clippy::unnecessary_debug_formatting,
    reason = "escape control characters in untrusted arguments"
)]
fn main() {
    let mut args = env::args_os().skip(1);
    let Some(task) = args.next() else {
        eprintln!("missing task\n{USAGE}");
        exit(2);
    };
    if let Some(extra) = args.next() {
        eprintln!("unexpected argument: {extra:?}\n{USAGE}");
        exit(2);
    }
    let full = match task.to_str() {
        Some("check") => false,
        Some("check-full") => true,
        Some("help" | "--help") => {
            println!("{USAGE}");
            return;
        }
        _ => {
            eprintln!("unknown task: {task:?}\n{USAGE}");
            exit(2);
        }
    };

    let cwd = env::current_dir().unwrap_or_else(|err| {
        eprintln!("cannot determine current directory: {err}");
        exit(1);
    });
    let cargo_executable = cargo_executable();
    let locate = ["locate-project", "--workspace", "--message-format", "plain"];
    let lookup = Command::new(&cargo_executable)
        .args(locate)
        .current_dir(&cwd)
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|err| {
            eprintln!("could not launch cargo {}: {err}", locate.join(" "));
            exit(if err.kind() == ErrorKind::NotFound {
                127
            } else {
                1
            });
        });
    if !lookup.status.success() {
        eprintln!("cannot find workspace root from {}", cwd.display());
        #[cfg(unix)]
        if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&lookup.status) {
            exit(128 + signal);
        }
        exit(1);
    }
    let manifest = String::from_utf8(lookup.stdout).unwrap_or_else(|err| {
        eprintln!("cargo locate-project returned a non-UTF-8 path: {err}");
        exit(1);
    });
    let manifest = manifest.strip_suffix('\n').unwrap_or(&manifest);
    let manifest = manifest.strip_suffix('\r').unwrap_or(manifest);
    let manifest = Path::new(manifest);
    if !manifest.is_absolute() || manifest.file_name() != Some(OsStr::new("Cargo.toml")) {
        eprintln!("cargo locate-project returned an invalid workspace manifest");
        exit(1);
    }
    let root = manifest.parent().unwrap_or_else(|| {
        eprintln!("cargo locate-project returned a workspace manifest without a parent");
        exit(1);
    });
    if !is_granary_workspace(root, manifest, &cargo_executable) {
        eprintln!("not a Granary workspace: {}", root.display());
        exit(1);
    }

    cargo(root, &["fmt", "--check"], &cargo_executable);
    cargo(
        root,
        &["clippy", "--workspace", "--all-targets", "--locked"],
        &cargo_executable,
    );
    let mut nextest = vec![
        "nextest",
        "run",
        "--profile",
        "ci",
        "--locked",
        "--retries",
        "0",
        "--no-tests",
        "fail",
    ];
    if full {
        nextest.push("--workspace");
    } else {
        nextest.extend(["-p", "granary-core", "-p", "granary-vfs"]);
    }
    cargo(root, &nextest, &cargo_executable);
    if full {
        cargo(
            root,
            &["test", "--doc", "--locked", "--workspace"],
            &cargo_executable,
        );
    }
}
