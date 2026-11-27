// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::io::ErrorKind;
use std::path::Path;
use std::process::{Command, exit};

const USAGE: &str = "Usage: cargo xtask <task>\nTasks: check  check-full  --help";

fn cargo(root: &Path, args: &[&str]) {
    let status = Command::new("cargo")
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
    let Some(root) = cwd
        .ancestors()
        .find(|p| p.join("Cargo.toml").is_file() && p.join("xtask/Cargo.toml").is_file())
    else {
        eprintln!("cannot find workspace root from {}", cwd.display());
        exit(1);
    };

    cargo(root, &["fmt", "--check"]);
    cargo(
        root,
        &["clippy", "--workspace", "--all-targets", "--locked"],
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
    if !full {
        nextest.extend(["-p", "granary-core", "-p", "granary-vfs"]);
    }
    cargo(root, &nextest);
    if full {
        cargo(root, &["test", "--doc", "--locked"]);
    }
}
