// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;

const PROBE_COMPLETED: &str = "discard plan refusal probe completed";

#[test]
fn plan_and_discard_require_distinct_exact_flags() {
    let mut args = ["discard", "--store-dir", "/store", "--scope"]
        .map(OsString::from)
        .to_vec();
    args.push("11".repeat(32).into());
    args.extend(["--volume", "vol"].map(OsString::from));
    assert!(parse(&args).is_none());
    let mut plan = args.clone();
    plan.push("--plan".into());
    assert!(parse(&plan).is_some_and(|args| args.selection.is_none()));
    args.extend(
        [
            "--writer",
            &"22".repeat(16),
            "--journal-incarnation",
            &"33".repeat(32),
            "--acknowledge-unsynced-loss",
        ]
        .map(OsString::from),
    );
    assert!(parse(&args).is_none());
    args.push("--acknowledge-may-land".into());
    assert!(parse(&args).is_some_and(|args| args.selection.is_some()));
    args.push("--plan".into());
    assert!(parse(&args).is_none());
}

#[test]
fn discard_plan_refusal_survives_broken_stderr() {
    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::{Command, Stdio},
    };

    let (stderr, peer) = UnixStream::pair().unwrap();
    drop(peer);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "overlay_discard::tests::discard_plan_refusal_probe",
            "--nocapture",
        ])
        .stderr(Stdio::from(OwnedFd::from(stderr)))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.lines().any(|line| line == PROBE_COMPLETED),
        "discard probe did not complete: {stdout}"
    );
}

#[test]
fn discard_plan_refusal_probe() {
    let scratch = crate::tests::ScratchDir::new();
    let args = [
        "discard".into(),
        "--plan".into(),
        "--store-dir".into(),
        scratch.0.join("missing").into_os_string(),
        "--scope".into(),
        "11".repeat(32).into(),
        "--volume".into(),
        "vol".into(),
    ];
    let log = std::sync::Mutex::new(Vec::new());
    assert_eq!(
        invoke_discard(&parse(&args).unwrap(), &log),
        ExitCode::FAILURE
    );
    assert_eq!(
        log.into_inner().unwrap(),
        concat!(
            "{\"level\":\"WARN\",\"target\":\"granary_client::event\",",
            "\"event\":\"overlay.discard_refused\",\"reason\":\"OverlayDiscardMissing\"}\n"
        )
        .as_bytes()
    );
    println!("{PROBE_COMPLETED}");
}
