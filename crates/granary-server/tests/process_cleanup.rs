// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socket-free controls for process ownership on timeout and unwind.
#![cfg(unix)]
#[path = "process/output.rs"]
mod output;
mod process;
use output::CommandExt as _;
use process::ChildGuard;
use std::process::{Command, Stdio};
use std::time::Duration;

fn sleeper() -> ChildGuard {
    ChildGuard(
        Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("sleep fixture: {error}")),
    )
}

fn alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn assert_gone(pid: u32) {
    let survived = alive(pid);
    if survived {
        // The negative control still owns this planted process.
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    assert!(!survived, "owned child survived guard teardown");
}

#[test]
fn timeout_keeps_child_owned_until_drop() {
    let mut child = sleeper();
    let pid = child.0.id();
    let status = child.wait_within(Duration::from_millis(20));
    assert!(matches!(status, Ok(None)), "wait result: {status:?}");
    assert!(alive(pid), "timeout fixture already dead: pid={pid}");
    drop(child);
    assert_gone(pid);
}

#[test]
fn unwind_kills_and_reaps_child() {
    let child = sleeper();
    let pid = child.0.id();
    assert!(alive(pid), "unwind fixture already dead: pid={pid}");
    let result = std::panic::catch_unwind(move || {
        let _owned = child;
        assert_eq!(0, 1, "injected fixture failure");
    });
    assert!(result.is_err(), "injected unwind did not occur");
    assert_gone(pid);
}

#[test]
fn successful_wait_observes_exit_status() {
    let mut child = ChildGuard(
        Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap_or_else(|error| panic!("exit fixture: {error}")),
    );
    let status = child
        .wait_within(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("waiting: {error}"));
    assert_eq!(status.and_then(|s| s.code()), Some(7));
}

#[test]
fn capture_drains_both_pipes_and_observes_status() {
    let output = Command::new("/bin/sh")
        .args(["-c", "printf out; dd if=/dev/zero bs=65536 count=2 2>/dev/null; printf err >&2; (dd if=/dev/zero bs=65536 count=2 2>/dev/null) >&2; exit 7"])
        .guarded_output()
        .unwrap_or_else(|error| panic!("capture fixture: {error}"));
    assert_eq!(
        (
            output.status.code(),
            output.stdout.len(),
            output.stderr.len(),
            output.stdout.starts_with(b"out"),
            output.stderr.starts_with(b"err"),
            output
                .stdout
                .get(3..)
                .is_some_and(|s| s.iter().all(|b| *b == 0)),
            output
                .stderr
                .get(3..)
                .is_some_and(|s| s.iter().all(|b| *b == 0))
        ),
        (Some(7), 131_075, 131_075, true, true, true, true)
    );
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "process ID isolates fixture scratch"
)]
fn capture_timeout_refuses_and_reaps_child() {
    let path = std::env::temp_dir().join(format!("granary-capture-{}", std::process::id()));
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "echo $$ > \"$1\"; exec sleep 30", "fixture"])
        .arg(&path);
    let result = output::output_within(&mut command, Duration::from_millis(200));
    let pid = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| {
            panic!("capture fixture did not record pid: {error}; result={result:?}")
        })
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("capture pid: {error}"));
    let _ = std::fs::remove_file(&path);
    let gone = !alive(pid);
    if !gone {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    let refused = result.as_ref().err().map(|e| (e.kind(), e.to_string()));
    assert_eq!(
        (refused, gone),
        (
            Some((
                std::io::ErrorKind::TimedOut,
                "child did not exit within fixture bound".to_owned()
            )),
            true
        ),
        "capture result: {result:?}"
    );
}
