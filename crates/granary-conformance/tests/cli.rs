// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![expect(
    clippy::expect_used,
    reason = "test harness setup failures are unrecoverable fixture errors"
)]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use granary_conformance::gendir::{PlannedNode, build_plan};
use granary_conformance::row::{DType, Kind, Payload, Row, new_row, render_line};

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("granconf-cli-test-{name}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create CLI scratch directory");
        Self(path)
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

fn file(path: &str, size: u64, content: char) -> Row {
    new_row(
        path.as_bytes().to_vec(),
        Kind::File,
        DType::File,
        Some(size),
        false,
        Payload::Content(content.to_string().repeat(64)),
    )
    .expect("valid file row")
}

fn write_dump(path: &Path, rows: &[Row]) {
    let mut text = rows.iter().map(render_line).collect::<Vec<_>>().join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    fs::write(path, text).expect("write dump");
}

fn run(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_granconf"))
        .args(args)
        .output()
        .expect("run granconf")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("granconf stdout is UTF-8")
}

#[test]
fn compare_identical_exits_zero_and_prints_the_stable_marker() {
    let dir = ScratchDir::new("identical");
    let a = dir.join("a.dump");
    let b = dir.join("b.dump");
    let rows = [file("same", 1, 'a')];
    write_dump(&a, &rows);
    write_dump(&b, &rows);

    let output = run(&[OsStr::new("compare"), a.as_os_str(), b.as_os_str()]);
    let text = stdout(&output);
    assert!(output.status.success(), "stdout:\n{text}");
    assert!(
        text.lines().any(|line| {
            line == "CONFORM: SUMMARY presence=0 kind=0 size=0 exec=0 content=0 target=0 dtype=0 equal=1"
        }),
        "stable summary marker missing from stdout:\n{text}"
    );
    assert!(
        text.lines()
            .any(|line| line == "CONFORM: identical, 1 rows"),
        "stable identical marker missing from stdout:\n{text}"
    );
}

#[test]
fn compare_divergence_exits_nonzero_and_prints_the_stable_marker() {
    let dir = ScratchDir::new("divergence");
    let a = dir.join("a.dump");
    let b = dir.join("b.dump");
    write_dump(&a, &[file("same", 1, 'a')]);
    write_dump(&b, &[file("same", 1, 'b')]);

    let output = run(&[OsStr::new("compare"), a.as_os_str(), b.as_os_str()]);
    let text = stdout(&output);
    assert!(!output.status.success(), "stdout:\n{text}");
    assert!(
        text.lines()
            .any(|line| line == "CONFORM: DIVERGE content same"),
        "stable divergence marker missing from stdout:\n{text}"
    );
    assert!(
        text.lines().any(|line| {
            line == "CONFORM: SUMMARY presence=0 kind=0 size=0 exec=0 content=1 target=0 dtype=0 equal=0"
        }),
        "stable summary marker missing from stdout:\n{text}"
    );
    assert!(
        text.lines()
            .any(|line| line == "CONFORM: NOT identical: diverged in content"),
        "stable non-identical marker missing from stdout:\n{text}"
    );
}

#[test]
fn compare_two_empty_dumps_exits_nonzero() {
    let dir = ScratchDir::new("empty");
    let a = dir.join("a.dump");
    let b = dir.join("b.dump");
    fs::write(&a, "").expect("write first empty dump");
    fs::write(&b, "").expect("write second empty dump");

    let output = run(&[OsStr::new("compare"), a.as_os_str(), b.as_os_str()]);
    let text = stdout(&output);
    assert!(!output.status.success(), "stdout:\n{text}");
    assert!(
        text.contains("CONFORM: NOT identical: no rows compared equal"),
        "stable empty-comparison marker missing from stdout:\n{text}"
    );
}

#[test]
fn compare_expect_content_exercises_success_and_failure_statuses() {
    let dir = ScratchDir::new("expect-content");
    let a = dir.join("a.dump");
    let b = dir.join("b.dump");
    let c = dir.join("c.dump");
    write_dump(&a, &[file("equal", 1, 'c'), file("changed", 2, 'a')]);
    write_dump(&b, &[file("equal", 1, 'c'), file("changed", 2, 'b')]);
    write_dump(&c, &[file("equal", 1, 'c'), file("changed", 2, 'a')]);

    let pass = run(&[
        OsStr::new("compare"),
        a.as_os_str(),
        b.as_os_str(),
        OsStr::new("--expect"),
        OsStr::new("content"),
    ]);
    let pass_text = stdout(&pass);
    assert!(pass.status.success(), "stdout:\n{pass_text}");
    assert!(
        pass_text
            .lines()
            .any(|line| line == "CONFORM: PASS --expect content"),
        "stable expect-pass marker missing from stdout:\n{pass_text}"
    );

    let fail = run(&[
        OsStr::new("compare"),
        a.as_os_str(),
        c.as_os_str(),
        OsStr::new("--expect"),
        OsStr::new("content"),
    ]);
    let fail_text = stdout(&fail);
    assert!(!fail.status.success(), "stdout:\n{fail_text}");
    assert!(
        fail_text
            .lines()
            .any(|line| line.starts_with("CONFORM: FAIL --expect content:")),
        "stable expect-fail marker missing from stdout:\n{fail_text}"
    );
}

fn rows_for_complete_plan() -> Vec<Row> {
    build_plan(19)
        .entries
        .into_iter()
        .map(|entry| {
            let (kind, dtype, size, exec, payload) = match entry.node {
                PlannedNode::Dir => (Kind::Dir, DType::Dir, None, false, Payload::None),
                PlannedNode::File { size, exec, .. } => (
                    Kind::File,
                    DType::File,
                    Some(size),
                    exec,
                    Payload::Content("a".repeat(64)),
                ),
                PlannedNode::Symlink { target } => (
                    Kind::Symlink,
                    DType::Symlink,
                    None,
                    false,
                    Payload::Target(target),
                ),
            };
            new_row(entry.path, kind, dtype, size, exec, payload).expect("valid planned row")
        })
        .collect()
}

#[test]
fn verify_cases_cli_accepts_a_complete_dump_and_rejects_an_inadequate_one() {
    let dir = ScratchDir::new("verify-cases");
    let good = dir.join("good.dump");
    let bad = dir.join("bad.dump");
    write_dump(&good, &rows_for_complete_plan());
    let inadequate = new_row(
        b"ordinary".to_vec(),
        Kind::Dir,
        DType::Dir,
        None,
        false,
        Payload::None,
    )
    .expect("valid inadequate row");
    write_dump(&bad, &[inadequate]);

    let pass = run(&[OsStr::new("verify-cases"), good.as_os_str()]);
    let pass_text = stdout(&pass);
    assert!(pass.status.success(), "stdout:\n{pass_text}");
    assert!(
        pass_text
            .lines()
            .any(|line| line == "VERIFY: name-len-1 PASS"),
        "verify-cases PASS markers missing from stdout:\n{pass_text}"
    );

    let fail = run(&[OsStr::new("verify-cases"), bad.as_os_str()]);
    let fail_text = stdout(&fail);
    assert!(!fail.status.success(), "stdout:\n{fail_text}");
    assert!(
        fail_text
            .lines()
            .any(|line| line.starts_with("VERIFY: name-len-1 FAIL:")),
        "verify-cases FAIL markers missing from stdout:\n{fail_text}"
    );
}
