// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt as _;

use super::super::cli::run_on;
use super::*;
use crate::protected_dir::tests::{Call, Phase, Recorder};

fn issue_args(fx: &Fx) -> Vec<OsString> {
    [
        "debug-grant",
        "issue",
        "--dir",
        fx.dir.to_str().unwrap(),
        "--accept-unsupported-filesystem",
        "--incarnation",
        "incarnation:42424242424242424242424242424242",
        "--expected-revision",
        "0",
        "--volume",
        "data",
        "--duration-secs",
        "600",
        "--lines",
        "50",
        "--bytes",
        "50000",
        "--owner",
        "operator",
        "--reason",
        "incident",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}
fn run(ops: &impl crate::protected_dir::DirOps, args: &[OsString]) -> (i32, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_on(ops, args, &NOW, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}
fn replace(args: &mut [OsString], flag: &str, value: OsString) {
    let at = args.iter().position(|a| a == flag).unwrap();
    args[at + 1] = value;
}

#[test]
fn debug_grant_cli_rejects_every_missing_repeated_unknown_and_malformed_argument() {
    let fx = Fx::new();
    let good = issue_args(&fx);
    for at in (0..good.len()).filter(|&n| {
        good[n].to_str().is_some_and(|s| s.starts_with("--"))
            && good[n] != "--accept-unsupported-filesystem"
    }) {
        let mut args = good.clone();
        args.drain(at..at + 2);
        assert_eq!(run(&NixOps, &args).0, 64, "missing {:?}", good[at]);
        let mut args = good.clone();
        args.extend_from_slice(&good[at..at + 2]);
        assert_eq!(run(&NixOps, &args).0, 64, "repeated {:?}", good[at]);
    }
    let cases = [
        ("--dir", "relative"),
        ("--incarnation", "42424242424242424242424242424242"),
        (
            "--incarnation",
            "incarnation:AB424242424242424242424242424242",
        ),
        ("--incarnation", "incarnation:00"),
        ("--expected-revision", "+0"),
        ("--expected-revision", "00"),
        ("--expected-revision", "-1"),
        ("--expected-revision", "18446744073709551616"),
        ("--volume", "*"),
        ("--volume", "Data"),
        ("--volume", "-data"),
        ("--volume", "data-"),
        ("--volume", ""),
        ("--duration-secs", "0"),
        ("--duration-secs", "901"),
        ("--duration-secs", "01"),
        ("--duration-secs", "x"),
        ("--lines", "0"),
        ("--lines", "1025"),
        ("--bytes", "0"),
        ("--bytes", "1023"),
        ("--bytes", "1048577"),
        ("--owner", ""),
        ("--owner", "has space"),
        ("--owner", "\n"),
        ("--reason", ""),
        ("--reason", "has space"),
        ("--reason", "é"),
    ];
    for (flag, value) in cases {
        let mut args = good.clone();
        replace(&mut args, flag, value.into());
        assert_eq!(run(&NixOps, &args).0, 64, "{flag}={value:?}");
    }
    for (flag, value) in [
        ("--owner", "a".repeat(65)),
        ("--reason", "a".repeat(257)),
        ("--volume", "a".repeat(64)),
    ] {
        let mut args = good.clone();
        replace(&mut args, flag, value.into());
        assert_eq!(run(&NixOps, &args).0, 64);
    }
    assert_eq!(fx.bytes(), None);
}

#[test]
fn debug_grant_cli_unknown_inapplicable_non_text_and_principal_refusals() {
    let fx = Fx::new();
    let good = issue_args(&fx);
    for tail in [
        vec!["--unknown", "secret"],
        vec!["--level", "TRACE"],
        vec!["--generation", "1"],
        vec!["--accept-unsupported-filesystem"],
        vec!["--owner"],
    ] {
        let mut args = good.clone();
        args.extend(tail.iter().map(OsString::from));
        let (code, _, err) = run(&NixOps, &args);
        assert_eq!(code, 64);
        assert!(!err.contains("secret"));
    }
    for principal in [
        "principal:01",
        "principal:AB010101010101010101010101010101",
        "*",
    ] {
        let mut args = good.clone();
        args.extend([OsString::from("--principal"), OsString::from(principal)]);
        assert_eq!(run(&NixOps, &args).0, 64);
    }
    let mut args = good.clone();
    replace(&mut args, "--reason", OsString::from_vec(vec![0xff]));
    assert_eq!(run(&NixOps, &args).0, 64);
    for args in [
        vec![],
        vec![OsString::from("debug-grant")],
        vec![OsString::from("debug-grant"), OsString::from("unknown")],
        vec![OsString::from("elsewhere")],
    ] {
        assert_eq!(run(&NixOps, &args).0, 64);
    }
    assert_eq!(fx.bytes(), None);
}

fn narrow_args(fx: &Fx) -> Vec<OsString> {
    [
        "debug-grant",
        "narrow",
        "--dir",
        fx.dir.to_str().unwrap(),
        "--accept-unsupported-filesystem",
        "--incarnation",
        "incarnation:42424242424242424242424242424242",
        "--expected-revision",
        "4",
        "--generation",
        "2",
        "--volume",
        "data",
        "--expires-at",
        "600.000000000",
        "--lines",
        "0",
        "--bytes",
        "0",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

#[test]
fn debug_grant_cli_timestamp_generation_and_verb_flag_refusals() {
    let fx = Fx::new();
    let good = narrow_args(&fx);
    for (flag, value) in [
        ("--generation", "0"),
        ("--generation", "02"),
        ("--expires-at", "600"),
        ("--expires-at", "600.0"),
        ("--expires-at", "600.1000000000"),
        ("--expires-at", "600.abcdefghi"),
        ("--expires-at", "+600.000000000"),
        ("--expires-at", "0600.000000000"),
        ("--expires-at", "-0.000000000"),
        ("--expires-at", "9223372036854775808.000000000"),
        ("--lines", "1025"),
        ("--bytes", "1048577"),
    ] {
        let mut args = good.clone();
        replace(&mut args, flag, value.into());
        assert_eq!(run(&NixOps, &args).0, 64, "{flag} {value}");
    }
    for verb in ["show", "revoke"] {
        let mut args = good.clone();
        args[1] = verb.into();
        assert_eq!(run(&NixOps, &args).0, 64);
    }
    for at in (0..good.len()).filter(|&n| {
        good[n].to_str().is_some_and(|s| s.starts_with("--"))
            && good[n] != "--accept-unsupported-filesystem"
    }) {
        let mut args = good.clone();
        args.drain(at..at + 2);
        assert_eq!(run(&NixOps, &args).0, 64);
    }
    assert_eq!(fx.bytes(), None);
}

#[test]
fn debug_grant_cli_show_and_escaped_bounded_written_report() {
    let fx = Fx::new();
    let mut args = issue_args(&fx);
    replace(&mut args, "--owner", "\"\\={}".into());
    replace(&mut args, "--reason", "\\".repeat(256).into());
    let (code, out, err) = run(&NixOps, &args);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("event=debug_grant_issue phase=written"));
    assert!(out.contains("file_revision=1 generation=1 scope=volume"));
    assert!(out.contains("owner=\"\\\"\\\\={}\""), "{out}");
    assert_eq!(out.lines().count(), 1);
    assert!(out.len() < 2000);
    assert!(!out.contains("phase=applied"));
    let show: Vec<OsString> = [
        "debug-grant",
        "show",
        "--dir",
        fx.dir.to_str().unwrap(),
        "--accept-unsupported-filesystem",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let (code, out, _) = run(&NixOps, &show);
    assert_eq!(code, 0);
    assert!(out.contains("state=present"));
    assert!(!out.contains("phase=written"));
    std::fs::remove_file(fx.dir.join(NAME)).unwrap();
    let (code, out, _) = run(&NixOps, &show);
    assert_eq!(code, 0);
    assert_eq!(out, "state=missing\n");
}

#[test]
fn debug_grant_cli_revision_mismatch_preserves_published_bytes() {
    let fx = Fx::new();
    fx.put(&base(GrantScope::Volume(volume("data"))));
    let before = fx.bytes();
    let mut args = narrow_args(&fx);
    replace(&mut args, "--expected-revision", "3".into());
    let (code, out, err) = run(&NixOps, &args);
    assert_eq!(
        (
            code,
            out.is_empty(),
            err.contains("revision-mismatch"),
            fx.bytes()
        ),
        (65, true, true, before),
        "stale revision must refuse before publication: out={out:?} err={err:?}"
    );
    let (code, out, err) = run(&NixOps, &narrow_args(&fx));
    assert_eq!(
        (code, out.contains("debug_grant_narrow phase=written")),
        (0, true),
        "matching revision positive control: out={out:?} err={err:?}"
    );
}

#[test]
fn debug_grant_cli_narrow_revoke_and_io_exit_codes() {
    let fx = Fx::new();
    fx.put(&base(GrantScope::Volume(volume("data"))));
    let (code, out, err) = run(&NixOps, &narrow_args(&fx));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("debug_grant_narrow phase=written"));
    let revoke: Vec<OsString> = [
        "debug-grant",
        "revoke",
        "--dir",
        fx.dir.to_str().unwrap(),
        "--accept-unsupported-filesystem",
        "--incarnation",
        "incarnation:42424242424242424242424242424242",
        "--expected-revision",
        "5",
        "--generation",
        "2",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let (code, out, err) = run(&NixOps, &revoke);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("debug_grant_revoke phase=written"));
    assert_eq!(run(&NixOps, &revoke).0, 65);
    for (call, code) in [(Call::WriteAt, 65), (Call::SyncDir { ino: 0 }, 74)] {
        let fx = Fx::new();
        let rec = Recorder::new();
        rec.set_hook(move |c, p| {
            if p == Phase::Before
                && (*c == call
                    || matches!((&call, c), (Call::SyncDir { .. }, Call::SyncDir { .. })))
            {
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        });
        assert_eq!(run(&rec, &issue_args(&fx)).0, code);
    }
}

struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected output"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn debug_grant_cli_output_failure_is_uncertain_after_publication() {
    let fx = Fx::new();
    let mut err = Vec::new();
    assert_eq!(
        run_on(&NixOps, &issue_args(&fx), &NOW, &mut BrokenOutput, &mut err),
        74
    );
    assert!(granary_core::debug_grant::decode_grant(&fx.bytes().unwrap()).is_ok());
}
