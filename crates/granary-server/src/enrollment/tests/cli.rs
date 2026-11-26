// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The command line: usage, the exit codes and the output
//! forms. The binary's own dispatch is `tests/enrollment_cli.rs`.

use std::ffi::OsString;

use super::super::cli::{EXIT_REFUSED, EXIT_USAGE, EXIT_VERB_DONE, run_command_line};
use super::{Door, Fx, digest, id, one};

struct Ran {
    code: i32,
    out: String,
    err: String,
}

fn run(args: &[&str], door: &mut Door) -> Ran {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_command_line(&args, door, &mut out, &mut err);
    Ran {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

#[test]
fn an_unparseable_command_line_is_a_usage_exit() {
    let fx = Fx::new("cli-usage");
    let dir = fx.dir.to_str().unwrap();
    let d = digest(1).to_string();
    let p = id(1).to_string();
    for args in [
        vec!["serve"],
        vec!["enrollment"],
        vec!["enrollment", "frobnicate", "--dir", dir],
        vec!["enrollment", "mint", "--tenant", "t", "--dir", dir],
        vec![
            "enrollment",
            "mint",
            "--tenant",
            "t",
            "--credential",
            &d,
            "--dir",
            dir,
            "--dir",
            dir,
        ],
        vec![
            "enrollment",
            "mint",
            "--tenant",
            "has space",
            "--credential",
            &d,
            "--dir",
            dir,
        ],
        vec![
            "enrollment",
            "revoke",
            "--credential",
            &d,
            "--principal",
            &p,
            "--dir",
            dir,
        ],
        vec![
            "enrollment",
            "retire",
            "--principal",
            "principal:XYZ",
            "--dir",
            dir,
        ],
        vec![
            "enrollment",
            "revoke",
            "--credential",
            "sha256/AAAA",
            "--dir",
            dir,
        ],
        vec!["enrollment", "list", "--dir"],
        vec!["enrollment", "list", "--dir", dir, "--verbose"],
    ] {
        let ran = run(&args, &mut Door::of(&[1]));
        assert_eq!(ran.code, EXIT_USAGE, "{args:?}: {}", ran.err);
        assert!(ran.err.contains("usage:"), "{args:?}");
        assert!(ran.err.contains("granary-server enrollment"), "{args:?}");
        assert!(ran.err.contains("granary-server debug-grant"), "{args:?}");
        assert!(ran.out.is_empty(), "{args:?}");
    }
    assert!(fx.bytes().is_none());
}

#[test]
fn list_of_a_missing_set_is_unavailable() {
    let fx = Fx::new("cli-list-missing");
    let dir = fx.dir.to_str().unwrap();
    let ran = run(
        &[
            "enrollment",
            "list",
            "--dir",
            dir,
            "--accept-unsupported-filesystem",
        ],
        &mut Door::of(&[]),
    );
    assert_eq!(
        ran.code, EXIT_REFUSED,
        "list of a missing set is unavailable"
    );
    assert!(ran.out.starts_with("unavailable missing"), "{}", ran.out);
}

#[test]
fn the_verbs_print_written_forms_and_list_prints_the_verdict_first() {
    let fx = Fx::new("cli-print");
    let dir = fx.dir.to_str().unwrap();
    let d1 = digest(1).to_string();
    let d2 = digest(2).to_string();
    let p = id(7).to_string();
    let acc = "--accept-unsupported-filesystem";
    let ran = run(
        &[
            "enrollment",
            "mint",
            "--tenant",
            "acme",
            "--credential",
            &d1,
            "--dir",
            dir,
            acc,
        ],
        &mut Door::of(&[7]),
    );
    assert_eq!(
        (ran.code, ran.out.as_str()),
        (EXIT_VERB_DONE, format!("{p} {d1}\n").as_str()),
        "{}",
        ran.err
    );
    let ran = run(
        &[
            "enrollment",
            "attach",
            "--principal",
            &p,
            "--credential",
            &d2,
            "--dir",
            dir,
            acc,
        ],
        &mut Door::of(&[]),
    );
    assert_eq!(ran.out, format!("{p} {d2}\n"));
    let ran = run(
        &["enrollment", "list", "--dir", dir, acc],
        &mut Door::of(&[]),
    );
    assert_eq!(ran.code, EXIT_VERB_DONE);
    assert_eq!(
        ran.out,
        format!(
            "ok principals=1 credentials=2\nprincipal {p} active acme\ncredential {d1} {p}\n\
             credential {d2} {p}\n"
        )
    );
    let ran = run(
        &[
            "enrollment",
            "revoke",
            "--credential",
            &d1,
            "--dir",
            dir,
            acc,
        ],
        &mut Door::of(&[]),
    );
    assert_eq!(ran.out, format!("{p} {d1}\n"));
    let ran = run(
        &[
            "enrollment",
            "revoke",
            "--credential",
            &d1,
            "--dir",
            dir,
            acc,
        ],
        &mut Door::of(&[]),
    );
    assert_eq!(ran.code, EXIT_REFUSED);
    assert!(ran.err.contains("not enrolled"), "{}", ran.err);
}

#[test]
fn an_io_failure_before_the_rename_exits_refused_with_nothing_changed() {
    let fx = Fx::new("cli-prewrite");
    fx.put(&one(1, "acme", 1));
    let before = fx.bytes();
    // A directory at the temporary's name: removing the leftover fails.
    std::fs::create_dir(fx.dir.join(super::super::TEMP_NAME)).unwrap();
    let dir = fx.dir.to_str().unwrap();
    let d = digest(1).to_string();
    let ran = run(
        &[
            "enrollment",
            "revoke",
            "--credential",
            &d,
            "--dir",
            dir,
            "--accept-unsupported-filesystem",
        ],
        &mut Door::of(&[]),
    );
    assert_eq!(ran.code, EXIT_REFUSED, "{}", ran.err);
    assert!(ran.err.contains("nothing was changed"), "{}", ran.err);
    assert!(!ran.err.contains("may or may not"), "{}", ran.err);
    assert_eq!(fx.bytes(), before);
}

#[test]
fn unknown_command_and_usage_name_all_local_commands() {
    let ran = run(&["unknown"], &mut Door::of(&[]));
    assert_eq!(ran.code, EXIT_USAGE);
    assert!(ran.err.contains(
        "the commands are `enrollment`, `debug-grant`, `support-export`, `initialise` and `unfence`"
    ));
    assert!(ran.err.contains("granary-server enrollment"));
    assert!(ran.err.contains("granary-server debug-grant"));
    assert!(ran.out.is_empty());
}
