// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `granconf` — the differential oracle's pure half. Four verbs:
//! `dump <root>`, `compare A B [--expect <class>]`,
//! `gendir --out DIR --seed N`, `verify-cases <source-dump>`. See
//! `crates/granary-conformance/src/lib.rs` for the crate-level design
//! note and each module for its own contract.
//!
//! Argument parsing is hand-rolled, on `gran`'s own precedent
//! (`crates/granary-cli/src/main.rs`) — the surface here is four
//! verbs and at most two flags, well inside the size that would
//! justify a parser dependency (`docs/dependency-policy.md`'s CLI rule).

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use granary_conformance::compare::{Class, Divergence, check_expect, check_identical, merge};
use granary_conformance::escape;
use granary_conformance::gendir::{build_plan, materialize, summarize};
use granary_conformance::row::{parse_dump, render_line};
use granary_conformance::verify_cases::verify_all;
use granary_conformance::walk::walk;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n\
         \x20 granconf dump <root>\n\
         \x20 granconf compare <a> <b> [--expect <class>]\n\
         \x20     class is one of: presence kind size exec content target dtype\n\
         \x20 granconf gendir --out <dir> --seed <n>\n\
         \x20 granconf verify-cases <source-dump>"
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let rest = args.get(2..).unwrap_or_default();
    match args.get(1).and_then(|a| a.to_str()) {
        Some("dump") => cmd_dump(rest),
        Some("compare") => cmd_compare(rest),
        Some("gendir") => cmd_gendir(rest),
        Some("verify-cases") => cmd_verify_cases(rest),
        _ => usage(),
    }
}

fn read_to_string(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn cmd_dump(args: &[OsString]) -> ExitCode {
    let [root] = args else {
        eprintln!(
            "granconf dump: expected exactly 1 argument (root), got {}",
            args.len()
        );
        return usage();
    };
    let rows = match walk(PathBuf::from(root).as_path()) {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("granconf dump: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut out = String::new();
    for row in &rows {
        out.push_str(&render_line(row));
        out.push('\n');
    }
    print!("{out}");
    ExitCode::SUCCESS
}

fn parse_class(text: &str) -> Option<Class> {
    match text {
        "presence" => Some(Class::Presence),
        "kind" => Some(Class::Kind),
        "size" => Some(Class::Size),
        "exec" => Some(Class::Exec),
        "content" => Some(Class::Content),
        "target" => Some(Class::Target),
        "dtype" => Some(Class::Dtype),
        _ => None,
    }
}

fn cmd_compare(args: &[OsString]) -> ExitCode {
    let mut positional: Vec<&OsString> = Vec::new();
    let mut expect: Option<Class> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg.to_str() == Some("--expect") {
            let Some(value) = it.next().and_then(|v| v.to_str()) else {
                eprintln!("granconf compare: --expect needs a value");
                return usage();
            };
            let Some(class) = parse_class(value) else {
                eprintln!("granconf compare: unknown class {value:?}");
                return usage();
            };
            expect = Some(class);
        } else {
            positional.push(arg);
        }
    }
    let [a_path, b_path] = positional.as_slice() else {
        eprintln!(
            "granconf compare: expected exactly 2 positional arguments (a, b), got {}",
            positional.len()
        );
        return usage();
    };
    let a_text = match read_to_string(PathBuf::from(a_path).as_path()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("granconf compare: {e}");
            return ExitCode::FAILURE;
        }
    };
    let b_text = match read_to_string(PathBuf::from(b_path).as_path()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("granconf compare: {e}");
            return ExitCode::FAILURE;
        }
    };
    let a_rows = match parse_dump(&a_text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("granconf compare: a: {e}");
            return ExitCode::FAILURE;
        }
    };
    let b_rows = match parse_dump(&b_text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("granconf compare: b: {e}");
            return ExitCode::FAILURE;
        }
    };
    let divergences = merge(&a_rows, &b_rows);

    let mut counts: [usize; 7] = [0; 7];
    let mut equal = 0usize;
    for d in &divergences {
        match d.class {
            None => equal = equal.saturating_add(1),
            Some(c) => {
                let idx = match c {
                    Class::Presence => 0,
                    Class::Kind => 1,
                    Class::Size => 2,
                    Class::Exec => 3,
                    Class::Content => 4,
                    Class::Target => 5,
                    Class::Dtype => 6,
                };
                if let Some(slot) = counts.get_mut(idx) {
                    *slot = slot.saturating_add(1);
                }
                println!("CONFORM: DIVERGE {c} {}", escape::escape(&d.path));
            }
        }
    }
    println!(
        "CONFORM: SUMMARY presence={} kind={} size={} exec={} content={} target={} dtype={} equal={equal}",
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6]
    );

    report_verdict(&divergences, expect)
}

/// Print the verdict LINE and turn it into an exit status.
///
/// Both arms matter equally: the `--expect` arm is what the should-fail
/// fixtures read, and the BASELINE arm is the oracle's primary assertion.
/// Returning success while printing DIVERGE lines would leave that primary
/// check readable only by a caller that parses the counters, which is not
/// what a shell gate does.
fn report_verdict(divergences: &[Divergence], expect: Option<Class>) -> ExitCode {
    match expect {
        None => match check_identical(divergences) {
            Ok(rows) => {
                println!("CONFORM: identical, {rows} rows");
                ExitCode::SUCCESS
            }
            Err(reason) => {
                println!("CONFORM: NOT identical: {reason}");
                ExitCode::FAILURE
            }
        },
        Some(class) => match check_expect(divergences, class) {
            Ok(()) => {
                println!("CONFORM: PASS --expect {class}");
                ExitCode::SUCCESS
            }
            Err(reason) => {
                println!("CONFORM: FAIL --expect {class}: {reason}");
                ExitCode::FAILURE
            }
        },
    }
}

fn cmd_gendir(args: &[OsString]) -> ExitCode {
    let mut out_dir: Option<PathBuf> = None;
    let mut seed: Option<u64> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--out") => {
                let Some(v) = it.next() else {
                    eprintln!("granconf gendir: --out needs a value");
                    return usage();
                };
                out_dir = Some(PathBuf::from(v));
            }
            Some("--seed") => {
                let Some(v) = it.next().and_then(|v| v.to_str()) else {
                    eprintln!("granconf gendir: --seed needs a value");
                    return usage();
                };
                let Ok(parsed) = v.parse::<u64>() else {
                    eprintln!("granconf gendir: --seed {v:?} is not a u64");
                    return usage();
                };
                seed = Some(parsed);
            }
            _ => {
                eprintln!("granconf gendir: unknown argument {}", arg.display());
                return usage();
            }
        }
    }
    let (Some(out_dir), Some(seed)) = (out_dir, seed) else {
        eprintln!("granconf gendir: both --out <dir> and --seed <n> are required");
        return usage();
    };
    let plan = build_plan(seed);
    println!("{}", summarize(&plan));
    match materialize(&plan, &out_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("granconf gendir: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_verify_cases(args: &[OsString]) -> ExitCode {
    let [dump_path] = args else {
        eprintln!(
            "granconf verify-cases: expected exactly 1 argument (source-dump), got {}",
            args.len()
        );
        return usage();
    };
    let text = match read_to_string(PathBuf::from(dump_path).as_path()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("granconf verify-cases: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rows = match parse_dump(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("granconf verify-cases: {e}");
            return ExitCode::FAILURE;
        }
    };
    let results = match verify_all(&rows) {
        Ok(r) => r,
        Err(e) => {
            println!("VERIFY: REFUSED {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut all_ok = true;
    for case in &results {
        match &case.outcome {
            Ok(()) => println!("VERIFY: {} PASS", case.name),
            Err(reason) => {
                all_ok = false;
                println!("VERIFY: {} FAIL: {reason}", case.name);
            }
        }
    }
    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
