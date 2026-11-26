// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `granary-bench` — the grain-size harness CLI.
//!
//! Arguments are parsed by hand (dependency-policy rule 1; lexopt is
//! the adopted CLI dependency for `gran`, and this dev-only binary has
//! five subcommands and no completions to emit).
//!
//! `--date` and `--granary-git-sha` are REQUIRED arguments rather than
//! ambient facts: the determinism-seam rule bans `SystemTime::now` workspace-wide,
//! and a record whose provenance came from the shell is a record whose
//! provenance is in the run script, where it can be reviewed.

use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use granary_bench::chunk::{all_arms, factorial_arms, validate_factorial_arms};
use granary_bench::compress::{self, GrainCompressor, ZSTD_API, ZSTD_LEVEL};
use granary_bench::control;
use granary_bench::corpus;
use granary_bench::cost::{
    self, Candidate, Cell, CellMeasure, Decision, FactorialDecision, PairBand, PairGrid, Replay,
};
use granary_bench::covariates::{self, C1, C2, C2_UNIT_NOTE};
use granary_bench::json::Json;
use granary_bench::report::{RunMetadata, arm_json, write_record};
use granary_bench::reproduce;
use granary_bench::sweep::{self, ArmMetrics, ManifestStatus};
use granary_bench::tuple::{GrainTuple, SWEEP_AVGS};
use granary_bench::wallclock;

const USAGE: &str = "\
granary-bench — grain-size harness

  granary-bench control
      Run the committed positive control suite at production sizes.

  granary-bench retention --older DIR --newer DIR
      Cross-version retention pre-check (no compression, no headline).

  granary-bench sweep --deciding-pair OLD:NEW [--replication-pair OLD:NEW]... \\
      --out FILE --dataset NAME --date YYYY-MM-DD --granary-git-sha SHA \\
      --machine STR --os STR --filesystem STR
      The average-sweep grid over every pair, in one process. Its committed
      records are the factorial's reproduction target.

  granary-bench factorial --deciding-pair OLD:NEW [--replication-pair OLD:NEW] \\
      --reproduction-baseline FILE --covariates on|off \\
      --out FILE --dataset NAME --date YYYY-MM-DD --granary-git-sha SHA \\
      --machine STR --os STR --filesystem STR
      The pre-registered 7x4 (min, normalization) factorial at
      avg = 256 KiB (31 arms/pair). With ONE replication pair (W1) the
      record carries the full factorial decision block; with none (W2/W3) it
      carries per-pair bands at binmap {0, 49, 98}. Refuses to write unless
      the factorial production controls pass, every cell is exact on every
      measured pair (control 4), and the four shared arms reproduce the committed
      baseline field-for-field (control 1). COMPUTING any factorial arm
      or covariate on a real dataset CLOSES the registered rule's
      amendment window.

  granary-bench verify-wallclock ARTIFACT
      Recompute the propagation measurement from one run artifact and
      print a consistency report. NON-MINTING: it writes no record, mints
      no token and creates no file. Its argv is EXACTLY one positional —
      every metadata value is read from the artifact, so a flag of any
      kind is a usage error refused before the artifact is opened.
";

/// How far a subcommand's own positional list sits from the real argv.
/// `collect_utf8_args` drops argv[0], the program name, and `main` consumes
/// argv[1], the subcommand — so a subcommand's `args[i]` is argv[i + 2].
/// Refusals number arguments the way the OPERATOR typed them, because a
/// message that numbers the same argument differently from the message beside
/// it sends its reader to the wrong one.
const ARGV_POSITIONAL_OFFSET: usize = 2;

fn main() -> ExitCode {
    let args = match collect_utf8_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("granary-bench: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(command) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let rest = args.get(1..).unwrap_or_default();
    // `verify-wallclock` is dispatched BEFORE `parse_flags`, and that
    // order is the contract rather than a convenience: its argv is one
    // POSITIONAL, `parse_flags` refuses a positional, and a flag on this
    // verb's argv must be a usage error refused before the artifact is
    // opened. Every metadata value is read from the artifact.
    if command == "verify-wallclock" {
        return match cmd_verify_wallclock(rest) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("granary-bench: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let flags = match parse_flags(rest) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("granary-bench: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let result = match command.as_str() {
        "control" => cmd_control(),
        "retention" => cmd_retention(&flags),
        "sweep" => cmd_sweep(&flags),
        "factorial" => cmd_factorial(&flags),
        other => Err(format!("unknown subcommand `{other}`")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("granary-bench: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `std::env::args()` PANICS on the first argument that is not valid
/// UTF-8 — `called Result::unwrap() on an Err value`, exit 101 — and it
/// ran BEFORE any of this binary's own argv vetting: `verify-wallclock`'s
/// control-character scan (`cmd_verify_wallclock`, below) never got the
/// chance to refuse a hostile path cleanly, because the process was
/// already dead. This project's hard rule is no unwrap/expect/panic
/// reachable from untrusted input, and argv is untrusted input.
///
/// `args_os()` cannot panic, so every element is read here and checked
/// EXPLICITLY: a non-UTF-8 argument is a REFUSAL — a normal, non-zero
/// exit, never a panic — naming which argument was bad and that it was
/// not valid UTF-8, and NOT echoing the raw bytes: invalid UTF-8 cannot
/// even be interpolated into a `String` message safely to begin with,
/// and the reasoning is the same one `wallclock::printable`'s own
/// refusal gives for not echoing its payload.
///
/// The index counts from `argv[0]`, the program name — the same base
/// `main`'s own C-style argv would use — so `argv[1]` is the subcommand
/// and `argv[2]` is its first argument; this runs BEFORE the subcommand
/// is even identified, so it cannot yet count relative to one.
///
/// ONE COLLECTION SITE for every subcommand. `main` calls this once and
/// dispatches `control`, `retention`, `sweep`, `factorial` and
/// `verify-wallclock` from its result — none of them calls
/// `std::env::args()` again — so fixing the panic here fixes it for all
/// five, not only the verb the report reproduced it against.
fn collect_utf8_args() -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (index, arg) in std::env::args_os().enumerate() {
        match arg.into_string() {
            Ok(s) => {
                if index > 0 {
                    out.push(s);
                }
            }
            Err(_) => {
                return Err(format!(
                    "argv[{index}] is not valid UTF-8 — granary-bench accepts UTF-8 \
                     argv only; the raw bytes are not shown here"
                ));
            }
        }
    }
    Ok(out)
}

/// Flags are kept as a LIST, not a map: `--replication-pair` is
/// repeatable and a map would silently keep only the last one.
type Flags = Vec<(String, String)>;

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut out = Flags::new();
    let mut i = 0usize;
    while let Some(key) = args.get(i) {
        let Some(name) = key.strip_prefix("--") else {
            return Err(format!("expected a --flag, got `{key}`"));
        };
        let Some(value) = args.get(i + 1) else {
            return Err(format!("--{name} needs a value"));
        };
        out.push((name.to_owned(), value.clone()));
        i += 2;
    }
    Ok(out)
}

/// `verify-wallclock ARTIFACT` — one positional, no flags, no output
/// file. See [`granary_bench::wallclock`] for why it mints nothing.
fn cmd_verify_wallclock(args: &[String]) -> Result<(), String> {
    // ARGV IS UNTRUSTED TOO, and it runs FIRST, over EVERY element,
    // before any other check in this function. Three sites below
    // interpolate an argv element into a message before anything has
    // vetted it — the unknown-flag error echoes `{arg}`, the not-found
    // error echoes `{path}`, and `REFUSED {path}` does too — and
    // `findings.render(path)` at the bottom interpolates the same path
    // again into the human-readable report. A file literally named
    // `artifact.json\nP1 VERDICT: fail\nFORGED` reached every one of
    // those sites: the artifact scan (`printable`, below) vets every
    // STRING and KEY inside the file, but the file's own NAME travels
    // from argv the operator typed and never went through that scan.
    // Vetted here with the SAME predicate `printable` uses — one table,
    // one rule, see [`wallclock::first_forbidden`] — so a `--date` typo
    // and a hostile path are refused by the identical mechanism. The
    // refusal names the CODE POINT and its POSITION and never echoes
    // the string, for the same reason `printable`'s own refusal does
    // not: a message built out of the payload would be the injection it
    // exists to refuse.
    // NUMBERED FROM THE REAL COMMAND LINE, not from this slice. `args` here
    // is argv[2..] — the program name is dropped in `collect_utf8_args` and
    // the subcommand is consumed by `main` — and the non-UTF-8 refusal there
    // reports TRUE argv indices. Two refusals that number the same argument
    // differently send a reader to the wrong one: measured, the same path
    // was `argv[0]` from here and `argv[2]` from there.
    for (index, arg) in args.iter().enumerate() {
        if let Some((c, at)) = wallclock::first_forbidden(arg) {
            let argv_index = index + ARGV_POSITIONAL_OFFSET;
            return Err(format!(
                "argv[{argv_index}] carries U+{:04X} at character {at} — an argv element is \
                 interpolated into this verb's own messages and into the report before \
                 the artifact is opened, so it is vetted first and never echoed",
                u32::from(c)
            ));
        }
    }
    // The flag scan runs SECOND and over EVERY argument, so
    // `verify-wallclock --date X /no/such/file` is a usage error and not
    // a not-found error: the refusal has to land before the artifact is
    // opened, or "refused before the artifact is opened" is untested
    // prose.
    for arg in args {
        if arg.starts_with('-') {
            return Err(format!(
                "verify-wallclock takes no flags — every metadata value is \
                 read from the artifact; argv is exactly one positional, the \
                 artifact path (got `{arg}`)"
            ));
        }
    }
    let [path] = args else {
        return Err(format!(
            "verify-wallclock takes exactly one positional, the artifact path \
             (got {} arguments)",
            args.len()
        ));
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read `{path}`: {e}"))?;
    let findings = wallclock::verify(&text).map_err(|e| format!("REFUSED {path}: {e}"))?;
    print!("{}", findings.render(path));
    Ok(())
}

fn need<'a>(flags: &'a Flags, key: &str) -> Result<&'a String, String> {
    let mut hits = flags.iter().filter(|(k, _)| k == key);
    let first = hits
        .next()
        .map(|(_, v)| v)
        .ok_or_else(|| format!("--{key} is required"))?;
    if hits.next().is_some() {
        return Err(format!("--{key} may be given only once"));
    }
    Ok(first)
}

fn all<'a>(flags: &'a Flags, key: &str) -> Vec<&'a String> {
    flags
        .iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v)
        .collect()
}

/// `OLD:NEW` -> the two directories, plus a label built from their
/// basenames. A pair whose halves are the same directory is refused:
/// it would compare a version with itself and report 0% novel.
fn parse_pair(spec: &str) -> Result<(PathBuf, PathBuf, String), String> {
    let (old, new) = spec
        .split_once(':')
        .ok_or_else(|| format!("--*-pair wants OLD:NEW, got `{spec}`"))?;
    if old.is_empty() || new.is_empty() {
        return Err(format!("--*-pair has an empty half: `{spec}`"));
    }
    let (old_path, new_path) = (PathBuf::from(old), PathBuf::from(new));
    // Two independent rules, because neither alone is enough. The raw
    // `old == new` string compare these replaced saw `v1` and `v1/` as
    // different trees: `--deciding-pair v1:v1/` ran the whole grid against
    // itself, every arm reported 0 novel, the tie-break cutoff became 0.0,
    // and `base()` mapped both halves to `v1` — so the written record's
    // `version_older`/`version_newer` were identical and did NOT show the
    // pair had been degenerate.
    if lexical(&old_path) == lexical(&new_path) || resolves_to_the_same_tree(&old_path, &new_path) {
        return Err(format!("--*-pair compares a tree with itself: `{spec}`"));
    }
    let label = format!("{}->{}", base(old), base(new));
    Ok((old_path, new_path, label))
}

/// A path's identity for self-pair detection, by pure lexical rule.
///
/// `Path::components()` already drops a `.` everywhere EXCEPT at the
/// start of a path, and already drops a trailing slash; filtering
/// [`Component::CurDir`] is what additionally makes `./v1` and `v1`
/// compare equal. Total and pure: no I/O, no failure mode, so it holds
/// for paths that do not exist on this machine.
///
/// It deliberately does NOT resolve `..`. `a/../v1` is the same tree as
/// `v1` only when `a` is not a symlink, which is a question for the
/// filesystem — see [`resolves_to_the_same_tree`].
fn lexical(p: &Path) -> Vec<Component<'_>> {
    p.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
}

/// Whether both halves resolve to the same directory on this machine.
///
/// Catches what no lexical rule may: `..` segments, symlinks, and any
/// second spelling that reaches the same tree. It is I/O and it fails on
/// a path that does not exist, so it may only ever ADD a refusal — when
/// either half does not resolve the answer is `false` and the lexical
/// rule stands alone. A legitimate pair must never become an error
/// because the filesystem could not answer.
fn resolves_to_the_same_tree(old: &Path, new: &Path) -> bool {
    match (std::fs::canonicalize(old), std::fs::canonicalize(new)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn base(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map_or_else(|| p.to_owned(), |n| n.to_string_lossy().into_owned())
}

fn cmd_control() -> Result<(), String> {
    let (outcomes, token) = control::run_production();
    for o in &outcomes {
        println!(
            "{:<22} {:<14} novel={:>12} bytes ({:>7.3}%) grains={:<8} {} [{}]",
            o.control,
            o.arm,
            o.novel_bytes,
            o.novel_pct,
            o.novel_grains,
            if o.passed { "PASS" } else { "FAIL" },
            o.expectation
        );
    }
    if token.is_some() {
        println!("controls: ALL PASS");
        Ok(())
    } else {
        Err("controls FAILED — no headline number is admissible".to_owned())
    }
}

fn cmd_retention(flags: &Flags) -> Result<(), String> {
    let older = load(Path::new(need(flags, "older")?))?;
    let newer = load(Path::new(need(flags, "newer")?))?;
    let r = sweep::retention(&older, &newer).map_err(|e| e.to_string())?;
    let identical_pct = share(r.path_identical_bytes, r.newer_bytes) * 100.0;
    println!(
        "paths: common={} added={} removed={}",
        r.paths_common, r.paths_added, r.paths_removed
    );
    println!("newer bytes: {}", r.newer_bytes);
    println!(
        "path-identical bytes: {} ({identical_pct:.2}%)",
        r.path_identical_bytes
    );
    println!(
        "whole-file retention ceiling: {}",
        ceiling(
            r.newer_bytes.saturating_sub(r.path_identical_bytes),
            r.newer_bytes
        )
    );
    Ok(())
}

fn cmd_sweep(flags: &Flags) -> Result<(), String> {
    let (outcomes, token) = control::run_production();
    let Some(token) = token else {
        for o in outcomes.iter().filter(|o| !o.passed) {
            eprintln!(
                "control FAILED: {} / {} — {}",
                o.control, o.arm, o.expectation
            );
        }
        return Err("controls FAILED — refusing to write a record".to_owned());
    };

    let deciding = parse_pair(need(flags, "deciding-pair")?)?;
    let mut replications = Vec::new();
    for spec in all(flags, "replication-pair") {
        replications.push(parse_pair(spec)?);
    }
    let out_path = PathBuf::from(need(flags, "out")?);
    let meta = metadata(flags, &deciding)?;

    let mut comp = GrainCompressor::new().map_err(|e| format!("zstd: {e}"))?;
    let mut pair_json = Vec::new();
    let mut deciding_candidates = Vec::new();
    let mut replication_candidates = Vec::new();

    for (index, (old, new, label)) in std::iter::once(&deciding).chain(&replications).enumerate() {
        let role = if index == 0 {
            "deciding"
        } else {
            "replication"
        };
        eprintln!("== pair {label} ({role})");
        let older = load(old)?;
        let newer = load(new)?;
        let mut measured = Vec::new();
        for arm in all_arms() {
            eprintln!("   {}", arm.label());
            let m = sweep::run_arm(&older, &newer, arm, &mut comp).map_err(|e| e.to_string())?;
            measured.push(m);
        }
        refuse_harness_errors(label, &measured)?;
        refuse_unfaithful_grid(label, &measured)?;
        let r = sweep::retention(&older, &newer).map_err(|e| e.to_string())?;
        let cands = candidates(&measured);
        if index == 0 {
            deciding_candidates = cands;
        } else {
            replication_candidates.push((label.clone(), cands));
        }
        pair_json.push(Json::Obj(vec![
            ("label".to_owned(), Json::s(label.clone())),
            ("role".to_owned(), Json::s(role)),
            ("older_root".to_owned(), Json::s(old.display().to_string())),
            ("newer_root".to_owned(), Json::s(new.display().to_string())),
            ("retention".to_owned(), retention_json(&r)),
            (
                "arms".to_owned(),
                Json::Arr(measured.iter().map(arm_json).collect()),
            ),
        ]));
    }

    let decision = cost::decide_with_replication(
        &deciding_candidates,
        &replication_candidates,
        (
            SWEEP_AVGS.first().copied().unwrap_or(0),
            SWEEP_AVGS.last().copied().unwrap_or(0),
        ),
        GrainTuple::shipped().avg,
    );

    let body = vec![
        ("pairs".to_owned(), Json::Arr(pair_json)),
        ("decision".to_owned(), decision_json(&decision)),
    ];
    write_record(&out_path, &meta, body, token).map_err(|e| e.to_string())?;
    println!("wrote {}", out_path.display());
    Ok(())
}

fn load(path: &Path) -> Result<corpus::Corpus, String> {
    corpus::load(path).map_err(|e| e.to_string())
}

fn metadata(flags: &Flags, deciding: &(PathBuf, PathBuf, String)) -> Result<RunMetadata, String> {
    let pairs = vec![
        ("record_version".to_owned(), "2".to_owned()),
        ("kind".to_owned(), "m3-grain-sweep".to_owned()),
        ("date".to_owned(), need(flags, "date")?.clone()),
        (
            "granary_git_sha".to_owned(),
            need(flags, "granary-git-sha")?.clone(),
        ),
        ("machine".to_owned(), need(flags, "machine")?.clone()),
        ("os".to_owned(), need(flags, "os")?.clone()),
        ("filesystem".to_owned(), need(flags, "filesystem")?.clone()),
        (
            "support_tier".to_owned(),
            "n/a (chunk-level analysis, no wall-clock claim)".to_owned(),
        ),
        ("dataset".to_owned(), need(flags, "dataset")?.clone()),
        // Derived from the DECIDING pair's directory basenames, not from
        // a flag: a hand-typed version string that disagrees with the
        // tree actually measured is a provenance defect waiting to happen.
        (
            "version_older".to_owned(),
            base(&deciding.0.display().to_string()),
        ),
        (
            "version_newer".to_owned(),
            base(&deciding.1.display().to_string()),
        ),
        (
            "chunker_algorithm".to_owned(),
            granary_core::thresh::CHUNKER_SPEC.algorithm.to_owned(),
        ),
        (
            "chunker_crate_version".to_owned(),
            granary_core::thresh::CHUNKER_SPEC.crate_version.to_owned(),
        ),
        (
            "zstd_crate_version".to_owned(),
            compress::ZSTD_CRATE_VERSION.to_owned(),
        ),
        (
            "zstd_library_version".to_owned(),
            compress::library_version(),
        ),
        (
            "zstd_level_and_api".to_owned(),
            format!("{ZSTD_LEVEL} / {ZSTD_API}"),
        ),
    ];
    RunMetadata::new(&pairs).map_err(|e| e.to_string())
}

/// Refuse to proceed if any arm on this pair reports `HarnessError`.
///
/// `candidates()` below folds `Unrepresentable` and `HarnessError` into a
/// single `eligible: bool`, and `cost::choose` filters on `eligible` with
/// no escalation distinguishing the two — a harness bug (bad corpus
/// ordering, a size/grain-sum mismatch) could silently shift the argmin
/// with nothing in `decision` flagging it. `sweep.rs`'s own
/// `ManifestStatus::HarnessError` doc names this the exact failure the
/// variant exists to prevent: a harness bug must never produce a
/// published record. `Unrepresentable` (a genuine frozen-format limit,
/// e.g. a whole file over the 8 MiB cap) is NOT refused here — that is
/// an expected finding, reported via `manifest_status` in the record,
/// not a harness defect.
fn refuse_harness_errors(label: &str, measured: &[ArmMetrics]) -> Result<(), String> {
    for m in measured {
        if let ManifestStatus::HarnessError(reason) = &m.manifest_status {
            return Err(format!(
                "harness error on pair {label}, arm {}: {reason} — refusing to write a \
                 record (a harness bug must never shift the argmin silently)",
                m.arm
            ));
        }
    }
    Ok(())
}

/// Refuse to proceed if this pair's CDC arms did not actually use the
/// tuples they are labelled with.
///
/// Sits beside [`refuse_harness_errors`] for the same reason it does: a
/// harness that silently ignores the swept tuple shifts the argmin with
/// nothing in `decision` flagging it, and the controls cannot see it —
/// they prove resync, and a cutter stuck at one tuple resyncs perfectly.
/// See `sweep::check_cdc_grid_fidelity` for the two saboteurs that pass
/// 61/61 and for why this is a record-write refusal rather than a
/// sixty-second control outcome.
fn refuse_unfaithful_grid(label: &str, measured: &[ArmMetrics]) -> Result<(), String> {
    sweep::check_cdc_grid_fidelity(measured).map_err(|e| {
        format!(
            "grid fidelity violated on pair {label}: {e} — refusing to write a \
             record (a grid whose points do not separate cannot have measured \
             the tuples it reports)"
        )
    })
}

fn candidates(measured: &[ArmMetrics]) -> Vec<Candidate> {
    measured
        .iter()
        .filter(|m| m.kind == "cdc")
        .map(|m| Candidate {
            avg: usize::try_from(m.configured_avg).unwrap_or(0),
            eligible: m.manifest_status == ManifestStatus::Exact,
            novel_stored_bytes: m.novel_stored_bytes,
            novel_manifest_bytes: m.novel_manifest_bytes,
            novel_grain_count: m.novel_grain_count,
            store_stored_bytes: m.store_stored_bytes,
            store_manifest_bytes: m.store_manifest_bytes,
            store_grain_count: m.store_grain_count,
            coalesced_ranges: m.coalesced_ranges,
        })
        .collect()
}

/// The factorial subcommand — the registered protocol, executed.
fn cmd_factorial(flags: &Flags) -> Result<(), String> {
    // Controls FIRST, before anything is measured: the factorial suite
    // (identical/disjoint/prepend over the 31 arms + the control-2 liveness
    // controls) gates the record via its own token kind.
    let (outcomes, token) = control::run_factorial_production();
    let Some(token) = token else {
        for o in outcomes.iter().filter(|o| !o.passed) {
            eprintln!(
                "control FAILED: {} / {} — {}",
                o.control, o.arm, o.expectation
            );
        }
        return Err("factorial controls FAILED — refusing to write a record".to_owned());
    };

    let deciding = parse_pair(need(flags, "deciding-pair")?)?;
    let replications: Vec<&String> = all(flags, "replication-pair");
    if replications.len() > 1 {
        return Err(
            "the registered design has at most ONE replication pair (W1's two \
             version pairs); more is a different, unregistered protocol"
                .to_owned(),
        );
    }
    let replication = replications
        .first()
        .map(|spec| parse_pair(spec))
        .transpose()?;
    let baseline_path = PathBuf::from(need(flags, "reproduction-baseline")?);
    let with_covariates = match need(flags, "covariates")?.as_str() {
        "on" => true,
        "off" => false,
        other => return Err(format!("--covariates must be `on` or `off`, got `{other}`")),
    };
    let out_path = PathBuf::from(need(flags, "out")?);
    let meta = factorial_metadata(flags, &deciding)?;

    // The arm list about to measure, validated as the registered design
    // (the controls validated their OWN list; this is the one the sweep
    // trusts, same function, checked where it is used).
    let arms = factorial_arms();
    validate_factorial_arms(&arms).map_err(|e| e.to_string())?;

    println!(
        "NOTE: computing a registered factorial arm (and any covariate) on a real \
         dataset CLOSES the registered rule's amendment window — computation \
         closes it, not commit."
    );

    let mut comp = GrainCompressor::new().map_err(|e| format!("zstd: {e}"))?;
    let mut pair_json = Vec::new();
    let mut grids: Vec<PairGrid> = Vec::new();

    for (index, pair) in std::iter::once(&deciding)
        .chain(replication.iter())
        .enumerate()
    {
        let role = if index == 0 {
            "deciding"
        } else {
            "replication"
        };
        let (pair_record, grid) = measure_factorial_pair(
            pair,
            role,
            &arms,
            &mut comp,
            &baseline_path,
            with_covariates,
        )?;
        grids.push(grid);
        pair_json.push(pair_record);
    }

    // The decision block: the full decision rule across W1's two pairs, or the
    // per-pair band report for a single-pair replication dataset.
    let decision_block = match grids.as_slice() {
        [d, r] => {
            let decision = cost::decide_factorial(d, r).map_err(|e| e.to_string())?;
            factorial_decision_json(&decision)
        }
        [single] => {
            let bands = cost::factorial_pair_bands(single).map_err(|e| e.to_string())?;
            Json::Obj(vec![
                (
                    "outcome".to_owned(),
                    // This text is written into the factorial records this command
                    // emits, and committed records carry it; it must not change, or a
                    // re-run's record stops matching them byte for byte.
                    Json::s("replication dataset — no §6 selection; bands reported"),
                ),
                (
                    "bands".to_owned(),
                    Json::Arr(bands.iter().map(band_json).collect()),
                ),
            ])
        }
        _ => return Err("no pairs were measured".to_owned()),
    };

    let body = vec![
        ("pairs".to_owned(), Json::Arr(pair_json)),
        ("decision".to_owned(), decision_block),
    ];
    write_record(&out_path, &meta, body, token).map_err(|e| e.to_string())?;
    println!("wrote {}", out_path.display());
    Ok(())
}

/// One pair of the factorial: measure all 31 arms, apply the per-pair
/// refusals (harness errors, control 4, control 1), compute the
/// covariates when in scope, and return the pair's record object plus
/// its decision-rule grid.
fn measure_factorial_pair(
    pair: &(PathBuf, PathBuf, String),
    role: &'static str,
    arms: &[granary_bench::chunk::Arm],
    comp: &mut GrainCompressor,
    baseline_path: &Path,
    with_covariates: bool,
) -> Result<(Json, PairGrid), String> {
    let (old, new, label) = pair;
    eprintln!("== pair {label} ({role})");
    let older = load(old)?;
    let newer = load(new)?;
    let mut measured = Vec::new();
    for arm in arms {
        eprintln!("   {}", arm.label());
        let m = sweep::run_arm(&older, &newer, *arm, comp).map_err(|e| e.to_string())?;
        measured.push(m);
    }
    refuse_harness_errors(label, &measured)?;
    refuse_incomplete_cells(label, &measured)?;
    // Control 1: the four shared arms reproduce the committed
    // baseline field-for-field, or the run is INVALID.
    let repro = reproduce::check_reproduction(baseline_path, label, &measured)
        .map_err(|e| format!("reproduction control (control 1): {e}"))?;
    let r = sweep::retention(&older, &newer).map_err(|e| e.to_string())?;
    let covariates_json = if with_covariates {
        let c1 = covariates::c1(&older, &newer).map_err(|e| e.to_string())?;
        let c2 = covariates::c2(&older, &newer).map_err(|e| e.to_string())?;
        covariates_to_json(&c1, &c2)
    } else {
        // This text is written into the factorial records this command
        // emits, and committed records carry it; it must not change, or a
        // re-run's record stops matching them byte for byte.
        Json::s("not computed (registered scope: W1 pairs and W2 — prereg §8)")
    };
    let grid = PairGrid {
        label: label.clone(),
        cells: cell_measures(&measured),
    };
    let record = Json::Obj(vec![
        ("label".to_owned(), Json::s(label.clone())),
        ("role".to_owned(), Json::s(role)),
        ("older_root".to_owned(), Json::s(old.display().to_string())),
        ("newer_root".to_owned(), Json::s(new.display().to_string())),
        ("retention".to_owned(), retention_json(&r)),
        ("reproduction_control".to_owned(), reproduction_json(&repro)),
        ("covariates".to_owned(), covariates_json),
        (
            "arms".to_owned(),
            Json::Arr(measured.iter().map(arm_json).collect()),
        ),
    ]);
    Ok((record, grid))
}

/// Control 4's record-level teeth: the run is invalid unless every
/// factorial CDC cell is `manifest_status = exact` on this pair — never
/// a zero term, never a silent band exclusion. (`decide_factorial`
/// re-checks structurally; this refusal reports ALL offending cells and
/// fires before any decision code runs.)
fn refuse_incomplete_cells(label: &str, measured: &[ArmMetrics]) -> Result<(), String> {
    let bad: Vec<String> = measured
        .iter()
        .filter(|m| {
            m.kind == "cdc"
                && m.configured_min.is_some()
                && m.manifest_status != ManifestStatus::Exact
        })
        .map(|m| m.arm.clone())
        .collect();
    if bad.is_empty() {
        return Ok(());
    }
    Err(format!(
        "pair {label}: {} cell(s) without an exact manifest term ({}) — the run \
         is INVALID (control 4: a cell that fails to measure is a control \
         failure, never a silent exclusion)",
        bad.len(),
        bad.join(", ")
    ))
}

fn cell_measures(measured: &[ArmMetrics]) -> Vec<CellMeasure> {
    measured
        .iter()
        .filter_map(|m| {
            let (Some(min), Some(level)) = (m.configured_min, m.configured_normalization) else {
                return None;
            };
            Some(CellMeasure {
                cell: Cell {
                    min: usize::try_from(min).unwrap_or(0),
                    level,
                },
                manifest_exact: m.manifest_status == ManifestStatus::Exact,
                novel_stored_bytes: m.novel_stored_bytes,
                novel_manifest_bytes: m.novel_manifest_bytes,
                novel_grain_count: m.novel_grain_count,
                store_stored_bytes: m.store_stored_bytes,
                store_manifest_bytes: m.store_manifest_bytes,
                store_grain_count: m.store_grain_count,
                coalesced_ranges: m.coalesced_ranges,
            })
        })
        .collect()
}

fn factorial_metadata(
    flags: &Flags,
    deciding: &(PathBuf, PathBuf, String),
) -> Result<RunMetadata, String> {
    let pairs = vec![
        ("record_version".to_owned(), "2".to_owned()),
        (
            "kind".to_owned(),
            "m4-floor-normalization-factorial".to_owned(),
        ),
        ("date".to_owned(), need(flags, "date")?.clone()),
        (
            "granary_git_sha".to_owned(),
            need(flags, "granary-git-sha")?.clone(),
        ),
        ("machine".to_owned(), need(flags, "machine")?.clone()),
        ("os".to_owned(), need(flags, "os")?.clone()),
        ("filesystem".to_owned(), need(flags, "filesystem")?.clone()),
        (
            "support_tier".to_owned(),
            "n/a (chunk-level analysis, no wall-clock claim)".to_owned(),
        ),
        ("dataset".to_owned(), need(flags, "dataset")?.clone()),
        (
            "version_older".to_owned(),
            base(&deciding.0.display().to_string()),
        ),
        (
            "version_newer".to_owned(),
            base(&deciding.1.display().to_string()),
        ),
        (
            "chunker_algorithm".to_owned(),
            granary_core::thresh::CHUNKER_SPEC.algorithm.to_owned(),
        ),
        (
            "chunker_crate_version".to_owned(),
            granary_core::thresh::CHUNKER_SPEC.crate_version.to_owned(),
        ),
        (
            "zstd_crate_version".to_owned(),
            compress::ZSTD_CRATE_VERSION.to_owned(),
        ),
        (
            "zstd_library_version".to_owned(),
            compress::library_version(),
        ),
        (
            "zstd_level_and_api".to_owned(),
            format!("{ZSTD_LEVEL} / {ZSTD_API}"),
        ),
    ];
    RunMetadata::new(&pairs).map_err(|e| e.to_string())
}

fn cell_json(c: Cell) -> Json {
    Json::Obj(vec![
        ("min".to_owned(), Json::UInt(c.min as u64)),
        ("normalization".to_owned(), Json::UInt(u64::from(c.level))),
    ])
}

fn opt_cell_json(c: Option<Cell>) -> Json {
    c.map_or(Json::Null, cell_json)
}

fn band_json(b: &PairBand) -> Json {
    Json::Obj(vec![
        ("pair".to_owned(), Json::s(b.pair.clone())),
        ("binmap_entry".to_owned(), Json::UInt(b.binmap_entry as u64)),
        ("argmin".to_owned(), cell_json(b.argmin)),
        (
            "argmin_republish_bytes".to_owned(),
            Json::UInt(b.argmin_republish_bytes),
        ),
        (
            "members".to_owned(),
            Json::Arr(b.members.iter().map(|&c| cell_json(c)).collect()),
        ),
    ])
}

fn replay_json(r: &Replay) -> Json {
    Json::Obj(vec![
        ("binmap_entry".to_owned(), Json::UInt(r.binmap_entry as u64)),
        ("selection".to_owned(), opt_cell_json(r.selection)),
    ])
}

/// The machine-readable factorial decision block: selection, bands,
/// intersection, replays, every escalation — and the standing preamble
/// that ANY escalation makes the output a recommendation for Adrian.
fn factorial_decision_json(d: &FactorialDecision) -> Json {
    Json::Obj(vec![
        (
            "outcome".to_owned(),
            match (&d.selection, d.escalations.is_empty()) {
                (Some(_), true) => Json::s("selected"),
                (Some(_), false) => Json::s(
                    "selected — WITH ESCALATIONS: a \
recommendation for Adrian, never an automatic adoption",
                ),
                (None, _) => Json::s("NO SELECTION — E1: the rule does not choose"),
            },
        ),
        ("selection".to_owned(), opt_cell_json(d.selection)),
        ("incumbent".to_owned(), cell_json(Cell::BASELINE)),
        (
            "tie_break_tolerance".to_owned(),
            Json::Num(cost::TIE_BREAK_TOLERANCE),
        ),
        (
            "binmap_entry_bytes".to_owned(),
            Json::UInt(cost::BINMAP_ENTRY_BYTES as u64),
        ),
        (
            "bands".to_owned(),
            Json::Arr(d.bands.iter().map(band_json).collect()),
        ),
        (
            "intersection".to_owned(),
            Json::Arr(d.intersection.iter().map(|&c| cell_json(c)).collect()),
        ),
        (
            "replays".to_owned(),
            Json::Arr(d.replays.iter().map(replay_json).collect()),
        ),
        (
            "escalations".to_owned(),
            Json::Arr(
                d.escalations
                    .iter()
                    .map(|e| Json::s(format!("{e:?}")))
                    .collect(),
            ),
        ),
    ])
}

fn reproduction_json(r: &reproduce::PairReproduction) -> Json {
    Json::Obj(vec![
        // DERIVED from the evidence, never asserted: a hardcoded `true`
        // would let a swallowed refusal write a record claiming a pass
        // it never earned.
        (
            "passed".to_owned(),
            Json::Bool(r.all_shared_arms_compared()),
        ),
        (
            "arms".to_owned(),
            Json::Arr(
                r.arms()
                    .iter()
                    .map(|arm| {
                        let mut fields = vec![
                            ("arm".to_owned(), Json::s(arm.m4_label())),
                            ("committed_as".to_owned(), Json::s(arm.committed_label())),
                            (
                                "fields_compared".to_owned(),
                                Json::UInt(arm.fields_compared() as u64),
                            ),
                        ];
                        // The population rule's move is RECORDED, never
                        // silently absorbed (reproduce.rs module doc).
                        // Additive field.
                        if let Some((committed, fresh)) = arm.population_moved() {
                            fields.push((
                                "cdc_population_moved".to_owned(),
                                Json::Obj(vec![
                                    (
                                        "committed_min_grain_bytes".to_owned(),
                                        Json::UInt(committed),
                                    ),
                                    ("fresh_min_grain_bytes".to_owned(), Json::UInt(fresh)),
                                ]),
                            ));
                        }
                        Json::Obj(fields)
                    })
                    .collect(),
            ),
        ),
    ])
}

fn covariates_to_json(c1: &C1, c2: &C2) -> Json {
    Json::Obj(vec![
        ("c1".to_owned(), c1_json(c1)),
        ("c2".to_owned(), c2_json(c2)),
    ])
}

fn c1_json(c1: &C1) -> Json {
    Json::Obj(vec![
        (
            "buckets".to_owned(),
            Json::Arr(
                c1.buckets
                    .iter()
                    .map(|&(k, files, bytes)| {
                        Json::Obj(vec![
                            ("log2".to_owned(), Json::UInt(u64::from(k))),
                            ("files".to_owned(), Json::UInt(files)),
                            ("bytes".to_owned(), Json::UInt(bytes)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("empty_files".to_owned(), Json::UInt(c1.empty_files)),
        ("total_files".to_owned(), Json::UInt(c1.total_files)),
        ("total_bytes".to_owned(), Json::UInt(c1.total_bytes)),
        (
            "thresholds".to_owned(),
            Json::Arr(
                c1.thresholds
                    .iter()
                    .map(|t| {
                        Json::Obj(vec![
                            ("threshold".to_owned(), Json::UInt(t.threshold)),
                            ("files".to_owned(), Json::UInt(t.files)),
                            ("bytes".to_owned(), Json::UInt(t.bytes)),
                            (
                                "whole_file_novel_bytes".to_owned(),
                                Json::UInt(t.whole_file_novel_bytes),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// A byte-weighted mean split (`by_class` / `by_size`): the mean beside
/// the bytes behind it, so a mean over nothing cannot read as a result.
fn mean_split_json<'a>(rows: impl Iterator<Item = &'a (&'static str, f64, u64)>) -> Json {
    Json::Obj(
        rows.map(|(label, mean, bytes)| {
            (
                (*label).to_owned(),
                Json::Obj(vec![
                    ("byte_weighted_mean".to_owned(), Json::Num(*mean)),
                    ("bytes".to_owned(), Json::UInt(*bytes)),
                ]),
            )
        })
        .collect(),
    )
}

fn c2_json(c2: &C2) -> Json {
    Json::Obj(vec![
        ("unit_note".to_owned(), Json::s(C2_UNIT_NOTE)),
        ("domain_files".to_owned(), Json::UInt(c2.domain_files)),
        ("domain_bytes".to_owned(), Json::UInt(c2.domain_bytes)),
        (
            "decile_bytes".to_owned(),
            Json::Arr(c2.decile_bytes.iter().map(|&b| Json::UInt(b)).collect()),
        ),
        ("by_class".to_owned(), mean_split_json(c2.by_class.iter())),
        ("by_size".to_owned(), mean_split_json(c2.by_size.iter())),
        (
            "headline_sub_512k".to_owned(),
            Json::Num(c2.headline_sub_512k),
        ),
        (
            "locality_boundary_label_only".to_owned(),
            Json::Num(covariates::LOCALITY_BOUNDARY),
        ),
        (
            "no_path_match_bytes".to_owned(),
            Json::UInt(c2.no_path_match_bytes),
        ),
        (
            "no_path_match_deduped_bytes".to_owned(),
            Json::UInt(c2.no_path_match_deduped_bytes),
        ),
    ])
}

fn retention_json(r: &sweep::Retention) -> Json {
    Json::Obj(vec![
        ("paths_common".to_owned(), Json::UInt(r.paths_common)),
        ("paths_added".to_owned(), Json::UInt(r.paths_added)),
        ("paths_removed".to_owned(), Json::UInt(r.paths_removed)),
        (
            "path_identical_bytes".to_owned(),
            Json::UInt(r.path_identical_bytes),
        ),
        ("newer_bytes".to_owned(), Json::UInt(r.newer_bytes)),
        (
            "path_identical_pct".to_owned(),
            Json::Num(share(r.path_identical_bytes, r.newer_bytes) * 100.0),
        ),
    ])
}

fn decision_json(d: &Decision) -> Json {
    match d {
        Decision::NoEligibleCandidate => Json::Obj(vec![(
            "outcome".to_owned(),
            Json::s("no eligible candidate"),
        )]),
        Decision::Chosen {
            avg,
            republish_bytes,
            argmin_avg,
            argmin_republish_bytes,
            headroom_to_cutoff_bytes,
            escalations,
        } => Json::Obj(vec![
            ("outcome".to_owned(), Json::s("chosen")),
            ("avg".to_owned(), Json::UInt(*avg as u64)),
            ("republish_bytes".to_owned(), Json::UInt(*republish_bytes)),
            // The four fields below exist so the block cannot be read as
            // "1 MiB minimises republish bytes" when what happened was
            // "1 MiB was promoted into the winner's seat by a 2% band".
            ("argmin_avg".to_owned(), Json::UInt(*argmin_avg as u64)),
            (
                "argmin_republish_bytes".to_owned(),
                Json::UInt(*argmin_republish_bytes),
            ),
            (
                "tie_break_tolerance".to_owned(),
                Json::Num(cost::TIE_BREAK_TOLERANCE),
            ),
            (
                "headroom_to_cutoff_bytes".to_owned(),
                Json::Num(*headroom_to_cutoff_bytes),
            ),
            (
                "binmap_entry_bytes".to_owned(),
                Json::UInt(cost::BINMAP_ENTRY_BYTES as u64),
            ),
            (
                "escalations".to_owned(),
                Json::Arr(
                    escalations
                        .iter()
                        .map(|e| Json::s(format!("{e:?}")))
                        .collect(),
                ),
            ),
        ]),
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts below 2^53; the result is a printed ratio"
)]
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 / whole as f64
}

/// The whole-file retention ceiling — `1 / novel_share` — as three
/// cases a reader must be able to tell apart.
///
/// The `f64` this replaced returned `0.0` when `novel == 0` and printed
/// `whole-file retention ceiling: 0.000x`, which reads as "no dedup
/// achievable" on precisely the pair with UNBOUNDED headroom (every
/// newer file byte-identical to the same path in older). `retention` is
/// a published pre-check (plan constraint 6), so a reader screening
/// candidate datasets by it would reject the best one. The `whole == 0`
/// guard inside [`share`] is correct; the bug was reusing its `0.0` as a
/// sentinel for "nothing novel", which means the opposite of the truth.
#[derive(Debug, PartialEq)]
enum Ceiling {
    /// The newer tree has no bytes at all: no denominator, so no ratio.
    /// Distinct from [`Self::Unbounded`] — nothing was measured, rather
    /// than nothing was novel.
    NoData,
    /// Nothing is novel: the ceiling is not a finite number.
    Unbounded,
    /// The finite ratio.
    Ratio(f64),
}

impl std::fmt::Display for Ceiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NoData => f.write_str("n/a (the newer tree has no bytes)"),
            Self::Unbounded => f.write_str(
                "unbounded (every newer byte is path-identical to older; nothing is novel)",
            ),
            Self::Ratio(x) => write!(f, "{x:.3}x"),
        }
    }
}

fn ceiling(novel: u64, total: u64) -> Ceiling {
    if total == 0 {
        return Ceiling::NoData;
    }
    if novel == 0 {
        return Ceiling::Unbounded;
    }
    Ceiling::Ratio(1.0 / share(novel, total))
}

#[cfg(test)]
mod tests;
