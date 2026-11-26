// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict local argv parsing and bounded, escaped publication reports.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use granary_core::clock::Clock;
use granary_core::debug_grant::{
    BYTE_CEILING_MAX, DURATION_MAX_SECS, DebugGrant, GrantAction, GrantScope, Incarnation,
    LINE_CEILING_MAX, Owner, Reason,
};
use granary_core::enrollment::PrincipalId;
use granary_core::root::VolumeName;
use granary_core::sheaf::Timestamp;

use super::verbs::{Error, Expected, Issue, Mutation, Narrow, mutate_on, show_on};
use crate::enrollment::{EXIT_IO_FAILED, EXIT_REFUSED, EXIT_USAGE, EXIT_VERB_DONE, VerbOptions};
use crate::protected_dir::{DirOps, NixOps};

const USAGE: &str = "usage: granary-server debug-grant issue|narrow|revoke|show --dir D\n\
  mutations: --incarnation incarnation:<32 lowercase hex> --expected-revision R\n\
  issue: --principal P and/or --volume V --duration-secs N --lines L --bytes B --owner O --reason Q\n\
  narrow: --generation G --principal P and/or --volume V --expires-at SECONDS.NNNNNNNNN --lines L --bytes B\n\
  revoke: --generation G; show: --dir D only\n\
  every verb accepts --accept-unsupported-filesystem; D must be absolute\n";

const FLAGS: &[&str] = &[
    "--dir",
    "--incarnation",
    "--expected-revision",
    "--generation",
    "--principal",
    "--volume",
    "--duration-secs",
    "--expires-at",
    "--lines",
    "--bytes",
    "--owner",
    "--reason",
];

type Raw = BTreeMap<&'static str, OsString>;

#[derive(Debug)]
struct Args {
    dir: PathBuf,
    options: VerbOptions,
    change: Option<(Expected, Mutation)>,
}

/// Run local debug-grant argv before constructing any runtime or subscriber.
/// `clock` supplies
/// issuance time and expired-narrowing decisions. Output acknowledges durable
/// publication only. Returns enrollment's 0, 64, 65 or 74 exit contract.
pub fn run_debug_grant_command_line(
    args: &[OsString],
    clock: &dyn Clock,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    run_on(&NixOps, args, clock, out, err)
}

pub(crate) fn run_on(
    ops: &impl DirOps,
    args: &[OsString],
    clock: &dyn Clock,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let parsed = match parse(args) {
        Ok(args) => args,
        Err(message) => {
            let _reported = writeln!(err, "{message}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let result = match &parsed.change {
        Some((expected, mutation)) => {
            mutate_on(ops, &parsed.dir, parsed.options, *expected, mutation, clock)
                .map(|grant| report(&grant, true))
        }
        None => show_on(ops, &parsed.dir, parsed.options).map(|grant| {
            grant
                .as_ref()
                .map_or_else(|| "state=missing".to_owned(), |g| report(g, false))
        }),
    };
    let line = match result {
        Ok(line) => line,
        Err(e) => {
            let code = error_exit(&e);
            let _reported = writeln!(err, "{e}");
            return code;
        }
    };
    match writeln!(out, "{line}").and_then(|()| out.flush()) {
        Ok(()) => EXIT_VERB_DONE,
        Err(e) => {
            let _reported = writeln!(
                err,
                "verb completed but output failed: {e}; run show before retrying"
            );
            EXIT_IO_FAILED
        }
    }
}

pub(super) const fn error_exit(error: &Error) -> i32 {
    match error {
        Error::Uncertain { .. } => EXIT_IO_FAILED,
        Error::Refused(_) | Error::Directory(_) | Error::Unwritten { .. } => EXIT_REFUSED,
    }
}

fn raw(args: &[OsString]) -> Result<(&str, Raw, bool), &'static str> {
    let mut words = args.iter();
    if words.next().and_then(|w| w.to_str()) != Some("debug-grant") {
        return Err("unknown command");
    }
    let verb = words
        .next()
        .and_then(|w| w.to_str())
        .ok_or("missing verb")?;
    if !["issue", "narrow", "revoke", "show"].contains(&verb) {
        return Err("unknown debug-grant verb");
    }
    let mut values = Raw::new();
    let mut accept = false;
    while let Some(word) = words.next() {
        let text = word.to_str().ok_or("non-text flag")?;
        if text == "--accept-unsupported-filesystem" {
            if accept {
                return Err("repeated filesystem acknowledgement");
            }
            accept = true;
            continue;
        }
        let flag = FLAGS
            .iter()
            .copied()
            .find(|f| *f == text)
            .ok_or("unknown flag")?;
        if values.contains_key(flag) {
            return Err("repeated flag");
        }
        let value = words.next().ok_or("missing flag value")?;
        values.insert(flag, value.clone());
    }
    Ok((verb, values, accept))
}

fn parse(args: &[OsString]) -> Result<Args, &'static str> {
    let (verb, values, accept) = raw(args)?;
    let specific: &[&str] = match verb {
        "issue" => &[
            "--principal",
            "--volume",
            "--duration-secs",
            "--lines",
            "--bytes",
            "--owner",
            "--reason",
        ],
        "narrow" => &[
            "--generation",
            "--principal",
            "--volume",
            "--expires-at",
            "--lines",
            "--bytes",
        ],
        "revoke" => &["--generation"],
        _ => &[],
    };
    for &flag in values.keys() {
        let common = flag == "--dir"
            || (verb != "show" && ["--incarnation", "--expected-revision"].contains(&flag));
        if !common && !specific.contains(&flag) {
            return Err("flag not accepted by this verb");
        }
    }
    let dir = PathBuf::from(values.get("--dir").ok_or("missing --dir")?);
    if !dir.is_absolute() {
        return Err("--dir must be absolute");
    }
    let change = if verb == "show" {
        None
    } else {
        let expected = Expected {
            incarnation: incarnation(text(&values, "--incarnation")?)?,
            revision: number(&values, "--expected-revision")?,
        };
        Some((expected, mutation(verb, &values)?))
    };
    Ok(Args {
        dir,
        options: VerbOptions {
            accept_unsupported_filesystem: accept,
        },
        change,
    })
}

fn mutation(verb: &str, raw: &Raw) -> Result<Mutation, &'static str> {
    match verb {
        "issue" => {
            let issue = Issue {
                scope: scope(raw)?,
                duration: number(raw, "--duration-secs")?,
                lines: number(raw, "--lines")?,
                bytes: number(raw, "--bytes")?,
                owner: Owner::from_bytes(text(raw, "--owner")?.as_bytes())
                    .map_err(|_| "invalid owner")?,
                reason: Reason::from_bytes(text(raw, "--reason")?.as_bytes())
                    .map_err(|_| "invalid reason")?,
            };
            if !(1..=u64::try_from(DURATION_MAX_SECS).unwrap_or(0)).contains(&issue.duration)
                || !(1..=LINE_CEILING_MAX).contains(&issue.lines)
                || !(1024..=BYTE_CEILING_MAX).contains(&issue.bytes)
            {
                return Err("issuance duration or budget outside bounds");
            }
            Ok(Mutation::Issue(issue))
        }
        "narrow" => {
            let narrow = Narrow {
                generation: generation(raw)?,
                scope: scope(raw)?,
                expires_at: timestamp(text(raw, "--expires-at")?)?,
                lines: number(raw, "--lines")?,
                bytes: number(raw, "--bytes")?,
            };
            if narrow.lines > LINE_CEILING_MAX || narrow.bytes > BYTE_CEILING_MAX {
                return Err("budget outside bounds");
            }
            Ok(Mutation::Narrow(narrow))
        }
        "revoke" => Ok(Mutation::Revoke {
            generation: generation(raw)?,
        }),
        _ => Err("unknown mutation"),
    }
}

fn text<'a>(raw: &'a Raw, flag: &str) -> Result<&'a str, &'static str> {
    raw.get(flag)
        .ok_or("missing required flag")?
        .to_str()
        .ok_or("non-text flag value")
}

fn number(raw: &Raw, flag: &str) -> Result<u64, &'static str> {
    let s = text(raw, flag)?;
    let n = s.parse::<u64>().map_err(|_| "invalid integer")?;
    if s != n.to_string() {
        return Err("noncanonical integer");
    }
    Ok(n)
}

fn generation(raw: &Raw) -> Result<u64, &'static str> {
    let n = number(raw, "--generation")?;
    if n == 0 {
        return Err("generation must be nonzero");
    }
    Ok(n)
}

pub(crate) fn incarnation(s: &str) -> Result<Incarnation, &'static str> {
    let hex = s
        .strip_prefix("incarnation:")
        .ok_or("invalid incarnation prefix")?;
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid incarnation hex");
    }
    let mut bytes = [0; 16];
    for (dest, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).map_err(|_| "invalid incarnation hex")?;
        *dest = u8::from_str_radix(text, 16).map_err(|_| "invalid incarnation hex")?;
    }
    Ok(Incarnation::from_bytes(bytes))
}

fn timestamp(s: &str) -> Result<Timestamp, &'static str> {
    let (seconds, nanos) = s
        .split_once('.')
        .ok_or("timestamp needs seconds and nine nanosecond digits")?;
    let secs = seconds
        .parse::<i64>()
        .map_err(|_| "invalid timestamp seconds")?;
    if seconds != secs.to_string() || nanos.len() != 9 || !nanos.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical timestamp");
    }
    let nanos = nanos.parse::<u32>().map_err(|_| "invalid nanoseconds")?;
    if nanos >= 1_000_000_000 {
        return Err("invalid nanoseconds");
    }
    Ok(Timestamp { secs, nanos })
}

fn scope(raw: &Raw) -> Result<GrantScope, &'static str> {
    let principal = raw
        .get("--principal")
        .map(|_| {
            PrincipalId::parse_written(text(raw, "--principal")?).map_err(|_| "invalid principal")
        })
        .transpose()?;
    let volume = raw
        .get("--volume")
        .map(|_| {
            VolumeName::from_bytes(text(raw, "--volume")?.as_bytes()).map_err(|_| "invalid volume")
        })
        .transpose()?;
    match (principal, volume) {
        (Some(principal), Some(volume)) => Ok(GrantScope::Conjunction { principal, volume }),
        (Some(p), None) => Ok(GrantScope::Principal(p)),
        (None, Some(v)) => Ok(GrantScope::Volume(v)),
        (None, None) => Err("a principal or volume is required"),
    }
}

fn report(grant: &DebugGrant, written: bool) -> String {
    let f = grant.fields();
    let action = match f.action {
        GrantAction::Issue => "issue",
        GrantAction::Narrow => "narrow",
        GrantAction::Revoke => "revoke",
    };
    let mut incarnation = String::from("incarnation:");
    for byte in f.incarnation.as_bytes() {
        use std::fmt::Write as _;
        let _formatted = write!(incarnation, "{byte:02x}");
    }
    let scope = match &f.scope {
        GrantScope::Principal(p) => format!("scope=principal principal={p}"),
        GrantScope::Volume(v) => format!("scope=volume volume={}", v.as_str()),
        GrantScope::Conjunction { principal, volume } => format!(
            "scope=conjunction principal={principal} volume={}",
            volume.as_str()
        ),
    };
    let owner: String = f.owner.as_bytes().iter().copied().map(char::from).collect();
    let reason: String = f
        .reason
        .as_bytes()
        .iter()
        .copied()
        .map(char::from)
        .collect();
    let phase = if written {
        format!("event=debug_grant_{action} phase=written")
    } else {
        "state=present".to_owned()
    };
    format!(
        "{phase} action={action} incarnation={incarnation} file_revision={} generation={} {scope} issued_at={}.{:09} expires_at={}.{:09} lines={} bytes={} issuer_uid={} owner={owner:?} reason={reason:?}",
        f.file_revision,
        f.grant_generation,
        f.issued_at.secs,
        f.issued_at.nanos,
        f.expires_at.secs,
        f.expires_at.nanos,
        f.line_ceiling,
        f.byte_ceiling,
        f.issuer_uid
    )
}
