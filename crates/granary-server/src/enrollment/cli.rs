// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The verbs' command line: `granary-server enrollment <verb> …`.
//!
//! The binary with no arguments serves; with a first argument it runs
//! [`run_command_line`] and exits with its code. Arguments are parsed by
//! hand: five verbs and five flags do not earn a parser dependency.
//!
//! The enrollment set's format is frozen v1.
//! Mutating verbs publish the enrollment set; `list` writes nothing.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use granary_core::enrollment::{ClientSpkiDigest, PrincipalId, TenantName};
use granary_core::secure_random::SecureRandom;

use super::verbs::{
    ListReport, VerbError, VerbOptions, attach, list, mint, resolve_credential, retire, revoke,
};

/// The verb did what it was asked.
pub const EXIT_VERB_DONE: i32 = 0;
/// The command line is not one this binary takes (`EX_USAGE`).
pub const EXIT_USAGE: i32 = 64;
/// The set or the directory refused the verb, or an I/O
/// failure stopped it before the rename that publishes a change; nothing
/// was written. `list` also exits with this when the set is unavailable.
pub const EXIT_REFUSED: i32 = 65;
/// An I/O failure (`EX_IOERR`) from the rename on: the change may or may
/// not be visible; run `list` before retrying.
pub const EXIT_IO_FAILED: i32 = 74;

const _: () = {
    // The values are the operator's contract, and the process tests assert
    // against these names; this is where the numbers are pinned.
    assert!(EXIT_VERB_DONE == 0, "0 is done, by contract");
    assert!(EXIT_USAGE == 64, "64 is EX_USAGE, by contract");
    assert!(EXIT_REFUSED == 65, "65 is the refusal, by contract");
    assert!(EXIT_IO_FAILED == 74, "74 is EX_IOERR, by contract");
};

const USAGE: &str = "\
usage: granary-server
           serve, configured by the environment
       granary-server enrollment mint --tenant T --credential C --dir D
       granary-server enrollment attach --principal P --credential C --dir D
       granary-server enrollment revoke --credential C --dir D
       granary-server enrollment retire --principal P --dir D
       granary-server enrollment list --dir D
       granary-server debug-grant issue|narrow|revoke|show --dir D [grant flags]
       granary-server initialise --state-dir D --volume V
       granary-server unfence --state-dir D
       granary-server support-export --support-dir S --state-dir D --out A [support flags]
  C is a credential's written digest (clientspki-v1:…) or a PEM certificate
  file; P is a principal (principal:…); D is the enrollment or authority
  state directory as the command names, an absolute path. Every verb also takes --accept-unsupported-filesystem.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Mint,
    Attach,
    Revoke,
    Retire,
    List,
}

/// One verb and its values.
#[derive(Debug)]
enum Command {
    Mint {
        tenant: TenantName,
        credential: ClientSpkiDigest,
    },
    Attach {
        principal: PrincipalId,
        credential: ClientSpkiDigest,
    },
    Revoke {
        credential: ClientSpkiDigest,
    },
    Retire {
        principal: PrincipalId,
    },
    List,
}

/// One verb's arguments, parsed.
#[derive(Debug)]
struct Args {
    command: Command,
    dir: PathBuf,
    options: VerbOptions,
}

/// Run the command line `args` (the arguments after the program's name)
/// and answer the process's exit code. `door` is the source a minted
/// principal id is drawn from. What a verb wrote goes to `out`, one item
/// per line in its written form; every message goes to `err`.
pub fn run_command_line(
    args: &[OsString],
    door: &mut impl SecureRandom,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            let _reported = write!(err, "{message}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let lines = match execute(&parsed, door) {
        Ok(Done::Lines(lines)) => lines,
        Ok(Done::Unavailable(message)) => {
            let _reported = writeln!(out, "{message}");
            return EXIT_REFUSED;
        }
        Err(e) => {
            let _reported = writeln!(err, "{e}");
            return match e {
                VerbError::Refused(_) | VerbError::Unwritten { .. } => EXIT_REFUSED,
                VerbError::Io { .. } => EXIT_IO_FAILED,
            };
        }
    };
    let mut text = String::new();
    for line in lines {
        text.push_str(&line);
        text.push('\n');
    }
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => EXIT_VERB_DONE,
        Err(e) => {
            let _reported = writeln!(
                err,
                "the verb completed, but its output could not be written: {e}"
            );
            EXIT_IO_FAILED
        }
    }
}

/// What a verb produced.
enum Done {
    Lines(Vec<String>),
    /// `list` on a set the reader would not use: its verdict line.
    Unavailable(String),
}

fn execute(args: &Args, door: &mut impl SecureRandom) -> Result<Done, VerbError> {
    let pair = |(p, d): (PrincipalId, ClientSpkiDigest)| Done::Lines(vec![format!("{p} {d}")]);
    match &args.command {
        Command::Mint { tenant, credential } => {
            mint(&args.dir, args.options, tenant, *credential, door).map(pair)
        }
        Command::Attach {
            principal,
            credential,
        } => attach(&args.dir, args.options, *principal, *credential).map(pair),
        Command::Revoke { credential } => revoke(&args.dir, args.options, *credential).map(pair),
        Command::Retire { principal } => {
            retire(&args.dir, args.options, *principal).map(|p| Done::Lines(vec![p.to_string()]))
        }
        Command::List => list(&args.dir, args.options).map(|report| match report {
            ListReport::Ok(set) => {
                let mut lines = vec![format!(
                    "ok principals={} credentials={}",
                    set.principal_count(),
                    set.credential_count()
                )];
                for (id, state, tenant) in set.principals() {
                    lines.push(format!("principal {id} {state} {tenant}"));
                }
                for (digest, id) in set.credentials() {
                    lines.push(format!("credential {digest} {id}"));
                }
                Done::Lines(lines)
            }
            ListReport::Unavailable { reason, detail } => {
                Done::Unavailable(format!("unavailable {reason}: {detail}"))
            }
        }),
    }
}

/// Parse `args` into one verb's arguments, or a usage message.
fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut words = args.iter();
    match words.next() {
        Some(first) if first == "enrollment" => {}
        Some(first) => {
            return Err(format!(
                "unknown command `{}`; the commands are `enrollment`, `debug-grant`, `support-export`, `initialise` and `unfence`",
                first.display()
            ));
        }
        None => return Err("no command".to_owned()),
    }
    let verb = match words.next().and_then(|w| w.to_str()) {
        Some("mint") => Verb::Mint,
        Some("attach") => Verb::Attach,
        Some("revoke") => Verb::Revoke,
        Some("retire") => Verb::Retire,
        Some("list") => Verb::List,
        Some(other) => return Err(format!("unknown enrollment verb `{other}`")),
        None => return Err("no enrollment verb".to_owned()),
    };
    let mut tenant = None;
    let mut credential = None;
    let mut principal = None;
    let mut dir = None;
    let mut accept = false;
    while let Some(flag) = words.next() {
        let flag = flag
            .to_str()
            .ok_or_else(|| format!("unknown argument `{}`", flag.display()))?;
        if flag == "--accept-unsupported-filesystem" {
            if accept {
                return Err(format!("{flag} given twice"));
            }
            accept = true;
            continue;
        }
        let slot = match flag {
            "--tenant" => &mut tenant,
            "--credential" => &mut credential,
            "--principal" => &mut principal,
            "--dir" => &mut dir,
            other => return Err(format!("unknown argument `{other}`")),
        };
        if slot.is_some() {
            return Err(format!("{flag} given twice"));
        }
        let value = words
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        *slot = Some(value.clone());
    }
    let wanted: &[&str] = match verb {
        Verb::Mint => &["--tenant", "--credential", "--dir"],
        Verb::Attach => &["--principal", "--credential", "--dir"],
        Verb::Revoke => &["--credential", "--dir"],
        Verb::Retire => &["--principal", "--dir"],
        Verb::List => &["--dir"],
    };
    for (name, given) in [
        ("--tenant", tenant.is_some()),
        ("--credential", credential.is_some()),
        ("--principal", principal.is_some()),
        ("--dir", dir.is_some()),
    ] {
        match (wanted.contains(&name), given) {
            (true, false) => return Err(format!("this verb needs {name}")),
            (false, true) => return Err(format!("this verb does not take {name}")),
            _ => {}
        }
    }
    command(verb, tenant, credential, principal, dir, accept)
}

/// Turn one verb's raw flag values into its [`Args`].
fn command(
    verb: Verb,
    tenant: Option<OsString>,
    credential: Option<OsString>,
    principal: Option<OsString>,
    dir: Option<OsString>,
    accept: bool,
) -> Result<Args, String> {
    let tenant = tenant
        .map(|t| {
            let text = t
                .to_str()
                .ok_or_else(|| format!("--tenant `{}` is not text", t.display()))?;
            TenantName::parse(text).map_err(|e| format!("--tenant `{text}`: {e}"))
        })
        .transpose()?;
    let principal = principal
        .map(|p| {
            let text = p
                .to_str()
                .ok_or_else(|| format!("--principal `{}` is not text", p.display()))?;
            PrincipalId::parse_written(text).map_err(|e| format!("--principal `{text}`: {e}"))
        })
        .transpose()?;
    let credential = credential
        .map(|c| resolve_credential(&c).map_err(|e| format!("--credential `{}`: {e}", c.display())))
        .transpose()?;
    let missing = || "a required flag is missing".to_owned();
    let command = match verb {
        Verb::Mint => Command::Mint {
            tenant: tenant.ok_or_else(missing)?,
            credential: credential.ok_or_else(missing)?,
        },
        Verb::Attach => Command::Attach {
            principal: principal.ok_or_else(missing)?,
            credential: credential.ok_or_else(missing)?,
        },
        Verb::Revoke => Command::Revoke {
            credential: credential.ok_or_else(missing)?,
        },
        Verb::Retire => Command::Retire {
            principal: principal.ok_or_else(missing)?,
        },
        Verb::List => Command::List,
    };
    Ok(Args {
        command,
        dir: PathBuf::from(dir.ok_or_else(missing)?),
        options: VerbOptions {
            accept_unsupported_filesystem: accept,
        },
    })
}
