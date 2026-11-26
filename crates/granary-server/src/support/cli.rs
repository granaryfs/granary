// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local argv only; reports use fixed policy reasons, never I/O error bodies.

use super::{SupportExportError, SupportExportRequest, publish_support_export};
use crate::{
    enrollment::{EXIT_IO_FAILED, EXIT_REFUSED, EXIT_USAGE, EXIT_VERB_DONE},
    protected_dir::ProtectionError,
};
use granary_core::{clock::Clock, debug_grant::Incarnation};
use std::{ffi::OsString, io::Write, path::PathBuf};

const USAGE: &str = "usage: granary-server support-export --support-dir S --state-dir D --out A\n\
  [--incarnation incarnation:<32 lowercase hex>] [--accept-unsupported-filesystem]\n\
  S, D and A must be absolute; A must be a new archive outside the source trees\n";

struct Args {
    support: PathBuf,
    state: PathBuf,
    out: PathBuf,
    expected: Option<Incarnation>,
    accept: bool,
}

fn parse(args: &[OsString]) -> Result<Args, &'static str> {
    let mut words = args.iter();
    if words.next().and_then(|w| w.to_str()) != Some("support-export") {
        return Err("unknown command");
    }
    let (mut support, mut state, mut out, mut expected, mut accept) =
        (None, None, None, None, false);
    while let Some(word) = words.next() {
        let flag = word.to_str().ok_or("non-text flag")?;
        match flag {
            "--accept-unsupported-filesystem" => {
                if accept {
                    return Err("repeated filesystem acknowledgement");
                }
                accept = true;
            }
            "--support-dir" | "--state-dir" | "--out" => {
                let slot = match flag {
                    "--support-dir" => &mut support,
                    "--state-dir" => &mut state,
                    _ => &mut out,
                };
                if slot.is_some() {
                    return Err("repeated flag");
                }
                let path = PathBuf::from(words.next().ok_or("missing path")?);
                if !path.is_absolute() {
                    return Err("paths must be absolute");
                }
                *slot = Some(path);
            }
            "--incarnation" => {
                if expected.is_some() {
                    return Err("repeated incarnation");
                }
                expected = Some(crate::debug_grant::cli::incarnation(
                    words
                        .next()
                        .and_then(|w| w.to_str())
                        .ok_or("invalid incarnation text")?,
                )?);
            }
            "--help" => return Err("support export arguments"),
            _ => return Err("unknown flag"),
        }
    }
    Ok(Args {
        support: support.ok_or("missing support directory")?,
        state: state.ok_or("missing state directory")?,
        out: out.ok_or("missing output archive")?,
        expected,
        accept,
    })
}

/// Export using only argv, the Clock seam and protected local files.
/// Success is silent. The binary bounds the wait for diagnostic delivery.
/// Returns 0 complete, 64 usage, 65 policy refusal, or 74 I/O/uncertainty.
pub fn run_support_export_command_line(
    args: &[OsString],
    clock: &dyn Clock,
    err: &mut dyn Write,
) -> i32 {
    let args = match parse(args) {
        Ok(args) => args,
        Err(reason) => {
            let _reported = write!(err, "{reason}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match publish_support_export(
        SupportExportRequest {
            support_dir: &args.support,
            state_dir: &args.state,
            expected_incarnation: args.expected,
            accept_unsupported_filesystem: args.accept,
        },
        &args.out,
        clock,
    ) {
        Ok(()) => EXIT_VERB_DONE,
        Err(error) => {
            let (code, reason) = failure(&error);
            let _reported = writeln!(err, "support-export refused: {reason}");
            code
        }
    }
}

fn failure(error: &SupportExportError) -> (i32, String) {
    match error {
        SupportExportError::Refused(reason) => (EXIT_REFUSED, (*reason).to_owned()),
        SupportExportError::Required { source, reason } => {
            (EXIT_REFUSED, format!("required {source}: {reason}"))
        }
        SupportExportError::PublicationUncertain(_) => {
            (EXIT_IO_FAILED, "publication uncertain".to_owned())
        }
        SupportExportError::Io(error) => {
            // The source library preserves a typed protected-walk failure
            // inside io::Error. Only actual syscall failures are I/O exits.
            match error
                .get_ref()
                .and_then(|e| e.downcast_ref::<ProtectionError>())
            {
                Some(ProtectionError::Missing { .. }) => {
                    (EXIT_REFUSED, "directory missing".to_owned())
                }
                Some(ProtectionError::LinkOrNotDirectory { .. }) => (
                    EXIT_REFUSED,
                    "directory symlink or non-directory".to_owned(),
                ),
                Some(
                    ProtectionError::Rule { .. }
                    | ProtectionError::NotAbsolute { .. }
                    | ProtectionError::NoComponent
                    | ProtectionError::DotComponent { .. },
                ) => (EXIT_REFUSED, "directory protection".to_owned()),
                _ => (EXIT_IO_FAILED, "I/O failure".to_owned()),
            }
        }
    }
}

#[cfg(test)]
mod tests;
