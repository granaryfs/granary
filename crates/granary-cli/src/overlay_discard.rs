// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use crate::terminal;
use granary_client::{
    BundleHistory, ClientEvent, LogFormat, LogPaths, OverlayRefusal, RecordWriter,
};
use granary_core::{overlay_discard::parse_hex, root::VolumeName};
use std::{ffi::OsString, io::Write as _, path::PathBuf, process::ExitCode};

mod reconcile;

pub(super) const HELP: &str = "\
gran overlay discard --plan --store-dir DIR --scope S --volume V
gran overlay discard --store-dir DIR --scope S --volume V --writer W \\
  --journal-incarnation I --acknowledge-unsynced-loss --acknowledge-may-land";

#[derive(Debug)]
struct Args {
    root: PathBuf,
    scope: [u8; 32],
    volume: VolumeName,
    selection: Option<([u8; 16], [u8; 32])>,
}

fn parse(args: &[OsString]) -> Option<Args> {
    let [verb, flags @ ..] = args else {
        return None;
    };
    if verb != "discard" {
        return None;
    }
    parse_selection(flags, false, |_, _| None)
}

fn parse_selection(
    flags: &[OsString],
    reconcile: bool,
    mut route_option: impl FnMut(&str, &OsString) -> Option<()>,
) -> Option<Args> {
    let mut data = std::collections::BTreeMap::new();
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        let flag = flag.to_str()?;
        let value = match flag {
            "--store-dir" | "--scope" | "--volume" | "--writer" | "--journal-incarnation" => {
                let value = flags.next()?;
                if value.is_empty() || value.as_encoded_bytes().starts_with(b"--") {
                    return None;
                }
                Some(value)
            }
            "--plan" | "--acknowledge-unsynced-loss" | "--acknowledge-may-land" => None,
            _ if reconcile => {
                let value = flags.next()?;
                if value.is_empty() || value.as_encoded_bytes().starts_with(b"--") {
                    return None;
                }
                route_option(flag, value)?;
                continue;
            }
            _ => return None,
        };
        if data.insert(flag, value).is_some() {
            return None;
        }
    }
    let root = PathBuf::from(data.remove("--store-dir")??);
    let scope = parse_hex(data.remove("--scope")??.to_str()?).ok()?;
    let volume = VolumeName::from_bytes(data.remove("--volume")??.as_encoded_bytes()).ok()?;
    let selection = if !reconcile && data.remove("--plan").is_some() {
        None
    } else {
        if !reconcile {
            data.remove("--acknowledge-unsynced-loss")?;
            data.remove("--acknowledge-may-land")?;
        }
        Some((
            parse_hex(data.remove("--writer")??.to_str()?).ok()?,
            parse_hex(data.remove("--journal-incarnation")??.to_str()?).ok()?,
        ))
    };
    data.is_empty().then_some(Args {
        root,
        scope,
        volume,
        selection,
    })
}

pub(super) fn invoke(args: &[OsString]) -> ExitCode {
    let (log, _worker) = crate::sink::sink_to(crate::logging::Destination::with_policy(
        std::io::stderr(),
        None,
        LogFormat::Json,
        LogPaths::Redacted,
        BundleHistory::default(),
    ));
    if let [verb, flags @ ..] = args
        && verb == "reconcile"
    {
        return reconcile::invoke(flags, &log);
    }
    if matches!(args, [verb, help] if verb == "discard" && help == "--help")
        || matches!(args, [help] if help == "--help")
    {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{HELP}");
        if matches!(args, [_]) {
            let _ = writeln!(out, "{}", reconcile::HELP);
        }
        return ExitCode::SUCCESS;
    }
    let Some(args) = parse(args) else {
        terminal::write_line(format_args!("{HELP}"));
        return ExitCode::from(2);
    };
    invoke_discard(&args, &log)
}

fn invoke_discard(args: &Args, log: &impl RecordWriter) -> ExitCode {
    let reason = if let Some(error) =
        crate::admission::set_id_refusal(&crate::admission::process_credentials())
    {
        terminal::write_line(format_args!("gran overlay discard: {error}"));
        OverlayRefusal::SetId
    } else {
        match granary_client::discard_overlay(&args.root, args.scope, &args.volume, args.selection)
        {
            Ok(row) => {
                let mut out = std::io::stdout().lock();
                if write!(out, "{row}").and_then(|()| out.flush()).is_ok() {
                    return ExitCode::SUCCESS;
                }
                terminal::write_line(format_args!(
                    "gran overlay discard: OverlayDiscardDurability: output failed; retry with the same tuple"
                ));
                OverlayRefusal::Durability
            }
            Err(error) => {
                terminal::write_line(format_args!("gran overlay discard: {error}"));
                error.reason()
            }
        }
    };
    log.write_record(&ClientEvent::overlay_discard_refused(reason).project().0);
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests;
