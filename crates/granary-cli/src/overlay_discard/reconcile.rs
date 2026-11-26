// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
// @file-disposition: STAYS — Reconciliation argument admission and dispatch over the pinned server route.

use crate::{
    NoPinsRemedy, admission, pins_from,
    publish_config::{self, PublishConfiguration},
    terminal,
};
use granary_client::{
    ArchiveReconciliation, ClientEvent, OverlayRefusal, PublishRoute, RecordWriter,
    open_publish_route_with_client_credential, publication_config::publication_scope,
};
use granary_core::retained_submission::Scope;
use granary_net::config::ENV_TLS_PINS;
use granary_store::crypto::TrustedKeys;
use std::{collections::BTreeSet, ffi::OsString, fmt, io::Write, process::ExitCode};

pub(super) const HELP: &str = "\
gran overlay reconcile --store-dir DIR --scope S --volume V --writer W \\
  --journal-incarnation I --endpoint URL --pin sha256/... --credential-context NAME \\
  --publisher-key ed25519:... [--client-cert FILE --client-key FILE]";

struct Args {
    selection: super::Args,
    route: Scope,
    endpoint: String,
    configuration: PublishConfiguration,
    keys: TrustedKeys,
}

fn parse(flags: &[OsString], env: &dyn Fn(&str) -> Option<String>) -> Option<Args> {
    let mut configuration = PublishConfiguration::default();
    let mut endpoint = None;
    let mut pins = Vec::new();
    let mut singles = BTreeSet::new();
    let selection = super::parse_selection(flags, true, |flag, value| {
        if !matches!(flag, "--pin" | "--publisher-key") && !singles.insert(flag.to_owned()) {
            return None;
        }
        match flag {
            "--endpoint" => endpoint = Some(value.to_str()?.to_owned()),
            "--pin" => pins.extend(parse_pins("--pin", value.to_str()?)?),
            flag if publish_config::FLAGS.contains(&flag) => {
                configuration.option(flag, Some(value)).ok()?;
            }
            _ => return None,
        }
        Some(())
    })?;
    configuration.validate(false).ok()?;
    let endpoint = endpoint?;
    let context = configuration.context.as_ref()?;
    if pins.is_empty() {
        pins = parse_pins(ENV_TLS_PINS, &env(ENV_TLS_PINS)?)?;
    }
    let route = publication_scope(&endpoint, &pins, context).ok()?;
    let keys = configuration.publishers.read_keys().ok()?;
    Some(Args {
        selection,
        route,
        endpoint,
        configuration,
        keys,
    })
}

fn parse_pins(source: &str, raw: &str) -> Option<Vec<granary_net::pin::SpkiPin>> {
    pins_from(source, raw, NoPinsRemedy::RecoverHasNoSecondRoute).ok()
}

pub(super) fn invoke(flags: &[OsString], log: &impl RecordWriter) -> ExitCode {
    if matches!(flags, [help] if help == "--help") {
        let _ = writeln!(std::io::stdout().lock(), "{HELP}");
        return ExitCode::SUCCESS;
    }
    let Some(args) = parse(flags, &|name| std::env::var(name).ok()) else {
        terminal::write_line(format_args!("{HELP}"));
        return ExitCode::from(2);
    };
    match run(&args, log) {
        Ok(exit) => exit,
        Err((reason, error)) => {
            report_refusal(log, reason, format_args!("{error}"));
            ExitCode::FAILURE
        }
    }
}

fn report_refusal(log: &impl RecordWriter, reason: OverlayRefusal, error: fmt::Arguments<'_>) {
    terminal::write_line(format_args!("gran overlay reconcile: {error}"));
    log.write_record(&ClientEvent::overlay_reconcile_refused(reason).project().0);
}

fn run(args: &Args, log: &impl RecordWriter) -> Result<ExitCode, (OverlayRefusal, String)> {
    let credentials = admission::process_credentials();
    if let Some(error) = admission::set_id_refusal(&credentials) {
        return Err((OverlayRefusal::SetId, error));
    }
    let tuple = args.selection.selection.ok_or_else(|| {
        let reason = OverlayRefusal::SelectionChanged;
        (reason, reason.as_str().into())
    })?;
    let archive = ArchiveReconciliation::open(
        &args.selection.root,
        args.selection.scope,
        &args.selection.volume,
        tuple,
    )
    .map_err(|error| (error.reason(), error.to_string()))?;
    if archive.is_settled_locally() {
        if archive.settled_without_publication_scope() {
            terminal::write_line(format_args!(
                "gran overlay reconcile: no publications directory for the selected scope; settled with no retained records"
            ));
        }
        return Ok(ExitCode::SUCCESS);
    }
    let credential = args
        .configuration
        .load(credentials.euid)
        .map_err(|error| unresolved(format_args!(": {error}")))?;
    let route = open_publish_route_with_client_credential(
        &args.endpoint,
        Some(args.route.pins.clone()),
        false,
        None,
        credential,
        &|_| None,
    )
    .map_err(|_| unresolved(format_args!(": could not construct authority route")))?;
    let PublishRoute::Server(remote) = route else {
        return Err(unresolved(format_args!("")));
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| unresolved(format_args!(": could not create runtime")))?;
    let rows = runtime.block_on(archive.reconcile(&remote, &args.route, &args.keys));
    write_rows(
        rows.iter().map(|row| (row, row.refusal_reason())),
        &mut std::io::stdout().lock(),
        log,
    )
}

fn unresolved(detail: fmt::Arguments<'_>) -> (OverlayRefusal, String) {
    let reason = OverlayRefusal::Unresolved;
    (reason, format!("{}{detail}", reason.as_str()))
}

fn write_rows(
    rows: impl IntoIterator<Item = (impl fmt::Display, Option<OverlayRefusal>)>,
    out: &mut impl Write,
    log: &impl RecordWriter,
) -> Result<ExitCode, (OverlayRefusal, String)> {
    let mut refused = false;
    let output_failed = |_| unresolved(format_args!(": output failed"));
    for (row, reason) in rows {
        write!(out, "{row}").map_err(output_failed)?;
        if let Some(reason) = reason {
            report_refusal(log, reason, format_args!("{}", reason.as_str()));
            refused = true;
        }
    }
    out.flush().map_err(output_failed)?;
    Ok(if refused {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests;
