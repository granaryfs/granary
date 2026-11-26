// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Explicit writer recovery, with publication's credential and key custody.

use crate::{
    NoPinsRemedy, WallClock,
    admission::{ProcessCredentials, process_credentials, set_id_refusal},
    path_separation::refuse_managed_paths,
    pins_from,
    publish_config::{self, PublishConfiguration},
    terminal,
};
use granary_client::{
    ClientEvent, LogPaths, OverlayConfig, OverlayDisk, PublishRoute, RecoveryCommand,
    RecoveryCommandError, RecoveryConflictInventory, RecoveryOutcome, Store,
    open_publish_route_with_client_credential, publication_config::publication_scope,
};
use granary_core::{rng::ProcessRng, root::VolumeName};
use granary_net::{config::ENV_TLS_PINS, pin::SpkiPin, secure_random::OsSecureRandom};
use std::{ffi::OsString, io::Write, path::PathBuf, process::ExitCode};

pub(crate) const HELP: &str = "       gran recover <store-dir> <volume> --writer <32 lowercase hex> --key-seed <file>\n         --endpoint <url> --pin sha256/... --credential-context <name>\n         [--construction-workspace-mib N] [--overlay-cap-bytes N] [--acknowledge-takeover <writer>] [--acknowledge-resend <publication-id>]\n         [--client-cert FILE --client-key FILE] [--publisher-key ed25519:<64 lowercase hex>]";

pub(crate) struct RecoverArgs {
    construction_workspace_bytes: u64,
    overlay_cap_bytes: u64,
    store_dir: PathBuf,
    volume: VolumeName,
    writer: [u8; 16],
    acknowledge_takeover: Option<[u8; 16]>,
    acknowledge_resend: Option<[u8; 16]>,
    endpoint: String,
    pins: Vec<SpkiPin>,
    key_seed: PathBuf,
    configuration: PublishConfiguration,
}

pub(crate) fn parse(
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<RecoverArgs, String> {
    let mut positional = Vec::new();
    let mut writer = None;
    let mut construction_workspace_bytes = granary_client::SyncOptions::default().workspace_bytes;
    let mut overlay_cap_bytes = 134_217_728;
    let mut acknowledge_takeover = None;
    let mut acknowledge_resend = None;
    let mut endpoint = None;
    let mut pins = None;
    let mut key_seed = None;
    let mut configuration = PublishConfiguration::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let text = arg.to_str().unwrap_or_default();
        let mut value = || it.next().ok_or_else(|| format!("{text} needs a value"));
        let utf8 = |value: &OsString| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{text}: value is not valid UTF-8"))
        };
        match text {
            "--construction-workspace-mib" => {
                construction_workspace_bytes =
                    crate::attach::parse_construction_workspace(&utf8(value()?)?)?;
            }
            "--overlay-cap-bytes" => {
                overlay_cap_bytes = crate::attach::parse_overlay_cap(&utf8(value()?)?)?;
            }
            "--writer" | "--acknowledge-takeover" | "--acknowledge-resend" => {
                let raw = utf8(value()?)?;
                let id = crate::publication::parse_id(&raw).map_err(|_| {
                    format!("{text} must contain exactly 32 lowercase hexadecimal digits")
                })?;
                if text == "--writer" {
                    writer = Some(id);
                } else if text == "--acknowledge-takeover" {
                    acknowledge_takeover = Some(id);
                } else {
                    acknowledge_resend = Some(id);
                }
            }
            "--endpoint" => endpoint = Some(utf8(value()?)?),
            "--key-seed" => key_seed = Some(PathBuf::from(value()?)),
            "--pin" => pins.get_or_insert_with(Vec::new).extend(pins_from(
                "--pin",
                &utf8(value()?)?,
                NoPinsRemedy::RecoverHasNoSecondRoute,
            )?),
            flag if publish_config::FLAGS.contains(&flag) => {
                configuration.option(flag, Some(value()?.as_os_str()))?;
            }
            flag if flag.starts_with("--") => return Err("unknown recover option".into()),
            _ => positional.push(arg),
        }
    }
    configuration.validate(false)?;
    if configuration.context.is_none() {
        return Err("--credential-context is required for recovery".into());
    }
    let [store_dir, volume] = positional.as_slice() else {
        return Err(format!(
            "expected 2 positional arguments (store-dir, volume), got {}",
            positional.len()
        ));
    };
    if pins.is_none()
        && let Some(raw) = env(ENV_TLS_PINS)
    {
        pins = Some(pins_from(
            ENV_TLS_PINS,
            &raw,
            NoPinsRemedy::RecoverHasNoSecondRoute,
        )?);
    }
    let pins =
        pins.ok_or_else(|| "recovery requires --pin sha256/... (or GRANARY_TLS_PINS)".to_owned())?;
    granary_net::pin::PinnedServerVerifier::new(
        pins.clone(),
        granary_net::crypto_provider().into(),
    )
    .map_err(|error| granary_client::HttpStoreError::Pins(error).to_string())?;
    Ok(RecoverArgs {
        construction_workspace_bytes,
        overlay_cap_bytes,
        store_dir: PathBuf::from(store_dir),
        volume: VolumeName::new(
            volume
                .to_str()
                .ok_or("volume name is not valid UTF-8")?
                .to_owned(),
        )
        .map_err(|error| error.to_string())?,
        writer: writer.ok_or("--writer is required")?,
        acknowledge_takeover,
        acknowledge_resend,
        endpoint: endpoint.ok_or("--endpoint is required")?,
        pins,
        key_seed: key_seed.ok_or("--key-seed is required")?,
        configuration,
    })
}

pub(crate) fn invoke(args: &RecoverArgs, paths: LogPaths) -> ExitCode {
    let result = run(args, &process_credentials());
    let stdout = std::io::stdout();
    invoke_result(result, paths, &mut stdout.lock())
}

fn invoke_result(
    result: Result<RecoveryOutcome, RecoverRunError>,
    paths: LogPaths,
    stdout: &mut impl Write,
) -> ExitCode {
    match result {
        Ok(outcome) => {
            let (refusals, archive_report_error) = match outcome {
                RecoveryOutcome::NothingOwed => return ExitCode::SUCCESS,
                RecoveryOutcome::JournalFinished { .. } => (Vec::new(), None),
                RecoveryOutcome::JournalFinishedAfterRefusal { refusals, .. } => (refusals, None),
                RecoveryOutcome::JournalFinishedWithUnavailableRefusalReport {
                    refusals,
                    reason,
                    ..
                } => (refusals, Some(reason)),
            };
            for refusal in refusals {
                terminal::write_line(format_args!(
                    "gran recover: archived publication refusal {refusal}"
                ));
            }
            if let Some(reason) = archive_report_error {
                terminal::write_line(format_args!(
                    "gran recover: archived publication refusal report unavailable: {reason}"
                ));
            }
            terminal::write_line(format_args!(
                "JournalFinished: Journal recovery completed and the writer row was released. Start the writable mount with this store."
            ));
            ExitCode::SUCCESS
        }
        Err(error) => {
            if matches!(error, RecoverRunError::SigningKeyRefused(_)) {
                ClientEvent::recovery_signing_key_refused().emit();
            }
            if let Some(inventory) = error.conflict_inventory()
                && write_inventory(stdout, inventory, paths).is_err()
            {
                terminal::write_line(format_args!(concat!(
                    "gran recover: RecoveryConflictInventoryOutput: B5 inventory output failed. ",
                    "Treat the capture as incomplete and preserve the store."
                )));
            }
            terminal::write_line(format_args!("gran recover: {error}"));
            if let Some(remedy) = remedy(&error.to_string()) {
                terminal::write_line(format_args!("{remedy}"));
            }
            ExitCode::FAILURE
        }
    }
}

fn write_inventory(
    stdout: &mut impl Write,
    inventory: &RecoveryConflictInventory,
    paths: LogPaths,
) -> std::io::Result<()> {
    let bytes = inventory.stdout_bytes(paths)?;
    write_inventory_buffer(stdout, &bytes)
}

fn write_inventory_buffer(stdout: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    stdout.write_all(bytes)?;
    stdout.flush()
}

#[derive(Debug)]
enum RecoverRunError {
    Message(String),
    Command(RecoveryCommandError),
    SigningKeyRefused(&'static str),
}

impl RecoverRunError {
    fn conflict_inventory(&self) -> Option<&RecoveryConflictInventory> {
        match self {
            Self::Command(error) => error.conflict_inventory(),
            Self::Message(_) | Self::SigningKeyRefused(_) => None,
        }
    }
}

impl std::fmt::Display for RecoverRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(error) => f.write_str(error),
            Self::Command(error) => error.fmt(f),
            Self::SigningKeyRefused(detail) => write!(f, "RecoverySigningKeyRefused: {detail}"),
        }
    }
}

impl From<String> for RecoverRunError {
    fn from(error: String) -> Self {
        Self::Message(error)
    }
}

impl From<&'static str> for RecoverRunError {
    fn from(error: &'static str) -> Self {
        Self::Message(error.to_owned())
    }
}

fn remedy(error: &str) -> Option<&'static str> {
    match error {
        "intent refused: RecoveryJournalBlocked" => Some(
            "Preserve this store. Journal recovery is incomplete; inspect the reported reason before retrying. Restore authenticated access or service before retrying transient failures; free space outside retained recovery files for capacity failures. Missing evidence, namespace mismatch or retained debt requires inspection or restoration of matching evidence. Release uncertainty requires service restoration and exact retained replay before the Release deadline; after expiry, the next gran recover refuses IntentFreshInstanceRequired.",
        ),
        "intent refused: IntentFreshInstanceRequired" => Some(
            "Preserve this store; do not delete its overlay area. An earlier run prepared this writer's release and it is unconfirmed, so recovery cannot own the writer again. No in-place repair is available.",
        ),
        "intent refused: RecoveryConflict" | "RecoveryConflict" => Some(
            "Preserve this store and inspect the reported collision. Recovery requires a supported resolution that changes the conflict or head before retrying.",
        ),
        "intent refused: RecoveryArchivedLanded" => Some(
            "stop every process using the volume; preserve <old-store> unchanged: do not delete it, reuse it as cache/store, or run recover/resend against it. Read each known published file with gran cat <volume> <path> --seq <published-seq> --root-key ... --endpoint ... --pin ... --cache-dir <separate-read-cache>, using the recover.archived_landed seq. If service may proceed without the old unpublished changes, use empty separate <fresh-store> and <fresh-cache> paths: gran mount <volume> <mountpoint> --writable --endpoint ... --pin ... --root-key ... --key-seed ... --store-dir <fresh-store> --client-cert ... --client-key ... --credential-context ... --cache-dir <fresh-cache> --foreground. This acquires a fresh writer; retry a cursor race with that same fresh store. If admission or row quota still refuses, preserve the old store and use gran cat until it clears. No command currently reapplies the preserved residual; the planned overlay-discard verb owns its in-place disposition",
        ),
        "intent refused: RecoveryArchivedUnresolved" => Some(
            "stop every process using the volume; preserve <old-store> unchanged: do not delete it, reuse it as cache/store, or run recover/resend against it. The unresolved seq is not claimed published: read each known published file with gran cat <volume> <path> --seq <independently-known-published-seq> --root-key ... --endpoint ... --pin ... --cache-dir <separate-read-cache>. If service may proceed without the old unpublished changes, use empty separate <fresh-store> and <fresh-cache> paths: gran mount <volume> <mountpoint> --writable --endpoint ... --pin ... --root-key ... --key-seed ... --store-dir <fresh-store> --client-cert ... --client-key ... --credential-context ... --cache-dir <fresh-cache> --foreground. This acquires a fresh writer; retry a cursor race with that same fresh store. If admission or row quota still refuses, preserve the old store and use gran cat until it clears. No command currently reapplies the preserved residual; the planned overlay-discard verb owns its in-place disposition",
        ),
        "RecoveryRemoteIntegrity: archived non-landing contradicted" => Some(
            "the authority/storage administrator must investigate the numbered root, decision log and trusted storage history; no authority repair command exists. Keep the volume read-only and preserve <old-store> unchanged until the administrator restores or validates the authoritative chain. Then read each known published file with gran cat <volume> <path> --seq <verified-published-seq> --root-key ... --endpoint ... --pin ... --cache-dir <separate-read-cache>. If service may proceed without the old unpublished changes, use empty separate <fresh-store> and <fresh-cache> paths: gran mount <volume> <mountpoint> --writable --endpoint ... --pin ... --root-key ... --key-seed ... --store-dir <fresh-store> --client-cert ... --client-key ... --credential-context ... --cache-dir <fresh-cache> --foreground. Retry a cursor race with that same fresh store; if admission or row quota still refuses, use gran cat until it clears. Do not delete or reuse the old store, or run recover/resend against it; no command currently reapplies its residual, whose in-place disposition belongs to the planned overlay-discard verb",
        ),
        "intent refused: RecoveryUnresolved" => Some(
            "inspect the retained publication; --acknowledge-resend <publication-id> permits one exact send and keeps the fence until evidence settles it",
        ),
        "intent refused: RecoveryResendUnanswered"
        | "intent refused: RecoveryResendNoWrite"
        | "intent refused: RecoveryResendPending"
        | "intent refused: RecoveryResendInvalidAnswer" => Some(
            "one exact resend was sent; inspect its retained answer and fence before deciding what to do next",
        ),
        _ => None,
    }
}

fn run(
    args: &RecoverArgs,
    credentials: &ProcessCredentials,
) -> Result<RecoveryOutcome, RecoverRunError> {
    if let Some(error) = set_id_refusal(credentials) {
        return Err(error.into());
    }
    refuse_managed_paths(&args.key_seed, args.configuration.key.as_deref(), &args.store_dir, None)
        .map_err(|_| "RecoveryManagedPaths: signing material and store must not nest; inspect the configured paths")?;
    let context = args
        .configuration
        .context
        .as_ref()
        .ok_or("--credential-context is required for recovery")?;
    let scope = publication_scope(&args.endpoint, &args.pins, context)
        .map_err(|error| error.to_string())?;
    let credential = args
        .configuration
        .load(credentials.euid)
        .map_err(|error| error.to_string())?;
    let route = open_publish_route_with_client_credential(
        &args.endpoint,
        Some(args.pins.clone()),
        false,
        None,
        credential,
        &|name| std::env::var(name).ok(),
    )
    .map_err(|error| error.to_string())?;
    let PublishRoute::Server(remote) = route else {
        return Err("recovery requires server authority".into());
    };
    let key =
        granary_client::load_existing_signing_key_with_spare(&args.key_seed, credentials.euid)
            .map_err(|_| {
                RecoverRunError::SigningKeyRefused(
                    "signing seed failed custody or could not be loaded",
                )
            })?;
    let spare = key.spare.ok_or(RecoverRunError::SigningKeyRefused(
        "signing seed did not yield an engine key",
    ))?;
    let trusted = args
        .configuration
        .publishers
        .build(*key.key.public_key())
        .map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime could not be created")?;
    RecoveryCommand {
        construction_workspace_bytes: args.construction_workspace_bytes,
        local: local(args, credentials.euid)?,
        config: overlay_config(args, scope, credentials.euid),
        transport: remote.as_ref(),
        runtime: &runtime,
        signer: &key.key,
        publisher_keys: &trusted,
        writer: args.writer,
        acknowledge_takeover: args.acknowledge_takeover,
        acknowledge_resend: args.acknowledge_resend,
        faults: granary_client::FaultControl::default(),
    }
    .run(
        &std::sync::Arc::new(WallClock),
        spare,
        &mut OsSecureRandom::new(),
        ProcessRng::new(),
    )
    .map_err(RecoverRunError::Command)
}

fn overlay_config(
    args: &RecoverArgs,
    scope: granary_core::retained_submission::Scope,
    euid: u32,
) -> OverlayConfig {
    OverlayConfig {
        scope,
        volume: args.volume.clone(),
        euid,
        cap: args.overlay_cap_bytes,
        ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
        instance: [0; 16],
    }
}

/// The locked store and its overlay io at the root the store resolved. A
/// store directory that does not exist is created only for an acknowledged
/// takeover; without one the run only reports its selection.
fn local(args: &RecoverArgs, euid: u32) -> Result<Option<(Store, OverlayDisk)>, String> {
    if args.acknowledge_takeover != Some(args.writer)
        && std::fs::symlink_metadata(&args.store_dir)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(None);
    }
    let store = Store::open(&args.store_dir).map_err(|error| error.to_string())?;
    let io = OverlayDisk::new(store.publication_root(), euid);
    Ok(Some((store, io)))
}

#[cfg(test)]
mod tests;
