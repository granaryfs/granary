// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local authority lifecycle operations over a stopped, exclusively held log.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

use granary_core::authlog::encode_envelope;
use granary_core::decisionlog::{DecisionLog, LogIoError, MarkerRead};
use granary_core::root::VolumeName;
use granary_core::runmarker::{BootId, RunMarker, decode_marker, encode_marker};
use granary_core::secure_random::SecureRandom;

use crate::authority::initialise::{Prepared, prepare};
use crate::authority::{FileLog, InitialiseError, Initialised, StartRefused, marker_admits};
use crate::enrollment::{EXIT_IO_FAILED, EXIT_REFUSED, EXIT_USAGE, EXIT_VERB_DONE};

/// Timestamps observed through held state-directory descriptors. The root's
/// ctime is required even when the directory contains no entries.
#[derive(Debug, Default, Clone)]
pub struct StateTimes {
    /// The later of each regular file's mtime and ctime, as Unix seconds and nanoseconds.
    pub files: Vec<(i64, i64)>,
    /// Every directory's ctime, including the state directory itself.
    pub directories: Vec<(i64, i64)>,
}

impl StateTimes {
    /// Check the strict before-boot rule. A same-boot chmod/chown also refuses.
    ///
    /// # Errors
    /// Refuses an empty directory observation, invalid timestamps, or any
    /// timestamp at or after the boot start. A stepped-back clock remains an
    /// operator responsibility.
    pub fn check(&self, boot_start: i64) -> io::Result<()> {
        if self.directories.is_empty() {
            return Err(io::Error::other(
                "the state-directory times are unavailable",
            ));
        }
        for &(seconds, nanos) in self.files.iter().chain(&self.directories) {
            if !(0..1_000_000_000).contains(&nanos) {
                return Err(io::Error::other("a state-directory timestamp is malformed"));
            }
            if (seconds, nanos) >= (boot_start, 0) {
                return Err(io::Error::other(
                    "unfence requires a host reboot: a file mtime/ctime or directory ctime is not before the current boot",
                ));
            }
        }
        Ok(())
    }
}

/// A lifecycle refusal, or an uncertain publishing mutation.
#[derive(Debug)]
pub enum LifecycleError {
    /// An unfenced refusal; initialise cleans after its running write succeeds.
    Refused(String),
    /// A publishing mutation began; inspect the state before retrying.
    Publishing(LogIoError),
    /// An admitted refusal's clean publication failed; both causes matter.
    RefusalCleanFailed {
        /// The refusal that required the clean publication.
        refusal: String,
        /// The failed clean publication.
        source: LogIoError,
    },
}

impl LifecycleError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Refused(_) => EXIT_REFUSED,
            Self::Publishing(_) | Self::RefusalCleanFailed { .. } => EXIT_IO_FAILED,
        }
    }
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(message) => f.write_str(message),
            Self::Publishing(LogIoError::SyncFailed) => f.write_str(
                "a sync failed during the lifecycle mutation; its durability is uncertain",
            ),
            Self::Publishing(error) => write!(
                f,
                "the lifecycle mutation failed; its durability is uncertain: {error}"
            ),
            Self::RefusalCleanFailed { refusal, source } => write!(
                f,
                "{refusal}; its clean write failed and durability is uncertain: {source}"
            ),
        }
    }
}
impl std::error::Error for LifecycleError {}

fn refusal(error: impl std::fmt::Display) -> LifecycleError {
    LifecycleError::Refused(error.to_string())
}

/// Initialise under the same run-marker table as an engine start. The caller
/// must hold the directory lock across this entire operation; the CLI's adapter
/// owns it for its life.
/// Draws only for a missing name. Creation uses the log seam's no-replace link.
///
/// # Cancellation safety
/// Not cancel-safe once a publishing call begins. Drive it to completion;
/// the CLI runs it in the foreground without a per-call timeout.
///
/// # Errors
/// The marker or initialise table's refusals, or uncertain publishing I/O.
/// After admission, success and refusals write clean; publishing errors leave
/// the marker as the failed call left it and make no further writes.
pub async fn initialise_log(
    log: &impl DecisionLog,
    volume: &VolumeName,
    random: &mut impl SecureRandom,
    boot: BootId,
) -> Result<Initialised, LifecycleError> {
    initialise_with_store(log, volume, random, boot, None).await
}

async fn initialise_with_store(
    log: &impl DecisionLog,
    volume: &VolumeName,
    random: &mut impl SecureRandom,
    boot: BootId,
    intents: Option<&crate::authority::IntentStore>,
) -> Result<Initialised, LifecycleError> {
    let read = log
        .read_marker()
        .await
        .map_err(|e| refusal(StartRefused::MarkerUnreadable(e)))?;
    marker_admits(read, boot).map_err(refusal)?;
    log.write_marker(&encode_marker(&RunMarker::Running(boot)))
        .await
        .map_err(marker_admission_write_error)?;

    let result = initialise_admitted(log, volume, random, intents).await;
    if !matches!(&result, Err(LifecycleError::Publishing(_))) {
        log.write_marker(&encode_marker(&RunMarker::Clean))
            .await
            .map_err(|source| match &result {
                Err(LifecycleError::Refused(refusal)) => LifecycleError::RefusalCleanFailed {
                    refusal: refusal.clone(),
                    source,
                },
                _ => LifecycleError::Publishing(source),
            })?;
    }
    result
}

async fn initialise_admitted(
    log: &impl DecisionLog,
    volume: &VolumeName,
    random: &mut impl SecureRandom,
    intents: Option<&crate::authority::IntentStore>,
) -> Result<Initialised, LifecycleError> {
    log.remove_temporary(volume)
        .await
        .map_err(|e| refusal(InitialiseError::TemporaryNotRemoved(e)))?;
    let bytes = log
        .read(volume)
        .await
        .map_err(|e| refusal(InitialiseError::Unreadable(e)))?;
    match prepare(bytes.as_deref(), volume, random).map_err(refusal)? {
        Prepared::Create(envelope) => {
            if let Some(store) = intents {
                let mut state = store
                    .io
                    .load_for_rebind(volume)
                    .map_err(refusal)?
                    .unwrap_or(crate::authority::intent::Snapshot {
                        volume: volume.clone(),
                        epoch: envelope.epoch(),
                        principals: std::collections::BTreeMap::new(),
                    });
                state.epoch = envelope.epoch();
                store
                    .io
                    .commit(&state)
                    .map_err(LifecycleError::Publishing)?;
                #[cfg(feature = "crash-points")]
                crate::authority::crash::hit(
                    crate::authority::crash::Site::IntentProvisioned,
                    None,
                );
            }
            log.initialise(&encode_envelope(&envelope))
                .await
                .map_err(LifecycleError::Publishing)?;
            #[cfg(feature = "crash-points")]
            if intents.is_some() {
                crate::authority::crash::hit(
                    crate::authority::crash::Site::IntentProvisionLogSynced,
                    None,
                );
            }
            Ok(Initialised::Created {
                epoch: envelope.epoch(),
            })
        }
        Prepared::Keep {
            envelope,
            committed_len,
            tail_len,
        } => {
            if tail_len > 0 {
                let len = u64::try_from(committed_len).map_err(refusal)?;
                log.truncate(volume, len)
                    .await
                    .map_err(LifecycleError::Publishing)?;
            }
            log.complete_namespace(volume)
                .await
                .map_err(LifecycleError::Publishing)?;
            Ok(Initialised::Kept {
                epoch: envelope.epoch(),
            })
        }
    }
}

/// Write clean only after every observed timestamp predates this boot.
/// The caller holds the lock across observation and this call. A marker running
/// in this boot refuses regardless of the times. Absent and malformed markers,
/// clean, and running in another boot still require the time rule.
///
/// # Cancellation safety
/// Not cancel-safe once the marker write begins. Drive it to completion.
///
/// # Errors
/// A marker-read, current-boot, time or temporary refusal, or uncertain
/// publishing I/O from the marker write.
pub async fn unfence_log(
    log: &impl DecisionLog,
    boot_start: i64,
    times: &StateTimes,
    boot: BootId,
) -> Result<(), LifecycleError> {
    let marker = log
        .read_marker()
        .await
        .map_err(|e| refusal(StartRefused::MarkerUnreadable(e)))?;
    if let MarkerRead::Present(bytes) = marker
        && let Ok(RunMarker::Running(marker_boot)) = decode_marker(&bytes)
        && marker_boot == boot
    {
        return Err(refusal(StartRefused::RunningInThisBoot));
    }
    times.check(boot_start).map_err(refusal)?;
    log.write_marker(&encode_marker(&RunMarker::Clean))
        .await
        .map_err(marker_admission_write_error)
}

fn marker_admission_write_error(error: LogIoError) -> LifecycleError {
    match error {
        LogIoError::AlreadyExists => refusal(StartRefused::MarkerTemporaryTaken),
        error => LifecycleError::Publishing(error),
    }
}

fn epoch_text(epoch: granary_core::authlog::Epoch) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(32);
    for byte in epoch.to_bytes() {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

const USAGE: &str = "usage: granary-server initialise --state-dir D --volume V\n       granary-server unfence --state-dir D\n  D must be absolute. Both accept --accept-unsupported-filesystem.\n";

struct Args {
    initialise: bool,
    dir: PathBuf,
    volume: Option<VolumeName>,
    accept: bool,
}

fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut words = args.iter();
    let initialise = match words.next().and_then(|word| word.to_str()) {
        Some("initialise") => true,
        Some("unfence") => false,
        _ => return Err("expected initialise or unfence".into()),
    };
    let (mut dir, mut volume, mut accept) = (None, None, false);
    while let Some(flag) = words.next() {
        if flag == "--accept-unsupported-filesystem" {
            if accept {
                return Err("--accept-unsupported-filesystem given twice".into());
            }
            accept = true;
            continue;
        }
        let slot = if flag == "--state-dir" {
            &mut dir
        } else if flag == "--volume" && initialise {
            &mut volume
        } else {
            return Err(format!("unknown argument `{}`", flag.display()));
        };
        if slot.is_some() {
            return Err(format!("{} given twice", flag.display()));
        }
        *slot = Some(
            words
                .next()
                .ok_or_else(|| format!("{} needs a value", flag.display()))?
                .clone(),
        );
    }
    let dir = PathBuf::from(dir.ok_or("this verb needs --state-dir")?);
    if !dir.is_absolute() {
        return Err("--state-dir must be absolute".into());
    }
    let volume = if initialise {
        let raw = volume.ok_or("this verb needs --volume")?;
        Some(
            VolumeName::new(raw.to_str().ok_or("--volume must be text")?.to_owned())
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    Ok(Args {
        initialise,
        dir,
        volume,
        accept,
    })
}

/// Run the operator command before any server configuration is read.
/// Outputs `created V EPOCH`, `kept V EPOCH`, or `clean` on success.
/// The boot readers are injectable; production supplies the host kernel readers.
pub fn run_lifecycle_command_line(
    args: &[OsString],
    random: &mut impl SecureRandom,
    boot_start: impl FnOnce() -> io::Result<i64>,
    boot_id: impl FnOnce() -> io::Result<BootId>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let args = match parse(args) {
        Ok(args) => args,
        Err(error) => {
            let _ = write!(err, "{error}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let execute = || -> Result<String, LifecycleError> {
        let log = FileLog::for_verb(&args.dir, args.accept).map_err(refusal)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(refusal)?;
        if args.initialise {
            let volume = args
                .volume
                .as_ref()
                .ok_or_else(|| refusal("missing volume"))?;
            let boot = boot_id().map_err(refusal)?;
            let result = runtime.block_on(initialise_with_store(
                &log,
                volume,
                random,
                boot,
                Some(&log.intent_store()),
            ))?;
            Ok(match result {
                Initialised::Created { epoch } => {
                    format!("created {} {}", volume.as_str(), epoch_text(epoch))
                }
                Initialised::Kept { epoch } => {
                    format!("kept {} {}", volume.as_str(), epoch_text(epoch))
                }
            })
        } else {
            let current_boot = boot_id().map_err(refusal)?;
            let boot = boot_start().map_err(refusal)?;
            let times = log.state_times().map_err(refusal)?;
            runtime.block_on(unfence_log(&log, boot, &times, current_boot))?;
            Ok("clean".into())
        }
    };
    match execute() {
        Ok(line) => match writeln!(out, "{line}").and_then(|()| out.flush()) {
            Ok(()) => EXIT_VERB_DONE,
            Err(error) => {
                let _ = writeln!(err, "the verb completed but its output failed: {error}");
                EXIT_IO_FAILED
            }
        },
        Err(error) => {
            let _ = writeln!(err, "{error}");
            error.exit_code()
        }
    }
}

#[cfg(test)]
mod tests;
