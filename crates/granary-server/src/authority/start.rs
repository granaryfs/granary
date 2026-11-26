// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The engine's start: the run marker's gate, recovery and replay.
//!
//! In this order:
//! 1. The marker is read and answered by spec §6.2's table against the
//!    given boot id. A refused row writes nothing; a read error is a
//!    refused row too (the seam reports a non-regular or symlinked marker
//!    as one), and a read never fences. An admitted row makes **running**
//!    under the boot id durable; that write's `AlreadyExists` is a refused
//!    start that wrote nothing, and any other error fences.
//! 2. Each configured volume in turn has its leftover temporary removed
//!    by its exact name, then is read and classified, and its committed
//!    records replayed through the one state machine. **No log write is
//!    made before every volume has been classified**: each volume's
//!    temporary removal, made as that volume is classified, is the only
//!    change this step makes, so a refusal on a later volume can follow
//!    the removal of an earlier volume's temporary. A missing log is "no
//!    log" for that volume alone. A failed removal, a file with no
//!    envelope, a refusal, a replay the state machine refuses, or any
//!    read error other than a missing name refuses the whole start, which
//!    then tells the host ([`AdmittedRefusal`]) and only then writes
//!    **clean**: no log write was made.
//! 3. Each log is then made ready: a tail is truncated to the committed
//!    length, a log holding records is re-synced (a committed survivor is
//!    made durable again before it is served), and a log with an envelope
//!    and no record runs `complete_namespace`, so its first append follows
//!    a durable name. Every error here fences.
//!
//! Replay is pure, so running it in step 2 rather than after step 3
//! changes nothing it produces; it lets a replay refusal refuse the start
//! before any log write is made.
//!
//! The owed attestation of an open entry is the worker's first step, in
//! the driver's `run()`, not part of the start.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use granary_core::authlog::{Classified, LogError, classify};
use granary_core::clock::Clock;
use granary_core::decisionlog::{DecisionLog, LogIoError, MarkerRead, StateDirectory};
use granary_core::rng::Rng;
use granary_core::root::VolumeName;
use granary_core::rootstore::RootStore;
use granary_core::runmarker::{BootId, MarkerDecodeError, RunMarker, decode_marker, encode_marker};
use granary_core::secure_random::SecureRandom;
use granary_store::crypto::TrustedKeys;
use tokio::sync::{mpsc, watch};

use super::gate::{Fence, FenceCause, LogCall, LogGate};
use super::ready::Readiness;
use super::state::{ApplyError, VolumeState};
use super::worker::Worker;
use super::{
    AdmissionRuntime, AuthorityDriver, AuthorityHandle, AuthorityParts, HandleInner, Notices,
    Pause, Shared, VolumeConfig, write_clean,
};

/// How many requests a volume's worker holds before a sender waits.
const INBOX: usize = 16;

/// Why a volume refused the start (step 2 of the module docs). The start
/// wrote **clean** before answering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeRefusal {
    /// Removing the volume's leftover temporary failed.
    TemporaryNotRemoved(LogIoError),
    /// Reading the log's name failed with something other than a missing
    /// name: a symlink, a non-regular file, a permission error.
    Unreadable(LogIoError),
    /// A file at the log's name holds no whole envelope.
    NoEnvelope,
    /// Recovery refused the file: damage, an unknown version, another
    /// volume's envelope, a grammar break.
    Damaged(LogError),
    /// The state machine refused a committed record `classify` accepted.
    Replay(ApplyError),
}

impl std::fmt::Display for VolumeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TemporaryNotRemoved(e) => {
                write!(f, "its leftover temporary was not removed: {e}")
            }
            Self::Unreadable(e) => write!(f, "its log could not be read: {e}"),
            Self::NoEnvelope => write!(f, "a file at its log's name holds no envelope"),
            Self::Damaged(e) => write!(f, "{e}"),
            Self::Replay(e) => write!(f, "replay refused a committed record: {e}"),
        }
    }
}

/// A refusal the start found after the marker admitted it (step 2 of the
/// module docs): what [`super::Notices::refusal`] is sent before the
/// start's **clean** write begins. The start then returns
/// [`StartRefused::Volume`] with the same volume and reason if that write
/// succeeds, or [`StartRefused::Fenced`] if it fences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedRefusal {
    /// The volume that refused.
    pub volume: VolumeName,
    /// Why it refused.
    pub reason: VolumeRefusal,
}

/// Why the engine did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartRefused {
    /// The configuration names a volume twice. Nothing was read.
    DuplicateVolume(VolumeName),
    /// The run marker could not be read (spec §6.2's table: not a regular
    /// file, a symlink, or any other read error). Nothing was written.
    MarkerUnreadable(LogIoError),
    /// The run marker is malformed or torn. Nothing was written.
    MarkerMalformed(MarkerDecodeError),
    /// The run marker says **running** under the current boot: an earlier
    /// run of this boot did not stop cleanly, or fenced. Nothing was
    /// written; only a host reboot (or an operator unfence) clears it.
    RunningInThisBoot,
    /// There is no run marker, and the state directory holds something.
    /// Nothing was written.
    StateDirectoryOccupied,
    /// Writing **running** found the marker's temporary name taken.
    /// Nothing was written, and the marker is as it was.
    MarkerTemporaryTaken,
    /// The marker admitted the start and `volume` refused it. **Clean**
    /// was written: no log write had been made.
    Volume {
        volume: VolumeName,
        reason: VolumeRefusal,
    },
    /// A mutating log call failed during the start: the engine is fenced
    /// and only a host reboot clears it. The marker was left as that call
    /// left it.
    Fenced(Fence),
}

impl std::fmt::Display for StartRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateVolume(v) => write!(f, "volume {} is configured twice", v.as_str()),
            Self::MarkerUnreadable(e) => write!(f, "the run marker could not be read: {e}"),
            Self::MarkerMalformed(e) => write!(f, "the run marker is malformed: {e}"),
            Self::RunningInThisBoot => {
                write!(
                    f,
                    "the run marker says running in this boot: reboot the host first"
                )
            }
            Self::StateDirectoryOccupied => {
                write!(f, "no run marker, and the state directory is not empty")
            }
            Self::MarkerTemporaryTaken => write!(f, "the run marker's temporary name is taken"),
            Self::Volume { volume, reason } => {
                write!(f, "volume {} refused the start: {reason}", volume.as_str())
            }
            Self::Fenced(fence) => write!(f, "{fence}"),
        }
    }
}

impl std::error::Error for StartRefused {}

/// Spec §6.2's table for a marker that was read.
pub(crate) fn marker_admits(read: MarkerRead, boot: BootId) -> Result<(), StartRefused> {
    match read {
        MarkerRead::Present(bytes) => match decode_marker(&bytes) {
            Err(e) => Err(StartRefused::MarkerMalformed(e)),
            Ok(RunMarker::Running(running)) if running == boot => {
                Err(StartRefused::RunningInThisBoot)
            }
            Ok(RunMarker::Running(_) | RunMarker::Clean) => Ok(()),
        },
        MarkerRead::Missing {
            state_dir: StateDirectory::Absent | StateDirectory::Empty,
        } => Ok(()),
        MarkerRead::Missing {
            state_dir: StateDirectory::Occupied,
        } => Err(StartRefused::StateDirectoryOccupied),
    }
}

/// A configured volume after step 2.
struct Found {
    volume: VolumeName,
    keys: TrustedKeys,
    intents: super::intent_worker::Intents,
    log: Option<Adopted>,
}

/// A log step 2 accepted, with what step 3 owes it.
struct Adopted {
    state: VolumeState,
    readiness: Readiness,
}

/// Step 2 for one volume: remove its temporary, read, classify, replay.
async fn classify_volume<L: DecisionLog>(
    log: &L,
    config: &VolumeConfig,
) -> Result<Found, VolumeRefusal> {
    let volume = &config.volume;
    log.remove_temporary(volume)
        .await
        .map_err(VolumeRefusal::TemporaryNotRemoved)?;
    let read = log.read(volume).await.map_err(VolumeRefusal::Unreadable)?;
    let Some(bytes) = read else {
        return Ok(Found {
            volume: volume.clone(),
            keys: config.keys.clone(),
            intents: super::intent_worker::Intents::load(
                config.intents.clone(),
                volume,
                &config.keys,
            ),
            log: None,
        });
    };
    match classify(&bytes, volume) {
        Err(e) => Err(VolumeRefusal::Damaged(e)),
        Ok(Classified::NoEnvelope) => Err(VolumeRefusal::NoEnvelope),
        Ok(Classified::Log {
            envelope,
            records,
            committed_len,
            tail_len,
        }) => {
            let state = VolumeState::replay(envelope, &records).map_err(VolumeRefusal::Replay)?;
            Ok(Found {
                volume: volume.clone(),
                keys: config.keys.clone(),
                intents: super::intent_worker::Intents::load(
                    config.intents.clone(),
                    volume,
                    &config.keys,
                ),
                log: Some(Adopted {
                    state,
                    readiness: Readiness::new(committed_len, tail_len, !records.is_empty()),
                }),
            })
        }
    }
}

/// Tell the host of an admitted start's refusal, then write **clean**:
/// the refusal came before any log write. The notice is sent before the
/// write begins, so a host sees it even while the write hangs.
async fn refuse_admitted<L: DecisionLog>(
    log: &L,
    gate: &LogGate,
    shared: &Shared,
    notice: &watch::Sender<Option<AdmittedRefusal>>,
    refused: AdmittedRefusal,
) -> StartRefused {
    notice.send_replace(Some(refused.clone()));
    match write_clean(log, gate, &shared.fence).await {
        Ok(()) => StartRefused::Volume {
            volume: refused.volume,
            reason: refused.reason,
        },
        Err(fence) => StartRefused::Fenced(fence),
    }
}

/// [`start_observed`] with notices nobody watches: for a caller that
/// learns everything from the start's result and the handle.
///
/// # Cancellation safety
/// As [`start_observed`].
///
/// # Errors
/// As [`start_observed`].
pub async fn start<L, S, C, R, E, P>(
    parts: AuthorityParts<L, S, C, R, E, P>,
    boot: BootId,
    volumes: Vec<VolumeConfig>,
) -> Result<(AuthorityHandle, AuthorityDriver<L, S, C, R, E, P>), StartRefused>
where
    L: DecisionLog,
    S: RootStore,
    C: Clock + 'static,
    R: Rng + Send,
    E: SecureRandom + Send,
    P: Pause,
{
    start_observed(parts, boot, volumes, Notices::new()).await
}

/// Start the engine over `volumes` under the host's boot id `boot`: the
/// marker gate, recovery and replay (module docs). On success, the
/// handle serves requests once the driver's [`AuthorityDriver::run`] is
/// polled.
///
/// `notices` carry what the start does to the host's receivers while it
/// runs: the engine's fence, raised by the start or later, publishes
/// through them, and a post-admission refusal is sent through them before
/// its **clean** write begins ([`AdmittedRefusal`]).
///
/// # Cancellation safety
/// Not cancel-safe: drive it to completion. Dropping this future during
/// a mutating log call drops that call, which the seam treats as a
/// fence; there is no engine yet to carry it. What the marker then says
/// depends on the call dropped:
/// - a call of step 3 (module docs): **running** under this boot, made
///   durable in step 1, so a same-boot restart refuses (spec §6.2);
/// - step 1's **running** write: **running** under this boot if the
///   write got past its rename, otherwise the marker as it was, which
///   admits a same-boot restart;
/// - the **clean** write of a start refused in step 2: **running** under
///   this boot, or **clean** if the write got past its rename, which
///   admits a same-boot restart.
///
/// An admitted restart after the last two is one of spec §6.2's two
/// benign cases: an unpublished marker temporary, which the next marker
/// write removes, or a **clean** write cut short after its rename. No log
/// write had been made in either.
///
/// # Errors
/// [`StartRefused`], naming the refusal, or the fence a failed log call
/// raised.
#[expect(
    clippy::too_many_lines,
    reason = "startup ordering keeps readiness before publishing handles and worker observations"
)]
pub async fn start_observed<L, S, C, R, E, P>(
    parts: AuthorityParts<L, S, C, R, E, P>,
    boot: BootId,
    volumes: Vec<VolumeConfig>,
    notices: Notices,
) -> Result<(AuthorityHandle, AuthorityDriver<L, S, C, R, E, P>), StartRefused>
where
    L: DecisionLog,
    S: RootStore,
    C: Clock + 'static,
    R: Rng + Send,
    E: SecureRandom + Send,
    P: Pause,
{
    let Notices { fence, refusal } = notices;
    let AuthorityParts {
        log,
        store,
        admission,
        clock,
        rng,
        secure_random,
        pause,
    } = parts;
    let mut seen = BTreeSet::new();
    for config in &volumes {
        if !seen.insert(config.volume.clone()) {
            return Err(StartRefused::DuplicateVolume(config.volume.clone()));
        }
    }
    let clock = Arc::new(clock);
    let shared = Arc::new(Shared::notifying(
        fence,
        AdmissionRuntime {
            config: admission.fresh(),
            clock: clock.clone(),
        },
    ));
    let gate = LogGate::default();

    let read = log
        .read_marker()
        .await
        .map_err(StartRefused::MarkerUnreadable)?;
    marker_admits(read, boot)?;
    let running = encode_marker(&RunMarker::Running(boot));
    gate.settling(
        &shared.fence,
        LogCall::WriteMarker,
        None,
        || log.write_marker(&running),
        |written| match written {
            Ok(()) => Ok(Ok(())),
            // The one error any log call spares (spec §6.2): the
            // temporary's name was taken, so nothing was written and the
            // marker is as it was.
            Err(LogIoError::AlreadyExists) => Ok(Err(StartRefused::MarkerTemporaryTaken)),
            Err(e) => Err(FenceCause::Failed(e)),
        },
    )
    .await
    .map_err(StartRefused::Fenced)??;

    let mut found = Vec::with_capacity(volumes.len());
    for config in &volumes {
        match classify_volume(&log, config).await {
            Ok(volume) => found.push(volume),
            Err(reason) => {
                let refused = AdmittedRefusal {
                    volume: config.volume.clone(),
                    reason,
                };
                return Err(refuse_admitted(&log, &gate, &shared, &refusal, refused).await);
            }
        }
    }
    for Found {
        volume,
        log: adopted,
        intents,
        ..
    } in &found
    {
        intents
            .ready(
                adopted.as_ref().map(|a| a.state.envelope().epoch()),
                &gate,
                &shared,
                volume,
            )
            .await
            .map_err(StartRefused::Fenced)?;
        if let Some(adopted) = adopted {
            adopted
                .readiness
                .make_ready(&log, &gate, &shared.fence, volume)
                .await
                .map_err(StartRefused::Fenced)?;
        }
    }
    // Startup recovery has made its last write; no worker has run.
    crash_point!(Recovered);

    let mut inboxes = std::collections::BTreeMap::new();
    let mut workers = Vec::with_capacity(found.len());
    let mut views = std::collections::BTreeMap::new();
    for Found {
        volume,
        keys,
        intents,
        log: adopted,
    } in found
    {
        let (sender, inbox) = mpsc::channel(INBOX);
        inboxes.insert(volume.clone(), sender);
        let mut worker = Worker::new(volume.clone(), keys, adopted.map(|a| a.state), inbox);
        worker.intents = intents;
        views.insert(volume, Arc::clone(&worker.view));
        workers.push(worker);
    }
    let (end, ended) = watch::channel(None);
    let handle = AuthorityHandle {
        inner: Arc::new(HandleInner {
            shared: Arc::clone(&shared),
            inboxes,
            views,
            ended,
        }),
    };
    let driver = AuthorityDriver {
        log,
        store,
        clock,
        rng: Mutex::new(rng),
        secure_random: Mutex::new(secure_random),
        pause,
        gate,
        shared,
        workers,
        end,
    };
    Ok((handle, driver))
}
