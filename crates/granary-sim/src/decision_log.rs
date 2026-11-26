// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The simulator's crash-consistency `DecisionLog`
//! ([`granary_core::decisionlog::DecisionLog`]): a filesystem of inodes
//! and names over the sim's shared world (the `disk` submodule), driven one step at
//! a time, with the two ends of a run, the injected faults, and the
//! ordering checks that hold a caller to the log's durability rules.
//!
//!
//! # Every internal step is its own operation
//!
//! A seam call is a sequence of steps — write, file sync, directory
//! sync, create, mkdir, link, unlink, rename, truncate, read — and each
//! one goes through the same order as every store operation in
//! [`crate::fakes`]: claim the next index, suspend once on
//! [`yield_once`], consult the fault schedule, apply, record. So a
//! crash or a fault lands between any two steps of `append`,
//! `initialise`, recovery or a marker write, and the step indices are
//! what a sweep discovers with [`SimDecisionLog::steps`]. Each call also
//! records one [`LogOp::Call`] entry with its result.
//!
//! The steps each call issues, in order:
//!
//! | call | steps |
//! |---|---|
//! | `read_marker` | read the marker (and observe the state directory) |
//! | `write_marker` | mkdir if the state directory is absent; unlink the temporary by its exact name, create it exclusively, write, file sync, rename over the marker, state-directory sync, and, if no marker existed before this write, anchor sync |
//! | `read` | read the log |
//! | `remove_temporary` | unlink the temporary |
//! | `initialise` | mkdir if the state directory is absent; unlink the temporary, create it exclusively, write, file sync, link to the log's name, unlink the temporary, state-directory sync, anchor sync |
//! | `complete_namespace` | unlink the temporary, state-directory sync, anchor sync |
//! | `append` | write the record, file sync, write the mark, file sync |
//! | `truncate` | truncate, file sync |
//! | `resync` | file sync |
//!
//! An `initialise` refused at its link unlinks its own temporary before
//! answering `AlreadyExists`, so the log's name and bytes are unchanged
//! and no temporary is left behind. That `AlreadyExists` comes after
//! the call began, so it fences like any other such error (below).
//!
//! **One live handle per world** ([`Sim::decision_log`]): a handle's
//! process state describes the world's one filesystem, and a second
//! live handle is refused rather than left to disagree with it.
//!
//! # The two ends of a run
//!
//! [`SimDecisionLog::restart_process`] models a process restart in the
//! same boot: the page cache survives, so every written byte stays
//! readable — including bytes whose sync failed — and nothing is drawn.
//! [`SimDecisionLog::crash_host`] models power loss: the medium keeps a
//! seeded draw of what was pending (the `disk` submodule's docs), and that
//! draw becomes the new medium. Both start a new process — every
//! barrier's progress is per process — and both end the old one: a call
//! still suspended mid-sequence dies at its next step and applies
//! nothing more. What a failed sync covered stays unsynced through a
//! restart, and so does the fence: only a host crash clears either
//! (the `disk` submodule's docs).
//!
//! # The ordering checks
//!
//! The fake records a [`LogViolation`] (in the trace, and in
//! [`SimDecisionLog::violations`]) and carries on as the medium would:
//! the checks observe, they do not refuse. Each is decided from the
//! steps this process actually took and from the medium's state, never
//! from what a call reported, so a fake variant that skips a step and
//! returns `Ok` is still caught ([`Mutation`]).
//!
//! - **A mark written before its record's sync returned**
//!   ([`LogViolation::MarkBeforeRecordSync`]), checked at the mark's
//!   write step.
//! - **A log write while a barrier is incomplete**
//!   ([`LogViolation::WriteBeforeBarrier`]):
//!   - the marker ([`Barrier::Marker`]): before `initialise`, `append`
//!     or `truncate`, this process must have renamed a synced
//!     temporary over the marker and synced the state directory after
//!     it, and synced the anchor after its first rename that created
//!     the marker's name (no marker existed before it) and after any
//!     state directory it created, whether or not it created the
//!     directory the marker went into. Checked at every log write, not only at an append:
//!     spec §6.2 has the marker say running before the run's first log
//!     write;
//!   - at an `append`, a log this process linked must have had the
//!     state directory and the anchor synced after the link, and its
//!     name must be durable ([`Barrier::Initialise`]); an adopted log
//!     with no records needs its own `complete_namespace` to have seen
//!     those two syncs return in this process — another volume's do not
//!     count ([`Barrier::CompleteNamespace`]);
//!   - no truncation of the log may be unsynced
//!     ([`Barrier::Truncation`]);
//!   - an adopted log holding records must have had a file sync in
//!     this process, and no byte of the log may be unsynced
//!     ([`Barrier::SurvivorResync`]).
//! - **An append over a tail recovery never truncated**
//!   ([`LogViolation::TailNotTruncated`]): after a host crash (or a
//!   fixture) leaves bytes past a log's committed prefix, an append
//!   before a truncation to that prefix.
//! - **Any mutating call after a fence** ([`LogViolation::AfterFence`]
//!   in the fenced process, [`LogViolation::SameBootAfterFence`] in a
//!   later one of the same boot). A fence is a failed sync — the
//!   step's, so it is seen even when a call hides it — or any error a
//!   mutating call returns after it issued its own first step, or such
//!   a call dropped, or cut off by a restart (fenced at the restart
//!   itself). An error returned before any step (`NotFound`,
//!   `OutOfRange`) does not fence; `remove_temporary` never fences,
//!   and neither does a marker write whose temporary's exclusive
//!   create finds the name already taken (spec §6.2: nothing was
//!   written and the marker is unchanged). A failed marker write
//!   otherwise fences like any other failed sync (spec §6.2): only a
//!   host crash clears it.
//! - **A second mutating call on one log while one is in flight**
//!   ([`LogViolation::ConcurrentCall`]); the marker counts as one log.
//!   Claims belong to their process: a restart or a host crash releases
//!   them all, and a call releases only its own.
//! - **A mutating call begun while another is in flight on any other
//!   log** ([`LogViolation::OverlappingCall`]): the engine holds one
//!   log token across every `write_marker`, `initialise`,
//!   `complete_namespace`, `append`, `truncate` and `resync`, so no two
//!   of them overlap anywhere. `remove_temporary` takes no part: it
//!   writes nothing a sync covers, and the seam exempts it from fencing.
//!   Checked when the second call begins, against the calls this
//!   process still has registered.
//! - **A step of a call begun before a fence, applied after it**
//!   ([`LogViolation::StepAfterFence`]): the fence stops a call already
//!   in flight, not only one begun later (spec §6.2: nothing is written
//!   after the failing sync returns). Every step of a registered call
//!   counts, `remove_temporary`'s unlink included; a read is never
//!   registered and never counts. A call begun after the fence is
//!   [`LogViolation::AfterFence`] alone, once, at its start.
//! - **An append whose epoch is not its log's**
//!   ([`LogViolation::EpochMismatch`]), read from the log's envelope
//!   alone.
//!
//! # Faults
//!
//! [`LogFault::CrashAt`] and [`LogFault::FailSync`] are indexed by step
//! and wired as [`crate::fakes::Fault`] is: a schedule keyed by index,
//! consulted after the suspension. The two media faults are applied at
//! the next [`SimDecisionLog::crash_host`], after the draw: media damage
//! is what a reboot reveals.

pub(crate) mod disk;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use granary_core::authlog::{
    Append, Classified, ENVELOPE_V1_MAX, EncodedEnvelope, Epoch, GrammarRule, LogError,
    LogErrorReason, classify,
};
use granary_core::decisionlog::{DecisionLog, IoErrorKind, LogIoError, MarkerRead, StateDirectory};
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::runmarker::EncodedMarker;
use granary_core::testkit::DecisionLogFixture;

use crate::fakes::{Sim, World, lock};
use crate::rng::Rng;
use crate::sched::yield_once;
use crate::trace::{
    Address, Barrier, Damage, DrawRow, LogCall, LogOp, LogPath, LogViolation, Op, Outcome, Refusal,
    TraceError, Verdict, Volume,
};
use disk::{DamageTarget, NsError, WriteKind};

// --------------------------------------------------------------- faults

/// One injected failure of the decision log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFault {
    /// The process dies at this step: it applies nothing, and neither
    /// does anything the process attempts until the next
    /// [`SimDecisionLog::restart_process`] or
    /// [`SimDecisionLog::crash_host`].
    CrashAt(u32),
    /// The sync at this step returns [`LogIoError::SyncFailed`], and the
    /// bytes it covered stay unsynced. On a step that is not a sync it
    /// degenerates to a refused step, applying nothing.
    FailSync {
        /// The step index.
        at: u32,
    },
    /// At the next host crash, flip one byte inside `volume`'s
    /// committed record number `record` (from 0), leaving its mark
    /// valid — damage recovery must refuse.
    CorruptDetectable {
        /// The log's volume.
        volume: VolumeName,
        /// Which committed record.
        record: u32,
    },
    /// At the next host crash, flip every byte from the mark of the
    /// last `records` committed records of `volume`'s log — or, with
    /// `into_record`, from the middle of the first of those records —
    /// to the end of the file: damage confined to the end of the file
    /// that destroys the mark of every committed record it touches.
    /// Recovery discards those records while the tail they leave is
    /// within the tail bound: no longer than the legal next record
    /// that leads it plus a mark, or, when no whole record leads it,
    /// no longer than the largest record. A tail beyond the bound is
    /// refused.
    ///
    ResidualLoss {
        /// The log's volume.
        volume: VolumeName,
        /// How many committed records, counted from the last.
        records: u32,
        /// Whether the damage starts inside the first record rather
        /// than at its mark.
        into_record: bool,
    },
    /// At the next host crash, replace everything after `volume`'s
    /// first `keep` committed records with `tail`, and trace it as
    /// `damage` (one of the planted kinds: [`Damage::Oversize`],
    /// [`Damage::AtBound`], [`Damage::ForeignRecord`],
    /// [`Damage::WrongSeqRecord`] and [`Damage::OtherEpochRecord`]). Recovery's verdict follows
    /// from the tail's bytes alone.
    PlantTail {
        /// The log's volume.
        volume: VolumeName,
        /// How many committed records stay.
        keep: u32,
        /// The bytes that follow them.
        tail: Vec<u8>,
        /// What the trace records the fault as.
        damage: Damage,
    },
}

/// The kind of an indexed fault, whether scheduled or fired at a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiredFault {
    /// A process crash before applying the step.
    Crash,
    /// A sync failure (a refusal on a non-sync step).
    FailSync,
}

/// A media fault waiting for the next host crash.
#[derive(Debug, Clone)]
struct MediaFault {
    volume: VolumeName,
    damage: Damage,
    target: DamageTarget,
}

/// A decision log's fault schedule. As with [`crate::fakes::Faults`], a
/// later [`LogFaults::with`] at an index already spoken for replaces it.
#[derive(Debug, Clone, Default)]
pub struct LogFaults {
    at: BTreeMap<u32, FiredFault>,
    media: Vec<MediaFault>,
}

impl LogFaults {
    /// No faults — the schedule a conformance run uses.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Exactly one fault.
    #[must_use]
    pub fn just(fault: LogFault) -> Self {
        Self::none().with(fault)
    }

    /// This schedule plus `fault`.
    #[must_use]
    pub fn with(mut self, fault: LogFault) -> Self {
        let index = |n: u32| usize::try_from(n).unwrap_or(usize::MAX);
        match fault {
            LogFault::CrashAt(at) => {
                self.at.insert(at, FiredFault::Crash);
            }
            LogFault::FailSync { at } => {
                self.at.insert(at, FiredFault::FailSync);
            }
            LogFault::CorruptDetectable { volume, record } => self.media.push(MediaFault {
                volume,
                damage: Damage::Detectable,
                target: DamageTarget::Record(index(record)),
            }),
            LogFault::ResidualLoss {
                volume,
                records,
                into_record,
            } => self.media.push(MediaFault {
                volume,
                damage: if into_record {
                    Damage::ResidualIntoRecord
                } else {
                    Damage::Residual
                },
                target: DamageTarget::Tail {
                    records: index(records),
                    into_record,
                },
            }),
            LogFault::PlantTail {
                volume,
                keep,
                tail,
                damage,
            } => self.media.push(MediaFault {
                volume,
                damage,
                target: DamageTarget::Plant {
                    keep: index(keep),
                    tail,
                },
            }),
        }
        self
    }

    /// Whether this schedule injects anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.at.is_empty() && self.media.is_empty()
    }
}

/// A deliberately broken variant of the fake: each skips or reorders
/// one step, so a test can show the ordering check that step feeds
/// catches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// `append` writes the mark before syncing the record, and syncs
    /// once.
    MarkBeforeRecordSync,
    /// `write_marker` skips its state-directory sync.
    MarkerSkipsDirSync,
    /// `write_marker` skips the parent sync a marker write that found no
    /// marker owes.
    MarkerSkipsAnchorSync,
    /// `initialise` skips its state-directory and anchor syncs.
    InitialiseSkipsNamespaceSync,
    /// `complete_namespace` skips its state-directory and anchor syncs.
    CompleteNamespaceSkipsSync,
    /// `truncate` skips its sync.
    TruncateSkipsSync,
    /// `resync` issues no sync.
    ResyncSkipsSync,
    /// A failed sync is reported to the caller as success.
    SwallowSyncFailure,
    /// `initialise` on an existing name reports success, keeping the old
    /// log.
    InitialiseSucceedsOnExisting,
    /// `initialise` links the temporary to the log's name before syncing
    /// it, so a crash can leave a name bound to bytes that never reached
    /// the medium.
    InitialiseLinksBeforeSync,
}

// -------------------------------------------------------------- process

/// One process's view of the run: whether it died or fenced, and the
/// timeline of its successful steps the barrier checks read.
#[derive(Debug, Default)]
struct Process {
    crashed: bool,
    fenced: bool,
    /// The position of this process's latest successful step, from 1.
    clock: u64,
    mkdir_at: Option<u64>,
    /// When the marker's temporary was last renamed over the marker, and
    /// whether the temporary was synced at that moment.
    marker_renamed: Option<(u64, bool)>,
    /// When this process first renamed a temporary to a marker name
    /// that did not exist: from then on the anchor sync is owed, and a
    /// later rename over the marker does not discharge it.
    marker_created_at: Option<u64>,
    dir_synced: BTreeMap<LogPath, u64>,
    file_synced: BTreeMap<LogPath, u64>,
    linked: BTreeMap<LogPath, u64>,
    /// Logs whose own `complete_namespace` saw both its syncs return.
    completed: BTreeSet<LogPath>,
}

impl Process {
    fn dir_synced_after(&self, dir: &LogPath, after: u64) -> bool {
        self.dir_synced.get(dir).is_some_and(|&at| at > after)
    }

    fn marker_barrier_complete(&self) -> bool {
        let Some((renamed, temp_synced)) = self.marker_renamed else {
            return false;
        };
        // Spec §6.2: a marker write that found no marker syncs the state
        // directory's parent after its rename, whether or not it created
        // the state directory.
        temp_synced
            && self.dir_synced_after(&LogPath::StateDir, renamed)
            && self
                .marker_created_at
                .is_none_or(|at| self.dir_synced_after(&LogPath::Anchor, at))
            && self
                .mkdir_at
                .is_none_or(|at| self.dir_synced_after(&LogPath::Anchor, at))
    }

    fn namespace_synced_after(&self, after: u64) -> bool {
        self.dir_synced_after(&LogPath::StateDir, after)
            && self.dir_synced_after(&LogPath::Anchor, after)
    }
}

// ----------------------------------------------------------------- steps

/// One internal step.
#[derive(Debug, Clone, Copy)]
enum Step<'a> {
    Read(&'a LogPath),
    Write(&'a LogPath, &'a [u8], WriteKind),
    FileSync(&'a LogPath),
    DirSync(&'a LogPath),
    Create(&'a LogPath, bool),
    Mkdir,
    Link(&'a LogPath, &'a LogPath),
    Unlink(&'a LogPath),
    Rename(&'a LogPath, &'a LogPath),
    Truncate(&'a LogPath, usize),
}

impl Step<'_> {
    fn is_sync(&self) -> bool {
        matches!(self, Self::FileSync(_) | Self::DirSync(_))
    }

    fn op(&self) -> LogOp {
        let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        match *self {
            Self::Read(path) => LogOp::Read { path: path.clone() },
            Self::Write(path, bytes, _) => LogOp::Write {
                path: path.clone(),
                len: len(bytes.len()),
                addr: Address::new(*GrainId::of(bytes).digest()),
            },
            Self::FileSync(path) => LogOp::FileSync { path: path.clone() },
            Self::DirSync(path) => LogOp::DirSync { path: path.clone() },
            Self::Create(path, exclusive) => LogOp::Create {
                path: path.clone(),
                exclusive,
            },
            Self::Mkdir => LogOp::Mkdir {
                path: LogPath::StateDir,
            },
            Self::Link(from, to) => LogOp::Link {
                from: from.clone(),
                to: to.clone(),
            },
            Self::Unlink(path) => LogOp::Unlink { path: path.clone() },
            Self::Rename(from, to) => LogOp::Rename {
                from: from.clone(),
                to: to.clone(),
            },
            Self::Truncate(path, n) => LogOp::Truncate {
                path: path.clone(),
                len: len(n),
            },
        }
    }
}

/// What a step answered, beyond success.
#[derive(Debug, Default)]
struct Done {
    /// Whether the name the step addressed was there.
    present: bool,
    /// A read's bytes.
    bytes: Option<Vec<u8>>,
    /// A read's observation of the state directory.
    state_dir: Option<StateDirectory>,
}

impl Done {
    /// A step that acted on a name that was there.
    fn found() -> Self {
        Self {
            present: true,
            ..Self::default()
        }
    }
}

fn ns_error(e: NsError) -> LogIoError {
    match e {
        NsError::NotFound => LogIoError::NotFound,
        NsError::AlreadyExists => LogIoError::AlreadyExists,
    }
}

/// The error a dead process's calls answer.
fn dead() -> LogIoError {
    LogIoError::Io(IoErrorKind::Other)
}

/// Map a seam error into the artifact's fixed vocabulary.
fn traced(err: LogIoError) -> TraceError {
    match err {
        LogIoError::NotFound => TraceError::NotFound,
        LogIoError::AlreadyExists => TraceError::AlreadyExists,
        LogIoError::SyncFailed => TraceError::SyncFailed,
        LogIoError::OutOfRange => TraceError::OutOfRange,
        LogIoError::Io(_) => TraceError::Backend,
    }
}

/// A refusal's reason in the artifact's fixed vocabulary.
fn refusal(reason: LogErrorReason) -> Refusal {
    match reason {
        LogErrorReason::UnknownVersion { .. } => Refusal::UnknownVersion,
        LogErrorReason::EnvelopeMalformed => Refusal::EnvelopeMalformed,
        LogErrorReason::WrongVolume => Refusal::WrongVolume,
        LogErrorReason::DamagedCommittedHistory => Refusal::DamagedHistory,
        LogErrorReason::Grammar(rule) => Refusal::Grammar(match rule {
            GrammarRule::Rule1SequencePosition => 1,
            GrammarRule::Rule2ConcurrentEntry => 2,
            GrammarRule::Rule3AttestationPreconditions => 3,
            GrammarRule::Rule4OutcomePreconditions => 4,
            GrammarRule::Rule5IdentityMismatch => 5,
            GrammarRule::Rule6LandedOperationReplay => 6,
            GrammarRule::Rule7DuplicateAnswer => 7,
        }),
    }
}

fn log_path(volume: &VolumeName) -> LogPath {
    LogPath::Log(Volume::from_checked(volume))
}

fn temp_path(volume: &VolumeName) -> LogPath {
    LogPath::Temp(Volume::from_checked(volume))
}

/// The epoch of the log in `bytes`, and whether anything follows its
/// envelope — read from the envelope alone, never by classifying the
/// whole log. `None` when `bytes` do not open with a whole envelope
/// naming `volume`.
///
/// [`classify`] runs over at most [`ENVELOPE_V1_MAX`] bytes: every v1
/// envelope fits, and what follows it inside that window is shorter
/// than a mark, so the prefix classifies as the envelope and a tail.
fn envelope_of(bytes: &[u8], volume: &VolumeName) -> Option<(Epoch, bool)> {
    let prefix = bytes.get(..ENVELOPE_V1_MAX).unwrap_or(bytes);
    match classify(prefix, volume) {
        Ok(Classified::Log {
            envelope,
            committed_len,
            ..
        }) => Some((envelope.epoch(), bytes.len() > committed_len)),
        _ => None,
    }
}

// ----------------------------------------------------------------- handle

/// Which call a step belongs to: the process it began in, its id in
/// [`SimDecisionLog`]'s call registry (0 for a read, which is not
/// registered), and the seam method it is.
#[derive(Debug, Clone, Copy)]
struct Cx {
    generation: u64,
    id: u64,
    call: LogCall,
}

/// One step a handle issued, as [`SimDecisionLog::step_records`] lists
/// it: recorded when the step claims its index, so a step a dropped call
/// never traced is listed too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    /// The step's index: what [`LogFault::CrashAt`] and
    /// [`LogFault::FailSync`] name.
    pub index: u32,
    /// The seam method the step is part of.
    pub call: LogCall,
    /// Which of that call's steps it is, from 0.
    pub within: u32,
    /// What the step does.
    pub op: LogOp,
    /// The indexed fault that fired at it, if any.
    pub fired: Option<FiredFault>,
}

/// One mutating call in flight, as the registry tracks it.
#[derive(Debug)]
struct CallState {
    path: LogPath,
    /// Whether this call holds `path`'s in-flight claim.
    claimed: bool,
    /// Whether an error after the call began fences: every mutating
    /// call but `remove_temporary`, which the seam exempts, and a
    /// `write_marker` whose exclusive create found its name taken (a
    /// refused start, spec §6.2), which clears it.
    fences: bool,
    /// Whether the engine's log token covers the call.
    cover: Cover,
    /// Whether this process was already fenced when the call began: its
    /// steps are then [`LogViolation::AfterFence`]'s, not
    /// [`LogViolation::StepAfterFence`]'s.
    began_fenced: bool,
    /// Steps this call has issued: it has begun once this is non-zero.
    steps: u32,
}

/// Whether the engine's one log token covers a mutating call (module
/// docs): every one but `remove_temporary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cover {
    /// `write_marker`, `initialise`, `complete_namespace`, `append`,
    /// `truncate` and `resync`.
    Token,
    /// `remove_temporary`.
    Outside,
}

/// A registered call's handle: it settles the call when it returns,
/// and fences if it is dropped after it began. A call a restart or a
/// host crash retired is no longer registered, and its guard does
/// nothing — the retirement already settled it.
struct CallGuard<'a> {
    log: &'a SimDecisionLog,
    cx: Cx,
    finished: bool,
}

impl CallGuard<'_> {
    /// The call returned: an error after it began fences.
    fn finish<T>(mut self, result: &Result<T, LogIoError>) {
        self.finished = true;
        self.log.settle(self.cx.id, result.is_err());
    }
}

impl Drop for CallGuard<'_> {
    /// A call dropped after it began fences, as the seam's cancellation
    /// rule says.
    fn drop(&mut self) {
        if !self.finished {
            self.log.settle(self.cx.id, true);
        }
    }
}

/// What a host crash did, for a test or a sweep to count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrashReport {
    /// Each unacknowledged append's outcome: its log, its record's
    /// offset, its row.
    pub rows: Vec<(LogPath, u64, DrawRow)>,
    /// Each media fault that fired: its log, its kind, and the byte
    /// range flipped.
    pub damaged: Vec<(LogPath, Damage, u64, u64)>,
    /// Media faults that could not fire: the log held too few committed
    /// records.
    pub unfired: usize,
}

/// One process's handle on the simulated filesystem: a
/// [`DecisionLog`] under a fault schedule (module docs).
#[derive(Debug)]
pub struct SimDecisionLog {
    world: Arc<World>,
    node: u32,
    indexed: BTreeMap<u32, FiredFault>,
    media: Mutex<Vec<MediaFault>>,
    mutation: Option<Mutation>,
    steps: AtomicU32,
    /// Which process is running: bumped by every restart and host
    /// crash, so a call begun under an earlier one dies at its next
    /// step instead of acting on a world that has moved on.
    generation: AtomicU64,
    process: Mutex<Process>,
    violations: Mutex<Vec<LogViolation>>,
    /// The mutating calls of the current process, by id.
    calls: Mutex<BTreeMap<u64, CallState>>,
    next_call: AtomicU64,
    /// The logs (and the marker) a mutating call is in flight on, and
    /// which call holds each claim.
    in_flight: Mutex<BTreeMap<LogPath, u64>>,
    /// Every step issued, by index ([`Self::step_records`]).
    step_records: Mutex<Vec<StepRecord>>,
    /// How many steps each mutating call has issued, by call id.
    call_steps: Mutex<BTreeMap<u64, u32>>,
}

impl Drop for SimDecisionLog {
    fn drop(&mut self) {
        self.world.decision_log_live.store(false, Ordering::SeqCst);
    }
}

impl Sim {
    /// A decision log over this world's filesystem, recorded under
    /// `node` with `faults` as its schedule.
    ///
    /// **One live handle per world.** The world holds one filesystem,
    /// and a handle's process state (its fence, its barriers' progress,
    /// its generation) describes that filesystem alone; two live
    /// handles would each believe they were the only process on it. A
    /// handle dropped frees the filesystem for the next, which then
    /// starts as a new process on the same disk.
    ///
    /// # Panics
    /// If another handle on this world is still live.
    #[must_use]
    pub fn decision_log(&self, node: u32, faults: LogFaults) -> SimDecisionLog {
        self.decision_log_handle(node, faults, None)
    }

    /// A deliberately broken decision log ([`Mutation`]), for the
    /// ordering checks' mutation tests.
    ///
    /// # Panics
    /// As [`Sim::decision_log`].
    #[must_use]
    pub fn decision_log_variant(
        &self,
        node: u32,
        faults: LogFaults,
        mutation: Mutation,
    ) -> SimDecisionLog {
        self.decision_log_handle(node, faults, Some(mutation))
    }

    fn decision_log_handle(
        &self,
        node: u32,
        faults: LogFaults,
        mutation: Option<Mutation>,
    ) -> SimDecisionLog {
        assert!(
            !self.world.decision_log_live.swap(true, Ordering::SeqCst),
            "one live decision-log handle per sim world: drop the first before taking another"
        );
        SimDecisionLog {
            world: Arc::clone(&self.world),
            node,
            indexed: faults.at,
            media: Mutex::new(faults.media),
            mutation,
            steps: AtomicU32::new(0),
            generation: AtomicU64::new(0),
            process: Mutex::new(Process::default()),
            violations: Mutex::new(Vec::new()),
            calls: Mutex::new(BTreeMap::new()),
            next_call: AtomicU64::new(1),
            in_flight: Mutex::new(BTreeMap::new()),
            step_records: Mutex::new(Vec::new()),
            call_steps: Mutex::new(BTreeMap::new()),
        }
    }
}

impl SimDecisionLog {
    /// How many steps this handle has issued — the range a sweep
    /// discovers by running once with [`LogFaults::none`].
    #[must_use]
    pub fn steps(&self) -> u32 {
        self.steps.load(Ordering::Relaxed)
    }

    /// Every step this handle has issued, in index order: its call, its
    /// place in that call, its op, and which indexed fault fired at
    /// it. A step is recorded when it claims its index, before it
    /// suspends, so the list is exact where the trace, which records a
    /// step after its suspension, can differ in order between steps of
    /// two calls in flight together, and omits a step whose call was
    /// dropped mid-suspension.
    #[must_use]
    pub fn step_records(&self) -> Vec<StepRecord> {
        lock(&self.step_records).clone()
    }

    /// Every ordering violation observed so far, in order.
    #[must_use]
    pub fn violations(&self) -> Vec<LogViolation> {
        lock(&self.violations).clone()
    }

    /// Whether the schedule has crashed this process.
    #[must_use]
    pub fn crashed(&self) -> bool {
        lock(&self.process).crashed
    }

    /// Register a mutating call and claim `path` for it, recording a
    /// [`LogViolation::ConcurrentCall`] if another call of this process
    /// holds the claim, and, for a call the token covers, a
    /// [`LogViolation::OverlappingCall`] if another such call of this
    /// process is in flight on any other path.
    fn begin_call(
        &self,
        path: LogPath,
        fences: bool,
        cover: Cover,
        call: LogCall,
    ) -> CallGuard<'_> {
        let id = self.next_call.fetch_add(1, Ordering::SeqCst);
        let claimed = {
            let mut in_flight = lock(&self.in_flight);
            if in_flight.contains_key(&path) {
                false
            } else {
                in_flight.insert(path.clone(), id);
                true
            }
        };
        if !claimed {
            self.violate(LogViolation::ConcurrentCall);
        }
        let overlaps = cover == Cover::Token
            && lock(&self.calls)
                .values()
                .any(|call| call.cover == Cover::Token && call.path != path);
        if overlaps {
            self.violate(LogViolation::OverlappingCall);
        }
        let began_fenced = lock(&self.process).fenced;
        lock(&self.calls).insert(
            id,
            CallState {
                path,
                claimed,
                fences,
                cover,
                began_fenced,
                steps: 0,
            },
        );
        CallGuard {
            log: self,
            cx: Cx {
                generation: self.generation(),
                id,
                call,
            },
            finished: false,
        }
    }

    /// A read's context: it is not registered and never fences.
    fn read_cx(&self, call: LogCall) -> Cx {
        Cx {
            generation: self.generation(),
            id: 0,
            call,
        }
    }

    /// Mark call `id` as never fencing, for a refusal this process has
    /// decided is not a partial write (module docs: the marker
    /// temporary's exclusive create finding its name taken).
    fn unfence_call(&self, id: u64) {
        if let Some(call) = lock(&self.calls).get_mut(&id) {
            call.fences = false;
        }
    }

    /// Settle call `id`: release its own claim, and fence if it `failed`
    /// after it began. A call no longer registered was retired by a
    /// restart or a host crash, which settled it then.
    fn settle(&self, id: u64, failed: bool) {
        let Some(call) = lock(&self.calls).remove(&id) else {
            return;
        };
        if call.claimed {
            let mut in_flight = lock(&self.in_flight);
            if in_flight.get(&call.path) == Some(&id) {
                in_flight.remove(&call.path);
            }
        }
        if call.fences && failed && call.steps > 0 {
            lock(&self.process).fenced = true;
            self.fence_disk();
        }
    }

    /// Fence the disk until the next host crash.
    fn fence_disk(&self) {
        lock(&self.world.disk).fence();
    }

    /// End the current process's calls: each that had begun is cut off,
    /// and fences the disk at once (the process it would fence is the
    /// one ending); every claim is released. A retired call's guard, and
    /// its next step, then do nothing but fail.
    fn retire_calls(&self) {
        let calls = std::mem::take(&mut *lock(&self.calls));
        lock(&self.in_flight).clear();
        for call in calls.into_values() {
            if call.fences && call.steps > 0 {
                self.fence_disk();
            }
        }
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn mutant(&self, mutation: Mutation) -> bool {
        self.mutation == Some(mutation)
    }

    fn record(&self, op: LogOp, outcome: Outcome) {
        lock(&self.world.trace).record(self.node, Op::Log(op), outcome);
    }

    fn violate(&self, violation: LogViolation) {
        lock(&self.violations).push(violation);
        self.record(LogOp::Violation(violation), Outcome::Ok);
    }

    fn record_call<T>(
        &self,
        call: LogCall,
        volume: Option<&VolumeName>,
        result: &Result<T, LogIoError>,
        found: impl FnOnce(&T) -> bool,
    ) {
        let outcome = match result {
            Ok(v) if found(v) => Outcome::Ok,
            Ok(_) => Outcome::Absent,
            Err(e) => Outcome::Failed(traced(*e)),
        };
        self.record(
            LogOp::Call {
                call,
                volume: volume.map(Volume::from_checked),
            },
            outcome,
        );
    }

    /// Recovery's classification of what [`DecisionLog::read`] returned
    /// for `volume`, recorded in the trace as its verdict. `read` is
    /// `None` for a volume with no log. A recording step, not a seam
    /// call: it takes no step index and consults no fault.
    pub fn classify_traced(
        &self,
        volume: &VolumeName,
        read: Option<&[u8]>,
    ) -> Option<Result<Classified, LogError>> {
        let as_u64 = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let classified = read.map(|bytes| classify(bytes, volume));
        let verdict = match &classified {
            None => Verdict::Absent,
            Some(Ok(Classified::NoEnvelope)) => Verdict::NoEnvelope,
            Some(Ok(Classified::Log {
                records,
                committed_len,
                tail_len,
                ..
            })) => Verdict::Log {
                records: as_u64(records.len()),
                committed: as_u64(*committed_len),
                tail: as_u64(*tail_len),
            },
            Some(Err(e)) => Verdict::Refused {
                reason: refusal(e.reason),
                offset: as_u64(e.offset),
            },
        };
        self.record(
            LogOp::Verdict {
                path: log_path(volume),
                verdict,
            },
            Outcome::Ok,
        );
        classified
    }

    /// A process restart in the same boot (module docs): nothing is
    /// lost, nothing is drawn, and a new process begins.
    pub fn restart_process(&self) {
        self.retire_calls();
        self.generation.fetch_add(1, Ordering::SeqCst);
        *lock(&self.process) = Process::default();
        self.record(LogOp::Restart, Outcome::Ok);
    }

    /// A host crash (module docs): draw what the medium keeps, make it
    /// the new medium, apply any pending media fault, and begin a new
    /// process. Every draw's boundaries, the namespace kept, and a
    /// digest of every resulting file go into the trace.
    pub fn crash_host(&self, rng: &mut Rng) -> CrashReport {
        self.retire_calls();
        self.generation.fetch_add(1, Ordering::SeqCst);
        let as_u64 = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let media = std::mem::take(&mut *lock(&self.media));
        let mut report = CrashReport::default();
        let mut entries = Vec::new();
        {
            let mut disk = lock(&self.world.disk);
            let draw = disk.crash(rng);
            entries.push((
                LogOp::Crash {
                    pending: as_u64(draw.pending),
                    kept: as_u64(draw.kept),
                },
                Outcome::Ok,
            ));
            for (path, file) in draw.files {
                entries.push((
                    LogOp::Draw {
                        path,
                        truncation: file.truncation,
                        base: as_u64(file.base),
                        written: as_u64(file.written),
                        kept: as_u64(file.kept),
                        garbage: as_u64(file.garbage),
                        fill: file.fill,
                    },
                    Outcome::Ok,
                ));
            }
            for (path, at, row) in draw.rows {
                entries.push((
                    LogOp::Row {
                        path: path.clone(),
                        at: as_u64(at),
                        row,
                    },
                    Outcome::Ok,
                ));
                report.rows.push((path, as_u64(at), row));
            }
            for fault in media {
                let path = log_path(&fault.volume);
                if let Some((start, end)) = disk.damage(&fault.volume, &fault.target) {
                    let (start, end) = (as_u64(start), as_u64(end));
                    entries.push((
                        LogOp::Damage {
                            path: path.clone(),
                            damage: fault.damage,
                            start,
                            end,
                        },
                        Outcome::Ok,
                    ));
                    report.damaged.push((path, fault.damage, start, end));
                } else {
                    entries.push((
                        LogOp::Damage {
                            path,
                            damage: fault.damage,
                            start: 0,
                            end: 0,
                        },
                        Outcome::Absent,
                    ));
                    report.unfired = report.unfired.saturating_add(1);
                }
            }
            disk.note_tails();
            entries.push((
                LogOp::StateDir {
                    present: disk.state_dir(),
                },
                Outcome::Ok,
            ));
            for (path, bytes) in disk.listing() {
                entries.push((
                    LogOp::File {
                        path,
                        len: as_u64(bytes.len()),
                        addr: Address::new(*GrainId::of(&bytes).digest()),
                    },
                    Outcome::Ok,
                ));
            }
        }
        *lock(&self.process) = Process::default();
        for (op, outcome) in entries {
            self.record(op, outcome);
        }
        report
    }

    /// Run one step through the op order: index, suspend, consult the
    /// schedule, apply, record. `cx.generation` is the process the call
    /// began in: if a restart or a host crash has happened since, the
    /// step applies nothing and the call dies.
    async fn step(&self, cx: Cx, step: Step<'_>) -> Result<Done, LogIoError> {
        let idx = self.steps.fetch_add(1, Ordering::Relaxed);
        if let Some(call) = lock(&self.calls).get_mut(&cx.id) {
            call.steps = call.steps.saturating_add(1);
        }
        let within = if cx.id == 0 {
            0
        } else {
            let mut counts = lock(&self.call_steps);
            let n = counts.entry(cx.id).or_insert(0);
            let within = *n;
            *n = n.saturating_add(1);
            within
        };
        {
            let mut records = lock(&self.step_records);
            let at = usize::try_from(idx).unwrap_or(usize::MAX);
            if records.len() <= at {
                records.resize_with(at.saturating_add(1), || StepRecord {
                    index: 0,
                    call: cx.call,
                    within: 0,
                    op: LogOp::Restart,
                    fired: None,
                });
            }
            if let Some(slot) = records.get_mut(at) {
                *slot = StepRecord {
                    index: idx,
                    call: cx.call,
                    within,
                    op: step.op(),
                    fired: None,
                };
            }
        }
        yield_once().await;
        let op = step.op();
        if self.generation() != cx.generation {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(dead());
        }
        let injection = {
            let mut process = lock(&self.process);
            if process.crashed {
                Some(FiredFault::Crash)
            } else {
                let injection = self.indexed.get(&idx).copied();
                if injection.is_some()
                    && let Some(record) =
                        lock(&self.step_records).get_mut(usize::try_from(idx).unwrap_or(usize::MAX))
                {
                    record.fired = injection;
                }
                match injection {
                    Some(FiredFault::Crash) => process.crashed = true,
                    Some(FiredFault::FailSync) if step.is_sync() => process.fenced = true,
                    Some(FiredFault::FailSync) | None => {}
                }
                injection
            }
        };
        match injection {
            Some(FiredFault::FailSync) if step.is_sync() => {
                if let Step::FileSync(path) | Step::DirSync(path) = step {
                    lock(&self.world.disk).poison(path);
                }
                self.fence_disk();
                self.record(op, Outcome::Failed(TraceError::SyncFailed));
                return Err(LogIoError::SyncFailed);
            }
            Some(_) => {
                self.record(op, Outcome::Failed(TraceError::Injected));
                return Err(dead());
            }
            None => {}
        }
        if self.step_after_fence(cx) {
            self.violate(LogViolation::StepAfterFence);
        }
        let (result, violation) = self.apply(step);
        if let Some(violation) = violation {
            self.violate(violation);
        }
        let outcome = match &result {
            Ok(done) if done.present => Outcome::Ok,
            Ok(_) => Outcome::Absent,
            Err(e) => Outcome::Failed(traced(*e)),
        };
        self.record(op, outcome);
        result
    }

    /// Whether a step of call `cx` about to apply comes after this
    /// process was fenced, the call having begun before the fence (module
    /// docs). A read (`cx.id` 0) is never registered and never counts.
    fn step_after_fence(&self, cx: Cx) -> bool {
        let began_fenced = lock(&self.calls).get(&cx.id).map(|call| call.began_fenced);
        began_fenced == Some(false) && lock(&self.process).fenced
    }

    /// Apply one step to the filesystem and, on success, to this
    /// process's timeline.
    fn apply(&self, step: Step<'_>) -> (Result<Done, LogIoError>, Option<LogViolation>) {
        let mut disk = lock(&self.world.disk);
        let mut process = lock(&self.process);
        let mut violation = None;
        let result = match step {
            Step::Read(path) => {
                let bytes = disk.file(path).map(|inode| inode.bytes().to_vec());
                let state_dir = if !disk.state_dir() {
                    StateDirectory::Absent
                } else if disk.occupied() {
                    StateDirectory::Occupied
                } else {
                    StateDirectory::Empty
                };
                Ok(Done {
                    present: bytes.is_some(),
                    bytes,
                    state_dir: Some(state_dir),
                })
            }
            Step::Write(path, bytes, kind) => disk.write(path, bytes, kind).map(|record_synced| {
                if record_synced == Some(false) {
                    violation = Some(LogViolation::MarkBeforeRecordSync);
                }
                Done::found()
            }),
            Step::FileSync(path) => disk.file_sync(path).map(|()| Done::found()),
            Step::DirSync(path) => {
                disk.dir_sync(path);
                Ok(Done::found())
            }
            Step::Create(path, exclusive) => disk.create(path, exclusive).map(|()| Done::found()),
            Step::Mkdir => disk.mkdir().map(|()| Done::found()),
            Step::Link(from, to) => disk.link(from, to).map(|()| Done::found()),
            Step::Unlink(path) => Ok(Done {
                present: disk.unlink(path),
                ..Done::default()
            }),
            Step::Rename(from, to) => {
                let synced = disk.file(from).is_some_and(disk::Inode::synced);
                let created = disk.file(to).is_none();
                disk.rename(from, to).map(|()| {
                    if *to == LogPath::Marker {
                        let at = process.clock + 1;
                        process.marker_renamed = Some((at, synced));
                        if created && process.marker_created_at.is_none() {
                            process.marker_created_at = Some(at);
                        }
                    }
                    Done::found()
                })
            }
            Step::Truncate(path, len) => disk.truncate(path, len).map(|()| Done::found()),
        };
        if result.is_ok() {
            process.clock += 1;
            let at = process.clock;
            match step {
                Step::FileSync(path) => {
                    process.file_synced.insert(path.clone(), at);
                }
                Step::DirSync(path) => {
                    process.dir_synced.insert(path.clone(), at);
                }
                Step::Mkdir => process.mkdir_at = Some(at),
                Step::Link(_, to) => {
                    process.linked.insert(to.clone(), at);
                }
                _ => {}
            }
        }
        (result.map_err(ns_error), violation)
    }

    /// A sync step's result as the call sees it: the
    /// [`Mutation::SwallowSyncFailure`] variant reports a failed sync
    /// as success.
    async fn sync(&self, cx: Cx, step: Step<'_>) -> Result<(), LogIoError> {
        match self.step(cx, step).await {
            Err(LogIoError::SyncFailed) if self.mutant(Mutation::SwallowSyncFailure) => Ok(()),
            other => other.map(|_| ()),
        }
    }

    /// Start a mutating call: refuse if the process is dead, and record
    /// a fence violation if a sync has failed — in this process, or in
    /// an earlier one of the same boot.
    fn begin_mutating(&self) -> Result<(), LogIoError> {
        let (crashed, fenced) = {
            let process = lock(&self.process);
            (process.crashed, process.fenced)
        };
        if crashed {
            return Err(dead());
        }
        if fenced {
            self.violate(LogViolation::AfterFence);
        } else if lock(&self.world.disk).fenced() {
            self.violate(LogViolation::SameBootAfterFence);
        }
        Ok(())
    }

    /// Start a log write: [`Self::begin_mutating`], then the marker
    /// barrier.
    fn begin_log_write(&self) -> Result<(), LogIoError> {
        self.begin_mutating()?;
        if !lock(&self.process).marker_barrier_complete() {
            self.violate(LogViolation::WriteBeforeBarrier(Barrier::Marker));
        }
        Ok(())
    }

    fn crashed_guard(&self) -> Result<(), LogIoError> {
        if lock(&self.process).crashed {
            Err(dead())
        } else {
            Ok(())
        }
    }

    /// The per-log checks an append makes before its first step (module
    /// docs). Silent when the log does not exist: the append answers
    /// `NotFound` and writes nothing.
    fn check_append(&self, append: &Append) {
        let path = log_path(append.volume());
        let (name_durable, truncation_pending, bytes_pending, tail, envelope) = {
            let disk = lock(&self.world.disk);
            let Some(inode) = disk.file(&path) else {
                return;
            };
            (
                disk.name_durable(&path),
                inode.truncation_pending(),
                inode.bytes_pending(),
                inode.tail_from().is_some(),
                envelope_of(inode.bytes(), append.volume()),
            )
        };
        if tail {
            self.violate(LogViolation::TailNotTruncated);
        }
        let has_records = envelope.map(|(_, has_records)| has_records);
        let mut found = Vec::new();
        {
            let process = lock(&self.process);
            if let Some(linked) = process.linked.get(&path).copied() {
                if !name_durable || !process.namespace_synced_after(linked) {
                    found.push(Barrier::Initialise);
                }
            } else {
                let empty = has_records == Some(false);
                if !name_durable || (empty && !process.completed.contains(&path)) {
                    found.push(Barrier::CompleteNamespace);
                }
                if has_records == Some(true) && !process.file_synced.contains_key(&path) {
                    found.push(Barrier::SurvivorResync);
                }
            }
            if truncation_pending {
                found.push(Barrier::Truncation);
            }
            if bytes_pending && !found.contains(&Barrier::SurvivorResync) {
                found.push(Barrier::SurvivorResync);
            }
        }
        for barrier in found {
            self.violate(LogViolation::WriteBeforeBarrier(barrier));
        }
        if envelope.map(|(epoch, _)| epoch) != Some(append.epoch()) {
            self.violate(LogViolation::EpochMismatch);
        }
    }

    fn log_exists(&self, path: &LogPath) -> bool {
        lock(&self.world.disk).file(path).is_some()
    }

    async fn write_marker_steps(&self, g: Cx, bytes: &[u8]) -> Result<(), LogIoError> {
        self.begin_mutating()?;
        let state_dir = lock(&self.world.disk).state_dir();
        if !state_dir {
            self.step(g, Step::Mkdir).await?;
        }
        let marker_existed = self.log_exists(&LogPath::Marker);
        self.step(g, Step::Unlink(&LogPath::MarkerTemp)).await?;
        if let Err(e) = self.step(g, Step::Create(&LogPath::MarkerTemp, true)).await {
            // The exclusive create found the name taken: nothing was
            // written and the marker is unchanged, so this is a refused
            // start, not a fence (spec §6.2) — unlike every other error
            // once the call has begun.
            if e == LogIoError::AlreadyExists {
                self.unfence_call(g.id);
            }
            return Err(e);
        }
        self.step(
            g,
            Step::Write(&LogPath::MarkerTemp, bytes, WriteKind::Plain),
        )
        .await?;
        self.sync(g, Step::FileSync(&LogPath::MarkerTemp)).await?;
        self.step(g, Step::Rename(&LogPath::MarkerTemp, &LogPath::Marker))
            .await?;
        if !self.mutant(Mutation::MarkerSkipsDirSync) {
            self.sync(g, Step::DirSync(&LogPath::StateDir)).await?;
        }
        if !marker_existed && !self.mutant(Mutation::MarkerSkipsAnchorSync) {
            self.sync(g, Step::DirSync(&LogPath::Anchor)).await?;
        }
        Ok(())
    }

    async fn initialise_steps(&self, g: Cx, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        self.begin_log_write()?;
        let volume = envelope.volume();
        let (log, temp) = (log_path(volume), temp_path(volume));
        let state_dir = lock(&self.world.disk).state_dir();
        if !state_dir {
            self.step(g, Step::Mkdir).await?;
        }
        self.step(g, Step::Unlink(&temp)).await?;
        self.step(g, Step::Create(&temp, true)).await?;
        self.step(g, Step::Write(&temp, envelope.as_bytes(), WriteKind::Plain))
            .await?;
        if !self.mutant(Mutation::InitialiseLinksBeforeSync) {
            self.sync(g, Step::FileSync(&temp)).await?;
        }
        match self.step(g, Step::Link(&temp, &log)).await {
            Ok(_) => {}
            Err(LogIoError::AlreadyExists) => {
                self.step(g, Step::Unlink(&temp)).await?;
                if self.mutant(Mutation::InitialiseSucceedsOnExisting) {
                    return Ok(());
                }
                return Err(LogIoError::AlreadyExists);
            }
            Err(e) => return Err(e),
        }
        if self.mutant(Mutation::InitialiseLinksBeforeSync) {
            self.sync(g, Step::FileSync(&temp)).await?;
        }
        self.step(g, Step::Unlink(&temp)).await?;
        if !self.mutant(Mutation::InitialiseSkipsNamespaceSync) {
            self.sync(g, Step::DirSync(&LogPath::StateDir)).await?;
            self.sync(g, Step::DirSync(&LogPath::Anchor)).await?;
        }
        Ok(())
    }

    async fn complete_namespace_steps(&self, g: Cx, volume: &VolumeName) -> Result<(), LogIoError> {
        self.begin_mutating()?;
        if !self.log_exists(&log_path(volume)) {
            return Err(LogIoError::NotFound);
        }
        self.step(g, Step::Unlink(&temp_path(volume))).await?;
        let from = lock(&self.process).clock;
        if !self.mutant(Mutation::CompleteNamespaceSkipsSync) {
            self.sync(g, Step::DirSync(&LogPath::StateDir)).await?;
            self.sync(g, Step::DirSync(&LogPath::Anchor)).await?;
        }
        // This log's barrier is complete only if its own call saw both
        // syncs return: another volume's syncs, or a marker write's, do
        // not count.
        let mut process = lock(&self.process);
        if process.namespace_synced_after(from) {
            process.completed.insert(log_path(volume));
        }
        Ok(())
    }

    async fn append_steps(&self, g: Cx, append: &Append) -> Result<(), LogIoError> {
        self.begin_log_write()?;
        let log = log_path(append.volume());
        if !self.log_exists(&log) {
            return Err(LogIoError::NotFound);
        }
        self.check_append(append);
        self.step(g, Step::Write(&log, append.record(), WriteKind::Record))
            .await?;
        if !self.mutant(Mutation::MarkBeforeRecordSync) {
            self.sync(g, Step::FileSync(&log)).await?;
        }
        self.step(g, Step::Write(&log, append.mark(), WriteKind::Mark))
            .await?;
        self.sync(g, Step::FileSync(&log)).await?;
        Ok(())
    }

    async fn truncate_steps(&self, g: Cx, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        self.begin_log_write()?;
        let log = log_path(volume);
        let current = lock(&self.world.disk)
            .file(&log)
            .map(|inode| inode.bytes().len());
        let Some(current) = current else {
            return Err(LogIoError::NotFound);
        };
        let len = match usize::try_from(len) {
            Ok(len) if len <= current => len,
            _ => return Err(LogIoError::OutOfRange),
        };
        self.step(g, Step::Truncate(&log, len)).await?;
        if !self.mutant(Mutation::TruncateSkipsSync) {
            self.sync(g, Step::FileSync(&log)).await?;
        }
        Ok(())
    }

    async fn resync_steps(&self, g: Cx, volume: &VolumeName) -> Result<(), LogIoError> {
        self.begin_mutating()?;
        let log = log_path(volume);
        if !self.log_exists(&log) {
            return Err(LogIoError::NotFound);
        }
        if !self.mutant(Mutation::ResyncSkipsSync) {
            self.sync(g, Step::FileSync(&log)).await?;
        }
        Ok(())
    }
}

impl DecisionLog for SimDecisionLog {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        let g = self.read_cx(LogCall::ReadMarker);
        let result = match self.crashed_guard() {
            Ok(()) => self
                .step(g, Step::Read(&LogPath::Marker))
                .await
                .map(|done| match done.bytes {
                    Some(bytes) => MarkerRead::Present(bytes),
                    None => MarkerRead::Missing {
                        state_dir: done.state_dir.unwrap_or(StateDirectory::Absent),
                    },
                }),
            Err(e) => Err(e),
        };
        self.record_call(LogCall::ReadMarker, None, &result, |read| {
            matches!(read, MarkerRead::Present(_))
        });
        result
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        let call = self.begin_call(LogPath::Marker, true, Cover::Token, LogCall::WriteMarker);
        let result = self.write_marker_steps(call.cx, marker.as_bytes()).await;
        call.finish(&result);
        self.record_call(LogCall::WriteMarker, None, &result, |()| true);
        result
    }

    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        let g = self.read_cx(LogCall::Read);
        let result = match self.crashed_guard() {
            Ok(()) => self
                .step(g, Step::Read(&log_path(volume)))
                .await
                .map(|done| done.bytes),
            Err(e) => Err(e),
        };
        self.record_call(LogCall::Read, Some(volume), &result, Option::is_some);
        result
    }

    async fn remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        let call = self.begin_call(
            log_path(volume),
            false,
            Cover::Outside,
            LogCall::RemoveTemporary,
        );
        let g = call.cx;
        let result = match self.begin_mutating() {
            Ok(()) => self
                .step(g, Step::Unlink(&temp_path(volume)))
                .await
                .map(|done| done.present),
            Err(e) => Err(e),
        };
        call.finish(&result);
        self.record_call(LogCall::RemoveTemporary, Some(volume), &result, |&b| b);
        result
    }

    async fn initialise(&self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        let call = self.begin_call(
            log_path(envelope.volume()),
            true,
            Cover::Token,
            LogCall::Initialise,
        );
        let result = self.initialise_steps(call.cx, envelope).await;
        call.finish(&result);
        self.record_call(
            LogCall::Initialise,
            Some(envelope.volume()),
            &result,
            |()| true,
        );
        result
    }

    async fn complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        let call = self.begin_call(
            log_path(volume),
            true,
            Cover::Token,
            LogCall::CompleteNamespace,
        );
        let result = self.complete_namespace_steps(call.cx, volume).await;
        call.finish(&result);
        self.record_call(LogCall::CompleteNamespace, Some(volume), &result, |()| true);
        result
    }

    async fn append(&self, append: &Append) -> Result<(), LogIoError> {
        let call = self.begin_call(
            log_path(append.volume()),
            true,
            Cover::Token,
            LogCall::Append,
        );
        let result = self.append_steps(call.cx, append).await;
        call.finish(&result);
        self.record_call(LogCall::Append, Some(append.volume()), &result, |()| true);
        result
    }

    async fn truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        let call = self.begin_call(log_path(volume), true, Cover::Token, LogCall::Truncate);
        let result = self.truncate_steps(call.cx, volume, len).await;
        call.finish(&result);
        self.record_call(LogCall::Truncate, Some(volume), &result, |()| true);
        result
    }

    async fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        let call = self.begin_call(log_path(volume), true, Cover::Token, LogCall::Resync);
        let result = self.resync_steps(call.cx, volume).await;
        call.finish(&result);
        self.record_call(LogCall::Resync, Some(volume), &result, |()| true);
        result
    }
}

/// The conformance suite's fixture hooks: harness operations that
/// bypass every step and every fault, each recorded in the trace.
impl DecisionLogFixture for SimDecisionLog {
    async fn seed_bytes(&self, volume: &VolumeName, bytes: Vec<u8>) {
        let path = log_path(volume);
        let op = LogOp::Seed {
            path: path.clone(),
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            addr: Address::new(*GrainId::of(&bytes).digest()),
        };
        lock(&self.world.disk).seed_file(&path, bytes);
        self.record(op, Outcome::Ok);
    }

    async fn seed_marker_bytes(&self, bytes: &[u8]) {
        let op = LogOp::Seed {
            path: LogPath::Marker,
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            addr: Address::new(*GrainId::of(bytes).digest()),
        };
        lock(&self.world.disk).seed_file(&LogPath::Marker, bytes.to_vec());
        self.record(op, Outcome::Ok);
    }

    async fn seed_empty_state_dir(&self) {
        lock(&self.world.disk).seed_empty_state_dir();
        self.record(LogOp::SeedEmptyStateDir, Outcome::Ok);
    }

    async fn seed_temporary(&self, volume: &VolumeName) {
        let path = temp_path(volume);
        let op = LogOp::Seed {
            path: path.clone(),
            len: 0,
            addr: Address::new(*GrainId::of(&[]).digest()),
        };
        lock(&self.world.disk).seed_file(&path, Vec::new());
        self.record(op, Outcome::Ok);
    }

    async fn reset(&self) {
        // Calls in flight are settled against the old disk first, so
        // none can fence the fresh one.
        self.retire_calls();
        lock(&self.world.disk).reset();
        self.generation.fetch_add(1, Ordering::SeqCst);
        *lock(&self.process) = Process::default();
        self.record(LogOp::Reset, Outcome::Ok);
    }
}

#[cfg(test)]
mod tests;
