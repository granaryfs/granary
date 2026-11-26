// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The scripted decision-log run behind [`crate::scenario::DECISION_LOG_SEEDS`]:
//! a writer that drives [`SimDecisionLog`] through a marker write, an
//! `initialise`, a few appends, a host crash and recovery, with no engine
//! above it, and checks the durability oracle inside the run.
//!
//! # What a seed decodes to
//!
//! [`LogPlan::decode`] reads the seed's low bits through the crate's
//! [`Rng`]: the fault kind ([`LogFaultKind`]), the raw target step, the
//! seed of the crash draws, how many appends the script makes, the
//! parameters of the media faults, whether a host crash cuts the append
//! phase, and whether a second crash lands inside recovery. Every choice
//! is a pure function of the seed.
//!
//! # The script
//!
//! 1. `write_marker`, `initialise`, then the plan's appends, each the
//!    next record of one legal sequence (a decision, its attestation and
//!    its landed outcome, then the next entry's decision, and so on).
//!    The first call that returns an error ends the process: the script
//!    models a fenced process and issues nothing more. Only the errors
//!    the scheduled faults produce end a process; any other is a defect
//!    ([`LogRunFailure::UnscheduledError`]).
//! 2. `crash_host`, drawing from the run's seeded generator.
//! 3. Recovery, as a new process: `read_marker`, `write_marker`,
//!    `remove_temporary`, `read`, classify (the verdict is traced),
//!    `truncate` to the committed prefix when a tail follows it, then
//!    `resync` a log that holds records or `complete_namespace` one that
//!    holds none, and finally one more append, so the fake's barrier
//!    checks judge whether recovery did everything an append needs. A
//!    last `read` and classify follows.
//! 4. A recovery that ends on an error is followed by another
//!    `crash_host` and another recovery. At most two faults are scheduled
//!    by step index (a failed sync or a crash in the append phase, and
//!    the second crash), each ends at most one process, and the recovery
//!    after them completes, so the rounds are bounded by three.
//!
//! # The faults by step index
//!
//! - **A failed sync** lands on the k-th sync step of the fault-free
//!   script, k being the raw target modulo the number of sync steps, so
//!   every [`LogFault::FailSync`] fails a real sync.
//! - **A crash in the append phase** ([`LogFault::CrashAt`], only for
//!   plans with no other fault) lands on any step of any append of the
//!   first process.
//! - **The second crash** is a [`LogFault::CrashAt`] inside the first
//!   recovery's steps. The recovery's step range is measured by running
//!   the same plan without it first: the two runs are identical up to the
//!   crash, because everything is a function of the seed. A plan with a
//!   failed sync takes the second crash only after the failed sync's
//!   step, so the fault always fires on the step the fault-free script
//!   names.
//!
//! # The oracle
//!
//! After every crash the expected committed records are the records
//! whose append returned, plus the survivors the draw kept
//! ([`DrawRow::Survivor`]). Recovery's classification of `read` must give
//! exactly those records, and the bytes of its committed prefix must
//! equal the bytes the script wrote for them.
//!
//! - **An honest crash never refuses.** No injected damage means every
//!   crash is one the log's format is built to recover from, so a
//!   refusal is [`LogRunFailure::HonestCrashRefused`], not a verdict.
//! - **A log that `initialise` created is always there.** Once the call
//!   returned, recovery finds the log with a whole envelope; a missing
//!   log or one with no envelope fails the run.
//! - **Every refusal names its reason and place.** The oracle expects
//!   [`granary_core::authlog::LogErrorReason::DamagedCommittedHistory`]
//!   at the byte offset where the committed prefix ends, computed from
//!   the byte lengths of the script's own records.
//! - **[`LogFault::CorruptDetectable`] must refuse.**
//! - **The tail bound** is computed from those lengths and never
//!   by asking the classifier. [`LogFault::ResidualLoss`] from a
//!   mark leaves a whole
//!   legal next record leading the tail: discarded when the tail is no
//!   longer than that record plus [`MARK_LEN`], refused otherwise, and
//!   the script's choices land on both sides. Residual loss from inside a
//!   record leaves no whole record leading it: discarded when the tail is
//!   no longer than [`RECORD_V1_MAX`]. The fixture's records are short,
//!   so that loss never exceeds the bound on its own; the refusal side is
//!   reached by [`LogFaultKind::OversizeTail`], a tail that begins with
//!   half a record and is one byte longer than the bound, and
//!   [`LogFaultKind::AtBoundTail`] pairs it at exactly the bound
//!   (discarded).
//!   [`LogFaultKind::ForeignTail`] leads the tail with a whole,
//!   check-valid record of this epoch that is not the legal next one
//!   (refused), and [`LogFaultKind::WrongSeqTail`] with the legal next
//!   record under the wrong entry sequence number (refused, which a check
//!   of the tag and entry state alone would miss).
//!   [`LogFaultKind::OtherEpochTail`] leads it with a whole record of
//!   another epoch that would be refused if it were this epoch's: a
//!   reader that checks the epoch first discards it, and one that does
//!   not refuses it.
//! - **A fence or barrier violation the fake records fails the run.**
//!   The script stops at the first error, so a run that reaches one has
//!   a defect in the script.

use std::fmt;

use granary_core::authlog::LogErrorReason;
use granary_core::authlog::{
    Append, Classified, EPOCH_LEN, Envelope, Epoch, LogError, MARK_LEN, Operation, Principal,
    RECORD_V1_MAX, Record, RecordBody, RootBytes, SubmissionIdentity, Tenant, encode_append,
    encode_envelope,
};
use granary_core::decisionlog::{DecisionLog, IoErrorKind, LogIoError};
use granary_core::hash::GrainId;
use granary_core::rng::Rng as _;
use granary_core::root::{self, RootDoc, RootSig, Timestamp, VolumeName};

use super::{DECISION_LOG_SEEDS, DRIVER_SEED, run};
use crate::decision_log::{CrashReport, LogFault, LogFaults, Mutation, SimDecisionLog};
use crate::fakes::Sim;
use crate::rng::Rng;
use crate::sched::Task;
use crate::trace::{Damage, DrawRow, LogOp, LogPath, LogViolation, Op, Outcome, Trace, TraceError};
use crate::trace::{TruncationDraw, Verdict, Volume};
use granary_core::runmarker::{BootId, EncodedMarker, RunMarker, encode_marker};

/// The volume the scripted log belongs to.
pub const LOG_VOLUME: &str = "sim-log";

/// The run marker a running process writes: any fixed boot id will do, the
/// scenario never reads it back.
fn running_marker() -> EncodedMarker {
    encode_marker(&RunMarker::Running(BootId::from_bytes([0x5A; 16])))
}

/// The stream the plan is decoded from.
const PLAN_STREAM: u64 = 0x10C5_0000_0001;

/// The stream the crash draws come from.
const DRAW_STREAM: u64 = 0x10C5_0000_0002;

/// How many crash-and-recovery rounds a run may take before it is called
/// non-convergent. At most two faults are scheduled by step index, each
/// ends at most one process, and the recovery after the last completes:
/// the first process may end on the first, the first recovery on the
/// second, and the third round completes.
const MAX_ROUNDS: u32 = 3;

/// Records built beyond the plan's appends, for the appends recovery
/// makes.
const SPARE_RECORDS: u32 = 8;

/// The fault a plan injects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogFaultKind {
    /// None: every crash is an honest one.
    None,
    /// A sync fails: the target selects which of the fault-free script's
    /// syncs.
    FailSync,
    /// One byte inside a committed record flips at the first crash.
    CorruptDetectable,
    /// The end of the file is destroyed from a committed record's mark,
    /// or from inside it, at the first crash.
    ResidualLoss,
    /// At the first crash the tail becomes half a record and filler, one
    /// byte longer than the largest record: refused.
    OversizeTail,
    /// The same tail at exactly the largest record's length: discarded.
    AtBoundTail,
    /// At the first crash the tail becomes a whole record of this epoch
    /// that is not the legal next one (its tag and entry state are wrong):
    /// refused.
    ForeignTail,
    /// At the first crash the tail becomes the legal next record with a
    /// wrong entry sequence number: refused.
    WrongSeqTail,
    /// At the first crash the tail becomes a whole record of another
    /// epoch, one that would be refused if it were this epoch's:
    /// discarded.
    OtherEpochTail,
}

impl LogFaultKind {
    /// Every kind, in a fixed order.
    pub const ALL: [Self; 9] = [
        Self::None,
        Self::FailSync,
        Self::CorruptDetectable,
        Self::ResidualLoss,
        Self::OversizeTail,
        Self::AtBoundTail,
        Self::ForeignTail,
        Self::WrongSeqTail,
        Self::OtherEpochTail,
    ];
}

impl fmt::Display for LogFaultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::FailSync => "fail-sync",
            Self::CorruptDetectable => "corrupt-detectable",
            Self::ResidualLoss => "residual-loss",
            Self::OversizeTail => "oversize-tail",
            Self::AtBoundTail => "at-bound-tail",
            Self::ForeignTail => "foreign-tail",
            Self::WrongSeqTail => "wrong-seq-tail",
            Self::OtherEpochTail => "other-epoch-tail",
        })
    }
}

/// What a decision-log seed decodes to (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPlan {
    /// The fault kind.
    pub kind: LogFaultKind,
    /// The raw target: taken modulo the number of sync steps of the
    /// fault-free script to name the sync a [`LogFaultKind::FailSync`]
    /// fails.
    pub target: u32,
    /// The seed of the crash draws.
    pub draw_seed: u64,
    /// How many appends the first process makes: 3 to 6.
    pub appends: u32,
    /// The committed record a [`LogFaultKind::CorruptDetectable`] flips
    /// a byte in.
    pub record: u32,
    /// How many committed records a [`LogFaultKind::ResidualLoss`]
    /// destroys, from the last, and a planted tail replaces: 1 to 3.
    pub records: u32,
    /// Whether a [`LogFaultKind::ResidualLoss`] starts inside the first
    /// destroyed record rather than at its mark.
    pub into_record: bool,
    /// The raw step of the second crash inside recovery, if the plan has
    /// one: taken modulo the first recovery's step count.
    pub second_crash: Option<u32>,
    /// The raw step of a host crash in the append phase of the first
    /// process, if the plan has one (only a plan with no fault does):
    /// taken modulo the number of steps of that phase.
    pub mid_crash: Option<u32>,
}

impl LogPlan {
    /// How many committed records a planted tail leaves.
    #[must_use]
    pub fn keep(&self) -> u32 {
        self.appends.saturating_sub(self.records)
    }

    /// The plan a seed decodes to. The selector bit is ignored: two seeds
    /// that differ only in it decode alike.
    #[must_use]
    pub fn decode(seed: u64) -> Self {
        let mut rng = Rng::seeded(seed & !DECISION_LOG_SEEDS, PLAN_STREAM);
        let kind = match rng.below(10) {
            0 | 1 => LogFaultKind::None,
            2 => LogFaultKind::FailSync,
            3 => LogFaultKind::CorruptDetectable,
            4 => LogFaultKind::ResidualLoss,
            5 => LogFaultKind::OversizeTail,
            6 => LogFaultKind::AtBoundTail,
            7 => LogFaultKind::ForeignTail,
            8 => LogFaultKind::WrongSeqTail,
            _ => LogFaultKind::OtherEpochTail,
        };
        let target = rng.next_u32();
        let draw_seed = rng.next_u64();
        let appends = 3 + rng.below(4);
        let record = rng.below(appends);
        let records = 1 + rng.below(3);
        let into_record = rng.below(2) == 1;
        let second_crash = (rng.below(2) == 1).then(|| rng.next_u32());
        let mid = rng.next_u32();
        let mid_crash = (kind == LogFaultKind::None && rng.below(2) == 1).then_some(mid);
        Self {
            kind,
            target,
            draw_seed,
            appends,
            record,
            records,
            into_record,
            second_crash,
            mid_crash,
        }
    }
}

/// Why a scripted run failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogRunFailure {
    /// A crash with no injected damage was refused by recovery's
    /// classification: a violation of the log format's contract.
    HonestCrashRefused {
        /// Where in the script the classification ran.
        stage: &'static str,
        /// The refusal.
        error: LogError,
    },
    /// Recovery's classification differed from the oracle's expectation.
    Mismatch {
        /// Where in the script the classification ran.
        stage: &'static str,
        /// What differed.
        detail: String,
    },
    /// The fake recorded ordering violations: a defect in the script.
    Violations(Vec<LogViolation>),
    /// A call returned an error although no fault was scheduled.
    UnscheduledError(LogIoError),
    /// Recovery kept ending on errors past the bound.
    NoConvergence,
    /// The script ran out of records to append.
    ScriptExhausted,
}

impl fmt::Display for LogRunFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HonestCrashRefused { stage, error } => write!(
                f,
                "at {stage}: a crash with no injected damage was refused, which the log \
                 format's contract forbids: {error}"
            ),
            Self::Mismatch { stage, detail } => write!(f, "at {stage}: {detail}"),
            Self::Violations(violations) => {
                write!(f, "the fake recorded ordering violations: {violations:?}")
            }
            Self::UnscheduledError(e) => {
                write!(f, "a call failed with no fault scheduled: {e:?}")
            }
            Self::NoConvergence => f.write_str("recovery did not converge"),
            Self::ScriptExhausted => f.write_str("the script ran out of records"),
        }
    }
}

/// A scripted run that failed, with the trace it left.
#[derive(Debug, Clone)]
pub struct LogRunError {
    /// The seed the run was started with, its selector bit set: the
    /// argument that replays the failure.
    pub seed: u64,
    /// Whether the plan is the one `seed` decodes to. A plan edited by a
    /// caller of [`run_plan`] is not, and its failure cannot be replayed
    /// from the seed.
    pub replayable: bool,
    /// The plan that ran, boxed to keep the error small.
    pub plan: Box<LogPlan>,
    /// What went wrong.
    pub failure: LogRunFailure,
    /// What the run had recorded when it stopped.
    pub trace: Trace,
}

impl fmt::Display for LogRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.replayable {
            write!(
                f,
                "decision-log run at seed {} failed {} (replay: sim-replay {})",
                self.seed, self.failure, self.seed
            )
        } else {
            write!(
                f,
                "decision-log run of an edited plan {:?} failed {} (seed {} decodes to a \
                 different plan, so `sim-replay {}` does not reproduce it)",
                self.plan, self.failure, self.seed, self.seed
            )
        }
    }
}

impl std::error::Error for LogRunError {}

/// A scripted run that satisfied its oracle.
#[derive(Debug)]
pub struct LogRun {
    /// The world the run ran in. Its [`Sim::trace`] IS the replay
    /// artifact.
    pub sim: Sim,
    /// What the seed decoded to.
    pub plan: LogPlan,
    /// The fault-free script's step count.
    pub steps: u32,
    /// The step a [`LogFaultKind::FailSync`] failed.
    pub fail_sync_at: Option<u32>,
    /// The step of the host crash in the append phase.
    pub mid_crash_at: Option<u32>,
    /// The step the second crash landed on.
    pub second_crash_at: Option<u32>,
}

// -------------------------------------------------------------- fixtures

/// A decodable root for `volume` at `seq` over `parent`. Its signature is
/// filler: the log's codec checks a candidate's structure, not its
/// signature.
///
/// # Panics
/// If the fixture cannot be encoded, a defect in this file.
fn sample_root(volume: &VolumeName, seq: u64, parent: Option<GrainId>) -> Vec<u8> {
    let doc = RootDoc {
        volume: volume.clone(),
        seq,
        parent,
        writer_uuid: [0xAB; root::WRITER_UUID_LEN],
        epoch: 7,
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        chunker_spec: "sim-chunker".to_owned(),
        manifest_root: GrainId::of(&seq.to_le_bytes()),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![RootSig {
            key_id: [0x01; root::KEY_ID_LEN],
            sig: [0x02; root::ED25519_SIG_LEN],
        }],
    };
    root::encode_root(&doc).unwrap_or_else(|e| panic!("the fixture root must encode: {e:?}"))
}

/// `count` records of one legal log: for each entry a decision, its
/// attestation and its landed outcome, the next entry's decision on top
/// of the last one's root. Any prefix is legal, an open entry included.
///
/// # Panics
/// If a fixture record cannot be built, a defect in this file.
pub(crate) fn script_records(volume: &VolumeName, count: usize) -> Vec<Record> {
    let build = |seq: u64, body: RecordBody| {
        Record::new(seq, body).unwrap_or_else(|e| panic!("entry seqs start at 1: {e}"))
    };
    let bytes = |raw: Vec<u8>| {
        RootBytes::new(raw).unwrap_or_else(|e| panic!("the fixture root is small: {e:?}"))
    };
    let mut out = Vec::with_capacity(count.saturating_add(3));
    let mut parent: Option<GrainId> = None;
    let mut entry = 1u64;
    while out.len() < count {
        let candidate = sample_root(volume, entry, parent);
        let id = GrainId::of(&candidate);
        let identity = SubmissionIdentity::new(
            Tenant::new(vec![0x11]).unwrap_or_else(|e| panic!("a one-byte tenant is legal: {e:?}")),
            Principal::new(vec![0x22, 0x22])
                .unwrap_or_else(|e| panic!("a two-byte principal is legal: {e:?}")),
            Operation::new(entry.to_le_bytes().to_vec())
                .unwrap_or_else(|e| panic!("an eight-byte operation is legal: {e:?}")),
            id,
        );
        out.push(build(
            entry,
            RecordBody::Decision {
                identity: identity.clone(),
                root_seq: entry,
                base: parent,
                decided_at: Timestamp {
                    secs: 1_760_000_001,
                    nanos: 0,
                },
                candidate: bytes(candidate.clone()),
            },
        ));
        out.push(build(
            entry,
            RecordBody::Attestation {
                identity: identity.clone(),
                stored_id: id,
                final_root: bytes(candidate),
            },
        ));
        out.push(build(entry, RecordBody::Landed { identity }));
        parent = Some(id);
        entry = entry.saturating_add(1);
    }
    out.truncate(count);
    out
}

/// The script's log: its volume, its envelope and the records it appends
/// in order, each with its encoded record and mark.
struct Script {
    volume: VolumeName,
    envelope: Envelope,
    records: Vec<Record>,
    appends: Vec<Append>,
}

impl Script {
    /// # Panics
    /// If the fixtures cannot be built, a defect in this file.
    fn new(count: usize) -> Self {
        let volume = VolumeName::new(LOG_VOLUME.to_owned())
            .unwrap_or_else(|e| panic!("{LOG_VOLUME} must be a DNS-1123 label: {e}"));
        let envelope = Envelope::new(volume.clone(), Epoch::from_bytes([0x5E; EPOCH_LEN]));
        let records = script_records(&volume, count);
        let appends = records
            .iter()
            .map(|record| {
                encode_append(&envelope, record)
                    .unwrap_or_else(|e| panic!("a fixture record must encode: {e:?}"))
            })
            .collect();
        Self {
            volume,
            envelope,
            records,
            appends,
        }
    }

    fn append(&self, index: usize) -> Result<&Append, LogRunFailure> {
        self.appends
            .get(index)
            .ok_or(LogRunFailure::ScriptExhausted)
    }

    /// The length of the envelope and the first `count` records with
    /// their marks.
    fn prefix_len(&self, count: usize) -> usize {
        self.prefix_bytes(count).len()
    }

    /// The bytes of the envelope and the first `count` records with
    /// their marks.
    fn prefix_bytes(&self, count: usize) -> Vec<u8> {
        let mut bytes = encode_envelope(&self.envelope).as_bytes().to_vec();
        for append in self.appends.iter().take(count) {
            bytes.extend_from_slice(append.record());
            bytes.extend_from_slice(append.mark());
        }
        bytes
    }

    /// The tail a planted-tail fault leaves after the first `keep`
    /// records.
    ///
    /// # Panics
    /// If a fixture cannot be encoded, a defect in this file.
    fn planted_tail(&self, kind: LogFaultKind, keep: usize) -> Vec<u8> {
        let record_at = |index: usize| {
            self.appends
                .get(index)
                .map(|append| append.record().to_vec())
                .unwrap_or_default()
        };
        // A tail that begins with the first half of record `keep`, then
        // filler, `len` bytes in all.
        let half_then_filler = |len: usize| {
            let record = record_at(keep);
            let mut tail = record.get(..record.len() / 2).unwrap_or_default().to_vec();
            tail.resize(len, 0xFF);
            tail
        };
        let in_epoch = |envelope: &Envelope, index: usize, seq_shift: u64| {
            self.records
                .get(index)
                .map(|record| {
                    let record = Record::new(
                        record.seq().saturating_add(seq_shift),
                        record.body().clone(),
                    )
                    .unwrap_or_else(|e| panic!("a shifted fixture seq is at least 1: {e}"));
                    encode_append(envelope, &record)
                        .unwrap_or_else(|e| panic!("a fixture record must encode: {e:?}"))
                        .record()
                        .to_vec()
                })
                .unwrap_or_default()
        };
        let other_epoch = Envelope::new(self.volume.clone(), Epoch::from_bytes([0xA5; EPOCH_LEN]));
        match kind {
            LogFaultKind::OversizeTail => half_then_filler(RECORD_V1_MAX + 1),
            LogFaultKind::AtBoundTail => half_then_filler(RECORD_V1_MAX),
            // Two records on is never the legal next one: whichever
            // record follows `keep`, the one after it breaks a grammar
            // rule.
            LogFaultKind::ForeignTail => record_at(keep + 2),
            // The legal next record under the wrong entry sequence
            // number: its tag and entry state are right.
            LogFaultKind::WrongSeqTail => in_epoch(&self.envelope, keep, 5),
            // The record two on, so an epoch-blind reader would judge it
            // an illegal next record and refuse, where a reader that
            // checks the epoch first finds no record of this log at all.
            LogFaultKind::OtherEpochTail => in_epoch(&other_epoch, keep + 2, 0),
            _ => Vec::new(),
        }
    }

    /// The length of record `index` alone, no mark.
    fn record_len(&self, index: usize) -> usize {
        self.appends
            .get(index)
            .map_or(0, |append| append.record().len())
    }
}

// ------------------------------------------------------------- the runner

/// What the oracle expects recovery to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The script's first `committed` records. `honest` says no damage
    /// was injected, so a refusal is a contract violation.
    Committed { honest: bool },
    /// A refusal for damaged committed history at this byte offset.
    Refuse { offset: usize },
}

/// Which faults a pass has scheduled by step index, and so which errors,
/// at which steps, end a process without being a defect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Scheduled {
    /// The step of a [`LogFault::FailSync`]: the call it fails returns
    /// `SyncFailed`.
    sync_fail: Option<u32>,
    /// The steps of the [`LogFault::CrashAt`]s: the process dies there,
    /// and its call returns an I/O error.
    crashes: Vec<u32>,
}

impl Scheduled {
    /// Whether a scheduled fault produces `error` at step `at`.
    fn explains(&self, error: LogIoError, at: u32) -> bool {
        match error {
            LogIoError::SyncFailed => self.sync_fail == Some(at),
            LogIoError::Io(IoErrorKind::Other) => self.crashes.contains(&at),
            _ => false,
        }
    }
}

/// Why the process stopped: the call it was in returned an error (the
/// process is fenced or dead), or the oracle failed.
enum Stop {
    Ended(LogIoError),
    Failed(LogRunFailure),
}

impl From<LogIoError> for Stop {
    fn from(e: LogIoError) -> Self {
        Self::Ended(e)
    }
}

impl From<LogRunFailure> for Stop {
    fn from(f: LogRunFailure) -> Self {
        Self::Failed(f)
    }
}

fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn as_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// The script and its oracle, driving one log handle.
struct Runner<'a> {
    log: &'a SimDecisionLog,
    script: &'a Script,
    plan: &'a LogPlan,
    rng: Rng,
    /// The faults scheduled on this pass.
    scheduled: Scheduled,
    /// Whether the log's name is durable: `initialise` or recovery's
    /// `complete_namespace` has returned.
    initialised: bool,
    /// The step range of the first process's appends.
    append_window: Option<(u32, u32)>,
    /// How many script records are committed: appends that returned, and
    /// survivors a draw kept, less what a residual loss destroyed.
    committed: usize,
    expect: Expect,
    /// The step range of the first recovery.
    window: Option<(u32, u32)>,
}

impl Runner<'_> {
    fn log_path(&self) -> LogPath {
        LogPath::Log(Volume::from_checked(&self.script.volume))
    }

    /// The first process: the marker, the log, the appends.
    async fn first_process(&mut self) -> Result<(), Stop> {
        self.log.write_marker(&running_marker()).await?;
        self.log
            .initialise(&encode_envelope(&self.script.envelope))
            .await?;
        self.initialised = true;
        let start = self.log.steps();
        for _ in 0..self.plan.appends {
            self.append_next().await?;
        }
        self.append_window = Some((start, self.log.steps()));
        Ok(())
    }

    /// Append the script's next record, counting it committed when the
    /// call returns.
    async fn append_next(&mut self) -> Result<(), Stop> {
        let append = self.script.append(self.committed)?;
        self.log.append(append).await?;
        self.committed += 1;
        Ok(())
    }

    /// One recovery process (module docs).
    async fn recover(&mut self) -> Result<(), Stop> {
        let (log, volume) = (self.log, &self.script.volume);
        log.read_marker().await?;
        log.write_marker(&running_marker()).await?;
        log.remove_temporary(volume).await?;
        let bytes = log.read(volume).await?;
        let verdict = log.classify_traced(volume, bytes.as_deref());
        self.check("recovery", bytes.as_deref(), verdict.as_ref())?;
        if let Some(Ok(Classified::Log {
            records,
            committed_len,
            tail_len,
            ..
        })) = &verdict
        {
            if *tail_len > 0 {
                log.truncate(volume, as_u64(*committed_len)).await?;
            }
            if records.is_empty() {
                log.complete_namespace(volume).await?;
                self.initialised = true;
            } else {
                log.resync(volume).await?;
            }
            self.append_next().await?;
        }
        let bytes = log.read(volume).await?;
        let verdict = log.classify_traced(volume, bytes.as_deref());
        self.check("final", bytes.as_deref(), verdict.as_ref())?;
        Ok(())
    }

    /// The whole run: the first process, then crash and recovery until a
    /// recovery completes.
    async fn drive(&mut self) -> Result<(), LogRunFailure> {
        let first = self.first_process().await;
        self.ended(first)?;
        for round in 0..MAX_ROUNDS {
            let report = self.log.crash_host(&mut self.rng);
            self.absorb(&report, round == 0);
            let start = self.log.steps();
            let outcome = self.recover().await;
            if self.window.is_none() {
                self.window = Some((start, self.log.steps()));
            }
            match outcome {
                Ok(()) => return Ok(()),
                Err(stop) => self.ended(Err(stop))?,
            }
        }
        Err(LogRunFailure::NoConvergence)
    }

    /// A process's end: an oracle failure propagates, and an error from a
    /// call is a modelled death only when a scheduled fault produces it
    /// at the step the call failed on, the last step taken.
    fn ended(&self, outcome: Result<(), Stop>) -> Result<(), LogRunFailure> {
        match outcome {
            Ok(()) => Ok(()),
            Err(Stop::Failed(failure)) => Err(failure),
            Err(Stop::Ended(e))
                if self
                    .scheduled
                    .explains(e, self.log.steps().saturating_sub(1)) =>
            {
                Ok(())
            }
            Err(Stop::Ended(e)) => Err(LogRunFailure::UnscheduledError(e)),
        }
    }

    /// Fold a host crash into the expectation: its survivors are
    /// committed, and at the first crash the injected damage decides
    /// whether recovery discards or refuses.
    fn absorb(&mut self, report: &CrashReport, first: bool) {
        let path = self.log_path();
        let survivors = report
            .rows
            .iter()
            .filter(|(p, _, row)| *p == path && *row == DrawRow::Survivor)
            .count();
        self.committed += survivors;
        if !first {
            return;
        }
        let Some((_, damage, _, end)) = report.damaged.iter().find(|(p, ..)| *p == path) else {
            self.expect = Expect::Committed { honest: true };
            return;
        };
        let records = usize::try_from(self.plan.records).unwrap_or(usize::MAX);
        let planted_keep = usize::try_from(self.plan.keep()).unwrap_or(usize::MAX);
        match damage {
            Damage::Detectable => {
                let record = usize::try_from(self.plan.record).unwrap_or(usize::MAX);
                self.expect = Expect::Refuse {
                    offset: self.script.prefix_len(record),
                };
            }
            Damage::Residual | Damage::ResidualIntoRecord => {
                let keep = self.committed.saturating_sub(records);
                let tail = as_usize(*end).saturating_sub(self.script.prefix_len(keep));
                // Damage from a mark leaves the record whole: a legal
                // next record, so the tail may run to it and one mark.
                // Damage from inside a record breaks it, so the tail is
                // bounded by the largest record.
                let bound = if *damage == Damage::ResidualIntoRecord {
                    RECORD_V1_MAX
                } else {
                    self.script.record_len(keep).saturating_add(MARK_LEN)
                };
                if tail <= bound {
                    self.committed = keep;
                    self.expect = Expect::Committed { honest: false };
                } else {
                    self.expect = Expect::Refuse {
                        offset: self.script.prefix_len(keep),
                    };
                }
            }
            Damage::Oversize | Damage::ForeignRecord | Damage::WrongSeqRecord => {
                self.committed = planted_keep;
                self.expect = Expect::Refuse {
                    offset: self.script.prefix_len(planted_keep),
                };
            }
            Damage::OtherEpochRecord | Damage::AtBound => {
                self.committed = planted_keep;
                self.expect = Expect::Committed { honest: false };
            }
        }
    }

    /// Compare recovery's classification of `bytes` with the oracle's
    /// expectation.
    fn check(
        &self,
        stage: &'static str,
        bytes: Option<&[u8]>,
        verdict: Option<&Result<Classified, LogError>>,
    ) -> Result<(), LogRunFailure> {
        let mismatch = |detail: String| LogRunFailure::Mismatch { stage, detail };
        let honest = match self.expect {
            Expect::Refuse { offset } => {
                return match verdict {
                    Some(Err(error))
                        if error.reason == LogErrorReason::DamagedCommittedHistory
                            && error.offset == offset =>
                    {
                        Ok(())
                    }
                    Some(Err(error)) => Err(mismatch(format!(
                        "recovery refused, but not for damaged committed history at byte \
                         {offset}: {error}"
                    ))),
                    _ => Err(mismatch(
                        "recovery accepted a log the injected damage must make it refuse"
                            .to_owned(),
                    )),
                };
            }
            Expect::Committed { honest } => honest,
        };
        let nothing = |what: &str| {
            if self.committed == 0 {
                Ok(())
            } else {
                Err(mismatch(format!(
                    "{what}, but {} records are committed",
                    self.committed
                )))
            }
        };
        match verdict {
            Some(Err(error)) if honest => Err(LogRunFailure::HonestCrashRefused {
                stage,
                error: *error,
            }),
            Some(Err(error)) => Err(mismatch(format!(
                "recovery refused a discard the injected damage promised: {error}"
            ))),
            None if self.initialised => Err(mismatch(
                "the log's name was made durable, but the log is absent".to_owned(),
            )),
            None => nothing("the log is absent"),
            // The log's name appears only once its envelope is durable,
            // so a file with no envelope there is never a crash outcome.
            Some(Ok(Classified::NoEnvelope)) => Err(mismatch(
                "the log's name holds a file with no envelope, which no crash can leave".to_owned(),
            )),
            Some(Ok(Classified::Log {
                records,
                committed_len,
                tail_len,
                ..
            })) => {
                let bytes = bytes.unwrap_or_default();
                if committed_len.saturating_add(*tail_len) != bytes.len() {
                    return Err(mismatch(
                        "the committed prefix and the tail do not add up to the log".to_owned(),
                    ));
                }
                if self.script.records.get(..self.committed) != Some(records.as_slice()) {
                    return Err(mismatch(format!(
                        "recovery committed {} records, the oracle expects the script's first {}",
                        records.len(),
                        self.committed
                    )));
                }
                if bytes.get(..*committed_len)
                    != Some(self.script.prefix_bytes(self.committed).as_slice())
                {
                    return Err(mismatch(
                        "the committed prefix is not the bytes the script wrote".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

// --------------------------------------------------------------- the passes

/// What one execution of the script leaves: how it ended, its step
/// count, its first recovery's step range and its append phase's.
type Pass = (
    Result<(), LogRunFailure>,
    u32,
    Option<(u32, u32)>,
    Option<(u32, u32)>,
);

/// One execution of the script under `faults`.
struct Executed {
    sim: Sim,
    steps: u32,
    /// The step range of the first recovery.
    window: Option<(u32, u32)>,
    /// The step range of the first process's appends.
    append_window: Option<(u32, u32)>,
    /// The index of every sync step, read off the trace.
    sync_steps: Vec<u32>,
}

/// Run the script once, in a fresh world, under `faults`, which
/// `scheduled` describes. Only tests run the script over a plain log
/// directly; [`run_plan`] goes through [`execute_variant`].
///
/// # Errors
/// [`LogRunError`] when the oracle, the fake's ordering checks or the
/// script itself fail. Its seed has the selector bit set, so it is the
/// argument that replays the failure.
#[cfg(test)]
fn execute(
    seed: u64,
    plan: &LogPlan,
    faults: LogFaults,
    scheduled: Scheduled,
) -> Result<Executed, LogRunError> {
    execute_variant(seed, plan, faults, scheduled, None)
}

/// [`execute`] over a deliberately broken log, when `mutation` is set.
fn execute_variant(
    seed: u64,
    plan: &LogPlan,
    faults: LogFaults,
    scheduled: Scheduled,
    mutation: Option<Mutation>,
) -> Result<Executed, LogRunError> {
    let seed = seed | DECISION_LOG_SEEDS;
    let sim = Sim::new();
    let log = match mutation {
        Some(mutation) => sim.decision_log_variant(0, faults, mutation),
        None => sim.decision_log(0, faults),
    };
    let count = usize::try_from(plan.appends + SPARE_RECORDS).unwrap_or(usize::MAX);
    let script = Script::new(count);
    let owned = plan.clone();
    let task: Task<Pass> = Box::pin(async move {
        let mut runner = Runner {
            log: &log,
            script: &script,
            rng: Rng::seeded(owned.draw_seed, DRAW_STREAM),
            plan: &owned,
            scheduled,
            initialised: false,
            append_window: None,
            committed: 0,
            expect: Expect::Committed { honest: true },
            window: None,
        };
        let mut outcome = runner.drive().await;
        let violations = log.violations();
        if outcome.is_ok() && !violations.is_empty() {
            outcome = Err(LogRunFailure::Violations(violations));
        }
        (outcome, log.steps(), runner.window, runner.append_window)
    });
    let (outcome, steps, window, append_window) = run(DRIVER_SEED, task);
    match outcome {
        Ok(()) => {
            let sync_steps = log_steps(&sim.trace())
                .iter()
                .enumerate()
                .filter(|(_, (op, _))| matches!(op, LogOp::FileSync { .. } | LogOp::DirSync { .. }))
                .filter_map(|(index, _)| u32::try_from(index).ok())
                .collect();
            Ok(Executed {
                sim,
                steps,
                window,
                append_window,
                sync_steps,
            })
        }
        Err(failure) => Err(LogRunError {
            seed,
            replayable: *plan == LogPlan::decode(seed),
            plan: Box::new(plan.clone()),
            failure,
            trace: sim.trace(),
        }),
    }
}

/// The scripted decision-log run a seed with
/// [`DECISION_LOG_SEEDS`] set selects: [`run_plan`] over the plan the seed
/// decodes to.
///
/// # Errors
/// [`LogRunError`], carrying the trace, when the run violates the oracle.
pub fn decision_log_run(seed: u64) -> Result<LogRun, LogRunError> {
    run_plan(seed, &LogPlan::decode(seed))
}

/// The scripted run of `plan`, which `seed` (used only to name a failure)
/// decoded to, or which a caller edited to vary one choice alone.
///
/// Three passes at most, each in a fresh world: the fault-free script,
/// which names the steps the faults land on; the plan's faults; and, for
/// a plan with a second crash, the same run with the crash at a step
/// inside recovery, measured on the pass before. The last pass is the
/// run.
///
/// # Errors
/// [`LogRunError`], carrying the trace, when a pass violates the oracle.
///
/// # Panics
/// If a fixture cannot be built, a defect in this file.
pub fn run_plan(seed: u64, plan: &LogPlan) -> Result<LogRun, LogRunError> {
    run_plan_with(seed, plan, None)
}

/// [`run_plan`] over a deliberately broken log, when `mutation` is set.
///
/// # Errors
/// As [`run_plan`].
///
/// # Panics
/// As [`run_plan`].
fn run_plan_with(
    seed: u64,
    plan: &LogPlan,
    mutation: Option<Mutation>,
) -> Result<LogRun, LogRunError> {
    let plan = plan.clone();
    let free = execute_variant(
        seed,
        &plan,
        LogFaults::none(),
        Scheduled::default(),
        mutation,
    )?;
    let steps = free.steps;
    let syncs = free.sync_steps.len().max(1);
    let fail_sync_at = (plan.kind == LogFaultKind::FailSync)
        .then(|| {
            let k = usize::try_from(plan.target).unwrap_or(0) % syncs;
            free.sync_steps.get(k).copied()
        })
        .flatten();
    let mid_crash_at = match (plan.mid_crash, free.append_window) {
        (Some(raw), Some((start, end))) if end > start => Some(start + raw % (end - start)),
        _ => None,
    };
    let count = usize::try_from(plan.appends + SPARE_RECORDS).unwrap_or(usize::MAX);
    let script = Script::new(count);
    let keep = plan.keep();
    let planted = |damage: Damage| LogFault::PlantTail {
        volume: script.volume.clone(),
        keep,
        tail: script.planted_tail(plan.kind, usize::try_from(keep).unwrap_or(usize::MAX)),
        damage,
    };
    let mut faults = match plan.kind {
        LogFaultKind::None => LogFaults::none(),
        LogFaultKind::FailSync => LogFaults::just(LogFault::FailSync {
            at: fail_sync_at.unwrap_or(0),
        }),
        LogFaultKind::CorruptDetectable => LogFaults::just(LogFault::CorruptDetectable {
            volume: script.volume.clone(),
            record: plan.record,
        }),
        LogFaultKind::ResidualLoss => LogFaults::just(LogFault::ResidualLoss {
            volume: script.volume.clone(),
            records: plan.records,
            into_record: plan.into_record,
        }),
        LogFaultKind::OversizeTail => LogFaults::just(planted(Damage::Oversize)),
        LogFaultKind::AtBoundTail => LogFaults::just(planted(Damage::AtBound)),
        LogFaultKind::ForeignTail => LogFaults::just(planted(Damage::ForeignRecord)),
        LogFaultKind::WrongSeqTail => LogFaults::just(planted(Damage::WrongSeqRecord)),
        LogFaultKind::OtherEpochTail => LogFaults::just(planted(Damage::OtherEpochRecord)),
    };
    if let Some(at) = mid_crash_at {
        faults = faults.with(LogFault::CrashAt(at));
    }
    let scheduled = Scheduled {
        sync_fail: fail_sync_at,
        crashes: mid_crash_at.into_iter().collect(),
    };
    let first = execute_variant(seed, &plan, faults.clone(), scheduled.clone(), mutation)?;
    let second_crash_at = match (plan.second_crash, first.window) {
        (Some(raw), Some((start, end))) if end > start => {
            let span = end - start;
            let offset = raw % span;
            // A second crash before the failed sync would displace it:
            // the recovery it cuts short is followed by another whose
            // steps are not the fault-free script's.
            [start + offset, start + (offset + 1) % span]
                .into_iter()
                .find(|at| fail_sync_at.is_none_or(|failed| *at > failed))
        }
        _ => None,
    };
    let sim = match second_crash_at {
        Some(at) => {
            let mut scheduled = scheduled;
            scheduled.crashes.push(at);
            execute_variant(
                seed,
                &plan,
                faults.with(LogFault::CrashAt(at)),
                scheduled,
                mutation,
            )?
            .sim
        }
        None => first.sim,
    };
    Ok(LogRun {
        sim,
        plan,
        steps,
        fail_sync_at,
        mid_crash_at,
        second_crash_at,
    })
}

// ------------------------------------------------------------ trace queries

/// Every decision-log entry of `trace`, in order.
fn log_ops(trace: &Trace) -> impl Iterator<Item = (&LogOp, Outcome)> {
    trace.entries().iter().filter_map(|e| match &e.op {
        Op::Log(op) => Some((op, e.outcome)),
        _ => None,
    })
}

/// The steps of the decision-log fake in `trace`, in the order they were
/// taken: position is the step index a fault names.
#[must_use]
pub fn log_steps(trace: &Trace) -> Vec<(LogOp, Outcome)> {
    log_ops(trace)
        .filter(|(op, _)| {
            matches!(
                op,
                LogOp::Write { .. }
                    | LogOp::FileSync { .. }
                    | LogOp::DirSync { .. }
                    | LogOp::Create { .. }
                    | LogOp::Mkdir { .. }
                    | LogOp::Link { .. }
                    | LogOp::Unlink { .. }
                    | LogOp::Rename { .. }
                    | LogOp::Truncate { .. }
                    | LogOp::Read { .. }
            )
        })
        .map(|(op, outcome)| (op.clone(), outcome))
        .collect()
}

/// The row of every unacknowledged append the FIRST host crash drew: the
/// entries between the first and the second `log-crash`.
#[must_use]
pub fn first_crash_rows(trace: &Trace) -> Vec<DrawRow> {
    let mut crashes = 0;
    let mut rows = Vec::new();
    for (op, _) in log_ops(trace) {
        match op {
            LogOp::Crash { .. } => crashes += 1,
            LogOp::Row { row, .. } if crashes == 1 => rows.push(*row),
            _ => {}
        }
    }
    rows
}

/// Whether the first process was cut by a host crash before the first
/// `log-crash`: a step refused as injected precedes it. A failed sync is
/// recorded as a sync failure, never as an injected step, so this is a
/// crash and nothing else.
#[must_use]
pub fn cut_by_a_crash(trace: &Trace) -> bool {
    for (op, outcome) in log_ops(trace) {
        match op {
            LogOp::Crash { .. } => return false,
            LogOp::Call { .. } => {}
            _ if outcome == Outcome::Failed(TraceError::Injected) => return true,
            _ => {}
        }
    }
    false
}

/// The row of every unacknowledged append a host crash drew, in order.
#[must_use]
pub fn log_rows(trace: &Trace) -> Vec<DrawRow> {
    log_ops(trace)
        .filter_map(|(op, _)| match op {
            LogOp::Row { row, .. } => Some(*row),
            _ => None,
        })
        .collect()
}

/// Every recovery verdict of `trace`, in order.
#[must_use]
pub fn log_verdicts(trace: &Trace) -> Vec<Verdict> {
    log_ops(trace)
        .filter_map(|(op, _)| match op {
            LogOp::Verdict { verdict, .. } => Some(*verdict),
            _ => None,
        })
        .collect()
}

/// How many host crashes `trace` records.
#[must_use]
pub fn host_crashes(trace: &Trace) -> usize {
    log_ops(trace)
        .filter(|(op, _)| matches!(op, LogOp::Crash { .. }))
        .count()
}

/// How many syncs of `trace` failed: the fault [`LogFault::FailSync`]
/// injects on a sync step.
#[must_use]
pub fn failed_syncs(trace: &Trace) -> usize {
    log_ops(trace)
        .filter(|(op, outcome)| {
            matches!(op, LogOp::FileSync { .. } | LogOp::DirSync { .. })
                && *outcome == Outcome::Failed(TraceError::SyncFailed)
        })
        .count()
}

/// How many steps of `trace` were refused by a crash: a
/// [`LogFault::CrashAt`] and the dead process's steps after it. A failed
/// sync is recorded differently, as [`TraceError::SyncFailed`].
#[must_use]
pub fn injected_steps(trace: &Trace) -> usize {
    log_ops(trace)
        .filter(|(op, outcome)| {
            !matches!(op, LogOp::Call { .. }) && *outcome == Outcome::Failed(TraceError::Injected)
        })
        .count()
}

/// Every media fault of `trace` that fired, in order.
#[must_use]
pub fn log_damage(trace: &Trace) -> Vec<Damage> {
    log_ops(trace)
        .filter_map(|(op, outcome)| match op {
            LogOp::Damage { damage, .. } if outcome == Outcome::Ok => Some(*damage),
            _ => None,
        })
        .collect()
}

/// What each host crash of `trace` did to an unsynced truncation.
#[must_use]
pub fn truncation_draws(trace: &Trace) -> Vec<TruncationDraw> {
    log_ops(trace)
        .filter_map(|(op, _)| match op {
            LogOp::Draw { truncation, .. } => Some(*truncation),
            _ => None,
        })
        .collect()
}

/// How many `resync` calls of `trace` returned: an adopted survivor made
/// durable again.
#[must_use]
pub fn resyncs(trace: &Trace) -> usize {
    log_ops(trace)
        .filter(|(op, outcome)| {
            matches!(
                op,
                LogOp::Call {
                    call: crate::trace::LogCall::Resync,
                    ..
                }
            ) && *outcome == Outcome::Ok
        })
        .count()
}

/// Whether the plan's fault fired in `trace`, measured from the trace
/// and counting only the fault's own entries: a
/// [`LogFaultKind::FailSync`] as a sync that returned a failure (a crash
/// is recorded as an injected step, which does not count), a media fault
/// as a damage entry of its own kind that flipped bytes, and
/// [`LogFaultKind::None`] always.
#[must_use]
pub fn fault_fired(kind: LogFaultKind, trace: &Trace) -> bool {
    let damaged = |wanted: &[Damage]| log_damage(trace).iter().any(|d| wanted.contains(d));
    match kind {
        LogFaultKind::None => true,
        LogFaultKind::FailSync => failed_syncs(trace) > 0,
        LogFaultKind::CorruptDetectable => damaged(&[Damage::Detectable]),
        LogFaultKind::ResidualLoss => damaged(&[Damage::Residual, Damage::ResidualIntoRecord]),
        LogFaultKind::OversizeTail => damaged(&[Damage::Oversize]),
        LogFaultKind::AtBoundTail => damaged(&[Damage::AtBound]),
        LogFaultKind::ForeignTail => damaged(&[Damage::ForeignRecord]),
        LogFaultKind::WrongSeqTail => damaged(&[Damage::WrongSeqRecord]),
        LogFaultKind::OtherEpochTail => damaged(&[Damage::OtherEpochRecord]),
    }
}

/// Whether step `at` of `trace` is a sync that failed: the failed sync
/// landed on the step the fault-free script names.
#[must_use]
pub fn failed_sync_at(trace: &Trace, at: u32) -> bool {
    usize::try_from(at)
        .ok()
        .and_then(|index| log_steps(trace).into_iter().nth(index))
        .is_some_and(|(op, outcome)| {
            matches!(op, LogOp::FileSync { .. } | LogOp::DirSync { .. })
                && outcome == Outcome::Failed(TraceError::SyncFailed)
        })
}

#[cfg(test)]
mod tests;
