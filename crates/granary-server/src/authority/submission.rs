// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A submission, its answers, and admission rules 1 to 5.
//!
//! Rules 1 to 5 read only the volume's state and the candidate's own
//! bytes, and write nothing. [`rules_1_to_4`] and [`rule_5`] are pure;
//! the worker runs them after its epoch guard, in order, and reaches rules
//! 6 to 8 (a head resolution, then a record) only when none answered. A rule 3
//! answer for a landed or lost candidate also carries the current verified
//! head, which needs a store read: [`Early::Recorded`] carries everything
//! else, and [`RecordedOutcome::answer`] finishes it once the head is
//! resolved.

use std::time::Duration;

use granary_core::authlog::{Epoch, Operation, Principal, RootBytes, SubmissionIdentity, Tenant};
use granary_core::hash::GrainId;
use granary_core::root::{RootIdentityError, VolumeName, decode_root};
use granary_core::sheaf::{NANOS_PER_SEC, Timestamp};
use granary_store::crypto::{HeadError, TrustedKeys, check_signatures};

use super::chain::VerifiedHead;
use super::state::{OpenEntry, Outcome, VolumeState, operation_key};
use granary_core::authority_answer::LAST_CANDIDATE_SEQ;

/// A candidate submitted for publication (spec §3), under a principal the
/// caller has already authenticated: the engine never builds one from
/// untrusted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    tenant: Tenant,
    principal: Principal,
    volume: VolumeName,
    epoch: Epoch,
    operation: Operation,
    candidate: Vec<u8>,
}

impl Submission {
    /// A submission of `candidate`, the exact bytes of a client-signed
    /// root, to `volume` under `operation`, built against `epoch`.
    #[must_use]
    pub const fn new(
        tenant: Tenant,
        principal: Principal,
        volume: VolumeName,
        epoch: Epoch,
        operation: Operation,
        candidate: Vec<u8>,
    ) -> Self {
        Self {
            tenant,
            principal,
            volume,
            epoch,
            operation,
            candidate,
        }
    }

    /// The volume it is submitted to.
    #[must_use]
    pub const fn volume(&self) -> &VolumeName {
        &self.volume
    }

    /// The log epoch the submission was built against.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The candidate's exact bytes.
    #[must_use]
    pub fn candidate(&self) -> &[u8] {
        &self.candidate
    }

    /// Observe the exact publication at the instrumented dispatch boundary.
    #[cfg(feature = "crash-points")]
    pub(crate) fn observe_dispatch(&self) {
        super::crash::observe_post(
            self.volume.as_str(),
            self.epoch,
            self.operation.as_bytes(),
            &self.candidate,
        );
    }

    /// The submission identity: the operation plus the candidate id.
    fn identity(&self) -> SubmissionIdentity {
        SubmissionIdentity::new(
            self.tenant.clone(),
            self.principal.clone(),
            self.operation.clone(),
            GrainId::of(&self.candidate),
        )
    }
}

/// A decision's place in the volume's one order: the log's epoch and the
/// entry sequence (spec §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    /// The epoch of the log the decision is in.
    pub epoch: Epoch,
    /// The entry sequence within it.
    pub seq: u64,
}

/// A landed candidate's receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    /// The decision's position.
    pub position: Position,
    /// The seq the candidate is published at.
    pub seq: u64,
    /// The id of the bytes stored there: for an unprofiled volume, the
    /// candidate id.
    pub stored_id: GrainId,
}

/// Why a candidate is not well formed for the volume (spec §3 rule 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidCandidate {
    /// It fails the publisher check: strict decoding, the volume it names,
    /// or the signature under the volume's configured keys.
    Root(HeadError),
    /// Its seq is 0, or one whose successor could not be published.
    SeqOutOfRange {
        /// The seq it carries.
        seq: u64,
    },
    /// It is longer than any root the log can hold.
    TooLong,
}

/// What an operation's binding holds when it refuses a different
/// candidate (spec §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// The operation's accepted candidate is open.
    Open {
        /// The open decision's position.
        position: Position,
        /// The open candidate's id.
        candidate_id: GrainId,
    },
    /// The operation's accepted candidate landed.
    Landed(Receipt),
}

/// The engine's answer to a submission (spec §3, in rule order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Rule 0: the submission names another log epoch. Nothing is written.
    EpochMismatch {
        /// The current log's epoch.
        epoch: Epoch,
        /// The current verified head, read for this answer; `None` when
        /// the read or verification fails.
        head: Option<VerifiedHead>,
    },
    /// Rule 1: the volume has no log. Not a decision.
    NoLog,
    /// Rule 2: the candidate is not well formed. Not a decision.
    InvalidCandidate(InvalidCandidate),
    /// Rule 3: this candidate was accepted, and its publication is open.
    Open {
        /// The decision's position.
        position: Position,
        /// The candidate id.
        candidate_id: GrainId,
    },
    /// Rule 3: this candidate landed.
    Landed {
        /// The receipt.
        receipt: Receipt,
        /// The current verified head, read for this answer; `None` when
        /// it does not verify.
        head: Option<VerifiedHead>,
    },
    /// Rule 3: this candidate lost to another valid root.
    Lost {
        /// The decision's position.
        position: Position,
        /// The candidate id.
        candidate_id: GrainId,
        /// The stored id of the root that took the seq.
        occupant: GrainId,
        /// The current verified head, read for this answer; `None` when
        /// it does not verify.
        head: Option<VerifiedHead>,
    },
    /// Rule 7: refused by the authority, because the candidate does not
    /// extend the verified head. Not a decision: it has no position and
    /// nothing is written, and the same candidate is judged afresh
    /// against the head each time it is submitted, so one that arrived
    /// ahead of the head is accepted once its parent lands.
    StaleBase {
        /// The verified head the candidate was judged against.
        head: VerifiedHead,
    },
    /// Rule 4 (a landed binding) or rule 5 (this operation's entry is
    /// open): refused, because the operation is bound.
    OperationBound(Bound),
    /// Rule 5: another operation's entry is open, so nothing is decided.
    NotDecided {
        /// The open decision's position.
        position: Position,
        /// The open candidate's id.
        candidate_id: GrainId,
    },
    /// Rule 6: the chain head does not verify. Nothing is written.
    VolumeDamaged,
    /// Rule 6 or 8 could not establish evidence within the admission limits.
    Validation(super::content::ValidationError),
    /// Rule 9: accepted. The decision record is durable; the candidate's
    /// outcome is learned by submitting it again (rule 3).
    Accepted {
        /// The decision's position.
        position: Position,
        /// The candidate id.
        candidate_id: GrainId,
    },
    /// The engine does not serve the volume.
    UnconfiguredVolume,
    /// The engine is fenced.
    Fenced,
    /// The engine is stopping or has stopped.
    Stopped,
}

/// A candidate rules 1 to 4 passed, as rules 5 to 9 need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WellFormed {
    pub(crate) identity: SubmissionIdentity,
    pub(crate) seq: u64,
    pub(crate) parent: Option<GrainId>,
    pub(crate) candidate: RootBytes,
    pub(super) references: super::content::RootReferences,
}

/// A rule 3 answer for a landed or lost candidate, awaiting the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordedOutcome {
    Landed(Receipt),
    Lost {
        position: Position,
        candidate_id: GrainId,
        occupant: GrainId,
    },
}

impl RecordedOutcome {
    /// The answer, carrying `head` as the current verified head.
    pub(crate) const fn answer(self, head: Option<VerifiedHead>) -> Answer {
        match self {
            Self::Landed(receipt) => Answer::Landed { receipt, head },
            Self::Lost {
                position,
                candidate_id,
                occupant,
            } => Answer::Lost {
                position,
                candidate_id,
                occupant,
                head,
            },
        }
    }
}

/// What rules 1 to 4 decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Early {
    /// A rule answered.
    Answer(Answer),
    /// Rule 3 answered with a landed or lost outcome, which carries the
    /// current head.
    Recorded(RecordedOutcome),
    /// No rule answered: rules 5 to 9 decide.
    Eligible(WellFormed),
}

/// Rule 2: whether `candidate` is well formed for `volume` under `keys`.
///
/// # Errors
/// [`InvalidCandidate`].
fn well_formed(
    submission: &Submission,
    keys: &TrustedKeys,
) -> Result<WellFormed, InvalidCandidate> {
    #[cfg(test)]
    let _validation = tracing::trace_span!("authority_validation").entered();
    let bytes = submission.candidate();
    // The head check's rules with the seq taken from the bytes: decoded
    // once, strictly, then the volume, then the signature.
    let identity = |e| InvalidCandidate::Root(HeadError::Identity(e));
    let doc = decode_root(bytes).map_err(|e| identity(RootIdentityError::Decode(e)))?;
    if doc.volume != submission.volume {
        return Err(identity(RootIdentityError::VolumeMismatch {
            expected: submission.volume.as_str().to_owned(),
            found: doc.volume.as_str().to_owned(),
        }));
    }
    check_signatures(&doc, bytes, keys).map_err(InvalidCandidate::Root)?;
    if !(1..=LAST_CANDIDATE_SEQ).contains(&doc.seq) {
        return Err(InvalidCandidate::SeqOutOfRange { seq: doc.seq });
    }
    let candidate = RootBytes::new(bytes.to_vec()).map_err(|_| InvalidCandidate::TooLong)?;
    Ok(WellFormed {
        references: (&doc).into(),
        identity: submission.identity(),
        seq: doc.seq,
        parent: doc.parent,
        candidate,
    })
}

/// The position `seq` takes in `state`'s log.
fn position(state: &VolumeState, seq: u64) -> Position {
    Position {
        epoch: state.envelope().epoch(),
        seq,
    }
}

/// Spec §3 rules 1 to 4, in order, for `submission` against the volume's
/// `state` (`None` while it has no log). Rule 5 is [`rule_5`].
pub(crate) fn rules_1_to_4(
    state: Option<&VolumeState>,
    keys: &TrustedKeys,
    submission: &Submission,
) -> Early {
    let Some(state) = state else {
        return Early::Answer(Answer::NoLog);
    };
    let candidate = match well_formed(submission, keys) {
        Ok(candidate) => candidate,
        Err(invalid) => return Early::Answer(Answer::InvalidCandidate(invalid)),
    };
    let candidate_id = candidate.identity.candidate_id();
    if let Some(recorded) = state.recorded(&candidate.identity) {
        let position = position(state, recorded.seq);
        return match recorded.outcome {
            Outcome::Open => Early::Answer(Answer::Open {
                position,
                candidate_id,
            }),
            Outcome::Landed => Early::Recorded(RecordedOutcome::Landed(Receipt {
                position,
                seq: recorded.root_seq,
                stored_id: candidate_id,
            })),
            Outcome::Lost { occupant } => Early::Recorded(RecordedOutcome::Lost {
                position,
                candidate_id,
                occupant,
            }),
        };
    }
    if let Some(binding) = state.binding(&candidate.identity)
        && binding.outcome == Outcome::Landed
    {
        return Early::Answer(Answer::OperationBound(Bound::Landed(Receipt {
            position: position(state, binding.seq),
            seq: binding.root_seq,
            stored_id: binding.candidate_id,
        })));
    }
    Early::Eligible(candidate)
}

/// Spec §3 rule 5, which always answers while `entry` is open:
/// operation bound if it is this operation's, otherwise not decided.
pub(crate) fn rule_5(state: &VolumeState, entry: &OpenEntry, candidate: &WellFormed) -> Answer {
    let position = position(state, entry.seq);
    let candidate_id = entry.identity.candidate_id();
    if operation_key(&entry.identity) == operation_key(&candidate.identity) {
        Answer::OperationBound(Bound::Open {
            position,
            candidate_id,
        })
    } else {
        Answer::NotDecided {
            position,
            candidate_id,
        }
    }
}

/// The answer a decision recorded at position `seq` of `epoch` gives
/// (rule 9).
pub(crate) const fn accepted(epoch: Epoch, seq: u64, candidate_id: GrainId) -> Answer {
    Answer::Accepted {
        position: Position { epoch, seq },
        candidate_id,
    }
}

/// The age spec §7 defines: a report at `now` of a decision recorded at
/// `decided_at`, or unknown when `now` reads earlier than `decided_at`
/// (the clock was stepped back, for example across a restart) or `now`
/// is not a valid reading (its nanoseconds past a second). A recorded
/// reading is always valid, since the log's codec refuses one that is
/// not; it is checked all the same, so no reading can make the
/// subtraction below underflow. `now` equal to `decided_at` is age
/// zero. The seconds are subtracted in `i128`, where
/// no two readings overflow, so a known age is always the exact
/// difference, never a wrapped or saturated one.
fn age(now: Timestamp, decided_at: Timestamp) -> Option<Duration> {
    if !now.is_valid() || !decided_at.is_valid() || now < decided_at {
        return None;
    }
    let mut secs = i128::from(now.secs) - i128::from(decided_at.secs);
    let nanos = if now.nanos >= decided_at.nanos {
        now.nanos - decided_at.nanos
    } else {
        secs -= 1;
        NANOS_PER_SEC - decided_at.nanos + now.nanos
    };
    Some(Duration::new(u64::try_from(secs).ok()?, nanos))
}

/// The flag spec §7 assigns for `age` against the report's `bound`: an
/// unknown age is always **clock behind**; a known age strictly greater
/// than `bound` is **past its bound**; anything else carries no flag
/// (an age at or under the bound is not flagged, so `age == bound`
/// never is).
fn flag(age: Option<Duration>, bound: Duration) -> Option<StuckFlag> {
    match age {
        None => Some(StuckFlag::ClockBehind),
        Some(age) if age > bound => Some(StuckFlag::PastBound),
        Some(_) => None,
    }
}

/// The report row for the open `entry` of `volume`, whose state is
/// `state`, judged at the engine's clock reading `now` against the
/// report's `bound` (spec §7). Called at the moment the report answers,
/// never from a snapshot taken when a publication round began, so a
/// round spanning a long re-issue backoff reports each request's own
/// age.
pub(crate) fn row(
    volume: &VolumeName,
    state: &VolumeState,
    entry: &OpenEntry,
    stuck: StuckState,
    reissues: u64,
    now: Timestamp,
    bound: Duration,
) -> OpenEntryRow {
    let age = age(now, entry.decided_at);
    OpenEntryRow {
        volume: volume.clone(),
        state: stuck,
        candidate_id: entry.identity.candidate_id(),
        position: position(state, entry.seq),
        reissues,
        age,
        flag: flag(age, bound),
    }
}

/// The report's data for one open entry (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenEntryRow {
    /// The volume.
    pub volume: VolumeName,
    /// Whether its last classification read found it wedged or
    /// unresolved.
    pub state: StuckState,
    /// The candidate id.
    pub candidate_id: GrainId,
    /// The decision's position.
    pub position: Position,
    /// How many times this run has re-issued the entry's PUT.
    pub reissues: u64,
    /// The engine's clock when this row was taken (when its volume
    /// answered the request), minus the clock reading the decision
    /// recorded (spec §7); a restart does not reset it. `None`, unknown,
    /// when the clock read earlier than the recorded reading or gave no
    /// valid reading.
    pub age: Option<Duration>,
    /// None, **past its bound**, or **clock behind** (spec §7); never
    /// set for a known age at or under the bound, and an entry the
    /// report does not flag is never reported as young.
    pub flag: Option<StuckFlag>,
}

/// Where an open entry stands, as its last classification read found it.
/// An entry this run has not classified yet is unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckState {
    /// Nothing at the seq, or a read failed.
    Unresolved,
    /// Something other than a valid root extending the base is there.
    Wedged,
}

/// Why an open entry's report row is flagged (spec §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckFlag {
    /// The age is strictly greater than the report's bound.
    PastBound,
    /// The age is unknown: the engine's clock read earlier than the
    /// decision's recorded reading, or gave no valid reading.
    ClockBehind,
}

#[cfg(test)]
mod tests;
