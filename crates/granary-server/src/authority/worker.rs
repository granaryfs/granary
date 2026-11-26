// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One volume's worker: the only caller of the log for its volume.
//!
//! A worker owns its volume's state, so the seam's "one writer, no
//! concurrent calls per volume" holds by construction: a worker has at
//! most one log call in flight and never races one against anything.
//! Its first step, before it takes any request, is the attestation an
//! open entry is owed (spec §6.4), so that attestation precedes anything
//! else the worker does for the entry, a PUT above all.
//!
//! **No entry open.** The worker takes one request at a time, in arrival
//! order, and runs it to its end: a submission runs spec §3's rules 0 to
//! 9, its head resolution and its record included, before the next is
//! taken. So of two eligible candidates exactly one reaches a decision,
//! and the other then meets rule 5.
//!
//! **An entry open.** The worker publishes it (spec §4): a step (the PUT
//! and one classification read, the `publication` module), then the
//! outcome record when the read closes the entry, or a pause before the
//! next step. While a step or a pause is pending the worker answers
//! requests beside it ([`race`]): with an entry open spec §3's rules 0 to
//! 5 always answer, and none of them writes, so answering never needs a
//! log call. A step is never dropped once begun; a pause is dropped by a
//! stop. No decision is made while the entry is open, because rules 6 to 9
//! are reached only on the no-entry path.
//!
//! **Only an appended record moves the state.** Rule 9's decision, the
//! attestation, landed and lost are each applied only after their append
//! returned `Ok`, and every answer that reports one is built after that.
//! Rules 0 to 8 write no log records; completed head resolutions update
//! only the observation and the head verification memo. Every answer is sent
//! with the fence read immediately before, and no await between.
//!
//! Between requests the worker waits on [`Next`], which also ends the
//! wait when the engine is fenced or asked to stop. A request already
//! taken runs to its end, and no log call or PUT is ever dropped by a
//! stop. A stop seen while a publication step runs lets the step finish
//! and records nothing of it; a step that finished first has its outcome
//! recorded (the engine's module docs, "The stop").

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use granary_core::authlog::{Record, RecordBody, encode_append, encode_envelope};
use granary_core::clock::Clock;
use granary_core::decisionlog::DecisionLog;
use granary_core::rng::Rng;
use granary_core::root::VolumeName;
use granary_core::rootstore::RootStore;
use granary_core::secure_random::SecureRandom;
use granary_store::crypto::TrustedKeys;
use tokio::sync::{mpsc, oneshot};

use super::Pause;
use super::chain::{
    ChainMemo, Classification, HeadRef, Unverified, VerifiedHead, resolve_head,
    resolve_head_for_admission,
};
use super::content::ValidationAttempt;
use super::content::ValidationError::Unavailable;
use super::content::store::Admission;
use super::content::{PendingProof, ValidationCandidate, ValidationError, intake};
use super::gate::{Fence, FenceCause, LogCall, LogGate, RecordRefusal};
use super::join::{Raced, race};
use super::observation::VolumeSlot;
use super::publication::{Publishing, Step, reissue_delay, step};
use super::ready::Readiness;
use super::state::{OpenEntry, VolumeState};
use super::submission::{
    Answer, Early, OpenEntryRow, StuckState, Submission, WellFormed, accepted, row, rule_5,
    rules_1_to_4,
};
use super::{InitialiseError, Initialised, Shared};

/// A request a handle sends a worker.
#[derive(Debug)]
pub(crate) enum Request {
    Intent {
        work: super::intent_worker::Work,
        context: tracing::Span,
        reply: oneshot::Sender<super::intent_worker::ResultValue>,
    },
    /// Initialise the worker's volume's log.
    Initialise {
        reply: oneshot::Sender<Result<Initialised, InitialiseError>>,
    },
    /// Answer a submission to the worker's volume.
    Submit {
        submission: Box<Submission>,
        reply: oneshot::Sender<Answer>,
        #[cfg(test)]
        queue: tracing::Span,
    },
    /// Report the volume's open entry, if one is open, judged against
    /// `bound` (spec §7).
    Report {
        /// The report's bound: an open entry's row is flagged **past its
        /// bound** when its age is strictly greater than this.
        bound: Duration,
        reply: oneshot::Sender<Option<OpenEntryRow>>,
    },
}

/// What every worker borrows from the driver for the run.
#[derive(Debug)]
pub(crate) struct Engine<'a, L, S, C, R, E, P> {
    pub(crate) log: &'a L,
    pub(crate) store: &'a S,
    pub(crate) clock: &'a C,
    pub(crate) rng: &'a Mutex<R>,
    pub(crate) secure_random: &'a Mutex<E>,
    pub(crate) pause: &'a P,
    pub(crate) gate: &'a LogGate,
    pub(crate) shared: &'a Shared,
}

/// Why a live record was not committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommitError {
    /// The record was refused before anything was written.
    Refused(RecordRefusal),
    /// The engine is fenced: before this append, by its failure, or by
    /// the state refusing the record once it was appended.
    Fenced(Fence),
}

#[derive(Debug, Default)]
enum Intake {
    #[default]
    Idle,
    Requested,
    Running,
    Damaged(HeadRef),
    LengthLimit(HeadRef),
}

/// One volume's worker (module docs).
#[derive(Debug)]
pub(crate) struct Worker {
    pub(super) intents: super::intent_worker::Intents,
    volume: VolumeName,
    /// The volume's publisher keys: a valid root is signed under them.
    keys: TrustedKeys,
    memo: ChainMemo,
    intake: Intake,
    intake_handoff: Option<intake::Handoff>,
    pending_proof: Option<PendingProof>,
    /// `None` while the volume has no log.
    state: Option<VolumeState>,
    pub(super) view: Arc<VolumeSlot>,
    inbox: mpsc::Receiver<Request>,
    /// This run's memory of the open entry's publication, for the report.
    tracking: Option<Tracking>,
}

impl Worker {
    /// This volume's `STATE` lines (the driver's `recovered`).
    #[cfg(all(test, feature = "crash-points"))]
    pub(crate) fn crash_lines(&self) -> Vec<String> {
        match &self.state {
            Some(state) => state.crash_lines(),
            None => vec![format!("STATE {} nolog", self.volume.as_str())],
        }
    }
}

/// What a run knows of the open entry's publication beyond its records:
/// kept in memory only, and begun afresh by each run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tracking {
    /// The open entry's position.
    seq: u64,
    /// How many PUTs this run has issued for it.
    issues: u64,
    /// What its last classification read found.
    stuck: StuckState,
}

impl Tracking {
    /// How many of the PUTs were re-issues.
    const fn reissues(self) -> u64 {
        self.issues.saturating_sub(1)
    }
}

/// Whether a worker carries on after a publication round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    End,
}

/// What ends a worker's wait.
enum Event {
    Request(Request),
    Stop,
    Fenced,
    /// Every handle is gone: nothing can send another request.
    Closed,
}

/// A worker's wait for its next request (module docs). Registers the
/// task's waker with the stop signal before it reads the flags, so a stop
/// raised after the read still wakes it.
struct Next<'a> {
    inbox: &'a mut mpsc::Receiver<Request>,
    shared: &'a Shared,
}

impl Future for Next<'_> {
    type Output = Event;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Event> {
        let this = self.get_mut();
        this.shared.stop.register(cx.waker());
        if this.shared.fence.is_set() {
            return Poll::Ready(Event::Fenced);
        }
        if this.shared.stop.requested() {
            return Poll::Ready(Event::Stop);
        }
        match this.inbox.poll_recv(cx) {
            Poll::Ready(Some(request)) => Poll::Ready(Event::Request(request)),
            Poll::Ready(None) => Poll::Ready(Event::Closed),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Send `answer` for `volume` unless the engine is fenced, and `Fenced`
/// if it is: the fence is read immediately before the send, with no
/// await between, so no answer computed before a fence is delivered after
/// it. A caller that dropped its future dropped only this reply.
fn send_answer(
    shared: &Shared,
    #[cfg_attr(
        not(any(test, feature = "crash-points")),
        expect(unused_variables, reason = "a test observes the volume")
    )]
    volume: &VolumeName,
    reply: oneshot::Sender<Answer>,
    answer: Answer,
) {
    #[cfg(feature = "crash-points")]
    if matches!(answer, Answer::Accepted { .. }) {
        super::crash::hold_reply();
    }
    let answer = if shared.fence.is_set() {
        Answer::Fenced
    } else {
        answer
    };
    #[cfg(test)]
    shared.replies.answer(volume, &answer);
    crash_point!(ReplySent, format!("REPLY {} {answer:?}", volume.as_str()));
    let _ = reply.send(answer);
}

/// Spec §3's rules 0 to 5, in order, for `submission` against the
/// volume's `state` (`None` while it has no log): the answer when one of
/// them answers, which always happens while an entry is open, and the
/// well-formed candidate otherwise. A rule 3 answer for a landed or lost
/// candidate, and a rule 0 mismatch, carry the current verified head,
/// read from `store`.
///
/// # Errors
/// The candidate, when no entry is open and none of rules 0 to 5
/// answered: rules 6 to 9 decide it.
async fn rules_0_to_5<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    keys: &TrustedKeys,
    state: Option<&VolumeState>,
    submission: &Submission,
    view: &VolumeSlot,
    memo: &mut ChainMemo,
) -> Result<Answer, WellFormed> {
    if let Some(state) = state {
        let epoch = state.envelope().epoch();
        if submission.epoch() != epoch {
            let head = resolve_head(store, volume, keys, memo).await.ok();
            view.verified(Some(state), head);
            return Ok(Answer::EpochMismatch { epoch, head });
        }
    }
    let candidate = match rules_1_to_4(state, keys, submission) {
        Early::Answer(answer) => return Ok(answer),
        Early::Recorded(outcome) => {
            let head = resolve_head(store, volume, keys, memo).await.ok();
            view.verified(state, head);
            return Ok(outcome.answer(head));
        }
        Early::Eligible(candidate) => candidate,
    };
    match state.and_then(|state| state.open().map(|entry| (state, entry))) {
        Some((state, entry)) => Ok(rule_5(state, entry, &candidate)),
        None => Err(candidate),
    }
}

impl Worker {
    pub(crate) fn new(
        volume: VolumeName,
        keys: TrustedKeys,
        state: Option<VolumeState>,
        inbox: mpsc::Receiver<Request>,
    ) -> Self {
        let view = Arc::new(VolumeSlot::new(state.as_ref()));
        Self {
            intents: super::intent_worker::Intents::load(None, &volume, &keys),
            volume,
            keys,
            memo: ChainMemo::default(),
            intake: Intake::Idle,
            intake_handoff: None,
            pending_proof: None,
            state,
            view,
            inbox,
            tracking: None,
        }
    }

    /// The volume's state; `None` while it has no log.
    #[cfg(test)]
    pub(crate) const fn state(&self) -> Option<&VolumeState> {
        self.state.as_ref()
    }

    /// The volume's state, for a test to plant a fault in.
    #[cfg(test)]
    pub(crate) const fn state_mut(&mut self) -> Option<&mut VolumeState> {
        self.state.as_mut()
    }

    /// The worker's whole life (module docs): an open entry's owed
    /// attestation first, then the open entry's publication or each
    /// request in turn, until the engine is fenced, asked to stop, or left
    /// with no handle.
    pub(crate) async fn run<L, S, C, R, E, P>(mut self, engine: &Engine<'_, L, S, C, R, E, P>)
    where
        L: DecisionLog,
        S: RootStore,
        C: Clock,
        R: Rng,
        E: SecureRandom,
        P: Pause,
    {
        let mut maintenance = None;
        let mut handoff_expiry = None;
        loop {
            if self.attest(engine).await.is_err() {
                return;
            }
            if engine.shared.fence.is_set() || engine.shared.stop.requested() {
                return;
            }
            if self.state.as_ref().and_then(VolumeState::open).is_some() {
                if self.publish(engine).await == Flow::End {
                    return;
                }
                continue;
            }
            if matches!(self.intake, Intake::Requested)
                && !self.has_intake_handoff()
                && let Some(runtime) = &engine.shared.admission
            {
                self.intake = Intake::Running;
                maintenance = Some(Box::pin(intake::run(
                    &runtime.config,
                    runtime.clock.clone(),
                    self.volume.clone(),
                    self.keys.clone(),
                )));
            }
            let next = Next {
                inbox: &mut self.inbox,
                shared: engine.shared,
            };
            let event = if let Some(job) = &mut maintenance {
                match race(job.as_mut(), pin!(next)).await {
                    Raced::First(outcome) => {
                        maintenance = None;
                        self.intake = Intake::Idle;
                        match outcome {
                            intake::Outcome::Verified(verified) => {
                                if let Some(runtime) = &engine.shared.admission {
                                    let (memo, handoff) = verified
                                        .promote(runtime.config.proofs(), runtime.clock.now());
                                    self.memo = memo;
                                    handoff_expiry = handoff
                                        .as_ref()
                                        .map(|handoff| Box::pin(handoff.expiration()));
                                    self.intake_handoff = handoff;
                                }
                            }
                            intake::Outcome::Damaged(head) => self.intake = Intake::Damaged(head),
                            intake::Outcome::LengthLimit(head) => {
                                self.intake = Intake::LengthLimit(head);
                            }
                            intake::Outcome::Retry => {}
                        }
                        continue;
                    }
                    Raced::Second(event) => event,
                }
            } else if let Some(expiry) = &mut handoff_expiry {
                match race(expiry.as_mut(), pin!(next)).await {
                    Raced::First(()) => {
                        handoff_expiry = None;
                        self.intake_handoff = None;
                        continue;
                    }
                    Raced::Second(event) => event,
                }
            } else {
                next.await
            };
            match event {
                Event::Request(request) => {
                    let mut serving = pin!(self.serve(engine, request));
                    if let Some(expiry) = &mut handoff_expiry {
                        if let Raced::First(()) = race(expiry.as_mut(), serving.as_mut()).await {
                            handoff_expiry = None;
                            serving.await;
                        }
                    } else {
                        serving.await;
                    }
                }
                Event::Stop | Event::Fenced | Event::Closed => return,
            }
            if !self.has_intake_handoff() {
                self.intake_handoff = None;
                handoff_expiry = None;
            }
        }
    }

    fn has_intake_handoff(&self) -> bool {
        self.intake_handoff
            .as_ref()
            .is_some_and(intake::Handoff::is_held)
    }

    /// Answer one request with no entry open, to its end.
    async fn serve<L, S, C, R, E, P>(
        &mut self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        request: Request,
    ) where
        L: DecisionLog,
        S: RootStore,
        C: Clock,
        R: Rng,
        E: SecureRandom,
        P: Pause,
    {
        match request {
            Request::Intent {
                work,
                context,
                reply,
            } => {
                use tracing::Instrument as _;
                #[cfg(feature = "crash-points")]
                let binding = intent_binding(&work);
                let epoch = self.state.as_ref().map(|s| s.envelope().epoch());
                let answer = self
                    .intents
                    .answer(engine, &self.volume, &self.keys, epoch, work)
                    .instrument(context)
                    .await;
                send_intent(
                    engine.shared,
                    reply,
                    answer,
                    #[cfg(feature = "crash-points")]
                    &binding,
                );
            }
            Request::Initialise { reply } => {
                let answer = self.initialise(engine).await;
                // The fence is read and the answer sent with no await
                // between them, so no answer computed before a fence is
                // delivered after it.
                let answer = if engine.shared.fence.is_set() {
                    Err(InitialiseError::Fenced)
                } else {
                    answer
                };
                #[cfg(test)]
                engine.shared.replies.initialised(&self.volume, &answer);
                crash_point!(
                    ReplySent,
                    format!("REPLY {} {answer:?}", self.volume.as_str())
                );
                // A caller that dropped its future dropped only this
                // reply: nothing it asked for is undone.
                let _ = reply.send(answer);
            }
            Request::Submit {
                submission,
                reply,
                #[cfg(test)]
                queue,
            } => {
                #[cfg(test)]
                drop(queue);
                let answer = self.admit(engine, &submission).await;
                send_answer(engine.shared, &self.volume, reply, answer);
            }
            Request::Report { reply, .. } => {
                if !engine.shared.fence.is_set() {
                    let _ = reply.send(None);
                }
            }
        }
    }

    /// Spec §3's rules 0 to 9, in order, for a submission taken with no
    /// entry open. Only rule 9's decision writes, and it is answered only
    /// after its append returned.
    pub(crate) async fn admit<L, S, C, R, E, P>(
        &mut self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        submission: &Submission,
    ) -> Answer
    where
        L: DecisionLog,
        S: RootStore,
        C: Clock,
    {
        let state = self.state.as_ref();
        let candidate = match rules_0_to_5(
            engine.store,
            &self.volume,
            &self.keys,
            state,
            submission,
            &self.view,
            &mut self.memo,
        )
        .await
        {
            Ok(answer) => return answer,
            Err(candidate) => candidate,
        };
        let Some(state) = state else {
            return Answer::NoLog;
        };
        let epoch = state.envelope().epoch();
        let next_seq = state.next_seq();
        if matches!(self.intake, Intake::Running)
            || (matches!(self.intake, Intake::Requested) && !self.has_intake_handoff())
        {
            return Answer::Validation(Unavailable);
        }
        let mut admission = match &engine.shared.admission {
            Some(runtime) => match runtime.config.preflight(runtime.clock.clone()) {
                Ok(attempt) => attempt.map(|attempt| (&runtime.config, attempt)),
                Err(error) => return Answer::Validation(error),
            },
            #[cfg(test)]
            None => None,
            #[cfg(not(test))]
            None => return Answer::Validation(Unavailable),
        };
        let admission_reads = admission.as_mut().map(|(source, work)| (*source, work));
        let head = match self.admission_head(engine.store, admission_reads).await {
            Ok(head) => head,
            Err(answer) => return answer,
        };
        // Rule 7 writes nothing: the answer is a function of the
        // candidate and the head, derived afresh on every submission.
        if !head.extended_by(candidate.seq, candidate.parent) {
            return Answer::StaleBase { head };
        }
        if let Intake::LengthLimit(at) = self.intake {
            if head.head == Some(at) {
                return Answer::Validation(ValidationError::LengthLimit);
            }
            self.intake = Intake::Idle;
        }
        // Rule 8 queues only eligible submissions. The serial worker
        // holds at most one place in the FIFO and releases its slot before
        // rule 9 can take the engine-wide append token.
        let candidate_id = candidate.identity.candidate_id();
        #[cfg(feature = "crash-points")]
        let validated = admission.is_some();
        let proof = if let Some((source, attempt)) = admission {
            match self
                .validate_candidate(engine.store, source, attempt, head, &candidate)
                .await
            {
                Ok(proof) => {
                    crash_point!(ValidatedBeforeAppend);
                    proof
                }
                Err(answer) => return answer,
            }
        } else {
            None
        };
        // Past `u64::MAX` records, which no log can hold: answered as
        // damage, never a wrap.
        let Some(seq) = next_seq else {
            return Answer::VolumeDamaged;
        };
        let body = RecordBody::Decision {
            identity: candidate.identity,
            root_seq: candidate.seq,
            base: candidate.parent,
            decided_at: engine.clock.now(),
            candidate: candidate.candidate,
        };
        match self.commit_body(engine, seq, body).await {
            Ok(()) => {
                self.pending_proof = proof;
                #[cfg(feature = "crash-points")]
                if validated {
                    crash_point!(ValidatedDecisionCommitted);
                }
                accepted(epoch, seq, candidate_id)
            }
            Err(answer) => answer,
        }
    }

    async fn validate_candidate<S: RootStore>(
        &mut self,
        store: &S,
        source: &Admission,
        mut attempt: ValidationAttempt,
        head: VerifiedHead,
        candidate: &WellFormed,
    ) -> Result<Option<PendingProof>, Answer> {
        let queued = source
            .acquire(&mut attempt)
            .await
            .map_err(Answer::Validation)?;
        let head = if queued {
            // A different writer may have advanced the head during the wait.
            let head = self
                .admission_head(store, Some((source, &mut attempt)))
                .await?;
            if !head.extended_by(candidate.seq, candidate.parent) {
                return Err(Answer::StaleBase { head });
            }
            head
        } else {
            head
        };
        // The validation slot now covers the parent. Consume the handoff
        // only after resolving the eligible candidate's exact head.
        let handoff = self.intake_handoff.take();
        if handoff.is_some() {
            self.intake = Intake::Idle;
        }
        let baseline = if let Some(head) = head.head {
            let proof = source.proofs().get(&self.volume, head.head_id);
            let proof = match (proof, handoff) {
                (None, Some(handoff)) => handoff.claim(&self.volume, head.head_id, attempt.now()),
                (proof, _) => proof,
            };
            let Some(proof) = proof else {
                self.intake = Intake::Requested;
                return Err(Answer::Validation(Unavailable));
            };
            Some(proof)
        } else {
            None
        };
        let references = ValidationCandidate::new(
            self.volume.clone(),
            candidate.identity.candidate_id(),
            candidate.parent,
            candidate.references,
        );
        let proof = attempt
            .validate(source, references, baseline.as_deref())
            .await
            .map_err(Answer::Validation)?;
        // Transfer the proof before the validation permit is released.
        // The decision can still proceed when the pending budget has no room.
        Ok(source.proofs().retain_pending(proof))
    }

    async fn admission_head<S: RootStore>(
        &mut self,
        store: &S,
        mut admission: Option<(&Admission, &mut ValidationAttempt)>,
    ) -> Result<VerifiedHead, Answer> {
        if let Intake::Damaged(head) = self.intake
            && let Some((source, attempt)) = admission.as_mut()
        {
            match intake::current(source, attempt, &self.volume, head).await {
                Ok(true)
                | Err(ValidationError::InvalidReference | ValidationError::MissingReference) => {
                    self.intake = Intake::Requested;
                    return Err(Answer::VolumeDamaged);
                }
                Ok(false) => self.intake = Intake::Idle,
                Err(error) => return Err(Answer::Validation(error)),
            }
        }
        let proofs = admission.as_ref().map(|(source, _)| (*source).proofs());
        let resolved =
            resolve_head_for_admission(store, &self.volume, &self.keys, &mut self.memo, admission)
                .await;
        self.view.verified(self.state.as_ref(), resolved.ok());
        match resolved {
            Ok(head) => Ok(head),
            Err(Unverified::WorkLimit) => {
                if proofs.is_some() {
                    self.intake = Intake::Requested;
                }
                Err(Answer::Validation(ValidationError::WorkLimit))
            }
            Err(Unverified::Unavailable) => {
                if !self.has_intake_handoff()
                    && proofs.is_some_and(|proofs| !proofs.has_landed(&self.volume))
                {
                    self.intake = Intake::Requested;
                }
                Err(Answer::Validation(Unavailable))
            }
            Err(Unverified::Unread) => Err(Answer::Validation(Unavailable)),
            Err(Unverified::Invalid) => Err(Answer::VolumeDamaged),
        }
    }

    /// Commit a record the engine built, as [`Self::commit`]; a record
    /// refused before its append fences the engine
    /// ([`FenceCause::RecordRefused`]): it breaks an invariant the rules
    /// before it hold, so the engine does not serve past it.
    ///
    /// # Errors
    /// [`Answer::Fenced`], the answer every failure gives.
    async fn commit_body<L: DecisionLog, S, C, R, E, P>(
        &mut self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        seq: u64,
        body: RecordBody,
    ) -> Result<(), Answer> {
        let refusal = match Record::new(seq, body) {
            Err(e) => RecordRefusal::Unbuildable(e),
            Ok(record) => match self.commit(engine, &record).await {
                Ok(()) => return Ok(()),
                Err(CommitError::Fenced(_)) => return Err(Answer::Fenced),
                Err(CommitError::Refused(refusal)) => refusal,
            },
        };
        engine
            .gate
            .fence(
                &engine.shared.fence,
                Fence {
                    call: LogCall::Append,
                    volume: Some(self.volume.clone()),
                    cause: FenceCause::RecordRefused(refusal),
                },
            )
            .await;
        Err(Answer::Fenced)
    }

    /// One round of the open entry's publication (spec §4.3; module
    /// docs): a step, then the outcome record if the read closed the
    /// entry, or a pause. Requests are answered beside the step and the
    /// pause. Ends the worker when a stop, the fence or the last handle's
    /// drop arrives: after the step, which is never dropped, and at once
    /// during the pause.
    async fn publish<L, S, C, R, E, P>(&mut self, engine: &Engine<'_, L, S, C, R, E, P>) -> Flow
    where
        L: DecisionLog,
        S: RootStore,
        C: Clock,
        R: Rng,
        E: SecureRandom,
        P: Pause,
    {
        let Some(entry) = self.state.as_ref().and_then(VolumeState::open) else {
            return Flow::Continue;
        };
        let publishing = Publishing {
            root_seq: entry.root_seq,
            base: entry.base,
            final_bytes: entry.candidate.as_bytes().to_vec(),
        };
        let identity = entry.identity.clone();
        let entry_seq = entry.seq;
        let mut tracking = match self.tracking {
            Some(tracking) if tracking.seq == entry_seq => tracking,
            _ => Tracking {
                seq: entry_seq,
                issues: 0,
                stuck: StuckState::Unresolved,
            },
        };
        tracking.issues = tracking.issues.saturating_add(1);
        self.tracking = Some(tracking);

        let (stepped, ended) = {
            let Some(serving) = self.serving(engine, tracking) else {
                return Flow::Continue;
            };
            let fut = pin!(step(
                engine.store,
                &engine.shared.fence,
                serving.volume,
                serving.keys,
                &publishing,
            ));
            serving.serve_while(fut, true).await
        };
        // Any head resolution beside the step has finished and released
        // the memo. The wedge leaves the last verified status view intact.
        if matches!(stepped, Some(Step::Read(Classification::Wedged))) {
            self.memo.clear();
        }
        let classification = match stepped {
            Some(Step::Read(classification)) if !ended => classification,
            _ => return Flow::End,
        };
        let body = match classification {
            Classification::Landed => RecordBody::Landed { identity },
            Classification::Lost { occupant } => RecordBody::Lost {
                identity,
                occupant_id: occupant,
            },
            Classification::Wedged | Classification::Unresolved => {
                self.pending_proof = None;
                tracking.stuck = if classification == Classification::Wedged {
                    StuckState::Wedged
                } else {
                    StuckState::Unresolved
                };
                self.tracking = Some(tracking);
                let delay = {
                    let mut rng = engine.rng.lock().unwrap_or_else(PoisonError::into_inner);
                    reissue_delay(tracking.reissues(), &mut *rng)
                };
                let Some(serving) = self.serving(engine, tracking) else {
                    return Flow::Continue;
                };
                let fut = pin!(engine.pause.pause(delay));
                let (_, ended) = serving.serve_while(fut, false).await;
                return if ended { Flow::End } else { Flow::Continue };
            }
        };
        match self.commit_body(engine, entry_seq, body).await {
            Ok(()) => {
                let proof = self.pending_proof.take();
                if let Some(runtime) = &engine.shared.admission {
                    let proofs = runtime.config.proofs();
                    match (classification, proof) {
                        (Classification::Landed, Some(proof)) => proof.install(proofs),
                        _ => proofs.discard(&self.volume),
                    }
                }
                Flow::Continue
            }
            Err(_) => Flow::End,
        }
    }

    /// What answering beside a step or a pause borrows: the state with
    /// its open entry, and the inbox. `None` with no entry open.
    fn serving<'w, 'a, L, S, C, R, E, P>(
        &'w mut self,
        engine: &'w Engine<'a, L, S, C, R, E, P>,
        tracking: Tracking,
    ) -> Option<Serving<'w, 'a, L, S, C, R, E, P>> {
        let Self {
            volume,
            keys,
            memo,
            state,
            view,
            inbox,
            ..
        } = self;
        let state = state.as_ref()?;
        let entry = state.open()?;
        Some(Serving {
            intents: &self.intents,
            engine,
            volume,
            keys,
            memo,
            state,
            view,
            entry,
            tracking,
            inbox,
        })
    }

    /// Append the attestation the open entry is owed, if it is owed one
    /// (spec §6.4): built from the recorded decision, before any other
    /// action for the entry.
    ///
    /// Fail-closed: the worker serves nothing for an entry whose owed
    /// attestation is not committed, so any failure here fences the
    /// engine. A refusal ([`FenceCause::AttestationRefused`]) cannot
    /// happen for a state replay built: the record comes from the state
    /// that then checks it, and the codec's attestation rule (the stored
    /// id is the final bytes' id) holds by construction.
    ///
    /// # Errors
    /// The [`Fence`] the engine carries.
    pub(crate) async fn attest<L: DecisionLog, S, C, R, E, P>(
        &mut self,
        engine: &Engine<'_, L, S, C, R, E, P>,
    ) -> Result<(), Fence> {
        let refusal = match self.state.as_ref().map(VolumeState::owed_attestation) {
            None | Some(Ok(None)) => return Ok(()),
            Some(Err(e)) => RecordRefusal::Unbuildable(e),
            Some(Ok(Some(record))) => match self.commit(engine, &record).await {
                Ok(()) => return Ok(()),
                Err(CommitError::Fenced(fence)) => return Err(fence),
                Err(CommitError::Refused(refusal)) => refusal,
            },
        };
        Err(engine
            .gate
            .fence(
                &engine.shared.fence,
                Fence {
                    call: LogCall::Append,
                    volume: Some(self.volume.clone()),
                    cause: FenceCause::AttestationRefused(refusal),
                },
            )
            .await)
    }

    /// The live path: check `record` against the state, encode it,
    /// append it under the log token, and only after the append has
    /// returned `Ok` apply it (the state module's docs). The apply runs
    /// under the token, in the append's settle step: a state that
    /// refuses a record the log now holds fences the engine before the
    /// token is released ([`FenceCause::CommittedRecordRefused`]).
    ///
    /// # Errors
    /// [`CommitError`]. On every one the state is unchanged; on
    /// [`CommitError::Fenced`] the log may hold the record.
    pub(crate) async fn commit<L: DecisionLog, S, C, R, E, P>(
        &mut self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        record: &Record,
    ) -> Result<(), CommitError> {
        let refused = CommitError::Refused;
        let state = self.state.as_mut().ok_or(refused(RecordRefusal::NoLog))?;
        state
            .check(record)
            .map_err(|e| refused(RecordRefusal::State(e)))?;
        let encoded = encode_append(state.envelope(), record)
            .map_err(|e| refused(RecordRefusal::Codec(e)))?;
        engine
            .gate
            .settling(
                &engine.shared.fence,
                LogCall::Append,
                Some(&self.volume),
                || engine.log.append(&encoded),
                |appended| {
                    appended.map_err(FenceCause::Failed)?;
                    state
                        .apply(record)
                        .map_err(FenceCause::CommittedRecordRefused)?;
                    self.view.committed(Some(state));
                    Ok(())
                },
            )
            .await
            .map_err(CommitError::Fenced)
    }

    /// Initialise the volume's log (spec §6.3): remove the volume's
    /// leftover temporary by its exact name, read and classify its name,
    /// then create a log under a new epoch only where nothing is (the one
    /// path that draws from the cryptographic-randomness seam; a failed
    /// draw refuses before any envelope is built or log call made, and
    /// fences nothing), keep an
    /// envelope with no record (handling its tail and finishing its
    /// barrier), and refuse everything else without calling
    /// `initialise`: nothing authorises replacing a file at the log's
    /// name. The removal comes first, before any read or log write, as
    /// spec §6.3 has it. It runs under the log token, so it never begins
    /// after a fence, and its failure refuses without fencing (the seam's
    /// `remove_temporary`).
    async fn initialise<L: DecisionLog, S, C, R, E: SecureRandom, P>(
        &mut self,
        engine: &Engine<'_, L, S, C, R, E, P>,
    ) -> Result<Initialised, InitialiseError> {
        let fenced = |_: Fence| InitialiseError::Fenced;
        engine
            .gate
            .exempt(&engine.shared.fence, || {
                engine.log.remove_temporary(&self.volume)
            })
            .await
            .map_err(fenced)?
            .map_err(InitialiseError::TemporaryNotRemoved)?;
        let read = engine
            .log
            .read(&self.volume)
            .await
            .map_err(InitialiseError::Unreadable)?;
        let prepared = super::initialise::prepare(
            read.as_deref(),
            &self.volume,
            &mut *engine
                .secure_random
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )?;
        let (envelope, created) = match prepared {
            super::initialise::Prepared::Create(envelope) => {
                if self.intents.configured() {
                    self.intents
                        .rebind(engine, &self.volume, envelope.epoch())
                        .await?;
                    crash_point!(IntentProvisioned);
                }
                let encoded = encode_envelope(&envelope);
                engine
                    .gate
                    .fencing(
                        &engine.shared.fence,
                        LogCall::Initialise,
                        Some(&self.volume),
                        || engine.log.initialise(&encoded),
                    )
                    .await
                    .map_err(fenced)?;
                #[cfg(feature = "crash-points")]
                if self.intents.configured() {
                    crash_point!(IntentProvisionLogSynced);
                }
                (envelope, true)
            }
            super::initialise::Prepared::Keep {
                envelope,
                committed_len,
                tail_len,
            } => {
                Readiness::new(committed_len, tail_len, false)
                    .make_ready(engine.log, engine.gate, &engine.shared.fence, &self.volume)
                    .await
                    .map_err(fenced)?;
                (envelope, false)
            }
        };
        let epoch = envelope.epoch();
        self.state = Some(VolumeState::new(envelope));
        self.view.committed(self.state.as_ref());
        Ok(if created {
            Initialised::Created { epoch }
        } else {
            Initialised::Kept { epoch }
        })
    }
}

/// Answering requests beside an open entry's step or pause (module docs):
/// spec §3's rules 0 to 5, which always answer while the entry is open,
/// and read the state without changing it.
struct Serving<'w, 'a, L, S, C, R, E, P> {
    intents: &'w super::intent_worker::Intents,
    engine: &'w Engine<'a, L, S, C, R, E, P>,
    volume: &'w VolumeName,
    keys: &'w TrustedKeys,
    memo: &'w mut ChainMemo,
    state: &'w VolumeState,
    view: &'w VolumeSlot,
    entry: &'w OpenEntry,
    /// The entry's PUT count and its last classification. The count
    /// includes this round's PUT, during its step and after; the
    /// classification is the previous round's read during the step (none
    /// yet on a run's first round: unresolved) and this round's during
    /// the pause after it. A report request's row is built from these plus the
    /// engine's clock read when the request is answered and the
    /// request's own bound (spec §7): a round can span a long re-issue
    /// backoff, during which each request needs its own age.
    tracking: Tracking,
    inbox: &'w mut mpsc::Receiver<Request>,
}

impl<L: DecisionLog, S, C, R, E: SecureRandom, P> Serving<'_, '_, L, S, C, R, E, P>
where
    S: RootStore,
    C: Clock,
{
    /// Poll `fut` to its end, answering each request that arrives
    /// meanwhile beside it; neither is dropped for the other. Returns
    /// `fut`'s output and whether a stop, the fence or the last handle's
    /// drop arrived. On one of those, `fut` is driven to its end when
    /// `finish` is set (a step, which is never dropped) and dropped
    /// otherwise (a pause), and no further request is taken.
    async fn serve_while<F: Future>(
        mut self,
        mut fut: Pin<&mut F>,
        finish: bool,
    ) -> (Option<F::Output>, bool) {
        loop {
            let next = pin!(Next {
                inbox: &mut *self.inbox,
                shared: self.engine.shared,
            });
            let request = match race(fut.as_mut(), next).await {
                Raced::First(out) => return (Some(out), false),
                Raced::Second(Event::Request(request)) => request,
                Raced::Second(Event::Stop | Event::Fenced | Event::Closed) => {
                    return if finish {
                        (Some(fut.await), true)
                    } else {
                        (None, true)
                    };
                }
            };
            let mut answering = pin!(self.answer(request));
            if let Raced::Second(out) = race(answering.as_mut(), fut.as_mut()).await {
                answering.await;
                return (Some(out), false);
            }
        }
    }

    /// Answer one request while the entry is open. A submission meets
    /// rules 0 to 4, then rule 5, which always answers. An initialise
    /// meets a log with records, which it refuses, so it is answered
    /// from the state without a log call.
    async fn answer(&mut self, request: Request) {
        let shared = self.engine.shared;
        match request {
            Request::Intent {
                work,
                context,
                reply,
            } => {
                use tracing::Instrument as _;
                #[cfg(feature = "crash-points")]
                let binding = intent_binding(&work);
                let answer = self
                    .intents
                    .answer(
                        self.engine,
                        self.volume,
                        self.keys,
                        Some(self.state.envelope().epoch()),
                        work,
                    )
                    .instrument(context)
                    .await;
                send_intent(
                    shared,
                    reply,
                    answer,
                    #[cfg(feature = "crash-points")]
                    &binding,
                );
            }
            Request::Submit {
                submission,
                reply,
                #[cfg(test)]
                queue,
            } => {
                #[cfg(test)]
                drop(queue);
                let state = Some(self.state);
                let answer = match rules_0_to_5(
                    self.engine.store,
                    self.volume,
                    self.keys,
                    state,
                    &submission,
                    self.view,
                    self.memo,
                )
                .await
                {
                    Ok(answer) => answer,
                    // Not reached: the entry is open, so rule 5
                    // answered. Answered by rule 5 all the same.
                    Err(candidate) => rule_5(self.state, self.entry, &candidate),
                };
                send_answer(shared, self.volume, reply, answer);
            }
            Request::Initialise { reply } => {
                let answer = if shared.fence.is_set() {
                    Err(InitialiseError::Fenced)
                } else {
                    Err(InitialiseError::LogHasRecords)
                };
                #[cfg(test)]
                shared.replies.initialised(self.volume, &answer);
                crash_point!(
                    ReplySent,
                    format!("REPLY {} {answer:?}", self.volume.as_str())
                );
                let _ = reply.send(answer);
            }
            Request::Report { bound, reply } => {
                if !shared.fence.is_set() {
                    let now = self.engine.clock.now();
                    let row = row(
                        self.volume,
                        self.state,
                        self.entry,
                        self.tracking.stuck,
                        self.tracking.reissues(),
                        now,
                        bound,
                    );
                    let _ = reply.send(Some(row));
                }
            }
        }
    }
}

#[cfg(feature = "crash-points")]
fn intent_binding(work: &super::intent_worker::Work) -> String {
    match work {
        super::intent_worker::Work::Request { bytes, .. } => {
            granary_core::hash::GrainId::of(bytes).to_string()
        }
        super::intent_worker::Work::Maintain { .. } => "maintenance".to_owned(),
        super::intent_worker::Work::Roots => "roots".to_owned(),
    }
}

fn send_intent(
    shared: &Shared,
    reply: oneshot::Sender<super::intent_worker::ResultValue>,
    answer: super::intent_worker::ResultValue,
    #[cfg(feature = "crash-points")] binding: &str,
) {
    crash_point!(IntentBeforeReply, format!("BINDING {binding}"));
    let answer = if shared.fence.is_set() {
        super::intent_worker::ResultValue::Answer(crate::wire::Outcome::intent_refused(
            crate::wire::Status::ServiceUnavailable,
            crate::wire::ErrorToken::Fenced,
        ))
    } else {
        answer
    };
    let _delivered = reply.send(answer);
    crash_point!(IntentReplySent);
}
