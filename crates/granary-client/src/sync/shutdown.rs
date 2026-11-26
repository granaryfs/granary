// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A writable mount's shutdown: the latch that stops new mutations, the
//! drain, one sync per dirty file, one commit and the release of the intent,
//! all under one deadline, then the report of what was left.

use super::engine::{CommitDrive, RuntimeSeams};
use super::{
    MonotonicClock, SyncContent, SyncEngine, SyncOptions, SyncRemote, SyncRuntime, refused,
};
use crate::observe::{self, OperationKind, UnmountCause, UnmountOutcome, UnmountTrigger};
use crate::overlay_store::ShutdownWork;
use crate::writable_store::sync_engine::CoalesceState;
use crate::{
    AuthorityTransport, CoordinationError, FailureClass, OverlayIo, PublicationOutcome,
    RecoveryIntent, SharedWritableStore, SyncTarget,
};
use granary_core::{
    clock::Clock, hash::GrainId, overlay_ownership::Operation, secure_random::SecureRandom,
};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

/// How long a shutdown may take, from its latch to its report.
pub(crate) const DEFAULT_SHUTDOWN_BOUND: Duration = Duration::from_secs(30);

/// How long past its bound the session thread waits for the sequence's
/// answer, so a runtime that no longer runs the sequence cannot hold it.
const SHUTDOWN_MARGIN: Duration = Duration::from_millis(500);

/// What began a shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The kernel ended the session: the adapter is gone, so a landing
    /// installs without the view.
    SessionEnd,
    /// The daemon was told to stop while its session serves: a landing
    /// installs through the adapter's gate, and reads go on being served on
    /// the landed view.
    Signal,
    /// The mount owner requested shutdown through the control exchange.
    Umount,
}

impl Trigger {
    /// The trigger as the shutdown's event spells it.
    const fn label(self) -> UnmountTrigger {
        match self {
            Self::SessionEnd => UnmountTrigger::SessionEnd,
            Self::Signal => UnmountTrigger::Signal,
            Self::Umount => UnmountTrigger::Umount,
        }
    }
}

/// Why a shutdown left work behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// The bound ran out, or a signal after the first stop request cut the sequence.
    Deadline,
    /// A step failed before the bound, with its error's class.
    Failed(FailureClass),
    /// The sequence was lost, or its answer never arrived.
    Internal,
}

impl Cause {
    /// The cause as the shutdown's event spells it.
    const fn label(self) -> UnmountCause {
        match self {
            Self::Deadline => UnmountCause::Deadline,
            Self::Failed(_) => UnmountCause::Failed,
            Self::Internal => UnmountCause::Internal,
        }
    }
}

/// How a shutdown ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every step succeeded and a commit moved the base to this seq.
    Committed(u64),
    /// Every step succeeded and nothing was committed.
    Clean,
    /// Work is left in the journal and staging, and the intent is kept.
    Incomplete(Cause),
    /// The authority fenced the mount's ownership or its commit.
    Fenced,
}

impl Outcome {
    /// Whether the intent was released: everything acknowledged is published.
    #[must_use]
    pub(crate) const fn released(self) -> bool {
        matches!(self, Self::Committed(_) | Self::Clean)
    }

    /// The class a coordination diagnostic reports this outcome under.
    #[must_use]
    pub(crate) const fn class(self) -> FailureClass {
        match self {
            Self::Committed(_) | Self::Clean => FailureClass::Refused,
            Self::Incomplete(Cause::Deadline) => FailureClass::Unavailable,
            Self::Incomplete(Cause::Failed(class)) => class,
            Self::Incomplete(Cause::Internal) => FailureClass::Internal,
            Self::Fenced => FailureClass::Conflict,
        }
    }
}

/// What cut a shutdown short, for an [`Outcome::Incomplete`] of
/// [`Cause::Deadline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// The bound ran out.
    Bound,
    /// A further signal expired the sequence before its bound.
    Signal,
}

/// What a shutdown left unacknowledged at its report, as its event counts
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Residue {
    /// The files still dirty.
    pub files: u64,
    /// Their dirty bytes.
    pub bytes: u64,
    /// The journal records since the base that are not bookkeeping.
    pub operations: u64,
}

/// How a shutdown ended, from the values its `mount.unmount` event carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// How it ended.
    pub outcome: Outcome,
    /// What cut it, for an `Incomplete(Deadline)`; `None` for every other
    /// outcome.
    pub cut: Option<Cut>,
    /// What a kept outcome left, or `None` when it could not be read; always
    /// `None` for a released one.
    pub residue: Option<Residue>,
    /// From the call that began it to its report.
    pub elapsed_ms: u64,
}

impl ShutdownReport {
    /// A sequence whose answer never arrived: `Incomplete(Internal)`, with
    /// no counts and no time.
    #[must_use]
    pub const fn lost() -> Self {
        Self {
            outcome: Outcome::Incomplete(Cause::Internal),
            cut: None,
            residue: None,
            elapsed_ms: 0,
        }
    }

    /// A lost sequence, `elapsed_ms` after it began.
    const fn lost_after(elapsed_ms: u64) -> Self {
        Self {
            elapsed_ms,
            ..Self::lost()
        }
    }
}

/// The milliseconds from `started` to `now`, saturating.
fn elapsed_ms(now: tokio::time::Instant, started: tokio::time::Instant) -> u64 {
    u64::try_from(now.saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX)
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Committed(seq) => write!(f, "committed at seq {seq}"),
            Self::Clean => f.write_str("clean"),
            Self::Incomplete(Cause::Deadline) => f.write_str("incomplete (deadline)"),
            Self::Incomplete(Cause::Failed(class)) => {
                write!(f, "incomplete (failed: {})", class.as_str())
            }
            Self::Incomplete(Cause::Internal) => f.write_str("incomplete (internal)"),
            Self::Fenced => f.write_str("fenced"),
        }
    }
}

/// A mount's shutdown, as its backend begins it.
pub(crate) trait MountShutdown: Send + Sync {
    /// Run the sequence once and answer how it ended, within the bound and
    /// its margin; a second call answers the first one's report.
    fn begin(&self, trigger: Trigger) -> ShutdownReport;

    /// Cut the sequence at its next poll, whichever trigger began it, or at
    /// its first poll when it has not begun: the expiry is never cleared.
    fn expire(&self);

    /// The report of a sequence that has ended, `None` before it has.
    fn report(&self) -> Option<ShutdownReport>;

    /// Run every later sequence under `bound` instead.
    #[cfg(test)]
    fn bound_for_test(&self, bound: Duration);
}

#[derive(Debug, Clone, Copy)]
enum State {
    Idle,
    Running,
    Done(ShutdownReport),
}

/// A shared handle on one mount's shutdown, for the daemon that stops it.
#[derive(Clone)]
pub struct ShutdownHandle(Arc<dyn MountShutdown>);

impl std::fmt::Debug for ShutdownHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownHandle").finish_non_exhaustive()
    }
}

impl ShutdownHandle {
    pub(crate) fn new(shutdown: Arc<dyn MountShutdown>) -> Self {
        Self(shutdown)
    }

    /// Run the shutdown, or wait for the one already running, and answer
    /// its report, within its bound and margin.
    #[must_use]
    pub fn begin(&self, trigger: Trigger) -> ShutdownReport {
        self.0.begin(trigger)
    }

    /// Cut the shutdown at once: a running sequence stops at its next
    /// poll, and one not yet begun stops at its first.
    pub fn expire(&self) {
        self.0.expire();
    }

    /// The report of a shutdown that has ended, `None` before it has.
    #[must_use]
    pub fn report(&self) -> Option<ShutdownReport> {
        self.0.report()
    }
}

/// Settles a run's state as it is dropped: `Done` with `report`, a lost one
/// unless the run answered, and every caller waiting for it woken.
struct Settle<'a> {
    state: &'a Mutex<State>,
    settled: &'a std::sync::Condvar,
    report: ShutdownReport,
}

impl Drop for Settle<'_> {
    fn drop(&mut self) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = State::Done(self.report);
        self.settled.notify_all();
    }
}

/// The cut a further signal asks for: once set, never cleared.
#[derive(Default)]
struct Expiry {
    expired: AtomicBool,
    /// Wakes a sequence parked in its steps; notified only after `expired`
    /// is stored.
    wake: tokio::sync::Notify,
}

/// Run `steps` until they answer, or until `expiry` is set: `None` when it
/// cut them.
///
/// Biased toward the steps: each poll polls them first, so a sequence that
/// is ready in the poll that observes the expiry is reported as it ended,
/// and only then reads the flag and the wake. The wake is enabled before the
/// first read of the flag, so an expiry between the read and the park is
/// not lost. An expiry already set before the steps are first polled cuts
/// them unpolled: a sequence never polled cannot be ready, and its first
/// poll would start work, a local transaction, that outlives the cut.
///
/// # Cancellation safety
///
/// Dropping it drops `steps` wherever they are parked, exactly as the
/// bound's timer drops them.
async fn cut_on_expiry<F: Future>(expiry: &Expiry, steps: F) -> Option<F::Output> {
    tokio::pin!(steps);
    let wake = expiry.wake.notified();
    tokio::pin!(wake);
    wake.as_mut().enable();
    if expiry.expired.load(Ordering::Acquire) {
        return None;
    }
    std::future::poll_fn(|context| {
        if let Poll::Ready(answer) = steps.as_mut().poll(context) {
            return Poll::Ready(Some(answer));
        }
        if expiry.expired.load(Ordering::Acquire) {
            return Poll::Ready(None);
        }
        wake.as_mut().poll(context).map(|()| None)
    })
    .await
}

/// The shutdown controller of one mount's engine.
pub(crate) struct Shutdown<P: OverlayIo, R, S, C, M, E, T> {
    engine: Arc<SyncEngine<P, R, S, C, M, E>>,
    mediator: SharedWritableStore<P>,
    runtime: Arc<E>,
    entropy: T,
    /// The sync executor's handle, entered to start the sequence from the
    /// session thread, which runs outside it.
    handle: Option<tokio::runtime::Handle>,
    bound: Duration,
    /// Never held across a wait.
    state: Mutex<State>,
    /// Shared with each sequence, so an expiry reaches the one running.
    expiry: Arc<Expiry>,
    /// Wakes a second caller waiting for the first one's outcome.
    settled: std::sync::Condvar,
    /// The sequence panics before its first step.
    #[cfg(test)]
    panics: std::sync::atomic::AtomicBool,
    /// The sequence holds its answer until its deadline has passed.
    #[cfg(test)]
    answers_late: std::sync::atomic::AtomicBool,
    /// Runs once in `begin` after it claims the run, before it starts the
    /// sequence.
    #[cfg(test)]
    claimed_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// A bound a test set in place of `bound`.
    #[cfg(test)]
    bound_for_test: Mutex<Option<Duration>>,
}

impl<P: OverlayIo, R, S, C, M, E, T> Shutdown<P, R, S, C, M, E, T> {
    pub(crate) fn new(
        engine: Arc<SyncEngine<P, R, S, C, M, E>>,
        mediator: SharedWritableStore<P>,
        runtime: Arc<E>,
        entropy: T,
        handle: Option<tokio::runtime::Handle>,
        bound: Duration,
    ) -> Self {
        Self {
            engine,
            mediator,
            runtime,
            entropy,
            handle,
            bound,
            state: Mutex::new(State::Idle),
            expiry: Arc::new(Expiry::default()),
            settled: std::sync::Condvar::new(),
            #[cfg(test)]
            panics: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            answers_late: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            claimed_hook: Mutex::new(None),
            #[cfg(test)]
            bound_for_test: Mutex::new(None),
        }
    }

    /// The bound every step runs under.
    fn bound(&self) -> Duration {
        #[cfg(test)]
        if let Some(bound) = *self
            .bound_for_test
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return bound;
        }
        self.bound
    }

    /// Make the sequence panic before its first step.
    #[cfg(test)]
    pub(crate) fn panic_for_test(&self) {
        self.panics
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Run `hook` once, in the next `begin` that claims the run, before it
    /// starts the sequence.
    #[cfg(test)]
    pub(crate) fn on_claimed_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .claimed_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Make the sequence wait past its deadline once its steps have ended,
    /// before it decides its outcome.
    #[cfg(test)]
    pub(crate) fn answer_late_for_test(&self) {
        self.answers_late
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

impl<P, R, S, C, M, E, T> MountShutdown for Shutdown<P, R, S, C, M, E, T>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + AuthorityTransport + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
    T: SecureRandom + Clone + Send + Sync + 'static,
{
    fn begin(&self, trigger: Trigger) -> ShutdownReport {
        // Before the state loop, so a session that ends while a signal's
        // sequence runs makes every landing after it install without the
        // adapter it no longer has.
        match trigger {
            Trigger::SessionEnd => self.engine.install_locally(),
            Trigger::Signal | Trigger::Umount => (),
        }
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                match *state {
                    State::Done(report) => return report,
                    // The first call answers within its bound and margin.
                    State::Running => {
                        state = self
                            .settled
                            .wait(state)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                    State::Idle => {
                        *state = State::Running;
                        break;
                    }
                }
            }
        }
        // From here this call owns the run: whichever way it leaves,
        // unwinding included, the state settles and a waiting caller wakes.
        let mut settle = Settle {
            state: &self.state,
            settled: &self.settled,
            report: ShutdownReport::lost(),
        };
        #[cfg(test)]
        if let Some(hook) = self
            .claimed_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            hook();
        }
        let bound = self.bound();
        // One instant starts the deadline, the reported elapsed time and
        // this call's wait, so a sequence the runtime starts late is cut,
        // timed and awaited from the same start.
        let started = self.runtime.now();
        let sequence = Sequence {
            trigger,
            engine: self.engine.clone(),
            mediator: self.mediator.clone(),
            runtime: self.runtime.clone(),
            entropy: self.entropy.clone(),
            bound,
            started,
            deadline: started.checked_add(bound),
            expiry: self.expiry.clone(),
            #[cfg(test)]
            panics: self.panics.load(std::sync::atomic::Ordering::Acquire),
            #[cfg(test)]
            answers_late: self.answers_late.load(std::sync::atomic::Ordering::Acquire),
        };
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        {
            let _entered = self.handle.as_ref().map(tokio::runtime::Handle::enter);
            let runtime = self.runtime.clone();
            // A monitor joins the sequence, so a panicked or lost sequence
            // still answers.
            drop(self.runtime.spawn(async move {
                let report = match runtime.spawn(sequence.run()).await {
                    Ok(report) => report,
                    Err(_) => ShutdownReport::lost_after(elapsed_ms(runtime.now(), started)),
                };
                let _ = send.send(report);
            }));
        }
        let report = receive
            .recv_timeout(
                bound
                    .saturating_add(SHUTDOWN_MARGIN)
                    .saturating_sub(self.runtime.now().saturating_duration_since(started)),
            )
            .unwrap_or_else(|_| {
                ShutdownReport::lost_after(elapsed_ms(self.runtime.now(), started))
            });
        settle.report = report;
        drop(settle);
        report
    }

    fn expire(&self) {
        self.expiry.expired.store(true, Ordering::Release);
        self.expiry.wake.notify_waiters();
    }

    fn report(&self) -> Option<ShutdownReport> {
        match *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            State::Done(report) => Some(report),
            State::Idle | State::Running => None,
        }
    }

    #[cfg(test)]
    fn bound_for_test(&self, bound: Duration) {
        *self
            .bound_for_test
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bound);
    }
}

/// One run of the shutdown, owned by the task that runs it.
struct Sequence<P: OverlayIo, R, S, C, M, E, T> {
    trigger: Trigger,
    engine: Arc<SyncEngine<P, R, S, C, M, E>>,
    mediator: SharedWritableStore<P>,
    runtime: Arc<E>,
    entropy: T,
    bound: Duration,
    /// When `begin` was called, which the elapsed time is measured from.
    started: tokio::time::Instant,
    /// Every step's deadline; `None` when the bound overflows the clock.
    deadline: Option<tokio::time::Instant>,
    /// The controller's expiry, which cuts the steps before the deadline.
    expiry: Arc<Expiry>,
    #[cfg(test)]
    panics: bool,
    #[cfg(test)]
    answers_late: bool,
}

impl<P, R, S, C, M, E, T> Sequence<P, R, S, C, M, E, T>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + AuthorityTransport + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
    T: SecureRandom + Clone + Send + Sync + 'static,
{
    /// Latch, run the steps under the deadline and the expiry, read what is
    /// left, report.
    async fn run(self) -> ShutdownReport {
        observe::op_begin(OperationKind::Unmount);
        let started = self.started;
        // Step 0: no user mutation or sync is admitted after this
        // acquisition, and a shrink waiting on its floor wakes to refuse.
        let base = self
            .mediator
            .with(|store| {
                store.close_mutations();
                store.floor_changed.notify_waiters();
                Ok(store.shutdown_base())
            })
            .ok()
            .flatten();
        let Some(deadline) = self.deadline else {
            return report_outcome(
                self.trigger.label(),
                Outcome::Incomplete(Cause::Internal),
                None,
                None,
                None,
                elapsed_ms(self.runtime.now(), started),
                false,
            );
        };
        let mut secure = self.entropy.clone();
        // Whether an error arrived late, and what made it late, is read
        // when it arrives: past the deadline is the bound's, before it only
        // an expiry can have made it late.
        let steps = self
            .runtime
            .timeout_at(
                deadline,
                cut_on_expiry(&self.expiry, async {
                    // A Release's judged completion has emitted its failure,
                    // so only an error that did not come from one is reported
                    // here.
                    let result = match self.steps(&mut secure, deadline).await {
                        Ok(()) => self.release(deadline).await,
                        Err(error) => Err((error, false)),
                    };
                    let late = if self.runtime.now() >= deadline {
                        Some(Cut::Bound)
                    } else if self.expiry.expired.load(Ordering::Acquire) {
                        Some(Cut::Signal)
                    } else {
                        None
                    };
                    #[cfg(test)]
                    if self.answers_late {
                        let _ = self
                            .runtime
                            .timeout_at(deadline, std::future::pending::<()>())
                            .await;
                    }
                    (result, late)
                }),
            )
            .await;
        // The timer polls the expiry's race first, so an expiry already set
        // when both have passed is the cut that answered.
        let (steps, late) = match steps {
            Ok(Some((result, late))) => (Some(result), late),
            Ok(None) => (None, Some(Cut::Signal)),
            Err(_) => (None, Some(Cut::Bound)),
        };
        // Step 7, after the cut: read from memory, whatever phase the
        // steps left the store in.
        let (work, now) = self
            .mediator
            .with(|store| Ok((store.shutdown_report(), store.shutdown_base())))
            .unwrap_or((None, None));
        let from_complete = matches!(steps, Some(Err((_, true))));
        let steps = steps.map(|result| result.map_err(|(error, _)| error));
        let (outcome, cut) = match steps {
            Some(Err(
                CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. },
            )) => (Outcome::Fenced, None),
            None => (Outcome::Incomplete(Cause::Deadline), late),
            Some(Err(error)) => match late {
                Some(cut) => (Outcome::Incomplete(Cause::Deadline), Some(cut)),
                None => (
                    Outcome::Incomplete(Cause::Failed(super::failure_class(&error))),
                    None,
                ),
            },
            // A step's error outranks a moved base, so only a sequence that
            // ran every step reads its seq from the base, however late it
            // answered.
            Some(Ok(())) => (
                match (base, now) {
                    (Some(base), Some(now)) if now != base => Outcome::Committed(now.1),
                    (Some(_), Some(_)) => Outcome::Clean,
                    _ => Outcome::Incomplete(Cause::Failed(FailureClass::Internal)),
                },
                None,
            ),
        };
        report_outcome(
            self.trigger.label(),
            outcome,
            cut,
            work.as_ref(),
            now,
            elapsed_ms(self.runtime.now(), started),
            from_complete,
        )
    }

    /// Steps 1 to 5; the first error stops them.
    async fn steps(
        &self,
        secure: &mut T,
        deadline: tokio::time::Instant,
    ) -> Result<(), CoordinationError> {
        #[cfg(test)]
        assert!(!self.panics, "the shutdown sequence panics");
        let (floor, workspace_bytes) = self.mediator.with(|store| {
            Ok((
                store.floor_changed.clone(),
                store.construction_workspace_bytes,
            ))
        })?;
        let options = SyncOptions {
            workspace_bytes,
            deadline: Some(deadline),
            ..SyncOptions::default()
        };
        // Steps 1 and 2: drive any retained lane, then drain what was
        // admitted before the latch, until the engine is quiet. A sync
        // drained here can leave a lane retained, which the next pass drives.
        loop {
            self.engine
                .take_over(
                    options,
                    deadline,
                    CommitDrive::Mount(RecoveryIntent::ExplicitRecovery),
                    secure,
                )
                .await?;
            let wake = floor.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if self.engine.quiescent()? {
                break;
            }
            self.runtime
                .timeout_at(deadline, wake)
                .await
                .map_err(|_| refused("SyncDeadline"))?;
        }
        // Step 3: one sync per dirty stage, in stage order, then the
        // namespace only when it changed. An unrepresentable scoped selection
        // is left for the complete commit after its preparation is released.
        let work = self
            .mediator
            .with(|store| store.overlay_transaction(|overlay| overlay.shutdown_work()))?;
        let mut complete = false;
        for (stage, _) in work.stages {
            match self
                .engine
                .sync(SyncTarget::Stage(stage), options)
                .wait()
                .await
            {
                Ok(()) => {}
                Err(CoordinationError::Refused("SyncSelectionUnrepresentable")) => {
                    complete = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if !complete && work.namespace_records > 0 {
            self.engine
                .sync(SyncTarget::Directory(None), options)
                .wait()
                .await?;
        }
        // Step 4: one commit of whatever is past the last boundary.
        let now = self.runtime.now();
        if self
            .mediator
            .with(|store| store.coalesce_state(&options, now))?
            != CoalesceState::Clean
        {
            let lane = self.engine.construct_commit(options, secure).await?;
            let result = self
                .engine
                .drive_commit_for(
                    &lane,
                    secure,
                    &mut RuntimeSeams(self.runtime.as_ref()),
                    CommitDrive::Mount(RecoveryIntent::Continue),
                    options,
                )
                .await?;
            if !matches!(result.outcome, PublicationOutcome::Landed(_)) {
                if let Some(error) = result.admission_error() {
                    return Err(error);
                }
                // Preserve the shutdown mediator's wake on a fenced store.
                self.mediator.with(|store| store.sync_admission_open())?;
                return Err(refused("SyncCommitUnresolved"));
            }
        }
        // Step 5: settle each failed caller's retained registration.
        let retained = self.mediator.with(|store| Ok(store.retained_requests()))?;
        for request in retained
            .iter()
            .filter(|request| request.operation() == Operation::Register)
        {
            self.engine.settle_registration(request, deadline).await?;
        }
        Ok(())
    }

    /// Step 6: release the intent, never once the deadline has passed: a
    /// cut polls the steps once more, and the release's preparation changes
    /// the phase before its first wait.
    async fn release(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), (CoordinationError, bool)> {
        if self.runtime.now() >= deadline {
            return Err((refused("SyncDeadline"), false));
        }
        let release = self
            .engine
            .prepare_release(self.bound, deadline)
            .await
            .map_err(|error| (error, false))?;
        self.engine.release(&release, deadline).await
    }
}

#[cfg(test)]
impl<P, R, S, C, M, E, T> Shutdown<P, R, S, C, M, E, T>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + AuthorityTransport + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
    T: SecureRandom + Clone + Send + Sync + 'static,
{
    /// Await the session-end sequence on the test's runtime, independent of
    /// the controller's synchronous wait for the report.
    pub(crate) async fn run_session_end_sequence_for_test(&self) -> ShutdownReport {
        self.engine.install_locally();
        let bound = self.bound();
        let started = self.runtime.now();
        Sequence {
            trigger: Trigger::SessionEnd,
            engine: self.engine.clone(),
            mediator: self.mediator.clone(),
            runtime: self.runtime.clone(),
            entropy: self.entropy.clone(),
            bound,
            started,
            deadline: started.checked_add(bound),
            expiry: self.expiry.clone(),
            panics: false,
            answers_late: false,
        }
        .run()
        .await
    }
}

/// Emit the event of a shutdown `trigger` ran, `elapsed` milliseconds
/// after it began, and its operation's end, then answer. `work` and `base`
/// are what it left, read after its cut; `from_complete` says the failure
/// came from [`crate::WritableStore::complete`]'s Release verdict, which
/// emitted its own `op.failed`.
pub(crate) fn report_outcome(
    trigger: UnmountTrigger,
    outcome: Outcome,
    cut: Option<Cut>,
    work: Option<&ShutdownWork>,
    base: Option<(GrainId, u64)>,
    elapsed: u64,
    from_complete: bool,
) -> ShutdownReport {
    let counts = work.map(|work| {
        [
            u64::try_from(work.stages.len()).unwrap_or(u64::MAX),
            work.stages
                .iter()
                .fold(0u64, |total, (_, bytes)| total.saturating_add(*bytes)),
            work.operations,
        ]
    });
    let seq = base.map_or(0, |(_, seq)| seq);
    match outcome {
        Outcome::Committed(seq) => {
            observe::mount_unmounted(trigger, UnmountOutcome::Committed, seq, elapsed);
        }
        Outcome::Clean => {
            observe::mount_unmounted(trigger, UnmountOutcome::Clean, seq, elapsed);
        }
        Outcome::Incomplete(cause) => {
            if let Cause::Failed(class) = cause
                && !from_complete
            {
                observe::op_failed(OperationKind::Unmount, class);
            }
            observe::mount_unmount_left(
                trigger,
                UnmountOutcome::Incomplete,
                cause.label(),
                counts,
                elapsed,
            );
        }
        // A fence is a step that failed: the authority's refusal. A
        // Release's completion has emitted its own.
        Outcome::Fenced => {
            if !from_complete {
                observe::op_failed(OperationKind::Unmount, FailureClass::Conflict);
            }
            observe::mount_unmount_left(
                trigger,
                UnmountOutcome::Fenced,
                UnmountCause::Failed,
                counts,
                elapsed,
            );
        }
    }
    observe::op_end(
        OperationKind::Unmount,
        if outcome.released() {
            observe::Outcome::Ok
        } else {
            observe::Outcome::Failed
        },
    );
    ShutdownReport {
        outcome,
        cut,
        // Only a kept outcome's event carries what was left.
        residue: counts
            .filter(|_| !outcome.released())
            .map(|[files, bytes, operations]| Residue {
                files,
                bytes,
                operations,
            }),
        elapsed_ms: elapsed,
    }
}
