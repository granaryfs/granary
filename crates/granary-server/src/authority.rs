// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The publication authority's decision engine for unprofiled volumes:
//! its start, recovery and replay, initialise, admission and
//! publication, the log token and the fence, and the stop.
//!
//! # Shape
//!
//! [`start`] reads the run marker, recovers every configured volume's log
//! and replays it, and returns an [`AuthorityHandle`] and an
//! [`AuthorityDriver`], or a [`StartRefused`].
//!
//! - **The handle** is cheap to clone. Each call sends a request to the
//!   volume's worker and awaits its reply. No log call ever runs on a
//!   caller's future, so dropping one drops only its reply and cancels
//!   nothing (spec §8's engine card).
//! - **The driver's [`AuthorityDriver::run`]** is the one future that
//!   runs every volume's worker. The host polls it once, to its end; the
//!   simulator puts it in its scheduler's task set. Workers are joined
//!   inside it, never spawned, so every worker runs in the one task.
//! - **One worker per configured volume** owns that volume's state and is
//!   the only caller of the log for that volume. It answers submissions
//!   by spec §3's rules in order and publishes the volume's open entry
//!   (spec §4), the `worker` module.
//! - **Validity** follows the `chain` module's checks under the volume's
//!   configured publisher keys ([`VolumeConfig`]). Classification walks the
//!   whole chain to seq 1. Head resolution verifies the listed head by
//!   re-reading to seq 1 or through the worker's verified anchor and one
//!   further ancestor.
//! - **One mutating log call at a time, engine-wide**, under one log
//!   token, with the fence checked after the token is taken and set by a
//!   failing call before the token is released (the `gate` module).
//!
//! # The fence
//!
//! Any error from a mutating log call fences the whole engine, every
//! volume with it (spec §6.2), except the start's marker write finding
//! its temporary's name taken. So does a mutating call's future dropped
//! before it completes, an open entry's owed attestation refused before
//! its append, and the state refusing a record the log has committed
//! ([`FenceCause`]). Once fenced: no further log write or sync, no
//! marker write, every answer is `Fenced`, and [`AuthorityDriver::run`]
//! returns [`RunEnd::Fenced`] when the workers have stopped. Only a host
//! reboot clears it: the marker says **running** under this boot, except
//! where a marker write itself was cut short in one of spec §6.2's two
//! benign cases ([`start`]'s and [`AuthorityDriver::run`]'s cancellation
//! docs).
//!
//! The fence is read before every PUT, so no PUT is issued after it. The
//! workers publish independently, so when the fence is set each worker
//! may have one PUT already in flight, and each of those may still land.
//! Nothing is written or answered on its result: the outcome's append
//! meets the fence.
//!
//! # What a host is told as it happens
//!
//! A host learns of the fence when it is set, not when the run ends:
//! [`AuthorityHandle::watch_fence`] gives a receiver whose value becomes
//! the fence at the moment the engine sets it, for every cause, a fence
//! of the final **clean** write included. A host that must also see what
//! happens while [`start_observed`] runs makes its [`Notices`] first and
//! keeps their receivers: the same fence, and an [`AdmittedRefusal`], sent
//! when the start finds a volume refusing after the marker admitted it
//! and before the start's **clean** write begins, so a host sees that
//! refusal even while that write hangs.
//!
//! # The stop
//!
//! [`AuthorityHandle::stop`] asks every worker to finish at its next step
//! boundary: a request already taken runs to its end, and a log call is
//! never dropped mid-flight. When every worker has stopped and the engine
//! is not fenced, `run()` writes **clean** and returns
//! [`RunEnd::Stopped`]. An open entry stays open in the log and resumes
//! at the next start.
//!
//! A publication step is never dropped. One that completes before its
//! worker observes the stop has its landed or lost outcome recorded, even
//! when the stop was already requested. One still running when its worker
//! observes the stop is driven to its end, its outcome is not recorded,
//! and the next start classifies the entry afresh (spec §6.4).

/// A crash site (the `crash` module): nothing unless the `crash-points` feature is
/// on. `crash_point!(Site)`, or `crash_point!(Site, line)` to write `line`
/// to the crash pipe first; `line` is not evaluated without the feature.
macro_rules! crash_point {
    ($site:ident) => {
        #[cfg(feature = "crash-points")]
        $crate::authority::crash::hit($crate::authority::crash::Site::$site, None);
    };
    ($site:ident, $line:expr) => {
        #[cfg(feature = "crash-points")]
        $crate::authority::crash::hit($crate::authority::crash::Site::$site, Some(&$line));
    };
}

mod chain;
pub(crate) mod content;
#[cfg(feature = "crash-points")]
pub(crate) mod crash;
mod file_log;
mod gate;
pub(crate) mod intent;
mod intent_worker;
pub use intent::IntentOperation;
pub use intent::persistence::IntentStore;
pub use intent_worker::IntentRoot;
pub(crate) mod initialise;
mod join;
mod observation;
mod outcome;
mod publication;
mod ready;
mod start;
pub(crate) use start::marker_admits;
mod state;
mod submission;
mod worker;

#[cfg(test)]
pub(crate) mod tests;

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Waker;
use std::time::Duration;

use granary_core::authlog::{Epoch, LogError};
use granary_core::clock::Clock;
use granary_core::decisionlog::{DecisionLog, LogIoError};
use granary_core::root::VolumeName;
use granary_core::rootstore::RootStore;
use granary_core::runmarker::{RunMarker, encode_marker};
use granary_store::crypto::TrustedKeys;
use tokio::sync::{mpsc, oneshot, watch};

pub use chain::{HeadRef, VerifiedHead};
pub use content::store::Admission;
pub(crate) use content::store::BoundedListingConnector;
pub use file_log::{FileLog, FileLogConfigError};
pub use gate::{Fence, FenceCause, LogCall, RecordRefusal};
pub use observation::{Observation, OpenPosition, TerminalState, VolumeView};
pub use outcome::{ShutdownCause, ShutdownObserved, StopObserved, shutdown_exit_code};
pub use start::{AdmittedRefusal, StartRefused, VolumeRefusal, start, start_observed};
pub use state::ApplyError;
pub use submission::{
    Answer, Bound, InvalidCandidate, OpenEntryRow, Position, Receipt, StuckFlag, StuckState,
    Submission,
};

use gate::{FenceCell, LogGate};
use join::{JoinAll, Joined};
use worker::{Engine, Request, Worker};

/// The engine's pause seam: how a worker waits between re-issues. A
/// production host waits on its runtime's timer; the simulator yields to
/// its scheduler. The engine computes every delay itself, from the
/// [`granary_core::rng::Rng`] seam, so a seed fixes each one.
pub trait Pause: Send + Sync {
    /// Wait for `duration`, as the host counts it.
    ///
    /// # Cancellation safety
    /// Must be cancel-safe: the stop drops a pause in progress.
    fn pause(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

/// Everything the engine runs on: the log, the root store, and the
/// determinism seams.
#[derive(Debug)]
pub struct AuthorityParts<L, S, C, R, E, P> {
    /// The decision log.
    pub log: L,
    /// The store the chain lives in: the engine lists, reads and
    /// publishes roots through it like any other writer.
    pub store: S,
    /// Bounded reads of the same storage for new publication decisions.
    pub admission: Admission,
    /// The clock: the reading a decision records.
    pub clock: C,
    /// The randomness seam: the jitter in each re-issue's delay, and
    /// nothing else.
    pub rng: R,
    /// The cryptographic-randomness seam: the only source of a new log's
    /// epoch, drawn only when initialise creates a missing log.
    pub secure_random: E,
    /// The pause seam: the wait between re-issues.
    pub pause: P,
}

/// One volume the engine serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeConfig {
    volume: VolumeName,
    keys: TrustedKeys,
    intents: Option<Arc<IntentStore>>,
}

impl VolumeConfig {
    /// The configuration of `volume`, whose roots are valid only when
    /// signed under `keys`, its publisher keys.
    #[must_use]
    pub const fn new(volume: VolumeName, keys: TrustedKeys) -> Self {
        Self {
            volume,
            keys,
            intents: None,
        }
    }
    /// Enable intent persistence through the log adapter's protected directory.
    #[must_use]
    pub fn with_intents(mut self, store: Arc<IntentStore>) -> Self {
        self.intents = Some(store);
        self
    }
}

/// Why [`AuthorityHandle::report`] has no rows to give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportError {
    /// The engine is fenced.
    Fenced,
    /// The engine has stopped.
    Stopped,
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fenced => write!(f, "the engine is fenced"),
            Self::Stopped => write!(f, "the engine has stopped"),
        }
    }
}

impl std::error::Error for ReportError {}

/// What an initialise did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initialised {
    /// No log was at the name: one was created under this new epoch.
    Created { epoch: Epoch },
    /// A log with an envelope and no record was there: its epoch is kept
    /// and its namespace barrier completed.
    Kept { epoch: Epoch },
}

/// Why an initialise did not happen (spec §6.3's table). Nothing was
/// written unless the answer is [`Self::Fenced`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialiseError {
    /// The engine does not serve the volume.
    UnconfiguredVolume,
    /// Removing the volume's leftover temporary failed.
    TemporaryNotRemoved(LogIoError),
    /// The log holds committed records.
    LogHasRecords,
    /// A file at the log's name holds no whole envelope.
    NoEnvelope,
    /// Recovery refused the file at the log's name.
    Damaged(LogError),
    /// No log was at the name, and no cryptographic randomness was
    /// available to draw the new log's epoch. What happened before the
    /// draw still happened: the volume's leftover temporary was removed
    /// and the log's name was read. Nothing after it did: no envelope was
    /// built, no recorded log call was made (none of [`LogCall`]'s:
    /// initialise, append, complete-namespace, truncate, resync or a
    /// marker write), and nothing was fenced.
    EntropyUnavailable,
    /// Reading the log's name failed with something other than a missing
    /// name.
    Unreadable(LogIoError),
    /// Intent state could not be validated; log creation did not begin.
    IntentUnavailable,
    /// The engine is fenced.
    Fenced,
    /// The engine has stopped.
    Stopped,
}

impl std::fmt::Display for InitialiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnconfiguredVolume => write!(f, "the volume is not configured"),
            Self::TemporaryNotRemoved(e) => {
                write!(f, "the volume's leftover temporary was not removed: {e}")
            }
            Self::LogHasRecords => write!(f, "the log holds committed records"),
            Self::IntentUnavailable => write!(f, "intent state is unavailable"),
            Self::NoEnvelope => write!(f, "a file at the log's name holds no envelope"),
            Self::Damaged(e) => write!(f, "{e}"),
            Self::EntropyUnavailable => {
                write!(f, "no randomness was available to draw the new log's epoch")
            }
            Self::Unreadable(e) => write!(f, "the log could not be read: {e}"),
            Self::Fenced => write!(f, "the engine is fenced"),
            Self::Stopped => write!(f, "the engine has stopped"),
        }
    }
}

impl std::error::Error for InitialiseError {}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEnd {
    /// Every worker stopped unfenced, and **clean** is durable.
    Stopped,
    /// The engine fenced. The marker was not touched after the fence.
    Fenced(Fence),
    /// Only [`AuthorityHandle::stop`] answers this: the driver was dropped
    /// before its run finished, unfenced. No clean was written, so the
    /// marker still says **running**.
    Abandoned,
}

/// Wakes the workers' waits when a stop is asked for.
///
/// Every `Next` is polled by the one task driving the engine's joined workers,
/// so the latest registration holds that task's waker. The stop flag is sticky,
/// so a request made before the next poll is still seen.
#[derive(Debug, Default)]
pub(crate) struct StopSignal {
    requested: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl StopSignal {
    pub(crate) fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Remember `waker`, to be woken by [`Self::request`].
    pub(crate) fn register(&self, waker: &Waker) {
        *self.waker.lock().unwrap_or_else(PoisonError::into_inner) = Some(waker.clone());
    }

    fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
        let waker = self
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    #[cfg(test)]
    fn waker_count(&self) -> usize {
        usize::from(self.waker.lock().unwrap().is_some())
    }
}

/// What a host is told as it happens (module docs), made before the
/// start so that nothing the start does goes unseen. Take the receivers
/// ([`Self::fence`], [`Self::refusal`]) before handing these to
/// [`start_observed`].
#[derive(Debug, Default)]
pub struct Notices {
    fence: watch::Sender<Option<Fence>>,
    refusal: watch::Sender<Option<AdmittedRefusal>>,
}

impl Notices {
    /// Notices nobody has been sent.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A receiver of the engine's fence: `None` until the fence is set,
    /// then the fence, for the life of the engine. The same value
    /// [`AuthorityHandle::watch_fence`] gives once the start has
    /// returned a handle; this one also sees a fence the start itself
    /// raises.
    #[must_use]
    pub fn fence(&self) -> watch::Receiver<Option<Fence>> {
        self.fence.subscribe()
    }

    /// A receiver of the start's post-admission refusal: `None` until the
    /// start finds a volume refusing after the marker admitted it, then
    /// that refusal, sent before the start's **clean** write begins. The
    /// channel closes when the start returns, so a host waits on it only
    /// while the start runs.
    #[must_use]
    pub fn refusal(&self) -> watch::Receiver<Option<AdmittedRefusal>> {
        self.refusal.subscribe()
    }
}

/// What the handle and the driver share.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    admission: Option<AdmissionRuntime>,
    pub(crate) fence: FenceCell,
    pub(crate) stop: StopSignal,
    /// A test's observer of every reply a worker sends.
    #[cfg(test)]
    pub(crate) replies: tests::ReplyHook,
}

impl Shared {
    /// Nothing shared yet, with the fence publishing through `fence`.
    fn notifying(fence: watch::Sender<Option<Fence>>, admission: AdmissionRuntime) -> Self {
        Self {
            admission: Some(admission),
            fence: FenceCell::over(fence),
            ..Self::default()
        }
    }
}

struct AdmissionRuntime {
    config: Admission,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AdmissionRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.config.fmt(f)
    }
}

#[derive(Debug)]
struct HandleInner {
    shared: Arc<Shared>,
    inboxes: BTreeMap<VolumeName, mpsc::Sender<Request>>,
    views: BTreeMap<VolumeName, Arc<observation::VolumeSlot>>,
    ended: watch::Receiver<Option<RunEnd>>,
}

/// The engine's handle (module docs). Cheap to clone.
///
/// **When an answer counts as "after the fence".** Every answer is decided
/// at a fence check, and an answer decided after the fence is set is
/// `Fenced`. An answer decided before it may still reach its caller after
/// the fence is set, as any reply in flight can; it is then the answer of a
/// call that completed just before the fence. Inside the engine the check
/// and the send have no await between them, in the one `run()` future
/// where the fence is set, so a worker's answer is decided either wholly
/// before the fence or after it. A refusal the handle gives itself from the
/// static configuration (an unconfigured volume) is decided at the handle's
/// own fence check, which on a multi-threaded runtime can precede a fence
/// that another thread sets while the refusal is returned. No answer
/// carries a durability claim the fence could falsify: the fence stops
/// writes, and nothing is written after it.
#[derive(Debug, Clone)]
pub struct AuthorityHandle {
    inner: Arc<HandleInner>,
}

impl AuthorityHandle {
    async fn intent_work(
        &self,
        volume: &VolumeName,
        work: intent_worker::Work,
    ) -> intent_worker::ResultValue {
        use crate::wire::ErrorToken;
        use intent_worker::refused as error;
        if let Some(token) = self.terminal(ErrorToken::Fenced, ErrorToken::Stopped) {
            return error(token);
        }
        let Some(inbox) = self.inner.inboxes.get(volume) else {
            return error(ErrorToken::UnknownVolume);
        };
        let (reply, answer) = oneshot::channel();
        if inbox
            .send(Request::Intent {
                work,
                context: tracing::Span::current(),
                reply,
            })
            .await
            .is_err()
        {
            return error(self.down(ErrorToken::Fenced, ErrorToken::Stopped));
        }
        answer
            .await
            .unwrap_or_else(|_| error(self.down(ErrorToken::Fenced, ErrorToken::Stopped)))
    }

    /// Execute a bounded, authenticated intent request. Cancellation drops only its reply.
    pub async fn intent(
        &self,
        volume: &VolumeName,
        principal: granary_core::enrollment::PrincipalId,
        operation: IntentOperation,
        bytes: Vec<u8>,
    ) -> crate::wire::Outcome {
        match self
            .intent_work(
                volume,
                intent_worker::Work::Request {
                    principal,
                    operation,
                    bytes,
                },
            )
            .await
        {
            intent_worker::ResultValue::Answer(outcome) => outcome,
            intent_worker::ResultValue::Roots(_) => crate::wire::Outcome::internal(),
        }
    }

    /// Enrollment-driven maintenance, separate from HTTP admission; preserves retired cursors.
    pub async fn maintain_intents(
        &self,
        volume: &VolumeName,
        enrollment: &granary_core::enrollment::EnrollmentSet,
        grace_secs: u64,
    ) -> crate::wire::Outcome {
        let principals = enrollment.principals().map(|(id, _, _)| id).collect();
        match self
            .intent_work(
                volume,
                intent_worker::Work::Maintain {
                    principals,
                    grace: grace_secs,
                },
            )
            .await
        {
            intent_worker::ResultValue::Answer(outcome) => outcome,
            intent_worker::ResultValue::Roots(_) => crate::wire::Outcome::internal(),
        }
    }

    /// Visit committed live roots for future coordinated collection. No collector is run.
    /// # Errors
    /// Unavailable, fenced or stopped state is an error, never an empty successful mark.
    pub async fn intent_roots(
        &self,
        volume: &VolumeName,
    ) -> Result<Vec<IntentRoot>, crate::wire::ErrorToken> {
        match self.intent_work(volume, intent_worker::Work::Roots).await {
            intent_worker::ResultValue::Roots(roots) => Ok(roots),
            intent_worker::ResultValue::Answer(outcome) => {
                Err(outcome.error().unwrap_or(crate::wire::ErrorToken::Internal))
            }
        }
    }

    /// Initialise `volume`'s log, through its worker (spec §6.3).
    ///
    /// # Cancellation safety
    /// Cancel-safe: dropping this future drops only its reply. An
    /// initialise the worker has taken runs to its end.
    ///
    /// # Errors
    /// [`InitialiseError`]. Once the engine is fenced every answer is
    /// [`InitialiseError::Fenced`], an unconfigured volume's included: the
    /// fence is read before anything else, and the worker reads it again
    /// before it answers. After a stop is requested or the run has ended,
    /// an unfenced engine answers [`InitialiseError::Stopped`] even for an
    /// unconfigured volume.
    pub async fn initialise(&self, volume: &VolumeName) -> Result<Initialised, InitialiseError> {
        if let Some(error) = self.terminal(InitialiseError::Fenced, InitialiseError::Stopped) {
            return Err(error);
        }
        let Some(inbox) = self.inner.inboxes.get(volume) else {
            return Err(InitialiseError::UnconfiguredVolume);
        };
        let (reply, answer) = oneshot::channel();
        if inbox.send(Request::Initialise { reply }).await.is_err() {
            return Err(self.down(InitialiseError::Fenced, InitialiseError::Stopped));
        }
        answer
            .await
            .unwrap_or_else(|_| Err(self.down(InitialiseError::Fenced, InitialiseError::Stopped)))
    }

    /// Submit a candidate (spec §3): its volume's worker answers it by the
    /// rules in order, and an accepted submission is answered only after
    /// its decision record is durable. Every other answer writes nothing.
    /// A submission made after a stop is requested or the run has ended answers
    /// [`Answer::Stopped`] even for an unconfigured volume, unless fenced.
    ///
    /// # Cancellation safety
    /// Cancel-safe: dropping this future drops only its reply. A
    /// submission the worker has taken runs to its end, its decision
    /// record included, and a later submission of the same accepted
    /// candidate gets its recorded answer.
    pub async fn submit(&self, submission: Submission) -> Answer {
        self.submit_inner(
            submission,
            #[cfg(feature = "crash-points")]
            || {},
        )
        .await
    }

    /// Observe successful inbox handoff, before waiting for the worker's reply.
    #[cfg(feature = "crash-points")]
    pub(crate) async fn submit_observed(
        &self,
        submission: Submission,
        dispatched: impl FnOnce() + Send,
    ) -> Answer {
        self.submit_inner(submission, dispatched).await
    }

    async fn submit_inner(
        &self,
        submission: Submission,
        #[cfg(feature = "crash-points")] dispatched: impl FnOnce() + Send,
    ) -> Answer {
        if let Some(answer) = self.terminal(Answer::Fenced, Answer::Stopped) {
            return answer;
        }
        let Some(inbox) = self.inner.inboxes.get(submission.volume()) else {
            return Answer::UnconfiguredVolume;
        };
        let (reply, answer) = oneshot::channel();
        let request = Request::Submit {
            submission: Box::new(submission),
            reply,
            #[cfg(test)]
            queue: tracing::trace_span!("authority_queue"),
        };
        if inbox.send(request).await.is_err() {
            return self.down(Answer::Fenced, Answer::Stopped);
        }
        #[cfg(feature = "crash-points")]
        dispatched();
        answer
            .await
            .unwrap_or_else(|_| self.down(Answer::Fenced, Answer::Stopped))
    }

    /// The report's data (spec §7): one row per volume with an open
    /// entry, in volume order. `bound` travels to every worker with the
    /// request; each worker computes its row's age and flag against the
    /// engine's clock at the moment it answers, not from a snapshot
    /// taken earlier.
    ///
    /// # Cancellation safety
    /// Cancel-safe: it only reads.
    ///
    /// # Errors
    /// [`ReportError`] once the engine is fenced, a stop is requested or
    /// the run has ended.
    pub async fn report(&self, bound: Duration) -> Result<Vec<OpenEntryRow>, ReportError> {
        if let Some(error) = self.terminal(ReportError::Fenced, ReportError::Stopped) {
            return Err(error);
        }
        let down = || self.down(ReportError::Fenced, ReportError::Stopped);
        // Every worker is asked before any answer is awaited, so the
        // workers answer side by side.
        let mut answers = Vec::with_capacity(self.inner.inboxes.len());
        for inbox in self.inner.inboxes.values() {
            if self.inner.shared.fence.is_set() {
                return Err(ReportError::Fenced);
            }
            let (reply, answer) = oneshot::channel();
            if inbox.send(Request::Report { bound, reply }).await.is_err() {
                return Err(down());
            }
            answers.push(answer);
        }
        let mut rows = Vec::new();
        for answer in answers {
            match answer.await {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => {}
                Err(_) => return Err(down()),
            }
        }
        Ok(rows)
    }

    /// Ask every worker to finish at its next step boundary, and wait for
    /// the run's end (module docs).
    ///
    /// # Cancellation safety
    /// Cancel-safe: the stop is asked for before the first await, and
    /// dropping the wait changes nothing.
    pub async fn stop(&self) -> RunEnd {
        self.inner.shared.stop.request();
        let mut ended = self.inner.ended.clone();
        loop {
            if let Some(end) = ended.borrow_and_update().clone() {
                return end;
            }
            if ended.changed().await.is_err() {
                let end = ended.borrow().clone();
                return end.unwrap_or_else(|| match self.inner.shared.fence.get() {
                    Some(fence) => RunEnd::Fenced(fence),
                    None => RunEnd::Abandoned,
                });
            }
        }
    }

    /// The fence, if the engine is fenced.
    #[must_use]
    pub fn fence(&self) -> Option<Fence> {
        self.inner.shared.fence.get()
    }

    /// A receiver of the fence (module docs): `None` until the engine is
    /// fenced, then the fence, sent when it is set, without waiting for
    /// the workers or the run to end. The value never changes again. A
    /// receiver taken after the fence reads it at once.
    #[must_use]
    pub fn watch_fence(&self) -> watch::Receiver<Option<Fence>> {
        self.inner.shared.fence.subscribe()
    }

    /// A terminal answer before volume lookup or inbox use, with the fence
    /// taking precedence over a requested stop or an ended run.
    fn terminal<T>(&self, fenced: T, stopped: T) -> Option<T> {
        if self.inner.shared.fence.is_set() {
            return Some(fenced);
        }
        if self.inner.shared.stop.requested()
            || self.inner.ended.borrow().is_some()
            || self.inner.ended.has_changed().is_err()
        {
            return Some(self.down(fenced, stopped));
        }
        None
    }

    /// The answer when a request can no longer reach a worker: `fenced`
    /// if the engine is fenced, `stopped` otherwise.
    fn down<T>(&self, fenced: T, stopped: T) -> T {
        if self.inner.shared.fence.is_set() {
            fenced
        } else {
            stopped
        }
    }
}

/// Write **clean** under the log token: the end of an unfenced run, and
/// of a start the marker admitted that then refused before any log write
/// (spec §6.2). Every error fences.
///
/// # Cancellation safety
/// As [`LogGate::fencing`]: dropped once the write has begun, it fences.
///
/// # Errors
/// The [`Fence`] the engine carries.
async fn write_clean<L: DecisionLog>(
    log: &L,
    gate: &LogGate,
    fence: &FenceCell,
) -> Result<(), Fence> {
    let clean = encode_marker(&RunMarker::Clean);
    gate.fencing(fence, LogCall::WriteMarker, None, || {
        log.write_marker(&clean)
    })
    .await
}

/// The engine's driver (module docs): [`Self::run`] runs every worker.
///
/// The store, the clock and the pause are the seams deciding and
/// publishing use; the start, initialise and the stop use none of them.
/// Initialise uses the cryptographic-randomness seam, and only to create
/// a missing log.
pub struct AuthorityDriver<L, S, C, R, E, P> {
    log: L,
    store: S,
    clock: Arc<C>,
    rng: Mutex<R>,
    secure_random: Mutex<E>,
    pause: P,
    gate: LogGate,
    shared: Arc<Shared>,
    workers: Vec<Worker>,
    end: watch::Sender<Option<RunEnd>>,
}

impl<L, S, C, R, E, P> std::fmt::Debug for AuthorityDriver<L, S, C, R, E, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityDriver")
            .field("workers", &self.workers.len())
            .field("fence", &self.shared.fence.get())
            .finish_non_exhaustive()
    }
}

impl<L, S, C, R, E, P> AuthorityDriver<L, S, C, R, E, P> {
    /// Each volume's state as startup recovery left it, before any worker
    /// has run: the crash harness's `STATE` lines, in volume order. A
    /// volume with no log has one line saying so.
    #[cfg(all(test, feature = "crash-points"))]
    pub(crate) fn recovered(&self) -> Vec<String> {
        self.workers
            .iter()
            .flat_map(worker::Worker::crash_lines)
            .collect()
    }
}

impl<L, S, C, R, E, P> AuthorityDriver<L, S, C, R, E, P>
where
    L: DecisionLog,
    S: RootStore,
    C: Clock,
    R: granary_core::rng::Rng + Send,
    E: granary_core::secure_random::SecureRandom + Send,
    P: Pause,
{
    /// Run every volume's worker until the engine is stopped or fenced,
    /// then write **clean** if it is not fenced (module docs).
    ///
    /// # Cancellation safety
    /// Not cancel-safe: drive it to completion and end it with
    /// [`AuthorityHandle::stop`]. Dropping this future while a log call is
    /// in flight fences the engine. Dropping it while a PUT is in flight
    /// leaves that PUT's fate to the store: the entry stays open in the
    /// log, and the next start's first classification read decides it. Dropped before its **clean** write
    /// begins, it leaves the marker saying **running** under this boot,
    /// so a same-boot restart refuses. Dropped during that write, it
    /// fences, and the marker says **running**, or **clean** if the write
    /// got past its rename: spec §6.2's benign case of a **clean** write
    /// cut short after its rename, which admits a same-boot restart.
    pub async fn run(self) -> RunEnd {
        let Self {
            log,
            store,
            clock,
            rng,
            secure_random,
            pause,
            gate,
            shared,
            workers,
            end,
        } = self;
        let engine = Engine {
            log: &log,
            store: &store,
            clock: clock.as_ref(),
            rng: &rng,
            secure_random: &secure_random,
            pause: &pause,
            gate: &gate,
            shared: &shared,
        };
        JoinAll::new(
            workers
                .into_iter()
                .map(|worker| -> Joined<'_> { Box::pin(worker.run(&engine)) }),
        )
        .await;
        let result = match write_clean(&log, &gate, &shared.fence).await {
            Ok(()) => RunEnd::Stopped,
            Err(fence) => RunEnd::Fenced(fence),
        };
        end.send_replace(Some(result.clone()));
        result
    }
}
