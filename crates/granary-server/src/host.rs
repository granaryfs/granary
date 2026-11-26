// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The publication authority's host: the lifecycle of a server running
//! the engine, from its start to the exit code.
//!
//! [`run_authority_host`] takes its collaborators as parameters: the
//! boot id, the closure that builds and starts the
//! engine, the step that binds and serves, the shutdown trigger and the
//! shutdown budget. It answers the exit code and its reason
//! ([`HostExit`]).
//!
//! # The engine runs on a thread of its own
//!
//! The host spawns one **authority thread** and builds a current-thread
//! runtime on it. The engine closure runs there: it builds the engine's
//! parts (the file log's construction does blocking filesystem work),
//! starts the engine through its [`AuthoritySeat`], and drives the
//! driver's `run()` to its end. The file log's calls block that thread
//! for each flush, so a slow or hung flush blocks only the authority: the
//! host and the serving it polls go on. The host never joins the thread.
//!
//! # Readiness
//!
//! The serve step is called only once the start has returned a handle,
//! and it is given that handle: before then there is no socket, so no
//! request is served before replay.
//!
//! # Shutdown: one budget, from the first cause
//!
//! The host watches, while the start runs and after: the shutdown trigger
//! (signals), the start's post-admission refusal notice, the engine's
//! fence notice, the serving ending on its own, a bind or service
//! construction failing after a start that returned a handle, and the
//! authority thread ending unasked. **The first of these starts the
//! shutdown budget, once; nothing restarts it.** The start is never
//! cancelled: a signal while it runs starts the budget, and the host then
//! ends at the budget's expiry or when the start has finished and the
//! engine has stopped, whichever is first. A start that then succeeds is
//! stopped without ever calling the serve step.
//!
//! On the first cause the host tells the serving to shut down and asks
//! the engine to stop, polling [`AuthorityHandle::stop`] (a stop future
//! merely built asks nothing). The drain and the stop both run under the
//! one budget, and the host ends when both have finished.
//!
//! **The budget's timer is a thread of its own** (a bounded
//! `recv_timeout`), which wakes the host when the budget expires. It
//! fires whatever the runtime's worker threads are doing; it needs only
//! that the host's own task is polled when woken, which holds when the
//! host is driven by `Runtime::block_on` on a thread of its own.
//!
//! # The exit code
//!
//! Decided once, by [`shutdown_exit_code`]'s precedence: a fence observed
//! from any cause is [`EXIT_FENCED`]; otherwise an expired budget is
//! [`EXIT_DEADLINE_EXPIRED`]; otherwise a stop answering
//! [`RunEnd::Stopped`] with a finished drain is [`EXIT_DRAINED`], or
//! [`EXIT_STARTUP_FAILED`] when the cause was a failure after the start
//! was admitted; anything else is
//! [`EXIT_SERVE_FAILED`](crate::EXIT_SERVE_FAILED). The start's own
//! answers map as follows:
//!
//! - a refusal before the marker admitted the start, or parts that could
//!   not be built: [`EXIT_STARTUP_FAILED`] at once, with nothing to stop;
//! - a volume refusing after admission ([`StartRefused::Volume`]):
//!   **clean** was written, so a stopped post-admission failure,
//!   [`EXIT_STARTUP_FAILED`], even when a signal came first;
//! - a fenced start ([`StartRefused::Fenced`]): [`EXIT_FENCED`];
//! - the authority thread ending with no answer (a panic, a seat
//!   dropped): [`EXIT_SERVE_FAILED`](crate::EXIT_SERVE_FAILED).
//!
//! # The caller ends the process at once
//!
//! The host returns without joining the authority thread, which may be
//! blocked in a flush that never returns, and without waiting for
//! connection tasks the serving left behind. The caller must end the
//! process with `std::process::exit` as soon as the host returns, and
//! must not drop a runtime first: its drop waits for its worker threads.

pub(crate) mod boot_id;
pub(crate) mod boot_start;

#[cfg(test)]
mod tests;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use granary_core::clock::Clock;
use granary_core::decisionlog::DecisionLog;
use granary_core::rng::Rng;
use granary_core::rootstore::RootStore;
use granary_core::runmarker::BootId;
use granary_core::secure_random::SecureRandom;
use granary_net::accept::ShutdownOutcome;
use tokio::sync::{oneshot, watch};

use crate::authority::{
    AdmittedRefusal, AuthorityDriver, AuthorityHandle, AuthorityParts, Fence, Notices, Pause,
    RunEnd, ShutdownCause, ShutdownObserved, StartRefused, StopObserved, VolumeConfig,
    shutdown_exit_code, start_observed,
};
use crate::serve::{EXIT_DEADLINE_EXPIRED, EXIT_DRAINED, EXIT_FENCED, EXIT_STARTUP_FAILED};

/// How the host ended: the process's exit code, one of the `EXIT_*`
/// constants, and what ended it, for the caller to report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct HostExit {
    /// The exit code.
    pub code: i32,
    /// Why the host ended, when it ended on a failure or a refusal.
    pub reason: Option<String>,
}

impl HostExit {
    fn refused(reason: String) -> Self {
        Self {
            code: EXIT_STARTUP_FAILED,
            reason: Some(reason),
        }
    }
}

/// What the start told the host.
#[derive(Debug)]
enum Started {
    /// The engine started: its handle.
    Running(AuthorityHandle),
    /// The start refused.
    Refused(StartRefused),
    /// The engine's parts could not be built.
    NotBuilt(String),
}

/// The engine closure's seat on the authority thread: the host's notices,
/// the boot id, and the one way to tell the host how the start went.
/// Consumed by [`Self::start`] or [`Self::not_built`]; dropped unused, it
/// tells the host the start gave no answer.
#[derive(Debug)]
pub struct AuthoritySeat {
    notices: Notices,
    boot: BootId,
    report: oneshot::Sender<Started>,
}

impl AuthoritySeat {
    /// Start the engine over `volumes` with the host's notices and boot
    /// id ([`start_observed`]), and tell the host the result. On success
    /// the driver is returned for the closure to drive to its end on this
    /// thread; the host already holds the handle.
    ///
    /// # Cancellation safety
    /// As [`start_observed`]: drive it to completion.
    pub async fn start<L, S, C, R, E, P>(
        self,
        parts: AuthorityParts<L, S, C, R, E, P>,
        volumes: Vec<VolumeConfig>,
    ) -> Option<AuthorityDriver<L, S, C, R, E, P>>
    where
        L: DecisionLog,
        S: RootStore,
        C: Clock + 'static,
        R: Rng + Send,
        E: SecureRandom + Send,
        P: Pause,
    {
        let Self {
            notices,
            boot,
            report,
        } = self;
        match start_observed(parts, boot, volumes, notices).await {
            Ok((handle, driver)) => {
                let _told = report.send(Started::Running(handle));
                Some(driver)
            }
            Err(refused) => {
                let _told = report.send(Started::Refused(refused));
                None
            }
        }
    }

    /// Tell the host the engine's parts could not be built, and why.
    pub fn not_built(self, reason: impl std::fmt::Display) {
        let _told = self.report.send(Started::NotBuilt(reason.to_string()));
    }
}

/// Run the publication authority's lifecycle (module docs) and answer how
/// it ended.
///
/// - `boot`: the host's boot id ([`crate::host_boot_id`] in production).
/// - `engine`: called once, on the authority thread, with the seat. Its
///   future runs on that thread's current-thread runtime (time and I/O
///   drivers enabled): it builds the parts, calls
///   [`AuthoritySeat::start`] (or [`AuthoritySeat::not_built`]), and
///   drives the returned driver's `run()` to its end.
/// - `serve`: called at most once, on the host's task, only after the
///   start returned a handle: it binds and builds the service over the
///   handle and returns the future that serves until the receiver it is
///   given turns `true`, then drains; or the bind or construction error.
///   Its drain is bounded by the same budget: the caller gives the drain
///   a deadline no shorter than `budget` (the host's timer is the one that
///   decides), and a drain that still ends on its own deadline
///   ([`ShutdownOutcome::DeadlineExpired`]) counts as the budget expiring,
///   [`EXIT_DEADLINE_EXPIRED`].
/// - `trigger`: the shutdown signal, registered by the caller before this
///   call ([`crate::shutdown_trigger`] registers eagerly).
/// - `budget`: the shutdown budget, started at the first cause.
///
/// Drive it with `Runtime::block_on` on a runtime with the time and I/O
/// drivers, from a thread of its own, and end the process with
/// `std::process::exit(exit.code)` as soon as it returns (module docs).
pub async fn run_authority_host<F, Fut, B, BE, SF, T>(
    boot: BootId,
    engine: F,
    serve: B,
    trigger: T,
    budget: Duration,
) -> HostExit
where
    F: FnOnce(AuthoritySeat) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
    B: FnOnce(AuthorityHandle, watch::Receiver<bool>) -> Result<SF, BE>,
    BE: std::fmt::Display,
    SF: Future<Output = std::io::Result<ShutdownOutcome>>,
    T: Future<Output = ()>,
{
    let watchdog = match Watchdog::spawn(budget) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            return HostExit::refused(format!("the shutdown budget's thread: {error}"));
        }
    };
    let notices = Notices::new();
    let fence = notices.fence();
    let fence_now = notices.fence();
    let refusal = notices.refusal();
    let (report, reported) = oneshot::channel();
    let (ended, thread_ended) = oneshot::channel();
    let seat = AuthoritySeat {
        notices,
        boot,
        report,
    };
    if let Err(error) = spawn_authority(engine, seat, ended) {
        return HostExit::refused(format!("the authority's thread: {error}"));
    }
    let (shutdown, _) = watch::channel(false);
    let mut lifecycle = Lifecycle {
        trigger: Some(Box::pin(trigger)),
        watchdog,
        fence: Some(Box::pin(fence_notice(fence))),
        fence_now,
        refusal: Some(Box::pin(refusal_notice(refusal))),
        reported: Some(reported),
        thread_ended: Some(thread_ended),
        serve: Some(serve),
        serving: None,
        shutdown,
        handle: None,
        stop: Stop::NotAsked,
        fenced: false,
        cause: None,
        drain: Drain::Owed,
        ended_unasked: false,
        reason: None,
    };
    // Repeat each poll until a pass moves nothing: a change in one pass
    // (the handle arriving, a stop asked for) can make a future to poll in
    // the next, and each must be polled before the host waits.
    std::future::poll_fn(|cx| {
        loop {
            match lifecycle.step(cx) {
                Pass::Exit(exit) => return Poll::Ready(exit),
                Pass::Moved => {}
                Pass::Idle => return Poll::Pending,
            }
        }
    })
    .await
}

/// What one pass of the host's loop came to.
enum Pass {
    /// Something changed: pass again.
    Moved,
    /// Nothing changed: every future polled has registered its waker.
    Idle,
    /// The host ends.
    Exit(HostExit),
}

/// Spawn the authority thread: a current-thread runtime running
/// `engine(seat)`. `ended` is dropped when the thread ends, however it
/// ends, a panic included.
fn spawn_authority<F, Fut>(
    engine: F,
    seat: AuthoritySeat,
    ended: oneshot::Sender<Infallible>,
) -> std::io::Result<()>
where
    F: FnOnce(AuthoritySeat) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    // `Builder::spawn`, not `std::thread::spawn`: the free function panics
    // when the operating system refuses a thread, and that refusal is a
    // startup failure the caller reports. The handle is dropped: the host
    // never joins this thread.
    let _detached = std::thread::Builder::new()
        .name("granary-authority".to_owned())
        .spawn(move || {
            let _ended = ended;
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    seat.not_built(format!("the authority's runtime: {error}"));
                    return;
                }
            };
            runtime.block_on(engine(seat));
        })?;
    Ok(())
}

/// Resolves with the fence once the engine is fenced, or `None` once no
/// engine can fence any more.
async fn fence_notice(mut fence: watch::Receiver<Option<Fence>>) -> Option<Fence> {
    loop {
        if let Some(fence) = fence.borrow_and_update().clone() {
            return Some(fence);
        }
        if fence.changed().await.is_err() {
            return fence.borrow().clone();
        }
    }
}

/// Resolves `true` once the start reports a post-admission refusal, or
/// `false` once the start has returned without one.
async fn refusal_notice(mut refusal: watch::Receiver<Option<AdmittedRefusal>>) -> bool {
    loop {
        if refusal.borrow_and_update().is_some() {
            return true;
        }
        if refusal.changed().await.is_err() {
            return refusal.borrow().is_some();
        }
    }
}

/// The shutdown budget's timer: a thread that, once armed, waits the
/// budget out with a bounded `recv_timeout` and then wakes the host.
/// Dropping the watchdog ends the thread without firing.
struct Watchdog {
    arm: std::sync::mpsc::Sender<()>,
    armed: bool,
    expiry: Arc<Expiry>,
}

/// Whether the budget has expired, and the host's waker to wake when it
/// does.
#[derive(Default)]
struct Expiry {
    expired: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Expiry {
    fn fire(&self) {
        self.expired.store(true, Ordering::SeqCst);
        let waker = self
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Watchdog {
    fn spawn(budget: Duration) -> std::io::Result<Self> {
        let (arm, armed) = std::sync::mpsc::channel::<()>();
        let expiry = Arc::new(Expiry::default());
        let fired = Arc::clone(&expiry);
        let _detached = std::thread::Builder::new()
            .name("granary-shutdown-budget".to_owned())
            .spawn(move || {
                // Armed once; the host dropping its sender before or
                // during the wait ends this thread without firing.
                if armed.recv().is_ok()
                    && matches!(armed.recv_timeout(budget), Err(RecvTimeoutError::Timeout))
                {
                    fired.fire();
                }
            })?;
        Ok(Self {
            arm,
            armed: false,
            expiry,
        })
    }

    /// Start the budget. Only the first call does anything.
    fn arm(&mut self) {
        if !self.armed {
            self.armed = true;
            let _armed = self.arm.send(());
        }
    }

    /// Whether the budget has expired, as of now.
    fn has_expired(&self) -> bool {
        self.expiry.expired.load(Ordering::SeqCst)
    }

    /// Whether the budget has expired, registering `cx`'s waker first so
    /// an expiry after this check wakes it.
    fn expired(&self, cx: &Context<'_>) -> bool {
        *self
            .expiry
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(cx.waker().clone());
        self.expiry.expired.load(Ordering::SeqCst)
    }
}

type Boxed<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Where the HTTP drain stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drain {
    /// Serving may still hold connections to drain.
    Owed,
    /// No HTTP remains to drain: none was ever served, or the serving
    /// drained after it was told to shut down.
    Done,
    /// The serving's drain ended on its own deadline: the budget's expiry,
    /// as the serving saw it.
    Expired,
}

/// Where the engine's stop stands.
enum Stop {
    /// Not asked for.
    NotAsked,
    /// Asked for: the stop future, polled until it answers.
    Asked(Boxed<RunEnd>),
    /// Answered.
    Answered(StopObserved),
}

/// The host's state after the threads are spawned: what it watches, and
/// what it has observed for the exit code.
struct Lifecycle<B, SF, T> {
    trigger: Option<Pin<Box<T>>>,
    watchdog: Watchdog,
    fence: Option<Boxed<Option<Fence>>>,
    /// The fence as it stands, read when the exit is decided.
    fence_now: watch::Receiver<Option<Fence>>,
    refusal: Option<Boxed<bool>>,
    reported: Option<oneshot::Receiver<Started>>,
    thread_ended: Option<oneshot::Receiver<Infallible>>,
    serve: Option<B>,
    serving: Option<Pin<Box<SF>>>,
    shutdown: watch::Sender<bool>,
    handle: Option<AuthorityHandle>,
    stop: Stop,
    fenced: bool,
    cause: Option<ShutdownCause>,
    drain: Drain,
    ended_unasked: bool,
    reason: Option<String>,
}

impl<B, BE, SF, T> Lifecycle<B, SF, T>
where
    B: FnOnce(AuthorityHandle, watch::Receiver<bool>) -> Result<SF, BE>,
    BE: std::fmt::Display,
    SF: Future<Output = std::io::Result<ShutdownOutcome>>,
    T: Future<Output = ()>,
{
    /// A shutdown cause: the first one starts the budget; every one tells
    /// the serving to shut down and asks a started engine to stop.
    fn begin(&mut self, kind: ShutdownCause) {
        if self.cause.is_none() {
            self.cause = Some(kind);
            self.watchdog.arm();
        }
        self.shutdown.send_replace(true);
        self.request_stop();
    }

    /// Ask a started engine to stop, once. The stop future is polled by
    /// the caller's loop before it next waits, which is what asks.
    fn request_stop(&mut self) {
        if let (Stop::NotAsked, Some(handle)) = (&self.stop, &self.handle) {
            let handle = handle.clone();
            self.stop = Stop::Asked(Box::pin(async move { handle.stop().await }));
        }
    }

    fn note_reason(&mut self, reason: String) {
        if self.reason.is_none() {
            self.reason = Some(reason);
        }
    }

    /// The exit code for what has been observed. The fence and the budget
    /// are read again here, as they stand at the decision: a fence set, or
    /// a budget expired, after this pass polled them but before it decides
    /// still counts, so a run that finished as the deadline passed is
    /// [`EXIT_DEADLINE_EXPIRED`] and a fence is never lost to the race.
    fn decide(&mut self) -> HostExit {
        if self.fence_now.borrow().is_some() {
            self.fenced = true;
        }
        let observed = ShutdownObserved {
            fenced: self.fenced,
            budget_expired: self.watchdog.has_expired() || self.drain == Drain::Expired,
            stop: match self.stop {
                _ if self.ended_unasked => StopObserved::DriverEndedUnexpectedly,
                Stop::Answered(stop) => stop,
                Stop::NotAsked | Stop::Asked(_) => StopObserved::Pending,
            },
            drained: self.drain == Drain::Done,
            cause: self.cause.unwrap_or(ShutdownCause::Signal),
        };
        let code = shutdown_exit_code(&observed);
        let reason = match code {
            EXIT_DRAINED => None,
            EXIT_FENCED => Some("the publication authority fenced".to_owned()),
            EXIT_DEADLINE_EXPIRED => Some("the shutdown budget expired".to_owned()),
            _ => self.reason.take(),
        };
        HostExit { code, reason }
    }

    /// The start's answer. `Some` ends the host at once.
    fn started(&mut self, answer: Result<Started, oneshot::error::RecvError>) -> Option<HostExit> {
        match answer {
            Err(_) => {
                self.ended_unasked = true;
                self.note_reason("the authority thread ended without a start result".to_owned());
                Some(self.decide())
            }
            Ok(Started::NotBuilt(reason)) => Some(HostExit::refused(reason)),
            Ok(Started::Refused(refused @ StartRefused::Volume { .. })) => {
                // Clean was written before this answer: a stopped
                // failure after admission, whatever came first.
                self.cause = Some(ShutdownCause::StartupFailedAfterAdmission);
                self.stop = Stop::Answered(StopObserved::Stopped);
                self.drain = Drain::Done;
                self.note_reason(refused.to_string());
                Some(self.decide())
            }
            Ok(Started::Refused(StartRefused::Fenced(_))) => {
                self.fenced = true;
                Some(self.decide())
            }
            Ok(Started::Refused(refused)) => Some(HostExit::refused(refused.to_string())),
            Ok(Started::Running(handle)) => {
                self.handle = Some(handle.clone());
                if self.cause.is_some() {
                    // A cause came while the start ran: stop the engine and
                    // never serve.
                    self.drain = Drain::Done;
                    self.request_stop();
                    return None;
                }
                // The serve step is taken once, here; the start answers
                // once, so it is always present.
                if let Some(serve) = self.serve.take() {
                    match serve(handle, self.shutdown.subscribe()) {
                        Ok(serving) => self.serving = Some(Box::pin(serving)),
                        Err(error) => {
                            self.note_reason(error.to_string());
                            self.drain = Drain::Done;
                            self.begin(ShutdownCause::StartupFailedAfterAdmission);
                        }
                    }
                }
                None
            }
        }
    }

    /// One pass over everything the host watches, biased in this order:
    /// the fence, the budget, the trigger, the refusal notice, the start's
    /// answer, the thread's end, the serving, the stop.
    fn step(&mut self, cx: &mut Context<'_>) -> Pass {
        let mut moved = false;
        if let Some(fence) = self.fence.as_mut()
            && let Poll::Ready(seen) = fence.as_mut().poll(cx)
        {
            self.fence = None;
            moved = true;
            if seen.is_some() {
                self.fenced = true;
                self.begin(ShutdownCause::Signal);
            }
        }
        if self.watchdog.expired(cx) {
            return Pass::Exit(self.decide());
        }
        if let Some(trigger) = self.trigger.as_mut()
            && trigger.as_mut().poll(cx).is_ready()
        {
            self.trigger = None;
            moved = true;
            self.begin(ShutdownCause::Signal);
        }
        if let Some(refusal) = self.refusal.as_mut()
            && let Poll::Ready(seen) = refusal.as_mut().poll(cx)
        {
            self.refusal = None;
            moved = true;
            if seen {
                self.begin(ShutdownCause::StartupFailedAfterAdmission);
            }
        }
        if let Some(reported) = self.reported.as_mut()
            && let Poll::Ready(answer) = Pin::new(reported).poll(cx)
        {
            self.reported = None;
            moved = true;
            if let Some(exit) = self.started(answer) {
                return Pass::Exit(exit);
            }
        }
        if self.reported.is_none()
            && let Some(ended) = self.thread_ended.as_mut()
            && Pin::new(ended).poll(cx).is_ready()
        {
            self.thread_ended = None;
            moved = true;
            if matches!(self.stop, Stop::NotAsked) {
                self.ended_unasked = true;
                self.note_reason("the authority's driver ended unasked".to_owned());
                self.begin(ShutdownCause::Signal);
            }
        }
        if let Some(serving) = self.serving.as_mut()
            && let Poll::Ready(served) = serving.as_mut().poll(cx)
        {
            self.serving = None;
            moved = true;
            let asked = *self.shutdown.borrow();
            match served {
                Ok(ShutdownOutcome::Drained) if asked => self.drain = Drain::Done,
                Ok(ShutdownOutcome::Drained) => {
                    self.note_reason("serving ended unasked".to_owned());
                }
                Ok(ShutdownOutcome::DeadlineExpired) => self.drain = Drain::Expired,
                Err(error) => self.note_reason(format!("serving failed: {error}")),
            }
            self.begin(ShutdownCause::Signal);
        }
        if let Stop::Asked(stopping) = &mut self.stop
            && let Poll::Ready(end) = stopping.as_mut().poll(cx)
        {
            moved = true;
            self.stop = Stop::Answered(match end {
                RunEnd::Stopped => StopObserved::Stopped,
                // The fence decides the code; the stop did answer.
                RunEnd::Fenced(_) => {
                    self.fenced = true;
                    StopObserved::Stopped
                }
                RunEnd::Abandoned => {
                    self.note_reason("the authority's driver was dropped unfinished".to_owned());
                    StopObserved::Abandoned
                }
            });
        }
        if self.reported.is_none()
            && self.cause.is_some()
            && matches!(self.stop, Stop::Answered(_))
            && self.serving.is_none()
        {
            return Pass::Exit(self.decide());
        }
        if moved { Pass::Moved } else { Pass::Idle }
    }
}
