// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Another writer's head, observed at a view boundary: one probe of the
//! authority's head at a time, and the adoption it leads to.
//!
//! A boundary starts an observation only when none is in flight, so the
//! probe that answers it began after its request; a boundary that finds one
//! in flight is served at once on the view the mount has. An observation
//! runs on the sync runtime to its end, so one whose boundary stopped
//! waiting still installs, and the next boundary finds it.

use super::engine::{Adopted, HeadAdopter};
use super::{SyncRuntime, SyncRuntimeError, refused};
use crate::{CoordinationError, ViewCause, ViewOutcome};
use granary_core::{root::VolumeName, rootstore::RootStore};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

/// How long a view boundary waits, from its request, for the observation it
/// started: the probe of the authority's head and the adoption it leads to.
pub(crate) const VIEW_PROBE_DEADLINE: Duration = Duration::from_secs(2);

/// Maximum backoff between background reachability probes while the mount is
/// in the unreachable state.
const PROBE_BACKOFF_CAP: Duration = Duration::from_secs(5);

/// Reachability of the authority as of the latest completed probe or landed
/// refresh.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Reach {
    #[default]
    Reachable,
    Unreachable {
        since: i64,
        pinned: u64,
    },
}

impl Reach {
    const fn pinned(self) -> u64 {
        match self {
            Self::Reachable => 0,
            Self::Unreachable { pinned, .. } => pinned,
        }
    }
}

/// How `HeadObserver::begin` answers a boundary request.
pub(crate) enum Begin<F> {
    Idle,
    Unreachable,
    InFlight(tokio::sync::watch::Receiver<u64>),
    Started(F),
}

/// How an observation that reached an answer ended. An `Err` beside it is
/// "no answer yet": the probe, the root read or a transient adoption step
/// failed, and nothing is latched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Observed {
    /// The mount now serves the head at this seq.
    Installed(u64),
    /// No head above the pin that was not already refused.
    Unchanged,
    /// The mount holds work of its own, so it keeps its view.
    Deferred(u64),
    /// The last observation deferred and a writer is still held: the store
    /// was checked and no probe sent, so the deferral goes on unreported.
    StillDeferred,
    /// The head at this seq can never be adopted.
    HeadRefused(u64),
    /// The probe proved the authority's transport down while serving the
    /// pin at this seq.
    Unreachable(u64),
    /// A landing made the probe's transport answer older than the current
    /// view, so the answer changed no state.
    Discarded,
    /// The view is closed and revoked; nothing is observed again. An
    /// adoption's close carries its head's seq; a dead store's close, which
    /// adopted and refused no head, carries none.
    Closed(Option<u64>),
}

/// An observation's answer, or the runtime's loss of it.
pub(crate) type Observation = Result<Result<Observed, CoordinationError>, SyncRuntimeError>;

/// The observer's state, under one mutex that is never held across a wait.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent state latches: in-flight observation, background prober, deferred pickup, and closed view"
)]
struct State {
    /// An observation runs now.
    in_flight: bool,
    /// Reachability of the authority as of the latest completed probe or
    /// landed refresh.
    reach: Reach,
    /// A background prober is running.
    prober: bool,
    /// The highest head seq whose adoption was refused.
    refused_through: u64,
    /// The last observation deferred, so a further deferral is not reported.
    deferring: bool,
    /// A closed view never reopens, so neither does observation.
    closed: bool,
    /// How many observations have completed.
    completed: u64,
    /// How many landed roots have reached the observer.
    landings: u64,
}

/// Observes the authority's head for a writable mount and adopts a newer
/// one through the engine, once the binding arms it.
pub(crate) struct HeadObserver<R, E> {
    remote: Arc<R>,
    runtime: Arc<E>,
    volume: VolumeName,
    wall: Arc<dyn granary_core::clock::Clock>,
    mode: crate::ViewMode,
    metrics: Option<crate::ClientMetrics>,
    /// Armed by the binding that sets the engine's view hook. Unarmed, no
    /// boundary observes anything.
    adopter: OnceLock<Arc<dyn HeadAdopter>>,
    state: Mutex<State>,
    settled: tokio::sync::watch::Sender<u64>,
    #[cfg(test)]
    before_prober_return: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl<R, E> std::fmt::Debug for HeadObserver<R, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadObserver")
            .field("armed", &self.adopter.get().is_some())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// An observation's in-flight mark: cleared with its answer, or, for a task
/// the runtime dropped before it answered, when the task is dropped.
struct InFlight<R, E> {
    observer: Option<Arc<HeadObserver<R, E>>>,
    landings: u64,
}
impl<R, E> InFlight<R, E>
where
    R: RootStore + 'static,
    E: SyncRuntime + 'static,
{
    fn complete(mut self, result: &Result<Observed, CoordinationError>) -> bool {
        if let Some(observer) = self.observer.take() {
            observer.complete(result, self.landings)
        } else {
            false
        }
    }
}
impl<R, E> Drop for InFlight<R, E> {
    fn drop(&mut self) {
        if let Some(observer) = self.observer.take() {
            observer.state().in_flight = false;
            observer.settled.send_modify(|n| *n = n.wrapping_add(1));
        }
    }
}

/// A background prober's running mark: cleared in the lock acquisition where
/// the prober observes or establishes reachability, or, for a prober that
/// unwinds or is dropped, when the task is dropped.
struct ProberGuard<R, E>(Option<Arc<HeadObserver<R, E>>>);
impl<R, E> Drop for ProberGuard<R, E> {
    fn drop(&mut self) {
        if let Some(observer) = self.0.take() {
            observer.state().prober = false;
        }
    }
}

impl<R, E> HeadObserver<R, E> {
    pub(crate) fn new(
        remote: Arc<R>,
        runtime: Arc<E>,
        volume: VolumeName,
        wall: Arc<dyn granary_core::clock::Clock>,
        mode: crate::ViewMode,
        metrics: Option<crate::ClientMetrics>,
    ) -> Self {
        Self {
            remote,
            runtime,
            volume,
            wall,
            mode,
            metrics,
            adopter: OnceLock::new(),
            state: Mutex::default(),
            settled: tokio::sync::watch::channel(0).0,
            #[cfg(test)]
            before_prober_return: Mutex::default(),
        }
    }

    /// Arm the observer with the engine it adopts through. The first arming
    /// stands; `false` when it was already armed.
    pub(crate) fn arm(&self, adopter: Arc<dyn HeadAdopter>) -> bool {
        self.adopter.set(adopter).is_ok()
    }

    pub(crate) fn label(&self) -> Option<Result<Vec<u8>, granary_fuse::MountError>> {
        let adopter = self.adopter.get()?;
        let (closed, reach) = {
            let state = self.state();
            (state.closed, state.reach)
        };
        if closed {
            return Some(Err(granary_fuse::MountError::Io));
        }
        let Ok((_, pin)) = adopter.pin() else {
            return Some(Err(granary_fuse::MountError::Io));
        };
        Some(Ok(match reach {
            Reach::Reachable => format!("fresh:{pin}").into_bytes(),
            Reach::Unreachable { since, .. } => {
                let since = since.max(0);
                format!("stale:{pin}:{since}").into_bytes()
            }
        }))
    }

    pub(crate) fn unconfirmed(&self) -> bool {
        self.mode == crate::ViewMode::Strict
            && matches!(self.state().reach, Reach::Unreachable { .. })
    }

    pub(crate) fn reached(&self, seq: u64) {
        let mut state = self.state();
        state.landings += 1;
        if !state.closed && matches!(state.reach, Reach::Unreachable { .. }) {
            state.reach = Reach::Reachable;
            if let Some(metrics) = &self.metrics {
                metrics.set_view_stale(false);
            }
            crate::observe::mount_view(ViewCause::Landed, ViewOutcome::Fresh, seq);
        }
    }

    #[cfg(test)]
    pub(crate) fn unreachable_for_test(&self) -> bool {
        matches!(self.state().reach, Reach::Unreachable { .. })
    }

    #[cfg(test)]
    pub(crate) fn prober_for_test(&self) -> bool {
        self.state().prober
    }

    #[cfg(test)]
    pub(crate) fn before_prober_return_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .before_prober_return
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn close_for_test(&self) {
        self.state().closed = true;
    }

    #[cfg(test)]
    pub(crate) fn landings_for_test(&self) -> u64 {
        self.state().landings
    }

    #[cfg(test)]
    pub(crate) fn in_flight_for_test(&self) -> bool {
        self.state().in_flight
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The highest refused head seq, the closed latch and the count of
    /// completed observations.
    #[cfg(test)]
    pub(crate) fn state_for_test(&self) -> (u64, bool, u64) {
        let state = self.state();
        (state.refused_through, state.closed, state.completed)
    }
}

impl<R, E> HeadObserver<R, E>
where
    R: RootStore + 'static,
    E: SyncRuntime + 'static,
{
    #[cfg(test)]
    pub(crate) fn complete_for_test(
        self: &Arc<Self>,
        result: &Result<Observed, CoordinationError>,
    ) {
        let landings = self.state().landings;
        self.complete(result, landings);
    }

    /// Publish an observation's answer: clear its in-flight mark, count it,
    /// latch what it decided, and report it once.
    fn complete(
        self: &Arc<Self>,
        result: &Result<Observed, CoordinationError>,
        landings: u64,
    ) -> bool {
        let mut spawn_prober = false;
        let mut discarded = false;
        let answered = matches!(
            result,
            Ok(Observed::Installed(_)
                | Observed::Unchanged
                | Observed::Deferred(_)
                | Observed::StillDeferred
                | Observed::HeadRefused(_))
        );
        let report = {
            let mut state = self.state();
            state.in_flight = false;
            state.completed += 1;
            match *result {
                Ok(Observed::Installed(seq)) => {
                    state.deferring = false;
                    Some((ViewOutcome::Installed, seq))
                }
                Ok(Observed::Unchanged) => {
                    // The pin has caught up with the head.
                    state.deferring = false;
                    None
                }
                Ok(Observed::Deferred(seq)) => (!std::mem::replace(&mut state.deferring, true))
                    .then_some((ViewOutcome::Deferred, seq)),
                Ok(Observed::StillDeferred | Observed::Discarded) | Err(_) => None,
                Ok(Observed::Unreachable(pin)) => {
                    discarded = landings != state.landings;
                    if !state.closed && matches!(state.reach, Reach::Reachable) && !discarded {
                        let since = self.wall.now().secs;
                        state.reach = Reach::Unreachable { since, pinned: pin };
                        if !state.prober {
                            state.prober = true;
                            spawn_prober = true;
                        }
                        if let Some(metrics) = &self.metrics {
                            metrics.set_view_stale(true);
                        }
                        crate::observe::mount_view(ViewCause::Adopted, ViewOutcome::Stale, pin);
                        crate::LocalReport::view_stale(self.volume.clone(), pin, since.max(0))
                            .emit();
                        if self.mode == crate::ViewMode::Strict {
                            crate::observe::op_failed(
                                crate::OperationKind::View,
                                crate::FailureClass::Unavailable,
                            );
                        }
                    }
                    None
                }
                Ok(Observed::HeadRefused(seq)) => {
                    state.deferring = false;
                    state.refused_through = state.refused_through.max(seq);
                    Some((ViewOutcome::Refused, seq))
                }
                Ok(Observed::Closed(seq)) => {
                    state.deferring = false;
                    state.closed = true;
                    seq.map(|seq| (ViewOutcome::Refused, seq))
                }
            }
        };
        self.settled.send_modify(|n| *n = n.wrapping_add(1));
        if let Some((outcome, seq)) = report {
            crate::observe::mount_view(ViewCause::Adopted, outcome, seq);
        }
        if answered && let Some(adopter) = self.adopter.get() {
            adopter.answered();
        }
        if spawn_prober {
            self.spawn_prober();
        }
        discarded
    }

    /// Spawn the prober. Its guard is taken before the task, so a task the
    /// runtime drops before its first poll still clears `prober`.
    fn spawn_prober(self: &Arc<Self>) {
        let guard = ProberGuard(Some(self.clone()));
        drop(self.runtime.spawn(self.clone().reprobe(guard)));
    }

    async fn reprobe(self: Arc<Self>, mut guard: ProberGuard<R, E>) {
        let mut delay = crate::fetcher::UNAVAILABLE_RETRY_DELAY;
        loop {
            self.runtime.sleep(delay).await;
            let landings = {
                let mut state = self.state();
                if matches!(state.reach, Reach::Reachable) {
                    state.prober = false;
                    guard.0 = None;
                    return;
                }
                state.landings
            };
            match self.remote.max_seq(self.volume.as_str()).await {
                Ok(_) => {
                    let retry = {
                        let mut state = self.state();
                        if landings != state.landings
                            && matches!(state.reach, Reach::Unreachable { .. })
                        {
                            true
                        } else {
                            state.prober = false;
                            guard.0 = None;
                            if matches!(state.reach, Reach::Unreachable { .. }) {
                                let pinned = state.reach.pinned();
                                state.reach = Reach::Reachable;
                                crate::observe::mount_view(
                                    ViewCause::Adopted,
                                    ViewOutcome::Fresh,
                                    pinned,
                                );
                                if let Some(metrics) = &self.metrics {
                                    metrics.set_view_stale(false);
                                }
                            }
                            false
                        }
                    };
                    if let Some(adopter) = self.adopter.get() {
                        adopter.answered();
                    }
                    if retry {
                        continue;
                    }
                    #[cfg(test)]
                    if let Some(hook) = self
                        .before_prober_return
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take()
                    {
                        hook();
                    }
                    return;
                }
                Err(_) => delay = (delay * 2).min(PROBE_BACKOFF_CAP),
            }
        }
    }

    /// Begin a boundary's observation in one lock acquisition, reading
    /// `writers` only when an observation starts.
    pub(crate) fn begin(
        self: &Arc<Self>,
        writers: &dyn Fn() -> bool,
    ) -> Begin<impl Future<Output = Observation> + use<R, E> + Send + 'static> {
        let Some(adopter) = self.adopter.get().cloned() else {
            return Begin::Idle;
        };
        let deferring;
        let landings;
        let mut spawn_prober = false;
        {
            let mut state = self.state();
            if state.closed {
                return Begin::Idle;
            }
            if matches!(state.reach, Reach::Unreachable { .. }) {
                if !state.prober {
                    state.prober = true;
                    spawn_prober = true;
                }
                drop(state);
                if spawn_prober {
                    self.spawn_prober();
                }
                return Begin::Unreachable;
            }
            if state.in_flight {
                return Begin::InFlight(self.settled.subscribe());
            }
            state.in_flight = true;
            deferring = state.deferring;
            landings = state.landings;
        }
        let writers = writers();
        let held = writers && deferring;
        let flight = InFlight {
            observer: Some(self.clone()),
            landings,
        };
        let (observer, runtime) = (self.clone(), self.runtime.clone());
        Begin::Started(async move {
            runtime
                .spawn(async move {
                    let result = if held {
                        observer.held(&*adopter).await
                    } else {
                        observer.observation(&*adopter, writers).await
                    };
                    if flight.complete(&result) {
                        Ok(Observed::Discarded)
                    } else {
                        result
                    }
                })
                .await
        })
    }

    /// Start an observation for a boundary whose adapter holds a
    /// write-capable descriptor when `writers`. `None` when the observer is
    /// unarmed, its view closed, in the unreachable state, or an observation
    /// is already in flight: the boundary is then served at once. The returned
    /// future spawns the observation on the sync runtime when first polled, so
    /// a caller that stops waiting for it stops nothing.
    #[cfg(test)]
    pub(crate) fn observe(
        self: &Arc<Self>,
        writers: bool,
    ) -> Option<impl Future<Output = Observation> + use<R, E> + Send + 'static> {
        match self.begin(&move || writers) {
            Begin::Started(observation) => Some(observation),
            Begin::Idle | Begin::Unreachable | Begin::InFlight(_) => None,
        }
    }

    /// Probe the head, compare it with the pin, check the advisory
    /// precondition before any network read, then adopt.
    async fn observation(
        &self,
        adopter: &dyn HeadAdopter,
        writers: bool,
    ) -> Result<Observed, CoordinationError> {
        let head = match self.remote.max_seq(self.volume.as_str()).await {
            Ok(head) => head,
            Err(error) if crate::resolve::is_transport_down(&error) => {
                return match adopter.pin() {
                    Ok((_, pin)) => Ok(Observed::Unreachable(pin)),
                    Err(error) => Self::close(adopter, error).await,
                };
            }
            Err(_) => return Err(refused("ViewRootUnavailable")),
        };
        // A store that refuses its own base or its check is poisoned,
        // fenced or in a commit conflict, and serves nothing: as for a
        // landing, the view is closed.
        let pin = match adopter.pin() {
            Ok((_, pin)) => pin,
            Err(error) => return Self::close(adopter, error).await,
        };
        let refused_through = self.state().refused_through;
        let Some(seq) = head.filter(|seq| *seq > pin && *seq > refused_through) else {
            return Ok(Observed::Unchanged);
        };
        let blocked = writers
            || match adopter.adoption_blocked() {
                Ok(blocked) => blocked,
                Err(error) => return Self::close(adopter, error).await,
            };
        if blocked {
            return Ok(Observed::Deferred(seq));
        }
        Ok(match adopter.adopt(seq).await? {
            Adopted::Installed => Observed::Installed(seq),
            Adopted::Deferred => Observed::Deferred(seq),
            Adopted::Refused { .. } => match adopter.pin() {
                // The mount's own landing reached the head after the pin was
                // read: nothing was refused, and nothing is latched.
                Ok((_, pin)) if pin >= seq => Observed::Unchanged,
                Ok(_) => Observed::HeadRefused(seq),
                Err(error) => return Self::close(adopter, error).await,
            },
            Adopted::Closed => Observed::Closed(Some(seq)),
        })
    }

    /// A held writer's next deferral: the store's own check, then one probe
    /// classified as `observation` does, skipping adoption reads.
    async fn held(&self, adopter: &dyn HeadAdopter) -> Result<Observed, CoordinationError> {
        let pin = match adopter.pin() {
            Ok((_, pin)) => pin,
            Err(error) => return Self::close(adopter, error).await,
        };
        match self.remote.max_seq(self.volume.as_str()).await {
            Ok(_) => Ok(Observed::StillDeferred),
            Err(error) if crate::resolve::is_transport_down(&error) => {
                Ok(Observed::Unreachable(pin))
            }
            Err(_) => Err(refused("ViewRootUnavailable")),
        }
    }

    /// Close the view over a dead store. Only a close that ran under the
    /// gate is `Closed`; one that failed before it closed nothing, so it is
    /// "no answer yet" and the next boundary tries it again. The close
    /// reports its own `op.failed{kind=view}`; no head was adopted or
    /// refused, so it carries no head seq.
    async fn close(
        adopter: &dyn HeadAdopter,
        error: CoordinationError,
    ) -> Result<Observed, CoordinationError> {
        adopter.close(error).await.map(|()| Observed::Closed(None))
    }
}
