// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Demand-driven grant application. A published-verdict cache never holds its
//! lock across I/O. One cancellation-safe blocking refresh runs at a time;
//! waiters join it, but accept only a refresh begun after their arrival. The
//! enrollment lookup deadline bounds waiting. A stall suspends capture without
//! retirement, publishing a stalled reason while the request proceeds with its
//! authorization unaffected. Only the flight that timed out can suspend capture;
//! its pending refresh still applies on completion.
//! No background watcher, timer or signal initiates refreshes.
//!
//! Protected content evidence clears capture and retires the high-water
//! generation, which may exceed the refused file's generation. I/O
//! failure suspends it without removing slots, so recovery cannot reset budgets
//! or expiry. Revision history and last accepted bytes are bounded to one record.
//! Only this coordinator applies persistent grants to the capture handle.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use granary_core::clock::Clock;
use granary_core::debug_grant::{DebugGrant, GrantAction, GrantScope, Incarnation, decode_grant};
use tokio::sync::watch;

use super::ServerIncarnation;
use super::clock::{ClockFailure, GrantClock};
use super::verbs::{FileRead, NAME, included, read_file};
use crate::diagnostics::{
    CaptureEntry, CaptureError, CaptureHandle, CaptureKind, CaptureRevision, CaptureSelector,
    CaptureSlot, CaptureUnsupported, Expiry,
};
use crate::enrollment::Identity;
use crate::enrollment::{LOOKUP_DEADLINE, ReaderStartError};
use crate::protected_dir::{DirOps, NixOps, ProtectedDir};

/// A fixed reason suitable for a local observation or transition record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    Missing,
    Unreadable,
    Stalled,
    Unprotected,
    Oversize,
    Corrupt,
    Directory,
    StaleIncarnation,
    FutureIssued,
    Expired,
    Rollback,
    RevisionConflict,
    Widening,
    Retired,
    Revoked,
    Clock(ClockFailure),
    Capture(CaptureError),
    SlotOverflow,
}

impl Reason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::Stalled => "stalled",
            Self::Unprotected => "unprotected",
            Self::Oversize => "oversize",
            Self::Corrupt => "corrupt",
            Self::Directory => "directory",
            Self::StaleIncarnation => "stale-incarnation",
            Self::FutureIssued => "future-issued",
            Self::Expired => "already-expired",
            Self::Rollback => "rollback",
            Self::RevisionConflict => "equal-revision-different-bytes",
            Self::Widening => "widening",
            Self::Retired => "retired-generation",
            Self::Revoked => "revoked",
            Self::Clock(reason) => reason.as_str(),
            Self::Capture(CaptureError::Unsupported(reason)) => match reason {
                CaptureUnsupported::ContextualCeiling => "unsupported-contextual-ceiling",
                CaptureUnsupported::Ceiling => "unsupported-host-ceiling",
                CaptureUnsupported::Instrumentation => "unsupported-instrumentation",
                CaptureUnsupported::Producer => "unsupported-producer",
                CaptureUnsupported::Clock => "unsupported-capture-clock",
            },
            Self::Capture(_) => "capture-refused",
            Self::SlotOverflow => "slot-overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReaderState {
    Unread,
    Disabled(Reason),
    Applied,
}

/// Saturating process counters; repeated cached content verdicts count refusals,
/// while applications and retirements count transitions only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReaderCounters {
    pub refreshes: u64,
    pub reloads: u64,
    pub refusals: u64,
    pub unreadable: u64,
    pub stalled: u64,
    pub applications: u64,
    pub retirements: u64,
}

/// Cached metadata at the last completed refresh or deadline suspension.
/// `accepted` is history, not live capture: capture independently
/// observes expiry and failure.
/// The observed record retains the received incarnation for stale diagnostics.
#[derive(Clone, Debug)]
pub(crate) struct ReaderSnapshot {
    pub(crate) incarnation: Incarnation,
    pub(crate) state: ReaderState,
    pub(crate) future_issued_lead_secs: Option<u64>,
    pub(crate) sequence: u64,
    pub(crate) observed: Option<Arc<DebugGrant>>,
    pub(crate) accepted: Option<Arc<DebugGrant>>,
    pub(crate) slot: Option<CaptureSlot>,
    pub(crate) capture_revision: CaptureRevision,
    pub(crate) high_revision: u64,
    pub(crate) high_generation: u64,
    pub(crate) retired_generation: u64,
    pub(crate) counters: ReaderCounters,
}

#[derive(Debug, Default)]
struct Counters {
    refreshes: AtomicU64,
    reloads: AtomicU64,
    refusals: AtomicU64,
    unreadable: AtomicU64,
    stalled: AtomicU64,
    applications: AtomicU64,
    retirements: AtomicU64,
}

fn increment(counter: &AtomicU64) {
    let _updated = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

impl Counters {
    fn snapshot(&self) -> ReaderCounters {
        let read = |c: &AtomicU64| c.load(Ordering::Relaxed);
        ReaderCounters {
            refreshes: read(&self.refreshes),
            reloads: read(&self.reloads),
            refusals: read(&self.refusals),
            unreadable: read(&self.unreadable),
            stalled: read(&self.stalled),
            applications: read(&self.applications),
            retirements: read(&self.retirements),
        }
    }
}

#[derive(Clone, Debug)]
struct Decoded {
    grant: Arc<DebugGrant>,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Failure {
    reason: Reason,
    evidence: bool,
    future_issued_lead_secs: Option<u64>,
}

impl Failure {
    fn content(reason: Reason) -> Self {
        Self {
            reason,
            evidence: true,
            future_issued_lead_secs: None,
        }
    }
    fn transient(reason: Reason) -> Self {
        Self {
            reason,
            evidence: false,
            future_issued_lead_secs: None,
        }
    }
}

type Verdict = Result<Arc<Decoded>, Failure>;

#[derive(Debug)]
struct Held {
    // Keep the inode allocated, so atomic replacement always changes identity.
    _file: File,
    identity: Identity,
    verdict: Verdict,
}

#[derive(Debug)]
struct Accepted {
    decoded: Arc<Decoded>,
    slot: CaptureSlot,
}

#[derive(Debug, Default)]
struct History {
    revision: u64,
    generation: u64,
    retired: u64,
    next_slot: u64,
    last: Option<Accepted>,
    applied: bool,
    retained: bool,
    capture_revision: CaptureRevision,
}

#[derive(Debug)]
struct Flight {
    start: u64,
    done: watch::Receiver<Option<()>>,
    joins: u64,
    completed: bool,
}

#[derive(Debug)]
struct Inner<O: DirOps> {
    ops: O,
    path: PathBuf,
    dir: ProtectedDir,
    incarnation: ServerIncarnation,
    clock: GrantClock,
    capture: CaptureHandle,
    directory_lost: AtomicBool,
    started: AtomicU64,
    held: Mutex<Option<Held>>,
    history: Mutex<History>,
    flight: Mutex<Option<Flight>>,
    published: Mutex<ReaderSnapshot>,
    counters: Counters,
    #[cfg(test)]
    pause: Mutex<Option<Arc<crate::protected_dir::tests::Pause>>>,
    #[cfg(test)]
    completion_pause: Mutex<Option<Arc<crate::protected_dir::tests::Pause>>>,
    #[cfg(test)]
    observations: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Clones share the coordinator, protected descriptor and published state.
#[derive(Debug)]
pub(crate) struct DebugGrantReader<O: DirOps = NixOps>(Arc<Inner<O>>);

impl<O: DirOps> Clone for DebugGrantReader<O> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl DebugGrantReader {
    /// Walk and hold the protected directory on the startup thread. No grant
    /// file is applied until the first demand refresh; initial state is unread.
    pub(crate) fn open(
        path: &Path,
        accept_unsupported_filesystem: bool,
        incarnation: ServerIncarnation,
        clock: GrantClock,
        capture: CaptureHandle,
    ) -> Result<Self, ReaderStartError> {
        Self::open_on(
            NixOps,
            path,
            accept_unsupported_filesystem,
            incarnation,
            clock,
            capture,
        )
    }
}

impl<O: DirOps> DebugGrantReader<O> {
    pub(super) fn open_on(
        ops: O,
        path: &Path,
        accept_unsupported_filesystem: bool,
        incarnation: ServerIncarnation,
        clock: GrantClock,
        capture: CaptureHandle,
    ) -> Result<Self, ReaderStartError> {
        let dir = ProtectedDir::for_server(&ops, path, accept_unsupported_filesystem)
            .map_err(ReaderStartError::Directory)?;
        match ops.stat_at(&dir.dir, NAME) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ReaderStartError::NotSearchable {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
        let revision = capture.snapshot().revision;
        let published = ReaderSnapshot {
            incarnation: incarnation.value(),
            state: ReaderState::Unread,
            future_issued_lead_secs: None,
            sequence: 0,
            observed: None,
            accepted: None,
            slot: None,
            capture_revision: revision,
            high_revision: 0,
            high_generation: 0,
            retired_generation: 0,
            counters: ReaderCounters::default(),
        };
        Ok(Self(Arc::new(Inner {
            ops,
            path: path.to_path_buf(),
            dir,
            incarnation,
            clock,
            capture,
            directory_lost: AtomicBool::new(false),
            started: AtomicU64::new(0),
            held: Mutex::new(None),
            history: Mutex::new(History {
                capture_revision: revision,
                ..History::default()
            }),
            flight: Mutex::new(None),
            published: Mutex::new(published),
            counters: Counters::default(),
            #[cfg(test)]
            pause: Mutex::new(None),
            #[cfg(test)]
            completion_pause: Mutex::new(None),
            #[cfg(test)]
            observations: AtomicU64::new(0),
        })))
    }

    /// Await a refresh begun after arrival, bounded by the enrollment deadline.
    /// A deadline suspends capture without retiring its slot or resetting its
    /// budget or expiry latch, publishing a stalled reason. The request proceeds
    /// with its authorization unaffected. The pending refresh still applies on
    /// completion; unchanged valid bytes resume the same slot.
    ///
    /// # Cancellation safety
    /// Dropping this future never cancels its blocking refresh or application.
    pub(crate) async fn refresh(&self) -> ReaderSnapshot {
        let arrival = self.0.started.load(Ordering::SeqCst);
        let mut pending = None;
        if tokio::time::timeout(LOOKUP_DEADLINE, self.refreshed_after(arrival, &mut pending))
            .await
            .is_err()
        {
            increment(&self.0.counters.stalled);
            if let Some(start) = pending {
                self.0.suspend_stalled(start);
            }
        }
        self.snapshot()
    }

    /// Initiate or join demand work without waiting for it.
    pub(crate) fn trigger(&self) {
        let _flight = self.join_or_start();
    }

    /// Filesystem-independent published state, available during stalled I/O.
    pub(crate) fn snapshot(&self) -> ReaderSnapshot {
        let mut snapshot = lock(&self.0.published).clone();
        snapshot.counters = self.0.counters.snapshot();
        snapshot
    }

    /// Coherent metadata and effective capture revision, without filesystem work.
    pub(crate) fn observation(&self) -> super::DebugGrantSnapshot {
        let mut notices = Vec::new();
        let history = lock(&self.0.history);
        let reader = self.snapshot();
        let capture = self.0.capture.snapshot_deferred(&mut notices);
        let effective = capture
            .entries
            .into_iter()
            .find(|entry| Some(entry.slot) == reader.slot);
        let reason =
            match reader.state {
                ReaderState::Disabled(reason) => Some(reason.as_str()),
                _ if effective.is_none() && reader.state == ReaderState::Applied => {
                    if capture.poisoned {
                        Some("capture-refused")
                    } else if let Some(failure) = self.0.clock.failure() {
                        // A failed clock is frozen at its last valid reading. That
                        // reading still proves expiry and takes precedence over
                        // the failure code, without consulting the source again.
                        Some(
                            if reader.accepted.as_ref().is_some_and(|grant| {
                                self.0.clock.now() >= grant.fields().expires_at
                            }) {
                                "expired"
                            } else {
                                failure.as_str()
                            },
                        )
                    } else {
                        Some("expired")
                    }
                }
                _ => self.0.clock.failure().map(ClockFailure::as_str),
            };
        let snapshot = super::DebugGrantSnapshot {
            incarnation: reader.incarnation,
            state: match reader.state {
                ReaderState::Unread => "unread",
                ReaderState::Applied if effective.is_some() => "applied",
                _ => "disabled",
            },
            reason,
            future_issued_lead_secs: reader.future_issued_lead_secs,
            observed: reader.observed.as_deref().cloned(),
            accepted: reader.accepted.as_deref().cloned(),
            effective,
            slot: reader.slot,
            capture_revision: capture.revision,
            high_revision: reader.high_revision,
            high_generation: reader.high_generation,
            retired_generation: reader.retired_generation,
            reader_counters: reader.counters,
            capture_counters: capture.counters,
        };
        drop(history);
        self.0.capture.announce_expiry(notices);
        snapshot
    }

    async fn refreshed_after(&self, arrival: u64, pending: &mut Option<u64>) {
        loop {
            let (start, mut done) = self.join_or_start();
            *pending = Some(start);
            let Ok(_) = done.wait_for(Option::is_some).await else {
                let mut flight = lock(&self.0.flight);
                if flight.as_ref().is_some_and(|f| f.start == start) {
                    *flight = None;
                }
                return;
            };
            if start > arrival {
                return;
            }
        }
    }

    fn join_or_start(&self) -> (u64, watch::Receiver<Option<()>>) {
        let mut flight = lock(&self.0.flight);
        if let Some(f) = flight.as_mut() {
            f.joins = f.joins.saturating_add(1);
            return (f.start, f.done.clone());
        }
        let start = self
            .0
            .started
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let (tx, rx) = watch::channel(None);
        *flight = Some(Flight {
            start,
            done: rx.clone(),
            joins: 0,
            completed: false,
        });
        drop(flight);
        let inner = Arc::clone(&self.0);
        #[expect(
            clippy::disallowed_methods,
            reason = "grant filesystem observation and application must run on the blocking pool, outside simulator execution"
        )]
        let _detached = tokio::task::spawn_blocking(move || inner.refresh(start, &tx));
        (start, rx)
    }

    #[cfg(test)]
    pub(crate) fn hold_refresh(&self, pause: Arc<crate::protected_dir::tests::Pause>) {
        *lock(&self.0.pause) = Some(pause);
    }

    #[cfg(test)]
    pub(super) fn hold_completion(&self, pause: Arc<crate::protected_dir::tests::Pause>) {
        *lock(&self.0.completion_pause) = Some(pause);
    }

    #[cfg(test)]
    pub(crate) fn observations(&self) -> u64 {
        self.0.observations.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn guard_free(&self) -> bool {
        self.0.history.try_lock().is_ok() && self.0.published.try_lock().is_ok()
    }

    #[cfg(test)]
    pub(super) fn seed_last_slot(&self, slot: u64) {
        lock(&self.0.history).next_slot = slot;
    }

    #[cfg(test)]
    pub(crate) fn joins_in_flight(&self) -> Option<u64> {
        lock(&self.0.flight).as_ref().map(|f| f.joins)
    }

    #[cfg(test)]
    pub(super) fn suspend_stalled(&self, start: u64) {
        self.0.suspend_stalled(start);
    }
}

impl<O: DirOps> Inner<O> {
    fn suspend_stalled(&self, start: u64) {
        let mut notices = Vec::new();
        let mut history = lock(&self.history);
        if lock(&self.flight)
            .as_ref()
            .is_some_and(|f| f.start == start && !f.completed)
        {
            let reason = self
                .disable(
                    &mut history,
                    Failure::transient(Reason::Stalled),
                    &mut notices,
                )
                .err()
                .map_or(Reason::Stalled, Reason::Capture);
            let mut published = lock(&self.published);
            let before = published.clone();
            published.state = ReaderState::Disabled(reason);
            published.future_issued_lead_secs = None;
            published.capture_revision = history.capture_revision;
            let transition = super::events::Transition::between(&before, &published);
            drop(published);
            drop(history);
            self.capture.announce_expiry(notices);
            if let Some(transition) = transition {
                transition.emit(&self.capture);
            }
        }
    }

    fn refresh(&self, start: u64, done: &watch::Sender<Option<()>>) {
        let verdict = self.observe();
        let mut notices = Vec::new();
        let mut history = lock(&self.history);
        let _expiry = self.capture.snapshot_deferred(&mut notices);
        let observed = verdict.as_ref().ok().map(|d| Arc::clone(&d.grant));
        let result = verdict.and_then(|decoded| self.apply(&mut history, decoded, &mut notices));
        let (state, future_issued_lead_secs) = match result {
            Ok(()) => (ReaderState::Applied, None),
            Err(failure) => {
                increment(&self.counters.refusals);
                if failure.reason == Reason::Unreadable {
                    increment(&self.counters.unreadable);
                }
                let reason = self
                    .disable(&mut history, failure, &mut notices)
                    .err()
                    .map_or(failure.reason, Reason::Capture);
                (
                    ReaderState::Disabled(reason),
                    failure
                        .future_issued_lead_secs
                        .filter(|_| reason == Reason::FutureIssued),
                )
            }
        };
        let snapshot = ReaderSnapshot {
            incarnation: self.incarnation.value(),
            state,
            future_issued_lead_secs,
            sequence: start,
            observed,
            accepted: history.last.as_ref().map(|a| Arc::clone(&a.decoded.grant)),
            slot: history.last.as_ref().map(|a| a.slot),
            capture_revision: history.capture_revision,
            high_revision: history.revision,
            high_generation: history.generation,
            retired_generation: history.retired,
            counters: ReaderCounters::default(),
        };
        increment(&self.counters.refreshes);
        let transition = {
            let mut published = lock(&self.published);
            let transition = super::events::Transition::between(&published, &snapshot);
            if start >= published.sequence {
                *published = snapshot;
                transition
            } else {
                None
            }
        };
        // Mark the flight completed under history so a concurrent deadline
        // cannot suspend its applied verdict before notifications finish, while
        // keeping the flight joinable until its lifecycle events are emitted.
        if let Some(flight) = lock(&self.flight).as_mut().filter(|f| f.start == start) {
            flight.completed = true;
        }
        drop(history);
        #[cfg(test)]
        {
            let pause = lock(&self.completion_pause).take();
            if let Some(pause) = pause {
                pause.arrive_and_wait();
            }
        }
        self.capture.announce_expiry(notices);
        if let Some(transition) = transition {
            transition.emit(&self.capture);
        }
        {
            let mut flight = lock(&self.flight);
            if flight.as_ref().is_some_and(|f| f.start == start) {
                *flight = None;
            }
        }
        done.send_replace(Some(()));
    }

    #[cfg(test)]
    fn observe_test(&self) {
        increment(&self.observations);
        let pause = lock(&self.pause).take();
        if let Some(pause) = pause {
            pause.arrive_and_wait();
        }
    }

    fn observe(&self) -> Verdict {
        #[cfg(test)]
        {
            self.observe_test();
        }
        let mut held = lock(&self.held);
        if self.directory_lost.load(Ordering::SeqCst) {
            *held = None;
            return Err(Failure::content(Reason::Directory));
        }
        match self.ops.stat_path(&self.path) {
            Ok(now) if now.is_dir() && self.dir.stat.same_directory(&now) => {}
            Ok(_) => {
                self.directory_lost.store(true, Ordering::SeqCst);
                *held = None;
                return Err(Failure::content(Reason::Directory));
            }
            Err(_) => {
                *held = None;
                return Err(Failure::transient(Reason::Directory));
            }
        }
        let name = match self.ops.stat_at(&self.dir.dir, NAME) {
            Ok(stat) => stat,
            Err(e) => {
                *held = None;
                return Err(if e.kind() == io::ErrorKind::NotFound {
                    Failure::content(Reason::Missing)
                } else {
                    Failure::transient(Reason::Unreadable)
                });
            }
        };
        if let Some(h) = held.as_ref()
            && h.identity == Identity::of(&name)
        {
            return h.verdict.clone();
        }
        match read_file(&self.ops, &self.dir) {
            FileRead::Loaded {
                file,
                identity,
                verdict,
            } => {
                let verdict = verdict
                    .map_err(|reason| {
                        Failure::content(match reason {
                            "grant-oversize" => Reason::Oversize,
                            "grant-changed" => Reason::Corrupt,
                            _ => Reason::Unprotected,
                        })
                    })
                    .and_then(|bytes| {
                        let grant =
                            decode_grant(&bytes).map_err(|_| Failure::content(Reason::Corrupt))?;
                        Ok(Arc::new(Decoded {
                            grant: Arc::new(grant),
                            bytes,
                        }))
                    });
                increment(&self.counters.reloads);
                *held = Some(Held {
                    _file: file,
                    identity,
                    verdict: verdict.clone(),
                });
                verdict
            }
            FileRead::Missing => {
                *held = None;
                Err(Failure::content(Reason::Missing))
            }
            FileRead::Link => {
                *held = None;
                Err(Failure::content(Reason::Unprotected))
            }
            FileRead::Io(_) => {
                *held = None;
                Err(Failure::transient(Reason::Unreadable))
            }
        }
    }

    fn validate(
        &self,
        history: &mut History,
        decoded: &Decoded,
        notices: &mut Vec<Expiry>,
    ) -> Result<(), Failure> {
        let fields = decoded.grant.fields();
        if fields.incarnation != self.incarnation.value() {
            return Err(Failure::content(Reason::StaleIncarnation));
        }
        // Protected, decoded evidence for this incarnation survives time
        // refusals, including a tombstone first observed after its expiry.
        let revision = history.revision;
        let generation = history.generation;
        history.revision = history.revision.max(fields.file_revision);
        history.generation = history.generation.max(fields.grant_generation);
        if fields.action == GrantAction::Revoke {
            self.retire(history, fields.grant_generation);
            return Err(Failure::content(Reason::Revoked));
        }
        let now = self.clock.now();
        if let Some(reason) = self.clock.failure() {
            // Failed clocks have no usable issuance comparison. Their last
            // valid observation still carries expiry evidence, which wins.
            let _expiry = self.capture.snapshot_deferred(notices);
            if now >= fields.expires_at {
                return Err(Failure::content(Reason::Expired));
            }
            return Err(Failure::transient(Reason::Clock(reason)));
        }
        let ahead = (i128::from(fields.issued_at.secs) - i128::from(now.secs)) * 1_000_000_000
            + i128::from(fields.issued_at.nanos)
            - i128::from(now.nanos);
        if ahead > 30_000_000_000 {
            let seconds = u64::try_from(ahead / 1_000_000_000)
                .unwrap_or(u64::MAX)
                .saturating_add(u64::from(ahead % 1_000_000_000 != 0));
            return Err(Failure {
                reason: Reason::FutureIssued,
                evidence: true,
                future_issued_lead_secs: Some(seconds),
            });
        }
        if now >= fields.expires_at {
            return Err(Failure::content(Reason::Expired));
        }
        if fields.file_revision < revision || fields.grant_generation < generation {
            return Err(Failure::content(Reason::Rollback));
        }
        if fields.file_revision == revision
            && history.last.as_ref().is_some_and(|a| {
                a.decoded.grant.fields().file_revision == fields.file_revision
                    && a.decoded.bytes != decoded.bytes
            })
        {
            return Err(Failure::content(Reason::RevisionConflict));
        }
        if fields.grant_generation <= history.retired {
            return Err(Failure::content(Reason::Retired));
        }
        if let Some(last) = &history.last
            && fields.grant_generation == last.decoded.grant.fields().grant_generation
        {
            let old = last.decoded.grant.fields();
            if !included(&fields.scope, &old.scope)
                || fields.expires_at > old.expires_at
                || fields.line_ceiling > old.line_ceiling
                || fields.byte_ceiling > old.byte_ceiling
            {
                return Err(Failure::content(Reason::Widening));
            }
        }
        if fields.grant_generation > generation && fields.file_revision <= revision {
            return Err(Failure::content(Reason::Rollback));
        }
        Ok(())
    }

    fn apply(
        &self,
        history: &mut History,
        decoded: Arc<Decoded>,
        notices: &mut Vec<Expiry>,
    ) -> Result<(), Failure> {
        self.validate(history, &decoded, notices)?;
        let fields = decoded.grant.fields();
        if history.applied
            && history
                .last
                .as_ref()
                .is_some_and(|a| a.decoded.bytes == decoded.bytes)
        {
            return Ok(());
        }
        let slot = if let Some(last) = &history.last
            && fields.grant_generation == last.decoded.grant.fields().grant_generation
        {
            last.slot
        } else {
            history.next_slot = history
                .next_slot
                .checked_add(1)
                .ok_or(Failure::transient(Reason::SlotOverflow))?;
            CaptureSlot(history.next_slot)
        };
        let selector = match &fields.scope {
            GrantScope::Principal(p) => CaptureSelector::Principal(*p),
            GrantScope::Volume(v) => CaptureSelector::Volume(v.clone()),
            GrantScope::Conjunction { principal, volume } => {
                CaptureSelector::PrincipalAndVolume(*principal, volume.clone())
            }
        };
        let entry = CaptureEntry {
            slot,
            selector,
            kind: CaptureKind::AuthenticatedRequest,
            level: tracing::Level::DEBUG,
            remaining_lines: fields.line_ceiling,
            remaining_bytes: fields.byte_ceiling,
            deadline: Some(fields.expires_at),
            lease: Some(fields.grant_generation),
        };
        history.capture_revision = self
            .capture
            .replace_deferred(
                history.capture_revision,
                &[entry],
                Some(&decoded.grant),
                notices,
            )
            .map_err(|e| Failure::transient(Reason::Capture(e)))?;
        history.last = Some(Accepted { decoded, slot });
        history.applied = true;
        history.retained = true;
        increment(&self.counters.applications);
        Ok(())
    }

    fn disable(
        &self,
        history: &mut History,
        failure: Failure,
        notices: &mut Vec<Expiry>,
    ) -> Result<(), CaptureError> {
        history.applied = false;
        if failure.evidence {
            self.retire(history, history.generation);
            if history.retained {
                match self
                    .capture
                    .replace_deferred(history.capture_revision, &[], None, notices)
                {
                    Ok(revision) => history.capture_revision = revision,
                    Err(error) => {
                        // Even revision exhaustion cannot leave the prior scope
                        // effective after content evidence. Suspension requires
                        // no revision increment; poison already disables capture.
                        history.capture_revision = self.capture.snapshot_deferred(notices).revision;
                        self.suspend_retained(history, notices)?;
                        return Err(error);
                    }
                }
                history.retained = false;
            }
        } else if history.retained {
            self.suspend_retained(history, notices)?;
        }
        Ok(())
    }

    fn retire(&self, history: &mut History, generation: u64) {
        if generation > history.retired {
            history.retired = generation;
            increment(&self.counters.retirements);
        }
    }

    fn suspend_retained(
        &self,
        history: &mut History,
        notices: &mut Vec<Expiry>,
    ) -> Result<(), CaptureError> {
        match self.capture.suspend(history.capture_revision) {
            Ok(()) => return Ok(()),
            Err(CaptureError::StaleRevision) => {
                history.capture_revision = self.capture.snapshot_deferred(notices).revision;
            }
            Err(error) => return Err(error), // Poison already disables capture.
        }
        if let Err(error) = self.capture.suspend(history.capture_revision) {
            // If retry cannot suspend, clear the effective set as for content
            // evidence. Revision exhaustion still permits suspension; poison
            // already disables capture. Every failure is returned to the caller.
            history.capture_revision = self.capture.snapshot_deferred(notices).revision;
            match self
                .capture
                .replace_deferred(history.capture_revision, &[], None, notices)
            {
                Ok(revision) => {
                    history.capture_revision = revision;
                    history.retained = false;
                }
                Err(fallback) => {
                    history.capture_revision = self.capture.snapshot_deferred(notices).revision;
                    self.capture.suspend(history.capture_revision)?;
                    return Err(fallback);
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
