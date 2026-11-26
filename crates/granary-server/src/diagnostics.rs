// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded, process-owned capture of authenticated write admission.
//! Captures share a read guard through scope checking, atomic budget charging and
//! enqueue. Replacement owns the write guard, so no old scope enqueues after it
//! returns. Deadlines are checked before charging and just before enqueue; expiry
//! latches and a shared clock high-water mark survive replacement and rollback.
//! Grant clock failure disables deadlines permanently, after observing expiry.
//! Conjunction selectors require both principal and volume. Grant-coordinated
//! replacement and snapshots defer expiry notices until both guards are released.
//! Transient reader failures suspend entries under the same guard, retaining
//! slots, allowances and expiry latches until replacement or retirement.
//! Notifications run outside the
//! guard. Poison disables capture until the process restarts.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock, TryLockError};

use granary_core::clock::Clock;
use granary_core::enrollment::PrincipalId;
use granary_core::root::{VOLUME_NAME_MAX, VolumeName};
use granary_core::sheaf::Timestamp;
use tracing::{Event, Metadata, Subscriber, subscriber::Interest};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer};

use crate::admission::{Operation, OperationKind};
use crate::debug_grant::clock::GrantClock;
#[cfg(test)]
use crate::debug_grant::clock::TimeHighWater;
use crate::sink::{DEBUG_LINE_BYTES, LossyStderr};

const TARGET: &str = "granary_server::scoped_capture";
const EVENT: &str = "request_authenticated";
const MAX_ENTRIES: usize = 64;
const MAX_LINES: u64 = 1024;
const MAX_BYTES: u64 = 1024 * 1024;
const RESERVATION: u64 = 1024;

// The two bounded allowances fit in one atomic word, so a reservation cannot
// spend one resource without the other or race a second capture into overspending.
const BUDGET_SHIFT: u32 = 32;
const BYTE_MASK: u64 = u32::MAX as u64;
const _: () = assert!(MAX_LINES <= u32::MAX as u64 && MAX_BYTES <= BYTE_MASK);

#[derive(Debug)]
struct LiveEntry {
    slot: CaptureSlot,
    selector: CaptureSelector,
    kind: CaptureKind,
    level: tracing::Level,
    budget: AtomicU64,
    deadline: Option<Timestamp>,
    lease: Option<u64>,
    expired: AtomicBool,
    grant: Option<Arc<granary_core::debug_grant::DebugGrant>>,
}

impl LiveEntry {
    fn new(entry: CaptureEntry) -> Self {
        Self {
            slot: entry.slot,
            selector: entry.selector,
            kind: entry.kind,
            level: entry.level,
            budget: AtomicU64::new((entry.remaining_lines << BUDGET_SHIFT) | entry.remaining_bytes),
            deadline: entry.deadline,
            lease: entry.lease,
            expired: AtomicBool::new(false),
            grant: None,
        }
    }

    fn allowance(&self) -> (u64, u64) {
        let remaining = self.budget.load(Ordering::Relaxed);
        (remaining >> BUDGET_SHIFT, remaining & BYTE_MASK)
    }

    fn charge(&self) -> bool {
        self.budget
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                let lines = remaining >> BUDGET_SHIFT;
                let bytes = remaining & BYTE_MASK;
                if lines == 0 || bytes < RESERVATION {
                    return None;
                }
                Some((lines.saturating_sub(1) << BUDGET_SHIFT) | bytes.saturating_sub(RESERVATION))
            })
            .is_ok()
    }

    fn snapshot(&self) -> CaptureEntry {
        let (remaining_lines, remaining_bytes) = self.allowance();
        CaptureEntry {
            slot: self.slot,
            selector: self.selector.clone(),
            kind: self.kind,
            level: self.level,
            remaining_lines,
            remaining_bytes,
            deadline: self.deadline,
            lease: self.lease,
        }
    }

    fn observe_expiry(
        &self,
        host: &Inner,
        revision: CaptureRevision,
        counters: &Counters,
        notices: &mut Vec<Expiry>,
    ) -> bool {
        if self.expired.load(Ordering::Relaxed) {
            return true;
        }
        if self.deadline.is_some() {
            // Deadline activation requires an injected clock; remain fail-closed
            // even if an internal caller bypasses replacement validation.
            let Some(now) = host.read_time() else {
                return true;
            };
            self.latch_at(now.0, revision, counters, notices);
            if !now.1 {
                return true;
            }
        }
        // Another reader may have observed expiry while this clock was read.
        self.expired.load(Ordering::Relaxed)
    }

    fn latch_at(
        &self,
        now: Timestamp,
        revision: CaptureRevision,
        counters: &Counters,
        notices: &mut Vec<Expiry>,
    ) {
        if let Some(deadline) = self.deadline
            && now >= deadline
            && !self.expired.swap(true, Ordering::Relaxed)
        {
            increment(&counters.expired);
            notices.push(Expiry {
                grant: self.grant.clone(),
                slot: self.slot,
                revision,
                lease: self.lease,
                deadline,
            });
        }
    }
}

/// An opaque slot identity, increasing for each new activation in a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaptureSlot(pub u64);

/// Exact event-field selection. Missing fields never match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureSelector {
    /// The principal resolved from current enrollment.
    Principal(PrincipalId),
    /// The admitted operation's volume.
    Volume(VolumeName),
    /// Both the resolved principal and admitted volume must match.
    PrincipalAndVolume(PrincipalId, VolumeName),
}

/// The closed set of supported diagnostic producers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureKind {
    /// Authenticated write admission, before inventory and controls checks.
    AuthenticatedRequest,
}

/// One effective scope and its remaining conservative output allowance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureEntry {
    /// Stable identity. Removed identities cannot be reactivated.
    pub slot: CaptureSlot,
    /// A typed, exact selector; wildcards and regular expressions are unrepresentable.
    pub selector: CaptureSelector,
    /// The producer this entry admits.
    pub kind: CaptureKind,
    /// Only DEBUG is supported.
    pub level: tracing::Level,
    /// At most 1,024 remaining attempts.
    pub remaining_lines: u64,
    /// At most 1 MiB; an attempt reserves 1,024 bytes without a refund.
    pub remaining_bytes: u64,
    /// An inclusive expiry boundary; `None` leaves capture without a time limit.
    pub deadline: Option<Timestamp>,
    /// Opaque, fixed-width lease identity carried by the expiry notification.
    /// Its ownership and meaning belong to the caller.
    pub lease: Option<u64>,
}

/// The revision of an atomically published capture set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureRevision(pub u64);

/// Why this host cannot activate capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureUnsupported {
    /// Span or field directives require a contextual capability proof.
    ContextualCeiling,
    /// The immutable target-specific ceiling excludes DEBUG.
    Ceiling,
    /// Compile-time tracing instrumentation excludes DEBUG.
    Instrumentation,
    /// This host has no authenticated-write producer.
    Producer,
    /// Deadline capture requires an injected clock and representable elapsed time.
    Clock,
}

/// Immutable host capabilities, computed from the already parsed ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureCapabilities {
    /// `None` means deadline-free authenticated-request DEBUG is supported.
    /// Deadline entries additionally require an injected clock.
    pub unsupported: Option<CaptureUnsupported>,
}

/// A refused replacement; no refusal partially changes the effective set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    /// The caller's revision is no longer current.
    StaleRevision,
    /// The host cannot activate this capture kind.
    Unsupported(CaptureUnsupported),
    /// More than 64 entries, a duplicate ID, unsupported level, excessive budget
    /// or an invalid deadline timestamp.
    InvalidEntries,
    /// A newly introduced slot at or below the retirement watermark.
    RetiredSlot,
    /// A new identity does not exceed every previously issued identity.
    NonMonotonicSlot,
    /// A retained slot cannot change its lease identity.
    LeaseMismatch,
    /// Capture stays disabled until restart after a poisoned write guard.
    Poisoned,
    /// The revision counter cannot advance.
    RevisionOverflow,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::StaleRevision => "stale capture revision",
            Self::Unsupported(_) => "capture unsupported by this host",
            Self::InvalidEntries => "invalid capture entries",
            Self::RetiredSlot => "capture slot is retired",
            Self::NonMonotonicSlot => "capture slot is not monotonic",
            Self::LeaseMismatch => "retained capture lease differs",
            Self::Poisoned => "capture state is poisoned",
            Self::RevisionOverflow => "capture revision exhausted",
        })
    }
}

impl std::error::Error for CaptureError {}

/// Separately sampled, saturating capture counters. Queued means local acceptance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureCounters {
    /// Attempts admitted by scope and budget, before formatting or final expiry.
    pub admitted: u64,
    /// Matching events suppressed by exhausted budgets.
    pub budget_suppressed: u64,
    /// Attempts refused by budget, replacement contention or expiry.
    pub suppressed: u64,
    /// Matching attempts refused by a latched or newly observed expiry.
    pub expiry_suppressed: u64,
    /// Slots whose expiry has been observed, counted once per slot.
    pub expired: u64,
    /// Attempts suppressed rather than waiting for a replacement's write guard.
    pub contention: u64,
    /// Events with missing, malformed or unsupported fields.
    pub malformed: u64,
    /// Fields or encoded records that exceed their bounds.
    pub oversize: u64,
    /// DEBUG lines accepted by the local queue.
    pub queued: u64,
    /// DEBUG lines refused by the local queue.
    pub sink_drops: u64,
}

#[derive(Debug, Default)]
struct Counters {
    admitted: AtomicU64,
    budget_suppressed: AtomicU64,
    suppressed: AtomicU64,
    expiry_suppressed: AtomicU64,
    expired: AtomicU64,
    contention: AtomicU64,
    malformed: AtomicU64,
    oversize: AtomicU64,
    queued: AtomicU64,
    sink_drops: AtomicU64,
}

fn increment(value: &AtomicU64) {
    let _updated = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(1))
    });
}

impl Counters {
    fn snapshot(&self) -> CaptureCounters {
        CaptureCounters {
            admitted: self.admitted.load(Ordering::Relaxed),
            budget_suppressed: self.budget_suppressed.load(Ordering::Relaxed),
            suppressed: self.suppressed.load(Ordering::Relaxed),
            expiry_suppressed: self.expiry_suppressed.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            contention: self.contention.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            oversize: self.oversize.load(Ordering::Relaxed),
            queued: self.queued.load(Ordering::Relaxed),
            sink_drops: self.sink_drops.load(Ordering::Relaxed),
        }
    }
}

/// A coherent scope snapshot with separately sampled per-slot budgets and counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureSnapshot {
    /// Current replacement revision.
    pub revision: CaptureRevision,
    /// Effective entries in increasing slot order; excludes latched expiry and
    /// is empty when poisoned. Taking a snapshot also observes deadlines.
    pub entries: Vec<CaptureEntry>,
    /// Whether the state lock has permanently disabled capture.
    pub poisoned: bool,
    /// Process counters, never reset by replacement.
    pub counters: CaptureCounters,
}

#[derive(Debug, Default)]
struct State {
    revision: CaptureRevision,
    entries: Vec<LiveEntry>,
    highest_issued: Option<CaptureSlot>,
    highest_retired: Option<CaptureSlot>,
    suspended: bool,
}

struct Inner {
    capabilities: CaptureCapabilities,
    any: AtomicBool,
    state: RwLock<State>,
    counters: Counters,
    clock: Option<GrantClock>,
    dispatch: OnceLock<tracing::dispatcher::WeakDispatch>,
    #[cfg(test)]
    activity: tests::Activity,
}

impl Inner {
    fn read_time(&self) -> Option<(Timestamp, bool)> {
        let clock = self.clock.as_ref()?;
        let now = clock.now();
        Some((now, clock.failure().is_none()))
    }

    fn clear_if_expired(&self, state: &State) {
        if state
            .entries
            .iter()
            .all(|entry| entry.expired.load(Ordering::Relaxed))
        {
            self.any.store(false, Ordering::Release);
        }
    }
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("capabilities", &self.capabilities)
            .field("any", &self.any)
            .field("state", &self.state)
            .field("counters", &self.counters)
            .field("clock_injected", &self.clock.is_some())
            .finish_non_exhaustive()
    }
}

// At most one notice per slot wins its atomic latch, so this list is bounded by
// MAX_ENTRIES. Keep bounded decoded lease metadata with capture identity and deadline.
pub(crate) struct Expiry {
    grant: Option<Arc<granary_core::debug_grant::DebugGrant>>,
    slot: CaptureSlot,
    revision: CaptureRevision,
    lease: Option<u64>,
    deadline: Timestamp,
}

/// The host-owned in-process control seam, shared with serving clones.
/// Authorization, grant ownership and narrowing policy belong to its caller.
#[derive(Clone, Debug)]
pub struct CaptureHandle(Arc<Inner>);

impl CaptureHandle {
    #[cfg(test)]
    pub(crate) fn seed_revision(&self, revision: CaptureRevision) {
        if let Ok(mut state) = self.0.state.write() {
            state.revision = revision;
        }
    }

    #[cfg(test)]
    fn new(ceiling: &EnvFilter, producer: bool) -> Self {
        Self::new_with_clock(ceiling, producer, None)
    }

    #[cfg(test)]
    fn new_with_clock(ceiling: &EnvFilter, producer: bool, clock: Option<Arc<dyn Clock>>) -> Self {
        Self::new_with_grant_clock(ceiling, producer, clock.map(GrantClock::injected))
    }

    fn new_with_grant_clock(
        ceiling: &EnvFilter,
        producer: bool,
        clock: Option<GrantClock>,
    ) -> Self {
        let normalized = ceiling.to_string();
        let unsupported = if !producer {
            Some(CaptureUnsupported::Producer)
        } else if tracing::level_filters::STATIC_MAX_LEVEL < LevelFilter::DEBUG {
            Some(CaptureUnsupported::Instrumentation)
        } else if normalized.contains(['[', ']']) {
            Some(CaptureUnsupported::ContextualCeiling)
        } else if normalized
            .parse::<Targets>()
            .is_ok_and(|targets| targets.would_enable(TARGET, &tracing::Level::DEBUG))
        {
            None
        } else {
            Some(CaptureUnsupported::Ceiling)
        };
        Self(Arc::new(Inner {
            capabilities: CaptureCapabilities { unsupported },
            any: AtomicBool::new(false),
            state: RwLock::new(State::default()),
            counters: Counters::default(),
            clock,
            dispatch: OnceLock::new(),
            #[cfg(test)]
            activity: tests::Activity::default(),
        }))
    }

    /// Construct the production JSON/CLOSE subscriber with an injected deadline
    /// clock. Install once at startup. The clock must be nonblocking and provide
    /// valid timestamps. Its grant wrapper permanently disables deadline capture
    /// on invalid readings or elapsed-time overflow. The production grant reader
    /// uses the shared, fallible grant clock constructor instead.
    #[must_use]
    pub fn subscriber_with_clock(
        ceiling: EnvFilter,
        sink: LossyStderr,
        authenticated_requests: bool,
        clock: Arc<dyn Clock>,
    ) -> (Self, impl Subscriber + Send + Sync) {
        subscriber_with_clock_and_observer(
            ceiling,
            sink.clone(),
            sink,
            authenticated_requests,
            Some(clock),
            tracing_subscriber::layer::Identity::new(),
        )
    }

    /// Compose capture with the same failure latch and time history as the reader.
    pub(crate) fn subscriber_with_grant_clock(
        ceiling: EnvFilter,
        sink: LossyStderr,
        authenticated_requests: bool,
        clock: GrantClock,
    ) -> (Self, impl Subscriber + Send + Sync) {
        subscriber_with_grant_clock_and_observer(
            ceiling,
            sink.clone(),
            sink,
            authenticated_requests,
            Some(clock),
            tracing_subscriber::layer::Identity::new(),
        )
    }

    /// Disable admission without removing slots. Successful replacement resumes
    /// them with their remaining budgets and permanent expiry latches intact.
    /// This is reserved for the grant reader's transient I/O failures.
    pub(crate) fn suspend(&self, expected: CaptureRevision) -> Result<(), CaptureError> {
        let mut state = self.0.state.write().map_err(|_| {
            self.0.any.store(false, Ordering::Release);
            CaptureError::Poisoned
        })?;
        if state.revision != expected {
            return Err(CaptureError::StaleRevision);
        }
        state.suspended = true;
        self.0.any.store(false, Ordering::Release);
        Ok(())
    }

    /// Report the immutable host profile without reading the environment.
    #[must_use]
    pub fn capabilities(&self) -> CaptureCapabilities {
        self.0.capabilities
    }

    /// Atomically replace the complete effective set. Retained slots carry the
    /// minimum of their current and requested budgets and deadlines, even when
    /// their scope changes. An absent requested deadline cannot remove a current
    /// one, and a retained expiry latch cannot be cleared. Retained leases must
    /// match exactly. Replacement observes deadlines under its write guard.
    /// New slots must increase monotonically; removed slots cannot be reused.
    /// An empty replacement disables capture and emits no audit event.
    ///
    /// # Errors
    /// Returns [`CaptureError`] for unsupported activation, invalid entries,
    /// stale revisions, reused identities, changed leases, poison or revision overflow.
    pub fn replace(
        &self,
        expected_revision: CaptureRevision,
        entries: &[CaptureEntry],
    ) -> Result<CaptureRevision, CaptureError> {
        let mut notices = Vec::new();
        let result = self.replace_deferred(expected_revision, entries, None, &mut notices);
        self.announce_expiry(notices);
        result
    }

    pub(crate) fn replace_deferred(
        &self,
        expected_revision: CaptureRevision,
        entries: &[CaptureEntry],
        grant: Option<&Arc<granary_core::debug_grant::DebugGrant>>,
        notices: &mut Vec<Expiry>,
    ) -> Result<CaptureRevision, CaptureError> {
        let mut candidate = validated_entries(entries)?;
        if !candidate.is_empty()
            && let Some(reason) = self.capabilities().unsupported
        {
            return Err(CaptureError::Unsupported(reason));
        }
        if self.0.clock.is_none() && candidate.iter().any(|entry| entry.deadline.is_some()) {
            return Err(CaptureError::Unsupported(CaptureUnsupported::Clock));
        }
        let mut state = self.0.state.write().map_err(|_| {
            self.0.any.store(false, Ordering::Release);
            CaptureError::Poisoned
        })?;
        if state.revision != expected_revision {
            return Err(CaptureError::StaleRevision);
        }
        let revision = CaptureRevision(
            state
                .revision
                .0
                .checked_add(1)
                .ok_or(CaptureError::RevisionOverflow)?,
        );
        let mut retained = Vec::with_capacity(candidate.len());
        for entry in &mut candidate {
            let previous = state.entries.iter().find(|old| old.slot == entry.slot);
            let retired = state.highest_retired.is_some_and(|id| entry.slot <= id);
            if previous.is_none()
                && (retired || state.highest_issued.is_some_and(|id| entry.slot <= id))
            {
                return Err(if retired {
                    CaptureError::RetiredSlot
                } else {
                    CaptureError::NonMonotonicSlot
                });
            }
            let retained_expiry = previous.is_some_and(|old| old.expired.load(Ordering::Relaxed));
            retained.push((previous.is_some(), retained_expiry));
            if let Some(old) = previous {
                let (lines, bytes) = old.allowance();
                entry.remaining_lines = entry.remaining_lines.min(lines);
                entry.remaining_bytes = entry.remaining_bytes.min(bytes);
                entry.deadline = match (old.deadline, entry.deadline) {
                    (Some(current), Some(requested)) => Some(current.min(requested)),
                    (current, requested) => current.or(requested),
                };
                entry.lease = if entry.lease == old.lease {
                    old.lease
                } else {
                    return Err(CaptureError::LeaseMismatch);
                };
            }
        }
        let now = self.0.read_time();
        if !now.is_some_and(|(_, healthy)| healthy)
            && candidate.iter().any(|entry| entry.deadline.is_some())
        {
            // Observe existing expiry before refusing a failed clock. Expiry
            // evidence already present at failure takes precedence.
            drop(state);
            let _observed = self.snapshot_deferred(notices);
            return Err(CaptureError::Unsupported(CaptureUnsupported::Clock));
        }
        let removed = state
            .entries
            .iter()
            .filter(|old| !candidate.iter().any(|new| new.slot == old.slot))
            .map(|entry| entry.slot)
            .max();
        state.highest_retired = state.highest_retired.max(removed);
        state.highest_issued = state
            .highest_issued
            .max(candidate.last().map(|entry| entry.slot));
        let entries = candidate
            .into_iter()
            .zip(retained)
            .map(|(entry, (is_retained, retained_expiry))| {
                let mut live = LiveEntry::new(entry);
                live.grant = grant.cloned();
                live.expired.fetch_or(retained_expiry, Ordering::Relaxed);
                if is_retained && let Some((now, _)) = now {
                    live.latch_at(now, revision, &self.0.counters, notices);
                }
                live
            })
            .collect();
        state.entries = entries;
        state.revision = revision;
        state.suspended = false;
        self.0.any.store(
            state
                .entries
                .iter()
                .any(|entry| !entry.expired.load(Ordering::Relaxed)),
            Ordering::Release,
        );
        drop(state);
        Ok(revision)
    }

    /// Read the current effective set, observing deadlines without replacement.
    /// Poison is reported with no effective entries. Expiry notifications are
    /// emitted only after releasing the guard; counters are sampled separately.
    #[must_use]
    pub fn snapshot(&self) -> CaptureSnapshot {
        let mut notices = Vec::new();
        let snapshot = self.snapshot_deferred(&mut notices);
        self.announce_expiry(notices);
        snapshot
    }

    pub(crate) fn snapshot_deferred(&self, notices: &mut Vec<Expiry>) -> CaptureSnapshot {
        let (state, poisoned) = match self.0.state.read() {
            Ok(state) => (state, false),
            Err(error) => {
                self.0.any.store(false, Ordering::Release);
                (error.into_inner(), true)
            }
        };
        let entries = if poisoned {
            Vec::new()
        } else {
            state
                .entries
                .iter()
                .filter(|entry| {
                    let expired =
                        entry.observe_expiry(&self.0, state.revision, &self.0.counters, notices);
                    !expired && !state.suspended
                })
                .map(LiveEntry::snapshot)
                .collect()
        };
        self.0.clear_if_expired(&state);
        let revision = state.revision;
        drop(state);
        CaptureSnapshot {
            revision,
            entries,
            poisoned,
            counters: self.0.counters.snapshot(),
        }
    }

    pub(crate) fn announce_expiry(&self, notices: Vec<Expiry>) {
        if notices.is_empty() || tracing::level_filters::STATIC_MAX_LEVEL < LevelFilter::INFO {
            return;
        }
        let Some(dispatch) = self
            .0
            .dispatch
            .get()
            .and_then(tracing::dispatcher::WeakDispatch::upgrade)
        else {
            return;
        };
        // Scoped tracing defaults suppress ambient events emitted inside a
        // subscriber callback. Use a weak reference to the complete installed
        // dispatch, checking its ceiling and event filters explicitly. Nothing
        // is emitted through an inner layer or while owning the capture guard.
        let callsite = tracing::callsite! {
            name: "debug_grant_expire",
            kind: tracing::metadata::Kind::EVENT,
            target: "granary_server::diagnostics",
            level: tracing::Level::INFO,
            fields: message, event, phase, outcome, incarnation, file_revision, generation, scope, effective_scope, capture_level, kind, line_ceiling, byte_ceiling, owner, reason, issuer_uid, slot, capture_revision, lease, expires_secs, expires_nanos,
        };
        let metadata = tracing::callsite::Callsite::metadata(callsite);
        if !dispatch.enabled(metadata) {
            return;
        }
        for notice in notices {
            let fields = notice.grant.as_ref().map(|g| g.fields());
            let incarnation = fields
                .map(|f| crate::debug_grant::events::IncarnationText(f.incarnation).to_string());
            dispatch.event(&Event::new_child_of(
                None,
                metadata,
                &tracing::valueset_all!(
                    metadata.fields(),
                    message = "debug_grant_expire",
                    event = "debug_grant_expire",
                    phase = "applied",
                    outcome = "expired",
                    incarnation = incarnation.as_deref(),
                    file_revision = fields.map(|f| f.file_revision),
                    generation = fields.map(|f| f.grant_generation),
                    scope = tracing::field::debug(&fields.map(|f| &f.scope)),
                    effective_scope = tracing::field::debug(
                        &Option::<granary_core::debug_grant::GrantScope>::None
                    ),
                    capture_level = "DEBUG",
                    kind = "AuthenticatedRequest",
                    line_ceiling = fields.map(|f| f.line_ceiling),
                    byte_ceiling = fields.map(|f| f.byte_ceiling),
                    owner = fields.and_then(|f| std::str::from_utf8(f.owner.as_bytes()).ok()),
                    reason = fields.and_then(|f| std::str::from_utf8(f.reason.as_bytes()).ok()),
                    issuer_uid = fields.map(|f| f.issuer_uid),
                    slot = notice.slot.0,
                    capture_revision = notice.revision.0,
                    lease = notice.lease,
                    expires_secs = notice.deadline.secs,
                    expires_nanos = notice.deadline.nanos,
                ),
            ));
        }
    }

    #[cfg(test)]
    pub(crate) fn guard_free(&self) -> bool {
        self.0.state.try_write().is_ok()
    }

    pub(crate) fn dispatch(&self) -> Option<tracing::Dispatch> {
        self.0
            .dispatch
            .get()
            .and_then(tracing::dispatcher::WeakDispatch::upgrade)
    }

    fn capture(&self, event: &Event<'_>, sink: &LossyStderr) {
        #[cfg(test)]
        increment(&self.0.activity.field_visits);
        let mut fields = Fields::default();
        event.record(&mut fields);
        if fields.oversize {
            increment(&self.0.counters.oversize);
            return;
        }
        let Some(principal) = fields.principal.filter(|_| !fields.malformed) else {
            increment(&self.0.counters.malformed);
            return;
        };
        let Some(operation) = fields.operation else {
            increment(&self.0.counters.malformed);
            return;
        };
        #[cfg(test)]
        increment(&self.0.activity.state_attempts);
        #[cfg(test)]
        self.0.activity.before_capture();
        let state = match self.0.state.try_read() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                increment(&self.0.counters.contention);
                increment(&self.0.counters.suppressed);
                return;
            }
            Err(TryLockError::Poisoned(_)) => {
                self.0.any.store(false, Ordering::Release);
                return;
            }
        };
        let mut notices = Vec::new();
        self.capture_guarded(principal, &fields, operation, &state, sink, &mut notices);
        if !notices.is_empty() {
            self.0.clear_if_expired(&state);
        }
        drop(state);
        self.announce_expiry(notices);
    }

    fn capture_guarded(
        &self,
        principal: PrincipalId,
        fields: &Fields,
        operation: &str,
        state: &State,
        sink: &LossyStderr,
        notices: &mut Vec<Expiry>,
    ) {
        if state.suspended {
            return;
        }
        let mut scope_found = false;
        let mut expired_match = false;
        let revision = state.revision;
        let selected = state.entries.iter().find(|entry| {
            let matches = match &entry.selector {
                CaptureSelector::Principal(id) => *id == principal,
                CaptureSelector::Volume(volume) => fields.volume.as_ref() == Some(volume),
                CaptureSelector::PrincipalAndVolume(id, volume) => {
                    *id == principal && fields.volume.as_ref() == Some(volume)
                }
            };
            scope_found |= matches;
            if !matches {
                return false;
            }
            if entry.observe_expiry(&self.0, revision, &self.0.counters, notices) {
                expired_match = true;
                return false;
            }
            entry.charge()
        });
        let Some(entry) = selected else {
            if scope_found {
                increment(&self.0.counters.suppressed);
                if expired_match {
                    increment(&self.0.counters.expiry_suppressed);
                } else {
                    increment(&self.0.counters.budget_suppressed);
                }
            }
            return;
        };
        increment(&self.0.counters.admitted);
        #[cfg(test)]
        increment(&self.0.activity.formats);
        let mut line = Capped::<DEBUG_LINE_BYTES>::default();
        let volume = fields
            .volume
            .as_ref()
            .map_or("null".to_owned(), |v| format!("\"{}\"", v.as_str()));
        if writeln!(line,
            "{{\"level\":\"DEBUG\",\"target\":\"{TARGET}\",\"event\":\"{EVENT}\",\"principal\":\"{principal}\",\"volume\":{volume},\"operation\":\"{operation}\",\"slot\":{},\"revision\":{}}}",
            entry.slot.0, revision.0).is_err()
        {
            increment(&self.0.counters.oversize);
            return;
        }
        // The last clock read is the admission selection point. Charging is
        // conservative even if expiry wins here; never refund a reservation.
        if entry.observe_expiry(&self.0, revision, &self.0.counters, notices) {
            increment(&self.0.counters.expiry_suppressed);
            increment(&self.0.counters.suppressed);
            return;
        }
        // The shared guard remains owned through this nonblocking queue attempt.
        #[cfg(test)]
        increment(&self.0.activity.enqueues);
        if sink.try_enqueue_debug(line.as_bytes()) {
            increment(&self.0.counters.queued);
        } else {
            increment(&self.0.counters.sink_drops);
        }
    }

    pub(crate) fn authenticated_request(&self, principal: PrincipalId, operation: &Operation<'_>) {
        // With no effective targets this is the producer's only work.
        if !self.0.any.load(Ordering::Acquire) {
            return;
        }
        let volume = match operation {
            Operation::Intent { volume, .. }
            | Operation::Publish { volume }
            | Operation::VolumeStatus { volume }
            | Operation::PutRoot { volume, .. }
            | Operation::GetRoot { volume, .. } => Some(volume.as_str()),
            Operation::PutMeta { volume, .. }
            | Operation::GetMeta { volume, .. }
            | Operation::MaxSeq { volume }
            | Operation::ReadHint { volume, .. }
            | Operation::WriteHint { volume } => Some(*volume),
            Operation::PutBin { .. } | Operation::GetBinRange { .. } => None,
        };
        tracing::event!(name: "request_authenticated", target: "granary_server::scoped_capture",
            tracing::Level::DEBUG, principal = %principal, volume = volume.unwrap_or(""),
            operation = operation.name());
    }
}

// Validate the complete bounded set before observing time or owning state.
fn validated_entries(entries: &[CaptureEntry]) -> Result<Vec<CaptureEntry>, CaptureError> {
    if entries.len() > MAX_ENTRIES {
        return Err(CaptureError::InvalidEntries);
    }
    let mut candidate = entries.to_vec();
    candidate.sort_by_key(|entry| entry.slot);
    if candidate.iter().any(|entry| {
        entry.level != tracing::Level::DEBUG
            || entry.remaining_lines > MAX_LINES
            || entry.remaining_bytes > MAX_BYTES
            || entry.deadline.is_some_and(|deadline| !deadline.is_valid())
    }) || candidate
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.slot == b.slot))
    {
        return Err(CaptureError::InvalidEntries);
    }
    Ok(candidate)
}

/// A buffer whose formatting cannot grow past its compile-time cap.
struct Capped<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Capped<N> {
    fn default() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> Capped<N> {
    fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

impl<const N: usize> std::fmt::Write for Capped<N> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(std::fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(std::fmt::Error)?;
        destination.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[derive(Default)]
struct Fields {
    principal: Option<PrincipalId>,
    volume: Option<VolumeName>,
    operation: Option<&'static str>,
    malformed: bool,
    oversize: bool,
}

impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "principal" => {
                if value.len() > 42 {
                    self.oversize = true;
                    return;
                }
                match PrincipalId::parse_written(value) {
                    Ok(id) => self.principal = Some(id),
                    Err(_) => self.malformed = true,
                }
            }
            "volume" => {
                if value.len() > VOLUME_NAME_MAX {
                    self.oversize = true;
                    return;
                }
                if value.is_empty() {
                    return;
                }
                match VolumeName::from_bytes(value.as_bytes()) {
                    Ok(volume) => self.volume = Some(volume),
                    Err(_) => self.malformed = true,
                }
            }
            "operation" => {
                self.operation = OperationKind::AUTHENTICATED_WRITES
                    .iter()
                    .chain(OperationKind::AUTHENTICATED_READS.iter())
                    .map(|kind| kind.name())
                    .find(|name| *name == value);
                self.malformed |= self.operation.is_none();
            }
            _ => self.malformed = true,
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() != "principal" {
            self.malformed = true;
            return;
        }
        let mut text = Capped::<42>::default();
        if write!(text, "{value:?}").is_err() {
            self.oversize = true;
            return;
        }
        match std::str::from_utf8(text.as_bytes()) {
            Ok(value) => self.record_str(field, value),
            Err(_) => self.malformed = true,
        }
    }
}

fn diagnostic(metadata: &Metadata<'_>) -> bool {
    metadata.is_event()
        && metadata.target() == TARGET
        && metadata.name() == EVENT
        && *metadata.level() == tracing::Level::DEBUG
}

/// Owns fmt so diagnostic events have exactly one, bounded output route.
struct HostDiagnostics<F> {
    baseline: F,
    handle: CaptureHandle,
    sink: LossyStderr,
}

impl<S, F> Layer<S> for HostDiagnostics<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    F: Layer<S>,
{
    fn on_register_dispatch(&self, dispatch: &tracing::Dispatch) {
        let _registered = self.handle.0.dispatch.set(dispatch.downgrade());
        self.baseline.on_register_dispatch(dispatch);
    }
    fn on_layer(&mut self, subscriber: &mut S) {
        self.baseline.on_layer(subscriber);
    }
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if diagnostic(metadata) {
            Interest::sometimes()
        } else {
            self.baseline.register_callsite(metadata)
        }
    }
    fn enabled(&self, metadata: &Metadata<'_>, context: Context<'_, S>) -> bool {
        if diagnostic(metadata) {
            self.handle.0.any.load(Ordering::Acquire)
        } else {
            self.baseline.enabled(metadata, context)
        }
    }
    // Target replacements cannot change the process's cached maximum level.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        None
    }
    fn event_enabled(&self, event: &Event<'_>, context: Context<'_, S>) -> bool {
        diagnostic(event.metadata()) || self.baseline.event_enabled(event, context)
    }
    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        if diagnostic(event.metadata()) {
            self.handle.capture(event, &self.sink);
        } else {
            self.baseline.on_event(event, context);
        }
    }
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        context: Context<'_, S>,
    ) {
        self.baseline.on_new_span(attrs, id, context);
    }
    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        context: Context<'_, S>,
    ) {
        self.baseline.on_record(id, values, context);
    }
    fn on_follows_from(
        &self,
        id: &tracing::span::Id,
        follows: &tracing::span::Id,
        context: Context<'_, S>,
    ) {
        self.baseline.on_follows_from(id, follows, context);
    }
    fn on_enter(&self, id: &tracing::span::Id, context: Context<'_, S>) {
        self.baseline.on_enter(id, context);
    }
    fn on_exit(&self, id: &tracing::span::Id, context: Context<'_, S>) {
        self.baseline.on_exit(id, context);
    }
    fn on_close(&self, id: tracing::span::Id, context: Context<'_, S>) {
        self.baseline.on_close(id, context);
    }
    fn on_id_change(
        &self,
        old: &tracing::span::Id,
        new: &tracing::span::Id,
        context: Context<'_, S>,
    ) {
        self.baseline.on_id_change(old, new, context);
    }
}

/// Construct the production JSON/CLOSE subscriber under its immutable ceiling.
/// Install once at startup; the returned handle changes only scoped capture.
/// Deadline entries require [`CaptureHandle::subscriber_with_clock`] instead;
/// this constructor injects no clock and preserves deadline-free capture.
/// `authenticated_requests` states whether this host enables authenticated writes
/// and will supply this handle to their serving clones.
#[must_use]
pub fn host_subscriber(
    ceiling: EnvFilter,
    sink: LossyStderr,
    authenticated_requests: bool,
) -> (CaptureHandle, impl Subscriber + Send + Sync) {
    host_subscriber_with_observer(
        ceiling,
        sink.clone(),
        sink,
        authenticated_requests,
        tracing_subscriber::layer::Identity::new(),
    )
}

pub(crate) fn host_subscriber_with_observer<W, O>(
    ceiling: EnvFilter,
    writer: W,
    sink: LossyStderr,
    authenticated_requests: bool,
    observer: O,
) -> (CaptureHandle, impl Subscriber + Send + Sync)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
    O: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    subscriber_with_clock_and_observer(
        ceiling,
        writer,
        sink,
        authenticated_requests,
        None,
        observer,
    )
}

fn subscriber_with_clock_and_observer<W, O>(
    ceiling: EnvFilter,
    writer: W,
    sink: LossyStderr,
    authenticated_requests: bool,
    clock: Option<Arc<dyn Clock>>,
    observer: O,
) -> (CaptureHandle, impl Subscriber + Send + Sync)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
    O: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    subscriber_with_grant_clock_and_observer(
        ceiling,
        writer,
        sink,
        authenticated_requests,
        clock.map(GrantClock::injected),
        observer,
    )
}

pub(crate) fn subscriber_with_grant_clock_and_observer<W, O>(
    ceiling: EnvFilter,
    writer: W,
    sink: LossyStderr,
    authenticated_requests: bool,
    clock: Option<GrantClock>,
    observer: O,
) -> (CaptureHandle, impl Subscriber + Send + Sync)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
    O: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    let handle = CaptureHandle::new_with_grant_clock(&ceiling, authenticated_requests, clock);
    let baseline = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        // The time.busy/time.idle Instant pair lives inside tracing-subscriber.
        // No workspace callsite reads a clock. These span durations cannot use
        // wall-clock Timestamp differences, which may step backwards under NTP.
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .json();
    let host = HostDiagnostics {
        baseline,
        handle: handle.clone(),
        sink,
    };
    let subscriber = tracing_subscriber::registry()
        .with(host.and_then(observer))
        .with(ceiling);
    (handle, subscriber)
}

#[cfg(test)]
pub(crate) mod tests;
