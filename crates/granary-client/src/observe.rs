// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client's observability vocabulary: the stable event names and fields,
//! the closed label domains, the operation span and the correlation id.
//! `docs/operating-client-observability.md` is the operator-facing statement
//! of the same table.
//!
//! **A name is an identifier, never prose.** Every event is emitted through
//! one function here, which fixes its `event` name and its field names at
//! compile time. A call site chooses only the VALUES, and every value that is
//! not a number is drawn from a closed domain (an enum with an `as_str`). A test, a dashboard or a support
//! script therefore matches `event="op.retry"` and `kind="commit"`; it never
//! matches a sentence.
//!
//! **The rule this module exists for:** every loud failure the client adds
//! emits [`op_failed`] (or another event in [`EVENTS`]) and its test asserts
//! the event, not only the exit code or the errno. A new loud failure that
//! needs a class or an event the table lacks adds it here, in the document and
//! in the table test together.
//!
//! **Correlation.** [`operation_span`] opens the span every event of one
//! operation is recorded inside; the id travels as the span's `op` field, so
//! the text and JSON layers both print it with each event emitted inside the
//! span without any call site repeating it. An event emitted on a thread or
//! task that has not entered a span carries no id. The id is drawn from the cryptographic-randomness seam
//! and from nothing else (never a path, a name, a clock or a counter), and it
//! is a different TYPE and a different spelling from the publish operation
//! identity the wire carries; [`publish_bound`] is the one event that names
//! both, which is how the two are joined.

use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

mod boundary;
pub use boundary::{
    Age, BundleHistory, BundleRecord, BundleSnapshot, BundleSnapshotError, CacheAction,
    ClientEvent, FaultPhase, FilterDetail, FilterSource, HttpSeam, IndexFileKind, LogName, LogPath,
    LogPaths, LogRecord, OperatorDiagnostic, OperatorNotice, OverlayFaultPoint, OverlayOwed,
    ProxyVariableName, PublishOperationId, PublishOperationRefusal, RecordWriter, RecoveryClass,
    SignalKind, SyncFaultPhase, SyncFaultPoint, SyncObjectKind, TeardownCause, WalkOutcome,
    WireRetryClass, closed_operation_span, closed_subscriber, closed_subscriber_with_paths,
};
pub(crate) use boundary::{PathSlot, current_operation_id, current_operation_span};

/// How many random bytes a correlation id carries. Every byte comes from the
/// draw: 64 bits is a collision bound for the operations of one process and
/// its logs, which is all a correlation id is asked to distinguish.
pub const CORRELATION_ID_LEN: usize = 8;

/// The prefix every correlation id is spelled with. The publish operation
/// identity is spelled in lowercase hex alone, so a `-` anywhere in a value
/// settles which of the two it is.
pub const CORRELATION_ID_PREFIX: &str = "cor-";

/// The identity of one client operation in the logs.
///
/// Built only by [`CorrelationId::draw`]: there is no constructor from a
/// string, a path or any other caller data, so an id cannot be derived from
/// user data or collide with one on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelationId([u8; CORRELATION_ID_LEN]);

impl CorrelationId {
    /// Draw a fresh id.
    ///
    /// # Errors
    /// [`EntropyUnavailable`] when the seam could not draw. The caller logs
    /// the operation without an id (and says so with [`op_failed`]); it never
    /// substitutes a counter, a clock reading or zeros.
    pub fn draw<R: SecureRandom + ?Sized>(random: &mut R) -> Result<Self, EntropyUnavailable> {
        let mut bytes = [0_u8; CORRELATION_ID_LEN];
        random.fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    const fn bytes(self) -> [u8; CORRELATION_ID_LEN] {
        self.0
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(CORRELATION_ID_PREFIX)?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// What an operation is. The `kind` field of every operation span, and of
/// the events that name the operation they belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// One `gran` process run: the span every event of the run shares
    /// when no narrower operation is open.
    Session,
    /// Absorbing a write into the overlay.
    OverlayWrite,
    /// Appending a record to the journal.
    JournalAppend,
    /// Registering a write intent with the authority.
    IntentRegister,
    /// A durability barrier (`fsync` and its directory counterpart).
    Fsync,
    /// Submitting a candidate root and landing it.
    Commit,
    /// Rebasing local work onto a newer head.
    Rebase,
    /// One retry sequence of any operation.
    Retry,
    /// Unmounting: the drain and the final flush.
    Unmount,
    /// Installing a landing as the mount's view.
    View,
}

impl OperationKind {
    /// Every label spelling, represented in operator-document order.
    pub const ALL: &'static [Self] = &[
        Self::Session,
        Self::OverlayWrite,
        Self::JournalAppend,
        Self::IntentRegister,
        Self::Fsync,
        Self::Commit,
        Self::Rebase,
        Self::Retry,
        Self::Unmount,
        Self::View,
    ];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::OverlayWrite => "overlay_write",
            Self::JournalAppend => "journal_append",
            Self::IntentRegister => "intent_register",
            Self::Fsync => "fsync",
            Self::Commit => "commit",
            Self::Rebase => "rebase",
            Self::Retry => "retry",
            Self::Unmount => "unmount",
            Self::View => "view",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }

    const fn bundle_tag(self) -> u8 {
        match self {
            Self::Session => 1,
            Self::OverlayWrite => 2,
            Self::JournalAppend => 3,
            Self::IntentRegister => 4,
            Self::Fsync => 5,
            Self::Commit => 6,
            Self::Rebase => 7,
            Self::Retry => 8,
            Self::Unmount => 9,
            Self::View => 10,
        }
    }
}

/// How an operation ended, the `outcome` of [`op_end`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It completed.
    Ok,
    /// It ended in a loud failure, which [`op_failed`] reported.
    Failed,
    /// The caller abandoned it before it finished.
    Cancelled,
    /// Policy or validation refused the operation before its effect.
    Refused,
}

impl Outcome {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Ok, Self::Failed, Self::Cancelled, Self::Refused];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// Why an operation is being retried, the `reason` of [`op_retry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryReason {
    /// A failure that may not recur: a timeout, a reset connection.
    Transient,
    /// The head moved: the work is rebased and tried again.
    Conflict,
    /// The authority or the store could not be reached.
    Unavailable,
}

impl RetryReason {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Transient, Self::Conflict, Self::Unavailable];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// What kind of loud failure it is, the `class` of [`op_failed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    /// The local filesystem or device refused or failed an operation.
    Io,
    /// The authority or the local policy refused the operation.
    Refused,
    /// The operation lost a race it cannot win by retrying alone.
    Conflict,
    /// A required service or resource could not be reached.
    Unavailable,
    /// Bytes that must verify did not.
    Corrupt,
    /// A condition the client believes cannot happen.
    Internal,
}

impl FailureClass {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[
        Self::Io,
        Self::Refused,
        Self::Conflict,
        Self::Unavailable,
        Self::Corrupt,
        Self::Internal,
    ];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Refused => "refused",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
            Self::Corrupt => "corrupt",
            Self::Internal => "internal",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }

    const fn bundle_tag(self) -> u8 {
        match self {
            Self::Io => 1,
            Self::Refused => 2,
            Self::Conflict => 3,
            Self::Unavailable => 4,
            Self::Corrupt => 5,
            Self::Internal => 6,
        }
    }
}

/// Closed class of a metrics exporter failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsFailureClass {
    /// The listener's I/O failed.
    Io,
    /// The exporter could not produce a report.
    Internal,
}

impl MetricsFailureClass {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Internal => "internal",
        }
    }
}

/// The `format` of [`log_config`]: how records are rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable lines.
    Text,
    /// One JSON object per line.
    Json,
}

impl LogFormat {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Text, Self::Json];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// The `destination` of [`log_config`]: where records go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogDestination {
    /// The process's standard error stream.
    Stderr,
    /// A size-rotated file.
    File,
}

impl LogDestination {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Stderr, Self::File];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stderr => "stderr",
            Self::File => "file",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// Why a log filter value was not used, the `reason` of
/// [`log_filter_rejected`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterRejection {
    /// The variable's bytes are not UTF-8.
    NotUnicode,
    /// The value is not a filter directive list.
    Malformed,
}

impl FilterRejection {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::NotUnicode, Self::Malformed];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotUnicode => "not_unicode",
            Self::Malformed => "malformed",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// What moved a writable mount's view, the `cause` of `mount.view`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewCause {
    /// The mount's own commit landed.
    Landed,
    /// Another writer's published head was picked up.
    Adopted,
}

impl ViewCause {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Landed, Self::Adopted];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Landed => "landed",
            Self::Adopted => "adopted",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// How a view change ended, the `outcome` of `mount.view`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewOutcome {
    /// The mount now serves the new root.
    Installed,
    /// The mount keeps its view until its own local work is committed.
    Deferred,
    /// The mount did not install the root.
    Refused,
    /// The mount cannot reach the authority and serves its pinned view.
    Stale,
    /// The mount can reach the authority again.
    Fresh,
}

impl ViewOutcome {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[
        Self::Installed,
        Self::Deferred,
        Self::Refused,
        Self::Stale,
        Self::Fresh,
    ];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Deferred => "deferred",
            Self::Refused => "refused",
            Self::Stale => "stale",
            Self::Fresh => "fresh",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// Why a live commit is backing off, the `cause` of `commit.backoff`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackoffCause {
    /// The authority cannot be reached.
    Outage,
    /// The commit has been refused eight times.
    Stall,
}

impl BackoffCause {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Outage, Self::Stall];

    /// The stable spelling that appears in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outage => "outage",
            Self::Stall => "stall",
        }
    }

    /// The member spelled `text`, or `None` when it is outside the domain.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// A live commit backoff episode's transition.
///
/// ```compile_fail,E0533
/// use granary_client::BackoffOutcome;
/// let outcome = BackoffOutcome::Recovered;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackoffOutcome {
    /// The episode began.
    Entered,
    /// A landing ended the episode.
    Recovered { attempts: u64 },
}

impl BackoffOutcome {
    /// Every label spelling, represented in operator-document order.
    pub const ALL: &'static [Self] = &[Self::Entered, Self::Recovered { attempts: 0 }];

    /// The stable spelling that appears in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entered => "entered",
            Self::Recovered { .. } => "recovered",
        }
    }

    /// The member spelled `text`, or `None` when it is outside the domain.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// Why a writable mount's live commit loop stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitStopCause {
    /// The writable store is fenced or poisoned.
    Fenced,
    /// The mount's served view is closed.
    Closed,
}

impl CommitStopCause {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Fenced, Self::Closed];

    /// The stable spelling that appears in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fenced => "fenced",
            Self::Closed => "closed",
        }
    }

    /// The member spelled `text`, or `None` when it is outside the domain.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// How the verified chain proves a prepared root published, the `relation` of
/// `recover.subsumed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubsumedRelation {
    /// A different verified chain root has the prepared manifest, including
    /// the prepared parent itself.
    Later,
    /// The prepared root itself is the head.
    Equal,
    /// The prepared root is on the chain below the head.
    Descendant,
}

impl SubsumedRelation {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Later, Self::Equal, Self::Descendant];

    /// The stable spelling that appears in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Later => "later",
            Self::Equal => "equal",
            Self::Descendant => "descendant",
        }
    }

    /// The member spelled `text`, or `None` when it is outside the domain.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// What an explicit recovery found or did, each its own `recover.*` event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoverEvent {
    /// Recovery could not use the existing signing seed.
    SigningKeyRefused,
    /// The actual journal is complete and the Released receipt is durable.
    JournalFinished(u64),
    /// Admitted journal work remains; the reason belongs to a closed domain.
    JournalBlocked(&'static str),
    /// An archived candidate matched the verified published chain.
    ArchivedLanded(u64),
    /// A proof-bound replacement removed the boundary and its fence.
    FenceSettled(&'static str),
    /// Publication classification is still owed at the sequence.
    Unresolved(u64),
    /// One explicitly acknowledged exact send completed its transport call.
    Resent(u64),
    /// The readback holds no row for the selected writer.
    Nothing,
    /// The root at the sequence carries the writer, related as given.
    Subsumed(SubsumedRelation, u64),
    /// The verified chain does not reach the prepared root's parent.
    Stale,
    /// The recovered root landed at the sequence.
    Landed(u64),
    /// It landed merged onto a head this many roots past its parent.
    Rebased(u64),
    /// The merge met a path both sides changed; nothing is published.
    Conflict,
    /// The carrier is not owned: only a renewed selection continues.
    SelectionChanged(&'static str),
    /// The carrier is not owned beside a landing it has not refreshed.
    LandedUnowned,
}

/// How a writable mount's shutdown ended, the `outcome` of `mount.unmount`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmountOutcome {
    /// Everything acknowledged is published and the intent is released.
    Committed,
    /// Nothing was owed, and the intent is released.
    Clean,
    /// Work is left in the journal and staging, and the intent is kept.
    Incomplete,
    /// The authority refused this mount's ownership or its commit.
    Fenced,
}

impl UnmountOutcome {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] =
        &[Self::Committed, Self::Clean, Self::Incomplete, Self::Fenced];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Clean => "clean",
            Self::Incomplete => "incomplete",
            Self::Fenced => "fenced",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// Why a shutdown left work behind, the `cause` of `mount.unmount`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmountCause {
    /// The shutdown's bound ran out.
    Deadline,
    /// A step failed, or the authority fenced the mount.
    Failed,
    /// The sequence itself was lost, or its residue could not be read.
    Internal,
}

impl UnmountCause {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Deadline, Self::Failed, Self::Internal];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Failed => "failed",
            Self::Internal => "internal",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// What ran a shutdown, the `trigger` of `mount.unmount`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmountTrigger {
    /// The mount's session ended.
    SessionEnd,
    /// A signal asked the daemon to stop while its session served.
    Signal,
    /// The next start finished a shutdown that left work behind, before it
    /// served.
    Start,
    /// The owner requested shutdown through the mount control socket.
    Umount,
}

impl UnmountTrigger {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::SessionEnd, Self::Signal, Self::Start, Self::Umount];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionEnd => "session_end",
            Self::Signal => "signal",
            Self::Start => "start",
            Self::Umount => "umount",
        }
    }

    /// The member spelled `text`, or `None`: a spelling outside the
    /// domain is refused, never rounded to a neighbour.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
}

/// The daemon's mount-table observation when its session did not end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountListing {
    /// The mount was absent.
    Gone,
    /// The mount was still present.
    Listed,
    /// The mount's presence could not be checked.
    Unknown,
}

impl MountListing {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Gone, Self::Listed, Self::Unknown];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gone => "gone",
            Self::Listed => "listed",
            Self::Unknown => "unknown",
        }
    }
}

/// The fusectl connection observation when the daemon's session did not end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuseConnection {
    /// The connection directory still existed.
    Alive,
    /// The connection directory was absent.
    Gone,
    /// The connection could not be checked.
    Unknown,
}

impl FuseConnection {
    /// Every member, in the order the operator document lists them.
    pub const ALL: &'static [Self] = &[Self::Alive, Self::Gone, Self::Unknown];

    /// The stable spelling that appears in the logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Gone => "gone",
            Self::Unknown => "unknown",
        }
    }
}

const MOUNT_SESSION_DID_NOT_END: &str =
    "client.gran.mount.the.fuse.session.did.not.end.after.its.unmount";

/// One entry of the vocabulary: an event's name, level and field names.
#[derive(Clone, Copy, Debug)]
pub struct EventSpec {
    /// The stable `event` value.
    pub name: &'static str,
    /// The level it is emitted at, spelled as the logs spell it.
    pub level: &'static str,
    /// Its field names, in emission order, not counting `event` itself.
    pub fields: &'static [&'static str],
}

/// The name of [`op_begin`].
pub const OP_BEGIN: &str = "op.begin";
/// The name of [`op_end`].
pub const OP_END: &str = "op.end";
/// The name of [`op_retry`].
pub const OP_RETRY: &str = "op.retry";
/// The name of [`op_failed`].
pub const OP_FAILED: &str = "op.failed";
/// The name of the typed metrics exporter failure event.
pub const METRICS_EXPORT_FAILED: &str = "metrics.export_failed";
/// The registered namespace-conflict detail name.
pub const OP_CONFLICT: &str = "op.conflict";
/// The name of [`publish_bound`].
pub const PUBLISH_BOUND: &str = "op.publish_bound";
/// The name of [`log_config`].
pub const LOG_CONFIG: &str = "log.config";
/// The name of [`log_filter_rejected`].
pub const LOG_FILTER_REJECTED: &str = "log.filter_rejected";
/// A writable mount's view change: INFO when installed or deferred, WARN
/// when refused.
pub const MOUNT_VIEW: &str = "mount.view";
/// A writable mount's shutdown: INFO when committed or clean, WARN when it
/// left work behind or was fenced.
pub const MOUNT_UNMOUNT: &str = "mount.unmount";
/// A live commit retry episode's transition.
pub const COMMIT_BACKOFF: &str = "commit.backoff";
/// A writable mount's live commit loop stopped before shutdown.
pub const COMMIT_STOPPED: &str = "commit.stopped";

/// The whole event vocabulary. A test emits every entry and compares the
/// output's name, level and field names to this table, and the operator
/// document is compared to it in turn.
pub const EVENTS: &[EventSpec] = &[
    EventSpec {
        name: "sync.fault",
        level: "WARN",
        fields: &["point", "phase", "occurrence", "object_kind"],
    },
    EventSpec {
        name: OP_CONFLICT,
        level: "WARN",
        fields: &["path", "class"],
    },
    EventSpec {
        name: "overlay.recovery",
        level: "INFO",
        fields: &[
            "outcome",
            "files",
            "bytes",
            "record_index",
            "cap",
            "commit_requested",
            "owed",
            "stage_reserve",
            "projected_reserve",
            "ownership_reserve",
            "completion_reserve",
            "writer_reserve",
            "journal_reserve",
            "rolled_back_stages",
            "rolled_back_bytes",
        ],
    },
    EventSpec {
        name: "overlay.stage_rolled_back",
        level: "WARN",
        fields: &[
            "rollback_seq",
            "stage_id",
            "old_size",
            "restored_size",
            "discarded_bytes",
            "path",
        ],
    },
    EventSpec {
        name: "overlay.stage_rolled_back",
        level: "WARN",
        fields: &[
            "rollback_seq",
            "stage_id",
            "old_size",
            "restored_size",
            "discarded_bytes",
        ],
    },
    EventSpec {
        name: "overlay.refused",
        level: "ERROR",
        fields: &["class", "record_index", "files", "bytes"],
    },
    EventSpec {
        name: "overlay.discard_refused",
        level: "WARN",
        fields: &["reason"],
    },
    EventSpec {
        name: "overlay.reconcile_refused",
        level: "WARN",
        fields: &["reason"],
    },
    EventSpec {
        name: "overlay.sweep",
        level: "INFO",
        fields: &["files", "bytes"],
    },
    EventSpec {
        name: "overlay.fault",
        level: "WARN",
        fields: &["point", "phase", "occurrence", "record_index"],
    },
    EventSpec {
        name: OP_BEGIN,
        level: "DEBUG",
        fields: &["kind"],
    },
    EventSpec {
        name: OP_END,
        level: "DEBUG",
        fields: &["kind", "outcome"],
    },
    EventSpec {
        name: OP_RETRY,
        level: "WARN",
        fields: &["kind", "attempt", "reason"],
    },
    EventSpec {
        name: METRICS_EXPORT_FAILED,
        level: "ERROR",
        fields: &["class"],
    },
    EventSpec {
        name: OP_FAILED,
        level: "ERROR",
        fields: &["kind", "class"],
    },
    EventSpec {
        name: "overlay.failures_dropped",
        level: "ERROR",
        fields: &["dropped"],
    },
    EventSpec {
        name: "commit.contention",
        level: "WARN",
        fields: &["commits", "conflicts"],
    },
    EventSpec {
        name: COMMIT_BACKOFF,
        level: "WARN",
        fields: &["cause", "outcome"],
    },
    EventSpec {
        name: COMMIT_BACKOFF,
        level: "INFO",
        fields: &["cause", "outcome", "attempts"],
    },
    EventSpec {
        name: "sync.workspace_exhausted",
        level: "WARN",
        fields: &["reason", "needed", "limit"],
    },
    EventSpec {
        name: "overlay.cap_exhausted",
        level: "WARN",
        fields: &["reason", "cap", "charged", "reserved", "captured", "needed"],
    },
    EventSpec {
        name: COMMIT_STOPPED,
        level: "ERROR",
        fields: &["cause"],
    },
    EventSpec {
        name: PUBLISH_BOUND,
        level: "INFO",
        fields: &["publish_operation"],
    },
    EventSpec {
        name: LOG_CONFIG,
        level: "DEBUG",
        fields: &["format", "destination"],
    },
    EventSpec {
        name: LOG_FILTER_REJECTED,
        level: "WARN",
        fields: &["source", "reason", "detail"],
    },
    EventSpec {
        name: MOUNT_VIEW,
        level: "INFO",
        fields: &["cause", "outcome", "seq"],
    },
    EventSpec {
        name: MOUNT_VIEW,
        level: "WARN",
        fields: &["cause", "outcome", "seq"],
    },
    EventSpec {
        name: MOUNT_UNMOUNT,
        level: "INFO",
        fields: &["trigger", "outcome", "seq", "elapsed_ms"],
    },
    EventSpec {
        name: MOUNT_UNMOUNT,
        level: "WARN",
        fields: &[
            "trigger",
            "outcome",
            "cause",
            "files",
            "bytes",
            "operations",
            "elapsed_ms",
        ],
    },
    EventSpec {
        name: MOUNT_UNMOUNT,
        level: "WARN",
        fields: &["trigger", "outcome", "cause", "elapsed_ms"],
    },
    EventSpec {
        name: MOUNT_SESSION_DID_NOT_END,
        level: "WARN",
        fields: &["message", "listed", "connection"],
    },
    EventSpec {
        name: "recover.nothing",
        level: "WARN",
        fields: &[],
    },
    EventSpec {
        name: "recover.signing_key_refused",
        level: "WARN",
        fields: &[],
    },
    EventSpec {
        name: "recover.subsumed",
        level: "INFO",
        fields: &["relation", "seq"],
    },
    EventSpec {
        name: "recover.stale",
        level: "WARN",
        fields: &[],
    },
    EventSpec {
        name: "recover.landed",
        level: "INFO",
        fields: &["seq"],
    },
    EventSpec {
        name: "recover.archived_landed",
        level: "WARN",
        fields: &["seq"],
    },
    EventSpec {
        name: "recover.rebased",
        level: "INFO",
        fields: &["chain_len"],
    },
    EventSpec {
        name: "recover.conflict",
        level: "WARN",
        fields: &["path"],
    },
    EventSpec {
        name: "recover.selection_changed",
        level: "WARN",
        fields: &["token"],
    },
    EventSpec {
        name: "recover.landed_unowned",
        level: "WARN",
        fields: &[],
    },
    EventSpec {
        name: "recover.journal_finished",
        level: "INFO",
        fields: &["base_seq"],
    },
    EventSpec {
        name: "recover.journal_blocked",
        level: "WARN",
        fields: &["reason"],
    },
    EventSpec {
        name: "recover.fence_settled",
        level: "INFO",
        fields: &["how"],
    },
    EventSpec {
        name: "recover.unresolved",
        level: "WARN",
        fields: &["seq"],
    },
    EventSpec {
        name: "recover.resent",
        level: "WARN",
        fields: &["seq"],
    },
];

/// The name of the span every operation's events are recorded inside.
pub const OPERATION_SPAN: &str = "op";

/// Open the span of one operation. Enter it (or instrument a future with it)
/// and every event recorded inside carries `op` and `kind`.
///
/// **The span is at ERROR level on purpose.** A filter drops a span whose
/// level it excludes, and an event inside a dropped span loses its `op`: an
/// INFO span would strip the correlation id from every WARN and ERROR line of
/// an operator running at `warn`, which is when the id matters. ERROR is the
/// level no filter that keeps any event excludes.
#[must_use]
pub fn operation_span(kind: OperationKind, id: &CorrelationId) -> tracing::Span {
    closed_operation_span(kind, id)
}

/// An operation began.
pub fn op_begin(kind: OperationKind) {
    ClientEvent::op_begin(kind).emit();
}
/// An operation ended.
pub fn op_end(kind: OperationKind, outcome: Outcome) {
    ClientEvent::op_end(kind, outcome).emit();
}
/// An operation is being retried; `attempt` counts from 1.
pub fn op_retry(kind: OperationKind, attempt: u32, reason: RetryReason) {
    ClientEvent::op_retry(kind, attempt, reason).emit();
}
/// Report a loud failure with a closed class.
pub fn op_failed(kind: OperationKind, class: FailureClass) {
    let deferred = kind == OperationKind::OverlayWrite
        && OVERLAY_CALLBACKS.with(|callbacks| {
            let mut callbacks = callbacks.borrow_mut();
            let Some((_, failures)) = callbacks.last_mut() else {
                return false;
            };
            if failures.classes.len() < DEFERRED_OVERLAY_FAILURE_LIMIT {
                failures.classes.push(class);
            } else {
                failures.dropped = failures.dropped.saturating_add(1);
            }
            true
        });
    if !deferred {
        ClientEvent::op_failed(kind, class).emit();
    }
}

const DEFERRED_OVERLAY_FAILURE_LIMIT: usize = 8;

#[derive(Debug, Default)]
struct DeferredOverlayFailures {
    classes: Vec<FailureClass>,
    dropped: usize,
}

impl DeferredOverlayFailures {
    fn flush(self) {
        // Emit through the closed facade without deferring into a parent scope.
        for class in self.classes {
            ClientEvent::op_failed(OperationKind::OverlayWrite, class).emit();
        }
        if self.dropped > 0 {
            ClientEvent::overlay_failures_dropped(self.dropped as u64).emit();
        }
    }
}

std::thread_local! {
    static OVERLAY_CALLBACKS: std::cell::RefCell<Vec<(std::rc::Rc<()>, DeferredOverlayFailures)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Held by the synchronous callback, including while it unwinds. The Rc also
/// keeps this scope on the thread whose buffer it owns.
#[derive(Debug)]
pub(crate) struct OverlayCallbackScope(std::rc::Rc<()>);

impl granary_fuse::CallbackScope for OverlayCallbackScope {}

impl Drop for OverlayCallbackScope {
    fn drop(&mut self) {
        let failures = OVERLAY_CALLBACKS.with(|callbacks| {
            let mut callbacks = callbacks.borrow_mut();
            let index = callbacks
                .iter()
                .position(|(scope, _)| std::rc::Rc::ptr_eq(scope, &self.0))?;
            Some(callbacks.remove(index).1)
        });
        if let Some(failures) = failures {
            failures.flush();
            op_end(OperationKind::OverlayWrite, Outcome::Cancelled);
        }
    }
}

/// The adapter retains this guard until after its synchronous completion.
pub(crate) fn overlay_callback_begin() -> OverlayCallbackScope {
    let scope = OverlayCallbackScope(std::rc::Rc::new(()));
    OVERLAY_CALLBACKS.with(|callbacks| {
        callbacks
            .borrow_mut()
            .push((scope.0.clone(), DeferredOverlayFailures::default()));
    });
    op_begin(OperationKind::OverlayWrite);
    scope
}

pub(crate) fn overlay_callback_end(outcome: Outcome, failure: Option<FailureClass>) {
    let deferred = OVERLAY_CALLBACKS
        .with(|callbacks| callbacks.borrow_mut().pop())
        .map(|(_, failures)| failures);
    finish_overlay_callback(deferred, outcome, failure);
}

fn finish_overlay_callback(
    deferred: Option<DeferredOverlayFailures>,
    outcome: Outcome,
    failure: Option<FailureClass>,
) {
    if outcome == Outcome::Ok
        && let Some(failures) = deferred
    {
        failures.flush();
    }
    if let Some(class) = failure {
        ClientEvent::op_failed(OperationKind::OverlayWrite, class).emit();
    }
    op_end(OperationKind::OverlayWrite, outcome);
}
/// Detach the local buffer without ending the operation before its retry.
pub(crate) fn overlay_callback_capture() -> Option<Box<dyn granary_fuse::DeferredCallbackScope>> {
    let failures = OVERLAY_CALLBACKS
        .with(|callbacks| callbacks.borrow_mut().pop())?
        .1;
    Some(Box::new(DeferredOverlayCallback(Some(failures))))
}

#[derive(Debug)]
struct DeferredOverlayCallback(Option<DeferredOverlayFailures>);
impl granary_fuse::DeferredCallbackScope for DeferredOverlayCallback {
    fn completed(mut self: Box<Self>, result: granary_fuse::CallbackOutcome) {
        let (outcome, failure) = crate::mount::callback_outcome(result);
        finish_overlay_callback(self.0.take(), outcome, failure);
    }
}
impl Drop for DeferredOverlayCallback {
    fn drop(&mut self) {
        if let Some(failures) = self.0.take() {
            failures.flush();
            op_end(OperationKind::OverlayWrite, Outcome::Cancelled);
        }
    }
}
/// Join the identity minted by the publication owner to the current operation.
pub fn publish_bound(identity: PublishOperationId) {
    ClientEvent::publish_bound(identity).emit();
}
/// Report the active log format and destination classes.
pub fn log_config(format: LogFormat, destination: LogDestination) {
    ClientEvent::log_config(format, destination).emit();
}
/// Report a refused optional filter without its bytes or parser chain.
pub fn log_filter_rejected(reason: FilterRejection, detail: FilterDetail) {
    ClientEvent::log_filter_rejected(FilterSource::RustLog, reason, detail).emit();
}
/// Assemble the production subscriber. Admission precedes filtering and encoding.
/// Scalar output uses no terminal controls.
#[must_use]
pub fn subscriber<W>(
    format: LogFormat,
    filter: tracing_subscriber::EnvFilter,
    writer: W,
) -> Box<dyn tracing::Subscriber + Send + Sync>
where
    W: boundary::RecordWriter + Clone + Send + Sync + 'static,
{
    closed_subscriber(format, filter, writer)
}

#[cfg(test)]
mod tests;

/// Closed recovery outcomes; no pathname or content is emitted.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RecoveryOutcome {
    Clean,
    Repaired,
    Pending,
}

pub(crate) fn overlay_recovery(
    outcome: RecoveryOutcome,
    files: u64,
    cap: u64,
    summary: crate::OverlaySummary,
) {
    let outcome = match outcome {
        RecoveryOutcome::Clean => RecoveryClass::Clean,
        RecoveryOutcome::Repaired => RecoveryClass::Repaired,
        RecoveryOutcome::Pending => RecoveryClass::Pending,
    };
    ClientEvent::overlay_recovery(
        outcome,
        files,
        summary.charged_bytes,
        summary.records,
        cap,
        summary.commit_requested,
        summary.owed,
        [summary.rolled_back_stages, summary.rolled_back_bytes],
    )
    .emit();
}
pub(crate) fn stage_rolled_back(
    seq: u64,
    id: u64,
    path: Option<&[granary_core::manifest::Name]>,
    old_size: u64,
    restored_size: u64,
    discarded_bytes: u64,
) {
    let event = ClientEvent::stage_rolled_back(
        seq,
        id,
        old_size,
        restored_size,
        discarded_bytes,
        path.is_some(),
    );
    if let Some(names) = path {
        let path = crate::local_report::namespace_path(names);
        event.emit_paths(&[PathSlot::Path("path", LogPath::file(&path))]);
    } else {
        event.emit();
    }
}
pub(crate) fn namespace_conflict(names: &[granary_core::manifest::Name]) {
    let path = crate::local_report::namespace_path(names);
    ClientEvent::conflict_detail().emit_paths(&[PathSlot::Path("path", LogPath::file(&path))]);
}
pub(crate) fn overlay_refused(class: FailureClass, record_index: u64, files: u64, bytes: u64) {
    ClientEvent::overlay_refused(class, record_index, files, bytes).emit();
}
pub(crate) fn overlay_sweep(files: u64, bytes: u64) {
    ClientEvent::overlay_sweep(files, bytes).emit();
}
/// A view change for `cause` at `seq` ended as `outcome`.
pub(crate) fn mount_view(cause: ViewCause, outcome: ViewOutcome, seq: u64) {
    ClientEvent::mount_view(cause, outcome, seq).emit();
}
/// A live commit backoff episode changed state.
pub(crate) fn commit_backoff(cause: BackoffCause, outcome: BackoffOutcome) {
    ClientEvent::commit_backoff(cause, outcome).emit();
}
/// A live commit loop stopped before shutdown.
pub(crate) fn commit_stopped(cause: CommitStopCause) {
    ClientEvent::commit_stopped(cause).emit();
}
/// An explicit recovery found or did `event`.
pub(crate) fn recover(event: RecoverEvent) {
    ClientEvent::recover(event).emit();
}
/// A shutdown `trigger` ran ended as `outcome` on the base at `seq`,
/// `elapsed_ms` after it began.
pub(crate) fn mount_unmounted(
    trigger: UnmountTrigger,
    outcome: UnmountOutcome,
    seq: u64,
    elapsed_ms: u64,
) {
    ClientEvent::mount_unmounted(trigger, outcome, seq, elapsed_ms).emit();
}
/// A shutdown `trigger` ran ended as `outcome` for `cause`, leaving
/// `counts` (files, bytes, operations) when its residue could be read.
pub(crate) fn mount_unmount_left(
    trigger: UnmountTrigger,
    outcome: UnmountOutcome,
    cause: UnmountCause,
    counts: Option<[u64; 3]>,
    elapsed_ms: u64,
) {
    ClientEvent::mount_unmount_left(trigger, outcome, cause, counts, elapsed_ms).emit();
}
#[cfg(any(test, feature = "overlay-fault-tests"))]
pub(crate) fn overlay_fault(
    point: OverlayFaultPoint,
    phase: FaultPhase,
    occurrence: u64,
    record_index: u64,
) {
    ClientEvent::overlay_fault(point, phase, occurrence, record_index).emit();
}

#[cfg(any(test, feature = "overlay-fault-tests"))]
pub(crate) fn sync_fault(
    point: &'static str,
    phase: &'static str,
    occurrence: u64,
    object_kind: &'static str,
) {
    ClientEvent::sync_fault(
        SyncFaultPoint::from_seam(point),
        SyncFaultPhase::from_seam(phase),
        occurrence,
        SyncObjectKind::from_seam(object_kind),
    )
    .emit();
}
