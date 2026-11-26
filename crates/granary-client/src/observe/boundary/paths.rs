// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ordinary path adapters and independent bounded bundle input.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::{BundleRecord, Scalar};
use granary_core::support::{
    BUNDLE_FAILURES_ENTRIES_MAX, BUNDLE_LOG_BYTES_MAX, BUNDLE_LOG_RECORD_MAX,
    BUNDLE_LOG_RECORDS_MAX, BundleFailure, BundleFailures, BundleRefusal,
};

const PATH_MAX: usize = 4096;
const HISTORY_RECORDS: usize = BUNDLE_LOG_RECORDS_MAX;
const HISTORY_BYTES: usize = BUNDLE_LOG_BYTES_MAX;

/// Disclosure policy for explicitly inventoried ordinary log paths and names.
/// Bundle input and metrics always retain their own redacted policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogPaths {
    /// Emit semantic classes, including for basenames.
    #[default]
    Redacted,
    /// Emit bounded, losslessly escaped ordinary path/name bytes.
    Full,
}
impl LogPaths {
    /// Accept only the exact lower-case configuration vocabulary.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "redacted" => Some(Self::Redacted),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// An ordinary path borrowed by an audited role adapter.
/// There is no public raw-path or credential-path constructor.
/// Debug always emits its class, including in a full-path session.
///
/// ```
/// use granary_client::{CorrelationId, LocalConflictStatus};
/// use granary_core::secure_random::SecureRandom;
/// struct Random;
/// impl SecureRandom for Random {
///     fn fill(&mut self, out: &mut [u8]) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
///         out.fill(42); Ok(())
///     }
/// }
/// let id = CorrelationId::draw(&mut Random).unwrap();
/// let status = LocalConflictStatus::new(std::path::Path::new("synthetic-path-sentinel"), id).unwrap();
/// assert_eq!(format!("{:?}", status.log_path()), "<file>");
/// ```
/// ```compile_fail,E0423
/// use granary_client::LogPath;
/// let credential = LogPath(std::path::Path::new("synthetic-credential"));
/// ```
#[derive(Clone, Copy)]
pub struct LogPath<'a> {
    source: &'a Path,
    class: &'static str,
}
impl std::fmt::Debug for LogPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.class)
    }
}
impl<'a> LogPath<'a> {
    pub(crate) fn file(source: &'a Path) -> Self {
        Self {
            source,
            class: "<file>",
        }
    }
    pub(crate) fn directory(source: &'a Path) -> Self {
        Self {
            source,
            class: "<directory>",
        }
    }
    pub(crate) fn cache_root(source: &'a Path) -> Self {
        Self {
            source,
            class: "<cache-root>",
        }
    }
    pub(super) fn log_file(source: &'a Path) -> Self {
        Self {
            source,
            class: "<log-file>",
        }
    }
    pub(super) fn project(self, policy: LogPaths) -> Scalar {
        project_bytes(self.source.as_os_str(), self.class, policy)
    }
}

/// A borrowed directory-entry name. Debug always emits `<name>`.
/// Construction is restricted to the directory-walk adapters.
#[derive(Clone, Copy)]
pub struct LogName<'a>(&'a OsStr);
impl std::fmt::Debug for LogName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<name>")
    }
}
impl<'a> LogName<'a> {
    pub(crate) fn entry(source: &'a OsStr) -> Self {
        Self(source)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PathSlot<'a> {
    Path(&'static str, LogPath<'a>),
    Name(&'static str, LogName<'a>),
}
impl PathSlot<'_> {
    pub(super) fn field(self) -> &'static str {
        match self {
            Self::Path(field, _) | Self::Name(field, _) => field,
        }
    }
    pub(super) fn class(self) -> &'static str {
        match self {
            Self::Path(_, path) => path.class,
            Self::Name(_, _) => "<name>",
        }
    }
    pub(super) fn project(self, policy: LogPaths) -> Scalar {
        match self {
            Self::Path(_, path) => path.project(policy),
            Self::Name(_, name) => project_bytes(name.0, "<name>", policy),
        }
    }
}

fn project_bytes(source: &OsStr, class: &'static str, policy: LogPaths) -> Scalar {
    if policy == LogPaths::Redacted {
        return Scalar::text(class);
    }
    let bytes = source.as_bytes();
    // Bound the source before allocating, copying or inspecting its contents.
    if bytes.len() > PATH_MAX {
        return Scalar::Text(format!("{class}:path_too_large"));
    }
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(*byte)),
            byte => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    Scalar::Text(out)
}

pub(super) fn projected_domain(class: &str, value: &str) -> bool {
    value == class
        || value == format!("{class}:path_too_large")
        || (value.len() <= PATH_MAX * 4 && value.bytes().all(|b| (0x20..=0x7e).contains(&b)))
}

#[cfg(test)]
std::thread_local! {
    static SNAPSHOT_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Default)]
struct History {
    records: VecDeque<BundleRecord>,
    bytes: usize,
    lost: u64,
}

pub(super) struct FailureHistory {
    entries: VecDeque<BundleFailure>,
    next_ordinal: Option<u64>,
}

impl Default for FailureHistory {
    fn default() -> Self {
        Self {
            entries: VecDeque::with_capacity(BUNDLE_FAILURES_ENTRIES_MAX),
            next_ordinal: Some(1),
        }
    }
}

impl History {
    fn snapshot(&self) -> BundleSnapshot {
        #[cfg(test)]
        SNAPSHOT_COPIES.set(SNAPSHOT_COPIES.get() + 1);
        BundleSnapshot {
            records: self.records.iter().cloned().collect(),
            bytes: self.bytes,
            lost: self.lost,
        }
    }
}

/// History availability and retained-bound failures are distinct collection outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleSnapshotError {
    /// The producer is busy or its history mutex is poisoned.
    Unavailable,
    /// The retained record count exceeds the format bound.
    CountBound,
    /// A record length, byte total or retained byte accounting is invalid.
    SizeBound,
}
impl std::fmt::Display for BundleSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "unavailable",
            Self::CountBound => "support count bound",
            Self::SizeBound => "support size bound",
        })
    }
}
impl std::error::Error for BundleSnapshotError {}

/// Independent typed input for a future client bundle writer.
/// No rendered-log, local-report or configuration-text input is accepted.
///
/// ```compile_fail,E0308
/// use granary_client::{BundleHistory, LogRecord};
/// fn tee(history: &BundleHistory, record: LogRecord) { history.record(record); }
/// ```
#[derive(Clone, Default)]
pub struct BundleHistory(Arc<Mutex<History>>, Arc<Mutex<FailureHistory>>);
impl std::fmt::Debug for BundleHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<bundle-history>")
    }
}
impl BundleHistory {
    /// Hold the log-history producer lock for cross-crate fault tests.
    #[cfg(feature = "overlay-fault-tests")]
    #[doc(hidden)]
    pub fn hold_log_lock_for_test(&self) -> impl Drop + '_ {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hold the failure-history producer lock for cross-crate fault tests.
    #[cfg(feature = "overlay-fault-tests")]
    #[doc(hidden)]
    pub fn hold_failure_ring_for_test(&self) -> impl Drop + '_ {
        self.1
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(super) fn set_failure_ordinal_for_test(&self, ordinal: u64) {
        self.1.lock().unwrap().next_ordinal = Some(ordinal);
    }

    #[cfg(test)]
    pub(super) fn hold_failure_lock_for_test(&self) -> std::sync::MutexGuard<'_, FailureHistory> {
        self.1.lock().unwrap()
    }

    /// Copy retained failure scalars without waiting for their producer.
    /// # Errors
    /// Returns [`BundleRefusal`] like the other scalar producers: this fixed-capacity
    /// ring has no count or size error, only contention, poison or ordinal exhaustion.
    pub fn try_failure_snapshot(&self) -> Result<BundleFailures, BundleRefusal> {
        let failures = self.1.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => BundleRefusal::TimedOut,
            std::sync::TryLockError::Poisoned(_) => BundleRefusal::Unavailable,
        })?;
        if failures.next_ordinal.is_none() {
            return Err(BundleRefusal::Unavailable);
        }
        let entries = failures.entries.iter().copied().collect();
        Ok(BundleFailures { entries })
    }

    pub(super) fn record_failure(
        &self,
        event: u8,
        kind: u8,
        class: u8,
        correlation: Option<[u8; 8]>,
    ) {
        let Ok(mut failures) = self.1.lock() else {
            return;
        };
        let Some(ordinal) = failures.next_ordinal else {
            return;
        };
        let Some(next_ordinal) = ordinal.checked_add(1) else {
            failures.next_ordinal = None;
            return;
        };
        if failures.entries.len() == BUNDLE_FAILURES_ENTRIES_MAX {
            failures.entries.pop_front();
        }
        failures.entries.push_back(BundleFailure {
            ordinal,
            event,
            kind,
            class,
            correlation,
        });
        failures.next_ordinal = Some(next_ordinal);
    }

    /// Copy a bounded redacted history without waiting for its producer.
    /// # Errors
    /// Returns [`BundleSnapshotError::Unavailable`] for contention or poison;
    /// count and size errors indicate broken retained invariants, not missing input.
    pub fn try_snapshot(&self) -> Result<BundleSnapshot, BundleSnapshotError> {
        let history = self
            .0
            .try_lock()
            .map_err(|_| BundleSnapshotError::Unavailable)?;
        if history.records.len() > BUNDLE_LOG_RECORDS_MAX {
            return Err(BundleSnapshotError::CountBound);
        }
        let mut bytes = 0usize;
        for record in &history.records {
            let length = record.as_bytes().len();
            if !(1..=BUNDLE_LOG_RECORD_MAX).contains(&length) {
                return Err(BundleSnapshotError::SizeBound);
            }
            bytes = bytes
                .checked_add(length)
                .filter(|n| *n <= BUNDLE_LOG_BYTES_MAX)
                .ok_or(BundleSnapshotError::SizeBound)?;
        }
        if bytes != history.bytes {
            return Err(BundleSnapshotError::SizeBound);
        }
        Ok(history.snapshot())
    }

    /// Retain a bounded independently redacted projection, evicting oldest whole records.
    pub fn record(&self, record: BundleRecord) {
        let mut history = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let size = record.as_bytes().len();
        if size > HISTORY_BYTES {
            history.lost = history.lost.saturating_add(1);
            return;
        }
        while history.records.len() >= HISTORY_RECORDS || history.bytes + size > HISTORY_BYTES {
            if let Some(oldest) = history.records.pop_front() {
                history.bytes -= oldest.as_bytes().len();
                history.lost = history.lost.saturating_add(1);
            }
        }
        history.bytes += size;
        history.records.push_back(record);
    }
    /// Copy only bounded typed projections; unavailable writers must not substitute logs.
    #[must_use]
    pub fn snapshot(&self) -> BundleSnapshot {
        let history = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        history.snapshot()
    }
}

/// A bounded bundle-input snapshot with whole-record loss accounting.
#[derive(Clone)]
pub struct BundleSnapshot {
    records: Vec<BundleRecord>,
    bytes: usize,
    lost: u64,
}
impl std::fmt::Debug for BundleSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<bundle-snapshot>")
    }
}
impl BundleSnapshot {
    /// Independent redacted records, oldest first.
    #[must_use]
    pub fn records(&self) -> &[BundleRecord] {
        &self.records
    }
    /// Total encoded record bytes.
    #[must_use]
    pub fn encoded_bytes(&self) -> usize {
        self.bytes
    }
    /// Records evicted or refused since this history was created.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.lost
    }
}

#[cfg(test)]
mod tests;
