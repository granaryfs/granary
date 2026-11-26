// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Session-owned cumulative observations. Recording performs only atomic operations;
//! export works on an owned, approximate copy and never holds a producer lock.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use crate::observe::{FailureClass, OperationKind, Outcome, RetryReason, op_failed};
use granary_core::secure_random::SecureRandom;
use granary_core::support::{BundleHistogram, BundleMetrics};

pub const METRICS_SCHEMA_VERSION: u64 = 2;
pub const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
pub const METRICS_MAX_BYTES: usize = 65_536;
pub const METRICS_MAX_SERIES: usize = 512;
pub const METRICS_MAX_LINE: usize = 512;
const INVALID: u64 = u64::MAX;
const BUCKET_US: [u64; 11] = [
    1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 5_000_000,
    30_000_000,
];
const BUCKET_TEXT: [&str; 12] = [
    "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "5", "30", "+Inf",
];

/// Fixed refusal text never repeats an operator-supplied label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsError {
    InvalidLabel,
    Unavailable,
    SequenceExhausted,
    OutputLimit,
}
impl std::fmt::Display for MetricsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLabel => "invalid metrics label",
            Self::Unavailable => "metrics incarnation unavailable",
            Self::SequenceExhausted => "metrics sequence exhausted",
            Self::OutputLimit => "metrics output limit exceeded",
        })
    }
}
impl std::error::Error for MetricsError {}

mod catalogue;
use catalogue::Metric;
pub use catalogue::{
    ByteDirection, CachePhase, CacheResult, CommitResult, METRICS_CATALOGUE, MetricSpec,
    MetricsGroup, RegistrationResult, UploadObject,
};
pub use granary_fuse::Callback as FuseCallback;

#[derive(Debug)]
struct Cell(AtomicU64);
impl Cell {
    fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    fn add(&self, amount: u64) -> u64 {
        let mut old = self.0.load(Ordering::Relaxed);
        loop {
            let next = old
                .checked_add(amount)
                .filter(|v| *v < INVALID)
                .unwrap_or(INVALID);
            match self
                .0
                .compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(value) => old = value,
            }
        }
    }
    fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct Histogram {
    buckets: [Cell; 12],
    sum: Cell,
    #[cfg(test)]
    pause: AtomicU8,
}
impl Histogram {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| Cell::new()),
            sum: Cell::new(),
            #[cfg(test)]
            pause: AtomicU8::new(0),
        }
    }
    fn record(&self, duration: Duration) {
        let Ok(us) = u64::try_from(duration.as_micros()) else {
            self.sum.0.store(INVALID, Ordering::Relaxed);
            return;
        };
        let index = BUCKET_US
            .iter()
            .position(|upper| us <= *upper)
            .unwrap_or(11);
        if let Some(bucket) = self.buckets.get(index) {
            bucket.add(1);
        }
        // The test seam holds a writer between independent atomic updates.
        #[cfg(test)]
        if self
            .pause
            .compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            while self.pause.load(Ordering::Relaxed) == 2 {
                std::thread::yield_now();
            }
        }
        self.sum.add(us);
    }
    fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            buckets: std::array::from_fn(|i| self.buckets.get(i).map_or(INVALID, Cell::load)),
            sum: self.sum.load(),
        }
    }
}

/// The closed result label of a completed TLS-admitted scrape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrapeResult {
    /// An authorized response finished.
    Ok,
    /// The peer closed without a request, or the request was refused.
    Refused,
    /// The connection exhausted its lifetime.
    Limited,
    /// The exporter, connection I/O or shutdown interrupted the response.
    Failed,
}

impl ScrapeResult {
    const ALL: [Self; 4] = [Self::Ok, Self::Refused, Self::Limited, Self::Failed];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::Limited => "limited",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug)]
struct Store {
    incarnation: Option<[u32; 4]>,
    sequence: Cell,
    available: [AtomicBool; 6],
    commits: [Cell; 6],
    commit_duration: [Histogram; 6],
    retries: [Cell; 3],
    conflicts: Cell,
    contention: AtomicU8,
    syncs: [Cell; 4],
    fuse: [[Cell; 4]; 40],
    registrations: [Cell; 4],
    registration_duration: [Histogram; 4],
    grains: Cell,
    uploads: [Cell; 2],
    rechunks: Cell,
    view_stale: AtomicBool,
    cache: [[Cell; 2]; 2],
    transport: [Cell; 2],
    listener: AtomicU8,
    scrapes: [Cell; 4],
}

/// A clone shares exactly one session's store, never a process-global registry.
#[derive(Debug, Clone)]
pub struct ClientMetrics(Arc<Store>);
impl ClientMetrics {
    /// Draw a fresh incarnation through the cryptographic randomness seam.
    /// Entropy failure emits a stable session/unavailable failure and leaves
    /// recording usable; exporting refuses rather than inventing an identity.
    #[must_use]
    pub fn new(random: &mut impl SecureRandom) -> Self {
        let mut bytes = [0; 16];
        let incarnation = if random.fill(&mut bytes).is_ok() {
            let mut words = [0; 4];
            for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
                let mut data = [0; 4];
                data.copy_from_slice(chunk);
                *word = u32::from_be_bytes(data);
            }
            Some(words)
        } else {
            op_failed(OperationKind::Session, FailureClass::Unavailable);
            None
        };
        Self(Arc::new(Store {
            incarnation,
            sequence: Cell::new(),
            available: std::array::from_fn(|_| AtomicBool::new(false)),
            commits: std::array::from_fn(|_| Cell::new()),
            commit_duration: std::array::from_fn(|_| Histogram::new()),
            retries: std::array::from_fn(|_| Cell::new()),
            conflicts: Cell::new(),
            contention: AtomicU8::new(0),
            syncs: std::array::from_fn(|_| Cell::new()),
            fuse: std::array::from_fn(|_| std::array::from_fn(|_| Cell::new())),
            registrations: std::array::from_fn(|_| Cell::new()),
            registration_duration: std::array::from_fn(|_| Histogram::new()),
            grains: Cell::new(),
            uploads: std::array::from_fn(|_| Cell::new()),
            rechunks: Cell::new(),
            view_stale: AtomicBool::new(false),
            cache: std::array::from_fn(|_| std::array::from_fn(|_| Cell::new())),
            transport: std::array::from_fn(|_| Cell::new()),
            listener: AtomicU8::new(0),
            scrapes: std::array::from_fn(|_| Cell::new()),
        }))
    }
    pub fn set_available(&self, group: MetricsGroup, available: bool) {
        if let Some(cell) = self.0.available.get(group as usize) {
            cell.store(available, Ordering::Relaxed);
        }
    }
    pub fn record_commit(&self, result: CommitResult, duration: Duration) {
        self.record_commit_sample(result, Some(duration));
    }
    /// Count a final outcome once; unavailable timing invalidates its histogram.
    pub fn record_commit_sample(&self, result: CommitResult, duration: Option<Duration>) {
        add_at(&self.0.commits, result as usize, 1);
        if let Some(hist) = self.0.commit_duration.get(result as usize) {
            if let Some(duration) = duration {
                hist.record(duration);
            } else {
                hist.sum.0.store(INVALID, Ordering::Relaxed);
            }
        }
    }
    pub fn record_retry(&self, reason: RetryReason) {
        let i = match reason {
            RetryReason::Transient => 0,
            RetryReason::Conflict => 1,
            RetryReason::Unavailable => 2,
        };
        add_at(&self.0.retries, i, 1);
    }
    pub fn record_rebase_conflict(&self) {
        self.0.conflicts.add(1);
    }
    /// Store an authoritative decision and make the contention producer available.
    /// `set_available(Contention, false)` suppresses a retained decision.
    pub fn set_contention(&self, flagged: bool) {
        self.set_available(MetricsGroup::Contention, true);
        self.0
            .contention
            .store(if flagged { 2 } else { 1 }, Ordering::Relaxed);
    }
    pub(crate) fn reset_contention(&self) {
        self.set_available(MetricsGroup::Contention, false);
        self.0.contention.store(0, Ordering::Relaxed);
    }
    /// Store whether the writable mount's authority view is in the unreachable state.
    pub fn set_view_stale(&self, stale: bool) {
        self.0.view_stale.store(stale, Ordering::Relaxed);
    }
    pub fn record_sync(&self, outcome: Outcome) {
        let i = match outcome {
            Outcome::Ok => 0,
            Outcome::Failed => 1,
            Outcome::Cancelled => 2,
            Outcome::Refused => 3,
        };
        add_at(&self.0.syncs, i, 1);
    }
    /// Count exactly one terminal adapter reply, never a kernel-only refusal.
    pub fn record_fuse(&self, callback: FuseCallback, outcome: Outcome) {
        let index = match outcome {
            Outcome::Ok => 0,
            Outcome::Failed => 1,
            Outcome::Cancelled => 2,
            Outcome::Refused => 3,
        };
        if let Some(row) = self.0.fuse.get(callback as usize) {
            add_at(row, index, 1);
        }
    }
    pub fn record_registration(&self, result: RegistrationResult, duration: Duration) {
        self.record_registration_sample(result, Some(duration));
    }
    /// Count an exchange once; unavailable timing contributes no histogram sample.
    pub fn record_registration_sample(
        &self,
        result: RegistrationResult,
        duration: Option<Duration>,
    ) {
        add_at(&self.0.registrations, result as usize, 1);
        if let Some(duration) = duration
            && let Some(hist) = self.0.registration_duration.get(result as usize)
        {
            hist.record(duration);
        }
    }
    pub fn record_uploaded_grains(&self, count: u64) {
        self.0.grains.add(count);
    }
    pub fn record_uploaded_bytes(&self, object: UploadObject, bytes: u64) {
        add_at(&self.0.uploads, object as usize, bytes);
    }
    pub fn record_rechunk_fallback(&self) {
        self.0.rechunks.add(1);
    }
    pub fn record_cache(&self, phase: CachePhase, result: CacheResult) {
        if let Some(cells) = self.0.cache.get(phase as usize) {
            add_at(cells, result as usize, 1);
        }
    }
    pub fn record_transport(&self, direction: ByteDirection, bytes: u64) {
        add_at(&self.0.transport, direction as usize, bytes);
    }
    /// Mark a configured listener down or up.
    pub fn set_metrics_listener_up(&self, up: bool) {
        self.0
            .listener
            .store(if up { 2 } else { 1 }, Ordering::Relaxed);
    }

    /// Count one terminal result after completed TLS admission.
    pub fn record_metrics_scrape(&self, result: ScrapeResult) {
        add_at(&self.0.scrapes, result as usize, 1);
    }

    /// One bounded pass of relaxed loads. No coherence between separate cells
    /// is promised; histogram infinity/count share the same copied buckets.
    /// # Errors
    /// Refuses absent entropy or an exhausted collection sequence.
    pub fn snapshot(&self) -> Result<MetricsSnapshot, MetricsError> {
        let incarnation = self.0.incarnation.ok_or(MetricsError::Unavailable)?;
        let sequence = self.0.sequence.add(1);
        if sequence == INVALID {
            return Err(MetricsError::SequenceExhausted);
        }
        Ok(MetricsSnapshot {
            incarnation,
            sequence,
            available: self
                .0
                .available
                .each_ref()
                .map(|v| v.load(Ordering::Relaxed)),
            commits: self.0.commits.each_ref().map(Cell::load),
            commit_duration: self.0.commit_duration.each_ref().map(Histogram::snapshot),
            retries: self.0.retries.each_ref().map(Cell::load),
            conflicts: self.0.conflicts.load(),
            contention: self.0.contention.load(Ordering::Relaxed),
            syncs: self.0.syncs.each_ref().map(Cell::load),
            fuse: self
                .0
                .fuse
                .each_ref()
                .map(|row| row.each_ref().map(Cell::load)),
            registrations: self.0.registrations.each_ref().map(Cell::load),
            registration_duration: self
                .0
                .registration_duration
                .each_ref()
                .map(Histogram::snapshot),
            grains: self.0.grains.load(),
            uploads: self.0.uploads.each_ref().map(Cell::load),
            rechunks: self.0.rechunks.load(),
            view_stale: self.0.view_stale.load(Ordering::Relaxed),
            cache: self
                .0
                .cache
                .each_ref()
                .map(|v| v.each_ref().map(Cell::load)),
            transport: self.0.transport.each_ref().map(Cell::load),
            listener: self.0.listener.load(Ordering::Relaxed),
            scrapes: self.0.scrapes.each_ref().map(Cell::load),
        })
    }
}
fn add_at(cells: &[Cell], index: usize, amount: u64) {
    if let Some(cell) = cells.get(index) {
        cell.add(amount);
    }
}

#[derive(Debug, Clone)]
struct HistogramSnapshot {
    buckets: [u64; 12],
    sum: u64,
}
fn total(values: &[u64]) -> Option<u64> {
    let total = values.iter().try_fold(0_u128, |sum, value| {
        if *value == INVALID {
            None
        } else {
            sum.checked_add(u128::from(*value))
        }
    })?;
    u64::try_from(total).ok().filter(|v| *v < INVALID)
}
impl HistogramSnapshot {
    fn valid(&self) -> bool {
        self.sum != INVALID && total(&self.buckets).is_some()
    }
}

/// Opaque owned report: callers cannot supply codes, labels, duplicates or a
/// schema version. This is an approximate collection, not a transaction.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    incarnation: [u32; 4],
    sequence: u64,
    available: [bool; 6],
    commits: [u64; 6],
    commit_duration: [HistogramSnapshot; 6],
    retries: [u64; 3],
    conflicts: u64,
    contention: u8,
    syncs: [u64; 4],
    fuse: [[u64; 4]; 40],
    registrations: [u64; 4],
    registration_duration: [HistogramSnapshot; 4],
    grains: u64,
    uploads: [u64; 2],
    rechunks: u64,
    view_stale: bool,
    cache: [[u64; 2]; 2],
    transport: [u64; 2],
    listener: u8,
    scrapes: [u64; 4],
}
impl MetricsSnapshot {
    /// Project support fields without rendering metric labels or text.
    #[must_use]
    pub fn bundle_projection(&self) -> BundleMetrics {
        let histogram = |h: &HistogramSnapshot| BundleHistogram {
            buckets: h.buckets,
            sum: h.sum,
        };
        BundleMetrics {
            incarnation: self.incarnation,
            sequence: self.sequence,
            available: self.available,
            commits: self.commits,
            commit_duration: self.commit_duration.each_ref().map(histogram),
            retries: self.retries,
            conflicts: self.conflicts,
            contention: self.contention,
            syncs: self.syncs,
            fuse: self.fuse,
            registrations: self.registrations,
            registration_duration: self.registration_duration.each_ref().map(histogram),
            grains: self.grains,
            uploads: self.uploads,
            rechunks: self.rechunks,
            cache: self.cache,
            transport: self.transport,
        }
    }

    #[must_use]
    pub const fn incarnation(&self) -> [u32; 4] {
        self.incarnation
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Render the fixed catalogue in Prometheus text format. Failure returns
    /// no partial response. Missing invalid groups keep healthy siblings.
    /// # Errors
    /// Refuses any byte, line or series limit overflow.
    pub fn render_prometheus(&self) -> Result<String, MetricsError> {
        self.render_with_limits(METRICS_MAX_BYTES, METRICS_MAX_LINE, METRICS_MAX_SERIES)
    }
}

struct Text {
    output: String,
    series: usize,
    bytes_cap: usize,
    line_cap: usize,
    series_cap: usize,
}
impl Text {
    fn line(&mut self, line: &str, sample: bool) -> Result<(), MetricsError> {
        if line.len().saturating_add(1) > self.line_cap
            || self
                .output
                .len()
                .saturating_add(line.len())
                .saturating_add(1)
                > self.bytes_cap
            || (sample && self.series >= self.series_cap)
        {
            return Err(MetricsError::OutputLimit);
        }
        self.output.push_str(line);
        self.output.push('\n');
        self.series += usize::from(sample);
        Ok(())
    }
    fn sample(
        &mut self,
        name: &str,
        labels: &str,
        value: impl std::fmt::Display,
    ) -> Result<(), MetricsError> {
        self.line(&format!("{name}{labels} {value}"), true)
    }
    fn counter(&mut self, name: &str, labels: &str, value: u64) -> Result<(), MetricsError> {
        if value != INVALID {
            self.sample(name, labels, value)?;
        }
        Ok(())
    }
    fn labelled(
        &mut self,
        name: &str,
        key: &str,
        labels: impl Iterator<Item = &'static str>,
        values: &[u64],
    ) -> Result<(), MetricsError> {
        for (label, value) in labels.zip(values) {
            self.counter(name, &format!("{{{key}=\"{label}\"}}"), *value)?;
        }
        Ok(())
    }
    fn histogram(
        &mut self,
        name: &str,
        result: &str,
        hist: &HistogramSnapshot,
    ) -> Result<(), MetricsError> {
        if !hist.valid() {
            return Ok(());
        }
        let mut cumulative = 0_u64;
        for (bound, count) in BUCKET_TEXT.iter().zip(hist.buckets) {
            cumulative = cumulative.saturating_add(count);
            self.sample(
                &format!("{name}_bucket"),
                &format!("{{result=\"{result}\",le=\"{bound}\"}}"),
                cumulative,
            )?;
        }
        self.sample(
            &format!("{name}_sum"),
            &format!("{{result=\"{result}\"}}"),
            format!("{}.{:06}", hist.sum / 1_000_000, hist.sum % 1_000_000),
        )?;
        self.sample(
            &format!("{name}_count"),
            &format!("{{result=\"{result}\"}}"),
            cumulative,
        )
    }
}
fn escape_help(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n")
}

impl MetricsSnapshot {
    fn available(&self, group: MetricsGroup) -> bool {
        self.available.get(group as usize).copied().unwrap_or(false)
    }
    fn present(&self, metric: Metric) -> bool {
        match metric {
            Metric::SchemaVersion | Metric::Incarnation | Metric::Available | Metric::Overflow => {
                true
            }
            Metric::Commits
            | Metric::CommitDuration
            | Metric::Retries
            | Metric::RebaseConflicts => self.available(MetricsGroup::Commit),
            Metric::Contention => self.available(MetricsGroup::Contention) && self.contention != 0,
            Metric::Syncs
            | Metric::Registrations
            | Metric::RegistrationDuration
            | Metric::UploadedGrains
            | Metric::UploadedBytes
            | Metric::Rechunks
            | Metric::MountViewStale => self.available(MetricsGroup::Sync),
            Metric::CacheLookups | Metric::CacheHitRatio => self.available(MetricsGroup::Cache),
            Metric::TransportBytes => self.available(MetricsGroup::Transport),
            Metric::ListenerUp | Metric::Scrapes => self.listener != 0,
            Metric::FuseRequests => self.available(MetricsGroup::Fuse),
        }
    }
    fn overflows(&self) -> [(&'static str, bool); 17] {
        [
            ("M02", false),
            ("M05", self.commits.contains(&INVALID)),
            ("M06", self.commit_duration.iter().any(|h| !h.valid())),
            ("M07", self.retries.contains(&INVALID)),
            ("M08", self.conflicts == INVALID),
            ("M09", false),
            ("M10", self.syncs.contains(&INVALID)),
            ("M11", self.registrations.contains(&INVALID)),
            ("M12", self.registration_duration.iter().any(|h| !h.valid())),
            ("M13", self.grains == INVALID),
            ("M14", self.uploads.contains(&INVALID)),
            ("M15", self.rechunks == INVALID),
            ("M16", self.cache.iter().any(|v| v.contains(&INVALID))),
            ("M17", self.cache.iter().any(|v| total(v).is_none())),
            ("M18", self.transport.contains(&INVALID)),
            ("M20", self.scrapes.contains(&INVALID)),
            ("M21", self.fuse.iter().any(|row| row.contains(&INVALID))),
        ]
    }
    fn render_with_limits(
        &self,
        bytes_cap: usize,
        line_cap: usize,
        series_cap: usize,
    ) -> Result<String, MetricsError> {
        let mut text = Text {
            output: String::new(),
            series: 0,
            bytes_cap,
            line_cap,
            series_cap,
        };
        for spec in METRICS_CATALOGUE {
            // Optional producers contribute neither metadata nor idle-zero series.
            if !self.present(spec.metric) {
                continue;
            }
            text.line(
                &format!("# HELP {} {}", spec.name, escape_help(spec.help)),
                false,
            )?;
            text.line(&format!("# TYPE {} {}", spec.name, spec.kind), false)?;
            self.render_family(&mut text, spec)?;
        }
        Ok(text.output)
    }
    fn render_cache(&self, text: &mut Text, spec: &MetricSpec) -> Result<(), MetricsError> {
        let name = spec.name;
        for (phase, values) in CachePhase::ALL.iter().zip(self.cache) {
            if matches!(spec.metric, Metric::CacheLookups) {
                for (result, count) in CacheResult::ALL.iter().zip(values) {
                    text.counter(
                        name,
                        &format!(
                            "{{phase=\"{}\",result=\"{}\"}}",
                            phase.as_str(),
                            result.as_str()
                        ),
                        count,
                    )?;
                }
            } else if let Some(denominator) = total(&values).filter(|v| *v != 0) {
                let [hits, _] = values;
                text.sample(
                    name,
                    &format!("{{phase=\"{}\"}}", phase.as_str()),
                    ratio(hits, denominator),
                )?;
            }
        }
        Ok(())
    }
    fn render_family(&self, text: &mut Text, spec: &MetricSpec) -> Result<(), MetricsError> {
        let name = spec.name;
        match spec.metric {
            Metric::SchemaVersion => text.sample(name, "", METRICS_SCHEMA_VERSION)?,
            Metric::Incarnation => {
                for (i, word) in self.incarnation.iter().enumerate() {
                    text.sample(name, &format!("{{word=\"{i}\"}}"), word)?;
                }
            }
            Metric::Available => {
                for group in MetricsGroup::ALL {
                    let value = self.available(*group)
                        && (*group != MetricsGroup::Contention || self.contention != 0);
                    text.sample(
                        name,
                        &format!("{{group=\"{}\"}}", group.as_str()),
                        u8::from(value),
                    )?;
                }
            }
            Metric::Overflow => {
                for (code, overflow) in self.overflows() {
                    text.sample(name, &format!("{{metric=\"{code}\"}}"), u8::from(overflow))?;
                }
            }
            Metric::Commits => text.labelled(
                name,
                "result",
                CommitResult::ALL.iter().map(|v| v.as_str()),
                &self.commits,
            )?,
            Metric::CommitDuration => {
                for (result, hist) in CommitResult::ALL.iter().zip(&self.commit_duration) {
                    text.histogram(name, result.as_str(), hist)?;
                }
            }
            Metric::Retries => text.labelled(
                name,
                "reason",
                RetryReason::ALL.iter().map(|v| v.as_str()),
                &self.retries,
            )?,
            Metric::RebaseConflicts => text.counter(name, "", self.conflicts)?,
            Metric::Contention => text.sample(name, "", u8::from(self.contention == 2))?,
            Metric::Syncs => text.labelled(
                name,
                "outcome",
                Outcome::ALL.iter().map(|v| v.as_str()),
                &self.syncs,
            )?,
            Metric::Registrations => text.labelled(
                name,
                "result",
                RegistrationResult::ALL.iter().map(|v| v.as_str()),
                &self.registrations,
            )?,
            Metric::RegistrationDuration => {
                for (result, hist) in RegistrationResult::ALL
                    .iter()
                    .zip(&self.registration_duration)
                {
                    text.histogram(name, result.as_str(), hist)?;
                }
            }
            Metric::UploadedGrains => text.counter(name, "", self.grains)?,
            Metric::UploadedBytes => text.labelled(
                name,
                "object",
                UploadObject::ALL.iter().map(|v| v.as_str()),
                &self.uploads,
            )?,
            Metric::Rechunks => text.counter(name, "", self.rechunks)?,
            Metric::MountViewStale => text.sample(name, "", u8::from(self.view_stale))?,
            Metric::CacheLookups | Metric::CacheHitRatio => self.render_cache(text, spec)?,
            Metric::TransportBytes => text.labelled(
                name,
                "direction",
                ByteDirection::ALL.iter().map(|v| v.as_str()),
                &self.transport,
            )?,
            Metric::FuseRequests => self.render_fuse(text, name)?,
            Metric::ListenerUp => text.sample(name, "", u8::from(self.listener == 2))?,
            Metric::Scrapes => text.labelled(
                name,
                "result",
                ScrapeResult::ALL.iter().map(|result| result.as_str()),
                &self.scrapes,
            )?,
        }
        Ok(())
    }
    fn render_fuse(&self, text: &mut Text, name: &str) -> Result<(), MetricsError> {
        for (callback, row) in FuseCallback::ALL.iter().zip(&self.fuse) {
            for (outcome, count) in Outcome::ALL.iter().zip(row) {
                text.counter(
                    name,
                    &format!(
                        "{{callback=\"{}\",outcome=\"{}\"}}",
                        callback.as_str(),
                        outcome.as_str()
                    ),
                    *count,
                )?;
            }
        }
        Ok(())
    }
}
#[expect(
    clippy::cast_precision_loss,
    reason = "Prometheus stores ratios as floating point; integer samples render in decimal"
)]
fn ratio(hits: u64, total: u64) -> f64 {
    hits as f64 / total as f64
}

#[cfg(test)]
pub(crate) mod tests;
