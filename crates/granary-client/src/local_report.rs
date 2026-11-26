// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Operator disclosures have a typed channel independent of telemetry policy.

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Arc, OnceLock};

use granary_core::hash::GrainId;
use granary_core::root::VolumeName;

use crate::{Age, CacheError, ClientEvent, CorrelationId, FailureClass, OperationKind};

static REPORTS: OnceLock<Arc<dyn LocalRecordWriter>> = OnceLock::new();

/// A destination accepting only already-rendered local records.
pub trait LocalRecordWriter: Send + Sync {
    /// Submit one whole record without blocking on the destination.
    fn write_local(&self, record: &LocalRecord);
}

/// Bind local reports to the process's bounded sink before mounting.
///
/// # Errors
/// Refuses replacement of an installed destination.
pub fn install_local_reports(
    writer: Arc<dyn LocalRecordWriter>,
) -> Result<(), LocalReportsInstalled> {
    REPORTS.set(writer).map_err(|_| LocalReportsInstalled)
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct Capture(Mutex<Vec<Vec<u8>>>);

#[cfg(test)]
impl LocalRecordWriter for Capture {
    fn write_local(&self, record: &LocalRecord) {
        self.0.lock().unwrap().push(record.as_bytes().to_vec());
    }
}

#[cfg(test)]
impl Capture {
    pub(crate) fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub(crate) fn since(&self, baseline: usize) -> Vec<String> {
        self.0.lock().unwrap()[baseline..]
            .iter()
            .map(|record| String::from_utf8(record.clone()).unwrap())
            .collect()
    }
}

#[cfg(test)]
pub(crate) fn local_capture() -> &'static Arc<Capture> {
    static CAPTURE: OnceLock<Arc<Capture>> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = Arc::new(Capture::default());
        let _ = install_local_reports(capture.clone());
        capture
    })
}

/// The local destination has already been bound.
#[derive(Debug)]
pub struct LocalReportsInstalled;

/// Startup accepts typed reports; other operator results use `Write`.
/// A sink overrides `report` to route these records through its Local stream.
pub trait LocalReporter: Write {
    /// Render synchronously, before any queue or buffer sees the report.
    fn report(&mut self, report: &LocalReport) {
        let _delivery = self.write_all(report.render().as_bytes());
    }
}
impl LocalReporter for Vec<u8> {}
impl LocalReporter for std::io::Sink {}

/// Rendered operator information, never an input to telemetry or bundle records.
pub struct LocalRecord(Vec<u8>);
impl LocalRecord {
    /// Borrow the complete local spelling.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for LocalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<local-record>")
    }
}

/// Retained mismatch evidence, independent of the report's delivery.
#[derive(Clone)]
pub struct EquivocationNotice {
    volume: VolumeName,
    seq: u64,
    wire: GrainId,
    cached: GrainId,
}
impl EquivocationNotice {
    /// Keep both digests and the accepted volume/sequence as typed evidence.
    #[must_use]
    pub fn new(volume: VolumeName, seq: u64, wire: GrainId, cached: GrainId) -> Self {
        Self {
            volume,
            seq,
            wire,
            cached,
        }
    }
    /// The local finding's spelling; no string is retained or forwarded to logs.
    #[must_use]
    pub fn render_finding(&self) -> String {
        format!(
            "cache/wire root mismatch at (volume={}, seq={}): wire={}, cached={}",
            self.volume.as_str(),
            self.seq,
            self.wire,
            self.cached
        )
    }
}
impl std::fmt::Debug for EquivocationNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<equivocation>")
    }
}

/// Which cleanup boundary failed.
#[derive(Clone, Copy, Debug)]
pub enum CloseStage {
    /// Cleanup after startup refusal; the original failure still wins.
    RefusedMount,
    /// Explicit filesystem shutdown.
    Shutdown,
    /// The session's final cleanup backstop.
    Drop,
}

/// A closed operator report, carrying only the fields its template needs.
///
/// ```compile_fail,E0423
/// use granary_client::LocalReport;
/// let report = LocalReport(String::from("synthetic arbitrary message"));
/// ```
/// ```compile_fail,E0308
/// use granary_client::LocalReport;
/// let report = LocalReport::commit_stalled("synthetic-volume");
/// ```
#[derive(Clone)]
pub struct LocalReport(Report);
#[derive(Clone)]
enum Report {
    Pinned(VolumeName, u64, GrainId, GrainId),
    History,
    Equivocation(EquivocationNotice),
    CacheUnverified(VolumeName, u64),
    CacheDegraded,
    SignatureUnchecked,
    Degraded(VolumeName, u64, Age),
    ViewStale(VolumeName, u64, i64),
    CommitStalled(VolumeName),
    Workspace(WorkspaceSite, Option<PathBuf>, u64, u64),
    CommitStopped(VolumeName, crate::CommitStopCause),
    Close(CloseStage, FailureClass, Option<i32>),
    Conflict(LocalConflictStatus),
}
#[derive(Clone)]
pub(crate) enum WorkspaceSite {
    Boundary(u64),
    Volume(VolumeName),
}
impl std::fmt::Debug for LocalReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<local-report>")
    }
}
impl LocalReport {
    /// The snapshot this mount accepted.
    #[must_use]
    pub fn pinned(volume: VolumeName, seq: u64, root: GrainId, manifest: GrainId) -> Self {
        Self(Report::Pinned(volume, seq, root, manifest))
    }
    /// The explicit history-check disclosure.
    #[must_use]
    pub fn history() -> Self {
        Self(Report::History)
    }
    /// Both cached and wire roots, retained separately by the session.
    #[must_use]
    pub fn equivocation(notice: EquivocationNotice) -> Self {
        Self(Report::Equivocation(notice))
    }
    /// A cached root failed verification and was evicted.
    #[must_use]
    pub fn cache_unverified(volume: VolumeName, seq: u64) -> Self {
        Self(Report::CacheUnverified(volume, seq))
    }
    /// A cache writer already holds the lock; this mount keeps no floor.
    #[must_use]
    pub fn cache_degraded() -> Self {
        Self(Report::CacheDegraded)
    }
    /// This mount verifies structure/content without a root-signing key.
    #[must_use]
    pub fn signature_unchecked() -> Self {
        Self(Report::SignatureUnchecked)
    }
    /// A transport-down reader is serving its retained verified head.
    #[must_use]
    pub fn degraded(volume: VolumeName, seq: u64, age: Age) -> Self {
        Self(Report::Degraded(volume, seq, age))
    }
    /// A writable mount cannot reach its authority and serves its pinned view.
    #[must_use]
    pub fn view_stale(volume: VolumeName, seq: u64, since: i64) -> Self {
        Self(Report::ViewStale(volume, seq, since))
    }
    /// A writable mount's commit reached the slow retry cadence.
    #[must_use]
    pub fn commit_stalled(volume: &VolumeName) -> Self {
        Self(Report::CommitStalled(volume.clone()))
    }
    /// A locally exhausted construction budget, with bounded namespace context.
    pub(crate) fn workspace_exhausted(
        site: WorkspaceSite,
        path: Option<&Path>,
        needed: u64,
        limit: u64,
    ) -> Self {
        use std::os::unix::ffi::OsStrExt as _;
        let path = path.filter(|path| path.as_os_str().as_bytes().len() <= 4096);
        Self(Report::Workspace(
            site,
            path.map(Path::to_owned),
            needed,
            limit,
        ))
    }
    /// A writable mount's live commit loop ended before shutdown.
    #[must_use]
    pub fn commit_stopped(volume: &VolumeName, cause: crate::CommitStopCause) -> Self {
        Self(Report::CommitStopped(volume.clone(), cause))
    }
    /// Cleanup discloses only a closed class and optional numeric errno.
    #[must_use]
    pub fn close_warning(stage: CloseStage, class: FailureClass, errno: Option<i32>) -> Self {
        Self(Report::Close(stage, class, errno))
    }
    /// Project a cache error without displaying its context or source chain.
    #[must_use]
    pub fn cache_close_warning(stage: CloseStage, error: &CacheError) -> Self {
        let errno = match error {
            CacheError::Io { source, .. } => source.raw_os_error(),
            CacheError::Incompatible { .. } => None,
        };
        Self::close_warning(stage, error.failure_class(), errno)
    }
    /// The exact namespace conflict belongs to local status alone.
    #[must_use]
    pub fn conflict(status: LocalConflictStatus) -> Self {
        Self(Report::Conflict(status))
    }
    /// Deliver through the installed local channel, even with logging OFF.
    /// An absent/closed recipient cannot cause a telemetry fallback.
    pub fn emit(&self) {
        if let Some(writer) = REPORTS.get() {
            writer.write_local(&self.render());
        }
    }
    /// Encode before delivery. There is no telemetry projection of this record.
    #[must_use]
    pub fn render(&self) -> LocalRecord {
        let mut out = String::new();
        match &self.0 {
            Report::Pinned(volume, seq, root, manifest) => {
                let _ = write!(out, "gran mount: pinned volume={} seq={seq} root={root} manifest-root={manifest}", volume.as_str());
            }
            Report::History => out.push_str("gran mount: history: not checked"),
            Report::Equivocation(notice) => {
                out.push_str("gran mount: EQUIVOCATION: "); out.push_str(&notice.render_finding());
            }
            Report::CacheUnverified(volume, seq) => {
                let _ = write!(out, "gran mount: warning: the cached root at (volume={}, seq={seq}) did not verify; evicting it and proceeding on the verified wire bytes.", volume.as_str());
            }
            Report::CacheDegraded => out.push_str("gran mount: warning: another process holds the writer lock on this cache directory; this session is read-only for the cache and may re-fetch content a live writer would have cached. No floor is kept under --manifest-root, so this costs only performance."),
            Report::SignatureUnchecked => out.push_str("gran mount: warning: no --root-key, so the root SIGNATURE is NOT checked.\ngran mount: warning: the content and structure checks still run — every object is re-hashed against the id that named it, the manifest tree is walked, and every grain is located and length-checked. That is INTEGRITY: the bytes are what SOME writer published, not a writer you trust."),
            Report::Degraded(volume, seq, age) => {
                let _ = write!(out, "gran cat: warning: the transport gave no answer; falling back to the cache's last verified head for this volume (possibly stale) — the read fails closed if the cache cannot fully satisfy it; volume={} seq={seq} age=", volume.as_str());
                match age { Age::Unknown => out.push_str("unknown"), Age::Seconds(n) => { let _ = write!(out, "{n}s"); } }

            }
            Report::ViewStale(volume, seq, since) => {
                let _ = write!(out, "gran mount: warning: STALE (pinned at seq {seq}, since {since}): the authority cannot be reached; this writable mount serves its pinned view of volume={}", volume.as_str());
            }
            Report::CommitStalled(volume) => {
                let _ = write!(out, "gran mount: warning: COMMIT STALLED: a commit of volume={} has been refused eight times and is now retried every 10 minutes; fsync fails until it lands or the mount is restarted", volume.as_str());
            }
            Report::Workspace(site, path, needed, limit) => {
                let _ = write!(out, "gran mount: warning: SyncWorkspaceExhausted: needed={needed} limit={limit}");
                match site {
                    WorkspaceSite::Boundary(id) => { let _ = write!(out, " boundary={id}"); }
                    WorkspaceSite::Volume(volume) => { let _ = write!(out, " volume={}", volume.as_str()); }
                }
                if let Some(path) = path {
                    out.push_str(" path=\"");
                    escaped_path(&mut out, path);
                    out.push('"');
                }
            }
            Report::CommitStopped(volume, crate::CommitStopCause::Fenced) => {
                let _ = write!(out, "gran mount: error: COMMIT STOPPED (fenced): new writes are refused; pending changes are kept in the store, but nothing more is committed while this mount runs; volume={}", volume.as_str());
            }
            Report::CommitStopped(volume, crate::CommitStopCause::Closed) => {
                let _ = write!(out, "gran mount: error: COMMIT STOPPED (closed): the served view is closed or its session has ended; pending changes are kept in the store, but nothing more is committed while this mount runs; volume={}", volume.as_str());
            }
            Report::Close(stage, class, errno) => {
                let prefix = match stage {
                    CloseStage::RefusedMount => "gran mount: warning: closing the cache after a refused mount failed",
                    CloseStage::Shutdown => "mount session shutdown: closing the cache failed",
                    CloseStage::Drop => "mount session drop: closing the cache failed",
                };
                let _ = write!(out, "{prefix}: class={}", class.as_str());
                if let Some(errno) = errno { let _ = write!(out, " errno={errno}"); }
                out.push_str("; the crash guard may remain, and the next open may report an unclean exit that never happened.");
            }
            Report::Conflict(status) => {
                out.push_str("gran mount: conflict path=\"");
                escaped_path(&mut out, &status.path);
                let _ = write!(out, "\" errno={} ESTALE op={}", status.errno(), status.operation);
            }
        }
        out.push('\n');
        LocalRecord(out.into_bytes())
    }
}

/// Caller-owned conflict status survives absent local delivery and logging OFF.
/// No conversion to an event, rendered log or bundle input is provided.
///
/// ```compile_fail,E0308
/// use granary_client::{BundleRecord, LocalConflictStatus};
/// fn tee(status: LocalConflictStatus) -> BundleRecord { status }
/// ```
#[derive(Clone)]
pub struct LocalConflictStatus {
    path: PathBuf,
    operation: CorrelationId,
}
impl std::fmt::Debug for LocalConflictStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<local-conflict>")
    }
}
/// Namespace status is refused before copying more than 4096 path bytes.
#[derive(Debug)]
pub struct ConflictPathTooLarge;
impl LocalConflictStatus {
    /// Keep the supplied path, without normalization, and the operation join.
    ///
    /// # Errors
    /// Refuses paths over 4096 source bytes before copying them.
    pub fn new(path: &Path, operation: CorrelationId) -> Result<Self, ConflictPathTooLarge> {
        use std::os::unix::ffi::OsStrExt as _;
        if path.as_os_str().as_bytes().len() > 4096 {
            return Err(ConflictPathTooLarge);
        }
        Ok(Self {
            path: path.to_owned(),
            operation,
        })
    }
    /// Exact conflict bytes remain available to the caller independently of logs.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Borrow the eligible namespace path through its fixed ordinary-file role.
    #[must_use]
    pub fn log_path(&self) -> crate::LogPath<'_> {
        crate::LogPath::file(&self.path)
    }
    /// The kernel receives the errno, without path bytes.
    #[must_use]
    pub fn errno(&self) -> i32 {
        libc::ESTALE
    }
    /// Independently project the two telemetry events and redacted bundle inputs.
    /// Local record bytes and paths are never inputs to either encoder.
    #[must_use]
    pub fn redacted_projections(&self) -> ([crate::LogRecord; 2], [crate::BundleRecord; 2]) {
        let (failed_log, failed_bundle) =
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Conflict)
                .project_operation(self.operation, OperationKind::Commit);
        let (detail_log, detail_bundle) =
            ClientEvent::conflict_detail().project_operation(self.operation, OperationKind::Commit);
        ([failed_log, detail_log], [failed_bundle, detail_bundle])
    }

    /// Emit two separately constructed telemetry events with the operation join.
    pub fn emit_telemetry(&self) {
        let span = crate::operation_span(OperationKind::Commit, &self.operation);
        let _entered = span.enter();
        ClientEvent::op_failed(OperationKind::Commit, FailureClass::Conflict).emit();
        ClientEvent::conflict_detail()
            .emit_paths(&[crate::observe::PathSlot::Path("path", self.log_path())]);
    }
}
fn escaped_path(out: &mut String, path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(*byte)),
            byte => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
}

/// Preserve namespace components without a filesystem lookup or normalization.
pub(crate) fn namespace_path(names: &[granary_core::manifest::Name]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    names
        .iter()
        .map(|name| std::ffi::OsString::from_vec(name.as_bytes().to_vec()))
        .collect()
}

#[cfg(test)]
mod tests;
