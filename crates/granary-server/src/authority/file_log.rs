// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The production [`DecisionLog`]: one file per volume, and the run
//! marker, directly in one state directory. Recovery's decisions are the
//! engine's; this adapter makes the calls the seam names, exactly.
//!
//! - **One open file description per log for the whole run.** A log is
//!   opened once, by its first `read` (after the marker gate in an engine run) or by the
//!   `initialise` that creates it, whose temporary's description becomes
//!   the log's own at the link. Every later write, sync and truncation of
//!   the log goes through it, so it sees every writeback error the kernel
//!   records against it.
//! - **Writes at a tracked offset.** The adapter tracks each log's length:
//!   from the bytes its first read found, from the envelope initialise
//!   wrote, and from a truncation once its sync returns. An append writes
//!   the record there with its own loop over single positional writes (a
//!   short write continues from its count at the advanced offset and never
//!   re-appends; an interrupted one retries the same offset; a zero-length
//!   one is an error), syncs, writes the mark after the record the same
//!   way, and syncs. The length advances only when the mark's sync returns.
//! - **Every call is inline and never suspends.** Each method's future
//!   completes on its first poll, its syscalls made in that poll. So a
//!   failing sync reaches the engine's fence before any other volume's
//!   worker is polled, and a call is never dropped halfway. The price is a
//!   thread blocked for each flush: **the host runs the engine's driver on
//!   a thread of its own** (spec §8's engine card), so a slow or hung
//!   flush blocks only the authority.
//! - **The state directory is provisioned and held.** The operator
//!   creates it (spec §6.2); the adapter never does. Building the adapter
//!   resolves it by the protection walk (`crate::protected_dir`: owner,
//!   mode and filesystem type of every component; the directory itself
//!   owned by the server's uid with no group or other access, `0o700` or
//!   stricter), refuses an absent one,
//!   and takes an exclusive `flock` on its descriptor before the marker
//!   is read, held for the adapter's life: a second adapter on the same
//!   directory is refused. Every later call is an `*at` call on the held
//!   descriptor, and every directory sync is on a held descriptor (the
//!   state directory's or its parent's), never a path ([`ops`]).
//! - **No symbolic link is followed** at the state directory's name, the
//!   marker's, or any log's or temporary's. Before its I/O, every call
//!   re-checks the configured name relative to the held parent: a link
//!   there, another directory, or nothing refuses the call (spec §6.1).
//!   Every open uses `O_NOFOLLOW | O_NONBLOCK` and judges the opened file
//!   by `fstat`; files are created `0o600`.
//! - **No fence of its own.** The engine's fence is the one fence (the
//!   seam's module docs); this adapter answers every call it is given.

mod ops;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use granary_core::authlog::{Append, EncodedEnvelope};
use granary_core::decisionlog::{DecisionLog, IoErrorKind, LogIoError, MarkerRead, StateDirectory};
use granary_core::root::VolumeName;
use granary_core::runmarker::EncodedMarker;

pub(crate) use ops::{DirState, FileOps, Held, Kind, StdFileOps};

use crate::protected_dir::ProtectionError;

/// The run marker's name in the state directory.
const MARKER: &str = "MARKER";
/// The run marker's temporary's name.
const MARKER_TMP: &str = "MARKER.tmp";

/// One open log: its one description, and its length as this adapter
/// has written it.
struct Open<F> {
    file: Arc<F>,
    len: u64,
}

/// The production log adapter (module docs): the state directory's files
/// through the real file operations.
#[derive(Debug)]
pub struct FileLog(FileLogOn<StdFileOps>);

impl FileLog {
    /// Intent persistence using this log adapter's held directory and lock.
    #[must_use]
    pub fn intent_store(&self) -> Arc<super::intent::persistence::IntentStore> {
        super::intent::persistence::FileIntent::store(Arc::clone(&self.0.ops))
    }

    /// Refuse an enrollment directory with the same device and inode as
    /// this adapter's state directory. Compares checked metadata of the
    /// held descriptors, without resolving either path again. Call before
    /// starting the engine; distinct parent/child directories are allowed.
    ///
    /// # Errors
    /// Names both configuration variables when their directories coincide.
    pub fn require_separate_enrollment(
        &self,
        reader: &crate::EnrollmentReader,
    ) -> Result<(), &'static str> {
        if self
            .0
            .ops
            .directory_stat()
            .same_directory(reader.directory_stat())
        {
            Err(
                "GRANARY_AUTHORITY_STATE_DIR and GRANARY_AUTHORITY_ENROLLMENT_DIR must name distinct directories",
            )
        } else {
            Ok(())
        }
    }

    /// The adapter over the state directory at `state`, an absolute path
    /// the operator has provisioned (spec §6.2): resolved by the
    /// protection walk and locked (module docs). The filesystem types of
    /// the walk are judged unless `accept_unsupported_filesystem`, which
    /// lifts only those refusals. The host runs the engine's driver on a
    /// thread of its own (module docs).
    ///
    /// # Errors
    /// [`FileLogConfigError::Directory`] when the walk refuses `state`
    /// (absent included); [`FileLogConfigError::Locked`] when another
    /// adapter, in this process or another, holds it;
    /// [`FileLogConfigError::Lock`] when the lock cannot be taken.
    pub fn new(
        state: impl AsRef<Path>,
        accept_unsupported_filesystem: bool,
    ) -> Result<Self, FileLogConfigError> {
        StdFileOps::open(state.as_ref(), accept_unsupported_filesystem)
            .map(|ops| Self(FileLogOn::with_ops(ops)))
    }
    pub(crate) fn for_verb(state: &Path, accept: bool) -> Result<Self, FileLogConfigError> {
        StdFileOps::for_verb(state, accept).map(|ops| Self(FileLogOn::with_ops(ops)))
    }

    pub(crate) fn state_times(&self) -> io::Result<crate::lifecycle::StateTimes> {
        self.0.ops.state_times()
    }
}

impl DecisionLog for FileLog {
    fn read_marker(&self) -> impl Future<Output = Result<MarkerRead, LogIoError>> + Send {
        self.0.read_marker()
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        #[cfg(feature = "crash-points")]
        super::crash::host_io(super::crash::HostSite::MarkerWrite)?;
        self.0.write_marker(marker).await
    }

    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        #[cfg(feature = "crash-points")]
        super::crash::host_io(super::crash::HostSite::LogRead)?;
        self.0.read(volume).await
    }

    fn remove_temporary(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<bool, LogIoError>> + Send {
        self.0.remove_temporary(volume)
    }

    fn initialise(
        &self,
        envelope: &EncodedEnvelope,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.initialise(envelope)
    }

    fn complete_namespace(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.complete_namespace(volume)
    }

    async fn append(&self, append: &Append) -> Result<(), LogIoError> {
        #[cfg(feature = "crash-points")]
        super::crash::host_io(super::crash::HostSite::LogAppend)?;
        self.0.append(append).await
    }

    fn truncate(
        &self,
        volume: &VolumeName,
        len: u64,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.truncate(volume, len)
    }

    fn resync(&self, volume: &VolumeName) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.resync(volume)
    }
}

/// The adapter over the file operations `O`: the real ones in
/// [`FileLog`], a recording double in the tests.
pub(crate) struct FileLogOn<O: FileOps> {
    ops: Arc<O>,
    logs: Mutex<BTreeMap<VolumeName, Open<O::File>>>,
}

impl<O: FileOps> std::fmt::Debug for FileLogOn<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLog").finish_non_exhaustive()
    }
}

/// Why a [`FileLog`] could not be built.
#[derive(Debug)]
pub enum FileLogConfigError {
    /// The state directory failed the protection walk: absent, a link or
    /// not a directory at a component, an owner or mode the rule refuses,
    /// or an unsupported filesystem type unacknowledged.
    Directory(ProtectionError),
    /// Another description holds the state directory's lock: a second
    /// authority on the same directory.
    Locked {
        /// The configured state directory.
        path: PathBuf,
    },
    /// The state directory's lock could not be taken.
    Lock {
        /// The configured state directory.
        path: PathBuf,
        /// The failure.
        source: io::Error,
    },
}

impl std::fmt::Display for FileLogConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory(e) => write!(f, "the authority's state directory: {e}"),
            Self::Locked { path } => write!(
                f,
                "the authority's state directory {} is locked by another process: one \
                 authority per state directory",
                path.display()
            ),
            Self::Lock { path, source } => write!(
                f,
                "the authority's state directory {}: cannot take its lock: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for FileLogConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Directory(e) => Some(e),
            Self::Lock { source, .. } => Some(source),
            Self::Locked { .. } => None,
        }
    }
}

/// `err`, narrowed to the seam's error.
fn io_error(err: &io::Error) -> LogIoError {
    LogIoError::Io(match err.kind() {
        io::ErrorKind::PermissionDenied => IoErrorKind::PermissionDenied,
        io::ErrorKind::StorageFull => IoErrorKind::StorageFull,
        _ => IoErrorKind::Other,
    })
}

/// A sync's failure: always [`LogIoError::SyncFailed`] (the seam's docs).
fn sync_failed(_: io::Error) -> LogIoError {
    LogIoError::SyncFailed
}

/// A name's absence as `Ok(false)`, its removal as `Ok(true)`.
fn unlinked(result: io::Result<()>) -> Result<bool, LogIoError> {
    match result {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(&e)),
    }
}

/// The crash pipe's line for a marker write's step: the value written.
#[cfg(feature = "crash-points")]
fn marker_line(marker: &EncodedMarker, step: &str) -> String {
    let value = match granary_core::runmarker::decode_marker(marker.as_bytes()) {
        Ok(granary_core::runmarker::RunMarker::Clean) => "clean",
        Ok(_) => "running",
        Err(_) => "undecodable",
    };
    format!("MARKER {value} {step}")
}

impl<O: FileOps> FileLogOn<O> {
    /// The adapter over `ops`, which hold the state directory.
    pub(crate) fn with_ops(ops: O) -> Self {
        Self {
            ops: Arc::new(ops),
            logs: Mutex::new(BTreeMap::new()),
        }
    }

    /// Forget every open log, as a new process would: a test's fixture
    /// that rewrote the directory behind the adapter's back calls this.
    #[cfg(test)]
    pub(crate) fn forget_open_logs(&self) {
        self.logs_lock().clear();
    }

    fn logs_lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<VolumeName, Open<O::File>>> {
        self.logs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn log_name(volume: &VolumeName) -> String {
        format!("{}.log", volume.as_str())
    }

    fn temp_name(volume: &VolumeName) -> String {
        format!("{}.log.tmp", volume.as_str())
    }

    /// Refuse the call unless the state directory's configured name is
    /// still the held directory: a link there, another directory, or
    /// nothing refuses it (spec §6.1). Every call makes this check before
    /// its I/O.
    fn check_state(&self) -> Result<(), LogIoError> {
        self.ops.check_state().map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LogIoError::Io(IoErrorKind::Other),
            _ => io_error(&e),
        })
    }

    /// Write all of `bytes` to `file` at `offset` (module docs).
    fn write_all_at(
        &self,
        file: &O::File,
        mut offset: u64,
        mut bytes: &[u8],
    ) -> Result<(), LogIoError> {
        while !bytes.is_empty() {
            match self.ops.pwrite(file, offset, bytes) {
                Ok(0) => return Err(LogIoError::Io(IoErrorKind::Other)),
                Ok(n) => {
                    bytes = bytes.get(n..).ok_or(LogIoError::Io(IoErrorKind::Other))?;
                    offset = offset
                        .checked_add(
                            u64::try_from(n).map_err(|_| LogIoError::Io(IoErrorKind::Other))?,
                        )
                        .ok_or(LogIoError::Io(IoErrorKind::Other))?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(io_error(&e)),
            }
        }
        Ok(())
    }

    /// `volume`'s open log, opening it now if this process has not: its
    /// description and its tracked length. `NotFound` when it has no log.
    ///
    /// The state directory's name is checked first, an open log's calls
    /// included: a link there refuses every call (spec §6.1).
    fn open_log(&self, volume: &VolumeName) -> Result<(Arc<O::File>, u64), LogIoError> {
        self.check_state()?;
        if let Some(open) = self.logs_lock().get(volume) {
            return Ok((Arc::clone(&open.file), open.len));
        }
        let path = Self::log_name(volume);
        match self.ops.stat_at(&path) {
            Ok(None) => return Err(LogIoError::NotFound),
            Ok(Some(Kind::File)) => {}
            Ok(Some(_)) => return Err(LogIoError::Io(IoErrorKind::Other)),
            Err(e) => return Err(io_error(&e)),
        }
        let file = self.ops.open_rw(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LogIoError::NotFound,
            _ => io_error(&e),
        })?;
        let bytes = self.ops.read_all(&file).map_err(|e| io_error(&e))?;
        let len = u64::try_from(bytes.len()).map_err(|_| LogIoError::Io(IoErrorKind::Other))?;
        let file = Arc::new(file);
        self.logs_lock().insert(
            volume.clone(),
            Open {
                file: Arc::clone(&file),
                len,
            },
        );
        Ok((file, len))
    }

    /// Set `volume`'s tracked length.
    fn set_len(&self, volume: &VolumeName, len: u64) {
        if let Some(open) = self.logs_lock().get_mut(volume) {
            open.len = len;
        }
    }

    /// The held state directory is never absent: an absent one refused
    /// the adapter's construction, so this never answers
    /// [`StateDirectory::Absent`].
    fn do_read_marker(&self) -> Result<MarkerRead, LogIoError> {
        self.check_state()?;
        match self.ops.stat_at(MARKER).map_err(|e| io_error(&e))? {
            None => {}
            Some(Kind::File) => {
                return self
                    .ops
                    .read_marker(MARKER)
                    .map(MarkerRead::Present)
                    .map_err(|e| io_error(&e));
            }
            Some(_) => return Err(LogIoError::Io(IoErrorKind::Other)),
        }
        let state_dir = match self.ops.dir_state().map_err(|e| io_error(&e))? {
            DirState::Empty => StateDirectory::Empty,
            DirState::Occupied => StateDirectory::Occupied,
        };
        Ok(MarkerRead::Missing { state_dir })
    }

    fn do_write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        self.check_state()?;
        let existed = self
            .ops
            .stat_at(MARKER)
            .map_err(|e| io_error(&e))?
            .is_some();
        unlinked(self.ops.unlink(MARKER_TMP))?;
        crash_point!(MarkerLeftoverRemoved);
        let file = self
            .ops
            .create_new(MARKER_TMP)
            .map_err(|e| match e.kind() {
                // The name was taken (a file or a link planted after the
                // removal): nothing was written and the marker is as it was.
                io::ErrorKind::AlreadyExists => LogIoError::AlreadyExists,
                _ => io_error(&e),
            })?;
        crash_point!(MarkerTempCreated, marker_line(marker, "temp-created"));
        self.write_all_at(&file, 0, marker.as_bytes())?;
        crash_point!(MarkerTempWritten, marker_line(marker, "temp-written"));
        self.ops.sync_file(&file).map_err(sync_failed)?;
        crash_point!(MarkerTempSynced, marker_line(marker, "temp-synced"));
        drop(file);
        self.ops
            .rename(MARKER_TMP, MARKER)
            .map_err(|e| io_error(&e))?;
        crash_point!(MarkerRenamed, marker_line(marker, "renamed"));
        self.ops.sync_dir(Held::State).map_err(sync_failed)?;
        crash_point!(MarkerStateSynced, marker_line(marker, "state-synced"));
        if !existed {
            self.ops.sync_dir(Held::Anchor).map_err(sync_failed)?;
            crash_point!(MarkerAnchorSynced, marker_line(marker, "anchor-synced"));
        }
        Ok(())
    }

    fn do_read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        match self.open_log(volume) {
            Ok((file, _)) => self.ops.read_all(&file).map(Some).map_err(|e| io_error(&e)),
            Err(LogIoError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn do_remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        self.check_state()?;
        let removed = unlinked(self.ops.unlink(&Self::temp_name(volume)))?;
        crash_point!(LogLeftoverRemoved);
        Ok(removed)
    }

    fn do_initialise(&self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        let volume = envelope.volume();
        self.check_state()?;
        let temp = Self::temp_name(volume);
        let path = Self::log_name(volume);
        unlinked(self.ops.unlink(&temp))?;
        crash_point!(LogLeftoverRemoved);
        let file = self.ops.create_new(&temp).map_err(|e| io_error(&e))?;
        crash_point!(InitTempCreated);
        self.write_all_at(&file, 0, envelope.as_bytes())?;
        crash_point!(InitTempWritten);
        self.ops.sync_file(&file).map_err(sync_failed)?;
        crash_point!(InitTempSynced);
        if let Err(e) = self.ops.link(&temp, &path) {
            // The log's name is taken: the temporary goes, and the name's
            // bytes are as they were.
            let _ = self.ops.unlink(&temp);
            return Err(match e.kind() {
                io::ErrorKind::AlreadyExists => LogIoError::AlreadyExists,
                _ => io_error(&e),
            });
        }
        crash_point!(InitLinked);
        self.ops.unlink(&temp).map_err(|e| io_error(&e))?;
        crash_point!(InitUnlinked);
        self.ops.sync_dir(Held::State).map_err(sync_failed)?;
        crash_point!(InitStateSynced);
        self.ops.sync_dir(Held::Anchor).map_err(sync_failed)?;
        crash_point!(InitAnchorSynced);
        let len = u64::try_from(envelope.as_bytes().len())
            .map_err(|_| LogIoError::Io(IoErrorKind::Other))?;
        self.logs_lock().insert(
            volume.clone(),
            Open {
                file: Arc::new(file),
                len,
            },
        );
        Ok(())
    }

    fn do_complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.check_state()?;
        match self.ops.stat_at(&Self::log_name(volume)) {
            Ok(None) => return Err(LogIoError::NotFound),
            Ok(Some(Kind::File)) => {}
            Ok(Some(_)) => return Err(LogIoError::Io(IoErrorKind::Other)),
            Err(e) => return Err(io_error(&e)),
        }
        unlinked(self.ops.unlink(&Self::temp_name(volume)))?;
        crash_point!(NamespaceUnlinked);
        self.ops.sync_dir(Held::State).map_err(sync_failed)?;
        crash_point!(NamespaceStateSynced);
        self.ops.sync_dir(Held::Anchor).map_err(sync_failed)?;
        crash_point!(NamespaceAnchorSynced);
        Ok(())
    }

    fn do_append(&self, append: &Append) -> Result<(), LogIoError> {
        let volume = append.volume();
        let (file, len) = self.open_log(volume)?;
        let record = append.record();
        let mark = append.mark();
        let record_len =
            u64::try_from(record.len()).map_err(|_| LogIoError::Io(IoErrorKind::Other))?;
        let mark_at = len
            .checked_add(record_len)
            .ok_or(LogIoError::Io(IoErrorKind::Other))?;
        self.write_all_at(&file, len, record)?;
        crash_point!(RecordWritten);
        self.ops.sync_file(&file).map_err(sync_failed)?;
        crash_point!(RecordSynced);
        self.write_all_at(&file, mark_at, mark)?;
        crash_point!(MarkWritten);
        self.ops.sync_file(&file).map_err(sync_failed)?;
        let mark_len = u64::try_from(mark.len()).map_err(|_| LogIoError::Io(IoErrorKind::Other))?;
        let end = mark_at
            .checked_add(mark_len)
            .ok_or(LogIoError::Io(IoErrorKind::Other))?;
        // Both syncs returned: the record is acknowledged.
        crash_point!(MarkSynced, format!("ACK {} {len} {end}", volume.as_str()));
        self.set_len(volume, end);
        Ok(())
    }

    fn do_truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        let (file, current) = self.open_log(volume)?;
        if len > current {
            return Err(LogIoError::OutOfRange);
        }
        self.ops.truncate(&file, len).map_err(|e| io_error(&e))?;
        crash_point!(Truncated);
        self.ops.sync_file(&file).map_err(sync_failed)?;
        crash_point!(TruncateSynced);
        self.set_len(volume, len);
        Ok(())
    }

    fn do_resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        let (file, _) = self.open_log(volume)?;
        self.ops.sync_file(&file).map_err(sync_failed)?;
        crash_point!(Resynced);
        Ok(())
    }
}

impl<O: FileOps> DecisionLog for FileLogOn<O> {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        self.do_read_marker()
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        self.do_write_marker(marker)
    }

    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        self.do_read(volume)
    }

    async fn remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        self.do_remove_temporary(volume)
    }

    async fn initialise(&self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        self.do_initialise(envelope)
    }

    async fn complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.do_complete_namespace(volume)
    }

    async fn append(&self, append: &Append) -> Result<(), LogIoError> {
        self.do_append(append)
    }

    async fn truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        self.do_truncate(volume, len)
    }

    async fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.do_resync(volume)
    }
}
