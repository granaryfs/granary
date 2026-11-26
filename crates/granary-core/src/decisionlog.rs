// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The authority log storage seam.
//! PURE: no I/O, no tokio, std only — the
//! trait is what the server's
//! file adapter implements and what the
//! simulator and tests fake, the same split [`crate::rootstore::RootStore`]
//! draws.
//!
//! **Values are the codec's types, never raw slices** (spec §8): an
//! [`append`](DecisionLog::append) takes a [`crate::authlog::Append`],
//! the opaque value only `crate::authlog::encode_append` builds, and
//! [`initialise`](DecisionLog::initialise) takes a
//! [`crate::authlog::EncodedEnvelope`] the same way, and
//! [`write_marker`](DecisionLog::write_marker) takes a
//! [`crate::runmarker::EncodedMarker`]. For these calls a caller cannot
//! move bytes across the record/mark boundary, or hand this seam bytes
//! the codec never produced. The marker's codec is
//! [`crate::runmarker`], not the authority log's.
//!
//! **Neither call takes a volume parameter of its own.** Both
//! [`crate::authlog::Append`] and [`crate::authlog::EncodedEnvelope`]
//! carry the volume (and, for `Append`, the epoch) they were encoded
//! against, and [`append`](DecisionLog::append)/
//! [`initialise`](DecisionLog::initialise) derive the log they address
//! from the value alone. There is structurally no second,
//! independently-supplied name that could send one volume's bytes to
//! another's log. This seam does not itself check a value's epoch
//! against the log it addresses — an `Append` built against a stale
//! epoch (after a log loss and re-`initialise`) is still the engine's to
//! avoid, never this trait's; a fake with a crash-consistency model
//! (`granary-sim`'s) is expected to assert that the engine never does.
//!
//! # The fencing rule
//!
//! **Any error returned after a mutating call has begun fences the
//! whole engine process** (spec §6.2): a partial write is recovery's to
//! decide, never a caller's to retry in place. "Begun" includes a call
//! that returns `Err` having already written some bytes —
//! [`append`](DecisionLog::append),
//! [`write_marker`](DecisionLog::write_marker),
//! [`initialise`](DecisionLog::initialise),
//! [`complete_namespace`](DecisionLog::complete_namespace),
//! [`truncate`](DecisionLog::truncate) and
//! [`resync`](DecisionLog::resync) are all mutating in this sense, and
//! every one of their errors fences, with one exception:
//! [`write_marker`](DecisionLog::write_marker)'s
//! [`LogIoError::AlreadyExists`], a refused start that wrote nothing.
//!
//! **No future this trait returns is cancel-safe, for a mutating method
//! most of all.** A dropped mutating future counts as an error that
//! fences: the write it started may already be in flight, and a caller
//! that drops it has no error to react to and no way to know whether the
//! bytes landed. `select!`ing on any mutating call, or wrapping one
//! alone in a timeout, silently converts a resolvable failure into an
//! unresolvable one — the same choreography hazard
//! [`crate::rootstore`]'s module docs state for `put_root`, here on
//! every mutating method rather than one.
//!
//! # Lifetime (the adapter's obligation)
//!
//! During an engine run the production adapter opens a volume's log **once**, **lazily**,
//! strictly **after** the marker gate ([`read_marker`](DecisionLog::read_marker)) has allowed the
//! run to start, and keeps that **one open file description** for the
//! whole run, issuing every sync through it (spec §6.2: this is what
//! lets the process see a writeback error the kernel recorded against
//! that description, whoever else has since re-opened the file). The
//! trait cannot express this — `Send + Sync` and the desugared futures
//! say nothing about how many times a path is opened — so it is stated
//! here as the obligation an implementor carries, the same way
//! `RootStore`'s ONE-PROBE RULE is a caller obligation the trait cannot
//! enforce by itself. Nothing in this crate tests it; a fake that models
//! the same one-open-file-description lifetime, so a test catching a
//! second open has somewhere to fail, belongs to `granary-sim`.
//!
//! **One writer per volume log, and no concurrent calls on one volume's
//! log** (spec §8's contract card). This is a caller obligation like the
//! one above: the engine must never join two `append`s (or any other two
//! mutating calls) to the same volume's log at once. Nothing in this
//! trait's shape enforces it — every method takes `&self`, so the type
//! system alone permits concurrent calls — and a fake that catches a
//! joined pair of appends is `granary-sim`'s, not this crate's.
//!
//! # Values this seam does not interpret
//!
//! The marker's bytes are [`crate::runmarker`]'s format;
//! this seam carries them without
//! interpreting them. [`DecisionLog::write_marker`] takes a marker the
//! codec encoded, and [`MarkerRead::Present`] returns whatever bytes the
//! medium holds, well-formed or not: decoding them is
//! [`crate::runmarker::decode_marker`]'s job. A log's bytes are equally
//! opaque to `read` — classification is `crate::authlog::classify`'s
//! job, never this seam's (see [`DecisionLog::read`]'s docs).

use std::future::Future;

use crate::authlog::{Append, EncodedEnvelope};
use crate::root::VolumeName;
use crate::runmarker::EncodedMarker;

/// Why a [`DecisionLog`] call failed.
///
/// Deliberately closed and small: this seam does not attempt to carry
/// every `std::io::ErrorKind` a real filesystem can report, only the
/// distinctions a caller (the engine, and this crate's own conformance
/// suite) actually branches on. Anything else the underlying medium
/// reports is [`Self::Io`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogIoError {
    /// The name a call addressed does not exist — a volume with no log,
    /// or (for [`DecisionLog::complete_namespace`],
    /// [`DecisionLog::append`], [`DecisionLog::truncate`] and
    /// [`DecisionLog::resync`]) a volume never
    /// [`initialise`](DecisionLog::initialise)d.
    NotFound,
    /// [`DecisionLog::initialise`] found the log's name already
    /// occupied, or [`DecisionLog::write_marker`] found its temporary's
    /// name taken. Nothing changed: the existing bytes are exactly as
    /// they were before the call.
    AlreadyExists,
    /// A sync returned failure. The bytes it covered stay unsynced and
    /// readable (spec §6.2: the kernel can keep failed-writeback pages
    /// in cache), and **this fences the whole engine process** — never
    /// retried in place, and cleared only by the run-marker protocol
    /// across a host reboot.
    SyncFailed,
    /// [`DecisionLog::truncate`]'s `len` is greater than the log's
    /// current length. Nothing changed: the bytes are exactly as they
    /// were before the call. Never a silent no-op — a correct caller
    /// only ever truncates to a length recovery measured against these
    /// same bytes, so this variant means the caller's own accounting was
    /// wrong, not a race with a concurrent writer (spec §8: one writer
    /// per volume log).
    OutOfRange,
    /// Anything else the medium reported, narrowed to [`IoErrorKind`].
    Io(IoErrorKind),
}

impl std::fmt::Display for LogIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no log at that name"),
            Self::AlreadyExists => write!(f, "a log already exists at that name"),
            Self::SyncFailed => write!(f, "a sync failed — the engine is fenced"),
            Self::OutOfRange => write!(f, "truncate length is past the log's current end"),
            Self::Io(kind) => write!(f, "log i/o failed: {kind}"),
        }
    }
}

impl std::error::Error for LogIoError {}

/// A small, typed subset of the medium's own failures — the ones a
/// caller of [`DecisionLog`] can usefully tell apart from "everything
/// else". Never grown for a single call site's convenience: a new
/// variant is a contract change (see the trait's `evolution` field in
/// spec §8's contract card).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoErrorKind {
    /// The call was refused for lack of permission.
    PermissionDenied,
    /// The medium has no space left.
    StorageFull,
    /// Anything the medium reported that does not fit the two kinds
    /// above.
    Other,
}

impl std::fmt::Display for IoErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::StorageFull => write!(f, "storage full"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// What the state directory holds, observed as part of
/// [`DecisionLog::read_marker`]. `Occupied` is deliberately unspecific —
/// it means anything at all is there: a volume's log, a leftover
/// temporary, or a file this engine never wrote — because spec §6.2's
/// missing-marker startup table (the type this decides) answers the
/// same way, "refuse to start", for every occupant alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateDirectory {
    /// The state directory itself does not exist. An adapter whose state
    /// directory the operator provisions never answers this.
    Absent,
    /// The state directory exists and holds nothing.
    Empty,
    /// The state directory exists and holds something: a volume's log,
    /// a leftover temporary, or an unrelated file.
    Occupied,
}

/// The result of [`DecisionLog::read_marker`] — spec §6.2's startup
/// table, decided **before any log is opened**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerRead {
    /// The marker file exists and holds these bytes, uninterpreted: the
    /// format is [`crate::runmarker`]'s, and a file damaged on the medium
    /// reads here as it is, for [`crate::runmarker::decode_marker`] to
    /// refuse.
    Present(Vec<u8>),
    /// No marker file exists. `state_dir` answers spec §6.2's remaining
    /// rows: `Absent`/`Empty` is a first start, `Occupied` (a log, a
    /// temporary, or an unrelated file with no marker) refuses.
    Missing {
        /// What the state directory holds.
        state_dir: StateDirectory,
    },
}

/// The authority log storage contract: owned by `granary-core`,
/// implemented by the simulator's fake
/// and the server's production file
/// adapter, consumed by the decision
/// engine and the exclusively locked local operator lifecycle. See the module docs for the fencing rule, cancellation
/// and the adapter's one-open-file-description lifetime obligation —
/// every method below is governed by all three, not restated per
/// method.
///
/// Written desugared — `fn … -> impl Future<Output = …> + Send` — for
/// the same reason [`crate::rootstore::RootStore`] is: sugared
/// `async fn` in a public trait cannot express `Send` on the returned
/// future, and core stays proc-macro-free.
pub trait DecisionLog: Send + Sync {
    /// Read the run marker, before any log is opened. Spec §6.2's whole
    /// startup table is decided from this one call plus the current
    /// boot id (the engine's, not this seam's).
    ///
    /// # Cancellation safety
    /// Not cancel-safe — a dropped future abandons a partially read
    /// marker. Nothing is at risk: this is a read with no side effect,
    /// and re-issuing it is always safe.
    ///
    /// # Errors
    /// [`LogIoError::Io`] if the state directory or the marker file
    /// exists but could not be read (permission, or anything else the
    /// medium reported) — never folded into [`MarkerRead::Missing`],
    /// which means only "no marker file", not "an error reading one".
    fn read_marker(&self) -> impl Future<Output = Result<MarkerRead, LogIoError>> + Send;

    /// Write the run marker `marker`, syncing its directories after its rename
    /// (spec §6.2): create the state directory if it is absent (an
    /// adapter whose state directory the operator provisions refuses to
    /// be built without it instead) and remove
    /// a leftover marker temporary by its exact name; create a temporary
    /// exclusively, write it and sync its file; rename it over any old
    /// marker; sync the state directory; then, if no marker existed
    /// before this write, sync the state directory's parent, whether or
    /// not this call created the state directory. Returns once the last
    /// sync has returned.
    ///
    /// # Cancellation safety
    /// Not cancel-safe, and dropping this future fences (module docs):
    /// the write may already be in flight, and a caller that drops it
    /// has no error to react to.
    ///
    /// # Errors
    /// [`LogIoError::SyncFailed`] fences the engine (module docs);
    /// [`LogIoError::AlreadyExists`] if the exclusive create found the
    /// temporary's name taken — nothing was written and the marker is
    /// unchanged, so this is a refused start and does **not** fence;
    /// [`LogIoError::Io`] for anything else the medium reported, which
    /// fences.
    fn write_marker(
        &self,
        marker: &EncodedMarker,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send;

    /// The bytes at `volume`'s log name, whole and unclassified. Never
    /// interprets them — a present-but-invalid file, an intact log, and
    /// a torn one all answer `Ok(Some(_))` alike, and telling them apart
    /// is `crate::authlog::classify`'s job on the returned bytes, not
    /// this method's.
    ///
    /// # Cancellation safety
    /// Not cancel-safe — a dropped future abandons a partially read
    /// file. Nothing is at risk: this is a read with no side effect, and
    /// re-issuing it is always safe.
    ///
    /// # Errors
    /// `Ok(None)` when the name or its directory is absent (`ENOENT`) —
    /// the only case that is not an error. Anything else the medium
    /// reports for an existing name — a symlink, a non-regular file, a
    /// permission error — is [`LogIoError::Io`], never folded into
    /// `Ok(None)`.
    fn read(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, LogIoError>> + Send;

    /// Remove `volume`'s exact-named leftover temporary, if one exists,
    /// by name alone — never opened for reading. Reports whether one
    /// was there. The engine calls this for every volume at startup,
    /// after the marker gate and before [`read`](Self::read).
    ///
    /// # Cancellation safety
    /// Not cancel-safe: a dropped future may or may not have removed
    /// the temporary. Unlike the mutating methods below, this does not
    /// fence — removing an already-absent temporary is `Ok(false)`, not
    /// an error, so re-issuing it after a drop is always safe.
    ///
    /// # Errors
    /// [`LogIoError::Io`] for anything the medium reported other than
    /// the temporary's simple absence (which is `Ok(false)`, not an
    /// error).
    fn remove_temporary(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<bool, LogIoError>> + Send;

    /// Create `envelope`'s volume's log: remove the exact leftover
    /// temporary if present, then create-only write the envelope, sync
    /// it, link it to the log's name, unlink the temporary, and run the
    /// [`complete_namespace`](Self::complete_namespace) barrier. The
    /// volume is [`envelope.volume()`](crate::authlog::EncodedEnvelope::volume)
    /// — there is no separate parameter that could name a different one
    /// (module docs).
    ///
    /// # Cancellation safety
    /// Not cancel-safe, and dropping this future fences (module docs):
    /// the create may already be in flight, and a caller that drops it
    /// has no error to react to.
    ///
    /// # Errors
    /// [`LogIoError::AlreadyExists`] if the log's name already exists —
    /// nothing changes; [`LogIoError::SyncFailed`] fences the engine;
    /// [`LogIoError::Io`] for anything else the medium reported.
    fn initialise(
        &self,
        envelope: &EncodedEnvelope,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send;

    /// The namespace barrier alone, with no create: remove the exact
    /// leftover temporary, then sync the log's directory, every
    /// directory [`initialise`](Self::initialise) created, and the
    /// pre-existing anchor. Idempotent — calling it again once it has
    /// returned changes nothing. This is what lets an adopted, already-
    /// durable empty log (spec §6.3's row 2) finish its barriers and
    /// keep its epoch without re-running `initialise`'s create step.
    ///
    /// # Cancellation safety
    /// Not cancel-safe, and dropping this future fences (module docs):
    /// a sync may already be in flight, and a caller that drops it has
    /// no error to react to.
    ///
    /// # Errors
    /// [`LogIoError::NotFound`] if `volume` has no log;
    /// [`LogIoError::SyncFailed`] fences the engine; [`LogIoError::Io`]
    /// for anything else the medium reported.
    fn complete_namespace(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send;

    /// Append one record: write [`Append::record`], sync it, write
    /// [`Append::mark`], sync it. Returns once the mark's sync has
    /// returned — never before, and never with the two syncs reordered
    /// or elided (spec §6.2: no batching, no relaxing setting). The
    /// volume is [`append.volume()`](crate::authlog::Append::volume) —
    /// there is no separate parameter that could name a different one
    /// (module docs). One writer per volume log, and no concurrent calls
    /// on one volume's log: the caller must never join two appends (or
    /// any other two mutating calls) to the same volume at once (spec
    /// §8; module docs).
    ///
    /// # Cancellation safety
    /// Not cancel-safe, and dropping this future is worse than any error
    /// it can return (module docs, and [`crate::rootstore`]'s
    /// `put_root` states the same choreography hazard): the record or
    /// its mark may already be partly durable, and a caller that drops
    /// it has no error to react to.
    ///
    /// # Errors
    /// [`LogIoError::NotFound`] if the volume has no log;
    /// [`LogIoError::SyncFailed`] fences the engine; [`LogIoError::Io`]
    /// for anything else the medium reported.
    fn append(&self, append: &Append) -> impl Future<Output = Result<(), LogIoError>> + Send;

    /// Truncate `volume`'s log to `len` bytes, then sync — discarding a
    /// tail recovery decided was an interrupted append (spec §6.4).
    /// Never grows the file: `len` is always at most the log's current
    /// length in a correct caller.
    ///
    /// # Cancellation safety
    /// Not cancel-safe, and dropping this future fences (module docs):
    /// the truncation may already be in flight, and a caller that drops
    /// it has no error to react to.
    ///
    /// # Errors
    /// [`LogIoError::NotFound`] if `volume` has no log;
    /// [`LogIoError::OutOfRange`] if `len` is greater than the log's
    /// current length — nothing changes, and this is never a silent
    /// no-op; [`LogIoError::SyncFailed`] fences the engine;
    /// [`LogIoError::Io`] for anything else the medium reported.
    fn truncate(
        &self,
        volume: &VolumeName,
        len: u64,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send;

    /// Sync the whole of `volume`'s log again — making a committed but
    /// never-acknowledged survivor (spec §6.4) durable a second time
    /// before it is served. Changes no byte.
    ///
    /// # Cancellation safety
    /// Not cancel-safe, and dropping this future fences (module docs):
    /// the sync may already be in flight, and a caller that drops it has
    /// no error to react to.
    ///
    /// # Errors
    /// [`LogIoError::NotFound`] if `volume` has no log;
    /// [`LogIoError::SyncFailed`] fences the engine; [`LogIoError::Io`]
    /// for anything else the medium reported.
    fn resync(&self, volume: &VolumeName) -> impl Future<Output = Result<(), LogIoError>> + Send;
}

#[cfg(test)]
mod tests;
