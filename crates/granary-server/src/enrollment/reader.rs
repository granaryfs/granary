// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The server's reader of the enrollment set: a lookup with three answers,
//! a status snapshot, and the refresh behind both.
//!
//! **What a refresh does.** It compares the configured path's identity with
//! the held directory descriptor's: a successful `stat` showing anything
//! else (not a directory, or a different device and inode) makes every later lookup
//! `unavailable(directory)` until the server restarts, so a set written
//! into a replacement directory is never read as absent from the old one;
//! a `stat` that fails (the path missing included) answers
//! `unavailable(directory)` for that refresh only, and the next refresh
//! looks again. It then `fstatat`s `ENROLLMENT` on the held descriptor; answers
//! from the held verdict when the name's identity equals the held file's;
//! and otherwise reads the file afresh ([`super::read_set`]). Only content
//! verdicts (a set, corrupt, oversize, unprotected) are kept against an
//! identity; an I/O failure is answered `unreadable` and retried by the
//! next refresh, and any failed refresh drops the held set, so no earlier
//! binding answers.
//!
//! **Where it runs, and how often.** No filesystem call runs on a runtime
//! worker: a refresh runs on the blocking pool. At most one is in flight. A
//! lookup takes a result only from a refresh that began after the lookup
//! arrived: a refresh increments a start counter before its first
//! observation and carries the value, and a lookup that finds an older
//! refresh in flight waits for it and then starts or joins the next one.
//! So a lookup that begins after a verb returned sees that verb's change.
//! A lookup waits at most [`LOOKUP_DEADLINE`]; past it the answer is
//! `unavailable(stalled)`, and a hung refresh is waited on again, never
//! duplicated.
//!
//! **Status never waits on the filesystem.** The counters are atomics, and
//! the published state sits behind a lock no refresh holds across I/O.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use granary_core::enrollment::{ClientSpkiDigest, EnrollmentSet, PrincipalId, TenantName};
use tokio::sync::watch;

use super::{Identity, ReadOutcome, SET_NAME, UnavailableReason, Verdict, read_set};
use crate::protected_dir::{DirOps, NixOps, ProtectedDir, ProtectionError};

/// The longest a lookup waits for the filesystem before it answers
/// `unavailable(stalled)`.
pub const LOOKUP_DEADLINE: Duration = Duration::from_secs(2);

/// A lookup's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The digest is enrolled to `principal` under `tenant`.
    Enrolled {
        /// The principal the credential is enrolled to.
        principal: PrincipalId,
        /// The principal's tenant.
        tenant: TenantName,
    },
    /// The set was read and the digest is not in it.
    Absent,
    /// The set could not be consulted; the client is neither admitted nor
    /// told it is unknown.
    Unavailable(UnavailableReason),
}

/// Why the reader could not be built: the server refuses to start.
#[derive(Debug)]
pub enum ReaderStartError {
    /// The directory fails the protection rule (or cannot be walked).
    Directory(ProtectionError),
    /// The directory is not searchable by the server's effective uid.
    NotSearchable {
        /// The configured path.
        path: PathBuf,
        /// The failure.
        source: io::Error,
    },
}

impl std::fmt::Display for ReaderStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory(e) => write!(f, "the enrollment directory is not protected: {e}"),
            Self::NotSearchable { path, source } => write!(
                f,
                "the enrollment directory {} cannot be searched: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ReaderStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Directory(e) => Some(e),
            Self::NotSearchable { source, .. } => Some(source),
        }
    }
}

/// The state the last completed refresh reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotState {
    /// A set was read.
    Ok {
        /// Its principal records, active and retired.
        principals: usize,
        /// Its enrolled credentials.
        credentials: usize,
    },
    /// No set could be read.
    Unavailable(UnavailableReason),
}

/// The reader's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapshotCounters {
    /// Lookups answered `unavailable(missing)`.
    pub missing: u64,
    /// Lookups answered `unavailable(unreadable)`.
    pub unreadable: u64,
    /// Lookups answered `unavailable(unprotected)`.
    pub unprotected: u64,
    /// Lookups answered `unavailable(oversize)`.
    pub oversize: u64,
    /// Lookups answered `unavailable(corrupt)`.
    pub corrupt: u64,
    /// Lookups answered `unavailable(directory)`.
    pub directory: u64,
    /// Lookups answered `unavailable(stalled)`.
    pub stalled: u64,
    /// Refreshes that read and decoded a new set.
    pub reloads: u64,
    /// Refreshes that did not produce a set, for any reason.
    pub reload_failures: u64,
}

/// The reader's status, as a value: what the last completed refresh found,
/// that refresh's sequence number (the start counter's value, not a time),
/// and the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentSnapshot {
    /// The last completed refresh's verdict.
    pub state: SnapshotState,
    /// The last completed refresh's sequence number.
    pub sequence: u64,
    /// The counters.
    pub counters: SnapshotCounters,
}

/// The reader (module docs), over the production file operations.
#[derive(Debug, Clone)]
pub struct EnrollmentReader(ReaderOn<NixOps>);

impl EnrollmentReader {
    /// Current lookup futures, including ones waiting for a refresh.
    #[cfg(test)]
    pub(crate) fn active_lookups(&self) -> u64 {
        self.0.inner.active_lookups.load(Ordering::SeqCst)
    }

    /// Hold a refresh immediately before its filesystem observation.
    #[cfg(test)]
    pub(crate) fn hold_refresh(&self, pause: Arc<crate::protected_dir::tests::Pause>) {
        *lock(&self.0.inner.refresh_pause) = Some(pause);
    }

    #[cfg(test)]
    pub(crate) fn seed_snapshot(&self, snapshot: EnrollmentSnapshot) {
        *lock(&self.0.inner.published) = Published {
            state: snapshot.state,
            sequence: snapshot.sequence,
        };
        let counters = &self.0.inner.counters;
        for (counter, value) in [
            (&counters.missing, snapshot.counters.missing),
            (&counters.unreadable, snapshot.counters.unreadable),
            (&counters.unprotected, snapshot.counters.unprotected),
            (&counters.oversize, snapshot.counters.oversize),
            (&counters.corrupt, snapshot.counters.corrupt),
            (&counters.directory, snapshot.counters.directory),
            (&counters.stalled, snapshot.counters.stalled),
            (&counters.reloads, snapshot.counters.reloads),
            (&counters.reload_failures, snapshot.counters.reload_failures),
        ] {
            counter.store(value, Ordering::Relaxed);
        }
    }

    pub(crate) fn directory_stat(&self) -> &crate::protected_dir::Stat {
        &self.0.inner.dir.stat
    }

    /// Check the enrollment directory at `path` and read the set once, on
    /// the calling thread. Call it at startup, before the server is ready:
    /// it blocks on the filesystem.
    ///
    /// `accept_unsupported_filesystem` is the operator's explicit
    /// acknowledgement that a component's filesystem type is outside the
    /// supported table; it lifts the type refusals and nothing else. On a
    /// platform without a type table (anything but Linux) the walk refuses
    /// without it.
    ///
    /// A missing, corrupt, oversize or unprotected file does not fail
    /// this: the reader starts, and every lookup is unavailable with that
    /// reason until the file is fixed.
    ///
    /// # Errors
    /// [`ReaderStartError`] when the directory fails the protection rule,
    /// is not owned by the effective uid, or is not searchable.
    pub fn open(
        path: &Path,
        accept_unsupported_filesystem: bool,
    ) -> Result<Self, ReaderStartError> {
        ReaderOn::open(NixOps, path, accept_unsupported_filesystem, LOOKUP_DEADLINE).map(Self)
    }

    /// Whether `digest` is enrolled (module docs).
    ///
    /// # Cancellation safety
    /// Cancel-safe. Dropping the future leaves any refresh it started
    /// running to completion on the blocking pool, where it publishes its
    /// result and clears itself; nothing is left half-done.
    pub async fn lookup(&self, digest: &ClientSpkiDigest) -> Lookup {
        #[cfg(test)]
        let _lookup = LookupGuard::enter(&self.0.inner.active_lookups);
        self.0.lookup(digest).await
    }

    /// Refresh validated enrollment for authority lifecycle maintenance.
    /// # Errors
    /// The same protected-file and deadline refusals as principal lookup.
    pub async fn current_set(&self) -> Result<Arc<EnrollmentSet>, UnavailableReason> {
        let arrival = self.0.inner.started.load(Ordering::SeqCst);
        tokio::time::timeout(self.0.deadline, self.0.refreshed_after(arrival))
            .await
            .unwrap_or_else(|_| {
                self.0.note_stall();
                Err(UnavailableReason::Stalled)
            })
    }

    /// The reader's status. Reads only atomics and a lock no refresh holds
    /// across I/O, so it never waits on the filesystem.
    #[must_use]
    pub fn snapshot(&self) -> EnrollmentSnapshot {
        self.0.snapshot()
    }
}

#[cfg(test)]
struct LookupGuard<'a>(&'a AtomicU64);

#[cfg(test)]
impl<'a> LookupGuard<'a> {
    fn enter(active: &'a AtomicU64) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self(active)
    }
}

#[cfg(test)]
impl Drop for LookupGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a refresh produced.
type Outcome = Result<Arc<EnrollmentSet>, UnavailableReason>;

/// The reader over any [`DirOps`].
#[derive(Debug)]
pub(crate) struct ReaderOn<O: DirOps> {
    inner: Arc<Inner<O>>,
    deadline: Duration,
}

impl<O: DirOps> Clone for ReaderOn<O> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            deadline: self.deadline,
        }
    }
}

/// The file the last refresh loaded, and its verdict.
#[derive(Debug)]
struct Held {
    /// Kept open so the inode stays allocated: a file renamed over the name
    /// always has another identity.
    _file: std::fs::File,
    identity: Identity,
    verdict: Verdict,
}

/// The refresh in flight.
#[derive(Debug)]
struct Flight {
    start: u64,
    done: watch::Receiver<Option<Outcome>>,
    /// Lookups that joined it rather than starting it.
    joins: u64,
}

#[derive(Debug, Default)]
struct Counters {
    missing: AtomicU64,
    unreadable: AtomicU64,
    unprotected: AtomicU64,
    oversize: AtomicU64,
    corrupt: AtomicU64,
    directory: AtomicU64,
    stalled: AtomicU64,
    reloads: AtomicU64,
    reload_failures: AtomicU64,
}

impl Counters {
    fn unavailable(&self, reason: UnavailableReason) -> &AtomicU64 {
        match reason {
            UnavailableReason::Missing => &self.missing,
            UnavailableReason::Unreadable => &self.unreadable,
            UnavailableReason::Unprotected => &self.unprotected,
            UnavailableReason::Oversize => &self.oversize,
            UnavailableReason::Corrupt => &self.corrupt,
            UnavailableReason::Directory => &self.directory,
            UnavailableReason::Stalled => &self.stalled,
        }
    }

    fn read(&self) -> SnapshotCounters {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        SnapshotCounters {
            missing: r(&self.missing),
            unreadable: r(&self.unreadable),
            unprotected: r(&self.unprotected),
            oversize: r(&self.oversize),
            corrupt: r(&self.corrupt),
            directory: r(&self.directory),
            stalled: r(&self.stalled),
            reloads: r(&self.reloads),
            reload_failures: r(&self.reload_failures),
        }
    }
}

/// The published state: written at the end of each refresh, read by the
/// snapshot. Never held across I/O.
#[derive(Debug, Clone, Copy)]
struct Published {
    state: SnapshotState,
    sequence: u64,
}

#[derive(Debug)]
struct Inner<O: DirOps> {
    ops: O,
    path: PathBuf,
    dir: ProtectedDir,
    /// Set once a successful `stat` of the path names another directory.
    directory_lost: AtomicBool,
    /// The refresh-start counter.
    started: AtomicU64,
    /// Touched only by the one refresh in flight (and the constructor).
    held: Mutex<Option<Held>>,
    flight: Mutex<Option<Flight>>,
    published: Mutex<Published>,
    /// The start value of the in-flight refresh a stall was last logged
    /// for, so a stall logs once.
    stall_logged: AtomicU64,
    counters: Counters,
    #[cfg(test)]
    refresh_pause: Mutex<Option<Arc<crate::protected_dir::tests::Pause>>>,
    #[cfg(test)]
    active_lookups: AtomicU64,
}

/// Lock a mutex, taking the value a panicking holder left: every value
/// guarded here is replaced whole, never left half-updated.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<O: DirOps> ReaderOn<O> {
    pub(crate) fn open(
        ops: O,
        path: &Path,
        accept_unsupported_filesystem: bool,
        deadline: Duration,
    ) -> Result<Self, ReaderStartError> {
        let dir = ProtectedDir::for_server(&ops, path, accept_unsupported_filesystem)
            .map_err(ReaderStartError::Directory)?;
        // The search check: a directory the server can open but not search
        // would make every lookup unreadable for ever.
        match ops.stat_at(&dir.dir, SET_NAME) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ReaderStartError::NotSearchable {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        }
        let inner = Arc::new(Inner {
            ops,
            path: path.to_path_buf(),
            dir,
            directory_lost: AtomicBool::new(false),
            started: AtomicU64::new(0),
            held: Mutex::new(None),
            flight: Mutex::new(None),
            published: Mutex::new(Published {
                // Replaced by the refresh below before anyone can read it.
                state: SnapshotState::Unavailable(UnavailableReason::Missing),
                sequence: 0,
            }),
            stall_logged: AtomicU64::new(0),
            counters: Counters::default(),
            #[cfg(test)]
            refresh_pause: Mutex::new(None),
            #[cfg(test)]
            active_lookups: AtomicU64::new(0),
        });
        let start = inner
            .started
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let _initial = inner.refresh(start, None);
        Ok(Self { inner, deadline })
    }

    pub(crate) async fn lookup(&self, digest: &ClientSpkiDigest) -> Lookup {
        let arrival = self.inner.started.load(Ordering::SeqCst);
        let timed = tokio::time::timeout(self.deadline, self.refreshed_after(arrival)).await;
        let outcome = timed.unwrap_or_else(|_| {
            self.note_stall();
            Err(UnavailableReason::Stalled)
        });
        match outcome {
            Ok(set) => match set.lookup(digest) {
                Some((principal, tenant)) => Lookup::Enrolled {
                    principal,
                    tenant: tenant.clone(),
                },
                None => Lookup::Absent,
            },
            Err(reason) => {
                self.inner
                    .counters
                    .unavailable(reason)
                    .fetch_add(1, Ordering::Relaxed);
                Lookup::Unavailable(reason)
            }
        }
    }

    pub(crate) fn snapshot(&self) -> EnrollmentSnapshot {
        let published = *lock(&self.inner.published);
        EnrollmentSnapshot {
            state: published.state,
            sequence: published.sequence,
            counters: self.inner.counters.read(),
        }
    }

    /// The outcome of a refresh that began after `arrival`.
    async fn refreshed_after(&self, arrival: u64) -> Outcome {
        loop {
            let (start, mut done) = self.join_or_start();
            // The refresh's sender gone without a result means its task
            // never ran (the runtime is shutting down). Clear the flight so
            // the next lookup starts afresh, and answer unreadable.
            let Ok(value) = done.wait_for(Option::is_some).await.map(|v| v.clone()) else {
                let mut flight = lock(&self.inner.flight);
                if flight.as_ref().is_some_and(|f| f.start == start) {
                    *flight = None;
                }
                return Err(UnavailableReason::Unreadable);
            };
            if start > arrival {
                return value.unwrap_or(Err(UnavailableReason::Unreadable));
            }
        }
    }

    /// Join the refresh in flight, or start one.
    fn join_or_start(&self) -> (u64, watch::Receiver<Option<Outcome>>) {
        let mut flight = lock(&self.inner.flight);
        if let Some(f) = flight.as_mut() {
            f.joins = f.joins.saturating_add(1);
            return (f.start, f.done.clone());
        }
        // Incremented before the refresh's first observation, so a lookup
        // that read the counter before this line accepts its result and
        // one that read it after does not.
        let start = self
            .inner
            .started
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let (tx, rx) = watch::channel(None);
        *flight = Some(Flight {
            start,
            done: rx.clone(),
            joins: 0,
        });
        drop(flight);
        let inner = Arc::clone(&self.inner);
        #[expect(
            clippy::disallowed_methods,
            reason = "the enrollment reader is never driven by the simulator, and its filesystem \
                      calls must not run on a runtime worker: the blocking pool is where they go"
        )]
        let _detached = tokio::task::spawn_blocking(move || {
            let _outcome = inner.refresh(start, Some(tx));
        });
        (start, rx)
    }

    /// How many lookups joined the refresh in flight, if one is.
    #[cfg(test)]
    pub(crate) fn joins_in_flight(&self) -> Option<u64> {
        lock(&self.inner.flight).as_ref().map(|f| f.joins)
    }

    fn note_stall(&self) {
        let start = lock(&self.inner.flight).as_ref().map(|f| f.start);
        if let Some(start) = start
            && self.inner.stall_logged.swap(start, Ordering::Relaxed) != start
        {
            tracing::warn!(
                path = %self.inner.path.display(),
                reason = UnavailableReason::Stalled.as_str(),
                "the enrollment set is unavailable: the filesystem did not answer in time"
            );
        }
    }
}

impl<O: DirOps> Inner<O> {
    /// One refresh (module docs), then publish its result: to the snapshot,
    /// and to the lookups waiting on `done`.
    fn refresh(&self, start: u64, done: Option<watch::Sender<Option<Outcome>>>) -> Outcome {
        let outcome = self.observe();
        match &outcome {
            Ok(_) => {}
            Err(_) => {
                self.counters
                    .reload_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        self.publish(start, &outcome);
        if let Some(done) = done {
            {
                let mut flight = lock(&self.flight);
                if flight.as_ref().is_some_and(|f| f.start == start) {
                    *flight = None;
                }
            }
            done.send_replace(Some(outcome.clone()));
        }
        outcome
    }

    fn observe(&self) -> Outcome {
        let mut held = lock(&self.held);
        #[cfg(test)]
        if let Some(pause) = lock(&self.refresh_pause).take() {
            pause.arrive_and_wait();
        }
        if self.directory_lost.load(Ordering::SeqCst) {
            *held = None;
            return Err(UnavailableReason::Directory);
        }
        match self.ops.stat_path(&self.path) {
            Ok(now)
                if now.is_dir() && now.dev == self.dir.stat.dev && now.ino == self.dir.stat.ino => {
            }
            Ok(_) => {
                self.directory_lost.store(true, Ordering::SeqCst);
                *held = None;
                return Err(UnavailableReason::Directory);
            }
            Err(_) => {
                *held = None;
                return Err(UnavailableReason::Directory);
            }
        }
        let name = match self.ops.stat_at(&self.dir.dir, SET_NAME) {
            Ok(stat) => stat,
            Err(e) => {
                *held = None;
                return Err(if e.kind() == io::ErrorKind::NotFound {
                    UnavailableReason::Missing
                } else {
                    UnavailableReason::Unreadable
                });
            }
        };
        if let Some(h) = held.as_ref()
            && h.identity == Identity::of(&name)
        {
            return h.verdict.outcome().map(Arc::clone);
        }
        let read = read_set(&self.ops, &self.dir.dir, self.dir.owner());
        let outcome = read.outcome().map(Arc::clone);
        *held = match read {
            // Only a content verdict is kept against an identity.
            ReadOutcome::Loaded {
                file,
                identity,
                verdict,
            } => {
                if outcome.is_ok() {
                    self.counters.reloads.fetch_add(1, Ordering::Relaxed);
                }
                Some(Held {
                    _file: file,
                    identity,
                    verdict,
                })
            }
            ReadOutcome::Missing | ReadOutcome::Link | ReadOutcome::Io(_) => None,
        };
        outcome
    }

    /// Record the refresh's result for the snapshot, and log a transition
    /// into or out of an unavailable state.
    fn publish(&self, start: u64, outcome: &Outcome) {
        let state = match outcome {
            Ok(set) => SnapshotState::Ok {
                principals: set.principal_count(),
                credentials: set.credential_count(),
            },
            Err(reason) => SnapshotState::Unavailable(*reason),
        };
        let previous = {
            let mut published = lock(&self.published);
            // A refresh's start is unique and the counter only grows, so an
            // older result never replaces a newer one. The constructor's
            // refresh publishes over the placeholder (sequence 0).
            if start < published.sequence {
                return;
            }
            let previous = (published.sequence != 0).then_some(published.state);
            *published = Published {
                state,
                sequence: start,
            };
            previous
        };
        match (previous, state) {
            (_, SnapshotState::Unavailable(reason))
                if previous != Some(SnapshotState::Unavailable(reason)) =>
            {
                tracing::warn!(
                    path = %self.path.display(),
                    reason = reason.as_str(),
                    "the enrollment set is unavailable; lookups refuse until it is readable"
                );
            }
            (
                Some(SnapshotState::Unavailable(was)),
                SnapshotState::Ok {
                    principals,
                    credentials,
                },
            ) => {
                tracing::info!(
                    path = %self.path.display(),
                    was = was.as_str(),
                    principals,
                    credentials,
                    "the enrollment set is available again"
                );
            }
            _ => {}
        }
    }
}
