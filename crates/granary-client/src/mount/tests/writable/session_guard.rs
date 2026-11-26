// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Bounded cleanup for Linux mount tests.

use super::{BackgroundSession, abort, detach_unmount};
use crate::SyncRuntime as _;
use crate::overlay_test_support::{arm_fuse_abort, mount_connection};
use granary_fuse::{MountIdentity, SessionEndEvidence, classify_session_end};
use std::fs::File;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

/// How long a detached session may take to end before the cleanup aborts it.
const JOIN_BOUND: Duration = Duration::from_secs(2);
/// What [`engine_join_bound`] adds to the shutdown's bound: its answer margin
/// and the session's exit after `destroy` returns.
const ENGINE_JOIN_SLACK: Duration = Duration::from_secs(1);
/// The least [`engine_join_bound`] gives, for a fixture that cuts its
/// shutdown's bound short: its session still has to exit on a loaded host.
/// Also the whole join of a fixture inside a harness with its own shorter
/// bound, which a wait for the shutdown's bound would outlast.
pub(super) const ENGINE_JOIN_FLOOR: Duration = Duration::from_secs(5);

/// [`JOIN_BOUND`] for a session with a sync engine attached, whose `destroy`
/// runs the engine's shutdown under `shutdown`, or the default bound. That
/// shutdown's commit is fsync-bound: with the scratch on a disk shared with a
/// parallel suite's fsyncs it took 2 to over 10 s, where tmpfs takes under
/// 0.6 s. So the join waits out the bound the shutdown promises rather than a
/// guess at its speed.
pub(super) fn engine_join_bound(shutdown: Option<Duration>) -> Duration {
    shutdown
        .unwrap_or(crate::sync::DEFAULT_SHUTDOWN_BOUND)
        .saturating_add(ENGINE_JOIN_SLACK)
        .max(ENGINE_JOIN_FLOOR)
}
const POLL: Duration = Duration::from_millis(10);
pub(super) const TEST_BOUND: Duration = Duration::from_secs(40);

/// Owns a mounted session and a supervisor that also runs if the test blocks.
/// The abort descriptor is opened while this mount owns its device number:
/// retaining that descriptor prevents cleanup from touching a recycled number.
/// If it cannot be pinned, cleanup uses lazy unmount and a bounded join alone.
pub(super) struct SessionGuard {
    session: Arc<Mutex<Option<BackgroundSession>>>,
    stop: mpsc::Sender<()>,
    result: mpsc::Receiver<io::Result<()>>,
    supervisor: Option<JoinHandle<()>>,
    pub(super) connection: Option<u64>,
    pub(super) abort_available: bool,
    join: Duration,
}

pub(super) fn connection_path(connection: u64) -> PathBuf {
    Path::new("/sys/fs/fuse/connections").join(connection.to_string())
}

pub(super) fn require_control_fs(case: &str) -> bool {
    abort::require_available(Path::new("/sys/fs/fuse/connections").is_dir(), case)
}

fn wait_for_session(
    session: &BackgroundSession,
    stop: &mpsc::Receiver<()>,
    join: Duration,
) -> bool {
    // Fixed bounded polling avoids an unbounded JoinHandle::join, including unwind.
    for _ in 0..join.as_millis() / POLL.as_millis() {
        if session.guard.is_finished() {
            return true;
        }
        let _ = stop.recv_timeout(POLL);
    }
    session.guard.is_finished()
}

fn cleanup(
    session: BackgroundSession,
    path: &Path,
    identity: io::Result<MountIdentity>,
    mut abort: Option<File>,
    stop: &mpsc::Receiver<()>,
    join: Duration,
) -> io::Result<()> {
    let detached = detach_unmount(path).map_err(io::Error::other);
    let mut forced = false;
    let started = crate::TokioSyncRuntime.now();
    let ended = wait_for_session(&session, stop, join);
    let waited = crate::TokioSyncRuntime
        .now()
        .saturating_duration_since(started);
    if ended && waited > JOIN_BOUND {
        eprintln!(
            "mount test cleanup: the session took {} ms to end after its detach",
            waited.as_millis()
        );
    }
    if !ended {
        let Some(abort) = abort.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test FUSE worker did not exit; connection abort unavailable",
            ));
        };
        forced = true;
        abort.write_all(b"1")?;
        if !wait_for_session(&session, stop, join) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test FUSE worker did not exit after abort",
            ));
        }
    }
    let joined = session.join();
    if let Err(error) = &joined {
        eprintln!(
            "mount test cleanup: FUSE session ended with {:?}: {error}",
            error.kind()
        );
    }
    // The device captured at mount time, at this fixture's own path, through
    // the strict parser: a row the parser cannot read never reads as gone,
    // and a parallel test's mount that took over the freed device number
    // sits at its own path, so it never reads as this one still listed.
    let listed = identity.and_then(|identity| identity.listed_at(path));
    classify_session_end(SessionEndEvidence {
        unmount: detached,
        joined,
        forced,
        listed,
    })
    .into_result()
}

impl SessionGuard {
    pub(super) fn new(session: BackgroundSession, path: &Path) -> Self {
        Self::with_deadline(session, path, TEST_BOUND)
    }

    pub(super) fn with_deadline(
        session: BackgroundSession,
        path: &Path,
        deadline: Duration,
    ) -> Self {
        Self::with_recovery(session, path, deadline, JOIN_BOUND, || {})
    }

    pub(super) fn with_recovery(
        session: BackgroundSession,
        path: &Path,
        deadline: Duration,
        join: Duration,
        recover: impl FnOnce() + Send + 'static,
    ) -> Self {
        let (stop, commands) = mpsc::channel();
        let (connection, abort) = arm_fuse_abort(
            mount_connection(path),
            Path::new("/sys/fs/fuse/connections"),
        );
        let abort_available = abort.is_some();
        let identity = MountIdentity::capture(path);
        let path = path.to_path_buf();
        let session = Arc::new(Mutex::new(Some(session)));
        let owned = session.clone();
        let (send_result, result) = mpsc::channel();
        let supervisor = std::thread::spawn(move || {
            let outcome =
                abort::supervise(&commands, deadline, abort, recover, |abort, commands| {
                    let session = owned.lock().unwrap().take().unwrap();
                    cleanup(session, &path, identity, abort, commands, join)
                });
            let _ = send_result.send(outcome);
        });
        Self {
            session,
            stop,
            result,
            supervisor: Some(supervisor),
            connection,
            abort_available,
            join,
        }
    }

    pub(super) fn daemon_alive(&self) -> bool {
        self.session
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| !s.guard.is_finished())
    }

    pub(super) fn stop_sender(&self) -> mpsc::Sender<()> {
        self.stop.clone()
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        let Some(supervisor) = self.supervisor.take() else {
            return Ok(());
        };
        let _ = self.stop.send(());
        let outcome = self
            .result
            .recv_timeout(self.join.saturating_mul(3))
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;
        supervisor
            .join()
            .map_err(|_| io::Error::other("mount cleanup supervisor panicked"))?;
        outcome
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("mount test cleanup: {error}");
        }
    }
}
