// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Bounded cleanup for Linux mount tests.

use super::{BackgroundSession, abort, detach_unmount};
use crate::{MountIdentity, SessionEndEvidence, classify_session_end};
use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

const JOIN_BOUND: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(10);
const TEST_BOUND: Duration = Duration::from_secs(40);

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
}

pub(super) fn connection_path(connection: u64) -> PathBuf {
    Path::new("/sys/fs/fuse/connections").join(connection.to_string())
}

pub(super) fn require_control_fs(case: &str) -> bool {
    abort::require_available(Path::new("/sys/fs/fuse/connections").is_dir(), case)
}

/// Reads mountinfo rather than issuing a stat request to a possibly stuck daemon.
pub(super) fn mount_connection(path: &Path) -> io::Result<Option<u64>> {
    let mut escaped = Vec::new();
    for &byte in path.as_os_str().as_bytes() {
        match byte {
            b' ' => escaped.extend_from_slice(b"\\040"),
            b'\t' => escaped.extend_from_slice(b"\\011"),
            b'\n' => escaped.extend_from_slice(b"\\012"),
            b'\\' => escaped.extend_from_slice(b"\\134"),
            _ => escaped.push(byte),
        }
    }
    let mountinfo = std::fs::read("/proc/self/mountinfo")?;
    for line in mountinfo.split(|&b| b == b'\n') {
        let mut fields = line.split(|&b| b == b' ');
        let device = fields.nth(2);
        if fields.nth(1) != Some(escaped.as_slice()) {
            continue;
        }
        let kind = fields.skip_while(|f| *f != b"-").nth(1);
        if !kind.is_some_and(|f| f == b"fuse" || f.starts_with(b"fuse.")) {
            return Err(io::Error::other("test mount is not FUSE"));
        }
        let minor = device
            .and_then(|d| d.strip_prefix(b"0:"))
            .and_then(|d| std::str::from_utf8(d).ok())
            .and_then(|d| d.parse().ok())
            .ok_or_else(|| io::Error::other("test FUSE mount has no anonymous device number"))?;
        return Ok(Some(minor));
    }
    Ok(None)
}

fn wait_for_session(session: &BackgroundSession, stop: &mpsc::Receiver<()>) -> bool {
    // Fixed bounded polling avoids an unbounded JoinHandle::join, including unwind.
    for _ in 0..JOIN_BOUND.as_millis() / POLL.as_millis() {
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
) -> io::Result<()> {
    let detached = detach_unmount(path).map_err(io::Error::other);
    let mut forced = false;
    if !wait_for_session(&session, stop) {
        let Some(abort) = abort.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test FUSE worker did not exit; connection abort unavailable",
            ));
        };
        forced = true;
        abort.write_all(b"1")?;
        if !wait_for_session(&session, stop) {
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
        let (stop, commands) = mpsc::channel();
        let (connection, abort) = abort::arm(
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
            let timed_out = commands.recv_timeout(deadline).is_err();
            let session = owned.lock().unwrap().take().unwrap();
            let cleaned = cleanup(session, &path, identity, abort, &commands);
            let outcome = cleaned.and_then(|()| {
                if timed_out {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "mounted test exceeded its deadline",
                    ))
                } else {
                    Ok(())
                }
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
        }
    }

    pub(super) fn daemon_alive(&self) -> bool {
        self.session
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| !s.guard.is_finished())
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        let Some(supervisor) = self.supervisor.take() else {
            return Ok(());
        };
        let _ = self.stop.send(());
        let outcome = self
            .result
            .recv_timeout(JOIN_BOUND * 3)
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
