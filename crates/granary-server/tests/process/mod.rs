// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Child ownership stays with the caller while a bounded wait is pending.
use std::io;
use std::process::{Child, ExitStatus};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(super) struct ChildGuard(pub(super) Child);

impl ChildGuard {
    #[expect(
        clippy::disallowed_methods,
        reason = "fixture process waits use real elapsed time, outside simulated execution"
    )]
    pub(super) fn wait_within(&mut self, bound: Duration) -> io::Result<Option<ExitStatus>> {
        let started = Instant::now();
        let (_held, pause) = mpsc::channel::<()>();
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(Some(status));
            }
            let remaining = bound.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(None);
            }
            let _ = pause.recv_timeout(remaining.min(Duration::from_millis(10)));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
