// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The composition root's log sink: LOSSY under backpressure, so a
//! tracing write can never block a runtime worker.
//!
//! **Why lossiness is the contract and not a defect.** Every log line in
//! this process is written from a runtime worker, and a synchronous
//! write to a backpressured stderr — a supervisor that stopped reading,
//! a full pipe — blocks that worker inside `write(2)`. Blocked workers
//! do not park on the runtime's I/O-and-time driver, and with every
//! worker blocked the driver is stranded: timers never advance, the
//! accept loop's drain deadline never fires, and a process whose signal
//! dispositions tokio holds becomes unkillable short of SIGKILL. A peer
//! that can provoke warn-level lines (a TLS handshake failure costs an
//! attacker three packets) can fill the pipe remotely, so this is a
//! shutdown-safety property, not a logging nicety: **when the sink
//! cannot keep up, lines are DROPPED and counted, and the worker moves
//! on.**
//!
//! The shape: every tracing writer hands its formatted line to a BOUNDED
//! channel; one plain `std::thread` owns the real stderr and drains the
//! channel. `std::process::exit` kills the thread with the process —
//! lines still queued at exit are lost, which is fine, because the exit
//! CODE is the outcome record on every path where that matters.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

/// How many formatted lines may wait for the writer thread before new
/// ones are dropped. Sized for bursts, not for a reader that has gone
/// away: a stuck stderr fills any finite queue, and the property that
/// matters is that the queue IS finite.
const QUEUE_LINES: usize = 1024;

/// Captured records never use generic fmt or receive a loss annotation.
pub(crate) const DEBUG_LINE_BYTES: usize = 896;

/// A [`tracing_subscriber`] writer whose `write` NEVER blocks on the
/// destination: lines go to a bounded queue, and a queue with no room
/// drops the line and bumps a counter that is reported on the next line
/// that fits.
#[derive(Clone, Debug)]
pub struct LossyStderr {
    sender: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicUsize>,
    #[cfg(test)]
    pub(crate) debug_gate: Option<Arc<tests::DebugGate>>,
}

fn add_dropped(counter: &AtomicUsize, count: usize) {
    let _updated = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(count))
    });
}

impl LossyStderr {
    /// Share the baseline queue without formatting or destination I/O. DEBUG
    /// loss is counted only by capture and never annotates a baseline line.
    pub(crate) fn try_enqueue_debug(&self, line: &[u8]) -> bool {
        if line.len() > DEBUG_LINE_BYTES {
            return false;
        }
        #[cfg(test)]
        if let Some(gate) = &self.debug_gate {
            gate.enter();
        }
        match self.sender.try_send(line.to_vec()) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }
}

/// The lossy sink writing to the process's real stderr.
///
/// The writer thread is detached by design: it lives exactly as long as
/// the process, and every exit path here is `std::process::exit`, which
/// does not wait for threads.
#[must_use]
pub fn lossy_stderr() -> LossyStderr {
    lossy(std::io::stderr())
}

/// The generic core, taking any destination — which is what makes the
/// drop semantics testable without capturing the process's stderr.
fn lossy<W: Write + Send + 'static>(mut destination: W) -> LossyStderr {
    let (sender, receiver): (SyncSender<Vec<u8>>, Receiver<Vec<u8>>) = sync_channel(QUEUE_LINES);
    // A plain std thread, deliberately outside the runtime: its whole
    // job is to be the one place that may block on stderr.
    std::thread::spawn(move || {
        while let Ok(line) = receiver.recv() {
            if destination.write_all(&line).is_err() {
                // stderr is gone for good (EPIPE stays broken); drain
                // the channel forever so senders keep not blocking.
                for _discarded in &receiver {}
                return;
            }
        }
    });
    LossyStderr {
        sender,
        dropped: Arc::new(AtomicUsize::new(0)),
        #[cfg(test)]
        debug_gate: None,
    }
}

/// One formatted event's worth of buffered bytes, handed to the queue on
/// flush/drop.
#[derive(Debug)]
pub struct LossyLine {
    sender: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicUsize>,
    line: Vec<u8>,
}

impl Write for LossyLine {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.line.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.line.is_empty() {
            return Ok(());
        }
        // A drop happened earlier: prefix the accounting onto the next
        // line that fits, so the loss is visible in the stream itself.
        let backlog = self.dropped.swap(0, Ordering::Relaxed);
        let mut line = std::mem::take(&mut self.line);
        if backlog > 0 {
            let mut annotated =
                format!("[lossy log sink: {backlog} line(s) dropped under backpressure]\n")
                    .into_bytes();
            annotated.append(&mut line);
            line = annotated;
        }
        match self.sender.try_send(line) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                // The queue is full (or the writer died): DROP, count,
                // and restore the count we failed to report.
                add_dropped(&self.dropped, backlog.saturating_add(1));
                Ok(())
            }
        }
    }
}

impl Drop for LossyLine {
    fn drop(&mut self) {
        let _best_effort = self.flush();
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LossyStderr {
    type Writer = LossyLine;

    fn make_writer(&'a self) -> Self::Writer {
        LossyLine {
            sender: self.sender.clone(),
            dropped: Arc::clone(&self.dropped),
            line: Vec::new(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
