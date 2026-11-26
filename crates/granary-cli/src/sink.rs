// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bounded, nonblocking output admission with one destination worker.
//!
//! The 1024-record queue reserves 64 slots from Telemetry. Local and Protected
//! share reserved admission and one FIFO; the worker drains that FIFO before
//! telemetry. Each admitted record carries its destination class. Local and
//! Protected go to the owned original stderr descriptor; telemetry goes to the
//! configured file or stderr, including any file-write fallback.
//!
//! Local accepts opaque typed records. Telemetry accepts only opaque projected
//! log records. Arbitrary `Write` callers have a Protected writer, which submits
//! a whole formatted message at once. Bare writes accumulate until flush/drop.
//! Typed reporting flushes any earlier Protected pending message before Local
//! admission, preserving ordering at the writer as well as at the queue.
//!
//! Loss accounting distinguishes all three streams. Local/Protected loss
//! notices have reserved service priority but are delivered to telemetry's
//! destination. Permanent destination failure can prevent delivery of both
//! records and loss notices; it never blocks producers. One 500 ms close wait
//! covers both destinations, after which the blocked worker is detached.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// How many complete messages may wait for the worker before a new one is
/// refused. Sized for a burst, never for a destination that has gone away: a
/// stuck stderr fills any finite queue, and the property that matters is that
/// the queue IS finite.
pub(crate) const CAPACITY: usize = 1024;

/// Slots [`Stream::Telemetry`] may never occupy, so a protected record still
/// has somewhere to land after an ordinary successful startup has filled the
/// rest.
pub(crate) const PROTECTED_RESERVE: usize = 64;

// Refusal wakes the worker, and a refusal requires a full queue. Checking
// accounting before the closed flag ensures a drained queue or close does not
// strand its last loss report when no later submission arrives.

/// Which guarantee a message carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stream {
    /// A user-facing result or an executable test contract: something greps
    /// it, or an operator needs it to act. Reserved admission, priority of
    /// service, and a loss that is REPORTED rather than silent.
    Protected,
    /// Typed operator reports, delivered only to original standard error.
    Local,
    /// Disposable telemetry. May be dropped under backpressure; the drop is
    /// counted and the count is surfaced in the stream.
    Telemetry,
}

#[derive(Default)]
struct Queues {
    protected: VecDeque<(Stream, Vec<u8>)>,
    telemetry: VecDeque<Vec<u8>>,
    /// Telemetry messages refused admission.
    dropped_telemetry: u64,
    /// Protected messages refused admission — the loss this type owes a
    /// report for.
    lost_protected: u64,
    lost_local: u64,
    /// The high-water marks the worker has written a report for.
    ///
    /// They advance only AFTER that write returns `Ok`, which is the correct
    /// order — but **nothing can observe the difference today, and saying
    /// otherwise would be a claim a reader counts on.** A failed write ends
    /// the worker (see `give_up`), so there is no path on which a report is
    /// attempted, fails, and is attempted again. The order is kept because it
    /// is the one that stays correct if a future version retries instead of
    /// giving up; a mutant that advanced them early left the whole suite
    /// green, and that is recorded here rather than papered over with a row
    /// that could not fail.
    reported_telemetry: u64,
    reported_protected: u64,
    reported_local: u64,
    closed: bool,
}

impl Queues {
    fn queued(&self) -> usize {
        self.protected.len() + self.telemetry.len()
    }

    fn unreported(&self) -> (u64, u64, u64) {
        (
            self.dropped_telemetry
                .saturating_sub(self.reported_telemetry),
            self.lost_protected.saturating_sub(self.reported_protected),
            self.lost_local.saturating_sub(self.reported_local),
        )
    }
}

#[derive(Debug)]
struct Shared {
    queues: Mutex<Queues>,
    ready: Condvar,
    /// Set by the worker as its last act, so a closer can tell "drained" from
    /// "still blocked inside `write(2)`" WITHOUT joining the thread.
    finished: Mutex<bool>,
    done: Condvar,
    format: granary_client::LogFormat,
    history: granary_client::BundleHistory,
}

/// How long [`SinkWorker::close`] waits for the drain before giving up on it.
///
/// **IT IS BOUNDED.** Against a destination that never drains, the
/// worker is blocked inside `write(2)` and a join of its thread never
/// returns — so an outright join would make a process closing the
/// sink at exit HANG on exactly the wedged stderr this whole module
/// exists to survive, and a test whose assertion fired would time out
/// instead of failing.
///
/// Bounded best-effort is the contract: what is guaranteed is the EXIT, not
/// the delivery. A record still queued when the bound expires is lost with
/// the detached worker, and that loss is the DESTINATION's — it is delivered
/// the moment the destination drains within the bound.
const CLOSE_BOUND: Duration = Duration::from_millis(500);

/// A handle that produces writers for one destination.
#[derive(Clone, Debug)]
pub(crate) struct Sink {
    shared: Arc<Shared>,
}

/// The worker thread's handle, for a caller that must know the drain finished.
///
/// Production `gran` never joins: the worker lives as long as the process.
/// A test does, which is why `close` exists at all.
#[derive(Debug)]
pub(crate) struct SinkWorker {
    shared: Arc<Shared>,
    joined: AtomicBool,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl SinkWorker {
    #[cfg(test)]
    pub(crate) fn drained(&self) -> bool {
        *self
            .shared
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Stop accepting, drain what is queued, write any outstanding
    /// accounting, and wait for the worker to finish.
    ///
    /// The SHUTDOWN surfaces an outstanding count as well as the drain does,
    /// which is the second half of "accounted even when nothing follows".
    pub(crate) fn close(&mut self) {
        if self.joined.swap(true, Ordering::SeqCst) {
            return;
        }
        {
            let mut q = match self.shared.queues.lock() {
                Ok(q) => q,
                Err(poisoned) => poisoned.into_inner(),
            };
            q.closed = true;
        }
        self.shared.ready.notify_all();
        // Wait for the worker to FINISH, not for its thread to be joinable:
        // a worker blocked inside `write(2)` on a destination nobody drains
        // never becomes joinable, and waiting on that is the hang this bound
        // exists to refuse.
        let finished = {
            let guard = match self.shared.finished.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let (guard, _timeout) =
                match self
                    .shared
                    .done
                    .wait_timeout_while(guard, CLOSE_BOUND, |done| !*done)
                {
                    Ok(pair) => pair,
                    Err(poisoned) => poisoned.into_inner(),
                };
            *guard
        };
        if finished {
            if let Some(handle) = self.handle.take() {
                let _drained = handle.join();
            }
        } else {
            // DETACHED deliberately. The process is exiting; the thread dies
            // with it, and the exit CODE is the outcome record on every path
            // where that matters.
            let _detached = self.handle.take();
        }
    }
}

impl Drop for SinkWorker {
    fn drop(&mut self) {
        self.close();
    }
}

/// Build a sink over `destination` and start its worker.
pub(crate) fn sink_to<E: Write + Send + 'static>(
    destination: crate::logging::Destination<E>,
) -> (Sink, SinkWorker) {
    let format = destination.format();
    let history = destination.history();
    start_with_history(
        destination,
        format,
        crate::logging::Destination::write_stream,
        history,
    )
}

#[cfg(test)]
pub(crate) fn sink_to_writer<W: Write + Send + 'static>(destination: W) -> (Sink, SinkWorker) {
    start(
        destination,
        granary_client::LogFormat::Text,
        |destination, _, bytes| {
            destination.write_all(bytes)?;
            let _best_effort = destination.flush();
            Ok(())
        },
    )
}

#[cfg(test)]
fn start<W: Write + Send + 'static>(
    destination: W,
    format: granary_client::LogFormat,
    drain: fn(&mut W, Stream, &[u8]) -> std::io::Result<()>,
) -> (Sink, SinkWorker) {
    start_with_history(
        destination,
        format,
        drain,
        granary_client::BundleHistory::default(),
    )
}

fn start_with_history<W: Write + Send + 'static>(
    mut destination: W,
    format: granary_client::LogFormat,
    drain: fn(&mut W, Stream, &[u8]) -> std::io::Result<()>,
    history: granary_client::BundleHistory,
) -> (Sink, SinkWorker) {
    let shared = Arc::new(Shared {
        queues: Mutex::new(Queues::default()),
        ready: Condvar::new(),
        finished: Mutex::new(false),
        done: Condvar::new(),
        format,
        history,
    });
    let worker_shared = Arc::clone(&shared);
    // `spawn` PANICS if the OS refuses a thread, and that is deliberate: it
    // happens at process start, before anything is served, and there is no
    // degraded mode worth having — a sink with no worker is a queue that
    // fills once and drops everything after. `granary-server`'s own sink
    // makes the identical choice. This is not a panic reachable from
    // untrusted input.
    // A plain std thread, deliberately outside any runtime: its whole job is
    // to be the ONE place that may block on the destination.
    let handle = std::thread::spawn(move || {
        worker(&worker_shared, &mut destination, drain);
        let mut finished = match worker_shared.finished.lock() {
            Ok(finished) => finished,
            Err(poisoned) => poisoned.into_inner(),
        };
        *finished = true;
        worker_shared.done.notify_all();
    });
    (
        Sink {
            shared: Arc::clone(&shared),
        },
        SinkWorker {
            shared,
            joined: AtomicBool::new(false),
            handle: Some(handle),
        },
    )
}

/// The one thread that touches the destination.
///
/// PROTECTED FIRST, then telemetry, FIFO within each — the scheduling rule,
/// not a convenience. Taking whatever is available lets replenished telemetry
/// defer an admitted protected record without bound.
fn worker<W: Write>(
    shared: &Arc<Shared>,
    destination: &mut W,
    drain: fn(&mut W, Stream, &[u8]) -> std::io::Result<()>,
) {
    loop {
        let (message, accounting, done) = {
            let mut q = match shared.queues.lock() {
                Ok(q) => q,
                Err(poisoned) => poisoned.into_inner(),
            };
            loop {
                if let Some(m) = q.protected.pop_front() {
                    break (Some(m), None, false);
                }
                let (telemetry, protected, local) = q.unreported();
                // >>> THE PROTECTED LOSS REPORT IS SERVED AT PROTECTED
                // PRIORITY, ABOVE TELEMETRY. <<< It IS the protected
                // guarantee, so putting it below the telemetry queue starves
                // it exactly as putting a protected RECORD there would: a
                // producer that keeps telemetry non-empty defers the report
                // without bound *while the destination is draining normally*,
                // which is the mechanism's own loss and is forbidden.
                // `a_protected_loss_report_is_not_starved_by_replenished_telemetry`
                // (`sink/tests.rs`) drives exactly that producer.
                if protected > 0 || local > 0 {
                    break (None, Some((0, protected, local)), false);
                }
                if let Some(m) = q.telemetry.pop_front() {
                    break (Some((Stream::Telemetry, m)), None, false);
                }
                // Telemetry accounting is itself disposable and stays below
                // the telemetry queue: it reports a loss the design ACCEPTS.
                if telemetry > 0 {
                    break (None, Some((telemetry, 0, 0)), false);
                }
                if q.closed {
                    break (None, None, true);
                }
                let guard = match shared.ready.wait(q) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                q = guard;
            }
        };
        if done {
            return;
        }
        if let Some((stream, bytes)) = message {
            // The destination is written to with the lock RELEASED, so a
            // blocked write never stops a producer from being refused
            // quickly and moving on.
            if drain(destination, stream, &bytes).is_err() {
                if stream == Stream::Telemetry {
                    give_up(shared);
                    return;
                }
                // Original standard error failed. It is not the telemetry
                // destination: count the lost record and keep draining.
                lose(shared, stream);
            }
            continue;
        }
        if let Some((telemetry, protected, local)) = accounting {
            let notice = granary_client::OperatorNotice::sink_loss(telemetry, protected, local);
            shared.history.record(notice.bundle_record());
            let line = notice.render(shared.format);
            if drain(destination, Stream::Telemetry, line.as_bytes()).is_err() {
                give_up(shared);
                return;
            }
            // The watermark advances ONLY now, after the write succeeded.
            let mut q = match shared.queues.lock() {
                Ok(q) => q,
                Err(poisoned) => poisoned.into_inner(),
            };
            q.reported_telemetry = q.reported_telemetry.saturating_add(telemetry);
            q.reported_protected = q.reported_protected.saturating_add(protected);
            q.reported_local = q.reported_local.saturating_add(local);
        }
    }
}

/// Count a protected or local record the original standard error refused.
fn lose(shared: &Arc<Shared>, stream: Stream) {
    let mut q = match shared.queues.lock() {
        Ok(q) => q,
        Err(poisoned) => poisoned.into_inner(),
    };
    match stream {
        Stream::Local => q.lost_local = q.lost_local.saturating_add(1),
        Stream::Protected | Stream::Telemetry => {
            q.lost_protected = q.lost_protected.saturating_add(1);
        }
    }
}

/// The destination is gone for good. Mark closed and drain so no producer
/// ever waits on a queue nobody will empty.
fn give_up(shared: &Arc<Shared>) {
    let mut q = match shared.queues.lock() {
        Ok(q) => q,
        Err(poisoned) => poisoned.into_inner(),
    };
    q.closed = true;
    q.protected.clear();
    q.telemetry.clear();
}

impl Sink {
    /// A writer for `stream`. Cheap; make one per call site.
    #[cfg(test)]
    pub(crate) fn writer(&self, stream: Stream) -> SinkWriter {
        self.stream_writer(stream)
    }

    /// Install the typed runtime-report channel on this same worker.
    pub(crate) fn install_local_reports(&self) -> Result<(), std::process::ExitCode> {
        granary_client::install_local_reports(Arc::new(self.clone())).map_err(|_| {
            crate::terminal::write_line(format_args!(
                "gran: local report destination already installed"
            ));
            std::process::ExitCode::FAILURE
        })
    }

    pub(crate) fn protected_writer(&self) -> SinkWriter {
        self.stream_writer(Stream::Protected)
    }

    fn stream_writer(&self, stream: Stream) -> SinkWriter {
        SinkWriter {
            shared: Arc::clone(&self.shared),
            stream,
            pending: Vec::new(),
        }
    }

    /// Admit one complete message, or count its refusal.
    ///
    /// Returns whether it was admitted — the caller in this type ignores it,
    /// because a writer must report `Ok` either way (a writer that returned
    /// an error would make `tracing-subscriber` print to stderr itself, which
    /// is the synchronous write this whole type removes).
    fn submit(&self, stream: Stream, bytes: Vec<u8>) -> bool {
        if bytes.is_empty() {
            return true;
        }
        let admitted = {
            let mut q = match self.shared.queues.lock() {
                Ok(q) => q,
                Err(poisoned) => poisoned.into_inner(),
            };
            if q.closed {
                // A submission AFTER the worker has stopped is counted and
                // can never be reported: the worker is gone, and `close` is
                // single-shot. That is stated rather than hidden. It is the
                // same accepted outcome a terminal write has — what survives
                // a closed sink is the EXIT CODE, which is the outcome record
                // on every path where that matters. A `Drop` that emits one
                // last record during shutdown lands here.
                match stream {
                    Stream::Protected => q.lost_protected = q.lost_protected.saturating_add(1),
                    Stream::Local => q.lost_local = q.lost_local.saturating_add(1),
                    Stream::Telemetry => {
                        q.dropped_telemetry = q.dropped_telemetry.saturating_add(1);
                    }
                }
                false
            } else {
                match stream {
                    // Protected may use the WHOLE queue; telemetry may not
                    // touch the reserve.
                    Stream::Protected | Stream::Local if q.queued() < CAPACITY => {
                        q.protected.push_back((stream, bytes));
                        true
                    }
                    Stream::Telemetry if q.queued() < CAPACITY - PROTECTED_RESERVE => {
                        q.telemetry.push_back(bytes);
                        true
                    }
                    Stream::Protected => {
                        q.lost_protected = q.lost_protected.saturating_add(1);
                        false
                    }
                    Stream::Local => {
                        q.lost_local = q.lost_local.saturating_add(1);
                        false
                    }
                    Stream::Telemetry => {
                        q.dropped_telemetry = q.dropped_telemetry.saturating_add(1);
                        false
                    }
                }
            }
        };
        self.shared.ready.notify_all();
        admitted
    }
}

/// One call site's writer. Every `writeln!` through it is one record.
pub(crate) struct SinkWriter {
    shared: Arc<Shared>,
    stream: Stream,
    pending: Vec<u8>,
}

impl SinkWriter {
    fn sink(&self) -> Sink {
        Sink {
            shared: Arc::clone(&self.shared),
        }
    }

    fn submit_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let bytes = std::mem::take(&mut self.pending);
        let _accounted = self.sink().submit(self.stream, bytes);
    }
}

impl Write for SinkWriter {
    /// A bare `write` has no message boundary, so it ACCUMULATES. Nothing is
    /// queued until `flush` or drop says the message ended.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// **THE WHOLE FORMATTED MESSAGE, AS ONE RECORD, WITHOUT A FLUSH.**
    ///
    /// This is what `writeln!` calls. Overriding it is what makes a record a
    /// MESSAGE rather than a `write` call, and what lets a startup notice
    /// reach the destination without the writer being flushed or dropped —
    /// the CLI's sink local spans the daemon, so a writer that submitted on
    /// drop would hold that notice for the life of the mount.
    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        // Any bytes a bare `write` left pending belong to an earlier message;
        // they go first, as their own record.
        self.submit_pending();
        let mut message = Vec::new();
        // Formatting into a `Vec` cannot fail for any `Display` this crate
        // writes, and a formatting error must not become a destination error.
        let _formatted = std::io::Write::write_all(&mut message, format!("{args}").as_bytes());
        let _accounted = self.sink().submit(self.stream, message);
        Ok(())
    }

    /// Ends the current message. **Never an error**, whatever the queue did:
    /// `tracing-subscriber` writes to stderr ITSELF when the configured
    /// writer returns one, which would reintroduce the synchronous write on
    /// exactly the path this type exists to remove it from.
    fn flush(&mut self) -> std::io::Result<()> {
        self.submit_pending();
        Ok(())
    }
}

impl Drop for SinkWriter {
    fn drop(&mut self) {
        self.submit_pending();
    }
}

/// Telemetry admission accepts only the opaque scalar projection.
impl granary_client::RecordWriter for Sink {
    fn write_record(&self, record: &granary_client::LogRecord) {
        let _admitted = self.submit(Stream::Telemetry, record.as_bytes().to_vec());
    }
}

#[cfg(test)]
mod tests;

impl std::fmt::Debug for Queues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<queues>")
    }
}
impl std::fmt::Debug for SinkWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<sink-writer>")
    }
}
impl granary_client::LocalRecordWriter for Sink {
    fn write_local(&self, record: &granary_client::LocalRecord) {
        let _admitted = self.submit(Stream::Local, record.as_bytes().to_vec());
    }
}
impl granary_client::LocalReporter for SinkWriter {
    fn report(&mut self, report: &granary_client::LocalReport) {
        self.submit_pending();
        granary_client::LocalRecordWriter::write_local(&self.sink(), &report.render());
    }
}
