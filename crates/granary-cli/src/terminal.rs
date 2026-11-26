// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Direct terminal diagnostics, independent of the telemetry and protected queues.

use std::fmt;
use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

/// Match the sink's shutdown allowance: enough for an ordinary stderr drain,
/// without letting a stalled destination hold process termination indefinitely.
const WRITE_BOUND: Duration = Duration::from_millis(500);

/// Write a terminal diagnostic to stderr, including its trailing newline.
pub(crate) fn write_line(message: fmt::Arguments<'_>) {
    write_line_to(std::io::stderr(), message, WRITE_BOUND);
}

/// Attempt a complete diagnostic directly, waiting at most `bound` for its I/O.
///
/// A dedicated thread owns the destination and performs both the write and flush;
/// the caller waits on completion, never queue admission. On timeout the worker
/// is detached, so exit can proceed even if stderr's lock or write blocks forever.
/// Missing or partial output is an accepted outcome when the destination cannot
/// drain within the bound. Write errors and failure to start a worker also lose
/// the diagnostic; none may change the caller's exit code or trigger a panic.
/// No join follows the timeout.
pub(crate) fn write_line_to<W: Write + Send + 'static>(
    mut destination: W,
    message: fmt::Arguments<'_>,
    bound: Duration,
) {
    let bytes = format!("{message}\n").into_bytes();
    let (done, finished) = mpsc::channel();
    // Builder returns an error instead of panicking if a thread cannot start,
    // which also makes this usable from inside the process's panic hook.
    if std::thread::Builder::new()
        .spawn(move || {
            let _ = destination
                .write_all(&bytes)
                .and_then(|()| destination.flush());
            let _ = done.send(());
        })
        .is_ok()
    {
        let _ = finished.recv_timeout(bound);
    }
}

/// Replace the synchronous default hook before startup can hold any senders.
/// Returning leaves Rust's configured unwind/abort behavior and exit status intact.
pub(crate) fn install_panic_hook() {
    std::panic::set_hook(panic_hook(write_line));
}

/// The hook `install_panic_hook` installs, with its reporter as a parameter so a
/// test can install the real closure and observe what a panic reports.
pub(crate) fn panic_hook(
    report: fn(fmt::Arguments<'_>),
) -> Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static> {
    Box::new(move |_| report_panic(report))
}

/// Report only the failure class. The hook takes no panic input: payloads,
/// thread names, locations and backtraces can carry operator data.
/// The reporter remains injectable to verify bounded delivery before unwinding.
pub(crate) fn report_panic(report: impl FnOnce(fmt::Arguments<'_>)) {
    report(format_args!("gran: panic: internal failure"));
}

#[cfg(test)]
mod tests;
