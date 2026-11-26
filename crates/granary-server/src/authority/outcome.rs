// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How a server running the authority ends: its exit code, decided once,
//! as a pure function of what the host observed by then.
//!
//! The host's shutdown budget starts once, on the first shutdown cause: a
//! signal, a failure after the marker admitted the start (a volume the
//! start refused, or a bind or service construction failing after it), the
//! fence's notification, the serving ending on its own, or the driver
//! ending unasked (`crate::host`). The HTTP drain and the engine's stop run
//! under that one budget. When both have finished, or the budget expires,
//! the host gathers what it saw into a [`ShutdownObserved`] and exits with
//! [`shutdown_exit_code`]'s answer, in this order of precedence:
//!
//! 1. **A fence, from any cause, is [`EXIT_FENCED`]**, whatever else
//!    happened: a fence observed together with an expired budget is still
//!    a fence. The host learns of it from the fence's notification, not
//!    from the run's end. A hung write that never returned is not a fence.
//! 2. **Otherwise an expired budget is [`EXIT_DEADLINE_EXPIRED`]**.
//! 3. **Otherwise a stop that returned [`RunEnd::Stopped`] together with
//!    a finished HTTP drain is [`EXIT_DRAINED`]**, or
//!    [`EXIT_STARTUP_FAILED`] when the shutdown's cause was a failure
//!    after the start was admitted: the engine wrote **clean**, and the
//!    server still never served.
//! 4. **Anything else is [`EXIT_SERVE_FAILED`]**: a run abandoned, a
//!    driver that ended unasked, or a stop or drain that had not finished.
//!    Never [`EXIT_DRAINED`].
//!
//! [`RunEnd::Stopped`]: super::RunEnd::Stopped

use crate::serve::{
    EXIT_DEADLINE_EXPIRED, EXIT_DRAINED, EXIT_FENCED, EXIT_SERVE_FAILED, EXIT_STARTUP_FAILED,
};

/// What began the shutdown: the first cause the host observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownCause {
    /// A shutdown signal, or any other cause that is not a failure after
    /// admission: the fence's notification (which then decides the code),
    /// the serving ending on its own (its drain not finished), or the
    /// driver ending unasked (whose stop result
    /// [`StopObserved::DriverEndedUnexpectedly`] then decides the code).
    Signal,
    /// A failure after the marker admitted the start: a volume the start
    /// refused, or a bind or service construction failing after it.
    StartupFailedAfterAdmission,
}

/// What the engine's stop came to, as the host saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopObserved {
    /// The stop has not answered.
    Pending,
    /// The stop answered [`super::RunEnd::Stopped`]: every worker stopped
    /// and **clean** is durable.
    Stopped,
    /// The stop answered [`super::RunEnd::Abandoned`]: the driver was
    /// dropped before its run finished.
    Abandoned,
    /// The driver ended without being asked to stop.
    DriverEndedUnexpectedly,
}

/// Everything the exit code depends on (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownObserved {
    /// The fence's notification was observed. A stop that answered
    /// [`super::RunEnd::Fenced`] counts as observing it.
    pub fenced: bool,
    /// The shutdown budget expired before the stop and the drain both
    /// finished.
    pub budget_expired: bool,
    /// What the engine's stop came to.
    pub stop: StopObserved,
    /// The HTTP drain finished.
    pub drained: bool,
    /// What began the shutdown.
    pub cause: ShutdownCause,
}

/// The exit code for `observed` (module docs' precedence).
#[must_use]
pub const fn shutdown_exit_code(observed: &ShutdownObserved) -> i32 {
    if observed.fenced {
        return EXIT_FENCED;
    }
    if observed.budget_expired {
        return EXIT_DEADLINE_EXPIRED;
    }
    match (observed.stop, observed.drained, observed.cause) {
        (StopObserved::Stopped, true, ShutdownCause::Signal) => EXIT_DRAINED,
        (StopObserved::Stopped, true, ShutdownCause::StartupFailedAfterAdmission) => {
            EXIT_STARTUP_FAILED
        }
        _ => EXIT_SERVE_FAILED,
    }
}

#[cfg(test)]
mod tests;
