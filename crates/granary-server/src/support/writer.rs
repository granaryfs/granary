// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Periodic disk sampling, independent of request traffic and serving progress.
use super::{SupportConfiguration, SupportError, SupportSnapshot, snapshot_from_observation};
use crate::{
    GrainService,
    authority::Observation,
    protected_dir::{DirOps, NixOps},
    protected_replace::{self, Stages},
};
use granary_core::{clock::Clock, sheaf::Timestamp};
use std::{
    future::{Future, pending},
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    thread::JoinHandle,
    time::Duration,
};
use tokio::sync::watch;

/// Fixed sampling interval, with no deployment override: 60 seconds.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the sampling contract is expressed in seconds"
)]
pub const SUPPORT_INTERVAL: Duration = Duration::from_secs(60);
const STAGES: Stages = Stages {
    lock: "support lock",
    cleanup: "support cleanup",
    create: "support create",
    chown: "support owner",
    chmod: "support mode",
    write: "support write",
    file_sync: "support file sync",
    rename: "support rename",
    dir_sync: "support directory sync",
    parent_sync: "support parent sync",
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Configuration,
    Snapshot,
}
impl Kind {
    fn names(self) -> (&'static str, &'static str) {
        match self {
            Self::Configuration => ("SUPPORT-CONFIGURATION.tmp", "SUPPORT-CONFIGURATION"),
            Self::Snapshot => ("SUPPORT-SNAPSHOT.tmp", "SUPPORT-SNAPSHOT"),
        }
    }
}
trait Flight: Send {
    fn finished(&self) -> bool;
}
impl Flight for JoinHandle<()> {
    fn finished(&self) -> bool {
        self.is_finished()
    }
}
trait Work {
    fn launch(&self, kind: Kind, earliest: Timestamp) -> io::Result<Box<dyn Flight>>;
}
trait Wait: Send + Sync {
    fn wait(&self, gap: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
struct TimerWait;
impl Wait for TimerWait {
    fn wait(&self, gap: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        // This ticker has its own seam: authority pacing permits sleep, but
        // disk sampling uses a timeout around pending and rechecks the Clock.
        Box::pin(async move {
            let _elapsed = tokio::time::timeout(gap, pending::<()>()).await;
        })
    }
}
fn after_interval(now: Timestamp) -> Option<Timestamp> {
    now.is_valid()
        .then_some(now)?
        .secs
        .checked_add(i64::try_from(SUPPORT_INTERVAL.as_secs()).ok()?)
        .map(|secs| Timestamp {
            secs,
            nanos: now.nanos,
        })
}
fn gap(now: Timestamp, due: Timestamp) -> Duration {
    if !now.is_valid() {
        return SUPPORT_INTERVAL;
    }
    let nanos = (i128::from(due.secs) - i128::from(now.secs)) * 1_000_000_000
        + i128::from(due.nanos)
        - i128::from(now.nanos);
    let nanos = u64::try_from(nanos).unwrap_or(if nanos < 0 { 0 } else { u64::MAX });
    Duration::from_nanos(nanos).min(SUPPORT_INTERVAL)
}
struct Ticker<W> {
    work: W,
    clock: Arc<dyn Clock>,
    due: Option<Timestamp>,
    flight: Option<Box<dyn Flight>>,
    started: bool,
}
impl<W: Work> Ticker<W> {
    fn new(work: W, clock: Arc<dyn Clock>) -> Self {
        let due = after_interval(clock.now());
        if due.is_none() {
            tracing::warn!("support sampling clock cannot schedule");
        }
        Self {
            work,
            clock,
            due,
            flight: None,
            started: false,
        }
    }
    fn start(&mut self) {
        if !self.started {
            self.started = true;
            self.submit(Kind::Configuration, self.clock.now());
        }
    }
    fn submit(&mut self, kind: Kind, earliest: Timestamp) {
        if self
            .flight
            .as_ref()
            .is_some_and(|flight| !flight.finished())
        {
            return;
        }
        self.flight = None; // Dropping a thread handle detaches; it never joins.
        match self.work.launch(kind, earliest) {
            Ok(flight) => self.flight = Some(flight),
            Err(error) => {
                tracing::warn!(error = %error, "support writer could not start its blocking job");
            }
        }
    }
    fn tick(&mut self) {
        let now = self.clock.now();
        let Some(due) = self.due else {
            return;
        };
        if !now.is_valid() || now < due {
            return;
        }
        self.due = after_interval(now); // Late wakes schedule once, without catch-up.
        self.submit(Kind::Snapshot, now);
    }
    async fn run(mut self, wait: &impl Wait, mut shutdown: watch::Receiver<bool>) {
        if *shutdown.borrow() {
            return;
        }
        self.start();
        loop {
            let delay = self
                .due
                .map_or(SUPPORT_INTERVAL, |due| gap(self.clock.now(), due));
            let event = {
                let mut changed = std::pin::pin!(shutdown.changed());
                let mut waited = wait.wait(delay);
                std::future::poll_fn(|cx| {
                    // Shutdown has fixed precedence; no random branch ordering.
                    if let std::task::Poll::Ready(result) = changed.as_mut().poll(cx) {
                        return std::task::Poll::Ready(result.map(|()| false));
                    }
                    if waited.as_mut().poll(cx).is_ready() {
                        return std::task::Poll::Ready(Ok(true));
                    }
                    std::task::Poll::Pending
                })
                .await
            };
            if event.is_err() || *shutdown.borrow() {
                return;
            }
            if event.unwrap_or(false) {
                self.tick();
            }
        }
    }
}
struct Publisher {
    path: PathBuf,
    accept: bool,
    configuration: SupportConfiguration,
    clock: Arc<dyn Clock>,
    cached: Arc<dyn Fn() -> Option<Observation> + Send + Sync>,
}
impl Work for Arc<Publisher> {
    fn launch(&self, kind: Kind, earliest: Timestamp) -> io::Result<Box<dyn Flight>> {
        let publisher = Arc::clone(self);
        // A dedicated thread keeps flock, copying, encoding and sync off the
        // runtime. Its handle covers the entire job and is never joined.
        std::thread::Builder::new()
            .name("support-writer".into())
            .spawn(move || {
                if let Err(error) = publisher.publish(&NixOps, kind, earliest) {
                    tracing::warn!(reason = error.0, "support writer publication refused");
                }
            })
            .map(|handle| Box::new(handle) as Box<dyn Flight>)
    }
}
impl Publisher {
    fn publish(
        &self,
        ops: &impl DirOps,
        kind: Kind,
        earliest: Timestamp,
    ) -> Result<(), SupportError> {
        let (directory, _held) =
            protected_replace::locked_server(ops, &self.path, self.accept, &STAGES)
                .map_err(|_| SupportError("support directory refused"))?;
        let bytes = match kind {
            Kind::Configuration => {
                let bytes = self.configuration.encode()?;
                verify_configuration(&self.configuration, &bytes)?;
                bytes
            }
            Kind::Snapshot => {
                let sampled_at = self.clock.now();
                if !sampled_at.is_valid() || sampled_at < earliest {
                    return Err(SupportError("support clock regressed"));
                }
                let observation =
                    (self.cached)().ok_or(SupportError("support observation missing"))?;
                let snapshot = snapshot_from_observation(
                    self.configuration.incarnation,
                    sampled_at,
                    &observation,
                )?;
                drop(observation); // No observation guard survives file publication.
                let bytes = snapshot.encode()?;
                verify_snapshot(&snapshot, &bytes)?;
                bytes
            }
        };
        let missing = protected_replace::prepare(ops, &directory, kind.names(), &STAGES)
            .map_err(|_| SupportError("support name refused"))?;
        protected_replace::publish(ops, &directory, kind.names(), &bytes, missing, &STAGES).map_err(
            |error| match error {
                protected_replace::ReplaceError::Io { .. } => {
                    SupportError("support publication uncertain")
                }
                protected_replace::ReplaceError::Directory(_)
                | protected_replace::ReplaceError::Unwritten { .. } => {
                    SupportError("support publication failed")
                }
            },
        )
    }
}
fn verify_configuration(expected: &SupportConfiguration, bytes: &[u8]) -> Result<(), SupportError> {
    if SupportConfiguration::decode(bytes)? != *expected {
        return Err(SupportError("support self check"));
    }
    Ok(())
}
fn verify_snapshot(expected: &SupportSnapshot, bytes: &[u8]) -> Result<(), SupportError> {
    if SupportSnapshot::decode(bytes)? != *expected {
        return Err(SupportError("support self check"));
    }
    Ok(())
}
/// Owns the once-only projection and a single detached blocking flight.
pub struct SupportWriter {
    ticker: Ticker<Arc<Publisher>>,
}
impl std::fmt::Debug for SupportWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupportWriter").finish_non_exhaustive()
    }
}
impl SupportWriter {
    /// Retain the completed allowlist and a cached service observation source.
    #[must_use]
    pub fn new<R: Send + Sync + 'static>(
        path: &Path,
        accept: bool,
        configuration: SupportConfiguration,
        clock: Arc<dyn Clock>,
        service: GrainService<R>,
    ) -> Self {
        let publisher = Arc::new(Publisher {
            path: path.to_path_buf(),
            accept,
            configuration,
            clock: clock.clone(),
            cached: Arc::new(move || service.observation()),
        });
        Self {
            ticker: Ticker::new(publisher, clock),
        }
    }
    /// Poll alongside serving; filesystem failures leave serving active.
    /// # Cancellation safety
    /// Dropping this future stops scheduling and detaches any blocking job.
    /// Shutdown never joins or flushes and does not extend the host budget.
    pub async fn run(self, shutdown: watch::Receiver<bool>) {
        self.ticker.run(&TimerWait, shutdown).await;
    }
}
#[cfg(test)]
mod tests;

#[cfg(test)]
impl SupportWriter {
    pub(crate) fn start_for_test(&mut self) {
        self.ticker.start();
    }
    pub(crate) fn tick_for_test(&mut self) {
        self.ticker.tick();
    }
    pub(crate) fn in_flight_for_test(&self) -> bool {
        self.ticker
            .flight
            .as_ref()
            .is_some_and(|flight| !flight.finished())
    }
    pub(crate) fn publish_configuration_for_test(
        &self,
        ops: &impl DirOps,
    ) -> Result<(), SupportError> {
        self.ticker
            .work
            .publish(ops, Kind::Configuration, self.ticker.clock.now())
    }
    pub(crate) fn publish_for_test(&self, ops: &impl DirOps) -> Result<(), SupportError> {
        self.ticker
            .work
            .publish(ops, Kind::Snapshot, self.ticker.clock.now())
    }
}
