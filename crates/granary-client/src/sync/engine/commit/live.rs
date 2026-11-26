// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The bound writable mount's commit driver and retry schedules.

use super::{CommitDrive, RuntimeSeams, commit_send_budget, driver::Waited, projected::Resumed};
use crate::sync::engine::{
    Clock, CoordinationError, MonotonicClock, OverlayIo, RuntimeRng, SyncContent, SyncEngine,
    SyncOptions, SyncRemote, SyncRuntime, failure_class,
};
use crate::writable_store::sync_engine::LiveAdmission;
use crate::{
    AuthorityTransport, BackoffCause, BackoffOutcome, CommitStopCause, OverlayError,
    PublicationOutcome, RecoveryIntent,
};
use granary_core::{rng::Rng, secure_random::SecureRandom};
use std::{future::Future as _, sync::Arc, time::Duration};

const OUTAGE_BASES_MS: [u64; 12] = [
    1_000, 1_600, 2_560, 4_096, 6_554, 10_486, 16_777, 26_844, 42_950, 68_719, 109_951, 120_000,
];
const OUTAGE_CAP_MS: u64 = 120_000;

/// Why the live driver ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveEnd {
    /// Shutdown closed user mutations.
    Latched,
    /// The writable store is fenced or poisoned.
    Fenced,
    /// The mount's served view is closed.
    Closed,
}

impl From<LiveEnd> for Option<CommitStopCause> {
    fn from(end: LiveEnd) -> Self {
        match end {
            LiveEnd::Latched => None,
            LiveEnd::Fenced => Some(CommitStopCause::Fenced),
            LiveEnd::Closed => Some(CommitStopCause::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Events {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Events {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
    impl Events {
        fn subscriber(&self) -> Box<dyn tracing::Subscriber + Send + Sync> {
            crate::subscriber(
                crate::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                self.clone(),
            )
        }
        fn backoffs(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .filter(|line| line.contains("\"event\":\"commit.backoff\""))
                .map(str::to_owned)
                .collect()
        }
    }

    #[test]
    fn live_driver_slows_after_eight_refusals_and_keeps_driving() {
        let events = Events::default();
        let mut schedule = Schedule::default();
        let mut rng = granary_core::rng::SeededRng::new(2);
        let first: Vec<_> = tracing::subscriber::with_default(events.subscriber(), || {
            (0..10).map(|_| schedule.stall(&mut rng).0).collect()
        });
        assert_eq!(
            first
                .iter()
                .map(|pause| pause.base.as_millis())
                .collect::<Vec<_>>(),
            vec![
                40, 80, 160, 320, 640, 1_280, 2_560, 600_000, 600_000, 600_000
            ],
            "seven fast pauses followed by three slow passes"
        );
        for pause in &first[7..] {
            let low = Duration::from_mins(8);
            let high = Duration::from_mins(12);
            assert!(
                (low..=high).contains(&pause.drawn),
                "slow draw {:?} is outside ±20% of 600000 ms",
                pause.drawn
            );
        }
        schedule.answered();
        let still_slow = schedule.stall(&mut rng).0.base;
        schedule.landed();
        let reset = schedule.stall(&mut rng).0.base;
        assert_eq!(
            (still_slow, reset),
            (Duration::from_mins(10), Duration::from_millis(40)),
            "an authority answer does not reset a refused streak; a landing does"
        );
        assert_eq!(
            events.backoffs().len(),
            1,
            "one stall transition is emitted for the episode, not one per pass"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Woken {
    Latched,
    Fenced,
    Answered,
    LaneEnded { landed: bool, answered: bool },
    Elapsed { answered: bool },
}

enum Verdict {
    Stop(LiveEnd),
    Retry(Pause),
}

#[derive(Debug, Clone, Copy)]
struct Pause {
    base: Duration,
    drawn: Duration,
    interrupt_after: Option<Duration>,
}

#[derive(Default)]
struct Schedule {
    outage_step: usize,
    refused_streak: u32,
    outage_attempts: Option<u64>,
    stall_attempts: Option<u64>,
}

impl Schedule {
    fn outage(&mut self, rng: &mut impl Rng) -> Pause {
        if self.outage_attempts.is_none() {
            crate::observe::commit_backoff(BackoffCause::Outage, BackoffOutcome::Entered);
        }
        *self.outage_attempts.get_or_insert(0) += 1;
        let base_ms = OUTAGE_BASES_MS
            .get(self.outage_step)
            .copied()
            .unwrap_or(OUTAGE_CAP_MS);
        self.outage_step = self.outage_step.saturating_add(1);
        Pause {
            base: Duration::from_millis(base_ms),
            drawn: Duration::from_millis(base_ms * (800 + rng.below(401)) / 1_000),
            interrupt_after: Some(Duration::from_secs(1)),
        }
    }

    fn stall(&mut self, rng: &mut impl Rng) -> (Pause, bool) {
        self.refused_streak += 1;
        let entered = self.refused_streak == crate::STARTUP_ATTEMPTS;
        if entered {
            self.stall_attempts = Some(u64::from(self.refused_streak));
            crate::observe::commit_backoff(BackoffCause::Stall, BackoffOutcome::Entered);
        } else if let Some(attempts) = &mut self.stall_attempts {
            *attempts += 1;
        }
        let base = if self.refused_streak >= crate::STARTUP_ATTEMPTS {
            crate::writable_store::CAPACITY_RETRY_DELAY
        } else {
            Duration::from_millis(super::startup_retry_ceiling(self.refused_streak - 1))
        };
        let drawn = if self.refused_streak >= crate::STARTUP_ATTEMPTS {
            let base_ms = base.as_secs() * 1_000;
            Duration::from_millis(base_ms * (800 + rng.below(401)) / 1_000)
        } else {
            Duration::from_millis(
                rng.below(super::startup_retry_ceiling(self.refused_streak - 1) + 1),
            )
        };
        (
            Pause {
                base,
                drawn,
                interrupt_after: None,
            },
            entered,
        )
    }

    fn answered(&mut self) {
        self.outage_step = 0;
    }

    fn landed(&mut self) {
        if let Some(attempts) = self.outage_attempts.take() {
            crate::observe::commit_backoff(
                BackoffCause::Outage,
                BackoffOutcome::Recovered { attempts },
            );
        }
        if let Some(attempts) = self.stall_attempts.take() {
            crate::observe::commit_backoff(
                BackoffCause::Stall,
                BackoffOutcome::Recovered { attempts },
            );
        }
        self.outage_step = 0;
        self.refused_streak = 0;
    }
}

impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + AuthorityTransport + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    /// Drive commits for a bound writable mount until shutdown, a fence, or a
    /// closed view ends the loop.
    #[expect(
        clippy::too_many_lines,
        reason = "takeover, construction and retry scheduling remain in one live-driver loop"
    )]
    pub async fn drive_live(
        self: Arc<Self>,
        options: SyncOptions,
        mut secure: impl SecureRandom + Send + 'static,
    ) -> LiveEnd {
        // A submission hold is too late: constructing that lane can block
        // the mounted fsyncs whose acknowledgements precede a disk-loss cut.
        #[cfg(feature = "overlay-fault-tests")]
        if self.faults.armed_at("sync.commit_wait", "background")
            && self
                .fault("sync.commit_wait", "background", 0, None, "none")
                .await
                .is_err()
        {
            return LiveEnd::Closed;
        }
        let mut schedule = Schedule::default();
        loop {
            #[cfg(test)]
            if let Some(hook) = self
                .before_live_drive
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                hook();
            }
            let drive_options = background_options(options);
            let step = match self.deadline(drive_options) {
                Ok(deadline) => {
                    match self
                        .take_over_latched(drive_options, deadline, &mut secure)
                        .await
                    {
                        Ok(Resumed::Open) => None,
                        Ok(Resumed::Ended { landed }) => {
                            if landed {
                                schedule.landed();
                            }
                            None
                        }
                        Ok(Resumed::Latched) => break LiveEnd::Latched,
                        Err(error) => Some(error),
                    }
                }
                Err(error) => Some(error),
            };
            let step = if let Some(error) = step {
                Some(error)
            } else {
                match self.live_wait(options).await {
                    Ok(Waited::Latched) => break LiveEnd::Latched,
                    Ok(Waited::LaneRetained) => continue,
                    Ok(Waited::Construct) => {
                        // A retry may act only on answers newer than this construction.
                        self.take_answered();
                        #[cfg(any(test, feature = "overlay-fault-tests"))]
                        self.live_constructions
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        match self.construct_latched(options, &mut secure).await {
                            Ok(lane) => {
                                #[cfg(test)]
                                if let Some(hook) = self
                                    .before_live_commit_drive
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .take()
                                {
                                    hook();
                                }
                                let mut delay = RuntimeSeams(self.runtime.as_ref());
                                let result = match self.deadline(drive_options) {
                                    Ok(deadline) => {
                                        Box::pin(self.drive_commit_for(
                                            &lane.with_deadline(deadline),
                                            &mut secure,
                                            &mut delay,
                                            CommitDrive::Background(RecoveryIntent::Continue),
                                            SyncOptions {
                                                deadline: Some(deadline),
                                                ..drive_options
                                            },
                                        ))
                                        .await
                                    }
                                    Err(error) => Err(error),
                                };
                                match result {
                                    Ok(result)
                                        if matches!(
                                            result.outcome,
                                            PublicationOutcome::Landed(_)
                                        ) =>
                                    {
                                        schedule.landed();
                                        continue;
                                    }
                                    Ok(result) => result.admission_error(),
                                    Err(CoordinationError::Refused("SyncCommitInFlight")) => {
                                        continue;
                                    }
                                    Err(error) => Some(error),
                                }
                            }
                            Err(CoordinationError::Overlay(OverlayError::MutationsClosed)) => {
                                break LiveEnd::Latched;
                            }
                            Err(CoordinationError::Refused("SyncCommitInFlight")) => continue,
                            Err(error) => Some(error),
                        }
                    }
                    Err(error) => Some(error),
                }
            };
            let Some(error) = step else { continue };
            let pause = match self.live_verdict(&error, &mut schedule) {
                Verdict::Stop(end) => break end,
                Verdict::Retry(pause) => pause,
            };
            match self.retry_wait(pause).await {
                Woken::Latched => break LiveEnd::Latched,
                Woken::Fenced => break LiveEnd::Fenced,
                Woken::Answered => schedule.answered(),
                Woken::LaneEnded { landed, answered } => {
                    if landed {
                        schedule.landed();
                    } else if answered {
                        schedule.answered();
                    }
                }
                Woken::Elapsed { answered } => {
                    if answered {
                        schedule.answered();
                    }
                }
            }
        }
    }

    /// Report a live-loop end unless shutdown already owns the store.
    pub(crate) fn report_live_end(&self, end: LiveEnd) {
        let Some(cause) = Option::from(end) else {
            return;
        };
        // A loop that ended after shutdown closed the store is part of that
        // shutdown, whatever stopped it; an unreadable store is not closed.
        if matches!(self.local(|local| Ok(local.mutations_closed())), Ok(true)) {
            return;
        }
        crate::observe::commit_stopped(cause);
        crate::LocalReport::commit_stopped(&self.volume, cause).emit();
    }

    #[cfg(test)]
    pub(crate) fn live_refusal_pause_for_test(
        &self,
        error: &CoordinationError,
    ) -> Option<Duration> {
        match self.live_verdict(error, &mut Schedule::default()) {
            Verdict::Retry(pause) => Some(pause.base),
            Verdict::Stop(_) => None,
        }
    }

    fn live_verdict(&self, error: &CoordinationError, schedule: &mut Schedule) -> Verdict {
        if matches!(
            error,
            CoordinationError::Fenced { .. }
                | CoordinationError::CommitFenced { .. }
                | CoordinationError::Refused("IntentPersistencePoisoned")
                | CoordinationError::Overlay(OverlayError::Poisoned)
        ) {
            return Verdict::Stop(LiveEnd::Fenced);
        }
        if matches!(
            error,
            CoordinationError::Overlay(OverlayError::MutationsClosed)
        ) {
            return Verdict::Stop(LiveEnd::Latched);
        }
        if matches!(error, CoordinationError::Refused("ViewPending"))
            || matches!(error, CoordinationError::Refused("ViewAdapterLost"))
        {
            return Verdict::Stop(LiveEnd::Closed);
        }
        let mut rng = RuntimeRng(self.runtime.as_ref());
        let mut pause = if failure_class(error) == crate::FailureClass::Unavailable {
            schedule.outage(&mut rng)
        } else {
            let (pause, entered) = schedule.stall(&mut rng);
            if entered && let Ok(volume) = self.local(|local| Ok(local.snapshot().volume.clone())) {
                crate::LocalReport::commit_stalled(&volume).emit();
            }
            pause
        };
        if matches!(
            error,
            CoordinationError::Refused("SyncWorkspaceExhausted")
                | CoordinationError::Overlay(
                    OverlayError::NoSpace | OverlayError::Refused("OverlayCapacityExhausted")
                )
        ) && self
            .local(|local| local.sync_admission_open())
            .unwrap_or(false)
        {
            let recorded = self
                .local(|local| Ok(local.note_capacity_refusal(error)))
                .unwrap_or(false);
            // Only a recorded refusal leaves the wait to the coalescer and
            // its room/floor wakes; otherwise keep the ordinary stall pause.
            if recorded {
                pause.drawn = Duration::ZERO;
            }
        }
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        self.live_pauses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((pause.base, pause.drawn));
        #[cfg(not(any(test, feature = "overlay-fault-tests")))]
        let _ = pause.base;
        Verdict::Retry(pause)
    }

    async fn retry_wait(&self, pause: Pause) -> Woken {
        let started = self.runtime.now();
        let Some(deadline) = started.checked_add(pause.drawn) else {
            return Woken::Elapsed { answered: false };
        };
        let interrupt_at = pause
            .interrupt_after
            .and_then(|minimum| started.checked_add(minimum));
        let mut first_landings = None;
        let mut held_serial = None;
        let mut answered = false;
        loop {
            let wake = self.floor_changed.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            answered |= self.take_answered();
            let Ok(admission) = self.local(|local| local.live_admission()) else {
                return Woken::Fenced;
            };
            let (landings, serial) = match admission {
                LiveAdmission::Latched => return Woken::Latched,
                LiveAdmission::Held { serial, landings } => (landings, Some(serial)),
                LiveAdmission::Open { landings } => (landings, None),
            };
            if let Some(initial) = first_landings {
                if landings > initial {
                    return Woken::LaneEnded {
                        landed: true,
                        answered,
                    };
                }
            } else {
                first_landings = Some(landings);
            }
            match serial {
                Some(serial) => {
                    if held_serial.is_some_and(|held| held != serial) {
                        return Woken::LaneEnded {
                            landed: false,
                            answered,
                        };
                    }
                    held_serial = Some(serial);
                }
                None if held_serial.is_some() => {
                    return Woken::LaneEnded {
                        landed: false,
                        answered,
                    };
                }
                None => {}
            }
            #[cfg(test)]
            if let Some(hook) = self
                .after_live_retry_read
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                hook();
            }
            let now = self.runtime.now();
            if answered && interrupt_at.is_some_and(|minimum| now >= minimum) {
                return Woken::Answered;
            }
            let wait_until = if answered {
                interrupt_at.unwrap_or(deadline)
            } else {
                deadline
            };
            let mut timer = std::pin::pin!(
                self.runtime
                    .timeout_at(wait_until, std::future::pending::<()>())
            );
            let elapsed = std::future::poll_fn(|cx| {
                if wake.as_mut().poll(cx).is_ready() {
                    std::task::Poll::Ready(false)
                } else if self.runtime.now() >= wait_until || timer.as_mut().poll(cx).is_ready() {
                    std::task::Poll::Ready(true)
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            if elapsed {
                return if answered && interrupt_at.is_some() {
                    Woken::Answered
                } else {
                    Woken::Elapsed { answered }
                };
            }
        }
    }
}

fn background_options(mut options: SyncOptions) -> SyncOptions {
    if options.resolution_bound == crate::DEFAULT_RESOLUTION_BOUND {
        options.resolution_bound = commit_send_budget();
    }
    options
}
