// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared grant time and permanent failure. The elapsed-time high-water mark
//! makes injected clock rollback harmless. Linux projects startup UTC through
//! `CLOCK_BOOTTIME`, including suspend. Failed observations keep their last valid
//! timestamp for expiry evidence, but never authorize activation or capture.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use granary_core::clock::Clock;
use granary_core::sheaf::Timestamp;

/// An observable, permanent refusal of the grant clock profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockFailure {
    #[cfg_attr(
        all(target_os = "linux", not(test)),
        expect(
            dead_code,
            reason = "unsupported production profiles are reported on other operating systems"
        )
    )]
    UnsupportedProfile,
    Source,
    Overflow,
}

impl ClockFailure {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedProfile => "unsupported-clock-profile",
            Self::Source => "clock-source-failure",
            Self::Overflow => "clock-overflow",
        }
    }
}

pub(super) trait Source: Send + Sync {
    fn read(&self) -> Result<Timestamp, ClockFailure>;
}

struct Injected(Arc<dyn Clock>);
impl Source for Injected {
    fn read(&self) -> Result<Timestamp, ClockFailure> {
        Ok(self.0.now())
    }
}

#[derive(Debug, Default)]
struct Reading {
    last: Option<Timestamp>,
    failure: Option<ClockFailure>,
}

struct Inner {
    source: Box<dyn Source>,
    reading: Mutex<Reading>,
    high_water: TimeHighWater,
}

/// A clone shares both time history and the permanent failure latch. Callers
/// read time, observe expiry, then check failure before granting admission.
#[derive(Clone)]
pub(crate) struct GrantClock(Arc<Inner>);

impl std::fmt::Debug for GrantClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantClock")
            .field("reading", &self.0.reading)
            .finish_non_exhaustive()
    }
}

impl GrantClock {
    pub(crate) fn injected(clock: Arc<dyn Clock>) -> Self {
        Self::from_source(Box::new(Injected(clock)))
    }

    pub(super) fn from_source(source: Box<dyn Source>) -> Self {
        Self(Arc::new(Inner {
            source,
            reading: Mutex::new(Reading::default()),
            high_water: TimeHighWater::default(),
        }))
    }

    /// Startup performs the fallible kernel observations through the clock seam.
    /// An unsupported or failed profile remains observable in the returned clock.
    pub(crate) fn production() -> Self {
        #[cfg(target_os = "linux")]
        let source: Box<dyn Source> = match BootTime::start() {
            Ok(source) => Box::new(source),
            Err(reason) => Box::new(Failed(reason)),
        };
        #[cfg(not(target_os = "linux"))]
        let source: Box<dyn Source> = Box::new(Failed(ClockFailure::UnsupportedProfile));
        let clock = Self::from_source(source);
        let _initial = clock.now();
        clock
    }

    pub(crate) fn failure(&self) -> Option<ClockFailure> {
        match self.0.reading.lock() {
            Ok(reading) => reading.failure,
            Err(error) => {
                let mut reading = error.into_inner();
                Some(*reading.failure.get_or_insert(ClockFailure::Source))
            }
        }
    }
}

impl Clock for GrantClock {
    fn now(&self) -> Timestamp {
        let mut reading = self.0.reading.lock().unwrap_or_else(|error| {
            let mut reading = PoisonError::into_inner(error);
            reading.failure.get_or_insert(ClockFailure::Source);
            reading
        });
        if reading.failure.is_none() {
            match self.0.source.read() {
                Ok(now) if now.nanos < 1_000_000_000 => {
                    let _origin = self.0.high_water.origin.set(now);
                    if let Some(now) = self.0.high_water.observe(now) {
                        reading.last = Some(now);
                    } else {
                        // The observed timestamp is valid expiry evidence;
                        // elapsed-time exhaustion still forbids admission.
                        reading.last = Some(reading.last.map_or(now, |last| last.max(now)));
                        reading.failure = Some(ClockFailure::Overflow);
                    }
                }
                Ok(_) => reading.failure = Some(ClockFailure::Source),
                Err(reason) => reading.failure = Some(reason),
            }
        }
        // Clock has no error channel. This value carries no authorization:
        // every grant consumer checks the shared failure latch after expiry.
        reading.last.unwrap_or(Timestamp { secs: 0, nanos: 0 })
    }
}

struct Failed(ClockFailure);
impl Source for Failed {
    fn read(&self) -> Result<Timestamp, ClockFailure> {
        Err(self.0)
    }
}

#[cfg(target_os = "linux")]
struct BootTime {
    utc: i128,
    boot: i128,
}

#[cfg(target_os = "linux")]
impl BootTime {
    fn start() -> Result<Self, ClockFailure> {
        // Sample boot first: startup sampling delay can shorten a grant, never
        // extend it. Subsequent wall-clock adjustments are not consulted.
        let boot = Self::nanos(nix::time::ClockId::CLOCK_BOOTTIME)?;
        let utc = Self::nanos(nix::time::ClockId::CLOCK_REALTIME)?;
        Ok(Self { utc, boot })
    }

    fn nanos(id: nix::time::ClockId) -> Result<i128, ClockFailure> {
        let time = nix::time::clock_gettime(id).map_err(|_| ClockFailure::Source)?;
        let nanos = i128::from(time.tv_nsec());
        if !(0..1_000_000_000).contains(&nanos) {
            return Err(ClockFailure::Source);
        }
        Ok(i128::from(time.tv_sec()) * 1_000_000_000 + nanos)
    }
}

#[cfg(target_os = "linux")]
impl Source for BootTime {
    fn read(&self) -> Result<Timestamp, ClockFailure> {
        let now = Self::nanos(nix::time::ClockId::CLOCK_BOOTTIME)?;
        let elapsed = now
            .checked_sub(self.boot)
            .filter(|n| *n >= 0)
            .ok_or(ClockFailure::Source)?;
        project(self.utc, elapsed)
    }
}

// This projection is also driven by scripted elapsed time in platform-neutral
// tests; its checked arithmetic is the production timestamp conversion.
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "UTC projection is production Linux clock logic; other platforms inject clocks"
    )
)]
fn project(utc: i128, elapsed: i128) -> Result<Timestamp, ClockFailure> {
    let nanos = utc.checked_add(elapsed).ok_or(ClockFailure::Overflow)?;
    Ok(Timestamp {
        secs: i64::try_from(nanos.div_euclid(1_000_000_000)).map_err(|_| ClockFailure::Overflow)?,
        nanos: u32::try_from(nanos.rem_euclid(1_000_000_000))
            .map_err(|_| ClockFailure::Overflow)?,
    })
}
// An origin accepts any timestamp epoch; only elapsed nanoseconds occupy
// the atomic word. The first observation initializes the origin under the
// shared clock guard. Every grant consumer uses the same elapsed high-water mark.
// Unrepresentable elapsed time disables deadlines instead of saturating time.
#[derive(Debug, Default)]
pub(crate) struct TimeHighWater {
    pub(crate) origin: OnceLock<Timestamp>,
    elapsed: AtomicU64,
    exhausted: AtomicBool,
}

impl TimeHighWater {
    pub(crate) fn observe(&self, now: Timestamp) -> Option<Timestamp> {
        let origin = self.origin.get()?;
        if self.exhausted.load(Ordering::Relaxed) {
            return None;
        }
        let elapsed = ((i128::from(now.secs) - i128::from(origin.secs)) * 1_000_000_000
            + i128::from(now.nanos)
            - i128::from(origin.nanos))
        .max(0);
        let Ok(elapsed) = u64::try_from(elapsed) else {
            self.exhausted.store(true, Ordering::Relaxed);
            return None;
        };
        let elapsed = self
            .elapsed
            .fetch_max(elapsed, Ordering::Relaxed)
            .max(elapsed);
        let nanos = u64::from(origin.nanos) + elapsed % 1_000_000_000;
        let secs = i128::from(origin.secs)
            + i128::from(elapsed / 1_000_000_000)
            + i128::from(nanos / 1_000_000_000);
        Some(Timestamp {
            secs: i64::try_from(secs).ok()?,
            nanos: (nanos % 1_000_000_000) as u32,
        })
    }
}

#[cfg(test)]
mod tests;
