// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Process-local monotonic samples, independent of format timestamps.

use std::sync::Arc;
use std::time::{Duration, Instant};

/// A process-local clock domain. Tokens cannot cross domains or be persisted.
#[derive(Debug, Default, Clone)]
pub struct MonotonicDomain(Arc<()>);

/// Opaque start reading, usable only in its originating domain.
#[derive(Debug)]
pub struct MonotonicToken {
    domain: Arc<()>,
    ticks: Duration,
}

impl MonotonicDomain {
    #[must_use]
    pub fn token(&self, ticks: Duration) -> MonotonicToken {
        MonotonicToken {
            domain: self.0.clone(),
            ticks,
        }
    }

    /// A foreign domain or a reversed reading makes timing unavailable.
    #[must_use]
    pub fn elapsed(&self, start: &MonotonicToken, ticks: Duration) -> Option<Duration> {
        Arc::ptr_eq(&self.0, &start.domain)
            .then(|| ticks.checked_sub(start.ticks))
            .flatten()
    }
}

/// Latency seam; missing samples never change an acknowledgement verdict.
pub trait MonotonicClock: Send + Sync {
    fn start(&self) -> Option<MonotonicToken>;
    fn elapsed(&self, start: &MonotonicToken) -> Option<Duration>;
}

/// Production clock. Only this adapter consults `std::time::Instant`.
#[derive(Debug)]
pub struct InstantClock {
    domain: MonotonicDomain,
    origin: Instant,
}
impl Default for InstantClock {
    #[expect(
        clippy::disallowed_methods,
        reason = "production monotonic clock adapter; format timestamps are never consulted"
    )]
    fn default() -> Self {
        Self {
            domain: MonotonicDomain::default(),
            origin: Instant::now(),
        }
    }
}
impl MonotonicClock for InstantClock {
    fn start(&self) -> Option<MonotonicToken> {
        Some(self.domain.token(self.origin.elapsed()))
    }
    fn elapsed(&self, start: &MonotonicToken) -> Option<Duration> {
        self.domain.elapsed(start, self.origin.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_tokens_refuse_foreign_domains_and_reversed_ticks() {
        let domain = MonotonicDomain::default();
        let start = domain.token(Duration::from_millis(12));
        assert_eq!(
            domain.elapsed(&start, Duration::from_millis(37)),
            Some(Duration::from_millis(25))
        );
        assert_eq!(domain.elapsed(&start, Duration::from_millis(11)), None);
        assert_eq!(
            MonotonicDomain::default().elapsed(&start, Duration::from_millis(37)),
            None
        );
        assert!(InstantClock::default().elapsed(&start).is_none());
    }
}
