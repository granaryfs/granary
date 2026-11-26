// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Volatile per-volume terminal commit rate, independent of admission policy.

use crate::{ClientEvent, ClientMetrics, CommitResult, publication_config::ConfigurationError};

/// Operator threshold for the fraction of terminal commits ending in contention.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ContentionThreshold(f64);
impl Default for ContentionThreshold {
    fn default() -> Self {
        Self(0.25)
    }
}
impl ContentionThreshold {
    /// Exact binary64 representation for a numeric support projection.
    #[must_use]
    pub const fn to_bits(self) -> u64 {
        self.0.to_bits()
    }

    /// Parse a finite rate greater than 0 and at most 1.
    /// # Errors
    /// Invalid, nonfinite or out-of-range rates; supplied bytes are never rendered.
    pub fn parse(value: &str) -> Result<Self, ConfigurationError> {
        value
            .parse::<f64>()
            .ok()
            .filter(|rate| rate.is_finite() && *rate > 0.0 && *rate <= 1.0)
            .map(Self)
            .ok_or(ConfigurationError(
                "--contention-rate needs a finite rate greater than 0 and at most 1",
            ))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Window {
    outcomes: u16,
    observed: u8,
    threshold: ContentionThreshold,
    decision: Option<bool>,
}
impl Window {
    pub(crate) fn set_threshold(&mut self, threshold: ContentionThreshold) {
        self.threshold = threshold;
    }
    pub(crate) fn publish(&self, metrics: &ClientMetrics) {
        if let Some(flagged) = self.decision {
            metrics.set_contention(flagged);
        }
    }
    pub(crate) fn record(&mut self, result: CommitResult, metrics: Option<&ClientMetrics>) {
        let contended = matches!(result, CommitResult::Conflict | CommitResult::Exhausted);
        self.outcomes = (self.outcomes << 1) | u16::from(contended);
        self.observed = (self.observed + 1).min(16);
        if self.observed < 4 {
            return;
        }
        let commits = u64::from(self.observed);
        let conflicts = u64::from(self.outcomes.count_ones());
        let flagged =
            f64::from(self.outcomes.count_ones()) / f64::from(self.observed) >= self.threshold.0;
        let rising = flagged && self.decision != Some(true);
        self.decision = Some(flagged);
        if let Some(metrics) = metrics {
            self.publish(metrics);
        }
        if rising {
            ClientEvent::commit_contention(commits, conflicts).emit();
        }
    }
}

#[cfg(test)]
mod tests;
