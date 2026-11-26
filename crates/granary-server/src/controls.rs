// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-principal write traffic and occupancy. Enrollment reloads never
//! touch this state: absence is not forgiveness of unrefilled traffic.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::clock::Clock;
use granary_core::enrollment::PrincipalId;
use granary_core::sheaf::Timestamp;

use crate::adapter::{WRITE_BODY_BUDGET_BYTES, WRITE_BUDGET_GRANULE_BYTES};
use crate::wire::Outcome;

const SECOND: u128 = 1_000_000_000;

/// Validated deployment-wide rates, bursts and write occupancy.
///
/// Defaults bound publish and intent mutation admissions per principal to 46 submissions/s with
/// burst 5, received write traffic to 32 MiB/s with burst 256 MiB, and
/// concurrent principal-bearing writes to 4. Each publish or intent mutation admission
/// spends a submission token, including retransmissions and replays; other uploads
/// spend only bytes and occupancy. Every read, including authenticated intent
/// readback, bypasses these controls and spends no token, bytes or occupancy.
/// The byte burst fits a maximal body and refills in eight seconds.
/// The cap times the largest rounded body reservation must stay below the
/// shared write-content budget; the default cap of 4 holds half that budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlsConfig {
    submission_rate: u64,
    submission_burst: u64,
    byte_rate: u64,
    byte_burst: u64,
    cap: usize,
}

impl Default for ControlsConfig {
    fn default() -> Self {
        Self {
            submission_rate: 46,
            submission_burst: 5,
            byte_rate: 32 * 1024 * 1024,
            byte_burst: 256 * 1024 * 1024,
            cap: 4,
        }
    }
}

impl ControlsConfig {
    /// Parse submissions/s, submission burst, bytes/s, byte burst, cap.
    ///
    /// # Errors
    /// Refuses anything other than five positive decimal integers, a byte
    /// burst smaller than a maximal body, a cap that can fill the shared
    /// budget, or a full-refill delay that cannot fit the wire's `u32`.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut values = value.split(',');
        let mut next = || {
            let field = values.next().ok_or("expected five integers")?;
            if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
                return Err("expected unsigned decimal integers");
            }
            let value = field.parse::<u64>().map_err(|_| "integer overflow")?;
            if value == 0 {
                return Err("values must be positive");
            }
            Ok(value)
        };
        let submission_rate = next()?;
        let submission_burst = next()?;
        let byte_rate = next()?;
        let byte_burst = next()?;
        let cap = usize::try_from(next()?).map_err(|_| "cap overflow")?;
        if values.next().is_some() {
            return Err("expected five integers".into());
        }
        if byte_burst < BIN_MAX_BYTES {
            return Err("byte burst is smaller than a maximal body".into());
        }
        let rounded = BIN_MAX_BYTES
            .div_ceil(WRITE_BUDGET_GRANULE_BYTES)
            .checked_mul(WRITE_BUDGET_GRANULE_BYTES)
            .ok_or("reservation overflow")?;
        let held = u64::try_from(cap)
            .ok()
            .and_then(|cap| cap.checked_mul(rounded));
        if held.is_none_or(|held| held >= WRITE_BODY_BUDGET_BYTES) {
            return Err("cap can exhaust the shared write budget".into());
        }
        for (rate, burst) in [(submission_rate, submission_burst), (byte_rate, byte_burst)] {
            if burst.div_ceil(rate) > u64::from(u32::MAX) {
                return Err("full-refill delay exceeds delay-seconds".into());
            }
        }
        Ok(Self {
            submission_rate,
            submission_burst,
            byte_rate,
            byte_burst,
            cap,
        })
    }

    /// The tuple in configuration order.
    #[must_use]
    pub fn tuple(self) -> (u64, u64, u64, u64, usize) {
        (
            self.submission_rate,
            self.submission_burst,
            self.byte_rate,
            self.byte_burst,
            self.cap,
        )
    }
}

/// A principal's own refusal. The delay is advisory for occupancy and
/// rounded up to the next submission or full byte bucket for traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRefusal {
    /// Positive delay-seconds for `Retry-After`.
    pub retry_after: u32,
}

impl std::fmt::Display for ControlRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "principal write allowance exhausted; retry after {}s",
            self.retry_after
        )
    }
}

impl std::error::Error for ControlRefusal {}

impl ControlRefusal {
    /// The common wire refusal for either currency and the cap.
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        Outcome::rate_limited(self.retry_after)
    }
}

#[derive(Debug)]
struct Bucket {
    rate: u64,
    burst: u128,
    // Nanotokens retain fractional credit independently of DATA framing.
    credit: u128,
}

impl Bucket {
    fn new(rate: u64, burst: u64) -> Self {
        let burst = u128::from(burst) * SECOND;
        Self {
            rate,
            burst,
            credit: burst,
        }
    }

    fn refill(&mut self, elapsed: u128) {
        self.credit = self
            .credit
            .saturating_add(elapsed.saturating_mul(u128::from(self.rate)))
            .min(self.burst);
    }

    fn debit(&mut self, amount: u64) -> bool {
        let amount = u128::from(amount) * SECOND;
        let admitted = self.credit >= amount;
        self.credit = self.credit.saturating_sub(amount);
        admitted
    }

    fn delay(&self, target: u128) -> ControlRefusal {
        let missing = target.saturating_sub(self.credit);
        let seconds = missing.div_ceil(u128::from(self.rate) * SECOND).max(1);
        ControlRefusal {
            retry_after: u32::try_from(seconds).unwrap_or(u32::MAX),
        }
    }
}

#[derive(Debug)]
struct Rates {
    submissions: Bucket,
    bytes: Bucket,
    watermark: i128,
}

fn nanos(timestamp: Timestamp) -> i128 {
    i128::from(timestamp.secs) * 1_000_000_000 + i128::from(timestamp.nanos)
}

impl Rates {
    /// Credit forward elapsed time only, tracking every clock reading so
    /// refill resumes from the lower watermark after a backward step.
    fn refill(&mut self, now: i128) {
        let elapsed = u128::try_from(now.saturating_sub(self.watermark)).unwrap_or(0);
        self.watermark = now;
        self.submissions.refill(elapsed);
        self.bytes.refill(elapsed);
    }

    fn full(&self) -> bool {
        self.submissions.credit == self.submissions.burst && self.bytes.credit == self.bytes.burst
    }
}

#[derive(Debug)]
struct PrincipalState {
    rates: Mutex<Rates>,
    in_flight: AtomicUsize,
}

/// Process-owned controls, shared across credentials and connections.
///
/// Every insertion sweeps full, idle entries. The map therefore retains
/// only principals charged within the longest full refill, live permits,
/// and the entry being inserted. Each charged principal was enrolled at
/// admission; enrollment history does not affect eviction.
pub struct PrincipalControls {
    config: ControlsConfig,
    clock: Arc<dyn Clock>,
    states: Mutex<BTreeMap<PrincipalId, Arc<PrincipalState>>>,
}

impl std::fmt::Debug for PrincipalControls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalControls")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PrincipalControls {
    /// Initially full allowances, on an injected clock.
    #[must_use]
    pub fn new(config: ControlsConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            states: Mutex::new(BTreeMap::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn state_count(&self) -> usize {
        self.states
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    pub(crate) fn in_flight(&self, principal: PrincipalId) -> usize {
        self.states
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&principal)
            .map_or(0, |state| state.in_flight.load(Ordering::Acquire))
    }

    /// Exact stored accounting, without refilling or creating a principal entry.
    #[cfg(test)]
    pub(crate) fn accounting(&self, principal: PrincipalId) -> Option<(u128, u128, usize)> {
        let states = self.states.lock().unwrap_or_else(PoisonError::into_inner);
        let state = states.get(&principal)?;
        let rates = state.rates.lock().unwrap_or_else(PoisonError::into_inner);
        Some((
            rates.submissions.credit,
            rates.bytes.credit,
            state.in_flight.load(Ordering::Acquire),
        ))
    }

    /// Admit one enrolled write; publish and intent mutations spend a submission token.
    /// The caller resolves enrollment on every write before calling. Every read,
    /// including authenticated intent readback, bypasses these controls.
    ///
    /// # Errors
    /// A principal at its cap, or a submission without one token.
    pub fn admit(
        &self,
        principal: PrincipalId,
        submission: bool,
    ) -> Result<WritePermit, ControlRefusal> {
        let mut states = self.states.lock().unwrap_or_else(PoisonError::into_inner);
        let now = nanos(self.clock.now());
        if !states.contains_key(&principal) {
            // Holding the admission lock prevents a sweep from orphaning
            // a newly issued permit. Drop only decreases occupancy.
            states.retain(|_, state| {
                let mut rates = state.rates.lock().unwrap_or_else(PoisonError::into_inner);
                rates.refill(now);
                !(rates.full() && state.in_flight.load(Ordering::Acquire) == 0)
            });
        }
        let state = states.entry(principal).or_insert_with(|| {
            Arc::new(PrincipalState {
                rates: Mutex::new(Rates {
                    submissions: Bucket::new(
                        self.config.submission_rate,
                        self.config.submission_burst,
                    ),
                    bytes: Bucket::new(self.config.byte_rate, self.config.byte_burst),
                    watermark: now,
                }),
                in_flight: AtomicUsize::new(0),
            })
        });
        let mut rates = state.rates.lock().unwrap_or_else(PoisonError::into_inner);
        rates.refill(now);
        if state.in_flight.load(Ordering::Acquire) >= self.config.cap {
            // A completion cannot be predicted; one second is a polling
            // advisory that avoids encouraging a tight retry loop.
            return Err(ControlRefusal { retry_after: 1 });
        }
        if submission {
            if rates.submissions.credit < SECOND {
                return Err(rates.submissions.delay(SECOND));
            }
            rates.submissions.debit(1);
        }
        state.in_flight.fetch_add(1, Ordering::AcqRel);
        Ok(WritePermit {
            state: Arc::clone(state),
            clock: Arc::clone(&self.clock),
        })
    }
}

/// Request-owned, non-cloneable slot. Keep it through response construction.
/// Dropping it frees only occupancy; traffic is never refunded.
pub struct WritePermit {
    state: Arc<PrincipalState>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for WritePermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritePermit").finish_non_exhaustive()
    }
}

impl WritePermit {
    /// Charge received content, including a frame that causes refusal.
    ///
    /// # Errors
    /// Insufficient byte allowance. The remaining credit is clamped to zero;
    /// the delay is until the byte bucket is full, with no negative debt.
    pub fn charge_bytes(&self, arrived: u64) -> Result<(), ControlRefusal> {
        let mut rates = self
            .state
            .rates
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        rates.refill(nanos(self.clock.now()));
        if rates.bytes.debit(arrived) {
            Ok(())
        } else {
            Err(rates.bytes.delay(rates.bytes.burst))
        }
    }
}

impl Drop for WritePermit {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
pub(crate) mod tests;
