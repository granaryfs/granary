// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The shared allowance for one admission's reads and verification.

use std::future::{Future, Pending, pending, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::clock::Clock;
use granary_core::sheaf::Timestamp;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Timeout, timeout};

use super::proofs::{Allocation, DEFAULT_VALIDATIONS, Proofs};

use super::{ValidationError, ValidationObject, ValidationRead, ValidationReadError};

type Result<T> = std::result::Result<T, ValidationError>;

/// Authority-owned work limits for a new publication decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum object read attempts, including repeated reads of one key.
    pub reads: u64,
    /// Aggregate response body bytes and the ceiling for retained decoded shards.
    pub bytes: u64,
    /// Aggregate declared expanded frame bytes.
    pub expansion: u64,
    /// Logical work, including metadata slots, rows and frame visits.
    pub steps: u64,
    /// Admission deadline. Deadline expiry is an availability failure.
    pub wall_time: Duration,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            // A 2048-to-4096 shard transition can read every old and new
            // slot. Leave room for its metadata, bins and head reads.
            reads: 8_192,
            // Fits three 200 MiB bins with room for metadata.
            bytes: 1024 * 1024 * 1024,
            // Fits the largest expansion admitted at bin ingest.
            expansion: 4 * 1024 * 1024 * 1024,
            steps: 1_000_000,
            wall_time: Duration::from_secs(30),
        }
    }
}

/// Share one validator across the authority process's volumes.
#[derive(Debug, Clone)]
pub struct PublicationValidator {
    permits: Arc<Semaphore>,
    limits: ValidationLimits,
    intake_ticket: Arc<Semaphore>,
    proofs: Proofs,
}

impl Default for PublicationValidator {
    fn default() -> Self {
        Self::new(ValidationLimits::default(), DEFAULT_VALIDATIONS)
    }
}

impl PublicationValidator {
    /// Give all clones a common admission concurrency ceiling.
    #[must_use]
    pub fn new(limits: ValidationLimits, concurrent: u16) -> Self {
        let permits = Semaphore::new(usize::from(concurrent));
        if concurrent == 0 {
            permits.close();
        }
        Self {
            permits: Arc::new(permits),
            limits,
            intake_ticket: Arc::new(Semaphore::new(1)),
            proofs: Proofs::new(concurrent),
        }
    }

    pub(super) fn fresh(mut self) -> Self {
        self.proofs = self.proofs.fresh();
        self
    }

    pub(super) fn proofs(&self) -> &Proofs {
        &self.proofs
    }

    #[cfg(test)]
    pub(super) fn limit_proofs(&mut self, bytes: usize) {
        self.proofs = self.proofs.with_resident_limit(bytes);
    }

    /// Wait in FIFO order for a validation slot for up to one wall-time
    /// allowance. A fresh deadline starts on grant.
    ///
    /// # Errors
    /// Unavailable if validation is disabled or the wait expires.
    ///
    /// # Panics
    /// The authority runtime must provide Tokio's time driver.
    ///
    /// # Cancellation safety
    /// Dropping a queued call loses its place in the queue.
    pub async fn begin(&self, clock: Arc<dyn Clock>) -> Result<ValidationAttempt> {
        let mut attempt = self.preflight(clock);
        self.acquire(&mut attempt).await?;
        Ok(attempt)
    }

    pub(super) fn preflight(&self, clock: Arc<dyn Clock>) -> ValidationAttempt {
        ValidationAttempt::new(clock, self.limits, self.proofs.clone())
    }

    // Return whether the attempt queued. Retain the charges from rule 6.
    pub(super) async fn acquire(&self, attempt: &mut ValidationAttempt) -> Result<bool> {
        let (permit, queued) = if let Ok(permit) = self.permits.clone().try_acquire_owned() {
            (permit, false)
        } else {
            let permit = timeout(attempt.work.remaining.wall_time, acquire(&self.permits))
                .await
                .map_err(|_| ValidationError::Unavailable)??;
            (permit, true)
        };
        attempt.permit = Some(Arc::new(permit));
        attempt.start_deadline();
        Ok(queued)
    }

    pub(super) async fn begin_intake(&self, clock: Arc<dyn Clock>) -> Result<ValidationAttempt> {
        let permit = acquire(&self.intake_ticket).await?;
        // Every legal single object and fixed-stride metadata decode
        // fits an atomic slice action even with tight admission limits.
        let mut limits = self.limits;
        limits.reads = limits.reads.max(1);
        limits.bytes = limits.bytes.max(BIN_MAX_BYTES);
        limits.steps = limits.steps.max(ValidationLimits::default().steps);
        limits.expansion = limits
            .expansion
            .max(u64::from(granary_core::manifest::GRAIN_UNPACKED_MAX));
        let mut attempt = ValidationAttempt::new(clock, limits, self.proofs.clone());
        attempt.work.sliced = true;
        attempt.permit = Some(Arc::new(permit));
        attempt.intake = Some(limits);
        Ok(attempt)
    }
}

async fn acquire(semaphore: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit> {
    semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ValidationError::Unavailable)
}

/// Read and work allowances for one admission, including its concurrency slot.
pub struct ValidationAttempt {
    work: Work,
    deadline: Deadline,
    proofs: Proofs,
    memory_bytes: u64,
    // Validation slot or whole-job intake ticket. Detached blocking work
    // retains its permit until it exits.
    permit: Option<Arc<OwnedSemaphorePermit>>,
    intake: Option<ValidationLimits>,
}

impl std::fmt::Debug for ValidationAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationAttempt")
            .field("remaining", &self.work.remaining)
            .finish_non_exhaustive()
    }
}

impl ValidationAttempt {
    fn new(clock: Arc<dyn Clock>, limits: ValidationLimits, proofs: Proofs) -> Self {
        Self {
            work: Work {
                started: nanos(clock.now()),
                clock,
                remaining: limits,
                sliced: false,
            },
            deadline: Some(Box::pin(timeout(limits.wall_time, pending()))),
            proofs,
            memory_bytes: limits.bytes,
            permit: None,
            intake: None,
        }
    }

    pub(super) fn length_allocation(&self) -> Result<Allocation> {
        let permit = self.permit.as_ref().ok_or(ValidationError::Unavailable)?;
        Ok(Allocation::new(self.proofs.clone(), permit))
    }

    pub(in crate::authority) fn now(&self) -> Timestamp {
        self.work.clock.now()
    }

    pub(super) fn into_intake_ticket(self) -> Option<Arc<OwnedSemaphorePermit>> {
        self.permit
    }

    pub(super) fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    fn start_deadline(&mut self) {
        self.work.started = nanos(self.work.clock.now());
        self.deadline = Some(Box::pin(timeout(self.work.remaining.wall_time, pending())));
    }

    async fn prepare(&mut self, reads: u64, bytes: u64, expansion: u64, steps: u64) -> Result<()> {
        let Some(limits) = self.intake else {
            return Ok(());
        };
        if reads > limits.reads
            || bytes > limits.bytes
            || expansion > limits.expansion
            || steps > limits.steps
        {
            return Err(ValidationError::WorkLimit);
        }
        let left = self.work.remaining;
        let elapsed = poll_fn(|cx| Poll::Ready(elapsed(&mut self.deadline, cx))).await;
        let exhausted = elapsed
            || self.work.time_left().is_err()
            || reads > left.reads
            || bytes > left.bytes
            || expansion > left.expansion
            || steps > left.steps;
        if exhausted {
            crash_point!(IntakeSlice);
            tokio::task::yield_now().await;
            self.work.remaining = limits;
            self.start_deadline();
        }
        Ok(())
    }

    pub(super) async fn meter(&mut self, steps: u64) -> Result<()> {
        tokio::task::consume_budget().await;
        self.prepare(0, 0, 0, steps).await?;
        self.steps(steps)
    }

    pub(super) async fn prepare_expansion(&mut self, len: u32) -> Result<()> {
        self.prepare(0, 0, u64::from(len), 1).await
    }

    pub(super) async fn prepare_page(&mut self, bytes: u64) -> Result<()> {
        self.prepare(1, bytes, 0, 2).await
    }

    pub(super) async fn prepare_entry(&mut self) -> Result<()> {
        self.prepare(0, 0, 0, 1).await
    }

    /// Charge logical steps before consuming them.
    ///
    /// # Errors
    /// The step allowance or deadline has run out.
    pub fn steps(&mut self, count: u64) -> Result<()> {
        self.work.steps(count)
    }

    /// Read an object under the smaller of its class cap and the remaining
    /// response allowance. The source receives that cap before dispatch.
    ///
    /// # Errors
    /// One of the validation refusals, using the supplied prior proof to
    /// distinguish a newly missing object from a previously verified one.
    ///
    /// # Cancellation safety
    /// Dropping the read cancels the fetch and leaves the reservation charged.
    pub async fn read(
        &mut self,
        source: &impl ValidationRead,
        object: ValidationObject<'_>,
        verified: bool,
    ) -> Result<Vec<u8>> {
        let mut backoff = Duration::from_millis(50);
        loop {
            match self.read_once(source, object, verified).await {
                Err(error) if self.retry(error, &mut backoff).await => {}
                result => return result,
            }
        }
    }

    async fn read_once(
        &mut self,
        source: &impl ValidationRead,
        object: ValidationObject<'_>,
        verified: bool,
    ) -> Result<Vec<u8>> {
        let class_cap = object.max_bytes();
        self.prepare(1, class_cap, 0, 1).await?;
        self.steps(1)?;
        charge(&mut self.work.remaining.reads, 1)?;
        if matches!(object, ValidationObject::BinRange(..)) && self.work.remaining.bytes < class_cap
        {
            return Err(ValidationError::WorkLimit);
        }
        let cap = self.reserve_bytes(class_cap)?;
        let result = self
            .request(async { source.read(object, cap).await })
            .await?;
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(ValidationReadError::Missing) => {
                // A definitive absence has no object body to charge.
                self.refund_bytes(cap);
                return Err(if verified {
                    ValidationError::Unavailable
                } else {
                    ValidationError::MissingReference
                });
            }
            Err(ValidationReadError::OverCap) if cap < class_cap => {
                return Err(ValidationError::WorkLimit);
            }
            Err(ValidationReadError::OverCap) => {
                return Err(if verified {
                    ValidationError::Unavailable
                } else {
                    ValidationError::InvalidReference
                });
            }
            Err(ValidationReadError::Unavailable) => return Err(ValidationError::Unavailable),
        };
        let size = u64::try_from(bytes.len()).map_err(|_| ValidationError::WorkLimit)?;
        if size > cap {
            return Err(ValidationError::Unavailable);
        }
        self.refund_bytes(cap.saturating_sub(size));
        Ok(bytes)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "content verification CPU seam, outside the worker task and append gate"
    )]
    pub(super) async fn blocking<T: Send + 'static>(
        &mut self,
        work: impl FnOnce(&mut Work) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.prepare(0, 0, 0, 0).await?;
        // Only this call can update the attempt until the job returns.
        let mut job = self.work.clone();
        let permit = self.permit.clone();
        let (job, result, _permit) = self
            .within(async move {
                tokio::task::spawn_blocking(move || {
                    let result = job.check_time().and_then(|()| work(&mut job));
                    // A discarded result can own lengths. Drop it before
                    // releasing the permit, even if the waiter has gone.
                    (job, result, permit)
                })
                .await
            })
            .await?
            .map_err(|_| ValidationError::Unavailable)?;
        self.work = job;
        result
    }

    pub(super) fn reserve_bytes(&mut self, cap: u64) -> Result<u64> {
        let cap = cap.min(self.work.remaining.bytes);
        if cap == 0 {
            return Err(ValidationError::WorkLimit);
        }
        charge(&mut self.work.remaining.bytes, cap)?;
        Ok(cap)
    }

    pub(super) fn refund_bytes(&mut self, bytes: u64) {
        self.work.remaining.bytes = self.work.remaining.bytes.saturating_add(bytes);
    }

    pub(in crate::authority) fn expired(&self) -> bool {
        self.deadline.is_none() || self.work.time_left().is_err()
    }

    /// Reserve one listing request and limit the page to the entries that
    /// can still be processed. A nonterminal page never supplies a head.
    pub(super) fn list_page(&mut self) -> Result<usize> {
        self.steps(1)?;
        charge(&mut self.work.remaining.reads, 1)?;
        let entries = self.work.remaining.steps.min(1_000);
        if entries == 0 {
            return Err(ValidationError::WorkLimit);
        }
        usize::try_from(entries).map_err(|_| ValidationError::WorkLimit)
    }

    pub(super) async fn retry(&mut self, error: ValidationError, backoff: &mut Duration) -> bool {
        if self.intake.is_none() || error != ValidationError::Unavailable {
            return false;
        }
        let _expired = timeout(*backoff, pending::<()>()).await;
        *backoff = (*backoff * 2).min(Duration::from_secs(2));
        true
    }

    pub(super) async fn request<T>(&mut self, operation: impl Future<Output = T>) -> Result<T> {
        if self.intake.is_some() {
            // A read already dispatched at the boundary gets its own timeout.
            let limit = Duration::from_secs(5).min(self.work.remaining.wall_time);
            return timeout(limit, operation)
                .await
                .map_err(|_| ValidationError::Unavailable);
        }
        self.within(operation).await
    }

    async fn within<T>(&mut self, work: impl Future<Output = T>) -> Result<T> {
        if self.intake.is_some() {
            return Ok(work.await);
        }
        let mut operation = std::pin::pin!(timeout(self.work.time_left()?, async {
            tokio::task::consume_budget().await;
            work.await
        }));
        let result = poll_fn(|cx| {
            // This timer spans the whole attempt, even if the clock is
            // adjusted while an operation is waiting on the backend.
            if elapsed(&mut self.deadline, cx) {
                return Poll::Ready(Err(ValidationError::Unavailable));
            }
            operation
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(|_| ValidationError::Unavailable))
        })
        .await?;
        self.work.time_left()?;
        Ok(result)
    }
}

type Deadline = Option<Pin<Box<Timeout<Pending<()>>>>>;

fn elapsed(deadline: &mut Deadline, cx: &mut Context<'_>) -> bool {
    if deadline
        .as_mut()
        .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
    {
        *deadline = None;
    }
    deadline.is_none()
}

#[derive(Clone)]
pub(super) struct Work {
    clock: Arc<dyn Clock>,
    started: i128,
    remaining: ValidationLimits,
    sliced: bool,
}

impl Work {
    pub(super) fn steps(&mut self, count: u64) -> Result<()> {
        self.check_time()?;
        charge(&mut self.remaining.steps, count)
    }

    pub(super) fn expand(&mut self, bytes: u32) -> Result<()> {
        self.steps(1)?;
        charge(&mut self.remaining.expansion, u64::from(bytes))
    }

    // A slice rotates between actions; a bounded CPU action may finish.
    fn check_time(&self) -> Result<()> {
        if !self.sliced {
            self.time_left()?;
        }
        Ok(())
    }

    fn time_left(&self) -> Result<Duration> {
        let elapsed = nanos(self.clock.now()) - self.started;
        let elapsed = u128::try_from(elapsed).map_err(|_| ValidationError::Unavailable)?;
        let elapsed = Duration::new(
            u64::try_from(elapsed / 1_000_000_000).map_err(|_| ValidationError::Unavailable)?,
            u32::try_from(elapsed % 1_000_000_000).map_err(|_| ValidationError::Unavailable)?,
        );
        self.remaining
            .wall_time
            .checked_sub(elapsed)
            .filter(|left| !left.is_zero())
            .ok_or(ValidationError::Unavailable)
    }
}

fn nanos(time: Timestamp) -> i128 {
    i128::from(time.secs) * 1_000_000_000 + i128::from(time.nanos)
}

fn charge(left: &mut u64, count: u64) -> Result<()> {
    *left = left.checked_sub(count).ok_or(ValidationError::WorkLimit)?;
    Ok(())
}
