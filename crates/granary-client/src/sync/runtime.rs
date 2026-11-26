// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Scheduling seam for supervised operations and their single enclosing bound.

use std::{future::Future, time::Duration};

#[derive(Debug, Clone, Copy)]
pub struct SyncRuntimeError;

/// The caller's operation span and default dispatcher, captured where work is
/// handed to a scheduler and re-entered wherever that work later runs, so the
/// work's events and requests carry the caller's operation id. Every
/// `SyncRuntime` captures through this one type, once per hop.
#[derive(Debug)]
pub struct OperationContext {
    dispatch: tracing::Dispatch,
    span: tracing::Span,
}
impl OperationContext {
    /// The calling thread's context.
    #[must_use]
    pub fn current() -> Self {
        Self {
            dispatch: tracing::dispatcher::get_default(Clone::clone),
            span: crate::observe::current_operation_span(),
        }
    }
    /// `work`, polled inside this context wherever it is polled.
    pub fn attach<F: Future>(self, work: F) -> impl Future<Output = F::Output> {
        use tracing::Instrument as _;
        use tracing::instrument::WithSubscriber as _;
        work.instrument(self.span).with_subscriber(self.dispatch)
    }
    /// Run `work` inside this context on the calling thread.
    pub fn run<T>(self, work: impl FnOnce() -> T) -> T {
        tracing::dispatcher::with_default(&self.dispatch, || {
            let _entered = self.span.enter();
            work()
        })
    }
}

/// Scheduling and deadlines are separate from timestamps and latency samples.
/// `spawn` starts work immediately; dropping its returned join future does not
/// cancel work. Simulators supply their own scheduler through this interface.
pub trait SyncRuntime: Send + Sync {
    /// Non-cryptographic retry jitter. Simulators override this with their
    /// replay stream; keys and request identities use the secure-random seam.
    fn random_u64(&self) -> u64 {
        granary_core::rng::Rng::next_u64(&mut granary_core::rng::ProcessRng::default())
    }
    fn now(&self) -> tokio::time::Instant;
    fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send;
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send;
    /// Poll a future whose synchronous callbacks may wait for remote work.
    /// The executor remains available to drive that work and pooled connections.
    /// Each scheduler supplies its own polling context, without blocking an
    /// executor thread on work that needs that executor to make progress.
    fn blocking_async<T: Send + 'static, F: Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl Future<Output = T> + Send,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send;
}

/// Runtime adapter used by production supervisors. No scheduler primitives are
/// hidden in engine logic, so a deterministic scheduler can replace this seam.
#[derive(Debug, Default)]
pub struct TokioSyncRuntime;
impl SyncRuntime for TokioSyncRuntime {
    #[expect(
        clippy::disallowed_methods,
        reason = "production scheduling clock adapter"
    )]
    fn now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "production supervisor spawning adapter; join is observed by its monitor"
    )]
    fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        let join = tokio::spawn(OperationContext::current().attach(work));
        async move { join.await.map_err(|_| SyncRuntimeError) }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "production bounded materialisation adapter; the supervisor observes its join"
    )]
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        let context = OperationContext::current();
        let join = tokio::task::spawn_blocking(move || context.run(work));
        async move { join.await.map_err(|_| SyncRuntimeError) }
    }

    async fn blocking_async<T: Send + 'static, F: Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> Result<T, SyncRuntimeError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| SyncRuntimeError)?;
        self.blocking(move || handle.block_on(work())).await
    }

    #[expect(clippy::disallowed_methods, reason = "production retry timer adapter")]
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }

    async fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl Future<Output = T> + Send,
    ) -> Result<T, SyncRuntimeError> {
        tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| SyncRuntimeError)
    }
}
