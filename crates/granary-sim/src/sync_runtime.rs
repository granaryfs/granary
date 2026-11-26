// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Seeded scheduling of engine supervisors, with explicit virtual time.
//! Blocking closures must be bounded and must not wait for another task.

use crate::rng::Rng;
use granary_client::{OperationContext, SyncRuntime, SyncRuntimeError};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake},
    time::Duration,
};
use tokio::{sync::oneshot, time::Instant};

type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Debug)]
struct Signal(AtomicBool);
impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

struct Task {
    work: Work,
    signal: Arc<Signal>,
    id: u64,
}
struct LocalTask<'a> {
    supervised: bool,
    work: Pin<Box<dyn Future<Output = ()> + 'a>>,
    signal: Arc<Signal>,
    id: u64,
}
impl std::fmt::Debug for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Task")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A deterministic pause before a selected blocking closure enters user code.
#[derive(Debug, Clone, Default)]
pub struct BlockingPause {
    entered: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
}
impl BlockingPause {
    #[must_use]
    pub fn entered(&self) -> bool {
        self.entered.load(Ordering::Acquire)
    }
    pub fn resume(&self) {
        self.released.store(true, Ordering::Release);
    }
}

#[derive(Debug)]
struct State {
    ready: VecDeque<Task>,
    ticks: u64,
    next: u64,
    polls: Vec<u64>,
    blocking_calls: u64,
    pause: Option<(u64, BlockingPause)>,
    random: Rng,
}

/// Work remains queued when a caller drops a join future. Each selected poll
/// advances virtual time by one millisecond; no operating-system timer runs.
#[derive(Debug)]
pub struct SimSyncRuntime {
    origin: Instant,
    state: Mutex<State>,
}
impl SimSyncRuntime {
    /// Monotonic simulator ticks, shared by timestamp and latency adapters.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        Duration::from_millis(
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ticks,
        )
    }
    #[must_use]
    pub fn new(origin: Instant) -> Self {
        Self {
            origin,
            state: Mutex::new(State {
                ready: VecDeque::new(),
                ticks: 0,
                next: 0,
                polls: Vec::new(),
                blocking_calls: 0,
                pause: None,
                random: Rng::seeded(0, 55),
            }),
        }
    }

    /// Pause one future blocking admission, without holding any local lock.
    /// # Errors
    /// Past/zero occurrence or another outstanding pause.
    pub fn pause_blocking_at(&self, occurrence: u64) -> Result<BlockingPause, &'static str> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if occurrence == 0 || occurrence <= state.blocking_calls {
            return Err("SyncBlockingOccurrence");
        }
        if state.pause.is_some() {
            return Err("SyncBlockingAlreadyPaused");
        }
        let pause = BlockingPause::default();
        state.pause = Some((occurrence, pause.clone()));
        Ok(pause)
    }

    fn queue<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> oneshot::Receiver<T> {
        let (send, receive) = oneshot::channel();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = state.next;
        state.next += 1;
        state.ready.push_back(Task {
            id,
            signal: Arc::new(Signal(AtomicBool::new(true))),
            work: Box::pin(async move {
                let _ = send.send(work.await);
            }),
        });
        receive
    }

    /// Drain all supervised work, including monitors and cancelled callers.
    /// # Errors
    /// Empty selection, missing wakeup or exhausted poll budget.
    pub fn drain(&self, seed: u64, budget: u64) -> Result<Vec<u64>, &'static str> {
        self.drive(seed, budget, Vec::new())
    }

    fn drive(
        &self,
        seed: u64,
        budget: u64,
        mut tasks: Vec<LocalTask<'_>>,
    ) -> Result<Vec<u64>, &'static str> {
        let mut rng = Rng::seeded(seed, 54);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .random = Rng::seeded(seed, 55);
        let start = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .polls
            .len();
        for _ in 0..budget {
            tasks.extend(
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .ready
                    .drain(..)
                    .map(|task| LocalTask {
                        supervised: true,
                        work: task.work,
                        signal: task.signal,
                        id: task.id,
                    }),
            );
            if tasks.is_empty() {
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let trace = state
                    .polls
                    .get(start..)
                    .ok_or("SyncScheduleTrace")?
                    .to_vec();
                return if trace.is_empty() {
                    Err("SyncScheduleEmpty")
                } else {
                    Ok(trace)
                };
            }
            let ready: Vec<_> = tasks
                .iter()
                .enumerate()
                .filter(|(_, task)| task.signal.0.load(Ordering::Acquire))
                .map(|(i, _)| i)
                .collect();
            if ready.is_empty() {
                return Err("SyncScheduleStalled");
            }
            let count = u32::try_from(ready.len()).map_err(|_| "SyncScheduleCapacity")?;
            let pick = usize::try_from(rng.below(count)).map_err(|_| "SyncScheduleCapacity")?;
            let index = *ready.get(pick).ok_or("SyncScheduleSelection")?;
            let task = tasks.get_mut(index).ok_or("SyncScheduleSelection")?;
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.ticks += 1;
                state.polls.push(task.id);
            }
            task.signal.0.store(false, Ordering::Release);
            let waker = Arc::clone(&task.signal).into();
            let mut context = Context::from_waker(&waker);
            let finished = if task.supervised {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    task.work.as_mut().poll(&mut context)
                })) {
                    Ok(poll) => poll.is_ready(),
                    Err(_) => true,
                }
            } else {
                task.work.as_mut().poll(&mut context).is_ready()
            };
            if finished {
                tasks.remove(index);
            }
        }
        Err("SyncScheduleBudget")
    }

    /// Queue a caller and drain every operation it started.
    /// # Errors
    /// Scheduler refusal or a caller that produced no result.
    pub fn run<T>(
        &self,
        seed: u64,
        budget: u64,
        work: impl Future<Output = T>,
    ) -> Result<(T, Vec<u64>), &'static str> {
        let id = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let id = state.next;
            state.next += 1;
            id
        };
        let mut result = None;
        let task = LocalTask {
            supervised: false,
            id,
            signal: Arc::new(Signal(AtomicBool::new(true))),
            work: Box::pin(async {
                result = Some(work.await);
            }),
        };
        let trace = self.drive(seed, budget, vec![task])?;
        Ok((result.ok_or("SyncScheduleResultMissing")?, trace))
    }
}

impl SyncRuntime for SimSyncRuntime {
    fn random_u64(&self) -> u64 {
        granary_core::rng::Rng::next_u64(
            &mut self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .random,
        )
    }
    fn now(&self) -> Instant {
        self.origin + self.elapsed()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        let receive = self.queue(OperationContext::current().attach(work));
        async move { receive.await.map_err(|_| SyncRuntimeError) }
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        let context = OperationContext::current();
        let pause = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.blocking_calls += 1;
            if state
                .pause
                .as_ref()
                .is_some_and(|(at, _)| *at == state.blocking_calls)
            {
                state.pause.take().map(|(_, pause)| pause)
            } else {
                None
            }
        };
        let receive = self.queue(async move {
            crate::sched::yield_once().await;
            if let Some(pause) = pause {
                pause.entered.store(true, Ordering::Release);
                std::future::poll_fn(|cx| {
                    if pause.released.load(Ordering::Acquire) {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
            }
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| context.run(work)))
                .map_err(|_| SyncRuntimeError)
        });
        async move { receive.await.map_err(|_| SyncRuntimeError)? }
    }
    async fn blocking_async<T: Send + 'static, F: Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> Result<T, SyncRuntimeError> {
        // Preserve the blocking seam's scheduled pause, then let the scheduler
        // poll the future alongside the work it awaits, inside the caller's
        // operation wherever this wait is later resumed.
        let context = OperationContext::current();
        let work = self.blocking(work).await?;
        Ok(context.attach(work).await)
    }

    async fn sleep(&self, duration: Duration) {
        let until = self.now() + duration;
        std::future::poll_fn(|cx| {
            if self.now() >= until {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }
    async fn timeout_at<T: Send>(
        &self,
        deadline: Instant,
        work: impl Future<Output = T> + Send,
    ) -> Result<T, SyncRuntimeError> {
        let mut work = std::pin::pin!(work);
        std::future::poll_fn(|cx| {
            if self.now() >= deadline {
                return Poll::Ready(Err(SyncRuntimeError));
            }
            let result = work.as_mut().poll(cx);
            if result.is_pending() {
                cx.waker().wake_by_ref();
            }
            result.map(Ok)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use granary_client::TokioSyncRuntime;

    #[test]
    fn supervised_work_survives_dropped_join_and_replays() {
        let run = |seed| {
            let runtime = Arc::new(SimSyncRuntime::new(TokioSyncRuntime.now()));
            let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
            for _ in 0..3 {
                let count = count.clone();
                drop(runtime.spawn(async move {
                    crate::sched::yield_once().await;
                    count.fetch_add(1, Ordering::Relaxed);
                }));
            }
            let trace = runtime.drain(seed, 100).unwrap();
            assert_eq!(count.load(Ordering::Relaxed), 3);
            trace
        };
        assert_eq!(run(42), run(42));
        assert_ne!(run(42), run(43));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one schedule compares every hop's carried operation against the plain run"
    )]
    fn queued_work_carries_its_callers_operation_without_changing_the_schedule() {
        use granary_client::{CorrelationId, OperationKind, Outcome};
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Self;
            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }
        struct Fixed(u8);
        impl granary_core::secure_random::SecureRandom for Fixed {
            fn fill(
                &mut self,
                dest: &mut [u8],
            ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
                dest.fill(self.0);
                Ok(())
            }
        }
        // Two operations each queue a spawned and a blocking hop; the seed
        // interleaves them. The first also starts a blocking-then-async wait
        // that a third operation resumes. The same run without operation
        // spans is the schedule the carried context must not change.
        let run = |seed: u64, operations: bool| {
            let output = Capture::default();
            let dispatch = granary_client::closed_subscriber(
                granary_client::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                output.clone(),
            );
            let span = |byte| {
                if operations {
                    granary_client::operation_span(
                        OperationKind::Fsync,
                        &CorrelationId::draw(&mut Fixed(byte)).unwrap(),
                    )
                } else {
                    tracing::Span::none()
                }
            };
            let trace = tracing::subscriber::with_default(dispatch, || {
                let runtime = SimSyncRuntime::new(TokioSyncRuntime.now());
                let mut resumed = None;
                for byte in [0x11, 0x22] {
                    let span = span(byte);
                    let _entered = span.enter();
                    drop(runtime.spawn(async {
                        crate::sched::yield_once().await;
                        granary_client::op_begin(OperationKind::Commit);
                    }));
                    drop(runtime.blocking(|| {
                        granary_client::op_end(OperationKind::Commit, Outcome::Ok);
                    }));
                    if resumed.is_none() {
                        let mut wait = Box::pin(runtime.blocking_async(|| async {
                            crate::sched::yield_once().await;
                            granary_client::op_begin(OperationKind::Rebase);
                        }));
                        assert!(
                            wait.as_mut()
                                .poll(&mut Context::from_waker(std::task::Waker::noop()))
                                .is_pending()
                        );
                        resumed = Some(wait);
                    }
                }
                let span = span(0x33);
                let _entered = span.enter();
                let (result, trace) = runtime.run(seed, 100, resumed.unwrap()).unwrap();
                assert!(result.is_ok());
                trace
            });
            let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
            let mut carried: Vec<(bool, bool, Option<String>)> = text
                .lines()
                .filter(|line| {
                    line.contains("\"kind\":\"commit\"") || line.contains("\"kind\":\"rebase\"")
                })
                .map(|line| {
                    (
                        line.contains("\"kind\":\"rebase\""),
                        line.contains("\"event\":\"op.begin\""),
                        line.split_once("\"op\":\"")
                            .and_then(|(_, rest)| rest.split('"').next())
                            .map(str::to_owned),
                    )
                })
                .collect();
            carried.sort();
            (trace, carried)
        };
        let (plain, _) = run(42, false);
        let (schedule, carried) = run(42, true);
        let id = |byte| Some(CorrelationId::draw(&mut Fixed(byte)).unwrap().to_string());
        assert_eq!(
            (schedule, carried),
            (
                plain,
                vec![
                    (false, false, id(0x11)),
                    (false, false, id(0x22)),
                    (false, true, id(0x11)),
                    (false, true, id(0x22)),
                    (true, true, id(0x11)),
                ],
            ),
        );
    }

    #[test]
    fn panicking_supervisor_reports_failure_to_joiner() {
        let runtime = SimSyncRuntime::new(TokioSyncRuntime.now());
        let join = runtime.spawn(async {
            panic!("simulated supervisor panic");
        });
        let (result, trace) = runtime.run(42, 100, join).unwrap();
        assert!(result.is_err(), "supervisor panic became success");
        assert!(!trace.is_empty());
    }

    #[test]
    fn virtual_deadline_and_scheduler_refusals_are_observable() {
        let runtime = Arc::new(SimSyncRuntime::new(TokioSyncRuntime.now()));
        assert_eq!(runtime.drain(1, 10), Err("SyncScheduleEmpty"));
        let task_runtime = runtime.clone();
        let (result, trace) = runtime
            .run(1, 100, async move {
                task_runtime
                    .timeout_at(
                        task_runtime.now() + Duration::from_millis(5),
                        std::future::pending::<()>(),
                    )
                    .await
            })
            .unwrap();
        assert!(result.is_err());
        assert_eq!(trace.len(), 6);
        drop(runtime.spawn(std::future::pending::<()>()));
        assert_eq!(runtime.drain(1, 10), Err("SyncScheduleStalled"));
        let runtime = SimSyncRuntime::new(TokioSyncRuntime.now());
        drop(runtime.spawn(async {
            loop {
                crate::sched::yield_once().await;
            }
        }));
        assert_eq!(runtime.drain(1, 4), Err("SyncScheduleBudget"));
    }
}
