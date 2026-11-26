// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The sim owns its scheduler: a poll loop that
//! picks the next runnable task with the seeded [`Rng`].
//!
//! **Why not `join!`, `spawn` or `select!`.** A concurrency scenario has
//! to be two things at once — genuinely contended and exactly
//! reproducible — and every off-the-shelf option gives up one of them.
//!
//! - **tokio promises nothing.** Its `tokio::runtime` module docs
//!   warn that the described current-thread behaviour "may change in future
//!   versions of Tokio".
//!   Determinism under `current_thread` remains outside the runtime's contract;
//!   it is an emergent property of the version in the lockfile. A harness
//!   whose replay rests on it can therefore break silently when that
//!   dependency changes.
//! - **`select!` is seeded from ambient entropy.** It randomises branch
//!   order by design, from a runtime RNG the sim cannot control:
//!   `Builder::rng_seed` is `cfg(tokio_unstable)` and so unavailable on
//!   the pinned stable `=1.53.1`. Measured over 200 iterations of two
//!   always-ready branches, branch A won 89/200 in one process and
//!   109/200 in the next. `select!` is therefore banned in this crate and
//!   in any code the sim drives.
//! - **`join!` on a current-thread runtime is degenerate.** The
//!   first-listed future is polled first and, for work that never truly
//!   blocks, runs to completion before the second is polled at all: a
//!   real race test against a real server measured 20/20 wins for the
//!   first future. Two publishers under `join!` never contend, so a
//!   scenario asserting "exactly one wins the contested seq" passes
//!   without a race ever happening. That is the exact degeneracy
//!   `tasks_genuinely_interleave` asserts against.
//! - **Two OS threads** contend genuinely — the live-backend lane's race
//!   test runs on them — precisely the nondeterminism this crate exists
//!   to exclude.
//!
//! Sequencing the interleaving here is the only option that is both. It
//! needs no tokio at all, and takes none: granary-sim has no tokio
//! dependency, so this loop is the only thing that ever polls a future
//! in this crate and there is no second scheduler to disagree with it.
//! That absence is also what enforces the bans above HERE — a macro from
//! a crate that is not in the graph cannot be written — so the clippy
//! entries that carry the bans (`clippy.toml`) are live only in the
//! crates the sim drives, which do have tokio. Adding tokio to this
//! crate would swap a structural guarantee for a lint, and arm those
//! entries here.
//!
//! **A real waker, under `unsafe_code = "forbid"`.** A hand-rolled
//! `RawWaker` vtable does not compile in this workspace — but that is a
//! fact about `RawWaker`, not about wakers. [`std::task::Wake`] is a SAFE
//! trait and `Waker::from(Arc<W>)` needs no `unsafe`, so the scheduler
//! carries one wakeup flag per task and the ban costs it nothing.
//! `Waker::noop()` also compiles, and is strictly worse: it gives up both
//! properties below.
//!
//! **What "runnable" means here, and why it is not "unfinished".** A task
//! is runnable when its own waker has been signalled since the last time
//! it was polled. Every task starts runnable, and the flag is consumed
//! immediately before each poll, so a task that returns `Pending` without
//! arranging a wakeup is not polled again. Two consequences, and both are
//! the point:
//!
//! - **Pend-without-wake is caught.** Under a no-op waker every
//!   unfinished task is runnable forever, so two futures that return
//!   `Pending` and NEVER call `wake` still run to completion — the
//!   harness would be strictly more lenient than any real executor, and a
//!   fake written that way would pass here and deadlock under tokio.
//! - **A stall is a test failure, not a hung job.** When no unfinished
//!   task is runnable, no further progress is possible: the run is
//!   single-threaded and nothing external can wake anything. So
//!   [`Scheduler::run`] panics, naming the tasks that never finished.
//!
//! **The poll budget covers the other shape.** A task that returns
//! `Pending` and DOES wake itself every poll stays runnable and spins —
//! measured at 7.7e8 polls per second, with no yield to the OS. Deadlock
//! is one of the two headline bug classes a deterministic sim exists to
//! find, and a tripwire that reports by hanging is not a tripwire, so the
//! loop counts polls against [`Scheduler::DEFAULT_POLL_BUDGET`] and fails
//! the same way. A FIXED budget stays deterministic — it is a function of
//! the schedule, not of wall time — so it costs replay nothing.
//!
//! **The schedule distribution is skewed, and one seed is not a race.**
//! Measured over 200 000 seeds against the shape of the three-task,
//! three-step fixture below — the sweep itself is NOT in the tree, so
//! the figures in this paragraph are a recorded measurement and not
//! something any test re-checks: the loop reaches all 1680 reachable
//! interleavings, which is the property that matters — but **7.14% of
//! seeds produce a fully segregated schedule**, the exact `join!`-shaped
//! degeneracy described above, and the hottest interleaving beats the
//! coldest by roughly 175:1 *toward* degeneracy. That is a consequence of
//! drawing uniformly among runnable tasks at every step, not a defect,
//! and the scheduler is not the place to fix it. **The consequence for
//! callers is the part to act on: a scenario that asserts a race property
//! on a single seed is roughly 1-in-14 vacuous.** So a scenario sweeps a
//! range of seeds, and/or asserts a handoff floor on the schedule it
//! actually got, rather than trusting one seed to have contended.
//! `tasks_genuinely_interleave` pins seed 42, which does interleave; that
//! is a fixture check, not a licence to single-seed a race.

use crate::rng::Rng;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

/// A task the scheduler drives.
///
/// Boxed and pinned because the tasks in one run are distinct future
/// types — `publish` under one fault schedule is not the same type as
/// `publish` under another — and a `Vec` needs one type. Not `Send`: the
/// whole run is single-threaded by design. The fakes still share their
/// state through `Arc`/`Mutex`, because the seam traits they implement
/// require `Send + Sync` and `Send` futures.
pub type Task<T> = Pin<Box<dyn Future<Output = T>>>;

/// Suspend exactly once, then resume.
///
/// This is the sim's await point. Every fake operation awaits it exactly
/// once, which is what gives the scheduler a boundary to interleave at:
/// without a genuine suspension the first task polled runs to completion
/// and nothing ever contends (the ready-shaped-fake defect — a fake that
/// never pends makes interleaving impossible however the loop is
/// written).
///
/// # Cancellation safety
///
/// Cancel-safe: it holds nothing and completes nothing, so dropping it
/// mid-flight loses no work. Stated because the house rule asks it of
/// every `async fn` a `select!` could reach — though `select!` is banned
/// in this crate and in any code the sim drives.
pub async fn yield_once() {
    /// Pending on the first poll, ready on every one after.
    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                // Load-bearing, not ceremony: the scheduler consumes
                // this task's wakeup flag before every poll, so a
                // `Pending` that arranged no wakeup is never polled
                // again and stalls the run. That is also the contract —
                // a future that quietly relies on its executor polling
                // it anyway is a future that hangs under any other one.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    YieldOnce(false).await;
}

/// One task's wakeup flag — the whole of the sim's waker.
///
/// `AtomicBool` rather than `Cell` because [`Wake`] requires
/// `Send + Sync`; the run is single-threaded, so the orderings only have
/// to be self-consistent.
#[derive(Debug)]
struct TaskWaker {
    woken: AtomicBool,
}

impl TaskWaker {
    /// A flag that starts set: every task is runnable before its first
    /// poll.
    fn runnable() -> Self {
        Self {
            woken: AtomicBool::new(true),
        }
    }

    /// Whether a wakeup is outstanding.
    fn is_woken(&self) -> bool {
        self.woken.load(Ordering::Acquire)
    }

    /// Consume the outstanding wakeup, immediately before polling. What
    /// the task does during that poll decides whether it is runnable
    /// again.
    fn consume(&self) {
        self.woken.store(false, Ordering::Release);
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
    }
}

/// A seeded poll loop over a set of tasks.
///
/// One scheduler drives one run. The [`Rng`] is consumed as the run
/// proceeds, so a scenario that replays a seed must build a fresh
/// scheduler rather than reuse one.
#[derive(Debug, Clone)]
pub struct Scheduler {
    rng: Rng,
    poll_budget: u64,
}

impl Scheduler {
    /// How many polls one [`Scheduler::run`] may issue before it calls
    /// the run stuck.
    ///
    /// **How this number was chosen.** A healthy run polls each task
    /// once per suspension plus once to finish, so its poll count is a
    /// small multiple of the work it does: the three-task, three-step
    /// fixture in this module's tests measures exactly 12, and a
    /// publisher's whole publish is 8–16 store operations, so a handful
    /// of publishers costs low hundreds. A million is three to four
    /// orders of magnitude of headroom over anything a scenario can
    /// legitimately reach, and a spinning task — measured at 7.7e8 polls
    /// per second — exhausts it in about a millisecond, so the
    /// diagnostic is free. Override it with
    /// [`Scheduler::with_poll_budget`] rather than raising it here.
    pub const DEFAULT_POLL_BUDGET: u64 = 1_000_000;

    /// A scheduler whose choices are drawn from `seed`.
    ///
    /// The sequence selector is fixed at 54 — the value the reference
    /// vector pins — and a scenario varies only its `seed`. What that
    /// buys, stated exactly: `initstate` and `initseq` are independent
    /// PARAMETERS, but with the increment fixed a PCG-32 has exactly ONE
    /// orbit, so two seeds are two OFFSETS on the same cycle rather than
    /// two independent streams. That is sufficient here, and it was
    /// measured rather than assumed — over 200 000 seeds every start
    /// state is distinct and no pair's streams overlap within 256 draws,
    /// which is far more than a run consumes. A harness that needed
    /// genuinely disjoint streams would have to vary `initseq` instead.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Rng::seeded(seed, 54),
            poll_budget: Self::DEFAULT_POLL_BUDGET,
        }
    }

    /// Replace [`Scheduler::DEFAULT_POLL_BUDGET`] for this run.
    ///
    /// For a scenario that legitimately polls more than the default, and
    /// for the tests that prove the budget bites. A fixed budget is
    /// deterministic whatever its value, so this changes no schedule.
    #[must_use]
    pub const fn with_poll_budget(mut self, polls: u64) -> Self {
        self.poll_budget = polls;
        self
    }

    /// Drive every task to completion, polling a seed-chosen runnable
    /// task at each step. Results come back in **task order**, not in
    /// completion order, so a caller can name its publishers positionally
    /// however the schedule fell out.
    ///
    /// # Panics
    ///
    /// Deliberately, in the two ways a run can fail to finish — both are
    /// the deadlock diagnostic, not a defect:
    ///
    /// - **Stalled**: no unfinished task has an outstanding wakeup, so
    ///   nothing can ever make progress. The message names the
    ///   unfinished task indices.
    /// - **Budget exhausted**: more than [`Scheduler::with_poll_budget`]
    ///   polls without every task finishing — a task that pends and
    ///   wakes itself forever. Same message shape.
    pub fn run<T>(&mut self, mut tasks: Vec<Task<T>>) -> Vec<T> {
        let count = tasks.len();
        let wakers: Vec<Arc<TaskWaker>> = (0..count)
            .map(|_| Arc::new(TaskWaker::runnable()))
            .collect();
        let mut results: Vec<Option<T>> = tasks.iter().map(|_| None).collect();
        let mut unfinished: Vec<usize> = (0..count).collect();
        let mut polls: u64 = 0;

        while !unfinished.is_empty() {
            // In a healthy run this is every unfinished task — the fakes
            // suspend on `yield_once`, which wakes before it pends — so
            // the draw below sees the same range it always did and no
            // seed changes meaning.
            let runnable: Vec<usize> = unfinished
                .iter()
                .copied()
                .filter(|i| wakers.get(*i).is_some_and(|w| w.is_woken()))
                .collect();
            assert!(
                !runnable.is_empty(),
                "sim deadlock: {} task(s) never finished and none has a wakeup \
                 outstanding, so no further progress is possible; unfinished \
                 tasks (by position): {unfinished:?}. A future returned Pending \
                 without arranging a wakeup — it would hang under any executor.",
                unfinished.len()
            );
            polls = polls.saturating_add(1);
            assert!(
                polls <= self.poll_budget,
                "sim poll budget exhausted: {polls} polls without finishing; \
                 unfinished tasks (by position): {unfinished:?}. A task is \
                 spinning — Pending with an immediate self-wake — and never \
                 completes. Raise the budget with Scheduler::with_poll_budget \
                 only if the run genuinely needs it."
            );
            // The count is the harness's own task list, never untrusted
            // input, and a `Vec` of that many boxed futures cannot be
            // built on any machine this runs on — but the conversions
            // are written totally rather than cast, so no input can make
            // this line panic or silently wrap.
            let n = u32::try_from(runnable.len()).unwrap_or(u32::MAX);
            let pick = usize::try_from(self.rng.below(n)).unwrap_or(0);
            let Some(&idx) = runnable.get(pick) else {
                break;
            };
            let (Some(task), Some(flag)) = (tasks.get_mut(idx), wakers.get(idx)) else {
                break;
            };
            // Consume BEFORE the poll, so a wake raised during the poll
            // counts and a `Pending` that raised none does not.
            flag.consume();
            let waker = Waker::from(Arc::clone(flag));
            let mut cx = Context::from_waker(&waker);
            if let Poll::Ready(value) = task.as_mut().poll(&mut cx) {
                if let Some(slot) = results.get_mut(idx) {
                    *slot = Some(value);
                }
                // `retain`, not `remove(pick)`: `Vec::remove` panics on
                // a stale index, and this one is total. It removes by
                // task identity rather than by position, and it keeps
                // the surviving order — which `swap_remove` would not,
                // making the meaning of a seed depend on which task
                // happened to finish first.
                unfinished.retain(|&i| i != idx);
            }
        }

        // Every entry is `Some`: the loop exits only when `unfinished`
        // is empty, and an index leaves it only after its result is
        // stored.
        let out: Vec<T> = results.into_iter().flatten().collect();
        // The two `break`s above are unreachable, but `flatten` would
        // collapse the hole either left rather than surface it, shifting
        // every later result down one position and quietly falsifying
        // the task-order promise above.
        debug_assert_eq!(out.len(), count, "a task's result went missing");
        out
    }
}

#[cfg(test)]
mod tests;
