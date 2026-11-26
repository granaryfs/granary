// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::sched` — the sim's own scheduler:
//! the seeded poll loop that picks the next runnable task.
//!
//! Out-of-line: `granary-sim`'s non-test artifact has its
//! own `tests/` directory
//! (`crates/granary-sim/tests/replay_across_processes.rs`,
//! `scenarios.rs`) and its own `[[bin]]`
//! (`src/bin/sim-replay.rs`) — either alone is enough. What
//! does NOT apply: nothing in the workspace depends on
//! `granary-sim`; `granary-sim` depends on `granary-client`,
//! not the reverse. So the module's own tests move out of
//! the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{Scheduler, Task, yield_once};
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

type Log = Rc<RefCell<Vec<String>>>;

/// Returns `Pending` forever and never wakes — the mistake a fake
/// makes when it suspends without arranging a wakeup. Under a no-op
/// waker two of these run to COMPLETION, which is why the scheduler
/// carries a real one.
struct PendsWithoutWaking;

impl Future for PendsWithoutWaking {
    type Output = &'static str;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<&'static str> {
        Poll::Pending
    }
}

/// Returns `Pending` forever but wakes itself every poll: runnable
/// forever, so the stall check cannot see it and only the budget
/// stops it.
struct SpinsForever;

impl Future for SpinsForever {
    type Output = &'static str;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<&'static str> {
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// A task that performs `count` steps, each behind a genuine await
/// point, recording the step it just resumed into.
async fn steps(name: &'static str, count: usize, log: Log) -> &'static str {
    for i in 0..count {
        yield_once().await;
        log.borrow_mut().push(format!("{name}{i}"));
    }
    name
}

/// Three tasks of three steps each — the fixture every measurement
/// in this module's docs is stated against.
fn three_by_three(log: &Log) -> Vec<Task<&'static str>> {
    vec![
        Box::pin(steps("A", 3, Rc::clone(log))),
        Box::pin(steps("B", 3, Rc::clone(log))),
        Box::pin(steps("C", 3, Rc::clone(log))),
    ]
}

/// Three tasks of three steps each, driven under `seed`; returns the
/// order the steps actually ran in, and the run's results.
fn schedule_for(seed: u64) -> (Vec<String>, Vec<&'static str>) {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let tasks = three_by_three(&log);
    let results = Scheduler::new(seed).run(tasks);
    let schedule = log.borrow().clone();
    (schedule, results)
}

fn task_of(label: &str) -> Option<char> {
    label.chars().next()
}

/// How many times the schedule hands off from one task to another.
fn handoffs(schedule: &[String]) -> usize {
    schedule
        .windows(2)
        .filter(|w| task_of(&w[0]) != task_of(&w[1]))
        .count()
}

#[test]
fn results_come_back_in_task_order() {
    let (_, results) = schedule_for(42);
    assert_eq!(results, vec!["A", "B", "C"]);
}

#[test]
fn same_seed_replays_the_same_interleaving() {
    let (first, _) = schedule_for(42);
    let (second, _) = schedule_for(42);
    assert_eq!(first, second);
    // Two empty schedules are also equal, so the equality above
    // cannot stand on its own.
    assert_eq!(first.len(), 9, "{first:?}");
}

#[test]
fn different_seeds_explore_different_interleavings() {
    let (a, _) = schedule_for(42);
    let (b, _) = schedule_for(7);
    assert_ne!(a, b, "the seed changed nothing: {a:?}");
    // What differs must be the ORDER and nothing else: both runs do
    // exactly the same work.
    let (mut sa, mut sb) = (a.clone(), b.clone());
    sa.sort();
    sb.sort();
    assert_eq!(
        sa, sb,
        "the two runs did different work, not the same work in a different order"
    );
}

#[test]
fn tasks_genuinely_interleave() {
    let (schedule, _) = schedule_for(42);
    assert_eq!(schedule.len(), 9, "{schedule:?}");
    // Running each task to completion in turn — the degenerate
    // `join!` shape — leaves exactly one handoff per task boundary,
    // so 3 tasks give 2. Anything more means a task was resumed
    // after another one ran.
    assert!(
        handoffs(&schedule) > 2,
        "schedule is segregated by task: {schedule:?}"
    );
}

/// A future that returns `Pending` without arranging a wakeup runs
/// to completion under a no-op waker — the scheduler would be
/// strictly more lenient than any real executor, and a fake written
/// that way would pass here and deadlock under tokio. It must fail
/// the run instead.
#[test]
#[should_panic(expected = "sim deadlock")]
fn a_task_that_pends_without_waking_stalls_the_run() {
    let tasks: Vec<Task<&'static str>> =
        vec![Box::pin(PendsWithoutWaking), Box::pin(PendsWithoutWaking)];
    let _ = Scheduler::new(42).run(tasks);
}

/// The diagnostic has to say WHICH task, or it sends the reader back
/// to the hang it replaced. Task 0 finishes; task 1 is the stuck one.
#[test]
#[should_panic(expected = "unfinished tasks (by position): [1]")]
fn the_stall_diagnostic_names_the_task_that_never_finished() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let tasks: Vec<Task<&'static str>> = vec![
        Box::pin(steps("A", 3, Rc::clone(&log))),
        Box::pin(PendsWithoutWaking),
    ];
    let _ = Scheduler::new(42).run(tasks);
}

/// The other shape: `Pending` WITH a self-wake stays runnable, so no
/// stall check can see it. Without a budget it spins at ~7.7e8 polls
/// per second and the job hangs rather than failing.
#[test]
#[should_panic(expected = "poll budget exhausted")]
fn a_task_that_spins_exhausts_the_poll_budget() {
    let tasks: Vec<Task<&'static str>> = vec![Box::pin(SpinsForever)];
    let _ = Scheduler::new(42).with_poll_budget(1_000).run(tasks);
}

/// The measurement [`Scheduler::DEFAULT_POLL_BUDGET`] is a multiple
/// of: a task of `n` steps costs `n + 1` polls — one per suspension,
/// one to finish — so this fixture costs exactly 12, and the default
/// budget is four to five orders of magnitude above it.
#[test]
fn a_healthy_run_costs_one_poll_per_step_plus_one() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let results = Scheduler::new(42)
        .with_poll_budget(12)
        .run(three_by_three(&log));
    assert_eq!(results, vec!["A", "B", "C"]);
    assert_eq!(log.borrow().len(), 9);
}

/// The other half of the measurement above: at 11 the budget bites,
/// so 12 is the exact cost rather than a bound that happens to hold.
#[test]
#[should_panic(expected = "poll budget exhausted")]
fn one_poll_fewer_than_the_measured_cost_trips_the_budget() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let _ = Scheduler::new(42)
        .with_poll_budget(11)
        .run(three_by_three(&log));
}

/// Each task's own steps must still run in order, however the tasks
/// are interleaved — a scheduler that reordered *within* a task
/// would satisfy every assertion above.
#[test]
fn a_task_never_runs_its_own_steps_out_of_order() {
    let (schedule, _) = schedule_for(42);
    for name in ['A', 'B', 'C'] {
        let own: Vec<&str> = schedule
            .iter()
            .filter(|l| task_of(l) == Some(name))
            .map(String::as_str)
            .collect();
        let expected = [format!("{name}0"), format!("{name}1"), format!("{name}2")];
        assert_eq!(own, expected, "{schedule:?}");
    }
}
