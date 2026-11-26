// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `JoinAll`'s rotation: a future that never suspends of its own accord
//! cannot starve the others.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll, Waker};

use super::{JoinAll, Joined};

/// The budget one poll of the task gives every future in it, as a
/// runtime's cooperative budget does: whoever is polled first may spend
/// all of it, and a future polled after that finds none and must wait.
const BUDGET: u32 = 128;

/// Spends every unit of the budget it finds, making progress on each, and
/// never finishes: a worker fed a request stream whose log calls complete
/// at once.
struct Greedy(Arc<AtomicU32>);

impl Future for Greedy {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        while self.0.load(Ordering::SeqCst) > 0 {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Needs one unit of the budget to finish: a worker with one request.
struct Needy(Arc<AtomicU32>, Arc<AtomicBool>);

impl Future for Needy {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0.load(Ordering::SeqCst) == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.0.fetch_sub(1, Ordering::SeqCst);
        self.1.store(true, Ordering::SeqCst);
        Poll::Ready(())
    }
}

/// A future joined first that spends every budget it is given does not
/// starve the one joined after it: that one finishes by the second poll
/// of the join, each poll starting with a fresh budget. Were every poll
/// to start at the first slot, the second future would never run.
#[test]
fn a_future_that_spends_every_budget_does_not_starve_the_next() {
    let budget = Arc::new(AtomicU32::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let futures: Vec<Joined<'_>> = vec![
        Box::pin(Greedy(Arc::clone(&budget))),
        Box::pin(Needy(Arc::clone(&budget), Arc::clone(&done))),
    ];
    let mut join = JoinAll::new(futures);
    let mut cx = Context::from_waker(Waker::noop());
    let mut polls = 0;
    while !done.load(Ordering::SeqCst) && polls < 16 {
        budget.store(BUDGET, Ordering::SeqCst);
        assert!(Pin::new(&mut join).poll(&mut cx).is_pending());
        polls += 1;
    }
    assert!(done.load(Ordering::SeqCst), "the second future starved");
    assert!(polls <= 2, "it took {polls} polls");
}
