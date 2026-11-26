// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Polling futures together inside the one `run()` future: the join of
//! the volumes' workers, and the race a worker runs between its
//! publication step and its answers.
//!
//! Workers are joined, never spawned: every worker is polled from the
//! same task, in an order fixed by the poll count, so the engine's
//! interleaving is a property of that order and of the seams' own
//! suspensions, never of a runtime's scheduling. That is what lets the simulator's seed fix a
//! run, and what makes a fence set by one worker visible to every other
//! before any of them takes another step (the fence is a plain flag read
//! in the same task).
//!
//! `tokio::join!` and `tokio::select!` are banned in this workspace
//! (`clippy.toml`): the first takes a fixed number of futures, and the
//! second picks its branch order from entropy the simulator cannot seed.
//! These are the dynamic-length join and the fixed-order race the engine
//! needs, and nothing more.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A worker's future, as the join holds it.
pub(crate) type Joined<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Polls every unfinished future on each poll, and finishes when all
/// have. After a pass in which any future finished it makes another pass
/// at once, so a future that finished (having set a flag or released the
/// token, say) is seen by the others in the same poll, whatever their
/// wakers were last told.
///
/// **Each poll starts one slot later than the last**, wrapping. A future
/// that never suspends (a worker whose log calls complete at once, fed a
/// request stream) spends the task's cooperative budget, after which the
/// futures polled later in the same poll find their receives and locks
/// `Pending` before they can queue. Were every poll to start at the same
/// slot, that future would spend every budget and starve the rest; with
/// the rotation each future is polled first once in every `n` polls. The
/// order is a function of the poll count alone.
pub(crate) struct JoinAll<'a> {
    futures: Vec<Option<Joined<'a>>>,
    /// The slot the next poll starts at.
    start: usize,
}

impl std::fmt::Debug for JoinAll<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinAll")
            .field("unfinished", &self.futures.iter().flatten().count())
            .finish()
    }
}

impl<'a> JoinAll<'a> {
    pub(crate) fn new(futures: impl IntoIterator<Item = Joined<'a>>) -> Self {
        Self {
            futures: futures.into_iter().map(Some).collect(),
            start: 0,
        }
    }
}

impl Future for JoinAll<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let n = this.futures.len();
        let start = this.start;
        this.start = if n == 0 { 0 } else { (start + 1) % n };
        loop {
            let mut finished = false;
            // `start < n` whenever there is a slot at all, so the split
            // is in range: the slots from `start` on, then those before it.
            let (before, from) = this.futures.split_at_mut(start.min(n));
            for (offset, slot) in from.iter_mut().chain(before.iter_mut()).enumerate() {
                if let Some(future) = slot
                    && {
                        #[cfg(test)]
                        let _poll = tracing::trace_span!(
                            "authority_worker_poll",
                            slot = (start + offset) % n,
                        )
                        .entered();
                        #[cfg(not(test))]
                        let _ = offset;
                        future.as_mut().poll(cx).is_ready()
                    }
                {
                    *slot = None;
                    finished = true;
                }
            }
            if this.futures.iter().all(Option::is_none) {
                return Poll::Ready(());
            }
            if !finished {
                return Poll::Pending;
            }
        }
    }
}

/// Which of a [`race`]'s two futures finished first.
#[derive(Debug)]
pub(crate) enum Raced<A, B> {
    /// The first.
    First(A),
    /// The second.
    Second(B),
}

/// Polls `first`, then `second`, on each poll, and finishes with the
/// first one to finish. Neither is dropped: both are borrowed, so the one
/// that did not finish stays where its owner pinned it, to be polled
/// again or driven to its end. The fixed order makes a run a function of
/// the schedule alone.
pub(crate) struct Race<'a, A: Future, B: Future> {
    first: Pin<&'a mut A>,
    second: Pin<&'a mut B>,
}

impl<A: Future, B: Future> std::fmt::Debug for Race<'_, A, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Race").finish_non_exhaustive()
    }
}

/// Race `first` against `second` (see [`Race`]). Neither may have
/// finished already.
pub(crate) const fn race<'a, A: Future, B: Future>(
    first: Pin<&'a mut A>,
    second: Pin<&'a mut B>,
) -> Race<'a, A, B> {
    Race { first, second }
}

impl<A: Future, B: Future> Future for Race<'_, A, B> {
    type Output = Raced<A::Output, B::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Poll::Ready(out) = this.first.as_mut().poll(cx) {
            return Poll::Ready(Raced::First(out));
        }
        if let Poll::Ready(out) = this.second.as_mut().poll(cx) {
            return Poll::Ready(Raced::Second(out));
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests;
