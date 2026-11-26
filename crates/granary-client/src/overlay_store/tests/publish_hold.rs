// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! An authority send held open by the test controller: it stays one
//! unresolved attempt until released, and a caller that stops waiting drops
//! it unanswered. Any authority fixture can hold its sends through one.

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

#[derive(Debug, Default)]
pub(crate) struct PublishHold {
    entered: Notify,
    release: Notify,
    held: AtomicUsize,
}
impl PublishHold {
    /// Hold this send until the controller releases it.
    pub(crate) async fn hold(&self) {
        self.held.fetch_add(1, Ordering::AcqRel);
        self.entered.notify_waiters();
        self.release.notified().await;
    }
    /// Wait until `count` sends in all have entered the hold.
    pub(crate) async fn entered(&self, count: usize) {
        loop {
            let entered = self.entered.notified();
            tokio::pin!(entered);
            entered.as_mut().enable();
            if self.held.load(Ordering::Acquire) >= count {
                return;
            }
            entered.await;
        }
    }
    /// Release one held send, or the next one to enter.
    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}
