// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Process-local shared owner of the single live [`WritableStore`] mediator.

use super::{
    BundleOverlay, BundleRefusal, CoordinationError, OverlayError, OverlayIo, WritableOverlay,
    WritableStore,
};
// Keep crate::sync::refused; super::refused records an intent coordination failure metric.
use crate::sync::refused;
use granary_core::hash::GrainId;
use std::sync::{Arc, Mutex, TryLockError};

/// Process-local shared owner of the single live [`WritableStore`] mediator.
#[derive(Debug)]
pub struct SharedWritableStore<P: OverlayIo = crate::OverlayDisk>(Arc<Mutex<WritableStore<P>>>);

impl<P: OverlayIo> Clone for SharedWritableStore<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<P: OverlayIo> SharedWritableStore<P> {
    /// Copy the retained overlay scalars without waiting for the producer.
    /// # Errors
    /// Busy, poisoned or unavailable producer, or a retained closed failure.
    pub fn try_overlay_bundle(&self) -> Result<BundleOverlay, BundleRefusal> {
        let guard = self.0.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => BundleRefusal::TimedOut,
            TryLockError::Poisoned(_) => BundleRefusal::Unavailable,
        })?;
        guard.overlay_bundle()
    }

    /// Wrap the admitted [`WritableStore`] in its single shared mutex owner.
    #[must_use]
    pub fn new(store: WritableStore<P>) -> Self {
        Self(Arc::new(Mutex::new(store)))
    }

    /// Hand the [`WritableStore`] back from its last owner: `None` while
    /// another handle still shares it, or once a panic has poisoned it.
    pub(crate) fn into_inner(self) -> Option<WritableStore<P>> {
        Arc::try_unwrap(self.0).ok()?.into_inner().ok()
    }

    /// Return a clone of the underlying `Arc<Mutex<WritableStore<P>>>`.
    #[must_use]
    pub fn as_arc(&self) -> Arc<Mutex<WritableStore<P>>> {
        Arc::clone(&self.0)
    }

    /// Execute one synchronous local transaction under the mediator lock.
    ///
    /// Callers are responsible for keeping transaction closures bounded in duration.
    ///
    /// # Errors
    /// Mediator lock poison or the inner coordination refusal.
    pub fn with<T>(
        &self,
        action: impl FnOnce(&mut WritableStore<P>) -> Result<T, CoordinationError>,
    ) -> Result<T, CoordinationError> {
        #[cfg(test)]
        begin_acquisition();
        let result = self.locked(action);
        #[cfg(test)]
        release_acquisition();
        result
    }

    fn locked<T>(
        &self,
        action: impl FnOnce(&mut WritableStore<P>) -> Result<T, CoordinationError>,
    ) -> Result<T, CoordinationError> {
        let mut guard = self.0.lock().map_err(|poisoned| {
            poisoned.get_ref().floor_changed.notify_waiters();
            refused("SyncMediatorPoisoned")
        })?;
        let result = action(&mut guard);
        if result.is_err() {
            guard.floor_changed.notify_waiters();
        }
        result
    }

    pub(crate) fn check_readiness(&self) -> Result<(), CoordinationError> {
        self.with(WritableStore::check_readiness)
    }

    pub(crate) fn check_quiescent(&self) -> Result<(), CoordinationError> {
        self.with(WritableStore::check_quiescent)
    }

    pub(crate) fn overlay_transaction<T>(
        &self,
        local: impl FnOnce(&mut WritableOverlay<'_, P>) -> Result<T, OverlayError>,
    ) -> Result<T, CoordinationError> {
        self.with(|store| {
            store.guard_view()?;
            store.overlay_transaction(local)
        })
    }

    pub(crate) fn leased(&self, inode: u64) -> Result<bool, CoordinationError> {
        self.with(|store| Ok(store.object_leases.contains_key(&inode)))
    }

    pub(crate) fn promote_holds(
        &self,
        node: &crate::OverlayEntry,
        handles: u64,
    ) -> Result<(), CoordinationError> {
        self.with(|store| {
            store.guard_view()?;
            let leases = store.object_leases.get(&node.inode).copied();
            let holds = handles
                .checked_add(
                    leases
                        .filter(|(_, stage)| stage.is_none())
                        .map_or(0, |(count, _)| count),
                )
                .ok_or_else(|| refused("SyncLeaseExhausted"))?;
            let stage =
                store.overlay_transaction(|overlay| overlay.open_stage_holds(&node.path, holds))?;
            if let Some(lease) = store.object_leases.get_mut(&node.inode) {
                lease.1 = Some(stage);
            }
            Ok(())
        })
    }

    /// Release one object lease hold.
    ///
    /// Drop-only contract: called only on [`ObjectLease`] drop. Poison still
    /// closes admission; only these memory-only lease counters are recovered
    /// so a failed supervisor cannot strand its stage hold.
    pub(crate) fn release_lease(&self, inode: u64) -> Result<(), CoordinationError> {
        let mut store = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (count, stage) = store
            .object_leases
            .get(&inode)
            .copied()
            .ok_or_else(|| refused("SyncLeaseMissing"))?;
        if count == 1 {
            store.object_leases.remove(&inode);
            store.replaced_leases.remove(&inode);
        } else {
            store.object_leases.insert(inode, (count - 1, stage));
        }
        if let Some(stage) = stage {
            store.release_stage_lease(stage)?;
        }
        if !store.has_open_write_handles() {
            store.coalesce_wake.notify_waiters();
        }
        Ok(())
    }

    /// Whether a shutdown has closed the store to user mutations.
    pub(crate) fn mutations_closed(&self) -> Result<bool, CoordinationError> {
        self.with(|store| Ok(store.mutations_closed()))
    }

    /// Admit one sync at the adapter: refused once a shutdown has closed the
    /// store, and otherwise counted until the returned guard drops. The latch
    /// is read and the count taken in one acquisition, the one a shutdown's
    /// close takes too, so its drain either waits for this sync or this sync
    /// is refused.
    pub(crate) fn admit_sync(&self) -> Result<AdmittedSync<P>, CoordinationError> {
        self.with(|store| {
            if store.mutations_closed() {
                return Err(OverlayError::MutationsClosed.into());
            }
            // One count per admitted sync: it cannot reach the integer's end.
            store.admitted_syncs = store.admitted_syncs.saturating_add(1);
            Ok(())
        })?;
        Ok(AdmittedSync(self.clone()))
    }

    pub(crate) fn release_stage(&self, stage: u64) -> Result<(), CoordinationError> {
        self.with(|store| store.release_stage(stage))
    }

    pub(crate) fn put_immutable(
        &self,
        id: GrainId,
        bytes: &[u8],
    ) -> Result<bool, CoordinationError> {
        self.with(|store| store.put_immutable(id, bytes))
    }

    #[cfg(test)]
    pub(crate) fn seal_lease_for_test(
        &self,
        inode: u64,
    ) -> Result<Option<crate::SyncBoundary>, CoordinationError> {
        self.with(|store| store.seal_lease(inode))
    }

    #[cfg(test)]
    pub(crate) fn phase_for_test(
        &self,
        phase: granary_core::overlay_ownership::Phase,
    ) -> Result<(), CoordinationError> {
        self.with(|store| store.phase_for_test(phase))
    }

    #[cfg(test)]
    pub(crate) fn get_mut_for_test(&mut self) -> &mut WritableStore<P> {
        Arc::get_mut(&mut self.0)
            .expect("direct mutable mediator access requires unshared store; use shared_mediator().with(...) when SyncEngine is attached")
            .get_mut()
            .expect("unpoisoned mediator mutex")
    }
}

/// One sync admitted at the adapter, counted until it is answered or its
/// job is dropped unstarted.
#[derive(Debug)]
pub(crate) struct AdmittedSync<P: OverlayIo>(SharedWritableStore<P>);

impl<P: OverlayIo> Drop for AdmittedSync<P> {
    /// Drop-only release, as [`SharedWritableStore::release_lease`]'s: the
    /// memory-only count is recovered from a poisoned mediator too, so a
    /// failed sync cannot hold a shutdown's drain.
    fn drop(&mut self) {
        let mut store = self
            .0
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.admitted_syncs = store.admitted_syncs.saturating_sub(1);
        store.floor_changed.notify_waiters();
    }
}

/// Start counting this thread's acquisitions through
/// [`SharedWritableStore::with`] and the overlay transactions each one runs.
/// With `after = Some((n, hook))`, `hook` runs once acquisition `n` (counted
/// from 1) has released the lock and before the next one begins. The record
/// is per thread, not per store.
#[cfg(test)]
pub(crate) fn track_acquisitions_for_test(after: Option<(u64, Box<dyn FnOnce()>)>) {
    ACQUISITIONS.with_borrow_mut(|acquisitions| {
        *acquisitions = Acquisitions {
            tracking: true,
            after,
            ..Acquisitions::default()
        };
    });
}

/// The acquisitions begun since tracking started, and the ordinal of each
/// one whose action ran an overlay transaction.
#[cfg(test)]
pub(crate) fn acquisitions_for_test() -> (u64, Vec<u64>) {
    ACQUISITIONS.with_borrow(|acquisitions| (acquisitions.begun, acquisitions.transactions.clone()))
}

/// One thread's tracked acquisitions; see [`track_acquisitions_for_test`].
#[cfg(test)]
#[derive(Default)]
struct Acquisitions {
    tracking: bool,
    begun: u64,
    held: Option<u64>,
    transactions: Vec<u64>,
    after: Option<(u64, Box<dyn FnOnce()>)>,
}

#[cfg(test)]
std::thread_local! {
    static ACQUISITIONS: std::cell::RefCell<Acquisitions> = std::cell::RefCell::new(Acquisitions::default());
}

#[cfg(test)]
fn begin_acquisition() {
    ACQUISITIONS.with_borrow_mut(|acquisitions| {
        if acquisitions.tracking {
            acquisitions.begun += 1;
            acquisitions.held = Some(acquisitions.begun);
        }
    });
}

/// Run the armed hook once its acquisition has released the lock, with the
/// record no longer borrowed, so the hook may acquire the mediator itself.
#[cfg(test)]
fn release_acquisition() {
    let hook = ACQUISITIONS.with_borrow_mut(|acquisitions| {
        let released = acquisitions.held.take()?;
        if acquisitions.after.as_ref()?.0 != released {
            return None;
        }
        acquisitions.after.take().map(|(_, hook)| hook)
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Note that the acquisition this thread holds ran an overlay transaction.
#[cfg(test)]
pub(super) fn record_transaction() {
    ACQUISITIONS.with_borrow_mut(|acquisitions| {
        if let Some(held) = acquisitions.held {
            acquisitions.transactions.push(held);
        }
    });
}
