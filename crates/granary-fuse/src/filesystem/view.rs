// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The writable view's kernel identities, times and install gate.
//!
//! An install moves the mount to a new view under the adapter gate. It re-keys
//! the paths whose identity changed, so the kernel's next LOOKUP allocates a
//! fresh inode while a held one keeps its displaced metadata. The gate is
//! taken before the [`ViewSlot`] mutex, never the reverse, and nothing waits
//! while it holds the gate.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
use std::time::SystemTime;

use fuser::{OpenAccMode, OpenFlags};
use granary_vfs::{HandleTable, InodeTable, PathKey};

use super::MountInner;
use crate::{MountBackend, OverlayNode};

/// Sends the kernel the invalidations a closed view owes its held inodes.
pub trait ViewNotifier: Send + Sync {
    /// Drops the kernel's cached attributes and pages for `ino`.
    ///
    /// # Errors
    ///
    /// The kernel's refusal of the notification.
    fn inval_inode(&self, ino: u64) -> std::io::Result<()>;
}

impl ViewNotifier for fuser::Notifier {
    fn inval_inode(&self, ino: u64) -> std::io::Result<()> {
        fuser::Notifier::inval_inode(self, fuser::INodeNo(ino), 0, 0)
    }
}

/// Why [`ViewHandle::try_install`] did not run its action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotBusy {
    /// The adapter state is gone: a preparation unwound, the mount was
    /// destroyed, or the filesystem was dropped. No later attempt can run.
    Abandoned,
    /// A preparation holds the adapter state. Later preparations now wait
    /// for the install, and the slot's return wakes the registered waker.
    Taken,
    /// A callback panicked while holding the adapter gate.
    Poisoned,
}

#[derive(Debug, Default)]
struct SlotState {
    install_waiting: bool,
    abandoned: bool,
}

type Waker = Arc<dyn Fn() + Send + Sync>;

/// The slot protocol between preparations, which take the adapter state out
/// of its gate across a network wait, and an install, which needs it present.
#[derive(Default)]
pub(super) struct ViewSlot {
    state: Mutex<SlotState>,
    cleared: Condvar,
    waker: OnceLock<Waker>,
    #[cfg(test)]
    pub(super) wait_hook: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl std::fmt::Debug for ViewSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewSlot")
            .field("state", &self.state)
            .field("waker", &self.waker.get().is_some())
            .finish_non_exhaustive()
    }
}

impl ViewSlot {
    fn state(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a preparation must let a waiting install go first.
    pub(super) fn install_waiting(&self) -> bool {
        let state = self.state();
        state.install_waiting && !state.abandoned
    }

    /// Blocks a preparation, holding nothing but this mutex, until no install
    /// waits for the slot. Bounded by the install's own exit, which always
    /// clears the flag.
    pub(super) fn wait_for_install(&self) {
        let state = self.state();
        #[cfg(test)]
        if state.install_waiting
            && let Some(hook) = self
                .wait_hook
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
        {
            hook();
        }
        drop(
            self.cleared
                .wait_while(state, |state| state.install_waiting && !state.abandoned)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// A preparation restored the adapter state.
    pub(super) fn returned(&self) {
        self.wake();
    }

    /// The adapter state will never return.
    pub(super) fn abandon(&self) {
        self.state().abandoned = true;
        self.wake();
    }

    fn clear_waiting(&self) {
        self.state().install_waiting = false;
        self.cleared.notify_all();
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.get() {
            waker();
        }
        self.cleared.notify_all();
    }
}

/// The install's handle on a writable mount's adapter state.
///
/// The handle is weak: the engine owns the install, which owns this handle,
/// while the mount reaches the engine through its own jobs. A strong handle
/// would keep a mount alive that its session has already dropped.
pub struct ViewHandle<B> {
    inner: Weak<Mutex<Option<MountInner<B>>>>,
    slot: Arc<ViewSlot>,
    notifier: Option<Arc<dyn ViewNotifier>>,
}

impl<B> std::fmt::Debug for ViewHandle<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewHandle")
            .field("slot", &self.slot)
            .field("notifier", &self.notifier.is_some())
            .finish_non_exhaustive()
    }
}

impl<B: MountBackend> super::GranaryFs<B> {
    /// The handle an install uses to reach this mount's adapter state.
    #[must_use]
    pub fn view_handle(&self) -> ViewHandle<B> {
        ViewHandle {
            inner: Arc::downgrade(&self.inner),
            slot: self.view_slot.clone(),
            notifier: None,
        }
    }
}

impl<B: MountBackend> ViewHandle<B> {
    /// Runs a read-only observation while the adapter gate is immediately available.
    ///
    /// # Errors
    ///
    /// Hands `action` back unspent when the backend is gone or the gate is held
    /// or poisoned. Observation reads the install slot's state only to tell a
    /// preparation's claim from abandonment, and never changes it.
    pub fn try_observe<F, R>(&self, action: F) -> Result<R, (SlotBusy, F)>
    where
        F: FnOnce(&B) -> R,
    {
        let Some(gate) = self.inner.upgrade() else {
            return Err((SlotBusy::Abandoned, action));
        };
        let guard = match gate.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Err((SlotBusy::Taken, action)),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err((SlotBusy::Poisoned, action));
            }
        };
        let Some(MountInner { backend, .. }) = guard.as_ref() else {
            let busy = if self.slot.state().abandoned {
                SlotBusy::Abandoned
            } else {
                SlotBusy::Taken
            };
            return Err((busy, action));
        };
        Ok(action(backend))
    }

    /// Attaches the notifier that [`Self::revoke`] sends through. A handle
    /// without one revokes nothing.
    pub fn set_notifier(&mut self, notifier: Arc<dyn ViewNotifier>) {
        self.notifier = Some(notifier);
    }

    /// Registers the waker called whenever a preparation returns or abandons
    /// the slot, and says whether it was registered. The first registration
    /// stands: a later one is refused, never a replacement.
    #[must_use]
    pub fn on_slot_returned(&self, waker: Arc<dyn Fn() + Send + Sync>) -> bool {
        self.slot.waker.set(waker).is_ok()
    }

    /// Whether a waker is already registered for the slot.
    #[must_use]
    pub fn has_slot_waker(&self) -> bool {
        self.slot.waker.get().is_some()
    }

    /// Runs `action` under the adapter gate with the adapter state present.
    ///
    /// Blocks while another holder has the gate. A successful run clears the
    /// install's claim on the slot, so waiting preparations proceed.
    ///
    /// # Errors
    ///
    /// Hands `action` back unspent with [`SlotBusy`] when the state is
    /// abandoned, taken by a preparation, or behind a poisoned gate.
    pub fn try_install<F, R>(&self, action: F) -> Result<R, (SlotBusy, F)>
    where
        F: FnOnce(&mut B, &mut ViewAdapter<'_>) -> R,
    {
        let Some(gate) = self.inner.upgrade() else {
            return Err((SlotBusy::Abandoned, action));
        };
        let Ok(mut guard) = gate.lock() else {
            let busy = if self.slot.state().abandoned {
                SlotBusy::Abandoned
            } else {
                SlotBusy::Poisoned
            };
            return Err((busy, action));
        };
        let state = self.slot.state();
        if state.abandoned {
            return Err((SlotBusy::Abandoned, action));
        }
        let Some(MountInner {
            backend,
            inodes,
            handles,
            write_handles,
            view,
            ..
        }) = guard.as_mut()
        else {
            let mut state = state;
            state.install_waiting = true;
            return Err((SlotBusy::Taken, action));
        };
        drop(state);
        let result = action(
            backend,
            &mut ViewAdapter {
                inodes,
                handles,
                write_handles,
                view,
            },
        );
        self.slot.clear_waiting();
        Ok(result)
    }

    /// Releases every preparation waiting for an install. The install calls
    /// it on each exit, so no preparation waits past the install's end.
    pub fn finish_install(&self) {
        self.slot.clear_waiting();
    }

    /// Invalidates each of `inodes` in the kernel, in order.
    ///
    /// # Errors
    ///
    /// The first refused notification; the rest are not sent.
    pub fn revoke(&self, inodes: &[u64]) -> std::io::Result<()> {
        let Some(notifier) = &self.notifier else {
            return Ok(());
        };
        inodes.iter().try_for_each(|ino| notifier.inval_inode(*ino))
    }
}

/// The adapter state an install may change, and nothing else.
#[derive(Debug)]
pub struct ViewAdapter<'a> {
    inodes: &'a mut InodeTable,
    handles: &'a HandleTable,
    write_handles: &'a BTreeMap<u64, OpenFlags>,
    view: &'a mut WritableView,
}

impl ViewAdapter<'_> {
    /// Re-keys each changed path, then gives the new view's `time` to each
    /// path present in it and to every ancestor directory of a changed path,
    /// the root included.
    ///
    /// Each path's `bool` says whether it is present in the new view. Every
    /// inode attached at or under a path is detached with the metadata
    /// `displaced` gives for its own path. A write, truncate or exec change
    /// through such an inode answers `ESTALE`; a namespace change under a
    /// detached directory answers `ENOENT`, as under a deleted one.
    pub fn rekey(
        &mut self,
        paths: &[(PathKey, bool)],
        displaced: &dyn Fn(&PathKey) -> Option<OverlayNode>,
        time: SystemTime,
    ) {
        for (path, _) in paths {
            for ino in self.view.detach_resident(self.inodes, path, displaced) {
                if let Some(record) = self.view.detached.get_mut(&ino) {
                    record.replaced = true;
                }
            }
        }
        for (path, present) in paths {
            if *present {
                self.view.paths.insert(path.clone(), time);
            }
            for depth in 0..path.len() {
                let ancestor = path.iter().take(depth).cloned().collect();
                self.view.paths.insert(ancestor, time);
            }
        }
    }

    /// The inodes with an open handle, each once.
    pub fn open_inodes(&self) -> impl Iterator<Item = u64> + use<> {
        self.handles.open_inodes()
    }

    /// Whether any open file handle may write: one opened other than
    /// read-only, from its open to its release, written through or not.
    #[must_use]
    pub fn write_capable(&self) -> bool {
        write_capable(self.write_handles)
    }
}

/// Whether any of `write_handles` may write: one opened other than read-only.
fn write_capable(write_handles: &BTreeMap<u64, OpenFlags>) -> bool {
    write_handles
        .values()
        .any(|flags| flags.acc_mode() != OpenAccMode::O_RDONLY)
}

impl<B: MountBackend> super::GranaryFs<B> {
    /// The boundary a writable mount over a live view waits at.
    pub(super) fn live_boundary(&self) -> Option<&dyn crate::ViewBoundary> {
        if self.writability != crate::MountWritability::Writable || self.snapshot_fixture {
            return None;
        }
        self.view_boundary.as_deref()
    }

    /// Wait at a `kind` boundary holding nothing: the adapter's writers are
    /// read under the gate, which is released before the wait, and only for
    /// a boundary that observes.
    pub(super) fn boundary(&self, kind: crate::BoundaryKind) -> crate::BoundaryOutcome {
        let Some(boundary) = self.live_boundary() else {
            return crate::BoundaryOutcome::Served;
        };
        boundary.wait(kind, &|| self.writers())
    }

    /// Whether the adapter holds a write-capable descriptor. A gate that
    /// cannot be read counts as one, so a head the probe finds defers rather
    /// than being adopted, and the callback then meets that gate itself.
    fn writers(&self) -> bool {
        self.write_inner(|inner| Ok(write_capable(&inner.write_handles)))
            .unwrap_or(true)
    }

    /// Wait at a rewind: a listing of `fh` from its start after the handle
    /// has already handed out a cookie. The first listing of a handle is no
    /// boundary, and neither is a listing that continues from a cookie.
    pub(super) fn rewind_boundary(&self, fh: u64, offset: u64) -> Result<(), super::ReplyError> {
        let Some(boundary) = self.live_boundary() else {
            return Ok(());
        };
        if offset != 0 {
            return Ok(());
        }
        let rewound = self.write_inner(|inner| {
            Ok(inner
                .directory_cursors
                .get(&fh)
                .is_some_and(|cursor| !cursor.is_empty()))
        });
        if rewound == Ok(true)
            && boundary.wait(crate::BoundaryKind::Rewind, &|| self.writers())
                == crate::BoundaryOutcome::Unreachable
        {
            return Err(super::ReplyError::Backend(crate::MountError::Unreachable));
        }
        Ok(())
    }

    pub(super) fn new_name_gate(&self) -> Result<(), super::ReplyError> {
        if self
            .live_boundary()
            .is_some_and(crate::ViewBoundary::unconfirmed)
        {
            return Err(super::ReplyError::Backend(crate::MountError::Unreachable));
        }
        Ok(())
    }
}

/// Per-path and per-detached-inode times and metadata of a writable view.
#[derive(Debug)]
pub(super) struct WritableView {
    /// The time a path not in `paths` reports: the mount's start view.
    start: SystemTime,
    paths: BTreeMap<PathKey, SystemTime>,
    detached: BTreeMap<u64, Detached>,
}

/// What a detached inode keeps from the path it was detached from.
#[derive(Debug)]
pub(super) struct Detached {
    pub(super) node: Option<OverlayNode>,
    time: SystemTime,
    replaced: bool,
}

impl WritableView {
    pub(super) fn new(start: SystemTime) -> Self {
        Self {
            start,
            paths: BTreeMap::new(),
            detached: BTreeMap::new(),
        }
    }

    /// The time `ino` reports: its detached record's once detached, else its
    /// path's.
    pub(super) fn time(&self, inodes: &InodeTable, ino: u64, path: &PathKey) -> SystemTime {
        if !inodes.attached(ino)
            && let Some(record) = self.detached.get(&ino)
        {
            return record.time;
        }
        self.paths.get(path).copied().unwrap_or(self.start)
    }

    /// Whether an install detached `ino`. A locally unlinked inode is not.
    pub(super) fn replaced(&self, ino: u64) -> bool {
        self.detached
            .get(&ino)
            .is_some_and(|record| record.replaced)
    }

    pub(super) fn detached(&self, ino: u64) -> Option<&Detached> {
        self.detached.get(&ino)
    }

    pub(super) fn detached_mut(&mut self, ino: u64) -> Option<&mut Detached> {
        self.detached.get_mut(&ino)
    }

    /// Drops the records of inodes the table has reclaimed.
    pub(super) fn prune(&mut self, inodes: &InodeTable) {
        self.detached.retain(|ino, _| inodes.resolve(*ino).is_ok());
    }

    /// Detaches every inode attached at or under `path`, recording for each
    /// the time of the path it held and the metadata `metadata` gives for that
    /// path, then forgets the times under `path`. Returns the inodes.
    pub(super) fn detach_resident(
        &mut self,
        inodes: &mut InodeTable,
        path: &PathKey,
        metadata: &dyn Fn(&PathKey) -> Option<OverlayNode>,
    ) -> Vec<u64> {
        let mut detached = Vec::new();
        for (key, ino) in inodes.detach_path(path) {
            let time = self.paths.get(&key).copied().unwrap_or(self.start);
            let node = metadata(&key);
            self.detached.insert(
                ino,
                Detached {
                    node,
                    time,
                    replaced: false,
                },
            );
            detached.push(ino);
        }
        self.paths.retain(|key, _| !key.starts_with(path));
        detached
    }

    /// Moves the times at or under `from` to the same places under `to`.
    pub(super) fn move_paths(&mut self, from: &PathKey, to: &PathKey) {
        let moved: Vec<_> = self
            .paths
            .iter()
            .filter(|(path, _)| path.starts_with(from))
            .map(|(path, time)| (path.clone(), *time))
            .collect();
        self.paths.retain(|path, _| !path.starts_with(from));
        for (old, time) in moved {
            let mut new = to.clone();
            new.extend(old.iter().skip(from.len()).cloned());
            self.paths.insert(new, time);
        }
    }
}
