// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Deterministic integration seams; arming is absent without the test feature.

// The wall covers ordinary release profiles. Artifact inspection also refuses
// arming symbols when a profile enables debug assertions.
#[cfg(all(feature = "overlay-fault-tests", not(debug_assertions)))]
compile_error!("overlay-fault-tests must not compile into a release artifact");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    Fail,
    Crash,
    Short(usize),
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultEvent {
    pub name: &'static str,
    pub phase: &'static str,
    pub occurrence: u64,
    pub record_index: u64,
}

#[cfg(any(test, feature = "overlay-fault-tests"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenameDirectoryFaultContext {
    pub journal_cursor: u64,
    pub directory_inode: Option<u64>,
}

/// Reliable engine firing identity, retained before any block/failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncFaultEvent {
    pub name: &'static str,
    pub phase: &'static str,
    pub occurrence: u64,
    pub capture: u64,
    pub request: Option<granary_core::hash::GrainId>,
    pub object_kind: &'static str,
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub rename_directory: Option<RenameDirectoryFaultContext>,
}

#[cfg(any(test, feature = "overlay-fault-tests"))]
#[derive(Debug, Default)]
struct Armed {
    target: Option<(&'static str, &'static str, u64, FaultAction)>,
    repetitions: u64,
    seen: u64,
    fired: Vec<FaultEvent>,
    sync_fired: Vec<SyncFaultEvent>,
    resume_permits: u64,
    released: bool,
    trace_sync: bool,
    sync_seen: std::collections::BTreeMap<(&'static str, &'static str), u64>,
}

/// The integration harness retains a clone to inspect firing and resume a block.
#[derive(Debug, Clone, Default)]
pub struct FaultControl {
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    inner: std::sync::Arc<(std::sync::Mutex<Armed>, std::sync::Condvar)>,
}

impl FaultControl {
    /// Observe every engine seam without arming a failure or a block. The
    /// per-name/phase occurrence counters have the same meaning as `arm`.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn trace_sync(&self) {
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = Armed {
            trace_sync: true,
            ..Armed::default()
        };
    }
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    #[must_use]
    pub fn sync_fired(&self) -> Vec<SyncFaultEvent> {
        self.inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sync_fired
            .clone()
    }

    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn sync_point(
        &self,
        name: &'static str,
        phase: &'static str,
        capture: u64,
        request: Option<granary_core::hash::GrainId>,
        object_kind: &'static str,
    ) -> Option<FaultAction> {
        self.sync_point_context(name, phase, capture, request, object_kind, None)
    }

    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn rename_directory_point(
        &self,
        context: RenameDirectoryFaultContext,
    ) -> Option<FaultAction> {
        self.sync_point_context(
            "fuse.sync.rename_directory",
            "before",
            0,
            None,
            "directory",
            Some(context),
        )
    }

    #[cfg(any(test, feature = "overlay-fault-tests"))]
    fn sync_point_context(
        &self,
        name: &'static str,
        phase: &'static str,
        capture: u64,
        request: Option<granary_core::hash::GrainId>,
        object_kind: &'static str,
        rename_directory: Option<RenameDirectoryFaultContext>,
    ) -> Option<FaultAction> {
        {
            let (lock, wake) = &*self.inner;
            let mut state = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.trace_sync {
                let count = state.sync_seen.entry((name, phase)).or_default();
                *count += 1;
                let occurrence = *count;
                state.sync_fired.push(SyncFaultEvent {
                    name,
                    phase,
                    occurrence,
                    capture,
                    request,
                    object_kind,
                    rename_directory,
                });
                return None;
            }
            Self::fire_armed(state, wake, name, phase, |state, fired_occurrence| {
                state.sync_fired.push(SyncFaultEvent {
                    name,
                    phase,
                    occurrence: fired_occurrence,
                    capture,
                    request,
                    object_kind,
                    rename_directory,
                });
                crate::observe::sync_fault(name, phase, fired_occurrence, object_kind);
            })
        }
        #[cfg(not(any(test, feature = "overlay-fault-tests")))]
        {
            let _ = (self, name, phase, capture, request, object_kind);
            None
        }
    }
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn arm(
        &self,
        name: &'static str,
        phase: &'static str,
        occurrence: u64,
        action: FaultAction,
    ) {
        let (lock, _) = &*self.inner;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = Armed {
            target: Some((name, phase, occurrence, action)),
            repetitions: 1,
            ..Armed::default()
        };
    }
    /// Arm each of the next `repetitions` matching engine occurrences.
    /// Every blocked occurrence needs its own `resume_one` call.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn arm_repeated(
        &self,
        name: &'static str,
        phase: &'static str,
        repetitions: std::num::NonZeroU64,
        action: FaultAction,
    ) {
        let (lock, _) = &*self.inner;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = Armed {
            target: Some((name, phase, 1, action)),
            repetitions: repetitions.get(),
            ..Armed::default()
        };
    }
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    #[must_use]
    pub fn fired(&self) -> Vec<FaultEvent> {
        self.inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fired
            .clone()
    }
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn resume(&self) {
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released = true;
        self.inner.1.notify_all();
    }
    /// Resume one repeated block while leaving its later targets armed.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn resume_one(&self) {
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.resume_permits = state.resume_permits.saturating_add(1);
        self.inner.1.notify_all();
    }

    /// Release one parked block and arm the next, causally downstream cut.
    ///
    /// # Panics
    /// Panics unless a single engine block has fired and is still parked.
    #[cfg(feature = "overlay-fault-tests")]
    pub fn resume_at(&self, name: &'static str, phase: &'static str) {
        let (lock, wake) = &*self.inner;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            (
                state.target.map(|(_, _, _, action)| action),
                state.sync_fired.len(),
                state.released,
                state.resume_permits,
            ),
            (Some(FaultAction::Block), 1, false, 0),
            "the first engine cut must be parked before switching cuts"
        );
        *state = Armed {
            target: Some((name, phase, 1, FaultAction::Block)),
            repetitions: 1,
            resume_permits: 1,
            ..Armed::default()
        };
        wake.notify_all();
    }

    #[cfg(feature = "overlay-fault-tests")]
    pub(crate) fn armed_at(&self, name: &'static str, phase: &'static str) -> bool {
        self.inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .target
            .is_some_and(|(point, at, _, _)| (point, at) == (name, phase))
    }

    #[cfg(any(test, feature = "overlay-fault-tests"))]
    fn fire_armed<'a>(
        mut state: std::sync::MutexGuard<'a, Armed>,
        wake: &'a std::sync::Condvar,
        name: &'static str,
        phase: &'static str,
        record: impl FnOnce(&mut Armed, u64),
    ) -> Option<FaultAction> {
        let (target, at, occurrence, action) = state.target?;
        if target != name || at != phase {
            return None;
        }
        state.seen = state.seen.saturating_add(1);
        let last = occurrence.saturating_add(state.repetitions.saturating_sub(1));
        if state.seen < occurrence || state.seen > last {
            return None;
        }
        let fired_occurrence = state.seen;
        record(&mut state, fired_occurrence);
        wake.notify_all();
        if action == FaultAction::Block {
            while !state.released && state.resume_permits == 0 {
                state = wake
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            if !state.released {
                state.resume_permits -= 1;
            }
            return None;
        }
        Some(action)
    }

    pub(crate) fn point(
        &self,
        name: &'static str,
        phase: &'static str,
        record_index: u64,
    ) -> Option<FaultAction> {
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        {
            let (lock, wake) = &*self.inner;
            let state = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Self::fire_armed(state, wake, name, phase, |state, fired_occurrence| {
                state.fired.push(FaultEvent {
                    name,
                    phase,
                    occurrence: fired_occurrence,
                    record_index,
                });
                if let (Some(point), Some(phase)) = (
                    crate::observe::OverlayFaultPoint::from_seam(name),
                    crate::observe::FaultPhase::from_seam(phase),
                ) {
                    crate::observe::overlay_fault(point, phase, fired_occurrence, record_index);
                }
            })
        }
        #[cfg(not(any(test, feature = "overlay-fault-tests")))]
        {
            let _ = (self, name, phase, record_index);
            None
        }
    }
}

#[cfg(test)]
mod tests;
