// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded observation, independent of the worker inbox, log token and store.
//! A slot's dedicated mutex protects only a complete fixed-size copy or
//! replacement. Projection, allocation and encoding happen outside its guard;
//! no I/O, callback or await can run under it. Writers holding the log token
//! take the slot only after I/O settles; a slot guard never acquires that token.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use granary_core::authlog::Epoch;
use granary_core::authority_answer::{Head, VolumeStatus};
use granary_core::root::VolumeName;

use super::state::VolumeState;
use super::{AuthorityHandle, VerifiedHead};
use crate::enrollment::EnrollmentSnapshot;
use crate::refusals::RefusalSnapshot;

pub use granary_core::authority_answer::OpenPosition;

/// One configured volume's complete, fixed-size observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeView {
    /// No log was adopted or successfully initialised by this run.
    NoLog,
    /// Committed log state and the last completed head verification.
    Log {
        /// The log's epoch, including before any head verification.
        epoch: Epoch,
        /// Unknown before verification or after its failure; empty is a head.
        head: Option<VerifiedHead>,
        /// Only the open decision's position and candidate identifier.
        open: Option<OpenPosition>,
    },
}

impl VolumeView {
    /// The public wire projection (the volume-status body), absent only for [`Self::NoLog`].
    #[must_use]
    pub fn status(self) -> Option<VolumeStatus> {
        match self {
            Self::NoLog => None,
            Self::Log { epoch, head, open } => Some(VolumeStatus {
                epoch,
                head: head.map(|h| Head {
                    root: h.head.map(|r| (r.head_seq, r.head_id)),
                    next_seq: h.next_seq,
                }),
                open,
            }),
        }
    }

    fn head(self) -> Option<VerifiedHead> {
        match self {
            Self::NoLog => None,
            Self::Log { head, .. } => head,
        }
    }

    fn project(state: Option<&VolumeState>, head: Option<VerifiedHead>) -> Self {
        state.map_or(Self::NoLog, |state| Self::Log {
            epoch: state.envelope().epoch(),
            head,
            open: state.open().map(|entry| OpenPosition {
                entry_seq: entry.seq,
                candidate_id: entry.identity.candidate_id(),
            }),
        })
    }
}

/// The terminal state at an observation's selection point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalState {
    /// Fencing takes precedence over every form of stop.
    Fenced,
    /// Stop requested, run ended, or driver abandoned.
    Stopped,
}

/// Operator-only observations; never encode this as a public status body.
///
/// Each volume is coherent, but the volumes, terminal state, enrollment and
/// refusal snapshots are sampled separately. Enrollment preserves its state,
/// sequence and every counter verbatim. Grant metadata and effective scope are
/// coherent with their capture revision; grant counters are sampled separately.
/// Counter sampling retains the source
/// APIs' semantics: this is not one atomic process-wide instant, and totals
/// need not equal retained per-principal rows. Storage is bounded by configured
/// volumes and the existing refusal registries, never log or request history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Exactly one view per configured volume, in name order.
    pub volumes: BTreeMap<VolumeName, VolumeView>,
    /// Sampled after the volume copies; no clean-marker wait.
    pub terminal: Option<TerminalState>,
    /// The enrollment reader's snapshot, unmodified.
    pub enrollment: EnrollmentSnapshot,
    /// Process totals and capped principal rows, once for the process.
    pub refusals: RefusalSnapshot,
    /// Local grant metadata and effective capture, never projected on the wire.
    pub debug_grant: Option<crate::debug_grant::DebugGrantSnapshot>,
}

#[derive(Debug)]
pub(super) struct VolumeSlot(
    Mutex<VolumeView>,
    #[cfg(test)] std::sync::atomic::AtomicUsize,
);

impl VolumeSlot {
    pub(super) fn new(state: Option<&VolumeState>) -> Self {
        Self(
            Mutex::new(VolumeView::project(state, None)),
            #[cfg(test)]
            std::sync::atomic::AtomicUsize::new(0),
        )
    }

    #[cfg(test)]
    pub(super) fn loads(&self) -> usize {
        self.1.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn load(&self) -> VolumeView {
        #[cfg(test)]
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn replace(&self, view: VolumeView) {
        // Recovery is safe: the private mutation is one whole-value assignment
        // of a Copy value, with no user code or fallible work under the guard.
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = view;
    }

    pub(super) fn committed(&self, state: Option<&VolumeState>) {
        let head = self.load().head();
        self.replace(VolumeView::project(state, head));
    }

    pub(super) fn verified(&self, state: Option<&VolumeState>, head: Option<VerifiedHead>) {
        self.replace(VolumeView::project(state, head));
    }
}

impl AuthorityHandle {
    /// Synchronously copy one configured volume's complete view. No worker
    /// request, store access or log-token acquisition occurs. The dedicated
    /// publication mutex can contend only with fixed-size copying/replacement.
    /// `None` means unserved, regardless of filesystem contents.
    ///
    /// Call [`Self::terminal_state`] before lookup and at final response
    /// selection, after any await. A terminal state overrides even an unserved
    /// volume; bytes selected before a later fence cannot be recalled.
    #[must_use]
    pub fn volume_view(&self, volume: &VolumeName) -> Option<VolumeView> {
        self.inner.views.get(volume).map(|slot| slot.load())
    }

    /// Synchronously sample every configured volume, each under its own short
    /// publication lock. No growing worker state is cloned. These copies do
    /// not represent one atomic instant across volumes.
    #[must_use]
    pub fn volume_views(&self) -> BTreeMap<VolumeName, VolumeView> {
        self.inner
            .views
            .iter()
            .map(|(v, slot)| (v.clone(), slot.load()))
            .collect()
    }

    /// Synchronous terminal check, independent of worker progress and clean
    /// marker completion. Fence wins over requested stop, ended run or abandoned
    /// driver. Response selection linearizes at its final call to this method.
    #[must_use]
    pub fn terminal_state(&self) -> Option<TerminalState> {
        self.terminal(TerminalState::Fenced, TerminalState::Stopped)
    }
}

#[cfg(test)]
mod tests;
