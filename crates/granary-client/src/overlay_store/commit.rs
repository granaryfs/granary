// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Durable publication progress without dispatch policy.

use super::{OverlayError, OverlayIo, OverlayStore, OwnershipStatus, Record, Store, codec};

impl<P: OverlayIo> OverlayStore<P> {
    fn check_commit_progress(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
    ) -> Result<(), OverlayError> {
        self.check(store, ownership)?;
        if !self.replayed {
            return Err(OverlayError::PendingReconciliation);
        }
        Ok(())
    }
    /// Read admitted progress, including a fence, without enabling namespace service.
    /// # Errors
    /// Custody, replay, poison or journal lock failure.
    pub fn commit_progress(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        publication: [u8; 16],
    ) -> Result<Option<codec::CommitProgress>, OverlayError> {
        self.check_commit_progress(store, ownership)?;
        Ok(self
            .journal
            .lock()
            .map_err(Self::lock_error)?
            .state
            .commit_progress(&publication))
    }

    /// Append a sync-class dispatch reservation before any retained attempt save.
    /// # Errors
    /// Invalid boundary/publication, nonconsecutive attempt, capacity or persistence.
    pub fn record_commit_attempt(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary_seq: u64,
        publication_id: [u8; 16],
        attempt: u64,
    ) -> Result<u64, OverlayError> {
        self.check_commit_progress(store, ownership)?;
        self.append_effect(
            &Record::CommitAttempt {
                boundary_seq,
                publication_id,
                attempt,
            },
            false,
        )
    }

    /// Persist a publication fence using both journal sync barriers.
    /// # Errors
    /// Invalid boundary/publication, capacity or persistence.
    pub fn record_commit_fence(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary_seq: u64,
        publication_id: [u8; 16],
    ) -> Result<u64, OverlayError> {
        self.check_commit_progress(store, ownership)?;
        self.append_effect(
            &Record::CommitFence {
                boundary_seq,
                publication_id,
            },
            false,
        )
    }
}
