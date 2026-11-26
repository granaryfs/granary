// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A root as the store holds it at a landed seq, checked once.
//!
//! A landing reads its root back through this type rather than trusting the
//! candidate this client prepared. Its one constructor reads the bytes from
//! the store and checks them, and nothing builds one from bytes a caller
//! already has.

use super::refused;
use crate::CoordinationError;
use crate::resolve::is_transport_down;
use granary_core::hash::GrainId;
use granary_core::root::{RootDoc, VolumeName};
use granary_core::rootstore::{RootStore, RootStoreError};
use granary_store::crypto::TrustedKeys;

/// The refusal for a store error on a readback. A transient failure (a
/// transport [`is_transport_down`] calls down, or a `429`/`503` the store
/// shed) is `ViewRootUnavailable`, which a retry can clear; any other answer
/// is `SyncCommitReadback`.
pub(super) fn readback_refusal(error: &RootStoreError) -> CoordinationError {
    if is_transport_down(error) || matches!(error, RootStoreError::Unavailable { .. }) {
        refused("ViewRootUnavailable")
    } else {
        refused("SyncCommitReadback")
    }
}

/// A signed root read back from the store: its bytes, their id, the seq and
/// volume it was read at, and the document `check_head` returned for it.
#[derive(Debug, Clone)]
pub(crate) struct PublishedRoot {
    bytes: Vec<u8>,
    id: GrainId,
    seq: u64,
    volume: VolumeName,
    doc: RootDoc,
}

impl PublishedRoot {
    /// Read the root of `volume` at `seq` and check it: the id of the bytes
    /// must be `expected` when one is given, and the bytes must be a trusted
    /// root of `volume` at `seq`. The read has no deadline of its own; the
    /// caller bounds it.
    ///
    /// # Errors
    /// `ViewRootUnavailable` or `SyncCommitReadback` for a store error, as
    /// [`readback_refusal`] classes it, `ViewRootUnpublished` when nothing is
    /// stored at `seq`, `ViewRootMismatch` when the bytes have another id than
    /// `expected`, and `SyncCommitSignature` when they are not a trusted root
    /// of `volume` at `seq`.
    pub(crate) async fn read<R: RootStore>(
        remote: &R,
        volume: &VolumeName,
        seq: u64,
        expected: Option<GrainId>,
        trusted: &TrustedKeys,
    ) -> Result<Self, CoordinationError> {
        let bytes = remote
            .get_root(volume.as_str(), seq)
            .await
            .map_err(|error| readback_refusal(&error))?
            .ok_or_else(|| refused("ViewRootUnpublished"))?;
        let id = GrainId::of(&bytes);
        if expected.is_some_and(|expected| expected != id) {
            return Err(refused("ViewRootMismatch"));
        }
        let doc = granary_store::crypto::check_head(&bytes, volume.as_str(), seq, trusted)
            .map_err(|_| refused("SyncCommitSignature"))?;
        Ok(Self {
            bytes,
            id,
            seq,
            volume: volume.clone(),
            doc,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn id(&self) -> GrainId {
        self.id
    }
    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }
    pub(crate) fn volume(&self) -> &VolumeName {
        &self.volume
    }
    pub(crate) fn doc(&self) -> &RootDoc {
        &self.doc
    }
}
