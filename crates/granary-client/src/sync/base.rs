// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The sync engine's base: a signed root with a routed, contained closure.
//!
//! The incremental projection reuses subtrees of the base without re-reading
//! them, so what it reuses must already be valid, spill trees included. This
//! type is the only way the engine obtains a base, and each constructor runs
//! (or is handed the witness of) one complete walk of the manifest.

use crate::CoordinationError;
use crate::publish::shards::Exhaustion;
use granary_core::binmap::ShardEntry;
use granary_core::binstore::BinStore;
use granary_core::grainsource::GrainSource;
use granary_core::hash::GrainId;
use granary_store::crypto::TrustedKeys;
use std::collections::BTreeMap;
use std::sync::Arc;

fn refused() -> CoordinationError {
    CoordinationError::Refused("SyncBase")
}

/// A remote transport failure during the binmap read keeps its preparation
/// class; every other failure is a bad base.
pub(crate) fn binmap_error(error: crate::PublishError) -> CoordinationError {
    match error {
        crate::PublishError::Remote(error) => CoordinationError::Recovery(
            crate::RecoveryError::Preparation(crate::PublishError::Remote(error)),
        ),
        _ => refused(),
    }
}

/// Whether every child and grain the node in `bytes` names is in `known`: a
/// `DirLeaf`'s directory children, inline grains and spill roots, a
/// `DirInterior`'s children, a `GrainListLeaf`'s grains and a
/// `GrainListIndex`'s children. An object of any other type, or one that
/// does not decode, is never covered.
pub(crate) fn contained(bytes: &[u8], known: &BTreeMap<GrainId, ShardEntry>) -> bool {
    contained_by(bytes, &|id| known.contains_key(id))
}

/// [`contained`] over any membership test, for a check that admits a
/// reference from more than one verified set.
pub(crate) fn contained_by(bytes: &[u8], covered: &dyn Fn(&GrainId) -> bool) -> bool {
    use granary_core::{
        encoding::{self, ObjectType},
        manifest::{self, EntryKind, FileGrains},
    };
    let Ok((kind, cursor)) = encoding::open_envelope(bytes) else {
        return false;
    };
    match kind {
        ObjectType::DirLeaf => manifest::decode_dir_leaf(cursor).is_ok_and(|entries| {
            entries.iter().all(|entry| match &entry.kind {
                EntryKind::Dir { child } => covered(child),
                EntryKind::File { grains, .. } => match grains {
                    FileGrains::Inline(refs) => refs.iter().all(|r| covered(&r.id)),
                    FileGrains::Spill { root, .. } => covered(root),
                },
                _ => true,
            })
        }),
        ObjectType::DirInterior => manifest::decode_dir_interior(cursor)
            .is_ok_and(|children| children.iter().all(|child| covered(&child.child))),
        ObjectType::GrainListLeaf => manifest::decode_grain_list_leaf(cursor)
            .is_ok_and(|refs| refs.iter().all(|r| covered(&r.id))),
        ObjectType::GrainListIndex => manifest::decode_grain_list_index(cursor)
            .is_ok_and(|children| children.iter().all(|child| covered(&child.child))),
        _ => false,
    }
}

/// A signed root, its checked head and its manifest root, built only after one
/// full `validate_dir_tree` and binmap containment of that manifest.
#[derive(Debug, Clone)]
pub struct VerifiedBase {
    bytes: Vec<u8>,
    id: GrainId,
    seq: u64,
    manifest_root: GrainId,
    exhausted: Arc<Exhaustion>,
}

/// Proof that a landed root's whole manifest was walked, containment included,
/// by the landed-commit refresh. Only that walk can make one.
#[derive(Debug)]
pub(crate) struct CommitWalk {
    manifest_root: GrainId,
}
impl CommitWalk {
    pub(super) fn new(manifest_root: GrainId) -> Self {
        Self { manifest_root }
    }
}

impl VerifiedBase {
    /// Authenticate the complete binmap and walk the manifest, checking every
    /// node and grain reference against it. The complete map is discarded after
    /// the walk. The engine bounds these steps through its scheduling seam.
    ///
    /// # Errors
    /// `SyncBase` when the bytes are not a trusted root of `volume` or its
    /// binmap or manifest is missing, corrupt, misrouted or uncovered. Remote
    /// transport errors retain their preparation refusal class.
    pub async fn attach<R: BinStore>(
        bytes: Vec<u8>,
        volume: &str,
        trusted: &TrustedKeys,
        source: &dyn GrainSource,
        remote: &R,
    ) -> Result<Self, CoordinationError> {
        let state = Self::attach_map(&bytes, volume, trusted, remote).await?;
        Self::attach_validated(bytes, volume, trusted, source, state)
    }

    pub(crate) async fn attach_map<R: BinStore>(
        bytes: &[u8],
        volume: &str,
        trusted: &TrustedKeys,
        remote: &R,
    ) -> Result<crate::publish::RemoteState, CoordinationError> {
        let doc = granary_core::root::decode_root(bytes).map_err(|_| refused())?;
        let volume =
            granary_core::root::VolumeName::from_bytes(volume.as_bytes()).map_err(|_| refused())?;
        crate::publish::state_from_head(remote, &volume, doc.seq, bytes, trusted)
            .await
            .map_err(binmap_error)
    }

    pub(crate) fn attach_validated(
        bytes: Vec<u8>,
        volume: &str,
        trusted: &TrustedKeys,
        source: &dyn GrainSource,
        state: crate::publish::RemoteState,
    ) -> Result<Self, CoordinationError> {
        let doc = granary_core::root::decode_root(&bytes).map_err(|_| refused())?;
        granary_store::crypto::check_head(&bytes, volume, doc.seq, trusted)
            .map_err(|_| refused())?;
        if state.parent != Some(GrainId::of(&bytes)) {
            return Err(refused());
        }
        // Containment is fused into the validator's existing fetch. Nodes and
        // every referenced grain are checked without a second closure walk.
        granary_core::manifest::validate_dir_tree(&doc.manifest_root, &|id| {
            if !state.known.contains_key(id) {
                return None;
            }
            let bytes = source.get(id).ok()?;
            contained(&bytes, &state.known).then_some(bytes)
        })
        .map_err(|_| refused())?;
        drop(state);
        Ok(Self {
            id: GrainId::of(&bytes),
            seq: doc.seq,
            manifest_root: doc.manifest_root,
            bytes,
            exhausted: Arc::default(),
        })
    }

    pub(crate) fn exhaustion(&self) -> Arc<Exhaustion> {
        self.exhausted.clone()
    }

    /// First fallback triggers and later bypasses for this exact captured base.
    #[must_use]
    pub fn binmap_exhaustion_counts(&self) -> (u64, u64) {
        self.exhausted.counts()
    }

    /// The base a landed commit's refresh installs, after its own full walk.
    pub(crate) fn landed(
        bytes: Vec<u8>,
        volume: &str,
        trusted: &TrustedKeys,
        walk: &CommitWalk,
    ) -> Result<Self, CoordinationError> {
        let doc = granary_core::root::decode_root(&bytes).map_err(|_| refused())?;
        granary_store::crypto::check_head(&bytes, volume, doc.seq, trusted)
            .map_err(|_| refused())?;
        if doc.manifest_root != walk.manifest_root {
            return Err(refused());
        }
        Ok(Self {
            id: GrainId::of(&bytes),
            seq: doc.seq,
            manifest_root: doc.manifest_root,
            bytes,
            exhausted: Arc::default(),
        })
    }

    /// The base an adopted head installs, after the rebuild's own full walk
    /// of that head. `published` is already checked as a trusted root of
    /// its volume at its seq.
    pub(crate) fn adopted(
        published: &super::PublishedRoot,
        walk: &crate::writable_start::AdoptionWalk,
    ) -> Result<Self, CoordinationError> {
        if walk.base() != (published.id(), published.seq())
            || walk.manifest_root() != published.doc().manifest_root
        {
            return Err(refused());
        }
        Ok(Self {
            bytes: published.bytes().to_vec(),
            id: published.id(),
            seq: published.seq(),
            manifest_root: walk.manifest_root(),
            exhausted: Arc::default(),
        })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn id(&self) -> GrainId {
        self.id
    }
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }
    #[must_use]
    pub fn manifest_root(&self) -> GrainId {
        self.manifest_root
    }
}
