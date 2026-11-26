// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only evidence for a publication candidate extending a verified baseline.

mod binmap;
mod budget;
mod frames;
pub(super) mod intake;
mod manifest;
mod proofs;
pub(super) mod store;

#[cfg(test)]
mod tests;

use std::future::Future;

use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::root::{ROOT_MAX_BYTES, RootDoc, VolumeName};
use granary_core::sheaf::decode_sheaf;
use granary_store::backend::META_MAX_BYTES;

pub use budget::{PublicationValidator, ValidationAttempt, ValidationLimits};
pub(super) use proofs::PendingProof;

type Result<T> = std::result::Result<T, ValidationError>;

/// A definitive validation refusal or inability to establish evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// A newly required object or mapping is absent.
    MissingReference,
    /// Integrity, format, linkage or physical mapping preservation failed.
    InvalidReference,
    /// The attempt would cross an authority work limit.
    WorkLimit,
    /// The volume maps more grains than the authority can carry in its proof.
    LengthLimit,
    /// Evidence is unavailable, including when a previously verified object disappears.
    Unavailable,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingReference => "missing publication reference",
            Self::InvalidReference => "invalid publication reference",
            Self::WorkLimit => "publication validation work limit",
            Self::LengthLimit => "publication volume length limit",
            Self::Unavailable => "publication evidence unavailable",
        })
    }
}

impl std::error::Error for ValidationError {}

/// Store objects that an authority admission can read under its allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationObject<'a> {
    /// A numbered signed root.
    Root(&'a VolumeName, u64),
    /// A volume-scoped metadata object.
    Meta(&'a VolumeName, GrainId),
    /// A whole bin by its untagged digest.
    Bin([u8; DIGEST_LEN]),
    /// An exact extent of a bin, used for index and frame evidence.
    BinRange([u8; DIGEST_LEN], u64, u32),
}

impl ValidationObject<'_> {
    fn max_bytes(self) -> u64 {
        match self {
            Self::Root(..) => ROOT_MAX_BYTES,
            Self::Meta(..) => META_MAX_BYTES,
            Self::Bin(..) => BIN_MAX_BYTES,
            Self::BinRange(_, _, len) => u64::from(len),
        }
    }
}

/// Store read failures without backend diagnostics or keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationReadError {
    /// The store definitively answered that the key is absent.
    Missing,
    /// The response advertised or streamed past the supplied cap.
    OverCap,
    /// The read failed without definitive evidence about the object.
    Unavailable,
}

impl std::fmt::Display for ValidationReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "object absent",
            Self::OverCap => "object response exceeds allowance",
            Self::Unavailable => "object read unavailable",
        })
    }
}

impl std::error::Error for ValidationReadError {}

/// The read-only, bounded object source used by admission.
pub trait ValidationRead: Send + Sync {
    /// Fetch one object. Apply the supplied cap to both advertised and streamed
    /// body bytes before collecting them. One call dispatches at most one request.
    /// Missing means no object body was collected. The authority may drop the
    /// future on deadline expiry.
    fn read(
        &self,
        object: ValidationObject<'_>,
        cap: u64,
    ) -> impl Future<Output = std::result::Result<Vec<u8>, ValidationReadError>> + Send;
}

/// The reference IDs from a chain-checked candidate and the ID of its exact
/// stored root bytes. Root signature and extension checks precede validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationCandidate {
    volume: VolumeName,
    root_id: GrainId,
    parent: Option<GrainId>,
    manifest: GrainId,
    binmap: GrainId,
    sheaf: GrainId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RootReferences {
    manifest: GrainId,
    binmap: GrainId,
    sheaf: GrainId,
}

impl From<&RootDoc> for RootReferences {
    fn from(root: &RootDoc) -> Self {
        Self {
            manifest: root.manifest_root,
            binmap: root.binmap_index,
            sheaf: root.sheaf_head,
        }
    }
}

impl ValidationCandidate {
    /// Carry IDs already decoded from the signed root into the validator.
    #[must_use]
    pub fn from_root(root: &RootDoc, stored_id: GrainId) -> Self {
        Self::new(root.volume.clone(), stored_id, root.parent, root.into())
    }

    pub(super) fn new(
        volume: VolumeName,
        root_id: GrainId,
        parent: Option<GrainId>,
        ids: RootReferences,
    ) -> Self {
        Self {
            volume,
            root_id,
            parent,
            manifest: ids.manifest,
            binmap: ids.binmap,
            sheaf: ids.sheaf,
        }
    }
}

/// Evidence for one volume and exact stored root ID. The admission worker
/// may use it as a baseline after the matching landed outcome is durable.
#[derive(Debug)]
pub struct VerifiedContent {
    root: ValidationCandidate,
    cache: binmap::Cache,
    lengths: proofs::Lengths,
}

impl VerifiedContent {
    /// Check this proof against the chain-verified head.
    #[must_use]
    pub fn matches(&self, volume: &VolumeName, root_id: GrainId) -> bool {
        &self.root.volume == volume && self.root.root_id == root_id
    }

    /// Release decoded binmap metadata while keeping verified frame lengths.
    /// A later attempt can re-read the metadata within its own allowance.
    pub fn evict_cached_objects(&mut self) {
        self.cache = binmap::Cache::default();
    }
}

impl ValidationAttempt {
    /// Verify the candidate's sheaf, physical map preservation, additions
    /// and the canonical manifest with its file-frame lengths.
    ///
    /// # Errors
    /// A missing or invalid reference, work exhaustion, or unavailable
    /// evidence. A non-genesis candidate requires a matching baseline.
    ///
    /// # Cancellation safety
    /// Drop the attempt if this future is cancelled. An in-flight CPU
    /// job keeps its concurrency permit until it exits.
    pub async fn validate(
        &mut self,
        source: &impl ValidationRead,
        candidate: ValidationCandidate,
        parent: Option<&VerifiedContent>,
    ) -> Result<VerifiedContent> {
        match (candidate.parent, parent) {
            (None, None) => {}
            (Some(id), Some(proof)) if proof.matches(&candidate.volume, id) => {}
            _ => return Err(ValidationError::Unavailable),
        }

        let old_sheaf = parent.map(|proof| proof.root.sheaf);
        let sheaf_parent = read_sheaf(
            self,
            source,
            &candidate.volume,
            candidate.sheaf,
            candidate.manifest,
            Some(candidate.sheaf) == old_sheaf,
        )
        .await?;
        if sheaf_parent != old_sheaf {
            return Err(ValidationError::InvalidReference);
        }

        let (cache, lengths) = binmap::validate(self, source, &candidate, parent).await?;
        Ok(VerifiedContent {
            root: candidate,
            cache,
            lengths,
        })
    }
}

async fn read_sheaf(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    volume: &VolumeName,
    id: GrainId,
    manifest: GrainId,
    verified: bool,
) -> Result<Option<GrainId>> {
    let bytes = work
        .read(source, ValidationObject::Meta(volume, id), verified)
        .await?;
    let (parent, ops) = work
        .blocking(move |_| {
            check_reference_id(&bytes, id, verified)?;
            let sheaf = decode_sheaf(&bytes).map_err(invalid)?;
            if sheaf.manifest_root == manifest {
                Ok((sheaf.parent, sheaf.ops.len() as u64))
            } else {
                Err(ValidationError::InvalidReference)
            }
        })
        .await?;
    work.meter(ops).await?;
    Ok(parent)
}

fn check_id(bytes: &[u8], expected: GrainId) -> Result<()> {
    if GrainId::of(bytes) == expected {
        Ok(())
    } else {
        Err(ValidationError::InvalidReference)
    }
}

fn check_reference_id(bytes: &[u8], expected: GrainId, verified: bool) -> Result<()> {
    check_id(bytes, expected).map_err(|error| {
        if verified {
            ValidationError::Unavailable
        } else {
            error
        }
    })
}

fn invalid(_: granary_core::encoding::DecodeError) -> ValidationError {
    ValidationError::InvalidReference
}
