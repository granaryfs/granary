// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Manifest bytes, measured EXACTLY — not modelled.
//!
//! The objective requires manifest/index bytes in the metric,
//! and they are the term that penalises small grains. granary already
//! owns the frozen v1 encoder (`granary_core::manifest`), so the sweep
//! builds the real content tree for each arm and sums the real encoded
//! node lengths. Manifest nodes are content-addressed, so "novel
//! manifest bytes" is the same set difference as novel grains: nodes
//! whose `GrainId` is absent from the older version.
//!
//! Only the binmap term is not measured directly — its frozen shard entry
//! matches the registered model field for field;
//! see [`crate::cost::BINMAP_ENTRY_BYTES`] and its sensitivity band.

use std::collections::BTreeMap;
use std::fmt;

use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EncodeNodeError, EntryKind, FILE_INLINE_MAX_REFS, FileGrains, GrainRef, Name,
    SymlinkTarget, build_dir, build_grain_list,
};

/// What one corpus node contributes to the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A regular file and its grain refs, in file order.
    File {
        /// Any exec bit set.
        exec: bool,
        /// File size; the encoder rejects a grain sum that disagrees.
        size: u64,
        /// Grain refs in file order.
        grains: Vec<GrainRef>,
    },
    /// A symlink.
    Symlink(SymlinkTarget),
    /// A directory with no entries.
    EmptyDir,
}

/// One manifest input, addressed by path components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Path components from the root, never empty.
    pub components: Vec<Name>,
    /// What it contributes.
    pub payload: Payload,
}

/// The encoded manifest: every distinct node, and the root id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestNodes {
    /// Root node id.
    pub root: GrainId,
    /// Distinct node id to encoded length. Identical subtrees appear
    /// once, exactly as the store would hold them.
    pub nodes: BTreeMap<GrainId, usize>,
}

impl ManifestNodes {
    /// Total encoded bytes of every distinct node.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.nodes.values().map(|&n| n as u64).sum()
    }
}

/// Why a manifest could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The frozen encoder refused the tree.
    Encode(EncodeNodeError),
    /// A file has more grains than `u32` can count.
    TooManyGrains {
        /// Offending count.
        count: usize,
    },
    /// An entry had no path components at all. Every OTHER shape of
    /// bad ordering (interleaved groups, a duplicate path, unsorted
    /// siblings, a name that is both a file and a directory prefix)
    /// reaches the frozen encoder's own check instead and surfaces as
    /// `Encode(NotStrictlySorted)` — pinned by
    /// `misordered_inputs_are_not_strictly_sorted_not_misordered_input`.
    MisorderedInput,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "manifest encoder refused the tree: {e}"),
            Self::TooManyGrains { count } => write!(f, "{count} grains exceeds u32"),
            Self::MisorderedInput => write!(f, "entries are not in depth-first component order"),
        }
    }
}

impl core::error::Error for ManifestError {}

impl From<EncodeNodeError> for ManifestError {
    fn from(e: EncodeNodeError) -> Self {
        Self::Encode(e)
    }
}

/// Build the whole manifest and collect every distinct node.
///
/// `entries` must be in the order [`crate::corpus::load`] emits:
/// depth-first, memcmp-sorted, which is `Vec<Name>` lexicographic
/// order.
///
/// # Errors
/// [`ManifestError`] if the encoder refuses the tree (an over-long
/// grain, a size/grain-sum mismatch) or the input is misordered.
pub fn build(entries: &[Entry]) -> Result<ManifestNodes, ManifestError> {
    let mut nodes = BTreeMap::new();
    let root = build_level(entries, 0, &mut nodes)?;
    Ok(ManifestNodes { root, nodes })
}

fn build_level(
    entries: &[Entry],
    depth: usize,
    nodes: &mut BTreeMap<GrainId, usize>,
) -> Result<GrainId, ManifestError> {
    let mut dir_entries: Vec<DirEntry> = Vec::new();
    let mut i = 0usize;
    while let Some(entry) = entries.get(i) {
        let Some(name) = entry.components.get(depth) else {
            return Err(ManifestError::MisorderedInput);
        };
        if entry.components.len() == depth + 1 {
            dir_entries.push(DirEntry {
                name: name.clone(),
                kind: leaf_kind(&entry.payload, nodes)?,
            });
            i += 1;
        } else {
            let mut j = i;
            while entries
                .get(j)
                .is_some_and(|e| e.components.get(depth) == Some(name))
            {
                j += 1;
            }
            let Some(group) = entries.get(i..j) else {
                return Err(ManifestError::MisorderedInput);
            };
            let child = build_level(group, depth + 1, nodes)?;
            dir_entries.push(DirEntry {
                name: name.clone(),
                kind: EntryKind::Dir { child },
            });
            i = j;
        }
    }
    Ok(collect(build_dir(&dir_entries)?, nodes))
}

fn leaf_kind(
    payload: &Payload,
    nodes: &mut BTreeMap<GrainId, usize>,
) -> Result<EntryKind, ManifestError> {
    match payload {
        Payload::Symlink(t) => Ok(EntryKind::Symlink { target: t.clone() }),
        Payload::EmptyDir => Ok(EntryKind::Dir {
            child: collect(build_dir(&[])?, nodes),
        }),
        Payload::File { exec, size, grains } => Ok(EntryKind::File {
            exec: *exec,
            size: *size,
            grains: file_grains(grains, nodes)?,
        }),
    }
}

fn file_grains(
    refs: &[GrainRef],
    nodes: &mut BTreeMap<GrainId, usize>,
) -> Result<FileGrains, ManifestError> {
    let count = u32::try_from(refs.len())
        .map_err(|_| ManifestError::TooManyGrains { count: refs.len() })?;
    if count <= FILE_INLINE_MAX_REFS {
        return Ok(FileGrains::Inline(refs.to_vec()));
    }
    let root = collect(build_grain_list(refs)?, nodes);
    Ok(FileGrains::Spill {
        grain_count: count,
        root,
    })
}

fn collect(
    tree: granary_core::manifest::BuiltTree,
    nodes: &mut BTreeMap<GrainId, usize>,
) -> GrainId {
    for (id, bytes) in tree.nodes {
        nodes.insert(id, bytes.len());
    }
    tree.root
}

#[cfg(test)]
mod tests;
