// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Owned authenticated values under exclusive mediator access, without a lock.

#[cfg(test)]
mod tests;

use super::OverlayError;
use granary_core::{hash::GrainId, manifest::FileGrains};
use std::{collections::BTreeMap, sync::Arc};

const METADATA_BYTES: usize = 16_777_216;
const GRAIN_BYTES: usize = 8_388_608;
// Conservatively reserves a full sparse map node, key/value and shared headers.
const ENTRY_OVERHEAD: usize = 2048;

#[derive(Debug)]
enum Metadata {
    Payload(u64, Arc<FileGrains>),
    List(Arc<[u8]>),
}

#[derive(Debug, Default)]
pub(crate) struct VerifiedRangeCache {
    generation: u64,
    metadata: BTreeMap<GrainId, (Metadata, usize)>,
    grains: BTreeMap<(GrainId, u32), Arc<[u8]>>,
    metadata_bytes: usize,
    grain_bytes: usize,
}

impl VerifiedRangeCache {
    #[cfg(test)]
    pub(crate) fn generation_for_test(&mut self, generation: u64) {
        self.generation = generation;
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> (u64, usize, usize, usize, usize) {
        (
            self.generation,
            self.metadata.len(),
            self.grains.len(),
            self.metadata_bytes,
            self.grain_bytes,
        )
    }

    pub(crate) fn invalidate(&mut self) -> Result<(), OverlayError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(OverlayError::Poisoned)?;
        self.metadata.clear();
        self.grains.clear();
        self.metadata_bytes = 0;
        self.grain_bytes = 0;
        Ok(())
    }

    pub(crate) fn payload(&self, id: GrainId) -> Option<(u64, Arc<FileGrains>)> {
        match &self.metadata.get(&id)?.0 {
            Metadata::Payload(size, grains) => Some((*size, Arc::clone(grains))),
            Metadata::List(_) => None,
        }
    }

    pub(crate) fn list(&self, id: GrainId) -> Option<Arc<[u8]>> {
        match &self.metadata.get(&id)?.0 {
            Metadata::List(bytes) => Some(Arc::clone(bytes)),
            Metadata::Payload(..) => None,
        }
    }

    pub(crate) fn grain(&self, id: GrainId, length: u32) -> Option<Arc<[u8]>> {
        self.grains.get(&(id, length)).map(Arc::clone)
    }

    pub(crate) fn insert_payload(&mut self, id: GrainId, size: u64, grains: Arc<FileGrains>) {
        let refs = match grains.as_ref() {
            FileGrains::Inline(refs) => {
                refs.capacity() * std::mem::size_of::<granary_core::manifest::GrainRef>()
            }
            FileGrains::Spill { .. } => 0,
        };
        self.insert_metadata(
            id,
            Metadata::Payload(size, grains),
            refs + std::mem::size_of::<FileGrains>(),
        );
    }

    pub(crate) fn insert_list(&mut self, id: GrainId, bytes: Arc<[u8]>) {
        let length = bytes.len();
        self.insert_metadata(id, Metadata::List(bytes), length);
    }

    fn insert_metadata(&mut self, id: GrainId, value: Metadata, bytes: usize) {
        let Some(charge) = bytes
            .checked_add(ENTRY_OVERHEAD)
            .filter(|n| *n <= METADATA_BYTES)
        else {
            return;
        };
        if let Some((_, old)) = self.metadata.remove(&id) {
            self.metadata_bytes -= old;
        }
        // Ordered eviction costs O((e + 1) log M), without an LRU clock.
        while self.metadata_bytes > METADATA_BYTES - charge {
            let Some((_, (_, old))) = self.metadata.pop_first() else {
                return;
            };
            self.metadata_bytes -= old;
        }
        self.metadata.insert(id, (value, charge));
        self.metadata_bytes += charge;
    }

    pub(crate) fn insert_grain(&mut self, id: GrainId, length: u32, bytes: Arc<[u8]>) {
        let Some(charge) = bytes
            .len()
            .checked_add(ENTRY_OVERHEAD)
            .filter(|n| *n <= GRAIN_BYTES)
        else {
            return;
        };
        if let Some(old) = self.grains.remove(&(id, length)) {
            self.grain_bytes -= old.len() + ENTRY_OVERHEAD;
        }
        while self.grain_bytes > GRAIN_BYTES - charge {
            let Some((_, old)) = self.grains.pop_first() else {
                return;
            };
            self.grain_bytes -= old.len() + ENTRY_OVERHEAD;
        }
        self.grains.insert((id, length), bytes);
        self.grain_bytes += charge;
    }
}
