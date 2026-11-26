// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The canonical manifest cursor over hash-verified binmap extents.

use granary_core::binmap::{BinmapIndexDoc, find_entry, shard_for};
use granary_core::hash::GrainId;
use granary_core::manifest::{GrainRef, Step, TreeCursor, TreeSource, ValidateError};

use super::binmap::{Shards, Table, read_shard};
use super::frames::{Facts, read_frame};
use super::{Result, ValidationAttempt, ValidationCandidate, ValidationError, ValidationRead};

pub(super) struct Map<'a> {
    pub(super) index: &'a BinmapIndexDoc,
    pub(super) table: &'a Table,
    pub(super) shards: Shards,
}

pub(super) async fn walk(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    root: &ValidationCandidate,
    map: Map<'_>,
    facts: &mut Facts,
    verified: bool,
) -> Result<()> {
    let mut source = Source {
        work,
        store: source,
        root,
        map,
        facts,
        verified,
        error: None,
    };
    match TreeCursor::new(root.manifest)
        .resume_with(&mut source)
        .await
    {
        Ok(Step::Done(_)) => Ok(()),
        Ok(Step::Need(_)) | Err(_) => {
            Err(source.error.unwrap_or(ValidationError::InvalidReference))
        }
    }
}

struct Source<'a, S> {
    work: &'a mut ValidationAttempt,
    store: &'a S,
    root: &'a ValidationCandidate,
    map: Map<'a>,
    facts: &'a mut Facts,
    verified: bool,
    error: Option<ValidationError>,
}

impl<S: ValidationRead> Source<'_, S> {
    async fn frame(&mut self, id: GrainId) -> Result<Vec<u8>> {
        let slot = shard_for(&id, self.map.index.prefix_bits);
        if self.map.shards.get(slot).is_none() {
            let shard = *self
                .map
                .index
                .shards
                .get(slot)
                .ok_or(ValidationError::InvalidReference)?;
            let rows = read_shard(
                self.work,
                self.store,
                &self.root.volume,
                shard,
                self.verified,
                None,
            )
            .await?;
            self.map.shards.insert(slot, rows)?;
        }
        let row = self
            .map
            .shards
            .get(slot)
            .and_then(|rows| find_entry(rows, &id))
            .copied()
            .ok_or(ValidationError::MissingReference)?;
        let digest = *self
            .map
            .table
            .get(row.bin_ordinal as usize)
            .ok_or(ValidationError::InvalidReference)?;
        let (bytes, _) = read_frame(self.work, self.store, digest, row, self.verified).await?;
        self.facts.remember_node(id, &bytes);
        Ok(bytes)
    }

    fn checked<T>(&mut self, result: Result<T>) -> std::result::Result<T, ValidateError> {
        result.map_err(|error| {
            self.error = Some(error);
            ValidateError::SourceInterrupted
        })
    }
}

impl<S: ValidationRead> TreeSource for Source<'_, S> {
    async fn node(&mut self, id: GrainId) -> std::result::Result<Vec<u8>, ValidateError> {
        if let Some(bytes) = self.facts.node(&id) {
            return Ok(bytes);
        }
        let result = self.frame(id).await;
        self.checked(result)
    }

    async fn charge(&mut self, steps: u64) -> std::result::Result<(), ValidateError> {
        let result = self.work.meter(steps).await;
        self.checked(result)
    }

    async fn file_ref(&mut self, reference: GrainRef) -> std::result::Result<(), ValidateError> {
        let result = async {
            self.work.meter(1).await?;
            let len = self
                .facts
                .lengths()
                .get(&reference.id)
                .ok_or(ValidationError::MissingReference)?;
            if len == reference.unpacked_len {
                Ok(())
            } else {
                Err(ValidationError::InvalidReference)
            }
        }
        .await;
        self.checked(result)
    }
}
