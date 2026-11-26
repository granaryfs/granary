// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Additive binmap proof. An unchanged ordinal retains its meaning because
//! the table prefix is retained. Rows then compare by grain ID and extent.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use granary_core::binfmt::BinIndexEntry;
use granary_core::binmap::{
    BINMAP_FIXED_HEADER_LEN, BINMAP_INDEX_FIXED_HEADER_LEN, BinmapIndexDoc, SHARD_ENTRY_LEN,
    ShardEntry, decode_bin_table, decode_binmap_index, decode_shard, shard_for, validate_ordinals,
    validate_routing,
};
use granary_core::hash::{DIGEST_LEN, GRAIN_ID_BINARY_LEN, GrainId};
use granary_core::root::VolumeName;

use super::{
    Result, ValidationAttempt, ValidationCandidate, ValidationError, ValidationObject,
    ValidationRead, VerifiedContent, check_reference_id, frames, invalid, manifest,
};

use super::budget::Work;
use super::proofs::Lengths;

pub(super) type Table = Arc<[[u8; DIGEST_LEN]]>;
pub(super) type Rows = Arc<[ShardEntry]>;

/// Decoded candidate shards retained only for the current manifest walk.
/// Keep one slot per index entry and charge the retained rows against a
/// fixed byte ceiling that also applies across intake slices.
pub(super) struct Shards {
    slots: Vec<Option<Rows>>,
    bytes_left: u64,
}

impl Shards {
    pub(super) fn new(work: &ValidationAttempt, index: &BinmapIndexDoc) -> Result<Self> {
        // Include each slot and the shared slice's reference counters.
        let slot_bytes = size_of::<Option<Rows>>() + 2 * size_of::<usize>();
        let slot_bytes = index.shards.len().saturating_mul(slot_bytes);
        let bytes_left = work
            .memory_bytes()
            .checked_sub(slot_bytes as u64)
            .ok_or(ValidationError::WorkLimit)?;
        Ok(Self {
            slots: vec![None; index.shards.len()],
            bytes_left,
        })
    }

    pub(super) fn get(&self, slot: usize) -> Option<&Rows> {
        self.slots.get(slot)?.as_ref()
    }

    pub(super) fn rows(&self) -> impl Iterator<Item = &ShardEntry> {
        self.slots.iter().flatten().flat_map(|rows| rows.iter())
    }

    pub(super) fn insert(&mut self, slot: usize, rows: Rows) -> Result<()> {
        let target = self
            .slots
            .get_mut(slot)
            .ok_or(ValidationError::InvalidReference)?;
        self.bytes_left = self
            .bytes_left
            .checked_sub(std::mem::size_of_val(rows.as_ref()) as u64)
            .ok_or(ValidationError::WorkLimit)?;
        *target = Some(rows);
        Ok(())
    }
}

const CACHE_OBJECT_BYTES: usize = 1024 * 1024;

/// One decoded index (bounded by the format), up to 1 MiB of table and
/// 1 MiB of root-shard rows per live baseline. Old snapshots carry no history.
#[derive(Debug, Clone, Default)]
pub(super) struct Cache {
    index: Option<Arc<BinmapIndexDoc>>,
    table: Option<Table>,
    root_shard: Option<(GrainId, Rows)>,
}

impl Cache {
    pub(super) fn new(
        index: Arc<BinmapIndexDoc>,
        table: Table,
        root_shard: Option<(GrainId, Rows)>,
    ) -> Self {
        Self {
            index: Some(index),
            table: (table.len() <= CACHE_OBJECT_BYTES / size_of::<[u8; DIGEST_LEN]>())
                .then_some(table),
            root_shard,
        }
    }
}

#[cfg(test)]
impl Cache {
    pub(super) fn evict_shard(&mut self) {
        self.root_shard = None;
    }
}

pub(super) async fn validate(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    root: &ValidationCandidate,
    parent: Option<&VerifiedContent>,
) -> Result<(Cache, Lengths)> {
    let new_manifest = parent.is_none_or(|proof| proof.root.manifest != root.manifest);
    if let Some(proof) = parent
        && !new_manifest
        && proof.root.binmap == root.binmap
    {
        return Ok((proof.cache.clone(), proof.lengths.clone()));
    }

    let prior = Cache::default();
    let prior = parent.map_or(&prior, |proof| &proof.cache);
    let (old, old_table) = if let Some(proof) = parent {
        let index = match &prior.index {
            Some(index) => index.clone(),
            None => read_index(work, source, &root.volume, proof.root.binmap, true).await?,
        };
        let table = match &prior.table {
            Some(table) => table.clone(),
            None => read_table(work, source, &root.volume, index.bin_table, true).await?,
        };
        (Some(index), table)
    } else {
        (None, Arc::from([]))
    };

    let index = if let Some(old) = &old
        && parent.is_some_and(|proof| proof.root.binmap == root.binmap)
    {
        old.clone()
    } else {
        read_index(work, source, &root.volume, root.binmap, false).await?
    };
    let old_width = old
        .as_ref()
        .map_or(index.prefix_bits, |prior| prior.prefix_bits);
    let gained_bits = index
        .prefix_bits
        .checked_sub(old_width)
        .ok_or(ValidationError::InvalidReference)?;
    let same_table = old
        .as_ref()
        .is_some_and(|prior| prior.bin_table == index.bin_table);
    let table = if same_table {
        old_table.clone()
    } else {
        let table = read_table(work, source, &root.volume, index.bin_table, false).await?;
        let candidate = table.clone();
        let prior = old_table.clone();
        work.blocking(move |work| {
            work.steps(prior.len() as u64)?;
            if candidate.starts_with(&prior) {
                Ok(())
            } else {
                Err(ValidationError::InvalidReference)
            }
        })
        .await?;
        table
    };

    let map = MapComparison {
        index: &index,
        old: old.as_deref(),
        prior,
        volume: &root.volume,
        manifest: root.manifest,
        old_table_len: old_table.len(),
        table_len: u32::try_from(table.len()).map_err(|_| ValidationError::InvalidReference)?,
        group_width: 1usize << gained_bits,
    };
    drop(old_table);
    let mut shards = new_manifest
        .then(|| Shards::new(work, &index))
        .transpose()?;
    let (additions, root_shard) = map.compare(work, source, shards.as_mut()).await?;
    let lengths = parent
        .map(|proof| proof.lengths.clone())
        .unwrap_or_default();
    let facts = frames::Facts::new(lengths, work.length_allocation()?);
    let mut facts =
        frames::verify(work, source, &table, map.old_table_len, additions, facts).await?;
    if let Some(shards) = shards {
        let map = manifest::Map {
            index: &index,
            table: &table,
            shards,
        };
        manifest::walk(work, source, root, map, &mut facts, true).await?;
    }
    Ok((Cache::new(index, table, root_shard), facts.into_lengths()))
}

struct MapComparison<'a> {
    index: &'a BinmapIndexDoc,
    old: Option<&'a BinmapIndexDoc>,
    prior: &'a Cache,
    volume: &'a VolumeName,
    manifest: GrainId,
    old_table_len: usize,
    table_len: u32,
    group_width: usize,
}

impl MapComparison<'_> {
    async fn compare(
        &self,
        work: &mut ValidationAttempt,
        source: &impl ValidationRead,
        mut shards: Option<&mut Shards>,
    ) -> Result<(Additions, Option<(GrainId, Rows)>)> {
        let mut delta = Additions::default();
        let root_slot = shard_for(&self.manifest, self.index.prefix_bits);
        let mut root_shard = None;
        let mut slot = 0usize;
        let mut old_ids = BTreeSet::new();
        if let Some(old) = self.old {
            work.steps(old.shards.len() as u64)?;
            old_ids.extend(old.shards.iter().copied());
        }

        // With a wider prefix, each consecutive group of candidate
        // slots partitions one old slot, in the same grain-ID order.
        for (old_slot, group) in self.index.shards.chunks(self.group_width).enumerate() {
            let old_id = self
                .old
                .and_then(|index| index.shards.get(old_slot))
                .copied();
            if let [id] = group
                && Some(*id) == old_id
            {
                work.steps(1)?;
                let cached = self
                    .prior
                    .root_shard
                    .as_ref()
                    .filter(|(cached, _)| cached == id);
                if let Some((_, rows)) = cached
                    && let Some(shards) = shards.as_deref_mut()
                {
                    shards.insert(slot, rows.clone())?;
                }
                if slot == root_slot {
                    root_shard = cached.cloned();
                }
                slot = slot.saturating_add(1);
                continue;
            }
            let old_rows = match old_id {
                Some(id) => self.old_rows(work, source, id).await?,
                None => Arc::from([]),
            };
            let mut consumed = 0;
            for &id in group {
                work.steps(1)?;
                let rows = read_shard(
                    work,
                    source,
                    self.volume,
                    id,
                    old_ids.contains(&id),
                    Some((self.index.prefix_bits, slot, self.table_len)),
                )
                .await?;
                let prior = old_rows.clone();
                let candidate = rows.clone();
                (delta, consumed) = work
                    .blocking(move |work| {
                        let consumed = delta.compare_rows(work, &candidate, &prior, consumed)?;
                        Ok((delta, consumed))
                    })
                    .await?;
                if slot == root_slot {
                    root_shard = cache_rows(id, rows.clone());
                }
                if let Some(shards) = shards.as_deref_mut() {
                    shards.insert(slot, rows)?;
                }
                slot = slot.saturating_add(1);
            }
            if consumed != old_rows.len() {
                return Err(ValidationError::InvalidReference);
            }
        }
        Ok((delta, root_shard))
    }

    async fn old_rows(
        &self,
        work: &mut ValidationAttempt,
        source: &impl ValidationRead,
        id: GrainId,
    ) -> Result<Rows> {
        if let Some((cached, rows)) = &self.prior.root_shard
            && *cached == id
        {
            work.steps(rows.len() as u64)?;
            return Ok(rows.clone());
        }
        read_shard(work, source, self.volume, id, true, None).await
    }
}

pub(super) fn cache_rows(id: GrainId, rows: Rows) -> Option<(GrainId, Rows)> {
    (rows.len() <= CACHE_OBJECT_BYTES / size_of::<ShardEntry>()).then_some((id, rows))
}

#[derive(Default)]
pub(super) struct Additions {
    pub(super) by_bin: BTreeMap<usize, Vec<BinIndexEntry>>,
}

impl Additions {
    fn add(&mut self, row: &ShardEntry) -> Result<()> {
        let ordinal =
            usize::try_from(row.bin_ordinal).map_err(|_| ValidationError::InvalidReference)?;
        self.by_bin.entry(ordinal).or_default().push(BinIndexEntry {
            id: row.id,
            offset: row.offset,
            comp_len: row.comp_len,
        });
        Ok(())
    }

    fn compare_rows(
        &mut self,
        work: &mut Work,
        rows: &[ShardEntry],
        prior: &[ShardEntry],
        mut consumed: usize,
    ) -> Result<usize> {
        work.steps(rows.len() as u64)?;
        for row in rows {
            let old = prior.get(consumed).filter(|old| old.id <= row.id);
            if let Some(old) = old {
                if old != row {
                    return Err(ValidationError::InvalidReference);
                }
                consumed = consumed.saturating_add(1);
            }
            if old.is_none() {
                self.add(row)?;
            }
        }
        Ok(consumed)
    }
}

pub(super) async fn read_index(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    volume: &VolumeName,
    id: GrainId,
    verified: bool,
) -> Result<Arc<BinmapIndexDoc>> {
    let bytes = work
        .read(source, ValidationObject::Meta(volume, id), verified)
        .await?;
    work.meter(row_steps(
        &bytes,
        BINMAP_INDEX_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN,
        GRAIN_ID_BINARY_LEN,
    ))
    .await?;
    work.blocking(move |_| {
        check_reference_id(&bytes, id, verified)?;
        Ok(Arc::new(decode_binmap_index(&bytes).map_err(invalid)?))
    })
    .await
}

pub(super) async fn read_table(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    volume: &VolumeName,
    id: GrainId,
    verified: bool,
) -> Result<Table> {
    let bytes = work
        .read(source, ValidationObject::Meta(volume, id), verified)
        .await?;
    work.meter(row_steps(&bytes, BINMAP_FIXED_HEADER_LEN, DIGEST_LEN))
        .await?;
    work.blocking(move |_| {
        check_reference_id(&bytes, id, verified)?;
        Ok(decode_bin_table(&bytes).map_err(invalid)?.into())
    })
    .await
}

pub(super) async fn read_shard(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    volume: &VolumeName,
    id: GrainId,
    verified: bool,
    routing: Option<(u8, usize, u32)>,
) -> Result<Rows> {
    let bytes = work
        .read(source, ValidationObject::Meta(volume, id), verified)
        .await?;
    work.meter(row_steps(&bytes, BINMAP_FIXED_HEADER_LEN, SHARD_ENTRY_LEN))
        .await?;
    work.blocking(move |_| {
        check_reference_id(&bytes, id, verified)?;
        let rows = decode_shard(&bytes).map_err(invalid)?;
        if let Some((bits, slot, bins)) = routing {
            validate_routing(&rows, bits, slot).map_err(invalid)?;
            validate_ordinals(&rows, bins).map_err(invalid)?;
        }
        Ok(rows.into())
    })
    .await
}

fn row_steps(bytes: &[u8], header: usize, row: usize) -> u64 {
    // Each strict decoder checks the exact fixed-stride length before
    // allocating rows from the declared count.
    (bytes.len().saturating_sub(header) / row) as u64
}
