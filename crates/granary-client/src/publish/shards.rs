// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Position-bound shard loading and verification of the final encoded map.

use super::{
    Policy, PublishError, RemoteState, binmap, choose_prefix_bits, decode_err, fetch_meta,
};
use granary_core::binmap::{BinmapIndexDoc, ShardEntry};
use granary_core::{binstore::BinStore, hash::GrainId, root::VolumeName};
use granary_store::crypto::{self, TrustedKeys};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

/// Object work for one captured base, including fallback reads exactly once.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Work {
    pub candidates: usize,
    pub novel: usize,
    pub fetched: Vec<(usize, usize, usize)>,
    pub rewritten: Vec<(usize, usize)>,
    pub encoded: Vec<usize>,
    pub first_trigger: bool,
    pub memo_bypass: bool,
}

/// Exhaustion belongs to the captured base; clones share the flag and counts.
#[derive(Debug, Default)]
pub(crate) struct Exhaustion {
    pub(crate) exhausted: AtomicBool,
    triggers: AtomicU64,
    bypasses: AtomicU64,
}
impl Exhaustion {
    fn trigger(&self) -> bool {
        if self
            .exhausted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.triggers.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    pub(crate) fn counts(&self) -> (u64, u64) {
        (
            self.triggers.load(Ordering::Relaxed),
            self.bypasses.load(Ordering::Relaxed),
        )
    }
}

/// This map is explicitly partial. Membership is only defined for loaded
/// positions. The captured root authenticates the index, table and positions.
#[derive(Debug)]
pub(crate) struct State {
    pub(super) seq: u64,
    pub(super) parent: Option<GrainId>,
    pub(super) epoch: u64,
    pub(super) sheaf_parent: Option<GrainId>,
    pub(super) bins: Vec<[u8; 32]>,
    prefix_bits: u8,
    index_id: Option<GrainId>,
    index_bytes: Option<Vec<u8>>,
    table: Option<(GrainId, Vec<u8>)>,
    prior_shards: Vec<GrainId>,
    loaded: BTreeMap<usize, Vec<ShardEntry>>,
    full: bool,
    memo: Arc<Exhaustion>,
    work: Work,
}
impl State {
    pub(crate) fn from_full(state: RemoteState) -> Self {
        let mut loaded = BTreeMap::<usize, Vec<ShardEntry>>::new();
        for entry in state.known.into_values() {
            loaded
                .entry(binmap::shard_for(&entry.id, state.prefix_bits))
                .or_default()
                .push(entry);
        }
        for at in 0..state.prior_shards.len() {
            loaded.entry(at).or_default();
        }
        Self {
            seq: state.seq,
            parent: state.parent,
            epoch: state.epoch,
            sheaf_parent: state.sheaf_parent,
            bins: state.bins,
            prefix_bits: state.prefix_bits,
            index_id: state.binmap_index,
            index_bytes: state.prior_index,
            table: state.prior_table,
            prior_shards: state.prior_shards,
            loaded,
            full: true,
            memo: Arc::default(),
            work: Work::default(),
        }
    }

    pub(crate) async fn load<R: BinStore>(
        remote: &R,
        volume: &VolumeName,
        bytes: &[u8],
        trusted: &TrustedKeys,
        policy: Policy,
        full: bool,
        memo: Arc<Exhaustion>,
    ) -> Result<Self, PublishError> {
        let head = granary_core::root::decode_root(bytes)
            .map_err(super::decode_err("root"))?
            .seq;
        let doc = crypto::check_head(bytes, volume.as_str(), head, trusted)
            .map_err(|e| super::head_err(head, e))?;
        let seq = head
            .checked_add(1)
            .filter(|&next| next != u64::MAX)
            .ok_or(PublishError::CounterOverflow { what: "root seq" })?;
        let epoch = doc
            .epoch
            .checked_add(1)
            .ok_or(PublishError::CounterOverflow { what: "root epoch" })?;
        let bypass = !full && memo.exhausted.load(Ordering::Acquire);
        if bypass {
            memo.bypasses.fetch_add(1, Ordering::Relaxed);
        }
        let index_bytes = fetch_meta(
            remote,
            volume.as_str(),
            head,
            "binmap index",
            &doc.binmap_index,
        )
        .await?;
        let index =
            binmap::decode_binmap_index(&index_bytes).map_err(decode_err("binmap index"))?;
        // A policy floor is decided before any shard GET, even when the later
        // table or full load refuses. Workspace refusal is never a trigger.
        let floor = !full && policy.min_prefix_bits > index.prefix_bits;
        let trigger = floor && !bypass && memo.trigger();
        let table_bytes =
            fetch_meta(remote, volume.as_str(), head, "bin table", &index.bin_table).await?;
        let bins = binmap::decode_bin_table(&table_bytes).map_err(decode_err("bin table"))?;
        let mut state = Self {
            seq,
            epoch,
            parent: Some(GrainId::of(bytes)),
            sheaf_parent: Some(doc.sheaf_head),
            bins,
            prefix_bits: index.prefix_bits,
            index_id: Some(doc.binmap_index),
            index_bytes: Some(index_bytes),
            table: Some((index.bin_table, table_bytes)),
            prior_shards: index.shards,
            loaded: BTreeMap::new(),
            full: full || bypass || floor,
            memo,
            work: Work {
                first_trigger: trigger,
                memo_bypass: bypass,
                ..Work::default()
            },
        };
        if state.full {
            state.complete(remote, volume.as_str()).await?;
        }
        Ok(state)
    }

    async fn position<R: BinStore>(
        &mut self,
        remote: &R,
        volume: &str,
        at: usize,
    ) -> Result<(), PublishError> {
        if self.loaded.contains_key(&at) {
            return Ok(());
        }
        let id = self
            .prior_shards
            .get(at)
            .ok_or(PublishError::BinmapConstruction)?;
        let bytes = fetch_meta(
            remote,
            volume,
            self.seq.saturating_sub(1),
            "binmap shard",
            id,
        )
        .await?;
        let entries = binmap::decode_shard(&bytes).map_err(decode_err("binmap shard"))?;
        binmap::validate_ordinals(&entries, u32::try_from(self.bins.len()).unwrap_or(u32::MAX))
            .map_err(decode_err("binmap shard"))?;
        binmap::validate_routing(&entries, self.prefix_bits, at)
            .map_err(decode_err("binmap shard"))?;
        self.work.fetched.push((at, bytes.len(), entries.len()));
        self.loaded.insert(at, entries);
        Ok(())
    }

    async fn complete<R: BinStore>(
        &mut self,
        remote: &R,
        volume: &str,
    ) -> Result<(), PublishError> {
        for at in 0..self.prior_shards.len() {
            self.position(remote, volume, at).await?;
        }
        let mut ids = BTreeSet::new();
        for entry in self.loaded.values().flatten() {
            if !ids.insert(entry.id) {
                return Err(PublishError::BinmapConstruction);
            }
        }
        self.full = true;
        Ok(())
    }

    fn lookup(&self, id: &GrainId) -> Result<Option<ShardEntry>, PublishError> {
        // A new volume has no base entries; an unloaded existing position has
        // no membership answer and must never be treated as absence.
        if self.index_id.is_none() {
            return Ok(None);
        }
        let entries = self
            .loaded
            .get(&binmap::shard_for(id, self.prefix_bits))
            .ok_or(PublishError::BinmapConstruction)?;
        Ok(binmap::find_entry(entries, id).copied())
    }

    pub(super) async fn select<R: BinStore>(
        &mut self,
        remote: &R,
        volume: &str,
        candidates: &[GrainId],
    ) -> Result<Vec<GrainId>, PublishError> {
        self.work.candidates = candidates.len();
        if !self.full {
            let routes: BTreeSet<_> = candidates
                .iter()
                .map(|id| binmap::shard_for(id, self.prefix_bits))
                .collect();
            for at in routes {
                self.position(remote, volume, at).await?;
            }
        }
        let novel: Vec<_> = candidates
            .iter()
            .copied()
            .map(|id| self.lookup(&id).map(|entry| (id, entry)))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|(id, entry)| entry.is_none().then_some(id))
            .collect();
        self.work.novel = novel.len();
        if !self.full {
            let mut additions = BTreeMap::<usize, usize>::new();
            for id in &novel {
                *additions
                    .entry(binmap::shard_for(id, self.prefix_bits))
                    .or_default() += 1;
            }
            let overflow = additions.iter().any(|(at, count)| {
                self.loaded
                    .get(at)
                    .and_then(|entries| entries.len().checked_add(*count))
                    .is_none_or(|count| count > binmap::SHARD_MAX_ENTRIES as usize)
            });
            if overflow {
                self.work.first_trigger = self.memo.trigger();
                // The authenticated header and R are moved into completion.
                // No budget reset, refund, recapture or repeated GET occurs.
                self.complete(remote, volume).await?;
            }
        }
        Ok(novel)
    }
}

/// Merge an already canonical shard with canonical additions. Only additions
/// are sorted; reading and copying the old shard is linear in its occupancy.
fn merge_entries(old: &[ShardEntry], new: &[ShardEntry]) -> Result<Vec<ShardEntry>, PublishError> {
    let count = old
        .len()
        .checked_add(new.len())
        .ok_or(PublishError::BinmapConstruction)?;
    let mut merged = Vec::with_capacity(count);
    let mut old = old.iter().peekable();
    let mut new = new.iter().peekable();
    loop {
        let entry = match (old.peek(), new.peek()) {
            (Some(a), Some(b)) => match a.id.cmp(&b.id) {
                std::cmp::Ordering::Less => old.next(),
                std::cmp::Ordering::Greater => new.next(),
                std::cmp::Ordering::Equal => return Err(PublishError::BinmapConstruction),
            },
            (Some(_), None) => old.next(),
            (None, Some(_)) => new.next(),
            (None, None) => break,
        }
        .ok_or(PublishError::BinmapConstruction)?;
        merged.push(*entry);
    }
    Ok(merged)
}

/// Check the decoded union independently of the builder's merge. Every old
/// entry and planned addition must be consumed exactly once, with exact fields.
fn exact_union(actual: &[ShardEntry], old: &[ShardEntry], new: &[ShardEntry]) -> bool {
    if old.len().checked_add(new.len()) != Some(actual.len()) {
        return false;
    }
    let mut old = old.iter().peekable();
    let mut new = new.iter().peekable();
    for entry in actual {
        if old.peek().is_some_and(|expected| *expected == entry) {
            old.next();
        } else if new.peek().is_some_and(|expected| *expected == entry) {
            new.next();
        } else {
            return false;
        }
    }
    old.next().is_none() && new.next().is_none()
}

#[derive(Debug)]
pub(super) struct Build {
    prefix_bits: u8,
    table_id: GrainId,
    table_bytes: Vec<u8>,
    index_id: GrainId,
    index_bytes: Vec<u8>,
    shards: BTreeMap<usize, (GrainId, Vec<u8>)>,
}

pub(super) fn build(
    state: &State,
    bins: &[[u8; 32]],
    additions: &[ShardEntry],
    policy: Policy,
) -> Result<Build, PublishError> {
    let old_count: usize = state.loaded.values().map(Vec::len).sum();
    let prefix_bits = if state.full {
        choose_prefix_bits(
            old_count.saturating_add(additions.len()) as u64,
            state.prefix_bits.max(policy.min_prefix_bits),
        )
    } else {
        state.prefix_bits
    };
    let unchanged_table = bins == state.bins;
    let (table_id, table_bytes) = match &state.table {
        Some((id, bytes)) if unchanged_table => (*id, bytes.clone()),
        _ => {
            let bytes = binmap::encode_bin_table(bins)?;
            (GrainId::of(&bytes), bytes)
        }
    };
    let mut buckets = BTreeMap::<usize, Vec<ShardEntry>>::new();
    if state.full {
        for at in 0..1usize << prefix_bits {
            buckets.insert(at, Vec::new());
        }
        for entry in state.loaded.values().flatten() {
            buckets
                .get_mut(&binmap::shard_for(&entry.id, prefix_bits))
                .ok_or(PublishError::BinmapConstruction)?
                .push(*entry);
        }
    } else {
        for entry in additions {
            buckets
                .entry(binmap::shard_for(&entry.id, prefix_bits))
                .or_default();
        }
    }
    for entry in additions {
        buckets
            .get_mut(&binmap::shard_for(&entry.id, prefix_bits))
            .ok_or(PublishError::BinmapConstruction)?
            .push(*entry);
    }
    let mut shard_ids = if prefix_bits == state.prefix_bits && state.index_id.is_some() {
        state.prior_shards.clone()
    } else {
        vec![GrainId::of(b""); 1usize << prefix_bits]
    };
    let mut shards = BTreeMap::new();
    for (at, mut entries) in buckets {
        entries.sort_unstable_by_key(|entry| entry.id);
        let entries = if state.full {
            entries
        } else {
            merge_entries(
                state
                    .loaded
                    .get(&at)
                    .ok_or(PublishError::BinmapConstruction)?,
                &entries,
            )?
        };
        let bytes = binmap::encode_shard(&entries)?;
        let id = GrainId::of(&bytes);
        *shard_ids
            .get_mut(at)
            .ok_or(PublishError::BinmapConstruction)? = id;
        shards.insert(at, (id, bytes));
    }
    let index_bytes = if additions.is_empty() && prefix_bits == state.prefix_bits && unchanged_table
    {
        match &state.index_bytes {
            Some(bytes) => bytes.clone(),
            None => binmap::encode_binmap_index(prefix_bits, table_id, &shard_ids)?,
        }
    } else {
        binmap::encode_binmap_index(prefix_bits, table_id, &shard_ids)?
    };
    Ok(Build {
        prefix_bits,
        table_id,
        table_bytes,
        index_id: GrainId::of(&index_bytes),
        index_bytes,
        shards,
    })
}

/// Only `verify` constructs this capability. Upload and sync acceptance consume
/// the exact bytes it verified, and cannot turn a partial map into a full one.
#[derive(Debug)]
pub(super) struct VerifiedBuild {
    build: Build,
    complete: Option<BTreeMap<GrainId, ShardEntry>>,
    work: Work,
    prior_shards: Vec<GrainId>,
    prior_width: u8,
    prior_table: Option<GrainId>,
    prior_index: Option<GrainId>,
}
impl VerifiedBuild {
    pub(super) fn prefix_bits(&self) -> u8 {
        self.build.prefix_bits
    }
    pub(super) fn index_id(&self) -> GrainId {
        self.build.index_id
    }
    pub(super) async fn upload<R: BinStore>(
        mut self,
        remote: &R,
        volume: &str,
    ) -> Result<(u64, Option<BTreeMap<GrainId, ShardEntry>>, Work), PublishError> {
        let mut rewritten = 0;
        for (at, (id, bytes)) in self.build.shards {
            if self.prior_width != self.build.prefix_bits || self.prior_shards.get(at) != Some(&id)
            {
                self.work.rewritten.push((at, bytes.len()));
                if remote.put_meta(volume, &id, bytes).await? {
                    rewritten += 1;
                }
            }
        }
        if self.prior_table != Some(self.build.table_id) {
            remote
                .put_meta(volume, &self.build.table_id, self.build.table_bytes)
                .await?;
        }
        if self.prior_index != Some(self.build.index_id) {
            remote
                .put_meta(volume, &self.build.index_id, self.build.index_bytes)
                .await?;
        }
        Ok((rewritten, self.complete, self.work))
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "final-byte integrity checks bind encoded objects, old entries and candidate routes at one capability boundary"
)]
pub(super) fn verify(
    state: &State,
    bins: &[[u8; 32]],
    additions: &[ShardEntry],
    candidates: &[GrainId],
    policy: Policy,
    built: Build,
) -> Result<VerifiedBuild, PublishError> {
    let invalid = || PublishError::BinmapConstruction;
    if GrainId::of(&built.index_bytes) != built.index_id
        || GrainId::of(&built.table_bytes) != built.table_id
    {
        return Err(invalid());
    }
    let index: BinmapIndexDoc =
        binmap::decode_binmap_index(&built.index_bytes).map_err(|_| invalid())?;
    let table = binmap::decode_bin_table(&built.table_bytes).map_err(|_| invalid())?;
    if index.prefix_bits != built.prefix_bits
        || index.bin_table != built.table_id
        || table != bins
        || !table.starts_with(&state.bins)
        || table.iter().collect::<BTreeSet<_>>().len() != table.len()
    {
        return Err(invalid());
    }
    // Full mode retains a complete map. Partial mode keeps canonical spans
    // by position and never sorts or inserts all loaded old entries into a map.
    let complete = if state.full {
        let mut expected = BTreeMap::<GrainId, ShardEntry>::new();
        for entry in state.loaded.values().flatten().chain(additions.iter()) {
            if expected.insert(entry.id, *entry).is_some() {
                return Err(invalid());
            }
        }
        Some(expected)
    } else {
        None
    };
    let want_width = if let Some(expected) = &complete {
        choose_prefix_bits(
            expected.len() as u64,
            state.prefix_bits.max(policy.min_prefix_bits),
        )
    } else {
        state.prefix_bits
    };
    if index.prefix_bits != want_width || index.shards.len() != 1usize << want_width {
        return Err(invalid());
    }
    let mut expected_routes = BTreeMap::<usize, Vec<ShardEntry>>::new();
    if let Some(expected) = &complete {
        for entry in expected.values() {
            expected_routes
                .entry(binmap::shard_for(&entry.id, want_width))
                .or_default()
                .push(*entry);
        }
    } else {
        for entry in additions {
            expected_routes
                .entry(binmap::shard_for(&entry.id, want_width))
                .or_default()
                .push(*entry);
        }
        for entries in expected_routes.values_mut() {
            entries.sort_unstable_by_key(|entry| entry.id);
        }
    }
    let mut decoded = BTreeMap::<usize, Vec<ShardEntry>>::new();
    for (at, (id, bytes)) in &built.shards {
        if GrainId::of(bytes) != *id || index.shards.get(*at) != Some(id) {
            return Err(invalid());
        }
        let entries = binmap::decode_shard(bytes).map_err(|_| invalid())?;
        binmap::validate_routing(&entries, want_width, *at).map_err(|_| invalid())?;
        binmap::validate_ordinals(&entries, u32::try_from(table.len()).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let wanted = expected_routes.get(at).map_or(&[][..], Vec::as_slice);
        let matches = if state.full {
            entries == wanted
        } else {
            exact_union(&entries, state.loaded.get(at).ok_or_else(invalid)?, wanted)
        };
        if !matches {
            return Err(invalid());
        }
        decoded.insert(*at, entries);
    }
    if state.full {
        if decoded.len() != index.shards.len() {
            return Err(invalid());
        }
    } else {
        for (at, id) in index.shards.iter().enumerate() {
            if !built.shards.contains_key(&at) && state.prior_shards.get(at) != Some(id) {
                return Err(invalid());
            }
        }
        for (at, entries) in &state.loaded {
            if !decoded.contains_key(at) {
                let old_id = state.prior_shards.get(*at).ok_or_else(invalid)?;
                if index.shards.get(*at) != Some(old_id) {
                    return Err(invalid());
                }
                decoded.insert(*at, entries.clone());
            }
        }
    }
    for id in candidates {
        let at = binmap::shard_for(id, index.prefix_bits);
        let entries = decoded.get(&at).ok_or_else(invalid)?;
        let wanted = if let Some(expected) = &complete {
            expected.get(id)
        } else {
            expected_routes
                .get(&at)
                .and_then(|planned| binmap::find_entry(planned, id))
                .or_else(|| {
                    state
                        .loaded
                        .get(&at)
                        .and_then(|old| binmap::find_entry(old, id))
                })
        };
        if wanted.is_none() || binmap::find_entry(entries, id) != wanted {
            return Err(invalid());
        }
    }
    let mut work = state.work.clone();
    work.encoded = built.shards.keys().copied().collect();
    Ok(VerifiedBuild {
        prior_width: state.prefix_bits,
        prior_shards: state.prior_shards.clone(),
        prior_table: state.table.as_ref().map(|(id, _)| *id),
        prior_index: state.index_id,
        build: built,
        complete,
        work,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod injection;
