// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory lengths and the authority's LRU of landed volume proofs.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    Arc, Mutex, PoisonError, Weak,
    atomic::{AtomicUsize, Ordering},
};

use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{Result, ValidationError, VerifiedContent};

const VOLUME_ENTRIES: usize = 1 << 20;
// Include the length, B-tree nodes and shared bucket bookkeeping.
const ENTRY_BYTES: usize = 96;
const BUCKET_BYTES: usize = 512;
const PROOF_BYTES: usize = VOLUME_ENTRIES * ENTRY_BYTES + 256 * BUCKET_BYTES;
pub(super) const DEFAULT_VALIDATIONS: u16 = 2;
const PENDING_BYTES: usize = 2 * PROOF_BYTES;
const RESIDENT_BYTES: usize = (1 << 30) - outside_lru_bytes(DEFAULT_VALIDATIONS);

const fn outside_lru_bytes(validations: u16) -> usize {
    // One parent and child per validation, the shared pending budget, and
    // one proof for intake (including any handoff).
    (2 * validations as usize + 1)
        .saturating_mul(PROOF_BYTES)
        .saturating_add(PENDING_BYTES)
}

pub(super) fn check_length_limit(count: usize) -> Result<()> {
    if count > VOLUME_ENTRIES {
        return Err(ValidationError::LengthLimit);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(in crate::authority) struct Proofs(Arc<Pool>);

#[derive(Debug)]
struct Pool {
    resident_limit: usize,
    live_limit: usize,
    bytes: Arc<AtomicUsize>,
    pending: Arc<Semaphore>,
    // Least recently used first, with at most one proof per volume.
    landed: Mutex<VecDeque<Arc<VerifiedContent>>>,
}

/// Drop or install the proof before returning its charge to the pending budget.
#[derive(Debug)]
pub(in crate::authority) struct PendingProof {
    proof: VerifiedContent,
    _charge: OwnedSemaphorePermit,
}

impl PendingProof {
    pub(in crate::authority) fn install(self, pool: &Proofs) {
        pool.install(self.proof);
    }
}

impl Proofs {
    pub(super) fn new(validations: u16) -> Self {
        Self::with_limits(
            RESIDENT_BYTES,
            RESIDENT_BYTES.saturating_add(outside_lru_bytes(validations)),
        )
    }

    fn with_limits(resident_limit: usize, live_limit: usize) -> Self {
        Self(Arc::new(Pool {
            resident_limit,
            live_limit,
            bytes: Arc::default(),
            pending: Arc::new(Semaphore::new(PENDING_BYTES)),
            landed: Mutex::default(),
        }))
    }

    pub(super) fn fresh(&self) -> Self {
        Self::with_limits(self.0.resident_limit, self.0.live_limit)
    }

    #[cfg(test)]
    pub(super) fn with_resident_limit(&self, bytes: usize) -> Self {
        let headroom = self.0.live_limit - self.0.resident_limit;
        Self::with_limits(bytes, bytes + headroom)
    }

    #[cfg(test)]
    pub(in crate::authority) fn resident_bytes(&self) -> usize {
        let landed = self.0.landed.lock().unwrap_or_else(PoisonError::into_inner);
        landed.iter().map(|proof| proof.lengths.bytes()).sum()
    }

    #[cfg(test)]
    pub(in crate::authority) fn live_bytes(&self) -> usize {
        self.0.bytes.load(Ordering::Relaxed)
    }

    pub(in crate::authority) fn get(
        &self,
        volume: &VolumeName,
        id: GrainId,
    ) -> Option<Arc<VerifiedContent>> {
        let mut landed = self.0.landed.lock().unwrap_or_else(PoisonError::into_inner);
        let at = landed
            .iter()
            .position(|proof| &proof.root.volume == volume)?;
        let proof = landed.remove(at)?;
        if !proof.matches(volume, id) {
            return None;
        }
        landed.push_back(proof.clone());
        Some(proof)
    }

    pub(in crate::authority) fn has_landed(&self, volume: &VolumeName) -> bool {
        let landed = self.0.landed.lock().unwrap_or_else(PoisonError::into_inner);
        landed.iter().any(|proof| &proof.root.volume == volume)
    }

    pub(in crate::authority) fn retain_pending(
        &self,
        proof: VerifiedContent,
    ) -> Option<PendingProof> {
        let bytes = u32::try_from(proof.lengths.bytes()).ok()?;
        let charge = self.0.pending.clone().try_acquire_many_owned(bytes).ok()?;
        Some(PendingProof {
            proof,
            _charge: charge,
        })
    }

    /// Install a landed proof and return it only if it exceeds the resident budget.
    pub(in crate::authority) fn install(&self, proof: VerifiedContent) -> Option<VerifiedContent> {
        let mut landed = self.0.landed.lock().unwrap_or_else(PoisonError::into_inner);
        let incoming = proof.lengths.bytes();
        // Resident proofs belong to distinct volumes, so their buckets are
        // disjoint. Readers and COW siblings affect only the live charge.
        let mut resident = 0;
        landed.retain(|old| {
            if old.root.volume == proof.root.volume {
                return false;
            }
            resident += old.lengths.bytes();
            true
        });
        let Some(room) = self.0.resident_limit.checked_sub(incoming) else {
            return Some(proof);
        };
        while resident > room {
            let Some(old) = landed.pop_front() else { break };
            resident -= old.lengths.bytes();
        }
        landed.push_back(Arc::new(proof));
        None
    }

    pub(in crate::authority) fn discard(&self, volume: &VolumeName) {
        let mut landed = self.0.landed.lock().unwrap_or_else(PoisonError::into_inner);
        landed.retain(|proof| &proof.root.volume != volume);
    }

    fn reserve(&self, bytes: usize) -> Result<()> {
        self.0
            .bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|&total| total <= self.0.live_limit)
            })
            .map(|_| ())
            .map_err(|_| ValidationError::Unavailable)
    }
}

/// A verification may allocate only while it holds its validation slot or
/// whole intake ticket. Detached CPU work holds its own copy of that permit.
#[derive(Debug)]
pub(super) struct Allocation {
    pool: Proofs,
    permit: Weak<OwnedSemaphorePermit>,
}

impl Allocation {
    pub(super) fn new(pool: Proofs, permit: &Arc<OwnedSemaphorePermit>) -> Self {
        Self {
            pool,
            permit: Arc::downgrade(permit),
        }
    }

    fn reserve(&self, bytes: usize) -> Result<()> {
        let _permit = self.permit.upgrade().ok_or(ValidationError::Unavailable)?;
        self.pool.reserve(bytes)
    }

    fn bucket(&self, entries: BTreeMap<GrainId, u32>) -> Arc<Bucket> {
        Arc::new(Bucket {
            entries,
            bytes: self.pool.0.bytes.clone(),
        })
    }
}

/// Buckets are shared with the parent until the candidate adds a length in
/// that bucket. Each allocation is charged until its last holder drops it,
/// including staged proofs, intake jobs and readers of evicted proofs.
#[derive(Debug, Clone, Default)]
pub(super) struct Lengths {
    count: usize,
    buckets: Arc<BTreeMap<u8, Arc<Bucket>>>,
}

#[derive(Debug)]
struct Bucket {
    entries: BTreeMap<GrainId, u32>,
    bytes: Arc<AtomicUsize>,
}

impl Drop for Bucket {
    fn drop(&mut self) {
        self.bytes.fetch_sub(
            BUCKET_BYTES + self.entries.len() * ENTRY_BYTES,
            Ordering::Relaxed,
        );
    }
}

impl Lengths {
    fn bytes(&self) -> usize {
        self.count * ENTRY_BYTES + self.buckets.len() * BUCKET_BYTES
    }

    pub(super) fn get(&self, id: &GrainId) -> Option<u32> {
        self.buckets.get(&prefix(id))?.entries.get(id).copied()
    }

    pub(super) fn insert(&mut self, allocation: &Allocation, id: GrainId, len: u32) -> Result<()> {
        if self.get(&id).is_some() {
            return Ok(());
        }
        check_length_limit(self.count.saturating_add(1))?;
        let buckets = Arc::make_mut(&mut self.buckets);
        let bucket = match buckets.entry(prefix(&id)) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let bucket = entry.into_mut();
                if Arc::get_mut(bucket).is_none() {
                    allocation.reserve(BUCKET_BYTES + (bucket.entries.len() + 1) * ENTRY_BYTES)?;
                    *bucket = allocation.bucket(bucket.entries.clone());
                } else {
                    allocation.reserve(ENTRY_BYTES)?;
                }
                Arc::get_mut(bucket).ok_or(ValidationError::Unavailable)?
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                allocation.reserve(BUCKET_BYTES + ENTRY_BYTES)?;
                let bucket = entry.insert(allocation.bucket(BTreeMap::new()));
                Arc::get_mut(bucket).ok_or(ValidationError::Unavailable)?
            }
        };
        bucket.entries.insert(id, len);
        self.count += 1;
        Ok(())
    }
}

fn prefix(id: &GrainId) -> u8 {
    id.digest().first().copied().unwrap_or_default()
}

#[cfg(test)]
mod tests;
