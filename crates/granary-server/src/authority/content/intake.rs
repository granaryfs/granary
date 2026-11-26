// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only baseline intake for the observed head of a cold volume.

use std::future::{Future, pending};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use granary_core::binfmt::{
    BIN_FIXED_HEADER_LEN, BIN_INDEX_ENTRY_LEN, BinIndexEntry, decode_bin_index,
};
use granary_core::binmap::{BinmapIndexDoc, shard_for};
use granary_core::clock::Clock;
use granary_core::hash::GrainId;
use granary_core::root::{RootDoc, VolumeName, check_link};
use granary_core::sheaf::Timestamp;
use granary_store::crypto::{TrustedKeys, check_head};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

use crate::authority::chain::{ChainMemo, HeadRef};

use super::binmap::{Cache, Shards, cache_rows, read_index, read_shard, read_table};
use super::frames::{Facts, check_mapping, read_bin, read_frame};
use super::manifest::{self, Map};
use super::proofs::{Lengths, Proofs, check_length_limit};
use super::store::{Admission, max_seq};
use super::{
    Result, ValidationAttempt, ValidationCandidate, ValidationError, ValidationObject,
    ValidationRead, VerifiedContent, check_id, read_sheaf,
};

const TOTAL_TIME: Duration = Duration::from_mins(30);
const HANDOFF_SECONDS: u32 = 30;

#[cfg(test)]
#[derive(Debug, Default)]
pub(in crate::authority) struct Gate {
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

#[derive(Debug)]
pub(in crate::authority) enum Outcome {
    Verified(Box<Verified>),
    Damaged(HeadRef),
    LengthLimit(HeadRef),
    Retry,
}

/// A job that passed the final head recheck still owns the intake ticket.
#[derive(Debug)]
pub(in crate::authority) struct Verified {
    memo: ChainMemo,
    proof: VerifiedContent,
    ticket: Arc<OwnedSemaphorePermit>,
}

impl Verified {
    #[cfg(test)]
    pub(in crate::authority) fn matches(&self, volume: &VolumeName, id: GrainId) -> bool {
        self.proof.matches(volume, id)
    }

    pub(in crate::authority) fn promote(
        self,
        pool: &Proofs,
        now: Timestamp,
    ) -> (ChainMemo, Option<Handoff>) {
        let handoff = pool.install(self.proof).map(|proof| {
            let lease = Lease {
                proof: Arc::new(proof),
                _ticket: self.ticket,
                expires_at: Timestamp {
                    secs: now.secs.saturating_add(i64::from(HANDOFF_SECONDS)),
                    nanos: now.nanos,
                },
            };
            Handoff(Arc::new(Mutex::new(Some(lease))))
        });
        (self.memo, handoff)
    }
}

/// Keep a proof that exceeds the resident budget available to a timely retry.
/// The worker drives expiry alongside requests.
#[derive(Debug, Clone)]
pub(in crate::authority) struct Handoff(Arc<Mutex<Option<Lease>>>);

// Drop the proof before releasing the ticket.
#[derive(Debug)]
struct Lease {
    proof: Arc<VerifiedContent>,
    _ticket: Arc<OwnedSemaphorePermit>,
    expires_at: Timestamp,
}

impl Handoff {
    pub(in crate::authority) fn expiration(&self) -> impl Future<Output = ()> + use<> {
        let lease = self.clone();
        let timer = timeout(
            Duration::from_secs(u64::from(HANDOFF_SECONDS)),
            pending::<()>(),
        );
        async move {
            let _expired = timer.await;
            lease.take();
        }
    }

    pub(in crate::authority) fn is_held(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn take(&self) -> Option<Lease> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    pub(in crate::authority) fn claim(
        self,
        volume: &VolumeName,
        id: GrainId,
        now: Timestamp,
    ) -> Option<Arc<VerifiedContent>> {
        let lease = self.take()?;
        if now >= lease.expires_at || !lease.proof.matches(volume, id) {
            return None;
        }
        Some(lease.proof.clone())
    }
}

pub(in crate::authority) async fn run(
    source: &Admission,
    clock: Arc<dyn Clock>,
    volume: VolumeName,
    keys: TrustedKeys,
) -> Outcome {
    timeout(TOTAL_TIME, intake(source, clock, &volume, &keys))
        .await
        .unwrap_or(Outcome::Retry)
}

/// Check the listing has completed and then re-read the exact root. A
/// matching ID at the original sequence alone says nothing about a newer head.
pub(in crate::authority) async fn current(
    source: &Admission,
    work: &mut ValidationAttempt,
    volume: &VolumeName,
    head: HeadRef,
) -> Result<bool> {
    if max_seq(source, work, volume, head.head_seq.checked_sub(1)).await? != Some(head.head_seq) {
        return Ok(false);
    }
    let bytes = work
        .read(source, ValidationObject::Root(volume, head.head_seq), false)
        .await?;
    Ok(GrainId::of(&bytes) == head.head_id)
}

async fn intake(
    source: &Admission,
    clock: Arc<dyn Clock>,
    volume: &VolumeName,
    keys: &TrustedKeys,
) -> Outcome {
    let Ok(Some(mut work)) = source.begin_intake(clock).await else {
        return Outcome::Retry;
    };
    let Ok(Some(seq)) = max_seq(source, &mut work, volume, None).await else {
        return Outcome::Retry;
    };
    let Ok(bytes) = work
        .read(source, ValidationObject::Root(volume, seq), false)
        .await
    else {
        return Outcome::Retry;
    };
    let head = HeadRef {
        head_seq: seq,
        head_id: GrainId::of(&bytes),
    };
    let result = verify(source, &mut work, (&bytes, head), volume, keys).await;
    if matches!(
        result,
        Err(ValidationError::WorkLimit | ValidationError::Unavailable)
    ) {
        return Outcome::Retry;
    }
    crash_point!(IntakeBeforeRecheck);
    #[cfg(test)]
    if let Some(gate) = &source.intake_gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    if current(source, &mut work, volume, head).await != Ok(true) {
        return Outcome::Retry;
    }
    match result {
        Ok((memo, proof)) => match work.into_intake_ticket() {
            Some(ticket) => Outcome::Verified(Box::new(Verified {
                memo,
                proof,
                ticket,
            })),
            None => Outcome::Retry,
        },
        Err(ValidationError::LengthLimit) => Outcome::LengthLimit(head),
        Err(_) => Outcome::Damaged(head),
    }
}

async fn verify(
    source: &Admission,
    work: &mut ValidationAttempt,
    (bytes, head): (&[u8], HeadRef),
    volume: &VolumeName,
    keys: &TrustedKeys,
) -> Result<(ChainMemo, VerifiedContent)> {
    let doc = check_head(bytes, volume.as_str(), head.head_seq, keys)
        .map_err(|_| ValidationError::InvalidReference)?;
    let root = ValidationCandidate::from_root(&doc, head.head_id);
    let memo = ChainMemo::established(head, doc.parent);
    verify_ancestry(source, work, doc).await?;
    let (cache, lengths) = verify_content(source, work, &root).await?;
    Ok((
        memo,
        VerifiedContent {
            root,
            cache,
            lengths,
        },
    ))
}

async fn verify_ancestry(
    source: &Admission,
    work: &mut ValidationAttempt,
    mut doc: RootDoc,
) -> Result<()> {
    loop {
        let sheaf = read_sheaf(
            work,
            source,
            &doc.volume,
            doc.sheaf_head,
            doc.manifest_root,
            false,
        )
        .await?;
        if doc.seq == 1 {
            return if doc.parent.is_none() && sheaf.is_none() {
                Ok(())
            } else {
                Err(ValidationError::InvalidReference)
            };
        }
        let prev = doc
            .seq
            .checked_sub(1)
            .ok_or(ValidationError::InvalidReference)?;
        let bytes = work
            .read(source, ValidationObject::Root(&doc.volume, prev), false)
            .await?;
        doc = check_link(doc.parent, &bytes, doc.volume.as_str(), prev)
            .map_err(|_| ValidationError::InvalidReference)?;
        if sheaf != Some(doc.sheaf_head) {
            return Err(ValidationError::InvalidReference);
        }
    }
}

/// Retain only a fingerprint per bin and one decoded index. The fingerprint
/// is of the exact prefix already checked against the whole-bin digest. This
/// lets arbitrarily ordered shard rows check exact tuples using small ranges.
struct BinIndex {
    id: GrainId,
    bytes: u32,
}

pub(super) async fn verify_content(
    source: &impl ValidationRead,
    work: &mut ValidationAttempt,
    root: &ValidationCandidate,
) -> Result<(Cache, Lengths)> {
    let index = read_index(work, source, &root.volume, root.binmap, false).await?;
    let table = read_table(work, source, &root.volume, index.bin_table, false).await?;
    let bins = u32::try_from(table.len()).map_err(|_| ValidationError::InvalidReference)?;
    let shards = read_shards(source, work, &root.volume, &index, bins).await?;
    let mut indexes = Vec::new();
    let mut cached = None;
    for (ordinal, &digest) in table.iter().enumerate() {
        let (bytes, entries) = read_bin(work, source, digest, false).await?;
        let (fingerprint, entries) = work
            .blocking(move |_| {
                let len = BIN_FIXED_HEADER_LEN + entries.len() * BIN_INDEX_ENTRY_LEN;
                let prefix = bytes.get(..len).ok_or(ValidationError::InvalidReference)?;
                Ok((
                    BinIndex {
                        id: GrainId::of(prefix),
                        bytes: u32::try_from(len).map_err(|_| ValidationError::InvalidReference)?,
                    },
                    entries,
                ))
            })
            .await?;
        indexes.push(fingerprint);
        cached = Some((ordinal, entries));
    }

    let mut facts = Facts::new(Lengths::default(), work.length_allocation()?);
    for row in shards.rows().copied() {
        work.meter(1).await?;
        let ordinal = row.bin_ordinal as usize;
        let digest = *table
            .get(ordinal)
            .ok_or(ValidationError::InvalidReference)?;
        if cached.as_ref().is_none_or(|(at, _)| *at != ordinal) {
            let prefix = indexes
                .get(ordinal)
                .ok_or(ValidationError::InvalidReference)?;
            let bytes = work
                .read(
                    source,
                    ValidationObject::BinRange(digest, 0, prefix.bytes),
                    false,
                )
                .await?;
            let steps = bytes.len().saturating_sub(BIN_FIXED_HEADER_LEN) / BIN_INDEX_ENTRY_LEN;
            work.meter(steps as u64).await?;
            let id = prefix.id;
            let entries = work
                .blocking(move |_| {
                    check_id(&bytes, id)?;
                    decode_bin_index(&bytes).map_err(super::invalid)
                })
                .await?;
            cached = Some((ordinal, entries));
        }
        let (_, entries) = cached.as_ref().ok_or(ValidationError::InvalidReference)?;
        check_mapping(
            entries,
            &BinIndexEntry {
                id: row.id,
                offset: row.offset,
                comp_len: row.comp_len,
            },
        )?;
        let (bytes, len) = read_frame(work, source, digest, row, false).await?;
        facts.remember(row.id, &bytes, len)?;
    }
    let root_slot = shard_for(&root.manifest, index.prefix_bits);
    let root_shard = index
        .shards
        .get(root_slot)
        .zip(shards.get(root_slot))
        .and_then(|(&id, rows)| cache_rows(id, rows.clone()));
    let map = Map {
        index: &index,
        table: &table,
        shards,
    };
    manifest::walk(work, source, root, map, &mut facts, false).await?;
    Ok((Cache::new(index, table, root_shard), facts.into_lengths()))
}

async fn read_shards(
    source: &impl ValidationRead,
    work: &mut ValidationAttempt,
    volume: &VolumeName,
    index: &BinmapIndexDoc,
    bins: u32,
) -> Result<Shards> {
    let mut shards = Shards::new(work, index)?;
    let mut count = 0usize;
    for (slot, &id) in index.shards.iter().enumerate() {
        let routing = Some((index.prefix_bits, slot, bins));
        let rows = read_shard(work, source, volume, id, false, routing).await?;
        // Each decoded shard has unique IDs and routing keeps IDs disjoint.
        count = count.saturating_add(rows.len());
        check_length_limit(count)?;
        shards.insert(slot, rows)?;
    }
    Ok(shards)
}
