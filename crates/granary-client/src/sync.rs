// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Object preparation over a sealed, immutable file version.

use crate::{CapturedFile, ClientMetrics, CoordinationError};
use granary_core::grainsource::GrainSource;
use granary_core::hash::GrainId;
use granary_core::manifest::{self, FileGrains, GrainRef};
use granary_core::thresh;

/// Work measured before deduplication, independently of upload novelty.
#[derive(Debug, Default, Clone, Copy)]
pub struct RechunkStats {
    pub cutter_bytes: u64,
    pub read_bytes: u64,
    pub max_buffer: usize,
    pub cut_grains: u64,
    pub reused_grains: u64,
    pub fallback: bool,
}

/// Canonical payload after bounded cutting. Grain and list objects have been
/// handed to the local object sink; remote acceptance is a separate barrier.
#[derive(Debug)]
pub struct RechunkedFile {
    pub grains: FileGrains,
    pub content: GrainId,
    pub stats: RechunkStats,
}

fn invalid() -> CoordinationError {
    CoordinationError::Refused("SyncRechunkContent")
}

struct Cutter {
    old: Vec<GrainRef>,
    offsets: Vec<u64>,
    dirty: Vec<(u64, u64)>,
    size: u64,
    buffer: Vec<u8>,
    buffer_start: u64,
    stats: RechunkStats,
}
impl Cutter {
    fn preceding(&self, offset: u64) -> usize {
        self.offsets
            .partition_point(|start| *start < offset)
            .saturating_sub(1)
    }

    fn reuse(
        &mut self,
        from: usize,
        to: usize,
        out: &mut Vec<GrainRef>,
    ) -> Result<(), CoordinationError> {
        let refs = self.old.get(from..to).ok_or_else(invalid)?;
        self.stats.reused_grains += refs.len() as u64;
        out.extend_from_slice(refs);
        Ok(())
    }

    fn cut(
        &mut self,
        at: u64,
        read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, CoordinationError>,
    ) -> Result<Vec<u8>, CoordinationError> {
        let buffered_end = self.buffer_start + self.buffer.len() as u64;
        if at >= self.buffer_start && at <= buffered_end {
            let consumed = usize::try_from(at - self.buffer_start).map_err(|_| invalid())?;
            self.buffer.drain(..consumed);
        } else {
            self.buffer.clear();
        }
        self.buffer_start = at;
        let wanted = usize::try_from((self.size - at).min(thresh::MAX_GRAIN as u64))
            .map_err(|_| invalid())?;
        while self.buffer.len() < wanted {
            let n = (wanted - self.buffer.len()).min(65_536);
            let bytes = read(at + self.buffer.len() as u64, n)?;
            if bytes.len() != n {
                return Err(invalid());
            }
            self.stats.read_bytes += n as u64;
            self.buffer.extend(bytes);
        }
        self.stats.max_buffer = self.stats.max_buffer.max(self.buffer.len());
        // A full maximum-sized lookahead, or the real captured EOF. A smaller
        // search window must never masquerade as EOF to FastCDC.
        let grain = thresh::grains(&self.buffer).next().ok_or_else(invalid)?;
        self.stats.cutter_bytes += grain.length as u64;
        self.stats.cut_grains += 1;
        Ok(self
            .buffer
            .get(..grain.length)
            .ok_or_else(invalid)?
            .to_vec())
    }

    fn run(
        &mut self,
        read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, CoordinationError>,
        put: &mut impl FnMut(GrainId, &[u8]) -> Result<(), CoordinationError>,
    ) -> Result<Vec<GrainRef>, CoordinationError> {
        let mut out = Vec::new();
        let mut next_old = 0;
        let mut next_dirty = 0;
        while let Some(&(start, end)) = self.dirty.get(next_dirty) {
            let begin = self.preceding(start);
            self.reuse(next_old, begin, &mut out)?;
            let mut at = *self.offsets.get(begin).ok_or_else(invalid)?;
            let expansion_start = at;
            let mut changed_end = end.min(self.size);
            next_dirty += 1;
            loop {
                if at == self.size {
                    next_old = self.old.len();
                    break;
                }
                let bytes = self.cut(at, read)?;
                let id = GrainId::of(&bytes);
                let end = at.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
                if end == self.size {
                    self.stats.fallback = !self.old.is_empty() && expansion_start == 0;
                }
                put(id, &bytes)?;
                out.push(GrainRef {
                    id,
                    unpacked_len: u32::try_from(bytes.len()).map_err(|_| invalid())?,
                });
                at = end;
                // Merge later expansions as soon as their preceding old grain
                // overlaps this one. Each changed byte is cut only once.
                while let Some(&(start, end)) = self.dirty.get(next_dirty) {
                    let begin = self.preceding(start);
                    if self.offsets.get(begin).copied().ok_or_else(invalid)? > at {
                        break;
                    }
                    changed_end = changed_end.max(end.min(self.size));
                    next_dirty += 1;
                }
                if at == self.size {
                    next_old = self.old.len();
                    break;
                }
                // Offset equality plus sealed no-touch provenance proves that
                // the following unchanged region restarts both cutters here.
                if at >= changed_end
                    && let Ok(index) = self.offsets.binary_search(&at)
                {
                    next_old = index;
                    break;
                }
            }
        }
        self.reuse(next_old, self.old.len(), &mut out)?;
        Ok(out)
    }
}

/// Re-cut only changed expansions through their first proved shared boundary.
/// `checkpoint` must be the captured file's canonical last synced/base payload;
/// its spill list is fetched and authenticated through `source`, never silently
/// replaced with initial chunking. `read` resolves the exact sealed version in
/// short range transactions outside callbacks; it receives at most 65,536 bytes.
/// `put` accepts local content-addressed objects, including a rebuilt spill list.
/// Neither callback may substitute live staging for the sealed byte version.
///
/// # Errors
/// Missing, corrupt or foreign checkpoint, invalid intervals, short immutable
/// read, or local object sink failure. Completed full-span cutter work counts
/// once even when a later object sink refuses it; unfinished cutting does not.
pub fn rechunk_captured(
    captured: &CapturedFile,
    checkpoint: Option<&FileGrains>,
    source: &dyn GrainSource,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, CoordinationError>,
    mut put: impl FnMut(GrainId, &[u8]) -> Result<(), CoordinationError>,
    metrics: &ClientMetrics,
) -> Result<RechunkedFile, CoordinationError> {
    let old = match (captured.checkpoint(), checkpoint) {
        (Some((content, size)), Some(grains)) => {
            let payload = manifest::node::file_payload(size, grains).map_err(|_| invalid())?;
            if GrainId::of(&payload) != content {
                return Err(invalid());
            }
            crate::writable_store::capture::captured_refs(source, size, grains)?
        }
        (None, None) => Vec::new(),
        _ => return Err(invalid()),
    };
    let size = captured.size();
    let dirty = if captured.checkpoint().is_none() {
        fresh_dirty(size)
    } else {
        captured.dirty_intervals()
    };
    let mut stats = RechunkStats::default();
    let output = rechunk_file(size, old, &dirty, &mut read, &mut put, &mut stats);
    if stats.fallback {
        captured.record_rechunk_fallback(metrics);
    }
    output
}

pub(crate) fn fresh_dirty(size: u64) -> Vec<(u64, u64)> {
    if size == 0 {
        Vec::new()
    } else {
        vec![(0, size)]
    }
}

pub(crate) fn rechunk_file(
    size: u64,
    old: Vec<GrainRef>,
    dirty: &[(u64, u64)],
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, CoordinationError>,
    put: &mut impl FnMut(GrainId, &[u8]) -> Result<(), CoordinationError>,
    stats: &mut RechunkStats,
) -> Result<RechunkedFile, CoordinationError> {
    let mut offsets = vec![0u64];
    for grain in &old {
        let end = offsets
            .last()
            .copied()
            .ok_or_else(invalid)?
            .checked_add(u64::from(grain.unpacked_len))
            .ok_or_else(invalid)?;
        offsets.push(end);
    }
    let limit = size.max(offsets.last().copied().ok_or_else(invalid)?);
    let mut previous_end = None;
    for &(start, end) in dirty {
        if start >= end || end > limit || previous_end.is_some_and(|previous| previous >= start) {
            return Err(invalid());
        }
        previous_end = Some(end);
    }
    let mut cutter = Cutter {
        old,
        offsets,
        dirty: dirty.to_vec(),
        size,
        buffer: Vec::new(),
        buffer_start: 0,
        stats: RechunkStats::default(),
    };
    let result = cutter.run(read, put);
    *stats = cutter.stats;
    let refs = result?;
    let grains = if refs.len() <= manifest::FILE_INLINE_MAX_REFS as usize {
        FileGrains::Inline(refs)
    } else {
        let grain_count = u32::try_from(refs.len()).map_err(|_| invalid())?;
        let built = manifest::build_grain_list(&refs).map_err(|_| invalid())?;
        for (id, bytes) in built.nodes {
            put(id, &bytes)?;
        }
        FileGrains::Spill {
            grain_count,
            root: built.root,
        }
    };
    let payload = manifest::node::file_payload(size, &grains).map_err(|_| invalid())?;
    Ok(RechunkedFile {
        grains,
        content: GrainId::of(&payload),
        stats: cutter.stats,
    })
}

#[cfg(test)]
mod tests;

mod base;
mod clock;
mod objects;
mod published;
pub use base::VerifiedBase;
pub(crate) use base::{CommitWalk, binmap_error, contained, contained_by};
pub use clock::{InstantClock, MonotonicClock, MonotonicDomain, MonotonicToken};
pub(crate) use published::PublishedRoot;
mod engine;
pub(crate) use engine::{
    Adopted, AdoptionCommit, Budget, CommitDrive, LandedCommit, MountViewHook, Revocation,
    RuntimeSeams, ViewInstall, build_landed_entries, commit_send_budget, failure_class,
    head_above_pin, refused, terminal_non_landing, workspace_error,
};
mod head;
#[cfg(test)]
pub(crate) use engine::{AdopterFuture, EngineHold, HeadAdopter, Resumed, RetentionPanic};
pub use engine::{
    LiveEnd, RetainedCommit, SyncContent, SyncEngine, SyncOptions, SyncRemote, SyncWaiter,
};
pub(crate) use head::{Begin, HeadObserver, Observed, VIEW_PROBE_DEADLINE};
pub(crate) mod rebase;
mod runtime;
mod shutdown;
#[cfg(test)]
pub(crate) use objects::accept_sync_projection_full;
pub(crate) use objects::entries_tree;
pub use objects::{
    AcceptedSyncProjection, SyncObjectSelection, SyncProjectionQueue, accept_sync_projection,
};
pub use runtime::{OperationContext, SyncRuntime, SyncRuntimeError, TokioSyncRuntime};
pub(crate) use shutdown::{
    Cause, Cut, DEFAULT_SHUTDOWN_BOUND, MountShutdown, Outcome, Shutdown, Trigger, report_outcome,
};
pub use shutdown::{
    Cause as ShutdownCause, Cut as ShutdownCut, Outcome as ShutdownOutcome, Residue,
    ShutdownHandle, ShutdownReport, Trigger as ShutdownTrigger,
};
