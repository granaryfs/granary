// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One publication step for an open entry, and the delay between steps.
//!
//! A step is one create-only PUT of the entry's recorded final bytes at
//! its decided seq, then one classification read of that seq. **The
//! PUT's result is never used**: a success still gets its read, and a
//! failure, a terminal one included, settles only the attempt it answers,
//! while an earlier attempt can still land. Only the read decides, and
//! only landed or lost closes the entry; the worker records them. A step
//! takes no state: it runs on a copy of what the entry recorded, so it
//! can be polled beside the worker's answers, and it is never dropped
//! once begun (the seam's `put_root` is not cancel-safe).

use std::time::Duration;

use granary_core::hash::GrainId;
use granary_core::rng::Rng;
use granary_core::root::VolumeName;
use granary_core::rootstore::RootStore;
use granary_store::crypto::TrustedKeys;

use super::chain::{Classification, classify_seq};
use super::gate::FenceCell;

/// The delay before the first re-issue.
const REISSUE_BASE: Duration = Duration::from_millis(100);
/// The longest delay between re-issues.
const REISSUE_CAP: Duration = Duration::from_secs(30);

/// What a step needs of an attested entry: the seq it was decided at, its
/// recorded base, and its recorded final bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Publishing {
    pub(crate) root_seq: u64,
    pub(crate) base: Option<GrainId>,
    pub(crate) final_bytes: Vec<u8>,
}

/// How a step ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// The engine was fenced before the PUT, which was never issued.
    Fenced,
    /// The PUT was issued and the seq read; this is what the read found.
    Read(Classification),
}

/// One step (module docs). The fence is read immediately before the PUT
/// is issued, with no await between, so no PUT begins after the fence.
///
/// # Cancellation safety
/// Not cancel-safe once polled: it holds a `put_root` in flight. Drive
/// it to completion.
pub(crate) async fn step<S: RootStore>(
    store: &S,
    fence: &FenceCell,
    volume: &VolumeName,
    keys: &TrustedKeys,
    entry: &Publishing,
) -> Step {
    if fence.is_set() {
        return Step::Fenced;
    }
    // Ignored on purpose (module docs): only the read below decides.
    let _ = store
        .put_root(volume.as_str(), entry.root_seq, entry.final_bytes.clone())
        .await;
    Step::Read(
        classify_seq(
            store,
            volume,
            keys,
            entry.root_seq,
            entry.base,
            &entry.final_bytes,
        )
        .await,
    )
}

/// The delay before re-issue number `reissue` (0 for the first): the
/// base doubled once per earlier re-issue, capped, then drawn uniformly
/// from its upper half with the randomness seam, so a seed fixes every
/// delay and entries on different volumes do not re-issue in step.
pub(crate) fn reissue_delay<R: Rng>(reissue: u64, rng: &mut R) -> Duration {
    let doublings = u32::try_from(reissue.min(16)).unwrap_or(16);
    let ceiling = REISSUE_BASE
        .saturating_mul(1_u32 << doublings)
        .min(REISSUE_CAP);
    let ceiling_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    let half = ceiling_ms / 2;
    Duration::from_millis(half.saturating_add(rng.below(ceiling_ms - half + 1)))
}

#[cfg(test)]
mod tests;
