// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Durable continuation of a frozen publication across authority epochs.
//!
//! A validated stale-base answer releases an exact current-epoch tuple only
//! after a fresh owned-first barrier witnessed foreign occupancy at its slot,
//! the reported head is at or beyond that slot (with the same foreign id when
//! equal), and no matching current entry has decision evidence.
//! Every accepted exact tuple replays before stale-base can answer, proving
//! no earlier decision. Permanent create-only chain progress prevents
//! a later one.
//! Other answers retain their attempt-local meaning and do not supply this
//! release proof. Unrelated tuples and retired entries are excluded.
//!
//! Same-epoch log restoration from a backup, a second authority process, and
//! out-of-band deletion break these premises.
//! An open entry behind witnessed foreign occupancy ends the invocation
//! pending possible out-of-band repair. The authority lifecycle guide
//! in `docs/operating-the-authority-lifecycle.md` describes safe recovery
//! of authority state.

mod command;
#[cfg(test)]
type ResidualCheck = Box<dyn FnMut() -> Result<(), crate::CoordinationError>>;
#[cfg(test)]
std::thread_local! {
    /// The expiry check a test injects at validation's cooperative boundaries.
    pub(crate) static RESIDUAL_CHECK: std::cell::RefCell<Option<ResidualCheck>> = const { std::cell::RefCell::new(None) };
    pub(crate) static FINISH_DELAYS: std::cell::Cell<(std::time::Duration, std::time::Duration, std::time::Duration)> = const {
        std::cell::Cell::new((std::time::Duration::ZERO, std::time::Duration::ZERO, std::time::Duration::ZERO))
    };
}
mod coordinator;
pub use command::{
    RecoveryCommand, RecoveryCommandError, RecoveryConflictInventory, RecoveryConflictStage,
    RecoveryOutcome,
};
pub(crate) use coordinator::resume_store_publication;
mod journal;
pub(crate) use journal::{DirtyWitness, WitnessTree};
mod landing;
pub use journal::RecoveryJournal;
pub(crate) use landing::finish_landing_matches;
#[cfg(test)]
pub(crate) use landing::{LandingHooks, landing_hooks_for_test};
mod preparation;
mod probe;
pub(crate) use probe::probe_archive;
pub use probe::{NeverLandedProof, ProbeOutcome, probe_submission};
pub(crate) use probe::{refetch_landing, same_landing};
mod residual;
#[cfg(test)]
pub(crate) use residual::CapturedContent;
#[cfg(test)]
pub(crate) use residual::authenticate_residual_sources;
pub(crate) use residual::{CapturedPayload, ResidualEvidence, ResidualSource, preflight_residual};
mod settlement;
pub(crate) use preparation::read_closure;
#[cfg(test)]
pub(crate) use settlement::finish_landed_boundary_for_test;
pub use settlement::settle_recovery_boundary;
mod types;
pub use coordinator::{
    SelectedPublication, begin_exact_publication, begin_publication, begin_selected_publication,
    bootstrap_publication, resume_exact_publication, resume_publication,
};
pub use types::{
    AuthorityTransport, NoWriteProof, PublicationHandle, PublicationJournal, PublicationOutcome,
    PublicationResult, RecoveredObjects, RecoveryBackoff, RecoveryDelay, RecoveryError,
    RecoveryIntent, RecoveryParts, RejectionProof,
};
pub(crate) use types::{DISPATCH_ATTEMPTS, MAX_UNAVAILABLE_EXEMPTIONS, charged_attempts};

use granary_core::hash::GrainId;
use granary_core::retained_submission::{Completion, Phase, Probe, ProbeReason, Role, Submission};

pub(crate) fn retire(record: &mut Submission, epoch: [u8; 16]) {
    record
        .candidates
        .retain(|c| c.role == Role::Retired || !c.evidence.never_decided());
    for candidate in &mut record.candidates {
        candidate.role = Role::Retired;
    }
    record.current = None;
    record.phase = Phase::EpochRecovery { epoch };
    clear_pruned_response(record);
}

fn clear_pruned_response(record: &mut Submission) {
    if record
        .last_response
        .as_ref()
        .is_some_and(|r| !record.candidates.iter().any(|c| c.number == r.candidate))
    {
        record.last_response = None;
    }
}

pub(crate) fn deferred_answer_pending(record: &Submission) -> bool {
    let Phase::Unresolved(probe) = record.phase else {
        return false;
    };
    if probe.reason != ProbeReason::ContentUnavailable {
        return false;
    }
    record.last_response.as_ref().is_some_and(|response| {
        !response.answer.is_empty()
            && record.candidates.iter().any(|candidate| {
                candidate.role == Role::Active
                    && candidate.number == response.candidate
                    && candidate.seq == probe.seq
            })
    })
}

fn deferred_probe(record: &Submission) -> Option<Probe> {
    let Phase::Unresolved(probe) = record.phase else {
        return None;
    };
    deferred_answer_pending(record).then_some(probe)
}

fn compare(
    record: &mut Submission,
    winner: Option<&granary_core::retained_submission::Candidate>,
    occupants: impl IntoIterator<Item = (u64, GrainId)>,
) {
    if let Some(winner) = winner {
        record.phase = Phase::Complete(Completion {
            seq: winner.seq,
            id: winner.id,
            root: winner.root.clone(),
            receipt: None,
        });
        record.current = None;
    } else {
        // Occupancy can wedge a current-epoch decision without closing it.
        // Release history only on the same all-submissions proof as retirement.
        for (seq, _) in occupants {
            record.candidates.retain(|c| match c.role {
                Role::Retired => c.seq != seq,
                Role::History => !c.evidence.never_decided(),
                Role::Active => true,
            });
        }
        clear_pruned_response(record);
    }
}

#[cfg(test)]
pub(crate) mod tests;
