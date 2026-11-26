// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded operator observation of refusals, independent of traffic controls.

use crate::wire::ErrorToken;
use granary_core::enrollment::{PRINCIPALS_MAX, PrincipalId};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// A closed refusal-reason registry; no request-derived labels are retained.
pub type RefusalReason = ErrorToken;

/// Process totals and the bounded, oldest-inserted principal working set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RefusalSnapshot {
    /// Saturating process totals, unaffected by row eviction.
    pub totals: BTreeMap<RefusalReason, u64>,
    /// Saturating totals for at most `PRINCIPALS_MAX` enrolled principals.
    pub principals: BTreeMap<PrincipalId, BTreeMap<RefusalReason, u64>>,
}

#[derive(Debug, Default)]
struct State {
    principals: BTreeMap<PrincipalId, BTreeMap<RefusalReason, u64>>,
    insertion_order: VecDeque<PrincipalId>,
}

/// Shared counters, with no log writes and no control-state mutation.
#[derive(Debug)]
pub struct RefusalCounters {
    totals: BTreeMap<RefusalReason, AtomicU64>,
    principals: Mutex<State>,
}

impl Default for RefusalCounters {
    fn default() -> Self {
        Self {
            totals: [
                ErrorToken::IntentSuperseded,
                ErrorToken::IntentBound,
                ErrorToken::IntentChanged,
                ErrorToken::IntentAbsent,
                ErrorToken::IntentCursorChanged,
                ErrorToken::IntentEpochExhausted,
                ErrorToken::IntentQuota,
                ErrorToken::NotFound,
                ErrorToken::UnknownTarget,
                ErrorToken::AlreadyExists,
                ErrorToken::AddressMismatch,
                ErrorToken::VerifyFailed,
                ErrorToken::LayoutInvalid,
                ErrorToken::BadRange,
                ErrorToken::ExtentTooWide,
                ErrorToken::BadRequest,
                ErrorToken::MethodNotAllowed,
                ErrorToken::TooLarge,
                ErrorToken::Internal,
                ErrorToken::Unavailable,
                ErrorToken::NoPrincipal,
                ErrorToken::NotEnrolled,
                ErrorToken::RateLimited,
                ErrorToken::AuthorityManaged,
                ErrorToken::InvalidCandidate,
                ErrorToken::NoLog,
                ErrorToken::UnknownVolume,
                ErrorToken::StaleBase,
                ErrorToken::OperationBound,
                ErrorToken::NotDecided,
                ErrorToken::EpochMismatch,
                ErrorToken::VolumeDamaged,
                ErrorToken::Fenced,
                ErrorToken::Stopped,
                ErrorToken::EnrollmentUnavailable,
            ]
            .into_iter()
            .map(|reason| (reason, AtomicU64::new(0)))
            .collect(),
            principals: Mutex::default(),
        }
    }
}

fn increment(row: &mut BTreeMap<RefusalReason, u64>, reason: RefusalReason) {
    let count = row.entry(reason).or_default();
    *count = count.saturating_add(1);
}

impl RefusalCounters {
    /// Observe one selected refusal. Unknown callers receive no row.
    pub(crate) fn record(&self, reason: RefusalReason, principal: Option<PrincipalId>) {
        if let Some(total) = self.totals.get(&reason) {
            let _ = total.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
        }
        let Some(principal) = principal else {
            return;
        };
        let mut state = self
            .principals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.principals.contains_key(&principal) {
            if state.principals.len() == PRINCIPALS_MAX
                && let Some(oldest) = state.insertion_order.pop_front()
            {
                state.principals.remove(&oldest);
            }
            state.insertion_order.push_back(principal);
        }
        increment(state.principals.entry(principal).or_default(), reason);
    }

    /// Operator data only; never part of the public volume-status bytes.
    /// Enrollment availability reasons remain in `EnrollmentReader::snapshot`.
    #[must_use]
    pub fn snapshot(&self) -> RefusalSnapshot {
        let principals = self
            .principals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .principals
            .clone();
        let totals = self
            .totals
            .iter()
            .filter_map(|(&reason, total)| {
                let count = total.load(Ordering::Relaxed);
                (count != 0).then_some((reason, count))
            })
            .collect();
        RefusalSnapshot { totals, principals }
    }
}

#[cfg(test)]
mod tests;
