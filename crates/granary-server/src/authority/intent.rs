// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Principal-scoped ownership transitions over committed intent snapshots.

pub(crate) mod codec;
pub(crate) mod persistence;
#[cfg(test)]
pub(crate) mod tests;

use crate::wire::{ContentType, ErrorToken, Outcome, Status};
use granary_core::authlog::Epoch;
use granary_core::enrollment::PrincipalId;
use granary_core::hash::GrainId;
use granary_core::intent::{self as wire, OwnershipMode, Receipt, ReceiptState};
use granary_core::root::VolumeName;
use granary_core::sheaf::Timestamp;
use granary_store::crypto::{TrustedKeys, check_signatures};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub receipt: Receipt,
    pub root: Arc<[u8]>,
    pub grant: wire::Grant,
    pub changed: Timestamp,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Principal {
    pub h: u64,
    pub rows: BTreeMap<[u8; 16], Row>,
}
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), derive(Clone))]
pub(crate) struct Snapshot {
    pub volume: VolumeName,
    pub epoch: Epoch,
    pub principals: BTreeMap<PrincipalId, Principal>,
}

#[cfg(test)]
pub(crate) static SNAPSHOT_CLONES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
impl Clone for Snapshot {
    fn clone(&self) -> Self {
        SNAPSHOT_CLONES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self {
            volume: self.volume.clone(),
            epoch: self.epoch,
            principals: self.principals.clone(),
        }
    }
}

/// An intent operation; ownership's body selects acquire or takeover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentOperation {
    /// Register or refresh a prepared root.
    Register,
    /// Release an owned row.
    Release,
    /// Acquire or conditionally transfer ownership.
    Ownership,
    /// Read only this principal's live rows and cursor.
    Readback,
}
impl IntentOperation {
    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::Register => "intent_register",
            Self::Release => "intent_release",
            Self::Ownership => "intent_ownership",
            Self::Readback => "intent_readback",
        }
    }
}
pub(crate) const STORE_KIND: &str = "intent_store";

pub(crate) struct Transition {
    pub outcome: Outcome,
    pub next: Option<Principal>,
}
fn answer(status: Status, token: Option<ErrorToken>, ty: ContentType, body: Vec<u8>) -> Outcome {
    Outcome::intent(status, token, ty, body)
}
fn refusal(token: ErrorToken) -> Transition {
    Transition {
        outcome: Outcome::intent_refused(Status::Conflict, token),
        next: None,
    }
}
fn receipt(row: &Row, token: Option<ErrorToken>) -> Transition {
    match wire::encode_receipt(row.receipt) {
        Ok(bytes) => Transition {
            outcome: answer(
                if token.is_some() {
                    Status::Conflict
                } else {
                    Status::Ok
                },
                token,
                ContentType::IntentReceipt,
                bytes,
            ),
            next: None,
        },
        Err(_) => internal(),
    }
}
fn internal() -> Transition {
    Transition {
        outcome: Outcome::intent_refused(Status::InternalServerError, ErrorToken::Internal),
        next: None,
    }
}
fn unchanged(outcome: Outcome) -> Transition {
    Transition {
        outcome,
        next: None,
    }
}
fn changed_at(old: Timestamp, now: Timestamp) -> Timestamp {
    if (old.secs, old.nanos) > (now.secs, now.nanos) {
        old
    } else {
        now
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "The complete ordered ownership outcome table stays at one review site"
)]
pub(crate) fn transition(
    current: Option<&Principal>,
    operation: IntentOperation,
    bytes: &[u8],
    volume: &VolumeName,
    keys: &TrustedKeys,
    now: Timestamp,
) -> Transition {
    // In a validated store an unseen principal has never allocated an epoch.
    let empty = Principal::default();
    let p = current.unwrap_or(&empty);
    match operation {
        IntentOperation::Readback => {
            let rows: Vec<_> = p
                .rows
                .values()
                .filter(|r| !r.root.is_empty())
                .map(|r| wire::ReadbackRow {
                    writer: r.receipt.writer,
                    epoch: r.receipt.epoch,
                    generation: r.receipt.generation,
                    root: &r.root,
                })
                .collect();
            match wire::encode_readback(p.h, &rows) {
                Ok(body) => unchanged(answer(Status::Ok, None, ContentType::IntentReadback, body)),
                Err(_) => internal(),
            }
        }
        IntentOperation::Ownership => {
            let Ok(request) = wire::decode_ownership(bytes) else {
                return unchanged(Outcome::intent_refused(
                    Status::BadRequest,
                    ErrorToken::BadRequest,
                ));
            };
            let old = p.rows.get(&request.writer);
            let q = GrainId::of(bytes);
            if let Some(row) = old
                && row.grant.request_id == q
                && row.grant.receipt.epoch == row.receipt.epoch
                && row.grant.receipt.instance == row.receipt.instance
            {
                return match wire::encode_grant(row.grant) {
                    Ok(body) => unchanged(answer(Status::Ok, None, ContentType::IntentGrant, body)),
                    Err(_) => internal(),
                };
            }
            match request.mode {
                OwnershipMode::Acquire { observed_cursor } => {
                    if let Some(row) = old {
                        return receipt(row, Some(ErrorToken::IntentChanged));
                    }
                    if observed_cursor != p.h {
                        return refusal(ErrorToken::IntentCursorChanged);
                    }
                }
                OwnershipMode::Takeover {
                    expected_epoch,
                    generation,
                    state,
                    ..
                } => {
                    let Some(row) = old else {
                        return refusal(ErrorToken::IntentAbsent);
                    };
                    if row.receipt.epoch != expected_epoch {
                        return receipt(row, Some(ErrorToken::IntentSuperseded));
                    }
                    if row.receipt.generation != generation || row.receipt.state != state {
                        return receipt(row, Some(ErrorToken::IntentChanged));
                    }
                }
            }
            let Some(epoch) = p.h.checked_add(1) else {
                return refusal(ErrorToken::IntentEpochExhausted);
            };
            if old.is_none() && p.rows.len() >= wire::MAX_TOTAL_ROWS {
                return refusal(ErrorToken::IntentQuota);
            }
            let mut row = old.cloned().unwrap_or(Row {
                receipt: Receipt {
                    writer: request.writer,
                    epoch,
                    instance: request.instance,
                    generation: 0,
                    state: ReceiptState::Released,
                },
                root: Arc::from([]),
                grant: wire::Grant {
                    request_id: q,
                    receipt: Receipt {
                        writer: request.writer,
                        epoch,
                        instance: request.instance,
                        generation: 0,
                        state: ReceiptState::Released,
                    },
                },
                changed: now,
            });
            row.receipt.epoch = epoch;
            row.receipt.instance = request.instance;
            row.grant = wire::Grant {
                request_id: q,
                receipt: row.receipt,
            };
            row.changed = changed_at(row.changed, now);
            let Ok(body) = wire::encode_grant(row.grant) else {
                return internal();
            };
            let mut next = p.clone();
            next.h = epoch;
            next.rows.insert(request.writer, row);
            Transition {
                outcome: answer(Status::Ok, None, ContentType::IntentGrant, body),
                next: Some(next),
            }
        }
        IntentOperation::Register | IntentOperation::Release => {
            let (writer, epoch, instance, g, root) = if operation == IntentOperation::Register {
                match wire::decode_register(bytes, volume, |doc, signed| {
                    check_signatures(doc, signed, keys).is_ok()
                }) {
                    Ok(r) => (r.writer, r.epoch, r.instance, r.generation, Some(r.root)),
                    Err(e) => {
                        let token = match e {
                            wire::Error::RootInvalid(_)
                            | wire::Error::RootWrongVolume
                            | wire::Error::RootBadSignature
                            | wire::Error::RootEmpty
                            | wire::Error::RootTooLong => ErrorToken::InvalidCandidate,
                            _ => ErrorToken::BadRequest,
                        };
                        return unchanged(Outcome::intent_refused(Status::BadRequest, token));
                    }
                }
            } else {
                let Ok(r) = wire::decode_release(bytes) else {
                    return unchanged(Outcome::intent_refused(
                        Status::BadRequest,
                        ErrorToken::BadRequest,
                    ));
                };
                (r.writer, r.epoch, r.instance, r.generation, None)
            };
            let Some(p) = current else {
                return refusal(ErrorToken::IntentAbsent);
            };
            let Some(old) = p.rows.get(&writer) else {
                return refusal(ErrorToken::IntentAbsent);
            };
            if old.receipt.epoch != epoch || old.receipt.instance != instance {
                return receipt(old, Some(ErrorToken::IntentSuperseded));
            }
            if let Some(root) = root {
                if g < old.receipt.generation
                    || (g == old.receipt.generation && old.root.is_empty())
                {
                    return receipt(old, Some(ErrorToken::IntentSuperseded));
                }
                if g == old.receipt.generation {
                    return receipt(
                        old,
                        if GrainId::of(root) == GrainId::of(&old.root) {
                            None
                        } else {
                            Some(ErrorToken::IntentBound)
                        },
                    );
                }
                let live = p.rows.values().filter(|r| !r.root.is_empty()).count();
                let total: usize = p.rows.values().map(|r| r.root.len()).sum();
                let projected = total
                    .checked_sub(old.root.len())
                    .and_then(|v| v.checked_add(root.len()));
                if (old.root.is_empty() && live >= wire::MAX_LIVE_ROWS)
                    || projected.is_none_or(|n| n > wire::MAX_ROOT_BYTES)
                {
                    return refusal(ErrorToken::IntentQuota);
                }
            } else if old.root.is_empty() && g <= old.receipt.generation {
                return receipt(old, None);
            }
            let mut row = old.clone();
            row.receipt.generation = g.max(old.receipt.generation);
            row.receipt.state = root.map_or(ReceiptState::Released, |root| ReceiptState::Live {
                prepared_root_id: GrainId::of(root),
            });
            row.root = root.map_or_else(|| Arc::from([]), Arc::from);
            row.changed = changed_at(row.changed, now);
            let mut result = receipt(&row, None);
            let mut next = p.clone();
            next.rows.insert(writer, row);
            result.next = Some(next);
            result
        }
    }
}

pub(crate) fn evict(snapshot: &mut Snapshot, now: Timestamp, grace: u64) -> bool {
    let horizon = wire::released_row_retention_secs(grace);
    let mut changed = false;
    for principal in snapshot.principals.values_mut() {
        principal.rows.retain(|_, row| {
            let elapsed = now
                .secs
                .checked_sub(row.changed.secs)
                .and_then(|s| u64::try_from(s).ok());
            let expired = elapsed
                .is_some_and(|s| s > horizon || (s == horizon && now.nanos >= row.changed.nanos));
            let keep = !row.root.is_empty() || !expired;
            changed |= !keep;
            keep
        });
    }
    changed
}
