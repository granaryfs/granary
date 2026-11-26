// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Intent transactions owned by a volume worker, sharing its log gate and fence.

use super::intent::persistence::IntentStore;
use super::intent::{self, IntentOperation, Principal, Snapshot};
use super::worker::Engine;
use super::{Fence, LogCall};
use crate::wire::{ErrorToken, Outcome, Status};
use granary_core::authlog::Epoch;
use granary_core::clock::Clock;
use granary_core::decisionlog::DecisionLog;
use granary_core::enrollment::PrincipalId;
use granary_core::root::VolumeName;
use granary_core::secure_random::SecureRandom;
use granary_store::crypto::TrustedKeys;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
pub(crate) enum Work {
    Request {
        principal: PrincipalId,
        operation: IntentOperation,
        bytes: Vec<u8>,
    },
    Maintain {
        principals: Vec<PrincipalId>,
        grace: u64,
    },
    Roots,
}
/// Exact live prepared roots, for future coordinated collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRoot {
    /// Volume containing this root.
    pub volume: VolumeName,
    /// Exact committed root bytes.
    pub bytes: Arc<[u8]>,
}
impl IntentRoot {
    /// Identity of the exact committed bytes.
    #[must_use]
    pub fn id(&self) -> granary_core::hash::GrainId {
        granary_core::hash::GrainId::of(&self.bytes)
    }
}
#[derive(Debug)]
pub(crate) enum ResultValue {
    Answer(Outcome),
    Roots(Vec<IntentRoot>),
}
#[derive(Debug)]
pub(crate) struct Intents {
    store: Option<Arc<IntentStore>>,
    state: Mutex<Option<Snapshot>>,
    readable: bool,
}
pub(crate) fn refused(token: ErrorToken) -> ResultValue {
    let status = if token == ErrorToken::UnknownVolume {
        Status::NotFound
    } else {
        Status::ServiceUnavailable
    };
    ResultValue::Answer(Outcome::intent_refused(status, token))
}
impl Intents {
    #[expect(
        clippy::single_match_else,
        reason = "Load verdicts are explicitly paired with readability"
    )]
    pub(crate) fn load(
        store: Option<Arc<IntentStore>>,
        volume: &VolumeName,
        keys: &TrustedKeys,
    ) -> Self {
        let (state, readable) = match &store {
            Some(store) => match store.io.load(volume, None, keys) {
                Ok(state) => (state, true),
                Err(_) => {
                    tracing::error!(
                        event = "op.failed",
                        kind = intent::STORE_KIND,
                        volume = volume.as_str(),
                        class = "corrupt",
                        "intent state refused"
                    );
                    (None, false)
                }
            },
            None => (None, false),
        };
        Self {
            store,
            state: Mutex::new(state),
            readable,
        }
    }
    pub(crate) async fn ready(
        &self,
        epoch: Option<Epoch>,
        gate: &super::gate::LogGate,
        shared: &super::Shared,
        volume: &VolumeName,
    ) -> Result<(), Fence> {
        let state = self.state.lock().await;
        // Absent logs and mismatched snapshots are never made ready or cleaned.
        if let (Some(store), Some(state), Some(epoch)) = (&self.store, &*state, epoch)
            && state.epoch == epoch
        {
            gate.fencing(
                &shared.fence,
                LogCall::IntentStore,
                Some(volume),
                || async { store.io.ready(volume) },
            )
            .await?;
        }
        Ok(())
    }
    async fn commit<L, S, C, R, E, P>(
        &self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        next: &Snapshot,
        store: &IntentStore,
    ) -> Result<(), Fence> {
        engine
            .gate
            .fencing(
                &engine.shared.fence,
                LogCall::IntentStore,
                Some(&next.volume),
                || async { store.io.commit(next) },
            )
            .await
    }
    pub(crate) fn configured(&self) -> bool {
        self.store.is_some()
    }
    pub(crate) async fn rebind<L, S, C, R, E, P>(
        &self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        volume: &VolumeName,
        selected: Epoch,
    ) -> Result<(), super::InitialiseError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        if !self.readable {
            return Err(super::InitialiseError::IntentUnavailable);
        }
        let mut committed = self.state.lock().await;
        let next = committed.get_or_insert_with(|| Snapshot {
            volume: volume.clone(),
            epoch: selected,
            principals: BTreeMap::new(),
        });
        let old_epoch = next.epoch;
        next.epoch = selected;
        tracing::info!(event = "op.begin", kind = intent::STORE_KIND);
        let durable = self.commit(engine, next, store).await;
        if durable.is_err() {
            next.epoch = old_epoch;
            tracing::error!(
                event = "op.failed",
                kind = intent::STORE_KIND,
                volume = volume.as_str(),
                class = "io",
                error = "fenced"
            );
            tracing::info!(
                event = "op.end",
                kind = intent::STORE_KIND,
                outcome = "failed"
            );
            return Err(super::InitialiseError::Fenced);
        }
        crash_point!(IntentRebound);
        tracing::info!(event = "op.end", kind = intent::STORE_KIND, outcome = "ok");
        Ok(())
    }
    pub(crate) async fn answer<L: DecisionLog, S, C: Clock, R, E: SecureRandom, P>(
        &self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        volume: &VolumeName,
        keys: &TrustedKeys,
        epoch: Option<Epoch>,
        work: Work,
    ) -> ResultValue {
        let kind = match &work {
            Work::Request { operation, .. } => operation.kind(),
            _ => intent::STORE_KIND,
        };
        tracing::info!(event = "op.begin", kind);
        let answer = self.execute(engine, volume, keys, epoch, work).await;
        if let ResultValue::Answer(outcome) = &answer
            && outcome.error().is_some()
        {
            let class = match outcome.status() {
                Status::Conflict => "conflict",
                Status::ServiceUnavailable => "unavailable",
                Status::InternalServerError => "internal",
                _ => "refused",
            };
            tracing::warn!(
                event = "op.failed",
                kind,
                volume = volume.as_str(),
                class,
                error = outcome.error().map(crate::wire::ErrorToken::as_str)
            );
            tracing::info!(event = "op.end", kind, outcome = "failed");
        } else {
            tracing::info!(event = "op.end", kind, outcome = "ok");
        }
        answer
    }
    async fn execute<L: DecisionLog, S, C: Clock, R, E: SecureRandom, P>(
        &self,
        engine: &Engine<'_, L, S, C, R, E, P>,
        volume: &VolumeName,
        keys: &TrustedKeys,
        epoch: Option<Epoch>,
        work: Work,
    ) -> ResultValue {
        if engine.shared.fence.is_set() {
            return refused(ErrorToken::Fenced);
        }
        let Some(store) = self.store.as_ref().filter(|_| self.readable) else {
            return refused(ErrorToken::Unavailable);
        };
        let mut committed = self.state.lock().await;
        match work {
            Work::Request {
                principal,
                operation,
                bytes,
            } => {
                let Some(state) = committed.as_mut().filter(|s| Some(s.epoch) == epoch) else {
                    return refused(ErrorToken::Unavailable);
                };
                let judged = intent::transition(
                    state.principals.get(&principal),
                    operation,
                    &bytes,
                    volume,
                    keys,
                    engine.clock.now(),
                );
                if let Some(next_principal) = judged.next {
                    if intent::codec::validate_principal(&next_principal, volume).is_err() {
                        return ResultValue::Answer(Outcome::internal());
                    }
                    let previous = state.principals.insert(principal, next_principal);
                    if self.commit(engine, state, store).await.is_err() {
                        if let Some(previous) = previous {
                            state.principals.insert(principal, previous);
                        } else {
                            state.principals.remove(&principal);
                        }
                        return refused(ErrorToken::Fenced);
                    }
                    crash_point!(IntentStateInstalled);
                }
                ResultValue::Answer(judged.outcome)
            }
            Work::Roots => {
                let Some(state) = committed.as_ref().filter(|s| Some(s.epoch) == epoch) else {
                    return refused(ErrorToken::Unavailable);
                };
                ResultValue::Roots(
                    state
                        .principals
                        .values()
                        .flat_map(|p| p.rows.values())
                        .filter(|r| !r.root.is_empty())
                        .map(|r| IntentRoot {
                            volume: volume.clone(),
                            bytes: Arc::clone(&r.root),
                        })
                        .collect(),
                )
            }
            Work::Maintain { principals, grace } => {
                let Some(state) = committed.as_ref().filter(|s| Some(s.epoch) == epoch) else {
                    return refused(ErrorToken::Unavailable);
                };
                let mut next = state.clone();
                let mut changed = intent::evict(&mut next, engine.clock.now(), grace);
                for principal in principals {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        next.principals.entry(principal)
                    {
                        entry.insert(Principal::default());
                        changed = true;
                    }
                }
                if changed {
                    if self.commit(engine, &next, store).await.is_err() {
                        return refused(ErrorToken::Fenced);
                    }
                    *committed = Some(next);
                    crash_point!(IntentEvicted);
                }
                ResultValue::Answer(Outcome::already_present())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        gate::LogGate,
        tests::{FixedClock, YieldPause, rng},
    };
    use super::*;
    use intent::persistence::Persistence;
    use intent::tests as fixture;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RefuseCommit {
        state: Snapshot,
        writes: AtomicUsize,
    }
    impl Persistence for RefuseCommit {
        fn load(
            &self,
            _: &VolumeName,
            _: Option<Epoch>,
            _: &TrustedKeys,
        ) -> std::io::Result<Option<Snapshot>> {
            Ok(Some(self.state.clone()))
        }
        fn load_for_rebind(&self, _: &VolumeName) -> std::io::Result<Option<Snapshot>> {
            Ok(Some(self.state.clone()))
        }
        fn ready(&self, _: &VolumeName) -> Result<(), granary_core::decisionlog::LogIoError> {
            Ok(())
        }
        fn commit(&self, _: &Snapshot) -> Result<(), granary_core::decisionlog::LogIoError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(granary_core::decisionlog::LogIoError::SyncFailed)
        }
    }
    #[tokio::test]
    async fn round1_changed_principal_validation_and_failed_commit_rollback() {
        for mode in 0..4 {
            let mut old = fixture::snapshot(fixture::owned(1));
            let principal = PrincipalId::from_bytes([if mode == 1 { 2 } else { 1 }; 16]);
            let bytes = if mode == 0 {
                fixture::takeover(
                    old.principals
                        .values()
                        .next()
                        .unwrap()
                        .rows
                        .values()
                        .next()
                        .unwrap(),
                    3,
                )
            } else {
                fixture::acquire(3, 4, 0)
            };
            if mode == 2 {
                // Model an internal invalid construction: a duplicate E under H=0.
                old.principals.values_mut().next().unwrap().h = 0;
            }
            let persistence = Arc::new(RefuseCommit {
                state: old.clone(),
                writes: AtomicUsize::new(0),
            });
            let intents = Intents::load(
                Some(Arc::new(IntentStore {
                    io: persistence.clone(),
                })),
                &fixture::volume(),
                &fixture::keys(),
            );
            let sim = granary_sim::fakes::Sim::new();
            let log = sim.decision_log(0, granary_sim::decision_log::LogFaults::none());
            let random = std::sync::Mutex::new(
                granary_sim::secure_random::SeededSecureRandom::for_incarnation(1, 1),
            );
            let rng = std::sync::Mutex::new(rng(1));
            let gate = LogGate::default();
            let shared = super::super::Shared::default();
            let engine = Engine {
                log: &log,
                store: &(),
                clock: &FixedClock,
                rng: &rng,
                secure_random: &random,
                pause: &YieldPause,
                gate: &gate,
                shared: &shared,
            };
            if mode == 3 {
                assert_eq!(
                    intents
                        .rebind(&engine, &fixture::volume(), Epoch::from_bytes([3; 16]))
                        .await,
                    Err(super::super::InitialiseError::Fenced)
                );
                assert_eq!(*intents.state.lock().await, Some(old));
                continue;
            }
            let answer = intents
                .execute(
                    &engine,
                    &fixture::volume(),
                    &fixture::keys(),
                    Some(old.epoch),
                    Work::Request {
                        principal,
                        operation: IntentOperation::Ownership,
                        bytes,
                    },
                )
                .await;
            let ResultValue::Answer(answer) = answer else {
                panic!("expected answer")
            };
            assert_eq!(
                answer.error(),
                Some(if mode == 2 {
                    ErrorToken::Internal
                } else {
                    ErrorToken::Fenced
                })
            );
            assert_eq!(*intents.state.lock().await, Some(old));
            assert_eq!(
                persistence.writes.load(Ordering::SeqCst),
                usize::from(mode != 2)
            );
        }
    }
}
