// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::{Arc, Mutex};

use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::rootstore::{HintRead, HintToken, RefusalKind, RootStore, RootStoreError};
use granary_sim::fakes::{Faults, Sim, SimStore};
use granary_sim::sched::yield_once;

/// Each call, including the arguments that distinguish it from other calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::authority) enum Call {
    List(String),
    Above(String, u64),
    Get(String, u64),
    Put(String, u64, Vec<u8>),
    ReadHint(String, Option<HintToken>),
    WriteHint(String, u64),
}

type Hook = Box<dyn FnOnce(&ScriptedStore) + Send>;

#[derive(Default)]
struct State {
    roots: BTreeMap<(String, u64), Vec<u8>>,
    calls: Vec<Call>,
    hook: Option<(Call, Hook)>,
    failure: Option<(Call, bool)>,
    parks: Vec<(Call, Park)>,
}

#[derive(Debug, Clone, Default)]
pub(in crate::authority) struct Park(Arc<Mutex<(bool, bool)>>);

impl Park {
    pub(in crate::authority) fn reached(&self) -> bool {
        self.0.lock().unwrap().0
    }

    pub(in crate::authority) fn release(&self) {
        self.0.lock().unwrap().1 = true;
    }

    async fn wait(self) {
        self.0.lock().unwrap().0 = true;
        while !self.0.lock().unwrap().1 {
            yield_once().await;
        }
    }
}

#[derive(Clone)]
pub(in crate::authority) struct ScriptedStore {
    state: Arc<Mutex<State>>,
    content: Arc<SimStore>,
}

impl Default for ScriptedStore {
    fn default() -> Self {
        Self {
            state: Arc::default(),
            content: Arc::new(Sim::new().node(1, Faults::none())),
        }
    }
}

impl ScriptedStore {
    pub(in crate::authority) fn set(&self, volume: &str, seq: u64, bytes: Option<Vec<u8>>) {
        let mut state = self.state.lock().unwrap();
        let key = (volume.to_owned(), seq);
        match bytes {
            Some(bytes) => state.roots.insert(key, bytes),
            None => state.roots.remove(&key),
        };
    }

    pub(in crate::authority) fn take_calls(&self) -> Vec<Call> {
        std::mem::take(&mut self.state.lock().unwrap().calls)
    }

    /// Run once after the named call's observation and before it returns.
    pub(in crate::authority) fn after(
        &self,
        call: Call,
        hook: impl FnOnce(&Self) + Send + 'static,
    ) {
        assert!(
            self.state
                .lock()
                .unwrap()
                .hook
                .replace((call, Box::new(hook)))
                .is_none()
        );
    }

    /// Fail the next matching call, by transport or by the root size cap.
    pub(in crate::authority) fn fail(&self, call: Call, over_cap: bool) {
        assert!(
            self.state
                .lock()
                .unwrap()
                .failure
                .replace((call, over_cap))
                .is_none()
        );
    }

    /// Pause the next matching call before it observes or changes the store.
    pub(in crate::authority) fn park(&self, call: Call) -> Park {
        let park = Park::default();
        self.state.lock().unwrap().parks.push((call, park.clone()));
        park
    }

    async fn call<T>(
        &self,
        call: Call,
        run: impl FnOnce(&mut State) -> Result<T, RootStoreError> + Send,
    ) -> Result<T, RootStoreError> {
        let park = {
            let mut state = self.state.lock().unwrap();
            let park = state.parks.iter().position(|(on, _)| *on == call);
            state.calls.push(call.clone());
            park.map(|index| state.parks.remove(index).1)
        };
        if let Some(park) = park {
            park.wait().await;
        }
        let (answer, hook) = {
            let mut state = self.state.lock().unwrap();
            let answer = if state.failure.as_ref().is_some_and(|(on, _)| *on == call) {
                if state.failure.take().unwrap().1 {
                    Err(RootStoreError::RefusedResponse {
                        reason: "over the root cap".to_owned(),
                        kind: RefusalKind::OverCap,
                    })
                } else {
                    Err(RootStoreError::Backend(
                        "scripted transport failure".to_owned(),
                    ))
                }
            } else {
                run(&mut state)
            };
            let hook = if state.hook.as_ref().is_some_and(|(on, _)| *on == call) {
                state.hook.take().map(|(_, hook)| hook)
            } else {
                None
            };
            (answer, hook)
        };
        if let Some(hook) = hook {
            hook(self);
        }
        answer
    }

    async fn list(
        &self,
        call: Call,
        volume: &str,
        floor: u64,
    ) -> Result<Option<u64>, RootStoreError> {
        self.call(call, |state| {
            Ok(state
                .roots
                .keys()
                .filter_map(|(name, seq)| {
                    (name == volume && *seq > floor && *seq < u64::MAX).then_some(*seq)
                })
                .max())
        })
        .await
    }
}

impl RootStore for ScriptedStore {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        self.call(
            Call::Put(volume.to_owned(), seq, bytes.clone()),
            |state| match state.roots.entry((volume.to_owned(), seq)) {
                Entry::Vacant(slot) => {
                    slot.insert(bytes);
                    Ok(())
                }
                Entry::Occupied(_) => Err(RootStoreError::AlreadyExists),
            },
        )
        .await
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.call(Call::Get(volume.to_owned(), seq), |state| {
            Ok(state.roots.get(&(volume.to_owned(), seq)).cloned())
        })
        .await
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        self.call(Call::ReadHint(volume.to_owned(), cached.cloned()), |_| {
            Ok(HintRead::Missing)
        })
        .await
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        self.call(Call::WriteHint(volume.to_owned(), seq), |_| Ok(()))
            .await
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.list(Call::List(volume.to_owned()), volume, 0).await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.list(Call::Above(volume.to_owned(), floor), volume, floor)
            .await
    }
}

impl BinStore for ScriptedStore {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.content.put_bin(digest, bytes).await
    }

    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.content.put_meta(volume, id, bytes).await
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.content.get_meta(volume, id).await
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.content.get_bin_range(digest, offset, len).await
    }
}
