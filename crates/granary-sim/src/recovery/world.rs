// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::{RecoveryRunError, lock, oracle::Oracle};
use crate::{
    fakes::{Sim, SimStore},
    sched::yield_once,
};
use granary_client::{
    AuthorityError, AuthorityTransport, PublicationJournal, PublicationStoreError, PublishRequest,
    PublishResponse, StatusResponse, validate_publish_answer, validate_status_observation,
};
use granary_core::{
    authlog::Epoch,
    authority_answer::{self, Bound, Head, Position, PublishAnswer, VolumeStatus},
    binstore::BinStore,
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    retained_submission::{self, Scope, Submission},
    root::{self, RootSig, VolumeName},
    rootstore::{HintRead, HintToken, RootStore, RootStoreError},
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum Action {
    DecideAndLose,
    #[cfg(test)]
    StoreVariantAndLose,
    #[cfg(test)]
    StoreVariantAndStale,
    #[cfg(test)]
    StoreChainAndLose,
    QueueAndLose,
    AcceptedContestAndLose,
    QueuedForeignAndLose,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "scripted by recovery contention tests")
    )]
    LoseContest,
}
#[derive(Debug, Clone)]
struct Write {
    volume: String,
    seq: u64,
    bytes: Vec<u8>,
}
#[derive(Debug)]
pub(super) struct World {
    pub(super) sim: Sim,
    pub(super) seed: u64,
    pub(super) events: Vec<String>,
    pub(super) violations: Vec<String>,
    durable: Option<Vec<u8>>,
    canonical: Option<Vec<u8>>,
    temporary: Option<Vec<u8>>,
    pub(super) replacements: usize,
    pub(super) fail_cut: Option<(usize, usize)>,
    epoch: [u8; 16],
    pub(super) defer_classification: bool,
    bindings: BTreeMap<Vec<u8>, (GrainId, Position)>,
    positions: BTreeMap<GrainId, u64>,
    outcomes: BTreeMap<EngineKey, PublishAnswer>,
    entry_seq: u64,
    held: Vec<Write>,
    queued: Vec<PublishRequest>,
    pub(super) actions: VecDeque<Action>,
    pub(super) fail_probe: bool,
    pub(super) probe_calls: u64,
    pub(super) send_calls: u64,
    pub(super) explicit: bool,
    #[cfg(test)]
    pub(super) answer_roots: Vec<(u64, Vec<u8>)>,
    invocation: u64,
    oracle: Oracle,
}
impl World {
    pub(super) fn new(sim: Sim, seed: u64) -> Self {
        Self {
            sim,
            seed,
            events: Vec::new(),
            violations: Vec::new(),
            durable: None,
            canonical: None,
            temporary: None,
            replacements: 0,
            fail_cut: None,
            epoch: [1; 16],
            defer_classification: false,
            bindings: BTreeMap::new(),
            positions: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            entry_seq: 77,
            held: Vec::new(),
            queued: Vec::new(),
            actions: VecDeque::new(),
            fail_probe: false,
            probe_calls: 0,
            send_calls: 0,
            explicit: false,
            #[cfg(test)]
            answer_roots: Vec::new(),
            invocation: 0,
            oracle: Oracle::default(),
        }
    }
    pub(super) fn failure(&self, reason: &str) -> RecoveryRunError {
        RecoveryRunError {
            seed: self.seed,
            reason: reason.to_owned(),
            events: self.events.clone(),
        }
    }
    pub(super) fn record(&self) -> Option<Submission> {
        self.durable
            .as_ref()
            .and_then(|b| retained_submission::decode(b).ok())
    }
    #[cfg(test)]
    pub(super) fn set_record(&mut self, record: &Submission) {
        let bytes = retained_submission::encode(record).unwrap();
        self.durable = Some(bytes.clone());
        self.canonical = Some(bytes);
    }
    pub(super) fn event(&mut self, event: String) {
        if event.starts_with("invoke ") {
            self.invocation += 1;
            self.oracle.begin_invocation(self.invocation);
        }
        self.events.push(event);
        let r = self.record();
        let roots = self.sim.root_snapshot();
        self.violations
            .extend(self.oracle.check(r.as_ref(), &roots));
    }
    pub(super) fn crash(&mut self) {
        if self.canonical != self.durable {
            if self.seed & 128 != 0 {
                self.durable.clone_from(&self.canonical);
                self.event("client-crash unsynced rename survives".into());
            } else {
                self.event("client-crash unsynced rename discarded".into());
            }
        }
        self.canonical = self.durable.clone();
        self.temporary = None;
        self.event("client-crash volatile generation discarded".into());
    }
    pub(super) fn reinitialise(&mut self, n: u32) {
        self.epoch = [u8::try_from(n).unwrap_or(0); 16];
        self.bindings.clear();
        self.outcomes.clear();
        self.event(format!("initialise epoch {n} held {}", self.held.len()));
    }
}
pub(super) struct Journal {
    world: Arc<Mutex<World>>,
    source: SimStore,
    poisoned: bool,
}
impl Journal {
    pub(super) fn new(world: Arc<Mutex<World>>) -> Self {
        let source = lock(&world).sim.oracle();
        Self {
            world,
            source,
            poisoned: false,
        }
    }
    fn persist(&mut self, r: &Submission) -> Result<(), PublicationStoreError> {
        if self.poisoned {
            return Err(journal_error("poisoned handle"));
        }
        let bytes = retained_submission::encode(r).map_err(|e| journal_error(&e.to_string()))?;
        self.poisoned = true;
        let mut w = lock(&self.world);
        w.replacements += 1;
        for (stage, name) in ["create", "write", "file-sync", "rename", "directory-sync"]
            .into_iter()
            .enumerate()
        {
            if w.fail_cut == Some((w.replacements, stage)) {
                w.event(format!("sync-failure {name}"));
                return Err(journal_error("injected persistence cut"));
            }
            match stage {
                1 => w.temporary = Some(bytes.clone()),
                3 => w.canonical = w.temporary.take(),
                4 => {
                    let canonical = w.canonical.clone();
                    w.durable.clone_from(&canonical);
                }
                _ => {}
            }
            w.event(format!("journal {name} generation {}", r.generation));
        }
        self.poisoned = false;
        Ok(())
    }
}
fn journal_error(s: &str) -> PublicationStoreError {
    PublicationStoreError {
        kind: granary_client::PublicationStoreErrorKind::Refused,
        path: "sim-journal".into(),
        reason: s.to_owned(),
    }
}
impl GrainSource for Journal {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.source.get(id)
    }
    fn has(&self, id: &GrainId) -> bool {
        self.source.has(id)
    }
}
impl PublicationJournal for Journal {
    fn load(
        &mut self,
        s: &Scope,
        v: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        let Some(mut r) = lock(&self.world).record() else {
            return Ok(None);
        };
        if r.scope != *s || r.volume != *v {
            return Err(journal_error("foreign scope"));
        }
        r.generation = r
            .generation
            .checked_add(1)
            .ok_or_else(|| journal_error("generation exhausted"))?;
        self.persist(&r)?;
        Ok(Some(r))
    }
    fn begin(&mut self, r: &Submission) -> Result<(), PublicationStoreError> {
        if lock(&self.world).record().is_some_and(|r| !r.is_complete()) {
            return Err(journal_error("publication pending"));
        }
        self.persist(r)
    }
    async fn replace(&mut self, g: u64, r: &Submission) -> Result<(), PublicationStoreError> {
        let old = lock(&self.world)
            .record()
            .ok_or_else(|| journal_error("missing record"))?;
        if old.generation != g
            || old.is_complete()
            || old.frozen != r.frozen
            || old.publication_id != r.publication_id
        {
            return Err(journal_error("replacement refused"));
        }
        self.persist(r)
    }
}

pub(super) struct Transport {
    pub(super) world: Arc<Mutex<World>>,
    pub(super) store: SimStore,
}
impl RootStore for Transport {
    async fn put_root(&self, _v: &str, _n: u64, _b: Vec<u8>) -> Result<(), RootStoreError> {
        Err(RootStoreError::Backend(
            "direct publication forbidden".into(),
        ))
    }
    async fn get_root(&self, _v: &str, _n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        Err(RootStoreError::Backend(
            "ordinary root read forbidden".into(),
        ))
    }
    async fn read_hint(
        &self,
        _v: &str,
        _t: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        Ok(HintRead::Missing)
    }
    async fn write_hint(&self, _v: &str, _n: u64) -> Result<(), RootStoreError> {
        Err(RootStoreError::Backend("hint outside coordinator".into()))
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        let r = self.store.max_seq(v).await;
        lock(&self.world).event("max-seq".into());
        r
    }

    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        let r = self.store.max_seq_above(v, floor).await;
        lock(&self.world).event("max-seq".into());
        r
    }
}
impl BinStore for Transport {
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        let r = self.store.put_bin(d, b).await;
        lock(&self.world).event("put-bin".into());
        r
    }
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        let r = self.store.put_meta(v, id, b).await;
        lock(&self.world).event(format!("put-meta {id}"));
        r
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        let r = self.store.get_meta(v, id).await;
        lock(&self.world).event(format!("get-meta {id}"));
        r
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        let r = self.store.get_bin_range(d, o, n).await;
        lock(&self.world).event("get-range".into());
        r
    }
}
impl Transport {
    pub(super) async fn release(&self, index: usize) -> Result<(), RecoveryRunError> {
        let write = {
            let mut w = lock(&self.world);
            if index >= w.held.len() {
                return Err(RecoveryRunError {
                    seed: w.seed,
                    reason: "no held write".into(),
                    events: w.events.clone(),
                });
            }
            w.held.remove(index)
        };
        let result = self
            .store
            .put_root(&write.volume, write.seq, write.bytes.clone())
            .await;
        if !matches!(result, Ok(()) | Err(RootStoreError::AlreadyExists)) {
            return Err(super::failure(&self.world, format!("release: {result:?}")));
        }
        lock(&self.world).event(format!(
            "release {} {} {result:?}",
            write.seq,
            GrainId::of(&write.bytes)
        ));
        Ok(())
    }
    pub(super) async fn release_all(&self) -> Result<(), RecoveryRunError> {
        while !lock(&self.world).held.is_empty() {
            self.release(0).await?;
        }
        Ok(())
    }
    pub(super) fn foreign_current(&self) -> Result<(), RecoveryRunError> {
        let mut w = lock(&self.world);
        let record = w
            .record()
            .ok_or_else(|| w.failure("missing current request"))?;
        let c = record
            .candidates
            .iter()
            .find(|c| c.role == retained_submission::Role::Active)
            .ok_or_else(|| w.failure("missing active request"))?;
        let owned =
            granary_client::OwnedCandidate::new(record.volume.as_str(), c.root.clone().into())
                .map_err(|e| w.failure(&e.to_string()))?;
        let req = PublishRequest::new(
            record.volume.as_str(),
            Epoch::from_bytes(c.request.epoch),
            &c.request.operation,
            owned.clone(),
            vec![owned],
        )
        .map_err(|e| w.failure(&e.to_string()))?;
        plant_foreign(&mut w, &req).map_err(|e| w.failure(&e.to_string()))
    }
    pub(super) fn replay_lost(&self, record: &Submission) -> Result<(), RecoveryRunError> {
        let mut w = lock(&self.world);
        let c = record
            .candidates
            .first()
            .ok_or_else(|| w.failure("missing original tuple"))?;
        let owned =
            granary_client::OwnedCandidate::new(record.volume.as_str(), c.root.clone().into())
                .map_err(|e| w.failure(&e.to_string()))?;
        let req = PublishRequest::new(
            record.volume.as_str(),
            Epoch::from_bytes(c.request.epoch),
            &c.request.operation,
            owned.clone(),
            vec![owned],
        )
        .map_err(|e| w.failure(&e.to_string()))?;
        if !matches!(engine(&mut w, &req), PublishAnswer::Lost { candidate_id, .. } if candidate_id == c.id)
        {
            return Err(w.failure("older exact outcome was replaced by the latest binding"));
        }
        w.event("older exact lost replay after newer binding".into());
        Ok(())
    }
    pub(super) async fn process_queued(&self) {
        yield_once().await;
        let mut w = lock(&self.world);
        let queued = std::mem::take(&mut w.queued);
        for req in queued {
            let answer = engine(&mut w, &req);
            w.event(format!("delayed duplicate processed {answer:?}"));
        }
        w.event("process queued requests independently of replies".into());
    }
}
fn decide(w: &mut World, r: &PublishRequest) -> PublishAnswer {
    let position = Position {
        epoch: r.epoch(),
        entry_seq: w.entry_seq,
    };
    w.entry_seq = w.entry_seq.saturating_add(1);
    w.bindings
        .insert(r.operation().to_vec(), (r.candidate().id(), position));
    w.positions.insert(r.candidate().id(), r.candidate().seq());
    w.held.push(Write {
        volume: r.volume().to_owned(),
        seq: r.candidate().seq(),
        bytes: r.candidate().bytes().to_vec(),
    });
    w.oracle.decided_request(r);
    w.event(format!(
        "decision {} held {}",
        position.entry_seq,
        r.candidate().id()
    ));
    let answer = PublishAnswer::Accepted {
        position,
        candidate_id: r.candidate().id(),
    };
    w.outcomes.insert(engine_key(r), answer);
    answer
}
fn plant_foreign(w: &mut World, r: &PublishRequest) -> Result<(), AuthorityError> {
    let mut doc = root::decode_root(r.candidate().bytes()).map_err(|_| AuthorityError::Elapsed)?;
    doc.writer_uuid = [99; 16];
    doc.sigs.clear();
    let key = crate::scenario::key();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).map_err(|_| AuthorityError::Elapsed)?),
    });
    let bytes = root::encode_root(&doc).map_err(|_| AuthorityError::Elapsed)?;
    if !w.sim.admin().plant_root(&doc.volume, doc.seq, bytes) {
        return Err(AuthorityError::Elapsed);
    }
    w.event(format!("foreign contender after empty probe {}", doc.seq));
    Ok(())
}
#[cfg(test)]
fn plant_variant(w: &mut World, r: &PublishRequest) -> Result<(), AuthorityError> {
    let mut doc = root::decode_root(r.candidate().bytes()).map_err(|_| AuthorityError::Elapsed)?;
    doc.sigs.push(RootSig {
        key_id: [99; 32],
        sig: [0; 64],
    });
    let bytes = root::encode_root(&doc).map_err(|_| AuthorityError::Elapsed)?;
    if !w.sim.admin().plant_root(&doc.volume, doc.seq, bytes) {
        return Err(AuthorityError::Elapsed);
    }
    w.event(format!("stored signature variant {}", doc.seq));
    Ok(())
}
fn lose_contest(w: &mut World, r: &PublishRequest) -> Result<PublishAnswer, AuthorityError> {
    plant_foreign(w, r)?;
    Ok(engine(w, r))
}

type EngineKey = (String, [u8; 16], Vec<u8>, GrainId);
fn engine_key(r: &PublishRequest) -> EngineKey {
    (
        r.volume().to_owned(),
        r.epoch().to_bytes(),
        r.operation().to_vec(),
        r.candidate().id(),
    )
}
fn head(w: &World, volume: &str) -> Head {
    Head::new(
        w.sim
            .root_snapshot()
            .iter()
            .filter(|((v, _), _)| v == volume)
            .map(|((_, seq), bytes)| (*seq, GrainId::of(bytes)))
            .max_by_key(|(seq, _)| *seq),
    )
}
fn classified(w: &mut World, r: &PublishRequest, answer: PublishAnswer) -> PublishAnswer {
    let (PublishAnswer::Accepted { position, .. } | PublishAnswer::Open { position, .. }) = answer
    else {
        return answer;
    };
    if w.defer_classification {
        return PublishAnswer::Open {
            position,
            candidate_id: r.candidate().id(),
        };
    }
    let occupant = w
        .sim
        .root_snapshot()
        .get(&(r.volume().to_owned(), r.candidate().seq()))
        .map(|bytes| GrainId::of(bytes));
    let answer = match occupant {
        Some(id) if id == r.candidate().id() => PublishAnswer::Landed {
            receipt: authority_answer::Receipt {
                position,
                root_seq: r.candidate().seq(),
                stored_id: id,
            },
            head: None,
        },
        Some(occupant) => PublishAnswer::Lost {
            position,
            candidate_id: r.candidate().id(),
            occupant,
            head: None,
        },
        None => PublishAnswer::Open {
            position,
            candidate_id: r.candidate().id(),
        },
    };
    w.outcomes.insert(engine_key(r), answer);
    answer
}
/// Exact outcomes precede operation binding and admission for live and delayed requests.
fn engine(w: &mut World, r: &PublishRequest) -> PublishAnswer {
    if r.epoch().to_bytes() != w.epoch {
        return PublishAnswer::EpochMismatch {
            epoch: Epoch::from_bytes(w.epoch),
            head: None,
        };
    }
    if let Some(answer) = w.outcomes.get(&engine_key(r)).copied() {
        w.event("exact outcome replay before admission".into());
        return classified(w, r, answer);
    }
    if let Some((id, position)) = w.bindings.get(r.operation()).copied() {
        let prior_key = (
            r.volume().to_owned(),
            r.epoch().to_bytes(),
            r.operation().to_vec(),
            id,
        );
        let seq = w.positions.get(&id).copied().unwrap_or(1);
        let occupant = w
            .sim
            .root_snapshot()
            .get(&(r.volume().to_owned(), seq))
            .map(|b| GrainId::of(b));
        if occupant == Some(id) {
            return PublishAnswer::OperationBound(Bound::Landed(authority_answer::Receipt {
                position,
                root_seq: seq,
                stored_id: id,
            }));
        }
        if occupant.is_none() {
            return PublishAnswer::OperationBound(Bound::Open {
                position,
                candidate_id: id,
            });
        }
        w.outcomes.insert(
            prior_key,
            PublishAnswer::Lost {
                position,
                candidate_id: id,
                occupant: occupant.unwrap_or(id),
                head: None,
            },
        );
    }
    let head = head(w, r.volume());
    let doc = root::decode_root(r.candidate().bytes());
    let extends = doc.as_ref().is_ok_and(|doc| match head.root {
        Some((seq, id)) => seq.checked_add(1) == Some(doc.seq) && doc.parent == Some(id),
        None => doc.seq == 1 && doc.parent.is_none(),
    });
    if !extends {
        w.event("undecided exact tuple forward-stale".into());
        return PublishAnswer::StaleBase(head);
    }
    decide(w, r)
}

impl AuthorityTransport for Transport {
    #[expect(
        clippy::too_many_lines,
        reason = "the authority action script keeps each response ordering visible"
    )]
    async fn publish_once(&self, r: &PublishRequest) -> Result<PublishResponse, AuthorityError> {
        yield_once().await;
        let mut w = lock(&self.world);
        let durable = w.record();
        if let Some(error) = w.oracle.send(durable.as_ref(), r) {
            w.violations.push(error);
        }
        w.send_calls += 1;
        w.event(format!(
            "send {} {} {:?}",
            r.candidate().seq(),
            r.candidate().id(),
            r.epoch()
        ));
        let exact_known = w.outcomes.contains_key(&engine_key(r));
        let answer = if r.epoch().to_bytes() != w.epoch || exact_known {
            engine(&mut w, r)
        } else {
            match w.actions.pop_front().unwrap_or(Action::DecideAndLose) {
                Action::QueueAndLose => {
                    w.queued.push(r.clone());
                    w.event("reply-lost before processing".into());
                    return Err(AuthorityError::Elapsed);
                }
                Action::QueuedForeignAndLose => {
                    w.queued.push(r.clone());
                    plant_foreign(&mut w, r)?;
                    w.event("queued undecided request with foreign root".into());
                    return Err(AuthorityError::Elapsed);
                }
                Action::AcceptedContestAndLose => {
                    let answer = engine(&mut w, r);
                    plant_foreign(&mut w, r)?;
                    let answer = classified(&mut w, r, answer);
                    w.event(format!(
                        "accepted foreign durable outcome {answer:?} reply dropped"
                    ));
                    return Err(AuthorityError::Elapsed);
                }
                Action::DecideAndLose => {
                    let answer = engine(&mut w, r);
                    if matches!(answer, PublishAnswer::Accepted { .. }) {
                        w.event("reply-lost after decision".into());
                        return Err(AuthorityError::Elapsed);
                    }
                    answer
                }
                #[cfg(test)]
                Action::StoreVariantAndLose => {
                    let answer = engine(&mut w, r);
                    plant_variant(&mut w, r)?;
                    classified(&mut w, r, answer)
                }
                #[cfg(test)]
                Action::StoreVariantAndStale => {
                    plant_variant(&mut w, r)?;
                    engine(&mut w, r)
                }
                #[cfg(test)]
                Action::StoreChainAndLose => {
                    let roots = std::mem::take(&mut w.answer_roots);
                    for (seq, bytes) in roots {
                        let volume = root::decode_root(&bytes)
                            .map_err(|_| AuthorityError::Elapsed)?
                            .volume;
                        if !w.sim.admin().plant_root(&volume, seq, bytes) {
                            return Err(AuthorityError::Elapsed);
                        }
                    }
                    let occupant = w
                        .sim
                        .root_snapshot()
                        .get(&(r.volume().to_owned(), r.candidate().seq()))
                        .map(|bytes| GrainId::of(bytes))
                        .ok_or(AuthorityError::Elapsed)?;
                    PublishAnswer::Lost {
                        position: Position {
                            epoch: r.epoch(),
                            entry_seq: w.entry_seq,
                        },
                        candidate_id: r.candidate().id(),
                        occupant,
                        head: None,
                    }
                }
                Action::LoseContest => {
                    engine(&mut w, r);
                    lose_contest(&mut w, r)?
                }
            }
        };
        let token = match answer {
            PublishAnswer::EpochMismatch { .. } => Some("epoch-mismatch"),
            PublishAnswer::OperationBound(_) => Some("operation-bound"),
            PublishAnswer::StaleBase(_) => Some("stale-base"),
            _ => None,
        };
        let response = validate_publish_answer(
            r,
            match answer {
                PublishAnswer::Landed { .. } | PublishAnswer::Lost { .. } => 200,
                _ if token.is_some() => 409,
                _ => 202,
            },
            token,
            &authority_answer::encode(answer).map_err(|_| AuthorityError::Elapsed)?,
        )?;
        if let Some(durable) = durable
            && let granary_core::retained_submission::Phase::AwaitingAnswer { candidate, .. } =
                durable.phase
        {
            if matches!(
                answer,
                PublishAnswer::EpochMismatch { .. }
                    | PublishAnswer::OperationBound(_)
                    | PublishAnswer::StaleBase(_)
            ) {
                w.oracle.no_write(&durable, candidate);
            }
            if let PublishAnswer::StaleBase(head) = answer {
                let no_decision = !w.outcomes.contains_key(&engine_key(r));
                let actual_head = head.root == self::head(&w, r.volume()).root;
                w.oracle
                    .forward_stale(&durable, r, head, no_decision && actual_head);
            }
            if let PublishResponse::Lost(lost) = response {
                w.oracle.checked_lost(&durable, candidate, r, lost);
            }
        }
        w.event(format!("checked-reply {answer:?}"));
        Ok(response)
    }
    async fn status_once(&self, _v: &str) -> Result<StatusResponse, AuthorityError> {
        yield_once().await;
        let mut w = lock(&self.world);
        w.event("status bootstrap".into());
        validate_status_observation(
            &authority_answer::encode_status(VolumeStatus {
                epoch: Epoch::from_bytes(w.epoch),
                head: None,
                open: None,
            })
            .map_err(|_| AuthorityError::Elapsed)?,
        )
    }
    async fn probe_root_once(&self, v: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        let failed = lock(&self.world).fail_probe;
        let result = if failed {
            yield_once().await;
            Err(RootStoreError::Backend("injected probe failure".into()))
        } else {
            self.store.get_root(v, seq).await
        };
        let mut w = lock(&self.world);
        w.probe_calls += 1;
        let occupied = matches!(&result, Ok(Some(_)));
        if let Ok(Some(bytes)) = &result {
            let durable = w.record();
            let invocation = w.invocation;
            if let Some(record) = durable {
                w.oracle
                    .occupancy(&record, seq, GrainId::of(bytes), invocation);
            }
        }
        let invocation = w.invocation;
        let explicit = w.explicit;
        if let Some(error) = w.oracle.probe(seq, occupied, failed, invocation, explicit) {
            w.violations.push(error);
        }
        w.event(format!(
            "probe {seq} {}",
            if failed {
                "failed"
            } else if occupied {
                "occupied"
            } else {
                "empty"
            }
        ));
        result
    }
}
