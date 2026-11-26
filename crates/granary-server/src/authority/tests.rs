// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The engine's start, recovery, initialise, fence and stop, driven
//! through the simulator's crash-consistency `DecisionLog` and its seeded
//! scheduler. Every run that should be correct also asserts the fake
//! recorded no ordering violation: the fake's checks (a mark before its
//! record's sync, a write before its barrier, anything after a fence, two
//! log calls overlapping anywhere, a step after a fence) are the oracle
//! the engine is held to.
//!
//! Out-of-line: this crate has its own binary and `tests/` directory.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use granary_core::authlog::{
    Append, Classified, EPOCH_LEN, EncodedEnvelope, Envelope, Epoch, GrammarRule, Operation,
    Principal, Record, RecordBody, RootBytes, SubmissionIdentity, Tenant, classify, encode_append,
    encode_envelope,
};
use granary_core::clock::Clock;
use granary_core::decisionlog::{DecisionLog, IoErrorKind, LogIoError, MarkerRead};
use granary_core::hash::GrainId;
use granary_core::root::{self, RootDoc, RootSig, VolumeName};
use granary_core::rootstore::{HintRead, HintToken, RefusalKind, RootStore, RootStoreError};
use granary_core::runmarker::{BootId, EncodedMarker, RunMarker, decode_marker, encode_marker};
use granary_core::secure_random::SecureRandom;
use granary_core::sheaf::Timestamp;
use granary_core::testkit::DecisionLogFixture;
use granary_sim::decision_log::{LogFault, LogFaults, SimDecisionLog};
use granary_sim::fakes::{Fault, Faults, Sim, SimStore};
use granary_sim::rng::Rng as SimRng;
use granary_sim::sched::{Scheduler, Task, yield_once};
use granary_sim::secure_random::SeededSecureRandom;
use granary_store::crypto::{SigningKey, TrustedKeys};

use super::state::VolumeState;
use super::worker::{CommitError, Engine};
use super::*;

mod admission;
mod baseline;
#[cfg(feature = "crash-points")]
mod crash;
mod epoch;
mod epoch_guard;
mod gateway;
pub(crate) mod intents;
mod measurements;
mod notice;
mod observation;
mod publication;
mod report;
mod sweep;

/// A reply a worker sends, as [`ReplyHook`] sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    Answer(Answer),
    Initialised(Result<Initialised, InitialiseError>),
}

pub(crate) type Observer = Arc<dyn Fn(&VolumeName, Reply) + Send + Sync>;

/// The engine's observer of every reply a worker sends: called after
/// the reply's fence check and before its send, with no await between,
/// so the order a test records is the order the engine emitted. Unset,
/// it does nothing.
#[derive(Default)]
pub(crate) struct ReplyHook(Mutex<Option<Observer>>);

impl std::fmt::Debug for ReplyHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplyHook")
    }
}

impl ReplyHook {
    /// Observe every reply from now on with `observer`.
    pub(crate) fn set(&self, observer: Observer) {
        *self.0.lock().unwrap() = Some(observer);
    }

    fn emit(&self, volume: &VolumeName, reply: Reply) {
        let observer = self.0.lock().unwrap().clone();
        if let Some(observer) = observer {
            observer(volume, reply);
        }
    }

    pub(crate) fn answer(&self, volume: &VolumeName, answer: &Answer) {
        self.emit(volume, Reply::Answer(answer.clone()));
    }

    pub(crate) fn initialised(
        &self,
        volume: &VolumeName,
        answer: &Result<Initialised, InitialiseError>,
    ) {
        self.emit(volume, Reply::Initialised(answer.clone()));
    }
}

// ------------------------------------------------------------ fixtures

/// The log the engine owns, shared with the test that inspects it.
#[derive(Debug, Clone)]
struct SharedLog(Arc<SimDecisionLog>);

impl DecisionLog for SharedLog {
    fn read_marker(&self) -> impl Future<Output = Result<MarkerRead, LogIoError>> + Send {
        self.0.read_marker()
    }

    fn write_marker(
        &self,
        marker: &EncodedMarker,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.write_marker(marker)
    }

    fn read(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, LogIoError>> + Send {
        self.0.read(volume)
    }

    fn remove_temporary(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<bool, LogIoError>> + Send {
        self.0.remove_temporary(volume)
    }

    fn initialise(
        &self,
        envelope: &EncodedEnvelope,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.initialise(envelope)
    }

    fn complete_namespace(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.complete_namespace(volume)
    }

    fn append(&self, append: &Append) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.append(append)
    }

    fn truncate(
        &self,
        volume: &VolumeName,
        len: u64,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.truncate(volume, len)
    }

    fn resync(&self, volume: &VolumeName) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.0.resync(volume)
    }
}

/// How a [`TestStore`] read of one seq fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadFault {
    /// The root size cap's refusal: proof the object is not a root.
    OverCap,
    /// A transport failure, which proves nothing.
    Transport,
}

/// The engine's root store: the simulator's, shared with the test, which
/// can also make a read of one `(volume, seq)` fail as a [`ReadFault`]
/// says. The simulator's own store holds owned bytes and never raises the
/// size cap's refusal, and its faults are by operation index, not by seq.
#[derive(Debug, Clone)]
pub(super) struct TestStore {
    inner: Arc<SimStore>,
    faults: Arc<Mutex<BTreeMap<(String, u64), ReadFault>>>,
    hold: Arc<Mutex<Option<Hold>>>,
}

/// A read of one `(volume, seq)` held after the store has answered it,
/// until the test releases it: a publication step held in flight.
#[derive(Debug)]
struct Hold {
    key: (String, u64),
    reached: bool,
    released: bool,
}

impl TestStore {
    pub(super) fn new(store: SimStore) -> Self {
        Self {
            inner: Arc::new(store),
            faults: Arc::new(Mutex::new(BTreeMap::new())),
            hold: Arc::new(Mutex::new(None)),
        }
    }

    /// Hold the next read of `volume` at `seq` once the store has
    /// answered it, until [`Self::release`].
    pub(super) fn hold_read(&self, volume: &VolumeName, seq: u64) {
        *self.hold.lock().unwrap() = Some(Hold {
            key: (volume.as_str().to_owned(), seq),
            reached: false,
            released: false,
        });
    }

    /// Whether a held read has been answered and is waiting.
    pub(super) fn hold_reached(&self) -> bool {
        self.hold
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|h| h.reached)
    }

    /// Let the held read return.
    pub(super) fn release(&self) {
        if let Some(hold) = self.hold.lock().unwrap().as_mut() {
            hold.released = true;
        }
    }

    /// Whether this read is the held one: marks it reached if so.
    fn holds(&self, volume: &str, seq: u64) -> bool {
        let mut hold = self.hold.lock().unwrap();
        match hold.as_mut() {
            Some(h) if !h.reached && !h.released && h.key == (volume.to_owned(), seq) => {
                h.reached = true;
                true
            }
            _ => false,
        }
    }

    fn released(&self) -> bool {
        self.hold
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|h| h.released)
    }

    /// A store every operation of which fails: an entry opened over it
    /// stays unresolved.
    fn dead() -> Self {
        Self::new(Sim::new().node(1, Faults::just(Fault::FailFrom(0))))
    }

    /// Make every read of `volume` at `seq` fail with `fault`, or, with
    /// `None`, read as the simulator's store does.
    pub(super) fn set_read_fault(&self, volume: &VolumeName, seq: u64, fault: Option<ReadFault>) {
        let mut faults = self.faults.lock().unwrap();
        let key = (volume.as_str().to_owned(), seq);
        match fault {
            Some(fault) => faults.insert(key, fault),
            None => faults.remove(&key),
        };
    }
}

impl RootStore for TestStore {
    fn put_root(
        &self,
        volume: &str,
        seq: u64,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send {
        self.inner.put_root(volume, seq, bytes)
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        let read = self.inner.get_root(volume, seq).await;
        if self.holds(volume, seq) {
            while !self.released() {
                yield_once().await;
            }
        }
        let fault = self
            .faults
            .lock()
            .unwrap()
            .get(&(volume.to_owned(), seq))
            .copied();
        match fault {
            None => read,
            Some(ReadFault::OverCap) => Err(RootStoreError::RefusedResponse {
                reason: "over the root cap".to_owned(),
                kind: RefusalKind::OverCap,
            }),
            Some(ReadFault::Transport) => Err(RootStoreError::Backend("planted".to_owned())),
        }
    }

    fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> impl Future<Output = Result<HintRead, RootStoreError>> + Send {
        self.inner.read_hint(volume, cached)
    }

    fn write_hint(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send {
        self.inner.write_hint(volume, seq)
    }

    fn max_seq(
        &self,
        volume: &str,
    ) -> impl Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.inner.max_seq(volume)
    }

    fn max_seq_above(
        &self,
        volume: &str,
        floor: u64,
    ) -> impl Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.inner.max_seq_above(volume, floor)
    }
}

#[derive(Debug)]
pub(super) struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        }
    }
}

/// A clock a test can step after the engine has started: seconds since
/// the epoch, nanoseconds always zero. Shared between the test and the
/// engine it drives, so the same handle that started a run can move the
/// clock forward, or back, before the next report (spec §7's clock-
/// behind case).
#[derive(Debug, Clone)]
struct SetClock(Arc<AtomicI64>);

impl SetClock {
    fn at(secs: i64) -> Self {
        Self(Arc::new(AtomicI64::new(secs)))
    }

    /// Move the clock to `secs`, forward or back.
    fn set(&self, secs: i64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl Clock for SetClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.0.load(Ordering::SeqCst),
            nanos: 0,
        }
    }
}

/// The simulator's pause: a yield to its scheduler.
#[derive(Debug)]
pub(super) struct YieldPause;

impl Pause for YieldPause {
    fn pause(&self, _duration: Duration) -> impl Future<Output = ()> + Send {
        yield_once()
    }
}

/// The engine's driver over this file's fixtures, generic in its clock
/// only: most tests run [`FixedClock`] (the plain [`Driver`] alias); a
/// test of spec §7's age needs one it can step, [`SetClock`].
/// A test that injects its own cryptographic-randomness source names it
/// as `E` (the `epoch` module).
type DriverOn<C, E = SeededSecureRandom> =
    AuthorityDriver<SharedLog, TestStore, C, SimRng, E, YieldPause>;
type Driver = DriverOn<FixedClock>;

/// The stream every test's engine randomness is drawn on.
const RNG_STREAM: u64 = 0xA7;

pub(super) fn rng(seed: u64) -> SimRng {
    SimRng::seeded(seed, RNG_STREAM)
}

/// The cryptographic-randomness stream a test's engine draws its epochs
/// from under `seed`: one simulated process lifetime's stream.
pub(super) fn secure(seed: u64) -> SeededSecureRandom {
    SeededSecureRandom::for_incarnation(seed, 1)
}

/// The epoch an engine whose cryptographic-randomness stream is
/// `secure(seed)` draws for its first new log: the stream's first
/// sixteen bytes.
fn first_epoch(seed: u64) -> Epoch {
    let mut bytes = [0u8; EPOCH_LEN];
    secure(seed).fill(&mut bytes).unwrap();
    Epoch::from_bytes(bytes)
}

/// The engine's parts over `log` and a store that fails everything.
fn parts(
    log: &Arc<SimDecisionLog>,
    seed: u64,
) -> AuthorityParts<SharedLog, TestStore, FixedClock, SimRng, SeededSecureRandom, YieldPause> {
    parts_with(log, TestStore::dead(), seed)
}

fn parts_with(
    log: &Arc<SimDecisionLog>,
    store: TestStore,
    seed: u64,
) -> AuthorityParts<SharedLog, TestStore, FixedClock, SimRng, SeededSecureRandom, YieldPause> {
    parts_with_clock(log, store, FixedClock, seed)
}

/// As [`parts_with`], over any clock: what [`World::start_with_clock`]
/// starts.
fn parts_with_clock<C: Clock>(
    log: &Arc<SimDecisionLog>,
    store: TestStore,
    clock: C,
    seed: u64,
) -> AuthorityParts<SharedLog, TestStore, C, SimRng, SeededSecureRandom, YieldPause> {
    AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        log: SharedLog(Arc::clone(log)),
        store,
        clock,
        rng: rng(seed),
        secure_random: secure(seed),
        pause: YieldPause,
    }
}

pub(super) fn vol(name: &str) -> VolumeName {
    VolumeName::new(name.to_owned()).unwrap()
}

fn a() -> VolumeName {
    vol("vol-a")
}

fn b() -> VolumeName {
    vol("vol-b")
}

fn c() -> VolumeName {
    vol("vol-c")
}

pub(super) fn boot(n: u8) -> BootId {
    BootId::from_bytes([n; 16])
}

/// The publisher key every test volume trusts.
pub(super) fn publisher() -> SigningKey {
    SigningKey::from_seed(&[0x5A; 32]).unwrap()
}

pub(super) fn configs(volumes: &[VolumeName]) -> Vec<VolumeConfig> {
    let keys = TrustedKeys::new([*publisher().public_key()]).unwrap();
    volumes
        .iter()
        .cloned()
        .map(|volume| VolumeConfig::new(volume, keys.clone()))
        .collect()
}

/// Drive one future to completion under the simulator's scheduler.
pub(super) fn block<T: 'static>(future: impl Future<Output = T> + 'static) -> T {
    granary_sim::scenario::run(0, Box::pin(future))
}

fn sim_log(sim: &Sim, faults: LogFaults) -> Arc<SimDecisionLog> {
    Arc::new(sim.decision_log(0, faults))
}

/// Start an engine over `volumes`, its randomness seeded with 1.
fn start_on(
    log: &Arc<SimDecisionLog>,
    at: BootId,
    volumes: &[VolumeName],
) -> Result<(AuthorityHandle, Driver), StartRefused> {
    let parts = parts(log, 1);
    let volumes = configs(volumes);
    block(async move { start(parts, at, volumes).await })
}

/// A decodable root for `volume` at `seq` over `parent`; `variant` tells
/// two candidates for one seq apart. Its signature is filler: the log's
/// codec checks a candidate's structure, not its signature.
fn sample_root(volume: &VolumeName, seq: u64, parent: Option<GrainId>, variant: u8) -> Vec<u8> {
    let doc = RootDoc {
        volume: volume.clone(),
        seq,
        parent,
        writer_uuid: [0xAB; root::WRITER_UUID_LEN],
        epoch: 7,
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        chunker_spec: "sim-chunker".to_owned(),
        manifest_root: GrainId::of(&[&seq.to_le_bytes()[..], &[variant]].concat()),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![RootSig {
            key_id: [0x01; root::KEY_ID_LEN],
            sig: [0x02; root::ED25519_SIG_LEN],
        }],
    };
    root::encode_root(&doc).unwrap()
}

pub(super) fn identity(operation: u8, candidate_id: GrainId) -> SubmissionIdentity {
    SubmissionIdentity::new(
        Tenant::new(vec![0x11]).unwrap(),
        Principal::new(vec![0x22]).unwrap(),
        Operation::new(vec![operation]).unwrap(),
        candidate_id,
    )
}

/// A decision at position `seq` for `operation`, publishing candidate
/// `variant` of a root at `root_seq` over `base`.
pub(super) fn decision(
    volume: &VolumeName,
    seq: u64,
    operation: u8,
    root_seq: u64,
    base: Option<GrainId>,
    variant: u8,
) -> Record {
    let candidate = sample_root(volume, root_seq, base, variant);
    Record::new(
        seq,
        RecordBody::Decision {
            identity: identity(operation, GrainId::of(&candidate)),
            root_seq,
            base,
            decided_at: Timestamp {
                secs: 1_760_000_001,
                nanos: 0,
            },
            candidate: RootBytes::new(candidate).unwrap(),
        },
    )
    .unwrap()
}

/// The candidate id of decision `d`.
pub(super) fn candidate_id(d: &Record) -> GrainId {
    d.body().identity().candidate_id()
}

/// The attestation decision `d` is owed.
pub(super) fn attestation(d: &Record) -> Record {
    let RecordBody::Decision {
        identity,
        candidate,
        ..
    } = d.body()
    else {
        panic!("not a decision: {d:?}");
    };
    Record::new(
        d.seq(),
        RecordBody::Attestation {
            identity: identity.clone(),
            stored_id: GrainId::of(candidate.as_bytes()),
            final_root: candidate.clone(),
        },
    )
    .unwrap()
}

pub(super) fn landed(d: &Record) -> Record {
    Record::new(
        d.seq(),
        RecordBody::Landed {
            identity: d.body().identity().clone(),
        },
    )
    .unwrap()
}

pub(super) fn lost(d: &Record, occupant: GrainId) -> Record {
    Record::new(
        d.seq(),
        RecordBody::Lost {
            identity: d.body().identity().clone(),
            occupant_id: occupant,
        },
    )
    .unwrap()
}

pub(super) fn envelope(volume: &VolumeName, epoch: u8) -> Envelope {
    Envelope::new(volume.clone(), Epoch::from_bytes([epoch; EPOCH_LEN]))
}

/// The envelope and each record with its mark.
pub(super) fn log_bytes(env: &Envelope, records: &[Record]) -> Vec<u8> {
    let mut bytes = encode_envelope(env).as_bytes().to_vec();
    for record in records {
        let append = encode_append(env, record).unwrap();
        bytes.extend_from_slice(append.record());
        bytes.extend_from_slice(append.mark());
    }
    bytes
}

/// A log whose one entry landed: decision, attestation, landed.
fn landed_log(volume: &VolumeName) -> (Envelope, Vec<Record>) {
    let d = decision(volume, 1, 1, 1, None, 0);
    let records = vec![d.clone(), attestation(&d), landed(&d)];
    (envelope(volume, 0x0A), records)
}

/// A log whose one entry's decision committed and nothing after it.
fn decided_log(volume: &VolumeName) -> (Envelope, Vec<Record>) {
    (
        envelope(volume, 0x0D),
        vec![decision(volume, 1, 1, 1, None, 0)],
    )
}

/// The first half of the next record's bytes: what an interrupted append
/// leaves.
fn torn_next(env: &Envelope, next: &Record) -> Vec<u8> {
    let append = encode_append(env, next).unwrap();
    append.record()[..append.record().len() / 2].to_vec()
}

/// Plant `bytes` at `volume`'s log name, durable, taking no step.
fn seed(log: &Arc<SimDecisionLog>, volume: &VolumeName, bytes: Vec<u8>) {
    let log = Arc::clone(log);
    let volume = volume.clone();
    block(async move { log.seed_bytes(&volume, bytes).await });
}

/// Plant `marker` as the run marker, taking no step.
fn seed_marker(log: &Arc<SimDecisionLog>, marker: &RunMarker) {
    let log = Arc::clone(log);
    let bytes = encode_marker(marker).as_bytes().to_vec();
    block(async move { log.seed_marker_bytes(&bytes).await });
}

fn read_log(log: &Arc<SimDecisionLog>, volume: &VolumeName) -> Option<Vec<u8>> {
    let log = Arc::clone(log);
    let volume = volume.clone();
    block(async move { log.read(&volume).await }).unwrap()
}

fn marker(log: &Arc<SimDecisionLog>) -> MarkerRead {
    let log = Arc::clone(log);
    block(async move { log.read_marker().await }).unwrap()
}

fn marker_says(log: &Arc<SimDecisionLog>) -> Option<RunMarker> {
    match marker(log) {
        MarkerRead::Present(bytes) => decode_marker(&bytes).ok(),
        MarkerRead::Missing { .. } => None,
    }
}

/// The committed records of `volume`'s log.
fn committed(log: &Arc<SimDecisionLog>, volume: &VolumeName) -> Vec<Record> {
    let bytes = read_log(log, volume).unwrap();
    match classify(&bytes, volume).unwrap() {
        Classified::Log { records, .. } => records,
        Classified::NoEnvelope => panic!("no envelope"),
    }
}

/// The rendered trace's `log-call` lines for `call`.
fn calls(sim: &Sim, call: &str) -> Vec<String> {
    let needle = format!("log-call call={call} ");
    sim.trace()
        .render()
        .lines()
        .filter(|line| line.contains(&needle))
        .map(str::to_owned)
        .collect()
}

/// What one scheduled task of a run finished with.
enum Done<T> {
    Run(RunEnd),
    Client(T),
}

/// Run `driver` beside `client` under scheduler seed `seed`: the run's
/// end and the client's result. The store, clock, pause and entropy
/// source may be driven by the test.
fn run_beside<T, S, C, E, P>(
    seed: u64,
    driver: AuthorityDriver<SharedLog, S, C, SimRng, E, P>,
    client: impl Future<Output = T> + 'static,
) -> (RunEnd, T)
where
    T: 'static,
    S: RootStore + 'static,
    C: Clock + 'static,
    E: SecureRandom + Send + 'static,
    P: Pause + 'static,
{
    let run: Task<Done<T>> = Box::pin(async move { Done::Run(driver.run().await) });
    let client: Task<Done<T>> = Box::pin(async move { Done::Client(client.await) });
    let mut out = Scheduler::new(seed).run(vec![run, client]).into_iter();
    let (Some(Done::Run(end)), Some(Done::Client(value))) = (out.next(), out.next()) else {
        panic!("the scheduler returns results in task order");
    };
    (end, value)
}

/// Run `driver` beside a client that only stops it: the run's end, and
/// the end the stop answered.
fn run_to_stop<C: Clock + 'static>(
    seed: u64,
    handle: AuthorityHandle,
    driver: DriverOn<C>,
) -> (RunEnd, RunEnd) {
    run_beside(seed, driver, async move { handle.stop().await })
}

// ------------------------------------- signed roots and a world to run in

/// A key no test volume trusts.
pub(super) fn stranger() -> SigningKey {
    SigningKey::from_seed(&[0x77; 32]).unwrap()
}

/// A root of `volume` at `seq` over `parent`, signed by each of
/// `signers` over its own signing prefix, as a publisher signs; `variant`
/// tells two roots for one seq apart.
pub(super) fn signed_root(
    volume: &VolumeName,
    seq: u64,
    parent: Option<GrainId>,
    variant: u8,
    signers: &[&SigningKey],
) -> Vec<u8> {
    let mut doc = RootDoc {
        volume: volume.clone(),
        seq,
        parent,
        writer_uuid: [variant; root::WRITER_UUID_LEN],
        epoch: 7,
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        chunker_spec: "sim-chunker".to_owned(),
        manifest_root: GrainId::of(&[&seq.to_le_bytes()[..], &[variant]].concat()),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: Vec::new(),
    };
    let prefix = root::signing_prefix_of(&doc).unwrap();
    for signer in signers {
        doc.sigs.push(RootSig {
            key_id: signer.key_id(),
            sig: signer.sign(&prefix),
        });
    }
    root::encode_root(&doc).unwrap()
}

/// A root signed by the volume's publisher.
pub(super) fn good_root(
    volume: &VolumeName,
    seq: u64,
    parent: Option<GrainId>,
    variant: u8,
) -> Vec<u8> {
    signed_root(volume, seq, parent, variant, &[&publisher()])
}

/// A submission against the envelope planted by `World`.
pub(super) fn submission(volume: &VolumeName, operation: u8, candidate: &[u8]) -> Submission {
    submission_at(
        Epoch::from_bytes([WORLD_EPOCH; EPOCH_LEN]),
        volume,
        operation,
        candidate,
    )
}

/// The same identity every test submission is made under, for `operation`.
pub(super) fn submission_at(
    epoch: Epoch,
    volume: &VolumeName,
    operation: u8,
    candidate: &[u8],
) -> Submission {
    Submission::new(
        Tenant::new(vec![0x11]).unwrap(),
        Principal::new(vec![0x22]).unwrap(),
        volume.clone(),
        epoch,
        Operation::new(vec![operation]).unwrap(),
        candidate.to_vec(),
    )
}

/// A decision at position `seq` for `operation`, deciding `candidate` at
/// `root_seq` over `base`: what the live path records for it.
fn decision_of(seq: u64, operation: u8, candidate: &[u8]) -> Record {
    let doc = root::decode_root(candidate).unwrap();
    Record::new(
        seq,
        RecordBody::Decision {
            identity: identity(operation, GrainId::of(candidate)),
            root_seq: doc.seq,
            base: doc.parent,
            decided_at: FixedClock.now(),
            candidate: RootBytes::new(candidate.to_vec()).unwrap(),
        },
    )
    .unwrap()
}

/// The lowercase hex of `id`'s digest, as the trace renders an address.
fn hex(id: GrainId) -> String {
    id.digest().iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A simulated world: the log (with a clean marker), and the engine's
/// root store on node 1 under `faults`.
struct World {
    sim: Sim,
    log: Arc<SimDecisionLog>,
    store: TestStore,
}

/// The epoch of every log [`World::with_empty_logs`] plants.
const WORLD_EPOCH: u8 = 0x0E;

impl World {
    fn new(faults: Faults) -> Self {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        Self::over(sim, log, faults)
    }

    fn over(sim: Sim, log: Arc<SimDecisionLog>, faults: Faults) -> Self {
        let store = TestStore::new(sim.node(1, faults));
        seed_marker(&log, &RunMarker::Clean);
        Self { sim, log, store }
    }

    /// A world whose `volumes` each hold an envelope and no record.
    fn with_empty_logs(volumes: &[VolumeName], faults: Faults) -> Self {
        let world = Self::new(faults);
        for volume in volumes {
            seed(
                &world.log,
                volume,
                log_bytes(&envelope(volume, WORLD_EPOCH), &[]),
            );
        }
        world
    }

    /// A world whose `volume` holds `records`.
    fn with_records(volume: &VolumeName, records: &[Record], faults: Faults) -> Self {
        let world = Self::new(faults);
        seed(
            &world.log,
            volume,
            log_bytes(&envelope(volume, WORLD_EPOCH), records),
        );
        world
    }

    fn start(&self, volumes: &[VolumeName]) -> (AuthorityHandle, Driver) {
        let parts = parts_with(&self.log, self.store.clone(), 1);
        let volumes = configs(volumes);
        block(async move { start(parts, boot(1), volumes).await }).unwrap()
    }

    /// As [`Self::start`], over `clock` in place of [`FixedClock`]: a
    /// restart reuses this world's log and store, so an entry's
    /// `decided_at` from a prior run survives to be aged against the new
    /// clock (spec §7).
    fn start_with_clock<C: Clock + 'static>(
        &self,
        volumes: &[VolumeName],
        clock: C,
    ) -> (AuthorityHandle, DriverOn<C>) {
        let parts = parts_with_clock(&self.log, self.store.clone(), clock, 1);
        let volumes = configs(volumes);
        block(async move { start(parts, boot(1), volumes).await }).unwrap()
    }

    fn plant(&self, volume: &VolumeName, seq: u64, bytes: &[u8]) {
        assert!(self.sim.admin().plant_root(volume, seq, bytes.to_vec()));
    }

    fn delete(&self, volume: &VolumeName, seq: u64) {
        assert!(self.sim.admin().delete_root(volume, seq));
    }

    /// Plant a publisher-signed chain of `volume` at seqs `1..=len`;
    /// each root's bytes, in seq order.
    fn plant_chain(&self, volume: &VolumeName, len: u64, variant: u8) -> Vec<Vec<u8>> {
        let mut chain: Vec<Vec<u8>> = Vec::new();
        for seq in 1..=len {
            let parent = chain.last().map(|bytes| GrainId::of(bytes));
            let bytes = good_root(volume, seq, parent, variant);
            self.plant(volume, seq, &bytes);
            chain.push(bytes);
        }
        chain
    }

    /// The trace's `put-root` lines for `volume` at `seq`.
    fn puts(&self, volume: &VolumeName, seq: u64) -> Vec<String> {
        let needle = format!("put-root vol={} seq={seq} ", volume.as_str());
        self.sim
            .trace()
            .render()
            .lines()
            .filter(|line| line.contains(&needle))
            .map(str::to_owned)
            .collect()
    }

    /// The position `seq` of this world's logs.
    fn position(seq: u64) -> Position {
        Position {
            epoch: Epoch::from_bytes([WORLD_EPOCH; EPOCH_LEN]),
            seq,
        }
    }
}

/// Submit `sub` until its answer is no longer [`Answer::Open`], yielding
/// between submissions: the answer once the publication closed.
pub(super) async fn settle(handle: &AuthorityHandle, sub: &Submission) -> Answer {
    for _ in 0..10_000 {
        let answer = handle.submit(sub.clone()).await;
        if !matches!(answer, Answer::Open { .. }) {
            return answer;
        }
        yield_once().await;
    }
    panic!("the publication never closed");
}

/// A bound a test passes when it is not testing the flag itself: an
/// entry built through [`decision_of`], or decided by an engine over
/// [`FixedClock`], carries [`FixedClock::now`], so its age there is zero
/// and no bound flags it.
const AMPLE_BOUND: Duration = Duration::from_mins(1);

/// Ask for the report at `bound` until its row for `volume` satisfies
/// `done`, yielding between: that row.
async fn await_row(
    handle: &AuthorityHandle,
    volume: &VolumeName,
    bound: Duration,
    done: impl Fn(&OpenEntryRow) -> bool,
) -> OpenEntryRow {
    for _ in 0..10_000 {
        let rows = handle.report(bound).await.unwrap();
        if let Some(row) = rows.into_iter().find(|row| row.volume == *volume)
            && done(&row)
        {
            return row;
        }
        yield_once().await;
    }
    panic!("the report never showed the row");
}

// --------------------------------------------- the marker's table (§6.2)

/// Malformed and torn markers refuse, and nothing is written.
#[test]
fn a_malformed_or_torn_marker_refuses_and_writes_nothing() {
    let running = encode_marker(&RunMarker::Running(boot(9)));
    let torn = running.as_bytes()[..running.as_bytes().len() - 1].to_vec();
    let mut flipped = running.as_bytes().to_vec();
    flipped[20] ^= 0x01;
    for bytes in [b"not a marker".to_vec(), torn, flipped, Vec::new()] {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        let planted = bytes.clone();
        let fixture = Arc::clone(&log);
        block(async move { fixture.seed_marker_bytes(&planted).await });
        let refused = start_on(&log, boot(1), &[a()]).unwrap_err();
        assert!(
            matches!(refused, StartRefused::MarkerMalformed(_)),
            "{refused:?}"
        );
        assert_eq!(log.steps(), 1, "only the marker was read");
        assert_eq!(marker(&log), MarkerRead::Present(bytes));
        assert_eq!(log.violations(), []);
    }
}

/// A marker that cannot be read refuses the start and does not fence:
/// the next start in the same process is admitted, and writes without
/// meeting a fence.
#[test]
fn a_marker_read_error_refuses_without_fencing() {
    let sim = Sim::new();
    // Step 0 is the start's `read_marker`; an injected failure on a step
    // that is not a sync fails it with an i/o error.
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: 0 }));
    let refused = start_on(&log, boot(1), &[a()]).unwrap_err();
    assert_eq!(
        refused,
        StartRefused::MarkerUnreadable(LogIoError::Io(IoErrorKind::Other))
    );
    assert_eq!(log.steps(), 1, "only the marker was read");
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    assert_eq!(run_to_stop(0, handle, driver).0, RunEnd::Stopped);
    assert_eq!(log.violations(), [], "no fence was met");
}

/// A same-boot restart after a run that did not stop cleanly refuses,
/// for every volume; a new boot admits it.
#[test]
fn running_under_this_boot_refuses_a_same_boot_restart() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    drop((handle, driver));
    assert_eq!(marker_says(&log), Some(RunMarker::Running(boot(1))));

    log.restart_process();
    let steps = log.steps();
    assert_eq!(
        start_on(&log, boot(1), &[a()]).unwrap_err(),
        StartRefused::RunningInThisBoot
    );
    assert_eq!(log.steps(), steps + 1, "only the marker was read");

    log.crash_host(&mut SimRng::seeded(3, 3));
    let (handle, driver) = start_on(&log, boot(2), &[a()]).unwrap();
    assert_eq!(marker_says(&log), Some(RunMarker::Running(boot(2))));
    assert_eq!(run_to_stop(0, handle, driver).0, RunEnd::Stopped);
    assert_eq!(log.violations(), []);
}

/// Running under another boot, and clean, both admit: running under
/// the current boot is written before anything else.
#[test]
fn running_under_another_boot_or_clean_admits() {
    for previous in [RunMarker::Running(boot(7)), RunMarker::Clean] {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        seed_marker(&log, &previous);
        let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
        assert_eq!(marker_says(&log), Some(RunMarker::Running(boot(1))));
        assert_eq!(run_to_stop(0, handle, driver).0, RunEnd::Stopped);
        assert_eq!(marker_says(&log), Some(RunMarker::Clean));
        assert_eq!(log.violations(), []);
    }
}

/// With no marker, an absent or empty state directory is a first start;
/// one holding anything refuses, writing nothing.
#[test]
fn a_missing_marker_admits_only_an_absent_or_empty_state_directory() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    assert!(start_on(&log, boot(1), &[a()]).is_ok());

    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let fixture = Arc::clone(&log);
    block(async move { fixture.seed_empty_state_dir().await });
    assert!(start_on(&log, boot(1), &[a()]).is_ok());

    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env, records) = landed_log(&a());
    seed(&log, &a(), log_bytes(&env, &records));
    assert_eq!(
        start_on(&log, boot(1), &[a()]).unwrap_err(),
        StartRefused::StateDirectoryOccupied
    );
    assert_eq!(log.steps(), 1, "only the marker was read");
    assert!(matches!(marker(&log), MarkerRead::Missing { .. }));
}

/// A volume named twice refuses before anything is read.
#[test]
fn a_volume_configured_twice_refuses_before_anything_is_read() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    assert_eq!(
        start_on(&log, boot(1), &[a(), b(), a()]).unwrap_err(),
        StartRefused::DuplicateVolume(a())
    );
    assert_eq!(log.steps(), 0);
}

// ------------------------------------- recovery before mutation (§6.3, §6.4)

/// Volume A holds a tail recovery would truncate; volume B, classified
/// after it, holds no envelope. The start refuses on B without touching
/// A, and writes clean.
#[test]
fn every_volume_is_classified_before_any_is_mutated() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env, records) = landed_log(&a());
    let mut a_bytes = log_bytes(&env, &records);
    a_bytes.extend(torn_next(&env, &decision(&a(), 2, 9, 1, None, 9)));
    seed(&log, &a(), a_bytes.clone());
    seed(&log, &b(), b"no envelope".to_vec());
    seed_marker(&log, &RunMarker::Clean);

    let refused = start_on(&log, boot(1), &[a(), b()]).unwrap_err();
    assert_eq!(
        refused,
        StartRefused::Volume {
            volume: b(),
            reason: VolumeRefusal::NoEnvelope
        }
    );
    assert_eq!(read_log(&log, &a()), Some(a_bytes), "A was not touched");
    for call in [
        "truncate",
        "resync",
        "complete-namespace",
        "append",
        "initialise",
    ] {
        assert!(calls(&sim, call).is_empty(), "{call}");
    }
    assert_eq!(marker_says(&log), Some(RunMarker::Clean));
    assert_eq!(log.violations(), []);
}

/// Each row of spec §6.3's table that refuses at start refuses the whole
/// start and writes clean.
#[test]
fn a_refused_volume_refuses_the_start_and_writes_clean() {
    let (env, records) = landed_log(&a());
    let mut damaged = log_bytes(&env, &records);
    let at = encode_envelope(&env).as_bytes().len() + 70;
    damaged[at] ^= 0x40;
    let (other_env, other_records) = landed_log(&b());
    let other_volume = log_bytes(&other_env, &other_records);
    for bytes in [damaged, other_volume] {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        seed(&log, &a(), bytes);
        seed_marker(&log, &RunMarker::Clean);
        let refused = start_on(&log, boot(1), &[a()]).unwrap_err();
        assert!(
            matches!(
                &refused,
                StartRefused::Volume { volume, reason: VolumeRefusal::Damaged(_) } if *volume == a()
            ),
            "{refused:?}"
        );
        assert_eq!(marker_says(&log), Some(RunMarker::Clean));
        assert_eq!(log.violations(), []);
    }

    // A read that fails: the last step of a start over one missing
    // volume is that volume's read.
    let dry = Sim::new();
    let dry_log = sim_log(&dry, LogFaults::none());
    start_on(&dry_log, boot(1), &[a()]).unwrap();
    let read_step = dry_log.steps() - 1;
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: read_step }));
    let refused = start_on(&log, boot(1), &[a()]).unwrap_err();
    assert!(
        matches!(
            &refused,
            StartRefused::Volume {
                reason: VolumeRefusal::Unreadable(_),
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(marker_says(&log), Some(RunMarker::Clean));
    assert_eq!(log.violations(), []);
}

/// A log holding a committed pair under the reserved tag `0x05`, after
/// a closed entry, refuses the start as damage to committed history at
/// the pair, writes nothing to the log, and writes clean: v1 never
/// writes the tag, so no correct writer left it there.
#[test]
fn a_committed_pair_under_the_reserved_tag_refuses_the_start() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env, records) = landed_log(&a());
    let mut bytes = log_bytes(&env, &records);
    let at = bytes.len();
    bytes.extend(granary_core::testkit::authlog_reserved_tag_pair(
        &env,
        2,
        GrainId::of(b"a stale candidate"),
    ));
    seed(&log, &a(), bytes.clone());
    seed_marker(&log, &RunMarker::Clean);
    let refused = start_on(&log, boot(1), &[a()]).unwrap_err();
    assert_eq!(
        refused,
        StartRefused::Volume {
            volume: a(),
            reason: VolumeRefusal::Damaged(LogError {
                offset: at,
                reason: granary_core::authlog::LogErrorReason::DamagedCommittedHistory,
            }),
        }
    );
    assert_eq!(read_log(&log, &a()), Some(bytes), "the log is untouched");
    assert_eq!(marker_says(&log), Some(RunMarker::Clean));
    assert_eq!(log.violations(), []);
}

/// Recovery truncates a tail, re-syncs a log holding records, completes
/// the namespace of a log holding none, and leaves a missing log alone;
/// each worker's state is its log's replay.
#[test]
fn recovery_truncates_resyncs_and_completes_before_serving() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env_a, records_a) = landed_log(&a());
    let committed_a = log_bytes(&env_a, &records_a);
    let mut a_bytes = committed_a.clone();
    a_bytes.extend(torn_next(&env_a, &decision(&a(), 2, 9, 1, None, 9)));
    seed(&log, &a(), a_bytes);
    let env_b = envelope(&b(), 0x0B);
    seed(&log, &b(), log_bytes(&env_b, &[]));
    seed_marker(&log, &RunMarker::Clean);

    let (handle, driver) = start_on(&log, boot(1), &[a(), b(), c()]).unwrap();
    assert_eq!(read_log(&log, &a()), Some(committed_a), "the tail is gone");
    assert_eq!(
        calls(&sim, "truncate"),
        ["n0 log-call call=truncate vol=vol-a -> ok"]
    );
    assert_eq!(
        calls(&sim, "resync"),
        ["n0 log-call call=resync vol=vol-a -> ok"]
    );
    assert_eq!(
        calls(&sim, "complete-namespace"),
        ["n0 log-call call=complete-namespace vol=vol-b -> ok"]
    );
    let states: Vec<Option<VolumeState>> =
        driver.workers.iter().map(|w| w.state().cloned()).collect();
    assert_eq!(
        states,
        [
            Some(VolumeState::replay(env_a, &records_a).unwrap()),
            Some(VolumeState::new(env_b)),
            None,
        ]
    );
    assert_eq!(run_to_stop(0, handle, driver).0, RunEnd::Stopped);
    assert_eq!(log.violations(), []);
}

/// A decision that committed without its attestation gets the
/// attestation appended as its worker's first action, before the worker
/// takes any request, however the client's request and the run
/// interleave.
#[test]
fn an_owed_attestation_is_the_workers_first_action() {
    for seed_n in 0..16 {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        let (env, records) = decided_log(&a());
        seed(&log, &a(), log_bytes(&env, &records));
        seed_marker(&log, &RunMarker::Clean);
        let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
        let started = sim.trace().render().lines().count();
        let (end, answer) = run_beside(seed_n, driver, async move {
            let answer = handle.initialise(&a()).await;
            handle.stop().await;
            answer
        });
        assert_eq!(end, RunEnd::Stopped);
        assert_eq!(answer, Err(InitialiseError::LogHasRecords));
        let rendered = sim.trace().render();
        let first_call = rendered
            .lines()
            .skip(started)
            .find(|line| line.contains("log-call"));
        assert_eq!(
            first_call,
            Some("n0 log-call call=append vol=vol-a -> ok"),
            "seed {seed_n}"
        );
        assert_eq!(
            committed(&log, &a()),
            [records[0].clone(), attestation(&records[0])]
        );
        assert_eq!(log.violations(), [], "seed {seed_n}");
    }
}

/// An owed attestation the state refuses fences the engine before the
/// worker takes any request: nothing reaches the log after the start, the
/// request is answered `Fenced`, and the marker stays running. The
/// refusal is planted by replacing the open entry's candidate bytes, so
/// the attestation built from them names another stored id.
#[test]
fn a_refused_owed_attestation_fences_and_nothing_is_served() {
    for seed_n in 0..8 {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        let (env, records) = decided_log(&a());
        let planted = log_bytes(&env, &records);
        seed(&log, &a(), planted.clone());
        seed_marker(&log, &RunMarker::Clean);
        let (handle, mut driver) = start_on(&log, boot(1), &[a()]).unwrap();
        let other = RootBytes::new(sample_root(&a(), 1, None, 9)).unwrap();
        driver.workers[0]
            .state_mut()
            .unwrap()
            .replace_open_candidate(other);
        let started = sim.trace().render().lines().count();
        let (end, (answer, stopped)) = run_beside(seed_n, driver, async move {
            let answer = handle.initialise(&a()).await;
            (answer, handle.stop().await)
        });
        let fence = Fence {
            call: LogCall::Append,
            volume: Some(a()),
            cause: FenceCause::AttestationRefused(RecordRefusal::State(ApplyError {
                seq: 1,
                rule: GrammarRule::Rule5IdentityMismatch,
            })),
        };
        assert_eq!(end, RunEnd::Fenced(fence.clone()), "seed {seed_n}");
        assert_eq!(stopped, RunEnd::Fenced(fence), "seed {seed_n}");
        assert_eq!(answer, Err(InitialiseError::Fenced), "seed {seed_n}");
        let rendered = sim.trace().render();
        let after: Vec<&str> = rendered
            .lines()
            .skip(started)
            .filter(|line| line.contains("log-call"))
            .collect();
        assert_eq!(after, Vec::<&str>::new(), "seed {seed_n}: nothing served");
        assert_eq!(read_log(&log, &a()), Some(planted.clone()));
        assert_eq!(marker_says(&log), Some(RunMarker::Running(boot(1))));
        assert_eq!(log.violations(), [], "seed {seed_n}");
    }
}

// ----------------------------------------------------- live and replay

/// Records committed through the live path, one at a time, leave the
/// worker in exactly the state replaying the log gives, after every
/// record. The log starts with an envelope and no record, so its first
/// append also meets the start's namespace barrier.
#[test]
fn live_commits_and_replay_give_the_same_state() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let env = envelope(&a(), 0x0E);
    seed(&log, &a(), log_bytes(&env, &[]));
    seed_marker(&log, &RunMarker::Clean);
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();

    let d1 = decision(&a(), 1, 1, 1, None, 0);
    let d2 = decision(&a(), 2, 2, 2, Some(candidate_id(&d1)), 0);
    // Operation 2's rebase after its candidate lost.
    let d3 = decision(&a(), 3, 2, 2, Some(candidate_id(&d1)), 1);
    let script = [
        d1.clone(),
        attestation(&d1),
        landed(&d1),
        d2.clone(),
        attestation(&d2),
        lost(&d2, GrainId::of(b"another root")),
        d3.clone(),
        attestation(&d3),
    ];

    let AuthorityDriver {
        log: owned_log,
        store,
        clock,
        rng,
        secure_random,
        pause,
        gate,
        shared,
        mut workers,
        ..
    } = driver;
    let mut worker = workers.remove(0);
    let volume = a();
    let checked = block(async move {
        let engine = Engine {
            log: &owned_log,
            store: &store,
            clock: &clock,
            rng: &rng,
            secure_random: &secure_random,
            pause: &pause,
            gate: &gate,
            shared: &shared,
        };
        for (n, record) in script.iter().enumerate() {
            worker.commit(&engine, record).await.unwrap();
            let bytes = owned_log.read(&volume).await.unwrap().unwrap();
            let Classified::Log {
                envelope, records, ..
            } = classify(&bytes, &volume).unwrap()
            else {
                panic!("the log has an envelope");
            };
            assert_eq!(records, script[..=n], "record {n} is committed");
            let replayed = VolumeState::replay(envelope, &records).unwrap();
            assert_eq!(worker.state(), Some(&replayed), "after record {n}");
        }
        script.len()
    });
    assert_eq!(checked, 8);
    drop(handle);
    assert_eq!(log.violations(), []);
}

/// A state that refuses a record after its append returned `Ok` fences
/// the engine with its own cause: the log holds the record, the state is
/// as it was, and the next commit is answered by the fence without a log
/// call.
#[test]
fn a_state_refusing_a_committed_record_fences() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let env = envelope(&a(), 0x0E);
    seed(&log, &a(), log_bytes(&env, &[]));
    seed_marker(&log, &RunMarker::Clean);
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    let AuthorityDriver {
        log: owned_log,
        store,
        clock,
        rng,
        secure_random,
        pause,
        gate,
        shared,
        mut workers,
        ..
    } = driver;
    let mut worker = workers.remove(0);
    let refusal = ApplyError {
        seq: 1,
        rule: GrammarRule::Rule1SequencePosition,
    };
    worker.state_mut().unwrap().refuse_next_apply(refusal);
    let d1 = decision(&a(), 1, 1, 1, None, 0);
    let fence = Fence {
        call: LogCall::Append,
        volume: Some(a()),
        cause: FenceCause::CommittedRecordRefused(refusal),
    };
    let expected = fence.clone();
    let before = VolumeState::new(env);
    block(async move {
        let engine = Engine {
            log: &owned_log,
            store: &store,
            clock: &clock,
            rng: &rng,
            secure_random: &secure_random,
            pause: &pause,
            gate: &gate,
            shared: &shared,
        };
        assert_eq!(
            worker.commit(&engine, &d1).await,
            Err(CommitError::Fenced(expected.clone()))
        );
        assert_eq!(shared.fence.get(), Some(expected.clone()));
        assert_eq!(worker.state(), Some(&before), "the state is unchanged");
        assert_eq!(
            worker.commit(&engine, &d1).await,
            Err(CommitError::Fenced(expected))
        );
    });
    assert_eq!(committed(&log, &a()), [decision(&a(), 1, 1, 1, None, 0)]);
    assert_eq!(
        calls(&sim, "append").len(),
        1,
        "the second commit made no call"
    );
    assert_eq!(handle.fence(), Some(fence));
    assert_eq!(log.violations(), []);
}

// ---------------------------------------------------------- initialise

/// A missing log is created under an epoch of sixteen bytes from the
/// cryptographic-randomness seam: the value an identically seeded stream
/// gives, and another under another seed.
#[test]
fn initialise_creates_a_log_under_an_epoch_drawn_from_the_secure_seam() {
    let mut epochs = Vec::new();
    for rng_seed in [5, 6] {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        let parts = parts(&log, rng_seed);
        let (handle, driver) =
            block(async move { start(parts, boot(1), configs(&[a()])).await }).unwrap();
        let (end, answer) = run_beside(0, driver, async move {
            let answer = handle.initialise(&a()).await;
            handle.stop().await;
            answer
        });
        assert_eq!(end, RunEnd::Stopped);
        let epoch = first_epoch(rng_seed);
        assert_eq!(answer, Ok(Initialised::Created { epoch }));
        let bytes = read_log(&log, &a()).unwrap();
        let Classified::Log {
            envelope, records, ..
        } = classify(&bytes, &a()).unwrap()
        else {
            panic!("an envelope was written");
        };
        assert_eq!((envelope.epoch(), records.len()), (epoch, 0));
        assert_eq!(log.violations(), []);
        epochs.push(epoch);
    }
    assert_ne!(epochs[0], epochs[1]);
}

/// An envelope with no record keeps its epoch: the namespace barrier is
/// completed again and no `initialise` call is made.
#[test]
fn initialise_keeps_an_envelope_only_log() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let env = envelope(&a(), 0x0C);
    seed(&log, &a(), log_bytes(&env, &[]));
    seed_marker(&log, &RunMarker::Clean);
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    let (end, answer) = run_beside(0, driver, async move {
        let answer = handle.initialise(&a()).await;
        handle.stop().await;
        answer
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(answer, Ok(Initialised::Kept { epoch: env.epoch() }));
    assert!(calls(&sim, "initialise").is_empty());
    assert_eq!(calls(&sim, "complete-namespace").len(), 2);
    assert_eq!(log.violations(), []);
}

/// Initialise removes the volume's leftover temporary before its first
/// step: a temporary and an envelope-only log with a tail, planted after
/// the start, see the removal before the read and the truncate.
#[test]
fn initialise_removes_the_temporary_before_its_first_step() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    let env = envelope(&a(), 0x0C);
    let mut planted = log_bytes(&env, &[]);
    planted.extend(torn_next(&env, &decision(&a(), 1, 1, 1, None, 0)));
    let started = sim.trace().render().lines().count();
    let client_log = Arc::clone(&log);
    let (end, answer) = run_beside(0, driver, async move {
        client_log.seed_bytes(&a(), planted).await;
        client_log.seed_temporary(&a()).await;
        let answer = handle.initialise(&a()).await;
        handle.stop().await;
        answer
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(answer, Ok(Initialised::Kept { epoch: env.epoch() }));
    let rendered = sim.trace().render();
    let after: Vec<&str> = rendered
        .lines()
        .skip(started)
        .filter(|line| line.contains("log-call") && line.contains("vol=vol-a"))
        .collect();
    assert_eq!(
        after,
        [
            "n0 log-call call=remove-temporary vol=vol-a -> ok",
            "n0 log-call call=read vol=vol-a -> ok",
            "n0 log-call call=truncate vol=vol-a -> ok",
            "n0 log-call call=complete-namespace vol=vol-a -> ok",
        ]
    );
    assert_eq!(read_log(&log, &a()), Some(log_bytes(&env, &[])));
    assert_eq!(log.violations(), []);
}

/// A committed log, a file with no envelope, damage and an unconfigured
/// volume all refuse, and none reaches the seam's `initialise`, whose
/// `AlreadyExists` would fence the engine. The engine stays unfenced and
/// stops clean.
#[test]
fn initialise_refuses_without_calling_initialise() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env, records) = landed_log(&a());
    seed(&log, &a(), log_bytes(&env, &records));
    seed_marker(&log, &RunMarker::Clean);
    let (handle, driver) = start_on(&log, boot(1), &[a(), b(), c()]).unwrap();

    let (other_env, other_records) = landed_log(&vol("vol-z"));
    let planted_c = log_bytes(&other_env, &other_records);
    let client_log = Arc::clone(&log);
    let planted = planted_c.clone();
    let (end, answers) = run_beside(0, driver, async move {
        // B and C had no log at the start; files appear at their names
        // behind the engine's back.
        client_log.seed_bytes(&b(), b"junk".to_vec()).await;
        client_log.seed_bytes(&c(), planted).await;
        let answers = vec![
            handle.initialise(&a()).await,
            handle.initialise(&b()).await,
            handle.initialise(&c()).await,
            handle.initialise(&vol("vol-unknown")).await,
        ];
        assert_eq!(handle.fence(), None);
        handle.stop().await;
        answers
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(answers[0], Err(InitialiseError::LogHasRecords));
    assert_eq!(answers[1], Err(InitialiseError::NoEnvelope));
    assert!(
        matches!(answers[2], Err(InitialiseError::Damaged(_))),
        "{:?}",
        answers[2]
    );
    assert_eq!(answers[3], Err(InitialiseError::UnconfiguredVolume));
    assert!(calls(&sim, "initialise").is_empty());
    assert_eq!(read_log(&log, &b()), Some(b"junk".to_vec()));
    assert_eq!(read_log(&log, &c()), Some(planted_c));
    assert_eq!(marker_says(&log), Some(RunMarker::Clean));
    assert_eq!(log.violations(), []);
}

/// A read of the log's name that fails refuses the initialise, without
/// fencing.
#[test]
fn initialise_after_a_failed_read_refuses() {
    let dry = Sim::new();
    let dry_log = sim_log(&dry, LogFaults::none());
    start_on(&dry_log, boot(1), &[a()]).unwrap();
    // The worker's first log step after the start is its removal of A's
    // temporary; its read of A is the second.
    let read_step = dry_log.steps() + 1;
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: read_step }));
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    let (end, answer) = run_beside(0, driver, async move {
        let answer = handle.initialise(&a()).await;
        handle.stop().await;
        answer
    });
    assert!(
        matches!(answer, Err(InitialiseError::Unreadable(_))),
        "{answer:?}"
    );
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(log.violations(), []);
}

// ------------------------------------------------ the fence and the token

/// Two volumes, each with a decision owed its attestation, and a clean
/// marker.
fn plant_two_decided(log: &Arc<SimDecisionLog>) {
    for volume in [a(), b()] {
        let (env, records) = decided_log(&volume);
        seed(log, &volume, log_bytes(&env, &records));
    }
    seed_marker(log, &RunMarker::Clean);
}

/// Volume A's attestation fails its record sync while volume B's
/// attestation waits for the token. The fence is set before the token
/// is released, so B's append never issues a step: the fake sees no
/// overlap and nothing after the failed sync, B's log is unchanged,
/// clean is never written, and every answer after it is `Fenced`.
#[test]
fn a_failed_sync_on_one_volume_fences_every_volume_and_nothing_follows() {
    let dry = Sim::new();
    let dry_log = sim_log(&dry, LogFaults::none());
    plant_two_decided(&dry_log);
    start_on(&dry_log, boot(1), &[a(), b()]).unwrap();
    // A's append: its record write is the first step after the start,
    // its record sync the second.
    let fail_at = dry_log.steps() + 1;
    let (env_b, records_b) = decided_log(&b());
    let b_before = log_bytes(&env_b, &records_b);
    for seed_n in 0..16 {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: fail_at }));
        plant_two_decided(&log);
        let (handle, driver) = start_on(&log, boot(1), &[a(), b()]).unwrap();
        let (end, (answer, stopped)) = run_beside(seed_n, driver, async move {
            let answer = handle.initialise(&b()).await;
            (answer, handle.stop().await)
        });
        let fence = Fence {
            call: LogCall::Append,
            volume: Some(a()),
            cause: FenceCause::Failed(LogIoError::SyncFailed),
        };
        assert_eq!(end, RunEnd::Fenced(fence.clone()), "seed {seed_n}");
        assert_eq!(stopped, RunEnd::Fenced(fence), "seed {seed_n}");
        assert_eq!(answer, Err(InitialiseError::Fenced), "seed {seed_n}");
        assert_eq!(log.violations(), [], "seed {seed_n}");
        assert_eq!(
            read_log(&log, &b()),
            Some(b_before.clone()),
            "seed {seed_n}: B untouched"
        );
        assert_eq!(calls(&sim, "append").len(), 1, "seed {seed_n}");
        assert_eq!(marker_says(&log), Some(RunMarker::Running(boot(1))));
    }
}

/// A run dropped while a worker's append is in flight fences: the
/// append's future did not run to completion.
#[test]
fn a_run_dropped_mid_append_fences() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env, records) = decided_log(&a());
    seed(&log, &a(), log_bytes(&env, &records));
    seed_marker(&log, &RunMarker::Clean);
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    let started = log.steps();
    {
        let mut run = Box::pin(driver.run());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..64 {
            if log.steps() > started {
                break;
            }
            assert!(run.as_mut().poll(&mut cx).is_pending());
        }
        assert!(log.steps() > started, "the run began no append");
    }
    assert_eq!(
        handle.fence(),
        Some(Fence {
            call: LogCall::Append,
            volume: Some(a()),
            cause: FenceCause::Dropped,
        })
    );
    let stopped = block(async move { handle.stop().await });
    assert!(matches!(stopped, RunEnd::Fenced(_)), "{stopped:?}");
    assert_eq!(marker_says(&log), Some(RunMarker::Running(boot(1))));
}

/// Once the engine is fenced every initialise answers `Fenced`: an
/// unconfigured volume's, and a configured one's.
#[test]
fn every_answer_after_the_fence_is_fenced() {
    let dry = Sim::new();
    let dry_log = sim_log(&dry, LogFaults::none());
    plant_two_decided(&dry_log);
    start_on(&dry_log, boot(1), &[a(), b()]).unwrap();
    let fail_at = dry_log.steps() + 1;
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: fail_at }));
    plant_two_decided(&log);
    let (handle, driver) = start_on(&log, boot(1), &[a(), b()]).unwrap();
    let later = handle.clone();
    let (end, _) = run_to_stop(0, handle, driver);
    assert!(matches!(end, RunEnd::Fenced(_)), "{end:?}");
    let answers = block(async move {
        vec![
            later.initialise(&vol("vol-unknown")).await,
            later.initialise(&a()).await,
            later.initialise(&b()).await,
        ]
    });
    assert_eq!(answers, vec![Err(InitialiseError::Fenced); 3]);
}

/// A worker with nothing to do (no request, no open entry, a live
/// handle) does not hold the run up once another worker fences: the run
/// ends `Fenced` under a small poll budget, across seeds, with no stop
/// asked for. The idle worker is A, joined before B, so B's fence lands
/// after A's last poll of the pass: only the join's next pass shows it
/// to A.
#[test]
fn an_idle_worker_ends_when_another_fences() {
    let (env, records) = decided_log(&b());
    let dry = Sim::new();
    let dry_log = sim_log(&dry, LogFaults::none());
    seed(&dry_log, &b(), log_bytes(&env, &records));
    seed_marker(&dry_log, &RunMarker::Clean);
    start_on(&dry_log, boot(1), &[a(), b()]).unwrap();
    // B's append: its record write is the first step after the start,
    // its record sync the second.
    let fail_at = dry_log.steps() + 1;
    for seed_n in 0..16 {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: fail_at }));
        seed(&log, &b(), log_bytes(&env, &records));
        seed_marker(&log, &RunMarker::Clean);
        let (handle, driver) = start_on(&log, boot(1), &[a(), b()]).unwrap();
        assert!(driver.workers[0].state().is_none(), "A has no log");
        let run: Task<Option<RunEnd>> = Box::pin(async move { Some(driver.run().await) });
        let delay = seed_n % 4;
        let idle: Task<Option<RunEnd>> = Box::pin(async move {
            for _ in 0..delay {
                yield_once().await;
            }
            None
        });
        let ends = Scheduler::new(seed_n)
            .with_poll_budget(64)
            .run(vec![run, idle]);
        let fence = Fence {
            call: LogCall::Append,
            volume: Some(b()),
            cause: FenceCause::Failed(LogIoError::SyncFailed),
        };
        assert_eq!(
            ends[0],
            Some(RunEnd::Fenced(fence.clone())),
            "seed {seed_n}"
        );
        assert_eq!(handle.fence(), Some(fence), "seed {seed_n}");
        assert_eq!(log.violations(), [], "seed {seed_n}");
    }
}

// ------------------------------------------------------------- the stop

#[test]
fn idle_workers_share_one_stop_waker() {
    struct ForwardWake(Waker);

    impl Wake for ForwardWake {
        fn wake(self: Arc<Self>) {
            self.0.wake_by_ref();
        }
    }

    let volumes = [a(), b()];
    let world = World::with_empty_logs(&volumes, Faults::none());
    let (_handle, driver) = world.start(&volumes);
    let shared = Arc::clone(&driver.shared);
    let stop = &shared.stop;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let end = std::thread::scope(|scope| {
        runtime.block_on(async {
            let mut run = pin!(driver.run());
            let mut deadline = pin!(tokio::time::timeout(
                Duration::from_secs(5),
                std::future::pending::<()>(),
            ));
            let mut first_poll = true;
            poll_fn(|cx| {
                // A deadline wake must fail before it can poll the driver.
                assert!(
                    deadline.as_mut().poll(cx).is_pending(),
                    "driver did not stop"
                );
                if std::mem::take(&mut first_poll) {
                    // Each adapter has its own identity and wakes this same task.
                    for _ in 0..64 {
                        let waker = Waker::from(Arc::new(ForwardWake(cx.waker().clone())));
                        let mut driver_context = Context::from_waker(&waker);
                        assert!(run.as_mut().poll(&mut driver_context).is_pending());
                    }
                    assert_eq!(stop.waker_count(), 1, "idle workers' stop waker count");
                    scope.spawn(move || stop.request());
                    Poll::Pending
                } else {
                    run.as_mut().poll(cx)
                }
            })
            .await
        })
    });
    assert_eq!(end, RunEnd::Stopped);
}

/// A stop asked for at any point of an attestation's append lets the
/// append finish, then writes clean. Across seeds and delays the stop
/// lands while the append is in flight at least once.
#[test]
fn a_stop_never_drops_an_append_mid_flight() {
    let mut mid_flight = 0;
    for seed_n in 0..24 {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        let (env, records) = decided_log(&a());
        seed(&log, &a(), log_bytes(&env, &records));
        seed_marker(&log, &RunMarker::Clean);
        let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
        let started = log.steps();
        let probe = Arc::clone(&log);
        let delay = seed_n % 6;
        let (end, (stopped, at)) = run_beside(seed_n, driver, async move {
            for _ in 0..delay {
                yield_once().await;
            }
            let at = probe.steps();
            (handle.stop().await, at)
        });
        // The append's four steps are `started..started + 4`: a stop
        // asked for once one has been issued and before the last is, is
        // asked for mid-flight.
        if at > started && at < started + 4 {
            mid_flight += 1;
        }
        assert_eq!(end, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(stopped, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(
            committed(&log, &a()),
            [records[0].clone(), attestation(&records[0])],
            "seed {seed_n}"
        );
        assert_eq!(marker_says(&log), Some(RunMarker::Clean), "seed {seed_n}");
        assert_eq!(log.violations(), [], "seed {seed_n}");
    }
    assert!(
        mid_flight > 0,
        "no stop landed mid-append: the check is vacuous"
    );
}

/// After the stop, a request answers `Stopped`.
#[test]
fn a_request_after_the_stop_answers_stopped() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    let later = handle.clone();
    assert_eq!(run_to_stop(0, handle, driver).0, RunEnd::Stopped);
    assert_eq!(
        block(async move { later.initialise(&a()).await }),
        Err(InitialiseError::Stopped)
    );
}

// ------------------------------------------------------------ the sweep

/// The sweep's scenario: A holds an owed attestation behind a tail, B an
/// envelope and no record, C nothing; the client initialises C, then
/// stops the engine.
fn plant_sweep(log: &Arc<SimDecisionLog>) {
    let (env, records) = decided_log(&a());
    let mut a_bytes = log_bytes(&env, &records);
    a_bytes.extend(torn_next(&env, &attestation(&records[0])));
    seed(log, &a(), a_bytes);
    seed(log, &b(), log_bytes(&envelope(&b(), 0x0B), &[]));
    seed_marker(log, &RunMarker::Clean);
}

/// How the sweep's scenario ended.
#[derive(Debug, PartialEq, Eq)]
enum SweepEnd {
    Refused(StartRefused),
    Ran(RunEnd, Result<Initialised, InitialiseError>),
}

/// Run the sweep's scenario under `faults`: its log, its end, and the
/// trace as it stood at the end, before any check reads the log.
fn sweep_once(faults: LogFaults) -> (Arc<SimDecisionLog>, SweepEnd, String) {
    let sim = Sim::new();
    let log = sim_log(&sim, faults);
    plant_sweep(&log);
    let end = match start_on(&log, boot(1), &[a(), b(), c()]) {
        Err(refused) => SweepEnd::Refused(refused),
        Ok((handle, driver)) => {
            let (end, answer) = run_beside(0, driver, async move {
                let answer = handle.initialise(&c()).await;
                handle.stop().await;
                answer
            });
            SweepEnd::Ran(end, answer)
        }
    };
    (log, end, sim.trace().render())
}

/// The seam call a `log-call` line names.
fn call_of(line: &str) -> Option<&str> {
    line.split("call=").nth(1)?.split_whitespace().next()
}

/// The seam calls of `trace`'s `log-call` lines, in order, each with
/// whether it failed.
fn log_calls(trace: &str) -> Vec<(String, bool)> {
    trace
        .lines()
        .filter(|line| line.contains("log-call"))
        .filter_map(|line| Some((call_of(line)?.to_owned(), line.contains("-> failed("))))
        .collect()
}

/// A failure injected at every step of the scenario, one at a time.
/// Wherever it lands the fake records no violation. A failure inside a
/// mutating call fences, and no mutating call follows it (clean
/// included); a failed read or temporary removal refuses or answers
/// without fencing, and that unfenced end writes clean.
#[test]
fn every_injected_failure_fences_or_refuses_and_nothing_follows_a_fence() {
    let (dry_log, dry_end, _) = sweep_once(LogFaults::none());
    // A's open entry re-issues over a store that fails everything; each
    // delay draws on the jitter seam, and C's epoch on the
    // cryptographic-randomness seam beside it.
    assert!(
        matches!(
            dry_end,
            SweepEnd::Ran(RunEnd::Stopped, Ok(Initialised::Created { .. }))
        ),
        "{dry_end:?}"
    );
    let steps = dry_log.steps();
    let mutating = [
        "write-marker",
        "initialise",
        "complete-namespace",
        "append",
        "truncate",
        "resync",
    ];
    let (mut fenced, mut refused) = (0, 0);
    for at in 0..steps {
        let (log, end, trace) = sweep_once(LogFaults::just(LogFault::FailSync { at }));
        assert_eq!(log.violations(), [], "step {at}: {end:?}");
        let is_fenced = matches!(
            end,
            SweepEnd::Refused(StartRefused::Fenced(_)) | SweepEnd::Ran(RunEnd::Fenced(_), _)
        );
        let calls = log_calls(&trace);
        let failed = calls
            .iter()
            .position(|(_, failed)| *failed)
            .unwrap_or_else(|| panic!("step {at}: no call failed: {end:?}"));
        let call = calls[failed].0.as_str();
        if mutating.contains(&call) {
            assert!(
                is_fenced,
                "step {at}: {call} failed and did not fence: {end:?}"
            );
            let after: Vec<&str> = calls[failed + 1..]
                .iter()
                .map(|(call, _)| call.as_str())
                .filter(|call| mutating.contains(call))
                .collect();
            assert_eq!(after, Vec::<&str>::new(), "step {at}: {call} fenced");
            fenced += 1;
        } else {
            assert!(!is_fenced, "step {at}: a failed {call} fenced: {end:?}");
            assert_eq!(marker_says(&log), Some(RunMarker::Clean), "step {at}");
            refused += 1;
        }
    }
    assert!(
        fenced > 10 && refused > 2,
        "fenced {fenced}, refused {refused}"
    );
}

/// Exercise the real engine admission after a successful operator repair.
pub(crate) fn assert_operator_start_admitted(log: SimDecisionLog) {
    let log = Arc::new(log);
    let parts = parts(&log, 1);
    let (handle, driver) = block(async move { start(parts, boot(3), Vec::new()).await }).unwrap();
    let (end, _) = run_beside(0, driver, async move { handle.stop().await });
    assert_eq!(end, RunEnd::Stopped);
    assert!(log.violations().is_empty(), "{:?}", log.violations());
}
