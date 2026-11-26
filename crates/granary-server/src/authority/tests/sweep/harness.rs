// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The sweep's harness: the kill, the timeline, and the log and store the
//! engine runs over.
//!
//! **The kill gates every seam, not only the tasks.** The driver's one
//! `run()` future polls every worker in one poll, so a check made only
//! when a task is polled would let a second worker act after the first
//! tripped the kill inside that same poll. [`SweepLog`] and
//! [`SweepStore`] check the kill when a call begins and at every poll of
//! the call beneath: once it is set, no call begins or completes, and
//! nothing more lands on the timeline. A worker can still compute in
//! memory and hand a reply to a channel whose receiver dies unread; the
//! reply hook records nothing once the kill is set.

use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use granary_core::authlog::{
    Append, Classified, EncodedEnvelope, Envelope, Epoch, Record, classify,
};
use granary_core::decisionlog::{DecisionLog, LogIoError, MarkerRead};
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError};
use granary_core::runmarker::EncodedMarker;
use granary_sim::decision_log::SimDecisionLog;
use granary_sim::fakes::{Admin, SimStore};

use super::super::{Observer, Reply};

// ------------------------------------------------------------- the kill

/// One process's death: set once, and every task and seam call of the
/// process stops at its next poll.
#[derive(Debug, Default)]
pub(super) struct Kill {
    dead: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

impl Kill {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(super) fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// Kill the process and wake every task, so each ends at its next
    /// poll and the scheduler never stalls.
    pub(super) fn trip(&self) {
        if !self.dead.swap(true, Ordering::SeqCst) {
            for waker in std::mem::take(&mut *self.wakers.lock().unwrap()) {
                waker.wake();
            }
        }
    }

    fn register(&self, waker: &Waker) {
        let mut wakers = self.wakers.lock().unwrap();
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }
}

/// A task of a process: it ends with `None` at its first poll after the
/// kill, dropping what it was doing, as a killed process's thread does.
pub(super) struct Mortal<F> {
    kill: Arc<Kill>,
    inner: Pin<Box<F>>,
}

impl<F> Mortal<F> {
    pub(super) fn new(kill: &Arc<Kill>, inner: F) -> Self {
        Self {
            kill: Arc::clone(kill),
            inner: Box::pin(inner),
        }
    }
}

impl<F: Future> Future for Mortal<F> {
    type Output = Option<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.kill.is_dead() {
            return Poll::Ready(None);
        }
        self.kill.register(cx.waker());
        self.inner.as_mut().poll(cx).map(Some)
    }
}

/// Pend for ever, having done nothing: a call of a dead process.
async fn dead<T>() -> T {
    std::future::pending().await
}

// --------------------------------------------------------- the timeline

/// What a seam call or a reply looked like on the timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Ev {
    /// A process began.
    Start,
    /// A mutating log call began.
    Begin {
        call: &'static str,
        volume: Option<VolumeName>,
    },
    /// A mutating log call returned.
    End {
        call: &'static str,
        volume: Option<VolumeName>,
        ok: bool,
    },
    /// An append began: its record, and the byte offset it is written at.
    Appending {
        volume: VolumeName,
        record: Record,
        offset: u64,
    },
    /// An append returned `Ok`: the record is acknowledged.
    Acked { volume: VolumeName, record: Record },
    /// A log was read whole: its envelope's epoch and its committed
    /// records, and how many bytes follow them; or it was absent
    /// (`epoch` `None`, no records).
    Read {
        volume: VolumeName,
        epoch: Option<Epoch>,
        records: Vec<Record>,
        tail: u64,
    },
    /// `initialise` returned `Ok` with this envelope's epoch.
    Initialised { volume: VolumeName, epoch: Epoch },
    /// A `put_root` was issued.
    Put {
        volume: String,
        seq: u64,
        id: GrainId,
    },
    /// A `get_root` returned: the id it read, nothing, or an error.
    Got {
        volume: String,
        seq: u64,
        found: Found,
    },
    /// An epoch-mismatch probe is about to be submitted.
    EpochProbe { volume: VolumeName },
    /// A worker sent a reply.
    Emit { volume: VolumeName, reply: Reply },
    /// A store cut fired at this operation of the process.
    Cut { index: u32, cut: Cut },
    /// The kill tripped.
    Killed,
    /// The engine appended bytes that do not decode as the log's next
    /// record.
    Undecodable { volume: VolumeName },
}

/// What a `get_root` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Found {
    Id(GrainId),
    Nothing,
    Failed,
}

/// Every event of a run, in order, each with the process it belongs to.
#[derive(Debug, Default)]
pub(super) struct Timeline {
    events: Mutex<Vec<(u32, Ev)>>,
    process: AtomicU32,
}

impl Timeline {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Begin process `process`.
    pub(super) fn start(&self, process: u32) {
        self.process.store(process, Ordering::SeqCst);
        self.push(Ev::Start);
    }

    pub(super) fn push(&self, ev: Ev) {
        let process = self.process.load(Ordering::SeqCst);
        self.events.lock().unwrap().push((process, ev));
    }

    pub(super) fn events(&self) -> Vec<(u32, Ev)> {
        self.events.lock().unwrap().clone()
    }
}

/// The reply hook's observer for one process: records every reply until
/// the kill.
pub(super) fn observer(kill: &Arc<Kill>, timeline: &Arc<Timeline>) -> Observer {
    let kill = Arc::clone(kill);
    let timeline = Arc::clone(timeline);
    Arc::new(move |volume, reply| {
        if !kill.is_dead() {
            timeline.push(Ev::Emit {
                volume: volume.clone(),
                reply,
            });
        }
    })
}

// -------------------------------------------------------------- the log

/// The log the engine runs over: the fake, gated by the kill, stamping
/// every mutating call on the timeline. A call that finds the fake
/// crashed when it returns trips the kill and never returns: the engine
/// computes nothing on the crash's error.
#[derive(Debug, Clone)]
pub(super) struct SweepLog {
    pub(super) log: Arc<SimDecisionLog>,
    kill: Arc<Kill>,
    timeline: Arc<Timeline>,
    /// Each log as this process knows it: its envelope, its committed
    /// records, and its current length. An append's record is decoded as
    /// the next record after them, and lands at that length.
    logs: Arc<Mutex<BTreeMap<VolumeName, Known>>>,
}

/// One log as a process knows it: the bytes of its envelope and its
/// committed records, with how many records they hold and the file's
/// current length.
#[derive(Debug, Clone)]
struct Known {
    committed: Vec<u8>,
    records: usize,
    len: u64,
}

impl Known {
    /// A log whose committed bytes are `committed`, holding `records`
    /// records, `len` bytes long.
    const fn new(committed: Vec<u8>, records: usize, len: u64) -> Self {
        Self {
            committed,
            records,
            len,
        }
    }

    /// The log after a truncation to `len`: the committed bytes cut to
    /// it, and their records counted again.
    fn truncate(&mut self, volume: &VolumeName, len: u64) {
        self.len = len;
        let keep = usize::try_from(len).unwrap_or(usize::MAX);
        if keep < self.committed.len() {
            self.committed.truncate(keep);
            self.records = match classify(&self.committed, volume) {
                Ok(Classified::Log { records, .. }) => records.len(),
                _ => 0,
            };
        }
    }
}

impl SweepLog {
    pub(super) fn new(
        log: &Arc<SimDecisionLog>,
        kill: &Arc<Kill>,
        timeline: &Arc<Timeline>,
    ) -> Self {
        Self {
            log: Arc::clone(log),
            kill: Arc::clone(kill),
            timeline: Arc::clone(timeline),
            logs: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Await `fut` unless the process is dead; if the fake crashed while
    /// it ran, kill the process and never return.
    async fn gated<T>(&self, fut: impl Future<Output = T>) -> T {
        if self.kill.is_dead() {
            return dead().await;
        }
        let mut fut = pin!(fut);
        let out = poll_fn(|cx| {
            if self.kill.is_dead() {
                return Poll::Pending;
            }
            fut.as_mut().poll(cx)
        })
        .await;
        if self.log.crashed() {
            self.kill.trip();
            self.timeline.push(Ev::Killed);
            return dead().await;
        }
        out
    }

    /// A mutating call: stamped when it begins and when it returns.
    async fn mutating<T>(
        &self,
        call: &'static str,
        volume: Option<&VolumeName>,
        fut: impl Future<Output = Result<T, LogIoError>>,
    ) -> Result<T, LogIoError> {
        if self.kill.is_dead() {
            return dead().await;
        }
        self.timeline.push(Ev::Begin {
            call,
            volume: volume.cloned(),
        });
        let out = self.gated(fut).await;
        self.timeline.push(Ev::End {
            call,
            volume: volume.cloned(),
            ok: out.is_ok(),
        });
        out
    }

    /// Decode `append`'s record as the next record of the log `known`
    /// describes: the codec has no decoder for a record alone, so it is
    /// classified after the records the log already commits.
    fn record_of(known: &Known, append: &Append) -> Option<Record> {
        let mut bytes = known.committed.clone();
        bytes.extend_from_slice(append.record());
        bytes.extend_from_slice(append.mark());
        match classify(&bytes, append.volume()) {
            Ok(Classified::Log { mut records, .. }) if records.len() == known.records + 1 => {
                records.pop()
            }
            _ => None,
        }
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap()
}

impl DecisionLog for SweepLog {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        self.gated(self.log.read_marker()).await
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        self.mutating("write-marker", None, self.log.write_marker(marker))
            .await
    }

    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        let out = self.gated(self.log.read(volume)).await;
        match &out {
            Ok(Some(bytes)) => {
                if let Ok(Classified::Log {
                    envelope,
                    records,
                    committed_len,
                    tail_len,
                }) = classify(bytes, volume)
                {
                    self.logs.lock().unwrap().insert(
                        volume.clone(),
                        Known::new(
                            bytes[..committed_len].to_vec(),
                            records.len(),
                            len_u64(bytes.len()),
                        ),
                    );
                    self.timeline.push(Ev::Read {
                        volume: volume.clone(),
                        epoch: Some(envelope.epoch()),
                        records,
                        tail: len_u64(tail_len),
                    });
                }
            }
            Ok(None) => self.timeline.push(Ev::Read {
                volume: volume.clone(),
                epoch: None,
                records: Vec::new(),
                tail: 0,
            }),
            Err(_) => {}
        }
        out
    }

    async fn remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        self.mutating(
            "remove-temporary",
            Some(volume),
            self.log.remove_temporary(volume),
        )
        .await
    }

    async fn initialise(&self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        let parsed = envelope_of(envelope);
        let volume = parsed.volume().clone();
        let out = self
            .mutating("initialise", Some(&volume), self.log.initialise(envelope))
            .await;
        if out.is_ok() {
            self.logs.lock().unwrap().insert(
                volume.clone(),
                Known::new(
                    envelope.as_bytes().to_vec(),
                    0,
                    len_u64(envelope.as_bytes().len()),
                ),
            );
            self.timeline.push(Ev::Initialised {
                volume,
                epoch: parsed.epoch(),
            });
        }
        out
    }

    async fn complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.mutating(
            "complete-namespace",
            Some(volume),
            self.log.complete_namespace(volume),
        )
        .await
    }

    async fn append(&self, append: &Append) -> Result<(), LogIoError> {
        if self.kill.is_dead() {
            return dead().await;
        }
        let volume = append.volume().clone();
        let known = self
            .logs
            .lock()
            .unwrap()
            .get(&volume)
            .cloned()
            .expect("an append to a log this process has read or created");
        let Some(record) = Self::record_of(&known, append) else {
            self.timeline.push(Ev::Undecodable {
                volume: volume.clone(),
            });
            let out = self
                .mutating("append", Some(&volume), self.log.append(append))
                .await;
            // Its bytes are in the file whatever they are: later appends
            // land after them, and decode no better than they do.
            if let Some(known) = self.logs.lock().unwrap().get_mut(&volume) {
                known.len += len_u64(append.record().len() + append.mark().len());
                known.committed.extend_from_slice(append.record());
                known.committed.extend_from_slice(append.mark());
                known.records += 1;
            }
            return out;
        };
        let offset = known.len;
        self.timeline.push(Ev::Appending {
            volume: volume.clone(),
            record: record.clone(),
            offset,
        });
        let out = self
            .mutating("append", Some(&volume), self.log.append(append))
            .await;
        // A failed append's bytes may be in the file too: the next
        // record is decoded after it either way.
        let grown = len_u64(append.record().len() + append.mark().len());
        if let Some(known) = self.logs.lock().unwrap().get_mut(&volume) {
            known.len += grown;
            known.committed.extend_from_slice(append.record());
            known.committed.extend_from_slice(append.mark());
            known.records += 1;
        }
        if out.is_ok() {
            self.timeline.push(Ev::Acked { volume, record });
        }
        out
    }

    async fn truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        let out = self
            .mutating("truncate", Some(volume), self.log.truncate(volume, len))
            .await;
        if out.is_ok()
            && let Some(known) = self.logs.lock().unwrap().get_mut(volume)
        {
            known.truncate(volume, len);
        }
        out
    }

    async fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.mutating("resync", Some(volume), self.log.resync(volume))
            .await
    }
}

/// The envelope an encoded envelope holds.
fn envelope_of(encoded: &EncodedEnvelope) -> Envelope {
    match classify(encoded.as_bytes(), encoded.volume()) {
        Ok(Classified::Log { envelope, .. }) => envelope,
        other => panic!("an encoded envelope does not classify: {other:?}"),
    }
}

// ------------------------------------------------------------ the store

/// Where a crash at a store operation falls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Cut {
    /// Before the request leaves: nothing applies.
    Before,
    /// After the store applied it: its response is lost.
    After,
}

/// The out-of-band actions the sweep's world takes at a store operation,
/// each once per run: a foreign writer winning a seq, a squatter, an
/// operator deleting a root between a PUT and its read.
#[derive(Debug, Default)]
pub(super) struct Hooks {
    /// `(volume, seq, bytes)` planted before the first `put_root` there.
    pub(super) plant_before_put: Vec<(String, u64, Vec<u8>, bool)>,
    /// `(volume, seq)` deleted after the first successful `put_root`
    /// there.
    pub(super) delete_after_put: Vec<(String, u64, bool)>,
}

/// A store operation's identity, as claimed at its index: what a
/// labelled point id names at a store index (`sweep.rs`'s discovery), and
/// what [`SweepStore::claims`] records for every operation the engine
/// issues, not only a `put_root`. The volume is one of [`super::VOLUMES`],
/// matched once so the identity stays `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum StoreOp {
    Put { volume: &'static str, seq: u64 },
    Get { volume: &'static str, seq: u64 },
    ReadHint { volume: &'static str },
    WriteHint { volume: &'static str, seq: u64 },
    MaxSeq { volume: &'static str },
}

impl fmt::Display for StoreOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put { volume, seq } => write!(f, "put:{volume}:{seq}"),
            Self::Get { volume, seq } => write!(f, "get:{volume}:{seq}"),
            Self::ReadHint { volume } => write!(f, "read-hint:{volume}"),
            Self::WriteHint { volume, seq } => write!(f, "write-hint:{volume}:{seq}"),
            Self::MaxSeq { volume } => write!(f, "max-seq:{volume}"),
        }
    }
}

impl StoreOp {
    /// The operation `Self`'s [`Display`] names, or `None`: the inverse.
    pub(super) fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split(':');
        let kind = parts.next()?;
        let volume = tag(parts.next()?);
        let op = match kind {
            "put" => Self::Put {
                volume,
                seq: parts.next()?.parse().ok()?,
            },
            "get" => Self::Get {
                volume,
                seq: parts.next()?.parse().ok()?,
            },
            "read-hint" => Self::ReadHint { volume },
            "write-hint" => Self::WriteHint {
                volume,
                seq: parts.next()?.parse().ok()?,
            },
            "max-seq" => Self::MaxSeq { volume },
            _ => return None,
        };
        parts.next().is_none().then_some(op)
    }
}

/// `volume`'s own entry of [`super::VOLUMES`]: a label's copy of a
/// volume's name, matched once so it stays `Copy`.
pub(super) fn tag(volume: &str) -> &'static str {
    super::VOLUMES
        .into_iter()
        .find(|v| *v == volume)
        .unwrap_or("?")
}

/// A store operation as its index and its identity: what a store index's
/// label names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OpClaim {
    /// The operation index: the one a cut or a simulator fault names.
    pub(super) index: u32,
    pub(super) op: StoreOp,
}

/// The store the engine runs over: the simulator's, gated by the kill,
/// stamping every PUT and read on the timeline, with the run's hooks and
/// an optional crash at one of its operations.
///
/// **An operation's index is claimed when it begins, and the simulator's
/// trace records it when it returns**, so two workers' calls in flight at
/// once can appear in the trace out of index order. An index's identity
/// is therefore read from [`Self::claims`], never from an operation's
/// position among the trace's store operations. The index here is the
/// simulator node's too: the node claims its own on the first poll of the
/// call beneath, with no suspension between the two claims.
#[derive(Debug)]
pub(super) struct SweepStore {
    inner: SimStore,
    admin: Admin,
    kill: Arc<Kill>,
    timeline: Arc<Timeline>,
    hooks: Arc<Mutex<Hooks>>,
    cut: Option<(u32, Cut)>,
    ops: Arc<AtomicU32>,
    claims: Arc<Mutex<Vec<OpClaim>>>,
}

impl SweepStore {
    pub(super) fn new(
        inner: SimStore,
        admin: Admin,
        kill: &Arc<Kill>,
        timeline: &Arc<Timeline>,
        hooks: &Arc<Mutex<Hooks>>,
        cut: Option<(u32, Cut)>,
    ) -> Self {
        Self {
            inner,
            admin,
            kill: Arc::clone(kill),
            timeline: Arc::clone(timeline),
            hooks: Arc::clone(hooks),
            cut,
            ops: Arc::new(AtomicU32::new(0)),
            claims: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Every operation this store began, in index order with its
    /// identity, readable after the store has moved into the engine.
    pub(super) fn claims(&self) -> Arc<Mutex<Vec<OpClaim>>> {
        Arc::clone(&self.claims)
    }

    /// The count of operations the engine issues through this store,
    /// readable after the store has moved into the engine.
    pub(super) fn counter(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.ops)
    }

    /// Run one store operation under the kill and the cut, recording its
    /// identity at the index it claims.
    async fn op_as<T>(&self, op: StoreOp, fut: impl Future<Output = T>) -> T {
        if self.kill.is_dead() {
            return dead().await;
        }
        let index = self.ops.fetch_add(1, Ordering::SeqCst);
        self.claims.lock().unwrap().push(OpClaim { index, op });
        if self.cut == Some((index, Cut::Before)) {
            self.timeline.push(Ev::Cut {
                index,
                cut: Cut::Before,
            });
            self.kill.trip();
            self.timeline.push(Ev::Killed);
            return dead().await;
        }
        let mut fut = pin!(fut);
        let out = poll_fn(|cx| {
            if self.kill.is_dead() {
                return Poll::Pending;
            }
            fut.as_mut().poll(cx)
        })
        .await;
        if self.cut == Some((index, Cut::After)) {
            self.timeline.push(Ev::Cut {
                index,
                cut: Cut::After,
            });
            self.kill.trip();
            self.timeline.push(Ev::Killed);
            return dead().await;
        }
        out
    }
}

impl RootStore for SweepStore {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        if self.kill.is_dead() {
            return dead().await;
        }
        let id = GrainId::of(&bytes);
        let vol = super::vol(volume);
        let plant = {
            let mut hooks = self.hooks.lock().unwrap();
            hooks
                .plant_before_put
                .iter_mut()
                .find(|(v, s, _, fired)| v == volume && *s == seq && !fired)
                .map(|(_, _, planted, fired)| {
                    *fired = true;
                    planted.clone()
                })
        };
        if let Some(planted) = plant {
            let _ = self.admin.plant_root(&vol, seq, planted);
        }
        self.timeline.push(Ev::Put {
            volume: volume.to_owned(),
            seq,
            id,
        });
        let out = self
            .op_as(
                StoreOp::Put {
                    volume: tag(volume),
                    seq,
                },
                self.inner.put_root(volume, seq, bytes),
            )
            .await;
        if out.is_ok() {
            let delete = {
                let mut hooks = self.hooks.lock().unwrap();
                hooks
                    .delete_after_put
                    .iter_mut()
                    .find(|(v, s, fired)| v == volume && *s == seq && !fired)
                    .map(|(_, _, fired)| *fired = true)
                    .is_some()
            };
            if delete {
                let _ = self.admin.delete_root(&vol, seq);
            }
        }
        out
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        let out = self
            .op_as(
                StoreOp::Get {
                    volume: tag(volume),
                    seq,
                },
                self.inner.get_root(volume, seq),
            )
            .await;
        self.timeline.push(Ev::Got {
            volume: volume.to_owned(),
            seq,
            found: match &out {
                Ok(Some(bytes)) => Found::Id(GrainId::of(bytes)),
                Ok(None) => Found::Nothing,
                Err(_) => Found::Failed,
            },
        });
        out
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        self.op_as(
            StoreOp::ReadHint {
                volume: tag(volume),
            },
            self.inner.read_hint(volume, cached),
        )
        .await
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        self.op_as(
            StoreOp::WriteHint {
                volume: tag(volume),
                seq,
            },
            self.inner.write_hint(volume, seq),
        )
        .await
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.op_as(
            StoreOp::MaxSeq {
                volume: tag(volume),
            },
            self.inner.max_seq(volume),
        )
        .await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.op_as(
            StoreOp::MaxSeq {
                volume: tag(volume),
            },
            self.inner.max_seq_above(volume, floor),
        )
        .await
    }
}
