// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The simulated world: one type implementing `RootStore`, `BinStore` and
//! `GrainSource` over `BTreeMap`s, std only — no filesystem, no `object_store`,
//! no network — plus the fault schedule the scenarios inject through it.
//!
//! # What every operation does, and why each part is load-bearing
//!
//! 1. **It appends to the trace.** The artifact is the sim's own
//!    ([`crate::trace`]), and the fakes are the only things that write to
//!    it: a store operation nothing recorded is a step of the run that
//!    the cross-process replay check cannot see.
//! 2. **It suspends exactly once**, on [`yield_once`]. This is a genuine
//!    await point, and it is not optional: granary-core's own in-crate
//!    fakes are `ready`-shaped, to the point that their shared test
//!    harness asserts `the fake future never pends` — and a fake that
//!    never pends makes interleaving impossible however the scheduler is
//!    written, because the first publisher polled runs to completion
//!    before the second is polled at all. That is the exact degeneracy
//!    that made the original concurrency scenario vacuous.
//! 3. **It consults the fault schedule** ([`Faults`]).
//! 4. **It validates the volume name.** `checked_volume` is a CONTRACT
//!    obligation on every implementation of these traits, not the
//!    production adapter's private business: a fake that skips DNS-1123
//!    validation accepts names production refuses, and a scenario that
//!    passes here against a store that would have rejected its volume
//!    proves nothing.
//!
//! **The local seam is the one exception to (2), by construction.**
//! [`GrainSource`] is SYNCHRONOUS — the local store is a filesystem and
//! `Store::get`/`Store::has` are sync, so the trait has no future to
//! suspend. Its two operations still trace and still stop at a crash;
//! they simply have no await point to offer, and they need none: the
//! interleaving the scheduler explores is over REMOTE operations, which
//! are the ones two publishers contend on.
//!
//! # The conformance closure
//!
//! [`SimStore`] passes `granary_core::testkit::binstore_conformance` AND
//! `granary_core::testkit::rootstore_conformance` with faults disabled,
//! and that is a structural property rather than a courtesy. The same
//! two suite bodies run against granary-core's in-crate fakes, against
//! the production granary-store adapter, and here. A rule that holds in
//! the sim's fake and not in production — or the reverse — cannot pass
//! all three sites. The fault schedule is layered ON TOP of a conforming
//! base, never in place of one, which is why the conformance runs
//! disable it rather than tolerating it.
//!
//! The `RootStore` half carries more weight than the `BinStore` half:
//! every CAS scenario — the crash sweep, re-run convergence, concurrent
//! publishers, the ambiguous PUT whose probe fails — is a
//! `put_root`/`get_root`/`max_seq` property, so a `RootStore` that
//! diverged would make those scenarios prove something about this fake.
//!
//! # The fault set, and what is deliberately absent
//!
//! [`Fault::Fail`] (the operation errors), [`Fault::LandButReportFailure`]
//! (the state change APPLIES and the caller sees an error anyway),
//! [`Fault::FailProbe`] (the `get_root` probe that follows a failed
//! `put_root` fails too), [`Fault::CrashAt`] (the publish stops dead),
//! [`Fault::FailFrom`] (the remote stops answering and stays down), and
//! [`Fault::DeferPut`] (the caller is told a `put_root` failed while the
//! write is held and lands LATER, after the caller gave up).
//! Two exclusions are as deliberate as the inclusions:
//!
//! - **Delay and reorder are the SCHEDULER's job, not a timer's.** There
//!   are no timers here and no clock. Two publishers observe each other
//!   in a different order because [`crate::sched::Scheduler`] polled them
//!   in a different order, which is seed-driven and replayable; a timer
//!   would make replay depend on tokio's timer ordering, which is the
//!   dependency this design removes. [`Fault::DeferPut`] keeps to this:
//!   its release point is a count of later store operations, so where
//!   it lands is a function of the fault schedule and the seed alone.
//! - **No torn writes.** A single-shot PUT is atomic per object, so an
//!   object is never half-written. The authority is S3's consistency
//!   model — "if you receive a success response, Amazon S3 added the
//!   entire object", single-key updates atomic including overwrites —
//!   together with `object_store` 0.14.1's own `put_opts` contract.
//!   **`MinIO` documents no such guarantee.** It is true in its source
//!   (temp write, commit by one `rename(2)`), but that is a source claim
//!   against an unmaintained repository, so it is not something this
//!   harness gets to assume on a backend's behalf: the live backend
//!   lanes remain the authority for what a backend actually does, and a
//!   green sim is never evidence about one.
//!
//! Short transfers are a DIFFERENT class and are also absent: object
//! atomicity is not transfer completeness. A truncated GET body is the
//! client's problem, and it is defended in the layer this module
//! replaces (`read_hint`'s size gate, `parse_hint_body`'s exact parse),
//! hence out of reach from here.
//!
//! # Operation indices
//!
//! The fault indices count STORE operations — the [`RootStore`] and
//! [`BinStore`] calls — **per node**, from 0, in the order that node
//! issued them. Local reads are traced but not indexed: the crash model
//! is about the remote store, and the simulated publish path only ever
//! READS the local one. A [`Fault::DeferPut`] release and an [`Admin`]
//! call are traced but not indexed either: neither is an operation a
//! node issued at that point.
//!
//! **The count is data-dependent, so a sweep must discover it rather
//! than hard-code it.** For [`crate::scenario::ONE`], the one-file
//! fixture: a first publish is 8 operations, a dedup-only republish is
//! also 8 (5
//! of them pure reads, and the binmap is reused rather than rebuilt),
//! and a one-file delta republish is 12. All three move with the tree,
//! with the routing width, and with anything that changes how many
//! shards a rebuild touches — so a sweep written as a fixed range
//! changes MEANING rather than failing when the fixture changes.
//! [`SimStore::store_ops`] is what makes the count discoverable: run
//! once with [`Faults::none`], read the count, then sweep `0..count`.
//!
//! # Crash semantics
//!
//! [`Fault::CrashAt`] POISONS the node: the named operation applies
//! nothing, and so does every operation that node attempts afterwards.
//! Surviving state is therefore exactly what landed BEFORE the crash
//! point. The publish future still unwinds its own error path, so a
//! crash at `put_root` is followed in the trace by the refused `get_root`
//! probe — a read, which changes nothing, so the surviving state is
//! unaffected by it.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use granary_client::{
    EmitSink, HeadContext, ResolveError, ResolveOutcome, ResolveTarget, resolve_head,
};
use granary_core::binstore::BinStore;
use granary_core::clock::Clock;
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::rng::SeededRng;
use granary_core::root::{Timestamp, VolumeName};
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError, filter_above};

use crate::sched::yield_once;
use crate::trace::{Address, Op, Outcome, Trace, TraceError, Volume};

// --------------------------------------------------------------- faults

/// One injected failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The node's store operation at this index errors, and nothing it
    /// would have written lands.
    Fail(u32),
    /// The node's store operation at this index APPLIES its change and
    /// reports failure anyway — the ambiguous PUT that the ONE-PROBE
    /// RULE exists for, and the one fault no real backend produces on
    /// demand.
    ///
    /// On a READ this degenerates to [`Fault::Fail`]: a read changes no
    /// state, so there is nothing for it to land. Target a write to get
    /// the behaviour this variant is named for.
    LandButReportFailure(u32),
    /// Every `get_root` this node issues after one of its own
    /// `put_root`s failed — for ANY reason, injected or a genuine
    /// occupied seq — fails too, reporting [`INJECTED_PROBE`].
    ///
    /// That read is the PROBE: `commit`'s one read-back, the whole of
    /// the ONE-PROBE RULE. Failing it reaches the arm that returns
    /// `PublishError::ProbeUnresolved { put_error, probe_error }` —
    /// carrying BOTH the put's own error and the probe's, rather than
    /// collapsing "nothing landed" with "the probe itself failed" into
    /// one discarded message.
    ///
    /// **The message differs from [`INJECTED`] on purpose.** That arm's
    /// claim is that it carries the put's own message AND the probe's
    /// OWN message, in their own fields; with one message for both
    /// injected failures the claim is unassertable, and an arm rewritten
    /// to swap which message lands in which field passes every test in
    /// the workspace. The ARTIFACT's vocabulary is unchanged —
    /// both paths record `failed(injected)`, because trace errors use
    /// a fixed vocabulary rather than caller-visible messages — so the
    /// distinction is caller-visible only.
    ///
    /// **The scoping is the point, not an implementation detail.** A
    /// `get_root` BEFORE any `put_root` failure is the head read at the
    /// start of a publish, and failing that would stop the publish
    /// before it ever reached `commit` — so the fault would never
    /// exercise what it is named for.
    FailProbe,
    /// The node dies at this store operation: it applies nothing, and
    /// neither does anything the node attempts afterwards.
    CrashAt(u32),
    /// Every operation at or past this index is refused — the smallest
    /// expression of "the seam flips to refusing-all", the shape a
    /// server that has gone down and STAYS down leaves behind. Unlike
    /// [`Fault::CrashAt`] this never poisons the node
    /// ([`SimStore::crashed`] stays `false`): nothing here models a
    /// local process failure, only a remote that stops answering, so a
    /// LOCAL read this node already holds (the disk cache a degraded
    /// read goes through) is unaffected.
    FailFrom(u32),
    /// The node's `put_root` at index `at` is HELD: the caller is told
    /// it failed ([`INJECTED`], recorded as `failed(deferred)`), and the
    /// write lands LATER — after `release_after` further store
    /// operations, issued by any of the RUN's handles on this world, have
    /// passed (the oracle's reads are the check, not the run, and never
    /// count — [`Sim::oracle`]). It
    /// is applied immediately before the next one acts, create-only
    /// exactly like a live `put_root`, and its fate — landed, or refused
    /// because the seq was taken meanwhile — is recorded as a
    /// `release-root` entry under this node.
    ///
    /// The release point is a COUNT of operations, never a timer (see
    /// the module doc on why delay is the scheduler's job): the same
    /// seed and schedule release it at the same boundary in every run.
    /// `release_after: 0` releases it before the very next store
    /// operation acts — which, for a publish, is the ONE-PROBE RULE's
    /// read-back.
    ///
    /// A held write outlives its node: a crash or a dropped handle
    /// does not retract a request the store already has. A write whose
    /// release point the run never reaches stays held and never lands;
    /// its `put_root` entry still says `failed(deferred)`.
    ///
    /// The caller's error is [`INJECTED`] even when the seq is already
    /// occupied, never `AlreadyExists`: a deferred PUT models a caller
    /// that gave up before the store answered, and a real PUT that
    /// timed out reports a transport error whatever the store went on
    /// to decide.
    ///
    /// On any operation other than `put_root` this degenerates to
    /// [`Fault::Fail`]: only a root PUT is deferred.
    DeferPut {
        /// The node's store-operation index of the `put_root` to hold.
        at: u32,
        /// How many later store operations pass before it is released.
        release_after: u32,
    },
}

/// What an injection does at the point of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Injection {
    /// Refuse, applying nothing.
    Refuse,
    /// Apply, then refuse.
    LandThenRefuse,
    /// Refuse, and poison the node.
    Crash,
    /// Refuse, and hold a `put_root` for release after this many
    /// later store operations.
    Defer(u32),
}

impl Injection {
    /// Whether the operation is refused WITHOUT applying its write
    /// now — every injection except [`Injection::LandThenRefuse`].
    const fn refuses_before_applying(self) -> bool {
        matches!(self, Self::Refuse | Self::Crash | Self::Defer(_))
    }
}

/// A node's fault schedule.
///
/// Indexed faults are keyed by operation index, so a schedule cannot
/// name one index twice: a later [`Faults::with`] at an index already
/// spoken for REPLACES it rather than stacking, which keeps the meaning
/// of an index single-valued.
#[derive(Debug, Clone, Default)]
pub struct Faults {
    at: BTreeMap<u32, Injection>,
    fail_probe: bool,
    /// [`Fault::FailFrom`]'s threshold — `None` when never set. A
    /// standing refusal from this index on, kept apart from `at`
    /// (single-index only) rather than expressed as an unbounded run of
    /// entries in it.
    fail_from: Option<u32>,
}

impl Faults {
    /// No faults at all — the schedule a conformance run uses.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Exactly one fault.
    #[must_use]
    pub fn just(fault: Fault) -> Self {
        Self::none().with(fault)
    }

    /// This schedule plus `fault`.
    #[must_use]
    pub fn with(mut self, fault: Fault) -> Self {
        match fault {
            Fault::Fail(at) => {
                self.at.insert(at, Injection::Refuse);
            }
            Fault::LandButReportFailure(at) => {
                self.at.insert(at, Injection::LandThenRefuse);
            }
            Fault::CrashAt(at) => {
                self.at.insert(at, Injection::Crash);
            }
            Fault::DeferPut { at, release_after } => {
                self.at.insert(at, Injection::Defer(release_after));
            }
            Fault::FailProbe => self.fail_probe = true,
            Fault::FailFrom(at) => self.fail_from = Some(at),
        }
        self
    }

    /// Whether this schedule injects anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.at.is_empty() && !self.fail_probe && self.fail_from.is_none()
    }
}

// ---------------------------------------------------------------- world

/// The simulated persistent state. `BTreeMap` throughout: iteration
/// order is part of what a replay reproduces.
#[derive(Debug, Default)]
struct State {
    /// `root/{volume}/{seq}` — put-if-absent.
    roots: BTreeMap<(String, u64), Vec<u8>>,
    /// The advisory CURRENT hint: `(seq, version)`, the version standing
    /// in for the store's `ETag`.
    hints: BTreeMap<String, (u64, u64)>,
    /// Bins, addressed by digest alone — bins are global, not
    /// per-volume.
    bins: BTreeMap<[u8; DIGEST_LEN], Vec<u8>>,
    /// Meta objects, per volume.
    meta: BTreeMap<(String, GrainId), Vec<u8>>,
    /// The local object store every node reads from.
    grains: BTreeMap<GrainId, Vec<u8>>,
    /// Deferred `put_root`s not yet released, in the order they were
    /// held — a `Vec`, so two released at one boundary apply in that
    /// order on every run.
    held: Vec<HeldRoot>,
}

/// One deferred `put_root` ([`Fault::DeferPut`]), waiting for its
/// release point.
#[derive(Debug)]
struct HeldRoot {
    /// The node that issued it — the one its release is recorded under.
    node: u32,
    /// The volume — already validated, so its rendering IS the store
    /// key's volume string, and one field serves both.
    volume: Volume,
    seq: u64,
    addr: Address,
    bytes: Vec<u8>,
    /// Store operations still to pass before release; released when an
    /// operation arrives with this at zero.
    remaining: u32,
}

/// The state and the artifact, behind separate locks so that recording
/// an operation and applying it never need both at once. The decision
/// log's filesystem ([`crate::decision_log`]) is a third, separate
/// lock: no store operation touches it.
#[derive(Debug, Default)]
pub(crate) struct World {
    state: Mutex<State>,
    pub(crate) trace: Mutex<Trace>,
    pub(crate) disk: Mutex<crate::decision_log::disk::Disk>,
    /// Whether a decision-log handle on `disk` is live
    /// ([`Sim::decision_log`]: one per world).
    pub(crate) decision_log_live: AtomicBool,
}

impl World {
    /// One store operation is about to act: release every held root
    /// whose release point this is, then count this operation against
    /// the rest.
    ///
    /// Each release is applied CREATE-ONLY — a late write never
    /// overwrites — and recorded, landed or refused, BEFORE the
    /// arriving operation records its own entry, so the artifact shows
    /// the release at the boundary where it took effect.
    fn pass_store_op(&self) {
        let released: Vec<(u32, Op, Outcome)> = {
            let mut state = lock(&self.state);
            if state.held.is_empty() {
                return;
            }
            let (due, mut waiting): (Vec<HeldRoot>, Vec<HeldRoot>) =
                std::mem::take(&mut state.held)
                    .into_iter()
                    .partition(|h| h.remaining == 0);
            for h in &mut waiting {
                h.remaining = h.remaining.saturating_sub(1);
            }
            state.held = waiting;
            due.into_iter()
                .map(|h| {
                    let landed = insert_root(&mut state.roots, h.volume.as_str(), h.seq, h.bytes);
                    let op = Op::ReleaseRoot {
                        volume: h.volume,
                        seq: h.seq,
                        addr: h.addr,
                    };
                    let outcome = if landed {
                        Outcome::Ok
                    } else {
                        Outcome::Failed(TraceError::AlreadyExists)
                    };
                    (h.node, op, outcome)
                })
                .collect()
        };
        let mut trace = lock(&self.trace);
        for (node, op, outcome) in released {
            trace.record(node, op, outcome);
        }
    }
}

/// The ONE create-only root insert — a live `put_root`, a deferred
/// write's release and [`Admin::plant_root`] all go through it, so the
/// rule that roots are never overwritten has one site. `true` when the
/// root landed, `false` (and nothing written) when the seq was taken.
fn insert_root(
    roots: &mut BTreeMap<(String, u64), Vec<u8>>,
    volume: &str,
    seq: u64,
    bytes: Vec<u8>,
) -> bool {
    match roots.entry((volume.to_owned(), seq)) {
        Entry::Occupied(_) => false,
        Entry::Vacant(slot) => {
            slot.insert(bytes);
            true
        }
    }
}

/// The simulated world: the store every node shares, and the factory for
/// the per-node handles that drive it.
///
/// Cloning is cheap and shares the world — a clone is another reference
/// to the same store, never a copy of it.
#[derive(Debug, Clone, Default)]
pub struct Sim {
    pub(crate) world: Arc<World>,
}

impl Sim {
    /// The node index the oracle's own reads are recorded under.
    ///
    /// Distinct from any publisher's so a trace shows plainly which
    /// operations were the run and which were the check.
    pub const ORACLE_NODE: u32 = u32::MAX;

    /// An empty world.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A node's handle on the world.
    ///
    /// `node` names the issuer in the trace and `faults` is that node's
    /// schedule; the operation indices the schedule refers to are this
    /// handle's own, counted from 0.
    ///
    /// # Panics
    /// If `node` is [`Sim::ORACLE_NODE`] or [`Sim::ADMIN_NODE`]: those
    /// indices name the check and the operator in the artifact, and a
    /// publisher recorded under either would be indistinguishable from
    /// them. The oracle's own handle is [`Sim::oracle`].
    #[must_use]
    pub fn node(&self, node: u32, faults: Faults) -> SimStore {
        assert!(
            node != Self::ORACLE_NODE && node != Self::ADMIN_NODE,
            "sim node {node} is reserved (ORACLE_NODE = {}, ADMIN_NODE = {}); a publisher \
             must use another index, and the oracle's handle is Sim::oracle()",
            Self::ORACLE_NODE,
            Self::ADMIN_NODE
        );
        self.handle(node, faults)
    }

    /// The oracle's handle: fault-free, recorded under
    /// [`Sim::ORACLE_NODE`], and NOT part of the run — its operations
    /// neither count toward a [`Fault::DeferPut`] release point nor
    /// trigger a release, so a check made mid-run cannot change when a
    /// held write lands.
    #[must_use]
    pub fn oracle(&self) -> SimStore {
        self.handle(Self::ORACLE_NODE, Faults::none())
    }

    fn handle(&self, node: u32, faults: Faults) -> SimStore {
        SimStore {
            world: Arc::clone(&self.world),
            node,
            faults,
            ops: AtomicU32::new(0),
            crashed: AtomicBool::new(false),
            put_root_failed: AtomicBool::new(false),
        }
    }

    /// Seed the local store with an object, under its own id.
    ///
    /// The local store is CONTENT-ADDRESSED and shared by every node,
    /// which loses nothing: an id names the same bytes wherever it is
    /// stored, so per-node local stores would differ only in which
    /// objects are absent — and the simulated publish path refuses a
    /// missing object before it uploads anything, which the local seam's
    /// own tests already cover.
    #[must_use]
    pub fn put_grain(&self, bytes: Vec<u8>) -> GrainId {
        let id = GrainId::of(&bytes);
        self.put_grain_raw(id, bytes);
        id
    }

    /// Seed the local store with bytes under an id they do NOT hash to —
    /// the only way to reach the corrupt-local-object path through a
    /// fake.
    pub fn put_grain_raw(&self, id: GrainId, bytes: Vec<u8>) {
        lock(&self.world.state).grains.insert(id, bytes);
    }

    /// Fault-free snapshot for publication invariants. Observing it neither
    /// counts store operations nor releases outstanding writes.
    pub(crate) fn root_snapshot(&self) -> BTreeMap<(String, u64), Vec<u8>> {
        lock(&self.world.state).roots.clone()
    }

    /// The run's artifact so far.
    #[must_use]
    pub fn trace(&self) -> Trace {
        lock(&self.world.trace).clone()
    }

    /// The node index the [`Admin`] handle's operations are recorded
    /// under — distinct from every publisher's and from
    /// [`Sim::ORACLE_NODE`].
    pub const ADMIN_NODE: u32 = u32::MAX - 1;

    /// The out-of-band operator handle on this world — see [`Admin`].
    #[must_use]
    pub fn admin(&self) -> Admin {
        Admin {
            world: Arc::clone(&self.world),
        }
    }

    /// Resolve `volume`'s head through the oracle, on a FAULT-FREE
    /// handle.
    ///
    /// The handle is fault-free on purpose: the oracle is the check, and
    /// a check that ran under the schedule it is checking would report
    /// "broken" for a volume that is merely unreadable through an
    /// injected failure.
    ///
    /// # Errors
    /// [`ResolveError::NoHead`] when the volume has no head — which is
    /// the expected outcome at most crash points, not a defect. Any
    /// other variant means the surviving volume is genuinely broken,
    /// EXCEPT `NoSuchTarget` and `PathBudgetExceeded`, which describe no
    /// damage. See [`ResolveError`].
    ///
    /// `sink` receives the whole tree's bytes as the fetcher walks it
    /// — a caller that only wants the outcome passes a no-op.
    pub async fn resolve_head(
        &self,
        volume: &str,
        sink: &mut EmitSink<'_>,
    ) -> Result<ResolveOutcome, ResolveError> {
        let reader = self.oracle();
        let ctx = oracle_head_context();
        resolve_head(&reader, volume, &ctx, None, ResolveTarget::WholeTree, sink).await
    }
}

/// A fixed reading for the oracle's own [`HeadContext`] — this handle
/// resolves with no cache (module doc above), so no persisted hint
/// exists to judge freshness against and the hint-freshness check
/// draws no TTL jitter on this run. The clock reading is fixed rather
/// than wall time: the sim replays from a seed, never the ambient
/// clock.
struct OracleClock;

impl Clock for OracleClock {
    fn now(&self) -> Timestamp {
        Timestamp { secs: 0, nanos: 0 }
    }
}

/// Fixed, not ambient: the oracle is a fault-free VERIFICATION
/// pass, run separately from the fault-injected schedule under study
/// (module doc above), so its own `HeadContext` needs no seed threaded
/// in from a scenario's own driver seed — it draws nothing observable,
/// since a cacheless resolve never draws head-hint TTL jitter.
const ORACLE_JITTER_SEED: u64 = 0x0AC1_E5EE_D000_0000;

pub(crate) fn oracle_head_context() -> HeadContext {
    HeadContext::new(
        Box::new(OracleClock),
        Box::new(SeededRng::new(ORACLE_JITTER_SEED)),
    )
}

/// Take a lock, recovering from poison.
///
/// A poisoned lock here means a panic already unwound while the lock was
/// held — the run is single-threaded, so there is no other way to poison
/// one — and the test that panicked is already failing. Dropping trace
/// entries or erroring out at that point would only hide the failure
/// behind a second one, so the guard is recovered rather than reported.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------ admin

/// Out-of-band access to the root namespace, OUTSIDE [`RootStore`]:
/// what an operator with direct access to the bucket can do and a
/// publisher cannot.
///
/// **Not a seam and not under the conformance suite.** `RootStore` is
/// unchanged; this is the harness reaching past it, so a scenario can
/// stage a squatter, a lost root or a recovery. Accordingly:
///
/// - **Any seq is accepted**, including 0 and `u64::MAX`, which no
///   caller of `put_root` ever produces — that is the point of planting
///   them. `max_seq` still never answers either (its own filter), so a
///   plant there is visible to [`Admin::root_seqs`] and a direct
///   `get_root`, never as a head.
/// - **No fault schedule, no suspension, no operation index.** A driver
///   calls these between or around scheduler runs, synchronously, and
///   they do not count toward a [`Fault::DeferPut`] release point: an
///   operator's action is not a store operation any node issued.
/// - **Every call is recorded** under [`Sim::ADMIN_NODE`], because a
///   change to the world the artifact cannot see is a step of the run
///   the replay check cannot see either.
///
/// The volume is a checked [`VolumeName`], so there is no refusal path:
/// a name the rules refuse cannot reach this handle at all.
#[derive(Debug, Clone)]
pub struct Admin {
    world: Arc<World>,
}

impl Admin {
    fn record(&self, op: Op, outcome: Outcome) {
        lock(&self.world.trace).record(Sim::ADMIN_NODE, op, outcome);
    }

    /// Plant `bytes` as the root at `(volume, seq)`, create-only:
    /// `false`, and nothing written, when a root is already there.
    /// Replacing a root is [`Admin::delete_root`] then this.
    #[must_use]
    pub fn plant_root(&self, volume: &VolumeName, seq: u64, bytes: Vec<u8>) -> bool {
        let addr = Address::new(*GrainId::of(&bytes).digest());
        let planted = insert_root(
            &mut lock(&self.world.state).roots,
            volume.as_str(),
            seq,
            bytes,
        );
        self.record(
            Op::AdminPlantRoot {
                volume: Volume::from_checked(volume),
                seq,
                addr,
            },
            if planted {
                Outcome::Ok
            } else {
                Outcome::Failed(TraceError::AlreadyExists)
            },
        );
        planted
    }

    /// Delete the root at `(volume, seq)`: `true` when there was one.
    #[must_use]
    pub fn delete_root(&self, volume: &VolumeName, seq: u64) -> bool {
        let deleted = lock(&self.world.state)
            .roots
            .remove(&(volume.as_str().to_owned(), seq))
            .is_some();
        self.record(
            Op::AdminDeleteRoot {
                volume: Volume::from_checked(volume),
                seq,
            },
            if deleted {
                Outcome::Ok
            } else {
                Outcome::Absent
            },
        );
        deleted
    }

    /// Every seq `volume` holds a root at, ascending — 0 and `u64::MAX`
    /// included, unlike `max_seq`. A held [`Fault::DeferPut`] write is
    /// not listed until it lands.
    #[must_use]
    pub fn root_seqs(&self, volume: &VolumeName) -> Vec<u64> {
        let seqs: Vec<u64> = lock(&self.world.state)
            .roots
            .keys()
            .filter(|(v, _)| v == volume.as_str())
            .map(|(_, s)| *s)
            .collect();
        self.record(
            Op::AdminListRoots {
                volume: Volume::from_checked(volume),
            },
            if seqs.is_empty() {
                Outcome::Absent
            } else {
                Outcome::Ok
            },
        );
        seqs
    }
}

// ------------------------------------------------------------ the store

/// One node's handle: [`RootStore`], [`BinStore`] and [`GrainSource`] in
/// one type, over the shared world, under this node's fault schedule.
#[derive(Debug)]
pub struct SimStore {
    world: Arc<World>,
    node: u32,
    faults: Faults,
    ops: AtomicU32,
    crashed: AtomicBool,
    put_root_failed: AtomicBool,
}

/// What an injected failure says.
///
/// A NAME rather than a literal because a scenario asserting WHICH
/// injected failure surfaced would otherwise compare against a magic
/// string — and a magic string in a test is how "the original error"
/// becomes a claim nothing checks.
pub const INJECTED: &str = "injected fault";

/// What an injected PROBE failure says — [`Fault::FailProbe`]'s
/// `get_root`, and deliberately NOT [`INJECTED`].
///
/// `commit`'s collapsing arm promises the original `put_root` error; two
/// distinct messages are what make that promise falsifiable.
pub const INJECTED_PROBE: &str = "injected probe fault";

/// The error an injected fault reports.
///
/// `Backend` rather than a dedicated variant because that is what the
/// seam's own vocabulary has: a caller cannot tell an injected failure
/// from a real transport failure, which is the point — the publish flow
/// must handle it as the transport failure it is impersonating.
fn injected() -> RootStoreError {
    RootStoreError::Backend(INJECTED.to_owned())
}

/// The error an injected PROBE failure reports — see [`INJECTED_PROBE`]
/// for why it is not [`injected`].
fn injected_probe() -> RootStoreError {
    RootStoreError::Backend(INJECTED_PROBE.to_owned())
}

impl SimStore {
    /// How many store operations this node has issued.
    ///
    /// The way a sweep discovers its own range: run once with
    /// [`Faults::none`], read this, then sweep `0..count`. Writing the
    /// range as a literal instead makes the sweep silently change
    /// meaning when the fixture changes.
    #[must_use]
    pub fn store_ops(&self) -> u32 {
        self.ops.load(Ordering::Relaxed)
    }

    /// Which node this handle is.
    ///
    /// The issuer field of every entry this handle records, and — under
    /// [`crate::scenario`] — the seed of this node's writer identity, so
    /// that a driver cannot pair one node's operations with another
    /// node's identity.
    #[must_use]
    pub fn node(&self) -> u32 {
        self.node
    }

    /// Whether the schedule has crashed this node.
    #[must_use]
    pub fn crashed(&self) -> bool {
        self.crashed.load(Ordering::Relaxed)
    }

    /// This operation is about to act: let the world release what is
    /// due and count it — unless this is the oracle, which is the check
    /// and not the run ([`Sim::oracle`]).
    fn pass_store_op(&self) {
        if self.node != Sim::ORACLE_NODE {
            self.world.pass_store_op();
        }
    }

    /// Claim this node's next store-operation index.
    fn next_op(&self) -> u32 {
        self.ops.fetch_add(1, Ordering::Relaxed)
    }

    /// Record one operation in the artifact.
    fn record(&self, op: Op, outcome: Outcome) {
        lock(&self.world.trace).record(self.node, op, outcome);
    }

    /// What the schedule says about this node's operation `idx`.
    ///
    /// `None` is the ordinary path. A crashed node answers
    /// [`Injection::Refuse`] to everything, which is what makes the
    /// crash total rather than a single failed call. The exact-index
    /// schedule (`at`) is consulted before [`Fault::FailFrom`]'s
    /// threshold, so a `with` naming one index twice keeps its documented
    /// REPLACE semantics even when a `FailFrom` also covers that index.
    fn verdict(&self, idx: u32) -> Option<Injection> {
        if self.crashed() {
            return Some(Injection::Refuse);
        }
        if let Some(injection) = self.faults.at.get(&idx).copied() {
            if injection == Injection::Crash {
                self.crashed.store(true, Ordering::Relaxed);
            }
            return Some(injection);
        }
        if self.faults.fail_from.is_some_and(|from| idx >= from) {
            return Some(Injection::Refuse);
        }
        None
    }

    /// Whether a `get_root` at this point is the probe the schedule was
    /// told to fail — see [`Fault::FailProbe`] on why the flag rather
    /// than every `get_root`.
    fn probe_fails(&self) -> bool {
        self.faults.fail_probe && self.put_root_failed.load(Ordering::Relaxed)
    }

    /// Validate a volume name and hand back the artifact's rendering of
    /// it; on refusal, record the attempt under the unforgeable rejected
    /// sentinel and return the error the trait's contract names.
    ///
    /// `op` builds this method's own [`Op`] so the refusal is recorded
    /// as the operation it was, rather than vanishing from the artifact.
    fn checked_volume<F: FnOnce(Volume) -> Op>(
        &self,
        name: &str,
        op: F,
    ) -> Result<Volume, RootStoreError> {
        match VolumeName::from_bytes(name.as_bytes()) {
            // The artifact's name for an already-validated name: one
            // accept-set, checked once, with no fallback whose
            // unreachability would rest on two checks agreeing.
            Ok(checked) => Ok(Volume::from_checked(&checked)),
            Err(e) => {
                self.record(
                    op(Volume::rejected()),
                    Outcome::Failed(TraceError::InvalidVolume),
                );
                Err(RootStoreError::InvalidVolume {
                    reason: e.to_string(),
                })
            }
        }
    }

    /// The state, locked.
    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.world.state)
    }
}

/// Map a seam error into the artifact's fixed vocabulary.
///
/// Free text never crosses: `Backend`'s message is the usual way an
/// absolute path or a locale-sensitive string escapes into a log.
fn traced(err: &RootStoreError) -> TraceError {
    match err {
        RootStoreError::AlreadyExists => TraceError::AlreadyExists,
        RootStoreError::NotFound => TraceError::NotFound,
        RootStoreError::RangeOverflow => TraceError::RangeOverflow,
        RootStoreError::InvalidVolume { .. } => TraceError::InvalidVolume,
        // `RefusedResponse` is a READ BOUND the granary-store adapter
        // applies to `object_store` responses, and `SimStore` cannot
        // produce one: it hands back owned `Vec`s from its own state,
        // which carry no advertised length and no stream, so there is
        // nothing for a bound to catch. `Unavailable` is likewise
        // unproduceable here: it is `granary-client`'s `HttpStore`
        // classifying a wire `503` from a granary SERVER, and `SimStore`
        // is neither that client nor anything downstream of one.
        // `Elapsed` is the same shape
        // again — `HttpStore`'s own per-seam-call deadline, cutting a
        // wedged wait on a peer that `SimStore` has no clock of any kind
        // to produce. `UnexpectedStatus` is `HttpStore`'s answer to a status
        // the wire map does not list, equally unproduceable here. All four are mapped to the catch-all rather than
        // given a word of their own — a trace vocabulary entry no
        // scenario can reach would be dead surface in the artifact.
        RootStoreError::Precondition
        | RootStoreError::Backend(_)
        | RootStoreError::RefusedResponse { .. }
        | RootStoreError::Unavailable { .. }
        | RootStoreError::Elapsed { .. }
        | RootStoreError::UnexpectedStatus { .. } => TraceError::Backend,
    }
}

impl RootStore for SimStore {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let addr = Address::new(*GrainId::of(&bytes).digest());
        let vol = self.checked_volume(volume, |volume| Op::PutRoot { volume, seq, addr })?;
        let op = Op::PutRoot {
            volume: vol.clone(),
            seq,
            addr,
        };
        let verdict = self.verdict(idx);
        if let Some(Injection::Defer(release_after)) = verdict {
            // Held, not dropped: the caller's view is a refused PUT, the
            // store's is a request still in flight. `pass_store_op`
            // lands or refuses it at its release point.
            self.put_root_failed.store(true, Ordering::Relaxed);
            self.state().held.push(HeldRoot {
                node: self.node,
                volume: vol,
                seq,
                addr,
                bytes,
                remaining: release_after,
            });
            self.record(op, Outcome::Failed(TraceError::Deferred));
            return Err(injected());
        }
        if verdict.is_some_and(Injection::refuses_before_applying) {
            // The probe rule keys off a put_root that an injection made
            // fail — including a crash, whose refused probe is the same
            // ambiguity from the caller's side.
            self.put_root_failed.store(true, Ordering::Relaxed);
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        let landed = if insert_root(&mut self.state().roots, volume, seq, bytes) {
            Ok(())
        } else {
            Err(RootStoreError::AlreadyExists)
        };
        match (landed, verdict) {
            // The one no real backend produces on demand: the root IS at
            // the seq and the caller is told the PUT failed.
            (Ok(()), Some(Injection::LandThenRefuse)) => {
                self.put_root_failed.store(true, Ordering::Relaxed);
                self.record(op, Outcome::Failed(TraceError::Injected));
                Err(injected())
            }
            (Ok(()), _) => {
                self.record(op, Outcome::Ok);
                Ok(())
            }
            // A legitimate refusal outranks the injection: nothing
            // landed, so there is nothing to lie about.
            (Err(e), _) => {
                self.put_root_failed.store(true, Ordering::Relaxed);
                self.record(op, Outcome::Failed(traced(&e)));
                Err(e)
            }
        }
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let vol = self.checked_volume(volume, |volume| Op::GetRoot { volume, seq })?;
        let op = Op::GetRoot { volume: vol, seq };
        // TWO guards rather than one disjunction, and the schedule's
        // comes FIRST: `verdict` latches a crash, so it must be consulted
        // on exactly the operations it was before. Only when the schedule
        // says nothing about this index is the failure the probe's — and
        // then it reports its own message, which is what lets a scenario
        // prove which of the two errors `commit` surfaced.
        if self.verdict(idx).is_some() {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        if self.probe_fails() {
            // The ARTIFACT does not change: `failed(injected)` on both
            // paths, because trace errors use a fixed vocabulary.
            // Only the caller-visible error differs.
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected_probe());
        }
        let found = self.state().roots.get(&(volume.to_owned(), seq)).cloned();
        self.record(
            op,
            if found.is_some() {
                Outcome::Ok
            } else {
                Outcome::Absent
            },
        );
        Ok(found)
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let vol = self.checked_volume(volume, |volume| Op::ReadHint { volume })?;
        let op = Op::ReadHint { volume: vol };
        if self.verdict(idx).is_some() {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        let hint = self.state().hints.get(volume).copied();
        let read = match hint {
            // Seq 0 names a root that cannot exist, so it is never a head.
            None | Some((0, _)) => HintRead::Missing,
            Some((seq, version)) => {
                let token = HintToken(version.to_string());
                if cached == Some(&token) {
                    HintRead::NotModified
                } else {
                    HintRead::Current { seq, token }
                }
            }
        };
        self.record(
            op,
            if matches!(read, HintRead::Missing) {
                Outcome::Absent
            } else {
                Outcome::Ok
            },
        );
        Ok(read)
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let vol = self.checked_volume(volume, |volume| Op::WriteHint { volume, seq })?;
        let op = Op::WriteHint { volume: vol, seq };
        let verdict = self.verdict(idx);
        if verdict.is_some_and(Injection::refuses_before_applying) {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        {
            let mut state = self.state();
            let next = state
                .hints
                .get(volume)
                .map_or(1, |&(_, v)| v.saturating_add(1));
            state.hints.insert(volume.to_owned(), (seq, next));
        }
        if verdict == Some(Injection::LandThenRefuse) {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        self.record(op, Outcome::Ok);
        Ok(())
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let vol = self.checked_volume(volume, |volume| Op::MaxSeq { volume })?;
        let op = Op::MaxSeq { volume: vol };
        if self.verdict(idx).is_some() {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        let max = self
            .state()
            .roots
            .keys()
            .filter(|(v, _)| v == volume)
            .map(|(_, s)| *s)
            // Seq 0 parses but can hold no root: an object planted there
            // must never become the head. Neither may the RESERVED
            // u64::MAX — selecting it would leave no higher
            // seq for the next publish, permanently.
            .filter(|&s| s != 0 && s != u64::MAX)
            .max();
        self.record(
            op,
            if max.is_some() {
                Outcome::Ok
            } else {
                Outcome::Absent
            },
        );
        Ok(max)
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

impl BinStore for SimStore {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let op = Op::PutBin {
            addr: Address::new(*digest),
        };
        let verdict = self.verdict(idx);
        if verdict.is_some_and(Injection::refuses_before_applying) {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        // Content-addressed: an occupant holds the same bytes, so a
        // second put is SUCCESS reporting not-novel, never AlreadyExists.
        let novel = self.state().bins.insert(*digest, bytes).is_none();
        if verdict == Some(Injection::LandThenRefuse) {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        self.record(
            op,
            if novel {
                Outcome::Novel
            } else {
                Outcome::Unchanged
            },
        );
        Ok(novel)
    }

    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let addr = Address::new(*id.digest());
        let vol = self.checked_volume(volume, |volume| Op::PutMeta { volume, addr })?;
        let op = Op::PutMeta { volume: vol, addr };
        let verdict = self.verdict(idx);
        if verdict.is_some_and(Injection::refuses_before_applying) {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        let novel = self
            .state()
            .meta
            .insert((volume.to_owned(), *id), bytes)
            .is_none();
        if verdict == Some(Injection::LandThenRefuse) {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        self.record(
            op,
            if novel {
                Outcome::Novel
            } else {
                Outcome::Unchanged
            },
        );
        Ok(novel)
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let addr = Address::new(*id.digest());
        let vol = self.checked_volume(volume, |volume| Op::GetMeta { volume, addr })?;
        let op = Op::GetMeta { volume: vol, addr };
        if self.verdict(idx).is_some() {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        let found = self.state().meta.get(&(volume.to_owned(), *id)).cloned();
        if let Some(bytes) = found {
            self.record(op, Outcome::Ok);
            Ok(bytes)
        } else {
            // An absent meta object is an ERROR here, not an empty
            // success: `get_meta` fetches an object a root already named.
            self.record(op, Outcome::Failed(TraceError::NotFound));
            Err(RootStoreError::NotFound)
        }
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let idx = self.next_op();
        yield_once().await;
        self.pass_store_op();
        let op = Op::GetBinRange {
            addr: Address::new(*digest),
            offset,
            len,
        };
        if self.verdict(idx).is_some() {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(injected());
        }
        let read = self.range(digest, offset, len);
        match read {
            Ok(bytes) => {
                self.record(op, Outcome::Ok);
                Ok(bytes)
            }
            Err(e) => {
                self.record(op, Outcome::Failed(traced(&e)));
                Err(e)
            }
        }
    }
}

impl SimStore {
    /// The pinned range semantic, which turns on where the range STARTS:
    /// a range beginning inside the object may overhang the end and then
    /// SHORT-READS; a range beginning at or past the end, or a
    /// zero-length range, is a backend range error. There is no
    /// empty-read success. `offset + len` is checked before any lookup,
    /// because an adversarial extent carries no upper bound.
    fn range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        offset
            .checked_add(u64::from(len))
            .ok_or(RootStoreError::RangeOverflow)?;
        let state = self.state();
        let bytes = state.bins.get(digest).ok_or(RootStoreError::NotFound)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= bytes.len() || len == 0 {
            return Err(RootStoreError::Backend("invalid range".to_owned()));
        }
        let stop = start.saturating_add(len as usize).min(bytes.len());
        Ok(bytes.get(start..stop).unwrap_or_default().to_vec())
    }
}

impl GrainSource for SimStore {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        let op = Op::GetGrain {
            addr: Address::new(*id.digest()),
        };
        if self.crashed() {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return Err(GrainSourceError::Backend(INJECTED.to_owned()));
        }
        let found = self.state().grains.get(id).cloned();
        match found {
            // Return bytes only when their hash matches the requested grain id.
            Some(bytes) if GrainId::of(&bytes) == *id => {
                self.record(op, Outcome::Ok);
                Ok(bytes)
            }
            Some(_) => {
                self.record(op, Outcome::Failed(TraceError::Corrupt));
                Err(GrainSourceError::Corrupt(*id))
            }
            None => {
                self.record(op, Outcome::Failed(TraceError::NotFound));
                Err(GrainSourceError::Missing(*id))
            }
        }
    }

    fn has(&self, id: &GrainId) -> bool {
        let op = Op::HasGrain {
            addr: Address::new(*id.digest()),
        };
        if self.crashed() {
            self.record(op, Outcome::Failed(TraceError::Injected));
            return false;
        }
        // Presence only, NOT an integrity claim.
        let present = self.state().grains.contains_key(id);
        self.record(
            op,
            if present {
                Outcome::Ok
            } else {
                Outcome::Absent
            },
        );
        present
    }
}

#[cfg(test)]
mod tests;
