// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The shared publish fixture the scenarios run on: an in-memory tree,
//! the pinned key, identity and clock, one driver, and the trace queries
//! a scenario uses to DISCOVER what a run did instead of hard-coding it.
//!
//! # Why this is in the lib rather than in `tests/`
//!
//! A `src/bin` target sees `[dependencies]` and this lib — never a test
//! target's helpers. The scenario runner binary runs ONE scenario at a
//! given seed and prints the artifact, so a fixture living in `tests/`
//! would force a second copy of the driver into the binary, and two
//! copies of a driver diverge exactly where it matters: the program the
//! cross-process replay check runs stops being the program the scenarios
//! assert on. The resolve oracle moved into granary-client's lib
//! for the same reason: the simulator and the hermetic suite must
//! run one body.
//!
//! # Everything here is pinned, and one pin has to vary
//!
//! The key, the timestamp, the volume and the trees are constants, so
//! that two runs of one scenario differ only in what the scenario itself
//! varies — a seed, a fault index. The WRITER IDENTITY is the deliberate
//! exception: it is derived from the NODE ID (the CLI's identity is
//! sixteen bytes of operating-system entropy per publication; the sim's
//! is the node id, because the CLI path is not simulated), and that is
//! load-bearing rather than bookkeeping.
//!
//! `writer_uuid`'s preimage is (timestamp, identity, seq, volume,
//! manifest root), and the uuid is a signed field of the root. So two
//! publishers that shared an identity — with this fixture's one clock,
//! one key, one volume and one tree — would mint BYTE-IDENTICAL root
//! bytes. The loser of a CAS race would then read *its own* bytes back
//! through the ONE-PROBE RULE, conclude it had won, and return success:
//! both publishers "win", and a scenario asserting "exactly one claims
//! the seq" passes with no race in it at all.
//!
//! # Discovery, not literals
//!
//! [`Published::ops`] and [`first_put_root`] exist because every
//! operation count and operation index here is DATA-DEPENDENT: this
//! fixture measures 8 store operations for a first publish and 12 for a
//! delta republish, where a different tree at a different routing width
//! measures something else entirely. A sweep written as a fixed range
//! does not fail when the fixture moves — it silently changes meaning,
//! which is worse. So a scenario runs once fault-free, reads the count
//! and the indices off that run, and sweeps what it found.

use std::collections::BTreeMap;

use granary_client::{
    HarvestStats, Policy, PublishError, PublishSummary, ResolveError, ResolveOutcome,
    ResolveTarget, commit, prepare_from_manifest, resolve_at, resolve_at_collecting, resolve_head,
    resolve_head_collecting,
};
use granary_core::hash::GrainId;
use granary_core::identity::{WRITER_IDENTITY_LEN, WriterIdentity};
use granary_core::manifest::{self, EntryKind};
use granary_core::root::{Timestamp, VolumeName};
use granary_store::crypto::SigningKey;

use crate::fakes::{Fault, Faults, Sim, SimStore, oracle_head_context};
use crate::sched::{Scheduler, Task};
use crate::trace::{Entry, Op, Outcome, Trace, TraceError};

/// The volume every scenario publishes to.
pub const VOLUME: &str = "sim-vol";

/// [`resolve_collecting`]/[`resolve_seq_collecting`]'s result: the outcome
/// alongside every `(id, bytes)` the fetcher handed the sink, in place
/// of the removed `ResolveOutcome.objects` field.
type ResolveWithObjects = Result<(ResolveOutcome, BTreeMap<GrainId, Vec<u8>>), ResolveError>;

/// The seed a single-publisher run is driven under.
///
/// One publisher has one runnable task at every step, so the schedule is
/// forced and the seed changes nothing — it is named rather than
/// inlined so a failure can print it, and so a scenario that grows a
/// second publisher cannot silently keep an arbitrary literal.
pub const DRIVER_SEED: u64 = 1;

/// The fixture's one-file tree.
pub const ONE: &[&[u8]] = &[b"a grain that never touched a disk"];

/// [`ONE`] plus a second file — a DELTA republish rather than a
/// dedup-only one.
pub const TWO: &[&[u8]] = &[
    b"a grain that never touched a disk",
    b"a second grain, appended later",
];

/// Eight one-grain files: a tree with enough mapped objects that a wide
/// routing width has something to spread across.
pub const WIDE: &[&[u8]] = &[
    b"wide grain 0",
    b"wide grain 1",
    b"wide grain 2",
    b"wide grain 3",
    b"wide grain 4",
    b"wide grain 5",
    b"wide grain 6",
    b"wide grain 7",
];

/// [`WIDE`] plus a ninth file — the one-grain delta.
///
/// The prefix must stay identical to [`WIDE`] or the "delta" is a
/// rewrite; `the_longer_fixtures_extend_the_shorter_ones` is the pin.
pub const WIDE_PLUS: &[&[u8]] = &[
    b"wide grain 0",
    b"wide grain 1",
    b"wide grain 2",
    b"wide grain 3",
    b"wide grain 4",
    b"wide grain 5",
    b"wide grain 6",
    b"wide grain 7",
    b"wide grain 8, appended later",
];

/// [`VOLUME`], checked.
///
/// # Panics
/// If [`VOLUME`] stops being a DNS-1123 label — a defect in this file.
#[must_use]
pub fn volume() -> VolumeName {
    VolumeName::new(VOLUME.to_owned())
        .unwrap_or_else(|e| panic!("{VOLUME} must be a DNS-1123 label: {e}"))
}

/// The one publishing key. Every node signs with it: the trust model is
/// self-publish, so a publisher extends only a chain it signed, and
/// two nodes on two keys could not race for the same volume at all.
///
/// # Panics
/// If the pinned seed stops being accepted key material.
#[must_use]
pub fn key() -> SigningKey {
    SigningKey::from_seed(&[9u8; 32]).unwrap_or_else(|e| panic!("a 32-byte seed: {e}"))
}

/// The writer identity derived from sim node `node`.
///
/// INJECTIVE in `node` — `identities_are_distinct_per_node` is the pin —
/// and that is the property a concurrency scenario rests on: see the
/// module doc on why two publishers must not share one.
#[must_use]
pub fn identity(node: u32) -> WriterIdentity {
    let mut bytes = *b"sim-node\0\0\0\0\0\0\0\0";
    // The tail is exactly `u32`-wide, so the write is total — and
    // `identities_are_distinct_per_node` is what proves it LANDS rather
    // than silently doing nothing and collapsing every node onto one
    // identity.
    if let Some(tail) = bytes.get_mut(WRITER_IDENTITY_LEN - 4..) {
        tail.copy_from_slice(&node.to_be_bytes());
    }
    WriterIdentity::from_bytes(bytes)
}

/// The pinned publish timestamp.
///
/// A constant, not a clock read: it enters `writer_uuid`'s preimage and
/// the sheaf, so a wall-clock value here would make a re-run mint
/// different root bytes and destroy the convergence property scenario 2
/// asserts.
#[must_use]
pub const fn now() -> Timestamp {
    Timestamp {
        secs: 1_760_000_000,
        nanos: 0,
    }
}

/// Build a flat manifest tree of one-grain files in the sim's local
/// store — no harvest, no filesystem — and return its manifest root.
///
/// Names are `f0`, `f1`, … in the canonical order a leaf requires, so a
/// longer `files` list is a strict extension of a shorter one: the
/// shared prefix's grains and names are unchanged, which is what makes
/// the difference a DELTA.
///
/// # Panics
/// If the fixture cannot be encoded — a defect in this file rather than
/// a property of a run.
#[must_use]
pub fn seed_tree(sim: &Sim, files: &[&[u8]]) -> GrainId {
    let mut entries = Vec::new();
    for (i, body) in files.iter().enumerate() {
        let len = u32::try_from(body.len()).unwrap_or_else(|e| panic!("the fixture is small: {e}"));
        let grain = sim.put_grain((*body).to_vec());
        entries.push(manifest::DirEntry {
            name: manifest::Name::new(format!("f{i}").into_bytes())
                .unwrap_or_else(|e| panic!("f{i} must be a name: {e}")),
            kind: EntryKind::File {
                exec: false,
                size: u64::from(len),
                grains: manifest::FileGrains::Inline(vec![manifest::GrainRef {
                    id: grain,
                    unpacked_len: len,
                }]),
            },
        });
    }
    let leaf = manifest::encode_dir_leaf(&entries)
        .unwrap_or_else(|e| panic!("the fixture leaf must encode: {e}"));
    sim.put_grain(leaf)
}

/// Drive one future to completion under the sim's own scheduler.
///
/// # Panics
/// If the scheduler returns no result for the one task it was given.
#[must_use]
pub fn run<T>(seed: u64, task: Task<T>) -> T {
    let mut out = Scheduler::new(seed).run(vec![task]);
    out.pop()
        .unwrap_or_else(|| panic!("one task must produce one result"))
}

/// What one publish did, and how many store operations it took to do it.
#[derive(Debug)]
pub struct Published {
    /// The publish's own result.
    pub outcome: Result<PublishSummary, PublishError>,
    /// Store operations this node issued — the range a crash sweep
    /// sweeps, discovered rather than assumed (module doc).
    pub ops: u32,
}

impl Published {
    /// The summary of a publish that was supposed to succeed.
    ///
    /// # Panics
    /// Naming the failure, when it did not.
    #[must_use]
    pub fn ok(self) -> PublishSummary {
        self.outcome
            .unwrap_or_else(|e| panic!("the publish was expected to succeed: {e}"))
    }

    /// The error of a publish that was supposed to fail.
    ///
    /// # Panics
    /// Naming the seq it claimed, when it succeeded instead.
    #[must_use]
    pub fn err(self) -> PublishError {
        match self.outcome {
            Ok(summary) => panic!(
                "the publish was expected to fail and claimed seq {} instead",
                summary.seq
            ),
            Err(e) => e,
        }
    }
}

/// One whole publish over `store`: prepare from a tree already in the
/// local store, then commit.
///
/// Takes the handle BY VALUE because the scheduler's tasks are
/// `'static`: a future borrowing a local cannot be boxed into one. The
/// writer identity comes from the handle's own node id, so a driver
/// cannot pair one node's operations with another node's identity.
pub async fn publish_with(store: SimStore, manifest_root: GrainId, policy: Policy) -> Published {
    let identity = identity(store.node());
    let outcome = match prepare_from_manifest(
        &store,
        &store,
        manifest_root,
        HarvestStats::default(),
        &volume(),
        &key(),
        &identity,
        now(),
        policy,
    )
    .await
    {
        Ok(prepared) => commit(&store, prepared).await,
        Err(e) => Err(e),
    };
    let ops = store.store_ops();
    Published { outcome, ops }
}

/// One publish by `node`, driven alone under [`DRIVER_SEED`].
#[must_use]
pub fn publish_on(
    sim: &Sim,
    node: u32,
    faults: Faults,
    manifest_root: GrainId,
    policy: Policy,
) -> Published {
    let store = sim.node(node, faults);
    run(
        DRIVER_SEED,
        Box::pin(publish_with(store, manifest_root, policy)),
    )
}

/// What one [`race`] did.
#[derive(Debug)]
pub struct Raced {
    /// The world the publishers ran in. Its [`crate::fakes::Sim::trace`]
    /// IS the replay artifact.
    pub sim: Sim,
    /// Each publisher's outcome, in task order — node 0, then node 1.
    pub results: Vec<Published>,
}

/// Two publishers of the same tree, racing for the same seq under the
/// schedule `seed` picks.
///
/// **One body, two callers.** The scenario that asserts on this race and
/// the `sim-replay` binary the cross-process meta-test spawns both run
/// exactly this. It is in the lib because a `src/bin` target sees
/// `[dependencies]` and this lib and never a test target's helpers, so a
/// second copy is the only alternative — and then the program the replay
/// check proves reproducible stops being the program the scenario proves
/// correct.
///
/// The two publishers are DIFFERENT NODES, hence different writer
/// identities (module doc): sharing one collapses their root bytes and
/// there is no race left to observe.
#[must_use]
pub fn race(seed: u64) -> Raced {
    let sim = Sim::new();
    let tree = seed_tree(&sim, ONE);
    let tasks: Vec<Task<Published>> = vec![
        Box::pin(publish_with(
            sim.node(0, Faults::none()),
            tree,
            Policy::default(),
        )),
        Box::pin(publish_with(
            sim.node(1, Faults::none()),
            tree,
            Policy::default(),
        )),
    ];
    let results = Scheduler::new(seed).run(tasks);
    Raced { sim, results }
}

/// The bit that selects [`deferred_race`] in [`replay_run`]'s seed
/// space: a seed with it set (and [`DECISION_LOG_SEEDS`] clear) runs the
/// deferred race at the seed with it cleared; a seed with neither
/// selector bit runs [`race`].
///
/// The high bit rather than, say, parity: every seed below the selector
/// bits keeps its meaning as the seed space grows, so a pinned
/// plain-race seed stays pinned.
pub const DEFERRED_SEEDS: u64 = 1 << 63;

/// How many release points [`deferred_race`] spreads its seeds over:
/// the held write is released after `seed % DEFERRED_RELEASE_SPAN`
/// later store operations.
///
/// Small on purpose. The read by [`DEFERRED_READER`] that closes the
/// run issues at least four store operations whenever the volume has a
/// head, and it always does — node 1 claims a seq whenever node 0's
/// write is still held — so with the probe that follows the held
/// `put_root`, every release point in the span is reached inside the
/// run and every deferred seed records its write's fate.
/// `every_deferred_replay_seed_records_the_fate_of_its_held_write` is
/// the pin.
pub const DEFERRED_RELEASE_SPAN: u64 = 4;

/// The node that reads the volume at the end of [`deferred_race`] — a
/// participant in the run, not the oracle, because only the run's own
/// store operations carry a held write to its release point
/// ([`Sim::oracle`]).
pub const DEFERRED_READER: u32 = 2;

/// [`race`], with node 0's `put_root` DEFERRED: node 0 is told its PUT
/// failed, and the write lands — or is refused, if node 1 took the seq
/// first — after `seed % `[`DEFERRED_RELEASE_SPAN`] later store
/// operations. The scheduler runs under the same `seed`, so one number
/// fixes both the interleaving and the release point.
///
/// **The deferred index is read off the fault-free RACE at the same
/// seed**, never off a solo publish: node 0's operation sequence in the
/// race depends on the interleaving (a publisher that sees the other's
/// root first prepares a different seq, and a different flow), so an
/// index measured alone can land on some other operation, where the
/// deferral degenerates to a plain refusal and the run defers nothing.
/// The faulted run is identical to the fault-free one up to that index —
/// same tasks, same scheduler draws, same answers — so the index names
/// node 0's `put_root` in both.
///
/// After the race [`DEFERRED_READER`] resolves the head once, and that
/// read is part of the run: its store operations are what carry a late
/// release point past the publishers' last one. Its answer is not
/// returned — whatever it is, the artifact records how it was reached.
///
/// # Panics
/// If node 0 issues no `put_root` in the fault-free race — every
/// publisher of the race attempts exactly one, so this is a defect in
/// the fixture.
#[must_use]
pub fn deferred_race(seed: u64) -> Raced {
    let cas_at = first_put_root(&race(seed).sim.trace(), 0)
        .unwrap_or_else(|| panic!("node 0 issued no put_root in the fault-free race at {seed}"));
    let release_after = u32::try_from(seed % DEFERRED_RELEASE_SPAN).unwrap_or(0);
    let sim = Sim::new();
    let tree = seed_tree(&sim, ONE);
    let tasks: Vec<Task<Published>> = vec![
        Box::pin(publish_with(
            sim.node(
                0,
                Faults::just(Fault::DeferPut {
                    at: cas_at,
                    release_after,
                }),
            ),
            tree,
            Policy::default(),
        )),
        Box::pin(publish_with(
            sim.node(1, Faults::none()),
            tree,
            Policy::default(),
        )),
    ];
    let results = Scheduler::new(seed).run(tasks);
    let reader = sim.node(DEFERRED_READER, Faults::none());
    let task: Task<Result<ResolveOutcome, ResolveError>> = Box::pin(async move {
        let ctx = oracle_head_context();
        let mut sink = |_: GrainId, _: &[u8]| Ok(());
        resolve_head(
            &reader,
            VOLUME,
            &ctx,
            None,
            ResolveTarget::WholeTree,
            &mut sink,
        )
        .await
    });
    let _ = run(DRIVER_SEED, task);
    Raced { sim, results }
}

/// How many `put_root`s in `trace` were HELD ([`Fault::DeferPut`]),
/// recorded as `failed(deferred)`.
///
/// What [`replay_run`] checks before returning a deferred seed's run: a
/// deferral aimed at an index that is not a `put_root` degenerates to a
/// plain refusal, and a replay of that run would pass while replaying no
/// held write at all.
#[must_use]
pub fn held_puts(trace: &Trace) -> usize {
    trace
        .entries()
        .iter()
        .filter(|e| {
            matches!(e.op, Op::PutRoot { .. }) && e.outcome == Outcome::Failed(TraceError::Deferred)
        })
        .count()
}

/// The bit that selects [`decision_log_run`] in [`replay_run`]'s seed
/// space: a seed with it set (and [`DEFERRED_SEEDS`] clear) runs the
/// scripted decision-log run, its low bits decoded by [`LogPlan::decode`].
///
/// The two selector bits are exclusive. A seed with both set names no
/// run, and [`select`] refuses it rather than pick one.
///
/// Every seed with this bit clear selects [`race`] or [`deferred_race`] by
/// [`DEFERRED_SEEDS`] alone; the cross-process test pins the artifacts of a
/// sample of them.
pub const DECISION_LOG_SEEDS: u64 = 1 << 62;

/// The seed spaces [`replay_run`] selects between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedSpace {
    /// The plain two-publisher [`race`]: no selector bit.
    Race,
    /// The [`deferred_race`]: [`DEFERRED_SEEDS`].
    Deferred,
    /// The [`decision_log_run`]: [`DECISION_LOG_SEEDS`].
    DecisionLog,
}

/// The seed space a seed names and the seed that space runs: the seed
/// with its selector bit cleared.
///
/// # Errors
/// [`ReplayError::BothSelectors`] for a seed with both selector bits set.
pub fn select(seed: u64) -> Result<(SeedSpace, u64), ReplayError> {
    match (seed & DEFERRED_SEEDS != 0, seed & DECISION_LOG_SEEDS != 0) {
        (true, true) => Err(ReplayError::BothSelectors { seed }),
        (true, false) => Ok((SeedSpace::Deferred, seed & !DEFERRED_SEEDS)),
        (false, true) => Ok((SeedSpace::DecisionLog, seed & !DECISION_LOG_SEEDS)),
        (false, false) => Ok((SeedSpace::Race, seed)),
    }
}

/// Why [`replay_run`] refused a seed.
#[derive(Debug, Clone)]
pub enum ReplayError {
    /// Both selector bits are set: a usage error.
    BothSelectors {
        /// The seed as given.
        seed: u64,
    },
    /// A deferred run held no `put_root`: its artifact would replay
    /// byte-identically while replaying no late write.
    NoHeldPut {
        /// The seed as given.
        seed: u64,
    },
    /// A decision-log run whose fault never fired on the step it names:
    /// its artifact would replay a different run under the name of a
    /// faulted one.
    FaultDidNotFire {
        /// The seed as given.
        seed: u64,
    },
    /// A decision-log run failed its oracle.
    LogRun(Box<LogRunError>),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BothSelectors { seed } => write!(
                f,
                "seed {seed} has both selector bits set (the deferred bit and the decision-log \
                 bit are exclusive)"
            ),
            Self::NoHeldPut { seed } => write!(
                f,
                "seed {seed}: the deferred run held no put_root, so its artifact replays no \
                 late write"
            ),
            Self::FaultDidNotFire { seed } => write!(
                f,
                "seed {seed}: the decision-log run's fault did not fire on the step it names, \
                 so its artifact replays a different run"
            ),
            Self::LogRun(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReplayError {}

/// What `sim-replay <seed>` runs, chosen by [`select`]: [`race`] for a
/// seed without a selector bit, [`deferred_race`] at the remaining bits
/// for [`DEFERRED_SEEDS`], [`decision_log_run`] at the remaining bits for
/// [`DECISION_LOG_SEEDS`]. One body for the binary and for any test that
/// asserts on the same run.
///
/// Each run carries its non-vacuity guard: a deferred run must hold a
/// `put_root` ([`held_puts`]), and a decision-log run's fault must fire
/// ([`log_fault_fired`]), a failed sync on the very step the fault-free
/// script names. Every error names the seed as given, so
/// `sim-replay <that seed>` reproduces it.
///
/// # Errors
/// [`ReplayError`]: the seed has both selector bits, a guard failed, or a
/// decision-log run failed its oracle.
pub fn replay_run(given: u64) -> Result<Sim, ReplayError> {
    let (space, seed) = select(given)?;
    match space {
        SeedSpace::Race => Ok(race(seed).sim),
        SeedSpace::Deferred => {
            let sim = deferred_race(seed).sim;
            if held_puts(&sim.trace()) == 0 {
                return Err(ReplayError::NoHeldPut { seed: given });
            }
            Ok(sim)
        }
        SeedSpace::DecisionLog => {
            let run = decision_log_run(given).map_err(|e| ReplayError::LogRun(Box::new(e)))?;
            let trace = run.sim.trace();
            let fired = log_fault_fired(run.plan.kind, &trace)
                && run.fail_sync_at.is_none_or(|at| failed_sync_at(&trace, at));
            if !fired {
                return Err(ReplayError::FaultDidNotFire { seed: given });
            }
            Ok(run.sim)
        }
    }
}

/// The volume's head, as the oracle sees it through a fault-free handle.
///
/// # Errors
/// [`ResolveError::NoHead`] when the volume has no head — the expected
/// outcome at most crash points. Any other variant means the surviving
/// volume is genuinely broken, EXCEPT the two that describe no damage:
/// `NoSuchTarget` and `PathBudgetExceeded` (a tree wider than one
/// whole-tree resolve may expand). See [`ResolveError`].
pub fn resolve(sim: &Sim) -> Result<ResolveOutcome, ResolveError> {
    let sim = sim.clone();
    let task: Task<Result<ResolveOutcome, ResolveError>> = Box::pin(async move {
        let mut sink = |_: GrainId, _: &[u8]| Ok(());
        sim.resolve_head(VOLUME, &mut sink).await
    });
    run(DRIVER_SEED, task)
}

/// [`resolve`], collecting every `(id, bytes)` the fetcher hands the
/// sink into a map — the shape a test re-validating the tree over
/// remote bytes independently needs, in place of the removed
/// `ResolveOutcome.objects` field.
///
/// # Errors
/// As [`resolve`].
pub fn resolve_collecting(sim: &Sim) -> ResolveWithObjects {
    let reader = sim.oracle();
    let ctx = oracle_head_context();
    let task: Task<ResolveWithObjects> =
        Box::pin(async move { resolve_head_collecting(&reader, VOLUME, &ctx).await });
    run(DRIVER_SEED, task)
}

/// The volume at exactly `seq`, through a fault-free handle.
///
/// Roots are immutable, so this reads a HISTORICAL publish as well as
/// the head — which is what lets a scenario assert that a crashed
/// republish left the PRIOR head resolvable, not merely that something
/// resolves.
///
/// # Errors
/// [`ResolveError::NoHead`] when no root sits at `seq`; any other
/// variant means that publish is broken, EXCEPT `NoSuchTarget` and
/// `PathBudgetExceeded`, which describe no damage. See [`ResolveError`].
pub fn resolve_seq(sim: &Sim, seq: u64) -> Result<ResolveOutcome, ResolveError> {
    let reader = sim.oracle();
    let task: Task<Result<ResolveOutcome, ResolveError>> = Box::pin(async move {
        let mut sink = |_: GrainId, _: &[u8]| Ok(());
        resolve_at(
            &reader,
            VOLUME,
            seq,
            None,
            ResolveTarget::WholeTree,
            &mut sink,
        )
        .await
    });
    run(DRIVER_SEED, task)
}

/// [`resolve_seq`], collecting every `(id, bytes)` the fetcher hands
/// the sink into a map — see [`resolve_collecting`].
///
/// # Errors
/// As [`resolve_seq`].
pub fn resolve_seq_collecting(sim: &Sim, seq: u64) -> ResolveWithObjects {
    let reader = sim.oracle();
    let task: Task<ResolveWithObjects> =
        Box::pin(async move { resolve_at_collecting(&reader, VOLUME, seq).await });
    run(DRIVER_SEED, task)
}

/// Whether an operation counts in the fault index space.
///
/// The fault indices count REMOTE operations only: the local seam is
/// synchronous and traced but not indexed (see [`crate::fakes`]), and
/// neither a deferred write's release nor an admin call is an operation
/// a node issued. The
/// match has no wildcard arm, so a new [`Op`] variant must be classified
/// here rather than silently joining whichever side happens to be
/// convenient — and an operation classified wrongly shifts every
/// discovered index by one.
#[must_use]
pub const fn is_store_op(op: &Op) -> bool {
    match op {
        Op::PutBin { .. }
        | Op::PutMeta { .. }
        | Op::PutRoot { .. }
        | Op::WriteHint { .. }
        | Op::GetBinRange { .. }
        | Op::GetMeta { .. }
        | Op::GetRoot { .. }
        | Op::ReadHint { .. }
        | Op::MaxSeq { .. } => true,
        // A release is the store applying a write a node issued EARLIER
        // — that `put_root` already holds the index — and the admin
        // handle is outside the seam altogether (`crate::fakes::Admin`).
        // The decision log counts its steps in its own index space
        // (`crate::decision_log::SimDecisionLog::steps`), never in a
        // store node's.
        Op::GetGrain { .. }
        | Op::HasGrain { .. }
        | Op::ReleaseRoot { .. }
        | Op::AdminPlantRoot { .. }
        | Op::AdminDeleteRoot { .. }
        | Op::AdminListRoots { .. }
        | Op::Log(_) => false,
    }
}

/// One node's store operations, in the order it issued them.
///
/// Position in this list IS the operation index a [`crate::fakes::Fault`]
/// names, which is what makes an index discoverable from a fault-free
/// run instead of counted by hand.
#[must_use]
pub fn store_ops(trace: &Trace, node: u32) -> Vec<&Entry> {
    trace
        .entries()
        .iter()
        .filter(|e| e.node == node && is_store_op(&e.op))
        .collect()
}

/// The store-operation index of `node`'s first `put_root` — the commit
/// point, and the boundary the re-run scenario's two arms sit either
/// side of.
#[must_use]
pub fn first_put_root(trace: &Trace, node: u32) -> Option<u32> {
    let at = store_ops(trace, node)
        .iter()
        .position(|e| matches!(e.op, Op::PutRoot { .. }))?;
    u32::try_from(at).ok()
}

/// How many times the trace hands off from one node to another.
///
/// The degeneracy check for a concurrency scenario: a schedule that ran
/// each publisher to completion in turn has one handoff per publisher
/// boundary and no race in it, whatever the outcomes look like.
///
/// Only operations a node ISSUED count: a deferred write's release is
/// recorded under its issuer at a boundary another node's operation
/// reached, and an admin call is the driver, not a node — counting
/// either would report a switch between nodes the scheduler never made.
#[must_use]
pub fn handoffs(trace: &Trace) -> usize {
    let issued: Vec<u32> = trace
        .entries()
        .iter()
        .filter(|e| {
            !matches!(
                e.op,
                Op::ReleaseRoot { .. }
                    | Op::AdminPlantRoot { .. }
                    | Op::AdminDeleteRoot { .. }
                    | Op::AdminListRoots { .. }
            )
        })
        .map(|e| e.node)
        .collect();
    issued.windows(2).filter(|w| w.first() != w.last()).count()
}

/// The exact command that re-runs `test`, carrying the seed the failure
/// was found on.
///
/// Every scenario is a pure function of its seed and its fault schedule,
/// so re-running the command reaches the same seed again; the seed is
/// printed because it is the input a reader needs in order to replay one
/// point of a sweep rather than the whole of it.
#[must_use]
pub fn replay(test: &str, seed: u64) -> String {
    format!("seed={seed}; replay with: cargo nextest run -p granary-sim -E 'test({test})'")
}

mod log_run;
#[cfg(test)]
pub(crate) use log_run::script_records;
pub use log_run::{
    LOG_VOLUME, LogFaultKind, LogPlan, LogRun, LogRunError, LogRunFailure, decision_log_run,
    failed_syncs, fault_fired as log_fault_fired, host_crashes, injected_steps, log_damage,
    log_rows, log_steps, log_verdicts, resyncs, run_plan, truncation_draws,
};
pub use log_run::{cut_by_a_crash, failed_sync_at, first_crash_rows};

#[cfg(test)]
mod tests;
