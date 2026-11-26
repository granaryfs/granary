// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The falsifiable scenarios, driven through granary-sim's
//! public API over the shared fixture in
//! [`granary_sim::scenario`].
//!
//! Each test's doc comment says what would BREAK it — a scenario that
//! cannot name its own falsifier is a scenario that cannot fail. Two
//! disciplines are common to all of them and are not restated in each:
//!
//! - **Nothing here is a literal operation count or index.** Every range
//!   and every fault target is read off a fault-free run's trace. The
//!   counts are fixture-dependent — this tree at this routing width
//!   measures 8 store operations for a first publish and 12 for a delta
//!   republish, where a multi-grain fixture measured 16, of which 8
//!   were reads — so a sweep written as a fixed range does not
//!   fail when the fixture moves, it silently changes meaning.
//! - **Every failure prints the seed and the exact replay command**, via
//!   [`granary_sim::scenario::replay`], together with the crash index or
//!   the sweep position it failed at.
//!
//! **No tokio.** The sim's own scheduler drives every future here; a
//! `#[tokio::test]` would put a second scheduler in charge of the
//! ordering these scenarios exist to control.

#![expect(
    clippy::too_many_lines,
    reason = "a scenario is ONE property, and its arms share a discovered index and a fixture; \
              hoisting an arm into a helper puts the assertion in one place and the thing it \
              asserts about in another, which is how a scenario quietly stops covering the arm \
              it is named for"
)]

use std::collections::{BTreeMap, BTreeSet};

use granary_client::{
    Cache, CacheOrigin, FreeSpace, FreeSpaceInfo, HeadContext, Policy, PublishError, ResolveError,
    ResolveTarget, RootVerifier, resolve_head_verified,
};
use granary_core::clock::Clock;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::rng::SeededRng;
use granary_core::root::Timestamp;
use granary_core::rootstore::{RootStore, RootStoreError};
use granary_sim::fakes::{Fault, Faults, INJECTED, INJECTED_PROBE, Sim};
use granary_sim::scenario::{
    self, ONE, TWO, WIDE, WIDE_PLUS, key, publish_on, resolve, resolve_collecting, resolve_seq,
    resolve_seq_collecting, seed_tree,
};
use granary_sim::sched::Scheduler;
use granary_sim::trace::{Address, Entry, Op, Outcome, Trace, TraceError};

// ------------------------------------------------------------- helpers

/// What a crash left behind, at the granularity the property is stated
/// at: the volume either has no head at all, or resolves COMPLETELY at
/// some seq. There is deliberately no third value — every other outcome
/// is a failure of the sweep, not a class of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Surviving {
    NoHead,
    Resolved(u64),
}

/// Classify the surviving volume, failing the sweep on anything that is
/// neither "resolves completely" nor "has no head".
///
/// **Not `objects.len() == outcome.entries.len()`, deliberately.**
/// The binmap is CUMULATIVE — nothing removes an entry a prior publish
/// mapped — so a leaf a crash-interrupted-then-recovered (or simply
/// superseded) tree no longer references stays mapped but UNREACHABLE,
/// and the whole-tree resolve correctly never fetches it (oracle hole
/// 2's closure: an object the binmap maps but the CURRENT tree does not
/// reference is never asked for). `resolve_collecting` returning `Ok`
/// at all is the "resolves completely" proof under this read contract —
/// every object the walk actually needed was produced, which is what
/// the resolve's own validation (structure, reachability, per-grain
/// length) already checked. The `<=` below is only a sanity bound: the
/// collector must never report MORE objects than the binmap maps.
fn surviving(sim: &Sim, test: &str, at: u32) -> Surviving {
    match resolve_collecting(sim) {
        Ok((outcome, objects)) => {
            assert!(
                objects.len() <= outcome.entries.len(),
                "crash at store op {at}: the collector reported {} objects, more than the \
                 {} the binmap maps. {}",
                objects.len(),
                outcome.entries.len(),
                scenario::replay(test, scenario::DRIVER_SEED)
            );
            Surviving::Resolved(outcome.seq)
        }
        Err(ResolveError::NoHead) => Surviving::NoHead,
        Err(broken) => panic!(
            "crash at store op {at} left a head that does not resolve: {broken}. {}",
            scenario::replay(test, scenario::DRIVER_SEED)
        ),
    }
}

/// One `put_root` attempt, as the artifact recorded it.
#[derive(Debug, Clone, Copy)]
struct RootAttempt {
    node: u32,
    seq: u64,
    /// Content address of the root BYTES this node tried to write. Two
    /// publishers whose attempts share an address are two publishers who
    /// cannot tell each other's roots apart.
    addr: [u8; DIGEST_LEN],
    /// Whether the store accepted it — at the `put_root` itself, or
    /// later, when a HELD write's release landed.
    won: bool,
}

/// Every `put_root` in the trace, in order.
///
/// A deferred `put_root` (`failed(deferred)`) whose release LANDED is a
/// winning root write: the store holds its bytes at its seq. It is
/// credited to the attempt rather than listed as a second one, because
/// it is the same write — one node, one seq, one address.
fn root_attempts(trace: &Trace) -> Vec<RootAttempt> {
    let mut attempts: Vec<(RootAttempt, bool)> = Vec::new();
    for e in trace.entries() {
        match &e.op {
            Op::PutRoot { seq, addr, .. } => attempts.push((
                RootAttempt {
                    node: e.node,
                    seq: *seq,
                    addr: *addr.digest(),
                    won: e.outcome == Outcome::Ok,
                },
                e.outcome == Outcome::Failed(TraceError::Deferred),
            )),
            Op::ReleaseRoot { seq, addr, .. } if e.outcome == Outcome::Ok => {
                if let Some((held, _)) = attempts.iter_mut().find(|(a, deferred)| {
                    *deferred && a.node == e.node && a.seq == *seq && a.addr == *addr.digest()
                }) {
                    held.won = true;
                }
            }
            _ => {}
        }
    }
    attempts.into_iter().map(|(a, _)| a).collect()
}

/// The commit-point index of `node`'s publish, discovered from a
/// fault-free run.
fn cas_index(trace: &Trace, node: u32) -> u32 {
    scenario::first_put_root(trace, node).unwrap_or_else(|| {
        panic!("the publish issued no put_root at all — every scenario below would be vacuous")
    })
}

/// The `get_root` a node issued immediately after its `put_root` — the
/// ONE-PROBE RULE's single read-back — asserted to be in that position
/// rather than searched for, so a flow that stopped probing shows up
/// here.
fn probe_entry(trace: &Trace, node: u32, cas_at: u32) -> Entry {
    let ops = scenario::store_ops(trace, node);
    let at = usize::try_from(cas_at)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let entry = ops
        .get(at)
        .unwrap_or_else(|| panic!("no operation followed the put_root: the probe never happened"));
    assert!(
        matches!(entry.op, Op::GetRoot { .. }),
        "the operation after a failed put_root is {}, not the ONE-PROBE RULE's read-back",
        entry.op
    );
    (*entry).clone()
}

// ------------------------------------------------------------ scenario 1

const CRASH_SWEEP: &str = "crash_at_every_store_op_leaves_a_resolvable_or_absent_head";

/// **Scenario 1.** At every store-operation boundary of a publish, the
/// surviving volume either resolves COMPLETELY through the oracle or has
/// no head at all — never a head referencing an object that is not
/// there. Two sweeps, because the second is where the property has
/// teeth: a crashed FIRST publish can only leave the volume empty, while
/// a crashed REPUBLISH must leave the prior head fully resolvable.
///
/// *Breaks if:* an upload moves after the root CAS. That injection is
/// invisible to a hermetic publish suite and is caught here at exactly
/// one crash point — which is what a crash-sweep buys over a suite that
/// only ever runs the happy ordering.
///
/// **Not a completeness claim.** Measured on this fixture: the
/// first-publish sweep is 8 crash points with ONE pure read (`max_seq`)
/// among them and reaches exactly 2 volume-level outcome classes (7 ×
/// no head, 1 × resolved at seq 1); the republish sweep is 12 crash
/// points, 5 of them pure reads (`max_seq`, `get_root`, and the three
/// `get_meta`s that re-verify the head's binmap), reaching 2 classes (11
/// × resolved at the prior seq, 1 × resolved at the new one). The
/// property holds by the ORDERING of the flow — the root is written
/// second-to-last and nothing is referenced until a root names it — not
/// by what 20 crash points happen to discover. The anti-vacuity
/// assertions below are what stop a sweep that landed entirely in one
/// class from passing while exercising one arm.
///
/// **Both sweeps run at ONE shard**, because `Policy::default()` leaves
/// this fixture at `prefix_bits = 0` — so a crash-ordering defect that
/// needs two or more shards to appear is unswept here, and that is
/// recorded rather than covered because the ordering the property rests
/// on is width-independent (the root is written second-to-last, and
/// nothing is referenced until a root names it).
#[test]
fn crash_at_every_store_op_leaves_a_resolvable_or_absent_head() {
    // Printed, not merely available: nextest shows a failing test's
    // stdout, so this puts the replay command in front of EVERY failure
    // in this test — including one raised inside a helper, which cannot
    // carry the message itself.
    println!("{}", scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED));

    // Discover both ranges from one fault-free world.
    let (first_ops, delta_ops) = {
        let sim = Sim::new();
        let one = seed_tree(&sim, ONE);
        let two = seed_tree(&sim, TWO);
        let first = publish_on(&sim, 0, Faults::none(), one, Policy::default());
        let first_ops = first.ops;
        let seq = first.ok().seq;
        assert_eq!(seq, 1);
        let delta = publish_on(&sim, 1, Faults::none(), two, Policy::default());
        let delta_ops = delta.ops;
        assert_eq!(delta.ok().seq, 2);
        let trace = sim.trace();
        // A sweep that never crosses the commit point cannot say anything
        // about a head at all.
        assert!(
            cas_index(&trace, 0) < first_ops,
            "the first publish's commit point is outside its own operation range"
        );
        assert!(
            cas_index(&trace, 1) < delta_ops,
            "the republish's commit point is outside its own operation range"
        );
        (first_ops, delta_ops)
    };

    // ---- sweep 1: a first publish, over an empty volume.
    let mut first_classes: BTreeSet<Surviving> = BTreeSet::new();
    for at in 0..first_ops {
        let sim = Sim::new();
        let one = seed_tree(&sim, ONE);
        let run = publish_on(
            &sim,
            0,
            Faults::just(Fault::CrashAt(at)),
            one,
            Policy::default(),
        );
        let claimed = run.outcome.as_ref().ok().map(|s| s.seq);
        let class = surviving(&sim, CRASH_SWEEP, at);
        // A publish that REPORTED success must have left its seq
        // resolvable — the crash at the advisory hint write is a
        // success, and it is the one point of this sweep that is.
        if let Some(seq) = claimed {
            assert_eq!(
                class,
                Surviving::Resolved(seq),
                "crash at store op {at}: the publish reported success at seq {seq} and the \
                 volume does not resolve there. {}",
                scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
            );
        }
        first_classes.insert(class);
    }
    // ANTI-VACUITY, permanent: a sweep that landed entirely on `NoHead`
    // never executes the "resolves completely" arm and proves nothing.
    assert!(
        first_classes.contains(&Surviving::NoHead),
        "the first-publish sweep never reached a crash point that left no head: \
         {first_classes:?}. {}",
        scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
    );
    assert!(
        first_classes.contains(&Surviving::Resolved(1)),
        "the first-publish sweep never reached a crash point that left a RESOLVABLE head, so \
         the resolve arm ran zero times: {first_classes:?}. {}",
        scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
    );
    assert_eq!(
        first_classes.len(),
        2,
        "the first-publish sweep's outcome classes moved; this test's doc records the measured \
         set and is now stale: {first_classes:?}. {}",
        scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
    );

    // ---- sweep 2: a delta republish over an already-committed head.
    // This is where "never a head referencing an absent object" bites:
    // seq 1 is published and resolvable BEFORE the crash, so a crash
    // that damaged it would show up as a broken resolve rather than as
    // the empty volume the first sweep can only ever produce.
    let mut delta_classes: BTreeSet<Surviving> = BTreeSet::new();
    for at in 0..delta_ops {
        let sim = Sim::new();
        let one = seed_tree(&sim, ONE);
        let two = seed_tree(&sim, TWO);
        assert_eq!(
            publish_on(&sim, 0, Faults::none(), one, Policy::default())
                .ok()
                .seq,
            1,
            "the head this sweep crashes a republish over must be published first"
        );
        let run = publish_on(
            &sim,
            1,
            Faults::just(Fault::CrashAt(at)),
            two,
            Policy::default(),
        );
        let claimed = run.outcome.as_ref().ok().map(|s| s.seq);
        let class = surviving(&sim, CRASH_SWEEP, at);
        if let Some(seq) = claimed {
            assert_eq!(
                class,
                Surviving::Resolved(seq),
                "republish crash at store op {at}: reported success at seq {seq}, which does \
                 not resolve. {}",
                scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
            );
        }
        assert_ne!(
            class,
            Surviving::NoHead,
            "republish crash at store op {at} destroyed the PRIOR head — a volume that had a \
             resolvable head at seq 1 before the crash has none after it. {}",
            scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
        );
        delta_classes.insert(class);
    }
    assert!(
        delta_classes.contains(&Surviving::Resolved(1)),
        "the republish sweep never left the PRIOR head standing, so the case it exists for ran \
         zero times: {delta_classes:?}. {}",
        scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
    );
    assert!(
        delta_classes.contains(&Surviving::Resolved(2)),
        "the republish sweep never reached a crash point after the new root landed: \
         {delta_classes:?}. {}",
        scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
    );
    assert_eq!(
        delta_classes.len(),
        2,
        "the republish sweep's outcome classes moved; this test's doc records the measured set \
         and is now stale: {delta_classes:?}. {}",
        scenario::replay(CRASH_SWEEP, scenario::DRIVER_SEED)
    );
}

// ------------------------------------------------------------ scenario 2

const RERUN: &str = "rerun_after_crash_reclaims_the_seq_or_advances_the_chain";

/// **Scenario 2, BOTH arms.** A publish that crashed before its CAS is
/// re-run: it re-claims the SAME seq and mints BYTE-IDENTICAL root bytes
/// — the property made possible by taking `std::process::id()` out of
/// `writer_uuid`'s preimage, and it is asserted on the bytes rather than
/// on the seq, because a seq is equal for two roots that differ in every
/// signed field. A publish that crashed AFTER its root landed is re-run
/// too: it advances to seq + 1 and the chain links.
///
/// *Breaks if:* only the first arm is asserted. "A re-run re-claims the
/// seq" is FALSE at the post-CAS crash point — the designed stale-hint
/// window, where the root is already the head and a second root at
/// seq + 1 is the correct outcome. It also breaks if an ambient value
/// re-enters the root preimage: the bytes then differ from the control's
/// while every seq assertion stays green.
#[test]
fn rerun_after_crash_reclaims_the_seq_or_advances_the_chain() {
    println!("{}", scenario::replay(RERUN, scenario::DRIVER_SEED));

    // The control, in its own fault-free world: same node id (hence the
    // same writer identity), same key, same clock, same tree.
    let control = Sim::new();
    let control_tree = seed_tree(&control, ONE);
    let control_run = publish_on(&control, 0, Faults::none(), control_tree, Policy::default());
    let ops = control_run.ops;
    assert_eq!(control_run.ok().seq, 1);
    let cas_at = cas_index(&control.trace(), 0);
    let control_root = resolve(&control)
        .unwrap_or_else(|e| panic!("the control publish must resolve: {e}"))
        .root_bytes;
    // Everything below compares BYTES against this one, and two empty
    // vectors are equal: a control that resolved to no root at all would
    // make every byte-identity assertion in this test pass vacuously.
    assert!(
        !control_root.is_empty(),
        "the control resolved to EMPTY root bytes, so the byte-identity comparisons below \
         compare nothing. {}",
        scenario::replay(RERUN, scenario::DRIVER_SEED)
    );

    // ---- arm 1: every crash point up to and including the CAS itself.
    // The CAS is included because a crashed put_root applies nothing —
    // which the `NoHead` assertion below re-proves at that index rather
    // than assuming.
    for at in 0..=cas_at {
        let sim = Sim::new();
        let tree = seed_tree(&sim, ONE);
        let crashed = publish_on(
            &sim,
            0,
            Faults::just(Fault::CrashAt(at)),
            tree,
            Policy::default(),
        );
        assert!(
            crashed.outcome.is_err(),
            "crash at store op {at} is before the commit point and must not report success. {}",
            scenario::replay(RERUN, scenario::DRIVER_SEED)
        );
        assert!(
            matches!(resolve(&sim), Err(ResolveError::NoHead)),
            "crash at store op {at} left a head, so this is not a pre-CAS crash point. {}",
            scenario::replay(RERUN, scenario::DRIVER_SEED)
        );

        // The re-run: a FRESH handle for the same node, no faults.
        let rerun = publish_on(&sim, 0, Faults::none(), tree, Policy::default()).ok();
        assert_eq!(
            rerun.seq,
            1,
            "the re-run after a crash at store op {at} did not re-claim the seq the crash \
             failed to take. {}",
            scenario::replay(RERUN, scenario::DRIVER_SEED)
        );
        let resolved = resolve(&sim).unwrap_or_else(|e| {
            panic!("the re-run after a crash at store op {at} must resolve: {e}")
        });
        assert_eq!(resolved.seq, 1);
        // The BYTES, not the seq: two roots at one seq can differ in
        // every signed field. Compared with `assert!` rather than
        // `assert_eq!` so a failure names the two content addresses
        // instead of dumping 600 bytes of root twice.
        assert!(
            resolved.root_bytes == control_root,
            "the re-run after a crash at store op {at} minted DIFFERENT root bytes from an \
             identical fault-free publish — something ambient is in the preimage: re-run {} \
             against control {}. {}",
            GrainId::of(&resolved.root_bytes),
            GrainId::of(&control_root),
            scenario::replay(RERUN, scenario::DRIVER_SEED)
        );
    }

    // ---- arm 2: the crash after the root landed.
    let after_cas = cas_at.saturating_add(1);
    assert!(
        after_cas < ops,
        "the fixture has no store operation after the CAS, so the post-CAS arm would be vacuous"
    );
    // The crash lands on the advisory hint write, and a failed hint is a
    // WARNING on a successful publish — so this arm's first publish
    // SUCCEEDS with a stale-absent hint. That is exactly why the arm
    // exists: the re-run must not try to re-claim seq 1.
    //
    // ASSERTED, not assumed. Everything below reads "the publish still
    // succeeded" as evidence about the re-run, and that reading holds
    // only while the operation after the CAS is the advisory one: aimed
    // at anything else, the crash fails the publish outright and this
    // arm reports the wrong thing about the wrong operation.
    {
        let trace = control.trace();
        let ops_of = scenario::store_ops(&trace, 0);
        let at = usize::try_from(after_cas).unwrap_or(usize::MAX);
        let entry = ops_of
            .get(at)
            .unwrap_or_else(|| panic!("no operation at index {after_cas}"));
        assert!(
            matches!(entry.op, Op::WriteHint { .. }),
            "the operation after the CAS is {}, not the advisory hint write — this arm's \
             premise (a crash there leaves a SUCCESSFUL publish) does not hold for it. {}",
            entry.op,
            scenario::replay(RERUN, scenario::DRIVER_SEED)
        );
    }
    let sim = Sim::new();
    let tree = seed_tree(&sim, ONE);
    let landed = publish_on(
        &sim,
        0,
        Faults::just(Fault::CrashAt(after_cas)),
        tree,
        Policy::default(),
    )
    .ok();
    assert_eq!(landed.seq, 1);
    assert!(
        !landed.hint_written,
        "the crash was aimed at the hint write and the hint was written anyway. {}",
        scenario::replay(RERUN, scenario::DRIVER_SEED)
    );
    let root1 = resolve_seq(&sim, 1)
        .unwrap_or_else(|e| panic!("the landed root must resolve: {e}"))
        .root_bytes;
    assert!(
        root1 == control_root,
        "the root that landed before the crash is not the control's bytes: {} against {}. {}",
        GrainId::of(&root1),
        GrainId::of(&control_root),
        scenario::replay(RERUN, scenario::DRIVER_SEED)
    );

    let rerun = publish_on(&sim, 0, Faults::none(), tree, Policy::default()).ok();
    assert_eq!(
        rerun.seq,
        2,
        "the re-run after a POST-CAS crash re-claimed seq 1: the root was already the head, so \
         the chain must advance instead. {}",
        scenario::replay(RERUN, scenario::DRIVER_SEED)
    );
    let head = resolve(&sim).unwrap_or_else(|e| panic!("the advanced head must resolve: {e}"));
    assert_eq!(head.seq, 2);
    assert_eq!(
        head.doc.parent,
        Some(GrainId::of(&root1)),
        "the chain does not link: seq 2's parent is not seq 1's bytes. {}",
        scenario::replay(RERUN, scenario::DRIVER_SEED)
    );
    // BOTH roots exist and resolve — an advance that orphaned the root
    // it extended would satisfy every assertion above.
    assert!(resolve_seq(&sim, 1).is_ok(), "seq 1 stopped resolving");
    assert!(resolve_seq(&sim, 2).is_ok(), "seq 2 does not resolve");
}

// ------------------------------------------------------------ scenario 3

const RACE: &str = "concurrent_publishers_interleave_and_exactly_one_claims_the_seq";

/// **Scenario 3.** Two publishers, driven by the sim's scheduler over a
/// SWEEP of seeds: whatever schedule a seed produces, at most one
/// publisher ever claims a given seq, and a publisher that lost the CAS
/// fails TERMINALLY with `LostRace` rather than silently rebasing onto
/// the winner's chain.
///
/// *Breaks if:* the schedule degenerates so that B's `max_seq` runs
/// after A's `write_hint` — then B publishes seq 2, both succeed, and
/// "exactly one wins" passes with no race in it at all. The scheduler's
/// own measurement puts a fully segregated schedule at ~7% of seeds, so
/// a single-seed race scenario is about 1-in-14 vacuous; the sweep and
/// the contention floor below are what close that.
///
/// *Also breaks if:* the two publishers share a writer identity. With
/// one clock, one key, one volume and one tree, identical identities
/// mint byte-identical root bytes, the loser's ONE-PROBE read-back sees
/// its own bytes, and BOTH publishers report success — the assertion
/// that distinct addresses are attempted at a contested seq is what
/// makes that failure loud instead of green.
#[test]
fn concurrent_publishers_interleave_and_exactly_one_claims_the_seq() {
    /// Seeds swept. Measured over this range, and the two measurements
    /// are NOT the same one: 60 of 64 seeds CONTEND (two publishers
    /// attempt one seq) while 63 of 64 INTERLEAVE (more than two
    /// handoffs), over schedules running from 1 to 12 handoffs. Exactly
    /// ONE seed is segregated — a single handoff, one publisher running
    /// to completion before the other is polled at all. The other three
    /// non-contending seeds DO interleave, at 3 handoffs each; they
    /// simply miss the CAS window, because in all three the loser's
    /// `max_seq` runs after the winner's `put_root`, so it prepares seq
    /// 2 and never attempts the contested one.
    const SEEDS: u64 = 64;

    // Every per-seed assertion below names the seed it failed on; this
    // names the range, so a failure inside a helper still says what to
    // re-run.
    println!(
        "sweeping seeds 0..{SEEDS} from {}",
        scenario::replay(RACE, 0)
    );

    let mut contested_seeds = 0u64;
    let mut interleaved_seeds = 0u64;

    for seed in 0..SEEDS {
        // The race body lives in the LIB, and this is not a convenience:
        // the `sim-replay` binary the cross-process meta-test spawns runs
        // the SAME `scenario::race`, so what that test proves reproducible
        // is what this test proves correct. Two copies would let the two
        // claims drift apart. Different nodes, hence different writer
        // identities, is `race`'s own pin — see the doc comment above.
        let scenario::Raced { sim, results } = scenario::race(seed);
        assert_eq!(results.len(), 2, "{}", scenario::replay(RACE, seed));

        let trace = sim.trace();
        let attempts = root_attempts(&trace);
        let handoffs = scenario::handoffs(&trace);
        if handoffs > 2 {
            interleaved_seeds = interleaved_seeds.saturating_add(1);
        }

        // A loser that rebased would try a second seq. One attempt per
        // publisher is what "terminal" means at the store.
        for node in [0u32, 1] {
            let tries = attempts.iter().filter(|a| a.node == node).count();
            assert_eq!(
                tries,
                1,
                "publisher {node} issued {tries} put_root attempts — a lost race must fail \
                 terminally, not rebase. {}",
                scenario::replay(RACE, seed)
            );
        }

        let mut by_seq: BTreeMap<u64, Vec<RootAttempt>> = BTreeMap::new();
        for a in &attempts {
            by_seq.entry(a.seq).or_default().push(*a);
        }
        let mut contested = false;
        for (seq, group) in &by_seq {
            let winners = group.iter().filter(|a| a.won).count();
            assert_eq!(
                winners,
                1,
                "seq {seq} was claimed {winners} times by {} attempt(s). {}",
                group.len(),
                scenario::replay(RACE, seed)
            );
            let distinct: BTreeSet<[u8; DIGEST_LEN]> = group.iter().map(|a| a.addr).collect();
            assert_eq!(
                distinct.len(),
                group.len(),
                "two publishers attempted seq {seq} with IDENTICAL root bytes: the loser's \
                 ONE-PROBE read-back sees its own bytes and reports success, so this seed \
                 asserts nothing about a race. {}",
                scenario::replay(RACE, seed)
            );
            if group.len() > 1 {
                contested = true;
            }
            // The root that is actually stored is the winner's.
            let stored = resolve_seq(&sim, *seq)
                .unwrap_or_else(|e| panic!("seq {seq} does not resolve: {e}"));
            let winner = group
                .iter()
                .find(|a| a.won)
                .unwrap_or_else(|| panic!("no winner at seq {seq}"));
            assert_eq!(
                *GrainId::of(&stored.root_bytes).digest(),
                winner.addr,
                "the root stored at seq {seq} is not the bytes of the attempt that succeeded. {}",
                scenario::replay(RACE, seed)
            );
        }
        if contested {
            contested_seeds = contested_seeds.saturating_add(1);
        }

        // No two successes at one seq, whether or not anyone contended.
        let ok_seqs: Vec<u64> = results
            .iter()
            .filter_map(|p| p.outcome.as_ref().ok())
            .map(|s| s.seq)
            .collect();
        let distinct_ok: BTreeSet<u64> = ok_seqs.iter().copied().collect();
        assert_eq!(
            distinct_ok.len(),
            ok_seqs.len(),
            "two publishers reported success at the same seq: {ok_seqs:?}. {}",
            scenario::replay(RACE, seed)
        );

        // The loser fails terminally, and names the seq it lost.
        for p in &results {
            match &p.outcome {
                Ok(_) => {}
                Err(PublishError::LostRace { attempted, .. }) => {
                    assert!(
                        by_seq.get(attempted).is_some_and(|g| g.len() > 1),
                        "a publisher reported losing seq {attempted}, which nobody else \
                         attempted. {}",
                        scenario::replay(RACE, seed)
                    );
                }
                Err(other) => panic!(
                    "a publisher failed with {other} rather than a terminal LostRace. {}",
                    scenario::replay(RACE, seed)
                ),
            }
        }

        // Whoever won, the volume is readable end to end afterwards.
        let (head, objects) = resolve_collecting(&sim)
            .unwrap_or_else(|e| panic!("the volume does not resolve after the race: {e}"));
        assert_eq!(
            objects.len(),
            head.entries.len(),
            "{}",
            scenario::replay(RACE, seed)
        );
    }

    // ANTI-VACUITY, permanent and across the sweep: a run in which no
    // seed ever contended proves nothing about a race, however many
    // per-seed invariants passed.
    let contested_floor = SEEDS * 3 / 4;
    assert!(
        contested_seeds >= contested_floor,
        "only {contested_seeds} of {SEEDS} seeds contended (floor {contested_floor}) — the \
         schedules degenerated and this sweep asserts nothing about a race"
    );
    // The SECOND degeneracy, and it is a different one: a schedule with
    // two handoffs or fewer ran one publisher to completion before the
    // other was polled at all, so the fakes gave the scheduler nowhere to
    // interleave — which is the ready-shaped-fake failure that made the
    // original concurrency scenario vacuous. Stated as a fraction of the
    // sweep rather than as a busiest-schedule literal: a handoff count is
    // a function of how many operations a publish issues, so a floor
    // written as a number would move with the flow while claiming to
    // measure the scheduler.
    let interleave_floor = SEEDS / 2;
    assert!(
        interleaved_seeds >= interleave_floor,
        "only {interleaved_seeds} of {SEEDS} schedules had more than two handoffs (floor \
         {interleave_floor}): the publishers ran almost back to back, so the sweep explores one \
         schedule shape"
    );
}

// ------------------------------------------------------------ scenario 4

const AMBIGUOUS: &str =
    "ambiguous_put_whose_probe_also_fails_surfaces_probe_unresolved_carrying_the_original_error";

/// **Scenario 4.** A failed PUT followed by a failed probe returns
/// `PublishError::ProbeUnresolved { put_error, probe_error }`, carrying
/// both errors. A probe that answers `Ok(None)` returns
/// `Unresolved { put_error }`: it completed and found no root at the
/// attempted seq, but nothing here can prove the failed PUT's own
/// attempt was the only one sent, so the outcome stays unresolved rather
/// than being promoted to the plain original error.
///
/// **Two claims that are easy to blur, kept apart.**
///
/// - *The arm surfaces the ORIGINAL error, PLUS the probe's.* This test
///   asserts both halves land in the variant's own fields, and asserting
///   it by MESSAGE (not merely by variant) is the whole reason
///   [`granary_sim::fakes::INJECTED`] and
///   [`granary_sim::fakes::INJECTED_PROBE`] are two different strings: an
///   arm rewritten to swap which message lands in which field is the
///   mutation this asserts against.
/// - *The arm distinguishes the two CAUSES* with different values:
///   (`Unresolved { put_error: INJECTED }` versus `ProbeUnresolved {
///   put_error: INJECTED, probe_error: INJECTED_PROBE }`), so the value
///   itself discriminates them, and the contrast run below asserts that
///   directly rather than only through the trace's probe outcome
///   (`failed(injected)` versus `absent`).
///
/// The second half is the one that matters, and it aims
/// `LandButReportFailure` at the `put_root` — a write that would
/// otherwise SUCCEED, at an unoccupied seq, because at a read or at an
/// already-failing write that fault is indistinguishable from `Fail` and
/// the test would be green while proving nothing. Its assertion is on
/// the STORE read back through a fault-free handle, never on the error
/// or the trace: a refused `put_root` and one that LANDED and reported
/// failure both surface `Backend(`[`INJECTED`]`)` and both record
/// `failed(injected)`, so neither the error nor the artifact can tell
/// them apart.
///
/// *Breaks if:* the ONE-PROBE RULE's read-back is removed (there is then
/// no probe entry after the `put_root` at all), or if a failed probe
/// starts being reported as a lost race — the caller would then be told
/// another writer holds a seq that is actually its own root.
///
/// *Not* the plain ambiguous PUT, which already exists
/// (`own_landed_root_is_not_a_lost_race`), and the third case below is
/// its contrast — the same landing fault with a WORKING probe recovers
/// into a success.
#[test]
fn ambiguous_put_whose_probe_also_fails_surfaces_probe_unresolved_carrying_the_original_error() {
    println!("{}", scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED));

    let cas_at = {
        let sim = Sim::new();
        let tree = seed_tree(&sim, ONE);
        assert_eq!(
            publish_on(&sim, 0, Faults::none(), tree, Policy::default())
                .ok()
                .seq,
            1
        );
        cas_index(&sim.trace(), 0)
    };

    // ---- the arm, reached with a probe that fails.
    let failing = Sim::new();
    let tree = seed_tree(&failing, ONE);
    let run = publish_on(
        &failing,
        0,
        Faults::none()
            .with(Fault::Fail(cas_at))
            .with(Fault::FailProbe),
        tree,
        Policy::default(),
    );
    let failed = run.err();
    let (put_message, probe_message) = match &failed {
        PublishError::ProbeUnresolved {
            put_error: RootStoreError::Backend(put_message),
            probe_error: RootStoreError::Backend(probe_message),
        } => (put_message.as_str(), probe_message.as_str()),
        other => panic!(
            "a failed put_root whose probe also failed must surface ProbeUnresolved, carrying \
             both the put's own error and the probe's — not a lost race and not a bare \
             `Remote` — it surfaced {other}. {}",
            scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
        ),
    };
    // WHICH error lands in WHICH field, not merely that both are
    // present. The put_root's failure and the probe's are the same
    // variant and differ only in this message, so an arm that swapped
    // `first` and `probe_error` between the two fields passes a check
    // that only confirmed both messages appear somewhere.
    assert_eq!(
        put_message,
        INJECTED,
        "the put_error field must carry the put_root's own message, not the probe's. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
    assert_eq!(
        probe_message,
        INJECTED_PROBE,
        "the probe_error field must carry the probe's own message, not the put_root's. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
    let failed_probe = probe_entry(&failing.trace(), 0, cas_at);
    // REACHABILITY, verified rather than assumed: this run took the
    // `Err(probe_error)` path into the arm.
    assert_eq!(
        failed_probe.outcome,
        Outcome::Failed(TraceError::Injected),
        "the probe did not fail, so this run reached the arm by the OTHER cause. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
    assert!(
        matches!(resolve(&failing), Err(ResolveError::NoHead)),
        "nothing landed, so the volume must still have no head. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );

    // The contrast: the same schedule minus FailProbe returns
    // `Unresolved` because the probe answers `Ok(None)` and no adapter
    // here can prove the failed put_root's own attempt was the only one
    // sent (the ONE-PROBE RULE's amended table,
    // `granary_core::rootstore` module doc).
    let absent = Sim::new();
    let tree = seed_tree(&absent, ONE);
    let contrast = publish_on(
        &absent,
        0,
        Faults::just(Fault::Fail(cas_at)),
        tree,
        Policy::default(),
    );
    // The absent-probe result carries the PUT error in `Unresolved`. The
    // failed-probe result carries both errors in `ProbeUnresolved`.
    assert!(
        matches!(
            contrast.err(),
            PublishError::Unresolved {
                put_error: RootStoreError::Backend(ref m)
            } if m.as_str() == INJECTED
        ),
        "the Ok(None) cause must be unresolved, carrying bare Unresolved(INJECTED), never the \
         plain original error. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
    let absent_probe = probe_entry(&absent.trace(), 0, cas_at);
    assert_eq!(
        absent_probe.outcome,
        Outcome::Absent,
        "without FailProbe the probe must SUCCEED and find nothing — otherwise the two runs \
         are one run and the contrast asserts nothing. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
    assert_ne!(
        failed_probe.outcome,
        absent_probe.outcome,
        "the two causes are indistinguishable even in the artifact. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );

    // ---- the sharper half: the PUT LANDS and reports failure, and the
    // probe fails too. The caller is told the publish failed while its
    // root is the volume's head.
    let landed = Sim::new();
    let tree = seed_tree(&landed, ONE);
    let told = publish_on(
        &landed,
        0,
        Faults::none()
            .with(Fault::LandButReportFailure(cas_at))
            .with(Fault::FailProbe),
        tree,
        Policy::default(),
    );
    assert!(
        matches!(told.outcome, Err(PublishError::ProbeUnresolved { .. })),
        "the caller must be told the publish failed, with ProbeUnresolved — its Display's \
         \"may have landed\" is LITERALLY true in this world, unlike the refusing run above \
         where nothing landed at all. Got {:?}. {}",
        told.outcome,
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
    // The ONLY evidence that distinguishes this from the refusing run:
    // the STORE, read back through a fault-free handle. The error and
    // the artifact render identically in both.
    let (head, objects) = resolve_collecting(&landed).unwrap_or_else(|e| {
        panic!(
            "the root landed, so the volume must resolve however the caller was answered: {e}. {}",
            scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
        )
    });
    assert_eq!(
        head.seq,
        1,
        "the write that reported failure did not land. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
    assert_eq!(objects.len(), head.entries.len());

    // ---- and the contrast that shows the probe is what makes the
    // difference: the same landing fault with a WORKING probe recovers
    // into a SUCCESS (the ONE-PROBE RULE doing its job).
    let recovered = Sim::new();
    let tree = seed_tree(&recovered, ONE);
    let summary = publish_on(
        &recovered,
        0,
        Faults::just(Fault::LandButReportFailure(cas_at)),
        tree,
        Policy::default(),
    )
    .ok();
    assert_eq!(
        summary.seq,
        1,
        "a landed write with a working probe must be recognised as this publisher's own. {}",
        scenario::replay(AMBIGUOUS, scenario::DRIVER_SEED)
    );
}

// ------------------------------------------------------------ scenario 5

const LEDGER: &str = "one_grain_delta_puts_only_the_shards_it_touched";

/// **Scenario 5, the operation ledger.** A one-grain delta issues PUTs
/// proportional to the shards it TOUCHED, not to `1 << prefix_bits`.
/// Asserted against the trace's operations rather than against
/// `PublishSummary::shards_rewritten`, which counts only the PUTs that
/// reported novel bytes — an implementation that re-PUT all 16 shards
/// would report the same `shards_rewritten` as one that skipped 14 of
/// them, because the 14 dedup on content address.
///
/// The arithmetic, measured on this fixture: 8 one-grain files publish 9
/// mapped objects at a 4-bit routing width, so `shards_total` is 16. The
/// delta adds one file: 2 novel objects (its grain, and the rewritten
/// directory leaf that names it), which route to 2 of the 16 shards.
/// Three meta objects are re-written unconditionally on any rebuild —
/// the bin table, the binmap index and the commit record — so the whole
/// `put_meta` ledger of the delta is 2 + 3 = 5. If every shard were
/// re-PUT it would be 16 + 3 = 19.
///
/// *Breaks if:* the shard-amplification defect returns — the rebuild
/// branch `put_meta`s every bucket unconditionally, which at this width
/// is 16 full bodies
/// for a two-object delta and at the maximum width 4096. This is the one
/// defect that shipped and that this architecture would have caught.
#[test]
fn one_grain_delta_puts_only_the_shards_it_touched() {
    println!("{}", scenario::replay(LEDGER, scenario::DRIVER_SEED));

    let policy = Policy { min_prefix_bits: 4 };
    let sim = Sim::new();
    let wide = seed_tree(&sim, WIDE);
    let plus = seed_tree(&sim, WIDE_PLUS);

    let first = publish_on(&sim, 0, Faults::none(), wide, policy).ok();
    assert_eq!(first.seq, 1);
    // VACUITY GUARD, and it comes first because everything below is
    // vacuous without it: a one-of-one binmap makes "only the shards it
    // touched" true of every possible implementation, including one that
    // rewrites the whole map.
    assert!(
        first.shards_total > 1,
        "a {}-shard binmap cannot distinguish a targeted rewrite from a whole one. {}",
        first.shards_total,
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    assert_eq!(
        (first.prefix_bits, first.shards_total),
        (4, 16),
        "the fixture's routing width moved and this test's arithmetic is stated against 16 \
         shards. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );

    let delta = publish_on(&sim, 1, Faults::none(), plus, policy).ok();
    assert_eq!(delta.seq, 2);
    assert_eq!(
        delta.shards_total,
        first.shards_total,
        "the routing width moved, so the positional shard skip does not apply and this ledger \
         measures something else. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    assert_eq!(
        delta.novel_objects,
        2,
        "the delta must be one grain plus the leaf that names it. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );

    // What actually changed, read off the published binmaps.
    let before = resolve_seq(&sim, 1).unwrap_or_else(|e| panic!("seq 1 must resolve: {e}"));
    let (after, after_objects) =
        resolve_seq_collecting(&sim, 2).unwrap_or_else(|e| panic!("seq 2 must resolve: {e}"));
    assert_eq!(before.shard_ids.len(), 16);
    assert_eq!(after.shard_ids.len(), 16);
    // Compared as the ARTIFACT's addresses, because that is what the
    // ledger below is read out of: the trace records a bare digest (see
    // `granary_sim::trace`'s module doc on why it does not depend on
    // granary-core), so a `GrainId`-level comparison would have to invent
    // an algorithm for every address it read back. Inventing `Blake3` is
    // correct only while Blake3 is the sole registered algorithm — and
    // registering a second one is a live obligation here, at which point
    // the reconstruction would silently stop comparing equal rather than
    // failing. The digest is the whole of what was recorded, so
    // comparing digests assumes nothing.
    let touched: BTreeSet<Address> = before
        .shard_ids
        .iter()
        .zip(&after.shard_ids)
        .filter(|(was, now)| was != now)
        .map(|(_, now)| Address::new(*now.digest()))
        .collect();
    assert!(
        !touched.is_empty(),
        "the delta changed no shard at all, so the ledger below is vacuous. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    let changed_positions = before
        .shard_ids
        .iter()
        .zip(&after.shard_ids)
        .filter(|(was, now)| was != now)
        .count();
    // Shard addresses are NOT unique across positions — every empty
    // bucket encodes to the same bytes, so this fixture's 16 positions
    // carry 9 distinct addresses before the delta and 10 after — and the
    // ledger's arithmetic below counts addresses. The two agree only
    // while no two CHANGED positions land on one address, which is what
    // this pins.
    assert_eq!(
        touched.len(),
        changed_positions,
        "two shard positions changed to the same address, so an address-counted ledger and a \
         position-counted one no longer agree. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    assert!(
        touched.len() <= 2,
        "{} shards changed for a 2-object delta — at most one shard per novel object. {}",
        touched.len(),
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    assert!(
        touched.len() < before.shard_ids.len(),
        "every shard changed, so a whole-binmap rewrite is indistinguishable here. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );

    // THE LEDGER: every meta object the delta actually PUT, from the
    // artifact — not from the summary, which cannot see a PUT that
    // deduped.
    let trace = sim.trace();
    let put_meta: Vec<Address> = scenario::store_ops(&trace, 1)
        .iter()
        .filter_map(|e| match &e.op {
            Op::PutMeta { addr, .. } => Some(*addr),
            _ => None,
        })
        .collect();
    let always_rewritten: BTreeSet<Address> = [
        after.bin_table,
        after.doc.binmap_index,
        after.doc.sheaf_head,
    ]
    .iter()
    .map(|id| Address::new(*id.digest()))
    .collect();
    assert_eq!(
        always_rewritten.len(),
        3,
        "the bin table, the binmap index and the sheaf must be three distinct objects for the \
         arithmetic below to hold. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    let expected: BTreeSet<Address> = touched.union(&always_rewritten).copied().collect();
    let issued: BTreeSet<Address> = put_meta.iter().copied().collect();
    assert_eq!(
        issued.len(),
        put_meta.len(),
        "the delta PUT the same meta object twice: {}. {}",
        put_meta
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    assert_eq!(
        issued,
        expected,
        "the delta's put_meta ledger is not the touched shards plus the bin table, the binmap \
         index and the sheaf: {} operations against {} expected. {}",
        put_meta.len(),
        expected.len(),
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    assert_eq!(
        put_meta.len(),
        touched.len() + 3,
        "the arithmetic in this test's doc comment no longer holds. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    // …and the summary agrees with the ledger, which is the weaker
    // statement the ledger exists to replace.
    assert_eq!(
        delta.shards_rewritten,
        u64::try_from(touched.len()).unwrap_or(u64::MAX),
        "the summary's shard count disagrees with the operations that were issued. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
    assert!(
        delta.shards_rewritten < delta.shards_total,
        "every shard was rewritten. {}",
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );

    // The delta is a delta: the binmap still MAPS everything it held —
    // cumulative, nothing removed. It does not follow that the new
    // tree still REFERENCES all of it: the touched directory's leaf was
    // re-encoded (a new id, counted in `delta.novel_objects`), so the
    // OLD leaf stays mapped but unreachable from the new head, and the
    // whole-tree resolve correctly never fetches it (oracle hole 2). So
    // this is `<`, not `==`: `after_objects` is the reachable set the
    // walk actually produced, strictly smaller by the one superseded
    // leaf.
    assert_eq!(after.entries.len(), before.entries.len() + 2);
    assert!(
        after_objects.len() < after.entries.len(),
        "expected the superseded leaf to be mapped but unreachable: {} objects produced, {} \
         entries mapped. {}",
        after_objects.len(),
        after.entries.len(),
        scenario::replay(LEDGER, scenario::DRIVER_SEED)
    );
}

// ------------------------------------------------------------ scenario 6

const SERVER_DOWN: &str = "server_down_cached_reads_keep_working";

/// Injected, never the real filesystem query (this scenario's own
/// rule): plenty of room, so nothing here is about the free-space
/// gate.
struct PlentyOfSpace;

impl FreeSpace for PlentyOfSpace {
    fn free_space(&self) -> std::io::Result<FreeSpaceInfo> {
        Ok(FreeSpaceInfo {
            free_bytes: 1_000_000_000_000,
            capacity_bytes: 2_000_000_000_000,
        })
    }
}

/// This scenario's own scratch dir for `Cache::open_with_free_space`'s
/// disk-backed structures — unique per run, removed on drop. Mirrors
/// `granary-client`'s own test idiom (`seam_drivable.rs`,
/// `cache.rs`); the sim has no cache-backed fixture of its own to reuse.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob \
                  (matches granary-client's own cache.rs/seam_drivable.rs test idiom)"
    )]
    fn new() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "granary-sim-server-down-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn server_down_cache_origin() -> CacheOrigin {
    CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x51; 32],
        root_key_id: None,
    }
}

fn server_down_fresh_cache(dir: &ScratchDir) -> Cache {
    Cache::open_with_free_space(
        &dir.0,
        1024 * 1024 * 1024,
        &server_down_cache_origin(),
        Box::new(PlentyOfSpace),
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// A fixed reading (never the ambient clock) shared by BOTH the warm
/// and the degraded `HeadContext` below — both must read the SAME "now"
/// for the persisted head hint to land inside its jittered TTL on the
/// degraded reader's own discovery, which is the demo's shape: zero
/// wire calls at discovery, so the transport failure
/// surfaces at the resolve's first `get_root` instead.
struct ServerDownClock;

impl Clock for ServerDownClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        }
    }
}

fn server_down_head_ctx() -> HeadContext {
    HeadContext::new(Box::new(ServerDownClock), Box::new(SeededRng::new(1)))
}

/// Drive a future to completion by hand, polling until `Ready` or until the
/// sim scheduler's standard poll budget proves it is stuck.
///
/// **Sound here for a narrower reason than `granary_client::head`'s own
/// identical idiom.** That module's version exists to force genuine
/// INTERLEAVING among several concurrent futures; this one drives
/// exactly ONE future with nothing else runnable at the same time, so
/// there is no schedule to control and no seed governs this loop —
/// unlike the sim's own multi-task `Scheduler`, which this scenario
/// still uses for the two publishes above. `SimStore`'s own operations
/// self-wake on their one `yield_once` (`sched::yield_once`'s own doc),
/// so a bare `Waker::noop()` polled in a tight loop is enough. The fixed
/// budget turns a regressed perpetual `Pending` into a deterministic test
/// failure rather than an unbounded CPU loop.
fn poll_to_completion<T>(
    fut: &mut std::pin::Pin<Box<dyn std::future::Future<Output = T> + '_>>,
) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut polls: u64 = 0;
    loop {
        polls = polls.saturating_add(1);
        assert!(
            polls <= Scheduler::DEFAULT_POLL_BUDGET,
            "poll_to_completion poll budget exhausted: {polls} polls without finishing; \
             the single future is still Pending. A regression in its self-wake/progress \
             path would otherwise spin this scenario forever"
        );
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

struct PendingPolls(u64);

impl std::future::Future for PendingPolls {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self.0 == 0 {
            std::task::Poll::Ready(())
        } else {
            self.0 -= 1;
            std::task::Poll::Pending
        }
    }
}

#[test]
fn poll_to_completion_allows_the_last_budgeted_poll() {
    let mut fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> = Box::pin(PendingPolls(
        Scheduler::DEFAULT_POLL_BUDGET.saturating_sub(1),
    ));
    poll_to_completion(&mut fut);
}

#[test]
#[should_panic(expected = "poll_to_completion poll budget exhausted")]
fn poll_to_completion_refuses_one_poll_past_its_budget() {
    let mut fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> =
        Box::pin(PendingPolls(Scheduler::DEFAULT_POLL_BUDGET));
    poll_to_completion(&mut fut);
}

/// **Scenario 6.** A volume published TWICE (`seq >= 2`, so
/// `check_chain`'s ancestor loop actually runs) resolves normally while
/// the seam is up, then keeps resolving — fully, from the cache,
/// byte-identical — once every
/// remote operation is refused from index 0 on (`Fault::FailFrom`), the
/// shape a server that goes down and STAYS down leaves behind. The cache
/// is opened through `Cache::open_with_free_space` with an INJECTED
/// `FreeSpace`, never the real filesystem query.
///
/// **The degraded branch is TRAVERSED, not merely an output that happens
/// to match.** `down.store_ops()` is asserted to be EXACTLY 1: the one
/// refused `get_root` for the head root at `resolve_at_verified_impl`'s
/// first line (discovery itself touches no wire at all — the SAME fixed
/// clock on both `HeadContext`s keeps the persisted head hint inside its
/// jittered TTL, so discovery uses that hint). A resolve that fell through
/// to `NoHead`/an error instead would never reach that count with a
/// matching `Ok(seq 2)`, and a resolve that (incorrectly) re-touched the
/// wire for metadata, an ancestor root, or content would push the count
/// above 1 — `down` cannot answer any of those calls, so it would
/// surface as a bare `Err`, not a silent pass.
///
/// *Breaks if:* the degraded fallback is dropped, mis-wired to the wrong
/// trigger, or `check_chain` still reads an ancestor root off the wire —
/// any of which turns this into a bare resolve failure against a store
/// that answers nothing, or a `store_ops()` count above 1.
#[test]
fn server_down_cached_reads_keep_working() {
    println!("{}", scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED));

    let sim = Sim::new();
    let tree_one = seed_tree(&sim, ONE);
    let tree_two = seed_tree(&sim, TWO);
    let first = publish_on(&sim, 0, Faults::none(), tree_one, Policy::default());
    assert_eq!(
        first.ok().seq,
        1,
        "{}",
        scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
    );
    let second = publish_on(&sim, 1, Faults::none(), tree_two, Policy::default());
    assert_eq!(
        second.ok().seq,
        2,
        "{}",
        scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
    );

    // A transport-down degraded serve now requires a VERIFYING reader:
    // the cache dir is path-keyed bytes with no
    // self-verification of its own, so the only trust it can replay
    // offline is the root signature. `key()` is the one publishing
    // key every sim node signs with (`scenario::key`'s own doc), so
    // this is the SAME reader identity a real client configured for
    // this volume would carry.
    let trusted = RootVerifier::trusting(*key().public_key()).unwrap_or_else(|e| panic!("{e}"));

    let scratch = ScratchDir::new();
    let mut warm_cache = server_down_fresh_cache(&scratch);
    let up = sim.node(2, Faults::none());
    let warm_ctx = server_down_head_ctx();
    let mut warm_collected: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let warm = {
        let mut sink = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
            warm_collected.insert(id, bytes.to_vec());
            Ok(())
        };
        let mut fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<_, ResolveError>> + '_>,
        > = Box::pin(resolve_head_verified(
            &up,
            scenario::VOLUME,
            &trusted,
            &warm_ctx,
            Some(&mut warm_cache),
            ResolveTarget::WholeTree,
            &mut sink,
        ));
        poll_to_completion(&mut fut)
    }
    .unwrap_or_else(|e| {
        panic!(
            "the warm resolve must succeed while the seam is up: {e}. {}",
            scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
        )
    });
    assert_eq!(
        warm.seq,
        2,
        "{}",
        scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
    );
    warm_cache.close().unwrap_or_else(|e| panic!("{e}"));

    // Fresh cache handle on the same dir; a NEW node whose schedule
    // refuses every operation from index 0 — the seam is down before
    // this reader issues its first call.
    let mut fresh_cache_handle = server_down_fresh_cache(&scratch);
    let down = sim.node(3, Faults::just(Fault::FailFrom(0)));
    let degraded_ctx = server_down_head_ctx();

    let mut degraded_collected: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let degraded_result = {
        let mut sink = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
            degraded_collected.insert(id, bytes.to_vec());
            Ok(())
        };
        let mut fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<_, ResolveError>> + '_>,
        > = Box::pin(resolve_head_verified(
            &down,
            scenario::VOLUME,
            &trusted,
            &degraded_ctx,
            Some(&mut fresh_cache_handle),
            ResolveTarget::WholeTree,
            &mut sink,
        ));
        poll_to_completion(&mut fut)
    };

    let degraded = degraded_result.unwrap_or_else(|e| {
        panic!(
            "a degraded read must still resolve completely with the seam down: {e}. {}",
            scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
        )
    });

    assert_eq!(
        degraded.seq,
        2,
        "{}",
        scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
    );
    assert_eq!(
        degraded_collected,
        warm_collected,
        "byte-identical content, object for object. {}",
        scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
    );
    assert_eq!(
        down.store_ops(),
        1,
        "the degraded branch must be TRAVERSED, not merely happen to match: exactly one refused \
         wire call (the head root read) and nothing more — a resolve that fell through, or one \
         that re-touched the wire for metadata/ancestor/content, could not have reached \
         Ok(seq 2) with this count. {}",
        scenario::replay(SERVER_DOWN, scenario::DRIVER_SEED)
    );
}

// ------------------------------------------------------------ scenario 7

const DEFER_SWEEP: &str = "deferred_put_released_at_every_boundary_lands_once_or_is_refused";

/// What a held write's release did, read off its `release-root` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Fate {
    /// It landed: the seq was still free.
    Landed,
    /// It was refused: the re-issue had already claimed the seq.
    Refused,
}

/// Every successful write of a root at `seq`, in trace order, as the
/// address it wrote: `put-root … -> ok` and `release-root … -> ok`.
/// More than one is an overwrite.
fn winning_writes(trace: &Trace, seq: u64) -> Vec<(u32, Address)> {
    trace
        .entries()
        .iter()
        .filter(|e| e.outcome == Outcome::Ok)
        .filter_map(|e| match &e.op {
            Op::PutRoot { seq: s, addr, .. } | Op::ReleaseRoot { seq: s, addr, .. }
                if *s == seq =>
            {
                Some((e.node, *addr))
            }
            _ => None,
        })
        .collect()
}

/// The address of the FIRST write of a root at `seq` that reached the
/// store, in trace order: a `put-root` the store answered (`ok` or
/// `failed(already-exists)`), or a held write's `release-root` either
/// way. A `put-root` refused by injection, or held (`failed(deferred)`),
/// did not reach the store at that point and is not a candidate.
fn earliest_store_write(trace: &Trace, seq: u64) -> Option<Address> {
    trace.entries().iter().find_map(|e| match &e.op {
        Op::PutRoot { seq: s, addr, .. }
            if *s == seq
                && matches!(
                    e.outcome,
                    Outcome::Ok | Outcome::Failed(TraceError::AlreadyExists)
                ) =>
        {
            Some(*addr)
        }
        Op::ReleaseRoot { seq: s, addr, .. } if *s == seq => Some(*addr),
        _ => None,
    })
}

/// The publish-then-re-issue driver both deferred scenarios run: node 0
/// publishes [`ONE`] with its commit-point `put_root` held for
/// `release_after` later store operations; if that publish fails, the
/// same node re-issues with [`TWO`] — the edited tree a publisher that
/// gave up would push next, and a DIFFERENT root at the same seq, so an
/// overwrite by the late write changes the stored bytes instead of
/// hiding behind identical ones.
fn publish_with_held_root(
    cas_at: u32,
    release_after: u32,
) -> (Sim, scenario::Published, Option<scenario::Published>) {
    let sim = Sim::new();
    let one = seed_tree(&sim, ONE);
    let two = seed_tree(&sim, TWO);
    let first = publish_on(
        &sim,
        0,
        Faults::just(Fault::DeferPut {
            at: cas_at,
            release_after,
        }),
        one,
        Policy::default(),
    );
    let reissue = first
        .outcome
        .is_err()
        .then(|| publish_on(&sim, 0, Faults::none(), two, Policy::default()));
    (sim, first, reissue)
}

/// **Scenario 7.** A `put_root` whose caller is told it FAILED lands
/// later, at every store-operation boundary of a publish-then-re-issue
/// run. Wherever it is released: it lands exactly once or is refused,
/// the seq it claimed holds exactly one root — the FIRST write to reach
/// it — and the head resolves.
///
/// The release point is swept over every boundary after the held
/// `put_root`, discovered from a run whose write is never released:
/// before the ONE-PROBE RULE's read-back, between the probe and the
/// re-issue, inside the re-issue before its `put_root`, and after it.
/// Measured on this fixture: 9 boundaries, 8 releases landing and 1
/// refused — the one boundary between the re-issue's `put_root` and its
/// hint write. Every earlier release lands, either before the probe, or
/// before the re-issue reads the head (it then advances to seq 2), or
/// inside the re-issue ahead of its `put_root` (which then loses the
/// seq to the late root).
///
/// *Breaks if:* a release overwrites (a second winning write at the seq,
/// and the stored bytes are the late ones), a release goes unrecorded,
/// or the deferral lands its write in the same poll as the `put_root`
/// — the probe then always finds it, the first publish always succeeds,
/// and the refused fate is never reached.
#[test]
fn deferred_put_released_at_every_boundary_lands_once_or_is_refused() {
    println!("{}", scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED));

    let cas_at = {
        let sim = Sim::new();
        let tree = seed_tree(&sim, ONE);
        assert_eq!(
            publish_on(&sim, 0, Faults::none(), tree, Policy::default())
                .ok()
                .seq,
            1
        );
        cas_index(&sim.trace(), 0)
    };

    // Discover the boundaries: a run whose held write is never released
    // counts the store operations that follow it.
    let boundaries = {
        let (sim, first, reissue) = publish_with_held_root(cas_at, u32::MAX);
        let trace = sim.trace();
        assert!(
            first.outcome.is_err() && reissue.is_some(),
            "with the write held for good, the first publish must fail and be re-issued. {}",
            scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
        );
        assert!(
            !trace
                .entries()
                .iter()
                .any(|e| matches!(e.op, Op::ReleaseRoot { .. })),
            "the discovery run released its held write, so it cannot count what follows it"
        );
        let held_at = trace
            .entries()
            .iter()
            .position(|e| e.outcome == Outcome::Failed(TraceError::Deferred))
            .unwrap_or_else(|| panic!("the discovery run held no put_root"));
        let later = trace
            .entries()
            .iter()
            .skip(held_at.saturating_add(1))
            .filter(|e| scenario::is_store_op(&e.op))
            .count();
        u32::try_from(later).unwrap_or(u32::MAX)
    };
    assert!(
        boundaries > 1,
        "only {boundaries} store operation(s) follow the held put_root — no re-issue to race"
    );

    let mut fates: BTreeMap<Fate, u32> = BTreeMap::new();
    for release_after in 0..boundaries {
        let (sim, first, reissue) = publish_with_held_root(cas_at, release_after);
        let trace = sim.trace();
        let (held_seq, held_addr) = trace
            .entries()
            .iter()
            .find_map(|e| match &e.op {
                Op::PutRoot { seq, addr, .. }
                    if e.outcome == Outcome::Failed(TraceError::Deferred) =>
                {
                    Some((*seq, *addr))
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("release after {release_after}: no put_root was held"));

        // The fate is RECORDED, exactly once, for the held write.
        let releases: Vec<&Entry> = trace
            .entries()
            .iter()
            .filter(|e| matches!(e.op, Op::ReleaseRoot { .. }))
            .collect();
        let fate = match releases.as_slice() {
            [only] => match (&only.op, only.outcome) {
                (Op::ReleaseRoot { seq, addr, .. }, outcome)
                    if (*seq, *addr) == (held_seq, held_addr) =>
                {
                    match outcome {
                        Outcome::Ok => Fate::Landed,
                        Outcome::Failed(TraceError::AlreadyExists) => Fate::Refused,
                        other => panic!(
                            "release after {release_after}: a release is landed or refused, \
                             got {other}. {}",
                            scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
                        ),
                    }
                }
                (op, _) => panic!(
                    "release after {release_after}: the release is {op}, not the held write. {}",
                    scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
                ),
            },
            other => panic!(
                "release after {release_after}: {} release entries, expected exactly one:\n{}",
                other.len(),
                trace.render()
            ),
        };

        // Exactly one root at the seq, and it is the FIRST write to
        // reach it — read back from the store, not from the trace alone.
        let winners = winning_writes(&trace, held_seq);
        let stored = resolve_seq(&sim, held_seq).unwrap_or_else(|e| {
            panic!(
                "release after {release_after}: seq {held_seq} does not resolve: {e}. {}",
                scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
            )
        });
        // The expectation is the EARLIEST write to reach the store at
        // the seq, whatever it was told: a model that kept a later
        // writer would record or store that writer, and differ here.
        let earliest = earliest_store_write(&trace, held_seq);
        assert_eq!(
            (
                winners.len(),
                winners.first().map(|(_, a)| *a),
                Some(Address::new(*GrainId::of(&stored.root_bytes).digest())),
            ),
            (1, earliest, earliest),
            "release after {release_after} ({fate:?}): seq {held_seq} must be won exactly once, \
             by the earliest write to reach it ({earliest:?}), and hold that write's bytes; \
             winners {winners:?}. {}",
            scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
        );
        assert_eq!(
            sim.admin().root_seqs(&scenario::volume()).first(),
            Some(&held_seq),
            "release after {release_after}: the held seq holds no root at all"
        );

        // A refusal is the late write arriving AFTER the re-issue took
        // the same seq — asserted, so the class means what it says.
        if fate == Fate::Refused {
            let reissued_same_seq = reissue
                .as_ref()
                .and_then(|p| p.outcome.as_ref().ok())
                .map(|s| s.seq);
            assert_eq!(
                (first.outcome.is_err(), reissued_same_seq),
                (true, Some(held_seq)),
                "release after {release_after}: refused, but not because the re-issue claimed \
                 seq {held_seq} first. {}",
                scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
            );
        }

        let head = resolve(&sim).unwrap_or_else(|e| {
            panic!(
                "release after {release_after}: the head does not resolve: {e}. {}",
                scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
            )
        });
        assert!(
            head.seq >= held_seq,
            "release after {release_after}: the head {} is below the seq the held write claimed",
            head.seq
        );
        let slot = fates.entry(fate).or_default();
        *slot = slot.saturating_add(1);
    }

    // ANTI-VACUITY: both orders happened — a late write that landed
    // before the re-issue could claim its seq, and one refused after it.
    assert!(
        fates.contains_key(&Fate::Landed) && fates.contains_key(&Fate::Refused),
        "the sweep over {boundaries} boundaries reached only {fates:?}: both a landed and a \
         refused release are needed. {}",
        scenario::replay(DEFER_SWEEP, scenario::DRIVER_SEED)
    );
    println!("{boundaries} boundaries: {fates:?}");
}

// ------------------------------------------------------------ scenario 8

const DEFER_EARLY: &str = "deferred_put_released_before_any_reissue_lands_without_an_overwrite";

/// **Scenario 8.** A held `put_root` released BEFORE the publisher
/// re-issues anything lands, and the ONE-PROBE RULE handles it without
/// an overwrite, in both of the places it can land:
///
/// - **before the probe** (`release_after: 0`): the read-back finds the
///   publisher's OWN bytes and the publish reports SUCCESS at the seq —
///   the rule recognising a write it was told had failed;
/// - **between the probe and the re-issue** (`release_after: 1`): the
///   probe answered "nothing there", so the publish reports the outcome
///   as UNRESOLVED — carrying the PUT's own error, but not promoted to
///   it, because nothing here can prove that attempt was the only one
///   sent — and the re-issue then sees the late root and ADVANCES past
///   it — seq 2, parented on the late root — rather than re-claiming the
///   seq.
///
/// *Breaks if:* the deferral lands its write in the same poll as the
/// `put_root` (the second arm's publish then succeeds), or never lands
/// it (the first arm's publish then fails), or the re-issue overwrites
/// the late root.
#[test]
fn deferred_put_released_before_any_reissue_lands_without_an_overwrite() {
    println!("{}", scenario::replay(DEFER_EARLY, scenario::DRIVER_SEED));
    let cas_at = {
        let sim = Sim::new();
        let tree = seed_tree(&sim, ONE);
        let _ = publish_on(&sim, 0, Faults::none(), tree, Policy::default()).ok();
        cas_index(&sim.trace(), 0)
    };

    // ---- arm 1: released before the probe.
    let (sim, first, reissue) = publish_with_held_root(cas_at, 0);
    let trace = sim.trace();
    let probe = probe_entry(&trace, 0, cas_at);
    let summary = first.outcome.as_ref().map(|s| s.seq);
    assert_eq!(
        (summary.ok(), probe.outcome, reissue.is_none()),
        (Some(1), Outcome::Ok, true),
        "released before the probe: the read-back must find the publisher's own root and the \
         publish report success at seq 1, with nothing re-issued; got {:?}. {}",
        first.outcome,
        scenario::replay(DEFER_EARLY, scenario::DRIVER_SEED)
    );
    // The release sits immediately before the probe in the artifact.
    let release_then_probe: Vec<String> = trace
        .entries()
        .iter()
        .filter(|e| e.node == 0)
        .skip_while(|e| e.outcome != Outcome::Failed(TraceError::Deferred))
        .skip(1)
        .take(2)
        .map(|e| format!("{} -> {}", e.op, e.outcome))
        .collect();
    assert!(
        release_then_probe
            .first()
            .is_some_and(|l| l.starts_with("release-root ") && l.ends_with("-> ok"))
            && release_then_probe
                .get(1)
                .is_some_and(|l| l.starts_with("get-root ")),
        "expected the landed release and then the probe: {release_then_probe:?}"
    );
    let head = resolve(&sim).unwrap_or_else(|e| panic!("the landed root must resolve: {e}"));
    assert_eq!(
        (head.seq, winning_writes(&trace, 1).len()),
        (1, 1),
        "{}",
        scenario::replay(DEFER_EARLY, scenario::DRIVER_SEED)
    );

    // ---- arm 2: released after the probe, before the re-issue.
    let (sim, first, reissue) = publish_with_held_root(cas_at, 1);
    let trace = sim.trace();
    let probe = probe_entry(&trace, 0, cas_at);
    assert!(
        matches!(
            (&first.outcome, probe.outcome),
            (
                Err(PublishError::Unresolved {
                    put_error: RootStoreError::Backend(m)
                }),
                Outcome::Absent
            ) if m.as_str() == INJECTED
        ),
        "released after the probe: the probe must find nothing and the publish report the \
         outcome as unresolved, carrying the PUT's own error; got {:?} with probe {}. {}",
        first.outcome,
        probe.outcome,
        scenario::replay(DEFER_EARLY, scenario::DRIVER_SEED)
    );
    let late_root = resolve_seq(&sim, 1)
        .unwrap_or_else(|e| panic!("the late root landed before the re-issue: {e}"))
        .root_bytes;
    let reissued = reissue
        .unwrap_or_else(|| panic!("a failed publish is re-issued"))
        .ok();
    let head = resolve(&sim).unwrap_or_else(|e| panic!("the advanced head must resolve: {e}"));
    assert_eq!(
        (reissued.seq, head.seq, head.doc.parent),
        (2, 2, Some(GrainId::of(&late_root))),
        "the re-issue must advance past the late root and link to it, not re-claim seq 1. {}",
        scenario::replay(DEFER_EARLY, scenario::DRIVER_SEED)
    );
    assert_eq!(
        (
            winning_writes(&trace, 1).len(),
            resolve_seq(&sim, 1).map(|o| o.root_bytes == late_root).ok()
        ),
        (1, Some(true)),
        "seq 1 must still hold the late root, written once. {}",
        scenario::replay(DEFER_EARLY, scenario::DRIVER_SEED)
    );
}

// ------------------------------------------------------------ scenario 9

const FLOOR: &str = "deleting_the_root_a_reader_holds_as_its_floor_never_serves_a_lower_head";

/// One verified, cached resolve of the head, on a fresh node, through
/// the cache dir at `scratch` — scenario 6's reader, driven the same
/// way.
fn cached_read(
    sim: &Sim,
    node: u32,
    scratch: &ScratchDir,
) -> Result<granary_client::ResolveOutcome, ResolveError> {
    let trusted = RootVerifier::trusting(*key().public_key()).unwrap_or_else(|e| panic!("{e}"));
    let mut cache = server_down_fresh_cache(scratch);
    let store = sim.node(node, Faults::none());
    let ctx = server_down_head_ctx();
    let result = {
        let mut sink = |_: GrainId, _: &[u8]| -> Result<(), String> { Ok(()) };
        let mut fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<_, ResolveError>> + '_>,
        > = Box::pin(resolve_head_verified(
            &store,
            scenario::VOLUME,
            &trusted,
            &ctx,
            Some(&mut cache),
            ResolveTarget::WholeTree,
            &mut sink,
        ));
        poll_to_completion(&mut fut)
    };
    cache.close().unwrap_or_else(|e| panic!("{e}"));
    result
}

/// The cache dir's freshness floor for the scenario volume.
fn floor_of(scratch: &ScratchDir) -> Option<u64> {
    let cache = server_down_fresh_cache(scratch);
    let floor = cache.read_anchor(&scenario::volume()).map(|a| a.seq);
    cache.close().unwrap_or_else(|e| panic!("{e}"));
    floor
}

/// **Scenario 9.** An operator deletes the root a reader holds as its
/// freshness floor, and the reader never reports a head below that
/// floor afterwards. What it does instead is the existing contract
/// (`granary_client`'s head discovery): the store answered, so this is
/// not a transport-down degraded read and the cache is not consulted
/// for the head; a candidate below the floor is refused as
/// `StaleHead`, and with no candidate at all the answer is `NoHead`.
/// The floor itself never moves down.
///
/// Two arms, because the literal case cannot reach "below":
///
/// - **seq 1 is the floor and the only root.** After the delete there
///   is no root at all, and nothing below seq 1 can be a head (seq 0
///   never is), so the reader answers `NoHead`.
/// - **seq 2 is the floor, seq 1 survives.** Deleting seq 2 leaves
///   `max_seq` answering 1, a real candidate BELOW the floor — the arm
///   in which a reader that ignored its floor would serve the older
///   head. It answers `StaleHead { candidate: 1, anchor: 2 }`.
///
/// *Breaks if:* the delete is a no-op (both arms then resolve the
/// deleted head), or the floor stops gating a candidate that came from
/// the `max_seq` retry.
#[test]
fn deleting_the_root_a_reader_holds_as_its_floor_never_serves_a_lower_head() {
    println!("{}", scenario::replay(FLOOR, scenario::DRIVER_SEED));
    let vol = scenario::volume();

    // ---- arm 1: the floor is seq 1, the only root.
    let sim = Sim::new();
    let tree = seed_tree(&sim, ONE);
    assert_eq!(
        publish_on(&sim, 0, Faults::none(), tree, Policy::default())
            .ok()
            .seq,
        1
    );
    let scratch = ScratchDir::new();
    let warm = cached_read(&sim, 2, &scratch)
        .unwrap_or_else(|e| panic!("the warm read must resolve: {e}"));
    assert_eq!((warm.seq, floor_of(&scratch)), (1, Some(1)));
    assert!(
        sim.admin().delete_root(&vol, 1),
        "seq 1 was there to delete"
    );
    let after = cached_read(&sim, 3, &scratch);
    assert!(
        matches!(after, Err(ResolveError::NoHead)),
        "with its floor's root deleted and nothing else in the volume, the reader must answer \
         NoHead — not the deleted head from its cache, not anything below its floor; got {:?}. {}",
        after.map(|o| o.seq),
        scenario::replay(FLOOR, scenario::DRIVER_SEED)
    );
    assert_eq!(
        floor_of(&scratch),
        Some(1),
        "the floor must never move down"
    );

    // ---- arm 2: the floor is seq 2, and seq 1 is still there.
    let sim = Sim::new();
    let one = seed_tree(&sim, ONE);
    let two = seed_tree(&sim, TWO);
    assert_eq!(
        publish_on(&sim, 0, Faults::none(), one, Policy::default())
            .ok()
            .seq,
        1
    );
    assert_eq!(
        publish_on(&sim, 1, Faults::none(), two, Policy::default())
            .ok()
            .seq,
        2
    );
    let scratch = ScratchDir::new();
    let warm = cached_read(&sim, 2, &scratch)
        .unwrap_or_else(|e| panic!("the warm read must resolve: {e}"));
    assert_eq!((warm.seq, floor_of(&scratch)), (2, Some(2)));
    assert!(
        sim.admin().delete_root(&vol, 2),
        "seq 2 was there to delete"
    );
    // The premise: a candidate below the floor now exists.
    assert!(
        resolve(&sim).is_ok_and(|o| o.seq == 1),
        "a cacheless reader must now land on seq 1, or this arm has no lower head to refuse"
    );
    let after = cached_read(&sim, 3, &scratch);
    assert!(
        matches!(
            after,
            Err(ResolveError::StaleHead {
                candidate: 1,
                anchor: 2
            })
        ),
        "a reader holding floor 2 must refuse seq 1 as StaleHead, never serve it; got {:?}. {}",
        after.map(|o| o.seq),
        scenario::replay(FLOOR, scenario::DRIVER_SEED)
    );
    assert_eq!(
        floor_of(&scratch),
        Some(2),
        "the floor must never move down"
    );
}

// ----------------------------------------------------------- scenario 10

const SQUAT: &str = "a_squatted_seq_deleted_by_the_operator_falls_back_to_the_honest_head";

/// `max_seq`, asked through a fresh fault-free handle.
fn max_seq_of(sim: &Sim) -> Option<u64> {
    let store = sim.oracle();
    let task: granary_sim::sched::Task<Result<Option<u64>, RootStoreError>> =
        Box::pin(async move { store.max_seq(scenario::VOLUME).await });
    scenario::run(scenario::DRIVER_SEED, task).unwrap_or_else(|e| panic!("max_seq failed: {e}"))
}

/// **Scenario 10.** A root planted at a seq ABOVE the honest head — the
/// next seq, one far above, the highest legal seq, and the reserved
/// `u64::MAX` — is an operator-recoverable squat: once it is deleted,
/// `max_seq` answers the honest head again, the volume resolves there
/// with the honest root's bytes, and the next publish claims the seq
/// after it.
///
/// While a non-reserved squat stands, `max_seq` answers IT — asserted,
/// so the squat is known to have been in effect. `u64::MAX` is the
/// exception by design: `max_seq` never answers the reserved seq, so
/// that plant is visible only in the admin listing, and the recovery
/// there is asserted as the listing emptying.
///
/// *Breaks if:* the delete is a no-op (`max_seq` keeps answering the
/// squat, and the next publish chains onto it), or a delete removes
/// more than the one seq.
#[test]
fn a_squatted_seq_deleted_by_the_operator_falls_back_to_the_honest_head() {
    println!("{}", scenario::replay(SQUAT, scenario::DRIVER_SEED));
    let vol = scenario::volume();
    for squat in [2, 1_000, u64::MAX - 1, u64::MAX] {
        let sim = Sim::new();
        let one = seed_tree(&sim, ONE);
        let two = seed_tree(&sim, TWO);
        let honest = publish_on(&sim, 0, Faults::none(), one, Policy::default()).ok();
        assert_eq!(honest.seq, 1);
        let honest_root = resolve(&sim)
            .unwrap_or_else(|e| panic!("the honest head must resolve: {e}"))
            .root_bytes;

        assert!(
            sim.admin()
                .plant_root(&vol, squat, b"not a root anyone signed".to_vec()),
            "squat {squat}: the seq was free"
        );
        let expected_during = if squat == u64::MAX { 1 } else { squat };
        assert_eq!(
            (max_seq_of(&sim), sim.admin().root_seqs(&vol)),
            (Some(expected_during), vec![1, squat]),
            "squat {squat}: the plant is not in effect. {}",
            scenario::replay(SQUAT, scenario::DRIVER_SEED)
        );

        assert!(
            sim.admin().delete_root(&vol, squat),
            "squat {squat}: deleted"
        );
        assert_eq!(
            (max_seq_of(&sim), sim.admin().root_seqs(&vol)),
            (Some(1), vec![1]),
            "squat {squat}: after the delete max_seq must fall back to the honest head. {}",
            scenario::replay(SQUAT, scenario::DRIVER_SEED)
        );
        let head = resolve(&sim).unwrap_or_else(|e| {
            panic!(
                "squat {squat}: the honest head must resolve after the delete: {e}. {}",
                scenario::replay(SQUAT, scenario::DRIVER_SEED)
            )
        });
        assert!(
            head.seq == 1 && head.root_bytes == honest_root,
            "squat {squat}: resolution landed on seq {} rather than the honest root. {}",
            head.seq,
            scenario::replay(SQUAT, scenario::DRIVER_SEED)
        );
        let next = publish_on(&sim, 1, Faults::none(), two, Policy::default()).ok();
        let advanced =
            resolve(&sim).unwrap_or_else(|e| panic!("squat {squat}: seq 2 must resolve: {e}"));
        assert_eq!(
            (next.seq, advanced.doc.parent),
            (2, Some(GrainId::of(&honest_root))),
            "squat {squat}: publishing must resume on the honest chain. {}",
            scenario::replay(SQUAT, scenario::DRIVER_SEED)
        );
    }
}

// ----------------------------------------------------------- scenario 11

const DEFER_RACE: &str = "a_deferred_put_in_a_concurrent_race_never_leaves_two_winners";

/// **Scenario 11.** The concurrent race with node 0's `put_root` HELD
/// (`scenario::deferred_race`, the body `sim-replay` runs for a deferred
/// seed), over the same 64 schedules scenario 3 sweeps, each with its
/// own release point. Whatever the interleaving and wherever the held
/// write is released:
///
/// - every seq anyone attempted has exactly ONE winning root write — a
///   `put-root … -> ok`, or a held write whose release landed;
/// - no release overwrote: walking the trace in order, a release is
///   refused exactly when its seq is already occupied, and lands exactly
///   when it is not — and no `put-root` succeeds at an occupied seq;
/// - the root stored at each seq is the winner's bytes, and the head
///   resolves through the oracle.
///
/// *Breaks if:* a release overwrites or lands on an occupied seq, a
/// landed release goes uncounted as a winning write (the held write and
/// a later PUT would then both look like the only winner), or a late
/// write leaves the volume unresolvable.
#[test]
fn a_deferred_put_in_a_concurrent_race_never_leaves_two_winners() {
    const SEEDS: u64 = 64;
    println!(
        "sweeping deferred seeds 0..{SEEDS} from {}",
        scenario::replay(DEFER_RACE, 0)
    );
    let mut fates: BTreeSet<String> = BTreeSet::new();
    for seed in 0..SEEDS {
        let scenario::Raced { sim, .. } = scenario::deferred_race(seed);
        let trace = sim.trace();
        assert_eq!(
            scenario::held_puts(&trace),
            1,
            "seed {seed}: the run held no put_root. {}",
            scenario::replay(DEFER_RACE, seed)
        );

        // Create-only, walked in trace order.
        let mut occupied: BTreeSet<u64> = BTreeSet::new();
        for e in trace.entries() {
            match &e.op {
                Op::PutRoot { seq, .. } if e.outcome == Outcome::Ok => {
                    assert!(
                        occupied.insert(*seq),
                        "seed {seed}: a put_root succeeded at occupied seq {seq}. {}",
                        scenario::replay(DEFER_RACE, seed)
                    );
                }
                Op::ReleaseRoot { seq, .. } => {
                    let expected = if occupied.contains(seq) {
                        Outcome::Failed(TraceError::AlreadyExists)
                    } else {
                        Outcome::Ok
                    };
                    assert_eq!(
                        e.outcome,
                        expected,
                        "seed {seed}: the release at seq {seq} must be refused exactly when the \
                         seq is occupied. {}",
                        scenario::replay(DEFER_RACE, seed)
                    );
                    occupied.insert(*seq);
                    fates.insert(e.outcome.to_string());
                }
                _ => {}
            }
        }

        // One winner per attempted seq, holding the winner's bytes.
        let attempts = root_attempts(&trace);
        let seqs: BTreeSet<u64> = attempts.iter().map(|a| a.seq).collect();
        for seq in seqs {
            let winners: Vec<&RootAttempt> =
                attempts.iter().filter(|a| a.seq == seq && a.won).collect();
            let stored = resolve_seq(&sim, seq)
                .ok()
                .map(|o| *GrainId::of(&o.root_bytes).digest());
            assert_eq!(
                (winners.len(), stored),
                (1, winners.first().map(|a| a.addr)),
                "seed {seed}: seq {seq} must have exactly one winning root write and store its \
                 bytes; winners {winners:?}. {}",
                scenario::replay(DEFER_RACE, seed)
            );
        }
        assert!(
            resolve(&sim).is_ok(),
            "seed {seed}: the head does not resolve after the deferred race. {}",
            scenario::replay(DEFER_RACE, seed)
        );
    }
    // ANTI-VACUITY: both fates of a held write occurred in the sweep.
    assert_eq!(
        fates.len(),
        2,
        "the deferred race reached only {fates:?} over {SEEDS} seeds"
    );
}
