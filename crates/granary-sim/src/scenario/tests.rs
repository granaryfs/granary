// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::scenario` — the shared publish fixture the scenarios
//! run on: the in-memory tree, the pinned key/identity/clock, one
//! driver, and the trace queries a scenario uses to discover what
//! a run did.
//!
//! Out-of-line: `granary-sim`'s non-test artifact has its
//! own `tests/` directory
//! (`crates/granary-sim/tests/replay_across_processes.rs`,
//! `scenarios.rs`) and its own `[[bin]]`
//! (`src/bin/sim-replay.rs`) — either alone is enough. What
//! does NOT apply: nothing in the workspace depends on
//! `granary-sim`; `granary-sim` depends on `granary-client`,
//! not the reverse. So the module's own tests move out of
//! the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{ONE, TWO, WIDE, WIDE_PLUS, identity, seed_tree, volume};
use crate::fakes::Sim;

/// The property the concurrency scenario rests on (module doc): two
/// nodes must not share a writer identity, or they mint identical
/// root bytes and the loser of a race reads its own bytes back and
/// reports success. A silently-truncated write into the identity's
/// tail would collapse every node onto one value, and this is what
/// catches it.
#[test]
fn identities_are_distinct_per_node() {
    let nodes = [0u32, 1, 2, 3, 7, 4095, u32::MAX - 1, u32::MAX];
    for (i, a) in nodes.iter().enumerate() {
        for b in nodes.iter().skip(i + 1) {
            assert_ne!(
                identity(*a),
                identity(*b),
                "nodes {a} and {b} share a writer identity"
            );
        }
    }
    assert_eq!(identity(3), identity(3), "the same node, the same identity");
}

/// A "delta" fixture whose prefix moved is a REWRITE, and every
/// ledger assertion built on it would be measuring the wrong thing.
#[test]
fn the_longer_fixtures_extend_the_shorter_ones() {
    assert_eq!(TWO.len(), ONE.len() + 1);
    assert!(TWO.starts_with(ONE), "TWO must extend ONE");
    assert_eq!(WIDE_PLUS.len(), WIDE.len() + 1);
    assert!(WIDE_PLUS.starts_with(WIDE), "WIDE_PLUS must extend WIDE");
}

/// The fixture builds, and a wider tree really is wider — a tree
/// builder that silently produced one node would make an operation
/// ledger vacuous.
#[test]
fn the_fixture_trees_are_distinct_and_grow() {
    let sim = Sim::new();
    let one = seed_tree(&sim, ONE);
    let two = seed_tree(&sim, TWO);
    let wide = seed_tree(&sim, WIDE);
    assert_ne!(one, two);
    assert_ne!(two, wide);
    assert_eq!(volume().as_str(), super::VOLUME);
}

/// The pin [`super::DEFERRED_RELEASE_SPAN`]'s doc rests on: every
/// deferred replay seed holds exactly one write and records its fate
/// inside the run — a seed whose release point the run never reached
/// would replay a hold with no outcome, which is the silent case the
/// fault exists to rule out. Over the sweep both fates occur, or the
/// seed space carries only one of the two outcomes a replay can
/// diverge on.
#[test]
fn every_deferred_replay_seed_records_the_fate_of_its_held_write() {
    use crate::trace::{Op, Outcome, TraceError};
    const SEEDS: u64 = 64;
    let mut fates = std::collections::BTreeSet::new();
    for seed in 0..SEEDS {
        let sim = super::replay_run(seed | super::DEFERRED_SEEDS)
            .unwrap_or_else(|e| panic!("deferred seed {seed}: {e}"));
        let trace = sim.trace();
        let held: Vec<(u32, Outcome)> = trace
            .entries()
            .iter()
            .filter(|e| {
                matches!(e.op, Op::PutRoot { .. })
                    && e.outcome == Outcome::Failed(TraceError::Deferred)
            })
            .map(|e| (e.node, e.outcome))
            .collect();
        let released: Vec<(u32, Outcome)> = trace
            .entries()
            .iter()
            .filter(|e| matches!(e.op, Op::ReleaseRoot { .. }))
            .map(|e| (e.node, e.outcome))
            .collect();
        assert_eq!(
            (held.len(), released.len()),
            (1, 1),
            "seed {seed}: expected one held put_root and one release, got held {held:?}, \
             released {released:?}:\n{}",
            trace.render()
        );
        let fate = released.first().map(|(_, o)| *o);
        assert!(
            matches!(
                fate,
                Some(Outcome::Ok | Outcome::Failed(TraceError::AlreadyExists))
            ),
            "seed {seed}: a release is landed or refused, got {fate:?}"
        );
        fates.insert(format!("{fate:?}"));
    }
    assert_eq!(
        fates.len(),
        2,
        "the deferred seeds reach only {fates:?}: both fates must be in the replayed seed space"
    );
}

/// Only operations a node ISSUED are handoffs: a release recorded under
/// node 0 at a boundary node 1's operation reached, and an admin call
/// between two operations of one node, are not switches the scheduler
/// made — counting them would inflate the interleaving measure a
/// concurrency scenario's anti-vacuity floor rests on.
#[test]
fn a_release_or_an_admin_call_is_not_a_handoff() {
    use crate::trace::{Address, Op, Outcome, Trace, TraceError, Volume};
    let vol = || Volume::new("demo").unwrap_or_else(Volume::rejected);
    let addr = Address::new([0xaa; 32]);
    let mut t = Trace::new();
    t.record(1, Op::MaxSeq { volume: vol() }, Outcome::Ok);
    t.record(
        0,
        Op::ReleaseRoot {
            volume: vol(),
            seq: 1,
            addr,
        },
        Outcome::Failed(TraceError::AlreadyExists),
    );
    t.record(
        1,
        Op::GetRoot {
            volume: vol(),
            seq: 1,
        },
        Outcome::Ok,
    );
    t.record(
        Sim::ADMIN_NODE,
        Op::AdminListRoots { volume: vol() },
        Outcome::Ok,
    );
    t.record(1, Op::MaxSeq { volume: vol() }, Outcome::Ok);
    assert_eq!(super::handoffs(&t), 0, "{}", t.render());
    // …while a genuine switch between issuing nodes still counts.
    t.record(0, Op::MaxSeq { volume: vol() }, Outcome::Ok);
    assert_eq!(super::handoffs(&t), 1, "{}", t.render());
}
