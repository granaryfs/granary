// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::resolve::budget` — the modelled costs and
//! the running charge that admits or refuses against them.
//!
//! Out-of-line, one flat level under `budget`. Two rows, by the
//! caller map: the constants' pin and the node charge's
//! boundary. A third row touches `MetadataBudget` and drives
//! `resolve_at`, so it is the parent's under the entry-point
//! rule, and the three `structure` rows that construct a
//! `MetadataBudget` by literal stay with structure — which is
//! why the struct's fields are `pub(super)` rather than private.
//!
//! No `#![expect(clippy::disallowed_methods)]`: neither row calls a
//! banned method.
#![cfg(test)]

use super::*;

/// Behavioural row pinning the chosen ceiling model: the numbers, not
/// a relation between them.
#[test]
fn the_metadata_budget_constants_are_pinned() {
    assert_eq!(METADATA_BUDGET_BYTES, 268_435_456);
    assert_eq!(ENTRY_COST_BYTES, 128);
}

/// The metadata admission boundary, on the budget alone. With seven nodes
/// already retained, a structure-node charge whose total is EXACTLY
/// `METADATA_BUDGET_BYTES` admits (only `>` refuses), and one byte
/// more refuses with `attempted` one past the budget. The general
/// predicate reads the SAME total: a meta fetch
/// declared at the node ceiling plus one node's overhead lands on
/// the same two verdicts, so the seven held nodes are in ITS sum too.
#[test]
fn the_node_charge_admits_at_the_boundary_and_refuses_one_past_it() {
    let worst = u64::from(MANIFEST_NODE_MAX_BYTES);
    let held: usize = 7;
    let held_cost = 7 * NODE_COST_BYTES;
    let at_boundary = MetadataBudget {
        retained_bytes: METADATA_BUDGET_BYTES - worst - NODE_COST_BYTES - held_cost,
        entries_len: 0,
        retained_nodes: held,
    };
    at_boundary
        .charge_before_structure_node(worst)
        .unwrap_or_else(|e| panic!("exactly the budget admits: {e}"));
    at_boundary
        .charge_before_fetch(worst + NODE_COST_BYTES)
        .unwrap_or_else(|e| panic!("the meta predicate counts the held nodes: {e}"));

    let one_past = MetadataBudget {
        retained_bytes: at_boundary.retained_bytes + 1,
        entries_len: 0,
        retained_nodes: held,
    };
    for (what, verdict) in [
        (
            "structure node",
            one_past.charge_before_structure_node(worst),
        ),
        (
            "meta fetch",
            one_past.charge_before_fetch(worst + NODE_COST_BYTES),
        ),
    ] {
        match verdict {
            Err(ResolveError::MetadataBudgetExceeded { attempted }) => assert_eq!(
                attempted,
                METADATA_BUDGET_BYTES + 1,
                "{what}: one byte past the budget"
            ),
            other => panic!("{what}: expected MetadataBudgetExceeded, got {other:?}"),
        }
    }
}
