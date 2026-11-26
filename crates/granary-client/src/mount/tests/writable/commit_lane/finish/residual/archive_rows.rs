// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Discard and reconcile over stores left by refused recovery.

use super::super::release::archive_rows::{
    discard_and_reconcile, journal_shape, retained_complete,
};
use super::*;
use granary_core::overlay_discard::Outcome as DiscardOutcome;

type Fixture = fn() -> Stopped;

/// Every store a refused or fenced recovery leaves must be plannable and
/// discardable, and reconciling it must write and send nothing (the helper
/// asserts that). A landing the journal recorded reconciles as landed. The
/// twelve stores run in four rows so each stays inside the per-test budget.
fn assert_discards_and_reconciles(fixtures: &[(&str, Fixture)]) {
    let mut table = Vec::new();
    for (case, fixture) in fixtures {
        let stopped = fixture();
        let shape = journal_shape(&stopped);
        let record = retained_complete(&stopped);
        let reconciled = discard_and_reconcile(&stopped);
        let outcome = reconciled.as_ref().map(|result| result.facts());
        assert!(
            matches!(&outcome, Ok(((DiscardOutcome::Live(_), DiscardOutcome::Moved), 1, rows)) if rows == &["landed"]),
            "{case}: journal {shape:?}, record complete {record:?}, discard and reconcile {outcome:?}",
        );
        table.push((*case, outcome.unwrap().0));
    }
    assert_eq!(table.len(), fixtures.len());
    eprintln!(
        "{} stores planned, moved and reconciled to one landed row: {table:?}",
        table.len()
    );
}

#[test]
fn discard_admits_sealed_and_unrecorded_stores() {
    assert_discards_and_reconciles(&[
        ("sealed", || sealed(false, DIRTY, 0)),
        ("sealed, head advanced", || sealed(true, DIRTY, 0)),
        ("b5 without record", b5_without_record),
    ]);
}

#[test]
fn discard_admits_collision_stores_valid_parent_kind() {
    assert_discards_and_reconciles(&[
        ("collision valid", || collision_disposition("valid")),
        ("collision parent", || collision_disposition("parent")),
        ("collision kind", || collision_disposition("kind")),
    ]);
}

#[test]
fn discard_admits_collision_stores_gone_parent_subtree_forged() {
    assert_discards_and_reconciles(&[
        ("collision gone-parent", || {
            collision_disposition("gone-parent")
        }),
        ("collision subtree", || collision_disposition("subtree")),
        ("collision forged", || collision_disposition("forged")),
    ]);
}

#[test]
fn discard_admits_partial_missing_and_padded_stores() {
    assert_discards_and_reconciles(&[
        ("collision partial", || collision_disposition("partial")),
        ("collision missing", || collision_disposition("missing")),
        ("padded disposition", || padded_disposition(3)),
    ]);
}
