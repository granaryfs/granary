// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Discard and reconcile over stores left by a writable mount.

use super::*;
use crate::{
    ArchiveReconciliation, DiscardError, OverlayRefusal, discard_overlay,
    overlay_discard::tests::{Entry, claim_healthy_store, put, snapshot},
};
use granary_core::{
    overlay_discard::{Outcome as DiscardOutcome, parse_hex},
    overlay_ownership::Operation,
};
use std::path::{Path, PathBuf};

#[expect(
    clippy::disallowed_methods,
    reason = "use the physical path to this test-owned store"
)]
fn store_root(stopped: &Stopped) -> PathBuf {
    stopped.paths.store.canonicalize().unwrap()
}

fn selection(
    stopped: &Stopped,
) -> (
    [u8; 32],
    granary_core::root::VolumeName,
    granary_core::retained_submission::Scope,
) {
    let input = input(&stopped.tree, &stopped.paths);
    let scope = input.scope.clone().unwrap();
    (
        parse_hex(&scope.digest().unwrap()).unwrap(),
        input.volume.clone(),
        scope,
    )
}

/// The journal's boundary and landing records, in order.
pub(in crate::mount::tests::writable::commit_lane::finish) fn journal_shape(
    stopped: &Stopped,
) -> Vec<String> {
    let input = input(&stopped.tree, &stopped.paths);
    let (_, records) = captured_records(&stopped.paths, &input);
    records
        .iter()
        .filter_map(|record| match record {
            Record::CommitBoundary { .. } => Some("CommitBoundary".to_owned()),
            Record::ProjectedBoundary { .. } => Some("ProjectedBoundary".to_owned()),
            Record::LandedCommit { .. } => Some("LandedCommit".to_owned()),
            _ => None,
        })
        .collect()
}

/// Whether the volume's retained record is complete, if it exists.
pub(in crate::mount::tests::writable::commit_lane::finish) fn retained_complete(
    stopped: &Stopped,
) -> Option<bool> {
    let input = input(&stopped.tree, &stopped.paths);
    let mut store = Store::open(&stopped.paths.store).unwrap();
    store
        .publications_read_only(input.euid)
        .unwrap()
        .observe(input.scope.as_ref().unwrap(), &input.volume)
        .unwrap()
        .map(|record| record.is_complete())
}

#[derive(Debug)]
pub(in crate::mount::tests::writable::commit_lane::finish) struct Reconciled {
    outcomes: (DiscardOutcome, DiscardOutcome),
    evidence: ArchiveRows,
}

#[derive(Debug)]
struct ArchiveRows {
    bindings: Vec<(String, bool, bool)>,
    rows: Vec<String>,
}

/// Plan, discard with the printed tuple, then reconcile through the
/// fixture's authority. The reconcile half must change no byte of the store
/// and send nothing. Local settlement must also leave authority reads unchanged.
pub(in crate::mount::tests::writable::commit_lane::finish) fn discard_and_reconcile(
    stopped: &Stopped,
) -> Result<Reconciled, String> {
    let root = store_root(stopped);
    let (scope, volume, _) = selection(stopped);
    let plan =
        discard_overlay(&root, scope, &volume, None).map_err(|error| format!("plan: {error}"))?;
    let tuple = (plan.name.writer, plan.name.incarnation);
    let moved = discard_overlay(&root, scope, &volume, Some(tuple))
        .map_err(|error| format!("discard: {error}"))?;
    Ok(Reconciled {
        outcomes: (plan.outcome, moved.outcome),
        evidence: reconcile_archived(stopped, tuple)?,
    })
}

fn reconcile_archived(
    stopped: &Stopped,
    tuple: ([u8; 16], [u8; 32]),
) -> Result<ArchiveRows, String> {
    let root = store_root(stopped);
    let (scope, volume, route) = selection(stopped);
    let authority_reads = || {
        let state = stopped.state.lock().unwrap();
        (state.probes, state.root_reads)
    };
    let before = snapshot(&root);
    let sent = counted(stopped);
    let reads = authority_reads();
    let opened = ArchiveReconciliation::open(&root, scope, &volume, tuple);
    let result = opened
        .map(|evidence| {
            let authority = Authority::new(&stopped.tree, &stopped.state).with_publication();
            let key = SigningKey::from_seed(&stopped.tree.seed).unwrap();
            let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
            let rows = runtime().block_on(crate::overlay_discard::probe_archive_rows(
                &evidence,
                &authority,
                Some(&route),
                &keys,
            ));
            ArchiveRows {
                bindings: crate::overlay_discard::archive_publication_bindings(&evidence),
                rows,
            }
        })
        .map_err(|error| format!("reconcile open: {error}"));
    let settled_locally = result.as_ref().is_ok_and(|archive| archive.rows.is_empty());
    assert_eq!(
        (
            snapshot(&root),
            counted(stopped),
            settled_locally.then(authority_reads)
        ),
        (before, sent, settled_locally.then_some(reads)),
        "reconcile changed the store, sent a mutation, or read the authority during local settlement",
    );
    result
}

impl Reconciled {
    pub(in crate::mount::tests::writable::commit_lane::finish) fn facts(
        &self,
    ) -> ((DiscardOutcome, DiscardOutcome), usize, Vec<&str>) {
        (self.outcomes, self.evidence.bindings.len(), self.statuses())
    }

    fn statuses(&self) -> Vec<&str> {
        self.evidence
            .rows
            .iter()
            .map(|row| row.split('\t').nth(6).unwrap())
            .collect()
    }
}

#[test]
fn reconcile_settles_a_journal_that_never_published() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let stopped = stop(fixture);
    assert_eq!(
        (
            journal_shape(&stopped),
            retained_complete(&stopped),
            counted(&stopped).1
        ),
        (Vec::new(), None, 0),
        "no boundary or publication was recorded or sent",
    );
    let result = discard_and_reconcile(&stopped);
    assert!(
        matches!(&result, Ok(settled) if matches!(
            settled.facts(),
            ((DiscardOutcome::Live(_), DiscardOutcome::Moved), 0, rows) if rows.is_empty()
        )),
        "dirty bytes that never published must archive and settle with zero rows: {result:?}",
    );
}

#[test]
fn reconcile_settles_a_completed_commit_left_by_a_crash() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let lane = construct_commit(&fixture.engine, &fixture.runtime, 70).unwrap();
    let committed = drive_commit(&fixture.engine, &fixture.runtime, &lane, 71);
    assert!(landed(&committed), "the commit lands: {committed:?}");
    let stopped = stop(fixture);
    let root = store_root(&stopped);
    let (scope, volume, _) = selection(&stopped);
    let plan = discard_overlay(&root, scope, &volume, None).map_err(DiscardError::reason);
    assert_eq!(
        (journal_shape(&stopped), retained_complete(&stopped), plan),
        (Vec::new(), Some(true), Err(OverlayRefusal::NotEligible)),
        "the completed commit left a healthy unclaimed overlay",
    );
    let area = overlay_area(&stopped.paths, &input(&stopped.tree, &stopped.paths));
    let tuple = claim_healthy_store(&root, &area, scope, &volume);
    let result = reconcile_archived(&stopped, tuple);
    assert!(
        matches!(&result, Ok(settled) if settled.bindings.is_empty() && settled.rows.is_empty()),
        "an already claimed completed commit must settle with zero rows: {result:?}",
    );
}

#[test]
fn reconcile_settles_dirty_bytes_after_a_committed_cycle() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let (outcome, stopped) = shut_down_as(
        fixture,
        Trigger::SessionEnd,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
    );
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
    let mut fixture = remount(stopped, 41).unwrap();
    create(fixture.ready.backend_for_test(), "b", DIRTY);
    let stopped = stop(fixture);
    assert_eq!(
        (journal_shape(&stopped), retained_complete(&stopped)),
        (Vec::new(), Some(true)),
        "the journal has no boundaries and the retained publication is complete",
    );
    let result = discard_and_reconcile(&stopped);
    assert!(
        matches!(&result, Ok(settled) if matches!(
            settled.facts(),
            ((DiscardOutcome::Live(_), DiscardOutcome::Moved), 0, rows) if rows.is_empty()
        )),
        "new dirty bytes after a completed commit must archive and settle with zero rows: {result:?}",
    );
}

#[test]
fn reconcile_settles_with_an_unanswered_register() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let clock = Time(Arc::clone(&fixture.state));
    fixture
        .mediator()
        .with(|store| {
            let root = store.snapshot().root.clone();
            let request = store.prepare_registration(&root, vec![], &clock, |_, _| true)?;
            store.dispatch(&request, &clock)
        })
        .unwrap();
    let stopped = stop(fixture);
    let carrier = carrier(&stopped);
    let pending = carrier.pending.last().unwrap();
    assert_eq!(
        (
            journal_shape(&stopped),
            retained_complete(&stopped),
            pending.operation,
            pending.terminal,
            pending.answered,
        ),
        (Vec::new(), None, Operation::Register, false, false),
        "only the ownership registration can still land",
    );
    let result = discard_and_reconcile(&stopped);
    assert!(
        matches!(&result, Ok(settled) if matches!(
            settled.facts(),
            ((DiscardOutcome::Live(_), DiscardOutcome::Moved), 0, rows) if rows.is_empty()
        )),
        "an unanswered Register must allow zero-row settlement: {result:?}",
    );
}

/// Every publication the authority refused before a write is not landed.
#[test]
fn reconcile_classifies_a_refused_publication() {
    let stopped = exhausted_recovery_fixture(false);
    let shape = journal_shape(&stopped);
    let reconciled = discard_and_reconcile(&stopped);
    let reconciled = reconciled.unwrap_or_else(|error| panic!("{error}; journal {shape:?}"));
    assert_eq!(
        reconciled.statuses(),
        ["not-landed"],
        "{reconciled:?}; journal {shape:?}"
    );
}

/// Timed-out sends whose slot a foreign head then took are not landed.
#[test]
fn reconcile_classifies_an_uncertain_publication_under_a_foreign_head() {
    let stopped = exhausted_recovery_fixture(true);
    let shape = journal_shape(&stopped);
    let reconciled = discard_and_reconcile(&stopped);
    let reconciled = reconciled.unwrap_or_else(|error| panic!("{error}; journal {shape:?}"));
    assert_eq!(
        reconciled.statuses(),
        ["not-landed"],
        "{reconciled:?}; journal {shape:?}"
    );
}

/// A committed cycle, then a commit the authority refuses until the lane
/// is exhausted.
#[test]
fn reconcile_classifies_an_exhausted_commit_after_a_committed_cycle() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let (outcome, stopped) = shut_down_as(
        fixture,
        Trigger::SessionEnd,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
    );
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
    let mut fixture = remount(stopped, 41).unwrap();
    create(fixture.ready.backend_for_test(), "b", DIRTY);
    fixture.state.lock().unwrap().publish_refusals = 8;
    let lane = construct_commit(&fixture.engine, &fixture.runtime, 70).unwrap();
    let result = drive_commit(&fixture.engine, &fixture.runtime, &lane, 80).unwrap();
    assert!(
        matches!(result.outcome, PublicationOutcome::Exhausted),
        "{result:?}"
    );
    let stopped = stop(fixture);
    let shape = journal_shape(&stopped);
    assert_eq!(retained_complete(&stopped), Some(false));
    let reconciled = discard_and_reconcile(&stopped);
    let reconciled = reconciled.unwrap_or_else(|error| panic!("{error}; journal {shape:?}"));
    assert_eq!(
        reconciled.statuses(),
        ["not-landed"],
        "{reconciled:?}; journal {shape:?}"
    );
}

/// A clean shutdown that committed and released leaves nothing to discard,
/// with or without an idle remount cycle after it.
#[test]
fn discard_plan_refuses_a_store_after_a_clean_shutdown() {
    let mut seen = Vec::new();
    for idle_cycle in [false, true] {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        create(fixture.ready.backend_for_test(), "a", DIRTY);
        let (outcome, mut stopped) = shut_down_as(
            fixture,
            Trigger::SessionEnd,
            crate::sync::DEFAULT_SHUTDOWN_BOUND,
        );
        assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
        if idle_cycle {
            let fixture = remount(stopped, 41).unwrap();
            let (outcome, ended) = shut_down_as(
                fixture,
                Trigger::Umount,
                crate::sync::DEFAULT_SHUTDOWN_BOUND,
            );
            assert!(matches!(outcome, Outcome::Clean), "{outcome:?}");
            stopped = ended;
        }
        let on_disk = carrier(&stopped);
        assert_eq!(on_disk.phase, Phase::Released);
        assert_eq!(row(&stopped).state, ReceiptState::Released);
        assert_eq!(retained_complete(&stopped), Some(true));
        let root = store_root(&stopped);
        let (scope, volume, _) = selection(&stopped);
        let plan = discard_overlay(&root, scope, &volume, None);
        seen.push((
            idle_cycle,
            on_disk
                .pending
                .iter()
                .map(|p| (p.operation, p.terminal, p.answered))
                .collect::<Vec<_>>(),
            plan.map(|row| (row.outcome, row.bytes))
                .map_err(DiscardError::reason),
        ));
    }
    assert!(
        seen.iter()
            .all(|(_, _, plan)| *plan == Err(OverlayRefusal::NotEligible)),
        "a committed, released store must refuse OverlayDiscardNotEligible: \
         (idle cycle, carrier pending, plan) = {seen:?}"
    );
}

/// The paths whose identity, mode, times or bytes differ, with what changed.
/// Each `Store::open` truncates the `lock` file and moves its times.
fn changed(before: &BTreeMap<PathBuf, Entry>, after: &BTreeMap<PathBuf, Entry>) -> Vec<String> {
    let mut out = Vec::new();
    for (path, old) in before {
        if path == Path::new("lock") {
            continue;
        }
        match after.get(path) {
            None => out.push(format!("{} removed", path.display())),
            Some(new) if new != old => {
                out.push(format!(
                    "{} changed from {old:?} to {new:?}",
                    path.display()
                ));
            }
            Some(_) => {}
        }
    }
    for path in after.keys().filter(|path| !before.contains_key(*path)) {
        out.push(format!("{} created", path.display()));
    }
    out
}

fn counted(stopped: &Stopped) -> (usize, usize) {
    let state = stopped.state.lock().unwrap();
    (state.sends.len(), state.publications.len())
}

/// A crash right after the discard's intent barriers leaves the intent
/// beside the live tree. The start and the recovery verb then refuse without
/// a write to the store or a send, so the same tuple still finishes.
/// The archived store refuses the start as well.
#[test]
fn pending_discard_survives_a_refused_start_and_recovery() {
    type Fixture = fn() -> Stopped;
    for (case, fixture) in [
        (
            "publication refused",
            (|| exhausted_recovery_fixture(false)) as Fixture,
        ),
        ("publication uncertain", || exhausted_recovery_fixture(true)),
        ("release unanswered", || interrupted(Some(false), false)),
        ("release landed, reply lost, past its horizon", || {
            interrupted(Some(true), true)
        }),
    ] {
        let stopped = fixture();
        let root = store_root(&stopped);
        let (scope, volume, _) = selection(&stopped);
        let plan = discard_overlay(&root, scope, &volume, None)
            .unwrap_or_else(|error| panic!("{case}: plan: {error}"));
        let tuple = (plan.name.writer, plan.name.incarnation);
        let scope_dir = overlay_area(&stopped.paths, &input(&stopped.tree, &stopped.paths))
            .parent()
            .unwrap()
            .to_owned();
        put(&scope_dir.join(plan.name.leaf(true)), b"");
        let pending = discard_overlay(&root, scope, &volume, None)
            .map(|row| row.outcome)
            .map_err(DiscardError::reason);
        let before = snapshot(&root);
        let sent = counted(&stopped);
        let started = restart(&stopped, &Events::default())
            .map(|_| ())
            .map_err(|error| error.to_string());
        let after_start = (
            changed(&before, &snapshot(&root)),
            counted(&stopped) == sent,
        );
        let recovered = recover_stopped(&stopped, crate::FaultControl::default())
            .map_err(|error| error.to_string());
        let middle = snapshot(&root);
        let after_recovery = (changed(&before, &middle), counted(&stopped) == sent);
        let retry = discard_overlay(&root, scope, &volume, Some(tuple))
            .map(|row| row.outcome)
            .map_err(DiscardError::reason);
        let archived = snapshot(&root);
        let restarted = restart(&stopped, &Events::default())
            .map(|_| ())
            .map_err(|error| error.to_string());
        let after_archive = (
            changed(&archived, &snapshot(&root)),
            counted(&stopped) == sent,
        );
        assert!(
            matches!(pending, Ok(DiscardOutcome::Pending(_)))
                && started
                    .as_ref()
                    .is_err_and(|error| error.contains("OverlayDiscardPending"))
                && after_start.0.is_empty()
                && after_start.1
                && recovered
                    .as_ref()
                    .is_err_and(|error| error.contains("OverlayDiscardPending"))
                && after_recovery.0.is_empty()
                && after_recovery.1
                && retry == Ok(DiscardOutcome::Moved)
                && restarted
                    .as_ref()
                    .is_err_and(|error| error.contains("OverlayArchived"))
                && after_archive.0.is_empty()
                && after_archive.1,
            "{case}: (plan after the intent, start, (store paths changed, nothing sent), recovery, (..), same-tuple retry, start on the archive, (..)) = {:#?}",
            (
                pending,
                started,
                after_start,
                recovered,
                after_recovery,
                retry,
                restarted,
                after_archive
            ),
        );
    }
}
