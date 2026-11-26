// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Every commit-lane fault point at each seed, armed and disarmed.

#![expect(clippy::unwrap_used, reason = "checked simulator fixture invariants")]

use super::*;
use granary_client::{CoordinationError, PublicationOutcome, RecoveryIntent};
use granary_sim::secure_random::SeededSecureRandom;
use std::sync::{Arc, Mutex};
use support::{Delay, PublishPlan, foreign_head};

const LATER: &[u8] = b"after the boundary";

/// Each point with the intent a restart's recovery needs once the fault has
/// stopped the commit there: a loaded rebase wants an explicit recovery, while
/// a rebased candidate resumes as it is.
const POINTS: [(&str, &str, RecoveryIntent); 9] = [
    ("sync.commit_wait", "before", RecoveryIntent::Continue),
    ("sync.commit", "captured", RecoveryIntent::Continue),
    ("sync.commit", "boundary_recorded", RecoveryIntent::Continue),
    ("sync.commit", "before_submit", RecoveryIntent::Continue),
    (
        "sync.commit",
        "before_rebase",
        RecoveryIntent::ExplicitRecovery,
    ),
    ("sync.commit", "after_rebase", RecoveryIntent::Continue),
    ("sync.commit", "landed_readback", RecoveryIntent::Continue),
    ("sync.commit", "landed_refresh", RecoveryIntent::Continue),
    ("sync.commit", "before_replace", RecoveryIntent::Continue),
];

#[derive(Clone, Default)]
pub(super) struct Capture(pub(super) Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// One test per point keeps each row far inside the suite's per-test kill.
macro_rules! point_tests {
    ($($test:ident: $index:expr,)*) => {
        $(
            #[test]
            fn $test() {
                let (name, phase, intent) = POINTS[$index];
                let mut cases = 0;
                for seed in [1, 42, 43] {
                    for armed in [false, true] {
                        pair(seed, (name, phase), intent, armed, 1);
                        cases += 1;
                    }
                }
                assert_eq!(cases, 6, "SyncCommitFaultEmptySelection");
            }
        )*
        #[test]
        fn every_commit_lane_point_has_a_test() {
            let listed = [$($index),*];
            assert_eq!(listed.len(), POINTS.len(), "SyncCommitFaultMissingTest");
            assert_eq!(listed, std::array::from_fn(|index| index));
        }
    };
}
point_tests! {
    commit_wait_fault_pairs_converge_at_every_seed: 0,
    captured_fault_pairs_converge_at_every_seed: 1,
    boundary_recorded_fault_pairs_converge_at_every_seed: 2,
    before_submit_fault_pairs_converge_at_every_seed: 3,
    before_rebase_fault_pairs_converge_at_every_seed: 4,
    after_rebase_fault_pairs_converge_at_every_seed: 5,
    landed_readback_fault_pairs_converge_at_every_seed: 6,
    landed_refresh_fault_pairs_converge_at_every_seed: 7,
    before_replace_fault_pairs_converge_at_every_seed: 8,
}

/// A rebasing commit reaches each rebase point twice: once for the head moved
/// before it submits and again for the stale answer the authority then gives.
/// The second occurrence is armed on its own.
macro_rules! second_occurrence_tests {
    ($($test:ident: $index:expr,)*) => {
        $(
            #[test]
            fn $test() {
                let (name, phase, intent) = POINTS[$index];
                let mut cases = 0;
                for seed in [1, 42, 43] {
                    for armed in [false, true] {
                        pair(seed, (name, phase), intent, armed, 2);
                        cases += 1;
                    }
                }
                assert_eq!(cases, 6, "SyncCommitFaultEmptySelection");
            }
        )*
    };
}
second_occurrence_tests! {
    before_rebase_second_occurrence_converges_at_every_seed: 4,
    after_rebase_second_occurrence_converges_at_every_seed: 5,
}

/// One point's `occurrence` at one seed. Armed, the fault stops the commit,
/// emits once, and a restart's recovery lands it once with every acknowledged
/// and later write. Disarmed, tracing shows the path reaches the point that
/// many times and the commit lands untouched, with nothing emitted.
fn pair(
    seed: u64,
    (name, phase): (&'static str, &'static str),
    intent: RecoveryIntent,
    armed: bool,
    occurrence: u64,
) {
    let label = format!("{name}/{phase} occurrence {occurrence} seed {seed} armed {armed}");
    let fixture = Fixture::new();
    let acknowledged = fixture.create("ack", b"acknowledged");
    assert!(
        fixture.sync(seed, acknowledged).0.is_ok(),
        "{label}: earlier fsync"
    );
    let synced = ok_syncs(&fixture);
    fixture.create("local", b"commit boundary");
    let faults = fixture.store.lock().unwrap().fault_control();
    if armed {
        faults.arm(name, phase, occurrence, FaultAction::Fail);
    } else {
        faults.trace_sync();
    }
    let output = Capture::default();
    let dispatch = granary_client::subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("warn"),
        output.clone(),
    );
    let (error, later) =
        tracing::subscriber::with_default(dispatch, || first_attempt(&fixture, seed, phase, armed));
    let fired: Vec<_> = faults
        .sync_fired()
        .into_iter()
        .filter(|event| (event.name, event.phase) == (name, phase))
        .collect();
    let emitted = emitted_faults(&output, name, phase);
    assert_eq!(
        (
            error.is_some(),
            error
                .as_ref()
                .is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
            fired.first().map(|event| event.occurrence),
            // A control must reach the point as many times as the armed
            // occurrence counts.
            armed || u64::try_from(fired.len()).unwrap() >= occurrence,
            // A capture is named unless the point is a fsync's wait, and only
            // the refresh names its request.
            fired
                .first()
                .map(|event| (event.capture > 0, event.request.is_some())),
            emitted,
        ),
        (
            armed,
            armed,
            Some(if armed { occurrence } else { 1 }),
            true,
            Some((phase != "before", phase == "landed_refresh")),
            usize::from(armed),
        ),
        "{label}: a fault must stop the commit once and emit once; a control must neither"
    );
    // The commit is stopped, not synced: no successful sync is counted for it.
    if armed {
        assert_eq!(
            ok_syncs(&fixture),
            synced,
            "{label}: a fault-stopped commit must not count as an ok sync"
        );
    }
    // A point before the boundary is durable leaves nothing for recovery, and
    // so does a second rebase point: the authority's stale answer already
    // proved the retained candidate cannot land, so restart discards it. One
    // fresh commit then publishes the write made after it; the others land
    // theirs, then that write needs its own fsync.
    let lane = occurrence == 1 && !matches!(phase, "captured" | "boundary_recorded");
    let fixture = if armed { fixture.restart() } else { fixture };
    if armed && lane {
        let lane = fixture
            .engine
            .recover_commit(SyncOptions::default())
            .unwrap_or_else(|error| panic!("{label}: recovery found no lane: {error}"));
        drive(&fixture, seed, &lane, intent, &label);
    } else if armed {
        assert!(
            fixture
                .engine
                .recover_commit(SyncOptions::default())
                .is_err(),
            "{label}: restart must find no lane to recover"
        );
        let lane = construct(&fixture, seed).unwrap();
        drive(&fixture, seed, &lane, RecoveryIntent::Continue, &label);
    }
    if !armed || lane {
        assert!(fixture.sync(seed, later).0.is_ok(), "{label}: later fsync");
    }
    let root = fixture.registered();
    for (file, bytes) in [
        ("ack", b"acknowledged".as_slice()),
        ("local", b"commit boundary"),
        ("later", LATER),
    ] {
        fixture.assert_file(&root, file, bytes);
    }
    let rebases = phase.ends_with("rebase");
    if rebases {
        fixture.assert_file(&root, "remote", b"");
    }
    assert_eq!(
        fixture.remote.publication_sends.lock().unwrap().len(),
        1 + usize::from(rebases),
        "{label}: the commit must be published once, and once more after a rebase"
    );
}

/// How many fault events the captured log holds for one point and phase.
fn emitted_faults(output: &Capture, name: &str, phase: &str) -> usize {
    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    text.lines()
        .filter(|line| {
            line.contains("\"event\":\"sync.fault\"")
                && line.contains(&format!("\"point\":\"{name}\""))
                && line.contains(&format!("\"phase\":\"{phase}\""))
        })
        .count()
}

/// The successful syncs the metrics count.
fn ok_syncs(fixture: &Fixture) -> u64 {
    fixture
        .metrics()
        .lines()
        .find_map(|line| line.strip_prefix("granary_client_syncs_total{outcome=\"ok\"} "))
        .unwrap()
        .parse()
        .unwrap()
}

fn construct(
    fixture: &Fixture,
    seed: u64,
) -> Result<granary_client::RetainedCommit, CoordinationError> {
    let engine = fixture.engine.clone();
    fixture
        .runtime
        .run(seed, 100_000, async move {
            engine
                .construct_commit(
                    SyncOptions::default(),
                    &mut SeededSecureRandom::for_incarnation(44, 1),
                )
                .await
        })
        .unwrap()
        .0
}

fn drive(
    fixture: &Fixture,
    seed: u64,
    lane: &granary_client::RetainedCommit,
    intent: RecoveryIntent,
    label: &str,
) {
    let result = fixture
        .runtime
        .run(seed, 100_000, async {
            fixture
                .engine
                .drive_commit(
                    lane,
                    &mut SeededSecureRandom::for_incarnation(45, 1),
                    &mut Delay,
                    intent,
                    SyncOptions::default(),
                )
                .await
        })
        .unwrap()
        .0
        .unwrap_or_else(|error| panic!("{label}: recovery could not drive the lane: {error}"));
    assert!(
        matches!(result.outcome, PublicationOutcome::Landed(_)),
        "{label}: recovery did not land the commit: {result:?}"
    );
}

/// Run the commit to its fault (or through it, when disarmed) and write after
/// the boundary; the error the commit gave and the stage written after it.
fn first_attempt(
    fixture: &Fixture,
    seed: u64,
    phase: &str,
    armed: bool,
) -> (Option<CoordinationError>, u64) {
    fixture
        .runtime
        .run(seed, 100_000, async {
            let options = SyncOptions::default();
            if phase == "before" {
                return wait_attempt(fixture, armed).await;
            }
            let lane = match fixture
                .engine
                .construct_commit(options, &mut SeededSecureRandom::for_incarnation(44, 0))
                .await
            {
                Ok(lane) => lane,
                Err(error) => return (Some(error), fixture.create("later", LATER)),
            };
            let later = fixture.create("later", LATER);
            if phase.ends_with("rebase") {
                foreign_head(fixture).await;
                fixture
                    .remote
                    .publication_plan
                    .lock()
                    .unwrap()
                    .extend([PublishPlan::StaleCurrent, PublishPlan::Land]);
            }
            let error = fixture
                .engine
                .drive_commit(
                    &lane,
                    &mut SeededSecureRandom::for_incarnation(45, 0),
                    &mut Delay,
                    RecoveryIntent::Continue,
                    options,
                )
                .await
                .err();
            (error, later)
        })
        .unwrap()
        .0
}

/// An fsync behind a constructed commit waits for it. Armed, the wait fails the
/// fsync and the commit stays in flight; disarmed, the commit is driven once the
/// wait is reached and the fsync is acknowledged behind it.
async fn wait_attempt(fixture: &Fixture, armed: bool) -> (Option<CoordinationError>, u64) {
    let faults = fixture.store.lock().unwrap().fault_control();
    let lane = fixture
        .engine
        .construct_commit(
            SyncOptions::default(),
            &mut SeededSecureRandom::for_incarnation(44, 0),
        )
        .await
        .unwrap();
    let later = fixture.create("later", LATER);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(later), SyncOptions::default());
    while !faults
        .sync_fired()
        .iter()
        .any(|event| event.name == "sync.commit_wait")
    {
        yield_once().await;
    }
    if !armed {
        let result = fixture
            .engine
            .drive_commit(
                &lane,
                &mut SeededSecureRandom::for_incarnation(45, 0),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            )
            .await
            .unwrap();
        assert!(matches!(result.outcome, PublicationOutcome::Landed(_)));
    }
    (waiter.wait().await.err(), later)
}
