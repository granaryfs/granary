// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Linux venue's runs: the engine over the production adapter on a
//! filesystem `scripts/authority-venue.sh` provisions, under its syscall
//! trace, and over a device it fails.
//!
//! Each is ignored, reads the script's environment, and panics without
//! it: a run that is not the venue's never counts one as passed.

use std::future::Future;
use std::path::{Path, PathBuf};

use granary_core::runmarker::RunMarker;
use granary_sim::fakes::{Faults, Sim};
use granary_sim::sched::{Scheduler, Task};

use super::super::super::tests::{
    FixedClock, TestStore, YieldPause, block, boot, configs, good_root, rng, secure, submission_at,
};
use super::super::super::{Answer, AuthorityHandle, AuthorityParts, Initialised, RunEnd, start};
use super::super::FileLog;
use super::engine::{MUTATING, marker_on_disk, process_over, run, workload};
use super::recording::Recording;
use super::vol;

/// The state directory the venue names, on its filesystem.
const STATE_ENV: &str = "GRANARY_VENUE_STATE";
/// Which process of the traced workload this is: `first` or `restart`.
const PHASE_ENV: &str = "GRANARY_VENUE_PHASE";
/// The directory the venue and the failing run signal each other through:
/// the run creates `ready` there, then blocks reading the FIFO `go` until
/// the venue has failed the device.
const CONTROL_ENV: &str = "GRANARY_VENUE_CONTROL";

fn venue(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is unset: this runs only under scripts/authority-venue.sh")
    })
}

/// What one of [`over_the_real_calls`]'s two tasks ended with.
enum Done {
    Run(RunEnd),
    Client(Vec<Answer>),
}

/// Run the engine over the production adapter at `state` under boot `n`,
/// with `client` beside its driver.
fn over_the_real_calls<F: Future<Output = Vec<Answer>> + 'static>(
    state: &Path,
    n: u8,
    client: impl FnOnce(AuthorityHandle) -> F,
) -> (RunEnd, Vec<Answer>) {
    let sim = Sim::new();
    let parts = AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        // The type acknowledgement off: the venue's ext4 is in the table.
        log: FileLog::new(state, false).unwrap(),
        store: TestStore::new(sim.node(1, Faults::none())),
        clock: FixedClock,
        rng: rng(1),
        secure_random: secure(1),
        pause: YieldPause,
    };
    let volumes = configs(&[vol("vol-a"), vol("vol-b")]);
    let (handle, driver) = block(async move { start(parts, boot(n), volumes).await }).unwrap();
    let client = client(handle);
    let tasks: Vec<Task<Done>> = vec![
        Box::pin(async move { Done::Run(driver.run().await) }),
        Box::pin(async move { Done::Client(client.await) }),
    ];
    let mut out = Scheduler::new(0).run(tasks).into_iter();
    match (out.next(), out.next()) {
        (Some(Done::Run(end)), Some(Done::Client(answers))) => (end, answers),
        _ => panic!("the scheduler returns results in task order"),
    }
}

/// The traced workload, one process per phase: `first` initialises both
/// volumes and lands a root on one; `restart`, a later process over the
/// same directory, recovers both logs and stops. The venue checks the
/// syscalls; this checks the answers.
#[test]
#[ignore = "the Linux venue's: scripts/authority-venue.sh"]
fn the_workload_over_the_real_calls() {
    let state = PathBuf::from(venue(STATE_ENV));
    match venue(PHASE_ENV).as_str() {
        "first" => {
            let (end, answers) = over_the_real_calls(&state, 1, workload);
            assert_eq!(end, RunEnd::Stopped);
            assert!(
                matches!(answers[..], [Answer::Landed { .. }]),
                "{answers:?}"
            );
        }
        "restart" => {
            let (end, _) = over_the_real_calls(&state, 2, |handle| async move {
                let _ = handle.stop().await;
                Vec::new()
            });
            assert_eq!(end, RunEnd::Stopped);
        }
        other => panic!("{PHASE_ENV}={other}: expected first or restart"),
    }
    assert_eq!(marker_on_disk(&state), Some(RunMarker::Clean));
}

/// A sync the device fails: both volumes initialised, then the venue maps
/// the first volume's log onto an error target, and the next submission's
/// decision append fails at its sync. The engine fences, answers
/// `Fenced`, and after the failed sync makes no mutating call at all: in
/// particular it never retries the sync.
#[test]
#[ignore = "the Linux venue's: scripts/authority-venue.sh"]
fn a_sync_the_device_fails_fences_and_is_not_retried() {
    let state = PathBuf::from(venue(STATE_ENV));
    let control = PathBuf::from(venue(CONTROL_ENV));
    let sim = Sim::new();
    let p = process_over(
        &sim,
        Recording::open(&state, false).unwrap(),
        &state,
        |_| {},
    );
    let ops = p.ops.clone();
    let shared = std::sync::Arc::clone(&ops.shared);
    let armed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mark = std::sync::Arc::clone(&armed);
    let (end, answers) = run(p, 1, |handle| async move {
        let mut epochs = std::collections::BTreeMap::new();
        for v in [vol("vol-a"), vol("vol-b")] {
            match handle.initialise(&v).await {
                Ok(Initialised::Created { epoch } | Initialised::Kept { epoch }) => {
                    epochs.insert(v, epoch);
                }
                Err(other) => panic!("initialise {}: {other:?}", v.as_str()),
            }
        }
        // Calls before this point ran on a healthy device; a leftover
        // temporary's removal finding nothing is one of them.
        mark.store(shared.calls().len(), std::sync::atomic::Ordering::SeqCst);
        std::fs::write(control.join("ready"), b"").unwrap();
        // Blocks until the venue has failed the device and opened the
        // FIFO's other end.
        let _ = std::fs::read(control.join("go")).unwrap();
        let c1 = good_root(&vol("vol-a"), 1, None, 1);
        let sub = submission_at(epochs[&vol("vol-a")], &vol("vol-a"), 1, &c1);
        vec![handle.submit(sub).await]
    })
    .unwrap();
    assert!(matches!(end, RunEnd::Fenced(_)), "{end:?}");
    assert!(matches!(answers[..], [Answer::Fenced]), "{answers:?}");
    let calls = ops.shared.calls();
    let from = armed.load(std::sync::atomic::Ordering::SeqCst);
    assert!(from > 0, "the run never reached the device's failure");
    let failed = from
        + calls[from..]
            .iter()
            .position(|c| !c.ok && c.note.is_none())
            .expect("no call failed: the device was never failed");
    let first = &calls[failed];
    assert_eq!(
        first.op, "sync_file",
        "the first failure was not a sync: {first:?}"
    );
    let after: Vec<_> = calls[failed + 1..]
        .iter()
        .filter(|c| MUTATING.contains(&c.op))
        .collect();
    assert!(after.is_empty(), "calls after the failed sync: {after:?}");
}
