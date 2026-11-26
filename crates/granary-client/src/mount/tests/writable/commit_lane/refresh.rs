// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::overlay_ownership::Operation;
use granary_fuse::{MountBackend as _, OverlayMutation as M};

fn drive_in_background(
    fixture: &EngineMount,
    lane: crate::RetainedCommit,
    entropy: u8,
) -> std::thread::JoinHandle<Result<crate::PublicationResult, crate::CoordinationError>> {
    let engine = fixture.engine.clone();
    let runtime = fixture.runtime.handle().clone();
    std::thread::spawn(move || {
        let mut secure = Entropy(entropy);
        let mut delay = NoDelay;
        runtime.block_on(Box::pin(engine.drive_commit(
            &lane,
            &mut secure,
            &mut delay,
            RecoveryIntent::Continue,
            crate::SyncOptions::default(),
        )))
    })
}

#[test]
fn commit_lane_refresh_window_serves_queries_and_writes() {
    let mut fixture = EngineMount::new();
    let object = dirty(&mut fixture);
    let lane = fixture.construct(70).unwrap();
    fixture.faults.arm(
        "sync.commit",
        "landed_refresh",
        1,
        crate::FaultAction::Block,
    );
    let driving = drive_in_background(&fixture, lane, 80);
    shutdown::wait_fired(&fixture.faults, "sync.commit", "landed_refresh");
    let mediator = fixture.ready.backend_for_test().shared_mediator().clone();
    let backend = fixture.ready.backend_for_test();
    let directory = backend.overlay_directory(&[]).map(|_| ());
    let lookup = backend
        .overlay_lookup(
            &[],
            &granary_core::manifest::Name::new(b"f.txt".to_vec()).unwrap(),
        )
        .map(|_| ());
    let write = backend.overlay_mutate(M::BoundWrite {
        object,
        offset: 0,
        bytes: b"refresh-window",
        append: false,
    });
    let readiness = mediator
        .with(crate::writable_store::WritableStore::check_readiness)
        .map_err(|error| error.to_string());
    fixture.faults.resume();
    let result = driving.join().unwrap();
    let pending = mediator
        .with(|store| {
            Ok(store
                .snapshot()
                .pending
                .iter()
                .filter(|pending| !pending.terminal)
                .count())
        })
        .unwrap();
    assert_eq!(
        (
            directory,
            lookup,
            write,
            readiness,
            landed(&result),
            pending,
        ),
        (Ok(()), Ok(()), Ok(()), Ok(()), true, 0),
        "the held refresh must serve its pinned directory, lookup, bound write and readiness; \
         then land with no pending request: {result:?}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row carries the matching and refusing controls plus the guard's conditional clear"
)]
fn commit_lane_refresh_admission_is_generation_scoped() {
    let mut cut = EngineMount::new();
    dirty(&mut cut);
    let lane = cut.construct(70).unwrap();
    cut.faults
        .arm("sync.commit", "landed_refresh", 1, crate::FaultAction::Fail);
    let cut_result = cut.drive(&lane, 80);
    assert_eq!(
        cut_result.err().map(|error| error.to_string()),
        Some("intent refused: SyncInjectedFault".to_owned()),
        "premise: the fixture must retain its refresh Register"
    );
    let mediator = cut.ready.backend_for_test().shared_mediator().clone();
    let pending = mediator
        .with(|store| {
            let snapshot = store.snapshot();
            Ok(snapshot
                .pending
                .iter()
                .find(|pending| pending.operation == Operation::Register && !pending.terminal)
                .and_then(|pending| pending.generation().ok()))
        })
        .unwrap();
    let Some(pending) = pending else {
        panic!("premise: the carrier must hold a pending Register")
    };
    let readiness = |field| {
        mediator
            .with(|store| {
                store.set_landing_refresh_for_test(field);
                store.check_readiness()
            })
            .map_err(|error| error.to_string())
    };
    let mut cases = 0;
    let matching = readiness(Some(pending));
    cases += 1;
    let other = readiness(pending.checked_add(1));
    cases += 1;
    let absent = readiness(None);
    cases += 1;

    let mut guarded = EngineMount::new();
    dirty(&mut guarded);
    let lane = guarded.construct(70).unwrap();
    guarded.faults.arm(
        "sync.commit",
        "landed_refresh",
        1,
        crate::FaultAction::Block,
    );
    let driving = drive_in_background(&guarded, lane, 80);
    shutdown::wait_fired(&guarded.faults, "sync.commit", "landed_refresh");
    let guarded_mediator = guarded.ready.backend_for_test().shared_mediator().clone();
    let (current, refresh, later) = guarded_mediator
        .with(|store| {
            let refresh = store
                .snapshot()
                .pending
                .iter()
                .find(|pending| pending.operation == Operation::Register && !pending.terminal)
                .and_then(|pending| pending.generation().ok())
                .ok_or(crate::CoordinationError::Refused(
                    "RefreshFixtureRegisterMissing",
                ))?;
            let later = refresh
                .checked_add(1)
                .ok_or(crate::CoordinationError::Refused(
                    "RefreshFixtureGenerationOverflow",
                ))?;
            let current = store.landing_refresh_for_test();
            store.set_landing_refresh_for_test(Some(later));
            Ok((current, refresh, later))
        })
        .unwrap();
    guarded.faults.resume();
    let result = driving.join().unwrap();
    let preserved = guarded_mediator
        .with(|store| Ok(store.landing_refresh_for_test()))
        .unwrap();
    guarded_mediator
        .with(|store| {
            store.set_landing_refresh_for_test(None);
            Ok(())
        })
        .unwrap();
    cases += 1;
    assert_eq!(
        (
            matching,
            other,
            absent,
            current,
            landed(&result),
            preserved,
            cases,
        ),
        (
            Ok(()),
            Err("intent refused: WritableRecoveryRequired".to_owned()),
            Err("intent refused: WritableRecoveryRequired".to_owned()),
            Some(refresh),
            true,
            Some(later),
            4,
        ),
        "(the pending generation admits; another generation and no field refuse; the live \
         field names its Register; the finishing guard leaves a later generation alone; cases)"
    );
}
