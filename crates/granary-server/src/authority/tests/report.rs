// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The stuck-publication report: every field, volume order and determinism,
//! a planted stall's flag
//! against its bound, a healthy run's silence, the report's size tracking
//! open entries rather than history, and the age surviving a restart —
//! including one where the clock reads behind the decision it ages.

use super::*;

/// An open entry for `operation` deciding `candidate` at log position 1,
/// root seq 1, attested, its `decided_at` [`FixedClock::now`]: what a
/// world's log holds so a worker started over [`FixedClock`] serves the
/// entry already open.
fn open_entry(operation: u8, candidate: &[u8]) -> Vec<Record> {
    let d = decision_of(1, operation, candidate);
    vec![d.clone(), attestation(&d)]
}

/// As [`open_entry`], with `decided_at` set to `decided_at` rather than
/// [`FixedClock::now`]: what a test over [`SetClock`] needs, since the
/// age is measured against a clock reading the entry does not share.
fn open_entry_at(operation: u8, candidate: &[u8], decided_at: Timestamp) -> Vec<Record> {
    let doc = root::decode_root(candidate).unwrap();
    let d = Record::new(
        1,
        RecordBody::Decision {
            identity: identity(operation, GrainId::of(candidate)),
            root_seq: doc.seq,
            base: doc.parent,
            decided_at,
            candidate: RootBytes::new(candidate.to_vec()).unwrap(),
        },
    )
    .unwrap();
    vec![d.clone(), attestation(&d)]
}

/// A store that fails every operation from the start: the entry it
/// opens over stays unresolved for as long as the test looks at it,
/// with a stable candidate id and position (`TestStore::dead`'s fault,
/// inlined so the store still shares this world's admin and hold).
fn never_resolves() -> Faults {
    Faults::just(Fault::FailFrom(0))
}

/// The report's row for `volume`, at `bound`; it must have one.
async fn row_for(handle: &AuthorityHandle, volume: &VolumeName, bound: Duration) -> OpenEntryRow {
    handle
        .report(bound)
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.volume == *volume)
        .unwrap()
}

/// Decide `candidate` through the engine at clock `t0`, over a store
/// whose every read of seq 1 fails, so the entry stays unresolved; stop
/// with it open. The world, its decided entry's row as the first run saw
/// it, and the answer to the submission.
fn decided_by_the_engine_at(t0: Timestamp, candidate: &[u8]) -> (World, OpenEntryRow, Answer) {
    // Admission reads an empty chain, and every read of seq 1 fails: the
    // PUT may land, but the entry stays unresolved across both runs.
    let world = World::with_empty_logs(&[a()], Faults::none());
    world
        .store
        .set_read_fault(&a(), 1, Some(ReadFault::Transport));
    let (handle, driver) = world.start_with_clock(&[a()], SetClock::at(t0.secs));
    let sub = submission(&a(), 1, candidate);
    let (end, (accepted, first)) = run_beside(0, driver, async move {
        let accepted = handle.submit(sub).await;
        let first = await_row(&handle, &a(), AMPLE_BOUND, |_| true).await;
        handle.stop().await;
        (accepted, first)
    });
    assert_eq!(
        end,
        RunEnd::Stopped,
        "the first run stops with the entry open"
    );
    (world, first, accepted)
}

// --------------------------------------------------- every field, in order

/// Two volumes, A and B, each with one open entry: the report's rows
/// come back A then B (spec §7's volume order), every field matches
/// what was decided, and running the same scheduler seed again gives
/// byte-for-byte the same rows — nothing here depends on anything but
/// the seed.
#[test]
fn every_field_is_reported_in_volume_order_and_is_deterministic() {
    let ca = good_root(&a(), 1, None, 0xA1);
    let cb = good_root(&b(), 1, None, 0xB1);
    let run = || {
        let world = World::new(never_resolves());
        seed(
            &world.log,
            &a(),
            log_bytes(&envelope(&a(), WORLD_EPOCH), &open_entry(1, &ca)),
        );
        seed(
            &world.log,
            &b(),
            log_bytes(&envelope(&b(), WORLD_EPOCH), &open_entry(2, &cb)),
        );
        let (handle, driver) = world.start(&[a(), b()]);
        let (end, rows) = run_beside(0, driver, async move {
            let rows = handle.report(AMPLE_BOUND).await.unwrap();
            handle.stop().await;
            rows
        });
        assert_eq!(end, RunEnd::Stopped);
        rows
    };

    let rows = run();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].volume, a());
    assert_eq!(rows[0].state, StuckState::Unresolved);
    assert_eq!(rows[0].candidate_id, GrainId::of(&ca));
    assert_eq!(rows[0].position, World::position(1));
    assert_eq!(rows[0].reissues, 0);
    assert_eq!(rows[0].age, Some(Duration::ZERO));
    assert_eq!(rows[0].flag, None);
    assert_eq!(rows[1].volume, b());
    assert_eq!(rows[1].state, StuckState::Unresolved);
    assert_eq!(rows[1].candidate_id, GrainId::of(&cb));
    assert_eq!(rows[1].position, World::position(1));
    assert_eq!(rows[1].reissues, 0);
    assert_eq!(rows[1].age, Some(Duration::ZERO));
    assert_eq!(rows[1].flag, None);

    assert_eq!(run(), rows, "the same seed reports identically");
}

// ------------------------------------------------- a planted stall's flag

/// A stall the engine cannot clear on its own: an unresolved entry (a
/// store that fails every PUT) and a wedged one (junk planted at the
/// decided seq). Judged with the clock at exactly `decided_at + bound`
/// the row is unflagged and its age is the bound; one second later it is
/// **past its bound**. Neither variant ever resolves on its own, so the
/// same open entry is judged twice at two clock readings.
#[test]
fn a_planted_stall_is_flagged_once_past_its_bound_and_not_before() {
    let t0 = Timestamp {
        secs: 2_000_000,
        nanos: 0,
    };
    let bound = Duration::from_secs(30);

    for (stuck, faults, plant_junk) in [
        (StuckState::Unresolved, never_resolves(), false),
        (StuckState::Wedged, Faults::none(), true),
    ] {
        let c1 = good_root(&a(), 1, None, 1);
        let world = World::new(faults);
        seed(
            &world.log,
            &a(),
            log_bytes(&envelope(&a(), WORLD_EPOCH), &open_entry_at(1, &c1, t0)),
        );
        if plant_junk {
            world.plant(&a(), 1, b"a squatter");
        }
        let clock = SetClock::at(t0.secs);
        let (handle, driver) = world.start_with_clock(&[a()], clock.clone());
        let at_bound_secs = t0.secs + i64::try_from(bound.as_secs()).unwrap();
        let (end, (before, after)) = run_beside(0, driver, async move {
            await_row(&handle, &a(), AMPLE_BOUND, |row| row.state == stuck).await;
            clock.set(at_bound_secs);
            let before = row_for(&handle, &a(), bound).await;
            clock.set(at_bound_secs + 1);
            let after = row_for(&handle, &a(), bound).await;
            handle.stop().await;
            (before, after)
        });
        assert_eq!(end, RunEnd::Stopped, "{stuck:?}");
        assert_eq!(before.age, Some(bound), "{stuck:?}: at the bound");
        assert_eq!(before.flag, None, "{stuck:?}: not past it yet");
        assert_eq!(
            after.age,
            Some(bound + Duration::from_secs(1)),
            "{stuck:?}: one second past"
        );
        assert_eq!(
            after.flag,
            Some(StuckFlag::PastBound),
            "{stuck:?}: now past it"
        );
    }
}

// ------------------------------------------------------- a healthy run

/// A publication that lands is never flagged while it is open, with the
/// clock moving and each report's bound exactly the age the clock then
/// gives (zero, then ten seconds): its reads fail until the client
/// lifts the fault, so both reports see it open on every seed. Once it
/// lands the report carries no row for it.
#[test]
fn a_healthy_run_flags_nothing() {
    let t0 = Timestamp {
        secs: 1_000_000,
        nanos: 0,
    };
    for seed_n in 0..16 {
        let c1 = good_root(&a(), 1, None, 1);
        let world = World::new(Faults::none());
        seed(
            &world.log,
            &a(),
            log_bytes(&envelope(&a(), WORLD_EPOCH), &open_entry_at(1, &c1, t0)),
        );
        // Every read of seq 1 fails until the client lifts the fault, so
        // the entry is open for both reports, whatever the schedule.
        world
            .store
            .set_read_fault(&a(), 1, Some(ReadFault::Transport));
        let store = world.store.clone();
        let clock = SetClock::at(t0.secs);
        let (handle, driver) = world.start_with_clock(&[a()], clock.clone());
        let sub = submission(&a(), 1, &c1);
        let (end, (at_decision, ten_seconds_on, answer, after_landing)) =
            run_beside(seed_n, driver, async move {
                // Time passes while the entry is open, and each report's
                // bound is exactly the age the clock then gives: never past.
                let at_decision = row_for(&handle, &a(), Duration::ZERO).await;
                clock.set(t0.secs + 10);
                let ten_seconds_on = row_for(&handle, &a(), Duration::from_secs(10)).await;
                store.set_read_fault(&a(), 1, None);
                let answer = settle(&handle, &sub).await;
                clock.set(t0.secs + 20);
                let after_landing = handle.report(Duration::ZERO).await.unwrap();
                handle.stop().await;
                (at_decision, ten_seconds_on, answer, after_landing)
            });
        assert_eq!(end, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(at_decision.age, Some(Duration::ZERO), "seed {seed_n}");
        assert_eq!(at_decision.flag, None, "seed {seed_n}");
        assert_eq!(
            ten_seconds_on.age,
            Some(Duration::from_secs(10)),
            "seed {seed_n}"
        );
        assert_eq!(ten_seconds_on.flag, None, "seed {seed_n}");
        assert!(
            matches!(answer, Answer::Landed { .. }),
            "seed {seed_n}: {answer:?}"
        );
        assert_eq!(
            after_landing,
            Vec::new(),
            "seed {seed_n}: a landed entry leaves no row"
        );
    }
}

// --------------------------------------------- size tracks open entries

/// Two closed entries (decided, attested, landed) at seqs 1 and 2, their
/// candidates' bytes the store's chain there: a volume whose history is
/// two decisions deep and has nothing open.
fn two_landed_entries() -> (Vec<Record>, Vec<u8>, Vec<u8>) {
    let c1 = good_root(&a(), 1, None, 1);
    let c2 = good_root(&a(), 2, Some(GrainId::of(&c1)), 1);
    let d1 = decision_of(1, 1, &c1);
    let d2 = decision_of(2, 2, &c2);
    let records = vec![
        d1.clone(),
        attestation(&d1),
        landed(&d1),
        d2.clone(),
        attestation(&d2),
        landed(&d2),
    ];
    (records, c1, c2)
}

/// After two decisions have landed on a volume, the report holds no row
/// for it; with a third decided and stuck (wedged, on a squatter planted
/// at its seq), it holds exactly one, naming that entry: the report's
/// size follows open entries, never how many have closed.
#[test]
fn the_report_grows_with_open_entries_not_history() {
    let (closed, c1, c2) = two_landed_entries();
    let world = World::new(Faults::none());
    seed(
        &world.log,
        &a(),
        log_bytes(&envelope(&a(), WORLD_EPOCH), &closed),
    );
    world.plant(&a(), 1, &c1);
    world.plant(&a(), 2, &c2);
    let (handle, driver) = world.start(&[a()]);
    let (end, closed_report) = run_beside(0, driver, async move {
        let report = handle.report(AMPLE_BOUND).await.unwrap();
        handle.stop().await;
        report
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(
        closed_report,
        Vec::new(),
        "two landed decisions leave no row"
    );

    let c3 = good_root(&a(), 3, Some(GrainId::of(&c2)), 1);
    let d3 = decision_of(3, 3, &c3);
    let mut open = closed;
    open.push(d3.clone());
    open.push(attestation(&d3));
    let world = World::new(Faults::none());
    seed(
        &world.log,
        &a(),
        log_bytes(&envelope(&a(), WORLD_EPOCH), &open),
    );
    world.plant(&a(), 1, &c1);
    world.plant(&a(), 2, &c2);
    world.plant(&a(), 3, b"a squatter");
    let (handle, driver) = world.start(&[a()]);
    let (end, one_open) = run_beside(0, driver, async move {
        await_row(&handle, &a(), AMPLE_BOUND, |row| {
            row.state == StuckState::Wedged
        })
        .await;
        let report = handle.report(AMPLE_BOUND).await.unwrap();
        handle.stop().await;
        report
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(one_open.len(), 1, "{one_open:?}");
    assert_eq!(one_open[0].position, World::position(3));
    assert_eq!(one_open[0].state, StuckState::Wedged);
}

// --------------------------------------------------- across a restart

/// A stall the engine itself decides at clock `t0`, in a first run that
/// then stops with the entry open: on restart, with the clock at
/// `t0 + bound + 1s`, the row's age is `bound + 1s` and it is flagged
/// **past its bound**. The age came from the reading the engine wrote
/// into the decision record, which a restart does not reset, not from
/// when the new run began.
#[test]
fn a_stall_spanning_a_restart_is_still_flagged() {
    let t0 = Timestamp {
        secs: 3_000_000,
        nanos: 0,
    };
    let bound = Duration::from_secs(30);
    let c1 = good_root(&a(), 1, None, 1);
    let (world, first, accepted) = decided_by_the_engine_at(t0, &c1);
    assert!(matches!(accepted, Answer::Accepted { .. }), "{accepted:?}");
    assert_eq!(first.age, Some(Duration::ZERO), "decided at the clock's t0");
    assert_eq!(first.flag, None);

    let after = t0.secs + i64::try_from(bound.as_secs()).unwrap() + 1;
    let (handle, driver) = world.start_with_clock(&[a()], SetClock::at(after));
    let (end, row) = run_beside(0, driver, async move {
        let row = await_row(&handle, &a(), bound, |row| row.flag.is_some()).await;
        handle.stop().await;
        row
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(row.age, Some(bound + Duration::from_secs(1)));
    assert_eq!(row.flag, Some(StuckFlag::PastBound));
}

/// A decision the engine recorded at clock `t0`, then a restart whose
/// clock reads one second earlier (a clock stepped back across the
/// restart): the age is unknown and the entry is flagged **clock
/// behind**, never reported as young.
#[test]
fn a_clock_stepped_behind_the_decision_is_reported_clock_behind() {
    let t0 = Timestamp {
        secs: 4_000_000,
        nanos: 0,
    };
    let c1 = good_root(&a(), 1, None, 1);
    let (world, first, accepted) = decided_by_the_engine_at(t0, &c1);
    assert!(matches!(accepted, Answer::Accepted { .. }), "{accepted:?}");
    assert_eq!(first.age, Some(Duration::ZERO), "decided at the clock's t0");

    let (handle, driver) = world.start_with_clock(&[a()], SetClock::at(t0.secs - 1));
    let (end, row) = run_beside(0, driver, async move {
        let row = await_row(&handle, &a(), AMPLE_BOUND, |row| row.flag.is_some()).await;
        handle.stop().await;
        row
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(row.age, None);
    assert_eq!(row.flag, Some(StuckFlag::ClockBehind));
}
