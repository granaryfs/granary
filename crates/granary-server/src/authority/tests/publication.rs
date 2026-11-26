// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Publication tests exercise
//! the classification table through the engine over the simulator's
//! store, an open entry's re-issues, the PUT's result never closing an
//! entry, recovery's attestation before any PUT, replay never
//! re-classifying, and the fence stopping PUTs on every volume.

use std::pin::pin;

use super::super::join::{Raced, race};
use super::*;

/// An open entry for operation 1 deciding `candidate`, attested: the log
/// a start resumes at re-issue.
fn open_entry(candidate: &[u8]) -> Vec<Record> {
    let d = decision_of(1, 1, candidate);
    vec![d.clone(), attestation(&d)]
}

/// Every `put-root` line in `puts` carries `bytes`.
fn all_carry(puts: &[String], bytes: &[u8]) -> bool {
    let addr = format!("addr={} ", hex(GrainId::of(bytes)));
    puts.iter().all(|line| line.contains(&addr))
}

/// The committed log's last record's body if it closes an entry (landed
/// or lost), else `None`.
fn outcome(records: &[Record]) -> Option<RecordBody> {
    records
        .last()
        .map(Record::body)
        .and_then(|body| match body {
            RecordBody::Landed { .. } | RecordBody::Lost { .. } => Some(body.clone()),
            _ => None,
        })
}

/// Run a world whose volume A holds an open entry for `candidate`, until
/// the report shows the entry `stuck` after at least `reissues`
/// re-issues; the row.
fn run_until_stuck(
    world: &World,
    candidate: &[u8],
    stuck: StuckState,
    reissues: u64,
) -> OpenEntryRow {
    let (handle, driver) = world.start(&[a()]);
    let other = good_root(&a(), 1, None, 0x7F);
    let candidate = candidate.to_vec();
    let (end, row) = run_beside(0, driver, async move {
        let row = await_row(&handle, &a(), AMPLE_BOUND, |row| {
            row.state == stuck && row.reissues >= reissues
        })
        .await;
        // No successor is decided while the entry is open.
        assert_eq!(
            handle.submit(submission(&a(), 9, &other)).await,
            Answer::NotDecided {
                position: World::position(1),
                candidate_id: GrainId::of(&candidate),
            }
        );
        handle.stop().await;
        row
    });
    assert_eq!(end, RunEnd::Stopped);
    row
}

// ------------------------------------------------- the classification table

/// The recorded bytes: landed, whether the PUT created them or found
/// them already there (a late landing from before the start). One PUT,
/// then the landed record.
#[test]
fn the_recorded_bytes_close_the_entry_landed() {
    for already_there in [false, true] {
        let c1 = good_root(&a(), 1, None, 1);
        let world = World::with_records(&a(), &open_entry(&c1), Faults::none());
        if already_there {
            world.plant(&a(), 1, &c1);
        }
        let (handle, driver) = world.start(&[a()]);
        let sub = submission(&a(), 1, &c1);
        let (_, answer) = run_beside(0, driver, async move {
            let answer = settle(&handle, &sub).await;
            handle.stop().await;
            answer
        });
        let c1_head = VerifiedHead::new(Some(HeadRef {
            head_seq: 1,
            head_id: GrainId::of(&c1),
        }));
        assert_eq!(
            answer,
            Answer::Landed {
                receipt: Receipt {
                    position: World::position(1),
                    seq: 1,
                    stored_id: GrainId::of(&c1),
                },
                head: Some(c1_head),
            }
        );
        let d = decision_of(1, 1, &c1);
        assert_eq!(
            outcome(&committed(&world.log, &a())),
            Some(landed(&d).body().clone())
        );
        let puts = world.puts(&a(), 1);
        assert_eq!(puts.len(), 1, "{puts:?}");
        assert!(all_carry(&puts, &c1));
        assert_eq!(world.log.violations(), []);
    }
}

/// A valid root that extends the recorded base (parentless at seq 1, or
/// naming the base at seq 2) closes the entry lost, with the occupant's
/// stored id, and the lost candidate is never re-issued.
#[test]
fn a_valid_root_on_the_base_closes_the_entry_lost() {
    for seq in [1_u64, 2] {
        let world = World::new(Faults::none());
        let chain = world.plant_chain(&a(), seq - 1, 0x50);
        let base = chain.last().map(|bytes| GrainId::of(bytes));
        let c1 = good_root(&a(), seq, base, 1);
        let occupant = good_root(&a(), seq, base, 2);
        world.plant(&a(), seq, &occupant);
        seed(
            &world.log,
            &a(),
            log_bytes(&envelope(&a(), WORLD_EPOCH), &open_entry(&c1)),
        );
        let (handle, driver) = world.start(&[a()]);
        let sub = submission(&a(), 1, &c1);
        let (_, (answer, later)) = run_beside(0, driver, async move {
            let answer = settle(&handle, &sub).await;
            for _ in 0..32 {
                yield_once().await;
            }
            let later = handle.submit(sub.clone()).await;
            handle.stop().await;
            (answer, later)
        });
        let expected = Answer::Lost {
            position: World::position(1),
            candidate_id: GrainId::of(&c1),
            occupant: GrainId::of(&occupant),
            head: Some(VerifiedHead::new(Some(HeadRef {
                head_seq: seq,
                head_id: GrainId::of(&occupant),
            }))),
        };
        assert_eq!(answer, expected, "seq {seq}");
        assert_eq!(later, expected, "seq {seq}");
        let d = decision_of(1, 1, &c1);
        assert_eq!(
            outcome(&committed(&world.log, &a())),
            Some(lost(&d, GrainId::of(&occupant)).body().clone())
        );
        assert_eq!(
            world.puts(&a(), seq).len(),
            1,
            "a lost candidate is not re-issued"
        );
        assert_eq!(world.log.violations(), []);
    }
}

/// Anything else at the seq wedges the entry: it stays open, is
/// re-issued with the same bytes, and no outcome is recorded. Each row:
/// an undecodable object, a root for another volume, a root signed by a
/// stranger, a valid root off the recorded base, a root on the base with
/// a missing ancestor, and a size-cap refusal at the seq and at an
/// ancestor.
#[test]
fn anything_else_at_the_seq_wedges_the_entry() {
    enum Occupant {
        Junk,
        OtherVolume,
        Stranger,
        OffBase,
        MissingAncestor,
        OverCapSeq,
        OverCapAncestor,
    }
    for occupant in [
        Occupant::Junk,
        Occupant::OtherVolume,
        Occupant::Stranger,
        Occupant::OffBase,
        Occupant::MissingAncestor,
        Occupant::OverCapSeq,
        Occupant::OverCapAncestor,
    ] {
        let world = World::new(Faults::none());
        let chain = world.plant_chain(&a(), 1, 0x60);
        let base = Some(GrainId::of(&chain[0]));
        let c1 = good_root(&a(), 2, base, 1);
        let on_base = good_root(&a(), 2, base, 2);
        match occupant {
            Occupant::Junk => world.plant(&a(), 2, b"junk at the seq"),
            Occupant::OtherVolume => world.plant(&a(), 2, &good_root(&b(), 2, base, 2)),
            Occupant::Stranger => {
                world.plant(&a(), 2, &signed_root(&a(), 2, base, 2, &[&stranger()]));
            }
            Occupant::OffBase => {
                // A valid chain of its own: the root at 1 is replaced,
                // and the occupant extends the replacement, not the
                // entry's recorded base.
                world.delete(&a(), 1);
                let replaced = good_root(&a(), 1, None, 0x61);
                world.plant(&a(), 1, &replaced);
                world.plant(
                    &a(),
                    2,
                    &good_root(&a(), 2, Some(GrainId::of(&replaced)), 2),
                );
            }
            Occupant::MissingAncestor => {
                world.plant(&a(), 2, &on_base);
                world.delete(&a(), 1);
            }
            Occupant::OverCapSeq => {
                world.plant(&a(), 2, &on_base);
                world
                    .store
                    .set_read_fault(&a(), 2, Some(ReadFault::OverCap));
            }
            Occupant::OverCapAncestor => {
                world.plant(&a(), 2, &on_base);
                world
                    .store
                    .set_read_fault(&a(), 1, Some(ReadFault::OverCap));
            }
        }
        seed(
            &world.log,
            &a(),
            log_bytes(&envelope(&a(), WORLD_EPOCH), &open_entry(&c1)),
        );
        let row = run_until_stuck(&world, &c1, StuckState::Wedged, 2);
        assert_eq!(row.candidate_id, GrainId::of(&c1));
        assert_eq!(row.position, World::position(1));
        assert_eq!(row.age, Some(Duration::ZERO), "the clock never moves here");
        assert_eq!(row.flag, None);
        assert_eq!(
            outcome(&committed(&world.log, &a())),
            None,
            "the entry stays open"
        );
        let puts = world.puts(&a(), 2);
        assert!(puts.len() >= 3, "re-issued: {puts:?}");
        assert!(all_carry(&puts, &c1), "only the recorded bytes: {puts:?}");
        assert_eq!(world.log.violations(), []);
    }
}

/// Nothing at the seq, or a failed read of the seq or of an ancestor:
/// unresolved, re-issued with the same bytes, no outcome recorded. Every
/// PUT fails here, a terminal answer included, and none closes the
/// entry.
#[test]
fn nothing_or_a_failed_read_leaves_the_entry_unresolved() {
    enum Read {
        Nothing,
        SeqFails,
        AncestorFails,
    }
    for read in [Read::Nothing, Read::SeqFails, Read::AncestorFails] {
        let world = World::new(Faults::none());
        let chain = world.plant_chain(&a(), 1, 0x70);
        let base = Some(GrainId::of(&chain[0]));
        let c1 = good_root(&a(), 2, base, 1);
        match read {
            // Every PUT fails and every read finds nothing: an injected
            // failure applies nothing.
            Read::Nothing => {}
            Read::SeqFails => world
                .store
                .set_read_fault(&a(), 2, Some(ReadFault::Transport)),
            Read::AncestorFails => {
                world.plant(&a(), 2, &good_root(&a(), 2, base, 2));
                world
                    .store
                    .set_read_fault(&a(), 1, Some(ReadFault::Transport));
            }
        }
        let faults = match read {
            Read::Nothing => (0..64)
                .step_by(2)
                .fold(Faults::none(), |f, at| f.with(Fault::Fail(at))),
            _ => Faults::none(),
        };
        let world = World {
            store: TestStore {
                inner: Arc::new(world.sim.node(2, faults)),
                faults: Arc::clone(&world.store.faults),
                hold: Arc::clone(&world.store.hold),
            },
            ..world
        };
        seed(
            &world.log,
            &a(),
            log_bytes(&envelope(&a(), WORLD_EPOCH), &open_entry(&c1)),
        );
        let row = run_until_stuck(&world, &c1, StuckState::Unresolved, 3);
        assert!(row.reissues >= 3);
        assert_eq!(
            outcome(&committed(&world.log, &a())),
            None,
            "the entry stays open"
        );
        let puts = world.puts(&a(), 2);
        assert!(puts.len() >= 4, "re-issued: {puts:?}");
        assert!(all_carry(&puts, &c1), "only the recorded bytes: {puts:?}");
        assert_eq!(world.log.violations(), []);
    }
}

/// A PUT whose failure is terminal (it applied nothing), one that landed
/// and reported failure, and one whose write lands only after its caller
/// was told it failed: none closes the entry, and the entry's own bytes
/// landing, late or not, close it landed.
#[test]
fn a_failed_put_never_closes_the_entry_and_a_late_landing_is_the_entrys_own() {
    // The worker's first store operation is its first PUT; its second is
    // the classification read.
    for fault in [
        Fault::Fail(0),
        Fault::LandButReportFailure(0),
        Fault::DeferPut {
            at: 0,
            release_after: 0,
        },
        Fault::DeferPut {
            at: 0,
            release_after: 1,
        },
    ] {
        let c1 = good_root(&a(), 1, None, 1);
        let world = World::with_records(&a(), &open_entry(&c1), Faults::just(fault));
        let (handle, driver) = world.start(&[a()]);
        let sub = submission(&a(), 1, &c1);
        let (_, answer) = run_beside(0, driver, async move {
            let answer = settle(&handle, &sub).await;
            handle.stop().await;
            answer
        });
        assert!(
            matches!(answer, Answer::Landed { .. }),
            "{fault:?}: {answer:?}"
        );
        let puts = world.puts(&a(), 1);
        assert!(puts[0].contains("-> failed("), "{fault:?}: {puts:?}");
        assert!(all_carry(&puts, &c1), "{fault:?}: {puts:?}");
        assert_eq!(world.log.violations(), []);
    }
}

/// A step that completes before its worker observes a stop has its
/// outcome recorded, even when the stop was requested first: the step's
/// read is released and the stop requested in one poll of the client, so
/// the worker's next poll finds both, and its race takes the step.
#[test]
fn a_step_that_completes_before_the_stop_is_observed_records_its_outcome() {
    for seed_n in 0..8 {
        let c1 = good_root(&a(), 1, None, 1);
        let world = World::with_records(&a(), &open_entry(&c1), Faults::none());
        world.store.hold_read(&a(), 1);
        let (handle, driver) = world.start(&[a()]);
        let store = world.store.clone();
        let (end, stopped) = run_beside(seed_n, driver, async move {
            while !store.hold_reached() {
                yield_once().await;
            }
            store.release();
            handle.stop().await
        });
        assert_eq!(end, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(stopped, RunEnd::Stopped, "seed {seed_n}");
        let d = decision_of(1, 1, &c1);
        assert_eq!(
            outcome(&committed(&world.log, &a())),
            Some(landed(&d).body().clone()),
            "seed {seed_n}: the outcome is recorded"
        );
        assert_eq!(world.puts(&a(), 1).len(), 1, "seed {seed_n}");
        assert_eq!(world.log.violations(), [], "seed {seed_n}");
    }
}

/// A step still running when its worker observes the stop is driven to
/// its end, and its outcome is not recorded: the entry stays open in the
/// log, and the next start classifies it afresh and closes it landed.
#[test]
fn a_step_running_when_the_stop_is_observed_finishes_and_records_nothing() {
    for seed_n in 0..8 {
        let c1 = good_root(&a(), 1, None, 1);
        let world = World::with_records(&a(), &open_entry(&c1), Faults::none());
        world.store.hold_read(&a(), 1);
        let (handle, driver) = world.start(&[a()]);
        let store = world.store.clone();
        let (end, (stopped, released_first)) = run_beside(seed_n, driver, async move {
            while !store.hold_reached() {
                yield_once().await;
            }
            // The stop is requested on the race's first poll; the read is
            // released only after the worker has had time to observe it.
            let mut stop = pin!(handle.stop());
            let mut release = pin!(async {
                for _ in 0..64 {
                    yield_once().await;
                }
                store.release();
            });
            match race(stop.as_mut(), release.as_mut()).await {
                Raced::First(end) => (end, false),
                Raced::Second(()) => (stop.await, true),
            }
        });
        assert!(
            released_first,
            "seed {seed_n}: the stop waited for the step"
        );
        assert_eq!(end, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(stopped, RunEnd::Stopped, "seed {seed_n}");
        let d = decision_of(1, 1, &c1);
        assert_eq!(
            committed(&world.log, &a()),
            open_entry(&c1),
            "seed {seed_n}: no outcome is recorded"
        );
        assert_eq!(world.puts(&a(), 1).len(), 1, "seed {seed_n}");

        let (handle, driver) = world.start(&[a()]);
        let sub = submission(&a(), 1, &c1);
        let (end, answer) = run_beside(seed_n, driver, async move {
            let answer = settle(&handle, &sub).await;
            handle.stop().await;
            answer
        });
        assert_eq!(end, RunEnd::Stopped, "seed {seed_n}");
        assert!(
            matches!(answer, Answer::Landed { .. }),
            "seed {seed_n}: {answer:?}"
        );
        assert_eq!(
            outcome(&committed(&world.log, &a())),
            Some(landed(&d).body().clone()),
            "seed {seed_n}: the next start closes it"
        );
        assert_eq!(world.log.violations(), [], "seed {seed_n}");
    }
}

/// A wedge clears when its occupant is removed out of band: the re-issue
/// lands and the entry closes landed.
#[test]
fn a_wedge_clears_when_the_occupant_is_removed() {
    let c1 = good_root(&a(), 1, None, 1);
    let world = World::with_records(&a(), &open_entry(&c1), Faults::none());
    world.plant(&a(), 1, b"a squatter");
    let (handle, driver) = world.start(&[a()]);
    let admin = world.sim.admin();
    let sub = submission(&a(), 1, &c1);
    let (_, answer) = run_beside(0, driver, async move {
        await_row(&handle, &a(), AMPLE_BOUND, |row| {
            row.state == StuckState::Wedged
        })
        .await;
        assert!(admin.delete_root(&a(), 1));
        let answer = settle(&handle, &sub).await;
        handle.stop().await;
        answer
    });
    assert!(matches!(answer, Answer::Landed { .. }), "{answer:?}");
    assert_eq!(world.log.violations(), []);
}

/// A foreign valid root on the base whose ancestor was deleted out of
/// band wedges, not lost; with the ancestor restored it closes lost; and
/// while the ancestor is absent, a submission with no entry open meets
/// rule 6 and is answered "volume damaged".
#[test]
fn a_missing_ancestor_wedges_then_restored_closes_lost_and_absent_is_damage() {
    let world = World::new(Faults::none());
    let chain = world.plant_chain(&a(), 1, 0x80);
    let base = Some(GrainId::of(&chain[0]));
    let c1 = good_root(&a(), 2, base, 1);
    let foreign = good_root(&a(), 2, base, 2);
    world.plant(&a(), 2, &foreign);
    world.delete(&a(), 1);
    seed(
        &world.log,
        &a(),
        log_bytes(&envelope(&a(), WORLD_EPOCH), &open_entry(&c1)),
    );
    let (handle, driver) = world.start(&[a()]);
    let admin = world.sim.admin();
    let ancestor = chain[0].clone();
    let sub = submission(&a(), 1, &c1);
    let next = good_root(&a(), 3, Some(GrainId::of(&foreign)), 3);
    let (_, answers) = run_beside(0, driver, async move {
        await_row(&handle, &a(), AMPLE_BOUND, |row| {
            row.state == StuckState::Wedged && row.reissues >= 1
        })
        .await;
        assert!(admin.plant_root(&a(), 1, ancestor.clone()));
        let closed = settle(&handle, &sub).await;
        assert!(admin.delete_root(&a(), 1));
        let damaged = handle.submit(submission(&a(), 2, &next)).await;
        assert!(admin.plant_root(&a(), 1, ancestor));
        let healed = handle.submit(submission(&a(), 2, &next)).await;
        handle.stop().await;
        (closed, damaged, healed)
    });
    assert!(
        matches!(answers.0, Answer::Lost { occupant, .. } if occupant == GrainId::of(&foreign)),
        "{:?}",
        answers.0
    );
    assert_eq!(answers.1, Answer::VolumeDamaged);
    assert!(
        matches!(answers.2, Answer::Accepted { .. }),
        "{:?}",
        answers.2
    );
    assert_eq!(world.log.violations(), []);
}

// ---------------------------------------------------------- recovery

/// A committed outcome is restored, never re-classified: a lost entry
/// whose own bytes landed later stays lost, a landed entry whose seq now
/// holds another root stays landed, and no PUT or read of the seq is
/// made for either.
#[test]
fn replay_never_reclassifies_a_committed_outcome() {
    let c1 = good_root(&a(), 1, None, 1);
    let foreign = good_root(&a(), 1, None, 2);
    let d = decision_of(1, 1, &c1);
    for (closing, at_seq) in [
        (lost(&d, GrainId::of(&foreign)), c1.clone()),
        (landed(&d), foreign.clone()),
    ] {
        let world = World::with_records(
            &a(),
            &[d.clone(), attestation(&d), closing.clone()],
            Faults::none(),
        );
        world.plant(&a(), 1, &at_seq);
        let (handle, driver) = world.start(&[a()]);
        let sub = submission(&a(), 1, &c1);
        let (_, answer) = run_beside(0, driver, async move {
            let answer = handle.submit(sub).await;
            handle.stop().await;
            answer
        });
        match closing.body() {
            RecordBody::Lost { .. } => assert!(
                matches!(answer, Answer::Lost { occupant, .. } if occupant == GrainId::of(&foreign)),
                "{answer:?}"
            ),
            _ => assert!(matches!(answer, Answer::Landed { .. }), "{answer:?}"),
        }
        assert!(world.puts(&a(), 1).is_empty(), "no PUT for a closed entry");
        assert_eq!(committed(&world.log, &a()).len(), 3);
        assert_eq!(world.log.violations(), []);
    }
}

/// An entry whose decision committed and whose attestation did not gets
/// its attestation committed before any PUT; if that append fails, the
/// engine fences and nothing is ever published.
#[test]
fn no_put_precedes_the_attestation() {
    let c1 = good_root(&a(), 1, None, 1);
    let decided = vec![decision_of(1, 1, &c1)];

    let world = World::with_records(&a(), &decided, Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let sub = submission(&a(), 1, &c1);
    let (_, answer) = run_beside(0, driver, async move {
        let answer = settle(&handle, &sub).await;
        handle.stop().await;
        answer
    });
    assert!(matches!(answer, Answer::Landed { .. }), "{answer:?}");
    let trace = world.sim.trace().render();
    let append = trace.find("log-call call=append").unwrap();
    let put = trace.find("put-root").unwrap();
    assert!(append < put, "the attestation precedes the PUT");

    let dry = World::with_records(&a(), &decided, Faults::none());
    dry.start(&[a()]);
    // The attestation's record sync: the second step after the start.
    let fail_at = dry.log.steps() + 1;
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: fail_at }));
    seed(
        &log,
        &a(),
        log_bytes(&envelope(&a(), WORLD_EPOCH), &decided),
    );
    let world = World::over(sim, log, Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let (end, _) = run_to_stop(0, handle, driver);
    assert!(matches!(end, RunEnd::Fenced(_)), "{end:?}");
    assert!(
        world.puts(&a(), 1).is_empty(),
        "no PUT without the attestation"
    );
    assert_eq!(world.log.violations(), []);
}

// ----------------------------------------------------------- the fence

/// Volume B's entry is open and re-issuing; volume A's decision fails its
/// record sync. The whole engine fences: A's submission is answered
/// `Fenced`, B's worker issues at most the one PUT already begun, and the
/// run ends fenced.
#[test]
fn a_failed_sync_on_one_volume_stops_every_volumes_puts() {
    let cb = good_root(&b(), 1, None, 1);
    let plant = |world: &World| {
        seed(
            &world.log,
            &a(),
            log_bytes(&envelope(&a(), WORLD_EPOCH), &[]),
        );
        seed(
            &world.log,
            &b(),
            log_bytes(&envelope(&b(), WORLD_EPOCH), &open_entry(&cb)),
        );
        // B's seq never reads: its entry stays unresolved.
        world
            .store
            .set_read_fault(&b(), 1, Some(ReadFault::Transport));
    };
    let dry = World::new(Faults::none());
    plant(&dry);
    dry.start(&[a(), b()]);
    // A's decision is the first log call after the start: B makes none.
    let fail_at = dry.log.steps() + 1;
    for seed_n in 0..8 {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: fail_at }));
        let world = World::over(sim, log, Faults::none());
        plant(&world);
        let (handle, driver) = world.start(&[a(), b()]);
        let ca = good_root(&a(), 1, None, 1);
        let (end, answer) = run_beside(seed_n, driver, async move {
            await_row(&handle, &b(), AMPLE_BOUND, |row| row.reissues >= 2).await;
            let answer = handle.submit(submission(&a(), 1, &ca)).await;
            // Time for B to re-issue, were it still publishing after the
            // fence; the stop comes only after it.
            for _ in 0..64 {
                yield_once().await;
            }
            handle.stop().await;
            answer
        });
        assert_eq!(answer, Answer::Fenced, "seed {seed_n}");
        assert!(matches!(end, RunEnd::Fenced(_)), "seed {seed_n}: {end:?}");
        let trace = world.sim.trace().render();
        let fenced_at = trace.find("call=append vol=vol-a -> failed").unwrap();
        let after = trace[fenced_at..].matches("put-root vol=vol-b").count();
        assert!(after <= 1, "seed {seed_n}: {after} PUTs after the fence");
        assert!(world.puts(&a(), 1).is_empty(), "seed {seed_n}");
        assert_eq!(world.log.violations(), [], "seed {seed_n}");
    }
}

// ---------------------------------------------------- head verification

use super::super::chain::tests::scripted::{Call, ScriptedStore};
use std::sync::atomic::AtomicUsize;

type ScriptedDriver<P> =
    AuthorityDriver<SharedLog, ScriptedStore, FixedClock, SimRng, SeededSecureRandom, P>;

pub(super) struct ScriptedVolume {
    pub(super) store: ScriptedStore,
    pub(super) log: Arc<SimDecisionLog>,
}

impl ScriptedVolume {
    pub(super) fn new(records: &[Record]) -> Self {
        let log = sim_log(&Sim::new(), LogFaults::none());
        seed_marker(&log, &RunMarker::Clean);
        seed(&log, &a(), log_bytes(&envelope(&a(), WORLD_EPOCH), records));
        Self {
            store: ScriptedStore::default(),
            log,
        }
    }

    pub(super) fn start<P: Pause + 'static>(
        &self,
        pause: P,
    ) -> (AuthorityHandle, ScriptedDriver<P>) {
        let parts = AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: SharedLog(Arc::clone(&self.log)),
            store: self.store.clone(),
            clock: FixedClock,
            rng: rng(1),
            secure_random: secure(1),
            pause,
        };
        block(async move { start(parts, boot(1), configs(&[a()])).await }).unwrap()
    }

    pub(super) fn plant(&self, len: u64) -> Vec<Vec<u8>> {
        let signer = publisher();
        let mut parent = None;
        (1..=len)
            .map(|seq| {
                let bytes = signed_root(&a(), seq, parent, 0x50, &[&signer]);
                self.store.set(a().as_str(), seq, Some(bytes.clone()));
                parent = Some(GrainId::of(&bytes));
                bytes
            })
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct HeldPause(Arc<PauseRounds>);

#[derive(Debug, Default)]
struct PauseRounds {
    entered: AtomicUsize,
    released: AtomicUsize,
}

impl HeldPause {
    pub(super) async fn wait(&self, round: usize) {
        wait_until(|| self.reached(round)).await;
    }

    fn reached(&self, round: usize) -> bool {
        self.0.entered.load(Ordering::SeqCst) == round
    }

    pub(super) fn release(&self) {
        self.0.released.fetch_add(1, Ordering::SeqCst);
    }
}

impl Pause for HeldPause {
    async fn pause(&self, _duration: Duration) {
        let round = self.0.entered.fetch_add(1, Ordering::SeqCst) + 1;
        while self.0.released.load(Ordering::SeqCst) < round {
            yield_once().await;
        }
    }
}

pub(super) async fn wait_until(mut ready: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if ready() {
            return;
        }
        yield_once().await;
    }
    panic!("script did not reach its next step");
}

pub(super) fn list_roots() -> Call {
    Call::List(a().as_str().to_owned())
}

pub(super) fn list_above(floor: u64) -> Call {
    Call::Above(a().as_str().to_owned(), floor)
}

pub(super) fn read_root(seq: u64) -> Call {
    Call::Get(a().as_str().to_owned(), seq)
}

pub(super) fn write_root(seq: u64, bytes: &[u8]) -> Call {
    Call::Put(a().as_str().to_owned(), seq, bytes.to_vec())
}

pub(super) fn verified(seq: u64, bytes: &[u8]) -> VerifiedHead {
    VerifiedHead::new(Some(HeadRef {
        head_seq: seq,
        head_id: GrainId::of(bytes),
    }))
}

pub(super) fn mismatched() -> Submission {
    submission_at(
        Epoch::from_bytes([0xFF; EPOCH_LEN]),
        &a(),
        1,
        b"epoch probe",
    )
}

pub(super) fn epoch_reply(head: Option<VerifiedHead>) -> Answer {
    Answer::EpochMismatch {
        epoch: World::position(1).epoch,
        head,
    }
}

pub(super) async fn await_closed(handle: &AuthorityHandle) {
    wait_until(|| {
        handle
            .volume_view(&a())
            .unwrap()
            .status()
            .unwrap()
            .open
            .is_none()
    })
    .await;
}

#[test]
fn serial_publication_has_exact_store_calls_at_each_depth() {
    for (depth, publishes) in [(0_u64, 40_u8), (64, 5), (2_500, 5)] {
        let world = ScriptedVolume::new(&[]);
        let chain = world.plant(depth);
        let (handle, driver) = world.start(YieldPause);
        let store = world.store.clone();
        let (end, ()) = run_beside(0, driver, async move {
            let signer = publisher();
            let mut parent = chain.last().map(|bytes| GrainId::of(bytes));
            let mut slow = None;
            for i in 1..=publishes {
                let seq = depth + u64::from(i);
                let bytes = signed_root(&a(), seq, parent, 0x60, &[&signer]);
                assert_eq!(
                    handle.submit(submission(&a(), i, &bytes)).await,
                    Answer::Accepted {
                        position: World::position(u64::from(i)),
                        candidate_id: GrainId::of(&bytes)
                    }
                );
                await_closed(&handle).await;
                let mut expected = if i == 1 || seq == 2 {
                    let mut calls = vec![list_roots()];
                    calls.extend((1..seq).rev().map(read_root));
                    calls
                } else {
                    let mut calls =
                        vec![list_above(seq - 3), read_root(seq - 1), read_root(seq - 2)];
                    if seq > 3 {
                        let at = slow.unwrap_or(seq - 3);
                        calls.push(read_root(at));
                        slow = (at > 1).then(|| at - 1);
                    }
                    calls
                };
                expected.extend([write_root(seq, &bytes), read_root(seq)]);
                assert_eq!(store.take_calls(), expected, "depth {depth}, publish {i}");
                parent = Some(GrainId::of(&bytes));
            }
            handle.stop().await;
        });
        assert_eq!(end, RunEnd::Stopped);
        let records = committed(&world.log, &a());
        assert_eq!(records.len(), usize::from(publishes) * 3);
        for (i, batch) in records.chunks_exact(3).enumerate() {
            assert!(
                matches!(batch[0].body(), RecordBody::Decision { root_seq, .. }
                if *root_seq == depth + u64::try_from(i).unwrap() + 1)
            );
            assert!(matches!(batch[1].body(), RecordBody::Attestation { .. }));
            assert!(matches!(batch[2].body(), RecordBody::Landed { .. }));
        }
    }
}

#[test]
fn classification_rechecks_below_an_anchor_at_the_occupant() {
    let seed_world = ScriptedVolume::new(&[]);
    let chain = seed_world.plant(4);
    let base = Some(GrainId::of(&chain[3]));
    let candidate = good_root(&a(), 5, base, 1);
    let occupant = good_root(&a(), 5, base, 2);
    let records = open_entry(&candidate);
    let world = ScriptedVolume::new(&records);
    world.plant(4);
    let put = write_root(5, &candidate);
    world.store.fail(put.clone(), false);
    let pause = HeldPause::default();
    let (handle, driver) = world.start(pause.clone());
    let store = world.store.clone();
    let (end, ()) = run_beside(0, driver, async move {
        pause.wait(1).await;
        assert_eq!(store.take_calls(), [put.clone(), read_root(5)]);
        store.set(a().as_str(), 5, Some(occupant.clone()));
        assert_eq!(
            handle.submit(mismatched()).await,
            epoch_reply(Some(verified(5, &occupant)))
        );
        let mut cold = vec![list_roots()];
        cold.extend((1..=5).rev().map(read_root));
        assert_eq!(store.take_calls(), cold);

        store.set(a().as_str(), 2, None);
        pause.release();
        let view = || handle.volume_view(&a()).unwrap().status().unwrap().open;
        wait_until(|| pause.reached(2) || view().is_none()).await;
        assert_eq!(
            view(),
            Some(OpenPosition {
                entry_seq: 1,
                candidate_id: GrainId::of(&candidate)
            }),
            "the foreign occupant must wedge rather than close the entry"
        );
        let rows = handle.report(AMPLE_BOUND).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, StuckState::Wedged);
        assert_eq!(
            store.take_calls(),
            [put, read_root(5), read_root(4), read_root(3), read_root(2)]
        );
        handle.stop().await;
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(committed(&world.log, &a()), records);
}

#[test]
fn off_base_occupant_rewarms_in_the_pause_and_the_next_wedge_clears_it() {
    let original = good_root(&a(), 1, None, 1);
    let candidate = good_root(&a(), 2, Some(GrainId::of(&original)), 2);
    let replacement = good_root(&a(), 1, None, 3);
    let occupant = good_root(&a(), 2, Some(GrainId::of(&replacement)), 4);
    let records = open_entry(&candidate);
    let world = ScriptedVolume::new(&records);
    world.store.set(a().as_str(), 1, Some(replacement));
    world.store.set(a().as_str(), 2, Some(occupant.clone()));
    let pause = HeldPause::default();
    let (handle, driver) = world.start(pause.clone());
    let store = world.store.clone();
    let (end, ()) = run_beside(0, driver, async move {
        for round in [1, 2] {
            pause.wait(round).await;
            let rows = handle.report(AMPLE_BOUND).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].state, StuckState::Wedged);
            assert_eq!(
                store.take_calls(),
                [write_root(2, &candidate), read_root(2)]
            );
            assert_eq!(
                handle.submit(mismatched()).await,
                epoch_reply(Some(verified(2, &occupant)))
            );
            assert_eq!(
                store.take_calls(),
                [list_roots(), read_root(2), read_root(1)]
            );
            // The fresh head became an anchor; its first slow step reads seq 1.
            assert_eq!(
                handle.submit(mismatched()).await,
                epoch_reply(Some(verified(2, &occupant)))
            );
            assert_eq!(
                store.take_calls(),
                [list_above(1), read_root(2), read_root(1)]
            );
            if round == 1 {
                pause.release();
            }
        }
        handle.stop().await;
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(committed(&world.log, &a()), records);
}

mod reader_window {
    use granary_client::{
        HeadContext, ResolveError, ResolveTarget, RootVerifier, resolve_head_verified,
    };
    use granary_core::binstore::BinStore;
    use granary_core::{binfmt, binmap, manifest, sheaf};
    use granary_store::codec::GrainCodec;

    use super::*;

    const CONTENT: &[u8] = b"verified publication";

    async fn meta(store: &ScriptedStore, bytes: Vec<u8>) -> GrainId {
        let id = GrainId::of(&bytes);
        assert!(store.put_meta(a().as_str(), &id, bytes).await.unwrap());
        id
    }

    async fn content_roots(store: &ScriptedStore, len: u64) -> Vec<Vec<u8>> {
        let name = manifest::Name::new(b"file".to_vec()).unwrap();
        let tree = manifest::build_dir(&[manifest::DirEntry {
            name,
            kind: manifest::EntryKind::File {
                exec: false,
                size: u64::try_from(CONTENT.len()).unwrap(),
                grains: manifest::FileGrains::Inline(vec![manifest::GrainRef {
                    id: GrainId::of(CONTENT),
                    unpacked_len: u32::try_from(CONTENT.len()).unwrap(),
                }]),
            },
        }])
        .unwrap();
        let mut codec = GrainCodec::new().unwrap();
        let frames: Vec<_> = tree
            .nodes
            .iter()
            .map(|(id, bytes)| (*id, bytes.as_slice()))
            .chain([(GrainId::of(CONTENT), CONTENT)])
            .map(|(id, bytes)| binfmt::PackedFrame {
                id,
                frame: codec.compress_grain(bytes).unwrap(),
            })
            .collect();
        let bin = binfmt::encode_bin(&frames).unwrap();
        let digest = *GrainId::of(&bin).digest();
        let mut entries: Vec<_> = binfmt::decode_bin(&bin)
            .unwrap()
            .into_iter()
            .map(|entry| binmap::ShardEntry {
                id: entry.id,
                bin_ordinal: 0,
                offset: entry.offset,
                comp_len: entry.comp_len,
            })
            .collect();
        entries.sort_by_key(|entry| entry.id);
        assert!(store.put_bin(&digest, bin).await.unwrap());
        let table = meta(store, binmap::encode_bin_table(&[digest]).unwrap()).await;
        let shard = meta(store, binmap::encode_shard(&entries).unwrap()).await;
        let index = meta(
            store,
            binmap::encode_binmap_index(0, table, &[shard]).unwrap(),
        )
        .await;

        let signer = publisher();
        let mut roots = Vec::new();
        let mut sheaf_parent = None;
        let mut parent = None;
        for seq in 1..=len {
            let timestamp = Timestamp {
                secs: 1_760_000_000 + i64::try_from(seq).unwrap(),
                nanos: 0,
            };
            let sheaf_head = meta(
                store,
                sheaf::encode_sheaf(&sheaf::SheafDoc {
                    parent: sheaf_parent,
                    manifest_root: tree.root,
                    timestamp,
                    ops: vec![sheaf::SheafOp::PublishTree],
                })
                .unwrap(),
            )
            .await;
            let mut doc = RootDoc {
                volume: a(),
                seq,
                parent,
                writer_uuid: [0xAB; root::WRITER_UUID_LEN],
                epoch: 7,
                timestamp,
                chunker_spec: "test-chunker".to_owned(),
                manifest_root: tree.root,
                binmap_index: index,
                sheaf_head,
                sigs: Vec::new(),
            };
            doc.sigs.push(RootSig {
                key_id: signer.key_id(),
                sig: signer.sign(&root::signing_prefix_of(&doc).unwrap()),
            });
            let bytes = root::encode_root(&doc).unwrap();
            sheaf_parent = Some(sheaf_head);
            parent = Some(GrainId::of(&bytes));
            roots.push(bytes);
        }
        roots
    }

    async fn online_read(store: &ScriptedStore) -> (Result<(u64, GrainId), ResolveError>, Vec<u8>) {
        let mut emitted = Vec::new();
        let names = [manifest::Name::new(b"file".to_vec()).unwrap()];
        let result = resolve_head_verified(
            store,
            a().as_str(),
            &RootVerifier::trusting(*publisher().public_key()).unwrap(),
            &HeadContext::new(Box::new(FixedClock), Box::new(rng(1))),
            None,
            ResolveTarget::Path(&names),
            &mut |_, bytes| {
                emitted.extend_from_slice(bytes);
                Ok(())
            },
        )
        .await
        .map(|out| (out.seq, GrainId::of(&out.root_bytes)));
        (result, emitted)
    }

    #[test]
    fn below_anchor_damage_can_land_before_the_slow_walk_refuses_it() {
        let world = ScriptedVolume::new(&[]);
        let (handle, driver) = world.start(YieldPause);
        let store = world.store.clone();
        let log = Arc::clone(&world.log);
        let (end, ()) = run_beside(0, driver, async move {
            let roots = content_roots(&store, 7).await;
            for (i, root) in roots[..5].iter().enumerate() {
                let seq = u8::try_from(i + 1).unwrap();
                assert_eq!(
                    handle.submit(submission(&a(), seq, root)).await,
                    Answer::Accepted {
                        position: World::position(u64::from(seq)),
                        candidate_id: GrainId::of(root)
                    }
                );
                await_closed(&handle).await;
            }
            let (result, emitted) = online_read(&store).await;
            assert_eq!(result.unwrap(), (5, GrainId::of(&roots[4])));
            assert_eq!(emitted, CONTENT);
            store.take_calls();

            store.set(a().as_str(), 2, None);
            let sixth = submission(&a(), 6, &roots[5]);
            assert_eq!(
                handle.submit(sixth).await,
                Answer::Accepted {
                    position: World::position(6),
                    candidate_id: GrainId::of(&roots[5]),
                }
            );
            await_closed(&handle).await;
            let log_after_landing = log.read(&a()).await.unwrap();
            let Classified::Log { records, .. } =
                classify(log_after_landing.as_ref().unwrap(), &a()).unwrap()
            else {
                panic!("expected a committed log");
            };
            assert_eq!(records.len(), 18);
            assert_eq!(records[15], decision_of(6, 6, &roots[5]));
            assert_eq!(records[17], landed(&records[15]));
            // The slow step completed its pass at seq 1, leaving the
            // persistent hole at seq 2 for the next pass.
            assert_eq!(
                store.take_calls(),
                [
                    list_above(3),
                    read_root(5),
                    read_root(4),
                    read_root(1),
                    write_root(6, &roots[5]),
                    read_root(6),
                ]
            );

            store.set(a().as_str(), 2, Some(roots[1].clone()));
            let (result, emitted) = online_read(&store).await;
            assert_eq!(result.unwrap(), (6, GrainId::of(&roots[5])));
            assert_eq!(emitted, CONTENT);
            store.set(a().as_str(), 2, None);
            let (result, emitted) = online_read(&store).await;
            assert!(
                matches!(result, Err(ResolveError::ChainBroken { seq: 2 })),
                "{result:?}"
            );
            assert!(emitted.is_empty());
            store.take_calls();

            let head = Some(verified(6, &roots[5]));
            assert_eq!(handle.submit(mismatched()).await, epoch_reply(head));
            assert_eq!(
                store.take_calls(),
                [list_above(4), read_root(6), read_root(5), read_root(4)]
            );
            assert_eq!(handle.submit(mismatched()).await, epoch_reply(head));
            assert_eq!(
                store.take_calls(),
                [list_above(5), read_root(6), read_root(3)]
            );
            let seventh = submission(&a(), 7, &roots[6]);
            assert_eq!(handle.submit(seventh).await, Answer::VolumeDamaged);
            assert_eq!(
                store.take_calls(),
                [list_above(5), read_root(6), read_root(2)]
            );
            assert_eq!(log.read(&a()).await.unwrap(), log_after_landing);

            store.set(a().as_str(), 2, Some(roots[1].clone()));
            assert_eq!(handle.submit(mismatched()).await, epoch_reply(head));
            let mut cold = vec![list_roots()];
            cold.extend((1..=6).rev().map(read_root));
            assert_eq!(store.take_calls(), cold);
            handle.stop().await;
        });
        assert_eq!(end, RunEnd::Stopped);
        assert_eq!(world.log.violations(), []);
    }
}

#[test]
fn slow_read_retry_and_growth_keep_the_cursor_until_it_reaches_damage() {
    let world = ScriptedVolume::new(&[]);
    let chain = world.plant(5);
    let (handle, driver) = world.start(YieldPause);
    let store = world.store.clone();
    let (end, ()) = run_beside(0, driver, async move {
        assert_eq!(
            handle.submit(mismatched()).await,
            epoch_reply(Some(verified(5, &chain[4])))
        );
        store.take_calls();
        store.fail(read_root(4), false);
        let sixth = good_root(&a(), 6, Some(GrainId::of(&chain[4])), 1);
        assert_eq!(
            handle.submit(submission(&a(), 1, &sixth)).await,
            Answer::Validation(crate::ValidationError::Unavailable)
        );
        assert_eq!(
            store.take_calls(),
            [list_above(4), read_root(5), read_root(4)]
        );

        store.set(a().as_str(), 6, Some(sixth.clone()));
        assert_eq!(
            handle.submit(mismatched()).await,
            epoch_reply(Some(verified(6, &sixth)))
        );
        assert_eq!(
            store.take_calls(),
            [list_above(4), read_root(6), read_root(5), read_root(4)]
        );
        store.set(a().as_str(), 3, None);
        let seventh = good_root(&a(), 7, Some(GrainId::of(&sixth)), 1);
        assert_eq!(
            handle.submit(submission(&a(), 2, &seventh)).await,
            Answer::VolumeDamaged
        );
        assert_eq!(
            store.take_calls(),
            [list_above(5), read_root(6), read_root(3)]
        );
        handle.stop().await;
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(committed(&world.log, &a()), []);
}

#[test]
fn restart_reads_cold_with_or_without_a_recovered_open_entry() {
    for open in [false, true] {
        let world = ScriptedVolume::new(&[]);
        let chain = world.plant(5);
        let candidate = good_root(&a(), 6, Some(GrainId::of(&chain[4])), 9);
        let put = write_root(6, &candidate);
        let sub = submission(&a(), 1, &candidate);
        let pause = HeldPause::default();
        let (handle, driver) = world.start(pause.clone());
        let store = world.store.clone();
        let first_put = put.clone();
        let first_sub = sub.clone();
        let (end, ()) = run_beside(0, driver, async move {
            assert_eq!(
                handle.submit(mismatched()).await,
                epoch_reply(Some(verified(5, &chain[4])))
            );
            if open {
                store.fail(first_put, false);
                assert!(matches!(
                    handle.submit(first_sub).await,
                    Answer::Accepted { .. }
                ));
                pause.wait(1).await;
            }
            handle.stop().await;
        });
        assert_eq!(end, RunEnd::Stopped);
        let previous = committed(&world.log, &a());
        if open {
            assert_eq!(previous, open_entry(&candidate));
        } else {
            assert_eq!(previous, []);
        }

        world.store.set(a().as_str(), 2, None);
        world.store.take_calls();
        let pause = HeldPause::default();
        let (handle, driver) = world.start(pause.clone());
        let store = world.store.clone();
        let (end, ()) = run_beside(0, driver, async move {
            let mut calls = Vec::new();
            if open {
                store.fail(put.clone(), false);
                pause.wait(1).await;
                assert_eq!(
                    handle.submit(sub).await,
                    Answer::Open {
                        position: World::position(1),
                        candidate_id: GrainId::of(&candidate)
                    }
                );
                assert_eq!(handle.submit(mismatched()).await, epoch_reply(None));
                calls.extend([put, read_root(6)]);
            } else {
                assert_eq!(handle.submit(sub).await, Answer::VolumeDamaged);
            }
            calls.extend([
                list_roots(),
                read_root(5),
                read_root(4),
                read_root(3),
                read_root(2),
            ]);
            assert_eq!(store.take_calls(), calls);
            handle.stop().await;
        });
        assert_eq!(end, RunEnd::Stopped);
        assert_eq!(committed(&world.log, &a()), previous);
    }
}
