// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The owed-case matrix: the crash cases a publication authority owes on
//! an unprofiled volume. Cases 1 to 4, 6 and 11 run through the sweep's
//! harness, every run checked by its oracle, with both of each case's
//! arms asserted reached. Case 5's limit and case 12's media verdicts
//! run on the engine's plain test world (the harness's workload cannot
//! stage them); they assert their own outcomes, and no oracle runs over
//! them.
//!
//! Arms that are admission logic alone, with no crash in them, are the
//! engine's own tests, named where a case relies on them: a different
//! candidate refused while its operation's binding is open or landed
//! (`an_open_binding_refuses_and_no_successor_is_decided`,
//! `a_landed_binding_refuses_every_other_candidate`), a waiting
//! candidate not decided while an entry is wedged (`run_until_stuck`'s
//! assertion in the publication tests), and an unreadable classification
//! read staying unresolved (`nothing_or_a_failed_read_leaves_the_entry_unresolved`).

use std::sync::Arc;

use granary_core::authlog::{Envelope, RECORD_V1_MAX, Record, RecordBody, encode_append};
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::runmarker::RunMarker;
use granary_sim::decision_log::{LogFault, LogFaults, SimDecisionLog};
use granary_sim::fakes::{Fault, Faults, Sim};
use granary_sim::rng::Rng as SimRng;
use granary_sim::scenario::store_ops;
use granary_sim::trace::{Damage, LogCall, Op, Volume};

use super::super::{
    Answer, AuthorityParts, FixedClock, RunEnd, StartRefused, TestStore, VolumeRefusal, YieldPause,
    block, boot, configs, decision_of, good_root, rng, run_beside, secure, seed, seed_marker,
    settle, start, submission, submission_at,
};
use super::harness::{Cut, Ev};
use super::run::{Inject, Point, Run};
use super::workload::{OP_C1, OP_C3, Roots};
use super::{Dry, a, b, checked, discover, put_index};

/// Each append of the dry run: its volume, its record, and the index of
/// its first log step (its record write; then its record sync, its
/// mark's write and its mark's sync).
fn appends(dry: &Dry) -> Vec<(VolumeName, Record, u32)> {
    let firsts = dry
        .steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.call == LogCall::Append && s.within == 0)
        .map(|(i, _)| u32::try_from(i).unwrap());
    let records = dry.run.timeline.iter().filter_map(|(_, ev)| match ev {
        Ev::Appending { volume, record, .. } => Some((volume.clone(), record.clone())),
        _ => None,
    });
    records
        .zip(firsts)
        .map(|((volume, record), first)| (volume, record, first))
        .collect()
}

/// The first step of the append of `volume`'s record of `kind` for
/// `candidate`.
fn append_of(dry: &Dry, volume: &VolumeName, kind: u8, candidate: &[u8]) -> u32 {
    let id = GrainId::of(candidate);
    appends(dry)
        .into_iter()
        .find(|(v, r, _)| {
            v == volume && super::oracle::tag(r) == kind && r.body().identity().candidate_id() == id
        })
        .map(|(_, _, first)| first)
        .expect("the dry run appends it")
}

/// The point that injects `first` into the dry run's schedule under
/// `draw`, labelled from `dry`.
fn point(dry: &Dry, first: Inject, draw: u64) -> Point {
    super::labelled_point(dry, first, draw)
}

/// The events of process `process`.
fn of(run: &Run, process: u32) -> impl Iterator<Item = &Ev> {
    run.timeline
        .iter()
        .filter(move |(p, _)| *p == process)
        .map(|(_, ev)| ev)
}

/// Whether process 2 of `run` read `volume`'s log with `pick` among its
/// committed records.
fn recovered(run: &Run, volume: &VolumeName, pick: impl Fn(&Record) -> bool) -> bool {
    of(run, 2).any(|ev| matches!(ev, Ev::Read { volume: v, records, .. } if v == volume && records.iter().any(&pick)))
}

fn is(record: &Record, kind: u8, candidate: &[u8]) -> bool {
    super::oracle::tag(record) == kind
        && record.body().identity().candidate_id() == GrainId::of(candidate)
}

const DECISION: u8 = 1;
const ATTESTATION: u8 = 2;
const LANDED: u8 = 3;

/// Case 1, a crash at the decision's commit. Before it commits the retry
/// is evaluated anew: the decision is gone and `c1` is accepted again at
/// the same position. After it, recovery finds exactly the one decision
/// and completes its attestation before any PUT. Crashes at each of the
/// decision's four steps, under draws, reach both.
#[test]
fn owed_case_1_a_crash_at_the_decision_commit() {
    let dry = discover(0);
    let roots = Roots::new();
    let first = append_of(&dry, &a(), DECISION, &roots.c1);
    let (mut anew, mut found) = (0, 0);
    for step in first..first + 4 {
        for draw in 0..8 {
            let run = checked(point(&dry, Inject::LogCrash(step), draw));
            if recovered(&run, &a(), |r| is(r, DECISION, &roots.c1)) {
                let attested_first = of(&run, 2)
                    .find_map(|ev| match ev {
                        Ev::Appending { record, .. } if is(record, ATTESTATION, &roots.c1) => {
                            Some(true)
                        }
                        Ev::Put { seq: 1, .. } => Some(false),
                        _ => None,
                    })
                    .unwrap_or(false);
                assert!(attested_first, "{}: no attestation before the PUT", run.point);
                found += 1;
            } else if of(&run, 2).any(|ev| {
                matches!(ev, Ev::Emit { reply: super::super::Reply::Answer(Answer::Accepted { position, candidate_id }), .. }
                    if position.seq == 1 && *candidate_id == GrainId::of(&roots.c1))
            }) {
                anew += 1;
            }
        }
    }
    assert!(anew > 0 && found > 0, "anew {anew}, found {found}");
}

/// Case 2, a crash at the attestation's commit. Before it commits, no
/// PUT has happened and recovery commits the attestation first. After,
/// recovery re-issues exactly the recorded bytes and never another id.
#[test]
fn owed_case_2_a_crash_at_the_attestation_commit() {
    let dry = discover(0);
    let roots = Roots::new();
    let first = append_of(&dry, &a(), ATTESTATION, &roots.c1);
    let c1 = GrainId::of(&roots.c1);
    let (mut first_commit, mut reissued) = (0, 0);
    for step in first..first + 4 {
        for draw in 0..8 {
            let run = checked(point(&dry, Inject::LogCrash(step), draw));
            assert!(
                !of(&run, 1).any(|ev| matches!(ev, Ev::Put { seq: 1, .. })),
                "{}: a PUT before the attestation committed",
                run.point
            );
            let puts: Vec<GrainId> = of(&run, 2)
                .filter_map(|ev| match ev {
                    Ev::Put { seq: 1, id, volume } if *volume == a().as_str() => Some(*id),
                    _ => None,
                })
                .collect();
            assert!(puts.iter().all(|id| *id == c1), "{}: {puts:?}", run.point);
            if recovered(&run, &a(), |r| is(r, ATTESTATION, &roots.c1)) {
                reissued += usize::from(!puts.is_empty());
            } else {
                first_commit += 1;
            }
        }
    }
    assert!(
        first_commit > 0 && reissued > 0,
        "first commit {first_commit}, re-issued {reissued}"
    );
}

/// The store-operation index of the dry run's first PUT at A's seq 1.
fn first_put(dry: &Dry) -> u32 {
    put_index(&dry.run, 1, &a(), 1).unwrap()
}

/// Cases 3 and 4, a crash at the publication's commit point, and a lost
/// success response. The PUT applied and its answer lost: the next start
/// reads the bytes, records landed, and answers `c1` with its original
/// position. The PUT never sent: the entry stays open in the next
/// process, and no successor is decided before its outcome.
#[test]
fn owed_cases_3_and_4_the_publication_commit_point_and_a_lost_response() {
    let dry = discover(0);
    let roots = Roots::new();
    let k = first_put(&dry);
    let after = checked(point(&dry, Inject::Store(k, Cut::After), 0));
    let landed_read = of(&after, 2).any(|ev| {
        matches!(ev, Ev::Got { seq: 1, found: super::harness::Found::Id(id), .. } if *id == GrainId::of(&roots.c1))
    });
    assert!(landed_read, "the next start never read the landed bytes");
    let answered = of(&after, 2).any(|ev| {
        matches!(ev, Ev::Emit { reply: super::super::Reply::Answer(Answer::Landed { receipt, .. }), .. }
            if receipt.position.seq == 1 && receipt.stored_id == GrainId::of(&roots.c1))
    });
    assert!(answered, "c1 was not answered landed at its position");

    let before = checked(point(&dry, Inject::Store(k, Cut::Before), 0));
    let order: Vec<(u64, u8)> = of(&before, 2)
        .filter_map(|ev| match ev {
            Ev::Acked { volume, record } if *volume == a() => {
                Some((record.seq(), super::oracle::tag(record)))
            }
            _ => None,
        })
        .collect();
    let landed_at = order.iter().position(|r| *r == (1, LANDED)).unwrap();
    let successor_at = order.iter().position(|r| *r == (2, DECISION)).unwrap();
    assert!(
        landed_at < successor_at,
        "a successor was decided while c1 was open: {order:?}"
    );
}

/// Case 5, the deferred PUT, in the dry run: the engine's first PUT at
/// A's seq 2 is told it failed and lands later, and the entry lands.
#[test]
fn owed_case_5_a_delayed_put_lands_as_the_entrys_own() {
    let dry = discover(0);
    let name = Volume::from_checked(&a());
    let released = dry
        .run
        .sim
        .trace()
        .entries()
        .iter()
        .any(|e| matches!(&e.op, Op::ReleaseRoot { volume, seq: 2, .. } if *volume == name));
    assert!(released, "the held PUT never reached its release point");
    assert_eq!(dry.run.end, super::run::End::Clean);
}

/// Case 5's limit (spec §4.4): the lost candidate's own PUT lands late.
/// `c3`'s first PUT is held; `f3` takes seq 3 meanwhile, so `c3` is
/// recorded lost; `f3` is deleted out of band; the held PUT then lands
/// `c3` at seq 3. The order still says lost, and the chain holds `c3`.
#[test]
fn owed_case_5_limit_a_lost_candidates_late_landing() {
    let roots = Roots::new();
    let chain = [(1, &roots.c1), (2, &roots.c2)];
    let d = decision_of(1, OP_C3, &roots.c3);
    let open = vec![d.clone(), super::super::attestation(&d)];
    // Discover the index of the engine's PUT at seq 3 over a store with
    // no fault: the classification read that follows it is the next
    // operation.
    let index = {
        let world = super::super::World::with_records(&a(), &open, Faults::none());
        for (seq, bytes) in chain {
            world.plant(&a(), seq, bytes);
        }
        let (handle, driver) = world.start(&[a()]);
        let sub = submission(&a(), OP_C3, &roots.c3);
        let _ = run_beside(0, driver, async move {
            let answer = settle(&handle, &sub).await;
            handle.stop().await;
            answer
        });
        // One volume, so one worker: its store calls never overlap, and
        // the trace's order is the order their indices were claimed in.
        let name = Volume::from_checked(&a());
        let at = store_ops(&world.sim.trace(), 1)
            .iter()
            .position(|e| matches!(&e.op, Op::PutRoot { volume, seq: 3, .. } if *volume == name))
            .unwrap();
        u32::try_from(at).unwrap()
    };
    let world = super::super::World::with_records(
        &a(),
        &open,
        Faults::just(Fault::DeferPut {
            at: index,
            release_after: 1_000,
        }),
    );
    for (seq, bytes) in chain {
        world.plant(&a(), seq, bytes);
    }
    world.plant(&a(), 3, &roots.f3);
    let (handle, driver) = world.start(&[a()]);
    let sub = submission(&a(), OP_C3, &roots.c3);
    let (end, answer) = run_beside(0, driver, async move {
        let answer = settle(&handle, &sub).await;
        handle.stop().await;
        answer
    });
    assert_eq!(end, RunEnd::Stopped);
    assert!(
        matches!(answer, Answer::Lost { occupant, .. } if occupant == GrainId::of(&roots.f3)),
        "{answer:?}"
    );
    // The held PUT is still held: delete `f3`, then let enough store
    // operations pass for it to land.
    world.delete(&a(), 3);
    let oracle = world.sim.node(7, Faults::none());
    let name = a().as_str().to_owned();
    let landed = block(async move {
        use granary_core::rootstore::RootStore as _;
        for _ in 0..1_100 {
            let _ = oracle.max_seq(&name).await;
        }
        oracle.get_root(&name, 3).await
    });
    assert_eq!(
        landed.unwrap(),
        Some(roots.c3.clone()),
        "the lost candidate landed late"
    );
    let records = super::super::committed(&world.log, &a());
    assert!(
        matches!(
            records.last().map(Record::body),
            Some(RecordBody::Lost { .. })
        ),
        "the order still says lost"
    );
}

/// Case 6 and case 11 in the sweep's workload: the stale probes, the
/// duplicate, the loss and its rebase, and both squatters removed, all
/// reached by the dry run.
#[test]
fn owed_cases_6_and_11_the_workloads_arms() {
    let dry = discover(0);
    let arms = &dry.run.script.arms;
    for arm in [
        "stale-ahead-of-head",
        "stale-refused",
        "duplicate-landed",
        "lost",
    ] {
        assert_eq!(arms.get(arm), Some(&1), "{arm}: {arms:?}");
    }
    assert_eq!(arms.get("squatter-removed"), Some(&2), "{arms:?}");
}

// --------------------------------------------------------- case 12

/// A world whose A holds the workload's whole finished log and B its
/// own, the marker **running** under boot 1, the store the chain: a host
/// crash after it ran, with `media` applied at the crash.
struct Crashed {
    sim: Sim,
    log: Arc<SimDecisionLog>,
    roots: Roots,
}

const EPOCH: u8 = 0x5E;

fn envelope(volume: &VolumeName) -> Envelope {
    super::super::envelope(volume, EPOCH)
}

fn encoded(volume: &VolumeName, records: &[Record]) -> Vec<u8> {
    super::super::log_bytes(&envelope(volume), records)
}

impl Crashed {
    fn new(media: Option<LogFault>) -> Self {
        let sim = Sim::new();
        let roots = Roots::new();
        let faults = media.map_or_else(LogFaults::none, LogFaults::just);
        let log = Arc::new(sim.decision_log(0, faults));
        for volume in [a(), b()] {
            seed(&log, &volume, encoded(&volume, &roots.expected(&volume)));
        }
        seed_marker(&log, &RunMarker::Running(boot(1)));
        let admin = sim.admin();
        for (volume, seq, bytes) in [
            (a(), 1, &roots.c1),
            (a(), 2, &roots.c2),
            (a(), 3, &roots.f3),
            (a(), 4, &roots.c3p),
            (a(), 5, &roots.c4),
            (b(), 1, &roots.d1),
        ] {
            assert!(admin.plant_root(&volume, seq, bytes.clone()));
        }
        let _ = log.crash_host(&mut SimRng::seeded(1, 1));
        Self { sim, log, roots }
    }

    fn start(
        &self,
    ) -> Result<
        (
            super::super::AuthorityHandle,
            super::super::DriverOn<FixedClock>,
        ),
        StartRefused,
    > {
        let parts = AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: super::super::SharedLog(Arc::clone(&self.log)),
            store: TestStore::new(self.sim.node(1, Faults::none())),
            clock: FixedClock,
            rng: rng(2),
            secure_random: secure(2),
            pause: YieldPause,
        };
        let volumes = configs(&[a(), b()]);
        block(async move { start(parts, boot(2), volumes).await })
    }

    fn records(&self, volume: &VolumeName) -> Vec<Record> {
        super::super::committed(&self.log, volume)
    }
}

/// Case 12, corrupt committed history: the start refuses A, before any
/// PUT, and writes clean (no log write had been made).
#[test]
fn owed_case_12_corrupt_committed_history_refuses_before_publishing() {
    let world = Crashed::new(Some(LogFault::CorruptDetectable {
        volume: a(),
        record: 2,
    }));
    let refused = world.start().err();
    assert!(
        matches!(
            &refused,
            Some(StartRefused::Volume { volume, reason: VolumeRefusal::Damaged(_) }) if *volume == a()
        ),
        "{refused:?}"
    );
    assert_eq!(world.sim.trace().render().matches("put-root").count(), 0);
    assert_eq!(
        super::super::marker_says(&world.log),
        Some(RunMarker::Clean)
    );
}

/// Case 12, the accepted residual: the last record's mark destroyed is
/// discarded, exactly that record; the engine serves on and the entry it
/// reopened closes landed again from the store.
#[test]
fn owed_case_12_the_accepted_residual_is_discarded_and_the_engine_serves_on() {
    let world = Crashed::new(Some(LogFault::ResidualLoss {
        volume: a(),
        records: 1,
        into_record: false,
    }));
    let expected = world.roots.expected(&a());
    let (handle, driver) = world.start().expect("the residual is within the bound");
    assert_eq!(
        world.records(&a()),
        expected[..expected.len() - 1],
        "exactly the last record discarded"
    );
    let sub = submission_at(
        envelope(&a()).epoch(),
        &a(),
        super::workload::OP_C4,
        &world.roots.c4,
    );
    let (end, answer) = run_beside(0, driver, async move {
        let answer = settle(&handle, &sub).await;
        handle.stop().await;
        answer
    });
    assert_eq!(end, RunEnd::Stopped);
    assert!(matches!(answer, Answer::Landed { .. }), "{answer:?}");
    assert_eq!(world.records(&a()), expected);
}

/// Case 12, a residual loss beyond what one interrupted append can leave
/// (the marks of the last two records destroyed): refused.
#[test]
fn owed_case_12_a_loss_beyond_the_tail_bound_refuses() {
    let world = Crashed::new(Some(LogFault::ResidualLoss {
        volume: a(),
        records: 2,
        into_record: false,
    }));
    let refused = world.start().err();
    assert!(
        matches!(
            &refused,
            Some(StartRefused::Volume { volume, reason: VolumeRefusal::Damaged(_) }) if *volume == a()
        ),
        "{refused:?}"
    );
}

/// Case 12, a planted mark-free tail after the committed log: at the
/// largest record's length it is discarded, one byte longer refused.
#[test]
fn owed_case_12_a_tail_at_the_bound_is_discarded_and_one_past_it_refused() {
    let roots = Roots::new();
    let next = good_root(&a(), 6, Some(GrainId::of(&roots.c4)), 1);
    let half = {
        let d = decision_of(16, 6, &next);
        let pair = encode_append(&envelope(&a()), &d).unwrap();
        pair.record()[..pair.record().len() / 2].to_vec()
    };
    for (len, damage, admitted) in [
        (RECORD_V1_MAX, Damage::AtBound, true),
        (RECORD_V1_MAX + 1, Damage::Oversize, false),
    ] {
        let mut tail = half.clone();
        tail.resize(len, 0);
        let world = Crashed::new(Some(LogFault::PlantTail {
            volume: a(),
            keep: u32::try_from(roots.expected(&a()).len()).unwrap(),
            tail,
            damage,
        }));
        let started = world.start();
        assert_eq!(started.is_ok(), admitted, "{damage:?}: {:?}", started.err());
        if admitted {
            assert_eq!(world.records(&a()), roots.expected(&a()));
        }
    }
}

/// Case 12, a missing log: B, whose log is gone, answers "no log", while
/// A keeps being served.
#[test]
fn owed_case_12_a_missing_log_answers_no_log_while_another_volume_serves() {
    let sim = Sim::new();
    let roots = Roots::new();
    let log = Arc::new(sim.decision_log(0, LogFaults::none()));
    seed(&log, &a(), encoded(&a(), &roots.expected(&a())));
    seed_marker(&log, &RunMarker::Clean);
    let admin = sim.admin();
    for (seq, bytes) in [
        (1, &roots.c1),
        (2, &roots.c2),
        (3, &roots.f3),
        (4, &roots.c3p),
        (5, &roots.c4),
    ] {
        assert!(admin.plant_root(&a(), seq, bytes.clone()));
    }
    let parts = AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        log: super::super::SharedLog(Arc::clone(&log)),
        store: TestStore::new(sim.node(1, Faults::none())),
        clock: FixedClock,
        rng: rng(3),
        secure_random: secure(3),
        pause: YieldPause,
    };
    let volumes = configs(&[a(), b()]);
    let (handle, driver) = block(async move { start(parts, boot(1), volumes).await }).unwrap();
    let (end, (on_b, on_a)) = run_beside(0, driver, async move {
        let on_b = handle.submit(submission(&b(), 3, &roots.d1)).await;
        let on_a = handle
            .submit(submission_at(
                envelope(&a()).epoch(),
                &a(),
                OP_C1,
                &roots.c1,
            ))
            .await;
        handle.stop().await;
        (on_b, on_a)
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(on_b, Answer::NoLog);
    assert!(matches!(on_a, Answer::Landed { .. }), "{on_a:?}");
}
