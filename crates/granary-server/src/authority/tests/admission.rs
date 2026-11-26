// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Admission tests cover
//! each rule in order, the duplicate table, what is and is not written,
//! the log's growth bound, and concurrent submissions under the
//! simulator's scheduler.

use granary_store::crypto::HeadError;

use super::*;

/// The verified head at `seq` holding `bytes`.
fn head_at(seq: u64, bytes: &[u8]) -> VerifiedHead {
    VerifiedHead::new(Some(HeadRef {
        head_seq: seq,
        head_id: GrainId::of(bytes),
    }))
}

fn receipt(position: u64, seq: u64, bytes: &[u8]) -> Receipt {
    Receipt {
        position: World::position(position),
        seq,
        stored_id: GrainId::of(bytes),
    }
}

fn count(records: &[Record], pick: impl Fn(&RecordBody) -> bool) -> usize {
    records.iter().filter(|r| pick(r.body())).count()
}

/// Volume A's worker admits each of `subs` in turn, called directly on
/// the no-entry path with `world`'s store: the answers, and the worker's
/// state before and after.
fn admit_each(world: &World, subs: Vec<Submission>) -> (Vec<Answer>, VolumeState, VolumeState) {
    let (handle, driver) = world.start(&[a()]);
    let AuthorityDriver {
        log,
        store,
        clock,
        rng,
        secure_random,
        pause,
        gate,
        shared,
        mut workers,
        ..
    } = driver;
    let mut worker = workers.remove(0);
    let out = block(async move {
        let engine = Engine {
            log: &log,
            store: &store,
            clock: clock.as_ref(),
            rng: &rng,
            secure_random: &secure_random,
            pause: &pause,
            gate: &gate,
            shared: &shared,
        };
        let before = worker.state().cloned().unwrap();
        let mut answers = Vec::new();
        for sub in &subs {
            answers.push(worker.admit(&engine, sub).await);
        }
        (answers, before, worker.state().cloned().unwrap())
    });
    drop(handle);
    out
}

/// `genuine` with a second signature slot under a key no volume
/// configures, its id and signature invented from `n`: a candidate
/// anyone holding `genuine` can mint, since the signature section lies
/// outside the signed prefix and the head check skips a slot whose key is
/// not configured.
fn malleated(genuine: &[u8], n: u16) -> Vec<u8> {
    let mut doc = root::decode_root(genuine).unwrap();
    let [hi, lo] = n.to_be_bytes();
    let mut key_id = [0xC0; root::KEY_ID_LEN];
    key_id[0] = hi;
    key_id[1] = lo;
    let mut sig = [0x5A; root::ED25519_SIG_LEN];
    sig[0] = hi;
    sig[1] = lo;
    doc.sigs.push(RootSig { key_id, sig });
    root::encode_root(&doc).unwrap()
}

// ------------------------------------------------------------- rule 1

/// A configured volume with no log answers "no log", and a first
/// submission never creates one: no log call is made for it, and nothing
/// is published.
#[test]
fn a_volume_with_no_log_answers_no_log_and_no_log_is_created() {
    let world = World::new(Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let candidate = good_root(&a(), 1, None, 1);
    let (end, answers) = run_beside(0, driver, async move {
        let mut answers = Vec::new();
        for _ in 0..3 {
            answers.push(handle.submit(submission(&a(), 1, &candidate)).await);
        }
        handle.stop().await;
        answers
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(answers, vec![Answer::NoLog; 3]);
    assert_eq!(read_log(&world.log, &a()), None, "no log was created");
    assert!(calls(&world.sim, "initialise").is_empty());
    assert!(calls(&world.sim, "append").is_empty());
    assert!(world.puts(&a(), 1).is_empty());
    assert_eq!(world.log.violations(), []);
}

/// An unconfigured volume is answered by the handle.
#[test]
fn an_unconfigured_volume_is_refused() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let candidate = good_root(&b(), 1, None, 1);
    let (_, answer) = run_beside(0, driver, async move {
        let answer = handle.submit(submission(&b(), 1, &candidate)).await;
        handle.stop().await;
        answer
    });
    assert_eq!(answer, Answer::UnconfiguredVolume);
}

// ------------------------------------------------------------- rule 2

/// Candidates that are not well formed, each submitted many times: every
/// one is answered "invalid candidate", nothing is appended, and nothing
/// is published. The chain is empty, so each of them would otherwise
/// reach rule 7 or rule 8.
#[test]
fn junk_is_rejected_every_time_and_the_log_never_grows() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let before = read_log(&world.log, &a());
    let mut bad_sig = good_root(&a(), 1, None, 3);
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0x01;
    let junk: Vec<Vec<u8>> = vec![
        b"not a root".to_vec(),
        Vec::new(),
        good_root(&b(), 1, None, 1),
        signed_root(&a(), 1, None, 2, &[&stranger()]),
        bad_sig,
        good_root(&a(), u64::MAX - 1, Some(GrainId::of(b"p")), 4),
    ];
    let (end, answers) = run_beside(0, driver, async move {
        let mut answers = Vec::new();
        for round in 0..8_u8 {
            for (n, bytes) in junk.iter().enumerate() {
                let operation = round
                    .wrapping_mul(16)
                    .wrapping_add(u8::try_from(n).unwrap());
                answers.push(handle.submit(submission(&a(), operation, bytes)).await);
            }
        }
        handle.stop().await;
        answers
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(answers.len(), 48);
    for (n, answer) in answers.iter().enumerate() {
        let expected = match n % 6 {
            0..=4 => {
                matches!(answer, Answer::InvalidCandidate(InvalidCandidate::Root(_)))
            }
            _ => {
                *answer
                    == Answer::InvalidCandidate(InvalidCandidate::SeqOutOfRange {
                        seq: u64::MAX - 1,
                    })
            }
        };
        assert!(expected, "submission {n}: {answer:?}");
    }
    assert!(matches!(
        answers[3],
        Answer::InvalidCandidate(InvalidCandidate::Root(HeadError::NoTrustedSlot))
    ));
    assert!(matches!(
        answers[4],
        Answer::InvalidCandidate(InvalidCandidate::Root(HeadError::BadSignature { .. }))
    ));
    assert_eq!(read_log(&world.log, &a()), before, "the log is unchanged");
    assert!(calls(&world.sim, "append").is_empty());
    assert!(world.puts(&a(), 1).is_empty());
    assert_eq!(world.log.violations(), []);
}

/// The highest seq rule 2 accepts is `u64::MAX - 2`: a candidate there
/// passes rule 2 (and meets rule 7 on this chain), and one at
/// `u64::MAX - 1` does not.
#[test]
fn rule_2s_seq_bound_is_the_last_seq_with_a_publishable_successor() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let parent = Some(GrainId::of(b"parent"));
    let highest = good_root(&a(), u64::MAX - 2, parent, 1);
    let over = good_root(&a(), u64::MAX - 1, parent, 1);
    let (_, answers) = run_beside(0, driver, async move {
        let answers = (
            handle.submit(submission(&a(), 1, &highest)).await,
            handle.submit(submission(&a(), 2, &over)).await,
        );
        handle.stop().await;
        answers
    });
    assert_eq!(
        answers.0,
        Answer::StaleBase {
            head: VerifiedHead::new(None),
        }
    );
    assert_eq!(
        answers.1,
        Answer::InvalidCandidate(InvalidCandidate::SeqOutOfRange { seq: u64::MAX - 1 })
    );
}

// -------------------------------------------------- the duplicate table

/// The same operation and candidate: accepted once, then its recorded
/// answer every time, with the head it landed on; nothing more is
/// written.
#[test]
fn the_same_operation_and_candidate_gets_its_recorded_answer() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let c1 = good_root(&a(), 1, None, 1);
    let sub = submission(&a(), 1, &c1);
    let (end, (first, settled, again)) = run_beside(3, driver, async move {
        let first = handle.submit(sub.clone()).await;
        let settled = settle(&handle, &sub).await;
        let again = handle.submit(sub.clone()).await;
        handle.stop().await;
        (first, settled, again)
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(
        first,
        Answer::Accepted {
            position: World::position(1),
            candidate_id: GrainId::of(&c1),
        }
    );
    let landed = Answer::Landed {
        receipt: receipt(1, 1, &c1),
        head: Some(head_at(1, &c1)),
    };
    assert_eq!(settled, landed);
    assert_eq!(again, landed);
    let records = committed(&world.log, &a());
    assert_eq!(
        records.len(),
        3,
        "decision, attestation, landed: {records:?}"
    );
    assert_eq!(world.log.violations(), []);
}

/// A stale candidate leaves the operation's binding none: it is answered
/// stale each time and nothing is recorded, a rebase under the same
/// operation is then accepted at the first position and lands, and the
/// stale candidate resubmitted after that meets the landed binding.
#[test]
fn a_stale_answer_leaves_the_binding_none_and_records_nothing() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let chain = world.plant_chain(&a(), 1, 0x90);
    let (handle, driver) = world.start(&[a()]);
    let stale = good_root(&a(), 1, None, 1);
    let rebase = good_root(&a(), 2, Some(GrainId::of(&chain[0])), 2);
    let (stale_sub, rebase_sub) = (submission(&a(), 1, &stale), submission(&a(), 1, &rebase));
    let (end, answers) = run_beside(5, driver, async move {
        let mut answers = vec![
            handle.submit(stale_sub.clone()).await,
            handle.submit(stale_sub.clone()).await,
            handle.submit(rebase_sub.clone()).await,
        ];
        answers.push(settle(&handle, &rebase_sub).await);
        answers.push(handle.submit(stale_sub.clone()).await);
        handle.stop().await;
        answers
    });
    assert_eq!(end, RunEnd::Stopped);
    let refused = Answer::StaleBase {
        head: head_at(1, &chain[0]),
    };
    assert_eq!(answers[0], refused);
    assert_eq!(answers[1], refused, "judged afresh, the same answer");
    assert_eq!(
        answers[2],
        Answer::Accepted {
            position: World::position(1),
            candidate_id: GrainId::of(&rebase),
        },
        "no stale answer took a position"
    );
    assert_eq!(
        answers[3],
        Answer::Landed {
            receipt: receipt(1, 2, &rebase),
            head: Some(head_at(2, &rebase)),
        }
    );
    assert_eq!(
        answers[4],
        Answer::OperationBound(Bound::Landed(receipt(1, 2, &rebase)))
    );
    assert_eq!(committed(&world.log, &a()).len(), 3);
    assert_eq!(world.log.violations(), []);
}

/// A different candidate under an open binding is refused as bound to
/// the open entry; another operation's candidate is not decided; junk is
/// still rule 2's, before rule 5. The store fails every PUT and read
/// after the head resolution, so the entry stays open.
#[test]
fn an_open_binding_refuses_and_no_successor_is_decided() {
    let world = World::with_empty_logs(&[a()], Faults::just(Fault::FailFrom(1)));
    let (handle, driver) = world.start(&[a()]);
    let c1 = good_root(&a(), 1, None, 1);
    let c2 = good_root(&a(), 1, None, 2);
    let c3 = good_root(&a(), 1, None, 3);
    let subs = [
        submission(&a(), 1, &c1),
        submission(&a(), 1, &c2),
        submission(&a(), 2, &c3),
        submission(&a(), 3, b"junk"),
    ];
    let (end, answers) = run_beside(7, driver, async move {
        let mut answers = Vec::new();
        for sub in subs {
            answers.push(handle.submit(sub).await);
        }
        handle.stop().await;
        answers
    });
    assert_eq!(end, RunEnd::Stopped);
    let open = (World::position(1), GrainId::of(&c1));
    assert_eq!(
        answers[0],
        Answer::Accepted {
            position: open.0,
            candidate_id: open.1
        }
    );
    assert_eq!(
        answers[1],
        Answer::OperationBound(Bound::Open {
            position: open.0,
            candidate_id: open.1
        })
    );
    assert_eq!(
        answers[2],
        Answer::NotDecided {
            position: open.0,
            candidate_id: open.1
        }
    );
    assert!(
        matches!(answers[3], Answer::InvalidCandidate(_)),
        "{:?}",
        answers[3]
    );
    let records = committed(&world.log, &a());
    assert_eq!(
        records.len(),
        2,
        "decision and attestation only: {records:?}"
    );
    assert_eq!(world.log.violations(), []);
}

/// A different candidate under a landed binding is refused with the
/// landed outcome, whether it would extend the head or is stale; the
/// chain gets nothing more.
#[test]
fn a_landed_binding_refuses_every_other_candidate() {
    let c1 = good_root(&a(), 1, None, 1);
    let d1 = decision_of(1, 1, &c1);
    let world = World::with_records(
        &a(),
        &[d1.clone(), attestation(&d1), landed(&d1)],
        Faults::none(),
    );
    world.plant(&a(), 1, &c1);
    let (handle, driver) = world.start(&[a()]);
    let extends = good_root(&a(), 2, Some(GrainId::of(&c1)), 2);
    let stale = good_root(&a(), 1, None, 3);
    let (_, answers) = run_beside(0, driver, async move {
        let answers = vec![
            handle.submit(submission(&a(), 1, &extends)).await,
            handle.submit(submission(&a(), 1, &stale)).await,
            handle.submit(submission(&a(), 1, &extends)).await,
        ];
        handle.stop().await;
        answers
    });
    let bound = Answer::OperationBound(Bound::Landed(receipt(1, 1, &c1)));
    assert_eq!(answers, vec![bound; 3]);
    assert_eq!(committed(&world.log, &a()).len(), 3, "nothing written");
    assert!(world.puts(&a(), 2).is_empty());
    assert_eq!(world.log.violations(), []);
}

/// The rules' order: a different candidate under a landed operation is
/// refused with the landed outcome (rule 4) even while another
/// operation's entry is open (rule 5), not "not decided".
#[test]
fn a_landed_binding_answers_before_another_operations_open_entry() {
    let c1 = good_root(&a(), 1, None, 1);
    let d1 = decision_of(1, 1, &c1);
    let c2 = good_root(&a(), 2, Some(GrainId::of(&c1)), 2);
    let d2 = decision_of(2, 2, &c2);
    let world = World::with_records(
        &a(),
        &[
            d1.clone(),
            attestation(&d1),
            landed(&d1),
            d2.clone(),
            attestation(&d2),
        ],
        Faults::just(Fault::FailFrom(0)),
    );
    let (handle, driver) = world.start(&[a()]);
    let other = good_root(&a(), 2, Some(GrainId::of(&c1)), 3);
    let (_, answers) = run_beside(0, driver, async move {
        let answers = (
            handle.submit(submission(&a(), 1, &other)).await,
            handle.submit(submission(&a(), 3, &other)).await,
        );
        handle.stop().await;
        answers
    });
    assert_eq!(
        answers.0,
        Answer::OperationBound(Bound::Landed(receipt(1, 1, &c1)))
    );
    assert_eq!(
        answers.1,
        Answer::NotDecided {
            position: World::position(2),
            candidate_id: GrainId::of(&c2),
        }
    );
}

/// A lost binding is eligible for a rebase under the same operation; a
/// stale candidate under it is refused without moving the binding or
/// writing anything, so the rebase that follows is still accepted and
/// lands, and then binds the operation.
#[test]
fn a_lost_binding_takes_a_rebase_and_a_stale_answer_never_moves_a_binding() {
    let foreign = good_root(&a(), 1, None, 0x40);
    let c1 = good_root(&a(), 1, None, 1);
    let d1 = decision_of(1, 1, &c1);
    let world = World::with_records(
        &a(),
        &[
            d1.clone(),
            attestation(&d1),
            lost(&d1, GrainId::of(&foreign)),
        ],
        Faults::none(),
    );
    world.plant(&a(), 1, &foreign);
    let (handle, driver) = world.start(&[a()]);
    let stale = good_root(&a(), 1, None, 2);
    let rebase = good_root(&a(), 2, Some(GrainId::of(&foreign)), 3);
    let after = good_root(&a(), 3, Some(GrainId::of(&rebase)), 4);
    let rebase_sub = submission(&a(), 1, &rebase);
    let c1_sub = submission(&a(), 1, &c1);
    let (_, answers) = run_beside(2, driver, async move {
        let mut answers = vec![
            handle.submit(c1_sub).await,
            handle.submit(submission(&a(), 1, &stale)).await,
            handle.submit(rebase_sub.clone()).await,
        ];
        answers.push(settle(&handle, &rebase_sub).await);
        answers.push(handle.submit(submission(&a(), 1, &after)).await);
        handle.stop().await;
        answers
    });
    assert_eq!(
        answers[0],
        Answer::Lost {
            position: World::position(1),
            candidate_id: GrainId::of(&c1),
            occupant: GrainId::of(&foreign),
            head: Some(head_at(1, &foreign)),
        }
    );
    assert_eq!(
        answers[1],
        Answer::StaleBase {
            head: head_at(1, &foreign),
        }
    );
    assert_eq!(
        answers[2],
        Answer::Accepted {
            position: World::position(2),
            candidate_id: GrainId::of(&rebase),
        }
    );
    assert_eq!(
        answers[3],
        Answer::Landed {
            receipt: receipt(2, 2, &rebase),
            head: Some(head_at(2, &rebase)),
        }
    );
    assert_eq!(
        answers[4],
        Answer::OperationBound(Bound::Landed(receipt(2, 2, &rebase))),
        "a third candidate never lands after a landed one"
    );
    assert!(world.puts(&a(), 3).is_empty());
    assert_eq!(world.log.violations(), []);
}

// ------------------------------------------------------------ rule 6

/// A stranger signature, missing ancestor and over-cap head prove damage.
/// A failed listing leaves the head unavailable. Each refusal writes nothing
/// and clears when the chain verifies again.
#[test]
fn head_resolution_distinguishes_damage_from_unavailability() {
    enum Damage {
        Stranger,
        MissingAncestor,
        OverCapHead,
        FailedListing,
    }
    for damage in [
        Damage::Stranger,
        Damage::MissingAncestor,
        Damage::OverCapHead,
        Damage::FailedListing,
    ] {
        // Op 0 is the first submission's listing.
        let faults = match damage {
            Damage::FailedListing => Faults::just(Fault::Fail(0)),
            _ => Faults::none(),
        };
        let world = World::with_empty_logs(&[a()], faults);
        let chain = world.plant_chain(&a(), 2, 0x20);
        match damage {
            Damage::Stranger => {
                world.delete(&a(), 2);
                let bad = signed_root(&a(), 2, Some(GrainId::of(&chain[0])), 0x21, &[&stranger()]);
                world.plant(&a(), 2, &bad);
            }
            Damage::MissingAncestor => world.delete(&a(), 1),
            Damage::OverCapHead => world
                .store
                .set_read_fault(&a(), 2, Some(ReadFault::OverCap)),
            Damage::FailedListing => {}
        }
        let (handle, driver) = world.start(&[a()]);
        let head = chain[1].clone();
        let candidate = good_root(&a(), 3, Some(GrainId::of(&head)), 1);
        let world_store = world.store.clone();
        let admin = world.sim.admin();
        let first_bytes = chain[0].clone();
        let (_, (damaged, healed)) = run_beside(0, driver, async move {
            let damaged = handle.submit(submission(&a(), 1, &candidate)).await;
            // Repair the chain behind the engine's back.
            world_store.set_read_fault(&a(), 2, None);
            let _ = admin.delete_root(&a(), 2);
            assert!(admin.plant_root(&a(), 2, head.clone()));
            if admin.root_seqs(&a()).first() != Some(&1) {
                assert!(admin.plant_root(&a(), 1, first_bytes));
            }
            let healed = handle.submit(submission(&a(), 1, &candidate)).await;
            handle.stop().await;
            (damaged, healed)
        });
        let expected = match damage {
            Damage::FailedListing => Answer::Validation(crate::ValidationError::Unavailable),
            _ => Answer::VolumeDamaged,
        };
        assert_eq!(damaged, expected);
        assert!(
            matches!(healed, Answer::Accepted { .. }),
            "the condition clears: {healed:?}"
        );
        assert_eq!(world.log.violations(), []);
    }
}

/// A foreign head at `u64::MAX - 1`, whose chain the store cannot hold,
/// does not verify: rule 6 answers, and no answer names a next seq of
/// `u64::MAX`.
#[test]
fn a_foreign_head_at_the_top_of_the_seq_space_is_damage_not_a_next_seq() {
    for top in [u64::MAX - 1, u64::MAX - 2] {
        let world = World::with_empty_logs(&[a()], Faults::none());
        world.plant(&a(), top, &good_root(&a(), top, Some(GrainId::of(b"p")), 1));
        let (handle, driver) = world.start(&[a()]);
        let candidate = good_root(&a(), 1, None, 2);
        let (_, answer) = run_beside(0, driver, async move {
            let answer = handle.submit(submission(&a(), 1, &candidate)).await;
            handle.stop().await;
            answer
        });
        assert_eq!(answer, Answer::VolumeDamaged, "head at {top}");
        assert!(calls(&world.sim, "append").is_empty());
    }
}

// ------------------------------------------------------- rules 7 and 8

/// A candidate that does not extend the verified head (the wrong seq,
/// the wrong parent, or both) is refused as stale with the head and its
/// next seq, and nothing is written.
#[test]
fn a_stale_candidate_is_refused_with_the_head_and_nothing_is_written() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let chain = world.plant_chain(&a(), 2, 0x30);
    let before = read_log(&world.log, &a());
    let (handle, driver) = world.start(&[a()]);
    let head = GrainId::of(&chain[1]);
    let candidates = [
        good_root(&a(), 2, Some(GrainId::of(&chain[0])), 1),
        good_root(&a(), 4, Some(head), 2),
        good_root(&a(), 3, Some(GrainId::of(b"elsewhere")), 3),
    ];
    let (_, answers) = run_beside(0, driver, async move {
        let mut answers = Vec::new();
        for (n, candidate) in candidates.iter().enumerate() {
            let operation = u8::try_from(n).unwrap();
            answers.push(handle.submit(submission(&a(), operation, candidate)).await);
        }
        handle.stop().await;
        answers
    });
    for answer in &answers {
        assert_eq!(
            *answer,
            Answer::StaleBase {
                head: head_at(2, &chain[1]),
            }
        );
    }
    assert_eq!(head_at(2, &chain[1]).next_seq, Some(3));
    assert_eq!(read_log(&world.log, &a()), before, "nothing written");
    assert!(calls(&world.sim, "append").is_empty());
    assert_eq!(world.log.violations(), []);
}

/// The same stale candidate answered twice: the same answer each time,
/// and the log and the volume's state are exactly as they were.
#[test]
fn a_stale_candidate_answered_twice_leaves_the_log_and_the_state_unchanged() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let chain = world.plant_chain(&a(), 2, 0x31);
    let before = read_log(&world.log, &a());
    let stale = good_root(&a(), 2, Some(GrainId::of(&chain[0])), 1);
    let sub = submission(&a(), 1, &stale);
    let (answers, state_before, state_after) = admit_each(&world, vec![sub.clone(), sub]);
    let refused = Answer::StaleBase {
        head: head_at(2, &chain[1]),
    };
    assert_eq!(answers, vec![refused.clone(), refused]);
    assert_eq!(state_after, state_before, "the state is unchanged");
    assert_eq!(read_log(&world.log, &a()), before, "the log is unchanged");
    assert!(calls(&world.sim, "append").is_empty());
}

/// A genuine old root with an invented second slot under a key the
/// volume does not configure passes rule 2, since the head check skips
/// that slot, and is refused as stale. Many such malleations, each a
/// distinct candidate id, are each refused, and together they write
/// nothing and leave the state as it was: the log grows only with the
/// chain.
#[test]
fn malleated_old_roots_pass_rule_2_are_refused_stale_and_write_nothing() {
    const MALLEATIONS: u16 = 48;
    let world = World::with_empty_logs(&[a()], Faults::none());
    let chain = world.plant_chain(&a(), 2, 0x32);
    let before = read_log(&world.log, &a());
    let candidates: Vec<Vec<u8>> = (0..MALLEATIONS).map(|n| malleated(&chain[0], n)).collect();
    let ids: std::collections::BTreeSet<GrainId> =
        candidates.iter().map(|c| GrainId::of(c)).collect();
    assert_eq!(ids.len(), usize::from(MALLEATIONS), "each is a distinct id");
    assert!(!ids.contains(&GrainId::of(&chain[0])));
    let keys = TrustedKeys::new([*publisher().public_key()]).unwrap();
    for candidate in &candidates {
        granary_store::crypto::check_head(candidate, a().as_str(), 1, &keys)
            .expect("an unconfigured slot is skipped: the malleation passes the head check");
    }
    let subs = candidates
        .iter()
        .enumerate()
        .map(|(n, c)| submission(&a(), u8::try_from(n % 256).unwrap(), c))
        .collect();
    let (answers, state_before, state_after) = admit_each(&world, subs);
    let refused = Answer::StaleBase {
        head: head_at(2, &chain[1]),
    };
    assert_eq!(answers, vec![refused; usize::from(MALLEATIONS)]);
    assert_eq!(state_after, state_before, "the state is unchanged");
    assert_eq!(read_log(&world.log, &a()), before, "the log is unchanged");
    assert!(calls(&world.sim, "append").is_empty());
}

/// The same stale bytes under two tenants get the same answer, and
/// neither submission changes the state or the log: no answer depends on
/// another tenant's history.
#[test]
fn the_same_stale_bytes_under_two_tenants_get_the_same_answer_and_change_nothing() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let chain = world.plant_chain(&a(), 2, 0x33);
    let before = read_log(&world.log, &a());
    let stale = good_root(&a(), 1, None, 1);
    let under = |tenant: u8| {
        Submission::new(
            Tenant::new(vec![tenant]).unwrap(),
            Principal::new(vec![0x22]).unwrap(),
            a(),
            World::position(1).epoch,
            Operation::new(vec![1]).unwrap(),
            stale.clone(),
        )
    };
    let subs = vec![under(0x11), under(0x99), under(0x11), under(0x99)];
    let (answers, state_before, state_after) = admit_each(&world, subs);
    let refused = Answer::StaleBase {
        head: head_at(2, &chain[1]),
    };
    assert_eq!(answers, vec![refused; 4]);
    assert_eq!(state_after, state_before);
    assert_eq!(read_log(&world.log, &a()), before);
}

/// A candidate submitted ahead of the head is refused as stale, and is
/// accepted once its parent lands: a stale answer is not terminal.
#[test]
fn a_candidate_ahead_of_the_head_is_refused_then_accepted_once_its_parent_lands() {
    let world = World::with_empty_logs(&[a()], Faults::none());
    let chain = world.plant_chain(&a(), 1, 0x34);
    let (handle, driver) = world.start(&[a()]);
    let parent = good_root(&a(), 2, Some(GrainId::of(&chain[0])), 2);
    let ahead = good_root(&a(), 3, Some(GrainId::of(&parent)), 3);
    let (parent_sub, ahead_sub) = (submission(&a(), 2, &parent), submission(&a(), 3, &ahead));
    let (end, answers) = run_beside(0, driver, async move {
        let mut answers = vec![
            handle.submit(ahead_sub.clone()).await,
            handle.submit(parent_sub.clone()).await,
        ];
        answers.push(settle(&handle, &parent_sub).await);
        answers.push(handle.submit(ahead_sub.clone()).await);
        answers.push(settle(&handle, &ahead_sub).await);
        handle.stop().await;
        answers
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(
        answers[0],
        Answer::StaleBase {
            head: head_at(1, &chain[0]),
        }
    );
    assert_eq!(
        answers[1],
        Answer::Accepted {
            position: World::position(1),
            candidate_id: GrainId::of(&parent),
        }
    );
    assert!(
        matches!(answers[2], Answer::Landed { .. }),
        "{:?}",
        answers[2]
    );
    assert_eq!(
        answers[3],
        Answer::Accepted {
            position: World::position(2),
            candidate_id: GrainId::of(&ahead),
        },
        "the same bytes now extend the head"
    );
    assert_eq!(
        answers[4],
        Answer::Landed {
            receipt: receipt(2, 3, &ahead),
            head: Some(head_at(3, &ahead)),
        }
    );
    assert_eq!(world.log.violations(), []);
}

// ----------------------------------------------------- the growth bound

/// The log grows only with the chain: after `k` landed and `m` lost
/// entries it holds exactly three records per closed entry, however many
/// stale and malleated candidates are submitted, and one more accepted
/// candidate adds its own three once it closes.
#[test]
fn the_log_holds_three_records_per_closed_entry_and_nothing_for_stale_answers() {
    // Entries 1, 2 and 4 land; 3 and 5 lose to a foreign root.
    let lost_at = [3_u64, 5];
    let world = World::new(Faults::none());
    let mut records = Vec::new();
    let mut parent: Option<GrainId> = None;
    let mut roots = Vec::new();
    for seq in 1..=5_u64 {
        let variant = u8::try_from(seq).unwrap();
        let candidate = good_root(&a(), seq, parent, variant);
        let d = decision_of(seq, variant, &candidate);
        records.push(d.clone());
        records.push(attestation(&d));
        let stored = if lost_at.contains(&seq) {
            let foreign = good_root(&a(), seq, parent, 0x80 | variant);
            records.push(lost(&d, GrainId::of(&foreign)));
            foreign
        } else {
            records.push(landed(&d));
            candidate
        };
        world.plant(&a(), seq, &stored);
        parent = Some(GrainId::of(&stored));
        roots.push(stored);
    }
    let (k, m) = (3, lost_at.len());
    seed(
        &world.log,
        &a(),
        log_bytes(&envelope(&a(), WORLD_EPOCH), &records),
    );
    let (handle, driver) = world.start(&[a()]);
    let head = roots[4].clone();
    let mut flood: Vec<Submission> = Vec::new();
    for (n, old) in roots.iter().enumerate() {
        for i in 0..8_u16 {
            let op = u8::try_from(0x40 + n * 8 + usize::from(i)).unwrap();
            flood.push(submission(&a(), op, &malleated(old, i)));
        }
    }
    let fresh = good_root(&a(), 6, Some(GrainId::of(&head)), 6);
    let fresh_sub = submission(&a(), 0xF0, &fresh);
    let log = Arc::clone(&world.log);
    let (end, (stale, flooded, settled)) = run_beside(0, driver, async move {
        let mut stale = 0;
        for sub in flood {
            if matches!(handle.submit(sub).await, Answer::StaleBase { .. }) {
                stale += 1;
            }
        }
        let flooded = log.read(&a()).await.unwrap().unwrap();
        let _ = handle.submit(fresh_sub.clone()).await;
        let settled = settle(&handle, &fresh_sub).await;
        handle.stop().await;
        (stale, flooded, settled)
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(stale, 40, "every flooded candidate was stale");
    let Classified::Log {
        records: after_flood,
        ..
    } = classify(&flooded, &a()).unwrap()
    else {
        panic!("the log has an envelope");
    };
    assert_eq!(after_flood.len(), 3 * (k + m), "the flood wrote nothing");
    assert!(matches!(settled, Answer::Landed { .. }), "{settled:?}");
    assert_eq!(committed(&world.log, &a()).len(), 3 * (k + m + 1));
    assert_eq!(world.log.violations(), []);
}

/// "Accepted" is answered only once the decision record is durable: a
/// decision whose record sync fails is answered `Fenced`, and nothing is
/// published.
#[test]
fn accepted_is_answered_only_after_the_decision_is_durable() {
    let dry = World::with_empty_logs(&[a()], Faults::none());
    dry.start(&[a()]);
    // The decision's append is the first log call after the start: its
    // record write, then its record sync.
    let fail_at = dry.log.steps() + 1;
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: fail_at }));
    seed(&log, &a(), log_bytes(&envelope(&a(), WORLD_EPOCH), &[]));
    let world = World::over(sim, log, Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let c1 = good_root(&a(), 1, None, 1);
    let (end, answer) = run_beside(0, driver, async move {
        let answer = handle.submit(submission(&a(), 1, &c1)).await;
        handle.stop().await;
        answer
    });
    assert_eq!(answer, Answer::Fenced);
    assert!(matches!(end, RunEnd::Fenced(_)), "{end:?}");
    assert!(world.puts(&a(), 1).is_empty(), "nothing published");
    assert_eq!(world.log.violations(), []);
}

// -------------------------------------------------------- concurrency

/// Several operations submit an eligible candidate for the same seq at
/// once, under the simulator's scheduler, across seeds. Exactly one is
/// accepted and reaches a decision record; each other one is answered by
/// §3's rules: not decided while the entry is open, or refused as stale
/// once it has landed. The log fake sees no ordering violation.
#[test]
fn concurrent_submissions_decide_exactly_one() {
    const CLIENTS: u8 = 4;
    let mut contended = 0;
    for seed_n in 0..24 {
        let world = World::with_empty_logs(&[a()], Faults::none());
        let (handle, driver) = world.start(&[a()]);
        let done = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let mut tasks: Vec<Task<Option<Answer>>> = Vec::new();
        let run = driver;
        tasks.push(Box::pin(async move {
            let _ = run.run().await;
            None
        }));
        for client in 0..CLIENTS {
            let handle = handle.clone();
            let done = Arc::clone(&done);
            tasks.push(Box::pin(async move {
                let candidate = good_root(&a(), 1, None, client);
                let answer = handle.submit(submission(&a(), client, &candidate)).await;
                done.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(answer)
            }));
        }
        tasks.push(Box::pin(async move {
            while done.load(std::sync::atomic::Ordering::SeqCst) < CLIENTS {
                yield_once().await;
            }
            handle.stop().await;
            None
        }));
        let answers: Vec<Answer> = Scheduler::new(seed_n)
            .run(tasks)
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(answers.len(), usize::from(CLIENTS));
        let accepted = answers
            .iter()
            .filter(|a| matches!(a, Answer::Accepted { .. }))
            .count();
        assert_eq!(accepted, 1, "seed {seed_n}: {answers:?}");
        let mut not_decided = 0;
        for answer in &answers {
            match answer {
                Answer::Accepted { .. } | Answer::StaleBase { .. } => {}
                Answer::NotDecided { .. } => not_decided += 1,
                other => panic!("seed {seed_n}: {other:?}"),
            }
        }
        if not_decided > 0 {
            contended += 1;
        }
        let records = committed(&world.log, &a());
        assert_eq!(
            count(&records, |b| matches!(b, RecordBody::Decision { .. })),
            1,
            "seed {seed_n}"
        );
        assert!(
            records.len() <= 3,
            "seed {seed_n}: only the one entry's records: {records:?}"
        );
        assert_eq!(world.log.violations(), [], "seed {seed_n}");
    }
    assert!(
        contended > 0,
        "no seed answered a submission while the entry was open"
    );
}

#[test]
fn bounded_listing_fallback_can_admit_a_restored_head() {
    use super::publication::{
        ScriptedVolume, await_closed, epoch_reply, list_above, list_roots, mismatched, read_root,
        verified, write_root,
    };

    for warm in [false, true] {
        for restores in [false, true] {
            let world = ScriptedVolume::new(&[]);
            let chain = world.plant(5);
            let base = chain[4].clone();
            let candidate = good_root(&a(), 6, Some(GrainId::of(&base)), 9);
            let candidate_id = GrainId::of(&candidate);
            let (handle, driver) = world.start(YieldPause);
            let store = world.store.clone();
            let (_, ()) = run_beside(0, driver, async move {
                if warm {
                    assert_eq!(
                        handle.submit(mismatched()).await,
                        epoch_reply(Some(verified(5, &base)))
                    );
                    assert_eq!(store.take_calls().first(), Some(&list_roots()));
                }
                let listing = if warm { list_above(4) } else { list_roots() };
                if restores {
                    store.set(a().as_str(), 5, None);
                }
                store.after(listing.clone(), move |store| {
                    store.set(a().as_str(), 5, restores.then_some(base));
                });
                let answer = handle.submit(submission(&a(), 1, &candidate)).await;
                let mut calls = vec![listing];
                match (restores, warm) {
                    (false, _) => {
                        assert_eq!(answer, Answer::VolumeDamaged);
                        calls.push(read_root(5));
                    }
                    (true, false) => {
                        assert_eq!(
                            answer,
                            Answer::StaleBase {
                                head: verified(4, &chain[3])
                            }
                        );
                        calls.extend((1..=4).rev().map(read_root));
                    }
                    (true, true) => {
                        assert_eq!(
                            answer,
                            Answer::Accepted {
                                position: World::position(1),
                                candidate_id,
                            }
                        );
                        await_closed(&handle).await;
                        calls.push(list_roots());
                        calls.extend((1..=5).rev().map(read_root));
                        calls.extend([write_root(6, &candidate), read_root(6)]);
                    }
                }
                assert_eq!(store.take_calls(), calls);
                assert_eq!(handle.stop().await, RunEnd::Stopped);
            });
            let records = committed(&world.log, &a());
            if warm && restores {
                assert_eq!(records.len(), 3);
                assert!(matches!(
                    records[0].body(),
                    RecordBody::Decision { root_seq: 6, .. }
                ));
                assert_eq!(records[0].body().identity().candidate_id(), candidate_id);
                assert!(matches!(records[2].body(), RecordBody::Landed { .. }));
            } else {
                assert!(records.is_empty());
            }
        }
    }
}
