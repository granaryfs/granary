// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::hash::GrainId;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "single and multi-sequence answer variants share one authority behavior row"
)]
fn lost_answer_variant_finishes_without_rebase() {
    for stale in [false, true] {
        let seed = 726 + u64::from(stale);
        let () = scenario::run(
            seed,
            Box::pin(async move {
                let sim = Sim::new();
                let manifest = scenario::seed_tree(&sim, scenario::ONE);
                let shared = Arc::new(Mutex::new(World::new(sim, seed)));
                lock(&shared).actions.push_back(if stale {
                    Action::StoreVariantAndStale
                } else {
                    Action::StoreVariantAndLose
                });
                let transport = Transport {
                    world: shared.clone(),
                    store: lock(&shared).sim.node(1, Faults::none()),
                };
                let key = scenario::key();
                let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
                let mut journal = Journal::new(shared.clone());
                let mut random = SeededSecureRandom::for_incarnation(seed, 0);
                let mut delay = Delay;
                let out = begin_publication(
                    RecoveryParts {
                        transport: &transport,
                        journal: &mut journal,
                        publisher_keys: &keys,
                        signer: &key,
                        secure: &mut random,
                        clock: &ClockValue(1),
                        delay: &mut delay,
                    },
                    Scope {
                        authority_base: b"https://sim-authority".to_vec(),
                        pins: vec![],
                        credential_context: b"writer".to_vec(),
                    },
                    scenario::volume(),
                    manifest,
                    granary_client::Policy::default(),
                )
                .await
                .unwrap();
                let record = lock(&shared).record().unwrap();
                let granary_core::retained_submission::Phase::Complete(done) = &record.phase else {
                    panic!("variant answer did not complete: {out:?}, record={record:?}")
                };
                let stored = lock(&shared)
                    .sim
                    .root_snapshot()
                    .get(&(scenario::VOLUME.to_owned(), done.seq))
                    .cloned()
                    .unwrap();
                assert_eq!(
                    (
                        out.outcome,
                        done.id,
                        record.candidates.len(),
                        lock(&shared).send_calls,
                    ),
                    (
                        PublicationOutcome::Landed(done.clone()),
                        GrainId::of(&done.root),
                        1,
                        1,
                    ),
                    "stale={stale}: candidate completion, stored variant, catalogue and send count"
                );
                assert_ne!(done.id, GrainId::of(&stored), "stale={stale}");
            }),
        );
    }

    let seed = 729;
    let () = scenario::run(
        seed,
        Box::pin(async move {
            let sim = Sim::new();
            let manifest = scenario::seed_tree(&sim, scenario::ONE);
            let shared = Arc::new(Mutex::new(World::new(sim, seed)));
            lock(&shared).actions.push_back(Action::QueueAndLose);
            let transport = Transport {
                world: shared.clone(),
                store: lock(&shared).sim.node(1, Faults::none()),
            };
            let key = scenario::key();
            let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
            let mut journal = Journal::new(shared.clone());
            let mut random = SeededSecureRandom::for_incarnation(seed, 0);
            let mut delay = Delay;
            let first = begin_publication(
                RecoveryParts {
                    transport: &transport,
                    journal: &mut journal,
                    publisher_keys: &keys,
                    signer: &key,
                    secure: &mut random,
                    clock: &ClockValue(1),
                    delay: &mut delay,
                },
                Scope {
                    authority_base: b"https://sim-authority".to_vec(),
                    pins: vec![],
                    credential_context: b"writer".to_vec(),
                },
                scenario::volume(),
                manifest,
                granary_client::Policy::default(),
            )
            .await
            .unwrap();
            let base = lock(&shared).record().unwrap();
            let template = base.candidates[0].clone();
            let mut chain = Vec::new();
            let mut parent = None;
            let mut candidates = Vec::new();
            let mut stored_seven = None;
            for seq in 1..=9 {
                let mut doc = granary_core::root::decode_root(&template.root).unwrap();
                doc.seq = seq;
                doc.parent = parent;
                doc.sigs.clear();
                doc.sigs.push(granary_core::root::RootSig {
                    key_id: key.key_id(),
                    sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
                });
                let candidate_root = granary_core::root::encode_root(&doc).unwrap();
                let stored = if seq == 5 || seq == 7 {
                    let mut variant = granary_core::root::decode_root(&candidate_root).unwrap();
                    variant.sigs.push(granary_core::root::RootSig {
                        key_id: [98; 32],
                        sig: [0; 64],
                    });
                    granary_core::root::encode_root(&variant).unwrap()
                } else if seq == 9 {
                    let mut foreign = granary_core::root::decode_root(&candidate_root).unwrap();
                    foreign.writer_uuid = [99; 16];
                    foreign.sigs.clear();
                    foreign.sigs.push(granary_core::root::RootSig {
                        key_id: key.key_id(),
                        sig: key.sign(&granary_core::root::signing_prefix_of(&foreign).unwrap()),
                    });
                    granary_core::root::encode_root(&foreign).unwrap()
                } else {
                    candidate_root.clone()
                };
                if seq == 5 || seq == 7 || seq == 9 {
                    let mut candidate = template.clone();
                    candidate.number = u64::try_from(candidates.len() + 1).unwrap();
                    candidate.role = if seq == 9 {
                        granary_core::retained_submission::Role::Active
                    } else {
                        granary_core::retained_submission::Role::History
                    };
                    candidate.seq = seq;
                    candidate.id = GrainId::of(&candidate_root);
                    candidate.root = candidate_root;
                    candidates.push(candidate);
                }
                if seq == 7 {
                    stored_seven = Some(stored.clone());
                }
                parent = Some(GrainId::of(&stored));
                chain.push((seq, stored));
            }
            let expected = candidates[1].clone();
            let stored_seven = stored_seven.unwrap();
            let mut record = base;
            record.candidates = candidates;
            record.phase = granary_core::retained_submission::Phase::Ready;
            record.last_response = None;
            granary_core::retained_submission::validate(&record).unwrap();
            {
                let mut world = lock(&shared);
                world.set_record(&record);
                world.answer_roots = chain;
                world.actions.push_back(Action::StoreChainAndLose);
            }
            let sends = lock(&shared).send_calls;
            let out = invoke(
                &shared,
                &transport,
                &keys,
                &key,
                &first.handle,
                1,
                RecoveryIntent::Continue,
            )
            .await
            .unwrap();
            let durable = lock(&shared).record().unwrap();
            let completion = granary_core::retained_submission::Completion {
                seq: expected.seq,
                id: expected.id,
                root: expected.root,
                receipt: None,
            };
            assert_eq!(
                (
                    out.outcome,
                    durable.phase,
                    durable.candidates.len(),
                    lock(&shared).send_calls - sends,
                ),
                (
                    PublicationOutcome::Landed(completion.clone()),
                    granary_core::retained_submission::Phase::Complete(completion),
                    3,
                    1,
                ),
                "the answer walk must pass the foreign seq-9 occupant and select seq 7"
            );
            assert_ne!(expected.id, GrainId::of(&stored_seven));
        }),
    );
}

#[test]
fn two_reinitialisations_keep_a_and_b_when_a_lands_late() {
    let seed = 19307;
    let run = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(run.completion.seq, 1, "seed {seed}");
    assert!(
        run.events
            .iter()
            .any(|e| e.starts_with("initialise epoch 3 held 2")),
        "seed {seed}"
    );
    assert_eq!(
        run.events
            .iter()
            .filter(|e| e.starts_with("release 1 ") && e.ends_with("Ok(())"))
            .count(),
        1,
        "seed {seed}"
    );
}
#[test]
fn seeded_recovery_campaign_has_nonzero_trace_coverage_and_settles() {
    let rows = [
        "initialise epoch 3",
        "client-crash",
        "reply-lost before processing",
        "reply-lost after decision",
        "probe 1 failed",
        "sync-failure create",
        "sync-failure write",
        "sync-failure file-sync",
        "sync-failure rename",
        "sync-failure directory-sync",
        "client-crash unsynced rename survives",
        "client-crash unsynced rename discarded",
        "release 1",
        "foreign root at retired slot",
    ];
    let mut counts = std::collections::BTreeMap::new();
    for seed in 0..512 {
        let run = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
        for row in rows {
            if run.events.iter().any(|e| e.starts_with(row)) {
                *counts.entry(row).or_insert(0_u64) += 1;
            }
        }
    }
    for row in rows {
        assert!(
            counts.get(row).copied().unwrap_or(0) > 0,
            "recovery seeds 0..512: no seed reached {row}: {counts:?}"
        );
    }
    eprintln!("recovery seeds 0..512: {counts:?}");
}
#[test]
fn recovery_artifacts_replay_exactly() {
    for seed in [19307, 19308, 0, 31, 127] {
        let a = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
        let b = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(a.render(), b.render(), "seed {seed}");
    }
}

#[test]
fn b_first_and_foreign_winner_controls() {
    for seed in [0, 2] {
        let run = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            run.completion.seq,
            if seed == 2 { 2 } else { 1 },
            "seed {seed}"
        );
        let mut incarnations = std::collections::BTreeSet::new();
        for event in run.events.iter().filter(|e| e.starts_with("invoke ")) {
            let incarnation = event.split_whitespace().nth(1).unwrap();
            assert!(
                incarnations.insert(incarnation),
                "reused incarnation: {event}"
            );
        }
    }
}

#[test]
fn lost_contention_releases_with_checked_answers_without_prior_occupancy() {
    let seed = 41;
    let () = scenario::run(
        seed,
        Box::pin(async move {
            let sim = Sim::new();
            let manifest = scenario::seed_tree(&sim, scenario::ONE);
            let shared = Arc::new(Mutex::new(World::new(sim, seed)));
            let rounds = granary_core::retained_submission::MAX_CANDIDATES / 8 + 1;
            lock(&shared)
                .actions
                .extend((0..rounds * 8).map(|_| Action::LoseContest));
            let transport = Transport {
                world: shared.clone(),
                store: lock(&shared).sim.node(1, Faults::none()),
            };
            let key = scenario::key();
            let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
            let mut journal = Journal::new(shared.clone());
            let mut random = SeededSecureRandom::for_incarnation(seed, 0);
            let mut delay = Delay;
            let mut out = begin_publication(
                RecoveryParts {
                    transport: &transport,
                    journal: &mut journal,
                    publisher_keys: &keys,
                    signer: &key,
                    secure: &mut random,
                    clock: &ClockValue(1),
                    delay: &mut delay,
                },
                Scope {
                    authority_base: b"https://sim-authority".to_vec(),
                    pins: vec![],
                    credential_context: b"writer".to_vec(),
                },
                scenario::volume(),
                manifest,
                granary_client::Policy::default(),
            )
            .await
            .unwrap();
            let current = lock(&shared).record().unwrap().current;
            for round in 0..rounds {
                if round != 0 {
                    out = invoke(
                        &shared,
                        &transport,
                        &keys,
                        &key,
                        &out.handle,
                        u32::try_from(round + 1).unwrap(),
                        RecoveryIntent::ExplicitRecovery,
                    )
                    .await
                    .unwrap();
                }
                assert_eq!(
                    out.outcome,
                    PublicationOutcome::Pending,
                    "seed {seed}, round {round}: {out:?}"
                );
                assert!(!out.uncertain, "seed {seed}, round {round}");
                let w = lock(&shared);
                let r = w.record().unwrap();
                assert!(r.candidates.is_empty(), "seed {seed}, round {round}");
                assert_eq!(r.current, current);
                assert!(
                    w.violations.is_empty(),
                    "seed {seed}, round {round}: {:?}",
                    w.violations
                );
            }
            let w = lock(&shared);
            assert_eq!(w.send_calls, u64::try_from(rounds * 8).unwrap());
            assert_eq!(
                w.events
                    .iter()
                    .filter(|e| e.starts_with("foreign contender after empty probe "))
                    .count(),
                rounds * 8
            );
            assert_eq!(
                w.events
                    .iter()
                    .filter(|e| e.starts_with("checked-reply Lost "))
                    .count(),
                rounds * 8
            );
        }),
    );
}

#[test]
fn foreign_reply_loss_schedules_reach_both_remedies_and_replay_identically() {
    for (seed, rows) in [
        (
            26801,
            vec![
                "accepted foreign durable outcome Lost",
                "exact outcome replay before admission",
                "accepted foreign exact replay lost released",
                "older exact lost replay after newer binding",
            ],
        ),
        (
            26802,
            vec![
                "queued undecided request with foreign root",
                "undecided foreign exact retry forward-stale released",
                "delayed duplicate processed OperationBound",
            ],
        ),
    ] {
        let a = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
        let b = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(a.render(), b.render());
        assert_eq!(a.completion.seq, 2);
        for row in rows {
            let count = a.events.iter().filter(|e| e.starts_with(row)).count();
            assert!(count > 0, "seed {seed}: missing trace row {row}");
        }
    }
    assert!(matches!(schedule(0), Schedule::Epochs));
    assert!(matches!(schedule(19307), Schedule::Epochs));
    assert!(matches!(schedule(26801), Schedule::AcceptedForeign));
    assert!(matches!(schedule(26802), Schedule::UndecidedForeign));
}

#[test]
fn foreign_replay_release_survives_every_persistence_stage() {
    for accepted in [false, true] {
        for stage in 0..5 {
            let seed = if accepted { 26801 } else { 26802 };
            let run = scenario::run(
                seed,
                Box::pin(foreign_run(seed, accepted, false, Some(stage))),
            )
            .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(run.completion.seq, 2);
            assert!(run.events.iter().any(|e| e.starts_with("sync-failure")));
        }
    }
}

#[test]
fn foreign_faults_leave_queued_requests_unprocessed_and_classify_accepted_once() {
    for seed in [26801, 26802] {
        let run = recovery_run(seed).unwrap_or_else(|e| panic!("{e}"));
        let first_send = run
            .events
            .iter()
            .take_while(|e| !e.starts_with("invoke "))
            .collect::<Vec<_>>();
        assert!(
            !first_send
                .iter()
                .any(|e| e.starts_with("exact outcome replay before admission")),
            "seed {seed}: engine ran twice at send time"
        );
        assert_eq!(
            first_send
                .iter()
                .filter(|e| e.starts_with("decision "))
                .count(),
            usize::from(seed == 26801)
        );
        assert!(
            !first_send
                .iter()
                .any(|e| e.starts_with("undecided exact tuple forward-stale")),
            "seed {seed}: queued request was processed at send time"
        );
        assert!(
            first_send
                .iter()
                .any(|e| e.starts_with("foreign contender after empty probe "))
        );
    }
}

#[test]
fn duplicate_processed_before_retry_returns_rule_three_open_and_keeps_candidate() {
    let seed = 26802;
    let run = scenario::run(seed, Box::pin(foreign_run(seed, false, true, None)))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        run.events
            .iter()
            .any(|e| e == "before-retry duplicate rule 3 open retained")
    );
    assert!(
        !run.events
            .iter()
            .any(|e| e.starts_with("undecided foreign exact retry forward-stale released"))
    );
    let before_retry = run
        .events
        .iter()
        .take_while(|e| !e.starts_with("invoke "))
        .collect::<Vec<_>>();
    assert_eq!(
        before_retry
            .iter()
            .filter(|e| e.starts_with("decision "))
            .count(),
        1
    );
    assert!(
        before_retry
            .iter()
            .any(|e| e.starts_with("delayed duplicate processed Accepted"))
    );
    assert!(
        run.events
            .iter()
            .any(|e| e == "exact outcome replay before admission")
    );
}
