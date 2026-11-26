// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::super::rebase::signed;
use super::*;
use granary_core::retained_submission::{
    self as submission, LastResponse, Phase, Probe, ProbeReason,
};

fn boundary(runtime: &tokio::runtime::Runtime, fenced: bool) -> Fixture {
    if fenced {
        return exhausted_boundary(runtime, PublishPlan::Timeout, PublishPlan::Timeout);
    }
    let fixture = runtime.block_on(Fixture::new());
    fixture.create("local", b"sealed");
    runtime.block_on(authenticate_registration(&fixture));
    let lane = runtime
        .block_on(
            fixture
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70)),
        )
        .unwrap();
    mark_boundary_attempt(&fixture, &lane);
    fixture
}

pub(super) fn evidence(io: &SimIo) -> BTreeMap<PathBuf, (Vec<u8>, Vec<u8>)> {
    let model = io.0.lock().unwrap();
    model
        .names
        .iter()
        .filter(|(path, _)| path.components().any(|part| part.as_os_str() == "overlay"))
        .map(|(path, id)| (path.clone(), model.files[id].clone()))
        .collect()
}

fn read_fault(ending: &str) -> Option<(&'static str, RootStoreError)> {
    let (site, kind) = ending.strip_prefix("read-")?.split_once('-')?;
    let site = match site {
        "listing" => "listing",
        "root" => "root",
        _ => return None,
    };
    let error = match kind {
        "elapsed" => RootStoreError::Elapsed {
            operation: "fixture",
            after: Duration::from_secs(1),
        },
        "unavailable429" => RootStoreError::Unavailable {
            operation: "fixture",
            status: 429,
        },
        "unavailable503" => RootStoreError::Unavailable {
            operation: "fixture",
            status: 503,
        },
        "backend" => RootStoreError::Backend("transport: fixture cut".to_owned()),
        "overcap" => RootStoreError::RefusedResponse {
            reason: "fixture root exceeds cap".to_owned(),
            kind: granary_core::rootstore::RefusalKind::OverCap,
        },
        _ => return None,
    };
    Some((site, error))
}

fn read_faults(fenced: bool, ending: &str) -> Vec<(&'static str, RootStoreError)> {
    let mut faults: Vec<_> = read_fault(ending).into_iter().collect();
    if fenced && ending == "read-listing-backend" {
        faults.push(read_fault("read-root-overcap").unwrap());
    }
    faults
}

pub(super) fn published(record: &submission::Submission, variant: bool, foreign: bool) -> Vec<u8> {
    let mut bytes = record.candidates[0].root.clone();
    if foreign {
        let mut doc = granary_core::root::decode_root(&bytes).unwrap();
        doc.writer_uuid = [99; 16];
        bytes = signed(doc);
    }
    if variant {
        let mut doc = granary_core::root::decode_root(&bytes).unwrap();
        doc.sigs.push(RootSig {
            key_id: [98; 32],
            sig: [0; 64],
        });
        bytes = granary_core::root::encode_root(&doc).unwrap();
    }
    bytes
}

fn defer_answer(record: &mut submission::Submission, lost: bool) {
    let active = record.candidates.last().unwrap().clone();
    record
        .candidates
        .last_mut()
        .unwrap()
        .evidence
        .last_answered_attempt = active.evidence.started;
    record.candidates.last_mut().unwrap().evidence.decision_seen = lost;
    let answer = if lost {
        PublishAnswer::Lost {
            position: Position {
                epoch: Epoch::from_bytes(active.request.epoch),
                entry_seq: 1,
            },
            candidate_id: active.id,
            occupant: GrainId::of(b"foreign"),
            head: None,
        }
    } else {
        PublishAnswer::StaleBase(Head::new(Some((active.seq, GrainId::of(b"foreign")))))
    };
    record.last_response = Some(LastResponse {
        candidate: active.number,
        attempt: active.evidence.started,
        status: if lost { 200 } else { 409 },
        token: if lost { vec![] } else { b"stale-base".to_vec() },
        answer: authority_answer::encode(answer).unwrap(),
    });
    record.phase = Phase::Unresolved(Probe {
        cycle: record.generation,
        seq: active.seq,
        reason: ProbeReason::ContentUnavailable,
    });
    record.generation += 1;
}

#[test]
fn live_deferred_nonconflicting_boundary_probes_before_replay() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary(&runtime, false);
    persist_content(&fixture);
    let mut record = budget::saved(&fixture);
    defer_answer(&mut record, false);
    submission::validate(&record).unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|journal| journal.replace(record.generation - 1, &record))
        .unwrap();
    let sends = fixture.remote.publication_sends.lock().unwrap().len();
    let (_scratch, io, remote, local) = fixture.reload_carrier();
    let mut local = open_owned_boundary(local, &io, &remote);
    let before_record = local
        .publication_transaction(|journal| journal.load(&record.scope, &record.volume))
        .unwrap()
        .unwrap();
    assert!(crate::recovery::deferred_answer_pending(&before_record));
    assert!(crate::NoWriteProof::from_submission(&before_record, 1).is_none());
    let probes = remote.probes.load(Ordering::Relaxed);
    let observed = Arc::new(AtomicBool::new(false));
    let proof_observed = observed.clone();
    let proof_remote = Arc::downgrade(&remote);
    remote.post_listing_probe.set(Arc::new(move || {
        if !proof_observed.swap(true, Ordering::Relaxed) {
            let remote = proof_remote.upgrade().unwrap();
            remote
                .failed_probe
                .store(remote.probes.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        }
    }));
    remote.post_listing_probe.arm();
    *remote.root_probe_fault.lock().unwrap() =
        Some(RootStoreError::Backend("proof read fixture".into()));
    let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
    let result = runtime.block_on(crate::settle_recovery_boundary(
        &mut local,
        remote.as_ref(),
        &keys,
        None,
    ));
    let retained = local
        .publication_transaction(|journal| journal.load(&record.scope, &record.volume))
        .unwrap()
        .unwrap();
    let mut expected = before_record;
    expected.generation = retained.generation;
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string),
            retained,
            remote.publication_sends.lock().unwrap().len(),
        ),
        (
            Some("intent refused: RecoveryUnresolved".into()),
            expected,
            sends,
        )
    );
    assert!(observed.load(Ordering::Relaxed));
    assert_eq!(
        remote.probes.load(Ordering::Relaxed),
        probes + 1,
        "deferred replay did not follow the proof read"
    );
}

#[test]
fn acknowledged_resend_waits_for_live_deferred_classification() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary(&runtime, false);
    persist_content(&fixture);
    let mut record = budget::saved(&fixture);
    defer_answer(&mut record, false);
    submission::validate(&record).unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|journal| journal.replace(record.generation - 1, &record))
        .unwrap();
    let sends = fixture.remote.publication_sends.lock().unwrap().len();
    let (_scratch, io, remote, local) = fixture.reload_carrier();
    let mut local = open_owned_boundary(local, &io, &remote);
    let before_record = local
        .publication_transaction(|journal| journal.load(&record.scope, &record.volume))
        .unwrap()
        .unwrap();
    assert!(crate::recovery::deferred_answer_pending(&before_record));
    let before = local
        .overlay_transaction(|transaction| transaction.commit_progress(record.publication_id))
        .unwrap()
        .unwrap()
        .attempts;
    let events = super::super::selected::Events::default();
    let _guard = events.guard();
    let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
    let result = runtime.block_on(crate::settle_recovery_boundary(
        &mut local,
        remote.as_ref(),
        &keys,
        Some(record.publication_id),
    ));
    let retained = local
        .publication_transaction(|journal| journal.load(&record.scope, &record.volume))
        .unwrap()
        .unwrap();
    let after = local
        .overlay_transaction(|transaction| transaction.commit_progress(record.publication_id))
        .unwrap()
        .unwrap()
        .attempts;
    assert_eq!(
        remote.publication_sends.lock().unwrap().len(),
        sends,
        "resend preceded deferred classification"
    );
    assert_eq!(before, 1);
    assert_eq!(after, before, "resend recorded a new attempt");
    assert_eq!(
        result.as_ref().err().map(ToString::to_string),
        Some("intent refused: RecoveryUnresolved".into())
    );
    assert_eq!(retained.last_response, before_record.last_response);
    assert!(crate::recovery::deferred_answer_pending(&retained));
    assert!(
        !events
            .recover()
            .iter()
            .any(|event| event.starts_with("resent"))
    );
}

#[test]
fn live_deferred_non_landing_rederives_proof_after_classification() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary(&runtime, false);
    let head = runtime.block_on(super::super::rebase::foreign_head(&fixture, "remote"));
    persist_content(&fixture);
    let mut record = budget::saved(&fixture);
    defer_answer(&mut record, false);
    let answer = PublishAnswer::StaleBase(Head::new(Some((
        record.candidates[0].seq,
        GrainId::of(&head),
    ))));
    record.last_response.as_mut().unwrap().answer = authority_answer::encode(answer).unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(record.generation - 1, &record))
        .unwrap();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    let events = super::super::selected::Events::default();
    let _guard = events.guard();
    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    );
    assert!(result.is_ok(), "{result:?}: {:?}", events.recover());
    let mut reopened = start(&scratch, &io, 158);
    let archive = reopened
        .publication_transaction(|j| {
            j.inspect_archive(
                &record.scope.digest().unwrap(),
                &record.volume,
                record.publication_id,
            )
        })
        .unwrap();
    assert!(archive.settled);
    assert_eq!(archive.submission.phase, Phase::Rebase);
    assert!(archive.submission.candidates.is_empty());
    assert!(archive.submission.generation > record.generation);
    let completed = reopened
        .publication_transaction(|j| j.load(&record.scope, &record.volume))
        .unwrap()
        .unwrap();
    assert!(completed.is_complete());
    assert_ne!(completed.publication_id, record.publication_id);
    assert_eq!(
        reopened.snapshot().phase,
        granary_core::overlay_ownership::Phase::Released
    );
    let observed = events.recover();
    let released = observed
        .iter()
        .position(|e| e == "fence_settled how=released")
        .unwrap();
    let finished = observed
        .iter()
        .position(|e| e.starts_with("journal_finished"))
        .unwrap();
    assert!(released < finished);
    assert!(
        !observed
            .iter()
            .any(|e| e.starts_with("conflict") || e.starts_with("resent"))
    );
    let sent = remote.publication_sends.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_ne!(sent[0], record.candidates[0].root);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the archive matrix keeps exact evidence and restart outcomes together"
)]
fn archived_landing_refuses_without_changing_evidence() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for fenced in [false, true] {
        for variant in [false, true] {
            for ancestor in [false, true] {
                for foreign_live in [false, true] {
                    let fixture = boundary(&runtime, fenced);
                    let record = budget::saved(&fixture);
                    let bytes = published(&record, variant, false);
                    let seq = record.candidates[0].seq;
                    fixture
                        .remote
                        .published
                        .lock()
                        .unwrap()
                        .insert(seq, bytes.clone());
                    if ancestor {
                        let mut doc = granary_core::root::decode_root(&bytes).unwrap();
                        doc.seq += 1;
                        doc.parent = Some(GrainId::of(&bytes));
                        doc.writer_uuid = [99; 16];
                        let seq = doc.seq;
                        let bytes = signed(doc);
                        fixture.remote.published.lock().unwrap().insert(seq, bytes);
                    }
                    let (scratch, io, remote, mut local) = fixture.reload_carrier();
                    abandon_boundary(&mut local, &record);
                    if foreign_live {
                        let mut other = record.clone();
                        other.publication_id = [88; 16];
                        other.generation = 1;
                        other.phase = Phase::Complete(submission::Completion {
                            seq,
                            id: record.candidates[0].id,
                            root: record.candidates[0].root.clone(),
                            receipt: None,
                        });
                        other.current = None;
                        local.publication_transaction(|j| j.begin(&other)).unwrap();
                    }
                    drop(local);
                    for restart in 0..2 {
                        let mut local = recover_boundary(start(&scratch, &io, 131), &io, &remote);
                        let before = (
                            publication_files(&scratch.0),
                            evidence(&io),
                            remote.publication_sends.lock().unwrap().clone(),
                        );
                        let sends = remote.authority.lock().unwrap().sends.len();
                        let events = super::super::selected::Events::default();
                        let _guard = events.guard();
                        let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32])
                            .unwrap()
                            .public_key()])
                        .unwrap();
                        let result = runtime.block_on(crate::settle_recovery_boundary(
                            &mut local,
                            remote.as_ref(),
                            &keys,
                            None,
                        ));
                        drop(local);
                        let mut reopened = start(&scratch, &io, 131);
                        let raw = remote.authority.lock().unwrap().sends[sends..].to_vec();
                        let kinds = (
                            raw.iter()
                                .filter(|bytes| {
                                    intent::decode_register(bytes, &record.volume, |_, _| true)
                                        .is_ok()
                                })
                                .count(),
                            raw.iter()
                                .filter(|bytes| intent::decode_release(bytes).is_ok())
                                .count(),
                        );
                        actual.push((
                            fenced,
                            variant,
                            ancestor,
                            foreign_live,
                            restart,
                            result.err().map(|e| e.to_string()),
                            events.recover(),
                            reopened.recovery_rule().unwrap(),
                            before
                                == (
                                    publication_files(&scratch.0),
                                    evidence(&io),
                                    remote.publication_sends.lock().unwrap().clone(),
                                ),
                            kinds == (0, 0) && raw.is_empty(),
                        ));
                        expected.push((
                            fenced,
                            variant,
                            ancestor,
                            foreign_live,
                            restart,
                            Some("intent refused: RecoveryArchivedLanded".to_owned()),
                            vec![format!("archived_landed seq={seq}")],
                            RecoveryRule::BoundaryArchived,
                            true,
                            true,
                        ));
                        drop(reopened);
                        io.crash();
                    }
                }
            }
        }
    }
    assert_eq!(actual.len(), 32);
    assert_eq!(
        actual, expected,
        "archive refusal/event/classifier/evidence/ownership sends"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the defensive seam pairs both archive provenances with a complete live installation"
)]
fn archived_finish_refuses_before_landed_append() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for fenced in [false, true] {
        for archived in [None, Some(false), Some(true)] {
            let fixture = boundary(&runtime, fenced);
            let record = budget::saved(&fixture);
            let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()])
                .unwrap();
            fixture
                .remote
                .published
                .lock()
                .unwrap()
                .insert(record.candidates[0].seq, record.candidates[0].root.clone());
            let proof = runtime
                .block_on(crate::probe_submission(
                    fixture.remote.as_ref(),
                    &record,
                    if fenced { 8 } else { 1 },
                    &keys,
                ))
                .unwrap();
            let crate::ProbeOutcome::Landed {
                candidate,
                stored_id,
                ..
            } = proof
            else {
                panic!("landing premise: {proof:?}")
            };
            let (scratch, io, remote, local) = fixture.reload_carrier();
            drop(local);
            let mut local = recover_boundary(start(&scratch, &io, 131), &io, &remote);
            if archived.is_some() {
                abandon_boundary(&mut local, &record);
            } else {
                let mut complete = record.clone();
                complete.generation += 1;
                complete.current = None;
                complete.phase = Phase::Complete(submission::Completion {
                    seq: candidate.seq,
                    id: candidate.id,
                    root: candidate.root.clone(),
                    receipt: None,
                });
                local
                    .publication_transaction(|j| j.replace(record.generation, &complete))
                    .unwrap();
            }
            let commits = local.recovery_commits().unwrap();
            let [crate::RecoveryCommit::Boundary { index, .. }] = commits.as_slice() else {
                panic!("boundary premise: {commits:?}")
            };
            let before = evidence(&io);
            let events = super::super::selected::Events::default();
            let _guard = events.guard();
            let result = crate::recovery::finish_landed_boundary_for_test(
                &mut local,
                *index,
                candidate.seq,
                stored_id,
                archived,
            );
            actual.push((
                fenced,
                archived,
                result.err().map(|e| e.to_string()),
                events.recover(),
                before == evidence(&io),
                local.recovery_rule().unwrap(),
            ));
            expected.push((
                fenced,
                archived,
                archived.map(|settled| {
                    if settled {
                        "RecoveryRemoteIntegrity: archived non-landing contradicted"
                    } else {
                        "intent refused: RecoveryArchivedLanded"
                    }
                    .to_owned()
                }),
                if archived.is_some() {
                    vec![format!("archived_landed seq={}", candidate.seq)]
                } else {
                    vec![]
                },
                archived.is_some(),
                if archived.is_some() {
                    RecoveryRule::BoundaryArchived
                } else {
                    RecoveryRule::LandedUnrefreshed
                },
            ));
            if archived.is_none() {
                let writer = local.writer_uuid();
                drop(local);
                let result = boundary_command(
                    &scratch,
                    &io,
                    &remote,
                    &runtime,
                    writer,
                    None,
                    FaultControl::default(),
                );
                let installed = start(&scratch, &io, 132);
                assert_eq!(
                    (
                        result.as_ref().map_err(ToString::to_string).err(),
                        installed.snapshot().phase,
                        granary_core::overlay_journal::scan_journal(
                            &io.recovered_bytes("journal").unwrap()
                        )
                        .unwrap()
                        .header
                        .base_root,
                        cut_file(installed.recovery_store(), &candidate.root, "local")
                    ),
                    (
                        None,
                        granary_core::overlay_ownership::Phase::Released,
                        GrainId::of(&candidate.root),
                        b"sealed".to_vec()
                    ),
                    "live finish installation: {result:?}"
                );
            }
        }
    }
    assert_eq!(actual.len(), 6);
    assert_eq!(
        actual, expected,
        "defensive finish refusal/event/unchanged journal/classifier"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one command row keeps the three archive endings and authority-send proof together"
)]
fn recovery_command_stops_at_each_archived_refusal() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut actual = Vec::new();
    for ending in ["plain-landed", "settled-landed", "unresolved"] {
        let fixture = boundary(&runtime, false);
        let mut record = budget::saved(&fixture);
        let proof = if ending == "settled-landed" {
            fixture
                .remote
                .published
                .lock()
                .unwrap()
                .insert(record.candidates[0].seq, published(&record, false, true));
            let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()])
                .unwrap();
            let outcome = runtime
                .block_on(crate::probe_submission(
                    fixture.remote.as_ref(),
                    &record,
                    1,
                    &keys,
                ))
                .unwrap();
            let crate::ProbeOutcome::NeverLanded(proof) = outcome else {
                panic!("settled archive premise: {outcome:?}")
            };
            Some(crate::RejectionProof::NeverLanded(proof))
        } else {
            None
        };
        if ending == "unresolved" {
            defer_answer(&mut record, false);
        }
        let (scratch, io, remote, mut local) = fixture.reload_carrier();
        if ending == "unresolved" {
            local
                .publication_transaction(|j| j.replace(record.generation - 1, &record))
                .unwrap();
        }
        let faults = FaultControl::default();
        if let Some(proof) = proof {
            local
                .publication_transaction(|j| {
                    j.abandon(
                        &record.scope,
                        &record.volume,
                        record.publication_id,
                        crate::AbandonAcknowledgement::Proven(&proof, &faults),
                    )
                })
                .unwrap();
        } else {
            abandon_boundary(&mut local, &record);
        }
        if ending.ends_with("landed") {
            remote
                .published
                .lock()
                .unwrap()
                .insert(record.candidates[0].seq, record.candidates[0].root.clone());
        }
        let sends = remote.authority.lock().unwrap().sends.len();
        let writer = local.writer_uuid();
        drop(local);
        let error = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        )
        .err()
        .map(|error| error.to_string());
        let raw = remote.authority.lock().unwrap().sends[sends..].to_vec();
        actual.push((
            ending,
            error,
            raw.iter()
                .filter(|bytes| intent::decode_register(bytes, &record.volume, |_, _| true).is_ok())
                .count(),
            raw.iter()
                .filter(|bytes| intent::decode_release(bytes).is_ok())
                .count(),
        ));
    }
    assert_eq!(
        actual,
        [
            (
                "plain-landed",
                Some("intent refused: RecoveryArchivedLanded".to_owned()),
                0,
                0,
            ),
            (
                "settled-landed",
                Some("RecoveryRemoteIntegrity: archived non-landing contradicted".to_owned()),
                0,
                0,
            ),
            (
                "unresolved",
                Some("intent refused: RecoveryArchivedUnresolved".to_owned()),
                0,
                0,
            ),
        ],
        "ending/refusal/refreshes/releases"
    );
}

const ARCHIVED_DEFERRED_ENDINGS: [&str; 17] = [
    "never-decided",
    "foreign",
    "empty",
    "history-exact",
    "history-variant",
    "live",
    "read-listing-elapsed",
    "read-listing-unavailable429",
    "read-listing-unavailable503",
    "read-listing-backend",
    "read-root-elapsed",
    "read-root-unavailable429",
    "read-root-unavailable503",
    "read-root-backend",
    "read-root-overcap",
    "missing-chain",
    "integrity",
];

fn archived_deferred_answer_case_count(fences: &[bool], endings: &[&str]) -> usize {
    let mut count = 0;
    for &fenced in fences {
        for ending in endings {
            for lost in [false, true] {
                if (lost && (*ending == "never-decided" || !read_faults(fenced, ending).is_empty()))
                    || (!fenced && *ending == "live")
                {
                    continue;
                }
                count += if read_faults(fenced, ending).is_empty() {
                    2
                } else {
                    1
                };
            }
        }
    }
    count
}

#[test]
fn archived_deferred_answer_case_matrix_stays_complete() {
    let expected_rows = ARCHIVED_DEFERRED_ENDINGS
        .iter()
        .flat_map(|&ending| [(ending, false), (ending, true)])
        // An unfenced live archive is handled directly rather than deferred.
        .filter(|&(ending, fenced)| fenced || ending != "live")
        .collect::<Vec<_>>();
    assert_eq!(ARCHIVED_DEFERRED_ANSWER_ROWS, expected_rows);

    let row_case_counts = ARCHIVED_DEFERRED_ANSWER_ROWS
        .iter()
        .map(|&(ending, fenced)| archived_deferred_answer_case_count(&[fenced], &[ending]))
        .collect::<Vec<_>>();
    assert!(row_case_counts.iter().all(|&count| count > 0));
    assert_eq!(row_case_counts.iter().sum::<usize>(), 74);
}

#[test]
fn archived_deferred_answer_row_functions_match_matrix() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/overlay_store/tests/coordination/engine/commits/rules/archived.rs");
    let mut file = crate::fsguard::open_regular_read(&path)
        .unwrap_or_else(|error| panic!("open {}: {error}", path.display()));
    let mut source = String::new();
    std::io::Read::read_to_string(&mut file, &mut source)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let function_prefix = "fn archived_deferred_answer_never_uses_live_replay_";
    let mut rows = std::collections::BTreeSet::new();
    for (line_index, line) in source.lines().enumerate() {
        let Some(declaration) = line.trim().strip_prefix(function_prefix) else {
            continue;
        };
        let function = declaration
            .strip_suffix("() {")
            .unwrap_or_else(|| panic!("malformed row function at line {}", line_index + 1));
        let body = source
            .lines()
            .skip(line_index + 1)
            .take_while(|line| line.trim() != "}");
        let arguments = body
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("archived_deferred_answer_case(&[")
                    .and_then(|line| line.strip_suffix("]);"))
            })
            .collect::<Vec<_>>();
        let [arguments] = arguments.as_slice() else {
            panic!("row function {function} must contain exactly one case call");
        };
        let (fenced, ending) = arguments
            .split_once("], &[\"")
            .unwrap_or_else(|| panic!("malformed case call in row function {function}"));
        let fenced = match fenced {
            "false" => false,
            "true" => true,
            _ => panic!("non-literal fence in row function {function}"),
        };
        let ending = ending
            .strip_suffix('"')
            .unwrap_or_else(|| panic!("non-literal ending in row function {function}"));
        assert!(
            rows.insert((ending, fenced)),
            "duplicate deferred-answer row in function {function}"
        );
    }

    let expected = ARCHIVED_DEFERRED_ANSWER_ROWS
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(rows, expected, "row functions do not match the row table");
}

#[expect(
    clippy::too_many_lines,
    reason = "paired archived/live deferred tuples include empty, foreign and matching history"
)]
fn archived_deferred_answer_case(fences: &[bool], endings: &[&str]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for &fenced in fences {
        for &ending in endings {
            for lost in [false, true] {
                if (lost && (ending == "never-decided" || !read_faults(fenced, ending).is_empty()))
                    || (!fenced && ending == "live")
                {
                    continue;
                }
                let fixture = boundary(&runtime, fenced);
                let mut record = budget::saved(&fixture);
                let (scratch, io, remote, mut local) = fixture.reload_carrier();
                let candidate = record.candidates[0].clone();
                let all_never = ending == "never-decided";
                let history_fault = fenced && ending == "read-root-backend";
                if all_never {
                    record.candidates[0].evidence.proved_no_write = candidate.evidence.started;
                    record.candidates[0].evidence.last_answered_attempt =
                        candidate.evidence.started;
                }
                if ending.starts_with("history") || history_fault {
                    record.candidates[0].role = submission::Role::History;
                    let mut active = candidate.clone();
                    active.number = 2;
                    let mut doc = granary_core::root::decode_root(&active.root).unwrap();
                    if history_fault {
                        doc.seq = doc.seq.checked_add(1).unwrap();
                        doc.parent = Some(candidate.id);
                        active.seq = doc.seq;
                    }
                    doc.timestamp.secs += 1;
                    active.root = signed(doc);
                    active.id = GrainId::of(&active.root);
                    active.evidence = submission::Evidence::default();
                    active.evidence.start().unwrap();
                    record.current = Some(active.request);
                    record.candidates.push(active);
                }
                defer_answer(&mut record, lost);
                let Phase::Unresolved(probe) = &record.phase else {
                    panic!("deferred fixture did not retain its probe")
                };
                let probe_seq = probe.seq;
                submission::validate(&record).unwrap_or_else(|error| {
                    panic!("{fenced} {ending} {lost}: {error}: {record:?}")
                });
                local
                    .publication_transaction(|j| j.replace(record.generation - 1, &record))
                    .unwrap();
                if ending == "foreign"
                    || ending.starts_with("history")
                    || ending.starts_with("read-listing")
                    || ending.starts_with("read-root")
                    || ending == "missing-chain"
                    || ending == "integrity"
                {
                    let (seq, bytes) = if ending == "integrity" {
                        (candidate.seq, b"malformed root".to_vec())
                    } else if ending == "missing-chain" {
                        let mut doc = granary_core::root::decode_root(&candidate.root).unwrap();
                        doc.seq = candidate.seq.checked_add(1).unwrap();
                        doc.parent = Some(candidate.id);
                        (doc.seq, signed(doc))
                    } else {
                        (
                            candidate.seq,
                            published(&record, ending == "history-variant", ending == "foreign"),
                        )
                    };
                    remote.published.lock().unwrap().insert(seq, bytes);
                }
                if ending != "live" {
                    abandon_boundary(&mut local, &record);
                }
                drop(local);
                let restarts = if read_faults(fenced, ending).is_empty() {
                    2
                } else {
                    1
                };
                for restart in 0..restarts {
                    let mut local = recover_boundary(start(&scratch, &io, 131), &io, &remote);
                    let before = (
                        publication_files(&scratch.0),
                        evidence(&io),
                        remote.publication_sends.lock().unwrap().clone(),
                    );
                    let events = super::super::selected::Events::default();
                    let _guard = events.guard();
                    let keys =
                        TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()])
                            .unwrap();
                    for (site, error) in read_faults(fenced, ending) {
                        let target = if site == "listing" {
                            &remote.listing_fault
                        } else {
                            &remote.root_probe_fault
                        };
                        *target.lock().unwrap() = Some(error);
                    }
                    let result = runtime.block_on(crate::settle_recovery_boundary(
                        &mut local,
                        remote.as_ref(),
                        &keys,
                        (ending != "live").then_some(record.publication_id),
                    ));
                    drop(local);
                    let mut reopened = start(&scratch, &io, 132);
                    let retained = if ending == "live" {
                        reopened
                            .publication_transaction(|j| j.observe(&record.scope, &record.volume))
                            .unwrap()
                            .unwrap()
                    } else {
                        reopened
                            .publication_transaction(|j| {
                                j.inspect_archive(
                                    &record.scope.digest().unwrap(),
                                    &record.volume,
                                    record.publication_id,
                                )
                            })
                            .unwrap()
                            .submission
                    };
                    let landed = matches!(ending, "history-exact" | "history-variant");
                    let ordered_overcap = fenced && ending == "read-listing-backend";
                    let refusal = if landed {
                        Some("intent refused: RecoveryArchivedLanded".to_owned())
                    } else if ending == "live" {
                        Some("intent refused: RecoveryUnresolved".to_owned())
                    } else if ending == "integrity"
                        || ending.ends_with("overcap")
                        || ordered_overcap
                    {
                        Some("RecoveryRemoteIntegrity: untrusted probe head".to_owned())
                    } else {
                        Some("intent refused: RecoveryArchivedUnresolved".to_owned())
                    };
                    actual.push((
                        fenced,
                        ending,
                        lost,
                        restart,
                        result.err().map(|e| e.to_string()),
                        events.recover(),
                        crate::recovery::deferred_answer_pending(&retained),
                        ending == "live"
                            || before
                                == (
                                    publication_files(&scratch.0),
                                    evidence(&io),
                                    remote.publication_sends.lock().unwrap().clone(),
                                ),
                    ));
                    expected.push((
                        fenced,
                        ending,
                        lost,
                        restart,
                        refusal,
                        if ending == "integrity" || ending.ends_with("overcap") || ordered_overcap {
                            vec![]
                        } else {
                            vec![format!(
                                "{} seq={}",
                                if landed {
                                    "archived_landed"
                                } else {
                                    "unresolved"
                                },
                                if landed { candidate.seq } else { probe_seq }
                            )]
                        },
                        true,
                        true,
                    ));
                    drop(reopened);
                    io.crash();
                }
            }
        }
    }
    assert_eq!(
        actual.len(),
        archived_deferred_answer_case_count(fences, endings)
    );
    assert_eq!(
        actual, expected,
        "deferred refusal/event/marker/exact evidence"
    );
}

const ARCHIVED_DEFERRED_ANSWER_ROWS: &[(&str, bool)] = &[
    ("never-decided", false),
    ("never-decided", true),
    ("foreign", false),
    ("foreign", true),
    ("empty", false),
    ("empty", true),
    ("history-exact", false),
    ("history-exact", true),
    ("history-variant", false),
    ("history-variant", true),
    ("live", true),
    ("read-listing-elapsed", false),
    ("read-listing-elapsed", true),
    ("read-listing-unavailable429", false),
    ("read-listing-unavailable429", true),
    ("read-listing-unavailable503", false),
    ("read-listing-unavailable503", true),
    ("read-listing-backend", false),
    ("read-listing-backend", true),
    ("read-root-elapsed", false),
    ("read-root-elapsed", true),
    ("read-root-unavailable429", false),
    ("read-root-unavailable429", true),
    ("read-root-unavailable503", false),
    ("read-root-unavailable503", true),
    ("read-root-backend", false),
    ("read-root-backend", true),
    ("read-root-overcap", false),
    ("read-root-overcap", true),
    ("missing-chain", false),
    ("missing-chain", true),
    ("integrity", false),
    ("integrity", true),
];

#[test]
fn archived_deferred_answer_never_uses_live_replay_never_decided_unfenced() {
    archived_deferred_answer_case(&[false], &["never-decided"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_never_decided_fenced() {
    archived_deferred_answer_case(&[true], &["never-decided"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_foreign_unfenced() {
    archived_deferred_answer_case(&[false], &["foreign"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_foreign_fenced() {
    archived_deferred_answer_case(&[true], &["foreign"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_empty_unfenced() {
    archived_deferred_answer_case(&[false], &["empty"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_empty_fenced() {
    archived_deferred_answer_case(&[true], &["empty"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_history_exact_unfenced() {
    archived_deferred_answer_case(&[false], &["history-exact"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_history_exact_fenced() {
    archived_deferred_answer_case(&[true], &["history-exact"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_history_variant_unfenced() {
    archived_deferred_answer_case(&[false], &["history-variant"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_history_variant_fenced() {
    archived_deferred_answer_case(&[true], &["history-variant"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_live_fenced() {
    archived_deferred_answer_case(&[true], &["live"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_elapsed_unfenced() {
    archived_deferred_answer_case(&[false], &["read-listing-elapsed"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_elapsed_fenced() {
    archived_deferred_answer_case(&[true], &["read-listing-elapsed"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_unavailable429_unfenced() {
    archived_deferred_answer_case(&[false], &["read-listing-unavailable429"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_unavailable429_fenced() {
    archived_deferred_answer_case(&[true], &["read-listing-unavailable429"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_unavailable503_unfenced() {
    archived_deferred_answer_case(&[false], &["read-listing-unavailable503"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_unavailable503_fenced() {
    archived_deferred_answer_case(&[true], &["read-listing-unavailable503"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_backend_unfenced() {
    archived_deferred_answer_case(&[false], &["read-listing-backend"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_listing_backend_fenced() {
    archived_deferred_answer_case(&[true], &["read-listing-backend"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_elapsed_unfenced() {
    archived_deferred_answer_case(&[false], &["read-root-elapsed"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_elapsed_fenced() {
    archived_deferred_answer_case(&[true], &["read-root-elapsed"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_unavailable429_unfenced() {
    archived_deferred_answer_case(&[false], &["read-root-unavailable429"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_unavailable429_fenced() {
    archived_deferred_answer_case(&[true], &["read-root-unavailable429"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_unavailable503_unfenced() {
    archived_deferred_answer_case(&[false], &["read-root-unavailable503"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_unavailable503_fenced() {
    archived_deferred_answer_case(&[true], &["read-root-unavailable503"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_backend_unfenced() {
    archived_deferred_answer_case(&[false], &["read-root-backend"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_backend_fenced() {
    archived_deferred_answer_case(&[true], &["read-root-backend"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_overcap_unfenced() {
    archived_deferred_answer_case(&[false], &["read-root-overcap"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_read_root_overcap_fenced() {
    archived_deferred_answer_case(&[true], &["read-root-overcap"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_missing_chain_unfenced() {
    archived_deferred_answer_case(&[false], &["missing-chain"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_missing_chain_fenced() {
    archived_deferred_answer_case(&[true], &["missing-chain"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_integrity_unfenced() {
    archived_deferred_answer_case(&[false], &["integrity"]);
}

#[test]
fn archived_deferred_answer_never_uses_live_replay_integrity_fenced() {
    archived_deferred_answer_case(&[true], &["integrity"]);
}
