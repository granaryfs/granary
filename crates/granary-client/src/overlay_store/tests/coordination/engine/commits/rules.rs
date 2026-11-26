// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

// @file-disposition: STAYS — test-only recovery classifier and settlement rows share the real commit restart fixtures.

//! Where explicit recovery places an intact store a commit fault left, and
//! the prologue that settles its retained requests before the classifier.

use super::*;
use crate::{RecoveryRule, RetainedCommit};
use std::cell::Cell;

mod release;

mod archived;
mod capture_window;
mod conflict;
mod dirty_reselect;
mod journal_finish;
mod landed_reselect;
mod owned_landing;
mod power_loss;
mod recover_refusals;
mod reselect;
mod torn_operation;

fn exhausted_boundary(
    runtime: &tokio::runtime::Runtime,
    prior: PublishPlan,
    last: PublishPlan,
) -> Fixture {
    let (fixture, lane) = sealed_boundary(runtime);
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([prior; 7]);
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(last);
    let result = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
    assert!(
        matches!(result.outcome, PublicationOutcome::Exhausted),
        "{result:?}"
    );
    fixture
}

fn sealed_boundary(runtime: &tokio::runtime::Runtime) -> (Fixture, RetainedCommit) {
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
    persist_content(&fixture);
    (fixture, lane)
}

fn boundary_refused_for_missing_reference(runtime: &tokio::runtime::Runtime) -> Fixture {
    let (fixture, lane) = sealed_boundary(runtime);
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::MissingReference);
    let result = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
    let record = budget::saved(&fixture);
    assert_eq!(
        (
            result.outcome,
            fixture.remote.publication_sends.lock().unwrap().len(),
            fixture.store.lock().unwrap().sync_admission_open().ok(),
            record.candidates.len(),
            record.candidates.iter().all(|c| c.evidence.never_decided()),
            record
                .last_response
                .as_ref()
                .map(|a| (a.status, a.token.as_slice())),
        ),
        (
            PublicationOutcome::Refused,
            1,
            Some(false),
            1,
            true,
            Some((400, b"missing-reference".as_slice()))
        ),
        "saved missing-reference before recovery"
    );
    fixture
}

fn mark_boundary_attempt(fixture: &Fixture, lane: &RetainedCommit) {
    let mut record = budget::saved(fixture);
    let attempt = record.candidates[0].evidence.start().unwrap();
    record.phase = granary_core::retained_submission::Phase::AwaitingAnswer {
        candidate: record.candidates[0].number,
        attempt,
    };
    let generation = record.generation;
    record.generation += 1;
    let mut local = fixture.store.lock().unwrap();
    local
        .overlay_transaction(|t| {
            t.record_commit_attempt(lane.boundary_seq(), record.publication_id, 1)
        })
        .unwrap();
    local
        .publication_transaction(|j| j.replace(generation, &record))
        .unwrap();
}

fn abandon_boundary(
    local: &mut WritableStore<SimIo>,
    record: &granary_core::retained_submission::Submission,
) {
    local
        .publication_transaction(|j| {
            j.abandon(
                &record.scope,
                &record.volume,
                record.publication_id,
                crate::MayLandAcknowledgement::Acknowledged,
            )
        })
        .unwrap();
}

fn recover_boundary(
    mut local: WritableStore<SimIo>,
    io: &SimIo,
    remote: &Remote,
) -> WritableStore<SimIo> {
    local.prepare_succession(&Tick(2_000_000)).unwrap();
    crate::writable_start::settle_recovery(
        &mut local,
        &Tick(2_000_000),
        drive(remote, &Cell::new(0)),
    )
    .unwrap();
    let (base, seq) = local.dirty_journal_base().unwrap().unwrap();
    let mut h = header();
    h.writer = local.writer_uuid();
    h.base_root = base;
    h.base_seq = seq;
    local
        .open_overlay(h, vec![], &mut Source::default(), io.clone())
        .unwrap();
    local
}

fn open_owned_boundary(
    mut local: WritableStore<SimIo>,
    io: &SimIo,
    remote: &Remote,
) -> WritableStore<SimIo> {
    let request = local.prepare_succession(&Tick(2_000_000)).unwrap();
    drive(remote, &Cell::new(0))(&mut local, &request, false).unwrap();
    let (base, seq) = local.dirty_journal_base().unwrap().unwrap();
    let mut h = header();
    h.writer = local.writer_uuid();
    h.base_root = base;
    h.base_seq = seq;
    local
        .open_overlay(h, vec![], &mut Source::default(), io.clone())
        .unwrap();
    local
}

struct LandingCut {
    scratch: Scratch,
    io: SimIo,
    remote: Arc<Remote>,
    writer: [u8; 16],
    record: granary_core::retained_submission::Submission,
    content: Arc<Content>,
}

fn landing_cut(
    runtime: &tokio::runtime::Runtime,
    change_live_stage: bool,
    suffix: Option<&[u8]>,
) -> LandingCut {
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("local", b"sealed");
    runtime.block_on(authenticate_registration(&fixture));
    retained_landing_cut(runtime, fixture, stage, change_live_stage, suffix)
}

fn retained_landing_cut(
    runtime: &tokio::runtime::Runtime,
    fixture: Fixture,
    stage: u64,
    change_live_stage: bool,
    suffix: Option<&[u8]>,
) -> LandingCut {
    let lane = runtime
        .block_on(
            fixture
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70)),
        )
        .unwrap();
    if let Some(suffix) = suffix {
        published::write(&fixture, stage, 0, suffix);
        published::settle_disk(&fixture.io);
    }
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Timeout; 8]);
    let result = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
    assert!(
        matches!(result.outcome, PublicationOutcome::Exhausted),
        "{result:?}"
    );
    let record = budget::saved(&fixture);
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(record.candidates[0].seq, record.candidates[0].root.clone());
    if change_live_stage {
        forge_live_stage(&fixture.io, stage);
    }
    let content = fixture.content.clone();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    LandingCut {
        scratch,
        io,
        remote,
        writer,
        record,
        content,
    }
}

fn forge_live_stage(io: &SimIo, stage: u64) {
    io.mutate_recovered("journal", |bytes| {
        let scan = granary_core::overlay_journal::scan_journal(bytes).unwrap();
        let header = scan.header;
        let mut rebuilt = header.encode().unwrap();
        granary_core::overlay_journal::scan_journal_with(bytes, |seq, record| {
            let mut record = record.clone();
            if let Record::WriteExtent {
                stage_id,
                offset,
                length,
                check,
            } = &mut record
                && (*stage_id, *offset, *length) == (stage, 0, 6)
            {
                *check = granary_core::overlay_journal::extent_check(stage, 0, b"forged");
            }
            rebuilt.extend(
                granary_core::overlay_journal::encode_record(&header, seq, &record).unwrap(),
            );
        })
        .unwrap();
        *bytes = rebuilt;
    });
    io.mutate_recovered(&format!("{stage:016x}"), |bytes| {
        bytes[160..].copy_from_slice(b"forged");
    });
}

fn run_landing_cut(
    cut: &LandingCut,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), crate::RecoveryCommandError> {
    let faults = FaultControl::default();
    faults.arm("recover.release", "before", 1, FaultAction::Fail);
    let result = boundary_command(
        &cut.scratch,
        &cut.io,
        &cut.remote,
        runtime,
        cut.writer,
        None,
        faults.clone(),
    );
    if faults.fired().is_empty() {
        result
    } else {
        assert_eq!(
            result.as_ref().err().map(ToString::to_string),
            Some("overlay I/O: overlay injected fault".to_owned()),
            "{result:?}"
        );
        Ok(())
    }
}

fn cut_file_grains(content: &impl GrainSource, root: &[u8], name: &str) -> (u64, Vec<GrainId>) {
    let doc = granary_core::root::decode_root(root).unwrap();
    let entries = crate::writable_store::capture::entries(content, doc.manifest_root, 1).unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.name.as_bytes() == name.as_bytes())
        .unwrap();
    let EntryKind::File { size, grains, .. } = &entry.kind else {
        panic!("file missing")
    };
    let FileGrains::Inline(grains) = grains else {
        panic!("test file unexpectedly spilled")
    };
    (*size, grains.iter().map(|grain| grain.id).collect())
}

fn cut_file(content: &impl GrainSource, root: &[u8], name: &str) -> Vec<u8> {
    let (size, grains) = cut_file_grains(content, root, name);
    let mut bytes = Vec::new();
    for grain in grains {
        bytes.extend(content.get(&grain).unwrap());
    }
    bytes.truncate(usize::try_from(size).unwrap());
    bytes
}

#[test]
fn the_first_mount_commit_has_a_published_base_and_cannot_have_seq_zero() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = exhausted_boundary(&runtime, PublishPlan::RateLimited, PublishPlan::RateLimited);
    let record = budget::saved(&fixture);
    let local = fixture.store.lock().unwrap();
    let area = crate::overlay_store::area_path(
        local.recovery_store().publication_root(),
        &record.scope,
        &record.volume,
    )
    .unwrap();
    let scan = codec::scan_journal(&fixture.io.bytes(&area.join("journal"))).unwrap();
    assert_eq!(
        (
            scan.header.base_seq,
            record.candidates[0].seq,
            fixture.remote.published.lock().unwrap().contains_key(&1)
        ),
        (1, 2, true)
    );
    let mut invalid = scan.header;
    invalid.base_seq = 0;
    assert!(codec::encode_journal(&invalid, &[]).is_err());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table observes each single resend's answer, journal reservation and exact candidate"
)]
fn a_single_resend_records_its_answer_and_journal_reservation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (name, plan, refusal, status) in [
        (
            "landed",
            PublishPlan::Land,
            "RecoveryJournalBlocked",
            Some(200),
        ),
        (
            "no-write",
            PublishPlan::RateLimited,
            "RecoveryResendNoWrite",
            Some(429),
        ),
        (
            "unanswered",
            PublishPlan::Timeout,
            "RecoveryResendUnanswered",
            None,
        ),
        (
            "stale-response",
            PublishPlan::Timeout,
            "RecoveryResendUnanswered",
            None,
        ),
        (
            "wrong-candidate",
            PublishPlan::Timeout,
            "RecoveryResendCandidate",
            None,
        ),
    ] {
        let fixture = exhausted_boundary(
            &runtime,
            PublishPlan::Timeout,
            if name == "stale-response" {
                PublishPlan::RateLimited
            } else {
                PublishPlan::Timeout
            },
        );
        let mut record = budget::saved(&fixture);
        let (scratch, io, remote, mut local) = fixture.reload_carrier();
        if name == "wrong-candidate" {
            use granary_core::retained_submission::{Evidence, Role};
            let mut next = record.candidates[0].clone();
            record.candidates[0].role = Role::History;
            let key = SigningKey::from_seed(&[39; 32]).unwrap();
            let mut doc = granary_core::root::decode_root(&next.root).unwrap();
            doc.seq += 1;
            doc.parent = Some(next.id);
            doc.sigs = vec![RootSig {
                key_id: key.key_id(),
                sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
            }];
            next.root = granary_core::root::encode_root(&doc).unwrap();
            next.id = GrainId::of(&next.root);
            next.seq = doc.seq;
            next.number += 1;
            next.evidence = Evidence::default();
            record.candidates.push(next);
            let generation = record.generation;
            record.generation += 1;
            local
                .publication_transaction(|j| j.replace(generation, &record))
                .unwrap();
        }
        let writer = local.writer_uuid();
        drop(local);
        remote.publication_plan.lock().unwrap().push_back(plan);
        let events = super::selected::Events::default();
        let _guard = events.guard();
        let observed = Arc::new(AtomicBool::new(false));
        let event_view = events.clone();
        let observed_send = observed.clone();
        let evidence_io = io.clone();
        let evidence_area =
            crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
        let evidence_record = scratch
            .0
            .join("publications")
            .join(record.scope.digest().unwrap())
            .join(format!("{}.sub", record.volume.as_str()));
        let publication = record.publication_id;
        *remote.publication_observer.lock().unwrap() = Some(Box::new(move || {
            use std::io::Read as _;
            observed_send.store(true, Ordering::Relaxed);
            assert!(
                !event_view
                    .recover()
                    .iter()
                    .any(|e| e.starts_with("resent seq=")),
                "{name}: resent must follow the transport call"
            );
            let progress = codec::scan_journal(&evidence_io.bytes(&evidence_area.join("journal")))
                .unwrap()
                .state
                .commit_progress(&publication)
                .unwrap();
            let file =
                crate::fsguard::open_sole_regular_read(&evidence_record, "dispatch evidence")
                    .unwrap_or_else(|error| panic!("dispatch evidence read refused: {error}"));
            let mut bytes = Vec::new();
            file.take(1_048_577).read_to_end(&mut bytes).unwrap();
            let saved = granary_core::retained_submission::decode(&bytes).unwrap();
            assert_eq!(
                (
                    progress.attempts,
                    saved
                        .candidates
                        .iter()
                        .map(|c| c.evidence.started)
                        .sum::<u64>(),
                    saved.last_response.is_none()
                ),
                (9, 9, true),
                "{name}: journal reservation and retained save must precede dispatch"
            );
        }));
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            Some(record.publication_id),
            FaultControl::default(),
        );
        let mut reopened = start(&scratch, &io, 131);
        let saved = super::selected::retained(&mut reopened).unwrap();
        let area =
            crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
        let scan = codec::scan_journal(&io.bytes(&area.join("journal"))).unwrap();
        let progress = scan.state.commit_progress(&record.publication_id).unwrap();
        let sent = name != "wrong-candidate";
        actual.push((
            name,
            result.err().map(|e| e.to_string()),
            remote.publication_sends.lock().unwrap().len(),
            saved.is_complete(),
            saved.last_response.as_ref().map(|r| r.status),
            (
                progress.attempts,
                saved
                    .candidates
                    .iter()
                    .map(|c| c.evidence.started)
                    .sum::<u64>(),
            ),
            (
                events
                    .recover()
                    .iter()
                    .any(|e| e.starts_with("resent seq=")),
                observed.load(Ordering::Relaxed),
            ),
        ));
        expected.push((
            name,
            Some(format!("intent refused: {refusal}")),
            if sent { 9 } else { 8 },
            name == "landed",
            status,
            if sent { (9, 9) } else { (8, 8) },
            (sent, sent),
        ));
    }
    assert_eq!(actual.len(), 5);
    assert_eq!(
        actual, expected,
        "(ending, refusal, sends, complete, answer, journal/record attempts, post-send event)"
    );
}

#[test]
fn recovery_after_outage_expiry_probes_landing_or_reports_acknowledged_refusal() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut actual = Vec::new();
    for landed in [true, false] {
        let (fixture, lane) = sealed_boundary(&runtime);
        let lane = runtime.block_on(async {
            lane.with_deadline(TokioSyncRuntime.now() + Duration::from_mins(40))
        });
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::Unavailable; 9]);
        runtime.block_on(async {
            let first = budget::drive(&fixture, &lane, &mut Delay).await;
            assert_eq!(first.outcome, PublicationOutcome::Pending);
            budget::advance_outage(Duration::from_mins(31)).await;
            let expired = budget::drive(&fixture, &lane, &mut Delay).await;
            assert_eq!(
                (
                    expired.outcome,
                    budget::saved(&fixture).unavailable_exemptions
                ),
                (PublicationOutcome::Exhausted, 1)
            );
        });
        let record = budget::saved(&fixture);
        let candidate = record.candidates.first().unwrap();
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        if landed {
            remote
                .published
                .lock()
                .unwrap()
                .insert(candidate.seq, candidate.root.clone());
        } else {
            remote
                .publication_plan
                .lock()
                .unwrap()
                .push_back(PublishPlan::WorkLimit);
        }
        // Explicit recovery runs in a fresh process with its own clock.
        let recovery_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = recovery_outcome(
            &scratch,
            &io,
            &remote,
            &recovery_runtime,
            writer,
            None,
            (!landed).then_some(record.publication_id),
            FaultControl::default(),
        );
        let sends = remote.publication_sends.lock().unwrap();
        actual.push((
            matches!(result, Ok(crate::RecoveryOutcome::JournalFinished { base_seq }) if base_seq == candidate.seq),
            result.err().map(|error| error.to_string()),
            sends.len(),
            sends.iter().all(|bytes| bytes == &candidate.root),
        ));
    }
    assert_eq!(
        actual,
        [
            (true, None, 9, true),
            (
                false,
                Some("publish-work-limit against this head (earlier attempts unresolved)".into()),
                10,
                true
            ),
        ],
        "(recovered exact landing, refusal, physical sends, exact candidate bytes)"
    );
}

#[test]
fn recovery_reports_missing_reference_without_sending_or_archiving() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary_refused_for_missing_reference(&runtime);
    let record = budget::saved(&fixture);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Land);

    let result = recovery_outcome(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        None,
        FaultControl::default(),
    );
    let error = result.as_ref().err().map(ToString::to_string);
    let publication = budget::publication_hex(record.publication_id);
    let mut reopened = start(&scratch, &io, 131);
    let retained = super::selected::retained(&mut reopened);
    let digest = record.scope.digest().unwrap();
    let archived = reopened
        .publication_transaction(|journal| {
            journal.archived(&digest, &record.volume, record.publication_id)
        })
        .unwrap();
    assert_eq!(
        (
            error
                .as_ref()
                .is_some_and(|e| e.contains("missing-reference") && e.contains(&publication)),
            remote.publication_sends.lock().unwrap().len(),
            retained.is_some_and(|r| r.publication_id == record.publication_id
                && r.last_response == record.last_response),
            archived,
        ),
        (true, 1, true, false),
        "(refusal names token and publication, total sends, saved refusal retained, archived); recover={result:?}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "all three probe outcomes use the same saved refusal and recovery command"
)]
fn recovery_probes_uncertain_missing_reference_without_acknowledgement() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (case, uncertainty) in [
        ("landed", None),
        ("never landed", Some(false)),
        ("unresolved", Some(true)),
    ] {
        let (fixture, lane) = sealed_boundary(&runtime);
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::Timeout, PublishPlan::MissingReference]);
        let first = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
        let record = budget::saved(&fixture);
        assert_eq!(
            (
                first.outcome,
                first.uncertain,
                record
                    .last_response
                    .as_ref()
                    .map(|answer| (answer.status, answer.token.as_slice())),
                fixture.remote.publication_sends.lock().unwrap().len(),
            ),
            (
                PublicationOutcome::Refused,
                true,
                Some((400, b"missing-reference".as_slice())),
                2,
            ),
            "{case}: earlier uncertain send and saved refusal before recovery"
        );
        let candidate = record.candidates.first().unwrap();
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let published = match case {
            "landed" => Some(candidate.root.clone()),
            "never landed" => Some(runtime.block_on(super::selected::one_file(
                &remote,
                b"foreign",
                b"occupied",
                [99; 16],
            ))),
            _ => None,
        };
        if let Some(root) = published {
            // Reveal the outcome of the earlier send only after the refusal was saved.
            let seq = granary_core::root::decode_root(&root).unwrap().seq;
            assert_eq!(
                seq, candidate.seq,
                "{case}: root must occupy the candidate slot"
            );
            remote.published.lock().unwrap().insert(seq, root);
        }
        let result = recovery_outcome(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            None,
            FaultControl::default(),
        );
        let refusal = match result {
            Ok(crate::RecoveryOutcome::JournalFinished { base_seq })
                if base_seq == candidate.seq =>
            {
                None
            }
            Err(
                ref error @ crate::RecoveryCommandError::Coordination(
                    CoordinationError::SyncRefusal(crate::SyncRefusalKind::MissingReference {
                        publication,
                        uncertain,
                    }),
                ),
            ) if publication == record.publication_id => Some((uncertain, error.to_string())),
            other => panic!("{case}: unexpected recovery result {other:?}"),
        };
        let digest = record.scope.digest().unwrap();
        let archived = start(&scratch, &io, 131)
            .publication_transaction(|journal| {
                journal.archived(&digest, &record.volume, record.publication_id)
            })
            .unwrap();
        actual.push((
            case,
            refusal,
            remote.publication_sends.lock().unwrap().len(),
            archived,
        ));
        let refusal = uncertainty.map(|unresolved| {
            let publication = budget::publication_hex(record.publication_id);
            let history = if unresolved {
                " (earlier attempts unresolved)"
            } else {
                ""
            };
            (
                unresolved,
                format!("missing-reference for publication {publication}{history}"),
            )
        });
        expected.push((case, refusal, 2, false));
    }
    assert_eq!(
        actual, expected,
        "(probe case, typed refusal and text, total sends, archived)"
    );
}

#[test]
fn recovery_acknowledging_missing_reference_resends_the_exact_candidate_once() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary_refused_for_missing_reference(&runtime);
    let record = budget::saved(&fixture);
    let candidate = record.candidates.first().unwrap();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::MissingReference);

    let result = recovery_outcome(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        Some(record.publication_id),
        FaultControl::default(),
    );
    let sends = remote.publication_sends.lock().unwrap();
    let operations = remote.publication_operations.lock().unwrap();
    assert_eq!(
        (
            sends.len(),
            sends.get(1) == Some(&candidate.root),
            operations.get(1).map(Vec::as_slice) == Some(candidate.request.operation.as_slice()),
            result
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("missing-reference")),
        ),
        (2, true, true, true),
        "(total sends, exact candidate bytes, exact operation, refusal names token); recover={result:?}"
    );
}

#[test]
fn fenced_settlement_classifies_deferred_answer_before_rejection() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = exhausted_boundary(&runtime, PublishPlan::Timeout, PublishPlan::Timeout);
    let record = budget::saved(&fixture);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::StaleForeign);
    let fault_remote = remote.clone();
    *remote.publication_observer.lock().unwrap() = Some(Box::new(move || {
        let next = fault_remote.probes.load(Ordering::Relaxed) + 1;
        fault_remote.failed_probe.store(next, Ordering::Relaxed);
    }));
    let deferred = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        Some(record.publication_id),
        FaultControl::default(),
    );
    assert_eq!(
        deferred.err().map(|error| error.to_string()),
        Some("intent refused: RecoveryResendPending".to_owned())
    );

    let mut local = start(&scratch, &io, 131);
    let mut marker = super::selected::retained(&mut local).unwrap();
    assert!(crate::recovery::deferred_answer_pending(&marker));
    for candidate in &mut marker.candidates {
        candidate.evidence.proved_no_write = candidate.evidence.started;
        candidate.evidence.last_answered_attempt = candidate.evidence.started;
        candidate.evidence.decision_seen = false;
    }
    let generation = marker.generation;
    marker.generation += 1;
    granary_core::retained_submission::validate(&marker).unwrap();
    local
        .publication_transaction(|journal| journal.replace(generation, &marker))
        .unwrap();
    drop(local);

    let sends = remote.publication_sends.lock().unwrap().len();
    boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    )
    .unwrap();
    let mut reopened = start(&scratch, &io, 132);
    let digest = marker.scope.digest().unwrap();
    let archived = reopened
        .publication_transaction(|journal| {
            journal.inspect_archive(&digest, &marker.volume, marker.publication_id)
        })
        .unwrap()
        .submission;
    assert_eq!(
        (
            archived.phase,
            archived.last_response.is_some(),
            remote.publication_sends.lock().unwrap().len(),
        ),
        (
            granary_core::retained_submission::Phase::Rebase,
            true,
            sends + 1,
        ),
        "settlement must apply the deferred answer before using its rejection proof"
    );
}

#[test]
fn settlement_and_an_unrecorded_boundary_can_be_recovered_twice() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut outcomes = Vec::new();
    for recorded in [false, true] {
        let fixture = if recorded {
            exhausted_boundary(&runtime, PublishPlan::RateLimited, PublishPlan::RateLimited)
        } else {
            runtime.block_on(cut_at("boundary_recorded", true))
        };
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        for pass in 0..2 {
            let result = boundary_command(
                &scratch,
                &io,
                &remote,
                &runtime,
                writer,
                None,
                FaultControl::default(),
            );
            outcomes.push((recorded, pass, result.err().map(|e| e.to_string())));
            let mut local = start(&scratch, &io, 140 + pass);
            assert_eq!(local.recovery_rule().unwrap(), RecoveryRule::Nothing);
        }
    }
    assert_eq!(
        outcomes,
        [
            (false, 0, None),
            (false, 1, None),
            (true, 0, None),
            (true, 1, None)
        ]
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one crash table keeps durable reservation, restart and both remedies together"
)]
fn a_crash_after_resend_reservation_keeps_a_probe_and_acknowledged_send_remedy() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for cut in [false, true] {
        let fixture = exhausted_boundary(&runtime, PublishPlan::Timeout, PublishPlan::Timeout);
        let record = budget::saved(&fixture);
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let faults = FaultControl::default();
        if cut {
            faults.arm("overlay.journal.post_sync", "after", 1, FaultAction::Fail);
        }
        remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Timeout);
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            Some(record.publication_id),
            faults.clone(),
        );
        assert_eq!(
            (
                result.is_err(),
                faults.fired().len(),
                remote.publication_sends.lock().unwrap().len()
            ),
            (true, usize::from(cut), if cut { 8 } else { 9 }),
            "cut={cut}: {result:?}"
        );
        io.crash();
        let mut local = start(&scratch, &io, 160);
        let area =
            crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
        let reserved = codec::scan_journal(&io.bytes(&area.join("journal")))
            .unwrap()
            .state
            .commit_progress(&record.publication_id)
            .unwrap()
            .attempts;
        let saved = local
            .publication_transaction(|j| j.load(&record.scope, &record.volume))
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                local.recovery_rule().unwrap(),
                reserved,
                saved.candidates[0].evidence.started
            ),
            (RecoveryRule::BoundaryRecorded, 9, if cut { 8 } else { 9 })
        );
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
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                Some("intent refused: RecoveryUnresolved".to_owned()),
                if cut { 8 } else { 9 }
            )
        );
        let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = seen.clone();
        let evidence = io.clone();
        let path = area.join("journal");
        *remote.publication_observer.lock().unwrap() = Some(Box::new(move || {
            let bytes = evidence
                .clone()
                .read_at(&path, 0, codec::JOURNAL_MAX + 1)
                .unwrap_or_else(|error| panic!("dispatch journal read refused: {error}"));
            let reserved = codec::scan_journal(&bytes)
                .unwrap()
                .state
                .commit_progress(&record.publication_id)
                .unwrap()
                .attempts;
            assert_eq!(reserved, 10, "dispatch needs its durable reservation");
            observed.store(true, Ordering::Relaxed);
        }));
        remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Timeout);
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            Some(record.publication_id),
            FaultControl::default(),
        );
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                remote.publication_sends.lock().unwrap().len(),
                seen.load(Ordering::Relaxed)
            ),
            (
                Some("intent refused: RecoveryResendUnanswered".to_owned()),
                if cut { 9 } else { 10 },
                true
            )
        );
        let foreign = runtime.block_on(super::selected::one_file(
            &remote,
            b"local",
            b"different concurrent bytes",
            [99; 16],
        ));
        remote.published.lock().unwrap().insert(
            granary_core::root::decode_root(&foreign).unwrap().seq,
            foreign,
        );
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        io.crash();
        let mut local = start(&scratch, &io, 180);
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                local.recovery_rule().unwrap(),
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                Some("intent refused: RecoveryConflict".to_owned()),
                RecoveryRule::BoundaryRecorded,
                if cut { 9 } else { 10 }
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

async fn authenticate_registration(fixture: &Fixture) {
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let bytes = super::selected::one_file(&fixture.remote, b"local", b"sealed", writer).await;
    register_bytes(
        &mut fixture.store.lock().unwrap(),
        &fixture.remote,
        &bytes,
        fixture.remote.time.as_ref(),
    );
}

fn register_bytes(
    local: &mut WritableStore<SimIo>,
    remote: &Remote,
    bytes: &[u8],
    time: &impl granary_core::clock::Clock,
) {
    let request = local
        .prepare_registration(bytes, vec![], time, |_, _| true)
        .unwrap();
    local.dispatch(&request, time).unwrap();
    let answer = remote.authority.lock().unwrap().send(&request);
    local
        .complete(&request, Ok(&answer), time, &mut SeededRng::new(2), 0, None)
        .unwrap();
}

fn boundary_command(
    scratch: &Scratch,
    io: &SimIo,
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    writer: [u8; 16],
    acknowledge_resend: Option<[u8; 16]>,
    faults: FaultControl,
) -> Result<(), crate::RecoveryCommandError> {
    boundary_command_with_ack(
        scratch,
        io,
        remote,
        runtime,
        writer,
        None,
        acknowledge_resend,
        faults,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "recovery command inputs and explicit consent controls"
)]
fn boundary_command_with_ack(
    scratch: &Scratch,
    io: &SimIo,
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    writer: [u8; 16],
    acknowledge_takeover: Option<[u8; 16]>,
    acknowledge_resend: Option<[u8; 16]>,
    faults: FaultControl,
) -> Result<(), crate::RecoveryCommandError> {
    recovery_outcome(
        scratch,
        io,
        remote,
        runtime,
        writer,
        acknowledge_takeover,
        acknowledge_resend,
        faults,
    )
    .map(|_| ())
}

#[expect(
    clippy::too_many_arguments,
    reason = "recovery command inputs and explicit consent controls"
)]
fn recovery_outcome(
    scratch: &Scratch,
    io: &SimIo,
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    writer: [u8; 16],
    acknowledge_takeover: Option<[u8; 16]>,
    acknowledge_resend: Option<[u8; 16]>,
    faults: FaultControl,
) -> Result<crate::RecoveryOutcome, crate::RecoveryCommandError> {
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let mut settings = config(&scratch.0);
    settings.cap = 134_217_728;
    settings.ownership_completion_reserve = granary_core::overlay_ownership::REPLACEMENT_RESERVE;
    crate::RecoveryCommand {
        construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        local: Some((Store::open(&scratch.0).unwrap(), io.clone())),
        config: settings,
        transport: remote,
        runtime,
        signer: &key,
        publisher_keys: &keys,
        writer,
        acknowledge_takeover,
        acknowledge_resend,
        faults,
    }
    .run(
        &remote.time,
        SigningKey::from_seed(&[39; 32]).unwrap(),
        &mut Entropy(
            130u8
                .wrapping_add(u8::try_from(remote.recovery_sends.load(Ordering::Relaxed)).unwrap()),
        ),
        SeededRng::new(2),
    )
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one restart transaction keeps its durable premises, action and paired outcome together"
)]
fn recovery_command_fence_settlement_and_publication_bound_resend() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for ending in ["no-write", "foreign", "landed", "empty", "wrong-ack", "ack"] {
        let fixture = runtime.block_on(Fixture::new());
        let stage = fixture.create("local", b"sealed");
        runtime.block_on(authenticate_registration(&fixture));
        let lane = runtime
            .block_on(
                fixture
                    .engine
                    .construct_commit(SyncOptions::default(), &mut Entropy(70)),
            )
            .unwrap();
        if ending == "landed" {
            published::write(&fixture, stage, 0, b"suffix");
            published::settle_disk(&fixture.io);
        }
        fixture.remote.publication_plan.lock().unwrap().extend(
            [if ending == "no-write" {
                PublishPlan::RateLimited
            } else {
                PublishPlan::Timeout
            }; 8],
        );
        let result = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
        assert_eq!(
            format!("{:?}", result.outcome),
            "Exhausted",
            "{ending}: {result:?}"
        );
        let record = budget::saved(&fixture);
        if matches!(ending, "foreign" | "landed") {
            let mut bytes = record.candidates[0].root.clone();
            if ending == "foreign" {
                bytes = runtime.block_on(super::selected::one_file(
                    &fixture.remote,
                    b"local",
                    b"different concurrent bytes",
                    [99; 16],
                ));
            }
            fixture
                .remote
                .published
                .lock()
                .unwrap()
                .insert(record.candidates[0].seq, bytes);
        }
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Timeout);
        let ack = match ending {
            "ack" => Some(record.publication_id),
            "wrong-ack" => Some([0; 16]),
            _ => None,
        };
        let events = super::selected::Events::default();
        let _guard = events.guard();
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            ack,
            FaultControl::default(),
        );
        let expected = match ending {
            "empty" | "wrong-ack" => Some("RecoveryUnresolved"),
            "ack" => Some("RecoveryResendUnanswered"),
            "foreign" => Some("RecoveryConflict"),
            _ => None,
        };
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                expected.map(|name| format!("intent refused: {name}")),
                match ending {
                    "ack" => 9,
                    "no-write" | "landed" => 10,
                    _ => 8,
                }
            ),
            "{ending}"
        );
        let mut reopened = start(&scratch, &io, 131);
        assert_eq!(
            reopened.recovery_rule().unwrap(),
            if expected.is_none() {
                RecoveryRule::Nothing
            } else {
                RecoveryRule::BoundaryRecorded
            },
            "{ending}"
        );
        if ending == "ack" {
            let after = super::selected::retained(&mut reopened).unwrap();
            assert_eq!(
                (
                    after.candidates[0].root.clone(),
                    after.candidates[0].request,
                    after.candidates[0].evidence.started
                ),
                (
                    record.candidates[0].root.clone(),
                    record.candidates[0].request,
                    9
                )
            );
            assert_eq!(
                (
                    remote.publication_sends.lock().unwrap().last().cloned(),
                    remote
                        .publication_operations
                        .lock()
                        .unwrap()
                        .last()
                        .cloned()
                ),
                (
                    Some(record.candidates[0].root.clone()),
                    Some(record.candidates[0].request.operation.to_vec())
                )
            );
        }
        if expected.is_none() {
            assert!(
                events.recover().iter().any(|e| {
                    e == if ending == "landed" {
                        "fence_settled how=landed"
                    } else {
                        "fence_settled how=released"
                    }
                }),
                "{ending}: {:?}",
                events.recover()
            );
        }
        if ending == "landed" {
            let root = remote
                .published
                .lock()
                .unwrap()
                .last_key_value()
                .unwrap()
                .1
                .clone();
            let doc = granary_core::root::decode_root(&root).unwrap();
            let objects = remote.objects.read_objects(doc.binmap_index).unwrap();
            assert_eq!(cut_file(&objects, &root, "local"), b"suffix");
            drop(reopened);
            io.crash();
            assert_eq!(
                boundary_command(
                    &scratch,
                    &io,
                    &remote,
                    &runtime,
                    writer,
                    None,
                    FaultControl::default()
                )
                .map_err(|error| error.to_string()),
                Ok(()),
                "clean released rerun"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 6);
}

#[test]
fn m13_finish_rederives_and_binds_the_exact_signed_landing() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let substituted = landing_cut(&runtime, false, None);
    let mut doc = granary_core::root::decode_root(&substituted.record.candidates[0].root).unwrap();
    doc.timestamp.secs += 1;
    doc.sigs.clear();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    crate::recovery::landing_hooks_for_test(crate::recovery::LandingHooks {
        substitute: Some(granary_core::root::encode_root(&doc).unwrap()),
        ..crate::recovery::LandingHooks::default()
    });
    let substituted_sends = substituted.remote.publication_sends.lock().unwrap().len();
    assert_eq!(
        (
            run_landing_cut(&substituted, &runtime)
                .unwrap_err()
                .to_string(),
            substituted.remote.publication_sends.lock().unwrap().len(),
        ),
        (
            "intent refused: SyncCommitLandingBinding".to_owned(),
            substituted_sends,
        ),
        "different signed timestamp passed the finish-seam binding"
    );

    let failed_read = landing_cut(&runtime, false, None);
    crate::recovery::landing_hooks_for_test(crate::recovery::LandingHooks {
        witness_failure: true,
        ..crate::recovery::LandingHooks::default()
    });
    let failed_sends = failed_read.remote.publication_sends.lock().unwrap().len();
    let error = run_landing_cut(&failed_read, &runtime)
        .unwrap_err()
        .to_string();
    assert_eq!(
        (
            error.contains("injected landing witness failure"),
            failed_read.remote.publication_sends.lock().unwrap().len(),
        ),
        (true, failed_sends),
        "witness failure result and publication sends: {error}"
    );
    let events = super::selected::Events::default();
    let _guard = events.guard();
    run_landing_cut(&failed_read, &runtime).unwrap();
    assert!(
        events
            .recover()
            .iter()
            .any(|event| event == "fence_settled how=landed"),
        "a completed B2 finish on re-run omitted its settled event: {:?}",
        events.recover()
    );

    let valid = landing_cut(&runtime, false, None);
    let expected = valid.record.candidates[0].root.clone();
    let sends = valid.remote.publication_sends.lock().unwrap().len();
    run_landing_cut(&valid, &runtime).unwrap();
    let installed = start(&valid.scratch, &valid.io, 132);
    assert_eq!(
        (
            installed.snapshot().root.clone(),
            valid.remote.publication_sends.lock().unwrap().len(),
        ),
        (expected, sends),
        "valid stored landing did not install without a publication send"
    );
}

#[test]
fn incomplete_landing_repair_prefers_the_exact_stored_candidate_without_sending() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cut = landing_cut(&runtime, false, None);
    let mut local = start(&cut.scratch, &cut.io, 138);
    let base = cut.remote.published.lock().unwrap()[&1].clone();
    let mut opened = header();
    opened.writer = local.writer_uuid();
    opened.base_root = GrainId::of(&base);
    local
        .open_overlay(opened, Vec::new(), &mut Source::default(), cut.io.clone())
        .unwrap();
    let (boundary, publication) = local
        .recovery_commits()
        .unwrap()
        .into_iter()
        .find_map(|commit| match commit {
            RecoveryCommit::Boundary {
                index,
                publication_id,
                ..
            } => Some((index, publication_id)),
            RecoveryCommit::Landed { .. } => None,
        })
        .unwrap();
    let scope = local.snapshot().scope.clone();
    let volume = local.snapshot().volume.clone();
    let exact = local
        .publication_transaction(|journal| {
            let mut record = journal.load(&scope, &volume)?.unwrap();
            let generation = record.generation;
            let mut exact = record.candidates[0].clone();
            let mut doc = granary_core::root::decode_root(&exact.root).unwrap();
            doc.sigs.push(RootSig {
                key_id: [98; 32],
                sig: [0; 64],
            });
            exact.number += 1;
            exact.root = granary_core::root::encode_root(&doc).unwrap();
            exact.id = GrainId::of(&exact.root);
            record.candidates[0].role = granary_core::retained_submission::Role::History;
            record.candidates.push(exact.clone());
            record.generation += 1;
            journal.replace(generation, &record)?;
            Ok(exact)
        })
        .unwrap();
    cut.remote
        .published
        .lock()
        .unwrap()
        .insert(exact.seq, exact.root.clone());
    local
        .overlay_transaction(|transaction| {
            transaction.record_landed(&crate::LandedProof {
                boundary_seq: boundary,
                landed_root: exact.id,
                landed_seq: exact.seq,
                captured_entries: Vec::new(),
                entries: Vec::new(),
            })
        })
        .unwrap();
    assert_eq!(publication, cut.record.publication_id);
    drop(local);
    cut.io.crash();
    let sends = cut.remote.publication_sends.lock().unwrap().len();
    run_landing_cut(&cut, &runtime).unwrap();
    let mut installed = start(&cut.scratch, &cut.io, 139);
    let completed = super::selected::retained(&mut installed).unwrap();
    let granary_core::retained_submission::Phase::Complete(done) = completed.phase else {
        panic!("incomplete retained landing was not repaired")
    };
    assert_eq!(
        (
            done.seq,
            done.id,
            done.root,
            installed.snapshot().root.clone(),
            cut.remote.publication_sends.lock().unwrap().len(),
        ),
        (exact.seq, exact.id, exact.root.clone(), exact.root, sends),
        "(completion, installed stored root, publication sends)"
    );
}

#[test]
fn landing_read_facade_shares_publication_controls_and_counters() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new());
    let facade = crate::WritableAuthority::read_facade(fixture.remote.as_ref());
    assert!(
        Arc::ptr_eq(&fixture.remote.publication_plan, &facade.publication_plan)
            && Arc::ptr_eq(&fixture.remote.publication_sends, &facade.publication_sends)
            && Arc::ptr_eq(
                &fixture.remote.publication_operations,
                &facade.publication_operations
            ),
        "landing facade hid publication plans or sends from the row observer"
    );
}

#[test]
fn landed_refresh_retry_uses_the_callers_advancing_clock() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cut = landing_cut(&runtime, false, None);
    cut.remote.unknown.store(true, Ordering::Relaxed);
    cut.remote.hold_first.store(true, Ordering::Relaxed);
    let remote = cut.remote.clone();
    let release = runtime.spawn(async move {
        remote.entered.notified().await;
        remote.release.notify_one();
        TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
        remote.unknown.store(false, Ordering::Relaxed);
    });
    let attempts = cut.remote.attempts.lock().unwrap().len();
    let sends = cut.remote.publication_sends.lock().unwrap().len();
    run_landing_cut(&cut, &runtime).unwrap();
    runtime.block_on(release).unwrap();
    assert_eq!(
        (
            cut.remote.attempts.lock().unwrap().len() - attempts,
            cut.remote.publication_sends.lock().unwrap().len(),
        ),
        (2, sends),
        "the first transient refresh was not retried without a publication send"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the two-candidate chain and installed completion are one end-to-end evidence row"
)]
fn m14_b2_completes_and_installs_the_highest_matching_candidate() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new());
    runtime.block_on(authenticate_registration(&fixture));
    let lane = runtime
        .block_on(
            fixture
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70)),
        )
        .unwrap();
    let initial_record = budget::saved(&fixture);
    let mut earlier = granary_core::root::decode_root(&initial_record.candidates[0].root).unwrap();
    earlier.sigs.push(RootSig {
        key_id: [98; 32],
        sig: [0; 64],
    });
    let earlier = granary_core::root::encode_root(&earlier).unwrap();
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(initial_record.candidates[0].seq, earlier);
    let foreign = runtime.block_on(rebase::foreign_head(&fixture, "remote"));
    let foreign_id = GrainId::of(&foreign);
    let foreign_seq = granary_core::root::decode_root(&foreign).unwrap().seq;
    let manifest = runtime
        .block_on(fixture.engine.rebase_commit_manifest(
            &lane,
            &initial_record.frozen,
            Some(foreign_id),
            foreign_seq + 1,
        ))
        .unwrap();
    let mut record = budget::saved(&fixture);
    let mut higher = record.candidates[0].clone();
    record.candidates[0].role = granary_core::retained_submission::Role::History;
    record.candidates[0].evidence.start().unwrap();
    let initial = granary_core::root::decode_root(&higher.root).unwrap();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let prepared = runtime
        .block_on(crate::prepare_from_manifest(
            fixture.remote.as_ref(),
            fixture.content.as_ref(),
            manifest,
            crate::HarvestStats::default(),
            &initial.volume,
            &key,
            &granary_core::identity::WriterIdentity::from_bytes(initial.writer_uuid),
            initial.timestamp,
            crate::Policy::default(),
        ))
        .unwrap();
    let mut prepared_doc = granary_core::root::decode_root(&prepared.root_bytes).unwrap();
    prepared_doc.writer_uuid = initial.writer_uuid;
    prepared_doc.sigs.clear();
    prepared_doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&prepared_doc).unwrap()),
    });
    higher.root = granary_core::root::encode_root(&prepared_doc).unwrap();
    higher.id = GrainId::of(&higher.root);
    higher.seq = granary_core::root::decode_root(&higher.root).unwrap().seq;
    higher.number += 1;
    higher.evidence = granary_core::retained_submission::Evidence::default();
    record.candidates.push(higher.clone());
    record.generation += 1;
    runtime
        .block_on(
            fixture
                .engine
                .replace_commit_record(&lane, record.generation - 1, &record),
        )
        .unwrap();
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Timeout; 8]);
    let sends = fixture.remote.publication_sends.lock().unwrap().len();
    let result = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
    let PublicationOutcome::Landed(done) = &result.outcome else {
        panic!("variant landing did not complete before dispatch: {result:?}")
    };
    let record = budget::saved(&fixture);
    let higher = record
        .candidates
        .iter()
        .find(|candidate| candidate.id == done.id)
        .unwrap()
        .clone();
    let stored_higher = fixture
        .remote
        .published
        .lock()
        .unwrap()
        .get(&higher.seq)
        .unwrap()
        .clone();
    assert_ne!(higher.id, GrainId::of(&stored_higher));
    assert_eq!(
        (
            record.phase,
            fixture.store.lock().unwrap().snapshot().root.clone(),
            fixture.remote.publication_sends.lock().unwrap().len(),
        ),
        (
            granary_core::retained_submission::Phase::Complete(done.clone()),
            stored_higher,
            sends,
        ),
        "(candidate completion, installed stored variant, publication sends)"
    );
}

#[test]
fn m15_requires_retained_checkpoint_material_and_preserves_journal_on_read_failure() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for material in ["missing", "foreign"] {
        let cut = landing_cut(&runtime, false, None);
        crate::recovery::landing_hooks_for_test(crate::recovery::LandingHooks {
            checkpoint_failure: true,
            ..crate::recovery::LandingHooks::default()
        });
        let sends = cut.remote.publication_sends.lock().unwrap().len();
        let error = run_landing_cut(&cut, &runtime).unwrap_err().to_string();
        let mut after_failure = start(&cut.scratch, &cut.io, 134);
        assert_eq!(
            (
                error.contains("injected checkpoint read failure"),
                after_failure.recovery_rule().unwrap(),
                cut.remote.publication_sends.lock().unwrap().len(),
            ),
            (true, RecoveryRule::LandedUnrefreshed, sends),
            "{material}: checkpoint failure did not preserve J and sends: {error}"
        );
        let scope = after_failure.snapshot().scope.clone();
        let volume = after_failure.snapshot().volume.clone();
        after_failure
            .publication_transaction(|journal| {
                if material == "missing" {
                    journal.inject_selected_for_test(&scope, &volume, None)
                } else {
                    let mut record = journal.observe(&scope, &volume)?.unwrap();
                    record.publication_id = [88; 16];
                    journal.inject_selected_for_test(&scope, &volume, Some(&record))
                }
            })
            .unwrap();
        drop(after_failure);
        let rerun = run_landing_cut(&cut, &runtime).map_err(|error| error.to_string());
        assert_eq!(
            (rerun, cut.remote.publication_sends.lock().unwrap().len()),
            (
                Err("intent refused: RecoveryLandedEvidenceMissing".to_owned()),
                sends,
            ),
            "{material}: invalid retained material was accepted"
        );
        cases += 1;
    }

    let valid = landing_cut(&runtime, true, None);
    let root = valid.record.candidates[0].root.clone();
    let sends = valid.remote.publication_sends.lock().unwrap().len();
    run_landing_cut(&valid, &runtime).unwrap();
    let installed = start(&valid.scratch, &valid.io, 135);
    let (_, grains) = cut_file_grains(valid.content.as_ref(), &root, "local");
    for grain in grains {
        valid
            .content
            .objects
            .lock()
            .unwrap()
            .insert(grain, b"forged".to_vec());
    }
    assert_eq!(
        (
            installed.snapshot().root.clone(),
            cut_file(installed.recovery_store(), &root, "local"),
            valid.remote.publication_sends.lock().unwrap().len(),
        ),
        (root, b"sealed".to_vec(), sends),
        "retained capture was not the installed source"
    );
    cases += 1;
    assert_eq!(cases, 3);
}

fn terminal_boundary(runtime: &tokio::runtime::Runtime) -> Fixture {
    let terminal = runtime.block_on(Fixture::new());
    terminal.create("local", b"sealed");
    runtime.block_on(authenticate_registration(&terminal));
    runtime
        .block_on(
            terminal
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70)),
        )
        .unwrap();
    let (_, _, _, _, record) = terminal.store.lock().unwrap().recovered_commit().unwrap();
    let mut answered = record.clone();
    let attempt = answered.candidates[0].evidence.start().unwrap();
    answered.candidates[0]
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    answered.last_response = Some(granary_core::retained_submission::LastResponse {
        candidate: 1,
        attempt,
        status: 409,
        token: b"stale-base".to_vec(),
        answer: vec![],
    });
    answered.generation += 1;
    terminal
        .store
        .lock()
        .unwrap()
        .publication_transaction(|journal| journal.replace(record.generation, &answered))
        .unwrap();
    assert!(crate::sync::terminal_non_landing(&answered), "{answered:?}");
    terminal
}

#[test]
fn deferred_answer_blocks_terminal_store_consumers() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = terminal_boundary(&runtime);
    let record = budget::saved(&fixture);
    let mut deferred = record.clone();
    let candidate = &deferred.candidates[0];
    deferred.last_response.as_mut().unwrap().answer = granary_core::authority_answer::encode(
        granary_core::authority_answer::PublishAnswer::StaleBase(
            granary_core::authority_answer::Head::new(Some((candidate.seq, candidate.id))),
        ),
    )
    .unwrap();
    deferred.phase = granary_core::retained_submission::Phase::Unresolved(
        granary_core::retained_submission::Probe {
            cycle: deferred.generation,
            seq: candidate.seq,
            reason: granary_core::retained_submission::ProbeReason::ContentUnavailable,
        },
    );
    deferred.generation += 1;
    granary_core::retained_submission::validate(&deferred).unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|journal| journal.replace(record.generation, &deferred))
        .unwrap();
    let refusal = fixture
        .store
        .lock()
        .unwrap()
        .reconcile_commit_rejection()
        .unwrap_err();
    assert_eq!(
        refusal.to_string(),
        "intent refused: SyncCommitUnresolved",
        "terminal reconciliation must not archive or strip deferred evidence"
    );

    let restarted = runtime.block_on(fixture.restart());
    restarted
        .engine
        .recover_commit(crate::SyncOptions::default())
        .unwrap();
    let retained = budget::saved(&restarted);
    assert_eq!(
        (
            restarted.engine.commit_lane_for_test(),
            retained.phase,
            retained.last_response.is_some(),
            restarted
                .store
                .lock()
                .unwrap()
                .recovery_commits()
                .unwrap()
                .len(),
        ),
        ((false, true), deferred.phase, true, 1),
        "restart attachment must retain the live lane, record and boundary"
    );
}

#[test]
fn terminal_no_boundary_archives_before_resume() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for terminal in [true, false] {
        let fixture = terminal_boundary(&runtime);
        let record = budget::saved(&fixture);
        if !terminal {
            let mut unknown = record.clone();
            unknown.candidates[0].evidence.start().unwrap();
            unknown.generation += 1;
            fixture
                .store
                .lock()
                .unwrap()
                .publication_transaction(|journal| journal.replace(record.generation, &unknown))
                .unwrap();
        }
        fixture.io.mutate_recovered("journal", |bytes| {
            let header = granary_core::overlay_journal::scan_journal(bytes)
                .unwrap()
                .header;
            *bytes = header.encode().unwrap();
        });
        let (scratch, io, remote, mut local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        assert_eq!(local.recovery_rule().unwrap(), RecoveryRule::ResumeRecovery);
        drop(local);
        // The authenticated journal-base read stops finishing before any send.
        // Terminal evidence must already be archived.
        let probes = remote.probes.load(Ordering::Relaxed);
        remote.failed_probe.store(probes + 1, Ordering::Relaxed);
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        let mut reopened = start(&scratch, &io, 136);
        let archived = reopened
            .publication_transaction(|journal| {
                journal.archived(
                    &record.scope.digest().unwrap(),
                    &record.volume,
                    record.publication_id,
                )
            })
            .unwrap();
        assert_eq!(
            (
                result.map_err(|error| error.to_string()),
                remote.probes.load(Ordering::Relaxed) != probes,
                archived,
                super::selected::retained(&mut reopened).is_some(),
                remote.publication_sends.lock().unwrap().len(),
            ),
            (
                Err("remote: store: probe fixture".to_owned()),
                true,
                terminal,
                !terminal,
                0
            ),
            "terminal={terminal}: (result, attempted resume, archived, retained, sends)"
        );
        if terminal {
            drop(reopened);
            let result = boundary_command(
                &scratch,
                &io,
                &remote,
                &runtime,
                writer,
                None,
                FaultControl::default(),
            );
            let mut reopened = start(&scratch, &io, 137);
            assert_eq!(
                (
                    result.map_err(|error| error.to_string()),
                    reopened.recovery_rule().unwrap(),
                    reopened.snapshot().phase
                ),
                (Ok(()), RecoveryRule::Nothing, Phase::Released)
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn terminal_no_boundary_cleanup_continues_to_release() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = terminal_boundary(&runtime);
    let record = budget::saved(&fixture);
    let Fixture {
        _scratch: scratch, ..
    } = &fixture;
    let area = crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
    let mut io = fixture.io.clone();
    io.remove(&area.join("journal")).unwrap();
    published::settle_disk(&io);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    )
    .unwrap();
    let mut released = start(&scratch, &io, 137);
    let archived = released
        .publication_transaction(|journal| {
            journal.archived(
                &record.scope.digest().unwrap(),
                &record.volume,
                record.publication_id,
            )
        })
        .unwrap();
    assert_eq!(
        (
            released.snapshot().phase,
            released.recovery_rule().unwrap(),
            archived,
            remote.publication_sends.lock().unwrap().len(),
        ),
        (Phase::Released, RecoveryRule::Nothing, true, 1),
        "(carrier phase, recovery rule, terminal archive, publication sends)"
    );
}

#[test]
fn terminal_no_boundary_archive_cuts_reenter_rule_three() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for cut in ["saved", "renamed", "synced"] {
        let fixture = terminal_boundary(&runtime);
        let record = budget::saved(&fixture);
        fixture.io.mutate_recovered("journal", |bytes| {
            let header = granary_core::overlay_journal::scan_journal(bytes)
                .unwrap()
                .header;
            *bytes = header.encode().unwrap();
        });
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let faults = FaultControl::default();
        faults.arm("recover.archive", cut, 1, FaultAction::Fail);
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            faults.clone(),
        );
        assert_eq!(
            (result.is_err(), faults.fired().len()),
            (true, 1),
            "{cut}: {result:?}"
        );
        io.crash();
        let mut reopened = start(&scratch, &io, 138);
        let archived = reopened
            .publication_transaction(|journal| {
                journal.archived(
                    &record.scope.digest().unwrap(),
                    &record.volume,
                    record.publication_id,
                )
            })
            .unwrap();
        assert_eq!(
            (archived, reopened.recovery_rule().unwrap()),
            (
                cut != "saved",
                if cut == "saved" {
                    RecoveryRule::ResumeRecovery
                } else {
                    RecoveryRule::DirtyJournal
                }
            ),
            "{cut}: (archive, restart rule)"
        );
        drop(reopened);
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        let mut reopened = start(&scratch, &io, 139);
        assert_eq!(
            (
                result.map_err(|error| error.to_string()),
                reopened.recovery_rule().unwrap(),
                reopened.snapshot().phase
            ),
            (Ok(()), RecoveryRule::Nothing, Phase::Released),
            "{cut}: re-run"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one restart row keeps installed identity controls and the release outcome together"
)]
fn installed_release_binds_header_root_and_sequence() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for (variant, cut) in [(false, false), (true, false), (true, true)] {
        let fixture = runtime.block_on(Fixture::new());
        // The selected registration must describe this empty journal.
        runtime
            .block_on(async {
                fixture
                    .engine
                    .sync(SyncTarget::Directory(None), SyncOptions::default())
                    .wait()
                    .await
            })
            .unwrap();
        let lane = runtime
            .block_on(
                fixture
                    .engine
                    .construct_commit(SyncOptions::default(), &mut Entropy(70)),
            )
            .unwrap();
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::Timeout; 8]);
        let result = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
        assert!(
            matches!(result.outcome, PublicationOutcome::Exhausted),
            "{result:?}"
        );
        let record = budget::saved(&fixture);
        let candidate = &record.candidates[0];
        let mut stored = candidate.root.clone();
        if variant {
            let mut doc = granary_core::root::decode_root(&stored).unwrap();
            doc.sigs.push(RootSig {
                key_id: [98; 32],
                sig: [0; 64],
            });
            stored = granary_core::root::encode_root(&doc).unwrap();
        }
        fixture
            .remote
            .published
            .lock()
            .unwrap()
            .insert(candidate.seq, stored.clone());
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let faults = FaultControl::default();
        if cut {
            faults.arm("overlay.replace.switched", "after", 1, FaultAction::Fail);
        } else {
            faults.arm("recover.release", "before", 1, FaultAction::Fail);
        }
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            faults.clone(),
        );
        assert_eq!(
            (result.is_err(), faults.fired().len()),
            (true, 1),
            "variant={variant}, cut={cut}: {result:?}"
        );
        io.crash();
        let mut installed = start(&scratch, &io, 137);
        assert_eq!(
            (
                installed.recovery_rule().unwrap(),
                installed.snapshot().root.clone(),
                remote.publication_sends.lock().unwrap().len()
            ),
            (RecoveryRule::Release, stored.clone(), 8),
            "variant={variant}: installed state must release before classification"
        );
        let original = io.recovered_bytes("journal").unwrap();
        for mismatch in ["root", "seq"].into_iter().filter(|_| variant) {
            io.mutate_recovered("journal", |bytes| {
                let mut header = granary_core::overlay_journal::scan_journal(bytes)
                    .unwrap()
                    .header;
                if mismatch == "root" {
                    header.base_root = GrainId::of(b"different base");
                } else {
                    header.base_seq += 1;
                }
                *bytes = header.encode().unwrap();
            });
            io.crash();
            assert_eq!(
                installed.recovery_rule().unwrap(),
                RecoveryRule::Classify,
                "variant={variant}, {mismatch}: mismatching installed header released early"
            );
            io.mutate_recovered("journal", |bytes| *bytes = original.clone());
            io.crash();
        }
        // A different unpublished P beside the older completion is not this
        // installed landing, even when its manifest and writer are identical.
        installed.prepare_succession(&Tick(2_000_000)).unwrap();
        crate::writable_start::settle_recovery(
            &mut installed,
            &Tick(2_000_000),
            drive(&remote, &Cell::new(0)),
        )
        .unwrap();
        let mut opened = header();
        opened.writer = writer;
        opened.base_root = GrainId::of(&stored);
        opened.base_seq = candidate.seq;
        installed
            .open_overlay(opened, vec![], &mut Source::default(), io.clone())
            .unwrap();
        let mut doc = granary_core::root::decode_root(&stored).unwrap();
        doc.timestamp.secs += 1;
        let unpublished = rebase::signed(doc);
        register_bytes(&mut installed, &remote, &unpublished, &Tick(2_000_010));
        assert_eq!(
            installed.recovery_rule().unwrap(),
            RecoveryRule::Classify,
            "older Complete R beside unpublished P released early"
        );
        // Restore the exact registered stored root, then run the real command
        // across another restart. No lost-store classification is necessary.
        register_bytes(&mut installed, &remote, &stored, &Tick(2_000_030));
        if variant {
            let owner = io.recovered_bytes("ownership").unwrap();
            installed
                .prepare_registration(&stored, vec![1], &Tick(2_000_040), |_, _| true)
                .unwrap();
            assert_eq!(
                installed.recovery_rule().unwrap(),
                RecoveryRule::Classify,
                "pending context released an installed landing"
            );
            io.mutate_recovered("ownership", |bytes| *bytes = owner.clone());
            io.crash();
            assert_eq!(io.recovered_bytes("ownership"), Some(owner));
        }
        drop(installed);
        let events = super::selected::Events::default();
        let _guard = events.guard();
        let probes = remote.probes.load(Ordering::Relaxed);
        *remote.listing_fault.lock().unwrap() = Some(RootStoreError::Backend(
            "classification must not run".into(),
        ));
        boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        )
        .unwrap();
        let mut released = start(&scratch, &io, 139);
        assert_eq!(
            (
                released.snapshot().phase,
                released.recovery_rule().unwrap(),
                remote.publication_sends.lock().unwrap().len(),
                remote.probes.load(Ordering::Relaxed) > probes,
                remote.listing_fault.lock().unwrap().is_some(),
                events
                    .recover()
                    .iter()
                    .any(|event| event.starts_with("journal_finished"))
            ),
            (Phase::Released, RecoveryRule::Nothing, 8, true, true, true),
            "variant={variant}: (phase, rule, sends, authenticated base read, classification fault retained, finished)"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "four cleanup entries keep each premise and archive outcome together"
)]
fn terminal_cleanup_archives_at_each_entry() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for entry in ["finish", "unsubmitted", "no-boundary"] {
        let fixture = terminal_boundary(&runtime);
        let mut record = budget::saved(&fixture);
        let mut local = fixture.store.lock().unwrap();
        let boundary = local
            .recovery_commits()
            .unwrap()
            .into_iter()
            .find_map(|commit| match commit {
                RecoveryCommit::Boundary { index, .. } => Some(index),
                RecoveryCommit::Landed { .. } => None,
            })
            .unwrap();
        match entry {
            "finish" => local
                .finish_non_landing(1, boundary, record.publication_id)
                .unwrap(),
            "unsubmitted" => {
                record.publication_id = [99; 16];
                local
                    .publication_transaction(|journal| {
                        journal.inject_selected_for_test(
                            &record.scope,
                            &record.volume,
                            Some(&record),
                        )
                    })
                    .unwrap();
            }
            "no-boundary" => {
                let proof = crate::RejectionProof::NoWrite(
                    crate::NoWriteProof::from_submission(&record, 0).unwrap(),
                );
                local
                    .overlay_transaction(|transaction| {
                        transaction.replace_rejected_with_proof(
                            boundary,
                            record.publication_id,
                            proof,
                        )
                    })
                    .unwrap();
                local.reconcile_commit_rejection().unwrap();
            }
            _ => unreachable!(),
        }
        drop(local);
        let (_scratch, io, remote, mut local) = fixture.reload_carrier();
        if entry == "unsubmitted" {
            let base = remote.published.lock().unwrap()[&1].clone();
            let mut opened = header();
            opened.writer = local.writer_uuid();
            opened.base_root = GrainId::of(&base);
            local
                .open_overlay(opened, vec![], &mut Source::default(), io.clone())
                .unwrap();
            local.reconcile_unsubmitted_commit().unwrap();
        }
        assert_eq!(
            (
                super::selected::retained(&mut local).is_none(),
                local
                    .publication_transaction(|journal| journal.archived(
                        &record.scope.digest().unwrap(),
                        &record.volume,
                        record.publication_id
                    ))
                    .unwrap(),
                remote.publication_sends.lock().unwrap().len()
            ),
            (true, true, 0),
            "{entry}: (live removed, archived, sends)"
        );
        cases += 1;
    }

    let fixture = terminal_boundary(&runtime);
    let record = budget::saved(&fixture);
    let (scratch, io, remote, mut local) = fixture.reload_carrier();
    let sends = remote.publication_sends.lock().unwrap().len();
    let base = remote.published.lock().unwrap()[&1].clone();
    let mut opened = header();
    opened.writer = local.writer_uuid();
    opened.base_root = GrainId::of(&base);
    local
        .open_overlay(opened, vec![], &mut Source::default(), io.clone())
        .unwrap();
    local.attach_sync_engine().unwrap();
    drop(local);
    let mut local = start(&scratch, &io, 141);
    assert_eq!(
        (
            super::selected::retained(&mut local).is_none(),
            local
                .publication_transaction(|journal| journal.archived(
                    &record.scope.digest().unwrap(),
                    &record.volume,
                    record.publication_id
                ))
                .unwrap(),
            remote.publication_sends.lock().unwrap().len()
        ),
        (true, true, sends),
        "attach: (live removed, archived, sends)"
    );
    cases += 1;
    assert_eq!(cases, 4);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "six durable cuts keep each fault, restart rule and preserved work together"
)]
fn terminal_rejection_archives_before_strip_and_restarts_at_each_cut() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for cut in [
        "none",
        "saved",
        "renamed",
        "synced",
        "strip-before",
        "stripped",
    ] {
        let fixture = terminal_boundary(&runtime);
        let record = budget::saved(&fixture);
        let faults = fixture.store.lock().unwrap().fault_control();
        if cut == "strip-before" {
            faults.arm("overlay.replace.sync", "before", 1, FaultAction::Fail);
        } else if cut == "stripped" {
            faults.arm("overlay.replace.switched", "after", 1, FaultAction::Fail);
        } else if cut != "none" {
            faults.arm("recover.archive", cut, 1, FaultAction::Fail);
        }
        let before = fixture.io.recovered_bytes("journal");
        let result = fixture.store.lock().unwrap().reconcile_commit_rejection();
        assert_eq!(
            (result.is_ok(), faults.fired().len()),
            (cut == "none", usize::from(cut != "none")),
            "{cut}: {result:?}"
        );
        if cut == "saved" {
            assert_eq!(
                fixture.io.recovered_bytes("journal"),
                before,
                "failed archive stripped the boundary"
            );
        }
        if cut == "strip-before" {
            assert_eq!(
                fixture
                    .store
                    .lock()
                    .unwrap()
                    .reconcile_commit_rejection()
                    .unwrap_err()
                    .to_string(),
                "intent refused: IntentPersistencePoisoned",
                "in-process retry after a durable archive"
            );
        }
        let (scratch, io, remote, mut local) = fixture.reload_carrier();
        let archived = local
            .publication_transaction(|journal| {
                journal.archived(
                    &record.scope.digest().unwrap(),
                    &record.volume,
                    record.publication_id,
                )
            })
            .unwrap();
        let rule = local.recovery_rule().unwrap();
        assert_eq!(
            (
                archived,
                rule,
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                cut != "saved",
                match cut {
                    "none" | "stripped" => RecoveryRule::DirtyJournal,
                    "saved" => RecoveryRule::BoundaryRecorded,
                    _ => RecoveryRule::BoundaryArchived,
                },
                0
            ),
            "{cut}: (archive, restart rule, sends)"
        );
        if cut == "saved" {
            let area =
                crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
            let stages = io.clone().entries(&area.join("staging")).unwrap();
            assert_eq!(stages.len(), 1, "{cut}: dirty file lost: {stages:?}");
            assert_eq!(
                io.bytes(&area.join("staging").join(&stages[0])).get(160..),
                Some(b"sealed".as_slice()),
                "{cut}"
            );
        } else {
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
            )
            .map_err(|error| error.to_string());
            local = start(&scratch, &io, 140);
            assert_eq!(
                (
                    result,
                    local.recovery_rule().unwrap(),
                    local.snapshot().phase
                ),
                (Ok(()), RecoveryRule::Nothing, Phase::Released),
                "{cut}: restart result"
            );
            let root = remote
                .published
                .lock()
                .unwrap()
                .last_key_value()
                .unwrap()
                .1
                .clone();
            let doc = granary_core::root::decode_root(&root).unwrap();
            let objects = remote.objects.read_objects(doc.binmap_index).unwrap();
            assert_eq!(
                cut_file(&objects, &root, "local"),
                b"sealed",
                "{cut}: published file"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 6);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one restart transaction keeps its durable premises, action and paired outcome together"
)]
fn recovery_command_b1_durable_cuts_reenter_the_classified_rule() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for (name, phase, expected) in [
        ("recover.boundary", "loaded", RecoveryRule::BoundaryRecorded),
        ("recover.archive", "saved", RecoveryRule::BoundaryRecorded),
        ("recover.archive", "renamed", RecoveryRule::BoundaryArchived),
        ("recover.archive", "synced", RecoveryRule::BoundaryArchived),
        (
            "overlay.replace.sync",
            "before",
            RecoveryRule::BoundaryArchived,
        ),
        (
            "overlay.replace.sync",
            "after",
            RecoveryRule::BoundaryArchived,
        ),
        (
            "overlay.replace.rename",
            "before",
            RecoveryRule::BoundaryArchived,
        ),
        (
            "overlay.replace.rename",
            "after",
            RecoveryRule::BoundaryArchived,
        ),
        (
            "overlay.replace.dir_sync",
            "before",
            RecoveryRule::BoundaryArchived,
        ),
        (
            "overlay.replace.dir_sync",
            "after",
            RecoveryRule::DirtyJournal,
        ),
        (
            "overlay.replace.switched",
            "after",
            RecoveryRule::DirtyJournal,
        ),
    ] {
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
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::RateLimited; 8]);
        let result = runtime.block_on(budget::drive(&fixture, &lane, &mut Delay));
        assert!(
            matches!(result.outcome, PublicationOutcome::Exhausted),
            "{name}/{phase}: {result:?}"
        );
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let faults = FaultControl::default();
        faults.arm(name, phase, 1, FaultAction::Fail);
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            faults.clone(),
        );
        assert_eq!(
            (result.is_err(), faults.fired().len()),
            (true, 1),
            "{name}/{phase}: {result:?}, {:?}",
            faults.fired()
        );
        io.crash();
        let mut reopened = start(&scratch, &io, 131);
        assert_eq!(
            reopened.recovery_rule().unwrap(),
            expected,
            "{name}/{phase}"
        );
        drop(reopened);
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        assert_eq!(result.err().map(|e| e.to_string()), None, "{name}/{phase}");
        let mut reopened = start(&scratch, &io, 132);
        assert_eq!(
            (
                reopened.recovery_rule().unwrap(),
                remote.publication_sends.lock().unwrap().len()
            ),
            (RecoveryRule::Nothing, 9),
            "{name}/{phase}"
        );
        cases += 1;
    }
    assert_eq!(cases, 11);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one restart table keeps terminal evidence and observed completion together"
)]
fn b1_settlement_releases_an_exhausted_restart() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for fence_only_loss in [false, true] {
        let fixture =
            exhausted_boundary(&runtime, PublishPlan::RateLimited, PublishPlan::RateLimited);
        let record = budget::saved(&fixture);
        let (scratch, mut io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        if fence_only_loss {
            let area =
                crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
            let path = area.join("journal");
            let old = io.bytes(&path);
            let header = codec::scan_journal(&old).unwrap().header;
            let mut records = Vec::new();
            codec::scan_journal_with(&old, |_, record| {
                if !matches!(record, Record::CommitFence { .. }) {
                    records.push(record.clone());
                }
            })
            .unwrap();
            let bytes = codec::encode_journal(&header, &records).unwrap();
            io.resize(&path, 0).unwrap();
            io.write_at(&path, 0, &bytes).unwrap();
            io.sync(&path).unwrap();
        }
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        let mut local = start(&scratch, &io, 132);
        assert_eq!(
            (
                result.is_ok(),
                local.recovery_rule().unwrap(),
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                !fence_only_loss,
                if fence_only_loss {
                    RecoveryRule::BoundaryRecorded
                } else {
                    RecoveryRule::Nothing
                },
                if fence_only_loss { 8 } else { 9 }
            ),
            "fence_only_loss={fence_only_loss}, cases={}, {result:?}",
            cases + 1
        );
        if fence_only_loss {
            let retained = super::selected::retained(&mut local).unwrap();
            assert_eq!(
                retained.candidates.first().unwrap().evidence.started,
                8,
                "{retained:?}"
            );
            assert!(
                matches!(
                    result,
                    Err(crate::RecoveryCommandError::Coordination(
                        CoordinationError::CommitFenced { .. }
                            | CoordinationError::Refused("SyncCommitExhausted")
                    ))
                ),
                "{result:?}"
            );
        }
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
        let mut local = start(&scratch, &io, 133);
        let after = super::selected::retained(&mut local).unwrap();
        assert_eq!(
            (
                result.is_ok(),
                local.recovery_rule().unwrap(),
                after.is_complete(),
                after.publication_id != record.publication_id,
                remote.publication_sends.lock().unwrap().len()
            ),
            (true, RecoveryRule::Nothing, true, true, 9),
            "fence_only_loss={fence_only_loss}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one restart transaction keeps its durable premises, action and paired outcome together"
)]
async fn boundary_settlement_restarts_in_the_classified_rule_without_an_extra_send() {
    let mut cases = 0;
    for ending in [
        "no-write",
        "foreign",
        "landed",
        "empty",
        "archive-fenced",
        "archive-unfenced",
        "archive-foreign",
        "archive-foreign-unfenced",
        "archive-acknowledged-landed-unfenced",
    ] {
        let fixture = Fixture::new().await;
        let stage = fixture.create("local", b"sealed");
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        if !ending.ends_with("unfenced") {
            fixture.remote.publication_plan.lock().unwrap().extend(
                [if matches!(ending, "no-write" | "archive-fenced") {
                    PublishPlan::RateLimited
                } else {
                    PublishPlan::Timeout
                }; 8],
            );
            let result = budget::drive(&fixture, &lane, &mut Delay).await;
            assert_eq!(
                format!("{:?}", result.outcome),
                "Exhausted",
                "{ending}: exhaustion premise: {result:?}"
            );
        }
        if matches!(
            ending,
            "archive-foreign-unfenced" | "archive-acknowledged-landed-unfenced"
        ) {
            mark_boundary_attempt(&fixture, &lane);
        }
        let record = budget::saved(&fixture);
        if matches!(
            ending,
            "landed"
                | "foreign"
                | "archive-foreign"
                | "archive-foreign-unfenced"
                | "archive-acknowledged-landed-unfenced"
        ) {
            let mut bytes = record.candidates[0].root.clone();
            if !matches!(ending, "landed" | "archive-acknowledged-landed-unfenced") {
                let mut doc = granary_core::root::decode_root(&bytes).unwrap();
                doc.writer_uuid = [99; 16];
                doc.sigs.clear();
                let key = SigningKey::from_seed(&[39; 32]).unwrap();
                doc.sigs.push(RootSig {
                    key_id: key.key_id(),
                    sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
                });
                bytes = granary_core::root::encode_root(&doc).unwrap();
            }
            fixture
                .remote
                .published
                .lock()
                .unwrap()
                .insert(record.candidates[0].seq, bytes);
        }
        let (scratch, io, remote, mut local) = fixture.reload_carrier();
        if ending.starts_with("archive-") {
            abandon_boundary(&mut local, &record);
        }
        let expected_before = if ending.starts_with("archive-") {
            RecoveryRule::BoundaryArchived
        } else {
            RecoveryRule::BoundaryRecorded
        };
        assert_eq!(local.recovery_rule().unwrap(), expected_before, "{ending}");
        let base = remote.published.lock().unwrap()[&1].clone();
        let mut untransferred = header();
        untransferred.writer = local.writer_uuid();
        untransferred.base_root = GrainId::of(&base);
        local
            .open_overlay(untransferred, vec![], &mut Source::default(), io.clone())
            .unwrap();
        let refused = crate::settle_recovery_boundary(
            &mut local,
            remote.as_ref(),
            &TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap(),
            None,
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(crate::RecoveryCommandError::Coordination(
                    CoordinationError::Refused("IntentFreshInstanceRequired")
                ))
            ),
            "{ending}: no action before this instance owns the grant: {refused:?}"
        );
        local = recover_boundary(local, &io, &remote);
        let keys =
            TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
        let probes = remote.probes.load(Ordering::Relaxed);
        let live_before = retained(&mut local);
        let overlay_before = local.recovery_commits().unwrap();
        let result =
            crate::settle_recovery_boundary(&mut local, remote.as_ref(), &keys, None).await;
        if ending.starts_with("archive-foreign") {
            assert_eq!(
                remote.probes.load(Ordering::Relaxed) - probes,
                if ending.ends_with("unfenced") { 5 } else { 1 },
                "{ending}: probe the archived set and verify an unfenced merge"
            );
        }
        let (refusal, expected_after) = match ending {
            "landed" => (None, RecoveryRule::LandedUnrefreshed),
            "archive-acknowledged-landed-unfenced" => (
                Some("intent refused: RecoveryArchivedLanded".to_owned()),
                RecoveryRule::BoundaryArchived,
            ),
            "empty" => (
                Some("intent refused: RecoveryUnresolved".to_owned()),
                RecoveryRule::BoundaryRecorded,
            ),
            _ => (None, RecoveryRule::DirtyJournal),
        };
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                local.recovery_rule().unwrap(),
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                refusal,
                expected_after,
                if ending.ends_with("unfenced") { 0 } else { 8 }
            ),
            "{ending}"
        );
        if ending == "archive-acknowledged-landed-unfenced" {
            assert_eq!(
                (
                    retained(&mut local),
                    local.recovery_commits().unwrap(),
                    remote.publication_sends.lock().unwrap().len(),
                ),
                (live_before, overlay_before, 0),
                "archived landing changed (live publication, overlay commits, publication sends)"
            );
        }
        if expected_after == RecoveryRule::DirtyJournal {
            let area =
                crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
            assert_eq!(
                io.bytes(&area.join("staging").join(format!("{stage:016x}")))
                    .get(160..),
                Some(b"sealed".as_slice())
            );
        }
        drop(local);
        io.crash();
        let mut reopened = start(&scratch, &io, 121);
        assert_eq!(
            reopened.recovery_rule().unwrap(),
            expected_after,
            "{ending}: restart"
        );
        cases += 1;
    }
    assert_eq!(cases, 9);
}

/// A commit stopped by the armed `sync.commit` point, after a first commit
/// landed when `landed_before`.
async fn cut_at(phase: &'static str, landed_before: bool) -> Fixture {
    let fixture = Fixture::new().await;
    authenticate_registration(&fixture).await;
    if landed_before {
        // Its own entropy, so its publication identity is not the next one's.
        fixture.create("first", b"landed");
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(69))
            .await
            .unwrap();
        Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(79),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
    }
    fixture.create("local", b"sealed");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", phase, 1, FaultAction::Fail);
    let error = first_commit_fault(&fixture, phase).await;
    assert!(
        error.is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
        "{phase}: the armed point stops the commit"
    );
    fixture
}

/// The refusal a classification is admitted with, or `None`.
fn admitted(rule: RecoveryRule) -> Option<&'static str> {
    match rule.admitted() {
        Ok(_) => None,
        Err(CoordinationError::Refused(name)) => Some(name),
        Err(error) => panic!("expected a named refusal: {error}"),
    }
}

/// The retained record's generation and completion, read without writing.
fn retained(local: &mut WritableStore<SimIo>) -> Option<(u64, bool)> {
    super::selected::retained(local).map(|record| (record.generation, record.is_complete()))
}

/// Answer each retained request from the fixture authority once, counting
/// the requests driven.
fn drive<'a>(
    remote: &'a Remote,
    driven: &'a Cell<usize>,
) -> impl FnMut(&mut WritableStore<SimIo>, &PendingIntent, bool) -> Result<(), crate::WritableStartError>
+ 'a {
    move |local, request, landed| {
        driven.set(driven.get() + 1);
        let at = 2_000_000;
        if landed {
            local.dispatch_landed_replay(request, &Tick(at))?;
        } else {
            local.dispatch(request, &Tick(at))?;
        }
        let answer = remote.authority.lock().unwrap().send(request);
        if landed {
            local.complete_landed_replay(
                request,
                Ok(&answer),
                &Tick(at + 1),
                &mut SeededRng::new(1),
                0,
                None,
            )?;
        } else {
            local.complete(
                request,
                Ok(&answer),
                &Tick(at + 1),
                &mut SeededRng::new(1),
                0,
                None,
            )?;
        }
        Ok(())
    }
}

/// Rule 1 and rule 2 on the stores the commit's own crash points leave: a
/// journalled landing without and with its refresh, and an open boundary
/// with its own incomplete record, then with that record archived.
#[tokio::test]
async fn commit_crash_points_land_in_their_open_boundary_rules() {
    let mut rows = Vec::new();
    for (phase, expected) in [
        ("landed_readback", RecoveryRule::LandedUnrefreshed),
        ("before_replace", RecoveryRule::LandedRefreshed),
        ("before_rebase", RecoveryRule::BoundaryRecorded),
    ] {
        let fixture = cut_at(phase, false).await;
        let (_scratch, _io, _remote, mut local) = fixture.reload_carrier();
        let before = retained(&mut local);
        let rule = local.recovery_rule().unwrap();
        rows.push((
            phase,
            rule == expected,
            admitted(rule),
            retained(&mut local) == before,
        ));
    }
    let fixture = cut_at("before_rebase", false).await;
    let (_scratch, _io, _remote, mut local) = fixture.reload_carrier();
    let scope = local.snapshot().scope.clone();
    let volume = local.snapshot().volume.clone();
    local
        .publication_transaction(|store| {
            let id = store.observe(&scope, &volume)?.unwrap().publication_id;
            store.abandon(
                &scope,
                &volume,
                id,
                crate::MayLandAcknowledgement::Acknowledged,
            )?;
            Ok(())
        })
        .unwrap();
    let rule = local.recovery_rule().unwrap();
    rows.push((
        "archived",
        rule == RecoveryRule::BoundaryArchived,
        admitted(rule),
        retained(&mut local).is_none(),
    ));
    let refused = Some("WritableRecoveryRequired");
    assert_eq!(
        rows,
        [
            ("landed_readback", true, refused, true),
            ("before_replace", true, refused, true),
            ("before_rebase", true, refused, true),
            ("archived", true, refused, true),
        ],
        "(cut, the rule expected, admitted refusal, record unchanged by placing it)"
    );
}

/// The cut between recording a boundary and beginning its record, on a
/// store whose previous commit landed: the earlier commit's completed record
/// is not the boundary's, so the store is rule 2b unfenced.
#[tokio::test]
async fn boundary_recorded_beside_a_landed_commits_record_is_rule_two_b() {
    let fixture = cut_at("boundary_recorded", true).await;
    let (_scratch, _io, _remote, mut local) = fixture.reload_carrier();
    let before = retained(&mut local);
    let rule = local.recovery_rule().unwrap();
    assert_eq!(
        (
            before.map(|(_, complete)| complete),
            rule,
            admitted(rule),
            retained(&mut local) == before,
        ),
        (
            Some(true),
            RecoveryRule::BoundaryUnrecorded,
            Some("WritableRecoveryRequired"),
            true,
        ),
        "(earlier record complete, rule, admitted refusal, record unchanged)"
    );
}

/// No commit fault point leaves these two rule-2 shapes, so the fixture
/// builds them directly: its own record is completed beside its still-open
/// boundary, and an unrelated incomplete record is begun beside a new
/// boundary after an earlier completion.
#[tokio::test]
async fn directly_built_rule_two_complete_and_unaccounted_states_refuse_by_name() {
    let complete = cut_at("before_rebase", false).await;
    let (_scratch, _io, _remote, mut complete) = complete.reload_carrier();
    let scope = complete.snapshot().scope.clone();
    let volume = complete.snapshot().volume.clone();
    complete
        .publication_transaction(|store| {
            let mut record = store.observe(&scope, &volume)?.unwrap();
            let expected = record.generation;
            let candidate = record.candidates.first_mut().unwrap();
            let attempt = candidate.evidence.start().unwrap();
            candidate.evidence.answer(attempt, false, true).unwrap();
            let completion = granary_core::retained_submission::Completion {
                seq: candidate.seq,
                id: candidate.id,
                root: candidate.root.clone(),
                receipt: None,
            };
            record.generation += 1;
            record.current = None;
            record.phase = granary_core::retained_submission::Phase::Complete(completion);
            store.replace(expected, &record)
        })
        .unwrap();
    let complete_rule = complete.recovery_rule().unwrap();

    let unaccounted = cut_at("boundary_recorded", true).await;
    let root = unaccounted
        .remote
        .published
        .lock()
        .unwrap()
        .get(&1)
        .unwrap()
        .clone();
    let foreign = fixture_submission(&unaccounted, root);
    let (_scratch, _io, _remote, mut unaccounted) = unaccounted.reload_carrier();
    unaccounted
        .publication_transaction(|store| store.begin(&foreign))
        .unwrap();
    let unaccounted_rule = unaccounted.recovery_rule().unwrap();

    assert_eq!(
        (
            complete_rule,
            admitted(complete_rule),
            unaccounted_rule,
            admitted(unaccounted_rule),
        ),
        (
            RecoveryRule::BoundaryComplete,
            Some("WritableRecoveryRequired"),
            RecoveryRule::BoundaryUnaccounted,
            Some("SyncCommitRecoveryRequired"),
        ),
        "(direct complete rule and refusal, direct unaccounted rule and refusal)"
    );
}

/// The prologue's landed replay is already past its deadline and readback
/// reports the exact refresh row. It settles from readback without sending,
/// advances the carrier to the landed root, and still refuses the open
/// boundary by rule 1a.
#[test]
fn settle_expired_landed_replay_prologue_arm_advances_without_a_send() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let fixture = runtime.block_on(cut_at("landed_refresh", false));
    let (_scratch, _io, remote, mut local) = fixture.reload_carrier();
    let replay = local.landed_replay().unwrap().unwrap();
    let expires = replay.expires();
    let sent = intent::decode_register(
        replay.request().bytes(),
        replay.request().volume(),
        |_, _| true,
    )
    .unwrap();
    let landed = sent.root.to_vec();
    local
        .dispatch_landed_replay(replay.request(), &Tick(2_000_000))
        .unwrap();
    // The refresh reached the authority; only its answer was lost. The
    // retry is eligible exactly at expiry, so the next action is readback.
    remote.authority.lock().unwrap().send(replay.request());
    local
        .complete_landed_replay(
            replay.request(),
            Err(IntentTransportError::Transport),
            &Tick(2_000_001),
            &mut SeededRng::new(1),
            expires,
            None,
        )
        .unwrap();
    let eligible = local
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.body == replay.request().bytes())
        .map(|pending| pending.eligible);
    assert_eq!(
        eligible,
        Some(expires),
        "retry eligibility at expiry: {eligible:?}"
    );
    let sends = remote.authority.lock().unwrap().sends.len();
    let scope = local.snapshot().scope.clone();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let settled = crate::recovery_prologue(
        &mut local,
        remote.as_ref(),
        &runtime,
        &scope,
        key.public_key(),
        &Tick(expires),
        &mut SeededRng::new(1),
    )
    .map_err(|error| error.to_string());
    let sends = remote.authority.lock().unwrap().sends.len() - sends;
    let rule = local.recovery_rule().unwrap();
    assert_eq!(
        (
            settled,
            sends,
            local.landed_replay().unwrap().is_none(),
            local.snapshot().root == landed,
            rule,
            admitted(rule),
        ),
        (
            Ok(()),
            0,
            true,
            true,
            RecoveryRule::LandedUnrefreshed,
            Some("WritableRecoveryRequired"),
        ),
        "(prologue result, sends, replay cleared, root advanced, rule, refusal)"
    );
}

/// Arm 1: the prologue answers the retained landed refresh, so the carrier
/// registers the landed root; the journal records the refresh only once an
/// overlay replays it, so the store stays rule 1a, refused by name. Arm
/// 2: the refresh is answered by a displacement, the prologue keeps the
/// fenced carrier, and rule 0 reports the landing; a re-run on the fenced
/// carrier drives nothing and reports it again.
#[tokio::test]
async fn prologue_settles_the_landed_refresh_and_rule_zero_reports_a_displaced_one() {
    let events = super::selected::Events::default();
    let _events = events.guard();
    let fixture = cut_at("landed_refresh", false).await;
    let landed = fixture.remote.published.lock().unwrap()[&2].clone();
    let (_scratch, _io, remote, mut local) = fixture.reload_carrier();
    let driven = Cell::new(0);
    let settled = crate::writable_start::settle_recovery(
        &mut local,
        &Tick(2_000_000),
        drive(&remote, &driven),
    );
    let rule = local.recovery_rule().unwrap();
    let accepted = (
        settled.map_err(|error| error.to_string()),
        driven.get(),
        local.snapshot().root == landed,
        local.landed_refresh_registered(&landed, false).unwrap(),
        rule,
        admitted(rule),
    );

    let fixture = cut_at("landed_refresh", false).await;
    {
        let mut authority = fixture.remote.authority.lock().unwrap();
        authority.row = authority.row.map(|row| Receipt {
            epoch: row.epoch + 1,
            ..row
        });
    }
    let (scratch, io, remote, mut local) = fixture.reload_carrier();
    let driven = Cell::new(0);
    let settled = crate::writable_start::settle_recovery(
        &mut local,
        &Tick(2_000_000),
        drive(&remote, &driven),
    );
    let rule = local.recovery_rule().unwrap();
    let displaced = (
        settled.map_err(|error| error.to_string()),
        driven.get(),
        local.snapshot().phase,
        rule,
        admitted(rule),
    );
    drop(local);
    io.crash();
    let mut rerun = start(&scratch, &io, 140);
    let sends = remote.authority.lock().unwrap().sends.len();
    let driven = Cell::new(0);
    let settled = crate::writable_start::settle_recovery(
        &mut rerun,
        &Tick(2_000_010),
        drive(&remote, &driven),
    );
    let rule = rerun.recovery_rule().unwrap();
    let rerun = (
        settled.map_err(|error| error.to_string()),
        driven.get() + remote.authority.lock().unwrap().sends.len() - sends,
        rerun.snapshot().phase,
        rule,
        admitted(rule),
    );
    assert_eq!(
        events.recover(),
        ["landed_unowned", "landed_unowned"],
        "rule 0 reports the displaced landing on the run and its re-run"
    );
    assert_eq!(
        (accepted, displaced, rerun),
        (
            (
                Ok(()),
                1,
                true,
                true,
                RecoveryRule::LandedUnrefreshed,
                Some("WritableRecoveryRequired"),
            ),
            (
                Ok(()),
                1,
                Phase::Fenced,
                RecoveryRule::LandedUnowned,
                Some("RecoveryLandedUnowned"),
            ),
            (
                Ok(()),
                0,
                Phase::Fenced,
                RecoveryRule::LandedUnowned,
                Some("RecoveryLandedUnowned"),
            ),
        ),
        "accepted (settled, driven, root is L, refresh registered, rule, refusal); \
         displaced and its re-run (settled, driven, phase, rule, refusal)"
    );
}

impl crate::MountMetrics for Remote {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics> {
        None
    }
}
impl crate::WritableAuthority for Remote {
    fn read_facade(&self) -> Self {
        Self {
            offline: AtomicBool::new(self.offline.load(Ordering::Relaxed)),
            root_reads: self.root_reads.clone(),
            unavailable_parent_read: AtomicU64::new(
                self.unavailable_parent_read.load(Ordering::Relaxed),
            ),
            corrupt_probe: AtomicU64::new(self.corrupt_probe.load(Ordering::Relaxed)),
            recovery_reads: AtomicU64::new(0),
            recovery_read_delay: AtomicU64::new(0),
            recovery_sends: AtomicU64::new(0),
            change_selection: AtomicBool::new(false),
            supersede_selection: AtomicBool::new(false),
            forget_selection: AtomicBool::new(false),
            readback_failure: Mutex::new(None),
            objects: self.objects.clone(),
            authority: self.authority.clone(),
            time: self.time.clone(),
            hold_first: self.hold_first.clone(),
            unknown: self.unknown.clone(),
            hold_upload: AtomicBool::new(false),
            hold_meta: AtomicBool::new(false),
            panic_register: AtomicBool::new(false),
            panic_status: AtomicBool::new(false),
            fail_status: AtomicBool::new(false),
            entered: self.entered.clone(),
            release: self.release.clone(),
            upload_entered: Notify::new(),
            upload_release: Notify::new(),
            attempts: self.attempts.clone(),
            published: self.published.clone(),
            publication_plan: self.publication_plan.clone(),
            publication_sends: self.publication_sends.clone(),
            publication_operations: self.publication_operations.clone(),
            publication_observer: Mutex::default(),
            publish_hold: crate::overlay_store::tests::publish_hold::PublishHold::default(),
            probes: AtomicU64::new(0),
            probe_delay: Mutex::new(None),
            failed_probe: AtomicU64::new(0),
            listing_fault: Mutex::new(None),
            root_probe_fault: Mutex::new(None),
            post_listing_probe: self.post_listing_probe.inherit(),
        }
    }
    async fn writable_status(&self, _: &VolumeName) -> Result<StatusResponse, AuthorityError> {
        self.status_once("v").await
    }
    async fn writable_readback(
        &self,
        _: &granary_core::retained_submission::Scope,
        _: &VolumeName,
        _: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        self.recovery_reads.fetch_add(1, Ordering::Relaxed);
        crate::TokioSyncRuntime
            .sleep(Duration::from_secs(
                self.recovery_read_delay.load(Ordering::Relaxed),
            ))
            .await;
        if let Some(error) = *self.readback_failure.lock().unwrap() {
            return Err(error);
        }
        let mut authority = self.authority.lock().unwrap();
        let rows = authority
            .row
            .into_iter()
            .filter_map(|row| {
                matches!(row.state, ReceiptState::Live { .. }).then_some(intent::ReadbackRow {
                    writer: row.writer,
                    epoch: row.epoch,
                    generation: row.generation,
                    root: &authority.root,
                })
            })
            .collect::<Vec<_>>();
        let response = reply(
            200,
            None,
            Some(intent::MEDIA_READBACK),
            intent::encode_readback(authority.cursor, &rows).unwrap(),
        );
        if self.change_selection.swap(false, Ordering::Relaxed) {
            authority.row.as_mut().unwrap().generation += 1;
        }
        if self.supersede_selection.swap(false, Ordering::Relaxed) {
            authority.cursor += 1;
            let row = authority.row.as_mut().unwrap();
            row.epoch += 1;
            row.instance = [99; 16];
        }
        if self.forget_selection.swap(false, Ordering::Relaxed) {
            authority.row = None;
        }
        Ok(response)
    }
    async fn writable_send(
        &self,
        _: &granary_core::retained_submission::Scope,
        request: &PendingIntent,
        _: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        self.recovery_sends.fetch_add(1, Ordering::Relaxed);
        Ok(self.authority.lock().unwrap().send(request))
    }
    async fn writable_wait(&self, _: u64) {
        panic!("prologue rows do not wait")
    }
}

/// A prior landed commit is settled; the newer boundary has no landing.
/// Neither the old landing nor its missing refresh belongs to that boundary.
#[tokio::test]
async fn earlier_landing_does_not_classify_a_newer_open_boundary() {
    let mut rows = Vec::new();
    for fenced in [false, true] {
        let fixture = cut_at("boundary_recorded", true).await;
        fixture.io.mutate_recovered("journal", |bytes| {
            let scan = granary_core::overlay_journal::scan_journal(bytes).unwrap();
            let h = scan.header;
            let records = [
                Record::CommitBoundary {
                    candidate: grain(70),
                    through_seq: 0,
                    publication_id: [71; 16],
                },
                Record::LandedCommit {
                    boundary_seq: 1,
                    landed_root: grain(72),
                    landed_seq: h.base_seq + 1,
                },
                Record::CommitBoundary {
                    candidate: grain(73),
                    through_seq: 2,
                    publication_id: [74; 16],
                },
            ];
            let mut records = records.to_vec();
            if fenced {
                records.push(Record::CommitFence {
                    boundary_seq: 3,
                    publication_id: [74; 16],
                });
            }
            *bytes = granary_core::overlay_journal::encode_journal(&h, &records).unwrap();
        });
        let (scratch, io, _remote, mut local) = fixture.reload_carrier();
        let rule = local.recovery_rule().unwrap();
        rows.push((fenced, false, rule, admitted(rule)));
        let mut carrier = local.snapshot().clone();
        carrier.phase = Phase::Fenced;
        carrier.fence = 2;
        drop(local);
        io.mutate_recovered("ownership", |bytes| {
            *bytes = granary_core::overlay_ownership::encode(&carrier).unwrap();
        });
        io.crash();
        let mut local = start(&scratch, &io, 141);
        let rule = local.recovery_rule().unwrap();
        rows.push((fenced, true, rule, admitted(rule)));
    }
    assert_eq!(
        rows,
        [
            (
                false,
                false,
                RecoveryRule::BoundaryUnrecorded,
                Some("WritableRecoveryRequired")
            ),
            (
                false,
                true,
                RecoveryRule::OwnershipLost,
                Some("IntentSelectedWriterMissing")
            ),
            (
                true,
                false,
                RecoveryRule::BoundaryUnaccounted,
                Some("SyncCommitRecoveryRequired")
            ),
            (
                true,
                true,
                RecoveryRule::OwnershipLost,
                Some("IntentSelectedWriterMissing")
            ),
        ],
        "(boundary fenced, carrier fenced, rule, refusal); four cases ran"
    );
    assert!(!rows.is_empty());
}
