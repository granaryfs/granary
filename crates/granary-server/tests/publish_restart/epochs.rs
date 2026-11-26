// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Epoch loss and credential rotation with externally retained signed PUTs.
use std::fmt::Write as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;

use granary_core::authlog::{self, Classified, Epoch, RecordBody};
use granary_core::authority_answer::{self as answer, Position, PublishAnswer};
use granary_core::enrollment::TenantName;
use granary_core::retained_submission::{Candidate, Completion, Evidence, Phase, Role, Submission};
use granary_core::root::VolumeName;
use granary_core::runmarker::{RunMarker, decode_marker};
use granary_net::secure_random::OsSecureRandom;
use granary_server::{EnrollmentReader, Lookup, VerbOptions, attach, mint, revoke};
use rustls_pki_types::pem::PemObject as _;
use std::sync::Arc;
use tokio::io::AsyncWriteExt as _;
use tokio::time::{sleep, timeout};

use super::backend::Identity;
use super::composition::{Composition, report, report_candidate};
use super::oracle::{self, RequestClass, RequestClass::*};
use super::support::{Process, ROOT_PATH, Rendezvous, WAIT, assert_exit, hex, wait_report};
use super::tails::{accepted, diagnostics, exact, interrupted, stages};

fn recover(fx: &Composition, record: &Submission) -> Command {
    let mut command = fx.client.command(true);
    command.args(["--recover", &hex(&record.publication_id)]);
    command
}

async fn cut_client(
    fx: &Composition,
    mut command: Command,
    cut: &str,
    occurrence: u64,
) -> (Submission, String) {
    let rendezvous = Rendezvous::arm(&mut command, &fx.client.scratch.0, cut, "after", occurrence);
    let mut process = Process::spawn(&mut command);
    let reached = rendezvous.reached(&mut process).await;
    if matches!(&reached, Err(error) if error.contains("child exit")) {
        let output = process.output().await;
        let diagnostic = diagnostics(&output);
        let record = fx
            .client
            .record()
            .unwrap_or_else(|| panic!("no durable state\n{diagnostic}"));
        assert!(
            fresh_operation(&record, epoch(fx)),
            "epoch recovery must durably install a fresh current-epoch operation\n{record:?}\n{diagnostic}"
        );
        panic!("client exited before {cut}\n{record:?}\n{diagnostic}");
    }
    process.assert_or_kill(reached.is_ok(), &format!("{cut}: {reached:?}"));
    let (event, _stream) = reached.unwrap();
    let output = process.kill().await;
    let diagnostic = diagnostics(&output);
    let record = fx
        .client
        .record()
        .unwrap_or_else(|| panic!("no retained state\n{diagnostic}"));
    assert_eq!(
        (output.status.signal(), event.id, event.generation),
        (Some(9), hex(&record.publication_id), record.generation),
        "durable client cut {cut}\n{record:?}\n{diagnostic}"
    );
    (record, diagnostic)
}

fn fresh_operation(record: &Submission, epoch: Epoch) -> bool {
    record.current.is_some_and(|current| {
        current.epoch == epoch.to_bytes()
            && record.candidates.iter().all(|candidate| {
                candidate.request.epoch == current.epoch
                    || candidate.request.operation != current.operation
            })
    })
}

pub(super) fn operation_failure_controls() {
    epoch_mismatch_controls();
    refusal_mismatch_controls();
    let mut record = granary_core::retained_submission::decode(include_bytes!(
        "../../../granary-core/tests/vectors/retained-submission/ready.bin"
    ))
    .unwrap();
    let current = record.current.unwrap();
    let epoch = Epoch::from_bytes(current.epoch);
    assert!(fresh_operation(&record, epoch));
    record.current = None;
    assert!(
        !fresh_operation(&record, epoch),
        "missing operation accepted"
    );
    record.current = Some(current);
    assert!(
        !fresh_operation(&record, Epoch::from_bytes([0x77; 16])),
        "old epoch operation accepted"
    );
    record.candidates[0].request.epoch[0] ^= 1;
    assert!(
        !fresh_operation(&record, epoch),
        "cross-epoch operation reuse accepted"
    );
    record.current.as_mut().unwrap().operation[0] ^= 1;
    assert!(fresh_operation(&record, epoch));
}

fn epoch(fx: &Composition) -> Epoch {
    match authlog::classify(
        &std::fs::read(fx.state.join("alpha.log")).unwrap(),
        &VolumeName::new("alpha".into()).unwrap(),
    )
    .unwrap()
    {
        Classified::Log {
            envelope,
            tail_len: 0,
            ..
        } => envelope.epoch(),
        other => panic!("incomplete epoch log: {other:?}"),
    }
}

async fn initialise_next(
    fx: &mut Composition,
    capture: Option<&Identity>,
    name: &str,
    diagnostic: &str,
) -> Epoch {
    let old_epoch = epoch(fx);
    let old_log = std::fs::read(fx.state.join("alpha.log")).unwrap();
    fx.signal_stop();
    let path = fx.client.scratch.0.join("stop-requested");
    let reached = wait_report(fx.host.as_mut().unwrap(), WAIT, async {
        while !path.exists() {
            sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    })
    .await;
    fx.host.as_mut().unwrap().assert_or_kill(
        reached.is_ok(),
        &format!("polled clean stop: {reached:?}\n{diagnostic}"),
    );
    if let Some(capture) = capture {
        assert_eq!(
            fx.proxy.detach(capture).await,
            Ok(()),
            "retain signed PUT after issuer stop\n{diagnostic}"
        );
    }
    let output = fx.host.take().unwrap().host_output().await;
    assert_exit(&output, 0);
    assert_eq!(
        (
            decode_marker(&std::fs::read(fx.state.join("MARKER")).unwrap()).unwrap(),
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            fx.roots().await
        ),
        (RunMarker::Clean, old_log, vec![]),
        "clean stop must precede explicit log loss\n{diagnostic}\n{}",
        diagnostics(&output)
    );
    // Preserve old committed history outside the disposable authority directory.
    // Normal initialization creates the missing log and cancels no captured PUT.
    std::fs::rename(fx.state.join("alpha.log"), fx.client.scratch.0.join(name)).unwrap();
    fx.start(false);
    fx.ready().await;
    let new_epoch = epoch(fx);
    assert_ne!(
        new_epoch, old_epoch,
        "initialise reused the lost epoch\n{diagnostic}"
    );
    assert_eq!(
        fx.records(),
        [],
        "initialization installed a decision\n{diagnostic}"
    );
    new_epoch
}

fn intent(before: &Submission, after: &Submission, diagnostic: &str) {
    assert_eq!(
        (
            &after.scope,
            &after.volume,
            after.publication_id,
            &after.frozen
        ),
        (
            &before.scope,
            &before.volume,
            before.publication_id,
            &before.frozen
        ),
        "frozen publication changed\n{diagnostic}"
    );
}

fn retired(candidate: &Candidate, evidence: Evidence) -> Candidate {
    let mut expected = candidate.clone();
    expected.role = Role::Retired;
    expected.evidence = evidence;
    expected
}

fn mismatched(record: &Submission, epoch: Epoch, candidate: u64, diagnostic: &str) -> String {
    let response = record
        .last_response
        .as_ref()
        .unwrap_or_else(|| panic!("missing real epoch mismatch\n{diagnostic}"));
    let decoded = answer::decode(&response.answer).unwrap();
    let expected = PublishAnswer::EpochMismatch {
        epoch,
        head: Some(answer::Head::new(None)),
    };
    assert_eq!(
        (
            response.candidate,
            response.status,
            response.token.as_slice(),
            decoded
        ),
        (candidate, 409, b"epoch-mismatch".as_slice(), expected),
        "checked real epoch mismatch for the empty slot: {response:?}\n{diagnostic}"
    );
    response_line(409, "epoch-mismatch", &answer::encode(expected).unwrap())
}

fn mismatch_before_acceptance(
    record: &Submission,
    epoch: Epoch,
    responses: &str,
) -> Result<String, String> {
    let candidate = record
        .candidates
        .last()
        .ok_or_else(|| "missing replacement candidate".to_owned())?;
    let mismatch = response_line(
        409,
        "epoch-mismatch",
        &answer::encode(PublishAnswer::EpochMismatch {
            epoch,
            head: Some(answer::Head::new(None)),
        })
        .unwrap(),
    );
    let accepted = response_line(
        202,
        "-",
        &answer::encode(PublishAnswer::Accepted {
            position: Position {
                epoch,
                entry_seq: 1,
            },
            candidate_id: candidate.id,
        })
        .unwrap(),
    );
    let posts: Vec<_> = responses
        .lines()
        .filter(|line| line.starts_with("POST "))
        .collect();
    if (
        record.last_response.is_none(),
        &record.phase,
        candidate.request.epoch,
        posts,
    ) != (
        true,
        &Phase::AwaitingAnswer {
            candidate: candidate.number,
            attempt: candidate.evidence.started,
        },
        epoch.to_bytes(),
        vec![mismatch.as_str(), accepted.as_str()],
    ) {
        return Err(format!(
            "checked real epoch mismatch before B's acceptance\n{record:?}\n{responses}"
        ));
    }
    Ok(mismatch)
}

fn epoch_mismatch_controls() {
    let record = granary_core::retained_submission::decode(include_bytes!(
        "../../../granary-core/tests/vectors/retained-submission/awaiting.bin"
    ))
    .unwrap();
    assert!(record.last_response.is_none());
    let epoch = Epoch::from_bytes(record.candidates.last().unwrap().request.epoch);
    let mismatch = response_line(
        409,
        "epoch-mismatch",
        &answer::encode(PublishAnswer::EpochMismatch {
            epoch,
            head: Some(answer::Head::new(None)),
        })
        .unwrap(),
    );
    let accepted = accepted(&record);
    let responses = format!("{mismatch}\nGET {ROOT_PATH} 404 - \n{accepted}\n");
    assert_eq!(
        mismatch_before_acceptance(&record, epoch, &responses),
        Ok(mismatch.clone()),
        "real mismatch must remain observable after the next attempt cleared LastResponse"
    );
    for (name, altered) in [
        ("empty", String::new()),
        ("absent", format!("{accepted}\n")),
        ("status", responses.replacen(" 409 ", " 503 ", 1)),
        (
            "token",
            responses.replacen(" epoch-mismatch ", " not-decided ", 1),
        ),
        (
            "body",
            format!("POST /volume/alpha/publish 409 epoch-mismatch ff\n{accepted}\n"),
        ),
        (
            "head",
            format!(
                "{}\n{accepted}\n",
                response_line(
                    409,
                    "epoch-mismatch",
                    &answer::encode(PublishAnswer::EpochMismatch { epoch, head: None }).unwrap(),
                )
            ),
        ),
        (
            "acceptance",
            responses.replace(&accepted, &accepted.replace(" 202 ", " 409 ")),
        ),
        ("order", format!("{accepted}\n{mismatch}\n")),
        ("extra", format!("{mismatch}\n{responses}")),
    ] {
        assert!(
            mismatch_before_acceptance(&record, epoch, &altered).is_err(),
            "{name} mismatch transcript accepted: {altered}"
        );
    }
    assert!(
        mismatch_before_acceptance(&record, Epoch::from_bytes([0x77; 16]), &responses).is_err(),
        "another epoch's mismatch accepted"
    );
}

fn response_line(status: u16, token: &str, body: &[u8]) -> String {
    format!("POST /volume/alpha/publish {status} {token} {}", hex(body))
}

fn refusal_mismatch_line(epoch: Epoch) -> String {
    response_line(
        409,
        "epoch-mismatch",
        &answer::encode(PublishAnswer::EpochMismatch {
            epoch,
            head: Some(answer::Head::new(None)),
        })
        .unwrap(),
    )
}

fn refusal_mismatch_controls() {
    let epoch = Epoch::from_bytes([0x77; 16]);
    let canonical = response_line(
        409,
        "epoch-mismatch",
        &answer::encode(PublishAnswer::EpochMismatch {
            epoch,
            head: Some(answer::Head::new(None)),
        })
        .unwrap(),
    );
    let check =
        |observed: &str| std::panic::catch_unwind(|| observed == refusal_mismatch_line(epoch));
    assert!(check(&canonical).unwrap());
    for (name, altered) in [
        (
            "truncated",
            canonical.get(..canonical.len() - 1).unwrap().to_owned(),
        ),
        ("odd nibble", format!("{canonical}a")),
        (
            "empty body",
            "POST /volume/alpha/publish 409 epoch-mismatch ".to_owned(),
        ),
    ] {
        let observed = check(&altered);
        assert!(
            matches!(observed, Ok(false)),
            "{name} mismatch body must be refused without panicking: {observed:?}"
        );
    }
}

fn trace(
    fx: &Composition,
    before: &str,
    counts: (usize, usize, usize, usize),
    order: Vec<(RequestClass, String)>,
    diagnostic: &str,
) {
    let responses = fx.responses();
    let suffix = responses
        .strip_prefix(before)
        .unwrap_or_else(|| panic!("tap prefix changed\n{responses}\n{diagnostic}"));
    assert_eq!(
        oracle::request_trace(suffix),
        Ok((counts, order)),
        "exact request classes/counts/order\n{suffix}\n{diagnostic}"
    );
}

struct EmptyEpochSchedule {
    fx: Composition,
    a: Submission,
    capture_a: Identity,
    capture_b: Identity,
    empty: Submission,
}

async fn empty_epoch_schedule() -> EmptyEpochSchedule {
    let mut fx = Composition::new(false).await;
    let (a, capture_a, diagnostic_a) = interrupted(&fx).await;
    let e1 = initialise_next(&mut fx, Some(&capture_a), "late-a-e0.log", &diagnostic_a).await;
    let (b, diagnostic_b) = cut_client(&fx, recover(&fx, &a), "dispatch", 2).await;
    let capture_b = fx
        .proxy
        .captured_matching(b.candidates.last().unwrap().id)
        .await;
    intent(&a, &b, &diagnostic_b);
    assert_eq!(
        (
            b.candidates.len(),
            b.candidates.last().unwrap().request.epoch
        ),
        (2, e1.to_bytes()),
        "E1 replacement must retain A before the second initialization\n{b:?}\n{diagnostic_b}"
    );
    let e2 = initialise_next(&mut fx, Some(&capture_b), "late-a-e1.log", &diagnostic_b).await;
    let (second, diagnostic_second) = cut_client(&fx, recover(&fx, &b), "epoch-save", 1).await;
    intent(&a, &second, &diagnostic_second);
    assert!(matches!(
        second.phase,
        Phase::EpochRecovery { epoch } if epoch == e2.to_bytes()
    ));
    let (empty, diagnostic_empty) = cut_client(&fx, recover(&fx, &second), "probe-result", 1).await;
    intent(&a, &empty, &diagnostic_empty);
    assert_eq!(
        (&empty.phase, fx.roots().await, fx.proxy.pending()),
        (&Phase::Rebase, vec![], 2),
        "schedule must hold both old candidates after the empty E2 probe\n{empty:?}\n{diagnostic_empty}"
    );
    EmptyEpochSchedule {
        fx,
        a,
        capture_a,
        capture_b,
        empty,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one delayed-write schedule verifies both create-only completion orders"
)]
async fn release_late_a_after_rebase(b_lands_first: bool) {
    let EmptyEpochSchedule {
        mut fx,
        a,
        capture_a,
        capture_b,
        empty,
    } = empty_epoch_schedule().await;
    let mut command = recover(&fx, &empty);
    let rendezvous = Rendezvous::arm(
        &mut command,
        &fx.client.scratch.0,
        "replacement-save",
        "after",
        1,
    );
    let mut process = Process::spawn(&mut command);
    let reached = rendezvous.reached(&mut process).await;
    process.assert_or_kill(
        reached.is_ok(),
        &format!("replacement-save rendezvous: {reached:?}"),
    );
    let (event, mut stream) = reached.unwrap();
    let rebased = fx
        .client
        .record()
        .unwrap_or_else(|| panic!("missing client state at replacement-save: {event:?}"));
    let diagnostic_rebase = format!("replacement-save rendezvous: {event:?}\n{rebased:?}");
    let publication_id = hex(&rebased.publication_id);
    assert_eq!(
        (event.id.as_str(), event.generation, event.phase.as_str()),
        (publication_id.as_str(), rebased.generation, "ready"),
        "same live client must be held at replacement-save\n{diagnostic_rebase}"
    );
    intent(&a, &rebased, &diagnostic_rebase);
    let replacement = rebased.candidates.last().unwrap().clone();
    assert_eq!(
        (rebased.phase.clone(), replacement.request.epoch),
        (Phase::Ready, epoch(&fx).to_bytes()),
        "replacement-save is after head resolution and before its PUT\n{rebased:?}\n{diagnostic_rebase}"
    );
    assert_ne!(replacement.id, a.candidates[0].id);

    if !b_lands_first {
        assert_eq!(
            (
                fx.proxy.release(&capture_a).await,
                fx.proxy.release(&capture_b).await
            ),
            (Ok(200), Ok(412)),
            "late A must land before the rebased candidate PUT\n{diagnostic_rebase}"
        );
    }

    let before = fx.responses();
    stream.write_all(b"continue\n").await.unwrap();
    if b_lands_first {
        let capture_replacement = fx.proxy.captured_matching(replacement.id).await;
        assert_eq!(
            fx.proxy.body(&capture_replacement),
            replacement.root,
            "rebased candidate PUT bytes changed\n{diagnostic_rebase}"
        );
        // The captured E2 PUT has reached MinIO and is released successfully
        // before the delayed E0 PUT is allowed to complete.
        assert_eq!(
            fx.proxy.release(&capture_replacement).await,
            Ok(200),
            "rebased candidate must land before delayed A\n{diagnostic_rebase}"
        );
        assert_eq!(
            (
                fx.proxy.release(&capture_a).await,
                fx.proxy.release(&capture_b).await
            ),
            (Ok(412), Ok(412)),
            "late A and the other retired candidate must lose create-only\n{diagnostic_rebase}"
        );
    }
    let output = process.output().await;
    let diagnostic = diagnostics(&output);
    if !b_lands_first {
        assert_eq!(
            fx.proxy.pending(),
            0,
            "B must not issue a PUT after late A has landed\n{diagnostic}"
        );
    }
    let winner = if b_lands_first {
        &replacement
    } else {
        &a.candidates[0]
    };
    report_candidate(&output, 0, &rebased, "landed", winner);
    let complete = fx
        .client
        .record()
        .unwrap_or_else(|| panic!("missing race completion\n{diagnostic}"));
    intent(&rebased, &complete, &diagnostic);
    assert_eq!(
        complete
            .candidates
            .iter()
            .map(|candidate| (candidate.id, candidate.seq, candidate.root.as_slice()))
            .collect::<Vec<_>>(),
        rebased
            .candidates
            .iter()
            .map(|candidate| (candidate.id, candidate.seq, candidate.root.as_slice()))
            .collect::<Vec<_>>(),
        "completion must preserve every retained candidate identity\n{complete:?}\n{diagnostic}"
    );
    assert_eq!(
        &complete.phase,
        &Phase::Complete(Completion {
            seq: winner.seq,
            id: winner.id,
            root: winner.root.clone(),
            receipt: None,
        }),
        "client must report the unique create-only winner as landed\n{complete:?}\n{diagnostic}"
    );
    assert_eq!(
        fx.roots().await,
        [(winner.seq, winner.root.clone())],
        "the delayed race must create exactly one root\n{diagnostic}"
    );
    let responses = fx.responses();
    let suffix = responses
        .strip_prefix(&before)
        .unwrap_or_else(|| panic!("response prefix changed\n{responses}\n{diagnostic}"));
    assert!(
        !suffix.is_empty(),
        "client completion must be driven through the composed gateway\n{diagnostic}"
    );
    assert_eq!(
        fx.proxy.pending(),
        0,
        "a delayed PUT remained held\n{diagnostic}"
    );
    fx.stop().await;
}

fn probe_post() -> Vec<(RequestClass, String)> {
    vec![
        (Recovery, format!("GET {ROOT_PATH}")),
        (Preparation, "GET /volume/alpha/max-seq".into()),
        (Publication, "POST /volume/alpha/publish".into()),
    ]
}

async fn finish(fx: &Composition, old: &Submission, explicit: bool) -> String {
    let before = fx.responses();
    let mut command = if explicit {
        recover(fx, old)
    } else {
        fx.client.command(true)
    };
    let output = Process::spawn(&mut command).output().await;
    let diagnostic = diagnostics(&output);
    report(&output, 0, old, "landed");
    let complete = fx
        .client
        .record()
        .unwrap_or_else(|| panic!("no Complete record\n{diagnostic}"));
    intent(old, &complete, &diagnostic);
    let a = &old.candidates[0];
    assert_eq!(
        (&complete.candidates, complete.current, &complete.phase),
        (
            &old.candidates,
            None,
            &Phase::Complete(Completion {
                seq: a.seq,
                id: a.id,
                root: a.root.clone(),
                receipt: None
            })
        ),
        "owned A completion must preserve both tuples and identify A, never prepared B\n{complete:?}\n{diagnostic}"
    );
    trace(
        fx,
        &before,
        (0, 1, 1, 1),
        vec![
            (Recovery, format!("GET {ROOT_PATH}")),
            (Preparation, "GET /volume/alpha/max-seq".into()),
            (Hint, "PUT /volume/alpha/hint".into()),
        ],
        &diagnostic,
    );
    diagnostic
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one schedule pins both retired identities across two real initializations"
)]
async fn two_epoch_changes_keep_both_candidates_and_complete_with_a() {
    // Loss is the existing dispatch-after cut, after a real checked Accepted.
    // Captured PUTs survive the clean issuer stops needed for explicit log loss.
    let mut fx = Composition::new(false).await;
    let (a, capture_a, diagnostic_a) = interrupted(&fx).await;
    let e0 = epoch(&fx);
    let e1 = initialise_next(&mut fx, Some(&capture_a), "epoch-zero.log", &diagnostic_a).await;
    let before = fx.responses();
    // One invocation observes mismatch, prepares B and loses B's Accepted reply.
    let (b, diagnostic_b) = cut_client(&fx, recover(&fx, &a), "dispatch", 2).await;
    let capture_b = fx
        .proxy
        .captured_matching(b.candidates.last().unwrap().id)
        .await;
    intent(&a, &b, &diagnostic_b);
    let a_retired = retired(
        &a.candidates[0],
        Evidence {
            started: 2,
            last_answered_attempt: 2,
            proved_no_write: 1,
            decision_seen: false,
        },
    );
    let candidate_b = b.candidates.last().unwrap().clone();
    let original = granary_core::root::decode_root(&a.frozen.initial_root).unwrap();
    let prepared = granary_core::root::decode_root(&candidate_b.root).unwrap();
    assert_eq!(
        (
            &prepared.volume,
            prepared.seq,
            prepared.parent,
            prepared.manifest_root,
            prepared.binmap_index,
            &prepared.chunker_spec,
            prepared.writer_uuid,
        ),
        (
            &original.volume,
            original.seq,
            original.parent,
            original.manifest_root,
            original.binmap_index,
            &original.chunker_spec,
            super::continuation::writer_uuid(&prepared, &a.frozen.writer_identity),
        ),
        "B must be prepared from the original frozen content and writer\n{diagnostic_b}"
    );
    assert_eq!(
        (
            &b.candidates,
            b.current,
            b.phase.clone(),
            fx.proxy.body(&capture_b),
            capture_b.seq,
            capture_b.occurrence
        ),
        (
            &vec![a_retired.clone(), candidate_b.clone()],
            Some(candidate_b.request),
            Phase::AwaitingAnswer {
                candidate: candidate_b.number,
                attempt: 1
            },
            candidate_b.root.clone(),
            a_retired.seq,
            1
        ),
        "B authorization retained A and exact B\n{b:?}\n{diagnostic_b}"
    );
    assert_eq!(
        (candidate_b.request.epoch, candidate_b.evidence),
        (e1.to_bytes(), a.candidates[0].evidence),
        "B's unanswered first attempt\n{diagnostic_b}"
    );
    assert!(
        oracle::open_log_positions(&fx.records())
            && matches!(fx.records()[0].body(), RecordBody::Decision { identity, candidate, root_seq, .. } if identity.candidate_id() == candidate_b.id && identity.operation().as_bytes() == candidate_b.request.operation && candidate.as_bytes() == candidate_b.root && *root_seq == candidate_b.seq),
        "B capture lacks its original committed decision/attestation\n{diagnostic_b}"
    );
    // Starting B durably cleared A's LastResponse; dispatch-after precedes
    // saving B's answer. The tap retains A's mismatch and B's exact Accepted.
    let responses = fx.responses();
    let suffix = responses
        .strip_prefix(&before)
        .unwrap_or_else(|| panic!("tap prefix changed\n{responses}\n{diagnostic_b}"));
    let mismatch_e1 = mismatch_before_acceptance(&b, e1, suffix)
        .unwrap_or_else(|error| panic!("{error}\n{diagnostic_b}"));
    let mut order = probe_post();
    order.push((Recovery, format!("GET {ROOT_PATH}")));
    order.push((Preparation, "GET /volume/alpha/max-seq".into()));
    order.extend(
        fx.preparation_requests(&candidate_b.root)
            .await
            .into_iter()
            .skip(2)
            .map(|path| (Preparation, path)),
    );
    order.extend(probe_post());
    trace(&fx, &before, (2, 9, 3, 0), order, &diagnostic_b);
    let e2 = initialise_next(&mut fx, Some(&capture_b), "epoch-one.log", &diagnostic_b).await;
    let before = fx.responses();
    let (second, diagnostic_second) = cut_client(&fx, recover(&fx, &b), "epoch-save", 1).await;
    intent(&a, &second, &diagnostic_second);
    let b_retired = retired(
        &candidate_b,
        Evidence {
            started: 2,
            last_answered_attempt: 2,
            proved_no_write: 1,
            decision_seen: false,
        },
    );
    let expected = vec![a_retired, b_retired];
    assert_eq!(
        (&second.candidates, second.current, second.phase.clone()),
        (
            &expected,
            None,
            Phase::EpochRecovery {
                epoch: e2.to_bytes()
            }
        ),
        "second durable epoch transition must retain both original tuples\n{second:?}\n{diagnostic_second}"
    );
    let mismatch_e2 = mismatched(&second, e2, candidate_b.number, &diagnostic_second);
    trace(&fx, &before, (1, 1, 1, 0), probe_post(), &diagnostic_second);
    let before = fx.responses();
    let (empty, diagnostic_empty) = cut_client(&fx, recover(&fx, &second), "probe-result", 1).await;
    intent(&a, &empty, &diagnostic_empty);
    assert_eq!(
        (
            &empty.candidates,
            &empty.phase,
            fx.roots().await,
            fx.proxy.pending()
        ),
        (&expected, &Phase::Rebase, vec![], 2),
        "empty occupancy released an owned candidate or prepared a third\n{empty:?}\n{diagnostic_empty}"
    );
    let current = empty
        .current
        .unwrap_or_else(|| panic!("missing fresh E2 operation\n{diagnostic_empty}"));
    assert_eq!(
        current.epoch,
        e2.to_bytes(),
        "new operation is not in E2\n{diagnostic_empty}"
    );
    assert!(
        e0 != e1
            && e1 != e2
            && e0 != e2
            && expected[0].request.operation != expected[1].request.operation
            && current.operation != expected[0].request.operation
            && current.operation != expected[1].request.operation
            && expected[0].id != expected[1].id
            && expected[0].root != expected[1].root,
        "distinct epochs, operations and A/B before completion\n{empty:?}\n{diagnostic_empty}"
    );
    trace(
        &fx,
        &before,
        (0, 1, 1, 0),
        vec![
            (Recovery, format!("GET {ROOT_PATH}")),
            (Preparation, "GET /volume/alpha/max-seq".into()),
        ],
        &diagnostic_empty,
    );
    assert_eq!(
        (
            fx.proxy.release(&capture_a).await,
            fx.proxy.release(&capture_b).await
        ),
        (Ok(200), Ok(412)),
        "late A wins; B must lose create-only without overwrite\n{diagnostic_empty}"
    );
    let diagnostic = finish(&fx, &empty, true).await;
    let mut only_b = b.clone();
    only_b.candidates = vec![candidate_b];
    assert!(
        oracle::post_transcripts_and_occupancy(
            &fx.notes(),
            &fx.responses(),
            &[&exact(&a), &exact(&a), &exact(&only_b), &exact(&only_b)],
            &[
                &accepted(&a),
                &mismatch_e1,
                &accepted(&only_b),
                &mismatch_e2
            ],
            &fx.roots().await,
            a.candidates[0].seq,
            &a.candidates[0].root
        ),
        "E exact POST transcript and owned A occupancy\n{}\n{}\n{diagnostic}",
        fx.notes(),
        fx.responses()
    );
    assert_eq!(
        (fx.proxy.finished().len(), fx.proxy.pending()),
        (2, 0),
        "all delayed attempts explicitly drained\n{diagnostic}"
    );
    fx.stop().await;
    assert_eq!(
        fx.records(),
        [],
        "E2 created a third decision\n{diagnostic}"
    );
    stages(
        "epochs::two_epoch_changes_keep_both_candidates_and_complete_with_a",
        &[
            "a-captured",
            "e1-mismatch",
            "b-captured",
            "e2-mismatch",
            "empty-catalogue",
            "distinct-identities",
            "late-releases",
            "owned-a",
        ],
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn delayed_a_release_after_rebase_before_b_put() {
    release_late_a_after_rebase(false).await;
    stages(
        "epochs::delayed_a_release_after_rebase_before_b_put",
        &[
            "a-held-across-reinitialise",
            "empty-probe",
            "head-resolved-cut",
            "a-released-before-b-put",
            "single-root",
            "client-landed",
        ],
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn delayed_a_release_after_b_put() {
    release_late_a_after_rebase(true).await;
    stages(
        "epochs::delayed_a_release_after_b_put",
        &[
            "a-held-across-reinitialise",
            "empty-probe",
            "head-resolved-cut",
            "b-put-landed",
            "a-released-after-b-put",
            "single-root",
            "client-landed",
        ],
    );
}

struct Peer {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buffered: Vec<u8>,
}
impl Peer {
    async fn new(fx: &Composition, name: &str) -> Self {
        let private = fx.client.scratch.0.join("private");
        let mut roots = rustls::RootCertStore::empty();
        for certificate in
            rustls_pki_types::CertificateDer::pem_file_iter(private.join("ca.pem")).unwrap()
        {
            roots.add(certificate.unwrap()).unwrap();
        }
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(granary_net::crypto_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    rustls_pki_types::CertificateDer::pem_file_iter(
                        private.join(format!("{name}.pem")),
                    )
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                    rustls_pki_types::PrivateKeyDer::from_pem_file(
                        private.join(format!("{name}.key")),
                    )
                    .unwrap(),
                )
                .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let address = std::fs::read_to_string(fx.client.scratch.0.join("ready")).unwrap();
        let tcp = timeout(WAIT, tokio::net::TcpStream::connect(address.trim()))
            .await
            .unwrap()
            .unwrap();
        let stream = timeout(
            WAIT,
            tokio_rustls::TlsConnector::from(Arc::new(config)).connect(
                rustls_pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        Self {
            stream,
            buffered: vec![],
        }
    }
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        candidate: Option<&Candidate>,
    ) -> (u16, String, Vec<u8>) {
        let body = candidate.map_or_else(Vec::new, |c| c.root.clone());
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\n",
            body.len()
        );
        if let Some(c) = candidate {
            write!(head, "content-type: application/vnd.granary.root.v1\r\ngranary-epoch: {}\r\ngranary-operation: {}\r\n", hex(&c.request.epoch), hex(&c.request.operation)).unwrap();
        }
        head.push_str("\r\n");
        timeout(WAIT, async {
            self.stream.write_all(head.as_bytes()).await.unwrap();
            self.stream.write_all(&body).await.unwrap();
            self.stream.flush().await.unwrap();
        })
        .await
        .unwrap();
        let raw = super::backend::read_frame(&mut self.stream, &mut self.buffered, false, false)
            .await
            .unwrap();
        let (response, token, body) = super::tails::shipping::gateway_response(&raw).unwrap();
        (response.status().as_u16(), token, body)
    }
    async fn publish(&mut self, record: &Submission) -> (u16, String, Vec<u8>) {
        self.request("POST", "/volume/alpha/publish", Some(&record.candidates[0]))
            .await
    }
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
#[expect(
    clippy::too_many_lines,
    reason = "rotation includes enrolled, revoked and foreign-principal controls against the same open decision"
)]
async fn credential_rotation_preserves_open_ownership() {
    // A real Accepted is lost only at the client dispatch-after cut.
    let mut fx = Composition::new(false).await;
    let (a, capture, diagnostic_a) = interrupted(&fx).await;
    let old_log = std::fs::read(fx.state.join("alpha.log")).unwrap();
    let enrollment = fx.client.scratch.0.join("enrollment");
    let private = fx.client.scratch.0.join("private");
    let digest = |name: &str| {
        granary_net::identity::client_spki_digest(
            &rustls_pki_types::CertificateDer::pem_file_iter(private.join(format!("{name}.pem")))
                .unwrap()
                .next()
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    };
    let c1 = digest("client");
    let c2 = digest("client2");
    let other = digest("foreign");
    let reader = EnrollmentReader::open(&enrollment, false).unwrap();
    let principal = match reader.lookup(&c1).await {
        Lookup::Enrolled { principal, .. } => principal,
        got => panic!("C1 enrollment: {got:?}\n{diagnostic_a}"),
    };
    // Open and warm C1 before revocation, retaining its TLS connection.
    let mut c1_peer = Peer::new(&fx, "client").await;
    let before = fx.responses();
    assert_eq!(
        c1_peer.request("GET", "/volume/alpha/status", None).await.0,
        200,
        "C1 warm read\n{diagnostic_a}"
    );
    trace(
        &fx,
        &before,
        (0, 1, 0, 0),
        vec![(Preparation, "GET /volume/alpha/status".into())],
        &diagnostic_a,
    );
    let options = VerbOptions {
        accept_unsupported_filesystem: false,
    };
    assert_eq!(
        attach(&enrollment, options, principal, c2).unwrap(),
        (principal, c2),
        "C2 attach\n{diagnostic_a}"
    );
    assert_eq!(
        revoke(&enrollment, options, c1).unwrap(),
        (principal, c1),
        "C1 revoke\n{diagnostic_a}"
    );
    let (foreign_principal, _) = mint(
        &enrollment,
        options,
        &TenantName::parse("test").unwrap(),
        other,
        &mut OsSecureRandom::new(),
    )
    .unwrap();
    assert!(
        c1 != c2
            && principal != foreign_principal
            && matches!(reader.lookup(&c2).await, Lookup::Enrolled { principal: observed, .. } if observed == principal),
        "rotation did not preserve principal continuity\n{diagnostic_a}"
    );
    let before = fx.responses();
    let revoked = c1_peer.publish(&a).await;
    let foreign = Peer::new(&fx, "foreign").await.publish(&a).await;
    assert_eq!(
        (
            (revoked.0, revoked.1.as_str()),
            (foreign.0, foreign.1.as_str()),
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            fx.roots().await,
            fx.proxy.pending()
        ),
        (
            (403, "not-enrolled"),
            (409, "not-decided"),
            old_log.clone(),
            vec![],
            1
        ),
        "revoked C1 / another principal must refuse while A stays open\n{revoked:?}\n{foreign:?}\n{diagnostic_a}"
    );
    trace(
        &fx,
        &before,
        (2, 0, 0, 0),
        vec![(Publication, "POST /volume/alpha/publish".into()); 2],
        &diagnostic_a,
    );
    for extension in ["pem", "key"] {
        std::fs::copy(
            private.join(format!("client2.{extension}")),
            private.join(format!("client.{extension}")),
        )
        .unwrap();
    }
    let before = fx.responses();
    let (retry, diagnostic_retry) =
        cut_client(&fx, fx.client.command(true), "answer-save", 1).await;
    intent(&a, &retry, &diagnostic_retry);
    let mut expected = a.candidates.clone();
    expected[0].evidence = Evidence {
        started: 2,
        last_answered_attempt: 2,
        proved_no_write: 0,
        decision_seen: true,
    };
    let position = Position {
        epoch: Epoch::from_bytes(a.candidates[0].request.epoch),
        entry_seq: 1,
    };
    let open = answer::encode(PublishAnswer::Open {
        position,
        candidate_id: a.candidates[0].id,
    })
    .unwrap();
    let last = retry.last_response.as_ref().unwrap();
    assert_eq!(
        (
            &retry.candidates,
            retry.current,
            &retry.phase,
            last.status,
            &last.token,
            &last.answer,
            std::fs::read(fx.state.join("alpha.log")).unwrap()
        ),
        (
            &expected,
            a.current,
            &Phase::Ready,
            202,
            &vec![],
            &open,
            old_log
        ),
        "C2 exact retry must yield checked Open at A's original position without a new decision\n{retry:?}\n{diagnostic_retry}"
    );
    trace(&fx, &before, (1, 1, 1, 0), probe_post(), &diagnostic_retry);
    assert_eq!(
        fx.proxy.release(&capture).await,
        Ok(200),
        "authorized A release\n{diagnostic_retry}"
    );
    let diagnostic = finish(&fx, &retry, false).await;
    let not_decided = response_line(
        409,
        "not-decided",
        &answer::encode(PublishAnswer::NotDecided {
            position,
            candidate_id: a.candidates[0].id,
        })
        .unwrap(),
    );
    // The tap includes C1's pre-dispatch refusal; the authority marker does not.
    assert!(
        oracle::post_transcripts_and_occupancy(
            &fx.notes(),
            &fx.responses(),
            &[exact(&a).as_str(); 3],
            &[
                &accepted(&a),
                &response_line(403, "not-enrolled", &[]),
                &not_decided,
                &response_line(202, "-", &open)
            ],
            &fx.roots().await,
            a.candidates[0].seq,
            &a.candidates[0].root
        ),
        "C exact transcript, original A and one root creation\n{}\n{}\n{diagnostic}",
        fx.notes(),
        fx.responses()
    );
    assert_eq!(
        (fx.proxy.finished().len(), fx.proxy.pending()),
        (1, 0),
        "C every delayed attempt drained\n{diagnostic}"
    );
    fx.stop().await;
    let records = fx.records();
    assert_eq!(
        (
            records.len(),
            records
                .iter()
                .filter(|r| matches!(r.body(), RecordBody::Decision { .. }))
                .count(),
            records
                .iter()
                .filter(|r| matches!(r.body(), RecordBody::Landed { .. }))
                .count()
        ),
        (3, 1, 1),
        "C one decision and one landing\n{records:?}\n{diagnostic}"
    );
    stages(
        "epochs::credential_rotation_preserves_open_ownership",
        &[
            "a-captured",
            "attached-c2",
            "revoked-c1",
            "foreign-principal",
            "checked-open",
            "exact-retry",
            "owned-a",
        ],
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
#[expect(
    clippy::too_many_lines,
    reason = "paired real refusal histories pin counters before and after retirement"
)]
async fn all_submissions_retirement_contrast() {
    for unknown in [true, false] {
        let mut fx = Composition::new(false).await;
        let (a, capture, diagnostic_a) = if unknown {
            let (a, capture, diagnostic) = interrupted(&fx).await;
            (a, Some(capture), diagnostic)
        } else {
            let (a, diagnostic) = cut_client(&fx, fx.client.command(false), "begin", 1).await;
            (a, None, diagnostic)
        };
        let set = fx.client.scratch.0.join("enrollment/ENROLLMENT");
        let enrolled = std::fs::read(&set).unwrap();
        // A malformed protected enrollment file exercises the real unavailable
        // path. No authority or transport answer is synthesized by the fixture.
        std::fs::write(&set, b"unreadable enrollment set").unwrap();
        let before = fx.responses();
        let (refusal, diagnostic_refusal) =
            cut_client(&fx, fx.client.command(true), "answer-save", 1).await;
        intent(&a, &refusal, &diagnostic_refusal);
        let attempts = if unknown { 2 } else { 1 };
        let last = refusal.last_response.as_ref().unwrap();
        assert_eq!(
            (
                refusal.candidates[0].evidence,
                &refusal.phase,
                last.status,
                last.token.as_slice(),
                last.answer.as_slice()
            ),
            (
                Evidence {
                    started: attempts,
                    last_answered_attempt: attempts,
                    proved_no_write: 1,
                    decision_seen: false
                },
                &Phase::Ready,
                503,
                b"enrollment-unavailable".as_slice(),
                &[][..]
            ),
            "enrollment refusal proves only its answered submission\n{refusal:?}\n{diagnostic_refusal}"
        );
        trace(
            &fx,
            &before,
            (1, 1, 1, 0),
            probe_post(),
            &diagnostic_refusal,
        );
        std::fs::write(&set, enrolled).unwrap();
        let next = initialise_next(
            &mut fx,
            capture.as_ref(),
            "before-refusal-epoch.log",
            &diagnostic_a,
        )
        .await;
        let before = fx.responses();
        let (retirement, diagnostic_retirement) =
            cut_client(&fx, fx.client.command(true), "epoch-save", 1).await;
        intent(&a, &retirement, &diagnostic_retirement);
        let expected = if unknown {
            vec![retired(
                &a.candidates[0],
                Evidence {
                    started: 3,
                    last_answered_attempt: 3,
                    proved_no_write: 2,
                    decision_seen: false,
                },
            )]
        } else {
            vec![]
        };
        assert_eq!(
            (
                &retirement.candidates,
                retirement.current,
                &retirement.phase,
                retirement.last_response.is_some(),
                fx.roots().await
            ),
            (
                &expected,
                None,
                &Phase::EpochRecovery {
                    epoch: next.to_bytes()
                },
                unknown,
                vec![]
            ),
            "all-submissions retirement contrast: unknown must stay; only validated refusals may prune\nunknown={unknown}\n{retirement:?}\n{diagnostic_retirement}"
        );
        trace(
            &fx,
            &before,
            (1, 1, 1, 0),
            probe_post(),
            &diagnostic_retirement,
        );
        let responses = fx.responses();
        let posts: Vec<_> = responses
            .lines()
            .filter(|line| line.starts_with("POST "))
            .collect();
        assert_eq!(
            posts.len(),
            if unknown { 3 } else { 2 },
            "contrast exact number of POSTs\n{responses}\n{diagnostic_retirement}"
        );
        assert_eq!(
            posts[usize::from(unknown)],
            response_line(503, "enrollment-unavailable", &[]),
            "real enrollment-unavailable response\n{diagnostic_retirement}"
        );
        let expected_mismatch = if unknown {
            mismatched(
                &retirement,
                next,
                a.candidates[0].number,
                &diagnostic_retirement,
            )
        } else {
            // Pruning clears LastResponse; derive the expected empty-slot
            // mismatch from the new epoch, independently of the wire bytes.
            refusal_mismatch_line(next)
        };
        let notes = fx.notes();
        assert_eq!(
            notes
                .lines()
                .filter(|line| line.starts_with("POST "))
                .collect::<Vec<_>>(),
            vec![exact(&a); if unknown { 2 } else { 1 }],
            "contrast dispatched POSTs retain exact A\n{notes}\n{diagnostic_retirement}"
        );
        assert_eq!(
            *posts.last().unwrap(),
            expected_mismatch,
            "contrast final exact epoch mismatch\n{diagnostic_retirement}"
        );
        if let Some(capture) = capture {
            assert_eq!(
                fx.proxy.release(&capture).await,
                Ok(200),
                "unknown old authorized PUT survives retirement\n{diagnostic_retirement}"
            );
            finish(&fx, &retirement, true).await;
        }
        assert_eq!(
            fx.proxy.pending(),
            0,
            "contrast leaves no delayed attempt\n{diagnostic_retirement}"
        );
        fx.stop().await;
    }
    stages(
        "epochs::all_submissions_retirement_contrast",
        &[
            "unknown-attempt",
            "enrollment-unavailable",
            "real-epoch-mismatch",
            "uncertain-retained",
            "refusals-pruned",
        ],
    );
}
