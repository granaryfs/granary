// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Replayed open publications and parent-owned writes after client archival.
use std::os::unix::process::ExitStatusExt as _;
use std::process::Output;

use granary_core::authlog::{Epoch, RecordBody};
use granary_core::authority_answer::{self as answer, Position, PublishAnswer};
use granary_core::retained_submission::{Phase, Submission};
use granary_core::runmarker::{RunMarker, decode_marker};
use tokio::time::{sleep, timeout};

use super::backend::Identity;
use super::composition::{Composition, report};
use super::oracle::{self, RequestClass::*};
use super::support::{Process, ROOT_PATH, Rendezvous, WAIT, assert_exit, hex, observe};

#[path = "shipping.rs"]
pub(super) mod shipping;

pub(super) fn diagnostics(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub(super) fn exact(record: &Submission) -> String {
    let c = &record.candidates[0];
    format!(
        "POST alpha {} {} {}",
        hex(&c.request.epoch),
        hex(&c.request.operation),
        hex(&c.root)
    )
}

pub(super) fn accepted(record: &Submission) -> String {
    let c = &record.candidates[0];
    format!(
        "POST /volume/alpha/publish 202 - {}",
        hex(&answer::encode(PublishAnswer::Accepted {
            position: Position {
                epoch: Epoch::from_bytes(c.request.epoch),
                entry_seq: 1
            },
            candidate_id: c.id,
        })
        .unwrap())
    )
}

pub(super) async fn initial_trace(fx: &Composition, record: &Submission, diagnostic: &str) {
    let mut order: Vec<_> = fx
        .preparation_requests(&record.frozen.initial_root)
        .await
        .into_iter()
        .map(|path| (Preparation, path))
        .collect();
    order.extend([
        (Recovery, format!("GET {ROOT_PATH}")),
        (Preparation, "GET /volume/alpha/max-seq".into()),
        (Publication, "POST /volume/alpha/publish".into()),
    ]);
    assert_eq!(
        oracle::request_trace(&fx.responses()),
        Ok(((1, 9, 1, 0), order)),
        "exact initial client request classes/counts/order\n{}\n{diagnostic}",
        fx.responses()
    );
    assert_eq!(
        fx.notes()
            .lines()
            .filter(|line| line.starts_with("POST "))
            .collect::<Vec<_>>(),
        [exact(record)],
        "exact initial publication POST\n{}\n{diagnostic}",
        fx.notes()
    );
}

async fn first_trace(fx: &Composition, record: &Submission, diagnostic: &str) {
    initial_trace(fx, record, diagnostic).await;
    assert_eq!(
        fx.responses()
            .lines()
            .filter(|line| line.starts_with("POST "))
            .collect::<Vec<_>>(),
        [accepted(record)],
        "normal committed Accepted answer\n{}\n{diagnostic}",
        fx.responses()
    );
}

/// Loss is the existing client dispatch-after cut: Accepted reached the client,
/// whose durable unanswered tuple has not yet accounted for that answer.
pub(super) async fn interrupted(fx: &Composition) -> (Submission, Identity, String) {
    let mut command = fx.client.command(false);
    let rendezvous = Rendezvous::arm(&mut command, &fx.client.scratch.0, "dispatch", "after", 1);
    let mut process = Process::spawn(&mut command);
    let reached = rendezvous.reached(&mut process).await;
    process.assert_or_kill(
        reached.is_ok(),
        &format!("client dispatch cut: {reached:?}"),
    );
    let (event, _stream) = reached.unwrap();
    let retained = fx.client.record();
    process.assert_or_kill(retained.is_some(), "missing unanswered publication");
    let record = retained.unwrap();
    let capture = fx.proxy.captured().await;
    let output = process.kill().await;
    let diagnostic = diagnostics(&output);
    let c = &record.candidates[0];
    assert_eq!(
        (
            output.status.signal(),
            event.id,
            record.phase.clone(),
            c.evidence.started,
            c.evidence.last_answered_attempt,
            c.evidence.proved_no_write,
            c.evidence.decision_seen
        ),
        (
            Some(9),
            hex(&record.publication_id),
            Phase::AwaitingAnswer {
                candidate: c.number,
                attempt: 1
            },
            1,
            0,
            0,
            false
        ),
        "durable unanswered tuple at client dispatch cut\n{diagnostic}"
    );
    assert_eq!(
        (
            &capture.volume,
            capture.seq,
            capture.id,
            capture.occurrence,
            fx.proxy.body(&capture)
        ),
        (&"alpha".to_owned(), c.seq, c.id, 1, c.root.clone()),
        "authorised captured A PUT\n{diagnostic}"
    );
    let records = fx.records();
    assert!(
        oracle::open_log_positions(&records),
        "exactly one decision then its attestation at entry position 1\n{records:?}\n{diagnostic}"
    );
    assert!(
        matches!(records[0].body(), RecordBody::Decision { identity, root_seq, candidate, .. } if identity.candidate_id() == c.id && identity.operation().as_bytes() == c.request.operation && *root_seq == c.seq && candidate.as_bytes() == c.root)
            && matches!(records[1].body(), RecordBody::Attestation { final_root, .. } if final_root.as_bytes() == c.root),
        "captured PUT requires this decision and exact attestation\n{records:?}\n{diagnostic}"
    );
    assert_eq!(fx.roots().await, [], "A must still be empty\n{diagnostic}");
    first_trace(fx, &record, &diagnostic).await;
    (record, capture, diagnostic)
}

fn state(fx: &Composition) -> Vec<(std::ffi::OsString, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(&fx.state)
        .unwrap()
        .map(|file| {
            let file = file.unwrap();
            (file.file_name(), std::fs::read(file.path()).unwrap())
        })
        .collect();
    files.sort();
    files
}

async fn replay_and_complete(
    mut fx: Composition,
    old: &Submission,
    capture: &Identity,
    diagnostic: &str,
    log: Vec<u8>,
) {
    fx.ready().await;
    let replay = fx.proxy.captured_except(capture).await;
    assert_eq!(
        (
            &replay.volume,
            replay.seq,
            replay.id,
            replay.occurrence,
            fx.proxy.body(&replay),
            std::fs::read(fx.state.join("alpha.log")).unwrap()
        ),
        (
            &capture.volume,
            capture.seq,
            capture.id,
            2,
            old.candidates[0].root.clone(),
            log
        ),
        "replayed PUT must retain exact bytes/seq and the original log identity\n{diagnostic}"
    );
    // Release both surviving attempts, oldest first. The original request
    // creates A; the replay's create-only conflict is not a second creation.
    assert_eq!(
        (
            fx.proxy.release(capture).await,
            fx.proxy.release(&replay).await
        ),
        (Ok(200), Ok(412)),
        "old/replayed conditional results\n{diagnostic}"
    );
    complete(&mut fx, old).await;
    fx.stop().await;
    let records = fx.records();
    assert_eq!((records.len(), records.iter().filter(|r| matches!(r.body(), RecordBody::Decision { .. })).count(), records.iter().filter(|r| matches!(r.body(), RecordBody::Landed { identity } if identity.candidate_id() == old.candidates[0].id)).count()), (3, 1, 1), "one decision, one landing, no successor\n{records:?}\n{diagnostic}");
}

fn snapshot_before_start(path: &std::path::Path, start: impl FnOnce()) -> Vec<u8> {
    let log = std::fs::read(path).unwrap();
    start();
    log
}

fn replay_snapshot_controls() {
    let scratch = super::support::Scratch::new();
    let path = scratch.0.join("alpha.log");
    std::fs::write(&path, b"original committed log").unwrap();
    let captured = snapshot_before_start(&path, || {
        std::fs::write(&path, b"changed during startup").unwrap();
    });
    assert_eq!(
        (captured, std::fs::read(&path).unwrap()),
        (
            b"original committed log".to_vec(),
            b"changed during startup".to_vec()
        ),
        "replay baseline must precede host startup"
    );
    let captured = snapshot_before_start(&path, || {});
    assert_eq!(captured, b"changed during startup");
}

async fn complete(fx: &mut Composition, old: &Submission) {
    let before = fx.responses();
    let output = Process::spawn(&mut fx.client.command(true)).output().await;
    let diagnostic = diagnostics(&output);
    report(&output, 0, old, "landed");
    let complete = fx
        .client
        .record()
        .unwrap_or_else(|| panic!("missing durable completion\n{diagnostic}"));
    assert_eq!(
        (
            &complete.scope,
            &complete.volume,
            complete.publication_id,
            &complete.frozen,
            &complete.current,
            &complete.candidates
        ),
        (
            &old.scope,
            &old.volume,
            old.publication_id,
            &old.frozen,
            &None,
            &old.candidates
        ),
        "owned completion must preserve the original catalogue and intent\n{diagnostic}"
    );
    assert!(
        matches!(complete.phase, Phase::Complete(_)),
        "not complete: {complete:?}\n{diagnostic}"
    );
    assert_eq!(
        oracle::request_trace(fx.responses().strip_prefix(&before).unwrap()),
        Ok((
            (0, 1, 1, 1),
            vec![
                (Recovery, format!("GET {ROOT_PATH}")),
                (Preparation, "GET /volume/alpha/max-seq".into()),
                (Hint, "PUT /volume/alpha/hint".into())
            ]
        )),
        "fresh invocation must only probe A and repair its hint\n{}\n{diagnostic}",
        fx.responses()
    );
    let c = &old.candidates[0];
    assert!(
        oracle::trace_and_occupancy(
            &fx.notes(),
            &fx.responses(),
            &exact(old),
            &[&accepted(old)],
            &fx.roots().await,
            c.seq,
            &c.root
        ),
        "exact POST transcript and owned occupancy; no successor\n{}\n{}\n{diagnostic}",
        fx.notes(),
        fx.responses()
    );
    assert_eq!(
        (
            fx.proxy
                .finished()
                .iter()
                .filter(|(_, status)| *status == 200)
                .count(),
            fx.proxy.pending()
        ),
        (1, 0),
        "one root creation and every PUT drained\n{:?}\n{diagnostic}",
        fx.proxy.finished()
    );
}

pub(super) fn stages(test: &str, stages: &[&str]) {
    observe(
        test,
        &stages
            .iter()
            .map(|stage| format!("{test}:{stage}"))
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn clean_replay_reissues_exact_open() {
    let mut fx = Composition::new(false).await;
    let (old, capture, diagnostic) = interrupted(&fx).await;
    let log = std::fs::read(fx.state.join("alpha.log")).unwrap();
    fx.signal_stop();
    // A reported, polled stop precedes issuer completion; it cannot race a
    // new publication step. The parent continues to own the signed capture.
    timeout(WAIT, async {
        while !fx.client.scratch.0.join("stop-requested").exists() {
            sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fx.proxy.detach(&capture).await,
        Ok(()),
        "explicit issuer refusal\n{diagnostic}"
    );
    let output = fx.host.take().unwrap().host_output().await;
    assert_exit(&output, 0);
    assert_eq!(
        (
            decode_marker(&std::fs::read(fx.state.join("MARKER")).unwrap()).unwrap(),
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            fx.proxy.pending(),
            fx.proxy.issuer_refusals(),
            fx.roots().await
        ),
        (RunMarker::Clean, log, 1, vec![capture.clone()], vec![]),
        "clean stop retains the open log and late write\n{diagnostic}\n{}",
        diagnostics(&output)
    );
    let path = fx.state.join("alpha.log");
    let log = snapshot_before_start(&path, || fx.start(false));
    replay_and_complete(fx, &old, &capture, &diagnostic, log).await;
    stages(
        "tails::clean_replay_reissues_exact_open",
        &[
            "dispatch-cut",
            "captured",
            "clean-stop",
            "same-boot",
            "exact-reissue",
            "owned-completion",
        ],
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn gateway_crash_refuses_same_boot_and_recovers_after_modeled_reboot() {
    let mut fx = Composition::new(false).await;
    let (old, capture, diagnostic) = interrupted(&fx).await;
    let killed = fx.host.take().unwrap().kill().await;
    assert_eq!(
        killed.status.signal(),
        Some(9),
        "host/gateway SIGKILL\n{}\n{diagnostic}",
        diagnostics(&killed)
    );
    let unchanged = state(&fx);
    fx.start(false);
    let ready = fx.client.scratch.0.join("ready");
    let seen = super::support::wait_report(fx.host.as_mut().unwrap(), WAIT, async {
        while !ready.exists() {
            sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    })
    .await;
    fx.host.as_mut().unwrap().assert_or_kill(
        seen.as_ref()
            .is_err_and(|e| e.contains("child exit before rendezvous")),
        &format!("same-boot restart served or failed to refuse: {seen:?}"),
    );
    let refusal = fx.host.take().unwrap().host_output().await;
    assert_eq!(
        (
            refusal.status.code(),
            String::from_utf8_lossy(&refusal.stderr).contains("running in this boot"),
            ready.exists(),
            state(&fx)
        ),
        (
            Some(granary_server::EXIT_STARTUP_FAILED),
            true,
            false,
            unchanged
        ),
        "same-boot refusal must neither serve nor change any state\n{}\n{diagnostic}",
        diagnostics(&refusal)
    );
    assert_eq!(
        fx.client.record().unwrap(),
        old,
        "host refusal changed the client's unanswered tuple\n{diagnostic}"
    );
    // A changed boot through the real host seam models a reboot. The marker
    // and logs are never edited to manufacture admission.
    let path = fx.state.join("alpha.log");
    let log = snapshot_before_start(&path, || fx.start(true));
    replay_and_complete(fx, &old, &capture, &diagnostic, log).await;
    stages(
        "tails::gateway_crash_refuses_same_boot_and_recovers_after_modeled_reboot",
        &[
            "dispatch-cut",
            "captured",
            "sigkill",
            "same-boot-refusal",
            "modeled-reboot",
            "exact-reissue",
            "owned-completion",
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
    reason = "one schedule snapshots the archive and checks both actual CLI selection refusals"
)]
async fn late_put_lands_after_unchanged_archive() {
    let mut fx = Composition::new(false).await;
    let (old, capture, diagnostic) = interrupted(&fx).await;
    let before = (fx.notes(), fx.responses());
    let mut command = fx.client.command(true);
    command.args([
        "--abandon",
        &hex(&old.publication_id),
        "--acknowledge-may-land",
    ]);
    let output = Process::spawn(&mut command).output().await;
    report(&output, 0, &old, "abandoned");
    let archive = fx.client.archives();
    assert_eq!(
        (
            fx.client.record(),
            archive.len(),
            fx.notes(),
            fx.responses(),
            fx.roots().await
        ),
        (None, 1, before.0, before.1, vec![]),
        "local may-land abandonment sends zero network requests and does not land A\n{}\n{diagnostic}",
        diagnostics(&output)
    );
    assert_eq!(
        (
            &archive[0].2.scope,
            &archive[0].2.volume,
            archive[0].2.publication_id,
            &archive[0].2.frozen,
            &archive[0].2.current,
            &archive[0].2.candidates,
            &archive[0].2.phase
        ),
        (
            &old.scope,
            &old.volume,
            old.publication_id,
            &old.frozen,
            &old.current,
            &old.candidates,
            &old.phase
        ),
        "archival must retain the unanswered catalogue and frozen intent\n{}",
        diagnostics(&output)
    );
    assert_eq!(
        fx.proxy.release(&capture).await,
        Ok(200),
        "authorised late A release\n{diagnostic}"
    );
    for recover in [false, true] {
        let before = fx.responses();
        let mut command = fx.client.command(recover);
        if recover {
            command.args(["--recover", &hex(&old.publication_id)]);
        }
        // A mutant that bypasses archive selection is stopped at its first
        // actual POST, making a semantic refusal instead of a timeout.
        let cut = Rendezvous::arm(&mut command, &fx.client.scratch.0, "dispatch", "after", 1);
        let mut process = Process::spawn(&mut command);
        let reached = cut.reached(&mut process).await;
        process.assert_or_kill(reached.as_ref().is_err_and(|e| e.contains("child exit before rendezvous")), &format!("archive-only evidence allowed a publication POST/new identity: {reached:?}; live={:?}", fx.client.record()));
        let output = process.output().await;
        let json = assert_exit(&output, 4);
        assert_eq!(
            (
                json.contains("\"outcome\":\"refused\""),
                oracle::request_trace(fx.responses().strip_prefix(&before).unwrap()),
                fx.client.record(),
                fx.client.archives()
            ),
            (true, Ok(((0, 0, 0, 0), vec![])), None, archive.clone()),
            "ordinary/archived-ID recovery preserves the exact archive and sends zero requests\n{}\n{diagnostic}",
            diagnostics(&output)
        );
    }
    let c = &old.candidates[0];
    assert!(
        oracle::trace_and_occupancy(
            &fx.notes(),
            &fx.responses(),
            &exact(&old),
            &[&accepted(&old)],
            &fx.roots().await,
            c.seq,
            &c.root
        ),
        "late PUT must leave exactly A and no successor\n{diagnostic}"
    );
    assert_eq!(
        (fx.proxy.finished().len(), fx.proxy.pending()),
        (1, 0),
        "all late attempts accounted for\n{diagnostic}"
    );
    fx.stop().await;
    stages(
        "tails::late_put_lands_after_unchanged_archive",
        &[
            "dispatch-cut",
            "captured",
            "empty-slot",
            "local-archive",
            "late-release",
            "archive-refusals",
        ],
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn shipping_server_binary_publishes_once_and_lands() {
    shipping::run().await;
    stages(
        "tails::shipping_server_binary_publishes_once_and_lands",
        &[
            "shipping-server",
            "accepted",
            "put-release",
            "landed",
            "human-output",
        ],
    );
}
