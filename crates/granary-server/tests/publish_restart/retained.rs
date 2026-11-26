// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator-created state, observed fences and retained publication settlement.
use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use granary_core::authlog::{self, Classified, Epoch, RecordBody};
use granary_core::retained_submission::{Phase, Submission};
use granary_core::root::VolumeName;
use granary_core::runmarker::{BootId, RunMarker, decode_marker};
use granary_net::secure_random::OsSecureRandom;
use granary_server::{
    EXIT_DRAINED, EXIT_FENCED, EXIT_REFUSED, EXIT_STARTUP_FAILED, EXIT_VERB_DONE, StateTimes,
    run_lifecycle_command_line,
};
use tokio::io::AsyncWriteExt as _;
use tokio::time::sleep;

use super::backend::Proxy;
use super::composition::{Composition, report, shipping_server};
use super::oracle::{self, RequestClass::*};
use super::support::{Process, ROOT_PATH, Rendezvous, WAIT, hex, wait_report};
use super::tails::{accepted, diagnostics, exact, initial_trace, interrupted, stages};

const INITIAL: BootId = BootId::from_bytes([0x71; 16]);
const REBOOT: BootId = BootId::from_bytes([0x72; 16]);
const NO_FAULT: &str = "HostReply:4294967295:hold";

fn state(path: &Path) -> Vec<(OsString, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|file| {
            let file = file.unwrap();
            assert!(
                file.file_type().unwrap().is_file(),
                "unexpected state entry: {file:?}"
            );
            (file.file_name(), std::fs::read(file.path()).unwrap())
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "empty operator state at {}",
        path.display()
    );
    files
}

fn marker(path: &Path) -> RunMarker {
    decode_marker(&std::fs::read(path.join("MARKER")).unwrap()).unwrap()
}

fn epoch(path: &Path) -> Epoch {
    match authlog::classify(
        &std::fs::read(path.join("alpha.log")).unwrap(),
        &VolumeName::new("alpha".into()).unwrap(),
    )
    .unwrap()
    {
        Classified::Log {
            envelope,
            tail_len: 0,
            ..
        } => envelope.epoch(),
        other => panic!("incomplete operator log: {other:?}"),
    }
}

fn journal(fx: &Composition, old: &Submission) -> Vec<u8> {
    let path = fx
        .client
        .store
        .join("publications")
        .join(old.scope.digest().unwrap())
        .join("alpha.sub");
    std::fs::read(path).unwrap()
}

fn unchanged(fx: &Composition, old: &Submission, bytes: &[u8]) {
    assert_eq!(
        (fx.client.record(), journal(fx, old)),
        (Some(old.clone()), bytes.to_vec()),
        "refusal lost or rewrote the retained unanswered tuple"
    );
}

fn verb(state: &Path, name: &str) -> Command {
    let mut command = Command::new(shipping_server());
    command.env_clear().args([name, "--state-dir"]).arg(state);
    if name == "initialise" {
        command.args(["--volume", "alpha"]);
    }
    command
}

fn verb_result(output: &Output, code: i32, stdout: &str, refusal: &str) {
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        (output.status.code(), out.as_ref(), err.contains(refusal)),
        (Some(code), stdout, true),
        "operator verb result\n{}",
        diagnostics(output)
    );
    if refusal.is_empty() {
        assert_eq!(err, "", "successful verb stderr\n{}", diagnostics(output));
    }
}

async fn provision(path: PathBuf) -> (Epoch, Vec<u8>) {
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert!(
        !path.join("alpha.log").exists(),
        "host already created the log"
    );
    let output = Process::spawn(&mut verb(&path, "initialise"))
        .output()
        .await;
    let created = epoch(&path);
    verb_result(
        &output,
        EXIT_VERB_DONE,
        &format!("created alpha {}\n", hex(&created.to_bytes())),
        "",
    );
    assert_eq!(
        marker(&path),
        RunMarker::Clean,
        "initialise must publish clean\n{}",
        diagnostics(&output)
    );
    (created, std::fs::read(path.join("alpha.log")).unwrap())
}

/// Observe the child we own; apply the prevent set to that observed status.
struct Supervisor {
    prevent: Vec<i32>,
    attempts: usize,
}
impl Supervisor {
    async fn start(plan: &str) -> (Composition, (Epoch, Vec<u8>)) {
        Composition::with_setup(plan, None, provision).await
    }

    fn after_exit(&mut self, fx: &mut Composition, output: &Output) {
        let code = output
            .status
            .code()
            .expect("supervised child must exit normally");
        if !self.prevent.contains(&code) {
            self.attempts += 1;
            fx.start(false);
        }
    }

    async fn wait(&mut self, fx: &mut Composition) -> Output {
        let output = fx.host.take().unwrap().host_output().await;
        self.after_exit(fx, &output);
        output
    }
}

async fn supervisor_controls(
    fx: &mut Composition,
    honoring: &mut Supervisor,
    old: &Submission,
    bytes: &[u8],
    ordinal: u32,
    before: Vec<(OsString, Vec<u8>)>,
) {
    let output = honoring.wait(fx).await;
    assert_eq!(
        (
            output.status.code(),
            honoring.attempts,
            fx.host.is_some(),
            marker(&fx.state),
            state(&fx.state)
        ),
        (
            Some(EXIT_FENCED),
            0,
            false,
            RunMarker::Running(INITIAL),
            before.clone()
        ),
        "observed fence and RestartPreventExitStatus=4\n{}",
        diagnostics(&output)
    );
    assert_eq!(
        fx.notes()
            .lines()
            .filter(|line| line.starts_with("REACHED HostLogAppend ")
                || line.starts_with("RELEASED HostLogAppend"))
            .collect::<Vec<_>>(),
        [
            format!("REACHED HostLogAppend {ordinal}"),
            "RELEASED HostLogAppend".into()
        ],
        "exact nonempty append rendezvous\n{}",
        fx.notes()
    );
    unchanged(fx, old, bytes);

    // A released plan cannot be installed at a fresh host start. Disable it
    // before testing the startup marker, retaining the observed fault notes.
    std::fs::remove_file(fx.client.scratch.0.join("release")).unwrap();
    fx.command.env("GRANARY_TEST_HOST_PLAN", NO_FAULT);
    let mut ignoring = Supervisor {
        prevent: vec![],
        attempts: 0,
    };
    ignoring.after_exit(fx, &output);
    let refusal = fx.host.take().unwrap().host_output().await;
    assert_eq!(
        (
            ignoring.attempts,
            refusal.status.code(),
            String::from_utf8_lossy(&refusal.stderr).contains("running in this boot"),
            fx.client.scratch.0.join("ready").exists(),
            state(&fx.state)
        ),
        (1, Some(EXIT_STARTUP_FAILED), true, false, before),
        "supervisor ignoring the fence must attempt and receive startup refusal\n{}",
        diagnostics(&refusal)
    );
    unchanged(fx, old, bytes);
}

fn times(path: &Path) -> StateTimes {
    let root = std::fs::symlink_metadata(path).unwrap();
    let mut observed = StateTimes {
        files: vec![],
        directories: vec![(root.ctime(), root.ctime_nsec())],
    };
    for file in std::fs::read_dir(path).unwrap() {
        let file = file.unwrap();
        let meta = std::fs::symlink_metadata(file.path()).unwrap();
        assert!(meta.is_file(), "unexpected state-time entry: {file:?}");
        observed
            .files
            .push((meta.mtime(), meta.mtime_nsec()).max((meta.ctime(), meta.ctime_nsec())));
    }
    assert!(!observed.files.is_empty());
    observed
}

fn max_time(observed: &StateTimes) -> (i64, i64) {
    *observed
        .files
        .iter()
        .chain(&observed.directories)
        .max()
        .unwrap()
}

async fn unfence(path: &Path, boot: BootId, start: i64) -> (i32, String, String) {
    let args = vec![
        "unfence".into(),
        "--state-dir".into(),
        path.as_os_str().to_owned(),
    ];
    tokio::task::spawn_blocking(move || {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_lifecycle_command_line(
            &args,
            &mut OsSecureRandom::new(),
            || Ok(start),
            || Ok(boot),
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    })
    .await
    .unwrap()
}

async fn unfence_controls(fx: &Composition, old: &Submission, bytes: &[u8]) {
    let before = state(&fx.state);
    let output = Process::spawn(&mut verb(&fx.state, "unfence"))
        .output()
        .await;
    verb_result(&output, EXIT_REFUSED, "", "requires a host reboot");
    assert_eq!(
        state(&fx.state),
        before,
        "real same-boot unfence modified state"
    );
    unchanged(fx, old, bytes);

    let observed = times(&fx.state);
    let (seconds, _) = max_time(&observed);
    let later = seconds.checked_add(1).unwrap();
    assert!(
        observed.check(later).is_ok(),
        "marker control's actual times must pass: {observed:?}"
    );
    let result = unfence(&fx.state, INITIAL, later).await;
    assert_eq!(
        (
            result.0,
            result.1.as_str(),
            result.2.contains("running in this boot")
        ),
        (EXIT_REFUSED, "", true),
        "marker must refuse even with passing times: {result:?}"
    );
    assert_eq!(state(&fx.state), before);
    unchanged(fx, old, bytes);

    // Boot start is whole-second: constructed values pin the library's strict boundary; real state checks refusal/admission.
    let boundary = StateTimes {
        files: vec![(seconds, 0)],
        directories: vec![(seconds, 0)],
    };
    let error = boundary.check(seconds).unwrap_err();
    assert!(
        error.to_string().contains("requires a host reboot"),
        "equal boundary refusal: {error}"
    );
    assert!(
        boundary.check(later).is_ok(),
        "strict boundary positive control"
    );
    let just_before = StateTimes {
        files: vec![(seconds - 1, 999_999_999)],
        directories: vec![(seconds - 1, 999_999_999)],
    };
    assert!(
        just_before.check(seconds).is_ok(),
        "constructed one-nanosecond-before boundary positive control"
    );
    let result = unfence(&fx.state, REBOOT, seconds).await;
    assert_eq!(
        (
            result.0,
            result.1.as_str(),
            result.2.contains("requires a host reboot")
        ),
        (EXIT_REFUSED, "", true),
        "actual maximum second must refuse: {result:?}; observed={observed:?}"
    );
    assert_eq!(state(&fx.state), before);
    unchanged(fx, old, bytes);
}

/// Start a byte-identical second copy in another boot without running unfence.
async fn reboot_without_unfence(
    fx: &mut Composition,
    old: &Submission,
    bytes: &[u8],
    landing: bool,
) {
    let before = state(&fx.state);
    let copy = fx.client.scratch.0.join("reboot-control");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&copy)
        .unwrap();
    for (name, _) in &before {
        std::fs::copy(fx.state.join(name), copy.join(name)).unwrap();
    }
    assert_eq!(
        state(&copy),
        before,
        "reboot control must begin with exact fenced bytes"
    );
    let log = std::fs::read(copy.join("alpha.log")).unwrap();
    // An independent capture proxy prevents the copied engine from consuming
    // the original fixture's replay occurrence or writing another root.
    let control = Proxy::new(fx.minio_endpoint().strip_prefix("http://").unwrap().into()).await;
    fx.command
        .env("GRANARY_AUTHORITY_STATE_DIR", &copy)
        .env("GRANARY_STORE_ENDPOINT", &control.endpoint);
    fx.start(true);
    fx.ready().await;
    assert_eq!(
        (
            marker(&copy),
            epoch(&copy),
            std::fs::read(copy.join("alpha.log")).unwrap()
        ),
        (RunMarker::Running(REBOOT), epoch(&fx.state), log),
        "reboot alone must admit the copied state without changing its log"
    );
    let captured = if landing {
        let captured = control.captured().await;
        assert_eq!(
            (
                captured.seq,
                captured.id,
                captured.occurrence,
                control.body(&captured)
            ),
            (
                old.candidates[0].seq,
                old.candidates[0].id,
                1,
                old.candidates[0].root.clone()
            )
        );
        Some(captured)
    } else {
        None
    };
    fx.signal_stop();
    let stop = fx.client.scratch.0.join("stop-requested");
    let result = wait_report(fx.host.as_mut().unwrap(), WAIT, async {
        while !stop.exists() {
            sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    })
    .await;
    fx.host
        .as_mut()
        .unwrap()
        .assert_or_kill(result.is_ok(), &format!("copied host stop: {result:?}"));
    if let Some(captured) = captured {
        assert_eq!(control.detach(&captured).await, Ok(()));
        assert_eq!(
            (control.pending(), control.issuer_refusals()),
            (1, vec![captured])
        );
    }
    let output = fx.host.take().unwrap().host_output().await;
    assert_eq!(
        (output.status.code(), control.pending()),
        (Some(EXIT_DRAINED), usize::from(landing)),
        "admitted copied host must stop cleanly; an undecided log must not replay a PUT\n{}",
        diagnostics(&output)
    );
    fx.command
        .env("GRANARY_AUTHORITY_STATE_DIR", &fx.state)
        .env("GRANARY_STORE_ENDPOINT", &fx.proxy.endpoint);
    assert_eq!(
        state(&fx.state),
        before,
        "control modified original fenced state"
    );
    unchanged(fx, old, bytes);
}

#[expect(
    clippy::too_many_lines,
    reason = "settlement jointly checks the retained catalogue, classified log, exact requests and root occupancy"
)]
async fn complete(fx: &mut Composition, old: &Submission, landing: bool) {
    let before = fx.responses();
    let output = if landing {
        Process::spawn(&mut fx.client.command(true)).output().await
    } else {
        let mut command = fx.client.command(true);
        let cut = Rendezvous::arm(&mut command, &fx.client.scratch.0, "dispatch", "after", 1);
        let mut client = Process::spawn(&mut command);
        let reached = cut.reached(&mut client).await;
        client.assert_or_kill(
            reached.is_ok(),
            &format!("undecided retained retry must re-POST: {reached:?}"),
        );
        let (_, mut stream) = reached.unwrap();
        let captured = fx.proxy.captured().await;
        assert_eq!(
            (
                captured.seq,
                captured.id,
                captured.occurrence,
                fx.proxy.body(&captured)
            ),
            (
                old.candidates[0].seq,
                old.candidates[0].id,
                1,
                old.candidates[0].root.clone()
            ),
            "undecided retry must keep its exact original candidate"
        );
        assert_eq!(fx.proxy.release(&captured).await, Ok(200));
        stream.write_all(b"continue\n").await.unwrap();
        client.output().await
    };
    report(&output, EXIT_VERB_DONE, old, "landed");
    let done = fx.client.record().unwrap();
    let mut candidates = old.candidates.clone();
    if !landing {
        // Re-POST consumes another durable attempt and accounts for Accepted.
        candidates[0].evidence.started = 2;
        candidates[0].evidence.last_answered_attempt = 2;
        candidates[0].evidence.decision_seen = true;
    }
    assert_eq!(
        (
            &done.scope,
            &done.volume,
            done.publication_id,
            &done.frozen,
            &done.candidates,
            &done.current
        ),
        (
            &old.scope,
            &old.volume,
            old.publication_id,
            &old.frozen,
            &candidates,
            &None
        ),
        "completion must preserve retained identity, intent and catalogue\n{}",
        diagnostics(&output)
    );
    assert!(
        matches!(&done.phase, Phase::Complete(winner) if winner.id == old.candidates[0].id && winner.seq == old.candidates[0].seq && winner.root == old.candidates[0].root),
        "missing original durable completion: {done:?}"
    );
    let mut order = vec![
        (Recovery, format!("GET {ROOT_PATH}")),
        (Preparation, "GET /volume/alpha/max-seq".into()),
    ];
    if !landing {
        order.extend([
            (Publication, "POST /volume/alpha/publish".into()),
            (Recovery, format!("GET {ROOT_PATH}")),
            (Preparation, "GET /volume/alpha/max-seq".into()),
        ]);
    }
    order.push((Hint, "PUT /volume/alpha/hint".into()));
    assert_eq!(
        oracle::request_trace(fx.responses().strip_prefix(&before).unwrap()),
        Ok((
            (
                usize::from(!landing),
                if landing { 1 } else { 2 },
                if landing { 1 } else { 2 },
                1
            ),
            order
        )),
        "decided recovery probes; undecided recovery re-POSTs the retained tuple\n{}\n{}",
        fx.responses(),
        diagnostics(&output)
    );

    let before = fx.responses();
    let output = Process::spawn(&mut fx.client.command(true)).output().await;
    report(&output, EXIT_VERB_DONE, old, "landed");
    let mut reloaded = fx.client.record().unwrap();
    let generation = reloaded.generation;
    let previous_generation = done.generation;
    let advanced = generation > previous_generation;
    reloaded.generation = previous_generation;
    assert_eq!(
        (
            oracle::request_trace(fx.responses().strip_prefix(&before).unwrap()),
            reloaded,
            advanced
        ),
        (
            Ok(((0, 0, 0, 1), vec![(Hint, "PUT /volume/alpha/hint".into())])),
            done,
            true
        ),
        "completed invocation only repairs the hint and advances the journal generation; no POST; generation {previous_generation} -> {generation}\n{}",
        diagnostics(&output)
    );
    assert_eq!(
        fx.roots().await,
        [(old.candidates[0].seq, old.candidates[0].root.clone())]
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
        "exactly one creation and no outstanding PUTs: {:?}",
        fx.proxy.finished()
    );
    fx.stop().await;
    let records = fx.records();
    assert_eq!(
        (
            records.len(),
            records
                .iter()
                .filter(|r| matches!(r.body(), RecordBody::Decision { .. }))
                .count()
        ),
        (3, 1),
        "one decision, attestation and landed; no successor: {records:?}"
    );
    assert!(
        records
            .iter()
            .all(|record| record.seq() == 1
                && record.body().identity() == records[0].body().identity()),
        "every record must belong to the original decision position and identity: {records:?}"
    );
    assert!(
        oracle::open_log_positions(&records[..2])
            && matches!(records[0].body(), RecordBody::Decision { identity, root_seq, candidate, .. } if identity.candidate_id() == old.candidates[0].id && identity.operation().as_bytes() == old.candidates[0].request.operation && *root_seq == old.candidates[0].seq && candidate.as_bytes() == old.candidates[0].root)
            && matches!(records[1].body(), RecordBody::Attestation { final_root, .. } if final_root.as_bytes() == old.candidates[0].root)
            && matches!(records[2].body(), RecordBody::Landed { identity } if identity.candidate_id() == old.candidates[0].id),
        "completion belongs to the original candidate: {records:?}"
    );
    let posts: Vec<_> = fx
        .notes()
        .lines()
        .filter(|line| line.starts_with("POST "))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        posts,
        vec![exact(old); if landing { 1 } else { 2 }],
        "all POSTs use the retained tuple"
    );
    let replies: Vec<_> = fx
        .responses()
        .lines()
        .filter(|line| line.starts_with("POST "))
        .map(str::to_owned)
        .collect();
    if landing {
        assert_eq!(replies, [accepted(old)]);
    } else {
        assert_eq!(
            replies.len(),
            2,
            "one refused initial POST and one committed retry: {replies:?}"
        );
        assert!(
            replies[0].starts_with("POST /volume/alpha/publish 503 fenced ")
                || replies[0].starts_with("POST /volume/alpha/publish 503 unavailable "),
            "initial fence reply: {replies:?}"
        );
        assert_eq!(replies[1], accepted(old));
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one schedule carries the same durable tuple through fence, refusal and reboot controls"
)]
async fn run(landing: bool) {
    // The record shape fixes the fault ordinal before host startup: Decision,
    // Attestation, Landed. The reached notes and classified log verify it later.
    let ordinal = if landing { 3 } else { 1 };
    let mut honoring = Supervisor {
        prevent: vec![EXIT_FENCED],
        attempts: 0,
    };
    let (mut fx, (created, empty_log)) =
        Supervisor::start(&format!("HostLogAppend:{ordinal}:fail")).await;
    assert_eq!(
        (
            epoch(&fx.state),
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            fx.records().len()
        ),
        (created, empty_log.clone(), 0),
        "first startup must preserve the verb-created log"
    );
    let before = state(&fx.state);
    let output = Process::spawn(&mut verb(&fx.state, "initialise"))
        .output()
        .await;
    verb_result(&output, EXIT_REFUSED, "", "locked by another process");
    assert_eq!(
        state(&fx.state),
        before,
        "lock refusal must not change operator state"
    );

    let (old, fence_state) = if landing {
        let (old, capture, _) = interrupted(&fx).await;
        assert_eq!(
            old.candidates[0].request.epoch,
            created.to_bytes(),
            "client must see the verb's epoch"
        );
        assert_eq!(
            fx.proxy.release(&capture).await,
            Ok(200),
            "original root release must trigger the landing append"
        );
        fx.append_fault_reached(ordinal, None).await;
        (old, state(&fx.state))
    } else {
        let mut command = fx.client.command(false);
        let cut = Rendezvous::arm(&mut command, &fx.client.scratch.0, "dispatch", "after", 1);
        let mut client = Process::spawn(&mut command);
        fx.append_fault_reached(ordinal, Some(&mut client)).await;
        let old = fx
            .client
            .record()
            .expect("first append requires a durable unanswered tuple");
        let bytes = journal(&fx, &old);
        let before = state(&fx.state);
        fx.release_reply();
        let result = cut.reached(&mut client).await;
        client.assert_or_kill(
            result.is_ok(),
            &format!("first-append refusal dispatch cut: {result:?}"),
        );
        let (event, _stream) = result.unwrap();
        assert_eq!(event.id, hex(&old.publication_id));
        let output = client.kill().await;
        assert_eq!(
            output.status.signal(),
            Some(9),
            "client cut after the first-append refusal, before answer accounting\n{}",
            diagnostics(&output)
        );
        unchanged(&fx, &old, &bytes);
        assert_eq!(
            (
                fx.records().len(),
                fx.proxy.pending(),
                fx.roots().await,
                old.candidates[0].request.epoch
            ),
            (0, 0, vec![], created.to_bytes()),
            "first-append control must have no committed decision or backend PUT"
        );
        (old, before)
    };
    assert_eq!(
        (
            old.phase.clone(),
            old.candidates.len(),
            old.candidates[0].evidence.started,
            old.candidates[0].evidence.last_answered_attempt,
            old.candidates[0].evidence.decision_seen
        ),
        (
            Phase::AwaitingAnswer {
                candidate: old.candidates[0].number,
                attempt: 1
            },
            1,
            1,
            0,
            false
        ),
        "fence cut must retain an unanswered tuple: {old:?}"
    );
    let bytes = journal(&fx, &old);
    let log = std::fs::read(fx.state.join("alpha.log")).unwrap();
    if landing {
        fx.release_reply();
    }
    supervisor_controls(&mut fx, &mut honoring, &old, &bytes, ordinal, fence_state).await;
    assert_eq!(
        (
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            fx.records().len(),
            epoch(&fx.state)
        ),
        (log, if landing { 2 } else { 0 }, created),
        "failed append must preserve the pre-fault committed prefix"
    );
    if !landing {
        assert_eq!(
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            empty_log
        );
        initial_trace(&fx, &old, "first-append fence").await;
    }
    unfence_controls(&fx, &old, &bytes).await;
    reboot_without_unfence(&mut fx, &old, &bytes, landing).await;

    let before = state(&fx.state);
    let start = max_time(&times(&fx.state)).0.checked_add(1).unwrap();
    let result = unfence(&fx.state, REBOOT, start).await;
    assert_eq!(
        result,
        (EXIT_VERB_DONE, "clean\n".into(), String::new()),
        "modelled reboot unfence result"
    );
    assert_eq!(marker(&fx.state), RunMarker::Clean);
    let mut expected = before;
    expected
        .iter_mut()
        .find(|(name, _)| name == "MARKER")
        .unwrap()
        .1 = std::fs::read(fx.state.join("MARKER")).unwrap();
    assert_eq!(
        state(&fx.state),
        expected,
        "unfence may only replace the marker"
    );
    unchanged(&fx, &old, &bytes);
    let log = std::fs::read(fx.state.join("alpha.log")).unwrap();
    fx.start(true);
    fx.ready().await;
    assert_eq!(
        (
            epoch(&fx.state),
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            marker(&fx.state)
        ),
        (created, log, RunMarker::Running(REBOOT)),
        "reboot startup must replay the original log and epoch"
    );
    if landing {
        let capture = fx.proxy.captured().await;
        assert_eq!(
            (
                capture.seq,
                capture.id,
                capture.occurrence,
                fx.proxy.body(&capture)
            ),
            (
                old.candidates[0].seq,
                old.candidates[0].id,
                2,
                old.candidates[0].root.clone()
            ),
            "exact second PUT from replay"
        );
        assert_eq!(
            fx.proxy.release(&capture).await,
            Ok(412),
            "replay sees the original root's create-only conflict"
        );
    }
    complete(&mut fx, &old, landing).await;
    assert_eq!(epoch(&fx.state), created);
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn landing_fence_unfence_settles_retained_state() {
    run(true).await;
    stages(
        "retained::landing_fence_unfence_settles_retained_state",
        &[
            "operator-initialise",
            "lock-refusal",
            "unanswered-cut",
            "landing-fence",
            "supervisor-controls",
            "unfence-refusals",
            "time-boundary",
            "reboot-without-unfence",
            "unfence-clean",
            "exact-replay",
            "single-decision",
            "completion-no-post",
        ],
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn first_append_fence_reposts_retained_state() {
    run(false).await;
    stages(
        "retained::first_append_fence_reposts_retained_state",
        &[
            "operator-initialise",
            "lock-refusal",
            "unanswered-cut",
            "first-append-fence",
            "supervisor-controls",
            "unfence-refusals",
            "time-boundary",
            "reboot-without-unfence",
            "unfence-clean",
            "retained-repost",
            "single-decision",
            "completion-no-post",
        ],
    );
}
