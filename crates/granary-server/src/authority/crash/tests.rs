// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::Site;

/// `ALL` lists every site once, in declaration order, and each name
/// parses back.
#[test]
fn every_site_is_listed_in_order() {
    for (i, site) in Site::ALL.into_iter().enumerate() {
        assert_eq!(site as usize, i, "{site:?}");
        assert_eq!(Site::parse(&site.name()), Some(site));
    }
    assert_eq!(Site::ALL.len(), Site::PutReturned as usize + 1);
}

#[test]
fn host_operation_hold_requires_release_and_delivers_failure() {
    use super::{HostPlan, HostSite, INSTALLED, Plan, host_io, install};
    use std::sync::mpsc;
    use std::time::Duration;
    let dir = crate::protected_dir::tests::scratch("host-handshake");
    let pipe = dir.join("reached");
    let release = dir.join("release");
    install(&pipe, Plan::List).unwrap();
    INSTALLED.lock().unwrap().as_mut().unwrap().host = Some(HostPlan {
        site: HostSite::LogRead,
        hits: 0,
        k: 2,
        release: release.clone(),
        fail: true,
        worker: false,
    });
    assert_eq!(host_io(HostSite::LogRead), Ok(()), "first call must pass");
    let (done, result) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        done.send(host_io(HostSite::LogRead)).unwrap();
    });
    let (_keep, wait) = mpsc::channel::<()>();
    let reached = (0..100).any(|_| {
        if std::fs::read_to_string(&pipe)
            .unwrap()
            .contains("REACHED HostLogRead 2")
        {
            return true;
        }
        let _elapsed = wait.recv_timeout(Duration::from_millis(10));
        false
    });
    assert!(reached, "no reached evidence");
    std::fs::write(&release, b"wrong").unwrap();
    assert_eq!(
        result.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    std::fs::write(&release, b"release").unwrap();
    assert_eq!(
        result.recv_timeout(Duration::from_secs(2)).unwrap(),
        Err(granary_core::decisionlog::LogIoError::SyncFailed)
    );
    worker.join().unwrap();
    assert!(
        std::fs::read_to_string(&pipe)
            .unwrap()
            .contains("RELEASED HostLogRead")
    );
    assert_eq!(
        host_io(HostSite::LogRead),
        Ok(()),
        "only the selected call fails"
    );
    *INSTALLED.lock().unwrap() = None;
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reply_plan_never_fabricates_a_failure() {
    use super::{HostSite, valid_host_plan};
    assert!(valid_host_plan(HostSite::Reply, 1, false, false));
    assert!(
        !valid_host_plan(HostSite::Reply, 1, true, false),
        "infallible reply plan admitted synthetic failure"
    );
    assert!(!valid_host_plan(HostSite::Reply, 0, false, false));
    assert!(!valid_host_plan(HostSite::Reply, 1, false, true));
    assert!(valid_host_plan(HostSite::LogRead, 1, true, false));
}

#[path = "../../../tests/publish_restart/process.rs"]
#[expect(
    dead_code,
    reason = "integration-only process operations are shared with these controls"
)]
mod process;

#[test]
fn fixture_root_is_created_before_canonicalization() {
    let scratch = process::Scratch::new();
    let dir = &scratch.0;
    let missing = dir.join("fresh-target");
    let result = process::prepare_root(&missing);
    assert!(
        result
            .as_ref()
            .is_ok_and(|path| path.is_absolute() && path.is_dir()),
        "missing fixture root must be created and canonical: {result:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn host_exit_bound_outlasts_the_drain() {
    assert!(
        process::HOST_EXIT > process::HOST_DRAIN,
        "host exit must outlast its drain: exit={:?}, drain={:?}",
        process::HOST_EXIT,
        process::HOST_DRAIN
    );
}

#[tokio::test]
async fn host_log_has_no_pipes_and_survives_failure() {
    let scratch = process::Scratch::new();
    let dir = &scratch.0;
    let log = dir.join("host.log");
    let mut command = std::process::Command::new("/bin/sh");
    command.args([
        "-c",
        "printf 'host stdout\\n'; printf 'host stderr\\n' >&2; exit 2",
    ]);
    let child = process::Process::spawn_logged(&mut command, &log);
    let output = child.host_output().await;
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        (
            output.status.code(),
            output.stdout.is_empty(),
            diagnostics.contains("host stdout"),
            diagnostics.contains("host stderr")
        ),
        (Some(2), true, true, true),
        "host output must avoid pipes and retain both streams on failure: {diagnostics}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one table checks every dispatch/drain provenance boundary"
)]
async fn dispatch_loss_requires_a_dispatched_submission_and_reply_timeout() {
    use crate::authority::tests::{submission, vol};
    use crate::authority::{Answer, AuthorityHandle, HandleInner, Shared, worker::Request};
    use std::collections::BTreeMap;
    use std::future::Future as _;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot, watch};
    let scratch = process::Scratch::new();
    let dir = &scratch.0;
    for schedule in [
        "already-draining",
        "full-timeout",
        "full-draining",
        "reply-draining",
        "reply-timeout",
        "stopped",
        "closed",
        "unconfigured",
    ] {
        let pipe = dir.join(schedule);
        super::install(&pipe, super::Plan::List).unwrap();
        let (inbox, mut queued) = mpsc::channel(1);
        let (_end, ended) = watch::channel(None);
        let shared = Arc::new(Shared::default());
        if schedule == "stopped" {
            shared.stop.request();
        }
        if schedule == "closed" {
            queued.close();
        }
        if schedule.starts_with("full-") {
            let (reply, _answer) = oneshot::channel();
            inbox
                .try_send(Request::Report {
                    bound: Duration::ZERO,
                    reply,
                })
                .unwrap();
        }
        let handle = AuthorityHandle {
            inner: Arc::new(HandleInner {
                shared,
                ended,
                views: BTreeMap::new(),
                inboxes: if schedule == "unconfigured" {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(vol("vol-a"), inbox)])
                },
            }),
        };
        let (drain, mut draining) = watch::channel(schedule == "already-draining");
        let wait = crate::adapter::publication_reply(
            &handle,
            submission(&vol("vol-a"), 1, b"candidate"),
            &mut draining,
            Some(Duration::from_millis(1)),
        );
        let mut wait = pin!(wait);
        if schedule.ends_with("-draining") && schedule != "already-draining" {
            assert!(
                matches!(
                    wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                ),
                "{schedule}: submission wait must be pending before draining"
            );
            drain.send(true).unwrap();
        }
        let answer = wait.await;
        let notes = std::fs::read_to_string(&pipe).unwrap();
        let post_count = notes
            .lines()
            .filter(|line| line.starts_with("POST "))
            .count();
        let loss_count = notes
            .lines()
            .filter(|line| *line == "GATEWAY post-dispatch unavailable")
            .count();
        let expected_answer = match schedule {
            "stopped" | "closed" => Some(Answer::Stopped),
            "unconfigured" => Some(Answer::UnconfiguredVolume),
            _ => None,
        };
        let expected_queue =
            usize::from(schedule.starts_with("full-") || schedule.starts_with("reply-"));
        let expected_post = usize::from(schedule.starts_with("reply-"));
        let expected_loss = usize::from(schedule == "reply-timeout");
        assert_eq!(
            (answer, queued.len(), post_count, loss_count),
            (
                expected_answer,
                expected_queue,
                expected_post,
                expected_loss
            ),
            "{schedule}: dispatch and timeout provenance must agree; notes={notes}"
        );
    }
    *super::INSTALLED.lock().unwrap() = None;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    clippy::too_many_lines,
    reason = "the real log and worker concurrency exercise the committed-reply boundary outside the simulator"
)]
async fn reply_hold_counts_only_a_decision_committed_by_this_submission() {
    use crate::authority::tests::{
        FixedClock, TestStore, YieldPause, boot, configs, good_root, rng, secure, submission_at,
        vol,
    };
    use crate::authority::{Answer, AuthorityParts, FileLog, start};
    use granary_sim::fakes::{Faults, Sim};
    let scratch = process::Scratch::new();
    let dir = &scratch.0;
    let authority_dir = dir.join("state");
    std::fs::create_dir(&authority_dir).unwrap();
    crate::protected_dir::tests::chmod(&authority_dir, 0o700);
    let volume = vol("vol-a");
    let store = TestStore::new(Sim::new().node(1, Faults::none()));
    store.hold_read(&volume, 1);
    let (handle, driver) = start(
        AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: FileLog::new(&authority_dir, true).unwrap(),
            store: store.clone(),
            clock: FixedClock,
            rng: rng(1),
            secure_random: secure(1),
            pause: YieldPause,
        },
        boot(1),
        configs(std::slice::from_ref(&volume)),
    )
    .await
    .unwrap();
    let running = tokio::spawn(driver.run());
    let initialised = handle.initialise(&volume).await.unwrap();
    let epoch = match initialised {
        crate::authority::Initialised::Created { epoch }
        | crate::authority::Initialised::Kept { epoch } => epoch,
    };
    let pipe = dir.join("notes");
    let release = dir.join("release");
    super::install(&pipe, super::Plan::List).unwrap();
    super::INSTALLED.lock().unwrap().as_mut().unwrap().host = Some(super::HostPlan {
        site: super::HostSite::Reply,
        hits: 0,
        k: 1,
        release: release.clone(),
        fail: false,
        worker: false,
    });
    std::fs::write(&release, b"release").unwrap();
    let invalid = handle
        .submit(submission_at(epoch, &volume, 1, b"invalid"))
        .await;
    let stale = handle
        .submit(submission_at(
            epoch,
            &volume,
            2,
            &good_root(
                &volume,
                2,
                Some(granary_core::hash::GrainId::of(b"foreign")),
                1,
            ),
        ))
        .await;
    let hits = || {
        super::INSTALLED
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .host
            .as_ref()
            .unwrap()
            .hits
    };
    assert_eq!(
        (
            matches!(invalid, Answer::InvalidCandidate(_)),
            matches!(stale, Answer::StaleBase { .. }),
            hits()
        ),
        (true, true, 0),
        "non-committing answers must pass without counting: {invalid:?}, {stale:?}"
    );
    let candidate = submission_at(epoch, &volume, 3, &good_root(&volume, 1, None, 1));
    let accepted = handle.submit(candidate.clone()).await;
    let retry = handle.submit(candidate).await;
    let notes = std::fs::read_to_string(&pipe).unwrap();
    assert_eq!(
        (
            matches!(accepted, Answer::Accepted { .. }),
            matches!((&accepted, &retry), (Answer::Accepted { position: first, candidate_id: candidate }, Answer::Open { position: second, candidate_id: retried }) if first == second && candidate == retried),
            hits(),
            notes.contains("REACHED HostReply 1")
        ),
        (true, true, 1, true),
        "a fresh decision counts once; its accepted retry writes nothing: {accepted:?}, {retry:?}, {notes}"
    );
    store.release();
    let stopped = handle.stop().await;
    assert_eq!(running.await.unwrap(), stopped);
    *super::INSTALLED.lock().unwrap() = None;
    std::fs::remove_dir_all(dir).unwrap();
}
