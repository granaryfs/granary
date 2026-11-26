// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process restart evidence against a controlled peer and a real authority host.
//! The real composition requires supported Linux storage. Process restart
//! checks reuse the client filesystem model for durability-order proof.
#![cfg(all(unix, feature = "publish-restart-tests"))]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test fixtures and assertions"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "test orchestration uses bounded real runtime timers"
)]

#[path = "publish_restart/abandonment.rs"]
mod abandonment;
#[cfg(feature = "crash-points")]
#[path = "publish_restart/backend.rs"]
mod backend;
#[cfg(feature = "crash-points")]
#[path = "publish_restart/composition.rs"]
mod composition;
#[path = "publish_restart/continuation.rs"]
mod continuation;
#[cfg(feature = "crash-points")]
#[path = "publish_restart/epochs.rs"]
mod epochs;
#[path = "publish_restart/oracle.rs"]
mod oracle;
#[cfg(feature = "crash-points")]
#[path = "publish_restart/retained.rs"]
mod retained;
#[path = "publish_restart/support.rs"]
mod support;
#[cfg(feature = "crash-points")]
#[path = "publish_restart/tails.rs"]
mod tails;
use granary_core::retained_submission::{Phase, Role};
use std::time::Duration;
use support::*;

#[tokio::test]
async fn c0_fresh_load_and_physical_cuts() {
    let physical = physical_registry();
    let mut observed = Vec::new();
    for name in std::iter::once("load".to_owned()).chain(physical) {
        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let old = ready(&fx).await;
            let event = cut(&fx, &name, side, true).await;
            let retained = fx.record().unwrap();
            assert_catalogue(&old, &retained);
            assert_eq!(retained.phase, old.phase);
            assert_eq!(
                retained.generation,
                old.generation
                    + u64::from(
                        name == "scope-sync"
                            || side == "after"
                                && ["temporary-install", "load"].contains(&name.as_str())
                    )
            );
            assert_eq!(event.id, hex(&old.publication_id));
            assert!(
                fx.transcript().is_empty(),
                "fresh barrier preceded by network"
            );
            fx.reset_transcript();
            landed(&fx, &old, true).await;
            observed.push(format!("{name}:{side}"));
        }
        let fx = Fixture::new().await;
        let old = ready(&fx).await;
        fail(&fx, &name, true).await;
        assert_catalogue(&old, &fx.record().unwrap());
        fx.reset_transcript();
        landed(&fx, &old, true).await;
    }
    observe("c0_fresh_load_and_physical_cuts", &observed);
}

#[tokio::test]
async fn c1_begin_retains_before_send_and_ignores_changed_or_deleted_source() {
    let mut observed = Vec::new();
    for side in ["before", "after"] {
        for source in ["original", "changed", "deleted"] {
            let fx = Fixture::new().await;
            let event = cut(&fx, "begin", side, false).await;
            if side == "before" {
                assert!(fx.record().is_none(), "begin before cut already retained");
                assert_unretained_prepare(&fx);
                assert!(
                    fx.peer.lock().unwrap().roots.is_empty(),
                    "POST before successful begin"
                );
                fresh_landed(&fx).await;
            } else {
                let old = fx.record().unwrap();
                assert_prepare(&fx, &old);
                assert_eq!(event.id, hex(&old.publication_id));
                if source == "changed" {
                    std::fs::write(fx.source.join("file"), b"changed source").unwrap();
                }
                if source == "deleted" {
                    std::fs::remove_dir_all(&fx.source).unwrap();
                }
                fx.reset_transcript();
                // Pass the original source path too: resuming must not harvest it.
                let json = run(&mut fx.command(false), 0).await;
                assert_landed_report(&json, &old);
                let after = fx.record().unwrap();
                assert_identity(&old, &after);
                let Phase::Complete(done) = after.phase else {
                    panic!("not complete");
                };
                assert_eq!(
                    done.root, old.frozen.initial_root,
                    "resumed publication reharvested source"
                );
                let mut expected = live_barrier([probe(None)], None);
                expected.extend([post(&old), hint()]);
                assert_eq!(fx.transcript(), expected);
                assert_eq!(
                    fx.peer.lock().unwrap().roots[ROOT_PATH],
                    old.frozen.initial_root
                );
                assert_eq!(fx.peer.lock().unwrap().landings, 1);
            }
        }
        observed.push(format!("begin:{side}"));
    }
    let fx = Fixture::new().await;
    fail(&fx, "begin", false).await;
    assert!(fx.record().is_none());
    observe(
        "c1_begin_retains_before_send_and_ignores_changed_or_deleted_source",
        &observed,
    );
}

#[tokio::test]
async fn c2_probe_started_and_delivery_require_explicit_recovery() {
    let mut observed = Vec::new();
    for name in ["probe-save", "probe-delivered"] {
        for &side in cut_sides(name) {
            let fx = Fixture::new().await;
            let old = ready(&fx).await;
            cut(&fx, name, side, true).await;
            let saved = fx.record().unwrap();
            assert_catalogue(&old, &saved);
            let interrupted = name == "probe-delivered" || side == "after";
            assert_eq!(matches!(saved.phase, Phase::ProbeStarted(_)), interrupted);
            assert_eq!(
                saved.generation,
                old.generation + 2 + u64::from(interrupted)
            );
            assert_eq!(
                fx.transcript(),
                if name == "probe-delivered" {
                    vec![probe(None)]
                } else {
                    vec![]
                }
            );
            fx.reset_transcript();
            if interrupted {
                let json = run(&mut fx.command(true), 5).await;
                assert!(json.contains("explicit recovery required"), "{json}");
                assert!(
                    fx.transcript().is_empty(),
                    "Continue repeated the interrupted probe"
                );
                assert_catalogue(&saved, &fx.record().unwrap());
                let mut cmd = fx.command(true);
                cmd.args(["--recover", &hex(&old.publication_id)]);
                let rendezvous =
                    Rendezvous::arm(&mut cmd, &fx.scratch.0, "probe-result", "after", 1);
                let mut child = Process::spawn(&mut cmd);
                let (_event, _stream) = rendezvous.reached(&mut child).await.unwrap();
                let out = child.kill().await;
                assert_eq!(
                    std::os::unix::process::ExitStatusExt::signal(&out.status),
                    Some(9),
                    "stdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(
                    fx.transcript(),
                    live_barrier([probe(None)], None),
                    "ExplicitRecovery must authorize exactly one new cycle"
                );
            } else {
                landed(&fx, &old, true).await;
            }
            observed.push(format!("{name}:{side}"));
        }
    }
    observe(
        "c2_probe_started_and_delivery_require_explicit_recovery",
        &observed,
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one parameterized probe matrix compares the persisted destination and complete transcript for each response class"
)]
async fn c3_probe_destination_preserves_catalogue_and_owned_completion() {
    let mut observed = Vec::new();
    for scenario in [
        "empty",
        "failed",
        "malformed",
        "oversized",
        "foreign",
        "owned",
    ] {
        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let old = ready(&fx).await;
            let foreign_root = if scenario == "foreign" {
                Some(continuation::foreign(&fx, &old))
            } else {
                None
            };
            {
                let mut s = fx.peer.lock().unwrap();
                match scenario {
                    "failed" => s.probe = ProbeReply::Failed,
                    "malformed" => s.probe = ProbeReply::Malformed,
                    "oversized" => s.probe = ProbeReply::Oversized,
                    "foreign" => s.landings = 1,
                    "owned" => {
                        s.roots
                            .insert(ROOT_PATH.into(), old.candidates[0].root.clone());
                        s.landings = 1;
                    }
                    _ => {}
                }
            }
            cut(&fx, "probe-result", side, true).await;
            let saved = fx.record().unwrap();
            assert_identity(&old, &saved);
            assert_eq!(saved.candidates, old.candidates);
            assert_eq!(saved.last_response, old.last_response);
            if side == "before" {
                assert!(
                    matches!(saved.phase, Phase::ProbeStarted(_)),
                    "{:?}",
                    saved.phase
                );
            } else {
                match scenario {
                    "failed" | "malformed" | "oversized" => assert!(
                        matches!(saved.phase, Phase::Unresolved(_)),
                        "{:?}",
                        saved.phase
                    ),
                    "foreign" => assert_eq!(saved.phase, Phase::Rebase),
                    "empty" => assert_eq!(saved.phase, Phase::Ready),
                    _ => assert!(saved.is_complete()),
                }
            }
            assert_eq!(
                saved.generation,
                old.generation + 3 + u64::from(side == "after")
            );
            let response = match scenario {
                "empty" => probe(None),
                "foreign" => probe(foreign_root.clone()),
                "owned" => probe(Some(old.candidates[0].root.clone())),
                "failed" => request("GET", ROOT_PATH, Vec::new(), 503, Vec::new()),
                "malformed" => probe(Some(b"malformed".to_vec())),
                _ => probe(Some(vec![
                    0;
                    usize::try_from(
                        granary_core::root::ROOT_MAX_BYTES
                    )
                    .unwrap()
                        + 1
                ])),
            };
            let expected = match scenario {
                "empty" => live_barrier([response], None),
                "foreign" | "owned" => live_barrier([response], Some(old.candidates[0].seq)),
                _ => vec![response],
            };
            assert_eq!(fx.transcript(), expected);
            fx.reset_transcript();
            if side == "before" || scenario != "empty" && scenario != "owned" {
                let json = run(&mut fx.command(true), 5).await;
                assert!(json.contains("explicit recovery required"), "{json}");
                assert!(
                    fx.transcript().is_empty(),
                    "unresolved probe continued automatically"
                );
                assert_catalogue(&saved, &fx.record().unwrap());
            } else if scenario == "owned" {
                assert!(
                    saved.is_complete(),
                    "owned probe did not persist completion"
                );
                let json = run(&mut fx.command(true), 0).await;
                assert_landed_report(&json, &old);
                assert_eq!(
                    fx.transcript(),
                    [hint()],
                    "Complete performed catalogue/network publication work"
                );
                let Phase::Complete(done) = saved.phase else {
                    panic!("not complete");
                };
                assert_eq!(done.root, fx.peer.lock().unwrap().roots[ROOT_PATH]);
            } else {
                landed(&fx, &old, true).await;
            }
            observed.push(format!("probe-result:{side}"));
        }
    }
    observed.sort();
    observed.dedup();
    observe(
        "c3_probe_destination_preserves_catalogue_and_owned_completion",
        &observed,
    );
}

#[tokio::test]
async fn c3_empty_retired_slot_blocks_other_target() {
    let fx = Fixture::new().await;
    let old = with_retired_slot(ready(&fx).await);
    fx.install(&old); // Validated setup boundary: creates a second retired tuple.
    let output = Process::spawn(&mut fx.command(true)).output().await;
    assert_catalogue(&old, &fx.record().unwrap());
    let json = assert_exit(&output, 5);
    assert!(
        json.contains("unresolved retired candidate is not at target"),
        "{json}"
    );
    assert_eq!(
        fx.transcript(),
        live_barrier(
            [
                probe(None),
                request(
                    "GET",
                    "/volume/alpha/root/00000000000000000002",
                    Vec::new(),
                    404,
                    Vec::new()
                )
            ],
            None
        )
    );
    assert!(fx.peer.lock().unwrap().roots.is_empty());
    observe("c3_empty_retired_slot_blocks_other_target", &[]);
}

#[test]
fn c3_retired_fixture_roundtrips_with_distinct_epoch_operations() {
    let ready = granary_core::retained_submission::decode(include_bytes!(
        "../../granary-core/tests/vectors/retained-submission/ready.bin"
    ))
    .unwrap();
    let retained = with_retired_slot(ready.clone());
    assert_identity(&ready, &retained);
    assert_eq!(retained.candidates[0], ready.candidates[0]);
    let retired = &retained.candidates[1];
    assert_eq!(retired.role, Role::Retired);
    assert_ne!(retired.request.epoch, ready.candidates[0].request.epoch);
    assert_ne!(
        retired.request.operation,
        ready.candidates[0].request.operation
    );
    assert_eq!(
        granary_core::retained_submission::decode(
            &granary_core::retained_submission::encode(&retained).unwrap()
        )
        .unwrap(),
        retained
    );
    let mut invalid = retained.clone();
    invalid.candidates[1].request.operation = invalid.candidates[0].request.operation;
    assert_eq!(
        granary_core::retained_submission::validate(&invalid),
        Err(granary_core::retained_submission::Error::Invalid(
            "operation crosses epochs"
        ))
    );
    observe(
        "c3_retired_fixture_roundtrips_with_distinct_epoch_operations",
        &[],
    );
}

#[tokio::test]
async fn c4_attempt_and_dispatch_preserve_exact_retry_tuple() {
    let mut observed = Vec::new();
    for name in ["attempt-save", "dispatch"] {
        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let old = ready(&fx).await;
            cut(&fx, name, side, true).await;
            let saved = fx.record().unwrap();
            assert_identity(&old, &saved);
            assert_eq!(saved.current, old.current);
            let mut expected = old.candidates.clone();
            let started = name == "dispatch" || side == "after";
            expected[0].evidence.started = u64::from(started);
            assert_eq!(
                saved.candidates, expected,
                "attempt was not saved before dispatch"
            );
            assert_eq!(saved.last_response, None);
            assert_eq!(matches!(saved.phase, Phase::AwaitingAnswer { .. }), started);
            let sent = name == "dispatch" && side == "after";
            let mut prefix = live_barrier([probe(None)], None);
            if sent {
                prefix.push(post(&old));
            }
            assert_eq!(fx.transcript(), prefix, "dispatch outran the attempt save");
            fx.reset_transcript();
            landed(&fx, &saved, !sent).await;
            let after = fx.record().unwrap();
            assert_eq!(
                after.candidates[0].evidence.started,
                if sent { 1 } else { 1 + u64::from(started) }
            );
            assert_eq!(
                after.candidates[0].evidence.proved_no_write, 0,
                "earlier unanswered attempt lost its uncertainty"
            );
            observed.push(format!("{name}:{side}"));
        }
    }
    observe(
        "c4_attempt_and_dispatch_preserve_exact_retry_tuple",
        &observed,
    );
}

#[test]
fn rendezvous_report_negative_controls() {
    let good = "REACHED begin before 1 33333333333333333333333333333333 ready 1\n";
    let event = Event::parse(good).unwrap();
    event.matches("begin", "before", 1).unwrap();
    for (label, cut, side, occurrence) in [
        ("unknown cut", "unknown", "before", 1),
        ("wrong occurrence", "begin", "before", 2),
        ("wrong side", "begin", "after", 1),
    ] {
        let e = event.matches(cut, side, occurrence).unwrap_err();
        assert!(e.contains("identity mismatch"));
        println!("REFUSED {label}: {e}");
    }
    // A failure request checks the loop's intended side independently of the
    // armed rendezvous, so accidentally arming before twice is refused.
    for name in archive_registry() {
        for (side, wrong) in [("before", "after"), ("after", "before")] {
            let line =
                format!("REACHED {name} {side} 1 33333333333333333333333333333333 ready 2\n");
            let event = Event::parse(&line).unwrap();
            event.matches(&name, side, 1).unwrap();
            let error = event.matches(&name, wrong, 1).unwrap_err();
            assert!(error.contains("identity mismatch"));
            println!("REFUSED archive failure at wrong side {name}:{wrong}: {error}");
        }
    }
    for line in [
        "",
        "REACHED begin before 1",
        "REACHED begin before 0 33333333333333333333333333333333 ready 1",
        "REACHED begin before 1 33333333333333333333333333333333 nonsense 1",
        "REACHED unknown before 1 33333333333333333333333333333333 ready 1",
        "REACHED probe-delivered before 1 33333333333333333333333333333333 probe-started 1\n",
    ] {
        println!(
            "REFUSED malformed report: {}",
            Event::parse(line).unwrap_err()
        );
    }
    for path in ["/nonexistent/gran", "/bin/sh", "gran"] {
        let e = checked_executable(std::path::Path::new(path)).unwrap_err();
        assert!(e.contains("wrong executable path"));
        println!("REFUSED {e}");
    }
    observe("rendezvous_report_negative_controls", &[]);
}

#[tokio::test]
async fn rendezvous_unreachable_negative_control() {
    let fx = Fixture::new().await;
    let mut cmd = fx.command(false);
    let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, "begin", "after", 99);
    let mut child = Process::spawn(&mut cmd);
    let e = rendezvous.reached(&mut child).await.err().unwrap();
    assert!(e.contains("child exit before rendezvous"), "{e}");
    let out = child.output().await;
    assert_exit(&out, 0);
    println!("REFUSED unreachable occurrence: {e}");
    observe("rendezvous_unreachable_negative_control", &[]);
}

#[tokio::test]
async fn rendezvous_exit_and_bound_negative_controls() {
    let scratch = Scratch::new();
    let report = scratch.0.join("report");
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.env_clear()
        .args(["-c", "printf reported > \"$1\"", "sh"])
        .arg(&report);
    let mut child = Process::spawn(&mut cmd);
    let status = child.wait_for_exit(WAIT).await.unwrap();
    tokio::time::pause();
    let result = wait_report(&mut child, WAIT, async {
        tokio::time::sleep(Duration::from_millis(15)).await;
        std::fs::read_to_string(&report).map_err(|error| error.to_string())
    })
    .await;
    tokio::time::resume();
    assert_eq!(
        (status.code(), result),
        (Some(0), Ok("reported".to_owned()))
    );
    println!("OBSERVED file report after clean child exit");

    let mut refused = 0;
    for (script, bound, expected) in [
        ("exit 0", WAIT, "child exit before rendezvous"),
        (
            "exec sleep 2",
            Duration::from_millis(50),
            "rendezvous bound exceeded (50ms)",
        ),
    ] {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.env_clear().args(["-c", script]);
        let mut child = Process::spawn(&mut cmd);
        let error = wait_report(
            &mut child,
            bound,
            std::future::pending::<Result<(), String>>(),
        )
        .await
        .unwrap_err();
        assert_eq!(error, expected);
        println!("REFUSED {error}");
        let output = child.kill().await;
        if script == "exit 0" {
            assert_exit(&output, 0);
        } else {
            assert_eq!(
                std::os::unix::process::ExitStatusExt::signal(&output.status),
                Some(9),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        println!("REAPED child; captured stdout and stderr reached EOF");
        refused += 1;
    }
    assert_eq!(refused, 2);
    #[cfg(feature = "crash-points")]
    composition::append_fault_controls().await;
    observe("rendezvous_exit_and_bound_negative_controls", &[]);
}

#[tokio::test]
async fn c0_c4_physical_occurrences_keep_whole_generations() {
    let mut observed = Vec::new();
    for (stage, occurrence) in [
        ("begin", 1),
        ("selection-load", 1),
        ("resume-load", 2),
        ("probe-save", 3),
        ("probe-result", 4),
        ("attempt-save", 5),
    ] {
        for name in physical_registry() {
            for side in ["before", "after"] {
                let fx = Fixture::new().await;
                let old = if stage == "begin" {
                    None
                } else {
                    Some(ready(&fx).await)
                };
                let event = cut_at(&fx, &name, side, old.is_some(), occurrence).await;
                let installed =
                    name == "scope-sync" || name == "temporary-install" && side == "after";
                let saved = fx.record();
                if let Some(old) = &old {
                    let saved = saved.as_ref().unwrap();
                    assert_identity(old, saved);
                    assert_eq!(event.id, hex(&old.publication_id));
                    assert_eq!(
                        saved.generation,
                        old.generation + occurrence - 1 + u64::from(installed),
                        "{stage} {name} {side}"
                    );
                    assert_eq!(saved.current, old.current);
                    assert_eq!(saved.last_response, old.last_response);
                    let mut catalogue = old.candidates.clone();
                    if stage == "attempt-save" && installed {
                        catalogue[0].evidence.started = 1;
                    }
                    assert_eq!(
                        saved.candidates, catalogue,
                        "torn semantic generation at {stage} {name} {side}"
                    );
                } else {
                    assert_unretained_prepare(&fx);
                    assert_eq!(saved.is_some(), installed);
                    if let Some(saved) = &saved {
                        assert_eq!(event.id, hex(&saved.publication_id));
                        assert_prepare(&fx, saved);
                    }
                }
                if stage == "begin" {
                    assert!(
                        fx.peer.lock().unwrap().roots.is_empty(),
                        "POST before begin"
                    );
                } else {
                    let expected = if occurrence >= 4 {
                        live_barrier([probe(None)], None)
                    } else {
                        vec![]
                    };
                    assert_eq!(
                        fx.transcript(),
                        expected,
                        "network ran before its persistence boundary"
                    );
                }
                fx.reset_transcript();
                match saved {
                    Some(saved) if matches!(saved.phase, Phase::ProbeStarted(_)) => {
                        let json = run(&mut fx.command(true), 5).await;
                        assert!(json.contains("explicit recovery required"), "{json}");
                        assert!(fx.transcript().is_empty());
                        assert_catalogue(&saved, &fx.record().unwrap());
                    }
                    Some(saved) => landed(&fx, &saved, true).await,
                    None => fresh_landed(&fx).await,
                }
                observed.push(format!("{stage}:{name}:{side}:{occurrence}"));
            }
        }
    }
    observe(
        "c0_c4_physical_occurrences_keep_whole_generations",
        &observed,
    );
}

#[tokio::test]
async fn rendezvous_unknown_cut_negative_control() {
    let scratch = Scratch::new();
    let path = std::env::var_os("GRANARY_RESTART_GRAN").expect("explicit instrumented path");
    checked_executable(std::path::Path::new(&path)).unwrap();
    for cut in ["unknown", "probe-delivered"] {
        let mut cmd = std::process::Command::new(&path);
        cmd.env_clear()
            .env("HOME", &scratch.0)
            .env("GRANARY_RESTART_SOCKET", scratch.0.join("unused.sock"))
            .env("GRANARY_RESTART_CUT", cut)
            .env("GRANARY_RESTART_SIDE", "before")
            .env("GRANARY_RESTART_OCCURRENCE", "1")
            .arg("--help");
        let output = Process::spawn(&mut cmd).output().await;
        assert_exit(&output, 1);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("invalid restart rendezvous selection"),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("REFUSED {cut}:before before connecting");
    }
    observe("rendezvous_unknown_cut_negative_control", &[]);
}

#[tokio::test]
async fn rendezvous_continue_and_invalid_reply_controls() {
    use tokio::io::AsyncWriteExt as _;
    for valid in [true, false] {
        let fx = Fixture::new().await;
        let mut cmd = fx.command(false);
        let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, "begin", "after", 1);
        let mut child = Process::spawn(&mut cmd);
        let (_, mut stream) = rendezvous.reached(&mut child).await.unwrap();
        let retained = fx.record().unwrap();
        assert_prepare(&fx, &retained);
        let mut expected = fx.transcript();
        stream
            .write_all(if valid { b"continue\n" } else { b"invalid\n" })
            .await
            .unwrap();
        let output = child.output().await;
        let json = assert_exit(&output, i32::from(!valid));
        if valid {
            assert_landed_report(&json, &retained);
            expected.extend(live_barrier([probe(None)], None));
            expected.extend([post(&retained), hint()]);
            assert_eq!(fx.peer.lock().unwrap().landings, 1);
        } else {
            assert_eq!(fx.record().unwrap(), retained);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                json.is_empty() && stderr.contains("rendezvous protocol error"),
                "stdout: {json}\nstderr: {stderr}"
            );
            println!("REFUSED invalid parent reply as a protocol error");
        }
        assert_eq!(fx.transcript(), expected);
    }
    observe("rendezvous_continue_and_invalid_reply_controls", &[]);
}

#[tokio::test]
async fn rendezvous_nonfallible_fail_negative_control() {
    use tokio::io::AsyncWriteExt as _;
    for name in ["dispatch", "probe-delivered"] {
        for &side in cut_sides(name) {
            let fx = Fixture::new().await;
            ready(&fx).await;
            let mut cmd = fx.command(true);
            let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, name, side, 1);
            let mut child = Process::spawn(&mut cmd);
            let (_, mut stream) = rendezvous.reached(&mut child).await.unwrap();
            let retained = fx.record().unwrap();
            let transcript = fx.transcript();
            stream.write_all(b"fail\n").await.unwrap();
            let output = child.output().await;
            let json = assert_exit(&output, 1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                json.is_empty()
                    && stderr.contains("rendezvous protocol error")
                    && stderr.contains(name),
                "stdout: {json}\nstderr: {stderr}"
            );
            assert_eq!(fx.record().unwrap(), retained);
            assert_eq!(
                fx.transcript(),
                transcript,
                "network continued after protocol error"
            );
            println!("REFUSED fail at {name}:{side} as a protocol error");
        }
    }
    observe("rendezvous_nonfallible_fail_negative_control", &[]);
}
