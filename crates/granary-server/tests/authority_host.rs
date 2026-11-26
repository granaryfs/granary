// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shipped authority binary evidence. Credentials belong to this test's
//! rustls peer, not to the production client credential loader. Linux arms
//! compile everywhere on Unix but require the real kernel boot ID to run.
//! The ext4 venue sets `GRANARY_HOST_EXT4` so no filesystem waiver is used.
#![cfg_attr(
    all(unix, feature = "crash-points"),
    expect(
        clippy::disallowed_macros,
        reason = "two finite fixtures poll a driver and its stop or CLI side together (each marked at its join!); tokio 1.53.3's join! expands through an inner $crate::join! that clippy reports at the crate, so a statement-level expect cannot cover it"
    )
)]
#![cfg(all(unix, feature = "crash-points"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test fixtures and assertions"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "process orchestration waits and the test Pause implementation use real runtime timers"
)]

#[path = "support_export/fixture.rs"]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod export_fixture;
#[path = "process/output.rs"]
mod output;
mod process;
#[path = "authority_host/support.rs"]
mod support;
use granary_core::runmarker::RunMarker;
use granary_net::accept::SHUTDOWN_DEADLINE;
use granary_server::{EXIT_DEADLINE_EXPIRED, EXIT_DRAINED, EXIT_FENCED, EXIT_STARTUP_FAILED};
use output::CommandExt as _;
use std::time::Duration;
use support::*;
use tokio::io::AsyncWriteExt as _;

// A five-second scheduling tolerance is separate from the shipped ten-second
// budget. No test sets or overrides the host's shutdown budget.
const EXIT_BOUND: Duration = Duration::from_secs(15);

fn assert_refusal(process: &Process, reasons: &[&str]) {
    let stderr = process.output();
    for expected in std::iter::once("startup failed:").chain(reasons.iter().copied()) {
        assert!(stderr.contains(expected), "missing {expected}: {stderr}");
    }
}

#[tokio::test]
async fn process_exit_waits_for_stderr_eof() {
    let stderr = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let buffer = stderr.clone();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (held, locked) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let _guard = buffer.lock().unwrap();
        held.send(()).unwrap();
        let _released = released.recv_timeout(EXIT_BOUND);
    });
    locked.recv_timeout(WAIT).unwrap();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.env_clear().args(["-c", "printf 'stderr tail\\n' >&2"]);
    let mut process = Process::spawn_with_stderr(&mut cmd, stderr);
    // Reap first to prove any subsequent wait is for the reader, whose
    // buffer is held above, rather than for the child to finish running.
    let status = tokio::time::timeout(WAIT, async {
        loop {
            if let Some(status) = process.child.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(status.success());
    let mut exiting = Box::pin(process.exit(0, WAIT));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut exiting)
            .await
            .is_err(),
        "exit returned while the stderr reader was still blocked"
    );
    release.send(()).unwrap();
    exiting.await;
    blocker.join().unwrap();
    assert_eq!(process.output(), "stderr tail\n");
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn every_host_refusal_carries_its_reason_under_parallel_spawns() {
    // Build first, then spawn every child before collecting any: the exits
    // must contend to expose a reason left queued in the lossy sink.
    let fixtures: Vec<_> = (0..32).map(|_| Fixture::new(0)).collect();
    let mut processes: Vec<_> = fixtures
        .iter()
        .map(|fx| {
            let mut cmd = fx.command();
            cmd.env("GRANARY_AUTHORITY_ENROLLMENT_DIR", &fx.state);
            Process::spawn(&mut cmd)
        })
        .collect();
    for process in &mut processes {
        process.exit(EXIT_STARTUP_FAILED, EXIT_BOUND).await;
        assert_refusal(
            process,
            &[
                "GRANARY_AUTHORITY_STATE_DIR",
                "GRANARY_AUTHORITY_ENROLLMENT_DIR",
            ],
        );
    }
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn replay_of_later_volume_precedes_bind_and_readiness() {
    let fx = Fixture::new(64); // 192 valid records per volume.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reserved.local_addr().unwrap();
    drop(reserved);
    let mut cmd = fx.command();
    cmd.env("GRANARY_LISTEN", addr.to_string());
    fx.plan(&mut cmd, "HostLogRead", 2, false);
    let mut process = Process::spawn(&mut cmd);
    fx.reached("REACHED HostLogRead 2").await;
    for _ in 0..10 {
        process.not_ready(addr);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    fx.release();
    assert_eq!(process.ready().await, addr);
    fx.seed_read(addr).await;
    fx.read(addr).await;
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
    assert_eq!(fx.marker(), RunMarker::Clean);
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn signal_during_held_startup_never_serves() {
    let fx = Fixture::new(64);
    let mut cmd = fx.command();
    fx.plan(&mut cmd, "HostLogRead", 2, false);
    let mut process = Process::spawn(&mut cmd);
    fx.reached("REACHED HostLogRead 2").await;
    process.signal("TERM");
    tokio::time::sleep(Duration::from_millis(100)).await;
    fx.release();
    process.exit(EXIT_DRAINED, WAIT).await;
    assert!(!process.output().contains("listening"));
    assert_eq!(fx.marker(), RunMarker::Clean);
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn hung_flush_keeps_http_live_and_exits_without_runtime_destruction() {
    let fx = Fixture::new(0);
    let candidate = fx.candidate().await;
    let mut cmd = fx.command();
    fx.plan(&mut cmd, "HostLogAppend", 1, false);
    cmd.env("GRANARY_TEST_HOST_WORKER", "hold");
    let mut process = Process::spawn(&mut cmd);
    let addr = process.ready().await;
    fx.reached("REACHED RuntimeWorker 1").await;
    fx.seed_read(addr).await;
    let mut peer = fx.connect(addr, Some(&fx.peer)).await;
    candidate.seed(&mut peer).await;
    peer.submit(&candidate.root).await;
    fx.reached("REACHED HostLogAppend 1").await;
    fx.read(addr).await; // A 200 response while the actual log thread is blocked.
    process.signal("TERM");
    process
        .exit(
            EXIT_DEADLINE_EXPIRED,
            SHUTDOWN_DEADLINE + Duration::from_secs(5),
        )
        .await;
    assert!(matches!(fx.marker(), RunMarker::Running(_)));
    assert!(fx.notes().contains("FORWARD draining=true deadline=10"));
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn append_fence_outranks_pending_transport_drain() {
    let fx = Fixture::new(0);
    let candidate = fx.candidate().await;
    let mut cmd = fx.command();
    fx.plan(&mut cmd, "HostLogAppend", 1, true);
    let mut process = Process::spawn(&mut cmd);
    let addr = process.ready().await;
    let mut peer = fx.connect(addr, Some(&fx.peer)).await;
    candidate.seed(&mut peer).await;
    peer.submit(&candidate.root).await;
    fx.reached("REACHED HostLogAppend 1").await;
    // Accepted but incomplete TLS handshake: transport drain remains owed.
    let _pending = tokio::net::TcpStream::connect(addr).await.unwrap();
    fx.seed_read(addr).await;
    fx.read(addr).await;
    fx.release();
    process.exit(EXIT_FENCED, EXIT_BOUND).await;
    assert!(matches!(fx.marker(), RunMarker::Running(_)));
    assert!(fx.notes().contains("FORWARD draining=true deadline=10"));
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn final_clean_write_failure_is_a_fence() {
    let fx = Fixture::new(0);
    let mut cmd = fx.command();
    fx.plan(&mut cmd, "HostMarkerWrite", 2, true);
    let mut process = Process::spawn(&mut cmd);
    let addr = process.ready().await;
    fx.seed_read(addr).await;
    fx.read(addr).await;
    let _pending = tokio::net::TcpStream::connect(addr).await.unwrap();
    process.signal("INT");
    fx.reached("REACHED HostMarkerWrite 2").await;
    fx.release();
    process.exit(EXIT_FENCED, EXIT_BOUND).await;
    assert!(matches!(fx.marker(), RunMarker::Running(_)));
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn signals_drain_inflight_body_and_write_clean() {
    for signal in ["TERM", "INT"] {
        let fx = Fixture::new(0);
        let mut cmd = fx.command();
        fx.plan(&mut cmd, "HostMarkerWrite", 99, false);
        let mut process = Process::spawn(&mut cmd);
        let addr = process.ready().await;
        fx.seed_read(addr).await;
        std::fs::write(fx.dir.join("reached"), b"").unwrap();
        let mut peer = fx.connect(addr, Some(&fx.peer)).await;
        peer.send(
            "POST",
            "/volume/alpha/publish",
            &[
                ("granary-epoch", EPOCH.as_bytes()),
                ("granary-operation", b"01"),
            ],
            b"x",
            300,
        )
        .await;
        // Prove the request got as far as its body wait before signalling.
        fx.reached("BODY_WAIT").await;
        process.signal(signal);
        let response = peer.response().await;
        assert_eq!(response.status, 503, "{response:?}");
        drop(peer);
        process.exit(EXIT_DRAINED, WAIT).await;
        assert_eq!(fx.marker(), RunMarker::Clean);
        assert!(fx.notes().contains("FORWARD draining=true deadline=10"));
    }
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn post_start_bind_failure_cleans_up() {
    let fx = Fixture::new(0);
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cmd = fx.command();
    let listen = busy.local_addr().unwrap().to_string();
    cmd.env("GRANARY_LISTEN", &listen);
    let mut process = Process::spawn(&mut cmd);
    process.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(&process, &[&format!("GRANARY_LISTEN={listen:?}: ")]);
    assert!(!process.output().contains("listening"));
    assert_eq!(fx.marker(), RunMarker::Clean);
    drop(busy);
    let mut next = Process::spawn(&mut fx.command());
    next.ready().await;
    next.signal("TERM");
    next.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn listen_resolution_failure_precedes_marker_admission() {
    let fx = Fixture::new(0);
    let before = fx.state_bytes();
    let mut cmd = fx.command();
    cmd.env("GRANARY_LISTEN", "localhost:not-a-port");
    fx.plan(&mut cmd, "HostMarkerWrite", 99, false);
    let mut process = Process::spawn(&mut cmd);
    process.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(&process, &["GRANARY_LISTEN=\"localhost:not-a-port\": "]);
    assert!(!process.output().contains("listening"));
    assert_eq!(fx.state_bytes(), before);
    assert!(fx.notes().is_empty(), "engine ran: {}", fx.notes());
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn empty_client_ca_refusal_names_its_variable_and_path() {
    let fx = Fixture::new(0);
    let ca = fx.dir.join("ca.pem");
    std::fs::write(&ca, b"").unwrap();
    let mut process = Process::spawn(&mut fx.command());
    process.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(
        &process,
        &[
            "GRANARY_AUTHORITY_CLIENT_CA",
            ca.to_str().unwrap(),
            "the client ca holds no certificate",
        ],
    );
    assert!(!process.output().contains("GRANARY_TLS_CERT"));
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn kernel_boot_id_and_unclean_same_boot_restart() {
    let fx = Fixture::new(0);
    let mut process = Process::spawn(&mut fx.command());
    process.ready().await;
    let kernel = std::fs::read("/proc/sys/kernel/random/boot_id").unwrap();
    assert_eq!(
        fx.marker(),
        RunMarker::Running(granary_server::parse_boot_id(&kernel).unwrap())
    );
    process.signal("KILL");
    drop(process);
    let before = fx.state_bytes();
    let mut next = Process::spawn(&mut fx.command());
    next.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(&next, &["the run marker says running in this boot"]);
    assert_eq!(fx.state_bytes(), before);
    assert!(!next.output().contains("listening"));
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn directory_identity_refusal_precedes_marker_admission() {
    for alternate in [false, true] {
        let fx = Fixture::new(0);
        let before = fx.state_bytes();
        let mut cmd = fx.command();
        cmd.env(
            "GRANARY_AUTHORITY_ENROLLMENT_DIR",
            if alternate {
                std::path::PathBuf::from(format!("{}/", fx.state.display()))
            } else {
                fx.state.clone()
            },
        );
        let mut process = Process::spawn(&mut cmd);
        process.exit(EXIT_STARTUP_FAILED, WAIT).await;
        assert_refusal(
            &process,
            &[
                "GRANARY_AUTHORITY_STATE_DIR",
                "GRANARY_AUTHORITY_ENROLLMENT_DIR",
            ],
        );
        assert_eq!(fx.state_bytes(), before);
        assert!(!process.output().contains("listening"));
    }
    let fx = Fixture::new(0); // distinct identities are the positive control.
    let mut process = Process::spawn(&mut fx.command());
    process.ready().await;
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[ignore = "requires authority venue's second bind mount at /alias"]
async fn bind_alias_identity_refusal() {
    let fx = Fixture::new(0);
    let relative = fx.state.strip_prefix("/venue").unwrap();
    let alias = std::path::Path::new("/alias").join(relative);
    let before = fx.state_bytes();
    let mut cmd = fx.command();
    cmd.env("GRANARY_AUTHORITY_ENROLLMENT_DIR", &alias);
    let mut process = Process::spawn(&mut cmd);
    process.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(
        &process,
        &[
            "GRANARY_AUTHORITY_STATE_DIR",
            "GRANARY_AUTHORITY_ENROLLMENT_DIR",
        ],
    );
    assert_eq!(fx.state_bytes(), before);
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn protection_missing_directory_and_competing_owner_refuse() {
    let fx = Fixture::new(0);
    let before = fx.state_bytes();
    for (name, path) in [
        ("GRANARY_AUTHORITY_STATE_DIR", fx.dir.join("missing")),
        ("GRANARY_AUTHORITY_ENROLLMENT_DIR", fx.dir.join("missing")),
    ] {
        let mut cmd = fx.command();
        cmd.env(name, path);
        let mut process = Process::spawn(&mut cmd);
        process.exit(EXIT_STARTUP_FAILED, WAIT).await;
        assert_refusal(&process, &[name]);
        assert_eq!(fx.state_bytes(), before);
    }
    chmod(&fx.state, 0o770);
    let mut process = Process::spawn(&mut fx.command());
    process.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(
        &process,
        &["GRANARY_AUTHORITY_STATE_DIR", "gives group or other access"],
    );
    chmod(&fx.state, 0o700);
    assert_eq!(fx.state_bytes(), before);
    let lock = granary_server::FileLog::new(&fx.state, fx.accept_unsupported).unwrap();
    let mut process = Process::spawn(&mut fx.command());
    process.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(
        &process,
        &[
            "GRANARY_AUTHORITY_STATE_DIR",
            "is locked by another process",
        ],
    );
    assert_eq!(fx.state_bytes(), before);
    drop(lock);
    let mut process = Process::spawn(&mut fx.command());
    process.ready().await;
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn enrolled_gateway_keys_inventory_and_shared_store() {
    let fx = Fixture::new(0);
    let candidate = fx.candidate().await;
    std::fs::remove_file(fx.state.join("beta.log")).unwrap();
    let mut process = Process::spawn(&mut fx.command());
    let addr = process.ready().await;
    fx.seed_read(addr).await;
    fx.read(addr).await;
    let before = fx.state_bytes();
    for (method, path) in [
        ("POST", "/volume/alpha/publish".to_owned()),
        ("PUT", "/volume/alpha/root/00000000000000000001".to_owned()),
        ("PUT", "/volume/alpha/hint".to_owned()),
        (
            "PUT",
            format!(
                "/volume/alpha/meta/{}",
                granary_core::hash::GrainId::of(b"m")
            ),
        ),
        ("PUT", format!("/bin/{}", "11".repeat(32))),
    ] {
        let mut peer = fx.connect(addr, None).await;
        let response = peer.request(method, &path, &[], &[]).await;
        assert_eq!(response.status, 403, "{response:?}");
        assert!(response.head.contains("no-principal"));
    }
    for name in ["alpha", "beta"] {
        let mut peer = fx.connect(addr, Some(&fx.peer)).await;
        let response = peer
            .request(
                "PUT",
                &format!("/volume/{name}/root/00000000000000000001"),
                &[],
                &[],
            )
            .await;
        assert_eq!(response.status, 403, "{response:?}");
        assert!(response.head.contains("authority-managed"));
    }
    // The same signed candidate can land once its references are available.
    let mut peer = fx.connect(addr, Some(&fx.other)).await;
    let mut cases = 0;
    for (seeded, expected) in [(false, (400, true)), (true, (202, false))] {
        if seeded {
            assert!(candidate.seed(&mut peer).await > 0);
            let stranger = granary_store::crypto::SigningKey::from_seed(&[0x44; 32]).unwrap();
            let signed = sign_root(
                granary_core::root::decode_root(&candidate.root).unwrap(),
                &stranger,
            );
            let mut other_peer = fx.connect(addr, Some(&fx.peer)).await;
            let response = other_peer.publish(&signed, 1).await;
            let invalid = response
                .head
                .lines()
                .any(|line| line == "granary-error: invalid-candidate");
            assert_eq!((response.status, invalid), (400, true), "{response:?}");
            assert_eq!(fx.state_bytes(), before);
        }
        let response = peer.publish(&candidate.root, 2).await;
        let missing = response
            .head
            .lines()
            .any(|line| line == "granary-error: missing-reference");
        assert_eq!(
            (response.status, missing),
            expected,
            "seeded={seeded}: {response:?}"
        );
        if !seeded {
            assert_eq!(fx.state_bytes(), before);
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
    let mut anonymous = fx.connect(addr, None).await;
    let response = tokio::time::timeout(WAIT, async {
        loop {
            let response = anonymous
                .request("GET", "/volume/alpha/root/00000000000000000001", &[], &[])
                .await;
            if response.status == 200 {
                break response;
            }
            assert_eq!(response.status, 404, "{response:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, candidate.root);
    drop((peer, anonymous));
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
    assert!(!fx.state.join("beta.log").exists());
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn enrollment_revocation_on_one_connection_and_shared_controls() {
    let fx = Fixture::new(0);
    let candidate = fx.candidate().await;
    let mut cmd = fx.command();
    cmd.env("GRANARY_AUTHORITY_CONTROLS", "4,4,33554432,268435456,1");
    fx.plan(&mut cmd, "HostMarkerWrite", 99, false);
    let mut process = Process::spawn(&mut cmd);
    let addr = process.ready().await;
    let mut peer = fx.connect(addr, Some(&fx.peer)).await;
    let body = &candidate.root;
    peer.send(
        "POST",
        "/volume/alpha/publish",
        &[
            ("granary-epoch", EPOCH.as_bytes()),
            ("granary-operation", b"01"),
        ],
        &[],
        body.len(),
    )
    .await;
    fx.reached("BODY_WAIT").await;
    let mut second = fx.connect(addr, Some(&fx.peer)).await;
    let response = second.publish(&[], 3).await;
    assert_eq!(response.status, 429, "process-owned controls: {response:?}");
    let mut other = fx.connect(addr, Some(&fx.other)).await;
    candidate.seed(&mut other).await;
    let response = other.publish(body, 4).await;
    assert_eq!(
        response.status, 202,
        "other principal must progress: {response:?}"
    );
    peer.stream.write_all(body).await.unwrap();
    let _completed = peer.response().await;
    granary_server::revoke(&fx.enrollment, OPTIONS, fx.peer.digest()).unwrap();
    let response = peer.publish(&[], 5).await;
    assert_eq!(
        response.status, 403,
        "current enrollment precedes controls: {response:?}"
    );
    let response = peer
        .request("GET", "/volume/alpha/root/00000000000000000001", &[], &[])
        .await;
    assert_eq!(response.status, 200);
    drop((peer, second, other));
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn invalid_presented_certificate_fails_tls() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let fx = Fixture::new(0);
    let rogue = Fixture::new(0);
    let mut process = Process::spawn(&mut fx.command());
    let addr = process.ready().await;
    fx.seed_read(addr).await;
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let attempt = tokio::time::timeout(
        WAIT,
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(fx.client(Some(&rogue.peer))))
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            ),
    )
    .await
    .unwrap();
    // TLS 1.3's client may finish its local handshake before it reads the
    // server's rejection of the client certificate. Neither arm may serve.
    if let Ok(mut stream) = attempt {
        let _sent = stream
            .write_all(b"GET /volume/probe/max-seq HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await;
        let mut bytes = [0; 1024];
        let read = tokio::time::timeout(WAIT, stream.read(&mut bytes))
            .await
            .unwrap();
        assert!(
            matches!(read, Err(_) | Ok(0)),
            "invalid client was served: {read:?}"
        );
    }
    fx.read(addr).await;
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn missing_enrollment_set_is_runtime_unavailability() {
    let fx = Fixture::new(0);
    std::fs::remove_file(fx.enrollment.join("ENROLLMENT")).unwrap();
    let mut process = Process::spawn(&mut fx.command());
    let addr = process.ready().await;
    let mut peer = fx.connect(addr, Some(&fx.peer)).await;
    let response = peer.publish(&[], 1).await;
    assert_eq!(response.status, 503, "{response:?}");
    assert!(response.head.contains("enrollment-unavailable"));
    drop(peer);
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "requires Linux tmpfs at /dev/shm")]
async fn unsupported_filesystem_refuses_until_explicitly_acknowledged() {
    let fx = Fixture::new(0);
    let tmpfs = std::path::Path::new("/dev/shm").join(fx.dir.file_name().unwrap());
    std::fs::create_dir(&tmpfs).unwrap();
    chmod(&tmpfs, 0o700);
    let mut cmd = fx.command();
    cmd.env("GRANARY_AUTHORITY_STATE_DIR", &tmpfs)
        .env("GRANARY_AUTHORITY_ACCEPT_UNSUPPORTED_FILESYSTEM", "false");
    let mut process = Process::spawn(&mut cmd);
    process.exit(EXIT_STARTUP_FAILED, WAIT).await;
    assert_refusal(
        &process,
        &["GRANARY_AUTHORITY_STATE_DIR", "filesystem type"],
    );
    assert_eq!(std::fs::read_dir(&tmpfs).unwrap().count(), 0);
    cmd.env("GRANARY_AUTHORITY_ACCEPT_UNSUPPORTED_FILESYSTEM", "true");
    let mut process = Process::spawn(&mut cmd);
    process.ready().await;
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
    std::fs::remove_dir_all(tmpfs).unwrap();
}

#[tokio::test]
async fn many_record_fixture_replays_and_stops_with_supplied_boot_id() {
    use granary_core::{clock::Clock, rng::SeededRng, sheaf::Timestamp};
    use granary_server::{AuthorityParts, Pause, VolumeConfig};
    struct Fixed;
    impl Clock for Fixed {
        fn now(&self) -> Timestamp {
            Timestamp {
                secs: 1_760_000_000,
                nanos: 0,
            }
        }
    }
    struct Timer;
    impl Pause for Timer {
        async fn pause(&self, duration: Duration) {
            tokio::time::sleep(duration).await;
        }
    }
    let fx = Fixture::new(64);
    let inventory = ["alpha", "beta"]
        .into_iter()
        .map(|name| {
            VolumeConfig::new(
                granary_core::root::VolumeName::new(name.to_owned()).unwrap(),
                granary_store::crypto::TrustedKeys::new([*publisher().public_key()]).unwrap(),
            )
        })
        .collect();
    let (handle, driver) = granary_server::start(
        AuthorityParts {
            admission: granary_server::Admission::unavailable(),
            log: granary_server::FileLog::new(&fx.state, true).unwrap(),
            store: granary_store::backend::GranaryStore::new(std::sync::Arc::new(
                object_store::memory::InMemory::new(),
            )),
            clock: Fixed,
            rng: SeededRng::new(1),
            secure_random: granary_net::secure_random::OsSecureRandom::new(),
            pause: Timer,
        },
        granary_core::runmarker::BootId::from_bytes([1; 16]),
        inventory,
    )
    .await
    .unwrap();
    // Both must be polled: stop sends the request and run services it.
    // join! is exempt here (the file's expect): a finite lifecycle fixture, no contention or simulator interleaving claim.
    let (run, stopped) = tokio::join!(driver.run(), handle.stop());
    assert_eq!(run, granary_server::RunEnd::Stopped);
    assert_eq!(stopped, run);
    assert_eq!(fx.marker(), RunMarker::Clean);
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority host requires Linux boot identity"
)]
#[expect(
    clippy::too_many_lines,
    reason = "the shipping binary lifecycle uses one generated TLS fixture through initial publication and retained completion"
)]
async fn shipping_gran_publish_uses_authority_and_repeats_completion_with_deleted_source() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;
    let fx = Fixture::new(0);
    let private = fx.dir.join("private");
    // create this generated-credential fixture's private directory.
    std::fs::create_dir(&private).unwrap();
    chmod(&private, 0o700);
    // PEM encoding of this fixture's generated public certificate.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in fx.peer.cert.as_ref().chunks(3) {
        let a = u32::from(chunk[0]);
        let b = u32::from(*chunk.get(1).unwrap_or(&0));
        let c = u32::from(*chunk.get(2).unwrap_or(&0));
        let word = (a << 16) | (b << 8) | c;
        for (shift, present) in [
            (18, true),
            (12, true),
            (6, chunk.len() > 1),
            (0, chunk.len() > 2),
        ] {
            encoded.push(if present {
                char::from(alphabet[((word >> shift) & 63) as usize])
            } else {
                '='
            });
        }
    }
    let certificate =
        format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n");
    let cert = private.join("client.pem");
    let key = private.join("client.key");
    let seed = private.join("seed");
    for (path, bytes) in [
        (&cert, certificate.as_bytes()),
        (&key, fx.peer.key.serialize_pem().as_bytes()),
        (&seed, &[0x33; 32]),
    ] {
        // write only generated test credentials and signing seed through an exclusive private fixture file.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        // restrict generated private test material to effective-uid-only access.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let source = fx.dir.join("content");
    // create this test-owned harvest source.
    std::fs::create_dir(&source).unwrap();
    // write public test content into this test-owned harvest source.
    std::fs::write(source.join("file"), b"published test content").unwrap();
    let mut process = Process::spawn(&mut fx.command());
    let addr = process.ready().await;
    // read only the certificate generated by this fixture to derive its public server pin.
    let server_pem = std::fs::read(fx.dir.join("server.pem")).unwrap();
    let server_cert = <rustls_pki_types::CertificateDer<'static> as rustls_pki_types::pem::PemObject>::from_pem_slice(&server_pem);
    let server_cert: rustls_pki_types::CertificateDer<'static> = server_cert.unwrap();
    let pin =
        granary_net::config::render_tls_pin(&granary_net::pin::spki_digest(&server_cert).unwrap());
    let endpoint = format!("https://{addr}");
    let gran = std::env::var_os("GRANARY_SHIPPING_GRAN").map_or_else(
        || std::path::Path::new(env!("CARGO_BIN_EXE_granary-server")).with_file_name("gran"),
        std::path::PathBuf::from,
    );
    assert!(
        gran.is_absolute() && gran.is_file() && gran.file_name().is_some_and(|name| name == "gran"),
        "explicit shipping gran executable required: {}",
        gran.display()
    );
    let invoke = |source: &std::path::Path| {
        let mut command = Command::new(&gran);
        command
            .env_clear()
            // seed custody walks the seed's ancestors up to HOME; the private
            // fixture directory is that stop, so the walk never reaches /tmp.
            .env("HOME", &private)
            .arg("publish")
            .arg(fx.dir.join("client-store"))
            .arg(source)
            .args(["alpha", "--endpoint", &endpoint, "--pin", &pin])
            .arg("--key-seed")
            .arg(&seed)
            .arg("--client-cert")
            .arg(&cert)
            .arg("--client-key")
            .arg(&key)
            .args(["--credential-context", "writer", "--json"]);
        command
    };
    let mut first_command = invoke(&source);
    let first = tokio::task::spawn_blocking(move || first_command.guarded_output().unwrap())
        .await
        .unwrap();
    assert!(
        first.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first_json = String::from_utf8(first.stdout).unwrap();
    assert_eq!(first_json.lines().count(), 1);
    assert!(first_json.contains("\"route\":\"authority\""));
    assert!(first_json.contains("\"outcome\":\"landed\""));
    assert!(first_json.contains("\"hint\":{\"result\":\"written\""));
    assert!(first_json.contains("\"publication\":null"));
    // delete this test-owned source to prove durable completion redisplay ignores source.
    std::fs::remove_dir_all(&source).unwrap();
    let mut second_command = invoke(&source);
    let second = tokio::task::spawn_blocking(move || second_command.guarded_output().unwrap())
        .await
        .unwrap();
    assert!(
        second.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let second_json = String::from_utf8(second.stdout).unwrap();
    for text in [&first_json, &second_json] {
        assert!(text.contains("\"seq\":1"));
        assert!(text.contains("\"publication\":null"));
    }
    let id = first_json
        .split("\"publication_id\":")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    assert!(second_json.contains(&format!("\"publication_id\":{id}")));
    process.signal("TERM");
    process.exit(EXIT_DRAINED, EXIT_BOUND).await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one authority lifecycle pins local CLI archival and continued refusal of another publisher"
)]
async fn shipping_local_abandonment_does_not_release_a_wedged_authority() {
    use granary_core::rootstore::RootStore as _;
    use granary_core::{
        authlog::{
            Envelope, Epoch, Operation, Principal, Record, RecordBody, RootBytes,
            SubmissionIdentity, Tenant, encode_append, encode_envelope,
        },
        clock::Clock,
        hash::GrainId,
        retained_submission::{
            Candidate, Evidence, FrozenIntent, Phase, RequestIdentity, Role, Scope,
            Submission as Retained,
        },
        rng::SeededRng,
        root::VolumeName,
        runmarker::BootId,
        sheaf::Timestamp,
    };
    use granary_server::{Answer, AuthorityParts, Pause, StuckState, Submission, VolumeConfig};
    use std::os::unix::fs::MetadataExt as _;
    struct Fixed;
    impl Clock for Fixed {
        fn now(&self) -> Timestamp {
            Timestamp {
                secs: 1_760_000_000,
                nanos: 0,
            }
        }
    }
    struct Timer;
    impl Pause for Timer {
        async fn pause(&self, duration: Duration) {
            tokio::time::sleep(duration).await;
        }
    }
    let fx = Fixture::new(0);
    let volume = VolumeName::new("alpha".into()).unwrap();
    let root = root_bytes("alpha", 1, None, &publisher());
    let id = GrainId::of(&root);
    let epoch = Epoch::from_bytes([0x11; 16]);
    let envelope = Envelope::new(volume.clone(), epoch);
    let mut log_bytes = encode_envelope(&envelope).as_bytes().to_vec();
    let decision = Record::new(
        1,
        RecordBody::Decision {
            identity: SubmissionIdentity::new(
                Tenant::new(b"test".to_vec()).unwrap(),
                Principal::new(vec![1; 16]).unwrap(),
                Operation::new(vec![1]).unwrap(),
                id,
            ),
            root_seq: 1,
            base: None,
            decided_at: Fixed.now(),
            candidate: RootBytes::new(root.clone()).unwrap(),
        },
    )
    .unwrap();
    let encoded = encode_append(&envelope, &decision).unwrap();
    log_bytes.extend_from_slice(encoded.record());
    log_bytes.extend_from_slice(encoded.mark());
    // Only this fixture's generated decision log is written.
    std::fs::write(fx.state.join("alpha.log"), &log_bytes).unwrap();
    let backend = std::sync::Arc::new(object_store::memory::InMemory::new());
    let remote = granary_store::backend::GranaryStore::new(backend.clone());
    remote
        .put_root("alpha", 1, b"test squatter".to_vec())
        .await
        .unwrap();
    let inventory = ["alpha", "beta"]
        .into_iter()
        .map(|name| {
            VolumeConfig::new(
                VolumeName::new(name.into()).unwrap(),
                granary_store::crypto::TrustedKeys::new([*publisher().public_key()]).unwrap(),
            )
        })
        .collect();
    let (handle, driver) = granary_server::start(
        AuthorityParts {
            admission: granary_server::Admission::unavailable(),
            log: granary_server::FileLog::new(&fx.state, true).unwrap(),
            store: granary_store::backend::GranaryStore::new(backend),
            clock: Fixed,
            rng: SeededRng::new(1),
            secure_random: granary_net::secure_random::OsSecureRandom::new(),
            pause: Timer,
        },
        BootId::from_bytes([1; 16]),
        inventory,
    )
    .await
    .unwrap();
    let request = RequestIdentity {
        epoch: [0x11; 16],
        operation: [1; 16],
    };
    let retained = Retained {
        generation: 1,
        publication_id: [7; 16],
        scope: Scope {
            authority_base: b"https://unreachable.invalid".to_vec(),
            pins: vec![[1; 32]],
            credential_context: b"writer".to_vec(),
        },
        volume: volume.clone(),
        frozen: FrozenIntent {
            writer_identity: [1; 16],
            min_prefix_bits: 0,
            initial_root: root.clone(),
        },
        current: Some(request),
        candidates: vec![Candidate {
            number: 1,
            role: Role::Active,
            request,
            seq: 1,
            id,
            root: root.clone(),
            evidence: Evidence {
                started: 1,
                ..Evidence::default()
            },
        }],
        phase: Phase::Ready,
        last_response: None,
        unavailable_exemptions: 0,
    };
    let client_dir = fx.dir.join("client-store");
    // The fixture's own directory metadata supplies the captured effective owner.
    let uid = std::fs::symlink_metadata(&fx.dir).unwrap().uid();
    let mut local = granary_client::Store::open(&client_dir).unwrap();
    local.publications(uid).unwrap().begin(&retained).unwrap();
    drop(local);
    let gran = std::env::var_os("GRANARY_SHIPPING_GRAN").map_or_else(
        || std::path::Path::new(env!("CARGO_BIN_EXE_granary-server")).with_file_name("gran"),
        std::path::PathBuf::from,
    );
    assert!(
        gran.is_absolute() && gran.is_file() && gran.file_name().is_some_and(|name| name == "gran"),
        "explicit shipping gran executable required: {}",
        gran.display()
    );
    let mut command = std::process::Command::new(gran);
    command
        .env_clear()
        .env("HOME", &fx.dir)
        .arg("publish")
        .arg(&client_dir)
        .args([
            "-",
            "alpha",
            "--endpoint",
            "https://unreachable.invalid",
            "--pin",
            &granary_net::config::render_tls_pin(&[2; 32]),
            "--credential-context",
            "writer",
            "--abandon",
            &hex(&retained.publication_id),
            "--acknowledge-may-land",
            "--json",
        ]);
    // join! is exempt here (the file's expect): a finite integration fixture polls the authority while the external CLI archives locally.
    let (run, ()) = tokio::join!(driver.run(), async {
        tokio::time::timeout(WAIT, async {
            loop {
                let rows = handle.report(Duration::from_secs(30)).await.unwrap();
                if rows
                    .iter()
                    .any(|r| r.volume == volume && r.state == StuckState::Wedged)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Capture after the authority has durably attested its open entry.
        let before_archival = std::fs::read(fx.state.join("alpha.log")).unwrap();
        let output = tokio::task::spawn_blocking(move || command.guarded_output().unwrap())
            .await
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let json = String::from_utf8(output.stdout).unwrap();
        assert_eq!(json.lines().count(), 1);
        assert!(json.contains("\"outcome\":\"abandoned\""));
        let mut local = granary_client::Store::open(&client_dir).unwrap();
        let archives = local
            .publications(uid)
            .unwrap()
            .list_archives(&volume)
            .unwrap();
        assert_eq!(
            archives.first().unwrap().submission.candidates,
            retained.candidates
        );
        drop(local);
        let other = Submission::new(
            Tenant::new(b"test".to_vec()).unwrap(),
            Principal::new(vec![2; 16]).unwrap(),
            volume.clone(),
            epoch,
            Operation::new(vec![2]).unwrap(),
            root,
        );
        assert!(
            matches!(handle.submit(other).await, Answer::NotDecided { candidate_id, .. } if candidate_id == id)
        );
        assert!(
            handle
                .report(Duration::from_secs(30))
                .await
                .unwrap()
                .iter()
                .any(|r| r.volume == volume && r.state == StuckState::Wedged)
        );
        assert_eq!(
            remote.get_root("alpha", 1).await.unwrap().unwrap(),
            b"test squatter"
        );
        // The generated authority log contains no successor decision after local archival.
        assert_eq!(
            std::fs::read(fx.state.join("alpha.log")).unwrap(),
            before_archival
        );
        handle.stop().await;
    });
    assert_eq!(run, granary_server::RunEnd::Stopped);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "two shipped incarnations prove readiness, real authenticated capture and refusal of unchanged bytes after restart"
)]
async fn debug_grant_linux_shipped_readiness_and_restart_reset() {
    let mut fx = Fixture::new(0);
    fx.accept_unsupported = false;
    let command = || {
        let mut cmd = fx.command();
        cmd.env("RUST_LOG", "info,granary_server::scoped_capture=debug");
        cmd
    };
    let mut first = Process::spawn(&mut command());
    let addr = first.ready().await;
    let incarnation = |process: &Process| {
        let output = process.output();
        let line = output
            .lines()
            .find(|s| s.contains("\"message\":\"listening\""))
            .unwrap();
        assert!(
            line.contains("\"debug_grant_restart\":\"reset\"")
                && line.contains("\"debug_grant_activation\":\"clock-supported\""),
            "{line}"
        );
        let token = line
            .split_once("\"incarnation\":\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(token.len(), 44);
        assert!(token.starts_with("incarnation:"));
        assert!(
            token.as_bytes()[12..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        );
        token
    };
    let token = incarnation(&first);
    let publication = std::process::Command::new(env!("CARGO_BIN_EXE_granary-server"))
        .env_clear()
        .args(["debug-grant", "issue", "--dir"])
        .arg(&fx.enrollment)
        .args([
            "--incarnation",
            &token,
            "--expected-revision",
            "0",
            "--volume",
            "alpha",
            "--duration-secs",
            "60",
            "--lines",
            "5",
            "--bytes",
            "5120",
            "--owner",
            "operator",
            "--reason",
            "incident",
        ])
        .guarded_output()
        .unwrap();
    assert_eq!(
        publication.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&publication.stderr)
    );
    assert!(
        String::from_utf8(publication.stdout)
            .unwrap()
            .contains("phase=written")
    );
    let bytes = std::fs::read(fx.enrollment.join("DEBUG-GRANT")).unwrap();
    let mut peer = fx.connect(addr, Some(&fx.peer)).await;
    assert_eq!(
        peer.request("PUT", "/volume/alpha/hint", &[], b"00000000000000000001")
            .await
            .status,
        204
    );
    let _observed = tokio::time::timeout(WAIT, async {
        while !first.output().contains("request_authenticated") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert_eq!(
        first
            .output()
            .lines()
            .filter(|s| s.contains("request_authenticated"))
            .count(),
        1,
        "known producer absent: {}",
        first.output()
    );
    drop(peer);
    first.signal("TERM");
    first.exit(EXIT_DRAINED, EXIT_BOUND).await;
    let mut second = Process::spawn(&mut command());
    let addr = second.ready().await;
    assert_ne!(
        incarnation(&second),
        token,
        "restart reused its secure incarnation"
    );
    let mut peer = fx.connect(addr, Some(&fx.peer)).await;
    assert_eq!(
        peer.request("PUT", "/volume/alpha/hint", &[], b"00000000000000000001")
            .await
            .status,
        204
    );
    let _observed = tokio::time::timeout(WAIT, async {
        while !second.output().contains("debug_grant_stale") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert_eq!(
        (
            second
                .output()
                .lines()
                .filter(|s| s.contains("debug_grant_stale"))
                .count(),
            second
                .output()
                .lines()
                .filter(|s| s.contains("request_authenticated"))
                .count()
        ),
        (1, 0),
        "{}",
        second.output()
    );
    assert_eq!(
        std::fs::read(fx.enrollment.join("DEBUG-GRANT")).unwrap(),
        bytes
    );
    drop(peer);
    second.signal("TERM");
    second.exit(EXIT_DRAINED, EXIT_BOUND).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Linux shipped authority and support flock venue"
)]
async fn support_writer_linux_flock_is_off_runtime() {
    let fx = Fixture::new(0);
    let support = fx.enrollment.join("SUPPORT");
    std::fs::create_dir(&support).unwrap();
    chmod(&support, 0o700);
    let held = nix::fcntl::Flock::lock(
        std::fs::File::open(&support).unwrap(),
        nix::fcntl::FlockArg::LockExclusive,
    )
    .unwrap();
    let mut command = fx.command();
    fx.plan(&mut command, "HostSupportLock", 1, false);
    let mut process = Process::spawn(&mut command);
    let addr = process.ready().await;
    fx.reached("REACHED HostSupportLock 1").await;
    fx.release();
    fx.seed_read(addr).await;
    let mut peer = fx.connect(addr, None).await;
    let response = peer
        .request("GET", "/volume/probe/root/00000000000000000001", &[], &[])
        .await;
    assert_eq!(
        (response.status, response.body),
        (200, root_bytes("probe", 1, None, &publisher()))
    );
    assert!(!support.join("SUPPORT-CONFIGURATION").exists());
    drop(held);
    tokio::time::timeout(WAIT, async {
        while !support.join("SUPPORT-CONFIGURATION").exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Linux shipped shutdown with support job held in flight"
)]
async fn support_writer_shutdown_does_not_join() {
    let fx = Fixture::new(0);
    let support = fx.enrollment.join("SUPPORT");
    std::fs::create_dir(&support).unwrap();
    chmod(&support, 0o700);
    let mut command = fx.command();
    fx.plan(&mut command, "HostSupportLock", 1, false);
    let mut process = Process::spawn(&mut command);
    let addr = process.ready().await;
    fx.reached("REACHED HostSupportLock 1").await;
    fx.seed_read(addr).await;
    let mut peer = fx.connect(addr, None).await;
    let response = peer
        .request("GET", "/volume/probe/root/00000000000000000001", &[], &[])
        .await;
    assert_eq!(
        (response.status, response.body),
        (200, root_bytes("probe", 1, None, &publisher()))
    );
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;
    assert_eq!(
        (support.join("SUPPORT-CONFIGURATION").exists(), fx.marker()),
        (false, RunMarker::Clean)
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
// Expected duration: about 60 seconds for the shipped writer's real first tick,
// plus startup, export and shutdown. The snapshot polling watchdog is 90 seconds.
async fn support_export_linux_live_writer_round_trip() {
    support_export_live_writer_round_trip().await;
}

// Type-check the composed body on macOS without running its Linux server.
// `pub(crate)`: `scripts/authority-venue.sh` takes every line starting `async fn`
// in this file for a test whose PASS it requires, and this is a helper.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[expect(
    clippy::too_many_lines,
    reason = "the live server, its first tick and the shipped verb share one process lifetime"
)]
pub(crate) async fn support_export_live_writer_round_trip() {
    use granary_core::{
        authlog::Epoch,
        support::{
            AgeStatus, SupportArchive, SupportConfiguration, SupportLogMetadata, SupportSnapshot,
        },
    };
    let fx = Fixture::new(0);
    let source = fx.enrollment.join("SUPPORT");
    std::fs::create_dir(&source).unwrap();
    chmod(&source, 0o700);
    assert_eq!(
        (
            source.join("SUPPORT-SNAPSHOT").exists(),
            source.join("SUPPORT-CONFIGURATION").exists()
        ),
        (false, false),
        "support directory must start empty: {}",
        source.display()
    );
    let mut server = Process::spawn(&mut fx.command());
    let addr = server.ready().await;
    tokio::time::timeout(
        granary_server::SUPPORT_INTERVAL + Duration::from_secs(30),
        async {
            loop {
                assert!(
                    server.child.try_wait().unwrap().is_none(),
                    "server exited before its first support tick: {}",
                    server.output()
                );
                if source.join("SUPPORT-SNAPSHOT").exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        },
    )
    .await
    .unwrap_or_else(|_| panic!("no SUPPORT-SNAPSHOT within 90 seconds: {}", server.output()));

    let out = fx.dir.join("archive");
    let output = export_fixture::command(&source, &fx.state, &out, fx.accept_unsupported)
        .guarded_output()
        .unwrap();
    export_fixture::outcome(&output, 0, "", true, &out);
    let diagnostic = export_fixture::diagnostic(&output);
    let archive = SupportArchive::decode(&std::fs::read(&out).unwrap())
        .unwrap_or_else(|e| panic!("archive decode: {e}; {diagnostic}"));
    let member = |name: &[u8]| {
        archive.members.get(name).unwrap_or_else(|| {
            panic!(
                "missing {name:?}; members={:?}; {diagnostic}",
                archive.members.keys()
            )
        })
    };
    let snapshot = SupportSnapshot::decode(member(b"snapshot.bin"))
        .unwrap_or_else(|e| panic!("snapshot decode: {e}; {diagnostic}"));
    let config = SupportConfiguration::decode(member(b"configuration.bin"))
        .unwrap_or_else(|e| panic!("configuration decode: {e}; {diagnostic}"));
    assert_eq!(
        (
            snapshot.incarnation,
            archive.manifest.incarnation,
            archive.manifest.age.status,
            config.listen_port,
            config
                .volumes
                .keys()
                .map(granary_core::root::VolumeName::as_str)
                .collect::<Vec<_>>(),
            snapshot.volumes.keys().eq(config.volumes.keys()),
            archive.members.len(),
            server.child.try_wait().unwrap().is_none()
        ),
        (
            config.incarnation,
            config.incarnation,
            AgeStatus::Fresh,
            addr.port(),
            vec!["alpha", "beta"],
            true,
            4,
            true
        ),
        "{diagnostic}; server stderr={}",
        server.output()
    );
    for volume in config.volumes.keys() {
        let name = format!("{}.logmeta", volume.as_str());
        let metadata = SupportLogMetadata::decode(member(name.as_bytes()))
            .unwrap_or_else(|e| panic!("{name} decode: {e}; {diagnostic}"));
        assert_eq!(
            (metadata.volume, metadata.envelope_version, metadata.epoch),
            (volume.clone(), 1, Epoch::from_bytes([0x11; 16])),
            "{diagnostic}"
        );
    }
    server.signal("TERM");
    server.exit(EXIT_DRAINED, WAIT).await;
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn support_export_linux_blocked_verb_still_serves() {
    support_export_blocked_verb().await;
}

// Compile the composed body on every Unix test host, including macOS.
// `pub(crate)`: a helper, kept out of `scripts/authority-venue.sh`'s test scan.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[expect(
    clippy::too_many_lines,
    reason = "the kernel flock waiter, live GET and completed archive share one process lifetime"
)]
pub(crate) async fn support_export_blocked_verb() {
    use granary_core::{
        root::VolumeName,
        support::{SupportArchive, VolumeView},
    };
    let fx = Fixture::new(0);
    // This independent serving row supplies valid disk state. The server's
    // real first tick is exercised separately by the live-writer round trip.
    let source = fx.dir.join("export-support");
    std::fs::create_dir(&source).unwrap();
    chmod(&source, 0o700);
    let (mut snapshot, mut config) = export_fixture::pair(&source);
    snapshot.volumes = ["alpha", "beta"]
        .into_iter()
        .map(|v| (VolumeName::new(v.to_owned()).unwrap(), VolumeView::NoLog))
        .collect();
    config.volumes = snapshot.volumes.keys().map(|v| (v.clone(), 1)).collect();
    export_fixture::write_pair(&source, &snapshot, &config);
    let token = export_fixture::incarnation_text(snapshot.incarnation);
    let out = fx.dir.join("archive");
    let output = export_fixture::command(&source, &fx.state, &out, fx.accept_unsupported)
        .args(["--incarnation", &token])
        .guarded_output()
        .unwrap();
    export_fixture::outcome(&output, 0, "", true, &out);
    let archive = SupportArchive::decode(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(
        archive.members.len(),
        4,
        "{}",
        export_fixture::diagnostic(&output)
    );
    std::fs::remove_file(&out).unwrap();

    let mut server = Process::spawn(&mut fx.command());
    let addr = server.ready().await;
    fx.seed_read(addr).await;
    let held = nix::fcntl::Flock::lock(
        std::fs::File::open(&source).unwrap(),
        nix::fcntl::FlockArg::LockExclusive,
    )
    .unwrap();
    let mut export_command =
        export_fixture::command(&source, &fx.state, &out, fx.accept_unsupported);
    export_command.args(["--incarnation", &token]);
    let mut exporter = ExportProcess::spawn(&mut export_command);
    let pid = exporter.child.id().to_string();
    // Observe a kernel flock waiter, rather than infer blocking from elapsed
    // time. This is a watchdog only; no serving latency bound is asserted.
    tokio::time::timeout(WAIT, async {
        loop {
            let locks = std::fs::read_to_string("/proc/locks").unwrap();
            let waiting = locks.lines().any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields
                    .windows(5)
                    .any(|w| w == ["->", "FLOCK", "ADVISORY", "WRITE", pid.as_str()])
            });
            if waiting {
                break;
            }
            assert!(
                exporter.child.try_wait().unwrap().is_none(),
                "exporter exited before flock wait: {} locks={locks}",
                exporter.output()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no exporter flock waiter: {}", exporter.output()));
    let mut peer = fx.connect(addr, None).await;
    let response = peer
        .request("GET", "/volume/probe/root/00000000000000000001", &[], &[])
        .await;
    assert_eq!(
        (
            response.status,
            response.body,
            exporter.child.try_wait().unwrap().is_none(),
            out.exists()
        ),
        (200, root_bytes("probe", 1, None, &publisher()), true, false),
        "while exporter flock is held: {} server stderr={}",
        exporter.output(),
        server.output()
    );
    drop(held);
    let status = tokio::time::timeout(WAIT, async {
        loop {
            if let Some(status) = exporter.child.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("exporter failed to finish: {}", exporter.output()));
    exporter.finish().await;
    assert_eq!(
        (status.code(), exporter.output(), out.exists()),
        (Some(0), "stdout=\"\" stderr=\"\"".to_owned(), true),
        "{}",
        exporter.output()
    );
    let completed = SupportArchive::decode(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(completed.members, archive.members, "{}", exporter.output());
    server.signal("TERM");
    server.exit(EXIT_DRAINED, WAIT).await;
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ExportProcess {
    child: std::process::Child,
    stdout: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    stderr: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl ExportProcess {
    fn spawn(command: &mut std::process::Command) -> Self {
        use std::io::Read as _;
        let child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut process = Self {
            child,
            stdout: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            stderr: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            readers: Vec::new(),
        };
        let stdout = process.stdout.clone();
        let stderr = process.stderr.clone();
        let streams: Vec<(Box<dyn std::io::Read + Send>, _)> = vec![
            (Box::new(process.child.stdout.take().unwrap()), stdout),
            (Box::new(process.child.stderr.take().unwrap()), stderr),
        ];
        process.readers = streams
            .into_iter()
            .map(|(mut stream, buffer)| {
                std::thread::spawn(move || {
                    let mut bytes = [0; 512];
                    loop {
                        let n = stream.read(&mut bytes).unwrap();
                        if n == 0 {
                            break;
                        }
                        buffer.lock().unwrap().extend_from_slice(&bytes[..n]);
                    }
                })
            })
            .collect();
        process
    }
    fn output(&self) -> String {
        format!(
            "stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&self.stdout.lock().unwrap()),
            String::from_utf8_lossy(&self.stderr.lock().unwrap())
        )
    }
    async fn finish(&mut self) {
        for reader in self.readers.drain(..) {
            tokio::time::timeout(WAIT, async {
                while !reader.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            reader.join().unwrap();
        }
    }
}
impl Drop for ExportProcess {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn shipped_host_readiness_preserves_no_log_and_orphan_state() {
    use granary_core::intent::{self, Ownership, OwnershipMode};
    use granary_core::root::VolumeName;
    for orphan in [false, true] {
        let fx = Fixture::new(0);
        std::fs::remove_file(fx.state.join("alpha.log")).unwrap();
        if orphan {
            fx.initialise("alpha");
            std::fs::remove_file(fx.state.join("alpha.log")).unwrap();
        }
        let snapshot = std::fs::read(fx.state.join("alpha.intent")).ok();
        let mut process = Process::spawn(&mut fx.command());
        let addr = process.ready().await;
        assert!(!fx.state.join("alpha.log").exists());
        assert_eq!(std::fs::read(fx.state.join("alpha.intent")).ok(), snapshot);
        let request = intent::encode_ownership(Ownership {
            writer: [1; 16],
            instance: [2; 16],
            mode: OwnershipMode::Acquire { observed_cursor: 0 },
        })
        .unwrap();
        let root = root_bytes("alpha", 1, None, &publisher());
        let register = intent::encode_register(&[1; 16], 1, &[2; 16], 1, &root).unwrap();
        let release = intent::encode_release(intent::Release {
            writer: [1; 16],
            epoch: 1,
            instance: [2; 16],
            generation: 1,
        })
        .unwrap();
        let mut peer = fx.connect(addr, Some(&fx.peer)).await;
        for (method, path, body) in [
            ("GET", "/volume/alpha/intent", &[][..]),
            ("POST", "/volume/alpha/intent/ownership", request.as_slice()),
            ("POST", "/volume/alpha/intent", register.as_slice()),
            ("POST", "/volume/alpha/intent/release", release.as_slice()),
        ] {
            let response = peer.request(method, path, &[], body).await;
            assert_eq!(response.status, 503, "{response:?}");
            assert!(response.head.contains("unavailable"));
        }
        // Refill the shared submission burst before exercising publication.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let published = peer
            .publish(&root_bytes("alpha", 1, None, &publisher()), 1)
            .await;
        assert_eq!(published.status, 404, "{published:?}");
        assert!(published.head.contains("no-log"));
        let status = peer.request("GET", "/volume/alpha/status", &[], &[]).await;
        assert_eq!(status.status, 404, "{status:?}");
        assert!(status.head.contains("no-log"));
        assert!(!fx.state.join("alpha.log").exists());
        assert_eq!(std::fs::read(fx.state.join("alpha.intent")).ok(), snapshot);
        drop(peer);
        process.signal("TERM");
        process.exit(EXIT_DRAINED, EXIT_BOUND).await;
        // Stopping and explicit offline initialise are a separate positive control.
        fx.initialise("alpha");
        let mut process = Process::spawn(&mut fx.command());
        let addr = process.ready().await;
        let mut peer = fx.connect(addr, Some(&fx.peer)).await;
        let read = peer.request("GET", "/volume/alpha/intent", &[], &[]).await;
        assert_eq!(read.status, 200, "{read:?}");
        let volume = VolumeName::new("alpha".into()).unwrap();
        assert_eq!(
            intent::decode_readback(&read.body, &volume, |_, _| true)
                .unwrap()
                .cursor,
            0
        );
        assert_eq!(
            peer.request("POST", "/volume/alpha/intent/ownership", &[], &request)
                .await
                .status,
            200
        );
        let read = peer.request("GET", "/volume/alpha/intent", &[], &[]).await;
        assert_eq!(
            intent::decode_readback(&read.body, &volume, |_, _| true)
                .unwrap()
                .cursor,
            1
        );
        drop(peer);
        process.signal("TERM");
        process.exit(EXIT_DRAINED, EXIT_BOUND).await;
    }
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
async fn round1_shipped_host_periodically_adds_new_enrollment_cursor() {
    use granary_core::enrollment::{ClientSpkiDigest, TenantName};
    use granary_net::secure_random::OsSecureRandom;
    let fx = Fixture::new(0);
    std::fs::remove_file(fx.state.join("alpha.log")).unwrap();
    fx.initialise("alpha");
    std::fs::remove_file(fx.state.join("beta.log")).unwrap();
    let mut process = Process::spawn(&mut fx.command());
    let _addr = process.ready().await;
    let (principal, _) = granary_server::mint(
        &fx.enrollment,
        OPTIONS,
        &TenantName::parse("test").unwrap(),
        ClientSpkiDigest::from_bytes([9; 32]),
        &mut OsSecureRandom::new(),
    )
    .unwrap();
    // Independently walk the private snapshot's bounded principal frames; no HTTP
    // request is allowed to create this cursor for the maintenance assertion.
    let present = |bytes: &[u8]| {
        let volume_len = usize::from(bytes[12]);
        let mut at = 13 + volume_len + 16 + 8 + 8 + 33;
        while at + 38 <= bytes.len() && &bytes[at..at + 8] != b"GRNINEND" {
            let length =
                usize::try_from(u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())).unwrap();
            if at + length + 38 > bytes.len() {
                return false;
            }
            if bytes[at + 4] == 1 && length == 26 && &bytes[at + 5..at + 21] == principal.as_bytes()
            {
                assert_eq!(
                    u64::from_be_bytes(bytes[at + 21..at + 29].try_into().unwrap()),
                    0
                );
                assert_eq!(&bytes[at + 29..at + 31], &[0, 0]);
                return true;
            }
            at += length + 38;
        }
        false
    };
    assert!(!present(
        &std::fs::read(fx.state.join("alpha.intent")).unwrap()
    ));
    tokio::time::timeout(Duration::from_secs(75), async {
        loop {
            if present(&std::fs::read(fx.state.join("alpha.intent")).unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(!fx.state.join("beta.log").exists());
    assert!(!fx.state.join("beta.intent").exists());
    process.signal("TERM");
    process.exit(EXIT_DRAINED, EXIT_BOUND).await;
}

struct RequestDesc<'a> {
    endpoint: &'static str,
    method: &'static str,
    path: &'static str,
    headers: Vec<(&'static str, &'static [u8])>,
    body: &'a [u8],
}

struct LoggedRequest {
    request_id: u64,
    endpoint: &'static str,
    shape: Option<RequestIdShape>,
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production authority boot identity requires Linux"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Shipped authority binary verifies status preservation and log filtering across request id shapes"
)]
async fn request_id_shapes_keep_status() {
    // Smallest millisecond sleep that refills at least one submission at the
    // default rate of 46 submissions/second (1000 ms / 46 = 21.74 ms -> 22 ms).
    const PUBLISH_PACE: Duration = Duration::from_millis(22);

    let fx = Fixture::new(0);
    let candidate = fx.candidate().await;
    let mut process = Process::spawn(&mut fx.command());
    let addr = process.ready().await;
    let mut next_request_id = candidate
        .seed(&mut fx.connect(addr, Some(&fx.peer)).await)
        .await;
    let candidate = candidate.root;

    let shapes = request_id_shapes();

    let parse_error_token = |head: &str| -> Option<String> {
        head.lines().find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("granary-error:")
                .map(|s| s.trim().to_owned())
        })
    };

    let mut peer: Option<Peer> = None;

    let epoch_bytes = EPOCH.as_bytes();
    let publish_headers: Vec<(&'static str, &'static [u8])> =
        vec![("granary-epoch", epoch_bytes), ("granary-operation", b"01")];

    let mut verified_cases = 0usize;
    let mut logged_requests = Vec::new();

    // 1. Send the valid publish control once.
    tokio::time::sleep(PUBLISH_PACE).await;
    if peer.is_none() {
        peer = Some(fx.connect(addr, Some(&fx.peer)).await);
    }
    let p = peer.as_mut().unwrap();
    p.send(
        "POST",
        "/volume/alpha/publish",
        &publish_headers,
        &candidate,
        candidate.len(),
    )
    .await;
    let control_res = p.response().await;
    if control_res
        .head
        .to_ascii_lowercase()
        .contains("connection: close")
    {
        peer = None;
    }
    assert_eq!(control_res.status, 202, "{control_res:?}");
    logged_requests.push(LoggedRequest {
        request_id: next_request_id,
        endpoint: "publish",
        shape: None,
    });
    next_request_id += 1;

    // Poll a plain, unshaped replay of the same candidate until it answers 200 (landed).
    let poll_start = tokio::time::Instant::now();
    loop {
        assert!(
            poll_start.elapsed() < WAIT,
            "publish candidate did not settle within {WAIT:?}"
        );
        tokio::time::sleep(PUBLISH_PACE).await;
        if peer.is_none() {
            peer = Some(fx.connect(addr, Some(&fx.peer)).await);
        }
        let p = peer.as_mut().unwrap();
        p.send(
            "POST",
            "/volume/alpha/publish",
            &publish_headers,
            &candidate,
            candidate.len(),
        )
        .await;
        let poll_res = p.response().await;
        if poll_res
            .head
            .to_ascii_lowercase()
            .contains("connection: close")
        {
            peer = None;
        }
        logged_requests.push(LoggedRequest {
            request_id: next_request_id,
            endpoint: "publish",
            shape: None,
        });
        next_request_id += 1;
        if poll_res.status == 200 {
            break;
        }
        assert_eq!(
            poll_res.status, 202,
            "polling replay got unexpected status: {poll_res:?}"
        );
    }

    // 2. For each shape, send an unshaped replay followed by a shaped replay.
    for shape in &shapes {
        let shape_fields = shape.as_wire_fields();
        let mut combined_headers = publish_headers.clone();
        combined_headers.extend_from_slice(&shape_fields);

        // Unshaped replay sent just before the shaped replay
        tokio::time::sleep(PUBLISH_PACE).await;
        if peer.is_none() {
            peer = Some(fx.connect(addr, Some(&fx.peer)).await);
        }
        let p = peer.as_mut().unwrap();
        p.send(
            "POST",
            "/volume/alpha/publish",
            &publish_headers,
            &candidate,
            candidate.len(),
        )
        .await;
        let unshaped_res = p.response().await;
        if unshaped_res
            .head
            .to_ascii_lowercase()
            .contains("connection: close")
        {
            peer = None;
        }
        assert_eq!(unshaped_res.status, 200, "{unshaped_res:?}");
        logged_requests.push(LoggedRequest {
            request_id: next_request_id,
            endpoint: "publish",
            shape: None,
        });
        next_request_id += 1;

        // Shaped replay
        tokio::time::sleep(PUBLISH_PACE).await;
        if peer.is_none() {
            peer = Some(fx.connect(addr, Some(&fx.peer)).await);
        }
        let p = peer.as_mut().unwrap();
        p.send(
            "POST",
            "/volume/alpha/publish",
            &combined_headers,
            &candidate,
            candidate.len(),
        )
        .await;
        let res = p.response().await;
        if res.head.to_ascii_lowercase().contains("connection: close") {
            peer = None;
        }
        assert_eq!(
            (res.status, parse_error_token(&res.head)),
            (unshaped_res.status, parse_error_token(&unshaped_res.head)),
            "mismatch on shape for POST /volume/alpha/publish"
        );
        logged_requests.push(LoggedRequest {
            request_id: next_request_id,
            endpoint: "publish",
            shape: Some(shape.clone()),
        });
        next_request_id += 1;
        verified_cases += 1;
    }

    // 4. Intent readback and status as idempotent reads compared with their control.
    let read_requests = [
        RequestDesc {
            endpoint: "intent",
            method: "GET",
            path: "/volume/alpha/intent",
            headers: vec![],
            body: b"",
        },
        RequestDesc {
            endpoint: "status",
            method: "GET",
            path: "/volume/alpha/status",
            headers: vec![],
            body: b"",
        },
    ];

    for req in &read_requests {
        // Control: no request id
        if peer.is_none() {
            peer = Some(fx.connect(addr, Some(&fx.peer)).await);
        }
        let p = peer.as_mut().unwrap();
        p.send(req.method, req.path, &req.headers, req.body, req.body.len())
            .await;
        let control_res = p.response().await;
        if control_res
            .head
            .to_ascii_lowercase()
            .contains("connection: close")
        {
            peer = None;
        }
        let control_status = control_res.status;
        let control_token = parse_error_token(&control_res.head);
        logged_requests.push(LoggedRequest {
            request_id: next_request_id,
            endpoint: req.endpoint,
            shape: None,
        });
        next_request_id += 1;

        // All 11 shapes: each must match control status and token
        for shape in &shapes {
            let shape_fields = shape.as_wire_fields();
            let mut combined_headers = req.headers.clone();
            combined_headers.extend_from_slice(&shape_fields);

            if peer.is_none() {
                peer = Some(fx.connect(addr, Some(&fx.peer)).await);
            }
            let p = peer.as_mut().unwrap();
            p.send(
                req.method,
                req.path,
                &combined_headers,
                req.body,
                req.body.len(),
            )
            .await;
            let res = p.response().await;
            if res.head.to_ascii_lowercase().contains("connection: close") {
                peer = None;
            }
            assert_eq!(
                (res.status, parse_error_token(&res.head)),
                (control_status, control_token.clone()),
                "mismatch on shape for {} {}",
                req.method,
                req.path
            );
            logged_requests.push(LoggedRequest {
                request_id: next_request_id,
                endpoint: req.endpoint,
                shape: Some(shape.clone()),
            });
            next_request_id += 1;
            verified_cases += 1;
        }
    }

    assert_eq!(verified_cases, 3 * 11);

    drop(peer);
    process.signal("TERM");
    process.exit(EXIT_DRAINED, WAIT).await;

    let stderr = process.output();

    // Attribute lines to requests using the request_id counter.
    let mut lines_by_request_id: std::collections::BTreeMap<u64, Vec<&str>> =
        std::collections::BTreeMap::new();
    for line in stderr.lines() {
        if !line.contains("grain_request") {
            continue;
        }
        if let Some(pos) = line.find("\"request_id\":") {
            let rest = &line[pos + "\"request_id\":".len()..];
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(req_id) = digits.parse::<u64>() {
                lines_by_request_id.entry(req_id).or_default().push(line);
            }
        }
    }

    let mut conforming_endpoints_verified = std::collections::BTreeSet::new();

    for logged in &logged_requests {
        let lines = lines_by_request_id
            .get(&logged.request_id)
            .unwrap_or_else(|| {
                panic!(
                    "missing grain_request log line for request_id {} ({}) in stderr: {stderr}",
                    logged.request_id, logged.endpoint
                )
            });
        assert!(
            !lines.is_empty(),
            "expected at least one grain_request line for request_id {} ({})",
            logged.request_id,
            logged.endpoint
        );

        match &logged.shape {
            None => {
                for line in lines {
                    assert!(
                        !line.contains("wire_request_id"),
                        "control request {} ({}) must not log wire_request_id: {line}",
                        logged.request_id,
                        logged.endpoint
                    );
                }
            }
            Some(shape) => {
                if is_conforming_request_id_shape(shape) {
                    let conforming_id = shape.conforming_value().unwrap();
                    let needle = format!("\"wire_request_id\":\"{conforming_id}\"");
                    let found = lines.iter().any(|line| line.contains(&needle));
                    assert!(
                        found,
                        "conforming wire_request_id {conforming_id} missing on grain_request for {} (request_id={}); lines: {lines:?}",
                        logged.endpoint, logged.request_id
                    );
                    conforming_endpoints_verified.insert(logged.endpoint);
                } else {
                    for line in lines {
                        assert!(
                            !line.contains("wire_request_id"),
                            "malformed shape on request {} ({}) must not log wire_request_id: {line}",
                            logged.request_id,
                            logged.endpoint
                        );
                        for (_, bytes) in shape.as_wire_fields() {
                            if bytes.len() > 1 {
                                let raw_str = String::from_utf8_lossy(bytes);
                                assert!(
                                    !line.contains(raw_str.as_ref()),
                                    "malformed raw identifier must not appear in log line for request {} ({}): {line}",
                                    logged.request_id,
                                    logged.endpoint
                                );
                            }
                            if bytes.len() > 64 {
                                let prefix_str = String::from_utf8_lossy(&bytes[..64]);
                                assert!(
                                    !line.contains(prefix_str.as_ref()),
                                    "truncated identifier must not appear in log line for request {} ({}): {line}",
                                    logged.request_id,
                                    logged.endpoint
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Per endpoint (publish, intent, status), assert that its own grain_request span carried the conforming value.
    for endpoint in ["publish", "intent", "status"] {
        assert!(
            conforming_endpoints_verified.contains(endpoint),
            "endpoint {endpoint} must have verified conforming wire_request_id on its grain_request span"
        );
    }
}
