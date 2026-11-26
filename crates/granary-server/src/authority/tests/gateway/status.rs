// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::wire::ErrorToken;
use granary_core::enrollment::PrincipalId;
use std::fmt::Write as _;
use std::future::poll_fn;
use std::pin::pin;

mod blocked;
mod publication;

fn get(v: &VolumeName) -> hyper::Request<Full<Bytes>> {
    request(
        "GET",
        &format!("/volume/{}/status", v.as_str()),
        Full::new(Bytes::new()),
    )
}

async fn status_bytes(
    response: Response<Full<Bytes>>,
    status: u16,
    token: Option<&str>,
) -> Vec<u8> {
    check(&response, status, token);
    for header in [
        "etag",
        "last-modified",
        "content-range",
        "accept-ranges",
        "retry-after",
    ] {
        assert!(!response.headers().contains_key(header), "{header}");
    }
    if status == 200 {
        assert_eq!(
            response.headers()["content-type"],
            "application/vnd.granary.volume-status.v1"
        );
    } else {
        assert!(!response.headers().contains_key("content-type"));
    }
    let length = response.body().size_hint().exact().unwrap();
    if let Some(header) = response.headers().get("content-length") {
        assert_eq!(header.to_str().unwrap().parse::<u64>().unwrap(), length);
    }
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    assert_eq!(length, bytes.len() as u64);
    if status == 200 {
        codec::decode_status(&bytes).unwrap();
    } else {
        assert!(bytes.is_empty());
    }
    bytes
}

async fn fence(handle: &AuthorityHandle) {
    let result: Result<(), Fence> = LogGate::default()
        .fencing(
            &handle.inner.shared.fence,
            LogCall::Append,
            None,
            || async { Err(LogIoError::AlreadyExists) },
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn status_inventory_matrix() {
    for file in [false, true] {
        let (fx, driver) = Fx::with_inventory(file, &[a(), b()], &[], &[a(), vol("no-log")]).await;
        let before = fx.bytes().await;
        let calls = fx.store.calls.load(Ordering::Relaxed);
        for (v, code, token) in [
            (a(), 200, None),
            (vol("no-log"), 404, Some("no-log")),
            (b(), 404, Some("unknown-volume")),
            (c(), 404, Some("unknown-volume")),
        ] {
            let bytes = status_bytes(fx.send(get(&v)).await, code, token).await;
            if code == 200 {
                assert_eq!(
                    codec::decode_status(&bytes).unwrap(),
                    codec::VolumeStatus {
                        epoch: Epoch::from_bytes([WORLD_EPOCH; 16]),
                        head: None,
                        open: None
                    }
                );
            }
        }
        assert_eq!(fx.store.calls.load(Ordering::Relaxed), calls);
        assert_eq!(fx.bytes().await, before);
        assert_eq!(fx.service.observation().unwrap().volumes.len(), 2);
        drop(driver);
    }
}

#[tokio::test]
async fn status_wire_contract() {
    let (fx, driver) = Fx::new(false, &[a()], &[]).await;
    for method in ["HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"] {
        let mut r = request(method, "/volume/vol-a/status", Full::new(Bytes::new()));
        r.headers_mut().insert("if-match", "*".parse().unwrap());
        let response = fx.send(r).await;
        assert_eq!(response.headers()["allow"], "GET");
        status_bytes(response, 405, Some("method-not-allowed")).await;
    }
    for conditional in [
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-range",
    ] {
        let mut r = get(&a());
        r.headers_mut()
            .insert(conditional, "anything".parse().unwrap());
        status_bytes(fx.send(r).await, 400, Some("bad-request")).await;
    }
    for path in [
        "/volume/Vol-a/status",
        "/volume/vol-a/status/",
        "/volume/vol-a/status?q=1",
        "/volume/vol%2Da/status",
        "/volume//status",
    ] {
        let response = fx
            .send(request("HEAD", path, Full::new(Bytes::new())))
            .await;
        assert_eq!(response.status(), 404);
        assert_eq!(response.headers()["granary-error"], "unknown-target");
        assert!(!response.headers().contains_key("cache-control"));
    }
    let mut r = get(&a());
    r.headers_mut().insert("range", "nonsense".parse().unwrap());
    status_bytes(fx.send(r).await, 200, None).await;
    let charge = fx
        .service
        .read_budget()
        .take(crate::adapter::READ_BODY_BUDGET_BYTES)
        .unwrap();
    status_bytes(fx.send(get(&a())).await, 503, Some("unavailable")).await;
    drop(charge);
    status_bytes(fx.send(get(&a())).await, 200, None).await;
    let charge = fx
        .service
        .read_budget()
        .take(crate::adapter::READ_BODY_BUDGET_BYTES - 28)
        .unwrap();
    status_bytes(fx.send(get(&a())).await, 503, Some("unavailable")).await;
    drop(charge);
    for (n, close) in [(16, false), (65_537, true)] {
        let response = fx
            .send(request(
                "GET",
                "/volume/vol-a/status",
                Full::new(Bytes::from(vec![0; n])),
            ))
            .await;
        assert_eq!(response.headers().contains_key("connection"), close);
        if close {
            assert_eq!(response.headers()["connection"], "close");
        }
        status_bytes(response, 200, None).await;
    }
    // A corrupt internal projection cannot become a malformed public success.
    fx.handle.inner.views[&a()].verified(
        driver.workers[0].state(),
        Some(VerifiedHead {
            head: None,
            next_seq: None,
        }),
    );
    status_bytes(fx.send(get(&a())).await, 500, Some("internal")).await;
}

#[tokio::test]
async fn status_authority_disabled() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    for configured in [false, true] {
        let mut service = crate::GrainService::new(Arc::new(fx.store.clone()), "", 2);
        if configured {
            service = service.with_test_write_controls(fx.reader.clone(), fx.controls.clone());
        }
        for method in ["GET", "HEAD", "POST", "PUT"] {
            let response = service
                .request_for_test(request(
                    method,
                    "/volume/vol-a/status",
                    Full::new(Bytes::new()),
                ))
                .await;
            assert_eq!(response.status(), 404);
            assert_eq!(response.headers()["granary-error"], "unknown-target");
        }
    }
}

#[tokio::test]
async fn status_terminal_overrides_snapshot() {
    for terminal in [0, 1, 2, 3, 4] {
        let (fx, driver) = Fx::new(false, &[a()], &[]).await;
        status_bytes(fx.send(get(&a())).await, 200, None).await;
        let mut run = None;
        match terminal {
            0 => {
                fx.handle.inner.shared.stop.request();
                drop(driver);
            }
            1 => {
                drop(driver);
            }
            2 => {
                run = Some(spawn_driver(driver));
                fx.handle.stop().await;
            }
            3 | 4 => {
                if terminal == 4 {
                    fx.handle.inner.shared.stop.request();
                }
                fence(&fx.handle).await;
                drop(driver);
            }
            _ => unreachable!(),
        }
        let loads = fx.handle.inner.views[&a()].loads();
        for v in [a(), b()] {
            status_bytes(
                fx.send(get(&v)).await,
                503,
                Some(if terminal >= 3 { "fenced" } else { "stopped" }),
            )
            .await;
        }
        assert_eq!(
            fx.handle.inner.views[&a()].loads(),
            loads,
            "terminal status must precede lookup"
        );
        if let Some(mut run) = run {
            run.join_next().await.unwrap().unwrap();
        }
    }
}

struct DrainHold {
    reached: Arc<std::sync::atomic::AtomicBool>,
    release: Arc<std::sync::atomic::AtomicBool>,
}
impl Body for DrainHold {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.reached.store(true, Ordering::SeqCst);
        if self.release.load(Ordering::SeqCst) {
            Poll::Ready(None)
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

#[tokio::test]
async fn status_terminal_during_drain_releases_success() {
    for fenced in [false, true] {
        let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
        for v in [a(), b()] {
            let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let r = request(
                "GET",
                &format!("/volume/{}/status", v.as_str()),
                DrainHold {
                    reached: reached.clone(),
                    release: release.clone(),
                },
            );
            let mut response = pin!(fx.send(r));
            poll_fn(|cx| {
                assert!(response.as_mut().poll(cx).is_pending());
                if reached.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            if fenced {
                fence(&fx.handle).await;
            } else {
                fx.handle.inner.shared.stop.request();
            }
            release.store(true, Ordering::SeqCst);
            status_bytes(
                response.await,
                503,
                Some(if fenced { "fenced" } else { "stopped" }),
            )
            .await;
            assert!(
                fx.service
                    .read_budget()
                    .take(crate::adapter::READ_BODY_BUDGET_BYTES)
                    .is_some()
            );
        }
    }
}

#[tokio::test]
async fn status_is_anonymous_and_uncharged() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let expected = status_bytes(fx.send(get(&a())).await, 200, None).await;
    assert_eq!(fx.controls.state_count(), 0);
    assert_eq!(fx.controls.in_flight(PRINCIPAL), 0);
    for state in 0..4 {
        if state == 1 {
            crate::enrollment::revoke(&fx.config.enrollment_dir, OPTIONS, DIGEST).unwrap();
        }
        if state == 2 {
            std::fs::rename(&fx.config.enrollment_dir, fx.dir.join("unavailable")).unwrap();
        }
        let enrollment = fx.reader.snapshot();
        let counters = fx.service.refusal_counters().unwrap().snapshot();
        for identity in [
            None,
            Some(DIGEST),
            Some(ClientSpkiDigest::from_bytes([0xF1; 32])),
        ] {
            let mut r = get(&a());
            r.extensions_mut().clear();
            if let Some(d) = identity {
                r.extensions_mut().insert(ConnectionIdentity::Verified(d));
            }
            assert_eq!(status_bytes(fx.send(r).await, 200, None).await, expected);
        }
        assert_eq!(
            fx.reader.snapshot(),
            enrollment,
            "status performed a lookup or refresh"
        );
        assert_eq!(fx.service.refusal_counters().unwrap().snapshot(), counters);
        if state == 0 {
            let permits: Vec<_> = (0..4)
                .map(|_| fx.controls.admit(PRINCIPAL, true).unwrap())
                .collect();
            assert!(fx.controls.admit(PRINCIPAL, true).is_err());
            assert_eq!(
                status_bytes(fx.send(get(&a())).await, 200, None).await,
                expected
            );
            drop(permits);
            drop(fx.controls.admit(PRINCIPAL, true).unwrap());
            assert!(fx.controls.admit(PRINCIPAL, true).is_err());
        }
    }
}

#[tokio::test]
async fn status_contains_only_public_fields_and_observation_preserves_enrollment() {
    let candidate = good_root(&a(), 1, None, 99);
    let d = Record::new(
        1,
        RecordBody::Decision {
            identity: SubmissionIdentity::new(
                Tenant::new(b"private-tenant".to_vec()).unwrap(),
                Principal::new(b"private-principal".to_vec()).unwrap(),
                Operation::new(b"private-operation".to_vec()).unwrap(),
                GrainId::of(&candidate),
            ),
            root_seq: 1,
            base: None,
            decided_at: FixedClock.now(),
            candidate: RootBytes::new(candidate.clone()).unwrap(),
        },
    )
    .unwrap();
    let (fx, _driver) = Fx::new(false, &[a()], &[d]).await;
    let before = status_bytes(fx.send(get(&a())).await, 200, None).await;
    let counters = fx.service.refusal_counters().unwrap();
    for n in 0..=granary_core::enrollment::PRINCIPALS_MAX * 2 {
        counters.record(
            ErrorToken::BadRequest,
            Some(PrincipalId::from_bytes((n as u128).to_be_bytes())),
        );
    }
    for _ in 0..2 {
        fx.reader.lookup(&DIGEST).await;
    }
    let observation = fx.service.observation().unwrap();
    assert_eq!(observation.enrollment, fx.reader.snapshot());
    assert_eq!(observation.refusals, counters.snapshot());
    assert_eq!(observation.volumes, fx.handle.volume_views());
    assert_eq!(observation.terminal, None);
    assert_eq!(
        observation.refusals.principals.len(),
        granary_core::enrollment::PRINCIPALS_MAX
    );
    assert_eq!(
        status_bytes(fx.send(get(&a())).await, 200, None).await,
        before
    );
    let mut expected = b"GRNVSTAT\x00\x01".to_vec();
    expected.extend([WORLD_EPOCH; 16]);
    expected.extend([0, 1]);
    expected.extend(1u64.to_be_bytes());
    expected.extend(GrainId::of(&candidate).to_bytes());
    assert_eq!(before, expected);
    assert!(
        fx.controls.admit(PRINCIPAL, true).is_ok(),
        "counter eviction changed controls"
    );
}

#[tokio::test]
async fn status_epoch_bootstrap() {
    let (fx, driver) = Fx::new(false, &[a()], &[]).await;
    let value =
        codec::decode_status(&status_bytes(fx.send(get(&a())).await, 200, None).await).unwrap();
    let mut r = publish(1, good_root(&a(), 1, None, 1));
    let mut epoch = String::new();
    for b in value.epoch.to_bytes() {
        write!(&mut epoch, "{b:02x}").unwrap();
    }
    r.headers_mut()
        .insert("granary-epoch", epoch.parse().unwrap());
    let mut run = spawn_driver(driver);
    binary(fx.send(r).await, 202, None, 3).await;
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

struct RefreshHold(Arc<crate::protected_dir::tests::Pause>);
impl Drop for RefreshHold {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test]
async fn observation_preserves_enrollment_snapshot_while_refresh_is_held() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let counters = crate::SnapshotCounters {
        missing: 1,
        unreadable: 2,
        unprotected: 3,
        oversize: 4,
        corrupt: 5,
        directory: 6,
        stalled: 7,
        reloads: 8,
        reload_failures: 9,
    };
    for state in [
        crate::SnapshotState::Ok {
            principals: 123,
            credentials: 234,
        },
        crate::SnapshotState::Unavailable(crate::UnavailableReason::Missing),
        crate::SnapshotState::Unavailable(crate::UnavailableReason::Unreadable),
        crate::SnapshotState::Unavailable(crate::UnavailableReason::Unprotected),
        crate::SnapshotState::Unavailable(crate::UnavailableReason::Oversize),
        crate::SnapshotState::Unavailable(crate::UnavailableReason::Corrupt),
        crate::SnapshotState::Unavailable(crate::UnavailableReason::Directory),
        crate::SnapshotState::Unavailable(crate::UnavailableReason::Stalled),
    ] {
        let snapshot = crate::EnrollmentSnapshot {
            state,
            sequence: 456,
            counters,
        };
        fx.reader.seed_snapshot(snapshot);
        assert_eq!(fx.service.observation().unwrap().enrollment, snapshot);
    }
    let before = fx.reader.snapshot();
    let pause = Arc::new(crate::protected_dir::tests::Pause::default());
    let hold = RefreshHold(pause.clone());
    fx.reader.hold_refresh(pause.clone());
    let mut lookup = pin!(fx.reader.lookup(&DIGEST));
    poll_fn(|cx| {
        assert!(lookup.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    let service = fx.service.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let sample = std::thread::spawn(move || {
        let _ = tx.send(service.observation().unwrap());
    });
    let observed = rx.recv_timeout(Duration::from_millis(250));
    if observed.is_err() {
        drop(hold);
        sample.join().unwrap();
        panic!("operator observation waited on the held filesystem refresh");
    }
    assert_eq!(observed.unwrap().enrollment, before);
    sample.join().unwrap();
    for identity in [None, Some(DIGEST)] {
        let mut r = get(&a());
        r.extensions_mut().clear();
        if let Some(d) = identity {
            r.extensions_mut().insert(ConnectionIdentity::Verified(d));
        }
        status_bytes(fx.send(r).await, 200, None).await;
    }
    drop(hold);
    lookup.await;
}
