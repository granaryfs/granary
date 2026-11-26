// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP gateway evidence over simulated and production decision logs.
use super::*;
use granary_core::authority_answer::{self as codec, PublishAnswer};
use granary_core::enrollment::{ClientSpkiDigest, TenantName};
use granary_net::identity::ConnectionIdentity;
use http_body_util::{BodyExt, Full};
use hyper::{
    Response,
    body::{Body, Bytes, Frame},
};
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
mod conformance;
pub(in crate::authority::tests) mod content;
mod debug_grant;
mod fixture;
mod readback;
mod status;
mod support_writer;
use fixture::*;

fn check(response: &Response<Full<Bytes>>, status: u16, token: Option<&str>) {
    assert_eq!(response.status().as_u16(), status, "{response:?}");
    assert_eq!(
        response
            .headers()
            .get("granary-error")
            .map(|h| h.to_str().unwrap()),
        token
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(
        response.headers().contains_key("retry-after"),
        status == 429
    );
}
async fn binary(
    response: Response<Full<Bytes>>,
    status: u16,
    token: Option<&str>,
    kind: u8,
) -> PublishAnswer {
    check(&response, status, token);
    assert_eq!(
        response.headers()["content-type"],
        "application/vnd.granary.authority-answer.v1"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = codec::decode(&bytes).unwrap();
    assert_eq!(value.kind(), kind);
    assert_eq!(codec::encode(value).unwrap(), bytes);
    value
}
fn decision_for(candidate: &[u8]) -> Record {
    let doc = root::decode_root(candidate).unwrap();
    Record::new(
        1,
        RecordBody::Decision {
            identity: SubmissionIdentity::new(
                TenantName::parse("test").unwrap().to_tenant(),
                PRINCIPAL.to_principal(),
                Operation::new(vec![1]).unwrap(),
                GrainId::of(candidate),
            ),
            root_seq: doc.seq,
            base: doc.parent,
            decided_at: FixedClock.now(),
            candidate: RootBytes::new(candidate.to_vec()).unwrap(),
        },
    )
    .unwrap()
}
struct NeverPolled;
impl Body for NeverPolled {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        panic!("refusal read request body")
    }
}

#[tokio::test]
async fn publish_response_metadata_agrees() {
    let (fx, driver) = Fx::new(false, &[], &[]).await;
    let mut run = spawn_driver(driver);
    let rows = [
        (
            "GET",
            "/volume/vol-a/publish",
            405,
            Some("method-not-allowed"),
        ),
        ("POST", "/volume/vol-a/publish", 400, Some("bad-request")),
    ];
    for (method, path, status, token) in rows {
        let response = fx
            .send(request(method, path, Full::new(Bytes::new())))
            .await;
        check(&response, status, token);
        if status == 405 {
            assert_eq!(response.headers()["allow"], "POST");
        }
    }
    let mut r = publish(1, vec![]);
    r.extensions_mut().clear();
    check(&fx.send(r).await, 403, Some("no-principal"));
    let mut r = publish(1, vec![]);
    r.headers_mut().insert("if-match", "*".parse().unwrap());
    check(&fx.send(r).await, 400, Some("bad-request"));
    fx.refill(100);
    let mut r = publish(1, vec![]);
    r.headers_mut()
        .insert("content-length", "65537".parse().unwrap());
    check(&fx.send(r).await, 413, Some("too-large"));
    fx.refill(200);
    check(
        &fx.send(publish(1, vec![0; 65537])).await,
        413,
        Some("too-large"),
    );
    fx.refill(300);
    check(&fx.send(publish(1, vec![])).await, 404, Some("no-log"));
    for _ in 0..4 {
        drop(fx.controls.admit(PRINCIPAL, true).unwrap());
    }
    check(
        &fx.send(publish(1, vec![])).await,
        429,
        Some("rate-limited"),
    );
    fx.handle.stop().await;
    assert_eq!(run.join_next().await.unwrap().unwrap(), RunEnd::Stopped);
    fx.refill(400);
    check(&fx.send(publish(1, vec![])).await, 503, Some("stopped"));
}

#[tokio::test]
async fn publish_fields_are_strict_and_bounded() {
    let (fx, driver) = Fx::new(false, &[], &[]).await;
    let mut run = spawn_driver(driver);
    for (n, (field, value)) in [
        ("granary-operation", ""),
        ("granary-operation", "a"),
        ("granary-operation", "AA"),
        ("granary-operation", "ab,cd"),
        ("granary-operation", "ag"),
        ("granary-operation", "ab cd"),
        ("granary-epoch", "0"),
        ("granary-epoch", "0000000000000000000000000000000A"),
        (
            "granary-epoch",
            "0000000000000000000000000000000000,00000000000000000000000000000000",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        fx.refill(n as i128 * 100);
        let mut r = publish(1, vec![]);
        r.headers_mut().insert(field, value.parse().unwrap());
        check(&fx.send(r).await, 400, Some("bad-request"));
    }
    let mut tick = 1000;
    for name in ["granary-operation", "granary-epoch"] {
        for duplicate in [false, true] {
            fx.refill(tick);
            tick += 100;
            let mut r = publish(1, vec![]);
            if duplicate {
                let value = r.headers()[name].clone();
                r.headers_mut().append(name, value);
            } else {
                r.headers_mut().remove(name);
            }
            check(&fx.send(r).await, 400, Some("bad-request"));
        }
    }
    for (len, status) in [(2, 404), (510, 404), (512, 400)] {
        fx.refill(tick);
        tick += 100;
        let mut r = publish(1, vec![]);
        r.headers_mut()
            .insert("granary-operation", "ab".repeat(len / 2).parse().unwrap());
        check(
            &fx.send(r).await,
            status,
            Some(if status == 404 {
                "no-log"
            } else {
                "bad-request"
            }),
        );
    }
    fx.refill(tick);
    let mut r = publish(1, vec![]);
    r.headers_mut()
        .insert("granary-operation", " \tab\t ".parse().unwrap());
    check(&fx.send(r).await, 404, Some("no-log"));
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn write_refusal_precedes_body_and_store() {
    let (fx, driver) = Fx::new(false, &[], &[]).await;
    let mut run = spawn_driver(driver);
    let before = fx.store.calls.load(Ordering::Relaxed);
    let mut anonymous = request("PUT", &direct(&a()), NeverPolled);
    anonymous.extensions_mut().clear();
    let response = fx.send(anonymous).await;
    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["granary-error"], "no-principal");
    let response = fx.send(request("PUT", &direct(&a()), NeverPolled)).await;
    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["granary-error"], "authority-managed");
    assert_eq!(response.headers()["connection"], "close");
    assert_eq!(
        fx.store.calls.load(Ordering::Relaxed),
        before,
        "refusal probed store"
    );
    assert_eq!(fx.controls.in_flight(PRINCIPAL), 0);
    assert_eq!(
        fx.store.inner.get_root(a().as_str(), 1).await.unwrap(),
        None
    );
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn competing_refusals_follow_decision_3() {
    let (fx, driver) = Fx::new(false, &[], &[]).await;
    let mut run = spawn_driver(driver);
    let slots: Vec<_> = (0..4)
        .map(|_| fx.controls.admit(PRINCIPAL, false).unwrap())
        .collect();
    let mut r = request("PUT", &direct(&a()), NeverPolled);
    r.extensions_mut().clear();
    let response = fx.send(r).await;
    assert_eq!(response.headers()["granary-error"], "no-principal");
    let response = fx.send(request("PUT", &direct(&a()), NeverPolled)).await;
    assert_eq!(
        response.status(),
        403,
        "managed refusal must precede controls"
    );
    assert_eq!(response.headers()["granary-error"], "authority-managed");
    check(
        &fx.send(request("POST", "/volume/vol-a/publish", NeverPolled))
            .await,
        429,
        Some("rate-limited"),
    );
    drop(slots);
    let mut r = request("POST", "/volume/vol-a/publish", NeverPolled);
    r.headers_mut()
        .insert("content-length", "65537".parse().unwrap());
    check(&fx.send(r).await, 400, Some("bad-request"));
    // Field refusals spend submission tokens and release occupancy.
    for _ in 0..4 {
        check(
            &fx.send(request("POST", "/volume/vol-a/publish", NeverPolled))
                .await,
            400,
            Some("bad-request"),
        );
    }
    assert_eq!(fx.controls.in_flight(PRINCIPAL), 0);
    check(
        &fx.send(publish(1, vec![])).await,
        429,
        Some("rate-limited"),
    );
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn served_unserved_with_and_without_log() {
    for has_log in [false, true] {
        let logs = if has_log { vec![a(), b()] } else { vec![] };
        let (fx, driver) = Fx::new(false, &logs, &[]).await;
        let mut run = spawn_driver(driver);
        for (n, v) in [a(), b()].into_iter().enumerate() {
            let response = fx
                .send(request(
                    "PUT",
                    &direct(&v),
                    Full::new(Bytes::from_static(b"seam")),
                ))
                .await;
            assert_eq!(response.status(), if v == a() { 403 } else { 201 });
            let response = fx
                .send(request(
                    "PUT",
                    &direct(&v),
                    Full::new(Bytes::from_static(b"seam")),
                ))
                .await;
            assert_eq!(response.status(), if v == a() { 403 } else { 409 });
            fx.refill((n as i128 + 1) * 100);
            let response = fx.send(publish_to(&v, 1, vec![])).await;
            let expected = if v != a() {
                (404, "unknown-volume")
            } else if has_log {
                (400, "invalid-candidate")
            } else {
                (404, "no-log")
            };
            check(&response, expected.0, Some(expected.1));
        }
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
        fx.refill(1000);
        for v in [a(), b()] {
            check(
                &fx.send(publish_to(&v, 1, vec![])).await,
                503,
                Some("stopped"),
            );
        }
        let response = fx.send(request("PUT", &direct(&a()), NeverPolled)).await;
        assert_eq!(response.status(), 403);
    }
    let (fx, driver) = Fx::new(false, &[], &[]).await;
    drop(driver);
    for v in [a(), b()] {
        check(
            &fx.send(publish_to(&v, 1, vec![])).await,
            503,
            Some("stopped"),
        );
    }
    assert_eq!(
        fx.send(request("PUT", &direct(&a()), NeverPolled))
            .await
            .status(),
        403
    );
}

#[tokio::test]
async fn every_write_requires_current_principal() {
    for endpoint in 0..5 {
        let (fx, driver) = Fx::new(false, &[], &[]).await;
        let mut run = spawn_driver(driver);
        let data = b"payload";
        let id = GrainId::of(data);
        let paths = [
            format!("/bin/{}", hex(id)),
            format!("/volume/vol-b/meta/{id}"),
            direct(&b()),
            "/volume/vol-b/hint".into(),
            "/volume/vol-a/publish".into(),
        ];
        let path = &paths[endpoint];
        let method = if endpoint == 4 { "POST" } else { "PUT" };
        for (identity, token) in [
            (None, "no-principal"),
            (Some(ClientSpkiDigest::from_bytes([9; 32])), "not-enrolled"),
        ] {
            let mut r = request(method, path, NeverPolled);
            r.extensions_mut().insert(
                identity.map_or(ConnectionIdentity::Anonymous, ConnectionIdentity::Verified),
            );
            let response = fx.send(r).await;
            assert_eq!(response.status(), 403);
            assert_eq!(response.headers()["granary-error"], token);
        }
        // An enrolled positive control reaches the endpoint's own check or store.
        let r = if endpoint == 4 {
            publish(1, vec![])
        } else {
            request(
                method,
                path,
                Full::new(Bytes::from(if endpoint == 3 {
                    b"00000000000000000001".to_vec()
                } else {
                    data.to_vec()
                })),
            )
        };
        let response = fx.send(r).await;
        assert_eq!(
            response.status().as_u16(),
            [201, 201, 201, 204, 404][endpoint]
        );
        crate::enrollment::revoke(&fx.dir.join("enrollment"), OPTIONS, DIGEST).unwrap();
        let response = fx.send(request(method, path, NeverPolled)).await;
        assert_eq!(response.status(), 403);
        assert_eq!(response.headers()["granary-error"], "not-enrolled");
        crate::enrollment::retire(&fx.dir.join("enrollment"), OPTIONS, PRINCIPAL).unwrap();
        let response = fx.send(request(method, path, NeverPolled)).await;
        assert_eq!(response.status(), 403);
        assert_eq!(response.headers()["granary-error"], "not-enrolled");
        let empty =
            granary_core::enrollment::encode_set(&granary_core::enrollment::EnrollmentSet::empty());
        let set_path = fx.dir.join("enrollment/ENROLLMENT");
        std::fs::write(&set_path, empty.as_bytes()).unwrap();
        let response = fx.send(request(method, path, NeverPolled)).await;
        assert_eq!(response.status(), 403);
        assert_eq!(response.headers()["granary-error"], "not-enrolled");
        // Rename the whole set directory: current lookup must fail closed.
        std::fs::rename(fx.dir.join("enrollment"), fx.dir.join("unavailable")).unwrap();
        let response = fx.send(request(method, path, NeverPolled)).await;
        assert_eq!(response.status(), 503);
        assert_eq!(
            response.headers()["granary-error"],
            "enrollment-unavailable"
        );
        let snapshot = fx.reader.snapshot();
        assert!(format!("{snapshot:?}").contains("Unavailable"));
        let mut r = request(method, path, NeverPolled);
        r.extensions_mut().clear();
        assert_eq!(fx.send(r).await.headers()["granary-error"], "no-principal");
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
    }
}

/// Every binary kind comes from a real engine scenario. The held read keeps
/// unrelated publication progress outside each byte-comparison interval.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "exhaustive engine answer matrix with byte comparisons under both log backends"
)]
async fn publish_answer_positive_controls() {
    for file in [false, true] {
        let candidate = good_root(&a(), 1, None, 1);
        let other = good_root(&a(), 1, None, 2);
        let d = decision_for(&candidate);
        for closed in [0, 1, 2] {
            let mut records = vec![d.clone(), attestation(&d)];
            if closed == 1 {
                records.push(landed(&d));
            }
            if closed == 2 {
                records.push(lost(&d, GrainId::of(&other)));
            }
            let (fx, driver) = Fx::new(file, &[a()], &records).await;
            if closed == 0 {
                fx.store.inner.hold_read(&a(), 1);
            }
            let mut run = spawn_driver(driver);
            let before = fx.bytes().await;
            if closed == 0 {
                binary(fx.send(publish(1, candidate.clone())).await, 202, None, 4).await;
                binary(
                    fx.send(publish(1, other.clone())).await,
                    409,
                    Some("operation-bound"),
                    6,
                )
                .await;
                binary(
                    fx.send(publish(2, other.clone())).await,
                    409,
                    Some("not-decided"),
                    7,
                )
                .await;
            } else {
                let kind = if closed == 1 { 1 } else { 2 };
                let value = binary(
                    fx.send(publish(1, candidate.clone())).await,
                    200,
                    None,
                    kind,
                )
                .await;
                assert!(matches!(
                    value,
                    PublishAnswer::Landed {
                        head: Some(codec::Head { root: None, .. }),
                        ..
                    } | PublishAnswer::Lost {
                        head: Some(codec::Head { root: None, .. }),
                        ..
                    }
                ));
                if closed == 1 {
                    binary(
                        fx.send(publish(1, other.clone())).await,
                        409,
                        Some("operation-bound"),
                        6,
                    )
                    .await;
                }
                fx.store
                    .inner
                    .put_root(
                        a().as_str(),
                        1,
                        if closed == 1 {
                            candidate.clone()
                        } else {
                            other.clone()
                        },
                    )
                    .await
                    .unwrap();
                fx.refill(100);
                let value = binary(
                    fx.send(publish(1, candidate.clone())).await,
                    200,
                    None,
                    kind,
                )
                .await;
                assert!(matches!(
                    value,
                    PublishAnswer::Landed {
                        head: Some(codec::Head { root: Some(_), .. }),
                        ..
                    } | PublishAnswer::Lost {
                        head: Some(codec::Head { root: Some(_), .. }),
                        ..
                    }
                ));
                fx.store
                    .inner
                    .set_read_fault(&a(), 1, Some(ReadFault::Transport));
                let value = binary(
                    fx.send(publish(1, candidate.clone())).await,
                    200,
                    None,
                    kind,
                )
                .await;
                assert!(matches!(
                    value,
                    PublishAnswer::Landed { head: None, .. }
                        | PublishAnswer::Lost { head: None, .. }
                ));
            }
            assert_eq!(
                fx.bytes().await,
                before,
                "read-only answer changed complete log bytes"
            );
            assert_eq!(
                fx.service.refusal_counters().unwrap().snapshot(),
                crate::refusals::RefusalSnapshot::default(),
                "200/202/409 decision answers are not refusals"
            );
            fx.store.inner.release();
            fx.handle.stop().await;
            run.join_next().await.unwrap().unwrap();
        }
        let (fx, driver) = Fx::new(file, &[a()], &[]).await;
        let mut run = spawn_driver(driver);
        let before = fx.bytes().await;
        let ahead = good_root(&a(), 2, Some(GrainId::of(&candidate)), 3);
        binary(fx.send(publish(2, ahead)).await, 409, Some("stale-base"), 5).await;
        let mut r = publish(2, vec![0xff]);
        r.headers_mut()
            .insert("granary-epoch", "ff".repeat(16).parse().unwrap());
        let value = binary(fx.send(r).await, 409, Some("epoch-mismatch"), 8).await;
        assert_eq!(
            value,
            PublishAnswer::EpochMismatch {
                epoch: Epoch::from_bytes([WORLD_EPOCH; 16]),
                head: Some(codec::Head::new(None))
            }
        );
        check(
            &fx.send(publish(2, vec![0xff])).await,
            400,
            Some("invalid-candidate"),
        );
        let out_of_range = good_root(&a(), u64::MAX - 1, Some(GrainId::of(&candidate)), 4);
        check(
            &fx.send(publish(2, out_of_range)).await,
            400,
            Some("invalid-candidate"),
        );
        assert_eq!(fx.bytes().await, before);
        fx.refill(100);
        binary(fx.send(publish(1, candidate.clone())).await, 202, None, 3).await;
        assert_eq!(
            fx.service.refusal_counters().unwrap().snapshot().totals,
            [(crate::ErrorToken::InvalidCandidate, 2)]
                .into_iter()
                .collect()
        );
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
        assert_eq!(
            fx.records()
                .await
                .iter()
                .filter(|r| matches!(r.body(), RecordBody::Decision { .. }))
                .count(),
            1
        );
        let response =
            crate::adapter::publish::outcome(&Answer::InvalidCandidate(InvalidCandidate::TooLong));
        assert_eq!(response.status(), crate::Status::ContentTooLarge);
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one refusal matrix snapshots the same complete logs around every response"
)]
async fn every_4xx_leaves_logs_byte_identical() {
    for file in [false, true] {
        // Complete snapshots include a served log, an unserved stray log,
        // and absence. No publication is open in this fixture.
        let (fx, driver) = Fx::new(file, &[a(), b()], &[]).await;
        let mut run = spawn_driver(driver);
        let candidate = good_root(&a(), 1, None, 1);
        let mut requests = Vec::new();
        let mut anonymous = publish(1, candidate.clone());
        anonymous.extensions_mut().clear();
        requests.push((anonymous, 403, "no-principal"));
        let mut unknown = publish(1, candidate.clone());
        unknown
            .extensions_mut()
            .insert(ConnectionIdentity::Verified(ClientSpkiDigest::from_bytes(
                [9; 32],
            )));
        requests.push((unknown, 403, "not-enrolled"));
        requests.push((
            request(
                "PUT",
                &direct(&a()),
                Full::new(Bytes::from(candidate.clone())),
            ),
            403,
            "authority-managed",
        ));
        requests.push((
            request("POST", "/volume/vol-a/publish?q=1", Full::new(Bytes::new())),
            404,
            "unknown-target",
        ));
        requests.push((
            request("GET", "/volume/vol-a/publish", Full::new(Bytes::new())),
            405,
            "method-not-allowed",
        ));
        let mut conditional = publish(1, candidate.clone());
        conditional
            .headers_mut()
            .insert("if-match", "*".parse().unwrap());
        requests.push((conditional, 400, "bad-request"));
        let mut missing_field = publish(1, candidate.clone());
        missing_field.headers_mut().remove("granary-operation");
        requests.push((missing_field, 400, "bad-request"));
        let mut declared = publish(1, candidate.clone());
        declared
            .headers_mut()
            .insert("content-length", "65537".parse().unwrap());
        requests.push((declared, 413, "too-large"));
        requests.push((publish(1, vec![0; 65537]), 413, "too-large"));
        requests.push((
            publish_to(&b(), 1, candidate.clone()),
            404,
            "unknown-volume",
        ));
        requests.push((publish(1, vec![0xff]), 400, "invalid-candidate"));
        requests.push((
            publish(1, good_root(&a(), 2, Some(GrainId::of(&candidate)), 2)),
            409,
            "stale-base",
        ));
        let mut epoch = publish(1, candidate.clone());
        epoch
            .headers_mut()
            .insert("granary-epoch", "ff".repeat(16).parse().unwrap());
        requests.push((epoch, 409, "epoch-mismatch"));
        for (n, (r, status, token)) in requests.into_iter().enumerate() {
            fx.refill(n as i128 * 100);
            let before = fx.bytes().await;
            let response = fx.send(r).await;
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()["granary-error"], token);
            assert_eq!(fx.bytes().await, before, "{token}: complete logs changed");
        }
        fx.refill(10000);
        let permits: Vec<_> = (0..4)
            .map(|_| fx.controls.admit(PRINCIPAL, false).unwrap())
            .collect();
        let before = fx.bytes().await;
        check(
            &fx.send(publish(1, candidate.clone())).await,
            429,
            Some("rate-limited"),
        );
        assert_eq!(fx.bytes().await, before);
        drop(permits);
        fx.store
            .inner
            .put_root(a().as_str(), 1, vec![0xff])
            .await
            .unwrap();
        let before = fx.bytes().await;
        binary(
            fx.send(publish(1, candidate)).await,
            409,
            Some("volume-damaged"),
            9,
        )
        .await;
        assert_eq!(fx.bytes().await, before);
        let mut r = publish(1, vec![]);
        r.headers_mut()
            .insert("granary-epoch", "ff".repeat(16).parse().unwrap());
        let value = binary(fx.send(r).await, 409, Some("epoch-mismatch"), 8).await;
        assert!(matches!(
            value,
            PublishAnswer::EpochMismatch { head: None, .. }
        ));
        assert_eq!(fx.bytes().await, before);
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
        // No-log must preserve absence, too.
        let (fx, driver) = Fx::new(file, &[b()], &[]).await;
        let mut run = spawn_driver(driver);
        let before = fx.bytes().await;
        check(&fx.send(publish(1, vec![])).await, 404, Some("no-log"));
        assert_eq!(fx.bytes().await, before);
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn request_identity_claims_are_ignored() {
    let (fx, driver) = Fx::new(false, &[a()], &[]).await;
    let mut run = spawn_driver(driver);
    let candidate = good_root(&a(), 1, None, 1);
    let mut r = publish(7, candidate.clone());
    for name in ["granary-principal", "granary-tenant", "principal", "tenant"] {
        r.headers_mut().insert(name, "spoofed".parse().unwrap());
    }
    r.headers_mut()
        .insert("content-type", "text/not-a-root".parse().unwrap());
    binary(fx.send(r).await, 202, None, 3).await;
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
    let records = fx.records().await;
    let identity = records.first().unwrap().body().identity();
    assert_eq!(identity.principal(), &PRINCIPAL.to_principal());
    assert_eq!(
        identity.tenant(),
        &TenantName::parse("test").unwrap().to_tenant()
    );
    assert_eq!(identity.operation().as_bytes(), [7]);
    let RecordBody::Decision {
        candidate: actual, ..
    } = records.first().unwrap().body()
    else {
        panic!("decision")
    };
    assert_eq!(actual.as_bytes(), candidate);
}

#[tokio::test]
async fn streamed_refusals_are_413_then_429_then_503() {
    for file in [false, true] {
        let (mut fx, driver) = Fx::new(file, &[a()], &[]).await;
        let mut run = spawn_driver(driver);
        fx.service = fx.service_with_budget(fx.handle.clone(), 0);
        let permit = fx.controls.admit(PRINCIPAL, false).unwrap();
        permit
            .charge_bytes(granary_core::binfmt::BIN_MAX_BYTES)
            .unwrap();
        drop(permit);
        let before = fx.bytes().await;
        check(
            &fx.send(publish(1, vec![0; 65537])).await,
            413,
            Some("too-large"),
        );
        assert_eq!(fx.bytes().await, before);
        check(
            &fx.send(publish(1, vec![0; 1])).await,
            429,
            Some("rate-limited"),
        );
        assert_eq!(fx.bytes().await, before);
        fx.refill(100);
        check(
            &fx.send(publish(1, vec![0; 1])).await,
            503,
            Some("unavailable"),
        );
        assert_eq!(fx.bytes().await, before);
        assert_eq!(fx.controls.in_flight(PRINCIPAL), 0);
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn settle_fence_retransmission_converges() {
    for file in [false, true] {
        let (mut fx, mut driver) = Fx::new(file, &[a()], &[]).await;
        driver
            .workers
            .first_mut()
            .unwrap()
            .state_mut()
            .unwrap()
            .refuse_next_apply(ApplyError {
                seq: 1,
                rule: GrammarRule::Rule1SequencePosition,
            });
        let mut run = spawn_driver(driver);
        let candidate = good_root(&a(), 1, None, 1);
        check(
            &fx.send(publish(1, candidate.clone())).await,
            503,
            Some("fenced"),
        );
        assert!(matches!(
            run.join_next().await.unwrap().unwrap(),
            RunEnd::Fenced(_)
        ));
        for v in [a(), b()] {
            check(
                &fx.send(publish_to(&v, 1, candidate.clone())).await,
                503,
                Some("fenced"),
            );
        }
        assert_eq!(
            fx.send(request("PUT", &direct(&a()), NeverPolled))
                .await
                .status(),
            403
        );
        assert_eq!(
            fx.records().await,
            vec![decision_for(&candidate)],
            "the durable decision survives the refused application"
        );
        assert!(matches!(
            start(fx.parts(), boot(1), configs(&[a()])).await,
            Err(StartRefused::RunningInThisBoot)
        ));
        let (handle, driver) = start(fx.parts(), boot(2), configs(&[a()])).await.unwrap();
        fx.service =
            fx.service_with_budget(handle.clone(), crate::adapter::WRITE_BODY_BUDGET_BYTES);
        fx.handle = handle;
        let mut run = spawn_driver(driver);
        let mut landed = None;
        for n in 1..100 {
            fx.refill(n * 100);
            let response = fx.send(publish(1, candidate.clone())).await;
            assert!(response.status() == 200 || response.status() == 202);
            if response.status() == 200 {
                landed = Some(binary(response, 200, None, 1).await);
                break;
            }
            binary(response, 202, None, 4).await;
            tokio::task::yield_now().await;
        }
        let Some(PublishAnswer::Landed { receipt, .. }) = landed else {
            panic!("unchanged retransmission did not land")
        };
        assert_eq!(receipt.position.entry_seq, 1);
        assert_eq!(receipt.position.epoch, Epoch::from_bytes([WORLD_EPOCH; 16]));
        assert_eq!(receipt.stored_id, GrainId::of(&candidate));
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
        let decisions: Vec<_> = fx
            .records()
            .await
            .into_iter()
            .filter(|r| matches!(r.body(), RecordBody::Decision { .. }))
            .collect();
        assert_eq!(
            decisions,
            vec![decision_for(&candidate)],
            "retransmission added a second decision"
        );
    }
}

#[test]
fn encoding_failure_is_internal() {
    let response = crate::adapter::publish::outcome(&Answer::Accepted {
        position: Position {
            epoch: Epoch::from_bytes([1; 16]),
            seq: 0,
        },
        candidate_id: GrainId::of(b"candidate"),
    });
    assert_eq!(response.status(), crate::Status::InternalServerError);
    assert_eq!(response.error(), Some(crate::ErrorToken::Internal));
    assert_eq!(response.cache_control(), Some(crate::CacheControl::NoStore));
}

#[tokio::test]
async fn gateway_refusal_counters_count_once() {
    let (fx, driver) = Fx::new(false, &[], &[]).await;
    let mut run = spawn_driver(driver);
    let counters = fx.service.refusal_counters().unwrap();
    let other = fx.service_with_budget(fx.handle.clone(), crate::adapter::WRITE_BODY_BUDGET_BYTES);
    assert!(Arc::ptr_eq(&counters, &other.refusal_counters().unwrap()));
    let id = GrainId::of(b"missing");
    for (method, path, status, token) in [
        ("GET", direct(&a()), 404, "not-found"),
        ("GET", format!("/bin/{}", hex(id)), 400, "bad-range"),
        ("PUT", "/unknown".into(), 404, "unknown-target"),
        (
            "POST",
            "/volume/vol-a/status".into(),
            405,
            "method-not-allowed",
        ),
        (
            "GET",
            "/volume/vol-a/publish".into(),
            405,
            "method-not-allowed",
        ),
    ] {
        let mut r = request(method, &path, Full::new(Bytes::new()));
        r.extensions_mut().clear();
        let response = fx.send(r).await;
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["granary-error"], token);
    }
    assert_eq!(
        counters.snapshot(),
        crate::refusals::RefusalSnapshot::default()
    );
    let mut anonymous = publish(1, vec![]);
    anonymous.extensions_mut().clear();
    check(
        &other.request_for_test(anonymous).await,
        403,
        Some("no-principal"),
    );
    assert_eq!(
        fx.send(request("PUT", &direct(&a()), NeverPolled))
            .await
            .status(),
        403
    );
    check(&fx.send(publish(1, vec![])).await, 404, Some("no-log"));
    let mut fields = publish(1, vec![]);
    fields.headers_mut().remove("granary-operation");
    check(&fx.send(fields).await, 400, Some("bad-request"));
    check(
        &fx.send(publish(1, vec![0; 65537])).await,
        413,
        Some("too-large"),
    );
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
    fx.refill(100);
    check(&fx.send(publish(1, vec![])).await, 503, Some("stopped"));
    let snapshot = counters.snapshot();
    let enrolled = [
        (crate::ErrorToken::AuthorityManaged, 1),
        (crate::ErrorToken::NoLog, 1),
        (crate::ErrorToken::BadRequest, 1),
        (crate::ErrorToken::TooLarge, 1),
        (crate::ErrorToken::Stopped, 1),
    ];
    assert_eq!(
        snapshot.totals,
        enrolled
            .into_iter()
            .chain([(crate::ErrorToken::NoPrincipal, 1)])
            .collect()
    );
    assert_eq!(
        snapshot.principals,
        [(PRINCIPAL, enrolled.into_iter().collect())]
            .into_iter()
            .collect()
    );
}

async fn stalled_publish(drain: bool) {
    let (fx, driver) = Fx::new(false, &[a()], &[]).await;
    let head = good_root(&a(), 1, None, 1);
    fx.store
        .put_root(a().as_str(), 1, head.clone())
        .await
        .unwrap();
    fx.store.inner.hold_read(&a(), 1);
    let fx = fx.with_dispatch_deadline(Duration::from_secs(if drain { 60 } else { 1 }));
    let mut run = spawn_driver(driver);
    let mut response =
        std::pin::pin!(fx.send(publish(1, good_root(&a(), 2, Some(GrainId::of(&head)), 2))));
    let mut response = std::pin::pin!(std::future::poll_fn(|cx| {
        let result = response.as_mut().poll(cx);
        if fx.store.inner.hold_reached() {
            if drain {
                fx.service.draining().begin();
            }
        } else {
            cx.waker().wake_by_ref();
        }
        result
    }));
    let response = if drain {
        response.await
    } else if let Ok(answer) = tokio::time::timeout(Duration::from_secs(2), &mut response).await {
        answer
    } else {
        // A gateway that ignores the deadline receives the real answer.
        fx.store.inner.release();
        response.await
    };
    assert!(
        fx.store.inner.hold_reached(),
        "read was never held: {response:?}"
    );
    check(&response, 503, Some("unavailable"));
    fx.store.inner.release();
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn stalled_publish_obeys_dispatch_deadline() {
    stalled_publish(false).await;
}

#[tokio::test]
async fn stalled_publish_is_shed_on_drain() {
    stalled_publish(true).await;
}

#[cfg(feature = "crash-points")]
#[tokio::test(start_paused = true)]
#[expect(
    clippy::disallowed_methods,
    reason = "measure the gateway timeout on the runtime's paused clock"
)]
async fn test_reply_deadline_bounds_authority_and_leaves_store_dispatch_alone() {
    let reply_deadline = Duration::from_millis(250);
    let dispatch_deadline = Duration::from_secs(5);
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let mut fx = fx.with_dispatch_deadline(dispatch_deadline);
    // Served through a clone, as each connection is, so Clone must carry the bound.
    fx.service = fx.service.with_test_reply_deadline(reply_deadline).clone();

    // The unpolled driver keeps each submitted authority reply pending.
    let inbox = &fx.handle.inner.inboxes[&a()];
    let intent = format!("/volume/{}/intent", a().as_str());
    for request in [
        publish(1, good_root(&a(), 1, None, 1)),
        request("POST", &intent, Full::new(Bytes::new())),
        request("GET", &intent, Full::new(Bytes::new())),
    ] {
        let route = format!("{} {}", request.method(), request.uri());
        let capacity = inbox.capacity();
        let start = tokio::time::Instant::now();
        let response = fx.send(request).await;
        let elapsed = start.elapsed();
        assert_eq!(
            (capacity.checked_sub(inbox.capacity()), elapsed),
            (Some(1), reply_deadline),
            "{route}: mailbox occupancy and reply wait for {response:?}"
        );
        check(&response, 503, Some("unavailable"));
    }

    fx.store
        .put_root(a().as_str(), 1, good_root(&a(), 1, None, 1))
        .await
        .unwrap();
    fx.store.inner.hold_read(&a(), 1);
    let root = format!("/volume/{}/root/{:020}", a().as_str(), 1);
    let mut read = std::pin::pin!(fx.send(request("GET", &root, Full::new(Bytes::new()))));
    std::future::poll_fn(|cx| {
        let polled = read.as_mut().poll(cx);
        match (fx.store.inner.hold_reached(), polled) {
            (true, Poll::Pending) => Poll::Ready(()),
            (false, Poll::Pending) => Poll::Pending,
            (held, Poll::Ready(response)) => {
                panic!("store read finished before release (held: {held}): {response:?}")
            }
        }
    })
    .await;
    tokio::time::advance(reply_deadline * 2).await;
    let held = std::future::poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await;
    assert!(
        held.is_pending(),
        "store read finished while held: {held:?}"
    );
    fx.store.inner.release();
    let response = read.await;
    assert_eq!(response.status().as_u16(), 200, "{response:?}");
}

#[tokio::test]
async fn enrollment_unavailable_is_pre_engine_and_preserves_prior_decisions() {
    let d = decision(&a(), 1, 1, 1, None, 1);
    let (fx, driver) = Fx::new(false, &[a()], &[d]).await;
    let before = fx.bytes().await;
    let calls = fx.store.calls.load(Ordering::SeqCst);
    std::fs::rename(fx.dir.join("enrollment"), fx.dir.join("unavailable")).unwrap();
    check(
        &fx.send(publish(2, good_root(&a(), 1, None, 2))).await,
        503,
        Some("enrollment-unavailable"),
    );
    assert_eq!(fx.bytes().await, before);
    assert_eq!(fx.store.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fx.controls.in_flight(PRINCIPAL), 0);
    // Reads do not consult enrollment or dispatch through the unstarted driver.
    check(
        &fx.send(request(
            "GET",
            "/volume/vol-a/status",
            Full::new(Bytes::new()),
        ))
        .await,
        200,
        None,
    );
    let mut run = spawn_driver(driver);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn unavailable_reply_and_later_admission_refusal_do_not_cancel_submission() {
    let (fx, driver) = Fx::new(false, &[a()], &[]).await;
    let head = good_root(&a(), 1, None, 1);
    fx.store
        .put_root(a().as_str(), 1, head.clone())
        .await
        .unwrap();
    fx.store.inner.hold_read(&a(), 1);
    let fx = fx.with_dispatch_deadline(Duration::from_millis(20));
    let mut run = spawn_driver(driver);
    let bytes = good_root(&a(), 2, Some(GrainId::of(&head)), 2);
    let owned = granary_client::OwnedCandidate::new(a().as_str(), bytes.clone().into()).unwrap();
    let retained_request = granary_client::PublishRequest::new(
        a().as_str(),
        Epoch::from_bytes([WORLD_EPOCH; 16]),
        &[2],
        owned.clone(),
        vec![owned],
    )
    .unwrap();
    let mut evidence = granary_core::retained_submission::Evidence::default();
    let first_attempt = evidence.start().unwrap();
    let response = fx.send(publish(2, bytes.clone())).await;
    check(&response, 503, Some("unavailable"));
    let checked = granary_client::validate_publish_answer(
        &retained_request,
        response.status().as_u16(),
        Some("unavailable"),
        &[],
    )
    .unwrap();
    evidence
        .answer(first_attempt, checked.request_wrote_nothing(), false)
        .unwrap();
    assert!(
        fx.store.inner.hold_reached(),
        "submission reached the engine"
    );
    std::fs::rename(fx.dir.join("enrollment"), fx.dir.join("unavailable")).unwrap();
    let second_attempt = evidence.start().unwrap();
    let response = fx.send(publish(2, bytes.clone())).await;
    check(&response, 503, Some("enrollment-unavailable"));
    let checked = granary_client::validate_publish_answer(
        &retained_request,
        response.status().as_u16(),
        Some("enrollment-unavailable"),
        &[],
    )
    .unwrap();
    evidence
        .answer(second_attempt, checked.request_wrote_nothing(), false)
        .unwrap();
    assert_eq!(evidence.started, 2);
    assert_eq!(evidence.proved_no_write, 1);
    assert!(
        !evidence.never_decided(),
        "the earlier dispatched request remains uncertain"
    );
    fx.store.inner.release();
    for _ in 0..1000 {
        if fx
            .records()
            .await
            .iter()
            .any(|r| r.body().identity().candidate_id() == GrainId::of(&bytes))
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        fx.records()
            .await
            .iter()
            .any(|r| r.body().identity().candidate_id() == GrainId::of(&bytes)),
        "the unanswered submission must remain able to decide"
    );
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn rotated_connection_has_same_principal_and_revoked_old_connection_is_refused() {
    let (fx, driver) = Fx::new(false, &[a()], &[]).await;
    let rotated = ClientSpkiDigest::from_bytes([77; 32]);
    crate::enrollment::attach(&fx.dir.join("enrollment"), OPTIONS, PRINCIPAL, rotated).unwrap();
    let mut run = spawn_driver(driver);
    // Warm both authenticated connection identities at the admission gate.
    for digest in [DIGEST, rotated] {
        let mut r = publish(1, vec![]);
        r.extensions_mut()
            .insert(ConnectionIdentity::Verified(digest));
        check(&fx.send(r).await, 400, Some("invalid-candidate"));
    }
    crate::enrollment::revoke(&fx.dir.join("enrollment"), OPTIONS, DIGEST).unwrap();
    let before = fx.bytes().await;
    check(
        &fx.send(publish(1, good_root(&a(), 1, None, 1))).await,
        403,
        Some("not-enrolled"),
    );
    assert_eq!(fx.bytes().await, before);
    let mut r = publish(1, good_root(&a(), 1, None, 1));
    r.extensions_mut()
        .insert(ConnectionIdentity::Verified(rotated));
    binary(fx.send(r).await, 202, None, 3).await;
    let record = fx
        .records()
        .await
        .into_iter()
        .find(|r| matches!(r.body(), RecordBody::Decision { .. }))
        .unwrap();
    assert_eq!(
        record.body().identity().principal(),
        &PRINCIPAL.to_principal()
    );
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn round1_intent_mutations_share_publish_submission_tokens() {
    for (method, suffix) in [
        ("POST", "intent"),
        ("POST", "intent/release"),
        ("POST", "intent/ownership"),
    ] {
        let (fx, driver) = Fx::new(false, &[a()], &[]).await;
        let request_work = async {
            let path = format!("/volume/{}/{suffix}", a().as_str());
            for _ in 0..5 {
                let response = fx
                    .send(request(method, &path, Full::new(Bytes::new())))
                    .await;
                assert_ne!(response.status().as_u16(), 429, "burst available");
            }
            check(
                &fx.send(request(method, &path, Full::new(Bytes::new())))
                    .await,
                429,
                Some("rate-limited"),
            );
            check(
                &fx.send(publish(1, vec![])).await,
                429,
                Some("rate-limited"),
            );
            fx.handle.stop().await
        };
        let mut tasks = spawn_driver(driver);
        let stopped = request_work.await;
        let end = tasks.join_next().await.unwrap().unwrap();
        assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
    }
}

#[tokio::test]
async fn product_maintenance_enrolls_evicts_and_preserves_h_after_explicit_initialise() {
    use crate::authority::intent::{codec, tests as intents};
    let (fx, driver) = Fx::new(true, &[], &[]).await;
    let requests = async {
        fx.handle.initialise(&a()).await.unwrap();
        fx.service.maintain_intents().await.unwrap();
        let path = fx.state_dir.join(format!("{}.intent", a().as_str()));
        assert!(path.exists());
        let principal = fx
            .reader
            .current_set()
            .await
            .unwrap()
            .principals()
            .next()
            .unwrap()
            .0;
        let acquire = fx
            .handle
            .intent(
                &a(),
                principal,
                crate::authority::IntentOperation::Ownership,
                intents::acquire(1, 2, 0),
            )
            .await;
        assert_eq!(acquire.status().as_u16(), 200);
        fx.service.maintain_intents().await.unwrap();
        // Enrollment changes are observed through the product reader, not a supplied set.
        let (new, _) = crate::mint(
            &fx.config.enrollment_dir,
            OPTIONS,
            &TenantName::parse("test").unwrap(),
            ClientSpkiDigest::from_bytes([8; 32]),
            &mut secure(9),
        )
        .unwrap();
        fx.service.maintain_intents().await.unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let snapshot = codec::decode(
            bytes.as_slice(),
            &a(),
            None,
            &TrustedKeys::new([*publisher().public_key()]).unwrap(),
        )
        .unwrap();
        assert!(snapshot.principals.contains_key(&new));
        assert_eq!(snapshot.principals[&principal].h, 1);
        fx.handle.stop().await
    };
    let mut tasks = spawn_driver(driver);
    let stopped = requests.await;
    let end = tasks.join_next().await.unwrap().unwrap();
    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
    // Seed an aged released row and restart; maintenance must evict it and retain H.
    let path = fx.state_dir.join(format!("{}.intent", a().as_str()));
    let bytes = std::fs::read(&path).unwrap();
    let mut snapshot = codec::decode(
        bytes.as_slice(),
        &a(),
        None,
        &TrustedKeys::new([*publisher().public_key()]).unwrap(),
    )
    .unwrap();
    let principal = snapshot
        .principals
        .iter_mut()
        .find(|(_, p)| p.h == 1)
        .unwrap()
        .1;
    principal.rows.values_mut().next().unwrap().changed.secs = i64::MIN;
    // Overflow ages retain; choose a representable age beyond the retention floor.
    principal.rows.values_mut().next().unwrap().changed.secs = -100_000;
    if let Log::File(log, _) = &fx.log {
        log.intent_store().io.commit(&snapshot).unwrap();
    }
    let config = VolumeConfig::new(a(), TrustedKeys::new([*publisher().public_key()]).unwrap())
        .with_intents(match &fx.log {
            Log::File(log, _) => log.intent_store(),
            Log::Sim(..) => unreachable!(),
        });
    let (handle, driver) = start(fx.parts(), boot(2), vec![config]).await.unwrap();
    let service = fx.service_with_budget(handle.clone(), crate::adapter::WRITE_BODY_BUDGET_BYTES);
    let request = async {
        service.maintain_intents().await.unwrap();
        handle.stop().await
    };
    let mut tasks = spawn_driver(driver);
    let stopped = request.await;
    let end = tasks.join_next().await.unwrap().unwrap();
    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
    let bytes = std::fs::read(path).unwrap();
    let next = codec::decode(
        bytes.as_slice(),
        &a(),
        None,
        &TrustedKeys::new([*publisher().public_key()]).unwrap(),
    )
    .unwrap();
    assert!(
        next.principals
            .values()
            .any(|p| p.h == 1 && p.rows.is_empty())
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "One provisioned service proves saturation, dispatch, refusal and resource recovery"
)]
async fn round1_intent_readback_respects_shared_read_count_and_enrollment_failure() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    // Poll the real driver only when explicitly allowed. Mailbox capacity then
    // distinguishes dispatch from merely waiting for a read permit.
    let (fx, driver) = Fx::new(true, &[], &[]).await;
    let mut driver = std::pin::pin!(driver.run());
    let provisioning = async {
        fx.handle.initialise(&a()).await.unwrap();
        fx.service.maintain_intents().await
    };
    tokio::pin!(provisioning);
    poll_fn(|cx| {
        if let Poll::Ready(result) = provisioning.as_mut().poll(cx) {
            result.unwrap();
            return Poll::Ready(());
        }
        assert!(
            driver.as_mut().poll(cx).is_pending(),
            "driver ended during provisioning"
        );
        Poll::Pending
    })
    .await;
    let path = format!("/volume/{}/intent", a().as_str());
    let inbox = &fx.handle.inner.inboxes[&a()];
    let capacity = inbox.capacity();
    let permits = fx.service.read_permits_handle();
    assert_eq!(permits.available_permits(), 8);
    let held = permits.acquire_many(8).await.unwrap();
    let read = fx.send(request("GET", &path, Full::new(Bytes::new())));
    tokio::pin!(read);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut read)
            .await
            .is_err()
    );
    assert_eq!(
        inbox.capacity(),
        capacity,
        "no authority dispatch before a shared permit"
    );
    assert_eq!(
        fx.controls.accounting(PRINCIPAL),
        None,
        "waiting GET holds no principal slot or allowance"
    );
    let refused = read.await;
    check(&refused, 503, Some("unavailable"));
    assert_eq!(
        inbox.capacity(),
        capacity,
        "permit timeout never dispatched"
    );
    assert!(refused.headers().get("retry-after").is_none());
    assert_eq!(refused.headers()["cache-control"], "no-store");
    drop(held);

    // Recovery: release one of the same eight permits to a waiting GET.
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(permits.acquire().await.unwrap());
    }
    let read = fx.send(request("GET", &path, Full::new(Bytes::new())));
    tokio::pin!(read);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut read)
            .await
            .is_err()
    );
    assert_eq!(inbox.capacity(), capacity, "recovery GET is still waiting");
    assert_eq!(fx.controls.accounting(PRINCIPAL), None);
    held.pop();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut read)
            .await
            .is_err()
    );
    assert_eq!(
        inbox.capacity(),
        capacity - 1,
        "released permit allows real authority dispatch"
    );
    assert_eq!(
        permits.available_permits(),
        0,
        "GET owns the released shared permit"
    );
    assert_eq!(
        fx.controls.accounting(PRINCIPAL),
        None,
        "admitted GET holds no principal slot"
    );
    let response = poll_fn(|cx| {
        if let Poll::Ready(response) = read.as_mut().poll(cx) {
            return Poll::Ready(response);
        }
        assert!(
            driver.as_mut().poll(cx).is_pending(),
            "driver ended during readback"
        );
        Poll::Pending
    })
    .await;
    check(&response, 200, None);
    assert!(
        fx.service.read_budget().in_flight() >= 20,
        "retained buffer capacity is charged"
    );
    drop(response);
    assert_eq!(fx.service.read_budget().in_flight(), 0);
    drop(held);
    assert_eq!(permits.available_permits(), 8);

    let requests = async {
        let budget = fx.service.read_budget();
        let held_bytes = budget.take(crate::adapter::READ_BODY_BUDGET_BYTES).unwrap();
        check(
            &fx.send(request("GET", &path, Full::new(Bytes::new())))
                .await,
            503,
            Some("unavailable"),
        );
        assert_eq!(budget.in_flight(), crate::adapter::READ_BODY_BUDGET_BYTES);
        assert_eq!(permits.available_permits(), 8);
        drop(held_bytes);
        let response = fx
            .send(request("GET", &path, Full::new(Bytes::new())))
            .await;
        check(&response, 200, None);
        assert!(
            budget.in_flight() >= 20,
            "retained buffer capacity is charged"
        );
        drop(response);
        assert_eq!(budget.in_flight(), 0);
        let set_path = fx.config.enrollment_dir.join(crate::enrollment::SET_NAME);
        let saved = std::fs::read(&set_path).unwrap();
        std::fs::write(&set_path, b"corrupt synthetic enrollment").unwrap();
        check(
            &fx.send(request("GET", &path, Full::new(Bytes::new())))
                .await,
            503,
            Some("enrollment-unavailable"),
        );
        assert_eq!(
            fx.service.maintain_intents().await,
            Err(crate::wire::ErrorToken::EnrollmentUnavailable)
        );
        std::fs::write(set_path, saved).unwrap();
        check(
            &fx.send(request("GET", &path, Full::new(Bytes::new())))
                .await,
            200,
            None,
        );
        permits.close();
        check(
            &fx.send(request("GET", &path, Full::new(Bytes::new())))
                .await,
            503,
            Some("unavailable"),
        );
        fx.handle.stop().await
    };
    tokio::pin!(requests);
    let mut stopped = None;
    let mut end = None;
    let (stopped, end) = poll_fn(|cx| {
        if stopped.is_none()
            && let Poll::Ready(result) = requests.as_mut().poll(cx)
        {
            stopped = Some(result);
        }
        if end.is_none()
            && let Poll::Ready(result) = driver.as_mut().poll(cx)
        {
            end = Some(result);
        }
        if stopped.is_some() && end.is_some() {
            Poll::Ready((stopped.take().unwrap(), end.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await;
    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
}

#[tokio::test]
async fn repeated_gets_preserve_the_shared_mutation_and_publish_burst() {
    let (fx, driver) = Fx::new(true, &[], &[]).await;
    let mut tasks = spawn_driver(driver);
    fx.handle.initialise(&a()).await.unwrap();
    fx.service.maintain_intents().await.unwrap();
    let path = format!("/volume/{}/intent", a().as_str());
    // The injected principal clock remains frozen at zero throughout.
    assert_eq!(fx.controls.accounting(PRINCIPAL), None);
    for _ in 0..12 {
        check(
            &fx.send(request("GET", &path, Full::new(Bytes::new())))
                .await,
            200,
            None,
        );
        assert_eq!(
            fx.controls.accounting(PRINCIPAL),
            None,
            "GET does not reduce the POST/publish burst"
        );
    }
    for (method, suffix) in [
        ("POST", "intent"),
        ("POST", "intent/release"),
        ("POST", "intent/ownership"),
        ("POST", "publish"),
        ("POST", "intent/ownership"),
    ] {
        let response = if suffix == "publish" {
            fx.send(publish(1, vec![])).await
        } else {
            fx.send(request(
                method,
                &format!("/volume/{}/{suffix}", a().as_str()),
                Full::new(Bytes::new()),
            ))
            .await
        };
        assert_ne!(
            response.status().as_u16(),
            429,
            "five shared mutation/publish admissions remain"
        );
    }
    let exhausted = fx.controls.accounting(PRINCIPAL).unwrap();
    assert_eq!(exhausted.0, 0);
    for _ in 0..12 {
        check(
            &fx.send(request("GET", &path, Full::new(Bytes::new())))
                .await,
            200,
            None,
        );
        assert_eq!(fx.controls.accounting(PRINCIPAL), Some(exhausted));
    }
    check(
        &fx.send(request("POST", &path, Full::new(Bytes::new())))
            .await,
        429,
        Some("rate-limited"),
    );
    check(
        &fx.send(publish(1, vec![])).await,
        429,
        Some("rate-limited"),
    );
    let stopped = fx.handle.stop().await;
    assert_eq!(tasks.join_next().await.unwrap().unwrap(), stopped);
}

#[tokio::test]
async fn product_maintenance_propagates_unavailable_pair_refusals() {
    let (fx, driver) = Fx::new(true, &[a()], &[]).await;
    let requests = async {
        assert_eq!(
            fx.service.maintain_intents().await,
            Err(crate::wire::ErrorToken::Unavailable)
        );
        assert_eq!(
            fx.service.maintain_intents().await,
            Err(crate::wire::ErrorToken::Unavailable)
        );
        assert!(
            !fx.state_dir
                .join(format!("{}.intent", a().as_str()))
                .exists()
        );
        fx.handle.stop().await
    };
    let mut tasks = spawn_driver(driver);
    let stopped = requests.await;
    let end = tasks.join_next().await.unwrap().unwrap();
    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
}

#[tokio::test]
async fn configured_volume_maintenance_keeps_intent_unavailable_and_publication_no_log() {
    use crate::authority::intent::tests as intents;
    let (fx, driver) = Fx::new(true, &[], &[]).await;
    let mut tasks = spawn_driver(driver);
    for tick in 0..3 {
        assert_eq!(fx.service.maintain_intents().await, Ok(()));
        assert!(!fx.state_dir.join(format!("{}.log", a().as_str())).exists());
        assert!(
            !fx.state_dir
                .join(format!("{}.intent", a().as_str()))
                .exists()
        );
        for (index, (method, suffix, body)) in [
            ("GET", "intent", Vec::new()),
            ("POST", "intent/ownership", intents::acquire(1, 2, 0)),
            (
                "POST",
                "intent",
                granary_core::intent::encode_register(
                    &[1; 16],
                    1,
                    &[2; 16],
                    1,
                    &good_root(&a(), 1, None, 1),
                )
                .unwrap(),
            ),
            (
                "POST",
                "intent/release",
                intents::release(&intents::owned(1), 1, 1),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            fx.refill((tick * 10 + index) as i128 * 100);
            check(
                &fx.send(request(
                    method,
                    &format!("/volume/{}/{suffix}", a().as_str()),
                    Full::new(Bytes::from(body)),
                ))
                .await,
                503,
                Some("unavailable"),
            );
        }
        fx.refill((tick * 10 + 5) as i128 * 100);
        check(
            &fx.send(publish(1, good_root(&a(), 1, None, 1))).await,
            404,
            Some("no-log"),
        );
        check(
            &fx.send(request(
                "GET",
                &format!("/volume/{}/status", a().as_str()),
                Full::new(Bytes::new()),
            ))
            .await,
            404,
            Some("no-log"),
        );
    }
    fx.handle.initialise(&a()).await.unwrap();
    fx.service.maintain_intents().await.unwrap();
    check(
        &fx.send(request(
            "GET",
            &format!("/volume/{}/intent", a().as_str()),
            Full::new(Bytes::new()),
        ))
        .await,
        200,
        None,
    );
    assert_eq!(fx.handle.stop().await, RunEnd::Stopped);
    assert_eq!(tasks.join_next().await.unwrap().unwrap(), RunEnd::Stopped);
}
