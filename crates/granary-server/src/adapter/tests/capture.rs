// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::controls::{A, AuthorityVenue, B, DA, DA2, DB, Fx, empty, request};
use super::*;
use crate::diagnostics::tests::{Observer, entry, rendered, stack};
use crate::diagnostics::{CaptureRevision, CaptureSelector, host_subscriber_with_observer};
use crate::loopback::{RequestIdShape, is_conforming_request_id_shape, request_id_shapes};
use granary_core::root::VolumeName;

fn hint() -> Full<Bytes> {
    Full::new(Bytes::from_static(b"00000000000000000001"))
}

const CEILING: &str = "info,granary_server::scoped_capture=debug";

#[tokio::test]
async fn capture_authenticated_write_has_exact_fields_and_one_rendered_line() {
    let fx = Fx::new("capture-authenticated");
    let (handle, observer, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(
            CaptureRevision(0),
            &[
                entry(1, CaptureSelector::Principal(A)),
                entry(
                    2,
                    CaptureSelector::Volume(VolumeName::from_bytes(b"v").unwrap()),
                ),
            ],
        )
        .unwrap();
    let service = fx.service.clone().with_capture(handle.clone());
    let response = service
        .clone()
        .request_for_test(request(Method::PUT, "/volume/v/hint", Some(DA2), hint()))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let events = observer.events.lock().unwrap();
    let captures: Vec<_> = events
        .iter()
        .filter(|(name, _, _)| name == "request_authenticated")
        .collect();
    assert_eq!(captures.len(), 1, "one real authenticated admission event");
    assert_eq!(captures[0].1, "DEBUG");
    assert_eq!(
        captures[0].2.get("principal"),
        Some(&A.to_string()),
        "capture callsite must record the resolved principal"
    );
    assert_eq!(
        captures[0].2.get("volume").map(String::as_str),
        Some("v"),
        "capture callsite must record the admitted volume"
    );
    assert_eq!(
        captures[0].2.get("operation").map(String::as_str),
        Some("write_hint")
    );
    assert_eq!(
        captures[0].2.len(),
        3,
        "closed event schema carries no request secrets"
    );
    let served: Vec<_> = events
        .iter()
        .filter(|(_, _, fields)| fields.get("message").is_some_and(|v| v == "served"))
        .collect();
    assert_eq!(served.len(), 1);
    assert_eq!(served[0].1, "INFO");
    assert_eq!(served[0].2.get("status").map(String::as_str), Some("204"));
    drop(events);
    let rendered = rendered(&lines);
    let captures: Vec<_> = rendered
        .iter()
        .filter(|line| line.contains("granary_server::scoped_capture"))
        .collect();
    assert_eq!(
        captures.len(),
        1,
        "diagnostic event must have exactly one rendered capture line and no generic fmt line"
    );
    assert_eq!(
        captures[0].as_str(),
        format!(
            "{{\"level\":\"DEBUG\",\"target\":\"granary_server::scoped_capture\",\"event\":\"request_authenticated\",\"principal\":\"{A}\",\"volume\":\"v\",\"operation\":\"write_hint\",\"slot\":1,\"revision\":1}}\n"
        )
    );
    assert!(captures[0].len() <= crate::sink::DEBUG_LINE_BYTES);
    assert_eq!(
        rendered.len(),
        3,
        "capture plus unchanged served and span-close lines"
    );
    assert_eq!(handle.snapshot().counters.queued, 1);
}

#[tokio::test]
async fn capture_ungranted_identity_and_volume_are_silent_with_positive_control() {
    let fx = Fx::new("capture-ungranted");
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(
            CaptureRevision(0),
            &[
                entry(1, CaptureSelector::Principal(A)),
                entry(
                    2,
                    CaptureSelector::Volume(VolumeName::from_bytes(b"a").unwrap()),
                ),
            ],
        )
        .unwrap();
    let service = fx.service.clone().with_capture(handle.clone());
    for (credential, volume, expected) in [(DB, "b", 0), (DA, "a", 1), (DB, "a", 1)] {
        let mut req = request(
            Method::PUT,
            &format!("/volume/{volume}/hint"),
            Some(credential),
            hint(),
        );
        req.headers_mut().insert(
            "principal",
            HeaderValue::from_static("principal:01010101010101010101010101010101"),
        );
        assert_eq!(
            service.clone().request_for_test(req).await.status(),
            StatusCode::NO_CONTENT
        );
        let captures: Vec<_> = rendered(&lines)
            .into_iter()
            .filter(|line| line.contains("request_authenticated"))
            .collect();
        assert_eq!(
            captures.len(),
            expected,
            "only current typed event-field selectors may capture"
        );
        if credential == DB && expected == 1 {
            assert!(
                captures[0].contains(&B.to_string()),
                "request-supplied identity is ignored"
            );
        }
    }
    assert_eq!(handle.snapshot().counters.queued, 2);
}

#[tokio::test]
async fn capture_empty_set_preserves_responses_baseline_and_read_authentication() {
    let fx = Fx::new("capture-empty");
    let (handle, observer, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    let service = fx.service.clone().with_capture(handle.clone());
    let mut baseline_fields = None;
    for with_handle in [false, true] {
        let response = if with_handle {
            service
                .request_for_test(request(Method::PUT, "/volume/v/hint", Some(DA), hint()))
                .await
        } else {
            fx.service
                .request_for_test(request(Method::PUT, "/volume/v/hint", Some(DA), hint()))
                .await
        };
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(body_of(response).is_empty());
        let baseline = rendered(&lines);
        assert_eq!(
            baseline.len(),
            2,
            "empty capture keeps the served and CLOSE outcome"
        );
        assert!(baseline[0].contains("served"));
        assert!(baseline[1].contains("close"));
        let events = observer.events.lock().unwrap();
        let served = events
            .iter()
            .rev()
            .find(|(_, _, fields)| {
                fields
                    .get("message")
                    .is_some_and(|message| message == "served")
            })
            .unwrap();
        assert_eq!(served.1, "INFO");
        if let Some(previous) = &baseline_fields {
            assert_eq!(
                &served.2, previous,
                "empty capture preserves baseline event fields"
            );
        } else {
            baseline_fields = Some(served.2.clone());
        }
    }
    assert_eq!(
        handle.snapshot().counters,
        crate::diagnostics::CaptureCounters::default()
    );
    assert!(
        observer
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|(name, _, _)| name != "request_authenticated")
    );
    handle
        .replace(
            CaptureRevision(0),
            &[entry(1, CaptureSelector::Principal(A))],
        )
        .unwrap();
    // A read with even a verified enrolled identity deliberately resolves no principal.
    assert_eq!(
        service
            .request_for_test(request(Method::GET, "/volume/v/max-seq", Some(DA), empty()))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(rendered(&lines).len(), 2);
    assert_eq!(handle.snapshot().counters.admitted, 0);
    assert_eq!(
        service
            .request_for_test(request(Method::PUT, "/volume/v/hint", Some(DA), hint()))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        rendered(&lines).len(),
        3,
        "matching authenticated write is the positive control"
    );
    assert_eq!(handle.snapshot().counters.queued, 1);
}

#[tokio::test]
async fn capture_blocked_destination_finishes_request_and_counts_debug_loss() {
    let fx = Fx::new("capture-blocked");
    let (sink, release) = crate::sink::tests::blocked_destination();
    let observer = Observer::default();
    let (handle, subscriber) = host_subscriber_with_observer(
        tracing_subscriber::EnvFilter::new(CEILING),
        sink.clone(),
        sink.clone(),
        true,
        observer.clone(),
    );
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(
            CaptureRevision(0),
            &[entry(1, CaptureSelector::Principal(A))],
        )
        .unwrap();
    assert!(sink.try_enqueue_debug(b"positive\n"));
    for _ in 1..1024 {
        assert!(sink.try_enqueue_debug(b"filler\n"));
    }
    let service = fx.service.clone().with_capture(handle.clone());
    let response = service
        .request_for_test(request(Method::PUT, "/volume/v/hint", Some(DA), hint()))
        .await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "request completes while the destination remains blocked"
    );
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.counters.admitted, 1);
    assert_eq!(snapshot.counters.queued, 0);
    assert_eq!(
        snapshot.counters.sink_drops, 1,
        "DEBUG sink loss is counted in the seam"
    );
    assert_eq!(
        snapshot.entries[0].remaining_lines, 1023,
        "sink loss receives no budget refund"
    );
    assert_eq!(snapshot.entries[0].remaining_bytes, 1024 * 1024 - 1024);
    assert!(
        observer
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|(name, _, fields)| name == "request_authenticated"
                && fields.get("principal") == Some(&A.to_string()))
    );
    handle.replace(CaptureRevision(1), &[]).unwrap();
    release.send(()).unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end matrix verifies valid and malformed request id logging across all five endpoint branches"
)]
async fn request_id_logged_on_every_request_and_malformed_values_never_appear() {
    use crate::authority::intent::tests as fixture;

    const MALFORMED_ID: &[u8] = br#"sample-"quoted"\path"#;
    const ESCAPED_ID: &str = r#"sample-\"quoted\"\\path"#;

    let venue = AuthorityVenue::new("capture-request-id").await;
    let (_, _, lines, subscriber) = stack("info");
    let _default = tracing::subscriber::set_default(subscriber);

    let shapes = request_id_shapes();
    let escaped_shape = RequestIdShape::Single(MALFORMED_ID);
    let vol = fixture::volume();
    let vol_str = vol.as_str();

    let mut valid_cases = 0usize;
    let mut malformed_cases = 0usize;

    for req_idx in 0..5 {
        let build_base_request = || -> Request<Full<Bytes>> {
            match req_idx {
                0 => request(
                    Method::GET,
                    &format!("/volume/{vol_str}/max-seq"),
                    Some(DA),
                    empty(),
                ),
                1 => request(
                    Method::PUT,
                    &format!("/volume/{vol_str}/hint"),
                    Some(DA2),
                    hint(),
                ),
                2 => {
                    let candidate = fixture::root(1, &vol);
                    let mut req = request(
                        Method::POST,
                        &format!("/volume/{vol_str}/publish"),
                        Some(DA),
                        Full::new(Bytes::from(candidate)),
                    );
                    req.headers_mut().insert(
                        "granary-epoch",
                        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
                    );
                    req
                }
                3 => {
                    let candidate = fixture::acquire(1, 2, 0);
                    request(
                        Method::POST,
                        &format!("/volume/{vol_str}/intent/ownership"),
                        Some(DA),
                        Full::new(Bytes::from(candidate)),
                    )
                }
                4 => request(
                    Method::GET,
                    &format!("/volume/{vol_str}/intent?bad"),
                    Some(DA),
                    empty(),
                ),
                _ => unreachable!(),
            }
        };

        for shape in shapes.iter().chain([&escaped_shape]) {
            let mut req = build_base_request();
            shape.apply_headers(req.headers_mut());
            if is_conforming_request_id_shape(shape) {
                let expected_id = shape.conforming_value().unwrap();
                let _ = rendered(&lines);
                let _response = venue.fx.service.clone().request_for_test(req).await;
                let output = rendered(&lines);
                let wire_id_needle = format!("\"wire_request_id\":\"{expected_id}\"");
                let found = output
                    .iter()
                    .any(|line| line.contains("grain_request") && line.contains(&wire_id_needle));
                assert!(
                    found,
                    "conforming wire_request_id {expected_id} missing on grain_request for request index {req_idx}; rendered lines: {output:?}"
                );
                valid_cases += 1;
            } else {
                let _ = rendered(&lines);
                let _response = venue.fx.service.clone().request_for_test(req).await;
                let output = rendered(&lines);
                let joined = output.join("");
                assert!(
                    joined.contains("grain_request"),
                    "missing rendered request log for request index {req_idx}: {joined}"
                );
                if shape == &escaped_shape {
                    assert!(
                        !joined.contains(ESCAPED_ID),
                        "JSON-escaped malformed identifier must not appear in rendered output for request index {req_idx}: {joined}"
                    );
                }
                assert!(
                    !joined.contains("wire_request_id"),
                    "malformed request id must not be recorded as wire_request_id for request index {req_idx}; rendered lines: {joined}"
                );
                for (_, bytes) in shape.as_wire_fields() {
                    if bytes.len() > 1 {
                        let raw_str = String::from_utf8_lossy(bytes);
                        assert!(
                            !joined.contains(raw_str.as_ref()),
                            "malformed raw identifier must not appear in rendered output for request index {req_idx}: {joined}"
                        );
                    }
                    if bytes.len() > 64 {
                        let prefix_str = String::from_utf8_lossy(&bytes[..64]);
                        assert!(
                            !joined.contains(prefix_str.as_ref()),
                            "truncated identifier must not appear in rendered output for request index {req_idx}: {joined}"
                        );
                    }
                }
                malformed_cases += 1;
            }
        }
    }

    assert_eq!((valid_cases, malformed_cases), (15, 45));
    venue.stop().await;
}
