// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_client::{
    AuthorityError, OwnedCandidate, PublishRequest, PublishResponse, StatusResponse,
};
use granary_core::authlog::Epoch;
use granary_core::authority_answer::{
    self as codec, Bound, Head, Position, PublishAnswer, Receipt, VolumeStatus,
};

fn submission() -> PublishRequest {
    let key = SigningKey::from_seed(&[7; 32]).unwrap_or_else(|e| panic!("{e}"));
    let candidate =
        OwnedCandidate::new(VOLUME, signed_root(&key).into()).unwrap_or_else(|e| panic!("{e}"));
    PublishRequest::new(
        VOLUME,
        Epoch::from_bytes([1; 16]),
        b"operation",
        candidate.clone(),
        vec![candidate],
    )
    .unwrap_or_else(|e| panic!("{e}"))
}
fn binary(status: u16, token: Option<&str>, media: &str, bytes: Vec<u8>) -> Response<StubBody> {
    let mut r = Response::builder()
        .status(status)
        .header("content-type", media);
    if let Some(t) = token {
        r = r.header("granary-error", t);
    }
    r.body(StubBody::of(bytes))
        .unwrap_or_else(|e| panic!("{e}"))
}
const ANSWER: &str = "application/vnd.granary.authority-answer.v1";
fn historical_submission() -> (PublishRequest, OwnedCandidate) {
    let key = signing_key(7);
    let make = |seq| {
        let mut doc = root::decode_root(&signed_root(&key)).unwrap_or_else(|e| panic!("{e}"));
        doc.seq = seq;
        doc.parent = Some(GrainId::of(b"parent"));
        let unsigned = root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
        doc.sigs = vec![RootSig {
            key_id: key.key_id(),
            sig: key.sign(root::signed_prefix(&unsigned).unwrap_or_else(|e| panic!("{e}"))),
        }];
        OwnedCandidate::new(
            VOLUME,
            root::encode_root(&doc)
                .unwrap_or_else(|e| panic!("{e}"))
                .into(),
        )
        .unwrap_or_else(|e| panic!("{e}"))
    };
    let current = make(5);
    let older = make(3);
    let request = PublishRequest::new(
        VOLUME,
        Epoch::from_bytes([1; 16]),
        b"operation",
        current.clone(),
        vec![older.clone(), current],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    (request, older)
}

#[tokio::test]
async fn every_answer_kind_and_owned_history_are_checked_on_the_wire() {
    let (request, older) = historical_submission();
    let position = Position {
        epoch: request.epoch(),
        entry_seq: 73,
    };
    let own = request.candidate().id();
    let receipt = Receipt {
        position,
        root_seq: 5,
        stored_id: own,
    };
    for (answer, status, token) in [
        (
            PublishAnswer::Landed {
                receipt,
                head: None,
            },
            200,
            None,
        ),
        (
            PublishAnswer::Lost {
                position,
                candidate_id: own,
                occupant: GrainId::of(b"occupant"),
                head: None,
            },
            200,
            None,
        ),
        (
            PublishAnswer::Accepted {
                position,
                candidate_id: own,
            },
            202,
            None,
        ),
        (
            PublishAnswer::Open {
                position,
                candidate_id: own,
            },
            202,
            None,
        ),
        (
            PublishAnswer::StaleBase(Head::new(None)),
            409,
            Some("stale-base"),
        ),
        (
            PublishAnswer::OperationBound(Bound::Open {
                position,
                candidate_id: older.id(),
            }),
            409,
            Some("operation-bound"),
        ),
        (
            PublishAnswer::OperationBound(Bound::Landed(Receipt {
                position,
                root_seq: older.seq(),
                stored_id: older.id(),
            })),
            409,
            Some("operation-bound"),
        ),
        (
            PublishAnswer::NotDecided {
                position,
                candidate_id: GrainId::of(b"other operation"),
            },
            409,
            Some("not-decided"),
        ),
        (
            PublishAnswer::EpochMismatch {
                epoch: Epoch::from_bytes([2; 16]),
                head: None,
            },
            409,
            Some("epoch-mismatch"),
        ),
        (PublishAnswer::VolumeDamaged, 409, Some("volume-damaged")),
    ] {
        let bytes = codec::encode(answer).unwrap();
        let peer = stub(answering(move |_| {
            binary(status, token, ANSWER, bytes.clone())
        }))
        .await;
        let checked = peer.store().publish_once(&request).await.unwrap();
        assert_eq!(checked.identification(), (status, token));
        assert_eq!(peer.seen().len(), 1);
    }
}

#[tokio::test]
async fn foreign_bindings_and_wrong_owned_sequences_are_refused_on_the_wire() {
    let (request, older) = historical_submission();
    let position = Position {
        epoch: request.epoch(),
        entry_seq: 73,
    };
    for bound in [
        Bound::Open {
            position,
            candidate_id: GrainId::of(b"unowned"),
        },
        Bound::Landed(Receipt {
            position,
            root_seq: 4,
            stored_id: older.id(),
        }),
        Bound::Open {
            position: Position {
                epoch: Epoch::from_bytes([2; 16]),
                ..position
            },
            candidate_id: older.id(),
        },
    ] {
        let bytes = codec::encode(PublishAnswer::OperationBound(bound)).unwrap();
        let peer = stub(answering(move |_| {
            binary(409, Some("operation-bound"), ANSWER, bytes.clone())
        }))
        .await;
        assert!(matches!(
            peer.store().publish_once(&request).await,
            Err(AuthorityError::Backend(_))
        ));
    }
}

#[tokio::test]
async fn status_uses_its_read_only_route_and_identification() {
    const MEDIA: &str = "application/vnd.granary.volume-status.v1";
    let observation = VolumeStatus {
        epoch: Epoch::from_bytes([1; 16]),
        head: None,
        open: None,
    };
    let bytes = codec::encode_status(observation).unwrap();
    let peer = stub(answering(move |_| binary(200, None, MEDIA, bytes.clone()))).await;
    let StatusResponse::Observed(checked) = peer.store().status_once(VOLUME).await.unwrap() else {
        panic!("missing observation")
    };
    assert_eq!(checked.observation(), observation);
    let seen = peer.seen();
    let sent = seen.first().unwrap();
    assert_eq!(sent.method, Method::GET);
    assert_eq!(sent.path, format!("/volume/{VOLUME}/status"));
    assert!(sent.body.is_empty());
    for (status, token, media, body) in [
        (
            200,
            Some("internal"),
            MEDIA,
            codec::encode_status(observation).unwrap(),
        ),
        (
            200,
            None,
            "text/plain",
            codec::encode_status(observation).unwrap(),
        ),
        (200, None, MEDIA, vec![0; 121]),
        (403, Some("no-principal"), MEDIA, vec![]),
        (429, Some("rate-limited"), MEDIA, vec![]),
        (503, Some("enrollment-unavailable"), MEDIA, vec![]),
    ] {
        let peer = stub(answering(move |_| {
            binary(status, token, media, body.clone())
        }))
        .await;
        assert!(matches!(
            peer.store().status_once(VOLUME).await,
            Err(AuthorityError::Backend(_))
        ));
        assert_eq!(peer.seen().len(), 1);
    }
}

#[tokio::test]
async fn publish_sends_exact_tuple_and_rejects_hostile_answers() {
    let request = submission();
    let position = Position {
        epoch: request.epoch(),
        entry_seq: 83,
    };
    let own = request.candidate().id();
    let foreign = GrainId::of(b"foreign");
    let good = codec::encode(PublishAnswer::Accepted {
        position,
        candidate_id: own,
    })
    .unwrap();
    let peer = stub(answering({
        let good = good.clone();
        move |_| binary(202, None, ANSWER, good.clone())
    }))
    .await;
    assert!(matches!(
        peer.store().publish_once(&request).await,
        Ok(PublishResponse::Accepted(_))
    ));
    let seen = peer.seen();
    let sent = seen.first().unwrap();
    assert_eq!(sent.method, Method::POST);
    assert_eq!(sent.path, format!("/volume/{VOLUME}/publish"));
    assert_eq!(sent.headers["granary-operation"], "6f7065726174696f6e");
    assert_eq!(sent.headers["granary-epoch"], "01".repeat(16));
    assert_eq!(
        sent.headers["content-type"],
        "application/vnd.granary.root.v1"
    );
    assert_eq!(sent.body.as_slice(), request.candidate().bytes().as_ref());
    let mut trailing = good.clone();
    trailing.push(0);
    let wrong_epoch = codec::encode(PublishAnswer::Accepted {
        position: Position {
            epoch: Epoch::from_bytes([2; 16]),
            ..position
        },
        candidate_id: own,
    })
    .unwrap();
    let wrong_id = codec::encode(PublishAnswer::Accepted {
        position,
        candidate_id: foreign,
    })
    .unwrap();
    let wrong_seq = codec::encode(PublishAnswer::Landed {
        receipt: Receipt {
            position,
            root_seq: 2,
            stored_id: own,
        },
        head: None,
    })
    .unwrap();
    let mismatch = codec::encode(PublishAnswer::EpochMismatch {
        epoch: request.epoch(),
        head: None,
    })
    .unwrap();
    let not_decided = codec::encode(PublishAnswer::NotDecided {
        position,
        candidate_id: foreign,
    })
    .unwrap();
    for (status, token, media, bytes) in [
        (200, None, ANSWER, vec![]),
        (202, Some("internal"), ANSWER, good.clone()),
        (202, None, "text/plain", good.clone()),
        (202, None, ANSWER, good[..10].to_vec()),
        (202, None, ANSWER, trailing),
        (202, None, ANSWER, vec![0; 154]),
        (202, None, ANSWER, wrong_epoch),
        (202, None, ANSWER, wrong_id),
        (200, None, ANSWER, wrong_seq),
        (409, Some("epoch-mismatch"), ANSWER, mismatch),
        (409, Some("stale-base"), ANSWER, not_decided.clone()),
        (409, None, ANSWER, not_decided.clone()),
        (409, Some("unknown"), ANSWER, not_decided),
        (304, Some("unavailable"), ANSWER, vec![]),
        (302, Some("unavailable"), ANSWER, vec![]),
    ] {
        let peer = stub(answering(move |_| {
            binary(status, token, media, bytes.clone())
        }))
        .await;
        assert!(
            matches!(
                peer.store().publish_once(&request).await,
                Err(AuthorityError::Backend(_))
            ),
            "{status} {token:?}"
        );
        assert_eq!(peer.seen().len(), 1);
    }
}
#[tokio::test]
async fn wrong_volume_constructs_no_wire_request() {
    let peer = stub(answering(|_| {
        refusal(StatusCode::SERVICE_UNAVAILABLE, Some("unavailable"))
    }))
    .await;
    let request = submission();
    assert!(OwnedCandidate::new("other", Arc::clone(request.candidate().bytes())).is_err());
    assert!(peer.store().status_once("../vol").await.is_err());
    assert!(peer.seen().is_empty());
}
#[tokio::test]
async fn authority_calls_never_retry_refused_streams_or_connection_resets() {
    for reason in [h2::Reason::REFUSED_STREAM, h2::Reason::INTERNAL_ERROR] {
        for call in 0..3 {
            let (peer, attempts) = h2_stub_reset_first_n_streams(usize::MAX, reason).await;
            let store = peer.store();
            match call {
                0 => assert!(guarded(store.publish_once(&submission())).await.is_err()),
                1 => assert!(guarded(store.status_once(VOLUME)).await.is_err()),
                _ => assert!(guarded(store.probe_root_once(VOLUME, 1)).await.is_err()),
            }
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
    }
    for call in 0..3 {
        let (peer, dials) = h2_stub_drop_first_n_connections(usize::MAX).await;
        let store = peer.store();
        match call {
            0 => assert!(guarded(store.publish_once(&submission())).await.is_err()),
            1 => assert!(guarded(store.status_once(VOLUME)).await.is_err()),
            _ => assert!(guarded(store.probe_root_once(VOLUME, 1)).await.is_err()),
        }
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn root_probe_is_exact_capped_and_identified() {
    let bytes = vec![17; usize::try_from(ROOT_MAX_BYTES).unwrap()];
    for (status, token, body, ok) in [
        (200, None, bytes.clone(), true),
        (404, Some("not-found"), vec![], true),
        (404, None, vec![], false),
        (404, Some("unknown-target"), vec![], false),
        (
            200,
            None,
            vec![0; usize::try_from(ROOT_MAX_BYTES).unwrap() + 1],
            false,
        ),
    ] {
        let peer = stub(answering(move |_| {
            binary(
                status,
                token,
                "application/vnd.granary.root.v1",
                body.clone(),
            )
        }))
        .await;
        let got = peer.store().probe_root_once(VOLUME, 1).await;
        assert_eq!(got.is_ok(), ok);
        if status == 200 && ok {
            assert_eq!(got.unwrap(), Some(bytes.clone()));
        } else if status == 404 && ok {
            assert_eq!(got.unwrap(), None);
        }
    }
}
#[tokio::test(start_paused = true)]
async fn authority_header_deadline_and_cancellation_keep_one_attempt() {
    let (peer, seen) = h2_stub_parking().await;
    let store = Arc::new(peer.store());
    let mut task = spawn({
        let store = store.clone();
        async move { store.publish_once(&submission()).await }
    });
    drive_to_completion(&mut task, Duration::from_secs(50)).await;
    assert!(matches!(task.await.unwrap(), Err(AuthorityError::Elapsed)));
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    let task = spawn({
        let store = store.clone();
        async move { store.status_once(VOLUME).await }
    });
    for _ in 0..1000 {
        if seen.load(Ordering::SeqCst) == 2 {
            break;
        }
        settle_real(1).await;
    }
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(seen.load(Ordering::SeqCst), 2);
}
#[test]
fn candidate_identity_is_derived_without_an_encoder() {
    // Canonical roots re-encode identically. This source constraint detects an
    // otherwise observationally equivalent re-encode-before-hash mutation.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/authority_transport/types.rs");
    let source = std::fs::read_to_string(path).unwrap();
    assert!(!source.contains("root::encode_root"));
    let candidate = submission().candidate().clone();
    assert_eq!(candidate.id(), GrainId::of(candidate.bytes()));
}

#[tokio::test]
async fn idle_pool_reuses_at_239_seconds_and_expires_after_240() {
    let peer = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("not-found"))
    }))
    .await;
    let store = peer.store();
    assert_eq!(
        guarded(store.probe_root_once(VOLUME, 1)).await.unwrap(),
        None
    );
    assert_eq!(peer.connections.load(Ordering::SeqCst), 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(239)).await;
    tokio::time::resume();
    assert_eq!(
        guarded(store.probe_root_once(VOLUME, 1)).await.unwrap(),
        None
    );
    assert_eq!(peer.connections.load(Ordering::SeqCst), 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(241)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::resume();
    assert_eq!(
        guarded(store.probe_root_once(VOLUME, 1)).await.unwrap(),
        None
    );
    assert_eq!(peer.connections.load(Ordering::SeqCst), 2);
}

#[test]
fn pool_and_socket_policy_is_explicit() {
    // The connector does not expose its socket options. This checks the
    // explicit configuration; socket behaviour needs the Linux venue.
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/http_store.rs"))
            .unwrap();
    for setting in [
        "http.set_connect_timeout(Some(CONNECT_TIMEOUT));",
        "http.set_nodelay(true);",
        "http.set_keepalive(Some(Duration::from_mins(1)));",
        ".pool_timer(TokioTimer::new())",
        ".pool_idle_timeout(Duration::from_mins(4))",
        ".pool_max_idle_per_host(1)",
        ".retry_canceled_requests(false)",
        ".http2_initial_stream_window_size(H2_STREAM_WINDOW)",
        ".http2_initial_connection_window_size(H2_CONN_WINDOW)",
        ".http2_adaptive_window(false)",
    ] {
        assert!(
            source.lines().map(str::trim).any(|line| line == setting),
            "missing explicit setting {setting}"
        );
    }
}

#[tokio::test]
async fn duplicate_identification_and_unread_error_text() {
    let request = submission();
    let damaged = codec::encode(PublishAnswer::VolumeDamaged).unwrap();
    let peer = stub(answering(move |_| {
        let mut r = binary(409, Some("volume-damaged"), ANSWER, damaged.clone());
        r.headers_mut().append(
            "granary-error",
            hyper::header::HeaderValue::from_static("volume-damaged"),
        );
        r
    }))
    .await;
    assert!(matches!(
        peer.store().publish_once(&request).await,
        Err(AuthorityError::Backend(_))
    ));
    let produced = Arc::new(AtomicUsize::new(0));
    let peer = stub(answering({
        let produced = produced.clone();
        move |_| {
            Response::builder()
                .status(503)
                .header("granary-error", "enrollment-unavailable")
                .body(StubBody::repeated(
                    Bytes::from(vec![b'x'; 65536]),
                    1_000_000,
                    &produced,
                ))
                .unwrap_or_else(|e| panic!("{e}"))
        }
    }))
    .await;
    let store = peer.store();
    let got = store.publish_once(&request).await.unwrap();
    assert!(got.request_wrote_nothing());
    assert_eq!(
        store.wire_bytes().total(),
        Some(0),
        "error text is never read into the framing counter"
    );
    assert!(
        produced.load(Ordering::SeqCst) < 4 * 1024 * 1024,
        "error body was drained"
    );
}
#[tokio::test(start_paused = true)]
async fn authority_body_stall_uses_the_same_whole_call_deadline() {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener.local_addr().unwrap();
    let request = submission();
    let bytes = codec::encode(PublishAnswer::Accepted {
        position: Position {
            epoch: request.epoch(),
            entry_seq: 71,
        },
        candidate_id: request.candidate().id(),
    })
    .unwrap();
    let partial = Bytes::from(bytes[..bytes.len() - 1].to_vec());
    let size = partial.len() as u64;
    let seen = Arc::new(AtomicUsize::new(0));
    let server_seen = seen.clone();
    let accepting = spawn_accepting(move |accept_error| async move {
        let socket = accept(&listener, &accept_error).await;
        let tls = acceptor
            .accept(socket)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut connection = h2::server::handshake(tls)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            server_seen.fetch_add(1, Ordering::SeqCst);
            let response = Response::builder()
                .status(202)
                .header("content-type", ANSWER)
                .body(())
                .unwrap_or_else(|e| panic!("{e}"));
            let mut stream = respond
                .send_response(response, false)
                .unwrap_or_else(|e| panic!("{e}"));
            stream
                .send_data(partial.clone(), false)
                .unwrap_or_else(|e| panic!("{e}"));
            let _held = spawn(async move {
                let _held = (request, stream);
                std::future::pending::<()>().await;
            });
        }
    });
    let peer = H2Stub {
        addr,
        pin,
        _accepting: accepting,
    };
    let store = Arc::new(peer.store());
    let mut call = spawn({
        let store = store.clone();
        async move { store.publish_once(&request).await }
    });
    // Let the real TLS/h2 socket deliver the partial body before spending
    // the virtual deadline, so this exercises a body stall on slow hosts too.
    #[expect(
        clippy::disallowed_methods,
        reason = "test harness wall-clock bound for real socket delivery, independent of the paused call deadline"
    )]
    let started = std::time::Instant::now();
    let real_wait_max = Duration::from_secs(20);
    while seen.load(Ordering::SeqCst) != 1 || store.wire_bytes().total() != Some(size) {
        assert!(
            started.elapsed() < real_wait_max,
            "partial authority body was not received within {real_wait_max:?} of real time: \
             saw {} requests and {:?} wire bytes, expected 1 request and {size} wire bytes",
            seen.load(Ordering::SeqCst),
            store.wire_bytes().total(),
        );
        settle_real(1).await;
    }
    drive_to_completion(&mut call, Duration::from_secs(50)).await;
    assert!(matches!(call.await.unwrap(), Err(AuthorityError::Elapsed)));
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert_eq!(store.wire_bytes().total(), Some(size));
}

struct Seeded([u8; 8]);
impl granary_core::secure_random::SecureRandom for Seeded {
    fn fill(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        for (slot, byte) in dest.iter_mut().zip(self.0.iter().cycle()) {
            *slot = *byte;
        }
        Ok(())
    }
}

#[tokio::test]
async fn every_http_store_seam_sends_one_request_id_from_the_operation_span() {
    use granary_core::intent::{self, Ownership, OwnershipMode, ReceiptState, Release};
    use granary_core::retained_submission::Scope;
    use tracing::Instrument as _;

    let peer = stub(answering(|_| {
        refusal(StatusCode::SERVICE_UNAVAILABLE, Some("stopped"))
    }))
    .await;
    let store = peer.store();
    let scope = Scope {
        authority_base: peer.base().into_bytes(),
        pins: vec![peer.pin],
        credential_context: b"test".to_vec(),
    };
    let vol = volume();
    let grain = GrainId::of(b"seam-grain");
    let req = submission();
    let acquire = intent::encode_ownership(Ownership {
        writer: [1; 16],
        instance: [2; 16],
        mode: OwnershipMode::Acquire { observed_cursor: 0 },
    })
    .unwrap();
    let takeover = intent::encode_ownership(Ownership {
        writer: [1; 16],
        instance: [2; 16],
        mode: OwnershipMode::Takeover {
            expected_epoch: 1,
            generation: 0,
            state: ReceiptState::Released,
            recovery_ack: false,
        },
    })
    .unwrap();
    let register =
        intent::encode_register(&[1; 16], 1, &[2; 16], 1, req.candidate().bytes()).unwrap();
    let release = intent::encode_release(Release {
        writer: [1; 16],
        epoch: 1,
        instance: [2; 16],
        generation: 1,
    })
    .unwrap();

    let log = DiagnosticLog::default();
    let _guard = tracing::subscriber::set_default(granary_client::closed_subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log,
    ));
    let id = granary_client::CorrelationId::draw(&mut Seeded([0x42; 8])).unwrap();
    let expected = id.to_string();
    let span = granary_client::operation_span(granary_client::OperationKind::Session, &id);
    async {
        let _ = store.get_root(VOLUME, 1).await;
        let _ = store.put_root(VOLUME, 1, vec![1]).await;
        let _ = store.get_meta(VOLUME, &grain).await;
        let _ = store.put_meta(VOLUME, &grain, vec![1]).await;
        let _ = store.get_bin_range(&DIGEST, 0, 8).await;
        let _ = store.put_bin(&DIGEST, vec![1]).await;
        let _ = store.read_hint(VOLUME, None).await;
        let _ = store.write_hint(VOLUME, 1).await;
        let _ = store.max_seq(VOLUME).await;
        let _ = store.publish_once(&req).await;
        let _ = store.status_once(VOLUME).await;
        let _ = store.probe_root_once(VOLUME, 1).await;
        let _ = store.intent_readback_once(&scope, &vol, |_, _| true).await;
        let _ = store.intent_acquire_once(&scope, &vol, &acquire).await;
        let _ = store.intent_takeover_once(&scope, &vol, &takeover).await;
        let _ = store
            .intent_register_once(&scope, &vol, &register, |_, _| true)
            .await;
        let _ = store.intent_release_once(&scope, &vol, &release).await;
    }
    .instrument(span)
    .await;

    let seen = peer.seen();
    assert_eq!(seen.len(), 17);
    for (idx, recorded) in seen.iter().enumerate() {
        let values: Vec<_> = recorded
            .headers
            .get_all("granary-request-id")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            values,
            vec![expected.clone()],
            "seam {idx} ({} {}): {values:?}",
            recorded.method,
            recorded.path
        );
    }
}

#[tokio::test]
async fn publish_request_id_stays_distinct_from_operation_and_changes_across_spans() {
    use tracing::Instrument as _;

    let request = submission();
    let answer = codec::encode(PublishAnswer::Accepted {
        position: Position {
            epoch: request.epoch(),
            entry_seq: 1,
        },
        candidate_id: request.candidate().id(),
    })
    .unwrap();
    let peer = stub(answering(move |_| {
        binary(202, None, ANSWER, answer.clone())
    }))
    .await;
    let store = peer.store();
    let log = DiagnosticLog::default();
    let _guard = tracing::subscriber::set_default(granary_client::closed_subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log,
    ));

    let first_id = granary_client::CorrelationId::draw(&mut Seeded([0x11; 8])).unwrap();
    let second_id = granary_client::CorrelationId::draw(&mut Seeded([0x22; 8])).unwrap();
    let first_span =
        granary_client::operation_span(granary_client::OperationKind::Session, &first_id);
    let second_span =
        granary_client::operation_span(granary_client::OperationKind::Session, &second_id);
    store
        .publish_once(&request)
        .instrument(first_span)
        .await
        .unwrap();
    store
        .publish_once(&request)
        .instrument(second_span)
        .await
        .unwrap();

    let seen = peer.seen();
    assert_eq!(seen.len(), 2);
    let op_first = seen[0]
        .headers
        .get("granary-operation")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let op_second = seen[1]
        .headers
        .get("granary-operation")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let req_first = seen[0]
        .headers
        .get("granary-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let req_second = seen[1]
        .headers
        .get("granary-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        (
            op_first,
            op_second,
            req_first,
            req_second,
            req_first.starts_with("cor-"),
            req_second.starts_with("cor-"),
            req_first != op_first && !req_first.contains(op_first) && !op_first.contains(req_first),
            req_first != req_second,
        ),
        (
            "6f7065726174696f6e",
            "6f7065726174696f6e",
            first_id.to_string().as_str(),
            second_id.to_string().as_str(),
            true,
            true,
            true,
            true,
        ),
    );
}

#[tokio::test]
async fn echoed_request_id_on_unidentified_status_never_acts_as_identification() {
    use tracing::Instrument as _;

    let log = DiagnosticLog::default();
    let _guard = tracing::subscriber::set_default(granary_client::closed_subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log,
    ));
    let id = granary_client::CorrelationId::draw(&mut Seeded([0x33; 8])).unwrap();
    let expected = id.to_string();
    let request = submission();
    let stale = codec::encode(PublishAnswer::StaleBase(Head::new(None))).unwrap();

    let mut root_outcomes = Vec::new();
    let mut publish_outcomes = Vec::new();
    for echo in [None, Some(expected.clone())] {
        let echo_root = echo.clone();
        let root_peer = stub(answering(move |_| {
            let mut r = Response::builder().status(StatusCode::NOT_FOUND);
            if let Some(id) = &echo_root {
                r = r.header("granary-request-id", id.as_str());
            }
            r.body(StubBody::empty()).unwrap()
        }))
        .await;
        let span = granary_client::operation_span(granary_client::OperationKind::Session, &id);
        let root_res = root_peer.store().get_root(VOLUME, 1).instrument(span).await;
        let root_seen = root_peer.seen();
        assert_eq!(
            root_seen[0]
                .headers
                .get("granary-request-id")
                .and_then(|v| v.to_str().ok()),
            Some(expected.as_str())
        );
        root_outcomes.push(root_res);

        let echo_pub = echo.clone();
        let body = stale.clone();
        let pub_peer = stub(answering(move |_| {
            let mut r = Response::builder()
                .status(StatusCode::CONFLICT)
                .header("content-type", ANSWER);
            if let Some(id) = &echo_pub {
                r = r.header("granary-request-id", id.as_str());
            }
            r.body(StubBody::of(body.clone())).unwrap()
        }))
        .await;
        let span = granary_client::operation_span(granary_client::OperationKind::Session, &id);
        let pub_res = pub_peer
            .store()
            .publish_once(&request)
            .instrument(span)
            .await;
        let pub_seen = pub_peer.seen();
        assert_eq!(
            pub_seen[0]
                .headers
                .get("granary-request-id")
                .and_then(|v| v.to_str().ok()),
            Some(expected.as_str())
        );
        publish_outcomes.push(pub_res);
    }

    assert_eq!(
        (
            matches!(
                &root_outcomes[0],
                Err(RootStoreError::UnexpectedStatus {
                    status: 404,
                    token: None,
                    ..
                })
            ),
            root_outcomes[0] == root_outcomes[1],
            matches!(&publish_outcomes[0], Err(AuthorityError::Backend(_))),
            format!("{:?}", publish_outcomes[0]) == format!("{:?}", publish_outcomes[1]),
        ),
        (true, true, true, true),
        "root={root_outcomes:?}, publish={publish_outcomes:?}"
    );
}
