// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::authlog::{Epoch, OPERATION_MAX};
use granary_core::authority_answer::{Head, Receipt, VolumeStatus};
use granary_core::hash::GrainId;
use granary_core::netid::{NetworkId, NetworkIdentity};
use granary_core::root::{self, RootDoc, RootSig, Timestamp, VolumeName};
use http_body_util::Full;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

struct Network;
impl NetworkIdentity for Network {
    fn current(&self) -> NetworkId {
        NetworkId::from_bytes([1; 32])
    }
}
fn store() -> HttpStore {
    HttpStore::new("https://localhost", vec![[1; 32]], &Network).unwrap()
}
fn candidate(volume: &str, seq: u64) -> OwnedCandidate {
    let doc = RootDoc {
        volume: VolumeName::new(volume.into()).unwrap(),
        seq,
        parent: (seq != 1).then(|| GrainId::of(b"parent")),
        writer_uuid: [1; 16],
        epoch: 1,
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "opaque spec".into(),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![RootSig {
            key_id: [1; 32],
            sig: [2; 64],
        }],
    };
    OwnedCandidate::new(volume, root::encode_root(&doc).unwrap().into()).unwrap()
}
fn request() -> PublishRequest {
    let current = candidate("vol", 5);
    PublishRequest::new(
        "vol",
        Epoch::from_bytes([1; 16]),
        b"operation",
        current.clone(),
        vec![candidate("vol", 3), current],
    )
    .unwrap()
}
fn position() -> Position {
    Position {
        epoch: Epoch::from_bytes([1; 16]),
        entry_seq: 73,
    }
}
fn accepted(r: &PublishRequest) -> PublishAnswer {
    PublishAnswer::Accepted {
        position: position(),
        candidate_id: r.candidate.id,
    }
}
fn response(
    status: u16,
    token: Option<&str>,
    media_type: Option<&str>,
    bytes: Vec<u8>,
) -> Response<Full<Bytes>> {
    let mut r = Response::builder().status(status);
    if let Some(t) = token {
        r = r.header("granary-error", t);
    }
    if let Some(m) = media_type {
        r = r.header(CONTENT_TYPE, m);
    }
    r.body(Full::new(Bytes::from(bytes))).unwrap()
}
fn answer_response(answer: PublishAnswer) -> Response<Full<Bytes>> {
    let (status, token) = answer_tuple(answer);
    response(
        status,
        token,
        Some(ANSWER_MEDIA),
        codec::encode(answer).unwrap(),
    )
}
fn refused(result: Result<PublishResponse, AuthorityError>, reason: &str) {
    let Err(AuthorityError::Backend(e)) = result else {
        panic!("expected backend: {result:?}")
    };
    assert!(e.reason().contains(reason), "{e:?}, expected {reason}");
}

#[tokio::test]
async fn all_answer_kinds_have_positive_controls() {
    let r = request();
    let s = store();
    let receipt = Receipt {
        position: position(),
        root_seq: 5,
        stored_id: r.candidate.id,
    };
    let older = r.owned.first().unwrap();
    let cases = [
        PublishAnswer::Landed {
            receipt,
            head: Some(Head::new(None)),
        },
        PublishAnswer::Lost {
            position: position(),
            candidate_id: r.candidate.id,
            occupant: GrainId::of(b"occupant"),
            head: None,
        },
        accepted(&r),
        PublishAnswer::Open {
            position: position(),
            candidate_id: r.candidate.id,
        },
        PublishAnswer::StaleBase(Head::new(Some((90, GrainId::of(b"head"))))),
        PublishAnswer::OperationBound(Bound::Open {
            position: position(),
            candidate_id: older.id,
        }),
        PublishAnswer::OperationBound(Bound::Landed(Receipt {
            position: position(),
            root_seq: older.seq,
            stored_id: older.id,
        })),
        PublishAnswer::NotDecided {
            position: position(),
            candidate_id: GrainId::of(b"other operation"),
        },
        PublishAnswer::EpochMismatch {
            epoch: Epoch::from_bytes([2; 16]),
            head: None,
        },
        PublishAnswer::VolumeDamaged,
    ];
    for answer in cases {
        let checked = publish_response(&s, &r, answer_response(answer))
            .await
            .unwrap();
        assert_eq!(checked.identification(), answer_tuple(answer));
    }
}
#[tokio::test]
async fn tuple_guard() {
    let r = request();
    let bytes = codec::encode(PublishAnswer::NotDecided {
        position: position(),
        candidate_id: GrainId::of(b"other"),
    })
    .unwrap();
    refused(
        publish_response(
            &store(),
            &r,
            response(409, Some("stale-base"), Some(ANSWER_MEDIA), bytes),
        )
        .await,
        "kind/status/token mismatch",
    );
}
#[tokio::test]
async fn identification_guards() {
    let r = request();
    let s = store();
    let a = PublishAnswer::VolumeDamaged;
    for token in [
        None,
        Some("unknown"),
        Some("volume-damaged, volume-damaged"),
    ] {
        let got = publish_response(
            &s,
            &r,
            response(409, token, Some(ANSWER_MEDIA), codec::encode(a).unwrap()),
        )
        .await;
        assert!(matches!(got, Err(AuthorityError::Backend(_))), "{got:?}");
    }
    let got = publish_response(&s, &r, response(503, Some("unknown"), None, vec![])).await;
    refused(got, "unexpected publish status/token");
    let mut duplicate = answer_response(a);
    duplicate.headers_mut().append(
        "granary-error",
        hyper::header::HeaderValue::from_static("volume-damaged"),
    );
    refused(
        publish_response(&s, &r, duplicate).await,
        "duplicate error token",
    );
    let bytes = codec::encode(accepted(&r)).unwrap();
    refused(
        publish_response(
            &s,
            &r,
            response(202, Some("internal"), Some(ANSWER_MEDIA), bytes),
        )
        .await,
        "success carries error token",
    );
}
#[tokio::test]
async fn unexpected_status_guard() {
    for status in [101, 103, 201, 204, 304, 301, 302, 412, 425, 418] {
        let got = publish_response(
            &store(),
            &request(),
            response(status, Some("unavailable"), None, vec![]),
        )
        .await;
        assert!(
            matches!(got, Err(AuthorityError::Backend(_))),
            "{status}: {got:?}"
        );
    }
}
#[tokio::test]
async fn identity_guards() {
    let r = request();
    let s = store();
    let foreign = GrainId::of(b"foreign");
    for answer in [
        PublishAnswer::Accepted {
            position: position(),
            candidate_id: foreign,
        },
        PublishAnswer::Open {
            position: position(),
            candidate_id: foreign,
        },
        PublishAnswer::Lost {
            position: position(),
            candidate_id: foreign,
            occupant: GrainId::of(b"occupant"),
            head: None,
        },
    ] {
        refused(
            publish_response(&s, &r, answer_response(answer)).await,
            "candidate id mismatch",
        );
    }
    for (id, seq, reason) in [
        (foreign, 5, "stored id mismatch"),
        (r.candidate.id, 6, "landed root sequence mismatch"),
    ] {
        let answer = PublishAnswer::Landed {
            receipt: Receipt {
                position: position(),
                root_seq: seq,
                stored_id: id,
            },
            head: None,
        };
        refused(
            publish_response(&s, &r, answer_response(answer)).await,
            reason,
        );
    }
}
#[tokio::test]
async fn epoch_guard_covers_every_position() {
    let r = request();
    let s = store();
    let p = Position {
        epoch: Epoch::from_bytes([2; 16]),
        ..position()
    };
    let receipt = Receipt {
        position: p,
        root_seq: 5,
        stored_id: r.candidate.id,
    };
    for a in [
        PublishAnswer::Accepted {
            position: p,
            candidate_id: r.candidate.id,
        },
        PublishAnswer::Open {
            position: p,
            candidate_id: r.candidate.id,
        },
        PublishAnswer::Lost {
            position: p,
            candidate_id: r.candidate.id,
            occupant: GrainId::of(b"other"),
            head: None,
        },
        PublishAnswer::Landed {
            receipt,
            head: None,
        },
        PublishAnswer::OperationBound(Bound::Open {
            position: p,
            candidate_id: r.candidate.id,
        }),
        PublishAnswer::OperationBound(Bound::Landed(receipt)),
        PublishAnswer::NotDecided {
            position: p,
            candidate_id: GrainId::of(b"other operation"),
        },
    ] {
        refused(
            publish_response(&s, &r, answer_response(a)).await,
            "position epoch mismatch",
        );
    }
    refused(
        publish_response(
            &s,
            &r,
            answer_response(PublishAnswer::EpochMismatch {
                epoch: r.epoch,
                head: None,
            }),
        )
        .await,
        "unchanged mismatch epoch",
    );
}
#[tokio::test]
async fn binding_guards() {
    let r = request();
    let s = store();
    for b in [
        Bound::Open {
            position: position(),
            candidate_id: GrainId::of(b"unknown"),
        },
        Bound::Landed(Receipt {
            position: position(),
            root_seq: 5,
            stored_id: GrainId::of(b"unknown"),
        }),
    ] {
        refused(
            publish_response(&s, &r, answer_response(PublishAnswer::OperationBound(b))).await,
            "binding not owned",
        );
    }
    let older = r.owned.first().unwrap();
    let b = Bound::Landed(Receipt {
        position: position(),
        root_seq: 5,
        stored_id: older.id,
    });
    refused(
        publish_response(&s, &r, answer_response(PublishAnswer::OperationBound(b))).await,
        "bound root sequence mismatch",
    );
}
#[tokio::test]
async fn media_guard() {
    let r = request();
    let s = store();
    let bytes = codec::encode(accepted(&r)).unwrap();
    for m in [
        None,
        Some("text/plain"),
        Some("application/vnd.granary.authority-answer.v1; charset=utf-8"),
    ] {
        refused(
            publish_response(&s, &r, response(202, None, m, bytes.clone())).await,
            "answer media type mismatch",
        );
    }
    let mut duplicate = answer_response(accepted(&r));
    duplicate.headers_mut().append(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(ANSWER_MEDIA),
    );
    refused(
        publish_response(&s, &r, duplicate).await,
        "answer media type mismatch",
    );
}
#[tokio::test]
async fn complete_canonical_body_guards() {
    let r = request();
    let s = store();
    let good = codec::encode(accepted(&r)).unwrap();
    for n in 0..good.len() {
        refused(
            publish_response(
                &s,
                &r,
                response(202, None, Some(ANSWER_MEDIA), good[..n].to_vec()),
            )
            .await,
            "answer decode",
        );
    }
    let mut trailing = good.clone();
    trailing.push(0);
    refused(
        publish_response(&s, &r, response(202, None, Some(ANSWER_MEDIA), trailing)).await,
        "trailing",
    );
    for (offset, value) in [(9, 0), (10, 255), (35, 0)] {
        let mut bytes = good.clone();
        bytes[offset] = value;
        refused(
            publish_response(&s, &r, response(202, None, Some(ANSWER_MEDIA), bytes)).await,
            "answer decode",
        );
    }
    let mut next = codec::encode(PublishAnswer::StaleBase(Head::new(None))).unwrap();
    *next.last_mut().unwrap() = 2;
    refused(
        publish_response(
            &s,
            &r,
            response(409, Some("stale-base"), Some(ANSWER_MEDIA), next),
        )
        .await,
        "head successor",
    );
    refused(
        publish_response(
            &s,
            &r,
            response(202, None, Some(ANSWER_MEDIA), vec![0; codec::MAX_BYTES + 1]),
        )
        .await,
        "answer exceeds cap",
    );
}

struct UnreadBody;
impl Body for UnreadBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        panic!("error text body must never be polled")
    }
}
#[tokio::test]
async fn error_bodies_are_never_polled() {
    let r = request();
    let s = store();
    for (status, token, no_write) in [
        (400, "bad-request", true),
        (429, "rate-limited", true),
        (503, "enrollment-unavailable", true),
        (503, "unavailable", false),
        (503, "fenced", false),
        (503, "stopped", false),
        (500, "internal", false),
    ] {
        let resp = Response::builder()
            .status(status)
            .header("granary-error", token)
            .body(UnreadBody)
            .unwrap();
        let got = publish_response(&s, &r, resp).await.unwrap();
        assert_eq!(got.identification(), (status, Some(token)));
        assert_eq!(got.request_wrote_nothing(), no_write);
    }
    let accepted = publish_response(&s, &r, answer_response(accepted(&r)))
        .await
        .unwrap();
    let later = publish_response(&s, &r, response(429, Some("rate-limited"), None, vec![]))
        .await
        .unwrap();
    assert!(!accepted.request_wrote_nothing());
    assert!(later.request_wrote_nothing());
}
#[tokio::test]
async fn status_guards_and_read_only_mapping() {
    let s = store();
    let status = VolumeStatus {
        epoch: Epoch::from_bytes([3; 16]),
        head: None,
        open: None,
    };
    let bytes = codec::encode_status(status).unwrap();
    let got = status_response(&s, response(200, None, Some(STATUS_MEDIA), bytes.clone()))
        .await
        .unwrap();
    let StatusResponse::Observed(observed) = got else {
        panic!("{got:?}")
    };
    assert_eq!(observed.observation(), status);
    for token in [
        "no-principal",
        "not-enrolled",
        "rate-limited",
        "enrollment-unavailable",
    ] {
        let code = if token == "rate-limited" {
            429
        } else if token == "enrollment-unavailable" {
            503
        } else {
            403
        };
        assert!(matches!(
            status_response(&s, response(code, Some(token), None, vec![])).await,
            Err(AuthorityError::Backend(_))
        ));
    }
    for (data, m, token) in [
        (vec![0; codec::STATUS_V1_MAX + 1], Some(STATUS_MEDIA), None),
        (vec![], Some(STATUS_MEDIA), None),
        (bytes.clone(), Some("text/plain"), None),
        (bytes, Some(STATUS_MEDIA), Some("internal")),
    ] {
        assert!(matches!(
            status_response(&s, response(200, token, m, data)).await,
            Err(AuthorityError::Backend(_))
        ));
    }
    for (code, token) in [
        (404, "no-log"),
        (404, "unknown-volume"),
        (503, "fenced"),
        (503, "stopped"),
    ] {
        let resp = Response::builder()
            .status(code)
            .header("granary-error", token)
            .body(UnreadBody)
            .unwrap();
        assert_eq!(
            status_response(&s, resp).await.unwrap().identification(),
            (code, Some(token))
        );
    }
}
#[tokio::test]
async fn peer_error_text_is_not_displayed() {
    let s = store();
    let r = request();
    for token in ["peer-message-".repeat(512), "peer message!?".to_owned()] {
        let publish = publish_response(&s, &r, response(400, Some(&token), None, vec![]))
            .await
            .unwrap_err();
        let status = status_response(&s, response(400, Some(&token), None, vec![]))
            .await
            .unwrap_err();
        for error in [publish, status] {
            assert!(
                !error.to_string().contains(&token),
                "peer text appeared in authority error Display"
            );
            let AuthorityError::Backend(error) = error else {
                panic!("expected backend error");
            };
            assert_eq!(error.token(), None);
        }
        let probe = probe_response(&s, response(404, Some(&token), None, vec![]))
            .await
            .unwrap_err();
        assert!(
            !probe.to_string().contains(&token),
            "peer text appeared in probe error Display"
        );
    }
    let headers = response(400, Some("unknown-token"), None, vec![])
        .into_parts()
        .0
        .headers;
    assert!(
        backend(400, &headers, "unexpected token")
            .to_string()
            .contains("unknown-token")
    );
    assert!(
        probe_response(&s, response(404, Some("unknown-target"), None, vec![]))
            .await
            .unwrap_err()
            .to_string()
            .contains("unknown-target")
    );
}

#[tokio::test]
async fn probe_guards() {
    let s = store();
    assert_eq!(
        probe_response(&s, response(404, Some("not-found"), None, vec![]))
            .await
            .unwrap(),
        None
    );
    for token in [None, Some("unknown-target")] {
        assert!(
            probe_response(&s, response(404, token, None, vec![]))
                .await
                .is_err()
        );
    }
    let exact = vec![17; usize::try_from(ROOT_MAX_BYTES).unwrap()];
    assert_eq!(
        probe_response(&s, response(200, None, Some(CT_ROOT), exact.clone()))
            .await
            .unwrap(),
        Some(exact)
    );
    assert!(matches!(
        probe_response(
            &s,
            response(
                200,
                None,
                Some(CT_ROOT),
                vec![0; usize::try_from(ROOT_MAX_BYTES).unwrap() + 1]
            )
        )
        .await,
        Err(RootStoreError::RefusedResponse { .. })
    ));
}
#[test]
fn constructors_guard_local_input() {
    let good = candidate("vol", 5);
    for volume in ["", "../vol", "VOL", "vol/other"] {
        assert!(OwnedCandidate::new(volume, good.bytes.clone()).is_err());
    }
    assert!(OwnedCandidate::new("other", good.bytes.clone()).is_err());
    assert!(
        OwnedCandidate::new(
            "vol",
            vec![0; usize::try_from(ROOT_MAX_BYTES).unwrap() + 1].into()
        )
        .is_err()
    );
    assert!(OwnedCandidate::new("vol", Arc::from(&b"malformed"[..])).is_err());
    let max = candidate("vol", 5);
    let mut doc = root::decode_root(&max.bytes).unwrap();
    doc.seq = u64::MAX - 1;
    assert!(OwnedCandidate::new("vol", root::encode_root(&doc).unwrap().into()).is_err());
    for op in [vec![], vec![0; OPERATION_MAX + 1]] {
        assert!(
            PublishRequest::new(
                "vol",
                position().epoch,
                &op,
                good.clone(),
                vec![good.clone()]
            )
            .is_err()
        );
    }
    assert!(
        PublishRequest::new(
            "vol",
            position().epoch,
            &[0; OPERATION_MAX],
            good.clone(),
            vec![good.clone()]
        )
        .is_ok()
    );
    assert!(PublishRequest::new("vol", position().epoch, b"op", good.clone(), vec![]).is_err());
    assert!(
        PublishRequest::new(
            "vol",
            position().epoch,
            b"op",
            good.clone(),
            vec![candidate("other", 5), good.clone()]
        )
        .is_err()
    );
    assert!(
        PublishRequest::new(
            "vol",
            position().epoch,
            b"op",
            good.clone(),
            vec![good.clone(); 129]
        )
        .is_err()
    );
    assert!(
        PublishRequest::new(
            "vol",
            position().epoch,
            b"op",
            good.clone(),
            vec![good.clone(); 2]
        )
        .is_err()
    );
    assert!(Arc::ptr_eq(good.bytes(), &good.bytes));
    assert_eq!(good.id(), GrainId::of(good.bytes()));
}
#[tokio::test(start_paused = true)]
async fn deadline_covers_stalled_headers_and_body() {
    let got = tokio::time::timeout(
        Duration::from_secs(46),
        deadline(
            Duration::from_secs(45),
            std::future::pending::<Result<(), AuthorityError>>(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(got, Err(AuthorityError::Elapsed));
    let s = store();
    let r = request();
    let resp = Response::builder()
        .status(202)
        .header(CONTENT_TYPE, ANSWER_MEDIA)
        .body(StalledBody)
        .unwrap();
    let call = publish_response(&s, &r, resp);
    assert_eq!(
        deadline(Duration::from_secs(45), call).await,
        Err(AuthorityError::Elapsed)
    );
}
struct StalledBody;
impl Body for StalledBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        Poll::Pending
    }
}
#[test]
fn every_policy_permits_only_the_provably_unsent_common_class() {
    use crate::retry::RetryClass;
    assert!(RetryPolicy::Never.permits(RetryClass::Unsent));
    assert!(RetryPolicy::CreateRoot.permits(RetryClass::Unsent));
    assert!(RetryPolicy::Idempotent.permits(RetryClass::Unsent));
    for class in [
        RetryClass::StreamRefused,
        RetryClass::ConnectionFailed,
        RetryClass::NotRetryable,
    ] {
        assert!(!RetryPolicy::Never.permits(class));
    }
    assert!(RetryPolicy::Idempotent.permits(RetryClass::StreamRefused));
    assert!(RetryPolicy::Idempotent.permits(RetryClass::ConnectionFailed));
    assert!(RetryPolicy::CreateRoot.permits(RetryClass::StreamRefused));
    assert!(!RetryPolicy::CreateRoot.permits(RetryClass::ConnectionFailed));
}

#[test]
fn whole_call_budgets_are_bounded() {
    assert_eq!(seam_deadline(0), Duration::from_secs(45));
    assert_eq!(seam_deadline(1), Duration::from_secs(45));
    assert_eq!(seam_deadline(65536), Duration::from_secs(46));
    assert_eq!(seam_deadline(ROOT_MAX_BYTES), Duration::from_secs(46));
}

#[tokio::test]
async fn invalid_probe_sequences_are_refused_locally() {
    let s = store();
    for seq in [0, u64::MAX] {
        let Err(RootStoreError::Backend(reason)) = s.probe_root_once("vol", seq).await else {
            panic!("invalid probe sequence was not refused locally")
        };
        assert_eq!(reason, "invalid probe root sequence");
    }
}

#[tokio::test]
async fn incomplete_frames_supply_no_evidence() {
    struct Broken;
    impl Body for Broken {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            Poll::Ready(Some(Err(std::io::Error::other("truncated frame"))))
        }
    }
    let resp = Response::builder()
        .status(202)
        .header(CONTENT_TYPE, ANSWER_MEDIA)
        .body(Broken)
        .unwrap();
    refused(
        publish_response(&store(), &request(), resp).await,
        "incomplete answer body",
    );
}

#[test]
fn local_refusals_name_the_guard() {
    let c = candidate("vol", 5);
    assert_eq!(
        OwnedCandidate::new("vol", vec![0; 65537].into())
            .unwrap_err()
            .to_string(),
        "candidate exceeds root cap"
    );
    assert_eq!(
        OwnedCandidate::new("other", c.bytes.clone())
            .unwrap_err()
            .to_string(),
        "candidate volume mismatch"
    );
    let epoch = position().epoch;
    for (op, owned, expected) in [
        (vec![], vec![c.clone()], "invalid operation length"),
        (
            vec![0; OPERATION_MAX + 1],
            vec![c.clone()],
            "invalid operation length",
        ),
        (
            b"op".to_vec(),
            vec![c.clone(); 129],
            "owned candidate history exceeds cap",
        ),
        (
            b"op".to_vec(),
            vec![],
            "submitted candidate missing from history",
        ),
        (
            b"op".to_vec(),
            vec![c.clone(); 2],
            "duplicate owned candidate",
        ),
        (
            b"op".to_vec(),
            vec![c.clone(), candidate("other", 5)],
            "owned candidate volume mismatch",
        ),
    ] {
        assert_eq!(
            PublishRequest::new("vol", epoch, &op, c.clone(), owned)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
}

#[tokio::test]
async fn zero_entry_sequence_is_rejected() {
    let r = request();
    let mut bytes = codec::encode(accepted(&r)).unwrap();
    bytes[27..35].fill(0);
    refused(
        publish_response(&store(), &r, response(202, None, Some(ANSWER_MEDIA), bytes)).await,
        "entry sequence",
    );
}
#[tokio::test]
async fn status_canonical_guards() {
    let s = store();
    let value = VolumeStatus {
        epoch: position().epoch,
        head: None,
        open: None,
    };
    let mut bytes = codec::encode_status(value).unwrap();
    bytes.push(0);
    let Err(AuthorityError::Backend(e)) =
        status_response(&s, response(200, None, Some(STATUS_MEDIA), bytes)).await
    else {
        panic!("accepted trailing status")
    };
    assert!(e.reason().contains("trailing"));
    let Err(AuthorityError::Backend(e)) =
        status_response(&s, response(200, None, Some(STATUS_MEDIA), vec![0; 121])).await
    else {
        panic!("accepted excess status")
    };
    assert_eq!(e.reason(), "status exceeds cap");
}

#[tokio::test]
async fn strict_kind_is_not_masked_by_trailing_bytes() {
    let r = request();
    let mut bytes = codec::encode(PublishAnswer::VolumeDamaged).unwrap();
    bytes[10] = 255;
    refused(
        publish_response(
            &store(),
            &r,
            response(409, Some("volume-damaged"), Some(ANSWER_MEDIA), bytes),
        )
        .await,
        "unknown authority answer kind",
    );
}
#[tokio::test]
async fn strict_presence_and_bound_tags() {
    let r = request();
    let mut presence = codec::encode(PublishAnswer::EpochMismatch {
        epoch: granary_core::authlog::Epoch::from_bytes([2; 16]),
        head: None,
    })
    .unwrap();
    presence[27] = 2;
    refused(
        publish_response(
            &store(),
            &r,
            response(409, Some("epoch-mismatch"), Some(ANSWER_MEDIA), presence),
        )
        .await,
        "presence",
    );
    let mut bound = codec::encode(PublishAnswer::OperationBound(Bound::Open {
        position: position(),
        candidate_id: r.candidate.id,
    }))
    .unwrap();
    bound[11] = 3;
    refused(
        publish_response(
            &store(),
            &r,
            response(409, Some("operation-bound"), Some(ANSWER_MEDIA), bound),
        )
        .await,
        "bound kind",
    );
}

#[tokio::test]
async fn all_refusals_keep_their_wire_identification() {
    let s = store();
    let r = request();
    for (status, token, expected) in [
        (400, "bad-request", PublishRefusal::BadRequest),
        (400, "invalid-candidate", PublishRefusal::InvalidCandidate),
        (400, "missing-reference", PublishRefusal::MissingReference),
        (400, "invalid-reference", PublishRefusal::InvalidReference),
        (413, "publish-work-limit", PublishRefusal::PublishWorkLimit),
        (403, "no-principal", PublishRefusal::NoPrincipal),
        (403, "not-enrolled", PublishRefusal::NotEnrolled),
        (404, "unknown-target", PublishRefusal::UnknownTarget),
        (404, "no-log", PublishRefusal::NoLog),
        (404, "unknown-volume", PublishRefusal::UnknownVolume),
        (405, "method-not-allowed", PublishRefusal::MethodNotAllowed),
        (413, "too-large", PublishRefusal::TooLarge),
    ] {
        let got = publish_response(&s, &r, response(status, Some(token), None, vec![]))
            .await
            .unwrap();
        assert_eq!(got, PublishResponse::Refused(expected));
        assert_eq!(got.identification(), (status, Some(token)));
        assert!(got.request_wrote_nothing());
    }
    for (status, token) in [
        (413, "missing-reference"),
        (413, "invalid-reference"),
        (400, "publish-work-limit"),
    ] {
        assert!(
            publish_response(&s, &r, response(status, Some(token), None, vec![]))
                .await
                .is_err()
        );
    }
    for (status, token, expected) in [
        (400, "bad-request", StatusRefusal::BadRequest),
        (404, "unknown-target", StatusRefusal::UnknownTarget),
        (404, "no-log", StatusRefusal::NoLog),
        (404, "unknown-volume", StatusRefusal::UnknownVolume),
        (405, "method-not-allowed", StatusRefusal::MethodNotAllowed),
        (413, "too-large", StatusRefusal::TooLarge),
    ] {
        let got = status_response(&s, response(status, Some(token), None, vec![]))
            .await
            .unwrap();
        assert_eq!(got, StatusResponse::Refused(expected));
        assert_eq!(got.identification(), (status, Some(token)));
    }
}

#[tokio::test]
async fn only_checked_unknown_target_is_unconfigured() {
    let s = store();
    let bytes = codec::encode_status(VolumeStatus {
        epoch: Epoch::from_bytes([3; 16]),
        head: None,
        open: None,
    })
    .unwrap();
    let observed = status_response(&s, response(200, None, Some(STATUS_MEDIA), bytes))
        .await
        .unwrap();
    assert_eq!(
        observed.authority_configuration(),
        AuthorityConfiguration::Configured
    );
    for (code, token) in [
        (400, "bad-request"),
        (404, "unknown-target"),
        (404, "no-log"),
        (404, "unknown-volume"),
        (405, "method-not-allowed"),
        (413, "too-large"),
        (503, "unavailable"),
        (503, "fenced"),
        (503, "stopped"),
        (500, "internal"),
    ] {
        let answer = status_response(&s, response(code, Some(token), None, vec![]))
            .await
            .unwrap();
        assert_eq!(
            answer.authority_configuration(),
            if token == "unknown-target" {
                AuthorityConfiguration::UnknownTarget
            } else {
                AuthorityConfiguration::Configured
            }
        );
    }
    for (code, token) in [
        (404, None),
        (404, Some("SECRET_SENTINEL")),
        (200, None),
        (503, Some("unknown-target")),
    ] {
        assert!(
            status_response(&s, response(code, token, None, vec![]))
                .await
                .is_err()
        );
    }
}
