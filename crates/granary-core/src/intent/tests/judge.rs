// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The agreement function: every accepted row, every wrong receipt, and every
//! status class the protocol defines for the intent endpoints.

use super::*;

const W: u8 = 0xA1;
const GEN: u64 = 5;
/// A process other than the one under test.
const OTHER: u8 = 0xC2;

fn rid(n: u8) -> GrainId {
    id(n)
}

fn register_req() -> RegisterRequest {
    RegisterRequest {
        epoch: 1,
        writer: writer(W),
        instance: inst(I),
        generation: GEN,
        root_id: rid(1),
    }
}

fn release_req() -> ReleaseRequest {
    ReleaseRequest {
        epoch: 1,
        writer: writer(W),
        instance: inst(I),
        generation: GEN,
    }
}

/// The same receipt as reported for another process's row.
fn held_by_other(r: Receipt) -> Receipt {
    Receipt {
        instance: inst(OTHER),
        ..r
    }
}

fn receipt_bytes(r: Receipt) -> Vec<u8> {
    encode_receipt(r).unwrap()
}

fn reply<'a>(
    status: u16,
    media: Option<&'a str>,
    token: Option<&'a str>,
    body: &'a [u8],
) -> Reply<'a> {
    Reply {
        status,
        media_type: media,
        token,
        body,
    }
}

/// Judge a registration answered with `status`/`token` and `rec` as the body.
fn reg(status: u16, token: Option<&str>, rec: Receipt) -> Verdict<Receipt> {
    let body = receipt_bytes(rec);
    judge_register(
        &register_req(),
        &reply(status, Some(MEDIA_RECEIPT), token, &body),
    )
}

fn rel(status: u16, token: Option<&str>, rec: Receipt) -> Verdict<Receipt> {
    let body = receipt_bytes(rec);
    judge_release(
        &release_req(),
        &reply(status, Some(MEDIA_RECEIPT), token, &body),
    )
}

fn backend<T>(v: Verdict<T>) -> &'static str
where
    T: std::fmt::Debug,
{
    match v {
        Verdict::Backend(d) => d.name(),
        other => panic!("expected a backend error, got {other:?}"),
    }
}

const SUP: Option<&str> = Some("intent-superseded");
const BOUND: Option<&str> = Some("intent-bound");

#[test]
fn a_registration_200_needs_this_writer_instance_generation_and_root() {
    let good = live(writer(W), GEN, rid(1));
    assert_eq!(reg(200, None, good), Verdict::Accepted(good));
    assert_eq!(
        backend(reg(200, None, Receipt { epoch: 2, ..good })),
        "receipt-epoch"
    );
    // Each field wrong in turn; the good row above is the positive control.
    assert_eq!(
        backend(reg(200, None, live(writer(W + 1), GEN, rid(1)))),
        "receipt-writer"
    );
    // A 200 means the row is this process's: a receipt naming another
    // process's token is a server that did not record the request.
    assert_eq!(
        backend(reg(200, None, held_by_other(good))),
        "receipt-instance"
    );
    assert_eq!(
        backend(reg(200, None, live(writer(W), GEN, rid(2)))),
        "receipt-root-id"
    );
    assert_eq!(
        backend(reg(200, None, gone(writer(W), GEN))),
        "receipt-state"
    );
    // A receipt for generation N is never proof of another.
    assert_eq!(
        backend(reg(200, None, live(writer(W), GEN + 1, rid(1)))),
        "receipt-generation"
    );
    assert_eq!(
        backend(reg(200, None, live(writer(W), GEN - 1, rid(1)))),
        "receipt-generation"
    );
}

/// Under the request's own token a superseded answer reports a recorded
/// generation that beats the request's.
#[test]
fn a_registration_superseded_under_its_own_token_reports_a_generation_that_beats_the_request() {
    for (rec, ok) in [
        (live(writer(W), GEN + 1, rid(9)), true),
        (live(writer(W), GEN, rid(9)), false),
        (live(writer(W), GEN - 1, rid(9)), false),
        (gone(writer(W), GEN + 1), true),
        (gone(writer(W), GEN), true),
        (gone(writer(W), GEN - 1), false),
    ] {
        let got = reg(409, SUP, rec);
        if ok {
            assert_eq!(
                got,
                if rec.instance == inst(I) {
                    Verdict::Overtaken(rec)
                } else {
                    Verdict::Superseded(rec)
                },
                "{rec:?}"
            );
        } else {
            assert_eq!(backend(got), "receipt-generation", "{rec:?}");
        }
    }
    assert_eq!(
        backend(reg(409, SUP, live(writer(W + 1), GEN + 1, rid(9)))),
        "receipt-writer"
    );
}

/// Strictly newer ownership fences at any generation, with either token.
#[test]
fn a_displaced_registration_is_superseded_at_any_generation() {
    for generation in [GEN - 1, GEN, GEN + 1] {
        for state in [
            ReceiptState::Released,
            ReceiptState::Live {
                prepared_root_id: rid(9),
            },
        ] {
            for instance in [inst(I), inst(OTHER)] {
                let rec = Receipt {
                    epoch: 2,
                    instance,
                    state,
                    ..gone(writer(W), generation)
                };
                assert_eq!(reg(409, SUP, rec), Verdict::Superseded(rec));
            }
        }
    }
}

/// A registration over a row released at the same or a higher generation is
/// superseded, whether the releaser was this process or its successor's
/// predecessor: the released row is what stops a delayed registration.
#[test]
fn a_delayed_registration_after_a_release_is_superseded() {
    // A release over an owned row at GEN records the row released at
    // GEN, answers 200, and the releaser's receipt says so.
    let released_at_gen = gone(writer(W), GEN);
    assert_eq!(
        rel(200, None, released_at_gen),
        Verdict::Accepted(released_at_gen)
    );
    // The registration at GEN that was delayed behind it is superseded by that
    // very row; a registration below it is too.
    assert_eq!(
        reg(409, SUP, released_at_gen),
        Verdict::Overtaken(released_at_gen)
    );
    let released_above = gone(writer(W), GEN + 3);
    assert_eq!(
        reg(409, SUP, released_above),
        Verdict::Overtaken(released_above)
    );
    // The same delayed registration answered 200 with a live receipt would be
    // a server that resurrected the intent, and a released receipt on a 200
    // is no registration receipt either.
    assert_eq!(backend(reg(200, None, released_at_gen)), "receipt-state");
    // A released row below the request's generation does not fence it.
    assert_eq!(
        backend(reg(409, SUP, gone(writer(W), GEN - 1))),
        "receipt-generation"
    );
}

#[test]
fn a_registration_bound_is_this_instances_live_row_at_this_generation_with_another_root() {
    let good = live(writer(W), GEN, rid(2));
    assert_eq!(reg(409, BOUND, good), Verdict::Bound(good));
    assert_eq!(
        backend(reg(409, BOUND, live(writer(W), GEN, rid(1)))),
        "receipt-root-id"
    );
    assert_eq!(
        backend(reg(409, BOUND, live(writer(W), GEN + 1, rid(2)))),
        "receipt-generation"
    );
    assert_eq!(
        backend(reg(409, BOUND, live(writer(W), GEN - 1, rid(2)))),
        "receipt-generation"
    );
    assert_eq!(
        backend(reg(409, BOUND, gone(writer(W), GEN))),
        "receipt-state"
    );
    assert_eq!(
        backend(reg(409, BOUND, live(writer(W + 1), GEN, rid(2)))),
        "receipt-writer"
    );
    // Another process's row at this generation is a fence, not a bound.
    assert_eq!(
        backend(reg(409, BOUND, held_by_other(good))),
        "receipt-instance"
    );
}

/// A release of g releases everything at or below g: the receipt is this
/// process's, released, at g or above (the row keeps the higher generation).
#[test]
fn a_release_200_needs_a_released_receipt_at_this_generation_or_above() {
    let good = gone(writer(W), GEN);
    assert_eq!(rel(200, None, good), Verdict::Accepted(good));
    let higher = gone(writer(W), GEN + 1);
    assert_eq!(rel(200, None, higher), Verdict::Accepted(higher));
    assert_eq!(
        backend(rel(200, None, live(writer(W), GEN, rid(1)))),
        "receipt-state"
    );
    assert_eq!(
        backend(rel(200, None, gone(writer(W), GEN - 1))),
        "receipt-generation"
    );
    assert_eq!(
        backend(rel(200, None, gone(writer(W + 1), GEN))),
        "receipt-writer"
    );
    assert_eq!(
        backend(rel(200, None, held_by_other(good))),
        "receipt-instance"
    );
}

/// A release is fenced by a strictly newer epoch, at any generation/token.
#[test]
fn a_release_superseded_requires_newer_ownership() {
    for generation in [GEN - 1, GEN, GEN + 1] {
        for state in [
            ReceiptState::Released,
            ReceiptState::Live {
                prepared_root_id: rid(1),
            },
        ] {
            for instance in [inst(I), inst(OTHER)] {
                let rec = Receipt {
                    epoch: 2,
                    instance,
                    state,
                    ..gone(writer(W), generation)
                };
                assert_eq!(rel(409, SUP, rec), Verdict::Superseded(rec));
            }
        }
    }
    for rec in [live(writer(W), GEN + 1, rid(1)), gone(writer(W), GEN + 1)] {
        assert_eq!(backend(rel(409, SUP, rec)), "receipt-epoch");
        assert_eq!(
            backend(rel(409, SUP, held_by_other(rec))),
            "receipt-instance"
        );
    }
    assert_eq!(
        backend(rel(409, SUP, held_by_other(gone(writer(W + 1), GEN + 1)))),
        "receipt-writer"
    );
}

/// A release at a higher generation than the row's is a release, not a
/// bound: there is no `intent-bound` answer to a release.
#[test]
fn a_release_has_no_bound_row() {
    for rec in [live(writer(W), GEN - 1, rid(1)), gone(writer(W), GEN - 1)] {
        assert_eq!(backend(rel(409, BOUND, rec)), "token-mismatch", "{rec:?}");
    }
}

/// A 200 or a receipt-bearing 409 needs the receipt media type, a body that
/// decodes, and (on a 200) no token.
#[test]
fn the_media_type_the_token_and_the_body_are_each_checked() {
    let good = live(writer(W), GEN, rid(1));
    let body = receipt_bytes(good);
    let req = register_req();
    let ok = reply(200, Some(MEDIA_RECEIPT), None, &body);
    assert_eq!(judge_register(&req, &ok), Verdict::Accepted(good));
    for media in [
        None,
        Some(MEDIA_READBACK),
        Some(MEDIA_REGISTER),
        Some("text/plain"),
    ] {
        assert_eq!(
            backend(judge_register(&req, &reply(200, media, None, &body))),
            "wrong-media-type",
            "{media:?}"
        );
    }
    assert_eq!(
        backend(judge_register(
            &req,
            &reply(200, Some(MEDIA_RECEIPT), Some("internal"), &body)
        )),
        "token-on-success"
    );
    assert_eq!(
        backend(judge_register(
            &req,
            &reply(200, Some(MEDIA_RECEIPT), None, b"")
        )),
        "body"
    );
    assert_eq!(
        backend(judge_register(
            &req,
            &reply(200, Some(MEDIA_RECEIPT), None, &body[..body.len() - 1])
        )),
        "body"
    );
    // The 409 receipt rows need the media type and a decodable body too.
    let rec = receipt_bytes(live(writer(W), GEN + 1, rid(9)));
    assert!(matches!(
        judge_register(&req, &reply(409, Some(MEDIA_RECEIPT), SUP, &rec)),
        Verdict::Overtaken(_)
    ));
    assert_eq!(
        backend(judge_register(&req, &reply(409, None, SUP, &rec))),
        "wrong-media-type"
    );
    assert_eq!(
        backend(judge_register(
            &req,
            &reply(409, Some("text/plain; charset=utf-8"), SUP, &rec)
        )),
        "wrong-media-type"
    );
    assert_eq!(
        backend(judge_register(
            &req,
            &reply(409, Some(MEDIA_RECEIPT), SUP, b"human text")
        )),
        "body"
    );
}

/// The media type is the header's bytes, compared exactly as the transport
/// that fetched the answer compares it: no parameters, no case folding. A
/// judge that normalised either would accept an answer the transport
/// refuses.
#[test]
fn the_media_type_is_compared_byte_exactly() {
    let good = live(writer(W), GEN, rid(1));
    let body = receipt_bytes(good);
    let sup_body = receipt_bytes(live(writer(W), GEN + 1, rid(9)));
    let req = register_req();
    let parameterised = format!("{MEDIA_RECEIPT}; charset=binary");
    let bare_semicolon = format!("{MEDIA_RECEIPT};");
    let padded = format!("{MEDIA_RECEIPT} ");
    let upper = MEDIA_RECEIPT.to_ascii_uppercase();
    let mixed = MEDIA_RECEIPT.replace("granary", "Granary");
    // The unmodified value is the positive control for every row below.
    assert_eq!(
        judge_register(&req, &reply(200, Some(MEDIA_RECEIPT), None, &body)),
        Verdict::Accepted(good)
    );
    for media in [&parameterised, &bare_semicolon, &padded, &upper, &mixed] {
        assert_eq!(
            backend(judge_register(&req, &reply(200, Some(media), None, &body))),
            "wrong-media-type",
            "200 {media:?}"
        );
        assert_eq!(
            backend(judge_register(
                &req,
                &reply(409, Some(media), SUP, &sup_body)
            )),
            "wrong-media-type",
            "409 {media:?}"
        );
        assert_eq!(
            backend(judge_release(
                &release_req(),
                &reply(200, Some(media), None, &body)
            )),
            "wrong-media-type",
            "release {media:?}"
        );
    }
    let rb = readback_of(VOLUME, &[1]);
    for media in [
        format!("{MEDIA_READBACK}; charset=binary"),
        MEDIA_READBACK.to_ascii_uppercase(),
    ] {
        let got = judge_readback(&reply(200, Some(&media), None, &rb), &vol(VOLUME), accept);
        assert_eq!(backend(got), "wrong-media-type", "readback {media:?}");
    }
    assert!(matches!(
        judge_readback(&readback_reply(&rb), &vol(VOLUME), accept),
        Verdict::Accepted(_)
    ));
}

/// A `Granary-Error` field on any 2xx is a disagreement; the status the table
/// has no row for is `unexpected-status` only when there is no token.
#[test]
fn a_token_on_any_2xx_is_token_on_success() {
    let body = receipt_bytes(live(writer(W), GEN, rid(1)));
    let rb = readback_of(VOLUME, &[1]);
    for status in [200u16, 201, 202, 204, 206, 299] {
        let with_token = reply(status, Some(MEDIA_RECEIPT), Some("internal"), &body);
        assert_eq!(
            backend(judge_register(&register_req(), &with_token)),
            "token-on-success",
            "register {status}"
        );
        assert_eq!(
            backend(judge_release(&release_req(), &with_token)),
            "token-on-success",
            "release {status}"
        );
        let rb_token = reply(status, Some(MEDIA_READBACK), Some("internal"), &rb);
        assert_eq!(
            backend(judge_readback(&rb_token, &vol(VOLUME), accept)),
            "token-on-success",
            "readback {status}"
        );
    }
    // Control: the same statuses without a token are the table's gap.
    for status in [201u16, 204, 299] {
        assert_eq!(
            backend(judge_register(
                &register_req(),
                &reply(status, Some(MEDIA_RECEIPT), None, &body)
            )),
            "unexpected-status",
            "{status}"
        );
    }
}

#[test]
fn the_quota_refusal_has_no_intent_body() {
    let req = register_req();
    for media in [None, Some("text/plain")] {
        assert_eq!(
            judge_register(
                &req,
                &reply(409, media, Some("intent-quota"), b"over quota")
            ),
            Verdict::OverQuota
        );
    }
    let body = receipt_bytes(live(writer(W), GEN, rid(1)));
    assert_eq!(
        backend(judge_register(
            &req,
            &reply(409, Some(MEDIA_RECEIPT), Some("intent-quota"), &body)
        )),
        "unexpected-intent-body"
    );
    // Release never creates ownership, so it has no quota outcome.
    assert_eq!(
        backend(judge_release(
            &release_req(),
            &reply(409, Some("text/plain"), Some("intent-quota"), b"")
        )),
        "token-mismatch"
    );
    assert_eq!(
        backend(judge_release(
            &release_req(),
            &reply(409, Some(MEDIA_RECEIPT), Some("intent-quota"), &body)
        )),
        "token-mismatch"
    );
    // A readback creates nothing and has no quota row.
    assert_eq!(
        backend(judge_readback(
            &reply(409, Some("text/plain"), Some("intent-quota"), b""),
            &vol(VOLUME),
            accept
        )),
        "unexpected-status"
    );
    // A 409 with no token, or a token that is not an intent one, proves nothing.
    for token in [None, Some("stale-base"), Some("internal")] {
        assert_eq!(
            backend(judge_register(
                &req,
                &reply(409, Some("text/plain"), token, b"")
            )),
            "token-mismatch"
        );
    }
}

/// Every status class the protocol defines for the intent endpoints, for a registration; the same
/// answers to a release except where an operation has no such row.
#[test]
fn every_non_table_status_is_its_own_class() {
    use Refusal::*;
    use UnknownCause::*;
    let text = Some("text/plain; charset=utf-8");
    let cases: [(u16, Option<&str>, Verdict<Receipt>); 18] = [
        (400, Some("bad-request"), Verdict::Refused(BadRequest)),
        (
            400,
            Some("invalid-candidate"),
            Verdict::Refused(InvalidPreparedRoot),
        ),
        (403, Some("no-principal"), Verdict::Refused(NoPrincipal)),
        (403, Some("not-enrolled"), Verdict::Refused(NotEnrolled)),
        (404, Some("unknown-target"), Verdict::NotImplemented),
        (404, Some("unknown-volume"), Verdict::Refused(UnknownVolume)),
        (
            405,
            Some("method-not-allowed"),
            Verdict::Refused(MethodNotAllowed),
        ),
        (413, Some("too-large"), Verdict::Refused(TooLarge)),
        (429, Some("rate-limited"), Verdict::RateLimited),
        (
            503,
            Some("enrollment-unavailable"),
            Verdict::EnrollmentUnavailable,
        ),
        (500, Some("internal"), Verdict::Unknown(Internal)),
        (500, None, Verdict::Unknown(Internal)),
        (503, Some("unavailable"), Verdict::Unknown(Unavailable)),
        (503, Some("fenced"), Verdict::Unknown(Fenced)),
        (503, Some("stopped"), Verdict::Unknown(Stopped)),
        (503, None, Verdict::Unknown(Other(503))),
        (502, None, Verdict::Unknown(Other(502))),
        (504, Some("anything"), Verdict::Unknown(Other(504))),
    ];
    for (status, token, want) in cases {
        let got = judge_register(&register_req(), &reply(status, text, token, b"for a human"));
        assert_eq!(got, want, "register {status} {token:?}");
        if token != Some("invalid-candidate") {
            let got = judge_release(&release_req(), &reply(status, text, token, b"for a human"));
            assert_eq!(got, want.clone(), "release {status} {token:?}");
        }
    }
}

/// What a client does next, for every class of answer to either operation:
/// only an answer that proves nothing about the request, and a 429 once its
/// delay has passed, may be resent unchanged. Every other validated 4xx and a
/// fence is final. A wrong implementation treats 429 as a refusal (the
/// release retried at unmount never goes), or treats a `409` as retryable.
#[test]
fn only_unknown_outcomes_and_a_delayed_429_may_be_resent() {
    use Resend::{AfterDelay, Never, Unchanged};
    let text = Some("text/plain");
    let sup_body = receipt_bytes(held_by_other(live(writer(W), GEN + 1, rid(9))));
    let bound_body = receipt_bytes(live(writer(W), GEN, rid(2)));
    let registered_ok = receipt_bytes(live(writer(W), GEN, rid(1)));
    let released_ok = receipt_bytes(gone(writer(W), GEN));
    let r = |status, media, token, body: &[u8]| (status, media, token, body.to_vec());
    let register_cases = [
        (
            r(200, Some(MEDIA_RECEIPT), None, &registered_ok),
            Never,
            "accepted",
        ),
        (
            r(409, Some(MEDIA_RECEIPT), SUP, &sup_body),
            Never,
            "superseded",
        ),
        (
            r(409, Some(MEDIA_RECEIPT), BOUND, &bound_body),
            Never,
            "bound",
        ),
        (r(409, text, Some("intent-quota"), b""), Never, "quota"),
        (r(400, text, Some("bad-request"), b""), Never, "400"),
        (
            r(400, text, Some("invalid-candidate"), b""),
            Never,
            "invalid",
        ),
        (r(403, text, Some("no-principal"), b""), Never, "403"),
        (r(403, text, Some("not-enrolled"), b""), Never, "403 enrol"),
        (
            r(404, text, Some("unknown-volume"), b""),
            Never,
            "404 volume",
        ),
        (
            r(404, text, Some("unknown-target"), b""),
            Never,
            "404 target",
        ),
        (r(405, text, Some("method-not-allowed"), b""), Never, "405"),
        (r(413, text, Some("too-large"), b""), Never, "413"),
        (r(429, text, Some("rate-limited"), b""), AfterDelay, "429"),
        (r(500, text, Some("internal"), b""), Unchanged, "500"),
        (r(502, text, None, b""), Unchanged, "502"),
        (
            r(503, text, Some("unavailable"), b""),
            Unchanged,
            "503 unavailable",
        ),
        (r(503, text, Some("fenced"), b""), Unchanged, "503 fenced"),
        (r(503, text, Some("stopped"), b""), Unchanged, "503 stopped"),
        (
            r(503, text, Some("enrollment-unavailable"), b""),
            Unchanged,
            "503 enrollment",
        ),
        (r(504, text, None, b""), Unchanged, "504"),
        (r(301, text, None, b""), Never, "unexpected status"),
        (r(400, text, None, b""), Never, "token mismatch"),
    ];
    for ((status, media, token, body), want, label) in &register_cases {
        let got = judge_register(&register_req(), &reply(*status, *media, *token, body));
        assert_eq!(got.resend(), *want, "register {label}: {got:?}");
    }
    resend_release_and_readback_cases(&released_ok);
}

/// The same classes for a release, with the release's own receipts, and for a
/// readback. The 429 row is the one the unmount depends on.
fn resend_release_and_readback_cases(released_ok: &[u8]) {
    use Resend::{AfterDelay, Never, Unchanged};
    let text = Some("text/plain");
    let rel_sup_body = receipt_bytes(held_by_other(gone(writer(W), GEN)));
    let r = |status, media, token, body: &[u8]| (status, media, token, body.to_vec());
    let release_cases = [
        (
            r(200, Some(MEDIA_RECEIPT), None, released_ok),
            Never,
            "accepted",
        ),
        (
            r(409, Some(MEDIA_RECEIPT), SUP, &rel_sup_body),
            Never,
            "superseded",
        ),
        (r(429, text, Some("rate-limited"), b""), AfterDelay, "429"),
        (r(413, text, Some("too-large"), b""), Never, "413"),
        (r(404, text, Some("unknown-target"), b""), Never, "404"),
        (r(403, text, Some("not-enrolled"), b""), Never, "403"),
        (r(500, text, Some("internal"), b""), Unchanged, "500"),
        (r(503, text, Some("fenced"), b""), Unchanged, "503 fenced"),
        (
            r(503, text, Some("enrollment-unavailable"), b""),
            Unchanged,
            "503 enrollment",
        ),
    ];
    for ((status, media, token, body), want, label) in &release_cases {
        let got = judge_release(&release_req(), &reply(*status, *media, *token, body));
        assert_eq!(got.resend(), *want, "release {label}: {got:?}");
    }
    // A disagreement is never retried, whatever the status it arrived under.
    let got = judge_release(
        &release_req(),
        &reply(200, Some(MEDIA_RECEIPT), Some("internal"), released_ok),
    );
    assert_eq!(got.resend(), Never);
    // No answer at all, a timeout, a broken connection and a REFUSED_STREAM
    // reset are the transport's: the request goes again unchanged.
    assert_eq!(RESEND_AFTER_TRANSPORT_FAILURE, Unchanged);
    // A readback is a read: its 429 and 5xx follow the same classes.
    let v = vol(VOLUME);
    let got = judge_readback(&reply(429, text, Some("rate-limited"), b""), &v, accept);
    assert_eq!(got.resend(), AfterDelay);
    let got = judge_readback(&reply(503, text, Some("fenced"), b""), &v, accept);
    assert_eq!(got.resend(), Unchanged);
    let got = judge_readback(&reply(403, text, Some("not-enrolled"), b""), &v, accept);
    assert_eq!(got.resend(), Never);
}

#[test]
fn a_status_or_token_the_table_does_not_name_is_a_backend_error() {
    let text = Some("text/plain");
    for status in [100u16, 201, 202, 204, 206, 301, 304, 410, 412, 425, 451] {
        assert_eq!(
            backend(judge_register(
                &register_req(),
                &reply(status, text, None, b"")
            )),
            "unexpected-status",
            "{status}"
        );
    }
    // A validated-looking 4xx needs its own token: absent or another's proves nothing.
    for (status, token) in [
        (400u16, None),
        (400, Some("not-enrolled")),
        (403, None),
        (403, Some("bad-request")),
        (404, None),
        (404, Some("not-found")),
        (405, None),
        (413, Some("bad-request")),
        (429, None),
    ] {
        assert_eq!(
            backend(judge_register(
                &register_req(),
                &reply(status, text, token, b"")
            )),
            "token-mismatch",
            "{status} {token:?}"
        );
    }
    // The registration's own cause is not a release's.
    assert_eq!(
        backend(judge_release(
            &release_req(),
            &reply(400, text, Some("invalid-candidate"), b"")
        )),
        "token-mismatch"
    );
}

#[test]
fn an_intent_body_on_a_row_that_carries_none_is_refused() {
    let body = receipt_bytes(live(writer(W), GEN, rid(1)));
    for (status, token) in [
        (400u16, Some("bad-request")),
        (403, Some("not-enrolled")),
        (404, Some("unknown-target")),
        (503, Some("enrollment-unavailable")),
        (500, Some("internal")),
        (503, Some("fenced")),
        (429, Some("rate-limited")),
    ] {
        for media in [MEDIA_RECEIPT, MEDIA_READBACK, MEDIA_REGISTER, MEDIA_RELEASE] {
            assert_eq!(
                backend(judge_register(
                    &register_req(),
                    &reply(status, Some(media), token, &body)
                )),
                "unexpected-intent-body",
                "{status} {media}"
            );
        }
        // Control: the same status with a human-readable body is its class.
        assert!(!matches!(
            judge_register(
                &register_req(),
                &reply(status, Some("text/plain"), token, b"x")
            ),
            Verdict::Backend(_)
        ));
    }
}

fn readback_reply(body: &[u8]) -> Reply<'_> {
    reply(200, Some(MEDIA_READBACK), None, body)
}

#[test]
fn a_readback_200_is_decoded_for_the_requested_volume_and_signature() {
    let body = readback_of(VOLUME, &[2, 5]);
    let got = judge_readback(&readback_reply(&body), &vol(VOLUME), accept);
    let Verdict::Accepted(rb) = got else {
        panic!("{got:?}")
    };
    assert_eq!(rb.rows.len(), 2);
    let empty = readback_of(VOLUME, &[]);
    assert!(matches!(
        judge_readback(&readback_reply(&empty), &vol(VOLUME), accept),
        Verdict::Accepted(rb) if rb.rows.is_empty()
    ));
    // Wrong volume and a refused signature are backend errors, never a success.
    assert_eq!(
        judge_readback(&readback_reply(&body), &vol(OTHER_VOLUME), accept),
        Verdict::Backend(Disagreement::Body(Error::RootWrongVolume))
    );
    assert_eq!(
        judge_readback(&readback_reply(&body), &vol(VOLUME), refuse),
        Verdict::Backend(Disagreement::Body(Error::RootBadSignature))
    );
    // Media type, token and body.
    for media in [None, Some(MEDIA_RECEIPT), Some("text/plain")] {
        let got = judge_readback(&reply(200, media, None, &body), &vol(VOLUME), accept);
        assert_eq!(backend(got), "wrong-media-type");
    }
    let got = judge_readback(
        &reply(200, Some(MEDIA_READBACK), Some("internal"), &body),
        &vol(VOLUME),
        accept,
    );
    assert_eq!(backend(got), "token-on-success");
    let got = judge_readback(
        &readback_reply(&body[..body.len() - 1]),
        &vol(VOLUME),
        accept,
    );
    assert_eq!(backend(got), "body");
}

#[test]
fn a_readback_has_no_conflict_rows_and_no_body_cap_status() {
    let text = Some("text/plain");
    let v = vol(VOLUME);
    for token in [SUP, BOUND, Some("intent-quota"), None] {
        let got = judge_readback(&reply(409, text, token, b""), &v, accept);
        assert_eq!(backend(got), "unexpected-status", "{token:?}");
    }
    let got = judge_readback(&reply(413, text, Some("too-large"), b""), &v, accept);
    assert_eq!(backend(got), "unexpected-status");
    let got = judge_readback(
        &reply(400, text, Some("invalid-candidate"), b""),
        &v,
        accept,
    );
    assert_eq!(backend(got), "token-mismatch");
    let got = judge_readback(&reply(404, text, Some("unknown-target"), b""), &v, accept);
    assert_eq!(got, Verdict::NotImplemented);
    let got = judge_readback(&reply(404, text, Some("unknown-volume"), b""), &v, accept);
    assert_eq!(got, Verdict::Refused(Refusal::UnknownVolume));
}

#[test]
fn a_release_receipt_is_not_a_readback_and_a_readback_is_not_a_receipt() {
    let body = receipt_bytes(gone(writer(W), GEN));
    let got = judge_readback(&readback_reply(&body), &vol(VOLUME), accept);
    assert_eq!(backend(got), "body");
    let rb = readback_of(VOLUME, &[1]);
    let got = judge_release(&release_req(), &reply(200, Some(MEDIA_RECEIPT), None, &rb));
    assert_eq!(backend(got), "body");
}
