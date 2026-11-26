// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(test)]

//! Unit tests for `crate::adapter` — the hyper adapter — the layer
//! meeting `granary_net::accept::serve`'s `Service<Request<Incoming>>`
//! bound with the policy layer behind it.
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{
    Accepted, BodyCap, Bounds, DRAIN_BUDGET_BYTES, DRAIN_MAX_WAIT, Drain, GRANARY_ERROR,
    GrainService, OTHER_METHOD, OverCap, PERMITTED_READ_TRANSIENT_CEILING_BYTES,
    READ_BODY_BUDGET_BYTES, READ_PERMITS, READ_TRANSIENT_PEAK_BYTES, ReadBudget, SHUTDOWN_DEADLINE,
    TEST_WORKER_THREADS, VERIFY_PERMIT_MAX_WAIT, VERIFY_PERMITS_MAX, WRITE_ACCEPT_MAX_WAIT,
    WRITE_ACCEPT_MAX_WAIT_SHIPPED, WRITE_BODY_BUDGET_BYTES, WRITE_BUDGET_GRANULE_BYTES,
    WriteBudget, accept_body, answer, charge_target, drain_to_budget, modelled_transient_peak,
    render, respond, shed_then_drain, takes_a_read_permit, until_draining, verify_permits,
    worker_threads, write_cap,
};
use crate::admission::{Conditionals, DECLARED_MAX_EXTENT, Operation, RequestHead, admit};
use crate::config::STORE_DISPATCH_DEADLINE;
use crate::fake::FakeSeam;
use crate::policy::VerifyPolicy;
use crate::wire::{
    Allow, CacheControl, ContentType, ETag, ErrorToken, Outcome, PublishConflict, PublishRefusal,
    Resource, Status, StatusRefusal,
};
use granary_core::binfmt::{BIN_MAX_BYTES, FRAME_COMP_MAX};
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::rootstore::SEQ_KEY_DIGITS;
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError, filter_above};
use granary_net::accept::{H2_MAX_CONCURRENT_STREAMS, MAX_CONNECTIONS};
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame};
use hyper::header::HeaderName;
use hyper::header::{
    ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderValue, RANGE,
    RETRY_AFTER,
};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use std::convert::Infallible;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

/// A no-runtime executor for the rendering rows: a `Full` body is
/// `Ready` on its first poll, so a `Pending` would mean the test is
/// wrong rather than the code.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a Full body never yields"),
    }
}

/// The rendered response's body, collected.
fn body_of(response: Response<Full<Bytes>>) -> Bytes {
    let Ok(collected) = block_on(response.into_body().collect());
    collected.to_bytes()
}

/// A named field's value as a string, or `None`.
fn field(response: &Response<Full<Bytes>>, name: &HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn token(response: &Response<Full<Bytes>>) -> Option<String> {
    field(response, &GRANARY_ERROR)
}

// -- §8.2, §6, §11: the transcription --------------------------------

/// Seam and selected authority [`Outcome`] rows with the expected §5.x
/// status and §8.2 token.
fn outcome_rows() -> Vec<(&'static str, Outcome, u16, Option<&'static str>)> {
    let mut rows = seam_outcome_rows();
    rows.extend([
        public_cache_miss_row(
            "max_seq_empty",
            Outcome::max_seq_empty(),
            CacheControl::NoStore,
        ),
        public_cache_miss_row(
            "hint_missing",
            Outcome::hint_missing(),
            CacheControl::NoCache,
        ),
    ]);
    rows.extend(authority_outcome_rows());
    rows
}

/// The rows for the constructors the nine seam endpoints answer with.
fn seam_outcome_rows() -> Vec<(&'static str, Outcome, u16, Option<&'static str>)> {
    let etag = || ETag::new("\"v7\"".to_owned()).unwrap_or_else(|| panic!("a strong tag"));
    let seq = NonZeroU64::new(41).unwrap_or_else(|| panic!("41 is not zero"));

    vec![
        ("created", Outcome::created(), 201, None),
        ("already_present", Outcome::already_present(), 200, None),
        ("hint_written", Outcome::hint_written(), 204, None),
        ("meta", Outcome::meta(b"meta bytes".to_vec()), 200, None),
        ("root", Outcome::root(b"root bytes".to_vec()), 200, None),
        ("max_seq", Outcome::max_seq(seq), 200, None),
        ("hint", Outcome::hint(seq, etag()), 200, None),
        (
            "hint_not_modified",
            Outcome::hint_not_modified(etag()),
            304,
            None,
        ),
        (
            "bin_range",
            Outcome::bin_range(100, vec![7u8; 10])
                .unwrap_or_else(|| panic!("a ten-byte range at 100")),
            206,
            None,
        ),
        ("not_found", Outcome::not_found(), 404, Some("not-found")),
        (
            "unknown_target",
            Outcome::unknown_target(),
            404,
            Some("unknown-target"),
        ),
        (
            "already_exists",
            Outcome::already_exists(),
            409,
            Some("already-exists"),
        ),
        (
            "address_mismatch",
            Outcome::address_mismatch(),
            400,
            Some("address-mismatch"),
        ),
        (
            "verify_failed",
            Outcome::verify_failed(),
            400,
            Some("verify-failed"),
        ),
        (
            "layout_invalid",
            Outcome::layout_invalid(),
            400,
            Some("layout-invalid"),
        ),
        (
            "bad_range_form",
            Outcome::bad_range_form(),
            400,
            Some("bad-range"),
        ),
        (
            "range_not_satisfiable",
            Outcome::range_not_satisfiable(),
            416,
            Some("bad-range"),
        ),
        (
            "extent_too_wide",
            Outcome::extent_too_wide(),
            400,
            Some("extent-too-wide"),
        ),
        (
            "bad_request",
            Outcome::bad_request(),
            400,
            Some("bad-request"),
        ),
        (
            "method_not_allowed(Bin)",
            Outcome::method_not_allowed(Resource::Bin),
            405,
            Some("method-not-allowed"),
        ),
        (
            "method_not_allowed(MaxSeq)",
            Outcome::method_not_allowed(Resource::MaxSeq),
            405,
            Some("method-not-allowed"),
        ),
        ("too_large", Outcome::too_large(), 413, Some("too-large")),
        ("internal", Outcome::internal(), 500, Some("internal")),
        (
            "unavailable",
            Outcome::unavailable(),
            503,
            Some("unavailable"),
        ),
    ]
}

fn public_cache_miss_row(
    name: &'static str,
    outcome: Outcome,
    directive: CacheControl,
) -> (&'static str, Outcome, u16, Option<&'static str>) {
    assert_eq!(outcome.status(), Status::NotFound, "{name}");
    assert_eq!(outcome.error(), Some(ErrorToken::NotFound), "{name}");
    assert_eq!(outcome.cache_control(), Some(directive), "{name}");
    assert_eq!(outcome.etag(), None, "{name}");
    assert!(outcome.body().is_empty(), "{name}");
    (name, outcome, 404, Some("not-found"))
}

/// Selected admission and authority response rows.
fn authority_outcome_rows() -> Vec<(&'static str, Outcome, u16, Option<&'static str>)> {
    vec![
        (
            "no_principal",
            Outcome::no_principal(),
            403,
            Some("no-principal"),
        ),
        (
            "not_enrolled",
            Outcome::not_enrolled(),
            403,
            Some("not-enrolled"),
        ),
        (
            "authority_managed",
            Outcome::authority_managed(),
            403,
            Some("authority-managed"),
        ),
        (
            "rate_limited",
            Outcome::rate_limited(30),
            429,
            Some("rate-limited"),
        ),
        (
            "publish_settled",
            Outcome::publish_settled(b"answer".to_vec()),
            200,
            None,
        ),
        (
            "publish_pending",
            Outcome::publish_pending(b"answer".to_vec()),
            202,
            None,
        ),
        (
            "volume_status",
            Outcome::volume_status(b"status".to_vec()),
            200,
            None,
        ),
        (
            "publish_conflict(StaleBase)",
            Outcome::publish_conflict(PublishConflict::StaleBase, b"answer".to_vec()),
            409,
            Some("stale-base"),
        ),
        (
            "publish_refused(Fenced)",
            Outcome::publish_refused(PublishRefusal::Fenced),
            503,
            Some("fenced"),
        ),
        (
            "publish_refused(RateLimited)",
            Outcome::publish_refused(PublishRefusal::RateLimited { retry_after: 2 }),
            429,
            Some("rate-limited"),
        ),
        (
            "status_refused(MethodNotAllowed)",
            Outcome::status_refused(StatusRefusal::MethodNotAllowed),
            405,
            Some("method-not-allowed"),
        ),
        (
            "enrollment_unavailable",
            Outcome::enrollment_unavailable(),
            503,
            Some("enrollment-unavailable"),
        ),
    ]
}

/// Render each fixture and check its status, token, and metadata.
#[test]
fn outcome_rows_render_their_status_token_and_metadata() {
    let rows = outcome_rows();
    assert_eq!(rows.len(), 38, "rendering fixture rows");

    for (name, outcome, status, expected) in rows {
        let is_refusal = outcome.status().is_refusal();
        let content_type = outcome.content_type().map(ContentType::as_str);
        let cache_control = outcome.cache_control().map(CacheControl::as_str);
        let allow = outcome.allow().map(Allow::as_str);
        let etag_value = outcome.etag().map(str::to_owned);
        let extent = outcome.extent();
        let retry_after = outcome.retry_after().map(|seconds| seconds.to_string());
        let answers_with_a_body = outcome.content_type().is_some();
        let body = outcome.body().to_vec();

        let response = render(outcome, Drain::Drained);
        assert_eq!(
            response.status().as_u16(),
            status,
            "{name}: the status is transcribed, never derived"
        );
        assert_eq!(token(&response).as_deref(), expected, "{name}");
        assert_eq!(
            token(&response).is_some(),
            is_refusal,
            "{name}: §8.2 puts the token on exactly the refusals"
        );
        assert_eq!(
            field(&response, &CONTENT_TYPE).as_deref(),
            content_type,
            "{name}"
        );
        if matches!(name, "not_found" | "unknown_target") {
            assert_eq!(field(&response, &CACHE_CONTROL), None, "{name}");
        }
        assert_eq!(
            field(&response, &CACHE_CONTROL).as_deref(),
            cache_control,
            "{name}"
        );
        assert_eq!(field(&response, &ALLOW).as_deref(), allow, "{name}");
        assert_eq!(field(&response, &ETAG), etag_value, "{name}");
        assert_eq!(field(&response, &RETRY_AFTER), retry_after, "{name}");
        assert_eq!(
            field(&response, &CONTENT_RANGE),
            extent.map(|extent| format!("bytes {}-{}/*", extent.first(), extent.last())),
            "{name}"
        );
        assert_eq!(
            field(&response, &CONNECTION),
            None,
            "{name}: the drained arm signals nothing"
        );
        assert_eq!(body_of(response), body, "{name}: the body is MOVED");
        // Publish's `409` is §8.3's one exception: its answer body is the
        // refusal's content, and it is the only refusal with a media type.
        if is_refusal && !answers_with_a_body {
            assert!(body.is_empty(), "{name}: §8.3/§8.4 — a refusal has no body");
        }
    }
}

/// The two rows the table above cannot state as data, spelled out:
/// the `405`'s `Allow` is the resource's own value and names no
/// `HEAD`, and the `206`'s `Content-Range` carries `*` for the
/// complete length.
#[test]
fn the_allow_and_the_content_range_are_spelled_exactly() {
    let refused = render(
        Outcome::method_not_allowed(Resource::MaxSeq),
        Drain::Drained,
    );
    assert_eq!(field(&refused, &ALLOW).as_deref(), Some("GET"));

    let bin = render(Outcome::method_not_allowed(Resource::Bin), Drain::Drained);
    assert_eq!(field(&bin, &ALLOW).as_deref(), Some("GET, PUT"));
    for response in [&refused, &bin] {
        let allow = field(response, &ALLOW).unwrap_or_default();
        assert!(!allow.contains("HEAD"), "§4.2: no Allow names HEAD");
    }

    let served = render(
        Outcome::bin_range(0, vec![0u8; 100]).unwrap_or_else(|| panic!("a 100-byte range")),
        Drain::Drained,
    );
    assert_eq!(
        field(&served, &CONTENT_RANGE).as_deref(),
        Some("bytes 0-99/*"),
        "§7.2: the complete length is literally `*`"
    );
    assert_eq!(served.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(field(&served, &ETAG), None, "§6: no ETag on a bin response");
}

/// §5.5's signal, and it is on EXACTLY the overflow arm.
#[test]
fn the_close_signal_is_on_exactly_the_overflowed_arm() {
    let torn = render(Outcome::unavailable(), Drain::Overflowed);
    assert_eq!(field(&torn, &CONNECTION).as_deref(), Some("close"));
    assert_eq!(torn.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(token(&torn).as_deref(), Some("unavailable"));

    let drained = render(Outcome::unavailable(), Drain::Drained);
    assert_eq!(
        field(&drained, &CONNECTION),
        None,
        "§5.5: a drained refusal signals nothing, and the connection stays usable"
    );
}

// -- the per-kind cap table ------------------------------------------

fn a_digest() -> [u8; DIGEST_LEN] {
    *GrainId::of(b"a bin").digest()
}

/// **Every operation's cap, and the two rows that are not a size.**
///
/// The five reads have NO cap because they have no content: their
/// stray content is drained, and giving them a cap would put a `413`
/// on an endpoint whose §5.x table has no such row. The hint's cap is
/// a `400` because §5.9's body has exactly one legal length, so
/// "too long" and "malformed" are one refusal — and a `413` there
/// would tell a client to retry smaller a body that has no smaller.
#[test]
fn every_operation_carries_the_cap_its_section_fixes() {
    let id = GrainId::of(b"an object");
    let rows: Vec<(&str, Operation<'_>, Option<BodyCap>)> = vec![
        (
            "PUT bin",
            Operation::PutBin { digest: a_digest() },
            Some(BodyCap {
                limit: BIN_MAX_BYTES,
                over: OverCap::TooLarge,
            }),
        ),
        (
            "PUT meta",
            Operation::PutMeta { volume: "v", id },
            Some(BodyCap {
                limit: META_MAX_BYTES,
                over: OverCap::TooLarge,
            }),
        ),
        (
            "PUT root",
            Operation::PutRoot {
                volume: granary_core::root::VolumeName::from_bytes(b"v").unwrap(),
                seq: 7,
            },
            Some(BodyCap {
                limit: ROOT_MAX_BYTES,
                over: OverCap::TooLarge,
            }),
        ),
        (
            "PUT hint",
            Operation::WriteHint { volume: "v" },
            Some(BodyCap {
                limit: 20,
                over: OverCap::BadRequest,
            }),
        ),
        (
            "GET bin",
            Operation::GetBinRange {
                digest: a_digest(),
                offset: 0,
                len: 1,
            },
            None,
        ),
        ("GET meta", Operation::GetMeta { volume: "v", id }, None),
        (
            "GET root",
            Operation::GetRoot {
                volume: granary_core::root::VolumeName::from_bytes(b"v").unwrap(),
                seq: 7,
            },
            None,
        ),
        ("GET max-seq", Operation::MaxSeq { volume: "v" }, None),
        (
            "GET hint",
            Operation::ReadHint {
                volume: "v",
                if_none_match: None,
            },
            None,
        ),
    ];
    assert_eq!(rows.len(), 9, "§4.2 defines nine operations");

    for (name, operation, expected) in rows {
        assert_eq!(write_cap(&operation), expected, "{name}");
    }

    // The hint's cap IS core's own constant, not a 20 written here.
    assert_eq!(
        u64::try_from(SEQ_KEY_DIGITS).unwrap_or(u64::MAX),
        20,
        "§5.9's body length"
    );
}

/// The refusal each `OverCap` renders, spelled where the wire can be
/// read: `413` + `too-large`, and `400` + `bad-request`.
#[test]
fn the_two_over_cap_refusals_render_their_own_status_and_token() {
    let too_large = BodyCap {
        limit: 1,
        over: OverCap::TooLarge,
    }
    .refusal();
    let rendered = render(too_large, Drain::Overflowed);
    assert_eq!(rendered.status().as_u16(), 413);
    assert_eq!(token(&rendered).as_deref(), Some("too-large"));

    let bad_request = BodyCap {
        limit: 20,
        over: OverCap::BadRequest,
    }
    .refusal();
    let rendered = render(bad_request, Drain::Overflowed);
    assert_eq!(rendered.status().as_u16(), 400);
    assert_eq!(token(&rendered).as_deref(), Some("bad-request"));
}

// -- the counting accept ---------------------------------------------

/// A budget nothing in a counting row can exhaust, so those rows
/// state something about the CAP and not about the charge.
fn ample() -> Arc<WriteBudget> {
    Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES))
}

/// The count is of BYTES THAT ARRIVED, and the boundary is where it
/// is said to be: the cap itself is inside it.
///
/// The declared length is deliberately absent from every row — the
/// bodies are `Full` and `Drip`, neither of which carries one — so
/// nothing here can pass by trusting a declaration.
#[tokio::test]
async fn the_accept_counts_framed_bytes_and_stops_at_the_cap() {
    let budget = ample();

    let at_the_cap = Full::new(Bytes::from(vec![0x11_u8; 64]));
    match accept_body(at_the_cap, 64, &mut budget.claim(), None).await {
        (Accepted::Body(content), counted) => {
            assert_eq!(content.len(), 64, "the cap is inside the cap");
            assert_eq!(counted, 64);
        }
        other => panic!("{other:?}"),
    }

    let one_over = Full::new(Bytes::from(vec![0x11_u8; 65]));
    assert!(matches!(
        accept_body(one_over, 64, &mut budget.claim(), None).await,
        (Accepted::TooLarge, _)
    ));

    // The SAME total in many frames, so the cap is a running count
    // and not a per-frame size check.
    let in_pieces = Drip::new(65, 1, Duration::ZERO);
    assert!(matches!(
        accept_body(in_pieces, 64, &mut budget.claim(), None).await,
        (Accepted::TooLarge, _)
    ));
    // 64 SEPARATE one-byte frames, isolated by a
    // before/after read of the process-wide counter around this one
    // call. `record_frame(arrived)` — this frame's own delta — and
    // `record_frame(counted)` — the running total so far — agree on
    // every SINGLE-frame row above, because a call's first frame
    // always has `counted == arrived`. They diverge only across
    // many frames in one call: the delta sums to exactly 64, while
    // re-adding the running total each time sums to 1+2+...+64 (or,
    // reading `counted` before its own update, 0+1+...+63) — either
    // way, far from 64.
    let before_inside = budget
        .request_bytes()
        .expect("not poisoned: ample() never overflows");
    let inside = Drip::new(64, 1, Duration::ZERO);
    assert!(matches!(
        accept_body(inside, 64, &mut budget.claim(), None).await,
        (Accepted::Body(_), _)
    ));
    let after_inside = budget
        .request_bytes()
        .expect("not poisoned: ample() never overflows");
    assert_eq!(
        after_inside - before_inside,
        64,
        "64 one-byte frames in ONE call must add exactly 64 to the \
         process-wide total — a running-total re-add would add far \
         more than the bytes that actually arrived"
    );

    // An empty body is a body, not a refusal — `PUT hint` with no
    // content is a `400` from the PARSER, and the difference matters
    // because the two carry different tokens.
    assert!(matches!(
        accept_body(Full::new(Bytes::new()), 20, &mut budget.claim(), None).await,
        (Accepted::Body(content), 0) if content.is_empty()
    ));

    assert_eq!(
        budget.in_flight(),
        0,
        "every claim above was dropped at the end of its statement"
    );
    // The process-wide total across every row above,
    // including the two REFUSED bodies — `one_over` (65, TooLarge as
    // a single frame) and `in_pieces` (65, TooLarge one byte at a
    // time). A `record_frame` moved after the cap check, or fired
    // only for `Accepted::Body`/`TransportRejected`, undercounts
    // exactly these two rows: 64 (at_the_cap) + 65 (one_over) + 65
    // (in_pieces) + 64 (inside) + 0 (empty) = 258.
    assert_eq!(
        budget.request_bytes(),
        Some(64 + 65 + 65 + 64),
        "the process-wide request-body total must include bytes from EVERY frame \
         that arrived, including the two refused bodies (one_over's 65 and \
         in_pieces' 65) — a refusal must not erase bytes that already landed"
    );
}

/// **What a write is charged is what it SENT, rounded up to one
/// granule and never past its cap.**
///
/// The rows are the boundaries: nothing sent is nothing charged, one
/// byte is one granule, the granule itself is one granule, one byte
/// past it is two — and a cap SMALLER than a granule is charged the
/// cap, because a `PUT hint`'s twenty octets have no larger form to
/// round up to and charging a granule for them would put the small
/// kinds back where the worst-case reservation had them.
#[test]
fn the_charge_is_the_granule_above_what_arrived_and_never_past_the_cap() {
    let granule = WRITE_BUDGET_GRANULE_BYTES;
    let bin = BIN_MAX_BYTES;

    assert_eq!(charge_target(0, bin), 0, "nothing sent is nothing charged");
    assert_eq!(charge_target(1, bin), granule);
    assert_eq!(charge_target(granule, bin), granule, "the boundary itself");
    assert_eq!(charge_target(granule + 1, bin), granule * 2);
    assert_eq!(charge_target(bin, bin), bin, "the cap is charged the cap");

    // A cap below a granule is never rounded past itself.
    let hint = u64::try_from(SEQ_KEY_DIGITS).unwrap_or(u64::MAX);
    assert!(hint < granule);
    assert_eq!(charge_target(1, hint), hint);
    assert_eq!(charge_target(hint, hint), hint);

    // A root is exactly one charge for its whole body, which is the
    // claim the granule's own doc makes about the small kinds.
    assert_eq!(charge_target(1, ROOT_MAX_BYTES), ROOT_MAX_BYTES);
    assert_eq!(
        charge_target(ROOT_MAX_BYTES, ROOT_MAX_BYTES),
        ROOT_MAX_BYTES
    );

    // The invariant the process bound rests on: the charge is never
    // below what has landed, at any size or cap.
    for counted in [0, 1, 2, granule - 1, granule, granule + 1, bin - 1, bin] {
        for limit in [hint, ROOT_MAX_BYTES, META_MAX_BYTES, bin] {
            if counted > limit {
                continue;
            }
            assert!(
                charge_target(counted, limit) >= counted,
                "counted {counted} under {limit} charged less than it holds"
            );
            assert!(charge_target(counted, limit) <= limit);
        }
    }
}

/// **A body whose charge is refused mid-stream STOPS being read**,
/// and the budget it did take comes back.
///
/// The discriminating shape is a body that starts inside the budget
/// and grows past it: a request refused before its first byte proves
/// only that a full budget refuses, which the up-front reservation
/// did too. What this row states is that the incremental charge is a
/// bound and not a best effort — the peer cannot get more than the
/// budget onto the heap by sending it a frame at a time.
#[tokio::test]
async fn a_body_that_outgrows_the_budget_mid_stream_is_shed_and_gives_it_back() {
    /// Four granules, delivered a frame at a time so the shed can
    /// land in the MIDDLE of the body rather than at its head.
    const PIECE: usize = 4096;
    let pieces = usize::try_from(WRITE_BUDGET_GRANULE_BYTES * 4).unwrap_or(usize::MAX) / PIECE;
    let total = pieces * PIECE;

    // Room for two granules and no more.
    let budget = Arc::new(WriteBudget::new(WRITE_BUDGET_GRANULE_BYTES * 2));
    let (shed, _counted) = {
        let mut charge = budget.claim();
        let accepted = accept_body(
            Drip::new(pieces, PIECE, Duration::ZERO),
            BIN_MAX_BYTES,
            &mut charge,
            None,
        )
        .await;
        assert!(
            charge.held() <= WRITE_BUDGET_GRANULE_BYTES * 2,
            "the charge never exceeded the budget it was taken from"
        );
        accepted
    };
    assert!(
        matches!(shed, Accepted::BudgetExhausted),
        "a body past the budget is shed, not accepted: {shed:?}"
    );
    assert_eq!(budget.in_flight(), 0, "and the charge came back");

    // The same body, under a budget that fits it: the shed above was
    // the budget and not the body.
    let ample = Arc::new(WriteBudget::new(WRITE_BUDGET_GRANULE_BYTES * 8));
    let (accepted, _counted) = accept_body(
        Drip::new(pieces, PIECE, Duration::ZERO),
        BIN_MAX_BYTES,
        &mut ample.claim(),
        None,
    )
    .await;
    assert!(matches!(accepted, Accepted::Body(content) if content.len() == total));
    assert_eq!(ample.in_flight(), 0);
}

// -- The process-wide request-byte counter ---------------------------

/// **Row (c): a fresh counter reads zero, per instance.**
///
/// Meaningful only because the counter is NOT a `static` — a global
/// would read whatever the previous row in this same test process
/// left, and this row would assert nothing.
#[test]
fn a_fresh_write_budget_reads_zero_request_bytes() {
    let budget = WriteBudget::new(WRITE_BODY_BUDGET_BYTES);
    assert_eq!(budget.request_bytes(), Some(0));
    assert_eq!(budget.requests_with_body(), 0);
}

/// **Row (d): the poison row.** A counter constructed at
/// `u64::MAX - 1` and fed 2 bytes must POISON — never wrap.
///
/// A plain `fetch_add` restarts near zero here, which is the
/// fail-open direction for an upper-bound gate; the two acceptable
/// shapes (a hand-written CAS loop, or `fetch_add` plus a sticky
/// flag read off the returned previous value) both refuse to let
/// that happen. This row is what tells the two apart.
#[test]
fn the_request_byte_counter_poisons_rather_than_wraps_on_overflow() {
    let budget = WriteBudget::new_with_request_bytes(WRITE_BODY_BUDGET_BYTES, u64::MAX - 1);
    budget.record_frame(2);
    assert_eq!(
        budget.request_bytes(),
        None,
        "an overflowing add must poison, not wrap: {:?}",
        budget.request_bytes()
    );
}

/// A body that hands over `good` as ONE data frame, then a
/// TRANSPORT error — the shape a peer's connection resetting
/// mid-body produces, and `Drip`'s `Error = Infallible` cannot
/// make.
struct BrokenAfter {
    good: Option<Bytes>,
    broke: bool,
}

impl BrokenAfter {
    fn new(good: Vec<u8>) -> Self {
        Self {
            good: Some(Bytes::from(good)),
            broke: false,
        }
    }
}

impl Body for BrokenAfter {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.good.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if !this.broke {
            this.broke = true;
            return Poll::Ready(Some(Err(std::io::Error::other(
                "connection reset mid-body",
            ))));
        }
        Poll::Ready(None)
    }
}

/// **Row (a): a request of known body length leaves the counter
/// holding exactly that many request bytes.**
#[tokio::test]
async fn a_known_length_body_leaves_the_process_counter_holding_exactly_its_length() {
    let budget = Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES));
    let body = Full::new(Bytes::from(vec![0x44_u8; 4096]));
    let mut charge = budget.claim();
    let (accepted, counted) = accept_body(body, WRITE_BODY_BUDGET_BYTES, &mut charge, None).await;
    assert!(matches!(accepted, Accepted::Body(_)), "{accepted:?}");
    assert_eq!(counted, 4096, "the per-request return value");
    assert_eq!(budget.request_bytes(), Some(4096), "the process-wide total");
    assert_eq!(budget.requests_with_body(), 1);
}

/// **Reset-then-retry counts BOTH attempts, including bytes
/// from the body that ended in a frame error.**
///
/// A body that yields `k` bytes and then a frame error
/// (`Accepted::TransportRejected`), followed by a COMPLETE `n`-byte
/// body on a fresh `accept_body` call against the SAME process
/// budget — the shape `HttpStore::send`'s one retry produces at the
/// server. The counter must hold `k + n`, never `n` alone: a counter
/// that exports only completed `Accepted::Body` totals loses the
/// first attempt, which is an UNDERCOUNT and therefore the fail-open
/// direction for an upper-bound gate.
#[tokio::test]
async fn reset_then_retry_counts_both_attempts() {
    let budget = Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES));

    let k = 100_usize;
    let broken = BrokenAfter::new(vec![0x22_u8; k]);
    let mut first_charge = budget.claim();
    let (first, first_counted) =
        accept_body(broken, WRITE_BODY_BUDGET_BYTES, &mut first_charge, None).await;
    assert!(matches!(first, Accepted::TransportRejected), "{first:?}");
    assert_eq!(first_counted, k as u64);

    let n = 250_usize;
    let complete = Full::new(Bytes::from(vec![0x33_u8; n]));
    let mut second_charge = budget.claim();
    let (second, second_counted) =
        accept_body(complete, WRITE_BODY_BUDGET_BYTES, &mut second_charge, None).await;
    assert!(matches!(second, Accepted::Body(_)), "{second:?}");
    assert_eq!(second_counted, n as u64);

    assert_eq!(
        budget.request_bytes(),
        Some(u64::try_from(k + n).unwrap_or(u64::MAX)),
        "the process-wide total must be k+n — losing the first \
         attempt is the undercount this test refuses"
    );
    assert_eq!(
        budget.requests_with_body(),
        2,
        "two separate accept_body calls, two counted requests"
    );
}

// -- the write-body budget -------------------------------------------

/// **The budget refuses, and — the half a shed cannot be trusted
/// without — it RELEASES.**
///
/// The park-proof property is the second one: a reservation taken
/// up front and released by a matched call is one early `return`
/// away from a budget that only ever fills, and a server whose write
/// path stops working after N requests forever looks exactly like a
/// server under load.
#[test]
fn the_budget_refuses_at_the_limit_and_returns_to_zero() {
    let budget = Arc::new(WriteBudget::new(100));
    assert_eq!(budget.in_flight(), 0);

    let first = budget
        .reserve(60)
        .unwrap_or_else(|| panic!("60 of 100 must fit"));
    assert_eq!(budget.in_flight(), 60);
    assert!(
        budget.reserve(60).is_none(),
        "the second 60 must be shed, not queued"
    );

    let second = budget
        .reserve(40)
        .unwrap_or_else(|| panic!("40 fills the budget exactly"));
    assert_eq!(budget.in_flight(), 100, "the limit itself is inside it");
    assert!(budget.reserve(1).is_none(), "and one byte more is not");

    drop(first);
    assert_eq!(
        budget.in_flight(),
        40,
        "a release is a release of ITS OWN size"
    );
    let third = budget
        .reserve(60)
        .unwrap_or_else(|| panic!("the released room must be reusable"));
    drop(second);
    drop(third);
    assert_eq!(
        budget.in_flight(),
        0,
        "every reservation released: the budget is park-proof"
    );

    // A reservation larger than the whole budget is shed rather than
    // wrapping into room.
    assert!(Arc::new(WriteBudget::new(10)).reserve(u64::MAX).is_none());
    let near_max = Arc::new(WriteBudget::new(u64::MAX));
    let held = near_max
        .reserve(u64::MAX - 1)
        .unwrap_or_else(|| panic!("inside the limit"));
    assert!(
        near_max.reserve(2).is_none(),
        "a checked add: the overflow must refuse, never wrap to room"
    );
    drop(held);
}

/// **The reservation is ATOMIC, and only real contention can say
/// so.**
///
/// Every other budget row calls `reserve` from one thread, and a
/// read-then-write — load the count, decide, store the sum — answers
/// all of them identically: single-threaded, the value cannot change
/// between the load and the store. Under contention it can, and then
/// every racer reads the same room and every racer takes it, so a
/// budget sized for one maximal bin admits eight of them and the
/// process-wide write-body bound is gone.
///
/// So the shape here is the one that separates the two: a budget
/// with room for exactly ONE maximal reservation, racers released
/// together by a barrier, and the winners COUNTED. The winner holds
/// its reservation until every racer has answered — a winner that
/// released early would let a slow loser win honestly, and the count
/// would then say two without anything being wrong.
#[test]
fn racing_reservations_cannot_both_take_the_last_of_the_budget() {
    /// Enough racers that a lost update is near-certain rather than
    /// merely possible.
    const RACERS: usize = 8;
    /// Enough rounds that a narrow load/store window is still hit.
    const ROUNDS: usize = 200;

    // Room for one maximal bin: the second reservation of this size
    // must be shed, whoever asks and whenever.
    let budget = Arc::new(WriteBudget::new(BIN_MAX_BYTES));

    for round in 0..ROUNDS {
        let winners = AtomicUsize::new(0);
        let gate = Barrier::new(RACERS);
        let budget = &budget;
        std::thread::scope(|scope| {
            for _ in 0..RACERS {
                let winners = &winners;
                let gate = &gate;
                scope.spawn(move || {
                    // Every racer arrives at `reserve` together.
                    gate.wait();
                    let reserved = budget.reserve(BIN_MAX_BYTES);
                    if reserved.is_some() {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                    // Held across this second rendezvous, so no
                    // loser was refused by a budget that had already
                    // been given back.
                    gate.wait();
                    drop(reserved);
                });
            }
        });

        assert_eq!(
            winners.load(Ordering::Relaxed),
            1,
            "round {round}: {RACERS} racers asked for the one \
             reservation the budget holds and more than one was \
             admitted — the reservation is not atomic, so the \
             process bound is not a bound"
        );
        assert_eq!(
            budget.in_flight(),
            0,
            "round {round}: the winner released, so the next round \
             races an empty budget"
        );
    }
}

/// The production figures, pinned where a reader can run them.
///
/// **The two capacity figures are read together or neither is true.**
/// Two gibibytes admits eight concurrent MAXIMAL bins, and the same
/// two gibibytes admits thirty-two thousand writes that have a
/// granule on the wire — because the charge is what arrived. Charged
/// a maximal bin per write instead, two gibibytes would admit eight
/// writes, not thirty-two thousand.
///
/// **And the clock ordering, which is the surprising one.** The
/// accept clock a shipped server runs is LONGER than the transport's
/// drain deadline. That is not an oversight to be fixed by moving
/// either constant — it is why the accept races the drain — so it is
/// pinned here where a reader meets it rather than left to be
/// rediscovered.
#[test]
fn the_shipped_write_bounds_are_the_figures_the_adr_records() {
    assert_eq!(WRITE_BODY_BUDGET_BYTES, 2 * 1024 * 1024 * 1024);
    assert_eq!(
        WRITE_BODY_BUDGET_BYTES / BIN_MAX_BYTES,
        8,
        "eight concurrent MAXIMAL bins"
    );
    assert_eq!(WRITE_BUDGET_GRANULE_BYTES, 64 * 1024);
    assert_eq!(
        WRITE_BODY_BUDGET_BYTES / WRITE_BUDGET_GRANULE_BYTES,
        32_768,
        "and thirty-two thousand writes that have sent a granule each"
    );
    assert_eq!(WRITE_ACCEPT_MAX_WAIT_SHIPPED, Duration::from_secs(30));
    assert!(
        WRITE_ACCEPT_MAX_WAIT <= WRITE_ACCEPT_MAX_WAIT_SHIPPED,
        "the test substitution may only be SHORTER"
    );
    assert!(
        WRITE_ACCEPT_MAX_WAIT_SHIPPED > DRAIN_MAX_WAIT,
        "the accept covers real content and the drain covers a refusal \
         body; a drain-sized accept refuses every large bin"
    );
    assert!(
        WRITE_ACCEPT_MAX_WAIT_SHIPPED > SHUTDOWN_DEADLINE,
        "the accept OUTLASTS the drain deadline, which is why an accept \
         in flight is abandoned on the drain rather than run to this \
         clock; a value that made this false would silently retire the \
         race that carries it"
    );
    assert_eq!(VERIFY_PERMIT_MAX_WAIT, Duration::from_secs(5));
    assert!(
        VERIFY_PERMIT_MAX_WAIT < WRITE_ACCEPT_MAX_WAIT_SHIPPED,
        "the queue bound is not the upload bound"
    );
}

// -- the verify permit -----------------------------------------------

/// **The sizing, at every worker count that changes the answer.**
///
/// `workers - 1`, floored at one and capped at four. The rows that
/// matter are the two ends: on a two-worker runtime the answer must
/// be ONE, because two permits there let two verifies occupy both
/// workers and nothing is left to answer a read — and on a large
/// host it must stop at the cap rather than scaling, because
/// verification is bounded work and the permit exists to leave the
/// runtime alive, not to schedule the machine.
#[test]
fn the_verify_permit_count_always_leaves_a_worker_free() {
    assert_eq!(verify_permits(0), 1, "a floor, never zero permits");
    assert_eq!(verify_permits(1), 1, "one worker: no count frees one");
    assert_eq!(verify_permits(2), 1, "NOT two — that occupies both");
    assert_eq!(verify_permits(3), 2);
    assert_eq!(verify_permits(5), 4);
    assert_eq!(verify_permits(64), VERIFY_PERMITS_MAX, "capped, not scaled");
    for workers in 2_usize..=64 {
        assert!(
            verify_permits(workers) < workers,
            "{workers} workers: a permit count that does not leave one \
             free is not a bound on anything"
        );
    }
    // The composition root's own figure is a real one.
    assert!(worker_threads() >= 1);
}

/// **The three process-wide handles are SHARED across clones, and
/// the accept loop clones one service per connection.**
///
/// A `WriteBudget::new(..)`, a `Semaphore::new(..)` or a
/// `watch::channel(..)` in `Clone` would compile and would pass every
/// single-connection row in this file, while giving each connection
/// its own — which for the two bounds is not a larger bound but
/// none, and for the drain level is a server where one shutdown
/// reaches one connection.
#[tokio::test]
async fn the_budget_the_permit_and_the_drain_are_shared_across_connection_clones() {
    let service = GrainService::for_test(
        Arc::new(FakeSeam::default()),
        "",
        VerifyPolicy::verifying(),
        Some(DECLARED_MAX_EXTENT),
        100,
        100,
        VERIFY_PERMIT_MAX_WAIT,
        None,
    );
    let connection = service.clone();
    let another = connection.clone();

    assert!(
        Arc::ptr_eq(service.write_budget(), another.write_budget()),
        "a clone of a clone must charge the same budget"
    );

    // Reserved through ONE connection's handle, observed through
    // another's.
    let held = connection
        .write_budget()
        .reserve(100)
        .unwrap_or_else(|| panic!("the whole budget"));
    assert_eq!(service.write_budget().in_flight(), 100);
    assert!(
        another.write_budget().reserve(1).is_none(),
        "a second connection must see the budget the first filled"
    );
    drop(held);
    assert_eq!(another.write_budget().in_flight(), 0);

    // The same for the permit: acquired on one clone, gone on every
    // other.
    let permits = verify_permits(TEST_WORKER_THREADS);
    assert_eq!(service.verify_permits_available(), permits);
    let mut taken = Vec::new();
    for _ in 0..permits {
        taken.push(
            connection
                .verify_permits
                .try_acquire()
                .unwrap_or_else(|e| panic!("{e}")),
        );
    }
    assert_eq!(
        another.verify_permits_available(),
        0,
        "a per-service permit would leave this handle reading a full \
         semaphore while every connection verified"
    );
    drop(taken);
    assert_eq!(
        service.verify_permits_available(),
        permits,
        "and the permits return"
    );

    // The read budget and read permits, the same way. A `ReadBudget::new(..)` or a second
    // `Semaphore::new(READ_PERMITS)` in `Clone` gives every
    // connection its own read allowance — which is the unbounded
    // aggregate both fields exist to remove, restored by a line that
    // compiles and passes every single-connection row.
    assert!(
        Arc::ptr_eq(service.read_budget(), another.read_budget()),
        "a clone of a clone must charge the same READ budget"
    );
    let read_held = connection
        .read_budget()
        .take(100)
        .unwrap_or_else(|| panic!("the whole read budget"));
    assert_eq!(service.read_budget().in_flight(), 100);
    assert!(
        another.read_budget().take(1).is_none(),
        "a second connection must see the read budget the first filled"
    );
    drop(read_held);
    assert_eq!(another.read_budget().in_flight(), 0);

    assert!(
        Arc::ptr_eq(service.read_permits_handle(), another.read_permits_handle()),
        "a clone of a clone must queue on the same read permit"
    );
    let mut read_taken = Vec::new();
    for _ in 0..READ_PERMITS {
        read_taken.push(
            connection
                .read_permits
                .try_acquire()
                .unwrap_or_else(|e| panic!("{e}")),
        );
    }
    assert_eq!(
        another.read_permits_available(),
        0,
        "a per-service read permit would leave this handle reading a \
         full semaphore while every connection was inside the store"
    );
    drop(read_taken);
    assert_eq!(service.read_permits_available(), READ_PERMITS);

    // And the drain level: raised through the handle a composition
    // root takes from ONE service value, observed on a clone of a
    // clone — which is the only shape that matters, because that is
    // what a connection is holding.
    let mut watched = another.draining.subscribe();
    assert!(!*watched.borrow_and_update(), "nothing has begun yet");
    service.draining().begin();
    assert!(
        watched.changed().await.is_ok() && *watched.borrow(),
        "a clone must hear the drain the composition root began"
    );
}

/// The handle-to-COUNTER linkage, driven end to
/// end through the real service — every counting row up to this one
/// (`the_accept_counts_framed_bytes_and_stops_at_the_cap` included)
/// shares one hand-built `WriteBudget` and reads it back DIRECTLY,
/// so none of them can tell [`GrainService::wire_bytes`] apart from
/// one that clones a FRESH budget, [`WireByteHandle::totals`] apart
/// from one that hardcodes `request_bytes: Some(0)`, or the write
/// path's own `bounds.budget.claim()` apart from a throwaway
/// counter charged instead of the shared one — every one of those
/// compiles, and every existing row would still pass it.
///
/// This row drives one real write through [`answer`] with `Bounds`
/// built from a live [`GrainService`]'s own fields (`through`'s own
/// pattern), then reads the total through the PUBLIC door a
/// composition root actually uses at shutdown: `service.wire_bytes()`.
#[tokio::test]
async fn the_public_wire_bytes_handle_reads_what_the_service_actually_served() {
    let service = GrainService::for_test(
        Arc::new(FakeSeam::default()),
        "",
        VerifyPolicy::seam_only(),
        Some(DECLARED_MAX_EXTENT),
        WRITE_BODY_BUDGET_BYTES,
        READ_BODY_BUDGET_BYTES,
        VERIFY_PERMIT_MAX_WAIT,
        None,
    );

    let body = b"a root this service really holds, end to end".to_vec();
    let sent = u64::try_from(body.len()).unwrap_or(0);
    let target = format!("/volume/t/root/{}", seq_key(41));

    let bounds = Bounds {
        capture: None,
        debug_grants: None,
        authority: None,
        budget: &service.write_budget,
        read_budget: &service.read_budget,
        permits: &service.verify_permits,
        read_permits: &service.read_permits,
        permit_wait: service.permit_wait,
        dispatch_deadline: service.dispatch_deadline,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: service.test_reply_deadline,
        draining: service.draining.subscribe(),
    };
    let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
    let response = answer(
        &*service.store,
        &service.base,
        service.policy,
        service.max_extent,
        bounds,
        &Method::PUT,
        &uri,
        &HeaderMap::new(),
        &hyper::http::Extensions::new(),
        Some(sent),
        Full::new(Bytes::from(body)),
        &mut None,
        &mut None,
        &mut None,
    )
    .await;
    assert!(
        response.status().is_success(),
        "the write must actually land for this row to state anything \
         about what got counted: {:?}",
        response.status()
    );

    assert_eq!(
        service.wire_bytes().totals().request_bytes,
        Some(sent),
        "GrainService::wire_bytes() — the same handle a composition \
         root reads at shutdown — must report the bytes THIS request \
         sent, read through WireByteHandle::totals() and not through \
         any test-only local counter"
    );
}

/// **An admission-refused body is still
/// a body that arrived, and the process-wide counter must hold it.**
///
/// `DELETE` on a `root` target is refused by `admit_declaring`
/// BEFORE `write_cap` is even consulted — `answer`'s own
/// `Err(refusal)` arm — so this request's content is read by
/// `drain_to_budget`, never by `accept_body`. A `WriteBudget` fed
/// only from `accept_body`'s loop reads `Some(0)` here even though
/// 4096 bytes crossed the wire and were read off it; that is the
/// undercount `record_frame`'s own doc calls the fail-open
/// direction, and it is not the declared-length fast path — this
/// arm reads every one of those bytes before answering.
#[tokio::test]
async fn an_admission_refused_body_is_still_counted() {
    let service = GrainService::for_test(
        Arc::new(FakeSeam::default()),
        "",
        VerifyPolicy::seam_only(),
        Some(DECLARED_MAX_EXTENT),
        WRITE_BODY_BUDGET_BYTES,
        READ_BODY_BUDGET_BYTES,
        VERIFY_PERMIT_MAX_WAIT,
        None,
    );

    let body = vec![0x99_u8; 4096];
    let sent = u64::try_from(body.len()).unwrap_or(0);
    let target = format!("/volume/t/root/{}", seq_key(41));

    let bounds = Bounds {
        capture: None,
        debug_grants: None,
        authority: None,
        budget: &service.write_budget,
        read_budget: &service.read_budget,
        permits: &service.verify_permits,
        read_permits: &service.read_permits,
        permit_wait: service.permit_wait,
        dispatch_deadline: service.dispatch_deadline,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: service.test_reply_deadline,
        draining: service.draining.subscribe(),
    };
    let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
    let response = answer(
        &*service.store,
        &service.base,
        service.policy,
        service.max_extent,
        bounds,
        &Method::DELETE,
        &uri,
        &HeaderMap::new(),
        &hyper::http::Extensions::new(),
        Some(sent),
        Full::new(Bytes::from(body)),
        &mut None,
        &mut None,
        &mut None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "DELETE on `root` is refused at admission, before write_cap \
         is ever consulted — accept_body never runs for this request"
    );

    assert_eq!(
        service.wire_bytes().totals().request_bytes,
        Some(sent),
        "the refused request's 4096 bytes were read off the wire by \
         drain_to_budget and must be counted just as accept_body's \
         own frames are — an admission refusal must not erase bytes \
         that already arrived"
    );
}

/// **The drain race abandons, and only on a drain.**
///
/// Three rows, and the third is the one a level-blind implementation
/// fails: a request that ARRIVES after the drain began must be
/// abandoned too, and it will never see a `changed()` edge because
/// the edge happened before it subscribed. Reading the level on
/// entry is what covers it.
#[tokio::test]
async fn the_drain_race_abandons_a_pending_future_and_nothing_else() {
    let (drain, mut watched) = watch::channel(false);

    // Nothing draining: the future's own answer comes back.
    assert_eq!(
        until_draining(&mut watched, std::future::ready(7_u8)).await,
        Some(7)
    );

    // Draining mid-await: a future that would never finish is
    // abandoned, which is the whole mechanism.
    let parked = std::future::pending::<u8>();
    let raced = std::pin::pin!(until_draining(&mut watched, parked));
    let begun = std::pin::pin!(async {
        let _observed = drain.send(true);
    });
    let (abandoned, ()) = {
        let mut raced = raced;
        let mut begun = begun;
        let mut sent = false;
        std::future::poll_fn(move |context| {
            if !sent && begun.as_mut().poll(context).is_ready() {
                sent = true;
            }
            raced.as_mut().poll(context).map(|value| (value, ()))
        })
        .await
    };
    assert_eq!(abandoned, None, "a drain abandons the future it wraps");

    // Arriving AFTER the drain began, with the edge already spent: a
    // fresh receiver reads the LEVEL and is abandoned at once.
    let mut latecomer = drain.subscribe();
    assert_eq!(
        until_draining(&mut latecomer, std::future::ready(7_u8)).await,
        None,
        "a request that arrived during the drain must not run its \
         clock out; its `changed()` edge is already spent"
    );

    // Every sender gone is a drain, not silence: read the other way
    // this would spin on an immediately-erroring `changed()`.
    let (gone, mut orphan) = watch::channel(false);
    drop(gone);
    assert_eq!(
        until_draining(&mut orphan, std::future::pending::<u8>()).await,
        None
    );
}

// -- §5.5: the drain -------------------------------------------------

/// A body that hands over `frames` chunks of `size` bytes, waiting
/// `gap` before each one.
///
/// **The wait is a bounded await and never a sleep.** `sleep` is
/// banned in this workspace and `timeout` deliberately is not, so
/// the pause is a timeout around a future that never completes —
/// which is the same clock with none of the seam's meaning.
struct Drip {
    frames: usize,
    size: usize,
    gap: Duration,
    /// How many frames this body has HANDED OVER. A test cannot read
    /// a clock — `Instant::now` is the `Clock` seam's and is banned —
    /// so the count of frames a drain accepted before it returned is
    /// how long it ran, in units of `gap`.
    delivered: Arc<AtomicUsize>,
    waiting: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl Drip {
    fn new(frames: usize, size: usize, gap: Duration) -> Self {
        Self {
            frames,
            size,
            gap,
            delivered: Arc::new(AtomicUsize::new(0)),
            waiting: None,
        }
    }

    /// A handle on the delivered count, taken before the body is
    /// MOVED into the drain.
    fn delivered(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.delivered)
    }
}

impl Body for Drip {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if this.frames == 0 {
            return Poll::Ready(None);
        }
        let gap = this.gap;
        let waiting = this.waiting.get_or_insert_with(|| {
            Box::pin(async move {
                let _expired = tokio::time::timeout(gap, std::future::pending::<()>()).await;
            })
        });
        match waiting.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                this.waiting = None;
                this.frames -= 1;
                this.delivered.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![0x5a; this.size])))))
            }
        }
    }
}

/// Content that ends inside the budget is DRAINED, and the boundary
/// is where it is said to be: exactly the budget is inside it.
#[tokio::test]
async fn content_inside_the_budget_drains() {
    let budget = ample();
    let empty = Full::new(Bytes::new());
    assert_eq!(
        drain_to_budget(empty, &budget).await,
        Drain::Drained,
        "no content"
    );

    let exact = usize::try_from(DRAIN_BUDGET_BYTES).unwrap_or(usize::MAX);
    let at_the_boundary = Full::new(Bytes::from(vec![0u8; exact]));
    assert_eq!(
        drain_to_budget(at_the_boundary, &budget).await,
        Drain::Drained,
        "the budget itself is inside the budget"
    );

    // Many small frames summing to the budget: the count is over the
    // whole content and not per frame.
    let in_pieces = Drip::new(64, exact / 64, Duration::ZERO);
    assert_eq!(drain_to_budget(in_pieces, &budget).await, Drain::Drained);
}

/// One byte past the budget is the OVERFLOW arm, whichever shape the
/// content arrives in.
#[tokio::test]
async fn content_past_the_budget_overflows() {
    let budget = ample();
    let over = usize::try_from(DRAIN_BUDGET_BYTES.saturating_add(1)).unwrap_or(usize::MAX);
    let one_frame = Full::new(Bytes::from(vec![0u8; over]));
    assert_eq!(drain_to_budget(one_frame, &budget).await, Drain::Overflowed);

    // The same total in pieces, so the budget is a count and not a
    // per-frame size check.
    let in_pieces = Drip::new(65, 1024, Duration::ZERO);
    assert_eq!(drain_to_budget(in_pieces, &budget).await, Drain::Overflowed);
}

/// **The slow-drip discriminator: ONE clock for the whole drain.**
///
/// A body that hands over a small frame every so often, far under
/// the byte budget, forever. A timeout re-armed per frame read never
/// fires — every frame lands inside its own window — so the drain
/// runs until the peer stops, which is the tarpit the bound exists
/// to exclude. A timeout around the whole loop fires at
/// [`DRAIN_MAX_WAIT`].
///
/// The outer bound is what makes the row FAIL rather than hang
/// against the per-frame implementation.
#[tokio::test]
async fn a_slow_drip_under_the_budget_overflows_on_the_clock() {
    let budget = ample();
    let gap = DRAIN_MAX_WAIT / 8;
    // 64 frames × 64 bytes is 4 KiB, an order of magnitude under the
    // budget, and 64 gaps is four times the whole-drain bound.
    let drip = Drip::new(64, 64, gap);
    let bound = DRAIN_MAX_WAIT.saturating_mul(4);
    match tokio::time::timeout(bound, drain_to_budget(drip, &budget)).await {
        Ok(drain) => assert_eq!(
            drain,
            Drain::Overflowed,
            "the clock, not the byte budget, must take the overflow arm"
        ),
        Err(elapsed) => panic!(
            "the drain was still running after {bound:?} ({elapsed}): the \
             bound is armed per frame, so a dripping peer never trips it"
        ),
    }
}

/// **The FAST drip: a per-frame clock is wrong at every window, not
/// only at [`DRAIN_MAX_WAIT`].**
///
/// The row above pins the overflow ARM against gaps wider than a
/// per-frame window would be. It says nothing about WHEN the arm was
/// taken, so a per-frame bound narrow enough to fire on its own first
/// read passes it. This row closes that by pinning how long the drain
/// ran, measured in the only unit available here: the frames the
/// peer got to hand over before the drain returned. No clock is read
/// — `Instant::now` is the `Clock` seam's — and none is needed.
///
/// The gap is a fortieth of the whole-drain bound and the content is
/// 256 × 16 bytes, three orders of magnitude under the byte budget,
/// so only a clock can end this drain and the peer offers roughly six
/// times as much dripping as the bound allows.
///
/// **Why those two counts.** One clock for the whole drain stops it
/// after about `DRAIN_MAX_WAIT / gap` = 40 frames, and it can never
/// exceed that, because a frame costs a gap. A per-frame window is
/// then wrong in one of exactly two observable ways: a window at or
/// above the gap never fires and every one of the 256 frames is
/// drained, and a window below the gap fires on the first read with
/// ZERO frames delivered. The lower bound of 8 (a fifth of the
/// expected count, a machine five times slower than one that keeps
/// up) rules out the second; the upper bound of 200, and the outer
/// deadline that keeps this row failing rather than hanging, rule out
/// the first. Both bounds are far outside anything scheduling jitter
/// moves, because jitter costs frames one at a time and the room is
/// 32 of them either way.
#[tokio::test]
async fn a_fast_drip_overflows_on_the_whole_wait_and_not_before() {
    let budget = ample();
    let gap = DRAIN_MAX_WAIT / 40;
    let drip = Drip::new(256, 16, gap);
    let delivered = drip.delivered();
    let bound = DRAIN_MAX_WAIT.saturating_mul(4);
    match tokio::time::timeout(bound, drain_to_budget(drip, &budget)).await {
        Ok(drain) => assert_eq!(
            drain,
            Drain::Overflowed,
            "the clock, not the byte budget, must take the overflow arm"
        ),
        Err(elapsed) => panic!(
            "the drain was still running after {bound:?} ({elapsed}): a \
             window at or above the gap never fires, so the peer drips on"
        ),
    }
    let count = delivered.load(Ordering::Relaxed);
    assert!(
        (8..=200).contains(&count),
        "{count} frames of {gap:?} were drained: the whole-drain bound is \
         {DRAIN_MAX_WAIT:?}, so a count at the floor means a clock that \
         fired per read and a count at the ceiling means one that never did"
    );
}

// -- the dispatch deadline --------------------------------------------

/// A seam that NEVER answers. Every method parks forever, which is
/// what a network store that has stopped answering looks like from
/// this layer — not an `Err`, which the handlers already have a
/// status for, but a future that is never `Ready`.
#[derive(Debug, Default)]
struct StalledSeam;

impl RootStore for StalledSeam {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        std::future::pending().await
    }
    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        std::future::pending().await
    }
    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        std::future::pending().await
    }
    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        std::future::pending().await
    }
    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        std::future::pending().await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

impl BinStore for StalledSeam {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        std::future::pending().await
    }
    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        std::future::pending().await
    }
    async fn get_meta(&self, _volume: &str, _id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        std::future::pending().await
    }
    async fn get_bin_range(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        std::future::pending().await
    }
}

/// Sixty-four lowercase hex digits, which is what §4.3's
/// `{grain-id}` and `{digest}` productions accept.
fn hex64(digest: &[u8; DIGEST_LEN]) -> String {
    let mut out = String::with_capacity(DIGEST_LEN * 2);
    for byte in digest {
        for nibble in [byte >> 4, byte & 0x0F] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    out
}

/// One request through the WHOLE adapter path — `answer`, so both
/// the read arm and the accept arm are the shipped ones — against a
/// store that never answers.
async fn against_stalled(
    dispatch_deadline: Option<Duration>,
    draining: watch::Receiver<bool>,
    method: &Method,
    target: &str,
    range: Option<&str>,
    body: Vec<u8>,
) -> Response<Full<Bytes>> {
    let store = StalledSeam;
    let budget = Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES));
    let read_budget = Arc::new(ReadBudget::new(READ_BODY_BUDGET_BYTES));
    let permits = Semaphore::new(verify_permits(TEST_WORKER_THREADS));
    let read_permits = Semaphore::new(READ_PERMITS);
    // The receiver comes from the CALLER, which is what lets a row
    // raise the level mid-request. Its sender must outlive the await:
    // dropping it closes the channel, and a closed drain level is a
    // different state from a process that is simply not draining.
    let bounds = Bounds {
        capture: None,
        debug_grants: None,
        authority: None,
        budget: &budget,
        read_budget: &read_budget,
        permits: &permits,
        read_permits: &read_permits,
        permit_wait: VERIFY_PERMIT_MAX_WAIT,
        dispatch_deadline,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: None,
        draining,
    };
    let mut headers = HeaderMap::new();
    if let Some(range) = range {
        let value = HeaderValue::from_str(range).unwrap_or_else(|e| panic!("{range:?}: {e}"));
        let _replaced = headers.insert(RANGE, value);
    }
    let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
    let declared = u64::try_from(body.len()).unwrap_or(u64::MAX);
    answer(
        &store,
        "",
        // SEAM-ONLY, so the row is about the DEADLINE and not about
        // whether a body verifies: a verifying policy would refuse
        // this content before the seam was ever reached.
        VerifyPolicy::seam_only(),
        Some(DECLARED_MAX_EXTENT),
        bounds,
        method,
        &uri,
        &headers,
        &hyper::http::Extensions::new(),
        Some(declared),
        Full::new(Bytes::from(body)),
        &mut None,
        &mut None,
        &mut None,
    )
    .await
}

/// **A store that stops answering must not take the request
/// with it — and the answer is a STATUS, not a dropped connection.**
///
/// **Both arms, because a deadline on writes alone bounds nothing
/// that matters.** A `GET` is the cheapest request an
/// unauthenticated peer can make, and until this landed the read
/// path awaited the seam with no clock at all — so a bucket that
/// went quiet would have held every reading connection open
/// indefinitely while every write was answered inside thirty
/// seconds.
///
/// **The park proof comes FIRST and it is `None`.** Without it the
/// two `503`s below are consistent with a store that failed
/// instantly for some unrelated reason, and the row would pass with
/// no timeout in the code at all. `None` hanging past a bound is
/// what makes "this store never answers" a measured fact rather than
/// an assumption — and it is simultaneously the assertion that a
/// `None` deadline does NOT time out, which is the memory-store
/// contract.
#[tokio::test]
async fn a_stalled_network_store_times_out_to_503_unavailable() {
    // Held for the whole row: this one never fires, so every arm
    // below is about the DEADLINE and not about the drain race.
    let (never_drains, _watched) = watch::channel(false);
    let digest = [0xAA_u8; DIGEST_LEN];
    let read_target = format!("/bin/{}", hex64(&digest));
    let write_body = b"a meta object the store will never accept".to_vec();
    // `{grain-id}` is the ALGORITHM-QUALIFIED form (§4.3):
    // `blake3:` + 64 lowercase hex. Bare hex is a `404`, which is
    // exactly what the park proof caught when this line had it.
    let write_target = format!("/volume/t/meta/{}", GrainId::of(&write_body));

    // 1 — PARK PROOF, both arms. `None` is the memory-store setting,
    // and against this store it must hang rather than answer.
    let parked_read = timeout(
        Duration::from_millis(200),
        against_stalled(
            None,
            never_drains.subscribe(),
            &Method::GET,
            &read_target,
            Some("bytes=0-15"),
            Vec::new(),
        ),
    )
    .await;
    assert!(
        parked_read.is_err(),
        "an unbounded READ against a store that never answers must not \
         produce a response — it did, so the row below proves nothing \
         about a deadline: {:?}",
        parked_read.map(|response| (response.status(), token(&response)))
    );
    let parked_write = timeout(
        Duration::from_millis(200),
        against_stalled(
            None,
            never_drains.subscribe(),
            &Method::PUT,
            &write_target,
            None,
            write_body.clone(),
        ),
    )
    .await;
    assert!(
        parked_write.is_err(),
        "an unbounded WRITE against a store that never answers must not \
         produce a response, got {:?}",
        parked_write.map(|response| (response.status(), token(&response)))
    );

    // 2 — the same two requests, bounded. The outer `timeout` is a
    // HANG DETECTOR two orders of magnitude above the deadline, so
    // an expiry inside it is the deadline's and nothing else's.
    for (what, method, target, range, body) in [
        (
            "read",
            &Method::GET,
            &read_target,
            Some("bytes=0-15"),
            Vec::new(),
        ),
        ("write", &Method::PUT, &write_target, None, write_body),
    ] {
        let response = timeout(
            Duration::from_secs(5),
            against_stalled(
                Some(Duration::from_millis(50)),
                never_drains.subscribe(),
                method,
                target,
                range,
                body,
            ),
        )
        .await
        .unwrap_or_else(|_expired| {
            panic!("the {what} arm HUNG: the dispatch deadline must answer, not wait")
        });
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the {what} arm answers §5.10's refusing-load status"
        );
        assert_eq!(
            token(&response).as_deref(),
            Some("unavailable"),
            "the {what} arm carries §8.2's token — the SAME renderer the \
             accept clock and the permit queue use, not a second one"
        );
        assert_eq!(
            field(&response, &CONNECTION),
            None,
            "an expiry is a STATUS, not a tear-down: a dropped connection \
             reads as retryable to every client in the stack"
        );
    }
}

/// The bound the drain-race row answers within, SHORTER than both
/// clocks on purpose.
///
/// Shorter than [`STORE_DISPATCH_DEADLINE`], so a pass cannot be the
/// deadline expiring — the seam never answers, and that deadline is
/// the only other way out of the await. Shorter than
/// [`SHUTDOWN_DEADLINE`], because that is the operational property
/// being tested: the request has to be off the machine before the
/// transport's drain deadline turns a deploy into
/// `std::process::exit(EXIT_DEADLINE_EXPIRED)`.
///
/// Both relations are asserted in the row rather than left here, so
/// a change to either constant cannot quietly leave this bound
/// describing nothing.
const RACED_WITHIN: Duration = Duration::from_secs(2);

/// One request against the stalled seam, with the drain raised only
/// once the request is INSIDE it.
///
/// **The park proof is the first poll.** Raising the level before
/// the request starts would exercise `until_draining`'s
/// level-on-entry arm — which
/// [`the_drain_race_abandons_a_pending_future_and_nothing_else`]
/// already covers — and would say nothing about a dispatch already
/// under way. Asserting that first poll is `Pending` is what makes
/// "in flight" a measured fact rather than a hope about scheduling.
///
/// **Hand-polled, because `tokio::spawn` is banned** and
/// because the INTERLEAVING is the property: poll the request, send,
/// poll again, in that order and no other.
async fn raced_by_the_drain(
    method: &Method,
    target: &str,
    range: Option<&str>,
    body: Vec<u8>,
) -> Response<Full<Bytes>> {
    let (drain, watched) = watch::channel(false);
    let mut request = pin!(against_stalled(
        Some(STORE_DISPATCH_DEADLINE),
        watched,
        method,
        target,
        range,
        body,
    ));
    let mut raised = false;
    std::future::poll_fn(move |context| {
        if !raised {
            assert!(
                request.as_mut().poll(context).is_pending(),
                "the request answered before the drain was raised: this \
                 store never answers, so nothing was in flight and the \
                 row would be proving the level-on-entry arm instead"
            );
            let _observed = drain.send(true);
            raised = true;
        }
        request.as_mut().poll(context)
    })
    .await
}

/// **A seam dispatch already IN FLIGHT is abandoned when the process
/// starts draining — including the seam await inside `dispatch_within`.**
///
/// `accept_and_dispatch` races the drain, and so does
/// `dispatch_within`; without the second race the abandonment would
/// stop at the seam call. A request that reached the store would then
/// hold its connection for the whole of [`STORE_DISPATCH_DEADLINE`] —
/// thirty seconds, three times [`SHUTDOWN_DEADLINE`] — and a SIGTERM
/// catching one would make a clean deploy exit `EXIT_DEADLINE_EXPIRED`
/// instead of draining. [`WRITE_ACCEPT_MAX_WAIT`]'s own doc records why
/// the longer clock cannot simply be shortened to fit under the
/// deadline; the race is what makes it safe, and it belongs on EVERY
/// await that can outlive the deadline.
///
/// **Both arms**, because a race on writes alone leaves every `GET`
/// against a quiet bucket holding the drain open — and the read arm
/// is the one an unauthenticated peer reaches most cheaply.
///
/// **The answer is a STATUS** (§5.10) and it carries
/// NO tear-down token: the content was read to its end on both arms,
/// so nothing is left unread and the connection stays usable for
/// whatever the drain still lets through.
#[tokio::test]
async fn a_dispatch_in_flight_is_abandoned_when_the_drain_is_raised() {
    assert!(
        RACED_WITHIN < STORE_DISPATCH_DEADLINE,
        "the bound must sit well inside the dispatch deadline, or a pass here \
         is the deadline expiring rather than the drain race"
    );
    assert!(
        RACED_WITHIN < SHUTDOWN_DEADLINE,
        "and inside the transport's drain deadline, which is the property \
         under test: past it the process exits EXIT_DEADLINE_EXPIRED \
         instead of draining"
    );

    let digest = [0xAA_u8; DIGEST_LEN];
    let read_target = format!("/bin/{}", hex64(&digest));
    let write_body = b"a meta object the store will never accept".to_vec();
    let write_target = format!("/volume/t/meta/{}", GrainId::of(&write_body));

    for (what, method, target, range, body) in [
        (
            "read",
            &Method::GET,
            &read_target,
            Some("bytes=0-15"),
            Vec::new(),
        ),
        ("write", &Method::PUT, &write_target, None, write_body),
    ] {
        let response = timeout(
            RACED_WITHIN,
            raced_by_the_drain(method, target, range, body),
        )
        .await
        .unwrap_or_else(|_expired| {
            panic!(
                "the {what} arm held the seam through the drain: an \
                 in-flight dispatch must be abandoned when the process \
                 starts going away, or a SIGTERM during one holds the \
                 connection for {STORE_DISPATCH_DEADLINE:?} — past \
                 {SHUTDOWN_DEADLINE:?}, where the transport exits \
                 EXIT_DEADLINE_EXPIRED instead of draining"
            )
        });
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the {what} arm answers §5.10's refusing-load status"
        );
        assert_eq!(
            token(&response).as_deref(),
            Some("unavailable"),
            "the {what} arm carries §8.2's token — the SAME renderer the \
             accept clock, the budget shed and the permit queue use"
        );
        assert_eq!(
            field(&response, &CONNECTION),
            None,
            "a drain is a STATUS, not a tear-down: the content was read \
             to its end, so nothing is left unread"
        );
    }
}

/// One request through the whole adapter path, with every bound
/// taken OFF A SERVICE VALUE.
///
/// The difference from [`against_stalled`] is the whole point:
/// that helper builds `Bounds` out of fresh values, so it can say
/// nothing about what a given service — or a CLONE of one — is
/// carrying. This one reads the same bounds `Service::call` reads,
/// `dispatch_deadline` included.
///
/// `Bounds` is a struct literal here, so a bound added to it stops
/// this helper compiling rather than letting it quietly answer under
/// some default.
async fn through(
    service: &GrainService<StalledSeam>,
    method: &Method,
    target: &str,
    range: Option<&str>,
) -> Response<Full<Bytes>> {
    let bounds = Bounds {
        capture: None,
        debug_grants: None,
        authority: None,
        budget: &service.write_budget,
        read_budget: &service.read_budget,
        permits: &service.verify_permits,
        read_permits: &service.read_permits,
        permit_wait: service.permit_wait,
        dispatch_deadline: service.dispatch_deadline,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: service.test_reply_deadline,
        draining: service.draining.subscribe(),
    };
    let mut headers = HeaderMap::new();
    if let Some(range) = range {
        let value = HeaderValue::from_str(range).unwrap_or_else(|e| panic!("{range:?}: {e}"));
        let _replaced = headers.insert(RANGE, value);
    }
    let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
    answer(
        &*service.store,
        &service.base,
        service.policy,
        service.max_extent,
        bounds,
        method,
        &uri,
        &headers,
        &hyper::http::Extensions::new(),
        Some(0),
        Full::new(Bytes::new()),
        &mut None,
        &mut None,
        &mut None,
    )
    .await
}

/// **The dispatch deadline survives `Clone` — and nothing else in this
/// crate would notice if it did not.**
///
/// The accept loop clones one service per connection, so every
/// request a peer makes is answered by a CLONE and never by the
/// value the composition root built. `Clone` zeroing
/// `dispatch_deadline` to `None` compiles and the whole lib suite
/// stays green: the dispatch-deadline rows above build `Bounds` directly and
/// never clone a service, and every other row that does clone one is
/// running with no deadline anyway. The only guard was
/// `shipped_store_config`'s thirty-second process test — a lone
/// guard of that cost is the kind that gets `#[ignore]`d, and the
/// division of labour is better served by a row that costs fifty
/// milliseconds.
///
/// **A clone OF A CLONE**, because that is the shape production
/// produces: `serve` is handed a clone and clones that again per
/// connection.
///
/// **The outer bound is the DISCRIMINATOR, not decoration.** With
/// the deadline lost, this store never answers and the request does
/// not fail — it HANGS, which without a bound is a suite that wedges
/// instead of a row that reports.
#[tokio::test]
async fn the_dispatch_deadline_survives_the_connection_clone() {
    let service = GrainService::for_test(
        Arc::new(StalledSeam),
        "",
        // SEAM-ONLY for the same reason as `against_stalled`: the row
        // is about the deadline, not about whether a body verifies.
        VerifyPolicy::seam_only(),
        Some(DECLARED_MAX_EXTENT),
        WRITE_BODY_BUDGET_BYTES,
        READ_BODY_BUDGET_BYTES,
        VERIFY_PERMIT_MAX_WAIT,
        Some(Duration::from_millis(50)),
    );
    let connection = service.clone().clone();

    let digest = [0xAA_u8; DIGEST_LEN];
    let target = format!("/bin/{}", hex64(&digest));
    let response = timeout(
        Duration::from_secs(5),
        through(&connection, &Method::GET, &target, Some("bytes=0-15")),
    )
    .await
    .unwrap_or_else(|_expired| {
        panic!(
            "the CLONE hung against a store that never answers: `Clone` \
             dropped the dispatch deadline, so every connection the accept loop \
             hands out is unbounded while the service the composition root \
             built is not"
        )
    });
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a clone answers §5.10's refusing-load status on the same clock \
         the original does"
    );
    assert_eq!(
        token(&response).as_deref(),
        Some("unavailable"),
        "and §8.2's token, from the same renderer"
    );
}

// --------------------------------------- read-response bounds

/// One READ through the whole adapter path, under read-budget and permit bounds the row
/// chose, handing the RESPONSE back undropped.
///
/// The response is the point: a charge is released by the body's
/// destructor, so a helper that consumed the response would make
/// every observation below read zero for the wrong reason.
async fn read_under<R: RootStore + BinStore>(
    store: &R,
    read_budget: &Arc<ReadBudget>,
    read_permits: &Semaphore,
    permit_wait: Duration,
    target: &str,
    range: Option<&str>,
) -> Response<Full<Bytes>> {
    let budget = Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES));
    let permits = Semaphore::new(verify_permits(TEST_WORKER_THREADS));
    // Held for the whole await: dropping the sender closes the
    // channel, which is a different state from "not draining".
    let (_alive, draining) = watch::channel(false);
    let bounds = Bounds {
        capture: None,
        debug_grants: None,
        authority: None,
        budget: &budget,
        read_budget,
        permits: &permits,
        read_permits,
        permit_wait,
        dispatch_deadline: None,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: None,
        draining,
    };
    let mut headers = HeaderMap::new();
    if let Some(range) = range {
        let value = HeaderValue::from_str(range).unwrap_or_else(|e| panic!("{range:?}: {e}"));
        let _replaced = headers.insert(RANGE, value);
    }
    let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
    answer(
        store,
        "",
        VerifyPolicy::seam_only(),
        Some(DECLARED_MAX_EXTENT),
        bounds,
        &Method::GET,
        &uri,
        &headers,
        &hyper::http::Extensions::new(),
        Some(0),
        Full::new(Bytes::new()),
        &mut None,
        &mut None,
        &mut None,
    )
    .await
}

/// A fully-specified range wider than any object these rows plant.
///
/// Spelled out rather than open-ended: `bytes=0-` maps to a `len` of
/// `u32::MAX`, which §7.1's declared maximum refuses at the gate —
/// before the store, the permit or the budget is touched, which would
/// make every row below assert about a `400`.
const WIDE: &str = "bytes=0-65535";

/// A store holding one bin of `len` bytes, and its target.
async fn planted(len: usize) -> (FakeSeam, String) {
    let store = FakeSeam::default();
    let body = vec![0x5a_u8; len];
    let digest = *GrainId::of(&body).digest();
    let planted = store.put_bin(&digest, body).await;
    assert!(planted.is_ok(), "planting the bin");
    let target = format!("/bin/{}", hex64(&digest));
    (store, target)
}

/// **The figure this module calls the uncharged transient must
/// cover what a ranged read ACTUALLY peaks at.**
///
/// The permit count exists to bound what the byte budget cannot see,
/// and the module states that blind spot as a number. The number is
/// only worth asserting over if it is the real one — and the real one
/// is not the extent. `granary_store::backend::collect_bounded`
/// reserves ONE FRAME and grows by DOUBLING past it, then calls
/// `shrink_to_fit`, whose `realloc` may hold the grown allocation and
/// the exact one at the same instant. So the peak a single read
/// reaches is the grown capacity PLUS the delivered length, and a
/// figure that named only the delivered length would understate the
/// process by the whole growth overshoot.
///
/// The model is recomputed here from the store's own constants rather
/// than restated as a literal, so a frame cap or an extent cap that
/// moves is read by this row rather than remembered by it.
#[test]
fn the_transient_figure_covers_the_stores_allocation_peak() {
    let delivered = u64::from(DECLARED_MAX_EXTENT);
    // The reservation: one frame, clamped by `range_alloc_hint`.
    let mut capacity = u64::from(FRAME_COMP_MAX);
    // `Vec` growth past the reservation is amortised doubling.
    while capacity < delivered {
        capacity *= 2;
    }
    // `shrink_to_fit`: the old allocation and the new one, both live
    // across the `realloc` that moves the bytes.
    let peak = capacity + delivered;

    assert_eq!(
        (capacity, peak),
        (134_742_160, 213_221_543),
        "the growth model changed underneath this row"
    );
    assert!(
        READ_TRANSIENT_PEAK_BYTES >= peak,
        "the module calls {READ_TRANSIENT_PEAK_BYTES} bytes the \
         uncharged transient of one ranged read, and the read peaks at \
         {peak}: every figure derived from it — the permit count above \
         all — is understated by the difference"
    );
    // The operator-facing figure, pinned against the prose that
    // quotes it: a doc naming 1.75 GiB and a constant computing
    // something else is a half-corrected document, which this
    // assertion refuses.
    assert_eq!(
        PERMITTED_READ_TRANSIENT_CEILING_BYTES, 1_883_505_192,
        "the permitted pool's ceiling moved — its unit is the LARGEST \
         member's peak (the ranged read's today; a grown \
         `META_MAX_BYTES` moves the meta member's witness instead): \
         the paragraph on `READ_PERMITS` quotes this number and has \
         to move with it"
    );
}

/// Which seam call a dispatch made, recorded by [`Recorder`].
///
/// **One variant per method on the two store traits**, so a seam
/// that GROWS a method does not compile until the recorder
/// implements it and [`resident_bound`] gives it a bound. That is
/// what keeps the derivation below total over the store as well as
/// over `Operation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeamCall {
    PutRoot,
    GetRoot,
    ReadHint,
    WriteHint,
    MaxSeq,
    PutBin,
    PutMeta,
    GetMeta,
    GetBinRange,
}

/// What ONE call of a seam method may leave resident in this
/// process — a bound read off the tree, never a measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResidentBound {
    /// A write. What it carries IN is the write budget's business
    /// (`write_cap`), and it hands no buffer back.
    NoReadBuffer,
    /// A read bounded by a frozen per-kind cap.
    Bounded(u64),
    /// A read with NO cap anywhere in this tree: `max_seq` hands the
    /// listing to the `ObjectStore` and nothing here bounds what
    /// that buffers.
    Unbounded,
}

/// The bound each seam method reads under. No wildcard arm.
const fn resident_bound(call: SeamCall) -> ResidentBound {
    match call {
        SeamCall::PutRoot | SeamCall::WriteHint | SeamCall::PutBin | SeamCall::PutMeta => {
            ResidentBound::NoReadBuffer
        }
        SeamCall::GetRoot => ResidentBound::Bounded(ROOT_MAX_BYTES),
        SeamCall::ReadHint => ResidentBound::Bounded(SEQ_KEY_DIGITS as u64),
        SeamCall::MaxSeq => ResidentBound::Unbounded,
        SeamCall::GetMeta => ResidentBound::Bounded(META_MAX_BYTES),
        SeamCall::GetBinRange => ResidentBound::Bounded(DECLARED_MAX_EXTENT as u64),
    }
}

/// Is a seam call's bound big enough that a figure whose UNIT is
/// [`READ_TRANSIENT_PEAK_BYTES`] would have to carry a term for it?
///
/// **The comparison is aggregate against one permitted read's
/// peak**, and both sides are shipped constants rather than a
/// threshold picked to make three rows come out right: an
/// unpermitted call that every resident connection could be inside
/// at once, holding less in total than a SINGLE ranged read's own
/// allocator spike, is noise inside a term this constant already
/// counts. One that holds more is a term it does not.
///
/// **The multiplier is the WHOLE envelope, both counts:**
/// `MAX_CONNECTIONS` x `H2_MAX_CONCURRENT_STREAMS` = 819 200
/// (`REQUESTS_IN_FLIGHT`), the figure §9.2 states and
/// [`PERMITTED_READ_TRANSIENT_CEILING_BYTES`]'s own comment
/// quotes, so the constant, its doc comment and this
/// threshold name one quantity instead of two.
/// `MAX_CONNECTIONS` alone would be a FLOOR on in-flight
/// requests — one that could under-count and never
/// over-count.
///
/// **What the row below asserts, at `REQUESTS_IN_FLIGHT`:** the
/// threshold has capped seam calls on BOTH sides of it — so a tree
/// where it stopped discriminating fails rather than silently
/// classifying everything one way — and the `omitted` list is exactly
/// `GetRoot` and `MaxSeq`.
fn wants_a_term_of_its_own(call: SeamCall) -> bool {
    match resident_bound(call) {
        ResidentBound::NoReadBuffer => false,
        ResidentBound::Unbounded => true,
        ResidentBound::Bounded(cap) => {
            cap.saturating_mul(REQUESTS_IN_FLIGHT) > READ_TRANSIENT_PEAK_BYTES
        }
    }
}

/// §9.2's transport envelope: every request that can be in flight at
/// once, across every resident connection.
///
/// Spelled once, here, because it is a product this file's doc
/// comments already state in prose, and each further spelling is one
/// more thing to get wrong. `scripts/check-protocol-constants.py` checks each
/// multiplicand against its own named limit.
const REQUESTS_IN_FLIGHT: u64 = (MAX_CONNECTIONS as u64) * (H2_MAX_CONCURRENT_STREAMS as u64);

/// A seam that RECORDS which store call a dispatch made, answering
/// out of a real [`FakeSeam`].
///
/// **A wrapper rather than a flag on the shared fake.** `fake.rs`
/// says in its own header that it has "no idea which handler is
/// calling", and that is a property worth keeping: the conformance
/// bodies hold it to the seam's semantics and nothing else. The
/// knowledge of who called belongs to the row that needs it.
#[derive(Debug, Default)]
struct Recorder {
    inner: FakeSeam,
    calls: std::sync::Mutex<Vec<SeamCall>>,
}

impl Recorder {
    /// Noted at CALL time, not inside the returned future, so no
    /// lock is ever held across an await.
    fn note(&self, call: SeamCall) {
        self.locked().push(call);
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Vec<SeamCall>> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Everything recorded since the last take.
    fn taken(&self) -> Vec<SeamCall> {
        std::mem::take(&mut *self.locked())
    }
}

impl RootStore for Recorder {
    fn put_root(
        &self,
        volume: &str,
        seq: u64,
        bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), RootStoreError>> + Send {
        self.note(SeamCall::PutRoot);
        self.inner.put_root(volume, seq, bytes)
    }

    fn get_root(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, RootStoreError>> + Send {
        self.note(SeamCall::GetRoot);
        self.inner.get_root(volume, seq)
    }

    fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> impl std::future::Future<Output = Result<HintRead, RootStoreError>> + Send {
        self.note(SeamCall::ReadHint);
        self.inner.read_hint(volume, cached)
    }

    fn write_hint(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl std::future::Future<Output = Result<(), RootStoreError>> + Send {
        self.note(SeamCall::WriteHint);
        self.inner.write_hint(volume, seq)
    }

    fn max_seq(
        &self,
        volume: &str,
    ) -> impl std::future::Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.note(SeamCall::MaxSeq);
        self.inner.max_seq(volume)
    }

    fn max_seq_above(
        &self,
        volume: &str,
        floor: u64,
    ) -> impl std::future::Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.note(SeamCall::MaxSeq);
        self.inner.max_seq_above(volume, floor)
    }
}

impl BinStore for Recorder {
    fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<bool, RootStoreError>> + Send {
        self.note(SeamCall::PutBin);
        self.inner.put_bin(digest, bytes)
    }

    fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<bool, RootStoreError>> + Send {
        self.note(SeamCall::PutMeta);
        self.inner.put_meta(volume, id, bytes)
    }

    fn get_meta(
        &self,
        volume: &str,
        id: &GrainId,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, RootStoreError>> + Send {
        self.note(SeamCall::GetMeta);
        self.inner.get_meta(volume, id)
    }

    fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, RootStoreError>> + Send {
        self.note(SeamCall::GetBinRange);
        self.inner.get_bin_range(digest, offset, len)
    }
}

/// Every §4.2 operation and one well-formed request for it.
///
/// **No classification column, and the absence is the point.** A
/// row that declared `permit:` and `omitted:` per operation would
/// make the gate's own answer a thing the row's author supplied —
/// and `(permit: false, omitted: false)` is both the least-effort
/// value and exactly the "counted by nobody" state this row exists
/// to catch. What a row supplies is a REQUEST; every
/// classification below is read off what the shipped code does
/// with it.
///
/// **A macro, because the compiler has to be the one counting.**
/// The invocation generates the row table AND an exhaustive `match`
/// over `Operation` from the same list, so a tenth operation does
/// not compile until it is named HERE — and naming it here adds a
/// row and a sample at one stroke, with no field left over to fill
/// in wrongly. A variant listed twice is an unreachable arm, which
/// CI denies as a warning.
macro_rules! operation_partition {
    ($($variant:ident: $method:literal $path:expr, $range:expr, $body:expr,)+) => {
        fn variant_of(operation: &Operation<'_>) -> &'static str {
            match operation {
                $(Operation::$variant { .. } => stringify!($variant),)+
                Operation::Intent { .. } => "Intent",
                Operation::Publish { .. } => "Publish",
                Operation::VolumeStatus { .. } => "VolumeStatus",
            }
        }

        /// `(variant, method, target, Range field lines, body)`.
        const PARTITION: &[(&str, &str, &str, &[&str], &[u8])] = &[
            $((stringify!($variant), $method, $path, $range, $body),)+
        ];
    };
}

/// One well-formed target per operation, spelled out rather than
/// formatted: §4.3 matches byte for byte, and a `format!` is not a
/// `const`.
const BIN_TARGET: &str = "/bin/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const META_TARGET: &str = "/volume/v1/meta/blake3:\
    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ROOT_TARGET: &str = "/volume/v1/root/00000000000000000042";
const MAX_SEQ_TARGET: &str = "/volume/v1/max-seq";
const HINT_TARGET: &str = "/volume/v1/hint";

operation_partition! {
    PutBin: "PUT" BIN_TARGET, &[], b"",
    GetBinRange: "GET" BIN_TARGET, &["bytes=0-1023"], b"",
    PutMeta: "PUT" META_TARGET, &[], b"",
    GetMeta: "GET" META_TARGET, &[], b"",
    // A body, because `put_root` stores opaque bytes with no
    // content check and so actually reaches the seam.
    PutRoot: "PUT" ROOT_TARGET, &[], b"a root",
    GetRoot: "GET" ROOT_TARGET, &[], b"",
    MaxSeq: "GET" MAX_SEQ_TARGET, &[], b"",
    ReadHint: "GET" HINT_TARGET, &[], b"",
    WriteHint: "PUT" HINT_TARGET, &[], b"00000000000000000042",
}

/// One request through the WHOLE adapter path under a read-permit
/// pool the caller chose, handing back the status and the seam
/// calls the dispatch made.
///
/// **The pool is the instrument.** Running the same request against
/// an EXHAUSTED pool and an ample one is how this file observes the
/// acquisition at `answer`'s own read arm rather than re-reading
/// the predicate that guards it — see the row below for why the
/// difference matters.
async fn answered_under(
    store: &Recorder,
    read_permits: &Semaphore,
    row: (&str, &str, &str, &[&str], &[u8]),
) -> (StatusCode, Vec<SeamCall>) {
    let (_variant, method, target, range, body) = row;
    let budget = Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES));
    let read_budget = Arc::new(ReadBudget::new(READ_BODY_BUDGET_BYTES));
    let permits = Semaphore::new(verify_permits(TEST_WORKER_THREADS));
    // Held for the whole await: dropping the sender closes the
    // channel, which is a different state from "not draining".
    let (_alive, draining) = watch::channel(false);
    let bounds = Bounds {
        capture: None,
        debug_grants: None,
        authority: None,
        budget: &budget,
        read_budget: &read_budget,
        permits: &permits,
        read_permits,
        // Short, because the exhausted-pool run is SUPPOSED to
        // reach it and a row must not pay the shipped wait to find
        // that out.
        permit_wait: Duration::from_millis(20),
        dispatch_deadline: None,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: None,
        draining,
    };
    let mut headers = HeaderMap::new();
    for line in range {
        let value = HeaderValue::from_str(line).unwrap_or_else(|e| panic!("{line:?}: {e}"));
        let _appended = headers.append(RANGE, value);
    }
    let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
    let verb = Method::from_bytes(method.as_bytes()).unwrap_or_else(|e| panic!("{method:?}: {e}"));
    let _drained = store.taken();
    let response = answer(
        store,
        "",
        VerifyPolicy::seam_only(),
        Some(DECLARED_MAX_EXTENT),
        bounds,
        &verb,
        &uri,
        &headers,
        &hyper::http::Extensions::new(),
        Some(body.len() as u64),
        Full::new(Bytes::copy_from_slice(body)),
        &mut None,
        &mut None,
        &mut None,
    )
    .await;
    (response.status(), store.taken())
}

/// **The partition
/// [`PERMITTED_READ_TRANSIENT_CEILING_BYTES`] is computed over,
/// derived per operation from what the shipped code DOES and
/// compared row by row.**
///
/// The constant bounds the PERMITTED read path only, not the
/// PROCESS-wide uncharged transient, as its own doc states. For a
/// row to catch the partition drifting from what the constant
/// counts, two things must be true of the row.
///
/// **It observes the ACQUISITION, not the predicate.** The permit
/// column is read off `answer`'s read arm by running each request
/// twice — once against a pool with no permits left and a short
/// wait, once against a full one — because the constant is derived
/// from what TAKES a permit, not from what `takes_a_read_permit`
/// returns. `GET meta` holds a slot in the same eight,
/// and that is why this row observes
/// the acquisition instead of trusting the predicate: the ceiling
/// stays the pool's upper bound only while `GetMeta`'s own modelled
/// peak sits under [`READ_TRANSIENT_PEAK_BYTES`] (the module's
/// `const _` witness pins that premise), and a THIRD member joining
/// without its peak under that unit would break the premise while
/// leaving the predicate looking untouched — exactly the drift this
/// row exists to catch. The ample-pool run is the positive control:
/// if BOTH runs refuse, the refusal was never the permit's and the
/// observation is blind.
///
/// **It DERIVES the omitted terms rather than accepting them.** An
/// operation is a term this constant leaves out when it takes no
/// permit and its seam call can hold more, across every resident
/// connection, than one permitted read's own allocator peak — read
/// off the recorded call and two shipped constants, with no column
/// for an author to fill in. A tenth unpermitted read inherits its
/// classification from the seam method it dispatches to, whatever
/// its row says, because its row says nothing.
#[expect(
    clippy::too_many_lines,
    reason = "the four positive controls and the two-list derivation are \
              one auditable flow: splitting it would separate an \
              assertion from the control that makes it mean something"
)]
#[tokio::test]
async fn the_read_permit_partition_matches_what_the_ceiling_claims() {
    let mut permitted: Vec<&str> = Vec::new();
    let mut omitted: Vec<&str> = Vec::new();
    let mut above = 0_usize;
    let mut below = 0_usize;

    for &row in PARTITION {
        let (variant, method, path, range, _body) = row;
        let head = RequestHead {
            method,
            path,
            base: "",
            range,
            conditionals: Conditionals::default(),
            declared_len: None,
        };
        let admitted = match admit(&head) {
            Ok(admitted) => admitted,
            Err(refusal) => panic!(
                "the {variant} row's sample request ({method} {path}) is refused \
                 with {:?}: a row that never reaches the dispatch tests nothing",
                refusal.outcome().status()
            ),
        };
        // THE FIRST POSITIVE CONTROL. A mistyped target would admit
        // as some OTHER operation, classify that one twice and
        // leave this one unexercised — and every assertion below
        // would still pass, which is a gate that cannot tell clean
        // from blind.
        assert_eq!(
            variant_of(admitted.operation()),
            variant,
            "the {variant} row's sample request admits as a different operation"
        );

        let store = Recorder::default();
        let starved = Semaphore::new(READ_PERMITS);
        let whole_pool = u32::try_from(READ_PERMITS).unwrap_or(u32::MAX);
        let drained = starved.try_acquire_many(whole_pool);
        assert!(
            drained.is_ok(),
            "{variant}: the pool must start full for the exhaustion to mean anything"
        );
        let (under_starvation, _refused) = answered_under(&store, &starved, row).await;
        let ample = Semaphore::new(READ_PERMITS);
        // The SEAM calls come from this run and not the one above.
        // A permitted operation under an exhausted pool is refused
        // BEFORE dispatch — which is the whole point of the permit
        // — so the starved run observes the acquisition and can
        // observe nothing else. Reading both off it classified
        // `GetBinRange` as a read that never touched the store,
        // and the control below caught it.
        let (under_plenty, calls) = answered_under(&store, &ample, row).await;

        // THE SECOND POSITIVE CONTROL. `unavailable` has other
        // sources — the dispatch deadline, a draining process — and
        // a row where BOTH runs refuse has observed one of those
        // instead of the permit.
        assert_ne!(
            under_plenty,
            StatusCode::SERVICE_UNAVAILABLE,
            "{variant} is refused even with the whole pool free, so the \
             exhausted-pool answer says nothing about the permit"
        );
        let takes_permit = under_starvation == StatusCode::SERVICE_UNAVAILABLE;

        // THE THIRD POSITIVE CONTROL. A read that never reached the
        // seam records nothing, and a classification derived from
        // nothing is not derived.
        let is_write = write_cap(admitted.operation()).is_some();
        assert!(
            is_write || !calls.is_empty(),
            "{variant} is a read that made no seam call: the bound its \
             classification is derived from was never observed"
        );

        // The predicate and the acquisition, cross-checked. Either
        // one moving without the other is a drift between the
        // constant's stated scope and the code that fills it.
        assert_eq!(
            takes_a_read_permit(&admitted),
            takes_permit,
            "`takes_a_read_permit` says {} for {variant} and the acquisition site \
             in `answer` does the opposite: one of them moved alone",
            takes_a_read_permit(&admitted)
        );

        // Only the CAPPED calls: those are the ones the threshold
        // arithmetic decides. Counting writes here too would have
        // kept the control below satisfied by `NoReadBuffer` alone,
        // which is not the threshold discriminating — it is the
        // threshold never being consulted.
        for call in &calls {
            if let ResidentBound::Bounded(cap) = resident_bound(*call) {
                if wants_a_term_of_its_own(*call) {
                    above += 1;
                } else {
                    below += 1;
                }
                // THE PER-MEMBER PREMISE, total over whatever the
                // predicate admits: the ceiling's unit is ONE ranged
                // read's peak, so every capped call a PERMITTED row
                // makes must have its own modelled peak under that
                // unit — the `const _` witness pins the meta member
                // by name, and this row pins every member there IS,
                // so a new member joining the pool without its peak
                // under the unit fails here rather than being typed
                // into the `permitted` list below and forgotten.
                if takes_permit {
                    assert!(
                        modelled_transient_peak(cap) <= READ_TRANSIENT_PEAK_BYTES,
                        "{variant} takes a permit but its capped seam call \
                         ({cap} bytes) has a modelled peak over one ranged \
                         read's: the ceiling formula is no longer the \
                         pool's upper bound and must be re-derived"
                    );
                }
            }
        }
        if takes_permit {
            permitted.push(variant);
        }
        if !takes_permit && calls.iter().copied().any(wants_a_term_of_its_own) {
            omitted.push(variant);
        }
    }

    // THE FOURTH POSITIVE CONTROL, on the threshold itself, and it
    // runs BEFORE the two lists it guards: a threshold every capped
    // seam call falls on one side of produces those lists by
    // accident, and the failure a reader needs to see first is that
    // the derivation stopped deriving.
    assert!(
        above > 0 && below > 0,
        "the aggregate-against-one-peak threshold no longer discriminates \
         ({above} capped seam calls above it, {below} below): the omitted \
         list is then a coincidence rather than a derivation"
    );
    assert_eq!(
        permitted,
        ["GetBinRange", "GetMeta"],
        "`PERMITTED_READ_TRANSIENT_CEILING_BYTES` ({PERMITTED_READ_TRANSIENT_CEILING_BYTES}) \
         is `READ_PERMITS` times the LARGEST permitted member's per-read \
         peak — the ranged read's — and this list is what ACQUIRES those \
         permits. The product stays the pool's upper bound only while \
         EVERY member's own peak sits under that unit; the `const _` \
         witness pins `GetMeta`'s, and a THIRD member joining without its \
         own peak under the unit breaks the FORMULA, not just this list"
    );
    assert_eq!(
        omitted,
        ["GetRoot", "MaxSeq"],
        "these two are what the constant's doc comment names as absent \
         from it, and they are the whole reason it is not the process-wide \
         figure: empty this list and the comment's central claim — that the \
         process-wide uncharged transient has no finite Phase-1 bound \
         — is the false half. A third belongs in \
         the comment as much as in this derivation"
    );
}

/// An ample read budget and an unexhausted read permit, for the rows
/// that are not about either.
fn ample_read() -> (Arc<ReadBudget>, Semaphore) {
    (
        Arc::new(ReadBudget::new(READ_BODY_BUDGET_BYTES)),
        Semaphore::new(READ_PERMITS),
    )
}

/// **A `GET` for an absent digest charges nothing.**
///
/// This distinguishes charging the returned buffer from reserving
/// the ask up front. A reservation sized by the DECLARED extent
/// would charge this request 74.84 MiB for an answer that holds four
/// header fields and no body at all — which is what makes such a
/// reservation an availability weapon rather than a memory bound:
/// the cheapest request an unauthenticated peer can make would be the
/// most expensive one to answer.
#[tokio::test]
async fn an_absent_digest_charges_nothing() {
    let store = FakeSeam::default();
    let (read_budget, read_permits) = ample_read();
    let target = format!("/bin/{}", hex64(&[0xAA_u8; DIGEST_LEN]));

    let response = read_under(
        &store,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some("bytes=0-78479382"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        read_budget.in_flight(),
        0,
        "a 404 held no bytes and must be charged for none — the response \
         is still alive at this assertion, so a zero here is a zero \
         CHARGE and not a released one"
    );
}

/// **A short read charges what it READ, not what was asked
/// for.**
///
/// The declared width here is nine thousand times the object. A
/// charge taken before the store call could only be the ask; a charge
/// taken on the buffer that came back is the object.
#[tokio::test]
async fn a_short_read_charges_what_it_read() {
    const STORED: usize = 100;
    let (store, target) = planted(STORED).await;
    let (read_budget, read_permits) = ample_read();

    let response = read_under(
        &store,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some("bytes=0-899999"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let held = read_budget.in_flight();
    assert_eq!(
        held, STORED as u64,
        "the ask was 900 000 bytes and the object is {STORED}: the charge \
         must be the object"
    );
    drop(response);
    assert_eq!(
        read_budget.in_flight(),
        0,
        "the charge must return when the response is dropped"
    );
}

/// **The capacity returns on COMPLETION** — the body read to
/// its end, the way a healthy client leaves it.
///
/// Distinct from the row above, which drops the response unread. Both
/// exits have to credit the budget, and only one of them is the
/// common case.
#[tokio::test]
async fn the_read_charge_returns_after_the_body_is_collected() {
    const STORED: usize = 4096;
    let (store, target) = planted(STORED).await;
    let (read_budget, read_permits) = ample_read();

    let response = read_under(
        &store,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some(WIDE),
    )
    .await;
    // THE PARK PROOF: the charge is genuinely held at this line, so
    // the zero below is a release rather than a charge that never
    // happened.
    assert_eq!(read_budget.in_flight(), STORED as u64);

    let collected = body_of(response);
    assert_eq!(collected.len(), STORED);
    // **The charge follows the BYTES, not the `Response`.** The
    // response value is gone here and the collected `Bytes` is a
    // clone of the same owner, so the allocation is still resident
    // and the charge must still be held. This is the property that
    // makes the accounting true of hyper: `PipeToSendStream` holds
    // exactly such a clone across every flow-control wait, and a
    // charge released when this layer stopped looking would go back
    // to the budget while the bytes were still in the process.
    assert_eq!(
        read_budget.in_flight(),
        STORED as u64,
        "the bytes are still resident in the collected clone"
    );
    drop(collected);
    assert_eq!(
        read_budget.in_flight(),
        0,
        "and the budget is credited when the LAST clone goes"
    );
}

/// **N maximal reads are SHED rather than growing the heap.**
///
/// The budget is filled from the outside — deterministic, rather than
/// a storm of concurrent reads timed to collide — and the park proof
/// is that the fill is still held when the read arrives.
#[tokio::test]
async fn a_full_read_budget_sheds_the_next_read() {
    const STORED: usize = 4096;
    const BUDGET: u64 = 8192;
    let (store, target) = planted(STORED).await;
    let read_budget = Arc::new(ReadBudget::new(BUDGET));
    let read_permits = Semaphore::new(READ_PERMITS);

    // Two reads' worth, taken and HELD.
    let filled = read_budget
        .take(BUDGET)
        .unwrap_or_else(|| panic!("the whole budget"));
    assert_eq!(read_budget.in_flight(), BUDGET, "the park proof");

    let shed = read_under(
        &store,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some(WIDE),
    )
    .await;
    assert_eq!(
        shed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a read whose bytes the budget cannot hold is §5.10's refusing \
         load, not a body the process has nowhere to put"
    );
    assert_eq!(token(&shed).as_deref(), Some("unavailable"));
    assert_eq!(
        read_budget.in_flight(),
        BUDGET,
        "the shed read charged nothing and left nothing behind"
    );

    // And the budget RECOVERS: the same read is served once the
    // holder lets go. A shed that never lifts is the outage this
    // whole decision is bounded against.
    drop(filled);
    drop(shed);
    let served = read_under(
        &store,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some(WIDE),
    )
    .await;
    assert_eq!(served.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(read_budget.in_flight(), STORED as u64);
}

/// **N reads FILL the budget with real charges, and the next
/// one is shed rather than added to the heap.**
///
/// The aggregate property, stated with responses rather than with a
/// number pushed into the counter from outside: three reads of the
/// same object are served, each holding its own charge because each
/// response is still alive, and the fourth is refused. Then one
/// holder lets go and the fourth is served — a shed that does not
/// lift is an outage, so a charge must have a bounded hold time
/// as well as a byte bound.
///
/// The budget is sized at exactly three objects so the boundary is
/// the assertion and not an approximation.
#[tokio::test]
async fn reads_fill_the_budget_with_their_own_charges_and_the_next_is_shed() {
    const STORED: usize = 4096;
    const ROOM_FOR: usize = 3;
    let (store, target) = planted(STORED).await;
    let read_budget = Arc::new(ReadBudget::new((STORED * ROOM_FOR) as u64));
    let read_permits = Semaphore::new(READ_PERMITS);

    let mut held = Vec::new();
    for n in 1..=ROOM_FOR {
        let response = read_under(
            &store,
            &read_budget,
            &read_permits,
            VERIFY_PERMIT_MAX_WAIT,
            &target,
            Some(WIDE),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::PARTIAL_CONTENT,
            "read {n} of {ROOM_FOR} is inside the budget"
        );
        assert_eq!(
            read_budget.in_flight(),
            (STORED * n) as u64,
            "each live response holds its OWN charge: a budget that \
             credited itself when this layer stopped looking would read \
             zero here"
        );
        held.push(response);
    }

    let shed = read_under(
        &store,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some(WIDE),
    )
    .await;
    assert_eq!(
        shed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the {}th read must be refused, not held",
        ROOM_FOR + 1
    );
    assert_eq!(token(&shed).as_deref(), Some("unavailable"));
    assert_eq!(read_budget.in_flight(), (STORED * ROOM_FOR) as u64);

    // One holder lets go, and the refusal LIFTS.
    drop(held.pop());
    assert_eq!(read_budget.in_flight(), (STORED * (ROOM_FOR - 1)) as u64);
    let served = read_under(
        &store,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some(WIDE),
    )
    .await;
    assert_eq!(
        served.status(),
        StatusCode::PARTIAL_CONTENT,
        "the shed must lift when the bytes it was about are gone"
    );

    drop(held);
    drop(served);
    assert_eq!(read_budget.in_flight(), 0);
}

/// **An exhausted read-permit queue sheds the PERMITTED
/// reads — RANGE and META — and only the permitted reads.**
///
/// Three arms, and the third is what makes the first two evidence.
/// The two positive arms prove the permit is a real bound over BOTH
/// members of the shared pool; the control proves the pool is still
/// SCOPED — a permit taken on every read would put `max-seq`, `GET
/// root` and `GET hint` behind eight slots as well, which is a
/// throughput bound nobody asked for and which this row would
/// otherwise never notice.
#[tokio::test]
async fn an_exhausted_read_permit_sheds_the_permitted_reads_only() {
    const STORED: usize = 4096;
    let (store, target) = planted(STORED).await;
    let read_budget = Arc::new(ReadBudget::new(READ_BODY_BUDGET_BYTES));
    let read_permits = Semaphore::new(READ_PERMITS);

    // THE PARK PROOF: every permit is taken and HELD, from the
    // outside, before the read is made.
    let mut taken = Vec::new();
    for _ in 0..READ_PERMITS {
        taken.push(read_permits.try_acquire().unwrap_or_else(|e| panic!("{e}")));
    }
    assert_eq!(read_permits.available_permits(), 0);

    let shed = read_under(
        &store,
        &read_budget,
        &read_permits,
        Duration::from_millis(50),
        &target,
        Some(WIDE),
    )
    .await;
    assert_eq!(
        shed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a range read that cannot get into the store within the queue \
         bound is shed, not queued indefinitely"
    );
    assert_eq!(token(&shed).as_deref(), Some("unavailable"));
    assert_eq!(
        read_budget.in_flight(),
        0,
        "a read shed at the queue never reached the store and charges \
         nothing"
    );

    // THE SECOND POSITIVE ARM: `GET meta` shares this pool now
    // and sheds at the same exhausted queue — no planted
    // meta is needed, because the shed happens BEFORE dispatch and
    // nothing is charged.
    let meta_shed = read_under(
        &store,
        &read_budget,
        &read_permits,
        Duration::from_millis(50),
        META_TARGET,
        None,
    )
    .await;
    assert_eq!(
        meta_shed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a meta read that cannot get into the store within the queue \
         bound is shed too — the permit is shared, not the range \
         path's alone"
    );
    assert_eq!(token(&meta_shed).as_deref(), Some("unavailable"));
    assert_eq!(
        read_budget.in_flight(),
        0,
        "a meta read shed at the queue never reached the store and \
         charges nothing"
    );

    // THE CONTROL: a read that is not PERMITTED is served while
    // every read permit is still held.
    let other = read_under(
        &store,
        &read_budget,
        &read_permits,
        Duration::from_millis(50),
        "/volume/v/max-seq",
        None,
    )
    .await;
    assert_eq!(
        other.status(),
        StatusCode::NOT_FOUND,
        "a `max-seq` on an empty volume answers 404, not the shared \
         pool's 503: the read permit is scoped to `GetBinRange` and \
         `GetMeta`, not to every read"
    );
    assert_eq!(token(&other).as_deref(), Some("not-found"));

    drop(taken);
    assert_eq!(read_permits.available_permits(), READ_PERMITS);
}

/// A seam whose `get_meta` PARKS on a semaphore gate that starts
/// closed, recording how many calls are inside the store at once and
/// the high-water mark of that count.
///
/// **The store-side positive control.** A count read off `answer`'s
/// own dispatch site would only prove the code PATH was taken, not
/// that the seam ever actually held more than one caller at once —
/// this fake makes "genuinely parked, concurrently" an observable
/// fact instead of an inference.
///
/// **A wrapper rather than a flag on the shared fake**, the same
/// reason [`Recorder`] is one: every method but `get_meta` forwards
/// to `inner` untouched.
struct ParkedMeta {
    inner: FakeSeam,
    in_flight: AtomicUsize,
    high_water: AtomicUsize,
    gate: Semaphore,
}

impl ParkedMeta {
    /// The gate starts at ZERO permits: every `get_meta` call parks
    /// until something calls `gate.add_permits`.
    fn new(inner: FakeSeam) -> Self {
        Self {
            inner,
            in_flight: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            gate: Semaphore::new(0),
        }
    }
}

impl RootStore for ParkedMeta {
    fn put_root(
        &self,
        volume: &str,
        seq: u64,
        bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), RootStoreError>> + Send {
        self.inner.put_root(volume, seq, bytes)
    }

    fn get_root(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, RootStoreError>> + Send {
        self.inner.get_root(volume, seq)
    }

    fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> impl std::future::Future<Output = Result<HintRead, RootStoreError>> + Send {
        self.inner.read_hint(volume, cached)
    }

    fn write_hint(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl std::future::Future<Output = Result<(), RootStoreError>> + Send {
        self.inner.write_hint(volume, seq)
    }

    fn max_seq(
        &self,
        volume: &str,
    ) -> impl std::future::Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.inner.max_seq(volume)
    }

    fn max_seq_above(
        &self,
        volume: &str,
        floor: u64,
    ) -> impl std::future::Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.inner.max_seq_above(volume, floor)
    }
}

impl BinStore for ParkedMeta {
    fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<bool, RootStoreError>> + Send {
        self.inner.put_bin(digest, bytes)
    }

    fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<bool, RootStoreError>> + Send {
        self.inner.put_meta(volume, id, bytes)
    }

    /// The counter spans ARRIVAL to RELEASE-FROM-THE-GATE: counted
    /// in before parking, counted out after the gate opens, and the
    /// forward to `inner` runs uncounted (immediate by construction
    /// — the shared fake answers from memory). Every counted call
    /// holds a read permit for that whole span, which is the
    /// quantity the bound is about; while the gate is CLOSED the
    /// count and "genuinely parked" coincide exactly, and the
    /// rows that read the counter only read it in that state. A
    /// refactor that opens the gate mid-observation or gives
    /// `inner` real latency changes what this measures — re-derive
    /// before trusting it there.
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.high_water.fetch_max(now, Ordering::SeqCst);
        let _permit = self.gate.acquire().await.unwrap_or_else(|e| panic!("{e}"));
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.inner.get_meta(volume, id).await
    }

    fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, RootStoreError>> + Send {
        self.inner.get_bin_range(digest, offset, len)
    }
}

/// One request through the whole adapter path, boxed so many of them
/// can be held and polled together.
type Answered = Pin<Box<dyn Future<Output = StatusCode>>>;

/// Build one boxed request against a [`ParkedMeta`], sharing every
/// process bound with every other caller of this function.
///
/// **`tokio::spawn` is banned workspace-wide with no test exemption**
/// and this row is not on the far side of the real-socket
/// boundary that owns `loopback`'s one sanctioned spawn site — so
/// concurrency here comes from many of these boxed futures being
/// polled by hand ([`poll_all`]) rather than from many tasks.
fn driven(
    store: Arc<ParkedMeta>,
    read_permits: Arc<Semaphore>,
    read_budget: Arc<ReadBudget>,
    write_budget: Arc<WriteBudget>,
    verify_pool: Arc<Semaphore>,
    target: String,
    range: Option<&'static str>,
) -> Answered {
    Box::pin(async move {
        // Held for the whole call: dropping the sender closes the
        // channel, which is a different state from "not draining".
        let (_alive, draining) = watch::channel(false);
        let bounds = Bounds {
            capture: None,
            debug_grants: None,
            authority: None,
            budget: &write_budget,
            read_budget: &read_budget,
            permits: &verify_pool,
            read_permits: &read_permits,
            // Generous: a parked meta must QUEUE on the shared pool,
            // not shed, while this row holds the pool exhausted on
            // purpose.
            permit_wait: Duration::from_secs(30),
            dispatch_deadline: None,
            #[cfg(feature = "crash-points")]
            test_reply_deadline: None,
            draining,
        };
        let mut headers = HeaderMap::new();
        if let Some(range) = range {
            let value = HeaderValue::from_str(range).unwrap_or_else(|e| panic!("{range:?}: {e}"));
            let _replaced = headers.insert(RANGE, value);
        }
        let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
        answer(
            &*store,
            "",
            VerifyPolicy::seam_only(),
            Some(DECLARED_MAX_EXTENT),
            bounds,
            &Method::GET,
            &uri,
            &headers,
            &hyper::http::Extensions::new(),
            Some(0),
            Full::new(Bytes::new()),
            &mut None,
            &mut None,
            &mut None,
        )
        .await
        .status()
    })
}

/// Poll every not-yet-finished slot once.
///
/// **The hand-rolled multiplexer `tokio::spawn`'s ban leaves
/// available.** Many boxed requests are held here as plain values;
/// this drives all of them forward on the ONE task this row has,
/// the same technique [`raced_by_the_drain`] uses for two futures,
/// generalised to N and re-invoked instead of run once.
async fn poll_all(slots: &mut [(Answered, Option<StatusCode>)]) {
    std::future::poll_fn(|context| {
        for (future, status) in slots.iter_mut() {
            if status.is_none()
                && let Poll::Ready(value) = future.as_mut().poll(context)
            {
                *status = Some(value);
            }
        }
        Poll::Ready(())
    })
    .await;
}

/// Real time, without `tokio::time::sleep` — banned — via the
/// same timeout-against-`pending` substitute this crate's loopback
/// battery uses, redefined locally because that one is private to
/// its own module.
async fn tick(gap: Duration) {
    let _expired = timeout(gap, std::future::pending::<()>()).await;
}

/// **The shared read permit bounds `GetMeta` exactly as
/// it bounds `GetBinRange`, twelve requests deep, and does not
/// starve a range read that arrives while the pool is full of
/// parked metas.**
///
/// **The store-side high-water is the positive control.** A count
/// read off `answer`'s own dispatch would only prove the predicate
/// was consulted, not that the SEAM ever held more than one call at
/// once; [`ParkedMeta`] parks every `get_meta` call on a gate that
/// starts closed and folds the concurrent count into a high-water
/// mark INSIDE the store — the only place that can tell a real bound
/// from a permit acquired and released so fast the process never
/// actually saw two readers at once.
///
/// **No `tokio::time::pause` and no immediate assert.** The pool
/// filling is a race between this row's polling and the runtime
/// scheduling twelve futures, with no bound on how many polls that
/// takes; a bounded REAL-time poll is what makes "the pool filled"
/// a measured fact rather than a hope about how fast the executor
/// runs on this machine.
///
/// **What this row does NOT pin: that the pool is the SHARED one.**
/// A private eight-slot pool for `GetMeta` alone would pass every
/// assertion here (high-water 8, range read served, permits
/// returned). The shared-pool property is held by two OTHER rows —
/// the partition row's predicate/acquisition cross-check, and the
/// shed row's meta arm, which exhausts the shared semaphore from
/// outside and demands the meta read shed with it. Lift or refactor
/// this test only with those two in view.
#[expect(
    clippy::too_many_lines,
    reason = "plant, fill, settle, interleave, release, drain: one \
              scenario with a real ordering between its phases — \
              splitting it would separate an assertion from the phase \
              that makes it mean something"
)]
#[tokio::test(flavor = "multi_thread")]
async fn n_concurrent_get_meta_are_permit_bounded_without_starving_a_resolve() {
    const N: usize = READ_PERMITS + 4;
    const TICK: Duration = Duration::from_millis(10);
    const FILL_TICKS: usize = 500; // 500 * 10ms = 5s, the bound.
    const SETTLE_TICKS: usize = 20; // 20 * 10ms = 200ms, the settle window.
    const DRAIN_TICKS: usize = 500;

    let inner = FakeSeam::default();
    // A meta object addressed by ITS OWN content: `FakeSeam::put_meta`
    // `debug_assert`s the content-address contract exactly as the
    // `granary-store` adapter does, so — unlike the PARTITION table's
    // `META_TARGET`, which is a fixed target admission never dispatches
    // to a store in that row — the digest here has to be
    // `GrainId::of` the bytes planted under it, not a chosen literal.
    let meta_body = b"a meta object every parked read resolves to".to_vec();
    let meta_id = GrainId::of(&meta_body);
    let meta_target = format!("/volume/v1/meta/{meta_id}");
    let planted_meta = inner.put_meta("v1", &meta_id, meta_body).await;
    assert!(
        planted_meta.is_ok(),
        "planting the meta every released read resolves to"
    );
    // Same reasoning for the bin the interleaved ranged GET serves
    // from: the digest is derived from the planted bytes.
    let bin_body = vec![0x5a_u8; 4096];
    let bin_id = GrainId::of(&bin_body);
    let bin_target = format!("/bin/{}", hex64(bin_id.digest()));
    let planted_bin = inner.put_bin(bin_id.digest(), bin_body).await;
    assert!(
        planted_bin.is_ok(),
        "planting the bin the interleaved range read serves from"
    );

    let store = Arc::new(ParkedMeta::new(inner));
    let read_permits = Arc::new(Semaphore::new(READ_PERMITS));
    let read_budget = Arc::new(ReadBudget::new(READ_BODY_BUDGET_BYTES));
    let write_budget = Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES));
    let verify_pool = Arc::new(Semaphore::new(verify_permits(TEST_WORKER_THREADS)));

    let mut slots: Vec<(Answered, Option<StatusCode>)> = (0..N)
        .map(|_| {
            (
                driven(
                    Arc::clone(&store),
                    Arc::clone(&read_permits),
                    Arc::clone(&read_budget),
                    Arc::clone(&write_budget),
                    Arc::clone(&verify_pool),
                    meta_target.clone(),
                    None,
                ),
                None,
            )
        })
        .collect();

    // FILL: the store-side counter reaching READ_PERMITS is the
    // proof that the pool actually admitted that many concurrently —
    // not merely that READ_PERMITS requests were dispatched.
    let mut filled = false;
    for _ in 0..FILL_TICKS {
        poll_all(&mut slots).await;
        if store.in_flight.load(Ordering::SeqCst) >= READ_PERMITS {
            filled = true;
            break;
        }
        tick(TICK).await;
    }
    assert!(
        filled,
        "the store never saw {READ_PERMITS} concurrent GetMeta calls \
         within {:?}: the pool never filled, so nothing below tests \
         the permit",
        TICK.saturating_mul(u32::try_from(FILL_TICKS).unwrap_or(u32::MAX))
    );

    // SETTLE: hold real time so an unpermitted extra has room to
    // arrive before the positive control reads the high-water mark.
    for _ in 0..SETTLE_TICKS {
        poll_all(&mut slots).await;
        tick(TICK).await;
    }
    let high_water = store.high_water.load(Ordering::SeqCst);
    assert_eq!(
        high_water, READ_PERMITS,
        "the store's high-water mark is {high_water} against a pool \
         of {READ_PERMITS}: GetMeta's aggregate is not permit-bounded"
    );

    // THE STARVATION WITNESS, interleaved while every meta is still
    // parked and the pool is exhausted — and the PARK PROOF that
    // makes its later 206 evidence: the pool must be exhausted when
    // it arrives, and it must actually QUEUE (still unanswered
    // after its poll), or "not starved" is satisfied by a range
    // read that never contended at all.
    assert_eq!(
        read_permits.available_permits(),
        0,
        "the pool must be exhausted when the range read arrives, or \
         the witness never contends"
    );
    slots.push((
        driven(
            Arc::clone(&store),
            Arc::clone(&read_permits),
            Arc::clone(&read_budget),
            Arc::clone(&write_budget),
            Arc::clone(&verify_pool),
            bin_target,
            Some("bytes=0-1023"),
        ),
        None,
    ));
    poll_all(&mut slots).await;
    assert_eq!(
        slots.last().and_then(|(_, status)| *status),
        None,
        "the interleaved range read answered while every permit was \
         held: it bypassed the pool, so its 206 below would witness \
         nothing"
    );

    // RELEASE: every parked (and every future) `get_meta` call may
    // now proceed.
    store.gate.add_permits(N);

    let mut drained = false;
    for _ in 0..DRAIN_TICKS {
        poll_all(&mut slots).await;
        if slots.iter().all(|(_, status)| status.is_some()) {
            drained = true;
            break;
        }
        tick(TICK).await;
    }
    assert!(drained, "not every request completed after the gate opened");

    let (meta_slots, range_slot) = slots.split_at(N);
    for (index, (_, status)) in meta_slots.iter().enumerate() {
        assert_eq!(
            *status,
            Some(StatusCode::OK),
            "meta request {index} did not answer 200 once released"
        );
    }
    assert_eq!(
        range_slot.first().and_then(|(_, status)| *status),
        Some(StatusCode::PARTIAL_CONTENT),
        "the interleaved range read did not answer 206: the shared \
         permit starved it instead of merely queuing it"
    );
    let high_water_end = store.high_water.load(Ordering::SeqCst);
    assert_eq!(
        high_water_end, READ_PERMITS,
        "the monotone high-water mark reads {high_water_end} at the \
         end of the run against a pool of {READ_PERMITS} — the \
         backstop re-check of the settle-window assert above, on the \
         same counter after the drain"
    );
    assert_eq!(
        store.in_flight.load(Ordering::SeqCst),
        0,
        "the parked-meta counter did not return to zero: the fake's \
         own bookkeeping is imbalanced and every reading above is \
         suspect"
    );
    assert_eq!(
        read_permits.available_permits(),
        READ_PERMITS,
        "the read-permit pool did not return every permit"
    );
}

/// **A served range read returns its permit.**
///
/// A permit held past the store call is a bound that tightens by one
/// on every request until the server answers nothing — the failure
/// mode an RAII guard exists to make unreachable, asserted rather
/// than assumed.
#[tokio::test]
async fn a_range_read_returns_its_read_permit() {
    const STORED: usize = 4096;
    let (store, target) = planted(STORED).await;
    let (read_budget, read_permits) = ample_read();

    for _ in 0..(READ_PERMITS * 2) {
        let response = read_under(
            &store,
            &read_budget,
            &read_permits,
            VERIFY_PERMIT_MAX_WAIT,
            &target,
            Some(WIDE),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            read_permits.available_permits(),
            READ_PERMITS,
            "the permit is released when the store call ends, not when \
             the response is dropped"
        );
    }
    assert_eq!(read_budget.in_flight(), 0);
}

/// A seam whose range read hands back a buffer with SPARE CAPACITY.
///
/// The one shape none of the rows above can produce: `FakeSeam`
/// slices with `to_vec`, which is exact, so every charge it can be
/// asked for is a charge where `len` and `capacity` agree — and a
/// budget charging the wrong one of the two would pass every one of
/// them. The real producer overshoots by growth doubling, and
/// `Bytes::from(Vec)` shrinks only on an exact fit, so the overshoot
/// is resident for the whole response.
struct RoomySeam;

/// What [`RoomySeam`] DELIVERS.
const ROOMY_LEN: usize = 1000;
/// What it HOLDS. The factor is the measured one at the declared
/// maximum extent, rounded up.
const ROOMY_CAPACITY: usize = 1720;

impl RootStore for RoomySeam {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        std::future::pending().await
    }
    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        std::future::pending().await
    }
    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        std::future::pending().await
    }
    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        std::future::pending().await
    }
    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        std::future::pending().await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

impl BinStore for RoomySeam {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        std::future::pending().await
    }
    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        std::future::pending().await
    }
    async fn get_meta(&self, _volume: &str, _id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        std::future::pending().await
    }
    async fn get_bin_range(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let mut out = Vec::with_capacity(ROOMY_CAPACITY);
        out.extend(std::iter::repeat_n(0x5a_u8, ROOMY_LEN));
        Ok(out)
    }
}

/// **The charge is the buffer's CAPACITY, not its length.**
///
/// The distinction is the whole difference between an accounting and
/// a decoration. Capacity is what the allocator is holding and what
/// the transport keeps hold of — `Bytes::from(Vec)` reuses the
/// allocation and shrinks it only on an exact fit — so a budget
/// charging `len()` under-counts by whatever the producer overshot,
/// and a budget that under-counts admits more than it says it does.
/// Every other row in this file uses a seam whose buffers are exactly
/// sized, which is precisely why `len()` would pass all of them.
#[tokio::test]
async fn the_charge_is_the_capacity_and_not_the_length() {
    let (read_budget, read_permits) = ample_read();
    let target = format!("/bin/{}", hex64(&[0xCC_u8; DIGEST_LEN]));

    let response = read_under(
        &RoomySeam,
        &read_budget,
        &read_permits,
        VERIFY_PERMIT_MAX_WAIT,
        &target,
        Some(WIDE),
    )
    .await;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        read_budget.in_flight(),
        ROOMY_CAPACITY as u64,
        "the seam delivered {ROOMY_LEN} bytes in a {ROOMY_CAPACITY}-byte \
         allocation, and the allocation is what stays resident"
    );
    drop(response);
    assert_eq!(read_budget.in_flight(), 0);
}

/// **The read permit is held ACROSS the store call**, which is
/// the only interval in which it bounds anything.
///
/// Every other permit row is satisfied by a permit acquired and
/// released on the next line: the queue still blocks when the
/// semaphore is empty, and the count still returns to full after a
/// served read. What none of them can see is a permit that is not
/// held while the buffer is being allocated — which is the entire
/// bound. So this one parks a read INSIDE a seam that never answers
/// and reads the count from outside.
///
/// Hand-polled rather than raced against a clock, because a clock
/// would have to expire before the assertion could run and the expiry
/// releases the very permit being asked about.
#[tokio::test]
async fn a_read_permit_is_held_across_the_store_call() {
    use std::pin::pin;
    use std::task::{Context, Waker};

    let (read_budget, read_permits) = ample_read();
    let target = format!("/bin/{}", hex64(&[0xDD_u8; DIGEST_LEN]));
    assert_eq!(read_permits.available_permits(), READ_PERMITS);

    // **A BLOCK, and not a `drop(..)` call.** `pin!` hands back a
    // `Pin<&mut F>` whose pointee lives in the enclosing scope, so
    // dropping the handle drops a POINTER and leaves the future — and
    // its permit — exactly where they were. In this fixture, dropping
    // the pinned handle fails the release assertion at 7 of 8, which
    // is the test being wrong rather than the guard. The scope is
    // what actually ends the future.
    {
        let mut parked = pin!(read_under(
            &StalledSeam,
            &read_budget,
            &read_permits,
            VERIFY_PERMIT_MAX_WAIT,
            &target,
            Some(WIDE),
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            parked.as_mut().poll(&mut context).is_pending(),
            "a seam that never answers cannot have produced a response"
        );

        // THE PARK PROOF, read from outside the parked request.
        assert_eq!(
            read_permits.available_permits(),
            READ_PERMITS - 1,
            "the request is inside a store that never answers and is \
             not holding a read permit: the permit bounds nothing"
        );
        assert_eq!(
            read_budget.in_flight(),
            0,
            "and nothing came back, so nothing is charged"
        );
    }

    // The peer disappeared — the future was dropped mid-await, which
    // is the one exit no matched release call could cover.
    assert_eq!(
        read_permits.available_permits(),
        READ_PERMITS,
        "a dropped request returns its permit"
    );
}

/// What the shed is HOLDING, with a destructor the test can read.
///
/// The reason [`shed_then_drain`] is generic: the real value is an
/// [`Outcome`] whose body is a `Vec<u8>`, and a `Vec`'s destructor is
/// invisible — no unsafe polling fixture is licensed here, so
/// this suite cannot install a counting allocator and ask the heap
/// instead. This type answers both halves of the ordering: WHETHER
/// the bytes were given up before the drain, and WHETHER the permit
/// was still held at the instant they were.
struct Held {
    semaphore: Arc<Semaphore>,
    given_up: Arc<AtomicBool>,
    permits_when_given_up: Arc<AtomicUsize>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.permits_when_given_up
            .store(self.semaphore.available_permits(), Ordering::SeqCst);
        self.given_up.store(true, Ordering::SeqCst);
    }
}

/// Request content that RECORDS the process state at the first poll
/// of the drain — the instant the shed's bytes must already be gone.
///
/// One frame's worth of nothing: the recording is the point, and a
/// body that ended without ever being polled would make every
/// assertion below vacuous, which is what the `polled` assertion in
/// the row guards.
struct Watching {
    semaphore: Arc<Semaphore>,
    given_up: Arc<AtomicBool>,
    given_up_at_drain: Arc<AtomicBool>,
    permits_at_drain: Arc<AtomicUsize>,
    polled: Arc<AtomicBool>,
}

impl Body for Watching {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if !this.polled.swap(true, Ordering::SeqCst) {
            this.given_up_at_drain
                .store(this.given_up.load(Ordering::SeqCst), Ordering::SeqCst);
            this.permits_at_drain
                .store(this.semaphore.available_permits(), Ordering::SeqCst);
        }
        Poll::Ready(None)
    }
}

/// **A shed gives up its BYTES before it drains the request
/// content, and the permit outlives them.**
///
/// The shed path is the one place where nothing takes over from the
/// permit. On the charged path the charge does — the bytes are
/// accounted from the store call to the response's destructor — so
/// releasing the permit and then draining holds nothing unwatched.
/// On the shed path the budget has just REFUSED to account for this
/// buffer, and the ordering that released the permit first and let
/// the buffer live through `drain_to_budget` held an uncharged,
/// unpermitted extent for up to [`DRAIN_MAX_WAIT`] per shed stream,
/// at the exact moment the process had declared itself too loaded to
/// hold it.
///
/// **Asserted on RESIDENCY and not on the status**, which is the only
/// reason this row can see the defect at all: both orderings answer
/// `503` + `unavailable`, charge nothing, and end with every permit
/// back. What separates them is WHEN the bytes go, and the two
/// assertions below are the two halves of that — the bytes before the
/// drain, the permit after the bytes.
#[tokio::test]
async fn a_shed_gives_up_its_bytes_before_the_drain() {
    let semaphore = Arc::new(Semaphore::new(READ_PERMITS));
    let given_up = Arc::new(AtomicBool::new(false));
    let given_up_at_drain = Arc::new(AtomicBool::new(false));
    let polled = Arc::new(AtomicBool::new(false));
    // `usize::MAX` rather than zero: an unwritten reading must not be
    // mistakable for a real one.
    let permits_when_given_up = Arc::new(AtomicUsize::new(usize::MAX));
    let permits_at_drain = Arc::new(AtomicUsize::new(usize::MAX));

    let permit = semaphore
        .try_acquire()
        .unwrap_or_else(|error| panic!("a fresh semaphore has a permit: {error}"));
    // THE PARK PROOF: the permit is genuinely held on the way in, so
    // a reading of `READ_PERMITS - 1` below is a permit still held
    // rather than one that was never taken.
    assert_eq!(semaphore.available_permits(), READ_PERMITS - 1);

    let budget = ample();
    let drain = shed_then_drain(
        Held {
            semaphore: Arc::clone(&semaphore),
            given_up: Arc::clone(&given_up),
            permits_when_given_up: Arc::clone(&permits_when_given_up),
        },
        Some(permit),
        Watching {
            semaphore: Arc::clone(&semaphore),
            given_up: Arc::clone(&given_up),
            given_up_at_drain: Arc::clone(&given_up_at_drain),
            permits_at_drain: Arc::clone(&permits_at_drain),
            polled: Arc::clone(&polled),
        },
        &budget,
    )
    .await;

    assert_eq!(drain, Drain::Drained);
    assert!(
        polled.load(Ordering::SeqCst),
        "the drain never polled the content, so every reading below is \
         an unwritten one and this row asserts nothing"
    );
    assert!(
        given_up_at_drain.load(Ordering::SeqCst),
        "the shed was still holding its buffer when the drain began: \
         an uncharged, unpermitted extent resident for up to \
         {DRAIN_MAX_WAIT:?} per shed stream, decided on by the peer, \
         at the moment the budget said it could not hold it"
    );
    assert_eq!(
        permits_when_given_up.load(Ordering::SeqCst),
        READ_PERMITS - 1,
        "the permit was released BEFORE the bytes it was standing in \
         for: the one bound over what the budget cannot see was gone \
         while the bytes were still there, so the next read enters the \
         store against a transient that is already resident"
    );
    assert_eq!(
        permits_at_drain.load(Ordering::SeqCst),
        READ_PERMITS,
        "and the permit must not linger through the drain either: the \
         bytes are gone by then, and holding a slot for a peer-paced \
         await would shed reads this process could serve"
    );
}

// ----------------------------------------- the instrumentation floor

/// One `served` event's FIELDS as a Layer saw them — never the
/// rendered line, which is the whole distinction the floor rests on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Served {
    status: Option<u64>,
    error: Option<String>,
    bytes: Option<u64>,
    /// What `accept_body` counted for THIS request, `None`
    /// on every read and on the declared-length fast-path refusal —
    /// see `served`'s own doc for the `Option` discipline.
    request_bytes: Option<u64>,
    overflowed: Option<bool>,
    operation: Option<String>,
}

/// One `internal failure` event's fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct StoreFailure {
    kind: Option<String>,
    detail: Option<String>,
    /// The event's LEVEL, which every row here would otherwise be
    /// blind to: `capturing()` builds a stack under an explicit TRACE ceiling,
    /// so an event demoted to DEBUG stays visible to this Layer while the shipped
    /// subscriber — `EnvFilter` defaulting to INFO, above the whole stack — drops
    /// its callsite outright.
    level: Option<String>,
}

/// What one span's attributes or one event carried.
#[derive(Default)]
struct Fields {
    message: Option<String>,
    request_id: Option<u64>,
    method: Option<String>,
    served: Served,
    store: StoreFailure,
}

impl tracing::field::Visit for Fields {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "request_id" => self.request_id = Some(value),
            "status" => self.served.status = Some(value),
            "bytes" => self.served.bytes = Some(value),
            "request_bytes" => self.served.request_bytes = Some(value),
            _other => {}
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if field.name() == "overflowed" {
            self.served.overflowed = Some(value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.text(field.name(), value);
    }

    /// The fallback every other `record_*` funnels through.
    ///
    /// Read as well as `record_str` and not instead of it: whether a
    /// `%`-sigil field or a message literal arrives as a `&str` or
    /// as `fmt::Arguments` is `tracing`'s business and has changed
    /// between releases, so this row reads both spellings rather
    /// than pinning one.
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        self.text(field.name(), rendered.trim_matches('"'));
    }
}

impl Fields {
    /// One string-valued field, from whichever `record_*` delivered it.
    fn text(&mut self, name: &str, value: &str) {
        match name {
            "message" => self.message = Some(value.to_owned()),
            "method" => self.method = Some(value.to_owned()),
            "error" => self.served.error = Some(value.to_owned()),
            "operation" => self.served.operation = Some(value.to_owned()),
            "kind" => self.store.kind = Some(value.to_owned()),
            "detail" => self.store.detail = Some(value.to_owned()),
            _other => {}
        }
    }
}

/// Everything the capture Layer recorded, in the order it arrived.
#[derive(Debug, Default)]
struct Recorded {
    /// Every `grain_request` span's `request_id`, at span creation.
    request_ids: Vec<u64>,
    /// Every `grain_request` span's `method`.
    methods: Vec<String>,
    /// Every `served` event.
    served: Vec<Served>,
    /// Every OTHER event's message, so a row can say "exactly one
    /// `served`" and mean it.
    others: Vec<String>,
    /// Every `internal failure` event.
    store_failures: Vec<StoreFailure>,
}

/// A Layer that records `grain_request` spans and `served` events —
/// **and deliberately NOT the sink**.
///
/// This makes the exact-dispatch claim runnable: `tracing` dispatches events
/// synchronously. This observer runs after fmt has formatted and discarded the
/// line, so it still records events when the baseline writer drops every line.
#[derive(Clone, Debug)]
struct Capture(Arc<std::sync::Mutex<Recorded>>);

impl Capture {
    fn read(&self) -> std::sync::MutexGuard<'_, Recorded> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if attributes.metadata().name() != "grain_request" {
            return;
        }
        let mut fields = Fields::default();
        attributes.record(&mut fields);
        let mut recorded = self.read();
        if let Some(id) = fields.request_id {
            recorded.request_ids.push(id);
        }
        if let Some(method) = fields.method {
            recorded.methods.push(method);
        }
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let mut recorded = self.read();
        match fields.message.as_deref() {
            Some("served") => recorded.served.push(fields.served),
            Some("internal failure") => {
                let mut failure = fields.store;
                failure.level = Some(event.metadata().level().to_string());
                recorded.store_failures.push(failure);
            }
            other => recorded.others.push(other.unwrap_or_default().to_owned()),
        }
    }
}

/// The [`LossyStderr`](crate::sink::LossyStderr) writer in its
/// DROPPING state, modelled at total loss.
///
/// **A model, and this is exactly how faithful it is.** `LossyLine`
/// accumulates bytes in `write` and decides in `flush` — reached
/// from its own `Drop` — whether the line joins the queue or is
/// discarded and counted. This does the same and always takes the
/// discard arm, so the loss sits at the same place in the same call:
/// inside the `fmt` Layer's `on_event`, downstream of the
/// dispatcher's synchronous fan-out. That placement is the ONLY
/// property the floor statement rests on.
///
/// What it does not model is the queue — this drops every line where
/// the shipped sink drops only under backpressure, which is the
/// strictly harsher condition and therefore the stronger witness.
///
/// **`formatted` is the positive control.** Without it "the capture
/// Layer saw the event and the writer wrote nothing" is equally
/// consistent with a `fmt` Layer that never ran at all — a filter
/// that excluded it, a builder that dropped it — and the row would
/// be asserting nothing about a fan-out it never exercised.
#[derive(Clone, Debug, Default)]
struct DroppingWriter {
    /// Bytes the `fmt` Layer actually formatted and handed over.
    formatted: Arc<AtomicUsize>,
    /// Lines discarded rather than written anywhere.
    dropped: Arc<AtomicUsize>,
    /// Each discarded line's rendered text, in the order the `fmt`
    /// Layer produced it.
    ///
    /// A COUNT cannot say which lines were rendered or in what
    /// order, and both are part of the queue claim: the module doc
    /// argues about which line reaches the sink FIRST when the queue
    /// is full, and only the sequence witnesses that. The span-close
    /// line is visible nowhere else — [`Capture`] is an event Layer
    /// and `FmtSpan::CLOSE` is not an event any Layer's `on_event`
    /// sees — so the writer is the only place both halves meet.
    lines: Arc<std::sync::Mutex<Vec<String>>>,
}

impl DroppingWriter {
    fn formatted(&self) -> usize {
        self.formatted.load(Ordering::SeqCst)
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }

    /// The `message` of every rendered line, in emission order.
    fn messages(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|line| rendered_message(line))
            .collect()
    }
}

/// The `message` field of one rendered JSON line.
///
/// **Exactly one occurrence is REQUIRED, not the first one taken.**
/// The lines these rows render carry store text in a `detail` field,
/// and a `detail` that happened to contain the key would make a
/// "first match wins" reading name the wrong line — quietly, and in
/// the one row whose whole subject is which line came first. A
/// second occurrence is a fixture this helper cannot read, so it
/// says so instead of guessing.
fn rendered_message(line: &str) -> String {
    let mut parts = line.split("\"message\":\"");
    let _before = parts.next();
    let Some(after) = parts.next() else {
        panic!("no `message` field in a rendered line: {line}");
    };
    assert!(
        parts.next().is_none(),
        "two `message` fields in one rendered line, so which one names \
         the line is a guess: {line}"
    );
    let Some((message, _rest)) = after.split_once('"') else {
        panic!("unterminated `message` field in a rendered line: {line}");
    };
    message.to_owned()
}

struct DroppingLine {
    formatted: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    lines: Arc<std::sync::Mutex<Vec<String>>>,
    line: Vec<u8>,
}

impl std::io::Write for DroppingLine {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.line.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.line.is_empty() {
            return Ok(());
        }
        let _bytes = self.formatted.fetch_add(self.line.len(), Ordering::SeqCst);
        let _lines = self.dropped.fetch_add(1, Ordering::SeqCst);
        self.lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(String::from_utf8_lossy(&self.line).into_owned());
        self.line.clear();
        Ok(())
    }
}

impl Drop for DroppingLine {
    fn drop(&mut self) {
        let _best_effort = std::io::Write::flush(self);
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DroppingWriter {
    type Writer = DroppingLine;

    fn make_writer(&'a self) -> Self::Writer {
        DroppingLine {
            formatted: Arc::clone(&self.formatted),
            dropped: Arc::clone(&self.dropped),
            lines: Arc::clone(&self.lines),
            line: Vec::new(),
        }
    }
}

/// Use the production JSON/CLOSE constructor with an event observer and a
/// dropping baseline writer. `HostDiagnostics` is inner and the observer is outer:
/// Layered calls the inner `on_event` first, so fmt has already handed the line to
/// the writer and discarded it when the observer records the event. This ordering
/// makes survival after rendering loss a measurement. The ceiling wraps both.
fn capturing() -> (
    Capture,
    DroppingWriter,
    impl tracing::Subscriber + Send + Sync,
) {
    capturing_under("trace")
}

fn capturing_under(
    directive: &str,
) -> (
    Capture,
    DroppingWriter,
    impl tracing::Subscriber + Send + Sync,
) {
    let capture = Capture(Arc::new(std::sync::Mutex::new(Recorded::default())));
    let writer = DroppingWriter::default();
    let (sink, _queued) = crate::sink::tests::queue();
    let (_handle, subscriber) = crate::diagnostics::host_subscriber_with_observer(
        tracing_subscriber::EnvFilter::new(directive),
        writer.clone(),
        sink,
        true,
        capture.clone(),
    );
    (capture, writer, subscriber)
}

#[tokio::test]
async fn instrumentation_observer_records_only_after_baseline_render() {
    #[derive(Clone)]
    struct AfterFmt {
        writer: DroppingWriter,
        served: Arc<AtomicUsize>,
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AfterFmt {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            if fields.message.as_deref() == Some("served") {
                assert_eq!(
                    self.writer.messages().last().map(String::as_str),
                    Some("served"),
                    "baseline fmt must render the line before the observer records its event"
                );
                self.served.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let writer = DroppingWriter::default();
    let served = Arc::new(AtomicUsize::new(0));
    let observer = AfterFmt {
        writer: writer.clone(),
        served: Arc::clone(&served),
    };
    let (sink, _lines) = crate::sink::tests::queue();
    let (_, subscriber) = crate::diagnostics::host_subscriber_with_observer(
        tracing_subscriber::EnvFilter::new("info"),
        writer.clone(),
        sink,
        true,
        observer,
    );
    let _default = tracing::subscriber::set_default(subscriber);
    let response = instrumented(
        &FakeSeam::default(),
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        "/volume/t/max-seq",
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        served.load(Ordering::Relaxed),
        1,
        "observer records the actual served event"
    );
    assert_eq!(writer.messages(), ["served", "close"]);
}

/// One request through the SHIPPED instrumented entry point.
///
/// `respond` and not `answer`: the span and the `served` event live
/// there, so a row driving `answer` would assert nothing about
/// either. This is why `respond` is generic in its body — hyper's
/// `Incoming` has no constructor.
async fn instrumented<R: RootStore + BinStore>(
    store: &R,
    write_budget: u64,
    method: &Method,
    target: &str,
    range: Option<&str>,
    body: Vec<u8>,
) -> Response<Full<Bytes>> {
    let budget = Arc::new(WriteBudget::new(write_budget));
    let read_budget = Arc::new(ReadBudget::new(READ_BODY_BUDGET_BYTES));
    let permits = Semaphore::new(verify_permits(TEST_WORKER_THREADS));
    let read_permits = Semaphore::new(READ_PERMITS);
    // Held for the whole await: dropping the sender closes the
    // channel, which is a different state from "not draining".
    let (_alive, draining) = watch::channel(false);
    let bounds = Bounds {
        capture: None,
        debug_grants: None,
        authority: None,
        budget: &budget,
        read_budget: &read_budget,
        permits: &permits,
        read_permits: &read_permits,
        permit_wait: VERIFY_PERMIT_MAX_WAIT,
        dispatch_deadline: None,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: None,
        draining,
    };
    let uri: Uri = target.parse().unwrap_or_else(|e| panic!("{target:?}: {e}"));
    let mut request = Request::new(Full::new(Bytes::from(body)));
    *request.method_mut() = method.clone();
    *request.uri_mut() = uri;
    if let Some(range) = range {
        let value = HeaderValue::from_str(range).unwrap_or_else(|e| panic!("{range:?}: {e}"));
        let _replaced = request.headers_mut().insert(RANGE, value);
    }
    respond(
        store,
        "",
        VerifyPolicy::seam_only(),
        Some(DECLARED_MAX_EXTENT),
        bounds,
        request,
    )
    .await
}

/// A `{seq}` in §4.3's form: exactly [`SEQ_KEY_DIGITS`] ASCII digits.
fn seq_key(seq: u64) -> String {
    format!("{seq:0SEQ_KEY_DIGITS$}")
}

/// **A store failure the wire may not describe is described
/// in the LOG.**
///
/// This is the family where the store REPORTED a failure and its own
/// words are the diagnosis. The sibling family — where it reported
/// SUCCESS and broke a pinned rule — is
/// [`a_store_that_breaks_its_contract_is_logged_with_the_rule_it_broke`].
///
/// An operator whose `GRANARY_STORE_BUCKET` does not exist sees
/// `status=500 error=internal` on every request, for as long as the
/// server runs, with the cause recorded NOWHERE — §8.4 forbids
/// putting the store's text on the wire and until this row nothing
/// put it anywhere else. `config.rs` explains why the answer is not
/// a startup probe; this is the other half.
///
/// The fixture is a range past the end of a stored object, which is
/// the `Backend` error `no_refusal_discloses_what_the_store_said`
/// drives at the wire — so the same request is asserted from both
/// sides: the store's own words in the log HERE, and their absence
/// from every byte the peer receives THERE.
#[tokio::test]
async fn a_seam_failure_puts_the_store_s_own_words_in_the_log() {
    let (capture, writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    let (store, target) = planted(16).await;
    let response = instrumented(
        &store,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        &target,
        // Past the end of a 16-byte object, under the §7.3 ceiling:
        // the seam answers `Backend`, and the server cannot tell it
        // from an outage.
        Some("bytes=200-207"),
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    assert!(
        writer.formatted() > 0,
        "the fmt Layer formatted nothing, so this row exercised no fan-out"
    );
    let recorded = capture.read();
    assert_eq!(
        recorded.served.len(),
        1,
        "one request, one served event: {:?}",
        recorded.served
    );
    // The `served` event's OTHER fields are UNCHANGED, and that is
    // deliberate: it is the per-request counting substrate and every field on
    // it has a closed domain. `request_bytes` is `None` here because
    // this is a read — no write-cap accept ever ran. See
    // `seam_failure` for why the diagnostic is a separate event
    // rather than a field here.
    assert_eq!(
        recorded.served.first(),
        Some(&Served {
            status: Some(500),
            error: Some("internal".to_owned()),
            bytes: Some(0),
            request_bytes: None,
            overflowed: Some(false),
            operation: Some("get_bin_range".to_owned()),
        })
    );

    let [failure] = recorded.store_failures.as_slice() else {
        panic!(
            "want exactly one `internal failure` event, got {:?}",
            recorded.store_failures
        );
    };
    assert_eq!(
        failure.kind.as_deref(),
        Some("backend"),
        "the VARIANT, from a closed set — this is the field an exporter can count"
    );
    assert_eq!(
        failure.detail.as_deref(),
        Some("invalid range: starts at or past the end of the object"),
        "and the store's own text, which is the only thing that names a missing bucket"
    );
    // **The level is part of the property, not presentation.** This
    // stack has no `EnvFilter` by design, so a demotion to DEBUG
    // would leave every assertion above green while production —
    // whose filter defaults to INFO and sits ABOVE the whole layer
    // stack — stopped emitting the callsite entirely, and the
    // operator this event exists for would be back to
    // `500 internal` and nothing else.
    assert_eq!(
        failure.level.as_deref(),
        Some("WARN"),
        "a store that cannot answer is an operational fault, and the default filter has to \
         admit it without an operator knowing to raise RUST_LOG first"
    );
}

/// **The clip is a BOUND, and this is the row that makes it one.**
///
/// `handlers::STORE_DETAIL_MAX` exists because the text it clips is
/// not granary's: `object_store` 0.14.1 embeds the endpoint's own
/// response body in two of its error arms, so an unbounded `detail`
/// is an amplifier reaching a queue bounded in LINES, not bytes.
/// Every other row here uses a 52-byte fixture, so DELETING the clip
/// leaves all of them green — which is exactly the mutation this
/// exists to fail.
///
/// Driven through the shipped funnel with a seam that answers a long
/// `Backend`, rather than by calling the clip directly: what is
/// under test is that the LOG PATH applies it.
#[tokio::test]
async fn a_long_store_message_is_clipped_before_it_reaches_the_log() {
    /// A seam whose every answer is an oversized backend error.
    struct Verbose;

    /// Longer than the clip by a wide margin, and NOT ASCII — a
    /// naive `&text[..MAX]` would panic mid-character on this
    /// rather than truncate, on a path only reached when something
    /// has already gone wrong.
    fn shouting() -> String {
        "é".repeat(4096)
    }

    impl RootStore for Verbose {
        async fn put_root(&self, _v: &str, _s: u64, _b: Vec<u8>) -> Result<(), RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
        async fn get_root(&self, _v: &str, _s: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
        async fn max_seq(&self, _v: &str) -> Result<Option<u64>, RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }

        async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
            Ok(filter_above(self.max_seq(v).await?, floor))
        }
        async fn write_hint(&self, _v: &str, _s: u64) -> Result<(), RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
        async fn read_hint(
            &self,
            _v: &str,
            _c: Option<&HintToken>,
        ) -> Result<HintRead, RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
    }

    impl BinStore for Verbose {
        async fn put_bin(
            &self,
            _d: &[u8; DIGEST_LEN],
            _b: Vec<u8>,
        ) -> Result<bool, RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
        async fn put_meta(
            &self,
            _v: &str,
            _i: &GrainId,
            _b: Vec<u8>,
        ) -> Result<bool, RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
        async fn get_meta(&self, _v: &str, _i: &GrainId) -> Result<Vec<u8>, RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
        async fn get_bin_range(
            &self,
            _d: &[u8; DIGEST_LEN],
            _o: u64,
            _l: u32,
        ) -> Result<Vec<u8>, RootStoreError> {
            Err(RootStoreError::Backend(shouting()))
        }
    }

    let (capture, _writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    let response = instrumented(
        &Verbose,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        "/volume/t/max-seq",
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let recorded = capture.read();
    let [failure] = recorded.store_failures.as_slice() else {
        panic!(
            "want one internal failure, got {:?}",
            recorded.store_failures
        );
    };
    let detail = failure
        .detail
        .as_deref()
        .unwrap_or_else(|| panic!("a Backend error carries text: {failure:?}"));
    assert!(
        detail.len() <= crate::handlers::STORE_DETAIL_MAX,
        "the store's text reached the log unbounded: {} bytes",
        detail.len()
    );
    // And it is a PREFIX of what the store said, not a summary or an
    // empty string — a clip that emptied the field would satisfy the
    // bound above and diagnose nothing.
    assert!(
        !detail.is_empty() && shouting().starts_with(detail),
        "the clipped text must be a prefix of the store's own: {detail:?}"
    );
}

/// The digest [`Liar`] answers with MORE bytes than were asked for.
fn liar_over_read() -> [u8; DIGEST_LEN] {
    *GrainId::of(b"liar: answers more than it was asked for").digest()
}

/// The digest [`Liar`] answers with NO bytes at all.
fn liar_empty() -> [u8; DIGEST_LEN] {
    *GrainId::of(b"liar: answers a range with no bytes at all").digest()
}

/// A seam that answers `Ok` with values its own pinned contract
/// forbids — **the store MISBEHAVING, which is a different thing
/// from the store failing.**
///
/// Every fake elsewhere in this crate is held to the shared
/// conformance bodies precisely so it cannot do this. That is what
/// makes a deliberate liar necessary: the arms under test only run
/// when a store breaks a rule every conforming implementation
/// keeps, so no honest fixture reaches them.
///
/// Which lie it tells is selected by the KEY it is asked for, so one
/// type covers every arm and the row's table reads as the rule list
/// it is.
struct Liar;

impl RootStore for Liar {
    async fn put_root(&self, _v: &str, _s: u64, _b: Vec<u8>) -> Result<(), RootStoreError> {
        Ok(())
    }
    async fn get_root(&self, volume: &str, _s: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        if volume == "over-root" {
            // One byte past the frozen ceiling: the smallest lie
            // that breaks the rule, so the row cannot pass by
            // accident on a bound that moved.
            let over = usize::try_from(ROOT_MAX_BYTES).unwrap_or(usize::MAX);
            return Ok(Some(vec![0x5a; over.saturating_add(1)]));
        }
        Ok(None)
    }
    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        match volume {
            "zero" => Ok(Some(0)),
            "reserved" => Ok(Some(u64::MAX)),
            _other => Ok(None),
        }
    }
    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
    async fn write_hint(&self, _v: &str, _s: u64) -> Result<(), RootStoreError> {
        Ok(())
    }
    async fn read_hint(
        &self,
        volume: &str,
        _cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        match volume {
            // A token carrying a DQUOTE fails RFC 9110 §8.8.3's
            // `etagc` both bare and wrapped, so `validator` answers
            // `None` on both routes.
            "badtoken" => Ok(HintRead::Current {
                seq: 5,
                token: HintToken("not \"a\" strong entity-tag".to_owned()),
            }),
            // `NotModified` for a request that sent no
            // `If-None-Match`: there is no validator to echo, and §6
            // requires the `304` to carry one.
            "notmodified" => Ok(HintRead::NotModified),
            _other => Ok(HintRead::Missing),
        }
    }
}

impl BinStore for Liar {
    async fn put_bin(&self, _d: &[u8; DIGEST_LEN], _b: Vec<u8>) -> Result<bool, RootStoreError> {
        Ok(true)
    }
    async fn put_meta(&self, _v: &str, _i: &GrainId, _b: Vec<u8>) -> Result<bool, RootStoreError> {
        Ok(true)
    }
    async fn get_meta(&self, volume: &str, _i: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        if volume == "over-meta" {
            let over = usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX);
            return Ok(vec![0x5a; over.saturating_add(1)]);
        }
        Err(RootStoreError::NotFound)
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        _o: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        if *digest == liar_over_read() {
            // One byte past what the request could have asked for.
            let width = usize::try_from(len).unwrap_or(usize::MAX);
            return Ok(vec![0x5a; width.saturating_add(1)]);
        }
        if *digest == liar_empty() {
            return Ok(Vec::new());
        }
        Err(RootStoreError::NotFound)
    }
}

/// Each invalid store reply must produce one warning naming the broken rule.
/// The client gets an empty 500 response for every case.
#[tokio::test]
async fn a_store_that_breaks_its_contract_is_logged_with_the_rule_it_broke() {
    let over_read = liar_over_read();
    let empty = liar_empty();
    let meta_id = GrainId::of(b"liar: an oversized meta object");

    for (target, range, want_kind, want_detail) in [
        (
            format!("/bin/{}", hex64(&over_read)),
            Some("bytes=0-7"),
            "contract-over-read",
            "a ranged read may return fewer bytes than requested, but the store returned more",
        ),
        (
            format!("/bin/{}", hex64(&empty)),
            Some("bytes=0-7"),
            "contract-extent",
            "the seam's answer has no legal Content-Range to declare — a zero-byte body, \
             or a last position past u64",
        ),
        (
            format!("/volume/over-meta/meta/{meta_id}"),
            None,
            "contract-over-cap",
            "the seam answered an object larger than the frozen format ceiling for its kind",
        ),
        (
            format!("/volume/over-root/root/{}", seq_key(7)),
            None,
            "contract-over-cap",
            "the seam answered an object larger than the frozen format ceiling for its kind",
        ),
        (
            "/volume/zero/max-seq".to_owned(),
            None,
            "contract-zero-seq",
            "the store returned sequence 0, which is invalid as a head",
        ),
        (
            "/volume/reserved/max-seq".to_owned(),
            None,
            "contract-reserved-seq",
            "the seam answered u64::MAX as a head; it is RESERVED and never a head, \
             and one planted root is enough to provoke this",
        ),
        (
            "/volume/badtoken/hint".to_owned(),
            None,
            "contract-hint-validator",
            "the store returned a hint token that cannot form the required strong ETag",
        ),
        (
            "/volume/notmodified/hint".to_owned(),
            None,
            "contract-stale-not-modified",
            "the store returned NotModified for a hint read with no usable cached validator \
             for the 304 response ETag",
        ),
    ] {
        let (capture, _writer, subscriber) = capturing();
        let _default = tracing::subscriber::set_default(subscriber);

        let response = instrumented(
            &Liar,
            WRITE_BODY_BUDGET_BYTES,
            &Method::GET,
            &target,
            range,
            Vec::new(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{target}"
        );
        assert_eq!(
            response.body().size_hint().exact(),
            Some(0),
            "{target}: a refusal carries no body"
        );

        let recorded = capture.read();
        let [failure] = recorded.store_failures.as_slice() else {
            panic!(
                "{target}: want exactly one internal-failure event, got {:?}",
                recorded.store_failures
            );
        };
        assert_eq!(failure.kind.as_deref(), Some(want_kind), "{target}");
        assert_eq!(
            failure.level.as_deref(),
            Some("WARN"),
            "{target}: a store breaking its contract is not a debug detail"
        );
        assert_eq!(failure.detail.as_deref(), Some(want_detail), "{target}");
    }
}

/// **THE POSITIVE CONTROL for the row above**: a request that does
/// NOT fail at the seam emits no `internal failure` event at all.
///
/// Without it, "the store's words are in the log" is satisfied by an
/// implementation that logs on every request — which would be the
/// log-flood the event's own doc comment argues about, and would
/// make the event useless for finding the failing one.
#[tokio::test]
async fn a_request_the_seam_answers_logs_no_store_failure() {
    let (capture, _writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    let (store, target) = planted(16).await;
    let response = instrumented(
        &store,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        &target,
        Some("bytes=0-15"),
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let recorded = capture.read();
    assert!(
        recorded.store_failures.is_empty(),
        "a served request logged an internal failure: {:?}",
        recorded.store_failures
    );
}

/// **The counters are EXACT, and the loss is at the writer.**
///
/// Three outcomes from three different arms of the adapter — a `206`
/// off the read path, a `404` off the seam, a `503` off the write-body
/// budget shed — and every one of them must produce exactly one
/// `served` event carrying the wire status, §8.2's token and the
/// bounded operation name.
///
/// **The writer is dropping the whole time**, which is the property
/// under test rather than a detail of the fixture: the shipped
/// subscriber's `MakeWriter` is lossy by contract, so a row that
/// captured with a working writer would prove something strictly
/// weaker than the floor statement claims.
#[tokio::test]
async fn every_request_emits_one_served_event_with_status_and_token() {
    let (capture, writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    let (read_store, read_target) = planted(16).await;
    let read = instrumented(
        &read_store,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        &read_target,
        Some("bytes=0-15"),
        Vec::new(),
    )
    .await;
    assert_eq!(read.status(), StatusCode::PARTIAL_CONTENT);

    let empty = FakeSeam::default();
    let missing = instrumented(
        &empty,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        "/volume/t/max-seq",
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    // A budget of ZERO: the first granule of content cannot be
    // charged, so the accept sheds with content left unread.
    let shed = instrumented(
        &empty,
        0,
        &Method::PUT,
        &format!("/volume/t/root/{}", seq_key(41)),
        None,
        b"a root this process will not hold".to_vec(),
    )
    .await;
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);

    // THE POSITIVE CONTROL, and it comes first: without it "the
    // capture Layer saw three events and the writer wrote nothing"
    // is equally consistent with a `fmt` Layer that never ran.
    assert!(
        writer.formatted() > 0,
        "the fmt Layer formatted nothing at all, so this row exercised \
         no fan-out and its conclusion is unearned"
    );
    assert!(
        writer.dropped() >= 3,
        "the writer must have DISCARDED at least one line per request \
         — {} discarded — or the rendering half was never lossy here",
        writer.dropped()
    );

    let recorded = capture.read();
    assert_eq!(
        recorded.served,
        vec![
            // The read: no token on a success, and the body's own
            // length. No write-cap accept ran, so `request_bytes`
            // is `None`.
            Served {
                status: Some(206),
                error: None,
                bytes: Some(16),
                request_bytes: None,
                overflowed: Some(false),
                operation: Some("get_bin_range".to_owned()),
            },
            // The seam refusal: §8.2's token verbatim, no body. Also
            // a read, so `request_bytes` is `None` here too.
            Served {
                status: Some(404),
                error: Some("not-found".to_owned()),
                bytes: Some(0),
                request_bytes: None,
                overflowed: Some(false),
                operation: Some("max_seq".to_owned()),
            },
            // The write-budget shed: content left unread, so the tear-down
            // bit is set. `accept_body` DID run and counted the one
            // frame before the budget refused it — the frame
            // rule applies here too, so `request_bytes` carries what
            // arrived (the fixture body's own 33-byte length) rather
            // than `None`.
            Served {
                status: Some(503),
                error: Some("unavailable".to_owned()),
                bytes: Some(0),
                request_bytes: Some(33),
                overflowed: Some(true),
                operation: Some("put_root".to_owned()),
            },
        ],
        "exactly one `served` event per request, with the wire status, \
         the token and the bounded operation — every one of them \
         dispatched to a Layer while the rendered line was thrown away"
    );
    assert_eq!(
        recorded.request_ids.len(),
        3,
        "one `grain_request` span per request"
    );
    assert_eq!(
        recorded.methods,
        vec!["GET".to_owned(), "GET".to_owned(), "PUT".to_owned()],
        "the span carries the method"
    );
    assert!(
        recorded.others.is_empty(),
        "nothing else on this path may emit an event — an extra one \
         is a second counter nobody agreed to: {:?}",
        recorded.others
    );
}

/// **`bytes` is what was SERVED, not what was asked for.**
///
/// Two different lengths off the same endpoint, so the field cannot
/// pass as a constant, and a refusal, whose body is empty.
#[tokio::test]
async fn the_served_bytes_field_is_the_body_length_on_reads_and_zero_on_refusals() {
    let (capture, _writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    for len in [16_usize, 4096] {
        let (store, target) = planted(len).await;
        let response = instrumented(
            &store,
            WRITE_BODY_BUDGET_BYTES,
            &Method::GET,
            &target,
            Some(WIDE),
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(body_of(response).len(), len, "the wire body");
    }

    let empty = FakeSeam::default();
    let missing = instrumented(
        &empty,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        "/volume/t/max-seq",
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let recorded = capture.read();
    let counted: Vec<Option<u64>> = recorded.served.iter().map(|row| row.bytes).collect();
    assert_eq!(
        counted,
        vec![Some(16), Some(4096), Some(0)],
        "the bytes-served counter is the response body's own length \
         on every row, and zero where there is no body: {:?}",
        recorded.served
    );
}

/// **Row (h): the `served` REQUEST-bytes field, following the
/// existing response-side test above and pinning the same 16,
/// 4096 and "no body" shapes for the other direction.**
///
/// The two write rows use garbage root bytes — this asserts what
/// `accept_body` COUNTED, not what the seam eventually made of it,
/// so a malformed root (which the seam refuses downstream) still
/// pins the count: `request_bytes` is set once `accept_body`
/// returns, before `dispatch` is ever reached.
#[tokio::test]
async fn the_served_request_bytes_field_pins_16_4096_and_no_body() {
    let (capture, _writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    // A FRESH seam per write: this row only cares what `accept_body`
    // COUNTED, never what the seam made of the garbage bytes, and a
    // shared seam across writes and the "no body" read below would
    // let an earlier write's side effect change what the read sees.
    for (len, seq) in [(16_usize, 41_u64), (4096_usize, 42_u64)] {
        let _response = instrumented(
            &FakeSeam::default(),
            WRITE_BODY_BUDGET_BYTES,
            &Method::PUT,
            &format!("/volume/t/root/{}", seq_key(seq)),
            None,
            vec![0x7a_u8; len],
        )
        .await;
    }

    // The "no body" row: a read carries no write-cap accept at all,
    // on its OWN fresh seam.
    let missing = instrumented(
        &FakeSeam::default(),
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        "/volume/t/max-seq",
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let recorded = capture.read();
    let counted: Vec<Option<u64>> = recorded
        .served
        .iter()
        .map(|row| row.request_bytes)
        .collect();
    assert_eq!(
        counted,
        vec![Some(16), Some(4096), None],
        "the request-bytes counter is what accept_body counted, and \
         `None` — never `0` — where no write-cap accept ran: {:?}",
        recorded.served
    );
}

/// **The request id is a plain counter — distinct and rising.**
///
/// It uses neither a clock nor randomness (no `Instant::now`, no `Rng`), and its one
/// job is that two requests are never confusable in a log. Asserted
/// as STRICTLY increasing rather than consecutive: the counter is
/// process-wide, so a concurrent request may take a number in
/// between, and consecutiveness would be a property of the test
/// harness rather than of the code.
#[tokio::test]
async fn the_request_ids_are_distinct_and_monotonic() {
    let (capture, _writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    let empty = FakeSeam::default();
    for _request in 0..5_u8 {
        let response = instrumented(
            &empty,
            WRITE_BODY_BUDGET_BYTES,
            &Method::GET,
            "/volume/t/max-seq",
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    let recorded = capture.read();
    assert_eq!(recorded.request_ids.len(), 5, "one span per request");
    for pair in recorded.request_ids.windows(2) {
        match pair {
            [earlier, later] => assert!(
                later > earlier,
                "request ids must rise: {:?}",
                recorded.request_ids
            ),
            _unreachable => panic!("windows(2) yields pairs"),
        }
    }
}

/// **The `413` a body cap produced and the `413` a seam produced are
/// distinguishable, and `operation` alone is not what distinguishes
/// them.**
///
/// The bounded `operation` field is required so that the ingest
/// decompressed-sum refusal — `413` + `too-large` + `put_bin` — is countable
/// apart from a body-cap `413`. It is, but not on `operation`: a
/// body-cap `413` on a `PUT bin` is `put_bin` too. What separates
/// them is `overflowed`. A cap refusal stops reading and tears the
/// connection down; a refusal that came back from the seam was
/// reached with the content fully read, so its bit is clear. This row
/// drives both halves on ONE operation, which is the only way the
/// claim is about the bit and not about the endpoint.
#[tokio::test]
async fn a_cap_refusal_and_a_seam_refusal_differ_in_the_served_overflowed_bit() {
    let (capture, _writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    let store = FakeSeam::default();
    let target = format!("/volume/t/root/{}", seq_key(41));

    // 1 — the body cap, refused before the seam with content unread.
    let over_cap = usize::try_from(ROOT_MAX_BYTES.saturating_add(1)).unwrap_or(usize::MAX);
    let capped = instrumented(
        &store,
        WRITE_BODY_BUDGET_BYTES,
        &Method::PUT,
        &target,
        None,
        vec![0x5a_u8; over_cap],
    )
    .await;
    assert_eq!(capped.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 2 — a refusal off the SEAM, same operation, content read whole.
    let planted = store.put_root("t", 41, b"the occupant".to_vec()).await;
    assert!(planted.is_ok(), "planting the occupant");
    let refused = instrumented(
        &store,
        WRITE_BODY_BUDGET_BYTES,
        &Method::PUT,
        &target,
        None,
        b"a second root at the same seq".to_vec(),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);

    let recorded = capture.read();
    let seen: Vec<(Option<u64>, Option<String>, Option<bool>)> = recorded
        .served
        .iter()
        .map(|row| (row.status, row.error.clone(), row.overflowed))
        .collect();
    assert_eq!(
        seen,
        vec![
            (Some(413), Some("too-large".to_owned()), Some(true)),
            (Some(409), Some("already-exists".to_owned()), Some(false)),
        ],
        "the accept-path refusal sets `overflowed` and the seam refusal \
         does not — the bit an operator needs to tell a mis-set body cap \
         from a refusal the store took"
    );
    assert!(
        recorded
            .served
            .iter()
            .all(|row| row.operation.as_deref() == Some("put_root")),
        "both rows are the SAME operation, which is what makes this a \
         row about the bit: {:?}",
        recorded.served
    );
}

/// **A FILTER above the stack takes the event away from EVERY Layer,
/// the future exporter included — the one qualification the floor
/// statement carries.**
///
/// Other instrumentation rows use the production constructor with an explicit
/// TRACE ceiling. This row uses restrictive directives on that same constructor;
/// production reads its immutable ceiling from `RUST_LOG`, and
/// `Layered::register_callsite` returns an outer `Interest::never()`
/// unchanged — so `RUST_LOG=granary_server=warn` does not merely
/// quieten stderr, it stops the `served` callsite from firing at all
/// and a counting Layer beside `fmt` counts nothing.
///
/// **The permissive half runs FIRST and is the positive control.**
/// "The capture Layer recorded nothing" is otherwise equally
/// consistent with a fixture that never drove a request, a directive
/// that matched no target, or a stack assembled wrong. The two halves
/// differ in the DIRECTIVE STRING and in nothing else.
#[tokio::test]
async fn instrumentation_the_env_filter_above_the_stack_suppresses_the_event_for_every_layer() {
    let empty = FakeSeam::default();

    // 1 — INFO admitted: the row's own fixture, proven to work.
    {
        let (capture, writer, subscriber) = capturing_under("granary_server=info");
        let _default = tracing::subscriber::set_default(subscriber);
        let response = instrumented(
            &empty,
            WRITE_BODY_BUDGET_BYTES,
            &Method::GET,
            "/volume/t/max-seq",
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let recorded = capture.read();
        assert_eq!(
            recorded.served.len(),
            1,
            "under a directive that ADMITS INFO the counter Layer must \
             see the event: {:?}",
            recorded.served
        );
        assert_eq!(recorded.request_ids.len(), 1, "and the span");
        assert!(
            writer.formatted() > 0,
            "and the fmt Layer must have rendered something, or the \
             halves below differ in more than the directive"
        );
    }

    // 2 — INFO suppressed. Same stack, same request, one word changed.
    let (capture, writer, subscriber) = capturing_under("granary_server=warn");
    let _default = tracing::subscriber::set_default(subscriber);
    let response = instrumented(
        &empty,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        "/volume/t/max-seq",
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the request still ran and still answered — the filter takes \
         the LOG away, never the response"
    );

    let recorded = capture.read();
    assert!(
        recorded.served.is_empty() && recorded.others.is_empty(),
        "a Layer BESIDE `fmt` — the shape a Phase-2 exporter has — \
         received nothing at all under `granary_server=warn`. This is \
         the floor statement's qualification: the loss sits at the \
         writer ONLY for events the filter admits: {:?} {:?}",
        recorded.served,
        recorded.others
    );
    assert!(
        recorded.request_ids.is_empty(),
        "the span is INFO too, so callsite interest takes it as well: \
         {:?}",
        recorded.request_ids
    );
    assert_eq!(
        writer.formatted(),
        0,
        "and nothing was rendered either — the suppression is ABOVE \
         the whole stack, not a property of one Layer"
    );
}

/// **The peer's method reaches the log BUCKETED, never verbatim.**
///
/// RFC 9110's `method` is a bare token with no length rule, so a peer
/// picks these bytes; hyper's h1 read buffer (~408 KiB by default,
/// and `granary_net::accept` sets no `max_buf_size`) is the only
/// thing above this layer that bounds them. Rendered verbatim the
/// field would be AMPLIFIED on the way out — the JSON formatter
/// writes a span's fields twice per line and `FmtSpan::CLOSE` makes
/// two lines — on a request that is REFUSED `405`, unauthenticated,
/// and whose exact bytes carry nothing the status code does not.
///
/// So the row drives a recognised method, a short unrecognised one
/// and a 100 000-byte one, and asserts the rendered field is a
/// closed-set label every time. **The byte assertion is the real
/// one**: the whole rendered output of all three requests is smaller
/// than the single method one peer sent, which a verbatim field
/// could not satisfy at any queue depth.
#[tokio::test]
async fn the_span_method_field_is_bucketed_to_a_closed_set() {
    let (capture, writer, subscriber) = capturing();
    let _default = tracing::subscriber::set_default(subscriber);

    let empty = FakeSeam::default();
    let oversized = vec![b'A'; 100_000];
    let huge = match Method::from_bytes(&oversized) {
        Ok(method) => method,
        Err(error) => panic!("a 100 000-byte RFC 9110 token: {error}"),
    };
    let brew = match Method::from_bytes(b"BREW") {
        Ok(method) => method,
        Err(error) => panic!("BREW: {error}"),
    };

    // A recognised method §4.2 does not define on this resource, then
    // two the gate has never heard of. All three are `405`s, which is
    // the point: this is the unauthenticated surface.
    for (method, expected) in [
        (&Method::POST, StatusCode::METHOD_NOT_ALLOWED),
        (&brew, StatusCode::METHOD_NOT_ALLOWED),
        (&huge, StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let response = instrumented(
            &empty,
            WRITE_BODY_BUDGET_BYTES,
            method,
            "/volume/t/max-seq",
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), expected);
    }
    // And one that IS served, so the row cannot pass by bucketing
    // everything to one label.
    let served = instrumented(
        &empty,
        WRITE_BODY_BUDGET_BYTES,
        &Method::GET,
        "/volume/t/max-seq",
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(served.status(), StatusCode::NOT_FOUND);

    let recorded = capture.read();
    assert_eq!(
        recorded.methods,
        vec![
            "POST".to_owned(),
            OTHER_METHOD.to_owned(),
            OTHER_METHOD.to_owned(),
            "GET".to_owned(),
        ],
        "a recognised method renders as ITSELF and everything else as \
         one fixed label — the domain is closed, not the field dropped"
    );
    assert!(
        writer.formatted() > 0,
        "the fmt Layer rendered nothing, so the byte reading below is \
         a reading of an unexercised path"
    );
    assert!(
        writer.formatted() < oversized.len(),
        "the WHOLE rendered output of four requests is {} bytes, which \
         must stay under the {} bytes of the single method one peer \
         sent — a verbatim field would render it four times over",
        writer.formatted(),
        oversized.len()
    );
}

/// **The rendered-line COUNT per request, both figures, in emission
/// order: two when the seam answers, three when it fails.**
///
/// The subscriber emits the span timings, so this row records their
/// price rather than arguing with it: `sink::QUEUE_LINES` is a line
/// count with no byte bound, so two lines per request halve the
/// number of requests whose records can be queued behind a stalled
/// writer — 512 rather than 1024 — and the `internal failure`
/// line makes a store-failing request THREE, which is 341. The sink
/// sees opaque `Vec<u8>`s in a FIFO and cannot prefer the outcome
/// line over either of the others.
///
/// **Both arms, because one cannot stand for the other.** A
/// served request is structurally incapable of reaching
/// `handlers::seam_failure`, so an arm built on one says
/// nothing about the failure figure however exactly it is
/// asserted: a guard claiming "a third line cannot arrive
/// silently" over a served-only fixture could never see that
/// line. The failure arm is here so that the third line is
/// counted.
///
/// **The ORDER is asserted and not just the count**, because the
/// module doc's queue argument is about which line takes the slot:
/// `seam_failure` calls `log_seam_failure` before returning an
/// `Outcome`, so the diagnostic goes AHEAD of `served` rather than
/// after it, and a count alone is blind to that being reversed.
/// Asserted as EXACT counts and not lower bounds: another line per
/// request is another slice off the depth.
///
/// **What the counting alone would MISS, and why the level is read
/// here too.** [`capturing`] is under an explicit TRACE ceiling, so an
/// `internal failure` demoted to `DEBUG` would still be dispatched
/// and still be rendered — three lines, in this order, green — while
/// production's `EnvFilter` (INFO by default, above the whole stack)
/// dropped the callsite and rendered two. The 341 figure is a claim
/// about the SHIPPED deployment, so the level it depends on is
/// asserted beside the count rather than left to
/// [`a_seam_failure_puts_the_store_s_own_words_in_the_log`], which
/// reads it for its own reasons.
///
/// **The residual:** this drives `seam_failure`, which is one of the
/// three sites that emit an `internal failure` event
/// (`contract_violation` and `codec_failure` are the others, and
/// neither is reachable from a `FakeSeam` that simply fails). All
/// three emit exactly one line, so the figure holds for all three;
/// what is EXECUTED here is one of them.
#[tokio::test]
async fn instrumentation_the_close_span_event_makes_two_rendered_lines_and_a_seam_failure_three() {
    let requests = 4_usize;

    // ARM 1 — the seam ANSWERS. `FakeSeam::default()` holds no root,
    // so `max_seq` is a clean `Ok(None)` and the request is served a
    // `404` without ever reaching `handlers::seam_failure`.
    {
        let (capture, writer, subscriber) = capturing();
        let _default = tracing::subscriber::set_default(subscriber);

        let empty = FakeSeam::default();
        for _request in 0..requests {
            let response = instrumented(
                &empty,
                WRITE_BODY_BUDGET_BYTES,
                &Method::GET,
                "/volume/t/max-seq",
                None,
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        assert_eq!(
            capture.read().served.len(),
            requests,
            "one `served` event per request, as every other row asserts"
        );
        assert_eq!(
            writer.dropped(),
            requests * 2,
            "TWO rendered lines per served request — the `served` \
             counter and the `FmtSpan::CLOSE` timing line. Against \
             `sink::QUEUE_LINES` (1024, a LINE count with no byte \
             bound) that is 512 requests' worth of records behind a \
             stalled writer where the counter alone would be 1024"
        );
        assert_eq!(
            writer.messages(),
            ["served", "close"].repeat(requests),
            "`served` FIRST and the span close after it — the ordering \
             the module doc calls the only thing favouring the outcome \
             line on this path"
        );
    }

    // ARM 2 — the seam FAILS. The bin is planted BEFORE the
    // subscriber is installed: a fixture that rendered lines of its
    // own would land in the count below and be read as the server's.
    {
        let (store, target) = planted(16).await;
        let (capture, writer, subscriber) = capturing();
        let _default = tracing::subscriber::set_default(subscriber);

        for _request in 0..requests {
            let response = instrumented(
                &store,
                WRITE_BODY_BUDGET_BYTES,
                &Method::GET,
                &target,
                // Past the end of a 16-byte object and under §7.3's
                // ceiling: the seam answers `Backend`, which is
                // `seam_failure` and therefore `log_seam_failure`.
                Some("bytes=200-207"),
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }

        let recorded = capture.read();
        assert_eq!(
            recorded.served.len(),
            requests,
            "one `served` event per request, failure or not"
        );
        assert_eq!(
            recorded.store_failures.len(),
            requests,
            "one `internal failure` event per request — the positive \
             control for the third line being the failure diagnostic and not some \
             other event the fixture happens to emit: {:?}",
            recorded.store_failures
        );
        assert!(
            recorded
                .store_failures
                .iter()
                .all(|failure| failure.level.as_deref() == Some("WARN")),
            "the third line is only a third line in production if the \
             shipped filter ADMITS it — this stack has none, so a \
             demotion would leave every count above green while the \
             deployment rendered two: {:?}",
            recorded.store_failures
        );
        drop(recorded);
        assert_eq!(
            writer.dropped(),
            requests * 3,
            "THREE rendered lines per store-failing request — the \
             `internal failure` diagnostic, the `served` counter and \
             the `FmtSpan::CLOSE` timing line. Against the same 1024 \
             slots that is 341 requests' worth of records, not 512"
        );
        assert_eq!(
            writer.messages(),
            ["internal failure", "served", "close"].repeat(requests),
            "the diagnostic goes AHEAD of `served` — `seam_failure` \
             logs before it returns an `Outcome` — so behind a stalled \
             writer it takes a slot `served` would have had. That \
             ordering is the module doc's queue argument, and a count \
             alone cannot see it reversed"
        );
    }
}

mod capture;
mod controls;
