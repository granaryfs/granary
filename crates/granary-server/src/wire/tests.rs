// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::wire` — the wire vocabulary the handlers
//! answer in.
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{
    Allow, CacheControl, ContentType, ETag, ErrorToken, NonZeroU64, Outcome, PublishConflict,
    PublishRefusal, Resource, Status, StatusRefusal, SuccessStatus,
};

/// A nonzero seq for a test body.
fn seq(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("a test seq is never zero")
}

/// A valid strong `entity-tag` for a test.
fn etag(value: &str) -> ETag {
    ETag::new(value.to_owned()).expect("a test ETag is a strong entity-tag")
}

/// §8.2's closed registry, transcribed row for row. A spelling that
/// drifts from the protocol document fails here.
const TOKENS: [(ErrorToken, &str); 38] = [
    (ErrorToken::IntentSuperseded, "intent-superseded"),
    (ErrorToken::IntentBound, "intent-bound"),
    (ErrorToken::IntentChanged, "intent-changed"),
    (ErrorToken::IntentAbsent, "intent-absent"),
    (ErrorToken::IntentCursorChanged, "intent-cursor-changed"),
    (ErrorToken::IntentEpochExhausted, "intent-epoch-exhausted"),
    (ErrorToken::IntentQuota, "intent-quota"),
    (ErrorToken::NotFound, "not-found"),
    (ErrorToken::UnknownTarget, "unknown-target"),
    (ErrorToken::AlreadyExists, "already-exists"),
    (ErrorToken::AddressMismatch, "address-mismatch"),
    (ErrorToken::VerifyFailed, "verify-failed"),
    (ErrorToken::LayoutInvalid, "layout-invalid"),
    (ErrorToken::BadRange, "bad-range"),
    (ErrorToken::ExtentTooWide, "extent-too-wide"),
    (ErrorToken::BadRequest, "bad-request"),
    (ErrorToken::MethodNotAllowed, "method-not-allowed"),
    (ErrorToken::TooLarge, "too-large"),
    (ErrorToken::Internal, "internal"),
    (ErrorToken::Unavailable, "unavailable"),
    (ErrorToken::NoPrincipal, "no-principal"),
    (ErrorToken::NotEnrolled, "not-enrolled"),
    (ErrorToken::RateLimited, "rate-limited"),
    (ErrorToken::AuthorityManaged, "authority-managed"),
    (ErrorToken::InvalidCandidate, "invalid-candidate"),
    (ErrorToken::MissingReference, "missing-reference"),
    (ErrorToken::InvalidReference, "invalid-reference"),
    (ErrorToken::PublishWorkLimit, "publish-work-limit"),
    (ErrorToken::NoLog, "no-log"),
    (ErrorToken::UnknownVolume, "unknown-volume"),
    (ErrorToken::StaleBase, "stale-base"),
    (ErrorToken::OperationBound, "operation-bound"),
    (ErrorToken::NotDecided, "not-decided"),
    (ErrorToken::EpochMismatch, "epoch-mismatch"),
    (ErrorToken::VolumeDamaged, "volume-damaged"),
    (ErrorToken::Fenced, "fenced"),
    (ErrorToken::Stopped, "stopped"),
    (ErrorToken::EnrollmentUnavailable, "enrollment-unavailable"),
];

/// How many tokens §8.2's registry holds.
const TOKEN_COUNT: usize = 38;

/// How many statuses the server generates.
const STATUS_COUNT: usize = 16;

/// Exhaustive over `ErrorToken` with NO wildcard arm, so a new
/// variant stops this file compiling exactly as it stops `as_str`
/// compiling. It is what makes the coverage assertion below a
/// statement about the ENUM rather than about the table's own length.
fn ordinal(token: ErrorToken) -> usize {
    match token {
        ErrorToken::IntentSuperseded => 28,
        ErrorToken::IntentBound => 29,
        ErrorToken::IntentChanged => 30,
        ErrorToken::IntentAbsent => 31,
        ErrorToken::IntentCursorChanged => 32,
        ErrorToken::IntentEpochExhausted => 33,
        ErrorToken::IntentQuota => 34,
        ErrorToken::NotFound => 0,
        ErrorToken::UnknownTarget => 1,
        ErrorToken::AlreadyExists => 2,
        ErrorToken::AddressMismatch => 3,
        ErrorToken::VerifyFailed => 4,
        ErrorToken::LayoutInvalid => 5,
        ErrorToken::BadRange => 6,
        ErrorToken::ExtentTooWide => 7,
        ErrorToken::BadRequest => 8,
        ErrorToken::MethodNotAllowed => 9,
        ErrorToken::TooLarge => 10,
        ErrorToken::Internal => 11,
        ErrorToken::Unavailable => 12,
        ErrorToken::NoPrincipal => 13,
        ErrorToken::NotEnrolled => 14,
        ErrorToken::RateLimited => 15,
        ErrorToken::AuthorityManaged => 16,
        ErrorToken::InvalidCandidate => 17,
        ErrorToken::MissingReference => 35,
        ErrorToken::InvalidReference => 36,
        ErrorToken::PublishWorkLimit => 37,
        ErrorToken::NoLog => 18,
        ErrorToken::UnknownVolume => 19,
        ErrorToken::StaleBase => 20,
        ErrorToken::OperationBound => 21,
        ErrorToken::NotDecided => 22,
        ErrorToken::EpochMismatch => 23,
        ErrorToken::VolumeDamaged => 24,
        ErrorToken::Fenced => 25,
        ErrorToken::Stopped => 26,
        ErrorToken::EnrollmentUnavailable => 27,
    }
}

/// The same device for `Status`, and for the same reason: it is what
/// makes the accept-set assertions below statements about the ENUM.
/// A new variant fails to compile HERE, which forces its
/// author to confront the two assertions that follow rather than
/// leaving them quietly true of a list that no longer covers the
/// type.
fn status_ordinal(status: Status) -> usize {
    match status {
        Status::Ok => 0,
        Status::Created => 1,
        Status::NoContent => 2,
        Status::PartialContent => 3,
        Status::NotModified => 4,
        Status::BadRequest => 5,
        Status::NotFound => 6,
        Status::MethodNotAllowed => 7,
        Status::Conflict => 8,
        Status::ContentTooLarge => 9,
        Status::RangeNotSatisfiable => 10,
        Status::InternalServerError => 11,
        Status::ServiceUnavailable => 12,
        Status::Accepted => 13,
        Status::Forbidden => 14,
        Status::TooManyRequests => 15,
    }
}

/// The same device for `SuccessStatus`. The list in
/// `the_funnels_success_arm_admits_no_refusal_status` is hand-written
/// and would otherwise fall quietly behind a new variant; with no
/// wildcard arm here, a new one stops this file compiling instead.
fn success_ordinal(status: SuccessStatus) -> usize {
    match status {
        SuccessStatus::Ok => 0,
        SuccessStatus::Created => 1,
        SuccessStatus::NoContent => 2,
        SuccessStatus::PartialContent => 3,
        SuccessStatus::NotModified => 4,
        SuccessStatus::Accepted => 5,
    }
}

#[test]
fn every_error_token_renders_its_registry_spelling() {
    for (token, expected) in TOKENS {
        assert_eq!(
            token.as_str(),
            expected,
            "{token:?} must render as the §8.2 token {expected:?}"
        );
    }
}

#[test]
fn the_token_table_covers_every_variant() {
    assert_eq!(TOKENS.len(), TOKEN_COUNT, "§8.2's registry");
    let mut seen = [false; TOKEN_COUNT];
    for (token, _) in TOKENS {
        let index = ordinal(token);
        assert!(!seen[index], "{token:?} appears twice in the table");
        seen[index] = true;
    }
    assert!(
        seen.iter().all(|covered| *covered),
        "a variant is missing from the table: {seen:?}"
    );
}

#[test]
fn no_two_tokens_share_a_spelling() {
    for (index, (_, spelling)) in TOKENS.iter().enumerate() {
        let clashes = TOKENS
            .iter()
            .enumerate()
            .filter(|(other, (_, candidate))| *other != index && candidate == spelling)
            .count();
        assert_eq!(clashes, 0, "{spelling:?} is rendered by two variants");
    }
}

#[test]
fn every_named_status_carries_its_protocol_value() {
    assert_eq!(Status::Ok.as_u16(), 200);
    assert_eq!(Status::Created.as_u16(), 201);
    assert_eq!(Status::NoContent.as_u16(), 204);
    assert_eq!(Status::Accepted.as_u16(), 202);
    assert_eq!(Status::Forbidden.as_u16(), 403);
    assert_eq!(Status::TooManyRequests.as_u16(), 429);
    assert_eq!(Status::PartialContent.as_u16(), 206);
    assert_eq!(Status::NotModified.as_u16(), 304);
    assert_eq!(Status::BadRequest.as_u16(), 400);
    assert_eq!(Status::NotFound.as_u16(), 404);
    assert_eq!(Status::MethodNotAllowed.as_u16(), 405);
    assert_eq!(Status::Conflict.as_u16(), 409);
    assert_eq!(Status::ContentTooLarge.as_u16(), 413);
    assert_eq!(Status::RangeNotSatisfiable.as_u16(), 416);
    assert_eq!(Status::InternalServerError.as_u16(), 500);
    assert_eq!(Status::ServiceUnavailable.as_u16(), 503);
}

/// The ACCEPT SET. `GENERATED` is declared by the same macro that
/// declares the variants, so it cannot fall behind the enum; the
/// exhaustive `status_ordinal` above is what makes a new variant
/// arrive here rather than slip past.
#[test]
fn the_generated_set_holds_no_status_this_server_never_sends() {
    let mut seen = [false; STATUS_COUNT];
    for status in Status::GENERATED {
        let index = status_ordinal(*status);
        assert!(!seen[index], "{status:?} appears twice in GENERATED");
        seen[index] = true;
        assert_ne!(
            status.as_u16(),
            412,
            "§5.10: a granary server never generates 412 — §5a.6 refuses \
             conditional request header fields instead of evaluating them, \
             so no precondition is left to fail"
        );
        assert_ne!(
            status.as_u16(),
            425,
            "§5.10: a granary server never generates 425; it exists in a \
             client's map only for one an intermediary supplies"
        );
    }
    assert!(
        seen.iter().all(|covered| *covered),
        "a Status variant is missing from GENERATED: {seen:?}"
    );
    let codes: Vec<u16> = Status::GENERATED.iter().map(|s| s.as_u16()).collect();
    assert_eq!(
        codes,
        vec![
            200, 201, 202, 204, 206, 304, 400, 403, 404, 405, 409, 413, 416, 429, 500, 503
        ],
        "the set is §5.1–§5.12 plus §3.2, §5a.6, §7.1–§7.3 — nothing else"
    );
}

/// `is_refusal` is what `Outcome` asks before it carries a token, so
/// it has to agree with §8.2's own scoping — a `4xx` or a `5xx` — on
/// every status the server generates. Two independent hand-written
/// classifications, bound together here.
#[test]
fn is_refusal_agrees_with_section_8_2s_scope_on_every_generated_status() {
    for status in Status::GENERATED {
        assert_eq!(
            status.is_refusal(),
            (400..600).contains(&status.as_u16()),
            "§8.2 scopes Granary-Error to 4xx/5xx, and {status:?} is \
             classified against that"
        );
    }
}

/// The success arm of the funnel cannot name a refusal status — that
/// is a compile property. This binds the two classifications so a
/// status moved from one side to the other cannot be moved in only
/// one place.
#[test]
fn the_funnels_success_arm_admits_no_refusal_status() {
    let mut seen = [false; 6];
    for success in [
        SuccessStatus::Ok,
        SuccessStatus::Created,
        SuccessStatus::NoContent,
        SuccessStatus::PartialContent,
        SuccessStatus::NotModified,
        SuccessStatus::Accepted,
    ] {
        let index = success_ordinal(success);
        assert!(!seen[index], "{success:?} appears twice in the list");
        seen[index] = true;
        assert!(
            !success.status().is_refusal(),
            "{success:?} reaches the arm that carries no token, so §8.2 \
             must not require one on it"
        );
    }
    assert!(
        seen.iter().all(|covered| *covered),
        "a SuccessStatus variant is missing from the list, so the arm it \
         reaches is unchecked: {seen:?}"
    );
}

#[test]
fn the_media_types_are_section_11s() {
    assert_eq!(ContentType::Bin.as_str(), "application/vnd.granary.bin.v1");
    assert_eq!(
        ContentType::Meta.as_str(),
        "application/vnd.granary.meta.v1"
    );
    assert_eq!(
        ContentType::Root.as_str(),
        "application/vnd.granary.root.v1"
    );
    assert_eq!(ContentType::Text.as_str(), "text/plain; charset=utf-8");
    assert_eq!(
        ContentType::AuthorityAnswer.as_str(),
        "application/vnd.granary.authority-answer.v1"
    );
    assert_eq!(
        ContentType::VolumeStatus.as_str(),
        "application/vnd.granary.volume-status.v1"
    );
}

#[test]
fn the_cache_directives_are_section_6s_and_carry_nothing_it_forbids() {
    assert_eq!(
        CacheControl::Immutable.as_str(),
        "max-age=31536000, immutable"
    );
    assert_eq!(CacheControl::NoStore.as_str(), "no-store");
    assert_eq!(CacheControl::NoCache.as_str(), "no-cache");
    for forbidden in ["public", "s-maxage", "must-revalidate"] {
        assert!(
            !CacheControl::Immutable.as_str().contains(forbidden),
            "§6: a bin response MUST NOT carry {forbidden:?}"
        );
    }
}

#[test]
fn put_bin_and_put_meta_answer_201_when_novel_and_200_when_present() {
    let novel = Outcome::created();
    assert_eq!(novel.status(), Status::Created);
    assert_eq!(novel.error(), None);
    assert_eq!(novel.content_type(), None);
    assert_eq!(novel.cache_control(), None);
    assert_eq!(novel.etag(), None);
    assert_eq!(novel.extent(), None);
    assert!(novel.body().is_empty());

    let present = Outcome::already_present();
    assert_eq!(present.status(), Status::Ok);
    assert_eq!(
        present.error(),
        None,
        "an existing content-addressed object is success, never an error"
    );
    assert_eq!(present.content_type(), None);
    assert!(present.body().is_empty());
}

#[test]
fn write_hint_answers_204_created_or_replaced_alike() {
    let written = Outcome::hint_written();
    assert_eq!(written.status(), Status::NoContent);
    assert_eq!(written.error(), None);
    assert!(written.body().is_empty());
    assert_eq!(written.etag(), None);
}

#[test]
fn get_meta_answers_200_with_the_stored_bytes() {
    let served = Outcome::meta(b"not-an-object".to_vec());
    assert_eq!(served.status(), Status::Ok);
    assert_eq!(served.error(), None);
    assert_eq!(served.content_type(), Some(ContentType::Meta));
    assert_eq!(served.body(), b"not-an-object");
    assert_eq!(served.etag(), None);
    assert_eq!(served.extent(), None);
}

#[test]
fn get_root_answers_200_immutable_and_carries_no_validator() {
    let served = Outcome::root(b"signed-root".to_vec());
    assert_eq!(served.status(), Status::Ok);
    assert_eq!(served.content_type(), Some(ContentType::Root));
    assert_eq!(
        served.cache_control(),
        Some(CacheControl::Immutable),
        "§6: a numbered root MAY carry the immutable directive, and does"
    );
    assert_eq!(
        served.etag(),
        None,
        "§6: an ETag on a numbered root is OPTIONAL and inert; emitting \
         none avoids a second place to get validator policy right"
    );
    assert_eq!(served.body(), b"signed-root");
}

#[test]
fn max_seq_answers_200_no_store_with_twenty_digits() {
    let served = Outcome::max_seq(seq(42));
    assert_eq!(served.status(), Status::Ok);
    assert_eq!(served.content_type(), Some(ContentType::Text));
    assert_eq!(
        served.cache_control(),
        Some(CacheControl::NoStore),
        "§6: max-seq changes on every publish and has no validator"
    );
    assert_eq!(served.body(), b"00000000000000000042");
    assert_eq!(served.etag(), None);
}

/// §5.7 and §5.8 both fix the body as exactly 20 ASCII digits,
/// zero-padded, no newline — at every magnitude, `u64::MAX` (which is
/// itself 20 digits) included. The width has no slack in either
/// direction, so this sweeps the boundary of every decade rather
/// than one convenient value.
#[test]
fn the_seq_body_is_twenty_ascii_digits_at_every_magnitude() {
    let mut values = vec![1_u64, 42, u64::MAX, u64::MAX - 1, 1_234_567_890];
    let mut decade = 1_u64;
    while let Some(next) = decade.checked_mul(10) {
        values.push(decade);
        values.push(next - 1);
        decade = next;
    }
    for value in values {
        let body = Outcome::max_seq(seq(value)).into_body();
        assert_eq!(
            body.len(),
            20,
            "§5.7: exactly 20 digits, and {value} rendered {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            body.iter().all(u8::is_ascii_digit),
            "§5.7: ASCII digits only — no sign, no newline, no padding \
             character but '0' ({})",
            String::from_utf8_lossy(&body)
        );
        let rendered = String::from_utf8(body).expect("ASCII digits are UTF-8");
        assert_eq!(
            rendered.trim_start_matches('0').parse::<u64>().ok(),
            Some(value),
            "the digits must read back as the seq"
        );
        assert_eq!(
            Outcome::hint(seq(value), etag("\"v\"")).into_body(),
            rendered.as_bytes(),
            "§5.8's body is §5.7's body"
        );
    }
}

/// The body §5.7 names as forbidden is not a body this type can
/// build: `max_seq` takes the VALUE, and `NonZeroU64::new(0)` is
/// `None` before an `Outcome` is reached.
#[test]
fn the_seq_zero_never_becomes_a_body() {
    assert_eq!(
        NonZeroU64::new(0),
        None,
        "§5.7: the server MUST NOT answer 0, so 0 never reaches a body"
    );
    let smallest = Outcome::max_seq(seq(1)).into_body();
    assert_eq!(smallest, b"00000000000000000001");
    assert_ne!(
        smallest, b"00000000000000000000",
        "the one body §5.7 forbids"
    );
}

#[test]
fn read_hint_answers_200_no_cache_with_its_required_strong_etag() {
    let served = Outcome::hint(seq(42), etag("\"v7\""));
    assert_eq!(served.status(), Status::Ok);
    assert_eq!(served.content_type(), Some(ContentType::Text));
    assert_eq!(served.cache_control(), Some(CacheControl::NoCache));
    assert_eq!(
        served.etag(),
        Some("\"v7\""),
        "§5.8: the ETag is REQUIRED here, and is echoed verbatim"
    );
    assert_eq!(served.body(), b"00000000000000000042");
}

/// RFC 9110 §8.8.3's `entity-tag`, strong form only: `DQUOTE *etagc
/// DQUOTE`, `etagc = %x21 / %x23-7E / obs-text`.
#[test]
fn an_etag_is_a_strong_entity_tag_or_it_is_not_built() {
    for accepted in [
        "\"v7\"",
        "\"\u{21}\"",
        "\"~\"",
        "\"a-very-long-opaque-token-0123456789\"",
        "\"caf\u{e9}\"",
    ] {
        assert!(
            ETag::new(accepted.to_owned()).is_some(),
            "{accepted:?} is a strong entity-tag"
        );
    }
    for rejected in [
        // Weak — §5.8 requires a STRONG validator.
        "W/\"v7\"",
        "w/\"v7\"",
        // Not an entity-tag at all: no DQUOTEs, or only one.
        "v7",
        "\"v7",
        "v7\"",
        "\"",
        "",
        // Header injection: CR and LF are not `etagc`.
        "\"v\"\r\nX-Injected: 1",
        "\"v\r\n\"",
        "\"v\n\"",
        "\"v\r\"",
        // `%x22` is excluded from `etagc`, so a tag cannot be quoted
        // twice and cannot be closed early.
        "\"\"v7\"\"",
        "\"a\"b\"",
        // Other CTLs and the space `%x20`, all outside `etagc`.
        "\"v\u{0}\"",
        "\"v\t\"",
        "\"v \"",
        "\"\u{7f}\"",
        // An empty validator cannot change when the seq changes.
        "\"\"",
    ] {
        assert_eq!(
            ETag::new(rejected.to_owned()),
            None,
            "{rejected:?} is not a strong entity-tag and must not reach a \
             response field"
        );
    }
}

#[test]
fn a_304_carries_the_etag_the_200_would_have_and_no_content() {
    let revalidated = Outcome::hint_not_modified(etag("\"v7\""));
    assert_eq!(revalidated.status(), Status::NotModified);
    assert_eq!(revalidated.error(), None);
    assert_eq!(revalidated.etag(), Some("\"v7\""));
    assert_eq!(
        revalidated.cache_control(),
        Some(CacheControl::NoCache),
        "§6: a 304 carries the same directives the 200 would have"
    );
    assert!(revalidated.body().is_empty());
    assert_eq!(revalidated.extent(), None);
}

#[test]
fn a_bin_206_declares_the_extent_it_delivers() {
    let served = Outcome::bin_range(100, vec![7u8; 100]).expect("100 bytes is a valid extent");
    assert_eq!(served.status(), Status::PartialContent);
    let extent = served.extent().expect("a 206 always carries its extent");
    assert_eq!(
        (extent.first(), extent.last()),
        (100, 199),
        "Content-Range's last-pos is INCLUSIVE (RFC 9110 §14.1.2)"
    );
    assert_eq!(served.body().len(), 100);
    assert_eq!(served.content_type(), Some(ContentType::Bin));
    assert_eq!(served.cache_control(), Some(CacheControl::Immutable));
    assert_eq!(
        served.etag(),
        None,
        "§6: no ETag on ANY bin response, the 206 included"
    );
}

#[test]
fn a_short_read_narrows_the_extent_and_never_the_body_under_it() {
    let served = Outcome::bin_range(0, vec![0u8; 50]).expect("a 50-byte tail is a short read");
    let extent = served.extent().expect("a 206 always carries its extent");
    assert_eq!((extent.first(), extent.last()), (0, 49));
    let width = extent.last() - extent.first() + 1;
    assert_eq!(
        width,
        u64::try_from(served.body().len()).unwrap(),
        "§7.2: the extent a server declares is the extent it delivers"
    );
}

/// §7.2 as a property over WIDTH, not over the five lengths that
/// happened to be convenient. A derivation that is right at 1, 2, 50
/// and 100 and wrong at 3 is a derivation nobody wrote on purpose,
/// which is exactly the shape a table of hand-picked lengths misses.
#[test]
fn the_declared_extent_is_the_delivered_one_at_every_width() {
    let widths = (1_usize..=64)
        .chain([100, 255, 256, 257, 4096])
        .flat_map(|len| [0_u64, 1, 4096, u64::from(u32::MAX)].map(move |first| (first, len)));
    for (first_pos, len) in widths {
        let served = Outcome::bin_range(first_pos, vec![7u8; len])
            .expect("a non-empty body below u64::MAX is always a valid extent");
        let extent = served.extent().expect("a 206 always carries its extent");
        assert_eq!(extent.first(), first_pos, "len {len}");
        assert_eq!(
            extent.last() - extent.first() + 1,
            u64::try_from(served.body().len()).unwrap(),
            "§7.2: the extent a server declares is the extent it delivers \
             (first_pos {first_pos}, len {len})"
        );
        assert_eq!(served.body().len(), len);
    }
}

#[test]
fn a_zero_width_or_overflowing_extent_has_no_206_at_all() {
    assert_eq!(
        Outcome::bin_range(0, Vec::new()),
        None,
        "§7.2: an empty read is never a success on this seam"
    );
    assert_eq!(
        Outcome::bin_range(u64::MAX, vec![0u8; 2]),
        None,
        "first_pos + len - 1 overflows u64"
    );
    assert!(
        Outcome::bin_range(u64::MAX, vec![0u8; 1]).is_some(),
        "the last addressable byte is still an extent"
    );
}

/// Every refusal the protocol defines, as (response, status, token).
/// §8.2 makes the field a MUST on every `4xx`/`5xx` the application
/// layer generates, and these nineteen pairs are the whole of
/// §5.1–§5.10, with the five admission refusals §3.2 and §5.5 add.
#[test]
fn every_refusal_pairs_its_status_with_exactly_one_token() {
    let rows = [
        (Outcome::not_found(), 404_u16, ErrorToken::NotFound),
        (Outcome::unknown_target(), 404, ErrorToken::UnknownTarget),
        (Outcome::already_exists(), 409, ErrorToken::AlreadyExists),
        (
            Outcome::address_mismatch(),
            400,
            ErrorToken::AddressMismatch,
        ),
        (Outcome::verify_failed(), 400, ErrorToken::VerifyFailed),
        (Outcome::layout_invalid(), 400, ErrorToken::LayoutInvalid),
        (Outcome::bad_range_form(), 400, ErrorToken::BadRange),
        (Outcome::range_not_satisfiable(), 416, ErrorToken::BadRange),
        (Outcome::extent_too_wide(), 400, ErrorToken::ExtentTooWide),
        (Outcome::bad_request(), 400, ErrorToken::BadRequest),
        (
            Outcome::method_not_allowed(Resource::Bin),
            405,
            ErrorToken::MethodNotAllowed,
        ),
        (Outcome::too_large(), 413, ErrorToken::TooLarge),
        (Outcome::internal(), 500, ErrorToken::Internal),
        (Outcome::unavailable(), 503, ErrorToken::Unavailable),
        (Outcome::no_principal(), 403, ErrorToken::NoPrincipal),
        (Outcome::not_enrolled(), 403, ErrorToken::NotEnrolled),
        (
            Outcome::authority_managed(),
            403,
            ErrorToken::AuthorityManaged,
        ),
        (Outcome::rate_limited(7), 429, ErrorToken::RateLimited),
        (
            Outcome::enrollment_unavailable(),
            503,
            ErrorToken::EnrollmentUnavailable,
        ),
    ];
    assert_eq!(rows.len(), 19, "the seam endpoints' nineteen refusal rows");
    for (outcome, status, token) in &rows {
        assert_eq!(outcome.status().as_u16(), *status, "{token:?}");
        assert_eq!(outcome.error(), Some(*token), "status {status}");
        assert!(
            (400..600).contains(status),
            "§8.2 scopes the token to 4xx/5xx, so a refusal cannot be a 2xx"
        );
        assert!(
            outcome.body().is_empty(),
            "§8.4: a refusal relays no diagnostic text"
        );
        assert_eq!(outcome.content_type(), None, "{token:?}");
        assert_eq!(outcome.etag(), None, "{token:?}");
        assert_eq!(outcome.extent(), None, "{token:?}");
        assert_eq!(
            outcome.retry_after().is_some(),
            *status == 429,
            "Retry-After on the 429 alone"
        );
    }
}

/// §8.2's biconditional, over **every public constructor** rather
/// than over the refusal rows alone: the field is present on exactly
/// the statuses §8.2 scopes it to.
///
/// The funnel is what makes this true by construction — a success
/// arm that cannot name a refusal status, and a status that decides
/// whether an offered token is carried. This asserts it anyway,
/// because the funnel cannot speak for a row whose *status* is the
/// wrong one for its endpoint.
#[test]
fn every_public_constructor_carries_a_token_exactly_when_section_8_2_asks() {
    let all = [
        Outcome::intent_refused(Status::Conflict, ErrorToken::IntentSuperseded),
        Outcome::intent_refused(Status::Conflict, ErrorToken::IntentBound),
        Outcome::intent_refused(Status::Conflict, ErrorToken::IntentChanged),
        Outcome::intent_refused(Status::Conflict, ErrorToken::IntentAbsent),
        Outcome::intent_refused(Status::Conflict, ErrorToken::IntentCursorChanged),
        Outcome::intent_refused(Status::Conflict, ErrorToken::IntentEpochExhausted),
        Outcome::intent_refused(Status::Conflict, ErrorToken::IntentQuota),
        Outcome::created(),
        Outcome::already_present(),
        Outcome::hint_written(),
        Outcome::meta(Vec::new()),
        Outcome::root(Vec::new()),
        Outcome::max_seq(seq(1)),
        Outcome::hint(seq(1), etag("\"v1\"")),
        Outcome::hint_not_modified(etag("\"v1\"")),
        Outcome::bin_range(0, vec![1u8]).expect("one byte is a valid extent"),
        Outcome::not_found(),
        Outcome::unknown_target(),
        Outcome::already_exists(),
        Outcome::address_mismatch(),
        Outcome::verify_failed(),
        Outcome::layout_invalid(),
        Outcome::bad_range_form(),
        Outcome::range_not_satisfiable(),
        Outcome::extent_too_wide(),
        Outcome::bad_request(),
        Outcome::method_not_allowed(Resource::MaxSeq),
        Outcome::too_large(),
        Outcome::internal(),
        Outcome::unavailable(),
        Outcome::no_principal(),
        Outcome::not_enrolled(),
        Outcome::authority_managed(),
        Outcome::rate_limited(1),
        Outcome::publish_settled(vec![1]),
        Outcome::publish_pending(vec![1]),
        Outcome::volume_status(vec![1]),
        Outcome::publish_conflict(PublishConflict::StaleBase, vec![1]),
        Outcome::publish_conflict(PublishConflict::OperationBound, vec![1]),
        Outcome::publish_conflict(PublishConflict::NotDecided, vec![1]),
        Outcome::publish_conflict(PublishConflict::EpochMismatch, vec![1]),
        Outcome::publish_conflict(PublishConflict::VolumeDamaged, vec![1]),
        Outcome::publish_refused(PublishRefusal::InvalidCandidate),
        Outcome::publish_refused(PublishRefusal::MissingReference),
        Outcome::publish_refused(PublishRefusal::InvalidReference),
        Outcome::publish_refused(PublishRefusal::PublishWorkLimit),
        Outcome::publish_refused(PublishRefusal::NoLog),
        Outcome::publish_refused(PublishRefusal::UnknownVolume),
        Outcome::publish_refused(PublishRefusal::Fenced),
        Outcome::publish_refused(PublishRefusal::Stopped),
        Outcome::publish_refused(PublishRefusal::MethodNotAllowed),
        Outcome::enrollment_unavailable(),
        Outcome::status_refused(StatusRefusal::NoLog),
    ];
    // NOT `assert_eq!(all.len(), 22)`, which is what stood here: an
    // array's length can only ever equal itself, so that assertion
    // could not fail and said nothing about what the list covers.
    // These two can fail. Every status the server generates and every
    // token §8.2 registers has to be reachable through some row here,
    // so the list going short is a red test rather than a comment —
    // unless the missing constructor's status AND token are both
    // already covered by another row, which is the residual and is
    // why this is a floor and not a proof of coverage.
    let mut statuses = [false; STATUS_COUNT];
    let mut tokens = [false; TOKEN_COUNT];
    for outcome in &all {
        statuses[status_ordinal(outcome.status())] = true;
        if let Some(token) = outcome.error() {
            tokens[ordinal(token)] = true;
        }
    }
    assert!(
        statuses.iter().all(|covered| *covered),
        "a Status variant reaches no constructor in this list: {statuses:?}"
    );
    assert!(
        tokens.iter().all(|covered| *covered),
        "a §8.2 token reaches no constructor in this list: {tokens:?}"
    );
    for outcome in &all {
        assert_eq!(
            outcome.error().is_some(),
            outcome.status().is_refusal(),
            "§8.2: a Granary-Error token on exactly the 4xx/5xx rows — \
             {:?} disagrees",
            outcome.status()
        );
        assert_eq!(
            outcome.status().is_refusal(),
            (400..600).contains(&outcome.status().as_u16()),
            "and 'refusal' means what §8.2 means by it"
        );
        assert_eq!(
            outcome.allow().is_some(),
            outcome.status() == Status::MethodNotAllowed,
            "RFC 9110 §15.5.6 puts Allow on the 405, and §4.2 nowhere else"
        );
    }
}

/// The other half of the funnel's rule, which no type signature can
/// state: the STATUS decides whether a token is carried, so a token
/// offered with a success status is not carried at all.
///
/// The funnel is private, so this is not a construction any caller
/// outside this module could attempt — which is the point. It is
/// asserted here because a `2xx` bearing a `Granary-Error` is what
/// §8.2 scopes the field against, and the guard is a branch rather
/// than a signature.
#[test]
fn the_funnel_carries_no_token_on_a_success_status() {
    let smuggled = Outcome::refused(Status::Ok, ErrorToken::NotFound);
    assert_eq!(
        smuggled.error(),
        None,
        "§8.2 scopes Granary-Error to 4xx/5xx: a 200 never carries one"
    );
    assert_eq!(smuggled.status(), Status::Ok);
}

/// Pin the advertised methods for the five store resources, publish and status.
#[test]
fn a_405_carries_the_target_resources_own_method_set() {
    let table = [
        (Resource::Bin, Allow::GetPut, "GET, PUT"),
        (Resource::Meta, Allow::GetPut, "GET, PUT"),
        (Resource::Root, Allow::GetPut, "GET, PUT"),
        (Resource::MaxSeq, Allow::Get, "GET"),
        (Resource::Hint, Allow::GetPut, "GET, PUT"),
        (Resource::Publish, Allow::Post, "POST"),
        (Resource::VolumeStatus, Allow::Get, "GET"),
    ];
    assert_eq!(
        table.len(),
        7,
        "five store resources plus publish and status"
    );
    for (resource, allow, spelling) in table {
        assert_eq!(
            resource.allow(),
            allow,
            "{resource:?} has a fixed method set"
        );
        assert_eq!(allow.as_str(), spelling);
        assert_eq!(
            Outcome::method_not_allowed(resource).allow(),
            Some(allow),
            "the 405 advertises the resource's own set, not a caller's"
        );
        assert!(
            !allow.as_str().contains("HEAD"),
            "HEAD is unsupported on these resources"
        );
    }
    assert_eq!(
        Resource::MaxSeq.allow(),
        Allow::Get,
        "max-seq is READ-ONLY: advertising PUT on it is the failure this \
         signature exists to prevent"
    );
    assert_eq!(
        Outcome::not_found().allow(),
        None,
        "a missing object does not advertise allowed methods"
    );
}

#[test]
fn no_success_carries_an_error_token() {
    let successes = [
        Outcome::created(),
        Outcome::already_present(),
        Outcome::hint_written(),
        Outcome::meta(Vec::new()),
        Outcome::root(Vec::new()),
        Outcome::max_seq(seq(1)),
        Outcome::hint(seq(1), etag("\"v1\"")),
        Outcome::hint_not_modified(etag("\"v1\"")),
        Outcome::bin_range(0, vec![1u8]).expect("one byte is a valid extent"),
        Outcome::publish_settled(vec![1]),
        Outcome::publish_pending(vec![1]),
        Outcome::volume_status(vec![1]),
    ];
    for outcome in &successes {
        assert_eq!(
            outcome.error(),
            None,
            "§8.2 scopes Granary-Error to 4xx/5xx, and {:?} is not one",
            outcome.status()
        );
        assert_eq!(outcome.allow(), None);
    }
}

/// The closed open question, executed: an owned body costs nothing
/// because the `Outcome` MOVES the seam's `Vec` rather than copying
/// it — same pointer, same capacity.
#[test]
fn an_owned_body_moves_rather_than_reallocating() {
    let body = vec![9u8; 4096];
    let pointer = body.as_ptr();
    let capacity = body.capacity();
    let carried = Outcome::meta(body).into_body();
    assert_eq!(carried.as_ptr(), pointer);
    assert_eq!(carried.capacity(), capacity);
}

/// Publish and volume status responses carry `no-store`, including refusals.
/// Store admission refusals omit the cache directive.
#[test]
fn every_authority_response_is_no_store_and_carries_its_body_rules() {
    let publish = [
        PublishRefusal::BadRequest,
        PublishRefusal::NoPrincipal,
        PublishRefusal::NotEnrolled,
        PublishRefusal::EnrollmentUnavailable,
        PublishRefusal::RateLimited { retry_after: 3 },
        PublishRefusal::InvalidCandidate,
        PublishRefusal::MissingReference,
        PublishRefusal::InvalidReference,
        PublishRefusal::PublishWorkLimit,
        PublishRefusal::TooLarge,
        PublishRefusal::NoLog,
        PublishRefusal::UnknownVolume,
        PublishRefusal::MethodNotAllowed,
        PublishRefusal::Internal,
        PublishRefusal::Unavailable,
        PublishRefusal::Fenced,
        PublishRefusal::Stopped,
    ];
    for refusal in publish {
        let outcome = Outcome::publish_refused(refusal);
        let (status, token) = refusal.answer();
        assert_eq!(outcome.status(), status, "{refusal:?}");
        assert_eq!(outcome.error(), Some(token), "{refusal:?}");
        assert_eq!(outcome.cache_control(), Some(CacheControl::NoStore));
        assert!(outcome.body().is_empty(), "§8.3: no answer body");
        assert_eq!(outcome.content_type(), None);
        let expected_retry = match refusal {
            PublishRefusal::RateLimited { retry_after } => Some(retry_after),
            _ => None,
        };
        assert_eq!(
            outcome.retry_after(),
            expected_retry,
            "Retry-After on 429 only; a fence carries none"
        );
        assert_eq!(
            outcome.allow(),
            (status == Status::MethodNotAllowed).then_some(Allow::Post)
        );
    }
    for (conflict, token) in [
        (PublishConflict::StaleBase, "stale-base"),
        (PublishConflict::OperationBound, "operation-bound"),
        (PublishConflict::NotDecided, "not-decided"),
        (PublishConflict::EpochMismatch, "epoch-mismatch"),
        (PublishConflict::VolumeDamaged, "volume-damaged"),
    ] {
        let outcome = Outcome::publish_conflict(conflict, vec![9, 9]);
        assert_eq!(outcome.status().as_u16(), 409);
        assert_eq!(outcome.error().map(ErrorToken::as_str), Some(token));
        assert_eq!(outcome.content_type(), Some(ContentType::AuthorityAnswer));
        assert_eq!(outcome.cache_control(), Some(CacheControl::NoStore));
        assert_eq!(outcome.body(), &[9, 9], "§8.3's one exception: the answer");
    }
    for (outcome, status, content_type) in [
        (
            Outcome::publish_settled(vec![1]),
            200,
            ContentType::AuthorityAnswer,
        ),
        (
            Outcome::publish_pending(vec![1]),
            202,
            ContentType::AuthorityAnswer,
        ),
        (
            Outcome::volume_status(vec![1]),
            200,
            ContentType::VolumeStatus,
        ),
    ] {
        assert_eq!(outcome.status().as_u16(), status);
        assert_eq!(outcome.error(), None);
        assert_eq!(outcome.content_type(), Some(content_type));
        assert_eq!(outcome.cache_control(), Some(CacheControl::NoStore));
    }
    for seam in [
        Outcome::no_principal(),
        Outcome::not_enrolled(),
        Outcome::enrollment_unavailable(),
        Outcome::authority_managed(),
        Outcome::rate_limited(1),
    ] {
        assert_eq!(
            seam.cache_control(),
            None,
            "a seam refusal, as §6 leaves it"
        );
    }
}

/// The volume status's refusals carry `no-store` and never a principal
/// refusal or a `429`, and a `405` takes its directive from the resource.
#[test]
fn every_status_refusal_is_no_store_and_a_405_follows_its_resource() {
    let status_refusals = [
        StatusRefusal::BadRequest,
        StatusRefusal::NoLog,
        StatusRefusal::UnknownVolume,
        StatusRefusal::MethodNotAllowed,
        StatusRefusal::Internal,
        StatusRefusal::Unavailable,
        StatusRefusal::Fenced,
        StatusRefusal::Stopped,
    ];
    for refusal in status_refusals {
        let outcome = Outcome::status_refused(refusal);
        let (status, token) = refusal.answer();
        assert_eq!(outcome.status(), status, "{refusal:?}");
        assert_eq!(outcome.error(), Some(token), "{refusal:?}");
        assert_eq!(outcome.cache_control(), Some(CacheControl::NoStore));
        assert!(outcome.body().is_empty());
        assert_eq!(outcome.retry_after(), None, "a read's refusal: no 429");
        assert_ne!(status, Status::Forbidden, "a read needs no principal");
        assert_eq!(
            outcome.allow(),
            (status == Status::MethodNotAllowed).then_some(Allow::Get)
        );
    }
    // A `405` built from the resource carries the resource's directive,
    // whichever constructor builds it.
    for resource in [Resource::Publish, Resource::VolumeStatus] {
        assert_eq!(
            Outcome::method_not_allowed(resource).cache_control(),
            Some(CacheControl::NoStore)
        );
    }
    for resource in [
        Resource::Bin,
        Resource::Meta,
        Resource::Root,
        Resource::MaxSeq,
        Resource::Hint,
    ] {
        assert_eq!(Outcome::method_not_allowed(resource).cache_control(), None);
    }
}
