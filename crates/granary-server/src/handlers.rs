// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! §4.2's nine operations, one free generic `async fn` each.
//!
//! **These own §5a.6 steps 7 and 8 only** — the body cap and the seam
//! call. Steps 1–6 are [`crate::admission::admit`]'s and are discharged
//! before any function here is reached, which is why a handler takes
//! already-parsed components and cannot see the raw target, the method,
//! or whether a conditional field was present. Re-encoding the order
//! here is not merely redundant; it is impossible.
//!
//! **The body cap runs BEFORE the address check.** A 300 MiB body
//! sent to the wrong digest is `413`, not `400`. This crate's enumeration
//! of §5a.6's order numbers the body caps step 7 and the seam call
//! step 8, and the address check is the seam call's precondition rather
//! than a step of its own. Stated because the two answers are both
//! defensible and an accept set that depends on which check ran first is
//! not an accept set (§7.1).
//!
//! **No hyper type and no tokio primitive.** Every parameter is a `&str`,
//! a plain value, or an owned `Vec<u8>`, and the only awaits are on the
//! seam's own futures — so the same functions serve the HTTP adapter, an
//! in-process embedding and the simulator without any of them inheriting
//! a runtime choice. Both seam traits are RPITIT and therefore
//! dyn-incompatible, so the store arrives as a generic bound and never as
//! `&dyn`.
//!
//! **What a seam error may say on the wire: nothing.**
//! `RootStoreError::RefusedResponse { reason }` and
//! `RootStoreError::Backend(String)` both carry text that names the store
//! key that was read, and §8.4 forbids relaying it — "a server maps such
//! a refusal to a status and a fixed token, and keeps the text for its
//! own logs". [`seam_failure`] is where that happens, once — and where
//! the second half of that sentence is now discharged: it emits the
//! `internal failure` event that keeps the text FOR the process's own logs.
//! Until that landed the text was dropped on the floor, so an
//! operator whose bucket did not exist saw `500`/`internal` for the life
//! of the process with the reason recorded nowhere.

use crate::admission::{Admitted, INGEST_UNPACKED_SUM_MAX, Operation};
use crate::policy::VerifyPolicy;
use crate::wire::{ETag, Outcome};
use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::rootstore::{
    HintRead, HintToken, RootStore, RootStoreError, SEQ_KEY_DIGITS, parse_hint_body,
};
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};
use granary_store::verify::{BinVerifyError, verify_bin};
use std::num::NonZeroU64;

// --------------------------------------------------------- shared decisions

/// §5a.6 step 7: is this body inside the cap for its object kind?
///
/// The count is the body's own length — §5a.2's "count the bytes as
/// framed; never trust `Content-Length`" reaching its last layer, where
/// the bytes are already in hand. `RequestHead::declared_len` is not
/// consulted and must not be.
///
/// The `try_from` cannot fail on any target this workspace supports; it
/// is written rather than asserted because a length that will not fit a
/// `u64` is over every cap here by construction, so the total form and
/// the correct answer coincide.
fn within_cap(body: &[u8], cap: u64) -> bool {
    u64::try_from(body.len()).is_ok_and(|len| len <= cap)
}

/// The longest answer a conforming seam can give a ranged read of `len`
/// bytes starting at `offset` (§7.2, §7.1).
///
/// Both halves are load-bearing and only the first is obvious. `len` is
/// what the request asked for, and §7.2 licenses fewer bytes ("a short
/// read is a success") and never more. The ceiling is what closes the
/// hole `len` alone leaves: §7.1 resolves the open-ended and over-wide
/// forms to `u32::MAX`, so `len` by itself would admit a 4 GiB answer for
/// a `bytes=0-` on an object no legal bin can fill.
///
/// **The ceiling term is what is left BELOW it from this offset, not the
/// whole of it.** `BIN_MAX_BYTES` alone bounds the answer's size and says
/// nothing about where it lands: `bytes=268435455-` names the last legal
/// byte position, and a two-byte answer there would be declared as
/// `bytes 268435455-268435456/*` — a byte at a position no legal bin can
/// hold, in a `Content-Range` that is internally consistent and
/// therefore invisible to §7.2's client-side checks.
fn seam_read_bound(offset: u64, len: u32) -> u64 {
    // 256 MiB is far below u32::MAX, so the first term narrows the
    // open-ended form and leaves every fully specified int-range alone.
    //
    // `saturating_sub` and not a bare `-`: `admit` refuses every
    // `offset >= BIN_MAX_BYTES` with `416` before a handler is reached
    // (§7.1), so the difference cannot go negative on a served request —
    // and if it ever could, a bound of zero refuses every answer, where
    // a wrap to 2^64 would admit every answer. The safe direction is the
    // one that is written.
    u64::from(len).min(BIN_MAX_BYTES.saturating_sub(offset))
}

/// Every seam failure that is not a row in the endpoint's own §5.x table.
///
/// **`500` + `internal`, and the text never leaves the process.** §8.4
/// makes that a MUST for diagnostic text generally, and `RefusedResponse`
/// carries the rule on its own doc as well ("never relay this to a remote
/// client — it names the store key that was read"). `Backend`'s doc says
/// only "anything else the backend reported", so the rule for that arm
/// rests on §8.4 alone; the answer is the same.
///
/// **`InvalidVolume` is unreachable from a served request**, and is
/// classified rather than left out. §4.3's `{volume}` grammar is the same
/// DNS-1123 predicate the store applies at its key boundary, and the gate
/// checks it first, so reaching this arm means the server's own parse and
/// the store's disagree — a server bug, not a statement about the
/// request. No §5.x table has a row for it, which is precisely why it
/// must not be given a `4xx` here.
///
/// **`Unavailable` is unreachable from the server's own store too, for
/// the same reason.** It is produced by `granary-client`'s `HttpStore`
/// mapping a wire `503` — a CLIENT-side classification of
/// a response FROM a granary server. `granary-store`'s adapter, which is
/// what this server's own seam actually is, never constructs it. Kept
/// here rather than left out for the same compile-time-exhaustiveness
/// reason as `InvalidVolume`.
///
/// **`Elapsed` is unreachable here for the identical reason:
/// it is `HttpStore`'s per-seam-call deadline, cutting a wedged CLIENT
/// wait on a peer — this server never runs the client seam, so its own
/// store never produces one.**
///
/// The match has no wildcard arm: a tenth `RootStoreError` variant is
/// classified here or does not compile.
fn seam_failure(error: &RootStoreError) -> Outcome {
    log_seam_failure(error);
    match error {
        RootStoreError::AlreadyExists
        | RootStoreError::Precondition
        | RootStoreError::NotFound
        | RootStoreError::RangeOverflow
        | RootStoreError::InvalidVolume { .. }
        | RootStoreError::RefusedResponse { .. }
        | RootStoreError::Unavailable { .. }
        | RootStoreError::Elapsed { .. }
        | RootStoreError::UnexpectedStatus { .. }
        | RootStoreError::Backend(_) => Outcome::internal(),
    }
}

/// **The one message every `500`-producing site in this module logs
/// under: `internal failure`.**
///
/// One name, because an operator has one question. A `500` reaches the
/// peer as §8.2's `internal` token and nothing else, so the whole of
/// what they can do is read that on the `served` line and then ask why
/// — and that answer must not be spread across event names they have to
/// know in advance. [`seam_kind`], [`SeamContract::kind`] and
/// [`codec_failure`]'s label are the discriminator; the message is the
/// thing to grep. It is deliberately the wire token's own word, so
/// `error=internal` on `served` and this event read as the pair they
/// are, joined by the span's `request_id`.
///
/// It is NOT `store failure`, which the initial store-error logging used.
/// Two of the three families are about the store; the third — a codec
/// that would not build — is this process's own environment, and telling
/// an operator their store failed when their zstd context did not build
/// sends them to the wrong system.
///
/// The literal is repeated at each emitting site because `tracing`'s
/// macros take the message as a format LITERAL — a `const` in that
/// position silently becomes a FIELD named after the constant, which is
/// how the first attempt at this emitted three events with no message at
/// all and every row above stayed on `others`. `the_internal_failure_*`
/// rows pin the count so the three cannot drift apart.
///
/// The most of a seam failure's own text that reaches a log line.
///
/// **A bound, and not tidiness.** The text this clips is not granary's:
/// `granary-store` builds [`RootStoreError::Backend`] from
/// `object_store::Error`'s `Display`, and `object_store` 0.14.1's
/// `RequestError::Status` and `RequestError::Response` arms embed the
/// ENDPOINT'S RESPONSE BODY verbatim (`client/retry.rs:116,122`) — a
/// string this process neither authored nor bounds. Rendered whole into
/// a line whose queue is bounded in LINES and not in bytes
/// (`sink::QUEUE_LINES`), that is precisely the amplifier
/// `adapter::method_label` exists to close, arriving through the store
/// instead of through the request head.
///
/// 512 bytes is generous for the messages that carry diagnosis — S3's
/// `NoSuchBucket` renders inside it — and it is a ceiling rather than a
/// target: the field costs what the message costs, up to this.
pub(crate) const STORE_DETAIL_MAX: usize = 512;

/// The seam failure's VARIANT, as a bounded label.
///
/// **These are NOT `Granary-Error` tokens and must never be read as
/// some.** §8.2's registry is closed and every one of these failures
/// answers the peer `internal`; this vocabulary is the log's, it never
/// reaches a header, and widening it costs a log reader nothing where
/// widening §8.2's would be a protocol change.
///
/// No wildcard arm, for [`seam_failure`]'s reason one line up.
const fn seam_kind(error: &RootStoreError) -> &'static str {
    // The log's vocabulary is the type's own; `Elapsed` is unreachable from
    // this server's own store (see `seam_failure`'s doc) and
    // `UnexpectedStatus` is raised only by the client's HTTP store, but both
    // are classified by the type's exhaustive match.
    error.kind()
}

/// The store's OWN words, where it had any.
///
/// `None` for the four unit variants deliberately: their `Display` is a
/// fixed phrase that [`seam_kind`] already implies, and a field carrying
/// it would be the kind spelled twice. `tracing` records nothing at all
/// for a `None`, so those events carry `kind` and no `detail` rather
/// than a placeholder.
fn seam_detail(error: &RootStoreError) -> Option<&str> {
    match error {
        RootStoreError::AlreadyExists
        | RootStoreError::Precondition
        | RootStoreError::NotFound
        | RootStoreError::RangeOverflow => None,
        RootStoreError::InvalidVolume { reason }
        | RootStoreError::RefusedResponse { reason, .. } => Some(reason),
        RootStoreError::Unavailable { operation, .. }
        | RootStoreError::Elapsed { operation, .. }
        | RootStoreError::UnexpectedStatus { operation, .. } => Some(*operation),
        RootStoreError::Backend(msg) => Some(msg),
    }
}

/// `text` truncated to at most `max` BYTES, on a character boundary.
///
/// Total by construction: the end offset is built from `char_indices`,
/// so it is always a boundary, and `get` answers `None` rather than
/// panicking if it somehow is not. `&str[..n]` would panic mid-character
/// on the first non-ASCII byte a store put in a message, on a path that
/// only runs when something has already gone wrong.
fn clipped(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let end = text
        .char_indices()
        .map(|(at, ch)| at + ch.len_utf8())
        .take_while(|&end| end <= max)
        .last()
        .unwrap_or(0);
    text.get(..end).unwrap_or("")
}

/// **The store's own words go in the LOG, because §8.4 forbids
/// them on the wire.**
///
/// An operator whose `GRANARY_STORE_BUCKET` does not exist — this server
/// never creates one, see `config::ENV_STORE_BUCKET` — gets
/// `status=500 error=internal` from the `served` event on every request
/// for as long as the process runs, and until this event the cause was
/// recorded nowhere at all. That is what makes "serve, and fail per
/// request" defensible instead of merely quiet.
///
/// **Why a SEPARATE event rather than a field on `served`.** A field
/// would cost no extra line, which is a real advantage; it was weighed
/// and lost on three counts.
///
/// 1. `served` is the per-request COUNTING SUBSTRATE, and `adapter.rs` states its
///    invariant: "every field this module logs has a closed domain or a
///    machine-generated value — no bytes a peer chose reach any line of
///    it". The store's text is free text a peer partly composes (the
///    volume name and grain id it was asked for become the store KEY the
///    message names), and a Phase-2 exporter is documented to read every
///    `served` event with zero loss — so the field would hand a metrics
///    pipeline an unbounded-cardinality label on the one path a peer can
///    provoke at will. `kind` is the closed-domain half and it sits
///    here, not there, for the same reason: one event, one concern.
/// 2. Reaching `served` from this function costs either an
///    out-parameter threaded through `dispatch` and all nine handlers —
///    `operation`'s precedent is ONE function, not eleven — or a field
///    on [`Outcome`] carrying store text into the type that BUILDS the
///    response. §8.3/§5.10 make that text a disclosure defect
///    (`loopback::no_refusal_discloses_what_the_store_said`), and "a
///    field that must never be rendered, on the renderer" is the
///    highest-risk of the three shapes for the one property that must
///    not break. Nothing on this path can reach a header or a body.
/// 3. Correlation does not need co-location: both lines are inside the
///    `grain_request` span and carry its `request_id`, so the pair
///    joins.
///
/// **What the extra line COSTS, said out loud rather than discovered
/// later.** It is a third rendered line on a store-failing request,
/// where `adapter.rs` already records that `FmtSpan::CLOSE`'s second
/// line halves the depth of a queue bounded in LINES. It is emitted
/// BEFORE `served`, so behind a stalled writer it takes a slot `served`
/// would have had — the ordering hazard that module names. Accepted on
/// two grounds: the line sits behind a COMPLETED store dispatch, so its
/// rate is the store's and not the peer's; and during the outage this
/// event exists for, every `served` line is the identical
/// `500`/`internal`/`operation` triple, so a dropped one costs a
/// duplicate where a dropped diagnostic costs the only copy. The queue still
/// cannot prioritise `served` lines, and this does not resolve that limitation.
///
/// WARN and not DEBUG: a store that cannot answer is an operational
/// fault, and a diagnostic only a re-run with `RUST_LOG=debug` can
/// obtain is no answer for a bucket that was missing all along.
fn log_seam_failure(error: &RootStoreError) {
    tracing::warn!(
        kind = seam_kind(error),
        detail = seam_detail(error).map(|text| clipped(text, STORE_DETAIL_MAX)),
        "internal failure"
    );
}

/// A pinned seam-CONTRACT rule broken by a store that answered `Ok`.
///
/// **A different family from [`seam_kind`]'s, and the difference is the
/// point.** A `RootStoreError` is the store REPORTING that it failed,
/// and it arrives with the store's own words. These are granary
/// detecting that the store answered successfully with something its
/// contract forbids — it did not fail, it LIED — and there are no words
/// to carry, only the rule. An operator needs to tell those apart
/// because the remediation is not the same: one is a bucket, a network
/// or a credential, the other is an implementation that does not
/// conform, or an object someone planted.
///
/// So every value here is prefixed `contract-`, and `detail` is a
/// `&'static str` naming the rule. That makes the whole event
/// FIXED-SIZE on this family — no store text, no peer bytes — which is
/// what makes the flood answer below hold.
#[derive(Clone, Copy, Debug)]
enum SeamContract {
    /// `get_bin_range` answered more bytes than the request could have
    /// asked for.
    OverRead,
    /// A served range has no legal `Content-Range` — a zero-byte answer,
    /// or one whose last position overflows.
    Extent,
    /// `get_meta`/`get_root` answered an object past the frozen ceiling
    /// for its kind.
    OverCap,
    /// `max_seq` answered `Some(0)`.
    ZeroSeq,
    /// `max_seq` answered `Some(u64::MAX)`.
    ReservedSeq,
    /// `read_hint` answered a token that is not a strong entity-tag.
    HintValidator,
    /// `read_hint` answered `NotModified` for a request that sent no
    /// validator to echo.
    StaleNotModified,
}

impl SeamContract {
    /// The bounded label. No wildcard arm: an eighth rule is named here
    /// or does not compile.
    ///
    /// `OverCap` covers `get_meta` and `get_root` with ONE value on
    /// purpose — the rule broken is identical ("an object past the
    /// frozen ceiling for its kind") and the `served` line carries
    /// `operation` under the same `request_id`, so which endpoint it was
    /// is already recorded and a second value would only be that fact
    /// spelled twice.
    const fn kind(self) -> &'static str {
        match self {
            Self::OverRead => "contract-over-read",
            Self::Extent => "contract-extent",
            Self::OverCap => "contract-over-cap",
            Self::ZeroSeq => "contract-zero-seq",
            Self::ReservedSeq => "contract-reserved-seq",
            Self::HintValidator => "contract-hint-validator",
            Self::StaleNotModified => "contract-stale-not-modified",
        }
    }

    /// Describes the store contract violation in the operator log.
    const fn detail(self) -> &'static str {
        match self {
            Self::OverRead => {
                "a ranged read may return fewer bytes than requested, but the store returned more"
            }
            Self::Extent => {
                "the seam's answer has no legal Content-Range to declare — a zero-byte body, \
                 or a last position past u64"
            }
            Self::OverCap => {
                "the seam answered an object larger than the frozen format ceiling for its kind"
            }
            Self::ZeroSeq => "the store returned sequence 0, which is invalid as a head",
            Self::ReservedSeq => {
                "the seam answered u64::MAX as a head; it is RESERVED and never a head, \
                 and one planted root is enough to provoke this"
            }
            Self::HintValidator => {
                "the store returned a hint token that cannot form the required strong ETag"
            }
            Self::StaleNotModified => {
                "the store returned NotModified for a hint read with no usable cached validator \
                 for the 304 response ETag"
            }
        }
    }
}

/// **The other store-diagnostic family: the `500`s where the store MISBEHAVED.**
///
/// [`seam_failure`] covers the store REPORTING a failure. This funnel
/// logs a contract violation before returning `Outcome::internal()`, so
/// a successful store response that breaks a pinned rule has a cause
/// recorded alongside its `500`.
///
/// **The flood question, re-asked for this family and answered
/// differently from [`log_seam_failure`]'s.** One of these arms is
/// PEER-TRIGGERABLE: an unauthenticated peer that plants a root at
/// `u64::MAX` makes every subsequent `GET max-seq` on
/// that volume take [`SeamContract::ReservedSeq`], for as long as the
/// object exists. Three things bound it, and the first is the one that
/// does the work:
///
/// 1. **The line is FIXED SIZE.** Both fields are `&'static str`, so
///    unlike a `Backend` failure there is no store text and no peer
///    bytes in it — nothing an attacker can inflate, only lines they can
///    provoke.
/// 2. It sits behind `max_seq`'s own uncapped recursive LIST over
///    `root/{volume}`, which is orders of magnitude
///    more expensive per request than a log line. The amplifier on that
///    path is the listing, not this.
/// 3. The request already renders two lines (`served` plus
///    `FmtSpan::CLOSE`), so this is the same 1.5x multiplier
///    [`log_seam_failure`] argues, on a queue whose loss is designed and
///    counted.
///
/// None of that gives `served` lines priority over other queued log lines.
fn contract_violation(broken: SeamContract) -> Outcome {
    tracing::warn!(
        kind = broken.kind(),
        detail = broken.detail(),
        "internal failure"
    );
    Outcome::internal()
}

/// The third family: **this process's own environment failed**, and
/// neither the store nor the request is at fault.
///
/// One site — `verify_bin`'s `Codec` arm, a zstd context that would not
/// build, which `BinVerifyError` itself documents as "Environmental, and
/// the server's `500`". It gets its own `kind` rather than being folded
/// into either family above, because both of those send an operator to
/// the store and this one must not: nothing about their bucket is wrong.
///
/// The text is the codec's own and is clipped like any other borrowed
/// message — it comes from a dependency, so its length is not this
/// crate's to promise.
fn codec_failure(detail: &str) -> Outcome {
    tracing::warn!(
        kind = "codec",
        detail = clipped(detail, STORE_DETAIL_MAX),
        "internal failure"
    );
    Outcome::internal()
}

/// The hint's REQUIRED strong `ETag` from the store's opaque version
/// token (§5.8, §6).
///
/// **The decision this encodes: try the token verbatim, then try it
/// wrapped in one pair of DQUOTEs, and answer `None` if neither is a
/// strong `entity-tag`.** `HintToken` is `e_tag.unwrap_or_default()`,
/// which arrives already quoted from S3 and `MinIO` and bare from an
/// in-memory backend, and RFC 9110 §8.8.3 requires the quotes.
///
/// It is not a shape *guess*: the grammar decides both times, so nothing
/// unsafe is admitted by the second attempt. A token holding a `"`, a
/// `CR`, an `LF`, a control byte or nothing at all fails both routes —
/// wrapping a value that contains a `"` puts one inside the tag, which
/// `etagc` excludes — and `None` is the caller's `500`, never a `4xx` and
/// never a panic. An already-quoted token is echoed verbatim and is never
/// quoted twice.
///
/// **What it costs, stated rather than discovered later.** On a backend
/// whose tokens are bare, the value a client caches is not the value the
/// store holds, so `read_hint`'s revalidation cannot match and the answer
/// is a fresh `200` where a `304` was possible. The wire stays conforming
/// — a `200` is always a legal answer to a conditional request, and §5.8's
/// "the `ETag` MUST change whenever the hint's seq changes" holds either
/// way — and the backends this profile is deployed on are the quoted
/// ones, where the round trip is exact.
fn validator(token: &HintToken) -> Option<ETag> {
    ETag::new(token.0.clone()).or_else(|| ETag::new(format!("\"{}\"", token.0)))
}

/// The `If-None-Match` field value as a cached validator, or `None` when
/// the field carried something this resource could not have issued
/// (§5a.6, §6).
///
/// **RFC 9110 §13.1.2 makes the field `"*" / #entity-tag` — the wildcard
/// or a LIST — and only one spelling of it is a validator here.** §5.8's
/// `ETag` is opaque and "a client echoes it verbatim", so a conforming
/// client sends exactly one strong entity-tag; an attacker sends the
/// other forms. Handing the raw value to the seam as a `HintToken` lets
/// a store that matched it drive a `NotModified`, and the `304` then
/// carries that value back as its `ETag` — `ETag: "*"` for the wildcard.
/// §6 requires a `304` to carry the same `ETag` the `200` would have
/// carried, and none of those forms is one.
///
/// **Refusing the value is not an error, and §5a.6 says which answer it
/// is**: "a value on the exempt field that the server cannot match is
/// not an error — the answer is whatever the unconditional request would
/// have produced". So `None` here is `cached: None` at the seam and an
/// ordinary unconditional read; the `400` belongs to the conditional
/// fields OUTSIDE the exemption, and this one is inside it.
///
/// The test is [`ETag`]'s own grammar — RFC 9110 §8.8.3's strong
/// `entity-tag`, checked once, in the constructor — so the wildcard, a
/// two-tag list, a weak tag, an empty value and a `CR`/`LF` all fail it
/// and none of them reaches the store.
fn cached_validator(value: &str) -> Option<HintToken> {
    ETag::new(value.to_owned())
        .is_some()
        .then(|| HintToken(value.to_owned()))
}

// ------------------------------------------------------------------- bins

/// `PUT {base}/bin/{digest}` — §5.1.
///
/// Cap first (`413`), then the address (`400` + `address-mismatch`), then
/// the seam: `Ok(true)` is `201` and `Ok(false)` is `200`, because an
/// existing content-addressed object holds the same bytes the caller was
/// about to write.
///
/// **§5.1's grain verification IS performed here, under `policy`.** The
/// ingest-verification admission layer — decode the bin, expand every grain, hold it to
/// the id its index claims — sits above the seam contract (§13.5), and
/// the mechanism is `granary-store`'s Apache primitive while the policy,
/// the ceiling and the token mapping are this crate's. §13.5's two
/// profiles both run: the shipped server verifies, and the seam-only
/// profile a conformance run declares does not.
pub(crate) async fn put_bin<R: RootStore + BinStore>(
    store: &R,
    digest: &[u8; DIGEST_LEN],
    body: Vec<u8>,
    policy: VerifyPolicy,
) -> Outcome {
    if !within_cap(&body, BIN_MAX_BYTES) {
        return Outcome::too_large();
    }
    // §5.1: "The server MUST verify the address before storing."
    // Presence is never integrity, and a mismatched pair would store
    // bytes under an id that does not name them.
    if GrainId::of(&body).digest() != digest {
        return Outcome::address_mismatch();
    }
    // §5.1's third and second duties, in the order §5.1 fixes: the
    // decompressed-sum test PRECEDES grain verification (it is inside
    // `verify_bin`, ahead of the loop), because avoiding that work is
    // what it is for.
    //
    // The MAPPING is this crate's and the mechanism is not — the licence
    // boundary runs AGPL handler to Apache primitive, which is the
    // permitted direction. `Undecodable` and `GrainInvalid` share one
    // token because §13.4 binds `verify-failed` to both; the sum
    // overflow is `413` + `too-large` and never `layout-invalid`,
    // because the client's action is re-pack smaller and RETRY and
    // `layout-invalid` reads as never-retry (§9.2); and a
    // codec that would not build is the environment failing, which is
    // nothing about the request.
    // The policy test SHORT-CIRCUITS the verify, and the order is not
    // stylistic: `&&` is what keeps a seam-only server from paying for a
    // verification whose answer it then discards.
    if policy.verifies()
        && let Err(error) = verify_bin(&body, INGEST_UNPACKED_SUM_MAX)
    {
        return match error {
            BinVerifyError::Undecodable(_) | BinVerifyError::GrainInvalid { .. } => {
                Outcome::verify_failed()
            }
            BinVerifyError::DecompressedSumExceeded { .. } => Outcome::too_large(),
            BinVerifyError::Codec(codec) => codec_failure(&codec.to_string()),
        };
    }
    match store.put_bin(digest, body).await {
        Ok(true) => Outcome::created(),
        Ok(false) => Outcome::already_present(),
        Err(error) => seam_failure(&error),
    }
}

/// `GET {base}/bin/{digest}` — §5.2, §7.2.
///
/// A `Range` is REQUIRED and there is no unranged form, which is why
/// `offset` and `len` are parameters rather than options:
/// `BinStore::get_bin` deliberately does not exist, and the gate has
/// already refused an absent or unacceptable `Range` (§7.1) and a
/// `first-pos` at or past the ceiling (§7.3).
///
/// **The extent is declared from the offset this function ASKED FOR,
/// because it is the only offset that exists here.**
/// `BinStore::get_bin_range` answers a bare `Vec<u8>` and carries no
/// extent of its own, so `Outcome::bin_range` derives the width from the
/// body — a short read narrows the extent honestly — and the `first-pos`
/// can only be the one that was requested. Anything else would be
/// invented, and would emit a `Content-Range` over a slice the request
/// never named, self-consistently.
///
/// **That is not the server-side twin of §7.2's check 1, and calling it
/// one would be backwards.** Check 1 is the CLIENT comparing the
/// response's `first-pos` against the offset it asked for, and a server
/// that echoes the requested offset is exactly the server against which
/// that check can never fire. §7.2's closing paragraph settles what the
/// gate then rests on and this layer does not re-argue it: "the server's
/// honest report of what it returned", with a server that lies "caught
/// one layer down … bins are content-addressed and every reader verifies
/// what it consumed" (§5a.3). What this layer owes is the honest report,
/// and the extent is honest by construction because both halves are
/// derived rather than declared.
///
/// **The seam's own answer is checked before a byte of it is relayed.**
/// §9.1 item 5 makes the store's responses untrusted input to the
/// SERVER, not only to the client, and §9.2 names "no byte used from a
/// response whose extent was not checked against the extent requested"
/// among the controls. `granary-store`'s adapter already refuses an
/// over-read with `RefusedResponse`; this function declines to depend on
/// that, because `BinStore` is an interface anyone may implement and
/// these bytes go straight out to an unauthenticated peer (§3). It is
/// the same enforcement `max_seq` applies to a seam that answered
/// `Some(0)`, and the same answer: a seam violating its own pinned
/// contract is a server bug, so `internal()` — not a `4xx`, because
/// nothing about the request was wrong.
///
/// **This applies no extent policy of its own, and the policy now
/// EXISTS.** §7.1's declared maximum extent is real and enforced — but
/// in the gate, at step 6, on the mapped `len` and before the store is
/// touched (see `admission::DECLARED_MAX_EXTENT`). By the time a `len`
/// reaches this function it is one the deployment's declaration admits,
/// so serving it as asked is the whole of this function's job.
///
/// **The division is the one §7.1 requires, not a tidiness preference.**
/// The rule refuses the ASK and refuses it WHOLE: a cap applied here
/// could only narrow an extent the gate had already admitted, which is
/// precisely what §7.1 forbids — "MUST NOT truncate the range, MUST NOT
/// serve a prefix of it, and MUST NOT narrow it to the declared maximum
/// and present the result as the short read", because §7.2 spends the
/// `complete-length` that would let a client tell a policy prefix from
/// end-of-object. A second cap here would also make the refusal
/// boundary depend on what the store holds, creating a forbidden
/// length oracle (§7.4). The clamp on the open-ended form stays sound
/// for its own separate reason: `BIN_MAX_BYTES` sits far below
/// `u32::MAX`, so it can never truncate a legal bin's tail.
///
/// The amplification hazard §9.2 names is what the gate's step 6
/// answers; §9.2 is explicit that the per-request bound is all this
/// layer claims, and that the controls bounding the NODE are the accept
/// envelope, §9.5's flow control and Part II's streaming.
///
/// **`Err(Backend)` is `500`, NEVER `416`** (§5.2, §7.3): the seam answers
/// that variant both for a range starting past the end of a stored object
/// and for a transport failure, and it carries no discriminator, so `416`
/// here would report a store outage to the client as a bad range. `416`
/// is reachable on exactly one route, and that route is in the gate.
pub(crate) async fn get_bin_range<R: RootStore + BinStore>(
    store: &R,
    digest: &[u8; DIGEST_LEN],
    offset: u64,
    len: u32,
) -> Outcome {
    match store.get_bin_range(digest, offset, len).await {
        // An OVER-read, refused. A short read is a success (§7.2) and
        // falls through to the arm below, where the extent narrows to
        // match it.
        Ok(bytes) if !within_cap(&bytes, seam_read_bound(offset, len)) => {
            contract_violation(SeamContract::OverRead)
        }
        // The SAME offset that was given to the seam.
        Ok(bytes) => Outcome::bin_range(offset, bytes)
            .unwrap_or_else(|| contract_violation(SeamContract::Extent)),
        Err(RootStoreError::NotFound) => Outcome::not_found(),
        Err(error) => seam_failure(&error),
    }
}

// ------------------------------------------------------------ meta objects

/// `PUT {base}/volume/{volume}/meta/{grain-id}` — §5.3.
///
/// **The server MUST verify the address and MUST NOT parse the body.** A
/// meta object is one of four kinds and the server has no reason to know
/// which: the shared conformance body stores a 13-byte non-object here
/// and requires success, and a publishing client is entitled to store a
/// shard under a format the server has not been taught. The address check
/// is the whole of the obligation.
pub(crate) async fn put_meta<R: RootStore + BinStore>(
    store: &R,
    volume: &str,
    id: &GrainId,
    body: Vec<u8>,
) -> Outcome {
    if !within_cap(&body, META_MAX_BYTES) {
        return Outcome::too_large();
    }
    if GrainId::of(&body) != *id {
        return Outcome::address_mismatch();
    }
    match store.put_meta(volume, id, body).await {
        Ok(true) => Outcome::created(),
        Ok(false) => Outcome::already_present(),
        Err(error) => seam_failure(&error),
    }
}

/// `GET {base}/volume/{volume}/meta/{grain-id}` — §5.4.
///
/// **The bound applies to what is read back, and the server applies it
/// even though the seam was not obliged to.** `RefusedResponse` is
/// documented as PERMITTED and not required, so a conforming
/// implementation may hand back an object of any size; §5a.2's "both
/// directions" puts `META_MAX_BYTES` on a meta *response* exactly as on
/// a `PUT`, and §9.1 item 5 makes the store's own answers untrusted
/// input to the SERVER — these bytes go straight out to an
/// unauthenticated peer (§3). Same answer as the other pinned-contract
/// violations: `internal()`, because nothing about the request was
/// wrong.
pub(crate) async fn get_meta<R: RootStore + BinStore>(
    store: &R,
    volume: &str,
    id: &GrainId,
) -> Outcome {
    match store.get_meta(volume, id).await {
        Ok(bytes) if !within_cap(&bytes, META_MAX_BYTES) => {
            contract_violation(SeamContract::OverCap)
        }
        Ok(bytes) => Outcome::meta(bytes),
        Err(RootStoreError::NotFound) => Outcome::not_found(),
        Err(error) => seam_failure(&error),
    }
}

// ------------------------------------------------------------------ roots

/// `PUT {base}/volume/{volume}/root/{seq}` — §5.5.
///
/// **Neither parses the body nor checks continuity** (§13.2 item 3): a
/// root's bytes are the client's, verified by signature and chain on the
/// read side, and a server that re-encoded or validated them would refuse
/// objects its own clients legally wrote.
///
/// **No occupancy probe.** §4.2 PERMITS a `get_root` before the content is
/// read, as a SHOULD serving the `Expect: 100-continue` path; it is a
/// permission, not an obligation, and it is not taken here. The ONE-PROBE
/// RULE is the CLIENT's obligation after an ambiguous `put_root` (§5.5),
/// never the server's, so this function makes exactly one seam call.
pub(crate) async fn put_root<R: RootStore + BinStore>(
    store: &R,
    volume: &str,
    seq: u64,
    body: Vec<u8>,
) -> Outcome {
    if !within_cap(&body, ROOT_MAX_BYTES) {
        return Outcome::too_large();
    }
    match store.put_root(volume, seq, body).await {
        Ok(()) => Outcome::created(),
        Err(RootStoreError::AlreadyExists) => Outcome::already_exists(),
        Err(error) => seam_failure(&error),
    }
}

/// `GET {base}/volume/{volume}/root/{seq}` — §5.6.
///
/// The body is the stored bytes **byte for byte**: no canonicalising, no
/// re-encoding, no repair (§2.1.1, §13.2 item 2). Only a non-canonical
/// stored object can tell a conforming server from one that re-encodes on
/// read, and only a bucket write outside granary produces one.
///
/// `Ok(None)` is `404` + `not-found` and is **not an error**: it is the
/// cheap negative a forward probe asks for constantly, and §8.1 maps the
/// token back to `Ok(None)` on the client.
///
/// **`ROOT_MAX_BYTES` bounds the relayed body, and the server applies it
/// even though the seam was not obliged to** — the reason [`get_meta`]
/// gives, with §5a.2 naming "a root response over `ROOT_MAX_BYTES`"
/// first among its examples. Refusing is not a re-encoding: the bytes
/// below the bound are still served byte for byte.
pub(crate) async fn get_root<R: RootStore + BinStore>(
    store: &R,
    volume: &str,
    seq: u64,
) -> Outcome {
    match store.get_root(volume, seq).await {
        Ok(Some(bytes)) if !within_cap(&bytes, ROOT_MAX_BYTES) => {
            contract_violation(SeamContract::OverCap)
        }
        Ok(Some(bytes)) => Outcome::root(bytes),
        Ok(None) => Outcome::not_found(),
        Err(error) => seam_failure(&error),
    }
}

/// `GET {base}/volume/{volume}/max-seq` — §5.7.
///
/// **`Ok(Some(0))` is not a head and MUST NOT be answered as one**
/// (§5.7, §13.2 item 4). The seam's own contract says it never returns
/// `Some(0)`, and the server enforces it anyway: an object planted at seq
/// 0 that became the head would block the first publish to a fresh volume
/// forever. The answer is `internal()` — a seam violating its pinned
/// contract is a server bug and §5.7's table offers no other row; it is
/// not a `4xx`, because nothing about the request was wrong, and it is
/// not the `404` row, which means something else entirely (the volume
/// has no roots at all).
///
/// **`Ok(Some(u64::MAX))` is not a head either**, and gets the identical
/// treatment on the identical grounds (§5.7, §13.2 item 4). The
/// seam contract already forbids the value — `u64::MAX` is RESERVED, and
/// the usable seq space is `1 ..= u64::MAX - 1` — and the server enforces
/// it anyway, which is this function's own idiom one paragraph up. The
/// harm mirrors seq 0's at the opposite end: a root planted at the top of
/// the range that became the head would leave no higher seq to publish
/// at, and a create-only PUT never releases the one it took, so seq 0
/// blocks a volume's FIRST publish and this blocks EVERY publish to it.
/// `u64::MAX - 1` is an ordinary `200`: exactly one value is reserved,
/// not a band.
pub(crate) async fn max_seq<R: RootStore + BinStore>(store: &R, volume: &str) -> Outcome {
    match store.max_seq(volume).await {
        // ORDER IS LOAD-BEARING: this arm must precede the one below.
        // `NonZeroU64::new(u64::MAX)` is `Some`, so a reversed pair would
        // send the reserved value straight to `Outcome::max_seq` and
        // serve it as a `200` — the guard would be present, compile, and
        // do nothing. Not a style choice; do not merge or reorder these
        // two arms. Swapping them fails
        // `max_seq_never_answers_the_reserved_top_of_the_range`, which
        // requires a `500`, not a `200`.
        Ok(Some(seq)) if seq == u64::MAX => contract_violation(SeamContract::ReservedSeq),
        Ok(Some(seq)) => NonZeroU64::new(seq).map_or_else(
            || contract_violation(SeamContract::ZeroSeq),
            Outcome::max_seq,
        ),
        Ok(None) => Outcome::max_seq_empty(),
        Err(error) => seam_failure(&error),
    }
}

// ------------------------------------------------------------------- hint

/// `GET {base}/volume/{volume}/hint` — §5.8.
///
/// `cached` is built from the `If-None-Match` value the gate carried
/// through, which is the one conditional this profile defines (§5a.6).
///
/// **The `404` row wins over the conditional.** A volume with no hint
/// object answers `404` + `not-found` even under `If-None-Match` — never
/// `304`, never `200` — and that is RFC 9110 §13.2.1's own ordering: a
/// precondition is irrelevant wherever the unconditional answer would be
/// neither `2xx` nor `412`. A `200` would have to invent 20 digits for a
/// hint that does not exist, and a `304` would confirm a seq whose hint is
/// gone.
///
/// **A stored hint of `0` degrades to `404`**, exactly as §5.8 degrades it
/// to `Ok(Missing)`: seq 0 can hold no root, so `Current { seq: 0 }` would
/// send every reader through a doomed `GET root/0` first. It is not a
/// `5xx` and not any other `4xx` — §5.8 forbids both on account of the
/// stored body's shape.
///
/// **A `304` with no validator to carry is `internal()`.** §6 requires the
/// `304` to carry the `ETag` the `200` would have carried, and the only
/// one available here is the client's own cached token; if the seam
/// answered `NotModified` without one having been sent, there is nothing
/// truthful to emit and the server has failed.
///
/// **`RefusedResponse` is `404` HERE, and on this endpoint alone.** §5.8
/// gives a server two conforming routes for a malformed or over-long
/// stored hint — serve the bytes, or "apply its own read bound and
/// answer `404`" — and forbids "a third: any `4xx` other than `404`, or
/// any `5xx`, on account of the stored body's shape".
/// `RootStore::read_hint` returns that variant for exactly the read
/// bound §5.8 licenses, so mapping it to a `500` is the forbidden answer
/// and it wedges every reader on the volume — the failure the section
/// exists to prevent, arriving through the input it calls the most
/// hostile. Every other variant keeps [`seam_failure`]'s mapping, and
/// §5.4 and §5.6 license no equivalent degrade, so the same error is
/// still a `500` on `GET meta` and `GET root`.
pub(crate) async fn read_hint<R: RootStore + BinStore>(
    store: &R,
    volume: &str,
    cached: Option<&HintToken>,
) -> Outcome {
    match store.read_hint(volume, cached).await {
        Ok(HintRead::Current { seq, token }) => NonZeroU64::new(seq).map_or_else(
            // §5.8: a hint body of 0 MUST degrade to Missing, which is
            // this endpoint's 404 + not-found on the wire.
            Outcome::hint_missing,
            |seq| {
                validator(&token).map_or_else(
                    // §5.8 makes the ETag REQUIRED here, so a token that
                    // is not a strong entity-tag leaves the server unable
                    // to answer at all.
                    || contract_violation(SeamContract::HintValidator),
                    |etag| Outcome::hint(seq, etag),
                )
            },
        ),
        Ok(HintRead::NotModified) => cached.and_then(validator).map_or_else(
            || contract_violation(SeamContract::StaleNotModified),
            Outcome::hint_not_modified,
        ),
        // §5.8's two conforming routes, on ONE arm because the section
        // puts them on one answer: "Both routes land on `Ok(Missing)`,
        // so the seam has exactly one conforming answer even though the
        // wire has two ways of producing it." `RefusedResponse` is the
        // read-bound route, and `404` on this endpoint is `Ok(Missing)`.
        Ok(HintRead::Missing) | Err(RootStoreError::RefusedResponse { .. }) => {
            Outcome::hint_missing()
        }
        Err(error) => seam_failure(&error),
    }
}

/// `PUT {base}/volume/{volume}/hint` — §5.9.
///
/// **A body that is not exactly 20 ASCII digits naming a `u64` is `400` +
/// `bad-request`, and never `413`.** §5.9's table has no `413` row: the
/// body has one legal length, so "too long" and "malformed" are the same
/// refusal, and the length check is the parse's first step rather than a
/// separate cap. `parse_hint_body` is core's own parser — the same one
/// §4.3 uses at the `{seq}` key and §5.7 on a `max-seq` body — so all
/// three agree by construction.
///
/// **`204` whether the hint was created or replaced** (deviation 9). The
/// seam cannot tell those apart: `write_hint` answers `Result<(), _>` and
/// no implementation reports whether an object was there before. A
/// pre-read would not repair it — §5.8's degrade rule makes a malformed
/// stored hint read as absent, and the write is a last-writer-wins
/// overwrite a concurrent publisher can land inside — so `201` would be
/// a guess dressed as a fact. `204` asserts only that the request
/// succeeded, which is true on both paths.
///
/// A body of `0` is accepted on write; §5.8's degrade handles the read
/// side.
pub(crate) async fn write_hint<R: RootStore + BinStore>(
    store: &R,
    volume: &str,
    body: Vec<u8>,
) -> Outcome {
    // The WIDTH first, before any pass over the bytes. §5.9 fixes the body
    // at exactly 20 octets, so every other length is refused whatever it
    // holds — and checking it here bounds the work at 20 bytes instead of
    // walking a 256 MiB body through a UTF-8 scan to reach the same answer.
    // The body is untrusted and unauthenticated (§3), so the cheapest
    // sufficient check goes first.
    if body.len() != SEQ_KEY_DIGITS {
        return Outcome::bad_request();
    }
    let Ok(text) = str::from_utf8(&body) else {
        return Outcome::bad_request();
    };
    let Ok(seq) = parse_hint_body(text) else {
        return Outcome::bad_request();
    };
    match store.write_hint(volume, seq).await {
        Ok(()) => Outcome::hint_written(),
        Err(error) => seam_failure(&error),
    }
}

// --------------------------------------------------------------- dispatch

/// §4.2's nine operations, routed from the evidence that §5a.6 steps 1–6
/// ran.
///
/// **This and [`crate::admit`] are the crate's whole public surface; the
/// nine handlers sit behind it.** An [`Admitted`] proves the ordered gate
/// ran on some request — it proves nothing about what the caller then did
/// with it. With the handlers reachable, an adapter could route a
/// conditional `DELETE`, or a request whose `Range` was never parsed,
/// straight to a handler and touch the store, and §5a.6's normative
/// `404` → `405` → `400` → `416` ordering would rest on the adapter
/// remembering it rather than on anything checkable. Routing here makes
/// `admit` the only way in, which is the same argument [`crate::Refusal`]'s
/// private constructors make one level down: evidence, not description.
///
/// `body` is the request content for the three `PUT`s. The six `GET`s
/// have none (§4.2) and ignore it, so an adapter hands over an empty
/// `Vec` — which allocates nothing.
///
/// **A Part-I composition root routes through [`GrainService`], never
/// here.** This function's write arms are LIVE — they reach the seam
/// with no ingest grain verification and take an already-accumulated body — and
/// both of those are exactly what §13.5 rule 1 and the streaming-cap
/// obligation forbid a production path until the ingest task lands
/// them. It stays exported because the sim edge and the in-process
/// embeddings are callers too, and because Part II replaces the
/// read-only router with this one; what may call it from a shipped
/// binary is the ingest task's decision, not a property this crate can
/// enforce from here.
///
/// [`GrainService`]: crate::GrainService
pub async fn dispatch<R: RootStore + BinStore>(
    store: &R,
    admitted: Admitted<'_>,
    body: Vec<u8>,
    policy: VerifyPolicy,
) -> Outcome {
    // No wildcard arm: a new operation is routed here or does not
    // compile.
    match admitted.operation() {
        // Authority dispatch requires private write-gate evidence in the adapter.
        Operation::Intent { .. } | Operation::Publish { .. } | Operation::VolumeStatus { .. } => {
            Outcome::unknown_target()
        }
        Operation::PutBin { digest } => put_bin(store, digest, body, policy).await,
        Operation::GetBinRange {
            digest,
            offset,
            len,
        } => get_bin_range(store, digest, *offset, *len).await,
        Operation::PutMeta { volume, id } => put_meta(store, volume, id, body).await,
        Operation::GetMeta { volume, id } => get_meta(store, volume, id).await,
        Operation::PutRoot { volume, seq } => put_root(store, volume.as_str(), *seq, body).await,
        Operation::GetRoot { volume, seq } => get_root(store, volume.as_str(), *seq).await,
        Operation::MaxSeq { volume } => max_seq(store, volume).await,
        Operation::ReadHint {
            volume,
            if_none_match,
        } => {
            let cached = if_none_match.and_then(cached_validator);
            read_hint(store, volume, cached.as_ref()).await
        }
        Operation::WriteHint { volume } => write_hint(store, volume, body).await,
    }
}

#[cfg(test)]
mod tests;
