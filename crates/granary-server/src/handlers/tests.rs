// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::handlers` — §4.2's nine operations, one free
//! generic `async fn` each.
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

/// Every [`SeamContract`] rule is spelled ONCE — no two share a
/// `kind` and no two share a `detail`.
///
/// The behavioural row in `adapter.rs` drives all seven arms and
/// asserts the `kind` each produces, so a `kind` collision turns it
/// red. It only asserts that `detail` is NON-EMPTY, because pinning
/// eight sentences in a test makes every wording improvement a test
/// edit — which leaves one mutation invisible: a copy-paste that
/// gives a new rule its neighbour's words. An operator reading
/// `contract-stale-not-modified: … the ranged read asked for …` is
/// being told about the wrong rule, and nothing else here would
/// notice.
///
/// The table is spelled out rather than derived, so ADDING a variant
/// fails to compile here (the `match` in `kind` has no wildcard) and
/// then fails this list until it is named — the same discipline
/// `seam_kind` keeps.
#[test]
fn no_two_contract_rules_share_a_label_or_a_sentence() {
    let all = [
        SeamContract::OverRead,
        SeamContract::Extent,
        SeamContract::OverCap,
        SeamContract::ZeroSeq,
        SeamContract::ReservedSeq,
        SeamContract::HintValidator,
        SeamContract::StaleNotModified,
    ];
    for (at, one) in all.iter().enumerate() {
        assert!(
            !one.kind().is_empty() && !one.detail().is_empty(),
            "{one:?} is unlabelled"
        );
        assert!(
            one.kind().starts_with("contract-"),
            "{one:?} must be greppable as the contract family: {:?}",
            one.kind()
        );
        for other in all.iter().skip(at + 1) {
            assert_ne!(
                one.kind(),
                other.kind(),
                "{one:?} and {other:?} share a kind, so the log cannot tell them apart"
            );
            assert_ne!(
                one.detail(),
                other.detail(),
                "{one:?} and {other:?} share a sentence, so one of them describes the \
                 wrong rule to an operator"
            );
        }
    }
}

/// **THE STRUCTURAL GUARD: no `500` in this module may be dark.**
///
/// Every behavioural row above proves that a `500` it drives is logged.
/// None of them can prove anything about a `500` that does not exist
/// yet — and the unlogged-internal-failure defect was exactly that: eight arms answering
/// `Outcome::internal()` directly, each individually reasonable, none
/// of them logging, and every test in the crate green. A ninth added
/// tomorrow reproduces it silently.
///
/// So this counts. `Outcome::internal()` may be CONSTRUCTED at exactly
/// three places in this module's production half — [`seam_failure`],
/// [`contract_violation`], [`codec_failure`] — and each of those emits
/// the event before returning it. A new arm that wants a `500` has to
/// route through one of the three or make this red, and the person who
/// makes it red has to decide which family their failure belongs to,
/// which is the decision that was skipped eight times.
///
/// **It also pins the message literal**, which nothing else can:
/// `tracing`'s macros take the message as a format LITERAL, so it is
/// spelled at each of the three sites rather than shared through a
/// `const` (a `const` in that position silently becomes a FIELD — the
/// measured first attempt emitted three events carrying no message at
/// all). Two of the three families have a behavioural row; the codec
/// family CANNOT have one, because provoking it needs a zstd context
/// that will not build, so for that site this count is the only thing
/// standing between a typo and a permanently dark `500`.
///
/// **Scope, stated rather than implied.** This reads THIS module only.
/// It is the whole of the server's `500` surface today — VERIFIED AT
/// SOURCE: `adapter.rs` constructs `Outcome::internal()` nowhere in its
/// production half, and `Status::InternalServerError` appears there only
/// in the status-code mapping — but that is a fact about today, not a
/// property this test enforces.
#[test]
fn every_500_this_module_builds_goes_through_one_of_the_three_funnels() {
    /// The three constructors, and the message they all log under.
    const FUNNELS: usize = 3;

    let source = include_str!("../handlers.rs");
    // The production half only: this test's own text mentions both
    // needles, and so may any row added beside it.
    //
    // Accept either inline or out-of-line test-module markers. If
    // neither is present, fail instead of scanning the whole file.
    let ceiling = source
        .find("\n#[cfg(test)]\nmod tests {")
        .or_else(|| source.find("\n#[cfg(test)]\nmod tests;"))
        .unwrap_or_else(|| {
            panic!(
                "this test's production/test ceiling marker is GONE from handlers.rs \
                 ({} bytes read). It looks for `#[cfg(test)]` followed by either \
                 `mod tests {{` (inline) or `mod tests;` (out-of-line). \
                 Without one, the scan below would cover this file's own test text \
                 and the funnel count would be about nothing. Re-point the needle; \
                 do NOT restore a fallback that widens the ceiling instead of failing",
                source.len()
            )
        });
    let production = source.get(..ceiling).unwrap_or("");

    // A line whose first non-blank characters are `//` is prose, not
    // code — the same rule `scripts/check-server-log-path.sh` uses, and
    // deliberately NOT a trailing-comment filter, which would drop code
    // before a `//` that sits inside a string literal.
    let code = |line: &&str| !line.trim_start().starts_with("//");

    let builds: Vec<&str> = production
        .lines()
        .filter(code)
        .filter(|line| line.contains("Outcome::internal"))
        .collect();
    assert_eq!(
        builds.len(),
        FUNNELS,
        "a 500 is built somewhere that is not one of the three logging funnels, so it is a \
         refusal whose cause is recorded NOWHERE. Route it through `seam_failure`, \
         `contract_violation` or `codec_failure` — whichever family it belongs to — rather \
         than raising this number: {builds:#?}"
    );

    let messages = production
        .lines()
        .filter(code)
        .filter(|line| line.contains("\"internal failure\""))
        .count();
    assert_eq!(
        messages, FUNNELS,
        "the three funnels must log under ONE message an operator can grep; the codec family \
         has no behavioural row and this count is all that holds its spelling"
    );
}

use super::{
    SeamContract, dispatch, get_bin_range, get_meta, get_root, max_seq, put_bin, put_meta,
    put_root, read_hint, seam_read_bound, validator, within_cap, write_hint,
};
use crate::admission::{Admitted, Conditionals, INGEST_UNPACKED_SUM_MAX, RequestHead, admit};
use crate::policy::VerifyPolicy;
use crate::wire::{CacheControl, ContentType, ErrorToken, Outcome, Status};
use granary_core::binfmt::{BIN_MAX_BYTES, PackedFrame, encode_bin};
use granary_core::binmap::SHARD_MAX_BYTES;
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use granary_core::manifest::GRAIN_UNPACKED_MAX;
use granary_core::rootstore::{
    HintRead, HintToken, RefusalKind, RootStore, RootStoreError, filter_above, format_hint_body,
};
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};
use granary_store::codec::GrainCodec;

/// The two §13.5 profiles, named so a call site READS as a
/// declaration. The seam-only one is what the rows predating
/// verification use: they store bodies that are not bins, which is
/// exactly `BinStore::put_bin`'s own contract and nothing above it.
const SEAM_ONLY: VerifyPolicy = VerifyPolicy::seam_only();
const VERIFYING: VerifyPolicy = VerifyPolicy::verifying();
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

/// A no-runtime executor. Every fake below answers from memory, so
/// one poll settles every future here and a `Pending` would mean the
/// test, not the handler, is wrong. **No tokio dev-dependency**: a
/// runtime in this crate's test graph would make the "calls no tokio
/// primitive" property unmeasurable from inside it.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a fake seam answers from memory and never yields"),
    }
}

/// What a handler asked the seam for. The offset and length matter
/// most: §7.2's honesty rule is about the request a handler made, and
/// only a record of it can check the extent it then declared.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    PutBin {
        digest: [u8; DIGEST_LEN],
        len: usize,
    },
    BinRange {
        digest: [u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    },
    PutMeta {
        volume: String,
        id: GrainId,
        len: usize,
    },
    GetMeta {
        volume: String,
        id: GrainId,
    },
    PutRoot {
        volume: String,
        seq: u64,
        len: usize,
    },
    GetRoot {
        volume: String,
        seq: u64,
    },
    MaxSeq {
        volume: String,
    },
    ReadHint {
        volume: String,
        cached: Option<HintToken>,
    },
    WriteHint {
        volume: String,
        seq: u64,
    },
}

/// A scripted seam. Deliberately minimal and deliberately dumb: it
/// answers whatever it was built with and records what it was asked.
#[derive(Debug)]
struct Fake {
    put_bin: Result<bool, RootStoreError>,
    bin_range: Result<Vec<u8>, RootStoreError>,
    put_meta: Result<bool, RootStoreError>,
    get_meta: Result<Vec<u8>, RootStoreError>,
    put_root: Result<(), RootStoreError>,
    get_root: Result<Option<Vec<u8>>, RootStoreError>,
    max_seq: Result<Option<u64>, RootStoreError>,
    read_hint: Result<HintRead, RootStoreError>,
    write_hint: Result<(), RootStoreError>,
    seen: Mutex<Vec<Call>>,
}

impl Default for Fake {
    fn default() -> Self {
        Self {
            put_bin: Ok(true),
            bin_range: Ok(vec![7u8; 10]),
            put_meta: Ok(true),
            get_meta: Ok(Vec::new()),
            put_root: Ok(()),
            get_root: Ok(None),
            max_seq: Ok(None),
            read_hint: Ok(HintRead::Missing),
            write_hint: Ok(()),
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl Fake {
    fn record(&self, call: Call) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(call);
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.seen.lock().map_or_else(|_| Vec::new(), |c| c.clone())
    }
}

impl BinStore for Fake {
    fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<bool, RootStoreError>> + Send {
        self.record(Call::PutBin {
            digest: *digest,
            len: bytes.len(),
        });
        std::future::ready(self.put_bin.clone())
    }

    fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<bool, RootStoreError>> + Send {
        self.record(Call::PutMeta {
            volume: volume.to_owned(),
            id: *id,
            len: bytes.len(),
        });
        std::future::ready(self.put_meta.clone())
    }

    fn get_meta(
        &self,
        volume: &str,
        id: &GrainId,
    ) -> impl Future<Output = Result<Vec<u8>, RootStoreError>> + Send {
        self.record(Call::GetMeta {
            volume: volume.to_owned(),
            id: *id,
        });
        std::future::ready(self.get_meta.clone())
    }

    fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> impl Future<Output = Result<Vec<u8>, RootStoreError>> + Send {
        self.record(Call::BinRange {
            digest: *digest,
            offset,
            len,
        });
        std::future::ready(self.bin_range.clone())
    }
}

impl RootStore for Fake {
    fn put_root(
        &self,
        volume: &str,
        seq: u64,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send {
        self.record(Call::PutRoot {
            volume: volume.to_owned(),
            seq,
            len: bytes.len(),
        });
        std::future::ready(self.put_root.clone())
    }

    fn get_root(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RootStoreError>> + Send {
        self.record(Call::GetRoot {
            volume: volume.to_owned(),
            seq,
        });
        std::future::ready(self.get_root.clone())
    }

    fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> impl Future<Output = Result<HintRead, RootStoreError>> + Send {
        self.record(Call::ReadHint {
            volume: volume.to_owned(),
            cached: cached.cloned(),
        });
        std::future::ready(self.read_hint.clone())
    }

    fn write_hint(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send {
        self.record(Call::WriteHint {
            volume: volume.to_owned(),
            seq,
        });
        std::future::ready(self.write_hint.clone())
    }

    fn max_seq(
        &self,
        volume: &str,
    ) -> impl Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.record(Call::MaxSeq {
            volume: volume.to_owned(),
        });
        std::future::ready(self.max_seq.clone())
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

fn digest_of(body: &[u8]) -> [u8; DIGEST_LEN] {
    *GrainId::of(body).digest()
}

const WRONG_DIGEST: [u8; DIGEST_LEN] = [9u8; DIGEST_LEN];

/// A store key, as a `Backend`/`RefusedResponse` message would carry
/// one. §8.4 forbids relaying it.
const LEAKY: &str = "root/tenant-7/00000000000000000042 in bucket granary-prod";

// -- §5.1 PUT bin ----------------------------------------------------

#[test]
fn put_bin_answers_201_when_novel_and_200_when_present() {
    let body = b"a bin's bytes".to_vec();
    let digest = digest_of(&body);

    let store = Fake::default();
    let outcome = block_on(put_bin(&store, &digest, body.clone(), SEAM_ONLY));
    assert_eq!(outcome.status(), Status::Created);
    assert_eq!(
        store.calls(),
        vec![Call::PutBin {
            digest,
            len: body.len()
        }]
    );

    let store = Fake {
        put_bin: Ok(false),
        ..Fake::default()
    };
    assert_eq!(
        block_on(put_bin(&store, &digest, body, SEAM_ONLY)).status(),
        Status::Ok,
        "§5.1: an existing content-addressed object is success"
    );
}

#[test]
fn put_bin_verifies_the_address_before_storing() {
    let store = Fake::default();
    let outcome = block_on(put_bin(
        &store,
        &WRONG_DIGEST,
        b"not those bytes".to_vec(),
        SEAM_ONLY,
    ));
    assert_eq!(outcome.status(), Status::BadRequest);
    assert_eq!(outcome.error(), Some(ErrorToken::AddressMismatch));
    assert!(
        store.calls().is_empty(),
        "§5.1: the address is verified BEFORE storing"
    );
}

/// §5.1 and §5.3's central MUST — "The server MUST verify the address
/// before storing" — against bodies whose claimed address agrees with
/// the real one everywhere but a single byte.
///
/// **One unrelated mismatch fixture cannot see this property.** A
/// digest of `[9; 32]` against `b"not those bytes"` is refused by a
/// comparator that reads any one byte of the array; what the
/// store-poisoning defence needs is that ALL of them are read, because "if
/// the server trusts a client's claimed hashes, one malicious client
/// poisons the deduplicated store for everybody". Every row below
/// flips one bit of the body's own digest, at every byte position, in
/// both the low bit and the high one — so a comparison truncated to
/// any prefix or any suffix of the array admits a body that does not
/// hash to the address it was sent to, and one of these rows says so.
#[test]
fn a_near_miss_address_is_refused_at_every_byte_of_the_digest() {
    let body = b"a bin's bytes".to_vec();
    let digest = digest_of(&body);
    let mut rows = 0_usize;

    for index in 0..DIGEST_LEN {
        for bit in [0x01_u8, 0x80] {
            let mut near = digest;
            near[index] ^= bit;
            assert_ne!(near, digest, "the fixture must be a MISS");
            rows += 1;

            let store = Fake::default();
            let outcome = block_on(put_bin(&store, &near, body.clone(), SEAM_ONLY));
            assert_eq!(
                (outcome.status(), outcome.error()),
                (Status::BadRequest, Some(ErrorToken::AddressMismatch)),
                "PUT bin, digest byte {index} flipped by {bit:#04x}"
            );
            assert!(
                store.calls().is_empty(),
                "§5.1: the address is verified BEFORE storing"
            );

            // §5.3's comparison is over a whole `GrainId`, whose
            // algorithm half is equal on every row here — so the
            // digest half is what has to decide, exactly as above.
            let id = GrainId::from_parts(HashAlgorithm::Blake3, near);
            let store = Fake::default();
            let outcome = block_on(put_meta(&store, "v1", &id, body.clone()));
            assert_eq!(
                (outcome.status(), outcome.error()),
                (Status::BadRequest, Some(ErrorToken::AddressMismatch)),
                "PUT meta, digest byte {index} flipped by {bit:#04x}"
            );
            assert!(store.calls().is_empty());
        }
    }
    assert_eq!(rows, 2 * DIGEST_LEN, "every byte of the digest, twice");

    // And the address the body really has is stored on both, so the
    // corpus above is a NEAR MISS and not a blanket refusal.
    let store = Fake::default();
    assert_eq!(
        block_on(put_bin(&store, &digest, body.clone(), SEAM_ONLY)).status(),
        Status::Created
    );
    let store = Fake::default();
    assert_eq!(
        block_on(put_meta(&store, "v1", &GrainId::of(&body), body)).status(),
        Status::Created
    );
}

/// **The ruling, executed.** This crate's enumeration numbers the body
/// cap step 7 and the seam call step 8, and the address check is the
/// seam call's
/// precondition — so a body over the cap is `413` even when its
/// digest is also wrong. Both refusals are defensible in isolation;
/// only the order makes two implementations agree.
#[test]
fn the_body_cap_runs_before_the_address_check() {
    let over = usize::try_from(BIN_MAX_BYTES + 1).unwrap_or(usize::MAX);
    let store = Fake::default();
    let outcome = block_on(put_bin(&store, &WRONG_DIGEST, vec![0u8; over], SEAM_ONLY));
    assert_eq!(outcome.status(), Status::ContentTooLarge);
    assert_eq!(outcome.error(), Some(ErrorToken::TooLarge));
    assert!(store.calls().is_empty());

    // The same ordering on the other two capped endpoints.
    let over = usize::try_from(META_MAX_BYTES + 1).unwrap_or(usize::MAX);
    let store = Fake::default();
    let id = GrainId::of(b"something else");
    assert_eq!(
        block_on(put_meta(&store, "v1", &id, vec![0u8; over])).status(),
        Status::ContentTooLarge
    );
    assert!(store.calls().is_empty());
}

/// §5a.1: **a `PUT bin` body is a BIN, not a grain.** A 32 MiB body is
/// over `META_MAX_BYTES` and well under `BIN_MAX_BYTES`, so a handler
/// reaching for the wrong constant refuses an object its own client
/// legally wrote. The over-cap row alone cannot see that mistake.
#[test]
fn the_bin_cap_is_bin_max_bytes_and_not_a_smaller_one() {
    let body = vec![3u8; 32 * 1024 * 1024];
    assert!(u64::try_from(body.len()).is_ok_and(|len| len > META_MAX_BYTES));
    let digest = digest_of(&body);
    let store = Fake::default();
    assert_eq!(
        block_on(put_bin(&store, &digest, body, SEAM_ONLY)).status(),
        Status::Created
    );
}

/// The cap boundary at every edge. The predicate is what all three
/// handlers call, so the off-by-one lives here — and `vec![0u8; n]`
/// is calloc'd, so the large rows cost address space rather than
/// resident pages.
#[test]
fn a_body_of_exactly_the_cap_is_inside_it_and_one_byte_more_is_not() {
    for cap in [
        0u64,
        1,
        20,
        4096,
        ROOT_MAX_BYTES,
        META_MAX_BYTES,
        BIN_MAX_BYTES,
    ] {
        let at = usize::try_from(cap).unwrap_or(usize::MAX);
        assert!(within_cap(&vec![0u8; at], cap), "exactly {cap} is inside");
        assert!(!within_cap(&vec![0u8; at + 1], cap), "{cap} + 1 is outside");
    }
}

/// §5a.1: **a meta body is bounded by `META_MAX_BYTES`, not by a
/// shard's budget.** A maximal bin table is 8,388,622 bytes — 14
/// bytes OVER `SHARD_MAX_BYTES` — so a handler reaching for the
/// shard figure returns `413` for an object its own client legally
/// wrote, and does it only once a volume reaches the format's
/// declared ceiling, which is the worst possible time to discover a
/// cap. The over-cap row alone cannot see that mistake.
#[test]
fn the_meta_cap_admits_an_object_a_shard_budget_would_refuse() {
    let body = vec![5u8; 8_388_622];
    assert!(
        u64::try_from(body.len()).is_ok_and(|len| len > SHARD_MAX_BYTES),
        "the fixture must sit above the budget it is testing against"
    );
    let id = GrainId::of(&body);
    let store = Fake::default();
    assert_eq!(
        block_on(put_meta(&store, "v1", &id, body)).status(),
        Status::Created
    );
}

// -- §5.2 GET bin ----------------------------------------------------

/// §7.2, both halves: the handler must give the seam the offset it
/// was asked for, and must declare that same offset — even when the
/// fake serves a short read whose bytes came from somewhere else
/// entirely. Declaring the fake's offset instead would emit a
/// `Content-Range` over a slice the request never named, and it would
/// be self-consistent: the width would still match the body.
#[test]
fn the_declared_extent_names_the_offset_the_handler_asked_for() {
    // The fake answers 50 bytes it took from offset 0, whatever it
    // was asked for — a backend that ignored the range, which §7.2
    // check 1 exists to catch on the client side.
    let store = Fake {
        bin_range: Ok(vec![1u8; 50]),
        ..Fake::default()
    };
    let digest = digest_of(b"whatever");
    let outcome = block_on(get_bin_range(&store, &digest, 100, 100));

    assert_eq!(outcome.status(), Status::PartialContent);
    let extent = outcome.extent().expect("a 206 always carries its extent");
    assert_eq!(
        (extent.first(), extent.last()),
        (100, 149),
        "§7.2: the extent declared is the extent requested-from, narrowed \
         by the short read — never the offset a backend served from"
    );
    assert_eq!(
        store.calls(),
        vec![Call::BinRange {
            digest,
            offset: 100,
            len: 100
        }],
        "the offset declared must be the offset given to the seam"
    );
    assert_eq!(outcome.content_type(), Some(ContentType::Bin));
    assert_eq!(outcome.cache_control(), Some(CacheControl::Immutable));
    assert_eq!(outcome.etag(), None, "§6: no ETag on ANY bin response");
}

/// §5.2 and §7.3, restated in both: `Err(Backend)` is `500`, never
/// `416`. The seam answers that variant for an unsatisfiable range
/// AND for an outage, with no discriminator.
#[test]
fn a_backend_error_from_a_ranged_read_is_500_and_never_416() {
    let digest = digest_of(b"whatever");
    for error in [
        RootStoreError::Backend("range start past the end".to_owned()),
        RootStoreError::Backend(LEAKY.to_owned()),
        RootStoreError::RefusedResponse {
            reason: LEAKY.to_owned(),
            kind: RefusalKind::Extent,
        },
        RootStoreError::RangeOverflow,
        RootStoreError::Precondition,
        RootStoreError::AlreadyExists,
        RootStoreError::InvalidVolume {
            reason: "impossible".to_owned(),
        },
    ] {
        let store = Fake {
            bin_range: Err(error.clone()),
            ..Fake::default()
        };
        let outcome = block_on(get_bin_range(&store, &digest, 0, 10));
        assert_eq!(
            (outcome.status(), outcome.error()),
            (Status::InternalServerError, Some(ErrorToken::Internal)),
            "{error:?}"
        );
        assert_ne!(
            outcome.status(),
            Status::RangeNotSatisfiable,
            "§5.2: a server MUST NOT map Err(Backend) from get_bin_range \
             to 416 — {error:?}"
        );
    }

    let store = Fake {
        bin_range: Err(RootStoreError::NotFound),
        ..Fake::default()
    };
    let outcome = block_on(get_bin_range(&store, &digest, 0, 10));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::NotFound, Some(ErrorToken::NotFound))
    );
}

/// §9.1 item 5 and §9.2: **the seam's answer is untrusted input to
/// the SERVER**, so a response longer than the extent asked for is
/// refused rather than relayed onward to an unauthenticated peer.
/// §7.2 keeps the other direction legal — a short read is a success,
/// declared honestly at its own narrower extent.
#[test]
fn a_seam_answer_longer_than_the_range_requested_is_refused() {
    let digest = digest_of(b"whatever");
    for (len, served) in [(10_u32, 11_usize), (10, 50), (10, 5_000), (1, 2)] {
        let store = Fake {
            bin_range: Ok(vec![1u8; served]),
            ..Fake::default()
        };
        let outcome = block_on(get_bin_range(&store, &digest, 0, len));
        assert_eq!(
            (outcome.status(), outcome.error()),
            (Status::InternalServerError, Some(ErrorToken::Internal)),
            "a {served}-byte answer to a {len}-byte request is a seam that \
             violated its own contract — a 500, not a 206 and not a 4xx"
        );
        assert_eq!(outcome.extent(), None);
        assert!(outcome.body().is_empty());
    }

    // Exactly the extent, and every short read under it, stay `206`.
    for served in [1_usize, 9, 10] {
        let store = Fake {
            bin_range: Ok(vec![1u8; served]),
            ..Fake::default()
        };
        let outcome = block_on(get_bin_range(&store, &digest, 100, 10));
        assert_eq!(outcome.status(), Status::PartialContent, "{served} bytes");
        let width = u64::try_from(served).expect("a test fixture fits a u64");
        let extent = outcome.extent().expect("a 206 always carries its extent");
        assert_eq!(
            (extent.first(), extent.last()),
            (100, 100 + width - 1),
            "§7.2: a short read is a SUCCESS, at its own narrower extent"
        );
    }
}

/// The bound the refusal above applies, at every edge. `len` alone is
/// not enough and this is where that shows: §7.1 resolves `bytes=0-`
/// and every over-wide `last-pos` to `u32::MAX`, so a bound of `len`
/// would relay a 4 GiB answer for an object `BIN_MAX_BYTES` says
/// cannot exist.
///
/// **And the ceiling alone is not enough either**, which is the half
/// a bound of `min(len, BIN_MAX_BYTES)` misses: it bounds the
/// answer's SIZE and says nothing about where it lands, so at an
/// offset one byte below the ceiling it still admits 256 MiB. What is
/// left below the ceiling from the offset is the bound, and the rows
/// at `BIN_MAX_BYTES - 1` are where the two formulations part.
///
/// Asserted here rather than driven through a fake because the
/// alternative is a test that allocates a quarter of a gigabyte —
/// twice, since the fake clones what it was built with.
#[test]
fn the_seam_read_bound_is_the_narrower_of_the_request_and_what_is_left() {
    for len in [0_u32, 1, 10, 4096] {
        assert_eq!(seam_read_bound(0, len), u64::from(len), "{len} is under it");
    }
    let at = u32::try_from(BIN_MAX_BYTES).expect("256 MiB fits a u32");
    assert_eq!(seam_read_bound(0, at - 1), BIN_MAX_BYTES - 1);
    assert_eq!(seam_read_bound(0, at), BIN_MAX_BYTES);
    assert_eq!(seam_read_bound(0, at + 1), BIN_MAX_BYTES);
    assert_eq!(
        seam_read_bound(0, u32::MAX),
        BIN_MAX_BYTES,
        "§7.1's open-ended form asks for u32::MAX bytes; no legal bin \
         holds more than BIN_MAX_BYTES, so that is the bound"
    );

    // The offset term. Every row here is a legal `first-pos` — the
    // gate refuses `offset >= BIN_MAX_BYTES` with `416` — and the
    // open-ended `len` is the one §7.1 resolves them all to.
    for offset in [0_u64, 1, 4096, BIN_MAX_BYTES / 2, BIN_MAX_BYTES - 1] {
        assert_eq!(
            seam_read_bound(offset, u32::MAX),
            BIN_MAX_BYTES - offset,
            "{offset}: the bound is what is left below the ceiling"
        );
    }
    assert_eq!(
        seam_read_bound(BIN_MAX_BYTES - 1, u32::MAX),
        1,
        "§7.1: one byte is all a legal bin can hold at the last position"
    );
    // A fully specified int-range below the ceiling is untouched by
    // the offset term, so this narrows nothing §7.1 accepts.
    assert_eq!(seam_read_bound(100, 100), 100);
    // Total at and past the ceiling, though the gate's `416` means no
    // served request reaches it.
    assert_eq!(seam_read_bound(BIN_MAX_BYTES, u32::MAX), 0);
    assert_eq!(seam_read_bound(u64::MAX, u32::MAX), 0);
}

/// An empty body is never a success on this seam (§7.2 check 3), and
/// a zero-width extent has no valid `Content-Range`.
#[test]
fn an_empty_ranged_read_is_500_rather_than_a_zero_width_206() {
    let store = Fake {
        bin_range: Ok(Vec::new()),
        ..Fake::default()
    };
    let outcome = block_on(get_bin_range(&store, &digest_of(b"x"), 0, 10));
    assert_eq!(outcome.status(), Status::InternalServerError);
    assert_eq!(outcome.extent(), None);
}

/// §7.2 and §7.1: the bound on a seam's answer is what is left
/// **below the ceiling from this offset**, not the requested length
/// alone.
///
/// `bytes=268435455-` is the last legal `first-pos` — one below
/// `BIN_MAX_BYTES` — and it resolves to `len = u32::MAX`, so a bound
/// of `min(len, BIN_MAX_BYTES)` admits 256 MiB of answer starting
/// there. Two bytes are already enough to break it: the second one
/// sits AT the ceiling, and the `Content-Range` would declare a byte
/// at a position no legal bin can hold — self-consistently, which is
/// what makes it undetectable one layer down.
#[test]
fn the_seam_bound_is_what_is_left_below_the_ceiling() {
    let digest = digest_of(b"whatever");
    let last = BIN_MAX_BYTES - 1;

    // One byte at the last legal position: a legal answer, and the
    // extent names exactly it.
    let store = Fake {
        bin_range: Ok(vec![1u8]),
        ..Fake::default()
    };
    let outcome = block_on(get_bin_range(&store, &digest, last, u32::MAX));
    assert_eq!(outcome.status(), Status::PartialContent);
    assert_eq!(
        outcome
            .extent()
            .map(|extent| (extent.first(), extent.last())),
        Some((last, last)),
        "§7.2: the extent is the one byte below the ceiling"
    );

    // Two bytes from the same offset: the second is AT the ceiling,
    // so the seam over-read its own contract and nothing is relayed.
    let store = Fake {
        bin_range: Ok(vec![1u8, 2]),
        ..Fake::default()
    };
    assert_eq!(
        (
            block_on(get_bin_range(&store, &digest, last, u32::MAX)).status(),
            block_on(get_bin_range(&store, &digest, last, u32::MAX)).error()
        ),
        (Status::InternalServerError, Some(ErrorToken::Internal)),
        "§7.1: no legal bin has a byte at BIN_MAX_BYTES"
    );

    // The bound narrows with the offset and nowhere else: a fully
    // specified int-range far below the ceiling is served as asked.
    let store = Fake {
        bin_range: Ok(vec![0u8; 100]),
        ..Fake::default()
    };
    assert_eq!(
        block_on(get_bin_range(&store, &digest, 100, 100)).status(),
        Status::PartialContent,
        "§7.1: a fully specified int-range is served as asked"
    );
}

// -- §5.3, §5.4 meta -------------------------------------------------

/// §5.3: the address check is the whole of the server's obligation —
/// the conformance body stores a 13-byte non-object here and requires
/// success.
#[test]
fn put_meta_verifies_the_address_and_never_parses_the_body() {
    let body = b"not-an-object".to_vec();
    assert_eq!(body.len(), 13);
    let id = GrainId::of(&body);
    let store = Fake::default();
    assert_eq!(
        block_on(put_meta(&store, "v1", &id, body.clone())).status(),
        Status::Created
    );
    assert_eq!(
        store.calls(),
        vec![Call::PutMeta {
            volume: "v1".to_owned(),
            id,
            len: 13
        }]
    );

    let store = Fake {
        put_meta: Ok(false),
        ..Fake::default()
    };
    assert_eq!(
        block_on(put_meta(&store, "v1", &id, body.clone())).status(),
        Status::Ok
    );

    let store = Fake::default();
    let outcome = block_on(put_meta(&store, "v1", &GrainId::of(b"different"), body));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::BadRequest, Some(ErrorToken::AddressMismatch))
    );
    assert!(store.calls().is_empty());
}

#[test]
fn get_meta_serves_the_stored_bytes_or_404s() {
    let store = Fake {
        get_meta: Ok(b"stored meta".to_vec()),
        ..Fake::default()
    };
    let id = GrainId::of(b"x");
    let outcome = block_on(get_meta(&store, "v1", &id));
    assert_eq!(outcome.status(), Status::Ok);
    assert_eq!(outcome.content_type(), Some(ContentType::Meta));
    assert_eq!(outcome.body(), b"stored meta");

    let store = Fake {
        get_meta: Err(RootStoreError::NotFound),
        ..Fake::default()
    };
    let outcome = block_on(get_meta(&store, "v1", &id));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::NotFound, Some(ErrorToken::NotFound))
    );
}

// -- §5.5, §5.6 roots ------------------------------------------------

/// §13.2 item 3 and §5.5: no parse, no continuity check, `409` on an
/// occupied seq — and exactly ONE seam call, because the one-probe
/// rule is the client's.
#[test]
fn put_root_stores_opaque_bytes_and_never_probes() {
    let store = Fake::default();
    let body = b"\xff\xfenot a decodable root".to_vec();
    assert_eq!(
        block_on(put_root(&store, "v1", 42, body.clone())).status(),
        Status::Created
    );
    assert_eq!(
        store.calls(),
        vec![Call::PutRoot {
            volume: "v1".to_owned(),
            seq: 42,
            len: body.len()
        }],
        "§5.5: the ONE-PROBE RULE is the client's; the server makes one \
         seam call and takes no occupancy probe"
    );

    let store = Fake {
        put_root: Err(RootStoreError::AlreadyExists),
        ..Fake::default()
    };
    let outcome = block_on(put_root(&store, "v1", 42, body));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::Conflict, Some(ErrorToken::AlreadyExists))
    );
    assert_eq!(store.calls().len(), 1);
}

#[test]
fn put_root_caps_at_root_max_bytes() {
    let at = usize::try_from(ROOT_MAX_BYTES).unwrap_or(usize::MAX);
    let store = Fake::default();
    assert_eq!(
        block_on(put_root(&store, "v1", 1, vec![0u8; at])).status(),
        Status::Created,
        "a root of exactly ROOT_MAX_BYTES is legal data"
    );
    let store = Fake::default();
    let outcome = block_on(put_root(&store, "v1", 1, vec![0u8; at + 1]));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::ContentTooLarge, Some(ErrorToken::TooLarge))
    );
    assert!(store.calls().is_empty());
}

/// §5.6, §13.2 item 2: byte for byte, with no canonicalising,
/// re-encoding or repair. Only a NON-CANONICAL stored object can tell
/// a conforming server from one that re-encodes on read.
#[test]
fn get_root_returns_the_stored_bytes_byte_for_byte() {
    let planted = vec![0x00, 0xff, 0x7f, 0x80, b'{', b'}', 0x00];
    let store = Fake {
        get_root: Ok(Some(planted.clone())),
        ..Fake::default()
    };
    let outcome = block_on(get_root(&store, "v1", 7));
    assert_eq!(outcome.status(), Status::Ok);
    assert_eq!(outcome.content_type(), Some(ContentType::Root));
    assert_eq!(outcome.body(), planted.as_slice());

    let store = Fake::default();
    let outcome = block_on(get_root(&store, "v1", 7));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::NotFound, Some(ErrorToken::NotFound)),
        "§5.6: Ok(None) is the cheap negative a forward probe expects"
    );
}

/// §5a.2's "both directions" and §9.1 item 5: an over-bound seam
/// body is refused rather than relayed.
///
/// `RootStoreError::RefusedResponse` is PERMITTED of an
/// implementation and not required, so a conforming seam may hand
/// back an object of any size — and these bytes go straight out to
/// an unauthenticated peer (§3). The `500` is the same answer every
/// other pinned-contract violation gets: nothing about the request
/// was wrong.
#[test]
fn an_over_bound_seam_body_is_refused_on_meta_and_root() {
    let id = GrainId::of(b"an address");
    let over_meta = usize::try_from(META_MAX_BYTES + 1).unwrap_or(usize::MAX);
    let store = Fake {
        get_meta: Ok(vec![0u8; over_meta]),
        ..Fake::default()
    };
    let outcome = block_on(get_meta(&store, "v1", &id));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::InternalServerError, Some(ErrorToken::Internal)),
        "§5a.2: META_MAX_BYTES bounds what is read back too"
    );
    assert!(outcome.body().is_empty());

    let over_root = usize::try_from(ROOT_MAX_BYTES + 1).unwrap_or(usize::MAX);
    let store = Fake {
        get_root: Ok(Some(vec![0u8; over_root])),
        ..Fake::default()
    };
    let outcome = block_on(get_root(&store, "v1", 1));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::InternalServerError, Some(ErrorToken::Internal)),
        "§5a.2: ROOT_MAX_BYTES bounds what is read back too"
    );
    assert!(outcome.body().is_empty());

    // A body of exactly the bound is inside it and is served, so the
    // rows above are a boundary and not a blanket refusal.
    let at_meta = usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX);
    let store = Fake {
        get_meta: Ok(vec![0u8; at_meta]),
        ..Fake::default()
    };
    assert_eq!(block_on(get_meta(&store, "v1", &id)).status(), Status::Ok);
    let at_root = usize::try_from(ROOT_MAX_BYTES).unwrap_or(usize::MAX);
    let store = Fake {
        get_root: Ok(Some(vec![0u8; at_root])),
        ..Fake::default()
    };
    assert_eq!(block_on(get_root(&store, "v1", 1)).status(), Status::Ok);
}

// -- §5.7 max-seq ----------------------------------------------------

#[test]
fn max_seq_serves_the_head_and_404s_an_empty_volume() {
    let store = Fake {
        max_seq: Ok(Some(42)),
        ..Fake::default()
    };
    let outcome = block_on(max_seq(&store, "v1"));
    assert_eq!(outcome.status(), Status::Ok);
    assert_eq!(outcome.content_type(), Some(ContentType::Text));
    assert_eq!(outcome.cache_control(), Some(CacheControl::NoStore));
    assert_eq!(outcome.body(), b"00000000000000000042");

    let store = Fake::default();
    let outcome = block_on(max_seq(&store, "v1"));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::NotFound, Some(ErrorToken::NotFound))
    );
}

/// §5.7 and §13.2 item 4: the server MUST NOT answer `0`. The seam's
/// contract says it never returns `Some(0)`; the server enforces it
/// anyway, and the answer is `internal()` — never a `4xx`, and
/// never the `404` row, which means the volume has no roots at all.
#[test]
fn max_seq_never_answers_zero_as_a_head() {
    let store = Fake {
        max_seq: Ok(Some(0)),
        ..Fake::default()
    };
    let outcome = block_on(max_seq(&store, "v1"));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::InternalServerError, Some(ErrorToken::Internal))
    );
    assert!(outcome.body().is_empty());
}

/// §5.7 and §13.2 item 4 at the OTHER end of the range: the server
/// MUST NOT answer `u64::MAX`. The seam's contract already
/// forbids it and the server enforces it anyway, on the same `internal()`
/// ruling and for the same reason as the seq-0 row above — a seam
/// violating its pinned contract is a server bug, not a `4xx` and not
/// the `404` row.
///
/// The POSITIVE CONTROL is the second half: `u64::MAX - 1` is the top
/// of the usable range and an ordinary `200`. Without it this test
/// could not tell "refuses the reserved value" from "refuses the top
/// of the range".
#[test]
fn max_seq_never_answers_the_reserved_top_of_the_range() {
    let store = Fake {
        max_seq: Ok(Some(u64::MAX)),
        ..Fake::default()
    };
    let outcome = block_on(max_seq(&store, "v1"));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::InternalServerError, Some(ErrorToken::Internal))
    );
    assert!(outcome.body().is_empty());

    let usable = Fake {
        max_seq: Ok(Some(u64::MAX - 1)),
        ..Fake::default()
    };
    let outcome = block_on(max_seq(&usable, "v1"));
    assert_eq!(outcome.status(), Status::Ok);
    assert_eq!(outcome.body(), format_hint_body(u64::MAX - 1).as_bytes());
}

/// §5.7: the 20-digit rendering this crate emits and core's
/// `format_hint_body` are one body, over the whole `u64` range —
/// §4.3 states the bound once "at the key so that all three agree",
/// and two spellings of it would disagree at some magnitude.
///
/// **The RENDERING leg still covers `u64::MAX`, and deliberately.**
/// That value is reserved as a HEAD, not as a seq: `{seq}` still
/// names it, `GET root/18446744073709551615` still serves it, and
/// [`Outcome::max_seq`] is the same 20-digit rendering every one of
/// those bodies uses — so narrowing the rendering check would retire a
/// magnitude-agreement guard that reserving a head value does not supersede.
///
/// **Only the HANDLER leg stops at `u64::MAX - 1`**, because the
/// handler now refuses the reserved value outright
/// ([`max_seq_never_answers_the_reserved_top_of_the_range`], which
/// asserts the refusal that this loop would otherwise trip over).
#[test]
fn the_max_seq_body_is_cores_own_hint_body() {
    for value in [
        1u64,
        42,
        999,
        1_234_567_890,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let seq = NonZeroU64::new(value).expect("a test seq is never zero");
        assert_eq!(
            Outcome::max_seq(seq).body(),
            format_hint_body(value).as_bytes(),
            "the wire rendering and granary-core's must agree at {value}"
        );
        if value == u64::MAX {
            continue;
        }
        let store = Fake {
            max_seq: Ok(Some(value)),
            ..Fake::default()
        };
        assert_eq!(
            block_on(max_seq(&store, "v1")).body(),
            format_hint_body(value).as_bytes()
        );
    }
}

// -- §5.8 read hint --------------------------------------------------

#[test]
fn read_hint_serves_the_seq_with_its_required_strong_etag() {
    let store = Fake {
        read_hint: Ok(HintRead::Current {
            seq: 42,
            token: HintToken("\"v7\"".to_owned()),
        }),
        ..Fake::default()
    };
    let outcome = block_on(read_hint(&store, "v1", None));
    assert_eq!(outcome.status(), Status::Ok);
    assert_eq!(outcome.body(), b"00000000000000000042");
    assert_eq!(outcome.etag(), Some("\"v7\""));
    assert_eq!(outcome.cache_control(), Some(CacheControl::NoCache));
}

/// §5.8: a body of `0` MUST degrade to `Ok(Missing)` — `404` +
/// `not-found` on the wire, never a `5xx` and never another `4xx`.
#[test]
fn a_stored_hint_of_zero_degrades_to_404() {
    let store = Fake {
        read_hint: Ok(HintRead::Current {
            seq: 0,
            token: HintToken("\"v7\"".to_owned()),
        }),
        ..Fake::default()
    };
    let outcome = block_on(read_hint(&store, "v1", None));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::NotFound, Some(ErrorToken::NotFound))
    );
}

/// §5.8, §5a.6 and §13.2 item 12: **the `404` row WINS over the
/// conditional.** A volume with no hint object answers `404` even
/// under `If-None-Match` — never `304`, never `200`.
#[test]
fn a_volume_with_no_hint_is_404_even_under_the_conditional() {
    let cached = HintToken("\"v7\"".to_owned());
    let store = Fake::default();
    let outcome = block_on(read_hint(&store, "v1", Some(&cached)));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::NotFound, Some(ErrorToken::NotFound))
    );
    assert_eq!(outcome.cache_control(), Some(CacheControl::NoCache));
    assert_eq!(outcome.etag(), None);
    assert_eq!(
        store.calls(),
        vec![Call::ReadHint {
            volume: "v1".to_owned(),
            cached: Some(cached)
        }],
        "the If-None-Match value reaches the seam as the cached token"
    );
}

#[test]
fn a_matching_conditional_answers_304_carrying_the_cached_validator() {
    let cached = HintToken("\"v7\"".to_owned());
    let store = Fake {
        read_hint: Ok(HintRead::NotModified),
        ..Fake::default()
    };
    let outcome = block_on(read_hint(&store, "v1", Some(&cached)));
    assert_eq!(outcome.status(), Status::NotModified);
    assert_eq!(outcome.etag(), Some("\"v7\""));
    assert_eq!(outcome.cache_control(), Some(CacheControl::NoCache));
    assert!(outcome.body().is_empty());
}

/// §6 requires the `304` to carry the `ETag` the `200` would have
/// carried, and the only one available is the client's own. A
/// `NotModified` with nothing cached leaves nothing truthful to emit.
#[test]
fn a_304_with_no_cached_validator_is_internal() {
    let store = Fake {
        read_hint: Ok(HintRead::NotModified),
        ..Fake::default()
    };
    let outcome = block_on(read_hint(&store, "v1", None));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::InternalServerError, Some(ErrorToken::Internal))
    );
    assert_eq!(outcome.etag(), None);
}

/// §5.8's REQUIRED strong `ETag`, over every shape a store's opaque
/// token arrives in. A bare token is quoted once; an already-quoted
/// one is echoed verbatim and never quoted twice; and a token that is
/// neither is `500`, never a panic and never a `4xx`.
#[test]
fn a_store_token_becomes_a_strong_entity_tag_or_it_becomes_a_500() {
    for (token, expected) in [
        ("\"v7\"", Some("\"v7\"")),
        (
            "\"d41d8cd98f00b204e9800998ecf8427e\"",
            Some("\"d41d8cd98f00b204e9800998ecf8427e\""),
        ),
        ("1", Some("\"1\"")),
        ("v7", Some("\"v7\"")),
        ("caf\u{e9}", Some("\"caf\u{e9}\"")),
    ] {
        assert_eq!(
            validator(&HintToken(token.to_owned()))
                .as_ref()
                .map(crate::wire::ETag::as_str),
            expected,
            "{token:?}"
        );
    }
    for token in [
        // The `unwrap_or_default()` case: the backend reported no
        // ETag at all, so there is no validator to emit.
        "",
        "\"\"",
        // A `"` anywhere inside fails `etagc` on BOTH routes, so
        // wrapping never smuggles one in.
        "a\"b",
        "\"a\"b\"",
        "\"unterminated",
        "trailing\"",
        // Header injection, refused by the grammar rather than by a
        // separate check.
        "v\r\nX-Injected: 1",
        "\"v\r\n\"",
        "v\n",
        // Other bytes outside `etagc`.
        "has space",
        "tab\there",
        "\u{0}",
        "\u{7f}",
        // The weak form: §5.8 requires a STRONG validator.
        "W/\"v7\"",
    ] {
        assert_eq!(
            validator(&HintToken(token.to_owned())),
            None,
            "{token:?} is not a strong entity-tag by either route"
        );
    }

    let store = Fake {
        read_hint: Ok(HintRead::Current {
            seq: 5,
            token: HintToken("bare-token".to_owned()),
        }),
        ..Fake::default()
    };
    assert_eq!(
        block_on(read_hint(&store, "v1", None)).etag(),
        Some("\"bare-token\""),
        "a bare token is quoted exactly once"
    );

    let store = Fake {
        read_hint: Ok(HintRead::Current {
            seq: 5,
            token: HintToken("a\"b".to_owned()),
        }),
        ..Fake::default()
    };
    let outcome = block_on(read_hint(&store, "v1", None));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::InternalServerError, Some(ErrorToken::Internal)),
        "§5.8 makes the ETag REQUIRED, so a server that cannot spell one \
         has failed — a 500, not a 4xx and not a panic"
    );
}

/// §5.8's read-bound route: a stored hint the seam REFUSED is this
/// endpoint's `404`, and never a `5xx`.
///
/// The section gives a server two conforming routes for a malformed
/// or over-long stored hint — serve the bytes, or "apply its own
/// read bound and answer `404`" — and forbids "a third: any `4xx`
/// other than `404`, or any `5xx`, on account of the stored body's
/// shape". `RootStore::read_hint` returns `RefusedResponse` for
/// exactly that read bound, so a `500` here is the forbidden answer
/// and it wedges every reader on the volume, which is the failure
/// §5.8 exists to prevent.
///
/// **This endpoint only.** §5.4 and §5.6 license no degrade, so the
/// same seam error stays a `500` there — asserted below, because a
/// fix applied in `seam_failure` would pass the first half of this
/// test and silently turn two `500`s into `404`s.
#[test]
fn a_refused_stored_hint_is_404_and_the_other_reads_stay_500() {
    let refused = || RootStoreError::RefusedResponse {
        reason: LEAKY.to_owned(),
        kind: RefusalKind::OverCap,
    };
    let store = Fake {
        read_hint: Err(refused()),
        ..Fake::default()
    };
    let outcome = block_on(read_hint(&store, "v1", None));
    assert_eq!(
        (outcome.status(), outcome.error()),
        (Status::NotFound, Some(ErrorToken::NotFound)),
        "§5.8: the read-bound route lands on Ok(Missing), which is 404"
    );
    assert_eq!(outcome.etag(), None);
    assert!(outcome.body().is_empty());

    // The conditional does not move it either: §5a.6 says the answer
    // is "whatever the unconditional request would have produced".
    let cached = HintToken("\"v7\"".to_owned());
    let store = Fake {
        read_hint: Err(refused()),
        ..Fake::default()
    };
    assert_eq!(
        block_on(read_hint(&store, "v1", Some(&cached))).status(),
        Status::NotFound
    );

    // Every OTHER seam error on this endpoint keeps its 500.
    for error in [
        RootStoreError::Backend(LEAKY.to_owned()),
        RootStoreError::InvalidVolume {
            reason: LEAKY.to_owned(),
        },
        RootStoreError::Precondition,
        RootStoreError::RangeOverflow,
        RootStoreError::AlreadyExists,
        RootStoreError::NotFound,
    ] {
        let store = Fake {
            read_hint: Err(error.clone()),
            ..Fake::default()
        };
        assert_eq!(
            block_on(read_hint(&store, "v1", None)).status(),
            Status::InternalServerError,
            "{error:?}: only the read-bound route degrades"
        );
    }

    // And the degrade is this endpoint's alone.
    let id = GrainId::of(b"an address");
    let store = Fake {
        get_meta: Err(refused()),
        get_root: Err(refused()),
        max_seq: Err(refused()),
        bin_range: Err(refused()),
        ..Fake::default()
    };
    for status in [
        block_on(get_meta(&store, "v1", &id)).status(),
        block_on(get_root(&store, "v1", 1)).status(),
        block_on(max_seq(&store, "v1")).status(),
        block_on(get_bin_range(&store, &digest_of(b"x"), 0, 10)).status(),
    ] {
        assert_eq!(
            status,
            Status::InternalServerError,
            "§5.4/§5.6/§5.7/§5.2 license no degrade"
        );
    }
}

// -- §5.9 write hint -------------------------------------------------

#[test]
fn write_hint_answers_204_created_or_replaced_alike() {
    for seq in [0u64, 1, 42, u64::MAX] {
        let store = Fake::default();
        let body = format_hint_body(seq).into_bytes();
        let outcome = block_on(write_hint(&store, "v1", body));
        assert_eq!(outcome.status(), Status::NoContent, "{seq}");
        assert!(outcome.body().is_empty());
        assert_eq!(
            store.calls(),
            vec![Call::WriteHint {
                volume: "v1".to_owned(),
                seq
            }],
            "a body of 0 is ACCEPTED on write; §5.8's degrade handles the \
             read side"
        );
    }
}

/// §5.9's own row: a body that is not exactly 20 digits naming a
/// `u64` is **`400` + `bad-request`, never `413`** — the endpoint has
/// no `413` row at all, because the body has exactly one legal length.
#[test]
fn a_hint_body_that_is_not_twenty_digits_is_400_and_never_413() {
    // **Every whitespace row below is itself exactly 20 bytes**, so a
    // parser that TRIMMED before counting would still refuse them —
    // at 19 digits, for the wrong reason. §5.9's "exactly 20" needs
    // bodies whose trim IS 20 valid digits, and these are those: they
    // are one byte over, and under `parse_hint_body(text.trim())`
    // each answers `204` and writes seq 42 from a body §5.9 forbids.
    let trims_to_twenty: [&[u8]; 9] = [
        b"\n00000000000000000042",
        b"00000000000000000042\n",
        b"\r00000000000000000042",
        b"00000000000000000042\r",
        b" 00000000000000000042",
        b"00000000000000000042 ",
        b"\t00000000000000000042",
        b"00000000000000000042\t",
        b"\x0c00000000000000000042",
    ];
    for row in trims_to_twenty {
        let text = str::from_utf8(row).expect("an ASCII fixture is UTF-8");
        assert_eq!(row.len(), 21, "{text:?} must be exactly one byte over");
        assert_eq!(
            text.trim(),
            "00000000000000000042",
            "{text:?} must be invisible to a trimming parser"
        );
    }

    let bodies: Vec<Vec<u8>> = [
        &b""[..],
        &b"0"[..],
        &b"42"[..],
        &b"0000000000000000004"[..],
        &b"000000000000000000042"[..],
        &b"0000000000000000004\n"[..],
        &b"\n0000000000000000042"[..],
        &b" 0000000000000000042"[..],
        &b"+0000000000000000042"[..],
        &b"-0000000000000000042"[..],
        &b"0000000000000000004a"[..],
        // 20 digits, over u64::MAX — §5.9's second half.
        &b"99999999999999999999"[..],
        &b"18446744073709551616"[..],
        // Not UTF-8 at all.
        &[0xffu8; 20][..],
        &[0x00u8; 20][..],
    ]
    .iter()
    .chain(trims_to_twenty.iter())
    .map(|b| (*b).to_vec())
    .chain([vec![b'0'; 300 * 1024 * 1024]])
    .collect();

    for body in bodies {
        let store = Fake::default();
        let outcome = block_on(write_hint(&store, "v1", body.clone()));
        assert_eq!(
            (outcome.status(), outcome.error()),
            (Status::BadRequest, Some(ErrorToken::BadRequest)),
            "a {}-byte hint body is §5.9's 400, never a 413",
            body.len()
        );
        assert!(store.calls().is_empty());
    }

    assert_eq!(
        block_on(write_hint(
            &Fake::default(),
            "v1",
            b"18446744073709551615".to_vec()
        ))
        .status(),
        Status::NoContent,
        "u64::MAX itself is exactly 20 digits and is legal"
    );
}

// -- §5a.6, §4.2: the gate and the routing, composed ------------------

/// A `RequestHead` through [`admit`], for the tests that drive the
/// public pair rather than a handler.
fn head<'a>(method: &'a str, path: &'a str, if_none_match: Option<&'a str>) -> RequestHead<'a> {
    RequestHead {
        method,
        path,
        base: "",
        range: &[],
        conditionals: Conditionals {
            if_none_match,
            fields: if_none_match.map_or(&[][..], |_| &["If-None-Match"][..]),
        },
        declared_len: None,
    }
}

fn admitted<'a>(head: &RequestHead<'a>) -> Admitted<'a> {
    admit(head).unwrap_or_else(|refusal| {
        panic!(
            "expected admission, got {:?} {:?}",
            refusal.outcome().status(),
            refusal.outcome().error()
        )
    })
}

/// §5a.6 and §6: **an `If-None-Match` value that is not a validator
/// this resource could have issued makes the request unconditional.**
///
/// RFC 9110 §13.1.2 makes the field `"*" / #entity-tag` — a LIST, or
/// the wildcard — while §5.8's `ETag` is opaque and "a client echoes
/// it verbatim", so a conforming client sends exactly one strong
/// entity-tag. Relaying anything else to the seam as a `HintToken`
/// lets a store that matched it drive a `304`, and the `304` then
/// carries that value as its `ETag`: `ETag: "*"` for the wildcard, a
/// validator the `200` would never have carried, which §6 forbids.
///
/// §5a.6 fixes the answer and it is not a `400`: "a value on the
/// exempt field that the server cannot match is not an error — the
/// answer is whatever the unconditional request would have
/// produced". So the seam is asked WITHOUT a cached token, and the
/// `404`/`200` it gives is the answer.
#[test]
fn only_one_strong_entity_tag_reaches_the_seam_as_a_cached_validator() {
    // A store that answers `NotModified` to any conditional read —
    // the case that turns a relayed value into a fabricated `ETag`.
    let matcher = || Fake {
        read_hint: Ok(HintRead::NotModified),
        ..Fake::default()
    };

    for value in [
        // The wildcard: a list form, never an entity-tag.
        "*",
        // A two-tag list, which is what `#entity-tag` means.
        "\"a\", \"b\"",
        "\"a\",\"b\"",
        // Weak: §5.8 requires a STRONG validator.
        "W/\"x\"",
        // Empty, and unquoted.
        "",
        "abc",
        "\"unterminated",
        // Header injection through the echoed `ETag`.
        "\"a\r\nX: y\"",
    ] {
        let store = matcher();
        let request = head("GET", "/volume/v1/hint", Some(value));
        let outcome = block_on(dispatch(&store, admitted(&request), Vec::new(), SEAM_ONLY));
        assert_eq!(
            store.calls(),
            vec![Call::ReadHint {
                volume: "v1".to_owned(),
                cached: None
            }],
            "{value:?}: §5a.6 makes an unmatchable value an UNCONDITIONAL read"
        );
        assert_ne!(
            outcome.status(),
            Status::NotModified,
            "{value:?}: §6 forbids a 304 carrying a validator the 200 \
             would not have carried"
        );
        assert_eq!(outcome.etag(), None, "{value:?}");
    }

    // The one spelling a conforming client sends does reach the seam,
    // so the rows above are a narrowing and not a blanket refusal.
    let store = matcher();
    let request = head("GET", "/volume/v1/hint", Some("\"v7\""));
    let outcome = block_on(dispatch(&store, admitted(&request), Vec::new(), SEAM_ONLY));
    assert_eq!(
        store.calls(),
        vec![Call::ReadHint {
            volume: "v1".to_owned(),
            cached: Some(HintToken("\"v7\"".to_owned()))
        }]
    );
    assert_eq!(outcome.status(), Status::NotModified);
    assert_eq!(outcome.etag(), Some("\"v7\""));

    // And an absent field is still an unconditional read.
    let store = matcher();
    let request = head("GET", "/volume/v1/hint", None);
    assert_eq!(
        block_on(dispatch(&store, admitted(&request), Vec::new(), SEAM_ONLY)).status(),
        Status::InternalServerError,
        "§6: a NotModified with nothing cached has no validator to carry"
    );
}

/// §4.2: every admitted operation reaches its own handler, with the
/// components the gate parsed and nothing invented.
#[test]
fn dispatch_routes_each_admitted_operation_to_its_own_handler() {
    let body = b"a body".to_vec();
    let digest = digest_of(&body);
    let id = GrainId::of(&body);
    let bin = format!(
        "/bin/{}",
        GrainId::of(&body).to_string().replace("blake3:", "")
    );
    let meta = format!("/volume/v1/meta/{id}");
    let hint_body = b"00000000000000000007".to_vec();

    let rows: Vec<(RequestHead<'_>, Vec<u8>, Call)> = vec![
        (
            head("PUT", &bin, None),
            body.clone(),
            Call::PutBin {
                digest,
                len: body.len(),
            },
        ),
        (
            RequestHead {
                range: &["bytes=100-199"],
                ..head("GET", &bin, None)
            },
            Vec::new(),
            Call::BinRange {
                digest,
                offset: 100,
                len: 100,
            },
        ),
        (
            head("PUT", &meta, None),
            body.clone(),
            Call::PutMeta {
                volume: "v1".to_owned(),
                id,
                len: body.len(),
            },
        ),
        (
            head("GET", &meta, None),
            Vec::new(),
            Call::GetMeta {
                volume: "v1".to_owned(),
                id,
            },
        ),
        (
            head("PUT", "/volume/v1/root/00000000000000000042", None),
            body.clone(),
            Call::PutRoot {
                volume: "v1".to_owned(),
                seq: 42,
                len: body.len(),
            },
        ),
        (
            head("GET", "/volume/v1/root/00000000000000000042", None),
            Vec::new(),
            Call::GetRoot {
                volume: "v1".to_owned(),
                seq: 42,
            },
        ),
        (
            head("GET", "/volume/v1/max-seq", None),
            Vec::new(),
            Call::MaxSeq {
                volume: "v1".to_owned(),
            },
        ),
        (
            head("GET", "/volume/v1/hint", None),
            Vec::new(),
            Call::ReadHint {
                volume: "v1".to_owned(),
                cached: None,
            },
        ),
        (
            head("PUT", "/volume/v1/hint", None),
            hint_body,
            Call::WriteHint {
                volume: "v1".to_owned(),
                seq: 7,
            },
        ),
    ];
    assert_eq!(rows.len(), 9, "§4.2 has nine operations");

    for (request, content, expected) in rows {
        let store = Fake::default();
        let _ = block_on(dispatch(&store, admitted(&request), content, SEAM_ONLY));
        assert_eq!(store.calls(), vec![expected], "{}", request.path);
    }
}

/// §5a.6: **a refused request never reaches the store, and the only
/// route to a handler is through the gate.** Each row below is
/// refused at a different step, and no `Admitted` exists for any of
/// them — which is what demoting the nine handlers to `pub(crate)`
/// buys: an adapter cannot answer one of these and then call a
/// handler anyway.
#[test]
fn nothing_the_gate_refuses_can_be_dispatched() {
    let bin = format!("/bin/{}", "0".repeat(64));
    let rows = [
        // Step 1: the target grammar.
        (404, head("GET", "/bin/nope", None)),
        // Step 2: the method.
        (405, head("DELETE", &bin, None)),
        (405, head("PUT", "/volume/v1/max-seq", None)),
        // Step 3: the conditional, outside its one exempt triple.
        (400, head("PUT", "/volume/v1/hint", Some("\"v7\""))),
        // Step 4: the range form — absent, on a resource that
        // REQUIRES one.
        (400, head("GET", &bin, None)),
    ];
    for (status, request) in rows {
        let refusal = admit(&request)
            .err()
            .unwrap_or_else(|| panic!("{} {} must be refused", request.method, request.path));
        assert_eq!(
            refusal.outcome().status().as_u16(),
            status,
            "{} {}",
            request.method,
            request.path
        );
    }
    // Step 5, which needs a range to reach.
    let past = format!("bytes={BIN_MAX_BYTES}-");
    let request = RequestHead {
        range: &[past.as_str()],
        ..head("GET", &bin, None)
    };
    assert_eq!(
        admit(&request)
            .err()
            .map(|refusal| refusal.outcome().status().as_u16()),
        Some(416)
    );
}

// -- §8.4 ------------------------------------------------------------

/// §8.4 and §13.2 item 9: **no error response discloses a store
/// key.** Every field of the rendered response is checked, not just
/// the body — a token, a validator or an `Allow` carrying the text
/// would leak it just as well.
#[test]
fn no_response_ever_relays_a_store_key() {
    let leaky = |error: RootStoreError| Fake {
        put_bin: Err(error.clone()),
        bin_range: Err(error.clone()),
        put_meta: Err(error.clone()),
        get_meta: Err(error.clone()),
        put_root: Err(error.clone()),
        get_root: Err(error.clone()),
        max_seq: Err(error.clone()),
        read_hint: Err(error.clone()),
        write_hint: Err(error),
        seen: Mutex::new(Vec::new()),
    };
    let body = b"a body".to_vec();
    let digest = digest_of(&body);
    let id = GrainId::of(&body);

    for error in [
        RootStoreError::Backend(LEAKY.to_owned()),
        RootStoreError::RefusedResponse {
            reason: LEAKY.to_owned(),
            kind: RefusalKind::OverCap,
        },
        RootStoreError::InvalidVolume {
            reason: LEAKY.to_owned(),
        },
    ] {
        let internal = (Status::InternalServerError, Some(ErrorToken::Internal));
        // §5.8's read-bound route is this endpoint's `404`, and the
        // rule under test is about the TEXT rather than the status:
        // a refusal that degrades must disclose no more than one
        // that does not.
        let hint = if matches!(error, RootStoreError::RefusedResponse { .. }) {
            (Status::NotFound, Some(ErrorToken::NotFound))
        } else {
            internal
        };
        let store = leaky(error.clone());
        let outcomes = vec![
            (
                internal,
                block_on(put_bin(&store, &digest, body.clone(), SEAM_ONLY)),
            ),
            (internal, block_on(get_bin_range(&store, &digest, 0, 10))),
            (
                internal,
                block_on(put_meta(&store, "v1", &id, body.clone())),
            ),
            (internal, block_on(get_meta(&store, "v1", &id))),
            (internal, block_on(put_root(&store, "v1", 1, body.clone()))),
            (internal, block_on(get_root(&store, "v1", 1))),
            (internal, block_on(max_seq(&store, "v1"))),
            (hint, block_on(read_hint(&store, "v1", None))),
            (
                internal,
                block_on(write_hint(&store, "v1", b"00000000000000000001".to_vec())),
            ),
        ];
        assert_eq!(outcomes.len(), 9, "§4.2 has nine operations");
        for (expected, outcome) in &outcomes {
            assert_eq!((outcome.status(), outcome.error()), *expected, "{error:?}");
            // The WHOLE struct first, then the accessors. The
            // accessors are the fields §6 puts on the wire today; the
            // struct rendering is every field there is, so a field
            // added to `Outcome` tomorrow — and rendered by an
            // adapter that transcribes what it finds — enters this
            // scan without anyone remembering to add it. The lossy
            // body stays: `Vec<u8>` renders as decimal bytes, in
            // which no fragment below can be spelled.
            //
            // CASE-FOLDED, because §8.4 is about the disclosure and
            // not about its spelling: a key relayed through anything
            // that shifts case — an uppercased diagnostic, a
            // normalising logger — discloses exactly as much. Every
            // fragment below is lowercase, so folding the haystack is
            // the whole of it.
            let rendered = format!(
                "{outcome:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {}",
                outcome.status(),
                outcome.error().map(ErrorToken::as_str),
                outcome.content_type().map(ContentType::as_str),
                outcome.cache_control().map(CacheControl::as_str),
                outcome.allow(),
                outcome.etag(),
                outcome.extent(),
                String::from_utf8_lossy(outcome.body())
            )
            .to_ascii_lowercase();
            for fragment in ["root/", "tenant-7", "bucket", "granary-prod", LEAKY] {
                // The haystack is case-folded, so a mixed-case
                // fragment could never match and would blind its own
                // row vacuously — refuse it before scanning with it.
                assert_eq!(
                    fragment,
                    fragment.to_ascii_lowercase(),
                    "a scan fragment must be lowercase or it can never match"
                );
                assert!(
                    !rendered.contains(fragment),
                    "§8.4: {fragment:?} reached the wire in {rendered}"
                );
            }
            assert!(outcome.body().is_empty());
        }
    }
}

// -- §5.1's third duty: ingest verification, and its two profiles ----

/// A bin a conforming packer emits: real grains, each frame
/// addressed by its own id.
fn honest_bin(grains: &[&[u8]]) -> Vec<u8> {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let frames: Vec<PackedFrame> = grains
        .iter()
        .map(|grain| PackedFrame {
            id: GrainId::of(grain),
            frame: codec
                .compress_grain(grain)
                .unwrap_or_else(|e| panic!("{e}")),
        })
        .collect();
    encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"))
}

/// A DECODABLE bin whose frame headers declare a decompressed sum
/// past the ingest limit — §13.4's verifying-profile-only row, and
/// §9.2's witness.
///
/// The frames are one real 8 MiB grain's bytes repeated under
/// FABRICATED ids, which is what an attacker sends: `decode_bin`
/// checks extents, headers and id UNIQUENESS and never that an id
/// hashes its frame, so the bin decodes. Every grain in it would
/// fail verification — which is the point of the row, because the
/// answer must still be the LIMIT's and not verification's.
fn declared_sum_bomb() -> Vec<u8> {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let grain = vec![0x5a_u8; GRAIN_UNPACKED_MAX as usize];
    let frame = codec
        .compress_grain(&grain)
        .unwrap_or_else(|e| panic!("{e}"));
    // 513 × 8 MiB = 4104 MiB, past the 4096 MiB limit, at a frame
    // count three orders of magnitude under the count cap and a body
    // of a few hundred kilobytes.
    let count = (INGEST_UNPACKED_SUM_MAX / u64::from(GRAIN_UNPACKED_MAX)) + 1;
    let frames: Vec<PackedFrame> = (0..count)
        .map(|i| PackedFrame {
            id: GrainId::of(&i.to_be_bytes()),
            frame: frame.clone(),
        })
        .collect();
    encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"))
}

fn digest_of_body(body: &[u8]) -> [u8; DIGEST_LEN] {
    *GrainId::of(body).digest()
}

/// **§5.1's third duty, and §13.4's two profiles over one request.**
///
/// The verifying profile refuses a body that is not a decodable bin
/// and one whose grain does not hash to its index id — both `400` +
/// `verify-failed`, which §13.4 binds to BOTH — and the store is
/// never reached. The seam-only profile stores the same bytes `201`,
/// and `200` on a repeat, because `BinStore::put_bin`'s contract is
/// the digest and nothing above it.
#[test]
fn ingest_verification_answers_both_section_13_5_profiles() {
    let not_a_bin = vec![0x5a_u8; 100];
    let digest = digest_of_body(&not_a_bin);

    let store = Fake::default();
    let refused = block_on(put_bin(&store, &digest, not_a_bin.clone(), VERIFYING));
    assert_eq!(
        (refused.status(), refused.error()),
        (Status::BadRequest, Some(ErrorToken::VerifyFailed)),
        "§13.4: an undecodable bin is verify-failed under the verifying profile"
    );
    assert!(
        store.calls().is_empty(),
        "§5.1: verification is an admission layer ABOVE the seam — a \
         refused bin never reaches the store"
    );

    let store = Fake::default();
    assert_eq!(
        block_on(put_bin(&store, &digest, not_a_bin.clone(), SEAM_ONLY)).status(),
        Status::Created,
        "§13.4: the seam-only profile answers 201 on the same bytes"
    );
    assert_eq!(store.calls().len(), 1, "and it DOES reach the store");
    // The repeat's `200` is the seam's own novelty bool, so here it
    // is a scripted answer; the STATEFUL form of the same claim — the
    // same bytes twice, over the wire — is the loopback battery's,
    // where a store that remembers exists.
    let occupied = Fake {
        put_bin: Ok(false),
        ..Fake::default()
    };
    assert_eq!(
        block_on(put_bin(&occupied, &digest, not_a_bin, SEAM_ONLY)).status(),
        Status::Ok,
        "§13.4: and 200 on the repeat"
    );

    // A DECODABLE bin whose grain is not what its index claims.
    let mut lying = honest_bin(&[b"the first grain", b"the second grain"]);
    let last = lying.len() - 1;
    lying[last] ^= 0xff;
    let lying_digest = digest_of_body(&lying);
    let store = Fake::default();
    let refused = block_on(put_bin(&store, &lying_digest, lying.clone(), VERIFYING));
    assert_eq!(
        (refused.status(), refused.error()),
        (Status::BadRequest, Some(ErrorToken::VerifyFailed)),
        "§13.4 binds one token to an undecodable bin AND a bad grain"
    );
    assert!(store.calls().is_empty());

    // The POSITIVE control, and it is what stops the two rows above
    // from passing against a check that refuses everything.
    let good = honest_bin(&[b"the first grain", b"the second grain"]);
    let good_digest = digest_of_body(&good);
    let store = Fake::default();
    assert_eq!(
        block_on(put_bin(&store, &good_digest, good.clone(), VERIFYING)).status(),
        Status::Created,
        "a bin a conforming packer emitted must be stored"
    );
    assert_eq!(store.calls().len(), 1, "and it must reach the seam");
    let occupied = Fake {
        put_bin: Ok(false),
        ..Fake::default()
    };
    assert_eq!(
        block_on(put_bin(&occupied, &good_digest, good, VERIFYING)).status(),
        Status::Ok,
        "a bin already present is success, never an error (§5.1)"
    );
}

/// **The ingest decompressed-sum refusal is `413` + `too-large`, and it PRECEDES grain
/// verification.**
///
/// The witness bin's grains would every one of them fail their hash
/// check, so a server that verified first would answer `400` +
/// `verify-failed`. §5.1 makes the precedence normative and states
/// why the client can act on it: the remedy for `413` is re-pack
/// smaller and RETRY, and `verify-failed`/`layout-invalid` both read
/// as never-retry.
#[test]
fn a_declared_sum_past_the_ingest_limit_is_413_too_large_and_not_verify_failed() {
    let bomb = declared_sum_bomb();
    assert!(
        granary_core::binfmt::decode_bin(&bomb).is_ok(),
        "the witness must be a DECODABLE bin, or it is testing the \
         undecodable row instead"
    );
    assert!(
        u64::try_from(bomb.len()).unwrap_or(u64::MAX) < BIN_MAX_BYTES,
        "and it must be inside the body cap, or it is testing that"
    );
    let digest = digest_of_body(&bomb);

    let store = Fake::default();
    let refused = block_on(put_bin(&store, &digest, bomb.clone(), VERIFYING));
    assert_eq!(
        (refused.status(), refused.error()),
        (Status::ContentTooLarge, Some(ErrorToken::TooLarge)),
        "§9.2: the ingest limit is 413 + too-large — never layout-invalid, \
         whose client action is the opposite one"
    );
    assert!(store.calls().is_empty());

    // §13.4: the seam-only profile answers 201 on the same request.
    let store = Fake::default();
    assert_eq!(
        block_on(put_bin(&store, &digest, bomb, SEAM_ONLY)).status(),
        Status::Created,
        "the limit is an admission-layer refusal, not a decode bound"
    );
}

/// The address check still runs FIRST, so a bomb sent to the wrong
/// digest costs no verification at all — and an over-cap body is
/// still `413` before either (§5a.6 step 7).
#[test]
fn the_cap_and_the_address_still_precede_verification() {
    let store = Fake::default();
    let bomb = declared_sum_bomb();
    let mismatched = block_on(put_bin(&store, &WRONG_DIGEST, bomb, VERIFYING));
    assert_eq!(
        (mismatched.status(), mismatched.error()),
        (Status::BadRequest, Some(ErrorToken::AddressMismatch)),
        "a body that is not the address it was sent to is refused before \
         any work is spent on what it holds"
    );

    let over = usize::try_from(BIN_MAX_BYTES).unwrap_or(usize::MAX) + 1;
    let huge = vec![0_u8; over];
    assert_eq!(
        block_on(put_bin(&store, &digest_of_body(&huge), huge, VERIFYING)).status(),
        Status::ContentTooLarge,
        "the body cap is step 7 and runs before everything here"
    );
    assert!(store.calls().is_empty());
}

/// The seam bound `granary_net::serve` will need: every handler
/// future is `Send`. Asserted rather than assumed, because the
/// failure mode is a `Service` impl that will not compile in a task
/// three layers away from here.
#[test]
fn every_handler_future_is_send() {
    fn assert_send<F: Send>(_: F) {}
    let store = Fake::default();
    let body = b"x".to_vec();
    let digest = digest_of(&body);
    let id = GrainId::of(&body);
    assert_send(put_bin(&store, &digest, body.clone(), SEAM_ONLY));
    assert_send(get_bin_range(&store, &digest, 0, 1));
    assert_send(put_meta(&store, "v1", &id, body.clone()));
    assert_send(get_meta(&store, "v1", &id));
    assert_send(put_root(&store, "v1", 1, body.clone()));
    assert_send(get_root(&store, "v1", 1));
    assert_send(max_seq(&store, "v1"));
    assert_send(read_hint(&store, "v1", None));
    assert_send(write_hint(&store, "v1", body.clone()));
    // And the routed pair, which is what an adapter actually holds.
    let request = head("GET", "/volume/v1/max-seq", None);
    assert_send(dispatch(&store, admitted(&request), body, SEAM_ONLY));
}
