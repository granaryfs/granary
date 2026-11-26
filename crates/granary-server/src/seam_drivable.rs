// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The nine handlers are drivable by a SECOND implementation of the two
//! seams — no `object_store`, no filesystem, no runtime.
//!
//! This is the property the crate's whole shape rests on:
//! [`crate::dispatch`] and the handlers behind it are generic over
//! `RootStore + BinStore` precisely so an in-process embedding and the
//! simulator can drive them against something that is not the production
//! adapter.
//!
//! **What is exclusive to this file is the GENERIC [`drive`], and that
//! is the whole of the structural claim.** The crate's other tests
//! already hold the bound down for most of what could creep into it:
//! they drive the handlers with a `&Fake` of their own, so a handler
//! that grew `+ Clone` stops compiling there, against a scripted seam
//! that is not `Clone`. What no concrete call site can see is a
//! requirement BOTH in-crate fakes happen to satisfy: ask a handler for
//! `Debug`, for `Default` or for `'static` and carry it up through
//! [`crate::dispatch`], and each errors at the [`drive`] call below and
//! at no other line in the crate. `Send` and `Sync` are NOT on that
//! list and cannot be — `RootStore` and `BinStore` already require
//! both, so a handler asking for either compiles everywhere and this
//! file stays green. [`drive`] is generic over `S`, so inside its body
//! the declared bound is the only thing known about the store and such
//! a creep breaks the build here; with [`drive`] made concrete the same
//! creep goes undetected anywhere in the crate.
//!
//! Everything else this file does is done better elsewhere or done here
//! as well, with ONE exception, named where it is driven: the same-seq
//! rewrite in
//! [`the_hint_is_written_polled_and_revalidated_over_the_wire`]. It
//! needs a store that MINTS a token per write, and the crate's other
//! seam answers one scripted value to every call, so nothing else in
//! the crate can ask for two tokens against one seq.
//!
//! **The fake itself lives in [`crate::fake`]**, because the loopback
//! battery drives the same store through the adapter over a real
//! connection. Two fakes would be two stores that could disagree about
//! what the seam does, with neither site's tests able to see it. What
//! stays here is the DRIVING: no runtime, no HTTP, [`admit`] then
//! [`dispatch`] and nothing between them.
//!
//! **Why it is a module of the lib and not an integration test.** A
//! `tests/` target is a separate crate and reaches only what is `pub`,
//! so anything this file came to need beyond the curated surface would
//! have to be published — and `main.rs`, the composition root, could
//! then reach it too. The second-implementation property lives in the
//! fake, never in crate separation, so nothing is bought by paying
//! that price. What the file does use is the curated surface and ONE
//! item beyond it: [`crate::admit`], [`crate::dispatch`], the wire
//! vocabulary, and `admission::admit_declaring` — the `#[cfg(test)]`
//! door that constructs a server declaring a different maximum extent
//! (§7.1). That exception is [`the_section_13_4_extent_rows_hold_under_both_profiles`]'s
//! reason to exist: §13.4 pins the extent rule's wire behaviour under
//! BOTH declared profiles, and the non-enforcing profile is not
//! constructible from the curated surface — deliberately, because
//! §13.5's reachability rule requires that the production composition
//! root cannot construct it either.
//!
//! **Both seam traits are RPITIT and therefore dyn-incompatible**
//! so every route through this file is by generic bound;
//! `&dyn RootStore` is not available and that is expected.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use granary_core::binstore::BinStore;
use granary_core::hash::GrainId;
use granary_core::rootstore::{RootStore, format_hint_body};
use granary_store::bounds::ROOT_MAX_BYTES;

use crate::admission::{DECLARED_MAX_EXTENT, admit_declaring};
use crate::fake::{FakeSeam, HINT_TOKEN_STEM};
use crate::policy::VerifyPolicy;
use crate::{
    Allow, CacheControl, Conditionals, ContentType, ErrorToken, Outcome, RequestHead, Status,
    admit, dispatch,
};

/// **The §13.5 profile THIS file declares: seam-only.** It is not a
/// convenience — the shared conformance bodies below store a 100-byte
/// non-bin under its own digest and require `Ok(true)`, which §13.5 says
/// in as many words a verifying server cannot serve. The verifying
/// profile's obligations are asserted where a real bin can be built:
/// `handlers`, which has the codec, and the loopback battery, which
/// sends both profiles the same request (§13.4).
const SEAM_ONLY: VerifyPolicy = VerifyPolicy::seam_only();

// ------------------------------------------------------------- no runtime

/// Poll a future to completion with no executor and no runtime.
///
/// **This cannot hang.** The fake answers out of a `BTreeMap`
/// with no await point in the body, so each future is `Ready` on its
/// first poll; `Pending` would mean the fake grew one, which is exactly
/// what this file exists to assert against, so it fails loudly instead
/// of spinning. A spin would be the worse answer twice over: a noop
/// waker is never woken, so nothing could ever make progress, and a
/// hung test says less than a failed one.
///
/// `Waker::noop` is what makes this writable at all — `unsafe_code` is
/// forbidden workspace-wide, and a hand-rolled `RawWaker` vtable needs
/// `unsafe`.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a fake seam answers from memory and never yields"),
    }
}

// --------------------------------------------------------------- driving

/// The configured `{base}` (§4.1), carried through every target below so
/// the base strip is on the path this file drives.
const BASE: &str = "/granary";

/// A DNS-1123 label (§4.3).
const VOLUME: &str = "seam-vol";

/// The composition an adapter performs, and the ONLY route this file
/// takes to a handler: [`admit`] then [`dispatch`], with a refusal
/// carried straight out (§5a.6).
///
/// **Generic on purpose.** A concrete call would keep compiling for any
/// requirement `FakeSeam` happens to satisfy — `Debug`, `Default`,
/// `'static` — while a second implementation without it broke. Inside
/// this body the bound is the only thing known about `S`, so the day a
/// handler asks for more than `RootStore + BinStore`, this stops
/// compiling here rather than in whoever writes the next store.
fn drive<S: RootStore + BinStore>(store: &S, head: &RequestHead<'_>, body: Vec<u8>) -> Outcome {
    block_on(async {
        match admit(head) {
            Ok(admitted) => dispatch(store, admitted, body, SEAM_ONLY).await,
            Err(refusal) => refusal.into_outcome(),
        }
    })
}

/// The same drive, at a server declaring `max_extent` (§7.1) — `None`
/// for one that enforces no maximum.
///
/// Generic for the reason [`drive`] is, and it composes the SAME two
/// steps in the same order: the declaration reaches the gate and
/// nothing else, so a row's answer under either profile differs only
/// where §7.1 says it may.
fn drive_declaring<S: RootStore + BinStore>(
    store: &S,
    head: &RequestHead<'_>,
    body: Vec<u8>,
    max_extent: Option<u32>,
) -> Outcome {
    block_on(async {
        match admit_declaring(head, max_extent) {
            Ok(admitted) => dispatch(store, admitted, body, SEAM_ONLY).await,
            Err(refusal) => refusal.into_outcome(),
        }
    })
}

/// A request head carrying no `Range` and no conditional.
fn head<'a>(method: &'a str, path: &'a str) -> RequestHead<'a> {
    RequestHead {
        method,
        path,
        base: BASE,
        range: &[],
        conditionals: Conditionals::default(),
        declared_len: None,
    }
}

/// A `GET` carrying `Range` field lines (§7.1).
fn ranged<'a>(path: &'a str, lines: &'a [&'a str]) -> RequestHead<'a> {
    RequestHead {
        range: lines,
        ..head("GET", path)
    }
}

/// The `{digest}` segment of a bin target (§4.3).
fn bin_path(body: &[u8]) -> String {
    format!("{BASE}/bin/{}", GrainId::of(body).digest_hex())
}

/// The response's extent, or a failure naming what was missing.
///
/// The `panic!` is the failure, and it is in scope: the workspace bans
/// `unwrap`/`expect`/indexing outright and bans panics REACHABLE FROM
/// UNTRUSTED INPUT, and a `#[cfg(test)]` accessor over an [`Outcome`] a
/// test just built is reachable from no input at all. `assert_eq!` on
/// `None` would say less about which invariant broke. Same for
/// [`etag`] below and for [`block_on`] above.
fn extent(outcome: &Outcome) -> (u64, u64) {
    outcome.extent().map_or_else(
        || panic!("a 206 carries the extent it served (§7.2)"),
        |extent| (extent.first(), extent.last()),
    )
}

/// The response's `ETag`, or a failure naming what was missing.
fn etag(outcome: &Outcome) -> String {
    outcome.etag().map_or_else(
        || panic!("§5.8 makes the hint's ETag REQUIRED"),
        str::to_owned,
    )
}

// ----------------------------------------------------------------- tests

/// The structural closure for the accept-set divergence class. A fake
/// that answers an empty success where production answers a range error
/// — or that skips the volume check — passes every test written around
/// it and diverges from the store the handlers will really face.
#[test]
fn the_fake_passes_the_shared_binstore_conformance_suite() {
    let store = FakeSeam::default();
    block_on(granary_core::testkit::binstore_conformance(&store));
}

/// The same closure on the other seam. The suite takes an EMPTY store,
/// so it gets its own.
#[test]
fn the_fake_passes_the_shared_rootstore_conformance_suite() {
    let store = FakeSeam::default();
    block_on(granary_core::testkit::rootstore_conformance(&store));
}

/// §5.1, §5.2 and §7.2 end to end: store a bin through the gate, read it
/// back in pieces, and watch the extent follow what was delivered.
#[test]
fn a_bin_round_trips_through_the_gate_and_the_handlers() {
    let store = FakeSeam::default();
    let body = b"a bin that never touched a disk".to_vec();
    let path = bin_path(&body);

    let created = drive(&store, &head("PUT", &path), body.clone());
    assert_eq!(created.status(), Status::Created, "§5.1: a novel bin");
    assert_eq!(created.error(), None);

    assert_eq!(
        drive(&store, &head("PUT", &path), body.clone()).status(),
        Status::Ok,
        "§5.1: an object already present is success, never a conflict"
    );

    let served = drive(&store, &ranged(&path, &["bytes=0-9"]), Vec::new());
    assert_eq!(served.status(), Status::PartialContent);
    assert_eq!(served.content_type(), Some(ContentType::Bin));
    assert_eq!(served.cache_control(), Some(CacheControl::Immutable));
    assert_eq!(served.body(), body.get(0..10).unwrap_or_default());
    assert_eq!(extent(&served), (0, 9));

    // A range that starts inside and overhangs the end SHORT-READS
    // (§7.2), and the declared extent narrows with the body rather than
    // promising bytes that were never sent.
    let overhang = drive(&store, &ranged(&path, &["bytes=25-99"]), Vec::new());
    assert_eq!(overhang.status(), Status::PartialContent);
    assert_eq!(overhang.body(), body.get(25..).unwrap_or_default());
    assert_eq!(extent(&overhang), (25, 30));

    let absent = bin_path(b"a bin nobody ever stored");
    let missing = drive(&store, &ranged(&absent, &["bytes=0-9"]), Vec::new());
    assert_eq!(missing.status(), Status::NotFound);
    assert_eq!(missing.error(), Some(ErrorToken::NotFound));
}

/// §13.4's declared-maximum-extent rows: four requests, each sent under
/// BOTH declared profiles, through the gate and the handlers.
///
/// **The declaration chooses which answer is asserted, never which rows
/// execute** — §13.4's discipline, inherited from §13.5's
/// verifying/seam-only split. Every request below is sent twice, so no
/// declaration is free and none deletes a row: an enforcing server
/// declared non-enforcing fails on the `400` it emits where a `404` or
/// a `206` was asserted, and a non-enforcing server declared enforcing
/// fails the other way.
///
/// **Row 3 is the one that pins the bound to the ASK rather than to the
/// answer.** The bin is 100 bytes and the honest answer to
/// `bytes=0-{E}` is 100 bytes, which is what the non-enforcing column
/// asserts — so a server that peeked at the store and refused only what
/// it could not serve would pass every other row here and fail this
/// one. That reading ("served-extent semantics") is forbidden:
/// it makes the refusal boundary a length oracle (§7.4).
///
/// **Row 4 is the boundary, and the `404` is what makes it a positive
/// control.** Its mapped `len` is EXACTLY the declared maximum, so the
/// request passes step 6 and reaches the store — a `404` from the store
/// is the proof it got there. Without it the table would be satisfied
/// by a server that refuses every range.
///
/// The wire-level corpus run is Part II's business (it needs the
/// adapter); what is asserted here is the same rule at the seam the
/// handlers actually answer on.
#[test]
fn the_section_13_4_extent_rows_hold_under_both_profiles() {
    const ENFORCING: Option<u32> = Some(DECLARED_MAX_EXTENT);
    const NON_ENFORCING: Option<u32> = None;

    let store = FakeSeam::default();
    let e = u64::from(DECLARED_MAX_EXTENT);

    // The stored 100-byte bin of row 3, put through the gate.
    let stored = vec![0x5a_u8; 100];
    let stored_path = bin_path(&stored);
    assert_eq!(
        drive(&store, &head("PUT", &stored_path), stored.clone()).status(),
        Status::Created,
        "row 3 needs a bin that is really there"
    );
    let absent_path = bin_path(b"a bin nobody ever stored");

    // Rows 1, 2 and 4 — an ABSENT digest, so the answer discriminates
    // "refused before the store" from "reached the store".
    let open_ended = "bytes=0-".to_owned();
    let over_by_one = format!("bytes=0-{e}");
    let at_the_boundary = format!("bytes=0-{}", e - 1);

    for (value, enforcing_row) in [
        // Row 1: the open-ended form, mapped `len` u32::MAX.
        (
            open_ended.as_str(),
            (Status::BadRequest, Some(ErrorToken::ExtentTooWide)),
        ),
        // Row 2: fully specified, mapped `len` is E + 1.
        (
            over_by_one.as_str(),
            (Status::BadRequest, Some(ErrorToken::ExtentTooWide)),
        ),
        // Row 4: mapped `len` is exactly E — admitted, and the store
        // answers.
        (
            at_the_boundary.as_str(),
            (Status::NotFound, Some(ErrorToken::NotFound)),
        ),
    ] {
        let enforcing = drive_declaring(
            &store,
            &ranged(&absent_path, &[value]),
            Vec::new(),
            ENFORCING,
        );
        assert_eq!(
            (enforcing.status(), enforcing.error()),
            enforcing_row,
            "{value}: §13.4, enforcing profile"
        );
        // Non-enforcing: every one of these reaches the store, and the
        // digest is absent.
        let non_enforcing = drive_declaring(
            &store,
            &ranged(&absent_path, &[value]),
            Vec::new(),
            NON_ENFORCING,
        );
        assert_eq!(
            (non_enforcing.status(), non_enforcing.error()),
            (Status::NotFound, Some(ErrorToken::NotFound)),
            "{value}: §13.4, non-enforcing profile"
        );
    }

    // Row 3 — the SAME over-wide ask against a bin that exists.
    let refused = drive_declaring(
        &store,
        &ranged(&stored_path, &[over_by_one.as_str()]),
        Vec::new(),
        ENFORCING,
    );
    assert_eq!(
        (refused.status(), refused.error()),
        (Status::BadRequest, Some(ErrorToken::ExtentTooWide)),
        "§13.4 row 3: the rule refuses the ask, not the answer"
    );
    assert!(
        refused.body().is_empty(),
        "§7.1: refused WHOLE — never a prefix, never a narrowed extent"
    );

    let served = drive_declaring(
        &store,
        &ranged(&stored_path, &[over_by_one.as_str()]),
        Vec::new(),
        NON_ENFORCING,
    );
    assert_eq!(served.status(), Status::PartialContent);
    assert_eq!(served.error(), None);
    assert_eq!(served.body(), stored, "§13.4 row 3: all 100 bytes");
    assert_eq!(
        extent(&served),
        (0, 99),
        "§7.2: the short read narrows the extent to what was delivered"
    );
}

/// §5.3 and §5.4: the server stores bytes it never parses and serves
/// them back unaltered.
///
/// The other half of §5.3 — the address check — is driven in
/// [`a_refused_request_never_reaches_the_store`], where the whole-store
/// assertion can also see that the refused write stored nothing. Every
/// id here is the body's own, so nothing below would notice the check
/// being removed.
#[test]
fn a_meta_object_round_trips_without_the_server_parsing_it() {
    let store = FakeSeam::default();
    // Not any of the four meta object formats — a server that had
    // learned to parse one would refuse this, and §5.3 forbids that.
    let body = b"thirteen bytes".to_vec();
    let id = GrainId::of(&body);
    let path = format!("{BASE}/volume/{VOLUME}/meta/{id}");

    assert_eq!(
        drive(&store, &head("PUT", &path), body.clone()).status(),
        Status::Created
    );
    assert_eq!(
        drive(&store, &head("PUT", &path), body.clone()).status(),
        Status::Ok,
        "§5.3: a second write of the same object is success"
    );

    let served = drive(&store, &head("GET", &path), Vec::new());
    assert_eq!(served.status(), Status::Ok);
    assert_eq!(served.content_type(), Some(ContentType::Meta));
    assert_eq!(served.body(), body, "§5.4: the stored bytes, unaltered");

    let absent = GrainId::of(b"a meta object nobody ever stored");
    let missing = drive(
        &store,
        &head("GET", &format!("{BASE}/volume/{VOLUME}/meta/{absent}")),
        Vec::new(),
    );
    assert_eq!(missing.status(), Status::NotFound);
    assert_eq!(missing.error(), Some(ErrorToken::NotFound));
}

/// §5.5, §5.6 and §5.7: a seq is claimed once, served byte for byte, and
/// counted as the head.
#[test]
fn a_root_is_put_if_absent_and_becomes_the_head() {
    let store = FakeSeam::default();
    let winner = b"the root the first writer created".to_vec();
    let loser = b"the root a second writer must never land".to_vec();
    let path = format!("{BASE}/volume/{VOLUME}/root/{}", format_hint_body(1));

    assert_eq!(
        drive(&store, &head("PUT", &path), winner.clone()).status(),
        Status::Created
    );
    let conflict = drive(&store, &head("PUT", &path), loser);
    assert_eq!(
        conflict.status(),
        Status::Conflict,
        "§5.5: the seq is taken"
    );
    assert_eq!(conflict.error(), Some(ErrorToken::AlreadyExists));

    let served = drive(&store, &head("GET", &path), Vec::new());
    assert_eq!(served.status(), Status::Ok);
    assert_eq!(served.content_type(), Some(ContentType::Root));
    assert_eq!(served.cache_control(), Some(CacheControl::Immutable));
    assert_eq!(
        served.body(),
        winner,
        "§5.5: put-if-absent does not overwrite, so the loser's bytes are not here"
    );

    let free = format!("{BASE}/volume/{VOLUME}/root/{}", format_hint_body(2));
    let unpublished = drive(&store, &head("GET", &free), Vec::new());
    assert_eq!(unpublished.status(), Status::NotFound);
    assert_eq!(
        unpublished.error(),
        Some(ErrorToken::NotFound),
        "§8.1: the token is what lets a client map this to Ok(None)"
    );
    assert_eq!(unpublished.cache_control(), None);

    let head_seq = drive(
        &store,
        &head("GET", &format!("{BASE}/volume/{VOLUME}/max-seq")),
        Vec::new(),
    );
    assert_eq!(head_seq.status(), Status::Ok);
    assert_eq!(head_seq.content_type(), Some(ContentType::Text));
    assert_eq!(head_seq.cache_control(), Some(CacheControl::NoStore));
    assert_eq!(
        head_seq.body(),
        format_hint_body(1).as_bytes(),
        "§5.7: exactly 20 zero-padded ASCII digits"
    );

    let elsewhere = drive(
        &store,
        &head("GET", &format!("{BASE}/volume/other-vol/max-seq")),
        Vec::new(),
    );
    assert_eq!(elsewhere.status(), Status::NotFound);
    assert_eq!(elsewhere.error(), Some(ErrorToken::NotFound));
    assert_eq!(elsewhere.cache_control(), Some(CacheControl::NoStore));
    assert_eq!(elsewhere.etag(), None);
    assert!(elsewhere.body().is_empty());
}

/// §5.8 and §5.9 end to end, including the `304` — which is reachable
/// only because a real store is on the other side of the seam: the
/// validator a `200` hands out has to be the one a later request
/// revalidates against, and a scripted answer cannot show that.
///
/// **The seqs are 41 and 42, not 1 and 2.** The store's token counts
/// writes from 1 ([`HINT_TOKEN_STEM`]), so seqs starting at 1 would make
/// the first token's number equal the first seq and the exact check
/// below would pass on a coincidence.
#[test]
fn the_hint_is_written_polled_and_revalidated_over_the_wire() {
    const SEQ: u64 = 41;
    const MOVED_SEQ: u64 = 42;

    let store = FakeSeam::default();
    let path = format!("{BASE}/volume/{VOLUME}/hint");

    let unset = drive(&store, &head("GET", &path), Vec::new());
    assert_eq!(unset.status(), Status::NotFound, "§5.8: no hint is Missing");
    assert_eq!(unset.error(), Some(ErrorToken::NotFound));
    assert_eq!(unset.cache_control(), Some(CacheControl::NoCache));
    assert_eq!(unset.etag(), None);
    assert!(unset.body().is_empty());

    let written = drive(
        &store,
        &head("PUT", &path),
        format_hint_body(SEQ).into_bytes(),
    );
    assert_eq!(written.status(), Status::NoContent, "§5.9");

    let polled = drive(&store, &head("GET", &path), Vec::new());
    assert_eq!(polled.status(), Status::Ok);
    assert_eq!(polled.content_type(), Some(ContentType::Text));
    assert_eq!(polled.cache_control(), Some(CacheControl::NoCache));
    assert_eq!(polled.body(), format_hint_body(SEQ).as_bytes());
    let first = etag(&polled);
    // The `1` is the volume's FIRST WRITE, not the seq — which is 41.
    assert_eq!(
        first,
        format!("\"{HINT_TOKEN_STEM}1\""),
        "§5.8, §6: the ETag is the STORE's opaque token carried through, \
         byte for byte and quoting included"
    );

    let fields = ["If-None-Match"];
    let fresh = drive(
        &store,
        &RequestHead {
            conditionals: Conditionals {
                if_none_match: Some(&first),
                fields: &fields,
            },
            ..head("GET", &path)
        },
        Vec::new(),
    );
    // This row binds a second implementation to QUOTED tokens, and that
    // is a choice about the FAKE rather than a rule about the server:
    // `handlers::validator` documents a bare-token backend as conforming
    // and says what it costs — the value a client echoes is not the value
    // the store holds, no revalidation can match, and a fresh `200` is
    // the legal answer. A simulator store minting bare tokens reads its
    // RED here as that, not as a server defect.
    assert_eq!(fresh.status(), Status::NotModified, "§5.8: the poll's 304");
    assert_eq!(fresh.etag(), Some(first.as_str()), "§6: the same validator");
    assert!(fresh.body().is_empty());

    // **The row that forbids a validator the handler computed itself.**
    // The hint is written again to the SAME seq. The `GET`s either side
    // of that write are the same request against the same volume and
    // read back the same seq, so every input a handler has is identical
    // across them — and so is any `ETag` it derived from one. What moved
    // is the store's write count, which no handler can see. This line
    // therefore fails for `"{seq}"`, for `"v{9000 + seq}"`, for a
    // hardcoded constant and for every other function of the volume and
    // the seq, instead of for the particular arithmetic someone thought
    // to write down.
    assert_eq!(
        drive(
            &store,
            &head("PUT", &path),
            format_hint_body(SEQ).into_bytes()
        )
        .status(),
        Status::NoContent
    );
    let repolled = drive(&store, &head("GET", &path), Vec::new());
    assert_eq!(repolled.status(), Status::Ok);
    assert_eq!(
        repolled.body(),
        format_hint_body(SEQ).as_bytes(),
        "the seq did not move — it is the store's token that must have"
    );
    let rewritten = etag(&repolled);
    assert_ne!(
        rewritten, first,
        "the store minted a new token for an unchanged seq and the ETag did not follow it, \
         so the ETag is not the store's token"
    );

    // The hint MOVES. §5.8 requires the validator to change with it, or
    // the cached one pins every reader to a dead seq. The conditional
    // carries the token the poll above handed out, which is the one a
    // client would be holding.
    assert_eq!(
        drive(
            &store,
            &head("PUT", &path),
            format_hint_body(MOVED_SEQ).into_bytes()
        )
        .status(),
        Status::NoContent
    );
    let moved = drive(
        &store,
        &RequestHead {
            conditionals: Conditionals {
                if_none_match: Some(&rewritten),
                fields: &fields,
            },
            ..head("GET", &path)
        },
        Vec::new(),
    );
    assert_eq!(
        moved.status(),
        Status::Ok,
        "a stale validator must not match"
    );
    assert_eq!(moved.body(), format_hint_body(MOVED_SEQ).as_bytes());
    let after_move = etag(&moved);
    assert_ne!(after_move, rewritten, "§5.8: the ETag changes with the seq");
    assert_ne!(after_move, first, "and never returns to an earlier one");

    // §5.9's body has one legal length, so "too long" and "malformed"
    // are the same refusal and neither is a 413.
    let malformed = drive(&store, &head("PUT", &path), b"1".to_vec());
    assert_eq!(malformed.status(), Status::BadRequest);
    assert_eq!(malformed.error(), Some(ErrorToken::BadRequest));
}

/// Every refusal above the seam leaves the store EMPTY — every map, and
/// not one probed key.
///
/// The whole-store form is what makes this a claim about refusals rather
/// than about one address. A handler that took a mismatched payload and
/// stored it under the payload's own re-hashed digest writes a key no
/// probe would think to read; a `put_root` that stores before answering
/// `413`, a `put_meta` that stores before answering `400` and a
/// `write_hint` that moves the hint before answering `400` write three
/// other maps entirely. So the refusals below are one per endpoint that
/// can write, and the assertion at the end is [`FakeSeam::objects`].
///
/// This is a claim only a stateful implementation can carry: a scripted
/// seam has no map to be empty.
#[test]
fn a_refused_request_never_reaches_the_store() {
    let store = FakeSeam::default();
    let body = b"bytes the store must never see".to_vec();
    let path = bin_path(&body);

    // Step 2 — the method, with the target resource's own Allow (§4.2).
    let refused = drive(&store, &head("DELETE", &path), body.clone());
    assert_eq!(refused.status(), Status::MethodNotAllowed);
    assert_eq!(refused.error(), Some(ErrorToken::MethodNotAllowed));
    assert_eq!(refused.allow(), Some(Allow::GetPut));

    // Step 1 — the target grammar (§4.3). Built from BASE rather than
    // spelled out: a literal that stopped agreeing with the configured
    // base would still answer `unknown-target`, and this row would then
    // pass for a reason it does not name — the base strip rather than
    // the `{digest}` grammar.
    let malformed_digest = format!("{BASE}/bin/not-a-digest");
    let unknown = drive(&store, &head("GET", &malformed_digest), Vec::new());
    assert_eq!(unknown.status(), Status::NotFound);
    assert_eq!(
        unknown.error(),
        Some(ErrorToken::UnknownTarget),
        "§8.1: never the token a client maps to a success"
    );

    // Step 4 — a GET bin with no Range at all (§7.1).
    let unranged = drive(&store, &head("GET", &path), Vec::new());
    assert_eq!(unranged.status(), Status::BadRequest);
    assert_eq!(unranged.error(), Some(ErrorToken::BadRange));

    // Step 6 then the seam call's precondition — the address (§5.1).
    let mismatched = drive(&store, &head("PUT", &path), b"not those bytes".to_vec());
    assert_eq!(mismatched.status(), Status::BadRequest);
    assert_eq!(mismatched.error(), Some(ErrorToken::AddressMismatch));

    // The same precondition on the other addressed object (§5.3). Its
    // check is a second one in a second handler over a second map, so
    // the bin row above says nothing about it.
    let elsewhere = GrainId::of(b"the id of some other object entirely");
    let mis_addressed = drive(
        &store,
        &head("PUT", &format!("{BASE}/volume/{VOLUME}/meta/{elsewhere}")),
        b"bytes that are not that id's".to_vec(),
    );
    assert_eq!(mis_addressed.status(), Status::BadRequest);
    assert_eq!(mis_addressed.error(), Some(ErrorToken::AddressMismatch));

    // Step 6 proper on a root — the body cap, the one refusal here that
    // is a 413 (§5.5, §5a.2). The `+ 1` is taken in `u64` and converted
    // after, so the length is one byte over the cap or the conversion
    // fails; a `usize::MAX` fallback would be an ALLOCATION SIZE rather
    // than a cap, which is the wrong way to fail. On a target where
    // 64 KiB does not fit a `usize` no body can exceed this cap at all
    // and the row is unwritable, which is what the message says.
    let Ok(over_cap) = usize::try_from(ROOT_MAX_BYTES.saturating_add(1)) else {
        panic!("ROOT_MAX_BYTES does not fit a usize here, so no body can exceed it")
    };
    let oversized = drive(
        &store,
        &head(
            "PUT",
            &format!("{BASE}/volume/{VOLUME}/root/{}", format_hint_body(1)),
        ),
        vec![0xA5; over_cap],
    );
    assert_eq!(oversized.status(), Status::ContentTooLarge);
    assert_eq!(oversized.error(), Some(ErrorToken::TooLarge));

    // And the hint, whose refusal is the body's SHAPE rather than a cap
    // (§5.9) — a fourth map, reached by a fourth handler.
    let short_hint = drive(
        &store,
        &head("PUT", &format!("{BASE}/volume/{VOLUME}/hint")),
        b"1".to_vec(),
    );
    assert_eq!(short_hint.status(), Status::BadRequest);
    assert_eq!(short_hint.error(), Some(ErrorToken::BadRequest));

    assert_eq!(
        store.objects(),
        0,
        "a refusal above the seam wrote to the store: every map must still be empty"
    );
}
