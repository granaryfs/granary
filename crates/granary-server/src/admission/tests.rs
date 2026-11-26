// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::admission` — the admission gate — §5a.6 steps
//! 1–6, in order, over a borrowed request head.
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{
    Admitted, Conditionals, DECLARED_MAX_EXTENT, INGEST_UNPACKED_SUM_MAX, Operation, RequestHead,
    admit, admit_declaring,
};
use crate::wire::{Allow, ErrorToken, Resource};
use granary_core::binfmt::{
    BIN_FIXED_HEADER_LEN, BIN_INDEX_ENTRY_LEN, BIN_MAX_BYTES, BIN_TARGET_BYTES,
    BIN_UNPACKED_TARGET_BYTES, FRAME_COMP_MAX, FramePlan, MAX_GRAINS_PER_BIN, plan_bins,
};
use granary_core::manifest::GRAIN_UNPACKED_MAX;

/// The two profiles §13.4 declares, named so that a call site reads
/// as a DECLARATION rather than as an argument. §13.4's discipline
/// is that the declaration chooses only which answer is asserted —
/// the same request is sent either way — so both names appear
/// against the same rows below.
const ENFORCING: Option<u32> = Some(DECLARED_MAX_EXTENT);
const NON_ENFORCING: Option<u32> = None;

/// 64 lowercase hex characters — a legal `{digest}` and, with the
/// tag, a legal `{grain-id}`.
const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GRAIN_ID: &str = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn req<'a>(method: &'a str, path: &'a str) -> RequestHead<'a> {
    RequestHead {
        method,
        path,
        base: "",
        range: &[],
        conditionals: Conditionals::default(),
        declared_len: None,
    }
}

/// A `GET bin` carrying one well-formed range, which is the only
/// shape §5.2 admits at all.
fn ranged<'a>(path: &'a str, lines: &'a [&'a str]) -> RequestHead<'a> {
    RequestHead {
        range: lines,
        ..req("GET", path)
    }
}

/// The refusal at a server declaring `max_extent` (§13.4's two
/// profiles), as (status, token, `Allow`).
fn refused_declaring(
    head: &RequestHead<'_>,
    max_extent: Option<u32>,
) -> (u16, Option<ErrorToken>, Option<Allow>) {
    match admit_declaring(head, max_extent) {
        Ok(admitted) => panic!("expected a refusal, got {:?}", admitted.operation()),
        Err(refusal) => {
            let outcome = refusal.outcome();
            (outcome.status().as_u16(), outcome.error(), outcome.allow())
        }
    }
}

/// The admission at a server declaring `max_extent`.
fn admitted_declaring<'a>(head: &RequestHead<'a>, max_extent: Option<u32>) -> Admitted<'a> {
    match admit_declaring(head, max_extent) {
        Ok(admitted) => admitted,
        Err(refusal) => panic!(
            "expected admission, got {:?} {:?}",
            refusal.outcome().status(),
            refusal.outcome().error()
        ),
    }
}

/// The mapped `(offset, len)` a bin GET carries, at the given
/// profile.
fn mapped(head: &RequestHead<'_>, max_extent: Option<u32>) -> (u64, u32) {
    let admitted = admitted_declaring(head, max_extent);
    let Operation::GetBinRange { offset, len, .. } = admitted.operation() else {
        panic!("a bin GET is always a ranged read");
    };
    (*offset, *len)
}

/// The refusal, as (status, token, `Allow`).
fn refused(head: &RequestHead<'_>) -> (u16, Option<ErrorToken>, Option<Allow>) {
    match admit(head) {
        Ok(admitted) => panic!("expected a refusal, got {:?}", admitted.operation()),
        Err(refusal) => {
            let outcome = refusal.outcome();
            (outcome.status().as_u16(), outcome.error(), outcome.allow())
        }
    }
}

fn admitted<'a>(head: &RequestHead<'a>) -> Admitted<'a> {
    match admit(head) {
        Ok(admitted) => admitted,
        Err(refusal) => panic!(
            "expected admission, got {:?} {:?}",
            refusal.outcome().status(),
            refusal.outcome().error()
        ),
    }
}

/// §7.1's band and its derivation, asserted where a reader can RUN
/// it rather than only where the compiler evaluates it.
///
/// The `const _` block beside [`DECLARED_MAX_EXTENT`] is the gate —
/// it fails the BUILD, which is what §7.1 asks for. This is its
/// readable twin, and it earns its place by asserting the two things
/// the build assert cannot say out loud: the literal figure §7.1
/// prints, and that the value sits inside the band at BOTH ends
/// rather than merely equalling a sum.
#[test]
fn the_declared_maximum_is_the_derivation_and_inside_the_band() {
    let derived = BIN_FIXED_HEADER_LEN as u64
        + u64::from(MAX_GRAINS_PER_BIN) * BIN_INDEX_ENTRY_LEN as u64
        + BIN_TARGET_BYTES
        + u64::from(FRAME_COMP_MAX);
    assert_eq!(derived, 78_479_383, "§7.1 prints this figure normatively");
    assert_eq!(u64::from(DECLARED_MAX_EXTENT), derived);
    // The band, both ends. The floor IS the declaration,
    // so the lower assertion is an equality; the upper
    // is the one that could ever be false on its own.
    assert_eq!(u64::from(DECLARED_MAX_EXTENT), 78_479_383, "§7.1's floor");
    assert!(
        u64::from(DECLARED_MAX_EXTENT) <= BIN_MAX_BYTES,
        "§7.1's ceiling"
    );
}

/// **The packer coordination, at the one site that sees both
/// numbers.** `granary-core` holds the client's bin-close target and
/// this crate holds the server's ingest ceiling; the `const _` beside
/// [`INGEST_UNPACKED_SUM_MAX`] binds the headroom between them, and
/// this row asserts the thing that headroom is FOR — that the
/// planner cannot emit a bin this server would refuse, on the input
/// where an uncoordinated planner does.
///
/// **The witness is the reachable worst case, not a contrived one.**
/// A highly compressible file — a preallocated journal, a sparse
/// image, a big log — chunks into maximal grains that compress to a
/// couple of hundred bytes each. Five thousand of them total about a
/// megabyte COMPRESSED, so a planner closing on compressed bytes
/// alone never reaches its 64 MiB target and never reaches the
/// 65 536-frame count cap either: it emits ONE bin, whose frames
/// declare forty gibibytes. That bin is structurally legal and this
/// server refuses it — a conforming client refused for packing to
/// the policy its own library implements.
///
/// So the assertion is per-BIN and not over the input: the input is
/// deliberately over the ceiling (asserted first, or the row proves
/// nothing), and every bin the planner emits from it must be under.
#[test]
fn a_compressible_publish_never_plans_a_bin_past_the_ingest_limit() {
    // ~200 compressed bytes per maximal grain is the measured shape
    // of highly compressible content, not a round number: the
    // adversarial ratio measurement put real logs at ~10 000x.
    const COMP_LEN: u32 = 200;
    const FRAMES: usize = 5_000;

    let planned = vec![
        FramePlan {
            comp_len: COMP_LEN,
            unpacked_len: GRAIN_UNPACKED_MAX,
        };
        FRAMES
    ];

    // The input IS the reachable worst case: under the compressed
    // target, under the count cap, over the ingest ceiling.
    let compressed_total = FRAMES as u64 * u64::from(COMP_LEN);
    assert!(
        compressed_total < BIN_TARGET_BYTES,
        "the compressed-bytes close condition must never fire here, \
         or the row is testing that condition instead"
    );
    assert!(
        FRAMES < MAX_GRAINS_PER_BIN as usize,
        "the count close condition must never fire here either"
    );
    let declared_total = FRAMES as u64 * u64::from(GRAIN_UNPACKED_MAX);
    assert!(
        declared_total > INGEST_UNPACKED_SUM_MAX,
        "the whole publish must be over the ceiling, or a single bin \
         would be under it for the wrong reason"
    );

    let plans = plan_bins(&planned).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        plans.len() > 1,
        "a publish declaring {declared_total} bytes packed into {} bin(s)",
        plans.len()
    );
    for plan in &plans {
        assert!(!plan.is_empty(), "an empty bin range");
        let declared: u64 = plan
            .clone()
            .map(|i| {
                planned
                    .get(i)
                    .map_or(0, |frame| u64::from(frame.unpacked_len))
            })
            .sum();
        assert!(
            declared <= INGEST_UNPACKED_SUM_MAX,
            "the planner emitted a bin declaring {declared} bytes, which \
             this server refuses 413 + too-large (§9.2)"
        );
        // The stronger statement the headroom exists to give: the
        // packer closes at its own TARGET, four times under the
        // server ceiling, so the ceiling has room to move as policy
        // without a flag day.
        assert!(
            declared <= BIN_UNPACKED_TARGET_BYTES,
            "the planner closed a bin at {declared} bytes, past its own target"
        );
    }
}

/// §7.1's declared maximum extent: a mapped `len` past it is refused
/// WHOLE with `400` + `extent-too-wide`.
///
/// **The boundary is at the ask, not at the answer**, and the two
/// rows either side of it are what pin that: a mapped `len` of
/// exactly the declared maximum is admitted, and one byte more is
/// refused — decided from the request head, with no store consulted
/// on either side.
///
/// **The rule is not ABOUT the open-ended forms** (§7.1 says so):
/// the fully-specified rows below are refused at the same boundary,
/// which is what stops an implementation from "enforcing" this by
/// refusing `bytes=N-` and calling it done.
#[test]
fn a_mapped_len_past_the_declared_maximum_is_400_extent_too_wide() {
    let bin = format!("/bin/{HEX}");
    let e = u64::from(DECLARED_MAX_EXTENT);

    // REFUSED — every spelling whose mapped `len` exceeds the
    // declared maximum.
    let at_e_plus_one = format!("bytes=0-{e}");
    let fully_specified = format!("bytes=100-{}", 100 + e);
    let way_over = format!("bytes=0-{}", BIN_MAX_BYTES - 1);
    for value in [
        // The open-ended form: mapped `len` is u32::MAX.
        "bytes=0-",
        "bytes=100-",
        // The over-wide `last-pos` form: the same mapped `len`.
        "bytes=100-99999999999999",
        "bytes=0-18446744073709551615",
        // Fully specified, one byte over the boundary.
        at_e_plus_one.as_str(),
        // Fully specified at a non-zero offset: the bound is on the
        // LENGTH, not on the last position.
        fully_specified.as_str(),
        way_over.as_str(),
    ] {
        assert_eq!(
            refused_declaring(&ranged(&bin, &[value]), ENFORCING),
            (400, Some(ErrorToken::ExtentTooWide), None),
            "{value}: §7.1 refuses a mapped len past the declared maximum"
        );
    }

    // ADMITTED — a mapped `len` AT the declared maximum, and below
    // it. The first is the boundary row: `bytes=0-{E-1}` maps to
    // exactly `E`, which §7.1 says "is never refused by this rule
    // anywhere" — it is the whole-policy-bin read the floor buys.
    let at_e = format!("bytes=0-{}", e - 1);
    let at_e_high = format!("bytes=1000-{}", 1000 + e - 1);
    for (value, expected) in [
        (at_e.as_str(), (0_u64, DECLARED_MAX_EXTENT)),
        (at_e_high.as_str(), (1000, DECLARED_MAX_EXTENT)),
        ("bytes=0-0", (0, 1)),
        ("bytes=100-199", (100, 100)),
    ] {
        assert_eq!(
            mapped(&ranged(&bin, &[value]), ENFORCING),
            expected,
            "{value}: at or under the declared maximum is admitted"
        );
    }
}

/// **What this server ITSELF declares**, asserted through the
/// production door and nothing else.
///
/// Every other extent test drives `admit_declaring` with a maximum it
/// supplies, which proves the CHECK honours a declaration but proves
/// nothing about the declaration the shipped binary makes. That gap
/// is not hypothetical: with only those tests, replacing [`admit`]'s
/// `Some(DECLARED_MAX_EXTENT)` with `None`, or with
/// `Some(BIN_MAX_BYTES)`, left the whole suite green — the second
/// admitting the full 256 MiB extent this rule exists to refuse.
/// This is the registered class "a gate whose set the caller picks
/// is not a gate", and the `#[cfg(test)]` door §13.4 needs is what
/// opened it here.
///
/// **Both rows are load-bearing and neither alone suffices.** The
/// refusal at `E + 1` pins the declaration at or BELOW the floor —
/// any smaller declaration also refuses it. The admission at exactly
/// `E` pins it at or ABOVE — `None` also admits it. Together they
/// pin it to the floor exactly,
/// which is what this server declares.
#[test]
fn the_shipped_server_declares_exactly_the_floor() {
    let bin = format!("/bin/{HEX}");
    let e = u64::from(DECLARED_MAX_EXTENT);

    // At or BELOW the floor: one byte past it is refused, through
    // `admit` itself.
    let past = format!("bytes=0-{e}");
    assert_eq!(
        refused(&ranged(&bin, &[past.as_str()])),
        (400, Some(ErrorToken::ExtentTooWide), None),
        "the shipped server must refuse a mapped len of E + 1"
    );

    // At or ABOVE the floor: exactly the floor is admitted, and
    // mapped unchanged.
    let at = format!("bytes=0-{}", e - 1);
    let fields = [at.as_str()];
    let admitted = admitted(&ranged(&bin, &fields));
    let Operation::GetBinRange { offset, len, .. } = admitted.operation() else {
        panic!("a bin GET is always a ranged read");
    };
    assert_eq!(
        (*offset, *len),
        (0, DECLARED_MAX_EXTENT),
        "the shipped server must admit a mapped len of exactly E"
    );
}

/// §7.1's precedence, extended: form (`400`) → ceiling (`416`) →
/// declared maximum extent (`400`), and the earlier steps of §5a.6
/// still run before all three.
///
/// **The `416` rows are the load-bearing ones.** Every one of them
/// ALSO maps to a `len` past the declared maximum, so an
/// implementation that ran the extent check first would answer them
/// `400` — and §7.1 forbids exactly that: "the ceiling is a
/// permanent truth from a frozen constant that no resizing of the
/// ask can cure, so it must not be reachable only for asks a policy
/// happens to admit".
#[test]
fn the_extent_check_runs_after_the_form_and_after_the_ceiling() {
    let bin = format!("/bin/{HEX}");

    // 5 before 6 — past the ceiling AND past the declared maximum.
    let at_ceiling = format!("bytes={BIN_MAX_BYTES}-");
    let past_ceiling = format!("bytes={}-", BIN_MAX_BYTES + 1);
    let over_u64 = "bytes=18446744073709551616-";
    for value in [at_ceiling.as_str(), past_ceiling.as_str(), over_u64] {
        assert_eq!(
            refused_declaring(&ranged(&bin, &[value]), ENFORCING),
            (416, Some(ErrorToken::BadRange), None),
            "{value}: §7.1 runs the ceiling BEFORE the declared maximum"
        );
    }

    // 4 before 6 — an invalid int-range that is also over-wide.
    for value in [
        "bytes=99999999999999999999-100",
        "bytes=200-100",
        "bytes=-500",
    ] {
        assert_eq!(
            refused_declaring(&ranged(&bin, &[value]), ENFORCING),
            (400, Some(ErrorToken::BadRange), None),
            "{value}: the form check runs first, so this is bad-range"
        );
    }

    // 3 before 6 — a conditional field alongside an over-wide range.
    assert_eq!(
        refused_declaring(
            &RequestHead {
                conditionals: Conditionals {
                    fields: &["If-Range"],
                    if_none_match: None,
                },
                ..ranged(&bin, &["bytes=0-"])
            },
            ENFORCING,
        ),
        (400, Some(ErrorToken::BadRequest), None),
        "§5a.6: the conditional refusal runs before the extent check"
    );

    // 2 before 6, and 1 before 6.
    assert_eq!(
        refused_declaring(
            &RequestHead {
                range: &["bytes=0-"],
                ..req("DELETE", &bin)
            },
            ENFORCING,
        ),
        (405, Some(ErrorToken::MethodNotAllowed), Some(Allow::GetPut)),
        "§5a.6: the method runs before the extent check"
    );
    assert_eq!(
        refused_declaring(&ranged("/bin/nope", &["bytes=0-"]), ENFORCING),
        (404, Some(ErrorToken::UnknownTarget), None),
        "§5a.6: the target grammar runs before the extent check"
    );
}

/// §7.1's SHOULD, declined: a server enforcing no declared maximum
/// admits every mapped `len` §7.1's table produces, and the
/// enforcing one refuses the same rows.
///
/// **This is §13.4's declaration discipline at the admission seam:**
/// the same request is sent under both profiles, and neither
/// declaration deletes a row — one asserts the refusal, the other
/// asserts the mapping.
#[test]
fn a_server_enforcing_no_declared_maximum_admits_what_the_table_maps() {
    let bin = format!("/bin/{HEX}");
    let at_e_plus_one = format!("bytes=0-{DECLARED_MAX_EXTENT}");
    for (value, expected) in [
        ("bytes=0-", (0_u64, u32::MAX)),
        ("bytes=100-", (100, u32::MAX)),
        ("bytes=100-99999999999999", (100, u32::MAX)),
        (at_e_plus_one.as_str(), (0, DECLARED_MAX_EXTENT + 1)),
    ] {
        assert_eq!(
            mapped(&ranged(&bin, &[value]), NON_ENFORCING),
            expected,
            "{value}: a non-enforcing server maps and does not refuse"
        );
        assert_eq!(
            refused_declaring(&ranged(&bin, &[value]), ENFORCING),
            (400, Some(ErrorToken::ExtentTooWide), None),
            "{value}: the same request at an enforcing server"
        );
    }

    // The ceiling is NOT a policy and does not move with the
    // declaration: a non-enforcing server still answers `416`.
    let past_ceiling = format!("bytes={}-", BIN_MAX_BYTES + 1);
    assert_eq!(
        refused_declaring(&ranged(&bin, &[past_ceiling.as_str()]), NON_ENFORCING),
        (416, Some(ErrorToken::BadRange), None),
        "the ceiling is a frozen constant, not deployment policy"
    );
}

/// §4.2's nine rows, each reached from its own target.
#[test]
fn the_nine_operations_parse_from_their_targets() {
    let bin = format!("/bin/{HEX}");
    let meta = format!("/volume/v1/meta/{GRAIN_ID}");
    let root = "/volume/v1/root/00000000000000000042";

    assert!(matches!(
        admitted(&req("PUT", &bin)).operation(),
        Operation::PutBin { .. }
    ));
    assert!(matches!(
        admitted(&ranged(&bin, &["bytes=100-199"])).operation(),
        Operation::GetBinRange {
            offset: 100,
            len: 100,
            ..
        }
    ));
    assert!(matches!(
        admitted(&req("PUT", &meta)).operation(),
        Operation::PutMeta { volume: "v1", .. }
    ));
    assert!(matches!(
        admitted(&req("GET", &meta)).operation(),
        Operation::GetMeta { volume: "v1", .. }
    ));
    assert_eq!(
        admitted(&req("PUT", root)).operation(),
        &Operation::PutRoot {
            volume: granary_core::root::VolumeName::from_bytes(b"v1").unwrap(),
            seq: 42
        }
    );
    assert_eq!(
        admitted(&req("GET", root)).operation(),
        &Operation::GetRoot {
            volume: granary_core::root::VolumeName::from_bytes(b"v1").unwrap(),
            seq: 42
        }
    );
    assert_eq!(
        admitted(&req("GET", "/volume/v1/max-seq")).operation(),
        &Operation::MaxSeq { volume: "v1" }
    );
    assert_eq!(
        admitted(&req("GET", "/volume/v1/hint")).operation(),
        &Operation::ReadHint {
            volume: "v1",
            if_none_match: None
        }
    );
    assert_eq!(
        admitted(&req("PUT", "/volume/v1/hint")).operation(),
        &Operation::WriteHint { volume: "v1" }
    );
}

/// The resource follows from the parsed target on **all nine
/// operations**, not one per resource. §4.2's per-resource `Allow`
/// rests on this, and [`Operation::resource`] is public API an
/// adapter routes on: five rows leave four operations classified by
/// nothing, and a misfiled one there advertises another resource's
/// method set with no test able to notice.
#[test]
fn the_resource_is_derived_from_the_parsed_target() {
    let bin = format!("/bin/{HEX}");
    let meta = format!("/volume/v1/meta/{GRAIN_ID}");
    let root = "/volume/v1/root/00000000000000000000";
    let rows = [
        (req("PUT", &bin), Resource::Bin),
        (ranged(&bin, &["bytes=0-9"]), Resource::Bin),
        (req("PUT", &meta), Resource::Meta),
        (req("GET", &meta), Resource::Meta),
        (req("PUT", root), Resource::Root),
        (req("GET", root), Resource::Root),
        (req("GET", "/volume/v1/max-seq"), Resource::MaxSeq),
        (req("GET", "/volume/v1/hint"), Resource::Hint),
        (req("PUT", "/volume/v1/hint"), Resource::Hint),
    ];
    assert_eq!(rows.len(), 9, "§4.2 has nine operations");
    for (head, resource) in &rows {
        let admitted = admitted(head);
        let operation = admitted.operation();
        assert_eq!(admitted.resource(), *resource, "{operation:?}");
        // The same value off the public `Operation`, which is the
        // one an adapter outside this crate can reach.
        assert_eq!(operation.resource(), *resource, "{operation:?}");
    }
}

/// §4.3: **the parser MUST be total over degenerate targets** — an
/// empty path, `*`, `.`, `..`, `//`, non-ASCII, control bytes —
/// without panicking or indexing. Every one is `404` +
/// `unknown-target`, never `not-found`, because none of them names a
/// resource this server serves (§5.10, §8.1).
#[test]
fn the_parser_is_total_over_degenerate_targets() {
    let long = format!("/bin/{}", "a".repeat(100_000));
    let deep = format!("/volume/v1/root/{}", "/".repeat(1000));
    let targets: Vec<String> = [
        "",
        "*",
        ".",
        "..",
        "/",
        "//",
        "///",
        "/.",
        "/..",
        "/../..",
        "/bin",
        "/bin/",
        "/bin//",
        "/volume",
        "/volume/",
        "/volume/v1",
        "/volume/v1/",
        "/volume/v1/hint/",
        "/volume/v1/hint/extra",
        "/volume/v1/max-seq/",
        "/volume//hint",
        "/volume/v1//hint",
        "bin/x",
        "/BIN/x",
        "/bin/x/y/z/w/v",
        "\u{0}",
        "/bin/\u{0}",
        "/volume/v1/hint\u{0}",
        "/\u{e9}",
        "/bin/caf\u{e9}",
        "/volume/caf\u{e9}/hint",
        "/volume/v1/hint\r\nX-Injected: 1",
        "/bin/{digest}",
        "/bin/\"x\"",
        "/volume/v1/hint#frag",
        "/volume/v1/hint?q=1",
    ]
    .iter()
    .map(|t| (*t).to_owned())
    .chain([long, deep])
    .collect();

    for target in &targets {
        for method in ["GET", "PUT", "HEAD", "DELETE", "POST", "OPTIONS", ""] {
            assert_eq!(
                refused(&req(method, target)),
                (404, Some(ErrorToken::UnknownTarget), None),
                "{method} {target:?} names no §4.2 resource"
            );
        }
    }
}

/// §4.3: total means full match — no prefix match, no trimming, no
/// case folding, no normalisation, and **no percent-decoding**.
#[test]
fn every_segment_is_matched_against_its_total_grammar() {
    let upper = HEX.to_uppercase();
    let cases = [
        // {digest}: exactly 64 lowercase hex.
        format!("/bin/{}", &HEX[..63]),
        format!("/bin/{HEX}a"),
        format!("/bin/{upper}"),
        format!("/bin/{GRAIN_ID}"),
        format!("/bin/{HEX}#"),
        format!("/bin/%2F{}", &HEX[2..]),
        // {grain-id}: exactly `blake3:` + 64 lowercase hex.
        format!("/volume/v1/meta/{HEX}"),
        format!("/volume/v1/meta/sha256:{HEX}"),
        format!("/volume/v1/meta/BLAKE3:{HEX}"),
        format!("/volume/v1/meta/blake3:{upper}"),
        format!("/volume/v1/meta/blake3:{}", &HEX[..63]),
        // {volume}: a DNS-1123 label.
        format!("/volume/V1/meta/{GRAIN_ID}"),
        format!("/volume/-v/meta/{GRAIN_ID}"),
        format!("/volume/v-/meta/{GRAIN_ID}"),
        format!("/volume/v.1/meta/{GRAIN_ID}"),
        format!("/volume/v_1/meta/{GRAIN_ID}"),
        format!("/volume/{}/hint", "v".repeat(64)),
        "/volume//hint".to_owned(),
        // {seq}: exactly 20 ASCII digits fitting a u64.
        "/volume/v1/root/42".to_owned(),
        "/volume/v1/root/0000000000000000042".to_owned(),
        "/volume/v1/root/000000000000000000042".to_owned(),
        "/volume/v1/root/9999999999999999999999".to_owned(),
        // 20 digits, over u64::MAX — a grammar failure, not a
        // separate status (§4.3).
        "/volume/v1/root/99999999999999999999".to_owned(),
        "/volume/v1/root/18446744073709551616".to_owned(),
        "/volume/v1/root/+0000000000000000042".to_owned(),
        "/volume/v1/root/0000000000000000-42".to_owned(),
        // Literals, byte for byte.
        "/volume/v1/MAX-SEQ".to_owned(),
        "/volume/v1/max_seq".to_owned(),
        "/volume/v1/HINT".to_owned(),
        format!("/volume/v1/META/{GRAIN_ID}"),
    ];
    for target in &cases {
        assert_eq!(
            refused(&req("GET", target)).0,
            404,
            "{target:?} must fail its total grammar"
        );
    }

    // The boundaries the cases above bracket, admitted.
    assert!(admit(&req("GET", &format!("/volume/{}/hint", "v".repeat(63)))).is_ok());
    assert!(admit(&req("GET", "/volume/a/hint")).is_ok());
    assert!(admit(&req("GET", "/volume/a-b/hint")).is_ok());
    assert!(admit(&req("GET", "/volume/v1/root/18446744073709551615")).is_ok());
    assert!(
        admit(&req("GET", "/volume/v1/root/00000000000000000000")).is_ok(),
        "§4.3: the grammar accepts seq 0 AT THE KEY; only max-seq and \
         the hint exclude it"
    );
}

/// §4.4: **the reserved registry is an ADMISSION rule, and every
/// endpoint serves a reserved volume normally.** "granary itself must
/// stay able to mint `gran-*` names. A server that applied the
/// registry at key construction … would refuse granary's own future
/// volumes and would change a frozen accept set." The registry binds
/// volume CREATION only, which v1 leaves to the client (§4.4).
///
/// Pinned rather than left structural: `is_reserved_volume_name` is a
/// public function in `granary-core`, one import and one `&&` away
/// from [`is_volume`], and adding it there leaves the rest of this
/// suite green.
///
/// (`gran-` and `xn--` are not themselves DNS-1123 labels — both end
/// in `-` — so the rows below are the shortest legal reserved names.)
#[test]
fn a_reserved_volume_is_served_normally_on_every_endpoint() {
    for volume in ["gran-a", "gran-reserved", "gran-golden", "xn--abc"] {
        let meta = format!("/volume/{volume}/meta/{GRAIN_ID}");
        let root = format!("/volume/{volume}/root/00000000000000000001");
        let max_seq = format!("/volume/{volume}/max-seq");
        let hint = format!("/volume/{volume}/hint");
        let rows = [
            ("GET", meta.as_str()),
            ("PUT", meta.as_str()),
            ("GET", root.as_str()),
            ("PUT", root.as_str()),
            ("GET", max_seq.as_str()),
            ("GET", hint.as_str()),
            ("PUT", hint.as_str()),
        ];
        for (method, target) in rows {
            assert!(
                admit(&req(method, target)).is_ok(),
                "§4.4: {method} {target} MUST be served normally — the \
                 registry binds volume CREATION, never key construction"
            );
        }
    }
}

/// §4.2: `HEAD` is `405` on **all five** resources, and no `Allow`
/// names it.
#[test]
fn head_is_405_on_every_resource_and_no_allow_names_it() {
    let bin = format!("/bin/{HEX}");
    let meta = format!("/volume/v1/meta/{GRAIN_ID}");
    let rows = [
        (bin.as_str(), Allow::GetPut),
        (meta.as_str(), Allow::GetPut),
        ("/volume/v1/root/00000000000000000001", Allow::GetPut),
        ("/volume/v1/max-seq", Allow::Get),
        ("/volume/v1/hint", Allow::GetPut),
    ];
    assert_eq!(rows.len(), 5, "§4.2's Allow table has five rows");
    for (target, allow) in rows {
        let (status, token, advertised) = refused(&req("HEAD", target));
        assert_eq!(status, 405, "{target}");
        assert_eq!(token, Some(ErrorToken::MethodNotAllowed), "{target}");
        assert_eq!(advertised, Some(allow), "{target}");
        assert!(
            !allow.as_str().contains("HEAD"),
            "§4.2: a server MUST NOT advertise a method it answers 405"
        );
    }
}

/// §4.2: the `405`'s `Allow` is a property of the PARSED TARGET and
/// is not something a caller can supply. `Refusal` has no public
/// constructor, so the only route to a `405` is through this gate —
/// and the value it carries varies with the target, which a
/// hand-picked constant could not do.
#[test]
fn the_405_advertises_the_parsed_resources_own_allow() {
    for method in ["HEAD", "DELETE", "POST", "OPTIONS", "TRACE", "PATCH", "get"] {
        assert_eq!(
            refused(&req(method, "/volume/v1/max-seq")).2,
            Some(Allow::Get),
            "max-seq is READ-ONLY: advertising PUT on it is the failure \
             this derivation exists to prevent"
        );
        assert_eq!(
            refused(&req(method, "/volume/v1/hint")).2,
            Some(Allow::GetPut)
        );
    }
    // The one method §4.2 defines somewhere but not here.
    let (status, token, allow) = refused(&req("PUT", "/volume/v1/max-seq"));
    assert_eq!((status, token), (405, Some(ErrorToken::MethodNotAllowed)));
    assert_eq!(allow, Some(Allow::Get));
}

/// §5a.6: "Target grammar first (`404`), then method (`405`), then
/// this refusal (`400`)". Each pair below qualifies for two answers
/// and the order decides which.
#[test]
fn the_five_checks_run_in_section_5a6s_order() {
    let bin = format!("/bin/{HEX}");
    let conditional = Conditionals {
        if_none_match: None,
        fields: &["If-Match"],
    };

    // 1 before 2: a malformed target with a method no resource
    // defines is `404`, not `405`.
    assert_eq!(refused(&req("DELETE", "/bin/nope")).0, 404);
    // 1 before 3: "one on a malformed target is `404`".
    assert_eq!(
        refused(&RequestHead {
            conditionals: conditional,
            ..req("GET", "/bin/nope")
        })
        .0,
        404
    );
    // 2 before 3: "a conditional field on `DELETE bin/{d}` is `405`".
    let (status, token, allow) = refused(&RequestHead {
        conditionals: conditional,
        ..req("DELETE", &bin)
    });
    assert_eq!(
        (status, token, allow),
        (405, Some(ErrorToken::MethodNotAllowed), Some(Allow::GetPut))
    );
    // 3 before 4: a refused conditional on a bin GET with NO `Range`
    // is `400` + `bad-request`, never `400` + `bad-range`. Same
    // status, different token — which is why a status-only assertion
    // cannot see this ordering at all.
    assert_eq!(
        refused(&RequestHead {
            conditionals: conditional,
            ..req("GET", &bin)
        }),
        (400, Some(ErrorToken::BadRequest), None)
    );
    // 3 before 5: and with a range past the ceiling, still the
    // conditional's `400` rather than the `416`.
    assert_eq!(
        refused(&RequestHead {
            conditionals: conditional,
            range: &["bytes=268435456-268435500"],
            ..req("GET", &bin)
        }),
        (400, Some(ErrorToken::BadRequest), None)
    );
    // 4 before 5: §7.1's own worked example. `last-pos` below
    // `first-pos` AND a `first-pos` past the ceiling — form first, so
    // `400`, not `416`.
    assert_eq!(
        refused(&ranged(&bin, &["bytes=99999999999999999999-100"])),
        (400, Some(ErrorToken::BadRange), None)
    );
    // That example discriminates the two orders on its own: §7.1's
    // ceiling "covers a `first-pos` too large to fit a `u64` at
    // all", so a ceiling-first implementation has an answer for it
    // and that answer is `416`. The rows below discriminate without
    // relying on that — every `first-pos` in them is past the
    // ceiling AND fits a `u64`.
    let past = BIN_MAX_BYTES + 1;
    let reversed = format!("bytes={past}-100");
    let multi_first = format!("bytes={past}-,0-9");
    let multi_second = format!("bytes=0-9,{past}-");
    let bad_last = format!("bytes={past}-notanumber");
    for value in [&reversed, &multi_first, &multi_second, &bad_last] {
        assert_eq!(
            refused(&ranged(&bin, &[value.as_str()])),
            (400, Some(ErrorToken::BadRange), None),
            "{value}: §7.1 runs the FORM check first, so this is 400 and \
             not 416"
        );
    }
    // And two `Range` field lines, the second of which is past the
    // ceiling: the field-line count is part of the form.
    assert_eq!(
        refused(&ranged(&bin, &["bytes=0-9", multi_second.as_str()])),
        (400, Some(ErrorToken::BadRange), None)
    );
    // A joined field value is refused by the SAME rule, so an adapter
    // that combines two lines per RFC 9110 §5.3 rather than passing
    // both cannot widen the accept set either.
    assert_eq!(
        refused(&ranged(&bin, &["bytes=0-9, bytes=100-199"])),
        (400, Some(ErrorToken::BadRange), None)
    );
}

/// §5a.6's order on the four pairs the corpus above cannot reach,
/// because it drives targets and methods and ranges **separately**: a
/// malformed target, or a refused method, arriving WITH a `Range`
/// field. Each request below qualifies for two answers and only the
/// order decides which.
///
/// The full triple is asserted rather than the status, and on two of
/// these rows that is the whole test: §7.1's `bad-range` and §5a.6's
/// `bad-request` are both `400`, and §4.2's `405` is worthless
/// without the `Allow` it must carry.
#[test]
fn the_range_checks_run_after_the_target_and_the_method() {
    let bin = format!("/bin/{HEX}");
    let past_ceiling = format!("bytes={}-", BIN_MAX_BYTES + 1);

    // 1 before 4 — malformed target, unparseable range. §4.3's `404`
    // + `unknown-target`; a form check running first says `400` +
    // `bad-range`.
    assert_eq!(
        refused(&ranged("/bin/nope", &["garbage"])),
        (404, Some(ErrorToken::UnknownTarget), None),
        "§5a.6: the target grammar runs before the range form"
    );
    // 1 before 5 — malformed target, `first-pos` past the ceiling.
    // Still `404`; a ceiling check running first says `416`.
    assert_eq!(
        refused(&ranged("/bin/nope", &[past_ceiling.as_str()])),
        (404, Some(ErrorToken::UnknownTarget), None),
        "§5a.6: the target grammar runs before the ceiling"
    );
    // 2 before 4 — the target parses, the method does not, and the
    // range is unparseable. §4.2's `405` carrying the bin's own
    // `Allow`; a form check running first says `400` + `bad-range`.
    assert_eq!(
        refused(&RequestHead {
            range: &["garbage"],
            ..req("DELETE", &bin)
        }),
        (405, Some(ErrorToken::MethodNotAllowed), Some(Allow::GetPut)),
        "§5a.6: the method runs before the range form"
    );
    // 2 before 5 — the same, with a `first-pos` past the ceiling.
    // Still `405`; a ceiling check running first says `416`.
    assert_eq!(
        refused(&RequestHead {
            range: &[past_ceiling.as_str()],
            ..req("DELETE", &bin)
        }),
        (405, Some(ErrorToken::MethodNotAllowed), Some(Allow::GetPut)),
        "§5a.6: the method runs before the ceiling"
    );
}

/// §5a.6: the exemption is ONE (field, resource, method) triple.
#[test]
fn exactly_one_conditional_request_is_exempt() {
    let bin = format!("/bin/{HEX}");
    let meta = format!("/volume/v1/meta/{GRAIN_ID}");
    let inm = Conditionals {
        if_none_match: Some("\"v7\""),
        fields: &["If-None-Match"],
    };

    // The exempt triple.
    assert_eq!(
        admitted(&RequestHead {
            conditionals: inm,
            ..req("GET", "/volume/v1/hint")
        })
        .operation(),
        &Operation::ReadHint {
            volume: "v1",
            if_none_match: Some("\"v7\"")
        },
        "the VALUE reaches the operation — a presence flag would make \
         §5.8's 304 unimplementable"
    );

    // Same field, wrong method.
    assert_eq!(
        refused(&RequestHead {
            conditionals: inm,
            ..req("PUT", "/volume/v1/hint")
        }),
        (400, Some(ErrorToken::BadRequest), None)
    );
    // Same field, wrong resource.
    for target in [
        bin.as_str(),
        meta.as_str(),
        "/volume/v1/root/00000000000000000001",
        "/volume/v1/max-seq",
    ] {
        let head = RequestHead {
            conditionals: inm,
            range: if target == bin { &["bytes=0-9"] } else { &[] },
            ..req("GET", target)
        };
        assert_eq!(
            refused(&head),
            (400, Some(ErrorToken::BadRequest), None),
            "{target}: §5a.6 refuses If-None-Match outside the hint's GET"
        );
    }
    // Right resource and method, wrong field — including alongside
    // the exempt one.
    for conditionals in [
        Conditionals {
            if_none_match: None,
            fields: &["If-Match"],
        },
        Conditionals {
            if_none_match: Some("\"v7\""),
            fields: &["If-None-Match", "If-Match"],
        },
    ] {
        assert_eq!(
            refused(&RequestHead {
                conditionals,
                ..req("GET", "/volume/v1/hint")
            }),
            (400, Some(ErrorToken::BadRequest), None),
            "§5a.6: If-Match on GET hint is refused"
        );
    }
}

/// §5a.6 fixes the conditional field SET at five names, and **this
/// gate holds it rather than taking it**: the head carries the field
/// names the request arrived with and `admit` matches them, so an
/// adapter that never learned about `If-Range` cannot narrow the set
/// by omission. A presence `bool` computed by the adapter would leave
/// no input to `admit` that told such an adapter apart from a request
/// carrying no conditional at all.
#[test]
fn the_conditional_field_set_is_decided_here_and_not_by_the_caller() {
    let bin = format!("/bin/{HEX}");
    let five = [
        "If-Match",
        "If-None-Match",
        "If-Modified-Since",
        "If-Unmodified-Since",
        "If-Range",
    ];
    assert_eq!(five.len(), 5, "§5a.6 names five conditional fields");

    for field in five {
        // RFC 9110 §5.1: a field name is case-insensitive, so all
        // three spellings are one field and all three are refused.
        for spelling in [field.to_owned(), field.to_lowercase(), field.to_uppercase()] {
            let names = [spelling.as_str()];
            let conditionals = Conditionals {
                if_none_match: None,
                fields: &names,
            };
            // A bin GET carrying a perfectly good range: step 3 still
            // decides, and it decides `bad-request`, not `bad-range`.
            assert_eq!(
                refused(&RequestHead {
                    range: &["bytes=0-9"],
                    conditionals,
                    ..req("GET", &bin)
                }),
                (400, Some(ErrorToken::BadRequest), None),
                "{spelling} on GET bin: §5a.6 refuses on the NAME, with no \
                 value read"
            );
            // On the exempt resource AND method, exactly one of the
            // five is exempt — and `If-Range` is the one a stale
            // field list drops.
            let head = RequestHead {
                conditionals,
                ..req("GET", "/volume/v1/hint")
            };
            if field == "If-None-Match" {
                assert!(
                    admit(&head).is_ok(),
                    "{spelling}: the exempt (field, resource, method) triple"
                );
            } else {
                assert_eq!(
                    refused(&head),
                    (400, Some(ErrorToken::BadRequest), None),
                    "{spelling} on GET hint is outside the exemption"
                );
            }
        }
    }

    // Names OUTSIDE the five change nothing — including the fields
    // every real request carries, and near-misses of the five.
    let ordinary = [
        "Host",
        "User-Agent",
        "Content-Length",
        "Range",
        "Accept",
        "If-Something-Else",
        "Notif-Match",
        "if-match-not",
        "",
    ];
    assert!(
        admit(&RequestHead {
            conditionals: Conditionals {
                if_none_match: None,
                fields: &ordinary,
            },
            ..req("PUT", "/volume/v1/hint")
        })
        .is_ok(),
        "only §5a.6's five names decide; every other field is ordinary"
    );
}

/// The rest of §5a.6 against the field names the head carries: the
/// exemption still admits, a second conditional beside it still
/// refuses, a value arriving without its name is still a field that
/// arrived, and none of it disturbs the order steps 1 and 2 run in.
#[test]
fn a_conditional_field_name_changes_nothing_else_about_section_5a6() {
    let bin = format!("/bin/{HEX}");

    // The exempt triple survives the ordinary names around it, and
    // the VALUE still reaches the operation.
    let with_exempt = ["Host", "If-None-Match", "Accept"];
    assert_eq!(
        admitted(&RequestHead {
            conditionals: Conditionals {
                if_none_match: Some("\"v7\""),
                fields: &with_exempt,
            },
            ..req("GET", "/volume/v1/hint")
        })
        .operation(),
        &Operation::ReadHint {
            volume: "v1",
            if_none_match: Some("\"v7\"")
        }
    );
    // A second conditional alongside the exempt one is still refused.
    let two = ["If-None-Match", "If-Range"];
    assert_eq!(
        refused(&RequestHead {
            conditionals: Conditionals {
                if_none_match: Some("\"v7\""),
                fields: &two,
            },
            ..req("GET", "/volume/v1/hint")
        }),
        (400, Some(ErrorToken::BadRequest), None)
    );
    // The other direction of the same guard: a VALUE handed over
    // without its name among the fields is still a field that
    // arrived, and outside the exemption it is still refused.
    assert_eq!(
        refused(&RequestHead {
            conditionals: Conditionals {
                if_none_match: Some("\"v7\""),
                fields: &[],
            },
            ..req("PUT", "/volume/v1/hint")
        }),
        (400, Some(ErrorToken::BadRequest), None)
    );

    // And §5a.6's order is unchanged by where the refusal's evidence
    // comes from: the target and then the method still decide first.
    let if_range = ["If-Range"];
    let conditionals = Conditionals {
        if_none_match: None,
        fields: &if_range,
    };
    assert_eq!(
        refused(&RequestHead {
            conditionals,
            ..req("GET", "/bin/nope")
        }),
        (404, Some(ErrorToken::UnknownTarget), None)
    );
    assert_eq!(
        refused(&RequestHead {
            conditionals,
            ..req("DELETE", &bin)
        }),
        (405, Some(ErrorToken::MethodNotAllowed), Some(Allow::GetPut))
    );
}

/// §7.1's table, row for row.
///
/// **The table is a MAPPING claim, and the declared maximum extent
/// is a later step that does not change it** (§7.1 fixes the order:
/// the bound binds "the value the table above produces, *after* its
/// `u32::MAX` clamp"). So every row's mapping is asserted at a
/// server enforcing no maximum, where step 6 cannot mask it — and
/// the rows the shipped server's own declaration then refuses are
/// asserted refused, in the same loop, from the same table. Reading
/// the mapping off the production door alone would leave the four
/// clamped rows untestable, which is how enforcement would come to
/// look like a change to the table it is not.
#[test]
fn the_four_range_forms_map_exactly() {
    let bin = format!("/bin/{HEX}");
    let accepted = [
        ("bytes=100-199", 100_u64, 100_u32),
        ("bytes=0-0", 0, 1),
        ("bytes=0-9", 0, 10),
        // Open-ended: len clamped to u32::MAX, answered by the short
        // read — and, at this server's declaration, refused by step
        // 6 before any short read happens (§7.1).
        ("bytes=100-", 100, u32::MAX),
        ("bytes=0-", 0, u32::MAX),
        // Over-wide last-pos: identical to the open-ended form,
        // including the refusal.
        ("bytes=100-99999999999999", 100, u32::MAX),
        ("bytes=0-18446744073709551615", 0, u32::MAX),
        // The range unit is a case-insensitive token (RFC 9110
        // §16.5.1); nothing else about the value is folded.
        ("BYTES=1-2", 1, 2),
        // 1*DIGIT admits leading zeros.
        ("bytes=0000000100-0000000199", 100, 100),
    ];
    for (value, offset, len) in accepted {
        assert_eq!(
            mapped(&ranged(&bin, &[value]), NON_ENFORCING),
            (offset, len),
            "{value}: §7.1's table maps this row"
        );
        // The same row at the shipped server, whose declaration is
        // §7.1's floor: admitted with the IDENTICAL mapping when the
        // ask fits, refused whole when it does not.
        if len <= DECLARED_MAX_EXTENT {
            assert_eq!(
                mapped(&ranged(&bin, &[value]), ENFORCING),
                (offset, len),
                "{value}: step 6 must not disturb a mapping it admits"
            );
        } else {
            assert_eq!(
                refused_declaring(&ranged(&bin, &[value]), ENFORCING),
                (400, Some(ErrorToken::ExtentTooWide), None),
                "{value}: mapped len {len} is past the declared maximum"
            );
        }
    }
}

/// §7.1 over numerals **no `u64` holds**, which the table above
/// cannot reach and which the section answers in three different
/// ways.
///
/// Each answer is a rule stated elsewhere in §7.1 applied to a wider
/// numeral, not a new rule:
///
/// - an over-wide `last-pos` is "accepted, identically to the
///   open-ended form". The table's own example fits a `u64`, and
///   nothing in the rule restricts it to those — RFC 9110 §14.1.2
///   makes any `last-pos` at or above the representation's length
///   mean the remainder, which every over-`u64` numeral is.
/// - the ceiling rule "covers a `first-pos` too large to fit a `u64`
///   at all", so that position is the `416` §7.3 defines and not a
///   `400`: the form was accepted and the range is provably
///   unsatisfiable from a frozen constant.
/// - the FORM check still runs first, and it compares two POSITIONS
///   rather than two `u64`s — so a `last-pos` below a `first-pos` is
///   `400` however wide either numeral is.
///
/// **A numeral that wraps or saturates fails this test in both
/// directions**, which is what it is for: a wrapped `first-pos`
/// would admit `bytes=18446744073709551616-` at offset 0, and a
/// wrapped `last-pos` would turn every over-wide row into an invalid
/// int-range.
#[test]
fn a_numeral_wider_than_a_u64_is_still_matched_against_section_7_1() {
    let bin = format!("/bin/{HEX}");

    // ACCEPTED — over-wide `last-pos`, identical to the open-ended
    // form. `first-pos` fits, so the ceiling does not fire. Asserted
    // at a server enforcing no maximum for the reason
    // `the_four_range_forms_map_exactly` gives: the claim here is
    // about the MAPPING of a wide numeral, and at the shipped
    // server step 6 refuses every one of these before the mapping
    // is observable. The refusal is asserted immediately below, so
    // no row leaves the test.
    for (value, expected) in [
        ("bytes=100-18446744073709551616", 100_u64),
        ("bytes=100-99999999999999999999999999999999999999", 100),
        ("bytes=0-18446744073709551616", 0),
        // Leading zeros are `1*DIGIT` and change no value.
        ("bytes=0000000100-000018446744073709551616", 100),
    ] {
        assert_eq!(
            mapped(&ranged(&bin, &[value]), NON_ENFORCING),
            (expected, u32::MAX),
            "{value}: §7.1 makes an over-wide last-pos the open-ended form"
        );
        assert_eq!(
            refused_declaring(&ranged(&bin, &[value]), ENFORCING),
            (400, Some(ErrorToken::ExtentTooWide), None),
            "{value}: u32::MAX is past every declared maximum (§7.1)"
        );
    }

    // `416` — the form is accepted and the `first-pos` fits no
    // `u64`, so §7.1's ceiling covers it.
    for value in [
        "bytes=18446744073709551616-",
        "bytes=99999999999999999999999999999999999999-",
        // Both positions over, `last-pos` at or above `first-pos`:
        // the form check passes and the ceiling decides.
        "bytes=18446744073709551616-18446744073709551617",
        "bytes=18446744073709551616-18446744073709551616",
        // Leading zeros do not make a numeral fit.
        "bytes=00000000000018446744073709551616-",
    ] {
        assert_eq!(
            refused(&ranged(&bin, &[value])),
            (416, Some(ErrorToken::BadRange), None),
            "{value}: §7.1's ceiling covers a first-pos too large for a u64"
        );
    }

    // `400` — the FORM check runs first, and it decides at every
    // width.
    for value in [
        // §7.1's own worked example: `last-pos` fits, `first-pos`
        // does not.
        "bytes=99999999999999999999-100",
        "bytes=18446744073709551616-18446744073709551615",
        // Both positions over `u64`, `last-pos` below `first-pos`.
        "bytes=18446744073709551617-18446744073709551616",
        "bytes=99999999999999999999999999999999999999-18446744073709551616",
        // Same, with the widths equal so only the digits separate
        // them.
        "bytes=99999999999999999999-99999999999999999998",
        // Leading zeros do not hide the order either.
        "bytes=000000000000000000000100-000000000000000000000099",
        // An over-`u64` numeral must still be `1*DIGIT` to be
        // over-wide at all.
        "bytes=100-notanumber",
        "bytes=100-1844674407370955161x",
        "bytes=100-18446744073709551616 ",
        "bytes=+18446744073709551616-",
        "bytes=-18446744073709551616",
    ] {
        assert_eq!(
            refused(&ranged(&bin, &[value])),
            (400, Some(ErrorToken::BadRange), None),
            "{value}: §7.1 runs the FORM check first, at every numeral width"
        );
    }
}

/// §7.1: every form v1 does not accept, and every malformation, is
/// `400` + `bad-range` — including an ABSENT field, because a bin
/// `GET` has no unranged form (§5.2, §12).
#[test]
fn a_range_form_v1_does_not_accept_is_400_bad_range() {
    let bin = format!("/bin/{HEX}");
    // Absent.
    assert_eq!(
        refused(&req("GET", &bin)),
        (400, Some(ErrorToken::BadRange), None)
    );
    let rejected = [
        // Suffix-range, `bytes=-0` included (§7.1's two deviations).
        "bytes=-500",
        "bytes=-0",
        "bytes=-",
        // More than one range-spec.
        "bytes=0-9,20-29",
        "bytes=0-9,",
        "bytes=,0-9",
        // Invalid int-range.
        "bytes=10-9",
        "bytes=1-0",
        // Not a ranges-specifier at all.
        "",
        "bytes",
        "bytes=",
        "bytes=100",
        "100-199",
        "items=0-9",
        "bytes 0-9",
        "bytes==0-9",
        // No trimming: OWS is not in the grammar for a single
        // element.
        "bytes= 100-199",
        "bytes=100 -199",
        "bytes=100- 199",
        " bytes=100-199",
        // Not 1*DIGIT.
        "bytes=+100-199",
        "bytes=-100-199",
        "bytes=0x10-0x20",
        "bytes=1e3-2e3",
        "bytes=100-19a",
        // Arbitrarily long numerals are NEVER wrapped (RFC 9110
        // §14.1.2, §9.1 item 2), and §7.1 does not answer them all
        // the same way — the rows here are the ones the FORM check
        // refuses, and
        // `a_numeral_wider_than_a_u64_is_still_matched_against_section_7_1`
        // carries the accepted and `416` halves.
        "bytes=18446744073709551617-18446744073709551616",
        "bytes=99999999999999999999999999999999999999-0",
    ];
    for value in rejected {
        assert_eq!(
            refused(&ranged(&bin, &[value])),
            (400, Some(ErrorToken::BadRange), None),
            "{value:?}"
        );
    }
}

/// More than one `Range` FIELD LINE is `400`, and this is the case a
/// `HeaderMap::get` in an adapter would have hidden: the first line
/// alone is a perfectly valid range.
#[test]
fn more_than_one_range_field_line_is_400_bad_range() {
    let bin = format!("/bin/{HEX}");
    for lines in [
        &["bytes=0-9", "bytes=100-199"][..],
        &["bytes=0-9", "bytes=0-9"][..],
        &["bytes=0-9", "garbage"][..],
        &["garbage", "bytes=0-9"][..],
        &["bytes=0-9", "bytes=10-19", "bytes=20-29"][..],
    ] {
        assert_eq!(
            refused(&ranged(&bin, lines)),
            (400, Some(ErrorToken::BadRange), None),
            "{lines:?}"
        );
    }
}

/// §6: "a server receiving one MUST ignore it and answer in full".
/// Ranges are meaningful only on `GET bin`, so everywhere else a
/// `Range` — even an unparseable one — changes nothing.
#[test]
fn a_range_is_ignored_everywhere_but_a_bin_get() {
    let bin = format!("/bin/{HEX}");
    let meta = format!("/volume/v1/meta/{GRAIN_ID}");
    let hostile = ["bytes=-0", "garbage", "bytes=0-9,20-29"];
    let elsewhere = [
        ("PUT", bin.as_str()),
        ("GET", meta.as_str()),
        ("PUT", meta.as_str()),
        ("GET", "/volume/v1/root/00000000000000000001"),
        ("PUT", "/volume/v1/root/00000000000000000001"),
        ("GET", "/volume/v1/max-seq"),
        ("GET", "/volume/v1/hint"),
        ("PUT", "/volume/v1/hint"),
    ];
    for (method, target) in elsewhere {
        for value in hostile {
            let head = RequestHead {
                range: &[value],
                ..req(method, target)
            };
            assert!(
                admit(&head).is_ok(),
                "{method} {target} with Range: {value} must be ADMITTED — \
                 §6 ignores the field here rather than refusing it"
            );
        }
        // Two field lines are equally ignored off the bin GET.
        let head = RequestHead {
            range: &["bytes=0-9", "bytes=10-19"],
            ..req(method, target)
        };
        assert!(admit(&head).is_ok(), "{method} {target}");
    }
}

/// §7.1/§7.3: `first-pos` at or past `BIN_MAX_BYTES` is `416`,
/// decided from a frozen constant before any store is touched. The
/// byte below the ceiling is not.
#[test]
fn the_ceiling_is_416_and_only_the_ceiling_is() {
    let bin = format!("/bin/{HEX}");
    let at = format!("bytes={BIN_MAX_BYTES}-");
    let past = format!("bytes={}-", BIN_MAX_BYTES + 1);
    let way_past = format!("bytes={}-{}", u64::MAX - 1, u64::MAX);
    let closed = format!("bytes={BIN_MAX_BYTES}-{}", BIN_MAX_BYTES + 10);
    for value in [&at, &past, &way_past, &closed] {
        assert_eq!(
            refused(&ranged(&bin, &[value.as_str()])),
            (416, Some(ErrorToken::BadRange), None),
            "{value}"
        );
    }
    // The last byte below the ceiling is still a form v1 accepts,
    // and asserting THAT is the point of the row — it is what makes
    // the rows above a statement about the ceiling rather than about
    // ranges in general. It is asserted at a server enforcing no
    // maximum, because this spelling is open-ended: at the shipped
    // server step 6 refuses it, and a bare `is_ok()` there would
    // stop discriminating the moment the ceiling moved.
    let below = format!("bytes={}-", BIN_MAX_BYTES - 1);
    assert!(
        admit_declaring(&ranged(&bin, &[below.as_str()]), NON_ENFORCING).is_ok(),
        "the last byte below the ceiling is still a form v1 accepts"
    );
    // And at the shipped server it is `400` + `extent-too-wide` —
    // NOT the `416` this test exists to fence in. A `first-pos`
    // below the ceiling never earns a `416`, whatever its length.
    assert_eq!(
        refused(&ranged(&bin, &[below.as_str()])),
        (400, Some(ErrorToken::ExtentTooWide), None),
        "below the ceiling is never 416, and this width is step 6's"
    );
}

/// §5a.2 and §13.2 item 5: a declared length is advisory. It is
/// carried and never acted on, so no value of it changes an answer.
#[test]
fn declared_len_never_decides_anything() {
    let bin = format!("/bin/{HEX}");
    for declared in [
        None,
        Some(0),
        Some(1),
        Some(u64::MAX),
        Some(BIN_MAX_BYTES + 1),
    ] {
        assert!(
            admit(&RequestHead {
                declared_len: declared,
                ..req("PUT", &bin)
            })
            .is_ok(),
            "{declared:?}: admit must not refuse on a declared length"
        );
    }
}

/// §4.1: `{base}` MAY carry a path, targets are formed by
/// concatenation, and a server MUST NOT require any other segment.
#[test]
fn the_configured_base_is_stripped_and_nothing_else_is() {
    let head = RequestHead {
        base: "/grain/v1",
        ..req("GET", "/grain/v1/volume/v1/hint")
    };
    assert_eq!(
        admitted(&head).operation(),
        &Operation::ReadHint {
            volume: "v1",
            if_none_match: None
        }
    );
    // A target outside the base is not one of §4.2's resources —
    // `unknown-target` and never `not-found`, which is what stops a
    // client whose base carries the wrong prefix reading a populated
    // volume as empty (§8.1, §13.2 item 1).
    for path in [
        "/volume/v1/hint",
        "/grain/volume/v1/hint",
        "/grain/v2/volume/v1/hint",
        "/grain/v1x/volume/v1/hint",
        "/grain/v1volume/v1/hint",
        "x/grain/v1/volume/v1/hint",
    ] {
        assert_eq!(
            refused(&RequestHead {
                base: "/grain/v1",
                ..req("GET", path)
            }),
            (404, Some(ErrorToken::UnknownTarget), None),
            "{path}"
        );
    }
}

/// A server with no authority configured is Phase 1 byte for byte
/// (§1, §4.2): both authority targets fail the target grammar and
/// answer `404` + `unknown-target` on every method, `POST` included,
/// before any method check.
#[test]
fn without_an_authority_both_authority_targets_are_unknown() {
    for path in ["/volume/vol/publish", "/volume/vol/status"] {
        for method in ["POST", "GET", "PUT", "HEAD", "DELETE"] {
            assert_eq!(
                refused(&req(method, path)),
                (404, Some(ErrorToken::UnknownTarget), None),
                "{method} {path}: no control target exists without an authority"
            );
        }
    }
}

#[test]
fn intent_resources_method_grammar_and_conditional_order() {
    use super::admit_authority;
    let mut cases = 0;
    for (suffix, allowed) in [
        ("intent", &["GET", "POST"][..]),
        ("intent/release", &["POST"][..]),
        ("intent/ownership", &["POST"][..]),
    ] {
        let path = format!("/volume/v/{suffix}");
        for method in [
            "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE", "other",
        ] {
            let head = req(method, &path);
            let no_authority = admit_authority(&head, ENFORCING, false)
                .unwrap_err()
                .into_outcome();
            assert_eq!(
                (no_authority.status().as_u16(), no_authority.error()),
                (404, Some(ErrorToken::UnknownTarget))
            );
            let result = admit_authority(&head, ENFORCING, true);
            if allowed.contains(&method) {
                assert!(
                    matches!(
                        result.as_ref().map(super::Admitted::operation),
                        Ok(Operation::Intent { .. })
                    ),
                    "{method} {suffix}: got {:?}",
                    result
                        .as_ref()
                        .err()
                        .map(|r| (r.outcome().status().as_u16(), r.outcome().error()))
                );
            } else {
                let outcome = result.unwrap_err().into_outcome();
                let allow = if suffix == "intent" {
                    Allow::GetPost
                } else {
                    Allow::Post
                };
                assert_eq!(
                    (outcome.status().as_u16(), outcome.error(), outcome.allow()),
                    (405, Some(ErrorToken::MethodNotAllowed), Some(allow))
                );
            }
            cases += 1;
        }
    }
    let mut head = req("HEAD", "/volume/v/intent");
    head.conditionals.fields = &["If-Match"];
    assert_eq!(
        super::admit_authority(&head, ENFORCING, true)
            .unwrap_err()
            .outcome()
            .status()
            .as_u16(),
        405
    );
    head.method = "GET";
    assert_eq!(
        super::admit_authority(&head, ENFORCING, true)
            .unwrap_err()
            .outcome()
            .status()
            .as_u16(),
        400
    );
    head.path = "/volume/v/intent?alias";
    assert_eq!(
        super::admit_authority(&head, ENFORCING, true)
            .unwrap_err()
            .outcome()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(cases, 24);
}

#[test]
fn round1_readback_is_an_authenticated_read() {
    use super::OperationKind;
    assert!(OperationKind::AUTHENTICATED_READS.contains(&OperationKind::IntentReadback));
    assert!(!OperationKind::AUTHENTICATED_WRITES.contains(&OperationKind::IntentReadback));
}
