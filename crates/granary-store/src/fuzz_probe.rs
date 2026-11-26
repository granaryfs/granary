// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Fuzz/replay instrumentation for the ingest verify pipeline. No
//! stability promises, never product logic — the `format-object` fuzz
//! obligation applied to [`crate::verify`].
//!
//! **ONE body, two callers.** `fuzz/fuzz_targets/bin_ingest.rs` (nightly,
//! libFuzzer, weekly) and `tests/fuzz_corpus_replay.rs` (stable, every
//! PR) both call [`bin_ingest_probe`] and nothing else, so the corpus a
//! crash produces replays through the identical code — the
//! `granary_core::testkit` precedent, and the reason PR CI needs no
//! nightly.
//!
//! **The probe drives the WHOLE pipeline**, not a slice of it:
//! `decode_bin` → the up-front declared-sum pass → per-frame
//! `decompress_frame_into` → blake3 → the running bail, by calling the
//! production entry point [`verify_bin`] rather than reimplementing any
//! part of it.
//!
//! **Its SANITIZER coverage is narrower than that, and the gap is worth
//! naming.** cargo-fuzz puts `-Zsanitizer=address` in `RUSTFLAGS` only,
//! so the C that `zstd-sys` builds is compiled uninstrumented — libzstd
//! is the largest C surface either fuzz workspace pulls in (blake3's
//! cc-built SIMD is the other, and much smaller). ASan's `memcpy` and
//! `memmove` interceptors still fire, which covers the raw-block copies,
//! but a direct out-of-bounds write from inside libzstd into the
//! destination slice would not be caught — and decompress law 3, which
//! makes that slice exactly the declaration wide
//! (`codec::GrainCodec::decompress_frame_into`), is an invariant this
//! target is meant to be the net for. Setting `CFLAGS`/`CXXFLAGS`
//! alongside the sanitizer `RUSTFLAGS` would close it; that is an
//! untested build change and belongs to the run that can actually
//! exercise the lane, not to this file.

use granary_core::binfmt::{BinIndexEntry, decode_bin, decode_frame_header, frame_bytes};
use granary_core::manifest::GRAIN_UNPACKED_MAX;

use crate::verify::{BinVerifyError, verify_bin};

/// The ceiling the probe drives [`verify_bin`] with — **a probe figure
/// and deliberately not the production one.**
///
/// `verify_bin` takes its limit as a parameter precisely so the one
/// policy site stays in `granary-server` (§9.2); a probe that
/// re-spelled that literal here would be a second figure site, and the
/// occurrence-count guard the doc-vs-code gate relies on would start
/// counting it. It is stated as **two maximal grains** rather than a
/// bare number so it reads as what it is: high enough that a bin of
/// real grains verifies end to end (the fuzzer reaches blake3, not just
/// the header pass), low enough that one execution can never hash more
/// than 16 MiB whatever the input declares.
pub const PROBE_SUM_MAX: u64 = 2 * GRAIN_UNPACKED_MAX as u64;

/// What [`verify_bin`]'s up-front declared-sum pass must conclude about
/// a bin, derived independently of that pass from the frame headers
/// alone.
///
/// The point of computing it twice is that the probe then holds
/// `verify_bin` to an answer it did not get from `verify_bin`: a bail
/// that stopped charging, charged in the wrong order, or was reordered
/// after the expansion it exists to prevent produces a verdict this
/// walk disagrees with, and the disagreement is the crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderWalk {
    /// A frame extent or header did not decode. The verdict must be
    /// `Undecodable` whatever a LATER frame declares — the pass walks
    /// in index order and stops at the first failure, so a bomb hiding
    /// behind a broken frame is refused for the broken frame.
    Undecodable,
    /// The running total crossed the limit at this frame, carrying the
    /// total AT the crossing — the number `DecompressedSumExceeded`
    /// reports as `at_least`, and never the whole bin's sum, which the
    /// pass deliberately stops short of computing.
    Crossed(u64),
    /// Every frame's declaration charged and the total stayed inside
    /// the limit.
    Within(u64),
}

/// Charge every frame's DECLARED length in index order, exactly as
/// [`verify_bin`]'s up-front pass does, and report where that walk ends.
///
/// Saturating, like the pass it mirrors: a saturated total is past every
/// limit, so the direction the arithmetic fails in refuses.
#[must_use]
pub fn walk_declared_headers(bin: &[u8], entries: &[BinIndexEntry], limit: u64) -> HeaderWalk {
    let mut running: u64 = 0;
    for entry in entries {
        let Ok(frame) = frame_bytes(bin, entry) else {
            return HeaderWalk::Undecodable;
        };
        let Ok(header) = decode_frame_header(frame) else {
            return HeaderWalk::Undecodable;
        };
        running = running.saturating_add(u64::from(header.unpacked_len));
        if running > limit {
            return HeaderWalk::Crossed(running);
        }
    }
    HeaderWalk::Within(running)
}

/// Drive arbitrary bytes through the ingest verify pipeline and assert
/// its totality and its bound. Panics on a violation — that is the
/// point; a panic is what libFuzzer reports and what the replay test
/// turns red.
///
/// Two properties, and neither is "it returned `Ok`":
///
/// 1. **Totality.** Every input yields `Ok` or one of the four
///    [`BinVerifyError`] variants. No panic, no unwind, no abort — on
///    bytes an unauthenticated peer chose.
/// 2. **The bound is not bypassable.** Whenever the frames' declared
///    lengths cross `PROBE_SUM_MAX`, the answer is
///    `DecompressedSumExceeded` reporting that same limit and that same
///    crossing total — so the bin was refused from headers, before any
///    expansion. Contrapositively, an accepted bin declared at most
///    `PROBE_SUM_MAX` bytes; decompress law 4 pins produced bytes to the
///    declaration, so "declared at most the ceiling" IS "expanded at
///    most the ceiling", which is the claim §9.2 makes and the one an
///    external caller can actually observe.
///
/// # Panics
/// On a violation of either property, and that is the mechanism rather
/// than a caveat: a panic is what libFuzzer records as a crash and what
/// the corpus-replay test turns red. Nothing in the crate calls this on
/// a production path.
pub fn bin_ingest_probe(data: &[u8]) {
    let verdict = verify_bin(data, PROBE_SUM_MAX);
    let Ok(entries) = decode_bin(data) else {
        assert!(
            matches!(verdict, Err(BinVerifyError::Undecodable(_))),
            "bytes decode_bin refuses must be Undecodable, got {verdict:?}"
        );
        return;
    };
    match walk_declared_headers(data, &entries, PROBE_SUM_MAX) {
        // Unreachable while `decode_bin` validates every frame header
        // itself (binfmt.rs, the final loop). Written anyway: the arm
        // costs nothing, and if that validation is ever relaxed the
        // probe keeps holding the ORDER — first failure wins — instead
        // of silently starting to accept a different answer here.
        HeaderWalk::Undecodable => assert!(
            matches!(verdict, Err(BinVerifyError::Undecodable(_))),
            "a frame header that does not decode must be Undecodable, got {verdict:?}"
        ),
        HeaderWalk::Crossed(at_least) => match verdict {
            Err(BinVerifyError::DecompressedSumExceeded {
                limit,
                at_least: reported,
            }) => {
                assert_eq!(limit, PROBE_SUM_MAX, "the reported limit is the caller's");
                assert_eq!(
                    reported, at_least,
                    "the refusal must report the running total AT the crossing frame"
                );
            }
            other => panic!(
                "declared lengths cross {PROBE_SUM_MAX} at {at_least}, so the bin must be \
                 refused for the limit and never expanded: {other:?}"
            ),
        },
        HeaderWalk::Within(sum) => {
            assert!(sum <= PROBE_SUM_MAX, "the walk's own postcondition");
            assert!(
                !matches!(verdict, Err(BinVerifyError::DecompressedSumExceeded { .. })),
                "a bin declaring {sum} bytes is inside the {PROBE_SUM_MAX}-byte limit and \
                 must not be refused for it: {verdict:?}"
            );
        }
    }
}
