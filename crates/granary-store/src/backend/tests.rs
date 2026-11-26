// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::backend` — the `object_store` adapters and
//! `RootStore` CAS implementation: bin/metadata round-trips, the
//! numbered-root layout, and the allocation-clamp behaviour that is
//! otherwise unobservable end-to-end.
//!
//! Out-of-line: `granary-store`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-server`,
//! `granary-sim`), so the module's own tests move out of
//! the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

/// The allocation clamp, pinned here for the same reason
/// `conditional_token` is: it is UNOBSERVABLE end-to-end. Every
/// caller that reaches `collect_bounded` has already made
/// `hint <= cap` true — `get_bounded` by its size gate, `read_hint`
/// by passing the cap itself, `get_bin_range` by passing a value it
/// has already taken a `min` over — so deleting the clamp changes no
/// outcome any public read can produce. It is defence in depth for
/// the next caller, and only inspecting the value catches its
/// removal.
///
/// The hint `get_bin_range` chooses is a different property — that
/// one asks which number the caller picked, this one asks what
/// happens if it picks a bad one — and it is pinned by value too,
/// in `range_alloc_hint_never_exceeds_one_frame` below, because a
/// read hides it: a body that does not match its declared extent is
/// refused, and `collect_bounded` shrinks a matching body's buffer
/// toward its length before returning it.
#[test]
fn alloc_hint_never_exceeds_the_cap() {
    // An advertised length far above the cap must not size a buffer.
    assert_eq!(alloc_hint(1_000_000, 64), 64);
    assert_eq!(alloc_hint(u64::MAX, 64), 64);
    // Under the cap, the advertisement is used as-is: clamping
    // upward instead would allocate the cap for every small object.
    assert_eq!(alloc_hint(10, 64), 10);
    assert_eq!(alloc_hint(64, 64), 64);
    assert_eq!(alloc_hint(0, 64), 0);
}

/// The ranged read's allocation proposal, pinned here by value: a
/// response whose body does not match its declared extent — a huge
/// declared extent over a tiny body — is refused, a matching body's
/// buffer is shrunk toward its length, and the buffer this number sizes
/// is reserved before the refusal can run. So the number is hard to see
/// through a read and load-bearing anyway.
#[test]
fn range_alloc_hint_never_exceeds_one_frame() {
    // The whole point: a legal but enormous extent must not name the
    // allocation.
    assert_eq!(range_alloc_hint(BIN_MAX_BYTES), u64::from(FRAME_COMP_MAX));
    assert_eq!(range_alloc_hint(u64::MAX), u64::from(FRAME_COMP_MAX));
    // At and under a frame, the extent is used as-is — clamping
    // upward would reserve a frame for every small range read.
    assert_eq!(
        range_alloc_hint(u64::from(FRAME_COMP_MAX)),
        u64::from(FRAME_COMP_MAX)
    );
    assert_eq!(range_alloc_hint(100), 100);
    assert_eq!(range_alloc_hint(0), 0);
}

/// An empty token is treated as no cached token at all, so no
/// `If-None-Match` is sent — see `conditional_token`'s doc comment
/// for why this must be pinned here rather than through
/// `RootStore::read_hint`'s end-to-end behaviour.
#[test]
fn conditional_token_treats_empty_as_absent() {
    assert_eq!(conditional_token(None), None);
    assert_eq!(conditional_token(Some(&HintToken(String::new()))), None);
    assert_eq!(
        conditional_token(Some(&HintToken("etag-1".to_owned()))),
        Some("etag-1")
    );
}
