// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::capability` — the `FUSE_INIT` capability decision,
//! extracted out of the `init` callback so it is testable.
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::negotiate;
use fuser::InitFlags;

#[test]
fn offered_alone_is_requested() {
    assert_eq!(
        negotiate(InitFlags::FUSE_DO_READDIRPLUS),
        Ok(InitFlags::FUSE_DO_READDIRPLUS)
    );
}

#[test]
fn not_offered_at_all_is_refused() {
    assert_eq!(
        negotiate(InitFlags::empty()),
        Err(InitFlags::FUSE_DO_READDIRPLUS)
    );
}

#[test]
fn auto_offered_without_do_readdirplus_is_still_refused() {
    // FUSE_READDIRPLUS_AUTO alone must not be mistaken for
    // FUSE_DO_READDIRPLUS — they gate different kernel behaviour.
    assert_eq!(
        negotiate(InitFlags::FUSE_READDIRPLUS_AUTO),
        Err(InitFlags::FUSE_DO_READDIRPLUS)
    );
}

#[test]
fn offered_alongside_unrelated_flags_never_requests_auto() {
    // The kernel offering FUSE_READDIRPLUS_AUTO too must not make this
    // function request it — that is trap T3's whole mechanism, and the
    // one property this piece of the wave exists to pin down.
    let offered = InitFlags::FUSE_DO_READDIRPLUS
        | InitFlags::FUSE_READDIRPLUS_AUTO
        | InitFlags::FUSE_ASYNC_READ
        | InitFlags::FUSE_BIG_WRITES;
    let wanted = negotiate(offered).expect("do_readdirplus was offered");
    assert_eq!(
        wanted,
        InitFlags::FUSE_DO_READDIRPLUS,
        "must request DO_READDIRPLUS only, never AUTO: {wanted:?}"
    );
    assert!(!wanted.contains(InitFlags::FUSE_READDIRPLUS_AUTO));
}

#[test]
fn writable_init_ignores_offered_writeback_cache() {
    let offered = InitFlags::FUSE_DO_READDIRPLUS | InitFlags::FUSE_WRITEBACK_CACHE;
    let negotiated = negotiate(offered).unwrap();
    assert_eq!(negotiated, InitFlags::FUSE_DO_READDIRPLUS);
    assert!(!negotiated.contains(InitFlags::FUSE_WRITEBACK_CACHE));
}
