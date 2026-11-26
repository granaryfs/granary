// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! fuser shim (linux only).

// The release wall, stated at its EXECUTED strength:
// this is not a claim that a hook-carrying release binary is
// unproducible; `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true`
// still flips `debug_assertions` back on in a release profile,
// and this wall cannot see that.
// What it DOES guarantee: the feature landing in a
// default list fails lint's musl build (CI's only release-profile
// compile of this crate), and a plain `cargo build --release --features
// conformance-breakage` fails to compile. The profile-independent wall
// is the runtime handshake: a feature-built `gran mount` refuses to
// start without `--breakage`, and a normal build rejects `--breakage`;
// every round also greps for the `BREAKAGE ACTIVE` banner. This
// compile-time wall only closes the ZERO- and ONE-deliberate-opt-in
// accidents.
#[cfg(all(feature = "conformance-breakage", not(debug_assertions)))]
compile_error!(
    "conformance-breakage must never compile into a release binary: it installs the seven \
     should-fail faults the differential-oracle rounds drive against a mount, and is \
     a test tool for that harness, never an operator-facing surface. This wall is not total — \
     CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true flips debug_assertions back on in a release \
     profile — the runtime mutual-refusal handshake (gran mount --breakage) is the \
     profile-independent guard."
);

#[cfg(feature = "conformance-breakage")]
mod breakage;
mod callback;
mod capability;
mod errno;
mod filesystem;
mod listing;
mod options;
mod session_end;
mod source;
#[cfg(test)]
pub(crate) mod test_cleanup_wait;
#[cfg(test)]
mod test_connection_abort;
#[cfg(target_os = "linux")]
mod unmount;
// Conformance layer 2 — the FUSE-mechanism property tests. All test code;
// compiles (cfg'd out) on macOS and RUNS only on Linux, in the container-root
// lane. The two cfg
// attributes are DELIBERATELY separate rather than `cfg(all(test, target_os =
// "linux"))`: clippy's `allow-{expect,unwrap}-in-tests` exemption only
// recognises a BARE `#[cfg(test)]` attribute and does not recurse into an
// `all(...)` predicate, so the combined form would deny every `.expect()` in
// this test module's fixtures. Stacked attributes are ANDed — same gate,
// clippy-visible test context.
#[cfg(target_os = "linux")]
#[cfg(test)]
mod mechanism;

#[cfg(feature = "conformance-breakage")]
pub use breakage::{Breakage, bend_attr, follow_sibling, list_dir_plus_with_breakage};
pub use callback::{Callback, CallbackOutcome};
pub use capability::negotiate;
pub use errno::errno;
pub use filesystem::{
    GranaryFs, MountRefused, SlotBusy, ViewAdapter, ViewHandle, ViewNotifier, kernel_time,
};
pub use listing::{
    DirPlusSink, DirSink, SinkOutcome, check_name_length, entry_file_type, list_dir, list_dir_plus,
};
#[cfg(target_os = "linux")]
pub use options::{BackgroundMount, spawn_session, spawn_writable_session};
pub use options::{SessionConfig, session_config, writable_session_config};
pub use session_end::{
    MountIdentity, MountRow, SessionEnd, SessionEndEvidence, classify_session_end, fuzz_probe,
    mountinfo_rows_at,
};
pub use source::{
    BoundaryKind, BoundaryOutcome, CallbackObserver, CallbackScope, DeferredCallbackScope,
    MountBackend, MountError, MountShrinkRequest, MountSyncError, MountSyncJob, MountSyncRequest,
    MountWritability, OverlayCapacity, OverlayChildren, OverlayDirectory, OverlayMetadata,
    OverlayMutation, OverlayNode, SyncCompletion, ViewBoundary, WriteError,
};
#[cfg(target_os = "linux")]
pub use unmount::{FusermountAttempt, FusermountOutcome, UnmountError, detach_unmount};

// Engine items are imported in the files that need them, under those
// files' cfg gates; this root does not re-export them downstream.

/// The longest symlink target a Linux FUSE `readlink` reply can carry on a
/// 4 KiB-page host. The kernel's readlink handler declares
/// `out_args[0].size = PAGE_SIZE - 1` (mainline: `folio_size(folio) - 1`
/// over an order-0 folio, the same page), and a longer reply is refused by
/// `fuse_copy_out_args` with `-EINVAL`, which `fuse_dev_do_write` turns into
/// `-EIO` for the caller's `readlink()`. Read at v5.14, v6.12 and mainline.
///
/// This is a SERVE-layer bound and deliberately NOT a manifest constant: the
/// manifest's accept set must be a property of the bytes, not of the host's
/// page size, or the same object would be valid on a 16 KiB-page host and
/// invalid on a 4 KiB-page one.
///
/// It is page-size AWARE and deliberately a FIXED NUMBER. **Do not call
/// `getpagesize`/`sysconf` here**: a runtime query would make mount admission
/// depend on the machine, which is the very thing this constant exists to
/// avoid. 4095 is the minimum across every page size a supported host uses, so
/// a reply inside it is servable everywhere. (Unrelated to
/// `filesystem.rs`'s `BSIZE = 4096`, which is the statfs BLOCK size.)
pub(crate) const FUSE_READLINK_TARGET_MAX_4K_PAGE: usize = 4095;

/// The constant's ABSOLUTE value, pinned directly.
///
/// Every other row pins the guard RELATIVE to this constant — move it and they
/// move with it. **The absolute value was once caught only through
/// `granary-vfs/src/snapshot/tests.rs`'s literal `len: 4096` expectations**, so a successor
/// "tidying" those to `FUSE_READLINK_TARGET_MAX_4K_PAGE + 1` would have
/// removed the last thing holding 4095 in place, silently and with a green
/// suite. Moving the constant to 4094 left the whole
/// `filesystem.rs` guard suite green.
///
/// Those expectations now pin `TEST_READLINK_BOUND` instead, itself derived
/// from the FORMAT constant (one less than `SYMLINK_TARGET_MAX`) rather than
/// from this adapter's own — precisely so those tests can travel to the
/// engine crate without naming anything here. This assert is therefore now
/// the ONLY thing pinning this constant's absolute value: nothing else in
/// this crate would notice if it drifted, as long as it drifted together
/// with every RELATIVE guard that reads it. Do not weaken this assert while
/// rewording around it.
const _: () = assert!(FUSE_READLINK_TARGET_MAX_4K_PAGE == 4095);

use granary_vfs::ServeLimits;

/// The adapter's own [`ServeLimits`] — the bound `GranaryFs::new` verifies
/// every mounted [`granary_vfs::Snapshot`] against. Built from this
/// crate's own servable-ceiling constant, which stays `pub(crate)`: the
/// number itself does not become public API, only this value does.
pub const FUSE_SERVE_LIMITS: ServeLimits = ServeLimits {
    readlink_target_max_bytes: FUSE_READLINK_TARGET_MAX_4K_PAGE,
};

#[cfg(test)]
mod test_queries;
