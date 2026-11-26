// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The `FUSE_INIT` capability decision, extracted so it is testable.
//!
//! The decision takes `InitFlags`, so tests can supply capability sets
//! directly without constructing a `fuser::KernelConfig`.

use fuser::InitFlags;

/// Decides which capabilities to request, given what the kernel advertised.
///
/// Returns `Ok` of the exact set to request when the kernel offers all of
/// it (today `FUSE_DO_READDIRPLUS` alone), or `Err` of the requested flags it
/// does not offer.
///
/// **Deliberately never requests `FUSE_READDIRPLUS_AUTO`, even when the
/// kernel offers it.** Upstream `fuse_use_readdirplus()`
/// (`fs/fuse/readdir.c`) is, in essence, `if (!fc->do_readdirplus) return
/// false; if (!fc->readdirplus_auto) return true; ...` — with
/// `FUSE_DO_READDIRPLUS` requested and `FUSE_READDIRPLUS_AUTO` left UNSET,
/// the kernel uses READDIRPLUS unconditionally, and plain `FUSE_READDIR`
/// never arrives in production. That is what makes the milestone's "a
/// READDIRPLUS arrived" gate deterministic rather than probabilistic, and
/// what guarantees a `readdirplus` defect has no plain-`readdir` fallback
/// silently masking it (trap T3).
///
/// # Errors
///
/// Returns `Err` of the requested flags the kernel did not advertise — the
/// caller is expected to fail mount initialisation on this, since nothing
/// downstream can recover a capability the kernel never offered.
pub fn negotiate(capabilities: InitFlags) -> Result<InitFlags, InitFlags> {
    if capabilities.contains(REQUESTED) {
        Ok(REQUESTED)
    } else {
        Err(REQUESTED.difference(capabilities))
    }
}

/// The exact set [`negotiate`] requests.
const REQUESTED: InitFlags = InitFlags::FUSE_DO_READDIRPLUS;

// The session-end classifier counts an `ECONNABORTED` read as a teardown race
// only because, without `FUSE_ABORT_ERROR`, the kernel answers it solely for a
// read that had just dequeued a request. With the flag negotiated, every
// end-of-connection read answers `ECONNABORTED`, a connection abort's
// included, so the error would no longer single out that race.
const _: () = assert!(
    !REQUESTED.contains(InitFlags::FUSE_ABORT_ERROR),
    "FUSE_ABORT_ERROR changes what ECONNABORTED means at the end of a session: revisit \
     classify_session_end before requesting it"
);

#[cfg(test)]
mod tests;
