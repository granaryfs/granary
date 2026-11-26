// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The FUSE mount session's option set.

pub use fuser::Config as SessionConfig;
use fuser::{Config, MountOption, SessionACL};

/// Builds the FUSE session configuration for a granary mount.
///
/// `allow_other` is the already-decided boolean the caller supplies;
/// this function carries no trust mode of its own — `TrustMode` is
/// defined in `granary-client`, and `granary-fuse` must not depend
/// on `granary-client`. `allow_other` being refused in both keyless
/// modes is that caller's job, not this one's.
#[must_use]
pub fn session_config(allow_other: bool) -> Config {
    // `Config` is `#[non_exhaustive]`, so it is built with
    // `Config::default()` and field assignment — a struct literal does
    // not compile from another crate.
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::NoSuid,
        MountOption::NoDev,
        // `noexec` is DELIBERATELY NOT forced. Every
        // primary source on unprivileged FUSE mounts names only
        // `nodev,nosuid` as fusermount3's own enforced pair — never
        // `noexec` — and a root mount (which is what `gran mount` runs
        // as, per its own `mount(2)` path) gets neither restriction for
        // free from libfuse either way. The smoke test executes a binary
        // from the mount, and that is the intended, supported shape:
        // this filesystem serves signed content, and refusing to execute
        // it would be a confidentiality control dressed up as an
        // integrity one. See `MOUNT_HELP` for the actual control on who
        // may read (and thus execute) a mount's content: `allow_other`.
        // `default_permissions` is NOT optional cosmetics. Without
        // it, the ONLY permission check available is a hand-rolled
        // one in the daemon, and a daemon-side check is structurally
        // GROUP-BLIND: `fuse_in_header` carries only `uid`, `gid`
        // and `pid`, while the kernel's own `generic_permission`
        // evaluates the caller's FULL supplementary group set — a
        // daemon has no wire field to reconstruct that from. A
        // hand-rolled check also cannot run on a cached-dentry or
        // mmap path (the kernel never calls back into the filesystem
        // for those) and forfeits the kernel's free, pre-emptive
        // rejection of `open(O_WRONLY)` against a read-only mount.
        // So this flag is a fork between a CORRECT check and a
        // BROKEN one, not between "kernel enforces it" and "the
        // daemon enforces it instead" — there is no daemon-side
        // equivalent that gets the group set right.
        MountOption::DefaultPermissions,
        MountOption::FSName("gran".to_owned()),
        MountOption::Subtype("gran".to_owned()),
    ];
    config.acl = if allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };
    // `allow_other` is REQUIRED for anyone but the mounting process
    // to read this mount AT ALL — root included. libfuse's
    // `fuse_allow_current_process` has no root exemption, so a root
    // mount with `SessionACL::Owner` is readable by root alone;
    // without this flag even a machine-wide mount serves nobody but
    // the process that opened `/dev/fuse`. Its OTHER edge is the
    // one that matters for the caller: setting it lets every local
    // user who can reach the mountpoint read the WHOLE snapshot and
    // execute any entry carrying the signed exec bit, under their
    // OWN credentials — which is why a machine-wide mount requires `--root-key`
    // before this crate's caller may ever pass `allow_other: true` in, and why
    // `MOUNT_HELP` states that consequence in an operator's own words rather
    // than only in a comment here.
    // Explicit, not the fuser default: the mount serves one request
    // at a time, and real read concurrency is not implemented.
    config.n_threads = Some(1);
    config.clone_fd = false;
    config
}

/// Owner-only writable attachment rails. Write handlers are supplied separately.
#[must_use]
pub fn writable_session_config() -> Config {
    let mut config = session_config(false);
    config
        .mount_options
        .retain(|option| *option != MountOption::RO);
    config.mount_options.insert(0, MountOption::RW);
    config
}

#[cfg(test)]
mod tests;

/// The running session a spawned mount returns.
#[cfg(target_os = "linux")]
pub use fuser::BackgroundSession as BackgroundMount;

/// Attach the existing filesystem adapter using a previously admitted configuration.
/// # Errors
/// Adapter or FUSE attachment/initialisation failure.
#[cfg(target_os = "linux")]
pub fn spawn_session<B: crate::MountBackend>(
    snapshot: granary_vfs::Snapshot,
    backend: B,
    generation: u64,
    writability: crate::MountWritability,
    mountpoint: &std::path::Path,
    config: &Config,
) -> std::io::Result<fuser::BackgroundSession> {
    serve(
        snapshot,
        backend,
        generation,
        writability,
        mountpoint,
        config,
        |_| Ok(()),
    )
}

/// Attach a writable filesystem, handing `bind` the handle an install
/// reaches its adapter state through, its notifier attached, before the
/// session serves a request. A refused bind drops the session unserved.
///
/// `bind` runs once, before the session serves, and is the only place the
/// handle is given out. A bind can outlast a failed spawn: whatever it bound
/// the handle to stays bound to an adapter that is gone, so a caller keeps
/// nothing from that bind once this returns an error.
/// # Errors
/// Adapter or FUSE attachment/initialisation failure, or `bind`'s refusal.
#[cfg(target_os = "linux")]
pub fn spawn_writable_session<B: crate::MountBackend>(
    snapshot: granary_vfs::Snapshot,
    backend: B,
    generation: u64,
    mountpoint: &std::path::Path,
    config: &Config,
    bind: impl FnOnce(crate::ViewHandle<B>) -> std::io::Result<()>,
) -> std::io::Result<fuser::BackgroundSession> {
    serve(
        snapshot,
        backend,
        generation,
        crate::MountWritability::Writable,
        mountpoint,
        config,
        bind,
    )
}

#[cfg(target_os = "linux")]
fn serve<B: crate::MountBackend>(
    snapshot: granary_vfs::Snapshot,
    backend: B,
    generation: u64,
    writability: crate::MountWritability,
    mountpoint: &std::path::Path,
    config: &Config,
    bind: impl FnOnce(crate::ViewHandle<B>) -> std::io::Result<()>,
) -> std::io::Result<fuser::BackgroundSession> {
    let filesystem = crate::GranaryFs::new(snapshot, backend, generation, writability)
        .map_err(|_| std::io::Error::other("filesystem admission refused"))?;
    let mut view = filesystem.view_handle();
    let session = fuser::Session::new(filesystem, mountpoint, config)?;
    view.set_notifier(std::sync::Arc::new(session.notifier()));
    // Bound before the session serves, so no request is answered without
    // the binding.
    bind(view)?;
    session.spawn()
}
