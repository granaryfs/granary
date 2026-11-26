// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::unmount` — the Linux `umount2(2)` path implementing
//! libfuse's own unmount shape (the PARENT `unmount.rs`'s test-only
//! `mount_state`, shared with `mechanism.rs`, stays at file scope and is
//! not part of this module; the mountinfo parser it calls is
//! `session_end.rs`'s, and its rows are there).
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use nix::mount::{MsFlags, mount};
use nix::unistd::{Uid, setuid};

use super::{FusermountOutcome, UnmountError, detach_unmount, mount_state};

// This crate cannot be unit-tested on macOS: the whole module is
// `#[cfg(target_os = "linux")]`. These tests only compile and run
// under Linux CI; on the dev machine, `cargo check --target
// x86_64-unknown-linux-gnu` is the type-check proof instead.
//
// SEVERAL tests below need root: creating a bind mount, mounting a
// daemonless FUSE filesystem, or dropping privilege irreversibly all
// need `CAP_SYS_ADMIN`/`CAP_SETUID`. Each checks for it and SKIPS
// with a printed reason rather than silently asserting nothing — a
// skipped test is not the same claim as one that verified the
// behaviour, and the difference belongs in the test's own output.
//
// TESTS THAT CALL `setuid` RELY ON PROCESS-PER-TEST ISOLATION.
// `setuid(2)` drops privilege for the WHOLE calling process,
// irreversibly, and this workspace's test runner is `cargo nextest
// run` (required for process-per-test isolation), which gives every
// `#[test]` its own process. Under that runner a privilege drop in
// one test cannot reach any other test. Do not run this file's tests
// with plain `cargo test` sharing one process across threads; that
// would leak a dropped-privilege state into whichever test happens to
// run next on the same thread.

/// Prints a reason and returns `false` rather than asserting nothing:
/// several tests below need to start as root (to create a mount, or
/// to drop privilege irreversibly), and a `#[test]` that silently
/// "passes" on a machine that cannot supply that precondition is not
/// the same claim as one that verified the behaviour.
fn require_root(test_name: &str) -> bool {
    if Uid::effective().is_root() {
        true
    } else {
        eprintln!(
            "SKIPPED {test_name}: needs to start as root (mount \
             creation or an irreversible privilege drop both need \
             CAP_SYS_ADMIN / CAP_SETUID) — NOT EXECUTED on this run"
        );
        false
    }
}

/// Creates and returns a scratch directory unique to the CALLING TEST
/// and to this specific call, under a CANONICAL base, and verified to
/// be a real, freshly made directory before handing it back.
///
/// The predecessor of this function only ever COMPUTED a path
/// (`std::env::temp_dir().join(a-fixed-per-test-label)`) and left
/// creating it to each caller via `create_dir_all` — which descends
/// into a pre-existing path, symlink or not, rather than refusing
/// it. Its own doc comment reasoned about a stale leftover from a
/// crashed prior run, never about a HOSTILE one: any unprivileged
/// local user can predict that exact `/tmp` path (the label
/// is a literal in this source file) and pre-plant a symlink
/// at it before a root test run starts, and this function's
/// callers go on to `mount` and `remove_dir_all` inside
/// whatever that resolves to, as root.
///
/// This function closes that in three parts:
///
/// - **`create_dir`, never `create_dir_all`.** `create_dir` FAILS if
///   the path already exists — a pre-planted symlink or directory is
///   refused outright rather than silently reused or descended into.
///   `std::process::id()` plus a per-process-call atomic counter make
///   the name unpredictable enough in practice that a would-be
///   attacker cannot usefully pre-plant at the exact path this call
///   will use, but the refusal above is the load-bearing half: even
///   a correct guess is refused, not exploited. (`process::id` is
///   otherwise banned by the workspace's `disallowed-methods` lint as an
///   ambient-input seam for a hashed/signed preimage, which this is not — it names a
///   throwaway test fixture, the same exception the rest of the
///   workspace's test suites already take, e.g.
///   `granary-bench/tests/smoke.rs::scratch`.)
/// - **Verify what `create_dir` just made is really a directory**,
///   via `symlink_metadata` (which, unlike `metadata`, does not
///   itself follow a final symlink). This is defence in depth against
///   the narrow window between `create_dir` returning and this check
///   running, not a claim that the window is closed — the same
///   check-then-use residual [`super::detach_unmount`] documents for
///   its parent check applies here too.
/// - **A CANONICAL base.** `detach_unmount` now requires a target's
///   parent to be its own canonical form, so a fixture built under a
///   symlinked temp directory (a `TMPDIR` pointing through one, or a
///   `/tmp` that is itself a link) would be refused for a reason that
///   has nothing to do with the property under test. Canonicalising
///   the base once here keeps every fixture's parent canonical by
///   construction.
#[expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]
fn scratch_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::fs::canonicalize(std::env::temp_dir())
        .expect("canonicalize the temp directory these fixtures live under");
    create_verified_scratch_dir(base.join(format!(
        "granary-fuse-unmount-test-{label}-{}-{n}",
        std::process::id()
    )))
}

/// The actual create-and-verify mechanism, split out of `scratch_dir`
/// so it is unit-testable directly on a PATH THE TEST CHOOSES, rather
/// than only ever on `scratch_dir`'s own unpredictable pid+counter
/// name (see `create_verified_scratch_dir_refuses_a_preplanted_symlink`
/// below, which pre-plants a symlink at a path it controls and
/// asserts this function refuses it).
fn create_verified_scratch_dir(dir: PathBuf) -> PathBuf {
    std::fs::create_dir(&dir).expect(
        "create a fresh, exclusively-owned scratch directory (refused if the \
         path already exists, planted or stale)",
    );
    let file_type = std::fs::symlink_metadata(&dir)
        .expect("stat the directory this call just created")
        .file_type();
    assert!(
        file_type.is_dir(),
        "scratch directory {} was replaced between creation and this check — refusing to use it",
        dir.display()
    );
    dir
}

/// Writes an executable `/bin/sh` stand-in for a `fusermount` helper
/// that appends `<name>:<code>` to `log` and exits `code`.
///
/// The private `fusermount_lazy_unmount_with`
/// seam takes its candidate list as an
/// argument, so the fakes live in the test's
/// own scratch directory and are handed to it
/// directly: the two dispatch tests below
/// need no fake on `PATH`, no root and no
/// real mount, and no external harness is
/// involved.
fn write_fake_helper(path: &Path, name: &str, log: &Path, code: i32) {
    let script = format!(
        "#!/bin/sh\nprintf '{name}:{code}\\n' >> '{}'\nexit {code}\n",
        log.display()
    );
    std::fs::write(path, script).expect("write the fake fusermount helper");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("make the fake fusermount helper executable");
}

#[test]
fn nonexistent_target_fails_without_panicking() {
    let target = Path::new("/nonexistent/granary-fuse-unmount-test-target");
    match detach_unmount(target) {
        Ok(()) => panic!("umount2 on a nonexistent path must not report success"),
        // The guard canonicalises the target's PARENT, so a target
        // whose parent never existed fails HERE rather than reaching
        // `umount2` at all. Before any of this the same input
        // reached the kernel and came back ENOENT or EINVAL (kernel
        // path resolution fails before any capability check runs
        // against a path that does not exist, on BOTH a root and
        // an unprivileged caller); the practical meaning ("no such
        // target") is unchanged, only which layer reports it. The
        // fusermount fallback must not even fire here. Tightened
        // from a blanket `Err(_) => {}`: that catch-all is what
        // made several of this module's own defects invisible
        // to this suite.
        Err(UnmountError::CanonicalizeParent { parent, source }) => {
            assert_eq!(parent, Path::new("/nonexistent"));
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::NotFound,
                "unexpected canonicalize failure: {source}"
            );
        }
        Err(other) => panic!("expected CanonicalizeParent(NotFound), got {other:?}"),
    }
}

/// The attack `create_verified_scratch_dir` refuses: a path is pre-planted as a symlink
/// before the real caller ever runs `create_dir` on it. The
/// predecessor of `create_verified_scratch_dir`
/// (`create_dir_all` with no verification) let this through
/// silently — `create_dir_all` treats an existing path that already
/// resolves to a directory (symlink or not) as success, since it
/// checks via `metadata`, which FOLLOWS the symlink. This test
/// exercises the mechanism directly, on a path it controls, rather
/// than trying to predict `scratch_dir`'s own pid+counter name.
///
/// No cleanup on the panic path below: `#[should_panic]` unwinds
/// past it, and the container directory used to hold the planted
/// symlink is uniquely named (via `scratch_dir` itself) and left for
/// the ephemeral test environment to reclaim, the same "best-effort
/// only" posture every other test in this file already takes for
/// its OWN cleanup.
#[test]
#[should_panic(expected = "create a fresh, exclusively-owned scratch directory")]
fn create_verified_scratch_dir_refuses_a_preplanted_symlink() {
    let container = scratch_dir("preplant-container");
    let attacked = container.join("attacked");
    std::os::unix::fs::symlink("/tmp", &attacked).expect("plant the hostile symlink");

    let _ = create_verified_scratch_dir(attacked);
}

/// `/`, `//` and any `..`-terminated spelling have no ordinary final
/// component, so there is no (parent, name) pair to guard and no
/// mountpoint being named. They are refused before any syscall.
///
/// **Driven through the private `resolve_target`, deliberately, not
/// through `detach_unmount`.** The mutation that proves this guard is
/// "delete the refusal", and if that mutation were applied to a test
/// calling `detach_unmount("/")` as root, the run would reach
/// `umount2("/", MNT_DETACH)` — whose Linux special case for the
/// process's own root is a remount, not a no-op. Proving a guard must
/// not require arming the thing it guards against.
#[test]
fn a_target_with_no_ordinary_final_component_is_refused() {
    for spelling in ["/", "//", "///", "/tmp/..", "/tmp/gran/.."] {
        match super::resolve_target(Path::new(spelling)) {
            Err(UnmountError::NoFinalComponent { requested }) => {
                assert!(requested.is_absolute(), "{spelling}: {requested:?}");
            }
            other => panic!(
                "`{spelling}` names no mountpoint and must be refused before any \
                 syscall; got {other:?}"
            ),
        }
    }
}

/// A `..` component in an ANCESTOR is refused by the byte-for-byte
/// parent comparison — `std::path::absolute` is lexical and preserves
/// `..`, so this is the check that catches it.
#[test]
fn a_dotdot_in_an_ancestor_is_refused() {
    let scratch = scratch_dir("dotdot");
    let sneaky = scratch.join("..").join(
        scratch
            .file_name()
            .expect("the scratch directory has a final component"),
    );
    let target = sneaky.join("mnt");

    let result = super::resolve_target(&target);
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Err(UnmountError::ParentNotCanonical {
            lexical_parent,
            canonical_parent,
            ..
        }) => {
            assert_eq!(canonical_parent, scratch);
            assert_ne!(lexical_parent, canonical_parent);
        }
        other => panic!("a `..` in an ancestor must be refused; got {other:?}"),
    }
}

/// A fully-real path resolves to itself and the mount detaches — the
/// positive control for every refusal above.
#[test]
fn mnt_detach_lazily_unmounts_a_busy_bind_mount() {
    if !require_root("mnt_detach_lazily_unmounts_a_busy_bind_mount") {
        return;
    }

    let scratch = scratch_dir("busy");
    let src = scratch.join("src");
    let dst = scratch.join("dst");
    std::fs::create_dir_all(&src).expect("create bind-mount source");
    std::fs::create_dir_all(&dst).expect("create bind-mount target");

    mount(
        Some(&src),
        &dst,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .expect("bind mount for the test fixture");

    // Make the target BUSY: MNT_DETACH's entire reason to exist is
    // that it lets a busy mount detach immediately instead of failing
    // EBUSY, so the test must actually hold it open, not merely
    // create it (verified directly: a plain `umount2` on this exact
    // fixture returns EBUSY, and the same call WITH `MNT_DETACH`
    // returns success).
    let busy_fd = std::fs::File::open(&dst).expect("open the mount to make it busy");

    let result = detach_unmount(&dst);
    let still_mounted = mount_state(&dst);

    drop(busy_fd);
    // Best-effort cleanup regardless of the assertion below: this
    // must not leave a real mount behind in whatever environment ran
    // it.
    let _ = super::umount2(&dst, super::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Ok(()) => {}
        Err(other) => panic!(
            "a busy mount must detach lazily under MNT_DETACH, got \
             {other:?} instead — this is what the mutation \
             `MntFlags::MNT_DETACH -> MntFlags::empty()` would \
             produce (a plain umount2 on a busy target returns EBUSY)"
        ),
    }
    assert!(
        !still_mounted.expect("read /proc/self/mountinfo to verify the mount's state"),
        "the mount must actually be gone, not merely reported detached"
    );
}

/// A FUSE mount whose daemon is gone must still be detachable — that
/// is the single case a lazy forced unmount exists to recover.
///
/// The fixture is a real one: open `/dev/fuse`, `mount(2)` it, then
/// CLOSE the device fd. Closing the last reference to the device
/// aborts the connection, which is what makes every subsequent
/// operation INTO the filesystem fail fast with `ENOTCONN` instead of
/// blocking forever — so this test cannot hang the suite the way a
/// live-but-unanswered daemon would. (That second shape is real too,
/// and was measured out of band: holding the device fd open and never
/// answering makes `lstat` on the mountpoint hang until killed. It is
/// deliberately NOT the fixture here, because a test that HANGS on
/// regression is worse than no test.)
///
/// **What this test does and does not claim.** It asserts that every
/// direct stat of the mountpoint fails with `ENOTCONN`, and that
/// `detach_unmount` nevertheless succeeds — so any filesystem call
/// naming the target that is added on the way to the syscall turns
/// this red. It does NOT assert that whole-target canonicalisation fails
/// on this fixture: measurements on glibc 2.41, glibc 2.36 and musl show
/// `realpath(3)` succeeding because it probes components with `readlink(2)`
/// (answered locally for a FUSE root inode) rather than `lstat(2)`. What
/// it guards is a libc that does not make that choice, and any filesystem
/// probe added here by hand. See [`super::detach_unmount`]'s own doc
/// comment for the full measurement.
#[test]
fn a_wedged_enotconn_mount_is_still_detachable() {
    if !require_root("a_wedged_enotconn_mount_is_still_detachable") {
        return;
    }

    let scratch = scratch_dir("enotconn");
    let mountpoint = scratch.join("mnt");
    std::fs::create_dir(&mountpoint).expect("create the mountpoint");

    let device = std::fs::File::open("/dev/fuse")
        .expect("open /dev/fuse (the container needs --device /dev/fuse)");
    let data = format!(
        "fd={},rootmode=40000,user_id=0,group_id=0",
        device.as_raw_fd()
    );
    mount(
        Some("granary-wedged"),
        &mountpoint,
        Some("fuse"),
        MsFlags::empty(),
        Some(data.as_str()),
    )
    .expect("mount a daemonless fuse filesystem");
    // The daemon is now gone before it ever served a single request.
    drop(device);

    // Every DIRECT stat of the target, taken before the call under
    // test, so the fixture's wedged-ness is proved rather than
    // assumed.
    let probes = [
        ("metadata", std::fs::metadata(&mountpoint).map(|_| ())),
        (
            "symlink_metadata",
            std::fs::symlink_metadata(&mountpoint).map(|_| ()),
        ),
        ("read_dir", std::fs::read_dir(&mountpoint).map(|_| ())),
    ];
    let result = detach_unmount(&mountpoint);
    let still_mounted = mount_state(&mountpoint);

    let _ = super::umount2(&mountpoint, super::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir_all(&scratch);

    for (name, probe) in probes {
        match probe {
            Err(err) => assert_eq!(
                err.raw_os_error(),
                Some(nix::errno::Errno::ENOTCONN as i32),
                "the fixture must be a WEDGED mount for this test to mean anything; \
                 {name} failed with something other than ENOTCONN: {err}"
            ),
            Ok(()) => panic!(
                "the fixture is not wedged: {name} on the mountpoint succeeded, so \
                 this test cannot show anything about a dead daemon"
            ),
        }
    }
    match result {
        Ok(()) => {}
        Err(other) => panic!(
            "a mount whose FUSE daemon is gone must STILL detach; got {other:?} \
             instead — every filesystem call naming this target fails ENOTCONN, so \
             any probe of it added on the way to umount2 produces exactly this and \
             leaves the wedged mount attached"
        ),
    }
    assert!(
        !still_mounted.expect("read /proc/self/mountinfo to verify the mount's state"),
        "the wedged mount must actually be gone, not merely reported detached"
    );
}

#[test]
fn umount_nofollow_refuses_a_symlinked_target() {
    if !require_root("umount_nofollow_refuses_a_symlinked_target") {
        return;
    }

    let scratch = scratch_dir("symlink");
    let src = scratch.join("src");
    let real_target = scratch.join("real");
    let link = scratch.join("link");
    std::fs::create_dir_all(&src).expect("create bind-mount source");
    std::fs::create_dir_all(&real_target).expect("create bind-mount target");

    mount(
        Some(&src),
        &real_target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .expect("bind mount for the test fixture");
    std::os::unix::fs::symlink(&real_target, &link).expect("create the symlink");

    let result = detach_unmount(&link);
    let still_mounted = mount_state(&real_target);

    // Best-effort cleanup regardless of the assertion below: this
    // must not leave a real mount behind in whatever environment ran
    // it.
    let _ = super::umount2(&real_target, super::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir_all(&scratch);

    // The FINAL component is where `UMOUNT_NOFOLLOW` does its job,
    // and this is the case that flag exists for: the parent is real
    // and canonical, so the guard passes it through, and the kernel
    // refuses the symlinked leaf itself with EINVAL (measured:
    // `umount2(a symlink, UMOUNT_NOFOLLOW)` -> EINVAL, and the SAME
    // call WITHOUT the flag dereferences the symlink and unmounts
    // the real target underneath it instead).
    match result {
        Err(UnmountError::Umount2(errno)) => assert_eq!(
            errno,
            nix::errno::Errno::EINVAL,
            "expected UMOUNT_NOFOLLOW's own refusal"
        ),
        other => panic!(
            "a symlinked target must be REFUSED, not dereferenced; got {other:?} \
             instead — dropping `MntFlags::UMOUNT_NOFOLLOW` makes this exact call \
             succeed and detach the real mount underneath the link"
        ),
    }
    assert!(
        still_mounted.expect("read /proc/self/mountinfo to verify the mount's state"),
        "the real mount under the symlink must survive a refused unmount"
    );
}

/// THE ESCALATION: a symlink in an INTERMEDIATE path component, with
/// the FINAL component real. `UMOUNT_NOFOLLOW` protects only the
/// final component — the kernel still traverses symlinks in every
/// ancestor — so this case is invisible to it. An unprivileged user
/// who owns `link_mid` (here: this test's own scratch directory,
/// standing in for a user-writable ancestor of a real mountpoint) can
/// point it at an ancestor of ANY directory and have a root `gran
/// umount` detach whatever is mounted there instead of the intended
/// target. The parent canonicalisation is what refuses it.
#[test]
fn intermediate_symlink_is_refused_even_though_the_final_component_is_real() {
    if !require_root("intermediate_symlink_is_refused_even_though_the_final_component_is_real") {
        return;
    }

    let scratch = scratch_dir("intermediate-symlink");
    let src = scratch.join("src");
    let real_mid = scratch.join("real_mid");
    let leaf = real_mid.join("leaf");
    let link_mid = scratch.join("link_mid");
    std::fs::create_dir_all(&src).expect("create bind-mount source");
    std::fs::create_dir_all(&leaf).expect("create bind-mount target (leaf is real)");
    std::os::unix::fs::symlink(&real_mid, &link_mid)
        .expect("create the INTERMEDIATE symlink (real_mid <- link_mid)");

    mount(
        Some(&src),
        &leaf,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .expect("bind mount for the test fixture");

    // The FINAL component ("leaf") is real; only the ancestor
    // ("link_mid") is a symlink. This is exactly the shape
    // UMOUNT_NOFOLLOW cannot see.
    let attacker_view = link_mid.join("leaf");

    let result = detach_unmount(&attacker_view);
    let still_mounted = mount_state(&leaf);

    // Best-effort cleanup regardless of the assertion below: this
    // must not leave a real mount behind in whatever environment ran
    // it.
    let _ = super::umount2(&leaf, super::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Err(UnmountError::ParentNotCanonical {
            lexical_parent,
            canonical_parent,
            ..
        }) => {
            assert_eq!(lexical_parent, link_mid);
            assert_eq!(canonical_parent, real_mid);
        }
        other => panic!(
            "a target reached through a symlinked INTERMEDIATE directory must be \
             REFUSED; got {other:?} instead — dropping the parent-canonicalisation \
             comparison lets the kernel traverse `link_mid` and detach the real \
             mount outright, because UMOUNT_NOFOLLOW never protected intermediate \
             components in the first place"
        ),
    }
    assert!(
        still_mounted.expect("read /proc/self/mountinfo to verify the mount's state"),
        "the real mount under the symlinked ancestor must survive a refused unmount"
    );
}

/// THE TRAILING-SLASH BYPASS: a trailing separator on an otherwise
/// symlinked FINAL component defeats `UMOUNT_NOFOLLOW` outright.
/// `std::path::absolute` preserves a trailing `/` (it is lexical
/// only), and the kernel then dereferences the symlinked mountpoint
/// despite the flag (probed directly in a container:
/// `umount2("/tmp/link", MNT_DETACH|UMOUNT_NOFOLLOW)` -> EINVAL,
/// mount survives; `umount2("/tmp/link/", ...)` -> 0, mount gone).
/// `gran umount /mnt/gran/` is the spelling tab-completion produces,
/// so this is not an exotic input.
///
/// The guard removes the separator by CONSTRUCTION rather than
/// detecting it: the path handed to the syscall is rebuilt from a
/// parent and a single component, so it cannot carry one, and
/// `UMOUNT_NOFOLLOW` gets to do its job on the symlinked leaf.
#[test]
fn trailing_slash_on_a_symlinked_target_is_refused() {
    if !require_root("trailing_slash_on_a_symlinked_target_is_refused") {
        return;
    }

    let scratch = scratch_dir("trailing-slash");
    let src = scratch.join("src");
    let real_target = scratch.join("real");
    let link = scratch.join("link");
    std::fs::create_dir_all(&src).expect("create bind-mount source");
    std::fs::create_dir_all(&real_target).expect("create bind-mount target");

    mount(
        Some(&src),
        &real_target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .expect("bind mount for the test fixture");
    std::os::unix::fs::symlink(&real_target, &link).expect("create the symlink");

    let mut with_trailing_slash = link.clone().into_os_string();
    with_trailing_slash.push("/");
    let with_trailing_slash = PathBuf::from(with_trailing_slash);

    let resolved = super::resolve_target(&with_trailing_slash);
    let result = detach_unmount(&with_trailing_slash);
    let still_mounted = mount_state(&real_target);

    // Best-effort cleanup regardless of the assertion below: this
    // must not leave a real mount behind in whatever environment ran
    // it.
    let _ = super::umount2(&real_target, super::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(
        resolved.ok().as_ref(),
        Some(&link),
        "the trailing separator must be gone from the path handed to the syscall — \
         that is what makes UMOUNT_NOFOLLOW effective on the leaf below"
    );
    match result {
        Err(UnmountError::Umount2(errno)) => assert_eq!(
            errno,
            nix::errno::Errno::EINVAL,
            "expected UMOUNT_NOFOLLOW's own refusal"
        ),
        other => panic!(
            "a trailing slash on a symlinked target must be REFUSED; got {other:?} \
             instead — keeping the separator makes the kernel dereference the \
             symlink despite UMOUNT_NOFOLLOW and detach the real mount underneath"
        ),
    }
    assert!(
        still_mounted.expect("read /proc/self/mountinfo to verify the mount's state"),
        "the real mount under the symlink must survive a refused unmount"
    );
}

#[test]
fn eperm_routes_to_the_fusermount_fallback_and_reports_its_failure() {
    if !require_root("eperm_routes_to_the_fusermount_fallback_and_reports_its_failure") {
        return;
    }
    // Drop to an unprivileged uid for the REST of this test's
    // process (relies on nextest's one-process-per-test isolation —
    // see the module doc comment above). An unprivileged caller's
    // raw umount2 on a real directory that is not a mountpoint
    // returns EPERM on Linux (verified: permission is checked before
    // "is this even a mountpoint", so a real, never-mounted directory
    // reaches the exact same EPERM branch a genuine FUSE mount
    // would).
    setuid(Uid::from_raw(65534)).expect("drop to an unprivileged uid");

    // Already created and verified real by scratch_dir — no
    // need to create_dir_all it again here.
    let target = scratch_dir("eperm");

    match detach_unmount(&target) {
        Ok(()) => panic!("must not report success for a real, unmounted directory"),
        // Collapsing the `Err(Errno::EPERM)` and `Err(errno)` arms
        // into one would return this variant directly instead of
        // ever running a fusermount helper.
        Err(UnmountError::Umount2(errno)) => panic!(
            "an unprivileged caller's EPERM must route to the \
             fusermount fallback, not stay a bare Umount2 error; got \
             Umount2({errno})"
        ),
        // The fallback must REPORT each helper's failure rather than
        // swallowing it (`let _ = status; Ok(())` would report a
        // false success).
        Err(UnmountError::FusermountFallbackFailed { attempts }) => {
            assert!(!attempts.is_empty());
            for attempt in &attempts {
                match &attempt.outcome {
                    FusermountOutcome::Failed(status) => assert!(
                        !status.success(),
                        "{} must have actually failed here: {status}",
                        attempt.binary.display()
                    ),
                    outcome @ FusermountOutcome::Spawn(_) => eprintln!(
                        "NOTE: {} not spawnable in this environment ({outcome}); the \
                         EPERM -> fallback routing is confirmed, but this binary's \
                         non-swallowing half is NOT exercised by this run",
                        attempt.binary.display()
                    ),
                }
            }
        }
        Err(UnmountError::NoFusermountHelper { searched }) => eprintln!(
            "NOTE: no fusermount helper installed at {searched:?}; the EPERM -> \
             fallback routing is confirmed, but no helper ran on this machine"
        ),
        Err(other) => panic!("unexpected error: {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&target);
}

#[test]
fn target_spelled_like_a_flag_does_not_report_false_success() {
    if !require_root("target_spelled_like_a_flag_does_not_report_false_success") {
        return;
    }

    let scratch = scratch_dir("flag");
    std::fs::create_dir_all(scratch.join("-V")).expect("create the fixture dir");

    setuid(Uid::from_raw(65534)).expect("drop to an unprivileged uid");
    std::env::set_current_dir(&scratch).expect("chdir into the fixture");

    // "-V" is fusermount3's own version flag. Handed the bare relative
    // path, `fusermount3 -u -z "-V"` parses it as a flag, prints its
    // version, and exits 0 — reporting success having unmounted
    // nothing (reproduced against a real `fusermount3 3.17.2`).
    // detach_unmount resolves the target to an absolute path (this
    // component becomes `<scratch>/-V`, which does not start with
    // `-`) and passes the `--` terminator, so the target is never
    // read as a flag.
    let target = Path::new("-V");
    match detach_unmount(target) {
        Ok(()) => panic!(
            "a target spelled like a flag must not report success — \
             this is exactly the false-success class this module \
             exists to prevent"
        ),
        Err(UnmountError::Umount2(errno)) => panic!(
            "an unprivileged caller must reach the fusermount \
             fallback here, not stay on the raw umount2 error; got \
             Umount2({errno})"
        ),
        Err(UnmountError::FusermountFallbackFailed { attempts }) => {
            for attempt in &attempts {
                match &attempt.outcome {
                    FusermountOutcome::Failed(status) => assert!(!status.success()),
                    outcome @ FusermountOutcome::Spawn(_) => eprintln!(
                        "NOTE: {} not spawnable here ({outcome})",
                        attempt.binary.display()
                    ),
                }
            }
        }
        Err(UnmountError::NoFusermountHelper { searched }) => {
            eprintln!("NOTE: no fusermount helper installed at {searched:?}");
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }

    let _ = std::env::set_current_dir("/");
    let _ = std::fs::remove_dir_all(&scratch);
}

/// A near-no-op `fuser::Filesystem`: every method keeps the trait's
/// own default (an `ENOSYS`/no-op reply) EXCEPT `getattr`, which the
/// kernel needs answered for the root inode before it will even let
/// `open(2)` succeed on the mountpoint — this crate's test needs that
/// open to make the mount busy. The property under test lives
/// entirely in `unmount.rs`, not in filesystem behaviour, so the root
/// directory's attributes themselves are otherwise arbitrary.
#[derive(Debug)]
struct NoopFs;

const ROOT_DIR_ATTR: fuser::FileAttr = fuser::FileAttr {
    ino: fuser::INodeNo::ROOT,
    size: 0,
    blocks: 0,
    atime: std::time::SystemTime::UNIX_EPOCH,
    mtime: std::time::SystemTime::UNIX_EPOCH,
    ctime: std::time::SystemTime::UNIX_EPOCH,
    crtime: std::time::SystemTime::UNIX_EPOCH,
    kind: fuser::FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 0,
    gid: 0,
    rdev: 0,
    blksize: 512,
    flags: 0,
};

impl fuser::Filesystem for NoopFs {
    fn getattr(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        reply.attr(&std::time::Duration::ZERO, &ROOT_DIR_ATTR);
    }
}

#[test]
fn fallback_needs_both_u_and_z_to_lazily_detach_a_busy_fuse_mount() {
    if !require_root("fallback_needs_both_u_and_z_to_lazily_detach_a_busy_fuse_mount") {
        return;
    }
    // Same isolation note as the EPERM test above: drop privilege for
    // the rest of THIS test's process. Reaching detach_unmount's
    // fusermount fallback at all needs umount2 to return EPERM,
    // which only an unprivileged caller gets — as root, umount2
    // succeeds directly and -u/-z are never exercised. The SAME uid
    // must mount and later unmount: fusermount3's own ownership
    // check (an `/etc/mtab` entry recording the mounting uid) refuses
    // -u/-z from any other caller.
    setuid(Uid::from_raw(65534)).expect("drop to an unprivileged uid");

    // Already created and verified real by scratch_dir.
    let mountpoint = scratch_dir("fuse");

    let config = crate::options::session_config(false);
    let session = match fuser::spawn_mount(NoopFs, &mountpoint, &config) {
        Ok(session) => session,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&mountpoint);
            panic!(
                "could not mount the no-op test filesystem (needs \
                 /dev/fuse access and fusermount3 on PATH): {err}"
            );
        }
    };

    let busy_fd = std::fs::File::open(&mountpoint).expect("open the mount to make it busy");

    let result = detach_unmount(&mountpoint);

    drop(busy_fd);
    drop(session);
    let _ = std::fs::remove_dir_all(&mountpoint);

    match result {
        Ok(()) => {}
        Err(other) => panic!(
            "a busy real FUSE mount, unmounted by its own \
             unprivileged owner, must detach via the `fusermount3 -u \
             -z --` fallback; got {other:?} instead — this is what \
             deleting `-u` (fusermount3 refuses the flag combination) \
             or `-z` (a plain unmount on a busy target fails EBUSY) \
             would produce"
        ),
    }
}

// ---- the helper never comes from PATH ------------------------------

/// The production constant is what the production call site passes,
/// and every entry in it must be an absolute path. This is half of
/// "`PATH` is never consulted"; the other half is
/// `a_relative_helper_that_really_exists_is_never_spawned` below, which
/// shows the MECHANISM refuses a non-absolute candidate even if the
/// constant were edited to contain one.
#[test]
fn every_fusermount_candidate_is_an_absolute_path() {
    assert!(
        !super::FUSERMOUNT_CANDIDATES.is_empty(),
        "an empty candidate list would make the fallback unreachable"
    );
    for candidate in super::FUSERMOUNT_CANDIDATES {
        let path = Path::new(candidate);
        assert!(
            path.is_absolute(),
            "`{candidate}` is not absolute, so Command::new would resolve it through \
             the inherited PATH — and this command can run as root"
        );
    }
}

/// A bare helper name is refused and reported as searched, never
/// run: what this row pins is that REPORT — both names, in order, in
/// `NoFusermountHelper`. On its own it cannot tell the `is_absolute()`
/// guard from "the bare name resolves to nothing": `Path::exists`
/// resolves a relative path against the WORKING DIRECTORY, never
/// `PATH`, so with the guard deleted `fusermount3` is still skipped,
/// as absent from whatever directory the test runs in. The row below,
/// whose relative candidate DOES resolve, is what shows the guard is
/// load-bearing.
#[test]
fn a_bare_helper_name_is_never_spawned() {
    let scratch = scratch_dir("bare-name");
    let result =
        super::fusermount_lazy_unmount_with(&["fusermount3", "fusermount"], &scratch.join("mnt"));
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Err(UnmountError::NoFusermountHelper { searched }) => assert_eq!(
            searched,
            vec![PathBuf::from("fusermount3"), PathBuf::from("fusermount")]
        ),
        other => panic!(
            "a bare binary name must never be spawned — `Command::new(\"fusermount3\")` \
             searches the INHERITED PATH, and this command can run as root; got \
             {other:?}"
        ),
    }
}

/// The mechanism, not the constant: a candidate that RESOLVES to a
/// real, executable helper is still refused if it is not spelled as
/// an ABSOLUTE path. That is what makes "`PATH` is never consulted" a
/// property of the code rather than of how the constant happens to be
/// spelled today.
///
/// The relative spelling is built from the working directory rather
/// than by changing it: one `..` per component of the current
/// directory reaches `/` (a `..` too many is a no-op there), then the
/// fake's own components follow, so it names the very script the
/// absolute path does. The precondition checks that it does, with the
/// same `exists()` test the mechanism applies, and the row refuses if
/// the working directory differs at its end from its start.
///
/// That check is not a guard against a shared process, and nothing
/// here is: this file relies on nextest's process-per-test isolation.
/// `target_spelled_like_a_flag_does_not_report_false_success` drops the
/// process to uid 65534 for good, changes into its scratch directory,
/// and ends at `/` — or, if it panics first, inside that removed
/// directory. Under a runner that shares one process, this row could
/// then see its candidate name nothing (and pass without testing the
/// guard), fail on the working-directory check, or fail to write its
/// fixture at all, depending on order.
///
/// The fake exits 0 and logs each run, so a spawn shows up both as a
/// success and in the log.
#[test]
fn a_relative_helper_that_really_exists_is_never_spawned() {
    let scratch = scratch_dir("relative-helper");
    let log = scratch.join("relative_log");
    let fake = scratch.join("fusermount3");
    write_fake_helper(&fake, "fusermount3", &log, 0);
    let cwd = std::env::current_dir().expect("read the working directory");
    let mut relative = PathBuf::new();
    for _ in cwd.components() {
        relative.push("..");
    }
    for component in fake.components() {
        if let std::path::Component::Normal(part) = component {
            relative.push(part);
        }
    }
    // Without this the row could pass on "the file does not exist",
    // which is exactly what the bare-name row above cannot rule out.
    let resolves = relative.exists();
    let candidate = relative.to_str().expect("utf-8 scratch path");
    let result = if resolves {
        Some(super::fusermount_lazy_unmount_with(
            &[candidate],
            &scratch.join("mnt"),
        ))
    } else {
        None
    };
    let cwd_after = std::env::current_dir().expect("read the working directory");

    let invocations = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&scratch);

    assert!(
        resolves,
        "fixture precondition: {relative:?} must resolve to the fake at {fake:?}"
    );
    assert_eq!(
        cwd_after, cwd,
        "the working directory moved while this row ran, so its relative candidate may have \
         named nothing"
    );
    match result.expect("the precondition above held, so the mechanism ran") {
        Err(UnmountError::NoFusermountHelper { searched }) => {
            assert_eq!(searched, vec![relative]);
        }
        other => panic!(
            "a relative candidate must be refused even when it resolves to a real \
             helper — spawning it depends on the working directory; got {other:?}"
        ),
    }
    assert_eq!(
        invocations, "",
        "the refused helper must never have run; invocation log: {invocations:?}"
    );
}

/// The production entry point reports which binary it actually ran,
/// and every one of them must have come from the fixed absolute
/// list. Reverting the fallback to `Command::new("fusermount3")`
/// makes the reported binary a bare name and fails this outright.
#[test]
fn the_production_fallback_only_runs_candidates_from_the_fixed_list() {
    let scratch = scratch_dir("production-candidates");

    // A real directory that is not a mountpoint: every installed
    // helper will refuse it, so this exercises the reporting path
    // without detaching anything.
    let result = super::fusermount_lazy_unmount(&scratch);
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Ok(()) => panic!("a helper must not report success on a directory that is not a mount"),
        Err(UnmountError::FusermountFallbackFailed { attempts }) => {
            for attempt in &attempts {
                assert!(
                    attempt.binary.is_absolute(),
                    "ran a non-absolute helper `{}` — that is a PATH lookup",
                    attempt.binary.display()
                );
                assert!(
                    super::FUSERMOUNT_CANDIDATES
                        .iter()
                        .any(|candidate| Path::new(candidate) == attempt.binary),
                    "ran `{}`, which is not in FUSERMOUNT_CANDIDATES",
                    attempt.binary.display()
                );
            }
        }
        Err(UnmountError::NoFusermountHelper { searched }) => assert_eq!(
            searched.len(),
            super::FUSERMOUNT_CANDIDATES.len(),
            "the searched list must be exactly the fixed candidate list"
        ),
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

/// When no candidate path exists, the fallback says so by name
/// rather than falling through to a `PATH` lookup or reporting a
/// spurious spawn failure.
#[test]
fn no_candidate_existing_reports_which_paths_were_searched() {
    let scratch = scratch_dir("no-helper");
    let absent3 = scratch.join("absent-fusermount3");
    let absent = scratch.join("absent-fusermount");
    let candidates = [
        absent3.to_str().expect("utf-8 scratch path"),
        absent.to_str().expect("utf-8 scratch path"),
    ];

    let result = super::fusermount_lazy_unmount_with(&candidates, &scratch.join("mnt"));
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Err(UnmountError::NoFusermountHelper { searched }) => {
            assert_eq!(searched, vec![absent3, absent]);
        }
        other => panic!("expected NoFusermountHelper, got {other:?}"),
    }
}

// ---- fusermount3 falls back to plain fusermount --------------------
//
// Both tests below call `super::fusermount_lazy_unmount_with`
// directly rather than going through `detach_unmount`+EPERM — that
// dispatch is already covered by the EPERM and flag tests above, and
// these two need no root and no real mount: they are unit tests of
// "try each candidate in order, stop at the first success, report
// every failure otherwise", the code `unmount.rs` owns rather than
// kernel behaviour.
//
// Neither test can be exercised with the REAL system binaries: a
// stock `fuse3` install makes `fusermount` a symlink to
// `fusermount3` (same inode, same behaviour always), so a genuine
// asymmetric outcome between the two names does not exist to
// observe. Each test therefore writes its OWN fake pair into its own
// `scratch_dir` and passes their absolute paths to the injectable
// seam — no external harness, no `PATH`, and no skip.

#[test]
fn fusermount3_failing_falls_back_to_plain_fusermount_and_succeeds() {
    let scratch = scratch_dir("fallback-dispatch-ok");
    let log = scratch.join("fallback_log");
    let fake3 = scratch.join("fusermount3");
    let fake = scratch.join("fusermount");
    write_fake_helper(&fake3, "fusermount3", &log, 1);
    write_fake_helper(&fake, "fusermount", &log, 0);
    let candidates = [
        fake3.to_str().expect("utf-8 scratch path"),
        fake.to_str().expect("utf-8 scratch path"),
    ];

    let result = super::fusermount_lazy_unmount_with(&candidates, &scratch.join("mnt"));

    let invocations = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Ok(()) => {}
        Err(other) => panic!(
            "fusermount3 failing must fall back to plain fusermount \
             and succeed; got {other:?} instead — this is what \
             stopping at the first failing candidate would produce; \
             invocation log: {invocations:?}"
        ),
    }
    assert_eq!(
        invocations, "fusermount3:1\nfusermount:0\n",
        "expected fusermount3 to be tried before fusermount, exactly \
         once each; invocation log was: {invocations:?}"
    );
}

#[test]
fn both_fusermount_binaries_failing_reports_both_failures() {
    let scratch = scratch_dir("fallback-dispatch-both-fail");
    let log = scratch.join("fallback_log");
    let fake3 = scratch.join("fusermount3");
    let fake = scratch.join("fusermount");
    // Distinct, deliberately weird exit codes: if the combined error
    // ever collapsed to reporting only one attempt, or reported the
    // same status twice, these would not both show up distinctly.
    write_fake_helper(&fake3, "fusermount3", &log, 3);
    write_fake_helper(&fake, "fusermount", &log, 5);
    let candidates = [
        fake3.to_str().expect("utf-8 scratch path"),
        fake.to_str().expect("utf-8 scratch path"),
    ];

    let result = super::fusermount_lazy_unmount_with(&candidates, &scratch.join("mnt"));

    let invocations = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&scratch);

    match result {
        Err(UnmountError::FusermountFallbackFailed { attempts }) => {
            let codes: Vec<(PathBuf, Option<i32>)> = attempts
                .iter()
                .map(|attempt| {
                    let code = match &attempt.outcome {
                        FusermountOutcome::Failed(status) => status.code(),
                        FusermountOutcome::Spawn(_) => None,
                    };
                    (attempt.binary.clone(), code)
                })
                .collect();
            assert_eq!(
                codes,
                vec![(fake3, Some(3)), (fake, Some(5))],
                "each helper's own absolute path and exit code must survive"
            );
        }
        other => panic!(
            "when every candidate fails, EVERY failure must be reported \
             distinctly; got {other:?} instead — this is what \
             reporting only the last attempt (or only the first) \
             would produce; invocation log: {invocations:?}"
        ),
    }
    assert_eq!(
        invocations, "fusermount3:3\nfusermount:5\n",
        "expected both fake helpers to be tried exactly once each; \
         invocation log was: {invocations:?}"
    );
}
