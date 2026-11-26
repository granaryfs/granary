// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![cfg(target_os = "linux")]

//! How a writable session ends under the kernel's own unmounts: a plain
//! unmount with nothing held runs `destroy` once, one with a descriptor held
//! is refused by the kernel, and a mount's identity follows it when it moves.

use super::*;
use crate::MountIdentity;

/// How long a row waits for a session to end before it names the hang.
const SESSION_END: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(5);

/// Wait until `alive` answers false, or name the hang. Bounded by a count
/// of polls, each a receive that never arrives, as the session guard waits.
fn wait_ended(what: &str, alive: impl Fn() -> bool) {
    let (_never, poll) = std::sync::mpsc::channel::<()>();
    for _ in 0..SESSION_END.as_millis() / POLL.as_millis() {
        if !alive() {
            return;
        }
        let _ = poll.recv_timeout(POLL);
    }
    assert!(!alive(), "{what}: the session never ended");
}

/// A writable adapter over the opcode fixture, counting its shutdowns.
fn counted() -> (GranaryFs<Backend>, Arc<AtomicU32>) {
    let (snapshot, backend, _) = fixture();
    let shutdowns = backend.shutdowns.clone();
    let fs = GranaryFs::new(snapshot, backend, 1, crate::MountWritability::Writable).unwrap();
    (fs, shutdowns)
}

/// A plain unmount with nothing held, after twenty handles were opened and
/// closed, ends the session every time: `destroy` runs the backend's
/// shutdown exactly once, and the cleanup classifies the end clean, a
/// teardown race with the mount gone included.
#[test]
fn writable_linux_plain_umount_runs_destroy_once() {
    let name = "writable_linux_plain_umount_runs_destroy_once";
    if !require_root(name) {
        return;
    }
    let mut cases = 0;
    for cycle in 0..20 {
        let (fs, shutdowns) = counted();
        let (mountpoint, guard) = spawn_guarded(name, fs, crate::writable_session_config());
        for _ in 0..20 {
            drop(std::fs::File::open(at(&mountpoint, N_FILE)).unwrap());
        }
        let unmounted = nix::mount::umount(&mountpoint);
        wait_ended(name, || guard.daemon_alive());
        assert_eq!(
            (unmounted, shutdowns.load(Ordering::SeqCst)),
            (Ok(()), 1),
            "cycle {cycle}: (the plain unmount, shutdowns)"
        );
        guard.teardown();
        cases += 1;
    }
    assert_eq!(cases, 20);
}

/// A plain unmount of a mount with a descriptor held is refused by the
/// kernel, `EBUSY`, before the daemon learns anything: the mount stays
/// listed, `destroy` has not run, and the mount still serves. Once the
/// descriptor is closed the same unmount succeeds and `destroy` runs once.
#[test]
fn writable_linux_busy_plain_umount_is_refused_by_the_kernel() {
    let name = "writable_linux_busy_plain_umount_is_refused_by_the_kernel";
    if !require_root(name) {
        return;
    }
    let (fs, shutdowns) = counted();
    let (mountpoint, guard) = spawn_guarded(name, fs, crate::writable_session_config());
    let held = std::fs::File::open(at(&mountpoint, N_FILE)).unwrap();
    let refused = nix::mount::umount(&mountpoint);
    let busy = (
        refused,
        mount_state(&mountpoint).ok(),
        shutdowns.load(Ordering::SeqCst),
        observe_root_names(&mountpoint).contains(N_FILE),
    );
    drop(held);
    let unmounted = nix::mount::umount(&mountpoint);
    wait_ended(name, || guard.daemon_alive());
    assert_eq!(
        (busy, unmounted, shutdowns.load(Ordering::SeqCst)),
        (
            (Err(nix::errno::Errno::EBUSY), Some(true), 0, true),
            Ok(()),
            1
        ),
        "((held unmount, listed, shutdowns, a listing served), the unmount once closed, \
         shutdowns)"
    );
    guard.teardown();
}

/// A private tmpfs at `path`, so a mount beneath it can be moved: the
/// kernel refuses to move a mount whose parent propagates.
fn private_tmpfs(path: &Path) {
    nix::mount::mount(
        Some("tmpfs"),
        path,
        Some("tmpfs"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    )
    .unwrap();
    nix::mount::mount(
        None::<&str>,
        path,
        None::<&str>,
        nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .unwrap();
}

/// A mount's identity is its superblock's device, kept across a
/// `mount --move` and a renamed parent: it is still listed after each, while
/// a test of the old path reads the moved mount as gone. Once unmounted it
/// is not listed.
#[test]
fn mount_identity_follows_a_moved_mount() {
    let name = "mount_identity_follows_a_moved_mount";
    if !require_root(name) {
        return;
    }
    let root = scratch_dir(name);
    private_tmpfs(&root);
    let first = root.join("first");
    let parent = root.join("parent");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir_all(parent.join("moved")).unwrap();
    let (fs, _) = counted();
    let session = fuser::spawn_mount(fs, &first, &crate::writable_session_config()).unwrap();
    let mut guard = SessionGuard::new(session, &first);
    let identity = MountIdentity::capture(&first).unwrap();
    let moved = parent.join("moved");
    nix::mount::mount(
        Some(&first),
        &moved,
        None::<&str>,
        nix::mount::MsFlags::MS_MOVE,
        None::<&str>,
    )
    .unwrap();
    let after_move = (identity.listed().ok(), mount_state(&first).ok());
    let renamed = root.join("renamed");
    std::fs::rename(&parent, &renamed).unwrap();
    let after_rename = identity.listed().ok();
    let at_moved_before = identity.listed_at(&renamed.join("moved")).ok();
    detach_unmount(&renamed.join("moved")).unwrap();
    wait_ended(name, || guard.daemon_alive());
    // Asked at the moved path: a parallel test's mount can take the freed
    // device number at once, and `listed` would read that mount as this one.
    let after_unmount = identity.listed_at(&renamed.join("moved")).ok();
    // The session has ended and its mount is gone at every path, so the
    // cleanup's own detach of the old path finds nothing and the end is
    // clean.
    let cleaned = guard.finish().map_err(|error| error.to_string());
    nix::mount::umount(&root).unwrap();
    std::fs::remove_dir(&root).unwrap();
    assert_eq!(
        (
            after_move,
            after_rename,
            (at_moved_before, after_unmount),
            cleaned
        ),
        (
            (Some(true), Some(false)),
            Some(true),
            (Some(true), Some(false)),
            Ok(())
        ),
        "((listed after the move, the old path's mount state), listed after the rename, \
         (at the moved path before and after the unmount), cleanup)"
    );
}
