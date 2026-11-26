// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A landing installed as the kernel's view: identities kept and re-keyed,
//! held descriptors on replaced paths, and a closed view's revocation.

use super::super::super::commit_lane::publish_head;
use super::*;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

/// How long a row waits for a detached revocation to reach the kernel.
const REVOKE_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Every path under `root` with its inode number and modification time.
fn identities(root: &Path) -> BTreeMap<std::path::PathBuf, (u64, i64, i64)> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.push(path.clone());
            }
            found.insert(
                path,
                (metadata.ino(), metadata.mtime(), metadata.mtime_nsec()),
            );
        }
    }
    found
}

pub(super) fn errno<T>(result: std::io::Result<T>) -> Result<(), Option<i32>> {
    result.map(drop).map_err(|error| error.raw_os_error())
}

fn daemon_reads(fixture: &SyncMount) -> usize {
    fixture
        .observer
        .callback_results()
        .iter()
        .filter(|(callback, _)| matches!(callback, Callback::Read))
        .count()
}

/// Plant a root at `seq`, validly signed by the volume's key, in the
/// mount's cache, so a landing there is an equivocation.
fn plant_equivocation(fixture: &SyncMount, seq: u64) {
    let forged = super::super::super::super::sign_root(
        &fixture.tree,
        &fixture.tree.key,
        &fixture.tree.volume,
        seq,
        1,
        [0xAA; 16],
    );
    let path = fixture
        .paths
        .cache
        .join("roots")
        .join(fixture.tree.volume.as_str())
        .join(format!("{seq:020}"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, forged).unwrap();
}

/// What a held descriptor whose pages the kernel caches sees when a landing
/// closes the view: (its second read before the landing was answered from
/// the cache, the landing's refusal, a later read reached the daemon as a
/// READ, that read's answer). The pages are not dropped first: only the
/// revocation can make the read reach the daemon.
fn revoked_read(fixture: &SyncMount, route: &str) -> (bool, String, bool, Result<(), Option<i32>>) {
    let file = fixture.file();
    file.write_at(b"commit-route", 0).unwrap();
    let mut buffer = [0_u8; 8];
    file.read_at(&mut buffer, 0).unwrap();
    let before = daemon_reads(fixture);
    file.read_at(&mut buffer, 0).unwrap();
    let cached = daemon_reads(fixture) == before;
    let lane = fixture.construct_commit(70).unwrap();
    if route == "after_switch" {
        fixture.faults().arm(
            "fuse.view.install",
            "after_switch",
            1,
            crate::FaultAction::Fail,
        );
    } else {
        plant_equivocation(fixture, 2);
    }
    let result = fixture.drive_commit(&lane, 80);
    let outcome = result
        .as_ref()
        .err()
        .map_or_else(|| "landed".to_owned(), ToString::to_string);
    // The sends are detached: read until one reaches the daemon.
    let deadline = std::time::Instant::now() + REVOKE_BOUND;
    let (reached, answer) = loop {
        let reads = daemon_reads(fixture);
        let answer = errno(file.read_at(&mut buffer, 0));
        if daemon_reads(fixture) > reads {
            break (true, answer);
        }
        if std::time::Instant::now() >= deadline {
            break (false, answer);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    drop(file);
    (cached, outcome, reached, answer)
}

#[test]
fn writable_linux_view_notifier_reaches_the_kernel() {
    if !venue("writable_linux_view_notifier_reaches_the_kernel") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let (cached, outcome, reached, _) = revoked_read(&fixture, "after_switch");
    assert_eq!(
        (cached, outcome.as_str(), reached),
        (true, "landed", true),
        "(premise: a cached read sent no READ; the landing stands; after the \
         invalidation the held read reached the daemon)"
    );
    fixture.finish();
}

#[test]
fn writable_linux_view_closed_view_revokes_held_pages() {
    if !venue("writable_linux_view_closed_view_revokes_held_pages") {
        return;
    }
    let deadline = sync_deadline();
    let mut cases = 0;
    for (route, expected) in [
        ("after_switch", "landed"),
        ("equivocation", "intent refused: ViewRootEquivocation"),
    ] {
        let fixture = SyncMount::new(deadline);
        let observed = revoked_read(&fixture, route);
        assert_eq!(
            observed,
            (true, expected.to_owned(), true, Err(Some(5))),
            "{route}: (premise: a cached read sent no READ; the landing's outcome; the held \
             read reached the daemon; its answer)"
        );
        fixture.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_view_own_landing_keeps_identities_and_held_handles() {
    if !venue("writable_linux_view_own_landing_keeps_identities_and_held_handles") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let file = fixture.file();
    file.write_at(b"commit-route", 0).unwrap();
    let before = identities(&fixture.paths.mountpoint);
    let lane = fixture.construct_commit(70).unwrap();
    let first = fixture.drive_commit(&lane, 80);
    let after = identities(&fixture.paths.mountpoint);
    let written = errno(file.write_at(b"after-landing", 0));
    let mut read = [0_u8; 13];
    let reread = errno(file.read_exact_at(&mut read, 0));
    let lane = fixture.construct_commit(71).unwrap();
    let second = fixture.drive_commit(&lane, 81);
    assert_eq!(
        (
            landed(&first),
            before.len() > 4 && before == after,
            written,
            reread,
            read.as_slice(),
            landed(&second),
            fixture.remote_seq(),
            fixture.bytes(b"f.txt").starts_with(b"after-landing"),
        ),
        (
            true,
            true,
            Ok(()),
            Ok(()),
            b"after-landing".as_slice(),
            true,
            3,
            true
        ),
        "an own landing moves no inode or time; the held descriptor keeps reading and \
         writing, and the next commit carries its write: before {before:?}, after {after:?}"
    );
    drop(file);
    fixture.finish();
}

#[test]
fn writable_linux_view_coalescer_landing_installs() {
    if !venue("writable_linux_view_coalescer_landing_installs") {
        return;
    }
    let fixture = SyncMount::live(sync_deadline(), crate::SyncOptions::default());
    let before = identities(&fixture.paths.mountpoint);
    let file = fixture.file();
    file.write_at(b"live-commit", 0).unwrap();
    drop(file);
    fixture.mark_close();
    fixture.wait("live landing", || super::remote::pin_seq(&fixture) == 2);
    fixture.assert_saw_commit();
    let after = identities(&fixture.paths.mountpoint);
    let file = fixture.file();
    let sync = errno(file.sync_all());
    assert_eq!(
        (
            before == after,
            super::remote::pin_seq(&fixture),
            fixture.remote_seq(),
            sync,
        ),
        (true, 2, 2, Ok(())),
        "(stable identities, served sequence, authority sequence, later fsync)"
    );
    drop(file);
    fixture.finish();
}

#[test]
fn writable_linux_view_refresh_window_serves_reads_and_writes() {
    if !venue("writable_linux_view_refresh_window_serves_reads_and_writes") {
        return;
    }
    let fixture = SyncMount::live(sync_deadline(), crate::SyncOptions::default());
    let faults = fixture.faults();
    faults.arm(
        "sync.commit",
        "landed_refresh",
        1,
        crate::FaultAction::Block,
    );
    let _resume = Resume(faults.clone());
    let first = fixture.file();
    first.write_at(b"refresh-base", 0).unwrap();
    drop(first);
    fixture.wait("landed-refresh fault", || {
        faults
            .sync_fired()
            .iter()
            .any(|event| event.name == "sync.commit" && event.phase == "landed_refresh")
    });
    let root = &fixture.paths.mountpoint;
    let listed = std::fs::read_dir(root)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map(drop);
    let metadata = std::fs::metadata(root.join("f.txt")).map(drop);
    let second = fixture.file();
    let written = second.write_at(b"refresh-window", 0).map(drop);
    let held = super::remote::pin_seq(&fixture);
    faults.resume();
    fixture.wait("refreshed landing", || {
        super::remote::pin_seq(&fixture) == 2
    });
    let installed = super::remote::pin_seq(&fixture);
    let synced = second.sync_all();
    fixture.wait("carried landing", || super::remote::pin_seq(&fixture) == 3);
    let carried = fixture.bytes(b"f.txt").starts_with(b"refresh-window");
    assert_eq!(
        (
            errno(listed),
            errno(metadata),
            errno(written),
            held,
            installed,
            errno(synced),
            fixture.remote_seq(),
            carried,
        ),
        (Ok(()), Ok(()), Ok(()), 1, 2, Ok(()), 3, true,),
        "(listing, metadata and second-handle write in the held refresh; pinned landing; \
         next commit and its carried write)"
    );
    drop(second);
    fixture.finish();
}

#[test]
fn writable_linux_view_unknown_outcome_keeps_view_until_landing() {
    if !venue("writable_linux_view_unknown_outcome_keeps_view_until_landing") {
        return;
    }
    let options = crate::SyncOptions {
        resolution_bound: std::time::Duration::from_secs(3),
        quiesce_delay: std::time::Duration::ZERO,
        max_coalesce_delay: std::time::Duration::ZERO,
        ..crate::SyncOptions::default()
    };
    let fixture = SyncMount::live_unscaled(sync_deadline(), options);
    fixture.state.lock().unwrap().reply_delay = Some(std::time::Duration::from_secs(6));
    // Keep live recovery from sharing the root-read interval attributed to fsync.
    let retry_held = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let held = Arc::clone(&retry_held);
    let (release_retry, released) = std::sync::mpsc::sync_channel(0);
    fixture.engine.after_live_retry_read_for_test(move || {
        held.store(true, std::sync::atomic::Ordering::Release);
        released.recv().unwrap();
    });
    let root = fixture.paths.mountpoint.clone();
    let file = fixture.file();
    file.write_at(b"unknown-outcome", 0).unwrap();
    let inode = file.metadata().unwrap().ino();
    drop(file);
    fixture.mark_close();
    let staged = fixture.bytes(b"f.txt");

    fixture.wait("held live retry", || {
        retry_held.load(std::sync::atomic::Ordering::Acquire)
    });
    assert_eq!(
        (
            fixture.remote_seq(),
            fixture.engine.live_pauses_for_test().is_empty(),
        ),
        (2, false),
        "the held retry follows the unknown-outcome publication and pause"
    );
    let faults = fixture.faults();
    faults.trace_sync();
    {
        let mut state = fixture.state.lock().unwrap();
        state
            .root_fault
            .insert(2, RootStoreError::Backend("connection refused".to_owned()));
    }
    let unresolved_view = (
        super::remote::pin_seq(&fixture),
        std::fs::metadata(root.join("f.txt")).unwrap().ino(),
        fixture.bytes(b"f.txt"),
        super::remote::view_xattr(&root),
    );
    let root_reads_before_fsync = fixture.state.lock().unwrap().root_reads;
    let unresolved_fsync = errno(fixture.file().sync_all());
    let root_reads_during_fsync =
        fixture.state.lock().unwrap().root_reads - root_reads_before_fsync;
    let unresolved = (
        unresolved_view,
        unresolved_fsync,
        fixture.observer.sync_results(),
        faults
            .sync_fired()
            .iter()
            .filter(|event| event.name == "sync.commit_wait" && event.phase == "before")
            .map(|event| event.occurrence)
            .collect::<Vec<_>>(),
        root_reads_during_fsync,
    );
    fixture.state.lock().unwrap().root_fault.remove(&2);
    release_retry.send(()).unwrap();
    fixture.wait("recovered landing", || {
        super::remote::pin_seq(&fixture) == 2
    });
    let landed = (
        super::remote::pin_seq(&fixture),
        super::remote::view_xattr(&root),
        errno(fixture.file().sync_all()),
    );
    assert_eq!(
        (unresolved, landed),
        (
            (
                (1, inode, staged, "fresh:1".to_owned()),
                Err(Some(5)),
                vec![(
                    Callback::Fsync,
                    CallbackOutcome::Failed(granary_fuse::MountError::Unavailable),
                )],
                (1..=u64::from(crate::STARTUP_ATTEMPTS)).collect::<Vec<_>>(),
                0,
            ),
            (2, "fresh:2".to_owned(), Ok(())),
        ),
        "(((served sequence, inode, bytes, view label), fsync, recorded fsync, commit-wait poll \
         occurrences, root reads during fsync) while the landed publication's reply is unresolved; \
         (served sequence, view label, fsync) after recovery)"
    );
    fixture.finish();
}

#[test]
fn writable_linux_view_resolution_bound_outlives_pre_publish_stall() {
    if !venue("writable_linux_view_resolution_bound_outlives_pre_publish_stall") {
        return;
    }
    let resolution_bound = std::time::Duration::from_secs(3);
    let pre_publish_hold = std::time::Duration::from_millis(400);
    let dispatch_margin = resolution_bound.saturating_sub(pre_publish_hold);
    let options = crate::SyncOptions {
        resolution_bound,
        quiesce_delay: std::time::Duration::ZERO,
        max_coalesce_delay: std::time::Duration::ZERO,
        ..crate::SyncOptions::default()
    };
    let fixture = SyncMount::live_unscaled(sync_deadline(), options);
    fixture.state.lock().unwrap().reply_delay = Some(std::time::Duration::from_secs(6));
    let faults = fixture.faults();
    faults.arm_repeated(
        "sync.commit",
        "before_submit",
        std::num::NonZeroU64::new(2).unwrap(),
        crate::FaultAction::Block,
    );
    let _resume = Resume(faults.clone());
    let file = fixture.file();
    file.write_at(b"bounded-stall", 0).unwrap();
    drop(file);
    fixture.wait("pre-publish stall", || {
        faults
            .sync_fired()
            .iter()
            .any(|event| event.name == "sync.commit" && event.phase == "before_submit")
    });
    std::thread::sleep(pre_publish_hold);
    faults.resume_one();
    fixture.wait("unknown-outcome pause", || {
        !fixture.engine.live_pauses_for_test().is_empty()
    });
    let records = fixture.timeline_records();
    let output = records.join("\n");
    let unavailable = records
        .iter()
        .filter(|line| {
            line.contains("\"event\":\"op.failed\"")
                && line.contains("\"kind\":\"commit\"")
                && line.contains("\"class\":\"unavailable\"")
        })
        .count();
    let published = output.matches("\"event\":\"op.publish_bound\"").count();
    assert_eq!(
        (unavailable, fixture.remote_seq(), published),
        (1, 2, 1),
        "(unavailable commit failures, authority sequence, bounded publications) at the first \
         live pause with {dispatch_margin:?} dispatch margin; events={output}"
    );
    fixture.finish();
}

#[test]
fn writable_linux_view_production_start_commits_on_its_own() {
    if !venue("writable_linux_view_production_start_commits_on_its_own") {
        return;
    }
    let paths = Arc::new(Paths::new());
    let tree = mounted_operation_tree();
    let parts = writable_fixture_core(
        crate::SyncProfile::default(),
        crate::ViewMode::Default,
        None,
        true,
        None,
        &paths,
        &tree,
        |ready, _, state, _| {
            let mut attachment = ready.attach();
            let runtime = attachment
                .start_sync(Arc::new(Time(state.clone())))
                .map_err(|error| format!("{error:?}"))?;
            let shutdown = attachment
                .shutdown_handle()
                .ok_or_else(|| "the production start has no shutdown".to_owned())?;
            Ok((attachment, runtime, shutdown))
        },
    )
    .unwrap();
    let WritableFixtureCore {
        mut attachment,
        sync_runtime,
        control,
        shutdown,
    } = parts;
    let state = Arc::clone(control.state());
    let faults = control.faults().clone();
    let mediator = control.mediator().clone();
    let sends = state.lock().unwrap().sends.len();
    let binding = attachment.backend.take_view_binding().unwrap();
    let (backend, observer) = indexed::observed(attachment.backend, None);
    observer.capture_events();
    let session = granary_fuse::spawn_writable_session(
        attachment.snapshot,
        backend,
        1,
        &paths.mountpoint,
        &granary_fuse::writable_session_config(),
        |view| {
            binding
                .bind(view, indexed::Measured::backend)
                .map_err(|error| std::io::Error::other(error.to_string()))
        },
    )
    .unwrap();
    let recovery = faults.clone();
    let mut mount = SessionGuard::with_recovery(
        session,
        &paths.mountpoint,
        session_guard::TEST_BOUND,
        session_guard::engine_join_bound(None),
        move || recovery.resume(),
    );
    std::fs::write(paths.mountpoint.join("production-live.txt"), b"live").unwrap();
    let started = std::time::Instant::now();
    loop {
        let landed = state.lock().unwrap().sends.len() > sends;
        let installed = mediator
            .with(|store| store.mount_base().map(|(_, seq)| seq == 2))
            .unwrap();
        if landed && installed {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the production binding did not commit and install"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    mount.finish().unwrap();
    drop(sync_runtime);
    assert_eq!(
        shutdown.report().map(|report| report.outcome),
        Some(crate::ShutdownOutcome::Clean),
        "the production runtime's bounded shutdown"
    );
}

#[test]
fn writable_linux_view_rebased_landing_rekeys_head_changed_paths() {
    if !venue("writable_linux_view_rebased_landing_rekeys_head_changed_paths") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    // The local change is on a path the head leaves alone.
    std::fs::write(root.join("local.txt"), b"local").unwrap();
    let mut same_size = FILE_CONTENT.to_vec();
    same_size[..4].copy_from_slice(b"head");
    let resized = b"a head file of another size\n".to_vec();
    let open = |name: &str| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(name))
            .unwrap()
    };
    let held = [
        ("sub/g.txt", open("sub/g.txt"), same_size.clone()),
        ("f.txt", open("f.txt"), resized.clone()),
    ];
    let inodes: Vec<_> = held
        .iter()
        .map(|(_, file, _)| file.metadata().unwrap().ino())
        .collect();
    let lane = fixture.construct_commit(70).unwrap();
    publish_head(&fixture.tree, &fixture.runtime, &resized, |source| {
        std::fs::write(source.join("sub/g.txt"), &same_size).unwrap();
    });
    let result = fixture.drive_commit(&lane, 80);
    assert!(
        landed(&result) && fixture.remote_seq() == 3,
        "premise: a rebased landing; got {result:?}"
    );
    let mut observed = Vec::new();
    for ((name, file, new), old_ino) in held.iter().zip(inodes) {
        let mut old = vec![0_u8; FILE_CONTENT.len()];
        let read = errno(file.read_exact_at(&mut old, 0));
        observed.push((
            *name,
            std::fs::metadata(root.join(name)).unwrap().ino() != old_ino,
            std::fs::read(root.join(name)).unwrap() == *new,
            read,
            old == FILE_CONTENT,
            errno(file.write_at(b"stale", 0)),
            errno(file.set_len(3)),
            errno(file.set_permissions(std::fs::Permissions::from_mode(0o755))),
        ));
    }
    let stale = Err(Some(116));
    assert_eq!(
        observed,
        vec![
            ("sub/g.txt", true, true, Ok(()), true, stale, stale, stale),
            ("f.txt", true, true, Ok(()), true, stale, stale, stale),
        ],
        "(fresh inode, fresh open reads the head, held read, held bytes are the old, write, \
         ftruncate, fchmod)"
    );
    drop(held);
    fixture.finish();
}

#[test]
fn writable_linux_view_local_rename_then_landing_keeps_target_identity() {
    if !venue("writable_linux_view_local_rename_then_landing_keeps_target_identity") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    std::fs::rename(root.join("sub/g.txt"), root.join("sub/renamed.txt")).unwrap();
    let target = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("sub/renamed.txt"))
        .unwrap();
    let ino = target.metadata().unwrap().ino();
    let lane = fixture.construct_commit(70).unwrap();
    let result = fixture.drive_commit(&lane, 80);
    assert_eq!(
        (
            landed(&result),
            std::fs::metadata(root.join("sub/renamed.txt"))
                .unwrap()
                .ino()
                == ino,
            errno(target.write_at(b"kept", 0)),
            errno(target.metadata()),
        ),
        (true, true, Ok(()), Ok(())),
        "a local rename's target keeps its identity, and its held descriptor stays attached"
    );
    drop(target);
    fixture.finish();
}

/// An inode the mount's own rebased landing replaced answers `ESTALE` at
/// OPEN, as one a pickup replaced does. A path open never meets it: the
/// kernel's revalidating LOOKUP finds the new inode, so the daemon answers
/// that open's one OPEN. An open of the held descriptor's `/proc` link
/// reaches the replaced inode itself and answers `ESTALE`.
#[test]
fn writable_linux_view_own_landing_replaced_inode_answers_estale_at_open() {
    use std::os::fd::AsRawFd as _;
    if !venue("writable_linux_view_own_landing_replaced_inode_answers_estale_at_open") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    std::fs::write(root.join("local.txt"), b"local").unwrap();
    let held = std::fs::File::open(root.join("sub/g.txt")).unwrap();
    let mut same_size = FILE_CONTENT.to_vec();
    same_size[..4].copy_from_slice(b"head");
    let lane = fixture.construct_commit(70).unwrap();
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), &same_size).unwrap();
    });
    let result = fixture.drive_commit(&lane, 80);
    assert!(
        landed(&result) && fixture.remote_seq() == 3,
        "premise: a rebased landing; got {result:?}"
    );
    let from = fixture.observer.callback_results().len();
    let fresh = std::fs::read(root.join("sub/g.txt")).map_err(|error| error.raw_os_error());
    let path_opens: Vec<_> = fixture
        .observer
        .callback_results()
        .into_iter()
        .skip(from)
        .filter(|(callback, _)| matches!(callback, Callback::Open))
        .map(|(_, outcome)| outcome)
        .collect();
    let link = format!("/proc/self/fd/{}", held.as_raw_fd());
    let via_link = errno(std::fs::File::open(link));
    assert_eq!(
        (fresh, path_opens, via_link),
        (Ok(same_size), vec![CallbackOutcome::Ok], Err(Some(116))),
        "(a path open reads the head's bytes, the daemon's OPENs for it, an open of the held \
         descriptor's link)"
    );
    drop(held);
    fixture.finish();
}

/// The engine's landings are bound to the view before the session serves a
/// request, so no landing can take the hook-less path and no preparation can
/// return its slot before the install's waker is registered. A refused bind
/// leaves no mount behind.
#[test]
fn writable_linux_view_binds_before_the_session_serves() {
    if !venue("writable_linux_view_binds_before_the_session_serves") {
        return;
    }
    let fixture = SyncMount::with_hook(sync_deadline(), Hook::Probed);
    let bound = (fixture.served_at_bind, fixture.view_probe());
    fixture.finish();

    let paths = Paths::new();
    let tree = mounted_operation_tree();
    let cfg = input(&tree, &paths);
    let (ready, _, _) = attempt(&cfg, &tree, "valid", &Events::default());
    let attachment = ready.unwrap().attach();
    let refused = granary_fuse::spawn_writable_session(
        attachment.snapshot,
        attachment.backend,
        1,
        &paths.mountpoint,
        &granary_fuse::writable_session_config(),
        |_| Err(std::io::Error::other("bind refused")),
    )
    .map(drop)
    .map_err(|error| error.to_string());
    let mountpoint = paths.mountpoint.to_string_lossy().into_owned();
    let mounted = std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .any(|line| line.split(' ').nth(4) == Some(mountpoint.as_str()));
    assert_eq!(
        (bound, refused, mounted),
        (
            (Some(false), [Ok(()); 3]),
            Err("bind refused".to_owned()),
            false
        ),
        "((the session answered at the bind, the bound mount serves), a refused bind, its \
         mount left behind)"
    );
}
