// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Another writer's head picked up at the kernel's close-to-open boundaries:
//! the OPEN of a file the head replaced, the LOOKUP of a name the view
//! lacks, an OPENDIR, a dirty mount's deferral, and a listing across a
//! pickup.

use super::super::super::commit_lane::{publish_head, publish_source};
use super::view::errno;
use super::*;
use std::os::unix::fs::MetadataExt as _;

/// `sub/g.txt` as another writer rewrites it, at the same size.
fn rewritten() -> Vec<u8> {
    let mut bytes = FILE_CONTENT.to_vec();
    bytes[..4].copy_from_slice(b"head");
    bytes
}

/// The outcome of each OPEN the daemon answered after its first `from`
/// callbacks.
fn opens_since(fixture: &SyncMount, from: usize) -> Vec<CallbackOutcome> {
    fixture
        .observer
        .callback_results()
        .into_iter()
        .skip(from)
        .filter(|(callback, _)| matches!(callback, Callback::Open))
        .map(|(_, outcome)| outcome)
        .collect()
}

/// The seq of the mount's admitted base.
pub(super) fn pin_seq(fixture: &SyncMount) -> u64 {
    fixture.mediator.with(|store| store.mount_base()).unwrap().1
}

/// A second writable start on the serving mount's cache is refused rather
/// than serving on a degraded cache. The owner can still land a later fsync,
/// follow that landing and serve the bytes it wrote.
#[test]
fn writable_linux_view_shared_cache_refuses_concurrent_writable_mount() {
    if !venue("writable_linux_view_shared_cache_refuses_concurrent_writable_mount") {
        return;
    }
    let paths = Arc::new(Paths::new());
    let tree = Arc::new(mounted_operation_tree());
    let fixture = SyncMount::shared_cache(
        sync_deadline(),
        crate::SyncProfile::Published,
        Arc::clone(&paths),
        Arc::clone(&tree),
    )
    .unwrap();
    let mut second_paths = Paths::new();
    second_paths.cache.clone_from(&paths.cache);
    let second = SyncMount::shared_cache(
        sync_deadline(),
        crate::SyncProfile::Published,
        Arc::new(second_paths),
        tree,
    );
    let refusal = second
        .as_ref()
        .err()
        .map_or_else(|| "Ok".to_owned(), Clone::clone);
    let before = fixture.remote_seq();
    let file = fixture.file();
    file.write_at(b"owner", 0).unwrap();
    let synced = errno(file.sync_all());
    let mut expected = FILE_CONTENT.to_vec();
    expected[..5].copy_from_slice(b"owner");
    assert_eq!(
        (
            refusal.as_str(),
            synced,
            before,
            fixture.remote_seq(),
            pin_seq(&fixture),
            std::fs::read(fixture.paths.mountpoint.join("f.txt"))
                .map_err(|error| error.raw_os_error()),
        ),
        (
            "ReadView(DegradedCacheRefused): DegradedCacheRefused",
            Ok(()),
            1,
            2,
            2,
            Ok(expected)
        ),
        "(the second start's refusal, the owner's fsync, head before and after, the \
         owner's pin, its served bytes); second start: {refusal}"
    );
    drop((file, second, paths));
    fixture.finish();
}

/// A cleanly finished owner leaves its landed sequence in the cache's
/// mount-private floor and the shared anchor as it found it, read from the
/// cache after the owner is gone. A later writable mount on that cache admits
/// the same landed base and serves its bytes.
#[test]
fn writable_linux_view_shared_cache_restart_admits_the_landed_base() {
    if !venue("writable_linux_view_shared_cache_restart_admits_the_landed_base") {
        return;
    }
    let paths = Arc::new(Paths::new());
    let tree = Arc::new(mounted_operation_tree());
    let fixture =
        SyncMount::shared_cache(sync_deadline(), crate::SyncProfile::Published, paths, tree)
            .unwrap();
    let shared_before = fixture.shared_anchor();
    let file = fixture.file();
    file.write_at(b"landed", 0).unwrap();
    let synced = errno(file.sync_all());
    let landed = fixture.served_pin();
    drop(file);
    let (paths, tree) = fixture.finish_shared_cache();
    let floor = mount_floor(&paths, &tree);
    let shared_after = shared_anchor(&paths, &tree);

    let mut restart_paths = Paths::new();
    restart_paths.cache.clone_from(&paths.cache);
    let restarted = SyncMount::shared_cache(
        sync_deadline(),
        crate::SyncProfile::Published,
        Arc::new(restart_paths),
        tree,
    )
    .unwrap();
    let mut expected = FILE_CONTENT.to_vec();
    expected[..6].copy_from_slice(b"landed");
    assert_eq!(
        (
            synced,
            landed.1,
            floor,
            shared_before,
            shared_after,
            restarted.served_pin(),
            std::fs::read(restarted.paths.mountpoint.join("f.txt"))
                .map_err(|error| error.raw_os_error()),
        ),
        (Ok(()), 2, Some(2), None, None, landed, Ok(expected)),
        "(the owner's fsync, landed sequence, private floor, shared anchor before (none: the start writes \
         only the private floor) and after the owner finished, restart base, served bytes)"
    );
    restarted.finish();
    drop(paths);
}

/// A remote same-size rewrite of a file is seen by a fresh `open`, which
/// gets a new inode; a descriptor opened before keeps reading the old bytes.
/// The revalidating LOOKUP is positive, so the OPEN's boundary adopts the
/// head and answers `ESTALE` for the inode it replaced, and the kernel
/// opens once more after a fresh LOOKUP.
#[test]
fn writable_linux_view_remote_modify_is_seen_at_open() {
    if !venue("writable_linux_view_remote_modify_is_seen_at_open") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let g = fixture.paths.mountpoint.join("sub/g.txt");
    let held = std::fs::File::open(&g).unwrap();
    let old_ino = held.metadata().unwrap().ino();
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
    });
    let from = fixture.observer.callback_results().len();
    let mut fresh = std::fs::File::open(&g).unwrap();
    let opens = opens_since(&fixture, from);
    let mut new = Vec::new();
    let reread = errno(fresh.read_to_end(&mut new));
    let mut old = vec![0_u8; FILE_CONTENT.len()];
    let read = errno(held.read_exact_at(&mut old, 0));
    assert_eq!(
        (
            opens,
            reread,
            new == rewritten(),
            fresh.metadata().unwrap().ino() != old_ino,
            read,
            old == FILE_CONTENT,
        ),
        (
            vec![
                CallbackOutcome::Failed(granary_fuse::MountError::Stale),
                CallbackOutcome::Ok
            ],
            Ok(()),
            true,
            true,
            Ok(()),
            true
        ),
        "(the daemon's OPENs for one open(2), the fresh read, its bytes are the head's, a new \
         inode, the held read, its bytes are the old)"
    );
    drop((held, fresh));
    fixture.finish();
}

/// A file another writer creates three directories deep is found by a
/// `stat`, whose first LOOKUP miss adopts the head. The root and the
/// existing ancestor keep their inodes, and a read-only descriptor on
/// another file still reads.
#[test]
fn writable_linux_view_remote_create_is_seen_at_lookup() {
    if !venue("writable_linux_view_remote_create_is_seen_at_lookup") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    let other = std::fs::File::open(root.join("f.txt")).unwrap();
    let ancestors =
        || [root.clone(), root.join("sub")].map(|path| std::fs::metadata(path).unwrap().ino());
    let before = ancestors();
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::create_dir_all(source.join("sub/a/b")).unwrap();
        std::fs::write(source.join("sub/a/b/deep.txt"), b"deep\n").unwrap();
    });
    let deep = std::fs::metadata(root.join("sub/a/b/deep.txt")).map(|metadata| metadata.len());
    let after = ancestors();
    let mut bytes = vec![0_u8; FILE_CONTENT.len()];
    let read = errno(other.read_exact_at(&mut bytes, 0));
    assert_eq!(
        (
            deep.map_err(|error| error.raw_os_error()),
            before == after,
            read,
            bytes == FILE_CONTENT
        ),
        (Ok(5), true, Ok(()), true),
        "(the deep file's size, the root and sub keep their inodes, the other read, its bytes)"
    );
    drop(other);
    fixture.finish();
}

/// A file another writer creates in an existing directory is listed by a
/// fresh `opendir` that looks no name up first: the OPENDIR's boundary
/// adopts the head.
#[test]
fn writable_linux_view_remote_create_is_seen_at_opendir() {
    if !venue("writable_linux_view_remote_create_is_seen_at_opendir") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let sub = fixture.paths.mountpoint.join("sub");
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/n.txt"), b"new\n").unwrap();
    });
    let mut listed: Vec<_> = std::fs::read_dir(&sub)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    listed.sort();
    assert_eq!(
        (listed, pin_seq(&fixture)),
        (vec!["g.txt".into(), "n.txt".into()], 2),
        "(the fresh listing, the pin)"
    );
    fixture.finish();
}

/// A rename and a removal another writer published are seen through
/// `stat` of names the kernel already holds: the LOOKUP miss of the new
/// name adopts the head, and the old names then answer `ENOENT`. A
/// descriptor held on the renamed file reads the old bytes. No `open(2)`
/// is in the tuple: an open of the old name would reach the replaced
/// inode, answer `ESTALE` and be retried with a fresh LOOKUP, so it would
/// pass with a cached dentry too.
#[test]
fn writable_linux_view_remote_remove_and_rename_are_seen_through_stat() {
    if !venue("writable_linux_view_remote_remove_and_rename_are_seen_through_stat") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    let held_dentries = (
        errno(std::fs::metadata(root.join("f.txt"))),
        errno(std::fs::symlink_metadata(root.join("original-link"))),
    );
    let held = std::fs::File::open(root.join("f.txt")).unwrap();
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::rename(source.join("f.txt"), source.join("moved.txt")).unwrap();
        std::fs::remove_file(source.join("original-link")).unwrap();
    });
    let moved = std::fs::metadata(root.join("moved.txt"))
        .map(|metadata| metadata.len())
        .map_err(|error| error.raw_os_error());
    let gone = (
        errno(std::fs::metadata(root.join("f.txt"))),
        errno(std::fs::symlink_metadata(root.join("original-link"))),
    );
    let mut old = vec![0_u8; FILE_CONTENT.len()];
    let read = errno(held.read_exact_at(&mut old, 0));
    let enoent = Err(Some(2));
    assert_eq!(
        (held_dentries, moved, gone, read, old == FILE_CONTENT),
        (
            (Ok(()), Ok(())),
            Ok(u64::try_from(FILE_CONTENT.len()).unwrap()),
            (enoent, enoent),
            Ok(()),
            true
        ),
        "(premise: the old names were looked up, the new name's size, the old names, the held \
         read, its bytes are the old)"
    );
    drop(held);
    fixture.finish();
}

/// A mount with a local change keeps serving its view over another
/// writer's head, until its own landing rebases onto that head and installs
/// it.
#[test]
fn writable_linux_view_dirty_mount_defers_until_its_own_landing() {
    if !venue("writable_linux_view_dirty_mount_defers_until_its_own_landing") {
        return;
    }
    let fixture = SyncMount::live(sync_deadline(), crate::SyncOptions::default());
    let root = fixture.paths.mountpoint.clone();
    // Creating the local file can start the coalescer's max-age clock.
    let dirty_started = std::time::Instant::now();
    let mut writer = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(root.join("d.txt"))
        .unwrap();
    std::io::Write::write_all(&mut writer, b"local").unwrap();
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
    });
    let deferred = std::fs::read(root.join("sub/g.txt")).unwrap();
    let pinned = pin_seq(&fixture);
    let wait_started = std::time::Instant::now();
    while pin_seq(&fixture) != 3 {
        assert!(
            wait_started.elapsed() < std::time::Duration::from_secs(10),
            "the live max-age commit did not install"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let reached_max_age = dirty_started.elapsed() >= crate::DEFAULT_MAX_COALESCE_DELAY;
    let after = std::fs::read(root.join("sub/g.txt")).unwrap();
    assert_eq!(
        (
            deferred == FILE_CONTENT,
            pinned,
            reached_max_age,
            fixture.remote_seq(),
            after == rewritten()
        ),
        (true, 1, true, 3, true),
        "(the dirty mount reads its own view, its pin, the max-age bound, the landed seq, the next \
         open reads the head's bytes)"
    );
    drop(writer);
    fixture.finish();
}

/// A directory stream opened before another writer's head is installed lists
/// every name the head left alone exactly once. The head that adds `n.txt`
/// and removes `r.txt` is installed by a LOOKUP miss while the stream is part
/// way through a directory wider than one READDIR reply; `n.txt` and `r.txt`
/// may or may not appear.
#[test]
fn writable_linux_view_directory_stream_across_advance() {
    if !venue("writable_linux_view_directory_stream_across_advance") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let sub = fixture.paths.mountpoint.join("sub");
    let wide: Vec<String> = (0..300).map(|index| format!("wide-{index:03}")).collect();
    let with_wide = |source: &Path, extra: &str| {
        write_operation_source(source, FILE_CONTENT);
        for name in &wide {
            std::fs::write(source.join("sub").join(name), b"w").unwrap();
        }
        std::fs::write(source.join("sub").join(extra), extra.as_bytes()).unwrap();
    };
    let first = publish_source(&fixture.tree, &fixture.runtime, |source| {
        with_wide(source, "r.txt");
    });
    let adopted_first = (
        errno(std::fs::metadata(sub.join("wide-000"))),
        pin_seq(&fixture),
    );
    let mut stream = std::fs::read_dir(&sub).unwrap();
    let mut names: Vec<String> = stream
        .by_ref()
        .take(10)
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let second = publish_source(&fixture.tree, &fixture.runtime, |source| {
        with_wide(source, "n.txt");
    });
    let adopted_second = (
        errno(std::fs::metadata(sub.join("n.txt"))),
        pin_seq(&fixture),
    );
    let from = fixture.observer.callback_results().len();
    names.extend(stream.map(|entry| entry.unwrap().file_name().into_string().unwrap()));
    let listings_after = fixture
        .observer
        .callback_results()
        .into_iter()
        .skip(from)
        .filter(|(callback, _)| matches!(callback, Callback::Readdir | Callback::Readdirplus))
        .count();
    let unaffected: Vec<_> = wide
        .iter()
        .map(String::as_str)
        .chain(["g.txt"])
        .filter(|name| {
            names
                .iter()
                .filter(|listed| listed.as_str() == *name)
                .count()
                != 1
        })
        .collect();
    assert_eq!(
        (
            adopted_first,
            adopted_second,
            listings_after > 0,
            unaffected
        ),
        ((Ok(()), first), (Ok(()), second), true, Vec::<&str>::new()),
        "(the wide head adopted, the second head adopted mid-stream, premise: the stream read \
         on after it, every unaffected name not listed exactly once): {names:?}"
    );
    fixture.finish();
}

pub(super) fn view_xattr(root: &Path) -> String {
    let bytes = python(
        root,
        "sys.stdout.buffer.write(os.getxattr(r,'user.granary.view'))",
    )
    .unwrap();
    String::from_utf8(bytes).unwrap()
}

fn stale_gauge(fixture: &SyncMount) -> Option<u64> {
    let rendered = fixture
        .metrics
        .snapshot()
        .unwrap()
        .render_prometheus()
        .unwrap();
    rendered.lines().find_map(|line| {
        line.strip_prefix("granary_client_mount_view_stale ")
            .and_then(|value| value.parse().ok())
    })
}

fn view_events(fixture: &SyncMount, level: &str, outcome: &str) -> usize {
    String::from_utf8(fixture.observer.events().0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"mount.view\"")
                && line.contains(&format!("\"level\":\"{level}\""))
                && line.contains("\"cause\":\"adopted\"")
                && line.contains(&format!("\"outcome\":\"{outcome}\""))
        })
        .count()
}

fn view_unavailable_failures(fixture: &SyncMount) -> usize {
    String::from_utf8(fixture.observer.events().0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"op.failed\"")
                && line.contains("\"level\":\"ERROR\"")
                && line.contains("\"kind\":\"view\"")
                && line.contains("\"class\":\"unavailable\"")
        })
        .count()
}

#[test]
fn writable_linux_view_unreachable_head_serves_declared_stale() {
    if !venue("writable_linux_view_unreachable_head_serves_declared_stale") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    let g = root.join("sub/g.txt");
    assert_eq!(std::fs::read(&g).unwrap(), FILE_CONTENT);
    // The first open's probe enters the state; every later probe waits at
    // the limit, so the prober cannot add to the count, and a boundary that
    // probed would hold its open for its 2 s budget.
    let probes_before = {
        let mut state = fixture.state.lock().unwrap();
        state.probe_fault = Some(RootStoreError::Backend("connection refused".to_owned()));
        state.probe_limit = Some(state.probes + 1);
        state.probes
    };
    let start_first = crate::TokioSyncRuntime.now();
    let first_bytes = std::fs::read(&g).unwrap();
    let first_elapsed = crate::TokioSyncRuntime
        .now()
        .saturating_duration_since(start_first);
    let start_second = crate::TokioSyncRuntime.now();
    let second_bytes = std::fs::read(&g).unwrap();
    let second_elapsed = crate::TokioSyncRuntime
        .now()
        .saturating_duration_since(start_second);
    let probes_after = fixture.state.lock().unwrap().probes;
    let stale_label = view_xattr(&root);
    let stale_ok = stale_label
        .strip_prefix("stale:1:")
        .and_then(|since| since.parse::<u64>().ok())
        .is_some();
    let stale_state = (
        first_elapsed < std::time::Duration::from_secs(1),
        second_elapsed < std::time::Duration::from_secs(1),
        probes_after - probes_before,
        first_bytes == FILE_CONTENT && second_bytes == FILE_CONTENT,
        stale_ok,
        view_events(&fixture, "WARN", "stale"),
        stale_gauge(&fixture),
    );
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
    });
    {
        let mut state = fixture.state.lock().unwrap();
        state.probe_fault = None;
        state.probe_limit = None;
    }
    fixture.wait("fresh view", || stale_gauge(&fixture) == Some(0));
    let fresh_before_open = view_xattr(&root);
    let recovered_bytes = std::fs::read(&g).unwrap();
    let fresh_after_open = view_xattr(&root);
    assert_eq!(
        (
            stale_state,
            view_events(&fixture, "INFO", "fresh"),
            stale_gauge(&fixture),
            fresh_before_open.as_str(),
            recovered_bytes == rewritten(),
            fresh_after_open.as_str(),
        ),
        (
            (true, true, 1, true, true, 1, Some(1)),
            1,
            Some(0),
            "fresh:1",
            true,
            "fresh:2",
        ),
        "(stale state: first open fast, second open fast, probe delta, pinned bytes, \
         stale:<seq>:<since> label: {stale_label}, rising WARN count, gauge 1; after recovery: \
         falling INFO count, gauge 0, label before next open, next open reads new bytes, label \
         after next open)"
    );
    fixture.finish();
}

#[test]
fn writable_linux_view_strict_unreachable_head_times_out() {
    if !venue("writable_linux_view_strict_unreachable_head_times_out") {
        return;
    }
    let fixture = SyncMount::strict(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    let held_file = std::fs::File::open(root.join("f.txt")).unwrap();
    let mut held = fixture.held_handles(HeldRead::Buffered);
    let cached_negative = errno(std::fs::metadata(root.join("created.txt")));
    fixture.state.lock().unwrap().probe_fault =
        Some(RootStoreError::Backend("connection refused".to_owned()));
    let open = errno(std::fs::File::open(root.join("f.txt")));
    let opendir = errno(std::fs::read_dir(&root));
    let absent = errno(std::fs::metadata(root.join("absent.txt")));
    let [held_probe_read, rewind] = held.probe();
    let create = errno(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("created.txt")),
    );
    let mkdir = errno(std::fs::create_dir(root.join("new-dir")));
    let symlink = errno(std::os::unix::fs::symlink("f.txt", root.join("new-link")));
    let mut bytes = vec![0_u8; FILE_CONTENT.len()];
    let read = errno(held_file.read_exact_at(&mut bytes, 0));
    let etimedout = Err(Some(110));
    assert_eq!(
        (
            cached_negative,
            open,
            opendir,
            absent,
            rewind,
            create,
            mkdir,
            symlink,
            view_unavailable_failures(&fixture),
            held_probe_read,
            read,
            bytes == FILE_CONTENT,
        ),
        (
            Err(Some(2)),
            etimedout,
            etimedout,
            etimedout,
            etimedout,
            etimedout,
            etimedout,
            etimedout,
            1,
            Ok(()),
            Ok(()),
            true,
        ),
        "(premise: stat before fault was ENOENT; OPEN, OPENDIR, stat of absent name, rewinddir \
         after one cookie, open(O_CREAT), mkdir, symlink all ETIMEDOUT; op.failed{{kind=view, \
         class=unavailable}} once; held fd reads its bytes)"
    );
    drop((held, held_file));
    fixture.finish();
}

#[test]
fn writable_linux_view_landing_in_the_unreachable_state_clears_it() {
    if !venue("writable_linux_view_landing_in_the_unreachable_state_clears_it") {
        return;
    }
    let mut cases = 0;
    for strict in [false, true] {
        let fixture = if strict {
            SyncMount::live_strict(sync_deadline(), crate::SyncOptions::default())
        } else {
            SyncMount::live(sync_deadline(), crate::SyncOptions::default())
        };
        let root = fixture.paths.mountpoint.clone();
        let recovery = std::fs::OpenOptions::new()
            .write(true)
            .open(root.join("f.txt"))
            .unwrap();
        fixture.state.lock().unwrap().probe_fault =
            Some(RootStoreError::Backend("connection refused".to_owned()));
        let before = errno(std::fs::File::open(root.join("f.txt")));
        assert_eq!(
            (before, stale_gauge(&fixture)),
            (if strict { Err(Some(110)) } else { Ok(()) }, Some(1)),
            "premise: the failed probe entered the unreachable state"
        );
        recovery.write_all_at(b"land", 0).unwrap();
        drop(recovery);
        fixture.wait("landing and fresh view", || {
            pin_seq(&fixture) == 2 && stale_gauge(&fixture) == Some(0)
        });
        let cleared = (pin_seq(&fixture), view_xattr(&root), stale_gauge(&fixture));
        let after = errno(std::fs::File::open(root.join("f.txt")));
        let stale_label = view_xattr(&root);
        assert_eq!(
            (
                cleared,
                (
                    after,
                    stale_label
                        .strip_prefix("stale:2:")
                        .and_then(|since| since.parse::<u64>().ok())
                        .is_some(),
                    stale_gauge(&fixture),
                    fixture.state.lock().unwrap().probe_fault.is_some(),
                ),
            ),
            (
                (2, "fresh:2".to_owned(), Some(0)),
                (
                    if strict { Err(Some(110)) } else { Ok(()) },
                    true,
                    Some(1),
                    true,
                ),
            ),
            "the landing clears the state; the next OPEN's still-failing probe begins a new episode"
        );
        fixture.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_view_authority_restart_fails_no_boundary() {
    if !venue("writable_linux_view_authority_restart_fails_no_boundary") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let f = fixture.paths.mountpoint.join("f.txt");
    assert_eq!(std::fs::read(&f).unwrap(), FILE_CONTENT);
    fixture.state.lock().unwrap().probe_fault =
        Some(RootStoreError::Backend("connection refused".to_owned()));
    let outage_until = crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(2);
    let mut opens = 0_usize;
    let mut failures = 0_usize;
    while crate::TokioSyncRuntime.now() < outage_until {
        opens += 1;
        if std::fs::read(&f).ok().as_deref() != Some(FILE_CONTENT) {
            failures += 1;
        }
        fixture.runtime.block_on(async {
            crate::TokioSyncRuntime
                .sleep(std::time::Duration::from_millis(20))
                .await;
        });
    }
    fixture.state.lock().unwrap().probe_fault = None;
    let recovery_deadline = crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(3);
    while stale_gauge(&fixture) != Some(0) && crate::TokioSyncRuntime.now() < recovery_deadline {
        opens += 1;
        if std::fs::read(&f).ok().as_deref() != Some(FILE_CONTENT) {
            failures += 1;
        }
        fixture.runtime.block_on(async {
            crate::TokioSyncRuntime
                .sleep(std::time::Duration::from_millis(20))
                .await;
        });
    }
    let probes_before_post = fixture.state.lock().unwrap().probes;
    let post_recovery = std::fs::read(&f).unwrap();
    let probes_after_post = fixture.state.lock().unwrap().probes;
    assert_eq!(
        (
            opens > 0,
            failures,
            view_events(&fixture, "WARN", "stale"),
            view_events(&fixture, "INFO", "fresh"),
            stale_gauge(&fixture),
            post_recovery == FILE_CONTENT,
            probes_after_post - probes_before_post,
        ),
        (true, 0, 1, 1, Some(0), true, 1),
        "(loop opened files, failed opens, rising WARN count, falling INFO count, gauge after \
         recovery, post-recovery read, first boundary after recovery probed)"
    );
    fixture.finish();
}
