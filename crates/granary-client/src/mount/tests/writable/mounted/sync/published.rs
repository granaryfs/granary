// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The published profile through a real mount: each sync lands a projection
//! of its own capture and every other file's durable bytes, and the writes it
//! did not sync stay in the mount for a later commit.

use super::super::super::commit_lane::{publish_head, publish_head_from};
use super::*;

const STALE: Result<(), Option<i32>> = Err(Some(116));
const EIO: Result<(), Option<i32>> = Err(Some(5));
/// Where a stage file's bytes begin, after its staging header.
const STAGE_DATA: usize = 160;

impl SyncMount {
    fn published(deadline: tokio::time::Instant) -> Self {
        Self::with_profile(deadline, Hook::Bound, crate::SyncProfile::Published)
    }
    /// The authority head's signed root.
    fn head_root(&self) -> Vec<u8> {
        let store = remote_handle(&self.tree.mem);
        let volume = self.tree.volume.as_str();
        self.runtime.block_on(async {
            let seq = store.max_seq(volume).await.unwrap().unwrap();
            store.get_root(volume, seq).await.unwrap().unwrap()
        })
    }
    /// The authority head's root directory entries, read through the mount's
    /// content source, which a fenced mount refuses.
    fn head_entries(&self) -> Vec<granary_core::manifest::DirEntry> {
        let root = self.head_root();
        let manifest = granary_core::root::decode_root(&root)
            .unwrap()
            .manifest_root;
        self.head_read(move |content| {
            let bytes = content.get(&manifest).unwrap();
            let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
            granary_core::manifest::decode_dir_leaf(cursor).unwrap()
        })
    }
    /// The authority head's root-level file `name`, if it has one.
    fn head_file(&self, name: &str) -> Option<Vec<u8>> {
        let entry = self
            .head_entries()
            .into_iter()
            .find(|entry| entry.name.as_bytes() == name.as_bytes())?;
        let granary_core::manifest::EntryKind::File {
            grains: granary_core::manifest::FileGrains::Inline(refs),
            ..
        } = entry.kind
        else {
            panic!("expected an inline head file at {name}: {entry:?}");
        };
        Some(self.head_read(move |content| {
            refs.iter()
                .flat_map(|grain| content.get(&grain.id).unwrap())
                .collect()
        }))
    }
    /// The authority head's root-level file `name`, if it has one, read from
    /// `publisher`, the store the head was published from: the mount's own
    /// content source has none of a remote head's new objects.
    fn head_file_in(&self, publisher: &Store, name: &str) -> Option<Vec<u8>> {
        let root = self.head_root();
        let manifest = granary_core::root::decode_root(&root)
            .unwrap()
            .manifest_root;
        let bytes = publisher.get(&manifest).unwrap();
        let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
        let entry = granary_core::manifest::decode_dir_leaf(cursor)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name.as_bytes() == name.as_bytes())?;
        let granary_core::manifest::EntryKind::File {
            grains: granary_core::manifest::FileGrains::Inline(refs),
            ..
        } = entry.kind
        else {
            panic!("expected an inline head file at {name}: {entry:?}");
        };
        Some(
            refs.iter()
                .flat_map(|grain| publisher.get(&grain.id).unwrap())
                .collect(),
        )
    }
    /// Run `read` against the authority's content on a scoped thread while
    /// this thread drives the fixture runtime, as [`prepared_bytes`] does.
    fn head_read<T: Send>(
        &self,
        read: impl FnOnce(&dyn granary_core::grainsource::GrainSource) -> T + Send,
    ) -> T {
        let (runtime, content) = (&self.runtime, &*self.content);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let _entered = runtime.enter();
                let content = content.with_deadline(
                    Arc::new(crate::TokioSyncRuntime),
                    crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(5),
                );
                read(&content)
            });
            runtime.block_on(async {
                while !worker.is_finished() {
                    tokio::task::yield_now().await;
                }
            });
            worker.join().unwrap()
        })
    }
    /// What the mount serves at `path`: none if it cannot open or read it.
    fn mounted(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(self.paths.mountpoint.join(path)).ok()
    }
    fn open_rw(&self, path: &str) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.paths.mountpoint.join(path))
            .unwrap()
    }
    /// Create `path` holding `bytes`, open for reading and writing.
    fn created(&self, path: &str, bytes: &[u8]) -> std::fs::File {
        let file = self.open_rw(path);
        file.write_at(bytes, 0).unwrap();
        file
    }
    fn sync_directory(&self) -> Result<(), Option<i32>> {
        errno(std::fs::File::open(self.paths.mountpoint.as_path()).and_then(|d| d.sync_all()))
    }
    /// Land a whole-tree commit of everything written so far.
    fn commit_all(&self, entropy: u8) -> bool {
        let lane = self.construct_commit(entropy).unwrap();
        landed(&self.drive_commit(&lane, entropy + 1))
    }
}

fn errno<T>(result: std::io::Result<T>) -> Result<(), Option<i32>> {
    result.map(drop).map_err(|error| error.raw_os_error())
}

/// `FILE_CONTENT` with its first bytes replaced by `prefix`.
fn edited(prefix: &[u8]) -> Vec<u8> {
    let mut bytes = FILE_CONTENT.to_vec();
    bytes[..prefix.len()].copy_from_slice(prefix);
    bytes
}

/// The operator-selected cap and construction workspace carry a tree that the
/// stock cap cannot seal through the mounted entry point.
#[test]
fn writable_linux_wedged_tree_lands_with_operator_exit_allowances() {
    if !venue("writable_linux_wedged_tree_lands_with_operator_exit_allowances") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    fixture
        .mediator
        .with(|store| {
            store.cap_for_test(268_435_456);
            Ok(())
        })
        .unwrap();
    let bytes = vec![7; 4 * 1_048_576];
    for index in 0..23 {
        let file = fixture.created(&format!("wedged-{index:02}"), &bytes);
        assert_eq!(file.metadata().unwrap().len(), 4 * 1_048_576);
    }
    let lane = fixture
        .construct_commit_with(
            crate::SyncOptions {
                workspace_bytes: 4_294_967_296,
                ..crate::SyncOptions::default()
            },
            70,
        )
        .unwrap();
    assert!(landed(&fixture.drive_commit(&lane, 71)));
}

/// x's fsync publishes x's captured bytes and f.txt's durable ones, never
/// f.txt's later, longer local bytes or a file never synced. The mount keeps
/// them, through either handle, and an ordinary commit publishes them later.
#[test]
fn writable_linux_projected_candidate_excludes_older_unsynced_bytes() {
    if !venue("writable_linux_projected_candidate_excludes_older_unsynced_bytes") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let writer = fixture.file();
    let reader = std::fs::File::open(fixture.paths.mountpoint.join("f.txt")).unwrap();
    let mut local = edited(b"local B");
    local.extend_from_slice(b", and longer");
    writer.write_at(&local, 0).unwrap();
    drop(fixture.created("z.txt", b"never synced"));
    let selected = fixture.created("x.txt", b"selected");
    let synced = errno(selected.sync_all());
    let mut through_reader = vec![0; local.len()];
    let read = errno(reader.read_exact_at(&mut through_reader, 0));
    let some = |bytes: &[u8]| Some(bytes.to_vec());
    let landed = (
        fixture.head_file("x.txt"),
        fixture.head_file("f.txt"),
        fixture.head_file("z.txt"),
        fixture.mounted("f.txt"),
        fixture.mounted("z.txt"),
        fixture.remote_seq(),
    );
    let committed = fixture.commit_all(70);
    assert_eq!(
        (
            synced,
            landed,
            (read, through_reader == local),
            committed,
            (fixture.head_file("f.txt"), fixture.head_file("z.txt")),
        ),
        (
            Ok(()),
            (
                some(b"selected"),
                some(FILE_CONTENT),
                None,
                some(&local),
                some(b"never synced"),
                2,
            ),
            (Ok(()), true),
            true,
            (some(&local), some(b"never synced")),
        ),
        "(x's fsync, (head x, f and z, mounted f and z, head seq), the other handle reads the \
         local bytes, a later ordinary commit lands, its head f and z)"
    );
    drop((writer, reader, selected));
    fixture.finish();
}

/// While x's fsync is held after its capture, f.txt is overwritten and z
/// created, and a later write to x waits for the reply. The head holds x's
/// captured bytes, f.txt's durable ones and no z; the mount keeps the later
/// bytes and z.
#[test]
fn writable_linux_projected_capture_keeps_writes_during_sync() {
    if !venue("writable_linux_projected_capture_keeps_writes_during_sync") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let selected = fixture.created("x.txt", b"captured x");
    let other = fixture.file();
    let faults = fixture.faults();
    faults.arm("sync.capture", "after", 1, crate::FaultAction::Block);
    // Keep the receiver alive through the scoped join, even after the wait times out.
    let (wrote, written) = mpsc::channel();
    let mut worker_timing = None;
    let outcome = std::thread::scope(|threads| {
        let _resume = Resume(faults.clone());
        let (sent, reply) = mpsc::channel();
        let syncing = &selected;
        threads.spawn(move || sent.send(errno(syncing.sync_all())).unwrap());
        fixture.wait("sync.capture/after fault", || {
            !faults.sync_fired().is_empty()
        });
        let now = || crate::TokioSyncRuntime.now();
        let capture_observed = now();
        let elapsed = move || now().saturating_duration_since(capture_observed);
        let other = &other;
        let root = fixture.paths.mountpoint.clone();
        let worker_timing = &mut worker_timing;
        threads.spawn(move || {
            let entered = elapsed();
            let sibling_result = errno(other.write_at(b"LATER Y", 0));
            let write_returned = elapsed();
            let file_result = errno(std::fs::write(
                root.join("z.txt"),
                b"created during the sync",
            ));
            let create_returned = elapsed();
            wrote.send((sibling_result, file_result)).unwrap();
            *worker_timing = Some([entered, write_returned, create_returned, elapsed()]);
        });
        let wait_started = elapsed();
        let during = written.recv_timeout(std::time::Duration::from_secs(5));
        let wait_returned = elapsed();
        let later = &selected;
        let (later_sent, later_reply) = mpsc::channel();
        threads.spawn(move || {
            later_sent
                .send(errno(later.write_at(b"LATER X", 0)))
                .unwrap();
        });
        faults.resume();
        let hold_released = elapsed();
        let synced = reply.recv_timeout(std::time::Duration::from_secs(10));
        let later = later_reply.recv_timeout(std::time::Duration::from_secs(10));
        let wait_timing = [wait_started, wait_returned, hold_released];
        ((synced, later), during, wait_timing)
    });
    drop(written);
    let (synced, during, [wait_started, wait_returned, hold_released]) = outcome;
    if matches!(during, Err(mpsc::RecvTimeoutError::Timeout))
        && let Some([worker_entered, write_returned, create_returned, result_sent]) = worker_timing
    {
        eprintln!(
            "held capture timeout (elapsed since capture observed): worker entered={worker_entered:?}, \
             sibling write returned={write_returned:?}, create returned={create_returned:?}, \
             result sent={result_sent:?}, wait started={wait_started:?}, \
             wait timed out={wait_returned:?}, hold released={hold_released:?}"
        );
    }
    let some = |bytes: &[u8]| Some(bytes.to_vec());
    assert_eq!(
        (
            synced,
            during,
            (
                fixture.head_file("x.txt"),
                fixture.head_file("f.txt"),
                fixture.head_file("z.txt"),
            ),
            (
                fixture.mounted("x.txt"),
                fixture.mounted("f.txt"),
                fixture.mounted("z.txt"),
            ),
        ),
        (
            (Ok(Ok(())), Ok(Ok(()))),
            Ok((Ok(()), Ok(()))),
            (some(b"captured x"), some(FILE_CONTENT), None),
            (
                some(b"LATER Xd x"),
                some(&edited(b"LATER Y")),
                some(b"created during the sync"),
            ),
        ),
        "((x's fsync, x's later write), (f's write and z's create while the fsync is held), \
         head (x, f, z), mounted (x, f, z))"
    );
    drop((selected, other));
    fixture.finish();
}

/// An unlinked file held open, never synced, and f.txt's copy-up unlinked
/// while held: fsync, fdatasync and fsyncdir of x each land with neither name
/// in the head, and both held descriptors keep reading, writing, extending
/// and truncating their own bytes.
#[test]
fn writable_linux_projected_unlinked_open_elsewhere() {
    if !venue("writable_linux_projected_unlinked_open_elsewhere") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    let tmp = fixture.created("tmp.txt", b"tmp bytes");
    std::fs::remove_file(root.join("tmp.txt")).unwrap();
    let copied = fixture.file();
    copied.write_at(b"partial", 10).unwrap();
    std::fs::remove_file(root.join("f.txt")).unwrap();
    let selected = fixture.created("x.txt", b"x");
    let calls = [
        errno(selected.sync_all()),
        errno(selected.sync_data()),
        fixture.sync_directory(),
    ];
    let names: Vec<_> = fixture
        .head_entries()
        .into_iter()
        .map(|entry| entry.name.as_bytes().to_vec())
        .filter(|name| matches!(name.as_slice(), b"tmp.txt" | b"f.txt" | b"x.txt"))
        .collect();
    let mut held = Vec::new();
    for (file, expected) in [
        (&tmp, b"tmp bytes".to_vec()),
        (&copied, {
            let mut bytes = FILE_CONTENT.to_vec();
            bytes[10..17].copy_from_slice(b"partial");
            bytes
        }),
    ] {
        let mut read = vec![0; expected.len()];
        let first = errno(file.read_exact_at(&mut read, 0)).map(|()| read == expected);
        let extended = errno(file.write_at(b"!", 40)).and_then(|()| errno(file.set_len(4)));
        let mut after = vec![0; 4];
        let reread = errno(file.read_exact_at(&mut after, 0)).map(|()| after == expected[..4]);
        held.push((first, extended, reread));
    }
    assert_eq!(
        (calls, names, fixture.remote_seq(), held),
        (
            [Ok(()); 3],
            vec![b"x.txt".to_vec()],
            4,
            vec![(Ok(true), Ok(()), Ok(true)); 2]
        ),
        "(fsync, fdatasync, fsyncdir of x; the head's tmp and x names; head seq; each held \
         descriptor's (read, extend then truncate, reread))"
    );
    drop((tmp, copied, selected));
    fixture.finish();
}

/// An fsync of a never-synced unlinked file through its held descriptor
/// lands with no name for it in the head and records no file sync; later
/// writes through the descriptor stay local and keep serving.
#[test]
fn writable_linux_projected_fsync_unlinked_open_file() {
    if !venue("writable_linux_projected_fsync_unlinked_open_file") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let tmp = fixture.created("tmp.txt", b"tmp bytes");
    std::fs::remove_file(fixture.paths.mountpoint.join("tmp.txt")).unwrap();
    let marks = fixture.synced_marks();
    let synced = errno(tmp.sync_all());
    let named = fixture
        .head_entries()
        .iter()
        .any(|entry| entry.name.as_bytes() == b"tmp.txt");
    let wrote = errno(tmp.write_at(b"TMP", 0));
    let mut read = [0; 9];
    let reread = errno(tmp.read_exact_at(&mut read, 0));
    assert_eq!(
        (
            synced,
            fixture.remote_seq(),
            named,
            fixture.synced_marks() - marks,
            wrote,
            reread,
            &read,
        ),
        (Ok(()), 2, false, 0, Ok(()), Ok(()), b"TMP bytes"),
        "(the unlinked file's fsync, head seq, a head name for it, file syncs recorded, a \
         later write, its read)"
    );
    drop(tmp);
    fixture.finish();
}

/// Omitted namespace work replays by identity: a temporary that replaced
/// f.txt and moved on, and an unsynced child of a directory moved after it
/// was made. x's fsync keeps f.txt durable in the head; the mount keeps the
/// moved file and the child under the directory's new name; a later ordinary
/// commit publishes them.
#[test]
fn writable_linux_projected_namespace_residual_replays() {
    if !venue("writable_linux_projected_namespace_residual_replays") {
        return;
    }
    let deadline = sync_deadline();
    let mut outcomes = Vec::new();
    for case in ["replace then move", "directory moved"] {
        let fixture = SyncMount::published(deadline);
        let root = fixture.paths.mountpoint.clone();
        let (moved, gone) = if case == "replace then move" {
            std::fs::write(root.join("tmp.txt"), b"replacement").unwrap();
            std::fs::rename(root.join("tmp.txt"), root.join("f.txt")).unwrap();
            std::fs::rename(root.join("f.txt"), root.join("moved.txt")).unwrap();
            ("moved.txt", "f.txt")
        } else {
            std::fs::create_dir(root.join("d")).unwrap();
            std::fs::write(root.join("d/u.txt"), b"replacement").unwrap();
            std::fs::rename(root.join("d"), root.join("e")).unwrap();
            ("e/u.txt", "d")
        };
        let selected = fixture.created("x.txt", b"x");
        let synced = errno(selected.sync_all());
        let head = (
            fixture.head_file("f.txt"),
            fixture.head_file("moved.txt"),
            fixture.head_file("x.txt"),
        );
        let mounted = (fixture.mounted(moved), root.join(gone).exists());
        drop(selected);
        let committed = fixture.commit_all(70);
        let later = fixture
            .head_entries()
            .iter()
            .any(|entry| entry.name.as_bytes() == gone.as_bytes());
        outcomes.push((case, synced, head, mounted, committed, later));
        fixture.finish();
    }
    let some = |bytes: &[u8]| Some(bytes.to_vec());
    let row = |case| {
        (
            case,
            Ok(()),
            (some(FILE_CONTENT), None, some(b"x")),
            (some(b"replacement"), false),
            true,
            false,
        )
    };
    assert_eq!(
        outcomes,
        [row("replace then move"), row("directory moved")],
        "(case, x's fsync, head (f, moved, x), (the moved file mounted, its old name \
         mounted), a later ordinary commit lands, the old name in its head)"
    );
}

/// A remote head adds a file while f.txt's local bytes are unsynced: x's
/// fsync rebases, lands the remote file and x, keeps f.txt durable in the
/// head and dirty in the mount. A remote change to f.txt itself, the same
/// size as the local one, refuses x's fsync with ESTALE before anything is
/// sent, and keeps the staged bytes.
#[test]
fn writable_linux_projected_rebase_preserves_remote_and_residual() {
    if !venue("writable_linux_projected_rebase_preserves_remote_and_residual") {
        return;
    }
    let deadline = sync_deadline();
    let mut outcomes = Vec::new();
    for case in ["disjoint", "same path"] {
        let fixture = SyncMount::published(deadline);
        let file = fixture.file();
        file.write_at(b"local B", 0).unwrap();
        // f.txt's copy-up is the only stage so far.
        let local_stage = fixture.staging();
        let scratch = ScratchDir::new();
        let publisher = Store::open(&scratch.0.join("publication")).unwrap();
        if case == "disjoint" {
            disjoint_head(&fixture.tree, &fixture.runtime);
        } else {
            publish_head_from(
                &fixture.tree,
                &fixture.runtime,
                &publisher,
                &edited(b"remote A'"),
                |_| (),
            );
        }
        let selected = fixture.created("x.txt", b"x");
        let sent = fixture.publications();
        let head_of = |fixture: &SyncMount| {
            (
                fixture.head_file("remote.txt").is_some(),
                fixture.head_file("x.txt"),
                fixture.head_file("f.txt"),
            )
        };
        let root = fixture.head_root();
        let synced = errno(selected.sync_all());
        // The remote head's objects are the publisher's, not the mount's, and
        // a refused sync fences the mount's content source besides: read that
        // head from its publisher, and show the refusal did not move it.
        let head = if case == "disjoint" {
            head_of(&fixture)
        } else {
            assert_eq!(fixture.head_root(), root, "the refused sync moved the head");
            (
                fixture.head_file_in(&publisher, "remote.txt").is_some(),
                fixture.head_file_in(&publisher, "x.txt"),
                fixture.head_file_in(&publisher, "f.txt"),
            )
        };
        // x's own stage records its registration's mark before the refusal,
        // so only f.txt's stage is compared: read from disk, past its header,
        // which the fence does not gate.
        let kept = (case == "same path").then(|| {
            let after = fixture.staging();
            local_stage
                .iter()
                .map(|(name, before)| {
                    let now = after.get(name);
                    (
                        now == Some(before),
                        now.and_then(|bytes| bytes.get(STAGE_DATA..).map(<[u8]>::to_vec)),
                    )
                })
                .collect::<Vec<_>>()
        });
        outcomes.push((
            case,
            synced,
            fixture.remote_seq(),
            head,
            (case == "disjoint").then(|| fixture.mounted("f.txt")),
            kept,
            fixture.publications() - sent,
        ));
        drop((file, selected, publisher));
        fixture.finish();
        drop(scratch);
    }
    let some = |bytes: &[u8]| Some(bytes.to_vec());
    assert_eq!(
        outcomes,
        [
            (
                "disjoint",
                Ok(()),
                3,
                (true, some(b"x"), some(FILE_CONTENT)),
                Some(some(&edited(b"local B"))),
                None,
                1
            ),
            (
                "same path",
                STALE,
                2,
                (false, None, some(&edited(b"remote A'"))),
                None,
                Some(vec![(true, some(&edited(b"local B")))]),
                0
            ),
        ],
        "(case, x's fsync, head seq, head (remote file, x, f), mounted f after a landing, f's \
         stage file unchanged by the refusal and its data, publications sent)"
    );
}

/// Successive projected landings with f.txt dirty, renamed between them, and
/// a clean file held open while a remote head changes it. The dirty file stays
/// attached and serving its local bytes while the head keeps its durable
/// ones: the rename of a durable file is an eligible namespace effect, so the
/// second landing publishes it at the new name with the durable bytes. The
/// held clean descriptor keeps its version while a fresh open reads the
/// head's, and nothing fences the mount.
#[test]
fn writable_linux_projected_s2_install_keeps_local_and_held_views() {
    if !venue("writable_linux_projected_s2_install_keeps_local_and_held_views") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let root = fixture.paths.mountpoint.clone();
    let dirty = fixture.file();
    dirty.write_at(b"local B", 0).unwrap();
    let held = std::fs::File::open(root.join("sub/g.txt")).unwrap();
    let remote = edited(b"head");
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), &remote).unwrap();
    });
    let first = fixture.created("x1.txt", b"first");
    let rebased = errno(first.sync_all());
    std::fs::rename(root.join("f.txt"), root.join("renamed.txt")).unwrap();
    let second = fixture.created("x2.txt", b"second");
    let landings = [rebased, errno(second.sync_all())];
    let mut old = vec![0; FILE_CONTENT.len()];
    let held_read = errno(held.read_exact_at(&mut old, 0)).map(|()| old == FILE_CONTENT);
    let dirty_write = errno(dirty.write_at(b"still B", 0));
    let mut local = vec![0; 7];
    let dirty_read = errno(dirty.read_exact_at(&mut local, 0)).map(|()| local == b"still B");
    let third = fixture.created("x3.txt", b"third");
    assert_eq!(
        (
            landings,
            fixture.remote_seq(),
            (fixture.head_file("f.txt"), fixture.head_file("renamed.txt")),
            (held_read, fixture.mounted("sub/g.txt") == Some(remote)),
            (
                dirty_write,
                dirty_read,
                fixture.mounted("renamed.txt").is_some()
            ),
            errno(third.sync_all()),
        ),
        (
            [Ok(()); 2],
            4,
            (None, Some(FILE_CONTENT.to_vec())),
            (Ok(true), true),
            (Ok(()), Ok(true), true),
            Ok(()),
        ),
        "(both fsyncs, head seq, head (f, renamed), (held clean read is the old version, a \
         fresh read is the head's), (dirty write, dirty read, renamed file mounted), a third \
         fsync is not fenced)"
    );
    drop((dirty, held, first, second, third));
    fixture.finish();
}

/// A retained whole-tree lane, constructed and never driven: x's fsync takes
/// it over under its own deadline and lands it, then lands its own capture.
#[test]
fn writable_linux_projected_takeover_uses_caller_deadline() {
    if !venue("writable_linux_projected_takeover_uses_caller_deadline") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let file = fixture.file();
    file.write_at(b"lane", 0).unwrap();
    let lane = fixture.construct_commit(70).unwrap();
    // The publication journal is read only while a commit lane is open, so
    // the retained lane shows as the refusal of a second one.
    let retained = fixture
        .construct_commit(71)
        .err()
        .is_some_and(|error| error.to_string().contains("SyncCommitInFlight"));
    let selected = fixture.created("x.txt", b"own");
    let synced = errno(selected.sync_all());
    assert_eq!(
        (
            retained,
            synced,
            fixture.remote_seq(),
            fixture.head_file("f.txt"),
            fixture.head_file("x.txt"),
        ),
        (
            true,
            Ok(()),
            3,
            Some(edited(b"lane")),
            Some(b"own".to_vec()),
        ),
        "(premise: the lane is retained; x's fsync; head seq; head f is the lane's; head x is \
         the caller's own)"
    );
    drop((lane, file, selected));
    fixture.finish();
}

/// f.txt is synced while held open, so its stage carries that sync's mark;
/// later edits are captured by a whole-tree lane, then more are made after
/// it. x's fsync takes the lane over and installs it, then f.txt's own fsync
/// publishes the lane's content with the later edits at the right size.
#[test]
fn writable_linux_projected_kind11_takeover_ignores_stale_mark() {
    if !venue("writable_linux_projected_kind11_takeover_ignores_stale_mark") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let file = fixture.file();
    file.write_at(b"M1", 0).unwrap();
    let marked = errno(file.sync_all());
    file.write_at(b"landed edit, longer than the mark", 4)
        .unwrap();
    let lane = fixture.construct_commit(70).unwrap();
    file.write_at(b"post", 50).unwrap();
    let selected = fixture.created("x.txt", b"x");
    let taken = errno(selected.sync_all());
    let seq = fixture.remote_seq();
    let own = errno(file.sync_all());
    let local = fixture.mounted("f.txt");
    assert_eq!(
        (
            (marked, taken, seq, own),
            fixture.head_file("f.txt") == local,
            local.map(|bytes| bytes.len()),
        ),
        ((Ok(()), Ok(()), 4, Ok(())), true, Some(54)),
        "((the marked fsync, x's fsync taking the lane over, head seq after it, f's own \
         fsync), head f is the mounted f, its length)"
    );
    drop((lane, file, selected));
    fixture.finish();
}

/// A landing whose readback, refresh or local switch fails is not the call's
/// success: the fsync answers EIO and records a failed sync, though the
/// authority holds the landing and the journal records it.
#[test]
fn writable_linux_projected_pending_and_install_are_not_success() {
    if !venue("writable_linux_projected_pending_and_install_are_not_success") {
        return;
    }
    let deadline = sync_deadline();
    let mut outcomes = Vec::new();
    for phase in ["landed_readback", "landed_refresh", "before_replace"] {
        let fixture = SyncMount::published(deadline);
        let selected = fixture.created("x.txt", b"published");
        fixture
            .faults()
            .arm("sync.commit", phase, 1, crate::FaultAction::Fail);
        let synced = errno(selected.sync_all());
        let journaled = fixture.journal_records().iter().any(|record| {
            matches!(
                record,
                granary_core::overlay_journal::Record::LandedCommit { .. }
            )
        });
        outcomes.push((
            phase,
            synced,
            fired_points(&fixture.faults()).len(),
            fixture.remote_seq(),
            journaled,
            fixture.sync_outcomes(),
        ));
        drop(selected);
        fixture.finish();
    }
    let row = |phase| (phase, EIO, 1, 2, true, (0, 1));
    assert_eq!(
        outcomes,
        [
            row("landed_readback"),
            row("landed_refresh"),
            row("before_replace")
        ],
        "(phase, fsync, faults fired, head seq, landing journaled, (ok, failed) fsyncs)"
    );
}

/// Eight rate-limited publications exhaust x's: its fsync answers ESTALE,
/// as does the next write, and nothing lands.
#[test]
fn writable_linux_projected_exhaustion_is_sticky_estale() {
    if !venue("writable_linux_projected_exhaustion_is_sticky_estale") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let selected = fixture.created("x.txt", b"exhausted");
    let view_before = (fixture.served_pin(), fixture.mount_floor());
    fixture.state.lock().unwrap().publish_refusals = 8;
    let before = fixture.publications();
    let synced = errno(selected.sync_all());
    let sent = fixture.publications() - before;
    let mutation = errno(selected.write_at(b"E", 0));
    assert_eq!(
        (
            synced,
            sent,
            mutation,
            fixture.remote_seq(),
            view_before.1,
            (fixture.served_pin(), fixture.mount_floor()),
        ),
        (STALE, 8, STALE, 1, Some(1), view_before),
        "(x's fsync, publications sent, a later write, head seq, private floor at start, \
         pinned base and private floor unchanged)"
    );
    drop(selected);
    fixture.finish();
}

/// On the published profile a Register refused before it is sent fails that
/// fsync with EIO and reopens admission: the next fsync of the same file
/// lands, and an ordinary commit of later work lands after it.
#[test]
fn writable_linux_projected_prepare_failure_reopens_admission() {
    if !venue("writable_linux_projected_prepare_failure_reopens_admission") {
        return;
    }
    let fixture = SyncMount::published(sync_deadline());
    let selected = fixture.created("x.txt", b"projected");
    fixture.faults().arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Fail,
    );
    let refused = errno(selected.sync_all());
    let seq = fixture.remote_seq();
    let retried = errno(selected.sync_all());
    let landed_x = fixture.head_file("x.txt");
    fixture.file().write_at(b"later", 0).unwrap();
    let committed = fixture.commit_all(70);
    assert_eq!(
        (
            (refused, seq),
            (retried, landed_x),
            committed,
            fixture.head_file("f.txt")
        ),
        (
            (EIO, 1),
            (Ok(()), Some(b"projected".to_vec())),
            true,
            Some(edited(b"later"))
        ),
        "((the refused fsync, head seq), (the retry, head x), an ordinary commit lands, its \
         head f)"
    );
    drop(selected);
    fixture.finish();
}

/// On the default profile a failed caller's Register, refused before it is
/// sent or after its answer, holds nothing open: writes to its file proceed,
/// another file's fsync registers, the failed file's retry registers its
/// bytes, and an ordinary commit lands.
#[test]
fn writable_linux_commit_drains_failed_register_contexts() {
    if !venue("writable_linux_commit_drains_failed_register_contexts") {
        return;
    }
    let deadline = sync_deadline();
    let mut outcomes = Vec::new();
    for phase in ["before_dispatch", "after_response"] {
        let fixture = SyncMount::new(deadline);
        let failed = fixture.file();
        failed.write_at(b"failed caller", 0).unwrap();
        fixture
            .faults()
            .arm("sync.registration", phase, 1, crate::FaultAction::Fail);
        let refused = errno(failed.sync_all());
        let wrote = errno(failed.write_at(b"written after", 0));
        let covering = fixture.created("other.txt", b"covering");
        let covered = errno(covering.sync_all());
        let retried = errno(failed.sync_all());
        let registered = fixture.bytes(b"f.txt") == edited(b"written after");
        let committed = fixture.commit_all(70);
        outcomes.push((
            phase, refused, wrote, covered, retried, registered, committed,
        ));
        drop((failed, covering));
        fixture.finish();
    }
    let row = |phase| (phase, EIO, Ok(()), Ok(()), Ok(()), true, true);
    assert_eq!(
        outcomes,
        [row("before_dispatch"), row("after_response")],
        "(phase, the failed fsync, a later write, another file's fsync, the retry, the \
         retry registered the written bytes, an ordinary commit lands)"
    );
}
