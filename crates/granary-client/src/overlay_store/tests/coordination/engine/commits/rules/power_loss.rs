// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Reopen and explicit recovery after power loss with a durable journal and
//! independently durable staging bytes.

use super::*;
use granary_core::{
    overlay_discard::Outcome as DiscardOutcome,
    overlay_journal::{self as oj, DeleteKind},
};
use std::collections::BTreeMap;

type Files = BTreeMap<String, Vec<u8>>;
type FileContents = &'static [(&'static str, &'static [u8])];

struct Cut {
    scratch: Scratch,
    io: SimIo,
    remote: Arc<Remote>,
    content: Arc<Content>,
    writer: [u8; 16],
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn fsync(rt: &tokio::runtime::Runtime, f: &Fixture, stage: u64) -> Result<(), CoordinationError> {
    rt.block_on(async {
        f.engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
    })
}

fn fsyncdir(rt: &tokio::runtime::Runtime, f: &Fixture) {
    rt.block_on(async {
        f.engine
            .sync(SyncTarget::Directory(None), SyncOptions::default())
            .wait()
            .await
    })
    .unwrap();
}

fn truncate(f: &Fixture, stage: u64, size: u64) {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, size))
        .unwrap();
}

fn unlink(f: &Fixture, path: &str, stage: u64) {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(Record::Delete {
                at: crate::overlay_store::tests::incremental::loc(path),
                kind: DeleteKind::File {
                    stage_id: Some(stage),
                },
            })
        })
        .unwrap();
}

fn stage_name(stage: u64) -> String {
    format!("{stage:016x}")
}

/// Let one file's dirty pages survive the cut through kernel writeback.
fn writeback(io: &SimIo, file_name: &str) {
    let live = io
        .tree()
        .into_iter()
        .find_map(|(path, bytes)| {
            (path.file_name().is_some_and(|name| name == file_name))
                .then_some(bytes)
                .flatten()
        })
        .unwrap();
    io.mutate_recovered(file_name, |durable| *durable = live);
}

fn cut(f: Fixture) -> Cut {
    let writer = f.store.lock().unwrap().writer_uuid();
    let Fixture {
        _scratch: scratch,
        io,
        store,
        engine,
        remote,
        content,
        ..
    } = f;
    drop(engine);
    drop(
        Arc::into_inner(store)
            .expect("fixture still has a client job")
            .into_inner()
            .unwrap(),
    );
    io.crash();
    Cut {
        scratch,
        io,
        remote,
        content,
        writer,
    }
}

/// The files in the newest published root.
fn head_files(remote: &Remote) -> Files {
    let head = remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    root_files(remote, &head)
}

fn root_files(remote: &Remote, root: &[u8]) -> Files {
    let doc = granary_core::root::decode_root(root).unwrap();
    let objects = remote.objects.read_objects(doc.binmap_index).unwrap();
    crate::writable_store::capture::entries(&objects, doc.manifest_root, 1)
        .unwrap()
        .into_iter()
        .filter(|entry| matches!(entry.kind, EntryKind::File { .. }))
        .map(|entry| {
            let name = String::from_utf8_lossy(entry.name.as_bytes());
            let bytes = cut_file(&objects, root, &name);
            (name.into_owned(), bytes)
        })
        .collect()
}

fn recover_in_place(
    c: &Cut,
    rt: &tokio::runtime::Runtime,
    resend: Option<[u8; 16]>,
) -> Result<crate::RecoveryOutcome, String> {
    c.io.crash();
    recovery_outcome(
        &c.scratch,
        &c.io,
        &c.remote,
        rt,
        c.writer,
        None,
        resend,
        FaultControl::default(),
    )
    .map_err(|e| e.to_string())
}

#[test]
fn recovery_command_settles_area_before_classifying_a_failed_journal_sync() {
    let rt = runtime();
    let c = cut(prepared_fixture(&rt));
    let before = c.io.recovered_bytes("journal").unwrap();
    let (path, _) =
        c.io.tree()
            .into_iter()
            .find(|(path, _)| path.file_name().is_some_and(|name| name == "journal"))
            .unwrap();
    let mut io = c.io.clone();
    io.write_at(&path, before.len() as u64, &[0]).unwrap();
    io.0.lock().unwrap().fail = Some("sync");
    let failed = io.sync(&path);
    assert_eq!(
        (
            failed.err().map(|error| error.to_string()).as_deref(),
            io.recovered_bytes("journal")
        ),
        (Some("model injected I/O"), Some(before))
    );
    let faults = FaultControl::default();
    faults.arm("overlay.open.barrier", "journal", 1, FaultAction::Fail);
    // Any writer or journal evidence read ahead of the barrier must fail
    // with the model's read error instead of reaching the injected barrier.
    io.0.lock().unwrap().read_error_at = Some(0);
    let result = recovery_outcome(
        &c.scratch,
        &io,
        &c.remote,
        &rt,
        c.writer,
        None,
        None,
        faults.clone(),
    );
    assert_eq!(
        (
            result.err().map(|error| error.to_string()).as_deref(),
            faults.fired().len()
        ),
        (Some("overlay I/O: overlay injected fault"), 1),
        "recovery must refuse before relying on the failed append"
    );
}

/// Materialize the durable overlay for the offline discard command.
#[expect(
    clippy::disallowed_methods,
    reason = "create the simulator's durable directories only in the test-owned store"
)]
fn materialize(c: &Cut) {
    use std::{io::Write as _, os::unix::fs::DirBuilderExt as _};

    for (path, bytes) in c.io.tree() {
        if path == c.scratch.0 {
            continue;
        }
        if let Some(bytes) = bytes {
            let mut file = crate::fsguard::create_regular_exclusive(&path).unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        } else {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
        }
    }
}

/// Plan the discard, then acknowledge the selected writer and incarnation.
fn discard(c: &Cut) -> Result<DiscardOutcome, String> {
    materialize(c);
    let settings = config(&c.scratch.0);
    let digest = settings.scope.digest().unwrap();
    let scope = granary_core::overlay_discard::parse_hex(&digest).unwrap();
    let plan = crate::overlay_discard::discard_overlay(&c.scratch.0, scope, &settings.volume, None)
        .map_err(|error| format!("plan: {error}"))?;
    crate::overlay_discard::discard_overlay(
        &c.scratch.0,
        scope,
        &settings.volume,
        Some((plan.name.writer, plan.name.incarnation)),
    )
    .map(|row| row.outcome)
    .map_err(|error| format!("discard: {error}"))
}

/// Take over the old writer from a separate store.
fn recover_fresh(c: &Cut, rt: &tokio::runtime::Runtime) -> Result<(), String> {
    super::super::selected::command_on(&Scratch::new(), &c.remote, rt, c.writer, Some(c.writer))
}

enum Reopen {
    Unchanged(FileContents),
    Rollback(FileContents),
    Refused(&'static str),
    /// Replay rolls the lost extent back, so startup reaches the fenced
    /// publication and stops there with the first message. Recovery with
    /// consent to resend that publication lands it and then stops with the
    /// second message, exactly as the same store does when the later stage
    /// reached disk.
    Fenced(&'static str, [u8; 16], &'static str),
}

struct Shape {
    name: &'static str,
    key: &'static str,
    reopen: Reopen,
    build: fn(&tokio::runtime::Runtime, &Fixture) -> Files,
}

impl Shape {
    fn label(&self) -> String {
        format!("{} ({})", self.name, self.key)
    }
}

fn files(pairs: &[(&str, &[u8])]) -> Files {
    pairs
        .iter()
        .map(|&(name, bytes)| (name.to_owned(), bytes.to_vec()))
        .collect()
}

const Y_ONLY: FileContents = &[("y", b"y-data-1")];
const Y_AND_W: FileContents = &[("y", b"y-data-1"), ("w", b"w-data")];
const W_AND_EMPTY_Y: FileContents = &[("w", b"w-data"), ("y", b"")];
const Y_AND_EMPTY_Z: FileContents = &[("y", b"y-data-1"), ("z", b"")];

use Reopen::{Fenced, Refused, Rollback, Unchanged};

const SYNCED_FILES_SURVIVE: Shape = Shape {
    name: "synced_files_survive",
    key: "c0",
    reopen: Unchanged(Y_AND_W),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// Two separately synced files keep both acknowledged versions.
#[test]
fn synced_files_survive() {
    check_reopen_and_recover(&SYNCED_FILES_SURVIVE);
}

const UNSYNCED_CREATE_WITHOUT_BARRIER_DISAPPEARS: Shape = Shape {
    name: "unsynced_create_without_barrier_disappears",
    key: "c1",
    reopen: Unchanged(&[]),
    build: |_, f| {
        f.create("y", b"y-data-1");
        files(&[])
    },
};

/// A buffered create disappears when its journal records never reach disk.
#[test]
fn unsynced_create_without_barrier_disappears() {
    check_reopen_and_recover(&UNSYNCED_CREATE_WITHOUT_BARRIER_DISAPPEARS);
}

const NEW_FILE_AFTER_OTHER_FILE_SYNC: Shape = Shape {
    name: "new_file_after_other_file_sync",
    key: "s1",
    reopen: Rollback(W_AND_EMPTY_Y),
    build: |rt, f| {
        f.create("y", b"y-data-1");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("w", b"w-data")])
    },
};

/// Syncing another file keeps the new name and rolls its lost extent back to empty.
#[test]
fn new_file_after_other_file_sync() {
    check_reopen_and_recover(&NEW_FILE_AFTER_OTHER_FILE_SYNC);
}

const NEW_FILE_AFTER_DIRECTORY_SYNC: Shape = Shape {
    name: "new_file_after_directory_sync",
    key: "s2",
    reopen: Rollback(&[("y", b"")]),
    build: |rt, f| {
        f.create("y", b"y-data-1");
        fsyncdir(rt, f);
        files(&[])
    },
};

/// A directory sync preserves the new name with empty content after the extent is lost.
#[test]
fn new_file_after_directory_sync() {
    check_reopen_and_recover(&NEW_FILE_AFTER_DIRECTORY_SYNC);
}

const UNLINKED_FILE_AFTER_OTHER_FILE_SYNC: Shape = Shape {
    name: "unlinked_file_after_other_file_sync",
    key: "s3",
    reopen: Rollback(&[("w", b"w-data")]),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        unlink(f, "y", y);
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("w", b"w-data")])
    },
};

/// Rolling back a detached stage keeps its name absent.
#[test]
fn unlinked_file_after_other_file_sync() {
    check_reopen_and_recover(&UNLINKED_FILE_AFTER_OTHER_FILE_SYNC);
}

const FULL_OVERWRITE_AFTER_FILE_SYNC: Shape = Shape {
    name: "full_overwrite_after_file_sync",
    key: "s4",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        published::write(f, y, 0, b"Y-DATA-2");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// A lost full overwrite restores all bytes from the file sync.
#[test]
fn full_overwrite_after_file_sync() {
    check_reopen_and_recover(&FULL_OVERWRITE_AFTER_FILE_SYNC);
}

const PARTIAL_OVERWRITE_AFTER_FILE_SYNC: Shape = Shape {
    name: "partial_overwrite_after_file_sync",
    key: "s5",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        published::write(f, y, 2, b"XX");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// A lost interior overwrite restores the entire acknowledged version.
#[test]
fn partial_overwrite_after_file_sync() {
    check_reopen_and_recover(&PARTIAL_OVERWRITE_AFTER_FILE_SYNC);
}

const APPEND_AFTER_FILE_SYNC: Shape = Shape {
    name: "append_after_file_sync",
    key: "s6",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        published::write(f, y, 8, b"+tail");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// A lost append restores the acknowledged size and bytes.
#[test]
fn append_after_file_sync() {
    check_reopen_and_recover(&APPEND_AFTER_FILE_SYNC);
}

const SHRINK_WITHOUT_WRITE: Shape = Shape {
    name: "shrink_without_write",
    key: "s7",
    reopen: Unchanged(&[("w", b"w-data"), ("y", b"y-d")]),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        truncate(f, y, 3);
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// A durable bare shrink keeps the surviving prefix readable.
#[test]
fn shrink_without_write() {
    check_reopen_and_recover(&SHRINK_WITHOUT_WRITE);
}

const EXTEND_WITHOUT_WRITE: Shape = Shape {
    name: "extend_without_write",
    key: "s8",
    reopen: Unchanged(&[("w", b"w-data"), ("y", b"y-data-1\0\0\0\0\0\0\0\0\0\0\0\0")]),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        truncate(f, y, 20);
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// A durable bare extension keeps the original bytes and exposes a zero-filled tail.
#[test]
fn extend_without_write() {
    check_reopen_and_recover(&EXTEND_WITHOUT_WRITE);
}

const SAME_SIZE_REWRITE_AFTER_TRUNCATE: Shape = Shape {
    name: "same_size_rewrite_after_truncate",
    key: "s9",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        truncate(f, y, 0);
        published::write(f, y, 0, b"Y-DATA-2");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// Truncating to zero and losing a same-size rewrite restores the synced version.
#[test]
fn same_size_rewrite_after_truncate() {
    check_reopen_and_recover(&SAME_SIZE_REWRITE_AFTER_TRUNCATE);
}

const SHORTER_REWRITE_AFTER_TRUNCATE: Shape = Shape {
    name: "shorter_rewrite_after_truncate",
    key: "s10",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        truncate(f, y, 0);
        published::write(f, y, 0, b"Y2");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// Truncating to zero and losing a shorter rewrite restores the synced size and bytes.
#[test]
fn shorter_rewrite_after_truncate() {
    check_reopen_and_recover(&SHORTER_REWRITE_AFTER_TRUNCATE);
}

const OVERWRITE_BEFORE_DIRECTORY_SYNC: Shape = Shape {
    name: "overwrite_before_directory_sync",
    key: "s11",
    reopen: Rollback(Y_ONLY),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        published::write(f, y, 0, b"Y-DATA-2");
        fsyncdir(rt, f);
        files(&[("y", b"y-data-1")])
    },
};

/// A directory sync after an overwrite leaves the previous file sync as the anchor.
#[test]
fn overwrite_before_directory_sync() {
    check_reopen_and_recover(&OVERWRITE_BEFORE_DIRECTORY_SYNC);
}

#[test]
fn directory_sync_registers_rename_at_the_previous_file_checkpoint() {
    use crate::overlay_store::tests::incremental::loc;

    let rt = runtime();
    let f = prepared_fixture(&rt);
    let stage = f.create("before", b"saved");
    fsync(&rt, &f, stage).unwrap();
    let file_root = f.remote.authority.lock().unwrap().root.clone();
    assert_eq!(
        root_files(&f.remote, &file_root),
        files(&[("before", b"saved")])
    );
    assert_eq!(f.marks(), 1);

    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(Record::Move {
                from: loc("before"),
                to: loc("after"),
            })
        })
        .unwrap();
    published::write(&f, stage, 0, b"later");
    fsyncdir(&rt, &f);

    let directory_root = f.remote.authority.lock().unwrap().root.clone();
    let journal = f.io.recovered_bytes("journal").unwrap();
    let mut registration = None;
    oj::scan_journal_with(&journal, |_, record| {
        if let Record::IntentRegistered {
            prepared_root,
            cause,
            ..
        } = record
        {
            registration = Some((*prepared_root, *cause));
        }
    })
    .unwrap();
    assert_eq!(
        root_files(&f.remote, &directory_root),
        files(&[("after", b"saved")]),
        "directory registration carries the file checkpoint under the new name"
    );
    assert_eq!(
        registration,
        Some((GrainId::of(&directory_root), oj::IntentCause::DirectorySync))
    );
    assert_eq!(f.marks(), 1);
    assert_eq!(
        synced_version(&f, stage).as_deref(),
        Some(b"saved".as_slice())
    );
    assert_eq!(
        published::local_file(&f, "after").as_deref(),
        Some(b"later".as_slice())
    );
}

const SECOND_WRITE_WITHOUT_FILE_SYNC: Shape = Shape {
    name: "second_write_without_file_sync",
    key: "s12",
    reopen: Rollback(W_AND_EMPTY_Y),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        published::write(f, y, 0, b"Y-DATA-2");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("w", b"w-data")])
    },
};

/// A second buffered write leaves a new file with an empty rollback anchor.
#[test]
fn second_write_without_file_sync() {
    check_reopen_and_recover(&SECOND_WRITE_WITHOUT_FILE_SYNC);
}

const PUBLISHED_FILE_SURVIVES: Shape = Shape {
    name: "published_file_survives",
    key: "c2",
    reopen: Unchanged(Y_ONLY),
    build: |rt, f| {
        f.create("y", b"y-data-1");
        rt.block_on(published::commit_all(f, 70));
        files(&[("y", b"y-data-1")])
    },
};

/// An installed landing leaves a clean file readable from its base.
#[test]
fn published_file_survives() {
    check_reopen_and_recover(&PUBLISHED_FILE_SURVIVES);
}

const OVERWRITE_OF_STAGE_HELD_ACROSS_LANDING: Shape = Shape {
    name: "overwrite_of_stage_held_across_landing",
    key: "s13",
    reopen: Rollback(Y_ONLY),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        published::hold(f, "y");
        rt.block_on(published::commit_all(f, 70));
        published::write(f, y, 0, b"Y-DATA-2");
        fsyncdir(rt, f);
        files(&[("y", b"y-data-1")])
    },
};

/// An open stage carried across a landing restores the committed version.
#[test]
fn overwrite_of_stage_held_across_landing() {
    check_reopen_and_recover(&OVERWRITE_OF_STAGE_HELD_ACROSS_LANDING);
}

fn overwrite_of_synced_stage_after_landing(
    rt: &tokio::runtime::Runtime,
    f: &Fixture,
    overwrite: &[u8],
    clear_mark: bool,
) -> Files {
    let y = f.create("y", b"y-data-1");
    fsync(rt, f, y).unwrap();
    published::hold(f, "y");
    rt.block_on(published::commit_all(f, 70));
    let journal = f.io.recovered_bytes("journal").unwrap();
    let scan = oj::scan_journal(&journal).unwrap();
    let stage = f.io.recovered_bytes(&stage_name(y)).unwrap();
    let mark = oj::StagingHeader::decode(&stage[..oj::STAGING_HEADER_LEN])
        .unwrap()
        .mark;
    assert!(
        synced_version(f, y).is_none()
            && matches!(mark, oj::MarkState::Present(mark) if mark.synced_size == 8),
        "landing must retain the header alone: journal {:?}, header {mark:?}",
        scan.state.stage(y)
    );
    published::write(f, y, 0, overwrite);
    let w = f.create("w", b"w-data");
    fsync(rt, f, w).unwrap();
    if clear_mark {
        f.io.mutate_recovered(&stage_name(y), |stage| {
            let bytes = &mut stage[..oj::STAGING_HEADER_LEN];
            let mut header = oj::StagingHeader::decode(bytes).unwrap();
            header.mark = oj::MarkState::Absent;
            bytes.copy_from_slice(&header.encode().unwrap());
        });
    }
    files(Y_AND_W)
}

const OVERWRITE_OF_SYNCED_STAGE_HELD_ACROSS_LANDING: Shape = Shape {
    name: "overwrite_of_synced_stage_held_across_landing",
    key: "held mark",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| overwrite_of_synced_stage_after_landing(rt, f, b"Y-DATA-2", false),
};

const GROWTH_OF_SYNCED_STAGE_HELD_ACROSS_LANDING: Shape = Shape {
    name: "growth_of_synced_stage_held_across_landing",
    key: "held mark with growth",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| overwrite_of_synced_stage_after_landing(rt, f, b"Y-DATA-2+tail", false),
};

const OVERWRITE_OF_SYNCED_STAGE_WITH_CLEARED_MARK: Shape = Shape {
    name: "overwrite_of_synced_stage_with_cleared_mark",
    key: "cleared held mark",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| overwrite_of_synced_stage_after_landing(rt, f, b"Y-DATA-2", true),
};

#[test]
fn overwrite_of_synced_stage_held_across_landing() {
    check_reopen_and_recover(&OVERWRITE_OF_SYNCED_STAGE_HELD_ACROSS_LANDING);
}

#[test]
fn growth_of_synced_stage_held_across_landing() {
    check_reopen_and_recover(&GROWTH_OF_SYNCED_STAGE_HELD_ACROSS_LANDING);
}

#[test]
fn overwrite_of_synced_stage_with_cleared_mark() {
    check_reopen_and_recover(&OVERWRITE_OF_SYNCED_STAGE_WITH_CLEARED_MARK);
}

#[test]
fn overwrite_of_rolled_back_stage_held_across_landing() {
    let rt = runtime();
    let (f, y) = restored_synced_file(&rt);
    published::hold(&f, "y");
    rt.block_on(published::commit_all(&f, 90));
    published::write(&f, y, 0, b"Y-DATA-2");
    fsyncdir(&rt, &f);
    persist_content(&f);
    let f = restart(&rt, f).unwrap_or_else(|error| panic!("startup after held landing: {error}"));
    let f = restart(&rt, f).unwrap();
    assert_eq!(
        local_files(&mut f.store.lock().unwrap(), "second startup"),
        Ok(files(Y_AND_W))
    );
    let capture = f.store.lock().unwrap().overlay_transaction(|t| {
        let capture = t.capture(y)?;
        t.complete_failed_capture(&capture)?;
        Ok(capture.chunks().concat())
    });
    assert_eq!(capture.unwrap(), b"y-data-1");
}

#[test]
fn projected_carry_keeps_a_mirror_that_names_its_rollback_checkpoint() {
    let rt = runtime();
    let (f, y) = restored_synced_file(&rt);
    published::hold(&f, "y");
    let v = f.create("v", b"v-data");
    rt.block_on(published::published(
        &f,
        SyncTarget::Stage(v),
        90,
        SyncOptions::default(),
    ))
    .unwrap();
    let journal = f.io.recovered_bytes("journal").unwrap();
    let stage = f.io.recovered_bytes(&stage_name(y)).unwrap();
    let header = oj::StagingHeader::decode(&stage[..oj::STAGING_HEADER_LEN]).unwrap();
    assert_eq!(
        (
            rollback_count(&journal),
            synced_version(&f, y),
            match header.mark {
                oj::MarkState::Present(mark) => Some(
                    f.content
                        .read_content(mark.content, 0, usize::try_from(mark.synced_size).unwrap())
                        .unwrap(),
                ),
                _ => None,
            },
        ),
        (1, None, Some(b"y-data-1".to_vec())),
        "projected carry keeps the rollback and its pre-rollback mirror"
    );
    published::write(&f, y, 0, b"Y-DATA-2");
    fsyncdir(&rt, &f);
    persist_content(&f);
    let f = restart(&rt, f).unwrap_or_else(|error| panic!("projected carry startup: {error}"));
    assert_eq!(published::local_file(&f, "y"), Some(b"y-data-1".to_vec()));
}

const NEW_FILE_AFTER_CAPTURE_AND_LANDING: Shape = Shape {
    name: "new_file_after_capture_and_landing",
    key: "s14",
    reopen: Rollback(Y_AND_EMPTY_Z),
    build: |rt, f| {
        f.create("y", b"y-data-1");
        let lane = rt
            .block_on(
                f.engine
                    .construct_commit(SyncOptions::default(), &mut Entropy(70)),
            )
            .unwrap();
        f.create("z", b"z-data");
        let landed = rt
            .block_on(Box::pin(f.engine.drive_commit(
                &lane,
                &mut Entropy(71),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            )))
            .unwrap();
        assert!(
            matches!(landed.outcome, PublicationOutcome::Landed(_)),
            "{landed:?}"
        );
        files(&[("y", b"y-data-1")])
    },
};

/// Journal replacement keeps a post-capture name while its lost extent rolls back to empty.
#[test]
fn new_file_after_capture_and_landing() {
    check_reopen_and_recover(&NEW_FILE_AFTER_CAPTURE_AND_LANDING);
}

const NEW_FILE_AFTER_UNANSWERED_CAPTURE: Shape = Shape {
    name: "new_file_after_unanswered_capture",
    key: "s15",
    reopen: FENCED_CAPTURE,
    build: |rt, f| {
        fenced_capture(rt, f, false);
        files(&[])
    },
};

const FENCED_CAPTURE: Reopen = Fenced(
    "commit publication 46464646464646464646464646464646 fenced (ESTALE)",
    [0x46; 16],
    "intent refused: RecoveryJournalBlocked",
);

/// Capture y, write z, then exhaust every send so the boundary is fenced.
/// With `flushed`, z's staging bytes reached disk before the power went.
fn fenced_capture(rt: &tokio::runtime::Runtime, f: &Fixture, flushed: bool) {
    f.create("y", b"y-data-1");
    let lane = rt
        .block_on(
            f.engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70)),
        )
        .unwrap();
    let z = f.create("z", b"z-data");
    if flushed {
        writeback(&f.io, &stage_name(z));
    }
    persist_content(f);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Timeout; 8]);
    let result = rt.block_on(budget::drive(f, &lane, &mut Delay));
    assert!(
        matches!(result.outcome, PublicationOutcome::Exhausted),
        "{result:?}"
    );
}

/// The fenced row's outcomes are the fence's own: the same store whose later
/// stage reached disk starts and recovers with the same messages.
#[test]
fn fenced_capture_outcomes_match_a_flushed_store() {
    let flushed = Shape {
        name: "fenced_capture_with_flushed_stage",
        key: "s15-flushed",
        reopen: FENCED_CAPTURE,
        build: |rt, f| {
            fenced_capture(rt, f, true);
            files(&[])
        },
    };
    check_reopen_and_recover(&flushed);
}

/// An open boundary protects the captured file while a later extent rolls back.
#[test]
fn new_file_after_unanswered_capture() {
    check_reopen_and_recover(&NEW_FILE_AFTER_UNANSWERED_CAPTURE);
}

const OVERWRITE_AFTER_COPY_UP: Shape = Shape {
    name: "overwrite_after_copy_up",
    key: "s16",
    reopen: Rollback(Y_AND_W),
    build: |rt, f| {
        let y = copied_up_file(rt, f, b"y-data-1");
        published::write(f, y, 0, b"Y-DATA-2");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        files(&[("y", b"y-data-1"), ("w", b"w-data")])
    },
};

/// A lost overwrite of a copied-up file restores its base bytes.
#[test]
fn overwrite_after_copy_up() {
    check_reopen_and_recover(&OVERWRITE_AFTER_COPY_UP);
}

const JOURNAL_WRITEBACK_WITHOUT_STAGE_WRITEBACK: Shape = Shape {
    name: "journal_writeback_without_stage_writeback",
    key: "m1",
    reopen: Rollback(&[("y", b"")]),
    build: |_, f| {
        f.create("y", b"y-data-1");
        writeback(&f.io, "journal");
        files(&[])
    },
};

/// Journal page writeback alone can leave a new file with an extent to roll back.
#[test]
fn journal_writeback_without_stage_writeback() {
    check_reopen_and_recover(&JOURNAL_WRITEBACK_WITHOUT_STAGE_WRITEBACK);
}

const STAGE_SIZE_WITHOUT_PAYLOAD: Shape = Shape {
    name: "stage_size_without_payload",
    key: "m2",
    reopen: Rollback(W_AND_EMPTY_Y),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        f.io.mutate_recovered(&stage_name(y), |d| d.resize(oj::STAGING_HEADER_LEN + 8, 0));
        files(&[("w", b"w-data")])
    },
};

/// A full-size, zero-filled extent rolls back when its check disagrees.
#[test]
fn stage_size_without_payload() {
    check_reopen_and_recover(&STAGE_SIZE_WITHOUT_PAYLOAD);
}

const PARTIAL_EXTENT_WRITEBACK: Shape = Shape {
    name: "partial_extent_writeback",
    key: "m3",
    reopen: Rollback(W_AND_EMPTY_Y),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        let w = f.create("w", b"w-data");
        fsync(rt, f, w).unwrap();
        f.io.mutate_recovered(&stage_name(y), |d| d.extend_from_slice(b"y-d"));
        files(&[("w", b"w-data")])
    },
};

/// A surviving prefix of a buffered extent rolls back to empty.
#[test]
fn partial_extent_writeback() {
    check_reopen_and_recover(&PARTIAL_EXTENT_WRITEBACK);
}

const UNJOURNALED_OVERWRITE_OF_SYNCED_EXTENT: Shape = Shape {
    name: "unjournaled_overwrite_of_synced_extent",
    key: "m4",
    reopen: Refused("overlay refused: live extent mismatch"),
    build: |rt, f| {
        let y = f.create("y", b"y-data-1");
        fsync(rt, f, y).unwrap();
        published::write(f, y, 0, b"Y-DATA-2");
        writeback(&f.io, &stage_name(y));
        files(&[("y", b"y-data-1")])
    },
};

/// An acknowledged extent with an unjournaled overwrite still refuses replay.
#[test]
fn unjournaled_overwrite_of_synced_extent() {
    check_reopen_and_recover(&UNJOURNALED_OVERWRITE_OF_SYNCED_EXTENT);
}

const SHAPES: &[Shape] = &[
    SYNCED_FILES_SURVIVE,
    UNSYNCED_CREATE_WITHOUT_BARRIER_DISAPPEARS,
    NEW_FILE_AFTER_OTHER_FILE_SYNC,
    NEW_FILE_AFTER_DIRECTORY_SYNC,
    UNLINKED_FILE_AFTER_OTHER_FILE_SYNC,
    FULL_OVERWRITE_AFTER_FILE_SYNC,
    PARTIAL_OVERWRITE_AFTER_FILE_SYNC,
    APPEND_AFTER_FILE_SYNC,
    SHRINK_WITHOUT_WRITE,
    EXTEND_WITHOUT_WRITE,
    SAME_SIZE_REWRITE_AFTER_TRUNCATE,
    SHORTER_REWRITE_AFTER_TRUNCATE,
    OVERWRITE_BEFORE_DIRECTORY_SYNC,
    SECOND_WRITE_WITHOUT_FILE_SYNC,
    PUBLISHED_FILE_SURVIVES,
    OVERWRITE_OF_STAGE_HELD_ACROSS_LANDING,
    NEW_FILE_AFTER_CAPTURE_AND_LANDING,
    NEW_FILE_AFTER_UNANSWERED_CAPTURE,
    OVERWRITE_AFTER_COPY_UP,
    JOURNAL_WRITEBACK_WITHOUT_STAGE_WRITEBACK,
    STAGE_SIZE_WITHOUT_PAYLOAD,
    PARTIAL_EXTENT_WRITEBACK,
    UNJOURNALED_OVERWRITE_OF_SYNCED_EXTENT,
];

fn build_fixture(runtime: &tokio::runtime::Runtime, shape: &Shape) -> (Fixture, Files) {
    let fixture = prepared_fixture(runtime);
    let acknowledged = (shape.build)(runtime, &fixture);
    match try_persist_content(&fixture) {
        Ok(()) => {}
        // The open boundary fixture cached its content before the send budget was exhausted.
        Err(CoordinationError::CommitFenced { .. })
            if matches!(shape.reopen, Reopen::Fenced(..)) => {}
        Err(error) => panic!("{}: persist local content: {error}", shape.label()),
    }
    (fixture, acknowledged)
}

fn build(runtime: &tokio::runtime::Runtime, shape: &Shape) -> (Cut, Files) {
    let (fixture, acknowledged) = build_fixture(runtime, shape);
    (cut(fixture), acknowledged)
}

/// Crash and reopen the same store with the manifest at the published head.
fn restart(
    runtime: &tokio::runtime::Runtime,
    fixture: Fixture,
) -> Result<Fixture, CoordinationError> {
    let seq = *fixture
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .0;
    if seq == 1 {
        runtime.block_on(fixture.try_restart_over(vec![]))
    } else {
        runtime.block_on(fixture.try_restart_at_head())
    }
}

/// Read the reopened namespace, including clean files with no staging file.
fn local_files(local: &mut WritableStore<SimIo>, label: &str) -> Result<Files, String> {
    local
        .overlay_transaction(|overlay| {
            let mut files = Files::new();
            for entry in overlay.entries()? {
                assert!(
                    matches!(entry.kind, OverlayKind::File { .. }) && entry.path.len() == 1,
                    "{label}: unexpected entry {entry:?}"
                );
                let name = String::from_utf8_lossy(entry.path.last().unwrap().as_bytes()).into();
                let length = usize::try_from(entry.size).unwrap();
                let bytes = match entry.stage_id {
                    Some(stage) => overlay.read_stage(stage, 0, length)?,
                    None => overlay.read_base(&entry.path, 0, length)?,
                };
                assert_eq!(bytes.len(), length, "{label}: size of {name}");
                files.insert(name, bytes);
            }
            Ok(files)
        })
        .map_err(|error| error.to_string())
}

/// Report missing files and any byte differences from the acknowledged version.
fn lost(acknowledged: &Files, have: &Files) -> Vec<String> {
    acknowledged
        .iter()
        .filter(|(name, bytes)| have.get(*name) != Some(bytes))
        .map(|(name, bytes)| {
            format!(
                "{name}: acknowledged {:?}, have {:?}",
                String::from_utf8_lossy(bytes),
                have.get(name).map(|bytes| String::from_utf8_lossy(bytes))
            )
        })
        .collect()
}

fn check_reopen_and_recover(shape: &Shape) {
    let runtime = runtime();
    let label = shape.label();
    let (fixture, acknowledged) = build_fixture(&runtime, shape);
    let opened = restart(&runtime, fixture);
    match shape.reopen {
        Reopen::Unchanged(expected) | Reopen::Rollback(expected) => {
            let reopened =
                opened.unwrap_or_else(|error| panic!("{label}: writable startup: {error}"));
            let first = local_files(&mut reopened.store.lock().unwrap(), &label);
            assert_eq!(
                first.as_ref(),
                Ok(&files(expected)),
                "{label}: files after writable startup"
            );
            let first = first.unwrap();
            if matches!(shape.reopen, Reopen::Rollback(_)) {
                assert!(
                    lost(&acknowledged, &first).is_empty(),
                    "{label}: acknowledged files after writable startup: {first:?}, expected {acknowledged:?}"
                );
            }
            let reopened = restart(&runtime, reopened)
                .unwrap_or_else(|error| panic!("{label}: second writable startup: {error}"));
            assert_eq!(
                local_files(&mut reopened.store.lock().unwrap(), &label).as_ref(),
                Ok(&first),
                "{label}: files after second writable startup"
            );
        }
        Reopen::Refused(expected) | Reopen::Fenced(expected, ..) => {
            assert_eq!(
                opened.err().map(|error| error.to_string()).as_deref(),
                Some(expected),
                "{label}: writable startup"
            );
        }
    }

    // Recover from an independent copy of the original cut, before startup
    // has had a chance to roll any extent back.
    let (cut, acknowledged) = build(&runtime, shape);
    let resend = match shape.reopen {
        Reopen::Fenced(_, publication, _) => Some(publication),
        _ => None,
    };
    let recovered = recover_in_place(&cut, &runtime, resend).map(|_| ());
    match shape.reopen {
        Reopen::Fenced(.., expected) => assert_eq!(
            (
                recovered.as_ref().err().map(String::as_str),
                head_files(&cut.remote).get("y").map(Vec::as_slice)
            ),
            (Some(expected), Some(&b"y-data-1"[..])),
            "{label}: same-store recovery resends the captured y"
        ),
        Reopen::Rollback(_) => assert_eq!(
            (recovered, lost(&acknowledged, &head_files(&cut.remote))),
            (Ok(()), vec![]),
            "{label}: same-store recovery and its acknowledged bytes at the head"
        ),
        Reopen::Unchanged(_) => assert_eq!(recovered, Ok(()), "{label}: same-store recovery"),
        Reopen::Refused(expected) => assert_eq!(
            recovered.as_ref().err().map(String::as_str),
            Some(expected),
            "{label}: same-store recovery"
        ),
    }
}

/// Offline discard leaves the head alone. A fresh store can still take
/// over the prepared root and recover each acknowledged version.
#[test]
fn discard_then_takeover_preserves_acknowledged_bytes() {
    let runtime = runtime();
    let mut cases = 0;
    for shape in SHAPES {
        let label = shape.label();
        let (cut, acknowledged) = build(&runtime, shape);
        let before = head_files(&cut.remote);
        // A store whose every file is published owes nothing, so the discard
        // plan refuses it as not eligible and leaves it in place.
        let expected = if shape.key == PUBLISHED_FILE_SURVIVES.key {
            Err("plan: OverlayDiscardNotEligible".to_owned())
        } else {
            Ok(DiscardOutcome::Moved)
        };
        assert_eq!(
            (discard(&cut), head_files(&cut.remote)),
            (expected, before),
            "{label}: discard and published files"
        );
        assert_eq!(
            (
                recover_fresh(&cut, &runtime),
                lost(&acknowledged, &head_files(&cut.remote))
            ),
            (Ok(()), vec![]),
            "{label}: fresh-store takeover and its acknowledged bytes at the head"
        );
        cases += 1;
    }
    assert_eq!(cases, 23);
}

fn prepared_fixture(rt: &tokio::runtime::Runtime) -> Fixture {
    let f = rt.block_on(Fixture::new());
    // Start from a signed empty prepared root, as a writable mount does.
    fsyncdir(rt, &f);
    f
}

fn copied_up_file(rt: &tokio::runtime::Runtime, f: &Fixture, bytes: &[u8]) -> u64 {
    f.create("y", bytes);
    rt.block_on(published::commit_all(f, 70));
    persist_content(f);
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.copy_up(crate::overlay_store::tests::incremental::loc("y")))
        .unwrap()
}

fn restored_synced_file(rt: &tokio::runtime::Runtime) -> (Fixture, u64) {
    let f = prepared_fixture(rt);
    let y = f.create("y", b"y-data-1");
    fsync(rt, &f, y).unwrap();
    published::write(&f, y, 0, b"Y-DATA-2");
    let w = f.create("w", b"w-data");
    fsync(rt, &f, w).unwrap();
    let f = restart(rt, f).unwrap();
    let journal = f.io.recovered_bytes("journal").unwrap();
    assert_eq!(
        (rollback_count(&journal), published::local_file(&f, "y")),
        (1, Some(b"y-data-1".to_vec())),
        "startup restores the synced file and records its rollback"
    );
    (f, y)
}

fn synced_version(f: &Fixture, stage: u64) -> Option<Vec<u8>> {
    let journal = f.io.recovered_bytes("journal").unwrap();
    let mut mark = None;
    oj::scan_journal_with(&journal, |_, record| {
        if let Record::FileSynced {
            stage_id,
            synced_size,
            content,
            ..
        } = record
            && *stage_id == stage
        {
            mark = Some((*content, *synced_size));
        }
    })
    .unwrap();
    let (content, size) = mark?;
    Some(
        f.content
            .read_content(content, 0, usize::try_from(size).unwrap())
            .unwrap_or_else(|error| panic!("read synced content {content:?}: {error}")),
    )
}

fn assert_synced_bytes(f: &Fixture, stage: u64, expected: &[u8]) {
    let local = published::local_file(f, "y");
    let synced = synced_version(f, stage);
    let durable = f.io.recovered_bytes(&stage_name(stage)).unwrap();
    assert_eq!(
        (
            local.as_deref(),
            synced.as_deref(),
            &durable[oj::STAGING_HEADER_LEN..]
        ),
        (Some(expected), Some(expected), expected),
        "local read, synced mark content, and durable stage body"
    );
}

/// Damage whole frames without touching the staging body or its synced mark.
fn damage_last_sync(io: &SimIo, before_write: usize, write_is_lost: bool, corrupt: bool) {
    let journal = io.recovered_bytes("journal").unwrap();
    let prefix = oj::scan_journal(&journal[..before_write]).unwrap();
    let mut offset = prefix.valid_len;
    let first = prefix.state.next_seq();
    let mut frames = Vec::new();
    let scan = oj::scan_journal_with(&journal, |seq, record| {
        if seq >= first {
            frames.push((offset, record.clone()));
            offset += oj::encode_record(&prefix.header, seq, record)
                .unwrap()
                .len();
        }
    })
    .unwrap();
    assert!(
        matches!(
            frames.as_slice(),
            [
                (_, Record::WriteExtent { .. } | Record::Truncate { .. }),
                (_, Record::FileSynced { .. }),
                (_, Record::IntentRegistered { .. })
            ]
        ) && offset == scan.valid_len,
        "expected payload and two receipt frames: {frames:?}, end {offset}, scan {}",
        scan.valid_len
    );
    let damaged = &frames[usize::from(!write_is_lost)..];
    io.mutate_recovered("journal", |durable| {
        if corrupt {
            for (offset, _) in damaged {
                durable[offset + 6] ^= 0x5a;
            }
        } else {
            durable.truncate(damaged[0].0);
        }
    });
}

fn stage_for_damaged_sync(
    rt: &tokio::runtime::Runtime,
    f: &Fixture,
    published_base: Option<&[u8]>,
    held: bool,
) -> u64 {
    let y = if let Some(base) = published_base {
        let y = copied_up_file(rt, f, base);
        if base.len() > 4 {
            truncate(f, y, 4);
        }
        published::write(f, y, 0, b"ABCD");
        y
    } else {
        f.create("y", b"ABCD")
    };
    if held {
        published::hold(f, "y");
    }
    fsync(rt, f, y).unwrap();
    y
}

fn reopen_after_damaged_sync(
    rt: &tokio::runtime::Runtime,
    f: Fixture,
    y: u64,
) -> (Result<Option<Vec<u8>>, String>, bool) {
    let io = f.io.clone();
    let stage = stage_name(y);
    let before = (io.recovered_bytes("journal"), io.recovered_bytes(&stage));
    let result = restart(rt, f)
        .map(|f| published::local_file(&f, "y"))
        .map_err(|error| error.to_string());
    let unchanged = (io.recovered_bytes("journal"), io.recovered_bytes(&stage)) == before;
    (result, unchanged)
}

#[test]
fn synced_mark_beyond_journal_refuses_missing_append() {
    let rt = runtime();
    let mut rows = Vec::new();
    let mut expected = Vec::new();
    for base in [None, Some(&b"abcd"[..])] {
        for held in [false, true] {
            for corrupt in [false, true] {
                let f = prepared_fixture(&rt);
                let y = stage_for_damaged_sync(&rt, &f, base, held);
                let before = f.io.recovered_bytes("journal").unwrap().len();
                published::write(&f, y, 4, b"EFGH");
                fsync(&rt, &f, y).unwrap();
                assert_synced_bytes(&f, y, b"ABCDEFGH");
                persist_content(&f);
                damage_last_sync(&f.io, before, true, corrupt);
                rows.push((base, held, corrupt, reopen_after_damaged_sync(&rt, f, y)));
                expected.push((
                    base,
                    held,
                    corrupt,
                    (
                        Err("overlay refused: synced mark beyond journal".into()),
                        true,
                    ),
                ));
            }
        }
    }
    assert_eq!(
        (rows, expected.len()),
        (expected, 8),
        "lost acknowledged append"
    );
}

#[test]
fn synced_mark_beyond_journal_damage_controls() {
    let rt = runtime();
    let mut rows = Vec::new();
    for case in [
        "intact",
        "lost receipt",
        "damaged receipt",
        "overwritten bytes",
        "earlier peak",
    ] {
        let f = prepared_fixture(&rt);
        let y = stage_for_damaged_sync(&rt, &f, None, false);
        if case == "earlier peak" {
            truncate(&f, y, 8);
            truncate(&f, y, 4);
            fsyncdir(&rt, &f);
        }
        let before = f.io.recovered_bytes("journal").unwrap().len();
        if case == "overwritten bytes" {
            published::write(&f, y, 0, b"ABgh");
        } else {
            published::write(&f, y, 4, b"EFGH");
        }
        fsync(&rt, &f, y).unwrap();
        persist_content(&f);
        if case != "intact" {
            damage_last_sync(
                &f.io,
                before,
                matches!(case, "overwritten bytes" | "earlier peak"),
                case == "damaged receipt",
            );
        }
        let io = f.io.clone();
        let (result, unchanged) = reopen_after_damaged_sync(&rt, f, y);
        let trimmed = (case == "earlier peak").then(|| {
            let stage = io.recovered_bytes(&stage_name(y)).unwrap();
            stage[oj::STAGING_HEADER_LEN..].to_vec()
        });
        rows.push((
            case,
            result,
            (case == "overwritten bytes").then_some(unchanged),
            trimmed,
        ));
    }
    let full = Ok(Some(b"ABCDEFGH".to_vec()));
    assert_eq!(
        rows,
        [
            ("intact", full.clone(), None, None),
            ("lost receipt", full.clone(), None, None),
            ("damaged receipt", full, None, None),
            (
                "overwritten bytes",
                Err("overlay refused: live extent mismatch".into()),
                Some(true),
                None
            ),
            (
                "earlier peak",
                Ok(Some(b"ABCD".to_vec())),
                None,
                Some(b"ABCD".to_vec())
            ),
        ]
    );
}

#[test]
fn synced_mark_beyond_journal_refuses_after_synced_shrink() {
    let rt = runtime();
    let f = prepared_fixture(&rt);
    let y = stage_for_damaged_sync(&rt, &f, Some(b"ABCDEFGH"), false);
    let before = f.io.recovered_bytes("journal").unwrap().len();
    published::write(&f, y, 4, b"EFGH");
    fsync(&rt, &f, y).unwrap();
    assert_synced_bytes(&f, y, b"ABCDEFGH");
    persist_content(&f);
    damage_last_sync(&f.io, before, true, false);
    assert_eq!(
        reopen_after_damaged_sync(&rt, f, y),
        (
            Err("overlay refused: synced mark beyond journal".into()),
            true
        ),
        "bound base agrees with the header, but the current checkpoint and peak do not"
    );
}

#[test]
fn mirror_without_a_journal_receipt_cannot_authorize_a_later_rollback() {
    let rt = runtime();
    let f = prepared_fixture(&rt);
    let y = f.create("y", b"ABCD");
    fsync(&rt, &f, y).unwrap();
    published::write(&f, y, 0, b"EFGH");
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("overlay.mark.sync", "after", 1, FaultAction::Crash);
    let first = fsync(&rt, &f, y);
    assert_eq!(
        (first.is_err(), faults.fired().len()),
        (true, 1),
        "first mark cut: {first:?}, faults {:?}",
        faults.fired()
    );
    let f = restart(&rt, f).unwrap();
    assert_eq!(published::local_file(&f, "y"), Some(b"EFGH".to_vec()));
    published::write(&f, y, 0, b"IJKL");
    fsyncdir(&rt, &f);
    let io = f.io.clone();
    let stage = stage_name(y);
    let before = (io.recovered_bytes("journal"), io.recovered_bytes(&stage));
    let reopened = restart(&rt, f).err().map(|error| error.to_string());
    assert_eq!(
        (
            reopened.as_deref(),
            (io.recovered_bytes("journal"), io.recovered_bytes(&stage)) == before
        ),
        (Some("overlay refused: live extent mismatch"), true),
        "disagreeing mirror with a failing extent"
    );
}

#[test]
fn fsync_after_rollback_and_partial_write() {
    let rt = runtime();
    let (f, y) = restored_synced_file(&rt);
    published::write(&f, y, 2, b"XX");
    assert_eq!(
        published::local_file(&f, "y").as_deref(),
        Some(&b"y-XXta-1"[..])
    );
    fsync(&rt, &f, y).unwrap();
    assert_synced_bytes(&f, y, b"y-XXta-1");
}

#[test]
fn fsync_after_partial_write() {
    let rt = runtime();
    let f = prepared_fixture(&rt);
    let y = f.create("y", b"y-data-1");
    fsync(&rt, &f, y).unwrap();
    published::write(&f, y, 2, b"XX");
    fsync(&rt, &f, y).unwrap();
    assert_synced_bytes(&f, y, b"y-XXta-1");
}

#[test]
fn commit_after_rollback_and_partial_write() {
    let rt = runtime();
    let (f, y) = restored_synced_file(&rt);
    published::write(&f, y, 2, b"XX");
    let expected = Some(b"y-XXta-1".to_vec());
    assert_eq!(published::local_file(&f, "y"), expected, "before commit");
    rt.block_on(published::commit_all(&f, 90));
    persist_content(&f);
    assert_eq!(
        (
            published::head_file(&f, "y"),
            published::local_file(&f, "y")
        ),
        (expected.clone(), expected),
        "published and local bytes after commit"
    );
}

#[test]
fn fsync_after_rollback_to_published_base_and_partial_write() {
    let rt = runtime();
    let f = prepared_fixture(&rt);
    let y = copied_up_file(&rt, &f, b"y-data-1");
    published::write(&f, y, 0, b"Y-DATA-2");
    let w = f.create("w", b"w-data");
    fsync(&rt, &f, w).unwrap();
    let f = restart(&rt, f).unwrap();
    persist_content(&f);
    assert_eq!(
        published::local_file(&f, "y").as_deref(),
        Some(&b"y-data-1"[..]),
        "restored published base"
    );
    published::write(&f, y, 2, b"XX");
    fsync(&rt, &f, y).unwrap();
    assert_synced_bytes(&f, y, b"y-XXta-1");
}

#[test]
fn fsync_after_rollback_and_append() {
    let rt = runtime();
    let (f, y) = restored_synced_file(&rt);
    published::write(&f, y, 8, b"+tail");
    fsync(&rt, &f, y).unwrap();
    assert_synced_bytes(&f, y, b"y-data-1+tail");
}

#[test]
fn commit_after_rollback_and_shrinking_truncate() {
    let rt = runtime();
    let (f, y) = restored_synced_file(&rt);
    truncate(&f, y, 4);
    let expected = Some(b"y-da".to_vec());
    assert_eq!(published::local_file(&f, "y"), expected, "before commit");
    rt.block_on(published::commit_all(&f, 90));
    persist_content(&f);
    assert_eq!(
        (
            published::head_file(&f, "y"),
            published::local_file(&f, "y")
        ),
        (expected.clone(), expected),
        "published and local bytes after commit"
    );
}

#[test]
fn fsync_after_rollback_to_newer_mark_and_partial_write() {
    let rt = runtime();
    let f = prepared_fixture(&rt);
    let y = copied_up_file(&rt, &f, b"y-data-1");
    published::write(&f, y, 0, b"Y-DATA-2");
    fsync(&rt, &f, y).unwrap();
    published::write(&f, y, 0, b"Y-DATA-3");
    let w = f.create("w", b"w-data");
    fsync(&rt, &f, w).unwrap();
    let f = restart(&rt, f).unwrap();
    persist_content(&f);
    assert_eq!(
        published::local_file(&f, "y").as_deref(),
        Some(&b"Y-DATA-2"[..]),
        "restored newer mark"
    );
    published::write(&f, y, 2, b"xx");
    assert_eq!(
        published::local_file(&f, "y").as_deref(),
        Some(&b"Y-xxTA-2"[..]),
        "before fsync"
    );
    fsync(&rt, &f, y).unwrap();
    assert_synced_bytes(&f, y, b"Y-xxTA-2");
}

#[test]
fn second_rollback_restores_synced_partial_write() {
    let rt = runtime();
    let (f, y) = restored_synced_file(&rt);
    published::write(&f, y, 2, b"XX");
    fsync(&rt, &f, y).unwrap();
    let f = restart(&rt, f).unwrap();
    let journal = f.io.recovered_bytes("journal").unwrap();
    assert_eq!(
        (published::local_file(&f, "y"), rollback_count(&journal)),
        (Some(b"y-XXta-1".to_vec()), 1),
        "first startup after the partial write was synced"
    );
    published::write(&f, y, 5, b"ZZZZZZ");
    let v = f.create("v", b"v-data");
    fsync(&rt, &f, v).unwrap();
    let f = restart(&rt, f).unwrap();
    assert_eq!(
        (
            published::local_file(&f, "y"),
            published::local_file(&f, "w"),
            published::local_file(&f, "v")
        ),
        (
            Some(b"y-XXta-1".to_vec()),
            Some(b"w-data".to_vec()),
            Some(b"v-data".to_vec())
        ),
        "startup after the later unsynced write"
    );
}

struct FailingExtent {
    seq: u64,
    stage: u64,
    failure: &'static str,
}

struct Evidence {
    failing: Vec<FailingExtent>,
    marks: BTreeMap<u64, (u64, oj::SyncedMark)>,
    headers: BTreeMap<u64, oj::MarkState>,
    boundary: u64,
}

/// Classify the live recorded extents by reading the durable files alone.
fn evidence(cut: &Cut) -> Evidence {
    let journal = cut.io.recovered_bytes("journal").unwrap();
    let mut marks = BTreeMap::new();
    let mut live: BTreeMap<u64, BTreeMap<u64, (u64, Record)>> = BTreeMap::new();
    let mut boundary = 0;
    oj::scan_journal_with(&journal, |seq, record| match record {
        Record::FileSynced {
            stage_id,
            synced_size,
            content,
            generation,
            ..
        } => {
            marks.insert(
                *stage_id,
                (
                    seq,
                    oj::SyncedMark {
                        synced_size: *synced_size,
                        content: *content,
                        generation: *generation,
                    },
                ),
            );
        }
        Record::WriteExtent {
            stage_id, offset, ..
        } => {
            let stage = live.entry(*stage_id).or_default();
            stage.retain(|_, (_, previous)| !previous.extent_superseded_by(record));
            stage.insert(*offset, (seq, record.clone()));
        }
        Record::Truncate { stage_id, .. } => {
            live.entry(*stage_id)
                .or_default()
                .retain(|_, (_, previous)| !previous.extent_superseded_by(record));
        }
        Record::CommitBoundary { through_seq, .. }
        | Record::ProjectedBoundary { through_seq, .. } => {
            boundary = boundary.max(*through_seq);
        }
        _ => {}
    })
    .unwrap();

    let mut failing = Vec::new();
    let mut headers = BTreeMap::new();
    for (stage, extents) in live {
        let bytes = cut
            .io
            .recovered_bytes(&stage_name(stage))
            .unwrap_or_default();
        if let Some(raw) = bytes.get(..oj::STAGING_HEADER_LEN) {
            headers.insert(stage, oj::StagingHeader::decode(raw).unwrap().mark);
        }
        for (seq, record) in extents.into_values() {
            let Record::WriteExtent {
                offset,
                length,
                check,
                ..
            } = record
            else {
                unreachable!()
            };
            let start = oj::STAGING_HEADER_LEN + usize::try_from(offset).unwrap();
            let end = start + usize::try_from(length).unwrap();
            let failure = match bytes.get(start..end) {
                None => "short",
                Some(staged) if oj::extent_check(stage, offset, staged) != check => "mismatch",
                Some(_) => continue,
            };
            failing.push(FailingExtent {
                seq,
                stage,
                failure,
            });
        }
    }
    Evidence {
        failing,
        marks,
        headers,
        boundary,
    }
}

/// Compare each failing extent's sequence with its own stage's sync and
/// the largest captured boundary. The unjournaled overwrite fails at the sync cutoff.
#[test]
fn failing_extents_follow_acknowledgements_and_captures() {
    let runtime = runtime();
    let mut cases = 0;
    for shape in SHAPES {
        let label = shape.label();
        let (cut, acknowledged) = build(&runtime, shape);
        let evidence = evidence(&cut);
        for (stage, (_, mark)) in &evidence.marks {
            assert_eq!(
                evidence.headers.get(stage),
                Some(&oj::MarkState::Present(*mark)),
                "{label}: mirrored mark for stage {stage}"
            );
            let bytes = cut
                .content
                .read_content(mark.content, 0, usize::try_from(mark.synced_size).unwrap())
                .unwrap();
            assert!(
                acknowledged.values().any(|version| *version == bytes),
                "{label}: stage {stage} marks {:?}, expected one of {acknowledged:?}",
                String::from_utf8_lossy(&bytes)
            );
        }

        let count = evidence.failing.len();
        match shape.reopen {
            Reopen::Unchanged(_) => assert_eq!(count, 0, "{label}: failing extent count"),
            Reopen::Refused(_) => assert_eq!(count, 1, "{label}: failing extent count"),
            Reopen::Rollback(_) | Reopen::Fenced(..) => {
                assert!(count > 0, "{label}: failing extent count {count}");
            }
        }
        for extent in evidence.failing {
            let mark_seq = evidence.marks.get(&extent.stage).map_or(0, |(seq, _)| *seq);
            if mark_seq == 0 {
                assert_eq!(
                    evidence.headers.get(&extent.stage),
                    Some(&oj::MarkState::Absent),
                    "{label}: header mark for stage {}",
                    extent.stage
                );
            }
            assert_eq!(
                (extent.seq > mark_seq, extent.seq > evidence.boundary),
                (!matches!(shape.reopen, Reopen::Refused(_)), true),
                "{label}: stage {} {} extent seq {}, file-synced seq {mark_seq}, boundary through_seq {}",
                extent.stage,
                extent.failure,
                extent.seq,
                evidence.boundary
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 23);
}
