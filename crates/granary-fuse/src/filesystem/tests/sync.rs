// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::filesystem::ReplyError;
use fuser::FileHandle;

pub(super) struct Job;
impl crate::MountSyncJob for Job {
    fn start(self: Box<Self>, completion: crate::SyncCompletion) {
        completion(Ok(()));
    }
}

#[derive(Clone, Default)]
pub(super) struct PendingSyncs(pub(super) Arc<Mutex<Vec<crate::SyncCompletion>>>);
impl std::fmt::Debug for PendingSyncs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PendingSyncs")
            .field(&self.0.lock().unwrap().len())
            .finish()
    }
}

pub(super) struct DeferredJob(pub(super) PendingSyncs);
impl crate::MountSyncJob for DeferredJob {
    fn start(self: Box<Self>, completion: crate::SyncCompletion) {
        self.0.0.lock().unwrap().push(completion);
    }
}

pub(super) struct FailingJob(pub(super) crate::MountSyncError);
impl crate::MountSyncJob for FailingJob {
    fn start(self: Box<Self>, completion: crate::SyncCompletion) {
        completion(Err(self.0));
    }
}

#[test]
fn sync_reply_delivers_one_terminal_for_success_failure_and_abandonment() {
    for (result, outcome) in [
        (Some(Ok(())), crate::CallbackOutcome::Ok),
        (
            Some(Err(crate::MountSyncError::Cancelled)),
            crate::CallbackOutcome::Cancelled,
        ),
        (
            Some(Err(crate::MountSyncError::Backend(crate::MountError::Io))),
            crate::CallbackOutcome::Failed(crate::MountError::Io),
        ),
        (None, crate::CallbackOutcome::Failed(crate::MountError::Io)),
    ] {
        let observer = Arc::new(Replies::default());
        let replies = Arc::new(Mutex::new(Vec::new()));
        let seen = replies.clone();
        let completion = super::super::sync::SyncReply::completion_for_test(
            observer.clone(),
            Box::new(move |result| {
                seen.lock().unwrap().push(result);
            }),
        );
        assert_eq!(
            (
                replies.lock().unwrap().len(),
                observer.0.lock().unwrap().len()
            ),
            (0, 0)
        );
        if let Some(result) = result {
            completion(result);
        } else {
            drop(completion);
        }
        let expected = result.unwrap_or(Err(crate::MountSyncError::Backend(crate::MountError::Io)));
        assert_eq!(
            (
                replies.lock().unwrap().clone(),
                observer.0.lock().unwrap().clone()
            ),
            (vec![expected], vec![(crate::Callback::Fsync, outcome)])
        );
    }
}

#[test]
fn sync_admission_checks_handle_kind_identity_removed_directory_and_ro_before_backend() {
    let mut fs = bound_adapter();
    let (attr, file) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .unwrap();
    let ino = INodeNo(attr.ino);
    let file = file.unwrap();
    let read_only = fs.open_flags_handle(ino, fuser::OpenFlags(0)).unwrap();
    let (directory, _) = fs
        .create_overlay(INodeNo::ROOT, b"dir", NodeKind::Dir, 0o755, None)
        .unwrap();
    let dir_ino = INodeNo(directory.ino);
    let dir = fs.opendir_handle(dir_ino).unwrap();
    assert!(fs.prepare_sync_reply(ino, read_only, false, false).is_ok());
    assert!(fs.prepare_sync_reply(ino, file, true, false).is_ok());
    assert!(fs.prepare_sync_reply(dir_ino, dir, false, true).is_ok());
    let object = fs
        .write_inner(|inner| Ok(*inner.object_handles.get(&u64::from(file)).unwrap()))
        .unwrap();
    assert_ne!(
        object,
        u64::from(ino),
        "fixture must distinguish kernel and overlay identities: object={object}, ino={ino:?}"
    );
    let targets = fs
        .write_inner(|inner| Ok(inner.backend.sync_objects.clone()))
        .unwrap();
    assert_eq!(
        targets,
        vec![object; 2],
        "sync used a kernel inode instead of the handle's bound object"
    );
    let calls = fs
        .write_inner(|inner| Ok(inner.backend.calls.clone()))
        .unwrap();
    assert_eq!(
        &calls[calls.len() - 3..],
        &["fsync", "fdatasync", "fsyncdir"]
    );
    assert_eq!(
        fs.prepare_sync_reply(ino, FileHandle(u64::MAX), false, false)
            .err(),
        Some(ReplyError::Errno(fuser::Errno::EBADF))
    );
    assert_eq!(
        fs.prepare_sync_reply(dir_ino, dir, false, false).err(),
        Some(ReplyError::Errno(fuser::Errno::EBADF))
    );
    assert_eq!(
        fs.prepare_sync_reply(ino, dir, false, true).err(),
        Some(ReplyError::Errno(fuser::Errno::EBADF))
    );
    fs.remove_overlay(INodeNo::ROOT, b"dir", true).unwrap();
    assert_eq!(
        fs.prepare_sync_reply(dir_ino, dir, false, true).err(),
        Some(ReplyError::Errno(fuser::Errno::EINVAL))
    );
    fs.writability = crate::MountWritability::ReadOnly;
    assert_eq!(
        fs.prepare_sync_reply(ino, read_only, true, false).err(),
        Some(ReplyError::Errno(fuser::Errno::ENOSYS))
    );
    let after = fs
        .write_inner(|inner| {
            Ok(inner
                .backend
                .calls
                .iter()
                .filter(|call| matches!(**call, "fsync" | "fdatasync" | "fsyncdir"))
                .count())
        })
        .unwrap();
    assert_eq!(after, 3, "invalid and RO requests reached sync admission");
}

#[test]
fn sync_error_keeps_backend_class_through_adapter_conversion() {
    for (error, outcome) in [
        (
            crate::MountSyncError::Backend(crate::MountError::Corrupt),
            crate::CallbackOutcome::Failed(crate::MountError::Corrupt),
        ),
        (
            crate::MountSyncError::Backend(crate::MountError::Stale),
            crate::CallbackOutcome::Failed(crate::MountError::Stale),
        ),
        (
            crate::MountSyncError::Backend(crate::MountError::Quota),
            crate::CallbackOutcome::Failed(crate::MountError::Quota),
        ),
        (
            crate::MountSyncError::InvalidHandle,
            crate::CallbackOutcome::Refused,
        ),
    ] {
        assert_eq!(
            (
                ReplyError::from(error).errno(),
                ReplyError::from(error).outcome()
            ),
            (error.errno(), outcome),
            "sync failure lost its closed diagnostic class: {error:?}"
        );
    }
}

#[test]
fn pending_setattr_invalid_modes_never_reach_retry() {
    for bound in [false, true] {
        let fs = bound_adapter();
        let (attr, fh) = fs
            .create_overlay(
                INodeNo::ROOT,
                b"mode",
                NodeKind::File,
                0o644,
                Some(fuser::OpenFlags(2)),
            )
            .unwrap();
        let ino = INodeNo(attr.ino);
        fs.write_overlay(ino, fh.unwrap(), 0, b"retained").unwrap();
        fs.write_inner(|inner| {
            inner.backend.shrink_floor = 8;
            Ok(())
        })
        .unwrap();
        let fh = if bound { fh } else { None };
        for mode in [0o600, 0o444, 0o655, 0o4644, 0o1644, u32::MAX] {
            let result = fs
                .setattr_result(ino, Some(mode), Some(0), false, fh)
                .map(|_| ())
                .map_err(ReplyError::errno);
            let calls = fs
                .write_inner(|inner| Ok(inner.backend.path_setattrs + inner.backend.bound_setattrs))
                .unwrap();
            assert_eq!(
                (result, calls),
                (Err(fuser::Errno::ENOTSUP), 0),
                "invalid mode {mode:o}, bound={bound}"
            );
        }
        let valid = fs
            .setattr_result(ino, Some(0o755), Some(0), false, fh)
            .map(|_| ());
        assert!(
            matches!(valid, Err(ReplyError::PendingShrink(_))),
            "valid mode must reach the pending backend: {valid:?}"
        );
    }
}

#[test]
fn pending_setattr_keeps_identity_through_admission_and_final_attributes() {
    for replace in [false, true] {
        let fs = bound_adapter();
        let (attr, fh) = fs
            .create_overlay(
                INodeNo::ROOT,
                b"retry",
                NodeKind::File,
                0o644,
                Some(fuser::OpenFlags(2)),
            )
            .unwrap();
        let ino = INodeNo(attr.ino);
        fs.write_overlay(ino, fh.unwrap(), 0, b"retained").unwrap();
        fs.write_inner(|inner| {
            inner.backend.shrink_floor = 8;
            Ok(())
        })
        .unwrap();
        let pending = fs.setattr_result(ino, None, Some(0), false, None);
        let inode = match pending {
            Err(ReplyError::PendingShrink(inode)) => inode,
            other => panic!("pending premise: {other:?}"),
        };
        let before = *fs.getattr_attr(ino).unwrap();
        fs.write_inner(|inner| {
            if replace {
                let node = inner
                    .backend
                    .nodes
                    .get_mut(&vec![Name::new(b"retry".to_vec()).unwrap()])
                    .unwrap();
                node.stage = Some(inode + 1);
                node.size = 77;
            }
            Ok(())
        })
        .unwrap();
        let _job = fs
            .prepare_setattr_retry(ino, None, None, Some(0), inode)
            .unwrap();
        let (requested, sampled) = fs
            .write_inner(|inner| {
                let requested = inner.backend.shrink_requests.last().unwrap().inode;
                if !replace {
                    inner
                        .backend
                        .nodes
                        .get_mut(&vec![Name::new(b"retry".to_vec()).unwrap()])
                        .unwrap()
                        .size = 0;
                }
                let sampled = GranaryFs::<MutableBackend>::retry_setattr_attr(
                    inner, ino, None, inode, before,
                )
                .map(|attr| attr.size)
                .map_err(ReplyError::errno);
                Ok((requested, sampled))
            })
            .unwrap();
        assert_eq!(
            (requested, sampled),
            (
                inode,
                if replace {
                    Err(fuser::Errno::ESTALE)
                } else {
                    Ok(0)
                }
            ),
            "retry must neither rebind its request nor sample replacement attrs, replace={replace}"
        );
    }
}

#[test]
fn sync_write_dispatches_two_writes_per_flag_and_trusts_retained_handle_flags() {
    #[cfg(target_os = "linux")]
    const O_SYNC: i32 = 0x0010_1000;
    #[cfg(target_os = "macos")]
    const O_SYNC: i32 = 0x80;
    #[cfg(target_os = "linux")]
    const O_DSYNC: i32 = 0x1000;
    #[cfg(target_os = "macos")]
    const O_DSYNC: i32 = 0x0040_0000;
    for (name, flag, expected_sync) in [
        (b"sync".as_slice(), O_SYNC, "fsync"),
        (b"dsync".as_slice(), O_DSYNC, "fdatasync"),
        (b"both".as_slice(), O_SYNC | O_DSYNC, "fsync"),
    ] {
        let mut fs = bound_adapter();
        let observer = Arc::new(Replies::default());
        fs.observer = Some(observer.clone());
        let (attr, fh) = fs
            .create_overlay(
                INodeNo::ROOT,
                name,
                NodeKind::File,
                0o644,
                Some(fuser::OpenFlags(2 | flag)),
            )
            .unwrap();
        let ino = INodeNo(attr.ino);
        let fh = fh.unwrap();
        let object = fs
            .write_inner(|inner| Ok(*inner.object_handles.get(&u64::from(fh)).unwrap()))
            .unwrap();
        let mut replies = Vec::new();
        for (offset, payload) in [(0, b"alpha".as_slice()), (5, b"beta!".as_slice())] {
            let slot = Arc::new(Mutex::new(None));
            let out = slot.clone();
            // Pass request_flags without synchronous bits so the decision must
            // come from the handle's retained open flags.
            fs.write_with_sync(ino, fh, offset, payload, fuser::OpenFlags(2), move |res| {
                *out.lock().unwrap() = Some(res);
            });
            replies.push(slot.lock().unwrap().take());
        }
        // An explicit kernel FSYNC after synchronous WRITE goes through the
        // normal path and is never memo-skipped.
        assert!(fs.prepare_sync_reply(ino, fh, false, false).is_ok());
        let (calls, objects, size) = fs
            .write_inner(|inner| {
                Ok((
                    inner.backend.calls.clone(),
                    inner.backend.sync_objects.clone(),
                    inner.backend.overlay_object(object).unwrap().size,
                ))
            })
            .unwrap();
        assert_eq!(
            (
                replies,
                calls,
                objects,
                size,
                observer.0.lock().unwrap().clone(),
                observer.1.lock().unwrap().clone(),
            ),
            (
                vec![Some(Ok(5)), Some(Ok(5))],
                vec![
                    "create",
                    "write",
                    expected_sync,
                    "write",
                    expected_sync,
                    "fsync"
                ],
                vec![object; 3],
                10,
                vec![
                    (crate::Callback::Write, crate::CallbackOutcome::Ok),
                    (crate::Callback::Write, crate::CallbackOutcome::Ok),
                ],
                vec![(2, 2 | flag), (2, 2 | flag)],
            ),
            "flag={flag:#x}"
        );
    }
}

#[test]
fn sync_write_separate_requests_wait_for_their_jobs_and_pure_read_is_noop() {
    #[cfg(target_os = "linux")]
    const O_SYNC: i32 = 0x0010_1000;
    #[cfg(target_os = "macos")]
    const O_SYNC: i32 = 0x80;
    #[cfg(target_os = "linux")]
    const O_DSYNC: i32 = 0x1000;
    #[cfg(target_os = "macos")]
    const O_DSYNC: i32 = 0x0040_0000;
    let mut fs = bound_adapter();
    let observer = Arc::new(Replies::default());
    fs.observer = Some(observer.clone());
    let pending = Arc::new(Mutex::new(Vec::new()));
    fs.write_inner(|inner| {
        inner.backend.pending_syncs = Some(PendingSyncs(pending.clone()));
        Ok(())
    })
    .unwrap();
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"requests",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2 | O_SYNC)),
        )
        .unwrap();
    let ino = INodeNo(attr.ino);
    let fh = fh.unwrap();

    let first_reply = Arc::new(Mutex::new(None));
    let out1 = first_reply.clone();
    fs.write_with_sync(ino, fh, 0, b"part1-", fuser::OpenFlags(2), move |res| {
        *out1.lock().unwrap() = Some(res);
    });
    assert_eq!(
        (*first_reply.lock().unwrap(), pending.lock().unwrap().len()),
        (None, 1),
        "first request replied before its sync job completed"
    );
    let job1 = pending.lock().unwrap().remove(0);
    job1(Ok(()));
    assert_eq!(*first_reply.lock().unwrap(), Some(Ok(6)));

    let second_reply = Arc::new(Mutex::new(None));
    let out2 = second_reply.clone();
    fs.write_with_sync(ino, fh, 6, b"part2!", fuser::OpenFlags(2), move |res| {
        *out2.lock().unwrap() = Some(res);
    });
    assert_eq!(
        (*second_reply.lock().unwrap(), pending.lock().unwrap().len()),
        (None, 1),
        "second request replied before its own sync job completed"
    );
    let job2 = pending.lock().unwrap().remove(0);
    job2(Ok(()));
    assert_eq!(
        (
            *second_reply.lock().unwrap(),
            fs.getattr_attr(ino).unwrap().size,
            observer.0.lock().unwrap().len(),
        ),
        (Some(Ok(6)), 12, 2)
    );

    // Pure synchronous reads have no write or sync effects.
    for sync in [O_SYNC, O_DSYNC] {
        let ro_fh = fs.open_flags_handle(ino, fuser::OpenFlags(sync)).unwrap();
        let before = fs
            .write_inner(|inner| Ok((inner.backend.calls.len(), inner.backend.sync_objects.len())))
            .unwrap();
        assert_eq!(fs.read_handle_bytes(ino, ro_fh, 0, 12).unwrap().len(), 12);
        let rejected = Arc::new(Mutex::new(None));
        let out = rejected.clone();
        fs.write_with_sync(ino, ro_fh, 0, b"nope", fuser::OpenFlags(sync), move |res| {
            *out.lock().unwrap() = Some(res);
        });
        let after = fs
            .write_inner(|inner| Ok((inner.backend.calls.len(), inner.backend.sync_objects.len())))
            .unwrap();
        assert_eq!(
            (*rejected.lock().unwrap(), after),
            (Some(Err(fuser::Errno::EBADF)), before),
            "pure synchronous read handle must not mutate or dispatch sync"
        );
        fs.release_handle(ro_fh, HandleKind::File).unwrap();
    }
}

#[test]
fn sync_write_error_returns_no_count_and_preserves_recoverable_capture() {
    #[cfg(target_os = "linux")]
    const O_SYNC: i32 = 0x0010_1000;
    #[cfg(target_os = "macos")]
    const O_SYNC: i32 = 0x80;
    for (error, expected_errno, expected_outcome) in [
        (
            crate::MountSyncError::Backend(crate::MountError::Io),
            fuser::Errno::EIO,
            crate::CallbackOutcome::Failed(crate::MountError::Io),
        ),
        (
            crate::MountSyncError::Backend(crate::MountError::Quota),
            fuser::Errno::EDQUOT,
            crate::CallbackOutcome::Failed(crate::MountError::Quota),
        ),
        (
            crate::MountSyncError::Backend(crate::MountError::Stale),
            fuser::Errno::ESTALE,
            crate::CallbackOutcome::Failed(crate::MountError::Stale),
        ),
        (
            crate::MountSyncError::Cancelled,
            fuser::Errno::EINTR,
            crate::CallbackOutcome::Cancelled,
        ),
    ] {
        let mut fs = bound_adapter();
        let observer = Arc::new(Replies::default());
        fs.observer = Some(observer.clone());
        let (attr, fh) = fs
            .create_overlay(
                INodeNo::ROOT,
                b"err",
                NodeKind::File,
                0o644,
                Some(fuser::OpenFlags(2 | O_SYNC)),
            )
            .unwrap();
        let ino = INodeNo(attr.ino);
        let fh = fh.unwrap();
        fs.write_inner(|inner| {
            inner.backend.sync_error = Some(error);
            Ok(())
        })
        .unwrap();
        let reply = Arc::new(Mutex::new(None));
        let out = reply.clone();
        fs.write_with_sync(
            ino,
            fh,
            0,
            b"recoverable",
            fuser::OpenFlags(2),
            move |res| {
                *out.lock().unwrap() = Some(res);
            },
        );
        assert_eq!(
            (
                *reply.lock().unwrap(),
                fs.getattr_attr(ino).unwrap().size,
                fs.read_handle_bytes(ino, fh, 0, 11).unwrap().len(),
                observer.0.lock().unwrap().clone(),
            ),
            (
                Some(Err(expected_errno)),
                11,
                11,
                vec![(crate::Callback::Write, expected_outcome)],
            ),
            "engine failure must return errno with no byte count while preserving local capture"
        );
        fs.write_inner(|inner| {
            inner.backend.sync_error = None;
            Ok(())
        })
        .unwrap();
        let retry = Arc::new(Mutex::new(None));
        let out = retry.clone();
        fs.write_with_sync(ino, fh, 11, b"!", fuser::OpenFlags(2), move |res| {
            *out.lock().unwrap() = Some(res);
        });
        assert_eq!(
            (*retry.lock().unwrap(), fs.getattr_attr(ino).unwrap().size),
            (Some(Ok(1)), 12)
        );
    }

    // Reuse SyncReply::completion_for_test to verify drop abandonment never maps to a count.
    let observer = Arc::new(Replies::default());
    let abandoned = Arc::new(Mutex::new(None));
    let out = abandoned.clone();
    let completion = super::super::sync::SyncReply::completion_for_test(
        observer.clone(),
        Box::new(move |result| {
            *out.lock().unwrap() =
                Some(result.map(|()| 11u32).map_err(crate::MountSyncError::errno));
        }),
    );
    drop(completion);
    assert_eq!(*abandoned.lock().unwrap(), Some(Err(fuser::Errno::EIO)));
}

#[derive(Debug, Default)]
struct CapturedWriteObserver(Arc<Mutex<Vec<crate::CallbackOutcome>>>);
impl crate::CallbackObserver for CapturedWriteObserver {
    fn begin(&self, _: crate::Callback) -> Option<Box<dyn crate::CallbackScope>> {
        None
    }
    fn completed(&self, _: crate::Callback, _: crate::CallbackOutcome) {}
    fn captured(&self, _: crate::Callback) -> Option<Box<dyn crate::DeferredCallbackScope>> {
        Some(Box::new(CapturedWrite {
            outcomes: self.0.clone(),
            finished: false,
        }))
    }
}
#[derive(Debug)]
struct CapturedWrite {
    outcomes: Arc<Mutex<Vec<crate::CallbackOutcome>>>,
    finished: bool,
}
impl crate::DeferredCallbackScope for CapturedWrite {
    fn completed(mut self: Box<Self>, outcome: crate::CallbackOutcome) {
        self.outcomes.lock().unwrap().push(outcome);
        self.finished = true;
    }
}
impl Drop for CapturedWrite {
    fn drop(&mut self) {
        if !self.finished {
            self.outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(crate::CallbackOutcome::Cancelled);
        }
    }
}

#[test]
fn sync_write_keeps_captured_scope_until_engine_outcome() {
    #[cfg(target_os = "linux")]
    const O_SYNC: i32 = 0x0010_1000;
    #[cfg(target_os = "macos")]
    const O_SYNC: i32 = 0x80;
    for result in [
        Some(Ok(())),
        Some(Err(crate::MountSyncError::Cancelled)),
        None,
    ] {
        let mut fs = bound_adapter();
        let observer = Arc::new(CapturedWriteObserver::default());
        fs.observer = Some(observer.clone());
        let pending = Arc::new(Mutex::new(Vec::new()));
        fs.write_inner(|inner| {
            inner.backend.pending_syncs = Some(PendingSyncs(pending.clone()));
            Ok(())
        })
        .unwrap();
        let (attr, fh) = fs
            .create_overlay(
                INodeNo::ROOT,
                b"scoped",
                NodeKind::File,
                0o644,
                Some(fuser::OpenFlags(2 | O_SYNC)),
            )
            .unwrap();
        let reply = Arc::new(Mutex::new(None));
        let out = reply.clone();
        fs.write_with_sync(
            INodeNo(attr.ino),
            fh.unwrap(),
            0,
            b"data",
            fuser::OpenFlags(2),
            move |res| {
                *out.lock().unwrap() = Some(res);
            },
        );
        let premise = (
            observer.0.lock().unwrap().clone(),
            *reply.lock().unwrap(),
            pending.lock().unwrap().len(),
        );
        assert_eq!(
            premise,
            (vec![], None, 1),
            "captured scope ended before the engine result"
        );
        let completion = pending.lock().unwrap().pop().unwrap();
        let expected = match result {
            Some(Ok(())) => crate::CallbackOutcome::Ok,
            Some(Err(_)) => crate::CallbackOutcome::Cancelled,
            None => crate::CallbackOutcome::Failed(crate::MountError::Io),
        };
        if let Some(result) = result {
            completion(result);
        } else {
            drop(completion);
        }
        assert_eq!(observer.0.lock().unwrap().as_slice(), &[expected]);
    }
}
