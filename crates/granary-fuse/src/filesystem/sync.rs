// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Owned sync replies outlive the callback without retaining an adapter lock.

use super::{
    Arc, Duration, GranaryFs, HandleKind, MountBackend, ReplyError, bent, errno, to_file_attr,
    write,
};
use crate::{MountSyncError, MountSyncJob, MountSyncRequest, SyncCompletion};
use fuser::{FileHandle, INodeNo, ReplyEmpty};

pub(super) struct SetattrRetry {
    pub(super) inode: u64,
    pub(super) observation: Option<Box<dyn crate::DeferredCallbackScope>>,
}

pub(super) struct SyncReply {
    terminal: Option<SyncCompletion>,
    observer: Option<Arc<dyn crate::CallbackObserver>>,
    callback: crate::Callback,
    observation: Option<Box<dyn crate::DeferredCallbackScope>>,
}
impl SyncReply {
    fn finish(mut self, result: Result<(), MountSyncError>) {
        self.deliver(result);
    }

    fn deliver(&mut self, result: Result<(), MountSyncError>) {
        if let Some(terminal) = self.terminal.take() {
            let outcome = match result {
                Ok(()) => crate::CallbackOutcome::Ok,
                Err(MountSyncError::Backend(error)) => ReplyError::from(error).outcome(),
                Err(error) => crate::CallbackOutcome::from_errno(Some(error.errno())),
            };
            if let Some(observation) = self.observation.take() {
                observation.completed(outcome);
            }
            if let Some(observer) = &self.observer {
                observer.deferred_completed(self.callback, outcome);
            }
            terminal(result);
        }
    }
}
impl Drop for SyncReply {
    fn drop(&mut self) {
        self.deliver(Err(MountSyncError::Backend(crate::MountError::Io)));
    }
}

impl<B: MountBackend> GranaryFs<B> {
    pub(super) fn prepare_sync_reply(
        &self,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        directory: bool,
    ) -> Result<Box<dyn MountSyncJob>, ReplyError> {
        if self.writability == crate::MountWritability::ReadOnly {
            return Err(fuser::Errno::ENOSYS.into());
        }
        self.write_inner(|inner| {
            let kind = if directory {
                HandleKind::Directory
            } else {
                HandleKind::File
            };
            if !inner.handles.matches(u64::from(fh), u64::from(ino), kind) {
                return Err(fuser::Errno::EBADF.into());
            }
            let request = if directory {
                if !inner.inodes.attached(u64::from(ino)) {
                    return Err(fuser::Errno::EINVAL.into());
                }
                let (path, _, _) = inner.inodes.resolve(u64::from(ino)).map_err(errno)?;
                MountSyncRequest::Directory {
                    path: write::names(path)?,
                    datasync,
                }
            } else {
                let object = inner
                    .object_handles
                    .get(&u64::from(fh))
                    .copied()
                    .ok_or(fuser::Errno::EBADF)?;
                MountSyncRequest::File { object, datasync }
            };
            inner
                .backend
                .prepare_sync(request)
                .map_err(ReplyError::from)
        })
    }

    pub(super) fn prepare_setattr_retry(
        &self,
        ino: INodeNo,
        fh: Option<FileHandle>,
        mode: Option<u32>,
        size: Option<u64>,
        inode: u64,
    ) -> Result<(Box<dyn MountSyncJob>, granary_vfs::Attr), ReplyError> {
        let size = size.ok_or(fuser::Errno::EINVAL)?;
        let current = self.getattr_attr(ino)?;
        let exec = Self::setattr_exec(&current, mode)?;
        let job = self.write_inner(|inner| {
            let path = Self::bound_path(inner, ino, fh, true)?;
            let object = fh
                .and_then(|fh| inner.object_handles.get(&u64::from(fh)))
                .copied();
            inner
                .backend
                .prepare_shrink_retry(crate::MountShrinkRequest {
                    inode,
                    object,
                    path,
                    size,
                    exec,
                })
                .map_err(ReplyError::from)
        })?;
        Ok((job, *current))
    }

    pub(super) fn retry_setattr_attr(
        inner: &mut super::MountInner<B>,
        ino: INodeNo,
        fh: Option<FileHandle>,
        inode: u64,
        mut attr: granary_vfs::Attr,
    ) -> Result<granary_vfs::Attr, ReplyError> {
        let path = Self::bound_path(inner, ino, fh, true)?;
        let (node, nlink) =
            if let Some(object) = fh.and_then(|fh| inner.object_handles.get(&u64::from(fh))) {
                let node = inner.backend.overlay_object(*object)?;
                let nlink = u32::from(inner.inodes.attached(u64::from(ino)));
                (node, nlink)
            } else {
                let metadata = inner.backend.overlay_path(&path)?;
                if metadata.inode != inode {
                    return Err(crate::MountError::Stale.into());
                }
                (metadata.node, metadata.nlink)
            };
        attr.size = node.size;
        attr.blocks = node.size.div_ceil(512);
        attr.perm = granary_vfs::permission_mode(true, node.kind, node.exec);
        attr.nlink = nlink;
        Ok(attr)
    }

    pub(super) fn resume_setattr(
        &self,
        ino: INodeNo,
        fh: Option<FileHandle>,
        mode: Option<u32>,
        size: Option<u64>,
        reply: fuser::ReplyAttr,
        mut retry: SetattrRetry,
    ) {
        let admission = self.prepare_setattr_retry(ino, fh, mode, size, retry.inode);
        let (job, mut attr) = match admission {
            Ok(admitted) => admitted,
            Err(error) => {
                if let Some(observation) = retry.observation.take() {
                    observation.completed(error.outcome());
                }
                if let Some(observer) = &self.observer {
                    observer.deferred_completed(crate::Callback::Setattr, error.outcome());
                }
                reply.error(error.errno());
                return;
            }
        };
        let inner = self.inner.clone();
        let observer = self.observer.clone();
        #[cfg(feature = "conformance-breakage")]
        let breakage = self.breakage;
        let completion = SyncReply {
            terminal: Some(Box::new(move |result| {
                let result = result.map_err(ReplyError::from).and_then(|()| {
                    let mut guard = inner.lock().map_err(|_| fuser::Errno::EIO)?;
                    let inner = guard.as_mut().ok_or(fuser::Errno::EIO)?;
                    attr = Self::retry_setattr_attr(inner, ino, fh, retry.inode, attr)?;
                    let (path, _, _) = inner.inodes.resolve(u64::from(ino)).map_err(errno)?;
                    let time = inner.view.time(&inner.inodes, u64::from(ino), path);
                    #[cfg(feature = "conformance-breakage")]
                    let attr = bent::bend(breakage, attr, time);
                    #[cfg(not(feature = "conformance-breakage"))]
                    let attr = bent::bend(attr, time);
                    Ok(attr)
                });
                if let Some(observation) = retry.observation.take() {
                    observation.completed(
                        result
                            .as_ref()
                            .err()
                            .copied()
                            .map_or(crate::CallbackOutcome::Ok, ReplyError::outcome),
                    );
                }
                if let Some(observer) = &observer {
                    observer.deferred_completed(
                        crate::Callback::Setattr,
                        result
                            .as_ref()
                            .err()
                            .copied()
                            .map_or(crate::CallbackOutcome::Ok, ReplyError::outcome),
                    );
                }
                match result {
                    Ok(attr) => reply.attr(&Duration::ZERO, &to_file_attr(&attr)),
                    Err(error) => reply.error(error.errno()),
                }
            })),
            observer: None,
            callback: crate::Callback::Setattr,
            observation: None,
        };
        job.start(Box::new(move |result| completion.finish(result)));
    }

    pub(super) fn sync_reply(
        &self,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        directory: bool,
        reply: ReplyEmpty,
    ) {
        let callback = if directory {
            crate::Callback::Fsyncdir
        } else {
            crate::Callback::Fsync
        };
        let _scope = self.begin(callback);
        let job = match self.prepare_sync_reply(ino, fh, datasync, directory) {
            Ok(job) => job,
            Err(error) => {
                let error = self
                    .completed::<()>(callback, Err(error))
                    .err()
                    .unwrap_or(fuser::Errno::EIO);
                reply.error(error);
                return;
            }
        };
        let terminal = SyncReply {
            terminal: Some(Box::new(move |result| match result {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(error.errno()),
            })),
            observer: self.observer.clone(),
            callback,
            observation: None,
        };
        job.start(Box::new(move |result| terminal.finish(result)));
    }

    /// Reply-free core of [`Self::finish_sync_write`], separated because
    /// [`fuser::ReplyWrite`] has no public constructor for in-process tests.
    ///
    /// After the ordinary bound write capture succeeds, a synchronous handle
    /// or request ends its thread-local `OverlayWrite` scope on the worker
    /// via [`crate::CallbackObserver::captured`] before dispatching the bound
    /// engine sync job through [`Self::prepare_sync_reply`]. The byte count is
    /// delivered only when the engine job completes with `Ok(())`; any engine
    /// error returns its mapped `Errno` with no byte count while leaving the
    /// captured local write in the overlay.
    pub(super) fn write_with_sync(
        &self,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        flags: fuser::OpenFlags,
        deliver: impl FnOnce(Result<u32, fuser::Errno>) + Send + 'static,
    ) {
        let scope = self.begin(crate::Callback::Write);
        let (written, sync_mode) = match self.write_overlay_request(ino, fh, offset, data, flags) {
            Ok(written) => written,
            Err(error) => {
                let error = self
                    .completed::<u32>(crate::Callback::Write, Err(error))
                    .err()
                    .unwrap_or(fuser::Errno::EIO);
                drop(scope);
                deliver(Err(error));
                return;
            }
        };
        let Some(datasync) = sync_mode else {
            let result = self.completed(crate::Callback::Write, Ok(written));
            drop(scope);
            deliver(result);
            return;
        };
        let observation = self
            .observer
            .as_ref()
            .and_then(|observer| observer.captured(crate::Callback::Write));
        let job = match self.prepare_sync_reply(ino, fh, datasync, false) {
            Ok(job) => job,
            Err(error) => {
                if let Some(observation) = observation {
                    observation.completed(error.outcome());
                }
                if let Some(observer) = &self.observer {
                    observer.deferred_completed(crate::Callback::Write, error.outcome());
                }
                deliver(Err(error.errno()));
                return;
            }
        };
        drop(scope);
        let terminal = SyncReply {
            terminal: Some(Box::new(move |result| match result {
                Ok(()) => deliver(Ok(written)),
                Err(error) => deliver(Err(error.errno())),
            })),
            observer: self.observer.clone(),
            callback: crate::Callback::Write,
            observation,
        };
        job.start(Box::new(move |result| terminal.finish(result)));
    }

    /// Thin `fuser::ReplyWrite` shim over [`Self::write_with_sync`].
    pub(super) fn finish_sync_write(
        &self,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        flags: fuser::OpenFlags,
        reply: fuser::ReplyWrite,
    ) {
        self.write_with_sync(ino, fh, offset, data, flags, move |result| match result {
            Ok(written) => reply.written(written),
            Err(error) => reply.error(error),
        });
    }
}

#[cfg(test)]
impl SyncReply {
    pub(super) fn completion_for_test(
        observer: Arc<dyn crate::CallbackObserver>,
        terminal: SyncCompletion,
    ) -> SyncCompletion {
        let reply = Self {
            terminal: Some(terminal),
            observer: Some(observer),
            callback: crate::Callback::Fsync,
            observation: None,
        };
        Box::new(move |result| reply.finish(result))
    }
}
