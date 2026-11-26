// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ordinary captured writes. Adapter state encloses the one-way mediator call.

use super::view::ViewSlot;
use super::{Bent, GranaryFs, MountInner, ReplyError};
use crate::{MountBackend, check_name_length, errno};
use crate::{OverlayMutation as Mutation, OverlayNode};
use fuser::{FileHandle, INodeNo, OpenAccMode, OpenFlags};
use granary_core::manifest::Name;
use granary_vfs::{Attr, HandleKind, NodeKind, PathKey};

pub(super) fn names(path: &PathKey) -> Result<Vec<Name>, ReplyError> {
    path.iter()
        .map(|part| Name::new(part.clone()).map_err(|_| ReplyError::from(fuser::Errno::EINVAL)))
        .collect()
}

pub(super) fn path_key(path: &[Name]) -> PathKey {
    path.iter().map(|name| name.as_bytes().to_vec()).collect()
}

#[cfg(target_os = "linux")]
const APPEND_FLAG: i32 = 0x400;
#[cfg(target_os = "macos")]
const APPEND_FLAG: i32 = 0x8;

/// Exclusive ownership survives a network wait without retaining the adapter
/// mutex. An unwind abandons the backend rather than running clean shutdown.
/// Every exit tells a waiting install, after the gate is released.
#[derive(Debug)]
struct PlanningInner<'a, B: MountBackend> {
    slot: &'a std::sync::Mutex<Option<MountInner<B>>>,
    view: &'a ViewSlot,
    inner: Option<MountInner<B>>,
}
impl<B: MountBackend> Drop for PlanningInner<'_, B> {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            if std::thread::panicking() {
                inner.backend.abandon();
                self.view.abandon();
            } else {
                *self
                    .slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(inner);
                self.view.returned();
            }
        }
    }
}

impl<B: MountBackend> GranaryFs<B> {
    /// Takes the adapter state out of its slot for a preparation. A waiting
    /// install goes first: the gate is released before the wait, so the
    /// worker waits holding only the slot's own mutex.
    fn take_slot(&self) -> Result<PlanningInner<'_, B>, ReplyError> {
        loop {
            {
                let mut slot = self.inner.lock().map_err(|_| fuser::Errno::EIO)?;
                if !self.view_slot.install_waiting() {
                    let inner = slot.take().ok_or(fuser::Errno::EIO)?;
                    return Ok(PlanningInner {
                        slot: &self.inner,
                        view: &self.view_slot,
                        inner: Some(inner),
                    });
                }
            }
            self.view_slot.wait_for_install();
        }
    }

    /// An inode an install replaced keeps its old content for reads only.
    pub(super) fn refuse_replaced(inner: &MountInner<B>, ino: INodeNo) -> Result<(), ReplyError> {
        if inner.view.replaced(u64::from(ino)) {
            return Err(crate::MountError::Stale.into());
        }
        Ok(())
    }

    pub(super) fn write_inner<R>(
        &self,
        action: impl FnOnce(&mut MountInner<B>) -> Result<R, ReplyError>,
    ) -> Result<R, ReplyError> {
        let mut guard = self.inner.lock().map_err(|_| fuser::Errno::EIO)?;
        let inner = guard.as_mut().ok_or(fuser::Errno::EIO)?;
        action(inner)
    }

    fn child_path(
        inner: &MountInner<B>,
        parent: INodeNo,
        name: &[u8],
    ) -> Result<Vec<Name>, ReplyError> {
        check_name_length(name)?;
        let name = Name::new(name.to_vec()).map_err(|_| fuser::Errno::EINVAL)?;
        let (path, _, kind) = inner.inodes.resolve(u64::from(parent)).map_err(errno)?;
        if !inner.inodes.attached(u64::from(parent)) {
            return Err(fuser::Errno::ENOENT.into());
        }
        if kind != NodeKind::Dir {
            return Err(fuser::Errno::ENOTDIR.into());
        }
        let mut path = names(path)?;
        path.push(name);
        Ok(path)
    }

    pub(super) fn overlay_attr(
        &self,
        inner: &mut MountInner<B>,
        ino: u64,
    ) -> Result<Bent, ReplyError> {
        let (path, _, _) = inner.inodes.resolve(ino).map_err(errno)?;
        if !inner.inodes.attached(ino) {
            let object = inner.object_handles.iter().find_map(|(fh, object)| {
                inner
                    .handles
                    .matches(*fh, ino, HandleKind::File)
                    .then_some(*object)
            });
            let node = if let Some(object) = object {
                inner
                    .backend
                    .overlay_object(object)
                    .map_err(ReplyError::from)?
            } else {
                inner
                    .view
                    .detached(ino)
                    .and_then(|record| record.node.clone())
                    .ok_or(fuser::Errno::ENOENT)?
            };
            return Ok(self.node_attr(inner, &node, ino, 0));
        }
        let path = names(path)?;
        let metadata = inner
            .backend
            .overlay_path(&path)
            .map_err(ReplyError::from)?;
        Ok(self.node_attr(inner, &metadata.node, ino, metadata.nlink))
    }

    pub(super) fn node_attr(
        &self,
        inner: &MountInner<B>,
        node: &OverlayNode,
        ino: u64,
        nlink: u32,
    ) -> Bent {
        self.bend(
            self.node_raw_attr(inner, node, ino, nlink),
            Self::node_time(inner, node, ino),
        )
    }

    /// The time `ino` reports, read from the state the caller already holds.
    pub(super) fn node_time(
        inner: &MountInner<B>,
        node: &OverlayNode,
        ino: u64,
    ) -> std::time::SystemTime {
        inner.view.time(&inner.inodes, ino, &path_key(&node.path))
    }

    pub(super) fn node_raw_attr(
        &self,
        inner: &MountInner<B>,
        node: &OverlayNode,
        ino: u64,
        nlink: u32,
    ) -> Attr {
        let policy = self.snapshot.policy();
        Attr {
            ino,
            generation: inner.inodes.generation(),
            kind: node.kind,
            perm: granary_vfs::permission_mode(true, node.kind, node.exec),
            nlink,
            uid: policy.uid,
            gid: policy.gid,
            size: node.size,
            blocks: node.size.div_ceil(512),
            blksize: 4096,
            time: self.snapshot.timestamp(),
        }
    }

    fn prepare_detach_path(&self, path: &[Name]) -> Result<(), ReplyError> {
        let mut planning = self.take_slot()?;
        planning
            .inner
            .as_mut()
            .ok_or(fuser::Errno::EIO)?
            .backend
            .prepare_detach(path)
            .map_err(ReplyError::from)
    }

    pub(super) fn read_handle_bytes(
        &self,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, ReplyError> {
        if self.writability == crate::MountWritability::Writable {
            let bound = self.write_inner(|inner| {
                Self::bound_path(inner, ino, Some(fh), false)?;
                if size > granary_vfs::READ_MAX_BYTES {
                    return Err(fuser::Errno::EINVAL.into());
                }
                if inner
                    .write_handles
                    .get(&u64::from(fh))
                    .is_some_and(|flags| flags.acc_mode() == OpenAccMode::O_WRONLY)
                {
                    return Err(fuser::Errno::EBADF.into());
                }
                Ok(inner.object_handles.get(&u64::from(fh)).copied())
            })?;
            if let Some(object) = bound {
                // Clean reads need local immutable preparation too.
                let mut planning = self.take_slot()?;
                planning
                    .inner
                    .as_mut()
                    .ok_or(fuser::Errno::EIO)?
                    .backend
                    .prepare_object(object)
                    .map_err(ReplyError::from)?;
                drop(planning);
                return self.write_inner(|inner| {
                    Self::bound_path(inner, ino, Some(fh), false)?;
                    inner
                        .backend
                        .read_object(object, offset, size as usize)
                        .map_err(ReplyError::from)
                });
            }
            if !self.snapshot_fixture {
                return Err(fuser::Errno::ENOSYS.into());
            }
        }
        self.read_bytes(ino, offset, size)
    }

    pub(super) fn symlink_overlay(
        &self,
        parent: INodeNo,
        name: &[u8],
        target: &[u8],
    ) -> Result<Bent, ReplyError> {
        self.new_name_gate()?;
        self.mutation_gate()?;
        if target.len() > crate::FUSE_READLINK_TARGET_MAX_4K_PAGE {
            return Err(fuser::Errno::ENAMETOOLONG.into());
        }
        let target = granary_core::manifest::SymlinkTarget::new(target.to_vec())
            .map_err(|_| fuser::Errno::EINVAL)?;
        self.write_inner(|inner| {
            let path = Self::child_path(inner, parent, name)?;
            let key = path_key(&path);
            inner.inodes.preflight_lookup(&key).map_err(errno)?;
            inner
                .backend
                .overlay_mutate(Mutation::Symlink {
                    path: &path,
                    target: &target,
                })
                .map_err(ReplyError::from)?;
            let metadata = inner
                .backend
                .overlay_path(&path)
                .map_err(ReplyError::from)?;
            let node = &metadata.node;
            let nlink = metadata.nlink;
            let (ino, _) = inner
                .inodes
                .lookup(key, self.snapshot.manifest_root(), NodeKind::Symlink)
                .map_err(errno)?;
            Ok(self.node_attr(inner, node, ino, nlink))
        })
    }

    pub(super) fn create_overlay(
        &self,
        parent: INodeNo,
        name: &[u8],
        kind: NodeKind,
        mode: u32,
        flags: Option<OpenFlags>,
    ) -> Result<(Bent, Option<FileHandle>), ReplyError> {
        self.new_name_gate()?;
        self.mutation_gate()?;
        self.write_inner(|inner| {
            let path = Self::child_path(inner, parent, name)?;
            let key = path_key(&path);
            inner.inodes.preflight_lookup(&key).map_err(errno)?;
            if flags.is_some() {
                inner.handles.preflight_open().map_err(errno)?;
            }
            inner
                .backend
                .overlay_mutate(Mutation::Create {
                    path: &path,
                    kind,
                    exec: mode & 0o111 != 0,
                })
                .map_err(ReplyError::from)?;
            let metadata = inner
                .backend
                .overlay_path(&path)
                .map_err(ReplyError::from)?;
            let node = &metadata.node;
            let nlink = metadata.nlink;
            let object = if flags.is_some() {
                inner
                    .backend
                    .overlay_open(&path)
                    .map_err(ReplyError::from)?
            } else {
                None
            };
            // Allocation was preflighted under this same gate; no backend call
            // follows publication of the kernel's credit and handle holds.
            let (ino, _) = inner
                .inodes
                .lookup(key, self.snapshot.manifest_root(), kind)
                .map_err(errno)?;
            let fh = if let Some(flags) = flags {
                inner.inodes.open(ino).map_err(errno)?;
                let fh = inner.handles.open(ino, HandleKind::File).map_err(errno)?;
                inner.write_handles.insert(fh, flags);
                if let Some(object) = object {
                    inner.object_handles.insert(fh, object);
                }
                Some(FileHandle(fh))
            } else {
                None
            };
            Ok((self.node_attr(inner, node, ino, nlink), fh))
        })
    }

    pub(super) fn open_overlay(
        &self,
        ino: INodeNo,
        flags: OpenFlags,
    ) -> Result<FileHandle, ReplyError> {
        self.write_inner(|inner| {
            // A file a boundary's install replaced is stale, so the kernel
            // looks its name up again; `bound_path` would answer `ENOENT`.
            Self::refuse_replaced(inner, ino)?;
            // Unimplemented test backends retain the immutable read seam.
            match self.overlay_attr(inner, u64::from(ino)) {
                Ok(attr) if attr.kind != NodeKind::File => return Err(fuser::Errno::EISDIR.into()),
                Err(error) if self.snapshot_fixture && error == fuser::Errno::ENOSYS => (),
                Err(error) => return Err(error),
                Ok(_) => (),
            }
            inner.handles.preflight_open().map_err(errno)?;
            inner.inodes.preflight_open(u64::from(ino)).map_err(errno)?;
            let path = Self::bound_path(inner, ino, None, false)?;
            let object = inner
                .backend
                .overlay_open(&path)
                .map_err(ReplyError::from)?;
            inner.inodes.open(u64::from(ino)).map_err(errno)?;
            let fh = inner
                .handles
                .open(u64::from(ino), HandleKind::File)
                .map_err(errno)?;
            inner.write_handles.insert(fh, flags);
            if let Some(object) = object {
                inner.object_handles.insert(fh, object);
            }
            Ok(FileHandle(fh))
        })
    }

    fn prepare_file(&self, ino: INodeNo, fh: Option<FileHandle>) -> Result<(), ReplyError> {
        let mut planning = self.take_slot()?;
        let inner = planning.inner.as_mut().ok_or(fuser::Errno::EIO)?;
        let path = Self::bound_path(inner, ino, fh, true)?;
        // An install may have replaced the inode while this waited for the slot.
        Self::refuse_replaced(inner, ino)?;
        if let Some(object) = fh
            .and_then(|fh| inner.object_handles.get(&u64::from(fh)))
            .copied()
        {
            return inner
                .backend
                .prepare_object(object)
                .map_err(ReplyError::from);
        }
        inner
            .backend
            .prepare_overlay(&path)
            .map_err(ReplyError::from)
    }

    pub(super) fn bound_path(
        inner: &MountInner<B>,
        ino: INodeNo,
        fh: Option<FileHandle>,
        writable: bool,
    ) -> Result<Vec<Name>, ReplyError> {
        if let Some(fh) = fh {
            if !inner
                .handles
                .matches(u64::from(fh), u64::from(ino), HandleKind::File)
            {
                return Err(fuser::Errno::EBADF.into());
            }
            if writable
                && inner
                    .write_handles
                    .get(&u64::from(fh))
                    .is_none_or(|flags| flags.acc_mode() == OpenAccMode::O_RDONLY)
            {
                return Err(fuser::Errno::EBADF.into());
            }
        }
        let (path, _, _) = inner.inodes.resolve(u64::from(ino)).map_err(errno)?;
        if !inner.inodes.attached(u64::from(ino))
            && fh.is_none_or(|fh| !inner.object_handles.contains_key(&u64::from(fh)))
        {
            return Err(fuser::Errno::ENOENT.into());
        }
        names(path)
    }

    pub(super) fn fallocate_handle(
        inner: &MountInner<B>,
        ino: INodeNo,
        fh: FileHandle,
    ) -> Result<(), ReplyError> {
        Self::bound_path(inner, ino, Some(fh), true).map(|_| ())
    }

    pub(super) fn write_overlay_request(
        &self,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        bytes: &[u8],
        request_flags: OpenFlags,
    ) -> Result<(u32, Option<bool>), ReplyError> {
        self.mutation_gate()?;
        self.write_inner(|inner| {
            Self::refuse_replaced(inner, ino)?;
            Self::bound_path(inner, ino, Some(fh), true)?;
            if bytes.len() as u64 > granary_core::overlay_journal::EXTENT_LEN_MAX {
                return Err(fuser::Errno::EINVAL.into());
            }
            let flags = request_flags;
            if flags.0 & APPEND_FLAG == 0 {
                let end = offset
                    .checked_add(bytes.len() as u64)
                    .ok_or(fuser::Errno::EINVAL)?;
                if offset > granary_core::overlay_journal::SIZE_MAX
                    || end > granary_core::overlay_journal::SIZE_MAX
                {
                    return Err(fuser::Errno::EFBIG.into());
                }
            }
            Ok(())
        })?;
        if !bytes.is_empty() {
            self.prepare_file(ino, Some(fh))?;
        }
        self.write_inner(|inner| {
            let path = Self::bound_path(inner, ino, Some(fh), true)?;
            let flags = request_flags;
            let append = flags.0 & APPEND_FLAG != 0;
            let request = if let Some(object) = inner.object_handles.get(&u64::from(fh)) {
                Mutation::BoundWrite {
                    object: *object,
                    offset,
                    bytes,
                    append,
                }
            } else {
                Mutation::Write {
                    path: &path,
                    offset,
                    bytes,
                    append,
                }
            };
            let retained = inner
                .write_handles
                .get(&u64::from(fh))
                .copied()
                .ok_or(fuser::Errno::EBADF)?;
            let sync_mode = super::synchronous_datasync(OpenFlags(retained.0 | request_flags.0));
            let written =
                u32::try_from(bytes.len()).map_err(|_| ReplyError::from(fuser::Errno::EINVAL))?;
            inner
                .backend
                .overlay_mutate(request)
                .map_err(ReplyError::from)?;
            if let Some(observer) = &self.observer {
                observer.write_flags_for_test(request_flags.0, retained.0);
            }
            Ok((written, sync_mode))
        })
    }

    pub(super) fn setattr_exec(
        current: &granary_vfs::Attr,
        mode: Option<u32>,
    ) -> Result<Option<bool>, ReplyError> {
        let exec = if let Some(mode) = mode {
            let permission = mode & !0o170_000;
            if current.kind == NodeKind::File {
                if !matches!(permission, 0o644 | 0o755) {
                    return Err(fuser::Errno::ENOTSUP.into());
                }
            } else if permission != u32::from(current.perm) {
                return Err(fuser::Errno::ENOTSUP.into());
            }
            (permission != u32::from(current.perm)).then_some(permission == 0o755)
        } else {
            None
        };
        Ok(exec)
    }

    pub(super) fn setattr_overlay(
        &self,
        ino: INodeNo,
        mode: Option<u32>,
        size: Option<u64>,
        unsupported: bool,
        fh: Option<FileHandle>,
    ) -> Result<Bent, ReplyError> {
        if mode.is_some() || size.is_some() || unsupported {
            self.mutation_gate()?;
        }
        if unsupported {
            return Err(fuser::Errno::ENOTSUP.into());
        }
        let current = self.getattr_attr(ino)?;
        let exec = Self::setattr_exec(&current, mode)?;
        if size.is_some() && current.kind != NodeKind::File {
            return Err(fuser::Errno::EISDIR.into());
        }
        if size.is_some_and(|size| size > granary_core::overlay_journal::SIZE_MAX) {
            return Err(fuser::Errno::EFBIG.into());
        }
        if mode.is_none() && size.is_none() && fh.is_none() {
            return Ok(current);
        }
        // Linux fchmod supplies an inode without ATTR_FILE/FATTR_FH. A held
        // detached regular file still has its own metadata, never its old name.
        if mode.is_some()
            && size.is_none()
            && fh.is_none()
            && let Some(reply) = self.detached_mode_reply(ino, current, exec)?
        {
            return Ok(reply);
        }
        let bound = self.write_inner(|inner| {
            Self::refuse_replaced(inner, ino)?;
            Self::bound_path(inner, ino, fh, size.is_some())?;
            if exec.is_some() && !inner.inodes.attached(u64::from(ino)) {
                return Err(fuser::Errno::ENOTSUP.into());
            }
            Ok(fh
                .and_then(|fh| inner.object_handles.get(&u64::from(fh)))
                .copied())
        })?;
        if exec.is_none() && size.is_none() {
            return Ok(current);
        }
        let Some(object) = bound else {
            return self.setattr_path(ino, fh, size, exec);
        };
        if size.is_some() {
            self.prepare_file(ino, fh)?;
        }
        self.write_inner(|inner| {
            Self::bound_path(inner, ino, fh, size.is_some())?;
            inner
                .backend
                .overlay_mutate(Mutation::BoundSetattr { object, size, exec })
                .map_err(|error| match error {
                    crate::WriteError::PendingShrink => ReplyError::PendingShrink(object),
                    error => ReplyError::from(error),
                })?;
            self.overlay_attr(inner, u64::from(ino))
        })
    }

    fn setattr_path(
        &self,
        ino: INodeNo,
        fh: Option<FileHandle>,
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<Bent, ReplyError> {
        let mut planning = self.take_slot()?;
        let inner = planning.inner.as_mut().ok_or(fuser::Errno::EIO)?;
        // Ahead of `bound_path`, which answers a replaced inode without a
        // handle `ENOENT`.
        Self::refuse_replaced(inner, ino)?;
        let path = Self::bound_path(inner, ino, fh, size.is_some())?;
        let metadata = match inner.backend.overlay_setattr(&path, size, exec) {
            Ok(metadata) => metadata,
            Err(crate::WriteError::PendingShrink) => {
                // Adapter ownership still excludes unlink/recreation until the
                // original identity has been copied into the deferred request.
                let inode = inner.backend.overlay_path(&path)?.inode;
                return Err(ReplyError::PendingShrink(inode));
            }
            Err(error) => return Err(ReplyError::from(error)),
        };
        Ok(self.node_attr(inner, &metadata.node, u64::from(ino), metadata.nlink))
    }

    fn detached_mode_reply(
        &self,
        ino: INodeNo,
        current: Bent,
        exec: Option<bool>,
    ) -> Result<Option<Bent>, ReplyError> {
        self.write_inner(|inner| {
            if inner.inodes.attached(u64::from(ino)) {
                return Ok(None);
            }
            Self::refuse_replaced(inner, ino)?;
            let held = inner
                .object_handles
                .keys()
                .any(|fh| inner.handles.matches(*fh, u64::from(ino), HandleKind::File));
            if !held {
                return Err(fuser::Errno::ENOENT.into());
            }
            if exec.is_some() {
                return Err(fuser::Errno::ENOTSUP.into());
            }
            Ok(Some(current))
        })
    }

    fn detached_metadata(
        inner: &mut MountInner<B>,
        path: &[Name],
    ) -> Result<Option<OverlayNode>, ReplyError> {
        if inner.inodes.peek(&path_key(path)).is_none() {
            return Ok(None);
        }
        let node = inner
            .backend
            .overlay_path(path)
            .map_err(ReplyError::from)?
            .node;
        Ok(Some(node))
    }

    pub(super) fn remove_overlay(
        &self,
        parent: INodeNo,
        name: &[u8],
        directory: bool,
    ) -> Result<(), ReplyError> {
        self.mutation_gate()?;
        let path = self.write_inner(|inner| Self::child_path(inner, parent, name))?;
        if !directory {
            self.prepare_detach_path(&path)?;
        }
        self.write_inner(|inner| {
            let path = Self::child_path(inner, parent, name)?;
            let detached = Self::detached_metadata(inner, &path)?;
            inner
                .backend
                .overlay_mutate(Mutation::Remove {
                    path: &path,
                    directory,
                })
                .map_err(ReplyError::from)?;
            let key = path_key(&path);
            let metadata = |at: &PathKey| detached.clone().filter(|_| *at == key);
            inner
                .view
                .detach_resident(&mut inner.inodes, &key, &metadata);
            Ok(())
        })
    }

    pub(super) fn rename_overlay(
        &self,
        parent: INodeNo,
        name: &[u8],
        new_parent: INodeNo,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), ReplyError> {
        self.mutation_gate()?;
        if !matches!(flags, 0 | 1) {
            return self.rename_refusal(flags);
        }
        let (source, target) = self.write_inner(|inner| {
            Ok((
                Self::child_path(inner, parent, name)?,
                Self::child_path(inner, new_parent, new_name)?,
            ))
        })?;
        if flags == 0 && source != target {
            self.prepare_detach_path(&target)?;
        }
        self.write_inner(|inner| {
            let from = Self::child_path(inner, parent, name)?;
            let to = Self::child_path(inner, new_parent, new_name)?;
            let detached = if from != to && inner.inodes.peek(&path_key(&to)).is_some() {
                Self::detached_metadata(inner, &to)?
            } else {
                None
            };
            inner
                .backend
                .overlay_mutate(Mutation::Rename {
                    from: &from,
                    to: &to,
                    no_replace: flags == 1,
                })
                .map_err(ReplyError::from)?;
            if from != to {
                let (from, to) = (path_key(&from), path_key(&to));
                let metadata = |at: &PathKey| detached.clone().filter(|_| *at == to);
                inner
                    .view
                    .detach_resident(&mut inner.inodes, &to, &metadata);
                inner.view.move_paths(&from, &to);
                inner.inodes.move_path(&from, &to);
            }
            Ok(())
        })
    }
}
