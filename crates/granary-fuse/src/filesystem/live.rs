// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Current namespace queries and directory credits under the adapter gate.

use super::{Bent, GranaryFs, MountInner, ReplyError, to_file_type};
use crate::{
    DirPlusSink, DirSink, MountBackend, MountError, OverlayMetadata, SinkOutcome, WriteError, errno,
};
use fuser::INodeNo;
use granary_core::manifest::Name;

fn directory_rows<B: MountBackend>(
    backend: &mut B,
    path: &[Name],
) -> Result<Vec<(Vec<u8>, OverlayMetadata)>, ReplyError> {
    for _ in 0..3 {
        let observation = backend.overlay_directory(path).map_err(ReplyError::from)?;
        let mut rows = vec![
            (b".".to_vec(), observation.directory),
            (b"..".to_vec(), observation.parent),
        ];
        let mut cursor = observation.cursor;
        let mut previous: Option<Name> = None;
        loop {
            let page = match backend.overlay_children(&cursor) {
                Ok(page) => page,
                Err(WriteError::Backend(MountError::PlanningExhausted)) => break,
                Err(error) => return Err(error.into()),
            };
            if page.entries.is_empty() && page.next.is_some() {
                return Err(fuser::Errno::EIO.into());
            }
            for child in page.entries {
                let (name, parent) = child.node.path.split_last().ok_or(fuser::Errno::EIO)?;
                if parent != path || previous.as_ref().is_some_and(|last| name <= last) {
                    return Err(fuser::Errno::EIO.into());
                }
                previous = Some(name.clone());
                rows.push((name.as_bytes().to_vec(), child));
            }
            if let Some(next) = page.next {
                cursor = next;
            } else {
                return Ok(rows);
            }
        }
    }
    Err(WriteError::Backend(MountError::PlanningExhausted).into())
}

type CookieRow<'a> = (u64, Vec<u8>, &'a OverlayMetadata);

impl<B: MountBackend> GranaryFs<B> {
    fn live_path(inner: &MountInner<B>, ino: u64) -> Result<Vec<Name>, ReplyError> {
        let (path, _, _) = inner.inodes.resolve(ino).map_err(errno)?;
        if !inner.inodes.attached(ino) {
            return Err(fuser::Errno::ENOENT.into());
        }
        super::write::names(path)
    }

    pub(super) fn lookup_overlay(
        &self,
        inner: &mut MountInner<B>,
        parent: INodeNo,
        name: &[u8],
    ) -> Result<Bent, ReplyError> {
        let parent_path = Self::live_path(inner, u64::from(parent))?;
        let Ok(name) = Name::new(name.to_vec()) else {
            let parent = inner
                .backend
                .overlay_path(&parent_path)
                .map_err(ReplyError::from)?;
            if parent.node.kind != granary_vfs::NodeKind::Dir {
                return Err(fuser::Errno::ENOTDIR.into());
            }
            return Err(fuser::Errno::EINVAL.into());
        };
        let metadata = inner
            .backend
            .overlay_lookup(&parent_path, &name)
            .map_err(ReplyError::from)?;
        let mut child_path = parent_path;
        child_path.push(name);
        let node = &metadata.node;
        if node.path != child_path {
            return Err(fuser::Errno::EIO.into());
        }
        let (ino, _) = inner
            .inodes
            .lookup(
                super::write::path_key(&child_path),
                self.snapshot.manifest_root(),
                node.kind,
            )
            .map_err(errno)?;
        Ok(self.node_attr(inner, node, ino, metadata.nlink))
    }

    fn directory_cookie_rows<'a>(
        inner: &mut MountInner<B>,
        ino: u64,
        fh: u64,
        directory: &'a [(Vec<u8>, OverlayMetadata)],
    ) -> Result<Vec<CookieRow<'a>>, ReplyError> {
        if !inner
            .handles
            .matches(fh, ino, granary_vfs::HandleKind::Directory)
        {
            return Err(fuser::Errno::EBADF.into());
        }
        let cursor = inner
            .directory_cursors
            .get_mut(&fh)
            .ok_or(fuser::Errno::EBADF)?;
        let mut next = cursor.values().copied().max().unwrap_or(0);
        let mut rows = Vec::new();
        for (name, node) in directory {
            let cookie = if let Some(cookie) = cursor.get(name) {
                *cookie
            } else {
                next = next.checked_add(1).ok_or(fuser::Errno::EOVERFLOW)?;
                cursor.insert(name.clone(), next);
                next
            };
            rows.push((cookie, name.clone(), node));
        }
        rows.sort_by_key(|row| row.0);
        Ok(rows)
    }

    pub(super) fn list_overlay<S: DirSink>(
        inner: &mut MountInner<B>,
        ino: u64,
        fh: u64,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), ReplyError> {
        let path = Self::live_path(inner, ino)?;
        let directory = directory_rows(&mut inner.backend, &path)?;
        let rows = Self::directory_cookie_rows(inner, ino, fh, &directory)?;
        for (next, name, metadata) in rows {
            let node = &metadata.node;
            if next <= offset {
                continue;
            }
            let child = inner
                .inodes
                .peek(&super::write::path_key(&node.path))
                .unwrap_or(0);
            if sink.offer(child, to_file_type(node.kind), &name, next) == SinkOutcome::Full {
                break;
            }
        }
        Ok(())
    }

    pub(super) fn list_overlay_plus<S: DirPlusSink>(
        &self,
        inner: &mut MountInner<B>,
        ino: u64,
        fh: u64,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), ReplyError> {
        let path = Self::live_path(inner, ino)?;
        let directory = directory_rows(&mut inner.backend, &path)?;
        let rows = Self::directory_cookie_rows(inner, ino, fh, &directory)?;
        for (next, name, metadata) in rows {
            let node = &metadata.node;
            if next <= offset {
                continue;
            }
            let nlink = metadata.nlink;
            let dot = name == b"." || name == b"..";
            let key = super::write::path_key(&node.path);
            let child = if dot {
                inner.inodes.peek(&key).unwrap_or(0)
            } else {
                inner
                    .inodes
                    .lookup(key, self.snapshot.manifest_root(), node.kind)
                    .map_err(errno)?
                    .0
            };
            // Raw attributes are bent exactly once by the terminal PLUS sink.
            // The time is read here: the sink cannot retake the held gate.
            let attr = self.node_raw_attr(inner, node, child, nlink);
            let time = Self::node_time(inner, node, child);
            if sink.offer_timed(attr, time, &name, next) == SinkOutcome::Full {
                if !dot {
                    inner.inodes.forget(child, 1);
                }
                break;
            }
        }
        Ok(())
    }
}
