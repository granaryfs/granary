// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Descriptor-relative publication shared by local protected-file verbs.
//! Policy and codec self-checks belong to the caller. The caller holds the
//! directory flock through read, construction, publication and final sync.

use std::fs::File;
use std::io;
use std::path::Path;

use nix::sys::stat::Mode;

use crate::protected_dir::{DirOps, HeldLock, ProtectedDir, ProtectionError, judge_file};

pub(crate) struct Stages {
    pub(crate) lock: &'static str,
    pub(crate) cleanup: &'static str,
    pub(crate) create: &'static str,
    pub(crate) chown: &'static str,
    pub(crate) chmod: &'static str,
    pub(crate) write: &'static str,
    pub(crate) file_sync: &'static str,
    pub(crate) rename: &'static str,
    pub(crate) dir_sync: &'static str,
    pub(crate) parent_sync: &'static str,
}

#[derive(Debug)]
pub(crate) enum ReplaceError {
    Directory(ProtectionError),
    Unwritten {
        during: &'static str,
        source: io::Error,
    },
    Io {
        during: &'static str,
        source: io::Error,
    },
}

fn unwritten(during: &'static str) -> impl FnOnce(io::Error) -> ReplaceError {
    move |source| ReplaceError::Unwritten { during, source }
}

fn uncertain(during: &'static str) -> impl FnOnce(io::Error) -> ReplaceError {
    move |source| ReplaceError::Io { during, source }
}

pub(crate) fn locked(
    ops: &impl DirOps,
    dir: &Path,
    accept: bool,
    stages: &Stages,
) -> Result<(ProtectedDir, HeldLock), ReplaceError> {
    let protected = ProtectedDir::for_verb(ops, dir, accept).map_err(ReplaceError::Directory)?;
    let held = ops.lock(&protected.dir).map_err(unwritten(stages.lock))?;
    Ok((protected, held))
}

/// Server walks require exact effective-uid ownership, including when root.
pub(crate) fn locked_server(
    ops: &impl DirOps,
    path: &Path,
    accept: bool,
    stages: &Stages,
) -> Result<(ProtectedDir, HeldLock), ReplaceError> {
    let directory = ProtectedDir::for_server(ops, path, accept).map_err(ReplaceError::Directory)?;
    #[cfg(feature = "crash-points")]
    crate::authority::crash::host_io(crate::authority::crash::HostSite::SupportLock)
        .map_err(|_| unwritten(stages.lock)(io::Error::other("support lock injected failure")))?;
    let held = ops.lock(&directory.dir).map_err(unwritten(stages.lock))?;
    let current = ProtectedDir::for_server(ops, path, accept).map_err(ReplaceError::Directory)?;
    if !directory.stat.same_directory(&current.stat) {
        return Err(unwritten(stages.lock)(io::Error::other(
            "support directory changed",
        )));
    }
    Ok((directory, held))
}
/// Preflight both names without following links before removing a stale temp.
/// A planted special or unprotected file is preserved, even at the destination.
pub(crate) fn prepare(
    ops: &impl DirOps,
    directory: &ProtectedDir,
    names: (&str, &str),
    stages: &Stages,
) -> Result<bool, ReplaceError> {
    let mut missing = false;
    for name in [names.0, names.1] {
        match ops.stat_at(&directory.dir, name) {
            Ok(stat) => judge_file(&stat, directory.owner())
                .map_err(|_| unwritten(stages.cleanup)(io::Error::other("unsafe support name")))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if name == names.1 {
                    missing = true;
                }
            }
            Err(error) => return Err(unwritten(stages.cleanup)(error)),
        }
    }
    cleanup(ops, directory, names.0, stages)?;
    Ok(missing)
}

pub(crate) fn cleanup(
    ops: &impl DirOps,
    protected: &ProtectedDir,
    temp_name: &str,
    stages: &Stages,
) -> Result<(), ReplaceError> {
    match ops.unlink_at(&protected.dir, temp_name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(unwritten(stages.cleanup)(e)),
    }
}

/// Publish bytes already self-checked by the caller, while it holds the lock.
/// Rename errors are uncertain: an injected or filesystem error may follow
/// the actual rename. Before rename, a failed temporary is removed best-effort.
pub(crate) fn publish(
    ops: &impl DirOps,
    protected: &ProtectedDir,
    names: (&str, &str),
    bytes: &[u8],
    was_missing: bool,
    stages: &Stages,
) -> Result<(), ReplaceError> {
    let (temp_name, name) = names;
    let temp = ops
        .create_excl_at(&protected.dir, temp_name)
        .map_err(unwritten(stages.create))?;
    // Validate the returned descriptor before chmod, write, or cleanup. A
    // substituted special descriptor must neither block nor lose its name.
    if !ops
        .fstat(&temp)
        .map_err(unwritten(stages.create))?
        .is_file()
    {
        return Err(unwritten(stages.create)(io::Error::other(
            "temporary is not regular",
        )));
    }
    if let Err(e) = fill(ops, protected, protected.euid, &temp, bytes, stages) {
        let _removed = ops.unlink_at(&protected.dir, temp_name);
        return Err(e);
    }
    drop(temp);
    if let Err(e) = ops.rename_at(&protected.dir, temp_name, name) {
        let _removed = ops.unlink_at(&protected.dir, temp_name);
        return Err(uncertain(stages.rename)(e));
    }
    ops.sync_dir(&protected.dir)
        .map_err(uncertain(stages.dir_sync))?;
    if was_missing {
        ops.sync_dir(&protected.parent)
            .map_err(uncertain(stages.parent_sync))?;
    }
    Ok(())
}

/// The effective uid was supplied through `DirOps` at the protected walk.
/// Give the temporary to the owner when root, set its mode, write and sync it.
fn fill(
    ops: &impl DirOps,
    protected: &ProtectedDir,
    effective_uid: u32,
    temp: &File,
    bytes: &[u8],
    stages: &Stages,
) -> Result<(), ReplaceError> {
    if effective_uid == 0 {
        ops.fchown(temp, protected.owner(), protected.gid())
            .map_err(unwritten(stages.chown))?;
    }
    ops.fchmod(temp, Mode::S_IRUSR | Mode::S_IWUSR)
        .map_err(unwritten(stages.chmod))?;
    let mut written = 0;
    while written < bytes.len() {
        let Some(rest) = bytes.get(written..) else {
            break;
        };
        let offset = u64::try_from(written).unwrap_or(u64::MAX);
        match ops.write_at(temp, rest, offset) {
            Ok(0) => {
                return Err(unwritten(stages.write)(io::Error::from(
                    io::ErrorKind::WriteZero,
                )));
            }
            Ok(n) => written = written.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(unwritten(stages.write)(e)),
        }
    }
    ops.sync_file(temp).map_err(unwritten(stages.file_sync))
}
