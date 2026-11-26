// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Protected Linux rendezvous directories and lifetime socket ownership.

use granary_client::open_directory;
use granary_core::hash::GrainId;
use std::{
    fs::{self, File},
    io,
    os::{
        fd::AsRawFd as _,
        unix::{
            ffi::OsStrExt as _,
            fs::{
                DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
                PermissionsExt as _,
            },
            net::UnixListener,
        },
    },
    path::{Path, PathBuf},
};

fn refused(what: &'static str) -> io::Error {
    io::Error::other(what)
}

pub(super) fn directory_name(owner: u32) -> PathBuf {
    if owner == 0 {
        PathBuf::from("/run/granary-umount")
    } else {
        PathBuf::from(format!("/run/user/{owner}/granary-umount"))
    }
}
fn socket_stem(namespace: (u64, u64), target: &Path) -> String {
    let mut bytes = b"granary-umount-path-v1\0".to_vec();
    bytes.extend_from_slice(&namespace.0.to_be_bytes());
    bytes.extend_from_slice(&namespace.1.to_be_bytes());
    bytes.extend_from_slice(target.as_os_str().as_bytes());
    GrainId::of(&bytes).digest_hex()
}
pub(super) fn socket_name(namespace: (u64, u64), target: &Path) -> String {
    format!("{}.sock", socket_stem(namespace, target))
}
pub(super) fn support_socket_name(namespace: (u64, u64), target: &Path) -> String {
    let stem = socket_stem(namespace, target)
        .chars()
        .take(56)
        .collect::<String>();
    format!("{stem}.support.sock")
}
fn alias(dir: &File, name: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name)
}
fn pathname(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(refused(
            "refusing: control socket pathname exceeds Linux limit or contains NUL",
        ));
    }
    Ok(())
}
fn ancestor(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(refused(
            "refusing: insecure root-owned control runtime ancestor",
        ));
    }
    Ok(())
}
fn private(file: &File, owner: u32) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o7777 != 0o700 {
        return Err(refused(
            "refusing: control runtime directory requires its owner and mode 0700",
        ));
    }
    Ok(())
}

fn claim_lock(lock: File, owner: u32) -> io::Result<File> {
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.uid() != owner || meta.mode() & 0o7777 != 0o600
    {
        return Err(refused(
            "refusing: control lock requires a sole regular owner-owned mode 0600 file",
        ));
    }
    lock.try_lock()
        .map_err(|_| refused("refusing: control endpoint is locked by another daemon"))?;
    Ok(lock)
}

#[expect(
    clippy::disallowed_methods,
    reason = "open a runtime lock intact with nofollow/nonblocking and mode 0600 on creation; claim_lock verifies the opened descriptor before exclusive acquisition, with no truncation or permission repair"
)]
fn open_lock(path: &Path, owner: u32) -> io::Result<File> {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    claim_lock(lock, owner)
}

pub(super) struct Directory {
    fd: File,
    original: PathBuf,
    owner: u32,
}
impl Directory {
    pub(super) fn open(owner: u32, create: bool) -> io::Result<Self> {
        Self::open_under(Path::new("/run"), owner, create)
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "create only the private child through its pinned checked parent, atomically at 0700; never repair existing permissions"
    )]
    pub(super) fn open_under(run_path: &Path, owner: u32, create: bool) -> io::Result<Self> {
        let run = open_directory(run_path)?;
        ancestor(&run)?;
        let parent = if owner == 0 {
            run
        } else {
            let users = open_directory(&alias(&run, "user"))?;
            ancestor(&users)?;
            let user = open_directory(&alias(&users, owner.to_string()))?;
            private(&user, owner)?;
            user
        };
        let child = alias(&parent, "granary-umount");
        if create {
            match fs::DirBuilder::new().mode(0o700).create(&child) {
                Ok(()) => (),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error),
            }
        }
        let fd = open_directory(&child)?;
        private(&fd, owner)?;
        let advertised = directory_name(owner);
        let relative = advertised
            .strip_prefix("/run")
            .map_err(|_| refused("invalid control runtime prefix"))?;
        let directory = Self {
            fd,
            original: run_path.join(relative),
            owner,
        };
        directory.recheck()?;
        Ok(directory)
    }
    fn recheck(&self) -> io::Result<()> {
        let current = open_directory(&self.original)?;
        private(&current, self.owner)?;
        private(&self.fd, self.owner)?;
        let actual = current.metadata()?;
        let pinned = self.fd.metadata()?;
        if (actual.dev(), actual.ino()) != (pinned.dev(), pinned.ino()) {
            return Err(refused(
                "refusing: control runtime directory binding changed",
            ));
        }
        Ok(())
    }
    pub(super) fn connect_path(
        &self,
        name: &str,
        owner: u32,
    ) -> io::Result<(PathBuf, fs::Metadata)> {
        self.recheck()?;
        let path = alias(&self.fd, name);
        pathname(&self.original.join(name))?;
        pathname(&path)?;
        let meta = fs::symlink_metadata(&path)?;
        if !meta.file_type().is_socket() || meta.uid() != owner || meta.mode() & 0o7777 != 0o600 {
            return Err(refused(
                "refusing: control endpoint requires an owner-owned mode 0600 socket",
            ));
        }
        Ok((path, meta))
    }
    pub(super) fn recheck_socket(&self, name: &str, before: &fs::Metadata) -> io::Result<()> {
        self.recheck()?;
        let after = fs::symlink_metadata(alias(&self.fd, name))?;
        if !after.file_type().is_socket()
            || after.uid() != self.owner
            || after.mode() & 0o7777 != 0o600
        {
            return Err(refused(
                "refusing: control endpoint requires an owner-owned mode 0600 socket",
            ));
        }
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(refused("refusing: control socket inode changed"));
        }
        Ok(())
    }
    pub(super) fn connection_absent(
        &self,
        name: &str,
        before: &fs::Metadata,
        error: &io::Error,
    ) -> bool {
        if !matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        ) {
            return false;
        }
        match self.recheck() {
            Err(check) => {
                error.kind() == io::ErrorKind::NotFound && check.kind() == io::ErrorKind::NotFound
            }
            Ok(()) if error.kind() == io::ErrorKind::NotFound => {
                fs::symlink_metadata(alias(&self.fd, name))
                    .is_err_and(|check| check.kind() == io::ErrorKind::NotFound)
            }
            Ok(()) => self.recheck_socket(name, before).is_ok(),
        }
    }
}

pub(super) struct Endpoint {
    directory: Directory,
    name: String,
    inode: (u64, u64),
    listener: Option<UnixListener>,
    // Dropped last, after listener closure and inode-checked cleanup.
    _lock: File,
}
impl Endpoint {
    pub(super) fn bind(owner: u32, namespace: (u64, u64), target: &Path) -> io::Result<Self> {
        Self::bind_in(Directory::open(owner, true)?, owner, namespace, target)
    }
    pub(super) fn bind_support(
        owner: u32,
        namespace: (u64, u64),
        target: &Path,
    ) -> io::Result<Self> {
        Self::bind_named(Directory::open(owner, true)?, owner, || {
            support_socket_name(namespace, target)
        })
    }
    pub(super) fn bind_in(
        directory: Directory,
        owner: u32,
        namespace: (u64, u64),
        target: &Path,
    ) -> io::Result<Self> {
        Self::bind_named(directory, owner, || socket_name(namespace, target))
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "nontruncating nofollow/nonblocking lock open; descriptor owner/type/mode/link checks precede exclusive try_lock, stale socket removal and bind beneath the pinned private directory"
    )]
    fn bind_named(
        directory: Directory,
        owner: u32,
        name: impl FnOnce() -> String,
    ) -> io::Result<Self> {
        private(&directory.fd, owner)?;
        let name = name();
        let lock_name = name.replace(".sock", ".lock");
        let lock = open_lock(&alias(&directory.fd, lock_name), owner)?;
        directory.recheck()?;
        let path = alias(&directory.fd, &name);
        pathname(&directory.original.join(&name))?;
        pathname(&path)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == owner => {
                fs::remove_file(&path)?;
            }
            Ok(_) => {
                return Err(refused(
                    "refusing: stale endpoint is not a same-owner socket",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        let meta = fs::symlink_metadata(&path)?;
        let mut endpoint = Self {
            directory,
            name,
            inode: (meta.dev(), meta.ino()),
            listener: Some(listener),
            _lock: lock,
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        endpoint.directory.connect_path(&endpoint.name, owner)?;
        endpoint.directory.recheck_socket(&endpoint.name, &meta)?;
        if let Some(listener) = &mut endpoint.listener {
            listener.set_nonblocking(true)?;
        }
        Ok(endpoint)
    }
    pub(super) fn take_listener(&mut self) -> io::Result<UnixListener> {
        self.listener
            .take()
            .ok_or_else(|| refused("control listener already taken"))
    }
}
impl Drop for Endpoint {
    #[expect(
        clippy::disallowed_methods,
        reason = "close listener before unlinking only the socket inode remembered beneath the pinned directory, under the held lifetime lock; never touch a replacement directory"
    )]
    fn drop(&mut self) {
        drop(self.listener.take());
        let path = alias(&self.directory.fd, &self.name);
        if fs::symlink_metadata(&path).is_ok_and(|meta| {
            meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.inode
        }) {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests;
