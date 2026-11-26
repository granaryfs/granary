// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Descriptor-relative opens and mount custody for discard evidence.

use super::{DURABILITY, FOREIGN, Refusal};
use nix::{
    dir::Dir,
    fcntl::{OFlag, openat},
    sys::stat::Mode,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
};

const OPEN: OFlag = OFlag::O_NOFOLLOW
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NONBLOCK);

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Refused(Refusal),
    Io,
}

impl Error {
    pub(super) fn refusal(self) -> Refusal {
        match self {
            Self::Refused(reason) => reason,
            Self::Io => FOREIGN,
        }
    }

    pub(super) fn after_move(self) -> Refusal {
        match self {
            Self::Refused(reason) => reason,
            Self::Io => DURABILITY,
        }
    }

    pub(super) fn open(error: &io::Error, missing: Refusal) -> Self {
        match error.raw_os_error() {
            Some(libc::ENOENT) => Self::Refused(missing),
            Some(libc::ELOOP | libc::ENOTDIR) => Self::Refused(FOREIGN),
            _ => Self::Io,
        }
    }
}

impl From<Refusal> for Error {
    fn from(reason: Refusal) -> Self {
        Self::Refused(reason)
    }
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        error.refusal()
    }
}

pub(super) fn at(parent: &File, leaf: &OsStr, flags: OFlag) -> io::Result<File> {
    #[cfg(test)]
    if OPEN_ERROR
        .with_borrow_mut(|failed| failed.take_if(|name| name.as_os_str() == leaf).is_some())
    {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(File::from(openat(
        parent,
        leaf,
        OPEN | flags,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )?))
}

#[cfg(test)]
thread_local! {
    pub(super) static OPEN_ERROR: std::cell::RefCell<Option<OsString>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(super) fn names(directory: &File) -> Result<Vec<OsString>, Error> {
    // A fresh open description keeps enumeration offsets out of the held fd.
    let fd =
        openat(directory, ".", OPEN | OFlag::O_DIRECTORY, Mode::empty()).map_err(|_| Error::Io)?;
    let entries = Dir::from_fd(fd).map_err(|_| Error::Io)?;
    entries
        .into_iter()
        .filter_map(|entry| match entry {
            Ok(entry) if matches!(entry.file_name().to_bytes(), b"." | b"..") => None,
            Ok(entry) => Some(Ok(
                OsStr::from_bytes(entry.file_name().to_bytes()).to_owned()
            )),
            Err(_) => Some(Err(Error::Io)),
        })
        .collect()
}

pub(super) fn identity(file: &File) -> io::Result<(u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(target_os = "linux")]
pub(super) fn mount(file: &File) -> Result<u64, Error> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let probe = statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).map_err(|_| Error::Io)?;
    (probe.stx_mask & StatxFlags::MNT_ID.bits() != 0)
        .then_some(probe.stx_mnt_id)
        .ok_or(Error::Refused(FOREIGN))
}

#[cfg(target_os = "macos")]
pub(super) fn mount(file: &File) -> Result<u64, Error> {
    Ok(file.metadata().map_err(|_| Error::Io)?.dev())
}

pub(super) fn protected(file: &File, device: u64, directory: bool) -> Result<u64, Error> {
    let m = file.metadata().map_err(|_| Error::Io)?;
    if m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || (directory && !m.is_dir())
        || (!directory && !m.is_file())
        || mount(file)? != device
    {
        return Err(Error::Refused(FOREIGN));
    }
    acl(file, directory)?;
    Ok(m.nlink())
}

pub(super) fn directory(parent: &File, name: &OsStr, device: u64) -> Result<Option<File>, Error> {
    match at(parent, name, OFlag::O_DIRECTORY) {
        Ok(dir) => {
            protected(&dir, device, true)?;
            Ok(Some(dir))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::open(&e, FOREIGN)),
    }
}

pub(super) fn check_intent(file: &File, device: u64) -> Result<(), Error> {
    if protected(file, device, false)? != 1 || file.metadata().map_err(|_| Error::Io)?.len() != 0 {
        return Err(Error::Refused(FOREIGN));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn acl(file: &File, directory: bool) -> Result<(), Error> {
    for name in ["system.posix_acl_access", "system.posix_acl_default"]
        .into_iter()
        .take(if directory { 2 } else { 1 })
    {
        use rustix::{fs::fgetxattr_query, io::Errno};
        match fgetxattr_query(file, name) {
            Err(Errno::NODATA | Errno::NOTSUP) => {}
            Ok(_) => return Err(Error::Refused(FOREIGN)),
            Err(_) => return Err(Error::Io),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn acl(file: &File, directory: bool) -> Result<(), Error> {
    use crate::custody::{AclRefusal, inspect_discard_acl};
    use std::os::fd::AsFd as _;
    inspect_discard_acl(file.as_fd(), directory).map_err(|error| match error {
        AclRefusal::Foreign(_) => Error::Refused(FOREIGN),
        AclRefusal::Io(_) => Error::Io,
    })
}
