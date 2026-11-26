// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Closed callback identities and terminal result classification.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Callback {
    Lookup,
    Getattr,
    Readlink,
    Open,
    Read,
    Release,
    Opendir,
    Readdir,
    Readdirplus,
    Releasedir,
    Statfs,
    Access,
    Getxattr,
    Listxattr,
    Setattr,
    Mknod,
    Mkdir,
    Unlink,
    Rmdir,
    Symlink,
    Rename,
    Link,
    Write,
    Flush,
    Fsync,
    Fsyncdir,
    Setxattr,
    Removexattr,
    Create,
    Getlk,
    Setlk,
    Bmap,
    Ioctl,
    Poll,
    Fallocate,
    Lseek,
    CopyFileRange,
    Setvolname,
    Exchange,
    Getxtimes,
}

impl Callback {
    pub const ALL: &'static [Self] = &[
        Self::Lookup,
        Self::Getattr,
        Self::Readlink,
        Self::Open,
        Self::Read,
        Self::Release,
        Self::Opendir,
        Self::Readdir,
        Self::Readdirplus,
        Self::Releasedir,
        Self::Statfs,
        Self::Access,
        Self::Getxattr,
        Self::Listxattr,
        Self::Setattr,
        Self::Mknod,
        Self::Mkdir,
        Self::Unlink,
        Self::Rmdir,
        Self::Symlink,
        Self::Rename,
        Self::Link,
        Self::Write,
        Self::Flush,
        Self::Fsync,
        Self::Fsyncdir,
        Self::Setxattr,
        Self::Removexattr,
        Self::Create,
        Self::Getlk,
        Self::Setlk,
        Self::Bmap,
        Self::Ioctl,
        Self::Poll,
        Self::Fallocate,
        Self::Lseek,
        Self::CopyFileRange,
        Self::Setvolname,
        Self::Exchange,
        Self::Getxtimes,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Getattr => "getattr",
            Self::Readlink => "readlink",
            Self::Open => "open",
            Self::Read => "read",
            Self::Release => "release",
            Self::Opendir => "opendir",
            Self::Readdir => "readdir",
            Self::Readdirplus => "readdirplus",
            Self::Releasedir => "releasedir",
            Self::Statfs => "statfs",
            Self::Access => "access",
            Self::Getxattr => "getxattr",
            Self::Listxattr => "listxattr",
            Self::Setattr => "setattr",
            Self::Mknod => "mknod",
            Self::Mkdir => "mkdir",
            Self::Unlink => "unlink",
            Self::Rmdir => "rmdir",
            Self::Symlink => "symlink",
            Self::Rename => "rename",
            Self::Link => "link",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Fsync => "fsync",
            Self::Fsyncdir => "fsyncdir",
            Self::Setxattr => "setxattr",
            Self::Removexattr => "removexattr",
            Self::Create => "create",
            Self::Getlk => "getlk",
            Self::Setlk => "setlk",
            Self::Bmap => "bmap",
            Self::Ioctl => "ioctl",
            Self::Poll => "poll",
            Self::Fallocate => "fallocate",
            Self::Lseek => "lseek",
            Self::CopyFileRange => "copy_file_range",
            Self::Setvolname => "setvolname",
            Self::Exchange => "exchange",
            Self::Getxtimes => "getxtimes",
        }
    }
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|member| member.as_str() == text)
    }
    #[must_use]
    pub const fn reports_overlay_operation(self) -> bool {
        !matches!(
            self,
            Self::Lookup
                | Self::Getattr
                | Self::Readlink
                | Self::Read
                | Self::Opendir
                | Self::Readdir
                | Self::Readdirplus
                | Self::Statfs
                | Self::Access
                | Self::Fsync
                | Self::Fsyncdir
        )
    }
}

/// One completion, distinct from lower-layer failures and journal frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackOutcome {
    Ok,
    Cancelled,
    Refused,
    Failed(crate::MountError),
}

impl CallbackOutcome {
    #[must_use]
    pub fn from_errno(error: Option<fuser::Errno>) -> Self {
        use fuser::Errno;
        match error {
            None => Self::Ok,
            Some(Errno::EINTR) => Self::Cancelled,
            Some(
                Errno::ENOSYS
                | Errno::ENOTSUP
                | Errno::EROFS
                | Errno::EINVAL
                | Errno::EBADF
                | Errno::EFBIG
                | Errno::ENAMETOOLONG
                | Errno::EEXIST
                | Errno::ENOENT
                | Errno::ENOTDIR
                | Errno::EISDIR
                | Errno::ENOTEMPTY
                | Errno::EACCES
                | Errno::EPERM
                | Errno::ERANGE
                | Errno::NO_XATTR,
            ) => Self::Refused,
            Some(Errno::EAGAIN) => Self::Failed(crate::MountError::PlanningExhausted),
            Some(Errno::ESTALE) => Self::Failed(crate::MountError::Stale),
            Some(Errno::ENOSPC) => Self::Failed(crate::MountError::NoSpace),
            Some(Errno::EDQUOT) => Self::Failed(crate::MountError::Quota),
            Some(Errno::ETIMEDOUT) => Self::Failed(crate::MountError::Unreachable),
            Some(_) => Self::Failed(crate::MountError::Io),
        }
    }
}

impl crate::MountError {
    #[must_use]
    pub const fn errno(self) -> fuser::Errno {
        match self {
            Self::Stale => fuser::Errno::ESTALE,
            Self::PlanningExhausted => fuser::Errno::EAGAIN,
            Self::NoSpace => fuser::Errno::ENOSPC,
            Self::Access => fuser::Errno::EACCES,
            Self::Quota => fuser::Errno::EDQUOT,
            Self::Unreachable => fuser::Errno::ETIMEDOUT,
            Self::Io | Self::Corrupt | Self::Unavailable => fuser::Errno::EIO,
            Self::Closing => fuser::Errno::EROFS,
        }
    }
}

#[cfg(test)]
mod tests;
