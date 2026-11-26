// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Strict temporary-file lifecycle and no-replace archive publication.

use super::{
    PrivateArchiveError, PrivateArchiveRefusal as Refusal, identity, refused,
    walk::PrivateArchiveParent,
};
use crate::fsguard::{create_regular_exclusive, open_sole_regular_read};
use nix::sys::stat::{Mode, fchmod};
use std::{
    fs::{File, Metadata},
    io::{self, Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const TEMP_ATTEMPTS: usize = 128;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn stable_metadata(metadata: &Metadata) -> (u64, u64, u64, u64, u32, u32, u32, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.nlink(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

trait ArchiveOps {
    fn created(&self, _file: &File, _path: &Path) -> io::Result<()> {
        Ok(())
    }

    fn before_link(&self, _temporary: &Path, _output: &Path) -> io::Result<()> {
        Ok(())
    }

    fn sync(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn link(&self, temporary: &Path, output: &Path) -> io::Result<()>;
    fn remove(&self, temporary: &Path) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy)]
struct RealArchiveOps;

impl ArchiveOps for RealArchiveOps {
    #[expect(
        clippy::disallowed_methods,
        reason = "hard_link is the atomic no-replace publication operation after exact-byte and parent-rebinding checks"
    )]
    fn link(&self, temporary: &Path, output: &Path) -> io::Result<()> {
        std::fs::hard_link(temporary, output)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "remove only the invocation-owned temporary after its name is rebound to the created inode"
    )]
    fn remove(&self, temporary: &Path) -> io::Result<()> {
        std::fs::remove_file(temporary)
    }
}

struct Temporary<'a, O: ArchiveOps> {
    path: PathBuf,
    identity: (u64, u64),
    ops: &'a O,
    armed: bool,
}

impl<O: ArchiveOps> Temporary<'_, O> {
    fn remove(&mut self) -> io::Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        if !named.is_file() || identity(&named) != self.identity {
            return Err(io::Error::other("archive temporary changed"));
        }
        self.ops.remove(&self.path)?;
        self.armed = false;
        Ok(())
    }
}

impl<O: ArchiveOps> Drop for Temporary<'_, O> {
    fn drop(&mut self) {
        if self.armed {
            let _cleanup = self.remove();
        }
    }
}

fn create_temporary<'a, O: ArchiveOps>(
    parent: &Path,
    invoking_uid: u32,
    first: u64,
    ops: &'a O,
) -> Result<(Temporary<'a, O>, File), PrivateArchiveError> {
    for attempt in 0..TEMP_ATTEMPTS {
        let sequence = first.wrapping_add(attempt as u64);
        let path = parent.join(format!(".SUPPORT-BUNDLE-{sequence}.tmp"));
        let file = match create_regular_exclusive(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(refused(Refusal::UnsafeArchiveTemporary)),
        };
        let metadata = file
            .metadata()
            .map_err(|_| refused(Refusal::UnsafeArchiveTemporary))?;
        ops.created(&file, &path)
            .map_err(|_| refused(Refusal::UnsafeArchiveTemporary))?;
        let mut temporary = Temporary {
            path,
            identity: identity(&metadata),
            ops,
            armed: true,
        };
        if !metadata.is_file()
            || metadata.uid() != invoking_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(refused(Refusal::UnsafeArchiveTemporary));
        }
        fchmod(&file, Mode::from_bits_truncate(0o600))
            .map_err(|_| refused(Refusal::ArchiveTemporaryMode))?;
        let exact = file
            .metadata()
            .map_err(|_| refused(Refusal::ArchiveTemporaryMode))?;
        if exact.mode() & 0o7777 != 0o600 {
            return Err(refused(Refusal::ArchiveTemporaryMode));
        }
        temporary.identity = identity(&exact);
        return Ok((temporary, file));
    }
    Err(refused(Refusal::TemporaryNameExhaustion))
}

fn verify_temporary(
    path: &Path,
    expected: &[u8],
    invoking_uid: u32,
    created_identity: (u64, u64),
) -> Result<File, PrivateArchiveError> {
    let mut file = open_sole_regular_read(path, "an archive temporary")
        .map_err(|_| refused(Refusal::ArchiveTemporaryIsNotSolePrivateRegular))?;
    let before = file
        .metadata()
        .map_err(|_| refused(Refusal::ArchiveTemporaryChanged))?;
    if before.uid() != invoking_uid || before.nlink() != 1 || before.mode() & 0o7777 != 0o600 {
        return Err(refused(Refusal::ArchiveTemporaryIsNotSolePrivateRegular));
    }
    if identity(&before) != created_identity {
        return Err(refused(Refusal::ArchiveTemporaryChanged));
    }
    if usize::try_from(before.len()).ok() != Some(expected.len()) {
        return Err(refused(Refusal::ArchiveTemporaryContentMismatch));
    }
    let mut buffer = [0_u8; 8_192];
    for chunk in expected.chunks(buffer.len()) {
        let slot = buffer
            .get_mut(..chunk.len())
            .ok_or_else(|| refused(Refusal::ArchiveTemporaryContentMismatch))?;
        file.read_exact(slot)
            .map_err(|_| refused(Refusal::ArchiveTemporaryContentMismatch))?;
        if slot != chunk {
            return Err(refused(Refusal::ArchiveTemporaryContentMismatch));
        }
    }
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| refused(Refusal::ArchiveTemporaryChanged))?
        != 0
    {
        return Err(refused(Refusal::ArchiveTemporaryContentMismatch));
    }
    let after = file
        .metadata()
        .map_err(|_| refused(Refusal::ArchiveTemporaryChanged))?;
    if stable_metadata(&before) != stable_metadata(&after) {
        return Err(refused(Refusal::ArchiveTemporaryChanged));
    }
    Ok(file)
}

fn verify_named_temporary(
    path: &Path,
    file: &File,
    created_identity: (u64, u64),
) -> Result<(), PrivateArchiveError> {
    let descriptor = file
        .metadata()
        .map_err(|_| refused(Refusal::ArchiveTemporaryChanged))?;
    let named =
        std::fs::symlink_metadata(path).map_err(|_| refused(Refusal::ArchiveTemporaryChanged))?;
    if identity(&descriptor) != created_identity
        || stable_metadata(&descriptor) != stable_metadata(&named)
    {
        return Err(refused(Refusal::ArchiveTemporaryChanged));
    }
    Ok(())
}

/// Publish bounded bytes through a parent previously proved by the protected walk.
///
/// # Errors
///
/// Returns a fixed refusal before the final hard link, and
/// [`PrivateArchiveError::PublicationUncertain`] only after that link lands.
#[expect(
    clippy::needless_pass_by_value,
    reason = "consuming the verified parent makes one protected walk authorize exactly one publication attempt"
)]
pub fn publish_private_archive(
    parent: PrivateArchiveParent,
    bytes: &[u8],
) -> Result<(), PrivateArchiveError> {
    publish_with_ops(&parent, bytes, &RealArchiveOps)
}

fn publish_with_ops<O: ArchiveOps>(
    parent: &PrivateArchiveParent,
    bytes: &[u8],
    ops: &O,
) -> Result<(), PrivateArchiveError> {
    if bytes.len() > granary_core::support::BUNDLE_ARCHIVE_MAX {
        return Err(refused(Refusal::SupportSizeBound));
    }
    if !parent.rebound() {
        return Err(refused(Refusal::OutputPathUnavailable));
    }
    match std::fs::symlink_metadata(parent.output()) {
        Ok(_) => return Err(refused(Refusal::OutputAlreadyExists)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(refused(Refusal::OutputPathUnavailable)),
    }

    let first = TEMP_SEQUENCE.fetch_add(TEMP_ATTEMPTS as u64, Ordering::Relaxed);
    let (mut temporary, mut created) =
        create_temporary(&parent.path, parent.invoking_uid(), first, ops)?;
    created
        .write_all(bytes)
        .map_err(|_| refused(Refusal::ArchiveWriteUnavailable))?;
    let verified = verify_temporary(
        &temporary.path,
        bytes,
        parent.invoking_uid(),
        temporary.identity,
    )?;
    ops.sync(&verified)
        .map_err(|_| refused(Refusal::ArchiveWriteUnavailable))?;
    if !parent.rebound() {
        return Err(refused(Refusal::OutputPathUnavailable));
    }
    let directory = parent.descriptor()?;
    ops.before_link(&temporary.path, parent.output())
        .map_err(|_| refused(Refusal::ArchivePublicationUnavailable))?;
    verify_named_temporary(&temporary.path, &verified, temporary.identity)?;
    match ops.link(&temporary.path, parent.output()) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(refused(Refusal::OutputAlreadyExists));
        }
        Err(_) => return Err(refused(Refusal::ArchivePublicationUnavailable)),
    }
    ops.sync(directory)
        .map_err(|_| PrivateArchiveError::PublicationUncertain)?;
    temporary
        .remove()
        .map_err(|_| PrivateArchiveError::PublicationUncertain)?;
    ops.sync(directory)
        .map_err(|_| PrivateArchiveError::PublicationUncertain)?;
    Ok(())
}

#[cfg(test)]
mod tests;
