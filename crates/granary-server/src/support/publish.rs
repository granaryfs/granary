// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Byte-oriented private publication, with wire-snapshot's content anchor.
//! The final hard link uses pathnames: the last check-to-link interval is
//! inside the trusted-owner boundary, not descriptor-relative publication.
use super::export::{SupportExportError, SupportExportRequest};
use crate::protected_dir::{DirOps, ProtectedDir, judge_file};
use granary_core::{
    hash::GrainId,
    support::{ARCHIVE_MAX, SupportArchive},
};
use nix::sys::stat::Mode;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TEMP_PREFIX: &str = ".support-export-";

fn temporary_namespace(name: &str) -> bool {
    name.chars()
        .flat_map(char::to_uppercase)
        .take(TEMP_PREFIX.len())
        .eq(TEMP_PREFIX.chars().map(|c| c.to_ascii_uppercase()))
}

pub(super) trait Links {
    fn link(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::hard_link(from, to)
    }
    fn before_link(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Ok(())
    }
    fn remove(&self, path: &Path) -> io::Result<()>;
    fn named_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(path)
    }
}
pub(super) struct PathLinks;
impl Links for PathLinks {
    fn remove(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
}
struct Temporary<'a, L: Links> {
    path: PathBuf,
    links: &'a L,
    armed: bool,
}
impl<L: Links> Drop for Temporary<'_, L> {
    fn drop(&mut self) {
        if self.armed {
            let _cleanup = self.links.remove(&self.path);
        }
    }
}
pub(super) fn publish(
    ops: &impl DirOps,
    links: &impl Links,
    request: SupportExportRequest<'_>,
    out: &Path,
    support: &ProtectedDir,
    state: &ProtectedDir,
    bytes: &[u8],
) -> Result<(), SupportExportError> {
    if bytes.len() > ARCHIVE_MAX {
        return Err(SupportExportError::Refused("support size bound"));
    }
    SupportArchive::decode(bytes)?;
    let parent_path = out
        .parent()
        .ok_or(SupportExportError::Refused("output parent"))?;
    let name = out
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .ok_or(SupportExportError::Refused("output name"))?;
    if temporary_namespace(name) {
        return Err(SupportExportError::Refused(
            "output name is in temporary namespace",
        ));
    }
    let parent = ProtectedDir::for_verb(ops, parent_path, request.accept_unsupported_filesystem)
        .map_err(|e| SupportExportError::Io(io::Error::other(e)))?;
    if parent.owner() != ops.euid() || parent.stat.perms() != 0o700 {
        return Err(SupportExportError::Refused(
            "output parent must be invoking uid and 0700",
        ));
    }
    for directory in parent.walked_directories() {
        let stat = ops.fstat(directory)?;
        if stat.same_directory(&support.stat) || stat.same_directory(&state.stat) {
            return Err(SupportExportError::Refused("output inside source tree"));
        }
    }
    match ops.stat_at(&parent.dir, name) {
        Ok(_) => return Err(SupportExportError::Refused("output already exists")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let digest = GrainId::of(bytes).to_string();
    let mut created = None;
    for _ in 0..128 {
        let temp_name = format!(
            "{TEMP_PREFIX}{}-{digest}.tmp",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        match ops.create_excl_at(&parent.dir, &temp_name) {
            Ok(file) => {
                created = Some((temp_name, file));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let (temp_name, file) =
        created.ok_or(SupportExportError::Refused("temporary name exhaustion"))?;
    let mut temp = Temporary {
        path: parent_path.join(&temp_name),
        links,
        armed: true,
    };
    let stat = ops.fstat(&file)?;
    judge_file(&stat, parent.owner())
        .map_err(|_| SupportExportError::Refused("unsafe archive temporary"))?;
    if file.metadata()?.nlink() != 1 {
        return Err(SupportExportError::Refused(
            "archive temporary is not sole regular",
        ));
    }
    ops.fchmod(&file, Mode::S_IRUSR | Mode::S_IWUSR)?;
    if ops.fstat(&file)?.perms() != 0o600 {
        return Err(SupportExportError::Refused("archive temporary mode"));
    }
    let mut written = 0;
    while written < bytes.len() {
        let chunk = bytes
            .get(written..)
            .ok_or(SupportExportError::Refused("archive write bound"))?;
        let n = ops.write_at(
            &file,
            chunk,
            u64::try_from(written)
                .map_err(|_| SupportExportError::Refused("archive write bound"))?,
        )?;
        if n == 0 || n > chunk.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "archive write").into());
        }
        written += n;
    }
    ops.sync_file(&file)?;
    verify_and_link(links, &temp.path, out, bytes, parent.owner())?;
    ops.sync_dir(&parent.dir)
        .map_err(SupportExportError::PublicationUncertain)?;
    links
        .remove(&temp.path)
        .map_err(SupportExportError::PublicationUncertain)?;
    temp.armed = false;
    ops.sync_dir(&parent.dir)
        .map_err(SupportExportError::PublicationUncertain)?;
    drop(temp);
    Ok(())
}
/// Reopen, compare the exact bounded content, then recheck the name. A
/// creation-time inode alone cannot anchor bytes on inode-recycling filesystems.
fn verify_and_link(
    links: &impl Links,
    temp: &Path,
    dest: &Path,
    expected: &[u8],
    owner: u32,
) -> Result<(), SupportExportError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(temp)?;
    verify(&file, expected, owner)?;
    let opened = file.metadata()?;
    let named = links.named_metadata(temp)?;
    if !named.file_type().is_file()
        || (
            opened.dev(),
            opened.ino(),
            opened.nlink(),
            opened.len(),
            opened.uid(),
            opened.gid(),
            opened.mode(),
            opened.mtime(),
            opened.mtime_nsec(),
            opened.ctime(),
            opened.ctime_nsec(),
        ) != (
            named.dev(),
            named.ino(),
            named.nlink(),
            named.len(),
            named.uid(),
            named.gid(),
            named.mode(),
            named.mtime(),
            named.mtime_nsec(),
            named.ctime(),
            named.ctime_nsec(),
        )
    {
        return Err(SupportExportError::Refused("archive temporary changed"));
    }
    links.before_link(temp, dest)?;
    links.link(temp, dest)?;
    Ok(())
}
fn verify(file: &File, expected: &[u8], owner: u32) -> Result<(), SupportExportError> {
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != owner
        || before.mode() & 0o7777 != 0o600
    {
        return Err(SupportExportError::Refused(
            "archive temporary is not sole private regular",
        ));
    }
    if usize::try_from(before.len()).ok() != Some(expected.len()) || expected.len() > ARCHIVE_MAX {
        return Err(SupportExportError::Refused(
            "archive temporary content mismatch",
        ));
    }
    let bound = u64::try_from(expected.len())
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or(SupportExportError::Refused("archive read bound"))?;
    let mut actual = Vec::with_capacity(expected.len());
    file.take(bound).read_to_end(&mut actual)?;
    if actual != expected {
        return Err(SupportExportError::Refused(
            "archive temporary content mismatch",
        ));
    }
    let after = file.metadata()?;
    if (
        before.len(),
        before.mode(),
        before.uid(),
        before.gid(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.len(),
        after.mode(),
        after.uid(),
        after.gid(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(SupportExportError::Refused("archive temporary changed"));
    }
    Ok(())
}
