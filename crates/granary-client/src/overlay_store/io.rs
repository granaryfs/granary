// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Descriptor custody and the persistence seam shared by disk and crash models.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use crate::{custody, fsguard, publication_store};

#[derive(Debug)]
#[doc(hidden)]
pub struct UnmergedEntry {
    pub name: String,
    pub prefix: Vec<u8>,
    pub length: u64,
    pub links: u64,
    pub payload_check: Option<[u8; 32]>,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct UnmergedInventory {
    pub present: bool,
    pub entries: Vec<UnmergedEntry>,
}

/// All paths are beneath the checked store root. Reads must be bounded;
/// successful syncs persist the entire file or the directory's current names.
pub trait OverlayIo: std::fmt::Debug {
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn establish(&mut self, root: &Path) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn check_root(&mut self, root: &Path, euid: u32) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn directory(&mut self, path: &Path) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn entries(&mut self, path: &Path) -> io::Result<Vec<String>>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn length(&mut self, path: &Path) -> io::Result<Option<u64>>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn modified(&mut self, path: &Path) -> io::Result<Option<(i64, i64)>>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn read_at(&mut self, path: &Path, offset: u64, length: usize) -> io::Result<Vec<u8>>;
    /// Read and custody-check every permanent export entry through held,
    /// descriptor-relative names. Each entry carries its name, bounded
    /// framing/header bytes, physical length, link count, and an optional
    /// streamed residual-payload check. Directory presence remains distinct
    /// from an absent directory.
    /// # Errors
    /// Returns a custody, bound or cooperative-deadline error.
    fn unmerged_inventory(&mut self, area: &Path, cap: u64) -> io::Result<UnmergedInventory>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn create_directory(&mut self, path: &Path) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn create(&mut self, path: &Path) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn write_at(&mut self, path: &Path, offset: u64, bytes: &[u8]) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn resize(&mut self, path: &Path, length: u64) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn sync(&mut self, path: &Path) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn sync_directory(&mut self, path: &Path) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
    /// # Errors
    /// Returns a custody or persistence error; never repairs permissions.
    fn remove(&mut self, path: &Path) -> io::Result<()>;
}

/// The disk adapter never owns a Store or a flock.
#[derive(Debug, Clone)]
pub struct OverlayDisk {
    root: PathBuf,
    euid: u32,
}

impl OverlayDisk {
    #[must_use]
    pub fn new(root: &Path, euid: u32) -> Self {
        Self {
            root: root.to_owned(),
            euid,
        }
    }

    pub(super) fn protected(&self, file: &File, path: &Path, directory: bool) -> io::Result<()> {
        let meta = file.metadata()?;
        if meta.uid() != self.euid || meta.mode() & 0o777 != if directory { 0o700 } else { 0o600 } {
            return Err(io::Error::other("overlay custody owner/mode refused"));
        }
        if directory {
            if !meta.is_dir() {
                return Err(io::Error::other("overlay directory type refused"));
            }
            custody::refuse_granting_directory_acl_on_fd(file.as_fd(), path, "overlay directory")
                .map_err(io::Error::other)
        } else {
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(io::Error::other("overlay file type/link refused"));
            }
            custody::refuse_granting_acl_on_fd(file.as_fd(), path, "overlay control file")
                .map_err(io::Error::other)
        }
    }

    fn parents(&self, path: &Path) -> io::Result<()> {
        publication_store::check_control_root(&self.root, self.euid).map_err(io::Error::other)?;
        let relative = path.strip_prefix(&self.root).map_err(io::Error::other)?;
        let mut prefix = self.root.clone();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err(io::Error::other("overlay path component refused"));
            }
            prefix.push(component.as_os_str());
            if components.peek().is_some() {
                self.protected(&fsguard::open_directory(&prefix)?, &prefix, true)?;
            }
        }
        Ok(())
    }

    fn leaf(&self, path: &Path, update: bool) -> io::Result<File> {
        self.parents(path)?;
        let file = if update {
            fsguard::open_regular_update(path)?
        } else {
            fsguard::open_sole_regular_read(path, "overlay control file")?
        };
        self.protected(&file, path, false)?;
        Ok(file)
    }

    pub(super) fn custody_root(&self) -> (&Path, u32) {
        (&self.root, self.euid)
    }
}

impl OverlayIo for OverlayDisk {
    fn establish(&mut self, root: &Path) -> io::Result<()> {
        self.check_root(root, self.euid)?;
        fsguard::open_sole_regular_read(&root.join(crate::store::MARKER_NAME), "store marker")?
            .sync_all()?;
        fsguard::open_directory(root)?.sync_all()?;
        fsguard::open_directory(root.parent().unwrap_or(root))?.sync_all()
    }
    fn check_root(&mut self, root: &Path, euid: u32) -> io::Result<()> {
        if root != self.root || euid != self.euid {
            return Err(io::Error::other("overlay Store binding refused"));
        }
        publication_store::check_control_root(root, euid).map_err(io::Error::other)
    }
    fn directory(&mut self, path: &Path) -> io::Result<()> {
        self.parents(path)?;
        self.protected(&fsguard::open_directory(path)?, path, true)
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "enumerate a checked private overlay directory; every child is separately custody-checked before use and non-UTF8 names refuse"
    )]
    fn entries(&mut self, path: &Path) -> io::Result<Vec<String>> {
        self.directory(path)?;
        fs::read_dir(path)?
            .map(|entry| {
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| io::Error::other("overlay foreign name refused"))
            })
            .collect()
    }
    fn length(&mut self, path: &Path) -> io::Result<Option<u64>> {
        match self.leaf(path, false) {
            Ok(file) => Ok(Some(file.metadata()?.len())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn modified(&mut self, path: &Path) -> io::Result<Option<(i64, i64)>> {
        let meta = self.leaf(path, false)?.metadata()?;
        Ok(Some((meta.mtime(), meta.mtime_nsec())))
    }
    fn read_at(&mut self, path: &Path, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let mut file = self.leaf(path, false)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.take(length as u64).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    fn unmerged_inventory(&mut self, area: &Path, cap: u64) -> io::Result<UnmergedInventory> {
        super::unmerged::disk_inventory(self, area, cap)
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "create one private child of the custody-checked store/overlay directory, never recursive; verify an existing entry without permission repair"
    )]
    fn create_directory(&mut self, path: &Path) -> io::Result<()> {
        self.parents(path)?;
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        self.directory(path)
    }
    fn create(&mut self, path: &Path) -> io::Result<()> {
        self.parents(path)?;
        let file = fsguard::create_regular_exclusive(path)?;
        self.protected(&file, path, false)
    }
    fn write_at(&mut self, path: &Path, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut file = self.leaf(path, true)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }
    fn resize(&mut self, path: &Path, length: u64) -> io::Result<()> {
        self.leaf(path, true)?.set_len(length)
    }
    fn sync(&mut self, path: &Path) -> io::Result<()> {
        self.leaf(path, false)?.sync_all()
    }
    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        self.directory(path)?;
        fsguard::open_directory(path)?.sync_all()
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "same-parent overlay control-file replacement after custody checks on both leaves and their private parent; never promote an unchecked temporary"
    )]
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        if from.parent() != to.parent() {
            return Err(io::Error::other("overlay rename parent refused"));
        }
        self.leaf(from, false)?;
        self.length(to)?;
        fs::rename(from, to)
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "unlink only a checked singly-linked overlay leaf selected by global evidence validation or a durable landing; no recursion and no symlink following"
    )]
    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.leaf(path, false)?;
        fs::remove_file(path)
    }
}
