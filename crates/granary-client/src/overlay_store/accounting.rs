// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Staging lengths are inventoried at replay and maintained by successful I/O.
//! The exclusive Store owner must retain its flock throughout the component's life.

use super::{OverlayIo, io::UnmergedInventory, stage_id};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct Accounted<P> {
    inner: P,
    staging: PathBuf,
    lengths: BTreeMap<u64, u64>,
    unmerged: BTreeMap<String, u64>,
}
impl<P: OverlayIo> Accounted<P> {
    pub(super) fn new(
        inner: P,
        staging: PathBuf,
        unmerged: impl IntoIterator<Item = (String, u64)>,
    ) -> Self {
        Self {
            inner,
            staging,
            lengths: BTreeMap::new(),
            unmerged: unmerged.into_iter().collect(),
        }
    }
    pub(super) fn inventory(&mut self) -> io::Result<()> {
        let mut lengths = BTreeMap::new();
        let result = (|| {
            for name in self.inner.entries(&self.staging)? {
                let id = stage_id(&name).ok_or_else(|| io::Error::other("foreign staging name"))?;
                let length = self
                    .inner
                    .length(&self.staging.join(name))?
                    .ok_or_else(|| io::Error::other("staging entry vanished"))?;
                lengths.insert(id, length);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.lengths.clear();
            return Err(error);
        }
        self.lengths = lengths;
        Ok(())
    }
    pub(super) fn stages(&self) -> &BTreeMap<u64, u64> {
        &self.lengths
    }
    pub(super) fn unmerged(&self) -> &BTreeMap<String, u64> {
        &self.unmerged
    }
    fn id(&self, path: &Path) -> Option<u64> {
        (path.parent() == Some(self.staging.as_path()))
            .then(|| path.file_name()?.to_str().and_then(stage_id))
            .flatten()
    }
}
impl<P: OverlayIo> OverlayIo for Accounted<P> {
    fn establish(&mut self, root: &Path) -> io::Result<()> {
        self.inner.establish(root)
    }
    fn check_root(&mut self, root: &Path, euid: u32) -> io::Result<()> {
        self.inner.check_root(root, euid)
    }
    fn directory(&mut self, path: &Path) -> io::Result<()> {
        self.inner.directory(path)
    }
    fn entries(&mut self, path: &Path) -> io::Result<Vec<String>> {
        self.inner.entries(path)
    }
    fn length(&mut self, path: &Path) -> io::Result<Option<u64>> {
        self.inner.length(path)
    }
    fn modified(&mut self, path: &Path) -> io::Result<Option<(i64, i64)>> {
        self.inner.modified(path)
    }
    fn read_at(&mut self, path: &Path, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        self.inner.read_at(path, offset, length)
    }
    fn unmerged_inventory(&mut self, area: &Path, cap: u64) -> io::Result<UnmergedInventory> {
        self.inner.unmerged_inventory(area, cap)
    }
    fn create_directory(&mut self, path: &Path) -> io::Result<()> {
        self.inner.create_directory(path)
    }
    fn sync(&mut self, path: &Path) -> io::Result<()> {
        self.inner.sync(path)
    }
    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        self.inner.sync_directory(path)
    }
    fn create(&mut self, path: &Path) -> io::Result<()> {
        self.inner.create(path)?;
        if let Some(id) = self.id(path) {
            self.lengths.insert(id, 0);
        }
        Ok(())
    }
    fn write_at(&mut self, path: &Path, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("write length overflow"))?;
        self.inner.write_at(path, offset, bytes)?;
        if let Some(id) = self.id(path) {
            self.lengths
                .entry(id)
                .and_modify(|n| *n = (*n).max(end))
                .or_insert(end);
        }
        Ok(())
    }
    fn resize(&mut self, path: &Path, length: u64) -> io::Result<()> {
        self.inner.resize(path, length)?;
        if let Some(id) = self.id(path) {
            self.lengths.insert(id, length);
        }
        Ok(())
    }
    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.inner.remove(path)?;
        if let Some(id) = self.id(path) {
            self.lengths.remove(&id);
        }
        Ok(())
    }
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        // Only control-file replacements belong to this persistence interface.
        if self.id(from).is_some() || self.id(to).is_some() {
            return Err(io::Error::other("staging rename refused"));
        }
        self.inner.rename(from, to)
    }
}
