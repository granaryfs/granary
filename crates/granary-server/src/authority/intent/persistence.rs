// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Snapshot IO through the publication log's held directory and file custody.

use super::super::file_log::{FileOps, Held, Kind};
use super::{Snapshot, codec};
use granary_core::authlog::Epoch;
use granary_core::decisionlog::{IoErrorKind, LogIoError};
use granary_core::root::VolumeName;
use granary_store::crypto::TrustedKeys;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex, PoisonError};

pub(crate) trait Persistence: Send + Sync {
    fn load(
        &self,
        volume: &VolumeName,
        epoch: Option<Epoch>,
        keys: &TrustedKeys,
    ) -> io::Result<Option<Snapshot>>;
    fn load_for_rebind(&self, volume: &VolumeName) -> io::Result<Option<Snapshot>>;
    fn ready(&self, volume: &VolumeName) -> Result<(), LogIoError>;
    fn commit(&self, snapshot: &Snapshot) -> Result<(), LogIoError>;
}

/// Durable intent state sharing the publication adapter's directory lock.
/// Operations are invoked only by the volume worker under its shared `LogGate`.
pub struct IntentStore {
    pub(crate) io: Arc<dyn Persistence>,
}
impl std::fmt::Debug for IntentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntentStore").finish_non_exhaustive()
    }
}
impl PartialEq for IntentStore {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.io, &other.io)
    }
}
impl Eq for IntentStore {}

pub(crate) struct FileIntent<O: FileOps<File = File>> {
    ops: Arc<O>,
    installed: Mutex<BTreeMap<VolumeName, Arc<File>>>,
}
impl<O: FileOps<File = File> + 'static> FileIntent<O> {
    pub(crate) fn store(ops: Arc<O>) -> Arc<IntentStore> {
        Arc::new(IntentStore {
            io: Arc::new(Self {
                ops,
                installed: Mutex::new(BTreeMap::new()),
            }),
        })
    }
}
fn names(volume: &VolumeName) -> (String, String) {
    (
        format!("{}.intent", volume.as_str()),
        format!("{}.intent.tmp", volume.as_str()),
    )
}
fn io_error(_: io::Error) -> LogIoError {
    LogIoError::Io(IoErrorKind::Other)
}
struct Positioned<'a, O: FileOps> {
    ops: &'a O,
    file: &'a O::File,
    offset: u64,
}
impl<O: FileOps> Write for Positioned<'_, O> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.ops.pwrite(self.file, self.offset, bytes)?;
        crash_point!(IntentPartialWrite);
        if n > bytes.len() {
            return Err(io::Error::other("invalid write count"));
        }
        self.offset = self
            .offset
            .checked_add(u64::try_from(n).map_err(|_| io::Error::other("write count over"))?)
            .ok_or_else(|| io::Error::other("write offset over"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct PositionedRead<'a> {
    file: &'a File,
    offset: u64,
}
impl Read for PositionedRead<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(u64::try_from(n).map_err(|_| io::Error::other("read count over"))?)
            .ok_or_else(|| io::Error::other("read offset over"))?;
        Ok(n)
    }
}
impl<O: FileOps<File = File>> Persistence for FileIntent<O> {
    fn load(
        &self,
        volume: &VolumeName,
        epoch: Option<Epoch>,
        keys: &TrustedKeys,
    ) -> io::Result<Option<Snapshot>> {
        self.ops.check_state()?;
        let (name, _) = names(volume);
        match self.ops.stat_at(&name)? {
            None => return Ok(None),
            Some(Kind::File) => {}
            Some(_) => return Err(io::Error::other("unsafe intent store")),
        }
        let file = Arc::new(self.ops.open_rw(&name)?);
        // Validation holds the installed description but never rewrites it.
        // The worker applies ready only after proving the existing log binding.
        let snapshot = codec::decode(
            PositionedRead {
                file: &file,
                offset: 0,
            },
            volume,
            epoch,
            keys,
        )?;
        self.installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(volume.clone(), file);
        Ok(Some(snapshot))
    }
    fn load_for_rebind(&self, volume: &VolumeName) -> io::Result<Option<Snapshot>> {
        self.ops.check_state()?;
        let (name, _) = names(volume);
        match self.ops.stat_at(&name)? {
            None => return Ok(None),
            Some(Kind::File) => {}
            Some(_) => return Err(io::Error::other("unsafe intent store")),
        }
        let file = self.ops.open_rw(&name)?;
        codec::decode_for_rebind(
            PositionedRead {
                file: &file,
                offset: 0,
            },
            volume,
        )
        .map(Some)
    }
    fn ready(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.ops.check_state().map_err(io_error)?;
        let held = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(volume)
            .cloned()
            .ok_or(LogIoError::NotFound)?;
        self.ops
            .sync_file(&held)
            .map_err(|_| LogIoError::SyncFailed)?;
        let (_, temporary) = names(volume);
        match self.ops.stat_at(&temporary).map_err(io_error)? {
            Some(Kind::File) => {
                // Open and judge custody before unlink; no temporary is promoted.
                let _held = self.ops.open_rw(&temporary).map_err(io_error)?;
                self.ops.unlink(&temporary).map_err(io_error)?;
            }
            Some(_) => return Err(LogIoError::Io(IoErrorKind::Other)),
            None => {}
        }
        self.ops
            .sync_dir(Held::State)
            .map_err(|_| LogIoError::SyncFailed)
    }
    fn commit(&self, snapshot: &Snapshot) -> Result<(), LogIoError> {
        self.ops.check_state().map_err(io_error)?;
        let (name, temporary) = names(&snapshot.volume);
        match self.ops.stat_at(&temporary).map_err(io_error)? {
            Some(Kind::File) => {
                let _held = self.ops.open_rw(&temporary).map_err(io_error)?;
                self.ops.unlink(&temporary).map_err(io_error)?;
                self.ops
                    .sync_dir(Held::State)
                    .map_err(|_| LogIoError::SyncFailed)?;
            }
            Some(_) => return Err(LogIoError::Io(IoErrorKind::Other)),
            None => {}
        }
        crash_point!(IntentBeforeTemporary);
        let file = Arc::new(self.ops.create_new(&temporary).map_err(io_error)?);
        crash_point!(IntentTemporaryCreated);
        // Bounded write aggregation, with an explicit flush before the file barrier.
        let mut writer = BufWriter::with_capacity(
            65_536,
            Positioned {
                ops: &*self.ops,
                file: &file,
                offset: 0,
            },
        );
        let written = codec::encode_frames(snapshot, &mut writer).and_then(|()| writer.flush());
        // Never flush on Drop after a failed write: the gate must fence first.
        let (_positioned, _pending) = writer.into_parts();
        written.map_err(io_error)?;
        crash_point!(IntentTemporaryWritten);
        self.ops
            .sync_file(&file)
            .map_err(|_| LogIoError::SyncFailed)?;
        crash_point!(IntentFileSynced);
        self.ops.rename(&temporary, &name).map_err(io_error)?;
        crash_point!(IntentRenamed);
        self.ops
            .sync_dir(Held::State)
            .map_err(|_| LogIoError::SyncFailed)?;
        crash_point!(IntentDirectorySynced);
        // Keep the old description through the directory barrier.
        self.installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(snapshot.volume.clone(), file);
        Ok(())
    }
}
