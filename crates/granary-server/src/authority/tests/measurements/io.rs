// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Delegating timers and a named, real filesystem backend for local rows.

use super::super::super::file_log::{DirState, FileOps, Held, Kind, StdFileOps};
use super::*;
use granary_core::binstore::BinStore;
use granary_core::rootstore::filter_above;
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    Get,
    List,
    Put,
    Gateway,
    SyncFile,
    SyncDir,
    IntentCommit,
    IntentWrite,
    IntentSyncFile,
    IntentSyncDir,
    DecisionAppend,
    DecisionSyncFile,
    DecisionSyncDir,
}
#[derive(Debug, Clone)]
pub(super) struct IoSample {
    pub call: Call,
    pub elapsed: Duration,
    pub start: Instant,
    pub end: Instant,
    pub bytes: usize,
    pub success: bool,
}
impl IoSample {
    pub(super) fn publication_interval(
        &self,
        start: Instant,
        end: Instant,
    ) -> Result<(), &'static str> {
        if self.start >= start && self.end <= end {
            Ok(())
        } else {
            Err("I/O outside completed publication interval")
        }
    }
}
#[derive(Debug, Clone)]
pub(super) struct Timings {
    buffer: Arc<Mutex<Vec<IoSample>>>,
    gateway: Arc<Mutex<Vec<IoSample>>>,
    lost: Arc<std::sync::atomic::AtomicUsize>,
    pub enabled: bool,
    counts: Arc<[std::sync::atomic::AtomicUsize; 13]>,
    bytes: Arc<[std::sync::atomic::AtomicUsize; 13]>,
    files: Arc<Mutex<BTreeMap<i32, FileState>>>,
    names: Arc<Mutex<BTreeMap<String, i32>>>,
    intents: Arc<Mutex<IntentTracker>>,
    pub store_delay: Duration,
    pub file_delay: Duration,
}
impl Timings {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::with_capacity(capacity.div_ceil(2)))),
            gateway: Arc::new(Mutex::new(Vec::with_capacity(capacity / 2))),
            lost: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            enabled: true,
            counts: Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicUsize::new(0)
            })),
            bytes: Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicUsize::new(0)
            })),
            files: Arc::new(Mutex::new(BTreeMap::new())),
            names: Arc::new(Mutex::new(BTreeMap::new())),
            intents: Arc::new(Mutex::new(IntentTracker::default())),
            store_delay: Duration::ZERO,
            file_delay: Duration::ZERO,
        }
    }
    pub(super) fn delayed(capacity: usize, store_delay: Duration, file_delay: Duration) -> Self {
        Self {
            store_delay,
            file_delay,
            ..Self::new(capacity)
        }
    }
    fn record(&self, call: Call, at: Option<Instant>, bytes: usize, success: bool) {
        if let Some(count) = self.counts.get(call as usize) {
            count.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(total) = self.bytes.get(call as usize) {
            total.fetch_add(bytes, Ordering::Relaxed);
        }
        if !self.enabled {
            return;
        }
        let Some(at) = at else {
            return;
        };
        let end = stopwatch();
        let elapsed = end.duration_since(at);
        // Driver I/O and the mixed GET task have separate bounded buffers.
        // A reader drains them only after the producers have joined.
        let lane = if call == Call::Gateway {
            &self.gateway
        } else {
            &self.buffer
        };
        let mut buffer = lane
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buffer.len() < buffer.capacity() {
            buffer.push(IoSample {
                call,
                elapsed,
                start: at,
                end,
                bytes,
                success,
            });
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(super) fn counts(&self) -> [usize; 13] {
        std::array::from_fn(|i| {
            self.counts
                .get(i)
                .map_or(0, |n| n.swap(0, Ordering::Relaxed))
        })
    }

    pub(super) fn bytes(&self) -> [usize; 13] {
        std::array::from_fn(|i| {
            self.bytes
                .get(i)
                .map_or(0, |n| n.swap(0, Ordering::Relaxed))
        })
    }

    fn remember<F: FileKey>(&self, name: &str, file: &F) {
        let key = file.key();
        self.files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, FileState::new(name));
        self.names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), key);
    }

    fn class<F: FileKey>(&self, file: &F) -> Option<FileClass> {
        self.files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&file.key())
            .map(|state| state.class)
    }

    fn intent_file<F: FileKey>(&self, file: &F) -> Option<String> {
        self.files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&file.key())
            .and_then(|state| state.intent_volume.clone())
    }

    fn decision_write<F: FileKey>(&self, file: &F) {
        if let Some(state) = self
            .files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&file.key())
        {
            state.append = match state.append {
                AppendStage::Idle | AppendStage::RecordWriting => AppendStage::RecordWriting,
                AppendStage::RecordSynced | AppendStage::MarkWriting => AppendStage::MarkWriting,
            };
        }
    }

    fn decision_sync<F: FileKey>(&self, file: &F, success: bool) {
        let barrier = self
            .files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&file.key())
            .is_some_and(|state| match (success, state.append) {
                (false, _) => {
                    state.append = AppendStage::Idle;
                    false
                }
                (true, AppendStage::RecordWriting) => {
                    state.append = AppendStage::RecordSynced;
                    true
                }
                (true, AppendStage::MarkWriting) => {
                    state.append = AppendStage::Idle;
                    true
                }
                (true, AppendStage::Idle | AppendStage::RecordSynced) => false,
            });
        if barrier {
            self.record(Call::DecisionSyncFile, None, 0, true);
        }
    }

    fn intent_pending(&self, volume: String, stage: IntentStage) {
        self.intents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .insert(
                volume,
                PendingIntent {
                    thread: std::thread::current().id(),
                    stage,
                },
            );
    }

    fn clear_intent_pending(&self, volume: &str) {
        self.intents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(volume);
    }

    fn take_intent_pending(&self) -> Option<IntentStage> {
        let thread = std::thread::current().id();
        let mut intents = self
            .intents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let volume = intents
            .pending
            .iter()
            .find_map(|(volume, pending)| (pending.thread == thread).then(|| volume.clone()))?;
        intents.pending.remove(&volume).map(|pending| pending.stage)
    }

    fn linked(&self, from: &str, to: &str) {
        let Some(key) = self
            .names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(from)
            .copied()
        else {
            return;
        };
        self.names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(to.to_owned(), key);
        if let Some(state) = self
            .files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&key)
        {
            state.class = FileClass::of(to);
        }
    }

    fn renamed(&self, from: &str, to: &str) {
        let key = self
            .names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(from);
        let Some(key) = key else {
            return;
        };
        self.names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(to.to_owned(), key);
        let class = FileClass::of(to);
        if let Some(state) = self
            .files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&key)
        {
            state.class = class;
            state.intent_volume = intent_volume(to).map(str::to_owned);
        }
        if class == FileClass::IntentInstalled
            && let Some(volume) = intent_volume(to)
        {
            self.intent_pending(volume.to_owned(), IntentStage::Commit);
        }
    }
    pub(super) fn take(&self) -> (Vec<IoSample>, usize) {
        let mut buffer = self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut samples: Vec<_> = buffer.drain(..).collect();
        drop(buffer);
        let mut gateway = self
            .gateway
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        samples.extend(gateway.drain(..));
        let lost = self.lost.swap(0, Ordering::Relaxed);
        (samples, lost)
    }
}

#[derive(Debug)]
pub(super) struct TimedLog<L> {
    pub inner: L,
    pub timings: Timings,
}

impl<L: DecisionLog> DecisionLog for TimedLog<L> {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        self.inner.read_marker().await
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        self.inner.write_marker(marker).await
    }

    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        self.inner.read(volume).await
    }

    async fn remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        self.inner.remove_temporary(volume).await
    }

    async fn initialise(&self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        self.inner.initialise(envelope).await
    }

    async fn complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.inner.complete_namespace(volume).await
    }

    async fn append(&self, append: &Append) -> Result<(), LogIoError> {
        let result = self.inner.append(append).await;
        if result.is_ok() {
            self.timings.record(Call::DecisionAppend, None, 0, true);
        }
        result
    }

    async fn truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        self.inner.truncate(volume, len).await
    }

    async fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.inner.resync(volume).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileClass {
    IntentTemporary,
    IntentInstalled,
    DecisionTemporary,
    Decision,
    Other,
}

impl FileClass {
    #[expect(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "the authority's exact lowercase protected filenames define the observer classes"
    )]
    fn of(name: &str) -> Self {
        if name.ends_with(".intent.tmp") {
            Self::IntentTemporary
        } else if name.ends_with(".intent") {
            Self::IntentInstalled
        } else if name.ends_with(".log.tmp") {
            Self::DecisionTemporary
        } else if name.ends_with(".log") {
            Self::Decision
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AppendStage {
    Idle,
    RecordWriting,
    RecordSynced,
    MarkWriting,
}

#[derive(Debug, Clone, Copy)]
enum IntentStage {
    Cleanup,
    Ready,
    Commit,
}

#[derive(Debug, Default)]
struct IntentTracker {
    // FileIntent calls from the file operation through its directory barrier
    // are synchronous. Volume identity prevents a stale operation from aliasing
    // its successor; the thread only associates otherwise anonymous sync_dir.
    pending: BTreeMap<String, PendingIntent>,
}

#[derive(Debug)]
struct PendingIntent {
    thread: std::thread::ThreadId,
    stage: IntentStage,
}

fn intent_volume(name: &str) -> Option<&str> {
    name.strip_suffix(".intent.tmp")
        .or_else(|| name.strip_suffix(".intent"))
}

#[derive(Debug, Clone)]
struct FileState {
    class: FileClass,
    append: AppendStage,
    intent_volume: Option<String>,
}

impl FileState {
    fn new(name: &str) -> Self {
        Self {
            class: FileClass::of(name),
            append: AppendStage::Idle,
            intent_volume: intent_volume(name).map(str::to_owned),
        }
    }
}
#[derive(Debug)]
pub(super) struct TimedFileOps<O = StdFileOps> {
    pub inner: O,
    pub timings: Timings,
    pub stalls: Arc<Stall>,
}
#[derive(Debug, Default)]
pub(super) struct Stall {
    pub armed: std::sync::atomic::AtomicBool,
    pub entered: std::sync::atomic::AtomicBool,
    pub released: std::sync::atomic::AtomicBool,
}
trait FileKey {
    fn key(&self) -> i32;
}

impl FileKey for std::fs::File {
    fn key(&self) -> i32 {
        self.as_raw_fd()
    }
}

impl<O: FileOps> FileOps for TimedFileOps<O>
where
    O::File: FileKey,
{
    type File = O::File;
    fn check_state(&self) -> io::Result<()> {
        self.inner.check_state()
    }
    fn stat_at(&self, name: &str) -> io::Result<Option<Kind>> {
        let result = self.inner.stat_at(name);
        let failed = match &result {
            Err(_) => true,
            Ok(Some(kind)) => *kind != Kind::File,
            Ok(None) => false,
        };
        if failed && let Some(volume) = intent_volume(name) {
            self.timings.clear_intent_pending(volume);
        }
        result
    }
    fn dir_state(&self) -> io::Result<DirState> {
        self.inner.dir_state()
    }
    fn create_new(&self, name: &str) -> io::Result<Self::File> {
        let file = self.inner.create_new(name)?;
        self.timings.remember(name, &file);
        Ok(file)
    }
    fn open_rw(&self, name: &str) -> io::Result<Self::File> {
        let file = self.inner.open_rw(name).inspect_err(|_| {
            if let Some(volume) = intent_volume(name) {
                self.timings.clear_intent_pending(volume);
            }
        })?;
        self.timings.remember(name, &file);
        Ok(file)
    }
    fn read_marker(&self, name: &str) -> io::Result<Vec<u8>> {
        self.inner.read_marker(name)
    }
    fn read_all(&self, file: &Self::File) -> io::Result<Vec<u8>> {
        self.inner.read_all(file)
    }
    fn pwrite(&self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.pwrite(file, offset, bytes)?;
        match self.timings.class(file) {
            Some(FileClass::IntentTemporary) => {
                self.timings.record(Call::IntentWrite, None, written, true);
            }
            Some(FileClass::Decision) => self.timings.decision_write(file),
            _ => {}
        }
        Ok(written)
    }
    fn sync_file(&self, file: &Self::File) -> io::Result<()> {
        let at = self.timings.enabled.then(stopwatch);
        delayed(self.timings.file_delay);
        if self.stalls.armed.swap(false, Ordering::SeqCst) {
            self.stalls.entered.store(true, Ordering::SeqCst);
            injected_stall();
            self.stalls.released.store(true, Ordering::SeqCst);
        }
        let result = self.inner.sync_file(file);
        self.timings.record(Call::SyncFile, at, 0, result.is_ok());
        match self.timings.class(file) {
            Some(FileClass::IntentTemporary) if result.is_ok() => {
                self.timings.record(Call::IntentSyncFile, None, 0, true);
            }
            Some(FileClass::IntentInstalled) if result.is_ok() => {
                self.timings.record(Call::IntentSyncFile, None, 0, true);
                if let Some(volume) = self.timings.intent_file(file) {
                    self.timings.intent_pending(volume, IntentStage::Ready);
                }
            }
            Some(FileClass::Decision) => self.timings.decision_sync(file, result.is_ok()),
            None
            | Some(
                FileClass::IntentTemporary
                | FileClass::IntentInstalled
                | FileClass::DecisionTemporary
                | FileClass::Other,
            ) => {}
        }
        result
    }
    fn sync_dir(&self, dir: Held) -> io::Result<()> {
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.sync_dir(dir);
        self.timings.record(Call::SyncDir, at, 0, result.is_ok());
        let pending = self.timings.take_intent_pending();
        if result.is_ok() && pending.is_some() {
            self.timings.record(Call::IntentSyncDir, None, 0, true);
            if matches!(pending, Some(IntentStage::Commit)) {
                self.timings.record(Call::IntentCommit, None, 0, true);
            }
        }
        result
    }
    fn truncate(&self, file: &Self::File, len: u64) -> io::Result<()> {
        self.inner.truncate(file, len)
    }
    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.link(from, to)?;
        self.timings.linked(from, to);
        Ok(())
    }
    fn unlink(&self, name: &str) -> io::Result<()> {
        self.inner.unlink(name).inspect_err(|_| {
            if let Some(volume) = intent_volume(name) {
                self.timings.clear_intent_pending(volume);
            }
        })?;
        if let Some(volume) = name.strip_suffix(".intent.tmp") {
            self.timings
                .intent_pending(volume.to_owned(), IntentStage::Cleanup);
        }
        Ok(())
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.rename(from, to)?;
        self.timings.renamed(from, to);
        Ok(())
    }
}

impl<O> FileOps for Arc<TimedFileOps<O>>
where
    O: FileOps,
    TimedFileOps<O>: FileOps,
{
    type File = <TimedFileOps<O> as FileOps>::File;
    fn check_state(&self) -> io::Result<()> {
        (**self).check_state()
    }
    fn stat_at(&self, name: &str) -> io::Result<Option<Kind>> {
        (**self).stat_at(name)
    }
    fn dir_state(&self) -> io::Result<DirState> {
        (**self).dir_state()
    }
    fn create_new(&self, name: &str) -> io::Result<Self::File> {
        (**self).create_new(name)
    }
    fn open_rw(&self, name: &str) -> io::Result<Self::File> {
        (**self).open_rw(name)
    }
    fn read_marker(&self, name: &str) -> io::Result<Vec<u8>> {
        (**self).read_marker(name)
    }
    fn read_all(&self, file: &Self::File) -> io::Result<Vec<u8>> {
        (**self).read_all(file)
    }
    fn pwrite(&self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        (**self).pwrite(file, offset, bytes)
    }
    fn sync_file(&self, file: &Self::File) -> io::Result<()> {
        (**self).sync_file(file)
    }
    fn sync_dir(&self, dir: Held) -> io::Result<()> {
        (**self).sync_dir(dir)
    }
    fn truncate(&self, file: &Self::File, len: u64) -> io::Result<()> {
        (**self).truncate(file, len)
    }
    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).link(from, to)
    }
    fn unlink(&self, name: &str) -> io::Result<()> {
        (**self).unlink(name)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).rename(from, to)
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the harness injects the specified synchronous one-second driver stall"
)]
fn injected_stall() {
    std::thread::sleep(Duration::from_secs(1));
}

#[expect(
    clippy::disallowed_methods,
    reason = "the test decorator injects its declared synchronous file barrier delay"
)]
fn delayed(delay: Duration) {
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
}
#[derive(Debug, Clone)]
pub(super) struct TimedStore<S> {
    pub inner: S,
    pub timings: Timings,
}
impl<S: RootStore> RootStore for TimedStore<S> {
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.get_root(v, n).await;
        self.timings.record(
            Call::Get,
            at,
            result
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .map_or(0, Vec::len),
            result.is_ok(),
        );
        result
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.max_seq(v).await;
        self.timings.record(Call::List, at, 0, result.is_ok());
        result
    }
    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.max_seq_above(v, floor).await;
        self.timings.record(Call::List, at, 0, result.is_ok());
        result
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "the harness injects the declared asynchronous store delay"
    )]
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        let size = b.len();
        let at = self.timings.enabled.then(stopwatch);
        if !self.timings.store_delay.is_zero() {
            tokio::time::sleep(self.timings.store_delay).await;
        }
        let result = self.inner.put_root(v, n, b).await;
        self.timings.record(Call::Put, at, size, result.is_ok());
        result
    }
    async fn read_hint(&self, v: &str, t: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        self.inner.read_hint(v, t).await
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        self.inner.write_hint(v, n).await
    }
}
impl<S: BinStore> BinStore for TimedStore<S> {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        let size = b.len();
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.put_meta(v, id, b).await;
        self.timings.record(Call::Gateway, at, size, result.is_ok());
        result
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.get_meta(v, id).await;
        self.timings.record(
            Call::Gateway,
            at,
            result.as_ref().map_or(0, Vec::len),
            result.is_ok(),
        );
        result
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        let size = b.len();
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.put_bin(d, b).await;
        self.timings.record(Call::Gateway, at, size, result.is_ok());
        result
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        let at = self.timings.enabled.then(stopwatch);
        let result = self.inner.get_bin_range(d, o, n).await;
        self.timings.record(
            Call::Gateway,
            at,
            result.as_ref().map_or(0, Vec::len),
            result.is_ok(),
        );
        result
    }
}

fn backend(e: impl std::fmt::Display) -> RootStoreError {
    RootStoreError::Backend(e.to_string())
}
#[derive(Debug, Clone)]
pub(super) struct DiskStore(pub PathBuf);
impl DiskStore {
    fn volume(&self, v: &str) -> Result<PathBuf, RootStoreError> {
        let v = VolumeName::new(v.to_owned()).map_err(backend)?;
        Ok(self.0.join(v.as_str()))
    }
    fn root(&self, v: &str, n: u64) -> Result<PathBuf, RootStoreError> {
        Ok(self.volume(v)?.join(format!("{n:020}")))
    }
    fn put(path: &Path, bytes: &[u8]) -> Result<bool, RootStoreError> {
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => return Err(backend(e)),
        };
        file.write_all(bytes).map_err(backend)?;
        file.sync_all().map_err(backend)?;
        Ok(true)
    }
}
impl RootStore for DiskStore {
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        match std::fs::read(self.root(v, n)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(backend(e)),
        }
    }
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        if Self::put(&self.root(v, n)?, &b)? {
            Ok(())
        } else {
            Err(RootStoreError::AlreadyExists)
        }
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        let mut highest = None;
        for entry in std::fs::read_dir(self.volume(v)?).map_err(backend)? {
            let entry = entry.map_err(backend)?;
            if let Some(n) = entry
                .file_name()
                .to_str()
                .filter(|s| s.len() == 20)
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|n| *n > 0 && *n < u64::MAX)
            {
                highest = Some(highest.map_or(n, |old: u64| old.max(n)));
            }
        }
        Ok(highest)
    }
    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(v).await?, floor))
    }
    async fn read_hint(&self, v: &str, _: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        self.volume(v)?;
        Ok(HintRead::Missing)
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        std::fs::write(self.volume(v)?.join("CURRENT"), format!("{n:020}")).map_err(backend)
    }
}
impl BinStore for DiskStore {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        if GrainId::of(&b) != *id {
            return Err(backend("meta id mismatch"));
        }
        Self::put(&self.volume(v)?.join(format!("meta-{id}")), &b)
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        std::fs::read(self.volume(v)?.join(format!("meta-{id}"))).map_err(backend)
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        if GrainId::of(&b).digest() != d {
            return Err(backend("bin id mismatch"));
        }
        Self::put(
            &self.0.join(format!(
                "bin-{}",
                GrainId::from_parts(granary_core::hash::HashAlgorithm::Blake3, *d)
            )),
            &b,
        )
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        let bytes = std::fs::read(self.0.join(format!(
            "bin-{}",
            GrainId::from_parts(granary_core::hash::HashAlgorithm::Blake3, *d)
        )))
        .map_err(backend)?;
        let start = usize::try_from(o).map_err(backend)?;
        if start >= bytes.len() || n == 0 {
            return Err(backend("invalid range"));
        }
        bytes
            .get(start..start.saturating_add(n as usize).min(bytes.len()))
            .map(<[u8]>::to_vec)
            .ok_or_else(|| backend("invalid range"))
    }
}

#[test]
fn authority_measurement_store_decorator_preserves_failed_reads() {
    let inner = TestStore::new(Sim::new().node(1, Faults::none()));
    let bytes = good_root(&a(), 1, None, 1);
    block({
        let inner = inner.clone();
        let bytes = bytes.clone();
        async move {
            inner.put_root(a().as_str(), 1, bytes).await.unwrap();
        }
    });
    let timings = Timings::new(8);
    let decorated = TimedStore {
        inner: inner.clone(),
        timings: timings.clone(),
    };
    let result = block(async move { decorated.get_root(a().as_str(), 1).await });
    assert_eq!(result, Ok(Some(bytes)));
    inner.set_read_fault(&a(), 1, Some(ReadFault::Transport));
    let decorated = TimedStore {
        inner,
        timings: timings.clone(),
    };
    let result = block(async move { decorated.get_root(a().as_str(), 1).await });
    assert_eq!(result, Err(RootStoreError::Backend("planted".to_owned())));
    let (samples, lost) = timings.take();
    assert_eq!((samples.len(), lost), (2, 0));
    assert_eq!(
        samples
            .iter()
            .map(|s| (s.call, s.success))
            .collect::<Vec<_>>(),
        [(Call::Get, true), (Call::Get, false)]
    );
    let mut timings = timings;
    timings.enabled = false;
    timings.record(Call::Get, None, 0, true);
    assert_eq!(timings.take().0.len(), 0);
    assert_eq!(timings.counts().first().copied(), Some(3));
}

#[tokio::test]
async fn authority_measurement_store_decorator_forwards_bounded_listing() {
    #[derive(Debug, Default)]
    struct ListingStore {
        listings: Mutex<Vec<(String, Option<u64>)>>,
    }

    impl RootStore for ListingStore {
        async fn get_root(&self, _: &str, _: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
            unreachable!()
        }
        async fn put_root(&self, _: &str, _: u64, _: Vec<u8>) -> Result<(), RootStoreError> {
            unreachable!()
        }
        async fn read_hint(
            &self,
            _: &str,
            _: Option<&HintToken>,
        ) -> Result<HintRead, RootStoreError> {
            unreachable!()
        }
        async fn write_hint(&self, _: &str, _: u64) -> Result<(), RootStoreError> {
            unreachable!()
        }
        async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
            self.listings.lock().unwrap().push((v.to_owned(), None));
            Ok(Some(99))
        }
        async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
            self.listings
                .lock()
                .unwrap()
                .push((v.to_owned(), Some(floor)));
            Ok(Some(42))
        }
    }

    let store = TimedStore {
        inner: ListingStore::default(),
        timings: Timings::new(8),
    };
    let result = store.max_seq_above("v000", 41).await;
    assert_eq!(
        store.inner.listings.into_inner().unwrap(),
        [("v000".to_owned(), Some(41))]
    );
    assert_eq!(result, Ok(Some(42)));
    let (samples, lost) = store.timings.take();
    assert_eq!((samples.len(), lost), (1, 0));
    let sample = &samples[0];
    assert_eq!(
        (sample.call, sample.bytes, sample.success),
        (Call::List, 0, true)
    );
}

#[derive(Debug, Default)]
struct SyncFixture(std::sync::atomic::AtomicUsize);

#[derive(Debug, Clone, Copy)]
struct SyncFile {
    key: i32,
    valid: bool,
}

impl FileKey for SyncFile {
    fn key(&self) -> i32 {
        self.key
    }
}

#[derive(Debug, Clone, Default)]
struct AppendFixture {
    entered: Arc<std::sync::atomic::AtomicBool>,
    held: Arc<std::sync::atomic::AtomicBool>,
}

impl DecisionLog for AppendFixture {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        Err(LogIoError::Io(IoErrorKind::Other))
    }
    async fn write_marker(&self, _: &EncodedMarker) -> Result<(), LogIoError> {
        Err(LogIoError::Io(IoErrorKind::Other))
    }
    async fn read(&self, _: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        Err(LogIoError::Io(IoErrorKind::Other))
    }
    async fn remove_temporary(&self, _: &VolumeName) -> Result<bool, LogIoError> {
        Err(LogIoError::Io(IoErrorKind::Other))
    }
    async fn initialise(&self, _: &EncodedEnvelope) -> Result<(), LogIoError> {
        Err(LogIoError::Io(IoErrorKind::Other))
    }
    async fn complete_namespace(&self, _: &VolumeName) -> Result<(), LogIoError> {
        Err(LogIoError::Io(IoErrorKind::Other))
    }
    async fn append(&self, _: &Append) -> Result<(), LogIoError> {
        self.entered.store(true, Ordering::SeqCst);
        while self.held.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        Ok(())
    }
    async fn truncate(&self, _: &VolumeName, _: u64) -> Result<(), LogIoError> {
        Ok(())
    }
    async fn resync(&self, _: &VolumeName) -> Result<(), LogIoError> {
        Ok(())
    }
}

impl FileOps for SyncFixture {
    type File = SyncFile;
    fn check_state(&self) -> io::Result<()> {
        Err(io::Error::other("unused operation"))
    }
    fn stat_at(&self, _: &str) -> io::Result<Option<Kind>> {
        Err(io::Error::other("unused operation"))
    }
    fn dir_state(&self) -> io::Result<DirState> {
        Err(io::Error::other("unused operation"))
    }
    fn create_new(&self, name: &str) -> io::Result<SyncFile> {
        Ok(SyncFile {
            key: i32::try_from(self.0.fetch_add(1, Ordering::Relaxed)).unwrap_or(i32::MAX),
            valid: !name.starts_with("fail"),
        })
    }
    fn open_rw(&self, _: &str) -> io::Result<SyncFile> {
        Ok(SyncFile {
            key: i32::try_from(self.0.fetch_add(1, Ordering::Relaxed)).unwrap_or(i32::MAX),
            valid: true,
        })
    }
    fn read_marker(&self, _: &str) -> io::Result<Vec<u8>> {
        Err(io::Error::other("unused operation"))
    }
    fn read_all(&self, _: &SyncFile) -> io::Result<Vec<u8>> {
        Err(io::Error::other("unused operation"))
    }
    fn pwrite(&self, _: &SyncFile, _: u64, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
    fn sync_file(&self, file: &SyncFile) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        if file.valid {
            Ok(())
        } else {
            Err(io::Error::other("injected sync failure"))
        }
    }
    fn sync_dir(&self, dir: Held) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        if matches!(dir, Held::State) {
            Ok(())
        } else {
            Err(io::Error::other("injected sync failure"))
        }
    }
    fn truncate(&self, _: &SyncFile, _: u64) -> io::Result<()> {
        Err(io::Error::other("unused operation"))
    }
    fn link(&self, _: &str, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn unlink(&self, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn rename(&self, _: &str, _: &str) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn authority_measurement_file_decorator_preserves_sync_failures() {
    let timings = Timings::new(8);
    let ops = TimedFileOps {
        inner: SyncFixture::default(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    };
    let valid = SyncFile {
        key: 1,
        valid: true,
    };
    let invalid = SyncFile {
        key: 2,
        valid: false,
    };
    ops.sync_file(&valid).unwrap();
    assert_eq!(
        ops.sync_file(&invalid).unwrap_err().to_string(),
        "injected sync failure"
    );
    ops.sync_dir(Held::State).unwrap();
    assert_eq!(
        ops.sync_dir(Held::Anchor).unwrap_err().to_string(),
        "injected sync failure"
    );
    let (samples, lost) = timings.take();
    assert_eq!(
        (ops.inner.0.load(Ordering::Relaxed), samples.len(), lost),
        (4, 4, 0)
    );
    assert_eq!(
        samples
            .iter()
            .map(|s| (s.call, s.success))
            .collect::<Vec<_>>(),
        [
            (Call::SyncFile, true),
            (Call::SyncFile, false),
            (Call::SyncDir, true),
            (Call::SyncDir, false)
        ]
    );
}

#[test]
fn authority_measurement_file_decorator_separates_durability_work() {
    let timings = Timings::new(16);
    let ops = TimedFileOps {
        inner: SyncFixture::default(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    };
    let intent = ops.create_new("v.intent.tmp").unwrap();
    assert_eq!(ops.pwrite(&intent, 0, b"intent").unwrap(), 6);
    ops.sync_file(&intent).unwrap();
    ops.rename("v.intent.tmp", "v.intent").unwrap();
    ops.sync_dir(Held::State).unwrap();
    let decision = ops.open_rw("v.log").unwrap();
    for offset in [0, 6] {
        assert_eq!(ops.pwrite(&decision, offset, b"record").unwrap(), 6);
        ops.sync_file(&decision).unwrap();
    }
    let counts = timings.counts();
    assert_eq!(
        (
            counts[Call::IntentCommit as usize],
            counts[Call::IntentWrite as usize],
            counts[Call::IntentSyncFile as usize],
            counts[Call::IntentSyncDir as usize],
            counts[Call::DecisionSyncFile as usize],
        ),
        (1, 1, 1, 1, 2),
        "logical intent completion and append barriers must remain separate"
    );
}

#[test]
fn authority_measurement_decision_append_probe_ignores_other_syncs_and_resets() {
    let timings = Timings::new(32);
    let ops = TimedFileOps {
        inner: SyncFixture::default(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    };
    let decision = ops.open_rw("v.log").unwrap();
    for offset in [0, 6] {
        assert_eq!(ops.pwrite(&decision, offset, b"record").unwrap(), 6);
        ops.sync_file(&decision).unwrap();
    }
    ops.sync_file(&decision).unwrap();
    ops.sync_file(&decision).unwrap();
    for offset in [12, 18] {
        assert_eq!(ops.pwrite(&decision, offset, b"record").unwrap(), 6);
        ops.sync_file(&decision).unwrap();
    }
    let counts = timings.counts();
    assert_eq!(
        (counts[Call::DecisionSyncFile as usize],),
        (4,),
        "truncate/resync barriers must not become append work"
    );

    assert_eq!(ops.pwrite(&decision, 24, b"record").unwrap(), 6);
    ops.sync_file(&decision).unwrap();
    let first = timings.counts();
    assert_eq!(ops.pwrite(&decision, 30, b"mark").unwrap(), 4);
    ops.sync_file(&decision).unwrap();
    let second = timings.counts();
    assert_eq!(
        (
            first[Call::DecisionSyncFile as usize],
            second[Call::DecisionSyncFile as usize],
        ),
        (1, 1),
        "a snapshot between an append's barriers must preserve both barriers"
    );
}

#[test]
fn authority_measurement_decision_append_is_counted_at_the_log_call() {
    let timings = Timings::new(16);
    let inner = AppendFixture::default();
    inner.held.store(true, Ordering::SeqCst);
    let log = Arc::new(TimedLog {
        inner: inner.clone(),
        timings: timings.clone(),
    });
    let volume = a();
    let append = encode_append(
        &envelope(&volume, WORLD_EPOCH),
        &decision(&volume, 1, 1, 1, None, 1),
    )
    .unwrap();
    let call = std::thread::spawn(move || block(async move { log.append(&append).await }));
    while !inner.entered.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    let during = timings.counts();
    inner.held.store(false, Ordering::SeqCst);
    assert_eq!(call.join().unwrap(), Ok(()));
    let after = timings.counts();
    let log = TimedLog {
        inner,
        timings: timings.clone(),
    };
    block(async move {
        log.truncate(&volume, 0).await?;
        log.resync(&volume).await
    })
    .unwrap();
    let other_calls = timings.counts();
    assert_eq!(
        (
            during[Call::DecisionAppend as usize],
            after[Call::DecisionAppend as usize],
            other_calls[Call::DecisionAppend as usize],
        ),
        (0, 1, 0),
        "a reset during append must neither drop it nor count other log calls"
    );
}

#[test]
fn authority_measurement_intent_commit_requires_completed_distinct_file() {
    let timings = Timings::new(16);
    let ops = TimedFileOps {
        inner: SyncFixture::default(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    };
    let intent = ops.create_new("v.intent.tmp").unwrap();
    let decision = ops.open_rw("v.log").unwrap();
    assert_eq!(ops.pwrite(&intent, 0, b"intent").unwrap(), 6);
    ops.sync_file(&intent).unwrap();
    let incomplete = timings.counts();
    assert_eq!(incomplete[Call::IntentCommit as usize], 0);
    assert_eq!(ops.pwrite(&decision, 0, b"record").unwrap(), 6);
    ops.sync_file(&decision).unwrap();
    assert_eq!(
        timings.counts()[Call::IntentSyncFile as usize],
        0,
        "the decision file must not inherit the intent file's class"
    );

    let failed = ops.create_new("fail.intent.tmp").unwrap();
    assert_eq!(ops.pwrite(&failed, 0, b"intent").unwrap(), 6);
    assert_eq!(
        ops.sync_file(&failed).unwrap_err().to_string(),
        "injected sync failure"
    );
    assert_eq!(timings.counts()[Call::IntentCommit as usize], 0);

    let failed_directory = ops.create_new("other.intent.tmp").unwrap();
    assert_eq!(ops.pwrite(&failed_directory, 0, b"intent").unwrap(), 6);
    ops.sync_file(&failed_directory).unwrap();
    ops.rename("other.intent.tmp", "other.intent").unwrap();
    assert_eq!(
        ops.sync_dir(Held::Anchor).unwrap_err().to_string(),
        "injected sync failure"
    );
    ops.sync_dir(Held::State).unwrap();
    assert_eq!(
        timings.counts()[Call::IntentCommit as usize],
        0,
        "a later directory sync must not complete a failed intent commit"
    );

    ops.rename("v.intent.tmp", "v.intent").unwrap();
    ops.sync_dir(Held::State).unwrap();
    let completed = timings.counts();
    assert_eq!(
        (
            completed[Call::IntentCommit as usize],
            completed[Call::IntentSyncDir as usize],
        ),
        (1, 1),
        "only the completed intent rename and directory barrier is a commit"
    );
}

#[test]
fn authority_measurement_real_intent_sequence_counts_every_barrier() {
    let path = super::super::intents::scratch();
    let timings = Timings::new(32);
    let inner = StdFileOps::open(&path, true).unwrap();
    drop(inner.create_new("intent-test.intent.tmp").unwrap());
    let ops = Arc::new(TimedFileOps {
        inner,
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    });
    let intents = super::super::super::intent::persistence::FileIntent::store(ops);
    let snapshot =
        super::super::super::intent::tests::snapshot(super::super::super::intent::tests::owned(1));
    intents.io.commit(&snapshot).unwrap();
    let committed = timings.counts();
    assert_eq!(
        (
            committed[Call::IntentCommit as usize],
            committed[Call::IntentSyncFile as usize],
            committed[Call::IntentSyncDir as usize],
            committed[Call::SyncFile as usize],
            committed[Call::SyncDir as usize],
        ),
        (1, 1, 2, 1, 2),
        "one real commit must attribute its temporary cleanup, file and rename barriers"
    );

    intents.io.ready(&snapshot.volume).unwrap();
    let released = timings.counts();
    assert_eq!(
        (
            released[Call::IntentCommit as usize],
            released[Call::IntentSyncFile as usize],
            released[Call::IntentSyncDir as usize],
            released[Call::SyncFile as usize],
            released[Call::SyncDir as usize],
        ),
        (0, 1, 1, 1, 1),
        "ready must attribute its installed-file and directory barriers"
    );
    drop(intents);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn authority_measurement_failed_ready_does_not_credit_later_directory_sync() {
    let path = super::super::intents::scratch();
    let timings = Timings::new(32);
    let ops = Arc::new(TimedFileOps {
        inner: StdFileOps::open(&path, true).unwrap(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    });
    let intents = super::super::super::intent::persistence::FileIntent::store(Arc::clone(&ops));
    let snapshot =
        super::super::super::intent::tests::snapshot(super::super::super::intent::tests::owned(1));
    intents.io.commit(&snapshot).unwrap();
    timings.counts();

    std::fs::create_dir(path.join("intent-test.intent.tmp")).unwrap();
    assert_eq!(
        intents.io.ready(&snapshot.volume),
        Err(LogIoError::Io(IoErrorKind::Other))
    );
    timings.counts();

    ops.sync_dir(Held::State).unwrap();
    assert_eq!(
        timings.counts()[Call::IntentSyncDir as usize],
        0,
        "a failed ready must not credit the next operation's directory sync"
    );

    drop(intents);
    drop(ops);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn authority_measurement_failed_ready_does_not_credit_other_thread_directory_sync() {
    let path = super::super::intents::scratch();
    let timings = Timings::new(32);
    let ops = Arc::new(TimedFileOps {
        inner: StdFileOps::open(&path, true).unwrap(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    });
    let intents = super::super::super::intent::persistence::FileIntent::store(Arc::clone(&ops));
    let snapshot =
        super::super::super::intent::tests::snapshot(super::super::super::intent::tests::owned(1));
    intents.io.commit(&snapshot).unwrap();
    timings.counts();

    std::fs::create_dir(path.join("intent-test.intent.tmp")).unwrap();
    assert_eq!(
        intents.io.ready(&snapshot.volume),
        Err(LogIoError::Io(IoErrorKind::Other))
    );
    timings.counts();

    let unrelated = Arc::clone(&ops);
    std::thread::spawn(move || unrelated.sync_dir(Held::State))
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(
        timings.counts()[Call::IntentSyncDir as usize],
        0,
        "a failed ready must not credit another thread's directory sync"
    );

    drop(intents);
    drop(ops);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn authority_measurement_intent_completion_is_per_volume() {
    let timings = Timings::new(16);
    let ops = Arc::new(TimedFileOps {
        inner: SyncFixture::default(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    });
    let _ = ops.create_new("a.intent.tmp").unwrap();
    let _ = ops.create_new("b.intent.tmp").unwrap();
    let renamed = Arc::new(std::sync::Barrier::new(2));
    let second_synced = Arc::new(std::sync::Barrier::new(2));
    let first = {
        let ops = ops.clone();
        let renamed = renamed.clone();
        let second_synced = second_synced.clone();
        std::thread::spawn(move || {
            ops.rename("a.intent.tmp", "a.intent").unwrap();
            renamed.wait();
            second_synced.wait();
            ops.sync_dir(Held::State).unwrap();
        })
    };
    renamed.wait();
    ops.rename("b.intent.tmp", "b.intent").unwrap();
    ops.sync_dir(Held::State).unwrap();
    second_synced.wait();
    first.join().unwrap();
    let counts = timings.counts();
    assert_eq!(
        (
            counts[Call::IntentCommit as usize],
            counts[Call::IntentSyncDir as usize],
        ),
        (2, 2),
        "one volume's directory sync must not consume another volume's completion"
    );
}

#[test]
fn authority_measurement_failed_mark_sync_resets_append_stage() {
    let timings = Timings::new(16);
    let ops = TimedFileOps {
        inner: SyncFixture::default(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    };
    let decision = ops.open_rw("v.log").unwrap();
    assert_eq!(ops.pwrite(&decision, 0, b"record").unwrap(), 6);
    ops.sync_file(&decision).unwrap();
    assert_eq!(ops.pwrite(&decision, 6, b"mark").unwrap(), 4);
    assert_eq!(
        ops.sync_file(&SyncFile {
            key: decision.key,
            valid: false,
        })
        .unwrap_err()
        .to_string(),
        "injected sync failure"
    );
    timings.counts();
    ops.sync_file(&decision).unwrap();
    assert_eq!(
        timings.counts()[Call::DecisionSyncFile as usize],
        0,
        "a sync after a failed mark must not be attributed to that failed append"
    );
}

#[tokio::test]
async fn authority_measurement_known_slow_store_and_file_controls() {
    let delay = Duration::from_millis(10);
    let timings = Timings::delayed(8, delay, delay);
    let store = TimedStore {
        inner: TestStore::new(Sim::new().node(1, Faults::none())),
        timings: timings.clone(),
    };
    let volume = a();
    store
        .put_root(volume.as_str(), 1, good_root(&volume, 1, None, 1))
        .await
        .unwrap();
    let ops = TimedFileOps {
        inner: SyncFixture::default(),
        timings: timings.clone(),
        stalls: Arc::new(Stall::default()),
    };
    ops.sync_file(&SyncFile {
        key: 1,
        valid: true,
    })
    .unwrap();
    let (samples, lost) = timings.take();
    let delayed = samples
        .iter()
        .filter(|sample| matches!(sample.call, Call::Put | Call::SyncFile))
        .count();
    let store_samples = samples
        .iter()
        .filter(|sample| sample.call == Call::Put)
        .count();
    let file_samples = samples
        .iter()
        .filter(|sample| sample.call == Call::SyncFile)
        .count();
    assert_eq!(
        (
            timings.store_delay,
            timings.file_delay,
            delayed,
            store_samples,
            file_samples,
            lost,
        ),
        (delay, delay, 2, 1, 1, 0),
        "store and file delays must be reported by independent observers"
    );
    assert!(samples.iter().all(|sample| sample.elapsed >= delay));
}

#[test]
fn authority_measurement_gateway_record_is_independent_of_driver_snapshot() {
    let timings = Timings::new(8);
    let driver_snapshot = timings.buffer.lock().unwrap();
    timings.record(Call::Gateway, Some(stopwatch()), 7, true);
    drop(driver_snapshot);
    let (samples, lost) = timings.take();
    assert_eq!(
        (
            samples.len(),
            lost,
            samples.first().map(|s| (s.call, s.bytes, s.success))
        ),
        (1, 0, Some((Call::Gateway, 7, true))),
        "gateway activity must not be lost behind the driver's sample buffer"
    );
}

#[test]
fn authority_measurement_io_window_excludes_setup_and_teardown() {
    let origin = stopwatch();
    let boundary = |millis| origin + Duration::from_millis(millis);
    let sample = |start, end| IoSample {
        call: Call::SyncFile,
        elapsed: Duration::from_millis(end - start),
        start: boundary(start),
        end: boundary(end),
        bytes: 0,
        success: true,
    };
    let valid = sample(1, 2);
    assert_eq!(valid.publication_interval(boundary(1), boundary(3)), Ok(()));
    let refused = [sample(0, 2), sample(2, 4)];
    for sample in &refused {
        assert_eq!(
            sample.publication_interval(boundary(1), boundary(3)),
            Err("I/O outside completed publication interval")
        );
    }
    assert_eq!(
        (
            usize::from(valid.publication_interval(boundary(1), boundary(3)).is_ok()),
            refused.len()
        ),
        (1, 2)
    );
}
