// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The medium under the decision-log fake: inodes and names, what each
//! holds durably and what is still pending, and the draw a host crash
//! applies to them.
//!
//! **Inodes.** Each holds its `durable` bytes (what the medium has) and
//! its `cache` bytes (what a read returns: every write, synced or not —
//! the page cache). `stable` is the length of the prefix the two are
//! known to share; it falls below `durable.len()` exactly when a
//! truncation has not been synced. Writes only ever append, so the
//! unsynced bytes are always `cache[stable..]`.
//!
//! **Names.** The medium's namespace (`durable`) and the process's view
//! (`current`) differ by the pending namespace operations, kept in
//! issue order across the whole filesystem. A directory sync commits
//! the pending operations up to and including the last one in that
//! directory; a host crash keeps a prefix of them. Both rest on the
//! model's assumption that **metadata commits in issue order**, which
//! this fake takes as given rather than verifying: the deployment
//! filesystems (spec §6.2) are journaled ext4, xfs, and btrfs, never
//! APFS. A temporary linked to a log's name is one inode under two
//! names, and a rename-over leaves the old binding as the medium's
//! answer until a directory sync commits it.
//!
//! **Truncation is inode metadata, covered by the file's sync**, not by
//! a directory sync: `truncate` then `fsync` of the same file is what
//! makes it durable, so an unsynced truncation is drawn per inode (kept
//! or undone), independently of the namespace prefix.
//!
//! **A failed sync poisons what it covered until the host crashes.**
//! For file data this is reproduced fact, the fsyncgate hazard: on a
//! real kernel a failed writeback can leave its pages clean in the page
//! cache, so a restarted process reads them back, its re-sync
//! "succeeds" without writing anything, and the next power loss can
//! still lose them — so a failed file sync marks its inode, and a later
//! successful sync of it moves nothing to the medium until the next
//! host crash. For the namespace this fake goes further, by a
//! **deliberately stronger, unverified** adversarial model: a failed
//! directory sync marks every pending namespace operation, and while
//! marked, a later successful sync of any directory moves nothing to
//! the medium either. This is not a claim about what ext4, xfs or btrfs
//! actually do after a failed directory sync — it is conservative for
//! operations issued after the failure, which costs nothing a correct
//! caller relies on: after a failed sync every further mutating call is
//! already a fence violation, so a correct caller issues none before
//! the host crashes and so never observes the difference. Only a host
//! crash clears the marks, and with them the disk's own record that a
//! sync failed since the last boot.
//!
//! **After a crash the draw is the new medium.** Every surviving byte
//! and name becomes durable, so a second crash draws only from what was
//! written after the first.
//! This medium models bytes and namespace durability, not file mtime or
//! directory ctime. Operator reboot checks therefore use constructed times
//! through the server's boot-start seam; a process restart keeps those times.

use std::collections::BTreeMap;

use granary_core::authlog::{Classified, MARK_LEN, classify, encode_append, encode_envelope};
use granary_core::root::VolumeName;

use crate::rng::Rng;
use crate::trace::{DrawRow, Fill, LogPath, TruncationDraw, Volume};

/// An inode number: a harness-assigned counter, never ambient.
pub(super) type Ino = u64;

/// What a write carries, so the inode's ledger of appends can name a
/// crash's outcome by its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteKind {
    /// Anything that is not one half of an append.
    Plain,
    /// An append's record.
    Record,
    /// An append's mark.
    Mark,
}

/// One append, as the inode's ledger tracks it: where its record and
/// mark lie, and which of its steps have happened.
#[derive(Debug, Clone)]
struct Pair {
    record_start: usize,
    mark_start: usize,
    mark_end: usize,
    record_synced: bool,
    mark_written: bool,
    mark_synced: bool,
}

/// One file's content (module docs).
#[derive(Debug, Clone, Default)]
pub(super) struct Inode {
    durable: Vec<u8>,
    cache: Vec<u8>,
    stable: usize,
    pairs: Vec<Pair>,
    /// A sync of this inode failed since the last host crash (module
    /// docs).
    poisoned: bool,
    /// Where a log's committed prefix ends, when bytes follow it that
    /// recovery has not yet truncated: noted when a host crash or a
    /// fixture leaves the log, cleared by a truncation to at most that
    /// length.
    tail_from: Option<usize>,
}

/// What a host crash drew for one file's unsynced bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileDraw {
    pub(super) truncation: TruncationDraw,
    pub(super) base: usize,
    pub(super) written: usize,
    pub(super) kept: usize,
    pub(super) garbage: usize,
    pub(super) fill: Fill,
}

/// A uniform index in `0..n`, `n` clamped to what [`Rng::below`] takes.
fn below(rng: &mut Rng, n: usize) -> usize {
    usize::try_from(rng.below(u32::try_from(n).unwrap_or(u32::MAX))).unwrap_or(usize::MAX)
}

impl Inode {
    fn durable(bytes: Vec<u8>) -> Self {
        Self {
            stable: bytes.len(),
            durable: bytes.clone(),
            cache: bytes,
            pairs: Vec::new(),
            poisoned: false,
            tail_from: None,
        }
    }

    /// Where an untruncated tail begins ([`Disk::note_tails`]).
    pub(super) fn tail_from(&self) -> Option<usize> {
        self.tail_from
    }

    /// What a read returns.
    pub(super) fn bytes(&self) -> &[u8] {
        &self.cache
    }

    /// A truncation whose sync has not returned.
    pub(super) fn truncation_pending(&self) -> bool {
        self.stable < self.durable.len()
    }

    /// Bytes written with no returned sync.
    pub(super) fn bytes_pending(&self) -> bool {
        self.cache.len() > self.stable
    }

    /// Everything a read returns is on the medium.
    pub(super) fn synced(&self) -> bool {
        !self.truncation_pending() && !self.bytes_pending()
    }

    /// Append `bytes`. For a [`WriteKind::Mark`], answers whether the
    /// record it follows had been synced — `None` when no record
    /// precedes it in the ledger.
    fn write(&mut self, bytes: &[u8], kind: WriteKind) -> Option<bool> {
        let start = self.cache.len();
        self.cache.extend_from_slice(bytes);
        match kind {
            WriteKind::Plain => None,
            WriteKind::Record => {
                let mark_start = self.cache.len();
                self.pairs.push(Pair {
                    record_start: start,
                    mark_start,
                    mark_end: mark_start.saturating_add(MARK_LEN),
                    record_synced: false,
                    mark_written: false,
                    mark_synced: false,
                });
                None
            }
            WriteKind::Mark => {
                let pair = self.pairs.last_mut()?;
                pair.mark_written = true;
                Some(pair.record_synced)
            }
        }
    }

    /// A successful sync: the cache reaches the medium — unless an
    /// earlier sync of this inode failed, when nothing moves (module
    /// docs).
    fn sync(&mut self) {
        if self.poisoned {
            return;
        }
        if self.truncation_pending() {
            self.durable.clone_from(&self.cache);
        } else {
            // No truncation pending: `durable` is exactly
            // `cache[..stable]`, so only the new suffix moves.
            self.durable
                .extend_from_slice(self.cache.get(self.stable..).unwrap_or_default());
        }
        self.stable = self.cache.len();
        for pair in &mut self.pairs {
            pair.record_synced = true;
            if pair.mark_written {
                pair.mark_synced = true;
            }
        }
    }

    fn truncate(&mut self, len: usize) {
        if self.tail_from.is_some_and(|from| len <= from) {
            self.tail_from = None;
        }
        self.cache.truncate(len);
        self.stable = self.stable.min(len);
        self.pairs.retain(|p| p.mark_end <= len);
    }

    /// Make `bytes` the medium's and the cache's content.
    fn settle(&mut self, bytes: Vec<u8>) {
        self.poisoned = false;
        self.stable = bytes.len();
        self.durable.clone_from(&bytes);
        self.cache = bytes;
        for pair in &mut self.pairs {
            pair.record_synced = true;
            pair.mark_written = true;
            pair.mark_synced = true;
        }
    }

    /// The crash draw for this file (module docs): an
    /// unsynced truncation kept or undone; the unsynced bytes absent,
    /// whole, a proper prefix, or a proper prefix followed by garbage
    /// within the written length. Answers the draw and, for each
    /// unacknowledged append, its row — an undone truncation takes every
    /// append written after it with it, and each gets
    /// [`DrawRow::LostWithUndoneTruncation`].
    fn crash(&mut self, rng: &mut Rng) -> (FileDraw, Vec<(usize, DrawRow)>) {
        let mut truncation = TruncationDraw::None;
        if self.truncation_pending() {
            if rng.below(2) == 1 {
                let restored = self.durable.clone();
                let base = restored.len();
                let mut rows = Vec::new();
                self.pairs.retain(|p| {
                    let kept = p.mark_synced && p.mark_end <= base;
                    if !kept {
                        rows.push((p.record_start, DrawRow::LostWithUndoneTruncation));
                    }
                    kept
                });
                self.settle(restored);
                let draw = FileDraw {
                    truncation: TruncationDraw::Undone,
                    base,
                    written: 0,
                    kept: 0,
                    garbage: 0,
                    fill: Fill::None,
                };
                return (draw, rows);
            }
            truncation = TruncationDraw::Kept;
        }
        let base = self.stable;
        let written = self.cache.len().saturating_sub(base);
        let (kept, garbage, fill) = if written == 0 {
            (0, 0, Fill::None)
        } else {
            match rng.below(4) {
                0 => (0, 0, Fill::None),
                1 => (written, 0, Fill::None),
                2 => (below(rng, written), 0, Fill::None),
                _ => {
                    let kept = below(rng, written);
                    let garbage = below(rng, written - kept).saturating_add(1);
                    let fill = if rng.below(2) == 0 {
                        Fill::Zero
                    } else {
                        Fill::Seeded
                    };
                    (kept, garbage, fill)
                }
            }
        };
        let true_end = base.saturating_add(kept);
        let mut result = self.cache.get(..true_end).unwrap_or_default().to_vec();
        for _ in 0..garbage {
            let byte = match fill {
                Fill::Seeded => {
                    let [byte, ..] = rng.next_u32().to_le_bytes();
                    byte
                }
                Fill::None | Fill::Zero => 0,
            };
            result.push(byte);
        }
        let garbage_end = true_end.saturating_add(garbage);

        let mut rows = Vec::new();
        self.pairs.retain(|p| {
            if p.mark_synced {
                return true;
            }
            let row = if !p.record_synced {
                if true_end >= p.mark_start {
                    DrawRow::RecordWholeUnsynced
                } else if garbage_end <= p.record_start {
                    DrawRow::RecordAbsent
                } else {
                    DrawRow::RecordTorn
                }
            } else if p.mark_written && true_end >= p.mark_end {
                DrawRow::Survivor
            } else {
                DrawRow::MarkAbsentOrTorn
            };
            rows.push((p.record_start, row));
            row == DrawRow::Survivor
        });
        self.settle(result);
        let draw = FileDraw {
            truncation,
            base,
            written,
            kept,
            garbage,
            fill,
        };
        (draw, rows)
    }
}

/// A namespace: whether the state directory exists, and which inode
/// each file name inside it names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Namespace {
    state_dir: bool,
    files: BTreeMap<LogPath, Ino>,
}

/// One pending namespace operation.
#[derive(Debug, Clone)]
enum NsOp {
    Mkdir,
    Bind(LogPath, Ino),
    Unlink(LogPath),
    Rename(LogPath, LogPath),
}

impl NsOp {
    /// The directory whose sync commits this operation.
    fn dir(&self) -> LogPath {
        match self {
            Self::Mkdir => LogPath::Anchor,
            Self::Bind(..) | Self::Unlink(_) | Self::Rename(..) => LogPath::StateDir,
        }
    }
}

impl Namespace {
    fn apply(&mut self, op: &NsOp) {
        match op {
            NsOp::Mkdir => self.state_dir = true,
            NsOp::Bind(path, ino) => {
                self.files.insert(path.clone(), *ino);
            }
            NsOp::Unlink(path) => {
                self.files.remove(path);
            }
            NsOp::Rename(from, to) => {
                if let Some(ino) = self.files.remove(from) {
                    self.files.insert(to.clone(), ino);
                }
            }
        }
    }
}

/// What a host crash drew, for the fake to trace and report.
#[derive(Debug)]
pub(super) struct CrashDraw {
    pub(super) pending: usize,
    pub(super) kept: usize,
    pub(super) files: Vec<(LogPath, FileDraw)>,
    pub(super) rows: Vec<(LogPath, usize, DrawRow)>,
}

/// Why a namespace step refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NsError {
    /// The name the step needs is absent, or its directory is.
    NotFound,
    /// The name the step would create exists.
    AlreadyExists,
}

/// The filesystem (module docs).
#[derive(Debug, Default)]
pub(crate) struct Disk {
    inodes: BTreeMap<Ino, Inode>,
    next_ino: Ino,
    durable: Namespace,
    current: Namespace,
    pending: Vec<NsOp>,
    /// A directory sync failed while namespace operations were pending
    /// (module docs).
    ns_poisoned: bool,
    /// A sync failed, or a mutating call failed after it began, since
    /// the last host crash.
    fenced: bool,
}

impl Disk {
    fn issue(&mut self, op: NsOp) {
        self.current.apply(&op);
        self.pending.push(op);
    }

    fn new_inode(&mut self, inode: Inode) -> Ino {
        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);
        self.inodes.insert(ino, inode);
        ino
    }

    /// Whether a sync failed, or a mutating call failed after it began,
    /// since the last host crash.
    pub(super) fn fenced(&self) -> bool {
        self.fenced
    }

    /// Fence the disk until the next host crash.
    pub(super) fn fence(&mut self) {
        self.fenced = true;
    }

    /// Note, for every log the process's view names, whether bytes
    /// follow its committed prefix ([`Inode::tail_from`]). One
    /// [`classify`] per log, at the moments a log's bytes can gain a
    /// tail without an append: a host crash, a media fault, a fixture.
    pub(super) fn note_tails(&mut self) {
        let logs: Vec<(Ino, VolumeName)> = self
            .current
            .files
            .iter()
            .filter_map(|(path, ino)| match path {
                LogPath::Log(volume) => {
                    Some((*ino, VolumeName::new(volume.as_str().to_owned()).ok()?))
                }
                _ => None,
            })
            .collect();
        for (ino, volume) in logs {
            if let Some(inode) = self.inodes.get_mut(&ino) {
                inode.tail_from = match classify(&inode.cache, &volume) {
                    Ok(Classified::Log {
                        committed_len,
                        tail_len,
                        ..
                    }) if tail_len > 0 => Some(committed_len),
                    _ => None,
                };
            }
        }
    }

    /// Poison what a failed sync of `path` covered (a file, or
    /// [`LogPath::Anchor`] or [`LogPath::StateDir`]; module docs).
    pub(super) fn poison(&mut self, path: &LogPath) {
        match path {
            LogPath::Anchor | LogPath::StateDir => self.ns_poisoned = true,
            LogPath::Marker | LogPath::MarkerTemp | LogPath::Log(_) | LogPath::Temp(_) => {
                if let Some(inode) = self.file_mut(path) {
                    inode.poisoned = true;
                }
            }
        }
    }

    /// Whether the state directory exists, in the process's view.
    pub(super) fn state_dir(&self) -> bool {
        self.current.state_dir
    }

    /// Whether the state directory holds anything.
    pub(super) fn occupied(&self) -> bool {
        !self.current.files.is_empty()
    }

    /// The file at `path`, in the process's view.
    pub(super) fn file(&self, path: &LogPath) -> Option<&Inode> {
        self.inodes.get(self.current.files.get(path)?)
    }

    fn file_mut(&mut self, path: &LogPath) -> Option<&mut Inode> {
        self.inodes.get_mut(self.current.files.get(path)?)
    }

    /// Whether `path` names the same inode on the medium as in the
    /// process's view, inside a durable state directory.
    pub(super) fn name_durable(&self, path: &LogPath) -> bool {
        let current = self.current.files.get(path);
        current.is_some() && self.durable.state_dir && self.durable.files.get(path) == current
    }

    pub(super) fn mkdir(&mut self) -> Result<(), NsError> {
        if self.current.state_dir {
            return Err(NsError::AlreadyExists);
        }
        self.issue(NsOp::Mkdir);
        Ok(())
    }

    /// Create an empty file at `path`: refused if the name exists and
    /// `exclusive`, otherwise it replaces the old binding.
    pub(super) fn create(&mut self, path: &LogPath, exclusive: bool) -> Result<(), NsError> {
        if !self.current.state_dir {
            return Err(NsError::NotFound);
        }
        if exclusive && self.current.files.contains_key(path) {
            return Err(NsError::AlreadyExists);
        }
        let ino = self.new_inode(Inode::default());
        self.issue(NsOp::Bind(path.clone(), ino));
        Ok(())
    }

    pub(super) fn link(&mut self, from: &LogPath, to: &LogPath) -> Result<(), NsError> {
        let ino = *self.current.files.get(from).ok_or(NsError::NotFound)?;
        if self.current.files.contains_key(to) {
            return Err(NsError::AlreadyExists);
        }
        self.issue(NsOp::Bind(to.clone(), ino));
        Ok(())
    }

    /// Remove `path`: `false`, and nothing issued, when it is absent.
    pub(super) fn unlink(&mut self, path: &LogPath) -> bool {
        if !self.current.files.contains_key(path) {
            return false;
        }
        self.issue(NsOp::Unlink(path.clone()));
        true
    }

    pub(super) fn rename(&mut self, from: &LogPath, to: &LogPath) -> Result<(), NsError> {
        if !self.current.files.contains_key(from) {
            return Err(NsError::NotFound);
        }
        self.issue(NsOp::Rename(from.clone(), to.clone()));
        Ok(())
    }

    /// Append `bytes` to the file at `path` ([`Inode::write`]'s answer).
    pub(super) fn write(
        &mut self,
        path: &LogPath,
        bytes: &[u8],
        kind: WriteKind,
    ) -> Result<Option<bool>, NsError> {
        let answer = self
            .file_mut(path)
            .ok_or(NsError::NotFound)?
            .write(bytes, kind);
        Ok(answer)
    }

    pub(super) fn file_sync(&mut self, path: &LogPath) -> Result<(), NsError> {
        self.file_mut(path).ok_or(NsError::NotFound)?.sync();
        Ok(())
    }

    /// Truncate the file at `path`; the caller has checked `len`.
    pub(super) fn truncate(&mut self, path: &LogPath, len: usize) -> Result<(), NsError> {
        self.file_mut(path).ok_or(NsError::NotFound)?.truncate(len);
        Ok(())
    }

    /// Commit the pending namespace operations up to and including the
    /// last one in `dir` (module docs: in-order metadata) — nothing at
    /// all while a failed directory sync has poisoned them.
    pub(super) fn dir_sync(&mut self, dir: &LogPath) {
        if self.ns_poisoned {
            return;
        }
        let Some(last) = self.pending.iter().rposition(|op| op.dir() == *dir) else {
            return;
        };
        let committed: Vec<NsOp> = self.pending.drain(..=last).collect();
        for op in &committed {
            self.durable.apply(op);
        }
    }

    /// A host crash: a prefix of the pending namespace operations
    /// survives, then each reachable file's unsynced bytes are drawn,
    /// and the result becomes the medium.
    pub(super) fn crash(&mut self, rng: &mut Rng) -> CrashDraw {
        let ops = std::mem::take(&mut self.pending);
        self.ns_poisoned = false;
        self.fenced = false;
        let pending = ops.len();
        let kept = below(rng, pending.saturating_add(1));
        for op in ops.iter().take(kept) {
            self.durable.apply(op);
        }
        self.current = self.durable.clone();
        if !self.current.state_dir {
            self.current.files.clear();
            self.durable.files.clear();
        }

        let mut named: BTreeMap<Ino, LogPath> = BTreeMap::new();
        for (path, ino) in &self.current.files {
            named.entry(*ino).or_insert_with(|| path.clone());
        }
        self.inodes.retain(|ino, _| named.contains_key(ino));

        let mut files = Vec::new();
        let mut rows = Vec::new();
        for (ino, inode) in &mut self.inodes {
            let Some(path) = named.get(ino) else {
                continue;
            };
            let (draw, file_rows) = inode.crash(rng);
            files.push((path.clone(), draw));
            rows.extend(
                file_rows
                    .into_iter()
                    .map(|(at, row)| (path.clone(), at, row)),
            );
        }
        CrashDraw {
            pending,
            kept,
            files,
            rows,
        }
    }

    /// Every file the process's view names, with its bytes.
    pub(super) fn listing(&self) -> Vec<(LogPath, Vec<u8>)> {
        self.current
            .files
            .iter()
            .filter_map(|(path, ino)| Some((path.clone(), self.inodes.get(ino)?.cache.clone())))
            .collect()
    }

    /// Flip bytes of `volume`'s log on the medium, as an injected media
    /// fault, and answer the range flipped. `None`, and nothing
    /// changed, when the log holds no committed record for the fault to
    /// land in. The committed records and their offsets are
    /// [`classify`]'s, re-encoded with the same codec — so a log planted
    /// through the fixture hooks, or one an undone truncation restored,
    /// is targeted exactly like one this fake appended to.
    pub(super) fn damage(
        &mut self,
        volume: &VolumeName,
        target: &DamageTarget,
    ) -> Option<(usize, usize)> {
        let path = LogPath::Log(Volume::from_checked(volume));
        let inode = self.file_mut(&path)?;
        let Ok(Classified::Log {
            envelope, records, ..
        }) = classify(&inode.cache, volume)
        else {
            return None;
        };
        // (record start, mark start) of each committed record, in order.
        let mut pos = encode_envelope(&envelope).as_bytes().len();
        let mut committed = Vec::with_capacity(records.len());
        for record in &records {
            let mark_start =
                pos.checked_add(encode_append(&envelope, record).ok()?.record().len())?;
            committed.push((pos, mark_start));
            pos = mark_start.checked_add(MARK_LEN)?;
        }
        let mid = |(record_start, mark_start): (usize, usize)| {
            record_start + (mark_start - record_start) / 2
        };
        let (start, end) = match target {
            DamageTarget::Record(index) => {
                let at = mid(*committed.get(*index)?);
                (at, at.saturating_add(1))
            }
            DamageTarget::Tail {
                records,
                into_record,
            } => {
                if *records == 0 {
                    return None;
                }
                let first = *committed.get(committed.len().checked_sub(*records)?)?;
                let start = if *into_record { mid(first) } else { first.1 };
                (start, inode.cache.len())
            }
            DamageTarget::Plant { keep, tail } => {
                let boundary = match committed.get(*keep) {
                    Some((record_start, _)) => *record_start,
                    None if *keep == committed.len() => pos,
                    None => return None,
                };
                let mut bytes = inode.cache.get(..boundary)?.to_vec();
                bytes.extend_from_slice(tail);
                let end = bytes.len();
                inode.pairs.retain(|p| p.mark_end <= boundary);
                inode.settle(bytes);
                return Some((boundary, end));
            }
        };
        let mut bytes = inode.cache.clone();
        for byte in bytes.get_mut(start..end)? {
            *byte ^= 0xFF;
        }
        inode.pairs.retain(|p| p.mark_end <= start);
        inode.settle(bytes);
        Some((start, end))
    }

    /// Plant `bytes` at `path` durably, bypassing every step.
    pub(super) fn seed_file(&mut self, path: &LogPath, bytes: Vec<u8>) {
        let ino = self.new_inode(Inode::durable(bytes));
        for ns in [&mut self.durable, &mut self.current] {
            ns.state_dir = true;
            ns.files.insert(path.clone(), ino);
        }
        self.note_tails();
    }

    /// Back to just-constructed: nothing on the medium, no fence.
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    /// An existing, empty state directory, durably.
    pub(super) fn seed_empty_state_dir(&mut self) {
        self.inodes.clear();
        self.pending.clear();
        self.durable = Namespace {
            state_dir: true,
            files: BTreeMap::new(),
        };
        self.current = self.durable.clone();
    }
}

/// Where an injected media fault lands in a log's committed records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DamageTarget {
    /// One byte inside this committed record, its mark untouched.
    Record(usize),
    /// Everything from the mark of the first of the last `records`
    /// committed records — or, with `into_record`, from the middle of
    /// that record — to the end of the file.
    Tail { records: usize, into_record: bool },
    /// Everything after the first `keep` committed records, replaced
    /// by `tail`.
    Plant { keep: usize, tail: Vec<u8> },
}
