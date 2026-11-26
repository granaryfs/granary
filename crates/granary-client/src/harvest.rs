// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Harvest: walk a source tree (std `read_dir`, raw-byte sort,
//! symlinks never followed), chunk+hash files (thresh/hash), build the
//! manifest content tree, write grains + manifest objects
//! into the local store. Deterministic: same tree bytes → same root.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirEntryExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use granary_core::hash::GrainId;
use granary_core::manifest::{
    self, DirEntry, EntryKind, FileGrains, GrainRef, Name, SymlinkTarget, tree,
};
use granary_core::thresh;

use crate::fsguard;
use crate::store::{Store, StoreError};

#[derive(Debug, Default, Clone, Copy)]
pub struct HarvestStats {
    pub dirs: u64,
    pub files: u64,
    pub symlinks: u64,
    pub grains_total: u64,
    pub grains_novel: u64,
    pub bytes_total: u64,
    pub bytes_novel: u64,
    pub nodes_total: u64,
    pub nodes_novel: u64,
}

/// Stable Unix identity captured from an already-open regular-file
/// descriptor. A path can gain another name (hard link, rename, or a
/// namespace alias), but every name that reaches the same file still
/// resolves to this `(st_dev, st_ino)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    /// Capture identity from the held descriptor, never from a path that
    /// could be replaced between the check and the later harvest.
    ///
    /// # Errors
    /// Whatever the descriptor's `fstat` reports.
    pub fn from_file(file: &fs::File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        metadata.dev() == self.dev && metadata.ino() == self.ino
    }
}

#[derive(Debug)]
pub enum HarvestError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Store(StoreError),
    /// Reject at write: a bad name in the SOURCE tree fails the
    /// harvest loudly (includes `.gran*` — documented behaviour).
    BadName {
        path: PathBuf,
        why: String,
    },
    BadSymlink {
        path: PathBuf,
        why: String,
    },
    /// fifo/socket/device/unknown — v1 harvests reject special files.
    SpecialFile {
        path: PathBuf,
    },
    /// TOCTOU tripwire: identity (dev/ino), type, size, or mtime of
    /// the opened file disagrees with the pre-read lstat.
    ChangedDuringHarvest {
        path: PathBuf,
    },
    /// A file with more than `u32::MAX` grains is not representable in
    /// manifest v1 (checked, never truncated).
    TooManyGrains {
        path: PathBuf,
    },
    /// v1 harvests one filesystem: a child directory on a different
    /// device is rejected, not crossed (restic --one-file-system
    /// precedent; mount-crossing identity is ambiguous — readdir sees
    /// the covered dir, lstat the mounted root).
    MountBoundary {
        path: PathBuf,
    },
    Build(manifest::EncodeNodeError),
    /// The root `source` argument itself is not a directory — a stable
    /// condition (a symlink-to-dir or a plain-file path), NOT a race:
    /// `ChangedDuringHarvest` stays reserved for a CHILD whose type
    /// moved between readdir and descent (macOS `/tmp` and many user
    /// paths are themselves symlinks).
    NotADirectory {
        path: PathBuf,
    },
    /// A caller-protected private key file reached the
    /// source under another path name. Refuse the whole harvest before
    /// reading it; silently omitting a named source entry would publish a
    /// tree different from the operator's input.
    RefusedFileIdentity {
        path: PathBuf,
    },
}

impl std::fmt::Display for HarvestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Store(e) => write!(f, "store: {e}"),
            // BadName and BadSymlink share one rendering — the `why`
            // text already names the rule (match_same_arms).
            Self::BadName { path, why } | Self::BadSymlink { path, why } => {
                write!(f, "{}: {why}", path.display())
            }
            Self::SpecialFile { path } => {
                write!(
                    f,
                    "{}: special file (fifo/socket/device) — not harvestable in v1",
                    path.display()
                )
            }
            Self::ChangedDuringHarvest { path } => {
                write!(
                    f,
                    "{}: changed during harvest (identity/type/size/mtime moved between stat and read)",
                    path.display()
                )
            }
            Self::TooManyGrains { path } => {
                write!(
                    f,
                    "{}: file exceeds u32::MAX grains — not representable in manifest v1",
                    path.display()
                )
            }
            Self::MountBoundary { path } => {
                write!(
                    f,
                    "{}: mount boundary — v1 harvests one filesystem at a time",
                    path.display()
                )
            }
            Self::Build(e) => write!(f, "manifest build: {e}"),
            Self::NotADirectory { path } => {
                write!(
                    f,
                    "{}: source is not a directory (symlinks are never followed — pass the resolved path)",
                    path.display()
                )
            }
            Self::RefusedFileIdentity { path } => {
                write!(
                    f,
                    "{}: source file is protected private key material; refusing harvest",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for HarvestError {}

impl From<StoreError> for HarvestError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<manifest::EncodeNodeError> for HarvestError {
    fn from(e: manifest::EncodeNodeError) -> Self {
        Self::Build(e)
    }
}

/// Harvest `source` into `store`; returns (root id, stats).
///
/// # Errors
/// Any [`HarvestError`]. The source tree's own shape produces most of
/// them — [`HarvestError::NotADirectory`] for a `source` that is not one,
/// [`HarvestError::BadName`] for names that are empty, exceed 255 bytes,
/// contain NUL or `/`, equal `.` or `..`, or start with `.gran`;
/// [`HarvestError::BadSymlink`] for targets that are empty, exceed
/// 4096 bytes, or contain NUL; [`HarvestError::SpecialFile`] for a
/// fifo/socket/device,
/// [`HarvestError::MountBoundary`] for a child on another filesystem, and
/// [`HarvestError::ChangedDuringHarvest`] when the TOCTOU tripwires catch
/// the tree moving underneath the walk. [`HarvestError::Store`] and
/// [`HarvestError::Io`] carry the local store's and the filesystem's own
/// failures. Objects already written when one of these fires STAY in the
/// store: it is content-addressed, so a partial harvest is a prefix of a
/// complete one, never a corruption of it.
pub fn harvest(source: &Path, store: &Store) -> Result<(GrainId, HarvestStats), HarvestError> {
    harvest_excluding_files(source, store, &[])
}

/// Harvest while refusing any regular file whose opened descriptor has
/// `refused`'s identity. This is the publish-side entry point: the CLI
/// captures the private seed's identity from the descriptor used to load
/// it, then supplies it here so a later hard link cannot evade path-name
/// nesting checks.
///
/// # Errors
/// The same errors as [`harvest`], plus
/// [`HarvestError::RefusedFileIdentity`] when the protected file is found.
#[doc(hidden)]
pub fn harvest_excluding_file(
    source: &Path,
    store: &Store,
    refused: FileIdentity,
) -> Result<(GrainId, HarvestStats), HarvestError> {
    harvest_excluding_files(source, store, &[refused])
}

/// Harvest while refusing every descriptor identity in `refused`.
/// Duplicate identities are harmless; a match refuses the whole harvest before reading.
///
/// # Errors
/// The errors from [`harvest`], including [`HarvestError::RefusedFileIdentity`].
pub fn harvest_excluding_files(
    source: &Path,
    store: &Store,
    refused: &[FileIdentity],
) -> Result<(GrainId, HarvestStats), HarvestError> {
    let mut stats = HarvestStats::default();
    let root = harvest_tree(source, store, &mut stats, refused)?;
    stats.dirs += 1;
    Ok((root, stats))
}

/// One directory in flight on the nesting worklist: its entry slots in
/// canonical name order, plus the cursor parked on the subdirectory
/// currently being descended into.
struct DirFrame {
    /// This directory's own device, which every child is checked
    /// against for the mount boundary.
    dev: u64,
    slots: Vec<Slot>,
    cursor: usize,
}

struct Slot {
    name: Name,
    kind: SlotKind,
}

enum SlotKind {
    /// Fully classified — a file, a symlink, or a finished subdirectory.
    Ready(EntryKind),
    /// A subdirectory the worklist has not descended into yet. `ino` is
    /// this entry's inode in THIS directory's readdir listing, carried
    /// so the descent can run the same identity tripwire the recursive
    /// walk ran at the same point.
    Sub { path: PathBuf, ino: u64 },
}

impl DirFrame {
    /// The next subdirectory to descend into, leaving the cursor parked
    /// on its slot so [`DirFrame::fill`] knows where the child id goes.
    fn next_sub(&mut self) -> Option<(PathBuf, u64, u64)> {
        loop {
            match self.slots.get(self.cursor) {
                Some(Slot {
                    kind: SlotKind::Sub { path, ino },
                    ..
                }) => return Some((path.clone(), self.dev, *ino)),
                Some(_) => self.cursor = self.cursor.saturating_add(1),
                None => return None,
            }
        }
    }

    /// Land a finished child's id in the parked slot and step past it.
    fn fill(&mut self, child: GrainId) {
        if let Some(slot) = self.slots.get_mut(self.cursor) {
            slot.kind = SlotKind::Ready(EntryKind::Dir { child });
        }
        self.cursor = self.cursor.saturating_add(1);
    }
}

/// Harvest the whole tree under `source`, deepest directories first.
///
/// Directory NESTING is an explicit WORKLIST, not native-stack
/// recursion. How deep a source tree can go is the platform's
/// `PATH_MAX` divided by the entry-name length — about 510 levels on
/// macOS's 1024 with one-byte names, about four times that on Linux's
/// 4096 — and a recursive walk answered the deep end of that range
/// with a stack overflow, which is SIGABRT and not a `HarvestError`.
/// The same shape `granary_core::manifest::validate_dir_tree` carries
/// for the same trees, on the reading side.
///
/// `frame` is always a live directory and `stack` holds only its
/// ancestors, so no arm of the loop can observe an empty worklist.
fn harvest_tree(
    source: &Path,
    store: &Store,
    stats: &mut HarvestStats,
    refused: &[FileIdentity],
) -> Result<GrainId, HarvestError> {
    let mut frame = open_dir(source, None, store, stats, refused)?;
    let mut stack: Vec<DirFrame> = Vec::new();
    loop {
        if let Some((path, dev, ino)) = frame.next_sub() {
            stack.push(frame);
            frame = open_dir(&path, Some((dev, ino)), store, stats, refused)?;
            continue;
        }
        let id = close_dir(frame, store, stats)?;
        match stack.pop() {
            Some(mut parent) => {
                parent.fill(id);
                frame = parent;
            }
            None => return Ok(id),
        }
    }
}

/// Build and store one directory's manifest nodes, once every slot is
/// classified. Returns its root id — the id the parent's `Dir` entry
/// names.
fn close_dir(
    frame: DirFrame,
    store: &Store,
    stats: &mut HarvestStats,
) -> Result<GrainId, HarvestError> {
    let mut entries: Vec<DirEntry> = Vec::with_capacity(frame.slots.len());
    for slot in frame.slots {
        match slot.kind {
            SlotKind::Ready(kind) => entries.push(DirEntry {
                name: slot.name,
                kind,
            }),
            // Unreachable: a frame is closed only once `next_sub` has
            // walked past every slot, and the driver fills each `Sub`
            // as it passes. Reported LOUDLY rather than papered over
            // with a placeholder id — a manifest is consensus bytes,
            // and a silently wrong one is worse than a failed harvest.
            SlotKind::Sub { path, .. } => {
                return Err(HarvestError::ChangedDuringHarvest { path });
            }
        }
    }
    let built = tree::build_dir(&entries)?;
    for (id, bytes) in &built.nodes {
        stats.nodes_total += 1;
        if store.put(id, bytes)? {
            stats.nodes_novel += 1;
        }
    }
    Ok(built.root)
}

/// `expected`: the `(dev, ino)` this directory had in its PARENT's
/// readdir — identity is re-checked before reading so a dir swapped
/// for a symlink between classification and descent is caught
/// (`ChangedDuringHarvest`), not followed. The root call passes None
/// (the user-given path is trusted as given). Residual, documented: an
/// ABA swap-and-restore AROUND the `read_dir` window can still feed an
/// impostor listing — closing it needs fd-based openat traversal (a
/// rustix dependency; recorded as hardening, not yet landed). Harvest
/// assumes a quiescent tree; there is no privilege boundary here
/// (reads run as the user, into the user's own store) — the contract
/// is loud detection where cheap, never silent wrongness.
#[expect(
    clippy::too_many_lines,
    reason = "the root-vs-child NotADirectory split pushed this over \
              the pedantic line count; the TOCTOU walk reads clearer flat than split further"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "read_dir enumerates the harvested source tree itself (the walk's own subject, not \
              the cache/store) — file_type() and ino come straight off the readdir entry, no \
              extra stat, and this function reads nothing through what it names. read_link is \
              reached ONLY inside the symlink arm below, bracketed by pre/post \
              fs::symlink_metadata lstats (lpre/lpost) — a BEST-EFFORT ABA tripwire, not a \
              proof: matching (dev, ino) before and after the read_link catches the entry \
              having ended up DIFFERENT, but not an attacker who renames the original aside, \
              plants a replacement at this name, lets read_link consume the replacement's \
              target, then renames the original BACK before lpost runs — same (dev, ino) both \
              times, replacement content in between. That residual is accepted by this crate's \
              quiescent-source contract (the same trust boundary every other TOCTOU narrowing \
              in this module states, never fully closed). The regular-file arm gets a \
              DIFFERENT, fresh, UNBANNED (not licensed — fs::symlink_metadata is not on this \
              ban list) lstat inside harvest_file itself, not here"
)]
fn open_dir(
    dir: &Path,
    expected: Option<(u64, u64)>,
    store: &Store,
    stats: &mut HarvestStats,
    refused: &[FileIdentity],
) -> Result<DirFrame, HarvestError> {
    let io = |source| HarvestError::Io {
        path: dir.to_owned(),
        source,
    };
    let pre = fs::symlink_metadata(dir).map_err(io)?;
    if !pre.file_type().is_dir() {
        // `expected.is_none()` is the ROOT call: a symlink-to-dir or
        // plain-file source is a stable condition, not a race.
        // `expected.is_some()` is a
        // CHILD whose type moved between this dir's readdir listing
        // and its own descent, which IS a race (ChangedDuringHarvest).
        return Err(if expected.is_none() {
            HarvestError::NotADirectory {
                path: dir.to_owned(),
            }
        } else {
            HarvestError::ChangedDuringHarvest {
                path: dir.to_owned(),
            }
        });
    }
    if let Some((dev, ino)) = expected {
        if pre.dev() != dev {
            return Err(HarvestError::MountBoundary {
                path: dir.to_owned(),
            });
        }
        if pre.ino() != ino {
            return Err(HarvestError::ChangedDuringHarvest {
                path: dir.to_owned(),
            });
        }
    }
    let mut names: Vec<(Vec<u8>, PathBuf, fs::FileType, u64)> = Vec::new();
    for entry in fs::read_dir(dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        // file_type() is free on unix; NEVER follows symlinks.
        let ft = entry.file_type().map_err(io)?;
        names.push((
            entry.file_name().as_bytes().to_vec(),
            entry.path(),
            ft,
            entry.ino(),
        ));
    }
    let post = fs::symlink_metadata(dir).map_err(io)?;
    if !post.file_type().is_dir() || post.dev() != pre.dev() || post.ino() != pre.ino() {
        return Err(HarvestError::ChangedDuringHarvest {
            path: dir.to_owned(),
        });
    }
    // Raw memcmp; unstable is fine — names in one dir are unique.
    names.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut slots: Vec<Slot> = Vec::with_capacity(names.len());
    for (name_bytes, path, ft, ino) in names {
        let name = Name::new(name_bytes).map_err(|e| HarvestError::BadName {
            path: path.clone(),
            why: e.to_string(),
        })?;
        if ft.is_dir() {
            stats.dirs += 1;
            // The descent is the caller's WORKLIST, not this stack:
            // nesting is the one dimension of a source tree with no
            // bound of its own, and recursing here put it on the
            // native stack. Everything else about this entry is
            // classified now, in readdir-sorted order, exactly as
            // before.
            slots.push(Slot {
                name,
                kind: SlotKind::Sub { path, ino },
            });
            continue;
        }
        let kind = if ft.is_symlink() {
            stats.symlinks += 1;
            // Identity around read_link: a symlink cannot be retargeted
            // in place (unlink+recreate changes the ino), so pre/post
            // lstat + ino-vs-readdir closes the swap race here.
            let lpre = fs::symlink_metadata(&path).map_err(|source| HarvestError::Io {
                path: path.clone(),
                source,
            })?;
            if !lpre.file_type().is_symlink() || lpre.ino() != ino {
                return Err(HarvestError::ChangedDuringHarvest { path });
            }
            let target = fs::read_link(&path).map_err(|source| HarvestError::Io {
                path: path.clone(),
                source,
            })?;
            let lpost = fs::symlink_metadata(&path).map_err(|source| HarvestError::Io {
                path: path.clone(),
                source,
            })?;
            if !lpost.file_type().is_symlink()
                || lpost.ino() != lpre.ino()
                || lpost.dev() != lpre.dev()
            {
                return Err(HarvestError::ChangedDuringHarvest { path });
            }
            let target =
                SymlinkTarget::new(target.as_os_str().as_bytes().to_vec()).map_err(|e| {
                    HarvestError::BadSymlink {
                        path: path.clone(),
                        why: e.to_string(),
                    }
                })?;
            EntryKind::Symlink { target }
        } else if ft.is_file() {
            stats.files += 1;
            harvest_file(&path, ino, store, stats, refused)?
        } else {
            return Err(HarvestError::SpecialFile { path });
        };
        slots.push(Slot {
            name,
            kind: SlotKind::Ready(kind),
        });
    }
    Ok(DirFrame {
        dev: pre.dev(),
        slots,
        cursor: 0,
    })
}

/// `ino`: this entry's inode in the parent's readdir listing — the same
/// identity tripwire the dir and symlink arms run: an entry
/// unlink+replaced between readdir and this lstat has a different ino.
///
/// The open goes through [`fsguard::open_regular_read`], not a bare
/// `File::open`: a FIFO
/// swapped in between the caller's classification and this open would
/// BLOCK a bare open, and the harvest thread, forever (`O_RDONLY` on a
/// FIFO with no writer blocks) — the exact wedge class the cache's own
/// structural opens are closed against. `open_regular_read`'s `O_NOFOLLOW` also fails
/// a swapped-to-symlink promptly instead of opening it — the
/// dev/ino identity check below still runs for every OTHER swap this
/// crate's other guards do not cover (a same-type replacement), and
/// harvest's own documented invariant is unaffected either way: this
/// function is only ever reached for an entry the caller already
/// classified as a regular file, never a symlink, which this crate
/// harvests through a separate path.
fn harvest_file(
    path: &Path,
    ino: u64,
    store: &Store,
    stats: &mut HarvestStats,
    refused: &[FileIdentity],
) -> Result<EntryKind, HarvestError> {
    let io = |source| HarvestError::Io {
        path: path.to_owned(),
        source,
    };
    let pre = fs::symlink_metadata(path).map_err(io)?;
    if pre.ino() != ino {
        return Err(HarvestError::ChangedDuringHarvest {
            path: path.to_owned(),
        });
    }
    let exec = pre.permissions().mode() & 0o111 != 0; // any exec bit (git's actual rule)
    let file = fsguard::open_regular_read(path).map_err(io)?;
    // Identity check on the OPEN handle (fstat) vs the pre-read lstat:
    // an entry swapped for a symlink between classification and open
    // has a different (dev, ino) on the handle — immune to the ABA
    // restore-the-path race a post-open path stat would miss.
    let opened = file.metadata().map_err(io)?;
    if !opened.file_type().is_file() || opened.dev() != pre.dev() || opened.ino() != pre.ino() {
        return Err(HarvestError::ChangedDuringHarvest {
            path: path.to_owned(),
        });
    }
    if refused.iter().any(|identity| identity.matches(&opened)) {
        return Err(HarvestError::RefusedFileIdentity {
            path: path.to_owned(),
        });
    }
    let mut refs: Vec<GrainRef> = Vec::new();
    let mut size: u64 = 0;
    for grain in thresh::grains_streaming(&file) {
        let g = grain.map_err(|e| HarvestError::Io {
            path: path.to_owned(),
            source: std::io::Error::other(e.to_string()),
        })?;
        let id = GrainId::of(&g.data);
        stats.grains_total += 1;
        size += g.data.len() as u64;
        stats.bytes_total += g.data.len() as u64;
        if store.put(&id, &g.data)? {
            stats.grains_novel += 1;
            stats.bytes_novel += g.data.len() as u64;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "grain length <= thresh::MAX_GRAIN (2 MiB), far inside u32"
        )]
        refs.push(GrainRef {
            id,
            unpacked_len: g.data.len() as u32,
        });
    }
    // Post-read coherence on the SAME handle (fstat, not a path stat).
    // Residual, documented: a same-length in-place write landing within
    // one mtime tick of a coarse-granularity filesystem passes both
    // checks (quiescent-tree contract — loud detection where cheap).
    let post = file.metadata().map_err(io)?;
    if post.len() != pre.len() || post.modified().ok() != pre.modified().ok() {
        return Err(HarvestError::ChangedDuringHarvest {
            path: path.to_owned(),
        });
    }
    let grains = if refs.len() <= manifest::FILE_INLINE_MAX_REFS as usize {
        FileGrains::Inline(refs)
    } else {
        let built = tree::build_grain_list(&refs)?;
        for (id, bytes) in &built.nodes {
            stats.nodes_total += 1;
            if store.put(id, bytes)? {
                stats.nodes_novel += 1;
            }
        }
        let grain_count = u32::try_from(refs.len()).map_err(|_| HarvestError::TooManyGrains {
            path: path.to_owned(),
        })?;
        FileGrains::Spill {
            grain_count,
            root: built.root,
        }
    };
    Ok(EntryKind::File { exec, size, grains })
}

#[cfg(test)]
mod tests;
