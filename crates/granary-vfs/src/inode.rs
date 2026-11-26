// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-path inode identity and kernel reference accounting.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use granary_core::hash::GrainId;

use crate::{NodeKind, ReaderError};

/// The path a mount uses as an inode's identity: the sequence of
/// directory-entry names from the manifest root. Owned bytes, because
/// names are arbitrary bytes and the map outlives any borrow of a
/// decoded node.
pub type PathKey = Vec<Vec<u8>>;

#[derive(Debug)]
pub struct InodeTable {
    by_path: BTreeMap<PathKey, u64>,
    by_ino: BTreeMap<u64, InodeEntry>,
    /// Lazy monotonic allocator. NEVER wraps and never reuses without a
    /// generation bump — the kernel cannot detect same-generation reuse
    /// for a different object.
    next: u64,
    generation: u64,
    /// The adapter's root inode number, supplied at construction. Every
    /// root comparison reads this rather than a constant, because the
    /// number is the host protocol's and the engine only owns the rule
    /// that the root is never reclaimed.
    root_ino: u64,
}

#[derive(Debug)]
struct InodeEntry {
    path: PathKey,
    /// The B-tree root of the directory this path's entry lives IN — the
    /// PARENT's node, not this path's own. For the ROOT inode — whichever
    /// number the adapter supplied — the two coincide, because the root is
    /// its own parent; for every other inode they do not, and an adapter
    /// that resolves an inode and then lists `dir` would list the parent's
    /// entries. Listing a directory means descending to its own node first.
    dir: GrainId,
    kind: NodeKind,
    /// The kernel's lookup count. `FORGET` carries the amount to
    /// subtract; `BATCH_FORGET` fans out to the same path.
    nlookup: u64,
    /// Open file handles. An inode with a live handle is NOT reclaimable
    /// even at `nlookup == 0` — that is the no-fd-invalidation property.
    handles: u32,
}

impl InodeTable {
    /// Creates a table whose permanent root is `root_ino`.
    ///
    /// `root_ino` is the ADAPTER's number, not the engine's: FUSE fixes the
    /// root at 1, APFS and ext4 use 2, and NTFS's root is MFT record 5. The
    /// engine owns the invariant that the root is permanent and is never
    /// reclaimed; it does not own the number. An engine-side constant here
    /// would be a host's value wearing a neutral name — identity VALUES
    /// are adapter inputs, and the algorithm over them is the engine's.
    ///
    /// # Domain
    ///
    /// `root_ino` must be **non-zero** and must leave allocation space
    /// above it. Zero is reserved: [`InodeTable::peek`] returns `Option`
    /// and `listing.rs` renders a miss as the wire value `0`, so a root at
    /// 0 would be indistinguishable from "no row allocated" in a `readdir`
    /// reply. A value at the top of the range leaves `next` with nothing to
    /// hand out and every `lookup` returns
    /// [`ReaderError::InodeNumberExhausted`].
    ///
    /// Both are adapter-authored constants rather than parsed input, so
    /// this constructor is infallible and states the domain instead of
    /// validating it — but `next` is `saturating_add` and not `checked_add`
    /// **deliberately**, and that is the one place the choice matters: with
    /// an out-of-domain `root_ino` the table then allocates nothing, rather
    /// than wrapping `next` onto the root row and handing a second object
    /// the root's identity.
    ///
    /// # A known hazard, stated because it is not fixed
    ///
    /// `generation` and `root_ino` are adjacent bare `u64`s, so transposing
    /// them compiles. `the_root_number_is_the_argument_and_not_a_constant`
    /// covers the one site that passes a distinguishable pair; it does
    /// **not** cover a transposition anywhere else, and no other test in
    /// this crate can tell a wrong `root_ino` from the right one, because
    /// every other site legitimately passes the FUSE value for both. A
    /// newtype would restore the compiler's check; the decision was
    /// deferred to the point where this module moved to its own crate
    /// and its public surface was curated. That point has now arrived,
    /// unchanged: this parameter is curated-root API for adapters
    /// outside this workspace as of this crate's first commit, and the
    /// newtype remains undone.
    #[must_use]
    pub fn new(root: GrainId, generation: u64, root_ino: u64) -> Self {
        let root_path = PathKey::new();
        let root_entry = InodeEntry {
            path: root_path.clone(),
            dir: root,
            kind: NodeKind::Dir,
            nlookup: 1,
            handles: 0,
        };
        Self {
            by_path: [(root_path, root_ino)].into_iter().collect(),
            by_ino: [(root_ino, root_entry)].into_iter().collect(),
            next: root_ino.saturating_add(1),
            generation,
            root_ino,
        }
    }

    /// Remaining monotonically allocated identities; the terminal value is reserved.
    #[must_use]
    pub const fn remaining_inodes(&self) -> u64 {
        u64::MAX.saturating_sub(self.next)
    }

    /// The root inode number this table was built with.
    #[must_use]
    pub const fn root_ino(&self) -> u64 {
        self.root_ino
    }

    /// Registers one kernel lookup, allocating a per-path inode on a miss.
    ///
    /// # Errors
    ///
    /// Returns a hard error if the lookup count or monotonic inode space is
    /// exhausted.
    pub fn lookup(
        &mut self,
        path: PathKey,
        dir: GrainId,
        kind: NodeKind,
    ) -> Result<(u64, u64), ReaderError> {
        if let Some(ino) = self.by_path.get(&path).copied() {
            let entry = self.by_ino.get_mut(&ino).ok_or(ReaderError::Inconsistent)?;
            entry.nlookup = entry
                .nlookup
                .checked_add(1)
                .ok_or(ReaderError::LookupCountOverflow)?;
            return Ok((ino, self.generation));
        }
        let ino = self.next;
        let successor = ino
            .checked_add(1)
            .ok_or(ReaderError::InodeNumberExhausted)?;
        self.next = successor;
        self.by_path.insert(path.clone(), ino);
        self.by_ino.insert(
            ino,
            InodeEntry {
                path,
                dir,
                kind,
                nlookup: 1,
                handles: 0,
            },
        );
        Ok((ino, self.generation))
    }

    /// Returns the path, resident directory node, and type recorded for an
    /// inode.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] if the inode is unknown.
    pub fn resolve(&self, ino: u64) -> Result<(&PathKey, GrainId, NodeKind), ReaderError> {
        self.by_ino
            .get(&ino)
            .map(|entry| (&entry.path, entry.dir, entry.kind))
            .ok_or(ReaderError::Inconsistent)
    }

    /// Reads the inode number already allocated for `path`, WITHOUT
    /// allocating one and without touching `nlookup`. Returns `None` if no
    /// row exists yet for this path.
    ///
    /// This is the read used by plain `readdir`'s best-effort `d_ino`:
    /// plain `READDIR` takes no kernel reference (trap T3), so answering
    /// it must never allocate a row that no FORGET will ever arrive to
    /// reclaim.
    #[must_use]
    pub fn peek(&self, path: &PathKey) -> Option<u64> {
        self.by_path.get(path).copied()
    }

    /// The mount-wide generation stamp every inode this table hands out
    /// shares. `lookup` always returns `self.generation` unchanged — it is
    /// a per-MOUNT constant, not a per-inode counter — so a caller that
    /// needs a `Generation` for an inode it already knows without
    /// re-crediting `nlookup` (readdirplus's synthesised `.`/`..`)
    /// can read it here instead of calling `lookup` again.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The number of resident inode rows.
    ///
    /// Unconditionally public so that this table can be observed from
    /// outside the crate that owns it: this module lives in a separate
    /// engine crate, and its observers — the FUSE mechanism suite, which
    /// watches the count on a live daemon to assert that a listing
    /// operation does not grow the table without bound — stay in the
    /// adapter. A `#[cfg(test)] pub(crate)` item is invisible
    /// across that boundary twice over: `pub(crate)` is `E0603`, and a
    /// `cfg(test)` item does not exist in a dependency build at all.
    ///
    /// Every caller today is test code, and that is expected — the count
    /// is an observable the engine OFFERS, not one it requires anyone to
    /// read.
    #[must_use]
    pub fn resident_count(&self) -> usize {
        self.by_ino.len()
    }

    /// Check allocation and lookup capacity before capturing creation.
    /// # Errors
    /// Monotonic inode or lookup-credit exhaustion.
    pub fn preflight_lookup(&self, path: &PathKey) -> Result<(), ReaderError> {
        if let Some(ino) = self.by_path.get(path) {
            self.by_ino
                .get(ino)
                .ok_or(ReaderError::Inconsistent)?
                .nlookup
                .checked_add(1)
                .ok_or(ReaderError::LookupCountOverflow)?;
        } else {
            self.next
                .checked_add(1)
                .ok_or(ReaderError::InodeNumberExhausted)?;
        }
        Ok(())
    }

    /// Remove name associations while preserving lookup and handle identities.
    /// Returns the associations removed: exactly the inodes attached at or
    /// under `path`, each with the path it was attached at. An inode detached
    /// earlier has no association left, so it is never returned again.
    pub fn detach_path(&mut self, path: &PathKey) -> Vec<(PathKey, u64)> {
        let mut removed = Vec::new();
        self.by_path.retain(|name, ino| {
            let keep = !name.starts_with(path);
            if !keep {
                removed.push((name.clone(), *ino));
            }
            keep
        });
        removed
    }

    /// Relocate referenced descendants and detach a displaced destination.
    /// The caller validates namespace types and cycles before journal capture.
    pub fn move_path(&mut self, from: &PathKey, to: &PathKey) {
        let moved: Vec<_> = self
            .by_path
            .iter()
            .filter(|(path, _)| path.starts_with(from))
            .map(|(path, ino)| (path.clone(), *ino))
            .collect();
        self.detach_path(to);
        for (old, ino) in moved {
            let mut new = to.clone();
            new.extend(old.iter().skip(from.len()).cloned());
            self.by_path.remove(&old);
            if let Some(entry) = self.by_ino.get_mut(&ino) {
                entry.path.clone_from(&new);
            }
            self.by_path.insert(new, ino);
        }
    }

    /// Applies a kernel `FORGET` notification and reclaims an unreferenced
    /// non-root inode.
    pub fn forget(&mut self, ino: u64, nlookup: u64) {
        if ino == self.root_ino {
            return;
        }
        let reclaim = if let Some(entry) = self.by_ino.get_mut(&ino) {
            entry.nlookup = entry.nlookup.saturating_sub(nlookup);
            entry.nlookup == 0 && entry.handles == 0
        } else {
            false
        };
        if reclaim {
            self.reclaim(ino);
        }
    }

    /// Applies a list of kernel forget notifications in order.
    pub fn batch_forget(&mut self, forgets: &[(u64, u64)]) {
        for &(ino, nlookup) in forgets {
            self.forget(ino, nlookup);
        }
    }

    /// Whether this resident inode still owns its namespace association.
    #[must_use]
    pub fn attached(&self, ino: u64) -> bool {
        self.by_ino
            .get(&ino)
            .is_some_and(|entry| self.by_path.get(&entry.path) == Some(&ino))
    }

    /// Check the inode hold before acquiring a backend resource.
    /// # Errors
    /// Unknown inode or handle count exhaustion.
    pub fn preflight_open(&self, ino: u64) -> Result<(), ReaderError> {
        self.by_ino
            .get(&ino)
            .ok_or(ReaderError::Inconsistent)?
            .handles
            .checked_add(1)
            .ok_or(ReaderError::HandleCountOverflow)?;
        Ok(())
    }

    /// Registers an open handle for an inode.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] if the inode is unknown, or
    /// [`ReaderError::HandleCountOverflow`] if its handle count is exhausted.
    pub fn open(&mut self, ino: u64) -> Result<(), ReaderError> {
        let entry = self.by_ino.get_mut(&ino).ok_or(ReaderError::Inconsistent)?;
        entry.handles = entry
            .handles
            .checked_add(1)
            .ok_or(ReaderError::HandleCountOverflow)?;
        Ok(())
    }

    /// Releases an open handle for an inode.
    pub fn release(&mut self, ino: u64) {
        let reclaim = if let Some(entry) = self.by_ino.get_mut(&ino) {
            entry.handles = entry.handles.saturating_sub(1);
            entry.nlookup == 0 && entry.handles == 0
        } else {
            false
        };
        if reclaim {
            self.reclaim(ino);
        }
    }

    fn reclaim(&mut self, ino: u64) {
        if ino == self.root_ino {
            return;
        }
        if let Some(entry) = self.by_ino.remove(&ino)
            && self.by_path.get(&entry.path) == Some(&ino)
        {
            self.by_path.remove(&entry.path);
        }
    }
}

#[cfg(test)]
mod tests;
