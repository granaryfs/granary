// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The directory operation's testable core: descent, the name-length
//! rule, and `readdir`/`readdirplus` behind a SINK.
//!
//! `fuser::ReplyDirectory` and `fuser::ReplyDirectoryPlus` have no public
//! constructor outside `fuser`, so nothing that calls their real `add`
//! could ever run in an in-process test. Everything below is written
//! against a small [`DirSink`]/[`DirPlusSink`] abstraction instead: the
//! adapter implements it over the real reply types, and the tests implement it
//! over a capacity-bounded `Vec` — which is what makes the credit rules
//! (trap T2), the plain-`readdir` non-credit rule (trap T3), the
//! parent-vs-child descent (trap T4) and the cookie pass-through (trap T9)
//! testable at all.

use granary_core::manifest::{EntryKind, Name};

use granary_vfs::{
    Attr, Entry, InodeTable, NodeKind, PathKey, ReaderError, Snapshot, dir_and_parent,
};

const DOT: &[u8] = b".";
const DOT_DOT: &[u8] = b"..";

/// The name-length refusal, decided BEFORE the snapshot is consulted at
/// all. The kernel's own component cap is kernel-dependent: up to v6.14
/// the kernel caps a FUSE name at 1024 bytes (`FUSE_NAME_MAX`); from
/// v6.15 it is `PATH_MAX - 1` once `FUSE_MAX_PAGES` is negotiated with
/// `max_pages > 1`, which fuser always requests. So a component of
/// 256..=1024 bytes REACHES the daemon on every kernel, and longer ones
/// do on newer kernels, even though the manifest format caps a stored name at
/// [`granary_core::manifest::name::NAME_MAX`] (255) bytes. Answering
/// `ENOENT` for such a name would claim it is merely ABSENT, when in fact
/// no name that long could ever have been stored — `ENOENT` conflates
/// "not present" with "not representable". `ENAMETOOLONG` says the true
/// thing, and says it before the reader is asked anything.
///
/// # Errors
///
/// Returns [`fuser::Errno::ENAMETOOLONG`] for a component longer than
/// `NAME_MAX` (255) bytes.
pub fn check_name_length(name: &[u8]) -> Result<(), fuser::Errno> {
    if name.len() > granary_core::manifest::name::NAME_MAX {
        Err(fuser::Errno::ENAMETOOLONG)
    } else {
        Ok(())
    }
}

/// Maps a manifest entry's kind to the FUSE directory-entry type. Total
/// over all five `EntryKind` variants — unlike [`Snapshot::attr_for`],
/// which refuses two of them. `Snapshot::new` now refuses to index any
/// manifest carrying a FIFO or socket entry at all — a decode-time refusal,
/// `SnapshotError::ReservedEntry` — so this function's Fifo/Socket arms are
/// unreachable on a successfully-constructed `Snapshot`. The same
/// construction-time family also refuses a `Symlink` entry whose target
/// this mount's FUSE `readlink` reply cannot carry
/// (`SnapshotError::UnrepresentableSymlinkTarget`), so `ReservedEntry` is
/// not the only entry-content refusal `Snapshot::new` performs — but
/// totality over `EntryKind` stays a virtue rather than dead weight to
/// trim: a NEW `EntryKind` variant must fail to compile here, not silently
/// fall through.
#[must_use]
pub fn entry_file_type(kind: &EntryKind) -> fuser::FileType {
    match kind {
        EntryKind::Dir { .. } => fuser::FileType::Directory,
        EntryKind::File { .. } => fuser::FileType::RegularFile,
        EntryKind::Symlink { .. } => fuser::FileType::Symlink,
        EntryKind::Fifo => fuser::FileType::NamedPipe,
        EntryKind::Socket => fuser::FileType::Socket,
    }
}

/// The manifest-entry-kind to allocatable-inode-kind mapping. `None` for
/// the two kinds `InodeTable`/`Attr` cannot represent at all (Fifo,
/// Socket) — see [`list_dir_plus`]'s doc for what happens to such an
/// entry.
fn allocatable_kind(kind: &EntryKind) -> Option<NodeKind> {
    match kind {
        EntryKind::Dir { .. } => Some(NodeKind::Dir),
        EntryKind::File { .. } => Some(NodeKind::File),
        EntryKind::Symlink { .. } => Some(NodeKind::Symlink),
        EntryKind::Fifo | EntryKind::Socket => None,
    }
}

/// A `Name` used only to satisfy [`granary_vfs::Entry`]'s shape when building an
/// `Attr` for a synthesised `.`/`..` entry, which has no real manifest
/// name to carry. Verified (by inspection, and by this module's own
/// mutation pass) that `Snapshot::attr_for` reads only `entry.kind` — never
/// `entry.name` or `entry.leaf` — so the exact bytes here are inert. Any
/// name that passes [`Name::new`] does; `"."`/`".."` themselves do not
/// (the format refuses them), which is exactly why a placeholder is needed here
/// and nowhere else in this file.
fn placeholder_name() -> Result<Name, ReaderError> {
    Name::new(b"dot".to_vec()).map_err(|_| ReaderError::Inconsistent)
}

/// Whether a directory-listing sink accepted the offered entry.
///
/// Deliberately not a bare `bool`: `fuser::ReplyDirectory::add` is
/// `#[must_use]` and `fuser::ReplyDirectoryPlus::add` is NOT — two
/// different signatures for the same idea is exactly the shape a
/// copy-paste stops checking, and `SinkOutcome::Full` cannot be silently
/// ignored the way a discarded `true` can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkOutcome {
    Added,
    Full,
}

/// The sink for plain `readdir`. The adapter implements this over
/// `fuser::ReplyDirectory`; tests in this module implement it over a
/// capacity-bounded `Vec`.
pub trait DirSink {
    /// Offers one entry. `ino` is `0` when the path has no allocated
    /// inode row yet — see [`list_dir`]'s doc for why plain `readdir`
    /// reports it best-effort rather than allocating one.
    fn offer(&mut self, ino: u64, kind: fuser::FileType, name: &[u8], next: u64) -> SinkOutcome;
}

/// The sink for `readdirplus`. The adapter implements this over
/// `fuser::ReplyDirectoryPlus`; tests in this module implement it over a
/// capacity-bounded `Vec`.
///
/// Takes the entry's full [`Attr`] — which already carries `ino` — rather
/// than a separate `ino` parameter. `ReplyDirectoryPlus::add`'s wire
/// encoding reads `attr.ino`, NOT its own `ino` argument (that argument is
/// `#[allow(unused)]` in `fuser`'s own source, with a comment saying so): a
/// caller with exactly one authoritative value has nothing left to
/// disagree with itself about.
pub trait DirPlusSink {
    fn offer(&mut self, attr: Attr, name: &[u8], next: u64) -> SinkOutcome;

    /// Offers one entry with the host time its attributes report. A sink that
    /// reports no times ignores it.
    fn offer_timed(
        &mut self,
        attr: Attr,
        _time: std::time::SystemTime,
        name: &[u8],
        next: u64,
    ) -> SinkOutcome {
        self.offer(attr, name, next)
    }
}

/// Fills `sink` for plain `readdir`, starting at `offset`.
///
/// Takes NO lookup credits at all — plain `READDIR` creates no kernel
/// reference (trap T3) — and allocates no row in `table` for an entry that
/// has none: a row created at `nlookup == 0` with no open handle can never
/// be reclaimed, because no FORGET will ever arrive for a reference nobody
/// took. `d_ino` is therefore best-effort: PEEKED from the table if the
/// path already has a row (from an earlier `lookup`), reported as `0`
/// (unknown) otherwise — a `d_ino` of 0 is licence for the kernel to `stat`
/// the entry itself rather than trust it.
///
/// This path is unreachable in production under this mount's own
/// capability negotiation (trap T3: `init` requests `FUSE_DO_READDIRPLUS`
/// and never `FUSE_READDIRPLUS_AUTO`, so the kernel uses READDIRPLUS
/// unconditionally); it remains implemented because the kernel falls back
/// to it if a READDIRPLUS is ever answered `ENOSYS`.
///
/// # Errors
///
/// Returns [`ReaderError`] if `dir_ino` does not resolve to a directory,
/// or if the underlying snapshot walk disagrees with itself.
pub fn list_dir<S: DirSink>(
    table: &InodeTable,
    snapshot: &Snapshot,
    dir_ino: u64,
    offset: u64,
    sink: &mut S,
) -> Result<(), ReaderError> {
    let (dir, parent) = dir_and_parent(table, snapshot, dir_ino)?;
    let (path, _, _) = table.resolve(dir_ino)?;
    let dir_path: PathKey = path.clone();
    let mut parent_path: PathKey = dir_path.clone();
    parent_path.pop();

    snapshot.readdir(&dir, &parent, offset, |entry| {
        let child_path: PathKey = if entry.name == DOT {
            dir_path.clone()
        } else if entry.name == DOT_DOT {
            parent_path.clone()
        } else {
            let mut child = dir_path.clone();
            child.push(entry.name.clone());
            child
        };
        let ino = table.peek(&child_path).unwrap_or(0);
        let file_type = entry_file_type(&entry.kind);
        match sink.offer(ino, file_type, &entry.name, entry.next) {
            SinkOutcome::Added => false,
            SinkOutcome::Full => true,
        }
    })
}

/// Fills `sink` for `readdirplus`, starting at `offset`.
///
/// The credit rule, exactly: `.` and `..` cost nothing — the kernel takes
/// no dentry reference for either name (trap T2), regardless of what `ino`
/// they carry on the wire. Every OTHER entry is registered through
/// `table.lookup`, which credits `nlookup` EAGERLY as part of allocating
/// or re-finding its row; if the sink then reports the buffer FULL, that
/// entry was never sent and no FORGET will ever repay the credit just
/// taken for it, so the one credit is repaid immediately with
/// `InodeTable::forget(ino, 1)` — which already reclaims at zero. There is
/// deliberately no rollback ledger: a FULL reverses exactly one credit,
/// and a general mechanism for a problem this narrow is how a bounded leak
/// turns into fd invalidation.
///
/// A FIFO or socket entry cannot be represented here: `ReplyDirectoryPlus::add`
/// requires a full attribute for every entry it carries — there is no
/// partial/plain fallback within one PLUS reply — and `Snapshot::attr_for`
/// structurally refuses the two reserved kinds (`ReaderError::UnsupportedEntry`).
/// That is resolved at the SOURCE rather than here: `Snapshot::new`
/// refuses to index any manifest that carries a FIFO or socket entry at all
/// (`SnapshotError::ReservedEntry`), so no successfully-constructed
/// `Snapshot` can ever hand this function a `readdir` emission of that kind
/// — the branch below is unreachable on any snapshot this function's own
/// callers can obtain. It stays anyway, as defence in depth: if that
/// construction-time gate ever regresses, this fails the WHOLE `readdirplus`
/// call (`ReaderError::UnsupportedEntry`) rather than silently omitting the
/// entry.
/// (`ReservedEntry` is not the only entry-content refusal `Snapshot::new`
/// performs — an over-length symlink target is refused the same way,
/// `SnapshotError::UnrepresentableSymlinkTarget` — but that refusal is
/// unrelated to the PLUS-reply representability argument above: a
/// `Symlink` entry always gets a full attribute from `Snapshot::attr_for`.)
///
/// # Errors
///
/// Returns [`ReaderError`] if `dir_ino` does not resolve to a directory, if
/// the underlying walk, lookup, or attribute construction disagrees with
/// itself, or if a FIFO/socket entry reaches this function despite the
/// construction-time gate above (unreachable on a successfully-constructed
/// `Snapshot`; see this function's doc).
pub fn list_dir_plus<S: DirPlusSink>(
    table: &mut InodeTable,
    snapshot: &Snapshot,
    dir_ino: u64,
    offset: u64,
    sink: &mut S,
) -> Result<(), ReaderError> {
    let (dir, parent) = dir_and_parent(table, snapshot, dir_ino)?;
    let (path, _, _) = table.resolve(dir_ino)?;
    let dir_path: PathKey = path.clone();
    // No root special case: the root's recorded path is empty and stays
    // empty (`lookup` returns the existing row rather than allocating,
    // `forget` returns early for the root, and `next` only ever increases
    // above it), so `pop()` on it is a no-op and both arms produced the
    // same value. `list_dir` above already writes it this way.
    let mut parent_peek_path: PathKey = dir_path.clone();
    parent_peek_path.pop();

    let mut failure: Option<ReaderError> = None;
    snapshot.readdir(&dir, &parent, offset, |entry| {
        let is_dot = entry.name == DOT;
        let is_dot_dot = entry.name == DOT_DOT;

        if is_dot || is_dot_dot {
            let ino = if is_dot {
                dir_ino
            } else {
                table.peek(&parent_peek_path).unwrap_or(0)
            };
            let name = match placeholder_name() {
                Ok(name) => name,
                Err(error) => {
                    failure = Some(error);
                    return true;
                }
            };
            let fabricated = Entry {
                name,
                kind: entry.kind.clone(),
                leaf: dir,
            };
            let attr = match snapshot.attr_for(&fabricated, ino, table.generation()) {
                Ok(attr) => attr,
                Err(error) => {
                    failure = Some(error);
                    return true;
                }
            };
            // No credit was ever taken for a dot entry, so there is
            // nothing to repay on FULL — just stop.
            return match sink.offer(attr, &entry.name, entry.next) {
                SinkOutcome::Added => false,
                SinkOutcome::Full => true,
            };
        }

        let Some(node_kind) = allocatable_kind(&entry.kind) else {
            // FIFO/Socket: unreachable-by-construction (`Snapshot::new` now
            // refuses any manifest carrying one). Kept as defence
            // in depth: fail the WHOLE operation loudly rather than skip
            // the entry silently, so a regression in the construction gate
            // cannot silently hide the entry from a listing.
            // See the function doc.
            failure = Some(ReaderError::UnsupportedEntry);
            return true;
        };
        let mut child_path = dir_path.clone();
        child_path.push(entry.name.clone());
        let (ino, generation) = match table.lookup(child_path, dir, node_kind) {
            Ok(pair) => pair,
            Err(error) => {
                failure = Some(error);
                return true;
            }
        };
        let Ok(name) = Name::new(entry.name.clone()) else {
            // A name `Snapshot::readdir` just emitted failing the format's
            // validation disagrees with the caller's completed proof.
            table.forget(ino, 1);
            failure = Some(ReaderError::Inconsistent);
            return true;
        };
        let fabricated = Entry {
            name,
            kind: entry.kind.clone(),
            leaf: dir,
        };
        let attr = match snapshot.attr_for(&fabricated, ino, generation) {
            Ok(attr) => attr,
            Err(error) => {
                // `node_kind` already excluded the only kinds `attr_for`
                // refuses, so this should not happen — but if `Snapshot`
                // ever disagrees with itself, the credit just taken must
                // still be repaid: this entry will not be sent either.
                table.forget(ino, 1);
                failure = Some(error);
                return true;
            }
        };
        match sink.offer(attr, &entry.name, entry.next) {
            SinkOutcome::Added => false,
            SinkOutcome::Full => {
                table.forget(ino, 1);
                true
            }
        }
    })?;

    // OBLIGATION THIS PLACES ON THE CALLER: every entry already
    // OFFERED to `sink` before this exit was credited via `table.lookup`
    // above, and NONE of those credits gets repaid here — only a
    // sink-rejected entry's credit is (see the FULL arm above). If the
    // caller answers this `Err` with `reply.error()`, the kernel discards
    // the whole accumulated buffer and never sends a FORGET for any of
    // those entries, permanently pinning their inode rows. The caller must
    // instead send `reply.ok()` with whatever was accumulated: the credits
    // are then legitimate (the kernel resumes from the last cookie), and
    // `error()` is safe ONLY when nothing was offered yet. Deliberately
    // not a rollback ledger — same reasoning as the FULL-credit repayment
    // above: a general unwind mechanism for a problem this narrow is how a
    // bounded leak turns into fd invalidation. This exit is currently
    // UNREACHABLE on a successfully-constructed `Snapshot` (`scan_dir_node`
    // validates counts/separators, `decode_dir_leaf` yields validated
    // `Name`s), so the obligation is latent — it goes live the moment a
    // caller and an indexed `Snapshot` ever disagree with each other.
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
