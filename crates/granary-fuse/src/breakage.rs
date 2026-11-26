// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The `conformance-breakage` feature's seven should-fail
//! variants, each changing a compared property.
//! Entirely `#[cfg(feature = "conformance-breakage")]` — see
//! `lib.rs` for the release wall this feature sits behind.
//!
//! **The root fact every siting below answers to.** `ENTRY_TTL` is
//! 60s (`filesystem.rs:63`) and is passed as BOTH `entry_valid` and
//! `attr_valid` on every readdirplus entry, so every child attribute
//! the differential oracle observes comes from the READDIRPLUS
//! reply, never from a separate `lookup`/`getattr` round trip —
//! EXECUTED, aarch64 container: an honest run recorded `readdir=0
//! readdirplus=6`, zero `LOOKUP`s and one root `GETATTR`. That is
//! why `ExecEverywhere`/`MisreportSize` must reach the readdirplus
//! path too — via [`bend_attr`], called at `lookup_entry`,
//! `getattr_attr`, and `filesystem.rs`'s
//! `RealDirPlusSink::offer`, NOT inside [`BreakageDirPlusSink`] here
//! (which never sees a `GranaryFs` to call `bend` on, by design —
//! see that struct's own doc) — and why [`follow_sibling`] has three
//! call sites rather than one (`filesystem.rs`'s `lookup_entry` and
//! `resolve_own_entry`, plus [`BreakageDirPlusSink`] here).

use granary_core::hash::GrainId;
use granary_core::manifest::EntryKind;

use crate::{DirPlusSink, SinkOutcome, list_dir_plus};
use granary_vfs::{Attr, Entry, InodeTable, NodeKind, ReaderError, Snapshot, dir_and_parent};

/// One of the seven should-fail variants a `conformance-breakage` build
/// can arm behind `gran mount --breakage <name>` — each variant below names
/// the compared property it changes and where its fault is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breakage {
    /// content, in `read_bytes` (filesystem.rs).
    TruncateRead,
    /// presence, in the readdirplus sink wrapper.
    OmitEntry,
    /// exec, an `Attr`-level transform via [`bend_attr`].
    ExecEverywhere,
    /// kind, via [`follow_sibling`] at three call sites.
    FollowSymlink,
    /// size, an `Attr`-level transform via [`bend_attr`].
    MisreportSize,
    /// target, in `readlink_bytes` (filesystem.rs).
    MangleSymlinkTarget,
    /// dtype, the zero-nodeid form in the readdirplus sink wrapper.
    DirentTypeLie,
}

impl Breakage {
    /// Every variant, in the order this table defines — the accepted set
    /// [`Self::parse`] checks against and [`Self::name`]'s own round-trip
    /// test walks.
    pub const ALL: [Self; 7] = [
        Self::TruncateRead,
        Self::OmitEntry,
        Self::ExecEverywhere,
        Self::FollowSymlink,
        Self::MisreportSize,
        Self::MangleSymlinkTarget,
        Self::DirentTypeLie,
    ];

    /// The `--breakage <name>` token this variant answers to. The parse is
    /// PORTABLE: unit-testable with no `target_os = "linux"` daemon
    /// anywhere near it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TruncateRead => "truncate-read",
            Self::OmitEntry => "omit-entry",
            Self::ExecEverywhere => "exec-everywhere",
            Self::FollowSymlink => "follow-symlink",
            Self::MisreportSize => "misreport-size",
            Self::MangleSymlinkTarget => "mangle-symlink-target",
            Self::DirentTypeLie => "dirent-type-lie",
        }
    }

    /// Parses a `--breakage` value against [`Self::ALL`]; `None` for
    /// anything else, which `parse_mount` (granary-client) turns into a
    /// refusal naming the accepted set — never a silent default variant.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|variant| variant.name() == name)
    }
}

/// The shared transform for attribute faults. The filesystem's `Bent`
/// construction seam applies it to local and deferred replies before wire
/// conversion. A no-op for other variants and non-file kinds:
/// `ExecEverywhere` and `MisreportSize` apply to regular files only.
pub fn bend_attr(breakage: Breakage, attr: &mut Attr) {
    match breakage {
        Breakage::ExecEverywhere => {
            if attr.kind == NodeKind::File {
                attr.perm = 0o555;
            }
        }
        Breakage::MisreportSize => {
            if attr.kind == NodeKind::File {
                // Upward, never downward: a downward lie also truncates
                // observable content, which would make this variant
                // indistinguishable from `TruncateRead`.
                // `saturating_add`: a file size this
                // close to u64::MAX cannot occur from real content, but
                // this is reachable from any local `ls`/`stat`, and the
                // coding standards forbid a panic reachable from
                // untrusted input — wrapping or saturating either would
                // do; saturating keeps the reported size monotonically
                // "at least as wrong as +1" rather than wrapping to
                // something smaller than the honest value.
                attr.size = attr.size.saturating_add(1);
            }
        }
        Breakage::TruncateRead
        | Breakage::OmitEntry
        | Breakage::FollowSymlink
        | Breakage::MangleSymlinkTarget
        | Breakage::DirentTypeLie => {}
    }
}

/// Substitutes the referent's [`Entry`] for a symlink's when
/// the target is a plain SIBLING name — no `/` byte, so it is one path
/// component resolved in the SAME directory `dir` — that resolves to a
/// regular file. Every other symlink (dangling, absolute,
/// `..`-containing, or resolving to a directory) comes back unchanged,
/// which is what keeps those rows comparing EQUAL under the oracle
/// rather than silently also diverging. Also a no-op for a non-symlink
/// `entry`, defensively — every call site only reaches this on a `Attr`
/// already known to be `Symlink`-kind, but the function does not trust
/// that from its own signature alone.
#[must_use]
pub fn follow_sibling(snapshot: &Snapshot, dir: &GrainId, entry: Entry) -> Entry {
    let EntryKind::Symlink { target } = &entry.kind else {
        return entry;
    };
    let target_bytes = target.as_bytes();
    if target_bytes.contains(&b'/') {
        return entry;
    }
    match snapshot.lookup(dir, target_bytes) {
        Ok(referent) if matches!(referent.kind, EntryKind::File { .. }) => referent,
        _ => entry,
    }
}

/// The cfg'd sink wrapper: sits between [`list_dir_plus`] and the
/// real (or, in tests, a fake) [`DirPlusSink`], applying whichever
/// variant is armed to every offered [`Attr`]. Generic over the inner
/// sink for the same reason `listing.rs`'s own tests are — it makes the
/// credit rules unit-testable over a plain `Vec`-backed fake instead of
/// a real `fuser::ReplyDirectoryPlus`, which nothing in this crate can
/// construct outside `fuser` itself.
///
/// This struct does NOT apply `ExecEverywhere`/
/// `MisreportSize` — it has no `GranaryFs` to call `bend` on, and `bend`
/// is now the only way to mint the `Bent` token `to_file_attr` accepts.
/// Those two are applied downstream, once, by whichever REAL sink
/// finally receives the entry (`filesystem.rs`'s `RealDirPlusSink::
/// offer`). This wrapper still applies its own three: `OmitEntry`,
/// `DirentTypeLie`, and `FollowSymlink`'s substitution — none of those
/// touch `bend`/`Bent` at all, since they change WHICH `Attr` is
/// offered, or intercept before an `Attr` is offered, rather than
/// converting one to a `FileAttr`.
struct BreakageDirPlusSink<'a, S> {
    inner: &'a mut S,
    breakage: Breakage,
    snapshot: &'a Snapshot,
    dir: GrainId,
    /// Credits `list_dir_plus` already took via
    /// `table.lookup` for an entry THIS wrapper's own transform then
    /// made unreachable to the kernel — withheld outright by (2), or
    /// zero-nodeid'd by (7) — that `list_dir_plus` itself never repays,
    /// because from its point of view the entry WAS sent successfully
    /// (`SinkOutcome::Added`). Drained by
    /// [`list_dir_plus_with_breakage`] after the call returns, on both
    /// its `Ok` and its `Err` exit (rule iii).
    withheld: Vec<u64>,
    /// `OmitEntry`: only the FIRST non-dot offer per call is
    /// withheld.
    omitted: bool,
}

impl<S: DirPlusSink> DirPlusSink for BreakageDirPlusSink<'_, S> {
    fn offer(&mut self, mut attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        let is_dot = name == b"." || name == b"..";

        // FollowSymlink in the readdirplus wrapper: the sink sees only the
        // ALREADY-BUILT Attr, not the manifest Entry `list_dir_plus`
        // read it from — so re-resolve `name` under this wrapper's own
        // `dir` and, if it substitutes, recompute the Attr for the
        // referent using THIS entry's own ino/generation (never the
        // referent's).
        if !is_dot
            && self.breakage == Breakage::FollowSymlink
            && attr.kind == NodeKind::Symlink
            && let Ok(entry) = self.snapshot.lookup(&self.dir, name)
        {
            let substituted = follow_sibling(self.snapshot, &self.dir, entry);
            if let Ok(new_attr) = self
                .snapshot
                .attr_for(&substituted, attr.ino, attr.generation)
            {
                attr = new_attr;
            }
        }

        // ExecEverywhere / MisreportSize are NOT applied here:
        // they are applied once, downstream, by
        // `RealDirPlusSink::offer` calling `GranaryFs::bend` — the ONLY
        // constructor of the `Bent` token `to_file_attr` now requires,
        // which this wrapper has no way to mint (it never sees a
        // `GranaryFs`, by design — it is unit-tested here against a
        // plain fake sink with no adapter anywhere near it). Applying
        // `bend_attr` HERE TOO would double the MisreportSize `+1` for
        // every entry that reaches a real sink through this wrapper.

        // (2) OmitEntry: the first non-dot offer is consumed WITHOUT
        // delegating. Nothing else will ever repay this credit (the
        // inner sink never even sees it), so it is recorded
        // unconditionally here.
        if !is_dot && self.breakage == Breakage::OmitEntry && !self.omitted {
            self.omitted = true;
            self.withheld.push(attr.ino);
            return SinkOutcome::Added;
        }

        // (7) DirentTypeLie, the zero-nodeid form: lie about the kind
        // AND zero the ino before delegating. The kernel emits the lied
        // dirent first and only then tries to link it to an inode;
        // `fuse_direntplus_link` returns immediately on a zero nodeid
        // (documented Linux behaviour, verified at v6.12 source), so no
        // inode is instantiated and no attr is cached for this entry —
        // the walker's `lstat` issues a fresh, honest `LOOKUP`.
        let mut zeroed_original_ino = None;
        if !is_dot && self.breakage == Breakage::DirentTypeLie && attr.kind == NodeKind::Dir {
            zeroed_original_ino = Some(attr.ino);
            attr.kind = NodeKind::File;
            attr.ino = 0;
        }

        let outcome = self.inner.offer(attr, name, next);

        // Rule (ii): record the zeroed entry's ORIGINAL credit only when
        // the inner sink actually answered `Added`. On `Full`,
        // `list_dir_plus` already repays that exact credit itself
        // (its own `SinkOutcome::Full => { table.forget(ino, 1); true
        // }` arm) — recording it here too would forget it TWICE, which
        // can reclaim a row a DIFFERENT, still-live `lookup` reference
        // still needs.
        if let Some(original_ino) = zeroed_original_ino
            && outcome == SinkOutcome::Added
        {
            self.withheld.push(original_ino);
        }

        outcome
    }
}

/// Wires the cfg'd sink wrapper over one `list_dir_plus` call and
/// repays its ledger afterward — three credit-repayment rules together:
/// the original nonzero ino is what gets recorded (never the zeroed
/// one), only when the inner sink actually took the entry, and the
/// drain runs on BOTH the `Ok` and the `Err` return so a later failure
/// in the same call cannot leak an earlier entry's credit.
///
/// **The `Err` branch of that third rule is an EQUIVALENT MUTANT on
/// this crate's own test doubles, named rather than chased**:
/// `list_dir_plus`'s own doc already states its failure exit is
/// "currently UNREACHABLE on a successfully-constructed `Snapshot`" —
/// `scan_dir_node` validates counts/separators and `decode_dir_leaf`
/// yields already-validated `Name`s, so nothing this function's own
/// callers can hand it ever drives that branch. Draining unconditionally
/// (not only in the `Ok` arm) is still the CORRECT contract — a defect
/// that reintroduced a leak on that branch would be real — it is only
/// UNIT-TESTABLE today by an `InodeTable`/`Snapshot` pair deliberately
/// built to disagree with each other, which this crate's fixtures do
/// not (and should not) construct. Adding a `#[cfg(test)]` seam to
/// `InodeTable` purely to force that disagreement was considered and
/// REJECTED: it would open a test-only door in a consensus-adjacent
/// type for a branch that cannot fire on any snapshot this codebase can
/// actually build.
///
/// # Errors
///
/// Whatever `list_dir_plus` itself returns; the drain still runs first.
pub fn list_dir_plus_with_breakage<S: DirPlusSink>(
    breakage: Breakage,
    table: &mut InodeTable,
    snapshot: &Snapshot,
    dir_ino: u64,
    offset: u64,
    sink: &mut S,
) -> Result<(), ReaderError> {
    let (dir, _parent) = dir_and_parent(table, snapshot, dir_ino)?;
    let mut wrapped = BreakageDirPlusSink {
        inner: sink,
        breakage,
        snapshot,
        dir,
        withheld: Vec::new(),
        omitted: false,
    };
    let result = list_dir_plus(table, snapshot, dir_ino, offset, &mut wrapped);
    let withheld = std::mem::take(&mut wrapped.withheld);
    for ino in withheld {
        table.forget(ino, 1);
    }
    result
}

#[cfg(test)]
mod tests;
