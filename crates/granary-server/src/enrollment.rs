// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client enrollment on disk: the server's reader of the enrollment set and
//! the local verbs that write it.
//!
//! The enrollment set’s bytes are encoded by
//! [`granary_core::enrollment`]. They live in one file, `ENROLLMENT`, in a
//! directory that passes the protection rule of [`crate::protected_dir`]:
//! only the directory's owner or root can change anything there, so the
//! file is the operator's statement of who is enrolled.
//!
//! - **The reader** ([`EnrollmentReader`]) answers one question per
//!   admission: is this client-SPKI digest enrolled, to which principal and
//!   tenant? It has three answers, never two: enrolled, absent, or
//!   unavailable with a reason. An unreadable, corrupt, oversize or
//!   unprotected set is never read as an empty one.
//! - **The verbs** ([`mint`], [`attach`], [`revoke`], [`retire`]) change
//!   the set under an exclusive lock on the directory and replace the file atomically: a
//!   temporary written and synced, renamed over the name, the directory
//!   synced. A verb returns only after that directory sync, so a lookup
//!   that begins after it returns sees the change. [`list`] reads the set
//!   as the reader does, with no lock and nothing created: the rename makes
//!   each read see one whole file.
//! - **The command line** ([`run_command_line`]) is the verbs' argv form,
//!   which the `granary-server` binary runs when its first argument is
//!   `enrollment`.
//!
//! Both sides read the file the same way ([`read_set`]): open with
//! `O_NOFOLLOW | O_NONBLOCK` on the held directory descriptor, judge the
//! opened inode by `fstat` against the file rule, refuse a size above
//! [`ENCODED_MAX`] before reading, read exactly the size `fstat` gave, and
//! decode strictly.

mod cli;
mod reader;
mod verbs;

use std::fs::File;
use std::io;
use std::sync::Arc;

use granary_core::enrollment::{ENCODED_MAX, EnrollmentSet, SetDecodeError, decode_set};

use crate::protected_dir::{DirOps, FileRuleBroken, Stat, is_link_refusal, judge_file};

pub use cli::{EXIT_IO_FAILED, EXIT_REFUSED, EXIT_USAGE, EXIT_VERB_DONE, run_command_line};
pub use reader::{
    EnrollmentReader, EnrollmentSnapshot, LOOKUP_DEADLINE, Lookup, ReaderStartError,
    SnapshotCounters, SnapshotState,
};
pub use verbs::{
    CredentialError, ListReport, VerbError, VerbOptions, VerbRefusal, attach, list, mint,
    resolve_credential, retire, revoke,
};

/// The set's file name in the enrollment directory.
pub(crate) const SET_NAME: &str = "ENROLLMENT";
/// The verbs' temporary, renamed over [`SET_NAME`].
pub(crate) const TEMP_NAME: &str = "ENROLLMENT.tmp";

/// Why a lookup could not answer enrolled or absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnavailableReason {
    /// No `ENROLLMENT` file: no principal has been minted yet, or the file
    /// was lost.
    Missing,
    /// The file or the directory could not be read (an I/O error, or a
    /// read that disagreed with the file's size). Retried on the next
    /// lookup.
    Unreadable,
    /// The file fails the file rule: not a regular file, another owner, or
    /// group or other write.
    Unprotected,
    /// The file is larger than the format's largest legal set.
    Oversize,
    /// The file is not a valid set.
    Corrupt,
    /// The configured path does not name the directory the server checked
    /// at startup. When a `stat` of the path shows anything else there
    /// (another directory, or not a directory), this lasts until the server
    /// restarts; when the `stat` fails (the
    /// path missing included), it holds for that refresh only, and a later
    /// refresh looks again.
    Directory,
    /// The file system did not answer within [`LOOKUP_DEADLINE`].
    Stalled,
}

impl UnavailableReason {
    /// The reason's name, as status and logs print it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::Unprotected => "unprotected",
            Self::Oversize => "oversize",
            Self::Corrupt => "corrupt",
            Self::Directory => "directory",
            Self::Stalled => "stalled",
        }
    }
}

impl std::fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A file's identity, as the reader compares it: an inode (device and
/// number), its mode and owner, and the size, modification and change
/// times.
///
/// The mode and owner are compared directly, not through the change time
/// that a `chmod` or `chown` bumps: an `unprotected` verdict is a verdict
/// about them, and two such changes inside one tick of the filesystem's
/// clock leave the change time as it was.
///
/// The verbs publish only by rename, which always puts a new inode at the
/// name, so every change they make is a new identity. Rewriting the file
/// in place is outside their contract. `ctime` narrows the window for such
/// an edit, since no `utimes` call can set it, but does not close it: a
/// change time is only as fine as the filesystem keeps it (whole seconds on
/// ext2 or ext3 with small inodes, a kernel clock tick elsewhere), so an
/// in-place rewrite that keeps the size and the modification time within
/// one tick can go unseen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Identity {
    dev: i128,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Identity {
    pub(crate) const fn of(stat: &Stat) -> Self {
        Self {
            dev: stat.dev,
            ino: stat.ino,
            mode: stat.mode,
            uid: stat.uid,
            gid: stat.gid,
            size: stat.size,
            mtime: stat.mtime,
            ctime: stat.ctime,
        }
    }
}

/// What a file's content was judged to be. Each is a property of the bytes
/// and the inode, so it is cached against the file's [`Identity`].
#[derive(Debug, Clone)]
pub(crate) enum Verdict {
    Set(Arc<EnrollmentSet>),
    Unprotected(FileRuleBroken),
    Oversize { size: i64 },
    Corrupt(SetDecodeError),
}

impl Verdict {
    /// The set, or the reason a lookup answers unavailable.
    pub(crate) const fn outcome(&self) -> Result<&Arc<EnrollmentSet>, UnavailableReason> {
        match self {
            Self::Set(set) => Ok(set),
            Self::Unprotected(_) => Err(UnavailableReason::Unprotected),
            Self::Oversize { .. } => Err(UnavailableReason::Oversize),
            Self::Corrupt(_) => Err(UnavailableReason::Corrupt),
        }
    }
}

/// One read of the set's file.
#[derive(Debug)]
pub(crate) enum ReadOutcome {
    /// No file at the name.
    Missing,
    /// A symbolic link at the name.
    Link,
    /// An I/O failure: an open, `fstat` or read error, or a read that
    /// returned fewer or more bytes than `fstat`'s size. Never cached.
    Io(io::Error),
    /// The file was opened and judged.
    Loaded {
        /// The opened descriptor, kept so its inode stays allocated.
        file: File,
        /// The opened descriptor's identity (its own `fstat`).
        identity: Identity,
        verdict: Verdict,
    },
}

impl ReadOutcome {
    /// The set read, or the reason the server's reader answers
    /// unavailable: the one mapping the reader and [`list`] share.
    pub(crate) const fn outcome(&self) -> Result<&Arc<EnrollmentSet>, UnavailableReason> {
        match self {
            Self::Missing => Err(UnavailableReason::Missing),
            Self::Link => Err(UnavailableReason::Unprotected),
            Self::Io(_) => Err(UnavailableReason::Unreadable),
            Self::Loaded { verdict, .. } => verdict.outcome(),
        }
    }
}

/// Read the set's file in `dir`, whose owner is `owner` (module docs).
pub(crate) fn read_set(ops: &impl DirOps, dir: &File, owner: u32) -> ReadOutcome {
    let file = match ops.open_read_at(dir, SET_NAME) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return ReadOutcome::Missing,
        Err(e) if is_link_refusal(&e) => return ReadOutcome::Link,
        Err(e) => return ReadOutcome::Io(e),
    };
    let stat = match ops.fstat(&file) {
        Ok(stat) => stat,
        Err(e) => return ReadOutcome::Io(e),
    };
    let identity = Identity::of(&stat);
    let loaded = |file, verdict| ReadOutcome::Loaded {
        file,
        identity,
        verdict,
    };
    if let Err(rule) = judge_file(&stat, owner) {
        return loaded(file, Verdict::Unprotected(rule));
    }
    let size = match usize::try_from(stat.size) {
        Ok(size) if size <= ENCODED_MAX => size,
        _ => return loaded(file, Verdict::Oversize { size: stat.size }),
    };
    let bytes = match read_exactly(ops, &file, size) {
        Ok(bytes) => bytes,
        Err(e) => return ReadOutcome::Io(e),
    };
    match decode_set(&bytes) {
        Ok(set) => loaded(file, Verdict::Set(Arc::new(set))),
        Err(e) => loaded(file, Verdict::Corrupt(e)),
    }
}

/// Read exactly `size` bytes of `file`, then confirm the file ends there.
/// `EINTR` is retried; a short or a long file is an error.
fn read_exactly(ops: &impl DirOps, file: &File, size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; size];
    let mut filled = 0;
    while filled < size {
        let offset = u64::try_from(filled).unwrap_or(u64::MAX);
        let Some(rest) = bytes.get_mut(filled..) else {
            break;
        };
        match ops.read_at(file, rest, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("the file ended at {filled} of the {size} bytes its size gave"),
                ));
            }
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let mut probe = [0_u8; 1];
    let end = u64::try_from(size).unwrap_or(u64::MAX);
    loop {
        match ops.read_at(file, &mut probe, end) {
            Ok(0) => return Ok(bytes),
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "the file is longer than the {size} bytes its size gave"
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests;
