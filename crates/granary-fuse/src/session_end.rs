// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! How a FUSE session ended, judged from what its owner saw at the end.
//!
//! fuser treats only `ENODEV` from the `/dev/fuse` read as a clean end. A read
//! that has just dequeued a request when the kernel tears the connection down
//! returns `ECONNABORTED` instead, even with `FUSE_ABORT_ERROR` not negotiated
//! (`fuse_dev_do_read` in the kernel's `fs/fuse/dev.c`), so an unmount that
//! raced the last queued requests ends the session with that error. Whether
//! such an end is a failure depends on whether the mount is still in the
//! table, and the table is the one thing fuser cannot see. This module is the
//! single place that decides it: the mount tests' cleanup and `gran mount`'s
//! daemon both call [`classify_session_end`].
//!
//! The mount table is read from `/proc/self/mountinfo`, never by a `stat` of
//! the mount point, which would be a request to a possibly stuck daemon.

use std::io;
use std::path::Path;

#[doc(hidden)]
pub mod fuzz_probe;

/// What a session's owner observed once the session's thread ended.
#[derive(Debug)]
pub struct SessionEndEvidence {
    /// The owner's own unmount, or its fallback detach when the unmount
    /// failed; `Ok(())` when the kernel ended the session without one.
    pub unmount: io::Result<()>,
    /// What the session's event loop returned.
    pub joined: io::Result<()>,
    /// Whether the owner wrote the connection's fusectl `abort` to end it.
    pub forced: bool,
    /// Whether the mount is still in the mount table, read after the join.
    pub listed: io::Result<bool>,
}

/// The verdict on a session's end.
#[derive(Debug)]
pub enum SessionEnd {
    /// The session ended and its mount is gone.
    Clean,
    /// The owner had to abort the connection to end the session.
    Forced,
    /// The mount is still listed, or could not be checked, and the owner's
    /// unmount failed.
    UnmountFailed(io::Error),
    /// The event loop ended with an error that is not a teardown race.
    Failed(io::Error),
    /// The event loop ended cleanly but the mount is still listed.
    Survived,
    /// The event loop ended cleanly but the mount table could not be read.
    Unverified(io::Error),
}

impl SessionEnd {
    /// The verdict as a plain result: `Ok` only for [`SessionEnd::Clean`].
    ///
    /// # Errors
    ///
    /// [`SessionEnd::Forced`] is `TimedOut`, [`SessionEnd::Survived`] is an
    /// `Other` error, and every other non-clean verdict returns the error it
    /// carries.
    pub fn into_result(self) -> io::Result<()> {
        match self {
            Self::Clean => Ok(()),
            Self::Forced => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the FUSE session ended only through a connection abort",
            )),
            Self::Survived => Err(io::Error::other("the mount survived its unmount")),
            Self::UnmountFailed(error) | Self::Failed(error) | Self::Unverified(error) => {
                Err(error)
            }
        }
    }
}

/// Classifies a session's end, first match wins:
///
/// 1. `forced`: [`SessionEnd::Forced`], whatever else was seen.
/// 2. The mount is gone (`listed` is `Ok(false)`): [`SessionEnd::Failed`] for
///    a joined error other than `ECONNABORTED`, else [`SessionEnd::Clean`]
///    **whatever the unmount answered**. The row is gone, so a failed unmount
///    only means someone else's detach got there first, and an `ECONNABORTED`
///    is the teardown race this module exists for.
/// 3. The mount is listed (`Ok(true)`): [`SessionEnd::UnmountFailed`] for an
///    unmount error, else [`SessionEnd::Failed`] for a joined error,
///    `ECONNABORTED` included, else [`SessionEnd::Survived`].
/// 4. The table could not be read: as rule 3, but a clean join is
///    [`SessionEnd::Unverified`]. An unread table never classifies clean.
///
/// The `ECONNABORTED` exception holds only while `FUSE_ABORT_ERROR` stays
/// un-negotiated: with it, every end-of-connection read would answer that
/// error. The capability decision asserts that at compile time.
#[must_use]
pub fn classify_session_end(evidence: SessionEndEvidence) -> SessionEnd {
    let SessionEndEvidence {
        unmount,
        joined,
        forced,
        listed,
    } = evidence;
    if forced {
        return SessionEnd::Forced;
    }
    let listed = match listed {
        Ok(false) => {
            return match joined {
                Err(error) if error.raw_os_error() != Some(fuser::Errno::ECONNABORTED.code()) => {
                    SessionEnd::Failed(error)
                }
                Ok(()) | Err(_) => SessionEnd::Clean,
            };
        }
        Ok(true) => None,
        Err(unreadable) => Some(unreadable),
    };
    match (unmount, joined, listed) {
        (Err(error), _, _) => SessionEnd::UnmountFailed(error),
        (Ok(()), Err(error), _) => SessionEnd::Failed(error),
        (Ok(()), Ok(()), None) => SessionEnd::Survived,
        (Ok(()), Ok(()), Some(unreadable)) => SessionEnd::Unverified(unreadable),
    }
}

/// A FUSE mount, identified by its superblock's device number.
///
/// The anonymous device is fixed for the connection's life and kept across a
/// `mount --move` or a renamed parent, so [`MountIdentity::listed`] still
/// answers `true` for a mount that lives on at another path; a path test would
/// read such a mount as gone. Two residuals, both in the safe direction:
///
/// - once the superblock is freed its number is free for the next anonymous
///   superblock, and the kernel hands out the lowest free number, so a FUSE
///   mount made by anyone in the same namespace around that time is likely
///   to take it, and [`MountIdentity::listed`] then reads as still listed.
///   The reuse is immediate, so any other FUSE mount made around a session's
///   end can turn a clean end into [`SessionEnd::Survived`], a daemon's exit
///   1: a false failure, never a false success, which is why the rule stays
///   the device alone. An owner that never moves its mount asks
///   [`MountIdentity::listed_at`] instead, which such a mount elsewhere cannot
///   answer;
/// - only `fuse` and `fuse.*` rows count as FUSE. A `fuseblk` superblock
///   carries its block device's number, never an anonymous (major 0) one, so
///   leaving those rows out cannot read our mount as gone; and our own mount
///   is never `fuseblk`, which needs a block device to mount from, so
///   `capture` refusing one refuses only a mount that is not ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountIdentity {
    device: (u32, u32),
}

impl MountIdentity {
    /// The identity of the FUSE mount at `path`, from `/proc/self/mountinfo`.
    ///
    /// When several mounts are stacked at `path`, the top one is taken: the
    /// row that no other row at `path` names as its parent.
    ///
    /// # Errors
    ///
    /// Fails when mountinfo cannot be read or parsed, when no row's mount
    /// point is `path`, when the rows at `path` have no top, or when the
    /// mount on top is not FUSE.
    pub fn capture(path: &Path) -> io::Result<Self> {
        Self::capture_in(&read_mountinfo()?, path)
    }

    /// Whether any mountinfo row, at any path, still carries this mount's
    /// device with a FUSE filesystem type.
    ///
    /// # Errors
    ///
    /// Fails when mountinfo cannot be read or parsed; "could not look" is
    /// never reported as "not listed".
    pub fn listed(&self) -> io::Result<bool> {
        self.listed_in(&read_mountinfo()?)
    }

    /// Whether this mount's connection directory still exists in fusectl.
    ///
    /// The directory is keyed by the anonymous device's minor, so `true`
    /// has the same reuse caveat as [`MountIdentity::listed`].
    ///
    /// # Errors
    ///
    /// Fails if fusectl is unavailable or the connection directory cannot be checked.
    #[cfg(target_os = "linux")]
    pub fn connection_alive(&self) -> io::Result<bool> {
        use nix::errno::Errno;
        use nix::fcntl::{AtFlags, OFlag, open};
        use nix::sys::stat::{Mode, fstatat};
        use nix::sys::statfs::{FsType, fstatfs};

        // FUSE_CTL_SUPER_MAGIC from linux/magic.h.
        const FUSECTL: FsType = FsType(0x6573_5543);
        let control = open(
            "/sys/fs/fuse/connections",
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        if fstatfs(&control)?.filesystem_type() != FUSECTL {
            return Err(io::ErrorKind::Unsupported.into());
        }
        // Check relative to the verified directory even if its mount is replaced.
        let (_, minor) = self.device;
        match fstatat(&control, minor.to_string().as_str(), AtFlags::empty()) {
            Ok(_) => Ok(true),
            Err(Errno::ENOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Whether a FUSE row carrying this mount's device is mounted at `path`.
    ///
    /// For an owner that never moves its mount, such as a test fixture on its
    /// own scratch path: a concurrent mount that took over a freed device
    /// number sits at its own path, so it cannot answer `true` here.
    ///
    /// # Errors
    ///
    /// Fails when mountinfo cannot be read or parsed; "could not look" is
    /// never reported as "not listed".
    pub fn listed_at(&self, path: &Path) -> io::Result<bool> {
        self.listed_at_in(&read_mountinfo()?, path)
    }

    fn capture_in(mountinfo: &[u8], path: &Path) -> io::Result<Self> {
        let rows = mountinfo_rows(mountinfo)?;
        let at_path = rows_at(&rows, path)?;
        if at_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no mount at {} in /proc/self/mountinfo", path.display()),
            ));
        }
        let row = at_path
            .iter()
            .rev()
            .find(|row| !at_path.iter().any(|other| other.parent_id == row.mount_id))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the mounts at {} in /proc/self/mountinfo have no top one",
                        path.display()
                    ),
                )
            })?;
        if !row.fuse {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the mount at {} is not a FUSE mount", path.display()),
            ));
        }
        Ok(Self { device: row.device })
    }

    fn listed_at_in(&self, mountinfo: &[u8], path: &Path) -> io::Result<bool> {
        let rows = mountinfo_rows(mountinfo)?;
        Ok(rows_at(&rows, path)?
            .iter()
            .any(|row| row.fuse && row.device == self.device))
    }

    fn listed_in(&self, mountinfo: &[u8]) -> io::Result<bool> {
        Ok(mountinfo_rows(mountinfo)?
            .iter()
            .any(|row| row.fuse && row.device == self.device))
    }
}

fn read_mountinfo() -> io::Result<Vec<u8>> {
    std::fs::read("/proc/self/mountinfo")
}

/// One `/proc/self/mountinfo` row, as far as this module reads it.
#[derive(Debug)]
pub struct MountRow<'a> {
    /// Field 1.
    pub mount_id: u32,
    /// Field 2, the mount this one is attached to.
    parent_id: u32,
    /// Field 3, `major:minor`.
    pub device: (u32, u32),
    /// Field 5 as the kernel wrote it, its escapes already checked; decoded
    /// only where a path is compared.
    mount_point: &'a [u8],
    /// Whether the filesystem type after the separator is `fuse` or `fuse.*`.
    pub fuse: bool,
    /// Mount source after the separator, as kernel-escaped bytes.
    pub source: &'a [u8],
    /// Superblock options after source.
    pub super_options: &'a [u8],
}

/// Checked rows at exactly the decoded target bytes.
///
/// # Errors
/// Refuses an empty, malformed or torn mountinfo body, including unrelated rows.
pub fn mountinfo_rows_at<'a>(mountinfo: &'a [u8], path: &Path) -> io::Result<Vec<MountRow<'a>>> {
    use std::os::unix::ffi::OsStrExt as _;
    let rows = mountinfo_rows(mountinfo)?;
    let wanted = path.as_os_str().as_bytes();
    let mut selected = Vec::new();
    for row in rows {
        if mountinfo_unescape(row.mount_point)? == wanted {
            selected.push(row);
        }
    }
    Ok(selected)
}

/// The rows whose decoded mount point is exactly `path`'s bytes.
fn rows_at<'r, 'a>(rows: &'r [MountRow<'a>], path: &Path) -> io::Result<Vec<&'r MountRow<'a>>> {
    use std::os::unix::ffi::OsStrExt as _;
    let wanted = path.as_os_str().as_bytes();
    let mut at = Vec::new();
    for row in rows {
        if mountinfo_unescape(row.mount_point)? == wanted {
            at.push(row);
        }
    }
    Ok(at)
}

/// Whether some mountinfo row's mount point decodes to exactly `path`'s
/// bytes, on literal bytes so it is testable with no mount at all.
#[cfg(test)]
pub(crate) fn mountinfo_lists(mountinfo: &[u8], path: &Path) -> io::Result<bool> {
    Ok(!rows_at(&mountinfo_rows(mountinfo)?, path)?.is_empty())
}

/// Parses every row of a mountinfo body, refusing the body if any row is not
/// one the kernel writes.
///
/// **Bytes, never `&str`.** The kernel escapes exactly four bytes in the
/// mount-point field — space, tab, newline and backslash — as `\ooo`
/// (`seq_path_root` with `" \t\n\\"` in `fs/proc_namespace.c`, through
/// `mangle_path` in `fs/seq_file.c`) and writes every OTHER byte raw, so an
/// unrelated mount whose path holds a non-UTF-8 byte must not make THIS
/// check unverifiable. The comparison is byte-for-byte with no lossy step.
///
/// **Strict, over every line.** A backslash that does not open a
/// three-octal-digit escape, a mount or parent id that is not a decimal
/// number, or a device field that is not `major:minor`, cannot occur on a
/// healthy row, so either is reported as `Err` rather than
/// passed through, whichever line it is on: an `Err` is what keeps a caller
/// from reading "gone" out of a row it does not understand, and a lenient
/// decode would be a guess in the direction that declares a live mount gone.
fn mountinfo_rows(mountinfo: &[u8]) -> io::Result<Vec<MountRow<'_>>> {
    let mut rows = Vec::new();
    for line in mountinfo.split(|&b| b == b'\n') {
        // The empty line after the final newline is not a row.
        if line.is_empty() {
            continue;
        }
        // Validate the WHOLE row's structure, not one truncation shape.
        // `proc_pid_mountinfo(5)`:
        //   mount_id parent_id major:minor root mount_point mount_options
        //   [optional_fields...] - fstype mount_source super_options
        // so a complete row has at least SIX fields through `mount_options`
        // BEFORE the mandatory bare `-` separator, and at least THREE after
        // it (fstype, source, super_options). Any nonempty line that is not
        // a complete row is a TORN read — a partial line a mid-file cut left
        // — and is refused, never mined for a mount point. Validating the
        // row STRUCTURE covers a missing separator, a short trailing row and
        // a row cut just after the separator together.
        let fields: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
        let separator = fields.iter().position(|field| *field == b"-");
        // `>= 6` fields before the separator (mount_point is field 5,
        // index 4; mount_options is field 6, index 5), `>= 3` after it.
        let complete = separator.is_some_and(|sep| sep >= 6 && fields.len() >= sep + 4);
        // `.get()`, never indexing — this workspace denies
        // `clippy::indexing_slicing`; `complete` guarantees each field, and
        // the `else` is a defensive refusal rather than a proof the branch
        // is unreachable.
        let (
            Some(&mount_id),
            Some(&parent_id),
            Some(&device),
            Some(&mount_point),
            Some(&fstype),
            Some(&source),
            Some(&super_options),
            true,
        ) = (
            fields.first(),
            fields.get(1),
            fields.get(2),
            fields.get(4),
            separator.and_then(|sep| fields.get(sep + 1)),
            separator.and_then(|sep| fields.get(sep + 2)),
            separator.and_then(|sep| fields.get(sep + 3)),
            complete,
        )
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated or malformed /proc/self/mountinfo row (not a complete mount line: a \
                 bare ` - ` separator with >= 6 fields before and >= 3 after); refusing to \
                 report a mount state from a torn read",
            ));
        };
        check_escapes(mount_point)?;
        rows.push(MountRow {
            mount_id: parse_id(mount_id)?,
            parent_id: parse_id(parent_id)?,
            device: parse_device(device)?,
            mount_point,
            fuse: fstype == b"fuse" || fstype.starts_with(b"fuse."),
            source,
            super_options,
        });
    }
    // A live process's `/proc/self/mountinfo` ALWAYS lists at least the root
    // mount, so a readable body with no complete row at all is not a valid
    // mountinfo — an empty or truncated read, not a real "nothing is
    // mounted". Reporting it as an empty table would be fail-OPEN: a caller
    // would read "gone" from a body that verified nothing.
    //
    // A truncation cut EXACTLY at a row boundary (whole rows, the last one
    // complete, but the wanted row never emitted) is the one shape no
    // content check can detect — but it cannot arise through the production
    // reader: `std::fs::read`'s `read_to_end` returns the COMPLETE seq_file
    // or an `Err`, never a partial `Ok` (seq_file emits whole records and
    // signals EOF only at the true end). A partial byte slice reaching here
    // is a test construction, and the complete-row check above refuses every
    // partial shape below a row boundary.
    if rows.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "/proc/self/mountinfo had no complete mount row (empty or truncated read); refusing \
             to report a mount state from it",
        ));
    }
    Ok(rows)
}

/// A plain unsigned decimal, as the kernel writes every number in a row.
fn decimal(digits: &[u8]) -> Option<u32> {
    std::str::from_utf8(digits)
        .ok()
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
}

/// Field 1 or 2, a mount id.
fn parse_id(field: &[u8]) -> io::Result<u32> {
    decimal(field).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "malformed /proc/self/mountinfo mount id {:?}",
                String::from_utf8_lossy(field)
            ),
        )
    })
}

/// Field 3, `major:minor`, both decimal, as the kernel writes it (`%u:%u`).
fn parse_device(field: &[u8]) -> io::Result<(u32, u32)> {
    let mut parts = field.splitn(2, |&b| b == b':');
    match (
        parts.next().and_then(decimal),
        parts.next().and_then(decimal),
    ) {
        (Some(major), Some(minor)) => Ok((major, minor)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "malformed /proc/self/mountinfo device field {:?} (not major:minor)",
                String::from_utf8_lossy(field)
            ),
        )),
    }
}

/// Checks one mount-point field's escapes without decoding it: every
/// backslash must open a well-formed `\ooo`, per [`mountinfo_rows`].
fn check_escapes(field: &[u8]) -> io::Result<()> {
    let mut i = 0_usize;
    while let Some(&b) = field.get(i) {
        if b == b'\\' {
            if octal_escape_at(field, i).is_none() {
                return Err(malformed_escape(field, i));
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    Ok(())
}

fn malformed_escape(field: &[u8], i: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "malformed escape at byte {i} of mountinfo mount-point field {:?}",
            String::from_utf8_lossy(field)
        ),
    )
}

/// Decodes one mount-point field: every `\ooo` becomes its byte, every
/// other byte passes through unchanged (bytes in, bytes out — no UTF-8
/// requirement and no lossy step). A backslash that is not the start of a
/// well-formed escape is an `Err` naming the field, per [`mountinfo_rows`].
fn mountinfo_unescape(field: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0_usize;
    while let Some(&b) = field.get(i) {
        if b == b'\\' {
            let decoded = octal_escape_at(field, i).ok_or_else(|| malformed_escape(field, i))?;
            out.push(decoded);
            i += 4;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

/// The octal escape at `bytes[i..]`: `bytes[i]` is `\` and the three bytes
/// after it are octal digits with the FIRST in `0..=3` — `\377` is the
/// largest byte, and admitting `4..=7` would let `(d1 - b'0') * 64` exceed
/// a `u8`. `None` otherwise, including when fewer than three bytes follow.
/// `.get()` throughout, never indexing.
fn octal_escape_at(bytes: &[u8], i: usize) -> Option<u8> {
    if *bytes.get(i)? != b'\\' {
        return None;
    }
    let d1 = *bytes.get(i + 1)?;
    let d2 = *bytes.get(i + 2)?;
    let d3 = *bytes.get(i + 3)?;
    if !(b'0'..=b'3').contains(&d1) || !(b'0'..=b'7').contains(&d2) || !(b'0'..=b'7').contains(&d3)
    {
        return None;
    }
    Some((d1 - b'0') * 64 + (d2 - b'0') * 8 + (d3 - b'0'))
}

#[cfg(test)]
mod tests;
