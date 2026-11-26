// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The total errno mapping from the reader's closed error set.

use granary_vfs::ReaderError;

/// Maps a [`ReaderError`] to the errno FUSE reports for it.
///
/// Deliberately written as an exhaustive match with NO wildcard arm:
/// `ReaderError` is a closed 9-variant enum, and the point of naming every
/// variant rather than writing `NotFound => ENOENT, _ => EIO` is that a NEW
/// variant added to `ReaderError` must fail to COMPILE here, rather than
/// silently falling through to whatever the wildcard said.
///
/// `NotFound` maps to `ENOENT`. Every other variant maps to
/// `EIO`, including [`ReaderError::UnsupportedEntry`]: a FIFO or
/// socket entry exists but has no supported semantics, so it
/// must answer `EIO`, not `ENOENT`. This does not depend on
/// production `readdir` visibility: `Snapshot::new` refuses a
/// manifest carrying a FIFO or socket entry (`SnapshotError::ReservedEntry`),
/// a decode-time refusal that fails the WHOLE snapshot before
/// it can mount, and neither `readdir` nor `lookup` ever reaches
/// one. `UnsupportedEntry -> EIO` stays anyway, as defence in
/// depth behind that construction gate: `attr_for`'s own refusal
/// and `list_dir_plus`'s now-unreachable FIFO/socket branch both
/// still answer it, so a regression in the construction gate
/// fails loudly rather than letting `ENOENT` claim a
/// known-but-unrepresentable entry is merely absent.
#[must_use]
pub fn errno(error: ReaderError) -> fuser::Errno {
    match error {
        ReaderError::NotFound => fuser::Errno::ENOENT,
        ReaderError::UnsupportedEntry
        | ReaderError::ReadTooFragmented
        | ReaderError::ReadTooLarge
        | ReaderError::GrainUnavailable
        | ReaderError::Inconsistent
        | ReaderError::LookupCountOverflow
        | ReaderError::HandleCountOverflow
        | ReaderError::InodeNumberExhausted => fuser::Errno::EIO,
    }
}

#[cfg(test)]
mod tests;
