// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::errno` — the total errno mapping from the reader's
//! closed error set.
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::errno;
use granary_vfs::ReaderError;

#[test]
fn every_variant_maps_to_its_named_errno() {
    let cases = [
        (ReaderError::NotFound, fuser::Errno::ENOENT),
        (ReaderError::UnsupportedEntry, fuser::Errno::EIO),
        (ReaderError::ReadTooFragmented, fuser::Errno::EIO),
        (ReaderError::ReadTooLarge, fuser::Errno::EIO),
        (ReaderError::GrainUnavailable, fuser::Errno::EIO),
        (ReaderError::Inconsistent, fuser::Errno::EIO),
        (ReaderError::LookupCountOverflow, fuser::Errno::EIO),
        (ReaderError::HandleCountOverflow, fuser::Errno::EIO),
        (ReaderError::InodeNumberExhausted, fuser::Errno::EIO),
    ];
    for (input, expected) in cases {
        assert_eq!(errno(input), expected, "{input:?} -> {expected:?}");
    }
}

#[test]
fn not_found_is_the_only_non_eio_variant() {
    // The row sweep above already kills a mutation that answers ENOENT
    // for some OTHER row. This pins the converse: NotFound itself must
    // NOT be EIO, so a mutation flipping NotFound's own arm is also
    // caught even by a reviewer skimming only this one assertion.
    assert_ne!(errno(ReaderError::NotFound), fuser::Errno::EIO);
}
