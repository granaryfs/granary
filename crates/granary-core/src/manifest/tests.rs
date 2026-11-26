// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::manifest` — the manifest content tree v1 module surface.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

/// Freeze pin. The house rule is that tests IMPORT the
/// constants rather than re-literal them; this test is the one
/// deliberate exception, because pinning the literal IS its
/// purpose. The vector suites pin C, F, K, `DEPTH_MAX` and
/// `GRAIN_UNPACKED_MAX` transitively through vectors and rejects,
/// but N and the index fanout are far too large to materialize in
/// a vector — without this test they can drift silently.
///
/// The entry-tag registry is pinned here for the same reason and
/// one more: tags must never be reused or renumbered, and
/// tags are hash-relevant wire bytes emittable through the public
/// encoder. 0x01–0x04 are pinned transitively by the golden vectors,
/// but 0x05 (fifo) and 0x06 (socket) appear in NO vector — v1 never
/// emits them — so before this pin they could be renumbered with the
/// whole suite staying green. Pinning all six together also states
/// the registry in one place (0x00 stays invalid forever; its reject
/// vector lives in `tests/manifest_rejects.rs`).
#[test]
fn constants_are_frozen() {
    assert_eq!(DIR_LEAF_MAX_ENTRIES, 256, "C");
    assert_eq!(DIR_INTERIOR_MAX_CHILDREN, 256, "F");
    assert_eq!(FILE_INLINE_MAX_REFS, 128, "K");
    assert_eq!(GRAINLIST_LEAF_MAX_REFS, 131_072, "N");
    assert_eq!(GRAINLIST_INDEX_MAX_CHILDREN, 131_072);
    assert_eq!(DEPTH_MAX, 16);
    assert_eq!(GRAIN_UNPACKED_MAX, 8_388_608);
    assert_eq!(name::NAME_MAX, 255);
    assert_eq!(name::SYMLINK_TARGET_MAX, 4096);
    assert_eq!(node::ENTRY_TAG_DIR, 0x01, "entry tag: dir");
    assert_eq!(node::ENTRY_TAG_FILE, 0x02, "entry tag: file");
    assert_eq!(node::ENTRY_TAG_EXEC_FILE, 0x03, "entry tag: exec file");
    assert_eq!(node::ENTRY_TAG_SYMLINK, 0x04, "entry tag: symlink");
    assert_eq!(node::ENTRY_TAG_FIFO, 0x05, "entry tag: fifo (reserved)");
    assert_eq!(node::ENTRY_TAG_SOCKET, 0x06, "entry tag: socket (reserved)");
}
