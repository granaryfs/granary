// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The crate root's own compile-time surface census: a single
//! never-called `fn` whose body names each of the twenty items
//! `lib.rs` re-exports, so an item LEAVING the root becomes a build
//! failure rather than a silently narrower public surface.
//!
//! Out-of-line, and declared at the CRATE ROOT rather than under a
//! module, because its subject is not any single module — it is the
//! shape of `lib.rs`'s `pub use` surface. The rule is that a test body
//! whose subject is not a single module gets its own file, declared at
//! the crate root.
//!
//! **The narrative belongs to the declaration, not to this file.**
//! `lib.rs`'s doc on `mod root_surface_probe;` states exactly what this
//! probe proves and — at greater length — what it does NOT, including
//! that the list below is hand-maintained against the root's `pub use`
//! lines and that keeping the two in step is a two-file comparison.
//! Read that before editing the list below.

use crate::{
    Attr, AttrPolicy, Entry, GrainFetch, GrainSlice, GrainUnavailable, HandleKind, HandleTable,
    InodeTable, NodeKind, PathKey, READ_MAX_BYTES, READ_MAX_GRAINS, ReaddirEntry, ReaderError,
    ReservedEntryKind, ServeLimits, Snapshot, SnapshotError, dir_and_parent,
};

#[expect(
    dead_code,
    reason = "never called at runtime — resolving every path at compile time is the \
              assertion this function exists to make"
)]
fn resolves_every_curated_item() {
    fn is_type<T>() {}
    fn is_trait<T: ?Sized>() {}
    is_type::<Attr>();
    is_type::<AttrPolicy>();
    is_type::<Entry>();
    is_trait::<dyn GrainFetch>();
    is_type::<GrainSlice>();
    is_type::<GrainUnavailable>();
    is_type::<HandleKind>();
    is_type::<HandleTable>();
    is_type::<InodeTable>();
    is_type::<NodeKind>();
    is_type::<PathKey>();
    let _: u32 = READ_MAX_BYTES;
    let _: usize = READ_MAX_GRAINS;
    is_type::<ReaddirEntry>();
    is_type::<ReaderError>();
    is_type::<ReservedEntryKind>();
    is_type::<ServeLimits>();
    is_type::<Snapshot>();
    is_type::<SnapshotError>();
    let _ = dir_and_parent;
}
