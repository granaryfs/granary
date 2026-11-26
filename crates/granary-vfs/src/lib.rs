// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The portable manifest-reading engine extracted from `granary-fuse`:
//! snapshot indexing, grain reads, attribute construction, an
//! inode table and a handle table — with no adapter surface, and no
//! dependency but `granary-core`.
//!
//! # The purity boundary
//!
//! `#![cfg_attr(not(test), no_std)]` on this crate root — and
//! `scripts/check-vfs-purity.sh`, which guards the attribute's own
//! presence, exact predicate and evasion, since its deletion is
//! otherwise unguarded — states one guarantee, at its real strength and
//! no stronger:
//!
//! > The engine's own production source cannot introduce a direct
//! > dependency on the `std` crate, in the configurations actually
//! > expanded and compiled. That is all it is. It is **not** an effect
//! > guarantee, and it is **not even a naming guarantee** — the engine
//! > may freely name `granary_core::rng::ProcessRng::new`, which IS an
//! > entry point to ambient process entropy. The ban is on naming
//! > `std`, not on naming an effect.
//!
//! So the attribute is a **purity boundary, not a portability claim**:
//! this crate never targets bare metal, and its only dependency
//! (`granary-core`) itself links `std`.
//!
//! Two statuses, recorded separately. The whole-engine property — the
//! *whole engine* is platform-I/O-free — is **not** declared complete by
//! this crate; only its own axis is:
//!
//! | axis | status |
//! |---|---|
//! | `granary-vfs`'s own direct source | enforced at birth by the attribute and its gate |
//! | the whole reachable engine stack | **not yet** platform-I/O-free — `granary-core` exposes ambient entropy (`granary_core::rng::ProcessRng::new`, `rng.rs:146`) and a `std::io::Read`-bounded API (`granary_core::thresh::grains_streaming`, `thresh.rs:160`) |

#![cfg_attr(not(test), no_std)]
#![warn(unnameable_types)]
extern crate alloc;

mod attr;
mod handle;
mod inode;
mod listing;
mod read;
mod snapshot;
mod source;

pub use attr::{Attr, NodeKind, permission_mode};
pub use handle::{HandleKind, HandleTable};
pub use inode::{InodeTable, PathKey};
pub use listing::dir_and_parent;
pub use read::{GrainSlice, READ_MAX_BYTES, READ_MAX_GRAINS};
pub use snapshot::{
    AttrPolicy, Entry, ReaddirEntry, ReaderError, ReservedEntryKind, ServeLimits, Snapshot,
    SnapshotError,
};
pub use source::{GrainFetch, GrainUnavailable};

/// A COMPILE-TIME assertion that the twenty names listed in its own
/// `use crate::{…}` — which lives in `root_surface_probe.rs` — resolve.
/// It catches an item LEAVING the root: removing one turns the matching
/// line in `resolves_every_curated_item` into `E0432`/`E0603`, a build
/// failure rather than a runtime test
/// failure — and does so without adding a row to
/// `cargo nextest run -p granary-vfs` at all, which a runtime test here
/// would.
///
/// **What this probe proves, exactly, and no more: the twenty names in
/// its own `use` list resolve.** That list is maintained BY HAND
/// alongside the root's `pub use` lines above, and nothing here checks
/// it against anything external — deleting a line from it silently
/// narrows what the probe proves; it does not fail. Read it as "these
/// twenty names, written once in `root_surface_probe.rs` and once at
/// the root, both resolve", not as a completeness guarantee over the
/// root's whole surface. Keeping the two lists in step requires
/// comparing this file with `root_surface_probe.rs`.
///
/// `#![warn(unnameable_types)]` catches a DIFFERENT, narrower gap: an
/// item reachable through a public signature but absent from the
/// curated root becomes visible via the type it appears in even though
/// nothing ever named it at the root. **The two together do not catch
/// everything that can go silently unreachable, and neither catches
/// every ADDITION either:**
///
/// - A `pub use` demoted to `pub(crate) use` is invisible to BOTH: this
///   probe still resolves it (a `pub(crate)` item is visible from
///   anywhere inside its own crate, which is exactly where this test
///   module lives), and `unnameable_types` has no complaint (the type
///   stays perfectly nameable — just no longer from OUTSIDE the crate).
/// - Neither catches an item being ADDED to the root. Nothing downstream
///   fails when the root gains an extra `pub use`, a `pub mod`
///   promotion, or a direct `pub` item declared straight at crate scope
///   — every line in `root_surface_probe.rs` still resolves, the crate
///   still compiles, and a twenty-first export sits there unnoticed. (A
///   `const NAMES: [&str; 20]` array with a
///   `const _: () = assert!(NAMES.len() == 20, …)`
///   beside it once stood here as an attempt at that direction; it
///   asserted only that a HAND-WRITTEN array of twenty string literals
///   has twenty elements — a tautology against nothing external, which
///   would keep passing however many items the root actually carried.
///   Removed rather than left implying a completeness it never had.)
///
/// **The addition gap was once answered by a standing gate — a
/// curated-root census in `scripts/check-vfs-purity.sh` that diffed this
/// root's actual `pub use` surface against the twenty names, by set, on
/// EVERY run. IT WAS WITHDRAWN**, because it enforced a policy nobody
/// had actually decided. The invariant that IS decided is
/// narrower:
/// the purity gate pins exactly three items (the `not(test)`
/// attribute; no post-expansion `extern crate std`; no
/// `#[path]`/`include!`), and the crate root's shape — declarations plus
/// a curated `pub use` surface — is a SHAPE requirement, not a mandate that
/// every future public addition must fail CI forever. Installing that as a
/// standing gate under the purity banner conflated two different
/// invariants.
///
/// The root was checked once against the compiler's own answer:
///
/// ```text
/// RUSTC_BOOTSTRAP=granary_vfs cargo rustdoc -p granary-vfs --lib -- \
///   -Zunstable-options --output-format json
/// ```
///
/// On the pinned rustc 1.97.1 (aarch64-apple-darwin),
/// `target/doc/granary_vfs.json` reported `format_version` **57** and a
/// root module of exactly **20** children, all `use` re-exports, named
/// exactly the twenty in `root_surface_probe.rs`. That count is a
/// measurement on that toolchain, not a standing assertion: a legitimate
/// new named `pub use` moves it, and this doc stays true without an update.
///
/// **The root is not frozen at any count, but its SHAPE is gated —
/// `scripts/check-vfs-root-shape.sh` (self-test first, wired beside
/// `check-vfs-purity.sh` in CI's `gates` job) enforces that this crate
/// scope is entirely attributes, a non-`pub` `extern crate`/`mod`/`use`,
/// and a `pub use` of named leaves — plus a crate-wide sweep for
/// `#[macro_export]`, which can add a root-namespace item with no diff
/// here at all.** That gate's own header carries the full grammar and
/// why it is an allow-list rather than a deny-list. Whether any of this
/// should extend past `granary-vfs` is open, and deliberately: the
/// measured price is the reason it has not.
///
/// **Stated plainly, and the gate says the same: this is a LITERAL-SOURCE
/// shape scanner, not complete public-surface enforcement, and it does
/// not resist a determined bypass** — a cfg-disabled module declaration
/// can spoof its own module inventory, and a macro can be built to
/// expand into the exact attribute text the scanner looks for. It
/// catches the honest mistake and the careless one. Both bypasses named
/// above are stated as NOT caught rather than claimed closed — not
/// claimed complete, either.
#[cfg(test)]
mod root_surface_probe;
