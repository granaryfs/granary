// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Cache paths: the layout's names, and the structural-directory
//! discipline every write and read passes through before it touches
//! one.
//!
//! **What breaks when this module is wrong:** a symlinked structural
//! directory is followed and the cache writes outside its own root, a
//! foreign object fan-out is adopted as if this cache had produced it,
//! or an object leaf is unlinked through a fan-out nobody classified.
//! The other half of the same subject is naming: an object, root or
//! anchor path derived the wrong way reads or writes the wrong file,
//! and a hex digest decoded loosely admits a name the layout forbids.
//!
//! It owns the four guarded-path helpers ([`create_structural_dir`],
//! [`refuse_symlinked_structural_dir`], [`refuse_foreign_object_fanout`],
//! [`unlink_object_leaf`]), the four path constructors
//! ([`object_path`], [`root_bytes_path`], [`anchor_path`],
//! [`mount_anchor_path`]) with the leaf width one of them renders
//! ([`ROOT_SEQ_WIDTH`]), the lower-hex vocabulary the layout's names are
//! spelled in ([`hex32`], [`is_lower_hex`], [`decode_hex_digest`]), and
//! [`io_err`], the one constructor every helper here reports through.
//! It does NOT own [`super::CacheError`] itself — an error enum REPORTS
//! failure domains and is not one, so it stays with the parent — nor
//! any decision about WHEN a path is written: that is the cache's own
//! state machine.
//!
//! It is the layer the other children sit on and reaches none of them
//! (the sibling order: `paths` first, then `write`, then
//! `marker`, `anchor` and `index-load`).
//!
//! Out-of-line, and a child one flat
//! level under `cache/`, beside `write`,
//! `marker`, `anchor` and `index-load`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use granary_core::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use granary_core::root::VolumeName;

use super::CacheError;

/// `roots/<volume>/<seq>` leaf width: 20 zero-padded digits (`u64::MAX`
/// is 20 digits).
pub(super) const ROOT_SEQ_WIDTH: usize = 20;

pub(super) fn io_err(context: impl Into<String>) -> impl FnOnce(io::Error) -> CacheError {
    let context = context.into();
    move |source| CacheError::Io { context, source }
}

/// Create a structural cache subdirectory, refusing one that ALREADY
/// EXISTS as a symlink. `create_dir_all` FOLLOWS a symlink whose target
/// is a directory — it finds the dir and returns `Ok` — so a pre-planted
/// `index -> ../source` (or `objects -> /elsewhere`) would make every
/// subsequent structural write land THROUGH the link, outside the cache
/// root: on the publish path that publishes the cache's own index files
/// as volume content (`Cache::open` runs before `prepare()` harvests the
/// source), and on any path it scatters cached bytes wherever the link
/// points. This extends the `O_NOFOLLOW` protection the structural FILES
/// (`lock`, `guard`, txn staging) already have to the structural
/// DIRECTORIES, which `create_dir_all` would otherwise follow.
/// A fresh subdir (no symlink) and a real
/// re-opened one are both unaffected. Same narrowing-not-closing caveat
/// as the file opens: an ACTIVE TOCTOU swapping the path between this
/// check and a later write remains out of scope; refusing a pre-existing
/// symlink does not close that race.
#[expect(
    clippy::disallowed_methods,
    reason = "the line above just refused a pre-existing symlink at `path` (lstat, fail closed \
              on error); create_dir_all is safe once that check has passed for a fresh or \
              already-real directory — the cache module's canonical guarded-create \
              helper, reused by every structural dir in it"
)]
pub(super) fn create_structural_dir(path: &Path, context: &'static str) -> Result<(), CacheError> {
    refuse_symlinked_structural_dir(path, context)?;
    fs::create_dir_all(path).map_err(io_err(context))
}

/// Non-creating structural-directory guard shared by reads, writer
/// creation, and verify. A final-component `O_NOFOLLOW` open still
/// follows a symlinked INTERMEDIATE directory, as do path-based removals.
/// Missing is allowed: readers turn the later open into a miss, creators
/// create it, and verify classifies it separately. Unexpected lstat
/// errors fail closed.
pub(super) fn refuse_symlinked_structural_dir(
    path: &Path,
    context: &'static str,
) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(io_err(context)(io::Error::other(
            "a structural cache directory is a symlink; refusing to read, write, or remove \
             through it",
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(context)(e)),
    }
}

/// The OBJECT-FANOUT classifier: `objects/<2hex>` is a real directory or
/// it is FOREIGN. Aligned with `store::refuse_foreign_object_fanout`,
/// deliberately — the two guard the same shape of tree and had no reason
/// to disagree about what counts as foreign.
///
/// **Stricter than [`refuse_symlinked_structural_dir`], which is why it
/// exists.** That helper refuses a symlink and passes everything else,
/// which is right for a structural directory the cache CREATES on
/// demand: a regular file at `index/` fails the create loudly. It is
/// wrong here. The cache creates nothing but a directory at an object
/// fanout, so a regular file, a FIFO or a socket at that name belongs to
/// something else, and no object of this cache can exist beneath it —
/// every path below fails `ENOTDIR`. Passing it turned each such read
/// into an ordinary MISS and each write into a bare inspect failure, so
/// a whole fanout became permanently un-servable with nothing in the log
/// naming the cause.
///
/// Missing is allowed, as everywhere else: the writer creates the fanout
/// further down, the reader turns the later open into a miss.
/// Unexpected lstat errors fail closed. No new filesystem primitive —
/// `symlink_metadata` is the class's SAFE half, never banned (see
/// `crates/granary-client/clippy.toml`'s header).
pub(super) fn refuse_foreign_object_fanout(
    path: &Path,
    context: &'static str,
) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(io_err(context)(io::Error::other(format!(
            "{} is not a real directory; this cache creates nothing but a directory at an \
             object fanout, so it is foreign and nothing below it belongs to this cache",
            path.display()
        )))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(context)(e)),
    }
}

/// THE one owner of "classify the fanout, then unlink the leaf" for
/// `object_path(root, id)` in this module. Every object-path
/// `remove_file` goes through it, so a bare one anywhere else in the
/// cache module — this file or its parent, where every caller lives — is
/// a review-visible anomaly rather than a fourth copy of the same three
/// lines.
///
/// `remove_file` never follows its FINAL component, which is what makes
/// unlinking a foreign leaf safe. It does follow a symlinked
/// INTERMEDIATE one. `objects/<2hex>` replaced by a link into another
/// content-addressed tree therefore turns an ordinary eviction into a
/// deletion over there: content addressing puts the same bytes at the
/// same relative path in every CAS, so an index this cache wrote for
/// itself — syntactically valid, never revalidated against the
/// filesystem when it is loaded — already names a file that exists on
/// the far side of the link.
///
/// **It answers nothing, and that is deliberate.** The three outcomes it
/// can reach — the name is gone, the fanout was foreign so nothing was
/// touched, the unlink could not be performed — differ ONLY in what is
/// logged, which is logged HERE. They do not differ in what any caller
/// must then do: every caller drops the index entry and refunds its
/// bytes on every outcome, because `total_bytes` is the sum of `live`'s
/// sizes and an entry removed without its refund makes that untrue. A
/// return value the callers cannot branch on is a value that invites a
/// branch that would be wrong.
///
/// **The classification is still three-way and NOT
/// [`refuse_foreign_object_fanout`]'s two.** That helper answers
/// foreign-or-not, which is all a read or a write needs; here the two
/// halves of "foreign" demand opposite WARNINGS. A symlinked fanout
/// means the entry named a leaf in someone else's tree, so nothing
/// belonging to this cache is on disk and nothing is left behind. An
/// `EACCES`/`EIO` means the object may well be STILL THERE, and what
/// the caller leaves behind is an unindexed residue rather than a clean
/// removal.
///
/// **The symmetry with the read and write paths, and where it stops.**
/// Those paths now treat ANY non-directory fanout as foreign
/// ([`refuse_foreign_object_fanout`]), so a regular file, a FIFO or a
/// socket at `objects/<2hex>` never reaches an insert or a get. This
/// function is reached from EVICTION, where the entry comes from an
/// index loaded with no filesystem revalidation, so it can still meet
/// one — and a non-directory fanout falls through to an unlink that
/// fails `ENOTDIR` and is reported as residue. That over-reports: no
/// object of this cache can live under a regular file, so there is
/// nothing left behind to re-adopt. It is a log line erring toward
/// "something may still be on disk", never an accounting difference —
/// the entry is dropped and its bytes refunded on every outcome
/// regardless.
///
/// **Where that residue surfaces.** Nothing here retries the unlink, so
/// the file outlives the index entry that named it. `gran verify`'s
/// independent on-disk scan is what finds it: it reports the file as
/// `adopted` when it can enumerate the fanout and is holding the index,
/// and as `corrupt`/`oversized` when the file's own content fails
/// verification; under a fanout verify cannot enumerate it reports that
/// FANOUT as `foreign` and names nothing beneath it. A cold rebuild
/// walk re-adopts the file into the index, which is what clears the
/// under-count.
///
/// An ACTIVE replacement of the fanout between the classification and
/// the unlink is out of scope; descriptor-relative directory traversal
/// and `unlinkat` are deferred, so this unlink still resolves by path.
#[expect(
    clippy::disallowed_methods,
    reason = "the one bare call is remove_file by NAME on an object path of this cache's own \
              content-addressed layout, and the match above it has just classified the fanout \
              non-followingly (lstat, three-way, fail closed on the unexpected arm). Unlink \
              never follows its FINAL component, so a foreign leaf's target is untouched; it \
              DOES follow an intermediate one, which is what the fanout classification is for. \
              This function is the single owner of that pairing for every object-path unlink \
              in the cache module — eviction, the hash-mismatch unlink and the oversized unlink \
              all route through it, so none of them carries a licence of its own. What \
              remains is an ACTIVE swap of the fanout between the lstat and the unlink: \
              descriptor-relative directory traversal and unlinkat remain deferred"
)]
pub(super) fn unlink_object_leaf(path: &Path, context: &'static str) {
    let Some(fanout) = path.parent() else {
        crate::observe::OperatorDiagnostic::refusing_to_unlink_an_object_path_that_has_no(
            crate::observe::CacheAction::from_adapter(context),
        )
        .emit_paths(&[crate::observe::PathSlot::Path(
            "path",
            crate::LogPath::file(path),
        )]);
        return;
    };
    match fs::symlink_metadata(fanout) {
        Ok(m) if m.file_type().is_symlink() => {
            crate::observe::OperatorDiagnostic::refusing_to_unlink_an_object_through_a_foreign_fanout(crate::observe::CacheAction::from_adapter(context)).emit_paths(&[crate::observe::PathSlot::Path("fanout", crate::LogPath::directory(fanout))]);
            return;
        }
        // A real directory — or a name that is not there at all, in
        // which case there is nothing below it to follow and the unlink
        // answers `NotFound` on its own. Anything ELSE that stats (a
        // regular file, a FIFO) falls through deliberately: the unlink
        // below fails `ENOTDIR` and the caller learns the object is
        // still on disk.
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {
            crate::observe::OperatorDiagnostic::refusing_to_unlink_an_object_under_a_fanout_that(
                crate::FailureClass::Io,
                crate::observe::CacheAction::from_adapter(context),
            )
            .emit_paths(&[crate::observe::PathSlot::Path(
                "fanout",
                crate::LogPath::directory(fanout),
            )]);
            return;
        }
    }
    match fs::remove_file(path) {
        // Already gone is the same answer as gone: an index entry
        // naming a file that is not there is exactly what an eviction
        // was trying to reach.
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {
            crate::observe::OperatorDiagnostic::an_object_leaf_could_not_be_unlinked_it_stays(
                crate::FailureClass::Io,
                crate::observe::CacheAction::from_adapter(context),
            )
            .emit_paths(&[crate::observe::PathSlot::Path(
                "path",
                crate::LogPath::file(path),
            )]);
        }
    }
}

pub(super) fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Strict lowercase-hex check: exactly `len` bytes, every byte
/// `[0-9a-f]`. Untrusted-input safe (the cold rebuild walk's names come
/// from the filesystem). `pub(crate)`: `verify.rs` reuses this exact
/// predicate (— "no parallel walk implementation") rather than
/// re-deriving its own name-validation rule.
pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| hex_nibble(b).is_some())
}

/// Decode a `DIGEST_LEN * 2`-character lowercase-hex string. `None` on
/// anything that is not exactly that shape — never a panic on
/// attacker-controlled filenames. `pub(crate)`: shared with `verify.rs`
/// for the same reason [`is_lower_hex`] is.
pub(crate) fn decode_hex_digest(s: &str) -> Option<[u8; DIGEST_LEN]> {
    if s.len() != DIGEST_LEN * 2 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; DIGEST_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(*bytes.get(i * 2)?)?;
        let lo = hex_nibble(*bytes.get(i * 2 + 1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

/// `objects/<2hex>/<64hex>` — identical fanout to `store::object_path`.
/// A second `HashAlgorithm` variant must fail to compile HERE — the
/// forcing function against silently sharing one CAS namespace across
/// two algorithms (mirrors `cacheindex::digest_only`).
///
/// `pub(crate)`: `verify.rs` reuses this exact fanout rule
/// rather than re-deriving `objects/<2hex>/<64hex>` a second time.
pub(crate) fn object_path(root: &Path, id: &GrainId) -> PathBuf {
    match id.algorithm() {
        HashAlgorithm::Blake3 => {}
    }
    let hex = id.digest_hex();
    let fanout = hex.get(..2).unwrap_or("00");
    root.join("objects").join(fanout).join(&hex)
}

/// `roots/<volume>/<seq>`, with `seq` rendered as a 20-digit zero-padded leaf.
pub(super) fn root_bytes_path(root: &Path, volume: &VolumeName, seq: u64) -> PathBuf {
    root.join("roots")
        .join(volume.as_str())
        .join(format!("{seq:0ROOT_SEQ_WIDTH$}"))
}

/// `anchors/<volume>` — one file per volume, holding [`super::HeadAnchor`]'s
/// two lines.
pub(super) fn anchor_path(root: &Path, volume: &VolumeName) -> PathBuf {
    root.join("anchors").join(volume.as_str())
}

/// `anchors/<volume>.mount` — the mount-private floor, a
/// SIBLING file in the same `anchors/` directory as the shared
/// anchor above, never a directory of its own. **Cannot
/// collide with a shared anchor for a different volume**: that
/// would need some volume `V` whose name is literally
/// `"<volume>.mount"`, and [`VolumeName`]'s DNS-1123 grammar
/// (`[a-z0-9-]` only) has no `.` byte to give it — see
/// `a_volume_name_can_never_collide_with_the_mount_anchor_suffix`
/// in `super`'s tests, which pins that claim as a test rather
/// than a comment so a later widening of the grammar (e.g. a
/// hierarchical volume name) cannot silently reopen it.
pub(super) fn mount_anchor_path(root: &Path, volume: &VolumeName) -> PathBuf {
    root.join("anchors")
        .join(format!("{}.mount", volume.as_str()))
}
