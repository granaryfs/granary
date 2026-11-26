// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Cache identity: prove this directory is THIS cache, of this version,
//! populated from this origin — or refuse it whole.
//!
//! **What breaks when this module is wrong:** a directory belonging to a
//! different origin, a different chunker/hash tuple or a future format
//! version is adopted as this cache's own, and every object in it is
//! trusted on the strength of a marker nobody actually checked. The
//! refusal side is the same subject: a marker whose grammar is loose
//! admits an origin line that does not bind the server the content came
//! from. The txn sweep belongs here because it is the same question asked
//! of leftovers — whose staging is this, and may it be removed.
//!
//! It owns the marker's version constant and first key, the probe
//! `gran verify` uses for root-type detection, the renderer, the two
//! checkers (open-time and verify-time), the tuple and origin-line
//! grammars, and the orphaned-txn sweep. It does NOT own the origin VALUE
//! it renders and compares — `super::CacheOrigin`, its fields and its
//! `pin_set_digest` are the parent's vocabulary — nor `MARKER_NAME` and
//! `MARKER_MAX_BYTES`, which the parent's own layout and bounds tables
//! carry.
//!
//! It uses two siblings, in the order `paths` records: `paths`
//! and `write`. Nothing here reaches `anchor` or `index-load`.
//!
//! Out-of-line, and a child one flat
//! level under `cache/`, beside `paths`,
//! `write`, `anchor` and `index-load`.

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::AtomicU64;

use granary_core::hash::{DIGEST_LEN, HashAlgorithm};
use granary_core::thresh::CHUNKER_SPEC;

use crate::fsguard::{self, MarkerProbe};

use super::paths::{hex32, io_err, is_lower_hex, refuse_symlinked_structural_dir};
use super::write::atomic_write;
use super::{CacheError, CacheOrigin, MARKER_MAX_BYTES, MARKER_NAME};

/// Cache marker format version (bump = migration event, same discipline
/// as `store::STORE_VERSION`).
pub(super) const CACHE_VERSION: u32 = 1;

/// The cache marker's first key — mirrors `store::MARKER_KEY`'s
/// identical role, for [`probe_cache_marker`]'s positive
/// identification.
const CACHE_MARKER_KEY: &str = "granary-cache-version ";

/// Probe `path` for a granary CACHE marker, for `gran verify`'s
/// root-type detection. Mirrors `store::probe_store_marker`'s exact
/// shape and rationale: bounded, first-line-only, and opened with the
/// hostile-root discipline ([`fsguard::open_regular_read`]) so a FIFO
/// planted at the marker name cannot hang the probe instead of
/// failing it.
pub(crate) fn probe_cache_marker(path: &Path) -> MarkerProbe {
    let f = match fsguard::open_regular_read(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return MarkerProbe::Absent,
        Err(_) => return MarkerProbe::Unreadable,
    };
    let mut buf = Vec::new();
    if f.take(MARKER_MAX_BYTES + 1).read_to_end(&mut buf).is_err() {
        return MarkerProbe::Unreadable;
    }
    if buf.len() as u64 > MARKER_MAX_BYTES {
        return MarkerProbe::Unreadable;
    }
    let Ok(text) = String::from_utf8(buf) else {
        return MarkerProbe::Unreadable;
    };
    if text
        .lines()
        .next()
        .is_some_and(|l| l.starts_with(CACHE_MARKER_KEY))
    {
        MarkerProbe::Present
    } else {
        MarkerProbe::Absent
    }
}

/// Rendered marker: the format tuple (chunker/hash, reusing core's
/// own [`CHUNKER_SPEC`] and [`HashAlgorithm`] name rather than retyping
/// either string) plus the origin line that binds the server this cache
/// dir was populated from. The origin line's field count is a VALUE: absence of
/// `root_key_id` is not rendered as a placeholder, so a marker written
/// without `--root-key` and one written with it differ by field count,
/// not merely by content.
pub(super) fn marker_contents(origin: &CacheOrigin) -> String {
    let mut s = format!(
        "granary-cache-version {CACHE_VERSION}\nchunker {CHUNKER_SPEC}\nhash {}\norigin {} {}",
        HashAlgorithm::Blake3.name(),
        origin.endpoint_url,
        hex32(&origin.pin_set_digest),
    );
    if let Some(root_key_id) = origin.root_key_id {
        s.push(' ');
        s.push_str(&hex32(&root_key_id));
    }
    s.push('\n');
    s
}

/// Compare (or, for a fresh writer, create) the marker file byte-exactly
/// against `expected`. `allow_create` is true only on the writer path —
/// a read-only-degraded opener that finds no marker cannot verify what
/// it would be trusting, so absence is a mismatch there too, never a
/// silent adoption.
pub(super) fn check_marker(
    root: &Path,
    expected: &str,
    allow_create: bool,
) -> Result<(), CacheError> {
    let marker = root.join(MARKER_NAME);
    // `fsguard`, exactly as `check_marker_for_verify` does. This one was
    // missed when that one was converted, and the miss was worse here:
    // this runs on the WRITER path with the exclusive flock ALREADY
    // HELD, so a FIFO at the marker name hangs the process while
    // holding the lock, and a symlink is followed and its contents
    // echoed into the `Incompatible` diagnostic.
    let f = match fsguard::open_regular_read(&marker) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return if allow_create {
                atomic_write(
                    root,
                    &marker,
                    expected.as_bytes(),
                    &AtomicU64::new(0),
                    0o644,
                )?;
                Ok(())
            } else {
                Err(CacheError::Incompatible {
                    detail: "marker absent (no writer has initialized this cache dir)".to_owned(),
                })
            };
        }
        Err(e) => return Err(io_err("open marker")(e)),
    };
    let mut buf = Vec::new();
    // Bounded read: a real marker is ~200 bytes; MARKER_MAX_BYTES
    // (64 KiB) is generous headroom. This read is bounded like every
    // other read in this module (index files, objects and roots all
    // bound their reads the same way) — an over-cap marker is refused
    // as Incompatible, the same class any other unparseable marker is.
    f.take(MARKER_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(io_err("read marker"))?;
    if buf.len() as u64 > MARKER_MAX_BYTES {
        return Err(CacheError::Incompatible {
            detail: format!("marker exceeds {MARKER_MAX_BYTES} bytes"),
        });
    }
    let found = String::from_utf8(buf).map_err(|_| CacheError::Incompatible {
        detail: "marker is not utf-8".to_owned(),
    })?;
    if found == expected {
        Ok(())
    } else {
        Err(CacheError::Incompatible {
            detail: format!("marker mismatch:\n--- cache\n{found}--- expected\n{expected}"),
        })
    }
}

/// The version/chunker/hash TUPLE lines only — the ADDRESSING
/// half of the marker handshake `marker_contents`' first three lines
/// render, shared verbatim but never including the origin line.
/// `open_for_verify` requires the origin line present-and-well-formed
/// WITHOUT comparing its value (verify supplies no origin and needs
/// none — it reads content-addressed objects and COMPARES them against
/// an index, never serving or writing trust-bearing state). **This
/// exception is limited to `open_for_verify`: the usual origin check
/// is byte-exact on open in both writer and read-only-degraded modes, with any
/// mismatch producing `CacheError::Incompatible`.** Every OTHER
/// opener still compares the origin line byte-exactly; verify requires
/// its presence and well-formedness without comparing its value.
fn marker_tuple_lines() -> [String; 3] {
    [
        format!("granary-cache-version {CACHE_VERSION}"),
        format!("chunker {CHUNKER_SPEC}"),
        format!("hash {}", HashAlgorithm::Blake3.name()),
    ]
}

/// Whether `line` is a well-formed `origin` marker line — the SAME
/// grammar [`marker_contents`] renders: `origin <endpoint>
/// <pin-digest-hex> [<root-key-hex>]`, exactly 3 or 4
/// whitespace-separated fields, no trailing separator. SHAPE only — the
/// field VALUES are never compared here. `endpoint`'s only
/// checked property is non-empty: [`validate_origin_grammar`] is what
/// refuses whitespace/control bytes in it at WRITE time, so any writer
/// that reaches this marker already satisfies that; this reader does
/// not re-derive the write-side rule.
fn origin_line_is_well_formed(line: &str) -> bool {
    let mut fields = line.split(' ');
    if fields.next() != Some("origin") {
        return false;
    }
    let Some(endpoint) = fields.next() else {
        return false;
    };
    if endpoint.is_empty() {
        return false;
    }
    let Some(pin_digest) = fields.next() else {
        return false;
    };
    // A 32-byte digest renders as DIGEST_LEN * 2 lowercase hex chars —
    // the same width `hex32` produces for both the pin-set digest and
    // the optional root-key id.
    if !is_lower_hex(pin_digest, DIGEST_LEN * 2) {
        return false;
    }
    match fields.next() {
        None => fields.next().is_none(),
        Some(root_key) => is_lower_hex(root_key, DIGEST_LEN * 2) && fields.next().is_none(),
    }
}

/// `open_for_verify`'s own marker check: compares the
/// version/chunker/hash TUPLE byte-exactly, requires the origin line
/// present-and-well-formed without comparing its value, and is bounded
/// the same way [`check_marker`] is — an over-cap or unreadable marker
/// is `Incompatible`, the same class a mismatched one is. Never creates
/// the marker — a verify open must not repair a missing one, only
/// classify or refuse it.
pub(super) fn check_marker_for_verify(root: &Path) -> Result<(), CacheError> {
    let marker = root.join(MARKER_NAME);
    // `fsguard`, not a bare `File::open`: verify is pointed at roots
    // this process does not own, and a FIFO at the marker name would
    // block this open forever rather than fail it.
    let f = fsguard::open_regular_read(&marker).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            CacheError::Incompatible {
                detail: "marker absent (no writer has initialized this cache dir)".to_owned(),
            }
        } else {
            io_err("open marker")(e)
        }
    })?;
    let mut buf = Vec::new();
    f.take(MARKER_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(io_err("read marker"))?;
    if buf.len() as u64 > MARKER_MAX_BYTES {
        return Err(CacheError::Incompatible {
            detail: format!("marker exceeds {MARKER_MAX_BYTES} bytes"),
        });
    }
    let found = String::from_utf8(buf).map_err(|_| CacheError::Incompatible {
        detail: "marker is not utf-8".to_owned(),
    })?;
    let mut lines = found.split('\n');
    for expected_line in marker_tuple_lines() {
        match lines.next() {
            Some(l) if l == expected_line => {}
            _ => {
                return Err(CacheError::Incompatible {
                    detail: format!(
                        "marker tuple line disagrees with this build (expected {expected_line:?})"
                    ),
                });
            }
        }
    }
    match lines.next() {
        Some(origin_line) if origin_line_is_well_formed(origin_line) => {}
        _ => {
            return Err(CacheError::Incompatible {
                detail: "marker origin line is absent or malformed".to_owned(),
            });
        }
    }
    // The file must end exactly here: one trailing empty string from
    // the final '\n' and nothing after it — trailing content past the
    // origin line is the same tamper class a bad tuple line is.
    match (lines.next(), lines.next()) {
        (Some(""), None) => Ok(()),
        _ => Err(CacheError::Incompatible {
            detail: "marker has trailing content after the origin line".to_owned(),
        }),
    }
}

/// The marker's `origin` line is plain `key value` text, one line, a
/// fixed field count — an `endpoint_url` containing ASCII whitespace or
/// a control byte would silently shift the field count (a space) or
/// inject a line (`\n`), corrupting the byte-exact grammar
/// [`check_marker`] relies on. Checked BEFORE any disk touch, so a bad
/// origin never even creates the cache directory.
pub(super) fn validate_origin_grammar(origin: &CacheOrigin) -> Result<(), CacheError> {
    if origin.endpoint_url.is_empty() {
        return Err(CacheError::Incompatible {
            detail: "origin endpoint_url is empty".to_owned(),
        });
    }
    if let Some(bad) = origin
        .endpoint_url
        .bytes()
        .find(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(CacheError::Incompatible {
            detail: format!(
                "origin endpoint_url contains byte 0x{bad:02x} (ASCII whitespace or control), \
                 which would corrupt the marker's line-based grammar"
            ),
        });
    }
    // The marker this origin renders must fit the SAME bound a reopen
    // enforces (`MARKER_MAX_BYTES`), or a fresh `--cache-dir` open would
    // succeed and then every reopen of that dir would fail permanently
    // with "marker exceeds …". The endpoint URL is the only unbounded
    // field, so an over-long one is refused here, symmetrically, at write
    // time.
    let marker_len = marker_contents(origin).len() as u64;
    if marker_len > MARKER_MAX_BYTES {
        return Err(CacheError::Incompatible {
            detail: format!(
                "origin renders a {marker_len}-byte marker, over the {MARKER_MAX_BYTES}-byte cap \
                 a reopen enforces — the endpoint URL is too long for a cache dir"
            ),
        });
    }
    Ok(())
}

/// Clear every NON-DIRECTORY name directly under `txn/` on a WRITER
/// open, before `load_index` — the exclusive lock just acquired proves
/// no other writer can be mid-`atomic_write`, so every such entry is
/// orphaned staging from a crashed prior writer, or a plant
/// (`store::Store::open`'s established-open sweep is the precedent).
/// Never called on the degraded-reader path: a reader must not mutate
/// the directory at all.
///
/// **Every one of them has to go, and leaving any is the more dangerous
/// choice.** `atomic_write` stages under `<pid>-<counter>`; numeric
/// pids are reused and every fresh process restarts its counter at
/// zero, so ANY name planted at `txn/<pid>-0` makes `create_new` fail
/// `EEXIST` for that pid forever — a permanent wedge of every write
/// this cache performs, and the sweep is the only thing that ever
/// clears a staging name. A symlink, a FIFO, a socket and a device node
/// all wedge it identically, and `unlink(2)` removes all of them, so
/// nothing distinguishes them from a regular leftover here. Removing
/// them is safe for the same reason the rest of the sweep is:
/// `remove_file` never follows its FINAL component, so a link's NAME is
/// unlinked and its target is untouched.
///
/// A DIRECTORY is the one entry still left alone (F6): it is an anomaly
/// rather than staging, `remove_file` cannot remove it anyway, and
/// sweeping directories is how a mistargeted `txn/` holding a user's own
/// files would get deleted.
///
/// **An entry that cannot be removed is skipped, not propagated.** The
/// widened sweep must not turn a per-name wedge into a per-cache one: an
/// `EPERM`/`EACCES` (a `txn/` this process cannot write, an
/// immutable-flagged node) fails ONE unlink, and returning that error
/// would fail every writer open of this cache from then on. It is
/// warned, counted and stepped over; the staging name it occupies stays
/// wedged for the pid that would use it, which is exactly the cost the
/// entry already had.
///
/// **STATED LIMIT: a `txn/` where NOTHING can be staged still reports a
/// healthy open.** The skip cannot tell "one stubborn name" from "this
/// process cannot write this directory at all" — a `0o555` `txn/` is
/// both at once. In the second case every `atomic_write` fails at its
/// `create_new`, and `insert` and `put_root_bytes` each warn and
/// return, so the cache caches nothing while the open looks well. What
/// an operator sees is one warn PER WRITE instead of one at open.
///
/// **What it does not cost: the cache's existing contents.**
/// `WriterState::insert` STAGES before it evicts — `StagedWrite::stage`
/// first, `evict_to_fit` between the staging and the rename — so an
/// insert into a cache that cannot stage fails at `create_new` having
/// unlinked nothing. It declines, warns, and leaves the cache exactly
/// as it found it, however many times it is retried. Evicting first
/// would drain a cache at quota down to the room the largest attempted
/// insert needed, losing objects it could not replace.
///
/// **What it still costs: one warning per write, and no operator signal
/// at open.** The skip above cannot tell "one stubborn name" from "this
/// process cannot write this directory at all", so the open still
/// reports healthy. A writer health flag — set once staging is proven
/// unusable and reported at close — remains a design change, and is not
/// implemented.
#[expect(
    clippy::disallowed_methods,
    reason = "the line above just refused a symlinked txn/ (lstat, fail closed); read_dir over \
              a confirmed-real directory and remove_file by NAME (never through a path derived \
              from following anything) are the two calls this sweep needs — `file_type()`, \
              never a followed stat, is what proves each removed name is not a directory. \
              Everything that is not a directory is cleared: unlink removes a symlink, FIFO, \
              socket or device node as readily as a regular file, and each of them wedges \
              create_new for its staging name just as permanently"
)]
pub(super) fn sweep_orphaned_txn_files(root: &Path) -> Result<(), CacheError> {
    let txn_dir = root.join("txn");
    // txn/ itself must be a real directory, never a symlink — the
    // cache never creates one there, so a symlink is foreign, and
    // following it would sweep (delete) files OUTSIDE the cache root.
    // Reuse the same non-follow structural guard as open-time creation;
    // recheck txn/ after acquiring the writer lock. A non-directory that
    // is not a symlink is rejected by `read_dir` below.
    refuse_symlinked_structural_dir(&txn_dir, "stat txn/")?;
    let mut swept: u64 = 0;
    let mut skipped: u64 = 0;
    for entry in fs::read_dir(&txn_dir).map_err(io_err("read txn/"))? {
        let entry = entry.map_err(io_err("read txn/ entry"))?;
        // `file_type()`, not `path().is_file()`: it reports a symlinked
        // entry AS a symlink rather than following it, which is what
        // lets this decide by ENTRY TYPE. Every non-directory name is
        // swept as a NAME (`remove_file` does not follow its final
        // component, so a link's target is never touched); a directory
        // is the one entry left alone.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            let path = entry.path();
            if fs::remove_file(&path).is_ok() {
                swept = swept.saturating_add(1);
            } else {
                // A name this sweep cannot clear is SKIPPED, never
                // propagated. Propagating turns one un-unlinkable entry
                // (EPERM/EACCES on a txn/ this process cannot write, an
                // immutable-flagged node) into a permanent failure of
                // every writer open of this cache — strictly worse than
                // the wedge of the staging name that the entry itself
                // causes.
                skipped = skipped.saturating_add(1);
                crate::observe::OperatorDiagnostic::cache_writer_open_an_orphaned_txn_entry_could_not(crate::FailureClass::Io).emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::directory(&path))]);
            }
        }
    }
    if swept > 0 || skipped > 0 {
        crate::observe::OperatorDiagnostic::cache_writer_open_swept_orphaned_txn_staging_files(
            swept, skipped,
        )
        .emit();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
