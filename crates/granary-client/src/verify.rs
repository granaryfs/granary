// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `gran verify`: walks a store or cache root and re-hashes every
//! object against its content address, reporting what it finds. See
//! `run_verify()` for the top-level dispatch; each mode's own function
//! states what it does and does not touch. Filenames and file CONTENTS
//! under a verify root are ATTACKER-INFLUENCED (this walks arbitrary
//! on-disk state), so every read here is bounded and every path byte is
//! treated as untrusted. An `objects/` tree that exists but cannot be
//! enumerated is a REFUSAL (cannot-open), never a silent empty/clean
//! result — see `scan_objects()`.
//!
//! **This verb REPORTS and REPAIRS NOTHING. It performs no unlink, no
//! rename, no truncation, no directory creation and no index write
//! under the root it is pointed at** — the only state it changes is an
//! advisory `flock` on a cache's `lock` file, held so the
//! snapshot/journal pair reads coherently against a concurrent
//! compaction. That is a deliberate design constraint, not an
//! omission. Every repair verb wants to name its target by
//! RECONSTRUCTING a path (`root/objects/<fanout>/<hex>`) long after
//! the one-time check that the intervening directories were real
//! directories, and whoever can write into the root during the walk —
//! measured at roughly 1.7s for 20k objects — can swap a component for
//! a symlink in between and steer the repair outside the root. Repair
//! returns when the operations it needs are descriptor-relative
//! (anchor the root once, descend with `openat` +
//! `O_NOFOLLOW|O_DIRECTORY`, act relative to the pinned directory), so
//! that no intermediate component is ever re-resolved by name.
//!
//! **The residual that remains, stated because it is the same shape
//! one level up.** Every open here carries `O_NOFOLLOW`, and that
//! binds the FINAL component only. An attacker who swaps
//! `objects/<fanout>` for a symlink after this walk has enumerated it
//! redirects everything that follows — and the sink is larger than a
//! single file. `fs::read_dir` on the reconstructed fanout path FOLLOWS
//! the swapped component, so the redirected listing yields one
//! `foreign` line per entry: the complete NAME LIST of an
//! operator-readable directory anywhere on the filesystem, and the
//! attacker gets 256 independent shots at the window (one per fanout)
//! in a walk that takes seconds. The impact is DISCLOSURE — directory
//! listings, paths and digests on stdout — and never a write, because
//! there are no writes. Closing it needs the same descriptor-relative
//! reader that repair needs, which is why the two are one register row
//! and not two.
//!
//! The HARD-LINK case is tracked separately and is only PARTLY closed.
//! A leaf with more than one link is refused outright (see
//! `classify_object_file`), which kills the no-race form; but an
//! attacker who links a victim in and then waits for the ORIGINAL
//! pathname to disappear leaves the planted leaf at one link, and
//! nothing at this layer tells that apart from an object this project
//! created. The negative was confirmed directly: no metadata field
//! decides it — `st_dev` matches for EVERY hard link by
//! definition, and mode, uid, birthtime and inode describe present
//! state rather than creation history. Closing it needs trusted
//! creation-time provenance or prevention, not another `fstat`
//! predicate. Register row, owner: the descriptor-relative *at migration.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::ExitCode;

use granary_core::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use granary_store::bounds::META_MAX_BYTES;

use crate::cache::{self, Cache, VerifyCache, VerifyIndex, decode_hex_digest, is_lower_hex};
use crate::fsguard::{self, MarkerProbe};
use crate::store::{self};

/// One finding kind, SIX in total: `corrupt` (hash mismatch), `dropped`
/// (an index entry whose file is gone — cache only), `adopted` (a file
/// the index does not know — cache only), `foreign` (name/fanout/
/// regular-file violation, a validated entry that failed to open, stat
/// or read, a fanout directory that could not be enumerated at all,
/// or an INDEX FILE that exists and cannot be trusted — cache only for
/// that last case), `oversized` (exceeds `META_MAX_BYTES`),
/// `size-mismatch` (an indexed, correctly-hashed object whose RECORDED
/// size differs from its actual size — cache only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindingKind {
    Corrupt,
    Dropped,
    Adopted,
    Foreign,
    Oversized,
    SizeMismatch,
}

impl FindingKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt",
            Self::Dropped => "dropped",
            Self::Adopted => "adopted",
            Self::Foreign => "foreign",
            Self::Oversized => "oversized",
            Self::SizeMismatch => "size-mismatch",
        }
    }
}

/// One `gran verify` finding, pre-encoding. `path` is ROOT-RELATIVE RAW
/// BYTES (a Unix path is arbitrary bytes) — percent-encoded only
/// at output time ([`encode_finding_line`]), never earlier, so no
/// information is lost before it must be.
#[derive(Debug)]
struct Finding {
    kind: FindingKind,
    path: Vec<u8>,
    expected: String,
    actual: String,
}

fn finding(
    kind: FindingKind,
    path: Vec<u8>,
    expected: impl Into<String>,
    actual: impl Into<String>,
) -> Finding {
    Finding {
        kind,
        path,
        expected: expected.into(),
        actual: actual.into(),
    }
}

/// every byte outside `[A-Za-z0-9._/-]` becomes `%XX` uppercase
/// hex — deterministic, injection-proof (a TAB or NEWLINE in an
/// attacker-controlled filename can never inject a field or a whole
/// line into this machine-parsed format), reversible.
fn percent_encode_path(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `<kind>\t<encoded-relpath>\t<expected>\t<actual>` — one line, no
/// trailing newline (the caller's `writeln!` supplies it).
fn encode_finding_line(f: &Finding) -> String {
    format!(
        "{}\t{}\t{}\t{}",
        f.kind.as_str(),
        percent_encode_path(&f.path),
        f.expected,
        f.actual
    )
}

// --------------------------------------------------------------- the walk

/// One classified `objects/` entry from the raw scan — BEFORE any index
/// cross-reference, which only a cache root's index audit performs.
#[derive(Debug)]
enum ScanOutcome {
    /// Name/fanout/regular-file violation, OR a validated name (64-hex,
    /// correct fanout, regular per `DirEntry::file_type`) that failed
    /// to open/stat/read for a reason other than `NotFound`. `claimed`
    /// carries the id in the second case (the name IS a real,
    /// determinable grain id — just transiently unreadable) and is
    /// `None` in the first (no id can be derived from a malformed
    /// name at all). A cross-referencing caller MUST still count a
    /// `Some` id as "seen on disk": the file is there, only unread,
    /// so it must never ALSO be reported `dropped` and evicted for the
    /// same reason it could not be opened.
    Foreign { claimed: Option<GrainId> },
    /// Vanished between enumeration and open — a concurrent
    /// eviction under a live writer verify does not hold the lock
    /// against, never a finding.
    Vanished,
    /// The fanout directory itself could not be enumerated (a
    /// non-`NotFound` error opening it) — as opposed to one that
    /// vanished between the top-level listing and this open, which is
    /// a concurrent removal and never reported. Any object that would
    /// have lived under this fanout could still be sitting on disk,
    /// unseen this run; a cross-referencing caller must not conclude
    /// `dropped` for indexed ids under this prefix on that evidence.
    FanoutUnreadable { dir_hex: String },
    /// A `DirEntry` at the TOP level of `objects/` (the fanout listing
    /// itself) came back an `Err` from the `read_dir` iterator — before
    /// even a name could be read, so there is no `dir_hex` to scope the
    /// doubt to the way [`Self::FanoutUnreadable`] does. Any fanout
    /// could be the one this entry would have named; a
    /// cross-referencing caller must not conclude `dropped` for ANY
    /// indexed id this run on that evidence.
    TopLevelUnreadable,
    /// Opened; its size (via the OPEN DESCRIPTOR's own metadata, never
    /// the enumeration-time `DirEntry`'s, so the size checked and the
    /// bytes hashed always come from the same open) exceeds
    /// [`META_MAX_BYTES`].
    Oversized { claimed: GrainId, actual_size: u64 },
    /// Hashed successfully: the id its NAME claims, and the id its
    /// BYTES actually hash to.
    Hashed {
        claimed: GrainId,
        actual_digest: GrainId,
        actual_size: u64,
    },
}

struct ScanEntry {
    rel_path: Vec<u8>,
    outcome: ScanOutcome,
}

/// Fail-closed guard for the walk's OWN structural-directory safety,
/// independent of whatever the root's open-time check already
/// confirmed: `read_dir` follows a symlinked INTERMEDIATE path
/// component regardless of any `O_NOFOLLOW` a later file open under it
/// might carry (`O_NOFOLLOW` guards only the LAST component), so a
/// caller that relied solely on an earlier, one-time check would still
/// be exposed to a link swapped in afterward, or to any future call
/// site that reaches this function without running that check at all —
/// a guard that only ever runs once, elsewhere, is not a guard.
/// Exhaustive on the `lstat` result and FAIL CLOSED on the unexpected
/// arm: `is_ok_and` would treat a transient lstat error (`EIO`,
/// `EACCES`) as "not a symlink" and fall through to a `read_dir` a
/// genuinely-planted link could then be walked straight through.
fn refuse_symlinked_objects_dir(root: &Path) -> Result<(), String> {
    let path = root.join("objects");
    match fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_symlink() => Err(format!(
            "{} is a symlink; gran verify refuses to walk through a symlinked structural \
             directory",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Enumerate EVERY entry under `<root>/objects/` and classify it — no
/// admit-or-drop wrapper; every entry gets an outcome, `Foreign`
/// included, never silence. Bounded, buffered reads throughout: a file
/// is opened once and its size AND content both come from that same
/// descriptor, never a second path-based stat that a TOCTOU could see
/// something different through. Refuses (rather than walks) a symlinked
/// `objects/` before touching it at all — see
/// [`refuse_symlinked_objects_dir`]. An `objects/` that is absent is a
/// legitimately empty tree (`NotFound`, exit 0 if nothing else is
/// found); one that exists but cannot be enumerated for any OTHER
/// reason is a REFUSAL (propagated as `Err`, cannot-open, exit 2) —
/// this walk never reports a tree clean that it could not read.
#[expect(
    clippy::too_many_lines,
    reason = "one two-level walk (fanout dirs, then their files) with every \
              exit classified inline — splitting the classification out \
              would scatter the exhaustive outcome list this function's \
              own doc promises across helpers"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "both read_dir calls walk this verify pass's own subject tree — the top-level one \
              is reached only after refuse_symlinked_objects_dir already refused a symlinked \
              objects/, and the fanout-level one is over dir_path, which this same loop just \
              classified via file_type() (not a followed stat) as dir_file_type.is_dir() — a \
              read-only enumeration, this module never writes"
)]
fn scan_objects(root: &Path, err: &mut impl Write) -> Result<Vec<ScanEntry>, String> {
    refuse_symlinked_objects_dir(root)?;
    let objects_dir = root.join("objects");
    let mut out = Vec::new();
    let top = match fs::read_dir(&objects_dir) {
        Ok(top) => top,
        // Absent objects/: a legitimately empty store/cache, nothing to
        // scan.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        // Anything else (a regular file where a directory belongs,
        // EACCES, ...) is a REFUSAL, never a silent empty result: verify
        // must not report a tree clean that it could not even read.
        Err(e) => return Err(format!("{}: {e}", objects_dir.display())),
    };
    for dir_entry in top {
        let Ok(dir_entry) = dir_entry else {
            // The `read_dir` iterator itself failed to produce this
            // entry (a transient I/O error reading the directory
            // stream) — no name was ever read, so there is no `dir_hex`
            // to record. Reported, never silently skipped: silence here
            // is exactly what let `find_dropped()` conclude `dropped`
            // for an indexed id whose fanout this entry might have
            // named.
            out.push(ScanEntry {
                rel_path: b"objects/?".to_vec(),
                outcome: ScanOutcome::TopLevelUnreadable,
            });
            continue;
        };
        let dir_name = dir_entry.file_name();
        let dir_hex = dir_name.to_str().filter(|s| is_lower_hex(s, 2));
        let Ok(dir_file_type) = dir_entry.file_type() else {
            let mut rel = b"objects/".to_vec();
            rel.extend_from_slice(dir_name.as_bytes());
            out.push(ScanEntry {
                rel_path: rel,
                outcome: unknown_type_top_level_outcome(dir_hex),
            });
            continue;
        };
        let Some(dir_hex) = dir_hex.filter(|_| dir_file_type.is_dir()) else {
            let mut rel = b"objects/".to_vec();
            rel.extend_from_slice(dir_name.as_bytes());
            out.push(ScanEntry {
                rel_path: rel,
                outcome: ScanOutcome::Foreign { claimed: None },
            });
            continue;
        };
        let dir_path = dir_entry.path();
        let sub = match fs::read_dir(&dir_path) {
            Ok(sub) => sub,
            // The fanout dir vanished between the top-level listing and
            // this open: a concurrent removal, not a finding — mirrors
            // `classify_object_file()`'s own `NotFound` arm for a single
            // object.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            // Any OTHER error means the fanout dir EXISTS but could not
            // be enumerated: any object that would live under it may
            // still be on disk, just unseen this run. Report it (never
            // silent) but as its own outcome — never `Foreign` with a
            // derived id and never left to `find_dropped()` to conclude
            // `dropped` for ids under this prefix, which would report
            // objects this run never actually looked at.
            Err(_) => {
                let mut rel = b"objects/".to_vec();
                rel.extend_from_slice(dir_hex.as_bytes());
                out.push(ScanEntry {
                    rel_path: rel,
                    outcome: ScanOutcome::FanoutUnreadable {
                        dir_hex: dir_hex.to_owned(),
                    },
                });
                continue;
            }
        };
        for file_entry in sub {
            let Ok(file_entry) = file_entry else {
                // The `read_dir` iterator failed to produce this ONE
                // entry inside an otherwise-enumerable fanout dir — the
                // name was never read, so there is no way to know
                // which id (if any) it would have named. Treated the
                // same as the whole fanout being unreadable
                // (`ScanOutcome::FanoutUnreadable`): reported, and the
                // prefix is marked so `find_dropped()` cannot conclude
                // `dropped` for an indexed id that might be exactly
                // this unread entry.
                let mut rel = b"objects/".to_vec();
                rel.extend_from_slice(dir_hex.as_bytes());
                rel.push(b'/');
                rel.push(b'?');
                out.push(ScanEntry {
                    rel_path: rel,
                    outcome: ScanOutcome::FanoutUnreadable {
                        dir_hex: dir_hex.to_owned(),
                    },
                });
                continue;
            };
            let file_name = file_entry.file_name();
            let mut rel = b"objects/".to_vec();
            rel.extend_from_slice(dir_hex.as_bytes());
            rel.push(b'/');
            rel.extend_from_slice(file_name.as_bytes());

            // The NAME is decoded BEFORE the entry's kind is consulted,
            // and the order matters: a `file_type()` that FAILS must
            // still be able to say WHICH id it could not classify.
            // Reported with no id, `find_dropped()` concludes `dropped`
            // for an object that is sitting right there — the same
            // false-report class the `DirEntry`-iterator arms already
            // close; `file_type()` failure needs that protection too.
            let claimed = file_name
                .to_str()
                .filter(|s| is_lower_hex(s, DIGEST_LEN * 2))
                .filter(|h| h.get(..2) == Some(dir_hex))
                .and_then(decode_hex_digest)
                .map(|digest| GrainId::from_parts(HashAlgorithm::Blake3, digest));

            let Ok(file_type) = file_entry.file_type() else {
                out.push(ScanEntry {
                    rel_path: rel,
                    // `claimed` and not `None`: see above. No helper —
                    // the decision here IS `Foreign { claimed }`, and a
                    // pure function that returns its own argument
                    // cannot be given a test that fails.
                    outcome: ScanOutcome::Foreign { claimed },
                });
                continue;
            };
            // A bad name, a fanout mismatch, or a non-regular entry: no
            // id may be attributed to it, so `claimed` is dropped here
            // deliberately rather than carried into the finding.
            //
            // **This is ASYMMETRIC with the open-time refusals below,
            // and the asymmetry is the intended answer rather than an
            // oversight.** A symlink or FIFO that `file_type()` can
            // SEE at this name means the object is definitively not
            // there: `foreign` here plus `dropped` from
            // `find_dropped()` is two true statements about one id, and
            // an operator needs both (the path is occupied AND the
            // object is missing). A symlink or FIFO that appears only
            // between this check and `classify_object_file`'s open is a
            // different state of knowledge — a regular file with the
            // right name was there a moment ago — so that path stays
            // conservative and reports `foreign` alone, never inventing
            // a `dropped` for an object it last saw present.
            let Some(claimed) = claimed.filter(|_| file_type.is_file()) else {
                out.push(ScanEntry {
                    rel_path: rel,
                    outcome: ScanOutcome::Foreign { claimed: None },
                });
                continue;
            };
            let outcome = classify_object_file(&file_entry.path(), claimed, err, &rel);
            if matches!(outcome, ScanOutcome::Vanished) {
                continue; // a concurrent eviction, never a finding
            }
            out.push(ScanEntry {
                rel_path: rel,
                outcome,
            });
        }
    }
    Ok(out)
}

/// What a TOP-LEVEL `objects/` entry becomes when
/// `DirEntry::file_type()` itself fails — the kind could not be
/// determined, so the entry was never enumerated as a fanout dir.
///
/// A valid two-hex NAME is the whole question. If this entry might
/// have been the fanout `<hex>/`, then every indexed id under that
/// prefix is one this run did NOT look at, and concluding `dropped`
/// for them on that evidence is a false finding —
/// [`ScanOutcome::FanoutUnreadable`] is the outcome that already
/// scopes exactly this doubt, and it still emits its own `foreign`
/// line, so nothing is hidden. A name that is not two hex digits can
/// hold no indexed id at all, so plain `Foreign` is honest there.
///
/// Split out as a pure function because a FAILING
/// `DirEntry::file_type()` is not constructible portably — on APFS and
/// ext4 the kind comes from `readdir`'s `d_type` and never stats — so
/// the DECISION is what a test can pin; the call site is verified by
/// reading.
fn unknown_type_top_level_outcome(dir_hex: Option<&str>) -> ScanOutcome {
    match dir_hex {
        Some(hex) => ScanOutcome::FanoutUnreadable {
            dir_hex: hex.to_owned(),
        },
        None => ScanOutcome::Foreign { claimed: None },
    }
}

/// Open, size-check and hash ONE already-validated candidate: the
/// caller has already confirmed the name is 64-hex, matches its fanout
/// dir, and the entry is a regular file (per its own, non-following
/// `DirEntry::file_type`) — this function's only job is the open+hash
/// step, and its `NotFound` arm is what makes the case of a live writer
/// unlinking an object between enumeration and open safe: a vanished
/// file is [`ScanOutcome::Vanished`], never `Foreign`, so a healthy
/// cache racing a concurrent eviction is never misreported as corrupt.
/// A single open descriptor serves BOTH the size check and the content
/// read, so the other half of the race (replaced after open) cannot
/// mislead either: the bytes hashed are exactly the bytes whose size
/// was just checked. Every `Foreign` this function returns carries
/// `claimed: Some(claimed)` — the caller already proved the name is a
/// real, determinable grain id before calling in, so a transient open/
/// stat/read failure here (`EACCES`, `EMFILE`, `EISDIR`, ...) must
/// still count as "this id was seen on disk" for any index
/// cross-reference, never ALSO reported `dropped` and evicted for the
/// very object it just failed to open.
fn classify_object_file(
    path: &Path,
    claimed: GrainId,
    err: &mut impl Write,
    rel_for_log: &[u8],
) -> ScanOutcome {
    // `fsguard`, not a bare `File::open`. The caller's
    // `DirEntry::file_type()` was honest when it ran, but this is a
    // FRESH open by RECONSTRUCTED path: between the two, whoever can
    // write into `objects/<fanout>/` can swap the leaf for a SYMLINK
    // (a plain open follows it and verify would hash and report bytes
    // from outside the root) or for a FIFO (a plain `O_RDONLY` open
    // blocks until a writer appears — verify hangs MID-WALK, having
    // reported nothing). `O_NOFOLLOW` and `O_NONBLOCK` refuse both,
    // and the `Err(_)` arm below classifies them the same way it
    // already classifies `EACCES`: foreign, and still SEEN.
    match fsguard::open_regular_read(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let _ = writeln!(
                err,
                "gran verify: {} vanished during the walk (concurrent eviction); skipping",
                String::from_utf8_lossy(rel_for_log)
            );
            ScanOutcome::Vanished
        }
        Err(_) => ScanOutcome::Foreign {
            claimed: Some(claimed),
        },
        Ok(f) => match f.metadata() {
            Err(_) => ScanOutcome::Foreign {
                claimed: Some(claimed),
            },
            // A HARD LINK defeats every part of the open discipline:
            // it is not a symlink (so `O_NOFOLLOW` does not apply), it
            // does not block (so `O_NONBLOCK` is irrelevant), and
            // `fstat` calls it a regular file. It also needs NO RACE —
            // `link(2)` requires search permission on the target's
            // directory and write on the destination, not read on the
            // target and not root, and macOS has no
            // `protected_hardlinks` equivalent. So an attacker who can
            // write into `objects/` links any same-volume file to a
            // 64-hex name OF THEIR CHOOSING and this walk reports
            // either its BLAKE3 digest (a content-confirmation oracle
            // over a file they cannot read) or, past the size bound,
            // its exact length. Both land on stdout, under an
            // operator's privileges rather than theirs.
            //
            // Refused here rather than deferred with the other
            // path-resolution residuals, because the planned
            // descriptor-relative fix does NOT close it:
            // `openat(fanout_fd, name, O_NOFOLLOW)` opens a hard link
            // exactly as `open` does. Safe by construction: every
            // object this project writes is staged under `txn/` and
            // RENAMED into place, so a legitimate object always has
            // exactly one link.
            //
            // **`> 1`, NOT `!= 1`, and the difference is
            // load-bearing.** A file whose last
            // directory entry is removed while a descriptor is still
            // open reports a link count of ZERO — that is a concurrent
            // eviction by a live writer, the case the `NotFound` arm
            // above catches when it loses the race earlier. Folding it
            // in with the hard links would report a HEALTHY evicted
            // object as `foreign` and exit 1, inventing a finding out
            // of ordinary cache behaviour.
            //
            // **What this does NOT close, stated rather than implied:**
            // an attacker who links a victim file here and then waits
            // for the ORIGINAL pathname to go away (a temporary file,
            // say) leaves the planted leaf as the sole link, and it
            // passes. Nothing available at this layer distinguishes
            // that from a legitimately created object. The guard closes
            // the case that needs no cooperation from the victim; the
            // rest is a register row, not a claim of closure.
            Ok(meta) if meta.nlink() == 0 => {
                let _ = writeln!(
                    err,
                    "gran verify: {} was unlinked during the walk (concurrent eviction); \
                     skipping",
                    String::from_utf8_lossy(rel_for_log)
                );
                ScanOutcome::Vanished
            }
            Ok(meta) if meta.nlink() > 1 => ScanOutcome::Foreign {
                claimed: Some(claimed),
            },
            Ok(meta) => {
                let actual_size = meta.len();
                if actual_size > META_MAX_BYTES {
                    ScanOutcome::Oversized {
                        claimed,
                        actual_size,
                    }
                } else {
                    let mut buf = Vec::new();
                    match f.take(META_MAX_BYTES + 1).read_to_end(&mut buf) {
                        Err(_) => ScanOutcome::Foreign {
                            claimed: Some(claimed),
                        },
                        Ok(_) if buf.len() as u64 > META_MAX_BYTES => ScanOutcome::Oversized {
                            claimed,
                            actual_size: buf.len() as u64,
                        },
                        // The size travels with the bytes that were
                        // actually HASHED, never with the earlier
                        // `metadata` call: a digest that matches
                        // `claimed` pins the content, and therefore its
                        // length, so `buf` is authoritative while
                        // `meta.len()` describes whatever the file was
                        // before the read. They differ only if the file
                        // changed in between — and it is precisely that
                        // case where recording the stale figure would
                        // write a size into the index that disagrees
                        // with the verified bytes.
                        Ok(_) => ScanOutcome::Hashed {
                            claimed,
                            actual_digest: GrainId::of(&buf),
                            actual_size: buf.len() as u64,
                        },
                    }
                }
            }
        },
    }
}

/// REPORT-ONLY object-integrity walk: re-hashes every entry
/// and reports `corrupt`/`foreign`/`oversized` findings, NEVER an index
/// finding. Shared by a STORE root (which has no index at all) and a
/// CACHE root whose writer lock is held by someone else, or whose index
/// exists and cannot be trusted. No mode of this verb mutates
/// anything — see the module doc.
///
/// # Errors
/// A `String` describing why `objects/` is unsafe to walk at all (see
/// [`refuse_symlinked_objects_dir`]) — never partial output.
fn report_only_walk(root: &Path, err: &mut impl Write) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    for entry in scan_objects(root, err)? {
        match entry.outcome {
            ScanOutcome::Vanished => {}
            ScanOutcome::Foreign { .. }
            | ScanOutcome::FanoutUnreadable { .. }
            | ScanOutcome::TopLevelUnreadable => {
                findings.push(finding(FindingKind::Foreign, entry.rel_path, "-", "-"));
            }
            ScanOutcome::Oversized { actual_size, .. } => {
                findings.push(finding(
                    FindingKind::Oversized,
                    entry.rel_path,
                    "-",
                    actual_size.to_string(),
                ));
            }
            ScanOutcome::Hashed {
                claimed,
                actual_digest,
                ..
            } => {
                if actual_digest != claimed {
                    findings.push(finding(
                        FindingKind::Corrupt,
                        entry.rel_path,
                        claimed.to_string(),
                        actual_digest.to_string(),
                    ));
                }
            }
        }
    }
    Ok(findings)
}

/// CACHE AUDIT mode: walk `objects/`, classify every entry against the
/// index [`Cache::open_for_verify`] already loaded, and REPORT. This
/// function writes NOTHING.
///
/// Having the index is what lets it report the three findings the
/// store-mode walk cannot — `adopted` (a file the index does not
/// know), `dropped` (an index entry whose file is gone) and
/// `size-mismatch` (indexed at a size the bytes disagree with) — on
/// top of the three it shares with that walk (`corrupt`, `foreign`,
/// `oversized`). It performs no unlink, no index write and no
/// truncation: the module doc states why repair waits on
/// descriptor-relative operations.
///
/// The caller holds the cache's writer lock for the whole call. That
/// is what makes the snapshot/journal pair a COHERENT read against a
/// concurrent compaction — it is not a licence to write, and nothing
/// here does.
///
/// # Errors
/// A `String` describing why `objects/` is unsafe to walk at all (see
/// [`refuse_symlinked_objects_dir`]) — checked BEFORE any entry is
/// classified, so a refusal means nothing was reported out of a tree
/// this walk could not trust.
fn audit_cache_against_index(
    root: &Path,
    index_entries: Vec<(GrainId, u32)>,
    err: &mut impl Write,
) -> Result<Vec<Finding>, String> {
    let index_map: BTreeMap<GrainId, u32> = index_entries.into_iter().collect();
    let mut acc = AuditAccumulator::default();

    for entry in scan_objects(root, err)? {
        acc.handle_entry(entry, &index_map);
    }
    acc.find_dropped(root, &index_map);

    Ok(acc.findings)
}

/// Mutable state threaded through one [`audit_cache_against_index`]
/// run — bundled into one struct so the per-entry classification
/// ([`Self::handle_entry`]) reads as a self-contained step rather than
/// a function with half a dozen accumulator parameters.
#[derive(Default)]
struct AuditAccumulator {
    findings: Vec<Finding>,
    /// Every id this walk actually SAW on disk, in ANY condition —
    /// hashed, corrupt, oversized, or present-but-unreadable.
    /// [`Self::find_dropped`] reports `dropped` for an indexed id only
    /// when it is absent from this set: a file that is there but could
    /// not be read is not a file that is gone, and reporting it
    /// `dropped` would be a second finding for one entry that is
    /// already reported.
    seen_ids: std::collections::BTreeSet<GrainId>,
    /// Two-hex fanout prefixes this run could not enumerate
    /// ([`ScanOutcome::FanoutUnreadable`]) — [`Self::find_dropped`]
    /// must not conclude `dropped` for any indexed id under one of
    /// these, since the run never actually looked at that part of the
    /// disk.
    unreadable_fanouts: std::collections::BTreeSet<String>,
    /// Set once by [`ScanOutcome::TopLevelUnreadable`] — a `DirEntry`
    /// at the top of `objects/` itself could not be read, before any
    /// name (so no `dir_hex`) was available. Unlike `unreadable_fanouts`,
    /// this has no prefix to scope the doubt to: [`Self::find_dropped`]
    /// must treat every indexed id as possibly-unseen this run rather
    /// than report one `dropped` under whatever fanout this entry would
    /// have named.
    top_level_unreadable: bool,
}

impl AuditAccumulator {
    /// Classify one scanned entry against `index_map` and update every
    /// accumulator accordingly.
    fn handle_entry(&mut self, entry: ScanEntry, index_map: &BTreeMap<GrainId, u32>) {
        match entry.outcome {
            ScanOutcome::Vanished => {}
            ScanOutcome::Foreign { claimed } => {
                self.findings
                    .push(finding(FindingKind::Foreign, entry.rel_path, "-", "-"));
                // A validated name that merely failed to open/stat/read
                // is still an object we KNOW is on disk — count it seen
                // so `find_dropped()` never ALSO reports it `dropped`
                // for the same transient failure.
                if let Some(id) = claimed {
                    self.seen_ids.insert(id);
                }
            }
            ScanOutcome::FanoutUnreadable { dir_hex } => {
                self.findings
                    .push(finding(FindingKind::Foreign, entry.rel_path, "-", "-"));
                self.unreadable_fanouts.insert(dir_hex);
            }
            ScanOutcome::TopLevelUnreadable => {
                self.findings
                    .push(finding(FindingKind::Foreign, entry.rel_path, "-", "-"));
                self.top_level_unreadable = true;
            }
            ScanOutcome::Oversized {
                claimed,
                actual_size,
            } => {
                self.findings.push(finding(
                    FindingKind::Oversized,
                    entry.rel_path,
                    "-",
                    actual_size.to_string(),
                ));
                // EXPLICIT, and load-bearing: nothing else records an
                // oversized object as seen. Without it an INDEXED oversized object is reported
                // `oversized` here and `dropped` again by
                // `find_dropped()` — two findings for one file that is
                // sitting right there.
                self.seen_ids.insert(claimed);
            }
            ScanOutcome::Hashed {
                claimed,
                actual_digest,
                actual_size,
            } => {
                self.seen_ids.insert(claimed);
                if actual_digest != claimed {
                    self.findings.push(finding(
                        FindingKind::Corrupt,
                        entry.rel_path,
                        claimed.to_string(),
                        actual_digest.to_string(),
                    ));
                    return;
                }
                self.handle_hashed_and_verified(claimed, actual_size, entry.rel_path, index_map);
            }
        }
    }

    /// The sub-case of [`Self::handle_entry`] reached once an entry has
    /// been re-hashed and the digest MATCHES its claimed id: either
    /// `adopted` (on disk, not in the index), `size-mismatch` (indexed
    /// at the wrong size), or healthy — no finding at all.
    fn handle_hashed_and_verified(
        &mut self,
        claimed: GrainId,
        actual_size: u64,
        rel_path: Vec<u8>,
        index_map: &BTreeMap<GrainId, u32>,
    ) {
        match index_map.get(&claimed) {
            None => {
                self.findings.push(finding(
                    FindingKind::Adopted,
                    rel_path,
                    "-",
                    claimed.to_string(),
                ));
            }
            Some(&recorded) => {
                // `actual_size` was already bounded to `META_MAX_BYTES`
                // (far under u32::MAX) by `classify_object_file()`, so
                // this narrowing cannot fail in practice — kept as a
                // safe fallback rather than an unwrap/indexing panic
                // (coding-standards rule 3).
                let actual_u32 = u32::try_from(actual_size).unwrap_or(u32::MAX);
                if recorded != actual_u32 {
                    self.findings.push(finding(
                        FindingKind::SizeMismatch,
                        rel_path,
                        recorded.to_string(),
                        actual_u32.to_string(),
                    ));
                }
            }
        }
    }

    /// DROPPED: every id in the loaded index that the walk never saw on
    /// disk. The path is DERIVED from the id (`cache::object_path()`) —
    /// there is no directory entry to read one from, the file is gone.
    /// An id whose fanout dir this run could not enumerate
    /// (`self.unreadable_fanouts`) is skipped entirely — not reported:
    /// the run never actually saw that part of the disk, so
    /// absence-here is not evidence of absence. When the TOP-LEVEL
    /// listing itself had an unreadable entry (`self.top_level_unreadable`
    /// — no `dir_hex` to scope to), the same reasoning applies to EVERY
    /// id: nothing is concluded `dropped` this run at all.
    fn find_dropped(&mut self, root: &Path, index_map: &BTreeMap<GrainId, u32>) {
        if self.top_level_unreadable {
            return;
        }
        for id in index_map.keys() {
            if self.seen_ids.contains(id) {
                continue;
            }
            let hex = id.digest_hex();
            if self.unreadable_fanouts.contains(&hex[..2]) {
                continue;
            }
            let full = cache::object_path(root, id);
            let rel = full.strip_prefix(root).map_or_else(
                |_| b"objects/?".to_vec(),
                |p| p.as_os_str().as_bytes().to_vec(),
            );
            self.findings
                .push(finding(FindingKind::Dropped, rel, id.to_string(), "-"));
        }
    }
}

/// STORE mode: a read-only marker check
/// ([`store::Store::open_for_verify`]), then the object walk. A store
/// has no index, so `corrupt`, `foreign` and `oversized` are the only
/// kinds it can produce. A refused walk (a symlinked `objects/`) is
/// cannot-open, exit 2 — never reported as a clean or partial run.
fn run_store(root: &Path, out: &mut impl Write, err: &mut impl Write) -> u8 {
    if let Err(e) = crate::store::Store::open_for_verify(root) {
        let _ = writeln!(err, "gran verify: {e}");
        return 2;
    }
    match report_only_walk(root, err) {
        Ok(findings) => write_findings(out, &findings),
        Err(msg) => {
            let _ = writeln!(err, "gran verify: {msg}");
            2
        }
    }
}

/// CACHE mode: three outcomes, not two. The writer lock is free AND
/// the index decodes → the full index-aware audit. The lock is free
/// and the index does NOT decode → the index file is itself a
/// finding, and the object walk runs WITHOUT it. The lock is held by
/// someone else → object-integrity findings only.
///
/// A refused walk (a symlinked `objects/`) is cannot-open, exit 2 —
/// the same rule `run_store()` follows, never reported as a clean or
/// partial run.
fn run_cache(root: &Path, out: &mut impl Write, err: &mut impl Write) -> u8 {
    match Cache::open_for_verify(root) {
        Ok(VerifyCache::WithIndex { index, .. }) => match index {
            VerifyIndex::Trusted(index) => {
                match audit_cache_against_index(root, index.entries, err) {
                    Ok(findings) => write_findings(out, &findings),
                    Err(msg) => {
                        let _ = writeln!(err, "gran verify: {msg}");
                        2
                    }
                }
            }
            // The index exists and cannot be trusted. Reporting it is
            // the whole point: collapsed to "an empty index", a cache
            // with a corrupt snapshot and an empty `objects/` verifies
            // CLEAN, exit 0, in silence. And the comparison is SKIPPED
            // rather than run against the damage — every `adopted` and
            // `dropped` line it produced would be an artefact of the
            // corruption, burying the one finding that is real.
            VerifyIndex::Untrusted { rel_path, detail } => {
                let _ = writeln!(
                    err,
                    "gran verify: {rel_path} cannot be trusted ({detail}); reporting it and \
                     falling back to object-integrity findings only — comparing objects \
                     against a damaged index would report most of them adopted or dropped, \
                     which describes the damage rather than the objects"
                );
                match report_only_walk(root, err) {
                    Ok(walk_findings) => {
                        let mut findings = vec![finding(
                            FindingKind::Foreign,
                            rel_path.as_bytes().to_vec(),
                            "-",
                            "-",
                        )];
                        findings.extend(walk_findings);
                        write_findings(out, &findings)
                    }
                    Err(msg) => {
                        let _ = writeln!(err, "gran verify: {msg}");
                        2
                    }
                }
            }
        },
        Ok(VerifyCache::ReportOnly) => {
            let _ = writeln!(
                err,
                "gran verify: the cache's writer lock is held by another process; reporting \
                 object-integrity findings only — the index comparison needs the lock \
                 (snapshot+journal have no generation permitting a coherent lockless read \
                 during compaction). Never blocks."
            );
            match report_only_walk(root, err) {
                Ok(findings) => write_findings(out, &findings),
                Err(msg) => {
                    let _ = writeln!(err, "gran verify: {msg}");
                    2
                }
            }
        }
        Err(e) => {
            let _ = writeln!(err, "gran verify: {e}");
            2
        }
    }
}

fn write_findings(out: &mut impl Write, findings: &[Finding]) -> u8 {
    for f in findings {
        let _ = writeln!(out, "{}", encode_finding_line(f));
    }
    u8::from(!findings.is_empty())
}

/// Which root kind [`detect_root_kind`] found.
enum RootKind {
    Store,
    Cache,
}

/// Root-type detection: a store marker selects STORE
/// mode; a cache marker selects CACHE mode; BOTH present → cannot-open
/// (exit 2, ambiguous — a dual-marker directory would otherwise let the
/// store silently win, and STORE mode cannot report the three index
/// findings a cache root's operator is running this for); EITHER one
/// unreadable → cannot-open, because the root's TYPE is then
/// undetermined and dispatching on the other runs the wrong
/// verification; neither → cannot-open.
fn detect_root_kind(root: &Path, err: &mut impl Write) -> Option<RootKind> {
    let store_marker = store::probe_store_marker(&root.join(store::MARKER_NAME));
    let cache_marker = cache::probe_cache_marker(&root.join(cache::MARKER_NAME));
    match (store_marker, cache_marker) {
        // UNREADABLE IS CHECKED FIRST, and that ordering is load-bearing.
        // An unreadable marker of either kind leaves the root's TYPE
        // undetermined, so dispatching on the OTHER one runs the wrong
        // verification against a directory this process could not
        // classify — an over-cap cache marker beside a valid store
        // marker would select STORE mode in silence. "I could not
        // read it" is not "it is not there".
        (MarkerProbe::Unreadable, _) => {
            let _ = writeln!(
                err,
                "gran verify: {}'s store marker exists and could not be read (over the size \
                 bound, not utf-8, not a regular file, or a symlink) — the root's type is \
                 undetermined, refusing",
                root.display()
            );
            None
        }
        (_, MarkerProbe::Unreadable) => {
            let _ = writeln!(
                err,
                "gran verify: {}'s cache marker exists and could not be read (over the size \
                 bound, not utf-8, not a regular file, or a symlink) — the root's type is \
                 undetermined, refusing",
                root.display()
            );
            None
        }
        (MarkerProbe::Present, MarkerProbe::Present) => {
            let _ = writeln!(
                err,
                "gran verify: {} holds BOTH a store marker and a cache marker — ambiguous, \
                 refusing",
                root.display()
            );
            None
        }
        (MarkerProbe::Present, MarkerProbe::Absent) => Some(RootKind::Store),
        (MarkerProbe::Absent, MarkerProbe::Present) => Some(RootKind::Cache),
        (MarkerProbe::Absent, MarkerProbe::Absent) => {
            let _ = writeln!(
                err,
                "gran verify: {} is neither a granary store nor a granary cache (no \
                 recognizable marker)",
                root.display()
            );
            None
        }
    }
}

/// A symlinked structural directory (`objects/` for either root kind,
/// `index/` for a cache root) is a REFUSAL, never a finding: verify
/// must not walk, hash or report through one at all.
/// [`store::Store::open_for_verify`] and [`Cache::open_for_verify`]
/// each refuse it before touching the directory, and [`scan_objects`]
/// refuses it again on its own — see [`refuse_symlinked_objects_dir`].
/// A refusal is cannot-open (exit 2), the same class an incompatible
/// marker already is, never reported as clean (exit 0) or as ordinary
/// findings (exit 1).
fn run_verify_with(root: &Path, out: &mut impl Write, err: &mut impl Write) -> u8 {
    match detect_root_kind(root, err) {
        None => 2,
        Some(RootKind::Store) => run_store(root, out, err),
        Some(RootKind::Cache) => run_cache(root, out, err),
    }
}

/// `gran verify <store-or-cache-root>`'s library entry point.
/// Exit code: 0 clean, 1 findings, 2 cannot-open.
#[must_use]
pub fn run_verify(root: &Path) -> ExitCode {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    ExitCode::from(run_verify_with(root, &mut stdout, &mut stderr))
}

#[cfg(test)]
mod tests;
