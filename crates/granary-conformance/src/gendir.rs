// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `granconf gendir`: a seeded, adversarial-but-legal source tree,
//! split into a PURE plan (this module's [`build_plan`], testable
//! without touching a filesystem) and a materializer
//! ([`materialize`]) that writes it to disk with `create_new`
//! semantics on every entry — a collision is an error, never a silent
//! overwrite, which is exactly what turns a case-folding filesystem
//! (APFS, by default) from a silent merger into a loud failure. There
//! is no skip flag: an uncreatable case fails the whole binary. On this
//! machine that is BY DESIGN — APFS is case-INSENSITIVE by default (the
//! `names/CaseA` / `names/casea` pair collides) and refuses non-UTF-8
//! names outright (the byte-0xff case), so [`materialize`] is expected
//! to die here; a byte-preserving filesystem accepts the full plan.
//!
//! **Seeding.** [`granary_core::rng::SeededRng`] draws every regular
//! file's CONTENT bytes, so two different seeds produce genuinely
//! different (but equally compliant) trees. The REQUIRED adversarial
//! structure — which cases exist, their names, sizes and nesting — is
//! deterministic BY CONSTRUCTION and does not vary with the seed: a
//! `verify-cases` run must pass for every seed, not just the ones this
//! crate's tests happen to try. Boundary sizes come from
//! `granary_core::thresh`/`granary_core::manifest`, never a copied
//! literal.
//!
//! **`gendir`'s printed summary is informational only.** Nothing in
//! this crate — least of all `verify-cases` — reads it; the summary
//! exists for a human watching the run, and [`crate::verify_cases::verify_all`]
//! only ever takes rows a real walk produced.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use granary_core::manifest::DIR_LEAF_MAX_ENTRIES;
use granary_core::rng::{Rng as _, SeededRng};
use granary_core::thresh::{AVG_GRAIN, MAX_GRAIN, MIN_GRAIN};

#[derive(Debug, Clone)]
pub enum PlannedNode {
    Dir,
    File {
        size: u64,
        exec: bool,
        content: Vec<u8>,
    },
    Symlink {
        target: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct PlannedEntry {
    pub path: Vec<u8>,
    pub node: PlannedNode,
}

/// A deterministic tree plan: entries in CREATION ORDER (every
/// directory precedes its children — [`materialize`] relies on this
/// and does not reorder).
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub entries: Vec<PlannedEntry>,
}

fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len().saturating_add(b.len()).saturating_add(1));
    out.extend_from_slice(a);
    out.push(b'/');
    out.extend_from_slice(b);
    out
}

/// Fill `size` bytes deterministically from `seed`, via the same
/// splitmix64 seam [`SeededRng`] uses everywhere else in this
/// workspace — never a byte pattern hand-rolled per call site.
fn fill_content(seed: u64, size: u64) -> Vec<u8> {
    let mut rng = SeededRng::new(seed);
    let mut buf: Vec<u8> = Vec::new();
    let mut produced: u64 = 0;
    while produced < size {
        buf.extend_from_slice(&rng.next_u64().to_le_bytes());
        produced = produced.saturating_add(8);
    }
    buf.truncate(usize::try_from(size).unwrap_or(usize::MAX));
    buf
}

struct Builder {
    rng: SeededRng,
    entries: Vec<PlannedEntry>,
}

impl Builder {
    fn dir(&mut self, path: &[u8]) {
        self.entries.push(PlannedEntry {
            path: path.to_vec(),
            node: PlannedNode::Dir,
        });
    }

    fn file(&mut self, path: &[u8], size: u64, exec: bool) {
        let seed = self.rng.next_u64();
        let content = fill_content(seed, size);
        self.entries.push(PlannedEntry {
            path: path.to_vec(),
            node: PlannedNode::File {
                size,
                exec,
                content,
            },
        });
    }

    fn symlink(&mut self, path: &[u8], target: &[u8]) {
        self.entries.push(PlannedEntry {
            path: path.to_vec(),
            node: PlannedNode::Symlink {
                target: target.to_vec(),
            },
        });
    }
}

/// Two disjoint subtrees whose prefix-stripped content is
/// byte-identical, digests included: BOTH copies are generated from
/// the SAME captured sub-seed through independent [`SeededRng`]
/// instances, so their draws — and so their file content — agree
/// exactly. The only difference between the two copies is `base`
/// itself, which every row's PATH carries and no row's CONTENT does.
fn build_dup_pair(b: &mut Builder, base: &[u8]) {
    let sub_seed = b.rng.next_u64();
    for copy in [b"one".as_slice(), b"two".as_slice()] {
        let mut local = SeededRng::new(sub_seed);
        let copy_base = join(base, copy);
        b.entries.push(PlannedEntry {
            path: copy_base.clone(),
            node: PlannedNode::Dir,
        });
        for i in 0..2u32 {
            let seed = local.next_u64();
            let size = 4096u64;
            let content = fill_content(seed, size);
            let path = join(&copy_base, format!("f{i}").as_bytes());
            b.entries.push(PlannedEntry {
                path,
                node: PlannedNode::File {
                    size,
                    exec: false,
                    content,
                },
            });
        }
    }
}

/// Build the deterministic adversarial plan for `seed`. Pure: touches
/// no filesystem, so it is fully exercised on macOS.
#[must_use]
pub fn build_plan(seed: u64) -> Plan {
    let mut b = Builder {
        rng: SeededRng::new(seed),
        entries: Vec::new(),
    };

    // names/ — length boundaries, ASCII case-folding, the two
    // escaping-adversarial bytes.
    b.dir(b"names");
    b.file(&join(b"names", b"a"), 3, false); // unescaped length 1
    let long_name = vec![b'q'; 255];
    b.file(&join(b"names", &long_name), 5, false); // unescaped length 255
    b.file(&join(b"names", b"CaseA"), 4, false);
    b.file(&join(b"names", b"casea"), 4, false); // same parent, ASCII-case-equal, distinct bytes
    // A name containing byte 0xff — never valid UTF-8, so this is
    // never a Rust `str`, only raw bytes: exactly the discipline
    // `crates/granary-core/src/manifest/name.rs`'s `Name` enforces.
    b.file(&join(b"names", &[b'x', b'f', b'f', 0xffu8]), 2, false);
    // The literal 4-byte ASCII sequence `\x2f` — Rust's OWN `\\` is a
    // single backslash byte in the source, so this literal is exactly
    // backslash, 'x', '2', 'f'. Distinct from a real path separator by
    // construction (see `crate::escape`'s module doc).
    b.file(&join(b"names", b"has\\x2fliteral"), 2, false);

    // sizes/ — every grain-chunker boundary, plus the size-0 and
    // exec/non-exec cases. Sizes are IMPORTED, never literals.
    b.dir(b"sizes");
    let min = u64::try_from(MIN_GRAIN).unwrap_or(u64::MAX);
    let avg = u64::try_from(AVG_GRAIN).unwrap_or(u64::MAX);
    let max = u64::try_from(MAX_GRAIN).unwrap_or(u64::MAX);
    let boundary_sizes: [(&str, u64); 8] = [
        ("min-1", min.saturating_sub(1)),
        ("min", min),
        ("min+1", min.saturating_add(1)),
        ("avg", avg),
        ("max-1", max.saturating_sub(1)),
        ("max", max),
        ("max+1", max.saturating_add(1)),
        (
            "two-max-plus-min",
            2u64.saturating_mul(max).saturating_add(min),
        ),
    ];
    for (i, (name, size)) in boundary_sizes.iter().enumerate() {
        // The first boundary file also carries the exec bit, so
        // "exec and non-exec both exist" holds without a dedicated
        // directory.
        b.file(&join(b"sizes", name.as_bytes()), *size, i == 0);
    }
    b.file(&join(b"sizes", b"empty"), 0, false);

    // wide/ — a directory crossing 2*DIR_LEAF_MAX_ENTRIES children.
    b.dir(b"wide");
    let wide_threshold = DIR_LEAF_MAX_ENTRIES.saturating_mul(2);
    for i in 0..=wide_threshold {
        b.file(&join(b"wide", format!("e{i:05}").as_bytes()), 8, false);
    }

    // deep/ — path depth >= 100.
    let mut cur = b"deep".to_vec();
    b.dir(&cur);
    for i in 0..100u32 {
        cur = join(&cur, format!("lvl{i:03}").as_bytes());
        b.dir(&cur);
    }
    b.file(&join(&cur, b"leaf"), 4, false);

    // symlinks/ — absolute, `..`-containing, dangling, to-a-directory,
    // and same-directory-to-a-sibling-regular-file.
    b.dir(b"symlinks");
    b.symlink(&join(b"symlinks", b"abs"), b"/etc/passwd");
    b.symlink(&join(b"symlinks", b"dotdot"), b"../escape-attempt");
    b.symlink(&join(b"symlinks", b"dangling"), b"nowhere-really");
    b.symlink(&join(b"symlinks", b"to-dir"), b"../names");
    b.file(&join(b"symlinks", b"sibling.txt"), 6, false);
    // A dtype-lie fixture requires a same-directory symlink naming a
    // sibling REGULAR FILE.
    b.symlink(&join(b"symlinks", b"to-sibling"), b"sibling.txt");

    // dup/{one,two}/ — disjoint, byte-identical subtrees (content
    // addressing MERGES these; the case that would surface as
    // directory hard links if inode identity were keyed by GrainId).
    b.dir(b"dup");
    build_dup_pair(&mut b, b"dup");

    Plan { entries: b.entries }
}

#[derive(Debug)]
pub enum GenDirError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for GenDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for GenDirError {}

/// Materialize `plan` under `out_dir`, `create_new` on every entry —
/// `out_dir` itself included, so a repeated `gendir` into the same
/// path is a collision, never a silent overwrite.
///
/// # Errors
/// The first [`GenDirError`] hit, naming the exact path — no skip
/// flag: an uncreatable case fails the whole run. On this machine that
/// is expected (case-folding and non-UTF-8 names, see the module doc).
pub fn materialize(plan: &Plan, out_dir: &Path) -> Result<(), GenDirError> {
    fs::create_dir(out_dir).map_err(|source| GenDirError::Io {
        path: out_dir.to_path_buf(),
        source,
    })?;
    for entry in &plan.entries {
        let abs = out_dir.join(OsStr::from_bytes(&entry.path));
        match &entry.node {
            PlannedNode::Dir => {
                fs::create_dir(&abs).map_err(|source| GenDirError::Io {
                    path: abs.clone(),
                    source,
                })?;
            }
            PlannedNode::File { exec, content, .. } => {
                use std::io::Write as _;
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&abs)
                    .map_err(|source| GenDirError::Io {
                        path: abs.clone(),
                        source,
                    })?;
                f.write_all(content).map_err(|source| GenDirError::Io {
                    path: abs.clone(),
                    source,
                })?;
                let mode = if *exec { 0o755 } else { 0o644 };
                fs::set_permissions(&abs, fs::Permissions::from_mode(mode)).map_err(|source| {
                    GenDirError::Io {
                        path: abs.clone(),
                        source,
                    }
                })?;
            }
            PlannedNode::Symlink { target } => {
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &abs).map_err(|source| {
                    GenDirError::Io {
                        path: abs.clone(),
                        source,
                    }
                })?;
            }
        }
    }
    Ok(())
}

/// A human-readable, INFORMATIONAL-ONLY summary — nothing in this
/// crate treats this as evidence of anything; `verify-cases` reads the
/// dump, never this.
#[must_use]
pub fn summarize(plan: &Plan) -> String {
    let mut dirs = 0u64;
    let mut files = 0u64;
    let mut symlinks = 0u64;
    for entry in &plan.entries {
        match entry.node {
            PlannedNode::Dir => dirs = dirs.saturating_add(1),
            PlannedNode::File { .. } => files = files.saturating_add(1),
            PlannedNode::Symlink { .. } => symlinks = symlinks.saturating_add(1),
        }
    }
    format!(
        "gendir: {dirs} dirs, {files} files, {symlinks} symlinks planned \
         (informational only — verify-cases proves nothing from this line)"
    )
}

#[cfg(test)]
mod tests;
