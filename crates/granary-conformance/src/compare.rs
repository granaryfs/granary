// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `granconf compare`: a sorted merge-join over two dumps' rows,
//! classifying every divergence by the most-upstream field that
//! differs — `presence > kind > size > exec > content > target >
//! dtype` — and, in `--expect` mode, the triple that makes a dead or
//! empty mount FAIL rather than vacuously PASS.
//!
//! **Why a merge-join, not a positional zip.** Both dumps are sorted
//! by the SAME raw-byte key, so walking them with two cursors and
//! comparing `path` at each step localizes exactly which paths are
//! missing on which side — the standard sorted-diff algorithm (`comm`,
//! `diff` on presorted input). A dump's ESCAPED text is not sorted the
//! same way its raw bytes are (see [`crate::escape`]'s module doc), so
//! the merge below compares [`crate::row::Row::path`] — decoded raw
//! bytes — never the escaped rendering; `Row::path`'s `Ord` is derived
//! `Vec<u8>` comparison, i.e. exact memcmp, the same rule
//! `crates/granary-core/src/manifest/name.rs`'s `Name` sorts by.

use crate::row::{Kind, Payload, Row};

/// The compared classes, in PRECEDENCE order — declaration order here
/// **is** "most upstream first" and backs the derived `Ord` the
/// `--expect` refusal-on-any-OTHER-class check does not even need
/// (each row gets exactly one class; nothing here compares classes to
/// each other), but keeping the enum's declaration order equal to the
/// stated precedence is what makes this module readable against the
/// design doc's own line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Presence,
    Kind,
    Size,
    Exec,
    Content,
    Target,
    Dtype,
}

impl Class {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Presence => "presence",
            Self::Kind => "kind",
            Self::Size => "size",
            Self::Exec => "exec",
            Self::Content => "content",
            Self::Target => "target",
            Self::Dtype => "dtype",
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// One divergent (or convergent) outcome from the merge: `path` is the
/// raw bytes both sides agree name the same entry (or the one side
/// that has it, for `Presence`); `class` is `None` for a row that
/// compared fully EQUAL.
#[derive(Debug, Clone)]
pub struct Divergence {
    pub path: Vec<u8>,
    pub class: Option<Class>,
}

/// Classify a same-path pair by the most-upstream field that differs.
/// `None` means every compared field agreed.
fn classify_same_path(a: &Row, b: &Row) -> Option<Class> {
    if a.kind != b.kind {
        return Some(Class::Kind);
    }
    if a.size != b.size {
        return Some(Class::Size);
    }
    if a.exec != b.exec {
        return Some(Class::Exec);
    }
    match a.kind {
        Kind::File => {
            if let (Payload::Content(x), Payload::Content(y)) = (&a.payload, &b.payload)
                && x != y
            {
                return Some(Class::Content);
            }
        }
        Kind::Symlink => {
            if let (Payload::Target(x), Payload::Target(y)) = (&a.payload, &b.payload)
                && x != y
            {
                return Some(Class::Target);
            }
        }
        Kind::Dir => {}
    }
    if a.dtype != b.dtype {
        return Some(Class::Dtype);
    }
    None
}

/// Merge-join two already-classified row sets (each is assumed sorted
/// by [`Row::path`] — [`crate::row::parse_dump`] guarantees this for
/// anything read off disk) into one [`Divergence`] per path union.
#[must_use]
pub fn merge(a: &[Row], b: &[Row]) -> Vec<Divergence> {
    let mut out = Vec::with_capacity(a.len().max(b.len()));
    // Two peekable cursors, never an index: `peek` + `next` reach the
    // same merge-join without a `[i]`/`[j]` this workspace's
    // `indexing_slicing` lint denies outright.
    let mut ai = a.iter().peekable();
    let mut bi = b.iter().peekable();
    loop {
        match (ai.peek(), bi.peek()) {
            (Some(ra), Some(rb)) => match ra.path.cmp(&rb.path) {
                std::cmp::Ordering::Less => {
                    out.push(Divergence {
                        path: ra.path.clone(),
                        class: Some(Class::Presence),
                    });
                    ai.next();
                }
                std::cmp::Ordering::Greater => {
                    out.push(Divergence {
                        path: rb.path.clone(),
                        class: Some(Class::Presence),
                    });
                    bi.next();
                }
                std::cmp::Ordering::Equal => {
                    out.push(Divergence {
                        path: ra.path.clone(),
                        class: classify_same_path(ra, rb),
                    });
                    ai.next();
                    bi.next();
                }
            },
            (Some(ra), None) => {
                out.push(Divergence {
                    path: ra.path.clone(),
                    class: Some(Class::Presence),
                });
                ai.next();
            }
            (None, Some(rb)) => {
                out.push(Divergence {
                    path: rb.path.clone(),
                    class: Some(Class::Presence),
                });
                bi.next();
            }
            (None, None) => break,
        }
    }
    out
}

/// The BASELINE verdict: source and mount must be identical.
///
/// This is the oracle's primary assertion, and it is the one an ordinary
/// shell gate reaches for, so it must be expressible as an exit status and
/// not merely as counters a caller has to parse. Returns the number of rows
/// that compared EQUAL so the caller can refuse a vacuous "identical" over
/// two empty dumps.
///
/// # Errors
/// A description naming every class that diverged, when any row did.
pub fn check_identical(divergences: &[Divergence]) -> Result<usize, String> {
    let mut equal = 0usize;
    let mut diverged: Vec<Class> = Vec::new();
    for d in divergences {
        match d.class {
            None => equal = equal.saturating_add(1),
            Some(c) => {
                if !diverged.contains(&c) {
                    diverged.push(c);
                }
            }
        }
    }
    if !diverged.is_empty() {
        let names: Vec<String> = diverged.iter().map(ToString::to_string).collect();
        return Err(format!("diverged in {}", names.join(", ")));
    }
    if equal == 0 {
        return Err("no rows compared equal — an empty comparison is not a match".to_owned());
    }
    Ok(equal)
}

/// The `--expect <class>` triple: at least one row of `want`, ZERO rows
/// of any OTHER class, and at least one row comparing EQUAL — the
/// third condition is what makes a dead or empty mount FAIL instead of
/// vacuously passing (an empty dump has no divergences of any class,
/// which would otherwise satisfy "zero rows of any other class" for
/// free).
///
/// Returns `Ok(())` on the triple holding, `Err(reason)` naming which
/// leg failed otherwise.
///
/// # Errors
/// A `String` naming which leg of the triple failed: zero rows of
/// `want`, a row of some OTHER class, or zero rows comparing EQUAL.
pub fn check_expect(divergences: &[Divergence], want: Class) -> Result<(), String> {
    let mut want_count = 0usize;
    let mut equal_count = 0usize;
    let mut other: Option<Class> = None;
    for d in divergences {
        match d.class {
            None => equal_count = equal_count.saturating_add(1),
            Some(c) if c == want => want_count = want_count.saturating_add(1),
            Some(c) => {
                other.get_or_insert(c);
            }
        }
    }
    if want_count == 0 {
        return Err(format!("zero rows of class {want} (expected at least one)"));
    }
    if let Some(c) = other {
        return Err(format!(
            "a row of class {c} diverged too — --expect {want} requires ONLY {want} divergences"
        ));
    }
    if equal_count == 0 {
        return Err(
            "zero rows compared EQUAL — a dead or empty mount must not pass this way".to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
