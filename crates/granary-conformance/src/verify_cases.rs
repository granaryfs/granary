// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `granconf verify-cases`: the generator's witness. Every predicate
//! here reads the SOURCE DUMP — rows a real walk produced off the real
//! filesystem — never `gendir`'s own tally. A count assertion is the
//! self-written-witness shape this project has deleted before: a dump
//! of files all sitting at exactly `MIN_GRAIN` would keep any COUNT
//! invariant true while proving no size boundary was ever exercised.
//! Each predicate below is an EXISTENCE check over the actual rows, and
//! names its own case on failure.

use std::collections::{HashMap, HashSet};

use granary_core::manifest::DIR_LEAF_MAX_ENTRIES;
use granary_core::thresh::{AVG_GRAIN, MAX_GRAIN, MIN_GRAIN};

use crate::row::{Kind, Payload, Row};

fn parent_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        // `i` came from `rposition` over this same slice, so `..i` is
        // always in bounds; `.get` + a default keeps the property
        // provable without an indexing operation clippy must deny.
        Some(i) => path.get(..i).unwrap_or_default(),
        None => b"",
    }
}

fn last_component(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => path.get(i.saturating_add(1)..).unwrap_or_default(),
        None => path,
    }
}

fn depth(path: &[u8]) -> usize {
    path.split(|&b| b == b'/').count()
}

/// Resolve a symlink's target against the row set: `.`/`..` components
/// are consumed, an absolute target is resolved from the tree root
/// rather than the entry's directory, and any attempt to `..` above
/// the tree root fails resolution (treated the same as "not found" —
/// i.e. dangling, which is a legitimate outcome here, not an error).
fn resolve(row_path: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    let mut components: Vec<Vec<u8>> = if target.first() == Some(&b'/') {
        Vec::new()
    } else {
        parent_of(row_path)
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    };
    for part in target.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                components.pop()?;
            }
            other => components.push(other.to_vec()),
        }
    }
    Some(components.join(&b'/'))
}

fn path_set(rows: &[Row]) -> HashSet<&[u8]> {
    rows.iter().map(|r| r.path.as_slice()).collect()
}

fn path_kind(rows: &[Row]) -> HashMap<&[u8], Kind> {
    rows.iter().map(|r| (r.path.as_slice(), r.kind)).collect()
}

type Check = fn(&[Row]) -> Result<(), String>;

fn check_name_len_1(rows: &[Row]) -> Result<(), String> {
    if rows.iter().any(|r| last_component(&r.path).len() == 1) {
        Ok(())
    } else {
        Err("no row has a name of unescaped length 1".to_owned())
    }
}

fn check_name_len_255(rows: &[Row]) -> Result<(), String> {
    if rows.iter().any(|r| last_component(&r.path).len() == 255) {
        Ok(())
    } else {
        Err("no row has a name of unescaped length 255".to_owned())
    }
}

fn check_case_fold_siblings(rows: &[Row]) -> Result<(), String> {
    let mut by_parent: HashMap<&[u8], Vec<&[u8]>> = HashMap::new();
    for row in rows {
        by_parent
            .entry(parent_of(&row.path))
            .or_default()
            .push(last_component(&row.path));
    }
    for names in by_parent.values() {
        for (i, a) in names.iter().enumerate() {
            for b in names.iter().skip(i.saturating_add(1)) {
                if a != b && a.eq_ignore_ascii_case(b) {
                    return Ok(());
                }
            }
        }
    }
    Err("no two same-parent rows have distinct, ASCII-case-equal names".to_owned())
}

fn check_depth_100(rows: &[Row]) -> Result<(), String> {
    if rows.iter().any(|r| depth(&r.path) >= 100) {
        Ok(())
    } else {
        Err("no row sits at path depth >= 100".to_owned())
    }
}

fn check_wide_dir(rows: &[Row]) -> Result<(), String> {
    let mut counts: HashMap<&[u8], usize> = HashMap::new();
    for row in rows {
        let counter = counts.entry(parent_of(&row.path)).or_insert(0usize);
        *counter = counter.saturating_add(1);
    }
    let threshold = (2 * DIR_LEAF_MAX_ENTRIES) as usize;
    if counts.values().any(|&n| n > threshold) {
        Ok(())
    } else {
        Err(format!(
            "no directory has more than {threshold} (2*DIR_LEAF_MAX_ENTRIES) child rows"
        ))
    }
}

fn check_empty_file(rows: &[Row]) -> Result<(), String> {
    if rows
        .iter()
        .any(|r| r.kind == Kind::File && r.size == Some(0))
    {
        Ok(())
    } else {
        Err("no size-0 file row".to_owned())
    }
}

fn check_grain_boundary_sizes(rows: &[Row]) -> Result<(), String> {
    let min = MIN_GRAIN as u64;
    let avg = AVG_GRAIN as u64;
    let max = MAX_GRAIN as u64;
    let wanted: [u64; 8] = [
        min.saturating_sub(1),
        min,
        min.saturating_add(1),
        avg,
        max.saturating_sub(1),
        max,
        max.saturating_add(1),
        2u64.saturating_mul(max).saturating_add(min),
    ];
    let present: HashSet<u64> = rows
        .iter()
        .filter(|r| r.kind == Kind::File)
        .filter_map(|r| r.size)
        .collect();
    let missing: Vec<String> = wanted
        .iter()
        .filter(|s| !present.contains(s))
        .map(u64::to_string)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing file rows at sizes: {}",
            missing.join(", ")
        ))
    }
}

fn check_exec_and_nonexec(rows: &[Row]) -> Result<(), String> {
    let mut files = rows.iter().filter(|r| r.kind == Kind::File);
    let has_exec = files.clone().any(|r| r.exec);
    let has_nonexec = files.any(|r| !r.exec);
    match (has_exec, has_nonexec) {
        (true, true) => Ok(()),
        (false, true) => Err("no exec file row".to_owned()),
        (true, false) => Err("no non-exec file row".to_owned()),
        (false, false) => Err("no file rows at all".to_owned()),
    }
}

fn symlink_rows(rows: &[Row]) -> impl Iterator<Item = (&Row, &[u8])> {
    rows.iter().filter_map(|r| match &r.payload {
        Payload::Target(t) => Some((r, t.as_slice())),
        _ => None,
    })
}

fn check_symlink_absolute(rows: &[Row]) -> Result<(), String> {
    if symlink_rows(rows).any(|(_, t)| t.first() == Some(&b'/')) {
        Ok(())
    } else {
        Err("no symlink row has an absolute target".to_owned())
    }
}

fn check_symlink_dotdot(rows: &[Row]) -> Result<(), String> {
    if symlink_rows(rows).any(|(_, t)| t.split(|&b| b == b'/').any(|c| c == b"..")) {
        Ok(())
    } else {
        Err("no symlink row has a '..'-containing target".to_owned())
    }
}

fn check_symlink_dangling(rows: &[Row]) -> Result<(), String> {
    let present = path_set(rows);
    if symlink_rows(rows).any(|(row, t)| match resolve(&row.path, t) {
        Some(resolved) => !present.contains(resolved.as_slice()),
        None => true,
    }) {
        Ok(())
    } else {
        Err("no symlink row is dangling".to_owned())
    }
}

fn check_symlink_to_dir(rows: &[Row]) -> Result<(), String> {
    let kinds = path_kind(rows);
    if symlink_rows(rows).any(|(row, t)| {
        resolve(&row.path, t)
            .is_some_and(|resolved| kinds.get(resolved.as_slice()) == Some(&Kind::Dir))
    }) {
        Ok(())
    } else {
        Err("no symlink row resolves to a directory row".to_owned())
    }
}

fn check_symlink_to_sibling_file(rows: &[Row]) -> Result<(), String> {
    let kinds = path_kind(rows);
    if symlink_rows(rows).any(|(row, t)| {
        !t.contains(&b'/')
            && resolve(&row.path, t)
                .is_some_and(|resolved| kinds.get(resolved.as_slice()) == Some(&Kind::File))
    }) {
        Ok(())
    } else {
        Err(
            "no same-directory symlink row names a sibling regular-file row \
             (the dtype-lie fixture's precondition)"
                .to_owned(),
        )
    }
}

/// One row's content, with its own path prefix stripped and every
/// field an owned value — what two subtrees are compared BY, so the
/// comparison is blind to WHERE each subtree sits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StrippedRow {
    suffix: Vec<u8>,
    kind: Kind,
    size: Option<u64>,
    exec: bool,
    payload: String,
}

fn stripped(prefix: &[u8], row: &Row) -> StrippedRow {
    let suffix = row
        .path
        .get(prefix.len().saturating_add(1)..)
        .unwrap_or_default()
        .to_vec();
    let payload = match &row.payload {
        Payload::None => "-".to_owned(),
        Payload::Content(hex) => hex.clone(),
        Payload::Target(t) => crate::escape::escape(t),
    };
    StrippedRow {
        suffix,
        kind: row.kind,
        size: row.size,
        exec: row.exec,
        payload,
    }
}

fn subtree_signature(rows: &[Row], dir_path: &[u8]) -> Vec<StrippedRow> {
    let mut prefix = dir_path.to_vec();
    prefix.push(b'/');
    let mut sig: Vec<StrippedRow> = rows
        .iter()
        .filter(|r| r.path.starts_with(&prefix))
        .map(|r| stripped(dir_path, r))
        .collect();
    sig.sort();
    sig
}

fn is_disjoint(a: &[u8], b: &[u8]) -> bool {
    let mut a_prefix = a.to_vec();
    a_prefix.push(b'/');
    let mut b_prefix = b.to_vec();
    b_prefix.push(b'/');
    a != b && !b.starts_with(a_prefix.as_slice()) && !a.starts_with(b_prefix.as_slice())
}

fn check_dup_subtrees(rows: &[Row]) -> Result<(), String> {
    let dirs: Vec<&[u8]> = rows
        .iter()
        .filter(|r| r.kind == Kind::Dir)
        .map(|r| r.path.as_slice())
        .collect();
    for (i, &d1) in dirs.iter().enumerate() {
        let sig_i = subtree_signature(rows, d1);
        if sig_i.is_empty() {
            continue;
        }
        for &d2 in dirs.iter().skip(i.saturating_add(1)) {
            if !is_disjoint(d1, d2) {
                continue;
            }
            if sig_i == subtree_signature(rows, d2) {
                return Ok(());
            }
        }
    }
    Err("no two disjoint subtrees have byte-identical prefix-stripped row multisets".to_owned())
}

fn check_byte_0xff(rows: &[Row]) -> Result<(), String> {
    if rows
        .iter()
        .any(|r| last_component(&r.path).contains(&0xffu8))
    {
        Ok(())
    } else {
        Err("no name contains byte 0xff".to_owned())
    }
}

fn check_literal_backslash_x2f(rows: &[Row]) -> Result<(), String> {
    if rows
        .iter()
        .any(|r| last_component(&r.path).windows(4).any(|w| w == b"\\x2f"))
    {
        Ok(())
    } else {
        Err("no name contains the literal 4-byte sequence \\x2f".to_owned())
    }
}

/// Every predicate, in the order the report should list them. The
/// `&'static str` is the case name a failure is reported under.
#[must_use]
pub fn checks() -> Vec<(&'static str, Check)> {
    vec![
        ("name-len-1", check_name_len_1),
        ("name-len-255", check_name_len_255),
        ("case-fold-siblings", check_case_fold_siblings),
        ("depth-100", check_depth_100),
        ("wide-dir", check_wide_dir),
        ("empty-file", check_empty_file),
        ("grain-boundary-sizes", check_grain_boundary_sizes),
        ("exec-and-nonexec", check_exec_and_nonexec),
        ("symlink-absolute", check_symlink_absolute),
        ("symlink-dotdot", check_symlink_dotdot),
        ("symlink-dangling", check_symlink_dangling),
        ("symlink-to-dir", check_symlink_to_dir),
        ("symlink-to-sibling-file", check_symlink_to_sibling_file),
        ("dup-subtrees", check_dup_subtrees),
        ("name-byte-0xff", check_byte_0xff),
        ("name-literal-backslash-x2f", check_literal_backslash_x2f),
    ]
}

#[derive(Debug, Clone)]
pub struct CaseResult {
    pub name: &'static str,
    pub outcome: Result<(), String>,
}

/// Run every predicate. Refuses an empty dump outright — the same
/// polarity control [`crate::compare::check_expect`] gets: a vacuous
/// input must not pass by having nothing to fail.
///
/// # Errors
/// `Err(())` if `rows` is empty.
pub fn verify_all(rows: &[Row]) -> Result<Vec<CaseResult>, EmptyDump> {
    if rows.is_empty() {
        return Err(EmptyDump);
    }
    Ok(checks()
        .into_iter()
        .map(|(name, check)| CaseResult {
            name,
            outcome: check(rows),
        })
        .collect())
}

#[derive(Debug, Clone, Copy)]
pub struct EmptyDump;

impl std::fmt::Display for EmptyDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing an empty dump: verify-cases proves nothing over zero rows"
        )
    }
}

impl std::error::Error for EmptyDump {}

#[cfg(test)]
mod tests;
