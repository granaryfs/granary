// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The dump row: `<escaped-path>\t<kind>\t<dtype>\t<size|->\t<exec|->\t<payload>`,
//! and its (de)serialization. This module never touches a filesystem —
//! [`crate::walk`] builds [`Row`]s from a real tree; [`crate::compare`]
//! and [`crate::verify_cases`] read them back from a dump file's text.

use crate::escape::{self, DecodeError};

/// The row's `kind` column — the lstat-derived kind the traversal is
/// keyed on, never the raw `d_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

impl Kind {
    const fn token(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "file" => Some(Self::File),
            "dir" => Some(Self::Dir),
            "symlink" => Some(Self::Symlink),
            _ => None,
        }
    }
}

/// The row's `dtype` column — the RAW readdir answer, recorded exactly
/// as `nix::dir::Entry::file_type()` reported it. `DT_UNKNOWN` never
/// reaches this type: [`crate::walk`] refuses it as a loud precondition
/// before a [`Row`] is ever built: source-side `unknown` is a loud
/// precondition refusal, never a skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DType {
    Fifo,
    Chr,
    Dir,
    Blk,
    File,
    Symlink,
    Sock,
}

impl DType {
    const fn token(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Chr => "chr",
            Self::Dir => "dir",
            Self::Blk => "blk",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Sock => "sock",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "fifo" => Some(Self::Fifo),
            "chr" => Some(Self::Chr),
            "dir" => Some(Self::Dir),
            "blk" => Some(Self::Blk),
            "file" => Some(Self::File),
            "symlink" => Some(Self::Symlink),
            "sock" => Some(Self::Sock),
            _ => None,
        }
    }
}

/// The row's `payload` column. Which variant is legal depends on
/// [`Kind`] — [`new_row`] and [`parse_line`] both enforce that
/// pairing; nothing downstream can construct a mismatched row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// `-`, for directories.
    None,
    /// The blake3 hex digest of the full content read through the
    /// filesystem, for regular files. Never escaped — blake3's hex
    /// alphabet is already inside the passthrough set.
    Content(String),
    /// The symlink target's raw bytes, exactly as `readlink(2)`
    /// returned them (escaped only at render time).
    Target(Vec<u8>),
}

/// One dump row: one filesystem entry, fully classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The raw relative path bytes (decoded — never the escaped text).
    pub path: Vec<u8>,
    pub kind: Kind,
    pub dtype: DType,
    /// `Some` for [`Kind::File`] only; a directory's size is
    /// synthesized (not observed) and a symlink's is superseded by
    /// comparing target bytes, so both render `-`.
    pub size: Option<u64>,
    /// `mode & 0o111 != 0` — harvest's own predicate
    /// (`crates/granary-client/src/harvest.rs`), computed uniformly
    /// for every kind from the entry's own lstat mode.
    pub exec: bool,
    pub payload: Payload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowError {
    /// A `Kind`/`Payload` pairing that no walk can produce (only
    /// reachable by parsing hand-edited or corrupt dump text).
    KindPayloadMismatch {
        kind: Kind,
    },
    WrongFieldCount {
        got: usize,
    },
    BadKind {
        text: String,
    },
    BadDType {
        text: String,
    },
    BadSize {
        text: String,
    },
    BadExec {
        text: String,
    },
    BadContent {
        text: String,
    },
    Decode(DecodeError),
}

impl std::fmt::Display for RowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KindPayloadMismatch { kind } => {
                write!(f, "payload does not match kind {}", kind.token())
            }
            Self::WrongFieldCount { got } => {
                write!(f, "expected 6 tab-separated fields, got {got}")
            }
            Self::BadKind { text } => write!(f, "unknown kind {text:?}"),
            Self::BadDType { text } => write!(f, "unknown dtype {text:?}"),
            Self::BadSize { text } => write!(f, "bad size field {text:?}"),
            Self::BadExec { text } => write!(f, "bad exec field {text:?} (want x or -)"),
            Self::BadContent { text } => {
                write!(
                    f,
                    "bad content payload {text:?} (want 64 lowercase hex digits)"
                )
            }
            Self::Decode(e) => write!(f, "path: {e}"),
        }
    }
}

impl std::error::Error for RowError {}

impl From<DecodeError> for RowError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// Build a row, refusing any [`Kind`]/[`Payload`] pairing a real walk
/// could never produce — the single choke point both [`crate::walk`]
/// and [`parse_line`] go through, so the invariant holds for a row
/// built off a real tree and one parsed back from text alike.
///
/// # Errors
/// [`RowError::KindPayloadMismatch`] if `kind`, `size` and `payload`
/// disagree about which of a file/dir/symlink this is.
pub fn new_row(
    path: Vec<u8>,
    kind: Kind,
    dtype: DType,
    size: Option<u64>,
    exec: bool,
    payload: Payload,
) -> Result<Row, RowError> {
    let shape_ok = matches!(
        (kind, &size, &payload),
        (Kind::File, Some(_), Payload::Content(_))
            | (Kind::Dir, None, Payload::None)
            | (Kind::Symlink, None, Payload::Target(_))
    );
    if !shape_ok {
        return Err(RowError::KindPayloadMismatch { kind });
    }
    Ok(Row {
        path,
        kind,
        dtype,
        size,
        exec,
        payload,
    })
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Render one [`Row`] as its tab-separated ASCII line (no trailing
/// newline).
#[must_use]
pub fn render_line(row: &Row) -> String {
    let path = escape::escape(&row.path);
    let size = row.size.map_or_else(|| "-".to_owned(), |n| n.to_string());
    let exec = if row.exec { "x" } else { "-" };
    let payload = match &row.payload {
        Payload::None => "-".to_owned(),
        Payload::Content(hex) => hex.clone(),
        Payload::Target(bytes) => escape::escape(bytes),
    };
    format!(
        "{path}\t{}\t{}\t{size}\t{exec}\t{payload}",
        row.kind.token(),
        row.dtype.token()
    )
}

/// Parse one tab-separated dump line back into a [`Row`].
///
/// # Errors
/// A [`RowError`] naming exactly which field failed to parse.
pub fn parse_line(line: &str) -> Result<Row, RowError> {
    let fields: Vec<&str> = line.split('\t').collect();
    let [path_f, kind_f, dtype_f, size_f, exec_f, payload_f] = fields.as_slice() else {
        return Err(RowError::WrongFieldCount { got: fields.len() });
    };
    let path = escape::decode(path_f)?;
    let kind = Kind::parse(kind_f).ok_or_else(|| RowError::BadKind {
        text: (*kind_f).to_owned(),
    })?;
    let dtype = DType::parse(dtype_f).ok_or_else(|| RowError::BadDType {
        text: (*dtype_f).to_owned(),
    })?;
    let size = if *size_f == "-" {
        None
    } else {
        Some(size_f.parse::<u64>().map_err(|_| RowError::BadSize {
            text: (*size_f).to_owned(),
        })?)
    };
    let exec = match *exec_f {
        "x" => true,
        "-" => false,
        other => {
            return Err(RowError::BadExec {
                text: other.to_owned(),
            });
        }
    };
    let payload = match kind {
        Kind::Dir => {
            // The payload column is part of the row's shape, so a dir row
            // must carry exactly `-`. Synthesising `None` regardless would
            // let a corrupted or hand-edited dump parse and then compare
            // EQUAL to the canonical row, which is precisely the corruption
            // `parse_dump` exists to refuse.
            if *payload_f != "-" {
                return Err(RowError::KindPayloadMismatch { kind });
            }
            Payload::None
        }
        Kind::File => {
            if !is_hex64(payload_f) {
                return Err(RowError::BadContent {
                    text: (*payload_f).to_owned(),
                });
            }
            Payload::Content((*payload_f).to_owned())
        }
        Kind::Symlink => Payload::Target(escape::decode(payload_f)?),
    };
    new_row(path, kind, dtype, size, exec, payload)
}

#[derive(Debug)]
pub enum DumpParseError {
    Row {
        line_number: usize,
        source: RowError,
    },
    DuplicatePath(crate::walk::WalkError),
}

impl std::fmt::Display for DumpParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Row {
                line_number,
                source,
            } => write!(f, "line {line_number}: {source}"),
            Self::DuplicatePath(source) => source.fmt(f),
        }
    }
}

impl std::error::Error for DumpParseError {}

/// Parse a whole dump artifact's text into rows, re-sorted by raw path
/// bytes regardless of the input's own order — never trust that a
/// dump file on disk was not hand-edited or concatenated out of order;
/// re-establishing the order here is what makes every downstream
/// merge-join correct without a separate "is this sorted" precondition.
///
/// # Errors
/// [`DumpParseError`] naming the first line that failed to parse and
/// why, 1-indexed to match a text editor.
pub fn parse_dump(text: &str) -> Result<Vec<Row>, DumpParseError> {
    let mut rows = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let row = parse_line(line).map_err(|source| DumpParseError::Row {
            line_number: i.saturating_add(1),
            source,
        })?;
        rows.push(row);
    }
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    crate::walk::refuse_duplicate_escaped_paths(&rows).map_err(DumpParseError::DuplicatePath)?;
    Ok(rows)
}

#[cfg(test)]
mod tests;
