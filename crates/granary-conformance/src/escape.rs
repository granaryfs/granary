// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The dump row's path/target escaper: an injective byte-to-ASCII
//! codec, never `OsStr::to_string_lossy` (which collapses distinct
//! non-UTF-8 names onto one output and defeats the whole point of a
//! byte-precise oracle).
//!
//! Every byte outside `[A-Za-z0-9._/-]` renders as `\xNN`, always
//! EXACTLY two lowercase hex digits — `\x7` for byte 0x07 would make
//! `\x7f` ambiguous against the two-byte sequence `\x7` + `f`. A literal
//! backslash (0x5c) is never passed through, precisely because it is
//! the escaper's own marker byte: it always renders `\x5c`. `/` (0x2f)
//! is the one deliberate passthrough exception, because it is the
//! walker's structural path separator and never appears inside a single
//! component's name (the kernel refuses `/` in a directory-entry name,
//! and [`granary_core::manifest::Name`] rejects it too) — so a literal
//! `/` in the escaped text is unambiguously a separator, never part of
//! an escaped byte.

/// Passthrough bytes: `[A-Za-z0-9._/-]`, rendered as themselves.
fn passthrough(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-')
}

/// Render raw bytes (a full relative path, `/`-joined component bytes)
/// as an injective ASCII string. Round-trips through [`decode`] for
/// every input, including the empty slice.
#[must_use]
pub fn escape(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if passthrough(b) {
            // `passthrough` never admits `\` (0x5c is not alphanumeric
            // and not one of `._/-`), so this arm never emits a bare
            // backslash — the decoder's `\x` scan stays unambiguous.
            out.push(b as char);
        } else {
            // `write!` to a `String` is infallible; the formatter
            // error type just has no live constructor here.
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A `\` not followed by `xNN` (exactly two hex digits) at `at`.
    BadEscape { at: usize },
    /// A trailing `\` with no room for `xNN`.
    Truncated,
    /// A byte whose representation is not the encoder's canonical one.
    NonCanonical { at: usize },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadEscape { at } => write!(f, "malformed \\xNN escape at byte {at}"),
            Self::Truncated => write!(f, "input ends mid-escape"),
            Self::NonCanonical { at } => {
                write!(f, "non-canonical byte representation at byte {at}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Invert [`escape`]. `text` is the escaped ASCII rendering; the
/// returned `Vec<u8>` is the exact original bytes.
///
/// # Errors
/// [`DecodeError`] if `text` contains a malformed escape or any byte in
/// a representation [`escape`] would not emit. This can only happen on
/// hand-edited or corrupt input, never on this module's own output.
pub fn decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b != b'\\' {
            if !passthrough(b) {
                return Err(DecodeError::NonCanonical { at: i });
            }
            out.push(b);
            i = i.saturating_add(1);
            continue;
        }
        let marker = bytes.get(i.saturating_add(1));
        if marker != Some(&b'x') {
            return Err(DecodeError::BadEscape { at: i });
        }
        let hi = bytes.get(i.saturating_add(2));
        let lo = bytes.get(i.saturating_add(3));
        let (Some(&hi), Some(&lo)) = (hi, lo) else {
            return Err(DecodeError::Truncated);
        };
        // LOWERCASE ONLY, because the renderer emits lowercase and this
        // format's whole value is that one byte string has exactly one
        // rendering. `to_digit(16)` also accepts A-F, which would make
        // `\xFF` and `\xff` two texts decoding to one path -- an
        // injective escaper with a non-injective decoder is not injective.
        let lower_hex = |b: u8| -> Option<u32> {
            match b {
                b'0'..=b'9' | b'a'..=b'f' => (b as char).to_digit(16),
                _ => None,
            }
        };
        let (Some(hi), Some(lo)) = (lower_hex(hi), lower_hex(lo)) else {
            return Err(DecodeError::BadEscape { at: i });
        };
        // `hi`/`lo` are each < 16 (`to_digit(16)` proves it), so
        // `hi * 16 + lo` < 256 and the mask below is provably a no-op
        // — kept anyway so the `as u8` cast is lossless BY
        // CONSTRUCTION rather than by an un-checked range argument.
        let decoded = ((hi * 16 + lo) & 0xff) as u8;
        if passthrough(decoded) {
            return Err(DecodeError::NonCanonical { at: i });
        }
        out.push(decoded);
        i = i.saturating_add(4);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
