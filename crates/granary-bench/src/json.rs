// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A JSON writer and parser, per dependency-policy rule 1 (prefer our own
//! small code over a dependency whose whole value is convenience). The
//! reproduction control parses committed records, and `verify-wallclock`
//! parses a harness artifact from any path the operator names. Files are
//! committed and diffed by humans, so output is pretty-printed with
//! stable key order.

use core::fmt::Write as _;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// Signed integer, emitted exactly.
    Int(i64),
    /// Unsigned integer, emitted exactly. Byte counts use this — a
    /// 1.8 GB total is exact in `u64` and lossy in `f64`.
    UInt(u64),
    /// Float, emitted with 6 decimal places. Non-finite becomes
    /// `null`: a NaN in a results file must be visible, not printed as
    /// a token no JSON reader accepts.
    Num(f64),
    /// String.
    Str(String),
    /// Array.
    Arr(Vec<Json>),
    /// Object; insertion order is preserved and is the emitted order.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Convenience constructor for string values.
    #[must_use]
    pub fn s(v: impl Into<String>) -> Self {
        Self::Str(v.into())
    }

    /// Render into `out` with two-space indentation.
    pub fn write(&self, out: &mut String) {
        self.write_at(out, 0);
    }

    /// Render to a fresh `String`, newline-terminated.
    #[must_use]
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out.push('\n');
        out
    }

    fn write_at(&self, out: &mut String, depth: usize) {
        let pad = "  ".repeat(depth);
        let inner_pad = "  ".repeat(depth + 1);
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Int(v) => {
                let _ = write!(out, "{v}");
            }
            Self::UInt(v) => {
                let _ = write!(out, "{v}");
            }
            Self::Num(v) => {
                if v.is_finite() {
                    let _ = write!(out, "{v:.6}");
                } else {
                    out.push_str("null");
                }
            }
            Self::Str(v) => write_str(out, v),
            Self::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&inner_pad);
                    item.write_at(out, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Self::Obj(fields) => {
                if fields.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (i, (k, v)) in fields.iter().enumerate() {
                    out.push_str(&inner_pad);
                    write_str(out, k);
                    out.push_str(": ");
                    v.write_at(out, depth + 1);
                    if i + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
        }
    }
}

fn write_str(out: &mut String, v: &str) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests;

// ===========================================================================
// The parser half reads committed records for the reproduction control
// (control 1) and, through `verify-wallclock`, an operator-named artifact
// that is untrusted input. Parsing requires one value followed only by
// whitespace, bounds integer ranges, and caps recursion at MAX_DEPTH. It
// accepts spellings the writer does not emit, including exponent
// notation.
// ===========================================================================

/// Why a byte sequence is not one of our records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset of the refusal.
    pub at: usize,
    /// What was expected.
    pub why: &'static str,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "json parse error at byte {}: {}", self.at, self.why)
    }
}

impl core::error::Error for ParseError {}

/// Recursion ceiling. Our records nest ~5 deep; 64 refuses a pathological
/// file long before the stack is at risk.
const MAX_DEPTH: usize = 64;

impl Json {
    /// Parse one JSON value, requiring end-of-input after it.
    ///
    /// # Errors
    /// [`ParseError`] naming the first offending byte.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let bytes = text.as_bytes();
        let mut pos = 0usize;
        let v = parse_value(bytes, &mut pos, 0)?;
        skip_ws(bytes, &mut pos);
        if pos != bytes.len() {
            return Err(ParseError {
                at: pos,
                why: "trailing bytes after the value",
            });
        }
        Ok(v)
    }
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while let Some(&c) = bytes.get(*pos) {
        if c == b' ' || c == b'\n' || c == b'\t' || c == b'\r' {
            *pos += 1;
        } else {
            break;
        }
    }
}

fn eat(bytes: &[u8], pos: &mut usize, lit: &[u8], why: &'static str) -> Result<(), ParseError> {
    if bytes.get(*pos..*pos + lit.len()) == Some(lit) {
        *pos += lit.len();
        Ok(())
    } else {
        Err(ParseError { at: *pos, why })
    }
}

fn parse_value(bytes: &[u8], pos: &mut usize, depth: usize) -> Result<Json, ParseError> {
    if depth > MAX_DEPTH {
        return Err(ParseError {
            at: *pos,
            why: "nesting deeper than any record this crate writes",
        });
    }
    skip_ws(bytes, pos);
    match bytes.get(*pos) {
        Some(b'n') => eat(bytes, pos, b"null", "expected `null`").map(|()| Json::Null),
        Some(b't') => eat(bytes, pos, b"true", "expected `true`").map(|()| Json::Bool(true)),
        Some(b'f') => eat(bytes, pos, b"false", "expected `false`").map(|()| Json::Bool(false)),
        Some(b'"') => parse_string(bytes, pos).map(Json::Str),
        Some(b'[') => {
            *pos += 1;
            let mut items = Vec::new();
            skip_ws(bytes, pos);
            if bytes.get(*pos) == Some(&b']') {
                *pos += 1;
                return Ok(Json::Arr(items));
            }
            loop {
                items.push(parse_value(bytes, pos, depth + 1)?);
                skip_ws(bytes, pos);
                match bytes.get(*pos) {
                    Some(b',') => *pos += 1,
                    Some(b']') => {
                        *pos += 1;
                        return Ok(Json::Arr(items));
                    }
                    _ => {
                        return Err(ParseError {
                            at: *pos,
                            why: "expected `,` or `]` in array",
                        });
                    }
                }
            }
        }
        Some(b'{') => {
            *pos += 1;
            let mut fields = Vec::new();
            skip_ws(bytes, pos);
            if bytes.get(*pos) == Some(&b'}') {
                *pos += 1;
                return Ok(Json::Obj(fields));
            }
            loop {
                skip_ws(bytes, pos);
                let key = parse_string(bytes, pos)?;
                skip_ws(bytes, pos);
                eat(bytes, pos, b":", "expected `:` after object key")?;
                let value = parse_value(bytes, pos, depth + 1)?;
                fields.push((key, value));
                skip_ws(bytes, pos);
                match bytes.get(*pos) {
                    Some(b',') => *pos += 1,
                    Some(b'}') => {
                        *pos += 1;
                        return Ok(Json::Obj(fields));
                    }
                    _ => {
                        return Err(ParseError {
                            at: *pos,
                            why: "expected `,` or `}` in object",
                        });
                    }
                }
            }
        }
        Some(c) if c.is_ascii_digit() || *c == b'-' => parse_number(bytes, pos),
        _ => Err(ParseError {
            at: *pos,
            why: "expected a JSON value",
        }),
    }
}

fn parse_string(bytes: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    eat(bytes, pos, b"\"", "expected `\"`")?;
    let mut out = String::new();
    loop {
        match bytes.get(*pos) {
            Some(b'"') => {
                *pos += 1;
                return Ok(out);
            }
            Some(b'\\') => {
                *pos += 1;
                match bytes.get(*pos) {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => {
                        let hex = bytes.get(*pos + 1..*pos + 5).ok_or(ParseError {
                            at: *pos,
                            why: "truncated \\u escape",
                        })?;
                        let hex_str = core::str::from_utf8(hex).map_err(|_| ParseError {
                            at: *pos,
                            why: "non-ASCII \\u escape",
                        })?;
                        let n = u32::from_str_radix(hex_str, 16).map_err(|_| ParseError {
                            at: *pos,
                            why: "non-hex \\u escape",
                        })?;
                        // The writer only emits \u for C0 controls;
                        // surrogates are refused rather than paired.
                        let c = char::from_u32(n).ok_or(ParseError {
                            at: *pos,
                            why: "\\u escape is not a scalar value",
                        })?;
                        out.push(c);
                        *pos += 4;
                    }
                    _ => {
                        return Err(ParseError {
                            at: *pos,
                            why: "unknown escape",
                        });
                    }
                }
                *pos += 1;
            }
            Some(&c) if c < 0x20 => {
                return Err(ParseError {
                    at: *pos,
                    why: "raw control byte in string",
                });
            }
            Some(_) => {
                // Multi-byte UTF-8 passes through byte-wise; the input
                // was a &str, so it is valid UTF-8 by construction.
                let start = *pos;
                let mut end = *pos + 1;
                while bytes.get(end).is_some_and(|&c| c & 0xC0 == 0x80) {
                    end += 1;
                }
                if let Some(slice) = bytes.get(start..end)
                    && let Ok(s) = core::str::from_utf8(slice)
                {
                    out.push_str(s);
                }
                *pos = end;
            }
            None => {
                return Err(ParseError {
                    at: *pos,
                    why: "unterminated string",
                });
            }
        }
    }
}

fn parse_number(bytes: &[u8], pos: &mut usize) -> Result<Json, ParseError> {
    let start = *pos;
    if bytes.get(*pos) == Some(&b'-') {
        *pos += 1;
    }
    let mut float = false;
    while let Some(&c) = bytes.get(*pos) {
        if c.is_ascii_digit() {
            *pos += 1;
        } else if c == b'.' || c == b'e' || c == b'E' || c == b'+' || c == b'-' {
            // `-` only re-appears in an exponent; the writer never emits
            // one, but a hand-edited record might.
            float = true;
            *pos += 1;
        } else {
            break;
        }
    }
    let text = core::str::from_utf8(bytes.get(start..*pos).unwrap_or_default()).unwrap_or_default();
    if text.is_empty() || text == "-" {
        return Err(ParseError {
            at: start,
            why: "expected digits",
        });
    }
    if float {
        return text.parse::<f64>().map(Json::Num).map_err(|_| ParseError {
            at: start,
            why: "unparseable number",
        });
    }
    if text.starts_with('-') {
        // Parsed WITH the sign: strip-then-negate cannot represent
        // i64::MIN (its magnitude is one past i64::MAX), so the one
        // value the writer emits at the boundary would refuse to round
        // trip.
        return text.parse::<i64>().map(Json::Int).map_err(|_| ParseError {
            at: start,
            why: "integer out of i64 range",
        });
    }
    text.parse::<u64>().map(Json::UInt).map_err(|_| ParseError {
        at: start,
        why: "integer out of u64 range",
    })
}

impl Json {
    /// Look up a key in an object; `None` for non-objects and misses.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The array items; `None` for non-arrays.
    #[must_use]
    pub fn items(&self) -> Option<&[Self]> {
        match self {
            Self::Arr(items) => Some(items),
            _ => None,
        }
    }
}
