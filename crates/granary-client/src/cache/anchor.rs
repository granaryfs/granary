// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The anchor file: a two-line record of the highest head this cache has
//! seen, parsed and rendered so it cannot lie about it.
//!
//! **What breaks when this module is wrong:** a mount's rollback floor
//! reads lower than the head that was actually confirmed, and a stale or
//! forged root is served as current — or it reads HIGHER, and a legal head
//! is refused forever. A grammar that normalises instead of refusing is
//! the same defect wearing a friendly face: a leading-zero sequence, a
//! token outside the printable band, a stamp with more digits than the
//! field admits, each must refuse rather than round-trip to something
//! plausible.
//!
//! It owns the field widths and byte bands, the per-field parsers, the
//! two line parsers, the whole-file parser and the renderer that is its
//! exact inverse. It does NOT own the values it parses into —
//! [`super::HeadAnchor`] and [`super::PersistedHint`] are the parent's
//! vocabulary — nor WHERE the file lives, nor when it is written: the
//! paths are `super::paths`'s and the raise decision is the cache's own
//! state machine.
//!
//! It reaches no sibling at all, which is the measurement and not an
//! assumption: the path constructors its callers use are called from
//! `impl Cache` and `WriterState`, never from inside this module.
//!
//! Out-of-line, and a child one flat
//! level under `cache/`, beside `paths`,
//! `write`, `marker` and `index-load`.

use std::fs;
use std::io::Read;
use std::path::Path;
// `PathBuf` appears only in `PathReadPostStatHook`, which is `#[cfg(test)]`.
#[cfg(test)]
use std::path::PathBuf;

use granary_core::rootstore::{SEQ_KEY_DIGITS, is_reserved_seq, parse_hint_body};

use crate::fsguard;

use super::{ANCHOR_FILE_MAX_BYTES, HeadAnchor, PersistedHint};

/// Width of the `seq` field in either the `seq` or `hint` line — the
/// SAME width `granary_core::rootstore::SEQ_KEY_DIGITS` uses (root keys
/// and the CURRENT hint body), not an independently chosen number.
pub(super) const ANCHOR_SEQ_WIDTH: usize = SEQ_KEY_DIGITS;

/// A persisted hint token's legal byte range (ASCII printable,
/// excluding space) and length.
pub(super) const ANCHOR_TOKEN_MIN_BYTE: u8 = 0x21;

pub(super) const ANCHOR_TOKEN_MAX_BYTE: u8 = 0x7E;

pub(super) const ANCHOR_TOKEN_MAX_LEN: usize = 512;

/// A persisted stamp's legal decimal-digit count — 1..=19, the widest
/// `i64` can ever need.
const ANCHOR_STAMP_MAX_DIGITS: usize = 19;

/// `seq`/`hint`'s shared seq field: exactly [`ANCHOR_SEQ_WIDTH`] ASCII
/// digits, fitting a `u64`, and never one of the two values that can
/// never be a head (seq 0 and the reserved
/// `u64::MAX`) — this writer can never produce either, so encountering
/// one here is foreign input, not a value this reader may act on.
/// Reuses core's own strict 20-digit parse ([`parse_hint_body`]) rather
/// than re-implementing it: same width, same digit-only strictness, same
/// overflow refusal — verified against `rootstore`'s own
/// `hint_body_is_exactly_twenty_digits_strict_parsed` row.
fn parse_anchor_seq(field: &str) -> Option<u64> {
    let seq = parse_hint_body(field).ok()?;
    (!is_reserved_seq(seq)).then_some(seq)
}

/// A persisted hint token: bytes 0x21..=0x7E only (excludes space, so
/// the field never shifts the line's whitespace-separated grammar),
/// length 1..=512. An `ETag` that fails this bound is UNPERSISTABLE —
/// [`super::WriterState::raise_anchor`] omits the hint line rather than write
/// one, the floor line still lands.
fn valid_anchor_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= ANCHOR_TOKEN_MAX_LEN
        && token
            .bytes()
            .all(|b| (ANCHOR_TOKEN_MIN_BYTE..=ANCHOR_TOKEN_MAX_BYTE).contains(&b))
}

fn parse_anchor_token(field: &str) -> Option<String> {
    valid_anchor_token(field).then(|| field.to_owned())
}

/// Whether a [`PersistedHint`] can be rendered into the strict grammar
/// [`parse_anchor_bytes`] accepts back. The token must be in range,
/// the stamp renderable as unsigned decimal (a negative `i64` renders with a sign),
/// and the hint seq outside the two absent-class values. A hint that
/// fails ANY of these omits the hint LINE (the floor line still
/// writes); rendering it instead would produce a file this module's
/// own strict reader refuses whole — silently erasing the just-written
/// FLOOR on the next read, and with it the per-volume rollback defence.
pub(super) fn persistable_anchor_hint(h: &PersistedHint) -> bool {
    valid_anchor_token(&h.token) && h.stamp_secs >= 0 && !is_reserved_seq(h.seq)
}

/// A persisted stamp: unsigned decimal, 1..=19 digits, fitting an
/// `i64`, in CANONICAL form — no leading zero except the single digit
/// `"0"` itself. Freshness (including the "a future stamp is STALE"
/// rule) is `head.rs`'s job — this only parses the field.
///
/// The leading-zero refusal is what keeps the grammar CANONICAL: the
/// renderer writes the stamp as a plain `{i64}` with no padding, so
/// `"05"` and `"5"` would both decode to `5` while only `"5"`
/// re-renders — decode-then-encode would not reproduce the input, and
/// the `fuzz_probe::anchor_decode_probe` canonical-form assertion (a
/// second encoding must never decode to the same value) would panic on
/// `"05"`. The seq fields dodge this by being fixed-width (exactly
/// [`ANCHOR_SEQ_WIDTH`] digits, so `"05"` is not even a valid seq); the
/// variable-width stamp needs the check made explicitly.
fn parse_anchor_stamp(field: &str) -> Option<i64> {
    if field.is_empty()
        || field.len() > ANCHOR_STAMP_MAX_DIGITS
        || !field.bytes().all(|b| b.is_ascii_digit())
        || (field.len() > 1 && field.starts_with('0'))
    {
        return None;
    }
    field.parse().ok()
}

fn parse_anchor_seq_line(line: &str) -> Option<u64> {
    let mut fields = line.split(' ');
    if fields.next() != Some("seq") {
        return None;
    }
    let seq = fields.next().and_then(parse_anchor_seq)?;
    if fields.next().is_some() {
        return None;
    }
    Some(seq)
}

fn parse_anchor_hint_line(line: &str) -> Option<PersistedHint> {
    let mut fields = line.split(' ');
    if fields.next() != Some("hint") {
        return None;
    }
    let seq = fields.next().and_then(parse_anchor_seq)?;
    let token = fields.next().and_then(parse_anchor_token)?;
    let stamp_secs = fields.next().and_then(parse_anchor_stamp)?;
    if fields.next().is_some() {
        return None;
    }
    Some(PersistedHint {
        seq,
        token,
        stamp_secs,
    })
}

/// Strict-parse an `anchors/<volume>` file: exactly `"seq <20
/// digits>\n"`, or that plus `"hint <20 digits> <token>
/// <unix-seconds>\n"` — nothing else. ANY deviation — an extra field, a missing trailing
/// newline, trailing bytes after it, non-UTF-8, an absent-class seq
/// value, an out-of-range token or stamp — degrades the WHOLE file to
/// `None` (absent). This is deliberately ONE strict pass with no partial
/// credit: a well-formed-looking file with one bad field is exactly as
/// untrustworthy as garbage bytes, and a single total function is what
/// makes that provable rather than assumed.
///
/// `pub(crate)`, not private: [`crate::fuzz_probe::anchor_decode_probe`]
/// is this parser's `format-object` fuzz obligation (coding-standards
/// MUST rule 3) — a byte-level parser of attacker-writable disk content.
pub(crate) fn parse_anchor_bytes(bytes: &[u8]) -> Option<HeadAnchor> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split('\n');
    let seq = lines.next().and_then(parse_anchor_seq_line)?;
    match (lines.next(), lines.next(), lines.next()) {
        // "seq X\n" — split('\n') on a string ending in '\n' yields one
        // trailing empty string and nothing after it.
        (Some(""), None, None) => Some(HeadAnchor { seq, hint: None }),
        // "seq X\nhint Y T S\n"
        (Some(hint_line), Some(""), None) => {
            let hint = parse_anchor_hint_line(hint_line)?;
            Some(HeadAnchor {
                seq,
                hint: Some(hint),
            })
        }
        _ => None,
    }
}

/// Render [`HeadAnchor`]'s two lines. `hint` is `None` either because
/// none was ever confirmed, or because [`super::WriterState::raise_anchor`]
/// found the caller's token unpersistable and omitted it — the floor
/// line still renders either way.
///
/// `pub(crate)`: [`crate::fuzz_probe::anchor_decode_probe`] uses this to
/// assert [`parse_anchor_bytes`]'s canonical-form property.
pub(crate) fn render_anchor_bytes(seq: u64, hint: Option<&PersistedHint>) -> Vec<u8> {
    use std::fmt::Write as _;

    let mut out = format!("seq {seq:0ANCHOR_SEQ_WIDTH$}\n");
    if let Some(h) = hint
        && persistable_anchor_hint(h)
    {
        let _ = writeln!(
            out,
            "hint {:0ANCHOR_SEQ_WIDTH$} {} {}",
            h.seq, h.token, h.stamp_secs
        );
    }
    out.into_bytes()
}

#[cfg(test)]
pub(super) struct PathReadPostStatHook {
    pub(super) path: PathBuf,
    pub(super) action: Box<dyn FnOnce() + Send>,
}

#[cfg(test)]
pub(super) static PATH_READ_POST_STAT_HOOKS: std::sync::Mutex<Vec<PathReadPostStatHook>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(super) fn run_path_read_post_stat_hook(path: &Path) {
    let Ok(mut hooks) = PATH_READ_POST_STAT_HOOKS.lock() else {
        return;
    };
    let selected = hooks
        .iter()
        .position(|hook| hook.path == path)
        .map(|position| hooks.swap_remove(position));
    drop(hooks);
    if let Some(hook) = selected {
        (hook.action)();
    }
}

/// Bounded read of `anchors/<volume>`, shared by [`super::Cache::read_anchor`]
/// and [`super::WriterState::raise_anchor`]'s own read-compare-rename cycle —
/// same discipline as [`super::Cache::get_root_bytes`]: size checked BEFORE any
/// content read, over-cap is the same untrustworthy class a failed parse
/// is, never an unbounded read of attacker-writable disk.
fn read_anchor_bytes_bounded(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > ANCHOR_FILE_MAX_BYTES {
        crate::observe::OperatorDiagnostic::cache_anchor_file_exceeds_the_size_bound_treating_it(
            meta.len(),
        )
        .emit();
        return None;
    }
    #[cfg(test)]
    run_path_read_post_stat_hook(path);
    let mut buf = Vec::new();
    let f = fsguard::open_regular_read(path).ok()?;
    f.take(ANCHOR_FILE_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() as u64 > ANCHOR_FILE_MAX_BYTES {
        crate::observe::OperatorDiagnostic::cache_anchor_file_exceeds_the_size_bound_treating_it(
            (buf.len()) as u64,
        )
        .emit();
        return None;
    }
    Some(buf)
}

/// Bounded read + strict parse of `anchors/<volume>`, with the shared
/// "failed strict parse" warning — [`super::Cache::read_anchor`] and
/// [`super::WriterState::raise_anchor`]'s own read-compare step both need this
/// identical sequence.
pub(super) fn read_and_parse_anchor(path: &Path) -> Option<HeadAnchor> {
    let bytes = read_anchor_bytes_bounded(path)?;
    let parsed = parse_anchor_bytes(&bytes);
    if parsed.is_none() {
        crate::observe::OperatorDiagnostic::cache_anchor_file_failed_strict_parse_treating_it_as()
            .emit();
    }
    parsed
}

/// Bounded read + strict parse of `anchors/<volume>.mount`, reusing
/// [`read_and_parse_anchor`]'s bounded read and strict grammar
/// wholesale (do not copy the parser) — with one additional rule
/// this file's own narrower grammar imposes: it is a floor and NEVER
/// a hint, so a file that DOES carry a `hint` line is refused whole,
/// exactly as any other grammar deviation degrades the whole file to
/// absent. A hint line is not a value to silently drop while keeping
/// the seq — this file was never a trusted mount-private floor to
/// begin with if it carries one, the same "well-formed-looking with
/// one bad field is exactly as untrustworthy as garbage" discipline
/// [`parse_anchor_bytes`]'s own doc states for the shared anchor.
pub(super) fn read_and_parse_mount_anchor(path: &Path) -> Option<u64> {
    let anchor = read_and_parse_anchor(path)?;
    if anchor.hint.is_some() {
        crate::observe::OperatorDiagnostic::mount_anchor_file_carries_a_hint_line_which_its()
            .emit();
        return None;
    }
    Some(anchor.seq)
}

#[cfg(test)]
mod tests;
