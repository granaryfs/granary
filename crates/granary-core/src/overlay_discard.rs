// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical names, selection digest and operator output for overlay discard v1.

use crate::root::VolumeName;
use std::fmt::{self, Write as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDiscard;
impl fmt::Display for InvalidDiscard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid overlay discard v1 encoding")
    }
}
impl std::error::Error for InvalidDiscard {}

/// Decode exact lowercase hexadecimal.
/// # Errors
/// The width or digits are noncanonical.
pub fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], InvalidDiscard> {
    if text.len() != N.saturating_mul(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(InvalidDiscard);
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| InvalidDiscard)?;
        *out = u8::from_str_radix(pair, 16).map_err(|_| InvalidDiscard)?;
    }
    Ok(bytes)
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardName {
    pub volume: VolumeName,
    pub writer: [u8; 16],
    pub incarnation: [u8; 32],
}

impl DiscardName {
    /// Parse a reserved leaf, with a flag for the intent suffix.
    /// # Errors
    /// A name claims the namespace but fails the v1 grammar.
    pub fn parse(bytes: &[u8]) -> Result<Option<(Self, bool)>, InvalidDiscard> {
        if !bytes.windows(8).any(|part| part == b".discard") {
            return Ok(None);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| InvalidDiscard)?;
        let (volume, rest) = text.split_once(".discard-v1-").ok_or(InvalidDiscard)?;
        let (writer, id) = rest.split_once('-').ok_or(InvalidDiscard)?;
        let intent = id.strip_suffix(".intent");
        Ok(Some((
            Self {
                volume: VolumeName::from_bytes(volume.as_bytes()).map_err(|_| InvalidDiscard)?,
                writer: parse_hex(writer)?,
                incarnation: parse_hex(intent.unwrap_or(id))?,
            },
            intent.is_some(),
        )))
    }

    #[must_use]
    pub fn leaf(&self, intent: bool) -> String {
        format!(
            "{}.discard-v1-{}-{}{}",
            self.volume.as_str(),
            hex(&self.writer),
            hex(&self.incarnation),
            if intent { ".intent" } else { "" }
        )
    }
}

/// A directory or a file's length and raw BLAKE3 digest.
pub type InventoryEntry = (Vec<u8>, Option<(u64, [u8; 32])>);

/// The lists are in raw relative-name order and exclude their root directories.
/// # Errors
/// A name exceeds the u16 length field.
pub fn incarnation(
    root: &[u8],
    scope: &[u8; 32],
    volume: &VolumeName,
    writer: &[u8; 16],
    overlay: &[InventoryEntry],
    publications: &[InventoryEntry],
) -> Result<[u8; 32], InvalidDiscard> {
    fn name(hash: &mut blake3::Hasher, bytes: &[u8]) -> Result<(), InvalidDiscard> {
        hash.update(
            &u16::try_from(bytes.len())
                .map_err(|_| InvalidDiscard)?
                .to_be_bytes(),
        );
        hash.update(bytes);
        Ok(())
    }
    let mut hash = blake3::Hasher::new_derive_key("granary overlay discard selection v1");
    hash.update(b"GRANARY\0\0\x01");
    name(&mut hash, root)?;
    hash.update(scope);
    name(&mut hash, volume.as_str().as_bytes())?;
    hash.update(writer);
    for (tag, entries) in [(1, overlay), (2, publications)] {
        hash.update(&[tag]);
        hash.update(&(entries.len() as u64).to_be_bytes());
        for (relative, file) in entries {
            hash.update(&[u8::from(file.is_some())]);
            name(&mut hash, relative)?;
            if let Some((length, digest)) = file {
                hash.update(&length.to_be_bytes());
                hash.update(digest);
            }
        }
    }
    Ok(*hash.finalize().as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Live(u64),
    Pending(u64),
    Archived(u64),
    Moved,
    AlreadyArchived,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub scope: [u8; 32],
    pub name: DiscardName,
    pub bytes: u64,
    pub outcome: Outcome,
}

impl Row {
    fn archive(&self) -> String {
        format!("overlay/{}/{}", hex(&self.scope), self.name.leaf(false))
    }

    /// Decode one complete, canonical TSV row.
    /// # Errors
    /// The row exceeds the bound or has noncanonical framing or fields.
    pub fn parse(bytes: &[u8]) -> Result<Self, InvalidDiscard> {
        // A max-length volume occurs twice in the already-archived row.
        if bytes.len() > 530 {
            return Err(InvalidDiscard);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| InvalidDiscard)?;
        let fields: Vec<_> = text
            .strip_suffix('\n')
            .ok_or(InvalidDiscard)?
            .split('\t')
            .collect();
        let ["overlay-discard-v1", scope, volume, writer, id, state, a, b] = fields.as_slice()
        else {
            return Err(InvalidDiscard);
        };
        let number = |text: &str| {
            text.parse::<u64>()
                .ok()
                .filter(|n| n.to_string() == text)
                .ok_or(InvalidDiscard)
        };
        let mut row = Self {
            scope: parse_hex(scope)?,
            name: DiscardName {
                volume: VolumeName::from_bytes(volume.as_bytes()).map_err(|_| InvalidDiscard)?,
                writer: parse_hex(writer)?,
                incarnation: parse_hex(id)?,
            },
            bytes: 0,
            outcome: Outcome::Moved,
        };
        if matches!(*state, "archived" | "already-archived") && *a == row.archive() {
            row.bytes = number(b)?;
            if *state == "already-archived" {
                row.outcome = Outcome::AlreadyArchived;
            }
        } else {
            row.bytes = number(a)?;
            let files = number(b)?;
            row.outcome = match *state {
                "live" => Outcome::Live(files),
                "discard-pending" => Outcome::Pending(files),
                "archived" => Outcome::Archived(files),
                _ => return Err(InvalidDiscard),
            };
        }
        Ok(row)
    }
}

impl fmt::Display for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "overlay-discard-v1\t{}\t{}\t{}\t{}\t",
            hex(&self.scope),
            self.name.volume.as_str(),
            hex(&self.name.writer),
            hex(&self.name.incarnation),
        )?;
        match self.outcome {
            Outcome::Live(files) => writeln!(f, "live\t{}\t{files}", self.bytes),
            Outcome::Pending(files) => writeln!(f, "discard-pending\t{}\t{files}", self.bytes),
            Outcome::Archived(files) => writeln!(f, "archived\t{}\t{files}", self.bytes),
            Outcome::Moved => writeln!(f, "archived\t{}\t{}", self.archive(), self.bytes),
            Outcome::AlreadyArchived => {
                writeln!(f, "already-archived\t{}\t{}", self.archive(), self.bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests;
