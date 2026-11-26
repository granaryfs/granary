// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Pure parsing of the reserved retained-publication archive namespace.

use crate::root::VolumeName;

/// A canonical sibling archive name, bound to a volume and publication identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveName {
    pub volume: VolumeName,
    pub publication_id: [u8; 16],
    pub settled: bool,
}

/// A name claiming the archive namespace failed its canonical grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidArchiveName;
impl std::fmt::Display for InvalidArchiveName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed retained archive name")
    }
}
impl std::error::Error for InvalidArchiveName {}

/// Whether bytes are the canonical lowercase digest directory component.
#[must_use]
pub fn is_scope_digest(bytes: &[u8]) -> bool {
    bytes.len() == 64
        && bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

impl ArchiveName {
    /// Parse a canonical name, or return `None` for an unrelated name.
    /// `VolumeName` is a DNS-1123 label containing no dots. Splitting at the first
    /// dot is therefore unambiguous and disjoint from live and temporary names.
    /// Any occurrence of `.abandoned` or `.settled` claims the reserved namespace, including
    /// non-UTF-8 names and invalid volume prefixes.
    /// # Errors
    /// A reserved claimant is not a canonical abandoned or settled name.
    pub fn parse(bytes: &[u8]) -> Result<Option<Self>, InvalidArchiveName> {
        if ![b".abandoned".as_slice(), b".settled".as_slice()]
            .iter()
            .any(|tag| bytes.windows(tag.len()).any(|w| w == *tag))
        {
            return Ok(None);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| InvalidArchiveName)?;
        let (volume, suffix) = text.split_once('.').ok_or(InvalidArchiveName)?;
        let volume = VolumeName::from_bytes(volume.as_bytes()).map_err(|_| InvalidArchiveName)?;
        let settled = suffix.starts_with("settled-");
        let hex = suffix
            .strip_prefix(if settled { "settled-" } else { "abandoned-" })
            .and_then(|s| s.strip_suffix(".sub"))
            .ok_or(InvalidArchiveName)?;
        if hex.len() != 32 {
            return Err(InvalidArchiveName);
        }
        let mut publication_id = [0; 16];
        for (out, pair) in publication_id
            .iter_mut()
            .zip(hex.as_bytes().chunks_exact(2))
        {
            let nibble = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(InvalidArchiveName),
            };
            let hi = nibble(*pair.first().ok_or(InvalidArchiveName)?)?;
            let lo = nibble(*pair.get(1).ok_or(InvalidArchiveName)?)?;
            *out = hi * 16 + lo;
        }
        Ok(Some(Self {
            volume,
            publication_id,
            settled,
        }))
    }

    /// Render the unique canonical filename for this identity, including zero.
    #[must_use]
    pub fn file_name(&self) -> String {
        let mut hex = String::with_capacity(32);
        for byte in self.publication_id {
            for nibble in [byte >> 4, byte & 15] {
                hex.push(char::from(if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + nibble - 10
                }));
            }
        }
        let kind = if self.settled { "settled" } else { "abandoned" };
        format!("{}.{kind}-{hex}.sub", self.volume.as_str())
    }
}

#[cfg(test)]
mod tests;
