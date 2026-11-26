// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The host's boot id: what the run marker's **running** state names, so
//! that a restart in the same boot refuses.
//!
//! On Linux it is the kernel's `/proc/sys/kernel/random/boot_id`, a random
//! UUID drawn once per boot, read with a bounded read and parsed by
//! [`parse_boot_id`]. An authority runs only on Linux (spec §6.2's
//! deployment), so on every other platform [`host_boot_id`] refuses.

use granary_core::runmarker::{BOOT_ID_LEN, BootId};

/// The canonical text's length: 32 hex digits and four hyphens.
const TEXT_LEN: usize = 36;

/// Where each hyphen of the canonical `8-4-4-4-12` text sits.
const HYPHENS: [usize; 4] = [8, 13, 18, 23];

/// Why the host's boot id is not available.
#[derive(Debug)]
pub enum BootIdError {
    /// This platform is not Linux: an authority runs only on Linux.
    NotLinux,
    /// The kernel's boot id could not be read.
    Unreadable(std::io::Error),
    /// The kernel's boot id is not its canonical text.
    Malformed(Malformed),
}

impl std::fmt::Display for BootIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLinux => write!(
                f,
                "a publication authority runs only on Linux: this platform has no boot id it reads"
            ),
            Self::Unreadable(e) => write!(f, "the host's boot id could not be read: {e}"),
            Self::Malformed(m) => write!(f, "the host's boot id is malformed: {m}"),
        }
    }
}

impl std::error::Error for BootIdError {}

/// How a boot id's text departs from the canonical form: 36 characters,
/// lowercase hex in groups of 8, 4, 4, 4 and 12 joined by hyphens, then
/// one newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The text is not 37 bytes long; `len` is its length, which a
    /// bounded read caps.
    Length { len: usize },
    /// The last byte is not a newline.
    NoNewline,
    /// The byte at `at` is not a hyphen where one belongs.
    Hyphen { at: usize },
    /// The byte at `at` is not a lowercase hex digit where one belongs.
    Digit { at: usize },
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length { len } => write!(
                f,
                "{len} bytes, not the {} of the canonical text and its newline",
                TEXT_LEN + 1
            ),
            Self::NoNewline => write!(f, "it does not end in a newline"),
            Self::Hyphen { at } => write!(f, "byte {at} is not a hyphen"),
            Self::Digit { at } => write!(f, "byte {at} is not a lowercase hex digit"),
        }
    }
}

/// The boot id in `text`, the kernel's file exactly as read: the
/// canonical text and one newline, nothing else.
///
/// # Errors
/// [`Malformed`], naming the first departure from the canonical form.
pub fn parse_boot_id(text: &[u8]) -> Result<BootId, Malformed> {
    if text.len() != TEXT_LEN + 1 {
        return Err(Malformed::Length { len: text.len() });
    }
    let Some((b'\n', body)) = text.split_last() else {
        return Err(Malformed::NoNewline);
    };
    let mut bytes = [0u8; BOOT_ID_LEN];
    // Nibbles in order, high first: the hyphens skipped, every other byte
    // a lowercase hex digit. The length check above makes them exactly
    // `2 * BOOT_ID_LEN`.
    let mut nibble = 0usize;
    for (at, &c) in body.iter().enumerate() {
        if HYPHENS.contains(&at) {
            if c != b'-' {
                return Err(Malformed::Hyphen { at });
            }
            continue;
        }
        let value = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return Err(Malformed::Digit { at }),
        };
        if let Some(byte) = bytes.get_mut(nibble / 2) {
            *byte = if nibble.is_multiple_of(2) {
                value << 4
            } else {
                *byte | value
            };
        }
        nibble += 1;
    }
    Ok(BootId::from_bytes(bytes))
}

/// The host's boot id.
///
/// # Errors
/// [`BootIdError::NotLinux`] on every platform but Linux; on Linux,
/// [`BootIdError::Unreadable`] or [`BootIdError::Malformed`].
pub fn host_boot_id() -> Result<BootId, BootIdError> {
    #[cfg(target_os = "linux")]
    {
        read_boot_id(std::path::Path::new("/proc/sys/kernel/random/boot_id"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(BootIdError::NotLinux)
    }
}

/// Read and parse the boot id at `path`, reading at most one byte more
/// than the canonical text and its newline, so a longer file is refused
/// by its length without being read whole.
#[cfg(target_os = "linux")]
fn read_boot_id(path: &std::path::Path) -> Result<BootId, BootIdError> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).map_err(BootIdError::Unreadable)?;
    let mut text = Vec::with_capacity(TEXT_LEN + 2);
    let bound = u64::try_from(TEXT_LEN + 2).unwrap_or(u64::MAX);
    file.take(bound)
        .read_to_end(&mut text)
        .map_err(BootIdError::Unreadable)?;
    parse_boot_id(&text).map_err(BootIdError::Malformed)
}

#[cfg(test)]
mod tests;
