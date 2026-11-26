// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Name and symlink-target validation. Names are exact bytes —
//! no normalization, non-UTF-8 accepted (the macOS
//! materialization consequence is documented in the format doc).

/// Max name length in bytes.
pub const NAME_MAX: usize = 255;
/// Max symlink target length in bytes (Linux `PATH_MAX`).
pub const SYMLINK_TARGET_MAX: usize = 4096;

/// A validated directory-entry name. Ordering is raw memcmp of the
/// bytes (derived `Ord` on `Vec<u8>` IS memcmp — pinned by test).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong {
        len: usize,
    },
    Nul,
    Slash,
    Dot,
    DotDot,
    /// Byte prefix `.gran` is reserved — note this rejects
    /// `.granite.txt` too; prefix semantics are deliberate.
    GranPrefix,
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty name"),
            Self::TooLong { len } => write!(f, "name is {len} bytes (max {NAME_MAX})"),
            Self::Nul => write!(f, "name contains NUL"),
            Self::Slash => write!(f, "name contains '/'"),
            Self::Dot => write!(f, "name is '.'"),
            Self::DotDot => write!(f, "name is '..'"),
            Self::GranPrefix => write!(f, "name starts with reserved prefix '.gran'"),
        }
    }
}

impl std::error::Error for NameError {}

impl Name {
    /// Validate `bytes` as a directory-entry name.
    ///
    /// # Errors
    /// The [`NameError`] variant naming the violated rule: empty, over
    /// 255 bytes, NUL, `/`, exactly `.` or `..`, or the reserved
    /// `.gran` byte prefix.
    pub fn new(bytes: Vec<u8>) -> Result<Self, NameError> {
        if bytes.is_empty() {
            return Err(NameError::Empty);
        }
        if bytes.len() > NAME_MAX {
            return Err(NameError::TooLong { len: bytes.len() });
        }
        if bytes.contains(&0) {
            return Err(NameError::Nul);
        }
        if bytes.contains(&b'/') {
            return Err(NameError::Slash);
        }
        if bytes == b"." {
            return Err(NameError::Dot);
        }
        if bytes == b".." {
            return Err(NameError::DotDot);
        }
        if bytes.starts_with(b".gran") {
            return Err(NameError::GranPrefix);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length as the u8 the wire encoding carries (invariant 1..=255).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "invariant: len <= 255 enforced at construction"
    )]
    pub fn wire_len(&self) -> u8 {
        self.0.len() as u8
    }
}

/// A validated symlink target: exact bytes, 1..=4096, no NUL. Targets
/// may dangle or contain `..` — resolution is the traversal budget's
/// problem; non-UTF-8 is fine (empirically: symlink(2) targets
/// are opaque bytes even on APFS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkTarget(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkTargetError {
    Empty,
    TooLong { len: usize },
    Nul,
}

impl std::fmt::Display for SymlinkTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty symlink target"),
            Self::TooLong { len } => {
                write!(
                    f,
                    "symlink target is {len} bytes (max {SYMLINK_TARGET_MAX})"
                )
            }
            Self::Nul => write!(f, "symlink target contains NUL"),
        }
    }
}

impl std::error::Error for SymlinkTargetError {}

impl SymlinkTarget {
    /// Validate `bytes` as a symlink target.
    ///
    /// # Errors
    /// The [`SymlinkTargetError`] variant naming the violated rule:
    /// empty, over 4096 bytes, or NUL.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SymlinkTargetError> {
        if bytes.is_empty() {
            return Err(SymlinkTargetError::Empty);
        }
        if bytes.len() > SYMLINK_TARGET_MAX {
            return Err(SymlinkTargetError::TooLong { len: bytes.len() });
        }
        if bytes.contains(&0) {
            return Err(SymlinkTargetError::Nul);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length as the u16 the wire encoding carries (1..=4096).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "invariant: len <= 4096 enforced at construction"
    )]
    pub fn wire_len(&self) -> u16 {
        self.0.len() as u16
    }
}

#[cfg(test)]
mod tests;
