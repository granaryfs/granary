// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical local support-trigger messages.

use crate::{
    encoding::{Cursor, DecodeError},
    mount_control::MountKey,
};

/// Wire magic, distinct from mount control.
pub const MAGIC: [u8; 8] = *b"GRNSUPRT";
/// Only supported wire version.
pub const VERSION: u8 = 1;
/// Exact fixed request size.
pub const REQUEST_LEN: usize = 10;
/// Largest source-layout header body.
pub const HEADER_MAX: usize = 12_401;
/// Largest canonical bundle body.
pub const BUNDLE_MAX: usize = 2_097_152;
const HEADER_MIN: u32 = 10;
const PATH_MAX: usize = 4096;

/// A source root's fixed role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RootRole {
    Cache,
    Overlay,
    Store,
}
impl RootRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Cache => 1,
            Self::Overlay => 2,
            Self::Store => 3,
        }
    }
    fn parse(tag: u8) -> Result<Self, Error> {
        match tag {
            1 => Ok(Self::Cache),
            2 => Ok(Self::Overlay),
            3 => Ok(Self::Store),
            _ => Err(Error::SourceRole),
        }
    }
}

/// One held source identity and its raw path spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRoot {
    pub role: RootRole,
    pub path: Vec<u8>,
    pub dev: u64,
    pub ino: u64,
}

/// Fixed mount identity block, including an explicit verified-absent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountState {
    Mounted {
        mountpoint: (u64, u64),
        key: MountKey,
    },
    Absent,
}

/// Private source separation metadata for one producing session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLayout {
    pub mount: MountState,
    pub roots: Vec<SourceRoot>,
}

/// First reply frame; unavailable ends the exchange without a bundle frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Layout(SourceLayout),
    Unavailable,
}

/// A strict, closed support-trigger format refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    RequestLength,
    Magic,
    Version,
    RequestKind,
    HeaderSize,
    BundleSize,
    SourceRole,
    Trailing,
    Truncated,
    SourceCount,
    MountIdentity,
    SourceOrder,
    SourceIdentity,
    HeaderStatus,
}
impl Error {
    /// Complete refusal catalogue; variants and messages are never inferred.
    pub const ALL: [Self; 14] = [
        Self::RequestLength,
        Self::Magic,
        Self::Version,
        Self::RequestKind,
        Self::HeaderSize,
        Self::BundleSize,
        Self::SourceRole,
        Self::Trailing,
        Self::Truncated,
        Self::SourceCount,
        Self::MountIdentity,
        Self::SourceOrder,
        Self::SourceIdentity,
        Self::HeaderStatus,
    ];
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RequestLength => "support request length",
            Self::Magic => "support trigger magic",
            Self::Version => "support trigger version",
            Self::RequestKind => "support request kind",
            Self::HeaderSize => "support header size bound",
            Self::BundleSize => "support bundle size bound",
            Self::SourceRole => "support source role",
            Self::Trailing => "trailing support trigger bytes",
            Self::Truncated => "truncated support trigger",
            Self::SourceCount => "support source count",
            Self::MountIdentity => "support mount identity",
            Self::SourceOrder => "support source order",
            Self::SourceIdentity => "support source identity",
            Self::HeaderStatus => "support header status",
        })
    }
}
impl std::error::Error for Error {}
impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Self {
        match error {
            DecodeError::TrailingBytes { .. } => Self::Trailing,
            _ => Self::Truncated,
        }
    }
}

/// The exact collection request.
#[must_use]
pub fn request() -> [u8; REQUEST_LEN] {
    [b'G', b'R', b'N', b'S', b'U', b'P', b'R', b'T', VERSION, 1]
}

/// Decode the exact collection request.
///
/// # Errors
/// Refuses every length, magic, version or kind other than the fixed request.
pub fn decode_request(bytes: &[u8]) -> Result<(), Error> {
    if bytes == request() {
        Ok(())
    } else if bytes.len() != REQUEST_LEN {
        Err(Error::RequestLength)
    } else if bytes.get(..8) != Some(MAGIC.as_slice()) {
        Err(Error::Magic)
    } else if bytes.get(8) != Some(&VERSION) {
        Err(Error::Version)
    } else {
        Err(Error::RequestKind)
    }
}

fn frame_length(prefix: [u8; 4], min: u32, max: usize, error: Error) -> Result<usize, Error> {
    let length = u32::from_be_bytes(prefix);
    if length < min || u64::from(length) > max as u64 {
        return Err(error);
    }
    usize::try_from(length).map_err(|_| error)
}

/// Validate a source-header prefix before allocating the body.
///
/// # Errors
/// Refuses lengths outside 10–12,401 bytes.
pub fn header_frame_length(prefix: [u8; 4]) -> Result<usize, Error> {
    frame_length(prefix, HEADER_MIN, HEADER_MAX, Error::HeaderSize)
}

/// Validate a bundle prefix before allocating the body.
///
/// # Errors
/// Refuses lengths above 2,097,152 bytes.
pub fn bundle_frame_length(prefix: [u8; 4]) -> Result<usize, Error> {
    frame_length(prefix, 0, BUNDLE_MAX, Error::BundleSize)
}

fn mount_fields(out: &mut Vec<u8>, mount: MountState) {
    let (tag, point, key) = match mount {
        MountState::Mounted { mountpoint, key } => (1, mountpoint, key),
        MountState::Absent => (
            2,
            (0, 0),
            MountKey {
                namespace_dev: 0,
                namespace_ino: 0,
                mount_id: 0,
                fuse_major: 0,
                fuse_minor: 0,
            },
        ),
    };
    out.push(tag);
    out.extend_from_slice(&point.0.to_be_bytes());
    out.extend_from_slice(&point.1.to_be_bytes());
    out.extend_from_slice(&key.namespace_dev.to_be_bytes());
    out.extend_from_slice(&key.namespace_ino.to_be_bytes());
    out.extend_from_slice(&key.mount_id.to_be_bytes());
    out.extend_from_slice(&key.fuse_major.to_be_bytes());
    out.extend_from_slice(&key.fuse_minor.to_be_bytes());
}

fn validate(layout: &SourceLayout) -> Result<usize, Error> {
    if layout.roots.len() > 3 {
        return Err(Error::SourceCount);
    }
    let valid_mount = match layout.mount {
        MountState::Mounted { mountpoint, key } => {
            mountpoint.0 != 0
                && mountpoint.1 != 0
                && key.namespace_dev != 0
                && key.namespace_ino != 0
                && key.mount_id != 0
                && (key.fuse_major, key.fuse_minor) != (0, 0)
                && mountpoint != (key.namespace_dev, key.namespace_ino)
        }
        MountState::Absent => true,
    };
    if !valid_mount {
        return Err(Error::MountIdentity);
    }
    let mut size = 56usize;
    let mut previous = None;
    for (index, root) in layout.roots.iter().enumerate() {
        if previous.is_some_and(|role| role >= root.role) {
            return Err(Error::SourceOrder);
        }
        if root.path.len() > PATH_MAX
            || !path_is_absolute_and_normalized(&root.path)
            || root.dev == 0
            || root.ino == 0
            || layout
                .roots
                .iter()
                .take(index)
                .any(|seen| (seen.dev, seen.ino) == (root.dev, root.ino))
        {
            return Err(Error::SourceIdentity);
        }
        size = size
            .checked_add(19)
            .and_then(|n| n.checked_add(root.path.len()))
            .ok_or(Error::HeaderSize)?;
        previous = Some(root.role);
    }
    if size > HEADER_MAX {
        return Err(Error::HeaderSize);
    }
    Ok(size)
}

fn path_is_absolute_and_normalized(path: &[u8]) -> bool {
    if path.last() == Some(&b'/') || path.iter().any(u8::is_ascii_control) {
        return false;
    }
    let Some(relative) = path.strip_prefix(b"/") else {
        return false;
    };
    relative
        .split(|byte| *byte == b'/')
        .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

/// Encode one canonical source-header body.
///
/// # Errors
/// Refuses invalid mount identities, source ordering, paths, identities or caps.
pub fn encode_header(header: &Header) -> Result<Vec<u8>, Error> {
    let layout = match header {
        Header::Unavailable => {
            let mut out = MAGIC.to_vec();
            out.extend_from_slice(&[VERSION, 2]);
            return Ok(out);
        }
        Header::Layout(layout) => layout,
    };
    let mut out = Vec::with_capacity(validate(layout)?);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&[VERSION, 1]);
    out.push(u8::try_from(layout.roots.len()).map_err(|_| Error::SourceCount)?);
    mount_fields(&mut out, layout.mount);
    for root in &layout.roots {
        out.push(root.role.tag());
        out.extend_from_slice(
            &u16::try_from(root.path.len())
                .map_err(|_| Error::SourceIdentity)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&root.path);
        out.extend_from_slice(&root.dev.to_be_bytes());
        out.extend_from_slice(&root.ino.to_be_bytes());
    }
    Ok(out)
}

fn decode_mount(c: &mut Cursor<'_>) -> Result<MountState, Error> {
    let state = c.u8()?;
    let point = (c.u64()?, c.u64()?);
    let key = MountKey {
        namespace_dev: c.u64()?,
        namespace_ino: c.u64()?,
        mount_id: c.u32()?,
        fuse_major: c.u32()?,
        fuse_minor: c.u32()?,
    };
    match state {
        1 => Ok(MountState::Mounted {
            mountpoint: point,
            key,
        }),
        2 if point == (0, 0)
            && key
                == MountKey {
                    namespace_dev: 0,
                    namespace_ino: 0,
                    mount_id: 0,
                    fuse_major: 0,
                    fuse_minor: 0,
                } =>
        {
            Ok(MountState::Absent)
        }
        _ => Err(Error::MountIdentity),
    }
}

/// Decode exactly one bounded canonical source-header body.
///
/// # Errors
/// Refuses malformed envelopes, fields, identities, bounds and trailing bytes.
pub fn decode_header(bytes: &[u8]) -> Result<Header, Error> {
    if bytes.len() > HEADER_MAX {
        return Err(Error::HeaderSize);
    }
    let mut c = Cursor::new(bytes);
    if c.take(8)? != MAGIC {
        return Err(Error::Magic);
    }
    if c.u8()? != VERSION {
        return Err(Error::Version);
    }
    let status = c.u8()?;
    if status == 2 {
        c.finish()?;
        return Ok(Header::Unavailable);
    }
    if status != 1 {
        return Err(Error::HeaderStatus);
    }
    let count = usize::from(c.u8()?);
    if count > 3 {
        return Err(Error::SourceCount);
    }
    let mount = decode_mount(&mut c)?;
    let mut roots = Vec::with_capacity(count);
    for _ in 0..count {
        let role = RootRole::parse(c.u8()?)?;
        let length = usize::from(c.u16()?);
        if !(1..=PATH_MAX).contains(&length) {
            return Err(Error::SourceIdentity);
        }
        let path = c.take(length)?;
        let root = SourceRoot {
            role,
            path: path.to_vec(),
            dev: c.u64()?,
            ino: c.u64()?,
        };
        roots.push(root);
    }
    c.finish()?;
    let layout = SourceLayout { mount, roots };
    validate(&layout)?;
    Ok(Header::Layout(layout))
}
