// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Held descriptor walk and source separation for private archives.

use super::{PrivateArchiveError, PrivateArchiveRefusal as Refusal, identity, refused};
use crate::{custody::refuse_granting_directory_acl_on_fd, fsguard::open_directory};
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::AsFd as _,
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    },
    path::{Path, PathBuf},
};

const PATH_BYTES_MAX: usize = 4_096;
const PATH_COMPONENTS_MAX: usize = 256;
const TEMP_PREFIX: &[u8] = b".SUPPORT-BUNDLE-";

/// A mounted namespace that output custody excludes by identity and device.
#[derive(Debug, Clone, Copy)]
pub struct MountedNamespace<'a> {
    path: &'a Path,
    identity: (u64, u64),
    device: Option<u64>,
}

impl<'a> MountedNamespace<'a> {
    /// Describe a mountpoint from declared mount state without opening it.
    ///
    /// `device` is present while the FUSE device is known to remain mounted,
    /// and absent for a known offline mountpoint.
    #[must_use]
    pub const fn new(path: &'a Path, identity: (u64, u64), device: Option<u64>) -> Self {
        Self {
            path,
            identity,
            device,
        }
    }
}

/// Source roots and optional mounted namespace excluded from archive custody.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveSources<'a> {
    roots: &'a [&'a Path],
    expected_identities: Option<&'a [(u64, u64)]>,
    mounted: Option<MountedNamespace<'a>>,
}

impl<'a> ArchiveSources<'a> {
    /// Build the complete source-separation declaration for one publication.
    #[must_use]
    pub const fn new(roots: &'a [&'a Path], mounted: Option<MountedNamespace<'a>>) -> Self {
        Self {
            roots,
            expected_identities: None,
            mounted,
        }
    }

    /// Build a source declaration bound to identities supplied by an authenticated peer.
    #[must_use]
    pub const fn with_expected_identities(
        roots: &'a [&'a Path],
        expected_identities: &'a [(u64, u64)],
        mounted: Option<MountedNamespace<'a>>,
    ) -> Self {
        Self {
            roots,
            expected_identities: Some(expected_identities),
            mounted,
        }
    }
}

/// A held, verified output parent. Only this module can construct one.
#[derive(Debug)]
pub struct PrivateArchiveParent {
    pub(super) output: PathBuf,
    pub(super) path: PathBuf,
    pub(super) held: Vec<File>,
    identity: (u64, u64),
    pub(super) invoking_uid: u32,
}

impl PrivateArchiveParent {
    /// Return the final output pathname validated by the walk.
    #[must_use]
    pub fn output(&self) -> &Path {
        &self.output
    }

    /// Return the invoking uid whose custody was proved.
    #[must_use]
    pub const fn invoking_uid(&self) -> u32 {
        self.invoking_uid
    }

    pub(super) fn descriptor(&self) -> Result<&File, PrivateArchiveError> {
        self.held
            .last()
            .ok_or_else(|| refused(Refusal::OutputPathUnavailable))
    }

    /// Reopen the descriptor-relative path and confirm it still reaches this parent.
    #[must_use]
    pub fn rebound(&self) -> bool {
        let Ok(names) = directory_components(&self.path) else {
            return false;
        };
        let Ok(reopened) = open_walk(&names) else {
            return false;
        };
        let Some(last) = reopened.last() else {
            return false;
        };
        match (
            self.descriptor().and_then(|file| {
                file.metadata()
                    .map_err(|_| refused(Refusal::OutputPathUnavailable))
            }),
            last.metadata(),
        ) {
            (Ok(held), Ok(reopened_metadata)) => {
                identity(&held) == self.identity && identity(&reopened_metadata) == self.identity
            }
            _ => false,
        }
    }
}

fn raw_components(path: &Path, root_allowed: bool) -> Result<Vec<Vec<u8>>, ()> {
    let mut spelling = path.as_os_str().as_bytes();
    if spelling.len() > PATH_BYTES_MAX
        || spelling.first() != Some(&b'/')
        || spelling.contains(&0)
        || (!root_allowed && spelling.last() == Some(&b'/'))
    {
        return Err(());
    }
    if root_allowed {
        while spelling.len() > 1 && spelling.last() == Some(&b'/') {
            spelling = spelling.get(..spelling.len() - 1).ok_or(())?;
        }
        if spelling.iter().all(|byte| *byte == b'/') {
            return Ok(Vec::new());
        }
    }
    let names = spelling
        .get(1..)
        .ok_or(())?
        .split(|byte| *byte == b'/')
        .filter(|name| !root_allowed || !name.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if names.len() > PATH_COMPONENTS_MAX
        || names
            .iter()
            .any(|name| name.is_empty() || name.as_slice() == b"." || name.as_slice() == b"..")
    {
        return Err(());
    }
    Ok(names)
}

fn output_components(output: &Path) -> Result<(PathBuf, Vec<Vec<u8>>), PrivateArchiveError> {
    let mut names =
        raw_components(output, false).map_err(|()| refused(Refusal::InvalidOutputPath))?;
    let basename = names
        .pop()
        .ok_or_else(|| refused(Refusal::InvalidOutputPath))?;
    if basename
        .get(..TEMP_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TEMP_PREFIX))
    {
        return Err(refused(Refusal::OutputNameIsInTemporaryNamespace));
    }
    let mut parent = PathBuf::from("/");
    for name in &names {
        parent.push(std::ffi::OsStr::from_bytes(name));
    }
    Ok((parent, names))
}

fn directory_components(path: &Path) -> Result<Vec<Vec<u8>>, ()> {
    raw_components(path, true)
}

fn io_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn open_walk(names: &[Vec<u8>]) -> io::Result<Vec<File>> {
    let mut held = vec![open_directory(Path::new("/"))?];
    for name in names {
        let component = CString::new(name.as_slice())
            .map_err(|_| io::Error::other("path component refused"))?;
        let parent = held
            .last()
            .ok_or_else(|| io::Error::other("directory walk lost root"))?;
        let fd = openat(
            parent,
            component.as_c_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)?;
        held.push(File::from(fd));
    }
    Ok(held)
}

fn component_refusal(
    metadata: &std::fs::Metadata,
    proved: &[ProvedSource<'_>],
    mounted: Option<&MountedNamespace<'_>>,
) -> Option<PrivateArchiveError> {
    let component_identity = identity(metadata);
    if proved
        .iter()
        .any(|source| source.identity == component_identity)
    {
        return Some(refused(Refusal::OutputInsideSourceTree));
    }
    if mounted.is_some_and(|mount| {
        mount.identity == component_identity || mount.device == Some(metadata.dev())
    }) {
        return Some(refused(Refusal::OutputInsideMountedNamespace));
    }
    None
}

fn output_open_error(error: &io::Error) -> PrivateArchiveError {
    if error.raw_os_error() == Some(libc::ELOOP) || error.raw_os_error() == Some(libc::ENOTDIR) {
        refused(Refusal::OutputPathContainsSymlinkOrNonDirectory)
    } else {
        refused(Refusal::OutputPathUnavailable)
    }
}

fn open_output_walk(
    names: &[Vec<u8>],
    proved: &[ProvedSource<'_>],
    mounted: Option<&MountedNamespace<'_>>,
) -> Result<Vec<File>, PrivateArchiveError> {
    let root = open_directory(Path::new("/")).map_err(|error| output_open_error(&error))?;
    let root_metadata = root
        .metadata()
        .map_err(|_| refused(Refusal::OutputPathUnavailable))?;
    if let Some(error) = component_refusal(&root_metadata, proved, mounted) {
        return Err(error);
    }
    let mut held = vec![root];
    for name in names {
        let component =
            CString::new(name.as_slice()).map_err(|_| refused(Refusal::OutputPathUnavailable))?;
        let parent = held
            .last()
            .ok_or_else(|| refused(Refusal::OutputPathUnavailable))?;
        #[cfg(target_os = "linux")]
        let flags = OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let fd = openat(parent, component.as_c_str(), flags, Mode::empty())
            .map_err(io_error)
            .map_err(|error| output_open_error(&error))?;
        let file = File::from(fd);
        let metadata = file
            .metadata()
            .map_err(|_| refused(Refusal::OutputPathUnavailable))?;
        if let Some(error) = component_refusal(&metadata, proved, mounted) {
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        let file = if names.last().is_some_and(|last| std::ptr::eq(name, last)) {
            let dot = CString::new(".").map_err(|_| refused(Refusal::OutputPathUnavailable))?;
            let fd = openat(
                &file,
                dot.as_c_str(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(io_error)
            .map_err(|error| output_open_error(&error))?;
            let directory = File::from(fd);
            let directory_metadata = directory
                .metadata()
                .map_err(|_| refused(Refusal::OutputPathUnavailable))?;
            if identity(&directory_metadata) != identity(&metadata) {
                return Err(refused(Refusal::OutputPathUnavailable));
            }
            directory
        } else {
            file
        };
        held.push(file);
    }
    Ok(held)
}

struct ProvedSource<'a> {
    path: &'a Path,
    file: File,
    identity: (u64, u64),
}

fn prove_source(path: &Path) -> Result<ProvedSource<'_>, PrivateArchiveError> {
    let names =
        directory_components(path).map_err(|()| refused(Refusal::SourceSeparationUnavailable))?;
    let file = open_walk(&names)
        .map_err(|_| refused(Refusal::SourceSeparationUnavailable))?
        .into_iter()
        .last()
        .ok_or_else(|| refused(Refusal::SourceSeparationUnavailable))?;
    let metadata = file
        .metadata()
        .map_err(|_| refused(Refusal::SourceSeparationUnavailable))?;
    Ok(ProvedSource {
        path,
        identity: identity(&metadata),
        file,
    })
}

/// Prove a declared mountpoint without following any pathname component.
///
/// Returns the held directory's identity and its held parent's device.
///
/// # Errors
///
/// Returns the source-separation refusal when the path cannot be proved as a
/// directory through the descriptor walk.
pub fn prove_mountpoint(path: &Path) -> Result<((u64, u64), u64), PrivateArchiveError> {
    let names =
        directory_components(path).map_err(|()| refused(Refusal::SourceSeparationUnavailable))?;
    let held = open_walk(&names).map_err(|_| refused(Refusal::SourceSeparationUnavailable))?;
    let (directory, ancestors) = held
        .split_last()
        .ok_or_else(|| refused(Refusal::SourceSeparationUnavailable))?;
    let parent = ancestors
        .last()
        .ok_or_else(|| refused(Refusal::SourceSeparationUnavailable))?;
    let metadata = directory
        .metadata()
        .map_err(|_| refused(Refusal::SourceSeparationUnavailable))?;
    let parent_metadata = parent
        .metadata()
        .map_err(|_| refused(Refusal::SourceSeparationUnavailable))?;
    Ok((identity(&metadata), parent_metadata.dev()))
}

fn source_rebound(source: &ProvedSource<'_>) -> bool {
    let Ok(names) = directory_components(source.path) else {
        return false;
    };
    let Ok(reopened) = open_walk(&names) else {
        return false;
    };
    let Some(last) = reopened.last() else {
        return false;
    };
    match (source.file.metadata(), last.metadata()) {
        (Ok(held), Ok(reopened_metadata)) => {
            identity(&held) == source.identity && identity(&reopened_metadata) == source.identity
        }
        _ => false,
    }
}

fn mounted_path_prefix(path: &Path, mount: &Path) -> bool {
    let mut path_components = path.components();
    mount.components().all(|mount_component| {
        path_components.next().is_some_and(|path_component| {
            path_component
                .as_os_str()
                .as_bytes()
                .eq_ignore_ascii_case(mount_component.as_os_str().as_bytes())
        })
    })
}

/// Prove output custody and source separation without creating an archive temporary.
///
/// Mounted-path components are compared without ASCII case before any filesystem access.
/// Non-ASCII case aliases on a case-folding filesystem can still reach the interruptible
/// descriptor walk and block behind an unresponsive mounted filesystem.
///
/// # Errors
///
/// Returns only fixed policy refusals; no path or operating-system error is disclosed.
pub fn prepare_private_archive_parent(
    output: &Path,
    sources: ArchiveSources<'_>,
    invoking_uid: u32,
) -> Result<PrivateArchiveParent, PrivateArchiveError> {
    let (parent_path, names) = output_components(output)?;
    if sources
        .mounted
        .is_some_and(|mount| directory_components(mount.path).is_err())
    {
        return Err(refused(Refusal::SourceSeparationUnavailable));
    }
    if sources
        .mounted
        .is_some_and(|mount| mounted_path_prefix(output, mount.path))
    {
        return Err(refused(Refusal::OutputInsideMountedNamespace));
    }
    if sources
        .expected_identities
        .is_some_and(|identities| identities.len() != sources.roots.len())
    {
        return Err(refused(Refusal::SourceSeparationUnavailable));
    }
    let mut proved = Vec::with_capacity(sources.roots.len());
    for (index, root) in sources.roots.iter().enumerate() {
        let source = prove_source(root)?;
        if sources
            .expected_identities
            .is_some_and(|identities| identities.get(index) != Some(&source.identity))
        {
            return Err(refused(Refusal::SourceSeparationUnavailable));
        }
        proved.push(source);
    }
    let mounted = sources.mounted;

    let held = open_output_walk(&names, &proved, mounted.as_ref())?;
    let metadata = held
        .iter()
        .map(File::metadata)
        .collect::<io::Result<Vec<_>>>()
        .map_err(|_| refused(Refusal::OutputPathUnavailable))?;
    let (parent, ancestors) = metadata
        .split_last()
        .ok_or_else(|| refused(Refusal::OutputPathUnavailable))?;
    let mut shown = PathBuf::from("/");
    for (index, (ancestor_file, ancestor)) in held.iter().zip(ancestors).enumerate() {
        if !ancestor.is_dir()
            || (ancestor.uid() != 0 && ancestor.uid() != invoking_uid)
            || (ancestor.mode() & 0o022 != 0 && ancestor.mode() & 0o1000 == 0)
        {
            return Err(refused(Refusal::OutputPathAncestorIsNotProtected));
        }
        refuse_granting_directory_acl_on_fd(
            ancestor_file.as_fd(),
            &shown,
            "support bundle output ancestor",
        )
        .map_err(|_| refused(Refusal::OutputPathAncestorIsNotProtected))?;
        if let Some(name) = names.get(index) {
            shown.push(std::ffi::OsStr::from_bytes(name));
        }
    }
    if !parent.is_dir() || parent.uid() != invoking_uid || parent.mode() & 0o7777 != 0o700 {
        return Err(refused(Refusal::OutputParentMustBeInvokingUidAnd0700));
    }
    let parent_file = held
        .last()
        .ok_or_else(|| refused(Refusal::OutputPathUnavailable))?;
    refuse_granting_directory_acl_on_fd(
        parent_file.as_fd(),
        &parent_path,
        "support bundle output parent",
    )
    .map_err(|_| refused(Refusal::OutputParentGrantsAccessThroughAcl))?;

    if proved.iter().any(|source| !source_rebound(source)) {
        return Err(refused(Refusal::SourceSeparationUnavailable));
    }
    Ok(PrivateArchiveParent {
        output: output.to_path_buf(),
        path: parent_path,
        identity: identity(parent),
        held,
        invoking_uid,
    })
}

#[cfg(test)]
mod tests;
