// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Protected custody for support-bundle archive publication.

use std::os::unix::fs::MetadataExt as _;

mod publish;
mod walk;

pub use publish::publish_private_archive;
pub use walk::{
    ArchiveSources, MountedNamespace, PrivateArchiveParent, prepare_private_archive_parent,
    prove_mountpoint,
};

/// A fixed refusal from the private-archive policy's closed catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateArchiveRefusal {
    ArchivePublicationUnavailable,
    ArchiveTemporaryChanged,
    ArchiveTemporaryContentMismatch,
    ArchiveTemporaryIsNotSolePrivateRegular,
    ArchiveTemporaryMode,
    ArchiveWriteUnavailable,
    InvalidOutputPath,
    OutputAlreadyExists,
    OutputInsideMountedNamespace,
    OutputInsideSourceTree,
    OutputNameIsInTemporaryNamespace,
    OutputParentGrantsAccessThroughAcl,
    OutputParentMustBeInvokingUidAnd0700,
    OutputPathAncestorIsNotProtected,
    OutputPathContainsSymlinkOrNonDirectory,
    OutputPathUnavailable,
    SourceSeparationUnavailable,
    SupportSizeBound,
    TemporaryNameExhaustion,
    UnsafeArchiveTemporary,
}

impl PrivateArchiveRefusal {
    /// Every refusal in this closed catalogue.
    pub const ALL: &'static [Self] = &[
        Self::ArchivePublicationUnavailable,
        Self::ArchiveTemporaryChanged,
        Self::ArchiveTemporaryContentMismatch,
        Self::ArchiveTemporaryIsNotSolePrivateRegular,
        Self::ArchiveTemporaryMode,
        Self::ArchiveWriteUnavailable,
        Self::InvalidOutputPath,
        Self::OutputAlreadyExists,
        Self::OutputInsideMountedNamespace,
        Self::OutputInsideSourceTree,
        Self::OutputNameIsInTemporaryNamespace,
        Self::OutputParentGrantsAccessThroughAcl,
        Self::OutputParentMustBeInvokingUidAnd0700,
        Self::OutputPathAncestorIsNotProtected,
        Self::OutputPathContainsSymlinkOrNonDirectory,
        Self::OutputPathUnavailable,
        Self::SourceSeparationUnavailable,
        Self::SupportSizeBound,
        Self::TemporaryNameExhaustion,
        Self::UnsafeArchiveTemporary,
    ];

    /// Return the fixed operator-facing reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ArchivePublicationUnavailable => "archive publication unavailable",
            Self::ArchiveTemporaryChanged => "archive temporary changed",
            Self::ArchiveTemporaryContentMismatch => "archive temporary content mismatch",
            Self::ArchiveTemporaryIsNotSolePrivateRegular => {
                "archive temporary is not sole private regular"
            }
            Self::ArchiveTemporaryMode => "archive temporary mode",
            Self::ArchiveWriteUnavailable => "archive write unavailable",
            Self::InvalidOutputPath => "invalid output path",
            Self::OutputAlreadyExists => "output already exists",
            Self::OutputInsideMountedNamespace => "output inside mounted namespace",
            Self::OutputInsideSourceTree => "output inside source tree",
            Self::OutputNameIsInTemporaryNamespace => "output name is in temporary namespace",
            Self::OutputParentGrantsAccessThroughAcl => "output parent grants access through ACL",
            Self::OutputParentMustBeInvokingUidAnd0700 => {
                "output parent must be invoking uid and 0700"
            }
            Self::OutputPathAncestorIsNotProtected => "output path ancestor is not protected",
            Self::OutputPathContainsSymlinkOrNonDirectory => {
                "output path contains symlink or non-directory"
            }
            Self::OutputPathUnavailable => "output path unavailable",
            Self::SourceSeparationUnavailable => "source separation unavailable",
            Self::SupportSizeBound => "support size bound",
            Self::TemporaryNameExhaustion => "temporary name exhaustion",
            Self::UnsafeArchiveTemporary => "unsafe archive temporary",
        }
    }
}

/// Closed public classification of a private-archive failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateArchiveErrorClass {
    /// Publication did not land.
    Refused,
    /// Publication landed, but durability or cleanup is uncertain.
    PublicationUncertain,
}

/// A pre-publication private-archive refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateArchiveError {
    /// The archive was refused before publication.
    Refused(PrivateArchiveRefusal),
    /// The final link landed, but subsequent durability or cleanup failed.
    PublicationUncertain,
}

impl std::fmt::Display for PrivateArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => f.write_str(reason.reason()),
            Self::PublicationUncertain => f.write_str("publication uncertain"),
        }
    }
}

impl std::error::Error for PrivateArchiveError {}

impl PrivateArchiveError {
    /// Classify the failure without inspecting its display text.
    #[must_use]
    pub const fn class(self) -> PrivateArchiveErrorClass {
        match self {
            Self::Refused(_) => PrivateArchiveErrorClass::Refused,
            Self::PublicationUncertain => PrivateArchiveErrorClass::PublicationUncertain,
        }
    }
}

const fn refused(reason: PrivateArchiveRefusal) -> PrivateArchiveError {
    PrivateArchiveError::Refused(reason)
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

#[cfg(test)]
mod catalogue_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn private_archive_refusal_catalogue_is_closed_and_unique() {
        let reasons = PrivateArchiveRefusal::ALL
            .iter()
            .map(|reason| reason.reason())
            .collect::<BTreeSet<_>>();
        assert_eq!(reasons.len(), PrivateArchiveRefusal::ALL.len());
        assert_eq!(
            PrivateArchiveRefusal::ALL.len(),
            PrivateArchiveRefusal::UnsafeArchiveTemporary as usize + 1,
            "catalogue must contain every enum variant exactly once"
        );
        assert_eq!(
            PrivateArchiveError::Refused(PrivateArchiveRefusal::InvalidOutputPath).class(),
            PrivateArchiveErrorClass::Refused
        );
        assert_eq!(
            PrivateArchiveError::PublicationUncertain.class(),
            PrivateArchiveErrorClass::PublicationUncertain
        );
    }
}
