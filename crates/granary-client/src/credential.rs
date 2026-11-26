// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client's TLS credential, loaded from its two files: the certificate
//! file and the key file.
//!
//! A credential is a pair or nothing. [`ClientCredential`] is built only
//! from both files, and an [`crate::HttpStore`] takes an
//! `Option<ClientCredential>`: `None` is a client that configured neither
//! file and connects anonymously. A half-configured credential cannot be
//! expressed as a value; [`ClientCredential::from_configured`] is where a
//! configuration naming one file and not the other is refused.
//!
//! The key file is opened under the private-key custody check (the
//! `custody` module's `open_private_key`), and read through the descriptor
//! that check judged. The certificate file is public, and is opened with the
//! guarded read (no symlink followed, no FIFO waited on, a regular file
//! only). Each is read to at most [`CREDENTIAL_FILE_MAX`] bytes; the content
//! is then held to the strict PEM profile, and the key to the end-entity
//! certificate, by [`ClientCertifiedKey::from_pem`].

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use granary_net::credential::{
    CREDENTIAL_FILE_MAX, ClientCertifiedKey, CredentialError as ContentError,
};

use crate::custody::open_private_key;
use crate::fsguard::open_regular_read;
use crate::harvest::FileIdentity;

/// A TLS client certificate chain and its key, loaded from their two files
/// and checked.
#[derive(Clone)]
pub struct ClientCredential {
    certified: ClientCertifiedKey,
    key_identity: FileIdentity,
}

impl std::fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<credential>")
    }
}

/// Which of the credential's two files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFile {
    /// The certificate file.
    Certificate,
    /// The key file.
    Key,
}

impl CredentialFile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "certificate file",
            Self::Key => "key file",
        }
    }
}

/// Why a client credential was refused at configuration.
pub enum CredentialError {
    /// One of the two files is configured and the other is not.
    Incomplete {
        /// The file that is not configured.
        missing: CredentialFile,
    },
    /// A file could not be opened or read, or the key file is not in the
    /// custody a private key requires.
    File {
        /// Which file.
        file: CredentialFile,
        /// Its path.
        path: PathBuf,
        /// The refusal, naming the path.
        reason: String,
    },
    /// The files' content was refused.
    Content {
        /// The certificate file's path.
        certificate: PathBuf,
        /// The key file's path.
        key: PathBuf,
        /// What was refused.
        error: Box<ContentError>,
    },
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete { missing } => write!(
                f,
                "client credential: the {} is not configured; configure both files or neither",
                missing.as_str()
            ),
            Self::File { file, reason, .. } => {
                write!(f, "client credential {}: {reason}", file.as_str())
            }
            Self::Content {
                certificate,
                key,
                error,
            } => match &**error {
                ContentError::Certificate(_) => write!(
                    f,
                    "client credential certificate file {}: content is invalid",
                    certificate.display()
                ),
                ContentError::Key(_) => write!(
                    f,
                    "client credential key file {}: content is invalid",
                    key.display()
                ),
                ContentError::Mismatch(_) => {
                    f.write_str("client credential key does not match the certificate")
                }
            },
        }
    }
}

impl std::fmt::Debug for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<credential-error>")
    }
}

impl std::error::Error for CredentialError {}

impl ClientCredential {
    /// The credential in the certificate file at `certificate` and the key
    /// file at `key`.
    ///
    /// `euid` is the process's effective uid, as the caller's credential
    /// snapshot read it: the key file must be owned by it.
    ///
    /// # Errors
    ///
    /// [`CredentialError::File`] when a file is missing, unreadable, not a
    /// regular file, larger than [`CREDENTIAL_FILE_MAX`], or (the key file)
    /// not in private-key custody; [`CredentialError::Content`] when the
    /// content fails the PEM profile or the key is not the end entity's.
    pub fn load(certificate: &Path, key: &Path, euid: u32) -> Result<Self, CredentialError> {
        let file_error = |file, reason| CredentialError::File {
            file,
            path: match file {
                CredentialFile::Certificate => certificate.to_path_buf(),
                CredentialFile::Key => key.to_path_buf(),
            },
            reason,
        };
        let certificate_file = open_regular_read(certificate).map_err(|e| {
            file_error(
                CredentialFile::Certificate,
                format!("{}: {e}", certificate.display()),
            )
        })?;
        let certificate_pem = read_bounded(certificate_file, certificate)
            .map_err(|reason| file_error(CredentialFile::Certificate, reason))?;
        let key_file = open_private_key(key, euid, "key")
            .map_err(|reason| file_error(CredentialFile::Key, reason))?;
        let key_identity = FileIdentity::from_file(&key_file).map_err(|_| {
            file_error(
                CredentialFile::Key,
                "key file identity could not be captured".to_owned(),
            )
        })?;
        let key_pem = read_bounded(key_file, key)
            .map_err(|reason| file_error(CredentialFile::Key, reason))?;
        let certified =
            ClientCertifiedKey::from_pem(&certificate_pem, &key_pem).map_err(|error| {
                CredentialError::Content {
                    certificate: certificate.to_path_buf(),
                    key: key.to_path_buf(),
                    error: Box::new(error),
                }
            })?;
        Ok(Self {
            certified,
            key_identity,
        })
    }

    /// The credential a configuration names: `None` when it names neither
    /// file, the loaded pair when it names both.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Incomplete`] when it names exactly one file, and
    /// whatever [`Self::load`] refuses when it names both. A configured file
    /// that fails to load never yields `None`.
    pub fn from_configured(
        certificate: Option<&Path>,
        key: Option<&Path>,
        euid: u32,
    ) -> Result<Option<Self>, CredentialError> {
        match (certificate, key) {
            (None, None) => Ok(None),
            (Some(_), None) => Err(CredentialError::Incomplete {
                missing: CredentialFile::Key,
            }),
            (None, Some(_)) => Err(CredentialError::Incomplete {
                missing: CredentialFile::Certificate,
            }),
            (Some(certificate), Some(key)) => Self::load(certificate, key, euid).map(Some),
        }
    }

    /// The private key identity captured from the custody-checked descriptor.
    #[must_use]
    pub const fn key_file_identity(&self) -> FileIdentity {
        self.key_identity
    }

    /// The checked chain and key, for the TLS configuration.
    pub(crate) fn into_certified_key(self) -> ClientCertifiedKey {
        self.certified
    }
}

/// Read `file` to at most [`CREDENTIAL_FILE_MAX`] bytes, refusing one that
/// holds more.
fn read_bounded(file: File, path: &Path) -> Result<Vec<u8>, String> {
    let limit = u64::try_from(CREDENTIAL_FILE_MAX)
        .map_err(|_| "the credential file limit cannot be represented".to_owned())?
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() > CREDENTIAL_FILE_MAX {
        return Err(format!(
            "{}: larger than {CREDENTIAL_FILE_MAX} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
