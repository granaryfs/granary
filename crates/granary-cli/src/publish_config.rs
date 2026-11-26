// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Checked configuration for credential-aware publication callers.
//! The command consumes credential identity and publisher trust before harvest.

use std::ffi::OsStr;
use std::path::PathBuf;

use granary_client::publication_config::{CredentialContext, PublisherTrust};
use granary_client::{ClientCredential, CredentialError, CredentialFile, FileIdentity};
use granary_net::credential::CredentialError as ContentError;

pub(crate) const FLAGS: [&str; 4] = [
    "--client-cert",
    "--client-key",
    "--credential-context",
    "--publisher-key",
];

#[derive(Clone, Default)]
pub(crate) struct PublishConfiguration {
    pub(crate) certificate: Option<PathBuf>,
    pub(crate) key: Option<PathBuf>,
    pub(crate) context: Option<CredentialContext>,
    pub(crate) publishers: PublisherTrust,
}

impl std::fmt::Debug for PublishConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishConfiguration")
            .field("certificate_configured", &self.certificate.is_some())
            .field("key_configured", &self.key.is_some())
            .field("context_configured", &self.context.is_some())
            .field("publishers_explicit", &self.publishers.is_explicit())
            .finish()
    }
}

impl PublishConfiguration {
    pub(crate) fn option(&mut self, flag: &str, value: Option<&OsStr>) -> Result<(), String> {
        if !FLAGS.contains(&flag) {
            return Err("unknown publish option".to_owned());
        }
        let value = value
            .filter(|value| !value.as_encoded_bytes().starts_with(b"-"))
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag {
            "--client-cert" | "--client-key" => {
                if value.is_empty() {
                    return Err(format!("{flag} needs a nonempty file path"));
                }
                let path = Some(PathBuf::from(value));
                if flag == "--client-cert" {
                    self.certificate = path;
                } else {
                    self.key = path;
                }
            }
            "--credential-context" => {
                self.context = Some(
                    CredentialContext::new(value.to_str().unwrap_or_default())
                        .map_err(|e| e.to_string())?,
                );
            }
            "--publisher-key" => {
                self.publishers
                    .push(value.to_str().unwrap_or_default())
                    .map_err(|e| e.to_string())?;
            }
            _ => return Err("unknown publish option".to_owned()),
        }
        Ok(())
    }

    pub(crate) fn validate(&self, direct_s3: bool) -> Result<(), String> {
        if direct_s3 {
            for (flag, supplied) in [
                ("--client-cert", self.certificate.is_some()),
                ("--client-key", self.key.is_some()),
                ("--credential-context", self.context.is_some()),
                ("--publisher-key", self.publishers.is_explicit()),
            ] {
                if supplied {
                    return Err(format!("{flag} is available only on the server route"));
                }
            }
        }
        if self.certificate.is_some() != self.key.is_some() {
            return Err("--client-cert and --client-key must be supplied together".to_owned());
        }
        Ok(())
    }

    pub(crate) fn load(&self, euid: u32) -> Result<Option<ClientCredential>, CredentialRefusal> {
        ClientCredential::from_configured(self.certificate.as_deref(), self.key.as_deref(), euid)
            .map_err(|error| CredentialRefusal::from_error(&error))
    }

    pub(crate) fn protected_files(
        seed: FileIdentity,
        credential: Option<FileIdentity>,
    ) -> Vec<FileIdentity> {
        let mut files = vec![seed];
        if let Some(identity) = credential {
            files.push(identity);
        }
        files
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CredentialRefusal(&'static str);
impl CredentialRefusal {
    fn from_error(error: &CredentialError) -> Self {
        Self(match error {
            CredentialError::Incomplete { .. } => {
                "--client-cert and --client-key must be supplied together"
            }
            CredentialError::File {
                file: CredentialFile::Certificate,
                ..
            } => "client credential certificate file could not be loaded",
            CredentialError::File {
                file: CredentialFile::Key,
                ..
            } => "client credential key file could not be loaded or failed custody",
            CredentialError::Content { error, .. } => match &**error {
                ContentError::Certificate(_) => "client credential certificate content is invalid",
                ContentError::Key(_) => "client credential key content is invalid",
                ContentError::Mismatch(_) => "client credential key does not match the certificate",
            },
        })
    }
}
impl std::fmt::Display for CredentialRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CredentialRefusal {}

#[cfg(test)]
mod tests;
