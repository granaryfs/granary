// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Independent publisher trust and exact retained-publication scope construction.
//! Transport pins and TLS credentials do not supply publisher signing keys.

use granary_core::retained_submission::Scope;
use granary_net::config::parse_signing_key;
use granary_net::pin::{PinnedServerVerifier, SpkiPin};
use granary_store::crypto::TrustedKeys;

use crate::http_store::{HttpStoreError, check_base};

/// A value-free configuration refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationError(pub &'static str);

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ConfigurationError {}

/// The operator's declaration of principal continuity, never a wire identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialContext(String);

impl CredentialContext {
    /// Check exact ASCII bytes, without trimming or normalization.
    ///
    /// # Errors
    /// A context outside `[A-Za-z0-9._-]{1,255}`.
    pub fn new(value: &str) -> Result<Self, ConfigurationError> {
        if !(1..=255).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ConfigurationError(
                "--credential-context must contain 1–255 ASCII letters, digits, '.', '_' or '-'",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Exact configured context bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical publisher public keys supplied explicitly by the operator.
/// An empty list selects the current signer's singleton trust.
#[derive(Debug, Clone, Default)]
pub struct PublisherTrust {
    explicit: Vec<[u8; 32]>,
}
impl PublisherTrust {
    /// Number of explicitly configured keys, without copying their bytes.
    #[must_use]
    pub fn configured_count(&self) -> usize {
        self.explicit.len()
    }

    /// Accumulate one occurrence, accepting only canonical public-key syntax.
    ///
    /// # Errors
    /// Invalid syntax or the all-zero key. No supplied value is rendered.
    pub fn push(&mut self, value: &str) -> Result<(), ConfigurationError> {
        let public = parse_signing_key(value).map_err(|_| {
            ConfigurationError(
                "--publisher-key must be ed25519: followed by 64 lowercase hex digits",
            )
        })?;
        if public == [0; 32] {
            return Err(ConfigurationError(
                "--publisher-key must not be the all-zero key",
            ));
        }
        self.explicit.push(public);
        Ok(())
    }

    /// Whether any publisher-key occurrence was supplied.
    #[must_use]
    pub fn is_explicit(&self) -> bool {
        !self.explicit.is_empty()
    }

    /// Construct trust from publisher keys only, requiring the current signer in an explicit set.
    ///
    /// # Errors
    /// An explicit set missing the signer, or an invalid trusted-key set.
    pub fn build(&self, signer_public: [u8; 32]) -> Result<TrustedKeys, ConfigurationError> {
        if self.is_explicit() && !self.explicit.contains(&signer_public) {
            return Err(ConfigurationError(
                "publisher trust must include the current signing key",
            ));
        }
        let publics = if self.is_explicit() {
            self.explicit.clone()
        } else {
            vec![signer_public]
        };
        TrustedKeys::new(publics)
            .map_err(|_| ConfigurationError("publisher trust contains an invalid key"))
    }

    /// Construct a read-only verifier using only the explicitly configured keys.
    ///
    /// # Errors
    /// The explicit key set is empty or invalid.
    pub fn read_keys(&self) -> Result<TrustedKeys, ConfigurationError> {
        TrustedKeys::new(self.explicit.iter().copied())
            .map_err(|_| ConfigurationError("at least one valid --publisher-key is required"))
    }

    /// Refuse explicit trust on any selected direct server seam.
    ///
    /// # Errors
    /// Explicit publisher keys cannot be consumed by direct publication.
    pub fn require_authority(&self) -> Result<(), ConfigurationError> {
        if self.is_explicit() {
            return Err(ConfigurationError(
                "--publisher-key requires authority publication",
            ));
        }
        Ok(())
    }
}

/// Check transport pins before any deduplication; the verifier's input cap remains in force.
///
/// # Errors
/// Empty, all-zero or oversized pin lists.
pub fn validate_publication_pins(pins: &[SpkiPin]) -> Result<(), ConfigurationError> {
    if pins.is_empty() {
        return Err(ConfigurationError(
            "publication scope requires nonempty TLS pins",
        ));
    }
    PinnedServerVerifier::new(pins.to_vec(), granary_net::crypto_provider().into())
        .map_err(|_| ConfigurationError("tls pin set is invalid"))?;
    Ok(())
}

/// Construct a scope with exact endpoint/context bytes and sorted distinct transport pins.
/// The directory digest excludes pins; loading still compares full scope equality.
///
/// # Errors
/// Invalid endpoint, scope length or transport pins. Rejected endpoint bytes are never rendered.
pub fn publication_scope(
    endpoint: &str,
    pins: &[SpkiPin],
    context: &CredentialContext,
) -> Result<Scope, ConfigurationError> {
    check_base(endpoint).map_err(|error| match error {
        HttpStoreError::Userinfo => ConfigurationError("endpoint userinfo is not permitted"),
        _ => ConfigurationError("invalid endpoint URL"),
    })?;
    if !(1..=8192).contains(&endpoint.len()) {
        return Err(ConfigurationError(
            "authority base must contain 1–8192 bytes",
        ));
    }
    validate_publication_pins(pins)?;
    let mut pins = pins.to_vec();
    pins.sort_unstable();
    pins.dedup();
    let scope = Scope {
        authority_base: endpoint.as_bytes().to_vec(),
        pins,
        credential_context: context.as_str().as_bytes().to_vec(),
    };
    scope
        .digest()
        .map_err(|_| ConfigurationError("invalid publication scope"))?;
    Ok(scope)
}

/// Collect the signing seed and a loaded TLS key for protected harvest.
/// Identities remain valid after their loading descriptors close.
#[must_use]
pub fn protected_private_files(
    seed: crate::FileIdentity,
    credential: Option<&crate::ClientCredential>,
) -> Vec<crate::FileIdentity> {
    let mut files = vec![seed];
    if let Some(credential) = credential {
        files.push(credential.key_file_identity());
    }
    files
}

#[cfg(test)]
mod tests;
