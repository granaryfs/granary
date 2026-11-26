// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 root signatures. aws-lc-rs is the one
//! crypto stack; the import paths below are the compile-verified
//! incantation — the `ed25519` module is private, everything lives in
//! `signature`, and the `KeyPair`/`AsBigEndian` traits must be in
//! scope.
//!
//! Signatures cover a root's SIGNED PREFIX — the full canonical object
//! bytes from the first envelope byte through the last byte before the
//! signature section (`granary_core::root::signed_prefix`); the
//! envelope's type tag is the domain separator. This module is
//! byte-generic: it signs and verifies prefixes, it does not parse
//! roots.
//!
//! Key material: the aws-lc-rs seed IS the RFC 8032 private key
//! (proven to test-vector conformance below), so committed test keys
//! are raw 32-byte seeds — portable to any Ed25519 implementation.
//! NO FIPS claim attaches to these signatures (the 1.18.0
//! fips module is submitted, not certified).

use aws_lc_rs::digest;
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// Ed25519 signature length — the only v1 root signature algorithm.
pub const SIG_LEN: usize = 64;
/// Raw seed / public key / key-id lengths.
pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const KEY_ID_LEN: usize = 32;

/// Signing failure (environmental — aws-lc-rs reports no detail).
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Key generation / seed extraction / signing failed inside AWS-LC.
    Backend,
    /// Seed and public key do not form a consistent Ed25519 pair, or
    /// the seed is malformed.
    BadKeyMaterial,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend => write!(f, "crypto backend failure"),
            Self::BadKeyMaterial => write!(f, "seed/public-key pair rejected"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Signature verification failure — deliberately carries nothing: a
/// bad signature is a bad signature.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyError;

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signature verification failed")
    }
}

impl std::error::Error for VerifyError {}

/// A signing key held in memory for one publish.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    public: [u8; PUBLIC_KEY_LEN],
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("key_id", &key_id(&self.public))
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generate a fresh keypair, returning the raw seed alongside so
    /// the caller can persist it (the seed IS the RFC 8032 private
    /// key).
    ///
    /// # Errors
    /// [`CryptoError::Backend`] on AWS-LC failure.
    pub fn generate() -> Result<(Self, [u8; SEED_LEN]), CryptoError> {
        let pair = Ed25519KeyPair::generate().map_err(|_| CryptoError::Backend)?;
        let seed_bin = pair
            .seed()
            .and_then(|s| s.as_be_bytes())
            .map_err(|_| CryptoError::Backend)?;
        let seed: [u8; SEED_LEN] = seed_bin
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Backend)?;
        let public: [u8; PUBLIC_KEY_LEN] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Backend)?;
        Ok((Self { pair, public }, seed))
    }

    /// Reconstruct from a stored seed + its public key. The
    /// consistency-checking constructor is used deliberately
    /// (`from_seed_unchecked` cannot detect a swapped argument).
    ///
    /// # Errors
    /// [`CryptoError::BadKeyMaterial`] if the pair is inconsistent.
    pub fn from_seed_and_public_key(
        seed: &[u8; SEED_LEN],
        public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Self, CryptoError> {
        let pair = Ed25519KeyPair::from_seed_and_public_key(seed, public)
            .map_err(|_| CryptoError::BadKeyMaterial)?;
        Ok(Self {
            pair,
            public: *public,
        })
    }

    /// Reconstruct from a stored seed ALONE, deriving its public key.
    /// Unlike [`from_seed_and_public_key`](Self::from_seed_and_public_key),
    /// there is no second, independently-supplied public key here to be
    /// INCONSISTENT with — the "swapped argument" hazard that
    /// constructor's checking exists to catch cannot
    /// arise when the public key is not an input at all, only an
    /// output. This exists for recovering a lost/never-written `.pub`
    /// sidecar from its seed; it is not a substitute for the checking
    /// constructor when a caller DOES hold an independently-supplied
    /// public key to validate against — that path stays on
    /// `from_seed_and_public_key` deliberately.
    ///
    /// # Errors
    /// [`CryptoError::BadKeyMaterial`] if the seed is rejected by the
    /// backend (malformed — 32 bytes is always structurally valid, so
    /// unreachable in practice, kept for defense).
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, CryptoError> {
        let pair =
            Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| CryptoError::BadKeyMaterial)?;
        let public: [u8; PUBLIC_KEY_LEN] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Backend)?;
        Ok(Self { pair, public })
    }

    /// The raw 32-byte public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// TUF-style key id of this key (SHA-256 of the raw public key).
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        key_id(&self.public)
    }

    /// Sign a root's signed prefix. Deterministic (RFC 8032): same
    /// key + same bytes → identical signature, every platform.
    #[must_use]
    pub fn sign(&self, signed_prefix: &[u8]) -> [u8; SIG_LEN] {
        let sig = self.pair.sign(signed_prefix);
        let mut out = [0u8; SIG_LEN];
        // Ed25519 signatures are exactly 64 bytes (RFC 8032); a
        // different length from AWS-LC would be a broken build, and
        // copy_from_slice panics are unreachable given the API
        // contract — enforced by the conformance test below.
        out.copy_from_slice(sig.as_ref());
        out
    }
}

/// TUF-style key id: SHA-256 over the raw 32-byte public key — of the
/// KEY BYTES, never of any envelope or encoding around them.
#[must_use]
pub fn key_id(public: &[u8; PUBLIC_KEY_LEN]) -> [u8; KEY_ID_LEN] {
    let d = digest::digest(&digest::SHA256, public);
    let mut out = [0u8; KEY_ID_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// Verify one signature over a root's signed prefix.
///
/// # Errors
/// [`VerifyError`] — a bad signature is a bad signature.
pub fn verify(
    public: &[u8; PUBLIC_KEY_LEN],
    signed_prefix: &[u8],
    sig: &[u8; SIG_LEN],
) -> Result<(), VerifyError> {
    UnparsedPublicKey::new(&signature::ED25519, public)
        .verify(signed_prefix, sig)
        .map_err(|_| VerifyError)
}

mod root_check;
pub use root_check::{HeadError, TrustedKeys, TrustedKeysError, check_head, check_signatures};

#[cfg(test)]
mod tests;
