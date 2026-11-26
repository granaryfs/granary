// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The head check: one root, read from a store, is accepted only if it
//! decodes strictly, is the root of the volume and seq it was read at, and
//! carries a valid signature from a key in a [`TrustedKeys`] set.
//!
//! The set's semantics: a slot whose key id is not in the set is ignored;
//! every slot that does name a set key must verify; at least one such slot
//! must exist. So a root signed by a stranger and a root signed by nobody
//! are the same refusal, and a bad signature from a set key is an error
//! even when another set key also signed well.
//!
//! The signature is verified over the signed prefix of the RECEIVED bytes,
//! never over a re-encoding of the decoded document. The decode, volume and
//! seq checks are [`granary_core::root::decode_expected`], and the check of
//! an ancestor against its child is [`granary_core::root::check_link`];
//! both are pure and carry no cryptography, so they live in
//! `granary_core::root`.
//!
//! The check is pure: it takes bytes the caller already read.

use granary_core::root::{self, RootDoc, RootIdentityError};

use super::{KEY_ID_LEN, PUBLIC_KEY_LEN, key_id, verify};

/// Why a set of trusted keys was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedKeysError {
    /// No key was supplied: a set that trusts nothing would refuse every
    /// root, and is far more likely a missing configuration than intent.
    Empty,
    /// The all-zero public key was supplied. It is what an unset, zeroed
    /// configuration field looks like, and it is a valid order-4 curve
    /// point under which an all-zero signature verifies for about one
    /// message in four, so accepting it would admit forged roots.
    ZeroKey,
}

impl std::fmt::Display for TrustedKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("a trusted key set needs at least one key"),
            Self::ZeroKey => f.write_str(
                "the all-zero public key is not a trusted key: it is a valid \
                 order-4 curve point, so an all-zero signature verifies under \
                 it for about one root in four",
            ),
        }
    }
}

impl std::error::Error for TrustedKeysError {}

/// A non-empty set of Ed25519 public keys a root's signature may come from.
///
/// Each key is held with its key id, derived from the key rather than
/// supplied beside it: a configured pair could disagree, leaving a slot
/// that matches with a key that cannot verify it. The set is deduplicated
/// by key id, keeping the first occurrence, so a key listed twice is one key
/// and the set's order never changes what verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKeys {
    keys: Vec<([u8; KEY_ID_LEN], [u8; PUBLIC_KEY_LEN])>,
}

impl TrustedKeys {
    /// Build a set from raw public keys.
    ///
    /// # Errors
    /// [`TrustedKeysError::Empty`] for no keys; [`TrustedKeysError::ZeroKey`]
    /// if any key is all zero.
    pub fn new(
        publics: impl IntoIterator<Item = [u8; PUBLIC_KEY_LEN]>,
    ) -> Result<Self, TrustedKeysError> {
        let mut keys: Vec<([u8; KEY_ID_LEN], [u8; PUBLIC_KEY_LEN])> = Vec::new();
        for public in publics {
            if public == [0_u8; PUBLIC_KEY_LEN] {
                return Err(TrustedKeysError::ZeroKey);
            }
            let id = key_id(&public);
            if !keys.iter().any(|(existing, _)| *existing == id) {
                keys.push((id, public));
            }
        }
        if keys.is_empty() {
            return Err(TrustedKeysError::Empty);
        }
        Ok(Self { keys })
    }

    /// How many distinct keys the set holds (at least one).
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Always false: construction refuses an empty set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn public_for(&self, id: &[u8; KEY_ID_LEN]) -> Option<&[u8; PUBLIC_KEY_LEN]> {
        self.keys
            .iter()
            .find(|(candidate, _)| candidate == id)
            .map(|(_, public)| public)
    }
}

/// Why [`check_head`] refused a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadError {
    /// The decode, volume or seq check failed.
    Identity(RootIdentityError),
    /// No signature slot names a key in the trusted set. A root signed by
    /// a stranger and a root signed by nobody are the same state here.
    NoTrustedSlot,
    /// A slot names a trusted key and its signature does not verify over
    /// the root's signed prefix.
    BadSignature {
        /// The trusted key whose slot failed.
        key_id: [u8; KEY_ID_LEN],
    },
}

impl std::fmt::Display for HeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(e) => e.fmt(f),
            Self::NoTrustedSlot => f.write_str("root carries no signature from a trusted key"),
            Self::BadSignature { .. } => {
                f.write_str("root carries a signature from a trusted key that does not verify")
            }
        }
    }
}

impl std::error::Error for HeadError {}

/// Check a root as the head of a chain: it decodes strictly, names
/// `volume` and `seq`, and is signed by a key in `keys`.
///
/// The signature is verified over [`root::signed_prefix`] of `bytes` AS
/// STORED, never over a re-encoding of the decoded document. Slots whose
/// key id is not in the set are ignored. Every slot that does name a
/// trusted key must verify, and at least one must exist: a bad signature
/// from a trusted key is an error even when another trusted key also
/// signed. (The decoder refuses duplicate key ids, so each key has at
/// most one slot.)
///
/// # Errors
/// [`HeadError`]; the identity checks run before any signature is read.
pub fn check_head(
    bytes: &[u8],
    volume: &str,
    seq: u64,
    keys: &TrustedKeys,
) -> Result<RootDoc, HeadError> {
    let doc = root::decode_expected(bytes, volume, seq).map_err(HeadError::Identity)?;
    check_signatures(&doc, bytes, keys)?;
    Ok(doc)
}

/// [`check_head`]'s signature rule alone, for a caller that has already
/// decoded `bytes` strictly into `doc` and checked its identity: every
/// slot naming a key in `keys` verifies over [`root::signed_prefix`] of
/// `bytes` as stored, and at least one does.
///
/// # Errors
/// [`HeadError::NoTrustedSlot`] or [`HeadError::BadSignature`];
/// [`HeadError::Identity`] only if `bytes` has no signed prefix, which a
/// strictly decoded root always has.
pub fn check_signatures(doc: &RootDoc, bytes: &[u8], keys: &TrustedKeys) -> Result<(), HeadError> {
    let prefix = root::signed_prefix(bytes)
        .map_err(|e| HeadError::Identity(RootIdentityError::Decode(e)))?;
    let mut matched = false;
    for slot in &doc.sigs {
        let Some(public) = keys.public_for(&slot.key_id) else {
            continue;
        };
        matched = true;
        verify(public, prefix, &slot.sig).map_err(|_failed| HeadError::BadSignature {
            key_id: slot.key_id,
        })?;
    }
    if matched {
        Ok(())
    } else {
        Err(HeadError::NoTrustedSlot)
    }
}

#[cfg(test)]
mod tests;
