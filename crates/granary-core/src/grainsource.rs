// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The local-store read contract. PURE: std only,
//! no I/O types — the trait is what granary-client's local `Store`
//! implements and what the sim fakes, which is what lets a
//! simulated publish need no filesystem at all.
//!
//! **This trait is SYNCHRONOUS on purpose.** The local store is a
//! filesystem, and `Store::get`/`Store::has` in granary-client are
//! already sync, so there is nothing here to await and no `Send` bound
//! to express on a future that does not exist. That also makes it the
//! one seam of the three that IS dyn-compatible: [`crate::rootstore::RootStore`]
//! and [`crate::binstore::BinStore`] return `impl Future` (RPITIT),
//! which makes them dyn-INcompatible, while `&dyn GrainSource` is
//! available to callers that want it.
//!
//! That last clause is only true if CONSUMERS keep it true: a generic
//! `G: GrainSource` carries an implicit `Sized`, so a `&dyn GrainSource`
//! cannot be passed to it. Functions taking this seam generically write
//! `G: GrainSource + ?Sized`, which costs nothing and is the difference
//! between the dyn-compatibility being real and being a claim.
//!
//! **`put` is deliberately absent.** Publish's write to the local store
//! happens inside `harvest`, which is hoisted out of the simulated path —
//! `prepare_from_manifest` is what the sim drives, and it only reads.
//! Harvest is a purely local operation with no remote interaction, so
//! keeping it concrete costs the sim nothing and is what lets this trait
//! stay read-only.

use crate::hash::GrainId;

/// Why a [`GrainSource`] read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrainSourceError {
    /// No object with that id.
    Missing(GrainId),
    /// The bytes are there and do not hash to the id (the read path
    /// is the verified path).
    Corrupt(GrainId),
    /// Anything the backing store reported, as its own message.
    Backend(String),
}

impl std::fmt::Display for GrainSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(id) => write!(f, "no object for {id}"),
            Self::Corrupt(id) => write!(f, "stored bytes do not hash to {id}"),
            Self::Backend(msg) => write!(f, "local store: {msg}"),
        }
    }
}

impl std::error::Error for GrainSourceError {}

/// The local-store read contract granary-client implements.
pub trait GrainSource: Send + Sync {
    /// Read an object, hash-verified.
    ///
    /// # Errors
    /// [`GrainSourceError::Missing`] when nothing is stored under `id`;
    /// [`GrainSourceError::Corrupt`] when the stored bytes are there and
    /// do not hash to `id`; [`GrainSourceError::Backend`] for anything
    /// the backing store itself reported.
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError>;

    /// Presence only. NOT an integrity claim: a `true` here says an
    /// object is stored under `id`, not that its bytes hash to it —
    /// [`GrainSource::get`] is the only verified answer.
    fn has(&self, id: &GrainId) -> bool;
}

#[cfg(test)]
mod tests;
