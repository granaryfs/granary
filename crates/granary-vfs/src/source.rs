// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The synchronous seam between the engine's reader and its content
//! source. `MountBackend` — the trait an adapter implements to plug a
//! real fetch path in, plus shutdown/crash-abandon lifecycle — stays with
//! the adapter (`granary-fuse::source`): it is `Send + 'static` and
//! adapter-shaped, not engine-shaped. Only the two items the reader
//! itself names live here.

use alloc::string::String;
use alloc::vec::Vec;

use granary_core::hash::GrainId;

/// A content grain could not be obtained by the mount backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrainUnavailable {
    message: String,
}

impl GrainUnavailable {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for GrainUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for GrainUnavailable {}

/// Where a mount gets a content grain. Synchronous on purpose: the
/// adapter holds one mutex across a FUSE callback and the implementor —
/// granary-client — does its own `block_on` inside. Keeping the async
/// out of this crate is what lets the whole reader be tested on a
/// machine that cannot mount anything.
pub trait GrainFetch: Send {
    /// Fetch one grain, already decompressed and already verified
    /// against `id` by the implementor. `unpacked_len` is what the
    /// manifest DECLARES; an implementor that returns a different
    /// length has broken its contract and the reader treats that as an
    /// inconsistency, not as a short file.
    ///
    /// # Errors
    /// Whatever the implementor could not do. The adapter maps every
    /// variant to `EIO` — a mount has no way to tell a caller "the
    /// network is down" except by failing the read.
    fn grain(&mut self, id: &GrainId, unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable>;
}
