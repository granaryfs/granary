// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The simulator's implementation of the cryptographic-randomness seam,
//! [`granary_core::secure_random::SecureRandom`]: a stream fixed by a
//! 32-byte key, so a replay seed reproduces every value drawn from it.
//!
//! **Construction.** Block `i` of the stream is
//! `BLAKE3(BLOCK_CONTEXT ‖ key ‖ i as u64 big-endian)`, 32 bytes, and the
//! stream is the blocks in order: a keyed counter-mode stream over
//! BLAKE3, reached through `granary_core::hash::GrainId::of`, the
//! workspace's one BLAKE3 entry point this crate already depends on.
//! Every field after the context is fixed-width, so no two (key, index)
//! pairs share a preimage.
//!
//! **One persistent stream per value.** A [`SeededSecureRandom`] holds
//! its key and its position, and advances the position with every fill,
//! so successive fills continue the stream and never repeat its prefix. It is deliberately
//! not `Clone`: a copy would hand out the same bytes twice.
//!
//! **A limit, refused.** The stream gives at most 2^64 − 1 bytes, the
//! most a `u64` position can count. A fill that would pass it is refused
//! whole, with nothing written, as [`EntropyUnavailable`].
//!
//! **One stream per simulated process lifetime.**
//! [`SeededSecureRandom::for_incarnation`] keys a stream by the replay
//! seed the simulator already prints and the incarnation's index, so a
//! harness that builds fresh parts for each simulated process gives each
//! its own stream, and the printed seed determines all of them.
//!
//! **Never production.** No production crate takes this crate as a
//! normal or build dependency; `scripts/check-licence-resolved.py`
//! refuses one.

use granary_core::hash::GrainId;
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

/// Bytes in one block of the stream.
const BLOCK_LEN: usize = 32;

/// [`BLOCK_LEN`] as a stream position counts it.
const BLOCK_LEN_U64: u64 = BLOCK_LEN as u64;

/// The context prefixed to every block's preimage.
const BLOCK_CONTEXT: &[u8] = b"granary sim secure-random v1 block\0";

/// A block's preimage: the context, the key, the block's index.
const BLOCK_PREIMAGE_LEN: usize = BLOCK_CONTEXT.len() + 32 + 8;

/// The context prefixed to an incarnation's key derivation.
const KEY_CONTEXT: &[u8] = b"granary sim secure-random v1 key\0";

/// A key's preimage: the context, the replay seed, the incarnation.
const KEY_PREIMAGE_LEN: usize = KEY_CONTEXT.len() + 8 + 4;

/// A seeded cryptographic-randomness stream (module docs): its key and
/// its position, and nothing else; every block is computed from the two
/// when a fill needs it.
#[derive(Debug)]
pub struct SeededSecureRandom {
    key: [u8; 32],
    /// Bytes given so far: the stream's position.
    given: u64,
}

impl SeededSecureRandom {
    /// The stream keyed by `key`, at its start.
    #[must_use]
    pub const fn from_key(key: [u8; 32]) -> Self {
        Self { key, given: 0 }
    }

    /// The stream of incarnation `incarnation` (the index of one
    /// simulated process lifetime) under replay seed `replay_seed`.
    #[must_use]
    pub fn for_incarnation(replay_seed: u64, incarnation: u32) -> Self {
        let mut preimage = [0u8; KEY_PREIMAGE_LEN];
        let (context, rest) = preimage.split_at_mut(KEY_CONTEXT.len());
        let (seed, index) = rest.split_at_mut(8);
        context.copy_from_slice(KEY_CONTEXT);
        seed.copy_from_slice(&replay_seed.to_be_bytes());
        index.copy_from_slice(&incarnation.to_be_bytes());
        Self::from_key(*GrainId::of(&preimage).digest())
    }

    /// Block `index` of the stream.
    fn block(&self, index: u64) -> [u8; BLOCK_LEN] {
        let mut preimage = [0u8; BLOCK_PREIMAGE_LEN];
        let (context, rest) = preimage.split_at_mut(BLOCK_CONTEXT.len());
        let (key, at) = rest.split_at_mut(32);
        context.copy_from_slice(BLOCK_CONTEXT);
        key.copy_from_slice(&self.key);
        at.copy_from_slice(&index.to_be_bytes());
        *GrainId::of(&preimage).digest()
    }
}

impl SecureRandom for SeededSecureRandom {
    /// # Errors
    /// [`EntropyUnavailable`] when the fill would carry the stream past
    /// 2^64 − 1 bytes; nothing is written and the position is unchanged.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        let len = u64::try_from(dest.len()).map_err(|_| EntropyUnavailable)?;
        let end = self.given.checked_add(len).ok_or(EntropyUnavailable)?;
        let mut at = self.given;
        let mut rest = dest;
        // One block hash per chunk: the chunk runs from `at` to the end of
        // its block, or to the end of `dest`, whichever comes first.
        while !rest.is_empty() {
            let block = self.block(at / BLOCK_LEN_U64);
            let offset = usize::try_from(at % BLOCK_LEN_U64).map_err(|_| EntropyUnavailable)?;
            let source = block.get(offset..).ok_or(EntropyUnavailable)?;
            let take = source.len().min(rest.len());
            let (chunk, tail) = std::mem::take(&mut rest).split_at_mut(take);
            chunk.copy_from_slice(source.get(..take).ok_or(EntropyUnavailable)?);
            rest = tail;
            at = at
                .checked_add(u64::try_from(take).map_err(|_| EntropyUnavailable)?)
                .ok_or(EntropyUnavailable)?;
        }
        self.given = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
