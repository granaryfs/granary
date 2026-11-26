// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Content-defined chunking: `FastCDC` v2020 wrapper (spec §4).
//!
//! The tuple in [`CHUNKER_SPEC`] is a PINNED FORMAT CONTRACT:
//! cut-point drift never breaks correctness, but it silently degrades
//! dedup across an epoch boundary, so (algorithm, crate version,
//! params, normalization) is recorded, the dependency is pinned
//! `=4.0.1`, and the golden vectors in `tests/thresh_golden.rs` are the
//! drift tripwire. Changing ANY element is a deliberate format event.
//!
//! Parameter validation note: fastcdc 4.x bounds-checks
//! only via `debug_assert!` and misbehaves data-dependently on invalid
//! params in release builds. This wrapper therefore exposes NO
//! runtime-parameter API — the params are compile-time constants,
//! validated by the `const` block below. A future milestone that needs
//! per-volume params adds a validated constructor then (YAGNI now).

use fastcdc::v2020::{FastCDC, Normalization, StreamCDC};

/// Minimum grain size: 128 KiB. Inputs below this are never split.
pub const MIN_GRAIN: usize = 128 * 1024;
/// Target average grain size: 256 KiB. Power of two — mask selection
/// has no rounding ambiguity (the v3→v4 upstream bug class only touched
/// non-power-of-two averages).
pub const AVG_GRAIN: usize = 256 * 1024;
/// Maximum grain size: 2 MiB.
pub const MAX_GRAIN: usize = 2 * 1024 * 1024;

/// `FastCDC` v2020 normalization level. One of the two tuple fields the
/// tuning factorial decides; threaded into both cutters below via
/// the private `NORMALIZATION`, never left to the crate's `new()`
/// default — a constant the code does not read is metadata, not a
/// contract.
pub const NORMALIZATION_LEVEL: u8 = 1;

/// [`NORMALIZATION_LEVEL`] as the upstream enum. A `const` ITEM, not a
/// function: the initializer is evaluated at compile time, so the
/// `panic!` arm is a build failure if the level ever leaves 0..=3 —
/// there is no runtime path to it.
const NORMALIZATION: Normalization = match NORMALIZATION_LEVEL {
    0 => Normalization::Level0,
    1 => Normalization::Level1,
    2 => Normalization::Level2,
    3 => Normalization::Level3,
    _ => panic!("NORMALIZATION_LEVEL must be 0..=3"),
};

// The six relations fastcdc 4.0.1 only debug_asserts, promoted to
// compile-time guarantees, plus our own coherence requirements.
const _: () = {
    assert!(MIN_GRAIN >= 64 && MIN_GRAIN <= 1_048_576);
    assert!(AVG_GRAIN >= 256 && AVG_GRAIN <= 4_194_304);
    assert!(MAX_GRAIN >= 1024 && MAX_GRAIN <= 16_777_216);
    assert!(MIN_GRAIN <= AVG_GRAIN && AVG_GRAIN <= MAX_GRAIN);
    assert!(AVG_GRAIN.is_power_of_two());
    // Every grain must be encodable in the frozen v1 manifest. Until
    // the grain-ceiling event this was structurally impossible to violate —
    // MAX_GRAIN and the manifest ceiling were the same 8 MiB — so it was
    // never written down. The event moved MAX_GRAIN to 2 MiB and left
    // the ceiling frozen, making the two INDEPENDENT: fastcdc alone
    // would accept a MAX_GRAIN of 16 MiB, and the first oversized grain
    // would then be refused by `GrainRef` encoding at RUNTIME, on user
    // data. Promoted to a build failure here.
    assert!(MAX_GRAIN <= crate::manifest::GRAIN_UNPACKED_MAX as usize);
};

/// The chunker identity tuple. Recorded in volume metadata from v1;
/// printed by `gran thresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkerSpec {
    pub algorithm: &'static str,
    pub crate_version: &'static str,
    pub min: usize,
    pub avg: usize,
    pub max: usize,
    pub normalization: u8,
}

/// The one chunker this crate ships.
pub const CHUNKER_SPEC: ChunkerSpec = ChunkerSpec {
    algorithm: "fastcdc-v2020",
    crate_version: "4.0.1",
    min: MIN_GRAIN,
    avg: AVG_GRAIN,
    max: MAX_GRAIN,
    normalization: NORMALIZATION_LEVEL,
};

impl core::fmt::Display for ChunkerSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}/{} min={} avg={} max={} nl={}",
            self.algorithm, self.crate_version, self.min, self.avg, self.max, self.normalization
        )
    }
}

/// A cut grain: a location within the source buffer. Offsets/lengths
/// are in-memory (`usize`); persistent formats re-encode as `u64` at
/// their own boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grain {
    pub offset: usize,
    pub length: usize,
}

/// Chunk an in-memory buffer. Empty input yields no grains; non-empty
/// input below [`MIN_GRAIN`] yields exactly one.
pub fn grains(data: &[u8]) -> impl Iterator<Item = Grain> + '_ {
    FastCDC::with_level(data, MIN_GRAIN, AVG_GRAIN, MAX_GRAIN, NORMALIZATION).map(|c| Grain {
        offset: c.offset,
        length: c.length,
    })
}

/// A grain cut from a stream: the bytes are owned (copied out of the
/// chunker's internal buffer). ~34% slower than [`grains`] (measured)
/// — prefer the slice path when the bytes are already in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedGrain {
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
}

/// Why streaming chunking stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum StreamGrainError {
    /// The underlying reader failed.
    Io(std::io::Error),
    /// The chunker reported a non-I/O error.
    Chunker(String),
}

impl core::fmt::Display for StreamGrainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "read failed: {e}"),
            Self::Chunker(msg) => write!(f, "chunker error: {msg}"),
        }
    }
}

impl core::error::Error for StreamGrainError {}

/// Chunk a byte stream with the same cut points as [`grains`]
/// (slice/stream equality is golden-vector- and property-tested).
/// Memory use is bounded by [`MAX_GRAIN`]-sized internal buffering.
///
/// An `Err` does NOT poison the iterator: the reader is simply retried
/// on the next call, so a persistently failing reader re-yields its
/// error forever, while a reader that recovers resumes cutting — the
/// caller cannot distinguish a transient hiccup from a truncated
/// stream. Treat any `Err` as terminal and stop iterating. (fastcdc
/// 4.0.1 does not retry `ErrorKind::Interrupted` internally either.)
pub fn grains_streaming<R: std::io::Read>(
    source: R,
) -> impl Iterator<Item = Result<OwnedGrain, StreamGrainError>> {
    StreamCDC::with_level(source, MIN_GRAIN, AVG_GRAIN, MAX_GRAIN, NORMALIZATION).map(|chunk| {
        match chunk {
            Ok(c) => Ok(OwnedGrain {
                offset: c.offset,
                length: c.length,
                data: c.data,
            }),
            Err(fastcdc::v2020::Error::IoError(e)) => Err(StreamGrainError::Io(e)),
            // Error::Empty is the iterator's internal EOF marker and is
            // not yielded by the Iterator impl in 4.0.1; mapped
            // defensively.
            Err(other) => Err(StreamGrainError::Chunker(other.to_string())),
        }
    })
}

#[cfg(test)]
mod tests;
