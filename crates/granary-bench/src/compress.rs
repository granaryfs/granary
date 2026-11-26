// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-grain compression accounting: the metric is
//! post-per-grain-compression bytes plus manifest/index bytes.
//!
//! Two pre-registered choices, both made before the objective was computed
//! for any dataset, and both binding on the per-grain compression the format froze:
//!
//! 1. **`zstd::bulk`, not `zstd::stream`.** The two were measured
//!    differing by up to 2.78% per grain — bulk passes `srcSize`,
//!    which shrinks window/chain/hash logs. Production compresses a
//!    whole grain it already holds in memory, so bulk is what
//!    production will do, so bulk is what the benchmark measures.
//! 2. **Level 3** (the zstd default). Pinned by the sweep so the curve is
//!    comparable across points and recorded as an input to the decision;
//!    The shipped encoder uses the same level.
//!
//! The crate — not the CLI — is authoritative: CLI/crate byte-identity
//! was measured BREAKING above ~393 KiB, with the CLI's
//! answer depending on threading mode.

use std::io::{self, Write};

/// Pre-registered compression level for every headline number.
pub const ZSTD_LEVEL: i32 = 3;

/// Pre-registered API, recorded in every result file.
pub const ZSTD_API: &str = "zstd::bulk";

/// The zstd CRATE version recorded in every result file. Pinned here
/// and tripwired against the workspace manifest below, the same idiom
/// `granary_core::thresh` uses for the chunker pin — a bump that forgets
/// this constant would make every record lie.
pub const ZSTD_CRATE_VERSION: &str = "0.14.3";

/// Per-grain compressor. Reused across a whole run: constructing one
/// `ZSTD_CCtx` per grain would measure allocator behaviour.
pub struct GrainCompressor {
    inner: zstd::bulk::Compressor<'static>,
}

// zstd's Compressor holds an opaque C context and derives no Debug;
// the workspace requires one on every public type.
impl core::fmt::Debug for GrainCompressor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrainCompressor")
            .field("level", &ZSTD_LEVEL)
            .field("api", &ZSTD_API)
            .finish()
    }
}

impl GrainCompressor {
    /// Build a compressor at [`ZSTD_LEVEL`].
    ///
    /// # Errors
    /// Propagates zstd context-creation failure.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            inner: zstd::bulk::Compressor::new(ZSTD_LEVEL)?,
        })
    }

    /// Compressed length of one grain, as a standalone zstd frame —
    /// exactly what a bin stores: one zstd frame per grain.
    ///
    /// # Errors
    /// Propagates zstd compression failure.
    pub fn compressed_len(&mut self, data: &[u8]) -> io::Result<usize> {
        Ok(self.inner.compress(data)?.len())
    }
}

/// A sink that counts bytes and keeps none of them.
#[derive(Debug, Default)]
pub struct CountingSink {
    /// Bytes written so far.
    pub written: u64,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Compressed length of the same grains as ONE stream — the
/// counterfactual that quantifies the measured independence penalty
/// (+61.4% at 8 KiB, +4.0% at 1 MiB).
///
/// Diagnostic only: it is a `zstd::stream` number by construction and
/// therefore not comparable byte-for-byte with [`GrainCompressor`]
/// output. Pre-registered as a reported diagnostic, never an input to
/// the decision rule.
///
/// # Errors
/// Propagates zstd encoder failure.
pub fn single_stream_len<'a, I>(grains: I) -> io::Result<u64>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut encoder = zstd::stream::write::Encoder::new(CountingSink::default(), ZSTD_LEVEL)?;
    for g in grains {
        encoder.write_all(g)?;
    }
    Ok(encoder.finish()?.written)
}

/// The vendored zstd C library version, recorded in every result file.
#[must_use]
pub fn library_version() -> String {
    let n = zstd::zstd_safe::version_number();
    format!("{}.{}.{}", n / 10_000, (n / 100) % 100, n % 100)
}

#[cfg(test)]
mod tests;
