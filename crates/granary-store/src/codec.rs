// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The grain codec: one zstd frame per grain, with compression fixed at
//! level 3 using the `bulk` API, wrapped in core's 9-byte frame header
//! (`granary_core::binfmt`). This is THE ONE decompress-with-cap
//! implementation every read path shares — client
//! pack-verify, server ingest (through `verify_bin`) and client fetch
//! alike.
//!
//! The decompress law, established by execution against libzstd's
//! actual behaviour:
//!
//! 1. The header's `unpacked_len` is validated against the 8 MiB cap
//!    BEFORE any allocation (the capacity argument pre-allocates
//!    fully).
//! 2. The payload must be exactly ONE zstd frame —
//!    `find_frame_compressed_size(payload) == payload.len()`, checked
//!    structurally BEFORE decompression. `bulk::decompress` is a
//!    MULTI-FRAME API: it consumes every frame in the buffer and
//!    silently skips *skippable* frames, so without this check
//!    `zstd(G) || skippable(junk)` decoded Ok to exactly G — a second
//!    byte encoding of the same grain, unbounded junk included. Exact
//!    capacity cannot enforce the one-frame rule alone: it rejects a
//!    concatenation only when the summed output EXCEEDS the declaration.
//!    The structural frame-size check is therefore required even with
//!    exact output capacity.
//! 3. Decompression runs with capacity = THE EXACT DECLARED LENGTH,
//!    never the cap (defence in depth under law 2: output can never
//!    exceed the declaration regardless of frame structure).
//! 4. `out.len() == declared` is asserted after the call (also closes
//!    the Vec-overallocation contract hazard, and refuses a payload
//!    that is one lone skippable/empty frame — a single frame in
//!    law 2's terms, but one producing zero bytes).
//! 5. Every zstd failure is ONE opaque [`CodecError::FrameInvalid`]:
//!    the safe API's error strings do not distinguish overrun from
//!    corruption (and libzstd passes ~99% of corruptions SILENTLY
//!    without checksums), so no code branches on zstd errors and
//!    **zstd `Ok` is never treated as integrity** — blake3
//!    verification of the decompressed bytes against the grain id is
//!    the integrity layer, and it belongs to the CALLER, which
//!    knows the expected id.
//!
//! No zstd checksum flag and content-size default left ON: both match
//! what granary-bench measured; the inner
//! content-size field is never read by granary code, and blake3
//! subsumes the checksum.

use granary_core::binfmt::{FRAME_HEADER_LEN, decode_frame_header, encode_frame_header};
use granary_core::encoding::DecodeError;
use granary_core::manifest::GRAIN_UNPACKED_MAX;

/// Pre-registered compression level — the zstd default.
pub const ZSTD_LEVEL: i32 = 3;

/// The vendored libzstd C version this crate is pinned to, as
/// `ZSTD_VERSION_NUMBER` (1.5.7). Compressed bytes are only
/// deterministic WITHIN a C-library version; the `=0.14.3` crate pin
/// does NOT transitively pin the C source (zstd-safe carets
/// zstd-sys), so the runtime version is tripwired in tests against
/// this constant alongside Cargo.lock and deny.toml's version-exact
/// build allowance. A conscious bump re-bakes every full-frame golden
/// vector.
pub const ZSTD_C_VERSION_NUMBER: u32 = 10507;

/// Grain-frame codec holding reused zstd contexts — constructing one
/// context per grain would measure allocator behaviour, not
/// compression (the documented fast path; reuse is state-leak-probed
/// clean by the tests below).
pub struct GrainCodec {
    compressor: zstd::bulk::Compressor<'static>,
    decompressor: zstd::bulk::Decompressor<'static>,
}

impl std::fmt::Debug for GrainCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrainCodec")
            .field("level", &ZSTD_LEVEL)
            .finish_non_exhaustive()
    }
}

/// Codec failure. `FrameInvalid` is deliberately opaque — see the
/// module doc's decompress law.
#[derive(Debug)]
pub enum CodecError {
    /// Empty grains are not encodable (the manifest refuses them too).
    EmptyGrain,
    /// Grain exceeds [`GRAIN_UNPACKED_MAX`] — never chunker output; a
    /// caller bug.
    GrainTooLarge { len: usize },
    /// The frame header failed validation (refuse-nonzero framing or
    /// `dict_id`, zero/over-cap declared length, truncation).
    Header(DecodeError),
    /// The zstd payload failed to decompress to exactly its declared
    /// length — overrun, corruption and truncation all land here,
    /// undistinguished BY DESIGN.
    FrameInvalid,
    /// The payload is not exactly ONE zstd frame (decompress law 2 —
    /// a second frame, a skippable frame, or trailing bytes follow the
    /// first frame). Typed separately from [`CodecError::FrameInvalid`]
    /// because this is granary's own canonicality law, not a zstd
    /// verdict: a test asserting THIS variant proves the single-frame
    /// check fired, not that zstd happened to choke.
    PayloadNotSingleFrame {
        frame_len: usize,
        payload_len: usize,
    },
    /// Decompression succeeded but produced fewer bytes than declared
    /// (the > case is refused by zstd itself at exact capacity).
    DeclaredLengthMismatch { declared: u32, actual: usize },
    /// zstd context construction/compression failure (environmental).
    Zstd(std::io::Error),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyGrain => write!(f, "empty grain is not encodable"),
            Self::GrainTooLarge { len } => {
                write!(f, "grain of {len} bytes exceeds GRAIN_UNPACKED_MAX")
            }
            Self::Header(e) => write!(f, "frame header: {e}"),
            Self::FrameInvalid => write!(f, "frame payload invalid (rejected, not grown)"),
            Self::PayloadNotSingleFrame {
                frame_len,
                payload_len,
            } => {
                write!(
                    f,
                    "payload is not a single zstd frame (first frame ends at {frame_len} of {payload_len} bytes)"
                )
            }
            Self::DeclaredLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "frame declared {declared} bytes, decompressed to {actual}"
                )
            }
            Self::Zstd(e) => write!(f, "zstd: {e}"),
        }
    }
}

impl std::error::Error for CodecError {}

impl GrainCodec {
    /// Build a codec at [`ZSTD_LEVEL`].
    ///
    /// # Errors
    /// [`CodecError::Zstd`] on context-creation failure.
    pub fn new() -> Result<Self, CodecError> {
        Ok(Self {
            compressor: zstd::bulk::Compressor::new(ZSTD_LEVEL).map_err(CodecError::Zstd)?,
            decompressor: zstd::bulk::Decompressor::new().map_err(CodecError::Zstd)?,
        })
    }

    /// Compress one grain into a complete v1 frame (header + zstd
    /// payload), ready for `granary_core::binfmt::encode_bin`.
    ///
    /// # Errors
    /// [`CodecError::EmptyGrain`] / [`CodecError::GrainTooLarge`] on
    /// illegal input (the encoder refuses what readers reject);
    /// [`CodecError::Zstd`] on compression failure.
    pub fn compress_grain(&mut self, grain: &[u8]) -> Result<Vec<u8>, CodecError> {
        if grain.is_empty() {
            return Err(CodecError::EmptyGrain);
        }
        if grain.len() > GRAIN_UNPACKED_MAX as usize {
            return Err(CodecError::GrainTooLarge { len: grain.len() });
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len <= GRAIN_UNPACKED_MAX (8 MiB) checked above"
        )]
        let header = encode_frame_header(grain.len() as u32).map_err(CodecError::Header)?;
        let payload = self.compressor.compress(grain).map_err(CodecError::Zstd)?;
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decompress one complete frame back to grain bytes, enforcing
    /// the decompress law (module doc). The returned bytes are NOT yet
    /// integrity-checked — the caller blake3-verifies them against the
    /// expected grain id; zstd success is never integrity.
    ///
    /// A thin owning wrapper over [`GrainCodec::decompress_frame_into`],
    /// which is where the law lives: one implementation, so a caller
    /// that reuses a buffer and a caller that wants a fresh `Vec` cannot
    /// come to enforce different rules.
    ///
    /// # Errors
    /// [`CodecError::Header`] on header violations (including
    /// refuse-nonzero framing/`dict_id`);
    /// [`CodecError::PayloadNotSingleFrame`] when the payload is not
    /// exactly one zstd frame (law 2); [`CodecError::FrameInvalid`] on
    /// any payload failure; [`CodecError::DeclaredLengthMismatch`] when
    /// output falls short of the declaration.
    pub fn decompress_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        let len = self.decompress_frame_into(frame, &mut out)?.len();
        out.truncate(len);
        Ok(out)
    }

    /// The same decompression, into a buffer the CALLER owns and reuses.
    ///
    /// **Why this exists: a bin holds up to 65 536 frames, and a fresh
    /// `Vec` per frame is 65 536 allocate-and-free cycles of up to 8 MiB
    /// each on a path that runs on unauthenticated input.** `out` is
    /// grown to fit and never shrunk, so a whole-bin verify pays for one
    /// buffer at the largest grain it met.
    ///
    /// The returned slice borrows `out` and is exactly the grain: `out`
    /// itself may be LONGER, carrying the tail of a previous, larger
    /// frame, and a caller that hashed the whole buffer would be hashing
    /// that tail. The slice is what makes that mistake unavailable
    /// rather than merely documented.
    ///
    /// **Law 3 survives the reuse**, which is the one thing a shared
    /// buffer could have cost: the destination handed to zstd is
    /// `out[..declared]`, so the capacity zstd sees is the DECLARATION
    /// and not the buffer — a frame declaring a hundred bytes cannot
    /// write into the eight mebibytes a previous frame left behind.
    ///
    /// # Errors
    /// The same four as [`GrainCodec::decompress_frame`].
    pub fn decompress_frame_into<'out>(
        &mut self,
        frame: &[u8],
        out: &'out mut Vec<u8>,
    ) -> Result<&'out [u8], CodecError> {
        let header = decode_frame_header(frame).map_err(CodecError::Header)?;
        let payload = frame
            .get(FRAME_HEADER_LEN..)
            .ok_or(CodecError::FrameInvalid)?;
        // Law 2: the payload must be exactly ONE zstd frame, checked
        // structurally BEFORE decompression — `bulk::decompress` is a
        // multi-frame API and would otherwise consume concatenated and
        // skippable frames silently. A parse
        // failure here (no legal frame header at byte 0, truncation)
        // is the opaque FrameInvalid; a parsed first frame that does
        // not span the whole payload is the typed canonicality refusal.
        let frame_len = zstd::zstd_safe::find_frame_compressed_size(payload)
            .map_err(|_| CodecError::FrameInvalid)?;
        if frame_len != payload.len() {
            return Err(CodecError::PayloadNotSingleFrame {
                frame_len,
                payload_len: payload.len(),
            });
        }
        // Law 1: declared is already <= 8 MiB (header validation), so
        // the grow below is bounded by the frame cap and not by the
        // frame's own claim about itself.
        let declared = header.unpacked_len;
        let declared_len = declared as usize;
        if out.len() < declared_len {
            out.resize(declared_len, 0);
        }
        // Law 3: the destination is EXACTLY the declaration wide. The
        // slice is taken through `get_mut` — the resize above makes the
        // `None` arm unreachable, and it is written rather than
        // asserted because this runs on untrusted input.
        let destination = out
            .get_mut(..declared_len)
            .ok_or(CodecError::FrameInvalid)?;
        let written = self
            .decompressor
            .decompress_to_buffer(payload, destination)
            .map_err(|_| CodecError::FrameInvalid)?;
        // Law 4: exact-length assertion (also closes the
        // over-allocation contract hazard, and refuses a payload
        // that is one lone zero-output frame).
        if written != declared_len {
            return Err(CodecError::DeclaredLengthMismatch {
                declared,
                actual: written,
            });
        }
        out.get(..declared_len).ok_or(CodecError::FrameInvalid)
    }

    /// Is `stored_frame` the frame this codec would have written for
    /// `plaintext`? (The frame byte-canonicality primitive.)
    ///
    /// **A BYTE comparison against a re-compression, and the alternative
    /// — comparing grain digests — is mechanically empty.** A grain id
    /// hashes the UNCOMPRESSED bytes, so it is identical for every
    /// valid compression of the same grain: a checksum-flagged frame, a
    /// frame from another level, a frame with another block split all
    /// carry the same id as the canonical one. A digest compare would
    /// therefore answer `true` for exactly the frames this exists to
    /// tell apart, and the accept-set ledger in this file's tests names
    /// those frames as accepted-and-distinct.
    ///
    /// What makes the comparison meaningful is law 2: the payload is one
    /// zstd frame, so a non-canonical frame cannot merely be a canonical
    /// one with padding appended.
    ///
    /// **Not invoked at server ingest (deferred).** The primitive
    /// exists so that wiring it in later needs no protocol edit; until
    /// then a hash-valid but byte-non-canonical bin is accepted.
    ///
    ///
    /// # Errors
    /// Whatever [`GrainCodec::compress_grain`] refuses about
    /// `plaintext` — an empty grain, a grain over the cap, or a zstd
    /// failure. A `stored_frame` that is not a legal frame at all is
    /// not an error here: it simply does not match.
    pub fn recompress_matches(
        &mut self,
        plaintext: &[u8],
        stored_frame: &[u8],
    ) -> Result<bool, CodecError> {
        let canonical = self.compress_grain(plaintext)?;
        Ok(canonical == stored_frame)
    }
}

#[cfg(test)]
mod tests;
