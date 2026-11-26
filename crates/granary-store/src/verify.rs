// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ingest verification for a bin: decode it, expand every grain, and
//! hold each one to the id its index claims. This is the bin-ingest
//! admission check (§5.1).
//!
//! **The PRIMITIVE is here and the POLICY is not.** This module decides
//! nothing about what a server does with a refusal, and it holds no
//! ceiling of its own: the decompressed-sum limit arrives as a
//! parameter, so the one figure site stays in the server that owns it
//! and a fuzz target can drive the bound directly (§9.2).
//! Mapping the four failures onto statuses and `Granary-Error` tokens is
//! `granary-server`'s, where the licence boundary puts it.
//!
//! **Two bounds, and the pair is what makes verification affordable.**
//! The declared-sum limit bounds the HASHING term — every byte expanded
//! is a byte blake3 must walk — and the body's own `BIN_MAX_BYTES` cap
//! bounds the SCANNING term, the cost of walking a frame's block
//! structure whatever it declares. Neither is the bound alone (§9.2).

use granary_core::binfmt::{BinIndexEntry, MAX_GRAINS_PER_BIN, decode_bin, frame_bytes};
use granary_core::encoding::DecodeError;
use granary_core::hash::GrainId;
use granary_core::manifest::GRAIN_UNPACKED_MAX;

use crate::codec::{CodecError, GrainCodec};

const _: () = {
    // The running sum accumulates at most MAX_GRAINS_PER_BIN terms, each
    // at most GRAIN_UNPACKED_MAX — the 512 GiB bomb itself, which must
    // be expressible in the accumulator or the bail would compare a
    // wrapped value. Const arithmetic overflow fails the build, so
    // WRITING the product is the check; the equality names the figure
    // §9.2 quotes so a cap change surfaces here.
    assert!(MAX_GRAINS_PER_BIN as u64 * GRAIN_UNPACKED_MAX as u64 == 549_755_813_888);
};

/// Why a bin was refused at ingest.
///
/// Four variants and no wildcard consumer: the server maps each to its
/// own status and token, and a fifth added here fails that match rather
/// than falling into a default.
#[derive(Debug)]
pub enum BinVerifyError {
    /// The bytes are not a decodable bin at all — envelope, index,
    /// extents, or a frame header.
    Undecodable(DecodeError),
    /// A grain expanded to bytes that are not the id the index gave it.
    /// Carries the id the INDEX claimed, never a hash of what arrived:
    /// the latter is attacker-chosen content and has no place in a log
    /// line, let alone on a wire (§8.4).
    GrainInvalid { id: GrainId },
    /// The frames' declared decompressed lengths sum past the limit this
    /// call was given (§9.2). `at_least` is the running total AT the
    /// frame that crossed — not the whole bin's sum, which is a number
    /// verification deliberately stops short of computing on the running
    /// path.
    DecompressedSumExceeded { limit: u64, at_least: u64 },
    /// The codec failed for a reason that is not about this bin: a zstd
    /// context that would not build. Environmental, and the server's
    /// `500`.
    Codec(CodecError),
}

impl std::fmt::Display for BinVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undecodable(e) => write!(f, "not a decodable bin: {e}"),
            Self::GrainInvalid { id } => write!(f, "grain {id} failed its hash check"),
            Self::DecompressedSumExceeded { limit, at_least } => write!(
                f,
                "declared decompressed sum reached {at_least} bytes, past the {limit}-byte ingest limit"
            ),
            Self::Codec(e) => write!(f, "codec: {e}"),
        }
    }
}

impl std::error::Error for BinVerifyError {}

/// Verify one bin: it decodes, its frames' declared decompressed lengths
/// stay inside `decompressed_sum_max`, and every grain expands to the id
/// its index entry names.
///
/// **The sum test runs FIRST and over the WHOLE bin, from frame headers
/// only** — an index walk plus a nine-byte read at each frame's offset,
/// never the expansion it refuses (§9.2). §5.1 makes that precedence
/// normative: a bin that is over the limit AND would also have failed a
/// grain check is refused for the limit, because avoiding that work is
/// what the limit is for.
///
/// **The running bail inside the loop is not redundant with it.** The
/// up-front pass is what a reader should see; the running charge is what
/// bounds the WORK if the pass is ever weakened, reordered, or reached
/// by a caller that skipped it — and both apply the identical boundary,
/// because they call the same `charge`.
///
/// `decompressed_sum_max` is a POLICY number and this module has none:
/// the production caller passes its own constant, and only tests and
/// the fuzz probe pass another.
///
/// # Errors
/// [`BinVerifyError`], one variant per refusal.
pub fn verify_bin(bin: &[u8], decompressed_sum_max: u64) -> Result<(), BinVerifyError> {
    let entries = decode_bin(bin).map_err(BinVerifyError::Undecodable)?;
    declared_sum(bin, &entries, decompressed_sum_max)?;
    let mut expanded: u64 = 0;
    verify_grains(bin, &entries, decompressed_sum_max, &mut expanded)
}

/// The ONE boundary predicate, so the up-front pass and the running bail
/// cannot come to disagree about which side of the limit a bin is on.
///
/// `saturating_add` rather than a bare `+`: the `const _` above proves
/// no reachable input can wrap a `u64` here, and the direction saturation
/// fails in is the safe one — a saturated total is over every limit and
/// refuses.
fn charge(running: u64, unpacked_len: u32, limit: u64) -> Result<u64, BinVerifyError> {
    let next = running.saturating_add(u64::from(unpacked_len));
    if next > limit {
        return Err(BinVerifyError::DecompressedSumExceeded {
            limit,
            at_least: next,
        });
    }
    Ok(next)
}

/// The up-front pass: every frame's DECLARED length, charged in index
/// order, before a byte is expanded. Returns the bin's declared sum.
fn declared_sum(bin: &[u8], entries: &[BinIndexEntry], limit: u64) -> Result<u64, BinVerifyError> {
    let mut running: u64 = 0;
    for entry in entries {
        let frame = frame_bytes(bin, entry).map_err(BinVerifyError::Undecodable)?;
        let header = granary_core::binfmt::decode_frame_header(frame)
            .map_err(BinVerifyError::Undecodable)?;
        running = charge(running, header.unpacked_len, limit)?;
    }
    Ok(running)
}

/// The verifying loop: expand each grain and hold it to its index id,
/// charging the same running sum as it goes.
///
/// `expanded` counts the bytes this call actually DECOMPRESSED, measured
/// from what each expansion produced rather than from what its header
/// declared, and it is an out-parameter rather than a return value for
/// one reason: the number matters most on the path that returns an
/// error. "At most the limit was expanded" is a claim about a refused
/// bin, and a `Result` cannot carry it.
///
/// **The charge runs BEFORE the expansion**, from the header, so the
/// frame that would cross the limit is never decompressed. Charging
/// afterwards would still refuse the bin and still report the same
/// `at_least` — and would have expanded one whole grain past the
/// ceiling first, which on a maximal grain is eight mebibytes of work
/// the limit exists to refuse.
///
/// **ONE decompression buffer for the whole bin.** A bin holds up to
/// 65 536 frames; a fresh allocation per frame would be that many
/// allocate-and-free cycles of up to 8 MiB on unauthenticated input.
/// The buffer grows to the largest grain met and is never shrunk, and
/// `decompress_frame_into` still hands zstd a destination exactly the
/// declaration wide, so the reuse costs nothing from the decompress law.
fn verify_grains(
    bin: &[u8],
    entries: &[BinIndexEntry],
    limit: u64,
    expanded: &mut u64,
) -> Result<(), BinVerifyError> {
    let mut codec = GrainCodec::new().map_err(BinVerifyError::Codec)?;
    let mut scratch: Vec<u8> = Vec::new();
    let mut charged: u64 = 0;
    for entry in entries {
        let frame = frame_bytes(bin, entry).map_err(BinVerifyError::Undecodable)?;
        let header = granary_core::binfmt::decode_frame_header(frame)
            .map_err(BinVerifyError::Undecodable)?;
        charged = charge(charged, header.unpacked_len, limit)?;
        let grain = match codec.decompress_frame_into(frame, &mut scratch) {
            Ok(grain) => grain,
            // Every payload-shaped failure is this bin's fault and not
            // the environment's: a frame that will not expand to its own
            // declaration is a grain that is not what the index says it
            // is, which is the same verdict as a hash mismatch and the
            // same token (§13.4 binds `verify-failed` to both).
            Err(CodecError::Zstd(error)) => {
                return Err(BinVerifyError::Codec(CodecError::Zstd(error)));
            }
            Err(_payload) => return Err(BinVerifyError::GrainInvalid { id: entry.id }),
        };
        let produced = u64::try_from(grain.len()).unwrap_or(u64::MAX);
        let matches = GrainId::of(grain) == entry.id;
        *expanded = expanded.saturating_add(produced);
        if !matches {
            return Err(BinVerifyError::GrainInvalid { id: entry.id });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
