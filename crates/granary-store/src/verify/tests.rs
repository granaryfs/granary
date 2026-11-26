// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::verify` — ingest verification of a bin: bin
//! decode, grain expansion, and each grain held to the id its index
//! claims (the bin-ingest admission check, §5.1).
//!
//! Out-of-line: `granary-store`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-server`,
//! `granary-sim`), so the module's own tests move out of
//! the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{BinVerifyError, charge, declared_sum, verify_bin, verify_grains};
use granary_core::binfmt::{PackedFrame, decode_bin, encode_bin};
use granary_core::hash::GrainId;
use granary_core::testkit;

use crate::codec::GrainCodec;

/// A limit no fixture here can reach, for the rows that are not
/// about the limit.
const NO_LIMIT: u64 = u64::MAX;

fn codec() -> GrainCodec {
    GrainCodec::new().unwrap_or_else(|e| panic!("{e}"))
}

/// A bin holding `grains`, each frame addressed by its own id — a
/// bin a conforming packer emits.
fn honest_bin(grains: &[Vec<u8>]) -> Vec<u8> {
    let mut codec = codec();
    let frames: Vec<PackedFrame> = grains
        .iter()
        .map(|grain| PackedFrame {
            id: GrainId::of(grain),
            frame: codec
                .compress_grain(grain)
                .unwrap_or_else(|e| panic!("{e}")),
        })
        .collect();
    encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"))
}

/// A bin whose index entries carry ids the frames do not hash to —
/// the shape a client poisoning the deduplicated store sends, and
/// the one `BinStore::put_bin`'s own contract cannot refuse (§13.5).
fn lying_bin(grains: &[Vec<u8>], lie_at: usize) -> Vec<u8> {
    let mut codec = codec();
    let frames: Vec<PackedFrame> = grains
        .iter()
        .enumerate()
        .map(|(i, grain)| PackedFrame {
            id: if i == lie_at {
                GrainId::of(b"an id no frame in this bin hashes to")
            } else {
                GrainId::of(grain)
            },
            frame: codec
                .compress_grain(grain)
                .unwrap_or_else(|e| panic!("{e}")),
        })
        .collect();
    encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"))
}

fn grains(count: usize, len: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| testkit::fill(i as u64 + 1, len))
        .collect()
}

// -- the unit rows (§5.1's three outcomes) ---------------------------

/// A valid multi-grain bin verifies; one lying index entry is
/// `GrainInvalid` naming the id the INDEX claimed; bytes that are
/// not a bin at all are `Undecodable`.
#[test]
fn verify_bin_answers_the_three_outcomes() {
    let set = grains(4, 4096);

    assert!(
        verify_bin(&honest_bin(&set), NO_LIMIT).is_ok(),
        "a bin a conforming packer emitted must verify"
    );

    let claimed = GrainId::of(b"an id no frame in this bin hashes to");
    match verify_bin(&lying_bin(&set, 2), NO_LIMIT) {
        Err(BinVerifyError::GrainInvalid { id }) => assert_eq!(
            id, claimed,
            "the error names the id the INDEX claimed, never a hash \
             of the attacker's own bytes"
        ),
        other => panic!("a lying index entry must be GrainInvalid: {other:?}"),
    }

    // The §13.4 corpus body: 100 bytes under their own digest, which
    // `BinStore::put_bin` stores happily and this layer refuses.
    assert!(matches!(
        verify_bin(&[0x5a_u8; 100], NO_LIMIT),
        Err(BinVerifyError::Undecodable(_))
    ));

    // A frame whose PAYLOAD will not expand to its declaration is
    // the same verdict as a hash mismatch — §13.4 binds one token to
    // both — and never a `Codec` failure, which would be a `500`.
    let mut corrupt = honest_bin(&set);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let corrupt_last_byte = corrupt.clone();
    assert!(
        matches!(
            verify_bin(&corrupt_last_byte, NO_LIMIT),
            Err(BinVerifyError::GrainInvalid { .. })
        ),
        "a corrupt payload is the bin's fault, not the environment's"
    );
}

// -- the decompressed-sum bound --------------------------------------

/// **The bomb negative, and the counter that proves the saving is
/// real.** A bin whose frames' declared lengths sum past the limit
/// is refused, and NOTHING is expanded: the up-front pass reads
/// headers only.
///
/// The positive control sits beside it, because a check that refuses
/// everything would pass the negative alone.
#[test]
fn a_declared_sum_past_the_limit_is_refused_with_nothing_expanded() {
    const LEN: usize = 4096;
    let set = grains(5, LEN);
    let bin = honest_bin(&set);
    let sum = 5 * LEN as u64;

    // Under the limit: served, and everything expanded.
    assert!(verify_bin(&bin, sum).is_ok(), "the positive control");
    let entries = decode_bin(&bin).unwrap_or_else(|e| panic!("{e}"));
    let mut expanded: u64 = 0;
    assert!(verify_grains(&bin, &entries, sum, &mut expanded).is_ok());
    assert_eq!(
        expanded, sum,
        "the counter must report the whole bin on the accepting path"
    );

    // Over the limit: refused, and the counter says nothing was
    // expanded at all, because the up-front pass answered first.
    let limit = sum - 1;
    match verify_bin(&bin, limit) {
        Err(BinVerifyError::DecompressedSumExceeded {
            limit: reported,
            at_least,
        }) => {
            assert_eq!(reported, limit);
            assert!(at_least > limit, "{at_least} must be past {limit}");
        }
        other => panic!("a bin over the limit must be refused for it: {other:?}"),
    }
    assert_eq!(
        declared_sum(&bin, &entries, limit).ok(),
        None,
        "the up-front pass is what refuses, before any expansion"
    );

    // **At most the limit is EVER expanded**, asserted against the
    // running loop with the up-front pass deliberately skipped —
    // which is the state a future refactor could leave this in, and
    // the reason the running charge is not redundant.
    //
    // The COUNTER is what discriminates here and `at_least` is not:
    // a loop charging after the expansion refuses the same bin and
    // reports the same `at_least`, having decompressed one whole
    // grain past the ceiling to do it.
    let tight = 3 * LEN as u64;
    let mut spent: u64 = 0;
    match verify_grains(&bin, &entries, tight, &mut spent) {
        Err(BinVerifyError::DecompressedSumExceeded { at_least, .. }) => {
            assert!(at_least > tight);
        }
        other => panic!("the running bail must fire: {other:?}"),
    }
    assert!(
        spent <= tight,
        "{spent} bytes were expanded against a {tight}-byte ceiling: the \
         charge ran AFTER the decompression it exists to prevent"
    );
}

/// **The boundary predicate is ONE predicate.** `sum == limit` is
/// accepted and `sum == limit + 1` is refused, asserted against the
/// up-front pass and the running bail separately — a bin that passed
/// one and tripped the other would be a server whose accept set
/// depends on which check ran.
#[test]
fn the_boundary_is_the_same_in_the_up_front_pass_and_the_running_bail() {
    const LEN: usize = 1000;
    let set = grains(4, LEN);
    let bin = honest_bin(&set);
    let entries = decode_bin(&bin).unwrap_or_else(|e| panic!("{e}"));
    let sum = 4 * LEN as u64;

    // AT the limit: both accept.
    let mut expanded: u64 = 0;
    assert_eq!(declared_sum(&bin, &entries, sum).ok(), Some(sum));
    assert!(verify_grains(&bin, &entries, sum, &mut expanded).is_ok());
    assert_eq!(expanded, sum);
    assert!(verify_bin(&bin, sum).is_ok());

    // ONE byte under it — the bin is now `limit + 1` — both refuse.
    let under = sum - 1;
    assert!(matches!(
        declared_sum(&bin, &entries, under),
        Err(BinVerifyError::DecompressedSumExceeded { .. })
    ));
    let mut ignored: u64 = 0;
    assert!(matches!(
        verify_grains(&bin, &entries, under, &mut ignored),
        Err(BinVerifyError::DecompressedSumExceeded { .. })
    ));
    assert!(matches!(
        verify_bin(&bin, under),
        Err(BinVerifyError::DecompressedSumExceeded { .. })
    ));

    // And the predicate itself, at the three points that matter.
    assert_eq!(charge(0, 10, 10).ok(), Some(10), "exactly the limit fits");
    assert!(charge(0, 11, 10).is_err(), "one past it does not");
    assert_eq!(charge(9, 1, 10).ok(), Some(10), "and it is a RUNNING sum");
    assert!(charge(10, 1, 10).is_err());
}

/// The limit is a PARAMETER and this module holds no constant of its
/// own — asserted the only way a test can: the same bin answers
/// differently under two ceilings, so nothing here can be reading a
/// figure of its own.
#[test]
fn the_ceiling_is_the_callers_and_never_this_modules() {
    let set = grains(3, 2048);
    let bin = honest_bin(&set);
    assert!(verify_bin(&bin, 3 * 2048).is_ok());
    assert!(matches!(
        verify_bin(&bin, 2048),
        Err(BinVerifyError::DecompressedSumExceeded { limit: 2048, .. })
    ));
}

/// The reused buffer is not a correctness cost: a bin whose grains
/// SHRINK verifies, which is the case a buffer left long by an
/// earlier frame breaks — the hash would run over the previous
/// grain's tail.
#[test]
fn one_reused_buffer_does_not_leak_a_larger_grains_tail() {
    let set = vec![
        testkit::fill(1, 64 * 1024),
        testkit::fill(2, 8),
        testkit::fill(3, 32 * 1024),
        testkit::fill(4, 1),
    ];
    assert!(
        verify_bin(&honest_bin(&set), NO_LIMIT).is_ok(),
        "a shrinking grain sequence must verify"
    );
}
