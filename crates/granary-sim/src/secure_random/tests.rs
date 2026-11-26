// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_core::hash::GrainId;
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

use super::{BLOCK_CONTEXT, KEY_CONTEXT, SeededSecureRandom};

fn draw<const N: usize>(stream: &mut SeededSecureRandom) -> [u8; N] {
    let mut out = [0u8; N];
    stream.fill(&mut out).unwrap();
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

/// The key `for_incarnation(7, 1)` derives, written out from the
/// construction rather than through the type.
fn key_7_1() -> [u8; 32] {
    let mut preimage = KEY_CONTEXT.to_vec();
    preimage.extend_from_slice(&7u64.to_be_bytes());
    preimage.extend_from_slice(&1u32.to_be_bytes());
    *GrainId::of(&preimage).digest()
}

/// Block `index` under `key`, written out from the construction.
fn block(key: &[u8; 32], index: u64) -> [u8; 32] {
    let mut preimage = BLOCK_CONTEXT.to_vec();
    preimage.extend_from_slice(key);
    preimage.extend_from_slice(&index.to_be_bytes());
    *GrainId::of(&preimage).digest()
}

/// A fixed seed's first 48 bytes, pinned as text, and equal to the
/// construction the module documents: block 0 then the first half of
/// block 1. A change to the contexts, the field order or the block size
/// moves the pinned text; a stream that does not follow its documented
/// construction fails the second half.
#[test]
fn a_fixed_seed_gives_fixed_bytes_by_the_documented_construction() {
    let mut stream = SeededSecureRandom::for_incarnation(7, 1);
    let got: [u8; 48] = draw(&mut stream);
    let key = key_7_1();
    let mut expected = block(&key, 0).to_vec();
    expected.extend_from_slice(block(&key, 1).get(..16).unwrap());
    assert_eq!(
        (hex(&got), got.to_vec()),
        (
            "357e3a10f0d34dce9105cc469c57f924afd2fe1de27f5047fd7024a9dc69c0de\
             4f6fccad4f0eeebc9f3b5215b9828827"
                .to_owned(),
            expected
        )
    );
}

/// **Successive fills continue the stream.** Two 16-byte fills equal one
/// 32-byte fill, and 8 + 8 equals 16, from fresh streams on one seed: a
/// stream that restarted on each fill would repeat its prefix and give
/// the second fill the first's bytes.
#[test]
fn split_fills_continue_one_stream_and_never_repeat_its_prefix() {
    let whole: [u8; 32] = draw(&mut SeededSecureRandom::for_incarnation(7, 1));
    let mut halves = SeededSecureRandom::for_incarnation(7, 1);
    let first: [u8; 16] = draw(&mut halves);
    let second: [u8; 16] = draw(&mut halves);
    let mut eighths = SeededSecureRandom::for_incarnation(7, 1);
    let a: [u8; 8] = draw(&mut eighths);
    let b: [u8; 8] = draw(&mut eighths);
    assert_eq!(
        ([first, second].concat(), [a, b].concat(), first == second),
        (whole.to_vec(), whole.get(..16).unwrap().to_vec(), false)
    );
}

/// A fill that crosses a block boundary takes the next block: 20 bytes,
/// then 20 more, equal 40 drawn at once.
#[test]
fn a_fill_across_a_block_boundary_takes_the_next_block() {
    let whole: [u8; 40] = draw(&mut SeededSecureRandom::for_incarnation(7, 1));
    let mut split = SeededSecureRandom::for_incarnation(7, 1);
    let a: [u8; 20] = draw(&mut split);
    let b: [u8; 20] = draw(&mut split);
    assert_eq!([a, b].concat(), whole.to_vec());
}

/// Another replay seed, another incarnation, or another key: another
/// stream.
#[test]
fn a_different_seed_or_incarnation_gives_a_different_stream() {
    let base: [u8; 16] = draw(&mut SeededSecureRandom::for_incarnation(7, 1));
    let other_seed: [u8; 16] = draw(&mut SeededSecureRandom::for_incarnation(8, 1));
    let other_incarnation: [u8; 16] = draw(&mut SeededSecureRandom::for_incarnation(7, 2));
    let other_key: [u8; 16] = draw(&mut SeededSecureRandom::from_key([0x42; 32]));
    assert_eq!(
        (
            base == other_seed,
            base == other_incarnation,
            base == other_key
        ),
        (false, false, false),
        "{base:?} {other_seed:?} {other_incarnation:?} {other_key:?}"
    );
}

/// **The limit refuses, whole.** At 8 bytes short of 2^64 − 1 given, an
/// 8-byte fill succeeds and a further 1-byte fill refuses, writing
/// nothing and leaving the position where it was; a 9-byte fill from the
/// same start refuses too.
#[test]
fn a_fill_past_the_limit_refuses_and_writes_nothing() {
    let mut stream = SeededSecureRandom::for_incarnation(7, 1);
    stream.given = u64::MAX - 8;
    let mut over = [0xAAu8; 9];
    let refused_9 = stream.fill(&mut over);
    let mut fits = [0u8; 8];
    let fitted = stream.fill(&mut fits);
    let mut one = [0xAAu8; 1];
    let refused_1 = stream.fill(&mut one);
    assert_eq!(
        (refused_9, over, fitted, refused_1, one, stream.given),
        (
            Err(EntropyUnavailable),
            [0xAA; 9],
            Ok(()),
            Err(EntropyUnavailable),
            [0xAA; 1],
            u64::MAX
        )
    );
}
