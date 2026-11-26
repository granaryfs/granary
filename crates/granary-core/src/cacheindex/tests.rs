// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::cacheindex` — the client-cache index format v1 encode/decode/replay logic.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::rng::{Rng, SeededRng};

fn id(byte: u8) -> GrainId {
    GrainId::from_parts(HashAlgorithm::Blake3, [byte; DIGEST_LEN])
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").unwrap_or_else(|e| panic!("{e}"));
    }
    out
}

fn raw_snapshot(count: u64, entries_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(KIND_SNAPSHOT);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(entries_bytes);
    out
}

fn random_digest(rng: &mut SeededRng) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_be_bytes());
    }
    out
}

/// `[0, u32::MAX]` INCLUSIVE — `below`'s own `[0, bound)` half-open
/// contract means the bound must be `u32::MAX + 1` (widened to
/// `u64` first; it never overflows there) or the size sweep can
/// never draw the boundary value itself.
fn random_u32(rng: &mut SeededRng) -> u32 {
    u32::try_from(rng.below(u64::from(u32::MAX) + 1)).unwrap_or(u32::MAX)
}

/// `n` entries with distinct digests, in canonical (ascending)
/// order — ready to feed `encode_snapshot` directly.
fn random_sorted_entries(rng: &mut SeededRng, n: usize) -> Vec<(GrainId, u32)> {
    let mut digests = std::collections::BTreeSet::new();
    while digests.len() < n {
        digests.insert(random_digest(rng));
    }
    digests
        .into_iter()
        .map(|d| {
            (
                GrainId::from_parts(HashAlgorithm::Blake3, d),
                random_u32(rng),
            )
        })
        .collect()
}

/// The round-trip body `snapshot_roundtrips` runs for every
/// seed/size AND for the boundary sweep — extracted so the two call
/// sites cannot drift.
fn assert_snapshot_roundtrips(entries: &[(GrainId, u32)], label: &str) {
    let bytes = encode_snapshot(entries).unwrap_or_else(|e| panic!("{label}: {e}"));
    let decoded = decode_snapshot(&bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
    assert_eq!(decoded, entries, "{label}");
    let re = encode_snapshot(&decoded).unwrap_or_else(|e| panic!("{label}: {e}"));
    assert_eq!(re, bytes, "canonical form, {label}");
}

// ---------------------------------------------------- round trips
//
// proptest cannot pass core's purity gate: getrandom is denied by
// name, proc-macros are forbidden, and only blake3 =1.8.7 and libc
// have build-script exceptions. Its dependency closure exceeds those
// permissions — these two tests draw cases from SeededRng instead,
// over enough seeds/sizes to exercise ordering, duplicates and
// boundary cases.

#[test]
fn snapshot_roundtrips() {
    for seed in [0u64, 1, 42, 0xDEAD_BEEF, u64::MAX] {
        let mut rng = SeededRng::new(seed);
        for n in [0usize, 1, 2, 200] {
            let entries = random_sorted_entries(&mut rng, n);
            assert_snapshot_roundtrips(&entries, &format!("seed {seed} n {n}"));
        }
    }

    // Boundary sweep: the digest extremes ([0x00;32] before
    // [0xFF;32], in canonical order) and the size extreme
    // (u32::MAX) — a 256-bit random draw essentially never lands on
    // either boundary id by chance, so this deterministic case is
    // the only witness for them.
    let boundary_entries = vec![(id(0x00), u32::MAX), (id(0xFF), u32::MAX)];
    assert_snapshot_roundtrips(&boundary_entries, "boundary sweep");
}

#[test]
fn records_roundtrip() {
    for seed in [0u64, 1, 42, 0xDEAD_BEEF, u64::MAX] {
        let mut rng = SeededRng::new(seed);
        for n in [0usize, 1, 2, 50] {
            let mut records = Vec::with_capacity(n);
            let mut bytes = Vec::new();
            for _ in 0..n {
                let which = rng.below(3);
                let gid = GrainId::from_parts(HashAlgorithm::Blake3, random_digest(&mut rng));
                let record = match which {
                    0 => Record::Insert {
                        id: gid,
                        size: random_u32(&mut rng),
                    },
                    1 => Record::Touch { id: gid },
                    _ => Record::Evict { id: gid },
                };
                encode_record_into(&mut bytes, &record);
                records.push(record);
            }
            let (decoded, tail) = replay_journal(&bytes);
            assert_eq!(decoded, records, "seed {seed} n {n}");
            assert_eq!(tail, JournalTail::CleanEof, "seed {seed} n {n}");
            // Single-record isolation too.
            for r in &records {
                let single = encode_record(r);
                let (got, tail2) = replay_journal(&single);
                assert_eq!(got, vec![*r]);
                assert_eq!(tail2, JournalTail::CleanEof);
            }
        }
    }
}

// ----------------------------------------------------------- fold

#[test]
fn fold_is_deterministic_and_orders_by_recency() {
    let (a, b, c) = (id(1), id(2), id(3));
    let state = fold(
        Vec::new(),
        &[
            Record::Insert { id: a, size: 10 },
            Record::Insert { id: b, size: 20 },
            Record::Insert { id: c, size: 30 },
            Record::Touch { id: a },
        ],
    );
    assert_eq!(state.entries, vec![(b, 20), (c, 30), (a, 10)]);
    assert_eq!(state.total_bytes, 60);

    // Absent-id touch/evict: each is a valid no-op, never an error or panic.
    let state2 = fold(
        Vec::new(),
        &[
            Record::Insert { id: a, size: 5 },
            Record::Evict { id: a },
            Record::Touch { id: b },
            Record::Evict { id: c },
        ],
    );
    assert_eq!(state2.entries, Vec::new());
    assert_eq!(state2.total_bytes, 0);

    // Snapshot-seeded start: cold entries keep their relative
    // (id-ascending) order until a record moves them.
    let state3 = fold(vec![(a, 1), (b, 2), (c, 3)], &[Record::Touch { id: b }]);
    assert_eq!(state3.entries, vec![(a, 1), (c, 3), (b, 2)]);
    assert_eq!(state3.total_bytes, 6);
}

/// The dedup contract `fold`'s own doc pins: seeding with a REPEATED
/// id keeps the FIRST occurrence's POSITION but the LAST
/// occurrence's SIZE. This is the contract's trickiest branch, and
/// this row is also the mutation-testing witness for `fold`'s seed
/// loop.
#[test]
fn fold_duplicate_id_snapshot_keeps_first_position_and_last_size() {
    let (a, b) = (id(1), id(2));
    let state = fold(vec![(a, 1), (b, 2), (a, 99)], &[]);
    assert_eq!(
        state.entries,
        vec![(a, 99), (b, 2)],
        "a keeps FIRST position (least recent) but LAST size (99, not 1)"
    );
    assert_eq!(state.total_bytes, 101);
}

// ------------------------------------------------------- torn tail

#[test]
fn a_torn_tail_truncates_and_the_prefix_stands() {
    let (a, b) = (id(4), id(5));
    let r1 = Record::Insert { id: a, size: 100 };
    let r2 = Record::Touch { id: b };
    let mut body = encode_record(&r1);
    body.extend_from_slice(&encode_record(&r2));
    let third_start = body.len();
    // A crash mid-append: only the tag and part of the id survive.
    let full_third = encode_record(&Record::Evict { id: a });
    body.extend_from_slice(full_third.get(..10).unwrap_or_default());

    let (records, tail) = replay_journal(&body);
    assert_eq!(records, vec![r1, r2]);
    assert_eq!(tail, JournalTail::TruncatedAt(third_start));
}

#[test]
fn a_flipped_check_byte_truncates_there() {
    let (a, b, c) = (id(6), id(7), id(8));
    let r1 = Record::Insert { id: a, size: 1 };
    let r2 = Record::Touch { id: b };
    let r3 = Record::Evict { id: c };
    let mut body = encode_record(&r1);
    let second_start = body.len();
    body.extend_from_slice(&encode_record(&r2));
    let third_start = body.len();
    body.extend_from_slice(&encode_record(&r3));

    // Flip the LAST byte of r2's check — a complete-length record
    // whose integrity still fails must truncate at r2's OWN start,
    // never r1's.
    let flip_at = third_start - 1;
    if let Some(byte) = body.get_mut(flip_at) {
        *byte ^= 0xFF;
    }

    let (records, tail) = replay_journal(&body);
    assert_eq!(records, vec![r1]);
    assert_eq!(tail, JournalTail::TruncatedAt(second_start));
}

// --------------------------------------------------- snapshot rejects

#[test]
fn duplicate_and_unsorted_snapshot_ids_are_refused() {
    let lo = id(0);
    let hi = id(1);

    assert_eq!(
        encode_snapshot(&[(hi, 1), (lo, 2)]),
        Err(CacheIndexError::NotStrictlyAscending)
    );
    assert_eq!(
        encode_snapshot(&[(lo, 1), (lo, 2)]),
        Err(CacheIndexError::NotStrictlyAscending)
    );

    let mut unsorted_body = Vec::new();
    unsorted_body.extend_from_slice(hi.digest());
    unsorted_body.extend_from_slice(&1u32.to_be_bytes());
    unsorted_body.extend_from_slice(lo.digest());
    unsorted_body.extend_from_slice(&2u32.to_be_bytes());
    assert_eq!(
        decode_snapshot(&raw_snapshot(2, &unsorted_body)),
        Err(CacheIndexError::NotStrictlyAscending)
    );

    let mut duplicate_body = Vec::new();
    duplicate_body.extend_from_slice(lo.digest());
    duplicate_body.extend_from_slice(&1u32.to_be_bytes());
    duplicate_body.extend_from_slice(lo.digest());
    duplicate_body.extend_from_slice(&2u32.to_be_bytes());
    assert_eq!(
        decode_snapshot(&raw_snapshot(2, &duplicate_body)),
        Err(CacheIndexError::NotStrictlyAscending)
    );
}

#[test]
fn version_2_and_foreign_magic_are_refused() {
    let mut wrong_magic = Vec::new();
    wrong_magic.extend_from_slice(b"XXXX");
    wrong_magic.extend_from_slice(&VERSION.to_be_bytes());
    wrong_magic.push(KIND_SNAPSHOT);
    wrong_magic.extend_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        decode_snapshot(&wrong_magic),
        Err(CacheIndexError::BadMagic)
    );

    let mut wrong_version = Vec::new();
    wrong_version.extend_from_slice(&MAGIC);
    wrong_version.extend_from_slice(&2u16.to_be_bytes());
    wrong_version.push(KIND_SNAPSHOT);
    wrong_version.extend_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        decode_snapshot(&wrong_version),
        Err(CacheIndexError::UnknownVersion { version: 2 })
    );

    // A well-formed envelope of the WRONG kind — the shared-envelope
    // discipline's other half.
    let mut wrong_kind = Vec::new();
    wrong_kind.extend_from_slice(&MAGIC);
    wrong_kind.extend_from_slice(&VERSION.to_be_bytes());
    wrong_kind.push(KIND_JOURNAL);
    assert_eq!(
        decode_snapshot(&wrong_kind),
        Err(CacheIndexError::WrongKind {
            want: FileKind::Snapshot,
            got: FileKind::Journal,
        })
    );

    // The mirror: a well-formed SNAPSHOT-kind envelope handed to
    // `decode_journal` is refused too — the guard is symmetric, not
    // `decode_snapshot`'s alone. Without it, a snapshot body would
    // silently replay as an empty, all-torn journal.
    let mut snapshot_kind = Vec::new();
    snapshot_kind.extend_from_slice(&MAGIC);
    snapshot_kind.extend_from_slice(&VERSION.to_be_bytes());
    snapshot_kind.push(KIND_SNAPSHOT);
    snapshot_kind.extend_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        decode_journal(&snapshot_kind),
        Err(CacheIndexError::WrongKind {
            want: FileKind::Journal,
            got: FileKind::Snapshot,
        })
    );

    let mut unknown_kind = Vec::new();
    unknown_kind.extend_from_slice(&MAGIC);
    unknown_kind.extend_from_slice(&VERSION.to_be_bytes());
    unknown_kind.push(9);
    assert_eq!(
        decode_snapshot(&unknown_kind),
        Err(CacheIndexError::UnknownKind { kind: 9 })
    );

    // Shorter than the 7-byte envelope: Truncated, not BadMagic —
    // the magic comparison never runs.
    assert_eq!(decode_snapshot(b"GRN"), Err(CacheIndexError::Truncated));
}

#[test]
fn a_declared_count_bomb_is_refused_before_allocation() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(KIND_SNAPSHOT);
    let bomb_count = u64::MAX / 36;
    bytes.extend_from_slice(&bomb_count.to_be_bytes());
    // Pad to exactly 100 bytes total — nowhere near the ~1.8e19
    // bytes `bomb_count` entries would require. If the decoder ever
    // allocated proportionally to the DECLARED count instead of
    // checking it first, this call would abort the process (OOM)
    // instead of returning promptly with an error.
    bytes.resize(100, 0);
    let remaining = bytes.len() - ENVELOPE_LEN - COUNT_FIELD_LEN;
    assert_eq!(
        decode_snapshot(&bytes),
        Err(CacheIndexError::CountMismatch {
            declared: bomb_count,
            remaining,
        })
    );
}

/// A `checked_mul` witness the previous bomb-gate test cannot be:
/// `u64::MAX / 36`'s TRUE product does not overflow u64 (it lands
/// well under `u64::MAX`), so that test's `None` never happens —
/// only the "computed fine, just doesn't match `remaining`" arm
/// runs, and a `wrapping_mul` mutant survives it. This count is
/// engineered so a WRAPPING product lands on exactly 36:
/// `(1 + 2^62) * 36 mod 2^64 == 36`, the same value a genuine
/// one-entry, 36-byte body presents as `remaining` — under
/// `wrapping_mul` this would falsely MATCH and fall through the
/// bomb gate entirely. `checked_mul` must return `None` here (the
/// true product is ~1.66e20, vastly over `u64::MAX`), refused the
/// same `CountMismatch` way the `None` arm always is.
#[test]
fn a_wrapping_count_bomb_is_refused() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(KIND_SNAPSHOT);
    let wrapping_count = 1u64 + (1u64 << 62);
    bytes.extend_from_slice(&wrapping_count.to_be_bytes());
    // Exactly SNAPSHOT_ENTRY_LEN (36) bytes remaining after the
    // envelope + count field — the body a wrapped-to-36 product
    // would wrongly claim to match.
    bytes.resize(bytes.len() + SNAPSHOT_ENTRY_LEN, 0);
    assert_eq!(
        decode_snapshot(&bytes),
        Err(CacheIndexError::CountMismatch {
            declared: wrapping_count,
            remaining: SNAPSHOT_ENTRY_LEN,
        })
    );
}

// ------------------------------------------------------ golden vectors
//
// Committed hex fixtures, byte-for-byte asserted (format-object
// discipline). A drift here is a FORMAT EVENT, never a refactor
// side effect.

/// One snapshot: three entries with fixed digests `[0x11;32]`,
/// `[0x22;32]`, `[0x33;32]` and sizes 1, 2, 3.
const SNAPSHOT_GOLDEN_HEX: &str = "47524e490001010000000000000003\
1111111111111111111111111111111111111111111111111111111111111111\
00000001\
2222222222222222222222222222222222222222222222222222222222222222\
00000002\
3333333333333333333333333333333333333333333333333333333333333333\
00000003";

#[test]
fn snapshot_golden_vector_is_pinned() {
    let entries = vec![(id(0x11), 1u32), (id(0x22), 2u32), (id(0x33), 3u32)];
    let bytes = encode_snapshot(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(hex_encode(&bytes), SNAPSHOT_GOLDEN_HEX);
    let decoded = decode_snapshot(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decoded, entries);
}

/// One journal: envelope + an Insert(`[0x44;32]`, size 7) record +
/// a Touch(`[0x55;32]`) record + a TORN third record (only the tag
/// and 4 digest bytes of an Evict(`[0x66;32]`) survive).
const JOURNAL_GOLDEN_HEX: &str = "47524e4900010201444444444444444444444444444444444444444444444444444444444444444400000007\
98776b490255555555555555555555555555555555555555555555555555555555555555\
55ed887ad10366666666";

#[test]
fn journal_golden_vector_with_torn_tail_is_pinned() {
    let insert = Record::Insert {
        id: id(0x44),
        size: 7,
    };
    let touch = Record::Touch { id: id(0x55) };
    let torn_source = Record::Evict { id: id(0x66) };

    let mut body = encode_record(&insert);
    body.extend_from_slice(&encode_record(&touch));
    let third_start = body.len();
    let full_third = encode_record(&torn_source);
    body.extend_from_slice(full_third.get(..5).unwrap_or_default());

    let mut full = Vec::new();
    full.extend_from_slice(&MAGIC);
    full.extend_from_slice(&VERSION.to_be_bytes());
    full.push(KIND_JOURNAL);
    full.extend_from_slice(&body);

    assert_eq!(hex_encode(&full), JOURNAL_GOLDEN_HEX);

    let (kind, opened_body) = open_index_envelope(&full).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(kind, FileKind::Journal);
    let (records, tail) = replay_journal(opened_body);
    assert_eq!(records, vec![insert, touch]);
    assert_eq!(tail, JournalTail::TruncatedAt(third_start));

    // decode_journal end to end: the same result via the guarded
    // entry point.
    let (records2, tail2) = decode_journal(&full).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(records2, vec![insert, touch]);
    assert_eq!(tail2, JournalTail::TruncatedAt(third_start));
}
