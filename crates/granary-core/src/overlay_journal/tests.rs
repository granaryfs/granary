// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::overlay_journal`.

use super::scan::record_check;
use super::*;
use crate::hash::{DIGEST_LEN, HashAlgorithm};
use crate::manifest::{Name, NameError, SymlinkTarget, SymlinkTargetError};

mod commit_progress;
mod fix_round_1;
mod projected_boundary;
mod recreate_file;
mod residual_disposition;

/// Only tests collect records; production replay visits them as they arrive.
#[derive(Debug)]
struct CollectedScan {
    scan: JournalScan,
    records: Vec<Record>,
}

impl std::ops::Deref for CollectedScan {
    type Target = JournalScan;
    fn deref(&self) -> &Self::Target {
        &self.scan
    }
}

fn scan_journal(bytes: &[u8]) -> Result<CollectedScan, Fence> {
    let mut records = Vec::new();
    let scan = scan_journal_with(bytes, |_, record| records.push(record.clone()))?;
    Ok(CollectedScan { scan, records })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn grain(n: u8) -> GrainId {
    GrainId::from_parts(HashAlgorithm::Blake3, [n; DIGEST_LEN])
}

fn name(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).unwrap()
}

fn loc(parents: &[&str], leaf: &str) -> Location {
    Location {
        parent: Parent::new(parents.iter().map(|p| name(p)).collect()).unwrap(),
        name: name(leaf),
    }
}

fn header() -> JournalHeader {
    JournalHeader {
        writer: [0x11; 16],
        base_root: grain(0xAA),
        base_seq: 7,
        next_stage_id: 1,
        receipt_generation: 0,
    }
}

fn golden_records() -> Vec<Record> {
    vec![
        Record::Create {
            at: loc(&[], "d"),
            kind: CreateKind::Dir,
        },
        Record::Create {
            at: loc(&["d"], "f"),
            kind: CreateKind::File {
                exec: false,
                stage_id: 1,
            },
        },
        Record::WriteExtent {
            stage_id: 1,
            offset: 0,
            length: 5,
            check: extent_check(1, 0, b"hello"),
        },
        Record::FileSynced {
            stage_id: 1,
            synced_size: 5,
            content: grain(0xC1),
            generation: 1,
            prepared_root: grain(0xD1),
        },
        Record::Move {
            from: loc(&["d"], "f"),
            to: loc(&[], "g"),
        },
        Record::CommitBoundary {
            candidate: grain(0xE1),
            through_seq: 5,
            publication_id: [0x22; 16],
        },
    ]
}

const HEADER_HEX: &str = "47524e4f564a524e000100001111111111111111111111111111111101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000700000000000000010000000000000000327e7684ad78b3edac0548d81fd331fb04222a923b46446f59246ba6436b5ff3";
const JOURNAL_HEX: &str = "47524e4f564a524e000100001111111111111111111111111111111101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000700000000000000010000000000000000327e7684ad78b3edac0548d81fd331fb04222a923b46446f59246ba6436b5ff30000003701000000000000000100000164020000000000000000001dab9cdc593b42fefa88e700198d1663b5d486d4aaa2f548b3134f8f1068b28d0000003901000000000000000200010164016601000000000000000001ee4826a5ca7797372300da72c386aed4744d51c7f8bd0ee4c8613a9a909532c800000061030000000000000003000000000000000100000000000000000000000000000005801a5e6259a2a9cfa7b9bdaccf5b91c7c6f55b2fa148024efa94f61edfb7ec07b9f5a120853002412cb44db821ae326d8774f0bcf86f1528354be55fee9b703b000000830900000000000000040000000000000001000000000000000501c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1000000000000000101d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1dd6a42bea904dda2a107e25f4a631b6936e6fe766fb80d01c5efc989ff4335900000003305000000000000000500010164016600000167e42992d22e5e02b3606819e303600cdeaca35bd5999477fe231759b0e7ea34bb000000620b000000000000000601e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1000000000000000522222222222222222222222222222222a4d12288fb7854261acdeb9ac4fff71ec1c71b898c337f49aed83eb89560416d";
const WRITER_HEX: &str = "47524e4f565749440001000033333333333333333333333333333333000000000000004005766f6c2d61662b720d723bbe0fb0591bbea9e4ddb30b6ed9d7e1264a8d8b916ed2d07a97c7";
const STAGING_ABSENT_HEX: &str = "47524e4f5653544700010000111111111111111111111111111111110000000000000001e2d7c9270953bd2770a65f52a50d71de109c81d7f6dd76e6504ff9816f841db50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const STAGING_MARK_HEX: &str = "47524e4f5653544700010000111111111111111111111111111111110000000000000001e2d7c9270953bd2770a65f52a50d71de109c81d7f6dd76e6504ff9816f841db5000000000000000501c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c100000000000000010100adef7e454c74fce504a9b1f23015a069d351b6f49eb56e8374f61f36bda50000000000000000000000";

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn flip(bytes: &[u8], byte: usize, bit: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[byte] ^= 1 << bit;
    out
}

fn golden_journal() -> Vec<u8> {
    unhex(JOURNAL_HEX)
}

/// The start offset of every frame of `records` under `h`, then the end.
fn frame_bounds(h: &JournalHeader, records: &[Record]) -> Vec<usize> {
    let mut at = JOURNAL_HEADER_LEN;
    let mut out = vec![at];
    for (i, r) in records.iter().enumerate() {
        at += encode_record(h, i as u64 + 1, r).unwrap().len();
        out.push(at);
    }
    out
}

/// A frame whose check is valid for `h` whatever `kind`, `seq` and `payload`
/// say, so a test can be wrong in exactly one way.
fn raw_frame(h: &JournalHeader, kind: u8, seq: u64, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len() + 41).unwrap();
    let mut out = len.to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&record_check(&h.check(), len, kind, seq, payload));
    out
}

fn journal_with_frame(h: &JournalHeader, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = h.encode().unwrap();
    for f in frames {
        out.extend_from_slice(f);
    }
    out
}

// ---- constants -------------------------------------------------------

#[test]
fn bounds_have_their_documented_values() {
    assert_eq!(JOURNAL_HEADER_LEN, 117);
    assert_eq!(LEN_MIN, 41);
    assert_eq!(LEN_MAX, 16425);
    assert_eq!(PAYLOAD_MAX, 16384);
    assert_eq!(JOURNAL_MAX, 67_108_864);
    assert_eq!(PATH_DEPTH_MAX, 128);
    assert_eq!(PATH_BYTES_MAX, 4096);
    assert_eq!(SIZE_MAX, 9_223_372_036_854_775_807);
    assert_eq!(STAGE_ID_MAX, 9_223_372_036_854_775_807);
    assert_eq!(EXTENT_LEN_MAX, 8_388_608);
    assert_eq!(GENERATION_MAX, 18_446_744_073_709_551_614);
    assert_eq!(STAGING_HEADER_LEN, 160);
    assert_eq!(STAGING_MARK_LEN, 81);
}

// ---- goldens ---------------------------------------------------------

#[test]
fn journal_header_golden() {
    let bytes = header().encode().unwrap();
    assert_eq!(hex(&bytes), HEADER_HEX);
    assert_eq!(JournalHeader::decode(&unhex(HEADER_HEX)), Ok(header()));
}

#[test]
fn journal_golden_scans_clean_and_re_encodes() {
    let bytes = encode_journal(&header(), &golden_records()).unwrap();
    assert_eq!(hex(&bytes), JOURNAL_HEX);
    let scan = scan_journal(&golden_journal()).unwrap();
    assert_eq!(scan.records, golden_records());
    assert_eq!(scan.header, header());
    assert_eq!(scan.valid_len, golden_journal().len());
    assert_eq!(scan.end, JournalEnd::Clean);
    assert_eq!(scan.state.next_seq(), 7);
    assert_eq!(scan.state.next_stage_id(), 2);
    assert_eq!(scan.state.highest_generation(), 1);
    assert_eq!(
        scan.state.stage(1),
        Some(&StageState {
            size: 5,
            synced_size: Some(5),
            bound_at: 2,
        })
    );
    assert_eq!(scan.state.open_boundaries().collect::<Vec<_>>(), vec![6]);
}

#[test]
fn writer_golden() {
    let record = WriterRecord {
        writer: [0x33; 16],
        ceiling: 64,
        volume: VolumeName::new("vol-a".to_owned()).unwrap(),
    };
    assert_eq!(hex(&record.encode().unwrap()), WRITER_HEX);
    assert_eq!(WriterRecord::decode(&unhex(WRITER_HEX)), Ok(record));
}

#[test]
fn staging_header_goldens() {
    let absent = StagingHeader {
        writer: [0x11; 16],
        stage_id: 1,
        mark: MarkState::Absent,
    };
    let marked = StagingHeader {
        mark: MarkState::Present(SyncedMark {
            synced_size: 5,
            content: grain(0xC1),
            generation: 1,
        }),
        ..absent
    };
    assert_eq!(hex(&absent.encode().unwrap()), STAGING_ABSENT_HEX);
    assert_eq!(hex(&marked.encode().unwrap()), STAGING_MARK_HEX);
    assert_eq!(
        StagingHeader::decode(&unhex(STAGING_ABSENT_HEX)),
        Ok(absent)
    );
    assert_eq!(StagingHeader::decode(&unhex(STAGING_MARK_HEX)), Ok(marked));
}

fn min_records() -> Vec<Record> {
    let a = || loc(&[], "a");
    let b = || loc(&[], "b");
    vec![
        Record::Create {
            at: a(),
            kind: CreateKind::File {
                exec: false,
                stage_id: 1,
            },
        },
        Record::StageBind {
            at: a(),
            cause: BindCause::CopyUp,
            stage_id: 1,
            staged_size: 0,
            base_content: grain(1),
        },
        Record::WriteExtent {
            stage_id: 1,
            offset: 0,
            length: 1,
            check: [0; 32],
        },
        Record::Truncate {
            stage_id: 1,
            new_size: 0,
        },
        Record::Move { from: a(), to: b() },
        Record::Replace { from: a(), to: b() },
        Record::Delete {
            at: a(),
            kind: DeleteKind::File { stage_id: None },
        },
        Record::SetattrExec {
            at: a(),
            exec: true,
        },
        Record::FileSynced {
            stage_id: 1,
            synced_size: 0,
            content: grain(1),
            generation: 1,
            prepared_root: grain(2),
        },
        Record::IntentRegistered {
            generation: 1,
            prepared_root: grain(2),
            cause: IntentCause::DirectorySync,
        },
        Record::CommitBoundary {
            candidate: grain(1),
            through_seq: 0,
            publication_id: [0; 16],
        },
        Record::LandedCommit {
            boundary_seq: 1,
            landed_root: grain(1),
            landed_seq: 2,
        },
        Record::CommitAttempt {
            boundary_seq: 1,
            publication_id: [0; 16],
            attempt: 1,
        },
        Record::CommitFence {
            boundary_seq: 1,
            publication_id: [0; 16],
        },
        Record::ProjectedBoundary {
            candidate: grain(1),
            through_seq: 0,
            publication_id: [0; 16],
            selection: None,
        },
        Record::RecreateFile {
            at: None,
            exec: false,
            stage_id: 1,
            anchor: None,
        },
        Record::ResidualDisposition(ResidualDisposition {
            boundary_seq: 1,
            publication_id: [0; 16],
            landed_root: grain(1),
            landed_seq: 2,
            source_end: 0,
            disposition: ResidualMode::KeepLocal,
            collision_count: 1,
            inventory_check: [0; 32],
        }),
        Record::StageRollback {
            stage_id: 1,
            old_size: 0,
            anchor: None,
            discarded_bytes: 0,
        },
    ]
}

/// The payload of each kind at its smallest shape, kinds 1 to 18.
const MIN_PAYLOAD_HEX: [&str; 18] = [
    "0000016101000000000000000001",
    "000001610100000000000000010000000000000000010101010101010101010101010101010101010101010101010101010101010101",
    "0000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000010000000000000000",
    "0000016100000162",
    "0000016100000162",
    "00000161010000000000000000",
    "0000016101",
    "000000000000000100000000000000000101010101010101010101010101010101010101010101010101010101010101010000000000000001010202020202020202020202020202020202020202020202020202020202020202",
    "000000000000000101020202020202020202020202020202020202020202020202020202020202020201",
    "010101010101010101010101010101010101010101010101010101010101010101000000000000000000000000000000000000000000000000",
    "00000000000000010101010101010101010101010101010101010101010101010101010101010101010000000000000002",
    "0000000000000001000000000000000000000000000000000000000000000001",
    "000000000000000100000000000000000000000000000000",
    "0101010101010101010101010101010101010101010101010101010101010101010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000001000000000000000000000000000000000101010101010101010101010101010101010101010101010101010101010101010000000000000002000000000000000001000000010000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
];

#[test]
fn each_kind_at_its_minimum_matches_its_golden_payload() {
    let records = min_records();
    assert_eq!(records.len(), 18);
    for (record, want) in records.iter().zip(MIN_PAYLOAD_HEX) {
        let kind = record.kind();
        let payload = record.encode_payload().unwrap();
        assert_eq!((kind, hex(&payload)), (kind, want.to_owned()));
        assert_eq!(Record::decode_payload(kind, &payload).as_ref(), Ok(record));
    }
    let kinds: Vec<u8> = records.iter().map(Record::kind).collect();
    assert_eq!(kinds, (1..=18).collect::<Vec<u8>>());
}

fn long_parent() -> Parent {
    // 128 names of 32 bytes: the depth and the byte bound both at their limits.
    Parent::new(
        (0..128)
            .map(|i| Name::new(format!("{i:03}{}", "x".repeat(29)).into_bytes()).unwrap())
            .collect(),
    )
    .unwrap()
}

fn long_loc() -> Location {
    Location {
        parent: long_parent(),
        name: Name::new(vec![b'n'; 255]).unwrap(),
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "one record per kind at its maximum")]
fn each_kind_at_its_maximum_round_trips_within_the_payload_bound() {
    let big = SIZE_MAX;
    let records = vec![
        Record::Create {
            at: long_loc(),
            kind: CreateKind::Symlink {
                target: SymlinkTarget::new(vec![b't'; 4096]).unwrap(),
            },
        },
        Record::Create {
            at: long_loc(),
            kind: CreateKind::File {
                exec: true,
                stage_id: STAGE_ID_MAX,
            },
        },
        Record::StageBind {
            at: long_loc(),
            cause: BindCause::Rebind,
            stage_id: STAGE_ID_MAX,
            staged_size: big,
            base_content: grain(0xFF),
        },
        Record::WriteExtent {
            stage_id: STAGE_ID_MAX,
            offset: big - EXTENT_LEN_MAX,
            length: EXTENT_LEN_MAX,
            check: [0xFF; 32],
        },
        Record::Truncate {
            stage_id: STAGE_ID_MAX,
            new_size: big,
        },
        Record::Move {
            from: long_loc(),
            to: long_loc(),
        },
        Record::Replace {
            from: long_loc(),
            to: long_loc(),
        },
        Record::Delete {
            at: long_loc(),
            kind: DeleteKind::File {
                stage_id: Some(STAGE_ID_MAX),
            },
        },
        Record::SetattrExec {
            at: long_loc(),
            exec: true,
        },
        // 0x8000000000000001 is a large positive generation, never a sign.
        Record::FileSynced {
            stage_id: STAGE_ID_MAX,
            synced_size: big,
            content: grain(0xFF),
            generation: 0x8000_0000_0000_0001,
            prepared_root: grain(0xFF),
        },
        Record::IntentRegistered {
            generation: GENERATION_MAX,
            prepared_root: grain(0xFF),
            cause: IntentCause::LandedRefresh,
        },
        Record::CommitBoundary {
            candidate: grain(0xFF),
            through_seq: u64::MAX,
            publication_id: [0xFF; 16],
        },
        Record::LandedCommit {
            boundary_seq: u64::MAX,
            landed_root: grain(0xFF),
            landed_seq: GENERATION_MAX,
        },
        Record::CommitAttempt {
            boundary_seq: u64::MAX,
            publication_id: [255; 16],
            attempt: u64::MAX,
        },
        Record::CommitFence {
            boundary_seq: u64::MAX,
            publication_id: [255; 16],
        },
        Record::ProjectedBoundary {
            candidate: grain(0xFF),
            through_seq: u64::MAX,
            publication_id: [0xFF; 16],
            selection: Some(ProjectedSelection {
                stage_id: STAGE_ID_MAX,
                content: grain(0xFF),
                size: SIZE_MAX,
            }),
        },
        Record::RecreateFile {
            at: Some(long_loc()),
            exec: true,
            stage_id: STAGE_ID_MAX,
            anchor: Some(RecreateAnchor {
                content: grain(0xFF),
                size: SIZE_MAX,
            }),
        },
        Record::ResidualDisposition(ResidualDisposition {
            boundary_seq: u64::MAX,
            publication_id: [255; 16],
            landed_root: grain(255),
            landed_seq: u64::MAX - 1,
            source_end: u64::MAX,
            disposition: ResidualMode::KeepRemote,
            collision_count: u32::MAX,
            inventory_check: [255; 32],
        }),
        Record::StageRollback {
            stage_id: STAGE_ID_MAX,
            old_size: SIZE_MAX,
            anchor: Some(RecreateAnchor {
                content: grain(255),
                size: SIZE_MAX,
            }),
            discarded_bytes: u64::MAX,
        },
    ];
    let mut widest = 0;
    for record in &records {
        let payload = record.encode_payload().unwrap();
        widest = widest.max(payload.len());
        assert!(payload.len() <= PAYLOAD_MAX, "{record:?}");
        assert_eq!(
            Record::decode_payload(record.kind(), &payload).as_ref(),
            Ok(record)
        );
    }
    // The widest record (two maximal paths) fits in 16 KiB with room to spare.
    assert!(widest > 8000 && widest < PAYLOAD_MAX, "widest {widest}");
}

#[test]
fn stage_rollback_payload_limits_are_golden_with_and_without_an_anchor() {
    for (stage_id, old_size, anchor, discarded_bytes, expected) in [
        (
            1,
            0,
            None,
            0,
            "000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            1,
            0,
            Some(RecreateAnchor {
                content: grain(0),
                size: 0,
            }),
            0,
            "000000000000000100000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            STAGE_ID_MAX,
            SIZE_MAX,
            None,
            u64::MAX,
            "7fffffffffffffff7fffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff",
        ),
        (
            STAGE_ID_MAX,
            SIZE_MAX,
            Some(RecreateAnchor {
                content: grain(255),
                size: SIZE_MAX,
            }),
            u64::MAX,
            "7fffffffffffffff7fffffffffffffff0101ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffff",
        ),
    ] {
        let record = Record::StageRollback {
            stage_id,
            old_size,
            anchor,
            discarded_bytes,
        };
        let bytes = record.encode_payload().unwrap();
        assert_eq!(
            (
                record.kind(),
                record.is_sync_class(),
                bytes.len(),
                hex(&bytes)
            ),
            (18, true, 66, expected.to_owned())
        );
        assert_eq!(Record::decode_payload(18, &bytes), Ok(record));
    }
}

// ---- reject vectors --------------------------------------------------

fn set(bytes: &[u8], at: usize, with: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at..at + with.len()].copy_from_slice(with);
    out
}

/// The writer record with `edit` applied to its body and a correct check.
fn writer_checked(edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = unhex(WRITER_HEX);
    body.truncate(body.len() - 32);
    edit(&mut body);
    let check = blake3::derive_key(WRITER_CONTEXT, &body);
    body.extend_from_slice(&check);
    body
}

#[test]
fn writer_record_reject_vectors() {
    let good = unhex(WRITER_HEX);
    let with_volume = |volume: &[u8], declared: u8| {
        writer_checked(|b| {
            b.truncate(8 + 2 + 2 + 16 + 8);
            b.push(declared);
            b.extend_from_slice(volume);
        })
    };
    let cases: Vec<(&str, Vec<u8>, WriterError)> = vec![
        ("magic", set(&good, 0, b"GRNOVXXX"), WriterError::BadMagic),
        (
            "short",
            good[..68].to_vec(),
            WriterError::BadLength { len: 68 },
        ),
        (
            "long",
            [WRITER_MAGIC.to_vec(), vec![0; 70 + 255 - 8]].concat(),
            WriterError::BadLength { len: 325 },
        ),
        ("check", flip(&good, 20, 0), WriterError::BadCheck),
        (
            "version",
            writer_checked(|b| b[9] = 2),
            WriterError::UnknownVersion { version: 2 },
        ),
        (
            "flags",
            writer_checked(|b| b[11] = 1),
            WriterError::NonZeroFlags { flags: 1 },
        ),
        (
            "ceiling max",
            writer_checked(|b| b[28..36].copy_from_slice(&u64::MAX.to_be_bytes())),
            WriterError::CeilingOutOfRange { ceiling: u64::MAX },
        ),
        (
            "volume shorter than declared",
            with_volume(b"vol-a", 6),
            WriterError::VolumeLengthMismatch {
                declared: 6,
                present: 5,
            },
        ),
        (
            "volume longer than declared",
            with_volume(b"vol-ab", 5),
            WriterError::VolumeLengthMismatch {
                declared: 5,
                present: 6,
            },
        ),
        (
            "volume of 64 bytes",
            with_volume(&[b'a'; 64], 64),
            WriterError::BadVolume(VolumeNameError::TooLong { len: 64 }),
        ),
        (
            "volume empty",
            with_volume(b"", 0),
            WriterError::BadVolume(VolumeNameError::Empty),
        ),
        (
            "volume uppercase",
            with_volume(b"Vol", 3),
            WriterError::BadVolume(VolumeNameError::BadByte { byte: b'V' }),
        ),
        (
            "volume leading dash",
            with_volume(b"-vol", 4),
            WriterError::BadVolume(VolumeNameError::LeadingDash),
        ),
    ];
    assert!(cases.len() >= 13);
    for (what, bytes, want) in cases {
        assert_eq!(WriterRecord::decode(&bytes), Err(want), "{what}");
    }
    // The all-zero identity and both ceiling extremes are legal.
    for (writer, ceiling) in [([0; 16], 0), ([0; 16], GENERATION_MAX), ([9; 16], 1)] {
        let record = WriterRecord {
            writer,
            ceiling,
            volume: VolumeName::new("v".repeat(63)).unwrap(),
        };
        let bytes = record.encode().unwrap();
        assert_eq!(WriterRecord::decode(&bytes), Ok(record));
    }
    let max = WriterRecord {
        writer: [0; 16],
        ceiling: u64::MAX,
        volume: VolumeName::new("v".to_owned()).unwrap(),
    };
    assert_eq!(
        max.encode(),
        Err(WriterError::CeilingOutOfRange { ceiling: u64::MAX })
    );
}

/// The header with `edit` applied to its first 85 bytes and a correct check.
fn header_checked(edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = unhex(HEADER_HEX);
    body.truncate(85);
    edit(&mut body);
    let check = blake3::derive_key(HEADER_CONTEXT, &body);
    body.extend_from_slice(&check);
    body
}

#[test]
fn journal_header_reject_vectors() {
    let good = unhex(HEADER_HEX);
    let put = |at: usize, v: u64| {
        header_checked(move |b| b[at..at + 8].copy_from_slice(&v.to_be_bytes()))
    };
    let cases: Vec<(&str, Vec<u8>, HeaderError)> = vec![
        ("magic", set(&good, 7, b"X"), HeaderError::BadMagic),
        (
            "short",
            good[..116].to_vec(),
            HeaderError::BadLength { len: 116 },
        ),
        (
            "long",
            [good.clone(), vec![0]].concat(),
            HeaderError::BadLength { len: 118 },
        ),
        ("check", flip(&good, 30, 3), HeaderError::BadCheck),
        (
            "version",
            header_checked(|b| b[9] = 2),
            HeaderError::UnknownVersion { version: 2 },
        ),
        (
            "flags",
            header_checked(|b| b[11] = 1),
            HeaderError::NonZeroFlags { flags: 1 },
        ),
        (
            "base root algorithm",
            header_checked(|b| b[28] = 0),
            HeaderError::BadGrainId,
        ),
        (
            "base seq 0",
            put(61, 0),
            HeaderError::BaseSeqOutOfRange { base_seq: 0 },
        ),
        (
            "base seq max-1",
            put(61, u64::MAX - 1),
            HeaderError::BaseSeqOutOfRange {
                base_seq: u64::MAX - 1,
            },
        ),
        (
            "next stage id 0",
            put(69, 0),
            HeaderError::NextStageIdOutOfRange { next_stage_id: 0 },
        ),
        (
            "next stage id 2^63+1",
            put(69, (1 << 63) + 1),
            HeaderError::NextStageIdOutOfRange {
                next_stage_id: (1 << 63) + 1,
            },
        ),
        (
            "receipt max",
            put(77, u64::MAX),
            HeaderError::ReceiptGenerationOutOfRange {
                generation: u64::MAX,
            },
        ),
    ];
    assert!(cases.len() >= 12);
    for (what, bytes, want) in cases {
        assert_eq!(JournalHeader::decode(&bytes), Err(want), "{what}");
        if bytes.len() > JOURNAL_HEADER_LEN {
            // The scan reads the first 117 bytes; the rest is a tail.
            continue;
        }
        // A bad header is never a tear: the scan fences at byte 0.
        let fence = scan_journal(&bytes).unwrap_err();
        assert_eq!(
            (fence.offset, fence.reason),
            (0, FenceReason::Header(want)),
            "{what}"
        );
    }
    // The bounds themselves are legal: base seq max-2, next stage id 2^63.
    for edit in [
        put(61, u64::MAX - 2),
        put(69, 1 << 63),
        put(77, GENERATION_MAX),
    ] {
        assert!(JournalHeader::decode(&edit).is_ok());
    }
    assert_eq!(
        scan_journal(&[]).unwrap_err().reason,
        FenceReason::Header(HeaderError::BadLength { len: 0 })
    );
}

#[test]
fn journal_above_its_bound_is_fenced_not_read() {
    let mut big = golden_journal();
    big.resize(JOURNAL_MAX + 1, 0);
    let fence = scan_journal(&big).unwrap_err();
    assert_eq!(
        (fence.offset, fence.reason),
        (
            0,
            FenceReason::TooLarge {
                len: JOURNAL_MAX + 1
            }
        )
    );
    // Exactly at the bound the same bytes are a tail, not a refusal.
    big.truncate(JOURNAL_MAX);
    assert!(scan_journal(&big).is_ok_and(|s| matches!(s.end, JournalEnd::Torn(_))));
}

/// The staging header with `edit` applied to its first 36 bytes and a
/// correct identity check, over `rest` as the remaining 124 bytes.
fn staging_checked(edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut identity = unhex(STAGING_ABSENT_HEX)[..36].to_vec();
    edit(&mut identity);
    let check = blake3::derive_key(STAGING_CONTEXT, &identity);
    identity.extend_from_slice(&check);
    identity.resize(STAGING_HEADER_LEN, 0);
    identity
}

/// A mark block for `fields` (size, content id, generation) whose own check
/// is correct for the header `identity`.
fn mark_block(identity_check: &[u8], fields: &[u8]) -> Vec<u8> {
    let check = StagingHeader::mark_check(identity_check.try_into().unwrap(), fields);
    [fields, &check].concat()
}

#[test]
fn staging_header_reject_vectors() {
    let good = unhex(STAGING_ABSENT_HEX);
    let marked = unhex(STAGING_MARK_HEX);
    let mut bad_gen = 0u64.to_be_bytes().to_vec();
    let mut fields = 5u64.to_be_bytes().to_vec();
    fields.extend_from_slice(&grain(0xC1).to_bytes());
    fields.append(&mut bad_gen);
    let mut out_of_range = good.clone();
    out_of_range[68..149].copy_from_slice(&mark_block(&good[36..68], &fields));
    let cases: Vec<(&str, Vec<u8>, StagingError)> = vec![
        ("magic", set(&good, 0, b"X"), StagingError::BadMagic),
        (
            "short",
            good[..159].to_vec(),
            StagingError::BadLength { len: 159 },
        ),
        (
            "long",
            [good.clone(), vec![0]].concat(),
            StagingError::BadLength { len: 161 },
        ),
        (
            "identity check",
            flip(&good, 40, 0),
            StagingError::BadIdentityCheck,
        ),
        (
            "version",
            staging_checked(|b| b[9] = 2),
            StagingError::UnknownVersion { version: 2 },
        ),
        (
            "flags",
            staging_checked(|b| b[11] = 1),
            StagingError::NonZeroFlags { flags: 1 },
        ),
        (
            "stage id 0",
            staging_checked(|b| b[28..36].copy_from_slice(&0u64.to_be_bytes())),
            StagingError::StageIdOutOfRange { stage_id: 0 },
        ),
        (
            "stage id 2^63",
            staging_checked(|b| b[28..36].copy_from_slice(&(1u64 << 63).to_be_bytes())),
            StagingError::StageIdOutOfRange { stage_id: 1 << 63 },
        ),
        (
            "padding",
            set(&marked, 159, &[1]),
            StagingError::NonZeroPadding,
        ),
        (
            "mark generation 0 under a valid check",
            out_of_range,
            StagingError::MarkOutOfRange,
        ),
    ];
    assert!(cases.len() >= 10);
    for (what, bytes, want) in cases {
        assert_eq!(StagingHeader::decode(&bytes), Err(want), "{what}");
    }
}

#[test]
fn staging_mark_is_absent_damaged_or_valid_and_bound_to_its_file() {
    let marked = unhex(STAGING_MARK_HEX);
    // A torn or flipped mark is damaged: neither absent nor valid.
    for byte in 68..149 {
        let h = StagingHeader::decode(&flip(&marked, byte, 0)).unwrap();
        assert_eq!(h.mark, MarkState::Damaged, "byte {byte}");
    }
    // Half a mark written over an absent one is damaged too.
    let mut half = unhex(STAGING_ABSENT_HEX);
    half[68..100].copy_from_slice(&marked[68..100]);
    assert_eq!(
        StagingHeader::decode(&half).unwrap().mark,
        MarkState::Damaged
    );
    // A damaged mark cannot be written back.
    let damaged = StagingHeader {
        mark: MarkState::Damaged,
        ..StagingHeader::decode(&marked).unwrap()
    };
    assert_eq!(damaged.encode(), Err(StagingError::DamagedMarkNotEncodable));
    // The same mark block moved into another stage's header does not verify:
    // its check covers the identity check of the header it was written in.
    let other = StagingHeader {
        writer: [0x11; 16],
        stage_id: 2,
        mark: MarkState::Absent,
    }
    .encode()
    .unwrap();
    let mut moved = other.clone();
    moved[68..149].copy_from_slice(&marked[68..149]);
    assert_eq!(
        StagingHeader::decode(&moved).unwrap().mark,
        MarkState::Damaged
    );
    // And the same block in its own header is valid.
    assert!(matches!(
        StagingHeader::decode(&marked).unwrap().mark,
        MarkState::Present(_)
    ));
}

#[test]
fn staging_header_binding_names_which_side_differs() {
    let h = StagingHeader::decode(&unhex(STAGING_MARK_HEX)).unwrap();
    assert_eq!(h.check_binding(&[0x11; 16], 1), Ok(()));
    assert_eq!(
        h.check_binding(&[0x12; 16], 1),
        Err(BindingError::WriterMismatch)
    );
    assert_eq!(
        h.check_binding(&[0x11; 16], 2),
        Err(BindingError::StageIdMismatch)
    );
}

#[test]
fn extent_check_binds_stage_offset_length_and_bytes() {
    let base = extent_check(1, 4096, b"hello");
    assert_ne!(base, extent_check(2, 4096, b"hello"), "stage id");
    assert_ne!(base, extent_check(1, 4097, b"hello"), "offset");
    assert_ne!(base, extent_check(1, 4096, b"hellp"), "a flipped byte");
    assert_ne!(base, extent_check(1, 4096, b"hell"), "length");
    let mut streamed = ExtentHasher::new(1, 4096, 5);
    streamed.update(b"he");
    streamed.update(b"llo");
    assert_eq!(streamed.finalize(), base);
    assert_eq!(base, extent_check(1, 4096, b"hello"));
}

/// Payload bytes for a location: u16 depth, names, then the leaf.
fn p_loc(parents: &[&[u8]], leaf: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(parents.len()).unwrap().to_be_bytes().to_vec();
    for p in parents {
        out.push(u8::try_from(p.len()).unwrap());
        out.extend_from_slice(p);
    }
    out.push(u8::try_from(leaf.len()).unwrap());
    out.extend_from_slice(leaf);
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn u64b(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
fn record_payload_reject_vectors() {
    use RecordError as E;
    let a = p_loc(&[], b"a");
    let id = grain(1).to_bytes().to_vec();
    let create_file = |exec: u8, stage: u64| cat(&[&a, &[1, exec], &u64b(stage)]);
    let create_dir = |exec: u8, stage: u64| cat(&[&a, &[2, exec], &u64b(stage)]);
    let sym = |target: &[u8]| {
        cat(&[
            &a,
            &[3, 0],
            &u64b(0),
            &u16::try_from(target.len()).unwrap().to_be_bytes(),
            target,
        ])
    };
    let extent =
        |stage: u64, off: u64, len: u64| cat(&[&u64b(stage), &u64b(off), &u64b(len), &[0; 32]]);
    let synced = |gen_: u64| cat(&[&u64b(1), &u64b(0), &id, &u64b(gen_), &id]);
    let intent = |gen_: u64, cause: u8| cat(&[&u64b(gen_), &id, &[cause]]);
    let bind = |cause: u8, grain_id: &[u8]| cat(&[&a, &[cause], &u64b(1), &u64b(0), grain_id]);
    let names = |n: usize, len: usize| -> Vec<u8> {
        let one = vec![b'n'; len];
        let parents: Vec<&[u8]> = (0..n).map(|_| one.as_slice()).collect();
        p_loc(&parents, b"a")
    };
    let delete = |tag: u8, stage: u64| cat(&[&a, &[tag], &u64b(stage)]);
    let cases: Vec<(&str, u8, Vec<u8>, RecordError)> = vec![
        ("kind 0", 0, vec![], E::UnknownKind { kind: 0 }),
        ("kind 19", 19, vec![], E::UnknownKind { kind: 19 }),
        ("empty payload", 1, vec![], E::Truncated),
        ("cut payload", 8, cat(&[&a, &[]]), E::Truncated),
        ("trailing byte", 8, cat(&[&a, &[1, 0]]), E::TrailingBytes),
        (
            "depth 129",
            1,
            129u16.to_be_bytes().to_vec(),
            E::PathTooDeep { depth: 129 },
        ),
        (
            "depth 65535",
            1,
            65535u16.to_be_bytes().to_vec(),
            E::PathTooDeep { depth: 65535 },
        ),
        (
            "4097 name bytes",
            1,
            names(17, 241),
            E::PathTooLong { bytes: 4097 },
        ),
        (
            "name NUL",
            1,
            p_loc(&[], b"a\0b"),
            E::BadName(NameError::Nul),
        ),
        (
            "name slash",
            1,
            p_loc(&[], b"a/b"),
            E::BadName(NameError::Slash),
        ),
        (
            "name empty",
            1,
            p_loc(&[], b""),
            E::BadName(NameError::Empty),
        ),
        ("name dot", 1, p_loc(&[], b"."), E::BadName(NameError::Dot)),
        (
            "name dotdot",
            1,
            p_loc(&[b".."], b"a"),
            E::BadName(NameError::DotDot),
        ),
        (
            "name .gran",
            1,
            p_loc(&[], b".gran"),
            E::BadName(NameError::GranPrefix),
        ),
        (
            "name .granite",
            1,
            p_loc(&[], b".granite"),
            E::BadName(NameError::GranPrefix),
        ),
        (
            "entry type 0",
            1,
            cat(&[&a, &[0, 0], &u64b(0)]),
            E::BadEntryType { tag: 0 },
        ),
        (
            "entry type 4",
            1,
            cat(&[&a, &[4, 0], &u64b(0)]),
            E::BadEntryType { tag: 4 },
        ),
        ("exec 2", 1, create_file(2, 1), E::BadExec { byte: 2 }),
        (
            "exec on a dir",
            1,
            create_dir(1, 0),
            E::MustBeZero { field: "exec" },
        ),
        (
            "stage on a dir",
            1,
            create_dir(0, 1),
            E::MustBeZero { field: "stage id" },
        ),
        (
            "file stage 0",
            1,
            create_file(0, 0),
            E::StageIdOutOfRange { stage_id: 0 },
        ),
        (
            "file stage 2^63",
            1,
            create_file(0, 1 << 63),
            E::StageIdOutOfRange { stage_id: 1 << 63 },
        ),
        (
            "symlink target empty",
            1,
            sym(b""),
            E::BadSymlinkTarget(SymlinkTargetError::Empty),
        ),
        (
            "symlink target NUL",
            1,
            sym(b"a\0"),
            E::BadSymlinkTarget(SymlinkTargetError::Nul),
        ),
        (
            "symlink target 4097",
            1,
            sym(&[b't'; 4097]),
            E::BadSymlinkTarget(SymlinkTargetError::TooLong { len: 4097 }),
        ),
        (
            "stage-bind cause 0",
            2,
            bind(0, &id),
            E::BadCause { byte: 0 },
        ),
        (
            "stage-bind cause 3",
            2,
            bind(3, &id),
            E::BadCause { byte: 3 },
        ),
        (
            "stage-bind algorithm 0",
            2,
            bind(1, &[0; 33]),
            E::BadGrainId,
        ),
        (
            "stage-bind id 0xFF tag",
            2,
            bind(2, &[0xFF; 33]),
            E::BadGrainId,
        ),
        ("extent length 0", 3, extent(1, 0, 0), E::ExtentEmpty),
        (
            "extent length 8388609",
            3,
            extent(1, 0, 8_388_609),
            E::ExtentTooLong { length: 8_388_609 },
        ),
        (
            "extent end 2^63",
            3,
            extent(1, SIZE_MAX, 1),
            E::ExtentOverflow {
                offset: SIZE_MAX,
                length: 1,
            },
        ),
        (
            "extent offset 2^63",
            3,
            extent(1, 1 << 63, 1),
            E::SizeOutOfRange { value: 1 << 63 },
        ),
        (
            "extent offset max",
            3,
            extent(1, u64::MAX, 1),
            E::SizeOutOfRange { value: u64::MAX },
        ),
        (
            "extent stage 0",
            3,
            extent(0, 0, 1),
            E::StageIdOutOfRange { stage_id: 0 },
        ),
        (
            "extent no check",
            3,
            cat(&[&u64b(1), &u64b(0), &u64b(1)]),
            E::Truncated,
        ),
        (
            "truncate size 2^63",
            4,
            cat(&[&u64b(1), &u64b(1 << 63)]),
            E::SizeOutOfRange { value: 1 << 63 },
        ),
        ("delete type 9", 7, delete(9, 0), E::BadEntryType { tag: 9 }),
        (
            "delete dir with stage",
            7,
            delete(2, 3),
            E::MustBeZero { field: "stage id" },
        ),
        (
            "delete file stage 2^63",
            7,
            delete(1, 1 << 63),
            E::StageIdOutOfRange { stage_id: 1 << 63 },
        ),
        (
            "setattr exec 2",
            8,
            cat(&[&a, &[2]]),
            E::BadExec { byte: 2 },
        ),
        (
            "synced generation 0",
            9,
            synced(0),
            E::GenerationOutOfRange { generation: 0 },
        ),
        (
            "synced generation max",
            9,
            synced(u64::MAX),
            E::GenerationOutOfRange {
                generation: u64::MAX,
            },
        ),
        (
            "intent generation 0",
            10,
            intent(0, 1),
            E::GenerationOutOfRange { generation: 0 },
        ),
        ("intent cause 0", 10, intent(1, 0), E::BadCause { byte: 0 }),
        ("intent cause 3", 10, intent(1, 3), E::BadCause { byte: 3 }),
        (
            "boundary missing publication id",
            11,
            cat(&[&id, &u64b(0)]),
            E::Truncated,
        ),
        (
            "landed boundary 0",
            12,
            cat(&[&u64b(0), &id, &u64b(2)]),
            E::SeqOutOfRange {
                field: "boundary seq",
                value: 0,
            },
        ),
        (
            "landed seq 1",
            12,
            cat(&[&u64b(1), &id, &u64b(1)]),
            E::SeqOutOfRange {
                field: "landed seq",
                value: 1,
            },
        ),
        (
            "landed seq max",
            12,
            cat(&[&u64b(1), &id, &u64b(u64::MAX)]),
            E::SeqOutOfRange {
                field: "landed seq",
                value: u64::MAX,
            },
        ),
    ];
    assert!(cases.len() >= 50);
    let h = header();
    for (what, kind, payload, want) in cases {
        assert_eq!(Record::decode_payload(kind, &payload), Err(want), "{what}");
        // Framed with a correct check, the same payload fences the journal:
        // a check-valid impossible record is never a tear.
        let frame = raw_frame(&h, kind, 1, &payload);
        let fence = scan_journal(&journal_with_frame(&h, &[frame])).unwrap_err();
        let reason = match want {
            E::UnknownKind { kind } => FenceReason::UnknownKind { kind },
            e => FenceReason::Payload(e),
        };
        assert_eq!(
            (fence.offset, fence.reason),
            (JOURNAL_HEADER_LEN, reason),
            "{what}"
        );
    }
}

#[test]
fn encoder_refuses_what_the_decoder_rejects() {
    let bad = [
        Record::Create {
            at: loc(&[], "a"),
            kind: CreateKind::File {
                exec: false,
                stage_id: 0,
            },
        },
        Record::WriteExtent {
            stage_id: 1,
            offset: 0,
            length: 0,
            check: [0; 32],
        },
        Record::WriteExtent {
            stage_id: 1,
            offset: SIZE_MAX,
            length: 1,
            check: [0; 32],
        },
        Record::FileSynced {
            stage_id: 1,
            synced_size: 0,
            content: grain(1),
            generation: 0,
            prepared_root: grain(1),
        },
        Record::Delete {
            at: loc(&[], "a"),
            kind: DeleteKind::File { stage_id: Some(0) },
        },
        Record::LandedCommit {
            boundary_seq: 1,
            landed_root: grain(1),
            landed_seq: 1,
        },
    ];
    for record in &bad {
        assert!(record.encode_payload().is_err(), "{record:?}");
    }
    // Control: the encoder is not simply refusing everything.
    for record in &golden_records() {
        assert!(record.encode_payload().is_ok(), "{record:?}");
    }
    let too_deep = Parent::new(vec![name("a"); 129]);
    assert_eq!(too_deep, Err(RecordError::PathTooDeep { depth: 129 }));
    let too_long = Parent::new(vec![Name::new(vec![b'a'; 255]).unwrap(); 17]);
    assert_eq!(too_long, Err(RecordError::PathTooLong { bytes: 4335 }));
    assert_eq!(
        encode_record(&header(), 0, &golden_records()[0]),
        Err(RecordError::SeqOutOfRange {
            field: "seq",
            value: 0
        })
    );
}

// ---- framing, seq and the checks -------------------------------------

#[test]
fn frame_length_is_bounded_before_it_is_read() {
    let h = header();
    let base = h.encode().unwrap();
    let with_len = |len: u32, tail: usize| {
        let mut out = base.clone();
        out.extend_from_slice(&len.to_be_bytes());
        out.resize(out.len() + tail, 0xAB);
        out
    };
    let cases = [
        (
            "len 40",
            with_len(40, 60),
            TornCause::LengthOutOfRange { len: 40 },
        ),
        (
            "len 0",
            with_len(0, 60),
            TornCause::LengthOutOfRange { len: 0 },
        ),
        (
            "len 16426",
            with_len(16426, 20000),
            TornCause::LengthOutOfRange { len: 16426 },
        ),
        (
            "len 4 GiB",
            with_len(u32::MAX, 20),
            TornCause::LengthOutOfRange { len: u32::MAX },
        ),
        (
            "len in range past the end",
            with_len(16425, 100),
            TornCause::ShortFrame { len: 16425 },
        ),
        (
            "three bytes of len",
            {
                let mut out = base.clone();
                out.extend_from_slice(&[0, 0, 0]);
                out
            },
            TornCause::ShortLength,
        ),
    ];
    for (what, bytes, cause) in cases {
        let scan = scan_journal(&bytes).unwrap();
        assert_eq!(
            (scan.end, scan.valid_len, scan.records.len()),
            (JournalEnd::Torn(cause), JOURNAL_HEADER_LEN, 0),
            "{what}"
        );
    }
}

#[test]
fn seq_must_be_gapless_and_exact() {
    let h = header();
    let dir = Record::Create {
        at: loc(&[], "d"),
        kind: CreateKind::Dir,
    }
    .encode_payload()
    .unwrap();
    let frames = |seqs: &[u64]| -> Vec<Vec<u8>> {
        seqs.iter().map(|&s| raw_frame(&h, 1, s, &dir)).collect()
    };
    let cases = [
        (
            "first seq 2",
            vec![2],
            0,
            FenceReason::SeqGap {
                expected: 1,
                found: 2,
            },
        ),
        (
            "first seq 0",
            vec![0],
            0,
            FenceReason::SeqRepeat {
                expected: 1,
                found: 0,
            },
        ),
        (
            "gap",
            vec![1, 3],
            1,
            FenceReason::SeqGap {
                expected: 2,
                found: 3,
            },
        ),
        (
            "repeat",
            vec![1, 1],
            1,
            FenceReason::SeqRepeat {
                expected: 2,
                found: 1,
            },
        ),
        (
            "backwards",
            vec![1, 2, 1],
            2,
            FenceReason::SeqRepeat {
                expected: 3,
                found: 1,
            },
        ),
    ];
    for (what, seqs, good_frames, reason) in cases {
        let f = frames(&seqs);
        let offset: usize =
            JOURNAL_HEADER_LEN + f.iter().take(good_frames).map(Vec::len).sum::<usize>();
        let fence = scan_journal(&journal_with_frame(&h, &f)).unwrap_err();
        assert_eq!((fence.offset, fence.reason), (offset, reason), "{what}");
    }
}

#[test]
fn a_record_from_another_journal_does_not_verify_here() {
    let a = header();
    let b = JournalHeader {
        writer: [0x99; 16],
        ..a
    };
    let records = golden_records();
    let from_b = encode_journal(&b, &records).unwrap();
    // Journal A's header followed by journal B's frames: every frame carries
    // B's header check in its own, so none verifies under A.
    let spliced = [a.encode().unwrap(), from_b[JOURNAL_HEADER_LEN..].to_vec()].concat();
    let scan = scan_journal(&spliced).unwrap();
    assert_eq!(
        (scan.records.len(), scan.valid_len, scan.end),
        (0, JOURNAL_HEADER_LEN, JournalEnd::Torn(TornCause::BadCheck))
    );
}

#[test]
fn an_unknown_kind_with_a_valid_check_is_a_fence_not_a_tear() {
    let h = header();
    for kind in [0u8, 19, 255] {
        let frame = raw_frame(&h, kind, 1, &[1, 2, 3]);
        let fence = scan_journal(&journal_with_frame(&h, &[frame])).unwrap_err();
        assert_eq!(
            (fence.offset, fence.reason),
            (JOURNAL_HEADER_LEN, FenceReason::UnknownKind { kind })
        );
    }
}

// ---- the value rules --------------------------------------------------

fn value_error(h: &JournalHeader, records: &[Record]) -> (usize, ValueError) {
    // The encoder runs the same rules and names the record; the scan of
    // hand-built frames must agree and fence at that record's offset.
    let Err(EncodeError::Value { index, error }) = encode_journal(h, records) else {
        panic!("expected a value error for {records:?}");
    };
    let mut state_free = h.encode().unwrap();
    for (i, r) in records.iter().enumerate() {
        state_free.extend_from_slice(&raw_frame(
            h,
            r.kind(),
            i as u64 + 1,
            &r.encode_payload().unwrap(),
        ));
    }
    let fence = scan_journal(&state_free).unwrap_err();
    let offset: usize = JOURNAL_HEADER_LEN
        + records[..index]
            .iter()
            .map(|r| 4 + 41 + r.encode_payload().unwrap().len())
            .sum::<usize>();
    assert_eq!(
        (fence.offset, fence.reason),
        (offset, FenceReason::Value(error))
    );
    (index, error)
}

fn file(id: u64) -> Record {
    Record::Create {
        at: loc(&[], &format!("f{id}")),
        kind: CreateKind::File {
            exec: false,
            stage_id: id,
        },
    }
}

fn bind(cause: BindCause, id: u64, size: u64) -> Record {
    Record::StageBind {
        at: loc(&[], "x"),
        cause,
        stage_id: id,
        staged_size: size,
        base_content: grain(3),
    }
}

fn extent(id: u64, offset: u64, length: u64) -> Record {
    Record::WriteExtent {
        stage_id: id,
        offset,
        length,
        check: [0; 32],
    }
}

fn synced(id: u64, size: u64, generation: u64) -> Record {
    Record::FileSynced {
        stage_id: id,
        synced_size: size,
        content: grain(4),
        generation,
        prepared_root: grain(5),
    }
}

fn boundary(through: u64) -> Record {
    Record::CommitBoundary {
        candidate: grain(6),
        through_seq: through,
        publication_id: [7; 16],
    }
}

fn landed(boundary_seq: u64, landed_seq: u64) -> Record {
    Record::LandedCommit {
        boundary_seq,
        landed_root: grain(8),
        landed_seq,
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
fn value_rule_reject_vectors() {
    use ValueError as V;
    let h = JournalHeader {
        next_stage_id: 3,
        receipt_generation: 5,
        base_seq: 7,
        ..header()
    };
    let cases: Vec<(&str, Vec<Record>, (usize, ValueError))> = vec![
        (
            "create file takes an id other than next",
            vec![file(4)],
            (
                0,
                V::StageIdNotNext {
                    expected: 3,
                    found: 4,
                },
            ),
        ),
        (
            "create file reuses an issued id",
            vec![file(3), file(3)],
            (
                1,
                V::StageIdNotNext {
                    expected: 4,
                    found: 3,
                },
            ),
        ),
        (
            "copy-up takes a lower id",
            vec![bind(BindCause::CopyUp, 1, 0)],
            (
                0,
                V::StageIdNotNext {
                    expected: 3,
                    found: 1,
                },
            ),
        ),
        (
            "re-bind of the next id (unissued)",
            vec![bind(BindCause::Rebind, 3, 0)],
            (
                0,
                V::RebindNotIssued {
                    stage_id: 3,
                    next: 3,
                },
            ),
        ),
        (
            "re-bind far above next",
            vec![bind(BindCause::Rebind, 99, 0)],
            (
                0,
                V::RebindNotIssued {
                    stage_id: 99,
                    next: 3,
                },
            ),
        ),
        (
            "re-bind twice",
            vec![bind(BindCause::Rebind, 1, 0), bind(BindCause::Rebind, 1, 0)],
            (1, V::StageAlreadyBound { stage_id: 1 }),
        ),
        (
            "re-bind of an id this journal copied up",
            vec![bind(BindCause::CopyUp, 3, 0), bind(BindCause::Rebind, 3, 0)],
            (1, V::StageAlreadyBound { stage_id: 3 }),
        ),
        (
            "extent for an unbound stage",
            vec![extent(1, 0, 1)],
            (0, V::UnknownStage { stage_id: 1 }),
        ),
        (
            "truncate of an unbound stage",
            vec![Record::Truncate {
                stage_id: 2,
                new_size: 0,
            }],
            (0, V::UnknownStage { stage_id: 2 }),
        ),
        (
            "delete naming an unbound stage",
            vec![Record::Delete {
                at: loc(&[], "x"),
                kind: DeleteKind::File { stage_id: Some(2) },
            }],
            (0, V::UnknownStage { stage_id: 2 }),
        ),
        (
            "synced for an unbound stage",
            vec![synced(1, 0, 6)],
            (0, V::UnknownStage { stage_id: 1 }),
        ),
        (
            "synced size above the accounted size",
            vec![file(3), extent(3, 0, 10), synced(3, 11, 6)],
            (
                2,
                V::SyncedExceedsStaged {
                    synced_size: 11,
                    staged_size: 10,
                },
            ),
        ),
        (
            "synced size above a truncated size",
            vec![
                file(3),
                extent(3, 0, 10),
                Record::Truncate {
                    stage_id: 3,
                    new_size: 4,
                },
                synced(3, 5, 6),
            ],
            (
                3,
                V::SyncedExceedsStaged {
                    synced_size: 5,
                    staged_size: 4,
                },
            ),
        ),
        (
            "generation equal to the receipt",
            vec![Record::IntentRegistered {
                generation: 5,
                prepared_root: grain(1),
                cause: IntentCause::DirectorySync,
            }],
            (
                0,
                V::GenerationNotAboveReceipt {
                    generation: 5,
                    receipt: 5,
                },
            ),
        ),
        (
            "generation decreasing",
            vec![
                Record::IntentRegistered {
                    generation: 9,
                    prepared_root: grain(1),
                    cause: IntentCause::DirectorySync,
                },
                Record::IntentRegistered {
                    generation: 8,
                    prepared_root: grain(1),
                    cause: IntentCause::DirectorySync,
                },
            ],
            (
                1,
                V::GenerationDecreased {
                    generation: 8,
                    previous: 9,
                },
            ),
        ),
        (
            "boundary through its own seq",
            vec![boundary(1)],
            (
                0,
                V::BoundaryThroughNotBelowSeq {
                    through_seq: 1,
                    seq: 1,
                },
            ),
        ),
        (
            "boundary through a later seq",
            vec![file(3), boundary(9)],
            (
                1,
                V::BoundaryThroughNotBelowSeq {
                    through_seq: 9,
                    seq: 2,
                },
            ),
        ),
        (
            "landed with no boundary",
            vec![landed(1, 8)],
            (0, V::NoOpenBoundary { boundary_seq: 1 }),
        ),
        (
            "landed naming a record that is not a boundary",
            vec![file(3), boundary(1), landed(1, 8)],
            (2, V::NoOpenBoundary { boundary_seq: 1 }),
        ),
        (
            "a boundary answered twice",
            vec![file(3), boundary(1), landed(2, 8), landed(2, 9)],
            (3, V::NoOpenBoundary { boundary_seq: 2 }),
        ),
        (
            "landed seq equal to the base",
            vec![file(3), boundary(1), landed(2, 7)],
            (
                2,
                V::LandedSeqNotAboveBase {
                    landed_seq: 7,
                    base_seq: 7,
                },
            ),
        ),
    ];
    assert!(cases.len() >= 20);
    for (what, records, want) in cases {
        assert_eq!(value_error(&h, &records), want, "{what}");
    }
}

#[test]
fn a_rebind_names_an_issued_id_and_does_not_advance_the_counter() {
    // A journal replaced at a landed commit: ids 1 and 2 were issued by the
    // old journal, so the new header continues at 5 (3 and 4 were dropped
    // files). File 2 continues: it is re-bound under its own id, its later
    // records keep that id, and a copy-up afterwards still takes 5.
    let h = JournalHeader {
        next_stage_id: 5,
        base_seq: 9,
        ..header()
    };
    let records = vec![
        bind(BindCause::Rebind, 2, 100),
        extent(2, 100, 8),
        synced(2, 100, 1),
        bind(BindCause::CopyUp, 5, 0),
        bind(BindCause::Rebind, 1, 0),
        extent(5, 0, 4),
    ];
    let bytes = encode_journal(&h, &records).unwrap();
    let scan = scan_journal(&bytes).unwrap();
    assert_eq!(scan.records, records);
    assert_eq!(scan.end, JournalEnd::Clean);
    assert_eq!(scan.state.next_stage_id(), 6);
    assert_eq!(
        scan.state.stage(2),
        Some(&StageState {
            size: 108,
            synced_size: Some(100),
            bound_at: 1,
        })
    );
    // Control: with the same records but the re-bind taking a fresh id, the
    // physical file's old id has no record naming it.
    let fresh = vec![bind(BindCause::CopyUp, 5, 100), extent(2, 100, 8)];
    assert_eq!(
        value_error(&h, &fresh),
        (1, ValueError::UnknownStage { stage_id: 2 })
    );
}

#[test]
fn writer_binding_checks_identity_and_ceiling() {
    let scan = scan_journal(&golden_journal()).unwrap();
    let writer = |writer: [u8; 16], ceiling: u64| WriterRecord {
        writer,
        ceiling,
        volume: VolumeName::new("v".to_owned()).unwrap(),
    };
    assert_eq!(scan.check_writer(&writer([0x11; 16], 1)), Ok(()));
    assert_eq!(scan.check_writer(&writer([0x11; 16], 64)), Ok(()));
    assert_eq!(
        scan.check_writer(&writer([0x12; 16], 64)),
        Err(WriterBindError::WriterMismatch)
    );
    assert_eq!(
        scan.check_writer(&writer([0x11; 16], 0)),
        Err(WriterBindError::CeilingBelowGeneration {
            highest: 1,
            ceiling: 0
        })
    );
    // A receipt generation the writer file has never reached is a rollback
    // too, even with no record in the journal.
    let h = JournalHeader {
        receipt_generation: 9,
        ..header()
    };
    let scan = scan_journal(&h.encode().unwrap()).unwrap();
    assert_eq!(
        scan.check_writer(&writer([0x11; 16], 8)),
        Err(WriterBindError::CeilingBelowGeneration {
            highest: 9,
            ceiling: 8
        })
    );
}

// ---- torn tails and mid-file damage -----------------------------------

#[test]
fn every_cut_of_the_golden_journal_is_a_prefix_never_an_error() {
    let h = header();
    let records = golden_records();
    let bytes = golden_journal();
    let bounds = frame_bounds(&h, &records);
    assert_eq!(bounds.last().copied(), Some(bytes.len()));
    let mut cases = 0;
    for cut in 0..=bytes.len() {
        let result = scan_journal(&bytes[..cut]);
        if cut < JOURNAL_HEADER_LEN {
            // A short header is never a tear: it is a fence.
            let fence = result.unwrap_err();
            assert_eq!(
                fence.reason,
                FenceReason::Header(HeaderError::BadLength { len: cut })
            );
            continue;
        }
        let scan = result.unwrap_or_else(|f| panic!("cut {cut}: {f}"));
        let whole = bounds.iter().take_while(|&&b| b <= cut).count() - 1;
        assert_eq!(scan.records, records[..whole], "cut {cut}");
        assert_eq!(scan.valid_len, bounds[whole], "cut {cut}");
        assert_eq!(
            matches!(scan.end, JournalEnd::Clean),
            cut == bounds[whole],
            "cut {cut}"
        );
        cases += 1;
    }
    assert_eq!(cases, bytes.len() - JOURNAL_HEADER_LEN + 1);
}

/// A deterministic byte stream, so the "garbage after a tear" cases repeat.
fn garbage(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            x.to_be_bytes()[0]
        })
        .collect()
}

#[test]
fn garbage_after_any_record_boundary_is_a_tear() {
    let h = header();
    let records = golden_records();
    let bytes = golden_journal();
    let bounds = frame_bounds(&h, &records);
    for (k, &b) in bounds.iter().enumerate() {
        for seed in 0..6u64 {
            let mut damaged = bytes[..b].to_vec();
            damaged.extend_from_slice(&garbage(
                seed + 10 * k as u64,
                1 + 37 * usize::try_from(seed).unwrap(),
            ));
            let scan = scan_journal(&damaged).unwrap_or_else(|f| panic!("boundary {k}: {f}"));
            assert_eq!(scan.records, records[..k], "boundary {k} seed {seed}");
            assert_eq!(scan.valid_len, b);
            assert!(matches!(scan.end, JournalEnd::Torn(_)));
        }
    }
}

#[test]
fn a_bit_flip_before_a_sync_record_fences_and_in_the_final_record_tears() {
    let h = header();
    let records = golden_records();
    let bytes = golden_journal();
    let bounds = frame_bounds(&h, &records);
    // Frame 6 (the commit boundary) is the last and a sync-class record.
    // Frames 1 to 5 all precede a sync-class record (frames 4 and 6).
    let mut fenced = 0;
    for frame in 0..5 {
        for byte in bounds[frame]..bounds[frame + 1] {
            for bit in 0..8 {
                let fence = scan_journal(&flip(&bytes, byte, bit)).unwrap_err();
                assert_eq!(
                    fence.offset, bounds[frame],
                    "frame {frame} byte {byte} bit {bit}"
                );
                assert!(matches!(fence.reason, FenceReason::MidFileDamage { .. }));
                fenced += 1;
            }
        }
    }
    assert_eq!(fenced, (bounds[5] - bounds[0]) * 8);
    // The final record has no later witness: a flip is a tear at it. This
    // is the stated residual, and why a synced mark is mirrored in the
    // staging header.
    for byte in bounds[5]..bounds[6] {
        let scan = scan_journal(&flip(&bytes, byte, 0)).unwrap();
        assert_eq!(
            (scan.valid_len, scan.records.len()),
            (bounds[5], 5),
            "byte {byte}"
        );
        assert!(matches!(scan.end, JournalEnd::Torn(_)));
    }
}

#[test]
fn a_bit_flip_in_an_ordinary_final_record_tears_at_it() {
    // Without the closing sync-class record, the frames after the synced
    // mark are ordinary: damage among them has no witness.
    let h = header();
    let records = golden_records()[..5].to_vec();
    let bytes = encode_journal(&h, &records).unwrap();
    let bounds = frame_bounds(&h, &records);
    for byte in bounds[4]..bounds[5] {
        for bit in 0..8 {
            let scan = scan_journal(&flip(&bytes, byte, bit)).unwrap();
            assert_eq!(
                (scan.valid_len, scan.records.len()),
                (bounds[4], 4),
                "byte {byte} bit {bit}"
            );
            assert!(matches!(scan.end, JournalEnd::Torn(_)));
        }
    }
    // Damage before the synced mark (frame 4) is still witnessed by it.
    for byte in bounds[2]..bounds[3] {
        assert!(scan_journal(&flip(&bytes, byte, 2)).is_err(), "byte {byte}");
    }
}

#[test]
fn a_hole_followed_by_ordinary_records_is_a_tear() {
    // Writeback is unordered: a later page can survive an earlier one. With
    // no sync-class record after the hole, that is a crash, not corruption.
    let h = header();
    let records = vec![
        Record::Create {
            at: loc(&[], "d"),
            kind: CreateKind::Dir,
        },
        Record::Create {
            at: loc(&["d"], "e"),
            kind: CreateKind::Dir,
        },
        Record::Create {
            at: loc(&["d", "e"], "f"),
            kind: CreateKind::Dir,
        },
        Record::Move {
            from: loc(&["d"], "e"),
            to: loc(&[], "e"),
        },
    ];
    let bytes = encode_journal(&h, &records).unwrap();
    let bounds = frame_bounds(&h, &records);
    let mut holed = bytes.clone();
    holed[bounds[1]..bounds[2]].fill(0);
    let scan = scan_journal(&holed).unwrap();
    assert_eq!((scan.records.len(), scan.valid_len), (1, bounds[1]));
    assert!(matches!(scan.end, JournalEnd::Torn(_)));
    // The records after the hole are dropped, never skipped over.
    assert_eq!(scan.records, records[..1]);
}

#[test]
fn a_hole_before_a_sync_record_is_a_fence_with_the_witness_named() {
    let h = header();
    let records = golden_records();
    let bytes = golden_journal();
    let bounds = frame_bounds(&h, &records);
    let mut holed = bytes.clone();
    holed[bounds[1]..bounds[2]].fill(0);
    let fence = scan_journal(&holed).unwrap_err();
    assert_eq!(fence.offset, bounds[1]);
    // The first valid sync-class frame after the hole is frame 4.
    assert!(matches!(
        fence.reason,
        FenceReason::MidFileDamage { witness, .. } if witness == bounds[3]
    ));
}

#[test]
fn only_a_sync_record_with_a_later_seq_is_a_witness() {
    let h = header();
    let records = golden_records();
    let bytes = golden_journal();
    let bounds = frame_bounds(&h, &records);
    // A copy of frame 4 (a sync-class frame, seq 4) after frame 4 and some
    // garbage: it verifies, but its seq is not above the last good one (4),
    // so it proves nothing about the garbage before it.
    let mut stale = bytes[..bounds[4]].to_vec();
    stale.extend_from_slice(&garbage(1, 9));
    stale.extend_from_slice(&bytes[bounds[3]..bounds[4]]);
    let scan = scan_journal(&stale).unwrap();
    assert_eq!((scan.records.len(), scan.valid_len), (4, bounds[4]));
    assert!(matches!(scan.end, JournalEnd::Torn(_)));
    // The same frame from the real position (seq 6) after garbage is a
    // witness: control for the vector above.
    let mut live = bytes[..bounds[4]].to_vec();
    live.extend_from_slice(&garbage(1, 9));
    live.extend_from_slice(&bytes[bounds[5]..bounds[6]]);
    assert!(scan_journal(&live).is_err());
}

#[test]
fn a_replayed_or_duplicated_record_is_a_fence() {
    let h = header();
    let records = golden_records();
    let bytes = golden_journal();
    let bounds = frame_bounds(&h, &records);
    // Record 2 appended again at the end: valid check, seq already used.
    let mut dup = bytes.clone();
    dup.extend_from_slice(&bytes[bounds[1]..bounds[2]]);
    let fence = scan_journal(&dup).unwrap_err();
    assert_eq!(
        (fence.offset, fence.reason),
        (
            bytes.len(),
            FenceReason::SeqRepeat {
                expected: 7,
                found: 2
            }
        )
    );
    // A frame deleted from the middle: the next one's seq jumps.
    let mut gap = bytes[..bounds[1]].to_vec();
    gap.extend_from_slice(&bytes[bounds[2]..]);
    let fence = scan_journal(&gap).unwrap_err();
    assert_eq!(
        (fence.offset, fence.reason),
        (
            bounds[1],
            FenceReason::SeqGap {
                expected: 2,
                found: 3
            }
        )
    );
}

// ---- the fuzz probe ----------------------------------------------------

#[test]
fn the_probe_accepts_goldens_and_hostile_bytes() {
    use crate::testkit::overlay_journal_decode_probe as probe;
    for bytes in [
        golden_journal(),
        unhex(WRITER_HEX),
        unhex(STAGING_ABSENT_HEX),
        unhex(STAGING_MARK_HEX),
        vec![],
        vec![0xFF; 300],
        garbage(3, 4000),
    ] {
        probe(&bytes);
    }
    for cut in 0..golden_journal().len() {
        probe(&golden_journal()[..cut]);
    }
}

/// Allocation is never sized by a declared length. A counting allocator
/// would need an `unsafe` global allocator, which this workspace forbids, so
/// this test pins the other half: every site in the codec that sizes a
/// buffer is listed here with the bound that makes it safe, and a new site
/// fails the test until it is added with its bound. The behaviour half
/// (a declared 4 GiB frame is refused as out of range, quickly, with a typed
/// cause) is `frame_length_is_bounded_before_it_is_read`.
#[test]
fn every_buffer_sizing_site_is_bounded_by_a_constant_or_an_earlier_check() {
    let sources = [
        ("overlay_journal.rs", include_str!("../overlay_journal.rs")),
        ("record.rs", include_str!("record.rs")),
        ("scan.rs", include_str!("scan.rs")),
    ];
    // (file, call text, why it is bounded)
    let allowed = [
        (
            "record.rs",
            "Vec::with_capacity(depth)",
            "depth was checked against 128 just above",
        ),
        (
            "overlay_journal.rs",
            "Vec::with_capacity(WRITER_FIXED_LEN + volume.len())",
            "the encoder's own volume, at most 63 bytes",
        ),
        (
            "overlay_journal.rs",
            "Vec::with_capacity(STAGING_HEADER_LEN)",
            "a constant",
        ),
        (
            "overlay_journal.rs",
            "out.resize(STAGING_HEADER_LEN, 0)",
            "a constant",
        ),
        (
            "overlay_journal.rs",
            "Vec::with_capacity(STAGING_MARK_LEN - CHECK_LEN)",
            "a constant",
        ),
        (
            "scan.rs",
            "Vec::with_capacity(JOURNAL_HEADER_LEN)",
            "a constant",
        ),
        (
            "scan.rs",
            "Vec::with_capacity(4 + len as usize)",
            "the encoder's own payload, at most 16 KiB",
        ),
    ];
    let mut seen = Vec::new();
    for (file, source) in sources {
        for pattern in ["with_capacity(", ".resize(", "vec![", ".reserve("] {
            for (at, _) in source.match_indices(pattern) {
                let start = source[..at].rfind([' ', '\n', '(']).map_or(0, |i| i + 1);
                let call_end = source[at..].find('\n').map_or(source.len(), |i| at + i);
                let call = &source[start..call_end];
                seen.push((file, call.to_owned()));
            }
        }
    }
    for (file, call) in &seen {
        assert!(
            allowed
                .iter()
                .any(|(f, c, _)| f == file && call.contains(c)),
            "{file}: unlisted buffer sizing site `{call}`"
        );
    }
    // Every listed site still exists: the list cannot go stale unnoticed.
    for (file, call, _) in allowed {
        assert!(
            seen.iter().any(|(f, c)| *f == file && c.contains(call)),
            "{file}: listed site `{call}` is gone"
        );
    }
}
