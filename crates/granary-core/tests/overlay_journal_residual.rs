// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

mod common;
use granary_core::{
    hash::GrainId,
    manifest::Name,
    overlay_journal::{
        CreateKind, FenceReason, IntentCause, JournalHeader, Location, Parent, Record, RecordError,
        ResidualDisposition, ResidualFile, ResidualMode, ResidualPayloadHasher, ValueError,
        encode_journal, residual_inventory_check, scan_journal,
    },
};
use std::fmt::Write as _;

const LICENSE: &str = "# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>\n# SPDX-License-Identifier: Apache-2.0\n";

fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}")
            .unwrap_or_else(|error| panic!("fixture hex formatting: {error}"));
    }
    text
}

fn raw_frame(h: &JournalHeader, kind: u8, seq: u64, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(41 + payload.len())
        .unwrap_or_else(|error| panic!("fixture frame length: {error}"));
    let mut covered = h.check().to_vec();
    covered.extend_from_slice(&len.to_be_bytes());
    covered.push(kind);
    covered.extend_from_slice(&seq.to_be_bytes());
    covered.extend_from_slice(payload);
    let check = blake3::derive_key("granary overlay journal record v1", &covered);
    let mut frame = covered
        .get(32..)
        .unwrap_or_else(|| panic!("fixture frame header"))
        .to_vec();
    frame.extend_from_slice(&check);
    frame
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table pins residual bytes, checks and matching fuzz seeds"
)]
fn residual_record_and_descriptor_goldens_and_fuzz_seeds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut goldens = LICENSE.to_owned();
    let mut rejects = LICENSE.to_owned();
    let mut count = 0;
    let mut payload = ResidualPayloadHasher::new(1, 0);
    payload.update(b"");
    let small = ResidualFile {
        stage_id: 1,
        at: Location {
            parent: Parent::root(),
            name: Name::new(b"f".to_vec()).unwrap(),
        },
        exec: false,
        local_size: 0,
        payload_check: payload.finalize(),
    };
    let mut large = small.clone();
    large.stage_id = 9_223_372_036_854_775_807;
    large.exec = true;
    large.local_size = 9_223_372_036_854_775_807;
    let parents = (0..128)
        .map(|i| {
            Name::new(vec![
                b'p';
                match i {
                    0..15 => 255,
                    15 => 159,
                    _ => 1,
                }
            ])
            .unwrap()
        })
        .collect();
    large.at = Location {
        parent: Parent::new(parents).unwrap(),
        name: Name::new(vec![b'f'; 255]).unwrap(),
    };
    for (label, file) in [("descriptor_min", &small), ("descriptor_max", &large)] {
        let bytes = file.encode().unwrap();
        assert_eq!(ResidualFile::decode(&bytes), Ok(file.clone()));
        writeln!(goldens, "{label}\t{}\t{}", hex(&bytes), GrainId::of(&bytes)).unwrap();
    }
    let mut second = small.clone();
    second.stage_id = 2;
    second.payload_check = ResidualPayloadHasher::new(2, 0).finalize();
    second.at.name = Name::new(b"g".to_vec()).unwrap();
    let files = [small, second];
    let inventory = residual_inventory_check(&files).unwrap();
    writeln!(goldens, "inventory_two\t{}", hex(&inventory)).unwrap();
    let h = JournalHeader {
        writer: [17; 16],
        base_root: GrainId::of(b"base"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let mut seeds = Vec::new();
    for (mode, disposition) in [(1, ResidualMode::KeepLocal), (2, ResidualMode::KeepRemote)] {
        let mut records: Vec<_> = files
            .iter()
            .map(|file| Record::Create {
                at: file.at.clone(),
                kind: CreateKind::File {
                    exec: file.exec,
                    stage_id: file.stage_id,
                },
            })
            .collect();
        records.extend([
            Record::CommitBoundary {
                candidate: GrainId::of(b"candidate"),
                through_seq: 2,
                publication_id: [7; 16],
            },
            Record::LandedCommit {
                boundary_seq: 3,
                landed_root: GrainId::of(b"landed"),
                landed_seq: 2,
            },
            Record::IntentRegistered {
                generation: 1,
                prepared_root: GrainId::of(b"landed"),
                cause: IntentCause::LandedRefresh,
            },
            Record::ResidualDisposition(ResidualDisposition {
                boundary_seq: 3,
                publication_id: [7; 16],
                landed_root: GrainId::of(b"landed"),
                landed_seq: 2,
                source_end: 5,
                disposition,
                collision_count: 2,
                inventory_check: inventory,
            }),
        ]);
        let bytes = encode_journal(&h, &records).unwrap();
        granary_core::testkit::overlay_journal_decode_probe(&bytes);
        writeln!(
            goldens,
            "journal_mode_{mode}\t{}\t{}",
            hex(&bytes),
            GrainId::of(&bytes)
        )
        .unwrap();
        seeds.push((format!("mode-{mode}"), bytes));
        if mode == 1 {
            let prefix = records[..5].to_vec();
            let payload = records[5].encode_payload().unwrap();
            let mismatch = FenceReason::Value(ValueError::ResidualSourceMismatch);
            let mut cases = Vec::new();
            for (label, offset, fields, expected) in [
                (
                    "boundary-zero",
                    0,
                    vec![0; 8],
                    FenceReason::Payload(RecordError::SeqOutOfRange {
                        field: "boundary seq",
                        value: 0,
                    }),
                ),
                (
                    "boundary-binding",
                    0,
                    99u64.to_be_bytes().to_vec(),
                    mismatch,
                ),
                ("publication-binding", 8, vec![8], mismatch),
                (
                    "root-algorithm",
                    24,
                    vec![0],
                    FenceReason::Payload(RecordError::BadGrainId),
                ),
                ("root-binding", 25, vec![payload[25] ^ 1], mismatch),
                (
                    "landed-zero",
                    57,
                    vec![0; 8],
                    FenceReason::Payload(RecordError::SeqOutOfRange {
                        field: "landed seq",
                        value: 0,
                    }),
                ),
                (
                    "landed-max",
                    57,
                    vec![255; 8],
                    FenceReason::Payload(RecordError::SeqOutOfRange {
                        field: "landed seq",
                        value: u64::MAX,
                    }),
                ),
                ("landed-binding", 57, 3u64.to_be_bytes().to_vec(), mismatch),
                ("source-cursor", 65, 4u64.to_be_bytes().to_vec(), mismatch),
                (
                    "mode-zero",
                    73,
                    vec![0],
                    FenceReason::Payload(RecordError::BadDisposition { byte: 0 }),
                ),
                (
                    "mode-three",
                    73,
                    vec![3],
                    FenceReason::Payload(RecordError::BadDisposition { byte: 3 }),
                ),
                (
                    "mode-max",
                    73,
                    vec![255],
                    FenceReason::Payload(RecordError::BadDisposition { byte: 255 }),
                ),
                (
                    "empty-count",
                    74,
                    vec![0; 4],
                    FenceReason::Payload(RecordError::EmptyInventory),
                ),
                ("count-bound", 74, 3u32.to_be_bytes().to_vec(), mismatch),
            ] {
                let mut bad = payload.clone();
                bad[offset..offset + fields.len()].copy_from_slice(&fields);
                cases.push((label, prefix.clone(), 17, bad, expected));
            }
            cases.push((
                "truncated",
                prefix.clone(),
                17,
                payload[..109].to_vec(),
                FenceReason::Payload(RecordError::Truncated),
            ));
            let mut trailing = payload.clone();
            trailing.push(0);
            cases.push((
                "trailing",
                prefix.clone(),
                17,
                trailing,
                FenceReason::Payload(RecordError::TrailingBytes),
            ));
            for (label, boundary) in [
                (
                    "open-boundary",
                    Record::CommitBoundary {
                        candidate: GrainId::of(b"next candidate"),
                        through_seq: 5,
                        publication_id: [8; 16],
                    },
                ),
                (
                    "open-projected-boundary",
                    Record::ProjectedBoundary {
                        candidate: GrainId::of(b"next candidate"),
                        through_seq: 5,
                        publication_id: [8; 16],
                        selection: None,
                    },
                ),
            ] {
                let mut open = prefix.clone();
                open.push(boundary);
                let mut choice = payload.clone();
                choice[65..73].copy_from_slice(&6u64.to_be_bytes());
                cases.push((label, open, 17, choice, mismatch));
            }
            let mut no_refresh = payload.clone();
            no_refresh[65..73].copy_from_slice(&4u64.to_be_bytes());
            cases.push((
                "refresh-missing",
                prefix[..4].to_vec(),
                17,
                no_refresh,
                mismatch,
            ));
            let mut no_landing = prefix.clone();
            no_landing.remove(3);
            let mut unlanded = payload.clone();
            unlanded[65..73].copy_from_slice(&4u64.to_be_bytes());
            cases.push(("landing-missing", no_landing, 17, unlanded, mismatch));
            let mut before = prefix.clone();
            before.swap(3, 4);
            cases.push((
                "refresh-before-landing",
                before,
                17,
                payload.clone(),
                mismatch,
            ));
            let mut directory = prefix.clone();
            directory[4] = Record::IntentRegistered {
                generation: 1,
                prepared_root: GrainId::of(b"landed"),
                cause: IntentCause::DirectorySync,
            };
            cases.push(("refresh-cause", directory, 17, payload.clone(), mismatch));
            let mut wrong_root = prefix.clone();
            wrong_root[4] = Record::IntentRegistered {
                generation: 1,
                prepared_root: GrainId::of(b"other"),
                cause: IntentCause::LandedRefresh,
            };
            cases.push(("refresh-root", wrong_root, 17, payload.clone(), mismatch));
            let mut duplicate = payload.clone();
            duplicate[65..73].copy_from_slice(&6u64.to_be_bytes());
            cases.push((
                "duplicate",
                records.clone(),
                17,
                duplicate,
                FenceReason::Value(ValueError::AfterResidualDisposition),
            ));
            cases.push((
                "after-terminal",
                records.clone(),
                4,
                Record::Truncate {
                    stage_id: 1,
                    new_size: 0,
                }
                .encode_payload()
                .unwrap(),
                FenceReason::Value(ValueError::AfterResidualDisposition),
            ));
            let mut newer = prefix.clone();
            newer.extend([
                Record::CommitBoundary {
                    candidate: GrainId::of(b"new candidate"),
                    through_seq: 5,
                    publication_id: [8; 16],
                },
                Record::LandedCommit {
                    boundary_seq: 6,
                    landed_root: GrainId::of(b"new landed"),
                    landed_seq: 3,
                },
                Record::IntentRegistered {
                    generation: 2,
                    prepared_root: GrainId::of(b"new landed"),
                    cause: IntentCause::LandedRefresh,
                },
            ]);
            let mut older = payload.clone();
            older[65..73].copy_from_slice(&8u64.to_be_bytes());
            cases.push(("older-landing", newer, 17, older, mismatch));
            for (label, prefix, kind, payload, expected) in cases {
                let mut bytes = encode_journal(&h, &prefix).unwrap();
                bytes.extend(raw_frame(&h, kind, prefix.len() as u64 + 1, &payload));
                assert_eq!(
                    scan_journal(&bytes).unwrap_err().reason,
                    expected,
                    "{label}"
                );
                writeln!(rejects, "{label}\t{}\t{expected:?}", hex(&bytes)).unwrap();
                granary_core::testkit::overlay_journal_decode_probe(&bytes);
                seeds.push((format!("reject-{label}"), bytes));
                count += 1;
            }
        }
    }
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_residual_v1.tsv"),
        &goldens,
    );
    assert_eq!(count, 26);
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_residual_v1_rejects.tsv"),
        &rejects,
    );
    for (label, bytes) in seeds {
        let path = root.join(format!(
            "fuzz/corpus/overlay_journal_decode/residual-{label}"
        ));
        if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(path.with_extension("license"), LICENSE).unwrap();
        }
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
