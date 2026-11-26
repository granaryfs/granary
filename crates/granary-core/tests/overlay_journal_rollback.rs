// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

mod common;
use granary_core::{
    hash::GrainId,
    manifest::Name,
    overlay_journal::{
        CreateKind, DeleteKind, FenceReason, JournalEnd, JournalHeader, Location, Parent, Record,
        RecordError, RecreateAnchor, SIZE_MAX, STAGE_ID_MAX, TornCause, ValueError, encode_journal,
        encode_record, extent_check, scan_journal, scan_journal_with,
    },
};
use std::fmt::Write as _;

const LICENSE: &str = "# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>\n# SPDX-License-Identifier: Apache-2.0\n";
const KIND: u8 = 18;

fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}")
            .unwrap_or_else(|error| panic!("fixture hex formatting: {error}"));
    }
    text
}

fn raw_frame(h: &JournalHeader, seq: u64, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(41 + payload.len())
        .unwrap_or_else(|error| panic!("fixture frame length: {error}"));
    let mut frame = Vec::new();
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(KIND);
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(payload);
    let check = blake3::derive_key(
        "granary overlay journal record v1",
        &[h.check().as_slice(), &frame].concat(),
    );
    frame.extend_from_slice(&check);
    frame
}

fn header() -> JournalHeader {
    JournalHeader {
        writer: [17; 16],
        base_root: GrainId::of(b"base"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    }
}

fn at() -> Location {
    Location {
        parent: Parent::root(),
        name: Name::new(b"f".to_vec()).unwrap_or_else(|error| panic!("fixture name: {error}")),
    }
}

fn file() -> Record {
    Record::Create {
        at: at(),
        kind: CreateKind::File {
            stage_id: 1,
            exec: true,
        },
    }
}

fn extent(offset: u64, bytes: &[u8]) -> Record {
    Record::WriteExtent {
        stage_id: 1,
        offset,
        length: bytes.len() as u64,
        check: extent_check(1, offset, bytes),
    }
}

fn anchor() -> RecreateAnchor {
    RecreateAnchor {
        content: GrainId::of(b"old"),
        size: 3,
    }
}

fn rollback(anchor: Option<RecreateAnchor>) -> Record {
    Record::StageRollback {
        stage_id: 1,
        old_size: 6,
        anchor,
        discarded_bytes: 6,
    }
}

fn payload(id: u64, old: u64, tag: u8, content: &[u8; 33], size: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&old.to_be_bytes());
    bytes.push(tag);
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(&6u64.to_be_bytes());
    bytes
}

fn seed(label: &str, bytes: &[u8]) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join(format!(
        "fuzz/corpus/overlay_journal_decode/rollback-{label}"
    ));
    if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
        std::fs::write(&path, bytes)
            .unwrap_or_else(|error| panic!("{label}: write fuzz seed: {error}"));
        std::fs::write(path.with_extension("license"), LICENSE)
            .unwrap_or_else(|error| panic!("{label}: write seed licence: {error}"));
    }
    let seed =
        std::fs::read(path).unwrap_or_else(|error| panic!("{label}: read fuzz seed: {error}"));
    assert_eq!(seed, bytes, "{label}: fuzz seed");
    granary_core::testkit::overlay_journal_decode_probe(&seed);
}

#[test]
fn rollback_journal_vectors_pin_bytes_size_and_generation() {
    let h = header();
    let records = [
        file(),
        extent(0, b"longer"),
        rollback(Some(anchor())),
        extent(3, b"new"),
        Record::Delete {
            at: at(),
            kind: DeleteKind::File { stage_id: Some(1) },
        },
        rollback(None),
        extent(1, b"x"),
    ];
    let bytes = encode_journal(&h, &records).unwrap();
    let mut decoded = Vec::new();
    let scan = scan_journal_with(&bytes, |_, record| decoded.push(record.clone())).unwrap();
    let mut sizes = Vec::new();
    let mut offset = granary_core::overlay_journal::JOURNAL_HEADER_LEN;
    for (i, record) in records.iter().enumerate() {
        offset += encode_record(&h, i as u64 + 1, record).unwrap().len();
        let prefix = scan_journal(&bytes[..offset]).unwrap();
        sizes.push(prefix.state.stage(1).unwrap().size);
    }
    assert_eq!(
        (scan.end, scan.state.highest_generation(), sizes),
        (JournalEnd::Clean, 0, vec![0, 6, 3, 6, 6, 0, 2])
    );
    assert_eq!(decoded, records);
    assert_eq!(encode_journal(&scan.header, &decoded).unwrap(), bytes);
    let exact_id = GrainId::of(&bytes);
    let mut goldens = LICENSE.to_owned();
    writeln!(goldens, "restored\t{}\t{exact_id}", hex(&bytes)).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_rollback_v1.tsv"),
        &goldens,
    );
    seed("restored", &bytes);
}

#[test]
fn malformed_rollback_vectors_fence_at_a_check_valid_frame() {
    use RecordError as E;
    let h = header();
    let prefix = encode_journal(&h, &[file(), extent(0, b"longer")]).unwrap();
    let control = [
        prefix.clone(),
        raw_frame(&h, 3, &payload(1, 6, 1, &anchor().content.to_bytes(), 3)),
    ]
    .concat();
    assert_eq!(scan_journal(&control).unwrap().state.next_seq(), 4);
    let mut rejects = LICENSE.to_owned();
    let zero = [0; 33];
    let content = anchor().content.to_bytes();
    let mut trailing = payload(1, 6, 0, &zero, 0);
    trailing.push(0);
    let oversized = SIZE_MAX + 1;
    let cases = [
        (
            "anchor_tag",
            payload(1, 6, 2, &zero, 0),
            E::BadPresenceTag {
                field: "anchor",
                tag: 2,
            },
        ),
        (
            "none_anchor_content",
            payload(1, 6, 0, &content, 0),
            E::MustBeZero {
                field: "anchor content",
            },
        ),
        (
            "none_anchor_size",
            payload(1, 6, 0, &zero, 1),
            E::MustBeZero {
                field: "anchor size",
            },
        ),
        (
            "anchor_content_algorithm",
            payload(1, 6, 1, &zero, 0),
            E::BadGrainId,
        ),
        (
            "stage_zero",
            payload(0, 6, 0, &zero, 0),
            E::StageIdOutOfRange { stage_id: 0 },
        ),
        (
            "stage_over",
            payload(STAGE_ID_MAX + 1, 6, 0, &zero, 0),
            E::StageIdOutOfRange {
                stage_id: STAGE_ID_MAX + 1,
            },
        ),
        (
            "old_size_over",
            payload(1, oversized, 0, &zero, 0),
            E::SizeOutOfRange { value: oversized },
        ),
        (
            "anchor_size_over",
            payload(1, 6, 1, &content, oversized),
            E::SizeOutOfRange { value: oversized },
        ),
        ("truncated", trailing[..65].to_vec(), E::Truncated),
        ("trailing_byte", trailing, E::TrailingBytes),
    ];
    let mut seeds = Vec::new();
    for (label, payload, expected) in cases
        .into_iter()
        .map(|(label, bytes, error)| (label, bytes, FenceReason::Payload(error)))
        .chain(std::iter::once((
            "unbound_stage",
            payload(2, 6, 0, &zero, 0),
            FenceReason::Value(ValueError::UnknownStage { stage_id: 2 }),
        )))
    {
        let bytes = [prefix.clone(), raw_frame(&h, 3, &payload)].concat();
        let error = scan_journal(&bytes).unwrap_err();
        assert_eq!(
            (error.offset, error.reason),
            (prefix.len(), expected),
            "{label}: {error:?}"
        );
        writeln!(rejects, "{label}\t{}\t{expected:?}", hex(&bytes)).unwrap();
        seeds.push((label, bytes));
    }
    assert_eq!(seeds.len(), 11);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_rollback_v1_rejects.tsv"),
        &rejects,
    );
    for (label, bytes) in seeds {
        seed(label, &bytes);
    }
}

#[test]
fn rollback_witness_fences_an_earlier_hole() {
    let h = header();
    let prefix = encode_journal(&h, &[file()]).unwrap();
    let mut damaged = encode_record(&h, 2, &extent(0, b"longer")).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    let witness = prefix.len() + damaged.len();
    let mut bytes = [prefix.clone(), damaged].concat();
    assert_eq!(
        scan_journal(&bytes).unwrap().end,
        JournalEnd::Torn(TornCause::BadCheck)
    );
    bytes.extend_from_slice(&encode_record(&h, 3, &rollback(None)).unwrap());
    let error = scan_journal(&bytes).unwrap_err();
    assert_eq!(
        (error.offset, error.reason),
        (
            prefix.len(),
            FenceReason::MidFileDamage {
                cause: TornCause::BadCheck,
                witness
            }
        )
    );
}
