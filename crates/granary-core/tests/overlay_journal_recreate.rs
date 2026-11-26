// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

mod common;
use granary_core::{
    hash::GrainId,
    manifest::Name,
    overlay_journal::{
        CreateKind, FenceReason, JournalHeader, Location, Parent, Record, RecordError,
        RecreateAnchor, ValueError, encode_journal, extent_check, scan_journal, scan_journal_with,
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
fn at(name: u8) -> Location {
    Location {
        parent: Parent::root(),
        name: Name::new(vec![name]).unwrap_or_else(|error| panic!("fixture name: {error}")),
    }
}
fn anchor() -> RecreateAnchor {
    RecreateAnchor {
        content: GrainId::of(b"anchor"),
        size: 9,
    }
}
fn recreate(at: Option<Location>, stage_id: u64, anchor: Option<RecreateAnchor>) -> Record {
    Record::RecreateFile {
        exec: at.is_some(),
        at,
        stage_id,
        anchor,
    }
}
/// A new file at the running next id, named by its stage.
fn file(stage_id: u8) -> Record {
    Record::Create {
        at: at(b'a' + stage_id),
        kind: CreateKind::File {
            exec: false,
            stage_id: u64::from(stage_id),
        },
    }
}
/// A payload with every field after the location given.
fn payload(location: &[u8], exec: u8, stage: u64, tag: u8, content: &[u8], size: u64) -> Vec<u8> {
    let mut out = location.to_vec();
    out.push(exec);
    out.extend_from_slice(&stage.to_be_bytes());
    out.push(tag);
    out.extend_from_slice(content);
    out.extend_from_slice(&size.to_be_bytes());
    out
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
    reason = "one paired vector corpus pins bytes, refusal reasons and matching fuzz seeds"
)]
fn journal_recreate_goldens_rejects_and_fuzz_seeds() {
    // Ids 1 to 4 were issued before this journal began.
    let h = JournalHeader {
        writer: [17; 16],
        base_root: GrainId::of(b"base"),
        base_seq: 1,
        next_stage_id: 5,
        receipt_generation: 0,
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut goldens = LICENSE.to_owned();
    let mut rejects = LICENSE.to_owned();
    let mut seeds = Vec::new();
    let records = vec![
        recreate(Some(at(b'u')), 1, Some(anchor())),
        recreate(Some(at(b'v')), 2, None),
        recreate(None, 3, Some(anchor())),
        recreate(None, 4, None),
        Record::WriteExtent {
            stage_id: 3,
            offset: 2,
            length: 3,
            check: extent_check(3, 2, b"new"),
        },
        Record::Truncate {
            stage_id: 1,
            new_size: 4,
        },
        file(5),
    ];
    let bytes = encode_journal(&h, &records).unwrap();
    let mut decoded = Vec::new();
    let scan = scan_journal_with(&bytes, |_, r| decoded.push(r.clone())).unwrap();
    assert_eq!(decoded, records);
    assert_eq!(encode_journal(&scan.header, &decoded).unwrap(), bytes);
    writeln!(
        goldens,
        "recreated\t{}\t{}",
        hex(&bytes),
        GrainId::of(&bytes)
    )
    .unwrap();
    seeds.push(("recreated", bytes));
    let id = anchor().content.to_bytes();
    let zero = [0u8; 33];
    let named = [1, 0, 0, 1, b'u'];
    let detached = payload(&[0], 0, 1, 1, &id, 9);
    let mut count = 0;
    for (label, prefix, kind, payload, expected) in [
        (
            "location_tag",
            vec![],
            16,
            payload(&[2, 0, 0, 1, b'u'], 1, 1, 0, &zero, 0),
            FenceReason::Payload(RecordError::BadPresenceTag {
                field: "location",
                tag: 2,
            }),
        ),
        (
            "detached_exec",
            vec![],
            16,
            payload(&[0], 1, 1, 0, &zero, 0),
            FenceReason::Payload(RecordError::MustBeZero { field: "exec" }),
        ),
        (
            "exec_byte",
            vec![],
            16,
            payload(&named, 2, 1, 0, &zero, 0),
            FenceReason::Payload(RecordError::BadExec { byte: 2 }),
        ),
        (
            "stage_zero",
            vec![],
            16,
            payload(&[0], 0, 0, 0, &zero, 0),
            FenceReason::Payload(RecordError::StageIdOutOfRange { stage_id: 0 }),
        ),
        (
            "stage_over",
            vec![],
            16,
            payload(&[0], 0, 1 << 63, 0, &zero, 0),
            FenceReason::Payload(RecordError::StageIdOutOfRange { stage_id: 1 << 63 }),
        ),
        (
            "anchor_tag",
            vec![],
            16,
            payload(&[0], 0, 1, 2, &id, 9),
            FenceReason::Payload(RecordError::BadPresenceTag {
                field: "anchor",
                tag: 2,
            }),
        ),
        (
            "none_anchor_content",
            vec![],
            16,
            payload(&[0], 0, 1, 0, &id, 0),
            FenceReason::Payload(RecordError::MustBeZero {
                field: "anchor content",
            }),
        ),
        (
            "none_anchor_size",
            vec![],
            16,
            payload(&[0], 0, 1, 0, &zero, 9),
            FenceReason::Payload(RecordError::MustBeZero {
                field: "anchor size",
            }),
        ),
        (
            "anchor_content_algorithm",
            vec![],
            16,
            payload(&[0], 0, 1, 1, &zero, 9),
            FenceReason::Payload(RecordError::BadGrainId),
        ),
        (
            "anchor_size_over",
            vec![],
            16,
            payload(&[0], 0, 1, 1, &id, 1 << 63),
            FenceReason::Payload(RecordError::SizeOutOfRange { value: 1 << 63 }),
        ),
        (
            "truncated",
            vec![],
            16,
            detached[..detached.len() - 1].to_vec(),
            FenceReason::Payload(RecordError::Truncated),
        ),
        (
            "trailing_byte",
            vec![],
            16,
            [detached.as_slice(), &[0]].concat(),
            FenceReason::Payload(RecordError::TrailingBytes),
        ),
        (
            "unissued",
            vec![],
            16,
            payload(&[0], 0, 5, 0, &zero, 0),
            FenceReason::Value(ValueError::RecreateNotIssued {
                stage_id: 5,
                next: 5,
            }),
        ),
        (
            "already_bound",
            vec![recreate(None, 1, None)],
            16,
            payload(&named, 1, 1, 0, &zero, 0),
            FenceReason::Value(ValueError::StageAlreadyBound { stage_id: 1 }),
        ),
        (
            "create_skips_counter",
            vec![recreate(None, 4, None)],
            1,
            file(6).encode_payload().unwrap(),
            FenceReason::Value(ValueError::StageIdNotNext {
                expected: 5,
                found: 6,
            }),
        ),
    ] {
        let mut bytes = encode_journal(&h, &prefix).unwrap();
        assert!(scan_journal(&bytes).is_ok(), "{label}: valid prefix");
        bytes.extend_from_slice(&raw_frame(&h, kind, prefix.len() as u64 + 1, &payload));
        let error = scan_journal(&bytes).unwrap_err();
        assert_eq!(error.reason, expected, "{label}: {error:?}");
        writeln!(rejects, "{label}\t{}\t{expected:?}", hex(&bytes)).unwrap();
        seeds.push((label, bytes));
        count += 1;
    }
    assert_eq!(count, 15);
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_recreate_v1.tsv"),
        &goldens,
    );
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_recreate_v1_rejects.tsv"),
        &rejects,
    );
    let corpus = root.join("fuzz/corpus/overlay_journal_decode");
    for (label, bytes) in seeds {
        let path = corpus.join(format!("recreate-{label}"));
        if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(path.with_extension("license"), LICENSE).unwrap();
        }
        let seed = std::fs::read(path).unwrap();
        assert_eq!(seed, bytes, "{label}: fuzz seed");
        granary_core::testkit::overlay_journal_decode_probe(&seed);
    }
}
