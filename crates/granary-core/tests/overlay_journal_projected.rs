// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

mod common;
use granary_core::{
    hash::GrainId,
    manifest::Name,
    overlay_journal::{
        CreateKind, FenceReason, JournalHeader, Location, Parent, ProjectedSelection, Record,
        RecordError, ValueError, encode_journal, scan_journal, scan_journal_with,
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
/// A new file at stage `stage_id`, named `x` for stage 1, `y` for stage 2.
fn file(stage_id: u8) -> Record {
    Record::Create {
        at: Location {
            parent: Parent::root(),
            name: Name::new(vec![b'w' + stage_id])
                .unwrap_or_else(|error| panic!("fixture name: {error}")),
        },
        kind: CreateKind::File {
            exec: false,
            stage_id: u64::from(stage_id),
        },
    }
}
fn projected(through_seq: u64, selection: Option<ProjectedSelection>) -> Record {
    Record::ProjectedBoundary {
        candidate: GrainId::of(b"candidate"),
        through_seq,
        publication_id: [7; 16],
        selection,
    }
}
fn selection() -> ProjectedSelection {
    ProjectedSelection {
        stage_id: 1,
        content: GrainId::of(b"selected"),
        size: 9,
    }
}
fn attempt(boundary_seq: u64, n: u64) -> Record {
    Record::CommitAttempt {
        boundary_seq,
        publication_id: [7; 16],
        attempt: n,
    }
}
/// A payload with every selection field after the boundary tuple given.
fn payload(tag: u8, stage: u64, content: &[u8], size: u64) -> Vec<u8> {
    let mut out = GrainId::of(b"candidate").to_bytes().to_vec();
    out.extend_from_slice(&1u64.to_be_bytes());
    out.extend_from_slice(&[7; 16]);
    out.push(tag);
    out.extend_from_slice(&stage.to_be_bytes());
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
fn journal_projected_boundary_goldens_rejects_and_fuzz_seeds() {
    let h = JournalHeader {
        writer: [17; 16],
        base_root: GrainId::of(b"base"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut goldens = LICENSE.to_owned();
    let mut rejects = LICENSE.to_owned();
    let mut seeds = Vec::new();
    for (label, records) in [
        (
            "selected",
            vec![
                file(1),
                projected(1, Some(selection())),
                attempt(2, 1),
                attempt(2, 2),
                Record::CommitFence {
                    boundary_seq: 2,
                    publication_id: [7; 16],
                },
            ],
        ),
        (
            "unselected",
            vec![
                projected(0, None),
                attempt(1, 1),
                Record::LandedCommit {
                    boundary_seq: 1,
                    landed_root: GrainId::of(b"landed"),
                    landed_seq: 2,
                },
            ],
        ),
    ] {
        let bytes = encode_journal(&h, &records).unwrap();
        let mut decoded = Vec::new();
        let scan = scan_journal_with(&bytes, |_, r| decoded.push(r.clone())).unwrap();
        assert_eq!(decoded, records, "{label}");
        assert_eq!(encode_journal(&scan.header, &decoded).unwrap(), bytes);
        writeln!(goldens, "{label}\t{}\t{}", hex(&bytes), GrainId::of(&bytes)).unwrap();
        seeds.push((label, bytes));
    }
    let id = GrainId::of(b"selected").to_bytes();
    let zero = [0u8; 33];
    let file_selected = payload(1, 1, &id, 9);
    let mut count = 0;
    for (label, prefix, kind, payload, expected) in [
        (
            "none_stage_id",
            vec![file(1)],
            15,
            payload(0, 1, &zero, 0),
            FenceReason::Payload(RecordError::MustBeZero {
                field: "selected stage id",
            }),
        ),
        (
            "none_content",
            vec![file(1)],
            15,
            payload(0, 0, &id, 0),
            FenceReason::Payload(RecordError::MustBeZero {
                field: "selected content",
            }),
        ),
        (
            "none_size",
            vec![file(1)],
            15,
            payload(0, 0, &zero, 9),
            FenceReason::Payload(RecordError::MustBeZero {
                field: "selected size",
            }),
        ),
        (
            "unknown_tag",
            vec![file(1)],
            15,
            payload(2, 1, &id, 9),
            FenceReason::Payload(RecordError::BadSelectionTag { tag: 2 }),
        ),
        (
            "file_stage_zero",
            vec![file(1)],
            15,
            payload(1, 0, &id, 9),
            FenceReason::Payload(RecordError::StageIdOutOfRange { stage_id: 0 }),
        ),
        (
            "file_content_algorithm",
            vec![file(1)],
            15,
            payload(1, 1, &zero, 9),
            FenceReason::Payload(RecordError::BadGrainId),
        ),
        (
            "file_size_over",
            vec![file(1)],
            15,
            payload(1, 1, &id, 1 << 63),
            FenceReason::Payload(RecordError::SizeOutOfRange { value: 1 << 63 }),
        ),
        (
            "truncated",
            vec![file(1)],
            15,
            file_selected[..106].to_vec(),
            FenceReason::Payload(RecordError::Truncated),
        ),
        (
            "trailing_byte",
            vec![file(1)],
            15,
            [file_selected.as_slice(), &[0]].concat(),
            FenceReason::Payload(RecordError::TrailingBytes),
        ),
        (
            "unbound_stage",
            vec![file(1)],
            15,
            payload(1, 2, &id, 9),
            FenceReason::Value(ValueError::UnknownStage { stage_id: 2 }),
        ),
        (
            "selection_after_through",
            vec![file(1), file(2)],
            15,
            payload(1, 2, &id, 9),
            FenceReason::Value(ValueError::SelectionAfterThrough {
                stage_id: 2,
                bound_at: 2,
                through_seq: 1,
            }),
        ),
        (
            "through_below_open_boundary",
            vec![
                file(1),
                Record::CommitBoundary {
                    candidate: GrainId::of(b"open"),
                    through_seq: 1,
                    publication_id: [8; 16],
                },
            ],
            15,
            projected(1, None).encode_payload().unwrap(),
            FenceReason::Value(ValueError::ThroughBelowOpenBoundary {
                through_seq: 1,
                boundary_seq: 2,
            }),
        ),
        (
            "through_at_own_seq",
            vec![],
            15,
            payload(0, 0, &zero, 0),
            FenceReason::Value(ValueError::BoundaryThroughNotBelowSeq {
                through_seq: 1,
                seq: 1,
            }),
        ),
        (
            "wrong_publication",
            vec![file(1), projected(1, Some(selection()))],
            13,
            Record::CommitAttempt {
                boundary_seq: 2,
                publication_id: [8; 16],
                attempt: 1,
            }
            .encode_payload()
            .unwrap(),
            FenceReason::Value(ValueError::CommitBinding { boundary_seq: 2 }),
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
    assert_eq!(count, 14);
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_projected_v1.tsv"),
        &goldens,
    );
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_projected_v1_rejects.tsv"),
        &rejects,
    );
    let corpus = root.join("fuzz/corpus/overlay_journal_decode");
    for (label, bytes) in seeds {
        let path = corpus.join(format!("projected-{label}"));
        if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(path.with_extension("license"), LICENSE).unwrap();
        }
        let seed = std::fs::read(path).unwrap();
        assert_eq!(seed, bytes, "{label}: fuzz seed");
        granary_core::testkit::overlay_journal_decode_probe(&seed);
    }
}
