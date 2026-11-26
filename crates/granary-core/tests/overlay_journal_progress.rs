// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

mod common;
use granary_core::{
    hash::GrainId,
    overlay_journal::{
        FenceReason, JournalHeader, Record, RecordError, ValueError, encode_journal, scan_journal,
        scan_journal_with,
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
fn boundary() -> Record {
    Record::CommitBoundary {
        candidate: GrainId::of(b"candidate"),
        through_seq: 0,
        publication_id: [7; 16],
    }
}
fn attempt(n: u64) -> Record {
    Record::CommitAttempt {
        boundary_seq: 1,
        publication_id: [7; 16],
        attempt: n,
    }
}
fn fence() -> Record {
    Record::CommitFence {
        boundary_seq: 1,
        publication_id: [7; 16],
    }
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
fn journal_progress_goldens_rejects_and_fuzz_seeds() {
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
        ("charged", vec![boundary(), attempt(1), attempt(2)]),
        ("fenced", vec![boundary(), attempt(1), attempt(2), fence()]),
    ] {
        let bytes = encode_journal(&h, &records).unwrap();
        let mut decoded = Vec::new();
        let scan = scan_journal_with(&bytes, |_, r| decoded.push(r.clone())).unwrap();
        assert_eq!(encode_journal(&scan.header, &decoded).unwrap(), bytes);
        writeln!(goldens, "{label}\t{}\t{}", hex(&bytes), GrainId::of(&bytes)).unwrap();
        seeds.push((label, bytes));
    }
    let mut count = 0;
    for (label, prefix, kind, payload, expected) in [
        (
            "truncated_attempt",
            vec![boundary()],
            13,
            attempt(1).encode_payload().unwrap()[..31].to_vec(),
            FenceReason::Payload(RecordError::Truncated),
        ),
        (
            "truncated_fence",
            vec![boundary()],
            14,
            fence().encode_payload().unwrap()[..23].to_vec(),
            FenceReason::Payload(RecordError::Truncated),
        ),
        (
            "wrong_publication",
            vec![boundary()],
            13,
            Record::CommitAttempt {
                boundary_seq: 1,
                publication_id: [8; 16],
                attempt: 1,
            }
            .encode_payload()
            .unwrap(),
            FenceReason::Value(ValueError::CommitBinding { boundary_seq: 1 }),
        ),
        (
            "decreasing_attempt",
            vec![boundary(), attempt(1), attempt(2)],
            13,
            attempt(1).encode_payload().unwrap(),
            FenceReason::Value(ValueError::AttemptNotNext {
                previous: 2,
                attempt: 1,
            }),
        ),
        (
            "duplicate_attempt",
            vec![boundary(), attempt(1)],
            13,
            attempt(1).encode_payload().unwrap(),
            FenceReason::Value(ValueError::AttemptNotNext {
                previous: 1,
                attempt: 1,
            }),
        ),
        (
            "fence_without_boundary",
            vec![],
            14,
            fence().encode_payload().unwrap(),
            FenceReason::Value(ValueError::CommitBinding { boundary_seq: 1 }),
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
    assert_eq!(count, 6);
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_progress_v1.tsv"),
        &goldens,
    );
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_progress_v1_rejects.tsv"),
        &rejects,
    );
    let corpus = root.join("fuzz/corpus/overlay_journal_decode");
    for (label, bytes) in seeds {
        let path = corpus.join(format!("commit-{label}"));
        if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(path.with_extension("license"), LICENSE).unwrap();
        }
        let seed = std::fs::read(path).unwrap();
        assert_eq!(seed, bytes, "{label}: fuzz seed");
        granary_core::testkit::overlay_journal_decode_probe(&seed);
    }
}
