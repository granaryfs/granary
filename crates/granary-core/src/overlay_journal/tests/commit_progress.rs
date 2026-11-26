// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn commit_progress_wire_records_round_trip() {
    let h = header();
    let mut progress = 1u64.to_be_bytes().to_vec();
    progress.extend_from_slice(&[7; 16]);
    let mut charge = progress.clone();
    charge.extend_from_slice(&1u64.to_be_bytes());
    let bytes = journal_with_frame(
        &h,
        &[
            encode_record(&h, 1, &boundary(0)).unwrap(),
            raw_frame(&h, 13, 2, &charge),
            raw_frame(&h, 14, 3, &progress),
        ],
    );
    let scanned = scan_journal(&bytes);
    let actual = scanned
        .as_ref()
        .map(|scan| {
            (
                scan.end,
                scan.records.iter().map(Record::kind).collect::<Vec<_>>(),
            )
        })
        .map_err(std::string::ToString::to_string);
    assert_eq!(
        actual,
        Ok((JournalEnd::Clean, vec![11, 13, 14])),
        "admitted commit evidence"
    );
    let scan = scanned.unwrap();
    assert_eq!(encode_journal(&h, &scan.records).unwrap(), bytes);
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

#[test]
fn commit_progress_rejects_nonconsecutive_or_unbound_evidence() {
    let h = header();
    let cases = [
        (
            "duplicate",
            vec![boundary(0), attempt(1)],
            attempt(1),
            "journal commit attempt 1 does not follow 1",
        ),
        (
            "decreasing",
            vec![boundary(0), attempt(1), attempt(2)],
            attempt(1),
            "journal commit attempt 1 does not follow 2",
        ),
        (
            "skipped",
            vec![boundary(0)],
            attempt(2),
            "journal commit attempt 2 does not follow 0",
        ),
        (
            "wrong publication",
            vec![boundary(0)],
            Record::CommitAttempt {
                boundary_seq: 1,
                publication_id: [8; 16],
                attempt: 1,
            },
            "journal commit evidence names no matching open boundary 1",
        ),
        (
            "fence without boundary",
            vec![],
            fence(),
            "journal commit evidence names no matching open boundary 1",
        ),
        (
            "wrong fence publication",
            vec![boundary(0)],
            Record::CommitFence {
                boundary_seq: 1,
                publication_id: [8; 16],
            },
            "journal commit evidence names no matching open boundary 1",
        ),
        (
            "attempt after landing",
            vec![boundary(0), landed(1, 8)],
            attempt(1),
            "journal commit evidence names no matching open boundary 1",
        ),
    ];
    let mut count = 0;
    for (label, prefix, invalid, reason) in cases {
        let valid = encode_journal(&h, &prefix).unwrap();
        let control = scan_journal(&valid);
        assert!(control.is_ok(), "{label}: valid prefix: {control:?}");
        let mut malformed = valid;
        malformed.extend_from_slice(&encode_record(&h, prefix.len() as u64 + 1, &invalid).unwrap());
        let result = scan_journal(&malformed);
        assert_eq!(
            result.as_ref().err().map(|error| match &error.reason {
                FenceReason::Value(value) => value.to_string(),
                other => format!("{other:?}"),
            }),
            Some(reason.to_owned()),
            "{label}: {result:?}"
        );
        let mut invalid_records = prefix;
        invalid_records.push(invalid);
        assert!(
            encode_journal(&h, &invalid_records).is_err(),
            "{label}: encoder accepted invalid sequence"
        );
        count += 1;
    }
    assert_eq!(count, 7);
}

#[test]
fn commit_progress_payloads_reject_truncation_zero_and_trailing_bytes() {
    let mut count = 0;
    for record in [attempt(1), fence()] {
        let valid = record.encode_payload().unwrap();
        assert_eq!(
            Record::decode_payload(record.kind(), &valid),
            Ok(record.clone())
        );
        for length in 0..valid.len() {
            assert_eq!(
                Record::decode_payload(record.kind(), &valid[..length]),
                Err(RecordError::Truncated)
            );
            count += 1;
        }
        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            Record::decode_payload(record.kind(), &trailing),
            Err(RecordError::TrailingBytes)
        );
    }
    assert_eq!(attempt(0).encode_payload(), Err(RecordError::AttemptZero));
    for record in [
        Record::CommitAttempt {
            boundary_seq: 0,
            publication_id: [7; 16],
            attempt: 1,
        },
        Record::CommitFence {
            boundary_seq: 0,
            publication_id: [7; 16],
        },
    ] {
        assert!(
            matches!(
                record.encode_payload(),
                Err(RecordError::SeqOutOfRange { .. })
            ),
            "{record:?}"
        );
    }
    assert_eq!(count, 56);
}

#[test]
fn commit_progress_is_replayed_and_sync_class() {
    let records = [boundary(0), attempt(1), attempt(2), fence()];
    let bytes = encode_journal(&header(), &records).unwrap();
    let scan = scan_journal(&bytes).unwrap();
    assert_eq!(
        scan.state.commit_progress(&[7; 16]),
        Some(CommitProgress {
            attempts: 2,
            fenced: true
        })
    );
    assert_eq!(scan.state.commit_progress(&[8; 16]), None);
    assert!(records.iter().all(Record::is_sync_class));
    for (kind, length) in [(13, 32), (14, 24)] {
        assert_eq!(super::super::record::sync_payload_len(kind), Some(length));
    }
}

#[test]
fn commit_progress_decoder_refuses_decreasing_attempt() {
    let h = header();
    let mut bytes = encode_journal(&h, &[boundary(0), attempt(1), attempt(2)]).unwrap();
    bytes.extend_from_slice(&encode_record(&h, 4, &attempt(1)).unwrap());
    let result = scan_journal(&bytes);
    assert_eq!(
        result.as_ref().err().map(|error| error.reason),
        Some(FenceReason::Value(ValueError::AttemptNotNext {
            previous: 2,
            attempt: 1
        })),
        "decreasing attempt: {result:?}"
    );
}

#[test]
fn commit_progress_aggregates_matching_open_boundaries_without_resetting() {
    let records = [
        boundary(0),
        attempt(1),
        boundary(2),
        Record::CommitAttempt {
            boundary_seq: 3,
            publication_id: [7; 16],
            attempt: 1,
        },
        fence(),
    ];
    let bytes = encode_journal(&header(), &records).unwrap();
    let scan = scan_journal(&bytes).unwrap();
    assert_eq!(
        scan.state.commit_progress(&[7; 16]),
        Some(CommitProgress {
            attempts: 2,
            fenced: true
        })
    );
    let empty = scan_journal(&encode_journal(&header(), &[boundary(0)]).unwrap()).unwrap();
    assert_eq!(
        empty.state.commit_progress(&[7; 16]),
        Some(CommitProgress {
            attempts: 0,
            fenced: false
        })
    );
}

#[test]
fn commit_attempt_zero_has_an_attempt_refusal() {
    assert_eq!(
        attempt(0)
            .encode_payload()
            .map_err(|error| error.to_string()),
        Err("journal commit attempt is zero".to_owned())
    );
}
