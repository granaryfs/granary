// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn selected(stage_id: u64) -> ProjectedSelection {
    ProjectedSelection {
        stage_id,
        content: grain(4),
        size: 9,
    }
}

fn projected(through: u64, selection: Option<ProjectedSelection>) -> Record {
    Record::ProjectedBoundary {
        candidate: grain(6),
        through_seq: through,
        publication_id: [7; 16],
        selection,
    }
}

/// The boundary tuple's bytes, laid out by hand: candidate, through seq and
/// publication id, as kind 11 has them.
fn tuple(through: u64) -> Vec<u8> {
    cat(&[&grain(6).to_bytes(), &u64b(through), &[7; 16]])
}

#[test]
fn projected_boundary_payload_is_the_boundary_tuple_then_a_fixed_selection() {
    let file = cat(&[&tuple(2), &[1], &u64b(1), &grain(4).to_bytes(), &u64b(9)]);
    let none = cat(&[&tuple(2), &[0; 50]]);
    let mut count = 0;
    for (record, bytes) in [
        (projected(2, Some(selected(1))), file),
        (projected(2, None), none),
    ] {
        assert_eq!(
            (
                bytes.len(),
                record.encode_payload().as_ref(),
                Record::decode_payload(15, &bytes).as_ref()
            ),
            (107, Ok(&bytes), Ok(&record)),
            "{record:?}"
        );
        for length in 0..bytes.len() {
            assert_eq!(
                Record::decode_payload(15, &bytes[..length]),
                Err(RecordError::Truncated),
                "{record:?} cut at {length}"
            );
            count += 1;
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            Record::decode_payload(15, &trailing),
            Err(RecordError::TrailingBytes)
        );
        count += 1;
    }
    assert_eq!(count, 216);
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
fn projected_boundary_payload_reject_vectors() {
    use RecordError as E;
    let id = grain(4).to_bytes();
    let selection = |tag: u8, stage: u64, content: &[u8], size: u64| {
        cat(&[&tuple(2), &[tag], &u64b(stage), content, &u64b(size)])
    };
    let zero = [0u8; 33];
    let mut nonzero_content = zero;
    nonzero_content[32] = 1;
    let cases: Vec<(&str, Vec<u8>, RecordError)> = vec![
        (
            "none with a stage id",
            selection(0, 1, &zero, 0),
            E::MustBeZero {
                field: "selected stage id",
            },
        ),
        (
            "none with a content byte",
            selection(0, 0, &nonzero_content, 0),
            E::MustBeZero {
                field: "selected content",
            },
        ),
        (
            "none with a registered content id",
            selection(0, 0, &id, 0),
            E::MustBeZero {
                field: "selected content",
            },
        ),
        (
            "none with a size",
            selection(0, 0, &zero, 1),
            E::MustBeZero {
                field: "selected size",
            },
        ),
        (
            "tag 2",
            selection(2, 1, &id, 9),
            E::BadSelectionTag { tag: 2 },
        ),
        (
            "tag 0xFF",
            selection(0xFF, 0, &zero, 0),
            E::BadSelectionTag { tag: 0xFF },
        ),
        (
            "file stage 0",
            selection(1, 0, &id, 9),
            E::StageIdOutOfRange { stage_id: 0 },
        ),
        (
            "file stage 2^63",
            selection(1, STAGE_ID_MAX + 1, &id, 9),
            E::StageIdOutOfRange {
                stage_id: STAGE_ID_MAX + 1,
            },
        ),
        (
            "file content algorithm 0",
            selection(1, 1, &zero, 9),
            E::BadGrainId,
        ),
        (
            "file content tag 0xFF",
            selection(1, 1, &[0xFF; 33], 9),
            E::BadGrainId,
        ),
        (
            "file size 2^63",
            selection(1, 1, &id, SIZE_MAX + 1),
            E::SizeOutOfRange {
                value: SIZE_MAX + 1,
            },
        ),
        (
            "candidate algorithm 0",
            cat(&[&zero, &tuple(2)[33..], &[0; 50]]),
            E::BadGrainId,
        ),
    ];
    let h = header();
    let mut count = 0;
    for (what, payload, want) in cases {
        assert_eq!(payload.len(), 107, "{what}");
        let frame = raw_frame(&h, 15, 1, &payload);
        let fence = scan_journal(&journal_with_frame(&h, &[frame])).unwrap_err();
        assert_eq!(
            (
                Record::decode_payload(15, &payload),
                fence.offset,
                fence.reason
            ),
            (Err(want), JOURNAL_HEADER_LEN, FenceReason::Payload(want)),
            "{what}"
        );
        count += 1;
    }
    assert_eq!(count, 12);
    // The encoder refuses the selections the decoder rejects.
    for (bad, want) in [
        (0, E::StageIdOutOfRange { stage_id: 0 }),
        (
            STAGE_ID_MAX + 1,
            E::StageIdOutOfRange {
                stage_id: STAGE_ID_MAX + 1,
            },
        ),
    ] {
        assert_eq!(
            projected(2, Some(selected(bad))).encode_payload(),
            Err(want)
        );
    }
    let oversized = projected(
        2,
        Some(ProjectedSelection {
            stage_id: 1,
            content: grain(4),
            size: SIZE_MAX + 1,
        }),
    );
    assert_eq!(
        oversized.encode_payload(),
        Err(E::SizeOutOfRange {
            value: SIZE_MAX + 1
        })
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
fn projected_boundary_value_rule_reject_vectors() {
    use ValueError as V;
    let attempt = |publication: u8, n: u64| Record::CommitAttempt {
        boundary_seq: 2,
        publication_id: [publication; 16],
        attempt: n,
    };
    let cases = [
        (
            "unbound selected stage",
            vec![file(1), projected(1, Some(selected(2)))],
            (1, V::UnknownStage { stage_id: 2 }),
        ),
        (
            "selection before its stage",
            vec![projected(0, Some(selected(1))), file(1)],
            (0, V::UnknownStage { stage_id: 1 }),
        ),
        (
            "selection bound after its through seq",
            vec![file(1), file(2), projected(1, Some(selected(2)))],
            (
                2,
                V::SelectionAfterThrough {
                    stage_id: 2,
                    bound_at: 2,
                    through_seq: 1,
                },
            ),
        ),
        (
            "selection with an empty prefix",
            vec![file(1), projected(0, Some(selected(1)))],
            (
                1,
                V::SelectionAfterThrough {
                    stage_id: 1,
                    bound_at: 1,
                    through_seq: 0,
                },
            ),
        ),
        (
            "prefix ends before an open whole-tree boundary",
            vec![boundary(0), projected(0, None)],
            (
                1,
                V::ThroughBelowOpenBoundary {
                    through_seq: 0,
                    boundary_seq: 1,
                },
            ),
        ),
        (
            "prefix reaches the first of two open boundaries only",
            vec![boundary(0), boundary(1), projected(1, None)],
            (
                2,
                V::ThroughBelowOpenBoundary {
                    through_seq: 1,
                    boundary_seq: 2,
                },
            ),
        ),
        (
            "prefix ends before an open projected boundary",
            vec![file(1), projected(1, None), projected(1, Some(selected(1)))],
            (
                2,
                V::ThroughBelowOpenBoundary {
                    through_seq: 1,
                    boundary_seq: 2,
                },
            ),
        ),
        (
            "through seq at its own seq",
            vec![file(1), projected(2, None)],
            (
                1,
                V::BoundaryThroughNotBelowSeq {
                    through_seq: 2,
                    seq: 2,
                },
            ),
        ),
        (
            "attempt for another publication",
            vec![file(1), projected(1, Some(selected(1))), attempt(8, 1)],
            (2, V::CommitBinding { boundary_seq: 2 }),
        ),
        (
            "attempt skipping one",
            vec![file(1), projected(1, Some(selected(1))), attempt(7, 2)],
            (
                2,
                V::AttemptNotNext {
                    previous: 0,
                    attempt: 2,
                },
            ),
        ),
        (
            "second landing",
            vec![file(1), projected(1, None), landed(2, 8), landed(2, 9)],
            (3, V::NoOpenBoundary { boundary_seq: 2 }),
        ),
    ];
    let mut count = 0;
    for (what, records, want) in cases {
        assert_eq!(value_error(&header(), &records), want, "{what}");
        let control = encode_journal(&header(), &records[..want.0]);
        assert!(control.is_ok(), "{what}: valid prefix {control:?}");
        count += 1;
    }
    assert_eq!(count, 11);
    // Controls: a prefix reaching the open boundary, or one past a landed
    // boundary, is admitted.
    for records in [
        vec![boundary(0), projected(1, None)],
        vec![boundary(0), landed(1, 8), projected(0, None)],
    ] {
        let control = encode_journal(&header(), &records);
        assert!(control.is_ok(), "{records:?}: {control:?}");
    }
}

#[test]
fn projected_boundary_opens_the_commit_family_boundary() {
    let records = [
        file(1),
        projected(1, Some(selected(1))),
        Record::CommitAttempt {
            boundary_seq: 2,
            publication_id: [7; 16],
            attempt: 1,
        },
        Record::CommitFence {
            boundary_seq: 2,
            publication_id: [7; 16],
        },
    ];
    let bytes = encode_journal(&header(), &records).unwrap();
    let open = scan_journal(&bytes).unwrap();
    let mut landed_bytes = bytes.clone();
    landed_bytes.extend_from_slice(&encode_record(&header(), 5, &landed(2, 8)).unwrap());
    let answered = scan_journal(&landed_bytes).unwrap();
    assert_eq!(
        (
            open.records.as_slice(),
            open.state.open_boundaries().collect::<Vec<_>>(),
            open.state.commit_progress(&[7; 16]),
            answered.state.open_boundaries().count(),
            answered.state.commit_progress(&[7; 16]),
        ),
        (
            &records[..],
            vec![2],
            Some(CommitProgress {
                attempts: 1,
                fenced: true
            }),
            0,
            None,
        )
    );
    assert_eq!(
        encode_journal(&header(), &answered.records).unwrap(),
        landed_bytes
    );
}

#[test]
fn projected_boundary_is_sync_class_with_a_fixed_witness_length() {
    assert_eq!(
        (
            projected(0, None).is_sync_class(),
            super::super::record::sync_payload_len(15),
            super::super::record::sync_payload_len(16),
        ),
        (true, Some(107), None)
    );
    let h = header();
    let ordinary = Record::Create {
        at: loc(&[], "d"),
        kind: CreateKind::Dir,
    };
    let records = vec![file(1), ordinary, projected(1, Some(selected(1)))];
    let bytes = encode_journal(&h, &records).unwrap();
    let bounds = frame_bounds(&h, &records);
    // A hole before a projected boundary was durable damage: it witnesses.
    let mut holed = bytes.clone();
    holed[bounds[1]..bounds[2]].fill(0);
    let fence = scan_journal(&holed).unwrap_err();
    assert_eq!(
        (fence.offset, fence.reason),
        (
            bounds[1],
            FenceReason::MidFileDamage {
                cause: TornCause::LengthOutOfRange { len: 0 },
                witness: bounds[2]
            }
        )
    );
    // A check-valid kind-15 frame one byte longer than the fixed payload is
    // no witness, so the same hole before it is a tear.
    let mut long = projected(1, Some(selected(1))).encode_payload().unwrap();
    long.push(0);
    let mut unwitnessed = bytes[..bounds[2]].to_vec();
    unwitnessed[bounds[1]..bounds[2]].fill(0);
    unwitnessed.extend_from_slice(&raw_frame(&h, 15, 3, &long));
    let scan = scan_journal(&unwitnessed).unwrap();
    assert_eq!(
        (scan.records.len(), scan.valid_len, scan.end),
        (
            1,
            bounds[1],
            JournalEnd::Torn(TornCause::LengthOutOfRange { len: 0 })
        )
    );
    // Every cut inside the final projected boundary is a tear at its start.
    let mut count = 0;
    for cut in bounds[2] + 1..bounds[3] {
        let scan = scan_journal(&bytes[..cut]).unwrap();
        assert_eq!(
            (
                scan.records.len(),
                scan.valid_len,
                matches!(scan.end, JournalEnd::Torn(_))
            ),
            (2, bounds[2], true),
            "cut at {cut}"
        );
        count += 1;
    }
    assert_eq!(count, 151);
}
