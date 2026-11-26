// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn anchor(size: u64) -> RecreateAnchor {
    RecreateAnchor {
        content: grain(4),
        size,
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

/// A journal whose ids 1 to 4 were issued before it began.
fn carried() -> JournalHeader {
    JournalHeader {
        next_stage_id: 5,
        ..header()
    }
}

/// The payload laid out by hand: location tag and location, exec, stage id,
/// anchor tag, anchor content and size.
fn layout(at: &[u8], exec: u8, stage: u64, tag: u8, content: &[u8], size: u64) -> Vec<u8> {
    cat(&[at, &[exec], &u64b(stage), &[tag], content, &u64b(size)])
}

/// Location tag 1, then the root parent (depth 0) and the name `u`.
const NAMED: [u8; 5] = [1, 0, 0, 1, b'u'];

#[test]
fn recreate_payload_is_an_optional_location_then_a_fixed_optional_anchor() {
    let id = grain(4).to_bytes();
    let zero = [0u8; 33];
    let mut count = 0;
    for (record, bytes) in [
        (
            recreate(Some(loc(&[], "u")), 1, Some(anchor(9))),
            layout(&NAMED, 1, 1, 1, &id, 9),
        ),
        (
            recreate(Some(loc(&[], "u")), 2, None),
            layout(&NAMED, 1, 2, 0, &zero, 0),
        ),
        (
            recreate(None, 3, Some(anchor(9))),
            layout(&[0], 0, 3, 1, &id, 9),
        ),
        (recreate(None, 4, None), layout(&[0], 0, 4, 0, &zero, 0)),
    ] {
        assert_eq!(
            (
                record.encode_payload().as_ref(),
                Record::decode_payload(16, &bytes).as_ref(),
                record.is_sync_class(),
            ),
            (Ok(&bytes), Ok(&record), false),
            "{record:?}"
        );
        for length in 0..bytes.len() {
            assert_eq!(
                Record::decode_payload(16, &bytes[..length]),
                Err(RecordError::Truncated),
                "{record:?} cut at {length}"
            );
            count += 1;
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            Record::decode_payload(16, &trailing),
            Err(RecordError::TrailingBytes)
        );
        count += 1;
    }
    assert_eq!(count, 2 * 57 + 2 * 53);
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
fn recreate_payload_reject_vectors() {
    use RecordError as E;
    let id = grain(4).to_bytes();
    let zero = [0u8; 33];
    let mut nonzero_content = zero;
    nonzero_content[32] = 1;
    let cases: Vec<(&str, Vec<u8>, RecordError)> = vec![
        (
            "location tag 2",
            layout(&[2, 0, 0, 1, b'u'], 1, 1, 0, &zero, 0),
            E::BadPresenceTag {
                field: "location",
                tag: 2,
            },
        ),
        (
            "detached with exec",
            layout(&[0], 1, 1, 0, &zero, 0),
            E::MustBeZero { field: "exec" },
        ),
        (
            "exec byte 2",
            layout(&NAMED, 2, 1, 0, &zero, 0),
            E::BadExec { byte: 2 },
        ),
        (
            "location with an empty name",
            layout(&[1, 0, 0, 0], 0, 1, 0, &zero, 0),
            E::BadName(NameError::Empty),
        ),
        (
            "stage 0",
            layout(&[0], 0, 0, 0, &zero, 0),
            E::StageIdOutOfRange { stage_id: 0 },
        ),
        (
            "stage 2^63",
            layout(&[0], 0, STAGE_ID_MAX + 1, 0, &zero, 0),
            E::StageIdOutOfRange {
                stage_id: STAGE_ID_MAX + 1,
            },
        ),
        (
            "anchor tag 2",
            layout(&[0], 0, 1, 2, &id, 9),
            E::BadPresenceTag {
                field: "anchor",
                tag: 2,
            },
        ),
        (
            "no anchor with a content byte",
            layout(&[0], 0, 1, 0, &nonzero_content, 0),
            E::MustBeZero {
                field: "anchor content",
            },
        ),
        (
            "no anchor with a registered content id",
            layout(&[0], 0, 1, 0, &id, 0),
            E::MustBeZero {
                field: "anchor content",
            },
        ),
        (
            "no anchor with a size",
            layout(&[0], 0, 1, 0, &zero, 1),
            E::MustBeZero {
                field: "anchor size",
            },
        ),
        (
            "anchor content algorithm 0",
            layout(&[0], 0, 1, 1, &zero, 9),
            E::BadGrainId,
        ),
        (
            "anchor size 2^63",
            layout(&[0], 0, 1, 1, &id, SIZE_MAX + 1),
            E::SizeOutOfRange {
                value: SIZE_MAX + 1,
            },
        ),
    ];
    let h = carried();
    let mut count = 0;
    for (what, payload, want) in cases {
        let frame = raw_frame(&h, 16, 1, &payload);
        let fence = scan_journal(&journal_with_frame(&h, &[frame])).unwrap_err();
        assert_eq!(
            (
                Record::decode_payload(16, &payload),
                fence.offset,
                fence.reason
            ),
            (Err(want), JOURNAL_HEADER_LEN, FenceReason::Payload(want)),
            "{what}"
        );
        count += 1;
    }
    assert_eq!(count, 12);
    // The encoder refuses what the decoder rejects.
    let detached_exec = Record::RecreateFile {
        at: None,
        exec: true,
        stage_id: 1,
        anchor: None,
    };
    let mut refused = 0;
    for (record, want) in [
        (detached_exec, E::MustBeZero { field: "exec" }),
        (
            recreate(None, 0, None),
            E::StageIdOutOfRange { stage_id: 0 },
        ),
        (
            recreate(None, 1, Some(anchor(SIZE_MAX + 1))),
            E::SizeOutOfRange {
                value: SIZE_MAX + 1,
            },
        ),
    ] {
        assert_eq!(record.encode_payload(), Err(want), "{record:?}");
        refused += 1;
    }
    assert_eq!(refused, 3);
}

#[test]
fn recreate_value_rule_reject_vectors() {
    use ValueError as V;
    let cases = [
        (
            "an id never issued",
            vec![recreate(None, 5, None)],
            (
                0,
                V::RecreateNotIssued {
                    stage_id: 5,
                    next: 5,
                },
            ),
        ),
        (
            "an id bound twice",
            vec![
                recreate(None, 1, None),
                recreate(Some(loc(&[], "u")), 1, None),
            ],
            (1, V::StageAlreadyBound { stage_id: 1 }),
        ),
        (
            "an id a re-bind holds",
            vec![
                bind(BindCause::Rebind, 2, 0),
                recreate(None, 2, Some(anchor(9))),
            ],
            (1, V::StageAlreadyBound { stage_id: 2 }),
        ),
        (
            "an id this journal issued",
            vec![file(5), recreate(None, 5, None)],
            (1, V::StageAlreadyBound { stage_id: 5 }),
        ),
        (
            "a create past the unchanged counter",
            vec![recreate(None, 4, None), file(6)],
            (
                1,
                V::StageIdNotNext {
                    expected: 5,
                    found: 6,
                },
            ),
        ),
        (
            "a mark above the anchor size",
            vec![recreate(None, 1, Some(anchor(9))), synced(1, 10, 1)],
            (
                1,
                V::SyncedExceedsStaged {
                    synced_size: 10,
                    staged_size: 9,
                },
            ),
        ),
        (
            "a mark on an empty recreate",
            vec![recreate(None, 1, None), synced(1, 1, 1)],
            (
                1,
                V::SyncedExceedsStaged {
                    synced_size: 1,
                    staged_size: 0,
                },
            ),
        ),
    ];
    let mut count = 0;
    for (what, records, want) in cases {
        assert_eq!(value_error(&carried(), &records), want, "{what}");
        let control = encode_journal(&carried(), &records[..want.0]);
        assert!(control.is_ok(), "{what}: valid prefix {control:?}");
        count += 1;
    }
    assert_eq!(count, 7);
}

#[test]
fn recreate_binds_its_issued_id_with_the_anchor_size_and_keeps_the_counter() {
    let records = vec![
        recreate(Some(loc(&[], "u")), 1, Some(anchor(9))),
        recreate(Some(loc(&[], "v")), 2, None),
        recreate(None, 3, Some(anchor(9))),
        recreate(None, 4, None),
        extent(4, 2, 3),
        synced(1, 9, 1),
        file(5),
    ];
    let bytes = encode_journal(&carried(), &records).unwrap();
    let scan = scan_journal(&bytes).unwrap();
    let stages: Vec<_> = (1..=5).map(|id| scan.state.stage(id).copied()).collect();
    let stage = |size, synced_size, bound_at| {
        Some(StageState {
            size,
            synced_size,
            bound_at,
        })
    };
    assert_eq!(
        (
            scan.records.as_slice(),
            stages,
            scan.state.next_stage_id(),
            encode_journal(&scan.header, &scan.records).as_ref(),
        ),
        (
            &records[..],
            vec![
                stage(9, Some(9), 1),
                stage(0, None, 2),
                stage(9, None, 3),
                stage(5, None, 4),
                stage(0, None, 7),
            ],
            6,
            Ok(&bytes),
        )
    );
}

#[test]
fn recreate_is_an_ordinary_record_a_tear_can_cut_and_names_its_staging_file() {
    let h = carried();
    let records = vec![recreate(None, 1, Some(anchor(9))), recreate(None, 2, None)];
    let bytes = encode_journal(&h, &records).unwrap();
    let bounds = frame_bounds(&h, &records);
    // A hole before a check-valid recreate is a tear: it witnesses nothing.
    let mut holed = bytes.clone();
    holed[bounds[0]..bounds[1]].fill(0);
    let scan = scan_journal(&holed).unwrap();
    assert_eq!(
        (scan.records.len(), scan.valid_len, scan.end),
        (
            0,
            bounds[0],
            JournalEnd::Torn(TornCause::LengthOutOfRange { len: 0 })
        )
    );
    // The recreate names stage 1's staging file, so its valid mark is not
    // unnamed recovery evidence; stage 3, which no record names, is.
    let marked = |stage_id| StagingHeader {
        writer: h.writer,
        stage_id,
        mark: MarkState::Present(SyncedMark {
            synced_size: 9,
            content: grain(4),
            generation: 1,
        }),
    };
    let named = codec_scan(&bytes);
    assert_eq!(
        (
            named.classify_staging(1, &marked(1)),
            named.classify_staging(3, &marked(3)),
        ),
        (
            Ok(StagingDisposition::Named),
            Ok(StagingDisposition::RecoveryEvidence)
        )
    );
}

fn codec_scan(bytes: &[u8]) -> JournalScan {
    scan_journal_with(bytes, |_, _| {}).unwrap()
}
