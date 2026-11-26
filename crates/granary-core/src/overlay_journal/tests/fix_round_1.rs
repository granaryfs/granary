// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Review regressions and executable examples of the replay contract.

use super::*;

#[test]
fn unnamed_synced_staging_is_recovery_evidence() {
    let mut bytes = golden_journal()[..473].to_vec();
    bytes[176..473].fill(0);
    let scan = scan_journal(&bytes).unwrap();
    assert_eq!(scan.valid_len, 176);
    assert!(scan.state.stage(1).is_none());
    let stage = StagingHeader::decode(&unhex(STAGING_MARK_HEX)).unwrap();
    assert!(matches!(stage.mark, MarkState::Present(_)));
    assert_eq!(
        scan.classify_staging(1, &stage),
        Ok(StagingDisposition::RecoveryEvidence)
    );
}

#[test]
fn replacement_counters_are_captured_at_the_boundary() {
    let old = vec![file(1), boundary(1), file(2), synced(2, 0, 1), landed(2, 8)];
    let old_scan = scan_journal(&encode_journal(&header(), &old).unwrap()).unwrap();
    assert_eq!(old_scan.state.next_stage_id(), 3);
    let replacement = JournalHeader {
        base_seq: 8,
        next_stage_id: 2,
        ..header()
    };
    let retained = &old[2..4];
    assert!(scan_journal(&encode_journal(&replacement, retained).unwrap()).is_ok());
    let wrong = JournalHeader {
        next_stage_id: 3,
        receipt_generation: 1,
        ..replacement
    };
    assert!(encode_journal(&wrong, retained).is_err());
}

#[test]
fn replacement_remaps_both_sequence_references_and_allows_empty_prefix() {
    let retained = vec![boundary(0), landed(1, 9)];
    let h = JournalHeader {
        base_seq: 8,
        ..header()
    };
    let bytes = encode_journal(&h, &retained).unwrap();
    assert!(scan_journal(&bytes).is_ok());
}

#[test]
fn partial_overwrite_retires_the_old_whole_extent_check() {
    assert_ne!(extent_check(1, 0, b"ABCD"), extent_check(1, 0, b"AXCD"));
    let checked = |offset, data: &[u8]| Record::WriteExtent {
        stage_id: 1,
        offset,
        length: data.len() as u64,
        check: extent_check(1, offset, data),
    };
    let records = [
        checked(0, b"ABCD"),
        checked(1, b"X"),
        checked(0, b"A"),
        checked(2, b"CD"),
    ];
    let final_bytes = b"AXCD";
    let mut live = 0;
    for (i, record) in records.iter().enumerate() {
        if records[i + 1..]
            .iter()
            .any(|later| record.extent_superseded_by(later))
        {
            continue;
        }
        if let Record::WriteExtent {
            stage_id,
            offset,
            length,
            check,
        } = record
        {
            assert_eq!(
                *check,
                extent_check(
                    *stage_id,
                    *offset,
                    &final_bytes[usize::try_from(*offset).unwrap()
                        ..usize::try_from(*offset + *length).unwrap()]
                )
            );
            live += 1;
        }
    }
    assert_eq!(live, 3);
}

#[test]
fn replacement_reserve_includes_rebind_growth() {
    let at = |id| {
        loc(
            &[],
            &char::from(b'a' + u8::try_from(id - 1).unwrap()).to_string(),
        )
    };
    let creates: Vec<_> = (1..=10)
        .map(|id| Record::Create {
            at: at(id),
            kind: CreateKind::File {
                exec: false,
                stage_id: id,
            },
        })
        .collect();
    let mut old = creates.clone();
    old.push(boundary(10));
    old.extend((1..=10).map(|id| extent(id, 0, 1)));
    old.push(landed(11, 8));
    let old_len = encode_journal(&header(), &old).unwrap().len();
    let h = JournalHeader {
        next_stage_id: 11,
        base_seq: 8,
        ..header()
    };
    let mut retained: Vec<_> = (1..=10)
        .map(|id| Record::StageBind {
            at: at(id),
            cause: BindCause::Rebind,
            stage_id: id,
            staged_size: 0,
            base_content: grain(3),
        })
        .collect();
    retained.extend((1..=10).map(|id| extent(id, 0, 1)));
    let new_len = encode_journal(&h, &retained).unwrap().len();
    assert_eq!(old_len, 1913);
    assert_eq!(new_len, 2117);
    assert!(new_len > old_len);
}

#[test]
fn equal_generations_require_the_same_prepared_root() {
    let intent = |root| Record::IntentRegistered {
        generation: 1,
        prepared_root: grain(root),
        cause: IntentCause::DirectorySync,
    };
    assert!(encode_journal(&header(), &[intent(1), intent(1)]).is_ok());
    assert!(encode_journal(&header(), &[intent(1), intent(2)]).is_err());
    let frames = [
        encode_record(&header(), 1, &intent(1)).unwrap(),
        encode_record(&header(), 2, &intent(2)).unwrap(),
    ];
    assert!(scan_journal(&journal_with_frame(&header(), &frames)).is_err());
}

#[test]
fn scan_retains_no_record_collection() {
    let source = include_str!("../scan.rs");
    assert!(!source.contains("pub records: Vec<Record>"));
    assert!(!source.contains("records.push(record)"));
    for state in ["JournalState", "StageState", "JournalScan"] {
        let fields = source
            .split(&format!("pub struct {state} {{"))
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        for unbounded in ["Vec<", "Record", "Parent", "Location", "Name"] {
            assert!(!fields.contains(unbounded), "{state} retains {unbounded}");
        }
    }
}

#[test]
fn encode_delete_zero_reports_the_stage_id_refusal() {
    let r = Record::Delete {
        at: loc(&[], "x"),
        kind: DeleteKind::File { stage_id: Some(0) },
    };
    assert_eq!(
        r.encode_payload(),
        Err(RecordError::StageIdOutOfRange { stage_id: 0 })
    );
}

#[test]
fn encode_validates_payload_before_value_rules() {
    let r = Record::WriteExtent {
        stage_id: 1,
        offset: 0,
        length: 0,
        check: [0; 32],
    };
    assert_eq!(
        encode_journal(&header(), &[r]),
        Err(EncodeError::Record {
            index: 0,
            error: RecordError::ExtentEmpty
        })
    );
}

#[test]
fn staging_probe_skips_only_damaged_marks() {
    let source = include_str!("../../testkit.rs");
    assert!(source.contains("header.mark != MarkState::Damaged"));
    crate::testkit::overlay_journal_decode_probe(&unhex(STAGING_MARK_HEX));
}

#[test]
fn mark_generation_max_matches_the_single_bounds_table() {
    let mut h = StagingHeader::decode(&unhex(STAGING_MARK_HEX)).unwrap();
    if let MarkState::Present(ref mut mark) = h.mark {
        mark.generation = GENERATION_MAX;
    }
    assert_eq!(StagingHeader::decode(&h.encode().unwrap()), Ok(h));
}

#[test]
fn short_journal_checks_present_magic_before_length() {
    for len in 8..JOURNAL_HEADER_LEN {
        let bytes = vec![b'X'; len];
        assert_eq!(
            scan_journal(&bytes).unwrap_err().reason,
            FenceReason::Header(HeaderError::BadMagic)
        );
    }
    assert_eq!(
        scan_journal(b"GRNOVJRN").unwrap_err().reason,
        FenceReason::Header(HeaderError::BadLength { len: 8 })
    );
}

#[test]
fn staging_classification_checks_binding_and_keeps_named_files() {
    let scan = scan_journal(&header().encode().unwrap()).unwrap();
    let absent = StagingHeader::decode(&unhex(STAGING_ABSENT_HEX)).unwrap();
    assert_eq!(
        scan.classify_staging(1, &absent),
        Ok(StagingDisposition::Sweep)
    );
    assert_eq!(
        scan.classify_staging(2, &absent),
        Err(BindingError::StageIdMismatch)
    );
    let other = StagingHeader {
        writer: [0; 16],
        ..absent
    };
    assert_eq!(
        scan.classify_staging(1, &other),
        Err(BindingError::WriterMismatch)
    );
    let damaged = StagingHeader {
        mark: MarkState::Damaged,
        ..absent
    };
    assert_eq!(
        scan.classify_staging(1, &damaged),
        Ok(StagingDisposition::Sweep)
    );
    let named = scan_journal(&encode_journal(&header(), &[file(1)]).unwrap()).unwrap();
    assert_eq!(
        named.classify_staging(1, &absent),
        Ok(StagingDisposition::Named)
    );
    let marked = StagingHeader::decode(&unhex(STAGING_MARK_HEX)).unwrap();
    assert_eq!(
        named.classify_staging(1, &marked),
        Ok(StagingDisposition::Named)
    );
    // A clean end also needs the evidence check: damage can remove whole frames.
    assert_eq!(
        scan.classify_staging(1, &marked),
        Ok(StagingDisposition::RecoveryEvidence)
    );
}

#[test]
fn extent_retirement_obeys_stage_intersection_and_truncate() {
    let r = extent(1, 4, 4);
    assert!(r.extent_superseded_by(&extent(1, 5, 1)));
    assert!(r.extent_superseded_by(&extent(1, 0, 5)));
    for later in [
        extent(1, 8, 1),
        extent(1, 0, 4),
        extent(2, 5, 1),
        synced(1, 0, 1),
    ] {
        assert!(!r.extent_superseded_by(&later));
    }
    assert!(r.extent_superseded_by(&Record::Truncate {
        stage_id: 1,
        new_size: 7
    }));
    for (stage_id, new_size) in [(1, 8), (1, 9), (2, 7)] {
        assert!(!r.extent_superseded_by(&Record::Truncate { stage_id, new_size }));
    }
    assert!(!file(1).extent_superseded_by(&extent(1, 0, 1)));
}

#[test]
fn equal_generation_binding_covers_both_receipt_kinds_and_is_atomic() {
    let intent = Record::IntentRegistered {
        generation: 1,
        prepared_root: grain(1),
        cause: IntentCause::DirectorySync,
    };
    let mut same = synced(1, 0, 1);
    if let Record::FileSynced { prepared_root, .. } = &mut same {
        *prepared_root = grain(1);
    }
    for records in [
        vec![file(1), intent.clone(), same.clone()],
        vec![file(1), same.clone(), intent.clone()],
    ] {
        assert!(encode_journal(&header(), &records).is_ok());
    }
    let mut state = JournalState::new(&header());
    state.admit(&file(1)).unwrap();
    state.admit(&intent).unwrap();
    let before = format!("{state:?}");
    assert_eq!(
        state.admit(&synced(1, 0, 1)),
        Err(ValueError::GenerationRootMismatch { generation: 1 })
    );
    assert_eq!(format!("{state:?}"), before);
    let err = value_error(&header(), &[file(1), intent, synced(1, 0, 1)]);
    assert_eq!(
        err,
        (2, ValueError::GenerationRootMismatch { generation: 1 })
    );
}

#[test]
fn streaming_deep_moves_at_the_file_bound_keep_only_fixed_state() {
    // The source assertion fails before a retaining mutation can allocate
    // the old scanner's 1+ GiB of decoded paths (256 Names per record).
    scan_retains_no_record_collection();
    let mut bytes = header().encode().unwrap();
    let at = Location {
        parent: Parent::new(vec![name("x"); 128]).unwrap(),
        name: name("y"),
    };
    let record = Record::Move {
        from: at.clone(),
        to: at,
    };
    let mut seq = 1;
    loop {
        let frame = encode_record(&header(), seq, &record).unwrap();
        if bytes.len() + frame.len() > JOURNAL_MAX {
            break;
        }
        bytes.extend_from_slice(&frame);
        seq += 1;
    }
    let mut visits = 0;
    let scan = scan_journal_with(&bytes, |n, r| {
        visits += 1;
        assert_eq!(n, visits);
        assert_eq!(*r, record);
    })
    .unwrap();
    assert_eq!(visits, seq - 1);
    assert_eq!(scan.state.next_seq(), seq);
    assert_eq!(scan.state.next_stage_id(), 1);
    assert_eq!(scan.state.open_boundaries().count(), 0);
    assert!(std::mem::size_of::<JournalScan>() < 1024);
    assert!(format!("{:?}", scan.state).len() < 1024);
    assert_eq!(scan.valid_len, bytes.len());
}

#[test]
fn witness_requires_the_registered_kind_seq_and_check() {
    let h = header();
    let good = Record::IntentRegistered {
        generation: 1,
        prepared_root: grain(1),
        cause: IntentCause::DirectorySync,
    };
    let mut tail = h.encode().unwrap();
    tail.extend_from_slice(&[0; 4]);
    let at = tail.len();
    let frame = encode_record(&h, 1, &good).unwrap();
    // A check-valid impossible payload remains conservative evidence: a
    // malformed synced frame cannot authorise dropping the preceding hole.
    let mut bad_payload = good.encode_payload().unwrap();
    bad_payload[..8].fill(0);
    let bad = raw_frame(&h, 10, 1, &bad_payload);
    let mut damaged = tail.clone();
    damaged.extend_from_slice(&bad);
    assert!(
        matches!(scan_journal(&damaged).unwrap_err().reason, FenceReason::MidFileDamage { witness, .. } if witness == at)
    );
    for non_witness in [
        raw_frame(&h, 5, 1, &good.encode_payload().unwrap()),
        raw_frame(&h, 10, 0, &good.encode_payload().unwrap()),
        flip(&frame, frame.len() - 1, 0),
        encode_record(&JournalHeader { base_seq: 9, ..h }, 1, &good).unwrap(),
    ] {
        let mut bytes = tail.clone();
        bytes.extend_from_slice(&non_witness);
        assert!(matches!(
            scan_journal(&bytes).unwrap().end,
            JournalEnd::Torn(_)
        ));
    }
    // The valid case proves the negative controls are not simply disabling witnesses.
    tail.extend_from_slice(&frame);
    assert!(
        matches!(scan_journal(&tail).unwrap_err().reason, FenceReason::MidFileDamage { witness, .. } if witness == at)
    );
}

#[test]
fn replacement_receipt_floor_handles_a_generation_spanning_the_boundary() {
    let intent = Record::IntentRegistered {
        generation: 1,
        prepared_root: grain(2),
        cause: IntentCause::DirectorySync,
    };
    let old = [
        file(1),
        intent.clone(),
        boundary(2),
        intent.clone(),
        landed(3, 8),
    ];
    assert!(encode_journal(&header(), &old).is_ok());
    let bad = JournalHeader {
        base_seq: 8,
        next_stage_id: 2,
        receipt_generation: 1,
        ..header()
    };
    assert!(encode_journal(&bad, std::slice::from_ref(&intent)).is_err());
    let good = JournalHeader {
        receipt_generation: 0,
        ..bad
    };
    let scan = scan_journal(&encode_journal(&good, &[intent]).unwrap()).unwrap();
    assert_eq!(scan.state.highest_generation(), 1);
}

#[test]
fn visitor_seqs_and_prefix_are_provisional_until_the_scan_finishes() {
    let bytes = golden_journal();
    let mut visits = Vec::new();
    let summary = scan_journal_with(&bytes, |seq, r| visits.push((seq, r.kind()))).unwrap();
    assert_eq!(
        visits,
        vec![(1, 1), (2, 1), (3, 3), (4, 9), (5, 5), (6, 11)]
    );
    assert_eq!(summary.state.next_seq(), 7);
    let frame = raw_frame(&header(), 99, 7, &[]);
    let mut refused = bytes.clone();
    refused.extend_from_slice(&frame);
    let mut count = 0;
    assert!(scan_journal_with(&refused, |_, _| count += 1).is_err());
    assert_eq!(count, 6);
}

#[test]
fn helpers_reuse_the_cursor_header_check_and_staging_layout() {
    let codec = include_str!("../../overlay_journal.rs");
    assert!(codec.contains("struct Reader<'a>(crate::encoding::Cursor<'a>)"));
    let scan = include_str!("../scan.rs");
    let encoder = scan
        .split("pub fn encode_journal")
        .nth(1)
        .unwrap()
        .split("pub enum TornCause")
        .next()
        .unwrap();
    assert_eq!(encoder.matches("header.check()").count(), 1);
    let kit = include_str!("../../testkit.rs");
    let recheck = kit
        .split("pub(crate) fn overlay_staging_recheck_input")
        .nth(1)
        .unwrap()
        .split("/// Fuzz body")
        .next()
        .unwrap();
    assert!(recheck.contains("MARK_OFFSET") && recheck.contains("STAGING_IDENTITY_LEN"));
    assert!(!recheck.contains("const IDENTITY_LEN") && !recheck.contains("const MARK_AT"));
}
