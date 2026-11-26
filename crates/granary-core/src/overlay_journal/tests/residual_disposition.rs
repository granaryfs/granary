// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn payload() -> Vec<u8> {
    cat(&[
        &u64b(2),
        &[7; 16],
        &grain(9).to_bytes(),
        &u64b(8),
        &u64b(4),
        &[2],
        &1u32.to_be_bytes(),
        &[3; 32],
    ])
}

fn source() -> Vec<Record> {
    vec![
        Record::Create {
            at: loc(&[], "f"),
            kind: CreateKind::File {
                exec: false,
                stage_id: 1,
            },
        },
        boundary(1),
        Record::LandedCommit {
            boundary_seq: 2,
            landed_root: grain(9),
            landed_seq: 8,
        },
        Record::IntentRegistered {
            generation: 1,
            prepared_root: grain(9),
            cause: IntentCause::LandedRefresh,
        },
    ]
}

#[test]
fn residual_disposition_payload_round_trip() {
    let bytes = payload();
    let actual = Record::decode_payload(17, &bytes)
        .and_then(|r| Ok((r.kind(), r.is_sync_class(), r.encode_payload()?)));
    assert_eq!(actual, Ok((17, true, bytes)));
}

#[test]
fn residual_disposition_replays_and_is_terminal() {
    let h = header();
    let mut bytes = encode_journal(&h, &source()).unwrap();
    bytes.extend(raw_frame(&h, 17, 5, &payload()));
    let actual = scan_journal(&bytes).map(|scan| {
        (
            scan.end,
            scan.state.next_seq(),
            scan.state.next_stage_id(),
            scan.state.highest_generation(),
        )
    });
    assert_eq!(actual, Ok((JournalEnd::Clean, 6, 2, 1)));
    for next in [
        Record::Truncate {
            stage_id: 1,
            new_size: 0,
        },
        Record::decode_payload(17, &{
            let mut p = payload();
            p[65..73].copy_from_slice(&5u64.to_be_bytes());
            p
        })
        .unwrap(),
    ] {
        let mut followed = bytes.clone();
        followed.extend(encode_record(&h, 6, &next).unwrap());
        assert_eq!(
            scan_journal(&followed).unwrap_err().reason.to_string(),
            "journal record follows residual disposition"
        );
    }
    let frame = raw_frame(&h, 17, 5, &payload());
    let prefix = encode_journal(&h, &source()).unwrap();
    for cut in 0..155 {
        let mut torn = prefix.clone();
        torn.extend_from_slice(&frame[..cut]);
        let scan = scan_journal(&torn).unwrap();
        assert_eq!(
            (scan.state.residual_disposition(), scan.valid_len),
            (None, prefix.len()),
            "cut {cut}"
        );
    }
}

#[test]
fn residual_disposition_binds_source_landing_and_refresh() {
    let h = header();
    let valid = payload();
    let mut count = 0;
    for (label, prefix, offset) in [
        ("boundary", source(), Some(7)),
        ("publication", source(), Some(8)),
        ("root", source(), Some(25)),
        ("landing seq", source(), Some(64)),
        ("source cursor", source(), Some(72)),
        ("count", source(), Some(77)),
        ("refresh absent", source()[..3].to_vec(), None),
    ] {
        let mut p = valid.clone();
        if let Some(offset) = offset {
            p[offset] ^= if label == "count" { 2 } else { 1 };
        }
        if label == "refresh absent" {
            p[65..73].copy_from_slice(&3u64.to_be_bytes());
        }
        let seq = prefix.len() as u64 + 1;
        let mut bytes = encode_journal(&h, &prefix).unwrap();
        bytes.extend(raw_frame(&h, 17, seq, &p));
        assert_eq!(
            scan_journal(&bytes).unwrap_err().reason.to_string(),
            "journal residual disposition source mismatch",
            "{label}"
        );
        count += 1;
    }
    for (label, prefix) in [
        ("landing absent", {
            let mut p = source();
            p.remove(2);
            p
        }),
        ("directory sync is not refresh", {
            let mut p = source();
            p[3] = Record::IntentRegistered {
                generation: 1,
                prepared_root: grain(9),
                cause: IntentCause::DirectorySync,
            };
            p
        }),
        ("refresh names another root", {
            let mut p = source();
            p[3] = Record::IntentRegistered {
                generation: 1,
                prepared_root: grain(8),
                cause: IntentCause::LandedRefresh,
            };
            p
        }),
        ("refresh before landing", {
            let mut p = source();
            p.swap(2, 3);
            p
        }),
    ] {
        let mut bytes = encode_journal(&h, &prefix).unwrap();
        let mut p = valid.clone();
        p[65..73].copy_from_slice(&(prefix.len() as u64).to_be_bytes());
        bytes.extend(raw_frame(&h, 17, prefix.len() as u64 + 1, &p));
        assert_eq!(
            scan_journal(&bytes).unwrap_err().reason.to_string(),
            "journal residual disposition source mismatch",
            "{label}"
        );
        count += 1;
    }
    assert_eq!(count, 11);
}

#[test]
fn residual_disposition_is_a_witness_even_with_impossible_values() {
    let h = header();
    let mut p = payload();
    p[73] = 0;
    let bytes = journal_with_frame(&h, &[vec![0; 4], raw_frame(&h, 17, 5, &p)]);
    assert!(matches!(
        scan_journal(&bytes).unwrap_err().reason,
        FenceReason::MidFileDamage { .. }
    ));
}

#[test]
fn residual_file_preserves_raw_names_and_full_payload_binding() {
    let at = Location {
        parent: Parent::root(),
        name: Name::new(vec![0xff, b'\n']).unwrap(),
    };
    let file = ResidualFile {
        stage_id: 1,
        at,
        exec: true,
        local_size: 5,
        payload_check: [3; 32],
    };
    let bytes = cat(&[&u64b(1), &[0, 0, 2, 0xff, b'\n', 1], &u64b(5), &[3; 32]]);
    assert_eq!(
        (file.encode(), ResidualFile::decode(&bytes)),
        (Ok(bytes), Ok(file))
    );
}

#[test]
fn residual_inventory_hashes_every_descriptor_in_stage_order() {
    let mut hasher = ResidualPayloadHasher::new(1, 5);
    hasher.update(b"he");
    hasher.update(b"llo");
    let expected = blake3::derive_key(
        "granary residual payload v1",
        &cat(&[&u64b(1), &u64b(5), b"hello"]),
    );
    assert_eq!(hasher.finalize(), expected);
    let file = ResidualFile {
        stage_id: 1,
        at: loc(&[], "f"),
        exec: false,
        local_size: 5,
        payload_check: expected,
    };
    let mut second = file.clone();
    second.stage_id = 2;
    let mut second_payload = ResidualPayloadHasher::new(2, 5);
    second_payload.update(b"hello");
    second.payload_check = second_payload.finalize();
    second.at = loc(&[], "g");
    let bytes = cat(&[&file.encode().unwrap(), &second.encode().unwrap()]);
    assert_eq!(
        residual_inventory_check(&[file.clone(), second.clone()]),
        Ok(blake3::derive_key("granary residual inventory v1", &bytes))
    );
    for files in [vec![], vec![file.clone(), file.clone()], vec![second, file]] {
        let expected = if files.is_empty() {
            "journal residual inventory is empty"
        } else {
            "journal residual inventory is not in stage order"
        };
        assert_eq!(
            residual_inventory_check(&files).unwrap_err().to_string(),
            expected,
            "{files:?}"
        );
    }
}

#[test]
fn residual_payload_and_descriptor_refuse_malformed_fields() {
    let mut count = 0;
    for (offset, bytes, expected) in [
        (0, vec![0; 8], "journal boundary seq 0 is out of range"),
        (24, vec![0], "journal id has an unregistered algorithm"),
        (57, vec![0; 8], "journal landed seq 0 is out of range"),
        (
            57,
            vec![255; 8],
            "journal landed seq 18446744073709551615 is out of range",
        ),
        (73, vec![0], "journal residual disposition 0 is invalid"),
        (73, vec![3], "journal residual disposition 3 is invalid"),
        (73, vec![255], "journal residual disposition 255 is invalid"),
        (74, vec![0; 4], "journal residual inventory is empty"),
    ] {
        let mut p = payload();
        p[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert_eq!(
            Record::decode_payload(17, &p).unwrap_err().to_string(),
            expected
        );
        count += 1;
    }
    let p = payload();
    for len in 0..110 {
        assert_eq!(
            Record::decode_payload(17, &p[..len]),
            Err(RecordError::Truncated),
            "cut {len}"
        );
        count += 1;
    }
    let mut p = p;
    p.push(0);
    assert_eq!(
        Record::decode_payload(17, &p),
        Err(RecordError::TrailingBytes)
    );
    assert_eq!(count, 118);
}

#[test]
fn residual_file_rejects_malformed_fields_and_trailing_bytes() {
    let file = ResidualFile {
        stage_id: 1,
        at: loc(&[], "f"),
        exec: false,
        local_size: 5,
        payload_check: [3; 32],
    };
    let valid = file.encode().unwrap();
    let mut count = 0;
    for (offset, bytes, expected) in [
        (0, vec![0; 8], "journal stage id 0 is out of range"),
        (
            0,
            (STAGE_ID_MAX + 1).to_be_bytes().to_vec(),
            "journal stage id 9223372036854775808 is out of range",
        ),
        (12, vec![2], "journal exec byte 2 is not 0 or 1"),
        (
            13,
            (SIZE_MAX + 1).to_be_bytes().to_vec(),
            "journal size 9223372036854775808 is out of range",
        ),
    ] {
        let mut bytes2 = valid.clone();
        bytes2[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert_eq!(
            ResidualFile::decode(&bytes2).unwrap_err().to_string(),
            expected
        );
        count += 1;
    }
    for len in 0..valid.len() {
        assert_eq!(
            ResidualFile::decode(&valid[..len]),
            Err(RecordError::Truncated)
        );
        count += 1;
    }
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(
        ResidualFile::decode(&trailing),
        Err(RecordError::TrailingBytes)
    );
    assert_eq!(count, 57);
}

#[test]
fn residual_disposition_names_only_latest_refreshed_landing() {
    let h = header();
    let mut count = 0;
    for (root, landed_seq) in [(grain(9), 8), (grain(10), 9)] {
        for projected in [false, true] {
            let mut prefix = source();
            prefix.push(if projected {
                Record::ProjectedBoundary {
                    candidate: grain(6),
                    through_seq: 4,
                    publication_id: [7; 16],
                    selection: None,
                }
            } else {
                boundary(4)
            });
            prefix.push(Record::LandedCommit {
                boundary_seq: 5,
                landed_root: root,
                landed_seq,
            });
            let mut latest = payload();
            latest[..8].copy_from_slice(&5u64.to_be_bytes());
            latest[24..57].copy_from_slice(&root.to_bytes());
            latest[57..65].copy_from_slice(&landed_seq.to_be_bytes());
            latest[65..73].copy_from_slice(&6u64.to_be_bytes());
            let unrefreshed = cat(&[
                &encode_journal(&h, &prefix).unwrap(),
                &raw_frame(&h, 17, 7, &latest),
            ]);
            prefix.push(Record::IntentRegistered {
                generation: 2,
                prepared_root: root,
                cause: IntentCause::LandedRefresh,
            });
            latest[65..73].copy_from_slice(&7u64.to_be_bytes());
            let mut older = payload();
            older[65..73].copy_from_slice(&7u64.to_be_bytes());
            let encoded = encode_journal(&h, &prefix).unwrap();
            let stale = cat(&[&encoded, &raw_frame(&h, 17, 8, &older)]);
            let current = cat(&[&encoded, &raw_frame(&h, 17, 8, &latest)]);
            let outcome = |bytes: &[u8]| {
                scan_journal(bytes)
                    .map(|s| s.end)
                    .map_err(|e| e.reason.to_string())
            };
            let refused = Err("journal residual disposition source mismatch".to_owned());
            assert_eq!(
                (outcome(&stale), outcome(&current), outcome(&unrefreshed)),
                (refused.clone(), Ok(JournalEnd::Clean), refused),
                "root {root}, projected {projected}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 4);
}

#[test]
fn residual_disposition_refuses_any_open_boundary() {
    let h = header();
    let outcome = |bytes: &[u8]| {
        scan_journal(bytes)
            .map(|s| s.end)
            .map_err(|e| e.reason.to_string())
    };
    let mut valid = encode_journal(&h, &source()).unwrap();
    valid.extend(raw_frame(&h, 17, 5, &payload()));
    let mut count = 0;
    for projected in [false, true] {
        for earlier in [false, true] {
            let mut prefix = source();
            let open = if projected {
                Record::ProjectedBoundary {
                    candidate: grain(6),
                    through_seq: if earlier { 1 } else { 4 },
                    publication_id: [8; 16],
                    selection: None,
                }
            } else {
                boundary(if earlier { 1 } else { 4 })
            };
            let mut p = payload();
            if earlier {
                prefix.insert(1, open);
                prefix[3] = Record::LandedCommit {
                    boundary_seq: 3,
                    landed_root: grain(9),
                    landed_seq: 8,
                };
                p[..8].copy_from_slice(&3u64.to_be_bytes());
            } else {
                prefix.push(open);
            }
            p[65..73].copy_from_slice(&5u64.to_be_bytes());
            let mut bytes = encode_journal(&h, &prefix).unwrap();
            bytes.extend(raw_frame(&h, 17, 6, &p));
            assert_eq!(
                (outcome(&valid), outcome(&bytes)),
                (
                    Ok(JournalEnd::Clean),
                    Err("journal residual disposition source mismatch".to_owned())
                ),
                "projected {projected}, earlier {earlier}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 4);
}
