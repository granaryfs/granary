// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Generated properties of the overlay journal codec: they stay
//! outside core's pure
//! dependency closure, as the other codecs' do.
#![expect(
    clippy::unwrap_used,
    reason = "generated test fixture invariants (standards rule 3)"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index byte vectors they built (standards rule 3)"
)]

use granary_core::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use granary_core::manifest::Name;
use granary_core::overlay_journal::{
    BindCause, CreateKind, DeleteKind, Fence, IntentCause, JournalEnd, JournalHeader, JournalScan,
    Location, MarkState, Parent, ProjectedSelection, Record, RecreateAnchor, ResidualDisposition,
    ResidualFile, ResidualMode, SIZE_MAX, STAGE_ID_MAX, StagingHeader, SyncedMark, WriterRecord,
    encode_journal, encode_record, extent_check, scan_journal_with,
};
use granary_core::root::VolumeName;
use proptest::prelude::*;

/// Only tests collect records; production replay visits them as they arrive.
#[derive(Debug)]
struct CollectedScan {
    scan: JournalScan,
    records: Vec<Record>,
}

impl std::ops::Deref for CollectedScan {
    type Target = JournalScan;
    fn deref(&self) -> &Self::Target {
        &self.scan
    }
}

fn scan_journal(bytes: &[u8]) -> Result<CollectedScan, Fence> {
    let mut records = Vec::new();
    let scan = scan_journal_with(bytes, |_, record| records.push(record.clone()))?;
    Ok(CollectedScan { scan, records })
}

fn grain(n: u8) -> GrainId {
    GrainId::from_parts(HashAlgorithm::Blake3, [n; DIGEST_LEN])
}

fn name(n: u8) -> Name {
    Name::new(format!("n{n}").into_bytes()).unwrap()
}

fn location(depth: u8, n: u8) -> Location {
    Location {
        parent: Parent::new((0..depth % 4).map(|i| name(n.wrapping_add(i))).collect()).unwrap(),
        name: name(n),
    }
}

fn header() -> JournalHeader {
    JournalHeader {
        writer: [0x42; 16],
        base_root: grain(0xAA),
        base_seq: 7,
        next_stage_id: 5,
        receipt_generation: 3,
    }
}

/// A valid record sequence built by a small state machine from arbitrary
/// choices: every record obeys the value rules, because the generator keeps
/// the stage table, the generation cursor and the open boundaries itself.
#[expect(clippy::too_many_lines, reason = "one arm per record kind")]
fn build(choices: &[(u8, u8, u8)]) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    let mut next_stage = 5u64;
    let mut rebindable = vec![1u64, 2, 3, 4];
    let mut stages: Vec<(u64, u64)> = Vec::new();
    let mut generation = 3u64;
    let mut prepared_root = grain(0);
    let mut boundaries: Vec<(u64, u8, u64)> = Vec::new();
    for &(op, a, b) in choices {
        let seq = out.len() as u64 + 1;
        let pick = if stages.is_empty() {
            None
        } else {
            Some(usize::from(a) % stages.len())
        };
        let record = match (op % 18, pick) {
            (0, _) => Record::Create {
                at: location(a, b),
                kind: CreateKind::Dir,
            },
            (1, _) => {
                stages.push((next_stage, 0));
                next_stage += 1;
                Record::Create {
                    at: location(a, b),
                    kind: CreateKind::File {
                        exec: a % 2 == 0,
                        stage_id: next_stage - 1,
                    },
                }
            }
            (2, Some(i)) => {
                let (id, size) = &mut stages[i];
                let offset = u64::from(b) * 7;
                let length = u64::from(a) + 1;
                *size = (*size).max(offset + length);
                Record::WriteExtent {
                    stage_id: *id,
                    offset,
                    length,
                    check: extent_check(*id, offset, &vec![a; usize::from(a) + 1]),
                }
            }
            (3, Some(i)) => {
                let (id, size) = &mut stages[i];
                *size = u64::from(b);
                Record::Truncate {
                    stage_id: *id,
                    new_size: u64::from(b),
                }
            }
            (4, _) => Record::Move {
                from: location(a, b),
                to: location(b, a),
            },
            (5, _) => Record::Replace {
                from: location(a, b),
                to: location(b, a),
            },
            (6, p) => Record::Delete {
                at: location(a, b),
                kind: match (a % 3, p) {
                    (0, Some(i)) => DeleteKind::File {
                        stage_id: Some(stages[i].0),
                    },
                    (0 | 1, _) => DeleteKind::Dir,
                    _ => DeleteKind::Symlink,
                },
            },
            (7, _) => Record::SetattrExec {
                at: location(a, b),
                exec: b % 2 == 1,
            },
            (8, Some(i)) => {
                generation += u64::from(b % 3);
                generation += 1;
                prepared_root = grain(b);
                Record::FileSynced {
                    stage_id: stages[i].0,
                    synced_size: stages[i].1 / 2,
                    content: grain(a),
                    generation,
                    prepared_root: grain(b),
                }
            }
            (9, _) => {
                if generation == 3 || a % 2 == 0 {
                    generation += 1;
                    prepared_root = grain(b);
                }
                Record::IntentRegistered {
                    generation,
                    prepared_root,
                    cause: if a % 2 == 0 {
                        IntentCause::DirectorySync
                    } else {
                        IntentCause::LandedRefresh
                    },
                }
            }
            (10, _) => {
                boundaries.push((seq, b, 0));
                Record::CommitBoundary {
                    candidate: grain(a),
                    through_seq: u64::from(b) % seq,
                    publication_id: [b; 16],
                }
            }
            (11, _) if !boundaries.is_empty() => {
                let (boundary_seq, _, _) = boundaries.remove(usize::from(a) % boundaries.len());
                Record::LandedCommit {
                    boundary_seq,
                    landed_root: grain(b),
                    landed_seq: 8 + u64::from(a),
                }
            }
            (13, _) if !boundaries.is_empty() => {
                let i = usize::from(a) % boundaries.len();
                let (boundary_seq, publication, attempt) = &mut boundaries[i];
                *attempt += 1;
                Record::CommitAttempt {
                    boundary_seq: *boundary_seq,
                    publication_id: [*publication; 16],
                    attempt: *attempt,
                }
            }
            (15, pick) => {
                let open = boundaries.iter().map(|(boundary, _, _)| *boundary).max();
                boundaries.push((seq, b, 0));
                let selection = pick.filter(|_| b % 2 == 1).map(|i| ProjectedSelection {
                    stage_id: stages[i].0,
                    content: grain(b),
                    size: u64::from(a),
                });
                // A selected stage was bound by an earlier record, so the whole
                // prefix before this one covers it; any prefix reaches the
                // latest open boundary.
                Record::ProjectedBoundary {
                    candidate: grain(a),
                    through_seq: if selection.is_some() {
                        seq - 1
                    } else {
                        (u64::from(b) % seq).max(open.unwrap_or(0))
                    },
                    publication_id: [b; 16],
                    selection,
                }
            }
            (14, _) if !boundaries.is_empty() => {
                let (boundary_seq, publication, _) = boundaries[usize::from(a) % boundaries.len()];
                Record::CommitFence {
                    boundary_seq,
                    publication_id: [publication; 16],
                }
            }
            (16, _) if !rebindable.is_empty() => {
                let id = rebindable.remove(usize::from(a) % rebindable.len());
                let anchor = (b % 2 == 1).then(|| RecreateAnchor {
                    content: grain(b),
                    size: u64::from(a),
                });
                stages.push((id, anchor.map_or(0, |anchor| anchor.size)));
                let at = (a % 2 == 1).then(|| location(a, b));
                Record::RecreateFile {
                    exec: at.is_some() && b % 4 < 2,
                    at,
                    stage_id: id,
                    anchor,
                }
            }
            (17, Some(i)) => {
                let (stage_id, size) = &mut stages[i];
                let anchor = (b % 2 == 1).then(|| RecreateAnchor {
                    content: grain(b),
                    size: u64::from(a),
                });
                let old_size = *size;
                *size = anchor.map_or(0, |anchor| anchor.size);
                Record::StageRollback {
                    stage_id: *stage_id,
                    old_size,
                    anchor,
                    discarded_bytes: u64::from(b),
                }
            }
            (12, _) if !rebindable.is_empty() => {
                let id = rebindable.remove(usize::from(a) % rebindable.len());
                stages.push((id, u64::from(b)));
                Record::StageBind {
                    at: location(a, b),
                    cause: BindCause::Rebind,
                    stage_id: id,
                    staged_size: u64::from(b),
                    base_content: grain(a),
                }
            }
            (_, _) => {
                stages.push((next_stage, u64::from(b)));
                next_stage += 1;
                Record::StageBind {
                    at: location(a, b),
                    cause: BindCause::CopyUp,
                    stage_id: next_stage - 1,
                    staged_size: u64::from(b),
                    base_content: grain(a),
                }
            }
        };
        out.push(record);
    }
    out
}

fn choices() -> impl Strategy<Value = Vec<(u8, u8, u8)>> {
    prop::collection::vec(any::<(u8, u8, u8)>(), 0..40)
}

/// The generator is not vacuous: one fixed choice list reaches every nonterminal kind
/// and both causes of a stage-bind, and the journal it builds is accepted.
#[test]
fn the_generator_reaches_every_nonterminal_record_kind() {
    let fixed: Vec<(u8, u8, u8)> = vec![
        (2, 0, 0), // no bound stage yet: fallback copy-up
        (1, 1, 1),
        (2, 0, 4),
        (3, 0, 9),
        (0, 1, 1),
        (4, 2, 2),
        (5, 3, 3),
        (6, 0, 0),
        (7, 1, 1),
        (8, 0, 2),
        (9, 1, 1),
        (10, 0, 5),
        (13, 0, 0),
        (14, 0, 0),
        (15, 0, 3),
        (15, 0, 4),
        (11, 0, 0),
        (12, 0, 7),
        (16, 1, 1),
        (16, 1, 2),
        (16, 0, 1),
        (17, 0, 1),
        (17, 0, 0),
    ];
    let records = build(&fixed);
    let mut kinds: Vec<u8> = records.iter().map(Record::kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(kinds, (1..=16).chain([18]).collect::<Vec<u8>>());
    let selections: Vec<bool> = records
        .iter()
        .filter_map(|r| match r {
            Record::ProjectedBoundary { selection, .. } => Some(selection.is_some()),
            _ => None,
        })
        .collect();
    assert_eq!(selections, [true, false]);
    let recreates: Vec<(bool, bool)> = records
        .iter()
        .filter_map(|r| match r {
            Record::RecreateFile { at, anchor, .. } => Some((at.is_some(), anchor.is_some())),
            _ => None,
        })
        .collect();
    assert_eq!(recreates, [(true, true), (true, false), (false, true)]);
    let rollbacks: Vec<bool> = records
        .iter()
        .filter_map(|r| match r {
            Record::StageRollback { anchor, .. } => Some(anchor.is_some()),
            _ => None,
        })
        .collect();
    assert_eq!(rollbacks, [true, false]);
    let causes: Vec<BindCause> = records
        .iter()
        .filter_map(|r| match r {
            Record::StageBind { cause, .. } => Some(*cause),
            _ => None,
        })
        .collect();
    assert!(causes.contains(&BindCause::CopyUp) && causes.contains(&BindCause::Rebind));
    assert!(scan_journal(&encode_journal(&header(), &records).unwrap()).is_ok());
}

proptest! {
    #[test]
    fn stage_rollback_payload_round_trips_and_re_encodes_canonically(
        stage_id in 1..=STAGE_ID_MAX,
        old_size in 0..=SIZE_MAX,
        anchor in prop::option::of((any::<[u8; DIGEST_LEN]>(), 0..=SIZE_MAX)),
        discarded_bytes in any::<u64>(),
    ) {
        let record = Record::StageRollback {
            stage_id,
            old_size,
            anchor: anchor.map(|(digest, size)| RecreateAnchor {
                content: GrainId::from_parts(HashAlgorithm::Blake3, digest),
                size,
            }),
            discarded_bytes,
        };
        let bytes = record.encode_payload().unwrap();
        let decoded = Record::decode_payload(18, &bytes).unwrap();
        prop_assert_eq!(&decoded, &record);
        prop_assert_eq!(decoded.encode_payload().unwrap(), bytes);
    }

    #[test]
    fn a_valid_journal_round_trips_and_re_encodes_canonically(c in choices()) {
        let records = build(&c);
        let bytes = encode_journal(&header(), &records).unwrap();
        let scan = scan_journal(&bytes).unwrap();
        prop_assert_eq!(&scan.records, &records);
        prop_assert_eq!(scan.end, JournalEnd::Clean);
        prop_assert_eq!(scan.valid_len, bytes.len());
        prop_assert_eq!(encode_journal(&scan.header, &scan.records).unwrap(), bytes);
    }

    #[test]
    fn every_cut_yields_a_prefix_of_the_records(c in choices(), cut in any::<prop::sample::Index>()) {
        let records = build(&c);
        let bytes = encode_journal(&header(), &records).unwrap();
        let cut = 117 + cut.index(bytes.len() - 117 + 1);
        let scan = scan_journal(&bytes[..cut]).unwrap();
        prop_assert!(scan.records.len() <= records.len());
        prop_assert_eq!(&scan.records[..], &records[..scan.records.len()]);
        prop_assert_eq!(matches!(scan.end, JournalEnd::Clean), scan.valid_len == cut);
    }

    #[test]
    fn a_flipped_bit_never_changes_a_record_and_fences_before_a_sync_record(
        c in choices(),
        at in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let records = build(&c);
        let bytes = encode_journal(&header(), &records).unwrap();
        let byte = at.index(bytes.len());
        let mut damaged = bytes.clone();
        damaged[byte] ^= 1 << bit;
        // Frame bounds, to find which record the flip landed in.
        let mut bounds = vec![117usize];
        for (i, r) in records.iter().enumerate() {
            let end = bounds[i] + encode_record(&header(), i as u64 + 1, r).unwrap().len();
            bounds.push(end);
        }
        match scan_journal(&damaged) {
            Err(_) => {}
            Ok(scan) => {
                // Whatever survives is exactly a prefix of what was written.
                prop_assert_eq!(&scan.records[..], &records[..scan.records.len()]);
                // And a flip in the header or a record that a later sync-class
                // record follows can never be read past.
                let frame = bounds.iter().rposition(|&b| b <= byte).unwrap();
                let last_sync = records.iter().rposition(Record::is_sync_class);
                prop_assert!(byte >= 117);
                prop_assert!(frame >= records.len() || last_sync.is_none_or(|s| frame >= s));
                prop_assert!(scan.records.len() <= frame);
            }
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_accepted_prefixes_are_canonical(
        bytes in prop::collection::vec(any::<u8>(), 0..2000),
    ) {
        granary_core::testkit::overlay_journal_decode_probe(&bytes);
        if let Ok(scan) = scan_journal(&bytes) {
            prop_assert_eq!(
                encode_journal(&scan.header, &scan.records).unwrap(),
                bytes[..scan.valid_len].to_vec()
            );
        }
    }

    #[test]
    fn a_writer_record_round_trips(
        writer in any::<[u8; 16]>(),
        ceiling in 0..u64::MAX,
        volume in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
    ) {
        let record = WriterRecord { writer, ceiling, volume: VolumeName::new(volume).unwrap() };
        let bytes = record.encode().unwrap();
        prop_assert_eq!(WriterRecord::decode(&bytes).unwrap(), record.clone());
        prop_assert_eq!(WriterRecord::decode(&bytes).unwrap().encode().unwrap(), bytes);
    }

    #[test]
    fn a_staging_header_round_trips(
        writer in any::<[u8; 16]>(),
        stage_id in 1..=i64::MAX as u64,
        mark in prop::option::of((0..=i64::MAX as u64, any::<u8>(), 1..u64::MAX)),
    ) {
        let header = StagingHeader {
            writer,
            stage_id,
            mark: mark.map_or(MarkState::Absent, |(size, c, generation)| {
                MarkState::Present(SyncedMark { synced_size: size, content: grain(c), generation })
            }),
        };
        let bytes = header.encode().unwrap();
        prop_assert_eq!(StagingHeader::decode(&bytes).unwrap(), header);
        prop_assert_eq!(StagingHeader::decode(&bytes).unwrap().encode().unwrap(), bytes);
    }
}

proptest! {
    #[test]
    fn a_replacement_preserves_creates_and_a_second_commit_cycle(
        before in 0u64..8, after in 0u64..8, answered in any::<bool>(),
    ) {
        let h = JournalHeader { next_stage_id: 1, receipt_generation: 0, ..header() };
        let create = |id| Record::Create { at: location(0, u8::try_from(id).unwrap()), kind: CreateKind::File { exec: false, stage_id: id } };
        let mut old: Vec<Record> = (1..=before).map(create).collect();
        let b1 = old.len() as u64 + 1;
        old.push(Record::CommitBoundary { candidate: grain(1), through_seq: before, publication_id: [1;16] });
        old.extend((before+1..=before+after).map(create));
        old.extend((1..=before).map(|id| Record::Truncate { stage_id: id, new_size: 1 }));
        let l1 = old.len() as u64 + 1;
        old.push(Record::LandedCommit { boundary_seq: b1, landed_root: grain(1), landed_seq: 8 });
        let b2 = old.len() as u64 + 1;
        old.push(Record::CommitBoundary { candidate: grain(2), through_seq: b2-1, publication_id: [2;16] });
        if answered { old.push(Record::LandedCommit { boundary_seq: b2, landed_root: grain(2), landed_seq: 9 }); }
        let old_scan = scan_journal(&encode_journal(&h, &old).unwrap()).unwrap();
        let carried: Vec<(u64, Record)> = old.iter().enumerate().filter_map(|(i, r)| {
            let seq = i as u64 + 1;
            (seq > before && seq != b1 && seq != l1).then(|| (seq, r.clone()))
        }).collect();
        let mut replacement: Vec<Record> = (1..=before).map(|id| Record::StageBind {
            at: location(0, u8::try_from(id).unwrap()), cause: BindCause::Rebind, stage_id: id, staged_size: 0, base_content: grain(0),
        }).collect();
        let count_through = |t| before + carried.iter().filter(|(s, _)| *s <= t).count() as u64;
        for (_, mut record) in carried.clone() {
            match &mut record {
                Record::CommitBoundary { through_seq, .. } => *through_seq = count_through(*through_seq),
                Record::LandedCommit { boundary_seq, .. } => *boundary_seq = count_through(*boundary_seq),
                _ => {},
            }
            replacement.push(record);
        }
        let new_h = JournalHeader { next_stage_id: before+1, base_seq: 8, base_root: grain(1), ..h };
        let bytes = encode_journal(&new_h, &replacement).unwrap();
        let new_scan = scan_journal(&bytes).unwrap();
        prop_assert_eq!(new_scan.state.next_stage_id(), old_scan.state.next_stage_id());
        prop_assert_eq!(new_scan.state.open_boundaries().count(), usize::from(!answered));
        prop_assert_eq!(new_scan.records, replacement);
    }

    #[test]
    fn equal_generation_roots_are_bound_across_receipt_kinds(generation in 4u64..u64::MAX, root in any::<u8>()) {
        let first = Record::IntentRegistered { generation, prepared_root: grain(root), cause: IntentCause::DirectorySync };
        let second = Record::IntentRegistered { generation, prepared_root: grain(root.wrapping_add(1)), cause: IntentCause::LandedRefresh };
        prop_assert!(encode_journal(&header(), &[first, second]).is_err());
    }
}

proptest! {
    #[test]
    fn residual_payload_round_trips_and_re_encodes_canonically(
        boundary in 1u64..u64::MAX,
        landed in 1u64..u64::MAX,
        source in any::<u64>(),
        publication in any::<[u8; 16]>(),
        inventory in any::<[u8; 32]>(),
        count in 1u32..=u32::MAX,
        remote in any::<bool>(),
    ) {
        let record = Record::ResidualDisposition(ResidualDisposition {
            boundary_seq: boundary, publication_id: publication, landed_root: grain(9),
            landed_seq: landed, source_end: source, disposition: if remote { ResidualMode::KeepRemote } else { ResidualMode::KeepLocal },
            collision_count: count, inventory_check: inventory,
        });
        let bytes = record.encode_payload().unwrap();
        let decoded = Record::decode_payload(17, &bytes).unwrap();
        prop_assert_eq!(&decoded, &record);
        prop_assert_eq!(decoded.encode_payload().unwrap(), bytes);
    }

    #[test]
    fn residual_file_round_trips_and_re_encodes_canonically(
        stage in 1u64..=9_223_372_036_854_775_807,
        size in 0u64..=9_223_372_036_854_775_807,
        depth in any::<u8>(), n in any::<u8>(),
        exec in any::<bool>(), check in any::<[u8; 32]>(),
    ) {
        let file = ResidualFile { stage_id: stage, at: location(depth, n), exec, local_size: size, payload_check: check };
        let bytes = file.encode().unwrap();
        let decoded = ResidualFile::decode(&bytes).unwrap();
        prop_assert_eq!(&decoded, &file);
        prop_assert_eq!(decoded.encode().unwrap(), bytes);
    }
}

proptest! {
    #[test]
    fn unmerged_path_round_trips_and_re_encodes_canonically(
        stage in 1u64..=9_223_372_036_854_775_807,
        size in 0u64..=9_223_372_036_854_775_807,
        depth in any::<u8>(), n in any::<u8>(),
        exec in any::<bool>(), check in any::<[u8; 32]>(),
        writer in any::<[u8; 16]>(),
    ) {
        use granary_core::overlay_journal::{ResidualFile, UnmergedPath, residual_inventory_check};
        let file = ResidualFile { stage_id: stage, at: location(depth, n), exec, local_size: size, payload_check: check };
        let listing = UnmergedPath { writer, record: ResidualDisposition {
            boundary_seq: 1, publication_id: [0;16], landed_root: grain(n), landed_seq: 2,
            source_end: 3, disposition: ResidualMode::KeepRemote,
            collision_count: 1, inventory_check: residual_inventory_check(std::slice::from_ref(&file)).unwrap(),
        }, file };
        let bytes = listing.encode().unwrap();
        let decoded = UnmergedPath::decode(&bytes).unwrap();
        prop_assert_eq!(&decoded, &listing);
        prop_assert_eq!(decoded.encode().unwrap(), bytes);
    }
}
