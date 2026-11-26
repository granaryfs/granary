// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::TokioSyncRuntime;
use std::time::Duration;

fn journal(witness: GrainId) -> Vec<u8> {
    let header = codec::JournalHeader {
        writer: [1; 16],
        base_root: GrainId::of(b"base"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let mut old = header.encode().unwrap();
    let registration = |generation| Record::IntentRegistered {
        generation,
        prepared_root: witness,
        cause: codec::IntentCause::DirectorySync,
    };
    let boundary = Record::CommitBoundary {
        candidate: witness,
        through_seq: 1,
        publication_id: [1; 16],
    };
    for (index, record) in [registration(1), registration(2), boundary]
        .iter()
        .enumerate()
    {
        old.extend(codec::encode_record(&header, index as u64 + 1, record).unwrap());
    }
    old
}

#[test]
fn recovery_suffix_cut_is_anchored_largest_and_below_open_boundary() {
    let witness = GrainId::of(b"witness");
    let old = journal(witness);
    let mut asked = Vec::new();
    let cut = CutSearch::scan(&old, witness, witness, None)
        .unwrap()
        .find_cut(|seq| {
            asked.push(seq);
            Ok(seq >= 1)
        })
        .unwrap();
    assert_eq!((cut, asked), (Some(2), vec![1, 2]));
    assert_eq!(
        CutSearch::scan(&old, witness, witness, None)
            .unwrap()
            .find_cut(|seq| Ok(seq == 3))
            .unwrap(),
        None
    );
}

#[test]
fn recovered_checkpoint_requires_a_verified_cursor() {
    let witness = GrainId::of(b"witness");
    let content = GrainId::of(b"empty file");
    let header = codec::JournalHeader {
        writer: [1; 16],
        base_root: GrainId::of(b"base"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let mut old = header.encode().unwrap();
    for (seq, record) in [
        Record::Create {
            at: codec::Location {
                parent: codec::Parent::new(vec![]).unwrap(),
                name: granary_core::manifest::Name::new(b"file".to_vec()).unwrap(),
            },
            kind: codec::CreateKind::File {
                stage_id: 1,
                exec: false,
            },
        },
        Record::FileSynced {
            stage_id: 1,
            synced_size: 0,
            generation: 1,
            content,
            prepared_root: witness,
        },
    ]
    .iter()
    .enumerate()
    {
        old.extend(codec::encode_record(&header, seq as u64 + 1, record).unwrap());
    }
    let replay = ReplayContext::retained(
        header,
        &super::super::super::OverlayConfig {
            scope: granary_core::retained_submission::Scope {
                authority_base: b"https://fixture.invalid".to_vec(),
                pins: Vec::new(),
                credential_context: b"test".to_vec(),
            },
            volume: granary_core::root::VolumeName::new("v".into()).unwrap(),
            euid: 0,
            cap: 1_048_576,
            ownership_completion_reserve: 2048,
            instance: [2; 16],
        },
    )
    .unwrap();
    let prefix = RecoveryPrefix {
        old,
        base: Vec::new(),
        context: replay,
    };
    let search = CutSearch::scan(&prefix.old, witness, witness, None).unwrap();
    let (namespace, history) = History::prefix(&prefix.base, &prefix.old, 2).unwrap();
    let projection = prefix
        .context
        .boundary(2, &namespace, history)
        .project(&[])
        .unwrap();
    assert!(search.receipts[0].matches(&projection.entries()[0]));
    let mut coverage = BTreeMap::new();
    let asked = Cell::new(0);
    let result = prefix.checkpoint_coverage(
        &projection,
        &search,
        2,
        &mut coverage,
        &|_, id, tested| {
            assert_eq!((id, tested), (1, content));
            asked.set(asked.get() + 1);
            Ok(false)
        },
        &|| Ok(()),
    );
    assert_eq!(asked.get(), 2);
    assert!(coverage.is_empty());
    assert!(!result.unwrap());
}

#[test]
fn witness_proof_uses_operation_clock() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let witness = GrainId::of(b"witness");
    let start = TokioSyncRuntime.now();
    let operation = Cell::new(start);
    let budget = ProofBudget {
        remaining: Cell::new(1),
        now: &|| operation.get(),
        deadline: start + Duration::from_secs(1),
    };
    assert!(matches!(
        budget.charge(2),
        Err(CoordinationError::Refused("SyncWorkspaceExhausted"))
    ));
    let mut asked = Vec::new();
    let error = CutSearch::scan(&journal(witness), witness, witness, None)
        .unwrap()
        .find_cut(|seq| {
            budget.charge(1)?;
            asked.push(seq);
            operation.set(budget.deadline);
            Ok(true)
        })
        .unwrap_err();
    assert!(matches!(error, CoordinationError::Refused("SyncDeadline")));
    assert_eq!(asked, [1]);
    assert_eq!(TokioSyncRuntime.now(), start);
}

#[test]
fn witness_proof_checks_inherited_read_length() {
    let stage = Stage {
        inode: 1,
        path: None,
        size: 3,
        base: Some(GrainId::of(b"old")),
        base_size: 3,
        mark: None,
        rollback: None,
        checkpoint_boundary: None,
        extents: BTreeMap::new(),
        zeros: Vec::new(),
        handles: 0,
        captures: BTreeMap::new(),
    };
    let now = TokioSyncRuntime.now();
    let budget = ProofBudget {
        remaining: Cell::new(0),
        now: &|| now,
        deadline: now + Duration::from_secs(1),
    };
    for (inherited, expected) in [
        (b"old".as_slice(), Some(true)),
        (b"new".as_slice(), Some(false)),
        (b"ol".as_slice(), None),
    ] {
        let result = stage_matches(
            &stage,
            1,
            &|_, _, length| range(Ok(inherited.to_vec()), length, &budget),
            &|_, _| Ok(b"old".to_vec()),
        );
        match expected {
            Some(same) => assert_eq!(result.unwrap(), same),
            None => assert!(matches!(
                result,
                Err(CoordinationError::Refused("WritableRecoveryRequired"))
            )),
        }
    }
}

#[test]
fn torn_stage_witness_checks_checkpoint_gaps() {
    let base = GrainId::of(b"old-base");
    let checkpoint = GrainId::of(b"synced!!");
    let stage = Stage {
        inode: 1,
        path: None,
        size: 4,
        base: Some(base),
        base_size: 8,
        mark: Some(codec::SyncedMark {
            synced_size: 8,
            content: checkpoint,
            generation: 1,
        }),
        rollback: None,
        checkpoint_boundary: None,
        extents: BTreeMap::new(),
        zeros: Vec::new(),
        handles: 0,
        captures: BTreeMap::new(),
    };
    let check = |witness: &[u8]| {
        stage_matches(
            &stage,
            1,
            &|content, offset, length| {
                let bytes = match content {
                    id if id == base => b"old-base",
                    id if id == checkpoint => b"synced!!",
                    id => panic!("unexpected witness source: {id:?}"),
                };
                let start = usize::try_from(offset).unwrap();
                Ok(bytes[start..start + length].to_vec())
            },
            &|offset, length| {
                let start = usize::try_from(offset).unwrap();
                Ok(witness[start..start + length].to_vec())
            },
        )
        .unwrap()
    };
    assert_eq!((check(b"sync"), check(b"old-")), (true, false));
}
