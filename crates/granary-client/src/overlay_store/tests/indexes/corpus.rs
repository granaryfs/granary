// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::oracle::{answers, directory, location, names};
use super::*;
use granary_core::manifest::SymlinkTarget;
use granary_core::rng::{Rng as _, SeededRng};

#[derive(Default)]
struct Coverage {
    operations: BTreeMap<&'static str, usize>,
    records: BTreeMap<&'static str, usize>,
    seen: BTreeSet<Vec<u8>>,
    queries: [usize; 5],
}

impl std::fmt::Debug for Coverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coverage")
            .field("operations", &self.operations)
            .field("records", &self.records)
            .field("queries", &self.queries)
            .finish_non_exhaustive()
    }
}

fn record_kind(record: &Record) -> &'static str {
    match record {
        Record::Create {
            kind: codec::CreateKind::Dir,
            ..
        } => "Create(directory)",
        Record::Create {
            kind: codec::CreateKind::File { .. },
            ..
        } => "Create(file)",
        Record::Create {
            kind: codec::CreateKind::Symlink { .. },
            ..
        } => "Create(symlink)",
        Record::StageBind { .. } => "StageBind",
        Record::WriteExtent { .. } => "WriteExtent",
        Record::Truncate { .. } => "Truncate",
        Record::Move { .. } => "Move",
        Record::Replace { .. } => "Replace",
        Record::Delete { .. } => "Delete",
        Record::SetattrExec { .. } => "SetattrExec",
        Record::FileSynced { .. } => "FileSynced",
        Record::IntentRegistered { .. } => "IntentRegistered",
        Record::CommitBoundary { .. } => "CommitBoundary",
        Record::LandedCommit { .. } => "LandedCommit",
        Record::CommitAttempt { .. } => "CommitAttempt",
        Record::CommitFence { .. } => "CommitFence",
        Record::ProjectedBoundary { .. } => "ProjectedBoundary",
        Record::RecreateFile { .. } => "RecreateFile",
        Record::StageRollback { .. } => "StageRollback",
        Record::ResidualDisposition(_) => "ResidualDisposition",
    }
}

fn audit(f: &mut Fixture, coverage: &mut Coverage) {
    let result = answers(f);
    assert!(
        result.is_ok(),
        "guard-independent complete answers: actual={result:?}, coverage={coverage:?}"
    );
    for (total, count) in coverage.queries.iter_mut().zip(result.unwrap()) {
        *total += count;
    }
    let bytes = f.io.bytes(&f.overlay.journal_path());
    let header = codec::scan_journal(&bytes).unwrap().header;
    codec::scan_journal_with(&bytes, |seq, record| {
        if coverage
            .seen
            .insert(codec::encode_record(&header, seq, record).unwrap())
        {
            *coverage.records.entry(record_kind(record)).or_default() += 1;
        }
    })
    .unwrap();
}

fn accept<T: std::fmt::Debug>(
    f: &mut Fixture,
    coverage: &mut Coverage,
    label: &'static str,
    action: impl FnOnce(&mut Fixture) -> Result<T, OverlayError>,
) -> T {
    let result = action(f);
    assert!(
        result.is_ok(),
        "accepted operation={label}, actual={result:?}"
    );
    *coverage.operations.entry(label).or_default() += 1;
    audit(f, coverage);
    result.unwrap()
}

fn mutate(f: &mut Fixture, coverage: &mut Coverage, label: &'static str, record: Record) {
    accept(f, coverage, label, |f| {
        f.overlay.namespace_record(&mut f.store, &f.owner, record)
    });
}

fn refuse(
    f: &mut Fixture,
    coverage: &mut Coverage,
    label: &'static str,
    record: Record,
    reason: &str,
) {
    let before = f.overlay.namespace.entries.clone();
    let bytes = f.io.bytes(&f.overlay.journal_path());
    let result = f.overlay.namespace_record(&mut f.store, &f.owner, record);
    assert_eq!(
        (
            result.err().map(|e| e.to_string()),
            f.overlay.readiness(),
            f.overlay.namespace.entries == before,
            f.io.bytes(&f.overlay.journal_path()) == bytes
        ),
        (Some(reason.into()), OverlayReadiness::Ready, true, true),
        "refused operation={label}"
    );
    *coverage.operations.entry(label).or_default() += 1;
    audit(f, coverage);
}

fn file(path: &str) -> OverlayEntry {
    OverlayEntry {
        kind: OverlayKind::File {
            content: Some(GrainId::of(b"body")),
        },
        size: 4,
        ..directory(path)
    }
}

fn directory_cycle(f: &mut Fixture, coverage: &mut Coverage, suffix: u64) {
    let src = format!("d/tree-{suffix}");
    let dst = format!("empty/tree-{suffix}");
    for path in [src.clone(), format!("{src}/child")] {
        mutate(
            f,
            coverage,
            "mkdir",
            Record::Create {
                at: location(&path),
                kind: codec::CreateKind::Dir,
            },
        );
    }
    mutate(
        f,
        coverage,
        "subtree-move",
        Record::Move {
            from: location(&src),
            to: location(&dst),
        },
    );
    mutate(
        f,
        coverage,
        "mkdir",
        Record::Create {
            at: location(&src),
            kind: codec::CreateKind::Dir,
        },
    );
    mutate(
        f,
        coverage,
        "subtree-replace",
        Record::Replace {
            from: location(&dst),
            to: location(&src),
        },
    );
    refuse(
        f,
        coverage,
        "nonempty-rmdir",
        Record::Delete {
            at: location(&src),
            kind: codec::DeleteKind::Dir,
        },
        "overlay refused: delete type/stage/nonempty refused",
    );
    for path in [format!("{src}/child"), src] {
        mutate(
            f,
            coverage,
            "rmdir",
            Record::Delete {
                at: location(&path),
                kind: codec::DeleteKind::Dir,
            },
        );
    }
}

fn symlink_cycle(f: &mut Fixture, coverage: &mut Coverage, suffix: u64) {
    let src = format!("d/link-{suffix}");
    let dst = format!("empty/link-{suffix}");
    let target = SymlinkTarget::new(format!("../wide/item-{suffix}").into_bytes()).unwrap();
    mutate(
        f,
        coverage,
        "symlink",
        Record::Create {
            at: location(&src),
            kind: codec::CreateKind::Symlink { target },
        },
    );
    mutate(
        f,
        coverage,
        "symlink-move",
        Record::Move {
            from: location(&src),
            to: location(&dst),
        },
    );
    mutate(
        f,
        coverage,
        "unlink-symlink",
        Record::Delete {
            at: location(&dst),
            kind: codec::DeleteKind::Symlink,
        },
    );
}

fn file_cycle(f: &mut Fixture, coverage: &mut Coverage, suffix: u64) {
    let path = format!("d/file-{suffix}");
    let id = accept(f, coverage, "create-file", |f| {
        f.overlay
            .create_file(&mut f.store, &f.owner, location(&path), false)
    });
    accept(f, coverage, "write", |f| {
        f.overlay.write(&mut f.store, &f.owner, id, 0, b"held")
    });
    for _ in 0..2 {
        accept(f, coverage, "shared-hold", |f| {
            f.overlay.open_stage(&mut f.store, &f.owner, &names(&path))
        });
    }
    mutate(
        f,
        coverage,
        "chmod",
        Record::SetattrExec {
            at: location(&path),
            exec: suffix.is_multiple_of(2),
        },
    );
    accept(f, coverage, "truncate", |f| {
        f.overlay.truncate(&mut f.store, &f.owner, id, 3)
    });
    let inode = f
        .overlay
        .namespace
        .entries
        .get(&names(&path))
        .unwrap()
        .inode;
    mutate(
        f,
        coverage,
        "unlink-held",
        Record::Delete {
            at: location(&path),
            kind: codec::DeleteKind::File { stage_id: Some(id) },
        },
    );
    let new_id = accept(f, coverage, "recreate-file", |f| {
        f.overlay
            .create_file(&mut f.store, &f.owner, location(&path), false)
    });
    assert_eq!(
        (
            f.overlay.namespace.stages.get(&id).unwrap().path.clone(),
            id != new_id,
            inode
                != f.overlay
                    .namespace
                    .entries
                    .get(&names(&path))
                    .unwrap()
                    .inode,
            f.overlay
                .read_stage(&mut f.store, &f.owner, id, 0, 3)
                .unwrap()
        ),
        (None, true, true, b"hel".to_vec())
    );
    for _ in 0..2 {
        accept(f, coverage, "close-hold", |f| {
            f.overlay.close_stage(&mut f.store, id)
        });
    }
    mutate(
        f,
        coverage,
        "unlink-recreated",
        Record::Delete {
            at: location(&path),
            kind: codec::DeleteKind::File {
                stage_id: Some(new_id),
            },
        },
    );
}

fn clean_unlink(f: &mut Fixture, coverage: &mut Coverage) {
    let path = names("clean-two");
    let inode = f.overlay.namespace.entries.get(&path).unwrap().inode;
    let stage = accept(f, coverage, "clean-detach-copy-up", |f| {
        f.overlay
            .copy_up(&mut f.store, &f.owner, at("clean-two"), &mut f.source)
    });
    assert_eq!(
        (
            f.overlay
                .namespace
                .stages
                .get(&stage)
                .unwrap()
                .extents
                .len(),
            f.overlay
                .read_stage(&mut f.store, &f.owner, stage, 0, 4)
                .unwrap()
        ),
        (0, b"body".to_vec()),
        "nonempty unchanged clean base before detach"
    );
    for _ in 0..2 {
        accept(f, coverage, "clean-shared-hold", |f| {
            f.overlay.open_stage(&mut f.store, &f.owner, &path)
        });
    }
    mutate(
        f,
        coverage,
        "unlink-clean-held",
        Record::Delete {
            at: at("clean-two"),
            kind: codec::DeleteKind::File {
                stage_id: Some(stage),
            },
        },
    );
    let new_stage = accept(f, coverage, "recreate-clean-name", |f| {
        f.overlay
            .create_file(&mut f.store, &f.owner, at("clean-two"), false)
    });
    assert_eq!(
        (
            f.overlay.namespace.stages.get(&stage).unwrap().path.clone(),
            stage != new_stage,
            inode != f.overlay.namespace.entries.get(&path).unwrap().inode,
            f.overlay
                .read_stage(&mut f.store, &f.owner, stage, 0, 4)
                .unwrap()
        ),
        (None, true, true, b"body".to_vec())
    );
    for _ in 0..2 {
        accept(f, coverage, "clean-close-hold", |f| {
            f.overlay.close_stage(&mut f.store, stage)
        });
    }
    mutate(
        f,
        coverage,
        "unlink-clean-recreated",
        Record::Delete {
            at: at("clean-two"),
            kind: codec::DeleteKind::File {
                stage_id: Some(new_stage),
            },
        },
    );
}

fn land(f: &mut Fixture, coverage: &mut Coverage) {
    let capture = accept(f, coverage, "capture-boundary", |f| {
        f.overlay.capture_boundary(&mut f.store, &f.owner)
    });
    let boundary = accept(f, coverage, "commit-boundary", |f| {
        f.overlay
            .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
    });
    let nodes: Vec<_> = f.overlay.namespace.entries.values().cloned().collect();
    let entries = nodes
        .into_iter()
        .map(|mut entry| {
            if let Some(id) = entry.stage_id {
                let body = f
                    .overlay
                    .read_stage(
                        &mut f.store,
                        &f.owner,
                        id,
                        0,
                        usize::try_from(entry.size).unwrap(),
                    )
                    .unwrap();
                let content = GrainId::of(&body);
                f.source.0.insert(content, body);
                entry.kind = OverlayKind::File {
                    content: Some(content),
                };
            }
            entry.stage_id = None;
            entry
        })
        .collect();
    let landed_entries: Vec<OverlayEntry> = entries;
    let expected_landed = landed_entries.clone();
    let proof = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(3),
        landed_seq: 2,
        captured_entries: landed_entries.clone(),
        entries: landed_entries,
    };
    accept(f, coverage, "landed-record", |f| {
        f.overlay.record_landed(&mut f.store, &f.owner, &proof)
    });
    accept(f, coverage, "register-landed", |f| {
        f.overlay.record_intent_registered(
            &mut f.store,
            &f.owner,
            20,
            grain(3),
            codec::IntentCause::LandedRefresh,
        )
    });
    accept(f, coverage, "landed-replacement", |f| {
        f.overlay.replace_landed(&mut f.store, &f.owner, proof)
    });
    assert_eq!(
        f.overlay
            .namespace
            .entries
            .values()
            .cloned()
            .collect::<Vec<_>>(),
        expected_landed,
        "landed answers equal the sealed primary image"
    );
}

fn lifecycle(f: &mut Fixture, coverage: &mut Coverage) {
    let id = accept(f, coverage, "copy-up", |f| {
        f.overlay
            .copy_up(&mut f.store, &f.owner, at("clean-one"), &mut f.source)
    });
    accept(f, coverage, "write", |f| {
        f.overlay.write(&mut f.store, &f.owner, id, 0, b"seed")
    });
    let capture = accept(f, coverage, "capture-file", |f| {
        f.overlay.capture(&mut f.store, &f.owner, id)
    });
    accept(f, coverage, "flush-boundary", |f| {
        f.overlay.flush_boundary(&mut f.store, &f.owner, &capture)
    });
    let body = capture.chunks.concat();
    let content = GrainId::of(&body);
    f.source.0.insert(content, body);
    let receipt = RegisteredCapture {
        capture,
        writer: [17; 16],
        generation: 1,
        prepared_root: grain(2),
        content,
    };
    accept(f, coverage, "file-sync", |f| {
        f.overlay
            .record_file_synced(&mut f.store, &f.owner, &receipt)
    });
    accept(f, coverage, "register-directory", |f| {
        f.overlay.record_intent_registered(
            &mut f.store,
            &f.owner,
            2,
            grain(2),
            codec::IntentCause::DirectorySync,
        )
    });
    let before_replay = f.overlay.namespace.entries.clone();
    accept(f, coverage, "replay", |f| {
        f.overlay.recover(&mut f.store, &f.owner, &mut f.source)
    });
    assert_eq!(
        f.overlay.namespace.entries, before_replay,
        "replay preserves all primary answers"
    );
    land(f, coverage);
    let capture = accept(f, coverage, "capture-boundary", |f| {
        f.overlay.capture_boundary(&mut f.store, &f.owner)
    });
    let boundary = accept(f, coverage, "commit-boundary", |f| {
        f.overlay
            .record_boundary(&mut f.store, &f.owner, capture, grain(4), [8; 16])
    });
    let before_rejected = f.overlay.namespace.entries.clone();
    accept(f, coverage, "rejected-replacement", |f| {
        f.overlay
            .replace_rejected(&mut f.store, &f.owner, boundary, [8; 16])
    });
    assert_eq!(
        f.overlay.namespace.entries, before_rejected,
        "rejected replacement preserves complete primary answers"
    );
    let normalized = |f: &Fixture| {
        f.overlay
            .namespace
            .entries
            .values()
            .cloned()
            .map(|mut entry| {
                entry.inode = 0;
                entry
            })
            .collect::<Vec<_>>()
    };
    let before_reopen = normalized(f);
    accept(f, coverage, "reopen", Fixture::reopen);
    assert_eq!(
        normalized(f),
        before_reopen,
        "reopen preserves answers across the new inode-allocation lifetime"
    );
}

#[test]
fn seeded_namespace_operations_match_independent_answers_and_cover_records() {
    let mut coverage = Coverage::default();
    let mut empty = Fixture::new();
    audit(&mut empty, &mut coverage);
    for seed in 1..=4 {
        let mut base = vec![
            directory("d"),
            directory("d/deep"),
            directory("empty"),
            directory("wide"),
            file("clean-one"),
            file("clean-two"),
        ];
        base.extend((0..17).map(|i| file(&format!("wide/item-{i}"))));
        let mut source = Source::default();
        source.0.insert(GrainId::of(b"body"), b"body".to_vec());
        let mut f = Fixture::with_base(base, source);
        assert_eq!(
            f.overlay.namespace.entries.len(),
            23,
            "actual seeded primary rows: {}",
            f.overlay.namespace.entries.len()
        );
        audit(&mut f, &mut coverage);
        let mut rng = SeededRng::new(seed);
        for round in 0..3 {
            let suffix = rng.below(100_000) + round * 100_000;
            let start = rng.below(3);
            for i in 0..3 {
                match (start + i) % 3 {
                    0 => directory_cycle(&mut f, &mut coverage, suffix),
                    1 => file_cycle(&mut f, &mut coverage, suffix),
                    _ => symlink_cycle(&mut f, &mut coverage, suffix),
                }
            }
        }
        refuse(
            &mut f,
            &mut coverage,
            "same-path",
            Record::Move {
                from: at("d"),
                to: at("d"),
            },
            "overlay refused: move cycle or identity",
        );
        refuse(
            &mut f,
            &mut coverage,
            "noreplace",
            Record::Move {
                from: at("d"),
                to: at("empty"),
            },
            "overlay refused: replace destination refused",
        );
        clean_unlink(&mut f, &mut coverage);
        lifecycle(&mut f, &mut coverage);
    }
    check_coverage(&coverage);
}

fn check_coverage(coverage: &Coverage) {
    let required = [
        "mkdir",
        "symlink",
        "create-file",
        "subtree-move",
        "subtree-replace",
        "write",
        "truncate",
        "chmod",
        "unlink-held",
        "unlink-clean-held",
        "recreate-file",
        "recreate-clean-name",
        "shared-hold",
        "clean-shared-hold",
        "copy-up",
        "capture-file",
        "flush-boundary",
        "file-sync",
        "register-directory",
        "capture-boundary",
        "commit-boundary",
        "landed-record",
        "register-landed",
        "landed-replacement",
        "rejected-replacement",
        "replay",
        "reopen",
        "same-path",
        "noreplace",
        "nonempty-rmdir",
        "rmdir",
        "symlink-move",
        "unlink-symlink",
        "unlink-recreated",
        "unlink-clean-recreated",
        "close-hold",
        "clean-close-hold",
        "clean-detach-copy-up",
    ];
    let operations =
        required.map(|label| (label, coverage.operations.get(label).copied().unwrap_or(0)));
    assert_eq!(
        (
            operations.len(),
            operations.iter().all(|(_, count)| *count > 0)
        ),
        (38, true),
        "nonzero operation coverage: {operations:?}"
    );
    assert_eq!(
        (
            coverage.records.len(),
            coverage.records.values().all(|count| *count > 0),
            coverage.queries.iter().all(|count| *count > 0)
        ),
        (14, true, true),
        "nonzero record/query coverage: {coverage:?}"
    );
    for label in [
        "replay",
        "reopen",
        "landed-replacement",
        "rejected-replacement",
    ] {
        assert_eq!(
            coverage.operations.get(label),
            Some(&4),
            "nonzero lifecycle route={label}, coverage={coverage:?}"
        );
    }
    eprintln!(
        "seeded operations={:?}; distinct encoded record observations={:?}; query routes={:?}",
        coverage.operations, coverage.records, coverage.queries
    );
}
