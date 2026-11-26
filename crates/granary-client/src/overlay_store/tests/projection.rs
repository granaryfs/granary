// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn replay_clones_only_record_namespace_paths() {
    let mut f = Fixture::with_base(
        (0..128).map(|i| base(&format!("base{i:03}"), 1)).collect(),
        Source::default(),
    );
    let stage = f.create();
    for _ in 0..32 {
        f.write(stage, b"edit");
    }
    f.sync(stage, 1);
    ns(
        &mut f,
        Record::Move {
            from: at("f"),
            to: at("moved"),
        },
    );
    let bytes = f.overlay.journal_bytes().unwrap();
    let mut live = f.overlay.namespace.clone();
    state::CLONED_ENTRIES.set(0);
    let replayed = provenance::History::replay(&f.overlay.base, &bytes, &mut live).unwrap();
    assert_eq!(
        state::CLONED_ENTRIES.get(),
        0,
        "replay cloned unrelated namespace entries per record"
    );
    let mut expected = f.overlay.history.clone();
    // The replay path conservatively resets volatile checkpoint boundaries.
    for checkpoint in expected.checkpoints.values_mut() {
        checkpoint.content_boundary = 0;
    }
    assert_eq!(
        replayed
            .records
            .iter()
            .map(|e| (e.source, e.result, e.dependencies.clone()))
            .collect::<Vec<_>>(),
        expected
            .records
            .iter()
            .map(|e| (e.source, e.result, e.dependencies.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        replayed.checkpoints.keys().collect::<Vec<_>>(),
        expected.checkpoints.keys().collect::<Vec<_>>()
    );
}

#[test]
fn replay_keys_a_detached_stage_checkpoint_by_its_live_inode() {
    let mut f = Fixture::with_base(vec![], Source::default());
    let stage = f.create();
    f.write(stage, b"edit");
    f.sync(stage, 1);
    ns(
        &mut f,
        Record::Delete {
            at: at("f"),
            kind: codec::DeleteKind::File {
                stage_id: Some(stage),
            },
        },
    );
    let bytes = f.overlay.journal_bytes().unwrap();
    let mut live = f.overlay.namespace.clone();
    // A rebuilt namespace keeps different numbers than a fresh replay assigns.
    for stage in live.stages.values_mut() {
        stage.inode += 1000;
    }
    let live_inode = live.stages.get(&stage).unwrap().inode;
    let replayed = provenance::History::replay(&f.overlay.base, &bytes, &mut live).unwrap();
    assert_eq!(
        replayed.checkpoints.keys().copied().collect::<Vec<_>>(),
        vec![live_inode],
        "detached stage checkpoint kept a replay inode"
    );
    assert_eq!(replayed.checkpoints[&live_inode].inode, live_inode);
}

fn durable(f: &Fixture, path: &str, byte: u8, boundary: u64) -> DurableFile {
    let entry = f.overlay.namespace.entries.get(&vec![name(path)]).unwrap();
    DurableFile {
        inode: entry.inode,
        size: 1,
        content: grain(byte),
        content_boundary: boundary,
    }
}
fn seal(f: &mut Fixture) -> SyncBoundary {
    f.overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap()
}
fn ns(f: &mut Fixture, record: Record) {
    f.overlay
        .namespace_record(&mut f.store, &f.owner, record)
        .unwrap();
}
pub(super) fn base(path: &str, byte: u8) -> OverlayEntry {
    OverlayEntry {
        path: vec![name(path)],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(grain(byte)),
        },
        stage_id: None,
        size: 1,
        exec: false,
    }
}
fn rows(entries: &[OverlayEntry]) -> Vec<(String, Option<GrainId>)> {
    entries
        .iter()
        .map(|entry| {
            (
                entry
                    .path
                    .iter()
                    .map(|name| std::str::from_utf8(name.as_bytes()).unwrap())
                    .collect::<Vec<_>>()
                    .join("/"),
                match entry.kind {
                    OverlayKind::File { content } => content,
                    _ => None,
                },
            )
        })
        .collect()
}

#[test]
fn unsynced_replacement_and_its_delete_do_not_remove_durable_target() {
    let mut f = Fixture::with_base(vec![base("x", 1)], Source::default());
    let y = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("y"), false)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, y, 0, b"unsynced")
        .unwrap();
    ns(
        &mut f,
        Record::Replace {
            from: at("y"),
            to: at("x"),
        },
    );
    ns(
        &mut f,
        Record::Delete {
            at: at("x"),
            kind: codec::DeleteKind::File { stage_id: Some(y) },
        },
    );
    let b = seal(&mut f);
    let deletion = b
        .effects()
        .iter()
        .find(|effect| matches!(effect.record(), Record::Delete { .. }))
        .unwrap();
    assert!(
        deletion.dependencies().contains(&3),
        "delete lost excluded replacement provenance"
    );
    assert_eq!(
        rows(b.project(&[]).unwrap().entries()),
        vec![("x".into(), Some(grain(1)))],
        "excluded replacement deleted the old durable target"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn rename_chains_and_reused_vacancies_follow_identity_dependencies() {
    let mut count = 0;
    for eligible in [false, true] {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"a");
        let d = durable(&f, "f", 8, 2);
        ns(
            &mut f,
            Record::Move {
                from: at("f"),
                to: at("b"),
            },
        );
        ns(
            &mut f,
            Record::Move {
                from: at("b"),
                to: at("c"),
            },
        );
        ns(
            &mut f,
            Record::Create {
                at: at("f"),
                kind: codec::CreateKind::Dir,
            },
        );
        let b = seal(&mut f);
        let expected = if eligible {
            vec![("c".into(), Some(grain(8))), ("f".into(), None)]
        } else {
            vec![]
        };
        assert_eq!(
            rows(
                b.project(if eligible {
                    std::slice::from_ref(&d)
                } else {
                    &[]
                })
                .unwrap()
                .entries()
            ),
            expected,
            "rename chain/vacancy exclusion was not forward closed"
        );
        f.overlay.release_sync_boundary(&b).unwrap();
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn directory_move_keeps_directories_and_only_eligible_descendants() {
    let mut f = Fixture::new();
    ns(
        &mut f,
        Record::Create {
            at: at("d"),
            kind: codec::CreateKind::Dir,
        },
    );
    let child = |s: &str| codec::Location {
        parent: codec::Parent::new(vec![name("d")]).unwrap(),
        name: name(s),
    };
    let s = f
        .overlay
        .create_file(&mut f.store, &f.owner, child("s"), false)
        .unwrap();
    let u = f
        .overlay
        .create_file(&mut f.store, &f.owner, child("u"), false)
        .unwrap();
    f.overlay.write(&mut f.store, &f.owner, s, 0, b"s").unwrap();
    f.overlay.write(&mut f.store, &f.owner, u, 0, b"u").unwrap();
    let checkpoint = DurableFile {
        inode: f
            .overlay
            .namespace
            .entries
            .get(&vec![name("d"), name("s")])
            .unwrap()
            .inode,
        size: 1,
        content: grain(3),
        content_boundary: 5,
    };
    ns(
        &mut f,
        Record::Create {
            at: child("q"),
            kind: codec::CreateKind::Dir,
        },
    );
    ns(
        &mut f,
        Record::Move {
            from: at("d"),
            to: at("e"),
        },
    );
    let b = seal(&mut f);
    assert_eq!(
        rows(b.project(&[checkpoint]).unwrap().entries()),
        vec![
            ("e".into(), None),
            ("e/q".into(), None),
            ("e/s".into(), Some(grain(3)))
        ],
        "directory move dropped eligible subtree or admitted unsynced child"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn durable_source_replaces_synced_or_omitted_target_atomically() {
    let mut cases = 0;
    for synced_target in [false, true] {
        for eligible in [false, true] {
            let mut f = if synced_target {
                Fixture::with_base(vec![base("x", 1)], Source::default())
            } else {
                Fixture::new()
            };
            if !synced_target {
                f.overlay
                    .create_file(&mut f.store, &f.owner, at("x"), false)
                    .unwrap();
            }
            let y = f
                .overlay
                .create_file(&mut f.store, &f.owner, at("y"), false)
                .unwrap();
            f.overlay
                .write(&mut f.store, &f.owner, y, 0, b"new")
                .unwrap();
            let d = durable(&f, "y", 2, 3);
            ns(
                &mut f,
                Record::Replace {
                    from: at("y"),
                    to: at("x"),
                },
            );
            let b = seal(&mut f);
            let expected = if eligible {
                vec![("x".into(), Some(grain(2)))]
            } else if synced_target {
                vec![("x".into(), Some(grain(1)))]
            } else {
                vec![]
            };
            assert_eq!(
                rows(
                    b.project(if eligible {
                        std::slice::from_ref(&d)
                    } else {
                        &[]
                    })
                    .unwrap()
                    .entries()
                ),
                expected,
                "replacement was not old-or-new durable content"
            );
            f.overlay.release_sync_boundary(&b).unwrap();
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn symlink_payload_does_not_require_regular_file_selection() {
    let mut f = Fixture::with_base(vec![base("x", 1)], Source::default());
    ns(
        &mut f,
        Record::Create {
            at: at("l"),
            kind: codec::CreateKind::Symlink {
                target: SymlinkTarget::new(b"never-synced-target".to_vec()).unwrap(),
            },
        },
    );
    ns(
        &mut f,
        Record::Move {
            from: at("l"),
            to: at("m"),
        },
    );
    ns(
        &mut f,
        Record::Replace {
            from: at("m"),
            to: at("x"),
        },
    );
    let b = seal(&mut f);
    let p = b.project(&[]).unwrap();
    assert_eq!(
        (
            p.entries().len(),
            &p.entries()[0].path,
            &p.entries()[0].kind
        ),
        (
            1,
            &vec![name("x")],
            &OverlayKind::Symlink {
                target: SymlinkTarget::new(b"never-synced-target".to_vec()).unwrap()
            }
        )
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn covering_cursor_contains_complete_mutations_and_sealed_namespace_identity() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"one");
    let d = durable(&f, "f", 4, 2);
    ns(
        &mut f,
        Record::Move {
            from: at("f"),
            to: at("g"),
        },
    );
    let b = seal(&mut f);
    ns(
        &mut f,
        Record::Move {
            from: at("g"),
            to: at("h"),
        },
    );
    f.overlay
        .write(&mut f.store, &f.owner, id, 0, b"two")
        .unwrap();
    let input = b.project(&[d]).unwrap().coverage_input(grain(5));
    assert_eq!(
        (
            input.boundary,
            input.projections[0].stage_id,
            input.projections[0].path.clone(),
            input.projections[0].content_boundary,
            input.mutations.len()
        ),
        (3, id, vec![name("g")], 2, 1),
        "live rename/write changed sealed covering provenance"
    );
    assert!(
        matches!(input.mutations[0], crate::StageMutation::Write { seq: 2, stage_id, offset: 0, length: 3, .. } if stage_id == id)
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn rollback_reaches_covering_projection_with_its_original_sequence() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"one");
    let selected = durable(&f, "f", 3, 2);
    let seq = f
        .overlay
        .append(&Record::StageRollback {
            stage_id: id,
            old_size: 3,
            anchor: Some(codec::RecreateAnchor {
                content: selected.content,
                size: 3,
            }),
            discarded_bytes: 3,
        })
        .unwrap();
    let seal = seal(&mut f);
    let coverage = seal.project(&[selected]).unwrap().coverage_input(grain(5));
    assert_eq!(
        coverage.mutations.len(),
        2,
        "write and rollback: {:?}",
        coverage.mutations
    );
    assert!(matches!(
        coverage.mutations.last(),
        Some(crate::StageMutation::Rollback { seq: actual, stage_id, incarnation })
            if (*actual, *stage_id, *incarnation) == (seq, id, seal.incarnation())
    ));
    f.overlay.release_sync_boundary(&seal).unwrap();
}

#[test]
fn unknown_duplicate_and_future_eligibility_refused_with_nonempty_control() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"a");
    let d = durable(&f, "f", 4, 2);
    let b = seal(&mut f);
    assert_eq!(
        b.project(std::slice::from_ref(&d)).unwrap().entries().len(),
        1
    );
    let mut unknown = d.clone();
    unknown.inode = 1000;
    let mut future = d.clone();
    future.content_boundary = 3;
    let mut oversized = d.clone();
    oversized.size = codec::SIZE_MAX + 1;
    let cases = [
        vec![unknown],
        vec![future],
        vec![oversized],
        vec![d.clone(), d],
    ];
    for case in &cases {
        assert_eq!(
            b.project(case).unwrap_err().to_string(),
            "overlay refused: durable projection identity/boundary"
        );
    }
    assert_eq!(cases.len(), 4);
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn mismatched_source_and_parent_provenance_refuses_with_valid_replay() {
    let mut f = Fixture::with_base(vec![base("x", 1)], Source::default());
    ns(
        &mut f,
        Record::Move {
            from: at("x"),
            to: at("y"),
        },
    );
    let valid = seal(&mut f);
    assert_eq!(
        rows(valid.project(&[]).unwrap().entries()),
        vec![("y".into(), Some(grain(1)))]
    );
    f.overlay.release_sync_boundary(&valid).unwrap();
    let original = f.overlay.history.records.last().unwrap().clone();
    let mut count = 0;
    for reason in ["source", "parent", "count"] {
        let mut bad = (*original).clone();
        match reason {
            "source" => bad.source = Some(999),
            "parent" => bad.parents[0] = 999,
            "count" => {
                bad.parents.pop();
            }
            _ => unreachable!(),
        }
        *f.overlay.history.records.last_mut().unwrap() = Arc::new(bad);
        let b = seal(&mut f);
        let expected = match reason {
            "source" => "overlay refused: projection source identity",
            "parent" => "overlay refused: projection parent identity",
            _ => "overlay refused: projection parent count",
        };
        assert_eq!(b.project(&[]).unwrap_err().to_string(), expected);
        f.overlay.release_sync_boundary(&b).unwrap();
        count += 1;
    }
    *f.overlay.history.records.last_mut().unwrap() = original;
    assert_eq!(count, 3);
}

#[test]
fn unsynced_overwrite_keeps_the_base_payload_in_projection() {
    let mut f = Fixture::with_base(
        vec![base("x", 1)],
        Source(BTreeMap::from([(grain(1), vec![1])])),
    );
    let stage = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("x"), &mut f.source)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, stage, 0, b"new bytes")
        .unwrap();
    let b = seal(&mut f);
    let projected = b.project(&[]).unwrap();
    assert_eq!(
        (
            rows(projected.entries()),
            projected.entries()[0].size,
            b.entries()[0].size
        ),
        (vec![("x".into(), Some(grain(1)))], 1, 9),
        "unsynced overwrite replaced the durable payload"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn unrelated_file_capture_does_not_make_an_unsynced_rename_eligible() {
    let mut f = Fixture::new();
    let selected = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("x"), false)
        .unwrap();
    let unsynced = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("y"), false)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, selected, 0, b"x")
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, unsynced, 0, b"y")
        .unwrap();
    ns(
        &mut f,
        Record::Move {
            from: at("y"),
            to: at("z"),
        },
    );
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(selected))
        .unwrap();
    let checkpoint = durable(&f, "x", 1, b.through_seq());
    let projected = b.project(&[checkpoint]).unwrap();
    assert_eq!(
        (b.files().len(), rows(projected.entries())),
        (1, vec![("x".into(), Some(grain(1)))]),
        "unrelated capture made the renamed file durable"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

fn dir_entry(path: &[&str]) -> OverlayEntry {
    OverlayEntry {
        path: path.iter().map(|p| name(p)).collect(),
        inode: 0,
        kind: OverlayKind::Directory,
        stage_id: None,
        size: 0,
        exec: false,
    }
}
fn file_entry(path: &[&str], byte: u8) -> OverlayEntry {
    OverlayEntry {
        path: path.iter().map(|p| name(p)).collect(),
        inode: 0,
        kind: OverlayKind::File {
            content: Some(grain(byte)),
        },
        stage_id: None,
        size: 1,
        exec: false,
    }
}
fn nested(parent: &[&str], leaf: &str) -> codec::Location {
    codec::Location {
        parent: codec::Parent::new(parent.iter().map(|p| name(p)).collect()).unwrap(),
        name: name(leaf),
    }
}
/// The directories in a projection's rebuild set, by path ("" is the root).
fn rebuild_paths(projection: &PreparedProjection) -> Vec<String> {
    let mut out: Vec<String> = projection
        .entries()
        .iter()
        .filter(|e| projection.rebuild_set().contains(&e.inode))
        .map(|e| {
            e.path
                .iter()
                .map(|n| std::str::from_utf8(n.as_bytes()).unwrap())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    if projection.rebuild_set().contains(&0) {
        out.push(String::new());
    }
    out.sort();
    out
}

#[test]
fn a_payload_that_differs_from_its_base_entry_dirties_its_parent_without_any_effect() {
    let mut f = Fixture::with_base(
        vec![
            dir_entry(&["d"]),
            file_entry(&["d", "x"], 1),
            dir_entry(&["e"]),
            file_entry(&["e", "y"], 2),
        ],
        Source::default(),
    );
    let inode = f.overlay.namespace.entries[&vec![name("d"), name("x")]].inode;
    let b = seal(&mut f);
    let same = DurableFile {
        inode,
        size: 1,
        content: grain(1),
        content_boundary: 0,
    };
    assert_eq!(
        rebuild_paths(&b.project(std::slice::from_ref(&same)).unwrap()),
        Vec::<String>::new(),
        "the base payload dirtied a directory"
    );
    for changed in [
        DurableFile {
            content: grain(9),
            ..same.clone()
        },
        DurableFile { size: 2, ..same },
    ] {
        assert_eq!(
            rebuild_paths(&b.project(&[changed]).unwrap()),
            ["", "d"],
            "a changed payload did not dirty its parent and the root, and only those"
        );
    }
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn surviving_effects_dirty_both_parents_and_an_excluded_one_dirties_none() {
    let mut f = Fixture::with_base(
        vec![
            dir_entry(&["a"]),
            file_entry(&["a", "x"], 1),
            dir_entry(&["b"]),
            dir_entry(&["c"]),
        ],
        Source::default(),
    );
    ns(
        &mut f,
        Record::Move {
            from: nested(&["a"], "x"),
            to: nested(&["b"], "x"),
        },
    );
    let stage = f
        .overlay
        .create_file(&mut f.store, &f.owner, nested(&["c"], "ghost"), false)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, stage, 0, b"never synced")
        .unwrap();
    let b = seal(&mut f);
    assert_eq!(
        rebuild_paths(&b.project(&[]).unwrap()),
        ["", "a", "b"],
        "the move must dirty its source and destination parents, the excluded create none"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn a_new_directory_and_its_ancestors_are_rebuilt_even_when_empty() {
    let mut f = Fixture::with_base(vec![dir_entry(&["a"])], Source::default());
    ns(
        &mut f,
        Record::Create {
            at: nested(&["a"], "fresh"),
            kind: codec::CreateKind::Dir,
        },
    );
    ns(
        &mut f,
        Record::Create {
            at: nested(&["a", "fresh"], "deeper"),
            kind: codec::CreateKind::Dir,
        },
    );
    let b = seal(&mut f);
    assert_eq!(
        rebuild_paths(&b.project(&[]).unwrap()),
        ["", "a", "a/fresh", "a/fresh/deeper"],
        "a created directory, even an empty one, and its ancestors are rebuilt"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

/// A projection's rows by path with sizes and stage annotations, leaving out
/// inodes: a replay numbers them differently from the view.
fn bound_rows(entries: &[OverlayEntry]) -> Vec<(String, Option<GrainId>, u64, Option<u64>)> {
    let mut out: Vec<_> = rows(entries)
        .into_iter()
        .zip(entries)
        .map(|((path, content), entry)| (path, content, entry.size, entry.stage_id))
        .collect();
    out.sort();
    out
}
fn create_at(f: &mut Fixture, path: &str, bytes: &[u8]) -> u64 {
    let stage = f
        .overlay
        .create_file(&mut f.store, &f.owner, at(path), false)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, stage, 0, bytes)
        .unwrap();
    stage
}
/// Seal `target`, project it with `selection` as its sync would, and record
/// a projected boundary at that seal's cursor. Returns the boundary's index
/// and the projection a restart must rebuild.
fn projected_boundary(
    f: &mut Fixture,
    target: SyncTarget,
    selection: Option<codec::ProjectedSelection>,
) -> (u64, Vec<OverlayEntry>) {
    let b = f.overlay.seal_sync(&mut f.store, &f.owner, target).unwrap();
    let selected: Vec<_> = selection
        .iter()
        .map(|s| DurableFile {
            inode: f.overlay.namespace.stages[&s.stage_id].inode,
            size: s.size,
            content: s.content,
            content_boundary: b.through_seq(),
        })
        .collect();
    let sealed = b.project(&selected).unwrap().entries().to_vec();
    let through_seq = b.through_seq();
    f.overlay.release_sync_boundary(&b).unwrap();
    let index = f
        .overlay
        .append(&Record::ProjectedBoundary {
            candidate: grain(9),
            through_seq,
            publication_id: [9; 16],
            selection,
        })
        .unwrap();
    (index, sealed)
}

/// A restart rebuilds the projection the seal made from the journal through
/// its cursor and the saved selection: a synced file at its mark although
/// overwritten before the seal, a never-synced creation left out, the selected
/// file at its saved payload, and nothing written, moved or created after the
/// seal.
#[test]
fn a_projected_boundary_rebuilds_its_seals_projection_after_later_work() {
    let mut outcomes = Vec::new();
    for selected in [true, false] {
        let mut f = Fixture::with_base(vec![base("y", 1)], Source::default());
        let w = create_at(&mut f, "w", b"w1");
        f.sync(w, 1);
        f.overlay
            .write(&mut f.store, &f.owner, w, 0, b"w2 is longer")
            .unwrap();
        create_at(&mut f, "z", b"never synced");
        let x = create_at(&mut f, "x", b"x captured");
        let (target, selection) = if selected {
            let selection = codec::ProjectedSelection {
                stage_id: x,
                content: grain(5),
                size: 10,
            };
            (SyncTarget::Stage(x), Some(selection))
        } else {
            (SyncTarget::Directory(None), None)
        };
        let (index, sealed) = projected_boundary(&mut f, target, selection);
        f.overlay
            .write(
                &mut f.store,
                &f.owner,
                x,
                0,
                b"x overwritten after the seal",
            )
            .unwrap();
        ns(
            &mut f,
            Record::Move {
                from: at("x"),
                to: at("moved"),
            },
        );
        create_at(&mut f, "later", b"after the seal");
        let live = f.overlay.projected_commit_entries(index, [9; 16]).unwrap();
        f.reopen().unwrap();
        let reopened = f.overlay.projected_commit_entries(index, [9; 16]).unwrap();
        outcomes.push((
            bound_rows(&live),
            bound_rows(&reopened),
            bound_rows(&sealed),
        ));
    }
    let mark = GrainId::of(b"w1");
    let synced = ("w".to_owned(), Some(mark), 2, Some(1));
    let durable = ("y".to_owned(), Some(grain(1)), 1, None);
    let with_x = vec![
        synced.clone(),
        ("x".to_owned(), Some(grain(5)), 10, Some(3)),
        durable.clone(),
    ];
    let without_x = vec![synced, durable];
    assert_eq!(
        outcomes,
        [
            (with_x.clone(), with_x.clone(), with_x),
            (without_x.clone(), without_x.clone(), without_x),
        ],
        "a rebuilt projection differs from its seal's"
    );
}

/// The boundary must be the projected record that names this publication,
/// and a selection must name a file at the boundary; each refuses alone.
#[test]
fn a_projected_boundary_that_does_not_bind_its_selection_refuses() {
    let mut outcomes = Vec::new();
    for case in ["bound", "whole tree", "publication", "unnamed"] {
        let mut f = Fixture::new();
        let x = create_at(&mut f, "x", b"x captured");
        let gone = create_at(&mut f, "gone", b"unlinked before the seal");
        ns(
            &mut f,
            Record::Delete {
                at: at("gone"),
                kind: codec::DeleteKind::File {
                    stage_id: Some(gone),
                },
            },
        );
        let stage_id = if case == "unnamed" { gone } else { x };
        let index = if case == "whole tree" {
            let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
            f.overlay
                .record_boundary(&mut f.store, &f.owner, capture, grain(9), [9; 16])
                .unwrap()
        } else {
            let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
            f.overlay
                .append(&Record::ProjectedBoundary {
                    candidate: grain(9),
                    through_seq,
                    publication_id: [9; 16],
                    selection: Some(codec::ProjectedSelection {
                        stage_id,
                        content: grain(5),
                        size: 10,
                    }),
                })
                .unwrap()
        };
        let publication = if case == "publication" {
            [8; 16]
        } else {
            [9; 16]
        };
        outcomes.push((
            case,
            f.overlay
                .projected_commit_entries(index, publication)
                .map(|entries| rows(&entries))
                .map_err(|error| error.to_string()),
        ));
    }
    let refused = |reason: &str| Err(format!("overlay refused: {reason}"));
    assert_eq!(
        outcomes,
        [
            ("bound", Ok(vec![("x".to_owned(), Some(grain(5)))])),
            ("whole tree", refused("projected prefix binding")),
            ("publication", refused("projected prefix binding")),
            ("unnamed", refused("projected selection unnamed")),
        ]
    );
}

#[test]
fn complete_snapshot_selection_is_exact_and_bounded() {
    let mut f = Fixture::with_base(
        vec![base("f", 1)],
        Source(BTreeMap::from([(grain(1), vec![1])])),
    );
    let stage = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    f.write(stage, b"x");
    let boundary = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
        .unwrap()
        .for_complete_commit();
    let selected = durable(&f, "f", 7, boundary.through_seq());
    assert_eq!(
        rows(
            boundary
                .project(std::slice::from_ref(&selected))
                .unwrap()
                .entries()
        ),
        vec![("f".into(), Some(grain(7)))]
    );
    let mut cases = 0;
    for malformed in [
        vec![],
        vec![selected.clone(), selected.clone()],
        vec![DurableFile {
            inode: u64::MAX,
            ..selected.clone()
        }],
        vec![DurableFile {
            size: 2,
            ..selected.clone()
        }],
        vec![DurableFile {
            content_boundary: boundary.through_seq() + 1,
            ..selected.clone()
        }],
    ] {
        let result = boundary.project(&malformed);
        assert!(
            matches!(
                result,
                Err(OverlayError::Refused("complete tree selection"))
            ),
            "{result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[test]
fn complete_snapshot_refuses_missing_or_inconsistent_clean_payloads() {
    let mut cases = 0;
    for malformed in ["size", "content", "missing"] {
        let mut f = Fixture::with_base(vec![base("f", 1)], Source::default());
        let valid = f
            .overlay
            .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
            .unwrap()
            .for_complete_commit();
        assert_eq!(
            rows(valid.project(&[]).unwrap().entries()),
            vec![("f".into(), Some(grain(1)))]
        );
        match malformed {
            "missing" => f.overlay.history.base.clear(),
            "size" => f.overlay.history.base.first_mut().unwrap().size += 1,
            _ => {
                f.overlay.history.base.first_mut().unwrap().kind = OverlayKind::File {
                    content: Some(grain(9)),
                }
            }
        }
        let boundary = f
            .overlay
            .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
            .unwrap()
            .for_complete_commit();
        let result = boundary.project(&[]);
        assert!(
            matches!(result, Err(OverlayError::Refused("complete tree payload"))),
            "{malformed}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}
