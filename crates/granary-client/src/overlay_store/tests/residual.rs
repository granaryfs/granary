// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::snapshot::materialize;
use super::*;
use codec::{ProjectedSelection, Record};

const PUBLICATION: [u8; 16] = [9; 16];

fn file(path: &str, bytes: &[u8]) -> OverlayEntry {
    OverlayEntry {
        path: vec![name(path)],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(GrainId::of(bytes)),
        },
        stage_id: None,
        size: bytes.len() as u64,
        exec: false,
    }
}
fn with_files(files: &[(&str, &[u8])]) -> Fixture {
    let mut source = Source::default();
    for (_, bytes) in files {
        source.0.insert(GrainId::of(bytes), bytes.to_vec());
    }
    Fixture::with_base(
        files
            .iter()
            .map(|(path, bytes)| file(path, bytes))
            .collect(),
        source,
    )
}
fn at_in(dir: &str, leaf: &str) -> codec::Location {
    codec::Location {
        parent: codec::Parent::new(vec![name(dir)]).unwrap(),
        name: name(leaf),
    }
}
fn ns(f: &mut Fixture, record: Record) {
    f.overlay
        .namespace_record(&mut f.store, &f.owner, record)
        .unwrap();
}
fn create_at(f: &mut Fixture, at: codec::Location, bytes: &[u8]) -> u64 {
    let stage = f
        .overlay
        .create_file(&mut f.store, &f.owner, at, false)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, stage, 0, bytes)
        .unwrap();
    stage
}
fn hold(f: &mut Fixture, path: &[Name]) {
    f.overlay.open_stage(&mut f.store, &f.owner, path).unwrap();
}
fn unlink(f: &mut Fixture, path: &str, stage: u64) {
    ns(
        f,
        Record::Delete {
            at: at(path),
            kind: codec::DeleteKind::File {
                stage_id: Some(stage),
            },
        },
    );
}
/// Record a published sync as its engine does: the cursor before the sync,
/// the selected file's sync after it, then a projected boundary selecting
/// that capture at the cursor. `None` is a directory sync.
fn publish(f: &mut Fixture, stage: Option<u64>, generation: u64) -> u64 {
    let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    let selection = stage.map(|stage_id| {
        let bytes = f.sync(stage_id, generation).chunks.concat();
        ProjectedSelection {
            stage_id,
            content: GrainId::of(&bytes),
            size: bytes.len() as u64,
        }
    });
    f.overlay
        .append(&Record::ProjectedBoundary {
            candidate: grain(9),
            through_seq,
            publication_id: PUBLICATION,
            selection,
        })
        .unwrap()
}
/// Land the boundary at its projection and record the matching refresh, as
/// the engine journals them.
fn land(f: &mut Fixture, boundary: u64) -> LandedProof {
    let entries: Vec<_> = f
        .overlay
        .projected_commit_entries(boundary, PUBLICATION)
        .unwrap()
        .into_iter()
        .map(|mut entry| {
            entry.stage_id = None;
            entry
        })
        .collect();
    let (base_seq, generation) = {
        let journal = f.overlay.journal.lock().unwrap();
        (journal.header.base_seq, journal.state.highest_generation())
    };
    let proof = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(4),
        landed_seq: base_seq + 1,
        captured_entries: entries.clone(),
        entries,
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            generation + 1,
            proof.landed_root,
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    proof
}
/// Land the boundary, install its replacement and reopen over the landed
/// entries. Returns the stages the install retired.
fn install(f: &mut Fixture, boundary: u64) -> Result<Vec<u64>, OverlayError> {
    let proof = land(f, boundary);
    let before: Vec<_> = f.overlay.namespace.stages.keys().copied().collect();
    f.overlay.replace_landed(&mut f.store, &f.owner, proof)?;
    f.reopen()?;
    Ok(before
        .into_iter()
        .filter(|id| !f.overlay.namespace.stages.contains_key(id))
        .collect())
}
fn journal_records(f: &Fixture) -> Vec<Record> {
    let mut records = Vec::new();
    codec::scan_journal_with(&f.io.bytes(&f.overlay.journal_path()), |_, record| {
        records.push(record.clone());
    })
    .unwrap();
    records
}
/// A file's bytes as a capture materializes them: staged through the stage's
/// journal state, otherwise its immutable entry's payload.
fn bytes_at(f: &mut Fixture, path: &str) -> Vec<u8> {
    let entry = f.overlay.namespace.entries[&vec![name(path)]].clone();
    if let Some(stage) = entry.stage_id {
        let b = f
            .overlay
            .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
            .unwrap();
        let file = b.files()[0].clone();
        let bytes = materialize(f, &b, &file).concat();
        f.overlay.release_sync_boundary(&b).unwrap();
        bytes
    } else {
        let OverlayKind::File {
            content: Some(content),
        } = entry.kind
        else {
            panic!("{path} is not a file");
        };
        f.source.0[&content].clone()
    }
}
/// Every entry as (path, stage, size), the inode-free namespace a replay
/// must reproduce.
fn namespace_rows(f: &Fixture) -> Vec<(Vec<Name>, Option<u64>, u64)> {
    f.overlay
        .namespace
        .entries
        .values()
        .map(|e| (e.path.clone(), e.stage_id, e.size))
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Write(u64, &'static [u8]),
    Truncate(u64),
    /// A sync of y alone, giving it a checkpoint.
    Sync,
    /// The published sync of x; later operations are after its boundary.
    Seal,
}
fn write_model(model: &mut Vec<u8>, offset: u64, bytes: &[u8]) {
    let start = usize::try_from(offset).unwrap();
    if model.len() < start + bytes.len() {
        model.resize(start + bytes.len(), 0);
    }
    model[start..start + bytes.len()].copy_from_slice(bytes);
}
fn apply(model: &mut Vec<u8>, op: Op) {
    match op {
        Op::Write(offset, bytes) => write_model(model, offset, bytes),
        Op::Truncate(size) => model.resize(usize::try_from(size).unwrap(), 0),
        Op::Sync | Op::Seal => {}
    }
}

/// Replaying a carried stage's whole history over its projected payload
/// reproduces its bytes: y re-bound at its base or checkpoint, z recreated
/// under its id from nothing, each with overlapping writes, sparse
/// extensions, shrinks and growths before and after the boundary. A dirty y
/// whose entry still names its old base must not refuse; a clean synced y
/// retires to its payload, and the selected x retires each time.
#[test]
fn a_projected_residual_replays_every_carried_file_to_its_reference_bytes() {
    use Op::{Seal, Sync, Truncate as T, Write as W};
    let cases: [(&str, &[Op]); 7] = [
        (
            "overlapping writes",
            &[
                W(10, &[b'a'; 20]),
                W(20, &[b'b'; 20]),
                Seal,
                W(35, b"ccccc"),
            ],
        ),
        ("sparse extension", &[W(150, b"dddd"), Seal, W(5, b"eee")]),
        ("shrink then grow", &[T(30), W(60, b"ffff"), Seal, T(90)]),
        (
            "checkpoint then shrink and grow",
            &[W(0, b"gggg"), Sync, T(40), W(50, b"hh"), Seal, W(0, b"i")],
        ),
        (
            "zero-sized checkpoint",
            &[T(0), Sync, W(3, b"jjjjjj"), Seal],
        ),
        (
            "checkpoint past the base end",
            &[
                W(90, &[b'k'; 12]),
                Sync,
                T(20),
                T(80),
                W(10, b"ll"),
                Seal,
                W(70, b"mmmmm"),
            ],
        ),
        ("clean after a checkpoint", &[W(0, b"nn"), Sync, Seal]),
    ];
    let mut outcomes = Vec::new();
    for (case, ops) in cases {
        let mut f = with_files(&[("y", &[b'y'; 100])]);
        let y = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
            .unwrap();
        let z = create_at(&mut f, at("z"), b"");
        let x = create_at(&mut f, at("x"), b"x captured");
        let (mut want_y, mut want_z) = (vec![b'y'; 100], Vec::new());
        let mut generation = 0;
        let mut boundary = None;
        for &op in ops {
            match op {
                Op::Write(offset, bytes) => {
                    for stage in [y, z] {
                        f.overlay
                            .write(&mut f.store, &f.owner, stage, offset, bytes)
                            .unwrap();
                    }
                }
                Op::Truncate(size) => {
                    for stage in [y, z] {
                        f.overlay
                            .truncate(&mut f.store, &f.owner, stage, size)
                            .unwrap();
                    }
                }
                Op::Sync => {
                    generation += 1;
                    f.sync(y, generation);
                }
                Op::Seal => {
                    generation += 1;
                    boundary = Some(publish(&mut f, Some(x), generation));
                }
            }
            apply(&mut want_y, op);
            apply(&mut want_z, op);
        }
        let before = (bytes_at(&mut f, "y"), bytes_at(&mut f, "z"));
        let installed = install(&mut f, boundary.unwrap()).map_err(|e| e.to_string());
        let staged =
            |f: &Fixture, path: &str| f.overlay.namespace.entries[&vec![name(path)]].stage_id;
        outcomes.push((
            case,
            installed.map(|retired| retired.contains(&x)),
            before == (want_y.clone(), want_z.clone()),
            bytes_at(&mut f, "y") == want_y,
            bytes_at(&mut f, "z") == want_z,
            bytes_at(&mut f, "x") == b"x captured",
            (staged(&f, "x"), staged(&f, "y"), staged(&f, "z")),
        ));
    }
    let expected: Vec<_> = cases
        .iter()
        .map(|(case, _)| {
            let y = (*case != "clean after a checkpoint").then_some(1);
            (*case, Ok(true), true, true, true, true, (None, y, Some(2)))
        })
        .collect();
    assert_eq!(outcomes, expected);
}

/// Each published sync of x with no handle and no later work retires its
/// stage, so its extents never accumulate; an unsynced y stays carried. With
/// a handle and a later write, x is re-bound at its captured payload and keeps
/// only the extents journaled after the boundary: the write and the fragment
/// of the earlier extent it overlapped.
#[test]
fn a_selected_file_retires_its_prefix_or_keeps_only_its_later_writes() {
    let mut f = with_files(&[("y", b"base")]);
    let y = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
        .unwrap();
    f.write(y, b"unsynced");
    let mut x = create_at(&mut f, at("x"), b"round zero");
    let mut want = b"round zero".to_vec();
    let mut outcomes = Vec::new();
    for round in 1..=3u8 {
        let generation = u64::from(round) * 10;
        let held = round == 3;
        if round > 1 {
            x = f
                .overlay
                .copy_up(&mut f.store, &f.owner, at("x"), &mut f.source)
                .unwrap();
        }
        let write = [b'0' + round; 3];
        f.overlay
            .write(&mut f.store, &f.owner, x, u64::from(round), &write)
            .unwrap();
        write_model(&mut want, u64::from(round), &write);
        if held {
            hold(&mut f, &[name("x")]);
        }
        let boundary = publish(&mut f, Some(x), generation);
        if held {
            f.overlay
                .write(&mut f.store, &f.owner, x, 0, b"late")
                .unwrap();
            write_model(&mut want, 0, b"late");
        }
        let retired = install(&mut f, boundary).unwrap();
        let records = journal_records(&f);
        let rebinds: Vec<_> = records
            .iter()
            .filter_map(|r| match r {
                Record::StageBind {
                    stage_id,
                    base_content,
                    staged_size,
                    cause: codec::BindCause::Rebind,
                    ..
                } if *stage_id == x => Some((*base_content, *staged_size)),
                _ => None,
            })
            .collect();
        let x_writes = records
            .iter()
            .filter(|r| matches!(r, Record::WriteExtent { stage_id, .. } if *stage_id == x))
            .count();
        outcomes.push((
            round,
            retired.contains(&x),
            rebinds,
            x_writes,
            f.overlay.namespace.stages.contains_key(&y),
            bytes_at(&mut f, "x") == want,
        ));
    }
    let captured = |bytes: &[u8]| vec![(GrainId::of(bytes), bytes.len() as u64)];
    let mut third = b"round zero".to_vec();
    for round in 1..=3u8 {
        write_model(&mut third, u64::from(round), &[b'0' + round; 3]);
    }
    assert_eq!(
        outcomes,
        [
            (1, true, vec![], 0, true, true),
            (2, true, vec![], 0, true, true),
            (3, false, captured(&third), 2, true, true),
        ]
    );
}

/// A stage as a replay leaves it: name, size and extent records. Its base is its
/// anchor, which a detached recreate may change from a mark or nothing.
fn stage_state(f: &Fixture, id: u64) -> Option<(Option<Vec<Name>>, u64, Vec<Record>)> {
    f.overlay.namespace.stages.get(&id).map(|s| {
        (
            s.path.clone(),
            s.size,
            s.extents.values().cloned().collect(),
        )
    })
}

/// Held unlinked files elsewhere survive a file or directory sync detached:
/// a never-synced one recreated from nothing, a copy-up from its base and a
/// synced one from its mark, each with its partial writes and size changes,
/// and none named in the projection or the image.
#[test]
fn held_unlinked_files_are_carried_detached_from_their_anchors() {
    let mut outcomes = Vec::new();
    for directory in [false, true] {
        let mut f = with_files(&[("b", &[b'b'; 50])]);
        let copied = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("b"), &mut f.source)
            .unwrap();
        f.overlay
            .write(&mut f.store, &f.owner, copied, 10, b"partial")
            .unwrap();
        hold(&mut f, &[name("b")]);
        unlink(&mut f, "b", copied);
        let tmp = create_at(&mut f, at("t"), b"tmp");
        hold(&mut f, &[name("t")]);
        unlink(&mut f, "t", tmp);
        let marked = create_at(&mut f, at("m"), b"mark");
        f.sync(marked, 1);
        f.overlay
            .write(&mut f.store, &f.owner, marked, 2, b"!")
            .unwrap();
        f.overlay
            .truncate(&mut f.store, &f.owner, marked, 10)
            .unwrap();
        hold(&mut f, &[name("m")]);
        unlink(&mut f, "m", marked);
        let x = create_at(&mut f, at("x"), b"x");
        let boundary = publish(&mut f, (!directory).then_some(x), 2);
        let before: Vec<_> = [copied, tmp, marked]
            .iter()
            .map(|id| stage_state(&f, *id))
            .collect();
        let projected: Vec<_> = f
            .overlay
            .projected_commit_entries(boundary, PUBLICATION)
            .unwrap()
            .iter()
            .map(|e| e.path.clone())
            .collect();
        let installed = install(&mut f, boundary).map_err(|e| e.to_string());
        let recreated: Vec<_> = journal_records(&f)
            .into_iter()
            .filter_map(|r| match r {
                Record::RecreateFile {
                    at: None,
                    stage_id,
                    anchor,
                    ..
                } => Some((stage_id, anchor.map(|a| (a.content, a.size)))),
                _ => None,
            })
            .collect();
        let after: Vec<_> = [copied, tmp, marked]
            .iter()
            .map(|id| stage_state(&f, *id))
            .collect();
        outcomes.push((directory, installed, projected, recreated, before == after));
    }
    let anchors = vec![
        (1, Some((GrainId::of(&[b'b'; 50]), 50))),
        (2, None),
        (3, Some((GrainId::of(b"mark"), 4))),
    ];
    let named = |directory: bool| {
        if directory {
            vec![]
        } else {
            vec![vec![name("x")]]
        }
    };
    assert_eq!(
        outcomes,
        [
            (false, Ok(vec![4]), named(false), anchors.clone(), true),
            (true, Ok(vec![]), named(true), anchors, true),
        ]
    );
}

/// Omitted namespace effects replay by identity: an unsynced temporary that
/// replaced a durable file and moved on, and an unsynced child of a directory
/// the projection moved, recreated under the directory's new name.
#[test]
fn omitted_namespace_effects_replay_by_identity() {
    let mut outcomes = Vec::new();
    for case in ["replace then move", "directory moved"] {
        let mut f = with_files(&[("f", b"durable")]);
        if case == "replace then move" {
            create_at(&mut f, at("t"), b"temporary");
            ns(
                &mut f,
                Record::Replace {
                    from: at("t"),
                    to: at("f"),
                },
            );
            ns(
                &mut f,
                Record::Move {
                    from: at("f"),
                    to: at("g"),
                },
            );
        } else {
            ns(
                &mut f,
                Record::Create {
                    at: at("d"),
                    kind: codec::CreateKind::Dir,
                },
            );
            create_at(&mut f, at_in("d", "u"), b"child");
            ns(
                &mut f,
                Record::Move {
                    from: at("d"),
                    to: at("e"),
                },
            );
        }
        let x = create_at(&mut f, at("x"), b"x");
        let boundary = publish(&mut f, Some(x), 1);
        let before = namespace_rows(&f);
        let projected: Vec<_> = f
            .overlay
            .projected_commit_entries(boundary, PUBLICATION)
            .unwrap()
            .iter()
            .map(|e| e.path.clone())
            .collect();
        let installed = install(&mut f, boundary).map_err(|e| e.to_string());
        let mut after = namespace_rows(&f);
        // x retires to its payload; every other row is carried unchanged.
        after.retain(|row| row.0 != vec![name("x")]);
        let mut expected = before.clone();
        expected.retain(|row| row.0 != vec![name("x")]);
        outcomes.push((case, installed, projected, after == expected));
    }
    let path = |names: &[&str]| names.iter().map(|n| name(n)).collect::<Vec<_>>();
    assert_eq!(
        outcomes,
        [
            (
                "replace then move",
                Ok(vec![2]),
                vec![path(&["f"]), path(&["x"])],
                true
            ),
            (
                "directory moved",
                Ok(vec![2]),
                vec![path(&["e"]), path(&["f"]), path(&["x"])],
                true
            ),
        ]
    );
}

/// An unsynced file a durable replacement displaced is dead when nothing
/// holds or names it: its omitted history drops and its stage retires, with
/// no name recreated over the occupied one. A handle, or a later record that
/// names it, carries it detached instead; the install's same-size truncate
/// of a held stage is the handle's later record.
#[test]
fn a_displaced_unsynced_file_retires_unless_held_or_named_later() {
    let mut outcomes = Vec::new();
    for case in ["dead", "held", "named later"] {
        let mut f = with_files(&[("s", b"durable source")]);
        let u = create_at(&mut f, at("g"), b"unsynced");
        if case == "held" {
            hold(&mut f, &[name("g")]);
        }
        ns(
            &mut f,
            Record::Replace {
                from: at("s"),
                to: at("g"),
            },
        );
        let x = create_at(&mut f, at("x"), b"x");
        let boundary = publish(&mut f, Some(x), 1);
        if case == "named later" {
            f.overlay
                .append(&Record::Truncate {
                    stage_id: u,
                    new_size: 8,
                })
                .unwrap();
        }
        let installed = install(&mut f, boundary).map_err(|e| e.to_string());
        let mentions = journal_records(&f)
            .iter()
            .filter(|r| reference_of(r) == Some(u))
            .count();
        outcomes.push((
            case,
            installed.map(|retired| retired.contains(&u)),
            stage_state(&f, u).map(|s| (s.0, s.1)),
            mentions,
            f.overlay.namespace.entries[&vec![name("g")]].kind.clone(),
        ));
    }
    let durable = OverlayKind::File {
        content: Some(GrainId::of(b"durable source")),
    };
    assert_eq!(
        outcomes,
        [
            ("dead", Ok(true), None, 0, durable.clone()),
            ("held", Ok(false), Some((None, 8)), 3, durable.clone()),
            ("named later", Ok(false), Some((None, 8)), 3, durable),
        ]
    );
}
fn reference_of(record: &Record) -> Option<u64> {
    match record {
        Record::RecreateFile { stage_id, .. }
        | Record::WriteExtent { stage_id, .. }
        | Record::Truncate { stage_id, .. }
        | Record::StageRollback { stage_id, .. } => Some(*stage_id),
        _ => None,
    }
}

/// Create unsynced u, replace durable f with it, move it to g, then replace g
/// with another durable file: the projection keeps f, and dropping dead u
/// cannot remove it, so the residual refuses before anything is sent and the
/// journal is untouched.
#[test]
fn an_unrepresentable_residual_refuses_before_publication() {
    let mut f = with_files(&[("f", b"durable"), ("s", b"source")]);
    create_at(&mut f, at("u"), b"unsynced");
    for record in [
        Record::Replace {
            from: at("u"),
            to: at("f"),
        },
        Record::Move {
            from: at("f"),
            to: at("g"),
        },
        Record::Replace {
            from: at("s"),
            to: at("g"),
        },
    ] {
        ns(&mut f, record);
    }
    let x = create_at(&mut f, at("x"), b"x");
    let boundary = publish(&mut f, Some(x), 1);
    let journal = f.io.bytes(&f.overlay.journal_path());
    let anchors = f
        .overlay
        .residual_snapshot(boundary, PUBLICATION)
        .and_then(|snapshot| snapshot.anchors())
        .map(|_| ())
        .map_err(|e| e.to_string());
    let image = f
        .overlay
        .residual_snapshot(boundary, PUBLICATION)
        .and_then(|snapshot| snapshot.residual())
        .map(|_| ())
        .map_err(|e| e.to_string());
    let refused = Err("overlay refused: projected residual unsupported".to_owned());
    assert_eq!(
        (
            anchors,
            image,
            f.io.bytes(&f.overlay.journal_path()) == journal
        ),
        (refused.clone(), refused, true)
    );
}

/// The anchors a rebased base must match: a carried dirty file's projected
/// entry, a recreated name and the directory it is recreated in, but not a
/// sibling or an unrelated path. A whole-tree boundary has no projection to
/// anchor.
#[test]
fn residual_anchors_name_carried_and_touched_paths_exactly() {
    let mut f = with_files(&[("y", b"A")]);
    let y = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
        .unwrap();
    f.write(y, b"B");
    ns(
        &mut f,
        Record::Create {
            at: at("d"),
            kind: codec::CreateKind::Dir,
        },
    );
    create_at(&mut f, at_in("d", "u"), b"child");
    ns(
        &mut f,
        Record::Move {
            from: at("d"),
            to: at("e"),
        },
    );
    let x = create_at(&mut f, at("x"), b"x");
    let boundary = publish(&mut f, Some(x), 1);
    let anchors = f
        .overlay
        .residual_snapshot(boundary, PUBLICATION)
        .and_then(|snapshot| snapshot.anchors())
        .unwrap();
    let projection: Vec<_> = f
        .overlay
        .projected_commit_entries(boundary, PUBLICATION)
        .unwrap()
        .into_iter()
        .map(|mut e| {
            e.stage_id = None;
            e
        })
        .collect();
    let child = |leaf: &str| OverlayEntry {
        path: vec![name("e"), name(leaf)],
        ..file(leaf, b"remote")
    };
    let mut outcomes = Vec::new();
    for case in [
        "projection",
        "unrelated",
        "carried changed",
        "recreated taken",
        "parent removed",
        "sibling added",
    ] {
        let mut merged = projection.clone();
        match case {
            "unrelated" => merged.push(file("z", b"remote")),
            "carried changed" => {
                for entry in &mut merged {
                    if entry.path == vec![name("y")] {
                        entry.kind = OverlayKind::File {
                            content: Some(GrainId::of(b"C")),
                        };
                    }
                }
            }
            "recreated taken" => merged.push(child("u")),
            "parent removed" => merged.retain(|e| e.path != vec![name("e")]),
            "sibling added" => merged.push(child("v")),
            _ => {}
        }
        outcomes.push((case, anchors.mismatch(&projection, &merged)));
    }
    let whole_tree = {
        let capture = f.overlay.capture_boundary(&mut f.store, &f.owner);
        capture.and_then(|capture| {
            let index =
                f.overlay
                    .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])?;
            f.overlay
                .residual_snapshot(index, [7; 16])?
                .anchors()
                .map(|_| ())
        })
    };
    assert_eq!(
        (outcomes, whole_tree.map_err(|e| e.to_string())),
        (
            vec![
                ("projection", None),
                ("unrelated", None),
                ("carried changed", Some(vec![name("y")])),
                ("recreated taken", Some(vec![name("e"), name("u")])),
                ("parent removed", Some(vec![name("e")])),
                ("sibling added", None),
            ],
            Err("overlay refused: projected prefix binding".to_owned())
        )
    );
}

/// Saving a never-synced file twice through temporaries moves the first
/// temporary to f, then replaces it with the second. Both are omitted; the
/// first is dead, so the second's replace lands on no occupant and replays as
/// a move, leaving the second temporary's stage named f.
#[test]
fn a_replace_over_a_dead_omitted_file_replays_as_a_move() {
    let mut f = with_files(&[("b", b"base")]);
    let first = create_at(&mut f, at("t1"), b"first");
    ns(
        &mut f,
        Record::Move {
            from: at("t1"),
            to: at("f"),
        },
    );
    let second = create_at(&mut f, at("t2"), b"second");
    ns(
        &mut f,
        Record::Replace {
            from: at("t2"),
            to: at("f"),
        },
    );
    let x = create_at(&mut f, at("x"), b"x");
    let boundary = publish(&mut f, Some(x), 1);
    let installed = install(&mut f, boundary).map_err(|e| e.to_string());
    assert_eq!(
        (
            installed,
            stage_state(&f, first).is_some(),
            stage_state(&f, second).map(|s| (s.0, s.1)),
            bytes_at(&mut f, "f"),
        ),
        (
            Ok(vec![first, x]),
            false,
            Some((Some(vec![name("f")]), 6)),
            b"second".to_vec()
        )
    );
}

/// y is written before the boundary and synced after it, with nothing
/// later. Its live checkpoint is not the projection's payload for it, so it
/// is carried with its write rather than retired to the projection's older
/// bytes.
#[test]
fn a_stage_synced_after_the_boundary_is_carried_not_retired() {
    let mut f = with_files(&[("y", b"AAAA")]);
    let y = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
        .unwrap();
    f.write(y, b"BBBB");
    let x = create_at(&mut f, at("x"), b"x");
    let boundary = publish(&mut f, Some(x), 1);
    f.sync(y, 5);
    let retired = install(&mut f, boundary).map_err(|e| e.to_string());
    assert_eq!(
        (retired, stage_state(&f, y).is_some(), bytes_at(&mut f, "y")),
        (Ok(vec![x]), true, b"BBBB".to_vec())
    );
}

fn residual_inventory_source(
    f: &mut Fixture,
    proof: LandedProof,
    publication: [u8; 16],
) -> crate::recovery::ResidualSource {
    let bytes = f.io.bytes(&f.overlay.journal_path());
    let scan = codec::scan_journal(&bytes).unwrap();
    let payloads = proof
        .captured_entries
        .iter()
        .filter_map(|entry| match entry.kind {
            OverlayKind::File {
                content: Some(content),
            } => f.source.0.get(&content).map(|bytes| {
                let grains = if bytes.is_empty() {
                    granary_core::manifest::FileGrains::Inline(Vec::new())
                } else {
                    granary_core::manifest::FileGrains::Inline(vec![
                        granary_core::manifest::GrainRef {
                            id: GrainId::of(bytes),
                            unpacked_len: u32::try_from(bytes.len()).unwrap(),
                        },
                    ])
                };
                (
                    content,
                    crate::recovery::CapturedPayload {
                        size: entry.size,
                        grains,
                    },
                )
            }),
            _ => None,
        })
        .collect();
    crate::recovery::ResidualSource {
        header: scan.header,
        journal: bytes,
        boundary_seq: proof.boundary_seq,
        publication_id: publication,
        source_end: scan.state.next_seq() - 1,
        base: Vec::new(),
        proof,
        base_entries: f.overlay.base.clone(),
        captured: crate::recovery::CapturedContent {
            payloads,
            nodes: BTreeMap::new(),
        },
        budget: crate::sync::Budget::new(&(), 16_777_216, None),
    }
}

fn inventory_from_source(
    f: &mut Fixture,
    source: &crate::recovery::ResidualSource,
) -> Result<super::super::ResidualInventory, String> {
    super::super::inventory(
        &mut f.io,
        &f.overlay.area,
        &f.overlay.config,
        source,
        || Ok(()),
    )
    .map_err(|error| error.to_string())
}

fn reconciled_restart_fixture(
    post_capture_restore: bool,
    restart: bool,
) -> (Fixture, LandedProof, u64, super::super::ResidualInventory) {
    let mut f = with_files(&[("y", b"AAAA")]);
    let y = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
        .unwrap();
    f.write(y, b"BBBB");
    f.sync(y, 1);
    let x = create_at(&mut f, at("x"), b"x");
    let boundary = publish(&mut f, Some(x), 2);
    if post_capture_restore {
        f.write(y, b"XXXX");
        f.write(y, b"BBBB");
    }
    let captured: Vec<_> = f
        .overlay
        .projected_commit_entries(boundary, PUBLICATION)
        .unwrap()
        .into_iter()
        .map(|mut entry| {
            entry.stage_id = None;
            entry
        })
        .collect();
    let mut landed = captured.clone();
    let remote = GrainId::of(b"CCCC");
    f.source.0.insert(remote, b"CCCC".to_vec());
    landed
        .iter_mut()
        .find(|entry| entry.path == vec![name("y")])
        .unwrap()
        .kind = OverlayKind::File {
        content: Some(remote),
    };
    let proof = f.landing(LandedProof {
        boundary_seq: boundary,
        landed_root: grain(4),
        landed_seq: 2,
        captured_entries: captured,
        entries: landed,
    });
    let source = residual_inventory_source(&mut f, proof.clone(), PUBLICATION);
    let inventory = inventory_from_source(&mut f, &source).unwrap();
    if restart {
        f.reopen().unwrap();
    }
    (f, proof, y, inventory)
}

fn commit_reconciliation_source(
    restore: bool,
) -> (Fixture, LandedProof, u64, crate::recovery::ResidualSource) {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"local");
    let mut proof = f.boundary_proof();
    if restore {
        f.write(id, b"later");
        f.write(id, b"local");
    } else {
        f.write(id, b"longer");
    }
    let remote = GrainId::of(b"remote");
    f.source.0.insert(remote, b"remote".to_vec());
    proof.entries.first_mut().unwrap().kind = OverlayKind::File {
        content: Some(remote),
    };
    proof.entries.first_mut().unwrap().size = 6;
    let proof = f.landing(proof);
    let source = residual_inventory_source(&mut f, proof.clone(), [7; 16]);
    (f, proof, id, source)
}

fn commit_reconciliation_fixture(
    restore: bool,
    restart: bool,
) -> (Fixture, LandedProof, u64, super::super::ResidualInventory) {
    let (mut f, proof, id, source) = commit_reconciliation_source(restore);
    let inventory = inventory_from_source(&mut f, &source).unwrap();
    if restart {
        f.reopen().unwrap();
    }
    (f, proof, id, inventory)
}

fn never_written_copy_up_fixture(
    mode: &str,
    before_capture: bool,
) -> (Fixture, LandedProof, u64, super::super::ResidualInventory) {
    let mut f = with_files(&[("y", b"local")]);
    let mut stage = before_capture.then(|| {
        f.overlay
            .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
            .unwrap()
    });
    let (mut proof, publication) = if mode == "projected" {
        let x = create_at(&mut f, at("x"), b"x");
        let boundary = publish(&mut f, Some(x), 1);
        let captured = f
            .overlay
            .projected_commit_entries(boundary, PUBLICATION)
            .unwrap()
            .into_iter()
            .map(|mut entry| {
                entry.stage_id = None;
                entry
            })
            .collect();
        (
            LandedProof {
                boundary_seq: boundary,
                landed_root: grain(4),
                landed_seq: 2,
                captured_entries: captured,
                entries: Vec::new(),
            },
            PUBLICATION,
        )
    } else {
        (f.boundary_proof(), [7; 16])
    };
    let stage = stage.take().unwrap_or_else(|| {
        f.overlay
            .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
            .unwrap()
    });
    proof.entries = proof.captured_entries.clone();
    let remote = GrainId::of(b"remote");
    f.source.0.insert(remote, b"remote".to_vec());
    if let Some(entry) = proof
        .entries
        .iter_mut()
        .find(|entry| entry.path == vec![name("y")])
    {
        entry.kind = OverlayKind::File {
            content: Some(remote),
        };
        entry.size = 6;
    } else {
        let mut entry = f
            .overlay
            .base
            .iter()
            .find(|entry| entry.path == vec![name("y")])
            .unwrap()
            .clone();
        entry.kind = OverlayKind::File {
            content: Some(remote),
        };
        entry.size = 6;
        proof.entries.push(entry);
    }
    let proof = f.landing(proof);
    let source = residual_inventory_source(&mut f, proof.clone(), publication);
    let inventory = inventory_from_source(&mut f, &source).unwrap();
    f.reopen().unwrap();
    (f, proof, stage, inventory)
}

#[test]
fn captured_equality_plan_retires_a_stage_after_restart_and_keeps_landed_bytes() {
    let (mut f, proof, y, inventory) = reconciled_restart_fixture(false, true);
    let plan = f
        .overlay
        .prepare_residual_replacement(&mut f.store, &f.owner, proof, &inventory)
        .unwrap();
    f.overlay
        .install_replacement(&mut f.store, &f.owner, plan)
        .unwrap();
    f.reopen().unwrap();
    assert_eq!(
        (
            stage_state(&f, y),
            f.overlay.namespace.entries[&vec![name("y")]].stage_id,
            bytes_at(&mut f, "y")
        ),
        (None, None, b"CCCC".to_vec())
    );
}

#[test]
fn inventory_plan_installs_post_capture_restore_in_both_modes() {
    let mut rows = Vec::new();
    for (mode, path, fixture) in [
        ("projected", "y", reconciled_restart_fixture(true, true)),
        ("commit", "f", commit_reconciliation_fixture(true, true)),
    ] {
        let (mut f, proof, stage, inventory) = fixture;
        let classified = (
            inventory.collisions.len(),
            inventory.reconciliation.contains(stage),
        );
        let result = f
            .overlay
            .replace_residual_landed(&mut f.store, &f.owner, proof, &inventory, &mut f.source)
            .map(|_| ())
            .map_err(|error| error.to_string());
        let (retired, bytes) = if result.is_ok() {
            f.reopen().unwrap();
            (
                stage_state(&f, stage).is_none(),
                Some(bytes_at(&mut f, path)),
            )
        } else {
            (false, None)
        };
        rows.push((mode, classified, result, retired, bytes));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("projected", (0, true), Ok(()), true, Some(b"CCCC".to_vec())),
                ("commit", (0, true), Ok(()), true, Some(b"remote".to_vec()))
            ],
            2
        )
    );
}

#[test]
fn never_written_copy_up_inventory_and_installation_agree_in_both_modes() {
    let mut rows = Vec::new();
    for before_capture in [false, true] {
        for mode in ["projected", "commit"] {
            let (mut f, proof, stage, inventory) =
                never_written_copy_up_fixture(mode, before_capture);
            let classified = (
                inventory.collisions.len(),
                inventory.reconciliation.contains(stage),
            );
            let result = f
                .overlay
                .replace_residual_landed(&mut f.store, &f.owner, proof, &inventory, &mut f.source)
                .map(|_| ())
                .map_err(|error| error.to_string());
            let (retired, bytes) = if result.is_ok() {
                f.reopen().unwrap();
                (
                    stage_state(&f, stage).is_none(),
                    Some(bytes_at(&mut f, "y")),
                )
            } else {
                (false, None)
            };
            rows.push((before_capture, mode, classified, result, retired, bytes));
        }
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    false,
                    "projected",
                    (1, false),
                    Err("overlay namespace conflict".into()),
                    false,
                    None
                ),
                (
                    false,
                    "commit",
                    (1, false),
                    Err("overlay namespace conflict".into()),
                    false,
                    None
                ),
                (
                    true,
                    "projected",
                    (0, true),
                    Ok(()),
                    true,
                    Some(b"remote".to_vec())
                ),
                (
                    true,
                    "commit",
                    (0, false),
                    Ok(()),
                    true,
                    Some(b"remote".to_vec())
                ),
            ],
            4
        )
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the four rows share one crafted stage and boundary setup"
)]
fn first_post_capture_rebind_inventory_and_installation_agree_in_both_modes() {
    let mut rows = Vec::new();
    for restore in [false, true] {
        for mode in ["projected", "commit"] {
            let mut f = with_files(&[("y", b"base y")]);
            let mut issued = header();
            issued.next_stage_id = 2;
            f.io.write_at(
                &f.overlay.journal_path(),
                0,
                &codec::encode_journal(&issued, &[]).unwrap(),
            )
            .unwrap();
            f.reopen().unwrap();
            let (mut proof, publication) = if mode == "projected" {
                let x = create_at(&mut f, at("x"), b"x");
                let boundary = publish(&mut f, Some(x), 1);
                let captured = f
                    .overlay
                    .projected_commit_entries(boundary, PUBLICATION)
                    .unwrap()
                    .into_iter()
                    .map(|mut entry| {
                        entry.stage_id = None;
                        entry
                    })
                    .collect();
                (
                    LandedProof {
                        boundary_seq: boundary,
                        landed_root: grain(4),
                        landed_seq: 2,
                        captured_entries: captured,
                        entries: Vec::new(),
                    },
                    PUBLICATION,
                )
            } else {
                (f.boundary_proof(), [7; 16])
            };
            let stage_path = f.overlay.stage_path(1);
            f.io.create(&stage_path).unwrap();
            f.io.write_at(
                &stage_path,
                0,
                &StagingHeader {
                    writer: issued.writer,
                    stage_id: 1,
                    mark: MarkState::Absent,
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
            f.io.write_at(&stage_path, 160, b"base y").unwrap();
            f.overlay
                .append(&Record::StageBind {
                    at: at("y"),
                    cause: codec::BindCause::Rebind,
                    stage_id: 1,
                    staged_size: 6,
                    base_content: GrainId::of(b"base y"),
                })
                .unwrap();
            if restore {
                f.write(1, b"later!");
                f.write(1, b"base y");
            }
            proof.entries = proof.captured_entries.clone();
            let remote = GrainId::of(b"remote");
            f.source.0.insert(remote, b"remote".to_vec());
            let entry = proof
                .entries
                .iter_mut()
                .find(|entry| entry.path == vec![name("y")])
                .unwrap();
            entry.kind = OverlayKind::File {
                content: Some(remote),
            };
            let proof = f.landing(proof);
            let source = residual_inventory_source(&mut f, proof.clone(), publication);
            let inventory = inventory_from_source(&mut f, &source).unwrap();
            let classified = (
                inventory.collisions.len(),
                inventory.reconciliation.contains(1),
            );
            f.reopen().unwrap();
            let result = f
                .overlay
                .replace_residual_landed(&mut f.store, &f.owner, proof, &inventory, &mut f.source)
                .map(|_| ())
                .map_err(|error| error.to_string());
            rows.push((restore, mode, classified, result));
        }
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    false,
                    "projected",
                    (1, false),
                    Err("overlay namespace conflict".into())
                ),
                (
                    false,
                    "commit",
                    (1, false),
                    Err("overlay namespace conflict".into())
                ),
                (
                    true,
                    "projected",
                    (1, false),
                    Err("overlay namespace conflict".into())
                ),
                (
                    true,
                    "commit",
                    (1, false),
                    Err("overlay namespace conflict".into())
                )
            ],
            4
        )
    );
}

#[test]
fn detached_rebind_is_refused_by_the_journal_codec() {
    let mut state = codec::JournalState::new(&header());
    state
        .admit(&Record::StageBind {
            at: at("y"),
            cause: codec::BindCause::CopyUp,
            stage_id: 1,
            staged_size: 6,
            base_content: GrainId::of(b"base y"),
        })
        .unwrap();
    state
        .admit(&Record::Delete {
            at: at("y"),
            kind: codec::DeleteKind::File { stage_id: Some(1) },
        })
        .unwrap();
    assert_eq!(
        state.admit(&Record::StageBind {
            at: at("y"),
            cause: codec::BindCause::Rebind,
            stage_id: 1,
            staged_size: 6,
            base_content: GrainId::of(b"base y"),
        }),
        Err(codec::ValueError::StageAlreadyBound { stage_id: 1 })
    );
}

#[test]
fn reconciled_held_stage_is_not_retired_in_either_mode() {
    let mut rows = Vec::new();
    for (mode, path, fixture) in [
        ("projected", "y", reconciled_restart_fixture(false, false)),
        ("commit", "f", commit_reconciliation_fixture(true, false)),
    ] {
        let (mut f, proof, stage, inventory) = fixture;
        hold(&mut f, &[name(path)]);
        let result = f
            .overlay
            .replace_residual_landed(&mut f.store, &f.owner, proof, &inventory, &mut f.source)
            .map(|_| ())
            .map_err(|error| error.to_string());
        rows.push((mode, result, stage_state(&f, stage).is_some()));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("projected", Err("overlay namespace conflict".into()), true),
                ("commit", Err("overlay namespace conflict".into()), true)
            ],
            2
        )
    );
}

#[test]
fn unequal_size_with_captured_payload_remains_a_collision() {
    let (mut f, _, stage, source) = commit_reconciliation_source(false);
    let result = inventory_from_source(&mut f, &source).map(|inventory| {
        (
            inventory.collisions.len(),
            inventory.reconciliation.contains(stage),
        )
    });
    assert_eq!(result, Ok((1, false)));
}

#[test]
fn equal_size_missing_capture_evidence_refuses_instead_of_becoming_a_collision() {
    let mut rows = Vec::new();
    for case in ["missing-content", "missing-payload"] {
        let (mut f, _, _, mut source) = commit_reconciliation_source(true);
        match case {
            "missing-content" => {
                source.proof.captured_entries.first_mut().unwrap().kind =
                    OverlayKind::File { content: None };
            }
            "missing-payload" => source.captured.payloads.clear(),
            _ => unreachable!(),
        }
        rows.push((case, inventory_from_source(&mut f, &source).map(|_| ())));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    "missing-content",
                    Err("intent refused: RecoveryResidualUnrepresentable".into())
                ),
                (
                    "missing-payload",
                    Err("intent refused: RecoveryResidualCaptureUnknown".into())
                )
            ],
            2
        )
    );
}

#[test]
fn reconciliation_plan_refuses_changed_stage_before_installation_writes() {
    let mut rows = Vec::new();
    for case in ["header", "payload"] {
        let (mut f, proof, y, inventory) = reconciled_restart_fixture(false, true);
        let plan = f
            .overlay
            .prepare_residual_replacement(&mut f.store, &f.owner, proof, &inventory)
            .unwrap();
        let stage = f.overlay.stage_path(y);
        f.io.mutate(&stage, |bytes| match case {
            "header" => {
                let mut header = StagingHeader::decode(bytes.get(..160).unwrap()).unwrap();
                header.writer[0] ^= 1;
                bytes
                    .get_mut(..160)
                    .unwrap()
                    .copy_from_slice(&header.encode().unwrap());
            }
            "payload" => *bytes.get_mut(161).unwrap() ^= 1,
            _ => unreachable!(),
        });
        let before = f.journal_and_stages();
        let start = f.io.0.lock().unwrap().trace.len();
        let result = f
            .overlay
            .install_replacement(&mut f.store, &f.owner, plan)
            .map_err(|error| error.to_string());
        let writes = f.io.0.lock().unwrap().trace[start..]
            .iter()
            .any(|(operation, _)| {
                matches!(
                    operation.as_str(),
                    "write" | "resize" | "sync" | "rename" | "create"
                )
            });
        rows.push((case, result, f.journal_and_stages() == before, writes));
    }
    let refused = Err("overlay refused: residual reconciliation changed".into());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("header", refused.clone(), true, false),
                ("payload", refused, true, false)
            ],
            2
        ),
    );
}

/// A landing installs a projected boundary's residual only for that lane's
/// own landing and matching refresh, with no other lane's boundary and every
/// registration after the boundary one that refresh absorbs; the landed
/// entries must equal the projection at the residual's anchors and keep a
/// retired file's name an immutable file. Each missing, extra or changed
/// record refuses alone and leaves the journal as it was.
#[test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
fn a_projected_landing_installs_only_its_own_landing_refresh_and_anchors() {
    let mut outcomes = Vec::new();
    for case in [
        "landed",
        "no landing",
        "no refresh",
        "later registration",
        "another boundary",
        "carried path changed",
        "retired name gone",
    ] {
        let mut f = with_files(&[("y", b"A")]);
        let y = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
            .unwrap();
        f.write(y, b"B");
        let x = create_at(&mut f, at("x"), b"x");
        let boundary = publish(&mut f, Some(x), 1);
        let mut entries: Vec<_> = f
            .overlay
            .projected_commit_entries(boundary, PUBLICATION)
            .unwrap()
            .into_iter()
            .map(|mut e| {
                e.stage_id = None;
                e
            })
            .collect();
        match case {
            "carried path changed" => {
                for entry in &mut entries {
                    if entry.path == vec![name("y")] {
                        entry.kind = OverlayKind::File {
                            content: Some(GrainId::of(b"C")),
                        };
                    }
                }
            }
            "retired name gone" => entries.retain(|e| e.path != vec![name("x")]),
            _ => {}
        }
        let proof = LandedProof {
            boundary_seq: boundary,
            landed_root: grain(2),
            landed_seq: 2,
            captured_entries: entries.clone(),
            entries,
        };
        if case != "no landing" {
            f.overlay
                .record_landed(&mut f.store, &f.owner, &proof)
                .unwrap();
        }
        if case != "no refresh" {
            f.overlay
                .record_intent_registered(
                    &mut f.store,
                    &f.owner,
                    2,
                    proof.landed_root,
                    codec::IntentCause::LandedRefresh,
                )
                .unwrap();
        }
        if case == "later registration" {
            f.overlay
                .record_intent_registered(
                    &mut f.store,
                    &f.owner,
                    3,
                    grain(5),
                    codec::IntentCause::DirectorySync,
                )
                .unwrap();
        }
        if case == "another boundary" {
            let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
            f.overlay
                .append(&Record::CommitBoundary {
                    candidate: grain(6),
                    through_seq,
                    publication_id: [6; 16],
                })
                .unwrap();
        }
        let before = f.io.bytes(&f.overlay.journal_path());
        let result = f
            .overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .map(|_| {
                f.overlay
                    .namespace
                    .stages
                    .keys()
                    .copied()
                    .collect::<Vec<_>>()
            })
            .map_err(|e| e.to_string());
        let kept = f.io.bytes(&f.overlay.journal_path()) == before;
        outcomes.push((case, result, kept));
    }
    let refused = |reason: &str| (Err(format!("overlay refused: {reason}")), true);
    let conflict = (Err("overlay namespace conflict".to_owned()), true);
    let rows: Vec<_> = outcomes.into_iter().map(|(c, r, k)| (c, (r, k))).collect();
    assert_eq!(
        rows,
        [
            ("landed", (Ok(vec![1]), false)),
            ("no landing", refused("durable landing/refresh required")),
            ("no refresh", refused("durable landing/refresh required")),
            (
                "later registration",
                refused("replacement unexpected control")
            ),
            (
                "another boundary",
                refused("replacement unexpected control")
            ),
            ("carried path changed", conflict.clone()),
            ("retired name gone", conflict),
        ]
    );
}

/// The dirty spans of a projected landing: the residual keeps every span its
/// retained work came from, before or after the boundary, with that span's
/// age, regrouped over the replacement, so the coalescer still owes y's
/// unsynced write its original age. A landing whose residual has no dirty
/// work leaves nothing to commit: the selected file retired, so the image is
/// empty, or held open, so it carries only as a re-bind and the install's
/// same-size truncate. Each dirty image is still dirty after a reopen.
#[test]
fn a_projected_landing_keeps_the_ages_of_its_residual_work() {
    use std::sync::{Arc, Mutex};
    // Any origin will do: the row's clock only ever reads ticks after it.
    let start = crate::SyncRuntime::now(&crate::TokioSyncRuntime);
    let at_tick = |tick: u64| start + std::time::Duration::from_secs(tick);
    let mut outcomes = Vec::new();
    for case in [
        "unsynced before",
        "before and after",
        "selected only",
        "selected held",
    ] {
        let mut f = with_files(&[("y", b"base")]);
        let now = Arc::new(Mutex::new(at_tick(0)));
        let clock = now.clone();
        f.overlay.install_coalescer(
            Some(crate::overlay_store::CoalesceClock(Arc::new(move || {
                *clock.lock().unwrap()
            }))),
            Arc::new(tokio::sync::Notify::new()),
        );
        let split = |f: &mut Fixture, tick: u64| {
            f.overlay.dirty_split_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
            *now.lock().unwrap() = at_tick(tick);
        };
        let x = create_at(&mut f, at("x"), b"x");
        if case == "selected held" {
            hold(&mut f, &[name("x")]);
        } else if case != "selected only" {
            split(&mut f, 1);
            let y = f
                .overlay
                .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
                .unwrap();
            f.write(y, b"unsynced");
        }
        let boundary = publish(&mut f, Some(x), 1);
        if case == "before and after" {
            split(&mut f, 2);
            create_at(&mut f, at("z"), b"later");
        }
        let spans = f.overlay.dirty_spans.len();
        let proof = land(&mut f, boundary);
        f.overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .unwrap();
        let installed = f
            .overlay
            .active_dirty_span(at_tick(9))
            .map(|(first, last, _)| (first, last));
        let records = f.overlay.summary.records;
        f.reopen().unwrap();
        let reopened = f.overlay.active_dirty_span(at_tick(9)).is_some();
        outcomes.push((case, spans, records > 0, installed, reopened));
    }
    assert_eq!(
        outcomes,
        [
            (
                "unsynced before",
                2,
                true,
                Some((at_tick(1), at_tick(1))),
                true
            ),
            (
                "before and after",
                3,
                true,
                Some((at_tick(1), at_tick(2))),
                true
            ),
            ("selected only", 1, false, None, false),
            ("selected held", 1, true, None, false),
        ]
    );
}

/// A projected landing's replacement takes the source's highest generation
/// as its header receipt, not the prefix's: the call's own file sync after
/// the boundary and the landed refresh both sit above every prefix
/// generation. After the install and a reopen, a registration above that
/// receipt is admitted and an equal or older one refuses. A directory call
/// records no file sync, so its refresh alone is the highest.
#[test]
fn projected_absorbed_receipt_generation() {
    let mut outcomes = Vec::new();
    for case in ["file", "directory"] {
        let mut f = with_files(&[("w", b"W")]);
        let w = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("w"), &mut f.source)
            .unwrap();
        f.write(w, b"synced before");
        f.sync(w, 2);
        let x = create_at(&mut f, at("x"), b"x");
        let boundary = publish(&mut f, (case == "file").then_some(x), 5);
        let refresh = {
            let journal = f.overlay.journal.lock().unwrap();
            journal.state.highest_generation() + 1
        };
        let installed = install(&mut f, boundary)
            .map(drop)
            .map_err(|e| e.to_string());
        let receipt = codec::scan_journal(&f.io.bytes(&f.overlay.journal_path()))
            .unwrap()
            .header
            .receipt_generation;
        let mut register = |generation: u64| {
            f.overlay
                .record_intent_registered(
                    &mut f.store,
                    &f.owner,
                    generation,
                    grain(8),
                    codec::IntentCause::DirectorySync,
                )
                .map(drop)
                .map_err(|e| e.to_string())
        };
        let (stale, equal, above) = (
            register(receipt.saturating_sub(1)),
            register(receipt),
            register(receipt + 1),
        );
        outcomes.push((case, refresh, installed, receipt, stale, equal, above));
    }
    let refused = Err("overlay refused: journal value rule".to_owned());
    assert_eq!(
        outcomes,
        [
            (
                "file",
                6,
                Ok(()),
                6,
                refused.clone(),
                refused.clone(),
                Ok(())
            ),
            ("directory", 3, Ok(()), 3, refused.clone(), refused, Ok(())),
        ],
        "(case, the refresh's generation, install, the reopened header receipt, a stale, an \
         equal and a later registration)"
    );
}

/// The greatest length the journal can reach and still have both images
/// within the journal bound, whatever the cap.
fn journal_limit(f: &mut Fixture) -> u64 {
    let stages = f.overlay.namespace.stages.len();
    let cap = std::mem::replace(&mut f.overlay.config.cap, u64::MAX);
    let (mut fits, mut refused) = (0, codec::JOURNAL_MAX as u64);
    while refused - fits > 1 {
        let middle = fits + (refused - fits) / 2;
        if f.overlay.capacity(0, middle, stages).is_ok() {
            fits = middle;
        } else {
            refused = middle;
        }
    }
    f.overlay.config.cap = cap;
    f.overlay.update_summary().unwrap();
    fits
}

/// The deepest legal directory path, of 16 names of 255 bytes, in the base,
/// and an unsynced `d/u` whose six exec changes all name `d` before `d`
/// moves under that path; `x` is the file a projected sync selects.
fn omitted_under_a_long_move() -> (Fixture, Vec<Name>, u64, u64) {
    let long: Vec<Name> = (0..16)
        .map(|i| Name::new(vec![b'a' + i; 255]).unwrap())
        .collect();
    let dir = |path: Vec<Name>| OverlayEntry {
        path,
        inode: 0,
        kind: OverlayKind::Directory,
        stage_id: None,
        size: 0,
        exec: false,
    };
    let mut base: Vec<_> = (1..=long.len())
        .map(|depth| dir(long[..depth].to_vec()))
        .collect();
    base.push(dir(vec![name("d")]));
    let mut f = Fixture::with_base(base, Source::default());
    let u = create_at(&mut f, at_in("d", "u"), b"unsynced");
    for exec in [true, false, true, false, true, false] {
        ns(
            &mut f,
            Record::SetattrExec {
                at: at_in("d", "u"),
                exec,
            },
        );
    }
    let x = create_at(&mut f, at("x"), b"x");
    ns(
        &mut f,
        Record::Move {
            from: at("d"),
            to: codec::Location {
                parent: codec::Parent::new(long.clone()).unwrap(),
                name: name("d"),
            },
        },
    );
    (f, long, u, x)
}

/// The free entries the journal bound leaves, whatever the cap.
fn journal_free_entries(f: &mut Fixture) -> u64 {
    let cap = std::mem::replace(&mut f.overlay.config.cap, u64::MAX);
    f.overlay.update_summary().unwrap();
    let free = f.overlay.free_entry_capacity().unwrap();
    f.overlay.config.cap = cap;
    f.overlay.update_summary().unwrap();
    free
}

/// A projected seal reserves what its residual replacement can add: an
/// omitted file's records replay under the long path its directory moved
/// to, and later work grows the tail. Work admitted at the smallest cap
/// still installs there, live or after a restart, and the journal bound
/// moves by the same reserve.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture admits the reserve, the cap and the journal bound, then installs at that cap"
)]
fn projected_reserve_covers_path_growth_and_tail() {
    let mut outcomes = Vec::new();
    for restart in [false, true] {
        let (mut f, long, u, x) = omitted_under_a_long_move();
        let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
        let unreserved = journal_limit(&mut f);
        let free = journal_free_entries(&mut f);
        f.overlay.reserve_projected().unwrap();
        let reserved = journal_limit(&mut f);
        // The free-entry estimate a statfs reports shrinks by the same reserve.
        assert!(
            journal_free_entries(&mut f) < free,
            "the projected reserve must shrink the free entries reported"
        );
        // u's and x's creates and six exec changes, one location each, and
        // the move's two; a recreate's two bytes over a rebind per stage.
        let growth = 10 * 4226 + 2 * 2;
        assert_eq!(
            (unreserved - reserved, f.overlay.projected_seal),
            (growth, Some(through_seq)),
            "the projected reserve moves the journal bound by its replacement growth"
        );
        let bytes = f.sync(x, 1).chunks.concat();
        let boundary = f
            .overlay
            .append(&Record::ProjectedBoundary {
                candidate: grain(9),
                through_seq,
                publication_id: PUBLICATION,
                selection: Some(ProjectedSelection {
                    stage_id: x,
                    content: GrainId::of(&bytes),
                    size: bytes.len() as u64,
                }),
            })
            .unwrap();
        // Later work grows the tail.
        f.overlay
            .write(&mut f.store, &f.owner, u, 8, b" and later")
            .unwrap();
        // The smallest cap that admits this work.
        let stages = f.overlay.namespace.stages.len();
        let length = f.overlay.journal.lock().unwrap().length;
        f.overlay.config.cap = u64::MAX;
        f.overlay.capacity(0, length, stages).unwrap();
        let summary = f.overlay.summary;
        f.overlay.config.cap =
            summary.charged_bytes + summary.reserved_bytes + summary.captured_bytes;
        let at_cap = (
            f.overlay.capacity(0, length, stages).is_ok(),
            matches!(
                f.overlay.write(&mut f.store, &f.owner, u, 18, b"!"),
                Err(OverlayError::NoSpace)
            ),
        );
        // A restart keeps the reserve while the boundary is retained.
        if restart {
            f.reopen().unwrap();
        }
        let held = (f.overlay.projected_seal, journal_limit(&mut f) == reserved);
        let proof = land(&mut f, boundary);
        let installed = f
            .overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .map(|_| {
                (
                    f.overlay
                        .namespace
                        .stages
                        .keys()
                        .copied()
                        .collect::<Vec<_>>(),
                    f.overlay.projected_seal,
                )
            })
            .map_err(|e| e.to_string());
        outcomes.push((restart, at_cap, held, installed.clone()));
        if installed.is_err() {
            continue;
        }
        // Reopen at the cap that admitted this work. The landed journal is
        // larger than the one it replaced, so its own reserve is above that
        // cap: the overlay opens degraded, serving reads, refusing writes and
        // asking for a commit.
        f.reopen().unwrap();
        let mut deep = long.clone();
        deep.extend([name("d"), name("u")]);
        let observed = f
            .overlay
            .observation(&f.store, &f.owner)
            .map(|o| (o.free_entries, o.summary.commit_requested))
            .map_err(|e| e.to_string());
        let write = f.overlay.write(&mut f.store, &f.owner, u, 0, b"!");
        let carried = f
            .overlay
            .read_stage(&mut f.store, &f.owner, u, 0, 64)
            .map_err(|e| e.to_string());
        assert_eq!(
            (
                f.overlay.readiness == OverlayReadiness::Ready,
                f.overlay.namespace.entries.get(&deep).map(|e| e.exec),
                carried,
                matches!(write, Err(OverlayError::NoSpace)),
                observed,
            ),
            (
                true,
                Some(false),
                Ok(b"unsynced and later".to_vec()),
                true,
                Ok((0, true)),
            ),
            "restart {restart}: at the admitted cap the residual reopens degraded, with u under the long path"
        );
    }
    // u is the first stage carried, x retires; the seal follows the move.
    let through_seq = 11;
    assert_eq!(
        outcomes,
        [
            (
                false,
                (true, true),
                (Some(through_seq), true),
                Ok((vec![1], None))
            ),
            (true, (true, true), (None, true), Ok((vec![1], None))),
        ],
        "work admitted under the reserve installs at the cap that admitted it"
    );
}

/// The projected growth read at each cursor a seal or a retained boundary can
/// name, against the same growth by a full scan of the history, at the stage
/// count the namespace holds and at others.
fn projected_growth_sweep(f: &mut Fixture) -> Vec<(u64, u64)> {
    let last = f.overlay.history.records.last().map_or(0, |e| e.seq);
    let retained = f.overlay.journal.lock().unwrap().completion.clone();
    let seal = f.overlay.projected_seal.take();
    let counts = [0, f.overlay.namespace.stages.len(), 3];
    let both = |f: &Fixture, stages: usize, completion: &CompletionReserve| {
        (
            f.overlay.projected_growth(stages, completion).unwrap(),
            f.overlay
                .projected_growth_by_scan(stages, completion)
                .unwrap(),
        )
    };
    let mut pairs = Vec::new();
    for through in 0..=last + 1 {
        let mut boundary = CompletionReserve::default();
        boundary.commits.insert(
            1_000,
            CompletionSlot {
                projected: Some(through),
                ..CompletionSlot::default()
            },
        );
        for stages in counts {
            f.overlay.projected_seal = Some(through);
            pairs.push(both(f, stages, &CompletionReserve::default()));
            f.overlay.projected_seal = None;
            pairs.push(both(f, stages, &boundary));
        }
    }
    f.overlay.projected_seal = seal;
    for stages in counts {
        pairs.push(both(f, stages, &retained));
    }
    pairs
}

/// The growth a projected reserve adds is read from a prefix kept with the
/// history, not scanned for. It equals the scan at every cursor, with a seal
/// live, with the boundary recorded beside it, with the boundary alone, and
/// after a restart restoring the retained boundary; the cursors give more than
/// one growth, so a value fixed when the reserve began would differ.
#[test]
fn projected_growth_equals_a_full_scan_at_every_cursor() {
    let (mut f, _, _, x) = omitted_under_a_long_move();
    let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    f.overlay.reserve_projected().unwrap();
    let mut phases = Vec::new();
    let mut judge = |f: &mut Fixture, phase: &'static str| {
        let pairs = projected_growth_sweep(f);
        let stages = f.overlay.namespace.stages.len();
        let completion = f.overlay.journal.lock().unwrap().completion.clone();
        let current = f.overlay.projected_growth(stages, &completion).unwrap();
        let mut distinct: Vec<u64> = pairs.iter().map(|&(cached, _)| cached).collect();
        distinct.sort_unstable();
        distinct.dedup();
        let mismatches: Vec<_> = pairs.into_iter().filter(|(c, s)| c != s).collect();
        phases.push((phase, mismatches, distinct.len() > 3, current > 0));
    };
    judge(&mut f, "seal");
    let bytes = f.sync(x, 1).chunks.concat();
    f.overlay
        .append(&Record::ProjectedBoundary {
            candidate: grain(9),
            through_seq,
            publication_id: PUBLICATION,
            selection: Some(ProjectedSelection {
                stage_id: x,
                content: GrainId::of(&bytes),
                size: bytes.len() as u64,
            }),
        })
        .unwrap();
    judge(&mut f, "seal and boundary");
    f.overlay.release_projected();
    judge(&mut f, "boundary");
    f.reopen().unwrap();
    judge(&mut f, "restart");
    assert_eq!(
        phases,
        [
            ("seal", Vec::new(), true, true),
            ("seal and boundary", Vec::new(), true, true),
            ("boundary", Vec::new(), true, true),
            ("restart", Vec::new(), true, true),
        ],
        "the prefix growth must equal the full scan, over a non-trivial domain"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResidualShape {
    CopyUpNoWrite,
    CopyUpRestore,
    CopyUpChange,
    RebindNoWrite,
    RebindRestore,
    RebindChange,
    RecreateNoWrite,
    Create,
    CopyUpThenMove,
    CopyUpThenDelete,
    CopyUpThenExec,
    DeleteThenCreate,
    MoveStaged,
    MoveBase,
    PreCopyUpNoWrite,
    PreCopyUpNoWriteThenRestore,
    PreCopyUpThenMove,
    PreCopyUpThenExec,
    DetachedWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ShapeOutcome {
    Install,
    Collision,
    RefusedBoth,
    InventoryOnlyRefusal,
    Unconstructible,
}

#[expect(
    clippy::too_many_lines,
    reason = "one matrix constructor keeps every namespace shape comparable"
)]
fn inventory_installation_shape(
    shape: ResidualShape,
    mode: &str,
    remote: bool,
    restart: bool,
) -> ShapeOutcome {
    use ResidualShape as S;

    let mut f = with_files(&[("y", b"base y")]);
    let issued = matches!(
        shape,
        S::RebindNoWrite | S::RebindRestore | S::RebindChange | S::RecreateNoWrite
    );
    if issued {
        let mut journal_header = header();
        journal_header.next_stage_id = 2;
        f.io.write_at(
            &f.overlay.journal_path(),
            0,
            &codec::encode_journal(&journal_header, &[]).unwrap(),
        )
        .unwrap();
        f.reopen().unwrap();
    }
    let mut pre = None;
    if matches!(
        shape,
        S::PreCopyUpNoWrite
            | S::PreCopyUpNoWriteThenRestore
            | S::PreCopyUpThenMove
            | S::PreCopyUpThenExec
    ) {
        pre = Some(
            f.overlay
                .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
                .unwrap(),
        );
    }
    if shape == S::DetachedWrite {
        let id = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
            .unwrap();
        f.write(id, b"staged");
        hold(&mut f, &[name("y")]);
        unlink(&mut f, "y", id);
        pre = Some(id);
    }
    if shape == S::MoveStaged {
        let id = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
            .unwrap();
        f.write(id, b"staged");
        if mode == "projected" {
            f.sync(id, 1);
        }
        pre = Some(id);
    }
    if shape == S::DetachedWrite && mode == "commit" {
        return ShapeOutcome::Unconstructible;
    }
    let (mut proof, publication) = if mode == "projected" {
        let x = create_at(&mut f, at("x"), b"x");
        let boundary = publish(&mut f, Some(x), 5);
        let captured: Vec<_> = f
            .overlay
            .projected_commit_entries(boundary, PUBLICATION)
            .unwrap()
            .into_iter()
            .map(|mut entry| {
                entry.stage_id = None;
                entry
            })
            .collect();
        (
            LandedProof {
                boundary_seq: boundary,
                landed_root: grain(4),
                landed_seq: 2,
                captured_entries: captured.clone(),
                entries: captured,
            },
            PUBLICATION,
        )
    } else {
        (f.boundary_proof(), [7; 16])
    };
    let mut stage = pre;
    let base = GrainId::of(b"base y");
    let craft = |f: &mut Fixture| {
        let path = f.overlay.stage_path(1);
        f.io.create(&path).unwrap();
        f.io.write_at(
            &path,
            0,
            &StagingHeader {
                writer: header().writer,
                stage_id: 1,
                mark: MarkState::Absent,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
    };
    match shape {
        S::CopyUpNoWrite
        | S::CopyUpRestore
        | S::CopyUpChange
        | S::CopyUpThenMove
        | S::CopyUpThenDelete
        | S::CopyUpThenExec => {
            let id = f
                .overlay
                .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
                .unwrap();
            stage = Some(id);
            match shape {
                S::CopyUpRestore => {
                    f.write(id, b"later!");
                    f.write(id, b"base y");
                }
                S::CopyUpChange => f.write(id, b"local!"),
                S::CopyUpThenMove => ns(
                    &mut f,
                    Record::Move {
                        from: at("y"),
                        to: at("z"),
                    },
                ),
                S::CopyUpThenDelete => unlink(&mut f, "y", id),
                S::CopyUpThenExec => ns(
                    &mut f,
                    Record::SetattrExec {
                        at: at("y"),
                        exec: true,
                    },
                ),
                _ => {}
            }
        }
        S::RebindNoWrite | S::RebindRestore | S::RebindChange => {
            craft(&mut f);
            f.io.write_at(&f.overlay.stage_path(1), 160, b"base y")
                .unwrap();
            f.overlay
                .append(&Record::StageBind {
                    at: at("y"),
                    cause: codec::BindCause::Rebind,
                    stage_id: 1,
                    staged_size: 6,
                    base_content: base,
                })
                .unwrap();
            stage = Some(1);
            if shape == S::RebindRestore {
                f.write(1, b"later!");
                f.write(1, b"base y");
            }
            if shape == S::RebindChange {
                f.write(1, b"local!");
            }
        }
        S::RecreateNoWrite => {
            craft(&mut f);
            f.overlay
                .append(&Record::RecreateFile {
                    at: Some(at("n")),
                    exec: false,
                    stage_id: 1,
                    anchor: None,
                })
                .unwrap();
            stage = Some(1);
        }
        S::Create => stage = Some(create_at(&mut f, at("n"), b"new!!!")),
        S::DeleteThenCreate => {
            ns(
                &mut f,
                Record::Delete {
                    at: at("y"),
                    kind: codec::DeleteKind::File { stage_id: None },
                },
            );
            stage = Some(create_at(&mut f, at("y"), b"new!!!"));
        }
        S::MoveStaged | S::MoveBase | S::PreCopyUpThenMove => ns(
            &mut f,
            Record::Move {
                from: at("y"),
                to: at("z"),
            },
        ),
        S::PreCopyUpNoWriteThenRestore => {
            let id = pre.unwrap();
            f.write(id, b"later!");
            f.write(id, b"base y");
        }
        S::PreCopyUpNoWrite => {}
        S::PreCopyUpThenExec => ns(
            &mut f,
            Record::SetattrExec {
                at: at("y"),
                exec: true,
            },
        ),
        S::DetachedWrite => {
            let id = pre.unwrap();
            if f.overlay
                .write(&mut f.store, &f.owner, id, 0, b"later!")
                .is_err()
            {
                return ShapeOutcome::Unconstructible;
            }
        }
    }
    let remote_id = GrainId::of(b"remote");
    f.source.0.insert(remote_id, b"remote".to_vec());
    if remote {
        let target = if matches!(shape, S::Create | S::RecreateNoWrite) {
            "n"
        } else {
            "y"
        };
        if let Some(entry) = proof
            .entries
            .iter_mut()
            .find(|entry| entry.path == vec![name(target)])
        {
            entry.kind = OverlayKind::File {
                content: Some(remote_id),
            };
            entry.size = 6;
        } else {
            proof.entries.push(file(target, b"remote"));
            proof.entries.sort_by(|a, b| a.path.cmp(&b.path));
        }
    }
    let proof = f.landing(proof);
    let source = residual_inventory_source(&mut f, proof.clone(), publication);
    let inventory = inventory_from_source(&mut f, &source);
    let classified = inventory
        .as_ref()
        .map(|inventory| inventory.collisions.len())
        .map_err(Clone::clone);
    let inventory = inventory.unwrap_or_else(|_| super::super::ResidualInventory {
        collisions: Vec::new(),
        reconciliation: super::super::residual_inventory::ReconciliationPlan::default(),
    });
    if restart {
        f.reopen().unwrap();
    }
    let result = f
        .overlay
        .replace_residual_landed(&mut f.store, &f.owner, proof, &inventory, &mut f.source)
        .map(|_| ())
        .map_err(|error| error.to_string());
    if result.is_ok() {
        f.reopen().unwrap();
    }
    match (&classified, &result) {
        (Ok(0), Ok(())) => ShapeOutcome::Install,
        (Ok(0), Err(error)) => panic!(
            "zero-collision inventory disagreed with installation for {shape:?}/{mode}/remote={remote}/restart={restart}: {error}"
        ),
        (Ok(_), Err(_)) => ShapeOutcome::Collision,
        (Ok(count), Ok(())) => panic!(
            "collision inventory disagreed with installation for {shape:?}/{mode}/remote={remote}/restart={restart}: count={count}, stage={stage:?}"
        ),
        (Err(_), Err(_)) => ShapeOutcome::RefusedBoth,
        (Err(_), Ok(())) => ShapeOutcome::InventoryOnlyRefusal,
    }
}

#[test]
fn residual_inventory_and_installation_agree_across_supported_shapes() {
    use ResidualShape as S;

    let mut outcomes = BTreeMap::new();
    let mut rows = 0usize;
    for shape in [
        S::CopyUpNoWrite,
        S::CopyUpRestore,
        S::CopyUpChange,
        S::RebindNoWrite,
        S::RebindRestore,
        S::RebindChange,
        S::RecreateNoWrite,
        S::Create,
        S::CopyUpThenMove,
        S::CopyUpThenDelete,
        S::CopyUpThenExec,
        S::DeleteThenCreate,
        S::MoveStaged,
        S::MoveBase,
        S::PreCopyUpNoWrite,
        S::PreCopyUpNoWriteThenRestore,
        S::PreCopyUpThenMove,
        S::PreCopyUpThenExec,
        S::DetachedWrite,
    ] {
        for mode in ["projected", "commit"] {
            for remote in [true, false] {
                for restart in [true, false] {
                    let outcome = inventory_installation_shape(shape, mode, remote, restart);
                    *outcomes.entry(outcome).or_insert(0usize) += 1;
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(
        (
            outcomes.get(&ShapeOutcome::Install).copied().unwrap_or(0),
            outcomes.get(&ShapeOutcome::Collision).copied().unwrap_or(0),
            outcomes
                .get(&ShapeOutcome::RefusedBoth)
                .copied()
                .unwrap_or(0),
            outcomes
                .get(&ShapeOutcome::InventoryOnlyRefusal)
                .copied()
                .unwrap_or(0),
            outcomes
                .get(&ShapeOutcome::Unconstructible)
                .copied()
                .unwrap_or(0),
            rows,
        ),
        (84, 32, 26, 6, 4, 152),
        "{outcomes:?}"
    );
}
