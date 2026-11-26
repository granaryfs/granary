// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn anchor(content: GrainId, size: u64) -> codec::RecreateAnchor {
    codec::RecreateAnchor { content, size }
}

fn recreate(
    at: Option<codec::Location>,
    stage_id: u64,
    anchor: Option<codec::RecreateAnchor>,
) -> Record {
    Record::RecreateFile {
        exec: at.is_some(),
        at,
        stage_id,
        anchor,
    }
}

fn nested(parent: &str, leaf: &str) -> codec::Location {
    codec::Location {
        parent: codec::Parent::new(vec![name(parent)]).unwrap(),
        name: name(leaf),
    }
}

/// A fixture whose stage 1 held `landed` and was retired by the landing that
/// published it: its id is issued and no longer bound, and its staging file
/// is gone. The landed tree holds `f` at that content and a directory `d`.
fn retired() -> (Fixture, GrainId) {
    let mut f = Fixture::new();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Create {
                at: at("d"),
                kind: codec::CreateKind::Dir,
            },
        )
        .unwrap();
    let id = f.create();
    f.write(id, b"landed");
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert!(f.overlay.namespace.stages.is_empty(), "stage 1 was carried");
    (f, GrainId::of(b"landed"))
}

/// A stage's path, size, base, base size and whether it holds a mark or checkpoint.
type StageRow = (Option<Vec<Name>>, u64, Option<GrainId>, u64, bool);

fn stage_row(f: &Fixture, id: u64) -> Option<StageRow> {
    f.overlay.namespace.stages.get(&id).map(|stage| {
        (
            stage.path.clone(),
            stage.size,
            stage.base,
            stage.base_size,
            stage.mark.is_some() || stage.checkpoint_boundary.is_some(),
        )
    })
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
fn recreate_names_or_detaches_an_issued_stage_with_its_anchor_as_base() {
    let base = vec![
        OverlayEntry {
            path: vec![name("d")],
            inode: 0,
            kind: OverlayKind::Directory,
            stage_id: None,
            size: 0,
            exec: false,
        },
        OverlayEntry {
            path: vec![name("f")],
            inode: 0,
            kind: OverlayKind::File {
                content: Some(grain(1)),
            },
            stage_id: None,
            size: 1,
            exec: false,
        },
    ];
    let mut ns = Namespace::base(&base).unwrap();
    let entries = ns.entries.len();
    ns.fold(&recreate(None, 2, None)).unwrap();
    ns.fold(&recreate(None, 3, Some(anchor(grain(4), 9))))
        .unwrap();
    // A detached stage adds no entry, so no name can be taken by it.
    assert_eq!(
        ns.entries.len(),
        entries,
        "a detached recreate made an entry"
    );
    ns.fold(&recreate(
        Some(nested("d", "u")),
        1,
        Some(anchor(grain(4), 9)),
    ))
    .unwrap();
    ns.fold(&Record::Truncate {
        stage_id: 1,
        new_size: 4,
    })
    .unwrap();
    ns.fold(&Record::Truncate {
        stage_id: 3,
        new_size: 12,
    })
    .unwrap();
    let u = vec![name("d"), name("u")];
    let stage = |id: u64| {
        let s = &ns.stages[&id];
        (s.path.clone(), s.size, s.base, s.base_size, s.mark)
    };
    assert_eq!(
        (
            ns.entries
                .get(&u)
                .map(|e| (e.kind.clone(), e.stage_id, e.size, e.exec)),
            stage(1),
            stage(2),
            stage(3),
        ),
        (
            Some((OverlayKind::File { content: None }, Some(1), 4, true)),
            (Some(u.clone()), 4, Some(grain(4)), 9, None),
            (None, 0, None, 0, None),
            (None, 12, Some(grain(4)), 9, None),
        )
    );
    let mut count = 0;
    for (what, record, want) in [
        (
            "occupied name",
            recreate(Some(at("f")), 4, None),
            "create destination exists",
        ),
        (
            "missing parent",
            recreate(Some(nested("e", "x")), 4, None),
            "parent is not a directory",
        ),
        (
            "file parent",
            recreate(Some(nested("f", "x")), 4, None),
            "parent is not a directory",
        ),
        (
            "named stage already present",
            recreate(Some(at("w")), 1, None),
            "bind type or stage conflict",
        ),
        (
            "detached stage already present",
            recreate(None, 2, Some(anchor(grain(4), 9))),
            "bind type or stage conflict",
        ),
    ] {
        let mut probe = ns.clone();
        assert_eq!(
            probe.fold(&record).map_err(|e| e.to_string()),
            Err(format!("overlay refused: {want}")),
            "{what}"
        );
        count += 1;
    }
    assert_eq!(count, 5);
}

#[test]
fn a_named_recreate_is_a_file_creation_its_anchor_does_not_make_eligible() {
    let (mut f, landed) = retired();
    let seq = f
        .overlay
        .append(&recreate(
            Some(nested("d", "u")),
            1,
            Some(anchor(landed, 6)),
        ))
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Move {
                from: nested("d", "u"),
                to: at("w"),
            },
        )
        .unwrap();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    let creation = b.effects().iter().find(|e| e.sequence() == seq).unwrap();
    let inode = creation.result_identity().unwrap();
    let moved = b
        .effects()
        .iter()
        .find(|e| e.sequence() == seq + 1)
        .unwrap();
    let selected = DurableFile {
        inode,
        size: 6,
        content: grain(7),
        content_boundary: 0,
    };
    assert_eq!(
        (
            moved.dependencies().contains(&seq),
            b.checkpoints().iter().any(|c| c.inode == inode),
            rows(b.project(&[]).unwrap().entries()),
            rows(b.project(&[selected]).unwrap().entries()),
        ),
        (
            true,
            false,
            vec![("d".to_owned(), None), ("f".to_owned(), Some(landed))],
            vec![
                ("d".to_owned(), None),
                ("f".to_owned(), Some(landed)),
                ("w".to_owned(), Some(grain(7)))
            ],
        )
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn an_unlinked_named_recreate_is_selectable_through_its_creation() {
    let (mut f, landed) = retired();
    let seq = f
        .overlay
        .append(&recreate(
            Some(nested("d", "u")),
            1,
            Some(anchor(landed, 6)),
        ))
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: nested("d", "u"),
                kind: codec::DeleteKind::File { stage_id: Some(1) },
            },
        )
        .unwrap();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    let creation = b.effects().iter().find(|e| e.sequence() == seq).unwrap();
    let selected = DurableFile {
        inode: creation.result_identity().unwrap(),
        size: 6,
        content: grain(7),
        content_boundary: 0,
    };
    // No entry names it now; only its creation makes the identity known.
    assert_eq!(
        b.project(&[selected])
            .map(|p| rows(p.entries()))
            .map_err(|e| e.to_string()),
        Ok(vec![("d".to_owned(), None), ("f".to_owned(), Some(landed))])
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

fn rows(entries: &[OverlayEntry]) -> Vec<(String, Option<GrainId>)> {
    entries
        .iter()
        .map(|e| {
            let content = match e.kind {
                OverlayKind::File { content } => content,
                _ => None,
            };
            let path = e
                .path
                .iter()
                .map(|n| std::str::from_utf8(n.as_bytes()).unwrap());
            (path.collect::<Vec<_>>().join("/"), content)
        })
        .collect()
}

#[test]
fn reopen_finds_a_named_recreate_dirty_and_restores_its_anchor_bytes() {
    let mut observed = Vec::new();
    for named in [true, false] {
        let (mut f, landed) = retired();
        f.source.0.insert(landed, b"landed".to_vec());
        let at = named.then(|| at("u"));
        let seq = f
            .overlay
            .append(&recreate(at, 1, Some(anchor(landed, 6))))
            .unwrap();
        // An ordinary record is durable at the next sync point.
        f.io.sync(&f.overlay.journal_path()).unwrap();
        f.io.crash();
        f.reopen().unwrap();
        observed.push((
            seq,
            f.overlay
                .dirty_spans
                .iter()
                .map(|s| (s.first_seq, s.last_seq))
                .collect::<Vec<_>>(),
            stage_row(&f, 1),
            f.io.bytes(&f.overlay.stage_path(1)).split_off(160),
        ));
    }
    assert_eq!(
        observed,
        [
            (
                2,
                vec![(2, 2)],
                Some((
                    Some(vec![name("u")]),
                    6,
                    Some(GrainId::of(b"landed")),
                    6,
                    false
                )),
                b"landed".to_vec()
            ),
            (
                2,
                vec![],
                Some((None, 6, Some(GrainId::of(b"landed")), 6, false)),
                b"landed".to_vec()
            ),
        ]
    );
}

#[test]
fn reopen_names_a_marked_detached_stage_only_through_its_recreate() {
    let mut observed = Vec::new();
    for recreated in [true, false] {
        let (mut f, landed) = retired();
        let mark = SyncedMark {
            synced_size: 6,
            content: landed,
            generation: 1,
        };
        let path = f.overlay.stage_path(1);
        f.io.create(&path).unwrap();
        let mut bytes = StagingHeader {
            writer: [17; 16],
            stage_id: 1,
            mark: MarkState::Present(mark),
        }
        .encode()
        .unwrap();
        bytes.extend_from_slice(b"landed");
        f.io.write_at(&path, 0, &bytes).unwrap();
        f.io.sync(&path).unwrap();
        f.io.sync_directory(&f.overlay.area.join("staging"))
            .unwrap();
        if recreated {
            f.overlay
                .append(&recreate(None, 1, Some(anchor(landed, 6))))
                .unwrap();
        }
        // An ordinary record is durable at the next sync point.
        f.io.sync(&f.overlay.journal_path()).unwrap();
        f.io.crash();
        let reopened = f.reopen().map_err(|e| e.to_string());
        observed.push((reopened, reopened_mark(&f), f.io.bytes(&path) == bytes));
    }
    assert_eq!(
        observed,
        [
            (Ok(()), Some(6), true),
            (
                Err("overlay refused: unnamed synced staging evidence".to_owned()),
                None,
                true
            ),
        ]
    );
}

/// The synced size of stage 1's mark, when it is present and detached.
fn reopened_mark(f: &Fixture) -> Option<u64> {
    f.overlay
        .namespace
        .stages
        .get(&1)
        .filter(|stage| stage.path.is_none())
        .and_then(|stage| stage.mark.map(|mark| mark.synced_size))
}

/// An anchored named recreate with no extents is clean against its anchor,
/// yet nothing has acknowledged it: its fsync still owes a mark, so the
/// directory sync that follows includes it. The completion records
/// `file-synced` exactly when the capture asks for a mark.
#[test]
fn an_anchored_named_recreate_owes_a_mark_on_its_first_fsync() {
    let (mut f, landed) = retired();
    f.source.0.insert(landed, b"landed".to_vec());
    f.overlay
        .append(&recreate(Some(at("u")), 1, Some(anchor(landed, 6))))
        .unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
    f.reopen().unwrap();
    let mark_after_reopen = f.overlay.namespace.stages[&1].mark;
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(1))
        .unwrap();
    let file = &b.files()[0];
    let observed = (
        file.needs_mark(),
        file.checkpoint(),
        file.dirty_intervals(),
        b.checkpoints().len(),
    );
    let needs_mark = file.needs_mark();
    f.overlay.release_sync_boundary(&b).unwrap();
    if needs_mark {
        f.sync(1, 21);
    }
    let d = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    let after_fsync = rows(d.project(&[]).unwrap().entries());
    f.overlay.release_sync_boundary(&d).unwrap();
    assert_eq!(
        (mark_after_reopen, observed, after_fsync),
        (
            None,
            (true, Some((landed, 6)), vec![], 0),
            vec![
                ("d".to_owned(), None),
                ("f".to_owned(), Some(landed)),
                ("u".to_owned(), Some(landed)),
            ]
        )
    );
}

/// Control for the anchored recreate: a clean copy-up's entry holds its base
/// as published content, so its fsync owes no mark.
#[test]
fn a_clean_copy_up_owes_no_mark_on_its_fsync() {
    let content = GrainId::of(b"base");
    let mut f = Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("x")],
            inode: 0,
            kind: OverlayKind::File {
                content: Some(content),
            },
            stage_id: None,
            size: 4,
            exec: false,
        }],
        Source::default(),
    );
    f.source.0.insert(content, b"base".to_vec());
    f.overlay
        .append(&Record::StageBind {
            at: at("x"),
            cause: codec::BindCause::CopyUp,
            stage_id: 1,
            staged_size: 4,
            base_content: content,
        })
        .unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
    f.reopen().unwrap();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(1))
        .unwrap();
    let file = &b.files()[0];
    let observed = (file.needs_mark(), file.checkpoint(), file.dirty_intervals());
    f.overlay.release_sync_boundary(&b).unwrap();
    assert_eq!(observed, (false, Some((content, 4)), vec![]));
}

/// What a sealed fsync asks for: a mark, its checkpoint and its dirty
/// intervals.
type SealRow = (bool, Option<(GrainId, u64)>, Vec<(u64, u64)>);

fn seal_stage_1(f: &mut Fixture) -> SealRow {
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(1))
        .unwrap();
    let file = &b.files()[0];
    let observed = (file.needs_mark(), file.checkpoint(), file.dirty_intervals());
    f.overlay.release_sync_boundary(&b).unwrap();
    observed
}

/// Once its first fsync's mark lands, an anchored named recreate is clean
/// against that mark and owes no further one, before and after a reopen
/// replays the mark.
#[test]
fn an_anchored_named_recreate_owes_no_mark_once_its_mark_lands() {
    let (mut f, landed) = retired();
    f.source.0.insert(landed, b"landed".to_vec());
    f.overlay
        .append(&recreate(Some(at("u")), 1, Some(anchor(landed, 6))))
        .unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
    f.reopen().unwrap();
    let first = seal_stage_1(&mut f);
    let synced = GrainId::of(&f.sync(1, 21).chunks.concat());
    let marked = seal_stage_1(&mut f);
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
    f.reopen().unwrap();
    let replayed = seal_stage_1(&mut f);
    assert_eq!(
        (first, marked, replayed),
        (
            (true, Some((landed, 6)), vec![]),
            (false, Some((synced, 6)), vec![]),
            (false, Some((synced, 6)), vec![]),
        )
    );
}
