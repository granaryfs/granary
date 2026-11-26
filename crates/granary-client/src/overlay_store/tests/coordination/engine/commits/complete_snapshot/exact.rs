// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Complete snapshots and the corresponding dependency-closed scoped projections.

use super::*;

const W: &[u8] = b"W bytes";
const F: &[u8] = b"F bytes";
const Y: &[u8] = b"Y checkpoint";
type Row = (&'static str, Option<&'static [u8]>, u64, bool);
type ImageRow = (String, Option<Vec<u8>>, u64, bool);
type Image = Vec<ImageRow>;

#[derive(Clone, Copy, Debug)]
enum Case {
    Directory,
    DurableMove,
    Checkpoint,
    RemoveDirectory,
    BeforePair,
    AfterPair,
    Replacement,
    MovedDurable,
    ExtraFile,
}

fn check_image(actual: &[ImageRow], expected: &[Row]) {
    let mut expected: Image = expected
        .iter()
        .map(|&(path, bytes, size, exec)| (path.to_owned(), bytes.map(<[u8]>::to_vec), size, exec))
        .collect();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(actual, expected.as_slice());
}

fn check_root(f: &Fixture, root: &[u8], expected: &[Row]) {
    let bytes = tree(f, root);
    let doc = granary_core::root::decode_root(root).unwrap();
    let entries = crate::writable_store::capture::overlay_base_entries(
        f.content.as_ref(),
        doc.manifest_root,
        &|_, _| 0,
        &mut |_, _| Ok(()),
        &|| CoordinationError::Refused("test image"),
    )
    .unwrap();
    check_image(
        &entries
            .into_iter()
            .map(|entry| {
                let path = entry
                    .path
                    .iter()
                    .map(|n| String::from_utf8_lossy(n.as_bytes()))
                    .collect::<Vec<_>>()
                    .join("/");
                (
                    path.clone(),
                    bytes.get(&path).unwrap().clone(),
                    entry.size,
                    entry.exec,
                )
            })
            .collect::<Image>(),
        expected,
    );
}

fn check_live(f: &Fixture, expected: &[Row]) {
    let image = transaction(f, |t| {
        t.entries()?
            .into_iter()
            .map(|entry| {
                let path = entry
                    .path
                    .iter()
                    .map(|n| String::from_utf8_lossy(n.as_bytes()))
                    .collect::<Vec<_>>()
                    .join("/");
                let bytes = if matches!(entry.kind, OverlayKind::File { .. }) {
                    let length = usize::try_from(entry.size).unwrap();
                    Some(if let Some(stage) = entry.stage_id {
                        t.read_stage(stage, 0, length)?
                    } else {
                        let OverlayKind::File {
                            content: Some(content),
                        } = entry.kind
                        else {
                            panic!("clean file has no content")
                        };
                        f.content.read_content(content, 0, length)?
                    })
                } else {
                    None
                };
                Ok((path, bytes, entry.size, entry.exec))
            })
            .collect::<Result<Image, OverlayError>>()
    });
    check_image(&image, expected);
}

fn payload(f: &Fixture, bytes: &[u8]) -> GrainId {
    let id = GrainId::of(bytes);
    f.content.put_object(id, bytes).unwrap();
    let grains = FileGrains::Inline(vec![granary_core::manifest::GrainRef {
        id,
        unpacked_len: u32::try_from(bytes.len()).unwrap(),
    }]);
    let content = GrainId::of(&manifest::node::file_payload(bytes.len() as u64, &grains).unwrap());
    f.content
        .remember_payload(content, bytes.len() as u64, &grains)
        .unwrap();
    content
}

/// A prior clean checkpoint, seeded through the same capture/mark seam as the
/// overlay fixtures; this is not a new fsync through the poisoned namespace.
fn checkpoint(f: &Fixture, stage: u64) -> crate::DurableFile {
    let mut local = f.store.lock().unwrap();
    let capture = crate::overlay_store::tests::coordination::captures::capture(&mut local, stage);
    let bytes = capture.chunks.concat();
    let content = payload(f, &bytes);
    let proof = RegisteredCapture {
        capture,
        writer: local.writer_uuid(),
        generation: granary_core::intent::decode_receipt(&local.snapshot().current)
            .unwrap()
            .generation,
        prepared_root: GrainId::of(&f.remote.authority.lock().unwrap().root),
        content,
    };
    local
        .overlay_transaction(|t| t.record_file_synced(&proof))
        .unwrap();
    let boundary = local
        .overlay_transaction(|t| t.seal_sync(SyncTarget::Directory(None)))
        .unwrap();
    let marked = boundary
        .checkpoints()
        .iter()
        .find(|p| p.content == content)
        .unwrap()
        .clone();
    local
        .overlay_transaction(|t| t.release_sync_boundary(&boundary))
        .unwrap();
    marked
}

struct Witness {
    fixture: Fixture,
    full: Vec<Row>,
    scoped: Vec<Row>,
    excluded: Vec<bool>,
    selected: Option<u64>,
}

#[expect(
    clippy::too_many_lines,
    reason = "the exact scripts keep independent full and scoped expected images together"
)]
async fn witness(case: Case) -> Witness {
    let f = Fixture::new().await;
    let base_file = match case {
        Case::DurableMove
        | Case::BeforePair
        | Case::AfterPair
        | Case::Replacement
        | Case::ExtraFile => Some("s"),
        Case::MovedDurable => Some("q"),
        _ => None,
    };
    if let Some(path) = base_file {
        f.create(path, F);
        record(
            &f,
            Record::SetattrExec {
                at: loc(path),
                exec: true,
            },
        );
    }
    if matches!(case, Case::ExtraFile) {
        f.create("f", b"old f");
    }
    if matches!(case, Case::RemoveDirectory) {
        record(
            &f,
            Record::Create {
                at: loc("d"),
                kind: codec::CreateKind::Dir,
            },
        );
    }
    if base_file.is_some() || matches!(case, Case::RemoveDirectory) {
        land(&f, 30).await;
    }
    let mut full = vec![("q", Some(W), 7, false)];
    let mut scoped: Vec<Row> = vec![];
    let mut excluded = vec![true; 5];
    let mut selected = None;
    if matches!(case, Case::ExtraFile) {
        f.create("u", W);
        record(
            &f,
            Record::Replace {
                from: loc("u"),
                to: loc("f"),
            },
        );
        record(
            &f,
            Record::Move {
                from: loc("f"),
                to: loc("g"),
            },
        );
        record(
            &f,
            Record::Replace {
                from: loc("s"),
                to: loc("g"),
            },
        );
        selected = Some(f.create("x", b"x"));
        full = vec![("g", Some(F), 7, true), ("x", Some(b"x"), 1, false)];
        scoped = vec![
            ("f", Some(b"old f"), 5, false),
            ("g", Some(F), 7, true),
            ("x", Some(b"x"), 1, false),
        ];
        excluded = vec![true, true, true, false, false];
    } else if matches!(case, Case::MovedDurable) {
        f.create("p", W);
        record(
            &f,
            Record::Move {
                from: loc("p"),
                to: loc("r"),
            },
        );
        record(
            &f,
            Record::Move {
                from: loc("q"),
                to: loc("p"),
            },
        );
        delete(&f, "p", None);
        selected = Some(f.create("p", Y));
        full = vec![("p", Some(Y), 12, false), ("r", Some(W), 7, false)];
        scoped = vec![("q", Some(F), 7, true)];
    } else {
        let path = if matches!(case, Case::RemoveDirectory) {
            "d/f"
        } else {
            "p"
        };
        f.create(path, W);
        record(
            &f,
            Record::Move {
                from: loc(path),
                to: loc("q"),
            },
        );
        let x = f.create(path, b"X");
        if matches!(case, Case::BeforePair | Case::AfterPair | Case::Replacement) {
            record(
                &f,
                Record::Replace {
                    from: loc("s"),
                    to: loc("p"),
                },
            );
            delete(&f, "p", None);
            excluded = vec![true, true, true, false, false];
            if !matches!(case, Case::BeforePair) {
                let z = f.create("p", b"Z");
                delete(&f, "p", Some(z));
                excluded.extend([true, true]);
            }
            if matches!(case, Case::Replacement) {
                record(
                    &f,
                    Record::Create {
                        at: loc("p"),
                        kind: codec::CreateKind::Dir,
                    },
                );
                full.push(("p", None, 0, false));
                excluded.push(true);
            }
        } else {
            delete(&f, path, Some(x));
            match case {
                Case::Directory => {
                    record(
                        &f,
                        Record::Create {
                            at: loc("p"),
                            kind: codec::CreateKind::Dir,
                        },
                    );
                    full.push(("p", None, 0, false));
                }
                Case::DurableMove => {
                    record(
                        &f,
                        Record::Move {
                            from: loc("s"),
                            to: loc("p"),
                        },
                    );
                    full.push(("p", Some(F), 7, true));
                    scoped.push(("s", Some(F), 7, true));
                }
                Case::Checkpoint => {
                    let y = f.create("p", Y);
                    let marked = checkpoint(&f, y);
                    assert_eq!((marked.size, marked.content_boundary > 0), (12, true));
                    full.push(("p", Some(Y), 12, false));
                }
                Case::RemoveDirectory => {
                    record(
                        &f,
                        Record::Delete {
                            at: loc("d"),
                            kind: codec::DeleteKind::Dir,
                        },
                    );
                    scoped.push(("d", None, 0, false));
                }
                _ => unreachable!("replacement variants handled above"),
            }
        }
    }
    check_live(&f, &full);
    Witness {
        fixture: f,
        full,
        scoped,
        excluded,
        selected,
    }
}

fn check_scoped(w: &Witness) {
    let target = w
        .selected
        .map_or(SyncTarget::Directory(None), SyncTarget::Stage);
    let boundary = transaction(&w.fixture, |t| t.seal_sync(target));
    let selected = if let Some(file) = boundary.files().first() {
        let entry = file.entry().unwrap();
        let bytes: &[u8] = if w.selected.is_some() && w.scoped.iter().any(|r| r.0 == "x") {
            b"x"
        } else {
            Y
        };
        vec![crate::DurableFile {
            inode: entry.inode,
            size: file.size(),
            content: payload(&w.fixture, bytes),
            content_boundary: boundary.through_seq(),
        }]
    } else {
        vec![]
    };
    let projection = boundary.project(&selected).unwrap();
    let mask: Vec<_> = boundary
        .effects()
        .iter()
        .filter(|e| {
            matches!(
                e.record,
                Record::Create { .. }
                    | Record::Move { .. }
                    | Record::Replace { .. }
                    | Record::Delete { .. }
            )
        })
        .map(|e| projection.excluded().contains(&e.seq))
        .collect();
    let actual: Image = projection
        .entries()
        .iter()
        .map(|e| {
            let path = e
                .path
                .iter()
                .map(|n| String::from_utf8_lossy(n.as_bytes()))
                .collect::<Vec<_>>()
                .join("/");
            let bytes = if let OverlayKind::File {
                content: Some(content),
            } = e.kind
            {
                Some(
                    w.fixture
                        .content
                        .read_content(content, 0, usize::try_from(e.size).unwrap())
                        .unwrap(),
                )
            } else {
                None
            };
            (path, bytes, e.size, e.exec)
        })
        .collect();
    assert_eq!(mask, w.excluded, "namespace exclusion mask");
    check_image(&actual, &w.scoped);
    transaction(&w.fixture, |t| t.release_sync_boundary(&boundary));
}

async fn complete(case: Case) {
    let w = witness(case).await;
    check_scoped(&w);
    let root = land(&w.fixture, 60).await;
    check_root(&w.fixture, &root, &w.full);
    let f = w.fixture.restart_at_head().await;
    check_live(&f, &w.full);
    check_root(&f, &root, &w.full);
}

async fn scoped(case: Case) {
    let w = witness(case).await;
    check_scoped(&w);
    let target = if matches!(case, Case::ExtraFile) {
        SyncTarget::Stage(w.selected.unwrap())
    } else {
        SyncTarget::Directory(None)
    };
    let result = published::published(&w.fixture, target, 70, SyncOptions::default()).await;
    if matches!(case, Case::ExtraFile) {
        assert_eq!(
            result.map_err(|e| e.to_string()),
            Err("overlay refused: projected residual unsupported".to_owned())
        );
    } else {
        assert!(result.is_ok(), "scoped publication: {result:?}");
        check_live(&w.fixture, &w.full);
    }
    let root = w
        .fixture
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    check_root(&w.fixture, &root, &w.scoped);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_vacancy_directory() {
    complete(Case::Directory).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_vacancy_directory() {
    scoped(Case::Directory).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_vacancy_durable_move() {
    complete(Case::DurableMove).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_vacancy_durable_move() {
    scoped(Case::DurableMove).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_vacancy_checkpoint() {
    complete(Case::Checkpoint).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_vacancy_checkpoint() {
    scoped(Case::Checkpoint).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_vacancy_remove_directory() {
    complete(Case::RemoveDirectory).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_vacancy_remove_directory() {
    scoped(Case::RemoveDirectory).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_replacement_before_pair() {
    complete(Case::BeforePair).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_replacement_before_pair() {
    scoped(Case::BeforePair).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_replacement_after_pair() {
    complete(Case::AfterPair).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_replacement_after_pair() {
    scoped(Case::AfterPair).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_replacement_directory() {
    complete(Case::Replacement).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_replacement_directory() {
    scoped(Case::Replacement).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_moved_durable() {
    complete(Case::MovedDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_moved_durable() {
    scoped(Case::MovedDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_complete_extra_file() {
    complete(Case::ExtraFile).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_scoped_extra_file() {
    scoped(Case::ExtraFile).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_selection_overrides_same_size_checkpoint() {
    let f = Fixture::new().await;
    let stage = f.create("p", Y);
    sync(&f, SyncTarget::Stage(stage)).await.unwrap();
    transaction(&f, |t| t.write(stage, 0, b"Z checkpoint").map(|_| ()));
    let root = land(&f, 60).await;
    let expected = [("p", Some(b"Z checkpoint".as_slice()), 12, false)];
    check_root(&f, &root, &expected);
    let f = f.restart_at_head().await;
    check_live(&f, &expected);
    check_root(&f, &root, &expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_scoped_moved_selection_keeps_legacy_path() {
    for published in [false, true] {
        let f = Fixture::new().await;
        f.create("r", W);
        record(
            &f,
            Record::Move {
                from: loc("r"),
                to: loc("q"),
            },
        );
        record(
            &f,
            Record::Create {
                at: loc("r"),
                kind: codec::CreateKind::Dir,
            },
        );
        let stage = f.create("y", Y);
        record(
            &f,
            Record::Move {
                from: loc("y"),
                to: loc("r/y"),
            },
        );
        let result = if published {
            f.engine
                .publish_sync(
                    SyncTarget::Stage(stage),
                    SyncOptions::default(),
                    Entropy(70),
                )
                .wait()
                .await
        } else {
            sync(&f, SyncTarget::Stage(stage)).await
        };
        assert!(result.is_ok(), "published={published}: {result:?}");
        let root = f.remote.authority.lock().unwrap().root.clone();
        check_root(&f, &root, &[("y", Some(Y), 12, false)]);
        check_live(
            &f,
            &[
                ("q", Some(W), 7, false),
                ("r", None, 0, false),
                ("r/y", Some(Y), 12, false),
            ],
        );
    }
}
