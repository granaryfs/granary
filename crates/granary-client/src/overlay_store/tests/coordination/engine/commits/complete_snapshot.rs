// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Complete commits compact admitted namespace histories without excluding files.

use super::*;
use crate::overlay_store::tests::incremental::loc;
use std::collections::BTreeMap;

mod exact;

fn transaction<T>(
    f: &Fixture,
    action: impl FnOnce(
        &mut crate::writable_store::WritableOverlay<'_, SimIo>,
    ) -> Result<T, OverlayError>,
) -> T {
    f.store.lock().unwrap().overlay_transaction(action).unwrap()
}
fn record(f: &Fixture, record: Record) {
    transaction(f, |t| t.namespace_record(record).map(|_| ()));
}
fn delete(f: &Fixture, path: &str, stage: Option<u64>) {
    record(
        f,
        Record::Delete {
            at: loc(path),
            kind: codec::DeleteKind::File { stage_id: stage },
        },
    );
}
fn poison(f: &Fixture, path: &str) -> u64 {
    let dead = f.create(path, b"dead");
    delete(f, path, Some(dead));
    f.create(path, b"live")
}
async fn land(f: &Fixture, seed: u8) -> Vec<u8> {
    let before = f
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .0
        .to_owned();
    let result = takeover::tree_commit(f, seed).await;
    assert!(result.is_ok(), "complete construction/drive: {result:?}");
    assert!(
        f.remote
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .unwrap()
            .0
            > &before,
        "complete commit did not land"
    );
    f.remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone()
}
fn tree(f: &Fixture, root: &[u8]) -> BTreeMap<String, Option<Vec<u8>>> {
    let doc = granary_core::root::decode_root(root).unwrap();
    crate::writable_store::capture::overlay_base_entries(
        f.content.as_ref(),
        doc.manifest_root,
        &|_, _| 0,
        &mut |_, _| Ok(()),
        &|| CoordinationError::Refused("test tree"),
    )
    .unwrap()
    .into_iter()
    .map(|e| {
        let path = e
            .path
            .iter()
            .map(|n| String::from_utf8_lossy(n.as_bytes()))
            .collect::<Vec<_>>()
            .join("/");
        let bytes = match e.kind {
            OverlayKind::File { content: Some(id) } => Some(
                f.content
                    .read_content(id, 0, usize::try_from(e.size).unwrap())
                    .unwrap(),
            ),
            _ => None,
        };
        (path, bytes)
    })
    .collect()
}
async fn sync(f: &Fixture, target: SyncTarget) -> Result<(), CoordinationError> {
    f.engine.sync(target, SyncOptions::default()).wait().await
}
async fn history(f: &Fixture, nested: bool) -> u64 {
    f.create("a", b"base a");
    f.create("f", b"base f");
    land(f, 40).await;
    record(
        f,
        Record::Move {
            from: loc("a"),
            to: loc("b"),
        },
    );
    if nested {
        record(
            f,
            Record::Create {
                at: loc("n1"),
                kind: codec::CreateKind::Dir,
            },
        );
        poison(f, "n1/n0")
    } else {
        poison(f, "x")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the transaction closure accepts the facade at any borrow lifetime"
)]
async fn complete_snapshot_lands_reopens_and_clears_repeated_poison() {
    for nested in [false, true] {
        let f = Fixture::new().await;
        history(&f, nested).await;
        let path = if nested { "n1/n0" } else { "x" };
        let root = land(&f, 60).await;
        let mut expected = BTreeMap::from([
            ("b".into(), Some(b"base a".to_vec())),
            ("f".into(), Some(b"base f".to_vec())),
            (path.into(), Some(b"live".to_vec())),
        ]);
        if nested {
            expected.insert("n1".into(), None);
        }
        assert_eq!(tree(&f, &root), expected);
        let f = f.restart_at_head().await;
        let inode = transaction(&f, |t| t.entries())
            .into_iter()
            .find(|e| e.path == path.split('/').map(name).collect::<Vec<_>>())
            .unwrap()
            .inode;
        sync(&f, SyncTarget::File(inode)).await.unwrap();
        poison(&f, "again");
        land(&f, 90).await;
        sync(
            &f,
            SyncTarget::File(
                transaction(&f, |t| t.entries())
                    .into_iter()
                    .find(|e| e.path == vec![name("again")])
                    .unwrap()
                    .inode,
            ),
        )
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_never_resurrects_dead_or_detached_checkpoints() {
    for keep in [false, true] {
        let f = Fixture::new().await;
        f.create("s", b"base");
        land(&f, 40).await;
        let q = f.create("q", b"unsynced");
        let p = f.create("p", b"checkpoint");
        sync(&f, SyncTarget::Stage(p)).await.unwrap();
        record(
            &f,
            Record::Replace {
                from: loc("q"),
                to: loc("p"),
            },
        );
        if !keep {
            delete(&f, "p", Some(q));
        }
        let root = land(&f, 60).await;
        let mut expected = BTreeMap::from([("s".into(), Some(b"base".to_vec()))]);
        if keep {
            expected.insert("p".into(), Some(b"unsynced".to_vec()));
        }
        assert_eq!(tree(&f, &root), expected, "keep={keep}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_keeps_sealed_bytes_and_held_suffix() {
    let f = Fixture::new().await;
    let stage = history(&f, true).await;
    transaction(&f, |t| t.hold_stage(stage));
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    let mut entropy = Entropy(60);
    let mut constructing = Box::pin(
        f.engine
            .construct_commit(SyncOptions::default(), &mut entropy),
    );
    let mut entered = Box::pin(fired(&faults, "sync.commit", "captured"));
    std::future::poll_fn(|cx| {
        assert!(constructing.as_mut().poll(cx).is_pending());
        entered.as_mut().poll(cx)
    })
    .await;
    transaction(&f, |t| t.write(stage, 0, b"NEWER!").map(|_| ()));
    f.create("late", b"suffix");
    faults.resume();
    let lane = constructing.await.unwrap();
    let root = f
        .store
        .lock()
        .unwrap()
        .recovered_commit()
        .unwrap()
        .4
        .frozen
        .initial_root
        .clone();
    assert_eq!(
        (
            tree(&f, &root).get("n1/n0").cloned(),
            tree(&f, &root).contains_key("late")
        ),
        (Some(Some(b"live".to_vec())), false)
    );
    Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(70),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(transaction(&f, |t| t.read_stage(stage, 0, 6)), b"NEWER!");
    let root = land(&f, 90).await;
    assert_eq!(
        tree(&f, &root).get("n1/n0"),
        Some(&Some(b"NEWER!".to_vec()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_scoped_refusal_is_eio_and_releases_every_reservation() {
    for published in [false, true] {
        let f = Fixture::new().await;
        let stage = history(&f, true).await;
        let initial = projected::reservations(&f);
        let attempts = f.remote.attempts.lock().unwrap().len();
        let records = transaction(&f, |t| Ok(t.summary().records));
        let result = if published {
            f.engine
                .prepare_projected(
                    projected::seal(SyncTarget::Stage(stage)),
                    SyncOptions::default(),
                )
                .await
                .map(|_| ())
        } else {
            sync(&f, SyncTarget::Stage(stage)).await
        };
        assert_eq!(
            (
                matches!(
                    result,
                    Err(CoordinationError::Refused("SyncSelectionUnrepresentable"))
                ),
                result.as_ref().err().map(crate::sync_mount_error),
                projected::reservations(&f),
                projected::lane_closed(&f),
                f.remote.attempts.lock().unwrap().len(),
                transaction(&f, |t| Ok(t.summary().records))
            ),
            (
                true,
                Some(granary_fuse::MountSyncError::Backend(
                    granary_fuse::MountError::Io
                )),
                initial,
                false,
                attempts,
                records
            ),
            "published={published}: {result:?}"
        );
        land(&f, 60).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_rebuilds_parents_of_excluded_deletions() {
    let f = Fixture::new().await;
    record(
        &f,
        Record::Create {
            at: loc("d"),
            kind: codec::CreateKind::Dir,
        },
    );
    f.create("s", b"base");
    land(&f, 40).await;
    let dead = f.create("d/p", b"dead");
    delete(&f, "d/p", Some(dead));
    record(
        &f,
        Record::Delete {
            at: loc("d"),
            kind: codec::DeleteKind::Dir,
        },
    );
    let root = land(&f, 60).await;
    assert_eq!(
        tree(&f, &root),
        BTreeMap::from([("s".into(), Some(b"base".to_vec()))])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::too_many_lines,
    reason = "each model round checks bytes, namespace, exec bits, landing and reopen together"
)]
async fn complete_snapshot_rename_model_rounds() {
    use granary_core::rng::{Rng as _, SeededRng};
    let mut motions = 0;
    for seed in 0..8 {
        let mut rng = SeededRng::new(seed);
        let mut f = Fixture::new().await;
        let mut model = BTreeMap::from([("d".to_owned(), None), ("e".to_owned(), None)]);
        let mut executable = BTreeMap::new();
        for path in ["d", "e"] {
            record(
                &f,
                Record::Create {
                    at: loc(path),
                    kind: codec::CreateKind::Dir,
                },
            );
        }
        for round in 0..3 {
            let forced = format!("poison{round}");
            poison(&f, &forced);
            executable.insert(forced.clone(), false);
            model.insert(forced, Some(b"live".to_vec()));
            for step in 0..16 {
                let prefixes = ["", "d/", "e/"];
                let from = format!(
                    "{}f{}",
                    prefixes[usize::try_from(rng.below(3)).unwrap()],
                    rng.below(6)
                );
                let to = format!(
                    "{}f{}",
                    prefixes[usize::try_from(rng.below(3)).unwrap()],
                    rng.below(6)
                );
                if from == to {
                    continue;
                }
                if let Some(bytes) = model.remove(&from) {
                    let record = if model.contains_key(&to) {
                        Record::Replace {
                            from: loc(&from),
                            to: loc(&to),
                        }
                    } else {
                        Record::Move {
                            from: loc(&from),
                            to: loc(&to),
                        }
                    };
                    self::record(&f, record);
                    let exec = executable.remove(&from).unwrap();
                    executable.insert(to.clone(), exec);
                    model.insert(to, bytes);
                    motions += 1;
                } else {
                    let bytes = format!("{seed}/{round}/{step}").into_bytes();
                    f.create(&from, &bytes);
                    executable.insert(from.clone(), false);
                    model.insert(from, Some(bytes));
                }
            }
            for (from, to) in [("d", "turn"), ("e", "d"), ("turn", "e")] {
                record(
                    &f,
                    Record::Move {
                        from: loc(from),
                        to: loc(to),
                    },
                );
                let prefix = format!("{from}/");
                let moved: Vec<_> = model
                    .keys()
                    .filter(|p| **p == from || p.starts_with(&prefix))
                    .cloned()
                    .collect();
                for old in moved {
                    let new = format!("{to}{}", old.strip_prefix(from).unwrap());
                    let bytes = model.remove(&old).unwrap();
                    if let Some(exec) = executable.remove(&old) {
                        executable.insert(new.clone(), exec);
                    }
                    model.insert(new, bytes);
                }
                motions += 1;
            }
            for (path, exec) in executable.iter_mut().take(2) {
                *exec = !*exec;
                record(
                    &f,
                    Record::SetattrExec {
                        at: loc(path),
                        exec: *exec,
                    },
                );
            }
            let root = land(&f, 40 + round * 40).await;
            assert_eq!(tree(&f, &root), model, "seed={seed} round={round}");
            let doc = granary_core::root::decode_root(&root).unwrap();
            let entries = crate::writable_store::capture::overlay_base_entries(
                f.content.as_ref(),
                doc.manifest_root,
                &|_, _| 0,
                &mut |_, _| Ok(()),
                &|| CoordinationError::Refused("test metadata"),
            )
            .unwrap();
            let actual_exec: BTreeMap<_, _> = entries
                .iter()
                .filter(|e| matches!(e.kind, OverlayKind::File { .. }))
                .map(|e| {
                    (
                        e.path
                            .iter()
                            .map(|n| String::from_utf8_lossy(n.as_bytes()))
                            .collect::<Vec<_>>()
                            .join("/"),
                        e.exec,
                    )
                })
                .collect();
            assert_eq!(
                actual_exec, executable,
                "seed={seed} round={round}: exec bits"
            );
            f = f.restart_at_head().await;
        }
    }
    assert!(motions > 100, "admitted motions={motions}");
    println!("24 landed/reopened model rounds; {motions} admitted motions");
}

async fn rename_family(variant: &str) {
    let f = Fixture::new().await;
    f.create("s", b"base s");
    f.create("f", b"base f");
    record(
        &f,
        Record::Create {
            at: loc("d"),
            kind: codec::CreateKind::Dir,
        },
    );
    land(&f, 40).await;
    let mut expected = tree(&f, &f.remote.authority.lock().unwrap().root.clone());
    if variant == "extra f" {
        f.create("u", b"unsynced");
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
        f.create("x", b"selected");
        expected.remove("s");
        expected.remove("f");
        expected.insert("g".into(), Some(b"base s".to_vec()));
        expected.insert("x".into(), Some(b"selected".to_vec()));
    } else {
        f.create("p", b"W");
        record(
            &f,
            Record::Move {
                from: loc("p"),
                to: loc("q"),
            },
        );
        let dead = f.create("p", b"X");
        delete(&f, "p", Some(dead));
        expected.insert("q".into(), Some(b"W".to_vec()));
        match variant {
            "directory" => {
                record(
                    &f,
                    Record::Create {
                        at: loc("p"),
                        kind: codec::CreateKind::Dir,
                    },
                );
                expected.insert("p".into(), None);
            }
            "durable move" => {
                record(
                    &f,
                    Record::Move {
                        from: loc("s"),
                        to: loc("p"),
                    },
                );
                expected.remove("s");
                expected.insert("p".into(), Some(b"base s".to_vec()));
            }
            "new file" => {
                f.create("p", b"Y");
                expected.insert("p".into(), Some(b"Y".to_vec()));
            }
            _ => {
                record(
                    &f,
                    Record::Delete {
                        at: loc("d"),
                        kind: codec::DeleteKind::Dir,
                    },
                );
                expected.remove("d");
            }
        }
    }
    let root = land(&f, 60).await;
    assert_eq!(tree(&f, &root), expected, "variant={variant}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_family_directory() {
    rename_family("directory").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_family_durable_move() {
    rename_family("durable move").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_family_new_file() {
    rename_family("new file").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_family_rmdir() {
    rename_family("rmdir").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_family_extra_f() {
    rename_family("extra f").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_snapshot_tree_target_keeps_scoped_lanes_projected() {
    for lane in ["published", "projected", "durable"] {
        let f = Fixture::new().await;
        f.create("s", b"base");
        land(&f, 40).await;
        poison(&f, "x");
        let before = f.remote.published.lock().unwrap().clone();
        let initial = projected::reservations(&f);
        let result = match lane {
            "durable" => sync(&f, SyncTarget::Tree).await,
            "projected" => f
                .engine
                .prepare_projected(projected::seal(SyncTarget::Tree), SyncOptions::default())
                .await
                .map(|_| ()),
            _ => {
                f.engine
                    .publish_sync(SyncTarget::Tree, SyncOptions::default(), Entropy(70))
                    .wait()
                    .await
            }
        };
        assert_eq!(
            (
                matches!(
                    result,
                    Err(CoordinationError::Refused("SyncSelectionUnrepresentable")
                        | CoordinationError::Overlay(OverlayError::CaptureCoverageLost))
                ),
                f.remote.published.lock().unwrap().clone(),
                projected::reservations(&f),
                projected::lane_closed(&f),
            ),
            (true, before, initial, false),
            "{lane}: {result:?}"
        );
        land(&f, 90).await;
    }
}
