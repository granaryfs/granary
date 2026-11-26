// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Real admitted-backend planning work, measured outside fixture setup.
// @file-disposition: STAYS — query-work and cache-lifecycle controls share the admitted backend fixture and its observation invariant.

use super::*;
use granary_core::manifest::Name;
use granary_fuse::{MountBackend as _, OverlayMutation as M, WriteError};
use granary_vfs::NodeKind;

pub(super) mod clean;

fn measured<T>(action: impl FnOnce() -> T) -> (T, usize, usize) {
    let (answer, (copies, visits, _)) = crate::overlay_store::measure_query(action);
    (answer, copies, visits)
}

#[test]
fn writable_backend_planning_never_requests_a_whole_namespace() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let cardinality = backend.overlay_nodes().unwrap().len();
    assert_eq!(cardinality, 6, "namespace cardinality: {cardinality}");
    let file = handler_path(b"f.txt");
    let missing = handler_path(b"missing");
    let (opened, copies, visits) = measured(|| backend.overlay_open(&file));
    let object = opened.unwrap().unwrap();
    let mut rows = vec![("open", (true, copies, visits))];
    let (answer, copies, visits) = measured(|| backend.prepare_overlay(&file));
    rows.push(("prepare_path", (answer == Ok(()), copies, visits)));
    let (answer, copies, visits) = measured(|| backend.prepare_object(object));
    rows.push(("prepare_object", (answer == Ok(()), copies, visits)));
    let (answer, copies, visits) = measured(|| backend.overlay_object(object));
    rows.push(("object", (answer.unwrap().path == file, copies, visits)));
    let (answer, copies, visits) = measured(|| backend.read_object(object, 0, 65536));
    rows.push((
        "read",
        (answer == Ok(FILE_CONTENT.to_vec()), copies, visits),
    ));
    let (answer, copies, visits) = measured(|| backend.read_object(object, u64::MAX, 1));
    rows.push(("read_eof", (answer == Ok(Vec::new()), copies, visits)));
    let (answer, copies, visits) = measured(|| backend.prepare_detach(&file));
    rows.push(("prepare_detach", (answer == Ok(()), copies, visits)));
    let (answer, copies, visits) = measured(|| backend.overlay_open(&missing));
    rows.push((
        "missing_open",
        (answer == Err(WriteError::Missing), copies, visits),
    ));
    let (answer, copies, visits) = measured(|| backend.prepare_overlay(&missing));
    rows.push((
        "missing_prepare",
        (answer == Err(WriteError::Missing), copies, visits),
    ));
    let (answer, copies, visits) = measured(|| backend.prepare_detach(&missing));
    rows.push(("missing_detach", (answer == Ok(()), copies, visits)));
    let expected: Vec<_> = rows.iter().map(|(name, _)| (*name, (true, 0, 0))).collect();
    assert_eq!(
        (rows.len(), &rows),
        (10, &expected),
        "answers and query work"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "operation and refusal cases share one admitted namespace and per-case query counts"
)]
fn writable_mutation_preflight_uses_only_involved_names() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let cardinality = backend.overlay_nodes().unwrap().len();
    assert_eq!(cardinality, 6, "namespace cardinality: {cardinality}");
    let file = handler_path(b"new-file");
    let moved = handler_path(b"moved-file");
    let link = handler_path(b"new-link");
    let directory = handler_path(b"new-directory");
    let target = granary_core::manifest::SymlinkTarget::new(b"f.txt".to_vec()).unwrap();
    let subdirectory = handler_path(b"sub");
    let operations = [
        (
            "create",
            M::Create {
                path: &file,
                kind: NodeKind::File,
                exec: false,
            },
            Ok(()),
        ),
        (
            "exists",
            M::Create {
                path: &file,
                kind: NodeKind::File,
                exec: false,
            },
            Err(WriteError::Exists),
        ),
        (
            "symlink",
            M::Symlink {
                path: &link,
                target: &target,
            },
            Ok(()),
        ),
        (
            "mkdir",
            M::Create {
                path: &directory,
                kind: NodeKind::Dir,
                exec: false,
            },
            Ok(()),
        ),
        (
            "write",
            M::Write {
                path: &file,
                offset: 0,
                bytes: b"data",
                append: false,
            },
            Ok(()),
        ),
        (
            "setattr",
            M::Setattr {
                path: &file,
                size: Some(7),
                exec: Some(true),
            },
            Ok(()),
        ),
        (
            "rename",
            M::Rename {
                from: &file,
                to: &moved,
                no_replace: false,
            },
            Ok(()),
        ),
        (
            "missing",
            M::Remove {
                path: &file,
                directory: false,
            },
            Err(WriteError::Missing),
        ),
        (
            "unlink",
            M::Remove {
                path: &moved,
                directory: false,
            },
            Ok(()),
        ),
        (
            "unlink_symlink",
            M::Remove {
                path: &link,
                directory: false,
            },
            Ok(()),
        ),
        (
            "rmdir",
            M::Remove {
                path: &directory,
                directory: true,
            },
            Ok(()),
        ),
        (
            "nonempty",
            M::Remove {
                path: &subdirectory,
                directory: true,
            },
            Err(WriteError::NotEmpty),
        ),
    ];
    let mut rows = Vec::new();
    for (name, operation, expected) in operations {
        let (answer, copies, _) = measured(|| backend.overlay_mutate(operation));
        rows.push((name, (answer, copies), (expected, 0)));
    }
    assert_eq!(rows.len(), 12, "preflight case count: {}", rows.len());
    let actual: Vec<_> = rows
        .iter()
        .map(|(name, actual, _)| (*name, actual))
        .collect();
    let expected: Vec<_> = rows
        .iter()
        .map(|(name, _, expected)| (*name, expected))
        .collect();
    assert_eq!(
        actual, expected,
        "mutation answers and whole-namespace query copies"
    );
}

#[test]
fn writable_object_refresh_copies_only_the_addressed_held_entry() {
    let mut cases = 0;
    for held_count in [1, 17] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let backend = ready.backend_for_test();
        let mut objects = Vec::new();
        for number in 0..held_count {
            let path = handler_path(format!("held-{number:02}").as_bytes());
            backend
                .overlay_mutate(M::Create {
                    path: &path,
                    kind: NodeKind::File,
                    exec: false,
                })
                .unwrap();
            objects.push(backend.overlay_open(&path).unwrap().unwrap());
        }
        let cardinality = backend.overlay_nodes().unwrap().len();
        assert_eq!(
            cardinality,
            held_count + 6,
            "namespace cardinality: {cardinality}"
        );
        let object = *objects.last().unwrap();
        let expected = handler_path(format!("held-{:02}", held_count - 1).as_bytes());
        let (answer, work) = crate::overlay_store::measure_query(|| backend.overlay_object(object));
        assert_eq!(
            (answer.unwrap().path, work),
            (expected, (0, 0, 1)),
            "held objects: {held_count}"
        );
        for object in objects {
            backend.overlay_close(object).unwrap();
        }
        cases += 1;
    }
    assert_eq!(cases, 2, "nonempty held-object cases: {cases}");
}

fn query_paths() -> Paths {
    let base = runtime_workspace_scratch().unwrap();
    std::fs::create_dir_all(&base).unwrap();
    Paths::with_store_base(&base)
}

// Counting only mutation dispatch misses the current and final attribute copies.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "each N/H fixture measures the complete bound setter query sequence and shared identity"
)]
fn writable_bound_setter_sequence_copies_at_most_two_entries() {
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for unrelated in [0, 64] {
        for held_count in [1, 17] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let mut objects = Vec::new();
            for number in 0..16 {
                let path = handler_path(format!("held-{number:02}").as_bytes());
                backend
                    .overlay_mutate(M::Create {
                        path: &path,
                        kind: NodeKind::File,
                        exec: false,
                    })
                    .unwrap();
                if held_count == 17 {
                    objects.push(backend.overlay_open(&path).unwrap().unwrap());
                }
            }
            let file = handler_path(b"f.txt");
            let object = backend.overlay_open(&file).unwrap().unwrap();
            let shared = backend.overlay_open(&file).unwrap().unwrap();
            objects.push(object);
            let cardinality = backend.overlay_nodes().unwrap().len();
            let distinct = objects
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            assert_eq!(
                (cardinality, objects.len(), distinct, shared),
                (unrelated + 22, held_count, held_count, object),
                "actual namespace/held/shared identities: {cardinality}/{objects:?}/{shared}"
            );
            for (site, size, exec, wanted) in [
                ("clean_size", Some(8), None, (8, false)),
                ("staged_size", Some(9), None, (9, false)),
                ("exec", None, Some(true), (9, true)),
                ("size_exec", Some(7), Some(false), (7, false)),
            ] {
                let (answer, query, storage) = crate::overlay_store::work::measure(|| {
                    let current = backend.overlay_path(&file)?;
                    if current.node.kind != NodeKind::File {
                        return Err(WriteError::IsDirectory);
                    }
                    if size.is_some() {
                        backend.prepare_object(object)?;
                    }
                    backend.overlay_mutate(M::BoundSetattr { object, size, exec })?;
                    let final_attr = backend.overlay_path(&file)?;
                    Ok((final_attr.node.size, final_attr.node.exec, final_attr.nlink))
                });
                let work = (
                    query.namespace_copies,
                    query.primary_visits,
                    query.entry_copies,
                );
                observed.push((
                    site,
                    unrelated,
                    held_count,
                    answer,
                    work,
                    storage.namespace_clones > 0,
                ));
                expected.push((
                    site,
                    unrelated,
                    held_count,
                    Ok((wanted.0, wanted.1, 1)),
                    (0, 0, 2),
                    true,
                ));
                eprintln!(
                    "bound setter {site}: namespace_entries={cardinality}, held_objects={held_count}, query_work={work:?}, storage_clones={}",
                    storage.namespace_clones
                );
            }
            assert_eq!(
                (
                    backend.overlay_object(shared).map(|n| (n.size, n.exec)),
                    backend.read_object(shared, 0, 65536)
                ),
                (Ok((7, false)), Ok(FILE_CONTENT[..7].to_vec())),
                "final setter attributes and bytes follow the shared identity"
            );
            backend.overlay_close(shared).unwrap();
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
        }
    }
    assert_eq!(
        (observed.len(), observed),
        (16, expected),
        "complete bound setter answers and work"
    );
}

#[test]
fn writable_unbound_setter_sequence_copies_at_most_two_entries() {
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for unrelated in [0, 64] {
        for held_count in [1, 17] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let mut objects = Vec::new();
            for number in 0..16 {
                let path = handler_path(format!("held-{number:02}").as_bytes());
                backend
                    .overlay_mutate(M::Create {
                        path: &path,
                        kind: NodeKind::File,
                        exec: false,
                    })
                    .unwrap();
                if held_count == 17 {
                    objects.push(backend.overlay_open(&path).unwrap().unwrap());
                }
            }
            let file = handler_path(b"f.txt");
            let object = backend.overlay_open(&file).unwrap().unwrap();
            let shared = backend.overlay_open(&file).unwrap().unwrap();
            objects.push(object);
            let cardinality = backend.overlay_nodes().unwrap().len();
            let distinct = objects
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            assert_eq!(
                (cardinality, objects.len(), distinct, shared),
                (unrelated + 22, held_count, held_count, object),
                "actual namespace/held/shared identities: {cardinality}/{objects:?}/{shared}"
            );
            for (site, size, exec, wanted) in [
                ("clean_size", Some(8), None, (8, false)),
                ("staged_size", Some(9), None, (9, false)),
                ("exec", None, Some(true), (9, true)),
                ("size_exec", Some(7), Some(false), (7, false)),
            ] {
                let (answer, query, storage) = crate::overlay_store::work::measure(|| {
                    let current = backend.overlay_path(&file)?;
                    if current.node.kind != NodeKind::File {
                        return Err(WriteError::IsDirectory);
                    }
                    let final_attr = backend.overlay_setattr(&file, size, exec)?;
                    Ok((final_attr.node.size, final_attr.node.exec, final_attr.nlink))
                });
                let work = (
                    query.namespace_copies,
                    query.primary_visits,
                    query.entry_copies,
                );
                observed.push((
                    site,
                    unrelated,
                    held_count,
                    answer,
                    work,
                    storage.namespace_clones > 0,
                ));
                expected.push((
                    site,
                    unrelated,
                    held_count,
                    Ok((wanted.0, wanted.1, 1)),
                    (0, 0, 2),
                    true,
                ));
                eprintln!(
                    "unbound setter {site}: namespace_entries={cardinality}, held_objects={held_count}, query_work={work:?}, storage_clones={}",
                    storage.namespace_clones
                );
            }
            assert_eq!(
                (
                    backend.overlay_object(shared).map(|n| (n.size, n.exec)),
                    backend.read_object(shared, 0, 65536)
                ),
                (Ok((7, false)), Ok(FILE_CONTENT[..7].to_vec())),
                "final setter attributes and bytes follow the shared identity"
            );
            backend.overlay_close(shared).unwrap();
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
        }
    }
    assert_eq!(
        (observed.len(), observed),
        (16, expected),
        "complete unbound setter answers and work"
    );
}

// Re-reading a changed plan during dispatch copies an entry already owned by preparation.
#[test]
fn writable_bound_setter_churn_keeps_the_latest_prepared_entry() {
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for unrelated in [0, 64] {
        for changes in [0, 1, 2, 3] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let file = handler_path(b"f.txt");
            let object = backend.overlay_open(&file).unwrap().unwrap();
            let cardinality = backend.overlay_nodes().unwrap().len();
            assert_eq!(
                cardinality,
                unrelated + 6,
                "actual admitted entries: {cardinality}"
            );
            backend.planning_changes_remaining = changes;
            let (answer, work) = crate::overlay_store::measure_query(|| {
                backend.overlay_path(&file)?;
                backend.prepare_object(object)?;
                backend.overlay_mutate(M::BoundSetattr {
                    object,
                    size: Some(8),
                    exec: None,
                })?;
                let final_attr = backend.overlay_path(&file)?;
                Ok((final_attr.node.size, final_attr.node.exec))
            });
            let exhausted = changes == 3;
            let wanted = if exhausted {
                Err(WriteError::Backend(
                    granary_fuse::MountError::PlanningExhausted,
                ))
            } else {
                Ok((8, changes % 2 != 0))
            };
            // Initial and final attributes copy once; each changed attempt owns
            // one replacement entry. Exhaustion does not query final attributes.
            let copies = if exhausted { 4 } else { 2 + changes };
            observed.push((unrelated, changes, answer, work, backend.planning_attempts));
            expected.push((
                unrelated,
                changes,
                wanted,
                (0, 0, copies),
                (changes + 1).min(3),
            ));
            let current = backend.overlay_path(&file).unwrap().node;
            assert_eq!(
                (current.size, current.exec, current.stage.is_some()),
                (
                    if exhausted {
                        FILE_CONTENT.len() as u64
                    } else {
                        8
                    },
                    changes % 2 != 0,
                    !exhausted
                ),
                "context churn must not poison or mutate the file on exhaustion, actual={current:?}"
            );
            eprintln!(
                "bound setter churn: namespace_entries={cardinality}, changes={changes}, attempts={}, query_work={work:?}",
                backend.planning_attempts
            );
            backend.overlay_close(object).unwrap();
        }
    }
    assert_eq!(
        (observed.len(), observed),
        (8, expected),
        "bound setter context-attempt answers and aggregate work"
    );
}

#[test]
fn writable_unlinked_objects_stay_detached_across_name_recreation() {
    let mut cases = 0;
    for dirty in [false, true] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        let mut expected = FILE_CONTENT.to_vec();
        if dirty {
            backend
                .overlay_mutate(M::BoundSetattr {
                    object,
                    size: Some(0),
                    exec: None,
                })
                .unwrap();
            backend
                .overlay_mutate(M::BoundWrite {
                    object,
                    offset: 0,
                    bytes: b"held",
                    append: false,
                })
                .unwrap();
            expected = b"held".to_vec();
        }
        backend.prepare_detach(&file).unwrap();
        backend
            .overlay_mutate(M::Remove {
                path: &file,
                directory: false,
            })
            .unwrap();
        let detached = backend.overlay_object(object).unwrap();
        let stage = detached.stage;
        assert_eq!(
            (
                backend.object_attached_for_test(object),
                backend.overlay_path(&file),
                backend.read_object(object, 0, 65536)
            ),
            (Some(false), Err(WriteError::Missing), Ok(expected.clone())),
            "unlink must detach identity and remove the old name, dirty={dirty}"
        );
        backend
            .overlay_mutate(M::Create {
                path: &file,
                kind: NodeKind::File,
                exec: false,
            })
            .unwrap();
        let replacement = backend.overlay_open(&file).unwrap().unwrap();
        backend
            .overlay_mutate(M::BoundWrite {
                object: replacement,
                offset: 0,
                bytes: b"replacement",
                append: false,
            })
            .unwrap();
        backend
            .overlay_mutate(M::BoundWrite {
                object,
                offset: 0,
                bytes: b"!",
                append: true,
            })
            .unwrap();
        expected.push(b'!');
        let held = backend.overlay_object(object).unwrap();
        assert_eq!(
            (
                backend.object_attached_for_test(object),
                replacement != object,
                held.stage == stage,
                backend.read_object(object, 0, 65536),
                backend.read_object(replacement, 0, 65536)
            ),
            (
                Some(false),
                true,
                true,
                Ok(expected),
                Ok(b"replacement".to_vec())
            ),
            "a held object must never reattach or retarget, dirty={dirty}"
        );
        backend.overlay_close(object).unwrap();
        backend.overlay_close(replacement).unwrap();
        cases += 1;
    }
    assert_eq!(cases, 2, "clean and dirty detach cases: {cases}");
}

#[test]
fn writable_mutation_preflight_preserves_parent_refusal_order() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let absent = handler_path(b"absent");
    let bad_parent = vec![
        Name::new(b"f.txt".to_vec()).unwrap(),
        Name::new(b"child".to_vec()).unwrap(),
    ];
    let absent_parent = vec![
        Name::new(b"absent".to_vec()).unwrap(),
        Name::new(b"child".to_vec()).unwrap(),
    ];
    let operations = [
        (
            M::Create {
                path: &absent_parent,
                kind: NodeKind::File,
                exec: false,
            },
            WriteError::Missing,
        ),
        (
            M::Create {
                path: &bad_parent,
                kind: NodeKind::File,
                exec: false,
            },
            WriteError::NotDirectory,
        ),
        (
            M::Rename {
                from: &absent,
                to: &bad_parent,
                no_replace: false,
            },
            WriteError::NotDirectory,
        ),
        (
            M::Remove {
                path: &absent_parent,
                directory: true,
            },
            WriteError::Missing,
        ),
    ];
    let before = backend.overlay_nodes().unwrap();
    let mut cases = 0;
    for (operation, expected) in operations {
        assert_eq!(backend.overlay_mutate(operation), Err(expected));
        cases += 1;
    }
    assert_eq!((cases, backend.overlay_nodes().unwrap()), (4, before));
}

fn query_tree(paths: &Paths) -> PublishedTree {
    query_tree_with_unrelated(paths, 0)
}

fn query_tree_with_unrelated(paths: &Paths, unrelated: usize) -> PublishedTree {
    query_tree_with_children(paths, unrelated, 0)
}

fn query_tree_with_children(paths: &Paths, unrelated: usize, children: usize) -> PublishedTree {
    // Harvest needs stable native-filesystem metadata even when the workspace is shared.
    let scratch = ScratchDir::new();
    let source = scratch.0.join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(source.join("sub")).unwrap();
    std::fs::create_dir(source.join("empty")).unwrap();
    std::fs::write(source.join("f.txt"), FILE_CONTENT).unwrap();
    std::fs::write(source.join("sub/g.txt"), FILE_CONTENT).unwrap();
    std::os::unix::fs::symlink("f.txt", source.join("original-link")).unwrap();
    for number in 0..unrelated {
        std::fs::write(source.join(format!("unrelated-{number:04}")), b"unrelated").unwrap();
    }
    for number in 0..children {
        let path = source.join("sub").join(format!("child-{number:04}"));
        if number % 64 == 0 {
            std::fs::create_dir(path).unwrap();
        } else {
            std::fs::write(path, FILE_CONTENT).unwrap();
        }
    }
    let mem = Arc::new(InMemory::new());
    let remote = GranaryStore::new(mem.clone());
    let (key, seed) = SigningKey::generate().unwrap();
    let volume = vol("v");
    let store = Store::open(&paths.scratch.join("publication")).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let summary = rt
        .block_on(publish(
            &remote,
            &store,
            &source,
            &volume,
            &key,
            &WriterIdentity::from_bytes(*b"mount-writer-id!"),
            stamp(),
            Policy::default(),
        ))
        .unwrap();
    let (outcome, collected) = rt
        .block_on(crate::resolve::resolve_at_collecting(
            &remote,
            volume.as_str(),
            1,
        ))
        .unwrap();
    let file_id = *collected
        .iter()
        .find_map(|(id, bytes)| (bytes.as_slice() == FILE_CONTENT).then_some(id))
        .unwrap();
    assert_eq!(summary.seq, 1, "published sequence: {}", summary.seq);
    PublishedTree {
        seq: summary.seq,
        seed,
        remote,
        mem,
        key,
        volume,
        file_id,
        manifest_root: outcome.doc.manifest_root,
        binmap_index: outcome.doc.binmap_index,
        sheaf_head: outcome.doc.sheaf_head,
    }
}

#[test]
fn writable_staged_read_preparation_and_dispatch_copy_at_most_two_entries() {
    let mut cases = 0;
    for unrelated in [0, 64] {
        for held_count in [1, 17] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let mut objects = Vec::new();
            for number in 0..17 {
                let path = handler_path(format!("held-{number:02}").as_bytes());
                backend
                    .overlay_mutate(M::Create {
                        path: &path,
                        kind: NodeKind::File,
                        exec: false,
                    })
                    .unwrap();
                if number < 17 - held_count {
                    continue;
                }
                let object = backend.overlay_open(&path).unwrap().unwrap();
                backend
                    .overlay_mutate(M::BoundWrite {
                        object,
                        offset: 0,
                        bytes: b"live",
                        append: false,
                    })
                    .unwrap();
                objects.push(object);
            }
            let cardinality = backend.overlay_nodes().unwrap().len();
            assert_eq!(
                cardinality,
                unrelated + 23,
                "admitted fixture cardinality: {cardinality}"
            );
            let distinct = objects
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            assert_eq!(
                (objects.len(), distinct),
                (held_count, held_count),
                "actual held objects: {objects:?}"
            );
            let object = *objects.last().unwrap();
            let (answer, work) = crate::overlay_store::measure_query(|| {
                backend.prepare_object(object)?;
                backend.read_object(object, 0, 65536)
            });
            assert_eq!(
                (answer, work),
                (Ok(b"live".to_vec()), (0, 0, 1)),
                "staged READ preparation plus dispatch, unrelated={unrelated}, held={held_count}"
            );
            eprintln!(
                "staged READ: namespace_entries={cardinality}, held_objects={held_count}, query_work={work:?}"
            );
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 4, "independent N/H staged read cases: {cases}");
}

#[test]
fn writable_staged_preparation_rechecks_readiness_after_success() {
    let mut cases = 0;
    for detached in [false, true] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let path = handler_path(b"held");
        let backend = ready.backend_for_test();
        backend
            .overlay_mutate(M::Create {
                path: &path,
                kind: NodeKind::File,
                exec: false,
            })
            .unwrap();
        let object = backend.overlay_open(&path).unwrap().unwrap();
        backend
            .overlay_mutate(M::BoundWrite {
                object,
                offset: 0,
                bytes: b"held",
                append: false,
            })
            .unwrap();
        if detached {
            backend
                .overlay_mutate(M::Remove {
                    path: &path,
                    directory: false,
                })
                .unwrap();
        }
        assert_eq!(
            (
                backend.prepare_object(object),
                backend.read_object(object, 0, 65536),
                backend.object_attached_for_test(object)
            ),
            (Ok(()), Ok(b"held".to_vec()), Some(!detached)),
            "nonempty staged preparation control, detached={detached}"
        );
        ready
            .mediator_for_test()
            .phase_for_test(granary_core::overlay_ownership::Phase::Releasing)
            .unwrap();
        let backend = ready.backend_for_test();
        assert_eq!(
            (
                backend.prepare_object(object),
                backend.read_object(object, 0, 65536)
            ),
            (
                Err(WriteError::Backend(granary_fuse::MountError::Access)),
                Err(WriteError::Backend(granary_fuse::MountError::Access))
            ),
            "a previously successful stage is not a readiness grant, detached={detached}"
        );
        cases += 1;
    }
    assert_eq!(
        cases, 2,
        "attached and detached readiness controls: {cases}"
    );
}

#[test]
fn writable_clean_read_preparation_and_dispatch_copy_at_most_two_entries() {
    let mut cases = 0;
    for unrelated in [0, 64] {
        for held_count in [1, 17] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let mut objects = Vec::new();
            for number in 0..16 {
                let path = handler_path(format!("held-{number:02}").as_bytes());
                backend
                    .overlay_mutate(M::Create {
                        path: &path,
                        kind: NodeKind::File,
                        exec: false,
                    })
                    .unwrap();
                if held_count == 17 {
                    objects.push(backend.overlay_open(&path).unwrap().unwrap());
                }
            }
            let object = backend
                .overlay_open(&handler_path(b"f.txt"))
                .unwrap()
                .unwrap();
            objects.push(object);
            let cardinality = backend.overlay_nodes().unwrap().len();
            let distinct = objects
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            assert_eq!(
                (cardinality, objects.len(), distinct),
                (unrelated + 22, held_count, held_count),
                "actual admitted entries/held identities: {cardinality}/{objects:?}"
            );
            for repeated in [false, true] {
                let (answer, work) = crate::overlay_store::measure_query(|| {
                    backend.prepare_object(object)?;
                    backend.read_object(object, 0, 65536)
                });
                assert_eq!(
                    (answer, work),
                    (Ok(FILE_CONTENT.to_vec()), (0, 0, 1)),
                    "clean READ preparation plus dispatch, unrelated={unrelated}, held={held_count}, repeated={repeated}"
                );
                eprintln!(
                    "clean READ: namespace_entries={cardinality}, held_objects={held_count}, repeated={repeated}, query_work={work:?}"
                );
                cases += 1;
            }
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
        }
    }
    assert_eq!(
        cases, 8,
        "nonempty independent N/H clean READ cases: {cases}"
    );
}

#[test]
fn writable_clean_preparation_failure_retains_the_held_object() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let object = backend.overlay_open(&file).unwrap().unwrap();
    assert_eq!(
        (
            backend.overlay_nodes().unwrap().len(),
            backend.prepare_object(object),
            backend.read_object(object, 0, 65536)
        ),
        (6, Ok(()), Ok(FILE_CONTENT.to_vec())),
        "nonempty clean-held control"
    );
    backend.planning_replace = true;
    let answer = backend.prepare_object(object);
    let held = backend
        .overlay_object(object)
        .map(|held| (held.path, held.size));
    assert_eq!(
        (
            answer,
            backend.object_attached_for_test(object),
            held,
            backend.overlay_close(object)
        ),
        (
            Err(WriteError::Missing),
            Some(false),
            Ok((file, FILE_CONTENT.len() as u64)),
            Ok(())
        ),
        "failed revalidation must restore the held identity and its releasable hold"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "each admitted N/H fixture shares four mutation counts and one shared-handle byte witness"
)]
fn writable_bound_mutation_preparation_and_dispatch_copy_at_most_two_entries() {
    let mut cases = 0;
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for unrelated in [0, 64] {
        for held_count in [1, 17] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let mut objects = Vec::new();
            for number in 0..16 {
                let path = handler_path(format!("held-{number:02}").as_bytes());
                backend
                    .overlay_mutate(M::Create {
                        path: &path,
                        kind: NodeKind::File,
                        exec: false,
                    })
                    .unwrap();
                if held_count == 17 {
                    objects.push(backend.overlay_open(&path).unwrap().unwrap());
                }
            }
            let file = handler_path(b"f.txt");
            let object = backend.overlay_open(&file).unwrap().unwrap();
            let shared = backend.overlay_open(&file).unwrap().unwrap();
            objects.push(object);
            let cardinality = backend.overlay_nodes().unwrap().len();
            let distinct = objects
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            assert_eq!(
                (cardinality, objects.len(), distinct, shared),
                (unrelated + 22, held_count, held_count, object),
                "actual namespace/held/shared identities: {cardinality}/{objects:?}/{shared}"
            );
            for site in ["clean_write", "staged_write", "size", "exec"] {
                let (answer, query, storage) = crate::overlay_store::work::measure(|| {
                    if site != "exec" {
                        backend.prepare_object(object)?;
                    }
                    let operation = match site {
                        "clean_write" | "staged_write" => M::BoundWrite {
                            object,
                            offset: 0,
                            bytes: b"live",
                            append: false,
                        },
                        "size" => M::BoundSetattr {
                            object,
                            size: Some(8),
                            exec: None,
                        },
                        "exec" => M::BoundSetattr {
                            object,
                            size: None,
                            exec: Some(true),
                        },
                        _ => unreachable!(),
                    };
                    backend.overlay_mutate(operation)
                });
                let work = (
                    query.namespace_copies,
                    query.primary_visits,
                    query.entry_copies,
                );
                observed.push((
                    site,
                    unrelated,
                    held_count,
                    (answer, work, storage.namespace_clones > 0),
                ));
                expected.push((site, unrelated, held_count, (Ok(()), (0, 0, 0), true)));
                eprintln!(
                    "bound {site}: namespace_entries={cardinality}, held_objects={held_count}, query_work={work:?}, storage_clones={}",
                    storage.namespace_clones
                );
                cases += 1;
            }
            assert_eq!(
                (
                    backend.overlay_object(object).map(|n| (n.size, n.exec)),
                    backend.read_object(shared, 0, 65536)
                ),
                (Ok((8, true)), Ok(b"livet te".to_vec())),
                "bound effects and shared-handle identity"
            );
            backend.overlay_close(shared).unwrap();
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
        }
    }
    assert_eq!(
        (cases, observed),
        (16, expected),
        "bound answers and independent N/H query/storage work"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one held identity spans rename, detach, refused size change, recreation and exact hold release"
)]
fn writable_bound_refresh_follows_rename_and_refuses_detached_exec_before_size() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let file = handler_path(b"f.txt");
    let moved = handler_path(b"moved");
    let backend = ready.backend_for_test();
    let object = backend.overlay_open(&file).unwrap().unwrap();
    let shared = backend.overlay_open(&file).unwrap().unwrap();
    assert_eq!(
        (backend.overlay_nodes().unwrap().len(), object),
        (6, shared),
        "admitted entries and shared identity"
    );
    backend.prepare_object(object).unwrap();
    backend
        .overlay_mutate(M::Rename {
            from: &file,
            to: &moved,
            no_replace: false,
        })
        .unwrap();
    let write = backend.overlay_mutate(M::BoundWrite {
        object,
        offset: 0,
        bytes: b"Q",
        append: false,
    });
    let mut bytes = FILE_CONTENT.to_vec();
    *bytes.first_mut().unwrap() = b'Q';
    assert_eq!(
        (
            write,
            backend.overlay_path(&file),
            backend.read_object(shared, 0, 65536)
        ),
        (Ok(()), Err(WriteError::Missing), Ok(bytes.clone())),
        "bound write must refresh a renamed identity before path planning"
    );
    let stage = backend.overlay_object(object).unwrap().stage.unwrap();
    backend
        .overlay_mutate(M::Remove {
            path: &moved,
            directory: false,
        })
        .unwrap();
    backend
        .overlay_mutate(M::Create {
            path: &moved,
            kind: NodeKind::File,
            exec: false,
        })
        .unwrap();
    let before = captured_records(&paths, &input).1;
    let answer = ready.backend_for_test().overlay_mutate(M::BoundSetattr {
        object,
        size: Some(1),
        exec: Some(true),
    });
    let after = captured_records(&paths, &input).1;
    let backend = ready.backend_for_test();
    assert_eq!(
        (
            answer,
            backend.object_attached_for_test(object),
            backend
                .overlay_path(&moved)
                .map(|m| (m.node.size, m.node.exec)),
            backend.read_object(shared, 0, 65536),
            after == before
        ),
        (
            Err(WriteError::Unsupported),
            Some(false),
            Ok((0, false)),
            Ok(bytes.clone()),
            true
        ),
        "detached exec refusal must precede size and never retarget a recreated name"
    );
    backend
        .overlay_mutate(M::BoundWrite {
            object,
            offset: 0,
            bytes: b"!",
            append: true,
        })
        .unwrap();
    bytes.push(b'!');
    backend.overlay_close(object).unwrap();
    assert_eq!(
        (
            backend.object_attached_for_test(shared),
            backend.read_object(shared, 0, 65536),
            backend
                .overlay_path(&moved)
                .map(|m| (m.node.size, m.node.exec))
        ),
        (Some(false), Ok(bytes), Ok((0, false))),
        "one remaining exact stage hold survives orphan mutation and close"
    );
    backend.overlay_close(shared).unwrap();
    let released = ready
        .mediator_for_test()
        .overlay_transaction(|o| o.read_stage(stage, 0, 1));
    assert!(
        released.is_err(),
        "last exact hold must retire the orphan stage: {released:?}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "each nonempty attached or detached fixture shares the refusal and unchanged journal byte witnesses"
)]
fn writable_bound_mutation_refusals_leave_attached_and_detached_bytes_unchanged() {
    let mut cases = 0;
    let oversized = vec![b'x'; 8_388_609];
    for detached in [false, true] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let file = handler_path(b"f.txt");
        let backend = ready.backend_for_test();
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        let before_empty = captured_records(&paths, &input).1;
        let empty = backend.overlay_mutate(M::BoundWrite {
            object,
            offset: 0,
            bytes: b"",
            append: false,
        });
        assert_eq!(
            (
                empty,
                backend.overlay_object(object).map(|n| n.stage),
                captured_records(&paths, &input).1 == before_empty
            ),
            (Ok(()), Ok(None), true),
            "empty bound write must not create a stage or journal effect"
        );
        backend
            .overlay_mutate(M::BoundWrite {
                object,
                offset: 0,
                bytes: b"Q",
                append: false,
            })
            .unwrap();
        if detached {
            backend
                .overlay_mutate(M::Remove {
                    path: &file,
                    directory: false,
                })
                .unwrap();
        }
        let mut expected = FILE_CONTENT.to_vec();
        *expected.first_mut().unwrap() = b'Q';
        assert_eq!(
            (
                backend.overlay_nodes().unwrap().len(),
                backend.read_object(object, 0, 65536)
            ),
            (if detached { 5 } else { 6 }, Ok(expected.clone())),
            "nonempty attached/detached refusal control, detached={detached}"
        );
        let before = captured_records(&paths, &input).1;
        let operations = [
            (
                "extent",
                M::BoundWrite {
                    object,
                    offset: 0,
                    bytes: &oversized,
                    append: false,
                },
                WriteError::Invalid,
            ),
            (
                "overflow",
                M::BoundWrite {
                    object,
                    offset: u64::MAX,
                    bytes: b"Q",
                    append: false,
                },
                WriteError::Invalid,
            ),
            (
                "offset",
                M::BoundWrite {
                    object,
                    offset: 9_223_372_036_854_775_808,
                    bytes: b"",
                    append: false,
                },
                WriteError::TooBig,
            ),
            (
                "end",
                M::BoundWrite {
                    object,
                    offset: 9_223_372_036_854_775_807,
                    bytes: b"Q",
                    append: false,
                },
                WriteError::TooBig,
            ),
            (
                "size",
                M::BoundSetattr {
                    object,
                    size: Some(9_223_372_036_854_775_808),
                    exec: None,
                },
                WriteError::TooBig,
            ),
        ];
        for (site, operation, error) in operations {
            let answer = ready.backend_for_test().overlay_mutate(operation);
            let after = captured_records(&paths, &input).1;
            let backend = ready.backend_for_test();
            assert_eq!(
                (
                    answer,
                    after == before,
                    backend.read_object(object, 0, 65536),
                    backend.object_attached_for_test(object)
                ),
                (Err(error), true, Ok(expected.clone()), Some(!detached)),
                "bound refusal {site}, detached={detached}"
            );
            cases += 1;
        }
        ready.backend_for_test().overlay_close(object).unwrap();
    }
    assert_eq!(cases, 10, "nonempty bound refusal cases: {cases}");
}

#[test]
fn writable_unbound_setter_rechecks_final_readiness() {
    let mut cases = 0;
    for size in [None, Some(7)] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let cardinality = backend.overlay_nodes().unwrap().len();
        assert_eq!(cardinality, 6, "actual namespace entries: {cardinality}");
        let valid = backend.overlay_setattr(&file, size, Some(true));
        assert_eq!(
            valid.map(|m| (m.node.size, m.node.exec, m.nlink)),
            Ok((size.unwrap_or(FILE_CONTENT.len() as u64), true, 1)),
            "nonempty final-readiness control"
        );
        backend.setattr_release_after_effect = true;
        let refused = backend.overlay_setattr(&file, size, Some(false));
        assert_eq!(
            (refused, backend.mutation_readiness()),
            (
                Err(WriteError::Backend(granary_fuse::MountError::Access)),
                Err(granary_fuse::MountError::Access)
            ),
            "final setter revalidation must refuse after the owner starts releasing"
        );
        cases += 1;
    }
    assert_eq!(
        cases, 2,
        "nonempty exec/size final-readiness cases: {cases}"
    );
}

#[test]
fn writable_unbound_setter_without_handles_preserves_refusals_and_capture() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let file = handler_path(b"f.txt");
    let backend = ready.backend_for_test();
    let cardinality = backend.overlay_nodes().unwrap().len();
    assert_eq!(cardinality, 6, "actual namespace entries: {cardinality}");
    let mut cases = 0;
    for (size, exec, wanted) in [
        (Some(7), None, (7, false)),
        (None, Some(true), (7, true)),
        (Some(8), Some(false), (8, false)),
        (None, Some(false), (8, false)),
    ] {
        let (answer, query, _) = crate::overlay_store::work::measure(|| {
            backend.overlay_path(&file)?;
            backend.overlay_setattr(&file, size, exec)
        });
        assert_eq!(
            (
                answer.map(|m| (m.node.size, m.node.exec, m.nlink)),
                (
                    query.namespace_copies,
                    query.primary_visits,
                    query.entry_copies
                )
            ),
            (Ok((wanted.0, wanted.1, 1)), (0, 0, 2)),
            "unbound setter with no handles, size={size:?}, exec={exec:?}"
        );
        cases += 1;
    }
    let before = captured_records(&paths, &input).1;
    for (path, size, error) in [
        (
            file.clone(),
            Some(9_223_372_036_854_775_808),
            WriteError::TooBig,
        ),
        (handler_path(b"sub"), Some(1), WriteError::IsDirectory),
        (
            handler_path(b"original-link"),
            Some(1),
            WriteError::IsDirectory,
        ),
        (handler_path(b"absent"), Some(1), WriteError::Missing),
    ] {
        let refused = ready
            .backend_for_test()
            .overlay_setattr(&path, size, Some(true));
        let after = captured_records(&paths, &input).1;
        assert_eq!(
            (refused, after == before),
            (Err(error), true),
            "unbound setter refusal must capture no operation, path={path:?}"
        );
        cases += 1;
    }
    let backend = ready.backend_for_test();
    let object = backend.overlay_open(&file).unwrap().unwrap();
    assert_eq!(
        (
            backend.overlay_object(object).map(|n| (n.size, n.exec)),
            backend.read_object(object, 0, 65536)
        ),
        (Ok((8, false)), Ok([&FILE_CONTENT[..7], &[0]].concat())),
        "unbound setter bytes are authoritative when opened later"
    );
    backend.overlay_close(object).unwrap();
    assert_eq!(cases, 8, "nonempty no-handle setter/refusal cases: {cases}");
}

#[test]
fn writable_unbound_setter_does_not_mutate_a_recreated_name_after_preparation() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let cardinality = backend.overlay_nodes().unwrap().len();
    assert_eq!(cardinality, 6, "actual namespace entries: {cardinality}");
    backend.planning_replace = true;
    assert_eq!(
        (
            backend.overlay_setattr(&file, Some(7), Some(true)),
            backend
                .overlay_path(&file)
                .map(|m| (m.node.size, m.node.exec)),
            backend.planning_attempts
        ),
        (Err(WriteError::Missing), Ok((0, false)), 1),
        "a path preparation cannot apply its old size or exec to a new identity"
    );
}

#[test]
fn writable_unbound_setter_does_not_follow_a_name_moved_during_preparation() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let moved = handler_path(b"prepared-moved");
    let cardinality = backend.overlay_nodes().unwrap().len();
    assert_eq!(cardinality, 6, "actual namespace entries: {cardinality}");
    backend.planning_move = Some(moved.clone());
    assert_eq!(
        (
            backend.overlay_setattr(&file, Some(7), Some(true)),
            backend.overlay_path(&file),
            backend
                .overlay_path(&moved)
                .map(|m| (m.node.size, m.node.exec)),
            backend.planning_attempts
        ),
        (
            Err(WriteError::Missing),
            Err(WriteError::Missing),
            Ok((FILE_CONTENT.len() as u64, false)),
            2
        ),
        "an unbound setter must retain its requested name across preparation"
    );
}

// An unlink owns both preparation and retained adapter metadata before capture.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "independent N/H fixtures join complete detach work with orphan identity and recreation"
)]
fn writable_detach_metadata_sequence_copies_at_most_two_entries() {
    let mut cases = 0;
    for unrelated in [0, 64] {
        for held_count in [1, 17] {
            for dirty in [false, true] {
                let paths = query_paths();
                let tree = query_tree_with_unrelated(&paths, unrelated);
                let input = input(&tree, &paths);
                let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
                let mut ready = ready.unwrap();
                let backend = ready.backend_for_test();
                let mut objects = Vec::new();
                for number in 0..16 {
                    let path = handler_path(format!("held-{number:02}").as_bytes());
                    backend
                        .overlay_mutate(M::Create {
                            path: &path,
                            kind: NodeKind::File,
                            exec: false,
                        })
                        .unwrap();
                    if held_count == 17 {
                        objects.push(backend.overlay_open(&path).unwrap().unwrap());
                    }
                }
                let file = handler_path(b"f.txt");
                let object = backend.overlay_open(&file).unwrap().unwrap();
                let shared = backend.overlay_open(&file).unwrap().unwrap();
                objects.push(object);
                let cardinality = backend.overlay_nodes().unwrap().len();
                let distinct = objects
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                assert_eq!(
                    (cardinality, distinct, shared),
                    (unrelated + 22, held_count, object),
                    "actual namespace/held/shared identities: {cardinality}/{objects:?}/{shared}"
                );
                let expected = if dirty {
                    backend.prepare_object(object).unwrap();
                    backend
                        .overlay_mutate(M::BoundSetattr {
                            object,
                            size: Some(4),
                            exec: Some(true),
                        })
                        .unwrap();
                    FILE_CONTENT[..4].to_vec()
                } else {
                    FILE_CONTENT.to_vec()
                };
                let (answer, query, storage) = crate::overlay_store::work::measure(|| {
                    backend.prepare_detach(&file)?;
                    let metadata = backend.overlay_path(&file)?;
                    backend.overlay_mutate(M::Remove {
                        path: &file,
                        directory: false,
                    })?;
                    Ok::<_, WriteError>((metadata.node.size, metadata.node.exec, metadata.nlink))
                });
                let work = (
                    query.namespace_copies,
                    query.primary_visits,
                    query.entry_copies,
                );
                assert_eq!(
                    (answer, work, storage.namespace_clones > 0),
                    (Ok((expected.len() as u64, dirty, 1)), (0, 0, 2), true),
                    "complete unlink: namespace_entries={cardinality}, held_objects={held_count}, dirty={dirty}, query_work={work:?}"
                );
                let (detached, detached_work) =
                    crate::overlay_store::measure_query(|| backend.overlay_object(object));
                let detached = detached.unwrap();
                assert_eq!(
                    (
                        backend.object_attached_for_test(object),
                        backend.overlay_path(&file),
                        backend.read_object(shared, 0, 65536),
                        detached.stage.is_some(),
                        detached_work
                    ),
                    (
                        Some(false),
                        Err(WriteError::Missing),
                        Ok(expected.clone()),
                        true,
                        (0, 0, 0)
                    ),
                    "unlink must stay detached with the old name absent, dirty={dirty}"
                );
                backend
                    .overlay_mutate(M::Create {
                        path: &file,
                        kind: NodeKind::File,
                        exec: false,
                    })
                    .unwrap();
                let replacement = backend.overlay_open(&file).unwrap().unwrap();
                backend
                    .overlay_mutate(M::BoundWrite {
                        object: replacement,
                        offset: 0,
                        bytes: b"new",
                        append: false,
                    })
                    .unwrap();
                assert_eq!(
                    (
                        replacement != object,
                        backend.object_attached_for_test(object),
                        backend.overlay_object(shared).unwrap().stage,
                        backend.read_object(shared, 0, 65536),
                        backend.read_object(replacement, 0, 65536)
                    ),
                    (
                        true,
                        Some(false),
                        detached.stage,
                        Ok(expected),
                        Ok(b"new".to_vec())
                    ),
                    "recreation must never reattach or retarget the shared orphan"
                );
                backend.overlay_close(replacement).unwrap();
                backend.overlay_close(shared).unwrap();
                for object in objects {
                    backend.overlay_close(object).unwrap();
                }
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 8, "nonempty detach cases: {cases}");
}

fn add_query_holds<B: granary_fuse::MountBackend>(backend: &mut B, held: usize) -> Vec<u64> {
    let mut objects = Vec::new();
    for number in 0..16 {
        let path = handler_path(format!("held-{number:02}").as_bytes());
        backend
            .overlay_mutate(M::Create {
                path: &path,
                kind: NodeKind::File,
                exec: false,
            })
            .unwrap();
        if number < held {
            objects.push(backend.overlay_open(&path).unwrap().unwrap());
        }
    }
    objects
}

#[track_caller]
fn assert_callback_work<T: std::fmt::Debug + PartialEq>(
    actual: &(T, (usize, usize, usize)),
    expected: T,
    entries: usize,
    site: &str,
) {
    assert_eq!(
        actual,
        &(expected, (0, 0, entries)),
        "callback answer/work: {site}"
    );
}

// A primary scan, whole-tree fallback or refresh of all H objects fails this corpus.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one admitted N/H fixture checks distinct query/refusal routes with fixed directory size"
)]
fn writable_callback_queries_keep_directory_size_and_holds_independent() {
    let mut cases = 0;
    for unrelated in [0, 64] {
        for held_count in [0, 16] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let objects = add_query_holds(backend, held_count);
            let directory = handler_path(b"sub");
            let mut child_dir = directory.clone();
            child_dir.push(Name::new(b"nested".to_vec()).unwrap());
            backend
                .overlay_mutate(M::Create {
                    path: &child_dir,
                    kind: NodeKind::Dir,
                    exec: false,
                })
                .unwrap();
            let cardinality = backend.overlay_nodes().unwrap().len();
            assert_eq!(
                (cardinality, objects.len()),
                (unrelated + 23, held_count),
                "actual namespace/H: {cardinality}/{objects:?}"
            );
            let file = handler_path(b"f.txt");
            let link = handler_path(b"original-link");
            let absent = Name::new(b"absent".to_vec()).unwrap();
            assert_callback_work(
                &crate::overlay_store::measure_query(|| {
                    backend
                        .overlay_lookup(&[], file.last().unwrap())
                        .map(|m| (m.node.path, m.node.size, m.node.exec, m.nlink))
                }),
                Ok((file.clone(), 32, false, 1)),
                1,
                "lookup",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| backend.overlay_lookup(&file, &absent)),
                Err(WriteError::NotDirectory),
                0,
                "lookup file parent",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| {
                    backend.overlay_lookup(std::slice::from_ref(&absent), &absent)
                }),
                Err(WriteError::Missing),
                0,
                "lookup missing parent",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| backend.overlay_lookup(&[], &absent)),
                Err(WriteError::Missing),
                0,
                "lookup missing child",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| {
                    backend
                        .overlay_path(&directory)
                        .map(|m| (m.node.kind, m.node.size, m.nlink))
                }),
                Ok((NodeKind::Dir, 4096, 3)),
                1,
                "directory getattr",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| {
                    backend.overlay_path(&[]).map(|m| (m.node.kind, m.nlink))
                }),
                Ok((NodeKind::Dir, 4)),
                0,
                "root getattr",
            );
            let (opened, work) = crate::overlay_store::measure_query(|| {
                let attr = backend.overlay_path(&file)?;
                let object = backend.overlay_open(&file)?.ok_or(WriteError::Missing)?;
                Ok::<_, WriteError>((object, attr.node.size, attr.node.exec))
            });
            let (object, size, exec) = opened.unwrap();
            assert_eq!(
                ((size, exec), work),
                ((32, false), (0, 0, 2)),
                "complete open, N={cardinality}, H={held_count}"
            );
            backend.overlay_close(object).unwrap();
            assert_callback_work(
                &crate::overlay_store::measure_query(|| backend.overlay_readlink(&link)),
                Ok(b"f.txt".to_vec()),
                1,
                "readlink",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| backend.overlay_readlink(&file)),
                Err(WriteError::Invalid),
                1,
                "readlink wrong kind",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| {
                    backend.overlay_readlink(std::slice::from_ref(&absent))
                }),
                Err(WriteError::Missing),
                0,
                "readlink missing",
            );
            assert_callback_work(
                &crate::overlay_store::measure_query(|| {
                    backend
                        .overlay_path(&file)
                        .map(|m| (m.node.size, m.node.exec))
                }),
                Ok((32, false)),
                1,
                "setattr query/canonical no-op",
            );
            for plus in [false, true] {
                let (answer, work) = crate::overlay_store::measure_query(|| {
                    let observation = backend.overlay_directory(&directory)?;
                    let mut cursor = observation.cursor;
                    let mut rows = Vec::new();
                    loop {
                        let page = backend.overlay_children(&cursor)?;
                        rows.extend(
                            page.entries
                                .into_iter()
                                .map(|m| (m.node.path, m.node.kind, m.nlink)),
                        );
                        if let Some(next) = page.next {
                            cursor = next;
                        } else {
                            break;
                        }
                    }
                    Ok::<_, WriteError>((
                        observation.directory.nlink,
                        observation.parent.nlink,
                        rows,
                    ))
                });
                let mut child_file = directory.clone();
                child_file.push(Name::new(b"g.txt".to_vec()).unwrap());
                assert_eq!(
                    (answer, work),
                    (
                        Ok((
                            3,
                            4,
                            vec![
                                (child_file, NodeKind::File, 1),
                                (child_dir.clone(), NodeKind::Dir, 2)
                            ]
                        )),
                        (0, 0, 3)
                    ),
                    "listing plus={plus}, N={cardinality}, H={held_count}, D=2; two owned children and one directory copy"
                );
                let empty = handler_path(b"empty");
                assert_callback_work(
                    &crate::overlay_store::measure_query(|| {
                        let observation = backend.overlay_directory(&empty)?;
                        let page = backend.overlay_children(&observation.cursor)?;
                        Ok::<_, WriteError>((
                            observation.directory.nlink,
                            page.entries.len(),
                            page.next.is_none(),
                        ))
                    }),
                    Ok((2, 0, true)),
                    1,
                    "empty listing",
                );
                assert_callback_work(
                    &crate::overlay_store::measure_query(|| {
                        backend
                            .overlay_directory(std::slice::from_ref(&absent))
                            .map(|_| ())
                    }),
                    Err(WriteError::Missing),
                    0,
                    "missing listing",
                );
            }
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
            cases += 17;
        }
    }
    assert_eq!(
        cases, 68,
        "nonempty independent N/H callback cases: {cases}"
    );
}

#[test]
fn writable_creation_replies_and_unheld_detach_use_only_involved_entries() {
    let mut cases = 0;
    for unrelated in [0, 64] {
        for held_count in [0, 16] {
            let paths = query_paths();
            let tree = query_tree_with_unrelated(&paths, unrelated);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let objects = add_query_holds(backend, held_count);
            let cardinality = backend.overlay_nodes().unwrap().len();
            assert_eq!(
                (cardinality, objects.len()),
                (unrelated + 22, held_count),
                "actual namespace/H: {cardinality}/{objects:?}"
            );
            for (label, kind, opened, size, nlink) in [
                (b"created".as_slice(), NodeKind::File, true, 0, 1),
                (b"mknod", NodeKind::File, false, 0, 1),
                (b"mkdir", NodeKind::Dir, false, 4096, 2),
                (b"symlink", NodeKind::Symlink, false, 5, 1),
            ] {
                let path = handler_path(label);
                let target = granary_core::manifest::SymlinkTarget::new(b"f.txt".to_vec()).unwrap();
                let (answer, query, storage) = crate::overlay_store::work::measure(|| {
                    let operation = if kind == NodeKind::Symlink {
                        M::Symlink {
                            path: &path,
                            target: &target,
                        }
                    } else {
                        M::Create {
                            path: &path,
                            kind,
                            exec: false,
                        }
                    };
                    backend.overlay_mutate(operation)?;
                    let metadata = backend.overlay_path(&path)?;
                    let object = if opened {
                        backend.overlay_open(&path)?
                    } else {
                        None
                    };
                    Ok::<_, WriteError>((metadata, object))
                });
                let (metadata, object) = answer.unwrap();
                assert_eq!(
                    (
                        (
                            metadata.node.path,
                            metadata.node.kind,
                            metadata.node.size,
                            metadata.nlink,
                            object.is_some()
                        ),
                        (
                            query.namespace_copies,
                            query.primary_visits,
                            query.entry_copies
                        ),
                        storage.namespace_clones > 0
                    ),
                    (
                        (path.clone(), kind, size, nlink, opened),
                        (0, 0, if opened { 2 } else { 1 }),
                        true
                    ),
                    "creation reply at N={cardinality}, H={held_count}, label={label:?}"
                );
                if let Some(object) = object {
                    backend.overlay_close(object).unwrap();
                }
                let (answer, work) = crate::overlay_store::measure_query(|| {
                    if kind != NodeKind::Dir {
                        backend.prepare_detach(&path)?;
                    }
                    let retained = backend.overlay_path(&path)?;
                    backend.overlay_mutate(M::Remove {
                        path: &path,
                        directory: kind == NodeKind::Dir,
                    })?;
                    Ok::<_, WriteError>((retained.node.kind, retained.node.size))
                });
                assert_eq!(
                    (answer, work, backend.overlay_path(&path).err()),
                    (Ok((kind, size)), (0, 0, 2), Some(WriteError::Missing)),
                    "unheld detach metadata, label={label:?}"
                );
                cases += 2;
            }
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
        }
    }
    assert_eq!(cases, 32, "nonempty creation/detach cases: {cases}");
}

#[test]
fn writable_detach_preparation_revalidates_and_retains_shared_holds_on_failure() {
    let mut cases = 0;
    for changes in [0, 2, 3] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        let shared = backend.overlay_open(&file).unwrap().unwrap();
        let cardinality = backend.overlay_nodes().unwrap().len();
        assert_eq!(
            (cardinality, shared),
            (6, object),
            "actual namespace/shared binding: {cardinality}/{object}/{shared}"
        );
        backend.planning_changes_remaining = changes;
        let result = backend.prepare_detach(&file);
        let expected = if changes == 3 {
            Err(WriteError::Backend(
                granary_fuse::MountError::PlanningExhausted,
            ))
        } else {
            Ok(())
        };
        let held = backend.overlay_object(object).unwrap();
        assert_eq!(
            (
                result,
                backend.planning_attempts,
                held.path,
                held.size,
                held.exec,
                held.stage,
                backend.object_attached_for_test(object),
                backend.overlay_close(shared),
                backend.overlay_close(object)
            ),
            (
                expected,
                (changes + 1).min(3),
                file,
                32,
                changes % 2 != 0,
                None,
                Some(true),
                Ok(()),
                Ok(())
            ),
            "detach preparation must revalidate and preserve both releasable holds on exhaustion, changes={changes}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3, "nonempty detach preparation routes: {cases}");
}

#[derive(Debug, Clone, Copy)]
enum CleanRoute {
    Read,
    Write,
    BoundSize,
    PathSize,
    Detach,
}

#[expect(
    clippy::too_many_lines,
    reason = "complete callback samples join retry work, exact effects and independent N/H premises"
)]
fn clean_route_attempts(route: CleanRoute) {
    use crate::overlay_store::work;
    let mut cases = 0;
    for unrelated in [0, 64] {
        for held_count in [1, 17] {
            for changes in 0..=3 {
                let paths = query_paths();
                let tree = query_tree_with_unrelated(&paths, unrelated);
                let input = input(&tree, &paths);
                let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
                let mut ready = ready.unwrap();
                let backend = ready.backend_for_test();
                let other = add_query_holds(backend, held_count - 1);
                let file = handler_path(b"f.txt");
                let object = backend.overlay_open(&file).unwrap().unwrap();
                let cardinality = backend.overlay_nodes().unwrap().len();
                assert_eq!(
                    (cardinality, other.len() + 1),
                    (unrelated + 22, held_count),
                    "actual N/H premise: {cardinality}/{other:?}"
                );
                backend.planning_changes_remaining = changes;
                let before = work::query_snapshot();
                let (answer, query, _) = work::measure(|| match route {
                    CleanRoute::Read => {
                        backend.prepare_object(object)?;
                        backend.read_object(object, 0, 65536)
                    }
                    CleanRoute::Write | CleanRoute::BoundSize => {
                        if matches!(route, CleanRoute::BoundSize) {
                            backend.overlay_path(&file)?;
                        }
                        backend.prepare_object(object)?;
                        let operation = if matches!(route, CleanRoute::Write) {
                            M::BoundWrite {
                                object,
                                offset: 0,
                                bytes: b"x",
                                append: false,
                            }
                        } else {
                            M::BoundSetattr {
                                object,
                                size: Some(7),
                                exec: None,
                            }
                        };
                        backend.overlay_mutate(operation)?;
                        if matches!(route, CleanRoute::BoundSize) {
                            backend.overlay_path(&file)?;
                        }
                        Ok(Vec::new())
                    }
                    CleanRoute::PathSize => {
                        backend.overlay_path(&file)?;
                        backend.overlay_setattr(&file, Some(7), None)?;
                        Ok(Vec::new())
                    }
                    CleanRoute::Detach => {
                        backend.overlay_path(&file)?;
                        backend.prepare_detach(&file)?;
                        backend.overlay_mutate(M::Remove {
                            path: &file,
                            directory: false,
                        })?;
                        Ok(Vec::new())
                    }
                });
                let exhausted = changes == 3;
                let expected_answer = if exhausted {
                    Err(WriteError::Backend(
                        granary_fuse::MountError::PlanningExhausted,
                    ))
                } else if matches!(route, CleanRoute::Read) {
                    Ok(FILE_CONTENT.to_vec())
                } else {
                    Ok(Vec::new())
                };
                // Replacement contexts belong to the attempt that consumes them.
                // The final sample includes all discarded/final-reply work.
                let mut previous = before;
                let mut samples: Vec<_> = backend
                    .planning_work_boundaries
                    .iter()
                    .map(|boundary| {
                        let delta = boundary.since(previous);
                        previous = *boundary;
                        (
                            delta.namespace_copies,
                            delta.primary_visits,
                            delta.entry_copies,
                        )
                    })
                    .collect();
                let tail = work::query_snapshot().since(previous);
                let last = samples.last_mut().unwrap();
                last.0 += tail.namespace_copies;
                last.1 += tail.primary_visits;
                last.2 += tail.entry_copies;
                let prefix = match route {
                    CleanRoute::PathSize => 2,
                    CleanRoute::BoundSize | CleanRoute::Detach => 1,
                    CleanRoute::Read | CleanRoute::Write => 0,
                };
                let suffix = match route {
                    CleanRoute::Read | CleanRoute::BoundSize | CleanRoute::Detach => 1,
                    CleanRoute::PathSize | CleanRoute::Write => 0,
                };
                let mut expected = vec![(0, 0, prefix)];
                expected.extend((0..changes.min(2)).map(|_| (0, 0, 1)));
                expected.last_mut().unwrap().2 += if exhausted { 1 } else { suffix };
                let sum = samples
                    .iter()
                    .fold((0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2));
                assert_eq!(
                    (
                        answer,
                        &samples,
                        sum,
                        backend.planning_attempts,
                        backend.mutation_readiness()
                    ),
                    (
                        expected_answer,
                        &expected,
                        (
                            query.namespace_copies,
                            query.primary_visits,
                            query.entry_copies
                        ),
                        (changes + 1).min(3),
                        Ok(())
                    ),
                    "route={route:?}, N={cardinality}, H={held_count}, changes={changes}"
                );
                let verdicts: Vec<_> = samples
                    .iter()
                    .map(|sample| callback_attempt_bound(0, *sample))
                    .collect();
                assert_eq!(
                    verdicts,
                    vec![Ok(()); expected.len()],
                    "route={route:?}, samples={samples:?}"
                );
                eprintln!(
                    "route={route:?}, N={cardinality}, H={held_count}, changes={changes}, samples={samples:?}, aggregate={sum:?}"
                );
                let wanted_bytes =
                    if exhausted || matches!(route, CleanRoute::Read | CleanRoute::Detach) {
                        FILE_CONTENT.to_vec()
                    } else if matches!(route, CleanRoute::Write) {
                        let mut bytes = FILE_CONTENT.to_vec();
                        bytes[0] = b'x';
                        bytes
                    } else {
                        FILE_CONTENT[..7].to_vec()
                    };
                let detached = !exhausted && matches!(route, CleanRoute::Detach);
                assert_eq!(
                    (
                        backend.read_object(object, 0, 65536),
                        backend.object_attached_for_test(object),
                        backend.overlay_path(&file).map(|_| ())
                    ),
                    (
                        Ok(wanted_bytes.clone()),
                        Some(!detached),
                        if detached {
                            Err(WriteError::Missing)
                        } else {
                            Ok(())
                        }
                    ),
                    "route={route:?}, changes={changes}: bytes, attachment and old-name state"
                );
                if detached {
                    backend
                        .overlay_mutate(M::Create {
                            path: &file,
                            kind: NodeKind::File,
                            exec: false,
                        })
                        .unwrap();
                    let replacement = backend.overlay_open(&file).unwrap().unwrap();
                    assert_eq!(
                        (
                            replacement != object,
                            backend.read_object(object, 0, 65536),
                            backend.object_attached_for_test(object),
                            backend.read_object(replacement, 0, 65536)
                        ),
                        (true, Ok(wanted_bytes), Some(false), Ok(Vec::new())),
                        "recreation must never reattach or retarget the detached held object"
                    );
                    backend.overlay_close(replacement).unwrap();
                }
                backend.overlay_close(object).unwrap();
                for object in other {
                    backend.overlay_close(object).unwrap();
                }
                cases += 1;
            }
        }
    }
    assert_eq!(
        cases, 16,
        "nonempty route cases: route={route:?}, actual={cases}"
    );
}

#[test]
fn writable_clean_read_samples_every_context_attempt() {
    clean_route_attempts(CleanRoute::Read);
}
#[test]
fn writable_clean_write_samples_every_context_attempt() {
    clean_route_attempts(CleanRoute::Write);
}
#[test]
fn writable_bound_size_samples_every_context_attempt() {
    clean_route_attempts(CleanRoute::BoundSize);
}
#[test]
fn writable_path_size_samples_every_context_attempt() {
    clean_route_attempts(CleanRoute::PathSize);
}
#[test]
fn writable_detach_samples_every_context_attempt() {
    clean_route_attempts(CleanRoute::Detach);
}

fn callback_attempt_bound(owned: usize, work: (usize, usize, usize)) -> Result<(), &'static str> {
    match work {
        (copies, _, _) if copies != 0 => Err("callback attempt copied a whole namespace"),
        (_, visits, _) if visits != 0 => Err("callback attempt iterated the primary map"),
        (_, _, copies) if copies.saturating_sub(owned) > 2 => {
            Err("callback attempt copied more than 2 extra entries")
        }
        _ => Ok(()),
    }
}

#[test]
fn callback_attempt_accounting_refuses_each_independent_violation() {
    let mut cases = 0;
    for owned in [0, 256] {
        for (malformed, refusal) in [
            (
                (1, 0, owned + 2),
                "callback attempt copied a whole namespace",
            ),
            (
                (0, 1, owned + 2),
                "callback attempt iterated the primary map",
            ),
            (
                (0, 0, owned + 3),
                "callback attempt copied more than 2 extra entries",
            ),
        ] {
            assert_eq!(
                (
                    callback_attempt_bound(owned, (0, 0, owned + 2)),
                    callback_attempt_bound(owned, malformed)
                ),
                (Ok(()), Err(refusal)),
                "owned={owned}, malformed={malformed:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6, "paired accounting controls: {cases}");
}

#[expect(
    clippy::too_many_lines,
    reason = "admitted multipage attempts join discarded rows, context refusal and complete ordered directory answers"
)]
fn multipage_listing_attempts(plus: bool) {
    let mut cases = 0;
    for unrelated in [0, 64] {
        for held_count in [0, 16] {
            let paths = query_paths();
            let tree = query_tree_with_children(&paths, unrelated, 512);
            let input = input(&tree, &paths);
            let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let backend = ready.backend_for_test();
            let objects = add_query_holds(backend, held_count);
            let cardinality = backend.overlay_nodes().unwrap().len();
            assert_eq!(
                (cardinality, objects.len()),
                (unrelated + 534, held_count),
                "actual namespace/H: {cardinality}/{objects:?}"
            );
            let directory = handler_path(b"sub");
            let expected_rows: Vec<_> = (0..512)
                .map(|number| {
                    let mut path = directory.clone();
                    path.push(Name::new(format!("child-{number:04}").into_bytes()).unwrap());
                    if number % 64 == 0 {
                        (path, NodeKind::Dir, 2)
                    } else {
                        (path, NodeKind::File, 1)
                    }
                })
                .chain(std::iter::once((
                    vec![
                        Name::new(b"sub".to_vec()).unwrap(),
                        Name::new(b"g.txt".to_vec()).unwrap(),
                    ],
                    NodeKind::File,
                    1,
                )))
                .collect();
            let mut exec = false;
            for changes in 0..=3 {
                let mut samples = Vec::new();
                let mut answer = Err(WriteError::Backend(
                    granary_fuse::MountError::PlanningExhausted,
                ));
                for attempt_number in 0..3 {
                    let ((links, mut rows, next), mut work) =
                        crate::overlay_store::measure_query(|| {
                            let observation = backend.overlay_directory(&directory).unwrap();
                            let page = backend.overlay_children(&observation.cursor).unwrap();
                            (
                                (observation.directory.nlink, observation.parent.nlink),
                                page.entries,
                                page.next,
                            )
                        });
                    assert_eq!(
                        (links, rows.len(), next.is_some()),
                        ((10, 4), 256, true),
                        "nonempty directory/first page: links={links:?}, rows={}, next={next:?}",
                        rows.len()
                    );
                    let next = next.unwrap();
                    if attempt_number < changes {
                        // This mutation represents another actor between callback pages;
                        // its storage/preflight work is outside callback samples.
                        exec = !exec;
                        backend
                            .overlay_mutate(M::Setattr {
                                path: &handler_path(b"f.txt"),
                                size: None,
                                exec: Some(exec),
                            })
                            .unwrap();
                        let (refused, refused_work) =
                            crate::overlay_store::measure_query(|| backend.overlay_children(&next));
                        assert_eq!(
                            (
                                refused.map(|_| ()),
                                refused_work,
                                backend.mutation_readiness()
                            ),
                            (
                                Err(WriteError::Backend(
                                    granary_fuse::MountError::PlanningExhausted
                                )),
                                (0, 0, 0),
                                Ok(())
                            ),
                            "stale continuation is a typed change, never EOF or poison"
                        );
                        samples.push((rows.len(), work, callback_attempt_bound(rows.len(), work)));
                        continue;
                    }
                    let ((rest, sizes), rest_work) = crate::overlay_store::measure_query(|| {
                        let mut cursor = Some(next);
                        let mut rest = Vec::new();
                        let mut sizes = vec![256];
                        while let Some(at) = cursor {
                            let page = backend.overlay_children(&at).unwrap();
                            sizes.push(page.entries.len());
                            rest.extend(page.entries);
                            cursor = page.next;
                        }
                        (rest, sizes)
                    });
                    assert_eq!(sizes, vec![256, 256, 1], "exact page sizes: {sizes:?}");
                    rows.extend(rest);
                    work.0 += rest_work.0;
                    work.1 += rest_work.1;
                    work.2 += rest_work.2;
                    samples.push((rows.len(), work, callback_attempt_bound(rows.len(), work)));
                    answer = Ok((
                        links,
                        rows.into_iter()
                            .map(|m| (m.node.path, m.node.kind, m.nlink))
                            .collect::<Vec<_>>(),
                    ));
                    break;
                }
                let mut expected_samples = vec![(256, (0, 0, 257), Ok(())); changes.min(3)];
                let expected_answer = if changes == 3 {
                    Err(WriteError::Backend(
                        granary_fuse::MountError::PlanningExhausted,
                    ))
                } else {
                    expected_samples.push((513, (0, 0, 514), Ok(())));
                    Ok(((10, 4), expected_rows.clone()))
                };
                assert_eq!(
                    answer, expected_answer,
                    "complete ordered directory answer, plus={plus}, changes={changes}"
                );
                assert_eq!(
                    (&samples, backend.mutation_readiness()),
                    (&expected_samples, Ok(())),
                    "plus={plus}, N={cardinality}, D=513, H={held_count}, changes={changes}"
                );
                eprintln!(
                    "plus={plus}, N={cardinality}, D=513, H={held_count}, changes={changes}, samples={samples:?}"
                );
                cases += 1;
            }
            for object in objects {
                backend.overlay_close(object).unwrap();
            }
        }
    }
    assert_eq!(
        cases, 16,
        "nonempty multipage cases: plus={plus}, actual={cases}"
    );
}

#[test]
fn writable_readdir_multipage_attempts_keep_directory_size_and_holds_independent() {
    multipage_listing_attempts(false);
}

#[test]
fn writable_readdirplus_multipage_attempts_keep_directory_size_and_holds_independent() {
    multipage_listing_attempts(true);
}

#[test]
fn writable_clean_completion_is_shared_by_content_and_revalidated_after_rename() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let shared = vec![
        Name::new(b"sub".to_vec()).unwrap(),
        Name::new(b"g.txt".to_vec()).unwrap(),
    ];
    let moved = handler_path(b"moved");
    let first = backend.overlay_open(&file).unwrap().unwrap();
    let second = backend.overlay_open(&shared).unwrap().unwrap();
    assert_eq!(
        (backend.overlay_nodes().unwrap().len(), first != second),
        (6, true),
        "nonempty distinct-name premise"
    );
    let mut answers = Vec::new();
    for object in [first, second, first] {
        backend.prepare_object(object).unwrap();
        answers.push(backend.read_object(object, 0, 65536));
    }
    backend
        .overlay_mutate(M::Rename {
            from: &shared,
            to: &moved,
            no_replace: false,
        })
        .unwrap();
    backend.prepare_object(second).unwrap();
    answers.push(backend.read_object(second, 0, 65536));
    assert_eq!(
        (
            answers,
            backend.materialization_passes,
            backend.overlay_object(second).unwrap().path
        ),
        (vec![Ok(FILE_CONTENT.to_vec()); 4], 1, moved),
        "one completed preparation per resident content id across names and rename"
    );
    backend.overlay_close(first).unwrap();
    backend.overlay_close(second).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one held-object sequence keeps copy-up, replacement and orphan assertions together"
)]
fn writable_warm_clean_tokens_follow_copy_up_truncate_replace_and_shared_orphans() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let other = vec![
        Name::new(b"sub".to_vec()).unwrap(),
        Name::new(b"g.txt".to_vec()).unwrap(),
    ];
    let first = backend.overlay_open(&file).unwrap().unwrap();
    let shared = backend.overlay_open(&file).unwrap().unwrap();
    let displaced = backend.overlay_open(&other).unwrap().unwrap();
    assert_eq!(
        (
            first,
            first != displaced,
            backend.overlay_nodes().unwrap().len()
        ),
        (shared, true, 6),
        "nonempty shared-content/shared-handle premise"
    );
    for object in [first, displaced] {
        backend.prepare_object(object).unwrap();
        assert_eq!(
            backend.read_object(object, 0, 65_536),
            Ok(FILE_CONTENT.to_vec())
        );
    }
    backend
        .overlay_mutate(M::BoundWrite {
            object: first,
            offset: 0,
            bytes: b"NEW",
            append: false,
        })
        .unwrap();
    backend
        .overlay_mutate(M::BoundSetattr {
            object: shared,
            size: Some(3),
            exec: None,
        })
        .unwrap();
    backend.prepare_object(shared).unwrap();
    backend.prepare_object(displaced).unwrap();
    assert_eq!(
        (
            backend.read_object(shared, 0, 65_536),
            backend.read_object(displaced, 0, 65_536),
            backend.materialization_passes
        ),
        (Ok(b"NEW".to_vec()), Ok(FILE_CONTENT.to_vec()), 1),
        "copy-up/truncate must route the shared object to stage while unchanged content stays resident"
    );
    backend.prepare_detach(&other).unwrap();
    backend
        .overlay_mutate(M::Rename {
            from: &file,
            to: &other,
            no_replace: false,
        })
        .unwrap();
    let stage = backend.overlay_object(displaced).unwrap().stage;
    assert_eq!(
        (
            backend.object_attached_for_test(displaced),
            backend.overlay_path(&file),
            backend.overlay_open(&other).unwrap(),
            backend.read_object(displaced, 0, 65_536),
            backend.read_object(first, 0, 65_536),
            backend.materialization_passes
        ),
        (
            Some(false),
            Err(WriteError::Missing),
            Some(first),
            Ok(FILE_CONTENT.to_vec()),
            Ok(b"NEW".to_vec()),
            1
        ),
        "replacement preserves displaced bytes and held identity without consuming clean content for the new occupant"
    );
    backend
        .overlay_mutate(M::Create {
            path: &file,
            kind: NodeKind::File,
            exec: false,
        })
        .unwrap();
    let recreated = backend.overlay_open(&file).unwrap().unwrap();
    backend
        .overlay_mutate(M::BoundWrite {
            object: recreated,
            offset: 0,
            bytes: b"fresh",
            append: false,
        })
        .unwrap();
    backend.prepare_object(displaced).unwrap();
    assert_eq!(
        (
            backend.object_attached_for_test(displaced),
            backend.overlay_object(displaced).unwrap().stage == stage,
            recreated != displaced,
            backend.read_object(displaced, 0, 65_536),
            backend.read_object(recreated, 0, 65_536),
            backend.materialization_passes
        ),
        (
            Some(false),
            true,
            true,
            Ok(FILE_CONTENT.to_vec()),
            Ok(b"fresh".to_vec()),
            1
        ),
        "the displaced object never reattaches after recreation; mount completion cannot replace stage routing"
    );
    for object in [first, shared, first, displaced, recreated] {
        backend.overlay_close(object).unwrap();
    }
}

#[test]
fn writable_warm_replay_invalidates_mount_tokens_and_mediator_ranges_together() {
    let mut observed = Vec::new();
    for corrupt in [false, true] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let base = runtime
            .block_on(tree.remote.get_root(tree.volume.as_str(), tree.seq))
            .unwrap()
            .unwrap();
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let file = handler_path(b"f.txt");
        let object = ready
            .backend_for_test()
            .overlay_open(&file)
            .unwrap()
            .unwrap();
        ready.backend_for_test().prepare_object(object).unwrap();
        assert_eq!(
            (
                ready.backend_for_test().read_object(object, 0, 65_536),
                ready.backend_for_test().materialization_passes
            ),
            (Ok(FILE_CONTENT.to_vec()), 1),
            "nonempty completion/range premise"
        );
        let mediator = ready.mediator_for_test();
        let entries = mediator.overlay_transaction(query_fixture_entries).unwrap();
        assert_eq!(
            entries.len(),
            5,
            "nonempty replay fixture: actual={}",
            entries.len()
        );
        let header = granary_core::overlay_journal::JournalHeader {
            writer: mediator.writer_uuid(),
            base_root: GrainId::of(&base),
            base_seq: tree.seq,
            next_stage_id: 1,
            receipt_generation: 0,
        };
        mediator
            .open_overlay_local(
                header,
                entries,
                OverlayDisk::new(&paths.store, input.euid),
                false,
            )
            .unwrap();
        ready.backend_for_test().prepare_object(object).unwrap();
        damage_query_grain(&paths, tree.file_id, corrupt);
        let backend = ready.backend_for_test();
        observed.push((
            corrupt,
            backend.materialization_passes,
            backend.read_object(object, 0, 65_536),
        ));
        backend.overlay_close(object).unwrap();
    }
    assert_eq!(
        (observed.len(), observed),
        (
            2,
            vec![
                (
                    false,
                    2,
                    Err(WriteError::Backend(granary_fuse::MountError::Unavailable))
                ),
                (
                    true,
                    2,
                    Err(WriteError::Backend(granary_fuse::MountError::Corrupt))
                ),
            ]
        ),
        "real replay must invalidate both cache owners: fresh preparation and typed disk failures"
    );
}

pub(super) fn query_fixture_entries(
    overlay: &mut crate::WritableOverlay<'_, OverlayDisk>,
) -> Result<Vec<crate::OverlayEntry>, crate::OverlayError> {
    overlay.entries()
}

fn warm_mount_replacement(landed: bool) {
    let mut observed = Vec::new();
    for corrupt in [false, true] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let file = handler_path(b"f.txt");
        let object = ready
            .backend_for_test()
            .overlay_open(&file)
            .unwrap()
            .unwrap();
        ready.backend_for_test().prepare_object(object).unwrap();
        assert_eq!(
            (
                ready.backend_for_test().read_object(object, 0, 65_536),
                ready.backend_for_test().materialization_passes
            ),
            (Ok(FILE_CONTENT.to_vec()), 1),
            "nonempty replacement completion/range premise"
        );
        let mediator = ready.mediator_for_test();
        let candidate = GrainId::of(&mediator.snapshot().root);
        let publication = [7; 16];
        let entries = mediator.overlay_transaction(query_fixture_entries).unwrap();
        assert_eq!(
            entries.len(),
            5,
            "nonempty replacement fixture: actual={}",
            entries.len()
        );
        let boundary = mediator
            .overlay_transaction(|t| {
                let capture = t.capture_boundary()?;
                t.record_boundary(capture, candidate, publication)
            })
            .unwrap();
        if landed {
            let proof = crate::LandedProof {
                boundary_seq: boundary,
                landed_root: candidate,
                landed_seq: 2,
                captured_entries: entries.clone(),
                entries,
            };
            mediator
                .overlay_transaction(|t| {
                    t.record_landed(&proof)?;
                    t.record_landed_refresh(2, candidate)?;
                    t.replace_landed(proof)
                })
                .unwrap();
        } else {
            mediator
                .overlay_transaction(|t| t.replace_rejected(boundary, publication))
                .unwrap();
        }
        ready.backend_for_test().prepare_object(object).unwrap();
        damage_query_grain(&paths, tree.file_id, corrupt);
        let backend = ready.backend_for_test();
        observed.push((
            corrupt,
            backend.materialization_passes,
            backend.object_attached_for_test(object),
            backend.read_object(object, 0, 65_536),
        ));
        backend.overlay_close(object).unwrap();
    }
    assert_eq!(
        (observed.len(), observed),
        (
            2,
            vec![
                (
                    false,
                    2,
                    Some(true),
                    Err(WriteError::Backend(granary_fuse::MountError::Unavailable))
                ),
                (
                    true,
                    2,
                    Some(true),
                    Err(WriteError::Backend(granary_fuse::MountError::Corrupt))
                ),
            ]
        ),
        "real replacement invalidates both cache owners without changing held attachment: landed={landed}"
    );
}

#[test]
fn writable_warm_landed_replacement_invalidates_both_cache_owners() {
    warm_mount_replacement(true);
}

#[test]
fn writable_warm_rejected_replacement_invalidates_both_cache_owners() {
    warm_mount_replacement(false);
}

#[test]
fn writable_clean_completion_invalidation_requires_fresh_preparation_and_disk_failure() {
    let mut observed = Vec::new();
    for corrupt in [false, true] {
        let paths = query_paths();
        let tree = query_tree(&paths);
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let file = handler_path(b"f.txt");
        let object = ready
            .backend_for_test()
            .overlay_open(&file)
            .unwrap()
            .unwrap();
        ready.backend_for_test().prepare_object(object).unwrap();
        assert_eq!(
            (
                ready.backend_for_test().read_object(object, 0, 65536),
                ready.backend_for_test().materialization_passes
            ),
            (Ok(FILE_CONTENT.to_vec()), 1),
            "nonempty resident completion premise"
        );
        ready
            .mediator_for_test()
            .invalidate_clean_content()
            .unwrap();
        ready.backend_for_test().prepare_object(object).unwrap();
        damage_query_grain(&paths, tree.file_id, corrupt);
        let backend = ready.backend_for_test();
        observed.push((
            corrupt,
            backend.materialization_passes,
            backend.read_object(object, 0, 65536),
        ));
        backend.overlay_close(object).unwrap();
    }
    assert_eq!(
        (observed.len(), observed),
        (
            2,
            vec![
                (
                    false,
                    2,
                    Err(WriteError::Backend(granary_fuse::MountError::Unavailable))
                ),
                (
                    true,
                    2,
                    Err(WriteError::Backend(granary_fuse::MountError::Corrupt))
                ),
            ]
        ),
        "fresh preparation and typed disk failures in both nonempty routes"
    );
}

#[test]
fn writable_clean_completion_hit_never_grants_readiness() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let object = ready
        .backend_for_test()
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    ready.backend_for_test().prepare_object(object).unwrap();
    ready.backend_for_test().prepare_object(object).unwrap();
    assert_eq!(
        (
            ready.backend_for_test().materialization_passes,
            ready.backend_for_test().read_object(object, 0, 65536)
        ),
        (1, Ok(FILE_CONTENT.to_vec())),
        "nonempty token/range hit premise"
    );
    ready
        .mediator_for_test()
        .phase_for_test(granary_core::overlay_ownership::Phase::Releasing)
        .unwrap();
    let backend = ready.backend_for_test();
    assert_eq!(
        (
            backend.prepare_object(object),
            backend.read_object(object, 0, 65536),
            backend.materialization_passes
        ),
        (
            Err(WriteError::Backend(granary_fuse::MountError::Access)),
            Err(WriteError::Backend(granary_fuse::MountError::Access)),
            1
        ),
        "every warmed callback still admits current lifecycle state"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
fn writable_clean_completion_never_records_exhausted_preparation() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let object = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    backend.planning_changes_remaining = 3;
    assert_eq!(
        (
            backend.prepare_object(object),
            backend.materialization_passes,
            backend.object_attached_for_test(object)
        ),
        (
            Err(WriteError::Backend(
                granary_fuse::MountError::PlanningExhausted
            )),
            3,
            Some(true)
        ),
        "all changed attempts stay incomplete and retain the held object"
    );
    backend.prepare_object(object).unwrap();
    assert_eq!(
        (
            backend.materialization_passes,
            backend.read_object(object, 0, 65536)
        ),
        (4, Ok(FILE_CONTENT.to_vec())),
        "stable attempt must complete fresh preparation after exhaustion"
    );
    backend.prepare_object(object).unwrap();
    assert_eq!(
        backend.materialization_passes, 4,
        "successful completed preparation becomes resident"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
fn writable_clean_completion_observed_missing_bytes_require_refetch() {
    let paths = query_paths();
    let tree = query_tree(&paths);
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let object = ready
        .backend_for_test()
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    ready.backend_for_test().prepare_object(object).unwrap();
    assert_eq!(
        ready.backend_for_test().read_object(object, 0, 65536),
        Ok(FILE_CONTENT.to_vec()),
        "nonempty resident completion/range premise"
    );
    ready
        .mediator_for_test()
        .invalidate_clean_content()
        .unwrap();
    ready.backend_for_test().prepare_object(object).unwrap();
    let digest = tree.file_id.digest_hex();
    std::fs::remove_file(paths.store.join("objects").join(&digest[..2]).join(digest)).unwrap();
    assert_eq!(
        ready.backend_for_test().read_object(object, 0, 65536),
        Err(WriteError::Backend(granary_fuse::MountError::Unavailable)),
        "uncached disk loss must be observed"
    );
    let backend = ready.backend_for_test();
    backend.prepare_object(object).unwrap();
    assert_eq!(
        (
            backend.materialization_passes,
            backend.read_object(object, 0, 65536)
        ),
        (3, Ok(FILE_CONTENT.to_vec())),
        "observed loss must evict completion and refetch before a new success"
    );
    backend.overlay_close(object).unwrap();
}

#[expect(
    clippy::disallowed_methods,
    reason = "damage only a fixture-owned CAS leaf after warming verified bytes"
)]
fn damage_query_grain(paths: &Paths, id: GrainId, corrupt: bool) {
    let digest = id.digest_hex();
    let path = paths.store.join("objects").join(&digest[..2]).join(digest);
    if corrupt {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(path, b"corrupt grain").unwrap();
    } else {
        std::fs::remove_file(path).unwrap();
    }
}
