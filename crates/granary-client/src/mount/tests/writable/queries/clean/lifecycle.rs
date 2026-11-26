// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Spill completions remain content-scoped across metadata and admission changes.

use super::*;

mod content_runtime;
mod direct_mode;
mod leases;
mod sync_fixes;

fn range_witness(
    answer: Result<Vec<u8>, WriteError>,
    expected: &[u8],
) -> Result<(bool, usize, GrainId), WriteError> {
    answer.map(|bytes| (bytes == expected, bytes.len(), GrainId::of(&bytes)))
}

#[derive(Clone, Copy, Debug)]
enum Admission {
    Replay,
    Landed,
    Rejected,
    Invalidation,
}

#[expect(
    clippy::too_many_lines,
    reason = "one warmed fixture witnesses fresh preparation and typed failures on each admission route"
)]
fn spill_admission(route: Admission) {
    let mut observations = Vec::new();
    for corrupt in [false, true] {
        let paths = query_paths();
        let fixture = clean_tree(&paths, true);
        let input = input(&fixture.tree, &paths);
        let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
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
                ready.backend_for_test().materialization_passes,
                ready.backend_for_test().overlay_nodes().unwrap().len()
            ),
            (Ok(fixture.bytes[..65_536].to_vec()), 1, 3),
            "nonempty spill completion/range/cardinality premise: route={route:?}"
        );
        let mediator = ready.mediator_for_test();
        let candidate = GrainId::of(&mediator.snapshot().root);
        let entries = mediator.overlay_transaction(query_fixture_entries).unwrap();
        assert_eq!(
            entries.len(),
            2,
            "actual spill primary count: {}",
            entries.len()
        );
        match route {
            Admission::Replay => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let base = runtime
                    .block_on(
                        fixture
                            .tree
                            .remote
                            .get_root(fixture.tree.volume.as_str(), fixture.tree.seq),
                    )
                    .unwrap()
                    .unwrap();
                let header = granary_core::overlay_journal::JournalHeader {
                    writer: mediator.writer_uuid(),
                    base_root: GrainId::of(&base),
                    base_seq: fixture.tree.seq,
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
            }
            Admission::Landed | Admission::Rejected => {
                let publication = [7; 16];
                let boundary = mediator
                    .overlay_transaction(|t| {
                        let capture = t.capture_boundary()?;
                        t.record_boundary(capture, candidate, publication)
                    })
                    .unwrap();
                if matches!(route, Admission::Landed) {
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
            }
            Admission::Invalidation => mediator.invalidate_clean_content().unwrap(),
        }
        let (prepared, work) = crate::writable_start::measure_preparation(|| {
            ready.backend_for_test().prepare_object(object)
        });
        damage_query_grain(&paths, fixture.tree.file_id, corrupt);
        let backend = ready.backend_for_test();
        let (answer, disk) = crate::overlay_store::local_content::measure_local_reads(|| {
            backend.read_object(object, 0, 65_536)
        });
        observations.push((
            corrupt,
            prepared,
            work,
            backend.materialization_passes,
            backend.object_attached_for_test(object),
            answer.map(|bytes| (bytes.len(), GrainId::of(&bytes))),
            disk.0,
        ));
        backend.overlay_close(object).unwrap();
    }
    assert_eq!(
        (observations.len(), observations),
        (
            2,
            vec![
                (
                    false,
                    Ok(()),
                    (1, 2),
                    2,
                    Some(true),
                    Err(WriteError::Backend(granary_fuse::MountError::Unavailable)),
                    3
                ),
                (
                    true,
                    Ok(()),
                    (1, 2),
                    2,
                    Some(true),
                    Err(WriteError::Backend(granary_fuse::MountError::Corrupt)),
                    3
                ),
            ]
        ),
        "admission must discard both owners and authenticate payload/list/grain: route={route:?}"
    );
}

#[test]
fn writable_spill_replay_requires_fresh_preparation_and_checked_ranges() {
    spill_admission(Admission::Replay);
}

#[test]
fn writable_spill_landed_replacement_requires_fresh_preparation_and_checked_ranges() {
    spill_admission(Admission::Landed);
}

#[test]
fn writable_spill_rejected_replacement_requires_fresh_preparation_and_checked_ranges() {
    spill_admission(Admission::Rejected);
}

#[test]
fn writable_spill_invalidation_preserves_missing_and_corrupt_classes() {
    spill_admission(Admission::Invalidation);
}

#[test]
fn writable_spill_missing_range_evicts_completion_and_refetches_before_success() {
    let paths = query_paths();
    let fixture = clean_tree(&paths, true);
    let input = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let object = ready
        .backend_for_test()
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    ready.backend_for_test().prepare_object(object).unwrap();
    assert_eq!(
        ready.backend_for_test().read_object(object, 0, 65_536),
        Ok(fixture.bytes[..65_536].to_vec()),
        "nonempty warm spill premise"
    );
    ready
        .mediator_for_test()
        .invalidate_clean_content()
        .unwrap();
    ready.backend_for_test().prepare_object(object).unwrap();
    damage_query_grain(&paths, fixture.tree.file_id, false);
    let backend = ready.backend_for_test();
    assert_eq!(
        (
            backend.materialization_passes,
            backend.read_object(object, 0, 65_536)
        ),
        (
            2,
            Err(WriteError::Backend(granary_fuse::MountError::Unavailable))
        ),
        "missing range must be observed before refetch"
    );
    let (answer, work) =
        crate::writable_start::measure_preparation(|| backend.prepare_object(object));
    assert_eq!(
        (
            answer,
            work,
            backend.materialization_passes,
            range_witness(
                backend.read_object(object, 0, 65_536),
                &fixture.bytes[..65_536]
            )
        ),
        (
            Ok(()),
            (1, 2),
            3,
            Ok((true, 65_536, GrainId::of(&fixture.bytes[..65_536])))
        ),
        "loss must remove completion and require another complete spill walk before exact success"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
fn writable_spill_exec_only_change_reuses_content_without_stage_binding() {
    let paths = query_paths();
    let fixture = clean_tree(&paths, true);
    let input = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let object = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    backend.prepare_object(object).unwrap();
    assert_eq!(
        backend.read_object(object, 0, 65_536),
        Ok(fixture.bytes[..65_536].to_vec())
    );
    let mut cases = 0;
    for exec in [true, false] {
        backend
            .overlay_mutate(M::BoundSetattr {
                object,
                size: None,
                exec: Some(exec),
            })
            .unwrap();
        let (((answer, work), disk), preparation) =
            crate::writable_start::measure_preparation(|| {
                crate::overlay_store::local_content::measure_local_reads(|| {
                    crate::overlay_store::measure_query(|| {
                        backend.prepare_object(object)?;
                        let node = backend.overlay_object(object)?;
                        let bytes = backend.read_object(object, 0, 65_536)?;
                        Ok::<_, WriteError>((
                            node.exec,
                            node.stage,
                            bytes.len(),
                            GrainId::of(&bytes),
                        ))
                    })
                })
            });
        assert_eq!(
            (
                answer,
                work,
                disk,
                preparation,
                backend.materialization_passes
            ),
            (
                Ok((exec, None, 65_536, GrainId::of(&fixture.bytes[..65_536]))),
                (0, 0, 2),
                (0, 0),
                (0, 0),
                1
            ),
            "exec-only metadata keeps content completion, verified bytes and clean routing"
        );
        cases += 1;
    }
    assert_eq!((cases, backend.overlay_nodes().unwrap().len()), (2, 3));
    backend.overlay_close(object).unwrap();
}

#[test]
fn writable_multilevel_spill_shared_names_prepare_once_and_reuse_verified_tree() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 131_073, 1);
    let input = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let first = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    let other = backend
        .overlay_open(&handler_path(b"g.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            fixture.bytes.len(),
            fixture.objects,
            first != other,
            backend.overlay_nodes().unwrap().len()
        ),
        (131_073, 8, true, 3),
        "nonempty multi-level shared-content premise"
    );
    let mut rounds = Vec::new();
    for object in [first, other] {
        let (((answers, disk), visits), preparation) =
            crate::writable_start::measure_preparation(|| {
                crate::overlay_store::local_content::measure_metadata_visits(|| {
                    crate::overlay_store::local_content::measure_local_reads(|| {
                        fixture
                            .bytes
                            .chunks(65_536)
                            .enumerate()
                            .map(|(number, expected)| {
                                backend.prepare_object(object).unwrap();
                                let bytes = backend
                                    .read_object(object, (number * 65_536) as u64, 65_536)
                                    .unwrap();
                                assert_eq!(
                                    (bytes == expected, bytes.len(), GrainId::of(&bytes)),
                                    (true, expected.len(), GrainId::of(expected)),
                                    "exact multi-level chunk {number}"
                                );
                                (bytes.len(), GrainId::of(&bytes))
                            })
                            .collect::<Vec<_>>()
                    })
                })
            });
        rounds.push((
            answers,
            disk,
            visits,
            preparation,
            backend.materialization_passes,
        ));
    }
    let expected: Vec<_> = fixture
        .bytes
        .chunks(65_536)
        .map(|bytes| (bytes.len(), GrainId::of(bytes)))
        .collect();
    assert_eq!(
        (rounds.len(), rounds),
        (
            2,
            vec![
                (expected.clone(), (8, fixture.hash_bytes), (1, 7), (3, 4), 1),
                (expected, (0, 0), (0, 7), (0, 0), 1),
            ]
        ),
        "multi-level mount preparation visits all refs once; range cache retains only authenticated hierarchy and grain bytes"
    );
    backend.overlay_close(first).unwrap();
    backend.overlay_close(other).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "each warmed spill fixture keeps natural budget eviction, typed damage and subsequent refetch in one sequence"
)]
fn writable_spill_budget_eviction_reauthenticates_damage_and_refetches_missing_grain() {
    let mut observations = Vec::new();
    for corrupt in [false, true] {
        let paths = query_paths();
        let fixture = clean_tree_with_pressure(&paths, 129, 1024, true);
        let input = input(&fixture.tree, &paths);
        let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let backend = ready.backend_for_test();
        let object = backend
            .overlay_open(&handler_path(b"f.txt"))
            .unwrap()
            .unwrap();
        backend.prepare_object(object).unwrap();
        assert_eq!(
            backend.read_object(object, 0, 65_536),
            Ok(fixture.bytes[..65_536].to_vec()),
            "nonempty spill warm premise"
        );
        assert_eq!(
            (
                fixture.pressure.len(),
                backend.overlay_nodes().unwrap().len()
            ),
            (128, 131),
            "actual pressure-file and namespace cardinalities"
        );
        let mut cases = 0;
        for (name, digest) in &fixture.pressure {
            let file = backend
                .overlay_open(std::slice::from_ref(name))
                .unwrap()
                .unwrap();
            backend.prepare_object(file).unwrap();
            let bytes = backend.read_object(file, 0, 65_536).unwrap();
            assert_eq!(
                (bytes.len(), GrainId::of(&bytes)),
                (65_536, *digest),
                "authenticated pressure-file bytes"
            );
            backend.overlay_close(file).unwrap();
            cases += 1;
        }
        let before = backend.materialization_passes;
        assert_eq!(
            (cases, before),
            (128, 129),
            "distinct completed pressure files"
        );
        damage_query_grain(&paths, fixture.tree.file_id, corrupt);
        let backend = ready.backend_for_test();
        let (answer, work) = crate::overlay_store::local_content::measure_local_reads(|| {
            backend.read_object(object, 0, 65_536)
        });
        observations.push((
            corrupt,
            cases,
            answer.map(|bytes| (bytes.len(), GrainId::of(&bytes))),
            work.0,
            backend.materialization_passes - before,
        ));
        if !corrupt {
            let (prepared, work) =
                crate::writable_start::measure_preparation(|| backend.prepare_object(object));
            assert_eq!(
                (
                    prepared,
                    work,
                    backend.materialization_passes - before,
                    range_witness(
                        backend.read_object(object, 0, 65_536),
                        &fixture.bytes[..65_536]
                    )
                ),
                (
                    Ok(()),
                    (1, 2),
                    1,
                    Ok((true, 65_536, GrainId::of(&fixture.bytes[..65_536])))
                ),
                "actual budget eviction and missing disk bytes must evict the mount completion before refetch"
            );
        }
        backend.overlay_close(object).unwrap();
    }
    assert_eq!(
        (observations.len(), observations),
        (
            2,
            vec![
                (
                    false,
                    128,
                    Err(WriteError::Backend(granary_fuse::MountError::Unavailable)),
                    1,
                    0
                ),
                (
                    true,
                    128,
                    Err(WriteError::Backend(granary_fuse::MountError::Corrupt)),
                    1,
                    0
                ),
            ]
        ),
        "natural grain-budget eviction must keep metadata cached while checking damaged disk grain bytes"
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "paired clean-object routes keep observed damage, eviction and exact retry together"
)]
fn copy_up_content_failure(routes: &[&str]) {
    let mut cases = 0;
    for &route in routes {
        for corrupt in [false, true] {
            let paths = query_paths();
            let fixture = clean_tree(&paths, false);
            let input = input(&fixture.tree, &paths);
            let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            let file = handler_path(b"f.txt");
            let content = ready
                .mediator_for_test()
                .overlay_transaction(|t| {
                    let actual = t.query_path(&file)?;
                    let crate::OverlayQuery::Found(query) = &actual else {
                        panic!("clean fixture query: {actual:?}");
                    };
                    let Some(crate::OverlayKind::File {
                        content: Some(content),
                    }) = query.entry.as_ref().map(|entry| &entry.kind)
                    else {
                        panic!("clean fixture content: {actual:?}");
                    };
                    Ok(*content)
                })
                .unwrap();
            let damaged = if corrupt {
                content
            } else {
                fixture.tree.file_id
            };
            let backend = ready.backend_for_test();
            let object = backend.overlay_open(&file).unwrap().unwrap();
            backend.prepare_object(object).unwrap();
            assert_eq!(
                (
                    backend.materialization_passes,
                    backend.overlay_object(object).unwrap().stage
                ),
                (1, None),
                "warm clean-object premise"
            );
            damage_query_grain(&paths, damaged, corrupt);
            let operation = match route {
                "bound-write" => M::BoundWrite {
                    object,
                    offset: 0,
                    bytes: b"Z",
                    append: false,
                },
                "bound-size" => M::BoundSetattr {
                    object,
                    size: Some(2),
                    exec: None,
                },
                "path-write" => M::Write {
                    path: &file,
                    offset: 0,
                    bytes: b"Z",
                    append: false,
                },
                "path-size" => M::Setattr {
                    path: &file,
                    size: Some(2),
                    exec: None,
                },
                "held-unlink" => M::Remove {
                    path: &file,
                    directory: false,
                },
                _ => unreachable!(),
            };
            let cause = if corrupt {
                granary_fuse::MountError::Corrupt
            } else {
                granary_fuse::MountError::Unavailable
            };
            assert_eq!(
                backend.overlay_mutate(operation),
                Err(WriteError::Backend(cause)),
                "copy-up must observe disk damage, route={route}"
            );
            let prepared = backend.prepare_object(object);
            assert_eq!(
                (prepared, backend.materialization_passes),
                (
                    if corrupt {
                        Err(WriteError::Backend(cause))
                    } else {
                        Ok(())
                    },
                    2
                ),
                "copy-up observation must evict completion before prepare retry, route={route}, corrupt={corrupt}"
            );
            if corrupt {
                damage_query_grain(&paths, damaged, false);
                backend.prepare_object(object).unwrap();
            }
            assert_eq!(
                backend.overlay_mutate(operation),
                Ok(()),
                "refetched content permits retry, route={route}, corrupt={corrupt}"
            );
            backend.overlay_close(object).unwrap();
            cases += 1;
        }
    }
    assert_eq!(
        cases,
        routes.len() * 2,
        "copy-up failure and recovery routes: {cases}"
    );
}

#[test]
fn writable_copy_up_bound_content_failure_evicts_completion_before_retry() {
    copy_up_content_failure(&["bound-write", "bound-size"]);
}
#[test]
fn writable_copy_up_path_content_failure_evicts_completion_before_retry() {
    copy_up_content_failure(&["path-write", "path-size", "held-unlink"]);
}

struct HandoffContent(std::path::PathBuf);
impl granary_core::grainsource::GrainSource for HandoffContent {
    fn has(&self, id: &GrainId) -> bool {
        let store = Store::open(&self.0).unwrap();
        granary_core::grainsource::GrainSource::has(&store, id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, granary_core::grainsource::GrainSourceError> {
        let store = Store::open(&self.0).unwrap();
        granary_core::grainsource::GrainSource::get(&store, id)
    }
}
impl crate::SyncContent for HandoffContent {
    fn payload(&self, _: GrainId) -> Result<FileGrains, crate::CoordinationError> {
        Err(crate::CoordinationError::Overlay(
            crate::OverlayError::ContentUnavailable,
        ))
    }
    fn read_content(&self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, crate::OverlayError> {
        Err(crate::OverlayError::ContentUnavailable)
    }
    fn put_object(&self, _: GrainId, _: &[u8]) -> Result<(), crate::CoordinationError> {
        Ok(())
    }
    fn remember_payload(
        &self,
        _: GrainId,
        _: u64,
        _: &FileGrains,
    ) -> Result<(), crate::CoordinationError> {
        Ok(())
    }
}

fn attach_test_sync(
    ready: &mut crate::WritableReadiness<Authority, OverlayDisk>,
    paths: &Paths,
    tree: &PublishedTree,
    state: &Arc<Mutex<AuthorityState>>,
) -> Arc<
    crate::SyncEngine<
        OverlayDisk,
        Authority,
        HandoffContent,
        Time,
        crate::InstantClock,
        crate::TokioSyncRuntime,
    >,
> {
    let authority = Arc::new(Authority::new(tree, state));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let metrics = crate::ClientMetrics::new(&mut Entropy(9));
    runtime
        .block_on(ready.backend_for_test().attach_sync(
            authority,
            Arc::new(HandoffContent(paths.scratch.join("publication"))),
            Arc::new(Time(Arc::clone(state))),
            Arc::new(crate::InstantClock::default()),
            metrics,
            Entropy(10),
        ))
        .unwrap()
}

fn file_content_id(
    ready: &mut crate::WritableReadiness<Authority, OverlayDisk>,
    name: &[u8],
) -> GrainId {
    let path = handler_path(name);
    ready
        .backend_for_test()
        .shared_mediator()
        .overlay_transaction(|overlay| {
            let crate::OverlayQuery::Found(query) = overlay.query_path(&path)? else {
                panic!("clean fixture query missing");
            };
            let Some(&crate::OverlayKind::File {
                content: Some(content),
            }) = query.entry.as_ref().map(|entry| &entry.kind)
            else {
                panic!("clean fixture content missing");
            };
            Ok(content)
        })
        .unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "verifies production attach->warm->land->observe order and secondary prewarmed handoff control together"
)]
fn sync_handoff_invalidates_both_caches() {
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 131_073, 1, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let spill_content = file_content_id(&mut ready, b"f.txt");
    let (inline_name, inline_grain) = fixture.pressure[0].clone();
    let inline_content = file_content_id(&mut ready, inline_name.as_bytes());
    assert_eq!(
        (
            ready.backend_for_test().range_cache_snapshot_for_test(),
            ready.backend_for_test().completion_tokens_for_test(),
        ),
        ((1, 0, 0, 0, 0), (None, 0, None)),
        "initial unattached cache and token state"
    );

    // Primary order: attach sync engine before mounting, prove sole mediator/flock and initial generation,
    // then warm nonempty inline and multilevel-spill files, then drive real landing and observe_engine_view.
    let engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &state);
    let duplicate = {
        let authority = Arc::new(Authority::new(&fixture.tree, &state));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let metrics = crate::ClientMetrics::new(&mut Entropy(11));
        runtime.block_on(ready.backend_for_test().attach_sync(
            authority,
            Arc::new(HandoffContent(paths.scratch.join("publication"))),
            Arc::new(Time(Arc::clone(&state))),
            Arc::new(crate::InstantClock::default()),
            metrics,
            Entropy(12),
        ))
    };
    assert_eq!(
        (
            matches!(
                duplicate,
                Err(crate::CoordinationError::Refused(
                    "SyncEngineAlreadyAttached"
                ))
            ),
            matches!(Store::open(&paths.store), Err(crate::StoreError::Locked)),
            Arc::strong_count(&ready.backend_for_test().shared_mediator().as_arc()),
            ready.backend_for_test().range_cache_snapshot_for_test(),
            ready.backend_for_test().completion_tokens_for_test(),
        ),
        // The mount, the engine and its content, the view binding the
        // attach leaves for the adapter, and the engine's shutdown share
        // the one mediator.
        (true, true, 5, (2, 0, 0, 0, 0), (Some(2), 0, None)),
        "attach_sync must share the sole mediator/flock, refuse duplicate attach, and advance initial cache generation"
    );

    let file = handler_path(b"f.txt");
    let spill_obj = ready
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    let inline_obj = ready
        .backend_for_test()
        .overlay_open(std::slice::from_ref(&inline_name))
        .unwrap()
        .unwrap();
    let (warm_spill_prep, warm_spill_work) = crate::writable_start::measure_preparation(|| {
        ready.backend_for_test().prepare_object(spill_obj)
    });
    let warm_spill_read = ready.backend_for_test().read_object(spill_obj, 0, 65_536);
    let (warm_inline_prep, warm_inline_work) = crate::writable_start::measure_preparation(|| {
        ready.backend_for_test().prepare_object(inline_obj)
    });
    let warm_inline_read = ready.backend_for_test().read_object(inline_obj, 0, 65_536);
    let (_, cached_work) = crate::writable_start::measure_preparation(|| {
        ready.backend_for_test().prepare_object(spill_obj).unwrap();
        ready.backend_for_test().prepare_object(inline_obj)
    });
    let warm_snapshot = ready.backend_for_test().range_cache_snapshot_for_test();
    assert_eq!(
        (
            warm_spill_prep,
            warm_spill_work,
            warm_spill_read == Ok(fixture.bytes[..65_536].to_vec()),
            warm_inline_prep,
            warm_inline_work,
            warm_inline_read.as_ref().map(|b| (b.len(), GrainId::of(b))),
            cached_work,
            ready.backend_for_test().materialization_passes,
            (
                warm_snapshot.0,
                warm_snapshot.1 > 0,
                warm_snapshot.2 > 0,
                warm_snapshot.3 > 0,
                warm_snapshot.4 > 0,
            ),
            ready.backend_for_test().completion_tokens_for_test(),
        ),
        (
            Ok(()),
            (3, 4),
            true,
            Ok(()),
            (0, 1),
            Ok((65_536, inline_grain)),
            (0, 0),
            2,
            (2, true, true, true, true),
            (Some(2), 2, Some(spill_content.min(inline_content))),
        ),
        "attached warm premise must populate both range_cache and completion_tokens for multilevel-spill and inline files"
    );

    let mediator = ready.backend_for_test().shared_mediator().clone();
    let _landed = drive_real_landing(&engine, &mediator, &fixture.tree);
    let observed = ready.backend_for_test().observe_engine_view();
    assert_eq!(
        (
            observed,
            ready.backend_for_test().range_cache_snapshot_for_test(),
            ready.backend_for_test().completion_tokens_for_test(),
            ready.backend_for_test().prepare_object(spill_obj),
            ready.backend_for_test().read_object(spill_obj, 0, 65_536),
            ready.backend_for_test().read_object(inline_obj, 0, 65_536),
        ),
        (
            Err(granary_fuse::MountError::Io),
            (3, 0, 0, 0, 0),
            (Some(3), 0, None),
            Err(WriteError::Backend(granary_fuse::MountError::Io)),
            Err(WriteError::Backend(granary_fuse::MountError::Io)),
            Err(WriteError::Backend(granary_fuse::MountError::Io)),
        ),
        "primary attach -> warm -> land -> observe order must clear both caches and close view with EIO"
    );
    ready.backend_for_test().overlay_close(inline_obj).unwrap();
    ready.backend_for_test().overlay_close(spill_obj).unwrap();

    // Secondary robustness control: prewarmed direct-backend before attach_sync.
    let paths_pre = query_paths();
    let fixture_pre = clean_tree(&paths_pre, true);
    let input_pre = input(&fixture_pre.tree, &paths_pre);
    let (ready_pre, state_pre, _) =
        attempt(&input_pre, &fixture_pre.tree, "valid", &Events::default());
    let mut ready_pre = ready_pre.unwrap();
    let content_pre = file_content_id(&mut ready_pre, b"f.txt");
    let object_pre = ready_pre
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    ready_pre
        .backend_for_test()
        .prepare_object(object_pre)
        .unwrap();
    assert_eq!(
        ready_pre
            .backend_for_test()
            .read_object(object_pre, 0, 65_536),
        Ok(fixture_pre.bytes[..65_536].to_vec()),
        "prewarmed direct-backend premise"
    );
    let pre_handoff = (
        ready_pre.backend_for_test().range_cache_snapshot_for_test(),
        ready_pre.backend_for_test().completion_tokens_for_test(),
        ready_pre.backend_for_test().materialization_passes,
    );
    let _engine_pre = attach_test_sync(&mut ready_pre, &paths_pre, &fixture_pre.tree, &state_pre);
    let post_handoff = (
        ready_pre.backend_for_test().range_cache_snapshot_for_test(),
        ready_pre.backend_for_test().completion_tokens_for_test(),
    );
    let (post_prepare, post_work) = crate::writable_start::measure_preparation(|| {
        ready_pre.backend_for_test().prepare_object(object_pre)
    });
    assert_eq!(
        (
            pre_handoff,
            post_handoff,
            post_prepare,
            post_work,
            ready_pre.backend_for_test().materialization_passes,
            ready_pre.backend_for_test().completion_tokens_for_test(),
        ),
        (
            ((1, 2, 2, 8923, 6144), (Some(1), 1, Some(content_pre)), 1),
            ((2, 0, 0, 0, 0), (Some(2), 0, None)),
            Ok(()),
            (1, 2),
            2,
            (Some(2), 1, Some(content_pre)),
        ),
        "prewarmed robustness control must also invalidate both caches across attach_sync"
    );
    ready_pre
        .backend_for_test()
        .overlay_close(object_pre)
        .unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "verifies real landing trace ordering, cache invalidation, and sticky ViewPending EIO across all callback families"
)]
fn engine_landing_closes_old_mount_view() {
    let paths = query_paths();
    let fixture = clean_tree(&paths, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let content = file_content_id(&mut ready, b"f.txt");
    let engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &state);
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
            ready.backend_for_test().range_cache_snapshot_for_test(),
            ready.backend_for_test().completion_tokens_for_test(),
        ),
        (
            Ok(fixture.bytes[..65_536].to_vec()),
            (2, 2, 2, 8923, 6144),
            (Some(2), 1, Some(content)),
        ),
        "warmed attached mount premise before engine commit landing"
    );

    let mediator = ready.backend_for_test().shared_mediator().clone();
    let faults = mediator.with(|local| Ok(local.fault_control())).unwrap();
    faults.trace_sync();
    let sends_before = state.lock().unwrap().sends.len();
    let landed_root = drive_real_landing(&engine, &mediator, &fixture.tree);
    let sends_after_landing = state.lock().unwrap().sends.len();

    let pinned_root = ready.verified_base().2;
    let backend = ready.backend_for_test();
    let observed = backend.observe_engine_view();
    let raw_events = faults.sync_fired();
    let view_requests: Vec<_> = raw_events
        .iter()
        .filter(|e| e.name == "fuse.sync.view")
        .map(|e| (e.phase, e.capture, e.request))
        .collect();
    let fired: Vec<_> = raw_events
        .into_iter()
        .map(|e| (e.name, e.phase, e.capture, e.request.is_some()))
        .collect();
    let snapshot = backend.range_cache_snapshot_for_test();
    let tokens = backend.completion_tokens_for_test();
    let prepare = backend.prepare_object(object);
    let read = backend.read_object(object, 0, 65_536);
    let lookup = backend.overlay_lookup(&[], &Name::new(b"f.txt".to_vec()).unwrap());
    let directory = backend.overlay_directory(&[]).err();
    let nodes = backend.overlay_nodes();
    let mutate = backend.overlay_mutate(M::BoundWrite {
        object,
        offset: 0,
        bytes: b"Z",
        append: false,
    });
    let readiness = backend.mutation_readiness();
    let repeat = backend.observe_engine_view();
    let phase = mediator.with(|local| Ok(local.snapshot().phase)).unwrap();
    let sends_after_view_pending = state.lock().unwrap().sends.len();
    assert_eq!(
        (
            (
                sends_after_landing - sends_before,
                fired,
                view_requests,
                observed,
                snapshot,
                tokens
            ),
            (
                prepare, read, lookup, directory, nodes, mutate, readiness, repeat
            ),
            (
                phase,
                sends_after_view_pending - sends_after_landing,
                backend.materialization_passes
            ),
        ),
        (
            (
                1,
                vec![
                    ("sync.commit", "captured", 1, false),
                    ("sync.commit", "boundary_recorded", 1, false),
                    ("sync.commit", "landed_readback", 1, false),
                    ("sync.commit", "landed_refresh", 1, true),
                    ("sync.registration", "before_dispatch", 0, true),
                    ("sync.registration", "after_response", 0, true),
                    ("sync.commit", "before_replace", 1, false),
                    ("fuse.sync.view", "observed", 2, true),
                    ("fuse.sync.view", "cleared", 3, true),
                ],
                vec![
                    ("observed", 2, Some(pinned_root)),
                    ("cleared", 3, Some(landed_root)),
                ],
                Err(granary_fuse::MountError::Io),
                (3, 0, 0, 0, 0),
                (Some(3), 0, None),
            ),
            (
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
                Some(WriteError::Backend(granary_fuse::MountError::Io)),
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
                Err(granary_fuse::MountError::Io),
                Err(granary_fuse::MountError::Io),
            ),
            (granary_core::overlay_ownership::Phase::Serving, 0, 1),
        ),
        "real finish_landed_commit must refresh intent before replacement, clear both caches, and close the old mount view with EIO without fencing: landed_root={landed_root}"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "exercises warm hits, facade recreation, staged fast route, missing/corrupt refetch, generation exhaustion, and fence together"
)]
fn view_invalidation_requires_fresh_preparation() {
    let mut observations = Vec::new();
    for corrupt in [false, true] {
        let paths = query_paths();
        let fixture = clean_tree(&paths, true);
        let input_cfg = input(&fixture.tree, &paths);
        let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let content = file_content_id(&mut ready, b"f.txt");
        let _engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &state);
        let file = handler_path(b"f.txt");
        let staged_path = handler_path(b"g.txt");
        let object = ready
            .backend_for_test()
            .overlay_open(&file)
            .unwrap()
            .unwrap();
        let staged_object = ready
            .backend_for_test()
            .overlay_open(&staged_path)
            .unwrap()
            .unwrap();
        ready.backend_for_test().prepare_object(object).unwrap();
        assert_eq!(
            ready.backend_for_test().read_object(object, 0, 65_536),
            Ok(fixture.bytes[..65_536].to_vec()),
            "warm clean object before view invalidation"
        );
        // Verify warmed hits across WritableOverlay facade recreation.
        let ((), warm_prep_work) = crate::writable_start::measure_preparation(|| {
            ready.backend_for_test().prepare_object(object).unwrap();
        });
        let (warm_hit, warm_disk) =
            crate::overlay_store::local_content::measure_local_reads(|| {
                ready
                    .backend_for_test()
                    .shared_mediator()
                    .overlay_transaction(|t| t.read_base(&file, 0, 65_536))
                    .unwrap()
            });
        ready
            .backend_for_test()
            .overlay_mutate(M::BoundWrite {
                object: staged_object,
                offset: 0,
                bytes: b"Z",
                append: false,
            })
            .unwrap();
        assert_eq!(
            (
                warm_prep_work,
                warm_hit == fixture.bytes[..65_536],
                warm_disk,
                ready.backend_for_test().range_cache_snapshot_for_test(),
                ready.backend_for_test().completion_tokens_for_test(),
                ready
                    .backend_for_test()
                    .overlay_object(staged_object)
                    .unwrap()
                    .stage
                    .is_some(),
            ),
            (
                (0, 0),
                true,
                (0, 0),
                (2, 2, 2, 8923, 6144),
                (Some(2), 1, Some(content)),
                true,
            ),
            "warmed clean and staged premise before invalidation"
        );

        let faults = ready
            .backend_for_test()
            .shared_mediator()
            .with(|local| {
                local.invalidate_clean_content()?;
                Ok(local.fault_control())
            })
            .unwrap();
        faults.trace_sync();
        // Exercise the staged fast route first: even when stage_id.is_some(),
        // prepare_object must observe the new generation and clear completion_tokens.
        let staged_prepare = ready.backend_for_test().prepare_object(staged_object);
        let view_events: Vec<_> = faults
            .sync_fired()
            .into_iter()
            .map(|event| (event.name, event.phase, event.capture, event.object_kind))
            .collect();
        let tokens_after_staged = ready.backend_for_test().completion_tokens_for_test();
        let snapshot_after_invalidation = ready.backend_for_test().range_cache_snapshot_for_test();

        let (prepared, work) = crate::writable_start::measure_preparation(|| {
            ready.backend_for_test().prepare_object(object)
        });
        damage_query_grain(&paths, fixture.tree.file_id, corrupt);
        let backend = ready.backend_for_test();
        let (answer, disk) = crate::overlay_store::local_content::measure_local_reads(|| {
            backend.read_object(object, 0, 65_536)
        });
        let tokens_after_damage = backend.completion_tokens_for_test();
        let passes_after_damage = backend.materialization_passes;
        if corrupt {
            damage_query_grain(&paths, fixture.tree.file_id, false);
        }
        let (reprepared, refetch_work) = crate::writable_start::measure_preparation(|| {
            ready.backend_for_test().prepare_object(object)
        });
        let restored = ready.backend_for_test().read_object(object, 0, 65_536);
        ready
            .backend_for_test()
            .overlay_close(staged_object)
            .unwrap();
        ready.backend_for_test().overlay_close(object).unwrap();
        let terminal_ok = if corrupt {
            ready
                .backend_for_test()
                .shared_mediator()
                .phase_for_test(granary_core::overlay_ownership::Phase::Fenced)
                .is_ok()
        } else {
            matches!(
                ready.backend_for_test().shared_mediator().with(|local| {
                    local.clean_generation_for_test(18_446_744_073_709_551_615);
                    local.invalidate_clean_content()
                }),
                Err(crate::CoordinationError::Overlay(
                    crate::OverlayError::Poisoned
                ))
            )
        };
        let terminal_view = ready.backend_for_test().observe_engine_view();
        observations.push((
            (
                corrupt,
                staged_prepare,
                view_events,
                snapshot_after_invalidation,
                tokens_after_staged,
            ),
            (
                prepared,
                work,
                passes_after_damage,
                answer.map(|bytes| (bytes.len(), GrainId::of(&bytes))),
                disk.0,
                tokens_after_damage,
            ),
            (
                reprepared,
                refetch_work,
                restored == Ok(fixture.bytes[..65_536].to_vec()),
                terminal_ok,
                terminal_view,
            ),
        ));
    }
    assert_eq!(
        (observations.len(), observations),
        (
            2,
            vec![
                (
                    (
                        false,
                        Ok(()),
                        vec![
                            ("fuse.sync.view", "observed", 2, "none"),
                            ("fuse.sync.view", "cleared", 3, "none"),
                        ],
                        (3, 0, 0, 0, 0),
                        (Some(3), 0, None),
                    ),
                    (
                        Ok(()),
                        (1, 2),
                        2,
                        Err(WriteError::Backend(granary_fuse::MountError::Unavailable)),
                        3,
                        (Some(3), 0, None),
                    ),
                    (
                        Ok(()),
                        (1, 2),
                        true,
                        true,
                        Err(granary_fuse::MountError::Io),
                    ),
                ),
                (
                    (
                        true,
                        Ok(()),
                        vec![
                            ("fuse.sync.view", "observed", 2, "none"),
                            ("fuse.sync.view", "cleared", 3, "none"),
                        ],
                        (3, 0, 0, 0, 0),
                        (Some(3), 0, None),
                    ),
                    (
                        Ok(()),
                        (1, 2),
                        2,
                        Err(WriteError::Backend(granary_fuse::MountError::Corrupt)),
                        3,
                        (Some(3), 0, None),
                    ),
                    (
                        Ok(()),
                        (1, 2),
                        true,
                        true,
                        Err(granary_fuse::MountError::Stale),
                    ),
                ),
            ]
        ),
        "generation advance without base mismatch must clear completion_tokens, force fresh preparation, preserve Unavailable vs Corrupt, succeed after refetch, and enforce exhaustion/fencing"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "verifies both post-materialization planning landing and mid-materialization warm-token landing together"
)]
fn landing_during_materialization_closes_view_without_token_use() {
    // Arm 1: landing inside change_planning_context (between iteration 1's materialization and
    // post-preparation / iteration 2) must refuse with ViewPending EIO without retrying or
    // repopulating completion_tokens under the changed base.
    let paths_plan = query_paths();
    let fixture_plan = clean_tree(&paths_plan, true);
    let input_plan = input(&fixture_plan.tree, &paths_plan);
    let (ready_plan, state_plan, _) =
        attempt(&input_plan, &fixture_plan.tree, "valid", &Events::default());
    let mut ready_plan = ready_plan.unwrap();
    let engine_plan = attach_test_sync(
        &mut ready_plan,
        &paths_plan,
        &fixture_plan.tree,
        &state_plan,
    );
    let file = handler_path(b"f.txt");
    let obj_plan = ready_plan
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    let tree_plan = fixture_plan.tree;
    let engine_for_plan = std::sync::Arc::clone(&engine_plan);
    ready_plan.backend_for_test().planning_hook = Some(Box::new(move |mediator| {
        let _ = drive_real_landing(&engine_for_plan, mediator, &tree_plan);
    }));
    let prepare_plan = ready_plan.backend_for_test().prepare_object(obj_plan);
    let plan_state = (
        prepare_plan,
        ready_plan.backend_for_test().planning_attempts,
        ready_plan.backend_for_test().materialization_passes,
        ready_plan.backend_for_test().completion_tokens_for_test(),
        ready_plan
            .backend_for_test()
            .read_object(obj_plan, 0, 65_536),
    );
    ready_plan
        .backend_for_test()
        .overlay_close(obj_plan)
        .unwrap();

    // Arm 2: landing between preparation_context and materialize_once on an already-warmed
    // token must refuse with ViewPending EIO before consulting completion_tokens.contains.
    let paths_mid = query_paths();
    let fixture_mid = clean_tree(&paths_mid, true);
    let input_mid = input(&fixture_mid.tree, &paths_mid);
    let (ready_mid, state_mid, _) =
        attempt(&input_mid, &fixture_mid.tree, "valid", &Events::default());
    let mut ready_mid = ready_mid.unwrap();
    let content_mid = file_content_id(&mut ready_mid, b"f.txt");
    let engine_mid = attach_test_sync(&mut ready_mid, &paths_mid, &fixture_mid.tree, &state_mid);
    let obj_mid = ready_mid
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    ready_mid
        .backend_for_test()
        .prepare_object(obj_mid)
        .unwrap();
    assert_eq!(
        (
            ready_mid.backend_for_test().completion_tokens_for_test(),
            ready_mid.backend_for_test().materialization_passes,
        ),
        ((Some(2), 1, Some(content_mid)), 1),
        "warm token premise before mid-materialization landing"
    );
    ready_mid.backend_for_test().planning_attempts = 0;
    let tree_mid = fixture_mid.tree;
    let engine_for_mid = std::sync::Arc::clone(&engine_mid);
    ready_mid.backend_for_test().before_materialize_hook = Some(Box::new(move |mediator| {
        let _ = drive_real_landing(&engine_for_mid, mediator, &tree_mid);
    }));
    let consulted_stale_token = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let consulted_flag = std::sync::Arc::clone(&consulted_stale_token);
    ready_mid.backend_for_test().planning_hook = Some(Box::new(move |_| {
        consulted_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }));
    let (prepare_mid, mid_work) = crate::writable_start::measure_preparation(|| {
        ready_mid.backend_for_test().prepare_object(obj_mid)
    });
    let mid_state = (
        prepare_mid,
        consulted_stale_token.load(std::sync::atomic::Ordering::SeqCst),
        mid_work,
        ready_mid.backend_for_test().planning_attempts,
        ready_mid.backend_for_test().materialization_passes,
        ready_mid.backend_for_test().completion_tokens_for_test(),
    );
    ready_mid.backend_for_test().overlay_close(obj_mid).unwrap();

    assert_eq!(
        (plan_state, mid_state),
        (
            (
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
                1,
                1,
                (Some(3), 0, None),
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
            ),
            (
                Err(WriteError::Backend(granary_fuse::MountError::Io)),
                false,
                (0, 0),
                1,
                1,
                (Some(3), 0, None),
            ),
        ),
        "a commit landing during preparation/materialization must latch ViewPending EIO without consulting or repopulating completion_tokens"
    );
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "ergonomic call site for Result::err() options in test assertions"
)]
fn refused_reason(err: Option<crate::CoordinationError>) -> Option<&'static str> {
    match err {
        Some(crate::CoordinationError::Refused(reason)) => Some(reason),
        _ => None,
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "exercises injected with_runtime failure, mediator flag preservation, repeated failure cause, recovery, and post-attach duplicate refusal"
)]
fn failed_attach_sync_preserves_signer_and_mediator_for_retry() {
    struct ToggleHandoffContent {
        inner: HandoffContent,
        fail_get: std::sync::atomic::AtomicBool,
    }
    impl granary_core::grainsource::GrainSource for ToggleHandoffContent {
        fn has(&self, id: &GrainId) -> bool {
            self.inner.has(id)
        }
        fn get(
            &self,
            id: &GrainId,
        ) -> Result<Vec<u8>, granary_core::grainsource::GrainSourceError> {
            if self.fail_get.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(b"corrupt".to_vec());
            }
            self.inner.get(id)
        }
    }
    impl crate::SyncContent for ToggleHandoffContent {
        fn payload(&self, id: GrainId) -> Result<FileGrains, crate::CoordinationError> {
            self.inner.payload(id)
        }
        fn read_content(
            &self,
            id: GrainId,
            offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, crate::OverlayError> {
            self.inner.read_content(id, offset, length)
        }
        fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), crate::CoordinationError> {
            self.inner.put_object(id, bytes)
        }
        fn remember_payload(
            &self,
            id: GrainId,
            size: u64,
            grains: &FileGrains,
        ) -> Result<(), crate::CoordinationError> {
            self.inner.remember_payload(id, size, grains)
        }
    }

    let paths = query_paths();
    let fixture = clean_tree(&paths, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let content = Arc::new(ToggleHandoffContent {
        inner: HandoffContent(paths.scratch.join("publication")),
        fail_get: std::sync::atomic::AtomicBool::new(true),
    });
    let make_authority = || Arc::new(Authority::new(&fixture.tree, &state));

    // 1. Inject a with_runtime failure during VerifiedBase::attach_validated.
    let first_err = refused_reason(
        runtime
            .block_on(ready.backend_for_test().attach_sync(
                make_authority(),
                Arc::clone(&content),
                Arc::new(Time(Arc::clone(&state))),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(11)),
                Entropy(15),
            ))
            .err(),
    );
    let flags_after_first = ready
        .backend_for_test()
        .shared_mediator()
        .with(|local| Ok((local.engine_attached(), local.sync_admission_open().ok())))
        .unwrap();

    // 2. Retry while fault is still active: must report the real SyncBase cause, never a false SyncEngineAlreadyAttached.
    let second_err = refused_reason(
        runtime
            .block_on(ready.backend_for_test().attach_sync(
                make_authority(),
                Arc::clone(&content),
                Arc::new(Time(Arc::clone(&state))),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(12)),
                Entropy(16),
            ))
            .err(),
    );
    let flags_after_second = ready
        .backend_for_test()
        .shared_mediator()
        .with(|local| Ok((local.engine_attached(), local.sync_admission_open().ok())))
        .unwrap();

    // 3. Clear the fault and retry: attach_sync must succeed and install the engine cleanly.
    content
        .fail_get
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let third_ok = runtime
        .block_on(ready.backend_for_test().attach_sync(
            make_authority(),
            Arc::clone(&content),
            Arc::new(Time(Arc::clone(&state))),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(13)),
            Entropy(17),
        ))
        .is_ok();
    let flags_after_third = ready
        .backend_for_test()
        .shared_mediator()
        .with(|local| Ok((local.engine_attached(), local.sync_admission_open().ok())))
        .unwrap();
    let fourth_err = refused_reason(
        runtime
            .block_on(ready.backend_for_test().attach_sync(
                make_authority(),
                Arc::clone(&content),
                Arc::new(Time(Arc::clone(&state))),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(14)),
                Entropy(18),
            ))
            .err(),
    );

    assert_eq!(
        (
            first_err,
            flags_after_first,
            second_err,
            flags_after_second,
            third_ok,
            flags_after_third,
            fourth_err,
        ),
        (
            Some("SyncBase"),
            (false, Some(true)),
            Some("SyncBase"),
            (false, Some(true)),
            true,
            (true, Some(true)),
            Some("SyncEngineAlreadyAttached"),
        ),
        "failed attach_sync must preserve signer key and mediator flags so retries report the real cause and succeed once resolved"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "verifies inline and multilevel spill round-trip, range bounds, corrupt grain/spill rejection, cache generation invalidation, readiness, and single mediator Store together"
)]
fn mount_sync_content_authenticates_inline_spill_and_bounds() {
    use crate::SyncContent as _;
    use granary_core::grainsource::GrainSource as _;
    use granary_core::overlay_ownership::Phase;

    use crate::SyncRuntime as _;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 131_073, 1, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let spill_content = file_content_id(&mut ready, b"f.txt");
    let (inline_name, inline_grain) = fixture.pressure[0].clone();
    let inline_content = file_content_id(&mut ready, inline_name.as_bytes());
    let authority = Arc::new(Authority::new(&fixture.tree, &state));
    let content = ready
        .backend_for_test()
        .sync_content(Arc::clone(&authority))
        .unwrap();
    let content = content.with_deadline(
        Arc::new(crate::TokioSyncRuntime),
        crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(30),
    );
    let mediator = ready.backend_for_test().shared_mediator().clone();

    // 1. Valid inline and multilevel-spill files round-trip through the one mediator Store.
    let inline_grains = content.payload(inline_content).unwrap();
    let spill_grains = content.payload(spill_content).unwrap();
    let FileGrains::Spill {
        grain_count: spill_count,
        root: spill_root,
    } = spill_grains
    else {
        panic!("expected spilled FileGrains for f.txt, got {spill_grains:?}");
    };
    let inline_bytes = content.read_content(inline_content, 0, 65_536).unwrap();
    let spill_head = content.read_content(spill_content, 0, 1024).unwrap();
    let spill_tail = content.read_content(spill_content, 131_072, 1).unwrap();
    let novel_grain = b"novel-sync-content-grain".to_vec();
    let novel_grain_id = GrainId::of(&novel_grain);
    content.put_object(novel_grain_id, &novel_grain).unwrap();
    let novel_file_grains = FileGrains::Inline(vec![GrainRef {
        id: novel_grain_id,
        unpacked_len: u32::try_from(novel_grain.len()).unwrap(),
    }]);
    let novel_payload_bytes =
        manifest::node::file_payload(novel_grain.len() as u64, &novel_file_grains).unwrap();
    let novel_content_id = GrainId::of(&novel_payload_bytes);
    content
        .remember_payload(
            novel_content_id,
            novel_grain.len() as u64,
            &novel_file_grains,
        )
        .unwrap();
    let novel_roundtrip = content.read_content(novel_content_id, 0, novel_grain.len());
    let mediator_has_all = mediator
        .with(|local| {
            let imm = local.immutable_content()?;
            Ok((
                imm.has(&inline_content),
                imm.has(&inline_grain),
                imm.has(&spill_content),
                imm.has(&spill_root),
                imm.has(&novel_grain_id),
                imm.has(&novel_content_id),
            ))
        })
        .unwrap();
    let cache_after_valid = ready.backend_for_test().range_cache_snapshot_for_test();
    assert_eq!(
        (
            matches!(Store::open(&paths.store), Err(crate::StoreError::Locked)),
            inline_grains
                == FileGrains::Inline(vec![GrainRef {
                    id: inline_grain,
                    unpacked_len: 65_536,
                }]),
            spill_count,
            GrainId::of(&inline_bytes),
            spill_head == fixture.bytes[..1024],
            spill_tail == fixture.bytes[131_072..131_073],
            novel_roundtrip.ok().as_deref() == Some(novel_grain.as_slice()),
            mediator_has_all,
            (
                cache_after_valid.0,
                cache_after_valid.1 >= 3,
                cache_after_valid.2 >= 3,
                cache_after_valid.3 > 0,
            ),
        ),
        (
            true,
            true,
            131_073,
            inline_grain,
            true,
            true,
            true,
            (true, true, true, true, true, true),
            (1, true, true, true),
        ),
        "valid inline, multilevel-spill, and remembered files must round-trip through the sole mediator Store and VerifiedRangeCache"
    );

    // 2. Hash mismatch on put_object / remember_payload and out-of-bounds ranges are refused.
    let bad_put = content.put_object(inline_grain, b"wrong-bytes");
    let bad_remember = content.remember_payload(inline_content, 999, &novel_file_grains);
    let oob_inline = content.read_content(inline_content, 65_536, 1);
    let oob_spill = content.read_content(spill_content, 131_073, 1);
    let oob_buffer = content.read_content(spill_content, 0, 65_537);
    let oob_overflow = content.read_content(inline_content, u64::MAX, 1);
    assert_eq!(
        (
            matches!(
                bad_put,
                Err(crate::CoordinationError::Overlay(
                    crate::OverlayError::ContentCorrupt
                ))
            ),
            matches!(
                bad_remember,
                Err(crate::CoordinationError::Overlay(
                    crate::OverlayError::ContentCorrupt
                ))
            ),
            matches!(oob_inline, Err(crate::OverlayError::ContentCorrupt)),
            matches!(oob_spill, Err(crate::OverlayError::ContentCorrupt)),
            matches!(oob_buffer, Err(crate::OverlayError::ContentCorrupt)),
            matches!(oob_overflow, Err(crate::OverlayError::ContentCorrupt)),
        ),
        (true, true, true, true, true, true),
        "hash mismatches and out-of-bounds ranges must be refused with ContentCorrupt"
    );

    // 3. Generation-invalidated cache entries must re-read the mediator Store and refuse corrupt grain bytes and tampered spill nodes.
    damage_query_grain(&paths, inline_grain, true);
    damage_query_grain(&paths, spill_root, true);
    // While generation 1 remains active, VerifiedRangeCache still holds the warmed verified entries;
    // invalidating clean content advances to generation 2 and evicts generation-1 cache entries.
    let gen_after_invalidation = mediator
        .with(|local| {
            local.invalidate_clean_content()?;
            Ok(local.mount_view_context()?.generation)
        })
        .unwrap();
    let corrupt_inline_read = content.read_content(inline_content, 0, 64);
    let corrupt_inline_get = content.get(&inline_grain);
    let tampered_spill_read = content.read_content(spill_content, 0, 64);
    assert_eq!(
        (
            gen_after_invalidation,
            matches!(
                corrupt_inline_read,
                Err(crate::OverlayError::ContentCorrupt)
            ),
            corrupt_inline_get,
            matches!(
                tampered_spill_read,
                Err(crate::OverlayError::ContentCorrupt)
            ),
        ),
        (
            2,
            true,
            Err(granary_core::grainsource::GrainSourceError::Corrupt(
                inline_grain
            )),
            true,
        ),
        "generation-invalidated cache entry must re-read from mediator Store and refuse corrupt grain bytes and tampered spill node"
    );

    // 4. Readiness check on the mediator: unready phase refuses all content routes while Serving allows them.
    let serving_read = content.read_content(novel_content_id, 0, novel_grain.len());
    mediator.phase_for_test(Phase::Releasing).unwrap();
    let unready_payload = content.payload(novel_content_id);
    let unready_read = content.read_content(novel_content_id, 0, 4);
    let unready_put = content.put_object(novel_grain_id, &novel_grain);
    let unready_fetch = content.fetch_immutable(novel_grain_id);
    let unready_has = content.has(&novel_grain_id);
    assert_eq!(
        (
            serving_read.ok().as_deref() == Some(novel_grain.as_slice()),
            matches!(
                unready_payload,
                Err(crate::CoordinationError::Refused(
                    "WritableRecoveryRequired"
                ))
            ),
            matches!(
                unready_read,
                Err(crate::OverlayError::Refused("WritableRecoveryRequired"))
            ),
            matches!(
                unready_put,
                Err(crate::CoordinationError::Refused(
                    "WritableRecoveryRequired"
                ))
            ),
            matches!(
                unready_fetch,
                Err(crate::CoordinationError::Refused(
                    "WritableRecoveryRequired"
                ))
            ),
            unready_has,
        ),
        (true, true, true, true, true, false),
        "unready mediator must refuse every content route while Phase::Serving serves verified content"
    );
}

#[test]
fn mount_sync_content_drops_mediator_before_fetch() {
    use crate::SyncRuntime as _;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 3, 65_536, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let (_, cold_grain_id) = fixture.pressure[0].clone();
    let pause = RangeReadPause::armed();
    let remote =
        Arc::new(Authority::new(&fixture.tree, &state).with_range_pause(Arc::clone(&pause)));
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(Arc::clone(&remote))
            .unwrap(),
    );
    let content = Arc::new(content.with_deadline(
        Arc::new(crate::TokioSyncRuntime),
        crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(30),
    ));
    let mediator = ready.backend_for_test().shared_mediator().clone();
    let present_before = mediator
        .with(|local| Ok(local.immutable_content()?.has(&cold_grain_id)))
        .unwrap();

    let worker_content = Arc::clone(&content);
    let worker_runtime = runtime.handle().clone();
    let handle = std::thread::spawn(move || {
        let _entered = worker_runtime.enter();
        worker_content.fetch_immutable(cold_grain_id)
    });

    // Wait until get_bin_range is actively in flight.
    assert!(
        pause.wait_entered(),
        "cold fetch get_bin_range must be entered within bounded wait"
    );

    // Probe the mediator while the remote BinStore read is blocked.
    // Use try_lock so a buggy implementation that holds the mediator lock across
    // remote I/O fails immediately instead of deadlocking the test.
    let probe_while_blocked = mediator.as_arc().try_lock().ok().and_then(|mut guard| {
        let imm = guard.immutable_content().ok()?;
        Some((imm.view().base_seq, imm.has(&cold_grain_id)))
    });

    pause.release();

    let fetched = handle.join().unwrap().unwrap();
    let present_after = mediator
        .with(|local| Ok(local.immutable_content()?.has(&cold_grain_id)))
        .unwrap();

    assert_eq!(
        (
            present_before,
            probe_while_blocked,
            GrainId::of(&fetched),
            fetched.len(),
            present_after,
        ),
        (false, Some((1, false)), cold_grain_id, 65_536, true),
        "cold fetch_immutable must release mediator lock before remote BinStore I/O and re-acquire it only to land verified bytes via put_immutable"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "verifies (W, E, T) and (base_id, base_seq) attach checks, cache invalidation, duplicate refusal, post-landing drift refusal, and real sync registration through MountSyncContent"
)]
fn mount_engine_attaches_once_to_admitted_base() {
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 129, 1024, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let spill_content = file_content_id(&mut ready, b"f.txt");
    let make_authority = || Arc::new(Authority::new(&fixture.tree, &state).with_publication());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Warm clean caches before attach so we can prove attach invalidates both.
    let file = handler_path(b"f.txt");
    let spill_obj = ready
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    ready.backend_for_test().prepare_object(spill_obj).unwrap();
    let _ = ready
        .backend_for_test()
        .read_object(spill_obj, 0, 1024)
        .unwrap();
    ready.backend_for_test().overlay_close(spill_obj).unwrap();
    let pre_attach_caches = (
        ready.backend_for_test().range_cache_snapshot_for_test(),
        ready.backend_for_test().completion_tokens_for_test(),
    );

    // 1. Owner (W, E, T) drift in mediator is refused before attach without consuming signer key.
    let original_owner = ready.backend_for_test().owner_for_test();
    ready
        .backend_for_test()
        .set_owner_for_test(([0xEE; 16], original_owner.1, original_owner.2));
    let owner_drift_sync_content = refused_reason(
        ready
            .backend_for_test()
            .sync_content(make_authority())
            .err(),
    );
    ready.backend_for_test().set_owner_for_test(original_owner);
    let valid_content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(make_authority())
            .unwrap(),
    );
    ready
        .backend_for_test()
        .set_owner_for_test(([0xEE; 16], original_owner.1, original_owner.2));
    let owner_drift_attach = refused_reason(
        runtime
            .block_on(ready.backend_for_test().attach_sync(
                make_authority(),
                Arc::clone(&valid_content),
                Arc::new(Time(Arc::clone(&state))),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(21)),
                Entropy(27),
            ))
            .err(),
    );
    ready.backend_for_test().set_owner_for_test(original_owner);

    // 2. Base (base_id, base_seq) mismatch is refused before attach without consuming signer key.
    let original_pinned_base = ready.backend_for_test().pinned_base_for_test();
    ready
        .backend_for_test()
        .set_pinned_base_for_test(original_pinned_base.1 + 1);
    let base_drift_attach = refused_reason(
        runtime
            .block_on(ready.backend_for_test().attach_sync(
                make_authority(),
                Arc::clone(&valid_content),
                Arc::new(Time(Arc::clone(&state))),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(22)),
                Entropy(28),
            ))
            .err(),
    );
    ready
        .backend_for_test()
        .set_pinned_base_for_test(original_pinned_base.1);

    // 3. Attach once to the admitted base using production MountSyncContent: invalidates caches and shares sole Store.
    let engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            make_authority(),
            Arc::clone(&valid_content),
            Arc::new(Time(Arc::clone(&state))),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(23)),
            Entropy(29),
        ))
        .unwrap();
    let sole_store_locked = matches!(Store::open(&paths.store), Err(crate::StoreError::Locked));
    let post_attach_caches = (
        ready.backend_for_test().range_cache_snapshot_for_test(),
        ready.backend_for_test().completion_tokens_for_test(),
    );
    let duplicate_attach = refused_reason(
        runtime
            .block_on(ready.backend_for_test().attach_sync(
                make_authority(),
                Arc::clone(&valid_content),
                Arc::new(Time(Arc::clone(&state))),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(24)),
                Entropy(30),
            ))
            .err(),
    );

    // 4. Base drift after landing closes the mount view and refuses subsequent attach or content access.
    let mediator = ready.backend_for_test().shared_mediator().clone();
    let landed_root = drive_real_landing(&engine, &mediator, &fixture.tree);
    let observed_after_landing = ready.backend_for_test().observe_engine_view();
    let sync_content_after_drift = refused_reason(
        ready
            .backend_for_test()
            .sync_content(make_authority())
            .err(),
    );
    let attach_after_drift = refused_reason(
        runtime
            .block_on(ready.backend_for_test().attach_sync(
                make_authority(),
                Arc::clone(&valid_content),
                Arc::new(Time(Arc::clone(&state))),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(25)),
                Entropy(31),
            ))
            .err(),
    );
    let content_payload_after_drift =
        refused_reason(crate::SyncContent::payload(valid_content.as_ref(), spill_content).err());

    // 5. Authority closure/registration control: mutate one file and run engine.sync through MountSyncContent.
    let paths_sync = query_paths();
    let fixture_sync = clean_tree_with_pressure(&paths_sync, 129, 1024, true);
    let input_sync = input(&fixture_sync.tree, &paths_sync);
    let (ready_sync, state_sync, _) =
        attempt(&input_sync, &fixture_sync.tree, "valid", &Events::default());
    let mut ready_sync = ready_sync.unwrap();
    let authority_sync =
        Arc::new(Authority::new(&fixture_sync.tree, &state_sync).with_publication());
    let content_sync = Arc::new(
        ready_sync
            .backend_for_test()
            .sync_content(Arc::clone(&authority_sync))
            .unwrap(),
    );
    let engine_sync = runtime
        .block_on(ready_sync.backend_for_test().attach_sync(
            Arc::clone(&authority_sync),
            content_sync,
            Arc::new(Time(Arc::clone(&state_sync))),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(26)),
            Entropy(32),
        ))
        .unwrap();
    let write_obj = ready_sync
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    ready_sync
        .backend_for_test()
        .prepare_object(write_obj)
        .unwrap();
    ready_sync
        .backend_for_test()
        .overlay_mutate(M::BoundWrite {
            object: write_obj,
            offset: 0,
            bytes: b"updated-via-mount-sync-content",
            append: false,
        })
        .unwrap();
    ready_sync
        .backend_for_test()
        .overlay_close(write_obj)
        .unwrap();
    let registers_before_sync = state_sync.lock().unwrap().calls[2];
    let sync_outcome = runtime.block_on(async {
        engine_sync
            .sync(crate::SyncTarget::Tree, crate::SyncOptions::default())
            .wait()
            .await
    });
    let registers_after_sync = state_sync.lock().unwrap().calls[2];

    assert_eq!(
        (
            (
                (
                    pre_attach_caches.0.0,
                    pre_attach_caches.0.1 > 0,
                    pre_attach_caches.1,
                ),
                owner_drift_sync_content,
                owner_drift_attach,
                base_drift_attach,
                post_attach_caches,
            ),
            (
                sole_store_locked,
                duplicate_attach,
                landed_root != original_pinned_base.0,
                sync_outcome.is_ok(),
                registers_after_sync > registers_before_sync,
            ),
            (
                observed_after_landing,
                sync_content_after_drift,
                attach_after_drift,
                content_payload_after_drift,
            ),
        ),
        (
            (
                (1, true, (Some(1), 1, Some(spill_content))),
                Some("SyncOwnerBinding"),
                Some("SyncOwnerBinding"),
                Some("SyncBaseBinding"),
                ((2, 0, 0, 0, 0), (Some(2), 0, None)),
            ),
            (true, Some("SyncEngineAlreadyAttached"), true, true, true,),
            (
                Err(granary_fuse::MountError::Io),
                Some("ViewPending"),
                Some("ViewPending"),
                Some("ViewPending"),
            ),
        ),
        "attach_sync with MountSyncContent must verify (W, E, T) and (base_id, base_seq), invalidate caches, refuse duplicate/drifted attach, and drive real sync registration over the sole mediator"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "holds first sync's registration in-flight and drives a second pipelined file sync's content operations"
)]
fn mount_sync_content_admits_pipelined_sync_while_registration_in_flight() {
    use crate::SyncContent as _;
    use crate::SyncRuntime as _;
    use granary_core::manifest::GrainRef;

    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 2, 1024, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let spill_content = file_content_id(&mut ready, b"f.txt");
    let (second_name, _) = fixture.pressure[0].clone();
    let second_content = file_content_id(&mut ready, second_name.as_bytes());
    let authority = Arc::new(Authority::new(&fixture.tree, &state).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(Arc::clone(&authority))
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            Arc::clone(&authority),
            Arc::clone(&content),
            Arc::new(Time(Arc::clone(&state))),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(31)),
            Entropy(33),
        ))
        .unwrap();
    let mediator = ready.backend_for_test().shared_mediator().clone();
    let faults = mediator.with(|local| Ok(local.fault_control())).unwrap();

    // Stage both files before starting sync 1 so we test engine content admission
    // while sync 1's registration is held in-flight.
    let file1 = handler_path(b"f.txt");
    let obj1 = ready
        .backend_for_test()
        .overlay_open(&file1)
        .unwrap()
        .unwrap();
    ready.backend_for_test().prepare_object(obj1).unwrap();
    ready
        .backend_for_test()
        .overlay_mutate(M::BoundWrite {
            object: obj1,
            offset: 0,
            bytes: b"pipelined-file-one",
            append: false,
        })
        .unwrap();
    ready.backend_for_test().overlay_close(obj1).unwrap();

    let file2 = handler_path(second_name.as_bytes());
    let obj2 = ready
        .backend_for_test()
        .overlay_open(&file2)
        .unwrap()
        .unwrap();
    ready.backend_for_test().prepare_object(obj2).unwrap();
    ready
        .backend_for_test()
        .overlay_mutate(M::BoundWrite {
            object: obj2,
            offset: 0,
            bytes: b"pipelined-file-two",
            append: false,
        })
        .unwrap();
    ready.backend_for_test().overlay_close(obj2).unwrap();

    faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );

    let (pending_non_terminal_while_held, direct_content_ops, sync2_while_sync1_held, sync1_ok) =
        runtime.block_on(async {
            let sync1 = engine.sync(crate::SyncTarget::File(obj1), crate::SyncOptions::default());
            while faults.sync_fired().is_empty() {
                crate::TokioSyncRuntime
                    .sleep(std::time::Duration::from_millis(1))
                    .await;
            }

            let pending_non_terminal = mediator
                .with(|local| Ok(local.snapshot().pending.iter().any(|p| !p.terminal)))
                .unwrap();

            let payload_res = content
                .payload(second_content)
                .map(|_| ())
                .map_err(|e| refused_reason(Some(e)).unwrap_or("other"));
            let read_res = content
                .read_content(spill_content, 0, 16)
                .map(|b| b.len())
                .map_err(|e| match e {
                    crate::OverlayError::Refused(reason) => reason,
                    _ => "read_err",
                });
            let put_bytes = b"pipelined-extra-grain";
            let put_id = GrainId::of(put_bytes);
            let put_res = content
                .put_object(put_id, put_bytes)
                .map_err(|e| refused_reason(Some(e)).unwrap_or("other"));
            let rem_grains = FileGrains::Inline(vec![GrainRef {
                id: put_id,
                unpacked_len: u32::try_from(put_bytes.len()).unwrap(),
            }]);
            let rem_id = GrainId::of(
                &granary_core::manifest::node::file_payload(put_bytes.len() as u64, &rem_grains)
                    .unwrap(),
            );
            let rem_res = content
                .remember_payload(rem_id, put_bytes.len() as u64, &rem_grains)
                .map_err(|e| refused_reason(Some(e)).unwrap_or("other"));

            let sync2_res = engine
                .sync(crate::SyncTarget::File(obj2), crate::SyncOptions::default())
                .wait()
                .await
                .map_err(|e| refused_reason(Some(e)).unwrap_or("other"));

            faults.resume();
            let res1 = sync1.wait().await.is_ok();
            (
                pending_non_terminal,
                (payload_res, read_res, put_res, rem_res),
                sync2_res,
                res1,
            )
        });

    assert_eq!(
        (
            pending_non_terminal_while_held,
            direct_content_ops,
            sync2_while_sync1_held,
            sync1_ok,
        ),
        (true, (Ok(()), Ok(16), Ok(()), Ok(())), Ok(()), true,),
        "pipelined second sync and MountSyncContent operations must succeed while the engine's own first registration is in-flight"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "evicts cold grain, arms stalled remote range read with watchdog, and asserts sync fails within resolution_bound with SyncDeadline"
)]
fn mount_sync_content_bounds_cold_fetch_by_sync_deadline() {
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 3, 65_536, true);
    let input_cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&input_cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let (cold_name, cold_grain_id) = fixture.pressure[0].clone();
    let pause = RangeReadPause::unarmed();
    let authority = Arc::new(
        Authority::new(&fixture.tree, &state)
            .with_publication()
            .with_range_pause(Arc::clone(&pause)),
    );
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(Arc::clone(&authority))
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            Arc::clone(&authority),
            Arc::clone(&content),
            Arc::new(Time(Arc::clone(&state))),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(32)),
            Entropy(34),
        ))
        .unwrap();
    let mediator = ready.backend_for_test().shared_mediator().clone();

    // Mutate only the first 6 bytes of the 64 KiB file, then evict cold_grain_id from
    // the local store so sync materialization must cold-fetch it via get_bin_range.
    let cold_path = handler_path(cold_name.as_bytes());
    let obj = ready
        .backend_for_test()
        .overlay_open(&cold_path)
        .unwrap()
        .unwrap();
    ready.backend_for_test().prepare_object(obj).unwrap();
    ready
        .backend_for_test()
        .overlay_mutate(M::BoundWrite {
            object: obj,
            offset: 0,
            bytes: b"prefix",
            append: false,
        })
        .unwrap();
    ready.backend_for_test().overlay_close(obj).unwrap();
    damage_query_grain(&paths, cold_grain_id, false);
    mediator
        .with(crate::WritableStore::invalidate_clean_content)
        .unwrap();
    let present_before = mediator
        .with(|local| Ok(local.immutable_content()?.has(&cold_grain_id)))
        .unwrap();

    pause.arm();
    let hung_past_bound = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let watchdog_pause = Arc::clone(&pause);
    let watchdog_hung = Arc::clone(&hung_past_bound);
    let watchdog_done = Arc::clone(&done);
    let watchdog = std::thread::spawn(move || {
        // Never wait unbounded: a sync that fails before the read is reached must
        // fail the assertion below (entered == false), not hang the test.
        if !watchdog_pause.wait_entered_timeout(std::time::Duration::from_secs(5)) {
            // A read entered after this point must not wait for a release nobody sends.
            watchdog_pause.release();
            return;
        }
        let (lock, cvar) = &*watchdog_done;
        let finished = lock.lock().unwrap();
        let (finished, _) = cvar
            .wait_timeout_while(finished, std::time::Duration::from_secs(3), |f| !*f)
            .unwrap();
        if !*finished {
            watchdog_hung.store(true, std::sync::atomic::Ordering::SeqCst);
            watchdog_pause.release();
        }
    });

    let sync_err = refused_reason(
        runtime
            .block_on(async {
                engine
                    .sync(
                        crate::SyncTarget::Tree,
                        crate::SyncOptions {
                            // Local work before the cold fetch must fit inside the bound: on a
                            // loaded run over virtiofs it exceeded 50 ms, and the sync then
                            // failed before the paused read was ever reached.
                            resolution_bound: std::time::Duration::from_secs(1),
                            ..Default::default()
                        },
                    )
                    .wait()
                    .await
            })
            .err(),
    );
    {
        let (lock, cvar) = &*done;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    watchdog.join().unwrap();

    let entered = pause.is_entered();
    let present_after = mediator
        .with(|local| Ok(local.immutable_content()?.has(&cold_grain_id)))
        .unwrap();

    assert_eq!(
        (
            entered,
            present_before,
            hung_past_bound.load(std::sync::atomic::Ordering::SeqCst),
            sync_err,
            present_after,
        ),
        (true, false, false, Some("SyncDeadline"), false),
        "stalled cold get_bin_range must fail within the enclosing sync deadline with SyncDeadline and land no bytes"
    );
}

#[test]
fn mount_mutation_during_engine_ownership_pending() {
    let paths = query_paths();
    let fixture = clean_tree(&paths, false);
    let cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let _engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &state);
    ready.backend_for_test().after_view_hook = Some(Box::new(move |mediator| {
        mediator
            .with(|local| {
                local.prepare_succession(&Time(state.clone()))?;
                // Isolate pending-operation admission from ownership phase admission.
                local.content_phase_for_test(granary_core::overlay_ownership::Phase::Serving);
                let pending: Vec<_> = local
                    .snapshot()
                    .pending
                    .iter()
                    .filter(|pending| !pending.terminal)
                    .map(|pending| pending.operation)
                    .collect();
                assert_eq!(
                    pending,
                    vec![Operation::Ownership],
                    "pending premise: {pending:?}"
                );
                Ok(())
            })
            .unwrap();
    }));
    let result = ready.backend_for_test().overlay_mutate(M::Create {
        path: &handler_path(b"new"),
        kind: granary_vfs::NodeKind::File,
        exec: false,
    });
    let entries = ready
        .backend_for_test()
        .shared_mediator()
        .with(|local| local.overlay_transaction(query_fixture_entries))
        .unwrap();
    assert_eq!((result, entries.len()), (Ok(()), 3));
}

/// Where a landing can fall between a view check and its effect.
#[derive(Clone, Copy)]
enum Landing {
    /// After `check_mount_view`, before the path's next acquisition.
    AfterViewCheck,
    /// No landing; the call's acquisitions are counted.
    Never,
    /// At the boundary after acquisition `n` of the call.
    AfterAcquisition(u64),
}

/// A view path's answer, the overlay entry count before and after it, and
/// whether the mediator base moved off the pin.
type ViewPathOutcome = (Result<(), WriteError>, usize, usize, bool);

/// Run one of the nine view paths on a fresh fixture with `landing`, and
/// return its outcome and the call's acquisition record.
fn view_path_case(case: usize, landing: Landing) -> (ViewPathOutcome, (u64, Vec<u64>)) {
    let paths = query_paths();
    let fixture = clean_tree(&paths, false);
    let cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &state);
    let file = handler_path(b"f.txt");
    let object = ready
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    let cursor = ready
        .backend_for_test()
        .overlay_directory(&[])
        .unwrap()
        .cursor;
    let pinned = ready.verified_base().2;
    let mediator = ready.backend_for_test().shared_mediator().clone();
    let land = {
        let mediator = mediator.clone();
        move || {
            let landed = drive_real_landing(&engine, &mediator, &fixture.tree);
            assert_ne!(
                landed, pinned,
                "landing premise: landed={landed:?}, pinned={pinned:?}"
            );
        }
    };
    let before = mediator
        .with(|local| local.overlay_transaction(query_fixture_entries))
        .unwrap()
        .len();
    match landing {
        Landing::AfterViewCheck => {
            let mut land = Some(land);
            ready.backend_for_test().after_view_hook = Some(Box::new(move |_| {
                if let Some(land) = land.take() {
                    land();
                }
            }));
        }
        Landing::Never => crate::writable_store::track_acquisitions_for_test(None),
        Landing::AfterAcquisition(n) => {
            crate::writable_store::track_acquisitions_for_test(Some((n, Box::new(land))));
        }
    }
    let backend = ready.backend_for_test();
    let result = match case {
        0 => backend.overlay_path(&file).map(|_| ()),
        1 => backend
            .overlay_lookup(&[], &Name::new(b"f.txt".to_vec()).unwrap())
            .map(|_| ()),
        2 => backend.overlay_directory(&[]).map(|_| ()),
        3 => backend.overlay_children(&cursor).map(|_| ()),
        4 => backend.overlay_nodes().map(|_| ()),
        5 => backend.overlay_capacity().map(|_| ()),
        6 => backend.overlay_readlink(&handler_path(b"link")).map(|_| ()),
        7 => backend.overlay_mutate(M::Create {
            path: &handler_path(b"new"),
            kind: granary_vfs::NodeKind::File,
            exec: false,
        }),
        8 => backend.read_object(object, 0, 1).map(|_| ()),
        _ => unreachable!(),
    };
    let acquisitions = crate::writable_store::acquisitions_for_test();
    let after = mediator
        .with(|local| local.overlay_transaction(query_fixture_entries))
        .unwrap()
        .len();
    let moved = mediator.with(|local| local.mount_base()).unwrap().0 != pinned;
    ((result, before, after, moved), acquisitions)
}

/// A landing between a view check and its effect is refused by the effect's
/// own acquisition, on nine paths. Each path runs three times on a fresh
/// fixture: with a real landing after `check_mount_view`; with no landing,
/// counting the call's mediator acquisitions and the ones that ran an overlay
/// transaction; and with the landing at the boundary just before the last of
/// those. That boundary is where an effect whose check ran in an earlier
/// acquisition would act on the moved base unchecked. The unlanded run
/// answers as the fixture does; every landed run refuses `EIO` and leaves the
/// overlay unchanged. Case count 9.
#[test]
fn mount_view_landing_between_admission_and_effect_refuses() {
    let mut observations = Vec::new();
    for case in 0..9 {
        let (after_view, _) = view_path_case(case, Landing::AfterViewCheck);
        let (unlanded, (begun, transactions)) = view_path_case(case, Landing::Never);
        let last = transactions.last().copied().unwrap_or(0);
        assert!(
            last > 1,
            "acquisition premise for case {case}: begun={begun}, transactions={transactions:?}"
        );
        let (before_effect, _) = view_path_case(case, Landing::AfterAcquisition(last - 1));
        observations.push((case, unlanded, after_view, before_effect));
    }
    let refused = || {
        (
            Err(WriteError::Backend(granary_fuse::MountError::Io)),
            2,
            2,
            true,
        )
    };
    assert_eq!(
        observations,
        (0..9)
            .map(|case| {
                // Unlanded, the readlink finds no link in this fixture, the
                // create adds an entry, and the clean read has no content
                // source.
                let unlanded = match case {
                    6 => (Err(WriteError::Missing), 2, 2, false),
                    7 => (Ok(()), 2, 3, false),
                    8 => (
                        Err(WriteError::Backend(granary_fuse::MountError::Unavailable)),
                        2,
                        2,
                        false,
                    ),
                    _ => (Ok(()), 2, 2, false),
                };
                (case, unlanded, refused(), refused())
            })
            .collect::<Vec<_>>()
    );
}

/// Every reader of the pinned base takes the mediator's one pin inside its
/// own acquisition, so moving the pin moves them together. After the
/// prepared root P lands, the content bridge, the mediator's overlay
/// transaction and the attach binding refuse against the start pin; once the
/// pin is rebound at P's base with P's bytes and the start material, those
/// three and the view admission (last, because its refusal latches the view)
/// all pass. A reader comparing against a base captured at construction or
/// attach would still refuse after the rebind.
#[test]
fn mount_pin_moves_every_reader_together() {
    fn reason(result: Result<(), crate::CoordinationError>) -> Result<(), String> {
        result.map_err(|error| match error {
            crate::CoordinationError::Refused(reason) => reason.to_owned(),
            other => format!("other: {other}"),
        })
    }
    let paths = query_paths();
    let fixture = clean_tree(&paths, false);
    let cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let prepared_seq = ready.verified_base().1 + 1;
    let prepared = ready.mediator_for_test().snapshot().root.clone();
    let engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &state);
    let backend = ready.backend_for_test();
    let owner = backend.owner_for_test();
    let content = backend
        .sync_content(Arc::new(Authority::new(&fixture.tree, &state)))
        .unwrap();
    let mediator = backend.shared_mediator().clone();
    let file = mediator
        .with(|local| Ok(local.mount_pin().unwrap().pin_files.keys().next().copied()))
        .unwrap()
        .expect("the start view pins a file");
    let landed = drive_real_landing(&engine, &mediator, &fixture.tree);
    assert_eq!(
        landed,
        GrainId::of(&prepared),
        "landing premise: the prepared root lands"
    );
    let admitted = mediator.with(crate::WritableStore::admitted_owner).unwrap();
    assert_eq!(
        admitted, owner,
        "premise: the landing's refresh keeps the owner, so the binding reaches its base comparison"
    );
    let before = (
        reason(crate::SyncContent::payload(&content, file).map(|_| ())),
        reason(mediator.overlay_transaction(|_| Ok(()))),
        reason(mediator.with(|local| local.check_mount_binding(owner).map(|_| ()))),
    );
    mediator
        .with(|local| {
            let start = local.mount_pin().unwrap();
            local.bind_mount(Arc::new(crate::writable_store::ViewContext {
                base_id: landed,
                base_seq: prepared_seq,
                base_bytes: prepared.clone(),
                ..(*start).clone()
            }));
            Ok(())
        })
        .unwrap();
    let after = (
        reason(crate::SyncContent::payload(&content, file).map(|_| ())),
        reason(mediator.overlay_transaction(|_| Ok(()))),
        reason(mediator.with(|local| local.check_mount_binding(owner).map(|_| ()))),
        backend
            .observe_engine_view()
            .map(|_| ())
            .map_err(|error| format!("{error:?}")),
    );
    assert_eq!(
        (before, after),
        (
            (
                Err("ViewPending".to_owned()),
                Err("ViewPending".to_owned()),
                Err("SyncBaseBinding".to_owned()),
            ),
            (Ok(()), Ok(()), Ok(()), Ok(())),
        )
    );
}

/// Read a `PublishedRoot` and reduce it to what the row compares: the id,
/// seq, volume and bytes it carries and its document's manifest root, or the
/// refusal reason.
fn read_published_root<R: RootStore>(
    remote: &R,
    volume: &VolumeName,
    seq: u64,
    expected: Option<GrainId>,
    trusted: &granary_store::crypto::TrustedKeys,
) -> Result<(GrainId, u64, VolumeName, Vec<u8>, GrainId), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(crate::sync::PublishedRoot::read(
            remote, volume, seq, expected, trusted,
        ))
        .map(|root| {
            (
                root.id(),
                root.seq(),
                root.volume().clone(),
                root.bytes().to_vec(),
                root.doc().manifest_root,
            )
        })
        .map_err(|error| match error {
            crate::CoordinationError::Refused(reason) => reason.to_owned(),
            other => format!("other: {other}"),
        })
}

/// A `PublishedRoot` comes only from the store, checked: the root the start
/// prepared and registered (P, at the base's seq + 1) is not one until the
/// store holds its bytes, and the store's answer is bound to the id asked for
/// and to the mount's key. Six refusals, each read through the counting
/// wrapper so the one store call is counted, and the base itself as the
/// positive control. A transient store failure, a transport that never
/// answered or a `503` the store shed, is `ViewRootUnavailable`: an object
/// over the root size cap is a permanent answer, and keeps the readback
/// refusal. Case count 7.
#[test]
fn published_root_is_read_from_the_store_never_from_the_prepared_root() {
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    for case in 0..7 {
        let paths = query_paths();
        let fixture = clean_tree(&paths, false);
        let cfg = input(&fixture.tree, &paths);
        let (ready, _, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let (volume, base_seq, base_id) = ready.verified_base().clone();
        let prepared = GrainId::of(&ready.mediator_for_test().snapshot().root);
        let prepared_seq = base_seq + 1;
        let tree = &fixture.tree;
        let trusted = trusted(tree);
        let base_bytes = read_published_root(&tree.remote, &volume, base_seq, None, &trusted)
            .unwrap_or_else(|reason| panic!("fixture precondition: the base must read: {reason}"))
            .3;
        assert_ne!(
            GrainId::of(&base_bytes),
            prepared,
            "fixture precondition: the prepared root must differ from the base"
        );
        let (counting, counts) = CountingRemote::new(&tree.remote);
        let (wanted, seq, want) = match case {
            0 => (
                Some(prepared),
                prepared_seq,
                Err("ViewRootUnpublished".to_owned()),
            ),
            1 => {
                let other = sign_root(tree, &tree.key, &volume, prepared_seq, 1, [0xAB; 16]);
                put_root(tree, &volume, prepared_seq, other);
                (
                    Some(prepared),
                    prepared_seq,
                    Err("ViewRootMismatch".to_owned()),
                )
            }
            2 => {
                let (foreign, _) = SigningKey::generate().unwrap();
                let bytes = sign_root(tree, &foreign, &volume, prepared_seq, 1, [0xAB; 16]);
                let id = GrainId::of(&bytes);
                put_root(tree, &volume, prepared_seq, bytes);
                (
                    Some(id),
                    prepared_seq,
                    Err("SyncCommitSignature".to_owned()),
                )
            }
            3 => {
                counts.fail_root_calls();
                (
                    Some(base_id),
                    base_seq,
                    Err("ViewRootUnavailable".to_owned()),
                )
            }
            4 => (
                Some(base_id),
                base_seq,
                Ok((
                    base_id,
                    base_seq,
                    volume.clone(),
                    base_bytes.clone(),
                    tree.manifest_root,
                )),
            ),
            5 => {
                let cap = usize::try_from(granary_core::root::ROOT_MAX_BYTES).unwrap();
                put_root(tree, &volume, prepared_seq, vec![0; cap + 1]);
                (
                    Some(prepared),
                    prepared_seq,
                    Err("SyncCommitReadback".to_owned()),
                )
            }
            6 => {
                counts.shed_root_calls();
                (
                    Some(base_id),
                    base_seq,
                    Err("ViewRootUnavailable".to_owned()),
                )
            }
            _ => unreachable!(),
        };
        let observed = read_published_root(&counting, &volume, seq, wanted, &trusted);
        observations.push((case, observed, counts.root.load(Ordering::SeqCst)));
        expected.push((case, want, 1));
    }
    assert_eq!(observations, expected);
}
