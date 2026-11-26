// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Local content and capacity observations preserve mediation and journal capture.

use super::*;
use granary_core::manifest::{self, FileGrains, GrainRef};

fn fixture_entries(
    overlay: &mut crate::WritableOverlay<'_, SimIo>,
) -> Result<Vec<OverlayEntry>, OverlayError> {
    overlay.entries()
}

fn warm_clean_range(client: &mut WritableStore<SimIo>) -> (OverlayEntry, u64) {
    let mut entries = client.overlay_transaction(fixture_entries).unwrap();
    assert_eq!(
        entries.len(),
        1,
        "nonempty single-file fixture: actual={entries:?}"
    );
    let entry = entries.remove(0);
    let ((), cold) = crate::overlay_store::local_content::measure_local_reads(|| {
        assert_eq!(
            client
                .overlay_transaction(|t| t.read_base(&entry.path, 2, 5))
                .unwrap(),
            b"thent"
        );
    });
    let (bytes, hot) = crate::overlay_store::local_content::measure_local_reads(|| {
        client
            .overlay_transaction(|t| t.read_base(&entry.path, 2, 5))
            .unwrap()
    });
    assert_eq!(
        (bytes, cold.0, hot),
        (b"thent".to_vec(), 2, (0, 0)),
        "nonempty cold/resident cache premise: cold={cold:?}"
    );
    let generation = client
        .overlay_transaction(|t| {
            t.preparation_context(&entry)
                .map(|(_, generation)| generation)
        })
        .unwrap();
    (entry, generation)
}

fn assert_lifecycle_cache_loss(
    client: &mut WritableStore<SimIo>,
    entry: &OverlayEntry,
    previous: u64,
    corrupt: bool,
) {
    let generation = client
        .overlay_transaction(|t| {
            t.preparation_context(entry)
                .map(|(_, generation)| generation)
        })
        .unwrap();
    let (answer, work) = crate::overlay_store::local_content::measure_local_reads(|| {
        client
            .overlay_transaction(|t| t.read_base(&entry.path, 2, 5))
            .map_err(|e| e.to_string())
    });
    let expected = if corrupt {
        "overlay content authentication failed"
    } else {
        "overlay recovery awaits verified content"
    };
    assert_eq!(
        (generation - previous, answer, work.0),
        (1, Err(expected.to_owned()), 2),
        "lifecycle must discard resident bytes and authenticate disk again: corrupt={corrupt}, work={work:?}"
    );
}

fn warm_replay(local: bool) {
    let mut cases = 0;
    for corrupt in [false, true] {
        let (scratch, io, mut client, _authority, _content) = clean_file();
        let (entry, generation) = warm_clean_range(&mut client);
        let data = GrainId::of(b"authenticated base");
        if corrupt {
            corrupt_object(&scratch, data);
        } else {
            remove_object(&scratch, data);
        }
        let mut h = header();
        h.writer = client.writer_uuid();
        if local {
            client
                .open_overlay_local(h, vec![entry.clone()], io, false)
                .unwrap();
        } else {
            client
                .open_overlay(h, vec![entry.clone()], &mut Source::default(), io)
                .unwrap();
        }
        assert_lifecycle_cache_loss(&mut client, &entry, generation, corrupt);
        cases += 1;
    }
    assert_eq!(
        cases, 2,
        "nonempty replay disk routes: local={local}, cases={cases}"
    );
}

#[test]
fn mediated_warm_replay_discards_verified_ranges() {
    warm_replay(false);
}

#[test]
fn mediated_warm_local_replay_discards_verified_ranges() {
    warm_replay(true);
}

fn warm_replacement(landed: bool) {
    let mut cases = 0;
    for corrupt in [false, true] {
        let (scratch, _io, mut client, _authority, _content) = clean_file();
        let (entry, generation) = warm_clean_range(&mut client);
        let publication = [7; 16];
        let candidate = grain(3);
        let boundary = client
            .overlay_transaction(|t| {
                let capture = t.capture_boundary()?;
                t.record_boundary(capture, candidate, publication)
            })
            .unwrap();
        if landed {
            let proof = LandedProof {
                boundary_seq: boundary,
                landed_root: candidate,
                landed_seq: 2,
                captured_entries: vec![entry.clone()],
                entries: vec![entry.clone()],
            };
            client
                .overlay_transaction(|t| {
                    t.record_landed(&proof)?;
                    t.record_landed_refresh(2, candidate)?;
                    t.replace_landed(proof)
                })
                .unwrap();
        } else {
            client
                .overlay_transaction(|t| t.replace_rejected(boundary, publication))
                .unwrap();
        }
        let data = GrainId::of(b"authenticated base");
        if corrupt {
            corrupt_object(&scratch, data);
        } else {
            remove_object(&scratch, data);
        }
        assert_lifecycle_cache_loss(&mut client, &entry, generation, corrupt);
        cases += 1;
    }
    assert_eq!(
        cases, 2,
        "nonempty replacement disk routes: landed={landed}, cases={cases}"
    );
}

#[test]
fn mediated_warm_landed_replacement_discards_verified_ranges() {
    warm_replacement(true);
}

#[test]
fn mediated_warm_rejected_replacement_discards_verified_ranges() {
    warm_replacement(false);
}

struct SpillFixture {
    payload: Vec<u8>,
    objects: Vec<(GrainId, Vec<u8>)>,
    hash_bytes: usize,
}

fn indexed_spill_file() -> SpillFixture {
    let a = GrainId::of(b"a");
    let b = GrainId::of(b"b");
    // One more ref than fits in a leaf produces the smallest canonical index.
    let refs: Vec<_> = (0..131_073)
        .map(|n| GrainRef {
            id: if n < 65_537 { a } else { b },
            unpacked_len: 1,
        })
        .collect();
    let built = manifest::build_grain_list(&refs).unwrap();
    let payload = manifest::node::file_payload(
        131_073,
        &FileGrains::Spill {
            grain_count: 131_073,
            root: built.root,
        },
    )
    .unwrap();
    let hash_bytes = payload.len() + built.nodes.iter().map(|(_, b)| b.len()).sum::<usize>() + 2;
    assert_eq!(
        built.nodes.len(),
        3,
        "canonical spill has two leaves and one index: actual={}",
        built.nodes.len()
    );
    let mut objects = built.nodes;
    objects.extend([(a, b"a".to_vec()), (b, b"b".to_vec())]);
    SpillFixture {
        payload,
        objects,
        hash_bytes,
    }
}

#[test]
fn mediated_multilevel_spill_chunks_reuse_only_authenticated_tree_nodes() {
    let SpillFixture {
        payload,
        objects,
        hash_bytes,
    } = indexed_spill_file();
    let (_scratch, _io, mut client, _authority, _content) = file_client(&payload, 131_073, objects);
    let path = vec![Name::new(b"file".to_vec()).unwrap()];
    let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
    let mut middle = vec![b'b'; 65_536];
    middle[0] = b'a';
    let expected = vec![vec![b'a'; 65_536], middle, b"b".to_vec()];
    let expected_digests: Vec<_> = expected
        .iter()
        .map(|bytes| (bytes.len(), GrainId::of(bytes)))
        .collect();
    let mut rounds = Vec::new();
    for _ in 0..2 {
        rounds.push(crate::overlay_store::local_content::measure_local_reads(
            || {
                [(0, 65_536), (65_536, 65_536), (131_072, 1)]
                    .into_iter()
                    .zip(&expected)
                    .map(|((offset, length), expected)| {
                        let bytes = client
                            .overlay_transaction(|t| t.read_base(&path, offset, length))
                            .unwrap();
                        assert!(
                            bytes == *expected,
                            "exact range bytes: offset={offset}, actual={:?}, expected={:?}",
                            (bytes.len(), GrainId::of(&bytes)),
                            (expected.len(), GrainId::of(expected))
                        );
                        (bytes.len(), GrainId::of(&bytes))
                    })
                    .collect::<Vec<_>>()
            },
        ));
    }
    assert_eq!(
        (
            rounds,
            client.overlay_transaction(|t| Ok(t.summary())).unwrap() == before
        ),
        (
            vec![
                (expected_digests.clone(), (6, hash_bytes)),
                (expected_digests, (0, 0))
            ],
            true
        ),
        "cross-leaf chunks authenticate payload/index/two leaves/two grains once; a per-range full tree walk or hash must fail"
    );
}

#[test]
fn mediated_multilevel_spill_parent_mismatch_never_becomes_a_resident_success() {
    let SpillFixture {
        payload: valid,
        objects,
        ..
    } = indexed_spill_file();
    let (_, cursor) = granary_core::encoding::open_envelope(&objects[2].1).unwrap();
    let children = manifest::decode_grain_list_index(cursor).unwrap();
    let invalid = manifest::node::file_payload(
        131_073,
        &FileGrains::Spill {
            grain_count: 131_074,
            root: GrainId::of(&objects[2].1),
        },
    )
    .unwrap();
    assert_eq!(
        children
            .last()
            .map(|c| (c.cum_ref_count, c.cum_unpacked_len)),
        Some((131_073, 131_073)),
        "nonempty canonical parent premise: actual={children:?}"
    );
    let mut cases = 0;
    for (payload, malformed) in [(valid, false), (invalid, true)] {
        let (_scratch, _io, mut client, _authority, _content) =
            file_client(&payload, 131_073, objects.clone());
        let path = vec![Name::new(b"file".to_vec()).unwrap()];
        let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
        for _ in 0..2 {
            let answer = client
                .overlay_transaction(|t| t.read_base(&path, 65_535, 3))
                .map_err(|e| e.to_string());
            assert_eq!(
                (
                    answer,
                    client.overlay_transaction(|t| Ok(t.summary())).unwrap() == before
                ),
                (
                    if malformed {
                        Err("overlay content authentication failed".to_owned())
                    } else {
                        Ok(b"aab".to_vec())
                    },
                    true
                ),
                "parent count mismatch must refuse on both cold and repeated reads: malformed={malformed}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4, "nonempty paired repeated parent checks: {cases}");
}

fn observe_local(
    t: &mut crate::WritableOverlay<'_, SimIo>,
) -> Result<crate::OverlayObservation, OverlayError> {
    t.observation()
}

fn clean_file() -> (Scratch, SimIo, WritableStore<SimIo>, Authority, GrainId) {
    let data = b"authenticated base";
    let id = GrainId::of(data);
    let payload = granary_core::manifest::node::file_payload(
        data.len() as u64,
        &FileGrains::Inline(vec![GrainRef {
            id,
            unpacked_len: u32::try_from(data.len()).unwrap(),
        }]),
    )
    .unwrap();
    file_client(&payload, data.len() as u64, vec![(id, data.to_vec())])
}

fn file_client(
    payload: &[u8],
    size: u64,
    objects: Vec<(GrainId, Vec<u8>)>,
) -> (Scratch, SimIo, WritableStore<SimIo>, Authority, GrainId) {
    let scratch = Scratch::new();
    let content = GrainId::of(payload);
    {
        let store = Store::open(&scratch.0).unwrap();
        store.put(&content, payload).unwrap();
        for (id, data) in objects {
            store.put(&id, &data).unwrap();
        }
    }
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    acquire(&mut client, &mut authority);
    let mut h = header();
    h.writer = client.writer_uuid();
    client
        .open_overlay(
            h,
            vec![OverlayEntry {
                path: vec![Name::new(b"file".to_vec()).unwrap()],
                inode: 2,
                kind: OverlayKind::File {
                    content: Some(content),
                },
                stage_id: None,
                size,
                exec: false,
            }],
            &mut Source::default(),
            io.clone(),
        )
        .unwrap();
    register(&mut client, &mut authority, 1);
    (scratch, io, client, authority, content)
}

#[test]
fn mediated_local_read_copy_up_and_close_preserve_capture() {
    let (_scratch, _io, mut client, _authority, _content) = clean_file();
    let path = at("file");
    let mut names = path.parent.names().to_vec();
    names.push(path.name.clone());
    let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
    let bytes = client
        .overlay_transaction(|t| t.read_base(&names, 2, 5))
        .unwrap();
    assert_eq!(
        bytes, b"thent",
        "clean reads must authenticate the pinned local payload"
    );
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary()))
            .unwrap()
            .records,
        before.records
    );
    let stage = client
        .overlay_transaction(|t| t.copy_up(path.clone()))
        .unwrap();
    client
        .overlay_transaction(|t| {
            assert_eq!(t.open_stage(&names)?, stage);
            assert_eq!(t.open_stage(&names)?, stage);
            t.write(stage, 0, b"NEW")?;
            t.truncate(stage, 5)?;
            t.truncate(stage, 8)?;
            t.namespace_record(Record::Delete {
                at: path,
                kind: codec::DeleteKind::File {
                    stage_id: Some(stage),
                },
            })?;
            assert_eq!(
                t.read_stage(stage, 0, 8)?,
                b"NEWhe\0\0\0",
                "shared open orphan retains bytes and dense zero extension"
            );
            assert_eq!(
                t.summary().records,
                before.records + 5,
                "copy-up, write, two truncates and delete are captured once"
            );
            assert!(t.summary().orphan_bytes >= 168);
            t.close_stage(stage)?;
            assert_eq!(t.read_stage(stage, 0, 8)?, b"NEWhe\0\0\0");
            t.close_stage(stage)?;
            assert_eq!(
                t.summary().records,
                before.records + 5,
                "close is bookkeeping, never sync"
            );
            assert!(matches!(
                t.read_stage(stage, 0, 8),
                Err(OverlayError::Refused("detached stage has no handle"))
            ));
            Ok(())
        })
        .unwrap();
    let reopened = client
        .overlay_transaction(|t| {
            assert!(t.entries()?.is_empty());
            Ok(t.summary())
        })
        .unwrap();
    assert_eq!(reopened.records, before.records + 5);
}

#[test]
fn mediated_immutable_put_is_verified_idempotent_and_uncharged() {
    let (_scratch, _io, mut client, _authority) = serving();
    let bytes = b"immutable fetched object";
    let id = GrainId::of(bytes);
    let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
    assert!(
        client.put_immutable(id, bytes).unwrap(),
        "first mediated CAS put must land a novel object"
    );
    assert!(
        !client.put_immutable(id, bytes).unwrap(),
        "identical put is idempotent"
    );
    assert!(
        matches!(
            client.put_immutable(id, b"wrong bytes"),
            Err(CoordinationError::Overlay(OverlayError::ContentCorrupt))
        ),
        "wrong-address bytes must refuse before landing"
    );
    let after = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
    assert_eq!(
        (
            after,
            client
                .overlay_transaction(|t| Ok(t.content_exists(&id)))
                .unwrap()
        ),
        (before, true),
        "CAS bytes must be visible without journal or overlay charge"
    );
    let volume = VolumeName::from_bytes(b"v").unwrap();
    client
        .publication_transaction(|p| {
            assert!(p.select_direct(&volume, None)?.completed.is_empty());
            Ok(())
        })
        .unwrap();
    let unowned_scratch = Scratch::new();
    let mut unowned = start(&unowned_scratch, &SimIo::default(), 50);
    assert!(unowned.check_readiness().is_err());
    let outside = b"immutable fetch completion before ownership";
    assert!(
        unowned
            .put_immutable(GrainId::of(outside), outside)
            .unwrap(),
        "CAS landing grants no writable readiness and stays outside ownership gates"
    );
}

#[test]
fn mediated_observation_counts_live_names_without_cloning_entries() {
    let (_scratch, io, mut client, _authority) = serving();
    client
        .overlay_transaction(|t| {
            t.create_file(at("one"), false)?;
            t.namespace_record(Record::Create {
                at: at("dir"),
                kind: codec::CreateKind::Dir,
            })?;
            Ok(())
        })
        .unwrap();
    let first = client.overlay_transaction(observe_local).unwrap();
    assert_eq!(
        first.namespace_len, 3,
        "live count includes root and both names"
    );
    assert_eq!(first.cap, 134_217_728);
    state::CLONED_ENTRY_VALUES.set(0);
    let again = client.overlay_transaction(observe_local).unwrap();
    assert_eq!(
        (again, state::CLONED_ENTRY_VALUES.get()),
        (first, 0),
        "capacity read must not clone the namespace"
    );
    client
        .overlay_transaction(|t| {
            let names = vec![Name::new(b"one".to_vec()).unwrap()];
            let stage = t.open_stage(&names)?;
            t.write(stage, 0, b"charged")?;
            t.namespace_record(Record::Delete {
                at: at("one"),
                kind: codec::DeleteKind::File {
                    stage_id: Some(stage),
                },
            })?;
            Ok(())
        })
        .unwrap();
    let orphan = client.overlay_transaction(observe_local).unwrap();
    assert_eq!(
        orphan.namespace_len, 2,
        "open orphans are charged but absent from namespace count"
    );
    assert!(orphan.summary.charged_bytes > first.summary.charged_bytes);
    assert_eq!(orphan.summary.orphan_bytes, 167);
    let journal =
        io.0.lock()
            .unwrap()
            .names
            .keys()
            .find(|p| p.file_name().is_some_and(|n| n == "journal"))
            .unwrap()
            .clone();
    let temporary = journal.parent().unwrap().join("ownership.tmp");
    let mut model_io = io.clone();
    model_io.create(&temporary).unwrap();
    model_io.write_at(&temporary, 0, &[0; 600]).unwrap();
    let fresh = client.overlay_transaction(observe_local).unwrap();
    assert_eq!(
        fresh.summary.charged_bytes - orphan.summary.charged_bytes,
        600,
        "observation must refresh physical control-file charges"
    );
}

#[test]
fn mediated_local_content_refuses_bad_payload_size_and_grain_length() {
    let log = LogCapture::default();
    let subscriber = crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("warn"),
        log.clone(),
    );
    let data = b"abcdef";
    let id = GrainId::of(data);
    let payload = |size, len| {
        manifest::node::file_payload(
            size,
            &FileGrains::Inline(vec![GrainRef {
                id,
                unpacked_len: len,
            }]),
        )
        .unwrap()
    };
    let cases = [
        (
            b"invalid payload".to_vec(),
            6,
            vec![(id, data.to_vec())],
            "malformed payload",
        ),
        (
            payload(6, 6),
            5,
            vec![(id, data.to_vec())],
            "namespace size differs from payload",
        ),
        (
            payload(5, 5),
            5,
            vec![(id, data.to_vec())],
            "hash-valid grain length differs",
        ),
    ];
    tracing::subscriber::with_default(subscriber, || {
        for (payload, size, objects, wrong_provider) in cases.clone() {
            let (_scratch, _io, mut client, _authority, _content) =
                file_client(&payload, size, objects);
            let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
            let result = client
                .overlay_transaction(|t| t.read_base(&[Name::new(b"file".to_vec()).unwrap()], 0, 1))
                .map_err(|e| e.to_string());
            assert_eq!(
                result,
                Err("overlay content authentication failed".to_owned()),
                "provider accepted {wrong_provider}"
            );
            assert_eq!(
                client.overlay_transaction(|t| Ok(t.summary())).unwrap(),
                before
            );
            let (_scratch, _io, mut valid, _authority, _content) = clean_file();
            assert_eq!(
                valid
                    .overlay_transaction(|t| t.read_base(
                        &[Name::new(b"file".to_vec()).unwrap()],
                        0,
                        1
                    ))
                    .unwrap(),
                b"a"
            );
        }
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\"event\":\"op.failed\"")
                && line.contains("\"kind\":\"overlay_write\"")
                && line.contains("\"class\":\"corrupt\""))
            .count(),
        0,
        "content helpers propagate errors; the callback owns terminal reporting"
    );
    assert_eq!(cases.len(), 3);
    assert!(
        !text.contains("file") && !text.contains("abcdef"),
        "content and names must not enter events: {text}"
    );
}

#[test]
fn mediated_local_spill_ranges_authenticate_parent_aggregates() {
    let id = GrainId::of(b"x");
    let refs = vec![
        GrainRef {
            id,
            unpacked_len: 1
        };
        129
    ];
    let leaf = manifest::encode_grain_list_leaf(&refs).unwrap();
    let root = GrainId::of(&leaf);
    let file = |count, size, root| {
        manifest::node::file_payload(
            size,
            &FileGrains::Spill {
                grain_count: count,
                root,
            },
        )
        .unwrap()
    };
    let good_index = manifest::encode_grain_list_index(&[
        manifest::GrainListIndexChild {
            child: root,
            cum_unpacked_len: 129,
            cum_ref_count: 129,
        },
        manifest::GrainListIndexChild {
            child: root,
            cum_unpacked_len: 258,
            cum_ref_count: 258,
        },
    ])
    .unwrap();
    let zero_index = manifest::encode_grain_list_index(&[
        manifest::GrainListIndexChild {
            child: root,
            cum_unpacked_len: 0,
            cum_ref_count: 0,
        },
        manifest::GrainListIndexChild {
            child: root,
            cum_unpacked_len: 129,
            cum_ref_count: 129,
        },
    ])
    .unwrap();
    let index = GrainId::of(&good_index);
    let zero = GrainId::of(&zero_index);
    let directory = manifest::encode_dir_leaf(&[]).unwrap();
    let dir_id = GrainId::of(&directory);
    let objects = vec![
        (id, b"x".to_vec()),
        (root, leaf),
        (index, good_index),
        (zero, zero_index),
        (dir_id, directory),
    ];
    for (payload, size, label) in [
        (file(130, 129, root), 129, "leaf count"),
        (file(129, 130, root), 130, "leaf size"),
        (file(257, 258, index), 258, "index count"),
        (file(258, 257, index), 257, "index size"),
        (file(129, 129, zero), 129, "zero first child"),
        (file(129, 129, dir_id), 129, "wrong list kind"),
    ] {
        let (_scratch, _io, mut client, _authority, _content) =
            file_client(&payload, size, objects.clone());
        let result = client
            .overlay_transaction(|t| t.read_base(&[Name::new(b"file".to_vec()).unwrap()], 0, 3))
            .map_err(|e| e.to_string());
        assert_eq!(
            result,
            Err("overlay content authentication failed".to_owned()),
            "accepted {label}"
        );
    }
    for (payload, size, offset, length) in [
        (file(129, 129, root), 129, 125, 4),
        (file(258, 258, index), 258, 125, 8),
    ] {
        let (_scratch, _io, mut client, _authority, _content) =
            file_client(&payload, size, objects.clone());
        assert_eq!(
            client
                .overlay_transaction(|t| t.read_base(
                    &[Name::new(b"file".to_vec()).unwrap()],
                    offset,
                    length
                ))
                .unwrap(),
            vec![b'x'; length]
        );
    }
}

#[test]
fn mediated_local_missing_content_never_substitutes_bytes_or_captures() {
    let log = LogCapture::default();
    let subscriber = crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("warn"),
        log.clone(),
    );
    tracing::subscriber::with_default(subscriber, || {
        let (_scratch, _io, mut client, _authority, _content) = file_client(
            &manifest::node::file_payload(
                1,
                &FileGrains::Inline(vec![GrainRef {
                    id: GrainId::of(b"x"),
                    unpacked_len: 1,
                }]),
            )
            .unwrap(),
            1,
            vec![],
        );
        let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
        for copy in [false, true] {
            let error = if copy {
                client.overlay_transaction(|t| t.copy_up(at("file")).map(|_| Vec::new()))
            } else {
                client.overlay_transaction(|t| {
                    t.read_base(&[Name::new(b"file".to_vec()).unwrap()], 0, 1)
                })
            }
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "overlay recovery awaits verified content"
            );
            assert_eq!(
                client
                    .overlay_transaction(|t| Ok(t.summary()))
                    .unwrap()
                    .records,
                before.records
            );
        }
        let bytes = b"x";
        client.put_immutable(GrainId::of(bytes), bytes).unwrap();
        let stage = client
            .overlay_transaction(|t| t.copy_up(at("file")))
            .unwrap();
        assert_eq!(
            client
                .overlay_transaction(|t| t.read_stage(stage, 0, 1))
                .unwrap(),
            b"x",
            "same stage allocation can proceed after local fetch landing"
        );
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\"event\":\"op.failed\"")
                && line.contains("\"class\":\"unavailable\""))
            .count(),
        0
    );
}

#[test]
fn mediated_immutable_put_enforces_object_bound_without_landing() {
    let (_scratch, _io, mut client, _authority) = serving();
    let bytes = vec![b'x'; 16_777_217];
    let id = GrainId::of(&bytes);
    let error = client
        .put_immutable(id, &bytes)
        .expect_err("oversized immutable object was landed");
    assert_eq!(
        error.to_string(),
        "overlay refused: immutable object size bound"
    );
    assert!(
        !client
            .overlay_transaction(|t| Ok(t.content_exists(&id)))
            .unwrap()
    );
    let valid = &bytes[..16_777_216];
    assert!(client.put_immutable(GrainId::of(valid), valid).unwrap());
}

#[test]
fn mediated_local_replay_uses_the_owned_store_and_exact_record_kinds() {
    let (_scratch, io, mut client, _authority, content) = clean_file();
    let stage = client
        .overlay_transaction(|t| t.copy_up(at("file")))
        .unwrap();
    client
        .overlay_transaction(|t| {
            t.write(stage, 0, b"NEW")?;
            t.truncate(stage, 5)?;
            t.truncate(stage, 8)?;
            Ok(())
        })
        .unwrap();
    let mut owned_io = io.clone();
    let paths =
        io.0.lock()
            .unwrap()
            .names
            .keys()
            .cloned()
            .collect::<Vec<_>>();
    let journal = paths
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n == "journal"))
        .unwrap();
    let mut kinds = Vec::new();
    codec::scan_journal_with(&io.bytes(journal), |_, r| {
        kinds.push(match r {
            Record::StageBind { .. } => "stage-bind",
            Record::WriteExtent { .. } => "write-extent",
            Record::Truncate { .. } => "truncate",
            Record::IntentRegistered { .. } => "intent-registered",
            _ => "unexpected",
        });
    })
    .unwrap();
    assert_eq!(
        kinds,
        [
            "intent-registered",
            "stage-bind",
            "write-extent",
            "truncate",
            "truncate"
        ],
        "ordinary capture must not invent sync/landing records or omit an operation"
    );
    // This fixture explicitly persists its accepted prefix. It does not infer
    // crash durability from an ordinary write or close acknowledgement.
    for path in &paths {
        owned_io.sync(path).unwrap();
    }
    io.crash();
    let mut h = header();
    h.writer = client.writer_uuid();
    client
        .open_overlay_local(
            h,
            vec![OverlayEntry {
                path: vec![Name::new(b"file".to_vec()).unwrap()],
                inode: 2,
                kind: OverlayKind::File {
                    content: Some(content),
                },
                stage_id: None,
                size: 18,
                exec: false,
            }],
            io.clone(),
            false,
        )
        .unwrap();
    assert_eq!(
        client
            .overlay_transaction(|t| t.read_stage(stage, 0, 8))
            .unwrap(),
        b"NEWhe\0\0\0",
        "replay must retain the shrink boundary and cannot resurrect the base tail"
    );
}

#[test]
fn mediated_empty_copy_up_authenticates_before_binding_any_stage() {
    let valid = manifest::node::file_payload(0, &FileGrains::Inline(vec![])).unwrap();
    for payload in [b"malformed empty file".to_vec(), valid] {
        let malformed = payload.starts_with(b"malformed");
        let (_scratch, _io, mut client, _authority, _content) = file_client(&payload, 0, vec![]);
        let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
        let result = client.overlay_transaction(|t| t.copy_up(at("file")));
        if malformed {
            assert_eq!(
                result.map_err(|e| e.to_string()),
                Err("overlay content authentication failed".to_owned()),
                "empty copy-up skipped payload authentication"
            );
            assert_eq!(
                client.overlay_transaction(|t| Ok(t.summary())).unwrap(),
                before,
                "malformed empty content must fail before stage allocation or binding"
            );
        } else {
            let stage = result.unwrap();
            assert!(
                client
                    .overlay_transaction(|t| t.read_stage(stage, 0, 1))
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                client
                    .overlay_transaction(|t| Ok(t.summary()))
                    .unwrap()
                    .records,
                before.records + 1
            );
        }
    }
}

#[test]
fn mediated_local_spill_depth_refuses_before_unbounded_descent() {
    let id = GrainId::of(b"x");
    let leaf = manifest::encode_grain_list_leaf(&vec![
        GrainRef {
            id,
            unpacked_len: 1
        };
        129
    ])
    .unwrap();
    let single = manifest::encode_grain_list_leaf(&[GrainRef {
        id,
        unpacked_len: 1,
    }])
    .unwrap();
    let mut root = GrainId::of(&leaf);
    let tail = GrainId::of(&single);
    let mut objects = vec![(id, b"x".to_vec()), (root, leaf), (tail, single)];
    let mut size = 129;
    for depth in 2..=17 {
        let next = manifest::encode_grain_list_index(&[
            manifest::GrainListIndexChild {
                child: root,
                cum_unpacked_len: size,
                cum_ref_count: size,
            },
            manifest::GrainListIndexChild {
                child: tail,
                cum_unpacked_len: size + 1,
                cum_ref_count: size + 1,
            },
        ])
        .unwrap();
        root = GrainId::of(&next);
        size += 1;
        objects.push((root, next));
        if depth >= 16 {
            let payload = manifest::node::file_payload(
                size,
                &FileGrains::Spill {
                    grain_count: u32::try_from(size).unwrap(),
                    root,
                },
            )
            .unwrap();
            let (_scratch, _io, mut client, _authority, _content) =
                file_client(&payload, size, objects.clone());
            let result = client
                .overlay_transaction(|t| t.read_base(&[Name::new(b"file".to_vec()).unwrap()], 0, 1))
                .map_err(|e| e.to_string());
            let expected = if depth == 16 {
                Ok(b"x".to_vec())
            } else {
                Err("overlay content authentication failed".to_owned())
            };
            assert_eq!(
                result, expected,
                "spill depth boundary must terminate explicitly at 16 levels"
            );
        }
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "corrupt only the CAS leaf in the exclusively owned test scratch to distinguish presence from verification"
)]
pub(super) fn corrupt_object(scratch: &Scratch, id: GrainId) {
    let digest = id.digest_hex();
    let path = scratch.0.join("objects").join(&digest[..2]).join(digest);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(path, b"corrupt existing object").unwrap();
}

#[test]
fn mediated_immutable_corruption_does_not_turn_presence_into_success() {
    let (scratch, _io, mut client, _authority) = serving();
    let bytes = b"verified immutable object";
    let id = GrainId::of(bytes);
    assert!(client.put_immutable(id, bytes).unwrap());
    corrupt_object(&scratch, id);
    let log = LogCapture::default();
    let subscriber = crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("warn"),
        log.clone(),
    );
    tracing::subscriber::with_default(subscriber, || {
        let result = client.put_immutable(id, bytes).map_err(|e| e.to_string());
        assert_eq!(
            result,
            Err("overlay content authentication failed".to_owned()),
            "existing CAS presence must never stand in for authenticated bytes"
        );
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\"event\":\"op.failed\"")
                && line.contains("\"class\":\"corrupt\""))
            .count(),
        0
    );
    assert!(
        !text.contains("corrupt existing object") && !text.contains(&id.digest_hex()),
        "content and identity must never enter this failure event: {text}"
    );
}

#[test]
fn mediated_local_provider_checks_bounds_and_cached_content_identity() {
    let scratch = Scratch::new();
    let store = Store::open(&scratch.0).unwrap();
    let mut content = Vec::new();
    for data in [b"abcdef".as_slice(), b"UVWXYZ".as_slice()] {
        let id = GrainId::of(data);
        let payload = manifest::node::file_payload(
            6,
            &FileGrains::Inline(vec![GrainRef {
                id,
                unpacked_len: 6,
            }]),
        )
        .unwrap();
        let file = GrainId::of(&payload);
        store.put(&id, data).unwrap();
        store.put(&file, &payload).unwrap();
        content.push(file);
    }
    let mut source = crate::overlay_store::local_content::LocalContent::new(&store);
    for (offset, length) in [(0, 65_537), (5, 2), (u64::MAX, 2)] {
        assert!(
            matches!(
                source.read_verified(content[0], offset, length),
                Err(OverlayError::ContentCorrupt)
            ),
            "provider bounds must refuse offset={offset}, length={length}"
        );
    }
    assert_eq!(source.read_verified(content[0], 1, 3).unwrap(), b"bcd");
    assert_eq!(
        source.read_verified(content[1], 1, 3).unwrap(),
        b"VWX",
        "cached payload must remain bound to its content identity"
    );
    let oversized = manifest::node::file_payload(
        9_223_372_036_854_775_808,
        &FileGrains::Spill {
            grain_count: 129,
            root: GrainId::of(b"missing list"),
        },
    )
    .unwrap();
    let id = GrainId::of(&oversized);
    store.put(&id, &oversized).unwrap();
    assert!(
        matches!(
            source.read_verified(id, 0, 0),
            Err(OverlayError::ContentCorrupt)
        ),
        "size bound must apply even to an empty read"
    );
    let empty = manifest::node::file_payload(0, &FileGrains::Inline(vec![])).unwrap();
    let id = GrainId::of(&empty);
    store.put(&id, &empty).unwrap();
    assert!(source.read_verified(id, 0, 0).unwrap().is_empty());
    let large = vec![b'x'; 131_072];
    let data = GrainId::of(&large);
    store.put(&data, &large).unwrap();
    let payload = manifest::node::file_payload(
        131_072,
        &FileGrains::Inline(vec![GrainRef {
            id: data,
            unpacked_len: 131_072,
        }]),
    )
    .unwrap();
    let file = GrainId::of(&payload);
    store.put(&file, &payload).unwrap();
    assert!(
        matches!(
            source.read_verified(file, 0, 65_537),
            Err(OverlayError::ContentCorrupt)
        ),
        "provider read buffer must remain bounded at 65536 bytes"
    );
    assert_eq!(
        source.read_verified(file, 0, 65_536).unwrap(),
        vec![b'x'; 65_536]
    );
}

#[test]
fn mediated_stage_release_disposes_exact_holds_after_poison_and_fence() {
    let mut cases = 0;
    for fenced in [false, true] {
        let (_scratch, io, mut client, mut authority) = serving();
        let path = vec![Name::new(b"held".to_vec()).unwrap()];
        let stage = client
            .overlay_transaction(|t| {
                let stage = t.create_file(at("held"), false)?;
                t.open_stage(&path)?;
                t.open_stage(&path)?;
                Ok(stage)
            })
            .unwrap();
        if fenced {
            let request = client
                .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                    true
                })
                .unwrap();
            client.dispatch(&request, &Tick(10)).unwrap();
            let receipt = authority.row.unwrap();
            authority.row = Some(Receipt {
                epoch: receipt.epoch + 1,
                instance: [99; 16],
                ..receipt
            });
            let answer = authority.send(&request);
            assert!(matches!(
                client.complete(
                    &request,
                    Ok(&answer),
                    &Tick(11),
                    &mut SeededRng::new(1),
                    0,
                    None
                ),
                Err(CoordinationError::Fenced { .. })
            ));
        } else {
            io.0.lock().unwrap().fail = Some("sync");
            client
                .overlay_transaction(|t| {
                    let capture = t.capture(stage)?;
                    assert!(matches!(
                        t.flush_boundary(&capture),
                        Err(OverlayError::Io(_))
                    ));
                    Ok(())
                })
                .unwrap();
        }
        assert!(
            client
                .overlay_transaction(|t| t.write(stage, 0, b"x"))
                .is_err(),
            "cleanup must not reauthorize mutations"
        );
        let closed = client.release_stage(stage);
        assert!(
            closed.is_ok(),
            "cleanup must succeed after lifecycle refusal: {closed:?}"
        );
        let closed = client.release_stage(stage);
        assert!(
            closed.is_ok(),
            "cleanup must succeed after lifecycle refusal: {closed:?}"
        );
        assert!(
            matches!(
                client.release_stage(stage),
                Err(CoordinationError::Overlay(OverlayError::Refused(
                    "close without handle"
                )))
            ),
            "exact cleanup count must survive lifecycle refusal"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn mediated_stage_hold_transfer_is_atomic_at_numeric_exhaustion() {
    let (_scratch, _io, mut client, _authority) = serving();
    let path = vec![Name::new(b"held".to_vec()).unwrap()];
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("held"), false)?;
            assert_eq!(t.open_stage_holds(&path, u64::MAX - 1)?, stage);
            assert_eq!(t.open_stage(&path)?, stage);
            let exhausted = t.open_stage_holds(&path, 2);
            assert!(
                matches!(exhausted, Err(OverlayError::Refused("handle exhaustion"))),
                "batch transfer must reject before changing any hold: {exhausted:?}"
            );
            Ok(stage)
        })
        .unwrap();
    let closed = client.release_stage(stage);
    assert!(
        closed.is_ok(),
        "overflow must preserve prior holds: {closed:?}"
    );
    let exhausted = client.overlay_transaction(|t| t.open_stage_holds(&path, 2));
    assert!(matches!(
        exhausted,
        Err(CoordinationError::Overlay(OverlayError::Refused(
            "handle exhaustion"
        )))
    ));
}

/// A free-entry estimate must pay for capture and future replacement, not just the header.
#[test]
fn mediated_observation_entry_capacity_reserves_journal_stage_and_identity_space() {
    let mut fixture = crate::overlay_store::tests::Fixture::new();
    let observation = fixture
        .overlay
        .observation(&fixture.store, &fixture.owner)
        .unwrap();
    let overlay = &mut fixture.overlay;
    let original_cap = overlay.config.cap;
    let used = observation.summary.charged_bytes
        + observation.summary.reserved_bytes
        + observation.summary.captured_bytes;
    let mut cases = 0;
    for (headroom, expected) in [(0, 0), (37716, 0), (37717, 1), (75434, 2)] {
        overlay.config.cap = used + headroom;
        assert_eq!(
            overlay.free_entry_capacity().unwrap(),
            expected,
            "conservative empty-file charge includes two frames, stage and completion"
        );
        cases += 1;
    }
    overlay.config.cap = original_cap;
    let (length, header_stage) = {
        let mut journal = overlay.journal.lock().unwrap();
        let length = journal.length;
        journal.length = granary_core::overlay_journal::JOURNAL_MAX as u64;
        (length, journal.header.next_stage_id)
    };
    assert_eq!(
        overlay.free_entry_capacity().unwrap(),
        0,
        "journal exhaustion cannot advertise free entries"
    );
    {
        let mut journal = overlay.journal.lock().unwrap();
        journal.length = length;
        journal.header.next_stage_id = granary_core::overlay_journal::STAGE_ID_MAX + 1;
        journal.state = granary_core::overlay_journal::JournalState::new(&journal.header);
    }
    assert_eq!(
        overlay.free_entry_capacity().unwrap(),
        0,
        "stage identity exhaustion cannot advertise free entries"
    );
    {
        let mut journal = overlay.journal.lock().unwrap();
        journal.header.next_stage_id = header_stage;
        journal.state = granary_core::overlay_journal::JournalState::new(&journal.header);
    }
    assert!(
        overlay.free_entry_capacity().unwrap() > 0,
        "restored capacity is usable"
    );
    assert_eq!(cases, 4);
}

#[test]
fn mediated_local_range_reuses_verified_owned_bytes_across_facades() {
    let (_scratch, _io, mut client, _authority, _content) = clean_file();
    let path = vec![Name::new(b"file".to_vec()).unwrap()];
    let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
    let (answers, work) = crate::overlay_store::local_content::measure_local_reads(|| {
        let mut answers = Vec::new();
        for _ in 0..3 {
            let mut bytes = client
                .overlay_transaction(|t| t.read_base(&path, 2, 5))
                .unwrap();
            answers.push(bytes.clone());
            bytes.fill(0);
        }
        answers
    });
    assert_eq!(
        (
            answers,
            work.0,
            client.overlay_transaction(|t| Ok(t.summary())).unwrap() == before
        ),
        (vec![b"thent".to_vec(); 3], 2, true),
        "resident payload/grain hits retain immutable owned bytes across facade recreation"
    );
    assert!(
        work.1 > 0,
        "nonempty authenticated hash-byte premise: {work:?}"
    );
}

#[test]
fn mediated_verified_range_eviction_refuses_missing_and_corrupt_disk_bytes() {
    let mut observed = Vec::new();
    for corrupt in [false, true] {
        let (scratch, _io, mut client, _authority, _content) = clean_file();
        let path = vec![Name::new(b"file".to_vec()).unwrap()];
        let data = GrainId::of(b"authenticated base");
        let before = client.overlay_transaction(|t| Ok(t.summary())).unwrap();
        assert_eq!(
            client
                .overlay_transaction(|t| t.read_base(&path, 2, 5))
                .unwrap(),
            b"thent"
        );
        if corrupt {
            corrupt_object(&scratch, data);
        } else {
            remove_object(&scratch, data);
        }
        let (resident, resident_work) =
            crate::overlay_store::local_content::measure_local_reads(|| {
                client.overlay_transaction(|t| t.read_base(&path, 2, 5))
            });
        assert_eq!(
            (resident.unwrap(), resident_work),
            (b"thent".to_vec(), (0, 0)),
            "owned verified bytes remain authentic after disk damage"
        );
        client.invalidate_clean_content().unwrap();
        let (refused, work) = crate::overlay_store::local_content::measure_local_reads(|| {
            client.overlay_transaction(|t| t.read_base(&path, 2, 5))
        });
        let class = match refused {
            Err(CoordinationError::Overlay(OverlayError::ContentCorrupt)) => "corrupt",
            Err(CoordinationError::Overlay(OverlayError::ContentUnavailable)) => "unavailable",
            Ok(_) => "success",
            Err(_) => "wrong error",
        };
        observed.push((
            corrupt,
            class,
            work.0,
            client.overlay_transaction(|t| Ok(t.summary())).unwrap() == before,
        ));
    }
    assert_eq!(
        (observed.len(), observed),
        (
            2,
            vec![(false, "unavailable", 2, true), (true, "corrupt", 2, true)]
        ),
        "evicted bytes must be checked again in both nonempty disk routes"
    );
}

#[expect(
    clippy::disallowed_methods,
    reason = "remove only an immutable CAS leaf in exclusively owned scratch to exercise checked cache misses"
)]
pub(super) fn remove_object(scratch: &Scratch, id: GrainId) {
    let digest = id.digest_hex();
    std::fs::remove_file(scratch.0.join("objects").join(&digest[..2]).join(digest)).unwrap();
}

#[test]
fn mediated_verified_spill_range_hits_retain_the_tree_and_parent_checks() {
    let grain = vec![b'x'; 65536];
    let id = GrainId::of(&grain);
    let refs = vec![
        GrainRef {
            id,
            unpacked_len: 65536
        };
        129
    ];
    let leaf = manifest::encode_grain_list_leaf(&refs).unwrap();
    let leaf_id = GrainId::of(&leaf);
    let size = 129 * 65536;
    let payload = manifest::node::file_payload(
        size,
        &FileGrains::Spill {
            grain_count: 129,
            root: leaf_id,
        },
    )
    .unwrap();
    let (_scratch, _io, mut client, _authority, _content) =
        file_client(&payload, size, vec![(id, grain), (leaf_id, leaf)]);
    let path = vec![Name::new(b"file".to_vec()).unwrap()];
    let (answers, work) = crate::overlay_store::local_content::measure_local_reads(|| {
        (0..4)
            .map(|chunk| client.overlay_transaction(|t| t.read_base(&path, chunk * 65536, 65536)))
            .collect::<Vec<_>>()
    });
    assert_eq!(
        (
            answers.iter().all(|answer| answer
                .as_ref()
                .is_ok_and(|bytes| *bytes == vec![b'x'; 65536])),
            answers.len(),
            work.0
        ),
        (true, 4, 3),
        "successive spill chunks reuse payload, list and grain; actual={work:?}"
    );
    assert!(
        work.1 > 65536,
        "nonempty metadata and grain hash bytes: {work:?}"
    );
    client.invalidate_clean_content().unwrap();
    let (answer, cold) = crate::overlay_store::local_content::measure_local_reads(|| {
        client.overlay_transaction(|t| t.read_base(&path, 0, 65536))
    });
    assert_eq!(
        (answer.unwrap(), cold),
        (vec![b'x'; 65536], work),
        "eviction reauthenticates the original indexed spill representation"
    );
}

#[test]
fn verified_payload_hit_rechecks_the_current_namespace_size() {
    let scratch = Scratch::new();
    let store = Store::open(&scratch.0).unwrap();
    let bytes = b"abcdef";
    let data = GrainId::of(bytes);
    let payload = manifest::node::file_payload(
        6,
        &FileGrains::Inline(vec![GrainRef {
            id: data,
            unpacked_len: 6,
        }]),
    )
    .unwrap();
    let content = GrainId::of(&payload);
    store.put(&content, &payload).unwrap();
    store.put(&data, bytes).unwrap();
    let mut memo = crate::overlay_store::verified_range::VerifiedRangeCache::default();
    let mut cases = 0;
    for size in [6, 5] {
        let mut source = crate::overlay_store::local_content::LocalContent::with_cache(
            &store,
            &mut memo,
            Some(size),
        );
        let answer = source
            .read_verified(content, 0, 1)
            .map_err(|error| error.to_string());
        assert_eq!(
            answer,
            if size == 6 {
                Ok(b"a".to_vec())
            } else {
                Err("overlay content authentication failed".to_owned())
            },
            "cached payload must validate the new namespace size, size={size}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2, "nonempty cached-size paired controls: {cases}");
}

#[test]
fn mediated_oversized_grain_uses_checked_range_fallback_on_every_read() {
    let bytes = vec![b'x'; 8_388_608];
    let id = GrainId::of(&bytes);
    let payload = manifest::node::file_payload(
        8_388_608,
        &FileGrains::Inline(vec![GrainRef {
            id,
            unpacked_len: 8_388_608,
        }]),
    )
    .unwrap();
    let (_scratch, _io, mut client, _authority, _content) =
        file_client(&payload, 8_388_608, vec![(id, bytes)]);
    let path = vec![Name::new(b"file".to_vec()).unwrap()];
    let (answers, work) = crate::overlay_store::local_content::measure_local_reads(|| {
        (0..2)
            .map(|chunk| {
                client
                    .overlay_transaction(|t| t.read_base(&path, chunk * 65536, 65536))
                    .unwrap()
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(
        (answers, work.0, work.1 > 16_777_216),
        (vec![vec![b'x'; 65536]; 2], 3, true),
        "oversized grain cannot bypass checked fallback; actual reads/hash bytes={work:?}"
    );
}

#[test]
fn mediated_verified_range_hit_is_refused_after_fence_and_poison() {
    let mut cases = 0;
    for fenced in [false, true] {
        let (_scratch, io, mut client, mut authority, _content) = clean_file();
        let path = vec![Name::new(b"file".to_vec()).unwrap()];
        assert_eq!(
            client
                .overlay_transaction(|t| t.read_base(&path, 2, 5))
                .unwrap(),
            b"thent",
            "nonempty resident range premise"
        );
        if fenced {
            let request = client
                .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                    true
                })
                .unwrap();
            client.dispatch(&request, &Tick(10)).unwrap();
            let receipt = authority.row.unwrap();
            authority.row = Some(Receipt {
                epoch: receipt.epoch + 1,
                instance: [99; 16],
                ..receipt
            });
            let reply = authority.send(&request);
            let refusal = client.complete(
                &request,
                Ok(&reply),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None,
            );
            assert!(
                matches!(refusal, Err(CoordinationError::Fenced { .. })),
                "actual fencing premise: {refusal:?}"
            );
        } else {
            let stage = client
                .overlay_transaction(|t| t.create_file(at("dirty"), false))
                .unwrap();
            io.0.lock().unwrap().fail = Some("sync");
            assert!(
                client
                    .overlay_transaction(|t| {
                        let capture = t.capture(stage)?;
                        t.flush_boundary(&capture)
                    })
                    .is_err(),
                "injected persistence failure must poison"
            );
        }
        let (answer, work) = crate::overlay_store::local_content::measure_local_reads(|| {
            client.overlay_transaction(|t| t.read_base(&path, 2, 5))
        });
        assert_eq!(
            (answer.is_err(), work),
            (true, (0, 0)),
            "cached bytes cannot grant lifecycle readiness, fenced={fenced}, actual={answer:?}"
        );
        if fenced {
            assert!(
                matches!(answer, Err(CoordinationError::Fenced { .. })),
                "typed fence: {answer:?}"
            );
        } else {
            assert!(
                matches!(
                    answer,
                    Err(CoordinationError::Refused("IntentPersistencePoisoned"))
                ),
                "sticky poison class: {answer:?}"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2, "nonempty fence/poison warmed controls: {cases}");
}

#[test]
fn mediated_verified_range_generation_exhaustion_poison_is_sticky() {
    cache_generation_exhaustion(false);
}

#[test]
fn facade_verified_range_generation_exhaustion_poison_is_sticky() {
    cache_generation_exhaustion(true);
}

#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the method item cannot satisfy the transaction facade's higher-ranked borrow"
)]
fn cache_generation_exhaustion(through_facade: bool) {
    let (_scratch, _io, mut client, _authority, _content) = clean_file();
    let path = vec![Name::new(b"file".to_vec()).unwrap()];
    assert_eq!(
        client
            .overlay_transaction(|t| t.read_base(&path, 2, 5))
            .unwrap(),
        b"thent",
        "nonempty resident generation control"
    );
    client.clean_generation_for_test(18_446_744_073_709_551_615);
    let invalidated = if through_facade {
        client.overlay_transaction(|t| t.invalidate_clean_content())
    } else {
        client.invalidate_clean_content()
    };
    assert!(
        matches!(
            invalidated,
            Err(CoordinationError::Overlay(OverlayError::Poisoned))
        ),
        "generation overflow class: {invalidated:?}"
    );
    let (answer, work) = crate::overlay_store::local_content::measure_local_reads(|| {
        client.overlay_transaction(|t| t.read_base(&path, 2, 5))
    });
    assert!(
        matches!(
            answer,
            Err(CoordinationError::Refused("IntentPersistencePoisoned"))
        ),
        "sticky mediated poison: through_facade={through_facade}, actual={answer:?}"
    );
    assert_eq!(
        work,
        (0, 0),
        "no old-generation cache success after overflow"
    );
}

#[test]
fn immutable_content_refuses_nonterminal_ownership_and_release() {
    let mut cases = 0;
    for operation in [Operation::Ownership, Operation::Release] {
        let (_scratch, _io, mut client, _authority, _content) = clean_file();
        assert!(
            client.immutable_content().is_ok(),
            "valid serving content premise: {:?}",
            client.snapshot()
        );
        match operation {
            Operation::Ownership => {
                client.prepare_succession(&Tick(4)).unwrap();
            }
            Operation::Release => {
                client
                    .prepare_release(&Tick(4), std::time::Duration::from_secs(1), None)
                    .unwrap();
            }
            Operation::Register => unreachable!(),
        }
        // Preserve a stale serving phase to isolate the pending-operation guard.
        client.content_phase_for_test(Phase::Serving);
        let pending: Vec<_> = client
            .snapshot()
            .pending
            .iter()
            .filter(|pending| !pending.terminal)
            .map(|pending| pending.operation)
            .collect();
        let result = client
            .immutable_content()
            .err()
            .map(|error| error.to_string());
        assert_eq!(
            (pending, result),
            (
                vec![operation],
                Some("intent refused: WritableRecoveryRequired".to_owned())
            ),
            "a live ownership/release request must close content admission even with a stale serving phase"
        );
        cases += 1;
    }
    assert_eq!(cases, 2, "ownership and release controls must both execute");
}

fn pending_plain_register(attached: bool) {
    let (_scratch, _io, mut client, _authority, _content) = clean_file();
    assert!(
        client.immutable_content().is_ok(),
        "valid serving content premise: {:?}",
        client.snapshot()
    );
    if attached {
        client.attach_sync_engine().unwrap();
    }
    client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(4), |_, _| {
            true
        })
        .unwrap();
    let pending = client
        .snapshot()
        .pending
        .iter()
        .filter(|pending| !pending.terminal && pending.operation == Operation::Register)
        .count();
    let admission = client.content_admission_for_test();
    let result = client
        .immutable_content()
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        (pending, admission, result),
        (
            1,
            (attached, 0),
            Some("intent refused: WritableRecoveryRequired".to_owned())
        ),
        "a non-capture Register must refuse content admission: engine_attached={attached}"
    );
}

#[test]
fn immutable_content_refuses_register_without_engine_or_capture() {
    pending_plain_register(false);
}
#[test]
fn immutable_content_refuses_non_engine_register() {
    pending_plain_register(true);
}
