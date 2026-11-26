// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Admitted clean-file reads and held-object transitions with canonical spill data.

use super::*;
use granary_core::manifest::{
    self, DirEntry, EntryKind, FileGrains, GRAINLIST_LEAF_MAX_REFS, GrainRef,
};

mod lifecycle;

pub(in crate::mount::tests::writable) struct CleanTree {
    pub(in crate::mount::tests::writable) tree: PublishedTree,
    pub(in crate::mount::tests::writable) bytes: Vec<u8>,
    hash_bytes: usize,
    objects: usize,
    pressure: Vec<(Name, GrainId)>,
}

pub(in crate::mount::tests::writable) fn clean_tree(paths: &Paths, spill: bool) -> CleanTree {
    let (count, width) = if spill { (129, 1024) } else { (3, 65_536) };
    clean_tree_with_geometry(paths, count, width)
}

fn clean_tree_with_geometry(paths: &Paths, count: usize, width: usize) -> CleanTree {
    clean_tree_with_pressure(paths, count, width, false)
}

fn clean_tree_with_pressure(
    paths: &Paths,
    count: usize,
    width: usize,
    pressure: bool,
) -> CleanTree {
    const LEAF_REFS: usize = GRAINLIST_LEAF_MAX_REFS as usize;
    let spill = count > 128;
    let mut refs = Vec::new();
    let mut bytes = Vec::new();
    let mut objects = BTreeMap::new();
    for number in 0..count {
        // A multilevel list opens and ends on grains no other leaf names, so
        // a walk that drops either leaf's grains, in whichever order it
        // expands them, is seen.
        let value = match number {
            _ if count > LEAF_REFS && number == 0 => b'c',
            _ if count > LEAF_REFS && number + 1 == count => b'd',
            _ if number % 2 == 0 => b'a',
            _ => b'b',
        };
        let grain = vec![value; width];
        let id = GrainId::of(&grain);
        bytes.extend_from_slice(&grain);
        objects.insert(id, grain);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(width).unwrap(),
        });
    }
    let file_id = refs[0].id;
    let grains = if spill {
        let built = manifest::build_grain_list(&refs).unwrap();
        assert_eq!(
            built.nodes.len(),
            if count == 129 { 1 } else { 3 },
            "canonical spill hierarchy premise: refs={count}"
        );
        objects.extend(built.nodes);
        FileGrains::Spill {
            grain_count: u32::try_from(count).unwrap(),
            root: built.root,
        }
    } else {
        FileGrains::Inline(refs)
    };
    publish_clean_tree(paths, bytes, &grains, objects, file_id, pressure)
}

/// One clean file, under both `f.txt` and `g.txt`, published with its grain
/// and list objects as a signed root at sequence 1.
fn publish_clean_tree(
    paths: &Paths,
    bytes: Vec<u8>,
    grains: &FileGrains,
    mut objects: BTreeMap<GrainId, Vec<u8>>,
    file_id: GrainId,
    pressure: bool,
) -> CleanTree {
    let store = Store::open(&paths.scratch.join("publication")).unwrap();
    let payload = manifest::node::file_payload(bytes.len() as u64, grains).unwrap();
    let hash_bytes = payload.len() + objects.values().map(Vec::len).sum::<usize>();
    let object_count = 1 + objects.len();
    let mut entries = [b"f.txt".as_slice(), b"g.txt"]
        .map(|name| DirEntry {
            name: Name::new(name.to_vec()).unwrap(),
            kind: EntryKind::File {
                exec: false,
                size: bytes.len() as u64,
                grains: grains.clone(),
            },
        })
        .to_vec();
    let pressure_files = if pressure {
        cache_pressure_files(&mut entries, &mut objects)
    } else {
        Vec::new()
    };
    let manifest = manifest::build_dir(&entries).unwrap();
    objects.extend(manifest.nodes);
    for (id, object) in objects {
        store.put(&id, &object).unwrap();
    }
    let mem = Arc::new(InMemory::new());
    let remote = GranaryStore::new(mem.clone());
    let (key, seed) = SigningKey::generate().unwrap();
    let volume = vol("v");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let accepted = rt
        .block_on(crate::publish::accept_from_state(
            &remote,
            &store,
            manifest.root,
            crate::HarvestStats::default(),
            &volume,
            stamp(),
            Policy::default(),
            crate::publish::RemoteState::empty(),
        ))
        .unwrap();
    let mut doc = accepted.doc;
    doc.writer_uuid = *b"mount-writer-id!";
    let prefix = root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    rt.block_on(remote.put_root(volume.as_str(), 1, root::encode_root(&doc).unwrap()))
        .unwrap();
    CleanTree {
        tree: PublishedTree {
            seq: 1,
            seed,
            remote,
            mem,
            key,
            volume,
            file_id,
            manifest_root: doc.manifest_root,
            binmap_index: doc.binmap_index,
            sheaf_head: doc.sheaf_head,
        },
        bytes,
        hash_bytes,
        objects: object_count,
        pressure: pressure_files,
    }
}

fn cache_pressure_files(
    entries: &mut Vec<DirEntry>,
    objects: &mut BTreeMap<GrainId, Vec<u8>>,
) -> Vec<(Name, GrainId)> {
    let mut pressure_files = Vec::new();
    let highest = *objects.keys().max().unwrap();
    let mut candidate = 0u32;
    while pressure_files.len() < 128 {
        let mut data = vec![b'p'; 65_536];
        data[..4].copy_from_slice(&candidate.to_be_bytes());
        candidate += 1;
        let id = GrainId::of(&data);
        if id <= highest {
            continue;
        }
        let name = Name::new(format!("pressure-{:03}", pressure_files.len()).into_bytes()).unwrap();
        entries.push(DirEntry {
            name: name.clone(),
            kind: EntryKind::File {
                exec: false,
                size: 65_536,
                grains: FileGrains::Inline(vec![GrainRef {
                    id,
                    unpacked_len: 65_536,
                }]),
            },
        });
        objects.insert(id, data);
        pressure_files.push((name, id));
    }
    pressure_files
}

fn sequential_reads(spill: bool) {
    let paths = query_paths();
    let fixture = clean_tree(&paths, spill);
    let input = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let first = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    let shared = backend
        .overlay_open(&handler_path(b"g.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            backend.overlay_nodes().unwrap().len(),
            first != shared,
            fixture.bytes.len()
        ),
        (3, true, if spill { 132_096 } else { 196_608 }),
        "nonempty distinct-name content and cardinality premise"
    );
    let mut rounds = Vec::new();
    for object in [first, shared] {
        let (((answers, work), visits), preparation) =
            crate::writable_start::measure_preparation(|| {
                crate::overlay_store::local_content::measure_metadata_visits(|| {
                    crate::overlay_store::local_content::measure_local_reads(|| {
                        fixture
                            .bytes
                            .chunks(65_536)
                            .enumerate()
                            .map(|(number, expected)| {
                                backend.prepare_object(object).unwrap();
                                let got = backend
                                    .read_object(object, (number * 65_536) as u64, 65_536)
                                    .unwrap();
                                assert_eq!(
                                    (got == expected, got.len(), GrainId::of(&got)),
                                    (true, expected.len(), GrainId::of(expected)),
                                    "exact sequential bytes: spill={spill}, chunk={number}"
                                );
                                (got.len(), GrainId::of(&got))
                            })
                            .collect::<Vec<_>>()
                    })
                })
            });
        rounds.push((
            answers,
            work,
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
                (
                    expected.clone(),
                    (fixture.objects, fixture.hash_bytes),
                    (1, if spill { 3 } else { 0 }),
                    if spill { (1, 2) } else { (0, 2) },
                    1
                ),
                (expected, (0, 0), (0, if spill { 3 } else { 0 }), (0, 0), 1),
            ]
        ),
        "resident shared content must prepare once and authenticate each owned object once: spill={spill}"
    );
    backend.overlay_close(first).unwrap();
    backend.overlay_close(shared).unwrap();
}

#[test]
fn writable_inline_sequential_chunks_share_completed_preparation_and_verified_ranges() {
    sequential_reads(false);
}

#[test]
fn writable_spill_sequential_chunks_share_completed_preparation_and_verified_ranges() {
    sequential_reads(true);
}

/// A spill file whose index names one full leaf from each of its three
/// slots: three leaves' worth of references through two list nodes, over
/// five distinct four-byte grains, built by the canonical encoder: three
/// full leaves are the split of three leaves' references, and identical
/// leaves share one id.
fn repeated_leaf_tree(paths: &Paths) -> CleanTree {
    const SLOTS: usize = 3;
    let width = GRAINLIST_LEAF_MAX_REFS as usize;
    let distinct: Vec<Vec<u8>> = (0..5).map(|number| vec![b'a' + number; 4]).collect();
    let refs: Vec<_> = (0..width)
        .map(|number| GrainRef {
            id: GrainId::of(&distinct[number % distinct.len()]),
            unpacked_len: 4,
        })
        .collect();
    let leaf_bytes: Vec<u8> = (0..width)
        .flat_map(|number| distinct[number % distinct.len()].clone())
        .collect();
    let built = manifest::build_grain_list(&refs.repeat(SLOTS)).unwrap();
    let mut objects: BTreeMap<_, _> = distinct
        .into_iter()
        .map(|grain| (GrainId::of(&grain), grain))
        .collect();
    objects.extend(built.nodes);
    assert_eq!(
        objects.len(),
        7,
        "premise: one leaf and one index over five grains"
    );
    let grains = FileGrains::Spill {
        grain_count: u32::try_from(SLOTS * width).unwrap(),
        root: built.root,
    };
    let bytes = leaf_bytes.repeat(SLOTS);
    publish_clean_tree(paths, bytes, &grains, objects, refs[0].id, false)
}

/// Preparing a file whose one leaf is named from several index slots
/// expands each list node once and fetches each distinct grain once, while
/// reads in every slot, and across the slot boundaries, keep their bytes.
/// The work is two list expansions, one per distinct node, and five grain
/// probes, one per distinct grain, whatever the slot count.
#[test]
fn writable_spill_preparation_expands_a_repeated_leaf_once() {
    let paths = query_paths();
    let fixture = repeated_leaf_tree(&paths);
    let input = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let object = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    let (prepared, work) =
        crate::writable_start::measure_preparation(|| backend.prepare_object(object));
    let leaf = fixture.bytes.len() / 3;
    let offsets = [0, leaf - 6, leaf + 1_234, 2 * leaf - 3, 3 * leaf - 10];
    let answers: Vec<_> = offsets
        .iter()
        .map(|&offset| {
            let answer = backend.read_object(object, offset as u64, 4_096);
            (
                offset,
                answer.map(|bytes| (bytes.len(), GrainId::of(&bytes))),
            )
        })
        .collect();
    let expected: Vec<_> = offsets
        .iter()
        .map(|&offset| {
            let bytes = &fixture.bytes[offset..fixture.bytes.len().min(offset + 4_096)];
            (offset, Ok((bytes.len(), GrainId::of(bytes))))
        })
        .collect();
    assert_eq!(
        (prepared, work, backend.materialization_passes, answers),
        (Ok(()), (2, 5), 1, expected),
        "repeated-leaf preparation work and slot reads"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one spill-backed held-object sequence distinguishes shared copy-up and displaced-orphan routing"
)]
fn writable_spill_shared_handles_keep_stage_identity_after_truncate_replace_and_recreation() {
    let paths = query_paths();
    let fixture = clean_tree(&paths, true);
    let input = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let other = handler_path(b"g.txt");
    let moved = handler_path(b"moved");
    let first = backend.overlay_open(&file).unwrap().unwrap();
    let shared = backend.overlay_open(&file).unwrap().unwrap();
    let displaced = backend.overlay_open(&other).unwrap().unwrap();
    assert_eq!(
        (
            first == shared,
            first != displaced,
            backend.overlay_nodes().unwrap().len()
        ),
        (true, true, 3),
        "nonempty shared-handle/shared-content premise"
    );
    for object in [first, displaced] {
        backend.prepare_object(object).unwrap();
        assert_eq!(
            backend.read_object(object, 65_536, 65_536),
            Ok(fixture.bytes[65_536..131_072].to_vec())
        );
    }
    backend
        .overlay_mutate(M::Rename {
            from: &other,
            to: &moved,
            no_replace: false,
        })
        .unwrap();
    backend.prepare_object(displaced).unwrap();
    assert_eq!(
        (
            backend.overlay_object(displaced).unwrap().path,
            backend.materialization_passes
        ),
        (moved.clone(), 1),
        "rename keeps resident content completion"
    );
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
    assert_eq!(
        (
            backend.read_object(shared, 0, 65_536),
            backend.materialization_passes
        ),
        (Ok(b"NEW".to_vec()), 1),
        "shared copy-up/truncate reads stage despite resident clean token"
    );
    backend.prepare_detach(&moved).unwrap();
    backend
        .overlay_mutate(M::Rename {
            from: &file,
            to: &moved,
            no_replace: false,
        })
        .unwrap();
    let stage = backend.overlay_object(displaced).unwrap().stage;
    assert_eq!(
        (
            backend.object_attached_for_test(displaced),
            stage.is_some(),
            backend.overlay_path(&file),
            backend.overlay_open(&moved).unwrap(),
            backend.read_object(displaced, 131_072, 65_536),
            backend.read_object(first, 0, 65_536)
        ),
        (
            Some(false),
            true,
            Err(WriteError::Missing),
            Some(first),
            Ok(fixture.bytes[131_072..].to_vec()),
            Ok(b"NEW".to_vec())
        ),
        "displaced spill object stays detached with old bytes and source identity follows replacement"
    );
    backend.prepare_detach(&moved).unwrap();
    backend
        .overlay_mutate(M::Remove {
            path: &moved,
            directory: false,
        })
        .unwrap();
    backend.overlay_object(first).unwrap();
    assert_eq!(
        (
            backend.object_attached_for_test(first),
            backend.overlay_path(&moved)
        ),
        (Some(false), Err(WriteError::Missing)),
        "unlink removes the replacement name while its source stays held"
    );
    backend
        .overlay_mutate(M::Create {
            path: &moved,
            kind: NodeKind::File,
            exec: false,
        })
        .unwrap();
    let recreated = backend.overlay_open(&moved).unwrap().unwrap();
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
            backend.overlay_object(displaced).unwrap().stage,
            recreated != displaced,
            backend.read_object(displaced, 131_072, 65_536),
            backend.read_object(recreated, 0, 65_536),
            backend.materialization_passes
        ),
        (
            Some(false),
            stage,
            true,
            Ok(fixture.bytes[131_072..].to_vec()),
            Ok(b"fresh".to_vec()),
            1
        ),
        "recreation never reattaches or retargets a displaced stage"
    );
    for object in [first, shared, first, displaced, recreated] {
        backend.overlay_close(object).unwrap();
    }
}

#[test]
fn writable_spill_clean_unlink_shared_handles_never_reattach_to_a_recreated_name() {
    let paths = query_paths();
    let fixture = clean_tree(&paths, true);
    let input = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&input, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let first = backend.overlay_open(&file).unwrap().unwrap();
    let shared = backend.overlay_open(&file).unwrap().unwrap();
    backend.prepare_object(first).unwrap();
    assert_eq!(
        (
            first == shared,
            backend.read_object(first, 131_072, 65_536),
            backend.materialization_passes
        ),
        (true, Ok(fixture.bytes[131_072..].to_vec()), 1),
        "resident nonempty shared spill premise"
    );
    backend.prepare_detach(&file).unwrap();
    backend
        .overlay_mutate(M::Remove {
            path: &file,
            directory: false,
        })
        .unwrap();
    let stage = backend.overlay_object(first).unwrap().stage;
    assert_eq!(
        (
            backend.object_attached_for_test(first),
            stage.is_some(),
            backend.overlay_path(&file)
        ),
        (Some(false), true, Err(WriteError::Missing)),
        "clean unlink stages the held identity and removes its name"
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
    backend
        .overlay_mutate(M::BoundWrite {
            object: shared,
            offset: 131_072,
            bytes: b"!",
            append: false,
        })
        .unwrap();
    let mut tail = fixture.bytes[131_072..].to_vec();
    tail[0] = b'!';
    assert_eq!(
        (
            backend.object_attached_for_test(first),
            backend.overlay_object(shared).unwrap().stage,
            first != recreated,
            backend.read_object(first, 131_072, 65_536),
            backend.read_object(recreated, 0, 65_536),
            backend.materialization_passes
        ),
        (Some(false), stage, true, Ok(tail), Ok(b"fresh".to_vec()), 1),
        "shared orphan writes must retain the old stage and never retarget the recreated path"
    );
    for object in [first, shared, recreated] {
        backend.overlay_close(object).unwrap();
    }
}
