// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{DurableFile, SyncBoundary, SyncTarget};

struct NoBase;
impl ContentSource for NoBase {
    fn read_verified(&mut self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, OverlayError> {
        panic!("new staged fixture unexpectedly read immutable base")
    }
}

fn verify_payload(
    client: &mut WritableStore<SimIo>,
    boundary: &SyncBoundary,
    index: usize,
    grains: FileGrains,
    source: &dyn GrainSource,
    immutable: &mut impl ContentSource,
) -> Result<crate::VerifiedSyncPayload, CoordinationError> {
    let mut verifier = client.begin_sync_payload(boundary, index, grains)?;
    if let Err(error) = verifier.authenticate(source) {
        client.abandon_sync_payload(boundary, verifier)?;
        return Err(error);
    }
    let size = boundary.files()[index].size();
    let mut offset = 0;
    while offset < size {
        let range = client.overlay_transaction(|t| t.captured_range(boundary, index, offset))?;
        if let Err(error) = verifier.consume(range, source, immutable) {
            client.abandon_sync_payload(boundary, verifier)?;
            return Err(error);
        }
        offset += (size - offset).min(65_536);
    }
    client.finish_sync_payload(boundary, verifier)
}

fn seal(client: &mut WritableStore<SimIo>, target: SyncTarget) -> SyncBoundary {
    client.overlay_transaction(|t| t.seal_sync(target)).unwrap()
}

fn prepare(
    client: &mut WritableStore<SimIo>,
    boundary: &SyncBoundary,
    bytes: &[&[u8]],
    objects: &mut Objects,
    known: &mut BTreeMap<GrainId, FileGrains>,
) -> (PendingIntent, Vec<u8>, CaptureCoverageInput) {
    assert_eq!(bytes.len(), boundary.files().len());
    let mut payloads = Vec::new();
    let mut selected = Vec::new();
    for (index, (captured, bytes)) in boundary.files().iter().zip(bytes).enumerate() {
        let grains = file(bytes, objects);
        let content = GrainId::of(&manifest::node::file_payload(captured.size(), &grains).unwrap());
        known.insert(content, grains.clone());
        if let Some(entry) = captured.entry() {
            selected.push(DurableFile {
                inode: entry.inode,
                size: captured.size(),
                content,
                content_boundary: boundary.through_seq(),
            });
        }
        let mut immutable = Source::default();
        for (content, grains) in known.iter() {
            let FileGrains::Inline(refs) = grains else {
                panic!("inline fixture");
            };
            immutable.0.insert(
                *content,
                refs.iter()
                    .flat_map(|r| objects.0[&r.id].iter().copied())
                    .collect(),
            );
        }
        payloads.push(
            verify_payload(client, boundary, index, grains, objects, &mut immutable).unwrap(),
        );
    }
    let projection = boundary.project(&selected).unwrap();
    let entries = projection
        .entries()
        .iter()
        .map(|entry| {
            assert_eq!(entry.path.len(), 1, "flat fixture");
            let OverlayKind::File {
                content: Some(content),
            } = entry.kind
            else {
                panic!("file fixture");
            };
            DirEntry {
                name: entry.path[0].clone(),
                kind: EntryKind::File {
                    exec: entry.exec,
                    size: entry.size,
                    grains: known[&content].clone(),
                },
            }
        })
        .collect::<Vec<_>>();
    let tree = manifest::build_dir(&entries).unwrap();
    objects.0.extend(tree.nodes);
    let mut doc = granary_core::root::decode_root(&root(client.writer_uuid(), 2)).unwrap();
    doc.manifest_root = tree.root;
    let root = granary_core::root::encode_root(&doc).unwrap();
    let input = projection.coverage_input(GrainId::of(&root));
    client
        .overlay_transaction(|t| t.flush_sync_boundary(boundary))
        .unwrap();
    let request = client
        .prepare_sync_registration(&root, boundary.clone(), payloads, &Tick(10), |_, _| true)
        .unwrap();
    (request, root, input)
}

fn complete(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    request: &PendingIntent,
    input: CaptureCoverageInput,
    objects: &Objects,
) -> Vec<crate::CaptureCompletion> {
    client.dispatch(request, &Tick(10)).unwrap();
    finish(client, request, &authority.send(request));
    let work = client.capture_completion_work().unwrap().unwrap();
    let plan = work
        .validate(&BTreeMap::from([(input.prepared_root, input)]), objects)
        .unwrap();
    client.apply_capture_completions(plan).unwrap()
}

fn marks(io: &SimIo) -> Vec<(u64, u64, GrainId)> {
    let path =
        io.0.lock()
            .unwrap()
            .names
            .keys()
            .find(|p| p.ends_with("journal"))
            .unwrap()
            .clone();
    let mut marks = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&io.bytes(&path), |_, record| {
        if let Record::FileSynced {
            stage_id,
            generation,
            content,
            ..
        } = record
        {
            marks.push((*stage_id, *generation, *content));
        }
    })
    .unwrap();
    marks
}

#[test]
fn shared_receipt_completes_all_files_and_retains_post_seal_dirtiness() {
    let (_scratch, io, mut client, mut authority) = serving();
    let a = client
        .overlay_transaction(|t| {
            let a = t.create_file(at("a"), false)?;
            t.write(a, 0, b"abc")?;
            let b = t.create_file(at("b"), false)?;
            t.write(b, 0, b"def")?;
            t.create_file(at("empty"), false)?;
            Ok(a)
        })
        .unwrap();
    let boundary = seal(&mut client, SyncTarget::Tree);
    client
        .overlay_transaction(|t| {
            t.write(a, 1, b"X")?;
            t.namespace_record(Record::Move {
                from: at("b"),
                to: at("moved"),
            })?;
            Ok(())
        })
        .unwrap();
    let mut objects = Objects::default();
    let mut known = BTreeMap::new();
    let (request, root, input) = prepare(
        &mut client,
        &boundary,
        &[b"abc", b"def", b""],
        &mut objects,
        &mut known,
    );
    let results = complete(&mut client, &mut authority, &request, input, &objects);
    assert_eq!(results.len(), 1);
    assert!(results[0].result.is_ok());
    assert_eq!(
        results[0].registered_captures().len(),
        3,
        "multi-file receipt omitted a proof"
    );
    assert_eq!(marks(&io).len(), 3, "multi-file receipt omitted a mark");
    assert_eq!(authority.root, root);
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
    let next = seal(&mut client, SyncTarget::Tree);
    assert_eq!(
        next.files().len(),
        1,
        "whole-tree seal recaptured clean checkpoints"
    );
    assert_eq!(
        next.files()[0].dirty_intervals(),
        vec![(1, 2)],
        "acknowledgement cleared later writes"
    );
    let checkpoint = next.files()[0].checkpoint().unwrap();
    assert_eq!(checkpoint.1, 3);
    assert_eq!(known[&checkpoint.0], file(b"abc", &mut objects));
    let (request, _, input) = prepare(&mut client, &next, &[b"aXc"], &mut objects, &mut known);
    assert!(
        input
            .identities
            .iter()
            .any(|entry| entry.path == vec![name("moved")] && entry.size == 3),
        "later root discarded an unrelated acknowledged projection"
    );
    assert!(
        complete(&mut client, &mut authority, &request, input, &objects)[0]
            .result
            .is_ok()
    );
    let clean = seal(&mut client, SyncTarget::Tree);
    assert!(clean.files().is_empty());
    client.release_sync_boundary(&clean).unwrap();
}

#[test]
fn clean_staged_file_and_directory_register_without_new_file_marks() {
    let (_scratch, io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"durable")?;
            Ok(stage)
        })
        .unwrap();
    let mut objects = Objects::default();
    let mut known = BTreeMap::new();
    let first = seal(&mut client, SyncTarget::Stage(stage));
    let (request, _, input) = prepare(&mut client, &first, &[b"durable"], &mut objects, &mut known);
    assert!(
        complete(&mut client, &mut authority, &request, input, &objects)[0]
            .result
            .is_ok()
    );
    for target in [SyncTarget::Stage(stage), SyncTarget::Directory(None)] {
        let boundary = seal(&mut client, target);
        assert!(boundary.files().iter().all(|file| !file.needs_mark()));
        let bytes: Vec<&[u8]> = boundary
            .files()
            .iter()
            .map(|_| b"durable".as_slice())
            .collect();
        let (request, _, input) = prepare(&mut client, &boundary, &bytes, &mut objects, &mut known);
        let results = complete(&mut client, &mut authority, &request, input, &objects);
        assert!(results[0].result.is_ok());
        assert!(
            results[0].registered_captures().is_empty(),
            "clean completion minted a stage mark"
        );
        assert_eq!(marks(&io).len(), 1);
        assert_eq!(
            client
                .overlay_transaction(|t| Ok(t.summary().captured_bytes))
                .unwrap(),
            0
        );
    }
}

#[test]
fn orphan_receipt_releases_floor_without_a_root_entry_or_file_mark() {
    let (_scratch, io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("gone"), false)?;
            t.write(stage, 0, b"orphan")?;
            // Keep the stage accessible through an open handle after unlink.
            Ok(stage)
        })
        .unwrap();
    client
        .overlay_transaction(|t| t.open_stage(&[name("gone")]))
        .unwrap();
    client
        .overlay_transaction(|t| {
            t.namespace_record(Record::Delete {
                at: at("gone"),
                kind: granary_core::overlay_journal::DeleteKind::File {
                    stage_id: Some(stage),
                },
            })?;
            Ok(())
        })
        .unwrap();
    let boundary = seal(&mut client, SyncTarget::Stage(stage));
    let mut objects = Objects::default();
    let (request, _, input) = prepare(
        &mut client,
        &boundary,
        &[b"orphan"],
        &mut objects,
        &mut BTreeMap::new(),
    );
    assert!(input.identities.is_empty());
    let results = complete(&mut client, &mut authority, &request, input, &objects);
    assert!(results[0].result.is_ok());
    assert!(results[0].registered_captures().is_empty());
    assert!(marks(&io).is_empty());
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
}

#[test]
fn payload_binding_rejects_newer_bytes_and_registration_before_flush() {
    let (_scratch, _io, mut client, _authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"old")?;
            Ok(stage)
        })
        .unwrap();
    let boundary = seal(&mut client, SyncTarget::Stage(stage));
    client
        .overlay_transaction(|t| t.write(stage, 0, b"new"))
        .unwrap();
    let mut objects = Objects::default();
    let wrong = file(b"new", &mut objects);
    assert!(matches!(
        verify_payload(&mut client, &boundary, 0, wrong, &objects, &mut NoBase),
        Err(CoordinationError::Overlay(
            OverlayError::CaptureCoverageLost
        ))
    ));
    let (root, grains) = prepared(client.writer_uuid(), "file", b"old", &mut objects);
    let payload = verify_payload(&mut client, &boundary, 0, grains, &objects, &mut NoBase).unwrap();
    let count = client.snapshot().pending.len();
    assert_eq!(
        client
            .prepare_sync_registration(&root, boundary.clone(), vec![payload], &Tick(10), |_, _| {
                true
            })
            .unwrap_err()
            .to_string(),
        "overlay refused: sync boundary was not flushed"
    );
    assert_eq!(
        client.snapshot().pending.len(),
        count,
        "unflushed seal admitted a request"
    );
    client.release_sync_boundary(&boundary).unwrap();
}

#[test]
fn same_size_overtake_fails_older_shared_seal_and_preserves_winner() {
    let (_scratch, io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let mut objects = Objects::default();
    let mut known = BTreeMap::new();
    let low_boundary = seal(&mut client, SyncTarget::Stage(stage));
    let (low, _, low_input) = prepare(
        &mut client,
        &low_boundary,
        &[b"abc"],
        &mut objects,
        &mut known,
    );
    client.dispatch(&low, &Tick(10)).unwrap();
    client
        .overlay_transaction(|t| t.write(stage, 0, b"xyz"))
        .unwrap();
    let high_boundary = seal(&mut client, SyncTarget::Stage(stage));
    let (high, _, high_input) = prepare(
        &mut client,
        &high_boundary,
        &[b"xyz"],
        &mut objects,
        &mut known,
    );
    client.dispatch(&high, &Tick(10)).unwrap();
    finish(&mut client, &high, &authority.send(&high));
    let results = client
        .complete_capture_queue(
            &BTreeMap::from([
                (low_input.prepared_root, low_input),
                (high_input.prepared_root, high_input),
            ]),
            &objects,
        )
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(matches!(
        results[0].result,
        Err(OverlayError::CaptureCoverageLost)
    ));
    assert!(results[1].result.is_ok());
    assert_eq!(marks(&io).len(), 1);
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
}

#[test]
fn clean_base_file_authenticates_receipt_without_a_stage_mark() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    acquire(&mut client, &mut authority);
    let mut objects = Objects::default();
    let grains = file(b"base", &mut objects);
    let content = GrainId::of(&manifest::node::file_payload(4, &grains).unwrap());
    let mut h = header();
    h.writer = client.writer_uuid();
    client
        .open_overlay(
            h,
            vec![OverlayEntry {
                inode: 1,
                path: vec![name("base")],
                kind: OverlayKind::File {
                    content: Some(content),
                },
                stage_id: None,
                size: 4,
                exec: false,
            }],
            &mut Source(BTreeMap::from([(content, b"base".to_vec())])),
            io.clone(),
        )
        .unwrap();
    register(&mut client, &mut authority, 1);
    let boundary = seal(&mut client, SyncTarget::File(1));
    let (request, _, input) = prepare(
        &mut client,
        &boundary,
        &[b"base"],
        &mut objects,
        &mut BTreeMap::from([(content, grains)]),
    );
    let results = complete(&mut client, &mut authority, &request, input, &objects);
    assert!(results[0].result.is_ok());
    assert!(results[0].registered_captures().is_empty());
    assert!(marks(&io).is_empty());
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
}

#[test]
fn shared_payload_set_rejects_missing_duplicate_and_foreign_files() {
    let (_scratch, _io, mut client, _authority) = serving();
    client
        .overlay_transaction(|t| {
            t.create_file(at("a"), false)?;
            t.create_file(at("b"), false)?;
            Ok(())
        })
        .unwrap();
    let boundary = seal(&mut client, SyncTarget::Tree);
    let other = seal(&mut client, SyncTarget::Tree);
    client
        .overlay_transaction(|t| t.flush_sync_boundary(&boundary))
        .unwrap();
    let objects = Objects::default();
    let root = root(client.writer_uuid(), 2);
    let empty = || FileGrains::Inline(vec![]);
    let count = client.snapshot().pending.len();
    assert!(
        client
            .prepare_sync_registration(&root, boundary.clone(), vec![], &Tick(10), |_, _| true)
            .is_err(),
        "missing payloads admitted a request"
    );
    let first = verify_payload(&mut client, &boundary, 0, empty(), &objects, &mut NoBase).unwrap();
    let duplicate =
        verify_payload(&mut client, &boundary, 0, empty(), &objects, &mut NoBase).unwrap();
    assert!(
        client
            .prepare_sync_registration(
                &root,
                boundary.clone(),
                vec![first, duplicate],
                &Tick(10),
                |_, _| true
            )
            .is_err(),
        "duplicate payloads admitted a request"
    );
    let first = verify_payload(&mut client, &boundary, 0, empty(), &objects, &mut NoBase).unwrap();
    let foreign = verify_payload(&mut client, &other, 1, empty(), &objects, &mut NoBase).unwrap();
    assert!(
        client
            .prepare_sync_registration(
                &root,
                boundary.clone(),
                vec![first, foreign],
                &Tick(10),
                |_, _| true
            )
            .is_err(),
        "foreign payload admitted a request"
    );
    assert_eq!(client.snapshot().pending.len(), count);
    client.release_sync_boundary(&boundary).unwrap();
    client.release_sync_boundary(&other).unwrap();
}

#[test]
fn dirty_checkpoint_ranges_cover_gap_extension_truncation_and_same_value_write() {
    let (_scratch, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let mut objects = Objects::default();
    let mut known = BTreeMap::new();
    let first = seal(&mut client, SyncTarget::Stage(stage));
    let (request, _, input) = prepare(&mut client, &first, &[b"abc"], &mut objects, &mut known);
    assert!(
        complete(&mut client, &mut authority, &request, input, &objects)[0]
            .result
            .is_ok()
    );
    client
        .overlay_transaction(|t| t.write(stage, 1, b"b"))
        .unwrap();
    let same = seal(&mut client, SyncTarget::Stage(stage));
    assert_eq!(
        same.files()[0].dirty_intervals(),
        vec![(1, 2)],
        "same-value write lost its dirty boundary"
    );
    client.release_sync_boundary(&same).unwrap();
    client
        .overlay_transaction(|t| t.write(stage, 6, b"x"))
        .unwrap();
    let extension = seal(&mut client, SyncTarget::Stage(stage));
    assert_eq!(
        extension.files()[0].dirty_intervals(),
        vec![(1, 2), (3, 7)],
        "extension omitted explicit zeros"
    );
    client.release_sync_boundary(&extension).unwrap();
    // Truncate remains a mediator transaction through the retained stage API.
    client
        .overlay_transaction(|t| t.truncate(stage, 2))
        .unwrap();
    let truncation = seal(&mut client, SyncTarget::Stage(stage));
    assert_eq!(
        truncation.files()[0].dirty_intervals(),
        // The removed tail past the acknowledged size is not a change from
        // the checkpoint, so it is clipped to the larger of the two sizes.
        vec![(1, 3)],
        "truncate omitted removed EOF"
    );
    client.release_sync_boundary(&truncation).unwrap();
}

#[test]
fn incremental_verifier_allows_writes_and_rejects_missing_or_foreign_ranges() {
    let (_scratch, _io, mut client, _authority) = serving();
    let bytes = vec![b'a'; 65_537];
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, &bytes)?;
            Ok(stage)
        })
        .unwrap();
    let boundary = seal(&mut client, SyncTarget::Stage(stage));
    let other = seal(&mut client, SyncTarget::Stage(stage));
    let mut objects = Objects::default();
    let grains = file(&bytes, &mut objects);
    let mut verifier = client
        .begin_sync_payload(&boundary, 0, grains.clone())
        .unwrap();
    verifier.authenticate(&objects).unwrap();
    let first = client
        .overlay_transaction(|t| t.captured_range(&boundary, 0, 0))
        .unwrap();
    // The verifier owns no mediator facade while callbacks/materialization pause.
    client
        .overlay_transaction(|t| t.write(stage, 65_536, b"x"))
        .unwrap();
    verifier.consume(first, &objects, &mut NoBase).unwrap();
    let last = client
        .overlay_transaction(|t| t.captured_range(&boundary, 0, 65_536))
        .unwrap();
    verifier.consume(last, &objects, &mut NoBase).unwrap();
    client.finish_sync_payload(&boundary, verifier).unwrap();
    let mut incomplete = client
        .begin_sync_payload(&boundary, 0, grains.clone())
        .unwrap();
    incomplete.authenticate(&objects).unwrap();
    assert!(
        client.finish_sync_payload(&boundary, incomplete).is_err(),
        "incomplete verifier minted a payload"
    );
    let mut foreign = client.begin_sync_payload(&boundary, 0, grains).unwrap();
    foreign.authenticate(&objects).unwrap();
    let range = client
        .overlay_transaction(|t| t.captured_range(&other, 0, 0))
        .unwrap();
    assert!(
        foreign.consume(range, &objects, &mut NoBase).is_err(),
        "foreign range minted a payload"
    );
    client.abandon_sync_payload(&boundary, foreign).unwrap();
    client.release_sync_boundary(&boundary).unwrap();
    client.release_sync_boundary(&other).unwrap();
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
}

#[test]
fn owned_completion_allows_writes_and_rejects_a_second_application() {
    let (_scratch, io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let boundary = seal(&mut client, SyncTarget::Stage(stage));
    let mut objects = Objects::default();
    let (request, _, input) = prepare(
        &mut client,
        &boundary,
        &[b"abc"],
        &mut objects,
        &mut BTreeMap::new(),
    );
    client.dispatch(&request, &Tick(10)).unwrap();
    finish(&mut client, &request, &authority.send(&request));
    let work = client.capture_completion_work().unwrap().unwrap();
    let duplicate = client.capture_completion_work().unwrap().unwrap();
    client
        .overlay_transaction(|t| t.write(stage, 1, b"X"))
        .unwrap();
    let inputs = BTreeMap::from([(input.prepared_root, input)]);
    let plan = work.validate(&inputs, &objects).unwrap();
    let duplicate = duplicate.validate(&inputs, &objects).unwrap();
    assert!(
        client.apply_capture_completions(plan).unwrap()[0]
            .result
            .is_ok()
    );
    assert!(
        client.apply_capture_completions(duplicate).is_err(),
        "stale completion applied twice"
    );
    assert_eq!(marks(&io).len(), 1);
    let next = seal(&mut client, SyncTarget::Stage(stage));
    assert_eq!(next.files()[0].dirty_intervals(), vec![(1, 2)]);
    client.release_sync_boundary(&next).unwrap();
}

#[test]
fn unsynced_replacement_preserves_detached_checkpoint_and_excludes_dependants() {
    let (_scratch, io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("target"), false)?;
            t.write(stage, 0, b"durable")?;
            Ok(stage)
        })
        .unwrap();
    let first = seal(&mut client, SyncTarget::Stage(stage));
    let mut objects = Objects::default();
    let mut known = BTreeMap::new();
    let (request, _, input) = prepare(&mut client, &first, &[b"durable"], &mut objects, &mut known);
    assert!(
        complete(&mut client, &mut authority, &request, input, &objects)[0]
            .result
            .is_ok()
    );
    client
        .overlay_transaction(|t| {
            t.create_file(at("replacement"), false)?;
            t.namespace_record(Record::Replace {
                from: at("replacement"),
                to: at("target"),
            })?;
            t.namespace_record(Record::Move {
                from: at("target"),
                to: at("later"),
            })?;
            Ok(())
        })
        .unwrap();
    let directory = seal(&mut client, SyncTarget::Directory(None));
    let (request, _, input) = prepare(&mut client, &directory, &[], &mut objects, &mut known);
    assert_eq!(
        input.identities.len(),
        1,
        "detached durable checkpoint was discarded"
    );
    assert_eq!(input.identities[0].path, vec![name("target")]);
    assert_eq!(input.identities[0].size, 7);
    assert!(
        complete(&mut client, &mut authority, &request, input, &objects)[0]
            .result
            .is_ok()
    );
    assert_eq!(marks(&io).len(), 1);
}

#[test]
fn checkpoint_ranges_reuse_immutable_content_and_pin_only_later_edits() {
    let (_scratch, _io, mut client, mut authority) = serving();
    let bytes = vec![b'a'; 65_536 * 3];
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, &bytes)?;
            Ok(stage)
        })
        .unwrap();
    let first = seal(&mut client, SyncTarget::Stage(stage));
    let mut objects = Objects::default();
    let mut known = BTreeMap::new();
    let (request, _, input) = prepare(&mut client, &first, &[&bytes], &mut objects, &mut known);
    assert!(
        complete(&mut client, &mut authority, &request, input, &objects)[0]
            .result
            .is_ok()
    );
    client
        .overlay_transaction(|t| t.write(stage, 65_541, b"x"))
        .unwrap();
    let next = seal(&mut client, SyncTarget::Stage(stage));
    assert_eq!(next.files()[0].dirty_intervals(), vec![(65_541, 65_542)]);
    assert!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap()
            < bytes.len() as u64,
        "checkpoint seal pinned unchanged staging bytes"
    );
    let parts = client
        .overlay_transaction(|t| t.captured_parts(&next, &next.files()[0], 0))
        .unwrap();
    assert!(
        parts
            .iter()
            .all(|part| matches!(part, crate::CapturedPart::Immutable { .. })),
        "unchanged captured range did not use the immutable checkpoint"
    );
    client.release_sync_boundary(&next).unwrap();
}

#[test]
fn prepare_sync_registration_refreshes_retained_bundle() {
    let (_scratch, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"durable")?;
            Ok(stage)
        })
        .unwrap();
    let mut objects = Objects::default();
    let mut known = BTreeMap::new();
    for round in 0..3 {
        let boundary = seal(&mut client, SyncTarget::Stage(stage));
        let (request, _, input) = prepare(
            &mut client,
            &boundary,
            &[b"durable"],
            &mut objects,
            &mut known,
        );
        let retained = client.overlay_bundle().unwrap();
        client.overlay_transaction(|_| Ok(())).unwrap();
        let fresh = client.overlay_bundle().unwrap();
        assert_eq!(
            retained, fresh,
            "round {round}: stale retained bundle after prepare_sync_registration"
        );
        assert!(
            complete(&mut client, &mut authority, &request, input, &objects)[0]
                .result
                .is_ok()
        );
    }
}

#[test]
fn failed_sync_registration_releases_and_refreshes_retained_bundle() {
    let (_scratch, _io, mut client, _authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"durable")?;
            Ok(stage)
        })
        .unwrap();
    let boundary = seal(&mut client, SyncTarget::Stage(stage));
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "file", b"durable", &mut objects);
    let payload = verify_payload(&mut client, &boundary, 0, grains, &objects, &mut NoBase).unwrap();
    client
        .overlay_transaction(|t| t.flush_sync_boundary(&boundary))
        .unwrap();
    let before = client.overlay_bundle().unwrap();
    let failed =
        client.prepare_sync_registration(&root, boundary, vec![payload], &Tick(10), |_, _| false);
    assert!(
        failed
            .as_ref()
            .is_err_and(|error| error.to_string().contains("IntentPreparedSignature")),
        "registration failure premise: {failed:?}"
    );
    let retained = client.overlay_bundle().unwrap();
    client.overlay_transaction(|_| Ok(())).unwrap();
    assert_eq!(
        (retained, client.overlay_bundle().unwrap()),
        (before, before),
        "failed registration did not retain its released charge"
    );
}
