// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{CaptureCoverageInput, StageMutation, StageProjection};
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::manifest::{self, DirEntry, EntryKind, FileGrains, GrainRef};
mod bundle;
mod sync;

#[derive(Default)]
struct Objects(BTreeMap<GrainId, Vec<u8>>, std::sync::Mutex<Vec<GrainId>>);
impl GrainSource for Objects {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.1.lock().unwrap().push(*id);
        self.0
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }
    fn has(&self, id: &GrainId) -> bool {
        self.0.contains_key(id)
    }
}
fn file(bytes: &[u8], objects: &mut Objects) -> FileGrains {
    let refs = if bytes.is_empty() {
        vec![]
    } else {
        let id = GrainId::of(bytes);
        objects.0.insert(id, bytes.to_vec());
        vec![GrainRef {
            id,
            unpacked_len: u32::try_from(bytes.len()).unwrap(),
        }]
    };
    FileGrains::Inline(refs)
}
fn prepared(
    writer: [u8; 16],
    path: &str,
    bytes: &[u8],
    objects: &mut Objects,
) -> (Vec<u8>, FileGrains) {
    let grains = file(bytes, objects);
    let tree = manifest::build_dir(&[DirEntry {
        name: Name::new(path.as_bytes().to_vec()).unwrap(),
        kind: EntryKind::File {
            exec: false,
            size: bytes.len() as u64,
            grains: grains.clone(),
        },
    }])
    .unwrap();
    objects.0.extend(tree.nodes);
    let mut doc = granary_core::root::decode_root(&root(writer, 2)).unwrap();
    doc.manifest_root = tree.root;
    (granary_core::root::encode_root(&doc).unwrap(), grains)
}
pub(super) fn capture(client: &mut WritableStore<SimIo>, stage: u64) -> CaptureToken {
    client
        .overlay_transaction(|t| {
            let c = t.capture(stage)?;
            t.flush_boundary(&c)?;
            Ok(c)
        })
        .unwrap()
}

#[test]
fn exact_prefix_disposal_remains_available_after_fence_or_poison() {
    let mut count = 0;
    for poison in [false, true] {
        let (_scratch, io, mut client, mut authority) = serving();
        let boundary = client
            .overlay_transaction(|transaction| {
                let stage = transaction.create_file(at("file"), false)?;
                transaction.write(stage, 0, b"captured")?;
                transaction.seal_sync(crate::SyncTarget::Stage(stage))
            })
            .unwrap();
        if poison {
            io.0.lock().unwrap().fail = Some("sync");
            assert!(
                client
                    .overlay_transaction(|transaction| transaction.flush_sync_boundary(&boundary))
                    .is_err()
            );
        } else {
            let request = client
                .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                    true
                })
                .unwrap();
            client.dispatch(&request, &Tick(10)).unwrap();
            authority.row = None;
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
        }
        assert!(
            client
                .overlay_transaction(|transaction| transaction.entries().map(|_| ()))
                .is_err()
        );
        let disposal = client.release_sync_boundary(&boundary);
        assert!(
            disposal.is_ok(),
            "exact disposal blocked by service readiness: {disposal:?}"
        );
        assert_eq!(
            client
                .release_sync_boundary(&boundary)
                .unwrap_err()
                .to_string(),
            "overlay refused: sync boundary context"
        );
        assert!(
            client
                .overlay_transaction(|transaction| transaction.entries().map(|_| ()))
                .is_err(),
            "disposal reopened unavailable service"
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[expect(
    clippy::too_many_lines,
    reason = "one overlap schedule compares the original and covering caller outcomes, journal and mirror together"
)]
fn overtake(change: &str) {
    let (_scratch, io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let id = t.create_file(at("old"), false)?;
            t.write(id, 0, b"abc")?;
            Ok(id)
        })
        .unwrap();
    let old = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (low_root, low_grains) = prepared(client.writer_uuid(), "old", b"abc", &mut objects);
    let low = client
        .prepare_captured_registration(&low_root, old.clone(), low_grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    let (path, bytes, mutation) = match change {
        "rename" => ("new", b"abc".as_slice(), None),
        "append" | "grain_hash" | "grain_length" => ("old", b"abcdef".as_slice(), Some((3, 3))),
        "overwrite" => ("old", b"xbc".as_slice(), Some((0, 1))),
        "same" => ("old", b"abc".as_slice(), Some((0, 1))),
        "truncate" | "size" => ("old", b"ab".as_slice(), None),
        "digest" => ("old", b"xbc".as_slice(), None),
        "boundary" | "cover_boundary" | "reuse" | "root_binding" | "rollback" => {
            ("old", b"abc".as_slice(), None)
        }
        _ => panic!("unknown fixture"),
    };
    if let Some((offset, length)) = mutation {
        client
            .overlay_transaction(|t| {
                t.write(
                    stage,
                    offset,
                    &bytes[usize::try_from(offset).unwrap()
                        ..usize::try_from(offset).unwrap() + length],
                )
            })
            .unwrap();
    }
    if mutation.is_none() {
        client
            .overlay_transaction(|t| t.create_file(at("unrelated"), false))
            .unwrap();
    }
    let high_capture = capture(&mut client, stage);
    // Shrink is blocked by the outstanding floor; the malformed projection is
    // constructed deliberately, rather than shrinking live staging.
    let high_bytes = if change == "truncate" {
        b"abc".as_slice()
    } else {
        bytes
    };
    let (mut high_root, mut high_grains) =
        prepared(client.writer_uuid(), path, high_bytes, &mut objects);
    if change == "grain_hash" {
        objects.0.insert(GrainId::of(b"abcdef"), b"abczzz".to_vec());
    }
    if change == "grain_length" {
        high_grains = FileGrains::Inline(vec![GrainRef {
            id: GrainId::of(b"abc"),
            unpacked_len: 6,
        }]);
        let tree = manifest::build_dir(&[DirEntry {
            name: Name::new(path.as_bytes().to_vec()).unwrap(),
            kind: EntryKind::File {
                exec: false,
                size: 6,
                grains: high_grains.clone(),
            },
        }])
        .unwrap();
        let mut doc = granary_core::root::decode_root(&high_root).unwrap();
        doc.manifest_root = tree.root;
        objects.0.extend(tree.nodes);
        high_root = granary_core::root::encode_root(&doc).unwrap();
    }
    let expected_content =
        GrainId::of(&manifest::node::file_payload(high_bytes.len() as u64, &high_grains).unwrap());
    let high = client
        .prepare_captured_registration(
            &high_root,
            high_capture.clone(),
            high_grains,
            &Tick(11),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&high, &Tick(11)).unwrap();
    let answer = authority.send(&high);
    client
        .complete(
            &high,
            Ok(&answer),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let boundary = high_capture.through_seq().max(old.through_seq() + 1);
    let mut input = CaptureCoverageInput {
        prepared_root: GrainId::of(&high_root),
        boundary,
        projections: vec![StageProjection {
            stage_id: stage,
            incarnation: old.incarnation(),
            path: vec![Name::new(path.as_bytes().to_vec()).unwrap()],
            content_boundary: boundary,
        }],
        mutations: vec![],
        identities: vec![],
    };
    if let Some((offset, length)) = mutation {
        input.mutations.push(StageMutation::Write {
            seq: boundary,
            stage_id: stage,
            incarnation: old.incarnation(),
            offset,
            length: length as u64,
        });
    }
    if change == "truncate" {
        input.mutations.push(StageMutation::Truncate {
            seq: old.through_seq() + 1,
            stage_id: stage,
            incarnation: old.incarnation(),
            size: 2,
        });
    }
    if change == "rollback" {
        input.mutations.push(StageMutation::Rollback {
            seq: old.through_seq() + 1,
            stage_id: stage,
            incarnation: old.incarnation(),
        });
    }
    if change == "root_binding" {
        input.prepared_root = grain(99);
    }
    if change == "boundary" {
        input.projections[0].content_boundary = old.through_seq() - 1;
    }
    if change == "cover_boundary" {
        input.boundary = old.through_seq() - 1;
    }
    if change == "reuse" {
        input.projections[0].incarnation += 1;
    }
    // The journal touch must fall strictly after the older boundary and at or
    // before the covering boundary, but before the newer capture's boundary.
    if change == "same" || change == "overwrite" || change == "append" {
        input.mutations[0] = StageMutation::Write {
            seq: high_capture.through_seq(),
            stage_id: stage,
            incarnation: old.incarnation(),
            offset: mutation.unwrap().0,
            length: mutation.unwrap().1 as u64,
        };
    }
    let completed = client.complete_capture_queue(
        &BTreeMap::from([(GrainId::of(&high_root), input)]),
        &objects,
    );
    assert!(
        completed.is_ok(),
        "root-bound capture validation must refuse per caller before mutation: {completed:?}"
    );
    let results = completed.unwrap();
    if change == "size" {
        assert!(
            !objects.1.lock().unwrap().contains(&GrainId::of(b"ab")),
            "size refusal avoids grain reads"
        );
    }
    assert_eq!(results.len(), 2, "ordered capture count");
    assert!(
        results.iter().all(
            |completion| completion.registered_capture().is_some() == completion.result.is_ok()
        ),
        "only completed covered captures expose a sealed proof"
    );
    assert_eq!(
        results.iter().map(|r| r.generation).collect::<Vec<_>>(),
        vec![2, 3],
        "ordered capture generations"
    );
    let covered = matches!(change, "rename" | "append");
    assert_eq!(
        results[0].result.is_ok(),
        covered,
        "older coverage {change}"
    );
    if !covered {
        assert!(
            matches!(results[0].result, Err(OverlayError::CaptureCoverageLost)),
            "coverage loss is typed"
        );
    }
    // Prefix-touch overtakes preserve the newer capture's own outcome.
    // Invalid shared covering provenance/content can fail both captures.
    assert_eq!(
        results[1].result.is_ok(),
        !matches!(
            change,
            "reuse"
                | "digest"
                | "boundary"
                | "cover_boundary"
                | "size"
                | "grain_hash"
                | "grain_length"
                | "root_binding"
        ),
        "newer acknowledgement {change}"
    );
    let journal =
        io.0.lock()
            .unwrap()
            .names
            .keys()
            .find(|path| path.file_name().is_some_and(|name| name == "journal"))
            .unwrap()
            .clone();
    let mut generations = Vec::new();
    let mut file_marks = Vec::new();
    granary_core::overlay_journal::scan_journal_with(
        &io.bytes(&journal),
        |_, record| match record {
            granary_core::overlay_journal::Record::FileSynced {
                generation,
                synced_size,
                content,
                ..
            } => {
                generations.push(*generation);
                file_marks.push((*synced_size, *content));
            }
            granary_core::overlay_journal::Record::IntentRegistered { generation, .. } => {
                generations.push(*generation);
            }
            _ => {}
        },
    )
    .unwrap();
    assert!(
        !generations.is_empty() && generations.windows(2).all(|pair| pair[0] <= pair[1]),
        "journal completions never decrease"
    );
    if results[1].result.is_ok() {
        assert_eq!(
            file_marks,
            vec![(high_capture.size(), expected_content)],
            "one unambiguous covering mirror and canonical payload id"
        );
    } else {
        assert!(
            file_marks.is_empty(),
            "failed captures cannot mint file marks"
        );
    }
    assert_eq!(
        client.snapshot().phase,
        Phase::Serving,
        "coverage refusal must not poison"
    );
    assert_eq!(
        intent::decode_receipt(&client.snapshot().current)
            .unwrap()
            .generation,
        3
    );
    client
        .overlay_transaction(|t| t.create_file(at("after"), false))
        .unwrap();
}
#[test]
fn rename_overtake_is_covered() {
    overtake("rename");
}
#[test]
fn append_overtake_is_covered() {
    overtake("append");
}
#[test]
fn prefix_overwrite_fails_older_call() {
    overtake("overwrite");
}
#[test]
fn same_value_overwrite_fails_older_call() {
    overtake("same");
}
#[test]
fn truncate_overtake_loses_coverage() {
    overtake("truncate");
}
#[test]
fn a_capture_spanning_a_rollback_is_lost() {
    overtake("rollback");
}

#[test]
fn stage_identity_reuse_loses_coverage() {
    overtake("reuse");
}

#[test]
fn empty_inline_payload_has_content_identity() {
    let (_scratch, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| t.create_file(at("empty"), false))
        .unwrap();
    let c = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "empty", b"", &mut objects);
    assert_eq!(
        manifest::node::file_payload(0, &grains).unwrap(),
        vec![0; 12]
    );
    let request = client
        .prepare_captured_registration(&root, c.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let input = CaptureCoverageInput {
        prepared_root: GrainId::of(&root),
        boundary: c.through_seq(),
        projections: vec![StageProjection {
            stage_id: stage,
            incarnation: c.incarnation(),
            path: vec![Name::new(b"empty".to_vec()).unwrap()],
            content_boundary: c.through_seq(),
        }],
        mutations: vec![],
        identities: vec![],
    };
    let results = client
        .complete_capture_queue(&BTreeMap::from([(input.prepared_root, input)]), &objects)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].result.is_ok());
}

#[test]
fn unauthenticated_prefix_cannot_cover_capture() {
    overtake("digest");
}
#[test]
fn older_content_boundary_cannot_cover_capture() {
    overtake("boundary");
}
#[test]
fn older_seal_boundary_cannot_cover_capture() {
    overtake("cover_boundary");
}
#[test]
fn shorter_file_cannot_cover_capture() {
    overtake("size");
}

#[test]
fn covering_grain_hash_must_authenticate_even_unchanged_prefix() {
    overtake("grain_hash");
}
#[test]
fn covering_grain_length_must_match_authenticated_bytes() {
    overtake("grain_length");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the paired spilled-list refusal and distinct-call control share one authority and persistence schedule"
)]
fn spill_list_is_authenticated_and_failure_requires_a_separate_recapture() {
    let (_scratch, io, mut client, mut authority) = serving();
    let bytes = vec![b'a'; 129];
    let stage = client
        .overlay_transaction(|t| {
            let id = t.create_file(at("spill"), false)?;
            t.write(id, 0, &bytes)?;
            Ok(id)
        })
        .unwrap();
    let mut objects = Objects::default();
    let data = GrainId::of(b"a");
    objects.0.insert(data, b"a".to_vec());
    let list = manifest::build_grain_list(&vec![
        GrainRef {
            id: data,
            unpacked_len: 1
        };
        129
    ])
    .unwrap();
    let list_root = list.root;
    let grains = FileGrains::Spill {
        grain_count: 129,
        root: list_root,
    };
    objects.0.extend(list.nodes);
    let tree = manifest::build_dir(&[DirEntry {
        name: Name::new(b"spill".to_vec()).unwrap(),
        kind: EntryKind::File {
            exec: false,
            size: 129,
            grains: grains.clone(),
        },
    }])
    .unwrap();
    let mut doc = granary_core::root::decode_root(&root(client.writer_uuid(), 2)).unwrap();
    doc.manifest_root = tree.root;
    objects.0.extend(tree.nodes);
    let root = granary_core::root::encode_root(&doc).unwrap();
    let canonical_list = objects.0[&list_root].clone();
    let mut corrupt = canonical_list.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut cases = 0;
    for valid in [false, true] {
        // Each iteration is a distinct caller/token; a failed call never silently
        // substitutes a newer snapshot for its original boundary.
        let captured = capture(&mut client, stage);
        let request = client
            .prepare_captured_registration(
                &root,
                captured.clone(),
                grains.clone(),
                &Tick(10 + cases),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(10 + cases)).unwrap();
        let answer = authority.send(&request);
        client
            .complete(
                &request,
                Ok(&answer),
                &Tick(11 + cases),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        objects.0.insert(
            list_root,
            if valid {
                canonical_list.clone()
            } else {
                corrupt.clone()
            },
        );
        let input = CaptureCoverageInput {
            prepared_root: GrainId::of(&root),
            boundary: captured.through_seq(),
            projections: vec![StageProjection {
                stage_id: stage,
                incarnation: captured.incarnation(),
                path: vec![Name::new(b"spill".to_vec()).unwrap()],
                content_boundary: captured.through_seq(),
            }],
            mutations: vec![],
            identities: vec![],
        };
        let results = client
            .complete_capture_queue(&BTreeMap::from([(input.prepared_root, input)]), &objects)
            .unwrap();
        assert_eq!(results.len(), 1, "spill control is nonempty");
        assert_eq!(
            results[0].result.is_ok(),
            valid,
            "spill authentication refusal/control"
        );
        if !valid {
            assert!(matches!(
                results[0].result,
                Err(OverlayError::CaptureCoverageLost)
            ));
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
    let journal =
        io.0.lock()
            .unwrap()
            .names
            .keys()
            .find(|path| path.file_name().is_some_and(|name| name == "journal"))
            .unwrap()
            .clone();
    let mut marks = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&io.bytes(&journal), |_, record| {
        if let granary_core::overlay_journal::Record::FileSynced { content, .. } = record {
            marks.push(*content);
        }
    })
    .unwrap();
    assert_eq!(
        marks,
        vec![GrainId::of(
            &manifest::node::file_payload(129, &grains).unwrap()
        )],
        "spill payload id includes the authenticated list root"
    );
}

#[test]
fn covering_provenance_is_bound_to_exact_retained_root() {
    overtake("root_binding");
}

fn coverage(root: &[u8], capture: &CaptureToken, path: &str) -> CaptureCoverageInput {
    CaptureCoverageInput {
        prepared_root: GrainId::of(root),
        boundary: capture.through_seq(),
        projections: vec![StageProjection {
            stage_id: capture.stage_id(),
            incarnation: capture.incarnation(),
            path: vec![Name::new(path.as_bytes().to_vec()).unwrap()],
            content_boundary: capture.through_seq(),
        }],
        mutations: vec![],
        identities: vec![],
    }
}

fn finish(client: &mut WritableStore<SimIo>, request: &PendingIntent, answer: &IntentReply) {
    client
        .complete(
            request,
            Ok(answer),
            &Tick(20),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
}

#[test]
fn covering_answer_rejects_late_lower_receipt() {
    let (_s, _io, mut client, mut authority) = serving();
    for seed in 2..5 {
        register(&mut client, &mut authority, seed);
    }
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let captured = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "file", b"abc", &mut objects);
    let low = client
        .prepare_captured_registration(&root, captured.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    let middle = client
        .prepare_registration(&root, vec![], &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&middle, &Tick(10)).unwrap();
    let late = authority.send(&middle);
    let skipped = client
        .prepare_registration(&root, vec![], &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&skipped, &Tick(10)).unwrap();
    let high = client
        .prepare_registration(&root, vec![], &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&high, &Tick(10)).unwrap();
    finish(&mut client, &high, &authority.send(&high));
    assert!(
        matches!(
            client.complete(
                &middle,
                Ok(&late),
                &Tick(21),
                &mut SeededRng::new(1),
                0,
                None
            ),
            Err(CoordinationError::Refused("IntentRequestNotRetained"))
        ),
        "late lower accepted receipt is rejected before covering answers change"
    );
    let answer = &client
        .snapshot()
        .pending
        .iter()
        .find(|p| p.body == low.bytes())
        .unwrap()
        .answer;
    assert_eq!(intent::decode_receipt(answer).unwrap().generation, 8);
    let results = client
        .complete_capture_queue(
            &BTreeMap::from([(GrainId::of(&root), coverage(&root, &captured, "file"))]),
            &objects,
        )
        .unwrap();
    assert!(results[0].result.is_ok());
    assert!(client.reopened_captures().unwrap().is_empty());
}

#[test]
fn missing_covering_root_fails_one_capture_and_drains_follower() {
    let (_s, _io, mut client, mut authority) = serving();
    for seed in 2..5 {
        register(&mut client, &mut authority, seed);
    }
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let captured = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (low_root, grains) = prepared(client.writer_uuid(), "file", b"abc", &mut objects);
    let low = client
        .prepare_captured_registration(&low_root, captured, grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    let middle = client
        .prepare_registration(&low_root, vec![], &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&middle, &Tick(10)).unwrap();
    authority.send(&middle);
    finish(&mut client, &low, &authority.send(&low));
    assert!(
        !client
            .snapshot()
            .pending
            .iter()
            .any(|p| p.body == middle.bytes())
    );
    client
        .overlay_transaction(|t| t.write(stage, 3, b"def"))
        .unwrap();
    let later = capture(&mut client, stage);
    let (high_root, grains) = prepared(client.writer_uuid(), "file", b"abcdef", &mut objects);
    let follower = client
        .prepare_captured_registration(&high_root, later.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&follower, &Tick(10)).unwrap();
    let high = client
        .prepare_registration(&high_root, vec![], &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&high, &Tick(10)).unwrap();
    finish(&mut client, &high, &authority.send(&high));
    let results = client.complete_capture_queue(
        &BTreeMap::from([(
            GrainId::of(&high_root),
            coverage(&high_root, &later, "file"),
        )]),
        &objects,
    );
    assert!(
        results.is_ok(),
        "missing covering root must fail only its caller: {results:?}"
    );
    let results = results.unwrap();
    assert_eq!(results.len(), 2);
    assert!(matches!(
        results[0].result,
        Err(OverlayError::CaptureCoverageLost)
    ));
    assert!(results[0].registered_capture().is_none());
    assert!(results[1].result.is_ok());
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
    assert!(client.reopened_captures().unwrap().is_empty());
    client
        .prepare_release(&Tick(30), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
}

#[test]
fn larger_exact_prefix_without_latest_mark_requires_recapture() {
    let (_s, io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let first = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (small_root, grains) = prepared(client.writer_uuid(), "file", b"abc", &mut objects);
    let low = client
        .prepare_captured_registration(&small_root, first.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    client
        .overlay_transaction(|t| t.write(stage, 3, b"def"))
        .unwrap();
    let second = capture(&mut client, stage);
    let (large_root, grains) = prepared(client.writer_uuid(), "file", b"abcdef", &mut objects);
    let middle = client
        .prepare_captured_registration(&large_root, second.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&middle, &Tick(10)).unwrap();
    finish(&mut client, &middle, &authority.send(&middle));
    let high = client
        .prepare_registration(&small_root, vec![], &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&high, &Tick(10)).unwrap();
    finish(&mut client, &high, &authority.send(&high));
    let results = client
        .complete_capture_queue(
            &BTreeMap::from([
                (
                    GrainId::of(&small_root),
                    coverage(&small_root, &first, "file"),
                ),
                (
                    GrainId::of(&large_root),
                    coverage(&large_root, &second, "file"),
                ),
            ]),
            &objects,
        )
        .unwrap();
    assert!(results[0].result.is_ok());
    assert!(
        matches!(results[1].result, Err(OverlayError::CaptureCoverageLost)),
        "larger exact prefix needs a durable mark or typed recapture outcome"
    );
    assert!(results[1].registered_capture().is_none());
    let journal =
        io.0.lock()
            .unwrap()
            .names
            .keys()
            .find(|p| p.ends_with("journal"))
            .unwrap()
            .clone();
    let mut marks = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&io.bytes(&journal), |_, record| {
        if let Record::FileSynced {
            generation,
            synced_size,
            ..
        } = record
        {
            marks.push((*generation, *synced_size));
        }
    })
    .unwrap();
    assert_eq!(marks, vec![(4, 3)]);
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
    let retry = capture(&mut client, stage);
    assert_eq!(retry.size(), 6);
    client
        .overlay_transaction(|t| t.complete_failed_capture(&retry))
        .unwrap();
}

#[test]
fn reopened_nonempty_capture_has_no_live_snapshot_charge() {
    let (scratch, io, mut client, _authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let captured = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "file", b"abc", &mut objects);
    client
        .prepare_captured_registration(&root, captured, grains, &Tick(10), |_, _| true)
        .unwrap();
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        3
    );
    assert!(client.reopened_captures().unwrap().is_empty());
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    open(&mut client, &io);
    let handoff = client.reopened_captures().unwrap();
    assert_eq!(handoff.len(), 1);
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
    client.fail_reopened_capture(&handoff[0]).unwrap();
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0
    );
    assert!(client.reopened_captures().unwrap().is_empty());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered two-receipt schedule checks the exact answer, sealed proofs and release together"
)]
fn exact_answer_retained_but_same_size_loser_fails() {
    let (_s, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let low_capture = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (low_root, low_grains) = prepared(client.writer_uuid(), "file", b"abc", &mut objects);
    let low = client
        .prepare_captured_registration(
            &low_root,
            low_capture.clone(),
            low_grains,
            &Tick(10),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    let answer = authority.send(&low);
    client
        .complete(
            &low,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let exact = client
        .snapshot()
        .pending
        .iter()
        .find(|p| p.body == low.bytes())
        .unwrap()
        .answer
        .clone();
    client
        .overlay_transaction(|t| t.write(stage, 0, b"xyz"))
        .unwrap();
    let high_capture = capture(&mut client, stage);
    let (high_root, high_grains) = prepared(client.writer_uuid(), "file", b"xyz", &mut objects);
    let high = client
        .prepare_captured_registration(
            &high_root,
            high_capture.clone(),
            high_grains,
            &Tick(12),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&high, &Tick(12)).unwrap();
    let answer = authority.send(&high);
    client
        .complete(
            &high,
            Ok(&answer),
            &Tick(13),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(
        client
            .snapshot()
            .pending
            .iter()
            .find(|p| p.body == low.bytes())
            .unwrap()
            .answer,
        exact,
        "exact capture answer is never overwritten by later receipt"
    );
    let results = client.complete_capture_queue(
        &BTreeMap::from([
            (
                GrainId::of(&low_root),
                coverage(&low_root, &low_capture, "file"),
            ),
            (
                GrainId::of(&high_root),
                coverage(&high_root, &high_capture, "file"),
            ),
        ]),
        &objects,
    );
    assert!(
        results.is_ok(),
        "exact receipt groups complete independently: {results:?}"
    );
    let results = results.unwrap();
    assert_eq!(
        results.len(),
        2,
        "separate exact answers drain in admission order"
    );
    assert!(
        matches!(results[0].result, Err(OverlayError::CaptureCoverageLost)),
        "same-size loser cannot rely on the winner's different prefix"
    );
    assert!(results[1].result.is_ok());
    client
        .prepare_release(&Tick(20), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
}

#[test]
fn coordination_round1_terminal_capture_refusal_drains_followers_and_release() {
    let (_s, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let low_capture = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "file", b"abc", &mut objects);
    let low = client
        .prepare_captured_registration(&root, low_capture, grains.clone(), &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    let refusal = reply(409, Some("intent-quota"), None, vec![]);
    assert!(
        client
            .complete(
                &low,
                Ok(&refusal),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None
            )
            .is_err()
    );
    let high_capture = capture(&mut client, stage);
    let high = client
        .prepare_captured_registration(&root, high_capture.clone(), grains, &Tick(12), |_, _| true)
        .unwrap();
    client.dispatch(&high, &Tick(12)).unwrap();
    let answer = authority.send(&high);
    client
        .complete(
            &high,
            Ok(&answer),
            &Tick(13),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let results = client.complete_capture_queue(
        &BTreeMap::from([(GrainId::of(&root), coverage(&root, &high_capture, "file"))]),
        &objects,
    );
    assert!(
        results.is_ok(),
        "terminal refused capture drains its follower: {results:?}"
    );
    let results = results.unwrap();
    assert_eq!(
        results.len(),
        2,
        "terminal refused capture drains its follower"
    );
    assert!(
        matches!(
            results[0].result,
            Err(OverlayError::Refused("IntentCaptureRegistrationRefused"))
        ),
        "capture refusal is a typed failure"
    );
    assert!(results[0].registered_capture().is_none() && results[1].result.is_ok());
    assert_eq!(
        client
            .overlay_transaction(|t| Ok(t.summary().captured_bytes))
            .unwrap(),
        0,
        "terminal capture refusal releases all captured bytes"
    );
    assert!(
        client
            .snapshot()
            .pending
            .iter()
            .all(|p| p.context.is_empty()),
        "refused and accepted contexts cleared"
    );
    client
        .prepare_release(&Tick(20), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
}

#[test]
fn coordination_round1_local_capture_refusal_retains_for_retry() {
    let (_s, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| t.create_file(at("empty"), false))
        .unwrap();
    let captured = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "empty", b"", &mut objects);
    let request = client
        .prepare_captured_registration(&root, captured.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    let result = client.complete(
        &request,
        Err(IntentTransportError::InvalidRequest),
        &Tick(11),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(result, Ok(crate::IntentCompletion::Unknown)),
        "no network evidence retains capture: {result:?}"
    );
    assert!(
        client
            .complete_capture_queue(&BTreeMap::new(), &objects)
            .unwrap()
            .is_empty(),
        "unanswered capture stays pending"
    );
    let eligible = client.snapshot().pending.last().unwrap().eligible;
    client.dispatch(&request, &Tick(eligible)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(eligible + 1),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let results = client
        .complete_capture_queue(
            &BTreeMap::from([(GrainId::of(&root), coverage(&root, &captured, "empty"))]),
            &objects,
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].result.is_ok());
    client
        .prepare_release(&Tick(eligible + 2), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "both answered and unanswered crash schedules keep context failure separate from network reconciliation"
)]
fn coordination_round1_reopened_capture_handoff_can_fail_durably() {
    // Both unanswered and already answered retained contexts must be surfaced.
    for answered in [false, true] {
        let (scratch, io, mut client, mut authority) = serving();
        let stage = client
            .overlay_transaction(|t| t.create_file(at("empty"), false))
            .unwrap();
        let captured = capture(&mut client, stage);
        let mut objects = Objects::default();
        let (root, grains) = prepared(client.writer_uuid(), "empty", b"", &mut objects);
        let request = client
            .prepare_captured_registration(&root, captured, grains, &Tick(10), |_, _| true)
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        if answered {
            let answer = authority.send(&request);
            client
                .complete(
                    &request,
                    Ok(&answer),
                    &Tick(11),
                    &mut SeededRng::new(1),
                    0,
                    None,
                )
                .unwrap();
        }
        assert!(
            client.reopened_captures().unwrap().is_empty(),
            "live capture is not a reopen handoff"
        );
        let context = client.snapshot().pending.last().unwrap().context.clone();
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 30);
        let handoff = client.reopened_captures().unwrap();
        assert_eq!(
            handoff.len(),
            1,
            "restart surfaces retained captured registration"
        );
        assert_eq!(handoff[0].context(), context);
        assert_eq!(handoff[0].request().bytes(), request.bytes());
        let result = client.fail_reopened_capture(&handoff[0]).unwrap();
        assert!(
            matches!(
                result.result,
                Err(OverlayError::Refused("IntentCaptureRecoveryFailed"))
            ),
            "reopened capture fails explicitly"
        );
        assert!(
            client.fail_reopened_capture(&handoff[0]).is_err(),
            "stale handoff cannot complete twice"
        );
        assert!(
            client.reopened_captures().unwrap().is_empty(),
            "reopened context cleared durably"
        );
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 40);
        assert!(
            client.reopened_captures().unwrap().is_empty(),
            "failed capture context stays cleared after restart"
        );
        if !answered {
            let retained = client.retained_requests().pop().unwrap();
            assert_eq!(
                retained.bytes(),
                request.bytes(),
                "local capture failure preserves unresolved network request"
            );
            open(&mut client, &io);
            client.dispatch(&retained, &Tick(18)).unwrap();
            let answer = authority.send(&retained);
            client
                .complete(
                    &retained,
                    Ok(&answer),
                    &Tick(19),
                    &mut SeededRng::new(1),
                    0,
                    None,
                )
                .unwrap();
        }
        let transfer = client.prepare_succession(&Tick(20)).unwrap();
        client.dispatch(&transfer, &Tick(20)).unwrap();
        let answer = authority.send(&transfer);
        client
            .complete(
                &transfer,
                Ok(&answer),
                &Tick(21),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        open(&mut client, &io);
        register(&mut client, &mut authority, 3);
        client
            .prepare_release(&Tick(22), crate::DEFAULT_RESOLUTION_BOUND, None)
            .unwrap();
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "same-stage and distinct-stage schedules jointly check per-caller proofs, latest mirrors and journal ordering"
)]
fn coordination_round1_mixed_exact_and_overtaken_answers_keep_monotonic_marks() {
    for distinct in [false, true] {
        let (_s, io, mut client, mut authority) = serving();
        let first_stage = client
            .overlay_transaction(|t| t.create_file(at("a"), false))
            .unwrap();
        let second_stage = client
            .overlay_transaction(|t| t.create_file(at("b"), false))
            .unwrap();
        let mut objects = Objects::default();
        let tree = manifest::build_dir(&["a", "b"].map(|path| DirEntry {
            name: Name::new(path.as_bytes().to_vec()).unwrap(),
            kind: EntryKind::File {
                exec: false,
                size: 0,
                grains: FileGrains::Inline(vec![]),
            },
        }))
        .unwrap();
        objects.0.extend(tree.nodes);
        let mut doc = granary_core::root::decode_root(&root(client.writer_uuid(), 2)).unwrap();
        doc.manifest_root = tree.root;
        let root = granary_core::root::encode_root(&doc).unwrap();
        let low_capture = capture(&mut client, first_stage);
        let low = client
            .prepare_captured_registration(
                &root,
                low_capture.clone(),
                FileGrains::Inline(vec![]),
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&low, &Tick(10)).unwrap();
        let middle_capture = capture(
            &mut client,
            if distinct { second_stage } else { first_stage },
        );
        let middle = client
            .prepare_captured_registration(
                &root,
                middle_capture.clone(),
                FileGrains::Inline(vec![]),
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&middle, &Tick(10)).unwrap();
        let answer = authority.send(&middle);
        client
            .complete(
                &middle,
                Ok(&answer),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        let high = client
            .prepare_registration(&root, vec![], &Tick(12), |_, _| true)
            .unwrap();
        client.dispatch(&high, &Tick(12)).unwrap();
        let answer = authority.send(&high);
        client
            .complete(
                &high,
                Ok(&answer),
                &Tick(13),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        let mut input = coverage(&root, &middle_capture, if distinct { "b" } else { "a" });
        input
            .projections
            .extend(coverage(&root, &low_capture, "a").projections);
        let results =
            client.complete_capture_queue(&BTreeMap::from([(GrainId::of(&root), input)]), &objects);
        assert!(
            results.is_ok(),
            "mixed exact and overtaken answers complete without decreasing journal: {results:?}"
        );
        let results = results.unwrap();
        assert_eq!(
            results.iter().map(|r| r.generation).collect::<Vec<_>>(),
            vec![2, 3],
            "mixed answers retain caller order"
        );
        assert!(results.iter().all(|r| r.result.is_ok()));
        assert_eq!(
            results
                .iter()
                .map(|r| r.registered_capture().unwrap().generation)
                .collect::<Vec<_>>(),
            vec![4, 3],
            "covering generations preserve the exact middle answer"
        );
        let journal =
            io.0.lock()
                .unwrap()
                .names
                .keys()
                .find(|p| p.ends_with("journal"))
                .unwrap()
                .clone();
        let mut marks = Vec::new();
        granary_core::overlay_journal::scan_journal_with(&io.bytes(&journal), |_, record| {
            if let Record::FileSynced { generation, .. } = record {
                marks.push(*generation);
            }
        })
        .unwrap();
        assert_eq!(
            marks,
            if distinct { vec![3, 4] } else { vec![4] },
            "latest mirrors are sorted by receipt generation"
        );
    }
}

#[test]
fn coordination_round1_only_refused_capture_has_no_intent_mark() {
    let (_s, _io, mut client, _authority) = serving();
    let stage = client
        .overlay_transaction(|t| t.create_file(at("empty"), false))
        .unwrap();
    let captured = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "empty", b"", &mut objects);
    let request = client
        .prepare_captured_registration(&root, captured, grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    assert!(
        client
            .complete(
                &request,
                Ok(&reply(400, Some("bad-request"), None, vec![])),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None
            )
            .is_err()
    );
    let results = client.complete_capture_queue(&BTreeMap::new(), &objects);
    assert!(
        results.is_ok(),
        "refused-only batch does not fabricate an intent receipt: {results:?}"
    );
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].result.is_err());
    client
        .prepare_release(&Tick(20), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
}

#[test]
fn overlay_base_content_equals_sealed_capture() {
    let (_scratch, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("file"), false)?;
            t.write(stage, 0, b"abc")?;
            Ok(stage)
        })
        .unwrap();
    let captured = capture(&mut client, stage);
    let mut objects = Objects::default();
    let (root, grains) = prepared(client.writer_uuid(), "file", b"abc", &mut objects);
    let request = client
        .prepare_captured_registration(&root, captured.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    let reply = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&reply),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let input = CaptureCoverageInput {
        prepared_root: GrainId::of(&root),
        boundary: captured.through_seq(),
        projections: vec![StageProjection {
            stage_id: stage,
            incarnation: captured.incarnation(),
            path: vec![Name::new(b"file".to_vec()).unwrap()],
            content_boundary: captured.through_seq(),
        }],
        mutations: vec![],
        identities: vec![],
    };
    let results = client
        .complete_capture_queue(&BTreeMap::from([(input.prepared_root, input)]), &objects)
        .unwrap();
    let sealed = results[0].registered_capture().unwrap();
    let doc = granary_core::root::decode_root(&root).unwrap();
    let stats =
        manifest::validate_dir_tree(&doc.manifest_root, &|id| objects.0.get(id).cloned()).unwrap();
    let snapshot = granary_vfs::Snapshot::new(
        objects.0.clone(),
        doc.manifest_root,
        doc.timestamp,
        stats,
        granary_vfs::AttrPolicy { uid: 0, gid: 0 },
        granary_vfs::ServeLimits::UNBOUNDED,
    )
    .unwrap();
    let base = crate::writable_start::overlay_base(&snapshot).unwrap();
    assert!(
        matches!(base[0].kind, OverlayKind::File { content: Some(id) } if id == sealed.content),
        "overlay base content must equal the sealed capture content"
    );
}

/// What the covering root holds around the captured file `d/f`.
#[derive(Clone, Copy, PartialEq)]
enum Covering {
    Sound,
    /// `f` appears in two sibling leaves of the directory the lookup crosses.
    DuplicateOnPath,
    /// A directory the lookup never crosses names an object that is not there.
    CorruptOffPath,
}

#[expect(
    clippy::too_many_lines,
    reason = "one covering root is assembled, registered and completed in a single schedule"
)]
fn cover(shape: Covering) -> Result<(), OverlayError> {
    use granary_core::manifest::node::{InteriorChild, encode_dir_interior, encode_dir_leaf};
    let (_scratch, _io, mut client, mut authority) = serving();
    let stage = client
        .overlay_transaction(|t| {
            t.namespace_record(Record::Create {
                at: at("d"),
                kind: granary_core::overlay_journal::CreateKind::Dir,
            })?;
            let id = t.create_file(
                granary_core::overlay_journal::Location {
                    parent: granary_core::overlay_journal::Parent::new(vec![
                        Name::new(b"d".to_vec()).unwrap(),
                    ])
                    .unwrap(),
                    name: Name::new(b"f".to_vec()).unwrap(),
                },
                false,
            )?;
            t.write(id, 0, b"payload")?;
            Ok(id)
        })
        .unwrap();
    let c = capture(&mut client, stage);
    let mut objects = Objects::default();
    let grains = file(b"payload", &mut objects);
    let entry = |name: &str, grains: &FileGrains| DirEntry {
        name: Name::new(name.as_bytes().to_vec()).unwrap(),
        kind: EntryKind::File {
            exec: false,
            size: 7,
            grains: grains.clone(),
        },
    };
    let put = |objects: &mut Objects, bytes: Vec<u8>| {
        let id = GrainId::of(&bytes);
        objects.0.insert(id, bytes);
        id
    };
    let d = if shape == Covering::DuplicateOnPath {
        let low = put(
            &mut objects,
            encode_dir_leaf(&[entry("a", &grains), entry("f", &grains)]).unwrap(),
        );
        let high = put(
            &mut objects,
            encode_dir_leaf(&[entry("f", &grains), entry("z", &grains)]).unwrap(),
        );
        put(
            &mut objects,
            encode_dir_interior(&[
                InteriorChild {
                    first_key: Name::new(b"a".to_vec()).unwrap(),
                    child: low,
                    subtree_entry_count: 2,
                },
                InteriorChild {
                    first_key: Name::new(b"f".to_vec()).unwrap(),
                    child: high,
                    subtree_entry_count: 2,
                },
            ])
            .unwrap(),
        )
    } else {
        let built = manifest::build_dir(&[
            entry("a", &grains),
            entry("f", &grains),
            entry("z", &grains),
        ])
        .unwrap();
        objects.0.extend(built.nodes);
        built.root
    };
    let other = if shape == Covering::CorruptOffPath {
        GrainId::of(b"an object nobody stored")
    } else {
        let built = manifest::build_dir(&[entry("g", &grains)]).unwrap();
        objects.0.extend(built.nodes);
        built.root
    };
    let top = manifest::build_dir(&[
        DirEntry {
            name: Name::new(b"d".to_vec()).unwrap(),
            kind: EntryKind::Dir { child: d },
        },
        DirEntry {
            name: Name::new(b"other".to_vec()).unwrap(),
            kind: EntryKind::Dir { child: other },
        },
    ])
    .unwrap();
    objects.0.extend(top.nodes);
    let mut doc = granary_core::root::decode_root(&root(client.writer_uuid(), 2)).unwrap();
    doc.manifest_root = top.root;
    let root_bytes = granary_core::root::encode_root(&doc).unwrap();
    let request = client
        .prepare_captured_registration(&root_bytes, c.clone(), grains, &Tick(10), |_, _| true)
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let input = CaptureCoverageInput {
        prepared_root: GrainId::of(&root_bytes),
        boundary: c.through_seq(),
        projections: vec![StageProjection {
            stage_id: stage,
            incarnation: c.incarnation(),
            path: vec![
                Name::new(b"d".to_vec()).unwrap(),
                Name::new(b"f".to_vec()).unwrap(),
            ],
            content_boundary: c.through_seq(),
        }],
        mutations: vec![],
        identities: vec![],
    };
    let results = client
        .complete_capture_queue(&BTreeMap::from([(input.prepared_root, input)]), &objects)
        .unwrap();
    assert_eq!(results.len(), 1);
    results.into_iter().next().unwrap().result
}

#[test]
fn a_duplicate_name_across_sibling_leaves_on_the_covering_path_loses_coverage() {
    cover(Covering::Sound).expect("the control layout covers its capture");
    assert!(matches!(
        cover(Covering::DuplicateOnPath),
        Err(OverlayError::CaptureCoverageLost)
    ));
}

/// Completion validates the directories it crosses and nothing else. This
/// pins that scope: a corrupt object off the path no longer fails coverage.
/// Only the sync engine builds the covering root, and it validated every node
/// it built, so the full-build equivalence tests are what guard that side.
#[test]
fn corruption_off_the_covering_path_is_not_caught_at_completion() {
    cover(Covering::CorruptOffPath).expect("off-path corruption must not fail coverage");
}
