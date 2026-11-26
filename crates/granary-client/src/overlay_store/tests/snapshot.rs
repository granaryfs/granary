// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn reopened_shrunken_checkpoint_dirty_ranges_fit_rechunk_limit() {
    let bytes = vec![1; 200];
    let grains =
        granary_core::manifest::FileGrains::Inline(vec![granary_core::manifest::GrainRef {
            id: GrainId::of(&bytes),
            unpacked_len: 200,
        }]);
    let content = GrainId::of(&granary_core::manifest::node::file_payload(200, &grains).unwrap());
    let entry = OverlayEntry {
        path: vec![name("f")],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: 200,
        exec: false,
    };
    let mut f = Fixture::with_base(vec![entry], Source(BTreeMap::from([(content, bytes)])));
    let id = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    f.overlay.truncate(&mut f.store, &f.owner, id, 100).unwrap();
    f.sync(id, 1);
    f.io.crash();
    f.reopen().unwrap();
    f.write(id, b"changed");
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    assert!(
        b.files()[0]
            .dirty_intervals()
            .iter()
            .all(|(_, end)| *end <= 100),
        "reopened shrink retained intervals beyond checkpoint EOF"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
}

fn base_fixture(len: usize) -> (Fixture, u64, Vec<u8>) {
    let bytes = vec![1; len];
    let grains =
        granary_core::manifest::FileGrains::Inline(vec![granary_core::manifest::GrainRef {
            id: GrainId::of(&bytes),
            unpacked_len: u32::try_from(len).unwrap(),
        }]);
    let content =
        GrainId::of(&granary_core::manifest::node::file_payload(len as u64, &grains).unwrap());
    let entry = OverlayEntry {
        path: vec![name("f")],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: len as u64,
        exec: false,
    };
    let mut f = Fixture::with_base(
        vec![entry],
        Source(BTreeMap::from([(content, bytes.clone())])),
    );
    let id = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    (f, id, bytes)
}

fn assert_truncated_hole_is_zero(synced_first: bool) {
    let (mut f, id, _) = base_fixture(200);
    if synced_first {
        f.write(id, b"zz");
        f.sync(id, 1);
    }
    f.overlay.truncate(&mut f.store, &f.owner, id, 10).unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, id, 300, b"tail")
        .unwrap();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let content = materialize(&mut f, &b, &b.files()[0]).concat();
    assert_eq!(content.len(), 304);
    let head: &[u8] = if synced_first { b"zz" } else { &[1, 1] };
    assert_eq!(&content[..2], head);
    assert!(content[2..10].iter().all(|byte| *byte == 1));
    assert!(
        content[10..300].iter().all(|byte| *byte == 0),
        "hole after truncate and extension exposed base bytes"
    );
    assert_eq!(&content[300..], b"tail");
}

#[test]
fn truncate_then_sparse_extension_reads_zeros_in_the_hole() {
    assert_truncated_hole_is_zero(false);
}

#[test]
fn truncate_then_sparse_extension_after_a_checkpoint_reads_zeros_in_the_hole() {
    assert_truncated_hole_is_zero(true);
}

pub(super) fn materialize(
    f: &mut Fixture,
    boundary: &SyncBoundary,
    file: &CapturedFile,
) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < file.size() {
        let result = f
            .overlay
            .captured_parts(&mut f.store, &f.owner, boundary, file, offset);
        assert!(
            result.is_ok(),
            "immutable range rejected after admitted writer: {result:?}"
        );
        let parts = result.unwrap();
        // The transaction has ended before the immutable provider is invoked.
        let mut chunk = Vec::new();
        for part in parts {
            match part {
                CapturedPart::Dirty {
                    bytes,
                    start,
                    length,
                } => chunk.extend_from_slice(&bytes[start..start + length]),
                CapturedPart::Zero(length) => chunk.resize(chunk.len() + length, 0),
                CapturedPart::Immutable {
                    content,
                    offset,
                    length,
                } => chunk.extend(f.source.read_verified(content, offset, length).unwrap()),
            }
        }
        offset += chunk.len() as u64;
        chunks.push(chunk);
    }
    chunks
}

#[test]
fn seal_reads_no_staging_content_and_writers_progress_between_ranges() {
    let mut f = Fixture::new();
    let id = f.create();
    let original = vec![b'a'; BUFFER * 3 + 7];
    f.write(id, &original);
    let before = f.io.0.lock().unwrap().trace.len();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let path = f.overlay.stage_path(id);
    let reads = f.io.0.lock().unwrap().trace[before..]
        .iter()
        .filter(|(op, p)| op == "read" && p == &path)
        .count();
    assert_eq!(
        (reads, b.files()[0].size(), b.through_seq()),
        (0, original.len() as u64, 2),
        "seal copied mutable staging"
    );
    // Two handles use the same stage; the second write must finish while the
    // captured operation has not materialized a single buffer.
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, id, 5, b"later")
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, id, original.len() as u64, b"append")
        .unwrap();
    let file = &b.files()[0];
    let chunks = materialize(&mut f, &b, file);
    assert_eq!(
        chunks.concat(),
        original,
        "post-boundary write leaked into captured bytes"
    );
    f.overlay
        .validate_capture(file.capture_token().unwrap())
        .unwrap();
    assert!(matches!(
        f.overlay.truncate(&mut f.store, &f.owner, id, 0),
        Err(OverlayError::PendingShrink)
    ));
    let newer = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let mut expected = original;
    expected[5..10].copy_from_slice(b"later");
    expected.extend_from_slice(b"append");
    assert_eq!(
        materialize(&mut f, &newer, &newer.files()[0]).concat(),
        expected,
        "later write lost from live overlay"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
    assert!(matches!(
        f.overlay.truncate(&mut f.store, &f.owner, id, 0),
        Err(OverlayError::PendingShrink)
    ));
    f.overlay.release_sync_boundary(&newer).unwrap();
    f.overlay.truncate(&mut f.store, &f.owner, id, 0).unwrap();
    assert_eq!(f.overlay.summary().captured_bytes, 0);
    assert_eq!(
        f.overlay.release_sync_boundary(&b).unwrap_err().to_string(),
        "overlay refused: sync boundary context"
    );
}

#[test]
fn shared_versions_charge_once_and_cap_refusal_precedes_writer_mutation() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, &vec![1; BUFFER + 3]);
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let first = f.overlay.summary().captured_bytes;
    let c = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    assert_eq!(
        f.overlay.summary().captured_bytes - first,
        first - (BUFFER + 3) as u64,
        "identical versions charged twice"
    );
    let chunks = materialize(&mut f, &b, &b.files()[0]);
    assert_eq!(chunks.concat(), vec![1; BUFFER + 3]);
    let before = f.io.bytes(&f.overlay.stage_path(id));
    let journal = f.io.bytes(&f.overlay.journal_path());
    f.overlay.config.cap = f.overlay.summary().charged_bytes
        + f.overlay.summary().reserved_bytes
        + f.overlay.summary().captured_bytes;
    let err = f
        .overlay
        .write(&mut f.store, &f.owner, id, 0, &[2])
        .unwrap_err();
    assert_eq!(
        (
            err.to_string(),
            f.overlay.readiness(),
            f.io.bytes(&f.overlay.stage_path(id)),
            f.io.bytes(&f.overlay.journal_path())
        ),
        (
            "overlay cap exhausted (ENOSPC)".into(),
            OverlayReadiness::Ready,
            before,
            journal
        ),
        "cap refusal mutated or poisoned the writer"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
    assert_eq!(
        materialize(&mut f, &c, &c.files()[0]).concat(),
        vec![1; BUFFER + 3]
    );
    f.overlay.release_sync_boundary(&c).unwrap();
    assert_eq!(f.overlay.summary().captured_bytes, 0);
    f.overlay.config.cap = 1_048_576;
    f.overlay
        .write(&mut f.store, &f.owner, id, 0, &[2])
        .unwrap();
}

#[test]
fn owned_graph_reservation_is_bounded_and_released_once() {
    let mut f = Fixture::new();
    let stage = f.create();
    f.write(stage, b"bytes");
    let boundary = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
        .unwrap();
    let before = f.overlay.summary();
    assert!(
        before.captured_bytes > 592 + 5,
        "owned boundary graph was not charged"
    );
    f.overlay.config.cap = before.charged_bytes + before.reserved_bytes + before.captured_bytes;
    assert!(matches!(
        f.overlay.reserve_sync_graph(&boundary, 1),
        Err(OverlayError::Refused("OverlayCapacityExhausted"))
    ));
    assert_eq!(f.overlay.summary().captured_bytes, before.captured_bytes);
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Ready);
    f.overlay.config.cap += 1;
    f.overlay.reserve_sync_graph(&boundary, 1).unwrap();
    assert_eq!(
        f.overlay.summary().captured_bytes,
        before.captured_bytes + 1
    );
    f.overlay.release_sync_graph(&boundary, 1).unwrap();
    assert_eq!(f.overlay.summary().captured_bytes, before.captured_bytes);
    f.overlay.release_sync_boundary(&boundary).unwrap();
    assert_eq!(f.overlay.summary().captured_bytes, 0);
    assert!(f.overlay.reserve_sync_graph(&boundary, 1).is_err());
}

#[test]
fn preservation_read_failure_refuses_before_mutation_without_poison() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"original");
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let stage = f.io.bytes(&f.overlay.stage_path(id));
    let journal = f.io.bytes(&f.overlay.journal_path());
    // Fail the staging-header read, after the ownership check's writer read.
    // Directly exercise the preservation transaction to make the intended I/O
    // seam unambiguous rather than relying on a read occurrence count.
    f.io.0.lock().unwrap().fail = Some("read");
    let error = f.overlay.preserve_versions(id, 0, 1).unwrap_err();
    assert_eq!(
        (
            error.to_string(),
            f.overlay.readiness(),
            f.io.bytes(&f.overlay.stage_path(id)),
            f.io.bytes(&f.overlay.journal_path())
        ),
        (
            "overlay I/O: model injected I/O".into(),
            OverlayReadiness::Ready,
            stage,
            journal
        )
    );
    f.overlay
        .write(&mut f.store, &f.owner, id, 0, b"later")
        .unwrap();
    assert_eq!(materialize(&mut f, &b, &b.files()[0]).concat(), b"original");
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn corrupt_unread_version_poisoned_before_overwrite_and_never_copied() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"original");
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let path = f.overlay.stage_path(id);
    f.io.mutate(&path, |bytes| bytes[162] ^= 1);
    let stage = f.io.bytes(&path);
    let journal = f.io.bytes(&f.overlay.journal_path());
    let error = f
        .overlay
        .write(&mut f.store, &f.owner, id, 7, b"x")
        .unwrap_err();
    assert_eq!(
        (
            error.to_string(),
            f.overlay.readiness(),
            f.io.bytes(&path),
            f.io.bytes(&f.overlay.journal_path())
        ),
        (
            "overlay refused: live extent mismatch".into(),
            OverlayReadiness::Poisoned,
            stage,
            journal
        )
    );
    f.overlay.release_sync_boundary(&b).unwrap();
    assert_eq!(f.overlay.summary().captured_bytes, 0);
}

#[test]
fn tree_has_one_cursor_and_directory_flush_does_not_forge_stage_marks() {
    let mut f = Fixture::new();
    let first = f.create();
    f.write(first, b"first");
    let second = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("g"), false)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, second, 0, b"second")
        .unwrap();
    let tree = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
        .unwrap();
    assert_eq!(
        tree.files()
            .iter()
            .map(|file| file.capture_token().unwrap().through_seq())
            .collect::<Vec<_>>(),
        vec![4, 4]
    );
    f.overlay
        .flush_sync_boundary(&mut f.store, &f.owner, &tree)
        .unwrap();
    for file in tree.files() {
        assert!(
            f.overlay
                .flushed
                .contains(&file.capture_token().unwrap().id)
        );
    }
    f.overlay.release_sync_boundary(&tree).unwrap();
    let dir = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    let start = f.io.0.lock().unwrap().trace.len();
    f.overlay
        .flush_sync_boundary(&mut f.store, &f.owner, &dir)
        .unwrap();
    let trace = f.io.0.lock().unwrap().trace[start..].to_vec();
    assert_eq!(
        (
            dir.files().len(),
            trace.iter().filter(|(op, _)| op == "sync").count(),
            trace.iter().filter(|(op, _)| op == "dir_sync").count()
        ),
        (0, 1, 1)
    );
    let mut kinds = Vec::new();
    codec::scan_journal_with(&f.io.bytes(&f.overlay.journal_path()), |_, record| {
        if matches!(record, Record::FileSynced { .. }) {
            kinds.push(record.clone());
        }
    })
    .unwrap();
    assert_eq!(kinds.len(), 0, "directory flush forged a stage mark");
    f.overlay.release_sync_boundary(&dir).unwrap();
    assert_eq!(f.overlay.summary().captured_bytes, 0);
}

#[test]
fn clean_and_orphan_captures_complete_without_stage_marks() {
    let content = grain(9);
    let bytes = b"authenticated base".to_vec();
    let entry = OverlayEntry {
        path: vec![name("base")],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: bytes.len() as u64,
        exec: false,
    };
    let mut f = Fixture::with_base(
        vec![entry],
        Source(BTreeMap::from([(content, bytes.clone())])),
    );
    let inode = f.overlay.entries(&mut f.store, &f.owner).unwrap()[0].inode;
    let clean = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::File(inode))
        .unwrap();
    assert_eq!(
        (
            clean.files()[0].capture_token().is_none(),
            materialize(&mut f, &clean, &clean.files()[0]).concat()
        ),
        (true, bytes)
    );
    f.overlay
        .flush_sync_boundary(&mut f.store, &f.owner, &clean)
        .unwrap();
    f.overlay.release_sync_boundary(&clean).unwrap();
    let id = f.create();
    f.write(id, b"unlinked");
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File { stage_id: Some(id) },
            },
        )
        .unwrap();
    let orphan = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    assert_eq!(
        (
            orphan.files()[0].entry().is_none(),
            materialize(&mut f, &orphan, &orphan.files()[0]).concat()
        ),
        (true, b"unlinked".to_vec())
    );
    f.overlay
        .flush_sync_boundary(&mut f.store, &f.owner, &orphan)
        .unwrap();
    f.overlay.release_sync_boundary(&orphan).unwrap();
    assert_eq!(
        (
            f.overlay.namespace.stages.get(&id).unwrap().mark,
            f.overlay.summary().captured_bytes
        ),
        (None, 0)
    );
}

#[test]
fn snapshot_flush_failure_poisoned_with_disarmed_control() {
    let mut count = 0;
    for point in [
        "overlay.stage.sync",
        "overlay.stage.dir_sync",
        "overlay.journal.pre_sync",
    ] {
        for armed in [false, true] {
            let mut f = Fixture::new();
            let id = f.create();
            f.write(id, b"a");
            let b = f
                .overlay
                .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
                .unwrap();
            let control = f.overlay.fault_control();
            if armed {
                control.arm(point, "before", 1, FaultAction::Fail);
            }
            let result = f.overlay.flush_sync_boundary(&mut f.store, &f.owner, &b);
            assert_eq!(
                (result.is_ok(), f.overlay.readiness()),
                if armed {
                    (false, OverlayReadiness::Poisoned)
                } else {
                    (true, OverlayReadiness::Ready)
                }
            );
            assert_eq!(
                control.fired(),
                if armed {
                    vec![FaultEvent {
                        name: point,
                        phase: "before",
                        occurrence: 1,
                        record_index: b.through_seq(),
                    }]
                } else {
                    vec![]
                },
                "prefix barrier fault did not fire with exact identity"
            );
            f.overlay.release_sync_boundary(&b).unwrap();
            count += 1;
        }
    }
    assert_eq!(count, 6);
}

#[test]
fn captured_read_buffers_are_bounded_and_authenticated_before_retention() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, &vec![7; BUFFER * 4 + 3]);
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    f.io.0.lock().unwrap().read_lengths.clear();
    assert_eq!(
        materialize(&mut f, &b, &b.files()[0]).concat(),
        vec![7; BUFFER * 4 + 3]
    );
    let reads = f.io.0.lock().unwrap().read_lengths.clone();
    let staging: Vec<_> = reads
        .iter()
        .filter(|(path, _)| path == &f.overlay.stage_path(id))
        .collect();
    assert!(
        !staging.is_empty(),
        "capture did not read any staging range"
    );
    assert!(
        staging.iter().all(|(_, length)| *length <= BUFFER),
        "capture exceeded 65,536-byte read buffer"
    );
    f.overlay.release_sync_boundary(&b).unwrap();
    let c = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    f.io.mutate(&f.overlay.stage_path(id), |bytes| bytes[170] ^= 1);
    let result = f
        .overlay
        .captured_parts(&mut f.store, &f.owner, &c, &c.files()[0], 0);
    assert_eq!(
        (result.unwrap_err().to_string(), f.overlay.readiness()),
        (
            "overlay refused: capture extent mismatch".into(),
            OverlayReadiness::Poisoned
        ),
        "corrupt capture bytes were retained"
    );
    f.overlay.release_sync_boundary(&c).unwrap();
}

#[test]
fn seal_reservation_refusal_is_atomic_and_has_a_valid_control() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, &vec![9; BUFFER]);
    let stage = f.io.bytes(&f.overlay.stage_path(id));
    let journal = f.io.bytes(&f.overlay.journal_path());
    let next = f.overlay.next_capture;
    f.overlay.config.cap = f.overlay.summary().charged_bytes + f.overlay.summary().reserved_bytes;
    let error = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
        .unwrap_err();
    assert_eq!(
        (
            error.to_string(),
            f.overlay.readiness(),
            f.overlay.next_capture,
            f.overlay.summary().captured_bytes,
            f.overlay.namespace.stages.get(&id).unwrap().captures.len()
        ),
        (
            "overlay refused: OverlayCapacityExhausted".into(),
            OverlayReadiness::Ready,
            next,
            0,
            0
        ),
        "failed seal left a reservation or poisoned service"
    );
    assert_eq!(
        (
            f.io.bytes(&f.overlay.stage_path(id)),
            f.io.bytes(&f.overlay.journal_path())
        ),
        (stage, journal)
    );
    f.overlay.config.cap = 1_048_576;
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
        .unwrap();
    assert_eq!(b.files().len(), 1);
    f.overlay.release_sync_boundary(&b).unwrap();
}

#[test]
fn stale_and_cross_scope_boundaries_refuse_before_copying_or_flushing() {
    let log = LogBytes::default();
    let dispatch = observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        log.clone(),
    );
    tracing::subscriber::with_default(dispatch, || {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"valid");
        let b = f
            .overlay
            .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
            .unwrap();
        let mut cases = Vec::new();
        let mut bad = b.clone();
        bad.scope.push('x');
        cases.push(bad);
        let mut bad = b.clone();
        bad.volume = VolumeName::new("other".into()).unwrap();
        cases.push(bad);
        let mut bad = b.clone();
        bad.instance = [9; 16];
        cases.push(bad);
        let mut bad = b.clone();
        bad.incarnation += 1;
        cases.push(bad);
        let mut bad = b.clone();
        bad.header.base_root = grain(9);
        cases.push(bad);
        let mut bad = b.clone();
        bad.through_seq += 1;
        cases.push(bad);
        let mut foreign_writer = b.clone();
        foreign_writer.header.writer = [99; 16];
        assert_eq!(
            f.overlay
                .release_sync_boundary(&foreign_writer)
                .unwrap_err()
                .to_string(),
            "overlay refused: sync boundary context"
        );
        cases.push(foreign_writer);
        for bad in &cases {
            let error = f
                .overlay
                .flush_sync_boundary(&mut f.store, &f.owner, bad)
                .unwrap_err();
            assert_eq!(error.to_string(), "overlay refused: sync boundary context");
        }
        assert_eq!(cases.len(), 7);
        assert_eq!(materialize(&mut f, &b, &b.files()[0]).concat(), b"valid");
        f.overlay
            .flush_sync_boundary(&mut f.store, &f.owner, &b)
            .unwrap();
        f.overlay.release_sync_boundary(&b).unwrap();
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\"event\":\"op.failed\"")
                && line.contains("\"kind\":\"overlay_write\"")
                && line.contains("\"class\":\"refused\""))
            .count(),
        8,
        "stale refusal did not emit stable event/kind/class"
    );
}

#[test]
fn base_change_refuses_success_but_exact_failure_release_unblocks_shrink() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old base");
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    f.overlay.journal.lock().unwrap().header.base_root = grain(99);
    let error = f
        .overlay
        .flush_sync_boundary(&mut f.store, &f.owner, &b)
        .unwrap_err();
    assert_eq!(error.to_string(), "overlay refused: sync boundary context");
    f.overlay.release_sync_boundary(&b).unwrap();
    assert_eq!(
        f.overlay.summary().captured_bytes,
        0,
        "stale-base failure kept an exact floor or charge"
    );
    f.overlay.truncate(&mut f.store, &f.owner, id, 0).unwrap();
}

#[test]
fn captured_range_rejects_unaligned_eof_and_foreign_file_controls() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"range");
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let c = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let cases = [
        (&b.files()[0], 1),
        (&b.files()[0], 65536),
        (&c.files()[0], 0),
    ];
    for (file, offset) in cases {
        assert_eq!(
            f.overlay
                .captured_parts(&mut f.store, &f.owner, &b, file, offset)
                .unwrap_err()
                .to_string(),
            "overlay refused: capture range context"
        );
    }
    assert_eq!(cases.len(), 3);
    assert_eq!(materialize(&mut f, &b, &b.files()[0]).concat(), b"range");
    f.overlay.release_sync_boundary(&b).unwrap();
    f.overlay.release_sync_boundary(&c).unwrap();
}

#[test]
fn outstanding_prefix_completion_has_journal_headroom() {
    let mut f = Fixture::new();
    f.overlay.config.cap = 268_435_456;
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    // Exercise the capacity policy's prospective journal-length input, without
    // constructing a millions-of-record fixture to test integer headroom.
    f.overlay.capacity(0, 67_107_779, 0).unwrap();
    let error = f.overlay.capacity(0, 67_107_979, 0).unwrap_err();
    assert_eq!(error.to_string(), "overlay cap exhausted (ENOSPC)");
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Ready);
    f.overlay.release_sync_boundary(&b).unwrap();
    f.overlay.capacity(0, 67_107_979, 0).unwrap();
}

#[test]
fn file_and_directory_targets_require_the_matching_namespace_identity() {
    let mut f = Fixture::new();
    let stage = f.create();
    f.write(stage, b"file");
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
    let file = f
        .overlay
        .namespace
        .entries
        .get(&vec![name("f")])
        .unwrap()
        .inode;
    let directory = f
        .overlay
        .namespace
        .entries
        .get(&vec![name("d")])
        .unwrap()
        .inode;
    let cases = [
        (
            SyncTarget::File(directory),
            "overlay refused: sync file identity",
        ),
        (SyncTarget::File(999), "overlay refused: sync file identity"),
        (
            SyncTarget::Directory(Some(file)),
            "overlay refused: sync directory identity",
        ),
        (
            SyncTarget::Directory(Some(999)),
            "overlay refused: sync directory identity",
        ),
    ];
    for (target, reason) in cases {
        assert_eq!(
            f.overlay
                .seal_sync(&mut f.store, &f.owner, target)
                .unwrap_err()
                .to_string(),
            reason
        );
    }
    assert_eq!(cases.len(), 4);
    for (target, files) in [
        (SyncTarget::File(file), 1),
        (SyncTarget::Directory(Some(directory)), 0),
    ] {
        let boundary = f.overlay.seal_sync(&mut f.store, &f.owner, target).unwrap();
        assert_eq!(boundary.files().len(), files);
        f.overlay.release_sync_boundary(&boundary).unwrap();
    }
    assert_eq!(f.overlay.summary().captured_bytes, 0);
}

/// Runs `id`'s fsync to the point where its staging-header mark is durable,
/// then crashes before its `file-synced` record is, and reopens. Returns the
/// failed record's error and the content the lost record named.
fn tear_file_synced(f: &mut Fixture, id: u64) -> (Result<(), String>, GrainId) {
    let token = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    f.overlay
        .flush_boundary(&mut f.store, &f.owner, &token)
        .unwrap();
    let content = GrainId::of(&token.chunks.concat());
    f.source.0.insert(content, token.chunks.concat());
    f.overlay
        .faults
        .arm("overlay.journal.post_sync", "before", 1, FaultAction::Crash);
    let torn = f.overlay.record_file_synced(
        &mut f.store,
        &f.owner,
        &RegisteredCapture {
            capture: token,
            writer: [17; 16],
            generation: 1,
            prepared_root: grain(2),
            content,
        },
    );
    f.io.crash();
    f.reopen().unwrap();
    (torn.map_err(|e| e.to_string()), content)
}

/// What the next fsync of `id` owes (mark, checkpoint, dirty intervals),
/// recording its mark only when owed, and what the directory sync that
/// follows projects.
type FsyncThenDirectory = (
    (bool, Option<(GrainId, u64)>, Vec<(u64, u64)>),
    Vec<(Vec<Name>, OverlayKind)>,
);

fn fsync_then_directory(f: &mut Fixture, id: u64) -> FsyncThenDirectory {
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let file = &b.files()[0];
    let owed = (file.needs_mark(), file.checkpoint(), file.dirty_intervals());
    f.overlay.release_sync_boundary(&b).unwrap();
    if owed.0 {
        f.sync(id, 2);
    }
    let d = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    let projected = d
        .project(&[])
        .unwrap()
        .entries()
        .iter()
        .map(|entry| (entry.path.clone(), entry.kind.clone()))
        .collect();
    f.overlay.release_sync_boundary(&d).unwrap();
    (owed, projected)
}

/// A crash after an fsync's staging-header mark is durable but before its
/// `file-synced` record is durable leaves a mark nothing acknowledged. The
/// next fsync still owes a mark, so the directory sync that follows includes
/// the file.
#[test]
fn a_header_mark_without_its_file_synced_record_still_owes_a_mark() {
    let mut f = Fixture::new();
    let id = f.create();
    let (torn, content) = tear_file_synced(&mut f, id);
    let mark_after_reopen = f.overlay.namespace.stages[&id].mark.map(|m| m.content);
    let (owed, projected) = fsync_then_directory(&mut f, id);
    assert_eq!(
        (torn, mark_after_reopen, owed, projected),
        (
            Err(OverlayError::InjectedCrash.to_string()),
            Some(content),
            (true, Some((content, 0)), vec![]),
            vec![(
                vec![name("f")],
                OverlayKind::File {
                    content: Some(content)
                }
            )]
        )
    );
}

/// A copy-up truncated below its base, whose fsync's header mark survived a
/// lost `file-synced`, is clean against that mark after reopen: its zeros lie
/// past the mark's size and it has no extents. Its entry still holds the base,
/// not the mark, so the next fsync owes a mark and the directory sync projects
/// the truncated content rather than the base.
#[test]
fn a_truncated_copy_up_with_a_header_only_mark_still_owes_a_mark() {
    let base = GrainId::of(b"base");
    let mut f = Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("x")],
            inode: 0,
            kind: OverlayKind::File {
                content: Some(base),
            },
            stage_id: None,
            size: 4,
            exec: false,
        }],
        Source::default(),
    );
    f.source.0.insert(base, b"base".to_vec());
    let id = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("x"), &mut f.source)
        .unwrap();
    f.overlay.truncate(&mut f.store, &f.owner, id, 2).unwrap();
    let (torn, synced) = tear_file_synced(&mut f, id);
    let stage = &f.overlay.namespace.stages[&id];
    let reopened = (
        stage.mark.map(|m| (m.content, m.synced_size)),
        stage.extents.len(),
        stage.zeros.clone(),
        stage.size,
    );
    let (owed, projected) = fsync_then_directory(&mut f, id);
    assert_eq!(
        (torn, reopened, owed, projected),
        (
            Err(OverlayError::InjectedCrash.to_string()),
            (Some((synced, 2)), 0, vec![(2, 4)], 2),
            (true, Some((synced, 2)), vec![]),
            vec![(
                vec![name("x")],
                OverlayKind::File {
                    content: Some(synced)
                }
            )]
        )
    );
}
