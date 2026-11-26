// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn disposition_fixture(
    mode: codec::ResidualMode,
    collision: bool,
    synced: bool,
) -> (Fixture, crate::recovery::ResidualEvidence, u64) {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"local");
    if synced {
        f.sync(id, 2);
    }
    let mut proof = f.boundary_proof();
    if collision {
        proof.entries.first_mut().unwrap().kind = OverlayKind::File {
            content: Some(GrainId::of(b"remote")),
        };
        f.write(id, b"later");
    }
    let proof = f.landing(proof);
    let entry = f.overlay.namespace.entries.values().next().unwrap();
    let (name, parent) = entry.path.split_last().unwrap();
    let mut hash = codec::ResidualPayloadHasher::new(id, 5);
    hash.update(b"later");
    let inventory = codec::residual_inventory_check(&[codec::ResidualFile {
        stage_id: id,
        at: codec::Location {
            parent: codec::Parent::new(parent.to_vec()).unwrap(),
            name: name.clone(),
        },
        exec: entry.exec,
        local_size: entry.size,
        payload_check: hash.finalize(),
    }])
    .unwrap();
    let evidence = seal_evidence(
        &mut f,
        proof,
        1,
        if collision { inventory } else { [3; 32] },
        [7; 16],
        16_777_216,
        mode,
    );
    (f, evidence, id)
}

#[test]
fn residual_disposition_is_held_before_replay_repairs() {
    let mut count = 0;
    for mode in [
        codec::ResidualMode::KeepLocal,
        codec::ResidualMode::KeepRemote,
    ] {
        let (mut f, evidence, id) = disposition_fixture(mode, false, false);
        let staged = f.overlay.stage_path(id);
        f.io.write_at(&staged, 165, b"unchecked suffix").unwrap();
        let before = f.journal_and_stages();
        let start = f.io.0.lock().unwrap().trace.len();
        let result = f.reopen();
        let replacement = f
            .overlay
            .prepare_replacement(&mut f.store, &f.owner, evidence.proof.clone())
            .err()
            .map(|e| e.to_string());
        let after = f.journal_and_stages();
        assert_eq!(
            (
                result.is_ok(),
                f.overlay.readiness(),
                after == before,
                after.1.first().map(|(_, b)| b.len()),
                replacement.as_deref(),
                f.persistence_since(start)
            ),
            (
                true,
                OverlayReadiness::PendingRecovery,
                true,
                before.1.first().map(|(_, b)| b.len()),
                Some("overlay pending ownership reconciliation"),
                f.open_barriers().to_vec()
            ),
            "mode {mode:?}: {result:?}"
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn residual_payload_reads_refuse_failures_and_short_answers_without_writes() {
    let mut rows = Vec::new();
    for case in [
        "valid",
        "length-read",
        "header-read",
        "payload-read",
        "short-header",
        "short-payload",
    ] {
        let (mut f, evidence, _) = disposition_fixture(codec::ResidualMode::KeepLocal, true, false);
        let before = f.journal_and_stages();
        let start = f.io.0.lock().unwrap().trace.len();
        {
            let mut model = f.io.0.lock().unwrap();
            match case {
                "length-read" => model.fail = Some("length"),
                "header-read" => model.fail = Some("read"),
                "payload-read" => model.read_error_at = Some(160),
                "short-header" => model.short_read_at = Some(0),
                "short-payload" => model.short_read_at = Some(160),
                _ => {}
            }
        }
        let result = super::super::validate_residual_sources(
            &mut f.io,
            &f.overlay.area,
            &f.overlay.config,
            &evidence,
            || Ok(()),
        )
        .map_err(|error| error.to_string());
        let preserved = f.journal_and_stages() == before;
        let writes = f.io.0.lock().unwrap().trace[start..].iter().any(|(op, _)| {
            matches!(
                op.as_str(),
                "write" | "resize" | "remove" | "sync" | "rename" | "dir_sync" | "create"
            )
        });
        rows.push((case, result, preserved, writes));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("valid", Ok(()), true, false),
                (
                    "length-read",
                    Err("intent refused: RecoveryResidualUnavailable".into()),
                    true,
                    false
                ),
                (
                    "header-read",
                    Err("intent refused: RecoveryResidualUnavailable".into()),
                    true,
                    false
                ),
                (
                    "payload-read",
                    Err("intent refused: RecoveryResidualUnavailable".into()),
                    true,
                    false
                ),
                (
                    "short-header",
                    Err("intent refused: RecoveryResidualPayloadHeader".into()),
                    true,
                    false
                ),
                (
                    "short-payload",
                    Err("intent refused: RecoveryResidualPayloadLength".into()),
                    true,
                    false
                ),
            ],
            6
        )
    );
}

#[test]
fn residual_payload_header_refuses_wrong_writer_stage_or_mark() {
    let mut rows = Vec::new();
    for case in ["valid", "writer", "stage", "mark"] {
        let (mut f, evidence, id) =
            disposition_fixture(codec::ResidualMode::KeepLocal, true, false);
        if case != "valid" {
            let path = f.overlay.stage_path(id);
            let bytes = f.io.bytes(&path);
            let mut header = StagingHeader::decode(bytes.get(..160).unwrap()).unwrap();
            match case {
                "writer" => header.writer = [99; 16],
                "stage" => header.stage_id = id + 1,
                "mark" => {
                    header.mark = MarkState::Present(codec::SyncedMark {
                        synced_size: 5,
                        content: GrainId::of(b"later"),
                        generation: 1,
                    });
                }
                _ => unreachable!(),
            }
            f.io.write_at(&path, 0, &header.encode().unwrap()).unwrap();
        }
        rows.push((case, validate_preserved(&mut f, &evidence)));
    }
    let refused = Err("intent refused: RecoveryResidualPayloadHeader".into());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("valid", Ok(())),
                ("writer", refused.clone()),
                ("stage", refused.clone()),
                ("mark", refused)
            ],
            4
        )
    );
}

#[test]
fn residual_inventory_accepts_an_older_agreeing_mark() {
    let mut rows = Vec::new();
    for (case, content, size, generation) in [
        ("checkpoint", b"local", 5, 1),
        ("writer-read", b"local", 5, 1),
        ("other content", b"later", 5, 1),
        ("other size", b"local", 4, 1),
        ("above ceiling", b"local", 5, 101),
    ] {
        let (mut f, evidence, id) = disposition_fixture(codec::ResidualMode::KeepLocal, true, true);
        let path = f.overlay.stage_path(id);
        let mut header = f.overlay.header(id).unwrap();
        header.mark = MarkState::Present(codec::SyncedMark {
            content: GrainId::of(content),
            synced_size: size,
            generation,
        });
        f.io.write_at(&path, 0, &header.encode().unwrap()).unwrap();
        if case == "writer-read" {
            let mut model = f.io.0.lock().unwrap();
            model.fail = Some("read");
            model.fail_path = Some(f.overlay.area.join("writer"));
        }
        rows.push((case, validate_preserved(&mut f, &evidence)));
    }
    let refused = Err("intent refused: RecoveryResidualPayloadHeader".into());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("checkpoint", Ok(())),
                (
                    "writer-read",
                    Err("intent refused: RecoveryResidualUnavailable".into())
                ),
                ("other content", refused.clone()),
                ("other size", refused.clone()),
                ("above ceiling", refused)
            ],
            5
        )
    );
}

fn seal_evidence(
    f: &mut Fixture,
    proof: LandedProof,
    count: u32,
    inventory: [u8; 32],
    publication: [u8; 16],
    workspace: u64,
    mode: codec::ResidualMode,
) -> crate::recovery::ResidualEvidence {
    let path = f.overlay.journal_path();
    let bytes = f.io.bytes(&path);
    let scan = codec::scan_journal(&bytes).unwrap();
    let disposition = codec::ResidualDisposition {
        boundary_seq: proof.boundary_seq,
        publication_id: publication,
        landed_root: proof.landed_root,
        landed_seq: proof.landed_seq,
        source_end: scan.state.next_seq() - 1,
        disposition: mode,
        collision_count: count,
        inventory_check: inventory,
    };
    let frame = codec::encode_record(
        &scan.header,
        scan.state.next_seq(),
        &Record::ResidualDisposition(disposition),
    )
    .unwrap();
    f.io.write_at(&path, bytes.len() as u64, &frame).unwrap();
    let payloads = proof
        .captured_entries
        .iter()
        .filter_map(|entry| match entry.kind {
            OverlayKind::File {
                content: Some(content),
            } => f.source.0.get(&content).map(|bytes| {
                let grains = if bytes.is_empty() {
                    granary_core::manifest::FileGrains::Inline(Vec::new())
                } else {
                    granary_core::manifest::FileGrains::Inline(vec![
                        granary_core::manifest::GrainRef {
                            id: GrainId::of(bytes),
                            unpacked_len: u32::try_from(bytes.len()).unwrap(),
                        },
                    ])
                };
                (
                    content,
                    crate::recovery::CapturedPayload {
                        size: entry.size,
                        grains,
                    },
                )
            }),
            _ => None,
        })
        .collect();
    crate::recovery::ResidualEvidence {
        disposition,
        source: crate::recovery::ResidualSource {
            header: scan.header,
            journal: bytes,
            boundary_seq: disposition.boundary_seq,
            publication_id: disposition.publication_id,
            source_end: disposition.source_end,
            base: Vec::new(),
            proof,
            base_entries: f.overlay.base.clone(),
            captured: crate::recovery::CapturedContent {
                payloads,
                nodes: BTreeMap::new(),
            },
            budget: crate::sync::Budget::new(&(), workspace, None),
        },
    }
}

fn validate_preserved(
    f: &mut Fixture,
    evidence: &crate::recovery::ResidualEvidence,
) -> Result<(), String> {
    let before = f.journal_and_stages();
    let result = super::super::validate_residual_sources(
        &mut f.io,
        &f.overlay.area,
        &f.overlay.config,
        evidence,
        || Ok(()),
    )
    .map_err(|error| error.to_string());
    assert_eq!(f.journal_and_stages(), before);
    result
}

fn collision_files(
    count: usize,
    size: usize,
    captured_only: bool,
) -> (Fixture, crate::recovery::ResidualEvidence) {
    let mut f = Fixture::with_base_capped(vec![], Source::default(), 1 << 30);
    let mut ids = Vec::new();
    for index in 0..count + usize::from(captured_only) {
        let id = f
            .overlay
            .create_file(&mut f.store, &f.owner, at(&format!("f{index:03}")), false)
            .unwrap();
        f.write(id, &vec![7; size]);
        ids.push(id);
    }
    let mut proof = f.boundary_proof();
    for entry in &mut proof.entries {
        entry.kind = OverlayKind::File {
            content: Some(GrainId::of(b"remote")),
        };
    }
    let mut files = Vec::new();
    for &id in ids.iter().take(count) {
        f.write(id, b"L");
        let entry = f
            .overlay
            .namespace
            .entries
            .values()
            .find(|e| e.stage_id == Some(id))
            .unwrap();
        let mut bytes = vec![7; size];
        bytes[0] = b'L';
        let mut hash = codec::ResidualPayloadHasher::new(id, size as u64);
        hash.update(&bytes);
        files.push(codec::ResidualFile {
            stage_id: id,
            at: codec::Location {
                parent: codec::Parent::new(vec![]).unwrap(),
                name: entry.path.last().unwrap().clone(),
            },
            exec: false,
            local_size: size as u64,
            payload_check: hash.finalize(),
        });
    }
    let proof = f.landing(proof);
    let evidence = seal_evidence(
        &mut f,
        proof,
        u32::try_from(count).unwrap(),
        codec::residual_inventory_check(&files).unwrap(),
        [7; 16],
        16_777_216,
        codec::ResidualMode::KeepLocal,
    );
    (f, evidence)
}

#[test]
fn residual_captured_only_stage_is_not_a_collision() {
    let (mut f, evidence) = collision_files(1, 8, true);
    assert_eq!(validate_preserved(&mut f, &evidence), Ok(()));
}

#[test]
fn residual_payload_buffer_is_shared_across_collisions() {
    let mut rows = Vec::new();
    for count in [1, 32, 40] {
        let (mut f, evidence) = collision_files(count, 65_536, false);
        rows.push((count, validate_preserved(&mut f, &evidence)));
    }
    assert_eq!(
        (&rows, rows.len()),
        (&vec![(1, Ok(())), (32, Ok(())), (40, Ok(()))], 3)
    );
}

#[test]
fn residual_payload_checks_every_chunk() {
    let (mut f, evidence) = collision_files(1, 131_073, false);
    assert_eq!(validate_preserved(&mut f, &evidence), Ok(()));
    let id = *f.overlay.namespace.stages.keys().next().unwrap();
    let stage = f.overlay.stage_path(id);
    f.io.mutate(&stage, |bytes| bytes[160 + 100_000] ^= 1);
    assert_eq!(
        validate_preserved(&mut f, &evidence),
        Err("intent refused: RecoveryResidualInventoryCheck".into())
    );
}

#[test]
fn residual_exec_only_landing_change_is_a_collision() {
    let (mut f, mut evidence, _) = disposition_fixture(codec::ResidualMode::KeepLocal, true, false);
    evidence.proof.entries = evidence.proof.captured_entries.clone();
    evidence.proof.entries.first_mut().unwrap().exec = true;
    assert_eq!(validate_preserved(&mut f, &evidence), Ok(()));
}

#[test]
fn local_payload_equal_to_landed_but_not_capture_remains_a_collision() {
    let (mut f, mut evidence, _) = disposition_fixture(codec::ResidualMode::KeepLocal, true, false);
    evidence.proof.entries.first_mut().unwrap().kind = OverlayKind::File {
        content: Some(GrainId::of(b"later")),
    };
    assert_eq!(validate_preserved(&mut f, &evidence), Ok(()));
}

#[test]
fn residual_capture_checks_length_and_path() {
    let mut rows = Vec::new();
    for case in ["valid", "length", "path"] {
        let (mut f, mut evidence, _) =
            disposition_fixture(codec::ResidualMode::KeepLocal, true, false);
        match case {
            "length" => {
                evidence.proof.captured_entries.pop();
            }
            "path" => {
                evidence.proof.captured_entries.first_mut().unwrap().path = vec![name("other")];
            }
            _ => {}
        }
        rows.push((case, validate_preserved(&mut f, &evidence)));
    }
    let refusal = Err("intent refused: RecoveryResidualCaptureChanged".into());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("valid", Ok(())),
                ("length", refusal.clone()),
                ("path", refusal)
            ],
            3
        )
    );
}

#[test]
fn residual_recreated_stage_is_a_collision_without_a_write_record() {
    let mut f = Fixture::new();
    let mut h = header();
    h.next_stage_id = 2;
    f.io.write_at(
        &f.overlay.journal_path(),
        0,
        &codec::encode_journal(&h, &[]).unwrap(),
    )
    .unwrap();
    f.reopen().unwrap();
    let mut proof = f.boundary_proof();
    proof.entries.push(OverlayEntry {
        path: vec![name("f")],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(GrainId::of(b"remote")),
        },
        stage_id: None,
        size: 6,
        exec: false,
    });
    f.overlay
        .append(&Record::RecreateFile {
            at: Some(at("f")),
            exec: false,
            stage_id: 1,
            anchor: None,
        })
        .unwrap();
    let path = f.overlay.stage_path(1);
    f.io.create(&path).unwrap();
    f.io.write_at(
        &path,
        0,
        &StagingHeader {
            writer: header().writer,
            stage_id: 1,
            mark: MarkState::Absent,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    let proof = f.landing(proof);
    let file = codec::ResidualFile {
        stage_id: 1,
        at: at("f"),
        exec: false,
        local_size: 0,
        payload_check: codec::ResidualPayloadHasher::new(1, 0).finalize(),
    };
    let evidence = seal_evidence(
        &mut f,
        proof,
        1,
        codec::residual_inventory_check(&[file]).unwrap(),
        [7; 16],
        16_777_216,
        codec::ResidualMode::KeepLocal,
    );
    assert_eq!(validate_preserved(&mut f, &evidence), Ok(()));
}

#[test]
fn synced_journal_does_not_encode_the_capture_cursor() {
    let mut rows = Vec::new();
    for late in [false, true] {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"same");
        let first = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
        f.write(id, b"same");
        let second = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
        let capture = if late { second } else { first };
        f.overlay
            .flush_boundary(&mut f.store, &f.owner, &capture)
            .unwrap();
        f.overlay
            .record_file_synced(
                &mut f.store,
                &f.owner,
                &RegisteredCapture {
                    capture,
                    writer: header().writer,
                    generation: 1,
                    prepared_root: grain(2),
                    content: GrainId::of(b"same"),
                },
            )
            .unwrap();
        let stage = &f.overlay.namespace.stages[&id];
        rows.push((
            f.io.bytes(&f.overlay.journal_path()),
            stage.checkpoint_boundary,
            f.overlay.checkpoint_dirty(id, stage).unwrap().is_empty(),
        ));
    }
    assert_eq!(
        (
            rows[0].0 == rows[1].0,
            rows[0].1 == rows[1].1,
            rows[0].2,
            rows[1].2,
            rows.len()
        ),
        (true, false, false, true, 2),
        "{rows:?}"
    );
}

#[test]
fn residual_copy_up_is_a_collision_without_a_write() {
    let mut rows = Vec::new();
    for dirty in [false, true] {
        let mut source = Source::default();
        source.0.insert(GrainId::of(b"base a"), b"base a".to_vec());
        let base = vec![OverlayEntry {
            path: vec![name("a")],
            inode: 0,
            kind: OverlayKind::File {
                content: Some(GrainId::of(b"base a")),
            },
            stage_id: None,
            size: 6,
            exec: false,
        }];
        let mut f = Fixture::with_base(base, source);
        let mut proof = f.boundary_proof();
        proof.entries.first_mut().unwrap().kind = OverlayKind::File {
            content: Some(GrainId::of(b"remote")),
        };
        let id = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("a"), &mut f.source)
            .unwrap();
        let bytes: &[u8] = if dirty { b"local!" } else { b"base a" };
        if dirty {
            f.write(id, bytes);
        }
        let proof = f.landing(proof);
        let mut hash = codec::ResidualPayloadHasher::new(id, 6);
        hash.update(bytes);
        let file = codec::ResidualFile {
            stage_id: id,
            at: at("a"),
            exec: false,
            local_size: 6,
            payload_check: hash.finalize(),
        };
        let evidence = seal_evidence(
            &mut f,
            proof,
            1,
            codec::residual_inventory_check(&[file]).unwrap(),
            [7; 16],
            16_777_216,
            codec::ResidualMode::KeepLocal,
        );
        rows.push((dirty, validate_preserved(&mut f, &evidence)));
    }
    assert_eq!(
        (&rows, rows.len()),
        (&vec![(false, Ok(())), (true, Ok(()))], 2)
    );
}

/// A projected x capture with y synced at an unrecorded capture cursor.
fn projected_synced_inventory(
    mode: codec::ResidualMode,
    remote_changes_y: bool,
    include_y: bool,
) -> Result<(), String> {
    let mut source = Source::default();
    source.0.insert(GrainId::of(&[b'y'; 100]), vec![b'y'; 100]);
    let mut f = Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("y")],
            inode: 0,
            kind: OverlayKind::File {
                content: Some(GrainId::of(&[b'y'; 100])),
            },
            stage_id: None,
            size: 100,
            exec: false,
        }],
        source,
    );
    let y = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
        .unwrap();
    f.write(y, b"nn");
    let x = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("x"), false)
        .unwrap();
    f.write(x, b"x captured");
    let y_bytes = f.sync(y, 1).chunks.concat();
    let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    let synced = f.sync(x, 2).chunks.concat();
    let boundary = f
        .overlay
        .append(&Record::ProjectedBoundary {
            candidate: grain(9),
            through_seq,
            publication_id: [9; 16],
            selection: Some(codec::ProjectedSelection {
                stage_id: x,
                content: GrainId::of(&synced),
                size: synced.len() as u64,
            }),
        })
        .unwrap();
    let captured: Vec<_> = f
        .overlay
        .projected_commit_entries(boundary, [9; 16])
        .unwrap()
        .into_iter()
        .map(|mut entry| {
            entry.stage_id = None;
            entry
        })
        .collect();
    let mut landed = captured.clone();
    for entry in &mut landed {
        if entry.path == vec![name("x")] || (remote_changes_y && entry.path == vec![name("y")]) {
            entry.kind = OverlayKind::File {
                content: Some(GrainId::of(b"remote")),
            };
            entry.size = 6;
        }
    }
    f.write(x, b"L");
    let proof = f.landing(LandedProof {
        boundary_seq: boundary,
        landed_root: grain(4),
        landed_seq: 2,
        captured_entries: captured,
        entries: landed,
    });
    let mut files = Vec::new();
    for (id, path, bytes) in [
        (y, "y", y_bytes.as_slice()),
        (x, "x", b"L captured".as_slice()),
    ] {
        if id == y && !include_y {
            continue;
        }
        let mut hash = codec::ResidualPayloadHasher::new(id, bytes.len() as u64);
        hash.update(bytes);
        files.push(codec::ResidualFile {
            stage_id: id,
            at: at(path),
            exec: false,
            local_size: bytes.len() as u64,
            payload_check: hash.finalize(),
        });
    }
    let evidence = seal_evidence(
        &mut f,
        proof,
        u32::try_from(files.len()).unwrap(),
        codec::residual_inventory_check(&files).unwrap(),
        [9; 16],
        16_777_216,
        mode,
    );
    validate_preserved(&mut f, &evidence)
}

#[test]
fn projected_synced_inventory_uses_captured_bytes_without_a_capture_cursor() {
    let mut rows = Vec::new();
    for mode in [
        codec::ResidualMode::KeepLocal,
        codec::ResidualMode::KeepRemote,
    ] {
        for remote_changes_y in [false, true] {
            for include_y in [false, true] {
                rows.push((
                    mode,
                    remote_changes_y,
                    include_y,
                    projected_synced_inventory(mode, remote_changes_y, include_y),
                ));
            }
        }
    }
    let refused = Err("intent refused: RecoveryResidualInventoryCount".into());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (codec::ResidualMode::KeepLocal, false, false, Ok(())),
                (codec::ResidualMode::KeepLocal, false, true, refused.clone()),
                (codec::ResidualMode::KeepLocal, true, false, Ok(())),
                (codec::ResidualMode::KeepLocal, true, true, refused.clone()),
                (codec::ResidualMode::KeepRemote, false, false, Ok(())),
                (
                    codec::ResidualMode::KeepRemote,
                    false,
                    true,
                    refused.clone()
                ),
                (codec::ResidualMode::KeepRemote, true, false, Ok(())),
                (codec::ResidualMode::KeepRemote, true, true, refused)
            ],
            8
        )
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "one projected equality fixture sequence"
)]
fn projected_equal_capture(
    bytes: &[u8],
    grains: granary_core::manifest::FileGrains,
    nodes: BTreeMap<GrainId, Vec<u8>>,
    workspace: u64,
    post_boundary: Option<Record>,
) -> Result<(usize, bool), String> {
    let mut source = Source::default();
    source.0.insert(GrainId::of(bytes), bytes.to_vec());
    let mut f = Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("y")],
            inode: 0,
            kind: OverlayKind::File {
                content: Some(GrainId::of(bytes)),
            },
            stage_id: None,
            size: bytes.len() as u64,
            exec: false,
        }],
        source,
    );
    let y = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("y"), &mut f.source)
        .unwrap();
    f.write(y, b"z");
    if let Some(first) = bytes.first().copied() {
        f.write(y, &[first]);
        f.overlay
            .truncate(
                &mut f.store,
                &f.owner,
                y,
                u64::try_from(bytes.len().saturating_add(1)).unwrap(),
            )
            .unwrap();
    }
    f.overlay
        .truncate(
            &mut f.store,
            &f.owner,
            y,
            u64::try_from(bytes.len()).unwrap(),
        )
        .unwrap();
    f.sync(y, 1);
    let x = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("x"), false)
        .unwrap();
    f.write(x, b"x");
    let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    let selected = f.sync(x, 2).chunks.concat();
    let boundary = f
        .overlay
        .append(&Record::ProjectedBoundary {
            candidate: grain(9),
            through_seq,
            publication_id: [9; 16],
            selection: Some(codec::ProjectedSelection {
                stage_id: x,
                content: GrainId::of(&selected),
                size: selected.len() as u64,
            }),
        })
        .unwrap();
    if let Some(record) = post_boundary {
        f.overlay
            .namespace_record(&mut f.store, &f.owner, record)
            .unwrap();
    }
    let captured: Vec<_> = f
        .overlay
        .projected_commit_entries(boundary, [9; 16])
        .unwrap()
        .into_iter()
        .map(|mut entry| {
            entry.stage_id = None;
            entry
        })
        .collect();
    let mut landed = captured.clone();
    landed
        .iter_mut()
        .find(|entry| entry.path == vec![name("y")])
        .unwrap()
        .kind = OverlayKind::File {
        content: Some(GrainId::of(b"remote")),
    };
    let proof = f.landing(LandedProof {
        boundary_seq: boundary,
        landed_root: grain(4),
        landed_seq: 2,
        captured_entries: captured,
        entries: landed,
    });
    let mut evidence = seal_evidence(
        &mut f,
        proof,
        1,
        [1; 32],
        [9; 16],
        workspace,
        codec::ResidualMode::KeepLocal,
    );
    let content = evidence
        .proof
        .captured_entries
        .iter()
        .find(|entry| entry.path == vec![name("y")])
        .and_then(|entry| match entry.kind {
            OverlayKind::File {
                content: Some(content),
            } => Some(content),
            _ => None,
        })
        .unwrap();
    evidence.captured.payloads.insert(
        content,
        crate::recovery::CapturedPayload {
            size: bytes.len() as u64,
            grains,
        },
    );
    evidence.captured.nodes = nodes;
    let before = f.journal_and_stages();
    let inventory = super::super::inventory(
        &mut f.io,
        &f.overlay.area,
        &f.overlay.config,
        &evidence.source,
        || Ok(()),
    )
    .map_err(|error| error.to_string())?;
    assert_eq!(f.journal_and_stages(), before);
    Ok((
        inventory.collisions.len(),
        inventory.reconciliation.contains(y),
    ))
}

#[test]
fn captured_layout_proves_inline_spill_and_multiple_leaf_equality() {
    let mut rows = Vec::new();
    for count in [128usize, 129, 131_073] {
        let bytes = vec![b'q'; count];
        let refs: Vec<_> = bytes
            .iter()
            .map(|byte| granary_core::manifest::GrainRef {
                id: GrainId::of(std::slice::from_ref(byte)),
                unpacked_len: 1,
            })
            .collect();
        let (grains, nodes) = if count == 128 {
            (
                granary_core::manifest::FileGrains::Inline(refs),
                BTreeMap::new(),
            )
        } else {
            let tree = granary_core::manifest::build_grain_list(&refs).unwrap();
            (
                granary_core::manifest::FileGrains::Spill {
                    grain_count: u32::try_from(count).unwrap(),
                    root: tree.root,
                },
                tree.nodes.into_iter().collect(),
            )
        };
        rows.push((
            count,
            projected_equal_capture(&bytes, grains, nodes, 16_777_216, None),
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (128, Ok((0, true))),
                (129, Ok((0, true))),
                (131_073, Ok((0, true)))
            ],
            3
        )
    );
}

#[test]
fn captured_equality_charges_one_exact_scratch_allowance() {
    let bytes = vec![b'q'; 128];
    let refs: Vec<_> = bytes
        .iter()
        .map(|byte| granary_core::manifest::GrainRef {
            id: GrainId::of(std::slice::from_ref(byte)),
            unpacked_len: 1,
        })
        .collect();
    let scratch = u64::try_from(
        (super::super::BUFFER + std::mem::size_of::<granary_core::hash::GrainIdHasher>()) * 8
            + 1024,
    )
    .unwrap();
    let mut rows = Vec::new();
    for workspace in [scratch - 1, scratch] {
        rows.push((
            workspace,
            projected_equal_capture(
                &bytes,
                granary_core::manifest::FileGrains::Inline(refs.clone()),
                BTreeMap::new(),
                workspace,
                None,
            ),
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    scratch - 1,
                    Err("intent refused: RecoveryResidualWorkspace".into())
                ),
                (scratch, Ok((0, true)))
            ],
            2
        )
    );
}

#[test]
fn captured_equality_refuses_missing_or_corrupt_spill_evidence() {
    let bytes = vec![b'q'; 129];
    let refs: Vec<_> = bytes
        .iter()
        .map(|byte| granary_core::manifest::GrainRef {
            id: GrainId::of(std::slice::from_ref(byte)),
            unpacked_len: 1,
        })
        .collect();
    let tree = granary_core::manifest::build_grain_list(&refs).unwrap();
    let grains = granary_core::manifest::FileGrains::Spill {
        grain_count: 129,
        root: tree.root,
    };
    let valid: BTreeMap<_, _> = tree.nodes.into_iter().collect();
    let mut corrupt = valid.clone();
    if let Some(byte) = corrupt.get_mut(&tree.root).unwrap().get_mut(15) {
        *byte ^= 1;
    }
    let mut rows = Vec::new();
    for (case, nodes) in [
        ("valid", valid),
        ("missing", BTreeMap::new()),
        ("corrupt", corrupt),
    ] {
        rows.push((
            case,
            projected_equal_capture(&bytes, grains.clone(), nodes, 16_777_216, None),
        ));
    }
    let unknown = Err("intent refused: RecoveryResidualCaptureUnknown".into());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("valid", Ok((0, true))),
                ("missing", unknown.clone()),
                ("corrupt", unknown)
            ],
            3
        )
    );
}

#[test]
fn captured_equality_refuses_false_cumulative_index_fields() {
    let bytes = vec![b'q'; 131_073];
    let refs: Vec<_> = bytes
        .iter()
        .map(|byte| granary_core::manifest::GrainRef {
            id: GrainId::of(std::slice::from_ref(byte)),
            unpacked_len: 1,
        })
        .collect();
    let tree = granary_core::manifest::build_grain_list(&refs).unwrap();
    let valid_nodes: BTreeMap<_, _> = tree.nodes.into_iter().collect();
    let mut rows = vec![(
        "valid",
        projected_equal_capture(
            &bytes,
            granary_core::manifest::FileGrains::Spill {
                grain_count: 131_073,
                root: tree.root,
            },
            valid_nodes.clone(),
            16_777_216,
            None,
        ),
    )];
    for case in ["length", "count"] {
        let root_bytes = valid_nodes.get(&tree.root).unwrap();
        let (kind, cursor) = granary_core::encoding::open_envelope(root_bytes).unwrap();
        assert_eq!(kind, granary_core::encoding::ObjectType::GrainListIndex);
        let mut children = granary_core::manifest::decode_grain_list_index(cursor).unwrap();
        let child = children.first_mut().unwrap();
        match case {
            "length" => child.cum_unpacked_len += 1,
            "count" => child.cum_ref_count += 1,
            _ => unreachable!(),
        }
        let false_index = granary_core::manifest::encode_grain_list_index(&children).unwrap();
        let false_root = GrainId::of(&false_index);
        let mut nodes = valid_nodes.clone();
        nodes.insert(false_root, false_index);
        rows.push((
            case,
            projected_equal_capture(
                &bytes,
                granary_core::manifest::FileGrains::Spill {
                    grain_count: 131_073,
                    root: false_root,
                },
                nodes,
                16_777_216,
                None,
            ),
        ));
    }
    let unknown = Err("intent refused: RecoveryResidualCaptureUnknown".into());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("valid", Ok((0, true))),
                ("length", unknown.clone()),
                ("count", unknown),
            ],
            3
        )
    );
}

#[test]
fn equal_payload_with_a_local_exec_change_refuses_before_inventory() {
    let bytes = vec![b'q'; 128];
    let refs = bytes
        .iter()
        .map(|byte| granary_core::manifest::GrainRef {
            id: GrainId::of(std::slice::from_ref(byte)),
            unpacked_len: 1,
        })
        .collect();
    assert_eq!(
        projected_equal_capture(
            &bytes,
            granary_core::manifest::FileGrains::Inline(refs),
            BTreeMap::new(),
            16_777_216,
            Some(Record::SetattrExec {
                at: at("y"),
                exec: true,
            }),
        ),
        Err("intent refused: RecoveryResidualExecChanged".into())
    );
}

#[test]
fn equal_payload_does_not_bypass_move_support() {
    let bytes = vec![b'q'; 128];
    let refs = bytes
        .iter()
        .map(|byte| granary_core::manifest::GrainRef {
            id: GrainId::of(std::slice::from_ref(byte)),
            unpacked_len: 1,
        })
        .collect();
    assert_eq!(
        projected_equal_capture(
            &bytes,
            granary_core::manifest::FileGrains::Inline(refs),
            BTreeMap::new(),
            16_777_216,
            Some(Record::Move {
                from: at("y"),
                to: at("moved"),
            }),
        ),
        Err("intent refused: RecoveryResidualUnrepresentable".into())
    );
}

#[test]
fn empty_captured_payload_reconciles_after_write_and_truncate_restore() {
    assert_eq!(
        projected_equal_capture(
            &[],
            granary_core::manifest::FileGrains::Inline(Vec::new()),
            BTreeMap::new(),
            16_777_216,
            None,
        ),
        Ok((0, true))
    );
}

#[test]
fn residual_validation_expiry_precedes_each_payload_operation() {
    let mut rows = Vec::new();
    // Entry, length, header, then three chunk checks; the last value is valid.
    for expire_at in [1, 2, 3, 4, 5, 6, 7] {
        let (mut f, evidence) = collision_files(1, 131_073, false);
        let before = f.journal_and_stages();
        let start = f.io.0.lock().unwrap().trace.len();
        let mut calls = 0;
        let result = super::super::validate_residual_sources(
            &mut f.io,
            &f.overlay.area,
            &f.overlay.config,
            &evidence,
            || {
                calls += 1;
                if calls >= expire_at {
                    Err(crate::sync::refused("SyncDeadline"))
                } else {
                    Ok(())
                }
            },
        )
        .map_err(|error| error.to_string());
        let preserved = f.journal_and_stages() == before;
        let model = f.io.0.lock().unwrap();
        let writes = model.trace[start..].iter().any(|(op, _)| {
            matches!(
                op.as_str(),
                "write" | "resize" | "remove" | "sync" | "rename" | "dir_sync" | "create"
            )
        });
        let reads = model.trace[start..]
            .iter()
            .filter(|(op, _)| op == "read")
            .count();
        rows.push((expire_at, result, calls, reads, preserved, writes));
    }
    let expired = || Err("intent refused: SyncDeadline".to_owned());
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (1, expired(), 1, 0, true, false),
                (2, expired(), 2, 0, true, false),
                (3, expired(), 3, 0, true, false),
                (4, expired(), 4, 1, true, false),
                (5, expired(), 5, 2, true, false),
                (6, expired(), 6, 3, true, false),
                (7, Ok(()), 6, 4, true, false)
            ],
            7
        )
    );
}

#[test]
fn residual_deadline_checks_each_file_and_spill_node() {
    let (mut files, files_source) = collision_files(2, 1, false);
    let mut file_calls = 0;
    let file_result = super::super::inventory(
        &mut files.io,
        &files.overlay.area,
        &files.overlay.config,
        &files_source.source,
        || {
            file_calls += 1;
            Ok(())
        },
    )
    .map(|inventory| inventory.collisions.len())
    .map_err(|error| error.to_string());

    let (mut spill, mut spill_source) = collision_files(1, 129, false);
    let refs: Vec<_> = (0..129)
        .map(|_| granary_core::manifest::GrainRef {
            id: GrainId::of(&[7]),
            unpacked_len: 1,
        })
        .collect();
    let tree = granary_core::manifest::build_grain_list(&refs).unwrap();
    let node_count = tree.nodes.len();
    let content = spill_source
        .proof
        .captured_entries
        .first()
        .and_then(|entry| match entry.kind {
            OverlayKind::File {
                content: Some(content),
            } => Some(content),
            _ => None,
        })
        .unwrap();
    spill_source.captured.payloads.insert(
        content,
        crate::recovery::CapturedPayload {
            size: 129,
            grains: granary_core::manifest::FileGrains::Spill {
                grain_count: 129,
                root: tree.root,
            },
        },
    );
    spill_source.captured.nodes = tree.nodes.into_iter().collect();
    let mut spill_calls = 0;
    let spill_result = super::super::inventory(
        &mut spill.io,
        &spill.overlay.area,
        &spill.overlay.config,
        &spill_source.source,
        || {
            spill_calls += 1;
            Ok(())
        },
    )
    .map(|inventory| inventory.collisions.len())
    .map_err(|error| error.to_string());
    assert_eq!(
        (
            file_result,
            file_calls,
            spill_result,
            spill_calls,
            node_count
        ),
        (Ok(2), 7, Ok(1), 3 + 129 + node_count, node_count)
    );
}

#[test]
fn residual_expiry_precedes_journal_replay() {
    let (mut f, mut evidence, _) = disposition_fixture(codec::ResidualMode::KeepLocal, true, false);
    evidence.journal[0] ^= 1;
    let before = f.journal_and_stages();
    let start = f.io.0.lock().unwrap().trace.len();
    let result = super::super::validate_residual_sources(
        &mut f.io,
        &f.overlay.area,
        &f.overlay.config,
        &evidence,
        || Err(crate::sync::refused("SyncDeadline")),
    )
    .map_err(|error| error.to_string());
    assert_eq!(
        (
            result,
            f.journal_and_stages() == before,
            f.io.0.lock().unwrap().trace[start..]
                .iter()
                .any(|(op, _)| matches!(
                    op.as_str(),
                    "read"
                        | "length"
                        | "write"
                        | "resize"
                        | "remove"
                        | "sync"
                        | "rename"
                        | "dir_sync"
                        | "create"
                ))
        ),
        (Err("intent refused: SyncDeadline".into()), true, false)
    );
}
