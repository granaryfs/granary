// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn file(path: &str, bytes: &[u8]) -> OverlayEntry {
    OverlayEntry {
        path: vec![name(path)],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(GrainId::of(bytes)),
        },
        stage_id: None,
        size: bytes.len() as u64,
        exec: false,
    }
}

#[test]
fn reopen_settles_failed_normalization_before_acknowledging_work() {
    let mut f = Fixture::new();
    let faults = f.overlay.fault_control();
    faults.arm(
        "overlay.journal.normalize",
        "dir_sync",
        1,
        FaultAction::Fail,
    );
    let failed = f.overlay.normalize_same_base(&f.store);
    assert_eq!(
        (
            matches!(failed, Err(OverlayError::Io(_))),
            faults.fired().len()
        ),
        (true, 1),
        "normalize switch: {failed:?}, faults {:?}",
        faults.fired()
    );
    f.reopen().unwrap();
    let id = f.create();
    f.write(id, b"accepted");
    f.sync(id, 1);
    f.io.crash();
    let read = f
        .reopen()
        .and_then(|()| f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8));
    assert_eq!(
        read.map_err(|error| error.to_string()).as_deref(),
        Ok(&b"accepted"[..])
    );
}

#[test]
fn reopen_settles_failed_replacement_before_acknowledging_work() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let faults = f.overlay.fault_control();
    faults.arm("overlay.replace.dir_sync", "before", 1, FaultAction::Fail);
    let failed = f
        .overlay
        .replace_landed(&mut f.store, &f.owner, proof.clone());
    assert_eq!(
        (
            matches!(failed, Err(OverlayError::Io(_))),
            faults.fired().len()
        ),
        (true, 1),
        "replacement switch: {failed:?}, faults {:?}",
        faults.fired()
    );
    f.overlay.base = proof.entries;
    f.reopen().unwrap();
    let id = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("g"), false)
        .unwrap();
    f.write(id, b"accepted");
    f.sync(id, 21);
    f.io.crash();
    let read = f
        .reopen()
        .and_then(|()| f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8));
    assert_eq!(
        read.map_err(|error| error.to_string()).as_deref(),
        Ok(&b"accepted"[..])
    );
}

#[test]
fn reopen_settles_staging_after_failed_retirement_sync() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let staging = f.overlay.area.join("staging");
    let path = f.overlay.stage_path(id);
    {
        let mut model = f.io.0.lock().unwrap();
        model.fail = Some("dir_sync");
        model.fail_path = Some(staging.clone());
    }
    let failed = f
        .overlay
        .replace_landed(&mut f.store, &f.owner, proof.clone());
    assert_eq!(
        (
            failed.err().map(|error| error.to_string()).as_deref(),
            f.io.length(&path).unwrap(),
            f.io.recovered_bytes(&format!("{id:016x}")).is_some()
        ),
        (Some("overlay I/O: model injected I/O"), None, true),
        "retirement removed the live name before its sync failed"
    );
    f.overlay.base = proof.entries;
    let start = f.io.0.lock().unwrap().trace.len();
    f.reopen().unwrap();
    let writer = f.overlay.area.join("writer");
    let settled_before_writer = f.io.0.lock().unwrap().trace[start..]
        .iter()
        .take_while(|(op, path)| op != "length" || path != &writer)
        .any(|(op, path)| op == "dir_sync" && path == &staging);
    let id = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("g"), false)
        .unwrap();
    f.write(id, b"accepted");
    f.sync(id, 21);
    f.io.crash();
    f.reopen().unwrap();
    let read = f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8);
    assert_eq!(
        (
            settled_before_writer,
            read.map_err(|error| error.to_string())
        ),
        (true, Ok(b"accepted".to_vec())),
        "staging settles before writer evidence after an uncertain retirement"
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "one crash-barrier matrix with reopen assertions before and after repair"
)]
pub(crate) fn normalized_stage_retirement_survives_crash() -> usize {
    let cuts = [
        ("overlay.normalize.mark_clear", "before"),
        ("overlay.normalize.mark_clear", "after-sync"),
        ("overlay.journal.normalize", "build"),
        ("overlay.journal.normalize", "before"),
        ("overlay.journal.normalize", "after"),
        ("overlay.journal.normalize", "sync"),
        ("overlay.journal.normalize", "after_sync"),
        ("overlay.journal.normalize", "rename"),
        ("overlay.journal.normalize", "after_rename"),
        ("overlay.journal.normalize", "dir_sync"),
        ("overlay.journal.normalize", "after_dir_sync"),
        ("overlay.normalize.retire", "before"),
        ("overlay.normalize.retire", "after-sync"),
    ];
    for (seam, phase) in cuts {
        let mut source = Source::default();
        source.0.insert(GrainId::of(b"old"), b"old".to_vec());
        let mut f = Fixture::with_base(vec![file("f", b"old")], source);
        let stage = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
            .unwrap();
        f.sync(stage, 1);
        let journal_path = f.overlay.journal_path();
        let journal = f.io.bytes(&journal_path);
        let mut records = Vec::new();
        let scan =
            codec::scan_journal_with(&journal, |_, record| records.push(record.clone())).unwrap();
        for record in &mut records {
            if let codec::Record::StageBind { cause, .. } = record {
                *cause = codec::BindCause::Rebind;
            }
        }
        let header = JournalHeader {
            next_stage_id: stage + 1,
            ..scan.header
        };
        let journal = codec::encode_journal(&header, &records).unwrap();
        f.io.resize(&journal_path, 0).unwrap();
        f.io.write_at(&journal_path, 0, &journal).unwrap();
        f.io.sync(&journal_path).unwrap();
        f.reopen().unwrap();
        let path = f.overlay.stage_path(stage);
        let before = codec::scan_journal(&f.io.bytes(&f.overlay.journal_path())).unwrap();
        let waters = (
            before.header.writer,
            before.state.next_stage_id(),
            before.state.highest_generation(),
            before.header.base_root,
            before.header.base_seq,
        );
        assert_eq!(
            (
                matches!(f.overlay.header(stage).unwrap().mark, MarkState::Present(_)),
                f.overlay.check_finish_obligations().is_ok(),
                f.overlay.initial_state_ready(),
                f.overlay.normalization_required().unwrap(),
            ),
            (true, true, true, true),
            "premise {seam}/{phase}"
        );
        let faults = f.overlay.fault_control();
        faults.arm(seam, phase, 1, FaultAction::Crash);
        let cut = f.overlay.normalize_same_base(&f.store);
        assert_eq!(
            (
                matches!(cut, Err(OverlayError::InjectedCrash)),
                faults.fired().len()
            ),
            (true, 1),
            "cut {seam}/{phase}: {cut:?}"
        );
        f.io.crash();
        let reopened = f.reopen();
        assert!(
            reopened.is_ok(),
            "crash reopen {seam}/{phase}: {reopened:?}"
        );
        let reopened_scan = codec::scan_journal(&f.io.bytes(&f.overlay.journal_path())).unwrap();
        let named_stage = f.overlay.namespace.stages.contains_key(&stage);
        let staged_file = f.io.length(&path).unwrap().is_some();
        let canonical =
            f.io.bytes(&f.overlay.journal_path()) == reopened_scan.header.encode().unwrap();
        assert_eq!(
            (
                reopened_scan.header.writer,
                reopened_scan.state.next_stage_id(),
                reopened_scan.state.highest_generation() >= waters.2,
                reopened_scan.header.base_root,
                reopened_scan.header.base_seq,
                (named_stage && staged_file) || canonical,
            ),
            (waters.0, waters.1, true, waters.3, waters.4, true),
            "reopened evidence and high waters {seam}/{phase}: named={named_stage}, file={staged_file}, canonical={canonical}"
        );
        if f.overlay.normalization_required().unwrap() {
            f.overlay.normalize_same_base(&f.store).unwrap();
        }
        f.io.crash();
        f.reopen().unwrap();
        let bytes = f.io.bytes(&f.overlay.journal_path());
        let scan = codec::scan_journal(&bytes).unwrap();
        assert_eq!(
            (
                scan.end,
                bytes == scan.header.encode().unwrap(),
                scan.header.writer,
                scan.state.next_stage_id(),
                scan.state.highest_generation() >= waters.2,
                scan.header.base_root,
                scan.header.base_seq,
                f.io.length(&path).unwrap().is_none(),
                f.overlay.initial_state_ready(),
            ),
            (
                codec::JournalEnd::Clean,
                true,
                waters.0,
                waters.1,
                true,
                waters.3,
                waters.4,
                true,
                true,
            ),
            "repaired canonical evidence {seam}/{phase}"
        );
    }
    cuts.len()
}

#[test]
fn same_base_normalization_refuses_a_divergent_stage_it_checks_itself() {
    let mut source = Source::default();
    source.0.insert(GrainId::of(b"old"), b"old".to_vec());
    let mut f = Fixture::with_base(vec![file("f", b"old")], source);
    let stage = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    f.sync(stage, 1);
    f.overlay.dirty_spans.clear();
    f.overlay
        .namespace
        .stages
        .get_mut(&stage)
        .unwrap()
        .extents
        .insert(
            0,
            codec::Record::WriteExtent {
                stage_id: stage,
                offset: 0,
                length: 3,
                check: codec::extent_check(stage, 0, b"new"),
            },
        );
    let journal = f.io.bytes(&f.overlay.journal_path());
    let stage_path = f.overlay.stage_path(stage);
    let staged = f.io.bytes(&stage_path);
    assert_eq!(
        (
            f.overlay.check_finish_obligations().is_ok(),
            f.overlay.initial_state_ready(),
        ),
        (true, false),
        "premise: obligations clear while same-size stage extents diverge"
    );
    let result = f.overlay.normalize_same_base(&f.store);
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string),
            f.io.bytes(&f.overlay.journal_path()) == journal,
            f.io.length(&stage_path)
                .unwrap()
                .is_some_and(|_| f.io.bytes(&stage_path) == staged),
            f.overlay.namespace.stages.contains_key(&stage),
        ),
        (
            Some("overlay refused: WritableRecoveryRequired".to_owned()),
            true,
            true,
            true,
        ),
        "inner same-base guard: {result:?}"
    );
}

#[test]
fn rebound_stage_write_crash_repairs_from_base_before_serving() {
    let mut cases = 0;
    for offset in [0, 5] {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"old");
        f.sync(id, 1);
        f.overlay
            .open_stage(&mut f.store, &f.owner, &[name("f")])
            .unwrap();
        let proof = f.boundary_proof();
        let proof = f.landing(proof);
        f.overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .unwrap();
        let stage = &f.overlay.namespace.stages[&id];
        assert_eq!(
            (stage.handles, f.overlay.initial_state_ready()),
            (1, true),
            "held clean rebound premise: {stage:?}"
        );
        let journal = f.io.bytes(&f.overlay.journal_path());
        let path = f.overlay.stage_path(id);
        let faults = f.overlay.fault_control();
        let occurrence = if offset == 0 { 1 } else { 2 };
        faults.arm(
            "overlay.stage.write",
            "after",
            occurrence,
            FaultAction::Crash,
        );
        let result = f.overlay.write(&mut f.store, &f.owner, id, offset, b"new");
        assert_eq!(
            (
                matches!(result, Err(OverlayError::InjectedCrash)),
                faults
                    .fired()
                    .iter()
                    .map(|event| (event.name, event.phase, event.occurrence))
                    .collect::<Vec<_>>(),
                f.io.bytes(&f.overlay.journal_path()),
                f.io.read_at(&path, 160 + offset, 3).unwrap(),
            ),
            (
                true,
                vec![("overlay.stage.write", "after", occurrence)],
                journal.clone(),
                b"new".to_vec(),
            ),
            "body changed before its record: offset={offset}, result={result:?}"
        );
        // The body may reach disk without a barrier; retain that crash outcome
        // while the injected stop has prevented the journal append entirely.
        f.io.sync(&path).unwrap();
        f.io.crash();
        let restarted = f.reopen();
        assert!(restarted.is_ok(), "offset={offset}: {restarted:?}");
        assert_eq!(
            (
                f.overlay.initial_state_ready(),
                f.overlay
                    .read_stage(&mut f.store, &f.owner, id, 0, 3)
                    .unwrap(),
                f.io.length(&path).unwrap(),
                f.io.bytes(&f.overlay.journal_path()),
            ),
            (true, b"old".to_vec(), Some(163), journal),
            "offset={offset}: repaired restart"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn in_process_replay_repairs_carried_bytes_after_landing() {
    use granary_core::manifest::{FileGrains, GrainRef, node::file_payload};

    let mut f = Fixture::new();
    let id = f.create();
    let landed = b"XY";
    f.write(id, landed);
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 2)
            .unwrap(),
        landed,
        "premise: the stage served before recovery"
    );

    let object = GrainId::of(landed);
    let payload = file_payload(
        2,
        &FileGrains::Inline(vec![GrainRef {
            id: object,
            unpacked_len: 2,
        }]),
    )
    .unwrap();
    let content = GrainId::of(&payload);
    f.store.put(&object, landed).unwrap();
    f.store.put(&content, &payload).unwrap();
    let mut proof = f.boundary_proof();
    proof.entries[0].kind = OverlayKind::File {
        content: Some(content),
    };
    proof.captured_entries.clone_from(&proof.entries);
    let proof = f.landing(proof);

    // Keep the overwrite frame without the surviving fragment's check.
    let journal = f.overlay.journal_path();
    let before = codec::scan_journal(&f.io.bytes(&journal)).unwrap();
    f.write(id, b"Z");
    let mut suffix = Vec::new();
    codec::scan_journal_with(&f.io.bytes(&journal), |seq, record| {
        if seq >= before.state.next_seq() {
            suffix.push((seq, record.clone()));
        }
    })
    .unwrap();
    let [(seq, write), (_, fragment)] = suffix.as_slice() else {
        panic!("premise: overwrite and fragment frames, got {suffix:?}");
    };
    assert!(
        matches!(
            (write, fragment),
            (
                Record::WriteExtent {
                    offset: 0,
                    length: 1,
                    ..
                },
                Record::WriteExtent {
                    offset: 1,
                    length: 1,
                    ..
                },
            )
        ),
        "premise: overwrite the first byte and retain the second, got {suffix:?}"
    );
    let frame = codec::encode_record(&before.header, *seq, write).unwrap();
    f.io.mutate(&journal, |bytes| {
        bytes.truncate(before.valid_len + frame.len());
    });
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();
    let stage = &f.overlay.namespace.stages[&id];
    assert_eq!(
        (
            stage.extents.keys().copied().collect::<Vec<_>>(),
            f.io.read_at(&f.overlay.stage_path(id), 160, 2).unwrap(),
        ),
        (vec![0], b"Z\0".to_vec()),
        "premise: replay filled the unchecked byte from the old checkpoint"
    );

    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 2)
            .unwrap(),
        b"ZY",
        "the first read must include the carried byte from the landed image"
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "one collision fixture compares the namespace, journal and every stage before and after refusal"
)]
fn suffix_collision(case: &str) {
    let mut source = Source::default();
    source.0.insert(GrainId::of(b"old"), b"old".to_vec());
    let mut f = Fixture::with_base(vec![file("f", b"old")], source);
    let stage = matches!(
        case,
        "required stage deleted"
            | "net-zero stage rewritten"
            | "net-zero stage retired"
            | "net-zero stage kind changed"
    )
    .then(|| {
        let stage = f
            .overlay
            .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
            .unwrap();
        if case != "required stage deleted" {
            f.write(stage, b"old");
        }
        stage
    });
    let proof = f.boundary_proof();
    let mut proof = f.landing(proof);
    match case {
        "created name gained" => {
            proof.entries.push(file("new", b"head"));
            f.overlay
                .namespace_record(
                    &mut f.store,
                    &f.owner,
                    codec::Record::Create {
                        at: at("new"),
                        kind: codec::CreateKind::Dir,
                    },
                )
                .unwrap();
        }
        "copy-up base changed" => {
            proof.entries = vec![file("f", b"head")];
            let stage = f
                .overlay
                .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
                .unwrap();
            f.write(stage, b"ack");
        }
        "required stage deleted" => {
            proof.entries.clear();
            f.write(stage.unwrap(), b"ack");
        }
        "net-zero stage rewritten" => {
            proof.entries = vec![file("f", b"new")];
            f.write(stage.unwrap(), b"ack");
        }
        "net-zero stage retired" => proof.entries.clear(),
        "net-zero stage kind changed" => {
            let mut entry = file("f", b"");
            entry.kind = OverlayKind::Directory;
            proof.entries = vec![entry];
        }
        "deleted name changed" => {
            proof.entries = vec![file("f", b"head")];
            f.overlay
                .namespace_record(
                    &mut f.store,
                    &f.owner,
                    codec::Record::Delete {
                        at: at("f"),
                        kind: codec::DeleteKind::File { stage_id: None },
                    },
                )
                .unwrap();
        }
        "renamed name changed" => {
            proof.entries = vec![file("f", b"head")];
            f.overlay
                .namespace_record(
                    &mut f.store,
                    &f.owner,
                    codec::Record::Move {
                        from: at("f"),
                        to: at("moved"),
                    },
                )
                .unwrap();
        }
        _ => panic!("unknown suffix case {case}"),
    }
    let journal = f.io.bytes(&f.overlay.journal_path());
    let entries: Vec<_> = f.overlay.namespace.entries.values().cloned().collect();
    let stages: Vec<_> = f
        .overlay
        .namespace
        .stages
        .keys()
        .map(|id| (*id, f.io.bytes(&f.overlay.stage_path(*id))))
        .collect();
    let log = LogBytes::default();
    let guard = tracing::subscriber::set_default(observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let result = f.overlay.prepare_replacement(&mut f.store, &f.owner, proof);
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let conflicts: Vec<_> = text
        .lines()
        .filter(|line| line.contains("\"event\":\"op.conflict\""))
        .collect();
    assert_eq!(
        (
            conflicts.len(),
            conflicts
                .iter()
                .all(|line| line.contains("\"path\":\"<file>\""))
        ),
        (1, true),
        "{case}: {text}"
    );
    let actual = result.map_err(|error| {
        (
            error.to_string(),
            crate::sync::failure_class(&crate::CoordinationError::Overlay(error)),
        )
    });
    assert_eq!(
        actual.as_ref().err(),
        Some(&(
            "overlay namespace conflict".to_owned(),
            crate::observe::FailureClass::Conflict,
        )),
        "{case}: {actual:?}"
    );
    assert_eq!(
        (
            f.io.bytes(&f.overlay.journal_path()),
            f.overlay
                .namespace
                .entries
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            stages
                .iter()
                .map(|(id, _)| (*id, f.io.bytes(&f.overlay.stage_path(*id))))
                .collect::<Vec<_>>()
        ),
        (journal, entries, stages),
        "{case}: recovery evidence changed"
    );
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Ready);
}

#[test]
fn suffix_create_conflicts_with_a_head_gained_name() {
    suffix_collision("created name gained");
}
#[test]
fn suffix_copy_up_conflicts_with_a_head_modified_base() {
    suffix_collision("copy-up base changed");
}
#[test]
fn suffix_required_stage_conflicts_with_a_head_deleted_path() {
    suffix_collision("required stage deleted");
}
#[test]
fn net_zero_stage_with_suffix_conflicts_with_a_head_rewrite() {
    suffix_collision("net-zero stage rewritten");
}
#[test]
fn net_zero_stage_without_suffix_conflicts_with_a_head_deletion() {
    suffix_collision("net-zero stage retired");
}
#[test]
fn net_zero_stage_without_suffix_conflicts_with_a_head_kind_change() {
    suffix_collision("net-zero stage kind changed");
}
#[test]
fn suffix_delete_conflicts_with_a_head_modified_path() {
    suffix_collision("deleted name changed");
}
#[test]
fn suffix_rename_conflicts_with_a_head_modified_path() {
    suffix_collision("renamed name changed");
}

#[test]
fn name_disjoint_suffix_replays_over_a_head_gained_name() {
    let mut f = Fixture::new();
    let proof = f.boundary_proof();
    let mut proof = f.landing(proof);
    proof.entries.push(file("remote", b"head"));
    let stage = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("suffix"), false)
        .unwrap();
    f.write(stage, b"ack");
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    f.reopen().unwrap();
    assert_eq!(
        (
            f.overlay.namespace.entries.len(),
            f.overlay
                .read_stage(&mut f.store, &f.owner, stage, 0, 3)
                .unwrap()
        ),
        (2, b"ack".to_vec())
    );
}

fn path(p: &str) -> Vec<Name> {
    p.split('/').map(name).collect()
}

fn nested(p: &str, kind: OverlayKind) -> OverlayEntry {
    OverlayEntry {
        path: path(p),
        kind,
        ..file("unused", b"")
    }
}

fn content(bytes: &[u8]) -> OverlayKind {
    OverlayKind::File {
        content: Some(GrainId::of(bytes)),
    }
}

/// The view's overlay inode at each path.
fn view_inodes(f: &Fixture) -> BTreeMap<Vec<Name>, u64> {
    f.overlay
        .namespace
        .entries
        .values()
        .map(|entry| (entry.path.clone(), entry.inode))
        .collect()
}

/// A landing of the local work below, plus `head`'s edits to the landed tree.
fn landed_view_change(case: &str) -> (ViewChange, BTreeMap<Vec<Name>, u64>, Fixture) {
    let bytes: [&[u8]; 6] = [b"d0", b"r0", b"m0", b"x0", b"c0", b"f0"];
    let mut source = Source::default();
    for b in bytes {
        source.0.insert(GrainId::of(b), b.to_vec());
    }
    let mut f = Fixture::with_base(
        vec![
            file("dirty", b"d0"),
            file("renamed_from", b"r0"),
            file("modified", b"m0"),
            file("removed", b"x0"),
            nested("dir_to_file", OverlayKind::Directory),
            nested("dir_to_file/child", content(b"c0")),
            file("file_to_dir", b"f0"),
            nested("a", OverlayKind::Directory),
            nested("a/b", OverlayKind::Directory),
            nested("a/b/c", OverlayKind::Directory),
        ],
        source,
    );
    let dirty = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("dirty"), &mut f.source)
        .unwrap();
    // Case 3 writes the original bytes back: a net-zero stage.
    f.write(dirty, if case == "net zero" { b"d0" } else { b"d1" });
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            codec::Record::Move {
                from: at("renamed_from"),
                to: at("renamed_to"),
            },
        )
        .unwrap();
    let proof = f.boundary_proof();
    let mut proof = f.landing(proof);
    match case {
        "plain" => {}
        "rebased" => {
            proof
                .entries
                .retain(|e| ![path("removed"), path("dir_to_file/child")].contains(&e.path));
            for entry in &mut proof.entries {
                if entry.path == path("modified") {
                    entry.kind = content(b"m1");
                } else if entry.path == path("dir_to_file") {
                    entry.kind = content(b"t1");
                } else if entry.path == path("file_to_dir") {
                    entry.kind = OverlayKind::Directory;
                    entry.size = 0;
                }
            }
            proof
                .entries
                .push(nested("file_to_dir/new", content(b"n1")));
            proof.entries.push(nested("a/b/c/deep", content(b"e1")));
        }
        "net zero" => {
            for entry in &mut proof.entries {
                if entry.path == path("dirty") {
                    entry.kind = content(b"h1");
                }
            }
        }
        _ => panic!("unknown landing case {case}"),
    }
    let rebased = proof.entries != proof.captured_entries;
    assert_eq!(
        rebased,
        case != "plain",
        "{case}: premise, the landed tree differs from the capture: {rebased}"
    );
    let before = view_inodes(&f);
    let change = f
        .overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    (change, before, f)
}

#[test]
fn view_change_is_a_view_diff_not_a_base_diff() {
    let mut cases = 0;
    for (case, listed, retired) in [
        ("plain", vec![], vec![]),
        (
            "rebased",
            vec![
                ("a/b/c/deep", false, true),
                ("dir_to_file", true, true),
                ("file_to_dir", true, true),
                ("file_to_dir/new", false, true),
                ("modified", true, true),
                ("removed", true, false),
            ],
            vec![
                "dir_to_file",
                "dir_to_file/child",
                "file_to_dir",
                "modified",
                "removed",
            ],
        ),
        ("net zero", vec![("dirty", true, true)], vec!["dirty"]),
    ] {
        let (change, before, f) = landed_view_change(case);
        let after = view_inodes(&f);
        let kept = before
            .iter()
            .filter(|(p, _)| !change.paths.iter().any(|c| &c.path == *p))
            .filter(|(p, _)| after.contains_key(*p))
            .all(|(p, inode)| after[p] == *inode);
        let fresh = change
            .paths
            .iter()
            .filter_map(|c| c.new)
            .all(|inode| !before.values().any(|old| *old == inode));
        let mut expected_retired: Vec<_> = retired.iter().map(|p| before[&path(p)]).collect();
        expected_retired.sort_unstable();
        assert_eq!(
            (
                change
                    .paths
                    .iter()
                    .map(|c| (c.path.clone(), c.old.is_some(), c.new.is_some()))
                    .collect::<Vec<_>>(),
                change
                    .paths
                    .iter()
                    .all(|c| c.old == before.get(&c.path).copied()
                        && c.new == after.get(&c.path).copied()),
                change.retired.keys().copied().collect::<Vec<_>>(),
                kept,
                fresh,
            ),
            (
                listed
                    .iter()
                    .map(|(p, old, new)| (path(p), *old, *new))
                    .collect::<Vec<_>>(),
                true,
                expected_retired,
                true,
                true,
            ),
            "{case}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

/// A boundary over creates made out of path order, recorded and then reopened,
/// so the lane must be rebuilt from the journal.
fn reopened_out_of_order_creates(f: &mut Fixture, creates: &[(&str, &[u8])]) -> u64 {
    for (p, bytes) in creates {
        let stage = f
            .overlay
            .create_file(&mut f.store, &f.owner, at(p), false)
            .unwrap();
        f.write(stage, bytes);
    }
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let boundary = f
        .overlay
        .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
        .unwrap();
    f.reopen().unwrap();
    boundary
}

/// The same creates under a projected boundary: z selected, b at its synced
/// mark, so both stay in the projection after the reopen renumbers them.
fn reopened_out_of_order_projection(f: &mut Fixture) -> u64 {
    let z = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("z"), false)
        .unwrap();
    f.write(z, b"z");
    let b = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("b"), false)
        .unwrap();
    f.write(b, b"b");
    f.sync(b, 1);
    let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    let boundary = f
        .overlay
        .append(&codec::Record::ProjectedBoundary {
            candidate: grain(3),
            through_seq,
            publication_id: [7; 16],
            selection: Some(codec::ProjectedSelection {
                stage_id: z,
                content: grain(5),
                size: 1,
            }),
        })
        .unwrap();
    f.reopen().unwrap();
    boundary
}

#[test]
fn recovered_commit_entries_carry_the_views_stage_inodes() {
    for projected in [false, true] {
        let mut f = Fixture::with_base(vec![file("a", b"")], Source::default());
        let entries = if projected {
            let boundary = reopened_out_of_order_projection(&mut f);
            f.overlay
                .projected_commit_entries(boundary, [7; 16])
                .unwrap()
        } else {
            let boundary = reopened_out_of_order_creates(&mut f, &[("z", b"z"), ("b", b"b")]);
            f.overlay.commit_entries(boundary, [7; 16]).unwrap()
        };
        assert_staged_entries_carry_view_inodes(&f, &entries, projected);
    }
}
fn assert_staged_entries_carry_view_inodes(f: &Fixture, entries: &[OverlayEntry], projected: bool) {
    let view = view_inodes(f);
    let staged: Vec<_> = entries
        .iter()
        .filter(|e| e.stage_id.is_some())
        .map(|e| (e.path.clone(), e.inode))
        .collect();
    assert_eq!(
        (
            staged.clone(),
            entries
                .iter()
                .filter(|e| e.stage_id.is_none())
                .map(|e| e.inode)
                .collect::<Vec<_>>(),
        ),
        (
            staged
                .iter()
                .map(|(p, _)| (p.clone(), view[p]))
                .collect::<Vec<_>>(),
            vec![0],
        ),
        "projected={projected} view inodes {view:?}"
    );
    assert_eq!(staged.len(), 2, "projected={projected}");
}

#[test]
fn recovered_lane_does_not_keep_a_changed_files_inode() {
    let mut source = Source::default();
    source.0.insert(GrainId::of(b"A"), b"A".to_vec());
    let mut f = Fixture::with_base(vec![file("a", b"A")], source);
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            codec::Record::Delete {
                at: at("a"),
                kind: codec::DeleteKind::File { stage_id: None },
            },
        )
        .unwrap();
    let boundary = reopened_out_of_order_creates(&mut f, &[("z", b"D"), ("a", b"A")]);
    let mut captured = f.overlay.commit_entries(boundary, [7; 16]).unwrap();
    // The engine resolves staged kinds from the retained candidate.
    for entry in &mut captured {
        entry.stage_id = None;
        entry.kind = content(if entry.path == path("z") { b"D" } else { b"A" });
    }
    // The head rewrites z with a's bytes: a's captured entry has z's new kind.
    let mut entries = captured.clone();
    for entry in &mut entries {
        if entry.path == path("z") {
            entry.kind = content(b"A");
        }
    }
    let proof = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(3),
        landed_seq: 2,
        captured_entries: captured,
        entries,
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    f.refresh(&proof);
    let before = view_inodes(&f);
    let change = f
        .overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    let after = view_inodes(&f);
    assert_eq!(
        (
            change
                .paths
                .iter()
                .map(|c| (c.path.clone(), c.old, c.new))
                .collect::<Vec<_>>(),
            after[&path("a")] == before[&path("a")],
            before.values().all(|old| *old != after[&path("z")]),
        ),
        (
            vec![(path("z"), Some(before[&path("z")]), Some(after[&path("z")]))],
            true,
            true,
        ),
        "view inodes before {before:?}, after {after:?}"
    );
}

/// Held files under a directory renamed to a long name: the old journal names
/// each file by its short creation path, while the landed image re-binds every
/// held stage at the long path, so the replacement is larger than the journal
/// it replaced.
fn grown_replacement(cap: u64) -> (Fixture, Vec<u64>) {
    let mut f = Fixture::with_base_capped(vec![], Source::default(), cap);
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            codec::Record::Create {
                at: at("d"),
                kind: codec::CreateKind::Dir,
            },
        )
        .unwrap();
    let ids = (0..4)
        .map(|i| {
            let file = name(&format!("f{i}"));
            let loc = codec::Location {
                parent: codec::Parent::new(vec![name("d")]).unwrap(),
                name: file.clone(),
            };
            let id = f
                .overlay
                .create_file(&mut f.store, &f.owner, loc, false)
                .unwrap();
            f.write(id, format!("held {i}").as_bytes());
            f.overlay
                .open_stage(&mut f.store, &f.owner, &[name("d"), file])
                .unwrap();
            id
        })
        .collect();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            codec::Record::Move {
                from: at("d"),
                to: at(&"l".repeat(255)),
            },
        )
        .unwrap();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let old = f.io.bytes(&f.overlay.journal_path()).len();
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    let new = f.io.bytes(&f.overlay.journal_path()).len();
    assert!(new > old, "image {new} is not larger than journal {old}");
    (f, ids)
}

/// An admission that must refuse leaves the journal and every stage as they were.
fn refused_writes(f: &mut Fixture, id: u64) -> (Option<OverlayError>, Option<OverlayError>, bool) {
    let before = f.journal_and_stages();
    let namespace = f
        .overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            codec::Record::Create {
                at: at("x"),
                kind: codec::CreateKind::Dir,
            },
        )
        .err();
    let write = f
        .overlay
        .write(&mut f.store, &f.owner, id, 0, b"more")
        .err();
    (namespace, write, f.journal_and_stages() == before)
}

#[test]
fn reopen_above_the_cap_after_a_grown_replacement_serves_reads_and_refuses_writes() {
    // The install fits this cap; the grown image's steady-state reserve does not.
    let (mut f, ids) = grown_replacement(26_000);
    let installed = f.overlay.summary();
    let reopened = f.reopen().map_err(|e| e.to_string());
    let summary = f.overlay.summary();
    let read = f
        .overlay
        .read_stage(&mut f.store, &f.owner, ids[2], 0, 6)
        .map_err(|e| e.to_string());
    let (namespace, write, unchanged) = refused_writes(&mut f, ids[0]);
    assert_eq!(
        (
            installed.commit_requested,
            reopened,
            f.overlay.readiness(),
            summary.commit_requested,
            summary.charged_bytes + summary.reserved_bytes + summary.captured_bytes > 26_000,
            read,
            matches!(namespace, Some(OverlayError::NoSpace)),
            matches!(write, Some(OverlayError::NoSpace)),
            unchanged,
        ),
        (
            true,
            Ok(()),
            OverlayReadiness::Ready,
            true,
            true,
            Ok(b"held 2".to_vec()),
            true,
            true,
            true,
        ),
        "summary {summary:?}, namespace {namespace:?}, write {write:?}"
    );
}

#[test]
fn reopen_within_the_cap_after_a_grown_replacement_stays_writable() {
    let (mut f, ids) = grown_replacement(28_500);
    f.reopen().unwrap();
    let summary = f.overlay.summary();
    let (namespace, write, _) = refused_writes(&mut f, ids[0]);
    assert_eq!(
        (
            summary.commit_requested,
            namespace.is_none(),
            write.is_none()
        ),
        (false, true, true),
        "summary {summary:?}, namespace {namespace:?}, write {write:?}"
    );
}

/// What a statfs reads above the cap: zero room, totals over the cap and the
/// commit request.
fn above_cap_observation(f: &mut Fixture) -> Result<(u64, bool, bool), String> {
    let seen = f
        .overlay
        .observation(&f.store, &f.owner)
        .map_err(|e| e.to_string())?;
    let s = seen.summary;
    Ok((
        seen.free_entries,
        s.charged_bytes + s.reserved_bytes + s.captured_bytes > seen.cap,
        s.commit_requested,
    ))
}

#[test]
fn above_the_cap_observation_answers_and_recovery_logs_the_cap_and_commit_request() {
    let (mut f, _) = grown_replacement(26_000);
    let installed = above_cap_observation(&mut f);
    let log = LogBytes::default();
    let guard = tracing::subscriber::set_default(observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log.clone(),
    ));
    let reopened = f.reopen().map_err(|e| e.to_string());
    let observed = above_cap_observation(&mut f);
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let recovery: Vec<_> = text
        .lines()
        .filter(|line| line.contains("\"event\":\"overlay.recovery\""))
        .map(|line| {
            (
                line.contains("\"cap\":26000"),
                line.contains("\"commit_requested\":true"),
            )
        })
        .collect();
    assert_eq!(
        (installed, reopened, observed, recovery),
        (
            Ok((0, true, true)),
            Ok(()),
            Ok((0, true, true)),
            vec![(true, true)]
        ),
        "{text}"
    );
}

/// The reserve terms recomputed from the overlay's own state: 4577 re-bind
/// and 122 completion bytes per bound stage, 1732 per completion slot, the
/// ownership reserve, the writer record and the journal file.
fn expected_terms(f: &Fixture, owed: u64) -> observe::OverlayOwed {
    let slots = f.overlay.journal.lock().unwrap().completion.slots();
    observe::OverlayOwed {
        owed,
        stages: f.overlay.namespace.stages.len() as u64 * (4577 + 122),
        projected: 0,
        ownership: f.overlay.config.ownership_completion_reserve,
        completion: 1732 * slots,
        writer: f.overlay.writer.encode().unwrap().len() as u64,
        journal: f.io.bytes(&f.overlay.journal_path()).len() as u64,
    }
}

/// Each owed field as the recovery event writes it.
fn logged_terms(terms: &observe::OverlayOwed) -> Vec<String> {
    [
        ("owed", terms.owed),
        ("stage_reserve", terms.stages),
        ("projected_reserve", terms.projected),
        ("ownership_reserve", terms.ownership),
        ("completion_reserve", terms.completion),
        ("writer_reserve", terms.writer),
        ("journal_reserve", terms.journal),
    ]
    .iter()
    .map(|(key, value)| format!("\"{key}\":{value}"))
    .collect()
}

/// Reopens under a JSON log and returns the overlay.recovery lines.
fn reopen_logged(f: &mut Fixture) -> (Result<(), String>, Vec<String>) {
    let log = LogBytes::default();
    let guard = tracing::subscriber::set_default(observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log.clone(),
    ));
    let reopened = f.reopen().map_err(|e| e.to_string());
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let lines = text
        .lines()
        .filter(|line| line.contains("\"event\":\"overlay.recovery\""))
        .map(str::to_owned)
        .collect();
    (reopened, lines)
}

#[test]
fn above_the_cap_observation_and_recovery_report_what_is_owed_and_what_holds_it() {
    let (mut f, _) = grown_replacement(26_000);
    let (reopened, lines) = reopen_logged(&mut f);
    let seen = f
        .overlay
        .observation(&f.store, &f.owner)
        .map_err(|e| e.to_string());
    let s = f.overlay.summary();
    let expected = expected_terms(
        &f,
        (s.charged_bytes + s.reserved_bytes + s.captured_bytes).saturating_sub(26_000),
    );
    let logged: Vec<_> = lines
        .iter()
        .map(|line| logged_terms(&expected).iter().all(|t| line.contains(t)))
        .collect();
    assert_eq!(
        (
            reopened,
            seen.map(|o| o.summary.owed),
            expected.owed > 0,
            logged
        ),
        (Ok(()), Ok(expected), true, vec![true]),
        "{lines:?}"
    );
}

#[test]
fn within_the_cap_nothing_is_owed_and_the_terms_are_still_reported() {
    let (mut f, _) = grown_replacement(28_500);
    f.reopen().unwrap();
    let owed = f
        .overlay
        .observation(&f.store, &f.owner)
        .unwrap()
        .summary
        .owed;
    assert_eq!(
        (owed, owed.stages > 0),
        (expected_terms(&f, 0), true),
        "{owed:?}"
    );
}

#[test]
fn a_pending_recovery_above_the_cap_logs_what_is_owed_and_serves_no_reads() {
    let mut f = Fixture::new();
    let id = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("f"), false)
        .unwrap();
    f.write(id, b"in doubt");
    f.boundary_proof();
    let s = f.overlay.summary();
    f.overlay.config.cap = s.charged_bytes + s.reserved_bytes + s.captured_bytes - 1;
    let cap = f.overlay.config.cap;
    let (reopened, lines) = reopen_logged(&mut f);
    let s = f.overlay.summary();
    let expected = expected_terms(
        &f,
        (s.charged_bytes + s.reserved_bytes + s.captured_bytes).saturating_sub(cap),
    );
    let logged: Vec<_> = lines
        .iter()
        .map(|line| {
            line.contains("\"outcome\":\"pending\"")
                && logged_terms(&expected).iter().all(|t| line.contains(t))
        })
        .collect();
    assert_eq!(
        (
            reopened,
            f.overlay.readiness(),
            s.owed,
            expected.owed > 0,
            logged,
            f.overlay.entries(&mut f.store, &f.owner).is_err(),
        ),
        (
            Ok(()),
            OverlayReadiness::PendingRecovery,
            expected,
            true,
            vec![true],
            true,
        ),
        "{lines:?}"
    );
}

#[test]
fn a_landing_makes_a_commit_refused_above_the_cap_eligible_again() {
    let mut f = Fixture::new();
    let id = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("f"), false)
        .unwrap();
    f.write(id, b"landing");
    f.overlay.config.cap = 1;
    f.overlay.note_capacity_refusal();
    let refused = refusal_holds(&mut f);
    f.overlay.config.cap = 1_048_576;
    let wake = f.overlay.coalesce_wake.clone();
    let mut notified = std::pin::pin!(wake.notified());
    notified.as_mut().enable();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    let signalled = notified
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        .is_ready();
    assert_eq!(
        (refused, refusal_holds(&mut f), signalled),
        (true, false, true)
    );
}

#[test]
fn a_refusal_lapses_once_the_overlay_measures_within_the_cap() {
    let (mut f, _) = grown_replacement(26_000);
    f.overlay.note_capacity_refusal();
    let refused = refusal_holds(&mut f);
    f.overlay.config.cap = 1_048_576;
    let seen = f.overlay.observation(&f.store, &f.owner).map(|_| ());
    assert_eq!(
        (refused, seen.is_ok(), refusal_holds(&mut f)),
        (true, true, false)
    );
}

/// Whether a recorded refusal still holds a commit back, read through the
/// coalescer's own query with no backoff left.
fn refusal_holds(f: &mut Fixture) -> bool {
    use crate::SyncRuntime as _;
    f.overlay
        .capacity_retry_at(crate::TokioSyncRuntime.now(), std::time::Duration::ZERO)
        .is_some()
}

#[test]
fn a_pending_recovery_without_repair_content_measures_what_is_owed_from_its_files() {
    struct Missing;
    impl ContentSource for Missing {
        fn read_verified(&mut self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, OverlayError> {
            Err(OverlayError::ContentUnavailable)
        }
    }
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"synced");
    f.sync(id, 1);
    for name in ["g", "h", "i"] {
        let other = f
            .overlay
            .create_file(&mut f.store, &f.owner, at(name), false)
            .unwrap();
        f.write(other, b"dirty");
    }
    f.io.remove(&f.overlay.stage_path(id)).unwrap();
    f.source.0.clear();
    f.overlay.config.cap = 1_000;
    let log = LogBytes::default();
    let guard = tracing::subscriber::set_default(observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log.clone(),
    ));
    let recovered = f.overlay.recover(&mut f.store, &f.owner, &mut Missing);
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let owed = f.overlay.summary().owed;
    let journal = f.io.bytes(&f.overlay.journal_path()).len() as u64;
    let line: Vec<_> = text
        .lines()
        .filter(|line| line.contains("\"event\":\"overlay.recovery\""))
        .map(|line| {
            (
                line.contains("\"outcome\":\"pending\""),
                line.contains(&format!("\"owed\":{}", owed.owed)),
                line.contains(&format!("\"stage_reserve\":{}", 3 * (4577 + 122))),
                line.contains(&format!("\"journal_reserve\":{journal}")),
            )
        })
        .collect();
    assert_eq!(
        (
            matches!(recovered, Err(OverlayError::ContentUnavailable)),
            f.overlay.readiness(),
            owed.owed > 0,
            line,
        ),
        (
            true,
            OverlayReadiness::PendingRecovery,
            true,
            vec![(true, true, true, true)],
        ),
        "{owed:?} {text}"
    );
}

#[test]
fn a_released_sync_boundary_wakes_a_commit_refused_for_room() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"sealed");
    let boundary = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
        .unwrap();
    // Far above this cap: only the sealed boundary's release frees room.
    f.overlay.config.cap = 1;
    f.overlay.note_capacity_refusal();
    let refused = refusal_holds(&mut f);
    let wake = f.overlay.coalesce_wake.clone();
    let mut notified = std::pin::pin!(wake.notified());
    notified.as_mut().enable();
    f.overlay.release_sync_boundary(&boundary).unwrap();
    let signalled = notified
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        .is_ready();
    assert_eq!(
        (refused, signalled, refusal_holds(&mut f)),
        (true, true, false)
    );
}

/// A held stage synced at mark M1, then, when `edited`, rewritten before a
/// whole-tree landing, so the landing rebinds it at content other than M1's.
fn carried_marked(edited: bool) -> (Fixture, u64, LandedProof, SyncedMark) {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    let mark = f.overlay.namespace.stages[&id].mark.unwrap();
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    if edited {
        f.write(id, b"landed");
        // The rewrite reaches the disk, as the landing's own capture would
        // have flushed it, so a crash keeps it.
        let path = f.overlay.stage_path(id);
        let mut model = f.io.0.lock().unwrap();
        let file = model.names[&path];
        let (live, durable) = model.files.get_mut(&file).unwrap();
        durable.clone_from(live);
    }
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    (f, id, proof, mark)
}

/// The stage's header mark, decoded, and whether its raw mark block is zero.
fn header_mark(f: &mut Fixture, id: u64) -> (MarkState, bool) {
    let raw = f.io.bytes(&f.overlay.stage_path(id));
    (
        f.overlay.header(id).unwrap().mark,
        raw[68..149].iter().all(|byte| *byte == 0),
    )
}

/// A landing that rebinds a carried stage at other content drops the mark
/// the new journal does not record, in memory and in the stage's header,
/// so a reopen cannot fold it back. A mark naming the landed content stays.
#[test]
fn a_carried_stage_keeps_only_a_mark_that_names_its_landed_base() {
    let mut outcomes = Vec::new();
    for edited in [true, false] {
        let (mut f, id, proof, mark) = carried_marked(edited);
        let before = header_mark(&mut f, id);
        f.overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .unwrap();
        outcomes.push((
            edited,
            before == (MarkState::Present(mark), false),
            f.overlay.namespace.stages.get(&id).map(|stage| stage.mark),
            header_mark(&mut f, id) == (MarkState::Present(mark), false),
            header_mark(&mut f, id) == (MarkState::Absent, true),
        ));
    }
    let (_, _, _, mark) = carried_marked(false);
    assert_eq!(
        outcomes,
        [
            (true, true, Some(None), false, true),
            (false, true, Some(Some(mark)), true, false),
        ],
        "(edited, header held M1, stage mark after, header kept M1, header zeroed)"
    );
}

#[test]
fn a_carried_stage_keeps_an_older_mark_that_names_its_checkpoint() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"base");
    let proof = f.boundary_proof();
    f.write(id, b"sync");
    f.sync(id, 1);
    let path = f.overlay.stage_path(id);
    let before = f.io.read_at(&path, 0, codec::STAGING_HEADER_LEN).unwrap();
    let header = StagingHeader::decode(&before).unwrap();
    let MarkState::Present(mark) = header.mark else {
        panic!("expected the older header mark, got {:?}", header.mark);
    };
    f.sync(id, 2);
    f.io.write_at(&path, 0, &before).unwrap();
    f.io.sync(&path).unwrap();
    let proof = f.landing(proof);

    let faults = f.overlay.fault_control();
    faults.arm("overlay.carry.mark_clear", "before", 1, FaultAction::Block);
    // Let the seam record a hit without blocking or interrupting the switch.
    faults.resume();
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();

    let stage = f.overlay.namespace.stages.get(&id);
    assert_eq!(
        stage.map(|stage| (
            stage.base,
            stage.mark,
            stage.checkpoint(),
            stage.base == Some(mark.content),
        )),
        Some((
            Some(GrainId::of(b"base")),
            Some(SyncedMark {
                generation: 2,
                ..mark
            }),
            (Some(mark.content), mark.synced_size),
            false,
        )),
        "the carried checkpoint has a newer generation and differs from the landed base"
    );
    let after = f.io.read_at(&path, 0, codec::STAGING_HEADER_LEN).unwrap();
    assert_eq!(
        (faults.fired(), after == before),
        (vec![], true),
        "(mark-clear trace, header bytes unchanged)"
    );
}

/// A crash at the carried stage's mark clear, which precedes the journal
/// switch, reopens the old journal with M1 recorded; the landing installs
/// again and, with no handle held after the restart, retires the stage.
#[test]
fn a_crash_at_the_carried_mark_clear_reopens_the_old_journal_and_reinstalls() {
    let mut outcomes = Vec::new();
    for phase in ["before", "after-sync"] {
        let (mut f, id, proof, mark) = carried_marked(true);
        let faults = f.overlay.fault_control();
        faults.arm("overlay.carry.mark_clear", phase, 1, FaultAction::Crash);
        let crashed = f
            .overlay
            .replace_landed(&mut f.store, &f.owner, proof.clone())
            .is_err();
        f.io.crash();
        let bytes = f.io.bytes(&f.overlay.journal_path());
        let header = codec::scan_journal(&bytes).unwrap().header;
        let old = header.base_root != proof.landed_root;
        let base = if old {
            f.overlay.base.clone()
        } else {
            proof.entries.clone()
        };
        f.overlay = OverlayStore::open(
            &mut f.store,
            f.overlay.config.clone(),
            header,
            base,
            &f.owner,
            &mut f.source,
            f.io.clone(),
            FaultControl::default(),
        )
        .unwrap();
        let reopened = f.overlay.namespace.stages.get(&id).map(|stage| stage.mark);
        let reinstalled = f
            .overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .map(|_| ())
            .map_err(|error| error.to_string());
        outcomes.push((
            phase,
            crashed,
            old,
            reopened == Some(Some(mark)),
            reinstalled,
            f.overlay.namespace.stages.contains_key(&id),
        ));
    }
    assert_eq!(
        outcomes,
        [
            ("before", true, true, true, Ok(()), false),
            ("after-sync", true, true, true, Ok(()), false),
        ],
        "(phase, crashed, old journal, M1 reopened, reinstall, stage still named)"
    );
}
