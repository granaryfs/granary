// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::overlay_store::tests::incremental::{Base, manifest_of};

#[expect(
    clippy::too_many_lines,
    reason = "one landing compares the frozen manifest, retained extents, fencing and durable recovery evidence"
)]
async fn stage_landing(case: &str, restart: bool) {
    let (head_content, suffix) = match case {
        "ordinary write with suffix" => (None, true),
        "changed with untouched head" | "unchanged with suffix" => (Some(b"old"), true),
        "rewritten with suffix" => (Some(b"new"), true),
        "deleted without suffix" | "directory without suffix" | "symlink without suffix" => {
            (None, false)
        }
        _ => panic!("unknown stage landing case {case}"),
    };
    let mut base = Base::new();
    base.file("f", b"old");
    let basis = super::super::super::incremental::basis_of(&mut base).await;
    let objects = basis.nodes.clone();
    let mut fixture = Fixture::over(basis).await.unwrap();
    let ordinary = case == "ordinary write with suffix";
    let prefix = if ordinary || case == "changed with untouched head" {
        b"new"
    } else {
        b"old"
    };
    let stage = {
        let mut local = fixture.store.lock().unwrap();
        for (id, bytes) in objects {
            local.put_immutable(id, &bytes).unwrap();
        }
        let grains = FileGrains::Inline(vec![manifest::GrainRef {
            id: GrainId::of(b"old"),
            unpacked_len: 3,
        }]);
        let payload = manifest::node::file_payload(3, &grains).unwrap();
        local
            .put_immutable(GrainId::of(&payload), &payload)
            .unwrap();
        fixture
            .content
            .remember_payload(GrainId::of(&payload), 3, &grains)
            .unwrap();
        local
            .overlay_transaction(|t| {
                let stage = t.copy_up(at("f"))?;
                t.write(stage, 0, prefix)?;
                Ok(stage)
            })
            .unwrap()
    };
    let mut lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let initial = root::decode_root(&load(&fixture).frozen.initial_root).unwrap();
    let mut captured = Base::new();
    captured.file("f", prefix);
    let captured_manifest = manifest_of(&mut captured.world, &captured.entries);
    assert_eq!(
        initial.manifest_root, captured_manifest,
        "{case}: captured prefix"
    );

    let mut head = Base::new();
    head.file("remote", b"");
    if let Some(bytes) = head_content {
        head.file("f", bytes);
    }
    if case == "directory without suffix" {
        head.dir("f");
    } else if case == "symlink without suffix" {
        head.entries.push(OverlayEntry {
            path: vec![name("f")],
            inode: 0,
            kind: OverlayKind::Symlink {
                target: manifest::SymlinkTarget::new(b"target".to_vec()).unwrap(),
            },
            stage_id: None,
            size: 0,
            exec: false,
        });
    }
    let head_manifest = manifest_of(&mut head.world, &head.entries);
    let expected_manifest = if case == "changed with untouched head" {
        let mut merged = Base::new();
        merged.file("f", prefix);
        merged.file("remote", b"");
        manifest_of(&mut merged.world, &merged.entries)
    } else if ordinary {
        captured_manifest
    } else {
        head_manifest
    };
    for (id, bytes) in &head.world.objects.0 {
        fixture.content.put_object(*id, bytes).unwrap();
    }
    let prepared = crate::prepare_from_manifest(
        fixture.remote.as_ref(),
        fixture.content.as_ref(),
        head_manifest,
        crate::HarvestStats::default(),
        &initial.volume,
        &SigningKey::from_seed(&[39; 32]).unwrap(),
        &granary_core::identity::WriterIdentity::from_bytes([77; 16]),
        initial.timestamp,
        crate::Policy::default(),
    )
    .await
    .unwrap();
    if !ordinary {
        fixture
            .remote
            .published
            .lock()
            .unwrap()
            .insert(2, prepared.root_bytes);
    }
    if suffix {
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.write(stage, 0, b"ack"))
            .unwrap();
    }
    if restart {
        // Persist the suffix without registering it in the sealed commit.
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                let token = t.capture(stage)?;
                t.flush_boundary(&token)?;
                t.complete_failed_capture(&token)
            })
            .unwrap();
        fixture = fixture.restart_over(base.entries.clone()).await;
        lane = fixture
            .engine
            .recover_commit(SyncOptions::default())
            .unwrap();
    }
    let stages = || {
        let model = fixture.io.0.lock().unwrap();
        model
            .names
            .iter()
            .filter(|(p, _)| {
                p.parent().and_then(std::path::Path::file_name)
                    == Some(std::ffi::OsStr::new("staging"))
            })
            .map(|(p, id)| (p.clone(), model.files.get(id).unwrap().0.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let before_stages = stages();
    let journal = fixture
        .io
        .0
        .lock()
        .unwrap()
        .names
        .keys()
        .find(|p| p.file_name() == Some(std::ffi::OsStr::new("journal")))
        .unwrap()
        .clone();
    let before_journal = fixture.io.bytes(&journal);
    let mut extents = (0, 0);
    granary_core::overlay_journal::scan_journal_with(&before_journal, |seq, record| {
        if matches!(record, Record::WriteExtent { stage_id, .. } if *stage_id == stage) {
            if seq < lane.boundary_seq() {
                extents.0 += 1;
            } else {
                extents.1 += 1;
            }
        }
    })
    .unwrap();
    assert_eq!(
        extents,
        (1, u32::from(suffix)),
        "{case}: pre/post-boundary extents"
    );
    if !ordinary {
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::StaleCurrent, PublishPlan::Land]);
    }
    let result = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    let landed_seq = if ordinary { 2 } else { 3 };
    if ordinary || case == "unchanged with suffix" || case == "changed with untouched head" {
        assert_eq!(
            result.map(|_| ()).map_err(|e| e.to_string()),
            Ok(()),
            "{case}: replay (restart={restart})"
        );
        let bytes = fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.read_stage(stage, 0, 3))
            .unwrap();
        assert_eq!(bytes, b"ack", "{case}: suffix replay");
    } else {
        let refusal = result.map(|_| ()).map_err(|error| {
            (
                matches!(error, CoordinationError::Fenced { .. }),
                crate::writable_start::sync_mount_error(&error),
            )
        });
        assert_eq!(
            refusal,
            Err((
                true,
                granary_fuse::MountSyncError::Backend(granary_fuse::MountError::Stale)
            )),
            "{case}: landing refusal"
        );
        let after_journal = fixture.io.bytes(&journal);
        let landed_root = GrainId::of(
            fixture
                .remote
                .published
                .lock()
                .unwrap()
                .get(&landed_seq)
                .unwrap(),
        );
        let mut landed = false;
        granary_core::overlay_journal::scan_journal_with(&after_journal, |_, record| {
            if matches!(record, Record::LandedCommit { landed_root: id, landed_seq: seq, .. } if *id == landed_root && *seq == landed_seq) { landed = true; }
        }).unwrap();
        assert_eq!(
            (after_journal.starts_with(&before_journal), stages(), landed),
            (true, before_stages, true),
            "{case}: recovery evidence"
        );
        let write = fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.write(stage, 0, b"later"));
        assert!(
            matches!(write, Err(CoordinationError::Fenced { .. })),
            "{case}: write after conflict: {write:?}"
        );
    }
    let landed = root::decode_root(
        fixture
            .remote
            .published
            .lock()
            .unwrap()
            .get(&landed_seq)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        landed.manifest_root, expected_manifest,
        "{case}: landed manifest"
    );
}

#[tokio::test]
async fn net_zero_stage_with_suffix_fences_on_a_head_rewrite() {
    stage_landing("rewritten with suffix", false).await;
}

#[tokio::test]
async fn net_zero_stage_with_suffix_replays_when_head_content_is_unchanged() {
    stage_landing("unchanged with suffix", false).await;
}

#[tokio::test]
async fn changed_file_with_suffix_replays_when_rebased_head_leaves_it_untouched() {
    stage_landing("changed with untouched head", false).await;
    stage_landing("changed with untouched head", true).await;
}

#[tokio::test]
async fn net_zero_stage_without_suffix_fences_on_a_head_deletion() {
    stage_landing("deleted without suffix", false).await;
}

#[tokio::test]
async fn ordinary_write_commit_write_again_replays_with_an_untouched_head() {
    stage_landing("ordinary write with suffix", false).await;
}

#[tokio::test]
async fn ordinary_write_commit_write_again_replays_after_restart() {
    stage_landing("ordinary write with suffix", true).await;
}

#[tokio::test]
async fn net_zero_stage_without_suffix_fences_on_a_head_directory() {
    stage_landing("directory without suffix", false).await;
}

#[tokio::test]
async fn net_zero_stage_without_suffix_fences_on_a_head_symlink() {
    stage_landing("symlink without suffix", false).await;
}
