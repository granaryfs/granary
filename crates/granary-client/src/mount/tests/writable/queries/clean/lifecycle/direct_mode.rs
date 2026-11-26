// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Catches a commit landing that can replace the base without first owning a
// lane, or a direct-mode backend path that moves the base by itself.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one direct mount exercises every view-check site and the retained-lane attach control"
)]
fn direct_mode_store_has_no_base_mover() {
    let paths = query_paths();
    let fixture = clean_tree(&paths, false);
    let cfg = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let start = ready
        .backend_for_test()
        .shared_mediator()
        .with(|local| {
            let pin = local.mount_pin().unwrap();
            Ok((
                (pin.base_id, pin.base_seq),
                local.mount_base()?,
                local.engine_attached(),
                local.sync_admission_open()?,
                local.sync_provenance_for_test().2,
            ))
        })
        .unwrap();
    assert_eq!(
        start,
        (start.1, start.1, false, true, false),
        "the direct mount must start pinned to its base with no engine or lane"
    );
    let base = start.1;
    let forged_entries = ready
        .backend_for_test()
        .shared_mediator()
        .overlay_transaction(query_fixture_entries)
        .unwrap();
    let forged = crate::LandedProof {
        boundary_seq: u64::MAX,
        landed_root: GrainId::of(b"forged landing without a lane"),
        landed_seq: u64::MAX,
        captured_entries: forged_entries.clone(),
        entries: forged_entries,
    };
    let forged_refusal = ready
        .backend_for_test()
        .shared_mediator()
        .with(|local| local.install_commit_base(u64::MAX, forged))
        .err();
    assert_eq!(
        refused_reason(forged_refusal),
        Some("SyncCommitContext"),
        "a forged landing proof without a lane must stop at lane admission"
    );

    let file = handler_path(b"f.txt");
    let other = handler_path(b"g.txt");
    let name = Name::new(b"f.txt".to_vec()).unwrap();
    let backend = ready.backend_for_test();
    let mut sites = Vec::new();
    sites.push((
        "overlay_path",
        backend
            .overlay_path(&file)
            .is_ok_and(|node| node.node.size == 196_608),
    ));
    sites.push((
        "overlay_lookup",
        backend
            .overlay_lookup(&[], &name)
            .is_ok_and(|node| node.node.path == file),
    ));
    let directory = backend.overlay_directory(&[]);
    sites.push((
        "overlay_directory",
        directory
            .as_ref()
            .is_ok_and(|dir| dir.directory.node.kind == NodeKind::Dir),
    ));
    sites.push((
        "overlay_children",
        directory
            .as_ref()
            .ok()
            .and_then(|dir| backend.overlay_children(&dir.cursor).ok())
            .is_some_and(|children| children.entries.len() == 2 && children.next.is_none()),
    ));
    sites.push((
        "overlay_nodes",
        backend.overlay_nodes().is_ok_and(|nodes| nodes.len() == 3),
    ));
    sites.push((
        "overlay_capacity",
        backend
            .overlay_capacity()
            .is_ok_and(|capacity| capacity.files == 3),
    ));
    sites.push((
        "overlay_readlink",
        backend.overlay_readlink(&file) == Err(WriteError::Invalid),
    ));
    let object = backend.overlay_open(&file).unwrap().unwrap();
    sites.push(("overlay_open", object > 0));
    sites.push((
        "overlay_object",
        backend
            .overlay_object(object)
            .is_ok_and(|node| node.path == file && node.size == 196_608),
    ));
    sites.push(("prepare_object", backend.prepare_object(object) == Ok(())));
    sites.push(("prepare_detach", backend.prepare_detach(&other) == Ok(())));
    let planning_attempts = backend.planning_attempts;
    let prepared = backend.prepare_overlay(&other);
    sites.push(("prepare_overlay", prepared == Ok(())));
    sites.push((
        "materialize",
        prepared == Ok(()) && backend.planning_attempts == planning_attempts + 1,
    ));
    sites.push((
        "overlay_setattr",
        backend
            .overlay_setattr(&other, None, Some(true))
            .is_ok_and(|node| node.node.exec),
    ));
    sites.push((
        "mutate",
        backend.overlay_mutate(M::BoundWrite {
            object,
            offset: 0,
            bytes: b"direct",
            append: false,
        }) == Ok(()),
    ));
    let after = backend
        .shared_mediator()
        .with(|local| {
            let pin = local.mount_pin().unwrap();
            Ok((
                (pin.base_id, pin.base_seq),
                local.mount_base()?,
                local.engine_attached(),
                local.sync_admission_open()?,
                local.sync_provenance_for_test().2,
            ))
        })
        .unwrap();
    assert_eq!(
        (
            sites.len(),
            sites.iter().all(|(_, answered)| *answered),
            after
        ),
        (15, true, (base, base, false, true, false)),
        "direct-site answers and unchanged pin and base: {sites:?}"
    );
    drop(ready);

    let paths = query_paths();
    let fixture = clean_tree(&paths, false);
    let cfg = input(&fixture.tree, &paths);
    let (ready, _, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let mediator = ready.backend_for_test().shared_mediator();
    let record = mediator
        .with(|local| {
            let root = local.snapshot().root.clone();
            let candidate = GrainId::of(&root);
            let publication = [8; 16];
            local.overlay_transaction(|overlay| {
                let boundary = overlay.capture_boundary()?;
                overlay.record_boundary(boundary, candidate, publication)?;
                Ok(())
            })?;
            let record = crate::overlay_store::tests::submission(
                local.snapshot().scope.clone(),
                local.writer_uuid(),
                root,
            );
            local.publication_transaction(|store| store.begin(&record))?;
            Ok(record)
        })
        .unwrap();
    assert_eq!(record.publication_id, [8; 16], "retained fixture identity");
    let attach = mediator
        .with(|local| {
            let before = (
                local.engine_attached(),
                local.sync_admission_open()?,
                local.sync_provenance_for_test().2,
            );
            local.attach_sync_engine()?;
            let after = (
                local.engine_attached(),
                local.sync_admission_open()?,
                local.sync_provenance_for_test().2,
            );
            Ok((before, after))
        })
        .unwrap();
    assert_eq!(
        attach,
        ((false, true, false), (true, false, true)),
        "attachment must set engine_attached in the same call that recovers the retained lane"
    );
}
