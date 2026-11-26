// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_fuse::{MountSyncError, MountSyncRequest, OverlayMutation};

#[test]
fn writable_daemon_attachment_starts_engine_before_serving() {
    let _ = crate::WritableAttachment::<crate::HttpStore, crate::OverlayDisk>::start_sync::<Time>;
    let paths = query_paths();
    let tree = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&tree.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &tree.tree, "sync_publish", &Events::default());
    let mut attachment = ready.unwrap().attach();
    let _runtime = attachment
        .start_sync(Arc::new(Time(state.clone())))
        .unwrap();
    let job = attachment
        .backend
        .prepare_sync(MountSyncRequest::Directory {
            path: vec![],
            datasync: false,
        });
    let admitted = job.as_ref().map(|_| ()).map_err(|error| *error);
    let attached = attachment
        .backend
        .shared_mediator()
        .with(|store| Ok(store.engine_attached()))
        .unwrap();
    assert_eq!(
        (attached, admitted),
        (true, Ok(())),
        "daemon must install its engine before any callback can serve"
    );
    let before = state.lock().unwrap().sends.len();
    let (sender, reply) = std::sync::mpsc::channel();
    job.unwrap().start(Box::new(move |result| {
        let _ = sender.send(result);
    }));
    let result = reply.recv_timeout(std::time::Duration::from_secs(3));
    assert_eq!(
        (result, state.lock().unwrap().sends.len() - before),
        (Ok(Ok(())), 1),
        "serving daemon runtime must drive the real waiter"
    );
}

#[test]
fn writable_daemon_attachment_names_engine_start_failure() {
    let paths = query_paths();
    let tree = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&tree.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &tree.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    ready
        .mediator_for_test()
        .phase_for_test(granary_core::overlay_ownership::Phase::Releasing)
        .unwrap();
    let mut attachment = ready.attach();
    let refusal = attachment
        .start_sync(Arc::new(Time(state)))
        .err()
        .map(|error| error.name());
    assert_eq!(
        refusal,
        Some("WritableSyncAttachFailed"),
        "invalid engine admission must fail at daemon startup"
    );
}

#[test]
fn pending_shrink_path_retry_refuses_recreated_object() {
    for recreate in [false, true] {
        let paths = query_paths();
        let tree = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&tree.tree, &paths);
        let (ready, state, _) = attempt(&cfg, &tree.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let _engine = attach_test_sync(&mut ready, &paths, &tree.tree, &state);
        let backend = ready.backend_for_test();
        let path = handler_path(b"f.txt");
        let object = backend.overlay_open(&path).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        backend
            .overlay_mutate(OverlayMutation::BoundWrite {
                object,
                offset: 0,
                bytes: b"original",
                append: false,
            })
            .unwrap();
        let mediator = backend.shared_mediator().clone();
        let boundary = mediator
            .overlay_transaction(|overlay| overlay.seal_sync(crate::SyncTarget::File(object)))
            .unwrap();
        let pending = backend.overlay_setattr(&path, Some(0), None);
        assert_eq!(
            pending.map(|_| ()),
            Err(WriteError::PendingShrink),
            "retained floor premise"
        );
        if recreate {
            backend
                .overlay_mutate(OverlayMutation::Remove {
                    path: &path,
                    directory: false,
                })
                .unwrap();
            backend
                .overlay_mutate(OverlayMutation::Create {
                    path: &path,
                    kind: granary_vfs::NodeKind::File,
                    exec: false,
                })
                .unwrap();
            backend
                .overlay_mutate(OverlayMutation::Write {
                    path: &path,
                    offset: 0,
                    bytes: b"replacement",
                    append: false,
                })
                .unwrap();
        }
        mediator
            .with(|store| store.release_sync_boundary(&boundary))
            .unwrap();
        let admission = backend
            .prepare_shrink_retry(granary_fuse::MountShrinkRequest {
                inode: object,
                object: None,
                path: path.clone(),
                size: 0,
                exec: None,
            })
            .map(|_| ());
        let expected = if recreate {
            Err(MountSyncError::Backend(granary_fuse::MountError::Stale))
        } else {
            Ok(())
        };
        assert_eq!(
            admission, expected,
            "retry admission must retain the original inode, recreate={recreate}"
        );
        backend.overlay_close(object).unwrap();
    }
}
