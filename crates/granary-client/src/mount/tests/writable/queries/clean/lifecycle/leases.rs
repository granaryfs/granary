// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::SyncRuntime as _;
use crate::mount::tests::writable::start_job;
use granary_fuse::{MountSyncRequest, OverlayMutation};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one composed row retains its admission, event boundary, byte oracle and cleanup controls"
)]
fn sync_lease_survives_both_unlink_release_orders_and_recreation() {
    for (release_first, replace) in [(false, false), (true, false), (false, true), (true, true)] {
        let paths = query_paths();
        let fixture = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&fixture.tree, &paths);
        let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let _engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &authority);
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        let job = backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap();
        if release_first {
            backend.overlay_close(object).unwrap();
        }
        backend.prepare_detach(&file).unwrap();
        if replace {
            let source = handler_path(b"g.txt");
            backend.prepare_overlay(&source).unwrap();
            backend
                .overlay_mutate(OverlayMutation::Write {
                    path: &source,
                    offset: 0,
                    bytes: b"replacement",
                    append: false,
                })
                .unwrap();
            backend
                .overlay_mutate(OverlayMutation::Rename {
                    from: &source,
                    to: &file,
                    no_replace: false,
                })
                .unwrap();
        } else {
            backend
                .overlay_mutate(OverlayMutation::Remove {
                    path: &file,
                    directory: false,
                })
                .unwrap();
            backend
                .overlay_mutate(OverlayMutation::Create {
                    path: &file,
                    kind: granary_vfs::NodeKind::File,
                    exec: false,
                })
                .unwrap();
            backend
                .overlay_mutate(OverlayMutation::Write {
                    path: &file,
                    offset: 0,
                    bytes: b"replacement",
                    append: false,
                })
                .unwrap();
        }
        if !release_first {
            backend.overlay_close(object).unwrap();
        }
        let mediator = backend.shared_mediator().clone();
        let stage = mediator
            .with(|store| Ok(store.object_leases.get(&object).copied()))
            .unwrap();
        assert!(
            matches!(stage, Some((1, Some(_)))),
            "lease promotion after release_first={release_first}: {stage:?}"
        );
        let boundary = mediator
            .seal_lease_for_test(object)
            .map(|sealed| sealed.expect("a held lease seals its object"));
        assert!(
            boundary.is_ok(),
            "detached lease lost its seal target: {boundary:?}"
        );
        let boundary = boundary.unwrap();
        assert_eq!(
            (
                boundary.files().len(),
                boundary
                    .files()
                    .first()
                    .map(|file| (file.size(), file.entry().is_none()))
            ),
            (1, Some((1024, true))),
            "old job selected the recreated pathname"
        );
        mediator
            .with(|store| store.release_sync_boundary(&boundary))
            .unwrap();
        drop(job);
        let stage = stage.unwrap().1.unwrap();
        let after = mediator.overlay_transaction(|overlay| overlay.read_stage(stage, 0, 1));
        assert!(
            matches!(
                after,
                Err(crate::CoordinationError::Overlay(
                    crate::OverlayError::Refused("detached stage has no handle")
                ))
            ),
            "last job must release its only hold: {after:?}"
        );
    }
}

#[test]
fn sync_leases_already_staged_two_handles_release_each_hold_once() {
    for staged in [false, true] {
        let paths = query_paths();
        let fixture = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&fixture.tree, &paths);
        let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let _engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &authority);
        let backend = ready.backend_for_test();
        let counter = backend.sync_job_counter_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        assert_eq!(backend.overlay_open(&file), Ok(Some(object)));
        backend.prepare_object(object).unwrap();
        if staged {
            backend
                .overlay_mutate(OverlayMutation::BoundWrite {
                    object,
                    offset: 0,
                    bytes: b"changed",
                    append: false,
                })
                .unwrap();
        }
        let first = backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap();
        let second = backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: true,
            })
            .unwrap();
        backend.overlay_close(object).unwrap();
        backend.overlay_close(object).unwrap();
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "release scheduled an extra sync"
        );
        backend
            .overlay_mutate(OverlayMutation::Remove {
                path: &file,
                directory: false,
            })
            .unwrap();
        let mediator = backend.shared_mediator().clone();
        let stage = mediator
            .with(|store| Ok(store.object_leases.get(&object).unwrap().1.unwrap()))
            .unwrap();
        let expected = if staged {
            b"changed".to_vec()
        } else {
            fixture.bytes[..7].to_vec()
        };
        let read = || mediator.overlay_transaction(|overlay| overlay.read_stage(stage, 0, 7));
        assert_eq!(
            read().map_err(|error| error.to_string()),
            Ok(expected.clone())
        );
        drop(first);
        assert_eq!(
            read().map_err(|error| error.to_string()),
            Ok(expected),
            "one job released another job's hold"
        );
        drop(second);
        let after = read();
        assert!(
            matches!(
                after,
                Err(crate::CoordinationError::Overlay(
                    crate::OverlayError::Refused("detached stage has no handle")
                ))
            ),
            "job hold leaked or last close consumed a job hold: {after:?}"
        );
        assert_eq!(
            mediator
                .with(|store| Ok(store.object_leases.len()))
                .unwrap(),
            0
        );
    }
}

struct ResumeOnDrop(crate::FaultControl);
impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        self.0.resume();
    }
}

async fn fired(faults: &crate::FaultControl, name: &str, phase: &str) {
    let deadline = crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(3);
    while faults.sync_fired().is_empty() && crate::TokioSyncRuntime.now() < deadline {
        tokio::task::yield_now().await;
    }
    let events = faults.sync_fired();
    if events.is_empty() {
        faults.resume();
    }
    assert_eq!(
        events
            .iter()
            .map(|event| (event.name, event.phase, event.occurrence))
            .collect::<Vec<_>>(),
        vec![(name, phase, 1)],
        "actual fault events: {events:?}"
    );
}

struct ObservedJobReply {
    engine_settled_at_delivery: bool,
    result: Result<(), granary_fuse::MountSyncError>,
}
impl ObservedJobReply {
    fn settlement(
        self,
        metrics: &crate::ClientMetrics,
        history: &Arc<Mutex<observed::CallbackHistory>>,
        pending_at_signal: bool,
        pending_after_interrupt_enosys: bool,
    ) -> observed::InterruptSettlement {
        let rendered = metrics.snapshot().unwrap().render_prometheus().unwrap();
        let engine_outcome = observed::sync_metric_counts(&rendered);
        let caller_errno = match self.result {
            Ok(()) => None,
            Err(granary_fuse::MountSyncError::Backend(_)) => Some(5),
            Err(other) => panic!("unexpected interrupt settlement error: {other:?}"),
        };
        observed::InterruptSettlement {
            pending_at_signal,
            pending_after_interrupt_enosys,
            caller_errno,
            engine_settled_at_caller_return: self.engine_settled_at_delivery,
            engine_outcome,
            terminal_outcomes: history.lock().unwrap().outcomes.clone(),
        }
    }
}

fn start_observed_job(
    job: Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError>,
    callback: granary_fuse::Callback,
    history: &Arc<Mutex<observed::CallbackHistory>>,
    metrics: &crate::ClientMetrics,
) -> tokio::sync::oneshot::Receiver<ObservedJobReply> {
    let history = history.clone();
    let metrics = metrics.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let completion: granary_fuse::SyncCompletion = Box::new(move |result| {
        let outcome = match &result {
            Ok(()) => granary_fuse::CallbackOutcome::Ok,
            Err(granary_fuse::MountSyncError::Backend(granary_fuse::MountError::Access)) => {
                granary_fuse::CallbackOutcome::Refused
            }
            Err(granary_fuse::MountSyncError::Backend(error)) => {
                granary_fuse::CallbackOutcome::Failed(*error)
            }
            Err(error) => panic!("unexpected observed job result: {error:?}"),
        };
        history.lock().unwrap().outcomes.push((callback, outcome));
        let settled = observed::at_caller_return(&metrics, || ()).0;
        let _ = sender.send(ObservedJobReply {
            engine_settled_at_delivery: settled,
            result,
        });
    });
    match job {
        Ok(job) => job.start(completion),
        Err(error) => completion(Err(error)),
    }
    receiver
}

#[test]
fn observed_job_samples_engine_at_reply_delivery() {
    struct Job {
        metrics: crate::ClientMetrics,
        early_reply: bool,
    }
    impl granary_fuse::MountSyncJob for Job {
        fn start(self: Box<Self>, completion: granary_fuse::SyncCompletion) {
            if !self.early_reply {
                self.metrics.record_sync(crate::observe::Outcome::Ok);
            }
            completion(Ok(()));
            if self.early_reply {
                self.metrics.record_sync(crate::observe::Outcome::Ok);
            }
        }
    }
    let mut cases = 0;
    for early_reply in [false, true] {
        let metrics = crate::ClientMetrics::new(&mut Entropy(35));
        metrics.set_available(crate::MetricsGroup::Sync, true);
        let history = Arc::new(Mutex::new(observed::CallbackHistory::default()));
        let mut reply = start_observed_job(
            Ok(Box::new(Job {
                metrics: metrics.clone(),
                early_reply,
            })),
            granary_fuse::Callback::Fsync,
            &history,
            &metrics,
        );
        let sample = reply
            .try_recv()
            .unwrap()
            .settlement(&metrics, &history, true, true);
        assert_eq!(
            (
                sample.engine_settled_at_caller_return,
                sample.engine_outcome,
                observed::check_interrupt_settlement(&sample, true)
            ),
            (
                !early_reply,
                (1, 0),
                if early_reply {
                    Err("interrupt acknowledged original sync request before engine settlement")
                } else {
                    Ok(())
                },
            ),
            "reply delivery sample: {sample:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

fn while_sync_paused<T: Send + std::fmt::Debug>(
    faults: &crate::FaultControl,
    action: impl FnOnce() -> T + Send,
) -> T {
    let answer = std::thread::scope(|scope| {
        let (send, receive) = std::sync::mpsc::channel();
        let worker = scope.spawn(move || send.send(action()).unwrap());
        let result = receive.recv_timeout(std::time::Duration::from_secs(3));
        if result.is_err() {
            faults.resume();
        }
        worker.join().unwrap();
        result
    });
    assert!(
        answer.is_ok(),
        "operation blocked after capture: {answer:?}"
    );
    answer.unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one composed row retains its admission, event boundary, byte oracle and cleanup controls"
)]
fn sync_job_waits_for_waiter_includes_preseal_write_and_preserves_postseal_write() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            remote,
            content.clone(),
            Arc::new(Time(authority.clone())),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(35)),
            Entropy(36),
        ))
        .unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let other = handler_path(b"g.txt");
    let object = backend.overlay_open(&file).unwrap().unwrap();
    backend.prepare_object(object).unwrap();
    backend.prepare_overlay(&other).unwrap();
    backend
        .overlay_mutate(OverlayMutation::Write {
            path: &other,
            offset: 0,
            bytes: b"unsynced",
            append: false,
        })
        .unwrap();
    let job = backend
        .prepare_sync(MountSyncRequest::File {
            object,
            datasync: true,
        })
        .unwrap();
    backend
        .overlay_mutate(OverlayMutation::BoundWrite {
            object,
            offset: 0,
            bytes: b"before",
            append: false,
        })
        .unwrap();
    let mediator = backend.shared_mediator().clone();
    let faults = mediator.with(|store| Ok(store.fault_control())).unwrap();
    faults.arm("sync.capture", "after", 1, crate::FaultAction::Block);
    let _resume = ResumeOnDrop(faults.clone());
    let mut reply = start_job(job);
    runtime.block_on(fired(&faults, "sync.capture", "after"));
    let pending = reply.try_recv();
    assert!(
        matches!(
            pending,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "reply before engine waiter: {pending:?}"
    );
    let write = while_sync_paused(&faults, || {
        backend.prepare_object(object).and_then(|()| {
            backend.overlay_mutate(OverlayMutation::BoundWrite {
                object,
                offset: 0,
                bytes: b"after!",
                append: false,
            })
        })
    });
    assert_eq!(write, Ok(()), "prepared write failed after capture");
    assert_eq!(
        backend.read_object(object, 0, 6),
        Ok(b"after!".to_vec()),
        "write must finish while sync is held"
    );
    faults.resume();
    assert_eq!(runtime.block_on(reply).unwrap(), Ok(()));
    let mut expected = fixture.bytes.clone();
    expected[..6].copy_from_slice(b"before");
    let first = prepared_bytes(
        &authority,
        &*content,
        &fixture.tree.volume,
        b"f.txt",
        &runtime,
    );
    let other = prepared_bytes(
        &authority,
        &*content,
        &fixture.tree.volume,
        b"g.txt",
        &runtime,
    );
    assert_eq!(
        (
            (first.len(), GrainId::of(&first)),
            (other.len(), GrainId::of(&other))
        ),
        (
            (expected.len(), GrainId::of(&expected)),
            (fixture.bytes.len(), GrainId::of(&fixture.bytes))
        ),
        "seal selected wrong bytes or a global tree"
    );
    assert_eq!(
        mediator
            .with(|store| Ok(store.object_leases.len()))
            .unwrap(),
        0
    );
    let reply = start_job(
        backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap(),
    );
    assert_eq!(runtime.block_on(reply).unwrap(), Ok(()));
    let mut expected = fixture.bytes.clone();
    expected[..6].copy_from_slice(b"after!");
    assert_eq!(
        prepared_bytes(
            &authority,
            &*content,
            &fixture.tree.volume,
            b"f.txt",
            &runtime
        ),
        expected
    );
    let directory = start_job(
        backend
            .prepare_sync(MountSyncRequest::Directory {
                path: vec![],
                datasync: false,
            })
            .unwrap(),
    );
    assert_eq!(runtime.block_on(directory).unwrap(), Ok(()));
    let other = prepared_bytes(
        &authority,
        &*content,
        &fixture.tree.volume,
        b"g.txt",
        &runtime,
    );
    assert_eq!(
        (other.len(), GrainId::of(&other)),
        (fixture.bytes.len(), GrainId::of(&fixture.bytes)),
        "directory sync admitted unsynced neighbour contents"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
fn sync_job_detached_after_admission_keeps_old_object() {
    for release_first in [false, true] {
        let paths = query_paths();
        let fixture = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&fixture.tree, &paths);
        let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
        let content = Arc::new(
            ready
                .backend_for_test()
                .sync_content(remote.clone())
                .unwrap(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _engine = runtime
            .block_on(ready.backend_for_test().attach_sync(
                remote,
                content.clone(),
                Arc::new(Time(authority.clone())),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(35)),
                Entropy(36),
            ))
            .unwrap();
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        let job = backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap();
        if release_first {
            backend.overlay_close(object).unwrap();
        }
        backend.prepare_detach(&file).unwrap();
        backend
            .overlay_mutate(OverlayMutation::Remove {
                path: &file,
                directory: false,
            })
            .unwrap();
        if !release_first {
            backend.overlay_close(object).unwrap();
        }
        backend
            .overlay_mutate(OverlayMutation::Create {
                path: &file,
                kind: granary_vfs::NodeKind::File,
                exec: false,
            })
            .unwrap();
        backend
            .overlay_mutate(OverlayMutation::Write {
                path: &file,
                offset: 0,
                bytes: b"replacement",
                append: false,
            })
            .unwrap();
        let before = authority.lock().unwrap().sends.len();
        let reply = start_job(job);
        let result = runtime.block_on(reply).unwrap();
        assert_eq!(
            (result, authority.lock().unwrap().sends.len() - before),
            (Ok(()), 1),
            "admitted clean job failed to resolve its detached stage, release_first={release_first}"
        );
        let entries = prepared_entries(&authority, &*content, &fixture.tree.volume);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_bytes())
                .collect::<Vec<_>>(),
            vec![b"g.txt".as_slice()],
            "old job synced the recreated path"
        );
        assert_eq!(
            backend
                .shared_mediator()
                .with(|store| Ok(store.object_leases.len()))
                .unwrap(),
            0
        );
    }
}

#[test]
fn sync_job_failure_releases_hold_and_never_acknowledges() {
    for (name, phase, registrations) in [
        ("sync.capture", "after", 0),
        ("fuse.sync.reply", "before", 1),
    ] {
        let paths = query_paths();
        let fixture = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&fixture.tree, &paths);
        let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
        let content = Arc::new(
            ready
                .backend_for_test()
                .sync_content(remote.clone())
                .unwrap(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _engine = runtime
            .block_on(ready.backend_for_test().attach_sync(
                remote,
                content,
                Arc::new(Time(authority.clone())),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(35)),
                Entropy(36),
            ))
            .unwrap();
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        backend
            .overlay_mutate(OverlayMutation::BoundWrite {
                object,
                offset: 0,
                bytes: b"dirty",
                append: false,
            })
            .unwrap();
        let stage = backend.overlay_object(object).unwrap().stage.unwrap();
        backend
            .overlay_mutate(OverlayMutation::Remove {
                path: &file,
                directory: false,
            })
            .unwrap();
        let job = backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap();
        backend.overlay_close(object).unwrap();
        let mediator = backend.shared_mediator().clone();
        let faults = mediator.with(|store| Ok(store.fault_control())).unwrap();
        faults.arm(name, phase, 1, crate::FaultAction::Fail);
        let before = authority.lock().unwrap().sends.len();
        let result = runtime.block_on(start_job(job)).unwrap();
        assert_eq!(
            faults
                .sync_fired()
                .iter()
                .map(|event| (event.name, event.phase, event.occurrence))
                .collect::<Vec<_>>(),
            vec![(name, phase, 1)],
            "failure must come from the selected seam"
        );
        let read = mediator.overlay_transaction(|overlay| overlay.read_stage(stage, 0, 1));
        assert_eq!(
            (
                result,
                authority.lock().unwrap().sends.len() - before,
                mediator
                    .with(|store| Ok(store.object_leases.len()))
                    .unwrap()
            ),
            (
                Err(granary_fuse::MountSyncError::Backend(
                    granary_fuse::MountError::Io
                )),
                registrations,
                0
            )
        );
        assert!(
            matches!(
                read,
                Err(crate::CoordinationError::Overlay(
                    crate::OverlayError::Refused("detached stage has no handle")
                ))
            ),
            "failed job leaked its stage hold: {read:?}"
        );
    }
}

#[test]
fn sync_lease_seal_refuses_base_change_inside_guarded_acquisition() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &authority);
    let file = handler_path(b"f.txt");
    let backend = ready.backend_for_test();
    let object = backend.overlay_open(&file).unwrap().unwrap();
    let job = backend
        .prepare_sync(MountSyncRequest::File {
            object,
            datasync: false,
        })
        .unwrap();
    let mediator = backend.shared_mediator().clone();
    drive_real_landing(&engine, &mediator, &fixture.tree);
    let seal = mediator
        .seal_lease_for_test(object)
        .map(|sealed| sealed.map(|boundary| boundary.id()));
    assert!(
        matches!(seal, Err(crate::CoordinationError::Refused("ViewPending"))),
        "base changed between admission and seal: {seal:?}"
    );
    drop(job);
    assert_eq!(
        mediator
            .with(|store| Ok(store.object_leases.len()))
            .unwrap(),
        0
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "a captured engine sync and floor retry retain their event boundaries and cleanup in one fixture"
)]
fn pending_shrink_retries_after_floor_without_holding_adapter_or_restarting_bound() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            remote,
            content,
            Arc::new(Time(authority.clone())),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(35)),
            Entropy(36),
        ))
        .unwrap();
    let backend = ready.backend_for_test();
    let file = handler_path(b"f.txt");
    let object = backend.overlay_open(&file).unwrap().unwrap();
    backend.prepare_object(object).unwrap();
    backend
        .overlay_mutate(OverlayMutation::BoundWrite {
            object,
            offset: 0,
            bytes: b"dirty",
            append: false,
        })
        .unwrap();
    let mediator = backend.shared_mediator().clone();
    let faults = mediator.with(|store| Ok(store.fault_control())).unwrap();
    faults.arm("sync.capture", "after", 1, crate::FaultAction::Block);
    let _resume = ResumeOnDrop(faults.clone());
    let sync = start_job(
        backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap(),
    );
    runtime.block_on(fired(&faults, "sync.capture", "after"));
    let pending = while_sync_paused(&faults, || {
        backend.prepare_object(object).unwrap();
        backend.overlay_mutate(OverlayMutation::BoundSetattr {
            object,
            size: Some(0),
            exec: Some(true),
        })
    });
    assert_eq!(
        pending,
        Err(WriteError::PendingShrink),
        "retained floor must reach the adapter as pending"
    );
    // Re-arming leaves capture blocked until resume; both waits must be reached.
    faults.arm("sync.floor", "checked", 1, crate::FaultAction::Block);
    let retry = backend
        .prepare_shrink_retry(granary_fuse::MountShrinkRequest {
            inode: object,
            object: Some(object),
            path: file,
            size: 0,
            exec: Some(true),
        })
        .unwrap();
    let mut reply = start_job(retry);
    runtime.block_on(fired(&faults, "sync.floor", "checked"));
    let pending = reply.try_recv();
    assert!(
        matches!(
            pending,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "shrink replied before the captured floor was released: {pending:?}"
    );
    while_sync_paused(&faults, || {
        let other = handler_path(b"g.txt");
        backend.prepare_overlay(&other).unwrap();
        backend.overlay_mutate(OverlayMutation::Write {
            path: &other,
            offset: 0,
            bytes: b"free",
            append: false,
        })
    })
    .unwrap();
    faults.resume();
    assert_eq!(runtime.block_on(sync).unwrap(), Ok(()));
    assert_eq!(runtime.block_on(reply).unwrap(), Ok(()));
    let node = backend.overlay_object(object).unwrap();
    assert_eq!(
        (
            node.size,
            node.exec,
            mediator
                .with(|store| Ok(store.object_leases.len()))
                .unwrap()
        ),
        (0, true, 0)
    );
    backend.overlay_close(object).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one composed row retains its admission, event boundary, byte oracle and cleanup controls"
)]
fn rename_directory_fault_has_exact_cursor_identity_and_disarmed_control() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            remote,
            content.clone(),
            Arc::new(Time(authority.clone())),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(35)),
            Entropy(36),
        ))
        .unwrap();
    let backend = ready.backend_for_test();
    let from = handler_path(b"f.txt");
    let to = handler_path(b"g.txt");
    let object = backend.overlay_open(&from).unwrap().unwrap();
    backend.prepare_object(object).unwrap();
    assert_eq!(
        runtime
            .block_on(start_job(
                backend
                    .prepare_sync(MountSyncRequest::File {
                        object,
                        datasync: false
                    })
                    .unwrap()
            ))
            .unwrap(),
        Ok(())
    );
    backend.overlay_close(object).unwrap();
    let before = authority.lock().unwrap().sends.len();
    backend
        .overlay_mutate(OverlayMutation::Rename {
            from: &from,
            to: &to,
            no_replace: false,
        })
        .unwrap();
    assert_eq!(
        authority.lock().unwrap().sends.len(),
        before,
        "rename registered before directory sync"
    );
    let mediator = backend.shared_mediator().clone();
    let cursor = mediator
        .overlay_transaction(|overlay| overlay.journal_cursor())
        .unwrap();
    let faults = mediator.with(|store| Ok(store.fault_control())).unwrap();
    faults.arm(
        "fuse.sync.rename_directory",
        "before",
        1,
        crate::FaultAction::Fail,
    );
    let failed = runtime
        .block_on(start_job(
            backend
                .prepare_sync(MountSyncRequest::Directory {
                    path: vec![],
                    datasync: false,
                })
                .unwrap(),
        ))
        .unwrap();
    let events = faults.sync_fired();
    assert_eq!(
        (
            failed,
            events
                .iter()
                .map(|event| (
                    event.name,
                    event.phase,
                    event.occurrence,
                    event.capture,
                    event.request,
                    event.object_kind,
                    event.rename_directory
                ))
                .collect::<Vec<_>>(),
            authority.lock().unwrap().sends.len() - before
        ),
        (
            Err(granary_fuse::MountSyncError::Backend(
                granary_fuse::MountError::Io
            )),
            vec![(
                "fuse.sync.rename_directory",
                "before",
                1,
                0,
                None,
                "directory",
                Some(crate::RenameDirectoryFaultContext {
                    journal_cursor: cursor,
                    directory_inode: None
                })
            )],
            0
        )
    );
    faults.trace_sync();
    let passed = runtime
        .block_on(start_job(
            backend
                .prepare_sync(MountSyncRequest::Directory {
                    path: vec![],
                    datasync: true,
                })
                .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        (passed, authority.lock().unwrap().sends.len() - before),
        (Ok(()), 1)
    );
    assert_eq!(
        prepared_bytes(
            &authority,
            &*content,
            &fixture.tree.volume,
            b"g.txt",
            &runtime
        ),
        fixture.bytes
    );
}

#[test]
fn sync_job_admission_deadline_survives_delayed_start() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let shifted = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let scheduler = Arc::new(super::content_runtime::OffsetRuntime(shifted.clone()));
    let _engine = runtime
        .block_on(ready.backend_for_test().attach_sync_with_runtime(
            remote,
            content,
            Arc::new(Time(authority.clone())),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(35)),
            scheduler,
            Entropy(36),
        ))
        .unwrap();
    let backend = ready.backend_for_test();
    let object = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    backend.prepare_object(object).unwrap();
    let job = backend
        .prepare_sync(MountSyncRequest::File {
            object,
            datasync: false,
        })
        .unwrap();
    let before = authority.lock().unwrap().sends.len();
    shifted.store(false, std::sync::atomic::Ordering::SeqCst);
    let result = runtime.block_on(start_job(job)).unwrap();
    assert_eq!(
        (
            result,
            authority.lock().unwrap().sends.len() - before,
            backend
                .shared_mediator()
                .with(|store| Ok(store.object_leases.len()))
                .unwrap()
        ),
        (
            Err(granary_fuse::MountSyncError::Backend(
                granary_fuse::MountError::Unavailable
            )),
            0,
            0
        ),
        "starting a queued job restarted its admission deadline"
    );
    backend.overlay_close(object).unwrap();
}

#[test]
fn sync_lease_cancellation_releases_hold_without_custody_io() {
    for poison in [false, true] {
        let paths = query_paths();
        let fixture = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&fixture.tree, &paths);
        let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let _engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &authority);
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        backend
            .overlay_mutate(OverlayMutation::BoundWrite {
                object,
                offset: 0,
                bytes: b"held",
                append: false,
            })
            .unwrap();
        let stage_id = backend.overlay_object(object).unwrap().stage.unwrap();
        let job = backend
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap();
        backend
            .overlay_mutate(OverlayMutation::Remove {
                path: &file,
                directory: false,
            })
            .unwrap();
        backend.overlay_close(object).unwrap();
        let mediator = backend.shared_mediator().clone();
        let retired = paths.store.with_extension("retired");
        std::fs::rename(&paths.store, &retired).unwrap();
        let unavailable =
            mediator.overlay_transaction(|overlay| overlay.read_stage(stage_id, 0, 1));
        let floors = mediator
            .with(|store| Ok(store.floor_changed.clone()))
            .unwrap();
        let mut wake = std::pin::pin!(floors.notified());
        wake.as_mut().enable();
        if poison {
            let shared = mediator.as_arc();
            let injected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = shared.lock().unwrap();
                panic!("injected mediator poison");
            }));
            assert!(injected.is_err());
        }
        drop(job);
        std::fs::rename(&retired, &paths.store).unwrap();
        assert!(
            unavailable.is_err(),
            "missing custody root premise: {unavailable:?}"
        );
        if poison {
            let admission = mediator.check_readiness();
            assert!(
                matches!(
                    admission,
                    Err(crate::CoordinationError::Refused("SyncMediatorPoisoned"))
                ),
                "cleanup reopened a poisoned mediator: {admission:?}"
            );
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            let signalled = std::future::Future::poll(wake.as_mut(), &mut context);
            assert!(
                signalled.is_ready(),
                "poisoned admission did not wake floor listeners: {signalled:?}"
            );
        }
        let after = if poison {
            let shared = mediator.as_arc();
            let mut owner = shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            owner.overlay_transaction(|overlay| overlay.read_stage(stage_id, 0, 1))
        } else {
            mediator.overlay_transaction(|overlay| overlay.read_stage(stage_id, 0, 1))
        };
        assert!(
            matches!(
                after,
                Err(crate::CoordinationError::Overlay(
                    crate::OverlayError::Refused("detached stage has no handle")
                ))
            ),
            "cancelled job retained its hold after custody returned: {after:?}"
        );
    }
}

#[test]
fn sync_lease_counter_exhaustion_refuses_admission_without_a_hold_or_job() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let _engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &authority);
    let backend = ready.backend_for_test();
    let calls = backend.sync_job_counter_for_test();
    let object = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    let valid = backend
        .prepare_sync(MountSyncRequest::File {
            object,
            datasync: false,
        })
        .unwrap();
    drop(valid);
    let mediator = backend.shared_mediator().clone();
    assert_eq!(
        mediator
            .with(|store| Ok(store.object_leases.len()))
            .unwrap(),
        0
    );
    mediator
        .with(|store| {
            store.object_leases.insert(object, (u64::MAX, None));
            Ok(())
        })
        .unwrap();
    let refused = backend
        .prepare_sync(MountSyncRequest::File {
            object,
            datasync: false,
        })
        .err();
    let retained = mediator
        .with(|store| Ok(store.object_leases.get(&object).copied()))
        .unwrap();
    assert_eq!(
        (
            refused,
            retained,
            calls.load(std::sync::atomic::Ordering::Relaxed)
        ),
        (
            Some(granary_fuse::MountSyncError::Backend(
                granary_fuse::MountError::Io
            )),
            Some((u64::MAX, None)),
            1
        ),
        "exhausted admission must preserve the count and schedule no new job"
    );
    mediator
        .with(|store| {
            store.object_leases.remove(&object);
            Ok(())
        })
        .unwrap();
    backend.overlay_close(object).unwrap();
}

#[test]
fn prepared_bytes_cold_pinned_content_uses_deadline() {
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
    let content = ready.backend_for_test().sync_content(remote).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(
        prepared_bytes(
            &authority,
            &content,
            &fixture.tree.volume,
            b"f.txt",
            &runtime
        ),
        fixture.bytes
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one matrix row exercises all applicable sync-path fault points and blocked interrupt settlement"
)]
fn sync_fault_matrix_routes_and_blocked_interrupt_settlement() {
    for (seam, phase, fail_after) in [
        ("sync.registration", "before_dispatch", false),
        ("sync.registration", "before_dispatch", true),
        ("sync.reply", "before", false),
    ] {
        let paths = query_paths();
        let fixture = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&fixture.tree, &paths);
        let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
        let content = Arc::new(
            ready
                .backend_for_test()
                .sync_content(remote.clone())
                .unwrap(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let metrics = crate::ClientMetrics::new(&mut Entropy(35));
        let _engine = runtime
            .block_on(ready.backend_for_test().attach_sync(
                remote,
                content,
                Arc::new(Time(authority.clone())),
                Arc::new(crate::InstantClock::default()),
                metrics.clone(),
                Entropy(36),
            ))
            .unwrap();
        let backend = ready.backend_for_test();
        let file = handler_path(b"f.txt");
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        backend
            .overlay_mutate(OverlayMutation::BoundWrite {
                object,
                offset: 0,
                bytes: b"interrupt",
                append: false,
            })
            .unwrap();
        let mediator = backend.shared_mediator().clone();
        let faults = mediator.with(|store| Ok(store.fault_control())).unwrap();
        faults.arm(seam, phase, 1, crate::FaultAction::Block);
        let _resume = ResumeOnDrop(faults.clone());
        let history = Arc::new(Mutex::new(observed::CallbackHistory::default()));
        let request = MountSyncRequest::File {
            object,
            datasync: false,
        };
        let mut reply = start_observed_job(
            backend.prepare_sync(request.clone()),
            granary_fuse::Callback::Fsync,
            &history,
            &metrics,
        );
        runtime.block_on(fired(&faults, seam, phase));
        let early_reply = reply.try_recv().ok();
        let pending_at_signal =
            early_reply.is_none() && history.lock().unwrap().outcomes.is_empty();
        runtime.block_on(tokio::task::yield_now());
        let after_interrupt = reply.try_recv();
        let pending_after_interrupt_enosys = matches!(
            after_interrupt,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ) && history.lock().unwrap().outcomes.is_empty();
        if fail_after {
            faults.arm("sync.reply", "before", 1, crate::FaultAction::Fail);
        }
        faults.resume();
        let out = match early_reply {
            Some(out) => out,
            None => runtime.block_on(reply).unwrap(),
        };
        let settlement = out.settlement(
            &metrics,
            &history,
            pending_at_signal,
            pending_after_interrupt_enosys,
        );
        assert_eq!(
            observed::check_interrupt_settlement(&settlement, !fail_after),
            Ok(()),
            "seam=({seam}, {phase}), fail_after={fail_after}, settlement={settlement:?}"
        );
        backend.overlay_close(object).unwrap();
    }

    let mut executed = Vec::new();
    for route in &observed::SYNC_FAULT_MATRIX_ROUTES {
        let paths = query_paths();
        let fixture = clean_tree_with_geometry(&paths, 1, 1024);
        let cfg = input(&fixture.tree, &paths);
        let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        let remote = Arc::new(Authority::new(&fixture.tree, &authority).with_publication());
        let content = Arc::new(
            ready
                .backend_for_test()
                .sync_content(remote.clone())
                .unwrap(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let metrics = crate::ClientMetrics::new(&mut Entropy(35));
        let _engine = runtime
            .block_on(ready.backend_for_test().attach_sync_with_runtime(
                remote,
                content.clone(),
                Arc::new(Time(authority.clone())),
                Arc::new(crate::InstantClock::default()),
                metrics.clone(),
                Arc::new(FastWaitRuntime),
                Entropy(36),
            ))
            .unwrap();
        let backend = ready.backend_for_test();
        let pinned_base = backend.pinned_base_for_test();
        let mediator = backend.shared_mediator().clone();
        let faults = mediator.with(|store| Ok(store.fault_control())).unwrap();
        let file = handler_path(b"f.txt");
        let mut expected = fixture.bytes.clone();
        let object = backend.overlay_open(&file).unwrap().unwrap();
        backend.prepare_object(object).unwrap();
        let before = authority.lock().unwrap().sends.len();
        if route.directory {
            backend.overlay_close(object).unwrap();
            let to = handler_path(b"g.txt");
            backend
                .overlay_mutate(OverlayMutation::Rename {
                    from: &file,
                    to: &to,
                    no_replace: false,
                })
                .unwrap();
        } else {
            backend
                .overlay_mutate(OverlayMutation::BoundWrite {
                    object,
                    offset: 0,
                    bytes: b"fault-route",
                    append: false,
                })
                .unwrap();
            expected[..11].copy_from_slice(b"fault-route");
        }
        let request = if route.directory {
            MountSyncRequest::Directory {
                path: vec![],
                datasync: false,
            }
        } else {
            MountSyncRequest::File {
                object,
                datasync: false,
            }
        };
        let history = Arc::new(Mutex::new(observed::CallbackHistory::default()));
        let sync_result = if route.name == "sync.floor" {
            faults.arm("sync.capture", "after", 1, crate::FaultAction::Block);
            let _resume = ResumeOnDrop(faults.clone());
            let sync = start_observed_job(
                backend.prepare_sync(request.clone()),
                granary_fuse::Callback::Fsync,
                &history,
                &metrics,
            );
            runtime.block_on(fired(&faults, "sync.capture", "after"));
            assert_eq!(
                backend.overlay_mutate(OverlayMutation::BoundSetattr {
                    object,
                    size: Some(0),
                    exec: None,
                }),
                Err(WriteError::PendingShrink)
            );
            faults.arm(route.name, route.phase, 1, crate::FaultAction::Fail);
            let shrink = backend.prepare_shrink_retry(granary_fuse::MountShrinkRequest {
                inode: object,
                object: Some(object),
                path: file.clone(),
                size: 0,
                exec: None,
            });
            let result = runtime
                .block_on(start_observed_job(
                    shrink,
                    granary_fuse::Callback::Setattr,
                    &history,
                    &metrics,
                ))
                .unwrap();
            faults.resume();
            runtime.block_on(sync).unwrap().result.unwrap();
            result.result
        } else {
            faults.arm(route.name, route.phase, 1, crate::FaultAction::Fail);
            runtime
                .block_on(start_observed_job(
                    backend.prepare_sync(request.clone()),
                    if route.directory {
                        granary_fuse::Callback::Fsyncdir
                    } else {
                        granary_fuse::Callback::Fsync
                    },
                    &history,
                    &metrics,
                ))
                .unwrap()
                .result
        };
        let syscall_errno = sync_result.map_err(|error| {
            Some(match error {
                granary_fuse::MountSyncError::Backend(granary_fuse::MountError::Access) => 13,
                granary_fuse::MountSyncError::Backend(granary_fuse::MountError::NoSpace) => 28,
                _ => 5,
            })
        });
        let sends = authority.lock().unwrap().sends.len() - before;
        let marks = observed::file_synced_marks(&captured_records(&paths, &cfg).1);
        let rendered = metrics.snapshot().unwrap().render_prometheus().unwrap();
        let engine_outcome = observed::sync_metric_counts(&rendered);
        let (base_id, _) = mediator.with(|store| store.mount_base()).unwrap();
        let remote_seq = runtime
            .block_on(remote_handle(&fixture.tree.mem).max_seq(fixture.tree.volume.as_str()))
            .unwrap()
            .unwrap();
        let target_name: &[u8] = if route.directory && sends > 0 {
            b"g.txt"
        } else {
            b"f.txt"
        };
        let expected_bytes = if route.acknowledged.0 == 0 {
            fixture.bytes.as_slice()
        } else {
            expected.as_slice()
        };
        let prepared = prepared_bytes(
            &authority,
            &*content,
            &fixture.tree.volume,
            target_name,
            &runtime,
        );
        let terminal_outcomes = history.lock().unwrap().outcomes.clone();
        let sample = observed::SyncFaultSample {
            syscall_errno,
            engine_outcome,
            acknowledged: (sends, marks),
            prepared_bytes: prepared,
            published_head: (base_id, remote_seq),
            terminal_outcomes,
            fired: faults.sync_fired(),
        };
        assert_eq!(
            observed::check_sync_fault_route(route, &sample, expected_bytes, pinned_base),
            Ok(()),
            "route={route:?}; sample={sample:?}"
        );
        executed.push((route.name, route.phase));
        if !route.directory {
            let _ = backend.overlay_close(object);
        }
    }
    assert_eq!(
        observed::check_sync_fault_matrix_coverage(&executed),
        Ok(())
    );
}

#[test]
fn close_and_lease_release_wake_coalescer_without_inline_commit_and_attach_keeps_coalescer_idle() {
    use crate::{SyncOptions, SyncRuntime as _, writable_store::sync_engine::CoalesceState};
    use std::time::Duration;
    let paths = query_paths();
    let fixture = clean_tree_with_geometry(&paths, 1, 1024);
    let cfg = input(&fixture.tree, &paths);
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let _engine = attach_test_sync(&mut ready, &paths, &fixture.tree, &authority);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let backend = ready.backend_for_test();
    let mediator = backend.shared_mediator().clone();
    let initial_base = mediator.with(|store| store.mount_base()).unwrap();
    let sends_before = authority.lock().unwrap().sends.len();
    let file = handler_path(b"f.txt");
    let object = backend.overlay_open(&file).unwrap().unwrap();
    backend.prepare_object(object).unwrap();
    backend
        .overlay_mutate(OverlayMutation::BoundWrite {
            object,
            offset: 0,
            bytes: b"portable-coalesce",
            append: false,
        })
        .unwrap();
    let options = SyncOptions {
        quiesce_delay: Duration::from_millis(20),
        max_coalesce_delay: Duration::from_secs(5),
        ..SyncOptions::default()
    };
    let now_after_quiesce = crate::TokioSyncRuntime.now() + Duration::from_millis(50);
    let state = || {
        mediator
            .with(|store| store.coalesce_state(&options, now_after_quiesce))
            .unwrap()
    };
    let state_while_open = state();
    let wake = mediator
        .with(|store| Ok(store.coalesce_wake.clone()))
        .unwrap();
    let close_notified = wake.notified();
    tokio::pin!(close_notified);
    close_notified.as_mut().enable();
    // With no `ObjectLease` held, closing the last stage handle wakes the
    // coalescer directly from `release_stage_hold` without an inline commit.
    backend.overlay_close(object).unwrap();
    runtime.block_on(async {
        let deadline = crate::TokioSyncRuntime.now() + Duration::from_millis(50);
        crate::TokioSyncRuntime
            .timeout_at(deadline, close_notified)
            .await
            .expect("closing the last stage handle must wake the coalescer");
    });
    let state_after_close = state();
    let object = backend.overlay_open(&file).unwrap().unwrap();
    backend.prepare_object(object).unwrap();
    let job = backend
        .prepare_sync(MountSyncRequest::File {
            object,
            datasync: false,
        })
        .unwrap();
    // Closing the file handle neither commits inline nor starts a background
    // mount coalescer while sync is attached; while `job` holds its
    // `ObjectLease`, quiescence remains withheld.
    backend.overlay_close(object).unwrap();
    runtime.block_on(async {
        let sleep = crate::TokioSyncRuntime.sleep(Duration::from_millis(30));
        sleep.await;
    });
    let state_while_leased = state();
    let notified = wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    drop(job);
    // Dropping the last `ObjectLease` wakes the coalescer immediately without
    // performing an inline commit, and allows quiescence to fire after `quiesce_delay`.
    runtime.block_on(async {
        let deadline = crate::TokioSyncRuntime.now() + Duration::from_millis(50);
        crate::TokioSyncRuntime
            .timeout_at(deadline, notified)
            .await
            .expect("dropping the last ObjectLease must wake the coalescer");
    });
    let state_after_lease_release = state();
    let sends_after = authority.lock().unwrap().sends.len();
    let base_after = mediator.with(|store| store.mount_base()).unwrap();
    assert_eq!(
        (
            (
                matches!(state_while_open, CoalesceState::WaitUntil(_)),
                matches!(state_while_leased, CoalesceState::WaitUntil(_)),
            ),
            (state_after_close, state_after_lease_release),
            (sends_after - sends_before, base_after),
        ),
        (
            (true, true),
            (CoalesceState::Ready, CoalesceState::Ready),
            (0, initial_base),
        ),
        "close and lease release must wake the coalescer without inline or background mount commits"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "verifies fsync HTTP request-id correlation over a TLS recording stub, cold bin fetch, and failed-draw fallback together"
)]
fn fsync_job_sends_its_logged_correlation_id_on_every_http_request_and_falls_back_on_failed_draw() {
    use granary_net::pin::{SpkiPin, spki_digest};
    use granary_net::tls::{ClientAuth, server_tls_config};
    use http_body_util::{BodyExt as _, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::header::RANGE;
    use hyper::service::service_fn;
    use hyper::{HeaderMap, Method, Request, Response, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn decode_hex_32(raw: &str) -> [u8; 32] {
        let hex = raw.strip_prefix("blake3:").unwrap_or(raw);
        assert_eq!(hex.len(), 64, "expected 64-char hex: {raw}");
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    struct Sequence(std::collections::VecDeque<Option<u8>>);
    impl granary_core::secure_random::SecureRandom for Sequence {
        fn fill(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
            let byte = self
                .0
                .pop_front()
                .flatten()
                .ok_or(granary_core::secure_random::EntropyUnavailable)?;
            dest.fill(byte);
            Ok(())
        }
    }

    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 3, 65_536, true);
    let mem = Arc::clone(&fixture.tree.mem);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let seen: Arc<Mutex<Vec<(Method, String, HeaderMap)>>> = Arc::new(Mutex::new(Vec::new()));
    let (base_url, pin, _server_guard) = runtime.block_on(async {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let cert: CertificateDer<'static> = params.self_signed(&key).unwrap().der().clone();
        let pin: SpkiPin = spki_digest(&cert).unwrap();
        let pkcs8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut tls = server_tls_config(vec![cert], pkcs8, ClientAuth::None).unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let seen_accept = Arc::clone(&seen);
        let mem_accept = Arc::clone(&mem);
        let handle = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let seen_conn = Arc::clone(&seen_accept);
                let mem_conn = Arc::clone(&mem_accept);
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(sock).await else {
                        return;
                    };
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let seen_req = Arc::clone(&seen_conn);
                        let mem_req = Arc::clone(&mem_conn);
                        async move {
                            let method = req.method().clone();
                            let path = req.uri().path().to_owned();
                            let headers = req.headers().clone();
                            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                            seen_req.lock().unwrap().push((
                                method.clone(),
                                path.clone(),
                                headers.clone(),
                            ));
                            let resp = match (method, path.as_str()) {
                                (Method::GET, p) if p.starts_with("/volume/v/meta/") => {
                                    let hex = p.strip_prefix("/volume/v/meta/").unwrap();
                                    let id: GrainId = hex.parse().unwrap();
                                    let bytes =
                                        remote_handle(&mem_req).get_meta("v", &id).await.unwrap();
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/vnd.granary.meta.v1")
                                        .body(Full::new(Bytes::from(bytes)))
                                        .unwrap()
                                }
                                (Method::GET, p) if p.starts_with("/bin/") => {
                                    let hex = p.strip_prefix("/bin/").unwrap();
                                    let digest = decode_hex_32(hex);
                                    let range = headers.get(RANGE).unwrap().to_str().unwrap();
                                    let (start, end) = range
                                        .strip_prefix("bytes=")
                                        .unwrap()
                                        .split_once('-')
                                        .unwrap();
                                    let start: u64 = start.parse().unwrap();
                                    let end: u64 = end.parse().unwrap();
                                    let len = u32::try_from(end - start + 1).unwrap();
                                    let slice = remote_handle(&mem_req)
                                        .get_bin_range(&digest, start, len)
                                        .await
                                        .unwrap();
                                    Response::builder()
                                        .status(StatusCode::PARTIAL_CONTENT)
                                        .header("content-type", "application/vnd.granary.bin.v1")
                                        .header("content-range", format!("bytes {start}-{end}/*"))
                                        .body(Full::new(Bytes::from(slice)))
                                        .unwrap()
                                }
                                (Method::PUT, p)
                                    if p.starts_with("/bin/") || p.contains("/meta/") =>
                                {
                                    Response::builder()
                                        .status(StatusCode::CREATED)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                }
                                (Method::POST, "/volume/v/intent") => {
                                    let reg =
                                        intent::decode_register(&body, &vol("v"), |_, _| true)
                                            .unwrap();
                                    let receipt = intent::encode_receipt(Receipt {
                                        writer: reg.writer,
                                        epoch: reg.epoch,
                                        instance: reg.instance,
                                        generation: reg.generation,
                                        state: ReceiptState::Live {
                                            prepared_root_id: reg.root_id(),
                                        },
                                    })
                                    .unwrap();
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("cache-control", "no-store")
                                        .header("content-type", intent::MEDIA_RECEIPT)
                                        .body(Full::new(Bytes::from(receipt)))
                                        .unwrap()
                                }
                                other => panic!("unexpected fsync HTTP request: {other:?}"),
                            };
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls_stream), svc)
                        .await;
                });
            }
        });
        (format!("https://127.0.0.1:{}", addr.port()), pin, handle)
    });

    let mut cfg = input(&fixture.tree, &paths);
    cfg.scope = Some(Scope {
        authority_base: base_url.as_bytes().to_vec(),
        pins: vec![pin],
        credential_context: b"fixture".to_vec(),
    });
    let (ready, authority, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let (cold_name, cold_grain_id) = fixture.pressure[0].clone();
    let http_remote =
        Arc::new(crate::HttpStore::new(&base_url, vec![pin], &crate::AmbientNetwork).unwrap());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(Arc::clone(&http_remote))
            .unwrap(),
    );

    let events = Events::default();
    let _guard = tracing::subscriber::set_default(events.subscriber());
    let _engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            Arc::clone(&http_remote),
            content,
            Arc::new(Time(authority)),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(35)),
            Sequence(std::collections::VecDeque::from([Some(0x55), None])),
        ))
        .unwrap();

    let backend = ready.backend_for_test();
    let mediator = backend.shared_mediator().clone();
    let cold_path = handler_path(cold_name.as_bytes());
    let obj = backend.overlay_open(&cold_path).unwrap().unwrap();
    backend.prepare_object(obj).unwrap();
    backend
        .overlay_mutate(OverlayMutation::BoundWrite {
            object: obj,
            offset: 0,
            bytes: b"fsync1",
            append: false,
        })
        .unwrap();
    damage_query_grain(&paths, cold_grain_id, false);
    mediator
        .with(crate::WritableStore::invalidate_clean_content)
        .unwrap();

    seen.lock().unwrap().clear();
    events.0.lock().unwrap().clear();
    let job1 = backend
        .prepare_sync(MountSyncRequest::File {
            object: obj,
            datasync: false,
        })
        .unwrap();
    assert_eq!(runtime.block_on(start_job(job1)).unwrap(), Ok(()));

    let text1 = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    let extract_op = |line: &str| -> Option<String> {
        let marker = "\"op\":\"";
        let start = line.find(marker)? + marker.len();
        let rest = &line[start..];
        Some(rest[..rest.find('"')?].to_owned())
    };
    let fsync_begin = text1
        .lines()
        .find(|l| l.contains("\"event\":\"op.begin\"") && l.contains("\"kind\":\"fsync\""))
        .and_then(extract_op);
    let fsync_end = text1
        .lines()
        .find(|l| l.contains("\"event\":\"op.end\"") && l.contains("\"kind\":\"fsync\""))
        .and_then(extract_op);
    let recorded1 = seen.lock().unwrap().clone();
    let cold_gets = recorded1
        .iter()
        .filter(|(m, p, _)| *m == Method::GET && p.starts_with("/bin/"))
        .count();
    let expected1 = "cor-5555555555555555";
    let header_matches1 = !recorded1.is_empty()
        && recorded1.iter().all(|(_, _, h)| {
            h.get_all("granary-request-id")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .eq(std::iter::once(expected1))
        });

    // 2. Failed draw with no enclosing operation span omits Granary-Request-Id.
    backend
        .overlay_mutate(OverlayMutation::BoundWrite {
            object: obj,
            offset: 0,
            bytes: b"fsync2",
            append: false,
        })
        .unwrap();
    seen.lock().unwrap().clear();
    events.0.lock().unwrap().clear();
    let job2 = backend
        .prepare_sync(MountSyncRequest::File {
            object: obj,
            datasync: false,
        })
        .unwrap();
    assert_eq!(runtime.block_on(start_job(job2)).unwrap(), Ok(()));
    backend.overlay_close(obj).unwrap();
    let recorded2 = seen.lock().unwrap().clone();
    let failed_without_outer = events.failed("unavailable");
    let header_absent2 = !recorded2.is_empty()
        && recorded2
            .iter()
            .all(|(_, _, h)| h.get_all("granary-request-id").iter().next().is_none());

    assert_eq!(
        (
            fsync_begin.as_deref(),
            fsync_end.as_deref(),
            recorded1.len() >= 3,
            cold_gets >= 1,
            header_matches1,
            (failed_without_outer, header_absent2),
        ),
        (
            Some(expected1),
            Some(expected1),
            true,
            true,
            true,
            (true, true),
        ),
        "fsync job must log its correlation id, send it on every HTTP request, and follow the failed-draw rule: begin={fsync_begin:?}, end={fsync_end:?}, req1={}, cold_gets={cold_gets}, req2={}, log1={text1}",
        recorded1.len(),
        recorded2.len()
    );
}
