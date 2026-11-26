// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Cold reads share the operation's scheduler and absolute bound.

use super::*;
use crate::{SyncRuntime, SyncRuntimeError, TokioSyncRuntime};
use std::{future::Future, time::Duration};

pub(super) struct OffsetRuntime(pub(super) Arc<std::sync::atomic::AtomicBool>);
impl SyncRuntime for OffsetRuntime {
    fn now(&self) -> tokio::time::Instant {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            TokioSyncRuntime.now() - Duration::from_hours(1)
        } else {
            TokioSyncRuntime.now()
        }
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        TokioSyncRuntime.spawn(work)
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        TokioSyncRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        TokioSyncRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        TokioSyncRuntime.sleep(duration)
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl Future<Output = T> + Send,
    ) -> impl Future<Output = Result<T, SyncRuntimeError>> + Send {
        let deadline = if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            deadline + Duration::from_hours(1)
        } else {
            deadline
        };
        TokioSyncRuntime.timeout_at(deadline, work)
    }
}

type Finished = Arc<(Mutex<bool>, std::sync::Condvar)>;
fn watchdog(pause: Arc<RangeReadPause>) -> (Finished, std::thread::JoinHandle<bool>) {
    let done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let finished = done.clone();
    let worker = std::thread::spawn(move || {
        let (lock, wake) = &*finished;
        let (finished, _) = wake
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(20), |finished| {
                !*finished
            })
            .unwrap();
        let overdue = !*finished;
        if overdue {
            pause.release();
        }
        overdue
    });
    (done, worker)
}
fn finish(done: &Finished) {
    let (lock, wake) = &**done;
    *lock.lock().unwrap() = true;
    wake.notify_all();
}

struct LostRegistration {
    authority: Authority,
    first: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
}
impl RootStore for LostRegistration {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        self.authority.put_root(volume, seq, bytes).await
    }
    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.authority.get_root(volume, seq).await
    }
    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.authority.max_seq(volume).await
    }
    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.authority.max_seq_above(volume, floor).await
    }
    async fn read_hint(
        &self,
        volume: &str,
        token: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        self.authority.read_hint(volume, token).await
    }
    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        self.authority.write_hint(volume, seq).await
    }
}
impl BinStore for LostRegistration {
    async fn put_bin(&self, digest: &[u8; 32], bytes: Vec<u8>) -> Result<bool, RootStoreError> {
        self.authority.put_bin(digest, bytes).await
    }
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.authority.put_meta(volume, id, bytes).await
    }
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.authority.get_meta(volume, id).await
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.authority.get_bin_range(digest, offset, len).await
    }
}
impl crate::AuthorityTransport for LostRegistration {
    async fn publish_once(
        &self,
        request: &crate::PublishRequest,
    ) -> Result<crate::PublishResponse, crate::authority_transport::AuthorityError> {
        self.authority.publish_once(request).await
    }
    async fn status_once(
        &self,
        volume: &str,
    ) -> Result<
        crate::authority_transport::StatusResponse,
        crate::authority_transport::AuthorityError,
    > {
        self.authority.status_once(volume).await
    }
    async fn probe_root_once(
        &self,
        volume: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.authority.probe_root_once(volume, seq).await
    }
}
impl crate::SyncRemote for LostRegistration {
    async fn register_once(
        &self,
        request: &PendingIntent,
        trusted: &granary_store::crypto::TrustedKeys,
    ) -> Result<IntentReply, IntentTransportError> {
        if self.first.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            return std::future::pending().await;
        }
        self.authority.register_once(request, trusted).await
    }
    async fn release_once(
        &self,
        request: &PendingIntent,
    ) -> Result<IntentReply, IntentTransportError> {
        self.authority.release_once(request).await
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "a timed-out engine registration and its retained evidence precede both content admission controls"
)]
fn after_failed_registration(foreign: bool) {
    use crate::SyncContent as _;
    use granary_core::{grainsource::GrainSource as _, manifest::GrainRef};

    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 2, 1024, true);
    let cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(LostRegistration {
        authority: Authority::new(&fixture.tree, &state).with_publication(),
        first: std::sync::atomic::AtomicBool::new(true),
        entered: tokio::sync::Notify::new(),
    });
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
    runtime.block_on(async {
        let engine = ready
            .backend_for_test()
            .attach_sync(
                remote.clone(),
                content.clone(),
                Arc::new(Time(state.clone())),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(35)),
                Entropy(36),
            )
            .await
            .unwrap();
        let mediator = ready.backend_for_test().shared_mediator().clone();
        let create = |name, bytes: &[u8]| {
            mediator
                .overlay_transaction(|local| {
                    let file = local.create_file(
                        granary_core::overlay_journal::Location {
                            parent: granary_core::overlay_journal::Parent::new(vec![]).unwrap(),
                            name: Name::new(name).unwrap(),
                        },
                        false,
                    )?;
                    local.write(file, 0, bytes)?;
                    Ok(file)
                })
                .unwrap()
        };
        let first = create(b"first".to_vec(), b"first");
        let waiter = engine.sync(
            crate::SyncTarget::Stage(first),
            crate::SyncOptions::default(),
        );
        remote.entered.notified().await;
        tokio::time::pause();
        let failed = refused_reason(waiter.wait().await.err());
        tokio::time::resume();
        let retained = mediator
            .with(|local| {
                Ok(local
                    .snapshot()
                    .pending
                    .iter()
                    .filter(|p| p.operation == Operation::Register && !p.terminal)
                    .map(|p| (p.context.is_empty(), p.attempts))
                    .collect::<Vec<_>>())
            })
            .unwrap();
        let admission = mediator
            .with(|local| Ok(local.content_admission_for_test()))
            .unwrap();
        assert_eq!(
            (failed, retained, admission),
            (Some("SyncDeadline"), vec![(true, 1)], (true, 0)),
            "a deadline must retain the unanswered Register and dispose its capture"
        );

        if foreign {
            let refused = mediator
                .with(|local| {
                    let root = local.snapshot().root.clone();
                    local.prepare_registration(&root, vec![], &Time(state), |_, _| true)?;
                    Ok((
                        local
                            .snapshot()
                            .pending
                            .iter()
                            .filter(|p| !p.terminal)
                            .count(),
                        local.immutable_content().err().map(|e| e.to_string()),
                    ))
                })
                .unwrap();
            assert_eq!(
                refused,
                (
                    2,
                    Some("intent refused: WritableRecoveryRequired".to_owned())
                ),
                "retained engine evidence must not admit a foreign Register"
            );
            return;
        }

        let bytes = b"later";
        let id = GrainId::of(bytes);
        let grains = FileGrains::Inline(vec![GrainRef {
            id,
            unpacked_len: 5,
        }]);
        let payload = GrainId::of(&granary_core::manifest::node::file_payload(5, &grains).unwrap());
        let put = content.put_object(id, bytes).map_err(|e| e.to_string());
        let remember = content
            .remember_payload(payload, 5, &grains)
            .map_err(|e| e.to_string());
        let get = content.get(&id).map_err(|e| e.to_string());
        let read = content
            .read_content(payload, 0, 5)
            .map_err(|e| e.to_string());
        let second = create(b"second".to_vec(), b"second");
        let synced = engine
            .sync(
                crate::SyncTarget::Stage(second),
                crate::SyncOptions::default(),
            )
            .wait()
            .await
            .map_err(|e| e.to_string());
        assert_eq!(
            (put, remember, get, read, synced),
            (
                Ok(()),
                Ok(()),
                Ok(bytes.to_vec()),
                Ok(bytes.to_vec()),
                Ok(())
            ),
            "retained engine evidence must allow content operations and the next sync"
        );
    });
}

#[test]
fn mount_sync_content_after_failed_registration_allows_next_sync() {
    after_failed_registration(false);
}

#[test]
fn mount_sync_content_after_failed_registration_refuses_foreign_register() {
    after_failed_registration(true);
}

fn record(
    mediator: &crate::SharedWritableStore<OverlayDisk>,
) -> granary_core::retained_submission::Submission {
    let (bytes, scope, writer) = mediator
        .with(|local| {
            Ok((
                local.snapshot().root.clone(),
                local.snapshot().scope.clone(),
                local.writer_uuid(),
            ))
        })
        .unwrap();
    crate::overlay_store::tests::submission(scope, writer, bytes)
}

#[test]
fn mount_sync_content_commit_verification_uses_deadline() {
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 3, 65_536, true);
    let cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let pause = RangeReadPause::unarmed();
    let remote = Arc::new(Authority::new(&fixture.tree, &state).with_range_pause(pause.clone()));
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
    runtime.block_on(async {
        let engine = ready.backend_for_test().attach_sync(remote, content,
            Arc::new(Time(state)), Arc::new(crate::InstantClock::default()), crate::ClientMetrics::new(&mut Entropy(33)), Entropy(34)).await.unwrap();
        let mediator = ready.backend_for_test().shared_mediator().clone();
        let record = record(&mediator);
        let root = granary_core::root::decode_root(&record.frozen.initial_root).unwrap().manifest_root;
        let capture = engine.begin_commit(crate::SyncOptions { resolution_bound: Duration::from_millis(100), ..Default::default() }).await.unwrap();
        damage_query_grain(&paths, root, false);
        pause.arm();
        let (done, watch) = watchdog(pause.clone());
        let result = engine.retain_commit(capture, &record).await;
        finish(&done);
        let overdue = watch.join().unwrap();
        let entered = *pause.entered.0.lock().unwrap();
        let present = mediator.with(|local| Ok(local.immutable_content()?.has(&root))).unwrap();
        assert_eq!((entered, overdue, result.is_err(), present), (true, false, true, false),
            "commit verification must bound a never-answering remote without installing bytes: error={:?}", result.as_ref().err());
    });
}

fn cold_poll(offset: bool) {
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 3, 65_536, true);
    let cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let pause = RangeReadPause::unarmed();
    let remote = Arc::new(
        Authority::new(&fixture.tree, &state)
            .with_publication()
            .with_range_pause(pause.clone()),
    );
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    if offset {
        // Keep attachment local so the clock-domain assertion reaches the cold
        // publisher callback under a clock that is offset for the whole operation.
        let mediator = ready.backend_for_test().shared_mediator().clone();
        let bytes = mediator
            .with(|local| Ok(local.snapshot().root.clone()))
            .unwrap();
        let root = granary_core::root::decode_root(&bytes)
            .unwrap()
            .manifest_root;
        let source = Store::open(&paths.scratch.join("publication")).unwrap();
        for id in crate::publish::collect_objects(&source, &root).unwrap() {
            let bytes = source.get(&id).unwrap();
            mediator.put_immutable(id, &bytes).unwrap();
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let offset_clock = Arc::new(std::sync::atomic::AtomicBool::new(offset));
        let engine = ready.backend_for_test().attach_sync_with_runtime(remote, content,
            Arc::new(Time(state)), Arc::new(crate::InstantClock::default()), crate::ClientMetrics::new(&mut Entropy(34)), Arc::new(OffsetRuntime(offset_clock.clone())), Entropy(35)).await.unwrap();
        let mediator = ready.backend_for_test().shared_mediator().clone();
        let root = mediator.with(|local| Ok(granary_core::root::decode_root(&local.snapshot().root).unwrap().manifest_root)).unwrap();
        let location = granary_core::overlay_journal::Location {
            parent: granary_core::overlay_journal::Parent::new(vec![]).unwrap(),
            name: Name::new(b"new".to_vec()).unwrap(),
        };
        let capture_stage = mediator
            .overlay_transaction(|local| local.create_file(location, false))
            .unwrap();
        damage_query_grain(&paths, root, false);
        pause.arm();
        let (done, watch) = watchdog(pause.clone());
        let releaser_pause = pause.clone();
        let releaser_done = done.clone();
        let releaser = TokioSyncRuntime.spawn(async move {
            loop {
                if *releaser_pause.entered.0.lock().unwrap() { releaser_pause.release(); return true; }
                if *releaser_done.0.lock().unwrap() { return false; }
                TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
            }
        });
        let result = engine.sync(crate::SyncTarget::Stage(capture_stage), crate::SyncOptions {
            resolution_bound: Duration::from_secs(10), ..Default::default()
        }).wait().await;
        finish(&done);
        let overdue = watch.join().unwrap();
        let released_on_executor = releaser.await.unwrap();
        assert_eq!((result.is_ok(), overdue, released_on_executor), (true, false, true),
            "cold publisher callback must leave the current-thread executor running and use its attached clock: offset={offset}, result={result:?}");
    });
}

#[test]
fn mount_sync_content_cold_poll_keeps_current_thread_running() {
    cold_poll(false);
}
#[test]
fn mount_sync_content_cold_poll_uses_attached_clock() {
    cold_poll(true);
}

#[test]
fn mount_sync_content_cold_fetch_requires_deadline() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let paths = query_paths();
    let fixture = clean_tree_with_pressure(&paths, 3, 65_536, true);
    let cfg = input(&fixture.tree, &paths);
    let (ready, state, _) = attempt(&cfg, &fixture.tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let content = ready
        .backend_for_test()
        .sync_content(Arc::new(Authority::new(&fixture.tree, &state)))
        .unwrap();
    let cold = fixture.pressure[0].1;
    let result = content.fetch_immutable(cold);
    assert_eq!(
        refused_reason(result.err()),
        Some("SyncContentDeadlineRequired"),
        "unbound cold fetch must refuse instead of starting a new clock"
    );
}
