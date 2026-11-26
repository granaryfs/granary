// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;
use crate::{
    AuthorityError, AuthorityTransport, IntentCompletion, PublicationOutcome, PublishRequest,
    PublishResponse, RecoveryDelay, RecoveryIntent, StatusResponse, validate_publish_answer,
    validate_status_observation,
};
use granary_core::rootstore::RootStore as _;
use granary_core::{
    authlog::Epoch,
    authority_answer::{self, Head, Position, PublishAnswer, VolumeStatus},
};
use std::{future::Future, pin::Pin};

mod budget;
mod capacity;
mod complete_snapshot;
mod contention;
mod drain;
mod fenced_takeover;
mod lifecycle;
mod projected;
mod published;
mod rebase;
mod refresh;
mod reporting;
mod rules;
mod selected;
mod takeover;

#[derive(Clone, Copy)]
pub(super) enum PublishPlan {
    Land,
    LandVariant,
    LandAfterDelay(Duration),
    /// Land once the test releases the hold; until then the send is one
    /// unresolved attempt, dropped unanswered if its caller stops waiting.
    Hold,
    Accepted,
    Timeout,
    Internal,
    RateLimited,
    Unavailable,
    UnavailableAfterDelay(Duration),
    BareUnavailable,
    OtherUnavailable(&'static str),
    RewordedUnavailable,
    BareRateLimited,
    MalformedUnavailable,
    Transport,
    Malformed,
    Reject,
    MissingReference,
    InvalidReference,
    WorkLimit,
    StaleForeign,
    StaleForeignUnreadable,
    StaleParentUnavailable,
    StaleCurrent,
    EpochMismatch(Epoch),
}

impl AuthorityTransport for Remote {
    #[expect(
        clippy::too_many_lines,
        reason = "the fake keeps every checked publication answer in one scripted transition"
    )]
    async fn publish_once(
        &self,
        request: &PublishRequest,
    ) -> Result<PublishResponse, AuthorityError> {
        let observer = self.publication_observer.lock().unwrap().take();
        if let Some(observer) = observer {
            observer();
        }
        self.publication_sends
            .lock()
            .unwrap()
            .push(request.candidate().bytes().to_vec());
        self.publication_operations
            .lock()
            .unwrap()
            .push(request.operation().to_vec());
        let action = self
            .publication_plan
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(PublishPlan::Land);
        if let PublishPlan::LandAfterDelay(duration)
        | PublishPlan::UnavailableAfterDelay(duration) = action
        {
            TokioSyncRuntime.sleep(duration).await;
        }
        if let PublishPlan::Hold = action {
            self.publish_hold.hold().await;
        }
        let position = Position {
            epoch: request.epoch(),
            entry_seq: 1,
        };
        let (status, token, answer) = match action {
            PublishPlan::EpochMismatch(epoch) => (
                409,
                Some("epoch-mismatch"),
                PublishAnswer::EpochMismatch { epoch, head: None },
            ),
            PublishPlan::StaleCurrent => {
                let roots = self.published.lock().unwrap();
                let (seq, bytes) = roots.last_key_value().unwrap();
                (
                    409,
                    Some("stale-base"),
                    PublishAnswer::StaleBase(Head::new(Some((*seq, GrainId::of(bytes))))),
                )
            }
            PublishPlan::Land
            | PublishPlan::LandVariant
            | PublishPlan::LandAfterDelay(_)
            | PublishPlan::Hold => {
                let mut stored = request.candidate().bytes().to_vec();
                if matches!(action, PublishPlan::LandVariant) {
                    let mut doc = granary_core::root::decode_root(&stored).unwrap();
                    doc.sigs.push(granary_core::root::RootSig {
                        key_id: [98; 32],
                        sig: [0; 64],
                    });
                    stored = granary_core::root::encode_root(&doc).unwrap();
                }
                self.published
                    .lock()
                    .unwrap()
                    .insert(request.candidate().seq(), stored);
                (
                    200,
                    None,
                    PublishAnswer::Landed {
                        receipt: authority_answer::Receipt {
                            position,
                            root_seq: request.candidate().seq(),
                            stored_id: request.candidate().id(),
                        },
                        head: None,
                    },
                )
            }
            PublishPlan::Accepted => (
                202,
                None,
                PublishAnswer::Accepted {
                    position,
                    candidate_id: request.candidate().id(),
                },
            ),
            PublishPlan::StaleForeign
            | PublishPlan::StaleForeignUnreadable
            | PublishPlan::StaleParentUnavailable => {
                let base = self
                    .published
                    .lock()
                    .unwrap()
                    .first_key_value()
                    .unwrap()
                    .1
                    .clone();
                let base = granary_core::root::decode_root(&base).unwrap();
                let prepared = crate::prepare_from_manifest(
                    self,
                    &self.objects.read_objects(base.binmap_index).unwrap(),
                    base.manifest_root,
                    crate::HarvestStats::default(),
                    &base.volume,
                    &SigningKey::from_seed(&[39; 32]).unwrap(),
                    &granary_core::identity::WriterIdentity::from_bytes([77; 16]),
                    base.timestamp,
                    crate::Policy { min_prefix_bits: 0 },
                )
                .await
                .unwrap();
                let mut doc = granary_core::root::decode_root(&prepared.root_bytes).unwrap();
                doc.writer_uuid = [77; 16];
                doc.sigs.clear();
                let key = SigningKey::from_seed(&[39; 32]).unwrap();
                let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
                doc.sigs.push(RootSig {
                    key_id: key.key_id(),
                    sig: key.sign(&prefix),
                });
                let bytes = granary_core::root::encode_root(&doc).unwrap();
                self.published
                    .lock()
                    .unwrap()
                    .insert(doc.seq, bytes.clone());
                if matches!(action, PublishPlan::StaleParentUnavailable) {
                    // Ancestry validation reads the parent before the merge walks it.
                    self.unavailable_parent_read.store(2, Ordering::Relaxed);
                }
                if matches!(action, PublishPlan::StaleForeignUnreadable) {
                    self.failed_probe
                        .store(self.probes.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
                }
                (
                    409,
                    Some("stale-base"),
                    PublishAnswer::StaleBase(Head::new(Some((doc.seq, GrainId::of(&bytes))))),
                )
            }
            PublishPlan::Timeout => return Err(AuthorityError::Elapsed),
            PublishPlan::Internal => {
                return validate_publish_answer(request, 500, Some("internal"), &[]);
            }
            PublishPlan::RateLimited => {
                return validate_publish_answer(request, 429, Some("rate-limited"), &[]);
            }
            PublishPlan::Unavailable | PublishPlan::UnavailableAfterDelay(_) => {
                return validate_publish_answer(request, 503, Some("unavailable"), &[]);
            }
            PublishPlan::Transport => {
                return Err(AuthorityError::Transport(crate::TransportError::from(
                    "transient fixture",
                )));
            }
            PublishPlan::BareRateLimited => {
                return validate_publish_answer(request, 429, None, &[]);
            }
            PublishPlan::MalformedUnavailable => {
                return validate_publish_answer(request, 503, Some("unrecognized"), &[]).map_err(
                    |error| match error {
                        AuthorityError::Backend(error) => {
                            AuthorityError::Backend(error.reword("missing error token"))
                        }
                        other => other,
                    },
                );
            }
            PublishPlan::RewordedUnavailable => {
                return validate_publish_answer(request, 503, None, &[]).map_err(
                    |error| match error {
                        AuthorityError::Backend(error) => AuthorityError::Backend(
                            error.reword("upstream response omitted identification"),
                        ),
                        other => other,
                    },
                );
            }
            PublishPlan::BareUnavailable => {
                return validate_publish_answer(request, 503, None, &[]);
            }
            PublishPlan::OtherUnavailable(token) => {
                return validate_publish_answer(request, 503, Some(token), &[]);
            }
            PublishPlan::Malformed => {
                return validate_publish_answer(request, 200, None, b"malformed");
            }
            PublishPlan::Reject => {
                return validate_publish_answer(request, 400, Some("invalid-candidate"), &[]);
            }
            PublishPlan::MissingReference => {
                return validate_publish_answer(request, 400, Some("missing-reference"), &[]);
            }
            PublishPlan::InvalidReference => {
                return validate_publish_answer(request, 400, Some("invalid-reference"), &[]);
            }
            PublishPlan::WorkLimit => {
                return validate_publish_answer(request, 413, Some("publish-work-limit"), &[]);
            }
        };
        validate_publish_answer(
            request,
            status,
            token,
            &authority_answer::encode(answer).unwrap(),
        )
    }
    async fn status_once(&self, _: &str) -> Result<StatusResponse, AuthorityError> {
        assert!(
            !self.panic_status.swap(false, Ordering::AcqRel),
            "fixture status read panics"
        );
        if self.fail_status.swap(false, Ordering::AcqRel) {
            return Err(AuthorityError::Elapsed);
        }
        let head = self
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .map(|(seq, bytes)| Head::new(Some((*seq, GrainId::of(bytes)))));
        validate_status_observation(
            &authority_answer::encode_status(VolumeStatus {
                epoch: Epoch::from_bytes([3; 16]),
                head,
                open: None,
            })
            .unwrap(),
        )
    }
    async fn probe_root_once(
        &self,
        volume: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.post_listing_probe.observe();
        if let Some(error) = self.root_probe_fault.lock().unwrap().take() {
            return Err(error);
        }
        let probe = self.probes.fetch_add(1, Ordering::Relaxed) + 1;
        let delay = self.probe_delay.lock().unwrap().take();
        if let Some(delay) = delay {
            TokioSyncRuntime.sleep(delay).await;
        }
        if probe == self.failed_probe.load(Ordering::Relaxed) {
            return Err(RootStoreError::Backend("probe fixture".into()));
        }
        if probe == self.corrupt_probe.load(Ordering::Relaxed) {
            return Ok(Some(b"corrupt root".to_vec()));
        }
        self.get_root(volume, seq).await
    }
}

pub(super) struct Delay;
impl RecoveryDelay for Delay {
    fn jitter(&mut self, _: Duration) -> Duration {
        Duration::ZERO
    }
    fn wait(&mut self, _: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

struct HeldDelay {
    calls: usize,
    at: usize,
    entered: Arc<Notify>,
}
impl RecoveryDelay for HeldDelay {
    fn jitter(&mut self, _: Duration) -> Duration {
        Duration::ZERO
    }
    fn wait(&mut self, _: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.calls += 1;
        let held = self.calls == self.at;
        let entered = self.entered.clone();
        Box::pin(async move {
            if held {
                entered.notify_one();
                std::future::pending::<()>().await;
            }
        })
    }
}

pub(super) fn assert_file(fixture: &Fixture, root: &[u8], name: &str, expected: &[u8]) {
    let doc = granary_core::root::decode_root(root).unwrap();
    let entries =
        crate::writable_store::capture::entries(fixture.content.as_ref(), doc.manifest_root, 1)
            .unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.name.as_bytes() == name.as_bytes())
        .unwrap();
    let EntryKind::File { size, grains, .. } = &entry.kind else {
        panic!("file missing")
    };
    let payload = manifest::node::file_payload(*size, grains).unwrap();
    assert_eq!(
        fixture
            .content
            .read_content(GrainId::of(&payload), 0, usize::try_from(*size).unwrap())
            .unwrap(),
        expected
    );
}

#[tokio::test]
async fn recovered_lane_reserves_what_capture_reserved() {
    let fixture = Fixture::new().await;
    fixture.create("alpha", b"a");
    fixture.create("beta", b"b");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    // Both lanes hold the same overlay graph share; RAM is accounted separately.
    let captured = lane.charge();
    let fixture = fixture.restart().await;
    let recovered = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    assert_eq!(
        recovered.charge(),
        captured,
        "recovery charged a different formula"
    );
}

#[tokio::test]
async fn replacement_preserves_unselected_and_colliding_checkpoints() {
    let fixture = Fixture::new().await;
    let z = fixture.create("z", b"old z");
    let a = fixture.create("a", b"old a");
    for reject in [false, true] {
        let lane = fixture
            .engine
            .construct_commit(
                SyncOptions::default(),
                &mut Entropy(if reject { 90 } else { 70 }),
            )
            .await
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.write(a, 0, b"new a")?;
                t.write(z, 0, b"new z")?;
                Ok(())
            })
            .unwrap();
        if reject {
            fixture
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .push_back(PublishPlan::Reject);
        }
        Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        if reject {
            let a_result = fixture
                .engine
                .sync(SyncTarget::Stage(a), SyncOptions::default())
                .wait()
                .await;
            let z_result = fixture
                .engine
                .sync(SyncTarget::Stage(z), SyncOptions::default())
                .wait()
                .await;
            assert_eq!(
                (
                    matches!(a_result, Err(CoordinationError::Fenced { .. })),
                    matches!(z_result, Err(CoordinationError::Fenced { .. }))
                ),
                (true, true),
                "refused checkpoints must remain fenced: {a_result:?}, {z_result:?}"
            );
            continue;
        }
        fixture
            .engine
            .sync(SyncTarget::Stage(a), SyncOptions::default())
            .wait()
            .await
            .expect("replacement lost an unselected checkpoint");
        let root = fixture.remote.authority.lock().unwrap().root.clone();
        assert_file(&fixture, &root, "a", b"new a");
        assert_file(
            &fixture,
            &root,
            "z",
            if reject { b"new z" } else { b"old z" },
        );
        fixture
            .engine
            .sync(SyncTarget::Stage(z), SyncOptions::default())
            .wait()
            .await
            .expect("replacement aliased a stale checkpoint inode");
        let root = fixture.remote.authority.lock().unwrap().root.clone();
        assert_file(&fixture, &root, "a", b"new a");
        assert_file(&fixture, &root, "z", b"new z");
    }
}

#[tokio::test]
async fn restart_discards_new_boundary_after_prior_terminal_refusal() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"retained");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Reject);
    Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    let fixture = fixture.restart().await;
    let capture = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.record_boundary(capture.boundary().clone(), grain(91), [91; 16]))
        .unwrap();
    let fixture = fixture.restart().await;
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_file(
        &fixture,
        &fixture.remote.authority.lock().unwrap().root,
        "file",
        b"retained",
    );
}

async fn land_without_refresh(fixture: &Fixture, lane: &crate::RetainedCommit) {
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "landed_readback", 1, FaultAction::Block);
    let mut secure = Entropy(80);
    let mut delay = Delay;
    let mut driving = Box::pin(fixture.engine.drive_commit(
        lane,
        &mut secure,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ));
    let mut entered = Box::pin(fired(&faults, "sync.commit", "landed_readback"));
    std::future::poll_fn(|cx| {
        assert!(
            driving.as_mut().poll(cx).is_pending(),
            "commit finished before its readback seam"
        );
        entered.as_mut().poll(cx)
    })
    .await;
    drop(driving);
    faults.resume();
    assert_eq!(
        (
            fixture.remote.published.lock().unwrap().len(),
            durable_commit_state(fixture),
        ),
        (2, (Some(("complete", 1)), (true, false))),
        "the readback seam must hold a journaled landing and no refresh"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_finishes_landed_commit_before_sync_admission() {
    let fixture = Fixture::new().await;
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    land_without_refresh(&fixture, &lane).await;
    let fixture = fixture.restart().await;
    let lane = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(90),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(
        fixture.remote.publication_sends.lock().unwrap().len(),
        1,
        "restart resubmitted a complete candidate"
    );
    let stage = fixture.create("later", b"after restart");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_eq!(fixture.registered().seq, 3);
}

struct ContentReader(Arc<Content>);
impl ContentSource for ContentReader {
    fn read_verified(
        &mut self,
        id: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.0.read_content(id, offset, length)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RestartCut {
    AfterReceipt,
    AfterGrant,
}

impl Fixture {
    async fn restart(self) -> Self {
        self.restart_over(vec![]).await
    }
    async fn restart_over(self, entries: Vec<OverlayEntry>) -> Self {
        self.try_restart_over(entries)
            .await
            .unwrap_or_else(|error| panic!("restart refused: {error}"))
    }
    /// Crash the fixture and reload its stored carrier from the same disk,
    /// before any step of startup has run against it.
    fn reload_carrier(self) -> (Scratch, SimIo, Arc<Remote>, WritableStore<SimIo>) {
        let Self {
            _scratch: scratch,
            io,
            store,
            engine,
            metrics,
            remote,
            ..
        } = self;
        drop(engine);
        let store = Arc::into_inner(store)
            .expect("fixture still has a client job")
            .into_inner()
            .unwrap();
        drop(store);
        io.crash();
        let mut local = start(&scratch, &io, 120);
        local.set_metrics(metrics);
        (scratch, io, remote, local)
    }
    async fn try_restart_over(self, entries: Vec<OverlayEntry>) -> Result<Self, CoordinationError> {
        let bytes = self.remote.published.lock().unwrap()[&1].clone();
        self.try_restart_at(entries, 1, bytes, false, None).await
    }
    async fn restart_twice_at(self, cut: RestartCut) -> Self {
        let bytes = self.remote.published.lock().unwrap()[&1].clone();
        self.try_restart_at(vec![], 1, bytes, false, Some(cut))
            .await
            .unwrap_or_else(|error| panic!("two-restart cut refused: {error}"))
    }
    /// Crash and reopen over the authority's head, as a mount does once its
    /// landings have installed; the head's whole tree is its namespace.
    pub(super) async fn restart_at_head(self) -> Self {
        self.try_restart_at_head()
            .await
            .unwrap_or_else(|error| panic!("restart at the head refused: {error}"))
    }

    async fn try_restart_at_head(self) -> Result<Self, CoordinationError> {
        let (seq, bytes) = {
            let published = self.remote.published.lock().unwrap();
            let (seq, bytes) = published.last_key_value().unwrap();
            (*seq, bytes.clone())
        };
        self.try_restart_at_published(seq, bytes, true).await
    }

    async fn try_restart_at_published(
        self,
        seq: u64,
        bytes: Vec<u8>,
        installed: bool,
    ) -> Result<Self, CoordinationError> {
        let doc = granary_core::root::decode_root(&bytes).unwrap();
        let entries = crate::writable_store::capture::overlay_base_entries(
            self.content.as_ref(),
            doc.manifest_root,
            &|_, _| 0,
            &mut |_, _| Ok(()),
            &|| CoordinationError::Refused("test reopen"),
        )
        .unwrap();
        self.try_restart_at(entries, seq, bytes, installed, None)
            .await
    }
    #[expect(
        clippy::too_many_lines,
        reason = "one restart fixture preserves replay, takeover, overlay recovery and engine attachment order"
    )]
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the transaction facade's concrete overlay type is private to its sibling module"
    )]
    async fn try_restart_at(
        self,
        entries: Vec<OverlayEntry>,
        base_seq: u64,
        base_bytes: Vec<u8>,
        installed: bool,
        cut: Option<RestartCut>,
    ) -> Result<Self, CoordinationError> {
        let base = GrainId::of(&base_bytes);
        let Self {
            _scratch: scratch,
            io,
            store,
            engine,
            remote,
            metrics,
            content,
            ..
        } = self;
        drop(engine);
        let store = Arc::into_inner(store)
            .expect("fixture still has a client job")
            .into_inner()
            .unwrap();
        drop(store);
        let mut pass = 0;
        let mut local = loop {
            io.crash();
            let mut local = start(&scratch, &io, 120 + pass);
            local.set_metrics(metrics.clone());
            if let Some(replay) = local.landed_replay()? {
                let replay_at = 2_000_000;
                local.dispatch_landed_replay(replay.request(), &Tick(replay_at))?;
                remote
                    .attempts
                    .lock()
                    .unwrap()
                    .push(replay.request().bytes().to_vec());
                let answer = remote.authority.lock().unwrap().send(replay.request());
                local.complete_landed_replay(
                    replay.request(),
                    Ok(&answer),
                    &Tick(replay_at.saturating_add(1)),
                    &mut SeededRng::new(1),
                    0,
                    None,
                )?;
            }
            if pass == 0 && cut == Some(RestartCut::AfterReceipt) {
                pass += 1;
                continue;
            }
            if !(pass == 1 && cut == Some(RestartCut::AfterGrant)) {
                let succession_at = 2_000_002;
                let transfer = local.prepare_succession(&Tick(succession_at))?;
                local.dispatch(&transfer, &Tick(succession_at))?;
                let answer = remote.authority.lock().unwrap().send(&transfer);
                local.complete(
                    &transfer,
                    Ok(&answer),
                    &Tick(succession_at + 1),
                    &mut SeededRng::new(1),
                    0,
                    None,
                )?;
            }
            if pass == 0 && cut == Some(RestartCut::AfterGrant) {
                pass += 1;
                continue;
            }
            break local;
        };
        let mut header = header();
        header.writer = local.writer_uuid();
        header.base_root = base;
        header.base_seq = base_seq;
        local.open_overlay(
            header,
            entries,
            &mut ContentReader(content.clone()),
            io.clone(),
        )?;
        for capture in local.reopened_captures()? {
            local.fail_reopened_capture(&capture)?;
        }
        let scope = local.snapshot().scope.clone();
        let volume = local.snapshot().volume.clone();
        let retained = local
            .publication_transaction(|j| j.load(&scope, &volume))
            .unwrap();
        if retained.is_none() {
            let commits = local.overlay_transaction(|overlay| overlay.recovery_commits())?;
            if matches!(commits.as_slice(), [crate::RecoveryCommit::Boundary { .. }]) {
                local.reconcile_unsubmitted_commit()?;
            }
            register(&mut local, &mut remote.authority.lock().unwrap(), 2);
        } else if retained
            .as_ref()
            .is_some_and(crate::sync::terminal_non_landing)
        {
            local.reconcile_commit_rejection()?;
            register(&mut local, &mut remote.authority.lock().unwrap(), 2);
        } else if installed {
            // An installed landing leaves nothing to reconcile.
            register(&mut local, &mut remote.authority.lock().unwrap(), 2);
        }
        let store = Arc::new(Mutex::new(local));
        let trusted =
            TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
        let engine = SyncEngine::with_runtime(
            store.clone(),
            remote.clone(),
            content.clone(),
            remote.time.clone(),
            remote.time.clone(),
            SigningKey::from_seed(&[39; 32]).unwrap(),
            trusted,
            base_bytes,
            metrics.clone(),
            Arc::new(TrackedRuntime(content.clone())),
        )
        .await?;
        Ok(Self {
            _scratch: scratch,
            io,
            store,
            engine,
            remote,
            metrics,
            base,
            content,
        })
    }
}

#[tokio::test]
async fn restart_discards_unsubmitted_boundary_and_preserves_namespace() {
    let fixture = Fixture::new().await;
    fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let bytes = fixture.remote.authority.lock().unwrap().root.clone();
    let capture = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.record_boundary(capture.boundary().clone(), GrainId::of(&bytes), [70; 16])
        })
        .unwrap();
    let fixture = fixture.restart().await;
    let stage = fixture.create("file", b"retained after interruption");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_file(
        &fixture,
        &fixture.remote.authority.lock().unwrap().root,
        "file",
        b"retained after interruption",
    );
}

/// Each fault leaves what a crash at its point leaves, and a restart converges:
/// a boundary with no submission is discarded and the namespace kept, and a
/// retained submission lands once recovered, merged onto a newer head when it
/// had to rebase.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one crash schedule binds retained restart and disk-loss subsumption to the same landing cut"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "test runs synchronous recovery on its own runtime while the asynchronous commit fixture remains live"
)]
async fn commit_faults_leave_the_crash_state_a_restart_recovers() {
    // Per point: the durable retained phase and candidate count, whether a
    // landing and its refresh are journaled, and the intent a restart needs. A
    // loaded rebase wants an explicit recovery; a rebased candidate is
    // resumable as it is.
    let points = [
        (
            "boundary_recorded",
            None,
            (false, false),
            None,
            RecoveryIntent::ExplicitRecovery,
        ),
        (
            "before_rebase",
            Some(("rebase", 1)),
            (false, false),
            None,
            RecoveryIntent::ExplicitRecovery,
        ),
        (
            "after_rebase",
            Some(("ready", 2)),
            (false, false),
            None,
            RecoveryIntent::Continue,
        ),
        (
            "landed_readback",
            Some(("complete", 1)),
            (true, false),
            Some(false),
            RecoveryIntent::Continue,
        ),
        (
            "landed_refresh",
            Some(("complete", 1)),
            (true, false),
            Some(true),
            RecoveryIntent::Continue,
        ),
        (
            "before_replace",
            Some(("complete", 1)),
            (true, true),
            None,
            RecoveryIntent::Continue,
        ),
    ];
    let mut cases = 0;
    for (phase, retained, journaled, pending_refresh, intent) in points {
        commit_fault_control(phase).await;
        commit_fault_restart(phase, retained, journaled, pending_refresh, intent).await;
        cases += 2;
    }
    assert_eq!(cases, 12);

    let fixture = Fixture::new().await;
    let stage = fixture.create("local", b"older");
    fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let prepared = fixture.remote.authority.lock().unwrap().root.clone();
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|overlay| overlay.write(stage, 0, b"sealed").map(|_| ()))
        .unwrap();
    fixture.store.lock().unwrap().fault_control().arm(
        "sync.commit",
        "landed_readback",
        1,
        FaultAction::Fail,
    );
    let cut = first_commit_fault(&fixture, "landed_readback").await;
    assert!(
        cut.as_ref()
            .is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
        "landed-readback cut: {cut:?}"
    );
    let remote = fixture.remote.clone();
    assert_ne!(
        remote.published.lock().unwrap().get(&2).unwrap(),
        &prepared,
        "the landing must carry newer bytes than the selected prepared root"
    );
    let writer = remote.authority.lock().unwrap().row.unwrap().writer;
    let sends = remote.publication_sends.lock().unwrap().len();
    let recovering = remote.clone();
    let recovered = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        selected::command_on(&Scratch::new(), &recovering, &runtime, writer, Some(writer))
    })
    .await
    .unwrap();
    assert_eq!(
        (
            recovered,
            remote.publication_sends.lock().unwrap().len(),
            remote.authority.lock().unwrap().row.unwrap().state
        ),
        (Ok(()), sends, ReceiptState::Released),
        "a lost disk after landing owes only release, with no second publication"
    );
}

#[tokio::test]
async fn restart_after_refresh_dispatch_transport_failure_replays_exactly() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    fixture.remote.unknown.store(true, Ordering::Relaxed);
    let error = first_commit_fault(&fixture, "refresh_transport").await;
    let refresh = fixture
        .store
        .lock()
        .unwrap()
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.operation == Operation::Register && !pending.terminal)
        .map(|pending| pending.body.clone())
        .unwrap();
    let attempts = fixture.remote.attempts.lock().unwrap().clone();
    assert_eq!(
        (
            error.is_some_and(|error| error.to_string().contains("IntentStartupAttemptsExhausted")),
            durable_commit_state(&fixture),
            fixture.registered().seq,
            attempts.len(),
            attempts.iter().all(|request| request == &refresh),
        ),
        (true, (Some(("complete", 1)), (true, false)), 2, 8, true),
        "a failed refresh dispatch must retain its exact accepted request"
    );
    fixture.remote.unknown.store(false, Ordering::Relaxed);
    let fixture = fixture.restart().await;
    restart_drives_the_lane(&fixture, "refresh_transport", RecoveryIntent::Continue).await;
    let attempts = fixture.remote.attempts.lock().unwrap();
    assert_eq!(
        (
            fixture.registered().seq,
            fixture.remote.publication_sends.lock().unwrap().len(),
            attempts.len(),
            attempts.iter().all(|request| request == &refresh),
        ),
        (2, 1, 9, true),
        "restart must replay the pending refresh exactly and install the landing"
    );
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_file(&fixture, &root, "local", b"sealed");
}

#[tokio::test]
async fn landed_replay_two_restart_cuts_install_once_without_a_new_register() {
    let mut outcomes = Vec::new();
    for (name, cut) in [
        ("after_receipt", RestartCut::AfterReceipt),
        ("after_grant", RestartCut::AfterGrant),
    ] {
        let fixture = landed_refresh_cut().await;
        let refresh = fixture.pending_registrations().last().unwrap().body.clone();
        let fixture = fixture.restart_twice_at(cut).await;
        restart_drives_the_lane(&fixture, name, RecoveryIntent::Continue).await;
        let root = fixture.remote.authority.lock().unwrap().root.clone();
        assert_file(&fixture, &root, "local", b"sealed");
        let attempts = fixture.remote.attempts.lock().unwrap();
        outcomes.push((
            name,
            attempts.len(),
            attempts.iter().all(|request| request == &refresh),
            fixture.registered().seq,
            landed_refresh_record_count(&fixture),
        ));
    }
    assert_eq!(
        (outcomes, 2),
        (
            vec![
                ("after_receipt", 1, true, 2, 1),
                ("after_grant", 1, true, 2, 1),
            ],
            2,
        ),
        "each second restart must send no register and install the one landing refresh"
    );
}

async fn landed_refresh_cut() -> Fixture {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Fail);
    let error = first_commit_fault(&fixture, "landed_refresh").await;
    assert!(
        error.is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
        "premise: the landed refresh cut must stop after retaining the request"
    );
    fixture
}

#[tokio::test]
async fn expired_fenced_takeover_skips_retained_release_and_landed_refresh() {
    use granary_core::overlay_ownership::{self as ownership, Pending};

    for with_release in [false, true] {
        let (scratch, io, remote, mut local) = landed_refresh_cut().await.reload_carrier();
        local.phase_for_test(Phase::Fenced).unwrap();
        let scope = local.snapshot().scope.clone();
        let volume = local.snapshot().volume.clone();
        let writer = local.writer_uuid();
        let observed =
            crate::WritableAuthority::writable_readback(&*remote, &scope, &volume, &[0; 32])
                .await
                .unwrap();
        let selected =
            crate::SelectedRecovery::from_readback(scope, volume, writer, &observed, |_, _| true)
                .unwrap();
        let takeover = local
            .reselect(
                selected.acknowledge_takeover(writer).unwrap(),
                &Tick(10_000),
            )
            .unwrap();
        local.dispatch(&takeover, &Tick(10_000)).unwrap();
        let refresh = local.landed_replay().unwrap();
        assert_eq!(
            refresh.as_ref().map(|r| r.request().operation()),
            Some(Operation::Register),
            "matched refresh premise: {refresh:?}"
        );
        let mut expected = local.snapshot().clone();
        let held = expected.pending.first().unwrap();
        assert_eq!(
            (held.body.as_slice(), expected.fence, expected.phase),
            (takeover.bytes(), 2, Phase::Handshake)
        );
        let expires = held.expires;
        drop(local);
        if with_release {
            // Load a retained carrier with a Release still within its horizon
            // at the selected epoch, so the Release expiry pass leaves it alone.
            let current = intent::decode_receipt(&expected.current).unwrap();
            let selected = intent::decode_receipt(&expected.selected).unwrap();
            assert_eq!(
                current.epoch, selected.epoch,
                "Release is at the selected epoch"
            );
            expected.pending.push(Pending {
                operation: Operation::Release,
                body: intent::encode_release(intent::Release {
                    writer,
                    epoch: current.epoch,
                    instance: current.instance,
                    generation: expected.sent,
                })
                .unwrap(),
                context: vec![],
                first: expires - 1,
                eligible: expires - 1,
                expires: expires + 1,
                attempts: 1,
                terminal: false,
                answered: false,
                answer: vec![],
            });
            io.mutate_recovered("ownership", |bytes| {
                *bytes = ownership::encode(&expected).unwrap();
            });
        }
        io.crash();
        let mut local = start(&scratch, &io, 122);
        let mut driven = Vec::new();
        let settled = crate::writable_start::settle_recovery(
            &mut local,
            &Tick(expires),
            |_, request, landed| {
                driven.push((request.operation(), landed));
                Ok(())
            },
        );
        let persisted = ownership::decode(&io.recovered_bytes("ownership").unwrap()).unwrap();
        expected.pending.first_mut().unwrap().terminal = true;
        assert_eq!(
            (
                settled.map_err(|error| error.name()),
                persisted.phase,
                persisted.fence,
                persisted.pending,
                driven
            ),
            (
                Ok(()),
                Phase::Fenced,
                expected.fence,
                expected.pending,
                vec![]
            ),
            "with_release={with_release}: expiry preserves the fence and skips all retained sends"
        );
    }
}

async fn transport_failed_landed_refresh() -> Fixture {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    fixture.remote.unknown.store(true, Ordering::Relaxed);
    let error = first_commit_fault(&fixture, "refresh_transport").await;
    fixture.remote.unknown.store(false, Ordering::Relaxed);
    assert_eq!(
        (
            error.is_some_and(|error| error.to_string().contains("IntentStartupAttemptsExhausted")),
            fixture
                .pending_registrations()
                .last()
                .map(|pending| pending.attempts),
        ),
        (true, Some(8)),
        "premise: the original start must retain the exact refresh after eight unknown sends"
    );
    fixture
}

async fn unrelated_pending_capture() -> (Fixture, Vec<u8>) {
    let fixture = Fixture::new().await;
    let stage = fixture.create("capture", b"");
    let body = {
        let mut local = fixture.store.lock().unwrap();
        let capture = local
            .overlay_transaction(|transaction| {
                let capture = transaction.capture(stage)?;
                transaction.flush_boundary(&capture)?;
                Ok(capture)
            })
            .unwrap();
        let root = root(local.writer_uuid(), 2);
        local
            .prepare_captured_registration(
                &root,
                capture,
                FileGrains::Inline(Vec::new()),
                &Tick(2_000),
                |_, _| true,
            )
            .unwrap()
            .bytes()
            .to_vec()
    };
    (fixture, body)
}

#[tokio::test]
async fn succession_requires_register_replay() {
    let mut cases = 0;
    let matched = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut local) = matched.reload_carrier();
    let matched_result = (
        local.landed_replay().unwrap().is_some(),
        local
            .prepare_succession(&Tick(2_000_000))
            .err()
            .map(|error| error.to_string()),
    );
    cases += 1;

    let (unrelated, _) = unrelated_pending_capture().await;
    let (_scratch, _io, _remote, mut reloaded) = unrelated.reload_carrier();
    let reloaded_no_match = reloaded.landed_replay().unwrap().is_none();
    assert!(
        reloaded_no_match,
        "reloaded unrelated capture must be a classifier no-match"
    );
    let (unrelated, body) = unrelated_pending_capture().await;
    let unrelated_result = match unrelated.try_restart_over(vec![]).await {
        Ok(unrelated) => {
            let context_failed = {
                let local = unrelated.store.lock().unwrap();
                local.reopened_captures().unwrap().is_empty()
                    && local
                        .retained_requests()
                        .iter()
                        .all(|request| request.bytes() != body)
            };
            let later = unrelated.create("later", b"converged");
            let converged = unrelated
                .engine
                .sync(SyncTarget::Stage(later), SyncOptions::default())
                .wait()
                .await
                .is_ok();
            (None, reloaded_no_match, context_failed, converged)
        }
        Err(error) => (Some(error.to_string()), reloaded_no_match, false, false),
    };
    cases += 1;
    assert_eq!(
        (matched_result, unrelated_result, cases),
        (
            (true, Some("intent refused: IntentReplayPending".to_owned())),
            (None, true, true, true),
            2
        ),
        "the guard must refuse only the matched refresh while unrelated capture recovery converges"
    );
    assert!(cases > 0, "the paired state table must execute cases");
}

#[tokio::test]
async fn landed_replay_classifier_fails_closed() {
    let valid = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut valid) = valid.reload_carrier();
    let one = valid
        .landed_replay()
        .map(|replay| replay.is_some())
        .map_err(|error| error.to_string());

    let duplicate = landed_refresh_cut().await;
    let root = duplicate
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    duplicate
        .store
        .lock()
        .unwrap()
        .prepare_registration_inner(&root, vec![], &Tick(2_000), |_, _| true)
        .unwrap();
    let (_scratch, _io, _remote, mut duplicate) = duplicate.reload_carrier();
    let two = duplicate
        .landed_replay()
        .map(|replay| replay.is_some())
        .map_err(|error| error.to_string());

    let torn = landed_refresh_cut().await;
    torn.io
        .mutate_recovered("journal", |bytes| bytes.push(0xa5));
    let (_scratch, _io, _remote, mut torn) = torn.reload_carrier();
    let torn = torn
        .landed_replay()
        .map(|replay| replay.is_some())
        .map_err(|error| error.to_string());

    let malformed = landed_refresh_cut().await;
    malformed.io.mutate_recovered("journal", |bytes| {
        let mut clean_ends = Vec::new();
        for end in 1..=bytes.len() {
            if granary_core::overlay_journal::scan_journal(&bytes[..end]).is_ok_and(|scan| {
                scan.end == granary_core::overlay_journal::JournalEnd::Clean
                    && scan.valid_len == end
            }) {
                clean_ends.push(end);
            }
        }
        let first_frame_end = clean_ends
            .get(1)
            .copied()
            .expect("the landed journal must have a record before its landing witness");
        let byte = bytes
            .get_mut(first_frame_end - 1)
            .expect("the first record check byte must exist");
        *byte ^= 0xff;
    });
    let (_scratch, _io, _remote, mut malformed) = malformed.reload_carrier();
    let malformed = malformed
        .landed_replay()
        .map(|replay| replay.is_some())
        .map_err(|error| error.to_string());

    assert_eq!(
        ((one, two, torn, malformed), 4),
        (
            (
                Ok(true),
                Err("intent refused: IntentLandedReplayInvalid".to_owned()),
                Ok(true),
                Err("intent refused: IntentLandedReplayInvalid".to_owned()),
            ),
            4
        ),
        "classifier must admit a tolerated torn tail and refuse ambiguous or corrupt evidence"
    );
}

#[tokio::test]
async fn landed_replay_journal_io_keeps_io_class_and_malformed_fails_closed() {
    let transient = landed_refresh_cut().await;
    let (_scratch, io, _remote, mut transient) = transient.reload_carrier();
    io.0.lock().unwrap().fail = Some("length");
    let transient = transient.landed_replay().unwrap_err();

    let malformed = landed_refresh_cut().await;
    malformed.io.mutate_recovered("journal", |bytes| {
        let byte = bytes
            .get_mut(0)
            .expect("the landed journal premise must be nonempty");
        *byte ^= 0xff;
    });
    let (_scratch, _io, _remote, mut malformed) = malformed.reload_carrier();
    let malformed = malformed.landed_replay().unwrap_err();

    assert_eq!(
        (
            matches!(
                &transient,
                CoordinationError::Overlay(crate::OverlayError::Io(_))
            ),
            crate::writable_start::coordination_class(&transient),
            malformed.to_string(),
            2,
        ),
        (
            true,
            crate::FailureClass::Io,
            "intent refused: IntentLandedReplayInvalid".to_owned(),
            2,
        ),
        "journal I/O must retain its class while malformed evidence fails closed"
    );
}

type FileState = (std::path::PathBuf, u64, std::time::SystemTime, Vec<u8>);

/// Every file in every publication scope, temporaries included, with what a
/// durable rewrite changes: the inode, the modification time and the bytes.
#[expect(
    clippy::disallowed_methods,
    reason = "read only a test-owned scratch store's publication directories"
)]
fn publication_files(root: &std::path::Path) -> Vec<FileState> {
    use std::os::unix::fs::MetadataExt as _;
    let mut files = Vec::new();
    for scope in std::fs::read_dir(root.join("publications")).unwrap() {
        for entry in std::fs::read_dir(scope.unwrap().path()).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::metadata(&path).unwrap();
            files.push((
                path.clone(),
                meta.ino(),
                meta.modified().unwrap(),
                std::fs::read(&path).unwrap(),
            ));
        }
    }
    files.sort();
    files
}

fn changed_files(before: &[FileState], after: &[FileState]) -> Vec<std::path::PathBuf> {
    let mut changed: Vec<_> = before
        .iter()
        .filter(|file| !after.contains(file))
        .chain(after.iter().filter(|file| !before.contains(file)))
        .map(|file| file.0.clone())
        .collect();
    changed.sort();
    changed.dedup();
    changed
}

/// The cut carrier, reloaded, with its registered root moved to the landed
/// one so `landed_refresh_registered` reaches the retained record, and a
/// leftover temporary beside that record for a read to leave alone.
#[expect(
    clippy::disallowed_methods,
    reason = "plant one leftover temporary in a test-owned scratch store"
)]
async fn landed_replay_store() -> (Scratch, Vec<u8>, WritableStore<SimIo>) {
    use std::os::unix::fs::PermissionsExt as _;
    let cut = landed_refresh_cut().await;
    let (scratch, _io, remote, mut local) = cut.reload_carrier();
    let landed = remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    local.set_carrier_root_for_test(landed.clone()).unwrap();
    let record = publication_files(&scratch.0)
        .into_iter()
        .map(|file| file.0)
        .find(|path| path.extension().is_some_and(|e| e == "sub"))
        .expect("premise: the cut must retain the landed publication");
    let leftover = record.with_extension("sub.tmp-9");
    std::fs::write(&leftover, b"leftover").unwrap();
    std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o600)).unwrap();
    (scratch, landed, local)
}

type Classified = (Result<bool, String>, Result<bool, String>);

/// What one pass of the landed-replay wait loop and one landing refresh each
/// ask of the retained publication.
fn classify(local: &mut WritableStore<SimIo>, landed: &[u8]) -> Classified {
    (
        local
            .landed_replay()
            .map(|replay| replay.is_some())
            .map_err(|error| error.to_string()),
        local
            .landed_refresh_registered(landed, false)
            .map_err(|error| error.to_string()),
    )
}

#[tokio::test]
async fn landed_classifier_leaves_the_publication_directory_untouched() {
    let (scratch, landed, mut local) = landed_replay_store().await;
    let before = publication_files(&scratch.0);
    let classified = classify(&mut local, &landed);
    let after = publication_files(&scratch.0);
    assert_eq!(
        (
            classified,
            before.len(),
            changed_files(&before, &after),
            before
                .iter()
                .any(|file| file.0.to_string_lossy().contains(".tmp-")),
        ),
        ((Ok(true), Ok(false)), 2, vec![], true),
        "classifying must neither rewrite the record's generation nor clean the leftover temporary"
    );
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "damage one record in a test-owned scratch store"
)]
async fn landed_classifier_read_keeps_the_record_custody_and_decode_checks() {
    use std::os::unix::fs::PermissionsExt as _;
    let mut cases = 0;
    let mut outcomes = Vec::new();
    for damage in ["intact", "bytes", "mode"] {
        let (scratch, landed, mut local) = landed_replay_store().await;
        let record = publication_files(&scratch.0)
            .into_iter()
            .map(|file| file.0)
            .find(|path| path.extension().is_some_and(|e| e == "sub"))
            .unwrap();
        match damage {
            "bytes" => {
                let mut bytes = std::fs::read(&record).unwrap();
                *bytes.last_mut().unwrap() ^= 0xff;
                std::fs::write(&record, bytes).unwrap();
            }
            "mode" => {
                std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => {}
        }
        outcomes.push((damage, classify(&mut local, &landed)));
        cases += 1;
    }
    let invalid = || Err("intent refused: IntentLandedReplayInvalid".to_owned());
    assert_eq!(
        (outcomes, cases),
        (
            vec![
                ("intact", (Ok(true), Ok(false))),
                ("bytes", (invalid(), invalid())),
                ("mode", (invalid(), invalid())),
            ],
            3
        ),
        "the read path must refuse a record that fails decode or custody, as the write path did"
    );
}

/// The kind of a publication failure and whether it names the injected device
/// failure.
fn sync_failure(result: Result<impl Sized, crate::CoordinationError>) -> Option<(bool, bool)> {
    match result {
        Err(crate::CoordinationError::Publication(error)) => Some((
            error.kind == crate::PublicationStoreErrorKind::Io,
            error.reason.contains("Input/output error"),
        )),
        _ => None,
    }
}

#[tokio::test]
async fn landed_classifier_barrier_sync_failure_is_io_and_writes_nothing() {
    let (scratch, landed, mut local) = landed_replay_store().await;
    local.fail_publication_file_sync_for_test(true);
    let before = publication_files(&scratch.0);
    let failed = (
        sync_failure(local.landed_replay()),
        sync_failure(local.landed_refresh_registered(&landed, false)),
    );
    let after = publication_files(&scratch.0);
    // Nothing was written, so nothing is poisoned: the next pass classifies.
    local.fail_publication_file_sync_for_test(false);
    let recovered = classify(&mut local, &landed);
    // The control runs last: a failed write poisons the store for good.
    local.fail_publication_file_sync_for_test(true);
    let config = config(&scratch.0);
    let write = local
        .publication_transaction(|store| store.load(&config.scope, &config.volume))
        .map(|_| ())
        .map_err(|error| error.to_string());
    assert_eq!(
        (
            write
                .as_ref()
                .is_err_and(|error| error.contains("Input/output error")),
            failed,
            changed_files(&before, &after),
            recovered,
        ),
        (
            true,
            (Some((true, true)), Some((true, true))),
            vec![],
            (Ok(true), Ok(false)),
        ),
        "a sync failing in the read barrier must stay an I/O failure, never IntentLandedReplayInvalid, and must not rewrite or poison"
    );
}

#[tokio::test]
async fn landed_replay_wait_loop_writes_nothing_per_pass() {
    let (scratch, landed, mut local) = landed_replay_store().await;
    let passes = crate::DEFAULT_RESOLUTION_BOUND.as_secs();
    let mut states = vec![publication_files(&scratch.0)];
    let mut results = Vec::new();
    for _ in 0..passes {
        results.push(classify(&mut local, &landed));
        states.push(publication_files(&scratch.0));
    }
    states.dedup();
    assert_eq!(
        (
            results
                .iter()
                .filter(|r| **r == (Ok(true), Ok(false)))
                .count(),
            states.len(),
            passes,
        ),
        (30, 1, 30),
        "every pass of the 30 s wait loop must classify without a durable publication write"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the five exact readback outcomes share one discriminating tuple and case count"
)]
async fn expired_landed_replay_readback_settles_only_exact_rows() {
    let refresh = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut refresh) = refresh.reload_carrier();
    let replay = refresh.landed_replay().unwrap().unwrap();
    let sent = intent::decode_register(
        replay.request().bytes(),
        replay.request().volume(),
        |_, _| true,
    )
    .unwrap();
    let refresh_row = intent::ReadbackRow {
        writer: sent.writer,
        epoch: sent.epoch,
        generation: sent.generation,
        root: sent.root,
    };
    refresh
        .settle_expired_landed_replay(&replay, Some(&refresh_row), &Tick(replay.expires()))
        .unwrap();
    let refresh_result = (
        refresh.landed_replay().unwrap().is_none(),
        intent::decode_receipt(&refresh.snapshot().current)
            .unwrap()
            .generation,
        refresh
            .prepare_succession(&Tick(replay.expires() + 1))
            .is_ok(),
    );

    let prior = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut prior) = prior.reload_carrier();
    let replay = prior.landed_replay().unwrap().unwrap();
    let current = intent::decode_receipt(&prior.snapshot().current).unwrap();
    let current_root = prior.snapshot().root.clone();
    let prior_row = intent::ReadbackRow {
        writer: current.writer,
        epoch: current.epoch,
        generation: current.generation,
        root: &current_root,
    };
    prior
        .settle_expired_landed_replay(&replay, Some(&prior_row), &Tick(replay.expires()))
        .unwrap();
    let prior_result = (
        prior.landed_replay().unwrap().is_none(),
        intent::decode_receipt(&prior.snapshot().current)
            .unwrap()
            .generation,
        prior
            .prepare_succession(&Tick(replay.expires() + 1))
            .is_ok(),
    );

    let different = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut different) = different.reload_carrier();
    let replay = different.landed_replay().unwrap().unwrap();
    let current = intent::decode_receipt(&different.snapshot().current).unwrap();
    let other_root = root(different.writer_uuid(), 99);
    let different_row = intent::ReadbackRow {
        writer: current.writer,
        epoch: current.epoch + 1,
        generation: current.generation + 1,
        root: &other_root,
    };
    let different_error = different
        .settle_expired_landed_replay(&replay, Some(&different_row), &Tick(replay.expires()))
        .err()
        .map(|error| error.to_string());
    let different_result = (
        different_error,
        different.landed_replay().unwrap().is_some(),
        different
            .prepare_succession(&Tick(replay.expires() + 1))
            .err()
            .map(|error| error.to_string()),
    );

    let absent = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut absent) = absent.reload_carrier();
    let replay = absent.landed_replay().unwrap().unwrap();
    let absent_error = absent
        .settle_expired_landed_replay(&replay, None, &Tick(replay.expires()))
        .err()
        .map(|error| error.to_string());
    let absent_result = (
        absent_error,
        absent.landed_replay().unwrap().is_some(),
        absent
            .prepare_succession(&Tick(replay.expires() + 1))
            .err()
            .map(|error| error.to_string()),
    );

    let duplicate = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut duplicate) = duplicate.reload_carrier();
    let replay = duplicate.landed_replay().unwrap().unwrap();
    let sent = intent::decode_register(
        replay.request().bytes(),
        replay.request().volume(),
        |_, _| true,
    )
    .unwrap();
    let row = intent::ReadbackRow {
        writer: sent.writer,
        epoch: sent.epoch,
        generation: sent.generation,
        root: sent.root,
    };
    let rows = [row, row];
    let duplicate_error = match crate::writable_start::unique_writer_row(&rows, sent.writer) {
        Ok(row) => duplicate
            .settle_expired_landed_replay(&replay, row, &Tick(replay.expires()))
            .err()
            .map_or_else(|| "settled".to_owned(), |error| error.to_string()),
        Err(error) => error.to_string(),
    };
    let duplicate_result = (
        duplicate_error,
        duplicate.landed_replay().unwrap().is_some(),
        duplicate
            .prepare_succession(&Tick(replay.expires() + 1))
            .err()
            .map(|error| error.to_string()),
    );

    assert_eq!(
        (
            (
                refresh_result,
                prior_result,
                different_result,
                absent_result,
                duplicate_result
            ),
            5,
        ),
        (
            (
                (true, 2, true),
                (true, 1, true),
                (
                    Some("intent refused: IntentExpiredRegisterUnresolved".to_owned()),
                    true,
                    Some("intent refused: IntentReplayPending".to_owned()),
                ),
                (
                    Some("intent refused: IntentExpiredRegisterUnresolved".to_owned()),
                    true,
                    Some("intent refused: IntentReplayPending".to_owned()),
                ),
                (
                    "WritableIntentDiscoveryInvalid".to_owned(),
                    true,
                    Some("intent refused: IntentReplayPending".to_owned()),
                ),
            ),
            5
        ),
        "expired refresh, pre-refresh, different, absent and duplicate readbacks must have exact outcomes"
    );
}

#[tokio::test]
async fn landed_replay_retry_reaching_expiry_settles_by_readback() {
    let fixture = landed_refresh_cut().await;
    let (scratch, io, _remote, mut local) = fixture.reload_carrier();
    let replay = local.landed_replay().unwrap().unwrap();
    let sent = intent::decode_register(
        replay.request().bytes(),
        replay.request().volume(),
        |_, _| true,
    )
    .unwrap();
    let sent = (sent.writer, sent.epoch, sent.generation, sent.root.to_vec());
    local
        .dispatch_landed_replay(replay.request(), &Tick(2_000_000))
        .unwrap();
    let completion = local
        .complete_landed_replay(
            replay.request(),
            Err(IntentTransportError::Transport),
            &Tick(2_000_001),
            &mut SeededRng::new(1),
            replay.expires(),
            None,
        )
        .map_err(|error| error.to_string());
    let eligible = local
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.body == replay.request().bytes())
        .map(|pending| pending.eligible);
    drop(local);
    io.crash();
    let mut later = start(&scratch, &io, 121);
    let later_replay = later.landed_replay().unwrap().unwrap();
    let row = intent::ReadbackRow {
        writer: sent.0,
        epoch: sent.1,
        generation: sent.2,
        root: &sent.3,
    };
    let settled = later
        .settle_expired_landed_replay(&later_replay, Some(&row), &Tick(later_replay.expires()))
        .map(|()| {
            intent::decode_receipt(&later.snapshot().current)
                .unwrap()
                .generation
        })
        .map_err(|error| error.to_string());
    assert_eq!(
        (
            (
                completion,
                eligible,
                settled,
                later.landed_replay().unwrap().is_none()
            ),
            1
        ),
        (
            (
                Ok(IntentCompletion::Unknown),
                Some(replay.expires()),
                Ok(2),
                true
            ),
            1
        ),
        "a retry crossing expiry must preserve R for authenticated readback settlement"
    );
}

#[test]
fn landed_replay_wait_accepts_past_and_equal_eligibility_without_panicking() {
    let mut cases = 0;
    for (eligible, expected) in [(900, None), (1_000, None), (1_100, Some(100))] {
        let observed = std::panic::catch_unwind(|| {
            crate::writable_store::landed_replay_wait(1_000, eligible, 31_000)
        })
        .map_err(|_| "wait panicked")
        .map(|result| result.map_err(|error| error.to_string()));
        assert_eq!(
            observed,
            Ok(Ok(expected)),
            "eligible={eligible}: a ready replay must not evaluate a negative delay"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn landed_replay_wait_refuses_a_retry_beyond_the_start_bound() {
    let near = crate::writable_store::landed_replay_wait(1_000, 1_100, 31_000)
        .map_err(|error| error.to_string());
    let hostile = crate::writable_store::landed_replay_wait(1_000, 86_400_000, 31_000)
        .map_err(|error| error.to_string());
    assert_eq!(
        ((near, hostile), 2),
        (
            (
                Ok(Some(100)),
                Err("intent refused: IntentStartupAttemptsExhausted".to_owned()),
            ),
            2,
        ),
        "a replay wait may use the remaining start bound but never R's retained horizon"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the paired exhaustion and accepted-eighth schedules share one exact budget assertion"
)]
async fn landed_replay_shares_the_startup_attempt_bound() {
    let exhausted = transport_failed_landed_refresh().await;
    let (_scratch, _io, _remote, mut exhausted) = exhausted.reload_carrier();
    let replay = exhausted.landed_replay().unwrap().unwrap();
    for seed in 0..8 {
        let eligible = exhausted
            .snapshot()
            .pending
            .iter()
            .find(|pending| pending.body == replay.request().bytes())
            .unwrap()
            .eligible;
        exhausted
            .dispatch_landed_replay(replay.request(), &Tick(eligible))
            .unwrap();
        assert!(matches!(
            exhausted.complete_landed_replay(
                replay.request(),
                Err(IntentTransportError::Transport),
                &Tick(eligible + 1),
                &mut SeededRng::new(seed),
                0,
                None,
            ),
            Ok(IntentCompletion::Unknown)
        ));
    }
    let eligible = exhausted
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.body == replay.request().bytes())
        .unwrap()
        .eligible;
    let exhausted_result = (
        exhausted
            .dispatch_landed_replay(replay.request(), &Tick(eligible))
            .err()
            .map(|error| error.to_string()),
        exhausted
            .snapshot()
            .pending
            .iter()
            .find(|pending| pending.body == replay.request().bytes())
            .map(|pending| (pending.terminal, pending.attempts)),
    );

    let accepted = transport_failed_landed_refresh().await;
    let (scratch, io, remote, mut accepted) = accepted.reload_carrier();
    let replay = accepted.landed_replay().unwrap().unwrap();
    for seed in 0..7 {
        let eligible = accepted
            .snapshot()
            .pending
            .iter()
            .find(|pending| pending.body == replay.request().bytes())
            .unwrap()
            .eligible;
        accepted
            .dispatch_landed_replay(replay.request(), &Tick(eligible))
            .unwrap();
        accepted
            .complete_landed_replay(
                replay.request(),
                Err(IntentTransportError::Transport),
                &Tick(eligible + 1),
                &mut SeededRng::new(seed),
                0,
                None,
            )
            .unwrap();
    }
    let eligible = accepted
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.body == replay.request().bytes())
        .unwrap()
        .eligible;
    accepted
        .dispatch_landed_replay(replay.request(), &Tick(eligible))
        .unwrap();
    let answer = remote.authority.lock().unwrap().send(replay.request());
    accepted
        .complete_landed_replay(
            replay.request(),
            Ok(&answer),
            &Tick(eligible + 1),
            &mut SeededRng::new(8),
            0,
            None,
        )
        .unwrap();
    let transfer = accepted.prepare_succession(&Tick(eligible + 2)).unwrap();
    let accepted_result = (
        intent::decode_receipt(&accepted.snapshot().current)
            .unwrap()
            .generation,
        accepted
            .dispatch(&transfer, &Tick(eligible + 2))
            .err()
            .map(|error| error.to_string()),
    );
    drop(accepted);
    io.crash();
    let mut restarted = start(&scratch, &io, 121);
    let next_start = (
        restarted.landed_replay().unwrap().is_none(),
        restarted
            .retained_requests()
            .iter()
            .filter(|request| request.operation() == Operation::Register)
            .count(),
    );

    assert_eq!(
        ((exhausted_result, accepted_result, next_start), 2),
        (
            (
                (
                    Some("intent refused: IntentStartupAttemptsExhausted".to_owned()),
                    Some((false, 16)),
                ),
                (
                    2,
                    Some("intent refused: IntentStartupAttemptsExhausted".to_owned()),
                ),
                (true, 0),
            ),
            2
        ),
        "the replay and succession must share one eight-send start budget"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the refusal, displacement and overtake controls share one no-succession assertion"
)]
async fn landed_replay_refusal_displacement_and_overtake_stop_before_succession() {
    let terminal = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut terminal) = terminal.reload_carrier();
    let replay = terminal.landed_replay().unwrap().unwrap();
    terminal
        .dispatch_landed_replay(replay.request(), &Tick(2_000_000))
        .unwrap();
    let refusal = reply(403, Some("no-principal"), None, vec![]);
    let terminal_result = terminal
        .complete_landed_replay(
            replay.request(),
            Ok(&refusal),
            &Tick(2_000_001),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .err()
        .map(|error| error.to_string());

    let displaced = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut displaced) = displaced.reload_carrier();
    let replay = displaced.landed_replay().unwrap().unwrap();
    let sent = intent::decode_register(
        replay.request().bytes(),
        replay.request().volume(),
        |_, _| true,
    )
    .unwrap();
    displaced
        .dispatch_landed_replay(replay.request(), &Tick(2_000_000))
        .unwrap();
    let successor = Receipt {
        writer: sent.writer,
        epoch: sent.epoch + 1,
        instance: sent.instance,
        generation: sent.generation,
        state: ReceiptState::Live {
            prepared_root_id: sent.root_id(),
        },
    };
    let displaced_reply = reply(
        409,
        Some("intent-superseded"),
        Some(intent::MEDIA_RECEIPT),
        intent::encode_receipt(successor).unwrap(),
    );
    let displaced_result = (
        matches!(
            displaced.complete_landed_replay(
                replay.request(),
                Ok(&displaced_reply),
                &Tick(2_000_001),
                &mut SeededRng::new(1),
                0,
                None,
            ),
            Err(CoordinationError::Fenced { .. })
        ),
        displaced.snapshot().phase,
    );

    let overtaken = landed_refresh_cut().await;
    let (_scratch, _io, _remote, mut overtaken) = overtaken.reload_carrier();
    let replay = overtaken.landed_replay().unwrap().unwrap();
    let sent = intent::decode_register(
        replay.request().bytes(),
        replay.request().volume(),
        |_, _| true,
    )
    .unwrap();
    overtaken
        .dispatch_landed_replay(replay.request(), &Tick(2_000_000))
        .unwrap();
    let covering = Receipt {
        writer: sent.writer,
        epoch: sent.epoch,
        instance: sent.instance,
        generation: sent.generation + 1,
        state: ReceiptState::Live {
            prepared_root_id: sent.root_id(),
        },
    };
    let overtake_reply = reply(
        409,
        Some("intent-superseded"),
        Some(intent::MEDIA_RECEIPT),
        intent::encode_receipt(covering).unwrap(),
    );
    let overtake_result = overtaken
        .complete_landed_replay(
            replay.request(),
            Ok(&overtake_reply),
            &Tick(2_000_001),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .err()
        .map(|error| error.to_string());
    let ownership_before_followup = [&terminal, &displaced, &overtaken]
        .into_iter()
        .map(|local| {
            local
                .snapshot()
                .pending
                .iter()
                .filter(|pending| pending.operation == Operation::Ownership && !pending.terminal)
                .count()
        })
        .sum::<usize>();
    let followup = (
        terminal
            .prepare_succession(&Tick(2_000_002))
            .map(|_| "prepared")
            .map_err(|error| error.to_string()),
        displaced
            .prepare_succession(&Tick(2_000_002))
            .map(|_| "prepared")
            .map_err(|error| error.to_string()),
        overtaken
            .prepare_succession(&Tick(2_000_002))
            .map(|_| "prepared")
            .map_err(|error| error.to_string()),
    );

    assert_eq!(
        (
            terminal_result,
            displaced_result,
            overtake_result,
            ownership_before_followup,
            followup,
            3,
        ),
        (
            Some("sync authorization refused".to_owned()),
            (true, Phase::Fenced),
            Some("intent refused: IntentCoveringRootUnknown".to_owned()),
            0,
            (
                Ok("prepared"),
                Err("intent fenced (ESTALE), recorded generation Some(2)".to_owned()),
                Err("intent refused: IntentReplayPending".to_owned()),
            ),
            3,
        ),
        "terminal refusal, displacement and unsupported overtake must not fall through to takeover"
    );
}

#[tokio::test]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
)]
async fn conflict_fenced_restart_subcases_keep_their_current_outcomes() {
    let stale = Fixture::new().await;
    stale.create("local", b"sealed");
    stale
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let (_, _, _, _, record) = stale.store.lock().unwrap().recovered_commit().unwrap();
    let mut answered = record.clone();
    let attempt = answered.candidates[0].evidence.start().unwrap();
    answered.candidates[0]
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    answered.last_response = Some(granary_core::retained_submission::LastResponse {
        candidate: 1,
        attempt,
        status: 409,
        token: b"stale-base".to_vec(),
        answer: vec![],
    });
    answered.generation += 1;
    stale
        .store
        .lock()
        .unwrap()
        .publication_transaction(|journal| journal.replace(record.generation, &answered))
        .unwrap();
    assert!(crate::sync::terminal_non_landing(&answered));
    let stale = stale.restart().await;
    let stripped = stale
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|overlay| overlay.recovery_commits())
        .unwrap();
    assert_eq!(
        (
            stripped.is_empty(),
            stale.engine.recover_commit(SyncOptions::default()).is_err(),
            stale.remote.publication_sends.lock().unwrap().len(),
        ),
        (true, true, 0)
    );

    let unsent = Fixture::new().await;
    unsent.create("local", b"sealed");
    let lane = unsent
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    rebase::foreign_head(&unsent, "local").await;
    let first = Box::pin(unsent.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    let unsent = unsent.restart().await;
    let record = rebase::load(&unsent);
    assert_eq!(
        (
            matches!(first, Err(CoordinationError::Fenced { .. })),
            crate::sync::terminal_non_landing(&record),
            unsent.remote.publication_sends.lock().unwrap().len(),
            reporting::counter(&unsent, "granary_client_commits_total{result=\"conflict\"}"),
        ),
        (true, false, 0, 1)
    );
    let lane = unsent
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    let second = Box::pin(unsent.engine.drive_commit(
        &lane,
        &mut Entropy(81),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            matches!(second, Err(CoordinationError::Fenced { .. })),
            unsent.remote.publication_sends.lock().unwrap().len(),
            reporting::counter(&unsent, "granary_client_commits_total{result=\"conflict\"}"),
        ),
        (true, 0, 2),
        "{second:?}"
    );
}

/// The same commit with the point disarmed lands once; tracing shows the path
/// still reaches the point, so the armed row stops at a point that is there.
async fn commit_fault_control(phase: &'static str) {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.trace_sync();
    let error = first_commit_fault(&fixture, phase).await;
    let rebases = phase.ends_with("rebase");
    let reached: Vec<_> = faults
        .sync_fired()
        .iter()
        .filter(|event| (event.name, event.phase) == ("sync.commit", phase))
        .map(|event| event.occurrence)
        .collect();
    assert_eq!(
        (error.is_none(), reached.first(), fixture.registered().seq),
        (true, Some(&1), 2 + u64::from(rebases)),
        "{phase}: a disarmed point must let the commit land once"
    );
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_file(&fixture, &root, "local", b"sealed");
}

/// Arm the point, check the durable crash state it leaves, write after the
/// boundary, restart and drive recovery: one landing of the sealed bytes. The
/// write after the boundary is never fsynced here, and an engine fsync cannot
/// finish while a commit is held, so nothing asserts it survives; the
/// simulator's commit fault rows carry that acknowledged-fsync coverage with
/// real fsyncs.
#[expect(
    clippy::too_many_lines,
    reason = "one crash table keeps durable premises, replay order and final convergence together"
)]
async fn commit_fault_restart(
    phase: &'static str,
    retained: Option<(&'static str, usize)>,
    journaled: (bool, bool),
    pending_refresh: Option<bool>,
    intent: RecoveryIntent,
) {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", phase, 1, FaultAction::Fail);
    let rebases = phase.ends_with("rebase");
    let error = first_commit_fault(&fixture, phase).await;
    assert_eq!(
        (
            error.is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
            faults
                .sync_fired()
                .iter()
                .map(|event| (event.name, event.phase, event.occurrence))
                .collect::<Vec<_>>(),
            fixture.registered().seq,
            durable_commit_state(&fixture),
        ),
        (
            true,
            vec![("sync.commit", phase, 1)],
            1 + u64::from(journaled.1),
            (retained, journaled)
        ),
        "{phase}: the fault must leave exactly its crash state"
    );
    if let Some(pending_refresh) = pending_refresh {
        let volume = fixture.store.lock().unwrap().snapshot().volume.clone();
        let pending_roots: Vec<_> = fixture
            .pending_registrations()
            .iter()
            .map(|pending| {
                intent::decode_register(&pending.body, &volume, |_, _| true)
                    .unwrap()
                    .root
                    .to_vec()
            })
            .collect();
        let expected = if pending_refresh {
            vec![
                fixture
                    .remote
                    .published
                    .lock()
                    .unwrap()
                    .last_key_value()
                    .unwrap()
                    .1
                    .clone(),
            ]
        } else {
            Vec::new()
        };
        assert_eq!(
            pending_roots, expected,
            "{phase}: the crash state must distinguish a persisted refresh from a pre-persist cut"
        );
    }
    let exact_refresh = (phase == "landed_refresh").then(|| {
        fixture
            .pending_registrations()
            .iter()
            .find(|pending| !pending.terminal)
            .expect("landed_refresh must retain its exact Register")
            .body
            .clone()
    });
    let sends_before_restart = fixture.remote.authority.lock().unwrap().sends.len();
    fixture.create("after", b"written after the boundary");
    let fixture = fixture.restart().await;
    if let Some(refresh) = exact_refresh {
        let authority = fixture.remote.authority.lock().unwrap();
        let restart_sends = &authority.sends[sends_before_restart..];
        assert_eq!(
            (
                fixture.remote.attempts.lock().unwrap().as_slice(),
                restart_sends.first().map(Vec::as_slice),
                restart_sends.get(1).is_some_and(|request| {
                    intent::decode_ownership(request)
                        .is_ok_and(|request| matches!(request.mode, OwnershipMode::Takeover { .. }))
                }),
            ),
            ([refresh.clone()].as_slice(), Some(refresh.as_slice()), true),
            "landed_refresh: the exact retained Register must be the restart's only registration and precede takeover"
        );
    }
    if retained.is_none() {
        assert!(
            fixture
                .engine
                .recover_commit(SyncOptions::default())
                .is_err(),
            "{phase}: restart must discard a boundary no submission follows"
        );
        // The discarded boundary's writes are dirty again, so one fresh commit
        // publishes the sealed file.
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(83))
            .await
            .unwrap();
        Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(84),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
    } else {
        restart_drives_the_lane(&fixture, phase, intent).await;
    }
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_eq!(
        fixture.registered().seq,
        2 + u64::from(rebases),
        "{phase}: recovery must converge on one landing of the commit"
    );
    assert_file(&fixture, &root, "local", b"sealed");
    if rebases {
        assert_file(&fixture, &root, "remote", b"");
    }
}

/// A fault between the journaled refresh and the base replacement leaves the
/// landing and its refresh done, so driving the same lane again installs the
/// landed base without publishing a second time.
#[tokio::test]
async fn retry_after_the_replace_fault_installs_the_landed_base_without_resending() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "before_replace", 1, FaultAction::Fail);
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let mut outcomes = Vec::new();
    let mut intent_sends = Vec::new();
    let mut refresh_markers = Vec::new();
    for seed in [80, 81] {
        let result = Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(seed),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        // (landed, stopped by the injected fault)
        outcomes.push(match result {
            Ok(result) => (
                matches!(result.outcome, PublicationOutcome::Landed(_)),
                false,
            ),
            Err(error) => (false, error.to_string().contains("SyncInjectedFault")),
        });
        intent_sends.push(fixture.remote.authority.lock().unwrap().sends.len());
        refresh_markers.push(fixture.store.lock().unwrap().landing_refresh_for_test());
    }
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_eq!(
        (
            outcomes,
            fixture.remote.publication_sends.lock().unwrap().len(),
            fixture.registered().seq,
            intent_sends,
            refresh_markers,
        ),
        (
            vec![(false, true), (true, false)],
            1,
            2,
            vec![3, 3],
            vec![None, None],
        ),
        "the faulted drive must fail and the retry must land the one candidate"
    );
    assert_file(&fixture, &root, "local", b"sealed");
}

/// Construct and drive a commit past an armed fault, after a foreign head when
/// the point is on the rebase path. A boundary fault stops construction itself.
async fn first_commit_fault(fixture: &Fixture, phase: &str) -> Option<CoordinationError> {
    let lane = match fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
    {
        Ok(lane) => lane,
        Err(error) => return Some(error),
    };
    if phase.ends_with("rebase") {
        rebase::foreign_head(fixture, "remote").await;
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::StaleCurrent, PublishPlan::Land]);
    }
    Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .err()
}

/// The retained phase and candidate count, and whether the journal bytes a crash
/// right now would recover hold a landing and its refresh. Nothing is flushed
/// first, so a record appended without its own sync barrier does not count.
fn durable_commit_state(fixture: &Fixture) -> (Option<(&'static str, usize)>, (bool, bool)) {
    use granary_core::retained_submission::Phase;
    let mut local = fixture.store.lock().unwrap();
    let scope = local.snapshot().scope.clone();
    let volume = local.snapshot().volume.clone();
    let retained = local
        .publication_transaction(|j| j.load(&scope, &volume))
        .unwrap()
        .map(|record| {
            let phase = match record.phase {
                Phase::Rebase => "rebase",
                Phase::Ready => "ready",
                Phase::Complete(_) => "complete",
                _ => "other",
            };
            (phase, record.candidates.len())
        });
    drop(local);
    let journal = fixture
        .io
        .recovered_bytes("journal")
        .expect("the journal's name must be durable");
    let mut journaled = (false, false);
    granary_core::overlay_journal::scan_journal_with(&journal, |_, record| match record {
        Record::LandedCommit { .. } => journaled.0 = true,
        Record::IntentRegistered {
            cause: granary_core::overlay_journal::IntentCause::LandedRefresh,
            ..
        } => journaled.1 = true,
        _ => {}
    })
    .unwrap();
    (retained, journaled)
}

fn landed_refresh_record_count(fixture: &Fixture) -> usize {
    let journal = fixture
        .io
        .recovered_bytes("journal")
        .expect("the journal's name must be durable");
    let mut count = 0;
    granary_core::overlay_journal::scan_journal_with(&journal, |_, record| {
        if matches!(
            record,
            Record::IntentRegistered {
                cause: granary_core::overlay_journal::IntentCause::LandedRefresh,
                ..
            }
        ) {
            count += 1;
        }
    })
    .unwrap();
    count
}

/// Recover the retained lane after a restart and drive it with the intent its
/// crash state needs. A loaded rebase refuses a plain continuation first.
async fn restart_drives_the_lane(fixture: &Fixture, phase: &str, intent: RecoveryIntent) {
    let lane = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    if phase == "before_rebase" {
        let refused = Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(81),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        assert_eq!(
            (
                matches!(refused.outcome, PublicationOutcome::Unresolved),
                refused
                    .diagnostic
                    .is_some_and(|text| text.contains("explicit recovery required")),
                fixture.registered().seq,
            ),
            (true, true, 1),
            "{phase}: a loaded rebase must not resume without an explicit recovery"
        );
    }
    Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(82),
        &mut Delay,
        intent,
        SyncOptions::default(),
    ))
    .await
    .unwrap_or_else(|error| panic!("{phase}: the restarted lane must land: {error}"));
}

/// A retention closure lost to a panic before its boundary is recorded
/// releases the construction it owned, with its captured boundary and graph
/// charge, before anything else runs: admission reopens and a later sync
/// lands within its deadline.
#[tokio::test]
async fn a_retention_closure_lost_before_its_boundary_releases_the_construction() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let initial = projected::reservations(&fixture);
    fixture
        .engine
        .panic_retention_for_test(crate::sync::RetentionPanic::BeforeRetain);
    let lost = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .err();
    let released = (
        fixture.engine.commit_lane_for_test(),
        projected::lane_closed(&fixture),
        projected::reservations(&fixture),
    );
    let stage = fixture.create("after", b"written after the loss");
    let later = fixture
        .engine
        .sync(
            SyncTarget::Stage(stage),
            SyncOptions {
                resolution_bound: Duration::from_secs(5),
                ..SyncOptions::default()
            },
        )
        .wait()
        .await
        .map_err(|error| error.to_string());
    assert_eq!(
        (lost.map(|error| error.to_string()), released, later),
        (
            Some("intent refused: SyncMaterializationLost".to_owned()),
            ((false, false), false, initial),
            Ok(()),
        ),
        "a lost closure must release its construction so a later sync lands"
    );
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_file(&fixture, &root, "after", b"written after the loss");
}

/// A retention closure lost to a panic after its boundary is durable keeps
/// the lane: the release is refused, the construction stays held, and only a
/// restart recovers and lands the retained candidate.
#[tokio::test]
async fn a_retention_closure_lost_after_its_boundary_keeps_the_lane_for_restart() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    fixture
        .engine
        .panic_retention_for_test(crate::sync::RetentionPanic::AfterRetain);
    let lost = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .err();
    assert_eq!(
        (
            lost.map(|error| error.to_string()),
            fixture.engine.commit_lane_for_test(),
            durable_commit_state(&fixture),
            fixture
                .engine
                .recover_commit(SyncOptions::default())
                .err()
                .map(|error| error.to_string()),
        ),
        (
            Some("intent refused: SyncMaterializationLost".to_owned()),
            (true, false),
            (Some(("ready", 1)), (false, false)),
            Some("intent refused: SyncCommitConstructionPending".to_owned()),
        ),
        "a closure lost after its durable boundary must leave the lane for restart"
    );
    let fixture = fixture.restart().await;
    restart_drives_the_lane(&fixture, "after_retain", RecoveryIntent::Continue).await;
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_eq!(
        fixture.registered().seq,
        2,
        "recovery must converge on one landing of the commit"
    );
    assert_file(&fixture, &root, "local", b"sealed");
}

/// A supervised construction lost to a panic in its own task, with its
/// capture taken and no boundary durable, is released by its monitor: the
/// caller sees the supervisor lost, admission reopens with the captured
/// boundary and graph charge released, and a later sync lands.
#[tokio::test]
async fn a_construction_lost_in_its_task_releases_the_lane() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let initial = projected::reservations(&fixture);
    fixture
        .engine
        .panic_retention_for_test(crate::sync::RetentionPanic::Constructing);
    let lost = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .err();
    let released = (
        fixture.engine.commit_lane_for_test(),
        projected::lane_closed(&fixture),
        projected::reservations(&fixture),
    );
    assert_eq!(fixture.engine.workspace_held_for_test(), 0);
    let stage = fixture.create("after", b"written after the loss");
    let later = fixture
        .engine
        .sync(
            SyncTarget::Stage(stage),
            SyncOptions {
                resolution_bound: Duration::from_secs(5),
                ..SyncOptions::default()
            },
        )
        .wait()
        .await
        .map_err(|error| error.to_string());
    assert_eq!(
        (lost.map(|error| error.to_string()), released, later),
        (
            Some("intent refused: SyncSupervisorLost".to_owned()),
            ((false, false), false, initial),
            Ok(()),
        ),
        "a construction lost in its task must release its lane so a later sync lands"
    );
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_file(&fixture, &root, "after", b"written after the loss");
}

/// A lost task's monitor releases only the construction that task opened.
/// Here the task's own construction was released by its lost retention
/// before the task died, and while its monitor is held another caller
/// opens a construction: the monitor must leave that one held, and it is
/// retained and lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_construction_monitor_leaves_a_later_construction_alone() {
    let f = Fixture::new().await;
    f.create("local", b"sealed");
    f.engine
        .panic_retention_for_test(crate::sync::RetentionPanic::BeforeRetain);
    f.engine
        .panic_retention_for_test(crate::sync::RetentionPanic::AfterLostRetention);
    f.content.hold_lost.store(true, Ordering::Release);
    let first = TokioSyncRuntime.spawn(
        f.engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70)),
    );
    // The held join-error arm clears the hold as it is entered.
    TokioSyncRuntime
        .timeout_at(TokioSyncRuntime.now() + Duration::from_secs(10), async {
            while f.content.hold_lost.load(Ordering::Acquire) {
                TokioSyncRuntime.sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    let released_first = (
        f.engine.commit_lane_for_test(),
        f.engine.construction_for_test(),
    );
    let faults = f.store.lock().unwrap().fault_control();
    let _resume = published::ResumeOnDrop(&faults);
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    let mut second = Box::pin(
        f.engine
            .construct_commit(SyncOptions::default(), &mut Entropy(80)),
    );
    hold_at_seam(&mut second, &faults, "sync.commit", "captured").await;
    let opened = f.engine.construction_for_test();
    f.content.lost_release.notify_one();
    let lost = first.await.unwrap().err().map(|error| error.to_string());
    let held = (
        f.engine.commit_lane_for_test(),
        f.engine.construction_for_test(),
    );
    faults.resume();
    let retained = second.await.map_err(|error| error.to_string());
    let after = (
        f.engine.commit_lane_for_test(),
        f.engine.construction_for_test(),
    );
    assert_eq!(
        (
            released_first,
            opened.is_some(),
            lost,
            held,
            retained.as_ref().err(),
            after,
        ),
        (
            ((false, false), None),
            true,
            Some("intent refused: SyncSupervisorLost".to_owned()),
            ((true, false), opened),
            None,
            ((false, true), None),
        ),
        "a lost task's monitor released a construction another caller opened"
    );
    Box::pin(f.engine.drive_commit(
        &retained.unwrap(),
        &mut Entropy(81),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    let root = f.remote.authority.lock().unwrap().root.clone();
    assert_file(&f, &root, "local", b"sealed");
}

/// A supervised task lost after its candidate's boundary is durable keeps
/// the lane: its monitor's release is refused, the construction and its
/// record stay held, and only a restart recovers and lands the candidate.
#[tokio::test]
async fn a_construction_lost_after_its_boundary_keeps_the_lane_for_restart() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    fixture
        .engine
        .panic_retention_for_test(crate::sync::RetentionPanic::AfterRetain);
    fixture
        .engine
        .panic_retention_for_test(crate::sync::RetentionPanic::AfterLostRetention);
    let lost = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .err();
    assert_eq!(
        (
            lost.map(|error| error.to_string()),
            fixture.engine.commit_lane_for_test(),
            fixture.engine.construction_for_test().is_some(),
            durable_commit_state(&fixture),
            fixture
                .engine
                .recover_commit(SyncOptions::default())
                .err()
                .map(|error| error.to_string()),
        ),
        (
            Some("intent refused: SyncSupervisorLost".to_owned()),
            (true, false),
            true,
            (Some(("ready", 1)), (false, false)),
            Some("intent refused: SyncCommitConstructionPending".to_owned()),
        ),
        "a task lost after its durable boundary must leave the lane for restart"
    );
    let fixture = fixture.restart().await;
    restart_drives_the_lane(&fixture, "after_retain", RecoveryIntent::Continue).await;
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_eq!(
        fixture.registered().seq,
        2,
        "recovery must converge on one landing of the commit"
    );
    assert_file(&fixture, &root, "local", b"sealed");
}

#[tokio::test]
async fn fsync_waits_for_inflight_commit_after_restart_and_refresh() {
    for accepted in [false, true] {
        let fixture = Fixture::new().await;
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        if accepted {
            fixture
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .extend([PublishPlan::Accepted, PublishPlan::Timeout]);
            let entered = Arc::new(Notify::new());
            let mut delay = HeldDelay {
                calls: 0,
                at: 2,
                entered: entered.clone(),
            };
            let mut entropy = Entropy(80);
            let mut driving = Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut entropy,
                &mut delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            ));
            let mut answer = Box::pin(entered.notified());
            std::future::poll_fn(|cx| {
                assert!(
                    driving.as_mut().poll(cx).is_pending(),
                    "driver finished before restart cut"
                );
                answer.as_mut().poll(cx)
            })
            .await;
            drop(driving);
            assert_eq!(fixture.remote.publication_sends.lock().unwrap().len(), 2);
        }
        let fixture = fixture.restart().await;
        let lane = fixture
            .engine
            .recover_commit(SyncOptions::default())
            .unwrap();
        assert_eq!(
            fixture
                .engine
                .recover_commit(SyncOptions::default())
                .unwrap()
                .boundary_seq(),
            lane.boundary_seq()
        );
        let result = fixture
            .engine
            .sync(
                SyncTarget::Directory(None),
                SyncOptions {
                    resolution_bound: Duration::from_millis(1),
                    ..SyncOptions::default()
                },
            )
            .wait()
            .await;
        assert!(result.is_err(), "restart reopened admission on old base");
        assert!(fixture.remote.attempts.lock().unwrap().is_empty());
        Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::ExplicitRecovery,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        let stage = fixture.create("later", b"w");
        fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
            .unwrap();
        assert_eq!(fixture.registered().seq, 3);
        let sends = fixture.remote.publication_sends.lock().unwrap();
        assert!(
            sends.iter().all(|bytes| bytes == &sends[0]),
            "restart changed retained submission bytes"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
)]
async fn restart_reconciles_terminal_rejection_before_sync_admission() {
    let fixture = Fixture::new().await;
    fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    // The answer barrier is durable, but the process dies before disposition.
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Reject);
    let (_, _, _, _, record) = fixture.store.lock().unwrap().recovered_commit().unwrap();
    let mut next = record.clone();
    let attempt = next.candidates[0].evidence.start().unwrap();
    next.candidates[0]
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    next.last_response = Some(granary_core::retained_submission::LastResponse {
        candidate: 1,
        attempt,
        status: 400,
        token: b"invalid-candidate".to_vec(),
        answer: vec![],
    });
    next.generation += 1;
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(record.generation, &next))
        .unwrap();
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let fixture = fixture.restart().await;
    let repeated = fixture.store.lock().unwrap().reconcile_commit_rejection();
    assert_eq!(
        repeated.map_err(|error| error.to_string()),
        Err("intent refused: SyncCommitNotRetained".to_owned()),
        "startup already archived the terminal publication"
    );
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            reporting::counter(&fixture, "granary_client_commits_total{result=\"failed\"}"),
            text.lines()
                .filter(|line| line.contains("\"event\":\"op.failed\"")
                    && line.contains("\"kind\":\"commit\"")
                    && line.contains("\"class\":\"refused\""))
                .count(),
            fixture.metrics().contains("granary_client_contention_flag"),
            text.lines()
                .filter(|line| line.contains("\"event\":\"overlay.refused\"")
                    && line.contains("\"class\":\"refused\""))
                .count()
        ),
        (1, 1, false, 1),
        "startup terminal refusal: {text}\n{}",
        fixture.metrics()
    );
    for _ in 0..3 {
        fixture
            .store
            .lock()
            .unwrap()
            .observe_commit(crate::CommitResult::Ok);
    }
    assert!(
        fixture
            .metrics()
            .contains("granary_client_contention_flag 0\n"),
        "startup outcome missing from window: {}",
        fixture.metrics()
    );
    assert!(
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.recovery_commits())
            .unwrap()
            .is_empty()
    );
    let stage = fixture.create("later", b"w");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn constructed_commit_preserves_sealed_bytes_and_adopts_landed_base() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"sealed bytes");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    let mut secure = Entropy(70);
    let mut constructing = Box::pin(
        fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut secure),
    );
    let mut entered = Box::pin(fired(&faults, "sync.commit", "captured"));
    std::future::poll_fn(|cx| {
        assert!(constructing.as_mut().poll(cx).is_pending());
        entered.as_mut().poll(cx)
    })
    .await;
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 0, b"newer bytes!").map(|_| ()))
        .unwrap();
    faults.resume();
    let lane = constructing.await.unwrap();
    let (_, _, _, _, record) = fixture.store.lock().unwrap().recovered_commit().unwrap();
    assert_file(
        &fixture,
        &record.frozen.initial_root,
        "file",
        b"sealed bytes",
    );
    let result = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    assert!(matches!(result.outcome, PublicationOutcome::Landed(_)));
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let prepared = fixture.remote.authority.lock().unwrap().root.clone();
    assert_file(&fixture, &prepared, "file", b"newer bytes!");
    assert_eq!(
        fixture.registered().parent,
        Some(GrainId::of(&record.frozen.initial_root))
    );
}

/// The landed root becomes the next base only after one walk finds its whole
/// closure in the binmap; a closure with a gap is refused before adoption.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_landed_root_whose_closure_is_not_mapped_refuses_before_adoption() {
    let fixture = Fixture::new().await;
    fixture.create("file", b"sealed bytes");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap()
        .with_mapped(std::collections::BTreeSet::new());
    let error = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap_err();
    assert!(
        matches!(error, CoordinationError::Refused("SyncCommitContainment")),
        "an unmapped landed closure was adopted: {error}"
    );
    assert!(
        !fixture.store.lock().unwrap().sync_admission_open().unwrap(),
        "a refused refresh reopened sync admission"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fsync_waits_for_inflight_commit_across_accepted_failure_and_cancellation() {
    for failure in [
        PublishPlan::Timeout,
        PublishPlan::Internal,
        PublishPlan::RateLimited,
    ] {
        let fixture = Fixture::new().await;
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        fixture.remote.publication_plan.lock().unwrap().extend([
            PublishPlan::Accepted,
            failure,
            PublishPlan::Timeout,
        ]);
        let entered = Arc::new(Notify::new());
        let mut delay = HeldDelay {
            calls: 0,
            at: 3,
            entered: entered.clone(),
        };
        let mut entropy = Entropy(80);
        let mut driving = Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut entropy,
            &mut delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ));
        let mut answer = Box::pin(entered.notified());
        std::future::poll_fn(|cx| {
            assert!(
                driving.as_mut().poll(cx).is_pending(),
                "driver finished before the third saved answer"
            );
            answer.as_mut().poll(cx)
        })
        .await;
        drop(driving);
        assert_eq!(fixture.remote.publication_sends.lock().unwrap().len(), 3);
        let stage = fixture.create("later", b"w");
        let faults = fixture.store.lock().unwrap().fault_control();
        faults.arm("sync.commit_wait", "before", 1, FaultAction::Block);
        let waiter = fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default());
        fired(&faults, "sync.commit_wait", "before").await;
        assert!(
            fixture.remote.attempts.lock().unwrap().is_empty(),
            "sync registered on old base after accepted submission"
        );
        assert_eq!(fixture.marks(), 0);
        drop(waiter);
        faults.resume();
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.truncate(stage, 0))
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.write(stage, 0, b"w").map(|_| ()))
            .unwrap();
        fixture.remote.publication_plan.lock().unwrap().clear();
        Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(90),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
            .unwrap();
        assert_eq!(
            fixture
                .metrics()
                .matches("granary_client_syncs_total{outcome=\"cancelled\"} 1")
                .count(),
            1
        );
        assert_eq!(fixture.registered().seq, 3);
    }
}

#[tokio::test]
async fn fsync_wait_budget_exhaustion_preserves_commit_evidence() {
    let fixture = Fixture::new().await;
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Accepted);
    let entered = Arc::new(Notify::new());
    let mut delay = HeldDelay {
        calls: 0,
        at: 1,
        entered: entered.clone(),
    };
    let mut entropy = Entropy(80);
    let mut driving = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut entropy,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ));
    let mut answer = Box::pin(entered.notified());
    std::future::poll_fn(|cx| {
        assert!(
            driving.as_mut().poll(cx).is_pending(),
            "driver finished before the accepted answer cut"
        );
        answer.as_mut().poll(cx)
    })
    .await;
    drop(driving);
    assert_eq!(fixture.remote.publication_sends.lock().unwrap().len(), 1);
    let stage = fixture.create("later", b"w");
    let result = fixture
        .engine
        .sync(
            SyncTarget::Stage(stage),
            SyncOptions {
                resolution_bound: Duration::from_millis(1),
                ..SyncOptions::default()
            },
        )
        .wait()
        .await;
    assert!(matches!(
        result,
        Err(CoordinationError::Refused(
            "SyncDeadline" | "SyncCommitUnresolved"
        ))
    ));
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    assert_eq!(fixture.marks(), 0);
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit_wait", "before", 8, FaultAction::Block);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    let deadline = TokioSyncRuntime.now() + Duration::from_secs(20);
    while faults.sync_fired().is_empty() && TokioSyncRuntime.now() < deadline {
        TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
    }
    let fired = faults.sync_fired();
    faults.resume();
    assert_eq!(fired.len(), 1, "eighth commit-wait seam missing");
    let result = waiter.wait().await;
    assert!(matches!(
        result,
        Err(CoordinationError::Refused("SyncCommitUnresolved"))
    ));
    assert_eq!(faults.sync_fired()[0].occurrence, 8);
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_commit_construction_retains_one_owned_lane() {
    let fixture = Fixture::new().await;
    fixture.create("file", b"sealed");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    let mut constructing = Box::pin(
        fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70)),
    );
    let mut entered = Box::pin(fired(&faults, "sync.commit", "captured"));
    std::future::poll_fn(|cx| {
        assert!(constructing.as_mut().poll(cx).is_pending());
        entered.as_mut().poll(cx)
    })
    .await;
    assert!(matches!(
        fixture.engine.recover_commit(SyncOptions::default()),
        Err(CoordinationError::Refused("SyncCommitConstructionPending"))
    ));
    drop(constructing);
    faults.resume();
    let deadline = TokioSyncRuntime.now() + Duration::from_secs(2);
    let lane = loop {
        match fixture.engine.recover_commit(SyncOptions::default()) {
            Ok(lane) => break lane,
            Err(CoordinationError::Refused("SyncCommitConstructionPending"))
                if TokioSyncRuntime.now() < deadline =>
            {
                TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
            }
            other => panic!("owned construction did not settle: {other:?}"),
        }
    };
    Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    let objects = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| Ok(t.summary().captured_bytes))
        .unwrap();
    assert_eq!(
        objects, 0,
        "construction recovered or released its charge twice"
    );
}

#[tokio::test]
async fn commit_rebase_preserves_store_writer_and_frozen_namespace() {
    let fixture = Fixture::new().await;
    fixture.create("file", b"acknowledged prefix");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::StaleForeign);
    let stage = fixture.create("later", b"suffix");
    let result = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("rebase failed: {result:?}")
    };
    assert_eq!(done.seq, 3);
    assert_eq!(
        fixture.engine.commit_retry_reasons(),
        vec![crate::RetryReason::Conflict]
    );
    assert_file(&fixture, &done.root, "file", b"acknowledged prefix");
    assert_eq!(
        granary_core::root::decode_root(&done.root)
            .unwrap()
            .writer_uuid,
        fixture.store.lock().unwrap().writer_uuid()
    );
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_eq!(fixture.registered().parent, Some(done.id));
}

#[tokio::test]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
)]
async fn rejected_commit_retires_boundary_without_absorbing_overlay() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"keep bytes");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::Reject);
    let result = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(
        (
            matches!(result.outcome, PublicationOutcome::Refused),
            fixture.engine.workspace_held_for_test()
        ),
        (true, 0)
    );
    let fenced = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.recovery_commits());
    assert!(
        matches!(fenced, Err(CoordinationError::Fenced { .. })),
        "{fenced:?}"
    );
    let fixture = fixture.restart().await;
    assert!(
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.recovery_commits())
            .unwrap()
            .is_empty()
    );
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let root = fixture.remote.authority.lock().unwrap().root.clone();
    assert_file(&fixture, &root, "file", b"keep bytes");
    let next = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(90))
        .await
        .unwrap();
    Box::pin(fixture.engine.drive_commit(
        &next,
        &mut Entropy(100),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
}

#[derive(Default)]
struct RecoveryJournal(Option<granary_core::retained_submission::Submission>);
impl GrainSource for RecoveryJournal {
    fn has(&self, _: &GrainId) -> bool {
        false
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        Err(GrainSourceError::Missing(*id))
    }
}
impl crate::PublicationJournal for RecoveryJournal {
    fn load(
        &mut self,
        _: &granary_core::retained_submission::Scope,
        _: &VolumeName,
    ) -> Result<Option<granary_core::retained_submission::Submission>, crate::PublicationStoreError>
    {
        Ok(self.0.clone())
    }
    fn begin(
        &mut self,
        record: &granary_core::retained_submission::Submission,
    ) -> Result<(), crate::PublicationStoreError> {
        assert!(self.0.is_none());
        self.0 = Some(record.clone());
        Ok(())
    }
    async fn replace(
        &mut self,
        generation: u64,
        record: &granary_core::retained_submission::Submission,
    ) -> Result<(), crate::PublicationStoreError> {
        assert_eq!(self.0.as_ref().unwrap().generation, generation);
        self.0 = Some(record.clone());
        Ok(())
    }
}

fn subsumed(remote: &Remote, prepared: &[u8]) -> bool {
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let doc = granary_core::root::decode_root(prepared).unwrap();
    granary_store::crypto::check_head(prepared, "v", doc.seq, &keys).unwrap();
    let published = remote.published.lock().unwrap();
    let parent_seq = doc.seq.saturating_sub(1).max(1);
    let Some(mut parent) = published.get(&parent_seq).cloned() else {
        return false;
    };
    if match doc.parent {
        Some(id) => id != GrainId::of(&parent),
        None => parent != prepared,
    } {
        return false;
    }
    let head = *published.last_key_value().unwrap().0;
    let mut found = granary_core::root::decode_root(&parent)
        .unwrap()
        .manifest_root
        == doc.manifest_root;
    for seq in parent_seq + 1..=head {
        let bytes = published.get(&seq).unwrap();
        let root = granary_store::crypto::check_head(bytes, "v", seq, &keys).unwrap();
        assert_eq!(root.parent, Some(GrainId::of(&parent)));
        found |= bytes == prepared || root.manifest_root == doc.manifest_root;
        parent = bytes.clone();
    }
    found
}

async fn recover_without_local_store(
    remote: &Remote,
    prepared: Vec<u8>,
) -> BTreeMap<GrainId, Vec<u8>> {
    if !subsumed(remote, &prepared) {
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let keys = TrustedKeys::new([*key.public_key()]).unwrap();
        let result = crate::begin_exact_publication(
            crate::RecoveryParts {
                transport: remote,
                journal: &mut RecoveryJournal::default(),
                publisher_keys: &keys,
                signer: &key,
                secure: &mut Entropy(90),
                clock: remote.time.as_ref(),
                delay: &mut Delay,
            },
            reply(200, None, None, vec![]).scope.unwrap(),
            VolumeName::from_bytes(b"v").unwrap(),
            granary_core::root::decode_root(&prepared)
                .unwrap()
                .writer_uuid,
            prepared,
        )
        .await
        .unwrap();
        assert!(matches!(result.outcome, PublicationOutcome::Landed(_)));
    }
    let seq = remote.max_seq("v").await.unwrap().unwrap();
    let (_, objects) = crate::resolve_at_collecting(remote, "v", seq)
        .await
        .unwrap();
    objects
}

#[expect(
    clippy::too_many_lines,
    reason = "one loss oracle keeps the accepted answer, misclassification, delayed landing and fresh recovery together"
)]
async fn accepted_failure_keeps_acknowledgement_recoverable(failure: PublishPlan) {
    let fixture = Fixture::new().await;
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let (_, _, _, _, candidate) = fixture.store.lock().unwrap().recovered_commit().unwrap();
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Accepted, failure]);
    {
        // Stop waiting after the later response's durable answer barrier, before
        // another send can clear it. Cancellation preserves this evidence.
        let entered = Arc::new(Notify::new());
        let mut delay = HeldDelay {
            calls: 0,
            at: 2,
            entered: entered.clone(),
        };
        let mut secure = Entropy(80);
        let mut driving = Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut secure,
            &mut delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ));
        let mut answer = Box::pin(entered.notified());
        std::future::poll_fn(|cx| {
            assert!(
                driving.as_mut().poll(cx).is_pending(),
                "commit returned before the retained answer cut"
            );
            answer.as_mut().poll(cx)
        })
        .await;
        let sends = fixture.remote.publication_sends.lock().unwrap().len();
        let concurrent = Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(85),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        assert!(
            matches!(
                concurrent,
                Err(CoordinationError::Refused("SyncCommitInFlight"))
            ),
            "concurrent commit driver dispatched"
        );
        assert_eq!(
            fixture.remote.publication_sends.lock().unwrap().len(),
            sends
        );
        drop(driving);
        let _ = fixture.engine.finish_rejected_commit(&lane);
    }
    let stage = fixture.create("later", b"acknowledged w");
    let reopened = fixture.store.lock().unwrap().sync_admission_open().unwrap();
    if reopened {
        // A misclassified accepted request admits P on the old base. The exact
        // already-decided W candidate can still land later without w.
        fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
            .unwrap();
        fixture
            .remote
            .published
            .lock()
            .unwrap()
            .insert(2, candidate.frozen.initial_root);
    } else {
        let blocked = fixture
            .engine
            .sync(
                SyncTarget::Stage(stage),
                SyncOptions {
                    resolution_bound: Duration::from_millis(1),
                    ..SyncOptions::default()
                },
            )
            .wait()
            .await;
        assert!(blocked.is_err());
        assert!(fixture.remote.attempts.lock().unwrap().is_empty());
        fixture.remote.publication_plan.lock().unwrap().clear();
        Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(90),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
            .unwrap();
    }
    let prepared = fixture.remote.authority.lock().unwrap().root.clone();
    let remote = fixture.remote.clone();
    drop(fixture);
    remote.publication_plan.lock().unwrap().clear();
    let recovered = recover_without_local_store(&remote, prepared).await;
    assert!(
        recovered.values().any(|bytes| bytes == b"acknowledged w"),
        "step-zero lost acknowledged w after delayed W landing"
    );
}

#[tokio::test]
async fn accepted_timeout_keeps_acknowledgement_recoverable() {
    Box::pin(accepted_failure_keeps_acknowledgement_recoverable(
        PublishPlan::Timeout,
    ))
    .await;
}
#[tokio::test]
async fn accepted_backend_failure_keeps_acknowledgement_recoverable() {
    Box::pin(accepted_failure_keeps_acknowledgement_recoverable(
        PublishPlan::Internal,
    ))
    .await;
}
#[tokio::test]
async fn accepted_rate_limit_keeps_acknowledgement_recoverable() {
    Box::pin(accepted_failure_keeps_acknowledgement_recoverable(
        PublishPlan::RateLimited,
    ))
    .await;
}

#[tokio::test]
async fn landed_refresh_keeps_the_driver_deadline() {
    let fixture = Fixture::new().await;
    fixture.create("file", b"committed");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(82))
        .await
        .unwrap();
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "landed_readback", 1, FaultAction::Block);
    // The enclosing deadline is far above any real time the driver spends
    // reaching the readback, and is crossed by advancing the paused clock rather
    // than by racing real time. The resolution bound is longer still, so a
    // deadline computed afresh at the readback would not be crossed.
    let bound = Duration::from_secs(10);
    let started = TokioSyncRuntime.now();
    let mut secure = Entropy(83);
    let mut delay = Delay;
    let mut driving = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut secure,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions {
            resolution_bound: Duration::from_mins(1),
            deadline: Some(started + bound),
            ..SyncOptions::default()
        },
    ));
    let mut entered = Box::pin(fired(&faults, "sync.commit", "landed_readback"));
    std::future::poll_fn(|cx| {
        assert!(
            driving.as_mut().poll(cx).is_pending(),
            "driver finished before readback"
        );
        entered.as_mut().poll(cx)
    })
    .await;
    let fired_count = faults.sync_fired().len();
    tokio::time::pause();
    tokio::time::advance(bound).await;
    faults.resume();
    let result = driving.await;
    assert_eq!(
        (
            fired_count,
            TokioSyncRuntime.now() >= started + bound,
            matches!(result, Err(CoordinationError::Refused("SyncDeadline")))
        ),
        (1, true, true),
        "landed verification must retain the enclosing driver's deadline: error={:?}",
        result.as_ref().err()
    );
}

/// The landing reads its root back bound to the stored landing's id: bytes the
/// store holds at the landed seq that are another root, validly signed by the
/// same key, refuse `ViewRootMismatch` at the readback, with the mediator base
/// and the retained landing untouched. A readback bound to nothing would
/// accept the substitute and refuse later, on its writer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_landing_reads_its_root_back_through_the_published_root() {
    let fixture = Fixture::new().await;
    fixture.create("file", b"landed bytes");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let base_before = fixture.store.lock().unwrap().mount_base().unwrap();
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "landed_readback", 1, FaultAction::Block);
    let mut secure = Entropy(80);
    let mut delay = Delay;
    let mut driving = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut secure,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ));
    let mut entered = Box::pin(fired(&faults, "sync.commit", "landed_readback"));
    std::future::poll_fn(|cx| {
        assert!(
            driving.as_mut().poll(cx).is_pending(),
            "commit finished before its readback seam"
        );
        entered.as_mut().poll(cx)
    })
    .await;
    {
        let mut published = fixture.remote.published.lock().unwrap();
        let landed = published
            .get(&2)
            .cloned()
            .expect("the landing must have published seq 2");
        let mut doc = granary_core::root::decode_root(&landed).unwrap();
        doc.writer_uuid[0] ^= 1;
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
        doc.sigs[0].sig = key.sign(&prefix);
        published.insert(2, granary_core::root::encode_root(&doc).unwrap());
    }
    faults.resume();
    let result = driving.await;
    let base_after = fixture.store.lock().unwrap().mount_base().unwrap();
    let durable = durable_commit_state(&fixture);
    assert_eq!(
        (
            matches!(result, Err(CoordinationError::Refused("ViewRootMismatch"))),
            base_after,
            durable,
        ),
        (true, base_before, (Some(("complete", 1)), (true, false))),
        "a substituted landed root must be refused at the readback: error={:?}",
        result.as_ref().err()
    );
}

/// A restarted lane reads the landed root's binmap back, and a `503` the
/// store sheds on that read is transient, as on the root readback: the
/// landing stays retained for a retry rather than refused as a bad readback.
#[tokio::test]
async fn a_shed_binmap_readback_after_a_landing_is_classed_unavailable() {
    let fixture = Fixture::new().await;
    fixture.create("file", b"landed bytes");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    land_without_refresh(&fixture, &lane).await;
    let fixture = fixture.restart().await;
    let lane = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    *fixture.remote.objects.get_failure.lock().unwrap() = Some("shed");
    let result = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(90),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            matches!(
                result,
                Err(CoordinationError::Refused("ViewRootUnavailable"))
            ),
            durable_commit_state(&fixture),
        ),
        (true, (Some(("complete", 1)), (true, false))),
        "a shed binmap readback must be transient: error={:?}",
        result.as_ref().err()
    );
}

/// A lane recovered after a restart reads its landed root's binmap back, and
/// a landing at epoch `u64::MAX` (over a base at `u64::MAX - 1`) must stay
/// readable there: the readback reserves no successor, so the recovered lane
/// finishes. A readback that reserved the next epoch would refuse the landing
/// it just made, and every retry with it. The landing's seq cannot reach the
/// terminal `u64::MAX - 1`: a candidate stops at `LAST_CANDIDATE_SEQ`.
#[tokio::test]
async fn a_recovered_landing_at_the_maximal_epoch_finishes() {
    let mut basis = Basis::empty().await;
    let mut doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    doc.epoch = u64::MAX - 1;
    doc.sigs.clear();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    basis.bytes = granary_core::root::encode_root(&doc).unwrap();
    let fixture = Fixture::over(basis)
        .await
        .unwrap_or_else(|error| panic!("fixture engine refused its base: {error}"));
    fixture.create("file", b"landed bytes");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    land_without_refresh(&fixture, &lane).await;
    let fixture = fixture.restart().await;
    let lane = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    let result = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(90),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await;
    let registered = fixture.registered();
    assert_eq!(
        (
            result
                .as_ref()
                .map(|result| matches!(result.outcome, PublicationOutcome::Landed(_)))
                .map_err(ToString::to_string),
            registered.seq,
            registered.epoch,
        ),
        (Ok(true), 2, u64::MAX),
        "a recovered landing at the maximal epoch must finish"
    );
}

/// Rewrite every whole-tree boundary of the durable journal as a projected
/// boundary with `selection`, keeping its cursor and publication, and its
/// candidate unless `candidate` replaces it.
fn project_durable_boundaries(
    io: &SimIo,
    selection: Option<granary_core::overlay_journal::ProjectedSelection>,
    candidate: Option<GrainId>,
) {
    let mut model = io.0.lock().unwrap();
    let id = *model
        .names
        .iter()
        .find(|(path, _)| path.file_name().unwrap() == "journal")
        .unwrap()
        .1;
    let durable = &model.files[&id].1;
    let mut records = Vec::new();
    let scan = granary_core::overlay_journal::scan_journal_with(durable, |_, record| {
        records.push(match record {
            Record::CommitBoundary {
                candidate: retained,
                through_seq,
                publication_id,
            } => Record::ProjectedBoundary {
                candidate: candidate.unwrap_or(*retained),
                through_seq: *through_seq,
                publication_id: *publication_id,
                selection,
            },
            other => other.clone(),
        });
    })
    .unwrap();
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::ProjectedBoundary { .. })),
        "fixture premise: a boundary to project"
    );
    let bytes = granary_core::overlay_journal::encode_journal(&scan.header, &records).unwrap();
    let file = model.files.get_mut(&id).unwrap();
    file.0.clone_from(&bytes);
    file.1 = bytes;
}

/// The overlay's live entry at `path`, as (stage, size), if it has one.
fn overlay_entry(fixture: &Fixture, path: &str) -> Option<(Option<u64>, u64)> {
    match fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.query_path(&[name(path)]))
        .unwrap()
    {
        crate::OverlayQuery::Found(found) => found.entry.map(|e| (e.stage_id, e.size)),
        _ => None,
    }
}

/// A restart over a retained projected boundary opens its lane, which lands
/// the projection and installs its residual: the head has x at its captured
/// bytes, while the overlay keeps x's later truncate and the file created
/// after the boundary, and no lane is left. A whole-tree boundary is the
/// control.
#[tokio::test]
async fn restart_resumes_a_projected_lane_and_installs_its_residual() {
    use granary_core::overlay_journal::ProjectedSelection;
    let mut outcomes = Vec::new();
    for projected in [false, true] {
        let fixture = Fixture::new().await;
        let stage = fixture.create("x", b"captured");
        fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        // After the boundary, with no staging bytes a restart could lose.
        fixture.create("y", b"");
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.truncate(stage, 4))
            .unwrap();
        {
            let mut model = fixture.io.0.lock().unwrap();
            let id = *model
                .names
                .iter()
                .find(|(path, _)| path.file_name().unwrap() == "journal")
                .unwrap()
                .1;
            let file = model.files.get_mut(&id).unwrap();
            file.1 = file.0.clone();
        }
        if projected {
            let captured = fixture
                .content
                .payloads
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, (size, _))| (*size == 8).then_some(*id))
                .unwrap();
            project_durable_boundaries(
                &fixture.io,
                Some(ProjectedSelection {
                    stage_id: stage,
                    content: captured,
                    size: 8,
                }),
                None,
            );
        }
        let fixture = fixture
            .try_restart_over(vec![])
            .await
            .map_err(|error| error.to_string());
        let landed = match &fixture {
            Ok(fixture) => {
                let lane = fixture
                    .engine
                    .recover_commit(SyncOptions::default())
                    .unwrap();
                Box::pin(fixture.engine.drive_commit(
                    &lane,
                    &mut Entropy(90),
                    &mut Delay,
                    RecoveryIntent::Continue,
                    SyncOptions::default(),
                ))
                .await
                .map(|_| {
                    let root = fixture.remote.authority.lock().unwrap().root.clone();
                    assert_file(fixture, &root, "x", b"captured");
                    (
                        overlay_entry(fixture, "x"),
                        overlay_entry(fixture, "y").is_some(),
                        fixture
                            .engine
                            .recover_commit(SyncOptions::default())
                            .is_err(),
                        fixture.remote.publication_sends.lock().unwrap().len(),
                    )
                })
                .map_err(|error| error.to_string())
            }
            Err(error) => Err(error.clone()),
        };
        outcomes.push((projected, landed));
    }
    assert_eq!(
        outcomes,
        [
            (false, Ok((Some((Some(1), 4)), true, true, 1))),
            (true, Ok((Some((Some(1), 4)), true, true, 1))),
        ]
    );
}

/// A projected boundary journaled before its submission was retained is
/// stripped at restart like a whole-tree one: the work before and after it
/// stays, and an ordinary sync then publishes it.
#[tokio::test]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
)]
async fn restart_strips_an_unsubmitted_projected_boundary_and_keeps_its_work() {
    let mut outcomes = Vec::new();
    for projected in [false, true] {
        let fixture = Fixture::new().await;
        fixture.create("before", b"");
        let bytes = fixture.remote.authority.lock().unwrap().root.clone();
        let capture = fixture
            .engine
            .begin_commit(SyncOptions::default())
            .await
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.record_boundary(capture.boundary().clone(), GrainId::of(&bytes), [70; 16])
            })
            .unwrap();
        drop(capture);
        if projected {
            project_durable_boundaries(&fixture.io, None, None);
        }
        let fixture = match fixture.try_restart_over(vec![]).await {
            Ok(fixture) => fixture,
            Err(error) => {
                outcomes.push((projected, Err(error.to_string())));
                continue;
            }
        };
        let boundaries = fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.recovery_commits())
            .unwrap()
            .len();
        let stage = fixture.create("after", b"retained");
        fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
            .unwrap();
        let root = fixture.remote.authority.lock().unwrap().root.clone();
        assert_file(&fixture, &root, "after", b"retained");
        outcomes.push((
            projected,
            Ok((boundaries, overlay_entry(&fixture, "before").is_some())),
        ));
    }
    assert_eq!(outcomes, [(false, Ok((0, true))), (true, Ok((0, true)))]);
}

/// A recovered projected lane carries its selection's saved content and size
/// and every other file at its durable payload, so the frozen candidate's
/// manifest must match each before any send. The fault before the first
/// attempt save stops a lane that verified.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one table of reject vectors")]
async fn a_recovered_projected_lane_binds_its_selection_to_the_frozen_candidate() {
    use granary_core::overlay_journal::{DeleteKind, ProjectedSelection};
    let mut outcomes = Vec::new();
    for case in ["bound", "content", "size", "none", "candidate", "unnamed"] {
        let fixture = Fixture::new().await;
        let stage = fixture.create("x", b"captured");
        // Empty, so the crash at restart leaves no unsynced staging bytes.
        let gone = fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                let gone = t.create_file(at("gone"), false)?;
                t.namespace_record(Record::Delete {
                    at: at("gone"),
                    kind: DeleteKind::File {
                        stage_id: Some(gone),
                    },
                })?;
                Ok(gone)
            })
            .unwrap();
        fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let fixture = fixture.restart().await;
        let captured = fixture
            .content
            .payloads
            .lock()
            .unwrap()
            .iter()
            .find_map(|(id, (size, _))| (*size == 8).then_some(*id))
            .unwrap();
        let selection = |stage_id, content, size| {
            Some(ProjectedSelection {
                stage_id,
                content,
                size,
            })
        };
        let (selection, candidate) = match case {
            "bound" => (selection(stage, captured, 8), None),
            "content" => (selection(stage, grain(5), 8), None),
            "size" => (selection(stage, captured, 7), None),
            "none" => (None, None),
            "candidate" => (selection(stage, captured, 8), Some(grain(5))),
            _ => (selection(gone, captured, 8), None),
        };
        project_durable_boundaries(&fixture.io, selection, candidate);
        let faults = fixture.store.lock().unwrap().fault_control();
        faults.arm("sync.commit", "before_submit", 1, FaultAction::Fail);
        let result = match fixture.engine.recover_commit(SyncOptions::default()) {
            Ok(lane) => Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut Entropy(90),
                &mut Delay,
                RecoveryIntent::ExplicitRecovery,
                SyncOptions::default(),
            ))
            .await
            .map(|_| ()),
            Err(error) => Err(error),
        };
        outcomes.push((
            case,
            result.as_ref().map_err(ToString::to_string).err(),
            result.as_ref().err().map(crate::sync::failure_class),
            fixture.remote.publication_sends.lock().unwrap().len(),
        ));
    }
    let refused = |reason: &str, class| (Some(format!("intent refused: {reason}")), Some(class));
    let rows: Vec<_> = [
        (
            "bound",
            (
                Some("publication journal: journal: intent refused: SyncInjectedFault".to_owned()),
                Some(crate::FailureClass::Io),
            ),
        ),
        (
            "content",
            refused("SyncCommitCheckpoint", crate::FailureClass::Refused),
        ),
        (
            "size",
            refused("SyncCommitNamespace", crate::FailureClass::Refused),
        ),
        (
            "none",
            refused("SyncCommitNamespace", crate::FailureClass::Refused),
        ),
        (
            "candidate",
            refused("SyncProjectedBinding", crate::FailureClass::Corrupt),
        ),
        (
            "unnamed",
            refused("SyncProjectedBinding", crate::FailureClass::Corrupt),
        ),
    ]
    .into_iter()
    .map(|(case, (error, class))| (case, error, class, 0))
    .collect();
    assert_eq!(outcomes, rows);
}

fn persist_content(fixture: &Fixture) {
    try_persist_content(fixture).unwrap();
}

fn try_persist_content(fixture: &Fixture) -> Result<(), CoordinationError> {
    let objects = fixture.content.objects.lock().unwrap().clone();
    let payloads = fixture.content.payloads.lock().unwrap().clone();
    let mut local = fixture.store.lock().unwrap();
    let mut immutable = local.immutable_content()?;
    for (id, bytes) in objects {
        immutable.put_object(id, &bytes).unwrap();
    }
    for (id, (size, grains)) in payloads {
        immutable.remember_payload(id, size, &grains).unwrap();
    }
    Ok(())
}

async fn spilled_file(grain_count: u32) -> (Fixture, u64) {
    use crate::overlay_store::tests::incremental::{Base, file};
    use granary_core::manifest::GrainRef;
    let mut base = Base::new();
    let bytes = b"same".to_vec();
    let id = GrainId::of(&bytes);
    base.world.objects.0.insert(id, bytes);
    let refs = vec![
        GrainRef {
            id,
            unpacked_len: 4
        };
        grain_count as usize
    ];
    let spill = manifest::build_grain_list(&refs).unwrap();
    base.world.objects.0.extend(spill.nodes);
    let content =
        base.world
            .register_spill_claim(u64::from(grain_count) * 4, grain_count, spill.root);
    base.entries.push(file("spill", content, false));
    let f = Fixture::over(super::incremental::basis_of(&mut base).await)
        .await
        .unwrap();
    f.content
        .remember_payload(
            content.0,
            u64::from(grain_count) * 4,
            &FileGrains::Spill {
                grain_count,
                root: spill.root,
            },
        )
        .unwrap();
    persist_content(&f);
    let stage = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let stage = t.copy_up(crate::overlay_store::tests::incremental::loc("spill"))?;
            t.write(stage, u64::from(grain_count) * 4 - 1, b"x")?;
            Ok(stage)
        })
        .unwrap();
    (f, stage)
}

#[tokio::test]
async fn captured_refs_workspace_exhaustion_is_named() {
    let (f, stage) = spilled_file(7200).await;
    let error = f
        .engine
        .sync(
            SyncTarget::Stage(stage),
            SyncOptions {
                workspace_bytes: 8_388_608,
                ..SyncOptions::default()
            },
        )
        .wait()
        .await
        .unwrap_err();
    assert_eq!(
        (
            error.to_string(),
            f.engine.workspace_held_for_test() == 0,
            f.remote.attempts.lock().unwrap().is_empty()
        ),
        ("intent refused: SyncWorkspaceExhausted".into(), true, true)
    );
}
