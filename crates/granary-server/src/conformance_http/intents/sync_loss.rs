// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
pub(super) mod recover;
use granary_client::{
    AuthorityError, AuthorityTransport, ClientMetrics, ContentSource, CoordinationError,
    FaultControl, InstantClock, IntentTransportError, OverlayConfig, OverlayDisk, OverlayError,
    PendingIntent, Policy, PublicationJournal, PublicationOutcome, PublicationStoreError,
    PublishRequest, PublishResponse, RecoveryBackoff, RecoveryDelay, RecoveryIntent, RecoveryParts,
    SelectedRecovery, StatusResponse, Store, SyncContent, SyncEngine, SyncOptions, SyncRemote,
    SyncTarget, WritableStore, begin_exact_publication, begin_publication,
    resume_exact_publication,
};
use granary_core::{
    binstore::BinStore,
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    manifest::{self, FileGrains, Name},
    overlay_journal::{JournalHeader, Location, Record},
    retained_submission::Submission,
    rootstore::{HintRead, HintToken, RootStore, RootStoreError},
};
use granary_store::crypto::TrustedKeys;
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Content {
    objects: Mutex<BTreeMap<GrainId, Vec<u8>>>,
    payloads: Mutex<BTreeMap<GrainId, FileGrains>>,
}
impl GrainSource for Content {
    fn has(&self, id: &GrainId) -> bool {
        self.objects.lock().unwrap().contains_key(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.objects
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }
}
impl SyncContent for Content {
    fn payload(&self, id: GrainId) -> Result<FileGrains, CoordinationError> {
        self.payloads
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(CoordinationError::Refused("missing fixture payload"))
    }
    fn read_content(
        &self,
        id: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        let FileGrains::Inline(refs) = self.payload(id).unwrap() else {
            panic!("small fixture spilled")
        };
        let bytes: Vec<_> = refs.iter().flat_map(|r| self.get(&r.id).unwrap()).collect();
        let offset = usize::try_from(offset).unwrap();
        Ok(bytes[offset..offset + length].to_vec())
    }
    fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError> {
        assert_eq!(GrainId::of(bytes), id);
        self.objects.lock().unwrap().insert(id, bytes.to_vec());
        Ok(())
    }
    fn remember_payload(
        &self,
        id: GrainId,
        size: u64,
        grains: &FileGrains,
    ) -> Result<(), CoordinationError> {
        let bytes = manifest::node::file_payload(size, grains).unwrap();
        assert_eq!(id, GrainId::of(&bytes));
        self.objects.lock().unwrap().insert(id, bytes);
        self.payloads.lock().unwrap().insert(id, grains.clone());
        Ok(())
    }
}
impl ContentSource for Content {
    fn read_verified(
        &mut self,
        id: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.read_content(id, offset, length)
    }
}

struct Journal(Arc<Mutex<WritableStore<OverlayDisk>>>);
impl GrainSource for Journal {
    fn has(&self, _: &GrainId) -> bool {
        false
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        Err(GrainSourceError::Missing(*id))
    }
}
impl Journal {
    fn local<T>(
        &mut self,
        f: impl FnOnce(&mut granary_client::PublicationStore<'_>) -> Result<T, PublicationStoreError>,
    ) -> Result<T, PublicationStoreError> {
        match self.0.lock().unwrap().publication_transaction(f) {
            Ok(value) => Ok(value),
            Err(CoordinationError::Publication(error)) => Err(error),
            Err(error) => panic!("publication mediator: {error}"),
        }
    }
}
impl PublicationJournal for Journal {
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.local(|j| j.load(scope, volume))
    }
    fn begin(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        self.local(|j| j.begin(record))
    }
    async fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        self.local(|j| j.replace(generation, record))
    }
}

struct PauseJournal<'a> {
    inner: granary_client::PublicationStore<'a>,
    pause: Option<Duration>,
}
impl GrainSource for PauseJournal<'_> {
    fn has(&self, id: &GrainId) -> bool {
        self.inner.has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.inner.get(id)
    }
}
impl PublicationJournal for PauseJournal<'_> {
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.inner.load(scope, volume)
    }
    fn begin(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        self.inner.begin(record)
    }
    async fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        if matches!(
            record.phase,
            granary_core::retained_submission::Phase::AwaitingAnswer { .. }
        ) && let Some(pause) = self.pause.take()
        {
            // One poll moves the held clock past every connection lifetime and
            // stops at advance's trailing yield: the client dispatches on its
            // pooled connection before the server is polled to close it.
            let mut advance = std::pin::pin!(tokio::time::advance(pause));
            let _yielded = advance
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        }
        self.inner.replace(generation, record)
    }
}
/// Spends the production backoff by advancing the held clock, which a wait
/// on it would never see move.
struct HeldDelay(RecoveryBackoff<SeededRng>);
impl RecoveryDelay for HeldDelay {
    fn jitter(&mut self, ceiling: Duration) -> Duration {
        self.0.jitter(ceiling)
    }
    fn wait(
        &mut self,
        duration: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::advance(duration))
    }
}
fn config(path: &std::path::Path, scope: Scope, volume: VolumeName) -> OverlayConfig {
    OverlayConfig {
        scope,
        volume,
        euid: std::fs::metadata(path).unwrap().uid(),
        cap: 134_217_728,
        ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
        instance: [0; 16],
    }
}
fn at(name: &str) -> Location {
    Location {
        parent: granary_core::overlay_journal::Parent::root(),
        name: Name::new(name.as_bytes().to_vec()).unwrap(),
    }
}
fn complete(
    local: &mut WritableStore<OverlayDisk>,
    request: &granary_client::PendingIntent,
    reply: &IntentReply,
    clock: &Ticks,
) {
    local
        .complete(request, Ok(reply), clock, &mut SeededRng::new(2), 0, None)
        .unwrap();
}

#[tokio::test]
async fn registered_tree_survives_store_loss() {
    for destroy in [false, true] {
        Box::pin(recover_registered_tree(
            destroy,
            false,
            0,
            AcceptConfig::default(),
        ))
        .await;
    }
    Box::pin(recover_registered_tree(
        true,
        false,
        100_000,
        AcceptConfig::default(),
    ))
    .await;
}

#[tokio::test]
async fn commit_parent_is_excluded_after_store_loss() {
    Box::pin(recover_registered_tree(
        true,
        true,
        0,
        AcceptConfig::default(),
    ))
    .await;
}

#[expect(
    clippy::too_many_lines,
    reason = "one recovery lifecycle binds lifetime cut, pending assertion and exact resume"
)]
#[tokio::test(start_paused = true)]
async fn recovery_resumes_after_connection_lifetime_expiry() {
    // A running blocking task stops the paused clock from auto-advancing while
    // the runtime waits on sockets, so no connection lifetime elapses until
    // the journal's pause advances the clock.
    let (release, latch) = std::sync::mpsc::channel::<()>();
    let holder = tokio::task::spawn_blocking(move || {
        let _closed = latch.recv();
    });
    let fx = Fixture::new(None);
    // Held time costs no wall time. The lifetime outlasts the most backoff the
    // resume can spend (about 10 s over its dispatch attempts), and the pause
    // stays inside the server's HTTP/2 keep-alive interval, so the lifetime
    // bound alone cuts the first send.
    let lifetime = Duration::from_secs(15);
    let margin = Duration::from_millis(200);
    let pause = lifetime + margin;
    let accept = AcceptConfig {
        connection_max_lifetime: lifetime,
        ..AcceptConfig::default()
    };
    let server = fx
        .start_with_accept_config(1, roomy(), true, None, accept)
        .await;
    let remote = Arc::new(fx.client(server.addr, 0));
    let scope = fx.scope(server.addr, 0);
    let key = SigningKey::from_seed(&[23; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let path = fx.dir.join("store");
    let mut disk = Store::open(&path).unwrap();
    let mut secure = SeededSecureRandom::from_key([31; 32]);
    let mut delay = HeldDelay(RecoveryBackoff {
        rng: SeededRng::new(2),
    });
    let content = Arc::new(Content::default());
    let tree = manifest::build_dir(&[]).unwrap();
    content.objects.lock().unwrap().extend(tree.nodes);
    let prepared = granary_client::prepare_from_manifest(
        remote.as_ref(),
        content.as_ref(),
        tree.root,
        granary_client::HarvestStats::default(),
        &fx.volume(),
        &key,
        &granary_core::identity::WriterIdentity::from_bytes([7; 16]),
        fx.clock.now(),
        Policy::default(),
    )
    .await
    .unwrap();
    let exact = prepared.root_bytes;
    let writer = granary_core::root::decode_root(&exact).unwrap().writer_uuid;
    let publications = disk
        .publications(std::fs::metadata(&path).unwrap().uid())
        .unwrap();
    let mut journal = PauseJournal {
        inner: publications,
        pause: Some(pause),
    };
    let result = begin_exact_publication(
        RecoveryParts {
            transport: remote.as_ref(),
            journal: &mut journal,
            publisher_keys: &keys,
            signer: &key,
            secure: &mut secure,
            clock: &fx.clock,
            delay: &mut delay,
        },
        scope.clone(),
        fx.volume(),
        writer,
        exact.clone(),
    )
    .await
    .unwrap();

    assert_eq!(
        result.outcome,
        PublicationOutcome::Pending,
        "first drive must encounter uncertain send: outcome={:?}, diagnostic={:?}",
        result.outcome,
        result.diagnostic
    );
    assert!(
        result.uncertain,
        "first drive must be uncertain: outcome={:?}, diagnostic={:?}",
        result.outcome, result.diagnostic
    );
    let diagnostic = result.diagnostic.as_deref().unwrap_or_else(|| {
        panic!(
            "missing diagnostic: outcome={:?}, diagnostic={:?}",
            result.outcome, result.diagnostic
        )
    });
    assert!(
        diagnostic.contains("transport"),
        "diagnostic must report transport failure: outcome={:?}, diagnostic={:?}",
        result.outcome,
        result.diagnostic
    );

    let resumed = resume_exact_publication(
        RecoveryParts {
            transport: remote.as_ref(),
            journal: &mut journal,
            publisher_keys: &keys,
            signer: &key,
            secure: &mut secure,
            clock: &fx.clock,
            delay: &mut delay,
        },
        &result.handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();

    let PublicationOutcome::Landed(done) = resumed.outcome else {
        panic!(
            "recovery did not land: outcome={:?}, diagnostic={:?}",
            resumed.outcome, resumed.diagnostic
        );
    };
    assert_eq!(done.root, exact, "landed root must match published root");
    assert_eq!(
        remote
            .get_root(fx.volume().as_str(), done.seq)
            .await
            .unwrap()
            .unwrap(),
        exact,
        "remote root must match published root"
    );
    drop(release);
    holder.await.unwrap();
}

#[expect(
    clippy::too_many_lines,
    reason = "one authority lifecycle binds commit, selection, destruction and a fresh ordinary reader"
)]
async fn recover_registered_tree(
    destroy: bool,
    commit_first: bool,
    grain_count: u32,
    accept: AcceptConfig,
) {
    let fx = Fixture::new(None);
    let server = fx
        .start_with_accept_config(1, roomy(), true, None, accept)
        .await;
    let remote = Arc::new(fx.client(server.addr, 0));
    let scope = fx.scope(server.addr, 0);
    let key = SigningKey::from_seed(&[23; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let path = fx.dir.join("original-store");
    let mut disk = Store::open(&path).unwrap();
    let source = fx.dir.join("empty-source");
    std::fs::create_dir(&source).unwrap();
    let (manifest, _) = granary_client::harvest(&source, &disk).unwrap();
    let mut secure = SeededSecureRandom::from_key([31; 32]);
    let mut delay = RecoveryBackoff {
        rng: SeededRng::new(2),
    };
    let content = Arc::new(Content::default());
    let mut base_entries = Vec::new();
    let prepared = if grain_count == 0 {
        content
            .objects
            .lock()
            .unwrap()
            .extend(manifest::build_dir(&[]).unwrap().nodes);
        None
    } else {
        let refs: Vec<_> = (0..grain_count)
            .map(|n| {
                let bytes = n.to_le_bytes().to_vec();
                let id = GrainId::of(&bytes);
                content.objects.lock().unwrap().insert(id, bytes);
                manifest::GrainRef {
                    id,
                    unpacked_len: 4,
                }
            })
            .collect();
        let spill = manifest::build_grain_list(&refs).unwrap();
        content.objects.lock().unwrap().extend(spill.nodes);
        let grains = FileGrains::Spill {
            grain_count,
            root: spill.root,
        };
        let tree = manifest::build_dir(&[manifest::DirEntry {
            name: Name::new(b"cold".to_vec()).unwrap(),
            kind: manifest::EntryKind::File {
                exec: false,
                size: u64::from(grain_count) * 4,
                grains: grains.clone(),
            },
        }])
        .unwrap();
        content.objects.lock().unwrap().extend(tree.nodes);
        let payload = GrainId::of(
            &manifest::node::file_payload(u64::from(grain_count) * 4, &grains).unwrap(),
        );
        base_entries.push(granary_client::OverlayEntry {
            path: vec![Name::new(b"cold".to_vec()).unwrap()],
            inode: 1,
            kind: granary_client::OverlayKind::File {
                content: Some(payload),
            },
            stage_id: None,
            size: u64::from(grain_count) * 4,
            exec: false,
        });
        Some(
            granary_client::prepare_from_manifest(
                remote.as_ref(),
                content.as_ref(),
                tree.root,
                granary_client::HarvestStats::default(),
                &fx.volume(),
                &key,
                &granary_core::identity::WriterIdentity::from_bytes([7; 16]),
                fx.clock.now(),
                Policy { min_prefix_bits: 8 },
            )
            .await
            .unwrap(),
        )
    };
    let base = {
        let parts = RecoveryParts {
            transport: remote.as_ref(),
            journal: &mut disk
                .publications(std::fs::metadata(&path).unwrap().uid())
                .unwrap(),
            publisher_keys: &keys,
            signer: &key,
            secure: &mut secure,
            clock: &fx.clock,
            delay: &mut delay,
        };
        if let Some(prepared) = prepared {
            let writer = granary_core::root::decode_root(&prepared.root_bytes)
                .unwrap()
                .writer_uuid;
            begin_exact_publication(
                parts,
                scope.clone(),
                fx.volume(),
                writer,
                prepared.root_bytes,
            )
            .await
            .unwrap()
        } else {
            begin_publication(
                parts,
                scope.clone(),
                fx.volume(),
                manifest,
                Policy::default(),
            )
            .await
            .unwrap()
        }
    };
    let PublicationOutcome::Landed(base) = base.outcome else {
        panic!(
            "base did not land: outcome={:?}, diagnostic={:?}",
            base.outcome, base.diagnostic
        )
    };
    let mut base_bytes = base.root;
    let mut local = WritableStore::new(
        disk,
        config(&path, scope.clone(), fx.volume()),
        OverlayDisk::new(&path, std::fs::metadata(&path).unwrap().uid()),
        &mut secure,
        FaultControl::default(),
        |d, p| granary_store::crypto::check_signatures(d, p, &keys).is_ok(),
    )
    .unwrap();
    let writer = local.writer_uuid();
    let request = local.prepare_acquire(0, &fx.clock).unwrap();
    local.dispatch(&request, &fx.clock).unwrap();
    let reply = remote
        .intent_acquire_once(&scope, &fx.volume(), request.bytes())
        .await
        .unwrap();
    complete(&mut local, &request, &reply, &fx.clock);
    local
        .open_overlay(
            JournalHeader {
                writer,
                base_root: GrainId::of(&base_bytes),
                base_seq: 1,
                next_stage_id: 1,
                receipt_generation: 0,
            },
            base_entries,
            &mut Content::default(),
            OverlayDisk::new(&path, std::fs::metadata(&path).unwrap().uid()),
        )
        .unwrap();
    let prepared = granary_client::prepare_from_manifest(
        remote.as_ref(),
        content.as_ref(),
        granary_core::root::decode_root(&base_bytes)
            .unwrap()
            .manifest_root,
        granary_client::HarvestStats::default(),
        &fx.volume(),
        &key,
        &granary_core::identity::WriterIdentity::from_bytes(writer),
        fx.clock.now(),
        Policy::default(),
    )
    .await
    .unwrap();
    let mut initial = granary_core::root::decode_root(&prepared.root_bytes).unwrap();
    assert_eq!(
        (initial.seq, initial.parent),
        (2, Some(GrainId::of(&base_bytes)))
    );
    initial.writer_uuid = writer;
    initial.sigs.clear();
    let prefix = granary_core::root::signing_prefix_of(&initial).unwrap();
    initial.sigs.push(granary_core::root::RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    let initial = granary_core::root::encode_root(&initial).unwrap();
    let request = local
        .prepare_registration(&initial, vec![], &fx.clock, |d, p| {
            granary_store::crypto::check_signatures(d, p, &keys).is_ok()
        })
        .unwrap();
    local.dispatch(&request, &fx.clock).unwrap();
    let reply = remote
        .intent_register_once(&scope, &fx.volume(), request.bytes(), |d, p| {
            granary_store::crypto::check_signatures(d, p, &keys).is_ok()
        })
        .await
        .unwrap();
    complete(&mut local, &request, &reply, &fx.clock);
    let local = Arc::new(Mutex::new(local));
    let engine = SyncEngine::new(
        local.clone(),
        remote.clone(),
        content.clone(),
        Arc::new(fx.clock.clone()),
        Arc::new(InstantClock::default()),
        SigningKey::from_seed(&[23; 32]).unwrap(),
        keys.clone(),
        base_bytes.clone(),
        ClientMetrics::new(&mut secure),
    )
    .await
    .unwrap();
    let create = |name: &str, bytes: &[u8]| {
        local
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                let id = t.create_file(at(name), false)?;
                t.write(id, 0, bytes)?;
                Ok(id)
            })
            .unwrap()
    };
    local
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(Record::Create {
                at: at("empty-dir"),
                kind: granary_core::overlay_journal::CreateKind::Dir,
            })
        })
        .unwrap();
    engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let commit = if commit_first {
        Some(
            engine
                .construct_commit(SyncOptions::default(), &mut secure)
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let first = create("first", b"first durable bytes");
    if let Some(commit) = commit {
        let result = Box::pin(engine.drive_commit(
            &commit,
            &mut secure,
            &mut delay,
            granary_client::RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        let PublicationOutcome::Landed(done) = result.outcome else {
            panic!("commit did not land")
        };
        assert_eq!(done.seq, 2);
        base_bytes = done.root;
    }
    engine
        .sync(SyncTarget::Stage(first), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let old = create("target", b"old complete bytes");
    engine
        .sync(SyncTarget::Stage(old), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let temp = create("temporary", b"replacement complete bytes");
    engine
        .sync(SyncTarget::Stage(temp), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    local
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(Record::Replace {
                from: at("temporary"),
                to: at("target"),
            })
        })
        .unwrap();
    create("never-synced", b"must remain absent");
    engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_eq!(
        remote.max_seq(fx.volume().as_str()).await.unwrap(),
        Some(if commit_first { 2 } else { 1 }),
        "sync published a root"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while Arc::strong_count(&engine) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(engine);
    drop(content);
    drop(local);
    if destroy {
        std::fs::remove_dir_all(&path).unwrap();
        assert!(!path.exists());
    }

    let readback = remote
        .intent_readback_once(&scope, &fx.volume(), |d, p| {
            granary_store::crypto::check_signatures(d, p, &keys).is_ok()
        })
        .await
        .unwrap();
    let rows = intent::decode_readback(readback.body(), &fx.volume(), |d, p| {
        granary_store::crypto::check_signatures(d, p, &keys).is_ok()
    })
    .unwrap();
    assert_eq!(rows.rows.len(), 1, "recovery selection is ambiguous");
    let selected_writer = rows.rows[0].writer;
    assert_eq!(
        selected_writer, writer,
        "authority selected a different writer"
    );
    let writer = selected_writer;
    let selected =
        SelectedRecovery::from_readback(scope.clone(), fx.volume(), writer, &readback, |d, p| {
            granary_store::crypto::check_signatures(d, p, &keys).is_ok()
        })
        .unwrap();
    let exact = selected.root_bytes().to_vec();
    assert_eq!(
        granary_core::root::decode_root(&exact).unwrap().parent,
        Some(GrainId::of(&base_bytes))
    );
    let parent = granary_core::root::decode_root(&base_bytes).unwrap();
    let head_seq = remote.max_seq(fx.volume().as_str()).await.unwrap().unwrap();
    assert_eq!(head_seq, parent.seq);
    if commit_first {
        assert_eq!(
            parent.writer_uuid, writer,
            "the excluded parent must carry W"
        );
        // The selected tree differs from this parent and is not published,
        // so its post-commit acknowledgement must be recovered from P.
        assert_eq!(
            granary_core::root::decode_root(&exact).unwrap().seq,
            head_seq + 1
        );
    }
    let fresh = fx.dir.join("fresh-store");
    let disk = Store::open(&fresh).unwrap();
    let mut recovered = WritableStore::adopt_selected(
        disk,
        config(&fresh, scope.clone(), fx.volume()),
        OverlayDisk::new(&fresh, std::fs::metadata(&fresh).unwrap().uid()),
        &mut secure,
        FaultControl::default(),
        selected.acknowledge_displacement(),
    )
    .unwrap();
    let request = recovered.begin_selected_attempt(&fx.clock).unwrap();
    recovered.dispatch(&request, &fx.clock).unwrap();
    let reply = remote
        .intent_takeover_once(&scope, &fx.volume(), request.bytes())
        .await
        .unwrap();
    complete(&mut recovered, &request, &reply, &fx.clock);
    let recovered = Arc::new(Mutex::new(recovered));
    let result = begin_exact_publication(
        RecoveryParts {
            transport: remote.as_ref(),
            journal: &mut Journal(recovered.clone()),
            publisher_keys: &keys,
            signer: &key,
            secure: &mut secure,
            clock: &fx.clock,
            delay: &mut delay,
        },
        scope.clone(),
        fx.volume(),
        writer,
        exact.clone(),
    )
    .await
    .unwrap();
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!(
            "selected root did not land: outcome={:?}, diagnostic={:?}",
            result.outcome, result.diagnostic
        )
    };
    assert_eq!(done.root, exact, "recovery rebuilt selected P");
    assert_eq!(
        remote
            .get_root(fx.volume().as_str(), done.seq)
            .await
            .unwrap()
            .unwrap(),
        exact
    );
    let reader = fx.client(server.addr, 0);
    for (name, expected) in [
        ("first", b"first durable bytes".as_slice()),
        ("target", b"replacement complete bytes".as_slice()),
    ] {
        let names = [Name::new(name.as_bytes().to_vec()).unwrap()];
        let mut bytes = Vec::<u8>::new();
        granary_client::resolve_head_verified(
            &reader,
            fx.volume().as_str(),
            &granary_client::RootVerifier::trusting(*key.public_key()).unwrap(),
            &granary_client::HeadContext::new(
                Box::new(fx.clock.clone()),
                Box::new(SeededRng::new(3)),
            ),
            None,
            granary_client::ResolveTarget::Path(&names),
            &mut |_, part| {
                bytes.extend_from_slice(part);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(bytes, expected, "ordinary reader recovered different bytes");
    }
    let doc = granary_core::root::decode_root(&exact).unwrap();
    let mut read_objects = BTreeMap::new();
    let resolved = granary_client::resolve_head_verified(
        &reader,
        fx.volume().as_str(),
        &granary_client::RootVerifier::trusting(*key.public_key()).unwrap(),
        &granary_client::HeadContext::new(Box::new(fx.clock.clone()), Box::new(SeededRng::new(4))),
        None,
        granary_client::ResolveTarget::WholeTree,
        &mut |id, bytes| {
            read_objects.insert(id, bytes.to_vec());
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(resolved.root_bytes, exact);
    if grain_count > 0 {
        let index = granary_core::binmap::decode_binmap_index(
            &reader
                .get_meta(fx.volume().as_str(), &doc.binmap_index)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(index.prefix_bits, 8);
        let cold: Vec<_> = (0..grain_count).flat_map(u32::to_le_bytes).collect();
        for n in 0..grain_count {
            assert_eq!(
                read_objects[&GrainId::of(&n.to_le_bytes())],
                cold[n as usize * 4..n as usize * 4 + 4]
            );
        }
    }
    let bytes = read_objects.get(&doc.manifest_root).unwrap();
    let (_, cursor) = granary_core::encoding::open_envelope(bytes).unwrap();
    let entries = manifest::decode_dir_leaf(cursor).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|e| e.name.as_bytes())
            .collect::<Vec<_>>(),
        if grain_count == 0 {
            vec![
                b"empty-dir".as_slice(),
                b"first".as_slice(),
                b"target".as_slice(),
            ]
        } else {
            vec![
                b"cold".as_slice(),
                b"empty-dir".as_slice(),
                b"first".as_slice(),
                b"target".as_slice(),
            ]
        }
    );
    let base_entries = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let (kind, size, exec) = match &entry.kind {
                manifest::EntryKind::File { exec, size, grains } => (
                    granary_client::OverlayKind::File {
                        content: Some(GrainId::of(
                            &manifest::node::file_payload(*size, grains).unwrap(),
                        )),
                    },
                    *size,
                    *exec,
                ),
                manifest::EntryKind::Dir { child } => {
                    let (_, cursor) =
                        granary_core::encoding::open_envelope(read_objects.get(child).unwrap())
                            .unwrap();
                    assert!(
                        manifest::decode_dir_leaf(cursor).unwrap().is_empty(),
                        "empty directory changed"
                    );
                    (granary_client::OverlayKind::Directory, 0, false)
                }
                _ => panic!("unexpected recovered kind"),
            };
            granary_client::OverlayEntry {
                path: vec![entry.name.clone()],
                inode: index as u64 + 1,
                kind,
                stage_id: None,
                size,
                exec,
            }
        })
        .collect();
    {
        let mut local = recovered.lock().unwrap();
        local
            .open_overlay(
                JournalHeader {
                    writer,
                    base_root: done.id,
                    base_seq: done.seq,
                    next_stage_id: 1,
                    receipt_generation: 0,
                },
                base_entries,
                &mut Content::default(),
                OverlayDisk::new(&fresh, std::fs::metadata(&fresh).unwrap().uid()),
            )
            .unwrap();
    }
    let request = recovered
        .lock()
        .unwrap()
        .prepare_registration(&exact, vec![], &fx.clock, |d, p| {
            granary_store::crypto::check_signatures(d, p, &keys).is_ok()
        })
        .unwrap();
    recovered
        .lock()
        .unwrap()
        .dispatch(&request, &fx.clock)
        .unwrap();
    let reply = remote
        .intent_register_once(&scope, &fx.volume(), request.bytes(), |d, p| {
            granary_store::crypto::check_signatures(d, p, &keys).is_ok()
        })
        .await
        .unwrap();
    complete(&mut recovered.lock().unwrap(), &request, &reply, &fx.clock);
    let receipt = intent::decode_receipt(&recovered.lock().unwrap().snapshot().current).unwrap();
    recovered
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.record_landed_refresh(receipt.generation, done.id))
        .unwrap();
    let request = recovered
        .lock()
        .unwrap()
        .prepare_release(&fx.clock, granary_client::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
    recovered
        .lock()
        .unwrap()
        .dispatch(&request, &fx.clock)
        .unwrap();
    let reply = remote
        .intent_release_once(&scope, &fx.volume(), request.bytes())
        .await
        .unwrap();
    complete(&mut recovered.lock().unwrap(), &request, &reply, &fx.clock);
    assert_eq!(
        intent::decode_receipt(&recovered.lock().unwrap().snapshot().current)
            .unwrap()
            .state,
        intent::ReceiptState::Released
    );
    assert_eq!(
        remote.max_seq(fx.volume().as_str()).await.unwrap(),
        Some(done.seq)
    );
    drop(recovered);
    drop(reader);
    drop(remote);
    server.stop().await;
}

/// The authority's real transport, with at most one scripted publication
/// cut: a send held unanswered past its caller's deadline, either before it
/// reaches the authority or after the authority has decided it.
struct Cut {
    inner: HttpStore,
    recovery_faults: FaultControl,
    publication_sends: Arc<Mutex<Vec<Vec<u8>>>>,
    deny_publications: Arc<std::sync::atomic::AtomicUsize>,
    lose_release: std::sync::atomic::AtomicBool,
    hold: Mutex<Option<Hold>>,
    recovery_race: Mutex<Option<(granary_core::overlay_ownership::Operation, Vec<u8>)>>,
    recovery_reads: AtomicU64,
    recovery_sends: Mutex<Vec<Vec<u8>>>,
    recovery_clock: Mutex<Option<Ticks>>,
    lose_takeover: std::sync::atomic::AtomicBool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    Unsent,
    Landed,
}
impl Cut {
    fn new(inner: HttpStore) -> Self {
        Self {
            inner,
            recovery_faults: FaultControl::default(),
            publication_sends: Arc::default(),
            deny_publications: Arc::default(),
            lose_release: std::sync::atomic::AtomicBool::new(false),
            hold: Mutex::new(None),
            recovery_race: Mutex::new(None),
            recovery_reads: AtomicU64::new(0),
            recovery_sends: Mutex::new(Vec::new()),
            recovery_clock: Mutex::new(None),
            lose_takeover: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl RootStore for Cut {
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        self.inner.put_root(v, n, b).await
    }
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.inner.get_root(v, n).await
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        self.inner.max_seq(v).await
    }
    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.inner.max_seq_above(v, floor).await
    }
    async fn read_hint(&self, v: &str, t: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        self.inner.read_hint(v, t).await
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        self.inner.write_hint(v, n).await
    }
}
impl BinStore for Cut {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.inner.put_meta(v, id, b).await
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.inner.get_meta(v, id).await
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.inner.put_bin(d, b).await
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        self.inner.get_bin_range(d, o, n).await
    }
}
impl AuthorityTransport for Cut {
    async fn publish_once(&self, r: &PublishRequest) -> Result<PublishResponse, AuthorityError> {
        self.publication_sends
            .lock()
            .unwrap()
            .push(r.candidate().bytes().to_vec());
        if self
            .deny_publications
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok()
        {
            return granary_client::validate_publish_answer(r, 429, Some("rate-limited"), &[]);
        }
        let hold = self.hold.lock().unwrap().take();
        if hold == Some(Hold::Landed) {
            let decided = self.inner.publish_once(r).await;
            assert!(
                decided.is_ok(),
                "the held send was not decided: {decided:?}"
            );
        }
        if hold.is_some() {
            std::future::pending::<()>().await;
        }
        self.inner.publish_once(r).await
    }
    async fn status_once(&self, v: &str) -> Result<StatusResponse, AuthorityError> {
        self.inner.status_once(v).await
    }
    async fn probe_root_once(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.inner.probe_root_once(v, n).await
    }
}
impl SyncRemote for Cut {
    async fn register_once(
        &self,
        request: &PendingIntent,
        trusted: &TrustedKeys,
    ) -> Result<IntentReply, IntentTransportError> {
        self.inner.register_once(request, trusted).await
    }
    async fn release_once(
        &self,
        request: &PendingIntent,
    ) -> Result<IntentReply, IntentTransportError> {
        self.inner.release_once(request).await
    }
}

impl granary_client::MountMetrics for Cut {
    fn client_metrics(&self) -> Option<&ClientMetrics> {
        None
    }
}
impl granary_client::WritableAuthority for Cut {
    fn read_facade(&self) -> Self {
        let mut facade = Self::new(granary_client::WritableAuthority::read_facade(&self.inner));
        facade.recovery_faults = self.recovery_faults.clone();
        facade.publication_sends = self.publication_sends.clone();
        facade.deny_publications = self.deny_publications.clone();
        facade
    }
    async fn writable_status(&self, volume: &VolumeName) -> Result<StatusResponse, AuthorityError> {
        self.inner.status_once(volume.as_str()).await
    }
    async fn writable_readback(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        public: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        self.recovery_reads.fetch_add(1, Ordering::Relaxed);
        let reply = self.inner.writable_readback(scope, volume, public).await?;
        let race = self.recovery_race.lock().unwrap().take();
        if let Some((operation, bytes)) = race {
            let raced = match operation {
                granary_core::overlay_ownership::Operation::Ownership => {
                    self.inner
                        .intent_takeover_once(scope, volume, &bytes)
                        .await?
                }
                granary_core::overlay_ownership::Operation::Register => {
                    self.inner
                        .intent_register_once(scope, volume, &bytes, |_, _| true)
                        .await?
                }
                granary_core::overlay_ownership::Operation::Release => {
                    self.inner
                        .intent_release_once(scope, volume, &bytes)
                        .await?
                }
            };
            assert_eq!(
                raced.status(),
                200,
                "concurrent update must succeed before the stale takeover: status={} body={:?}",
                raced.status(),
                raced.body()
            );
        }
        Ok(reply)
    }
    async fn writable_send(
        &self,
        scope: &Scope,
        request: &PendingIntent,
        public: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        self.recovery_sends
            .lock()
            .unwrap()
            .push(request.bytes().to_vec());
        let reply = self.inner.writable_send(scope, request, public).await?;
        if request.operation() == granary_core::overlay_ownership::Operation::Release
            && self.lose_release.swap(false, Ordering::Relaxed)
        {
            return Err(IntentTransportError::Transport);
        }
        if request.operation() == granary_core::overlay_ownership::Operation::Ownership
            && self.lose_takeover.swap(false, Ordering::Relaxed)
        {
            return Err(IntentTransportError::Transport);
        }
        Ok(reply)
    }
    async fn writable_wait(&self, milliseconds: u64) {
        let clock = self.recovery_clock.lock().unwrap().clone();
        if let Some(clock) = clock {
            clock
                .0
                .fetch_add(milliseconds.div_ceil(1000), Ordering::Relaxed);
        } else {
            self.inner.writable_wait(milliseconds).await;
        }
    }
}

type Engine = SyncEngine<OverlayDisk, Cut, Content, Ticks, InstantClock>;

/// One process of the writer: its store and engine. A crash drops both;
/// the store directory, the content it uploaded and its signing key are
/// what the next process starts from.
struct Writer {
    local: Arc<Mutex<WritableStore<OverlayDisk>>>,
    engine: Arc<Engine>,
    remote: Arc<Cut>,
}
impl Writer {
    fn create(&self, name: &str, bytes: &[u8]) -> u64 {
        self.local
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                let id = t.create_file(at(name), false)?;
                t.write(id, 0, bytes)?;
                Ok(id)
            })
            .unwrap()
    }
    /// Hold `name`'s stage open, so a landing carries it rather than
    /// retiring it.
    fn hold(&self, name: &str) {
        self.local
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.open_stage(&[Name::new(name.as_bytes().to_vec()).unwrap()]))
            .unwrap();
    }
    fn write(&self, stage: u64, bytes: &[u8]) {
        self.local
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.write(stage, 0, bytes).map(|_| ()))
            .unwrap();
    }
    /// What the writer reads at `name`, staged or from its base.
    fn read(&self, name: &str) -> Option<Vec<u8>> {
        let path = [Name::new(name.as_bytes().to_vec()).unwrap()];
        let mut local = self.local.lock().unwrap();
        let granary_client::OverlayQuery::Found(found) =
            local.overlay_transaction(|t| t.query_path(&path)).ok()?
        else {
            return None;
        };
        let entry = found.entry?;
        let length = usize::try_from(entry.size).unwrap();
        local
            .overlay_transaction(|t| match entry.stage_id {
                Some(stage) => t.read_stage(stage, 0, length),
                None => t.read_base(&path, 0, length),
            })
            .ok()
    }
    async fn publish(&self, target: SyncTarget, seed: u8, options: SyncOptions) -> String {
        match self
            .engine
            .publish_sync(target, options, SeededSecureRandom::from_key([seed; 32]))
            .wait()
            .await
        {
            Ok(()) => "landed".to_owned(),
            Err(error) => error.to_string(),
        }
    }
    /// Land everything written so far as an ordinary commit; its root.
    async fn commit(&self, secure: &mut SeededSecureRandom) -> Vec<u8> {
        let lane = self
            .engine
            .construct_commit(SyncOptions::default(), secure)
            .await
            .unwrap();
        let result = Box::pin(self.engine.drive_commit(
            &lane,
            secure,
            &mut RecoveryBackoff {
                rng: SeededRng::new(2),
            },
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        let PublicationOutcome::Landed(done) = result.outcome else {
            panic!("commit did not land: {:?}", result.diagnostic)
        };
        done.root
    }
    /// Crash: drop the process once its supervised work has let go.
    async fn crash(self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(&self.engine) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

fn signer() -> (SigningKey, TrustedKeys) {
    let key = SigningKey::from_seed(&[23; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    (key, keys)
}

fn verifies(keys: &TrustedKeys) -> impl Fn(&granary_core::root::RootDoc, &[u8]) -> bool + '_ {
    |d, p| granary_store::crypto::check_signatures(d, p, keys).is_ok()
}

/// Land an empty base, then attach a writer over it; the base's bytes.
async fn attach(
    fx: &Fixture,
    addr: SocketAddr,
    path: &std::path::Path,
    content: &Arc<Content>,
    secure: &mut SeededSecureRandom,
) -> (Writer, Vec<u8>) {
    let http = fx.client(addr, 0);
    let scope = fx.scope(addr, 0);
    let (key, keys) = signer();
    let mut disk = Store::open(path).unwrap();
    let source = path.with_extension("source");
    std::fs::create_dir(&source).unwrap();
    let (manifest, _) = granary_client::harvest(&source, &disk).unwrap();
    content
        .objects
        .lock()
        .unwrap()
        .extend(manifest::build_dir(&[]).unwrap().nodes);
    let landed = begin_publication(
        RecoveryParts {
            transport: &http,
            journal: &mut disk
                .publications(std::fs::metadata(path).unwrap().uid())
                .unwrap(),
            publisher_keys: &keys,
            signer: &key,
            secure,
            clock: &fx.clock,
            delay: &mut RecoveryBackoff {
                rng: SeededRng::new(2),
            },
        },
        scope.clone(),
        fx.volume(),
        manifest,
        Policy::default(),
    )
    .await
    .unwrap();
    let PublicationOutcome::Landed(base) = landed.outcome else {
        panic!("base did not land: {:?}", landed.diagnostic)
    };
    let mut local = WritableStore::new(
        disk,
        config(path, scope.clone(), fx.volume()),
        OverlayDisk::new(path, std::fs::metadata(path).unwrap().uid()),
        secure,
        FaultControl::default(),
        verifies(&keys),
    )
    .unwrap();
    let request = local.prepare_acquire(0, &fx.clock).unwrap();
    local.dispatch(&request, &fx.clock).unwrap();
    let reply = http
        .intent_acquire_once(&scope, &fx.volume(), request.bytes())
        .await
        .unwrap();
    complete(&mut local, &request, &reply, &fx.clock);
    let writer = Box::pin(start_writer(
        fx, addr, path, local, content, &base.root, true,
    ))
    .await;
    (writer, base.root)
}

/// The writer's next process over the same store directory: its ownership
/// succeeds its own, and its overlay reopens over `base`.
async fn reopen(
    fx: &Fixture,
    addr: SocketAddr,
    path: &std::path::Path,
    content: &Arc<Content>,
    base: &[u8],
    register: bool,
    secure: &mut SeededSecureRandom,
) -> Writer {
    let http = fx.client(addr, 0);
    let (_, keys) = signer();
    let mut local = WritableStore::new(
        Store::open(path).unwrap(),
        config(path, fx.scope(addr, 0), fx.volume()),
        OverlayDisk::new(path, std::fs::metadata(path).unwrap().uid()),
        secure,
        FaultControl::default(),
        verifies(&keys),
    )
    .unwrap();
    let request = local.prepare_succession(&fx.clock).unwrap();
    local.dispatch(&request, &fx.clock).unwrap();
    let reply = http
        .intent_takeover_once(&fx.scope(addr, 0), &fx.volume(), request.bytes())
        .await
        .unwrap();
    complete(&mut local, &request, &reply, &fx.clock);
    Box::pin(start_writer(fx, addr, path, local, content, base, register)).await
}

/// Open the overlay over `base` and, when its process starts with no
/// retained lane to recover, register its first prepared root; then attach
/// the engine.
async fn start_writer(
    fx: &Fixture,
    addr: SocketAddr,
    path: &std::path::Path,
    mut local: WritableStore<OverlayDisk>,
    content: &Arc<Content>,
    base: &[u8],
    register: bool,
) -> Writer {
    let http = fx.client(addr, 0);
    let scope = fx.scope(addr, 0);
    let (key, keys) = signer();
    let doc = granary_core::root::decode_root(base).unwrap();
    let writer = local.writer_uuid();
    local
        .open_overlay(
            JournalHeader {
                writer,
                base_root: GrainId::of(base),
                base_seq: doc.seq,
                next_stage_id: 1,
                receipt_generation: 0,
            },
            entries(&http, fx, content, doc.manifest_root).await,
            &mut Content::default(),
            OverlayDisk::new(path, std::fs::metadata(path).unwrap().uid()),
        )
        .unwrap();
    if register {
        let prepared = granary_client::prepare_from_manifest(
            &http,
            content.as_ref(),
            doc.manifest_root,
            granary_client::HarvestStats::default(),
            &fx.volume(),
            &key,
            &granary_core::identity::WriterIdentity::from_bytes(writer),
            fx.clock.now(),
            Policy::default(),
        )
        .await
        .unwrap();
        let mut initial = granary_core::root::decode_root(&prepared.root_bytes).unwrap();
        initial.writer_uuid = writer;
        initial.sigs.clear();
        let prefix = granary_core::root::signing_prefix_of(&initial).unwrap();
        initial.sigs.push(granary_core::root::RootSig {
            key_id: key.key_id(),
            sig: key.sign(&prefix),
        });
        let initial = granary_core::root::encode_root(&initial).unwrap();
        let request = local
            .prepare_registration(&initial, vec![], &fx.clock, verifies(&keys))
            .unwrap();
        local.dispatch(&request, &fx.clock).unwrap();
        let reply = http
            .intent_register_once(&scope, &fx.volume(), request.bytes(), verifies(&keys))
            .await
            .unwrap();
        complete(&mut local, &request, &reply, &fx.clock);
    }
    let local = Arc::new(Mutex::new(local));
    let remote = Arc::new(Cut::new(http));
    let engine = SyncEngine::new(
        local.clone(),
        remote.clone(),
        content.clone(),
        Arc::new(fx.clock.clone()),
        Arc::new(InstantClock::default()),
        key,
        keys,
        base.to_vec(),
        ClientMetrics::new(&mut SeededSecureRandom::from_key([41; 32])),
    )
    .await
    .unwrap();
    Writer {
        local,
        engine,
        remote,
    }
}

/// A base manifest's top-level files, as the overlay opens over them: the
/// writer's own content holds every manifest it uploaded, and the authority
/// holds the rest.
async fn entries(
    http: &HttpStore,
    fx: &Fixture,
    content: &Content,
    manifest_root: GrainId,
) -> Vec<granary_client::OverlayEntry> {
    let bytes = match content.get(&manifest_root) {
        Ok(bytes) => bytes,
        Err(_) => http
            .get_meta(fx.volume().as_str(), &manifest_root)
            .await
            .unwrap(),
    };
    let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
    manifest::decode_dir_leaf(cursor)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let manifest::EntryKind::File { exec, size, grains } = entry.kind else {
                panic!("fixture bases hold files only")
            };
            granary_client::OverlayEntry {
                path: vec![entry.name],
                inode: index as u64 + 1,
                kind: granary_client::OverlayKind::File {
                    content: Some(GrainId::of(
                        &manifest::node::file_payload(size, &grains).unwrap(),
                    )),
                },
                stage_id: None,
                size,
                exec,
            }
        })
        .collect()
}

/// What a fresh ordinary reader of the authority's head reads at `name`.
async fn head_file(fx: &Fixture, addr: SocketAddr, name: &str) -> Option<Vec<u8>> {
    let reader = fx.client(addr, 0);
    let (key, _) = signer();
    let names = [Name::new(name.as_bytes().to_vec()).unwrap()];
    let mut bytes = Vec::<u8>::new();
    granary_client::resolve_head_verified(
        &reader,
        fx.volume().as_str(),
        &granary_client::RootVerifier::trusting(*key.public_key()).unwrap(),
        &granary_client::HeadContext::new(Box::new(fx.clock.clone()), Box::new(SeededRng::new(3))),
        None,
        granary_client::ResolveTarget::Path(&names),
        &mut |_, part| {
            bytes.extend_from_slice(part);
            Ok(())
        },
    )
    .await
    .ok()?;
    Some(bytes)
}

/// The authority's head root.
async fn head(fx: &Fixture, addr: SocketAddr) -> Vec<u8> {
    let reader = fx.client(addr, 0);
    let seq = reader.max_seq(fx.volume().as_str()).await.unwrap().unwrap();
    reader
        .get_root(fx.volume().as_str(), seq)
        .await
        .unwrap()
        .unwrap()
}

/// After a published sync of x succeeds, the writer's whole store is
/// removed and the authority restarts: a fresh reader of the restarted
/// authority sees x's captured bytes and y's durable ones, never y's later
/// local bytes or a file never synced.
#[tokio::test]
async fn projected_authority_loss_after_success() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let path = fx.dir.join("loss-store");
    let content = Arc::new(Content::default());
    let mut secure = SeededSecureRandom::from_key([31; 32]);
    let (writer, _) = Box::pin(attach(&fx, server.addr, &path, &content, &mut secure)).await;
    let y = writer.create("y", b"durable y");
    writer.hold("y");
    writer.commit(&mut secure).await;
    writer.write(y, b"LOCAL Y, never synced");
    writer.create("z", b"never synced");
    let x = writer.create("x", b"captured x");
    let published = writer
        .publish(SyncTarget::Stage(x), 51, SyncOptions::default())
        .await;
    writer.crash().await;
    drop(content);
    std::fs::remove_dir_all(&path).unwrap();
    let addr = server.stop().await;
    let server = fx.start(2, roomy(), false, Some(addr)).await;
    let read = (
        head_file(&fx, addr, "x").await,
        head_file(&fx, addr, "y").await,
        head_file(&fx, addr, "z").await,
    );
    assert_eq!(
        (published, path.exists(), read),
        (
            "landed".to_owned(),
            false,
            (
                Some(b"captured x".to_vec()),
                Some(b"durable y".to_vec()),
                None
            ),
        ),
        "a published sync's landing survives the writer's store and an authority restart"
    );
    server.stop().await;
}

/// One cut of a published sync of x, over a base whose durable y has later
/// local bytes: the writer crashes after the call returns, the authority
/// restarts, and the writer's next process reopens its store over the base
/// its journal names. Its next published sync, of a z written before the
/// cut, takes over any lane the cut retained. What the call answered, whether the cut was taken, the
/// head's seq above the base, the head's x, y and z, and what the reopened
/// writer reads at x and y.
async fn switch_cut(
    hold: Option<Hold>,
) -> (
    String,
    bool,
    u64,
    [Option<Vec<u8>>; 3],
    String,
    [Option<Vec<u8>>; 2],
) {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let path = fx.dir.join("cut-store");
    let content = Arc::new(Content::default());
    let mut secure = SeededSecureRandom::from_key([31; 32]);
    let (writer, _) = Box::pin(attach(&fx, server.addr, &path, &content, &mut secure)).await;
    let y = writer.create("y", b"durable y");
    writer.hold("y");
    let base = writer.commit(&mut secure).await;
    writer.write(y, b"LOCAL Y, never synced");
    let z = writer.create("z", b"synced after the restart");
    let x = writer.create("x", b"captured x");
    writer.hold("x");
    *writer.remote.hold.lock().unwrap() = hold;
    let options = SyncOptions {
        resolution_bound: Duration::from_secs(10),
        ..SyncOptions::default()
    };
    let answered = writer.publish(SyncTarget::Stage(x), 51, options).await;
    let taken = writer.remote.hold.lock().unwrap().is_none();
    // Written after the cut, so only the reopened journal can hold it.
    writer.write(x, b"CAPTURED X");
    writer.crash().await;
    let addr = server.stop().await;
    let server = fx.start(2, roomy(), false, Some(addr)).await;
    // A landing that installed reopens over its own root and registers anew;
    // a retained lane reopens over the old base for its takeover to land.
    let reopened = if hold.is_none() {
        head(&fx, addr).await
    } else {
        base.clone()
    };
    let writer = Box::pin(reopen(
        &fx,
        addr,
        &path,
        &content,
        &reopened,
        hold.is_none(),
        &mut secure,
    ))
    .await;
    let later = writer
        .publish(SyncTarget::Stage(z), 61, SyncOptions::default())
        .await;
    let seq = granary_core::root::decode_root(&head(&fx, addr).await)
        .unwrap()
        .seq
        - granary_core::root::decode_root(&base).unwrap().seq;
    let heads = [
        head_file(&fx, addr, "x").await,
        head_file(&fx, addr, "y").await,
        head_file(&fx, addr, "z").await,
    ];
    let local = [writer.read("x"), writer.read("y")];
    writer.crash().await;
    server.stop().await;
    (answered, taken, seq, heads, later, local)
}

/// The authority-side cuts of a published sync's switch: its send never
/// reached the authority, the authority decided it and the answer never
/// came, or the call landed and installed. Each recovers one self-contained
/// image: the head has x's captured bytes and y's durable ones, from exactly
/// one landing of x's lane and one of z's, and the reopened writer still has
/// x's later bytes and y's residual, neither dropped nor truncated.
#[tokio::test]
async fn projected_switch_crash_matrix() {
    let some = |bytes: &[u8]| Some(bytes.to_vec());
    for (hold, answered) in [
        (Some(Hold::Unsent), "intent refused: SyncDeadline"),
        (Some(Hold::Landed), "intent refused: SyncDeadline"),
        (None, "landed"),
    ] {
        assert_eq!(
            Box::pin(switch_cut(hold)).await,
            (
                answered.to_owned(),
                true,
                2,
                [
                    some(b"captured x"),
                    some(b"durable y"),
                    some(b"synced after the restart"),
                ],
                "landed".to_owned(),
                [some(b"CAPTURED X"), some(b"LOCAL Y, never synced")],
            ),
            "the {hold:?} cut did not recover one self-contained image"
        );
    }
}
