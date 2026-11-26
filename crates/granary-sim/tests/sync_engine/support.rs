// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![expect(clippy::unwrap_used, reason = "checked simulator fixture invariants")]

#[path = "support/journal.rs"]
pub(crate) mod journal;

use granary_client::*;
use granary_core::{
    binstore::BinStore,
    clock::Clock,
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    intent::{self, Grant, OwnershipMode, Receipt, ReceiptState},
    manifest::{self, FileGrains},
    overlay_journal::JournalHeader,
    overlay_ownership::{Operation, Phase, REPLACEMENT_RESERVE},
    retained_submission::Scope,
    root::{RootSig, Timestamp, VolumeName},
    rootstore::RootStoreError,
};
use granary_sim::{
    fakes::{Faults, Sim, SimStore},
    sched::yield_once,
    secure_random::SeededSecureRandom,
    sync_runtime::SimSyncRuntime,
};
use granary_store::crypto::{SigningKey, TrustedKeys};
use std::{
    collections::BTreeMap,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

fn volume() -> VolumeName {
    VolumeName::new("v".into()).unwrap()
}
fn scope() -> Scope {
    Scope {
        authority_base: b"https://fixture.invalid".to_vec(),
        pins: vec![],
        credential_context: b"test".to_vec(),
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "fixture callers hand over newly encoded owned response bytes"
)]
fn reply(status: u16, token: Option<&str>, media: Option<&str>, body: Vec<u8>) -> IntentReply {
    IntentReply::test_response(
        scope(),
        volume(),
        intent::Reply {
            status,
            token,
            media_type: media,
            body: &body,
        },
    )
}
#[derive(Default)]
struct Authority {
    rows: BTreeMap<[u8; 16], (Receipt, Vec<u8>)>,
    cursor: u64,
    grants: BTreeMap<GrainId, Grant>,
    sends: Vec<Vec<u8>>,
}
impl Authority {
    fn readback(&self) -> Vec<u8> {
        let rows = self
            .rows
            .values()
            .filter_map(|(receipt, root)| {
                matches!(receipt.state, ReceiptState::Live { .. }).then_some(intent::ReadbackRow {
                    writer: receipt.writer,
                    epoch: receipt.epoch,
                    generation: receipt.generation,
                    root,
                })
            })
            .collect::<Vec<_>>();
        intent::encode_readback(self.cursor, &rows).unwrap()
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the deterministic fake applies each complete wire transition without network or callbacks"
    )]
    fn send(&mut self, request: &PendingIntent) -> IntentReply {
        self.sends.push(request.bytes().to_vec());
        match request.operation() {
            Operation::Ownership => {
                let decoded = intent::decode_ownership(request.bytes()).unwrap();
                let request_id = GrainId::of(request.bytes());
                if let Some(generation) = self.grants.get(&request_id)
                    && self
                        .rows
                        .get(&generation.receipt.writer)
                        .is_some_and(|(row, _)| {
                            (row.epoch, row.instance)
                                == (generation.receipt.epoch, generation.receipt.instance)
                        })
                {
                    return reply(
                        200,
                        None,
                        Some(intent::MEDIA_GRANT),
                        intent::encode_grant(*generation).unwrap(),
                    );
                }
                match decoded.mode {
                    OwnershipMode::Acquire { observed_cursor } => {
                        if self.rows.contains_key(&decoded.writer) {
                            return self.recorded(decoded.writer, 409, Some("intent-changed"));
                        }
                        if observed_cursor != self.cursor {
                            return reply(409, Some("intent-cursor-changed"), None, vec![]);
                        }
                        self.cursor += 1;
                        self.rows.insert(
                            decoded.writer,
                            (
                                Receipt {
                                    writer: decoded.writer,
                                    epoch: self.cursor,
                                    instance: decoded.instance,
                                    generation: 0,
                                    state: ReceiptState::Released,
                                },
                                vec![],
                            ),
                        );
                    }
                    OwnershipMode::Takeover {
                        expected_epoch,
                        generation,
                        state,
                        ..
                    } => {
                        let Some(&(current, _)) = self.rows.get(&decoded.writer) else {
                            return reply(409, Some("intent-absent"), None, vec![]);
                        };
                        if current.epoch != expected_epoch {
                            return self.recorded(decoded.writer, 409, Some("intent-superseded"));
                        }
                        if (current.epoch, current.generation, current.state)
                            != (expected_epoch, generation, state)
                        {
                            return self.recorded(decoded.writer, 409, Some("intent-changed"));
                        }
                        self.cursor += 1;
                        self.rows.get_mut(&decoded.writer).unwrap().0 = Receipt {
                            epoch: self.cursor,
                            instance: decoded.instance,
                            ..current
                        };
                    }
                }
                let generation = Grant {
                    request_id,
                    receipt: self.rows.get(&decoded.writer).unwrap().0,
                };
                self.grants.insert(request_id, generation);
                reply(
                    200,
                    None,
                    Some(intent::MEDIA_GRANT),
                    intent::encode_grant(generation).unwrap(),
                )
            }
            Operation::Register => {
                let decoded =
                    intent::decode_register(request.bytes(), request.volume(), |_, _| true)
                        .unwrap();
                let Some(&(current, _)) = self.rows.get(&decoded.writer) else {
                    return reply(409, Some("intent-absent"), None, vec![]);
                };
                if (decoded.epoch, decoded.instance) != (current.epoch, current.instance) {
                    return self.recorded(decoded.writer, 409, Some("intent-superseded"));
                }
                if decoded.generation < current.generation
                    || (decoded.generation == current.generation
                        && current.state == ReceiptState::Released)
                {
                    return self.recorded(decoded.writer, 409, Some("intent-superseded"));
                }
                if decoded.generation == current.generation
                    && current.state
                        != (ReceiptState::Live {
                            prepared_root_id: decoded.root_id(),
                        })
                {
                    return self.recorded(decoded.writer, 409, Some("intent-bound"));
                }
                self.rows.insert(
                    decoded.writer,
                    (
                        Receipt {
                            generation: decoded.generation,
                            state: ReceiptState::Live {
                                prepared_root_id: decoded.root_id(),
                            },
                            ..current
                        },
                        decoded.root.to_vec(),
                    ),
                );
                self.recorded(decoded.writer, 200, None)
            }
            Operation::Release => {
                let decoded = intent::decode_release(request.bytes()).unwrap();
                let Some(&(current, _)) = self.rows.get(&decoded.writer) else {
                    return reply(409, Some("intent-absent"), None, vec![]);
                };
                if (decoded.epoch, decoded.instance) != (current.epoch, current.instance) {
                    return self.recorded(decoded.writer, 409, Some("intent-superseded"));
                }
                self.rows.insert(
                    decoded.writer,
                    (
                        Receipt {
                            generation: decoded.generation.max(current.generation),
                            state: ReceiptState::Released,
                            ..current
                        },
                        vec![],
                    ),
                );
                self.recorded(decoded.writer, 200, None)
            }
        }
    }
    fn recorded(&self, writer: [u8; 16], status: u16, token: Option<&str>) -> IntentReply {
        reply(
            status,
            token,
            Some(intent::MEDIA_RECEIPT),
            intent::encode_receipt(self.rows.get(&writer).unwrap().0).unwrap(),
        )
    }
}

pub(crate) struct Scratch(pub(crate) PathBuf);
impl Scratch {
    pub(crate) fn evidence(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut directories = vec![self.0.clone()];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    directories.push(entry.path());
                } else {
                    files.insert(entry.path(), std::fs::read(entry.path()).unwrap());
                }
            }
        }
        files
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "claim only simulator-owned scratch beneath the runtime-resolved workspace build directory"
    )]
    pub(crate) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let cwd = std::env::current_dir().unwrap();
        let root = cwd
            .ancestors()
            .find(|p| p.join("crates/granary-sim/Cargo.toml").is_file())
            .unwrap();
        let parent = root.join("target").canonicalize().unwrap();
        loop {
            let path = parent.join(format!(
                "sync-sim-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    return Self(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("scratch claim: {e}"),
            }
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

#[derive(Default)]
pub(crate) struct Content {
    objects: Mutex<BTreeMap<GrainId, Vec<u8>>>,
    payloads: Mutex<BTreeMap<GrainId, (u64, FileGrains)>>,
    /// Every id read through `GrainSource::get`, in order.
    pub(crate) reads: Mutex<Vec<GrainId>>,
    pub(crate) corrupt_get: AtomicBool,
    pub(crate) fail_put: AtomicBool,
    pub(crate) panic_put: AtomicBool,
}
impl GrainSource for Content {
    fn has(&self, id: &GrainId) -> bool {
        self.objects.lock().unwrap().contains_key(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.reads.lock().unwrap().push(*id);
        let mut bytes = self
            .objects
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))?;
        if self.corrupt_get.load(Ordering::Acquire)
            && let Some(byte) = bytes.first_mut()
        {
            *byte ^= 1;
        }
        Ok(bytes)
    }
}
impl ContentSource for Content {
    fn read_verified(
        &mut self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.read_content(content, offset, length)
    }
}
impl SyncContent for Content {
    fn payload(&self, id: GrainId) -> Result<FileGrains, CoordinationError> {
        self.payloads
            .lock()
            .unwrap()
            .get(&id)
            .map(|(_, g)| g.clone())
            .ok_or(CoordinationError::Refused("SyncFixturePayload"))
    }
    fn read_content(
        &self,
        id: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        let (_, grains) = self.payloads.lock().unwrap().get(&id).cloned().unwrap();
        let refs = match grains {
            FileGrains::Inline(refs) => refs,
            FileGrains::Spill { root, .. } => {
                let bytes = self.get(&root).unwrap();
                let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
                manifest::decode_grain_list_leaf(cursor).unwrap()
            }
        };
        let data: Vec<_> = refs.iter().flat_map(|r| self.get(&r.id).unwrap()).collect();
        let start = usize::try_from(offset).unwrap();
        Ok(data.get(start..start + length).unwrap().to_vec())
    }
    fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError> {
        assert!(
            !self.panic_put.load(Ordering::Acquire),
            "simulated materialization panic"
        );
        if self.fail_put.load(Ordering::Acquire) {
            return Err(OverlayError::Io(std::io::Error::other("simulated local sink I/O")).into());
        }
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
        assert_eq!(
            GrainId::of(&manifest::node::file_payload(size, grains).unwrap()),
            id
        );
        self.payloads
            .lock()
            .unwrap()
            .insert(id, (size, grains.clone()));
        Ok(())
    }
}

pub(crate) struct Time {
    runtime: Arc<SimSyncRuntime>,
    domain: MonotonicDomain,
}
impl Clock for Time {
    fn now(&self) -> Timestamp {
        let elapsed = self.runtime.elapsed();
        Timestamp {
            secs: 1000 + i64::try_from(elapsed.as_secs()).unwrap(),
            nanos: elapsed.subsec_nanos(),
        }
    }
}
impl MonotonicClock for Time {
    fn start(&self) -> Option<MonotonicToken> {
        Some(self.domain.token(self.runtime.elapsed()))
    }
    fn elapsed(&self, token: &MonotonicToken) -> Option<Duration> {
        self.domain.elapsed(token, self.runtime.elapsed())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BinRangeRead {
    pub(crate) digest: [u8; 32],
    pub(crate) offset: u64,
    pub(crate) length: u32,
    pub(crate) bytes: Vec<u8>,
    pub(crate) publication_sends: usize,
}

pub(crate) struct Remote {
    runtime: Arc<SimSyncRuntime>,
    pub(crate) objects: Arc<SimStore>,
    source: Arc<Content>,
    authority: Mutex<Authority>,
    pub(crate) hold_upload: AtomicBool,
    pub(crate) fail_upload: AtomicBool,
    pub(crate) fenced: AtomicBool,
    pub(crate) upload_entered: AtomicBool,
    pub(crate) hold_reply: AtomicBool,
    pub(crate) reply_entered: AtomicBool,
    pub(crate) attempts: Mutex<Vec<Vec<u8>>>,
    pub(crate) published: Mutex<BTreeMap<u64, Vec<u8>>>,
    replaced_heads: AtomicUsize,
    pub(crate) publication_sends: Mutex<Vec<Vec<u8>>>,
    pub(crate) publication_plan: Mutex<std::collections::VecDeque<PublishPlan>>,
    pub(crate) bin_ranges: Mutex<Vec<BinRangeRead>>,
    probes: AtomicUsize,
    failed_probe: AtomicUsize,
    epoch: Mutex<granary_core::authlog::Epoch>,
}
impl Remote {
    /// Make the next recovery probe return the simulator's backend failure.
    pub(crate) fn fail_next_probe_for_test(&self) {
        self.failed_probe
            .store(self.probes.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    }

    /// Replace one checked head to model storage contradicting create-only roots.
    pub(crate) fn replace_published_head_for_test(
        &self,
        seq: u64,
        expected_foreign_id: GrainId,
        signed_bytes: Vec<u8>,
    ) -> usize {
        let mut roots = self.published.lock().unwrap();
        let actual = roots
            .last_key_value()
            .map(|(seq, bytes)| (*seq, GrainId::of(bytes)));
        assert_eq!(
            actual,
            Some((seq, expected_foreign_id)),
            "replacement head premise"
        );
        assert_eq!(
            granary_core::root::decode_root(&signed_bytes).unwrap().seq,
            seq
        );
        let previous = self.replaced_heads.fetch_add(1, Ordering::Relaxed);
        assert_eq!(previous, 0, "only one integrity fault per fixture");
        roots.insert(seq, signed_bytes);
        previous + 1
    }

    async fn upload_gate(&self) {
        self.upload_entered.store(true, Ordering::Release);
        while self.hold_upload.load(Ordering::Acquire) {
            yield_once().await;
        }
    }
}
impl BinStore for Remote {
    async fn put_bin(&self, digest: &[u8; 32], bytes: Vec<u8>) -> Result<bool, RootStoreError> {
        self.upload_gate().await;
        if self.fail_upload.load(Ordering::Acquire) {
            return Err(RootStoreError::Backend(
                "simulated transport unavailable".into(),
            ));
        }
        self.objects.put_bin(digest, bytes).await
    }
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.upload_gate().await;
        self.objects.put_meta(volume, id, bytes).await
    }
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.objects.get_meta(volume, id).await
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; 32],
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let bytes = self.objects.get_bin_range(digest, offset, length).await?;
        self.bin_ranges.lock().unwrap().push(BinRangeRead {
            digest: *digest,
            offset,
            length,
            bytes: bytes.clone(),
            publication_sends: self.publication_sends.lock().unwrap().len(),
        });
        Ok(bytes)
    }
}
impl SyncRemote for Remote {
    async fn register_once(
        &self,
        request: &PendingIntent,
        trusted: &TrustedKeys,
    ) -> Result<IntentReply, IntentTransportError> {
        yield_once().await;
        intent::decode_register(request.bytes(), request.volume(), |doc, prefix| {
            granary_store::crypto::check_signatures(doc, prefix, trusted).is_ok()
        })
        .unwrap();
        self.attempts.lock().unwrap().push(request.bytes().to_vec());
        if self.fenced.load(Ordering::Acquire) {
            return Ok(reply(409, Some("intent-absent"), None, vec![]));
        }
        let answer = self.authority.lock().unwrap().send(request);
        self.reply_entered.store(true, Ordering::Release);
        while self.hold_reply.load(Ordering::Acquire) {
            yield_once().await;
        }
        Ok(answer)
    }
    async fn release_once(
        &self,
        request: &PendingIntent,
    ) -> Result<IntentReply, IntentTransportError> {
        yield_once().await;
        Ok(self.authority.lock().unwrap().send(request))
    }
}

/// The fixture's content as an overlay replay source.
struct Reader(Arc<Content>);
impl ContentSource for Reader {
    fn read_verified(
        &mut self,
        id: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.0.read_content(id, offset, length)
    }
}

/// A fresh store over the same directory, owned by a successor instance.
fn successor_store(scratch: &Scratch, remote: &Remote, time: &Time) -> WritableStore<OverlayDisk> {
    let euid = std::fs::metadata(&scratch.0).unwrap().uid();
    let config = OverlayConfig {
        scope: scope(),
        volume: volume(),
        euid,
        cap: 4_294_967_296,
        ownership_completion_reserve: REPLACEMENT_RESERVE,
        instance: [35; 16],
    };
    let mut local = WritableStore::new(
        Store::open(&scratch.0).unwrap(),
        config,
        OverlayDisk::new(&scratch.0, euid),
        &mut SeededSecureRandom::for_incarnation(42, 1),
        FaultControl::default(),
        |_, _| true,
    )
    .unwrap();
    if let Some(replay) = local.landed_replay().unwrap() {
        local
            .dispatch_landed_replay(replay.request(), time)
            .unwrap();
        let answer = remote.authority.lock().unwrap().send(replay.request());
        local
            .complete_landed_replay(
                replay.request(),
                Ok(&answer),
                time,
                &mut granary_sim::rng::Rng::seeded(1, 54),
                0,
                None,
            )
            .unwrap();
    }
    let succession = local.prepare_succession(time).unwrap();
    local.dispatch(&succession, time).unwrap();
    let answer = remote.authority.lock().unwrap().send(&succession);
    local
        .complete(
            &succession,
            Ok(&answer),
            time,
            &mut granary_sim::rng::Rng::seeded(1, 54),
            0,
            None,
        )
        .unwrap();
    local
}

/// Register the authority's current root again under the store's own writer.
fn register_again(local: &mut WritableStore<OverlayDisk>, remote: &Remote, time: &Time) {
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let authority = remote.authority.lock().unwrap();
    let (_, root) = authority.rows.get(&local.writer_uuid()).unwrap();
    let mut doc = granary_core::root::decode_root(root).unwrap();
    drop(authority);
    doc.writer_uuid = local.writer_uuid();
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    let bytes = granary_core::root::encode_root(&doc).unwrap();
    let request = local
        .prepare_registration(&bytes, vec![], time, |_, _| true)
        .unwrap();
    local.dispatch(&request, time).unwrap();
    let answer = remote.authority.lock().unwrap().send(&request);
    local
        .complete(
            &request,
            Ok(&answer),
            time,
            &mut granary_sim::rng::Rng::seeded(1, 54),
            0,
            None,
        )
        .unwrap();
}

pub(crate) type Engine = SyncEngine<OverlayDisk, Remote, Content, Time, Time, SimSyncRuntime>;
pub(crate) struct Fixture {
    pub(crate) engine: Arc<Engine>,
    pub(crate) store: Arc<Mutex<WritableStore<OverlayDisk>>>,
    pub(crate) remote: Arc<Remote>,
    pub(crate) runtime: Arc<SimSyncRuntime>,
    pub(crate) metrics: ClientMetrics,
    pub(crate) content: Arc<Content>,
    pub(crate) base: Vec<u8>,
    scratch: Scratch,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TakeoverChange {
    Epoch,
    Generation,
    State,
    Absent,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        Self::with_scratch(Scratch::new())
    }
    pub(crate) fn with_case(case: &str) -> Self {
        Self::with_scratch_case(Scratch::new(), case)
    }
    pub(crate) fn with_scratch(scratch: Scratch) -> Self {
        Self::with_scratch_case(scratch, "plain")
    }
    #[expect(
        clippy::too_many_lines,
        reason = "one complete ownership/bootstrap/engine fixture transaction"
    )]
    pub(crate) fn with_scratch_case(scratch: Scratch, case: &str) -> Self {
        let runtime = Arc::new(SimSyncRuntime::new(TokioSyncRuntime.now()));
        let mut entropy = SeededSecureRandom::for_incarnation(42, 0);
        let config = OverlayConfig {
            scope: scope(),
            volume: volume(),
            euid: std::fs::metadata(&scratch.0).unwrap().uid(),
            cap: if case == "pressure" {
                220_000_000
            } else {
                4_294_967_296
            },
            ownership_completion_reserve: REPLACEMENT_RESERVE,
            instance: [34; 16],
        };
        let mut local = WritableStore::new(
            Store::open(&scratch.0).unwrap(),
            config.clone(),
            OverlayDisk::new(&scratch.0, config.euid),
            &mut entropy,
            FaultControl::default(),
            |_, _| true,
        )
        .unwrap();
        let time = Arc::new(Time {
            runtime: runtime.clone(),
            domain: MonotonicDomain::default(),
        });
        let mut authority = Authority::default();
        let acquire = local.prepare_acquire(0, time.as_ref()).unwrap();
        local.dispatch(&acquire, time.as_ref()).unwrap();
        let answer = authority.send(&acquire);
        local
            .complete(
                &acquire,
                Ok(&answer),
                time.as_ref(),
                &mut granary_sim::rng::Rng::seeded(1, 54),
                0,
                None,
            )
            .unwrap();
        let sim = Sim::new();
        let objects = Arc::new(sim.node(0, Faults::none()));
        let tree = manifest::build_dir(&[]).unwrap();
        for (id, bytes) in &tree.nodes {
            assert_eq!(sim.put_grain(bytes.clone()), *id);
        }
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
        let object_task = objects.clone();
        let manifest_root = tree.root;
        let (base, _) = runtime
            .run(1, 10000, async move {
                prepare_from_manifest(
                    object_task.as_ref(),
                    object_task.as_ref(),
                    manifest_root,
                    HarvestStats::default(),
                    &volume(),
                    &SigningKey::from_seed(&[39; 32]).unwrap(),
                    &granary_sim::scenario::identity(0),
                    Timestamp {
                        secs: 1000,
                        nanos: 0,
                    },
                    Policy {
                        min_prefix_bits: if case == "multi" { 8 } else { 0 },
                    },
                )
                .await
                .unwrap()
                .root_bytes
            })
            .unwrap();
        let extras = match case {
            "divergent" => 21_398,
            "fallback" => granary_core::binmap::SHARD_MAX_ENTRIES - 1,
            _ => 0,
        };
        let base = if extras == 0 {
            base
        } else {
            runtime
                .run(1, 100_000, seed_extra_map(objects.as_ref(), base, extras))
                .unwrap()
                .0
        };
        local
            .open_overlay(
                JournalHeader {
                    writer: local.writer_uuid(),
                    base_root: GrainId::of(&base),
                    base_seq: 1,
                    next_stage_id: 1,
                    receipt_generation: 0,
                },
                vec![],
                &mut Content::default(),
                OverlayDisk::new(&scratch.0, config.euid),
            )
            .unwrap();
        let mut doc = granary_core::root::decode_root(&base).unwrap();
        doc.writer_uuid = local.writer_uuid();
        doc.sigs.clear();
        doc.sigs.push(RootSig {
            key_id: key.key_id(),
            sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
        });
        let initial = granary_core::root::encode_root(&doc).unwrap();
        let request = local
            .prepare_registration(&initial, vec![], time.as_ref(), |_, _| true)
            .unwrap();
        local.dispatch(&request, time.as_ref()).unwrap();
        let answer = authority.send(&request);
        local
            .complete(
                &request,
                Ok(&answer),
                time.as_ref(),
                &mut granary_sim::rng::Rng::seeded(1, 54),
                0,
                None,
            )
            .unwrap();
        let metrics = ClientMetrics::new(&mut entropy);
        let content = Arc::new(Content {
            objects: Mutex::new(tree.nodes.into_iter().collect()),
            payloads: Mutex::default(),
            ..Content::default()
        });
        let remote = Arc::new(Remote {
            runtime: runtime.clone(),
            objects,
            source: content.clone(),
            authority: Mutex::new(authority),
            hold_upload: AtomicBool::new(false),
            fail_upload: AtomicBool::new(false),
            fenced: AtomicBool::new(false),
            upload_entered: AtomicBool::new(false),
            hold_reply: AtomicBool::new(false),
            reply_entered: AtomicBool::new(false),
            attempts: Mutex::default(),
            published: Mutex::new([(1, base.clone())].into_iter().collect()),
            replaced_heads: AtomicUsize::new(0),
            publication_sends: Mutex::default(),
            publication_plan: Mutex::default(),
            bin_ranges: Mutex::default(),
            probes: AtomicUsize::new(0),
            failed_probe: AtomicUsize::new(0),
            epoch: Mutex::new(granary_core::authlog::Epoch::from_bytes([3; 16])),
        });
        let store = Arc::new(Mutex::new(local));
        let engine = runtime
            .run(
                42,
                100_000,
                SyncEngine::with_runtime(
                    store.clone(),
                    remote.clone(),
                    content.clone(),
                    time.clone(),
                    time,
                    key,
                    trusted,
                    base.clone(),
                    metrics.clone(),
                    runtime.clone(),
                ),
            )
            .unwrap()
            .0
            .unwrap();
        Self {
            engine,
            store,
            remote,
            runtime,
            metrics,
            content,
            base,
            scratch,
        }
    }
    pub(crate) fn replay_landed(&self, root: &[u8], base: Vec<OverlayEntry>) {
        let doc = granary_core::root::decode_root(root).unwrap();
        let mut store = self.store.lock().unwrap();
        let header = JournalHeader {
            writer: store.writer_uuid(),
            base_root: GrainId::of(root),
            base_seq: doc.seq,
            next_stage_id: 1,
            receipt_generation: 0,
        };
        let euid = std::fs::metadata(&self.scratch.0).unwrap().uid();
        store
            .open_overlay(
                header,
                base,
                &mut Reader(self.content.clone()),
                OverlayDisk::new(&self.scratch.0, euid),
            )
            .unwrap();
    }

    pub(crate) fn writer(&self) -> [u8; 16] {
        self.store.lock().unwrap().writer_uuid()
    }

    /// Replace this fixture writer's live registered root, as the retained
    /// authority row read from a lost store would name it.
    pub(crate) fn select_registered(&self, root: Vec<u8>) {
        let writer = self.writer();
        let mut authority = self.remote.authority.lock().unwrap();
        let (receipt, selected_root) = authority.rows.get_mut(&writer).unwrap();
        receipt.state = ReceiptState::Live {
            prepared_root_id: GrainId::of(&root),
        };
        *selected_root = root;
    }

    pub(crate) fn add_live_writer(
        &self,
        writer: [u8; 16],
        epoch: u64,
        generation: u64,
        root: Vec<u8>,
    ) {
        let mut authority = self.remote.authority.lock().unwrap();
        authority.cursor = authority.cursor.max(epoch);
        authority.rows.insert(
            writer,
            (
                Receipt {
                    writer,
                    epoch,
                    instance: [90; 16],
                    generation,
                    state: ReceiptState::Live {
                        prepared_root_id: GrainId::of(&root),
                    },
                },
                root,
            ),
        );
    }

    pub(crate) fn remove_writer(&self, writer: [u8; 16]) {
        self.remote.authority.lock().unwrap().rows.remove(&writer);
    }

    pub(crate) fn select_from_readback(
        &self,
        writer: [u8; 16],
    ) -> Result<SelectedRecovery, CoordinationError> {
        let readback = self.remote.authority.lock().unwrap().readback();
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
        SelectedRecovery::from_readback(
            scope(),
            volume(),
            writer,
            &reply(200, None, Some(intent::MEDIA_READBACK), readback),
            |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok(),
        )
    }

    pub(crate) fn changed_takeover(
        &self,
        seed: u64,
        change: TakeoverChange,
    ) -> (u16, Phase, Option<String>, usize, usize) {
        let writer = self.writer();
        let selection = self.select_from_readback(writer).unwrap();
        let scratch = Scratch::new();
        let euid = std::fs::metadata(&scratch.0).unwrap().uid();
        let config = OverlayConfig {
            scope: scope(),
            volume: volume(),
            euid,
            cap: 4_294_967_296,
            ownership_completion_reserve: REPLACEMENT_RESERVE,
            instance: [0; 16],
        };
        let mut entropy = SeededSecureRandom::for_incarnation(seed, 2);
        let mut local = WritableStore::adopt_selected(
            Store::open(&scratch.0).unwrap(),
            config,
            OverlayDisk::new(&scratch.0, euid),
            &mut entropy,
            FaultControl::default(),
            selection.acknowledge_takeover(writer).unwrap(),
        )
        .unwrap();
        let time = Time {
            runtime: self.runtime.clone(),
            domain: MonotonicDomain::default(),
        };
        let request = local.begin_selected_attempt(&time).unwrap();
        local.dispatch(&request, &time).unwrap();
        let mut authority = self.remote.authority.lock().unwrap();
        match change {
            TakeoverChange::Epoch => authority.rows.get_mut(&writer).unwrap().0.epoch += 1,
            TakeoverChange::Generation => {
                authority.rows.get_mut(&writer).unwrap().0.generation += 1;
            }
            TakeoverChange::State => {
                authority.rows.get_mut(&writer).unwrap().0.state = ReceiptState::Live {
                    prepared_root_id: GrainId::of(b"another selected root"),
                };
            }
            TakeoverChange::Absent => {
                authority.rows.remove(&writer);
            }
        }
        let before = authority.sends.len();
        let answer = authority.send(&request);
        let status = answer.status();
        drop(authority);
        let result = local
            .complete(
                &request,
                Ok(&answer),
                &time,
                &mut granary_sim::rng::Rng::seeded(seed, 57),
                0,
                None,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
            .err();
        let sent = self.remote.authority.lock().unwrap().sends.len() - before;
        (
            status,
            local.snapshot().phase,
            result,
            sent,
            local.retained_requests().len(),
        )
    }

    pub(crate) fn publish_root(&self, root: Vec<u8>) {
        let seq = granary_core::root::decode_root(&root).unwrap().seq;
        self.remote.published.lock().unwrap().insert(seq, root);
    }

    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the method item cannot satisfy the transaction's higher-ranked lifetime"
    )]
    pub(crate) fn retained_answer_state(
        &self,
    ) -> (granary_core::retained_submission::Phase, bool, usize) {
        let mut local = self.store.lock().unwrap();
        let record = local
            .publication_transaction(|journal| journal.observe(&scope(), &volume()))
            .unwrap()
            .unwrap();
        let boundaries = local
            .overlay_transaction(|overlay| overlay.recovery_commits())
            .unwrap()
            .len();
        (record.phase, record.last_response.is_some(), boundaries)
    }

    pub(crate) fn register_root(&self, seed: u64, root: &[u8]) {
        let time = Time {
            runtime: self.runtime.clone(),
            domain: MonotonicDomain::default(),
        };
        let mut local = self.store.lock().unwrap();
        let request = local
            .prepare_registration(root, vec![], &time, |_, _| true)
            .unwrap();
        local.dispatch(&request, &time).unwrap();
        let answer = self.remote.authority.lock().unwrap().send(&request);
        local
            .complete(
                &request,
                Ok(&answer),
                &time,
                &mut granary_sim::rng::Rng::seeded(seed, 58),
                0,
                None,
            )
            .unwrap();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the intact row keeps reopen, refused pre-succession action, succession, publication and release in order"
    )]
    pub(crate) fn recover_intact(
        self,
        seed: u64,
    ) -> (
        Option<String>,
        usize,
        RecoveryRule,
        SelectedPublication,
        Option<ReceiptState>,
        usize,
    ) {
        let (scratch, remote, runtime) = journal::stop(self);
        let time = Time {
            runtime: runtime.clone(),
            domain: MonotonicDomain::default(),
        };
        let euid = std::fs::metadata(&scratch.0).unwrap().uid();
        let mut local = WritableStore::new(
            Store::open(&scratch.0).unwrap(),
            OverlayConfig {
                scope: scope(),
                volume: volume(),
                euid,
                cap: 4_294_967_296,
                ownership_completion_reserve: REPLACEMENT_RESERVE,
                instance: [35; 16],
            },
            OverlayDisk::new(&scratch.0, euid),
            &mut SeededSecureRandom::for_incarnation(seed, 4),
            FaultControl::default(),
            |_, _| true,
        )
        .unwrap();
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
        let writer = local.writer_uuid();
        let prepared = local.snapshot().root.clone();
        let before_early = remote.publication_sends.lock().unwrap().len();
        let mut early_entropy = SeededSecureRandom::for_incarnation(seed, 5);
        let (early, _) = runtime
            .run(seed, 100_000, async {
                let mut journal = RecoveryJournal::new(&mut local, remote.as_ref(), &trusted);
                begin_selected_publication(
                    RecoveryParts {
                        transport: remote.as_ref(),
                        journal: &mut journal,
                        publisher_keys: &trusted,
                        signer: &key,
                        secure: &mut early_entropy,
                        clock: &time,
                        delay: &mut Delay,
                    },
                    scope(),
                    volume(),
                    writer,
                    prepared.clone(),
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
            .unwrap();
        let early_sends = remote.publication_sends.lock().unwrap().len() - before_early;
        let succession = local.prepare_succession(&time).unwrap();
        local.dispatch(&succession, &time).unwrap();
        let answer = remote.authority.lock().unwrap().send(&succession);
        local
            .complete(
                &succession,
                Ok(&answer),
                &time,
                &mut granary_sim::rng::Rng::seeded(seed, 60),
                0,
                None,
            )
            .unwrap();
        let rule = local.recovery_rule().unwrap();
        let mut entropy = SeededSecureRandom::for_incarnation(seed, 3);
        let sends = remote.publication_sends.lock().unwrap().len();
        let (outcome, _) = runtime
            .run(seed, 100_000, async {
                let mut journal = RecoveryJournal::new(&mut local, remote.as_ref(), &trusted);
                begin_selected_publication(
                    RecoveryParts {
                        transport: remote.as_ref(),
                        journal: &mut journal,
                        publisher_keys: &trusted,
                        signer: &key,
                        secure: &mut entropy,
                        clock: &time,
                        delay: &mut Delay,
                    },
                    scope(),
                    volume(),
                    writer,
                    prepared,
                )
                .await
                .unwrap()
            })
            .unwrap();
        let release = local
            .prepare_recovery_release(&time, DEFAULT_RESOLUTION_BOUND)
            .unwrap();
        local.dispatch(&release, &time).unwrap();
        let answer = remote.authority.lock().unwrap().send(&release);
        local
            .complete(
                &release,
                Ok(&answer),
                &time,
                &mut granary_sim::rng::Rng::seeded(seed, 59),
                0,
                None,
            )
            .unwrap();
        let state = remote
            .authority
            .lock()
            .unwrap()
            .rows
            .get(&writer)
            .map(|(row, _)| row.state);
        let made = remote.publication_sends.lock().unwrap().len() - sends;
        drop(local);
        drop(scratch);
        (early.err(), early_sends, rule, outcome, state, made)
    }

    pub(crate) fn clear_bin_ranges(&self) {
        self.remote.bin_ranges.lock().unwrap().clear();
    }

    pub(crate) fn into_recovery_store(
        self,
    ) -> (
        Scratch,
        Arc<Remote>,
        Arc<SimSyncRuntime>,
        WritableStore<OverlayDisk>,
        granary_core::retained_submission::Submission,
    ) {
        let content = self.content.clone();
        let base = self.base.clone();
        let (scratch, remote, runtime) = journal::stop(self);
        let time = Time {
            runtime: runtime.clone(),
            domain: MonotonicDomain::default(),
        };
        let mut local = successor_store(&scratch, &remote, &time);
        let euid = std::fs::metadata(&scratch.0).unwrap().uid();
        let record = local
            .publication_transaction(|j| j.observe(&scope(), &volume()))
            .unwrap()
            .unwrap();
        local
            .open_overlay(
                JournalHeader {
                    writer: local.writer_uuid(),
                    base_root: GrainId::of(&base),
                    base_seq: 1,
                    next_stage_id: 1,
                    receipt_generation: 0,
                },
                vec![],
                &mut Reader(content),
                OverlayDisk::new(&scratch.0, euid),
            )
            .unwrap();
        (scratch, remote, runtime, local, record)
    }

    pub(crate) fn settle_fence(
        self,
        seed: u64,
        acknowledge: bool,
    ) -> (Option<String>, usize, RecoveryRule) {
        let (_scratch, remote, runtime, mut local, record) = self.into_recovery_store();
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let keys = TrustedKeys::new([*key.public_key()]).unwrap();
        let (result, _) = runtime
            .run(
                seed,
                100_000,
                granary_client::settle_recovery_boundary(
                    &mut local,
                    remote.as_ref(),
                    &keys,
                    acknowledge.then_some(record.publication_id),
                ),
            )
            .unwrap();
        let rule = local.recovery_rule().unwrap();
        let sends = remote.publication_sends.lock().unwrap().len();
        (result.err().map(|e| e.to_string()), sends, rule)
    }

    pub(crate) fn bin_ranges(&self) -> Vec<BinRangeRead> {
        self.remote.bin_ranges.lock().unwrap().clone()
    }

    /// Recover this store's writer as if its disk were lost: on a fresh store
    /// that never sees this one's disk, select the authority's live row from
    /// its readback, take it over, run the selected publication through a
    /// recovery journal over the remote, then release the row. This store is
    /// left idle. The publication's answer, the authority's row state after
    /// the release, and the publication sends the recovery made.
    pub(crate) fn recover_destroyed(
        &self,
        seed: u64,
    ) -> (SelectedPublication, Option<ReceiptState>, usize) {
        let (outcome, state, sends) = self.try_recover_destroyed(seed);
        (outcome.unwrap(), state, sends)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one recovery keeps selection, takeover, publication and conditional release in order"
    )]
    pub(crate) fn try_recover_destroyed(
        &self,
        seed: u64,
    ) -> (
        Result<SelectedPublication, RecoveryError>,
        Option<ReceiptState>,
        usize,
    ) {
        let (remote, runtime) = (&self.remote, &self.runtime);
        let time = Time {
            runtime: runtime.clone(),
            domain: MonotonicDomain::default(),
        };
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
        let writer = self.store.lock().unwrap().writer_uuid();
        let readback = remote.authority.lock().unwrap().readback();
        let scratch = Scratch::new();
        let euid = std::fs::metadata(&scratch.0).unwrap().uid();
        let config = OverlayConfig {
            scope: scope(),
            volume: volume(),
            euid,
            cap: 4_294_967_296,
            ownership_completion_reserve: REPLACEMENT_RESERVE,
            instance: [0; 16],
        };
        let mut entropy = SeededSecureRandom::for_incarnation(seed, 1);
        let selection = SelectedRecovery::from_readback(
            scope(),
            volume(),
            writer,
            &reply(200, None, Some(intent::MEDIA_READBACK), readback),
            |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok(),
        )
        .unwrap();
        let mut local = WritableStore::adopt_selected(
            Store::open(&scratch.0).unwrap(),
            config,
            OverlayDisk::new(&scratch.0, euid),
            &mut entropy,
            FaultControl::default(),
            selection.acknowledge_takeover(writer).unwrap(),
        )
        .unwrap();
        let takeover = local.begin_selected_attempt(&time).unwrap();
        local.dispatch(&takeover, &time).unwrap();
        let answer = remote.authority.lock().unwrap().send(&takeover);
        local
            .complete(
                &takeover,
                Ok(&answer),
                &time,
                &mut granary_sim::rng::Rng::seeded(seed, 55),
                0,
                None,
            )
            .unwrap();
        let prepared = local.snapshot().selected_root.clone();
        let sends = remote.publication_sends.lock().unwrap().len();
        let (outcome, _) = runtime
            .run(seed, 100_000, async {
                let mut journal = RecoveryJournal::new(&mut local, remote.as_ref(), &trusted);
                begin_selected_publication(
                    RecoveryParts {
                        transport: remote.as_ref(),
                        journal: &mut journal,
                        publisher_keys: &trusted,
                        signer: &key,
                        secure: &mut entropy,
                        clock: &time,
                        delay: &mut Delay,
                    },
                    scope(),
                    volume(),
                    writer,
                    prepared,
                )
                .await
            })
            .unwrap();
        if outcome.as_ref().is_ok_and(|outcome| {
            matches!(
                outcome,
                SelectedPublication::Driven(_) | SelectedPublication::Subsumed { .. }
            )
        }) {
            let release = local
                .prepare_recovery_release(&time, DEFAULT_RESOLUTION_BOUND)
                .unwrap();
            local.dispatch(&release, &time).unwrap();
            let answer = remote.authority.lock().unwrap().send(&release);
            local
                .complete(
                    &release,
                    Ok(&answer),
                    &time,
                    &mut granary_sim::rng::Rng::seeded(seed, 56),
                    0,
                    None,
                )
                .unwrap();
        }
        let state = remote
            .authority
            .lock()
            .unwrap()
            .rows
            .get(&writer)
            .map(|(row, _)| row.state);
        let made = remote.publication_sends.lock().unwrap().len() - sends;
        (outcome, state, made)
    }

    /// Drop the engine and the store and reopen the same overlay under a
    /// successor instance, as a restart does: an unsubmitted boundary is
    /// discarded and the authority's registered root is registered again.
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
    )]
    pub(crate) fn restart(self) -> Self {
        let Self {
            engine,
            store,
            remote,
            runtime,
            metrics,
            content,
            base,
            scratch,
        } = self;
        drop(engine);
        drop(Arc::into_inner(store).unwrap());
        let time = Arc::new(Time {
            runtime: runtime.clone(),
            domain: MonotonicDomain::default(),
        });
        let mut local = successor_store(&scratch, &remote, time.as_ref());
        local
            .open_overlay(
                JournalHeader {
                    writer: local.writer_uuid(),
                    base_root: GrainId::of(&base),
                    base_seq: 1,
                    next_stage_id: 1,
                    receipt_generation: 0,
                },
                vec![],
                &mut Reader(content.clone()),
                OverlayDisk::new(&scratch.0, std::fs::metadata(&scratch.0).unwrap().uid()),
            )
            .unwrap();
        let retained = local
            .publication_transaction(|j| j.load(&scope(), &volume()))
            .unwrap()
            .is_some();
        // A retained submission whose last answer proved it cannot land is
        // reconciled before registration, as an unsubmitted boundary is; any
        // other retained submission keeps its lane for the engine to recover.
        let rejected = retained && local.reconcile_commit_rejection().is_ok();
        if !retained || rejected {
            if local
                .overlay_transaction(|t| t.recovery_commits())
                .unwrap()
                .len()
                == 1
            {
                local.reconcile_unsubmitted_commit().unwrap();
            }
            register_again(&mut local, &remote, time.as_ref());
        }
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
        let store = Arc::new(Mutex::new(local));
        let engine = runtime
            .run(
                42,
                100_000,
                SyncEngine::with_runtime(
                    store.clone(),
                    remote.clone(),
                    content.clone(),
                    time.clone(),
                    time,
                    key,
                    trusted,
                    base.clone(),
                    metrics.clone(),
                    runtime.clone(),
                ),
            )
            .unwrap()
            .0
            .unwrap();
        Self {
            engine,
            store,
            remote,
            runtime,
            metrics,
            content,
            base,
            scratch,
        }
    }

    pub(crate) fn create(&self, name: &str, bytes: &[u8]) -> u64 {
        self.store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                let stage = t.create_file(at(name), false)?;
                for (index, chunk) in bytes.chunks(65_536).enumerate() {
                    t.write(stage, (index as u64) * 65_536, chunk)?;
                }
                Ok(stage)
            })
            .unwrap()
    }
    pub(crate) fn sync_tree(&self, seed: u64) -> (Result<(), CoordinationError>, Vec<u64>) {
        self.sync_target(seed, SyncTarget::Tree)
    }
    pub(crate) fn sync(&self, seed: u64, stage: u64) -> (Result<(), CoordinationError>, Vec<u64>) {
        self.sync_target(seed, SyncTarget::Stage(stage))
    }
    fn sync_target(
        &self,
        seed: u64,
        target: SyncTarget,
    ) -> (Result<(), CoordinationError>, Vec<u64>) {
        let engine = self.engine.clone();
        self.runtime
            .run(seed, 100_000, async move {
                engine
                    .sync(
                        target,
                        SyncOptions {
                            workspace_bytes: 2_147_483_648,
                            ..SyncOptions::default()
                        },
                    )
                    .wait()
                    .await
            })
            .unwrap()
    }
    pub(crate) fn registered(&self) -> Vec<u8> {
        let writer = self.store.lock().unwrap().writer_uuid();
        self.remote
            .authority
            .lock()
            .unwrap()
            .rows
            .get(&writer)
            .unwrap()
            .1
            .clone()
    }
    pub(crate) fn metrics(&self) -> String {
        self.metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
    }
    pub(crate) fn assert_file(&self, root: &[u8], name: &str, expected: &[u8]) {
        let doc = granary_core::root::decode_root(root).unwrap();
        let bytes = self.content.get(&doc.manifest_root).unwrap();
        let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
        let entries = manifest::decode_dir_leaf(cursor).unwrap();
        let entry = entries
            .iter()
            .find(|e| e.name.as_bytes() == name.as_bytes())
            .unwrap();
        let manifest::EntryKind::File { size, grains, .. } = &entry.kind else {
            panic!("expected file");
        };
        let id = GrainId::of(&manifest::node::file_payload(*size, grains).unwrap());
        assert_eq!(
            self.content
                .read_content(id, 0, usize::try_from(*size).unwrap())
                .unwrap(),
            expected
        );
    }
}
pub(crate) fn at(name: &str) -> granary_core::overlay_journal::Location {
    granary_core::overlay_journal::Location {
        parent: granary_core::overlay_journal::Parent::new(vec![]).unwrap(),
        name: manifest::Name::new(name.as_bytes().to_vec()).unwrap(),
    }
}

/// Prepare and upload one flat manifest over the current remote head without
/// publishing its root.
pub(crate) async fn prepared_root(
    fixture: &Fixture,
    files: &[(&str, &[u8])],
    writer: [u8; 16],
) -> Vec<u8> {
    let entries = files
        .iter()
        .map(|(name, body)| {
            let id = GrainId::of(body);
            fixture.content.put_object(id, body).unwrap();
            let grains = FileGrains::Inline(vec![manifest::GrainRef {
                id,
                unpacked_len: u32::try_from(body.len()).unwrap(),
            }]);
            let payload = GrainId::of(
                &manifest::node::file_payload(u64::try_from(body.len()).unwrap(), &grains).unwrap(),
            );
            fixture
                .content
                .remember_payload(payload, u64::try_from(body.len()).unwrap(), &grains)
                .unwrap();
            manifest::DirEntry {
                name: manifest::Name::new(name.as_bytes().to_vec()).unwrap(),
                kind: manifest::EntryKind::File {
                    exec: false,
                    size: u64::try_from(body.len()).unwrap(),
                    grains,
                },
            }
        })
        .collect::<Vec<_>>();
    let tree = manifest::build_dir(&entries).unwrap();
    for (id, bytes) in tree.nodes {
        fixture.content.put_object(id, &bytes).unwrap();
    }
    let prepared = prepare_from_manifest(
        fixture.remote.as_ref(),
        fixture.content.as_ref(),
        tree.root,
        HarvestStats::default(),
        &volume(),
        &SigningKey::from_seed(&[39; 32]).unwrap(),
        &granary_core::identity::WriterIdentity::from_bytes(writer),
        Timestamp {
            secs: 1001,
            nanos: 0,
        },
        Policy::default(),
    )
    .await
    .unwrap();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let mut doc = granary_core::root::decode_root(&prepared.root_bytes).unwrap();
    doc.writer_uuid = writer;
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    granary_core::root::encode_root(&doc).unwrap()
}

/// The exact bin range a signed root maps for `id`.
pub(crate) async fn bin_extent(
    fixture: &Fixture,
    root: &[u8],
    id: GrainId,
) -> ([u8; 32], u64, u32) {
    let doc = granary_core::root::decode_root(root).unwrap();
    let index = fixture
        .remote
        .get_meta(volume().as_str(), &doc.binmap_index)
        .await
        .unwrap();
    let index = granary_core::binmap::decode_binmap_index(&index).unwrap();
    let shard = index
        .shards
        .get(granary_core::binmap::shard_for(&id, index.prefix_bits))
        .unwrap();
    let shard = fixture
        .remote
        .get_meta(volume().as_str(), shard)
        .await
        .unwrap();
    let entry = granary_core::binmap::decode_shard(&shard)
        .unwrap()
        .into_iter()
        .find(|entry| entry.id == id)
        .unwrap();
    let table = fixture
        .remote
        .get_meta(volume().as_str(), &index.bin_table)
        .await
        .unwrap();
    let table = granary_core::binmap::decode_bin_table(&table).unwrap();
    (
        *table
            .get(usize::try_from(entry.bin_ordinal).unwrap())
            .unwrap(),
        entry.offset,
        entry.comp_len,
    )
}

/// The authority's head moves on a path the commit does not touch.
pub(crate) async fn foreign_head(fixture: &Fixture) {
    let tree = manifest::build_dir(&[manifest::DirEntry {
        name: manifest::Name::new(b"remote".to_vec()).unwrap(),
        kind: manifest::EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(vec![]),
        },
    }])
    .unwrap();
    for (id, bytes) in tree.nodes {
        fixture.content.put_object(id, &bytes).unwrap();
    }
    let head = prepare_from_manifest(
        fixture.remote.as_ref(),
        fixture.content.as_ref(),
        tree.root,
        HarvestStats::default(),
        &volume(),
        &SigningKey::from_seed(&[39; 32]).unwrap(),
        &granary_core::identity::WriterIdentity::from_bytes([77; 16]),
        Timestamp {
            secs: 1001,
            nanos: 0,
        },
        Policy::default(),
    )
    .await
    .unwrap();
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(2, head.root_bytes);
}

use granary_core::rootstore::{HintRead, HintToken, RootStore, filter_above};
use granary_core::{
    authlog::Epoch,
    authority_answer::{self, Head, Position, PublishAnswer, VolumeStatus},
};
use std::{future::Future, pin::Pin};
impl RootStore for Remote {
    async fn put_root(&self, _: &str, _: u64, _: Vec<u8>) -> Result<(), RootStoreError> {
        panic!("engine bypassed retained authority submission")
    }
    async fn get_root(&self, _: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        yield_once().await;
        Ok(self.published.lock().unwrap().get(&seq).cloned())
    }
    async fn max_seq(&self, _: &str) -> Result<Option<u64>, RootStoreError> {
        yield_once().await;
        Ok(self.published.lock().unwrap().keys().copied().max())
    }
    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
    async fn read_hint(&self, _: &str, _: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        Ok(HintRead::Missing)
    }
    async fn write_hint(&self, _: &str, _: u64) -> Result<(), RootStoreError> {
        panic!("engine wrote hint")
    }
}
pub(crate) enum PublishPlan {
    Land,
    Accepted,
    Timeout,
    DelayedLand,
    Internal,
    RateLimited,
    Reject,
    StaleForeign,
    StaleForeignUnreadable,
    StaleRoot(Vec<u8>),
    StaleCurrent,
    EpochMismatch,
}

impl AuthorityTransport for Remote {
    #[expect(
        clippy::too_many_lines,
        reason = "the deterministic fake keeps all checked publication replies in one scripted transition"
    )]
    async fn publish_once(
        &self,
        request: &PublishRequest,
    ) -> Result<PublishResponse, AuthorityError> {
        yield_once().await;
        self.publication_sends
            .lock()
            .unwrap()
            .push(request.candidate().bytes().to_vec());
        let action = self
            .publication_plan
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(PublishPlan::Land);
        let position = Position {
            epoch: request.epoch(),
            entry_seq: 1,
        };
        let (status, token, answer) = match action {
            PublishPlan::Land => {
                self.published.lock().unwrap().insert(
                    request.candidate().seq(),
                    request.candidate().bytes().to_vec(),
                );
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
            PublishPlan::StaleCurrent => {
                let head = self
                    .published
                    .lock()
                    .unwrap()
                    .last_key_value()
                    .map(|(seq, bytes)| (*seq, GrainId::of(bytes)))
                    .unwrap();
                (
                    409,
                    Some("stale-base"),
                    PublishAnswer::StaleBase(Head::new(Some(head))),
                )
            }
            PublishPlan::StaleRoot(bytes) => {
                let doc = granary_core::root::decode_root(&bytes).unwrap();
                self.published
                    .lock()
                    .unwrap()
                    .insert(doc.seq, bytes.clone());
                (
                    409,
                    Some("stale-base"),
                    PublishAnswer::StaleBase(Head::new(Some((doc.seq, GrainId::of(&bytes))))),
                )
            }
            action @ (PublishPlan::StaleForeign | PublishPlan::StaleForeignUnreadable) => {
                let base = self
                    .published
                    .lock()
                    .unwrap()
                    .last_key_value()
                    .unwrap()
                    .1
                    .clone();
                let base = granary_core::root::decode_root(&base).unwrap();
                let prepared = granary_client::prepare_from_manifest(
                    self,
                    self.source.as_ref(),
                    base.manifest_root,
                    HarvestStats::default(),
                    &base.volume,
                    &SigningKey::from_seed(&[39; 32]).unwrap(),
                    &granary_core::identity::WriterIdentity::from_bytes([77; 16]),
                    base.timestamp,
                    Policy { min_prefix_bits: 0 },
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
            PublishPlan::EpochMismatch => {
                let epoch = Epoch::from_bytes([5; 16]);
                *self.epoch.lock().unwrap() = epoch;
                (
                    409,
                    Some("epoch-mismatch"),
                    PublishAnswer::EpochMismatch { epoch, head: None },
                )
            }
            PublishPlan::Timeout => return Err(AuthorityError::Elapsed),
            PublishPlan::DelayedLand => {
                self.published.lock().unwrap().insert(
                    request.candidate().seq(),
                    request.candidate().bytes().to_vec(),
                );
                self.runtime.sleep(Duration::from_mins(1)).await;
                return Err(AuthorityError::Elapsed);
            }
            PublishPlan::Internal => {
                return validate_publish_answer(request, 500, Some("internal"), &[]);
            }
            PublishPlan::RateLimited => {
                return validate_publish_answer(request, 429, Some("rate-limited"), &[]);
            }
            PublishPlan::Reject => {
                return validate_publish_answer(request, 400, Some("invalid-candidate"), &[]);
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
        let head = self
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .map(|(seq, bytes)| Head::new(Some((*seq, GrainId::of(bytes)))));
        validate_status_observation(
            &authority_answer::encode_status(VolumeStatus {
                epoch: *self.epoch.lock().unwrap(),
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
        let probe = self.probes.fetch_add(1, Ordering::Relaxed) + 1;
        if self.failed_probe.load(Ordering::Relaxed) == probe {
            return Err(RootStoreError::Backend("claimed root unavailable".into()));
        }
        self.get_root(volume, seq).await
    }
}

pub(crate) struct Delay;
impl RecoveryDelay for Delay {
    fn jitter(&mut self, _: Duration) -> Duration {
        Duration::ZERO
    }
    fn wait(&mut self, _: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

pub(crate) fn submission_child(mode: &str) {
    let root = std::env::var_os("GRANARY_SYNC_SCRATCH").unwrap();
    let fixture = Fixture::with_scratch(Scratch(root.into()));
    fixture.create("file", b"submission boundary");
    match std::env::var("GRANARY_SUBMISSION_TRANSITION")
        .unwrap()
        .as_str()
    {
        "epoch-save" | "operation-save" => fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::EpochMismatch, PublishPlan::Land]),
        "replacement-save" => fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::StaleForeign, PublishPlan::Land]),
        _ => {}
    }
    granary_client::publish_restart::initialize().unwrap();
    let result = fixture
        .runtime
        .run(42, 100_000, async {
            let lane = fixture
                .engine
                .construct_commit(
                    SyncOptions::default(),
                    &mut SeededSecureRandom::for_incarnation(44, 0),
                )
                .await?;
            fixture
                .engine
                .drive_commit(
                    &lane,
                    &mut SeededSecureRandom::for_incarnation(45, 0),
                    &mut Delay,
                    RecoveryIntent::Continue,
                    SyncOptions::default(),
                )
                .await
        })
        .unwrap()
        .0;
    if mode == "fail" {
        assert!(
            result.is_err(),
            "submission persistence failure acknowledged"
        );
    } else {
        let result = result.unwrap();
        assert!(matches!(result.outcome, PublicationOutcome::Landed(_)));
        fixture.assert_file(&fixture.registered(), "file", b"submission boundary");
    }
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
    );
}

pub(crate) fn spill_bytes() -> Vec<u8> {
    let mut rng = granary_sim::rng::Rng::seeded(73, 54);
    let mut bytes = Vec::with_capacity(67_108_864);
    for _ in 0..16_777_216 {
        bytes.extend_from_slice(&rng.next_u32().to_le_bytes());
    }
    bytes
}

pub(crate) fn replay_child(seed: u64) {
    let root = std::env::var_os("GRANARY_SYNC_SCRATCH").unwrap();
    let fixture = Fixture::with_scratch(Scratch(root.into()));
    let stage = fixture.create("file", b"before");
    let (lane, _) = fixture
        .runtime
        .run(seed, 100_000, async {
            fixture
                .engine
                .construct_commit(
                    SyncOptions::default(),
                    &mut SeededSecureRandom::for_incarnation(44, 0),
                )
                .await
                .unwrap()
        })
        .unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 0, b"after!").map(|_| ()))
        .unwrap();
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.trace_sync();
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    let ((), trace) = fixture
        .runtime
        .run(seed, 100_000, async {
            while !faults
                .sync_fired()
                .iter()
                .any(|e| e.name == "sync.commit_wait")
            {
                yield_once().await;
            }
            fixture.runtime.sleep(Duration::from_millis(120)).await;
            fixture
                .engine
                .drive_commit(
                    &lane,
                    &mut SeededSecureRandom::for_incarnation(45, 0),
                    &mut Delay,
                    RecoveryIntent::Continue,
                    SyncOptions::default(),
                )
                .await
                .unwrap();
            waiter.wait().await.unwrap();
        })
        .unwrap();
    fixture.assert_file(&fixture.registered(), "file", b"after!");
    let polls: Vec<_> = trace.iter().map(ToString::to_string).collect();
    println!(
        "REPLAY,{},{}",
        GrainId::of(&fixture.registered()),
        polls.join(":")
    );
}

/// The root a from-scratch build gives these files: the oracle for a tree
/// assembled from reused landed subtrees and re-encoded paths.
pub(crate) fn oracle_root(files: &[(&str, &[u8])]) -> GrainId {
    use granary_core::manifest::{DirEntry, EntryKind, GrainRef, Name};
    let name = |s: &str| Name::new(s.as_bytes().to_vec()).unwrap();
    let mut dirs: BTreeMap<Vec<String>, Vec<DirEntry>> = BTreeMap::from([(vec![], vec![])]);
    for (path, _) in files {
        let parts: Vec<String> = path.split('/').map(str::to_owned).collect();
        for end in 1..parts.len() {
            dirs.entry(parts.get(..end).unwrap().to_vec()).or_default();
        }
    }
    for (path, bytes) in files {
        let parts: Vec<String> = path.split('/').map(str::to_owned).collect();
        let refs: Vec<manifest::GrainRef> = granary_core::thresh::grains(bytes)
            .map(|grain| GrainRef {
                id: GrainId::of(
                    bytes
                        .get(grain.offset..grain.offset + grain.length)
                        .unwrap(),
                ),
                unpacked_len: u32::try_from(grain.length).unwrap(),
            })
            .collect();
        let (leaf, parent) = parts.split_last().unwrap();
        dirs.get_mut(parent).unwrap().push(DirEntry {
            name: name(leaf),
            kind: EntryKind::File {
                exec: false,
                size: bytes.len() as u64,
                grains: FileGrains::Inline(refs),
            },
        });
    }
    let mut paths: Vec<_> = dirs.keys().cloned().collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
    let mut root = None;
    for path in paths {
        let mut entries = dirs.remove(&path).unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let built = manifest::build_dir(&entries).unwrap();
        match path.split_last() {
            Some((leaf, parent)) => dirs.get_mut(parent).unwrap().push(DirEntry {
                name: name(leaf),
                kind: EntryKind::Dir { child: built.root },
            }),
            None => root = Some(built.root),
        }
    }
    root.unwrap()
}

async fn seed_extra_map(objects: &SimStore, base: Vec<u8>, count: u32) -> Vec<u8> {
    use granary_core::{binfmt, binmap};
    let mut doc = granary_core::root::decode_root(&base).unwrap();
    let index =
        binmap::decode_binmap_index(&objects.get_meta("v", &doc.binmap_index).await.unwrap())
            .unwrap();
    assert_eq!(index.prefix_bits, 0);
    let mut table =
        binmap::decode_bin_table(&objects.get_meta("v", &index.bin_table).await.unwrap()).unwrap();
    let mut entries = binmap::decode_shard(
        &objects
            .get_meta("v", index.shards.first().unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    let mut codec = granary_store::codec::GrainCodec::new().unwrap();
    for begin in (0..count).step_by(10_000) {
        let frames: Vec<_> = (begin..count.min(begin + 10_000))
            .map(|n| {
                let bytes = n.to_le_bytes();
                binfmt::PackedFrame {
                    id: GrainId::of(&bytes),
                    frame: codec.compress_grain(&bytes).unwrap(),
                }
            })
            .collect();
        let bytes = binfmt::encode_bin(&frames).unwrap();
        let digest = *GrainId::of(&bytes).digest();
        let ordinal = u32::try_from(table.len()).unwrap();
        table.push(digest);
        for entry in binfmt::decode_bin(&bytes).unwrap() {
            entries.push(binmap::ShardEntry {
                id: entry.id,
                bin_ordinal: ordinal,
                offset: entry.offset,
                comp_len: entry.comp_len,
            });
        }
        objects.put_bin(&digest, bytes).await.unwrap();
    }
    entries.sort_unstable_by_key(|entry| entry.id);
    let shard = binmap::encode_shard(&entries).unwrap();
    let shard_id = GrainId::of(&shard);
    objects.put_meta("v", &shard_id, shard).await.unwrap();
    let table = binmap::encode_bin_table(&table).unwrap();
    let table_id = GrainId::of(&table);
    objects.put_meta("v", &table_id, table).await.unwrap();
    let index = binmap::encode_binmap_index(0, table_id, &[shard_id]).unwrap();
    doc.binmap_index = GrainId::of(&index);
    objects
        .put_meta("v", &doc.binmap_index, index)
        .await
        .unwrap();
    doc.sigs.clear();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    granary_core::root::encode_root(&doc).unwrap()
}
