// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn stop(fixture: Fixture) -> (Scratch, Arc<Remote>, Arc<SimSyncRuntime>) {
    let Fixture {
        engine,
        store,
        remote,
        runtime,
        scratch,
        ..
    } = fixture;
    drop(engine);
    drop(Arc::into_inner(store).unwrap());
    (scratch, remote, runtime)
}

/// The simulated content provider keeps immutable data in memory. Persist it
/// through the production content seam before handing the journal to recovery.
pub(crate) fn persist_content(fixture: &Fixture) {
    let objects = fixture.content.objects.lock().unwrap().clone();
    let payloads = fixture.content.payloads.lock().unwrap().clone();
    let mut local = fixture.store.lock().unwrap();
    let mut immutable = local.immutable_content().unwrap();
    for (id, bytes) in objects {
        immutable.put_object(id, &bytes).unwrap();
    }
    for (id, (size, grains)) in payloads {
        immutable.remember_payload(id, size, &grains).unwrap();
    }
}

/// Recovery's facade shares the simulated authority and transport with the
/// engine that left the journal, so a second invocation sees the same evidence.
#[derive(Clone)]
struct RecoveryRemote(Arc<Remote>);
impl granary_core::rootstore::RootStore for RecoveryRemote {
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        self.0.put_root(v, n, b).await
    }
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.0.get_root(v, n).await
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        self.0.max_seq(v).await
    }
    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.0.max_seq_above(v, floor).await
    }
    async fn read_hint(
        &self,
        v: &str,
        token: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        self.0.read_hint(v, token).await
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        self.0.write_hint(v, n).await
    }
}
impl BinStore for RecoveryRemote {
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.0.put_bin(d, b).await
    }
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.0.put_meta(v, id, b).await
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.0.get_meta(v, id).await
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        self.0.get_bin_range(d, o, n).await
    }
}
impl AuthorityTransport for RecoveryRemote {
    async fn publish_once(&self, r: &PublishRequest) -> Result<PublishResponse, AuthorityError> {
        self.0.publish_once(r).await
    }
    async fn status_once(&self, v: &str) -> Result<StatusResponse, AuthorityError> {
        self.0.status_once(v).await
    }
    async fn probe_root_once(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.0.probe_root_once(v, n).await
    }
}
impl SyncRemote for RecoveryRemote {
    async fn register_once(
        &self,
        r: &PendingIntent,
        keys: &TrustedKeys,
    ) -> Result<IntentReply, IntentTransportError> {
        self.0.register_once(r, keys).await
    }
    async fn release_once(&self, r: &PendingIntent) -> Result<IntentReply, IntentTransportError> {
        self.0.release_once(r).await
    }
}
impl MountMetrics for RecoveryRemote {
    fn client_metrics(&self) -> Option<&ClientMetrics> {
        None
    }
}
impl WritableAuthority for RecoveryRemote {
    fn read_facade(&self) -> Self {
        self.clone()
    }
    async fn writable_status(&self, v: &VolumeName) -> Result<StatusResponse, AuthorityError> {
        self.0.status_once(v.as_str()).await
    }
    async fn writable_readback(
        &self,
        _: &Scope,
        _: &VolumeName,
        _: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        let bytes = self.0.authority.lock().unwrap().readback();
        Ok(reply(200, None, Some(intent::MEDIA_READBACK), bytes))
    }
    async fn writable_send(
        &self,
        _: &Scope,
        r: &PendingIntent,
        _: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        Ok(self.0.authority.lock().unwrap().send(r))
    }
    async fn writable_wait(&self, millis: u64) {
        TokioSyncRuntime.sleep(Duration::from_millis(millis)).await;
    }
}

pub(crate) struct Journal {
    pub(crate) scratch: Scratch,
    pub(crate) remote: Arc<Remote>,
    runtime: Arc<SimSyncRuntime>,
    writer: [u8; 16],
}
impl Journal {
    pub(crate) fn new(fixture: Fixture) -> Self {
        let writer = fixture.store.lock().unwrap().writer_uuid();
        let (scratch, remote, runtime) = stop(fixture);
        Self {
            scratch,
            remote,
            runtime,
            writer,
        }
    }
    pub(crate) fn run(
        &self,
        incarnation: u32,
        faults: FaultControl,
        acknowledge: bool,
    ) -> Result<RecoveryOutcome, String> {
        let euid = std::fs::metadata(&self.scratch.0).unwrap().uid();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let key = SigningKey::from_seed(&[39; 32]).unwrap();
        let keys = TrustedKeys::new([*key.public_key()]).unwrap();
        let clock = Time {
            runtime: self.runtime.clone(),
            domain: MonotonicDomain::default(),
        };
        RecoveryCommand {
            construction_workspace_bytes: SyncOptions::default().workspace_bytes,
            local: Some((
                Store::open(&self.scratch.0).unwrap(),
                OverlayDisk::new(&self.scratch.0, euid),
            )),
            config: OverlayConfig {
                scope: scope(),
                volume: volume(),
                euid,
                cap: 4_294_967_296,
                ownership_completion_reserve: REPLACEMENT_RESERVE,
                instance: [0; 16],
            },
            transport: &RecoveryRemote(self.remote.clone()),
            runtime: &runtime,
            signer: &key,
            publisher_keys: &keys,
            writer: self.writer,
            acknowledge_takeover: acknowledge.then_some(self.writer),
            acknowledge_resend: None,
            faults,
        }
        .run(
            &Arc::new(clock),
            SigningKey::from_seed(&[39; 32]).unwrap(),
            &mut SeededSecureRandom::for_incarnation(82, incarnation),
            granary_sim::rng::Rng::seeded(82, u64::from(incarnation)),
        )
        .map_err(|error| error.to_string())
    }
    pub(crate) fn displace(&self) {
        let mut authority = self.remote.authority.lock().unwrap();
        authority.cursor += 1;
        let epoch = authority.cursor;
        let receipt = &mut authority.rows.get_mut(&self.writer).unwrap().0;
        receipt.epoch = epoch;
        receipt.instance = [99; 16];
    }
    pub(crate) fn classifier(&self) -> RecoveryRule {
        let euid = std::fs::metadata(&self.scratch.0).unwrap().uid();
        let mut store = WritableStore::new(
            Store::open(&self.scratch.0).unwrap(),
            OverlayConfig {
                scope: scope(),
                volume: volume(),
                euid,
                cap: 4_294_967_296,
                ownership_completion_reserve: REPLACEMENT_RESERVE,
                instance: [0; 16],
            },
            OverlayDisk::new(&self.scratch.0, euid),
            &mut SeededSecureRandom::for_incarnation(83, 1),
            FaultControl::default(),
            |_, _| true,
        )
        .unwrap();
        store.recovery_rule().unwrap()
    }
    pub(crate) fn released(&self) -> bool {
        self.remote
            .authority
            .lock()
            .unwrap()
            .rows
            .get(&self.writer)
            .is_some_and(|(receipt, _)| receipt.state == ReceiptState::Released)
    }
    pub(crate) fn file(&self, name: &str) -> Vec<u8> {
        let root = self
            .remote
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .unwrap()
            .1
            .clone();
        let doc = granary_core::root::decode_root(&root).unwrap();
        let (_, objects) = self
            .runtime
            .run(
                82,
                100_000,
                granary_client::resolve_at_collecting(self.remote.as_ref(), "v", doc.seq),
            )
            .unwrap()
            .0
            .unwrap();
        let bytes = objects.get(&doc.manifest_root).unwrap();
        let (_, cursor) = granary_core::encoding::open_envelope(bytes).unwrap();
        let entries = manifest::decode_dir_leaf(cursor).unwrap();
        let Some(entry) = entries
            .iter()
            .find(|e| e.name.as_bytes() == name.as_bytes())
        else {
            return Vec::new();
        };
        let manifest::EntryKind::File {
            size,
            grains: FileGrains::Inline(grains),
            ..
        } = &entry.kind
        else {
            panic!("small file fixture spilled");
        };
        let mut result = grains
            .iter()
            .flat_map(|grain| objects.get(&grain.id).unwrap().clone())
            .collect::<Vec<_>>();
        result.truncate(usize::try_from(*size).unwrap());
        result
    }
}
