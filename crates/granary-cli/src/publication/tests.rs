// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;
use crate::{admission::process_credentials, publication_report::hex};
use granary_client::{
    PublishRequest, PublishResponse, validate_publish_answer, validate_status_observation,
};
use granary_core::{
    authlog::Epoch,
    authority_answer::{self, Position, PublishAnswer, Receipt, VolumeStatus},
    retained_submission::{
        Candidate, Evidence, FrozenIntent, Phase, Probe, ProbeReason, RequestIdentity, Role,
    },
    root::{self, RootDoc, RootSig, Timestamp},
    rootstore::{HintRead, HintToken, RootStoreError},
};
use granary_store::backend::GranaryStore;
use object_store::memory::InMemory;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[expect(
    clippy::disallowed_methods,
    reason = "create a test-owned source directory below the private fixture root"
)]
fn mkdir(path: &Path) {
    std::fs::create_dir(path).unwrap();
}
#[expect(
    clippy::disallowed_methods,
    reason = "write generated test material in the private fixture root"
)]
fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
}
#[expect(
    clippy::disallowed_methods,
    reason = "open generated test material to capture its descriptor identity"
)]
fn identity(path: &Path) -> FileIdentity {
    FileIdentity::from_file(&std::fs::File::open(path).unwrap()).unwrap()
}
#[expect(
    clippy::disallowed_methods,
    reason = "plant a protected-inode alias in the test-owned source"
)]
fn link(from: &Path, to: &Path) {
    std::fs::hard_link(from, to).unwrap();
}
#[expect(
    clippy::disallowed_methods,
    reason = "plant a source/key-directory symlink alias under the private fixture root"
)]
fn alias(from: &Path, to: &Path) {
    std::os::unix::fs::symlink(from, to).unwrap();
}
#[expect(
    clippy::disallowed_methods,
    reason = "remove a test-owned source to prove retained recovery is source independent"
)]
fn remove(path: &Path) {
    std::fs::remove_dir_all(path).unwrap();
}
#[expect(
    clippy::disallowed_methods,
    reason = "replace generated test material by rename to exercise configured-location protection"
)]
fn rename(from: &Path, to: &Path) {
    std::fs::rename(from, to).unwrap();
}

struct Scratch(PathBuf);
impl Scratch {
    #[expect(
        clippy::disallowed_methods,
        reason = "canonicalize the platform temp directory and create only this private test-owned fixture"
    )]
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut nonce = [0; 16];
        granary_core::secure_random::SecureRandom::fill(&mut OsSecureRandom::new(), &mut nonce)
            .unwrap();
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("publication-unit-{}", hex(&nonce)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

struct Peer {
    remote: GranaryStore<InMemory>,
    status: Mutex<VecDeque<StatusResponse>>,
    posts: AtomicUsize,
    operations: Mutex<Vec<Vec<u8>>>,
    puts: AtomicUsize,
    probes: AtomicUsize,
    hints: Mutex<Vec<u64>>,
    fail_hint: bool,
    lock_path: Option<PathBuf>,
}
impl Peer {
    fn new(statuses: Vec<StatusResponse>) -> Self {
        Self {
            remote: GranaryStore::new(InMemory::new()),
            status: Mutex::new(statuses.into()),
            posts: AtomicUsize::new(0),
            operations: Mutex::new(Vec::new()),
            puts: AtomicUsize::new(0),
            probes: AtomicUsize::new(0),
            hints: Mutex::new(Vec::new()),
            fail_hint: false,
            lock_path: None,
        }
    }
}
impl RootStore for Peer {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        if let Some(path) = &self.lock_path {
            let path = path.clone();
            assert!(
                std::thread::spawn(move || Store::open(&path).is_err())
                    .join()
                    .unwrap(),
                "the selected Store lock must remain held through direct commit"
            );
        }
        self.remote.put_root(volume, seq, bytes).await
    }
    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.remote.get_root(volume, seq).await
    }
    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        self.remote.read_hint(volume, cached).await
    }
    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        self.hints.lock().unwrap().push(seq);
        if self.fail_hint {
            Err(RootStoreError::Backend("TEST_SENTINEL".into()))
        } else {
            self.remote.write_hint(volume, seq).await
        }
    }
    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.remote.max_seq(volume).await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.remote.max_seq_above(volume, floor).await
    }
}
impl BinStore for Peer {
    async fn put_bin(&self, digest: &[u8; 32], bytes: Vec<u8>) -> Result<bool, RootStoreError> {
        self.remote.put_bin(digest, bytes).await
    }
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.remote.put_meta(volume, id, bytes).await
    }
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.remote.get_meta(volume, id).await
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.remote.get_bin_range(digest, offset, len).await
    }
}
impl AuthorityTransport for Peer {
    async fn status_once(&self, _: &str) -> Result<StatusResponse, AuthorityError> {
        Ok(self
            .status
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected status"))
    }
    async fn probe_root_once(
        &self,
        volume: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        self.remote.get_root(volume, seq).await
    }
    async fn publish_once(
        &self,
        request: &PublishRequest,
    ) -> Result<PublishResponse, AuthorityError> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        self.operations
            .lock()
            .unwrap()
            .push(request.operation().to_vec());
        if let Some(path) = &self.lock_path {
            assert!(
                Store::open(path).is_err(),
                "the original Store lock must remain held through POST"
            );
        }
        let candidate = request.candidate();
        self.remote
            .put_root(
                request.volume(),
                candidate.seq(),
                candidate.bytes().to_vec(),
            )
            .await
            .unwrap();
        let answer = PublishAnswer::Landed {
            receipt: Receipt {
                position: Position {
                    epoch: request.epoch(),
                    entry_seq: 77,
                },
                root_seq: candidate.seq(),
                stored_id: candidate.id(),
            },
            head: None,
        };
        validate_publish_answer(
            request,
            200,
            None,
            &authority_answer::encode(answer).unwrap(),
        )
    }
}
fn observed() -> StatusResponse {
    validate_status_observation(
        &authority_answer::encode_status(VolumeStatus {
            epoch: Epoch::from_bytes([1; 16]),
            head: None,
            open: None,
        })
        .unwrap(),
    )
    .unwrap()
}
fn args(dir: &Path) -> PublishArgs {
    let context = granary_client::publication_config::CredentialContext::new("writer").unwrap();
    PublishArgs {
        store_dir: dir.join("store"),
        source: dir.join("source"),
        volume: VolumeName::new("vol".into()).unwrap(),
        endpoint: "https://test.invalid".into(),
        bucket: None,
        key_seed: dir.join("seed"),
        tls_pins: Some(vec![[1; 32]]),
        direct_s3: false,
        cache_dir: None,
        wire: None,
        json: false,
        mode: PublishMode::Auto,
        selection: Selection::Ordinary,
        configuration: PublishConfiguration {
            certificate: Some(dir.join("test-cert")),
            key: Some(dir.join("test-key")),
            context: Some(context),
            ..PublishConfiguration::default()
        },
    }
}
fn setup() -> (Scratch, PublishArgs, Store, SigningKey, Vec<FileIdentity>) {
    let dir = Scratch::new();
    let args = args(&dir.0);
    mkdir(&args.source);
    write(&args.source.join("file"), b"test content");
    write(&args.key_seed, &[9; 32]);
    write(
        args.configuration.key.as_deref().unwrap(),
        b"generated key test material",
    );
    let protected = PublishConfiguration::protected_files(
        identity(&args.key_seed),
        Some(identity(args.configuration.key.as_deref().unwrap())),
    );
    let store = Store::open(&args.store_dir).unwrap();
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    (dir, args, store, key, protected)
}
async fn run(
    args: &PublishArgs,
    peer: &Peer,
    store: &mut Store,
    signer: &SigningKey,
    protected: &[FileIdentity],
    retained: Option<Submission>,
) -> InvocationReport {
    let mut report = InvocationReport::new(Some(args.volume.clone()));
    let mut cache = CacheOnDrop(None);
    server(
        args,
        process_credentials().euid,
        peer,
        store,
        signer,
        protected,
        scope(args).unwrap(),
        retained,
        None,
        &mut cache,
        &mut report,
    )
    .await;
    report
}
fn signed_root(key: &SigningKey, seq: u64, stamp: i64) -> Vec<u8> {
    let mut doc = RootDoc {
        volume: VolumeName::new("vol".into()).unwrap(),
        seq,
        parent: (seq > 1).then(|| GrainId::of(b"fixture parent")),
        writer_uuid: [3; 16],
        epoch: 2,
        timestamp: Timestamp {
            secs: stamp,
            nanos: 0,
        },
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(&1_i64.to_le_bytes()),
        binmap_index: GrainId::of(b"index"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: Vec::new(),
    };
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    root::encode_root(&doc).unwrap()
}
fn record(args: &PublishArgs, key: &SigningKey, phase: Option<Phase>) -> Submission {
    let root = signed_root(key, 1, 1);
    let request = RequestIdentity {
        epoch: [1; 16],
        operation: [2; 16],
    };
    let done = Completion {
        seq: 1,
        id: GrainId::of(&root),
        root: root.clone(),
        receipt: None,
    };
    Submission {
        generation: 1,
        publication_id: [7; 16],
        scope: scope(args).unwrap().unwrap(),
        volume: args.volume.clone(),
        frozen: FrozenIntent {
            writer_identity: [3; 16],
            min_prefix_bits: 0,
            initial_root: root.clone(),
        },
        current: if phase.is_none() { None } else { Some(request) },
        candidates: vec![Candidate {
            number: 1,
            role: Role::Active,
            request,
            seq: 1,
            id: GrainId::of(&root),
            root,
            evidence: Evidence {
                started: 1,
                ..Evidence::default()
            },
        }],
        phase: phase.unwrap_or(Phase::Complete(done)),
        last_response: None,
        unavailable_exemptions: 0,
    }
}
fn persist(store: &mut Store, r: &Submission) {
    store
        .publications(process_credentials().euid)
        .unwrap()
        .begin(r)
        .unwrap();
}

#[test]
fn mode_status_matrix_and_configured_pair_gate() {
    use granary_client::StatusServiceReason;
    for mode in [
        PublishMode::Auto,
        PublishMode::Authority,
        PublishMode::LegacyServer,
    ] {
        for (status, expected) in [
            (
                observed(),
                if mode == PublishMode::LegacyServer {
                    Preflight::Stop
                } else {
                    Preflight::Coordinator
                },
            ),
            (
                StatusResponse::Refused(StatusRefusal::UnknownVolume),
                match mode {
                    PublishMode::Auto => Preflight::Coordinator,
                    PublishMode::LegacyServer => Preflight::Seam,
                    PublishMode::Authority => Preflight::Stop,
                },
            ),
            (
                StatusResponse::Refused(StatusRefusal::UnknownTarget),
                if mode == PublishMode::LegacyServer {
                    Preflight::Seam
                } else {
                    Preflight::Stop
                },
            ),
            (
                StatusResponse::Refused(StatusRefusal::NoLog),
                Preflight::Stop,
            ),
            (
                StatusResponse::ServiceUnavailable(StatusServiceReason::Fenced),
                Preflight::Stop,
            ),
            (StatusResponse::Internal, Preflight::Stop),
        ] {
            assert_eq!(preflight(mode, &status), expected, "{mode:?} {status:?}");
        }
    }
    let mut a = args(Path::new("/nonexistent/unused"));
    a.configuration.certificate = None;
    a.configuration.key = None;
    assert!(write_admission(&a, true, false).is_err());
    assert!(write_admission(&a, false, false).is_ok());
    a.configuration.context = None;
    assert!(write_admission(&a, false, true).is_err());
}
#[tokio::test]
async fn served_publication_uses_coordinator_post_and_holds_store_lock() {
    let (_dir, a, mut store, key, protected) = setup();
    let mut peer = Peer::new(vec![observed(), observed()]);
    peer.lock_path = Some(a.store_dir.clone());
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_eq!(report.route, Some(Route::Authority));
    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
    assert_eq!(peer.puts.load(Ordering::SeqCst), 0);
    assert_eq!(*peer.hints.lock().unwrap(), vec![1]);
    assert_eq!(
        report
            .completion
            .unwrap()
            .receipt
            .unwrap()
            .position
            .entry_seq,
        77
    );
}
/// The one publish a `gran publish` run sends is named by `op.publish_bound`
/// under the session's id, with the identity the authority received. The wrong
/// implementations this catches: no emission, an identity other than the
/// wire's, and an emission outside the session's span.
#[tokio::test]
async fn served_publication_binds_the_wire_identity_under_the_session_id() {
    #[derive(Clone, Default)]
    struct Buffer(std::sync::Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_dir, a, mut store, key, protected) = setup();
    let peer = Peer::new(vec![observed(), observed()]);
    let out = Buffer::default();
    let (sink, mut worker) = crate::sink::sink_to_writer(out.clone());
    let guard = tracing::subscriber::set_default(granary_client::subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        sink,
    ));
    let session = crate::logging::session_span().expect("the test host has entropy");
    let entered = session.enter();
    granary_client::log_config(
        granary_client::LogFormat::Json,
        granary_client::LogDestination::Stderr,
    );
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    drop(entered);
    drop(guard);
    worker.close();
    let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    let events = |name: &str| -> Vec<&str> {
        text.lines()
            .filter(|l| l.contains(&format!("\"event\":\"{name}\"")))
            .collect()
    };
    let field = |line: &str, key: &str| -> Option<String> {
        line.split(key)
            .nth(1)
            .and_then(|rest| rest.split_once('"'))
            .map(|(value, _)| value.to_owned())
    };
    let wire: Vec<_> = peer
        .operations
        .lock()
        .unwrap()
        .iter()
        .map(|operation| hex(operation))
        .collect();
    let bound = events("op.publish_bound");
    assert_eq!(
        (
            report.outcome,
            wire.len(),
            bound
                .iter()
                .map(|l| field(l, "\"publish_operation\":\""))
                .collect::<Vec<_>>(),
        ),
        (
            Outcome::Landed,
            1,
            wire.iter().cloned().map(Some).collect::<Vec<_>>()
        ),
        "{text}"
    );
    let ids = |lines: &[&str]| -> Vec<Option<String>> {
        lines.iter().map(|l| field(l, "\"op\":\"")).collect()
    };
    let session_id = ids(&events("log.config"));
    assert!(
        matches!(session_id.as_slice(), [Some(id)] if id.starts_with("cor-")),
        "{text}"
    );
    assert_eq!(ids(&bound), session_id, "{text}");
    assert!(bound[0].contains("\"kind\":\"session\""), "{text}");
}
#[tokio::test]
async fn auto_seam_only_from_fresh_bootstrap_unknown_volume() {
    let (_dir, a, mut store, key, protected) = setup();
    let unknown = StatusResponse::Refused(StatusRefusal::UnknownVolume);
    let peer = Peer::new(vec![unknown, observed()]);
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.route, Some(Route::Authority));
    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
    assert_eq!(peer.puts.load(Ordering::SeqCst), 0);
    for resuming in [false, true] {
        for preflight_unknown in [false, true] {
            for status in [
                observed(),
                unknown,
                StatusResponse::Refused(StatusRefusal::UnknownTarget),
                StatusResponse::Internal,
            ] {
                assert_eq!(
                    bootstrap_seam(PublishMode::Auto, resuming, preflight_unknown, &status),
                    !resuming && preflight_unknown && status == unknown
                );
            }
        }
    }
    let (_dir, a, mut store, key, protected) = setup();
    let peer = Peer::new(vec![observed(), unknown]);
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::Refused);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    assert_eq!(peer.puts.load(Ordering::SeqCst), 0);
    assert!(report.publication_id.is_none());
    let (_dir, a, mut store, key, protected) = setup();
    let peer = Peer::new(vec![unknown, unknown]);
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_eq!(report.route, Some(Route::ServerSeam));
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    assert_eq!(peer.puts.load(Ordering::SeqCst), 1);
    assert!(report.json().contains("\"token\":\"unknown-volume\""));
    let mut out = Vec::new();
    assert_eq!(
        report.render(false, &mut out, &mut Vec::new()),
        std::process::ExitCode::from(report.outcome.code())
    );
    let human = String::from_utf8(out).unwrap();
    assert!(human.starts_with("published vol seq 1 epoch 1 route=server-seam\n"));
    assert!(human.contains("novel objects "));
    assert!(report.summary.is_some());
    let (_dir, mut a, mut store, key, protected) = setup();
    a.configuration.context = None;
    let peer = Peer::new(vec![observed(), unknown]);
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::Refused);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    assert_eq!(peer.puts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn direct_and_seam_keep_exclusive_store_lock_through_commit() {
    for seam_route in [false, true] {
        let (_dir, mut a, mut store, key, protected) = setup();
        let mut peer = Peer::new(vec![StatusResponse::Refused(StatusRefusal::UnknownTarget)]);
        peer.lock_path = Some(a.store_dir.clone());
        let report = if seam_route {
            a.mode = PublishMode::LegacyServer;
            run(&a, &peer, &mut store, &key, &protected, None).await
        } else {
            let mut report = InvocationReport::new(Some(a.volume.clone()));
            direct(
                &a,
                process_credentials().euid,
                &peer,
                &mut store,
                &key,
                &protected,
                &mut CacheOnDrop(None),
                &mut report,
            )
            .await;
            report
        };
        assert_eq!(report.outcome, Outcome::Landed);
        assert_eq!(peer.puts.load(Ordering::SeqCst), 1);
        assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bootstrap_seam_reuses_coordinator_cache() {
    let (_dir, mut a, mut store, key, protected) = setup();
    a.cache_dir = Some(a.store_dir.parent().unwrap().join("cache"));
    let unknown = StatusResponse::Refused(StatusRefusal::UnknownVolume);
    let peer = Peer::new(vec![unknown, unknown]);
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::Landed, "{:?}", report.diagnostic);
    assert_eq!(report.route, Some(Route::ServerSeam));
    assert_eq!(report.cache.result, "written");
    assert_eq!(peer.puts.load(Ordering::SeqCst), 1);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
}

#[test]
fn refused_fresh_paths_and_swapped_operands_create_no_files() {
    for case in [
        "swapped",
        "store-in-source",
        "seed-in-store",
        "seed-in-source",
        "cache-in-source",
    ] {
        let (_dir, mut a, store, _, _) = setup();
        drop(store);
        match case {
            "swapped" => std::mem::swap(&mut a.store_dir, &mut a.source),
            "store-in-source" => a.store_dir = a.source.join("new-store"),
            "seed-in-store" => {
                a.store_dir = a.store_dir.with_file_name("new-store");
                a.key_seed = a.store_dir.join("txn/seed");
            }
            "seed-in-source" => {
                a.store_dir = a.store_dir.with_file_name("new-store");
                a.key_seed = a.source.join("seed");
            }
            "cache-in-source" => {
                a.store_dir = a.store_dir.with_file_name("new-store");
                a.cache_dir = Some(a.source.join("new-cache"));
            }
            _ => unreachable!(),
        }
        let before = if case == "swapped" {
            Some(directory_entries(&a.store_dir))
        } else {
            None
        };
        let report = invoke(&a, &process_credentials());
        assert_eq!(report.outcome, Outcome::LocalError, "{case}");
        if let Some(before) = before {
            assert_eq!(directory_entries(&a.store_dir), before, "{case}");
            assert!(report.diagnostic.unwrap().contains("argument order"));
        } else {
            assert!(
                std::fs::symlink_metadata(&a.store_dir).is_err(),
                "{case}: refused invocation created a store"
            );
        }
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "list only this test's source to detect scaffolding from a refused invocation"
)]
fn directory_entries(path: &Path) -> Vec<std::ffi::OsString> {
    let mut names: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    names
}

#[test]
fn tls_key_in_store_or_cache_refuses_before_sweep_even_on_resume() {
    for cache_root in [false, true] {
        for aliased in [false, true] {
            let (dir, mut a, mut store, key, _) = setup();
            persist(&mut store, &record(&a, &key, Some(Phase::Ready)));
            drop(store);
            remove(&a.source);
            let root = if cache_root {
                let path = dir.0.join("cache");
                mkdir(&path);
                mkdir(&path.join("txn"));
                a.cache_dir = Some(path.clone());
                path
            } else {
                a.store_dir.clone()
            };
            let tls = root.join("txn/test-key");
            write(&tls, b"GENERATED_TLS_SENTINEL");
            a.configuration.key = Some(if aliased {
                let path = dir.0.join("managed-alias");
                alias(&root, &path);
                path.join("txn/test-key")
            } else {
                tls.clone()
            });
            let report = invoke(&a, &process_credentials());
            assert_eq!(report.outcome, Outcome::LocalError);
            let diagnostic = report.diagnostic.unwrap();
            assert!(diagnostic.contains("client TLS key"), "{diagnostic}");
            assert!(diagnostic.contains(&root.display().to_string()));
            assert_eq!(read_fixture(&tls), b"GENERATED_TLS_SENTINEL");
        }
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "read only a generated sentinel to check the refused invocation did not sweep it"
)]
fn read_fixture(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "make only a test-owned seed parent unsafe to exercise the custody diagnostic and remedy"
)]
fn local_diagnostics_preserve_seed_remedy_store_error_and_colliding_roots() {
    let (_dir, mut a, mut store, key, _) = setup();
    persist(&mut store, &record(&a, &key, Some(Phase::Ready)));
    drop(store);
    let unsafe_parent = a.key_seed.with_file_name("unsafe-seed-parent");
    mkdir(&unsafe_parent);
    std::fs::set_permissions(
        &unsafe_parent,
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    )
    .unwrap();
    a.key_seed = unsafe_parent.join("seed");
    a.configuration.certificate = None;
    a.configuration.key = None;
    let diagnostic = invoke(&a, &process_credentials()).diagnostic.unwrap();
    assert!(diagnostic.contains("unsafe seed ancestor"), "{diagnostic}");
    assert!(diagnostic.contains("Run: chmod g-w"));
    assert!(diagnostic.contains(&unsafe_parent.display().to_string()));
    a.key_seed = unsafe_parent.with_file_name("unused-seed");
    let held = Store::open(&a.store_dir).unwrap();
    let diagnostic = invoke(&a, &process_credentials()).diagnostic.unwrap();
    assert!(diagnostic.contains("locked"), "{diagnostic}");
    drop(held);
    a.key_seed = a.store_dir.join("txn/seed");
    let diagnostic = invoke(&a, &process_credentials()).diagnostic.unwrap();
    assert!(diagnostic.contains(&a.key_seed.display().to_string()));
    assert!(diagnostic.contains(&a.store_dir.display().to_string()));
    a.key_seed = unsafe_parent.with_file_name("unused-seed");
    a.cache_dir = Some(a.store_dir.join("cache"));
    let diagnostic = invoke(&a, &process_credentials()).diagnostic.unwrap();
    assert!(diagnostic.contains(&a.cache_dir.as_ref().unwrap().display().to_string()));
    assert!(diagnostic.contains(&a.store_dir.display().to_string()));
    a.cache_dir = None;
    a.store_dir = a.source.join("store");
    let diagnostic = invoke(&a, &process_credentials()).diagnostic.unwrap();
    assert!(diagnostic.contains("must not nest"), "{diagnostic}");
    assert!(diagnostic.contains(&a.store_dir.display().to_string()));
    assert!(diagnostic.contains(&a.source.display().to_string()));
}

#[test]
fn route_diagnostics_name_missing_aws_configuration_without_values() {
    for (provided, missing) in [
        ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        ("AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"),
    ] {
        let error = open_publish_route_with_client_credential(
            "https://test.invalid",
            None,
            true,
            Some("test-bucket"),
            None,
            &|name| (name == provided).then(|| "GENERATED_SENTINEL".into()),
        )
        .unwrap_err();
        let diagnostic = route_diagnostic(&error);
        assert!(diagnostic.contains(missing), "{error}: {diagnostic}");
        assert!(!diagnostic.contains("GENERATED_SENTINEL"));
    }
    let error = open_publish_route_with_client_credential(
        "https://userinfo:PRIVATE_SENTINEL@test.invalid",
        Some(vec![[1; 32]]),
        false,
        None,
        None,
        &|_| panic!("server route must not read environment"),
    )
    .unwrap_err();
    let diagnostic = route_diagnostic(&error);
    assert!(diagnostic.contains("userinfo"));
    assert!(!diagnostic.contains("PRIVATE_SENTINEL"));
    assert!(
        !route_diagnostic(&RouteError::Store("PRIVATE_SENTINEL".into()))
            .contains("PRIVATE_SENTINEL")
    );
}

#[test]
fn local_marker_diagnostics_never_echo_private_contents_or_url_userinfo() {
    let (dir, mut a, store, key, _) = setup();
    drop(store);
    rename(
        &a.store_dir.join(granary_client::MARKER_NAME),
        &dir.0.join("saved-store-marker"),
    );
    write(&a.store_dir.join(granary_client::MARKER_NAME),
        b"granary-store-version 1\n-----BEGIN PRIVATE KEY-----\nPRIVATE_SENTINEL\nhttps://user:PRIVATE_SENTINEL@test.invalid\n");
    let diagnostic = invoke(&a, &process_credentials()).diagnostic.unwrap();
    assert!(diagnostic.contains("incompatible store"), "{diagnostic}");
    assert!(!diagnostic.contains("PRIVATE_SENTINEL"));
    assert!(!diagnostic.contains("BEGIN PRIVATE KEY"));
    a.cache_dir = Some(a.store_dir.with_file_name("cache"));
    let mut cache = CacheOnDrop(None);
    let mut report = InvocationReport::new(Some(a.volume.clone()));
    open_cache(&a, &key, &mut cache, &mut report).unwrap();
    drop(cache);
    rename(
        &a.cache_dir.as_ref().unwrap().join("granary-cache"),
        &dir.0.join("saved-cache-marker"),
    );
    write(&a.cache_dir.as_ref().unwrap().join("granary-cache"),
        b"-----BEGIN PRIVATE KEY-----\nPRIVATE_SENTINEL\nhttps://user:PRIVATE_SENTINEL@test.invalid\n");
    assert!(open_cache(&a, &key, &mut CacheOnDrop(None), &mut report).is_err());
    let diagnostic = report.diagnostic.unwrap();
    assert!(diagnostic.contains("incompatible cache"));
    assert!(!diagnostic.contains("PRIVATE_SENTINEL"));
    assert!(!diagnostic.contains("BEGIN PRIVATE KEY"));
}
#[tokio::test]
async fn fresh_stop_has_no_record_and_pending_remedy_is_rerun() {
    let (_dir, a, mut store, key, protected) = setup();
    for status in [
        StatusResponse::ServiceUnavailable(granary_client::StatusServiceReason::Stopped),
        StatusResponse::Refused(StatusRefusal::NoLog),
        StatusResponse::Internal,
    ] {
        let peer = Peer::new(vec![status]);
        let report = run(&a, &peer, &mut store, &key, &protected, None).await;
        assert!(report.publication_id.is_none());
        assert_eq!(report.retention, Retention::None);
        let mut err = Vec::new();
        assert_eq!(
            report.render(false, &mut Vec::new(), &mut err),
            std::process::ExitCode::from(report.outcome.code())
        );
        let err = String::from_utf8(err).unwrap();
        assert!(!err.contains("submission retained"));
        if matches!(status, StatusResponse::ServiceUnavailable(_)) {
            assert!(err.contains("re-run the invocation"));
            assert!(!err.contains("--recover"));
        }
        assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
        assert_eq!(peer.puts.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn selection_precedes_source_and_continue_differs_from_explicit_recovery() {
    let (_dir, mut a, mut store, key, protected) = setup();
    let probe = Probe {
        cycle: 1,
        seq: 1,
        reason: ProbeReason::Interrupted,
    };
    let r = record(&a, &key, Some(Phase::Unresolved(probe)));
    persist(&mut store, &r);
    remove(&a.source);
    let mut report = InvocationReport::new(Some(a.volume.clone()));
    let selected = select(
        &a,
        &mut store,
        process_credentials().euid,
        scope(&a).unwrap().as_ref(),
        &mut report,
    )
    .unwrap();
    assert!(selected.is_some());
    let peer = Peer::new(vec![]);
    let report = run(&a, &peer, &mut store, &key, &protected, selected.clone()).await;
    assert_eq!(report.outcome, Outcome::Unresolved);
    assert_eq!(peer.probes.load(Ordering::SeqCst), 0);
    assert!(peer.hints.lock().unwrap().is_empty());
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    peer.remote
        .put_root("vol", 1, r.frozen.initial_root.clone())
        .await
        .unwrap();
    a.selection = Selection::Recover(r.publication_id);
    let report = run(&a, &peer, &mut store, &key, &protected, selected).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert!(peer.probes.load(Ordering::SeqCst) > 0);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    a.selection = Selection::Recover([8; 16]);
    assert!(
        select(
            &a,
            &mut store,
            process_credentials().euid,
            scope(&a).unwrap().as_ref(),
            &mut InvocationReport::new(Some(a.volume.clone()))
        )
        .is_err()
    );
}
#[test]
fn new_refuses_incomplete_and_all_direct_routes_guard_foreign_state() {
    let (_dir, mut a, mut store, key, _) = setup();
    let r = record(&a, &key, Some(Phase::Ready));
    persist(&mut store, &r);
    a.selection = Selection::New;
    let mut report = InvocationReport::new(Some(a.volume.clone()));
    assert!(
        select(
            &a,
            &mut store,
            process_credentials().euid,
            scope(&a).unwrap().as_ref(),
            &mut report
        )
        .is_err()
    );
    assert_eq!(report.publication_id, Some(r.publication_id));
    assert_eq!(report.retention, Retention::Live);
    a.configuration.context = None;
    a.direct_s3 = true;
    assert!(
        select(
            &a,
            &mut store,
            process_credentials().euid,
            None,
            &mut report
        )
        .is_err()
    );
    assert_eq!(
        store
            .publications(process_credentials().euid)
            .unwrap()
            .load(&r.scope, &r.volume)
            .unwrap()
            .unwrap()
            .candidates,
        r.candidates
    );
}
#[tokio::test]
async fn archive_refusal_and_explicit_new_adapter_reaches_begin() {
    let (_dir, mut a, mut store, key, protected) = setup();
    let r = record(&a, &key, Some(Phase::Ready));
    persist(&mut store, &r);
    store
        .publications(process_credentials().euid)
        .unwrap()
        .abandon(
            &r.scope,
            &r.volume,
            r.publication_id,
            MayLandAcknowledgement::Acknowledged,
        )
        .unwrap();
    let mut report = InvocationReport::new(Some(a.volume.clone()));
    assert!(
        select(
            &a,
            &mut store,
            process_credentials().euid,
            Some(&r.scope),
            &mut report
        )
        .is_err()
    );
    assert_eq!(report.outcome, Outcome::Refused);
    assert_eq!(report.outcome.code(), 4);
    assert_eq!(report.retention, Retention::Archive);
    assert!(
        report
            .next_action
            .as_ref()
            .unwrap()
            .action
            .contains("--new")
    );
    a.selection = Selection::New;
    assert!(
        select(
            &a,
            &mut store,
            process_credentials().euid,
            Some(&r.scope),
            &mut report
        )
        .unwrap()
        .is_none()
    );
    let peer = Peer::new(vec![observed(), observed()]);
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_ne!(report.publication_id, Some(r.publication_id));
    assert_eq!(
        store
            .publications(process_credentials().euid)
            .unwrap()
            .list_archives(&a.volume)
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn explicit_trust_reaches_coordinator_and_refuses_every_seam() {
    let (_dir, mut a, mut store, key, protected) = setup();
    let old = SigningKey::from_seed(&[8; 32]).unwrap();
    for key in [&key, &old] {
        a.configuration
            .publishers
            .push(&format!("ed25519:{}", hex(key.public_key())))
            .unwrap();
    }
    let r = record(&a, &old, None);
    persist(&mut store, &r);
    let peer = Peer::new(vec![]);
    let report = run(&a, &peer, &mut store, &key, &protected, Some(r.clone())).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_eq!(*peer.hints.lock().unwrap(), vec![1]);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    let (_dir, mut a, mut store, key, protected) = setup();
    a.configuration
        .publishers
        .push(&format!("ed25519:{}", hex(key.public_key())))
        .unwrap();
    for mode in [PublishMode::Auto, PublishMode::LegacyServer] {
        a.mode = mode;
        let peer = Peer::new(vec![
            StatusResponse::Refused(StatusRefusal::UnknownVolume),
            StatusResponse::Refused(StatusRefusal::UnknownVolume),
        ]);
        let report = run(&a, &peer, &mut store, &key, &protected, None).await;
        assert_eq!(report.outcome, Outcome::LocalError);
        assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
        assert_eq!(peer.puts.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn both_protected_identities_reach_authority_and_direct_harvest() {
    for which in [0, 1] {
        for authority in [true, false] {
            let (_dir, mut a, mut store, key, protected) = setup();
            link(
                if which == 0 {
                    &a.key_seed
                } else {
                    a.configuration.key.as_deref().unwrap()
                },
                &a.source.join("ordinary.bin"),
            );
            let peer = Peer::new(vec![observed(), observed()]);
            let report = if authority {
                run(&a, &peer, &mut store, &key, &protected, None).await
            } else {
                a.configuration.key = None;
                a.configuration.certificate = None;
                let mut report = InvocationReport::new(Some(a.volume.clone()));
                let mut cache = CacheOnDrop(None);
                direct(
                    &a,
                    process_credentials().euid,
                    &peer,
                    &mut store,
                    &key,
                    &protected,
                    &mut cache,
                    &mut report,
                )
                .await;
                report
            };
            assert_eq!(
                report.outcome,
                Outcome::LocalError,
                "identity={which} authority={authority}"
            );
            let diagnostic = report.diagnostic.unwrap();
            assert!(
                diagnostic.contains("protected private key material"),
                "{diagnostic}"
            );
            assert!(diagnostic.contains(&a.source.join("ordinary.bin").display().to_string()));
            assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
            assert_eq!(peer.puts.load(Ordering::SeqCst), 0);
        }
    }
}
#[test]
fn configured_tls_directory_and_symlink_alias_refuse_rename_replacement() {
    let (dir, mut a, _store, _key, _protected) = setup();
    let nested = a.source.join("private");
    mkdir(&nested);
    let key = nested.join("key");
    write(&key, b"generated test key");
    let replacement = dir.0.join("replacement");
    write(&replacement, b"generated replacement");
    rename(&replacement, &key);
    a.configuration.key = Some(key.clone());
    assert!(fresh_source_checks(&a).is_err());
    let aliased = dir.0.join("alias");
    alias(&nested, &aliased);
    a.configuration.key = Some(aliased.join("key"));
    assert!(fresh_source_checks(&a).is_err());
    let source_alias = dir.0.join("source-alias");
    alias(&a.source, &source_alias);
    a.source = source_alias;
    assert!(fresh_source_checks(&a).is_err());
    a.configuration.key = Some(dir.0.join("test-key"));
    assert!(fresh_source_checks(&a).is_ok());
}
#[tokio::test]
async fn completion_winner_drives_cache_anchor_hint_and_redisplay_without_post() {
    let (_dir, mut a, mut store, key, protected) = setup();
    a.cache_dir = Some(a.store_dir.parent().unwrap().join("cache"));
    let mut r = record(&a, &key, None);
    r.frozen.initial_root = signed_root(&key, 1, 0);
    let winner = signed_root(&key, 4, 1);
    let loser = signed_root(&key, 8, 2);
    assert_ne!(winner, loser);
    assert_ne!(GrainId::of(&winner), GrainId::of(&loser));
    r.candidates.first_mut().unwrap().role = Role::Retired;
    r.candidates.first_mut().unwrap().seq = 4;
    r.candidates.first_mut().unwrap().root.clone_from(&winner);
    r.candidates.first_mut().unwrap().id = GrainId::of(&winner);
    r.candidates.push(Candidate {
        number: 2,
        role: Role::Active,
        request: RequestIdentity {
            epoch: [2; 16],
            operation: [3; 16],
        },
        seq: 8,
        id: GrainId::of(&loser),
        root: loser,
        evidence: Evidence {
            started: 1,
            ..Evidence::default()
        },
    });
    r.phase = Phase::Complete(Completion {
        seq: 4,
        id: GrainId::of(&winner),
        root: winner.clone(),
        receipt: None,
    });
    persist(&mut store, &r);
    let mut initial_cache = Cache::open(
        a.cache_dir.as_ref().unwrap(),
        DEFAULT_CACHE_QUOTA_BYTES,
        &cache_origin(&a.endpoint, &[[1; 32]], Some(key.public_key())),
    )
    .unwrap();
    initial_cache.raise_anchor(&a.volume, Some(2), HintUpdate::Unchanged);
    initial_cache.close().unwrap();
    let peer = Peer::new(vec![]);
    for _ in 0..2 {
        let selected = select(
            &a,
            &mut store,
            process_credentials().euid,
            Some(&r.scope),
            &mut InvocationReport::new(Some(a.volume.clone())),
        )
        .unwrap();
        let report = run(&a, &peer, &mut store, &key, &protected, selected).await;
        assert_eq!(report.outcome, Outcome::Landed);
        assert_eq!(report.completion.as_ref().unwrap().seq, 4);
        assert_eq!(report.completion.unwrap().id, GrainId::of(&winner));
    }
    let cache = Cache::open(
        a.cache_dir.as_ref().unwrap(),
        DEFAULT_CACHE_QUOTA_BYTES,
        &cache_origin(&a.endpoint, &[[1; 32]], Some(key.public_key())),
    )
    .unwrap();
    assert_eq!(cache.get_root_bytes(&a.volume, 4).unwrap(), winner);
    assert_eq!(cache.read_anchor(&a.volume).unwrap().seq, 4);
    cache.close().unwrap();
    assert_eq!(*peer.hints.lock().unwrap(), vec![4, 4]);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    assert_eq!(peer.probes.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn excluded_old_winner_skips_cache_and_keeps_higher_floor_but_repairs_hint() {
    let (dir, mut a, mut store, key, protected) = setup();
    a.cache_dir = Some(dir.0.join("cache"));
    let old = SigningKey::from_seed(&[8; 32]).unwrap();
    for k in [&key, &old] {
        a.configuration
            .publishers
            .push(&format!("ed25519:{}", hex(k.public_key())))
            .unwrap();
    }
    let r = record(&a, &old, None);
    persist(&mut store, &r);
    let mut cache = Cache::open(
        a.cache_dir.as_ref().unwrap(),
        DEFAULT_CACHE_QUOTA_BYTES,
        &cache_origin(&a.endpoint, &[[1; 32]], Some(key.public_key())),
    )
    .unwrap();
    cache.raise_anchor(&a.volume, Some(99), HintUpdate::Unchanged);
    cache.close().unwrap();
    let mut peer = Peer::new(vec![]);
    peer.fail_hint = true;
    let report = run(&a, &peer, &mut store, &key, &protected, Some(r)).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_eq!(report.cache.result, "skipped");
    assert_eq!(report.hint.result, "failed");
    assert_eq!(*peer.hints.lock().unwrap(), vec![1]);
    assert!(!report.json().contains("TEST_SENTINEL"));
    let cache = Cache::open(
        a.cache_dir.as_ref().unwrap(),
        DEFAULT_CACHE_QUOTA_BYTES,
        &cache_origin(&a.endpoint, &[[1; 32]], Some(key.public_key())),
    )
    .unwrap();
    assert!(cache.get_root_bytes(&a.volume, 1).is_none());
    assert_eq!(cache.read_anchor(&a.volume).unwrap().seq, 99);
    cache.close().unwrap();
}
#[test]
fn local_abandon_survives_pin_change_without_loading_credentials_or_source() {
    let (_dir, mut a, mut store, key, _) = setup();
    let r = record(&a, &key, Some(Phase::Ready));
    persist(&mut store, &r);
    drop(store);
    a.tls_pins = Some(vec![[2; 32]]);
    a.selection = Selection::Abandon(r.publication_id);
    a.key_seed = PathBuf::from("/no-signing-key");
    a.configuration.key = Some(PathBuf::from("/no-client-key"));
    a.configuration.certificate = Some(PathBuf::from("/no-certificate"));
    a.source = PathBuf::from("/no-source");
    let report = invoke(&a, &process_credentials());
    assert_eq!(report.outcome, Outcome::Abandoned);
    assert!(report.pin_difference.is_some());
    let mut store = Store::open(&a.store_dir).unwrap();
    let archives = store
        .publications(process_credentials().euid)
        .unwrap()
        .list_archives(&a.volume)
        .unwrap();
    assert_eq!(
        archives.first().unwrap().submission.candidates,
        r.candidates
    );
    let mut out = Vec::new();
    assert_eq!(
        report.render(false, &mut out, &mut Vec::new()),
        std::process::ExitCode::from(report.outcome.code())
    );
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("wedged volume remains unavailable"));
    assert!(text.contains("all candidates retained"));
}

#[test]
fn parser_ids_modes_acknowledgement_and_json_option_position() {
    use std::ffi::OsString;
    assert_eq!(
        parse_id("00000000000000000000000000000000").unwrap(),
        [0; 16]
    );
    for invalid in [
        "",
        "00",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "gggggggggggggggggggggggggggggggg",
    ] {
        assert!(parse_id(invalid).is_err());
    }
    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    let base = [
        "store",
        "-",
        "vol",
        "--endpoint",
        "https://test.invalid",
        "--pin",
        &pin,
        "--key-seed",
        "seed",
        "--credential-context",
        "writer",
    ];
    for (extra, want_json) in [
        (vec!["--json", "--unregistered"], true),
        (vec!["--unregistered", "--json"], true),
        (vec!["--client-key", "--json"], false),
        (vec!["--endpoint", "--json"], false),
        (
            vec!["--abandon", "07070707070707070707070707070707", "--json"],
            true,
        ),
        (vec!["--acknowledge-may-land", "--json"], true),
        (
            vec![
                "--new",
                "--recover",
                "07070707070707070707070707070707",
                "--json",
            ],
            true,
        ),
    ] {
        let input: Vec<OsString> = base
            .iter()
            .copied()
            .chain(extra)
            .map(OsString::from)
            .collect();
        let mut json = false;
        let result = crate::parse_publish_checked(
            &input,
            &|_| None,
            &mut PublishConfiguration::default(),
            &mut json,
        );
        if let Ok(parsed) = result {
            assert_eq!(parsed.endpoint, "--json");
        }
        assert_eq!(json, want_json);
    }
    let input: Vec<OsString> = base
        .iter()
        .copied()
        .chain([
            "--abandon",
            "07070707070707070707070707070707",
            "--acknowledge-may-land",
        ])
        .map(OsString::from)
        .collect();
    assert!(crate::tests::parse_publish(&input, &|_| None).is_ok());
    for extra in [
        vec!["--abandon", "07070707070707070707070707070707"],
        vec!["--acknowledge-may-land"],
        vec!["--new", "--recover", "07070707070707070707070707070707"],
    ] {
        let input: Vec<OsString> = base
            .iter()
            .copied()
            .chain(extra)
            .map(OsString::from)
            .collect();
        assert!(crate::tests::parse_publish(&input, &|_| None).is_err());
    }
}
#[test]
fn capacity_and_open_pending_preserve_diagnostics_uncertainty_and_abandon_remedy() {
    for (outcome, code, diagnostic) in [
        (
            PublicationOutcome::Exhausted,
            5,
            "candidate capacity exhausted",
        ),
        (
            PublicationOutcome::Unresolved,
            5,
            "candidate capacity exhausted",
        ),
        (
            PublicationOutcome::Pending,
            3,
            "open entry under foreign occupancy: possible wedge, repaired out of band",
        ),
    ] {
        let handle = PublicationHandle {
            scope: Scope {
                authority_base: b"https://test.invalid".to_vec(),
                pins: vec![[1; 32]],
                credential_context: b"writer".to_vec(),
            },
            volume: VolumeName::new("vol".into()).unwrap(),
            publication_id: [7; 16],
        };
        let mut report = InvocationReport::new(Some(handle.volume.clone()));
        apply_result(
            &mut report,
            PublicationResult::new(
                handle.clone(),
                outcome.clone(),
                None,
                true,
                Some(diagnostic.into()),
            ),
        );
        assert_eq!(report.outcome.code(), code);
        assert!(report.uncertain);
        assert_eq!(report.diagnostic.as_deref(), Some(diagnostic));
        let mut err = Vec::new();
        assert_eq!(
            report.render(false, &mut Vec::new(), &mut err),
            std::process::ExitCode::from(report.outcome.code())
        );
        let text = String::from_utf8(err).unwrap();
        assert!(text.contains(diagnostic));
        assert!(text.contains("--abandon 07070707070707070707070707070707 --acknowledge-may-land"));
        assert!(text.contains("--recover 07070707070707070707070707070707"));
        let mut untrusted = InvocationReport::new(Some(handle.volume.clone()));
        apply_result(
            &mut untrusted,
            PublicationResult::new(
                handle,
                outcome,
                None,
                true,
                Some(format!("{diagnostic}; TEST_SENTINEL")),
            ),
        );
        assert_eq!(untrusted.outcome.code(), code);
        assert_eq!(
            untrusted.diagnostic.as_deref(),
            Some(
                "publication work stopped; inspect checked response and explicitly recover retained content"
            )
        );
        assert!(!untrusted.json().contains("TEST_SENTINEL"));
    }
}
#[test]
fn direct_error_categories_use_typed_variants() {
    for (error, expected, uncertain) in [
        (
            PublishError::LostRace {
                volume: "vol".into(),
                attempted: 1,
                head: 1,
            },
            Outcome::Refused,
            false,
        ),
        (
            PublishError::Unresolved {
                put_error: RootStoreError::Backend("test lost reply".into()),
            },
            Outcome::Unresolved,
            true,
        ),
        (
            PublishError::Remote(RootStoreError::Backend("TEST_SENTINEL".into())),
            Outcome::BackendError,
            false,
        ),
    ] {
        let mut report = InvocationReport::new(None);
        direct_error(&mut report, &error, true);
        assert_eq!(report.outcome, expected);
        assert_eq!(report.uncertain, uncertain);
        assert!(!report.json().contains("TEST_SENTINEL"));
    }
}

/// A failed remote store call is a backend error (exit 6), the same class as
/// a failed remote call during recovery, and names the call and its status.
#[test]
fn a_failed_remote_call_is_a_backend_error_naming_the_call() {
    let mut report = InvocationReport::new(None);
    direct_error(
        &mut report,
        &PublishError::Remote(RootStoreError::UnexpectedStatus {
            operation: "PUT bin",
            status: 500,
            token: Some("no-principal".into()),
        }),
        false,
    );
    assert_eq!(report.outcome, Outcome::BackendError);
    assert_eq!(report.outcome.code(), 6);
    let text = report.diagnostic.clone().unwrap();
    assert!(
        text.contains("publication failed at a remote store call (PUT bin: status 500)"),
        "{text}"
    );
    assert!(!text.contains("no-principal"), "{text}");
    assert!(report.json().contains(r#""outcome":"backend-error""#));
    assert!(report.json().contains(r#""exit_code":6"#));
}

/// Every `PublishError` variant the router once folded into one generic
/// sentence names its own cause and carries the outcome of its class.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table naming every variant is the point of the row"
)]
fn every_publish_error_variant_has_its_own_classified_text() {
    use granary_core::encoding::DecodeError;
    let id = GrainId::of(b"x");
    for (error, outcome, wanted) in [
        (
            PublishError::Decode {
                what: "head root",
                source: DecodeError::Truncated,
            },
            Outcome::BackendError,
            "head root failed to decode",
        ),
        (
            PublishError::MissingRoot { seq: 3 },
            Outcome::BackendError,
            "a listed root is missing",
        ),
        (
            PublishError::MissingMeta {
                what: "sheaf",
                id,
                volume: "vol".into(),
                seq: 3,
            },
            Outcome::BackendError,
            "a metadata object is missing",
        ),
        (
            PublishError::VolumeMismatch {
                want: "vol".into(),
                got: "other".into(),
            },
            Outcome::BackendError,
            "the head root names another volume",
        ),
        (
            PublishError::SeqMismatch {
                key_seq: 1,
                doc_seq: 2,
            },
            Outcome::BackendError,
            "a root's seq differs from its key",
        ),
        (
            PublishError::UnknownSigner { seq: 1 },
            Outcome::BackendError,
            "carries no signature by this key",
        ),
        (
            PublishError::BadSignature { seq: 1 },
            Outcome::BackendError,
            "a root signature failed verification",
        ),
        (
            PublishError::CorruptMeta { id },
            Outcome::BackendError,
            "does not hash to its id",
        ),
        (
            PublishError::NotAManifestNode { id },
            Outcome::BackendError,
            "is not a manifest node",
        ),
        (
            PublishError::LostRace {
                volume: "vol".into(),
                attempted: 2,
                head: 1,
            },
            Outcome::Refused,
            "publication lost the race",
        ),
        (
            PublishError::Unresolved {
                put_error: RootStoreError::Precondition,
            },
            Outcome::Unresolved,
            "the put failed (precondition) and the settling probe found nothing",
        ),
        (
            PublishError::ProbeUnresolved {
                put_error: RootStoreError::Precondition,
                probe_error: RootStoreError::NotFound,
            },
            Outcome::Unresolved,
            "the put failed (precondition) and the settling probe failed (not-found)",
        ),
    ] {
        let mut report = InvocationReport::new(None);
        direct_error(&mut report, &error, false);
        let text = report.diagnostic.clone().unwrap();
        assert_eq!(report.outcome, outcome, "{error:?}: {text}");
        assert!(
            text.contains(wanted),
            "{error:?}: wanted {wanted:?}: {text}"
        );
        assert!(
            !text.contains("direct publication") && !text.contains("failed; inspect verified"),
            "{text}"
        );
        assert!(!text.contains("vol\""), "no volume name echoed: {text}");
    }
}

/// A diagnostic names its step and kind, never the raw backend text (an
/// endpoint, a key, server bytes), and stays bounded.
#[test]
fn publication_failures_name_their_cause_without_peer_text() {
    const LEAK: &str = "http://user:LEAK_SENTINEL@minio.invalid:9000/bucket/key";
    let diagnostic = |error: &RecoveryError| {
        let mut report = InvocationReport::new(None);
        recovery_error(&mut report, error);
        let text = report.diagnostic.clone().unwrap();
        assert!(!report.json().contains("LEAK_SENTINEL"), "{text}");
        assert!(text.len() < 220, "{text}");
        (report.outcome, text)
    };
    let direct = |error: PublishError| diagnostic(&RecoveryError::Preparation(error));
    for (error, outcome, wanted) in [
        (
            PublishError::Remote(RootStoreError::Backend(LEAK.into())),
            Outcome::BackendError,
            "remote store call (backend error)",
        ),
        (
            PublishError::Remote(RootStoreError::Unavailable {
                operation: "PUT bin",
                status: 503,
            }),
            Outcome::BackendError,
            "remote store call (PUT bin: status 503)",
        ),
        (
            PublishError::Remote(RootStoreError::UnexpectedStatus {
                operation: "GET root",
                status: 500,
                token: None,
            }),
            Outcome::BackendError,
            "remote store call (GET root: status 500)",
        ),
        (
            PublishError::Remote(RootStoreError::Elapsed {
                operation: "PUT meta",
                after: std::time::Duration::from_mins(1),
            }),
            Outcome::BackendError,
            "remote store call (PUT meta: no answer within 60s)",
        ),
        (
            PublishError::Remote(RootStoreError::NotFound),
            Outcome::BackendError,
            "remote store call (not-found)",
        ),
        (
            PublishError::Source(GrainSourceError::Backend(LEAK.into())),
            Outcome::LocalError,
            "reading the local store (backend error)",
        ),
        (
            PublishError::BadPlan,
            Outcome::LocalError,
            "bin plan does not cover its frames",
        ),
        (
            PublishError::ReservedVolumeName {
                volume: LEAK.into(),
            },
            Outcome::LocalError,
            "name is reserved; nothing was uploaded, but the source tree was already harvested into the local store",
        ),
    ] {
        let (got, text) = direct(error);
        assert_eq!(got, outcome, "{text}");
        assert!(text.contains(wanted), "wanted {wanted:?}, got {text:?}");
        assert!(!text.contains("direct publication"), "{text}");
    }
    for (error, wanted) in [
        (
            RecoveryError::Record(granary_core::retained_submission::Error::Exhausted),
            "retained submission capacity exhausted",
        ),
        (
            RecoveryError::Record(granary_core::retained_submission::Error::Decode(
                granary_core::encoding::DecodeError::Truncated,
            )),
            "retained submission could not be decoded",
        ),
        (
            RecoveryError::Entropy(granary_core::secure_random::EntropyUnavailable),
            "no cryptographic randomness was available",
        ),
        (
            RecoveryError::Invalid("candidate set is empty"),
            "invalid state: candidate set is empty",
        ),
    ] {
        let (outcome, text) = diagnostic(&error);
        assert_eq!(outcome, Outcome::LocalError, "{text}");
        assert!(text.contains(wanted), "wanted {wanted:?}, got {text:?}");
    }
}

/// A rule raised while verifying the remote history is the peer's evidence
/// failing (backend error, rule named); a local-state rule stays local.
#[test]
fn remote_integrity_rules_are_backend_errors_and_local_rules_stay_local() {
    let mut report = InvocationReport::new(None);
    recovery_error(
        &mut report,
        &RecoveryError::Refused("SyncWorkspaceExhausted"),
    );
    let text = report.diagnostic.clone().unwrap();
    assert_eq!(
        (report.outcome, text.contains("SyncWorkspaceExhausted")),
        (Outcome::Refused, true),
        "{text}"
    );
    for rule in [
        "untrusted head",
        "root ancestry mismatch",
        "listed head missing",
        "sheaf hash mismatch",
    ] {
        let mut report = InvocationReport::new(None);
        recovery_error(&mut report, &RecoveryError::RemoteIntegrity(rule));
        assert_eq!(report.outcome, Outcome::BackendError, "{rule}");
        assert_eq!(report.outcome.code(), 6);
        let text = report.diagnostic.clone().unwrap();
        assert!(text.contains(rule), "{text}");
        assert!(!text.contains("persisted"), "{text}");
    }
    let mut report = InvocationReport::new(None);
    recovery_error(&mut report, &RecoveryError::Invalid("frozen root"));
    assert_eq!(report.outcome, Outcome::LocalError);
    assert_eq!(report.outcome.code(), 1);
}

#[tokio::test]
async fn source_nesting_refuses_before_seed_creation_with_valid_control() {
    let (_dir, mut a, mut store, key, protected) = setup();
    let original = a.key_seed.clone();
    a.key_seed = a.source.join("new-seed");
    let peer = Peer::new(vec![observed(), observed(), observed()]);
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::LocalError);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
    a.key_seed = original;
    let report = run(&a, &peer, &mut store, &key, &protected, None).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn degraded_cache_skips_winner_writes_but_keeps_landing_and_hint() {
    let (dir, mut a, mut store, key, protected) = setup();
    a.cache_dir = Some(dir.0.join("cache"));
    let origin = cache_origin(&a.endpoint, &[[1; 32]], Some(key.public_key()));
    let held = Cache::open(
        a.cache_dir.as_ref().unwrap(),
        DEFAULT_CACHE_QUOTA_BYTES,
        &origin,
    )
    .unwrap();
    let r = record(&a, &key, None);
    persist(&mut store, &r);
    let peer = Peer::new(vec![]);
    let report = run(&a, &peer, &mut store, &key, &protected, Some(r)).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_eq!(report.cache.result, "skipped");
    assert_eq!(report.hint.result, "written");
    assert!(held.get_root_bytes(&a.volume, 1).is_none());
    assert!(held.read_anchor(&a.volume).is_none());
    assert_eq!(*peer.hints.lock().unwrap(), vec![1]);
    held.close().unwrap();
}

#[tokio::test]
async fn auto_without_context_bootstraps_before_seam_or_context_refusal() {
    for (status, outcome, route, puts) in [
        (
            StatusResponse::Refused(StatusRefusal::UnknownVolume),
            Outcome::Landed,
            Some(Route::ServerSeam),
            1,
        ),
        (observed(), Outcome::LocalError, None, 0),
    ] {
        let (_dir, mut a, mut store, key, protected) = setup();
        a.configuration.context = None;
        let peer = Peer::new(vec![
            StatusResponse::Refused(StatusRefusal::UnknownVolume),
            status,
        ]);
        let report = run(&a, &peer, &mut store, &key, &protected, None).await;
        assert_eq!(report.outcome, outcome);
        assert_eq!(report.route, route);
        assert_eq!(peer.puts.load(Ordering::SeqCst), puts);
        assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
        assert!(peer.status.lock().unwrap().is_empty());
    }
}

#[test]
fn failed_new_keeps_previous_completion_identity_separate_from_attempt_retention() {
    let (_dir, mut a, mut store, key, _) = setup();
    let r = record(&a, &key, None);
    persist(&mut store, &r);
    drop(store);
    a.selection = Selection::New;
    let report = invoke(&a, &process_credentials());
    assert_eq!(report.outcome, Outcome::LocalError);
    assert_eq!(report.previous_completion_id, Some(r.publication_id));
    assert!(report.publication_id.is_none());
    assert_eq!(report.retention, Retention::None);
    assert!(
        report
            .diagnostic
            .as_ref()
            .unwrap()
            .contains(&hex(&r.publication_id))
    );
}

#[test]
fn invoke_loads_retained_before_source_or_credential_admission() {
    let (_dir, a, mut store, key, _) = setup();
    let r = record(
        &a,
        &key,
        Some(Phase::Unresolved(Probe {
            cycle: 1,
            seq: 1,
            reason: ProbeReason::Interrupted,
        })),
    );
    persist(&mut store, &r);
    drop(store);
    remove(&a.source);
    let report = invoke(&a, &process_credentials());
    assert_eq!(report.outcome, Outcome::LocalError);
    assert_eq!(report.publication_id, Some(r.publication_id));
    assert_eq!(report.retention, Retention::Live);
    let mut store = Store::open(&a.store_dir).unwrap();
    let loaded = store
        .publications(process_credentials().euid)
        .unwrap()
        .load(&r.scope, &r.volume)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.generation, 3);
    assert_eq!(loaded.candidates, r.candidates);
}

#[tokio::test]
async fn cache_admission_failure_is_advisory_and_hint_still_repairs() {
    let (dir, mut a, mut store, key, protected) = setup();
    a.cache_dir = Some(dir.0.join("cache"));
    let cache = Cache::open(
        a.cache_dir.as_ref().unwrap(),
        DEFAULT_CACHE_QUOTA_BYTES,
        &cache_origin(&a.endpoint, &[[1; 32]], Some(key.public_key())),
    )
    .unwrap();
    let volume_dir = a
        .cache_dir
        .as_ref()
        .unwrap()
        .join("roots")
        .join(a.volume.as_str());
    mkdir(&volume_dir);
    mkdir(&volume_dir.join("00000000000000000001"));
    cache.close().unwrap();
    let r = record(&a, &key, None);
    persist(&mut store, &r);
    let peer = Peer::new(vec![]);
    let report = run(&a, &peer, &mut store, &key, &protected, Some(r)).await;
    assert_eq!(report.outcome, Outcome::Landed);
    assert_eq!(report.cache.result, "failed");
    assert_eq!(report.hint.result, "written");
    assert_eq!(*peer.hints.lock().unwrap(), vec![1]);
    assert_eq!(
        report.render(true, &mut Vec::new(), &mut Vec::new()),
        std::process::ExitCode::SUCCESS
    );
}

#[tokio::test]
async fn ready_resume_ignores_changed_and_deleted_source() {
    for deleted in [false, true] {
        let (_dir, a, mut store, key, protected) = setup();
        let r = record(&a, &key, Some(Phase::Ready));
        persist(&mut store, &r);
        if deleted {
            remove(&a.source);
        } else {
            write(&a.source.join("file"), b"different content");
        }
        let peer = Peer::new(vec![]);
        let report = run(&a, &peer, &mut store, &key, &protected, Some(r.clone())).await;
        assert_eq!(
            report.outcome,
            Outcome::Landed,
            "retained Ready must bypass source harvesting"
        );
        assert_eq!(report.publication_id, Some(r.publication_id));
        assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
        assert_eq!(peer.probes.load(Ordering::SeqCst), 1);
        assert_eq!(
            peer.remote.get_root("vol", 1).await.unwrap(),
            Some(r.frozen.initial_root.clone())
        );
        let saved = store
            .publications(process_credentials().euid)
            .unwrap()
            .load(&r.scope, &r.volume)
            .unwrap()
            .unwrap();
        assert_eq!(saved.frozen, r.frozen);
    }
}
