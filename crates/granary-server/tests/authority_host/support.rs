// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::output::CommandExt as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use granary_core::authlog::{
    Envelope, Epoch, Operation, Record, RecordBody, RootBytes, SubmissionIdentity, encode_append,
    encode_envelope,
};
use granary_core::binmap::{decode_bin_table, decode_binmap_index};
use granary_core::enrollment::{ClientSpkiDigest, TenantName};
use granary_core::hash::GrainId;
use granary_core::identity::WriterIdentity;
use granary_core::root::{self, RootDoc, RootSig, VolumeName};
use granary_core::runmarker::{RunMarker, decode_marker, encode_marker};
use granary_core::sheaf::Timestamp;
use granary_net::alpn::ALPN_HTTP11;
use granary_net::secure_random::OsSecureRandom;
use granary_server::{VerbOptions, mint};
use granary_store::backend::GranaryStore;
use granary_store::crypto::SigningKey;
use object_store::memory::InMemory;
use rcgen::PublicKeyData as _;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

#[path = "shapes.rs"]
#[allow(dead_code)]
pub(super) mod shapes;
pub(super) use shapes::*;

pub(super) const WAIT: Duration = Duration::from_secs(5);
const STDERR_BOUND: Duration = Duration::from_secs(5);
pub(super) const EPOCH: &str = "11111111111111111111111111111111";
pub(super) const OPTIONS: VerbOptions = VerbOptions {
    accept_unsupported_filesystem: true,
};

pub(super) fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub(super) struct Credential {
    pub(super) cert: rustls::pki_types::CertificateDer<'static>,
    pub(super) key: rcgen::KeyPair,
}
impl Credential {
    pub(super) fn digest(&self) -> ClientSpkiDigest {
        ClientSpkiDigest::from_spki_der(&self.key.subject_public_key_info())
    }
}

pub(super) struct Fixture {
    pub(super) dir: PathBuf,
    pub(super) state: PathBuf,
    pub(super) enrollment: PathBuf,
    pub(super) peer: Credential,
    pub(super) other: Credential,
    ca: rcgen::Certificate,
    pub(super) accept_unsupported: bool,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl Fixture {
    #[expect(
        clippy::disallowed_methods,
        reason = "process ID only isolates test scratch paths"
    )]
    pub(super) fn new(records: u64) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("granary-host-{}-{n}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        let state = dir.join("state");
        let enrollment = dir.join("enrollment");
        for path in [&state, &enrollment] {
            std::fs::create_dir(path).unwrap();
            chmod(path, 0o700);
        }
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let mut server = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert = server.signed_by(&server_key, &issuer).unwrap();
        std::fs::write(dir.join("server.pem"), server_cert.pem()).unwrap();
        std::fs::write(dir.join("server.key"), server_key.serialize_pem()).unwrap();
        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        let credential = || {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::default();
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            Credential {
                cert: params.signed_by(&key, &issuer).unwrap().der().clone(),
                key,
            }
        };
        let peer = credential();
        let other = credential();
        for cred in [&peer, &other] {
            mint(
                &enrollment,
                OPTIONS,
                &TenantName::parse("test").unwrap(),
                cred.digest(),
                &mut OsSecureRandom::new(),
            )
            .unwrap();
        }
        let fx = Self {
            dir,
            state,
            enrollment,
            peer,
            other,
            ca,
            accept_unsupported: std::env::var_os("GRANARY_HOST_EXT4").is_none(),
        };
        std::fs::write(
            fx.state.join("MARKER"),
            encode_marker(&RunMarker::Clean).as_bytes(),
        )
        .unwrap();
        for name in ["alpha", "beta"] {
            fx.log(name, records);
        }
        fx
    }

    fn log(&self, name: &str, count: u64) {
        let volume = VolumeName::new(name.to_owned()).unwrap();
        let env = Envelope::new(volume, Epoch::from_bytes([0x11; 16]));
        let mut bytes = encode_envelope(&env).as_bytes().to_vec();
        let mut parent = None;
        for seq in 1..=count {
            let candidate = root_bytes(name, seq, parent, &publisher());
            let id = GrainId::of(&candidate);
            let identity = SubmissionIdentity::new(
                granary_core::authlog::Tenant::new(b"test".to_vec()).unwrap(),
                granary_core::authlog::Principal::new(vec![1; 16]).unwrap(),
                Operation::new(seq.to_le_bytes().to_vec()).unwrap(),
                id,
            );
            for body in [
                RecordBody::Decision {
                    identity: identity.clone(),
                    root_seq: seq,
                    base: parent,
                    decided_at: Timestamp { secs: 1, nanos: 0 },
                    candidate: RootBytes::new(candidate.clone()).unwrap(),
                },
                RecordBody::Attestation {
                    identity: identity.clone(),
                    stored_id: id,
                    final_root: RootBytes::new(candidate).unwrap(),
                },
                RecordBody::Landed { identity },
            ] {
                let append = encode_append(&env, &Record::new(seq, body).unwrap()).unwrap();
                bytes.extend_from_slice(append.record());
                bytes.extend_from_slice(append.mark());
            }
            parent = Some(id);
        }
        std::fs::write(self.state.join(format!("{name}.log")), bytes).unwrap();
    }

    /// Explicit operator creation for tests needing an available intent service.
    /// General fixtures retain their missing-store and missing-log cases.
    pub(super) fn initialise(&self, volume: &str) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_granary-server"));
        command
            .env_clear()
            .args(["initialise", "--state-dir"])
            .arg(&self.state)
            .args(["--volume", volume]);
        if self.accept_unsupported {
            command.arg("--accept-unsupported-filesystem");
        }
        let output = command.guarded_output().unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    pub(super) fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_granary-server"));
        command
            .env_clear()
            .envs([
                ("GRANARY_AUTHORITY", "single-process"),
                ("GRANARY_AUTHORITY_VOLUMES", "alpha,beta"),
                ("GRANARY_STORE", "memory:"),
                ("GRANARY_LISTEN", "127.0.0.1:0"),
                ("RUST_LOG", "info"),
                (
                    "GRANARY_AUTHORITY_ACCEPT_UNSUPPORTED_FILESYSTEM",
                    if self.accept_unsupported {
                        "true"
                    } else {
                        "false"
                    },
                ),
            ])
            .env("GRANARY_AUTHORITY_STATE_DIR", &self.state)
            .env("GRANARY_AUTHORITY_ENROLLMENT_DIR", &self.enrollment)
            .env("GRANARY_AUTHORITY_CLIENT_CA", self.dir.join("ca.pem"))
            .env("GRANARY_TLS_CERT", self.dir.join("server.pem"))
            .env("GRANARY_TLS_KEY", self.dir.join("server.key"));
        for volume in ["ALPHA", "BETA"] {
            command.env(
                format!("GRANARY_AUTHORITY_VOLUME_{volume}_PUBLISHER_KEYS"),
                format!("ed25519:{}", hex(publisher().public_key())),
            );
        }
        command
    }

    pub(super) fn plan(&self, command: &mut Command, site: &str, k: u32, fail: bool) {
        command
            .env(
                "GRANARY_TEST_HOST_PLAN",
                format!("{site}:{k}:{}", if fail { "fail" } else { "hold" }),
            )
            .env("GRANARY_TEST_HOST_REACHED", self.dir.join("reached"))
            .env("GRANARY_TEST_HOST_RELEASE", self.dir.join("release"));
    }
    pub(super) async fn reached(&self, line: &str) {
        timeout(WAIT, async {
            loop {
                if self.notes().lines().any(|s| s == line) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("never reached {line}: {}", self.notes()));
    }
    pub(super) fn notes(&self) -> String {
        std::fs::read_to_string(self.dir.join("reached")).unwrap_or_default()
    }
    pub(super) fn release(&self) {
        std::fs::write(self.dir.join("release"), b"release").unwrap();
    }
    pub(super) fn marker(&self) -> RunMarker {
        decode_marker(&std::fs::read(self.state.join("MARKER")).unwrap()).unwrap()
    }
    pub(super) fn state_bytes(&self) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(&self.state)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect()
    }
    pub(super) fn client(&self, cred: Option<&Credential>) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca.der().clone()).unwrap();
        let builder =
            rustls::ClientConfig::builder_with_provider(Arc::new(granary_net::crypto_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots);
        let mut config = match cred {
            Some(c) => builder
                .with_client_auth_cert(
                    vec![c.cert.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key.serialize_der())),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        config
    }
    pub(super) async fn connect(&self, addr: SocketAddr, cred: Option<&Credential>) -> Peer {
        let tcp = timeout(WAIT, TcpStream::connect(addr))
            .await
            .unwrap()
            .unwrap();
        let stream = timeout(
            WAIT,
            TlsConnector::from(Arc::new(self.client(cred)))
                .connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap();
        Peer {
            stream,
            buffered: vec![],
        }
    }
    pub(super) async fn seed_read(&self, addr: SocketAddr) {
        let mut peer = self.connect(addr, Some(&self.other)).await;
        let body = root_bytes("probe", 1, None, &publisher());
        let response = peer
            .request("PUT", "/volume/probe/root/00000000000000000001", &[], &body)
            .await;
        assert_eq!(response.status, 201, "{response:?}");
    }
    pub(super) async fn candidate(&self) -> Candidate {
        let source = self.dir.join("empty-tree");
        std::fs::create_dir(&source).unwrap();
        let local = granary_client::Store::open(&self.dir.join("candidate-store")).unwrap();
        let store = GranaryStore::new(Arc::new(InMemory::new()));
        let prepared = granary_client::prepare(
            &store,
            &local,
            &source,
            &VolumeName::new("alpha".to_owned()).unwrap(),
            &publisher(),
            &WriterIdentity::from_bytes([1; 16]),
            Timestamp {
                secs: 1_760_000_000,
                nanos: 0,
            },
            granary_client::Policy::default(),
        )
        .await
        .unwrap();
        Candidate {
            root: prepared.root_bytes,
            store,
        }
    }
    pub(super) async fn read(&self, addr: SocketAddr) {
        let mut peer = self.connect(addr, None).await;
        let response = peer
            .request("GET", "/volume/probe/root/00000000000000000001", &[], &[])
            .await;
        assert_eq!(response.status, 200, "{response:?}");
    }
}

pub(super) struct Candidate {
    pub(super) root: Vec<u8>,
    store: GranaryStore<Arc<InMemory>>,
}

impl Candidate {
    /// Copy the prepared closure through the shipped host's upload routes.
    /// Return the request count so request IDs can be attributed after setup.
    pub(super) async fn seed(&self, peer: &mut Peer) -> u64 {
        let doc = root::decode_root(&self.root).unwrap();
        let volume = doc.volume.as_str();
        let index = self
            .store
            .get_meta(volume, &doc.binmap_index)
            .await
            .unwrap();
        let index = decode_binmap_index(&index).unwrap();
        let table = self.store.get_meta(volume, &index.bin_table).await.unwrap();
        let mut requests = 0;
        for digest in decode_bin_table(&table).unwrap() {
            let bytes = self.store.get_bin(&digest).await.unwrap();
            let response = peer
                .request("PUT", &format!("/bin/{}", hex(&digest)), &[], &bytes)
                .await;
            assert_eq!(response.status, 201, "{response:?}");
            requests += 1;
        }
        let meta: BTreeSet<_> = [doc.binmap_index, index.bin_table, doc.sheaf_head]
            .into_iter()
            .chain(index.shards)
            .collect();
        for id in meta {
            let bytes = self.store.get_meta(volume, &id).await.unwrap();
            let response = peer
                .request("PUT", &format!("/volume/{volume}/meta/{id}"), &[], &bytes)
                .await;
            assert_eq!(response.status, 201, "{response:?}");
            requests += 1;
        }
        requests
    }
}

pub(super) fn publisher() -> SigningKey {
    SigningKey::from_seed(&[0x33; 32]).unwrap()
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(&mut text, "{byte:02x}").unwrap();
        text
    })
}
pub(super) fn root_bytes(
    name: &str,
    seq: u64,
    parent: Option<GrainId>,
    key: &SigningKey,
) -> Vec<u8> {
    let doc = RootDoc {
        volume: VolumeName::new(name.to_owned()).unwrap(),
        seq,
        parent,
        writer_uuid: [1; 16],
        epoch: 7,
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        chunker_spec: "test-chunker".to_owned(),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![],
    };
    sign_root(doc, key)
}

pub(super) fn sign_root(mut doc: RootDoc, key: &SigningKey) -> Vec<u8> {
    doc.sigs.clear();
    let prefix = root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    root::encode_root(&doc).unwrap()
}

pub(super) struct Process {
    pub(super) child: Child,
    pub(super) stderr: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Process {
    pub(super) fn spawn(command: &mut Command) -> Self {
        Self::spawn_with_stderr(command, Arc::new(Mutex::new(String::new())))
    }
    pub(super) fn spawn_with_stderr(command: &mut Command, stderr: Arc<Mutex<String>>) -> Self {
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut process = Self {
            child,
            stderr,
            reader: None,
        };
        let lines = BufReader::new(process.child.stderr.take().unwrap());
        let buffer = process.stderr.clone();
        let reader = std::thread::spawn(move || {
            for line in lines.lines() {
                let line = line.unwrap();
                writeln!(buffer.lock().unwrap(), "{line}").unwrap();
            }
        });
        process.reader = Some(reader);
        process
    }
    pub(super) fn output(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }
    pub(super) async fn ready(&mut self) -> SocketAddr {
        timeout(WAIT, async {
            loop {
                if let Some((_, after)) = self.output().split_once("\"addr\":\"") {
                    return after.split('"').next().unwrap().parse().unwrap();
                }
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "exited before ready: {}",
                    self.output()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no readiness: {}", self.output()))
    }
    pub(super) fn signal(&self, signal: &str) {
        assert!(
            Command::new("/bin/kill")
                .args([format!("-{signal}"), self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
    pub(super) async fn exit(&mut self, code: i32, bound: Duration) {
        let status = timeout(bound, async {
            loop {
                if let Some(s) = self.child.try_wait().unwrap() {
                    break s;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("child survived {bound:?}: {}", self.output()));
        if let Some(reader) = self.reader.take() {
            timeout(STDERR_BOUND, async {
                while !reader.is_finished() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("stderr reader did not reach EOF within {STDERR_BOUND:?}"));
            // Finished already: joining propagates read failures without blocking.
            reader.join().unwrap();
        }
        assert_eq!(status.code(), Some(code), "{}", self.output());
    }
    pub(super) fn not_ready(&mut self, addr: SocketAddr) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "{}",
            self.output()
        );
        assert!(!self.output().contains("listening"));
        assert!(
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_err(),
            "listener bound before replay"
        );
    }
}

#[derive(Debug)]
pub(super) struct Response {
    pub(super) status: u16,
    pub(super) head: String,
    pub(super) body: Vec<u8>,
}
pub(super) struct Peer {
    pub(super) stream: TlsStream<TcpStream>,
    buffered: Vec<u8>,
}
impl Peer {
    pub(super) async fn send(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &[u8])],
        body: &[u8],
        length: usize,
    ) {
        let mut head =
            format!("{method} {path} HTTP/1.1\r\nhost: localhost\r\ncontent-length: {length}\r\n")
                .into_bytes();
        for (name, val) in headers {
            head.extend_from_slice(name.as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(val);
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        self.stream.write_all(&head).await.unwrap();
        self.stream.write_all(body).await.unwrap();
        self.stream.flush().await.unwrap();
    }
    pub(super) async fn response(&mut self) -> Response {
        timeout(WAIT, async {
            let end = loop {
                if let Some(n) = self.buffered.windows(4).position(|w| w == b"\r\n\r\n") {
                    break n + 4;
                }
                self.more().await;
            };
            let head = String::from_utf8(self.buffered[..end].to_vec()).unwrap();
            let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
            let length: usize = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse().unwrap())
                })
                .unwrap_or(0);
            while self.buffered.len() < end + length {
                self.more().await;
            }
            let body = self.buffered[end..end + length].to_vec();
            self.buffered.drain(..end + length);
            Response { status, head, body }
        })
        .await
        .unwrap()
    }
    async fn more(&mut self) {
        let mut bytes = [0; 4096];
        let n = self.stream.read(&mut bytes).await.unwrap();
        assert!(n > 0, "closed before response: {:?}", self.buffered);
        self.buffered.extend_from_slice(&bytes[..n]);
    }
    pub(super) async fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &[u8])],
        body: &[u8],
    ) -> Response {
        self.send(method, path, headers, body, body.len()).await;
        self.response().await
    }
    pub(super) async fn publish(&mut self, body: &[u8], op: u8) -> Response {
        let op_str = format!("{op:02x}");
        self.request(
            "POST",
            "/volume/alpha/publish",
            &[
                ("granary-epoch", EPOCH.as_bytes()),
                ("granary-operation", op_str.as_bytes()),
            ],
            body,
        )
        .await
    }
    pub(super) async fn submit(&mut self, body: &[u8]) {
        self.send(
            "POST",
            "/volume/alpha/publish",
            &[
                ("granary-epoch", EPOCH.as_bytes()),
                ("granary-operation", b"01"),
            ],
            body,
            body.len(),
        )
        .await;
    }
}
