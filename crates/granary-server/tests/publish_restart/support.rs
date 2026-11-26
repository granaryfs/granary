// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use granary_core::authlog::Epoch;
use granary_core::authority_answer::{
    self as answer, Head, Position, PublishAnswer, Receipt, VolumeStatus,
};
use granary_core::hash::GrainId;
use granary_core::retained_submission::{self as retained, Candidate, Role, Submission};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::time::timeout;

pub(super) const EPOCH: [u8; 16] = [0x11; 16];
pub(super) const ROOT_PATH: &str = "/volume/alpha/root/00000000000000000001";

pub(super) fn base_url(addr: SocketAddr) -> String {
    format!("https://{addr}")
}

pub(super) fn registry() -> Vec<String> {
    cut_names("CUTS")
}

fn cut_names(name: &str) -> Vec<String> {
    // Read the one nonshipping cut registry, without enabling the client feature
    // through this test target's dependency graph.
    let source = include_str!("../../../granary-client/src/publish_restart.rs");
    let header = format!("pub const {name}: &[&str] = &[");
    let list = source
        .split(header.as_str())
        .nth(1)
        .unwrap()
        .split("];")
        .next()
        .unwrap();
    list.split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_owned())
        .collect()
}

pub(super) fn physical_registry() -> Vec<String> {
    cut_names("PHYSICAL_CUTS")
}

pub(super) fn archive_registry() -> Vec<String> {
    cut_names("ARCHIVE_CUTS")
}

pub(super) fn cut_sides(name: &str) -> &'static [&'static str] {
    if cut_names("AFTER_ONLY_CUTS").iter().any(|cut| cut == name) {
        &["after"]
    } else {
        &["before", "after"]
    }
}

/// The publisher key seed every fixture and every expected key derives from.
pub(super) const SEED: [u8; 32] = [0x33; 32];

/// The signing key the fixtures' `seed` file holds.
pub(super) fn seed_key() -> granary_store::crypto::SigningKey {
    granary_store::crypto::SigningKey::from_seed(&SEED).unwrap()
}

/// The public half of [`SEED`], as the fixtures' `seed.pub` file holds it.
pub(super) fn seed_public() -> [u8; 32] {
    *seed_key().public_key()
}

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in bytes {
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

#[path = "process.rs"]
mod process;
#[cfg(feature = "crash-points")]
pub(super) use process::HOST_DRAIN;
pub(super) use process::{Process, Scratch, WAIT};

/// Full observed exchanges, including preparation and repair; no count stands
/// in for the request/response bytes. Header identities are retained verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Exchange {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) body: Vec<u8>,
    pub(super) epoch: Option<String>,
    pub(super) operation: Option<String>,
    pub(super) status: u16,
    pub(super) response: Vec<u8>,
}
#[derive(Default)]
pub(super) struct PeerState {
    /// Authority epoch; scenarios can rotate it after retaining an old request.
    pub(super) epoch: Option<[u8; 16]>,
    pub(super) transcript: Vec<Exchange>,
    pub(super) objects: BTreeMap<String, Vec<u8>>,
    pub(super) roots: BTreeMap<String, Vec<u8>>,
    pub(super) roots_on_publish: BTreeMap<String, Vec<u8>>,
    pub(super) probe: ProbeReply,
    pub(super) probe_replies: VecDeque<ProbeReply>,
    pub(super) max_seq_replies: VecDeque<MaxSeqReply>,
    pub(super) landings: usize,
    pub(super) replies: VecDeque<Reply>,
}
#[derive(Clone, Debug)]
pub(super) enum Reply {
    Wire(u16, Option<&'static str>, Vec<u8>),
    Disconnect,
    Historical(Candidate),
}
impl Reply {
    pub(super) fn answer(status: u16, value: PublishAnswer) -> Self {
        let token = match value {
            PublishAnswer::StaleBase(_) => Some("stale-base"),
            PublishAnswer::EpochMismatch { .. } => Some("epoch-mismatch"),
            _ => None,
        };
        Self::Wire(status, token, answer::encode(value).unwrap())
    }
}
#[derive(Default, Clone)]
pub(super) enum ProbeReply {
    #[default]
    Normal,
    Missing,
    Failed,
    Malformed,
    Oversized,
}
#[derive(Clone, Debug)]
pub(super) enum MaxSeqReply {
    Failed,
    Value(Option<u64>),
}

#[expect(
    clippy::too_many_lines,
    reason = "one controlled peer records every request and its independently encoded response"
)]
async fn exchange(
    req: Request<Incoming>,
    state: Arc<Mutex<PeerState>>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let epoch = req
        .headers()
        .get("granary-epoch")
        .map(|v| v.to_str().unwrap().to_owned());
    let operation = req
        .headers()
        .get("granary-operation")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
    let mut s = state.lock().unwrap();
    let current_epoch = s.epoch.unwrap_or(EPOCH);
    let mut status = 200;
    let mut token = None;
    let mut media = "application/vnd.granary.root.v1";
    let mut disconnect = false;
    let response = if method == "GET" && path.ends_with("/status") {
        media = "application/vnd.granary.volume-status.v1";
        answer::encode_status(VolumeStatus {
            epoch: Epoch::from_bytes(current_epoch),
            head: Some(Head::new(None)),
            open: None,
        })
        .unwrap()
    } else if method == "POST" && path.ends_with("/publish") {
        let root = granary_core::root::decode_root(&body).unwrap();
        let slot = format!("/volume/alpha/root/{:020}", root.seq);
        assert!(epoch.as_ref().is_some_and(|v| v.len() == 32));
        assert!(operation.as_ref().is_some_and(|v| v.len() == 32));
        media = "application/vnd.granary.authority-answer.v1";
        let reply = if epoch
            .as_ref()
            .unwrap()
            .eq_ignore_ascii_case(&hex(&current_epoch))
        {
            s.replies.pop_front()
        } else {
            Some(Reply::answer(
                409,
                PublishAnswer::EpochMismatch {
                    epoch: Epoch::from_bytes(current_epoch),
                    head: Some(Head::new(None)),
                },
            ))
        };
        for (path, bytes) in std::mem::take(&mut s.roots_on_publish) {
            s.roots.insert(path, bytes);
        }
        match reply {
            Some(Reply::Wire(code, error, bytes)) => {
                status = code;
                token = error;
                bytes
            }
            Some(Reply::Historical(winner)) => {
                assert_ne!(
                    winner.root, body,
                    "historical fixture needs distinct A/B roots"
                );
                assert!(
                    s.roots
                        .insert(
                            format!("/volume/alpha/root/{:020}", winner.seq),
                            winner.root.clone(),
                        )
                        .is_none(),
                    "historical landing overwrote an occupied root"
                );
                s.landings += 1;
                status = 409;
                token = Some("operation-bound");
                answer::encode(PublishAnswer::OperationBound(answer::Bound::Landed(
                    Receipt {
                        position: Position {
                            epoch: Epoch::from_bytes(winner.request.epoch),
                            entry_seq: 1,
                        },
                        root_seq: winner.seq,
                        stored_id: winner.id,
                    },
                )))
                .unwrap()
            }
            Some(Reply::Disconnect) => {
                status = 0;
                disconnect = true;
                Vec::new()
            }
            None => {
                if let Some(old) = s.roots.get(&slot) {
                    assert_eq!(*old, body, "unexpected successor/foreign POST");
                } else {
                    s.landings += 1;
                    s.roots.insert(slot, body.clone());
                }
                answer::encode(PublishAnswer::Landed {
                    receipt: Receipt {
                        position: Position {
                            epoch: Epoch::from_bytes(current_epoch),
                            entry_seq: 1,
                        },
                        root_seq: root.seq,
                        stored_id: GrainId::of(&body),
                    },
                    head: Some(Head::new(Some((root.seq, GrainId::of(&body))))),
                })
                .unwrap()
            }
        }
    } else if method == "GET" && path.ends_with("/max-seq") {
        media = "text/plain";
        match s.max_seq_replies.pop_front() {
            Some(MaxSeqReply::Failed) => {
                status = 503;
                token = Some("internal");
                Vec::new()
            }
            Some(MaxSeqReply::Value(Some(seq))) => format!("{seq:020}").into_bytes(),
            Some(MaxSeqReply::Value(None)) => {
                status = 404;
                token = Some("not-found");
                Vec::new()
            }
            None => {
                if let Some(path) = s.roots.keys().next_back() {
                    path.rsplit('/').next().unwrap().as_bytes().to_vec()
                } else {
                    status = 404;
                    token = Some("not-found");
                    Vec::new()
                }
            }
        }
    } else if method == "PUT" {
        if path.ends_with("/hint") {
            status = 204;
            Vec::new()
        } else {
            if let Some(old) = s.objects.get(&path) {
                assert_eq!(*old, body, "immutable upload changed across restart");
            } else {
                status = 201;
                s.objects.insert(path.clone(), body.clone());
            }
            Vec::new()
        }
    } else if path.contains("/root/") {
        let reply = s
            .probe_replies
            .pop_front()
            .unwrap_or_else(|| s.probe.clone());
        match reply {
            ProbeReply::Missing => {
                status = 404;
                token = Some("not-found");
                Vec::new()
            }
            ProbeReply::Failed => {
                status = 503;
                token = Some("internal");
                Vec::new()
            }
            ProbeReply::Malformed => {
                media = "text/plain";
                b"malformed".to_vec()
            }
            ProbeReply::Oversized => {
                vec![0; usize::try_from(granary_core::root::ROOT_MAX_BYTES).unwrap() + 1]
            }
            ProbeReply::Normal => {
                if let Some(b) = s.roots.get(&path) {
                    b.clone()
                } else {
                    status = 404;
                    token = Some("not-found");
                    Vec::new()
                }
            }
        }
    } else if let Some(b) = s.objects.get(&path) {
        media = if path.contains("/meta/") {
            "application/vnd.granary.meta.v1"
        } else {
            "application/vnd.granary.bin.v1"
        };
        b.clone()
    } else {
        status = 404;
        token = Some("not-found");
        Vec::new()
    };
    s.transcript.push(Exchange {
        method,
        path,
        body,
        epoch,
        operation,
        status,
        response: response.clone(),
    });
    if disconnect {
        return Err(std::io::Error::other("controlled lost reply"));
    }
    let mut response_builder = Response::builder()
        .status(status)
        .header("content-type", media);
    if let Some(token) = token {
        response_builder = response_builder.header("granary-error", token);
    }
    Ok(response_builder
        .body(Full::new(Bytes::from(response)))
        .unwrap())
}

pub(super) struct Fixture {
    pub(super) scratch: Scratch,
    pub(super) peer: Arc<Mutex<PeerState>>,
    pub(super) source: PathBuf,
    pub(super) store: PathBuf,
    pub(super) endpoint: String,
    pin: String,
    task: Option<tokio::task::JoinHandle<()>>,
    shutdown: Option<tokio::sync::watch::Sender<bool>>,
}
impl Fixture {
    pub(super) async fn new() -> Self {
        let scratch = Scratch::new();
        let private = scratch.0.join("private");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .unwrap();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = generated.cert.der().clone();
        for (name, bytes) in [
            ("client.pem", generated.cert.pem().into_bytes()),
            (
                "client.key",
                generated.signing_key.serialize_pem().into_bytes(),
            ),
            ("seed", SEED.to_vec()),
            ("seed.pub", seed_public().to_vec()),
        ] {
            let path = private.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = base_url(addr);
        let pin =
            granary_net::config::render_tls_pin(&granary_net::pin::spki_digest(&cert).unwrap());
        let peer = Arc::new(Mutex::new(PeerState::default()));
        let state = peer.clone();
        let (shutdown, stopping) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let service = hyper::service::service_fn(move |r| exchange(r, state.clone()));
            granary_net::accept::serve(
                listener,
                config,
                service,
                stopping,
                granary_net::accept::AcceptConfig::default(),
            )
            .await
            .unwrap();
        });
        let mut fixture = Self::client(scratch, endpoint, pin);
        fixture.peer = peer;
        fixture.task = Some(task);
        fixture.shutdown = Some(shutdown);
        fixture
    }
    /// Client paths shared by the controlled peer and the real composition.
    pub(super) fn client(scratch: Scratch, endpoint: String, pin: String) -> Self {
        let source = scratch.0.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), b"frozen content").unwrap();
        let store = scratch.0.join("store");
        Self {
            scratch,
            peer: Arc::new(Mutex::new(PeerState::default())),
            source,
            store,
            endpoint,
            pin,
            task: None,
            shutdown: None,
        }
    }
    pub(super) fn command(&self, retained: bool) -> Command {
        let gran = std::env::var_os("GRANARY_RESTART_GRAN")
            .expect("explicit instrumented gran path required");
        checked_executable(Path::new(&gran)).unwrap();
        self.command_at(Path::new(&gran), retained, true)
    }
    pub(super) fn shipping_command(&self, retained: bool, json: bool) -> Command {
        let gran = std::env::var_os("GRANARY_SHIPPING_GRAN")
            .expect("explicit feature-off gran path required");
        checked_executable(Path::new(&gran)).unwrap();
        self.command_at(Path::new(&gran), retained, json)
    }
    fn command_at(&self, gran: &Path, retained: bool, json: bool) -> Command {
        let private = self.scratch.0.join("private");
        let mut cmd = Command::new(gran);
        cmd.env_clear()
            .env("HOME", &private)
            .arg("publish")
            .arg(&self.store);
        if retained {
            cmd.arg("-");
        } else {
            cmd.arg(&self.source);
        }
        cmd.args([
            "alpha",
            "--endpoint",
            &self.endpoint,
            "--pin",
            &self.pin,
            "--credential-context",
            "writer",
        ])
        .arg("--key-seed")
        .arg(private.join("seed"))
        .arg("--client-cert")
        .arg(private.join("client.pem"))
        .arg("--client-key")
        .arg(private.join("client.key"));
        if json {
            cmd.arg("--json");
        }
        cmd
    }
    pub(super) fn record(&self) -> Option<Submission> {
        let publications = self.store.join("publications");
        let mut records = Vec::new();
        if let Ok(dirs) = std::fs::read_dir(publications) {
            for scope in dirs {
                for file in std::fs::read_dir(scope.unwrap().path()).unwrap() {
                    let path = file.unwrap().path();
                    if path.file_name().is_some_and(|e| e == "alpha.sub") {
                        records.push(retained::decode(&std::fs::read(path).unwrap()).unwrap());
                    }
                }
            }
        }
        assert!(records.len() <= 1);
        records.pop()
    }
    pub(super) fn install(&self, record: &Submission) {
        let scope = self
            .store
            .join("publications")
            .join(record.scope.digest().unwrap());
        std::fs::write(scope.join("alpha.sub"), retained::encode(record).unwrap()).unwrap();
    }
    pub(super) fn archives(&self) -> Vec<(PathBuf, Vec<u8>, Submission)> {
        let mut records = Vec::new();
        for scope in std::fs::read_dir(self.store.join("publications")).unwrap() {
            for file in std::fs::read_dir(scope.unwrap().path()).unwrap() {
                let path = file.unwrap().path();
                let name = path.file_name().unwrap().as_encoded_bytes();
                if let Some(parsed) =
                    granary_core::retained_archive::ArchiveName::parse(name).unwrap()
                {
                    let bytes = std::fs::read(&path).unwrap();
                    let record = retained::decode(&bytes).unwrap();
                    assert_eq!(parsed.publication_id, record.publication_id);
                    assert_eq!(parsed.volume, record.volume);
                    records.push((path, bytes, record));
                }
            }
        }
        records
    }
    pub(super) fn transcript(&self) -> Vec<Exchange> {
        self.peer.lock().unwrap().transcript.clone()
    }
    pub(super) fn reset_transcript(&self) {
        self.peer.lock().unwrap().transcript.clear();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(shutdown) = &self.shutdown {
            let _ = shutdown.send(true);
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub(super) fn checked_executable(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || !path.is_file() || path.file_name().is_none_or(|s| s != "gran") {
        return Err(format!("wrong executable path: {}", path.display()));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Event {
    pub(super) cut: String,
    pub(super) side: String,
    pub(super) occurrence: u64,
    pub(super) id: String,
    pub(super) phase: String,
    pub(super) generation: u64,
}
impl Event {
    pub(super) fn parse(line: &str) -> Result<Self, String> {
        let words: Vec<_> = line.split_whitespace().collect();
        if !line.ends_with('\n')
            || line.lines().count() != 1
            || words.len() != 7
            || words[0] != "REACHED"
            || !registry().iter().any(|s| s == words[1])
            || !cut_sides(words[1]).contains(&words[2])
            || !["before", "after"].contains(&words[2])
            || words[4].len() != 32
            || !words[4].bytes().all(|b| b.is_ascii_hexdigit())
            || ![
                "ready",
                "probe-started",
                "unresolved",
                "awaiting-answer",
                "rebase",
                "epoch-recovery",
                "complete",
            ]
            .contains(&words[5])
        {
            return Err(format!("malformed rendezvous report: {line:?}"));
        }
        let occurrence = words[3].parse::<u64>().map_err(|e| e.to_string())?;
        let generation = words[6].parse::<u64>().map_err(|e| e.to_string())?;
        if occurrence == 0 || generation == 0 {
            return Err("zero rendezvous identity".into());
        }
        Ok(Self {
            cut: words[1].into(),
            side: words[2].into(),
            occurrence,
            id: words[4].into(),
            phase: words[5].into(),
            generation,
        })
    }
    pub(super) fn matches(&self, cut: &str, side: &str, occurrence: u64) -> Result<(), String> {
        if self.cut != cut || self.side != side || self.occurrence != occurrence {
            return Err(format!(
                "rendezvous identity mismatch: {self:?}; wanted {cut} {side} {occurrence}"
            ));
        }
        Ok(())
    }
}

pub(super) struct Rendezvous {
    listener: UnixListener,
    cut: String,
    side: String,
    occurrence: u64,
}
impl Rendezvous {
    pub(super) fn arm(
        cmd: &mut Command,
        scratch: &Path,
        cut: &str,
        side: &str,
        occurrence: u64,
    ) -> Self {
        let socket = scratch.join("control.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        cmd.env("GRANARY_RESTART_SOCKET", socket)
            .env("GRANARY_RESTART_CUT", cut)
            .env("GRANARY_RESTART_SIDE", side)
            .env("GRANARY_RESTART_OCCURRENCE", occurrence.to_string());
        Self {
            listener,
            cut: cut.into(),
            side: side.into(),
            occurrence,
        }
    }
    pub(super) async fn reached(
        &self,
        process: &mut Process,
    ) -> Result<(Event, UnixStream), String> {
        // Startup/filesystem work can stall on a loaded host. Connection and
        // report bytes renew the idle budget, but cannot extend the hard cap.
        receive_rendezvous(
            process,
            (&self.cut, &self.side, self.occurrence),
            (Duration::from_mins(1), Duration::from_mins(3)),
            async {
                self.listener
                    .accept()
                    .await
                    .map(|(stream, _)| stream)
                    .map_err(|e| e.to_string())
            },
        )
        .await
    }
}

/// Share the exact arrival/protocol/deadline path with socket-free controls.
async fn receive_rendezvous<S: tokio::io::AsyncRead + Unpin>(
    process: &mut Process,
    (cut, side, occurrence): (&str, &str, u64),
    (idle, total): (Duration, Duration),
    connect: impl std::future::Future<Output = Result<S, String>>,
) -> Result<(Event, S), String> {
    let progress = Cell::new(0_usize);
    let stage = Cell::new("child connection (parent listener armed)");
    let report = async {
        let mut stream = connect.await?;
        progress.set(1);
        stage.set("child REACHED report (connection accepted by parent)");
        let mut bytes = Vec::new();
        // Read one byte at a time to observe progress without consuming any
        // bytes beyond the report. Bound malformed reports as well as time.
        loop {
            let byte = stream.read_u8().await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    "child exit before rendezvous (control EOF)".to_owned()
                } else {
                    e.to_string()
                }
            })?;
            bytes.push(byte);
            progress.set(progress.get() + 1);
            if byte == b'\n' {
                break;
            }
            if bytes.len() >= 1024 {
                return Err("oversized rendezvous report".into());
            }
        }
        let event = Event::parse(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)?;
        event.matches(cut, side, occurrence)?;
        Ok((event, stream))
    };
    match wait_progress(process, idle, total, &progress, report).await {
        Ok(value) => Ok(value),
        Err(error) => {
            // Control EOF can precede process exit. Preserve the natural
            // status/output for negative controls, with a bounded grace.
            if error.starts_with("child exit before rendezvous") {
                let _ =
                    wait_report(process, WAIT, std::future::pending::<Result<(), String>>()).await;
            }
            let out = process.stop_and_capture();
            Err(format!(
                "{error}; missing {}; cut={} side={} occurrence={}\nstdout: {}\nstderr: {}",
                stage.get(),
                cut,
                side,
                occurrence,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }
}

/// Polling observes exit only; it never decides whether a cut was reached.
/// The caller's bound covers every poll of the pinned report, including the
/// final check after observing exit.
pub(super) async fn wait_report<T>(
    process: &mut Process,
    bound: Duration,
    report: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let mut report = std::pin::pin!(report);
    timeout(bound, async {
        loop {
            if let Ok(result) = timeout(Duration::from_millis(10), report.as_mut()).await {
                return result;
            }
            if process.try_wait().is_some() {
                return final_report_check(report.as_mut()).await;
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err(format!("rendezvous bound exceeded ({bound:?})")))
}

async fn final_report_check<T>(
    report: std::pin::Pin<&mut impl std::future::Future<Output = Result<T, String>>>,
) -> Result<T, String> {
    // File pollers sleep at most 10 ms. Give the pinned poller time to start
    // another check after observed exit, when any pre-exit write is visible.
    timeout(Duration::from_millis(25), report)
        .await
        .unwrap_or_else(|_| Err("child exit before rendezvous".into()))
}

/// Output chatter and process liveness are not progress. Only the control
/// protocol can renew idle time, and even continuous progress has a hard cap.
async fn wait_progress<T>(
    process: &mut Process,
    idle: Duration,
    total: Duration,
    progress: &Cell<usize>,
    report: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let start = tokio::time::Instant::now();
    let absolute = start + total;
    let mut deadline = start + idle;
    let bound_error = |at: tokio::time::Instant| {
        let kind = if at >= absolute { "absolute" } else { "idle" };
        format!("rendezvous bound exceeded ({kind}; idle={idle:?}, total={total:?})")
    };
    let mut seen = progress.get();
    let mut report = std::pin::pin!(report);
    loop {
        // Poll the report first: a host scheduling stall must not discard an
        // arrival already waiting in the socket when the parent resumes.
        if let Ok(result) = timeout(Duration::from_millis(10), report.as_mut()).await {
            return result;
        }
        let now = tokio::time::Instant::now();
        if progress.get() != seen {
            seen = progress.get();
            deadline = now + idle;
        }
        let limit = absolute.min(deadline);
        if now >= limit {
            return Err(bound_error(now));
        }
        if process.try_wait().is_some() {
            return tokio::time::timeout_at(limit, final_report_check(report.as_mut()))
                .await
                .unwrap_or_else(|_| Err(bound_error(limit)));
        }
    }
}

pub(super) fn assert_exit(output: &Output, code: i32) -> String {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}
pub(super) async fn run(cmd: &mut Command, code: i32) -> String {
    assert_exit(&Process::spawn(cmd).output().await, code)
}

pub(super) async fn cut(fx: &Fixture, name: &str, side: &str, retained: bool) -> Event {
    cut_at(fx, name, side, retained, 1).await
}

pub(super) async fn cut_at(
    fx: &Fixture,
    name: &str,
    side: &str,
    retained: bool,
    occurrence: u64,
) -> Event {
    let mut cmd = fx.command(retained);
    cut_command(fx, &mut cmd, name, side, occurrence).await
}

pub(super) async fn cut_command(
    fx: &Fixture,
    cmd: &mut Command,
    name: &str,
    side: &str,
    occurrence: u64,
) -> Event {
    let rendezvous = Rendezvous::arm(cmd, &fx.scratch.0, name, side, occurrence);
    let mut process = Process::spawn(cmd);
    let (event, _stream) = match rendezvous.reached(&mut process).await {
        Ok(v) => v,
        Err(e) => {
            let out = process.kill().await;
            panic!(
                "{e}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    };
    let out = process.kill().await;
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&out.status),
        Some(9),
        "SIGKILL stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        name == "output-write" && side == "after" || out.stdout.is_empty(),
        "premature result stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if name == "output-write" && side == "after" {
        let json = String::from_utf8(out.stdout).unwrap();
        if let Some(record) = fx.record() {
            assert_landed_report(&json, &record);
        } else {
            let archives = fx.archives();
            assert_eq!(archives.len(), 1);
            assert_abandoned_report(&json, &archives[0].2);
        }
    }
    event
}

pub(super) async fn fail(fx: &Fixture, name: &str, retained: bool) {
    let mut cmd = fx.command(retained);
    let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, name, "before", 1);
    let mut process = Process::spawn(&mut cmd);
    let (_, mut stream) = rendezvous.reached(&mut process).await.unwrap();
    let before = fx.transcript();
    stream.write_all(b"fail\n").await.unwrap();
    let out = process.output().await;
    let json = assert_exit(&out, 1);
    assert!(!json.contains("\"outcome\":\"landed\""));
    assert_eq!(
        fx.transcript(),
        before,
        "network continued after failed barrier"
    );
}

pub(super) fn observe(test: &str, observed: &[String]) {
    if let Some(dir) = std::env::var_os("GRANARY_RESTART_REPORT_DIR") {
        let run =
            std::env::var("GRANARY_RESTART_RUN").expect("fresh coverage run identity required");
        let binary = std::env::current_exe().unwrap();
        assert!(
            binary
                .file_name()
                .unwrap()
                .as_encoded_bytes()
                .starts_with(b"publish_restart-")
        );
        let mut report = format!("TEST {test}\nRUN {run}\nBINARY publish_restart\n");
        for identity in observed {
            use std::fmt::Write as _;
            writeln!(&mut report, "CUT {identity}").unwrap();
        }
        std::fs::write(Path::new(&dir).join(test), report).unwrap();
    }
}

pub(super) fn request(
    method: &str,
    path: &str,
    body: Vec<u8>,
    status: u16,
    response: Vec<u8>,
) -> Exchange {
    Exchange {
        method: method.into(),
        path: path.into(),
        body,
        status,
        response,
        epoch: None,
        operation: None,
    }
}
pub(super) fn probe(bytes: Option<Vec<u8>>) -> Exchange {
    let status = if bytes.is_some() { 200 } else { 404 };
    request(
        "GET",
        ROOT_PATH,
        Vec::new(),
        status,
        bytes.unwrap_or_default(),
    )
}
pub(super) fn live_barrier(
    probes: impl IntoIterator<Item = Exchange>,
    head: Option<u64>,
) -> Vec<Exchange> {
    let mut expected: Vec<_> = probes.into_iter().collect();
    // Complete live classification reads the current head after probing retained slots.
    let (status, response) = head.map_or((404, Vec::new()), |seq| {
        (200, format!("{seq:020}").into_bytes())
    });
    expected.push(request(
        "GET",
        "/volume/alpha/max-seq",
        Vec::new(),
        status,
        response,
    ));
    expected
}
pub(super) fn post(record: &Submission) -> Exchange {
    let c = record
        .candidates
        .iter()
        .find(|c| c.role == Role::Active)
        .unwrap();
    let response = answer::encode(PublishAnswer::Landed {
        receipt: Receipt {
            position: Position {
                epoch: Epoch::from_bytes(c.request.epoch),
                entry_seq: 1,
            },
            root_seq: c.seq,
            stored_id: c.id,
        },
        head: Some(Head::new(Some((c.seq, c.id)))),
    })
    .unwrap();
    let mut e = request(
        "POST",
        "/volume/alpha/publish",
        c.root.clone(),
        200,
        response,
    );
    e.epoch = Some(hex(&c.request.epoch));
    e.operation = Some(hex(&c.request.operation));
    e
}
pub(super) fn hint() -> Exchange {
    request(
        "PUT",
        "/volume/alpha/hint",
        b"00000000000000000001".to_vec(),
        204,
        Vec::new(),
    )
}
pub(super) fn assert_identity(old: &Submission, new: &Submission) {
    assert_eq!(old.scope, new.scope);
    assert_eq!(old.volume, new.volume);
    assert_eq!(old.publication_id, new.publication_id);
    assert_eq!(
        old.frozen, new.frozen,
        "frozen intent changed across restart"
    );
}
pub(super) fn assert_catalogue(old: &Submission, new: &Submission) {
    assert_identity(old, new);
    assert_eq!(old.current, new.current);
    assert_eq!(
        old.candidates, new.candidates,
        "catalogue changed without a semantic save"
    );
    assert_eq!(old.last_response, new.last_response);
}

pub(super) fn with_retired_slot(mut record: Submission) -> Submission {
    let mut retired = record.candidates[0].clone();
    retired.number = 2;
    retired.role = Role::Retired;
    retired.request.epoch = [0x22; 16];
    // An operation belongs to exactly one epoch, including retained history.
    retired.request.operation[0] ^= 1;
    retired.evidence = retained::Evidence {
        started: 1,
        ..retained::Evidence::default()
    };
    let mut doc = granary_core::root::decode_root(&retired.root).unwrap();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(b"absent parent"));
    let key = seed_key();
    doc.sigs.clear();
    doc.sigs.push(granary_core::root::RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    retired.root = granary_core::root::encode_root(&doc).unwrap();
    retired.seq = 2;
    retired.id = GrainId::of(&retired.root);
    record.candidates.push(retired);
    retained::validate(&record).unwrap();
    record
}

pub(super) fn assert_prepare(fx: &Fixture, record: &Submission) {
    let root = granary_core::root::decode_root(&record.frozen.initial_root).unwrap();
    assert_preparation_objects(fx, root.binmap_index, root.sheaf_head);
}

pub(super) fn assert_unretained_prepare(fx: &Fixture) {
    // Before installation there is no canonical root to decode. The immutable
    // peer objects independently supply the index/table graph and one sheaf.
    let s = fx.peer.lock().unwrap();
    let indexes: Vec<_> = s
        .objects
        .values()
        .filter(|b| granary_core::binmap::decode_binmap_index(b).is_ok())
        .collect();
    let sheaves: Vec<_> = s
        .objects
        .values()
        .filter(|b| granary_core::sheaf::decode_sheaf(b).is_ok())
        .collect();
    assert_eq!(indexes.len(), 1);
    assert_eq!(sheaves.len(), 1);
    let index = GrainId::of(indexes[0]);
    let sheaf = GrainId::of(sheaves[0]);
    drop(s);
    assert_preparation_objects(fx, index, sheaf);
}

fn assert_preparation_objects(fx: &Fixture, binmap_index: GrainId, sheaf_head: GrainId) {
    let s = fx.peer.lock().unwrap();
    let expected = preparation_transcript(&s, binmap_index, sheaf_head, &BTreeSet::new());
    assert_eq!(
        s.transcript, expected,
        "complete preparation transcript (no POST before begin)"
    );
    assert!(s.roots.is_empty(), "root occupied before durable begin");
}

pub(super) fn preparation_transcript(
    s: &PeerState,
    binmap_index: GrainId,
    sheaf_head: GrainId,
    previously_uploaded: &BTreeSet<String>,
) -> Vec<Exchange> {
    let meta = |id: GrainId| format!("/volume/alpha/meta/{id}");
    let index = granary_core::binmap::decode_binmap_index(&s.objects[&meta(binmap_index)]).unwrap();
    let bins = granary_core::binmap::decode_bin_table(&s.objects[&meta(index.bin_table)]).unwrap();
    let status = answer::encode_status(VolumeStatus {
        epoch: Epoch::from_bytes(EPOCH),
        head: Some(Head::new(None)),
        open: None,
    })
    .unwrap();
    let mut expected = vec![
        request(
            "GET",
            "/volume/alpha/status",
            Vec::new(),
            200,
            status.clone(),
        ),
        request("GET", "/volume/alpha/status", Vec::new(), 200, status),
        request("GET", "/volume/alpha/max-seq", Vec::new(), 404, Vec::new()),
    ];
    for digest in bins {
        let path = format!("/bin/{}", hex(&digest));
        let bytes = s.objects[&path].clone();
        assert_eq!(*GrainId::of(&bytes).digest(), digest);
        let status = if previously_uploaded.contains(&path) {
            200
        } else {
            201
        };
        expected.push(request("PUT", &path, bytes, status, Vec::new()));
    }
    for id in index
        .shards
        .into_iter()
        .chain([index.bin_table, binmap_index, sheaf_head])
    {
        let bytes = s.objects[&meta(id)].clone();
        assert_eq!(GrainId::of(&bytes), id);
        let path = meta(id);
        let status = if previously_uploaded.contains(&path) {
            200
        } else {
            201
        };
        expected.push(request("PUT", &path, bytes, status, Vec::new()));
    }
    expected
}
pub(super) async fn ready(fx: &Fixture) -> Submission {
    let event = cut(fx, "begin", "after", false).await;
    let record = fx.record().unwrap();
    assert_eq!(event.id, hex(&record.publication_id));
    assert_eq!(
        record.phase,
        granary_core::retained_submission::Phase::Ready
    );
    assert_prepare(fx, &record);
    fx.reset_transcript();
    record
}
pub(super) fn assert_landed_report(json: &str, record: &Submission) {
    assert_eq!(json.lines().count(), 1, "{json}");
    assert!(
        json.contains(&format!(
            "\"publication_id\":\"{}\"",
            hex(&record.publication_id)
        )),
        "{json}"
    );
    assert!(json.contains("\"outcome\":\"landed\""), "{json}");
    assert!(
        json.contains(&format!(
            "\"completion\":{{\"seq\":{},\"id\":\"{}\"",
            record.candidates[0].seq, record.candidates[0].id
        )),
        "JSON names a different winner: {json}"
    );
}

pub(super) fn assert_abandoned_report(json: &str, record: &Submission) {
    assert_eq!(json.lines().count(), 1, "{json}");
    assert!(
        json.contains("\"outcome\":\"abandoned\"")
            && json.contains("\"route\":\"local\"")
            && json.contains("\"retention\":\"archive\"")
            && json.contains("\"uncertain\":true"),
        "{json}"
    );
    assert!(
        json.contains(&format!(
            "\"publication_id\":\"{}\"",
            hex(&record.publication_id)
        )),
        "{json}"
    );
    assert!(json.contains("\"completion\":null"), "{json}");
}

pub(super) async fn fresh_landed(fx: &Fixture) {
    let previously_uploaded = fx.peer.lock().unwrap().objects.keys().cloned().collect();
    fx.reset_transcript();
    let json = run(&mut fx.command(false), 0).await;
    let record = fx.record().unwrap();
    assert_landed_report(&json, &record);
    let granary_core::retained_submission::Phase::Complete(done) = &record.phase else {
        panic!("not complete: {:?}", record.phase);
    };
    assert_eq!(record.candidates.len(), 1);
    assert_eq!(done.root, record.frozen.initial_root);
    assert_eq!(done.id, GrainId::of(&done.root));
    let root = granary_core::root::decode_root(&record.frozen.initial_root).unwrap();
    let s = fx.peer.lock().unwrap();
    let mut expected =
        preparation_transcript(&s, root.binmap_index, root.sheaf_head, &previously_uploaded);
    expected.extend(live_barrier([probe(None)], None));
    expected.extend([post(&record), hint()]);
    assert_eq!(
        s.transcript, expected,
        "complete unretained restart transcript"
    );
    assert_eq!(s.roots.len(), 1, "unintended successor root");
    assert_eq!(s.roots[ROOT_PATH], done.root);
    assert_eq!(s.landings, 1, "logical publication landed more than once");
}

pub(super) async fn landed(fx: &Fixture, before: &Submission, sends: bool) {
    let json = run(&mut fx.command(true), 0).await;
    assert_landed_report(&json, before);
    let after = fx.record().unwrap();
    assert_identity(before, &after);
    let granary_core::retained_submission::Phase::Complete(done) = &after.phase else {
        panic!("not complete: {:?}", after.phase);
    };
    assert_eq!(done.root, before.candidates[0].root);
    assert_eq!(done.id, before.candidates[0].id);
    let probe = probe(if sends { None } else { Some(done.root.clone()) });
    let mut expected = live_barrier([probe], (!sends).then_some(done.seq));
    if sends {
        expected.push(post(before));
    }
    expected.push(hint());
    assert_eq!(fx.transcript(), expected, "complete restart transcript");
    let s = fx.peer.lock().unwrap();
    assert_eq!(s.roots.len(), 1, "unintended successor root");
    assert_eq!(
        s.roots[ROOT_PATH], done.root,
        "backend winner differs from completion"
    );
    assert_eq!(s.landings, 1, "logical publication landed more than once");
}

#[cfg(test)]
mod rendezvous_tests {
    use super::*;

    fn waiting_child() -> Process {
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear().args([
            "-c",
            "printf 'fixture stdout'; printf 'fixture stderr' >&2; exec sleep 30",
        ]);
        Process::spawn(&mut cmd)
    }

    #[tokio::test]
    async fn abandonment_rendezvous_never_arriving_names_missing_side_and_cut() {
        for connected in [false, true] {
            let mut child = waiting_child();
            let (_sender, receiver) = tokio::io::duplex(1024);
            let connect = async {
                if !connected {
                    std::future::pending::<()>().await;
                }
                Ok(receiver)
            };
            let start = tokio::time::Instant::now();
            let idle = Duration::from_secs(1);
            let total = Duration::from_secs(5);
            let error =
                receive_rendezvous(&mut child, ("begin", "after", 1), (idle, total), connect)
                    .await
                    .unwrap_err();
            assert!(start.elapsed() >= idle);
            assert!(start.elapsed() < total + Duration::from_secs(1));
            let missing = if connected {
                "child REACHED report"
            } else {
                "child connection"
            };
            for expected in [
                "rendezvous bound exceeded (idle",
                missing,
                "cut=begin side=after occurrence=1",
                "fixture stdout",
                "fixture stderr",
            ] {
                assert!(error.contains(expected), "{error}");
            }
            assert!(!child.kill().await.status.success());
        }

        let mut cases = 0;
        for sent in [true, false] {
            let (mut sender, receiver) = tokio::io::duplex(1024);
            if sent {
                sender
                    .write_all(b"REACHED begin after 1 33333333333333333333333333333333 ready 1\n")
                    .await
                    .unwrap();
            }
            let mut cmd = Command::new("/bin/sh");
            cmd.env_clear().args(["-c", "exit 0"]);
            let mut child = Process::spawn(&mut cmd);
            let status = child.wait_for_exit(WAIT).await.unwrap();
            tokio::time::pause();
            let result = receive_rendezvous(
                &mut child,
                ("begin", "after", 1),
                (Duration::from_secs(1), Duration::from_secs(5)),
                async {
                    tokio::time::sleep(Duration::from_millis(15)).await;
                    Ok(receiver)
                },
            )
            .await;
            tokio::time::resume();
            if sent {
                assert_eq!(
                    (status.code(), result.map(|(event, _)| event.id)),
                    (Some(0), Ok("33333333333333333333333333333333".to_owned()))
                );
                println!("OBSERVED buffered socket report after clean child exit");
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    (
                        status.code(),
                        error.starts_with("child exit before rendezvous")
                    ),
                    (Some(0), true),
                    "{error}"
                );
                println!("REFUSED {error}");
            }
            cases += 1;
        }
        assert_eq!(cases, 2);
        observe(
            "support::rendezvous_tests::abandonment_rendezvous_never_arriving_names_missing_side_and_cut",
            &[],
        );
    }

    #[cfg(feature = "crash-points")]
    #[tokio::test]
    async fn abandonment_rendezvous_assert_or_kill_preserves_captured_diagnostic() {
        let mut child = waiting_child();
        let error = receive_rendezvous(
            &mut child,
            ("begin", "after", 1),
            (Duration::from_secs(1), Duration::from_secs(5)),
            std::future::pending::<Result<tokio::io::DuplexStream, String>>(),
        )
        .await
        .unwrap_err();
        assert!(child.child.is_none(), "failed rendezvous must reap child");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            child.assert_or_kill(false, &error);
        }))
        .unwrap_err();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap();
        for expected in [
            error.as_str(),
            "missing child connection (parent listener armed)",
            "cut=begin side=after occurrence=1",
            "stdout: fixture stdout",
            "stderr: fixture stderr",
        ] {
            assert!(message.contains(expected), "{message}");
        }
        assert!(!child.kill().await.status.success());
        observe(
            "support::rendezvous_tests::abandonment_rendezvous_assert_or_kill_preserves_captured_diagnostic",
            &[],
        );
    }

    #[tokio::test]
    async fn abandonment_rendezvous_slow_progress_passes() {
        let mut child = waiting_child();
        let (mut stream, receiver) = tokio::io::duplex(1024);
        let sender = tokio::spawn(async move {
            let report = b"REACHED begin after 1 33333333333333333333333333333333 ready 1\n";
            for part in report.chunks(3) {
                tokio::time::sleep(Duration::from_millis(100)).await;
                stream.write_all(part).await.unwrap();
            }
            stream
        });
        let idle = Duration::from_secs(1);
        let start = tokio::time::Instant::now();
        let (event, _stream) = receive_rendezvous(
            &mut child,
            ("begin", "after", 1),
            (idle, Duration::from_secs(10)),
            async { Ok(receiver) },
        )
        .await
        .unwrap();
        assert!(start.elapsed() > idle * 2);
        event.matches("begin", "after", 1).unwrap();
        let _sender_stream = sender.await.unwrap();
        child.kill().await;
        observe(
            "support::rendezvous_tests::abandonment_rendezvous_slow_progress_passes",
            &[],
        );
    }

    #[tokio::test]
    async fn abandonment_rendezvous_continuous_progress_still_hits_absolute_cap() {
        let mut child = waiting_child();
        let (mut stream, receiver) = tokio::io::duplex(1024);
        let sender = tokio::spawn(async move {
            loop {
                if stream.write_all(b"x").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let start = tokio::time::Instant::now();
        let total = Duration::from_secs(3);
        let error = receive_rendezvous(
            &mut child,
            ("begin", "after", 1),
            (Duration::from_secs(1), total),
            async { Ok(receiver) },
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("rendezvous bound exceeded (absolute"),
            "{error}"
        );
        assert!(error.contains("missing child REACHED report"), "{error}");
        assert!(start.elapsed() >= total);
        assert!(start.elapsed() < total + Duration::from_secs(1));
        sender.await.unwrap();
        child.kill().await;
        observe(
            "support::rendezvous_tests::abandonment_rendezvous_continuous_progress_still_hits_absolute_cap",
            &[],
        );
    }
}
