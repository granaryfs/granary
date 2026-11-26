// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real TLS admission, authority lifecycle and persistent backend composition.
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::future::Future as _;
use std::io::Write as _;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use granary_core::authlog::{self, Classified, RecordBody};
use granary_core::clock::Clock;
use granary_core::enrollment::{ClientSpkiDigest, TenantName};
use granary_core::rng::ProcessRng;
use granary_core::root::VolumeName;
use granary_core::rootstore::RootStore;
use granary_core::runmarker::BootId;
use granary_core::sheaf::Timestamp;
use granary_net::secure_random::OsSecureRandom;
use granary_server::{
    AuthorityParts, EnrollmentReader, FileLog, GrainService, Pause, PrincipalControls, VerbOptions,
    VolumeConfig, config, mint, run_authority_host,
};
use granary_store::backend::GranaryStore;
use granary_store::crypto::TrustedKeys;
use http_body_util::BodyExt as _;
use hyper::service::Service as _;
use object_store::aws::AmazonS3Builder;
use rcgen::PublicKeyData as _;
use rustls_pki_types::pem::PemObject as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

use super::backend::Proxy;
use super::support::HOST_DRAIN;
use super::support::{
    Fixture, Process, Rendezvous, SEED, Scratch, WAIT, base_url, hex, seed_public, wait_report,
};
use super::tails::{diagnostics, interrupted, stages};

const REPLY_DEADLINE: Duration = Duration::from_millis(250);
// Give loaded MinIO writes room to finish while keeping dispatch within half of WAIT.
const NORMAL_DISPATCH: Duration = Duration::from_secs(5);
const _: () = assert!(NORMAL_DISPATCH.as_millis() * 2 <= WAIT.as_millis());
const MINIO_START_ATTEMPTS: u32 = 3;

pub(super) struct WallClock;
impl Clock for WallClock {
    fn now(&self) -> Timestamp {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        Timestamp {
            secs: i64::try_from(d.as_secs()).unwrap(),
            nanos: d.subsec_nanos(),
        }
    }
}
struct TimerPause;
impl Pause for TimerPause {
    async fn pause(&self, duration: Duration) {
        sleep(duration).await;
    }
}

pub(super) fn backend(endpoint: &str) -> Arc<dyn object_store::ObjectStore> {
    Arc::new(
        AmazonS3Builder::new()
            .with_endpoint(endpoint)
            .with_allow_http(true)
            .with_http_connector(granary_store::http_client::NoRedirectConnector)
            .with_bucket_name("granary-test")
            .with_region("us-east-1")
            .with_access_key_id("granary-test")
            .with_secret_access_key("granary-test-secret")
            .build()
            .unwrap(),
    )
}

/// The listening socket must belong to the spawned process.
pub(super) fn owns_listener(pid: u32, port: u16) -> std::io::Result<bool> {
    let sockets = std::fs::read_to_string("/proc/net/tcp")?;
    let inodes: Vec<_> = sockets
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (_, encoded_port) = fields.get(1)?.rsplit_once(':')?;
            (fields.get(3) == Some(&"0A")
                && u16::from_str_radix(encoded_port, 16).ok() == Some(port))
            .then(|| fields.get(9).copied())
            .flatten()
        })
        .collect();
    for file in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        if let Ok(link) = std::fs::read_link(file?.path())
            && inodes
                .iter()
                .any(|inode| link.as_os_str() == std::ffi::OsStr::new(&format!("socket:[{inode}]")))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn ready_address(path: &Path) -> std::net::SocketAddr {
    loop {
        if let Ok(address) = std::fs::read_to_string(path)
            && let Ok(address) = address.trim().parse()
        {
            return address;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

fn bind_host_socket(address: SocketAddr, reuse_addr: bool) -> std::io::Result<TcpSocket> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseport(true)?;
    socket.set_reuseaddr(reuse_addr)?;
    socket.bind(address)?;
    Ok(socket)
}

pub(super) fn host_listener(address: SocketAddr) -> std::io::Result<TcpListener> {
    // SO_REUSEADDR lets a new listener bind over the previous host's TIME_WAIT sockets.
    bind_host_socket(address, true)?.listen(1024)
}

#[cfg(target_os = "linux")]
async fn host_reservation_controls() {
    let reservation = bind_host_socket(([127, 0, 0, 1], 0).into(), false).unwrap();
    let address = reservation.local_addr().unwrap();
    let mut cases = 0;
    for _ in 0..2 {
        let foreign = TcpSocket::new_v4().unwrap();
        foreign.set_reuseaddr(true).unwrap();
        let bind = foreign.bind(address).unwrap_err();
        let connect = timeout(WAIT, TcpStream::connect(address))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (bind.kind(), connect.kind()),
            (
                std::io::ErrorKind::AddrInUse,
                std::io::ErrorKind::ConnectionRefused
            ),
            "reserved address {address}: bind={bind}, connect={connect}"
        );
        println!("REFUSED foreign bind and connection without host: {bind}, {connect}");

        let listener = host_listener(address).unwrap();
        // The kernel completes the handshake into the backlog, so connect
        // returns before accept runs.
        let (client, (_, peer)) = timeout(WAIT, async {
            let client = TcpStream::connect(address).await?;
            Ok::<_, std::io::Error>((client, listener.accept().await?))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (listener.local_addr().unwrap(), peer),
            (address, client.local_addr().unwrap()),
            "the listening socket accepts connections on each bind"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

async fn ready_file_controls() {
    let scratch = Scratch::new();
    let path = scratch.0.join("ready");
    for partial in ["", "127.0.", "127.0.0.1:", "not an address"] {
        std::fs::write(&path, partial).unwrap();
        let mut reading = std::pin::pin!(ready_address(&path));
        let observed = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || reading.as_mut().poll(cx),
            )))
        })
        .await;
        assert!(
            matches!(observed, Ok(std::task::Poll::Pending)),
            "partial ready-file contents must remain pending: {partial:?}, got {observed:?}"
        );
        std::fs::write(&path, "127.0.0.1:12345\n").unwrap();
        assert_eq!(
            timeout(WAIT, reading).await.unwrap(),
            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap()
        );
    }
}

struct Minio {
    child: Child,
    endpoint: String,
}

fn retry_minio_start(exited: bool, log: &str, attempt: u32) -> bool {
    exited && log.contains("port is already in use") && (1..MINIO_START_ATTEMPTS).contains(&attempt)
}

fn minio_retry_controls() {
    let collision = "FATAL Unable to start the server: Specified port is already in use";
    assert_eq!(
        (
            MINIO_START_ATTEMPTS,
            retry_minio_start(true, collision, 1),
            retry_minio_start(true, collision, 2),
            retry_minio_start(true, collision, 3),
            retry_minio_start(true, collision, 4),
            retry_minio_start(false, collision, 1),
            retry_minio_start(true, "FATAL permission denied", 1),
            retry_minio_start(true, "", 1),
        ),
        (3, true, true, false, false, false, false, false),
        "only an exited port collision may retry, within three startup attempts"
    );
}

impl Minio {
    async fn new(dir: &Path) -> Self {
        std::fs::create_dir_all(dir.join("granary-test")).unwrap();
        let minio_home = dir.with_file_name("minio-home");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&minio_home)
            .unwrap();
        let binary =
            std::env::var_os("GRANARY_COMPOSITION_MINIO").expect("verified MinIO path required");
        let mut attempt = 1;
        loop {
            let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = reservation.local_addr().unwrap();
            drop(reservation);
            let log = std::fs::File::create(dir.join("process.log")).unwrap();
            let child = Command::new(&binary)
                .env_clear()
                .env("HOME", &minio_home)
                .env("MINIO_ROOT_USER", "granary-test")
                .env("MINIO_ROOT_PASSWORD", "granary-test-secret")
                .args([
                    "server",
                    "--quiet",
                    "--address",
                    &address.to_string(),
                    "--console-address",
                    "127.0.0.1:0",
                ])
                .arg(dir)
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap();
            let mut minio = Self {
                child,
                endpoint: format!("http://{address}"),
            };
            let failure = timeout(WAIT, async {
            loop {
                if let Some(status) = minio.child.try_wait().unwrap() {
                    break Some((status, std::fs::read_to_string(dir.join("process.log")).unwrap()));
                }
                if let Ok(mut stream) = TcpStream::connect(address).await {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    stream.write_all(b"GET /minio/health/ready HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n").await.unwrap();
                    let mut response = Vec::new();
                    if timeout(Duration::from_millis(100), stream.read_to_end(&mut response)).await.is_ok()
                        && response.starts_with(b"HTTP/1.1 200")
                        && owns_listener(minio.child.id(), address.port()).unwrap() {
                        assert!(!owns_listener(std::process::id(), address.port()).unwrap(), "a foreign process cannot supply MinIO readiness");
                        break None;
                    }
                }
                sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("MinIO never became ready");
            let Some((status, log)) = failure else {
                return minio;
            };
            assert!(
                retry_minio_start(true, &log, attempt),
                "MinIO startup failed on attempt {attempt}: {status}\n{log}"
            );
            attempt += 1;
        }
    }
}
impl Drop for Minio {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) fn shipping_server() -> PathBuf {
    let binary = PathBuf::from(
        std::env::var_os("GRANARY_SHIPPING_SERVER")
            .expect("explicit shipping server path required"),
    );
    assert!(
        binary.is_absolute()
            && binary.is_file()
            && binary.file_name().is_some_and(|s| s == "granary-server"),
        "invalid shipping server path: {}",
        binary.display()
    );
    binary
}

pub(super) struct Composition {
    pub(super) client: Fixture,
    pub(super) addr: SocketAddr,
    pub(super) proxy: Proxy,
    pub(super) state: PathBuf,
    pub(super) host: Option<Process>,
    minio: Minio,
    pub(super) command: Command,
    // A bound TCP socket holds the port without joining the listener group.
    // Keep SO_REUSEADDR off here so only cooperating SO_REUSEPORT binds can share it.
    _reservation: TcpSocket,
}
impl Drop for Composition {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "authority host log:\n{}",
                std::fs::read_to_string(self.client.scratch.0.join("host.log")).unwrap_or_default()
            );
        }
    }
}
impl Composition {
    pub(super) fn minio_endpoint(&self) -> &str {
        &self.minio.endpoint
    }

    pub(super) async fn new(hold: bool) -> Self {
        let (plan, reply_deadline) = if hold {
            ("HostReply:1:hold", Some(REPLY_DEADLINE))
        } else {
            ("HostReply:4294967295:hold", None)
        };
        Self::with_setup(plan, reply_deadline, |_| async {}).await.0
    }

    /// Provision operator-owned state before the first host can initialise it.
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture establishes real admission, isolated persistent backend and the host boundary"
    )]
    pub(super) async fn with_setup<T, F: Future<Output = T>>(
        plan: &str,
        reply_deadline: Option<Duration>,
        setup: impl FnOnce(PathBuf) -> F,
    ) -> (Self, T) {
        // Refuse unsupported/unreadable storage before creating any authority state.
        let scratch = Scratch::new();
        let state = scratch.0.join("authority");
        let enrollment = scratch.0.join("enrollment");
        let private = scratch.0.join("private");
        for path in [&state, &enrollment, &private] {
            std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).unwrap();
        let issuer = rcgen::Issuer::from_params(&params, &key);
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&client_key, &issuer).unwrap();
        for (name, bytes) in [
            ("ca.pem", ca.pem().into_bytes()),
            ("server.pem", server.pem().into_bytes()),
            ("server.key", server_key.serialize_pem().into_bytes()),
            ("client.pem", cert.pem().into_bytes()),
            ("client.key", client_key.serialize_pem().into_bytes()),
            ("seed", SEED.to_vec()),
            ("seed.pub", seed_public().to_vec()),
        ] {
            let path = private.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        for name in ["client2", "foreign"] {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::default();
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let cert = params.signed_by(&key, &issuer).unwrap();
            for (extension, bytes) in [
                ("pem", cert.pem().into_bytes()),
                ("key", key.serialize_pem().into_bytes()),
            ] {
                let path = private.join(format!("{name}.{extension}"));
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        mint(
            &enrollment,
            VerbOptions {
                accept_unsupported_filesystem: false,
            },
            &TenantName::parse("test").unwrap(),
            ClientSpkiDigest::from_spki_der(&client_key.subject_public_key_info()),
            &mut OsSecureRandom::new(),
        )
        .unwrap();
        let minio = Minio::new(&scratch.0.join("backend")).await;
        let upstream = minio.endpoint.strip_prefix("http://").unwrap().to_owned();
        let proxy = Proxy::new(upstream).await;
        let pin = granary_net::config::render_tls_pin(
            &granary_net::pin::spki_digest(server.der()).unwrap(),
        );
        let reservation = bind_host_socket(([127, 0, 0, 1], 0).into(), false).unwrap();
        let address = reservation.local_addr().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .args(["--exact", "composition::host_child", "--nocapture"])
            .env("GRANARY_COMPOSITION_CHILD", &scratch.0)
            .env("GRANARY_COMPOSITION_LISTEN", address.to_string())
            .env(
                "GRANARY_COMPOSITION_DISPATCH_MS",
                NORMAL_DISPATCH.as_millis().to_string(),
            )
            .env("GRANARY_STORE", "s3:")
            .env("GRANARY_STORE_ENDPOINT", &proxy.endpoint)
            .env("GRANARY_STORE_BUCKET", "granary-test")
            .env("GRANARY_STORE_REGION", "us-east-1")
            .env("AWS_ACCESS_KEY_ID", "granary-test")
            .env("AWS_SECRET_ACCESS_KEY", "granary-test-secret")
            .env("GRANARY_AUTHORITY", "single-process")
            .env("GRANARY_AUTHORITY_STATE_DIR", &state)
            .env("GRANARY_AUTHORITY_ENROLLMENT_DIR", &enrollment)
            .env("GRANARY_AUTHORITY_CLIENT_CA", private.join("ca.pem"))
            .env("GRANARY_AUTHORITY_VOLUMES", "alpha")
            .env(
                "GRANARY_AUTHORITY_VOLUME_ALPHA_PUBLISHER_KEYS",
                format!("ed25519:{}", hex(&seed_public())),
            )
            .env("GRANARY_TEST_HOST_REACHED", scratch.0.join("notes"))
            .env("GRANARY_TEST_HOST_RELEASE", scratch.0.join("release"))
            .env("GRANARY_TEST_HOST_PLAN", plan);
        if let Some(deadline) = reply_deadline {
            command.env(
                "GRANARY_COMPOSITION_REPLY_MS",
                deadline.as_millis().to_string(),
            );
        }
        let configured = setup(state.clone()).await;
        let host = Process::spawn_logged(&mut command, &scratch.0.join("host.log"));
        let mut fixture = Self {
            client: Fixture::client(scratch, base_url(address), pin),
            addr: address,
            proxy,
            state,
            host: Some(host),
            minio,
            command,
            _reservation: reservation,
        };
        fixture.ready().await;
        (fixture, configured)
    }
    pub(super) fn notes(&self) -> String {
        std::fs::read_to_string(self.client.scratch.0.join("notes")).unwrap_or_default()
    }
    pub(super) fn responses(&self) -> String {
        std::fs::read_to_string(self.client.scratch.0.join("responses")).unwrap_or_default()
    }
    pub(super) async fn append_fault_reached(
        &mut self,
        ordinal: u32,
        client: Option<&mut Process>,
    ) {
        let host = self.host.as_mut().unwrap();
        let result = append_fault_report(host, client, &self.client.scratch.0, ordinal, WAIT).await;
        if let Err(error) = result {
            host.assert_or_kill(
                false,
                &format!("append fault was not reached: ordinal {ordinal}: {error}"),
            );
        }
    }
    pub(super) fn release_reply(&self) {
        std::fs::write(self.client.scratch.0.join("release"), b"release").unwrap();
    }
    pub(super) fn records(&self) -> Vec<authlog::Record> {
        match authlog::classify(
            &std::fs::read(self.state.join("alpha.log")).unwrap(),
            &VolumeName::new("alpha".into()).unwrap(),
        )
        .unwrap()
        {
            Classified::Log {
                records,
                tail_len: 0,
                ..
            } => records,
            other => panic!("not a complete real log: {other:?}"),
        }
    }
    pub(super) async fn roots(&self) -> Vec<(u64, Vec<u8>)> {
        let store = GranaryStore::new(backend(&self.minio.endpoint));
        let mut roots = Vec::new();
        let objects = backend(&self.minio.endpoint);
        let prefix = object_store::path::Path::from("root/alpha");
        let mut listed = objects.list(Some(&prefix));
        while let Some(object) = std::future::poll_fn(|cx| listed.as_mut().poll_next(cx)).await {
            let object = object.unwrap();
            let name = object.location.as_ref().rsplit('/').next().unwrap();
            if name == "CURRENT" {
                continue;
            }
            let seq = name.parse::<u64>().unwrap();
            roots.push((seq, store.get_root("alpha", seq).await.unwrap().unwrap()));
        }
        roots
    }
    pub(super) async fn preparation_requests(&self, initial_root: &[u8]) -> Vec<String> {
        let root = granary_core::root::decode_root(initial_root).unwrap();
        let store = GranaryStore::new(backend(&self.minio.endpoint));
        let index = granary_core::binmap::decode_binmap_index(
            &store.get_meta("alpha", &root.binmap_index).await.unwrap(),
        )
        .unwrap();
        let bins = granary_core::binmap::decode_bin_table(
            &store.get_meta("alpha", &index.bin_table).await.unwrap(),
        )
        .unwrap();
        let mut requests = vec![
            "GET /volume/alpha/status".into(),
            "GET /volume/alpha/status".into(),
            "GET /volume/alpha/max-seq".into(),
        ];
        requests.extend(
            bins.iter()
                .map(|digest| format!("PUT /bin/{}", hex(digest))),
        );
        requests.extend(
            index
                .shards
                .into_iter()
                .chain([index.bin_table, root.binmap_index, root.sheaf_head])
                .map(|id| format!("PUT /volume/alpha/meta/{id}")),
        );
        requests
    }
    pub(super) async fn land(
        &self,
        record: &granary_core::retained_submission::Submission,
    ) -> Result<(), String> {
        let candidate = &record.candidates[0];
        let capture = self.proxy.captured().await;
        if (&capture.volume, capture.seq, capture.id, capture.occurrence)
            != (&"alpha".to_owned(), candidate.seq, candidate.id, 1)
        {
            return Err(format!("wrong captured PUT: {capture:?}"));
        }
        if !self.records().iter().any(|r| matches!(r.body(), RecordBody::Attestation { final_root, .. } if final_root.as_bytes() == candidate.root)) {
            return Err("PUT precedes its committed attestation".into());
        }
        let release = self.proxy.release(&capture).await;
        let roots = self.roots().await;
        let drained = (self.proxy.finished().len(), self.proxy.pending());
        if release != Ok(200)
            || roots != [(candidate.seq, candidate.root.clone())]
            || drained != (1, 0)
        {
            return Err(format!(
                "landing/release not exact: {release:?}, {roots:?}, {drained:?}"
            ));
        }
        Ok(())
    }
    pub(super) async fn shutdown(mut self) {
        self.stop().await;
    }
    pub(super) fn signal_stop(&self) {
        assert!(
            Command::new("/bin/kill")
                .args(["-TERM", &self.host.as_ref().unwrap().id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
    pub(super) async fn stop(&mut self) {
        let host = self.host.take().unwrap();
        // The test child uses the production signal trigger and host clean stop.
        assert!(
            Command::new("/bin/kill")
                .args(["-TERM", &host.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let out = host.host_output().await;
        super::support::assert_exit(&out, 0);
    }
    pub(super) fn start(&mut self, reboot: bool) {
        // SO_REUSEPORT would let a second host share a live predecessor's port.
        assert!(
            self.host.is_none(),
            "previous host must be reaped before a start"
        );
        let dir = &self.client.scratch.0;
        let _ = std::fs::remove_file(dir.join("ready"));
        let _ = std::fs::remove_file(dir.join("stop-requested"));
        self.command.env(
            "GRANARY_COMPOSITION_BOOT",
            if reboot { "reboot" } else { "initial" },
        );
        self.host = Some(Process::spawn_logged(
            &mut self.command,
            &dir.join("host.log"),
        ));
    }
    pub(super) async fn ready(&mut self) {
        let path = self.client.scratch.0.join("ready");
        let reached = wait_report(self.host.as_mut().unwrap(), WAIT, async {
            Ok(ready_address(&path).await)
        })
        .await;
        self.host
            .as_mut()
            .unwrap()
            .assert_or_kill(reached.is_ok(), &format!("host readiness: {reached:?}"));
        assert_eq!(
            reached.unwrap(),
            self.addr,
            "restart must preserve the endpoint"
        );
    }
}

async fn append_fault_report(
    host: &mut Process,
    mut client: Option<&mut Process>,
    dir: &Path,
    ordinal: u32,
    bound: Duration,
) -> Result<(), String> {
    let notes_path = dir.join("notes");
    let expected = format!("REACHED HostLogAppend {ordinal}");
    let result = wait_report(host, bound, async {
        loop {
            let exited = client.as_deref_mut().and_then(Process::try_wait).is_some();
            let notes = std::fs::read_to_string(&notes_path).unwrap_or_default();
            if notes.lines().any(|line| line == expected) {
                return Ok(());
            }
            if exited {
                return Err("client exit before append fault".to_owned());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let Err(error) = result else {
        return result;
    };
    let client = client.map_or_else(
        || "no client running for this append".to_owned(),
        |client| {
            let output = client.stop_and_capture();
            format!("client status: {}\n{}", output.status, diagnostics(output))
        },
    );
    let read = |path: &Path| {
        std::fs::read_to_string(path)
            .unwrap_or_else(|error| format!("cannot read {}: {error}", path.display()))
    };
    Err(format!(
        "{error}\n{client}\nnotes:\n{}\nresponses:\n{}",
        read(&notes_path),
        read(&dir.join("responses"))
    ))
}

pub(super) async fn append_fault_controls() {
    use std::os::unix::process::ExitStatusExt as _;

    let scratch = Scratch::new();
    std::fs::write(scratch.0.join("notes"), "REACHED HostLogAppend 1\n").unwrap();
    std::fs::write(scratch.0.join("responses"), "fixture response").unwrap();
    let mut host = Command::new("/bin/sh");
    host.env_clear().args(["-c", "exec sleep 30"]);
    let mut host = Process::spawn(&mut host);
    let mut cases = 0;
    for (ordinal, exits, expected) in [
        (1, true, Ok(())),
        (2, true, Err("client exit before append fault")),
        (2, false, Err("rendezvous bound exceeded (50ms)")),
    ] {
        let script = if exits {
            "printf out; printf err >&2; exit 7"
        } else {
            "exec sleep 2"
        };
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear().args(["-c", script]);
        let mut client = Process::spawn(&mut cmd);
        if exits {
            let status = client.wait_for_exit(WAIT).await.unwrap();
            assert_eq!(status.code(), Some(7), "{status}");
        }
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        let result = append_fault_report(
            &mut host,
            Some(&mut client),
            &scratch.0,
            ordinal,
            Duration::from_millis(50),
        )
        .await;
        let elapsed = start.elapsed();
        tokio::time::resume();
        if exits {
            assert!(
                elapsed.is_zero(),
                "exited client was classified after {elapsed:?}: {result:?}"
            );
        }
        if let Err(prefix) = expected {
            let error = result.unwrap_err();
            let output = client.output().await;
            let (stdout, stderr) = if exits { ("out", "err") } else { ("", "") };
            assert!(
                error.starts_with(prefix)
                    && error.contains(&format!("client status: {}", output.status))
                    && error.contains(&format!(
                        "stdout: {stdout}\nstderr: {stderr}\nnotes:\nREACHED HostLogAppend 1"
                    ))
                    && error.contains("responses:\nfixture response"),
                "{error}"
            );
            assert_eq!(
                (
                    output.status.code(),
                    output.status.signal(),
                    output.stdout.as_slice(),
                    output.stderr.as_slice()
                ),
                (
                    exits.then_some(7),
                    (!exits).then_some(9),
                    stdout.as_bytes(),
                    stderr.as_bytes()
                ),
                "{error}"
            );
            println!("REFUSED {error}");
        } else {
            assert_eq!(result, Ok(()));
        }
        cases += 1;
    }
    assert_eq!(cases, 3);
}

async fn anonymous_request(fx: &Composition, method: &str, path: &str) -> (u16, String, Vec<u8>) {
    use rustls_pki_types::{ServerName, pem::PemObject as _};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut roots = rustls::RootCertStore::empty();
    for cert in
        rustls_pki_types::CertificateDer::pem_file_iter(fx.client.scratch.0.join("private/ca.pem"))
            .unwrap()
    {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(granary_net::crypto_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(fx.addr).await.unwrap();
    let mut stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    stream.write_all(format!("{method} {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\ncontent-length: 0\r\n\r\n").as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let status = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = bytes[end..].to_vec();
    (status, head, body)
}

pub(super) async fn anonymous_root(fx: &Composition, seq: u64) -> (u16, Vec<u8>) {
    let path = format!("/volume/alpha/root/{seq:020}");
    let (status, _, body) = anonymous_request(fx, "GET", &path).await;
    (status, body)
}

fn dispatch_deadlines(
    dispatch: Option<&OsStr>,
    reply: Option<&OsStr>,
) -> Result<(Duration, Option<Duration>), &'static str> {
    let positive_millis = |value: &str| {
        let millis = value.parse::<NonZeroU64>().ok()?;
        Some(Duration::from_millis(millis.get()))
    };
    let dispatch = dispatch
        .ok_or("GRANARY_COMPOSITION_DISPATCH_MS is required")?
        .to_str()
        .and_then(positive_millis)
        .ok_or("GRANARY_COMPOSITION_DISPATCH_MS must be positive milliseconds")?;
    let reply = reply
        .map(|value| {
            value
                .to_str()
                .and_then(positive_millis)
                .ok_or("GRANARY_COMPOSITION_REPLY_MS must be positive milliseconds")
        })
        .transpose()?;
    Ok((dispatch, reply))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "the test child composes the production host and TLS admission once"
)]
async fn host_child() -> Result<(), &'static str> {
    let Some(dir) = std::env::var_os("GRANARY_COMPOSITION_CHILD") else {
        super::support::observe("composition::host_child", &[]);
        return Ok(());
    };
    let (dispatch, reply_deadline) = dispatch_deadlines(
        std::env::var_os("GRANARY_COMPOSITION_DISPATCH_MS").as_deref(),
        std::env::var_os("GRANARY_COMPOSITION_REPLY_MS").as_deref(),
    )?;
    let dir = PathBuf::from(dir);
    let config = config::authority::authority_from_env().unwrap().unwrap();
    let configured = config::store_from_env().unwrap();
    let store = configured.store;
    let admission = configured.admission;
    granary_server::install_host_test_plan().unwrap();
    let reader = EnrollmentReader::open(&config.enrollment_dir, false).unwrap();
    let log = FileLog::new(&config.state_dir, false).unwrap();
    log.require_separate_enrollment(&reader).unwrap();
    let keys = TrustedKeys::new([seed_public()]).unwrap();
    let engine_store = GranaryStore::new(store.clone());
    let private = dir.join("private");
    let tls = granary_net::tls::server_tls_config(
        rustls_pki_types::CertificateDer::pem_file_iter(private.join("server.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        rustls_pki_types::PrivateKeyDer::from_pem_file(private.join("server.key")).unwrap(),
        granary_net::tls::ClientAuth::Enrolled {
            ca: rustls_pki_types::CertificateDer::pem_file_iter(private.join("ca.pem"))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            clock: Arc::new(WallClock),
        },
    )
    .unwrap();
    let trigger = granary_server::shutdown_trigger().unwrap();
    let exit = run_authority_host(
        BootId::from_bytes(
            if std::env::var("GRANARY_COMPOSITION_BOOT").as_deref() == Ok("reboot") {
                [0x72; 16]
            } else {
                [0x71; 16]
            },
        ),
        move |seat| async move {
            let parts = AuthorityParts {
                log,
                store: engine_store,
                admission,
                clock: WallClock,
                rng: ProcessRng::new(),
                secure_random: OsSecureRandom::new(),
                pause: TimerPause,
            };
            if let Some(driver) = seat
                .start(
                    parts,
                    vec![VolumeConfig::new(
                        VolumeName::new("alpha".into()).unwrap(),
                        keys,
                    )],
                )
                .await
            {
                let _end = driver.run().await;
            }
        },
        move |handle, mut shutdown| {
            let controls = Arc::new(PrincipalControls::new(config.controls, Arc::new(WallClock)));
            let service = GrainService::with_deadline(
                Arc::new(GranaryStore::new(store)),
                "",
                2,
                Some(dispatch),
            )
            .with_authority_writes(
                reader,
                controls,
                Arc::new(granary_server::refusals::RefusalCounters::default()),
                &config,
                handle.clone(),
            );
            let service = if let Some(deadline) = reply_deadline {
                service.with_test_reply_deadline(deadline)
            } else {
                service
            };
            let draining = service.draining();
            Ok::<_, std::io::Error>(async move {
                if !config.state_dir.join("alpha.log").exists() {
                    handle
                        .initialise(&VolumeName::new("alpha".into()).unwrap())
                        .await
                        .unwrap();
                }
                let address = std::env::var("GRANARY_COMPOSITION_LISTEN")
                    .unwrap()
                    .parse()
                    .unwrap();
                let listener = host_listener(address)?;
                std::fs::write(
                    dir.join("ready"),
                    listener.local_addr().unwrap().to_string(),
                )
                .unwrap();
                let responses = dir.join("responses");
                let tap = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let service = service.clone();
                        let responses = responses.clone();
                        async move {
                            let method = request.method().to_string();
                            let path = request.uri().path().to_owned();
                            let response = service
                                .call(request)
                                .await
                                .unwrap_or_else(|never| match never {});
                            let (parts, body) = response.into_parts();
                            let body = body
                                .collect()
                                .await
                                .unwrap_or_else(|never| match never {})
                                .to_bytes();
                            let token = parts
                                .headers
                                .get("granary-error")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("-");
                            let line = format!(
                                "{method} {path} {} {token} {}\n",
                                parts.status.as_u16(),
                                hex(&body)
                            );
                            OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&responses)?
                                .write_all(line.as_bytes())?;
                            Ok::<_, std::io::Error>(hyper::Response::from_parts(
                                parts,
                                http_body_util::Full::new(body),
                            ))
                        }
                    },
                );
                let (stop, stopping) = tokio::sync::watch::channel(false);
                let stop_requested = dir.join("stop-requested");
                let forward = async move {
                    while !*shutdown.borrow_and_update() {
                        if shutdown.changed().await.is_err() {
                            break;
                        }
                    }
                    draining.begin();
                    // Poll the cancel-safe stop once before reporting: the
                    // request is set before its first await. A captured PUT
                    // may then finish its issuer without starting another step.
                    let mut stopping = std::pin::pin!(handle.stop());
                    std::future::poll_fn(|cx| {
                        let _ = stopping.as_mut().poll(cx);
                        std::task::Poll::Ready(())
                    })
                    .await;
                    std::fs::write(stop_requested, b"requested").unwrap();
                    stop.send(true).unwrap();
                };
                let forward = tokio::spawn(forward);
                let result = granary_net::accept::serve(
                    listener,
                    Arc::new(tls),
                    tap,
                    stopping,
                    granary_net::accept::AcceptConfig::default(),
                )
                .await;
                forward.abort();
                result
            })
        },
        trigger,
        HOST_DRAIN,
    )
    .await;
    if exit.code != 0 {
        eprintln!("{exit:?}");
        std::process::exit(exit.code);
    }
    Ok(())
}

const REPORT_CHECKS: &str = r"
import json, sys
if not __debug__:
    raise SystemExit('report validation requires Python assertions')
r = json.load(sys.stdin)
outcome, publication, seq, ident, exit_code = sys.argv[1:]
assert r['exit_code'] == int(exit_code), r
assert (r['outcome'], r['publication_id'], r['uncertain']) == (outcome, publication, outcome in ('pending', 'abandoned', 'unresolved')), r
if outcome == 'pending':
    assert (r['completion'], r['response']['status'], r['response']['token'], r['retention']) == (None, 503, 'unavailable', 'live'), r
elif outcome == 'abandoned':
    assert (r['completion'], r['route'], r['retention']) == (None, 'local', 'archive'), r
elif outcome == 'unresolved':
    assert (r['completion'], r['retention'], r['response']['status']) == (None, 'live', 503), r
    assert r['response']['token'] in ('fenced', 'unavailable'), r
else:
    assert (r['completion']['seq'], r['completion']['id'], r['completion']['receipt']) == (int(seq), ident, None), r
";

pub(super) fn report(
    output: &std::process::Output,
    code: i32,
    record: &granary_core::retained_submission::Submission,
    outcome: &str,
) {
    report_candidate(output, code, record, outcome, &record.candidates[0]);
}

pub(super) fn report_candidate(
    output: &std::process::Output,
    code: i32,
    record: &granary_core::retained_submission::Submission,
    outcome: &str,
    candidate: &granary_core::retained_submission::Candidate,
) {
    use std::io::Write as _;
    let diagnostics = format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(code), "{diagnostics}");
    // Python is already the lane's structural JSON checker; no Rust dependency
    // is added merely to parse the CLI's report in this AGPL fixture.
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(REPORT_CHECKS)
        .args([
            outcome,
            &hex(&record.publication_id),
            &candidate.seq.to_string(),
            &candidate.id.to_string(),
            &code.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&output.stdout)
        .unwrap();
    let parsed = child.wait_with_output().unwrap();
    assert!(
        parsed.status.success(),
        "structural JSON refusal: {}\n{diagnostics}",
        String::from_utf8_lossy(&parsed.stderr)
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one schedule pins the eight real unavailable replies and its owned occupancy tail"
)]
async fn dispatch_loss_retains_uncertainty_and_resumes_without_post() {
    use super::oracle::RequestClass::{Hint, Preparation, Publication, Recovery};
    use granary_core::retained_submission::Phase;
    assert!(REPLY_DEADLINE < granary_client::SEAM_DEADLINE_BASE);
    let fx = Composition::new(true).await;
    // The loss mechanism is HostReply, never backend delay or a client timeout.
    // No release is issued until the bounded invocation has returned Pending.
    let output = Process::spawn(&mut fx.client.command(false))
        .output_with_bound(Duration::from_secs(35))
        .await;
    let diagnostics = format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let record = fx.client.record();
    assert!(
        record.is_some(),
        "missing retained publication\n{diagnostics}"
    );
    let record = record.unwrap();
    let candidate = &record.candidates[0];
    assert_eq!(
        (
            candidate.evidence.started,
            candidate.evidence.proved_no_write,
            candidate.evidence.last_answered_attempt
        ),
        (8, 0, 8),
        "unavailable is not a no-write proof\n{diagnostics}"
    );
    report(&output, 3, &record, "pending");
    let notes = fx.notes();
    let exact = format!(
        "POST alpha {} {} {}",
        hex(&candidate.request.epoch),
        hex(&candidate.request.operation),
        hex(&candidate.root)
    );
    assert_eq!(
        notes
            .lines()
            .filter(|l| l.starts_with("POST "))
            .collect::<Vec<_>>(),
        vec![exact.as_str(); 8],
        "exact eight-send transcript\n{notes}\n{diagnostics}"
    );
    let responses = fx.responses();
    let preparation = fx.preparation_requests(&record.frozen.initial_root).await;
    let mut order: Vec<_> = preparation
        .into_iter()
        .map(|request| (Preparation, request))
        .collect();
    for _ in 0..8 {
        order.push((Recovery, format!("GET {}", super::support::ROOT_PATH)));
        order.push((Preparation, "GET /volume/alpha/max-seq".into()));
        order.push((Publication, "POST /volume/alpha/publish".into()));
    }
    assert_eq!(
        super::oracle::request_trace(&responses),
        Ok(((8, 16, 8, 0), order)),
        "complete Pending request classes/counts/order\n{responses}\n{diagnostics}"
    );
    assert_eq!(
        responses
            .lines()
            .filter(|l| l.starts_with("POST "))
            .collect::<Vec<_>>(),
        vec!["POST /volume/alpha/publish 503 unavailable "; 8],
        "client must observe real 503 unavailable, not transport errors\n{responses}\n{diagnostics}"
    );
    assert_eq!(
        (
            notes.contains("REACHED HostReply 1"),
            notes.contains("RELEASED HostReply"),
            notes
                .lines()
                .filter(|l| *l == "GATEWAY post-dispatch unavailable")
                .count()
        ),
        (true, false, 8),
        "post-dispatch reply-hold provenance\n{notes}\n{diagnostics}"
    );
    let decisions = fx.records();
    assert_eq!(
        decisions.len(),
        1,
        "only the committed decision precedes the reply hold: {decisions:?}\n{diagnostics}"
    );
    let committed = matches!(decisions[0].body(), RecordBody::Decision { identity, candidate: bytes, root_seq, .. } if identity.candidate_id() == candidate.id && bytes.as_bytes() == candidate.root && *root_seq == candidate.seq);
    assert!(
        super::oracle::provenance(committed, &notes),
        "dispatch-loss provenance\n{decisions:?}\n{notes}\n{diagnostics}"
    );
    assert!(
        fx.roots().await.is_empty(),
        "reply hold must precede backend execution\n{diagnostics}"
    );
    fx.release_reply();
    let landing = fx.land(&record).await;
    assert_eq!(landing, Ok(()), "{diagnostics}");
    let before = fx
        .notes()
        .lines()
        .filter(|l| l.starts_with("POST "))
        .count();
    let output = Process::spawn(&mut fx.client.command(true)).output().await;
    let complete = fx.client.record();
    assert!(
        complete.is_some(),
        "missing completion record\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let complete = complete.unwrap();
    assert_eq!(
        (
            &complete.scope,
            &complete.volume,
            complete.publication_id,
            &complete.frozen
        ),
        (
            &record.scope,
            &record.volume,
            record.publication_id,
            &record.frozen
        ),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        matches!(complete.phase, Phase::Complete(_)),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        (&complete.current, &complete.candidates),
        (&None, &record.candidates),
        "candidate catalogue changed at owned completion\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    report(&output, 0, &record, "landed");
    let fresh_responses = fx.responses();
    let fresh_responses = fresh_responses.strip_prefix(&responses).unwrap_or_else(|| {
        panic!(
            "gateway transcript prefix changed\n{fresh_responses}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(
        super::oracle::request_trace(fresh_responses),
        Ok((
            (0, 1, 1, 1),
            vec![
                (Recovery, format!("GET {}", super::support::ROOT_PATH)),
                (Preparation, "GET /volume/alpha/max-seq".into()),
                (Hint, "PUT /volume/alpha/hint".into())
            ]
        )),
        "complete fresh request classes/counts/order\n{fresh_responses}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fx.notes()
            .lines()
            .filter(|l| l.starts_with("POST "))
            .count(),
        before,
        "resumed publication sent a POST\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fx.roots().await,
        vec![(candidate.seq, candidate.root.clone())],
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        super::oracle::trace_and_occupancy(
            &notes,
            &responses,
            &exact,
            &["POST /volume/alpha/publish 503 unavailable "; 8],
            &fx.roots().await,
            candidate.seq,
            &candidate.root
        ),
        "transcript/occupancy oracle\n{notes}\n{responses}\n{diagnostics}"
    );
    super::support::observe(
        "composition::dispatch_loss_retains_uncertainty_and_resumes_without_post",
        &[
            "decision",
            "reply-hold",
            "eight-unavailable",
            "pending",
            "put-release",
            "owned-completion",
        ]
        .map(|stage| {
            format!(
                "composition::dispatch_loss_retains_uncertainty_and_resumes_without_post:{stage}"
            )
        }),
    );
    fx.shutdown().await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture checks normal replies and explicitly releases conflicting signed captures"
)]
async fn unheld_reply_and_put_release_controls() {
    let fx = Composition::new(false).await;
    let premature = super::backend::Identity {
        volume: "control".into(),
        seq: 1,
        id: granary_core::hash::GrainId::of(b"old"),
        occurrence: 1,
    };
    assert_eq!(
        (
            fx.proxy.pending(),
            fx.proxy.release(&premature).await.is_err()
        ),
        (0, true),
        "premature release admitted: {premature:?}"
    );
    let mut command = fx.client.command(false);
    let rendezvous =
        super::support::Rendezvous::arm(&mut command, &fx.client.scratch.0, "dispatch", "after", 1);
    let mut process = Process::spawn(&mut command);
    let (_, mut stream) = rendezvous.reached(&mut process).await.unwrap();
    let record = fx.client.record();
    process.assert_or_kill(record.is_some(), "missing retained publication");
    let record = record.unwrap();
    let captured = fx.proxy.captured().await;
    process.assert_or_kill(
        fx.responses()
            .lines()
            .any(|l| l.starts_with("POST /volume/alpha/publish 202 - ")),
        &format!("unheld normal Accepted answer: {}", fx.responses()),
    );
    process.assert_or_kill(
        !fx.notes().contains("GATEWAY post-dispatch unavailable"),
        "unheld reply used loss path",
    );
    for wrong in [
        super::backend::Identity {
            volume: "beta".into(),
            ..captured.clone()
        },
        super::backend::Identity {
            seq: 2,
            ..captured.clone()
        },
        super::backend::Identity {
            id: granary_core::hash::GrainId::of(b"foreign"),
            ..captured.clone()
        },
        super::backend::Identity {
            occurrence: 2,
            ..captured.clone()
        },
    ] {
        process.assert_or_kill(
            fx.proxy.release(&wrong).await.is_err(),
            &format!("wrong capture identity accepted: {wrong:?}"),
        );
    }
    let landing = fx.land(&record).await;
    process.assert_or_kill(landing.is_ok(), &format!("{landing:?}"));
    process.assert_or_kill(
        fx.proxy.release(&captured).await.is_err(),
        "duplicate release accepted",
    );
    stream.write_all(b"continue\n").await.unwrap();
    let output = process.output().await;
    // The first invocation may obtain a checked receipt on its normal retry.
    let stdout = super::support::assert_exit(&output, 0);
    let diagnostics = format!(
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("\"outcome\":\"landed\""),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store = Arc::new(GranaryStore::new(backend(&fx.proxy.endpoint)));
    let issuer_store = store.clone();
    let issuer =
        tokio::spawn(async move { issuer_store.put_root("control", 1, b"old".to_vec()).await });
    let old = fx.proxy.captured().await;
    assert_eq!(old, premature, "{diagnostics}");
    issuer.abort();
    let _cancelled = issuer.await;
    let competitor_store = store.clone();
    let competitor = tokio::spawn(async move {
        competitor_store
            .put_root("control", 1, b"winner".to_vec())
            .await
    });
    let winner = fx
        .proxy
        .captured_matching(granary_core::hash::GrainId::of(b"winner"))
        .await;
    assert_eq!(fx.proxy.release(&winner).await, Ok(200), "{diagnostics}");
    assert_eq!(
        fx.proxy.release(&old).await,
        Ok(412),
        "disconnected signed write must survive and lose create-only conflict\n{diagnostics}"
    );
    competitor.await.unwrap().unwrap();
    assert_eq!(
        (
            store.get_root("control", 1).await.unwrap(),
            fx.proxy.pending()
        ),
        (Some(b"winner".to_vec()), 0),
        "{diagnostics}"
    );
    super::support::observe(
        "composition::unheld_reply_and_put_release_controls",
        &[
            "accepted",
            "capture-refusals",
            "disconnected-release",
            "competing-release",
        ]
        .map(|stage| format!("composition::unheld_reply_and_put_release_controls:{stage}")),
    );
    fx.shutdown().await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn append_fence_refuses_and_retains_submission() {
    let mut fx = Composition::new(false).await;
    fx.stop().await;
    fx.command
        .env("GRANARY_TEST_HOST_PLAN", "HostLogAppend:1:fail");
    fx.start(false);
    fx.ready().await;
    let mut client = Process::spawn(&mut fx.client.command(false));
    fx.append_fault_reached(1, Some(&mut client)).await;
    fx.release_reply();
    let output = client.output_with_bound(Duration::from_secs(35)).await;
    let retained = fx.client.record();
    assert!(
        retained.is_some(),
        "fenced response lost retained submission\n{}",
        diagnostics(&output)
    );
    let retained = retained.unwrap();
    assert!(
        !retained.candidates.is_empty()
            && retained
                .candidates
                .iter()
                .all(|candidate| candidate.evidence.proved_no_write == 0)
            && retained
                .candidates
                .iter()
                .any(|candidate| candidate.evidence.started > 0),
        "fenced attempts must remain uncertain\n{}",
        diagnostics(&output)
    );
    let responses = fx.responses();
    let post_responses: Vec<_> = responses
        .lines()
        .filter(|line| line.starts_with("POST /volume/alpha/publish "))
        .collect();
    // A fenced authority answer or a retry shed during drain is valid here;
    // the fenced rendering is pinned at the adapter and wire seams.
    assert!(
        !post_responses.is_empty()
            && post_responses.iter().all(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.get(2) == Some(&"503")
                    && matches!(fields.get(3), Some(&"fenced" | &"unavailable"))
            }),
        "publish responses must all be 503 fenced or unavailable, and nonempty\n{post_responses:?}\n{}",
        diagnostics(&output)
    );
    let received_fenced = post_responses
        .iter()
        .any(|line| line.split_whitespace().nth(3) == Some("fenced"));
    if received_fenced {
        report(&output, 5, &retained, "unresolved");
    } else {
        // Unavailable answers retry to Pending at the send bound, or a failed
        // next barrier returns Unresolved (coordinator.rs:432-454).
        match output.status.code() {
            Some(3) => report(&output, 3, &retained, "pending"),
            Some(5) => report(&output, 5, &retained, "unresolved"),
            code => panic!(
                "unavailable-only fence run exited {code:?}\n{}",
                diagnostics(&output)
            ),
        }
    }
    assert_eq!(
        fx.records(),
        [],
        "failed append committed a decision\n{}",
        diagnostics(&output)
    );
    let host = fx.host.take().unwrap().host_output().await;
    assert_eq!(
        host.status.code(),
        Some(granary_server::EXIT_FENCED),
        "host did not exit fenced\n{}",
        diagnostics(&host)
    );
    assert!(
        fx.notes().contains("RELEASED HostLogAppend"),
        "append failure release was not observed\n{}",
        fx.notes()
    );
    stages(
        "composition::append_fence_refuses_and_retains_submission",
        &["append-fault", "fenced-exit", "uncertain-submission"],
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn anonymous_reader_and_writer_policy_on_composed_gateway() {
    let mut fx = Composition::new(false).await;
    let (record, capture, diagnostic) = interrupted(&fx).await;
    assert_eq!(
        anonymous_root(&fx, record.candidates[0].seq).await,
        (404, vec![]),
        "anonymous reader must be served while the publication PUT is held\n{diagnostic}"
    );
    assert_eq!(
        fx.proxy.release(&capture).await,
        Ok(200),
        "authorized landing\n{diagnostic}"
    );
    let root_path = format!("/volume/alpha/root/{:020}", record.candidates[0].seq);
    let (status, _, body) = anonymous_request(&fx, "GET", &root_path).await;
    assert_eq!(
        (status, body),
        (200, record.candidates[0].root.clone()),
        "anonymous reader must see the composed landing\n{diagnostic}"
    );
    let paths = [
        ("POST", "/volume/alpha/publish".to_owned()),
        ("PUT", root_path),
        ("PUT", "/volume/alpha/hint".to_owned()),
        (
            "PUT",
            format!("/volume/alpha/meta/blake3:{}", "11".repeat(32)),
        ),
        ("PUT", format!("/bin/{}", "22".repeat(32))),
    ];
    let mut refusals = Vec::new();
    for (method, path) in paths {
        let (status, head, _) = anonymous_request(&fx, method, &path).await;
        refusals.push((status, head.contains("no-principal")));
    }
    assert_eq!(
        refusals,
        vec![(403, true); 5],
        "anonymous writes must be refused at every write endpoint\n{diagnostic}"
    );
    assert_eq!(
        fx.roots().await,
        [(record.candidates[0].seq, record.candidates[0].root.clone())],
        "anonymous write changed MinIO occupancy\n{diagnostic}"
    );
    fx.stop().await;
    stages(
        "composition::anonymous_reader_and_writer_policy_on_composed_gateway",
        &[
            "anonymous-read",
            "write-endpoints-refused",
            "occupancy-unchanged",
        ],
    );
}

/// A remote fault on the first content PUT must reach the operator as a
/// classified cause naming the failed call and its status, not as a
/// generic text. The
/// authority host answers the client's content PUT with a 500 when its own
/// backend PUT is refused; the client runs to exit before its dispatch cut.
#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires supported authority storage in the Linux venue"
)]
async fn content_put_fault_surfaces_a_classified_backend_error() {
    let fx = Composition::new(false).await;
    // 403 is terminal for the backend client's retry policy; a 5xx would be
    // retried for minutes before the host answered its own client.
    fx.proxy.fail_content_puts(403);
    let mut command = fx.client.command(false);
    let rendezvous = Rendezvous::arm(&mut command, &fx.client.scratch.0, "dispatch", "after", 1);
    let mut process = Process::spawn(&mut command);
    let reached = rendezvous.reached(&mut process).await;
    let exited_early = matches!(&reached, Err(error) if error.contains("child exit"));
    let output = process.output().await;
    let text = diagnostics(&output);
    assert!(
        exited_early,
        "client reached its dispatch cut: {reached:?}\n{text}"
    );
    let injected = fx.proxy.injected();
    assert!(injected >= 1, "no content PUT was faulted\n{text}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        (
            output.status.code(),
            stdout.contains(r#""outcome":"backend-error""#),
            stdout.contains("remote store call (PUT bin: status 500)"),
            stdout.contains("publication failed; inspect verified remote state"),
        ),
        (Some(6), true, true, false),
        "exit, outcome, surfaced cause, generic text\n{text}"
    );
    fx.shutdown().await;
    super::support::observe(
        "composition::content_put_fault_surfaces_a_classified_backend_error",
        &[
            "fault-injected",
            "exit-before-dispatch",
            "classified-diagnostic",
        ]
        .map(|stage| {
            format!("composition::content_put_fault_surfaces_a_classified_backend_error:{stage}")
        }),
    );
}

fn dispatch_deadline_controls() {
    use std::os::unix::ffi::OsStrExt as _;
    let normal = NORMAL_DISPATCH.as_millis().to_string();
    let normal = OsStr::new(&normal);
    let short = REPLY_DEADLINE.as_millis().to_string();
    let short = OsStr::new(&short);
    let dispatch_cases = [
        (
            None,
            None,
            None,
            "GRANARY_COMPOSITION_DISPATCH_MS is required",
        ),
        (
            None,
            Some(OsStr::new("invalid")),
            None,
            "GRANARY_COMPOSITION_DISPATCH_MS must be positive milliseconds",
        ),
        (
            None,
            Some(OsStr::new("0")),
            None,
            "GRANARY_COMPOSITION_DISPATCH_MS must be positive milliseconds",
        ),
        (
            Some(short),
            Some(normal),
            Some(OsStr::new("invalid")),
            "GRANARY_COMPOSITION_REPLY_MS must be positive milliseconds",
        ),
        (
            Some(short),
            Some(normal),
            Some(OsStr::new("0")),
            "GRANARY_COMPOSITION_REPLY_MS must be positive milliseconds",
        ),
        (
            Some(short),
            Some(OsStr::from_bytes(b"\xff")),
            None,
            "GRANARY_COMPOSITION_DISPATCH_MS must be positive milliseconds",
        ),
        (
            Some(short),
            Some(normal),
            Some(OsStr::from_bytes(b"\xff")),
            "GRANARY_COMPOSITION_REPLY_MS must be positive milliseconds",
        ),
    ];
    for (reply, bad_dispatch, bad_reply, refusal) in dispatch_cases {
        assert_eq!(
            (
                dispatch_deadlines(Some(normal), reply),
                dispatch_deadlines(bad_dispatch, bad_reply),
            ),
            (
                Ok((NORMAL_DISPATCH, reply.map(|_| REPLY_DEADLINE))),
                Err(refusal)
            ),
            "dispatch controls for {reply:?}, {bad_dispatch:?}, {bad_reply:?}"
        );
    }
}

#[tokio::test]
async fn structural_report_controls() {
    use std::os::unix::process::ExitStatusExt as _;
    dispatch_deadline_controls();
    minio_retry_controls();
    ready_file_controls().await;
    #[cfg(target_os = "linux")]
    host_reservation_controls().await;
    let record = granary_core::retained_submission::decode(include_bytes!(
        "../../../granary-core/tests/vectors/retained-submission/ready.bin"
    ))
    .unwrap();
    let json = format!(
        r#"{{"outcome":"abandoned","exit_code":0,"publication_id":"{}","uncertain":true,"completion":null,"route":"local","retention":"archive"}}"#,
        hex(&record.publication_id)
    );
    let output = std::process::Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: json.as_bytes().to_vec(),
        stderr: b"CLI diagnostics".to_vec(),
    };
    report(&output, 0, &record, "abandoned");
    let bad = std::process::Output {
        stdout: json
            .replace(
                &hex(&record.publication_id),
                "ffffffffffffffffffffffffffffffff",
            )
            .into_bytes(),
        ..output
    };
    assert!(
        std::panic::catch_unwind(|| report(&bad, 0, &record, "abandoned")).is_err(),
        "report accepted a substituted publication identity"
    );
    let bad_exit = std::process::Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: json
            .replace("\"exit_code\":0", "\"exit_code\":1")
            .into_bytes(),
        stderr: b"CLI diagnostics".to_vec(),
    };
    assert!(
        std::panic::catch_unwind(|| report(&bad_exit, 0, &record, "abandoned")).is_err(),
        "report accepted an exit_code that disagreed with the process status"
    );
    let scratch = Scratch::new();
    let input = scratch.0.join("report.json");
    std::fs::write(&input, json.as_bytes()).unwrap();
    let optimized = Command::new("python3")
        .args([
            "-O",
            "-c",
            REPORT_CHECKS,
            "abandoned",
            &hex(&record.publication_id),
            "1",
            &record.candidates[0].id.to_string(),
            "0",
        ])
        .stdin(std::fs::File::open(input).unwrap())
        .output()
        .unwrap();
    assert_eq!(
        (
            optimized.status.success(),
            String::from_utf8_lossy(&optimized.stderr)
                .contains("report validation requires Python assertions")
        ),
        (false, true),
        "optimized report checks silently bypassed assertions: {optimized:?}"
    );
    super::support::observe("composition::structural_report_controls", &[]);
}
