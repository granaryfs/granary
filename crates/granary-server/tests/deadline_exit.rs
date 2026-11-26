// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `DeadlineExpired` must kill the process, with a
//! non-yielding worker outstanding.
//!
//! **What makes this a test and not a demonstration.** With a poll that
//! never returns `Poll::Ready` and never yields resident on the runtime,
//! dropping the runtime HANGS and returning from `main` HANGS — the
//! runtime's drop joins its workers and one of them is inside that poll
//! forever. `std::process::exit` dies immediately. So a `serve_and_exit`
//! that drops the runtime or returns from `main` does not fail this test
//! on a judgement call; the child never exits and the wall bound below
//! fires. The OTHER exit requirement — that the `DeadlineExpired` arm carries
//! no statement before the exit — is not observable from out here and is
//! not claimed to be: it is a reading gate on the source.
//!
//! **A SINGLE `#[test]`, and the file is arranged around that.** The test
//! re-executes its own binary as the server child, and the three
//! libtest arguments it passes are all load-bearing: `--nocapture`
//! because the harness otherwise swallows the child's readiness line into
//! a capture buffer the parent can never read, and `--exact` with the
//! test's name because a multi-test binary would otherwise run every test
//! in the child. The name is spelled once, in [`TEST_NAME`], and the
//! `#[test]` fn below must keep it.
//!
//! **The two properties are carried by two different residents, and that
//! split is a MEASUREMENT rather than a preference.** One
//! spinning service was tried for both jobs. It cannot, on stable tokio: a task
//! woken by an I/O event and then never yielding does not merely occupy
//! its worker, it strands the runtime's whole I/O-and-time driver.
//! Exactly one worker at a time parks ON that driver and the rest park on
//! a condvar; when I/O arrives the driver's worker unparks, RELEASES the
//! driver and runs the woken task, and the hand-off that would wake
//! another worker to take it over is `cfg!(tokio_unstable)`-gated
//! (`enable_eager_driver_handoff`, tokio's
//! `multi_thread/worker.rs`). So the spinning service froze every timer
//! in the child: the 500 ms drain deadline never fired, `serve` never
//! resolved, and the child had to be killed — executed here at 2, 3, 4
//! and 8 workers, and at a ZERO deadline too, which does not help because
//! the timer wheel's `elapsed` tick is itself only advanced by the
//! driver. With no wedge the same child's timers fired on schedule.
//!
//! So: [`HoldingService`] keeps the connection RESIDENT by parking
//! forever, which is what makes the drain time out while leaving the
//! driver healthy — and a separate [`spin_forever`] task, scheduled
//! through the injection queue rather than woken by I/O, is what makes
//! `Runtime::drop` and a return from `main` hang. Both are resident when
//! `serve` reports `DeadlineExpired`, when process exit must stop both
//! without waiting for the runtime to drop.
//!
//! **The child prints its own readiness line.** It calls
//! [`serve_and_exit`] directly rather than running the shipped binary, so
//! no tracing subscriber exists in this process and `main`'s readiness
//! line is never emitted here. A bare `eprintln!` carrying the bound
//! address takes its place — after the bind, and after the trust anchor
//! is fully written, because the parent treats that line as permission to
//! do both.

#![cfg(unix)]

mod process;

use std::future::Future;
use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use granary_net::accept::AcceptConfig;
use granary_net::alpn::ALPN_HTTP11;
use granary_net::tls::{ClientAuth, server_tls_config};
use granary_server::{EXIT_DEADLINE_EXPIRED, serve_and_exit};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// The `#[test]` fn's name, passed to the child so `--exact` has
/// something to be exact about.
const TEST_NAME: &str = "deadline_expiry_kills_the_process";

/// Set on the child and on nothing else; the fork in the `#[test]` fn.
const CHILD_MARKER: &str = "GRANARY_DEADLINE_EXIT_CHILD";

/// Where the child writes the trust anchor the parent must use.
const CHILD_TRUST: &str = "GRANARY_DEADLINE_EXIT_TRUST";

/// The child's readiness line, which the shipped binary's JSON line
/// deliberately does not resemble — this one is the test's own.
const READY: &str = "granary-deadline-exit listening on ";

/// The name the certificate carries and the client asks for.
const HOST: &str = "localhost";

/// The drain deadline under test. Short, because the property is that the
/// process dies AFTER it and not that it is long.
const DEADLINE: Duration = Duration::from_millis(500);

/// The wall bound on the whole child lifecycle. An order of magnitude past
/// [`DEADLINE`], which is margin against CI scheduling and not against the
/// behaviour.
const WALL_BOUND: Duration = Duration::from_secs(10);

/// How long the parent waits for a response that a wedged server never
/// sends. A NEGATIVE bound: the event is one a correct server does not
/// produce, so a short value cannot flake.
const BEAT: Duration = Duration::from_millis(400);

#[test]
fn deadline_expiry_kills_the_process() {
    if std::env::var_os(CHILD_MARKER).is_some() {
        child();
    }
    parent();
}

// ------------------------------------------------------------ the child

/// The server side: a resident [`spin_forever`] task, a service that
/// holds its connection open, a 500 ms drain deadline, and the real
/// [`serve_and_exit`]. Never returns.
fn child() -> ! {
    let trust = match std::env::var(CHILD_TRUST) {
        Ok(path) => PathBuf::from(path),
        Err(error) => panic!("{CHILD_TRUST}: {error}"),
    };

    let certs = mint();
    // Fully written and closed BEFORE the readiness line: the parent reads
    // this file the moment it sees that line.
    if let Err(error) = std::fs::write(&trust, certs.ca_pem.as_bytes()) {
        panic!("writing {}: {error}", trust.display());
    }

    let tls = Arc::new(
        server_tls_config(vec![certs.leaf], certs.key, ClientAuth::None)
            .unwrap_or_else(|error| panic!("server tls config: {error}")),
    );

    // `worker_threads(2)` EXPLICITLY: `spin_forever` owns one worker for
    // the rest of the process, and on a one-worker runtime there would be
    // none left to serve the connection or to park on the driver — the
    // deadline would never fire and the test would hang against a CORRECT
    // implementation. `enable_all` is the caller obligation
    // `serve_and_exit` documents: the drain calls `tokio::time::timeout`,
    // which panics without the time driver.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("runtime: {error}"));

    // Scheduled BEFORE serving and through the injection queue, which is
    // the half of the module note that makes this survivable: a worker
    // notified this way takes the task while another parks on the driver,
    // so the runtime keeps its timers. The same loop reached by an I/O
    // wakeup does not, which is why the connection cannot carry it.
    {
        let _entered = runtime.enter();
        #[expect(
            clippy::disallowed_methods,
            reason = "the deadline-exit process test needs a resident non-yielding poll; it is the state under test, not concurrency the sim must sequence"
        )]
        let _detached = tokio::spawn(spin_forever());
    }

    let listener = runtime
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .unwrap_or_else(|error| panic!("bind: {error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("local addr: {error}"));

    let config = AcceptConfig {
        shutdown_deadline: DEADLINE,
        ..AcceptConfig::default()
    };

    eprintln!("{READY}{addr}");

    serve_and_exit(
        runtime,
        listener,
        tls,
        HoldingService,
        config,
        stdin_eof(),
        None,
    );
}

/// The non-yielding resident: a poll that never returns `Poll::Ready` and
/// never yields.
///
/// `std::hint::spin_loop` and not a `pending()`: a future that parks is
/// abandonable and a runtime drop would sail past it. This one owns its
/// worker thread until the process dies, which requires an exit that does
/// not drop the runtime — `Runtime::drop` joins its workers, so a `serve_and_exit`
/// that dropped the runtime or returned from `main` would hang here
/// instead of exiting, and the parent's wall bound is what catches it. It
/// burns one core for well under a second.
#[expect(
    clippy::unused_async,
    reason = "the ABSENCE of an await is the property: a future with an await point yields, and a yielding future is one a runtime drop can step over"
)]
async fn spin_forever() {
    loop {
        std::hint::spin_loop();
    }
}

/// The trigger: the parent holds this child's stdin, and dropping it is
/// the shutdown. Test code, which is why tokio's `io-std` is a DEV
/// feature — production's trigger is the signal pair.
async fn stdin_eof() {
    let mut stdin = tokio::io::stdin();
    let mut sink = [0_u8; 64];
    loop {
        match stdin.read(&mut sink).await {
            Ok(0) | Err(_) => return,
            Ok(_more) => {}
        }
    }
}

/// A service that accepts a request and never answers it.
///
/// It parks rather than spins, deliberately: parking keeps the connection
/// task RESIDENT — the graceful drain waits on its receiver and can never
/// complete — while leaving the runtime's driver free to fire the drain
/// deadline. A spinning service would do the first job and destroy the
/// second (see the module note); [`spin_forever`] carries the
/// non-yielding half instead.
#[derive(Clone, Debug)]
struct HoldingService;

impl Service<Request<Incoming>> for HoldingService {
    type Response = Response<Full<Bytes>>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, _request: Request<Incoming>) -> Self::Future {
        Box::pin(std::future::pending())
    }
}

// ----------------------------------------------------------- the parent

/// SIGKILLs the child if the test unwinds before `take()` — a panic in
/// any assertion between spawn and wait would otherwise leave the child
/// running until the runner reaps orphans, and THIS child is the worst
/// orphan available: its spin task burns a full core forever. `Child`'s
/// own drop neither signals nor waits.
struct Reaped(Option<std::process::Child>);

impl Reaped {
    fn get(&mut self) -> &mut std::process::Child {
        self.0
            .as_mut()
            .unwrap_or_else(|| panic!("the child was already taken"))
    }
    fn take(mut self) -> std::process::Child {
        self.0
            .take()
            .unwrap_or_else(|| panic!("the child was already taken"))
    }
}

impl Drop for Reaped {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn parent() {
    let exe = std::env::current_exe().unwrap_or_else(|error| panic!("current exe: {error}"));
    let dir = scratch("deadline-exit");
    let trust = dir.join("trust.pem");

    let mut child = Reaped(Some(
        Command::new(exe)
            .args([TEST_NAME, "--exact", "--nocapture"])
            .env(CHILD_MARKER, "1")
            .env(CHILD_TRUST, &trust)
            .stdin(Stdio::piped())
            // Nothing reads stdout (libtest's own lines land there under
            // `--nocapture`), so nothing may buffer into it: a piped fd
            // nobody drains deadlocks the child once the pipe fills.
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning the child: {error}")),
    ));

    let Some(stdin) = child.get().stdin.take() else {
        panic!("the child was spawned without a stdin pipe")
    };
    let Some(stderr) = child.get().stderr.take() else {
        panic!("the child was spawned without a stderr pipe")
    };

    let log = Arc::new(Mutex::new(String::new()));
    let addr = read_readiness(stderr, Arc::clone(&log));

    // The runtime and the connection outlive the shutdown deliberately:
    // the wedged connection must still be resident when the deadline
    // expires, and a client that has gone away is a connection the server
    // could legitimately have finished with.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("parent runtime: {error}"));

    let held = runtime.block_on(async {
        let mut stream = tls_connect(addr, &trust).await;
        let request = format!("GET /volume/x/max-seq HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .unwrap_or_else(|error| panic!("write: {error}"));
        stream
            .flush()
            .await
            .unwrap_or_else(|error| panic!("flush: {error}"));

        // The wedge is entered when the request gets no response at all.
        // An `Ok` here — even `Ok(0)` — means the service answered or the
        // connection ended, so nothing is resident and the rest of the
        // test would be measuring the wrong thing.
        let mut chunk = [0_u8; 256];
        let answered = tokio::time::timeout(BEAT, stream.read(&mut chunk)).await;
        assert!(
            answered.is_err(),
            "the wedge answered within {BEAT:?}, so no non-yielding poll is resident \
             and the deadline this test exists to observe cannot be reached: {answered:?}"
        );
        stream
    });

    drop(stdin);
    let status = wait_within(child.take(), WALL_BOUND, &log);

    assert_eq!(
        status.code(),
        Some(EXIT_DEADLINE_EXPIRED),
        "the child must die with the deadline code, not {status:?}\n--- child stderr ---\n{}",
        captured(&log)
    );

    drop(held);
    drop(runtime);
}

/// Read the child's readiness line off stderr within [`WALL_BOUND`],
/// draining the rest into `log` so a failure can print it.
fn read_readiness(stderr: std::process::ChildStderr, log: Arc<Mutex<String>>) -> SocketAddr {
    let (sender, receiver) = mpsc::channel();
    let _reader = std::thread::spawn(move || {
        let mut announced = false;
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            // A poisoned lock still appends — `captured` recovers the
            // same way, and a diagnostics log that silently truncates at
            // a poisoning point hides exactly the line someone needs.
            let mut held = match log.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            held.push_str(&line);
            held.push('\n');
            drop(held);
            if !announced && let Some(addr) = line.strip_prefix(READY) {
                announced = sender.send(addr.to_owned()).is_ok();
            }
        }
    });

    let line = match receiver.recv_timeout(WALL_BOUND) {
        Ok(line) => line,
        Err(error) => panic!("no readiness line within {WALL_BOUND:?}: {error}"),
    };
    line.parse()
        .unwrap_or_else(|error| panic!("readiness address {line:?}: {error}"))
}

/// A TLS-1.3 client trusting exactly the anchor the child wrote, offering
/// exactly `http/1.1`.
async fn tls_connect(addr: SocketAddr, trust: &Path) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    let anchors = CertificateDer::pem_file_iter(trust)
        .unwrap_or_else(|error| panic!("opening {}: {error}", trust.display()));
    for anchor in anchors {
        let anchor = anchor.unwrap_or_else(|error| panic!("reading {}: {error}", trust.display()));
        roots
            .add(anchor)
            .unwrap_or_else(|error| panic!("trust anchor: {error}"));
    }

    let mut config = ClientConfig::builder_with_provider(Arc::new(granary_net::crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|error| panic!("client versions: {error}"))
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

    let tcp = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|error| panic!("tcp: {error}"));
    let name = ServerName::try_from(HOST).unwrap_or_else(|error| panic!("server name: {error}"));
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .unwrap_or_else(|error| panic!("tls: {error}"))
}

/// Wait for `child` within `bound`, killing it if the bound expires.
///
/// Ownership stays in this thread until exit or guard teardown. A timed-out
/// wedge is killed and reaped before the failure leaves this function.
fn wait_within(child: Child, bound: Duration, log: &Arc<Mutex<String>>) -> ExitStatus {
    let mut child = process::ChildGuard(child);
    match child.wait_within(bound) {
        Ok(Some(status)) => status,
        Err(error) => panic!("waiting for the child: {error}"),
        Ok(None) => {
            panic!(
                "the child was still alive {bound:?} after shutdown — a `serve_and_exit` that \
                 returns from `main` or drops the runtime hangs exactly here\n\
                 --- child stderr ---\n{}",
                captured(log)
            );
        }
    }
}

fn captured(log: &Arc<Mutex<String>>) -> String {
    match log.lock() {
        Ok(held) => held.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

// ------------------------------------------------------------- fixtures

/// A CA, the leaf it signed, and the CA in the form the parent trusts.
struct Certs {
    ca_pem: String,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn mint() -> Certs {
    let ca_key = rcgen::KeyPair::generate().unwrap_or_else(|error| panic!("ca keypair: {error}"));
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|error| panic!("ca: {error}"));
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "granary deadline-exit ca");
    ca_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let ca = ca_params
        .self_signed(&ca_key)
        .unwrap_or_else(|error| panic!("ca self-sign: {error}"));

    let leaf_key =
        rcgen::KeyPair::generate().unwrap_or_else(|error| panic!("leaf keypair: {error}"));
    let mut leaf_params =
        rcgen::CertificateParams::new(vec![HOST.to_owned(), "127.0.0.1".to_owned()])
            .unwrap_or_else(|error| panic!("leaf: {error}"));
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOST);
    leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .unwrap_or_else(|error| panic!("leaf sign: {error}"));

    Certs {
        ca_pem: ca.pem(),
        leaf: leaf.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

/// A fresh directory under cargo's per-crate test temporary, which is what
/// keeps a machine-local path out of this source file.
fn scratch(name: &str) -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join(name);
    let _previous = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base)
        .unwrap_or_else(|error| panic!("scratch {}: {error}", base.display()));
    base
}
