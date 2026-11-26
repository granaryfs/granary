// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SHIPPED binary drains on SIGTERM and on SIGINT.
//!
//! **`CARGO_BIN_EXE_granary-server`, not a composed harness.** Everything
//! else in this crate drives the library; this drives the artefact a
//! deploy runs, which is the only way to check the parts `main` alone
//! owns — that the environment is read at all, that the trigger is
//! registered before the readiness line goes out, and that a signal
//! reaches the shutdown channel rather than the default disposition.
//!
//! **TWO arms.** `shutdown_trigger` promises SIGTERM *or* SIGINT, and a
//! SIGTERM-only gate leaves half of that unexecuted — a trigger that
//! registered one handler and dropped the other passes a one-armed test
//! while a `^C` in front of an operator kills the process outright.
//!
//! **The signal is delivered by `kill(1)` through
//! `std::process::Command`.** `libc::kill` is unsafe FFI and this
//! workspace forbids `unsafe_code` globally, test targets included, so
//! there is no per-site route to it; `/bin/kill` exists on both CI
//! platforms and needs no dependency at all.
//!
//! **The readiness line is what the test WAITS ON; the
//! registered-before-bound ordering is a READING property.** `main`
//! registers the trigger before it binds and logs, so a line on stderr
//! means the handlers are installed — but a child that registered a
//! moment after logging would still win the race against a spawned
//! `kill(1)` every time. No test here can discriminate the ordering,
//! which is established in `main`. What this file pins is the
//! signal's effect on a server that was demonstrably still running.

#![cfg(unix)]

mod mounted;

mod process;

use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use granary_net::alpn::ALPN_HTTP11;
use granary_server::EXIT_DRAINED;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The JSON key `main`'s readiness line carries the bound address under.
const READY_KEY: &str = "\"addr\":\"";

/// The name the certificate carries. Nothing connects in these two arms —
/// the drain under test is the one with no connections open — but the
/// material still has to be a usable pair or the server never starts.
const HOST: &str = "localhost";

/// The wall bound on start-to-death.
const WALL_BOUND: Duration = Duration::from_secs(10);

/// How long the binary must demonstrably sit PARKED after readiness before
/// the signal goes out. A trigger that fired spuriously at startup drains
/// an empty server and exits 0 well inside this window, so the park proof
/// below goes red instead of the kill landing on a corpse and passing.
const SETTLE: Duration = Duration::from_millis(400);

#[test]
fn sigterm_drains_the_shipped_binary() {
    drains_on("TERM");
}

#[test]
fn sigint_drains_the_shipped_binary() {
    drains_on("INT");
}

/// SIGTERM still drains when stderr is BACKPRESSURED — the pipe held
/// open and deliberately unread while warn-level traffic fills it.
///
/// This is the end-to-end discriminator for the lossy log sink: with a
/// bare synchronous stderr writer, the workers block inside `write(2)`
/// once the pipe fills, the drain deadline's timer is starved, and the
/// process survives its own SIGTERM until the wall bound kills it. With
/// the lossy sink the workers never block, lines are dropped instead,
/// and the drain completes on time. The warn traffic is attacker-shaped
/// on purpose: a failed TLS handshake is a few packets from an
/// unauthenticated peer, and each one buys log lines.
#[test]
fn sigterm_drains_with_stderr_backpressured() {
    let dir = scratch("binary-signals-backpressure");
    let (chain, key) = mint_into(&dir);

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env("GRANARY_STORE", "memory:")
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", &chain)
            .env("GRANARY_TLS_KEY", &key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning the binary: {error}")),
    ));

    let Some(stderr) = child.get().stderr.take() else {
        panic!("the binary was spawned without a stderr pipe")
    };

    // Read ONLY up to the readiness line, in this thread, then STOP
    // reading while KEEPING the reader alive: dropping it would close
    // the pipe and turn every later write into an instant EPIPE, which
    // is not backpressure — an open, unread pipe is.
    let mut reader = BufReader::new(stderr);
    let addr = loop {
        let mut line = String::new();
        match std::io::BufRead::read_line(&mut reader, &mut line) {
            Ok(0) => panic!("stderr ended before the readiness line"),
            Ok(_bytes) => {
                if let Some((_before, after)) = line.split_once(READY_KEY)
                    && let Some((addr, _rest)) = after.split_once('"')
                {
                    break addr.to_owned();
                }
            }
            Err(error) => panic!("reading readiness: {error}"),
        }
    };
    let addr: std::net::SocketAddr = addr
        .parse()
        .unwrap_or_else(|error| panic!("the readiness address {addr:?}: {error}"));

    // Fill the pipe with warn-level lines: each garbage connection fails
    // its TLS handshake and buys log output the test never reads.
    for _peer in 0..4000_u32 {
        if let Ok(mut stream) = std::net::TcpStream::connect(addr) {
            use std::io::Write as _;
            let _sent = stream.write_all(b"this is not a client hello");
        }
    }

    // A beat, so the writes have flowed into the (now full) pipe.
    let (_hold, settle) = mpsc::channel::<()>();
    let _elapsed = settle.recv_timeout(SETTLE);

    let pid = child.get().id();
    let delivered = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap_or_else(|error| panic!("/bin/kill -TERM: {error}"));
    assert!(delivered.success(), "/bin/kill -TERM {pid} failed");

    let empty = Arc::new(Mutex::new(String::new()));
    let status = wait_within(child.take(), WALL_BOUND, &empty);
    assert_eq!(
        status.code(),
        Some(EXIT_DRAINED),
        "SIGTERM must drain even with stderr backpressured, not {status:?}"
    );

    // Vacuity guard: prove the pipe really was under pressure — the
    // residue drained after exit must be at least a pipe buffer's
    // worth, or the warn traffic never filled anything and this test
    // discriminated nothing.
    let mut residue = Vec::new();
    let _rest = std::io::Read::read_to_end(&mut reader, &mut residue);
    assert!(
        residue.len() >= 32 * 1024,
        "only {} bytes of stderr residue — the pipe never filled and the \
         backpressure this test exists to exercise never happened",
        residue.len()
    );
}

/// SIGTERM still drains, within the SAME wall
/// bound, when stderr is backpressured AND the shutdown-time wire-snapshot
/// write is refused — the ONE combination that reaches
/// `write_wire_snapshot`'s own direct `io::stderr().lock().write_all`,
/// which (unlike ordinary request logging) does not go through the lossy
/// sink's queue at all.
///
/// **Why `sigterm_drains_with_stderr_backpressured` above does not cover
/// this.** That row proves the LOSSY SINK never blocks a worker — it is
/// silent about the ONE write in this binary that bypasses the sink on
/// purpose (`write_wire_snapshot`'s own doc explains why: it runs after
/// every worker is idle, so the sink's backpressure argument does not
/// apply to IT). With no bound, that write is synchronous and
/// unbounded: on a wedged pipe it would block the very thread that is
/// about to call `std::process::exit`, so a drain that earned
/// `EXIT_DRAINED` would instead hang past this test's own [`WALL_BOUND`]
/// — the SAME failure shape a reverted lossy sink produces, on a
/// DIFFERENT write this file's other row cannot see.
///
/// **A pre-existing snapshot destination is enough to reach the direct
/// stderr write:** the destination is planted before
/// the server ever starts, so `write_server_snapshot` refuses
/// `AlreadyExists` at shutdown and `write_wire_snapshot` takes the error
/// arm — the ONLY arm that touches stderr directly.
#[test]
fn sigterm_drains_with_stderr_backpressured_and_a_refused_wire_snapshot() {
    let dir = scratch("binary-signals-backpressure-wire-snapshot");
    let (chain, key) = mint_into(&dir);
    let snapshot_dest = dir.join("wire-snapshot.json");
    std::fs::write(&snapshot_dest, b"planted before the server ever starts")
        .unwrap_or_else(|error| panic!("planting {}: {error}", snapshot_dest.display()));

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env("GRANARY_STORE", "memory:")
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", &chain)
            .env("GRANARY_TLS_KEY", &key)
            .env("GRANARY_WIRE_SNAPSHOT", &snapshot_dest)
            .env("GRANARY_WIRE_RUN_ID", "run-1")
            .env("GRANARY_WIRE_ROLE", "server")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning the binary: {error}")),
    ));

    let Some(stderr) = child.get().stderr.take() else {
        panic!("the binary was spawned without a stderr pipe")
    };

    // The SAME technique as `sigterm_drains_with_stderr_backpressured`:
    // read only up to readiness, then stop reading while KEEPING the pipe
    // open — an unread, open pipe is backpressure; a dropped reader is
    // just EPIPE.
    let mut reader = BufReader::new(stderr);
    let addr = loop {
        let mut line = String::new();
        match std::io::BufRead::read_line(&mut reader, &mut line) {
            Ok(0) => panic!("stderr ended before the readiness line"),
            Ok(_bytes) => {
                if let Some((_before, after)) = line.split_once(READY_KEY)
                    && let Some((addr, _rest)) = after.split_once('"')
                {
                    break addr.to_owned();
                }
            }
            Err(error) => panic!("reading readiness: {error}"),
        }
    };
    let addr: SocketAddr = addr
        .parse()
        .unwrap_or_else(|error| panic!("the readiness address {addr:?}: {error}"));

    // Fill the pipe with warn-level lines, exactly as the row above does.
    for _peer in 0..4000_u32 {
        if let Ok(mut stream) = std::net::TcpStream::connect(addr) {
            use std::io::Write as _;
            let _sent = stream.write_all(b"this is not a client hello");
        }
    }

    let (_hold, settle) = mpsc::channel::<()>();
    let _elapsed = settle.recv_timeout(SETTLE);

    let pid = child.get().id();
    let delivered = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap_or_else(|error| panic!("/bin/kill -TERM: {error}"));
    assert!(delivered.success(), "/bin/kill -TERM {pid} failed");

    let empty = Arc::new(Mutex::new(String::new()));
    let status = wait_within(child.take(), WALL_BOUND, &empty);
    assert_eq!(
        status.code(),
        Some(EXIT_DRAINED),
        "SIGTERM must drain even with stderr backpressured AND a refused \
         wire-snapshot write, not {status:?} — a hang here means \
         write_wire_snapshot's own stderr write blocked the exit"
    );

    // The SAME vacuity guard: prove the pipe really was under pressure.
    let mut residue = Vec::new();
    let _rest = std::io::Read::read_to_end(&mut reader, &mut residue);
    assert!(
        residue.len() >= 32 * 1024,
        "only {} bytes of stderr residue — the pipe never filled and the \
         backpressure this test exists to exercise never happened",
        residue.len()
    );
}

/// The wall bound on the upload arm, which must OUTLAST the drain
/// deadline rather than race it: a server that holds the upload runs the
/// deadline out and exits 3, and this bound has to let that happen so the
/// row reads an exit CODE rather than a timeout.
const UPLOAD_WALL_BOUND: Duration = Duration::from_secs(25);

/// How long the parent waits for a response the server must not send
/// while it is still reading the request content. A NEGATIVE bound: the
/// event is one a correct server does not produce here, so a short value
/// cannot flake.
const BEAT: Duration = Duration::from_millis(400);

/// A grammatical `{grain-id}`: sixty-four lowercase hex digits. The
/// content that would hash to it never arrives, which is the point — the
/// row is about a body still in flight, not about what it contains.
const GRAIN_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// SIGTERM during an in-flight UPLOAD drains, rather than running the
/// drain deadline out and killing the process.
///
/// **A regression the write path can introduce and nothing else can
/// see.** While every request was answered before its content was read,
/// the longest a connection could hold the drain was the refusal drain's
/// two seconds, comfortably inside `SHUTDOWN_DEADLINE`. An accepted write
/// is bounded by a clock that is LONGER than that deadline, so an
/// ordinary slow-but-legitimate upload — an honest client on a thin link,
/// not an attacker — keeps its connection resident past the deadline, and
/// the deadline's contract is `std::process::exit`. A deploy would then
/// take the hard-exit path on every SIGTERM that lands during a publish,
/// dropping the rest of the in-flight work with it.
///
/// **The park proof is the ABSENCE of an answer.** The request target is
/// grammatical and the method is defined, so a gate refusal would be
/// answered at once; nothing arriving within [`BEAT`] means the server is
/// inside the counting accept with the body still open. Without that
/// check a SIGTERM landing after the request had already been answered
/// would drain an idle server and pass while proving nothing.
#[test]
fn sigterm_drains_during_an_in_flight_upload() {
    let dir = scratch("binary-signals-upload");
    let (chain, key) = mint_into(&dir);

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env("GRANARY_STORE", "memory:")
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", &chain)
            .env("GRANARY_TLS_KEY", &key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning the binary: {error}")),
    ));

    let Some(stderr) = child.get().stderr.take() else {
        panic!("the binary was spawned without a stderr pipe")
    };
    let log = Arc::new(Mutex::new(String::new()));
    let addr = read_readiness(stderr, &log);
    let addr: SocketAddr = addr
        .parse()
        .unwrap_or_else(|error| panic!("the readiness address {addr:?}: {error}"));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("parent runtime: {error}"));

    // The connection outlives the shutdown deliberately: the upload must
    // still be in flight when the drain starts, and a client that has gone
    // away is a connection the server could legitimately have finished
    // with.
    let held = runtime.block_on(async {
        let mut stream = tls_connect(addr, &chain).await;
        let head = format!(
            "PUT /bin/{GRAIN_ID} HTTP/1.1\r\nhost: {HOST}\r\ntransfer-encoding: chunked\r\n\r\n"
        );
        // A head and ONE small chunk: enough that the server is inside the
        // counting accept, nowhere near enough to end the body.
        stream
            .write_all(head.as_bytes())
            .await
            .unwrap_or_else(|error| panic!("write head: {error}"));
        stream
            .write_all(b"10\r\n0123456789abcdef\r\n")
            .await
            .unwrap_or_else(|error| panic!("write chunk: {error}"));
        stream
            .flush()
            .await
            .unwrap_or_else(|error| panic!("flush: {error}"));

        let mut sink = [0_u8; 256];
        let answered = tokio::time::timeout(BEAT, stream.read(&mut sink)).await;
        assert!(
            answered.is_err(),
            "the server answered within {BEAT:?}, so the upload is not in \
             flight and the SIGTERM below would land on an idle server: {answered:?}"
        );
        stream
    });

    let pid = child.get().id();
    let delivered = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap_or_else(|error| panic!("/bin/kill -TERM: {error}"));
    assert!(delivered.success(), "/bin/kill -TERM {pid} failed");

    let status = wait_within(child.take(), UPLOAD_WALL_BOUND, &log);
    assert_eq!(
        status.code(),
        Some(EXIT_DRAINED),
        "SIGTERM during an in-flight upload must DRAIN, not {status:?} — the \
         accept clock is longer than the drain deadline, so an upload the \
         drain cannot abandon runs that deadline out and forces the exit \
         path that exists for undrained work\n--- binary stderr ---\n{}",
        captured(&log)
    );

    drop(held);
    drop(runtime);
}

/// A TLS-1.3 client trusting exactly the anchor `mint_into` wrote, and
/// offering exactly `http/1.1` — the accept path refuses a connection
/// whose negotiated token it does not admit, so the ALPN is not optional.
async fn tls_connect(addr: SocketAddr, trust: &Path) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    let anchors = CertificateDer::pem_file_iter(trust)
        .unwrap_or_else(|error| panic!("opening {}: {error}", trust.display()));
    for anchor in anchors {
        let anchor = anchor.unwrap_or_else(|error| panic!("reading {}: {error}", trust.display()));
        roots
            .add(anchor)
            .unwrap_or_else(|error| panic!("trusting the anchor: {error}"));
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

    let name = ServerName::try_from(HOST).unwrap_or_else(|error| panic!("server name: {error}"));
    let stream = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|error| panic!("connect {addr}: {error}"));
    TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .unwrap_or_else(|error| panic!("tls connect: {error}"))
}

/// Start the shipped binary, wait for it to say it is listening, deliver
/// `signal`, and require a clean drained exit.
/// SIGKILLs the child if the test unwinds before `take()` — a panic in
/// any assertion between spawn and wait would otherwise leave a live
/// server (bound port, reader thread and all) running until the CI
/// runner reaps orphans. `Child`'s own drop neither signals nor waits.
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

fn drains_on(signal: &str) {
    let dir = scratch(&format!("binary-signals-{signal}"));
    let (chain, key) = mint_into(&dir);

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env("GRANARY_STORE", "memory:")
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", &chain)
            .env("GRANARY_TLS_KEY", &key)
            // Pinned rather than inherited: the readiness line is an INFO
            // record, and a `RUST_LOG` in the ambient environment would
            // otherwise decide whether this test can see it.
            .env("RUST_LOG", "info")
            // Nothing reads stdout, so nothing may buffer into it: a piped
            // fd nobody drains deadlocks the child once the pipe fills.
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning the binary: {error}")),
    ));

    let Some(stderr) = child.get().stderr.take() else {
        panic!("the binary was spawned without a stderr pipe")
    };

    let log = Arc::new(Mutex::new(String::new()));
    let addr = read_readiness(stderr, &log);
    assert!(
        addr.parse::<std::net::SocketAddr>().is_ok(),
        "the readiness line must carry the BOUND address, not {addr:?} — port 0 is what \
         was asked for and the resolved port is the only thing that proves a bind happened"
    );

    // Park proof: the exit below must be CAUSED by the signal, and the only
    // cheap evidence is that the process is still alive a beat after
    // readiness. Without this, a shutdown trigger that fires spuriously at
    // startup drains the empty server and exits 0 before the kill — which
    // then lands on the zombie, succeeds, and both arms stay green with the
    // signal path never exercised. (`recv_timeout` on a channel nobody
    // sends on is the bounded pause; `std::thread::sleep` is banned.)
    let (_hold, settle) = mpsc::channel::<()>();
    let _elapsed = settle.recv_timeout(SETTLE);
    let early = child
        .get()
        .try_wait()
        .unwrap_or_else(|error| panic!("try_wait: {error}"));
    assert!(
        early.is_none(),
        "the binary exited {early:?} within {SETTLE:?} of readiness, BEFORE any signal was \
         sent — a spurious shutdown trigger, and the SIG{signal} below would prove nothing\n\
         --- binary stderr ---\n{}",
        captured(&log)
    );

    let pid = child.get().id();
    let delivered = Command::new("/bin/kill")
        .args([&format!("-{signal}"), &pid.to_string()])
        .status()
        .unwrap_or_else(|error| panic!("/bin/kill -{signal}: {error}"));
    assert!(
        delivered.success(),
        "/bin/kill -{signal} {pid} failed: {delivered:?}"
    );

    let status = wait_within(child.take(), WALL_BOUND, &log);
    assert_eq!(
        status.code(),
        Some(EXIT_DRAINED),
        "SIG{signal} must drain the binary clean, not {status:?}\n\
         --- binary stderr ---\n{}",
        captured(&log)
    );
}

/// Read the bound address out of `main`'s JSON readiness line, draining
/// the rest of stderr into `log` so a failure can print it.
fn read_readiness(stderr: std::process::ChildStderr, log: &Arc<Mutex<String>>) -> String {
    let (sender, receiver) = mpsc::channel();
    let drained = Arc::clone(log);
    let _reader = std::thread::spawn(move || {
        let mut announced = false;
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            // A poisoned lock still appends — `captured` recovers the
            // same way, and a diagnostics log that silently truncates at
            // a poisoning point hides exactly the line someone needs.
            let mut held = match drained.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            held.push_str(&line);
            held.push('\n');
            drop(held);
            if !announced
                && let Some((_before, after)) = line.split_once(READY_KEY)
                && let Some((addr, _rest)) = after.split_once('"')
            {
                announced = sender.send(addr.to_owned()).is_ok();
            }
        }
    });

    match receiver.recv_timeout(WALL_BOUND) {
        Ok(addr) => addr,
        Err(error) => panic!(
            "no readiness line within {WALL_BOUND:?}: {error}\n--- binary stderr ---\n{}",
            captured(log)
        ),
    }
}

/// Wait for `child` within `bound`, killing it if the bound expires.
fn wait_within(child: Child, bound: Duration, log: &Arc<Mutex<String>>) -> ExitStatus {
    let mut child = process::ChildGuard(child);
    match child.wait_within(bound) {
        Ok(Some(status)) => status,
        Err(error) => panic!("waiting for the child: {error}"),
        Ok(None) => {
            panic!(
                "the binary ignored the signal for {bound:?}\n--- binary stderr ---\n{}",
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

/// Mint a self-signed leaf into `dir` as the PEM pair the binary reads,
/// and return the two paths.
fn mint_into(dir: &Path) -> (PathBuf, PathBuf) {
    let key_pair = rcgen::KeyPair::generate().unwrap_or_else(|error| panic!("keypair: {error}"));
    let mut params = rcgen::CertificateParams::new(vec![HOST.to_owned(), "127.0.0.1".to_owned()])
        .unwrap_or_else(|error| panic!("params: {error}"));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOST);
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let leaf = params
        .self_signed(&key_pair)
        .unwrap_or_else(|error| panic!("self-sign: {error}"));

    let chain = dir.join("chain.pem");
    let key = dir.join("key.pem");
    std::fs::write(&chain, leaf.pem())
        .unwrap_or_else(|error| panic!("writing {}: {error}", chain.display()));
    std::fs::write(&key, key_pair.serialize_pem())
        .unwrap_or_else(|error| panic!("writing {}: {error}", key.display()));
    (chain, key)
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
