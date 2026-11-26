// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SHIPPED binary reads the store schema and threads the seam-dispatch
//! deadline into its service.
//!
//! **A unit-tested `store_from_env` that `main.rs` never calls passes
//! every row in `src/config.rs` and serves nothing.** That is the whole
//! reason this file drives `CARGO_BIN_EXE_granary-server` rather than the
//! library: what is under test is the WIRING — that the composition root
//! asks `config` for the store at all, and that the deadline it gets back
//! reaches the service it builds. Neither fact is visible from inside the
//! crate, and both are exactly what a refactor drops silently.
//!
//! **The positive arm is `s3:`, and the discriminator is that it STARTS.**
//! Until this landed, `main.rs` refused every value but `memory:` before
//! it bound a socket — so a readiness line under `GRANARY_STORE=s3:` is
//! not a weak signal, it is a state the previous binary could not reach.
//! The store constructs lazily, so pointing it at an endpoint that never
//! answers changes nothing about startup and everything about the first
//! request.
//!
//! **The endpoint is a listener THIS TEST owns, which accepts and then
//! says nothing.** Not an unroutable address: a blackholed IP depends on
//! the machine's routing table (offline, it is an instant
//! `EHOSTUNREACH`), and a refused port fails fast enough that
//! `object_store`'s retry budget can expire well inside thirty seconds.
//! A socket that is accepted and never answered is a stall this file
//! creates rather than hopes for.
//!
//! **BOTH a read and a write, because they take different routes out of
//! the store.** `object_store`'s retry loop re-runs an idempotent
//! request on its own expiry and gives up on a non-idempotent one
//! (`client/retry.rs`, the `HttpErrorKind::Timeout` arm). A listing is a
//! safe method and is retried, so the seam call stays pending and the dispatch deadline
//! answers; a conditional `PUT` — which is every write this server makes
//! — is marked `idempotent(false)` by `aws/mod.rs`, so its single
//! attempt ERRORS and whatever the store says becomes the wire status.
//! At `object_store` 0.14.1's INHERITED default the store's per-request
//! clock was thirty seconds, the same figure as
//! [`STORE_DISPATCH_DEADLINE`], and the tie went to the inner future:
//! **MEASURED, 2026-08-19**, the write arm returned `HTTP/1.1 500
//! Internal Server Error` with `granary-error: internal` after 30.66 s.
//! `STORE_CLIENT_TIMEOUT` pins that clock ABOVE the dispatch deadline,
//! so the dispatch deadline owns the refusal token on both routes — and the
//! write arm below is the row that says so.
//!
//! **The write arm is `PUT meta`, chosen for what it does NOT engage.**
//! §5.10's `503`/`unavailable` has four producers in this server —
//! dispatch-deadline expiry and three others — and a row that cannot tell them
//! apart proves nothing about the dispatch deadline:
//!
//! - the verify permit — `verifies()` is `Operation::PutBin` and
//!   nothing else, so a `PUT meta` never queues for one;
//! - the write budget and the whole-accept clock — both need the
//!   request content to be large or late, and this one is a few dozen
//!   bytes written and flushed in full before the park proof begins;
//! - and mechanically, both of those render `Drain::Overflowed`, which
//!   puts `Connection: close` on the response. Dispatch-deadline expiry renders
//!   `Drained`. **Asserting the header is ABSENT is therefore the
//!   discriminator**, not decoration — and it also enforces the requirement
//!   to answer a stall with a status rather than tearing the connection down.
//!
//! The write arm sends NO `connection: close` of its own for exactly
//! that reason: hyper echoes the request's close token onto the
//! response, which would make the discriminator unreadable.
//!
//! **Both arms run CONCURRENTLY against one server**, on two connections
//! and two OS threads driving the same runtime. The two seam calls stall
//! inside one thirty-second window instead of two, so the file's cost is
//! one deadline rather than the sum of the arms.
//!
//! **The park proof covers the other direction**: an answer arriving in
//! the first seconds would mean the store failed instead of stalling,
//! and the row goes red rather than passing on the wrong `503`. On the
//! write arm it covers one more thing — §5.3 refuses a `{grain-id}` that
//! does not address the body (`Outcome::address_mismatch`) BEFORE the
//! seam and in microseconds, so a stale body here trips the proof rather
//! than passing on a fast `400`.

#![cfg(unix)]

mod process;

use std::io::{BufRead as _, BufReader, Read as _};
use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use granary_core::hash::GrainId;
use granary_net::alpn::ALPN_HTTP11;
use granary_server::EXIT_STARTUP_FAILED;
use granary_server::config::{
    ENV_AWS_ACCESS_KEY_ID, ENV_AWS_SECRET_ACCESS_KEY, ENV_STORE, ENV_STORE_BUCKET,
    ENV_STORE_ENDPOINT, ENV_STORE_REGION, STORE_DISPATCH_DEADLINE, STORE_MEMORY, STORE_S3,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The JSON key `main`'s readiness line carries the bound address under.
const READY_KEY: &str = "\"addr\":\"";

/// The name the in-test certificate carries.
const HOST: &str = "localhost";

/// How long start-to-readiness may take.
const READY_BOUND: Duration = Duration::from_secs(20);

/// How long the request may take: the dispatch deadline's OWN figure plus slack, and the
/// figure is imported rather than restated so a change to the constant
/// cannot leave this bound describing the old one.
const WRITE_BOUND: Duration = Duration::from_secs(STORE_DISPATCH_DEADLINE.as_secs() + 25);

/// The credential in the ambient proxy URL the S3 row sets; it must never
/// appear in the server's output.
const PROXY_SECRET: &str = "proxy-secret-must-not-print";

/// How long the server must demonstrably stay SILENT before the answer
/// is credited to the deadline. A negative bound on an event a correct
/// server does not produce here, so a short value cannot flake — and an
/// instant `500` from a store that errored rather than stalled trips it.
const PARK_PROOF: Duration = Duration::from_secs(3);

/// **The shipped binary opens an `s3:` store and bounds its dispatch.**
#[test]
fn the_shipped_binary_serves_the_s3_form_and_answers_503_on_a_stalled_store() {
    let dir = scratch("shipped-store-config-s3");
    let (chain, key) = mint_into(&dir);
    let stall = Stall::listening();

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env(ENV_STORE, STORE_S3)
            .env(ENV_STORE_BUCKET, "granary")
            .env(ENV_STORE_ENDPOINT, format!("http://{}", stall.addr))
            .env(ENV_STORE_REGION, "us-east-1")
            .env(ENV_AWS_ACCESS_KEY_ID, "an-id")
            .env(ENV_AWS_SECRET_ACCESS_KEY, "a-secret")
            // An ambient proxy the store must ignore, carrying a credential
            // the log must never show. The endpoint is plain HTTP, so this is
            // the variable reqwest would read; the exclusions and the CGI
            // marker are removed so an inherited one cannot bypass it.
            .env(
                "HTTP_PROXY",
                format!("http://proxy-user:{PROXY_SECRET}@127.0.0.1:9"),
            )
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("REQUEST_METHOD")
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
    // THE FIRST ASSERTION, and it is the one about `store_from_env`
    // being called at all: the previous binary exited 2 on this
    // environment before it ever bound a socket.
    let addr = read_readiness(stderr, &log);
    let addr: SocketAddr = addr
        .parse()
        .unwrap_or_else(|error| panic!("the readiness address {addr:?}: {error}"));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("parent runtime: {error}"));

    // The two arms, issued CONCURRENTLY on their own connections so both
    // seam calls stall inside ONE deadline window. `Handle::block_on`
    // from a plain thread drives each future while the runtime's worker
    // threads carry the reactor; `tokio::join!` would be the obvious
    // spelling and is banned workspace-wide, `tokio::spawn`
    // with it.
    let handle = runtime.handle();
    let read_request = max_seq_request();
    let write_request = meta_write_request();
    let (read_arm, write_arm) = std::thread::scope(|threads| {
        let reader =
            threads.spawn(|| handle.block_on(probe(addr, &chain, "GET max-seq", &read_request)));
        let writer =
            threads.spawn(|| handle.block_on(probe(addr, &chain, "PUT meta", &write_request)));
        (joined(reader.join()), joined(writer.join()))
    });

    the_store_went_direct_and_startup_reported_the_proxy(&stall, &log);

    // THE READ ARM FIRST, and it is a REGRESSION row. This path already
    // answered `503` before the client's own clock was pinned, so a
    // failure here says the pin moved something that was not broken.
    let read_seen = read_arm
        .unwrap_or_else(|reason| panic!("{reason}\n--- binary stderr ---\n{}", captured(&log)));
    assert!(
        read_seen.starts_with("HTTP/1.1 503 "),
        "a store that never answers is §5.10's refusing load, not {read_seen:?}\n\
         --- binary stderr ---\n{}",
        captured(&log)
    );
    assert!(
        read_seen
            .to_ascii_lowercase()
            .contains("granary-error: unavailable"),
        "the §8.2 token must be `unavailable`: {read_seen:?}"
    );

    // THE WRITE ARM must also report the stalled store as unavailable.
    let write_seen = write_arm
        .unwrap_or_else(|reason| panic!("{reason}\n--- binary stderr ---\n{}", captured(&log)));
    assert!(
        write_seen.starts_with("HTTP/1.1 503 "),
        "a write against a store that never answers is §5.10's refusing \
         load — `unavailable` (retry later), never `internal` (this server \
         has a defect). Got {write_seen:?}; the read arm saw {read_seen:?}\n\
         --- binary stderr ---\n{}",
        captured(&log)
    );
    assert!(
        write_seen
            .to_ascii_lowercase()
            .contains("granary-error: unavailable"),
        "the §8.2 token must be `unavailable`: {write_seen:?}"
    );
    // THE DISCRIMINATOR: a stall gets a status. Dispatch-deadline expiry renders
    // `Drain::Drained`; the write budget, the whole-accept clock and
    // every other over-cap refusal render `Drain::Overflowed`, which puts
    // `Connection: close` on the response. Its absence is what says this
    // `503` came from the deadline and not from a shed — and that the
    // answer to a stall is a STATUS rather than a tear-down.
    assert!(
        !write_seen.to_ascii_lowercase().contains("\r\nconnection:"),
        "`Connection: close` means the answer came from an over-cap drain \
         (the write budget or the accept clock), not from the dispatch deadline — and a \
         tear-down is not how a stall is answered: \
         {write_seen:?}"
    );

    let pid = child.get().id();
    let _delivered = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let _status = wait_within(child.take(), READY_BOUND, &log);
    drop(runtime);
    drop(stall);
}

/// **An unknown discriminant refuses to start, naming the variable.**
///
/// The binary must refuse an unknown store form, so this test drives
/// the process entry point with `GRANARY_STORE=disk:`.
#[test]
fn an_unknown_store_form_refuses_to_start_naming_the_variable() {
    let dir = scratch("shipped-store-config-unknown");
    let (chain, key) = mint_into(&dir);

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env(ENV_STORE, "disk:")
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

    // BOUNDED, not `Command::output()`. The regression this arm exists
    // to catch — a `main` that stopped consulting `config` and served
    // `disk:` anyway — produces a process that never exits, and
    // `output()` would then wait on it forever: a gate that fails by
    // HANGING reports nothing at all.
    let log = Arc::new(Mutex::new(String::new()));
    let drained = Arc::clone(&log);
    let (at_eof, drained_fully) = mpsc::channel();
    let _reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            let mut held = match drained.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            held.push_str(&line);
            held.push('\n');
        }
        let _delivered = at_eof.send(());
    });

    let status = wait_within(child.take(), READY_BOUND, &log);
    // **Wait for the PIPE, not only for the process.** A child can exit
    // with its last lines still in the pipe and the reader thread not
    // yet scheduled — which under a loaded parallel run is exactly what
    // happens, and the assertions below would then read an empty log and
    // report a refusal that did not name its variable. Bounded rather
    // than `join()`ed for the same reason this arm does not use
    // `Command::output()`: a wait with no bound reports nothing.
    let _drained = drained_fully.recv_timeout(READY_BOUND);
    assert_eq!(
        status.code(),
        Some(EXIT_STARTUP_FAILED),
        "a store form this build cannot open is a startup refusal, not {status:?}"
    );
    let stderr = captured(&log);
    assert!(
        stderr.contains(ENV_STORE),
        "the refusal must name the variable at fault: {stderr}"
    );
    assert!(
        stderr.contains("disk:"),
        "and the value it carried: {stderr}"
    );
}

/// An out-of-vocabulary `GRANARY_WIRE_ROLE` refuses to
/// start, naming the trio — and does so BEFORE the listener ever binds,
/// exactly the process-level shape
/// `an_unknown_store_form_refuses_to_start_naming_the_variable` above
/// proves for the store. `wire_snapshot_env`'s own doc claims this is a
/// startup refusal "like any other misconfigured variable, never a
/// failure discovered only after a whole run has already been served" —
/// this row checks the refusal through the process entry point with
/// a malformed role value.
///
/// The store is `memory:` — legal — so a bad role is the ONLY possible
/// refusal reason a passing row could report.
#[test]
fn a_role_outside_the_closed_vocabulary_refuses_to_start_before_serving() {
    let dir = scratch("shipped-wire-snapshot-bad-role");
    let (chain, key) = mint_into(&dir);
    let snapshot_dest = dir.join("wire-snapshot.json");

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env(ENV_STORE, STORE_MEMORY)
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", &chain)
            .env("GRANARY_TLS_KEY", &key)
            .env("GRANARY_WIRE_SNAPSHOT", &snapshot_dest)
            .env("GRANARY_WIRE_RUN_ID", "run-1")
            .env("GRANARY_WIRE_ROLE", "not-a-real-role")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning the binary: {error}")),
    ));
    let Some(stderr) = child.get().stderr.take() else {
        panic!("the binary was spawned without a stderr pipe")
    };

    // Bounded, not `Command::output()` — the same reason the store row
    // above gives: a `main` that stopped validating VALUES here would
    // start the listener and never exit, and an unbounded wait would
    // then hang forever instead of reporting the regression.
    let log = Arc::new(Mutex::new(String::new()));
    let drained = Arc::clone(&log);
    let (at_eof, drained_fully) = mpsc::channel();
    let _reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            let mut held = match drained.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            held.push_str(&line);
            held.push('\n');
        }
        let _delivered = at_eof.send(());
    });

    let status = wait_within(child.take(), READY_BOUND, &log);
    let _drained = drained_fully.recv_timeout(READY_BOUND);
    assert_eq!(
        status.code(),
        Some(EXIT_STARTUP_FAILED),
        "a malformed GRANARY_WIRE_ROLE is a startup refusal, not {status:?} — \
         a process that instead bound a listener and served would mean the \
         VALUE was never checked before the process ran, only its presence"
    );
    let stderr = captured(&log);
    assert!(
        stderr.contains("GRANARY_WIRE_RUN_ID") || stderr.contains("GRANARY_WIRE_ROLE"),
        "the refusal must name the trio at fault: {stderr}"
    );
    assert!(
        stderr.contains("not-a-real-role"),
        "and the value that failed the closed vocabulary: {stderr}"
    );
    assert!(
        !snapshot_dest.exists(),
        "a startup refusal must create no snapshot file — the request \
         never reached write_server_snapshot, and nothing should have \
         written to this path at all"
    );
}

/// `GRANARY_WIRE_SNAPSHOT=""` — an unexpanded
/// shell variable's shape — refuses to start, naming the path, rather
/// than passing startup and only producing a symptom at shutdown: a stray
/// `.tmp` in the server's OWN current working directory and a silent
/// non-write at `EXIT_DRAINED`.
///
/// The store is `memory:` and the run id/role are both legal, so an
/// empty PATH is the only possible refusal reason a passing row could
/// report.
#[test]
fn an_empty_wire_snapshot_path_refuses_to_start_before_serving() {
    let dir = scratch("shipped-wire-snapshot-empty-path");
    let (chain, key) = mint_into(&dir);

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env(ENV_STORE, STORE_MEMORY)
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", &chain)
            .env("GRANARY_TLS_KEY", &key)
            .env("GRANARY_WIRE_SNAPSHOT", "")
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

    let log = Arc::new(Mutex::new(String::new()));
    let drained = Arc::clone(&log);
    let (at_eof, drained_fully) = mpsc::channel();
    let _reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            let mut held = match drained.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            held.push_str(&line);
            held.push('\n');
        }
        let _delivered = at_eof.send(());
    });

    let status = wait_within(child.take(), READY_BOUND, &log);
    let _drained = drained_fully.recv_timeout(READY_BOUND);
    assert_eq!(
        status.code(),
        Some(EXIT_STARTUP_FAILED),
        "an empty GRANARY_WIRE_SNAPSHOT is a startup refusal, not {status:?} — a \
         process that instead bound a listener and served would mean the PATH \
         was never checked, only run_id/role"
    );
    let stderr = captured(&log);
    assert!(
        stderr.contains("GRANARY_WIRE_SNAPSHOT"),
        "the refusal must name the variable at fault: {stderr}"
    );
    // If startup accepts an empty snapshot path, shutdown creates a
    // stray `.tmp` in the process's CWD at shutdown. A startup refusal
    // must not reach far enough to create anything, anywhere, so this
    // checks the one directory this test owns and controls.
    let stray: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        stray.iter().all(|name| {
            let name = name.to_string_lossy();
            name == "chain.pem" || name == "key.pem"
        }),
        "a startup refusal must create nothing beyond the fixture's own \
         chain/key files: {stray:?}"
    );
}

/// A `GRANARY_WIRE_SNAPSHOT` that is SET but not
/// valid UTF-8 refuses to start, naming the variable — rather than
/// being read the way `std::env::var(..).ok()` reads it, which maps
/// `VarError::NotUnicode` onto the SAME `None` as a genuinely unset
/// variable. With `GRANARY_WIRE_RUN_ID`/`GRANARY_WIRE_ROLE` both
/// genuinely unset, this is the sharpest form of that conflation: read
/// that way, this exact input lands in the `(None, None, None)` arm and
/// the process runs the WHOLE instrumented run uninstrumented and
/// silent, exiting 0.
#[test]
fn a_non_utf8_wire_snapshot_path_refuses_to_start_naming_the_variable() {
    use std::os::unix::ffi::OsStrExt as _;

    let dir = scratch("shipped-wire-snapshot-non-utf8-path");
    let (chain, key) = mint_into(&dir);
    // A byte string that is not valid UTF-8 in any encoding: 0xFF and
    // 0xFE are not valid UTF-8 leading or continuation bytes anywhere.
    let bad_path = std::ffi::OsStr::from_bytes(b"/tmp/snapshot-\xff\xfe.json");

    let mut child = Reaped(Some(
        Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env(ENV_STORE, STORE_MEMORY)
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", &chain)
            .env("GRANARY_TLS_KEY", &key)
            .env("GRANARY_WIRE_SNAPSHOT", bad_path)
            .env_remove("GRANARY_WIRE_RUN_ID")
            .env_remove("GRANARY_WIRE_ROLE")
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
    let drained = Arc::clone(&log);
    let (at_eof, drained_fully) = mpsc::channel();
    let _reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            let mut held = match drained.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            held.push_str(&line);
            held.push('\n');
        }
        let _delivered = at_eof.send(());
    });

    let status = wait_within(child.take(), READY_BOUND, &log);
    let _drained = drained_fully.recv_timeout(READY_BOUND);
    assert_eq!(
        status.code(),
        Some(EXIT_STARTUP_FAILED),
        "a set-but-non-UTF-8 GRANARY_WIRE_SNAPSHOT is a startup refusal, not \
         {status:?} — a process that instead bound a listener and served would \
         mean the byte-lossy variable was silently read as UNSET"
    );
    let stderr = captured(&log);
    assert!(
        stderr.contains("GRANARY_WIRE_SNAPSHOT"),
        "the refusal must name the variable that is set but unreadable: {stderr}"
    );
    assert!(
        stderr.contains("UTF-8") || stderr.contains("utf-8") || stderr.contains("Utf8"),
        "the refusal should say WHY: {stderr}"
    );
}

/// How many refusals are raced at once.
///
/// **Sized by MEASUREMENT, not by taste.** The regression this row
/// exists to catch — `startup_failure` reverted to `tracing::error!`
/// through the lossy sink — loses the reason on a spawn only when the
/// process exits before the sink's writer thread is scheduled, so ONE
/// spawn under an idle machine catches it about once in two hundred
/// tries. `an_unknown_store_form_refuses_to_start_naming_the_variable`
/// is exactly that one spawn, and it stayed green 30/30 targeted and
/// 5/5 full-suite with the regression applied. Contention is the whole
/// instrument: at this fanout the same revert loses the reason on a
/// large fraction of the spawns, and the assertion is over ALL of them.
///
/// **MEASURED, 2026-08-20**, with the revert applied and this row at
/// thirty-two: 11/32, 23/32 and 23/32 spawns exited
/// [`EXIT_STARTUP_FAILED`] with an empty stderr, on three consecutive
/// runs — a per-spawn loss between a third and three quarters, so the
/// row fails on every attempt rather than most of them. Sixteen would
/// very probably do; thirty-two costs 0.6 s instead of 0.4 s and buys
/// the margin, which matters because the alternative to a reliable
/// failure here is a row that reports the regression as a flake. Over
/// the same twenty runs the single-spawn row above passed 20/20 with
/// the identical revert in place.
const REFUSAL_FANOUT: usize = 32;

/// **Every startup refusal reaches the operator, under CONTENTION.**
///
/// An operator holding exit `2` and an empty stderr cannot tell which
/// variable is wrong — every startup failure exits the same
/// [`EXIT_STARTUP_FAILED`], so on this path the reason string is the
/// only discriminator there is. `main.rs` records the measurement that
/// made the direct write necessary; this is its runnable counterpart,
/// because a measurement living only in a doc comment is a claim the
/// suite cannot re-check.
///
/// **Cheap on purpose.** A bad `GRANARY_STORE` discriminant is refused
/// immediately after the TLS material loads, so each child is a
/// sub-hundred-millisecond process and the whole row costs one batch of
/// them rather than a deadline.
///
/// **Every spawn is asserted, not a quorum.** A row that tolerated one
/// silent refusal would be describing the regression rather than
/// catching it.
#[test]
fn every_startup_refusal_carries_its_reason_under_parallel_spawns() {
    let dir = scratch("shipped-store-config-fanout");
    let (chain, key) = mint_into(&dir);

    // SPAWNED FIRST, ALL OF THEM, then collected: the children have to
    // contend with each other, which they cannot do if each is waited
    // on before the next starts.
    let mut spawned: Vec<Spawned> = (0..REFUSAL_FANOUT)
        .map(|_| Spawned::refusing(&chain, &key))
        .collect();

    // EACH PIPE ON ITS OWN THREAD, AND EVERY CHILD STAYS HERE.
    // `wait_with_output` would read to EOF and reap in one call — and
    // would move the handle into the thread with it, leaving this row
    // nothing to signal on the timeout branch but pids captured at
    // spawn, an unknown subset of which the collectors have already
    // reaped. Draining the pipe is the half that needs a thread; the
    // reap is this thread's, one child at a time, and only once that
    // child's pipe has ended.
    let (sender, receiver) = mpsc::channel();
    for (index, one) in spawned.iter_mut().enumerate() {
        let stderr = one.stderr();
        let sender = sender.clone();
        let _collector = std::thread::spawn(move || {
            let mut read = Vec::new();
            let outcome = BufReader::new(stderr).read_to_end(&mut read);
            let _delivered = sender.send((index, outcome.map(|_count| read)));
        });
    }
    drop(sender);

    // BOUNDED, for the reason the single-spawn row above states: the
    // regression that makes a child never exit would turn an unbounded
    // wait into a gate that reports nothing at all. The bound is on the
    // PIPE, which is the same bound: a child that never exits never
    // closes its stderr, so it never reaches the reap below. And the
    // pipe is read to EOF before the reap, so a reason still in flight
    // when the process exits is still collected — which is what makes a
    // MISSING reason a real loss rather than a race in this test.
    let mut collected: Vec<(Vec<u8>, ExitStatus)> = Vec::with_capacity(REFUSAL_FANOUT);
    for _ in 0..REFUSAL_FANOUT {
        match receiver.recv_timeout(READY_BOUND) {
            Ok((index, Ok(stderr))) => {
                let one = spawned.get_mut(index).unwrap_or_else(|| {
                    panic!("a collector reported an index this row never spawned: {index}")
                });
                collected.push((stderr, one.reap()));
            }
            Ok((_index, Err(error))) => panic!("reading a refusing binary's stderr: {error}"),
            Err(expired) => {
                let signalled = kill_unreaped(&mut spawned);
                panic!(
                    "only {} of {REFUSAL_FANOUT} refusals finished within \
                     {READY_BOUND:?}: {expired} (SIGKILLed {} still held)",
                    collected.len(),
                    signalled.len()
                );
            }
        }
    }

    let mut silent = 0_usize;
    let mut wrong_code = 0_usize;
    let mut sample = String::new();
    for (stderr, status) in &collected {
        if status.code() != Some(EXIT_STARTUP_FAILED) {
            wrong_code += 1;
        }
        let stderr = String::from_utf8_lossy(stderr);
        if stderr.contains(ENV_STORE) && stderr.contains("disk:") {
            if sample.is_empty() {
                sample = stderr.into_owned();
            }
        } else {
            silent += 1;
        }
    }
    assert_eq!(
        wrong_code, 0,
        "{wrong_code}/{REFUSAL_FANOUT} spawns exited with something other \
         than EXIT_STARTUP_FAILED"
    );
    // POSITIVE CONTROL: at least one refusal was actually read back, so
    // a row that collected nothing at all cannot report success.
    assert!(
        !sample.is_empty(),
        "no spawn produced a readable refusal, so this row read nothing"
    );
    assert_eq!(
        silent, 0,
        "{silent}/{REFUSAL_FANOUT} spawns exited EXIT_STARTUP_FAILED with no \
         reason on stderr — an operator holding exit 2 and an empty stderr \
         cannot tell which variable is wrong. A refusal that reached the \
         operator looks like: {sample}"
    );
}

/// One spawned child of the fanout row, and the pid it was given.
///
/// **The handle is what a signal goes through; the pid is only ever
/// REPORTED.** `None` once the child has been reaped — see
/// [`kill_unreaped`] for why that distinction is the whole of this type.
#[derive(Debug)]
struct Spawned {
    child: Option<Child>,
    pid: u32,
}

impl Spawned {
    /// A child of the shipped binary that refuses its store discriminant
    /// and exits [`EXIT_STARTUP_FAILED`] in under a hundred
    /// milliseconds.
    fn refusing(chain: &Path, key: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env(ENV_STORE, "disk:")
            .env("GRANARY_LISTEN", "127.0.0.1:0")
            .env("GRANARY_TLS_CERT", chain)
            .env("GRANARY_TLS_KEY", key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning the binary: {error}"));
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
        }
    }

    /// This child's stderr pipe, for a draining thread. The CHILD is not
    /// handed over with it.
    fn stderr(&mut self) -> std::process::ChildStderr {
        self.held()
            .stderr
            .take()
            .unwrap_or_else(|| panic!("the binary was spawned without a stderr pipe"))
    }

    /// Wait for this child, CONSUMING the handle — after which its pid
    /// names nothing this row may signal.
    fn reap(&mut self) -> ExitStatus {
        let mut child = self
            .child
            .take()
            .unwrap_or_else(|| panic!("pid {} was reaped twice", self.pid));
        child
            .wait()
            .unwrap_or_else(|error| panic!("waiting for a refusing binary: {error}"))
    }

    fn held(&mut self) -> &mut Child {
        let pid = self.pid;
        self.child
            .as_mut()
            .unwrap_or_else(|| panic!("pid {pid} was already reaped"))
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _killed = child.kill();
            let _reaped = child.wait();
        }
    }
}

/// SIGKILL every child still HELD here, reaping each, and report the
/// pids signalled.
///
/// **Through the handles, never through a list captured at spawn.** A
/// `Child` that has not been waited on keeps its pid reserved: the
/// kernel holds the zombie until somebody reaps it, so the number still
/// names this child and nothing else. A reaped one reserves nothing —
/// the pid goes back to the machine, and the next process to ask may
/// already have it. A cleanup working from spawn-time pids therefore
/// aims `SIGKILL` at whatever now holds those numbers, which on a test
/// machine is another process owned by the same user.
fn kill_unreaped(spawned: &mut [Spawned]) -> Vec<u32> {
    let mut signalled = Vec::new();
    for one in spawned {
        // `take` and not `as_mut`: this both narrows the signal to the
        // children still held and leaves nothing behind for a second
        // pass to signal a second time.
        let Some(mut child) = one.child.take() else {
            continue;
        };
        let _killed = child.kill();
        let _reaped = child.wait();
        signalled.push(one.pid);
    }
    signalled
}

/// **The fanout row's cleanup never signals a pid it has already
/// reaped.**
///
/// The timeout branch SIGKILLs the children that did not finish, and the
/// list it worked from was the pids captured at spawn. By then an
/// unknown subset had been collected — and collecting REAPS, which
/// releases the pid back to the machine. Whatever holds one next is
/// owned by the same user as this test, so the signal lands and an
/// unrelated process dies.
///
/// Three children, one collected exactly as the row collects them. The
/// cleanup must report the two it still holds and nothing else: a
/// cleanup working from spawn-time pids reports three, and the third
/// names a process this test has no claim on.
///
/// **The count is not the assertion — the MEMBERSHIP is.** A row
/// asserting only "two were signalled" passes for a cleanup that
/// signalled the reaped pid and skipped a live one.
#[test]
fn the_fanout_cleanup_never_signals_a_pid_it_has_already_reaped() {
    let dir = scratch("shipped-store-config-cleanup");
    let (chain, key) = mint_into(&dir);
    let mut spawned: Vec<Spawned> = (0..3).map(|_| Spawned::refusing(&chain, &key)).collect();

    let still_held: Vec<u32> = spawned.iter().skip(1).map(|one| one.pid).collect();
    let (reaped, status) = {
        let first = spawned
            .first_mut()
            .unwrap_or_else(|| panic!("three were spawned"));
        (first.pid, first.reap())
    };
    assert_eq!(
        status.code(),
        Some(EXIT_STARTUP_FAILED),
        "the child must have refused and exited, or it was never reaped \
         and this row proves nothing"
    );

    let signalled = kill_unreaped(&mut spawned);
    assert!(
        !signalled.contains(&reaped),
        "pid {reaped} was reaped before the cleanup ran, so the kernel is \
         free to have handed it to an unrelated process owned by this user \
         — and this cleanup SIGKILLed it: {signalled:?}"
    );
    assert_eq!(
        signalled, still_held,
        "the cleanup signals exactly the children it still holds, in order"
    );
}

/// The store reached its endpoint DIRECTLY: with the ambient proxy honoured,
/// every request would have gone to the dead proxy port and the stub would
/// have seen nothing. And startup said so, naming the variable and never its
/// value.
fn the_store_went_direct_and_startup_reported_the_proxy(stall: &Stall, log: &Arc<Mutex<String>>) {
    let reached = match stall.held.lock() {
        Ok(held) => held.len(),
        Err(poisoned) => poisoned.into_inner().len(),
    };
    assert!(
        reached > 0,
        "the store never contacted its endpoint; an ambient proxy took its requests\n\
             --- binary stderr ---\n{}",
        captured(log)
    );
    let startup = captured(log);
    assert!(
        startup.contains("HTTP_PROXY") && startup.contains("ignored"),
        "startup did not report the ignored proxy variable:\n{startup}"
    );
    assert!(
        !startup.contains(PROXY_SECRET),
        "a proxy variable's VALUE reached the log:\n{startup}"
    );
}

/// A TCP listener that ACCEPTS and then says nothing — a bucket that has
/// stopped answering, built rather than hoped for.
struct Stall {
    addr: SocketAddr,
    /// Every accepted connection, held open. Dropping them would send a
    /// FIN, which is an ANSWER — the peer would see the connection close
    /// and fail fast instead of waiting.
    held: Arc<Mutex<Vec<StdTcpStream>>>,
}

impl Stall {
    fn listening() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("binding the stall listener: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("the stall listener's address: {error}"));
        let held: Arc<Mutex<Vec<StdTcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::clone(&held);
        let _acceptor = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let mut kept = match accepted.lock() {
                    Ok(kept) => kept,
                    Err(poisoned) => poisoned.into_inner(),
                };
                kept.push(stream);
            }
        });
        Self { addr, held }
    }
}

impl Drop for Stall {
    fn drop(&mut self) {
        if let Ok(mut kept) = self.held.lock() {
            kept.clear();
        }
    }
}

/// §4.2's `max-seq`: a grammatical request with no content, whose
/// handler's FIRST act is a store listing. Every refusal the gate could
/// produce is answered in microseconds, so a slow answer here is a slow
/// STORE and nothing else.
fn max_seq_request() -> Vec<u8> {
    format!("GET /volume/v1/max-seq HTTP/1.1\r\nhost: {HOST}\r\nconnection: close\r\n\r\n")
        .into_bytes()
}

/// §5.3's `PUT meta`: the WRITE route, and the one the store does not
/// retry.
///
/// The body is a few dozen bytes — far under `META_MAX_BYTES` and under
/// any granule of the write budget — so nothing between the wire
/// and the seam can refuse it, and the whole of it is written before the
/// park proof begins. The `{grain-id}` is computed FROM those bytes
/// because the handler checks the address before it dispatches; a
/// literal here would rot into an instant `400` the moment the body
/// changed, which the park proof would then report rather than silently
/// pass.
///
/// **No `connection: close`.** hyper copies the request's close token
/// onto the response, and the absence of that header is this row's
/// discriminator between the dispatch deadline's `503` and an over-cap drain's.
fn meta_write_request() -> Vec<u8> {
    let body = b"granary: the shipped write arm's meta object".to_vec();
    let id = GrainId::of(&body);
    let mut request = format!(
        "PUT /volume/v1/meta/{id} HTTP/1.1\r\nhost: {HOST}\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    request
}

/// One arm: a fresh connection, the whole request, the PARK PROOF, then
/// the response head.
///
/// Returns `Err` rather than asserting so the caller holds both arms at
/// once and can print each in the other's failure — a write arm that
/// fails while the read arm succeeded is a different defect from both
/// failing, and that distinction is lost if the first panic wins.
async fn probe(
    addr: SocketAddr,
    trust: &Path,
    arm: &str,
    request: &[u8],
) -> Result<String, String> {
    let mut stream = tls_connect(addr, trust).await;
    stream
        .write_all(request)
        .await
        .map_err(|error| format!("{arm}: writing the request: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("{arm}: flushing the request: {error}"))?;

    // PARK PROOF. The request is complete, so a server that was going to
    // answer from anything but the store has already done it. Silence
    // here is the evidence that the request is inside the seam call
    // wrapped by the dispatch deadline.
    let mut peek = [0_u8; 64];
    if let Ok(read) = tokio::time::timeout(PARK_PROOF, stream.read(&mut peek)).await {
        let seen = read.map(|n| String::from_utf8_lossy(peek.get(..n).unwrap_or(&[])).into_owned());
        return Err(format!(
            "{arm}: the server answered within {PARK_PROOF:?}, so this answer \
             is not the dispatch deadline's — and the cause is AMBIGUOUS between at least two \
             states this proof cannot separate: the request never reached the \
             store at all (a gate above the seam refused it), or it reached a \
             store that REFUSED THE ENDPOINT rather than stalling on it — \
             which is what an `http://` endpoint looks like when `allow_http` \
             was dropped, and what a wrong bucket, region or credential shape \
             looks like too. Read the status and the body before crediting \
             either: {seen:?}"
        ));
    }

    tokio::time::timeout(WRITE_BOUND, read_response(&mut stream))
        .await
        .map_err(|_expired| {
            format!(
                "{arm}: no answer within {WRITE_BOUND:?}: the shipped binary is \
                 not threading the {STORE_DISPATCH_DEADLINE:?} dispatch deadline, so a \
                 bucket that stops answering holds the connection open"
            )
        })
}

/// Re-raise a probe thread's panic in the test thread, where the harness
/// attributes it. `tls_connect` and `read_response` still panic on a
/// broken transport, and swallowing that would turn a dead connection
/// into a missing assertion.
fn joined(result: std::thread::Result<Result<String, String>>) -> Result<String, String> {
    match result {
        Ok(seen) => seen,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Read one HTTP/1.1 response head off the connection.
async fn read_response(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> String {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .unwrap_or_else(|error| panic!("reading the response: {error}"));
        if read == 0 {
            break;
        }
        seen.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&seen).into_owned()
}

/// A TLS-1.3 client trusting exactly the anchor `mint_into` wrote, and
/// offering exactly `http/1.1`.
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

/// SIGKILLs the child if the test unwinds before `take()`.
struct Reaped(Option<Child>);

impl Reaped {
    fn get(&mut self) -> &mut Child {
        self.0
            .as_mut()
            .unwrap_or_else(|| panic!("the child was already taken"))
    }
    fn take(mut self) -> Child {
        self.0
            .take()
            .unwrap_or_else(|| panic!("the child was already taken"))
    }
}

impl Drop for Reaped {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _killed = child.kill();
            let _reaped = child.wait();
        }
    }
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

    match receiver.recv_timeout(READY_BOUND) {
        Ok(addr) => addr,
        Err(error) => panic!(
            "no readiness line within {READY_BOUND:?}: {error}\n\
             --- binary stderr ---\n{}",
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

/// Mint a self-signed leaf into `dir` as the PEM pair the binary reads.
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

/// A fresh directory under cargo's per-crate test temporary.
fn scratch(name: &str) -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join(name);
    let _previous = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base)
        .unwrap_or_else(|error| panic!("scratch {}: {error}", base.display()));
    base
}
