// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::retry` — reason-scoped
//! seam retry classification.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use tokio::io::AsyncReadExt as _;
use tokio::task::JoinHandle;

// ------------------------------------------------- hand-built chains

/// An error whose `Display` lies — it renders the same three words
/// every `hyper_util::client::legacy::Error::SendRequest` does — and
/// whose `source()` carries whatever the test wants classified. This
/// is the negative control for the string-matching defect class:
/// [`classify`] must reach the same verdict regardless of what this
/// prints.
#[derive(Debug)]
struct DisplayLies {
    source: Box<dyn StdError + Send + Sync + 'static>,
}

impl std::fmt::Display for DisplayLies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "client error (SendRequest)")
    }
}

impl StdError for DisplayLies {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

/// The negative control: an io-flavoured chain renders the identical
/// `Display` text and must NOT classify as `StreamRefused` — proving
/// the two hand-built rows below are distinguished by `source()`
/// alone, matching the h2-driven pair in
/// `classification_never_reads_the_display_string`.
#[test]
fn classify_never_reads_the_display_string_io_case() {
    let chain = DisplayLies {
        source: Box::new(io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
    };
    assert_eq!(format!("{chain}"), "client error (SendRequest)");
    assert_eq!(classify(&chain), RetryClass::ConnectionFailed);
    assert!(
        !reclaimed_unsent(chain.source()),
        "an io source does not prove that hyper returned the complete request"
    );
}

// `hyper_util::client::legacy::Error` has no public constructor, so
// `is_connect()` (the connection-acquisition U1 case) has nothing
// to hand-build a test over: the ONLY way to obtain a real one is a
// real client dialling a closed or dead connection. The unit row
// `metrics_offered_bytes_count_failed_attempts_on_independent_pooled_facades`
// in `http_store/tests.rs` is the witness: a dead port makes both an
// Idempotent and a Never seam offer the body twice, which requires
// `classify_lib_error`'s `is_connect()` arm to return `Unsent`.

fn empty_request() -> hyper::Request<Empty<Bytes>> {
    hyper::Request::builder()
        .uri("/")
        .body(Empty::new())
        .unwrap_or_else(|error| panic!("request: {error}"))
}

#[tokio::test]
async fn a_reclaimed_hyper_request_is_unsent() {
    let (client, _server) = tokio::io::duplex(1024);
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(client))
            .await
            .unwrap_or_else(|error| panic!("client handshake: {error}"));
    drop(connection);

    let mut error = sender
        .try_send_request(empty_request())
        .await
        .expect_err("a sender whose connection future was dropped must return the request");
    assert!(
        error.error().is_canceled(),
        "test setup: expected hyper's canceled kind, got {:?}",
        error.error()
    );
    assert!(
        reclaimed_unsent(Some(error.error())),
        "a real canceled hyper error is the U2 proof"
    );
    assert!(
        error.take_message().is_some(),
        "the canceled dispatcher must return the complete request"
    );
}

#[tokio::test]
async fn a_non_canceled_hyper_error_is_not_unsent() {
    let (client, mut server) = tokio::io::duplex(4096);
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(client))
            .await
            .unwrap_or_else(|error| panic!("client handshake: {error}"));
    let connection = spawn(connection);
    let peer = spawn(async move {
        let mut bytes = [0_u8; 1024];
        let count = server
            .read(&mut bytes)
            .await
            .unwrap_or_else(|error| panic!("peer read: {error}"));
        assert!(count > 0, "peer must observe request bytes before closing");
    });
    let error = sender
        .send_request(empty_request())
        .await
        .expect_err("a peer closing without a response must fail the request");
    peer.await
        .unwrap_or_else(|error| panic!("peer task: {error}"));
    let _connection = connection
        .await
        .unwrap_or_else(|error| panic!("connection task: {error}"));
    assert!(
        error.is_incomplete_message() && !error.is_canceled(),
        "test setup: expected a non-canceled incomplete message, got {error:?}"
    );
    assert!(
        !reclaimed_unsent(Some(&error)),
        "a hyper error is not U2 unless its kind is canceled"
    );
}

// ------------------------------------------------ the h2 lock gate

/// The downcast in [`classify`] is sound only if hyper's h2
/// and this crate's are the SAME compiled crate — which holds only
/// if the workspace lock resolves exactly one `h2` package. Two
/// would make `downcast_ref::<h2::Error>()` fail SILENTLY: every
/// other test in this file would stay green (they all run against
/// the one h2 the workspace lock actually has today), and
/// `classify` would return `NotRetryable` forever in production —
/// fails safe (no wrongful retry), but blind (no test anywhere
/// would notice).
#[test]
fn exactly_one_h2_in_the_lock() {
    let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", lock_path.display()));
    let count = lock
        .lines()
        .filter(|line| line.trim() == "name = \"h2\"")
        .count();
    assert_eq!(
        count,
        1,
        "exactly one h2 package must resolve in the workspace lock \
         ({}) — the classifier's downcast is silently unsound \
         otherwise",
        lock_path.display()
    );
}

// -------------------------------------- a real, in-memory h2 peer
//
// h2::Error exposes no public constructor for its Reset/GoAway
// variants outside the crate (they live behind the `unstable`
// feature this workspace does not enable — h2's own Cargo.toml has
// `unstable = []`, not a default). A real wire exchange is the only
// way to hand `classify` a genuine one, so the two tests below drive
// a hand-rolled h2 client/server pair over an in-memory duplex — no
// TLS, no TCP, which is what keeps this a UNIT-level harness rather
// than a repeat of `tests/http_store.rs`'s raw-TLS stub server. That
// file is the witness for everything a real socket adds (the
// `is_remote()` GOAWAY case included, over TLS, through the shipped
// `HttpsConnector`).

/// The one spawn site in this module, mirroring `tests/http_store.rs`'s
/// identical wrapper: the lint bans `tokio::spawn` with no test
/// exemption because the sim owns its scheduler, but these tasks drive
/// in-memory protocol peers and Hyper connections standing in for a
/// layer the sim replaces rather than drives, not code the sim ever
/// replays. Routing every spawn through one wrapper keeps the exemption
/// to a single reviewable site.
#[expect(
    clippy::disallowed_methods,
    reason = "in-memory protocol peers and Hyper connections stand in for a layer the sim doesn't drive, following tests/http_store.rs's spawn()"
)]
fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

/// What the in-memory server side of [`one_client_h2_error`] does
/// before the client's `ResponseFuture` is expected to fail. The
/// reset variants carry a `Reason` rather than hard-coding one:
/// CLASS A's predicate has TWO independent conjuncts (`is_remote()`
/// and the reason code), and pinning each one separately needs a
/// row that isolates it — a REMOTE reset with the WRONG reason, and
/// a LOCAL reset with the RIGHT one.
#[derive(Clone, Copy)]
enum ServerBehaviour {
    /// `SendResponse::send_reset` on the accepted request, with the
    /// given `Reason` — a REMOTE reset. `REFUSED_STREAM` is
    /// CLASS A; any other reason (e.g. `INTERNAL_ERROR`) pins that
    /// the reason conjunct, not `is_remote()` alone, gates it.
    RemoteReset(h2::Reason),
    /// `Connection::abrupt_shutdown` before ever answering — a
    /// REMOTE GOAWAY (CLASS B, the eight-seam member).
    GoAway,
    /// The server answers nothing; the CLIENT resets its OWN
    /// stream with the given `Reason` — LOCAL, whatever the reason
    /// code. `is_reset()` alone would match CLASS A's first
    /// conjunct even here — which is why the predicate
    /// additionally requires `is_remote()`, and a `REFUSED_STREAM`
    /// reason here (as opposed to the "ordinary" local-cancel
    /// `CANCEL`) is what isolates that conjunct from the reason
    /// check.
    LocalReset(h2::Reason),
}

/// Drive one request over a hand-rolled, in-memory h2 client/server
/// pair far enough to observe the client-side `h2::Error` `server`
/// produces, and return it.
async fn one_client_h2_error(server: ServerBehaviour) -> h2::Error {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let (mut send_request, connection) = h2::client::handshake(client_io)
        .await
        .unwrap_or_else(|e| panic!("client handshake: {e}"));
    let _client_driver = spawn(async move {
        let _ = connection.await;
    });

    let _server_driver = spawn(async move {
        let mut conn = h2::server::handshake(server_io)
            .await
            .unwrap_or_else(|e| panic!("server handshake: {e}"));
        match server {
            ServerBehaviour::GoAway => {
                // Sent BEFORE accepting anything: `last_stream_id`
                // is then 0, so h2's client attributes the pending
                // request to "never processed" cleanly — the drain
                // race under test (a request in flight
                // when GOAWAY arrives), rather than racing this
                // harness's own abrupt teardown of an
                // ALREADY-accepted stream (empirically flaky: h2
                // reports that shape as a raw `BrokenPipe`, an
                // `abrupt_shutdown` doc warning in different words
                // — "reserved for... open streams cannot be
                // properly handled").
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
            }
            ServerBehaviour::RemoteReset(_) | ServerBehaviour::LocalReset(_) => {
                let Some(accepted) = conn.accept().await else {
                    panic!("no request arrived");
                };
                let (_request, mut respond) =
                    accepted.unwrap_or_else(|e| panic!("server accept: {e}"));
                if let ServerBehaviour::RemoteReset(reason) = server {
                    respond.send_reset(reason);
                }
                // `LocalReset`: answer nothing: the CLIENT resets
                // its own stream; this side just keeps the
                // connection's I/O moving so that reset is
                // actually received and acted on.
            }
        }
        // Keep driving the connection's I/O (flushing the frame(s)
        // just queued above) until it closes — and PARK rather
        // than return once it does. Returning here would drop
        // `conn`, dropping this side of the duplex mid-flight and
        // risking exactly the raw `BrokenPipe` noted above instead
        // of the clean GOAWAY/RESET this test is about.
        loop {
            if conn.accept().await.is_none() {
                std::future::pending::<()>().await;
            }
        }
    });

    let request = hyper::Request::builder()
        .method("GET")
        .uri("https://example.invalid/")
        .body(())
        .unwrap_or_else(|e| panic!("request: {e}"));
    // ONE exhaustive match, NO wildcard arm: both `end_of_stream` and
    // whether (and with what reason) THIS end resets its own stream
    // afterward are derived here, together, so a `ServerBehaviour`
    // variant added later is a compile error at this one site rather
    // than a silently-wrong default at whichever of the two
    // derivations someone remembered to update.
    //
    // `end_of_stream` is `false` ONLY for `LocalReset`, which needs a
    // live `SendStream` to reset. The other two send a body-less,
    // already-closed request — no second write for the client's
    // background connection driver to race against the server's
    // action, which is what made this harness flaky before: a
    // `send_data` queued after `send_request` had no ordering
    // guarantee against the server's `abrupt_shutdown`/`send_reset`.
    let (end_of_stream, reset_locally) = match server {
        ServerBehaviour::RemoteReset(_) | ServerBehaviour::GoAway => (true, None),
        ServerBehaviour::LocalReset(reason) => (false, Some(reason)),
    };
    let (response_fut, send_stream) = send_request
        .send_request(request, end_of_stream)
        .unwrap_or_else(|e| panic!("send_request: {e}"));

    // Driven by the Option the match above already derived
    // exhaustively — not a second match on `server` a new variant
    // could silently skip.
    if let Some(reason) = reset_locally {
        let mut send_stream = send_stream;
        send_stream.send_reset(reason);
    }

    response_fut
        .await
        .expect_err("the configured server behaviour must fail this response")
}

/// The negative control for the string-matching defect class,
/// against a REAL h2 `REFUSED_STREAM` reset (not hand-instantiated —
/// see the module-level note on why h2 forces that).
#[tokio::test]
async fn classification_never_reads_the_display_string() {
    let h2_err =
        one_client_h2_error(ServerBehaviour::RemoteReset(h2::Reason::REFUSED_STREAM)).await;
    assert!(
        h2_err.is_reset()
            && h2_err.is_remote()
            && h2_err.reason() == Some(h2::Reason::REFUSED_STREAM),
        "test setup: expected a remote REFUSED_STREAM reset, got {h2_err:?}"
    );
    let display_lies = DisplayLies {
        source: Box::new(h2_err),
    };
    assert_eq!(format!("{display_lies}"), "client error (SendRequest)");
    assert_eq!(classify(&display_lies), RetryClass::StreamRefused);
    assert!(
        !reclaimed_unsent(display_lies.source()),
        "a remote REFUSED_STREAM is not hyper's reclaimed-request proof"
    );
}

/// The `is_remote()` conjunct on the CLASS A predicate,
/// and the GOAWAY arm of CLASS B, both over a REAL h2 error.
#[tokio::test]
async fn a_remote_goaway_is_class_b_and_a_local_reset_is_not() {
    let goaway = one_client_h2_error(ServerBehaviour::GoAway).await;
    assert!(
        goaway.is_go_away() && goaway.is_remote(),
        "test setup: expected a remote GOAWAY, got {goaway:?}"
    );
    assert_eq!(classify(&goaway), RetryClass::ConnectionFailed);
    assert!(
        !reclaimed_unsent(Some(&goaway)),
        "a remote GOAWAY does not prove that this request stayed off the wire"
    );

    let local = one_client_h2_error(ServerBehaviour::LocalReset(h2::Reason::CANCEL)).await;
    assert!(
        local.is_reset() && !local.is_remote(),
        "test setup: expected a LOCAL reset (is_reset but not is_remote), got {local:?}"
    );
    assert_eq!(
        classify(&local),
        RetryClass::NotRetryable,
        "is_reset() alone is not CLASS A — a local reset carries none of \
         RFC 9113 §8.7's remote guarantee"
    );
}

/// Isolating the `is_remote()` conjunct BY ITSELF: a LOCAL
/// reset carrying the exact `REFUSED_STREAM` reason. The sibling
/// test above uses `CANCEL` for its local reset, so the reason
/// conjunct alone already refuses it — dropping `is_remote()` from
/// CLASS A's predicate would not change that test's verdict. This
/// row is the one a dropped `is_remote()` conjunct flips: without
/// it, `is_reset() && reason() == Some(REFUSED_STREAM)` is
/// satisfied by a reset the CLIENT sent to itself, and RFC 9113
/// §8.7's guarantee is a REMOTE server's — nothing said by a local
/// reset.
#[tokio::test]
async fn a_local_refused_stream_reset_is_not_class_a() {
    let local = one_client_h2_error(ServerBehaviour::LocalReset(h2::Reason::REFUSED_STREAM)).await;
    assert!(
        local.is_reset()
            && local.reason() == Some(h2::Reason::REFUSED_STREAM)
            && !local.is_remote(),
        "test setup: expected a LOCAL REFUSED_STREAM reset, got {local:?}"
    );
    assert_eq!(
        classify(&local),
        RetryClass::NotRetryable,
        "the is_remote() conjunct must gate CLASS A independently of the \
         reason code — a REFUSED_STREAM reset the client sent to itself \
         carries none of RFC 9113 §8.7's remote guarantee"
    );
}

/// Isolating the REASON conjunct BY ITSELF: a REMOTE reset
/// carrying `INTERNAL_ERROR` rather than `REFUSED_STREAM`. Dropping
/// the reason check from CLASS A's predicate would leave
/// `is_reset() && is_remote()` — satisfied here — and RFC 9113
/// §8.7's non-processing guarantee is SPECIFIC to `REFUSED_STREAM`;
/// nothing else in the reset-reason registry carries it.
#[tokio::test]
async fn a_remote_internal_error_reset_is_not_class_a() {
    let remote =
        one_client_h2_error(ServerBehaviour::RemoteReset(h2::Reason::INTERNAL_ERROR)).await;
    assert!(
        remote.is_reset()
            && remote.is_remote()
            && remote.reason() == Some(h2::Reason::INTERNAL_ERROR),
        "test setup: expected a REMOTE INTERNAL_ERROR reset, got {remote:?}"
    );
    assert_eq!(
        classify(&remote),
        RetryClass::NotRetryable,
        "the reason conjunct must gate CLASS A independently of \
         is_remote() — an INTERNAL_ERROR reset carries no non-processing \
         guarantee, remote or not"
    );
}
