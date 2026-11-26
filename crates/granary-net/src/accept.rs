// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The accept loop, the connection envelope, and the shutdown contract.
//!
//! One accept task, one spawned task per admitted connection, and a
//! connection cap that bounds how many of those can exist. The cap is not a
//! nicety: spawn-per-connection without one is this shape's own degenerate,
//! and it is a *tested* requirement here rather than a documented intention.
//!
//! **No `select!`.** The ban on it has no working per-site exemption below
//! the crate root, and the crate-root route would disarm neighbouring bans on
//! the way past. Every race here is a small hand-rolled [`poll_fn`] that
//! polls the shutdown arm first — biased and deterministic, which is what the
//! ban wanted in the first place.
//!
//! **What the loop deliberately does not do.** At the cap it stops accepting
//! rather than accepting and closing: a connection is never admitted and then
//! dropped, so a peer either gets served or waits in the kernel backlog and
//! times out on its own clock. Evicting a live but idle connection to make
//! room needs per-connection idle bookkeeping hyper does not expose, and is a
//! later hardening rather than something this loop pretends to do.
//!
//! **What it does do, and it is not the same thing:** every admitted
//! connection has an absolute lifetime ([`CONNECTION_MAX_LIFETIME`]). That is
//! not eviction — nothing is closed to make room for a waiting peer — it is
//! the only clock here a peer cannot re-arm, and it exists so that anything
//! the connection is HOLDING is given back on a schedule the peer does not
//! choose.
//!
//! [`poll_fn`]: std::future::poll_fn

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Body;
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulConnection;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch::error::RecvError;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::timeout;

use crate::alpn::Protocol;
use crate::identity::{ConnectionIdentity, Identified};
use crate::preface::PrefaceDeadline;

/// The most connections that may be resident at once.
pub const MAX_CONNECTIONS: usize = 8192;

/// How long a peer may take to complete the TLS handshake.
///
/// This bounds ONE of the two windows a silent peer can sit in, and it is the
/// earlier one: [`AcceptConfig::header_read_timeout`] does not start until TLS
/// finishes, so nothing but this covers the handshake itself. The window after
/// it — handshake done, not a byte of HTTP sent — is bounded separately, by
/// serving the connection on the protocol its ALPN token already named rather
/// than on one re-derived from bytes that have not arrived, and then by
/// [`HEADER_READ_TIMEOUT`] on both legs: hyper arms it on the HTTP/1.1 leg,
/// and the accept path arms it on the HTTP/2 leg over the client connection
/// preface.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection may take to deliver its opening bytes. ONE value,
/// TWO different things, because the two legs open differently.
///
/// On **HTTP/1.1** it is hyper's own slowloris default, made explicit and
/// actually armed — it does nothing unless a timer is installed alongside it —
/// and it bounds a complete request head. It arms on that connection's first
/// poll, before any byte has arrived, which is what makes it a bound on a
/// silent peer and not only on a slow one.
///
/// On **HTTP/2** hyper never arms it at all, so the accept path does: it
/// bounds the 24-byte client connection preface, above TLS, and disarms for
/// good once those bytes have been read. Past that point the connection is
/// established and [`H2_KEEP_ALIVE_INTERVAL`] is what holds a clock on it.
///
/// One value for both because they are the same question asked of the two
/// protocols — how long may a peer that has said hello say nothing further —
/// and a second constant would only be a second thing to get wrong.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the graceful drain may run before the outcome is forced.
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// How long an ESTABLISHED connection may remain resident before
/// it is closed.
///
/// **This is the only clock in the envelope a peer cannot re-arm, and that is
/// the whole of its job.** Every other bound here is reset by activity: the
/// HTTP/1.1 header-read timeout re-arms per request head, and the HTTP/2
/// keep-alive pair is scheduled at `last_read_at + interval`, where
/// `last_read_at` is updated by every frame READ from the peer — a
/// `WINDOW_UPDATE` included. A peer that opens its flow-control window by one
/// byte per interval is therefore, to hyper, a healthy connection forever, and
/// nothing above this line ever ends it.
///
/// **What that costs is not the connection, it is the RESIDENT BYTES the
/// connection is holding.** A server that answers a range request buffers the
/// extent and hands it to the transport, which releases it only as flow
/// control drains it — at the CLIENT's pace. Any byte-weighted bound over
/// those buffers (`granary-server`'s read-response budget is one) is a bound whose
/// held charges are returned only when the responses holding them are dropped.
/// Without a clock the peer cannot re-arm, a full budget is a PERMANENT
/// refusal sustained by idle streams — strictly worse than holding no budget
/// at all, where the process dies and a supervisor restarts it. This is what
/// makes such a budget shippable, and the ordering is not a preference: the
/// budget does not ship without it.
///
/// **Five minutes, and the derivation is a floor and a ceiling.** The FLOOR is
/// the longest legitimate single exchange: `granary-server` gives an admitted
/// write thirty seconds of accept clock plus five in the verify queue, so a
/// connection must outlive at least one of those by a wide margin or the bound
/// would cut healthy publishes rather than stalled reads. The CEILING is how
/// long a charge may be pinned: every charge on this connection is released by
/// this clock at the latest, so the recovery time of any byte budget the
/// deployment runs is one lifetime, not unbounded. Five minutes is roughly
/// nine times the floor and is the value a fleet frontend conventionally runs.
///
/// **What it does NOT claim.** A peer may reconnect, so this bounds the HOLD
/// and not the ATTACK: under sustained load a byte budget still sheds, which
/// is a refusal (`503`) rather than a crash and is what a resource control is
/// for. What the bound buys is that shedding ENDS — within one lifetime of the
/// last offending connection — instead of persisting until the process is
/// restarted.
pub const CONNECTION_MAX_LIFETIME: Duration = Duration::from_mins(5);

/// How long a rotating connection may finish work after graceful shutdown
/// starts and before [`CONNECTION_MAX_LIFETIME`] drops it.
pub const CONNECTION_DRAIN_GRACE: Duration = Duration::from_secs(75);

/// How long the loop waits after a failed `accept` before trying again.
///
/// Log-and-continue alone hands an attacker who exhausts the process's file
/// descriptors a spin loop: `accept` fails immediately, the slot is free
/// immediately, and the loop burns a core emitting warnings. The wait is the
/// shutdown race itself, so throttling never delays a deploy.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// The HTTP/2 stream concurrency limit, and the one DIRECTION it is bounded
/// in: never below [`H2_ADVERTISED_STREAM_FLOOR`].
///
/// **The rule is not "100 is safe". It is: advertise no fewer than the
/// largest pre-SETTINGS optimistic cap among the clients we intend to
/// serve.** RFC 9113 §3.4 permits a client to send frames immediately after
/// its own preface "without waiting to receive the server connection
/// preface", and §6.5.2 says that until a `SETTINGS` frame arrives
/// "initially, there is no limit to this value", recommending it "be no
/// smaller than 100, so as to not unnecessarily limit parallelism". So a
/// client opening 100 streams into that window is not exceeding a limit —
/// there is no limit yet — and every stream past what the server's SETTINGS
/// then announces is answered `RST_STREAM(REFUSED_STREAM)` on arrival.
/// hyper's own optimistic cap is `DEFAULT_INITIAL_MAX_SEND_STREAMS = 100`
/// (`hyper-1.11.0/src/proto/h2/client.rs:54-62`), and its comment gives that
/// exact reason; neither `hyper-util` nor granary's own `HttpStore`
/// overrides it.
///
/// **What lowering it costs is MEASURED, not reasoned.** With the
/// server's `SETTINGS` delayed by a path RTT, a parallel client's cold burst
/// loses exactly `min(fan, 100) − limit` requests: 48 of 64 at limit 16, 32
/// of 64 at 32, 0 at 100 — at 5 ms and at 50 ms alike. hyper does not retry
/// them, though RFC 9113 §8.7 makes `REFUSED_STREAM` explicitly retry-safe:
/// `Error::new_h2` maps to `Kind::Http2`, which `is_canceled()` does not
/// match, and `hyper-util` builds a retry only for a REUSED connection,
/// which a cold burst by definition is not. So the cost is deterministic
/// rather than probabilistic — every parallel client, every connection,
/// every path with an RTT.
///
/// **What the value does NOT protect, said because the shape invites the
/// assumption.** Nothing a server advertises protects an optimistically
/// UNBOUNDED client: bare `hyperium/h2` defaults `initial_max_send_streams`
/// to `usize::MAX` (`h2-0.4.18/src/client.rs:667`), `OkHttp` to
/// `Int.MAX_VALUE`, Python's `h2` to `2**32 + 1`. 100 refuses those exactly
/// as 16 would. What it buys is the hyper / Go net-http2 / grpc-go /
/// Chromium class — the class granary's own client is in.
///
/// **THE RECHECK TRIGGER IS A HYPER BUMP.** This value is a floor only while
/// hyper's optimistic default is what [`H2_ADVERTISED_STREAM_FLOOR`] claims,
/// and that is a dependency's private constant which a routine version bump
/// may move. A one-sided guard goes green on precisely that event: "16
/// sheds" stays true while 100 quietly stops being enough. So the premise is
/// ASSERTED and not assumed — `granary-net/tests/accept_loop.rs` row 25
/// reads hyper's cap off a live connection whose peer never sends SETTINGS,
/// and fails the day it moves. The shed itself is controlled from both sides
/// in `granary-server`'s `stream_floor` module: at this value with a fan
/// above it, ZERO failures; below the floor, the refusal reason and the
/// rate.
///
/// **And one gate reads none of the above: it reads the WIRE.** Every guard
/// named so far compares numbers written down in this tree, `envelope`
/// included — not one of them observes what that builder actually
/// advertises, so deleting its `.max_concurrent_streams(..)` line puts
/// hyper's own default (200, measured) on the wire with every one of them
/// still green. Row 26 of the accept-loop suite is the MIRROR of row 25 and
/// closes that: row 25 reads a client's cap BEFORE any SETTINGS, row 26
/// reads it AFTER a real exchange with the shipped `serve`, against a client
/// built with a sentinel optimistic cap so the two readings cannot be
/// confused for one another.
///
/// **Raising it is a different question and is NOT settled here.** The bound
/// is on the direction only. Upward, this constant is one multiplicand of
/// §9.2's aggregate — [`MAX_CONNECTIONS`] is the other, and their product is
/// what §9.2 calls "no bound at all".
pub const H2_MAX_CONCURRENT_STREAMS: u32 = 100;

/// The floor under [`H2_MAX_CONCURRENT_STREAMS`] — a SECOND name, which is
/// the whole mechanism rather than a restatement.
///
/// A `const _` comparing the advertised value against a literal spelled
/// beside it is a tautology one edit rewrites in a single pass. Comparing it
/// against a constant whose doc comment IS the derivation means the edit
/// that lowers the advertised value has to come here to make the build green
/// again — and lowering THIS one is a diff that reads as what it is: a claim
/// about hyper, not a tuning change.
///
/// **The derivation, and none of it is a granary number.** RFC 9113 §6.5.2's
/// recommended minimum, which is also hyper's
/// `DEFAULT_INITIAL_MAX_SEND_STREAMS`
/// (`hyper-1.11.0/src/proto/h2/client.rs:54-62`) and Go's `net/http2`
/// (`transport.go:52-55`). It is the largest pre-SETTINGS optimistic cap
/// among the clients this deployment intends to serve, and it moves only
/// when that population does — a measurement, not a preference. The
/// population has been checked against exactly ONE member by execution
/// (hyper, row 25 of the accept-loop suite); Go corroborates by source read
/// and is not executed anywhere.
pub const H2_ADVERTISED_STREAM_FLOOR: u32 = 100;

const _: () = assert!(
    H2_MAX_CONCURRENT_STREAMS >= H2_ADVERTISED_STREAM_FLOOR,
    "advertising fewer concurrent streams than the largest pre-SETTINGS \
     optimistic cap among the clients we serve sheds `min(fan, cap) - limit` \
     requests out of EVERY parallel client's cold burst, on every path with \
     an RTT, unretried — measured at 48 of 64 with this value at 16. RFC \
     9113 §3.4 authorises the burst and §6.5.2 recommends 100; hyper's own \
     optimistic default IS 100. Read H2_ADVERTISED_STREAM_FLOOR's derivation \
     before moving either number"
);

/// The bound on HTTP/2's pending-accept reset-stream queue.
const H2_MAX_PENDING_ACCEPT_RESET_STREAMS: usize = 20;

/// The bound on locally-generated HTTP/2 stream resets.
const H2_MAX_LOCAL_ERROR_RESET_STREAMS: usize = 1024;

/// The HTTP/2 header list limit. granary's protocol carries tiny headers.
const H2_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;

/// The per-stream write buffer hyper may hold ahead of the peer's flow-control
/// window.
///
/// §9.5 lists this among the settings a server "MUST set explicitly rather than
/// inherit defaults", and until now this envelope set the other four and not
/// this one. The VALUE is hyper's own current default, and that is the point:
/// the requirement is not that the number be different, it is that the number
/// be *stated* — hyper documents its default as "currently ~400KB, but may
/// change", which is exactly a security-relevant figure this deployment would
/// otherwise inherit silently from a dependency bump.
///
/// **What it does and does not bound, because the shape invites the
/// assumption.** This is hyper's OWN send buffer, per stream. It does not
/// bound the application's response body: a `Full<Bytes>` handed to hyper is
/// held by the application's allocation until the transport has drained it,
/// and 400 KiB of hyper buffer in front of a 74 MiB body bounds nothing about
/// the 74 MiB. The byte-weighted bound over response bodies is the server's
/// read-response budget, and this setting is not a substitute for it.
const H2_MAX_SEND_BUF_SIZE: usize = 400 * 1024;

/// How often an idle HTTP/2 connection is sent a PING.
pub const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// How long a PING may go unanswered before the peer is considered gone.
pub const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

const _: () = {
    // The lifetime is the OUTERMOST clock or it is a bug: every bound it
    // exceeds keeps its meaning, and every bound it undercuts becomes
    // unreachable code that no test would fail on. The keep-alive pair is
    // named as a SUM because that is what a silent peer actually experiences
    // — the first PING at the interval, the close a timeout later.
    assert!(CONNECTION_MAX_LIFETIME.as_secs() > HEADER_READ_TIMEOUT.as_secs());
    assert!(
        CONNECTION_MAX_LIFETIME.as_secs()
            > H2_KEEP_ALIVE_INTERVAL.as_secs() + H2_KEEP_ALIVE_TIMEOUT.as_secs(),
        "a lifetime under the keep-alive pair would close every silent \
         connection before the PING that is supposed to"
    );
    // A drain is bounded by the drain deadline and not by this, so the two do
    // not compete; the assertion is that the lifetime cannot be the thing that
    // ends a connection the drain was already about to end.
    assert!(CONNECTION_MAX_LIFETIME.as_secs() > SHUTDOWN_DEADLINE.as_secs());
    assert!(CONNECTION_DRAIN_GRACE.as_secs() < CONNECTION_MAX_LIFETIME.as_secs());
};

/// The listening seam.
///
/// It exists so the accept-ERROR branch can be reached at all: a
/// `TcpListener` cannot be made to fail on demand, and an error branch no
/// test can enter is an error branch nothing checks. This is a testability
/// seam, not a determinism seam — nothing here is replayed.
pub trait Listener: Send {
    /// The accepted connection's byte stream.
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Accept one connection.
    ///
    /// **Implementations must be cancel safe:** the loop races this future
    /// against shutdown and drops the loser, so a dropped `accept` must leave
    /// no connection accepted-but-lost. `TcpListener::accept` documents
    /// exactly that guarantee; an implementation that buffers an accepted
    /// connection inside the future instead would drop live peers on every
    /// shutdown-race loss, silently.
    fn accept(&mut self) -> impl Future<Output = std::io::Result<Self::Io>> + Send;
}

impl Listener for tokio::net::TcpListener {
    type Io = tokio::net::TcpStream;

    /// `TCP_NODELAY` is set on every accepted socket, and it is not
    /// hygiene — it is the server half of the hazard the client's
    /// `HttpStore` connector closes with `set_nodelay(true)`.
    ///
    /// Nothing in this crate sets the option on the LISTENER, so without
    /// this line Nagle's algorithm is on for every connection this server
    /// serves. (An accepted socket does inherit `TCP_NODELAY` from its
    /// listener — measured 2026-08-27 on macOS and on Linux, `0 -> 0` and
    /// `1 -> 1` — so setting it on the listener would work too. It is set
    /// HERE because this is the one place every accepted socket passes
    /// through, whatever bound it.) Under Nagle a SMALL write
    /// issued while
    /// earlier bytes are still unacknowledged is held by the kernel
    /// until the peer's delayed ACK fires — up to ~40 ms on Linux — and
    /// almost everything an h2 server writes is small and interleaved:
    /// `SETTINGS`, `WINDOW_UPDATE`, `PING` ACKs, `RST_STREAM`, and a
    /// response `HEADERS` issued behind any of them. The measured cost
    /// on the client half of exactly this shape was ~15 ms per affected
    /// write, on loopback, the only path measured. HTTP/2 does its own
    /// multiplexing and framing, so Nagle can only add head-of-line
    /// blocking across streams that the protocol was designed to keep
    /// independent — which is why every serious h2 implementation sets
    /// this.
    ///
    /// A failure to set it is WARNED and the connection is served
    /// anyway. The option is a latency knob, not a correctness one:
    /// refusing a peer because a `setsockopt` failed would trade a
    /// slower connection for no connection.
    async fn accept(&mut self) -> std::io::Result<Self::Io> {
        let (stream, _peer) = tokio::net::TcpListener::accept(self).await?;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "could not set TCP_NODELAY on an accepted connection");
        }
        Ok(stream)
    }
}

/// The bounds an operator may vary, defaulting to the named constants above.
#[derive(Debug, Clone)]
pub struct AcceptConfig {
    /// The most connections that may be resident at once.
    ///
    /// **Must be in `1..=Semaphore::MAX_PERMITS`.** This field is not
    /// validated here and both ends bite: `Semaphore::new` panics above the
    /// maximum, and `0` wedges the loop silently — it parks on a permit that
    /// can never be issued and accepts nothing, with no log line. Nothing in
    /// this crate constructs an out-of-range value; the configuration surface
    /// that first accepts operator input owns the bound.
    pub max_connections: usize,
    /// How long a peer may take to complete the TLS handshake.
    pub tls_handshake_timeout: Duration,
    /// How long a connection may take to deliver its opening bytes: a complete
    /// request head on HTTP/1.1, the 24-byte client connection preface on
    /// HTTP/2. See [`HEADER_READ_TIMEOUT`] for why one value governs both.
    pub header_read_timeout: Duration,
    /// How long the graceful drain may run before the outcome is forced.
    pub shutdown_deadline: Duration,
    /// How long an ESTABLISHED connection may remain resident before it is
    /// closed — the clock the peer cannot re-arm. See
    /// [`CONNECTION_MAX_LIFETIME`] for what it bounds and, more to the point,
    /// what depends on it existing at all.
    ///
    /// The clock starts once the connection is admitted — after TLS and after
    /// ALPN — so it never overlaps [`Self::tls_handshake_timeout`], and it is
    /// longer than every other bound here so that none of them becomes dead
    /// code behind it.
    pub connection_max_lifetime: Duration,
    /// How long before [`Self::connection_max_lifetime`] to ask an established
    /// connection to finish gracefully. A value greater than or equal to the
    /// lifetime disables early rotation while preserving the hard lifetime.
    pub connection_drain_grace: Duration,
    /// How often an idle HTTP/2 connection is sent a PING.
    ///
    /// With [`Self::h2_keep_alive_timeout`] this pair is the ONLY bound on a
    /// peer that has COMPLETED the HTTP/2 handshake and then goes silent or
    /// dead: hyper's own `header_read_timeout` is an HTTP/1.1 knob and never
    /// arms on that leg, so nothing else in the envelope holds a clock on an
    /// established HTTP/2 connection. hyper builds its keep-alive from the
    /// INTERVAL alone — drop it and there is no bound at all rather than a
    /// longer one.
    ///
    /// The window BEFORE that handshake resolves is a different one and is
    /// bounded separately, by [`Self::header_read_timeout`] over the client
    /// connection preface: this pair cannot cover it, because hyper builds
    /// the PING machinery only once the handshake has already resolved.
    pub h2_keep_alive_interval: Duration,
    /// How long a PING may go unanswered before the peer is considered gone.
    ///
    /// What a silent-but-established peer actually sees is
    /// [`Self::h2_keep_alive_interval`] plus this: the first PING goes out at
    /// the interval, and the connection ends a timeout later with nothing
    /// having answered it.
    pub h2_keep_alive_timeout: Duration,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            tls_handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
            header_read_timeout: HEADER_READ_TIMEOUT,
            shutdown_deadline: SHUTDOWN_DEADLINE,
            connection_max_lifetime: CONNECTION_MAX_LIFETIME,
            connection_drain_grace: CONNECTION_DRAIN_GRACE,
            h2_keep_alive_interval: H2_KEEP_ALIVE_INTERVAL,
            h2_keep_alive_timeout: H2_KEEP_ALIVE_TIMEOUT,
        }
    }
}

/// How the drain ended.
#[derive(Debug, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// Every watched connection finished before the deadline.
    Drained,
    /// The deadline expired first, and connection tasks are still resident.
    DeadlineExpired,
}

/// Which arm of a shutdown race completed.
pub(crate) enum Raced<T> {
    /// The raced future finished.
    Ready(T),
    /// The shutdown channel spoke: `Ok` is a change notification, `Err` means
    /// every sender is gone.
    Shutdown(Result<(), RecvError>),
}

/// Race `future` against the shutdown channel, polling shutdown FIRST.
///
/// Biased on purpose. The alternative — a randomised branch order — is the
/// property the concurrency ban exists to avoid, and there is nothing to gain
/// from it here.
///
/// Both raced futures are safe to drop: `changed` is documented cancel safe
/// ("it is guaranteed that no values have been marked seen by this call"), as
/// is `TcpListener::accept` ("no new connections were accepted"), and
/// `acquire_owned` documents only that cancelling it "makes you lose your
/// place in the queue" — benign for a loop that immediately re-queues.
/// Neither arm holds a determinism-seam call.
pub(crate) async fn race<T, F: Future>(
    shutdown: &mut watch::Receiver<T>,
    future: F,
) -> Raced<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut changed = std::pin::pin!(shutdown.changed());
    std::future::poll_fn(move |cx| {
        if let std::task::Poll::Ready(observed) = changed.as_mut().poll(cx) {
            return std::task::Poll::Ready(Raced::Shutdown(observed));
        }
        future.as_mut().poll(cx).map(Raced::Ready)
    })
    .await
}

/// Whether an observed shutdown-channel event stops the loop.
///
/// This is the one place the channel's semantics live, and all three race
/// sites go through it. An ERRORED `changed()` means every sender is gone,
/// which is a shutdown trigger — reading it as "nothing happened" and polling
/// again would return immediately forever, turning any wait built on it into
/// a hot loop. A COMPLETED `changed()` proves only that *something* was sent,
/// so the LEVEL decides: a `false` send violates the channel's contract and
/// merely re-arms the wait rather than stopping the server.
///
/// Level rather than edge is also what makes the arms composable: `changed()`
/// CONSUMES a notification, so an edge observed by one arm is invisible to
/// the next, while the level survives.
fn stops(shutdown: &mut watch::Receiver<bool>, observed: Result<(), RecvError>) -> bool {
    match observed {
        Err(_every_sender_gone) => true,
        Ok(()) => *shutdown.borrow_and_update(),
    }
}

/// Build the connection envelope for a connection that negotiated
/// `protocol`. ONE function, so there is one place to read it and no
/// connection can be served under a different set of bounds.
///
/// The http1 pair is joint or useless: the timeout without a timer panics on
/// the first connection, and the timer without the timeout leaves the
/// connection set unbounded against a peer that opens a request and stops.
///
/// No initial-window settings on http2 — they are mutually exclusive with
/// adaptive windowing. `max_frame_size` is left at hyper's default, which is
/// the RFC 9113 minimum; raising it is a security trade, not a tuning knob.
///
/// §9.5's list of settings that MUST be set explicitly is satisfied HERE and
/// only here: pending-accept resets, local error resets, concurrent streams,
/// send buffer size, header list size. A settings knob added to that list and
/// not to this function is an unmet MUST wherever it is read.
///
/// **The builder is pinned to one version, and that is a bound and not a
/// tidiness.** Left unpinned it decides the version by reading the first
/// bytes off the wire, and that read has no timer of its own: a peer that
/// finishes TLS and then sends nothing parks there, holding its permit
/// against the cap until the process dies, with `header_read_timeout` never
/// armed because no HTTP/1.1 connection exists yet to arm it. Pinning also
/// makes the negotiated token binding rather than advisory — a peer that
/// negotiates one protocol and speaks the other is refused instead of served
/// (RFC 7301 §3.2).
///
/// **The pin binds `serve_connection` and NOTHING ELSE.** hyper-util
/// documents that it "does not do anything" when the connection is served
/// through `serve_connection_with_upgrades`, which silently falls back to
/// sniffing the version off the wire. Switching to that method — the obvious
/// move the day an endpoint wants an HTTP upgrade — therefore reinstates both
/// the unbounded window and the protocol mismatch, with every test still
/// green except the two that name them. Read that as a blocker on the switch,
/// not a caveat.
///
/// **What pinning does NOT bound, stated because the shape invites the
/// assumption:** the HTTP/2 leg's opening window. hyper reads the client
/// connection preface through a bare `poll_read` loop and builds its
/// keep-alive machinery only once that has resolved, so on an undecorated
/// stream an `h2` peer that sends no preface holds its permit indefinitely.
/// Nothing on this builder closes that — `connection` wraps the HTTP/2 leg's
/// stream in the preface deadline instead, and this function's only part in it
/// is the keep-alive pair that takes over at the other end.
fn envelope(config: &AcceptConfig, protocol: Protocol) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .max_pending_accept_reset_streams(H2_MAX_PENDING_ACCEPT_RESET_STREAMS)
        .max_local_error_reset_streams(H2_MAX_LOCAL_ERROR_RESET_STREAMS)
        .max_header_list_size(H2_MAX_HEADER_LIST_SIZE)
        .max_send_buf_size(H2_MAX_SEND_BUF_SIZE)
        .keep_alive_interval(config.h2_keep_alive_interval)
        .keep_alive_timeout(config.h2_keep_alive_timeout);
    match protocol {
        Protocol::Http1 => builder.http1_only(),
        Protocol::Http2 => builder.http2_only(),
    }
}

/// Poll `future` to completion while staying responsive to shutdown, and
/// return `None` if shutdown wins.
///
/// The loop's own arms answer a shutdown by dropping their future and
/// re-entering the loop, which is free for them: an `accept` or an
/// `acquire_owned` can be started again. A handshake cannot — it owns the
/// socket — so this races without discarding, handing the future back to the
/// next race by pinned reference.
///
/// The shutdown semantics are the loop's, unchanged: the level is read on
/// entry because a receiver already `true` had its edge consumed elsewhere, an
/// errored `changed()` stops, and a completed one stops only if the level says
/// `true` — so a contract-violating `false` send cannot kill a live handshake.
async fn until_shutdown<F: Future>(
    shutdown: &mut watch::Receiver<bool>,
    future: F,
) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    loop {
        if *shutdown.borrow_and_update() {
            return None;
        }
        match race(shutdown, future.as_mut()).await {
            Raced::Ready(output) => return Some(output),
            Raced::Shutdown(observed) => {
                if stops(shutdown, observed) {
                    return None;
                }
            }
        }
    }
}

/// One admitted connection, from TLS through to the end of its last request.
///
/// `permit` is held for the whole task and released however it ends, which is
/// what makes the cap a bound on resident connections rather than on accepts.
///
/// `drain` is subscribed before the spawn and holds a receiver from that
/// moment. That is why shutdown is watched here too: a task still handshaking
/// has nothing worth draining, and left to run it would hold the drain open
/// for the whole handshake timeout.
async fn connection<IO, S, B>(
    io: IO,
    tls: Arc<rustls::ServerConfig>,
    service: S,
    drain: watch::Receiver<()>,
    mut shutdown: watch::Receiver<bool>,
    config: AcceptConfig,
    permit: OwnedSemaphorePermit,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let _permit = permit;

    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let handshake = timeout(config.tls_handshake_timeout, acceptor.accept(io));
    let stream = match until_shutdown(&mut shutdown, handshake).await {
        Some(Ok(Ok(stream))) => stream,
        Some(Ok(Err(error))) => {
            tracing::warn!(%error, "tls handshake failed");
            return;
        }
        Some(Err(_expired)) => {
            tracing::warn!(
                timeout = ?config.tls_handshake_timeout,
                "tls handshake timed out"
            );
            return;
        }
        // Nothing has been admitted yet, so there is nothing to drain. The
        // peer sees a closed socket, exactly as it would have if the loop had
        // stopped accepting one connection earlier.
        None => {
            tracing::debug!("handshake abandoned: shutdown");
            return;
        }
    };

    // The negotiated protocol is readable in exactly one place, and this is
    // it. The refusal is not "nothing was negotiated": a peer that negotiates
    // a token the server also offers but granary does not admit is refused
    // too. What is admitted is also what BINDS — the token decides which
    // protocol the connection is served with, so a peer cannot negotiate one
    // and then be handed the other by sending its bytes.
    //
    // Nothing awaits between here and `watch` below, so an admitted
    // connection joins the drain set without a window in which it is neither
    // abandonable nor counted.
    let Some(protocol) = crate::alpn::serves(stream.get_ref().1.alpn_protocol()) else {
        tracing::warn!("connection refused: negotiated protocol is not admitted");
        return;
    };

    // The client's identity is bound here, once, from the certificates this
    // handshake verified, and every request on the connection carries it
    // (`crate::identity`). A chain that cannot be read closes the
    // connection rather than serving it as anonymous.
    let identity =
        match ConnectionIdentity::from_peer_certificates(stream.get_ref().1.peer_certificates()) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(%error, "connection refused: the client identity cannot be read");
                return;
            }
        };
    let service = Identified::new(identity, service);

    let builder = envelope(&config, protocol);
    #[expect(
        clippy::unchecked_time_subtraction,
        reason = "the strict less-than branch proves subtraction, while equality must produce None rather than checked_sub's Some(0)"
    )]
    let rotate_after = if config.connection_drain_grace >= config.connection_max_lifetime {
        None
    } else {
        Some(config.connection_max_lifetime - config.connection_drain_grace)
    };
    // The preface bound is the HTTP/2 leg's and ONLY the HTTP/2 leg's, so the
    // two legs are built here rather than inside a wrapper that would have to
    // be trusted to know which one it is on. `GET / HTTP/1.1\r\n\r\n` is 18
    // bytes — a COMPLETE HTTP/1.1 head, under the preface length — so the same
    // rule applied there would evict healthy keep-alive connections.
    //
    // Above TLS on purpose: `stream` is the decrypted side, which is what
    // makes the count a count of plaintext bytes. Below it the handshake's own
    // reads would disarm the bound, and `tls_handshake_timeout` already covers
    // that window.
    //
    // The lifetime bound wraps BOTH legs and starts HERE — after TLS, after
    // ALPN — so it never overlaps `tls_handshake_timeout` and cannot be spent
    // on a connection that was never admitted. It is applied around
    // `drain_watched` rather than inside it because the two legs' connection
    // futures have different types and a shared wrapper would have to be
    // generic over both anyway; see `expire`.
    match protocol {
        Protocol::Http1 => {
            expire(
                config.connection_max_lifetime,
                drain_watched(
                    drain,
                    rotate_after,
                    builder.serve_connection(TokioIo::new(stream), service),
                ),
            )
            .await;
        }
        Protocol::Http2 => {
            let bounded = PrefaceDeadline::new(stream, config.header_read_timeout);
            expire(
                config.connection_max_lifetime,
                drain_watched(
                    drain,
                    rotate_after,
                    builder.serve_connection(TokioIo::new(bounded), service),
                ),
            )
            .await;
        }
    }
}

/// End `served` at `lifetime` however healthy the connection looks.
///
/// **Dropping the connection future IS the close**, and that is deliberate
/// rather than a shortcut: hyper's graceful path asks the peer to finish, which
/// is precisely what a peer holding bytes hostage declines to do, so a bound
/// that waited for cooperation would not be a bound. Everything the connection
/// held — the response buffers, any charge riding in them, the socket, the
/// connection permit — is released by that drop, because every one of them is
/// owned by the future or by a value the future owns (RAII, the same property
/// the request path relies on).
///
/// What the peer sees at this point is a transport-level close mid-stream.
/// Graceful rotation has already had its configured window to finish work;
/// this outer bound remains unconditional so an uncooperative peer cannot
/// retain the connection's resources indefinitely.
///
/// [`CONNECTION_MAX_LIFETIME`] carries the reasoning for the value and for why
/// this clock has to exist at all.
async fn expire<F: Future<Output = ()>>(lifetime: Duration, served: F) {
    if timeout(lifetime, served).await.is_err() {
        // **`info!`, and the level is the claim: this is the design
        // running, not an anomaly.** A connection still present after its
        // graceful rotation window ends here — so at `warn!` the level that
        // carries the failed handshake, the refused protocol and the
        // accept error is a level an operator has learned to scroll past.
        // It is still EMITTED because the RATE is the signal: this is how
        // a fleet sees peers that did not finish within the grace, which is
        // the condition the server's read-response byte budget sheds on.
        tracing::info!(?lifetime, "connection closed: lifetime bound reached");
    }
}

/// Watch one connection for the drain, and report how it ended.
///
/// One function for both legs: the arms above differ only in what the stream
/// is wrapped in, and duplicating the error path is how the two quietly stop
/// agreeing.
async fn drain_watched<C>(
    mut drain: watch::Receiver<()>,
    rotate_after: Option<Duration>,
    connection: C,
) where
    C: GracefulConnection,
    C::Error: std::fmt::Display,
{
    let mut connection = std::pin::pin!(connection);
    let until_rotation = async {
        match race(&mut drain, connection.as_mut()).await {
            Raced::Ready(result) => Some(result),
            Raced::Shutdown(_observed) => None,
        }
    };
    let result = match rotate_after {
        Some(after) => match timeout(after, until_rotation).await {
            Ok(result) => result,
            Err(_elapsed) => {
                tracing::debug!(
                    rotate_after = ?after,
                    "connection rotating: graceful shutdown started"
                );
                None
            }
        },
        None => until_rotation.await,
    };
    if let Some(result) = result {
        if let Err(error) = result {
            tracing::warn!(%error, "connection ended in error");
        }
        return;
    }

    connection.as_mut().graceful_shutdown();
    if let Err(error) = connection.await {
        tracing::warn!(%error, "connection ended in error");
    }
}

/// Serve connections until shutdown, then drain.
///
/// # The shutdown channel's contract
///
/// The sender is a **one-shot monotonic trigger**: send `true` once, or drop
/// it. `false` is never sent after startup. The loop is defensive about that
/// anyway — a `false` send re-arms the wait instead of stopping the server —
/// but a caller that toggles the channel is outside the contract and gets no
/// guarantee beyond "it did not stop".
///
/// Both `true` and a dropped sender are shutdown triggers, and a receiver
/// whose level is already `true` on entry stops the loop before it accepts
/// anything.
///
/// # What the deadline bounds
///
/// The drain waits for every task holding a graceful-shutdown receiver, and a
/// task holds one from the moment it is spawned — before its TLS handshake,
/// before ALPN admission, before there is any connection to drain. A task
/// still in that phase therefore **abandons** on shutdown rather than being
/// waited out; otherwise a single silent `connect()` landing just before a
/// deploy would hold the drain for the whole handshake timeout and, when that
/// is not strictly shorter than the deadline, turn a clean `Drained` into
/// [`ShutdownOutcome::DeadlineExpired`] — an outcome whose caller contract is
/// to kill the process.
///
/// What the deadline bounds is otherwise the **wait**, not the tasks.
/// Connection tasks are detached, so
/// [`ShutdownOutcome::DeadlineExpired`] means undrained tasks are still
/// resident on the runtime and only process death stops them. **The caller's
/// obligation on that outcome is to exit the process immediately** —
/// `std::process::exit` as the arm's only statement, with the exit code
/// carrying the outcome. Returning from `main` is not process death (the
/// runtime's drop joins workers, and a non-yielding poll holds it open), and
/// even a log line first can block on a synchronous tracing sink under
/// backpressure — which is why the WHOLE drain path is log-free: a write
/// before the deadline's `timeout` is constructed blocks shutdown before
/// the deadline is armed, the same backpressure hazard one step earlier.
/// The outcome's record is the caller's exit code. A caller that keeps its
/// runtime alive after `DeadlineExpired` has not shut anything down.
///
/// [`ShutdownOutcome::Drained`] may be returned from normally: no connection
/// tasks remain.
///
/// # The client's identity
///
/// Every request `service` receives carries its connection's
/// [`crate::identity::ConnectionIdentity`] in its extensions, on both
/// protocol legs: [`ConnectionIdentity::Anonymous`] when the client
/// presented no certificate (always, under a configuration without client
/// authentication), the verified certificate's digest otherwise. A
/// connection whose presented chain cannot be read is closed before any
/// request is served.
///
/// # Errors
///
/// Reserved for a listener failure the loop cannot survive. Accept errors are
/// not that: they are logged, throttled and retried.
pub async fn serve<L, S, B>(
    mut listener: L,
    tls: Arc<rustls::ServerConfig>,
    service: S,
    mut shutdown: watch::Receiver<bool>,
    config: AcceptConfig,
) -> std::io::Result<ShutdownOutcome>
where
    L: Listener,
    S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (drain, _) = watch::channel(());
    let slots = Arc::new(Semaphore::new(config.max_connections));

    loop {
        // FIRST, before anything else. A receiver that is already `true` when
        // `serve` is called had its edge consumed before this loop existed,
        // so no `changed()` in any arm below can ever observe it — only this
        // read can.
        if *shutdown.borrow_and_update() {
            break;
        }

        // The slot is taken BEFORE the accept, so nothing is ever accepted
        // that cannot be served. Acquiring inside the spawned task instead is
        // indistinguishable to every client and unbounded in tasks and file
        // descriptors under a connect flood.
        let permit = match race(&mut shutdown, Arc::clone(&slots).acquire_owned()).await {
            Raced::Ready(Ok(permit)) => permit,
            Raced::Ready(Err(_closed)) => break,
            Raced::Shutdown(observed) => {
                if stops(&mut shutdown, observed) {
                    break;
                }
                continue;
            }
        };

        let io = match race(&mut shutdown, listener.accept()).await {
            Raced::Ready(Ok(io)) => io,
            Raced::Ready(Err(error)) => {
                // Breaking here is what F11e measured: a listening socket
                // that accepts nothing forever, at no CPU cost and with no
                // log line to say so.
                tracing::warn!(%error, "accept failed");
                drop(permit);
                match timeout(ACCEPT_ERROR_BACKOFF, shutdown.changed()).await {
                    Err(_expired) => continue,
                    Ok(observed) => {
                        if stops(&mut shutdown, observed) {
                            break;
                        }
                        continue;
                    }
                }
            }
            Raced::Shutdown(observed) => {
                if stops(&mut shutdown, observed) {
                    break;
                }
                continue;
            }
        };

        let task = connection(
            io,
            Arc::clone(&tls),
            service.clone(),
            drain.subscribe(),
            shutdown.clone(),
            config.clone(),
            permit,
        );
        #[expect(
            clippy::disallowed_methods,
            reason = "the accept loop is the layer granary-sim replaces rather than drives, so its per-connection tasks are outside the sim boundary"
        )]
        let _detached = tokio::spawn(task);
    }

    // NOTHING is logged between the shutdown observation and the outcome —
    // not here, and (by the caller's contract) not on the `DeadlineExpired`
    // arm either. A synchronous tracing sink under backpressure blocks the
    // WRITE, and a write sitting before the `timeout` below blocks shutdown
    // before the deadline is even armed: stderr behind a supervisor that
    // stopped reading fills, a peer that can provoke warn-level lines can
    // fill it remotely, and tokio has replaced both signals' dispositions,
    // so a wedged drain is a process only SIGKILL ends. The drain's
    // observability is the caller's EXIT CODE.
    drop(listener);
    let drained = async {
        let _ = drain.send(());
        drain.closed().await;
    };
    match timeout(config.shutdown_deadline, drained).await {
        Ok(()) => Ok(ShutdownOutcome::Drained),
        Err(_expired) => Ok(ShutdownOutcome::DeadlineExpired),
    }
}

#[cfg(test)]
mod tests;
