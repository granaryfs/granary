// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The two-sided control on [`H2_MAX_CONCURRENT_STREAMS`]: what the
//! advertised value buys at its shipped figure, and what it costs below the
//! floor.
//!
//! **Why a control at all, when nothing here is changing.** The proposal
//! `H2_MAX_CONCURRENT_STREAMS = 16` was measured and refused: below
//! the floor, a parallel client's cold burst lost `min(fan, cap) − limit`
//! requests on every path with an RTT, unretried. Recording that refusal
//! in prose does not enforce it — so the rate is measured
//! HERE, by execution, and a later change that reaches for the same lever
//! meets a red suite rather than relying on the explanation being read.
//!
//! **TWO-SIDED ON PURPOSE, and the second side is the point.** A control that
//! only proves "below the floor sheds" goes green on the exact event that
//! invalidates the floor: if a hyper bump raises its pre-SETTINGS optimistic
//! default, "16 sheds" stays true while granary's 100 quietly stops being
//! enough. The row that notices THAT is the derivation gate, and it lives
//! beside the constant —
//! `granary-net/tests/accept_loop.rs::hypers_pre_settings_optimistic_cap_is_the_advertised_floor`,
//! which reads hyper's cap off a live connection and fails the day it moves.
//! It is in the other crate because the constant is; the rows below need
//! `granary-client` and `h2` together, and this is the only crate that
//! dev-depends on both. Neither half is sufficient alone. Deleting either
//! leaves a gate that cannot tell clean from blind.
//!
//! **The mechanism, so the harness reads as evidence rather than a fixture.**
//! `h2::client::handshake` returns before the peer's `SETTINGS` has been
//! read, and RFC 9113 §3.4 explicitly permits the client to send frames into
//! that window; §6.5.2 says that until `SETTINGS` arrives "initially, there is
//! no limit to this value". So a client's opening burst is sized by its OWN
//! optimistic cap, and every stream past what the server then announces is
//! answered `RST_STREAM(REFUSED_STREAM)` — refused, not queued. The window is
//! as wide as the path's RTT. **On loopback it is tens of microseconds wide
//! and the defect does not reproduce at all**, which is why the harness
//! delays the server's h2 handshake by [`SETTINGS_DELAY`] after the TLS
//! accept: the client has completed TLS and may open streams for the whole of
//! it, which is exactly what a path does. §9.5 already records that this
//! project's topology is the one topology where such defects hide; this is
//! that problem met with a delay instead of a network.
//!
//! **Every request is answered `404` + `granary-error: not-found`**, which
//! §8.1 makes `max_seq`'s clean `Ok(None)`. So any `Err` from the seam is a
//! TRANSPORT failure and never a protocol answer, and the counting needs no
//! parsing.
//!
//! **No `sleep`.** It is banned; `tokio::time::timeout` is deliberately not,
//! so every wait here is [`pause`] — a bound around a future that never
//! completes.

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use granary_client::{AmbientNetwork, HttpStore};
use granary_core::rootstore::{RootStore, RootStoreError};
use granary_net::accept::{H2_ADVERTISED_STREAM_FLOOR, H2_MAX_CONCURRENT_STREAMS};
use granary_net::alpn::ALPN_H2;
use granary_net::pin::{SpkiPin, spki_digest};
use granary_net::tls::{ClientAuth, server_tls_config};
use hyper::body::Bytes;
use hyper::header::HeaderValue;
use hyper::{Response, StatusCode};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

use crate::loopback::{HOST, client_config, mint, spawn};

/// The volume every request in this module addresses (§4.3's DNS-1123
/// label). Nothing is ever planted under it: the server here answers `404`
/// to everything.
const VOLUME: &str = "floor-vol";

/// How long the server waits, AFTER the TLS accept, before running the h2
/// handshake — a path RTT, modelled.
///
/// **Picked for margin, not for realism, and the direction of the margin
/// matters.** The rows below need the client's whole burst to be on the wire
/// before the server's `SETTINGS` lands; a window that is too SHORT lets part
/// of the burst queue instead of shedding and under-counts, which on a shared
/// CI runner is the flake this constant exists to prevent. A window that is
/// too LONG at this scale costs only wall-clock: `HttpStore` wraps every seam
/// call in `seam_deadline`; `SEAM_DEADLINE_BASE` alone is far longer than this
/// delay, and the connect timeout is already spent by the time this starts.
/// The shed measured identical at 5 ms and at 50 ms, so this is a
/// fiftyfold margin over the smaller of two figures that already agreed.
const SETTINGS_DELAY: Duration = Duration::from_millis(250);

/// The fan for both shed rows, and it is ABOVE the advertised limit on
/// purpose.
///
/// A fan under the limit makes "zero failures" true of a server that enforces
/// nothing, so the positive control would pass on an envelope with the
/// setting deleted. Above it, the excess has to QUEUE — which is the property
/// being controlled for — and the same fan then serves the negative row, so
/// the two rows differ in the advertised limit and in nothing else.
const FAN: usize = 128;

/// The advertised limit the negative control runs at — the value that was
/// measured and refused.
const BELOW_FLOOR: u32 = 16;

/// The bound on a POSITIVE arm. Generous for macOS scheduling jitter; the
/// rows themselves are sub-second on an idle machine.
const GENEROUS: Duration = Duration::from_mins(1);

/// Wait `gap` without sleeping.
async fn pause(gap: Duration) {
    let _expired = timeout(gap, std::future::pending::<()>()).await;
}

/// A spawned task stopped when its handle goes out of scope, so no early
/// return can leave a server running against the next row's listener.
struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What one burst did, from BOTH ends of the connection.
///
/// Two independent observers, and that is deliberate: the client's failure
/// count and the server's accepted-stream count are produced by different
/// processes of the same run, and a harness that had silently stopped
/// delivering the burst would move one and not the other.
struct Burst {
    /// Seam calls that returned `Err` — transport failures, since §8.1 makes
    /// the server's `404` a clean `Ok(None)`.
    failures: usize,
    /// Streams the SERVER accepted, counted at `h2::server::Connection::accept`.
    accepted: usize,
    /// Connections that carried at least one stream. `min(fan, cap) −
    /// limit` is a statement about ONE connection's stream budget, and a
    /// burst split over two connections has two budgets — the identity
    /// would then be reading a quantity it does not name while still
    /// producing a number.
    ///
    /// **This is a harness INVARIANT, asserted rather than assumed.** The
    /// accept loop serves the first connection and parks the rest, so a
    /// second one cannot carry streams; the assertion exists because that
    /// arrangement is one edit away from being removed, and its removal
    /// would be invisible in every other number these rows read.
    serving: usize,
    /// TCP connections accepted, carried for the failure message only.
    ///
    /// **It is much larger than [`Burst::serving`], and the difference is
    /// `hyper-util`'s rather than this harness's.** `HttpStore` does not
    /// set `http2_only`, so the pool key is `Ver::Auto` and
    /// `Pool::connecting` takes no lock (`pool.rs:175-199`): a cold
    /// parallel burst of N starts N connects at once, and the dedup only
    /// happens once ALPN has resolved. Measured here at a fan of 128: 128
    /// TCP accepts, of which one carries the whole burst.
    connections: usize,
}

/// A server whose `SETTINGS` is late, advertising `limit` concurrent streams.
///
/// `h2::server` DIRECTLY rather than through the shipped accept envelope, and
/// the reason is the subject: [`H2_MAX_CONCURRENT_STREAMS`] is not
/// configurable — deliberately, since a limit the caller picks is not a gate
/// — so a harness that could set it through `AcceptConfig` would be
/// exercising a knob that does not exist. `h2::server` is the enforcement
/// layer hyper delegates to either way, and what these rows are about is the
/// CLIENT's behaviour against an advertised value, which is protocol-level.
struct Delayed {
    addr: SocketAddr,
    pin: SpkiPin,
    ca: CertificateDer<'static>,
    accepted: Arc<AtomicUsize>,
    serving: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    _accepting: Task,
}

impl Delayed {
    async fn start(limit: u32) -> Self {
        let certs = mint();
        let pin = spki_digest(&certs.leaf).unwrap_or_else(|e| panic!("spki digest: {e}"));
        let mut tls = server_tls_config(vec![certs.leaf.clone()], certs.key, ClientAuth::None)
            .unwrap_or_else(|e| panic!("server tls config: {e}"));
        // h2 ONLY. `HttpStore` offers `{h2, http/1.1}`, and on the HTTP/1.1
        // leg there are no streams to refuse — the whole subject would
        // vanish and every row would pass.
        tls.alpn_protocols = vec![ALPN_H2.to_vec()];
        let tls = Arc::new(tls);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local addr: {e}"));
        let accepted = Arc::new(AtomicUsize::new(0));
        let serving = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let accepting = {
            let accepted = Arc::clone(&accepted);
            let serving = Arc::clone(&serving);
            let connections = Arc::clone(&connections);
            spawn(async move {
                // ONE connection is SERVED, and the rest are accepted and
                // PARKED. That is not tidiness — it is what makes the rows
                // deterministic, and the flake it fixes is real client
                // behaviour rather than scheduling jitter.
                //
                // `hyper-util`'s h2 dedup is a lock held only while a
                // connection is being ESTABLISHED. The winner takes
                // `Connecting::alpn_h2` when its ALPN resolves
                // (`client/legacy/client.rs:518-533`), and the lock is
                // released the moment that connection is pooled. A connect
                // that finishes AFTER that point finds the lock free, takes
                // it, and becomes a SECOND h2 connection with a second
                // stream budget. Measured here: 5 runs in 25 produced two
                // stream-carrying connections at a fan of 128. The identity
                // `min(fan, cap) − limit` is per connection, so a row that
                // let that race decide would be reading a different quantity
                // one run in five.
                //
                // Parked, NOT dropped. Dropping resets the TCP and the
                // client's connect fails, which turns a spare connect into a
                // request failure and pollutes the count. Held, the peer
                // waits in TLS exactly as an unaccepted backlog entry does,
                // its `connect` future loses the race to the pool checkout,
                // and every request rides the one connection this server
                // serves. A client that somehow used a second one gets no
                // answer at all and the row fails on `GENEROUS` rather than
                // silently measuring two budgets.
                //
                // Both vectors are HELD here rather than detached: this loop
                // is itself inside a `Task`, so aborting it drops them and
                // with them every connection it started.
                let mut open: Vec<Task> = Vec::new();
                let mut parked: Vec<TcpStream> = Vec::new();
                loop {
                    let Ok((tcp, _peer)) = listener.accept().await else {
                        return;
                    };
                    if connections.fetch_add(1, Ordering::SeqCst) == 0 {
                        open.push(Task(spawn(connection(
                            Arc::clone(&tls),
                            tcp,
                            limit,
                            Arc::clone(&accepted),
                            Arc::clone(&serving),
                        ))));
                    } else {
                        parked.push(tcp);
                    }
                }
            })
        };
        Self {
            addr,
            pin,
            ca: certs.ca,
            accepted,
            serving,
            connections,
            _accepting: Task(accepting),
        }
    }

    /// The shipped client, pinned to this server.
    fn client(&self) -> HttpStore {
        HttpStore::new(
            &format!("https://{}", self.addr),
            vec![self.pin],
            &AmbientNetwork,
        )
        .unwrap_or_else(|e| panic!("http store: {e}"))
    }

    /// A TLS connection to this server on the `h2` leg, for the row that
    /// needs the refusal REASON rather than the rate.
    async fn tls(&self) -> tokio_rustls::client::TlsStream<TcpStream> {
        let tcp = TcpStream::connect(self.addr)
            .await
            .unwrap_or_else(|e| panic!("tcp: {e}"));
        let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("server name: {e}"));
        TlsConnector::from(Arc::new(client_config(&self.ca, ALPN_H2)))
            .connect(name, tcp)
            .await
            .unwrap_or_else(|e| panic!("tls: {e}"))
    }

    /// `fan` concurrent `max_seq` calls through ONE [`HttpStore`], counted
    /// from both ends.
    async fn burst(&self, fan: usize) -> Burst {
        let store = Arc::new(self.client());
        let mut tasks = Vec::with_capacity(fan);
        for _ in 0..fan {
            let store = Arc::clone(&store);
            tasks.push(spawn_with_current_subscriber(async move {
                store.max_seq(VOLUME).await
            }));
        }
        let mut failures = 0;
        for task in tasks {
            let answered = timeout(GENEROUS, task)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "a burst request did not settle inside {GENEROUS:?}. The likeliest \
                         cause is a request that went to a SECOND connection: this server \
                         serves the first and parks the rest, so anything not riding the \
                         served connection waits in TLS forever"
                    )
                })
                .unwrap_or_else(|e| panic!("burst task: {e}"));
            match answered {
                // §8.1: `404` + `not-found` IS the clean answer for an empty
                // volume, so a success here is a request that completed end
                // to end.
                Ok(None) => {}
                Ok(Some(seq)) => panic!("nothing was ever planted, yet max-seq answered {seq}"),
                // The SHAPE, not the gate. `Backend` also carries a
                // malformed-URL failure that never reached the wire, and
                // counting one of those as a shed would be counting the
                // harness. The refusal REASON is asserted in its own row,
                // by reason code, because this string cannot carry it.
                Err(RootStoreError::Backend(text)) => {
                    assert!(
                        text.starts_with("transport:"),
                        "a burst failure that is not a transport failure is \
                         the harness failing, not the server refusing: {text}"
                    );
                    failures += 1;
                }
                // The harness's own client carries the per-seam-call
                // deadline: a CI stall past it surfaces here as the
                // CLIENT cutting, which says nothing about the server
                // under test — named so it never reads as a server bug.
                Err(RootStoreError::Elapsed { .. }) => {
                    panic!(
                        "the harness client's own seam deadline fired — the machine \
                         stalled past it; this is harness environment, not a server verdict"
                    )
                }
                Err(other) => panic!("unexpected seam error: {other}"),
            }
        }
        Burst {
            failures,
            accepted: self.accepted.load(Ordering::SeqCst),
            serving: self.serving.load(Ordering::SeqCst),
            connections: self.connections.load(Ordering::SeqCst),
        }
    }
}

/// Spawn a task with the dispatcher that is current at this call site.
///
/// A scoped [`tracing::subscriber::set_default`] is thread-local, while the
/// futures in [`Delayed::burst`] are polled on Tokio worker threads. Attaching
/// the dispatcher to the future makes the subscriber current whenever that
/// future is polled, without making it process-global or admitting events from
/// unrelated tests. Keeping the attachment in the same helper used by the
/// worker-thread control below makes cross-thread visibility an executed
/// property rather than an assumption about the runtime.
fn spawn_with_current_subscriber<F>(future: F) -> JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    spawn(future.with_current_subscriber())
}

/// One connection: TLS, then the delay, then a `SETTINGS` announcing `limit`.
async fn connection(
    tls: Arc<rustls::ServerConfig>,
    tcp: TcpStream,
    limit: u32,
    accepted: Arc<AtomicUsize>,
    serving: Arc<AtomicUsize>,
) {
    let Ok(stream) = TlsAcceptor::from(tls).accept(tcp).await else {
        return;
    };
    // THE WHOLE MECHANISM, in one line. TLS is complete on both ends, so the
    // client may open streams for the whole of this wait, and its ceiling
    // until the handshake below is its OWN optimistic cap.
    pause(SETTINGS_DELAY).await;
    let Ok(mut conn) = h2::server::Builder::new()
        .max_concurrent_streams(limit)
        .handshake::<_, Bytes>(stream)
        .await
    else {
        return;
    };
    let mut carried = 0_usize;
    while let Some(next) = conn.accept().await {
        let Ok((_request, mut respond)) = next else {
            return;
        };
        if carried == 0 {
            serving.fetch_add(1, Ordering::SeqCst);
        }
        carried += 1;
        accepted.fetch_add(1, Ordering::SeqCst);
        let answer = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("granary-error", HeaderValue::from_static("not-found"))
            .body(())
            .unwrap_or_else(|e| panic!("response: {e}"));
        let _sent = respond.send_response(answer, true);
    }
}

/// What the identity predicts a burst of `fan` loses against an advertised
/// `limit`: `min(fan, cap) − limit`, where `cap` is the client's
/// pre-SETTINGS optimistic ceiling.
///
/// **Written ONCE and used by both rows**, so the positive control is the
/// same arithmetic evaluated at a different point rather than a separate
/// claim that happens to say zero. `H2_ADVERTISED_STREAM_FLOOR` stands in for
/// `cap` and the derivation gate in `granary-net` is what keeps that
/// substitution honest.
fn predicted_shed(fan: usize, limit: u32) -> usize {
    fan.min(H2_ADVERTISED_STREAM_FLOOR as usize)
        .saturating_sub(limit as usize)
}

/// Is `error` — or anything under it — an `h2` stream refusal?
///
/// **A REASON CODE, walked out of the chain, and never a `Display` string.**
/// Each failure of this shape renders as `client error (SendRequest)`, which
/// is `hyper-util`'s `ErrorKind::SendRequest` (`client.rs:336`) — emitted for
/// ANY inner error carrying `message: None`, which includes two purely local
/// hyper paths as well as a server refusal. A row that counted that string
/// would go on passing when the failures stopped being refusals, which is a
/// gate that cannot tell clean from blind.
fn is_refused_stream(error: &(dyn Error + 'static)) -> bool {
    let mut link = Some(error);
    while let Some(current) = link {
        if let Some(h2) = current.downcast_ref::<h2::Error>()
            && h2.reason() == Some(h2::Reason::REFUSED_STREAM)
        {
            return true;
        }
        link = current.source();
    }
    false
}

// ---------------------------------------- REFUSED_STREAM retry count
//
// Count the client's StreamRefused retry events. Zero final failures
// alone cannot distinguish recovery from a burst with no refused streams.

/// The exact text `HttpStore::send`'s retry diagnostic emits before its
/// ONE retry (`granary-client/src/http_store.rs`, the `tracing::debug!`
/// call in `send`) — read from source rather than duplicated by guess,
/// since a drifted copy here would silently stop counting anything and the
/// row would go on passing for the wrong reason.
const RETRY_EVENT_TEXT: &str = "seam attempt failed; retrying once";

/// A `tracing::field::Visit` that identifies the exact retry event these
/// rows measure: the diagnostic message AND `class = StreamRefused`.
/// Level and target are filtered by [`RetryCounter::on_event`] first.
struct FindsStreamRefusedRetry {
    message: bool,
    class: bool,
}

impl Visit for FindsStreamRefusedRetry {
    // The client's retry diagnostic records closed text labels.
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" && value == RETRY_EVENT_TEXT {
            self.message = true;
        }
        if field.name() == "class" && value == "stream_refused" {
            self.class = true;
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

/// Counts `granary_client`'s own `StreamRefused` retry events at `DEBUG`, and
/// nothing else — a `tracing_subscriber::Layer` installed as a scoped
/// thread-default subscriber by each test. [`Delayed::burst`] propagates
/// that dispatcher into its request tasks; a process-global subscriber would
/// also see retries from unrelated tests in the same process and would turn
/// this per-row measurement into shared state.
struct RetryCounter(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> Layer<S> for RetryCounter {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if *meta.level() != tracing::Level::DEBUG || !meta.target().starts_with("granary_client") {
            return;
        }
        let mut finder = FindsStreamRefusedRetry {
            message: false,
            class: false,
        };
        event.record(&mut finder);
        if finder.message && finder.class {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Install the retry-counting subscriber for the current scope. The guard
/// is returned with the counter so callers cannot accidentally drop the
/// subscriber before driving the client.
fn count_client_retries() -> (Arc<AtomicUsize>, tracing::dispatcher::DefaultGuard) {
    let count = Arc::new(AtomicUsize::new(0));
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(RetryCounter(Arc::clone(&count))),
    );
    (count, guard)
}

#[derive(Debug, Clone, Copy)]
enum ObservedRetryClass {
    StreamRefused,
    ConnectionFailed,
}

fn emit_observed_retry(class: ObservedRetryClass, message: &'static str) {
    let class = match class {
        ObservedRetryClass::StreamRefused => "stream_refused",
        ObservedRetryClass::ConnectionFailed => "connection_failed",
    };
    tracing::debug!(
        target: "granary_client::event",
        message,
        class,
    );
}

#[test]
fn the_retry_counter_counts_only_stream_refusals() {
    let count = Arc::new(AtomicUsize::new(0));
    let _default = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(RetryCounter(Arc::clone(&count))),
    );

    emit_observed_retry(ObservedRetryClass::ConnectionFailed, RETRY_EVENT_TEXT);
    emit_observed_retry(ObservedRetryClass::StreamRefused, "unrelated diagnostic");
    emit_observed_retry(ObservedRetryClass::StreamRefused, RETRY_EVENT_TEXT);

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the same retry message under ConnectionFailed is the negative control; \
         a StreamRefused carrying other text is the message control"
    );
}

#[test]
fn retry_counters_can_be_nested_in_one_process() {
    let (outer, _outer_default) = count_client_retries();
    emit_observed_retry(ObservedRetryClass::StreamRefused, RETRY_EVENT_TEXT);

    let inner = {
        let (inner, _inner_default) = count_client_retries();
        emit_observed_retry(ObservedRetryClass::StreamRefused, RETRY_EVENT_TEXT);
        assert_eq!(
            inner.load(Ordering::SeqCst),
            1,
            "the inner scope must observe its event"
        );
        inner
    };

    emit_observed_retry(ObservedRetryClass::StreamRefused, RETRY_EVENT_TEXT);
    assert_eq!(
        outer.load(Ordering::SeqCst),
        2,
        "the outer subscriber must resume after the inner guard drops"
    );
    assert_eq!(
        inner.load(Ordering::SeqCst),
        1,
        "the dropped inner subscriber must not observe the outer event"
    );
}

/// A scoped subscriber on the test thread must see an event emitted by the
/// same propagated spawn path [`Delayed::burst`] uses. Without the dispatcher
/// attachment the event runs under the worker thread's empty default, and a
/// zero retry count at the shipped limit could pass merely because the
/// observer was blind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_retry_counter_observes_a_tokio_worker_thread() {
    let test_thread = std::thread::current().id();
    let (count, _retry_default) = count_client_retries();
    let event_thread = timeout(
        GENEROUS,
        spawn_with_current_subscriber(async {
            emit_observed_retry(ObservedRetryClass::StreamRefused, RETRY_EVENT_TEXT);
            std::thread::current().id()
        }),
    )
    .await
    .unwrap_or_else(|_| panic!("the subscriber visibility probe did not settle"))
    .unwrap_or_else(|e| panic!("subscriber visibility task: {e}"));

    assert_ne!(
        event_thread, test_thread,
        "the subscriber visibility event must be emitted on a Tokio worker, \
         not on the thread carrying the scoped default guard"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the scoped retry counter did not observe the event emitted on a \
         Tokio worker; the burst would report zero retries if its dispatcher \
         propagation were missing"
    );
}

/// **THE POSITIVE CONTROL.** At the SHIPPED value, a fan above the advertised
/// limit costs NOTHING: the excess queues.
///
/// This is the half a one-sided guard leaves out, and without it the negative
/// row below is compatible with "the harness sheds whatever you give it".
///
/// **Stays two-sided on the retry axis too.** The negative row observes
/// `REFUSED_STREAM` retries because the shipped client recovers the shed.
/// This row is the pair's other half: at the SHIPPED limit there is no
/// excess to retry, so `retry_count` must be zero, or the negative row's
/// positive count would be just as compatible with "this harness retries
/// everything" as with "this harness retries the shed".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_the_shipped_limit_a_fan_above_it_sheds_nothing() {
    assert!(
        FAN > H2_MAX_CONCURRENT_STREAMS as usize,
        "a fan at or under the advertised limit ({H2_MAX_CONCURRENT_STREAMS}) \
         makes this row true of a server that enforces no limit at all. If \
         `H2_MAX_CONCURRENT_STREAMS` was RAISED, raise `FAN` past it — the \
         row is about the excess queueing, and there has to be an excess"
    );
    assert_eq!(
        predicted_shed(FAN, H2_MAX_CONCURRENT_STREAMS),
        0,
        "the identity itself must say zero here, or this row is asserting \
         something the negative row's arithmetic does not agree with"
    );

    let (retry_count, _retry_default) = count_client_retries();
    let server = Delayed::start(H2_MAX_CONCURRENT_STREAMS).await;
    let burst = server.burst(FAN).await;

    assert_eq!(
        burst.serving, 1,
        "the shed identity is a statement about ONE connection's stream \
         budget; {} connections carried streams, which is {} budgets, and \
         this row would be reading the wrong quantity ({} TCP connections \
         were accepted — see `Burst::serving` for why that number is \
         larger and why it is not what is asserted)",
        burst.serving, burst.serving, burst.connections
    );
    assert_eq!(
        burst.failures, 0,
        "at the SHIPPED limit ({H2_MAX_CONCURRENT_STREAMS}) a cold burst of \
         {FAN} lost {} requests. The advertised value is supposed to be at or \
         above every intended client's pre-SETTINGS optimistic cap \
         ({H2_ADVERTISED_STREAM_FLOOR}), which is what makes the excess QUEUE \
         instead of being refused",
        burst.failures
    );
    // THE CONTROL THAT MAKES `serving == 1` MEAN SOMETHING. Every request
    // is accounted for on the SERVER's side of the one connection it
    // serves, so the client's zero cannot be zero-because-nothing-happened.
    assert_eq!(
        burst.accepted, FAN,
        "every request must have reached the server on the one connection it \
         serves: {} of {FAN} did, so some settled somewhere this row does not \
         name",
        burst.accepted
    );
    assert_eq!(
        retry_count.load(Ordering::SeqCst),
        0,
        "nothing was shed at the SHIPPED limit, so the REFUSED_STREAM retry must \
         never have fired — a nonzero count here would mean this harness \
         retries indiscriminately rather than in response to a real \
         REFUSED_STREAM, which would make the negative row's positive \
         count worthless as evidence"
    );
}

/// **THE NEGATIVE CONTROL, the rate half.** Below the floor, the client's
/// `REFUSED_STREAM` retry pays for exactly `min(fan, cap) − limit` requests.
///
/// The rejected configuration was `H2_MAX_CONCURRENT_STREAMS = 16`. This is
/// what it costs, executed rather than cited — and the count is EXACT, not a
/// threshold, because a threshold ("some retried") passes on a harness that
/// is merely broken. At this row's fixed `FAN = 128` and `BELOW_FLOOR = 16`,
/// that exact count is 84 `StreamRefused` retries. A `ConnectionFailed`
/// diagnostic carries the same message but contributes nothing to the count;
/// there is no connection-failure component hidden inside the 84.
///
/// This row checks zero final failures, `FAN` accepted requests, and a
/// retry count equal to `predicted_shed(FAN, BELOW_FLOOR)`. It counts
/// the client's `StreamRefused` retry diagnostics through `RetryCounter`;
/// zero failures alone cannot distinguish recovery from a harness that
/// produced no refused streams.
///
/// **Why the client here is `HttpStore` and not something that would surface
/// the reason.** `HttpStore` hands back a rendered
/// [`RootStoreError::Backend`] string and never a typed `h2::Reason`
/// (`granary-client/src/http_store.rs::transport_failure`), so no reason code
/// survives AS A REASON to be asserted on — the most a row here could do is
/// match on prose. That loss of typed errors is why the
/// reason is a separate row with a separate client. This row measures
/// the retry count through the client that ships.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn below_the_floor_the_shipped_client_sheds_the_optimistic_excess() {
    let expected = predicted_shed(FAN, BELOW_FLOOR);
    assert!(
        expected > 0,
        "the identity predicts no shed at limit {BELOW_FLOOR} with a fan of \
         {FAN}, so this row would pass without the effect it exists to measure"
    );

    let (retry_count, _retry_default) = count_client_retries();
    let server = Delayed::start(BELOW_FLOOR).await;
    let burst = server.burst(FAN).await;

    assert_eq!(
        burst.serving, 1,
        "{} connections carried streams, which is {} stream budgets, and \
         the identity below assumes one ({} TCP connections were accepted; \
         see `Burst::serving`)",
        burst.serving, burst.serving, burst.connections
    );
    assert_eq!(
        burst.failures, 0,
        "the client retries a REFUSED_STREAM reset once, on the same \
         connection, before it ever reaches the caller — a below-floor \
         burst against the shipped client must therefore surface ZERO \
         failures; {} did not recover, which means either the retry \
         regressed or this harness stopped producing the shed to retry",
        burst.failures
    );
    // The SERVER's own count, which is a second observer and not a
    // restatement: every request — original attempt or REFUSED_STREAM retry —
    // rides the one connection this server serves, and the concurrent-
    // stream budget that refused it the first time frees up as earlier
    // streams complete, so all FAN eventually land.
    assert_eq!(
        burst.accepted, FAN,
        "every request must eventually reach the server on the one \
         connection it serves, original attempt or REFUSED_STREAM retry: {} of \
         {FAN} did, so some settled somewhere this row does not name",
        burst.accepted
    );
    // THE IDENTITY, SURVIVING AS THE RETRY COUNT. `predicted_shed` still
    // names exactly how many streams the server refuses past its
    // advertised limit — that fact did not change, only WHERE it is
    // observable from: not the client's failures (the retry recovers them)
    // but the client's retries (one for each refused stream).
    assert_eq!(
        retry_count.load(Ordering::SeqCst),
        expected,
        "advertising {BELOW_FLOOR} concurrent streams — the rejected \
         lower stream limit — should still cost exactly `min({FAN}, \
         {H2_ADVERTISED_STREAM_FLOOR}) - {BELOW_FLOOR}` = {expected} of a \
         cold burst of {FAN}, now paid as REFUSED_STREAM retries rather than \
         failures. RFC 9113 §3.4 lets the client open its own optimistic \
         cap's worth of streams before this server's SETTINGS lands, and \
         every one past the advertised limit is refused once and retried \
         once — never zero retries (the harness stopped producing the \
         shed) and never more than {expected} (something retried twice, \
         violating the at-most-one-retry-per-call bound)"
    );
}

/// **THE NEGATIVE CONTROL, the reason half.** The shed is a server
/// `RST_STREAM(REFUSED_STREAM)` and not a local failure.
///
/// **The client is `h2` directly, pinned to the SAME optimistic cap the floor
/// claims** (`initial_max_send_streams(H2_ADVERTISED_STREAM_FLOOR)`), so it
/// bursts exactly as a hyper client does — bare `h2`'s own default is
/// `usize::MAX`, which would make this row about a client granary does not
/// intend to serve. What it adds over the row above is the REASON CODE,
/// which `HttpStore` cannot supply because it stringifies the chain.
///
/// It also re-derives the same count from a second, independent client
/// stack: two clients agreeing on `min(fan, cap) − limit` is what
/// distinguishes the identity from an artefact of `hyper-util`'s pool.
///
/// **This row does NOT depend on [`SETTINGS_DELAY`] and the row above
/// does — measured, not assumed.** With the delay set to zero the
/// `HttpStore` row sheds NOTHING on loopback: a pooled client cannot fill
/// an optimistic window tens of microseconds wide. This row still sheds its full count at zero delay,
/// because the burst below is issued synchronously before the connection
/// driver has been polled, so no `SETTINGS` can have been read yet. The
/// RTT dependence is therefore the OTHER row's evidence and never this
/// one's; what this row owns is the reason code. Delete the row above and
/// the suite stops knowing the defect needs a path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn below_the_floor_the_shed_is_a_server_refused_stream() {
    let expected = predicted_shed(FAN, BELOW_FLOOR);

    let server = Delayed::start(BELOW_FLOOR).await;
    let (mut send, connection) = h2::client::Builder::new()
        .initial_max_send_streams(H2_ADVERTISED_STREAM_FLOOR as usize)
        .handshake::<_, Bytes>(server.tls().await)
        .await
        .unwrap_or_else(|e| panic!("h2 client handshake: {e}"));
    let _driver = Task(spawn(async move {
        let _ended = connection.await;
    }));

    let target = format!("https://{HOST}/volume/{VOLUME}/max-seq");
    let mut pending = Vec::with_capacity(FAN);
    for _ in 0..FAN {
        // `ready` before every send, which is hyper's own discipline
        // (`proto/h2/client.rs:757-766`) and the reason `UserError::Rejected`
        // is unreachable under it: a client that parks instead of
        // re-entering `send_request` never rejects locally, so every refusal
        // this row sees came off the wire.
        send = send
            .ready()
            .await
            .unwrap_or_else(|e| panic!("h2 client ready: {e}"));
        let request = hyper::Request::builder()
            .method("GET")
            .uri(&target)
            .body(())
            .unwrap_or_else(|e| panic!("request: {e}"));
        let (response, _body) = send
            .send_request(request, true)
            .unwrap_or_else(|e| panic!("h2 send_request: {e}"));
        pending.push(response);
    }

    let mut refused = 0;
    let mut other = Vec::new();
    for response in pending {
        match timeout(GENEROUS, response).await {
            Ok(Ok(answer)) => assert_eq!(answer.status(), StatusCode::NOT_FOUND),
            Ok(Err(error)) => {
                if is_refused_stream(&error) {
                    refused += 1;
                } else {
                    other.push(format!("{:?}", error.reason()));
                }
            }
            Err(elapsed) => panic!(
                "a stream did not settle inside {GENEROUS:?} ({elapsed}): every stream \
                 here is either answered `404` or reset, so a stream that does neither \
                 means the burst went somewhere this server is not serving"
            ),
        }
    }

    assert!(
        other.is_empty(),
        "every failure below the floor must be a REFUSED_STREAM the server \
         sent; these were something else: {other:?}"
    );
    assert_eq!(
        refused, expected,
        "the server advertised {BELOW_FLOOR} and the client optimistically \
         opened up to {H2_ADVERTISED_STREAM_FLOOR}, so exactly {expected} \
         streams should carry `Reason::REFUSED_STREAM`; {refused} did. The \
         reason code is what makes this a SERVER refusal rather than a local \
         one — `client error (SendRequest)`, the string these render as, is \
         emitted for two purely local hyper paths as well"
    );
}
