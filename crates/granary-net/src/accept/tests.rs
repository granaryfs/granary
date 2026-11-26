// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::accept` — the accept loop, the connection
//! envelope, the connection cap, and the shutdown contract (no
//! `select!`; every race is a biased, deterministic `poll_fn`).
//!
//! Out-of-line: `granary-net`'s non-test artifact has
//! workspace consumers (`granary-client`,
//! `granary-server`), so the module's own tests move out
//! of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{Listener, drain_watched, expire};
use http_body_util::Empty;
use hyper::Response;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::future::{pending, ready};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{Event, Level, Metadata, Subscriber, span};

/// How many events landed at each level.
#[derive(Debug, Default)]
struct Levels {
    error: AtomicUsize,
    warn: AtomicUsize,
    info: AtomicUsize,
    below: AtomicUsize,
}

/// A subscriber that records nothing but the LEVEL of what it sees.
///
/// Hand-rolled rather than pulled in: `tracing-subscriber` is the
/// server crate's dependency and this one has only `tracing`, and the
/// question here needs no formatting, no filtering and no fields —
/// which level a given event carries is the whole assertion.
#[derive(Debug)]
struct Counting(Arc<Levels>);

impl Subscriber for Counting {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "granary_net::accept"
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let level = *event.metadata().level();
        let counted = if level == Level::ERROR {
            &self.0.error
        } else if level == Level::WARN {
            &self.0.warn
        } else if level == Level::INFO {
            &self.0.info
        } else {
            &self.0.below
        };
        let _previous = counted.fetch_add(1, Ordering::SeqCst);
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

/// Rotation is observable when its own timer fires. Removing the debug event
/// leaves the graceful close mechanically correct but makes the venue unable
/// to pair a rotation with the client's retry diagnostic.
#[tokio::test]
async fn the_rotation_timer_reports_when_graceful_shutdown_starts() {
    let levels = Arc::new(Levels::default());
    let _default = tracing::subscriber::set_default(Counting(Arc::clone(&levels)));
    let (_client, server) = tokio::io::duplex(1024);
    let connection = hyper::server::conn::http1::Builder::new().serve_connection(
        TokioIo::new(server),
        service_fn(|_request| async {
            Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
        }),
    );
    let (_drain, receiver) = tokio::sync::watch::channel(());

    drain_watched(receiver, Some(Duration::from_millis(1)), connection).await;

    assert_eq!(
        (
            levels.below.load(Ordering::SeqCst),
            levels.info.load(Ordering::SeqCst),
            levels.warn.load(Ordering::SeqCst),
        ),
        (1, 0, 0),
        "the rotation timer must emit exactly one debug event before graceful shutdown"
    );
}

/// **A connection reaching the lifetime bound is the DESIGN, and the
/// design is not a warning.**
///
/// A connection still present after its graceful rotation window reaches this
/// line by design. At `warn!` that routine enforcement would share the level
/// an operator is meant to be able to read — the failed handshake, the refused
/// protocol, the accept error — and a noisy level is a level nobody looks at.
/// The event is worth EMITTING, because its rate is how a fleet notices peers
/// that did not finish inside the grace; it is not worth waking anyone.
///
/// **The subscriber is a THREAD-LOCAL default**, never
/// `set_global_default`: a global one is process-wide and settable
/// once, which under a harness that puts several tests in a process
/// is a row that passes or fails on which test ran first.
#[tokio::test]
async fn a_lifetime_close_is_not_a_warning() {
    let levels = Arc::new(Levels::default());
    let _default = tracing::subscriber::set_default(Counting(Arc::clone(&levels)));

    // A connection that never finishes, and a bound it cannot beat.
    expire(Duration::from_millis(1), pending::<()>()).await;

    assert_eq!(
        levels.warn.load(Ordering::SeqCst),
        0,
        "a connection reaching its hard lifetime after the graceful window is \
         routine enforcement, not a warning that should drown this level"
    );
    assert_eq!(
        levels.info.load(Ordering::SeqCst),
        1,
        "and it must still be REPORTED — the rate of this event is how \
         a fleet sees peers holding responses to the bound, so dropping \
         it to `debug!` or removing it takes the signal with the noise"
    );
    assert_eq!(levels.error.load(Ordering::SeqCst), 0);

    // THE CONTROL: a connection that ends on its own says nothing at
    // all. Without it, a row asserting "no warnings" would pass on an
    // `expire` that had stopped bounding anything.
    let quiet = Arc::new(Levels::default());
    let _also = tracing::subscriber::set_default(Counting(Arc::clone(&quiet)));
    expire(Duration::from_mins(1), ready(())).await;
    assert_eq!(quiet.info.load(Ordering::SeqCst), 0);
    assert_eq!(quiet.warn.load(Ordering::SeqCst), 0);
}
/// The accepted socket carries `TCP_NODELAY`, and the CONTROL proves
/// the assertion can fail: the same platform, the same listener, one
/// socket accepted through the [`Listener`] impl and one accepted
/// through `TcpListener::accept` directly. The first is `true`, the
/// second is the platform default — and if that default ever became
/// `true` on its own, this row would say so rather than passing
/// vacuously on a guarantee nothing here provides.
///
/// **What the control depends on, stated because it is not obvious:**
/// an accepted socket DOES inherit `TCP_NODELAY` from its listener
/// (measured on macOS and Linux). So the control is honest only while
/// the listener here leaves the option unset, which this row does by
/// binding its own listener and touching nothing. A future change that
/// sets the option on a listener would make the control fail — and
/// that failure would be correct, not spurious: it would mean this
/// row is no longer testing what it claims.
///
/// No concurrency is needed to reach either: the kernel completes a
/// loopback handshake into the listen backlog, so `connect` returns
/// before anyone calls `accept` and the accept then returns at once.
#[tokio::test]
async fn an_accepted_socket_carries_tcp_nodelay_and_a_raw_accept_does_not() {
    let mut listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));

    let _dialed = tokio::net::TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let accepted = Listener::accept(&mut listener)
        .await
        .unwrap_or_else(|e| panic!("accept: {e}"));
    assert!(
        accepted
            .nodelay()
            .unwrap_or_else(|e| panic!("nodelay read: {e}")),
        "every socket this server accepts must have Nagle OFF — an h2 \
         server writes small interleaved frames constantly, and Nagle \
         holds each one behind the peer's delayed ACK"
    );

    // THE CONTROL, on the same listener: a raw accept, bypassing the
    // impl above.
    let _also = tokio::net::TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let (raw, _peer) = tokio::net::TcpListener::accept(&listener)
        .await
        .unwrap_or_else(|e| panic!("raw accept: {e}"));
    assert!(
        !raw.nodelay()
            .unwrap_or_else(|e| panic!("nodelay read: {e}")),
        "the platform default is Nagle ON: if this ever fails, the \
         option above has stopped being load-bearing and the comment \
         on it is wrong"
    );
}
