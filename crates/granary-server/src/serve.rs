// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Serving, and the process death that ends it.
//!
//! **Why this is a library item and not four lines of `main`.** The exit
//! is the part of shutdown that cannot be checked by reading a log: it is
//! a process that must be gone. Driving it needs a caller that can supply
//! its own trigger and a service that refuses to drain, and `main` can
//! offer neither — so the race, the outcome mapping and the exit codes
//! live here, where `tests/deadline_exit.rs` reaches them.
//!
//! **The shape is a spawn-free biased race**, the same one `granary-net`'s
//! accept loop uses and for the same reason: `select!` randomises branch
//! order from an RNG the simulator cannot seed, and it is banned. The
//! trigger is polled first and fused — once it completes, the shutdown
//! level goes up ONCE and the trigger is never polled again — and the
//! sender is kept alive for the whole race, so a dropped-sender shutdown
//! cannot fire by accident.
//!
//! **Nothing runs after `serve` resolves.** The async block ends at the
//! `serve` future, and [`serve_and_exit`] returns `!`, so a restart loop
//! or a second accept pass is not something a reviewer has to look for —
//! an arm that returns does not compile.

use std::future::Future;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use granary_net::accept::{AcceptConfig, Listener, ShutdownOutcome, serve};
use hyper::body::Body;
use hyper::service::Service;
use hyper::{Request, Response};

use crate::adapter::WireByteHandle;
use crate::wire_snapshot::write_server_snapshot;

/// The drain completed: every connection finished before the deadline.
///
/// The exit CODE is the outcome record — deploy tooling reads it, not the
/// logs, which is why each one is named here rather than spelled as a
/// literal at its `exit` call.
pub const EXIT_DRAINED: i32 = 0;

/// The listener failed in a way the accept loop could not survive.
pub const EXIT_SERVE_FAILED: i32 = 1;

/// Configuration or bind failure: nothing was ever served.
///
/// The original scaffold used `2` for this and retires with it; the code
/// is unchanged for a genuine startup refusal.
pub const EXIT_STARTUP_FAILED: i32 = 2;

/// The shutdown budget expired with connections or authority stop still
/// pending, and the process killed itself to stop outstanding work.
///
/// Connection tasks are detached, so this outcome means undrained tasks
/// are still on the runtime and only process death stops them.
pub const EXIT_DEADLINE_EXPIRED: i32 = 3;

/// The publication authority fenced itself: it observed that its state
/// can no longer be trusted to be its own, and stopped serving rather than
/// sign over it.
///
/// Answered by the authority host ([`crate::run_authority_host`]) composed
/// by the shipped binary. An observed fence outranks every other shutdown outcome, so a
/// fenced run answers this code whatever else ended it.
pub const EXIT_FENCED: i32 = 4;

const _: () = {
    // The VALUES are the deploy-tooling contract — the whole reason the
    // exits are named constants — and the process tests assert against
    // the same names that produce the exits, so both sides of a drifted
    // value would drift together. This is the one place the numbers
    // themselves are pinned.
    assert!(EXIT_DRAINED == 0, "0 is the drained exit, by contract");
    assert!(
        EXIT_SERVE_FAILED == 1,
        "1 is the serve failure, by contract"
    );
    assert!(
        EXIT_STARTUP_FAILED == 2,
        "2 is the startup refusal, by contract"
    );
    assert!(
        EXIT_DEADLINE_EXPIRED == 3,
        "3 is the forced exit, by contract"
    );
    assert!(EXIT_FENCED == 4, "4 is the authority's fence, by contract");
};

/// The production shutdown trigger: whichever of SIGTERM or SIGINT
/// arrives first.
///
/// **Call this inside a runtime context** — `main` does it under
/// `runtime.enter()`. `tokio::signal::unix::signal` does not return `Err`
/// when there is no reactor running; it PANICS ("there is no reactor
/// running"), so the guard is what turns a registration problem into the
/// startup failure this signature promises rather than a panic on a
/// no-panic surface.
///
/// Registration happens HERE, eagerly, and the returned future is only
/// the waiting half. A trigger that registered lazily on first poll would
/// leave a window in which the process is listening and a signal is still
/// handled by the default disposition — which for SIGTERM is immediate
/// death with no drain at all.
///
/// # Errors
///
/// Returns the registration failure, which the caller must treat as a
/// startup failure: a future that silently never fires is a server that
/// cannot be shut down gracefully.
#[cfg(unix)]
pub fn shutdown_trigger() -> std::io::Result<impl Future<Output = ()> + Send> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    // Biased and hand-rolled, like every other race in the transport
    // stack: `select!` is banned, and the bias is harmless here because
    // either arm means the same thing.
    Ok(std::future::poll_fn(move |context| {
        if terminate.poll_recv(context).is_ready() {
            return std::task::Poll::Ready(());
        }
        interrupt.poll_recv(context).map(|_arrived| ())
    }))
}

/// What a composition root supplies to have [`serve_and_exit`]
/// write the wire-byte snapshot after a clean drain — present only when
/// the harness asked for one. `main.rs`'s boot contract is
/// environment-only (`GRANARY_WIRE_SNAPSHOT`/`_RUN_ID`/`_ROLE`, all
/// three or none), so this is `Option`-shaped end to end: no env vars,
/// no `WireSnapshotRequest`, and production is unchanged — a process
/// given none of the three writes nothing and counts anyway.
#[derive(Debug)]
pub struct WireSnapshotRequest {
    /// The destination — REFUSED if it already exists.
    pub path: PathBuf,
    /// Operator-supplied, never inferred from the network; refused if
    /// empty.
    pub run_id: String,
    /// From the closed vocabulary; refused if empty or outside it.
    pub role: String,
    /// The address the server bound, as the readiness line prints it.
    pub listen_addr: String,
    /// The process-wide counters this write seals.
    pub handle: WireByteHandle,
}

/// Serve on `listener` until `trigger` fires, drain, and end the process.
///
/// # The runtime is the caller's, and it must be built with the drivers
///
/// `runtime` MUST have both the time and I/O drivers enabled —
/// `tokio::runtime::Builder::new_multi_thread().enable_all()` is the
/// spelling every caller here uses. This is a constraint the signature
/// cannot express and the code cannot show: the accept loop's drain calls
/// `tokio::time::timeout`, which PANICS on a runtime with no time driver,
/// and the loop cannot accept a connection without the I/O driver. A
/// runtime built with `enable_io()` alone compiles and then panics on the
/// first shutdown.
///
/// # What the outcome means
///
/// The three arms are the three ways serving can end, and each one exits.
/// [`ShutdownOutcome::DeadlineExpired`] exits and does nothing else —
/// not even a log line, because exit must not be blocked: undrained
/// connection tasks are resident on a runtime whose workers may be inside
/// a poll that never yields, so a synchronous tracing sink under
/// backpressure could block before the exit ever runs. The same argument
/// binds the whole drain path — `serve` logs NOTHING once shutdown is
/// observed, because a blocked write before the deadline is armed wedges
/// shutdown one step earlier — so the exit CODE is the outcome's only
/// record, by design. Dropping the runtime instead of exiting is worse
/// still: its drop joins the workers, and a non-yielding poll holds it
/// open forever.
///
/// `std::process::exit` runs no destructors and does not join the
/// runtime. That is the point.
#[expect(
    clippy::needless_pass_by_value,
    reason = "taking the runtime BY VALUE is the contract: this function ends the process, so a caller that kept a handle to the runtime would be describing a lifetime that does not exist"
)]
pub fn serve_and_exit<L, S, B>(
    runtime: tokio::runtime::Runtime,
    listener: L,
    tls: Arc<rustls::ServerConfig>,
    service: S,
    config: AcceptConfig,
    trigger: impl Future<Output = ()> + Send,
    wire_snapshot: Option<WireSnapshotRequest>,
) -> !
where
    L: Listener,
    S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (shutdown, watched) = tokio::sync::watch::channel(false);

    let outcome = runtime.block_on(async move {
        let mut trigger = std::pin::pin!(trigger);
        let mut served = std::pin::pin!(serve(listener, tls, service, watched, config));
        // The fuse. `serve`'s channel contract is a one-shot monotonic
        // trigger — send `true` once, or drop the sender — and polling a
        // completed future again is a contract violation of its own, so
        // one flag answers both.
        let mut fired = false;
        std::future::poll_fn(move |context| {
            if !fired && trigger.as_mut().poll(context).is_ready() {
                fired = true;
                // The sender stays alive for the whole race: it is moved
                // into this closure, so the "every sender gone" shutdown
                // path cannot fire behind the trigger's back.
                let _observed = shutdown.send(true);
            }
            served.as_mut().poll(context)
        })
        .await
    });

    match outcome {
        Ok(ShutdownOutcome::Drained) => {
            // The ONLY point at which every connection is
            // closed and the count is final — after `block_on` returns,
            // before the exit, and only on THIS outcome. A
            // `DeadlineExpired` exit means a connection was still
            // resident, so some request's frames may be partial; no
            // snapshot is the fail-closed answer there, and the exit
            // code says why.
            if let Some(request) = wire_snapshot {
                write_wire_snapshot(&request);
            }
            std::process::exit(EXIT_DRAINED)
        }
        Ok(ShutdownOutcome::DeadlineExpired) => std::process::exit(EXIT_DEADLINE_EXPIRED),
        Err(error) => {
            tracing::error!(%error, "serve failed");
            std::process::exit(EXIT_SERVE_FAILED)
        }
    }
}

/// How long [`write_wire_snapshot`] waits for its diagnostic line to
/// reach stderr before giving up on it.
///
/// This uses the SAME bound and the SAME reasoning as
/// `main.rs`'s own `STARTUP_REPORT_BOUND`, at the OTHER end of the
/// process — see that constant's doc for the measurement behind the
/// figure. It is not reused directly only because `main.rs` is a
/// SEPARATE crate (the `[[bin]]` target) from this `[lib]` and the
/// constant is private to it.
const WIRE_SNAPSHOT_REPORT_BOUND: Duration = Duration::from_millis(250);

/// The snapshot write, on the ONLY arm that calls it.
///
/// **A refused write does not change the exit code.** The write is
/// auxiliary instrumentation an operator opted into by setting all
/// three `GRANARY_WIRE_*` variables; the service itself drained
/// cleanly, which is what [`EXIT_DRAINED`] records, and a misconfigured
/// run id or role — the harness's own bug, not this process's — does
/// not turn a successful drain into a reported failure. The reason is
/// written DIRECTLY to stderr, the same reasoning `main.rs`'s
/// `startup_failure` uses for its own exit-adjacent line: nothing here
/// runs inside the drain race any more (this is strictly AFTER
/// `block_on` returned, with every worker idle), so the backpressure
/// argument that keeps ordinary request logging off this path does not
/// apply.
///
/// **The write is BOUNDED, not merely
/// synchronous.** Written directly on this thread, unbounded, it could
/// stall: if stderr were a full pipe with no reader draining
/// it — or if the lossy sink's OWN writer thread held the very same
/// handle at a bad moment — this thread would BLOCK inside
/// `write_all`, and since this runs on the thread that is about to call
/// `std::process::exit`, a blocked write here means the process never
/// reaches that exit at all: a clean drain that earned
/// [`EXIT_DRAINED`] would instead hang forever, indistinguishable from
/// a wedged server to anything watching the process. **A pre-existing
/// snapshot destination is enough to reach this path** — an ordinary
/// operator mistake, not a privileged one — so "this line is rare" was
/// never a reason to leave it unbounded.
///
/// This follows `main.rs`'s `startup_failure` precedent exactly: the
/// write happens on a helper thread the process is free to walk away
/// from, and this thread waits [`WIRE_SNAPSHOT_REPORT_BOUND`] for it to
/// land before falling through to the exit that already follows this
/// call. **Do NOT simply delete the diagnostic instead** — a refused
/// snapshot write does not change the exit code (see above), so this
/// line is the ONLY signal anything went wrong; losing it to a wedged
/// stderr is one failure, but losing it BY DELETING THE LINE ON
/// PURPOSE, on every run, is strictly worse, and blocking the exit
/// forever on a rare wedge would have been worse still.
fn write_wire_snapshot(request: &WireSnapshotRequest) {
    let totals = request.handle.totals();
    if let Err(error) = write_server_snapshot(
        &request.path,
        &request.run_id,
        &request.role,
        &request.listen_addr,
        totals,
    ) {
        let line = format!("wire-snapshot not written: {error}\n");
        let (done, waited) = std::sync::mpsc::channel();
        // `Builder::spawn`, not `std::thread::spawn`: the free function
        // PANICS when the OS refuses a thread, and a panic on this
        // exit-adjacent path would replace the named refusal with `101`
        // and a backtrace — the same reasoning `startup_failure` states
        // for its own identical spawn. On `Err` the closure (and the
        // `done` sender inside it) is simply dropped, so the recv below
        // returns `Disconnected` immediately rather than waiting out
        // the bound.
        let _writer = std::thread::Builder::new().spawn(move || {
            let mut stderr = std::io::stderr().lock();
            let _written = stderr.write_all(line.as_bytes());
            let _flushed = stderr.flush();
            let _signalled = done.send(());
        });
        let _bounded = waited.recv_timeout(WIRE_SNAPSHOT_REPORT_BOUND);
    }
}
