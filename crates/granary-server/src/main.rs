// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The production composition root.
//!
//! It reads the environment,
//! builds a runtime, registers the shutdown signals, loads the TLS
//! material, constructs the store and the service, binds, says it is
//! listening, and drives the selected host. The libraries define the
//! admission order, drain budget, accept envelope and exit codes. The
//! composition required by [`run_authority_host`]'s contract is spelled
//! here: write drain begins before transport shutdown is forwarded, and
//! the accept loop's deadline equals the host budget. This wiring adds no
//! policy beyond that contract.
//!
//! **The STORE schema lives in [`granary_server::config`], not here.**
//! This file reads `GRANARY_LISTEN` and the two TLS paths — the boot
//! minimum a composition root cannot delegate — and hands the rest to
//! `store_from_env`, which decides the discriminant, builds the store
//! and carries back the dispatch deadline that store runs under.
//! Two forms exist: `memory:` (no deadline — an in-process map cannot
//! stop answering) and `s3:` (thirty seconds). Any other value is a
//! startup refusal naming the variable.
//!
//! **Authority mode composes [`run_authority_host`].** Complete authority
//! configuration requires the real Linux boot ID.
//! Recovery finishes on a dedicated thread before the serve callback binds
//! and announces readiness. Every shutdown cause cancels writes before
//! transport drain, under one host budget. The process exits with the host's
//! code while its runtime remains alive.
//!
//! **Arguments select the command line, before anything of `serve`'s is
//! read.** With no arguments the binary serves. With any, it runs
//! [`run_command_line`] for `enrollment` or [`run_debug_grant_command_line`]
//! for `debug-grant`, the local `support-export`, `initialise` or `unfence`:
//! `0` done, `64` usage,
//! `65` refused, `74` I/O or publication uncertainty. Enrollment and grant
//! and lifecycle verbs use `65` for I/O before publication and `74` from publication on;
//! support export uses `74` for all I/O failures. An unknown first argument
//! is a usage exit. Support export runs before any environment read, with
//! argv, the wall Clock and bounded final reporting. The other verbs receive
//! enrollment randomness, grant Clock and standard streams.

// `disallowed_types` is `allow` on the workspace line. This binary is its
// own crate root, so the library's opt-in does not reach it: it opts in
// for the same reasons, hash-iteration order and aws-lc's generator,
// which `clippy.toml` bans outside the cryptographic-randomness seam's
// one sanctioned construction.
#![deny(clippy::disallowed_types)]

use std::future::Future as _;
use std::io::Write as _;
use std::net::ToSocketAddrs as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use granary_core::clock::Clock;
use granary_core::rng::ProcessRng;
use granary_core::sheaf::Timestamp;
use granary_net::accept::{AcceptConfig, SHUTDOWN_DEADLINE, serve};
use granary_net::secure_random::OsSecureRandom;
use granary_net::tls::{ClientAuth, TlsConfigError, server_tls_config};
use granary_server::{
    AuthorityParts, EXIT_STARTUP_FAILED, EnrollmentReader, FileLog, GrainService, Pause,
    PrincipalControls, VolumeConfig, WireSnapshotRequest, config, host_boot_id, run_authority_host,
    run_command_line, run_debug_grant_command_line, serve_and_exit, shutdown_trigger,
    worker_threads,
};
use granary_store::backend::GranaryStore;
use granary_store::crypto::TrustedKeys;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Where to listen: `host:port`.
///
/// The port may be `0` — `127.0.0.1:0` is the tested spelling and what
/// the process tests use, with the BOUND address recovered from the
/// readiness line. A bare `:0` is NOT a supported form: the string goes
/// to `ToSocketAddrs` as written, and an empty host is the platform
/// resolver's business rather than a granary contract, so it lands on the
/// ordinary unparseable-value refusal below.
const LISTEN: &str = "GRANARY_LISTEN";

/// The PEM file holding the certificate CHAIN.
const TLS_CERT: &str = "GRANARY_TLS_CERT";

/// The PEM file holding the private key.
const TLS_KEY: &str = "GRANARY_TLS_KEY";

/// This server's configured `{base}` (§4.1) is empty. The plumbing exists so
/// the configuration surface has somewhere to land.
const BASE: &str = "";

/// The wire-byte snapshot destination — a harness sets this on
/// the command line of exactly the server process it is for, never
/// exported into its own environment where every child would inherit
/// it. Absent in production.
const WIRE_SNAPSHOT: &str = "GRANARY_WIRE_SNAPSHOT";
/// The run id stamped into the snapshot, verbatim.
const WIRE_RUN_ID: &str = "GRANARY_WIRE_RUN_ID";
/// The role stamped into the snapshot, verbatim.
const WIRE_ROLE: &str = "GRANARY_WIRE_ROLE";

/// Read `name` from the environment the way [`wire_snapshot_env`] needs
/// to: `Some` for genuinely SET (whatever the bytes), `None` only for
/// genuinely UNSET.
///
/// `std::env::var(name).ok()` collapses TWO different `VarError` variants
/// onto the same `None`: `NotPresent` (the variable is unset, the
/// intended case) and `NotUnicode` (the variable IS set, to a byte
/// string that is not valid UTF-8). A Unix environment variable is
/// bytes, not text, and `GRANARY_WIRE_SNAPSHOT` is a PATH — a scratch
/// filename containing an arbitrary byte is exactly the operator input
/// this variable exists to carry. A caller that cannot tell "unset"
/// from "set but unreadable" would fold a non-UTF-8 path into the
/// `(None, None, None)` arm below and run the ENTIRE instrumented run
/// uninstrumented and silent — the very failure the all-or-nothing rule
/// exists to refuse — or, with only one of three variables affected
/// this way, report a set variable as unset in the refusal text,
/// misleading whoever reads it.
///
/// So this refuses OUTRIGHT, naming the variable, rather than folding
/// the ambiguity into `None`: a value this process cannot read as text
/// cannot be validated as a run id, a role, or a path either, and a
/// startup refusal that names the byte-lossy variable is a strictly
/// more informative failure than a process that quietly never
/// instruments anything.
fn wire_env_var(name: &str) -> Option<String> {
    match std::env::var_os(name) {
        None => None,
        Some(value) => match value.into_string() {
            Ok(value) => Some(value),
            Err(raw) => startup_failure(&format!(
                "{name} is set but is not valid UTF-8 ({}) — a wire-snapshot \
                 variable must be legible text",
                raw.display()
            )),
        },
    }
}

/// The wire-snapshot request the environment describes, or
/// `None` — ALL THREE `GRANARY_WIRE_*` variables or none, the same
/// all-or-nothing rule the CLI's `--wire-snapshot`/`--wire-run-id`/
/// `--wire-role` trio uses. A harness that set one but not the other two
/// almost certainly meant to set all three; running uninstrumented and
/// silent is a worse failure than refusing to start.
///
/// **PRESENCE is not enough.** When all three are set, their VALUES are
/// also validated here, through `granary_server::wire_snapshot_trio_is_valid`
/// — the same check the library's own shutdown-time writer makes. An
/// empty destination path, an empty run id, or a role outside the closed
/// vocabulary each refuses at startup, not only after a whole run has
/// already been served.
fn wire_snapshot_env() -> Option<(String, String, String)> {
    // Use `wire_env_var`, not `std::env::var(..).ok()` — see that
    // function's own doc for the set-but-non-UTF-8 gap this closes.
    let path = wire_env_var(WIRE_SNAPSHOT);
    let run_id = wire_env_var(WIRE_RUN_ID);
    let role = wire_env_var(WIRE_ROLE);
    match (path, run_id, role) {
        (Some(path), Some(run_id), Some(role)) => {
            // Validate the trio HERE with the same check the library's own
            // shutdown-time writer makes: a `PRESENT`
            // trio can still be malformed (an empty path, an empty run
            // id, a role outside the closed vocabulary), and that must
            // be a startup refusal like any other misconfigured
            // variable, never a failure discovered only after a whole
            // run has already been served.
            //
            // `dest` is part of this
            // check — `wire_snapshot_trio_is_valid`'s own name promises a
            // TRIO, and validating only `run_id`/`role` lets
            // `GRANARY_WIRE_SNAPSHOT=""` (an unexpanded shell variable)
            // pass startup, serve the entire instrumented run, and only THEN
            // produce a stray `.tmp` in the process's current working
            // directory and a silent non-write at
            // [`granary_server::EXIT_DRAINED`].
            if let Err(error) = granary_server::wire_snapshot_trio_is_valid(
                std::path::Path::new(&path),
                &run_id,
                &role,
            ) {
                startup_failure(&format!(
                    "{WIRE_SNAPSHOT}={path:?}, {WIRE_RUN_ID}={run_id:?} and {WIRE_ROLE}={role:?} \
                     do not form a legal wire-snapshot trio: {error}"
                ));
            }
            Some((path, run_id, role))
        }
        (None, None, None) => None,
        (path, run_id, role) => startup_failure(&format!(
            "{WIRE_SNAPSHOT} ({}), {WIRE_RUN_ID} ({}) and {WIRE_ROLE} ({}) must be set together \
             or not at all",
            presence(path.as_ref()),
            presence(run_id.as_ref()),
            presence(role.as_ref()),
        )),
    }
}

/// Whether an `Option` the operator supplied is set — the three-word
/// fragment [`wire_snapshot_env`]'s refusal names each variable with.
fn presence<T>(value: Option<&T>) -> &'static str {
    if value.is_some() { "set" } else { "unset" }
}

#[expect(
    clippy::too_many_lines,
    reason = "composition preserves startup ordering and ownership across the two host branches"
)]
fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if !args.is_empty() {
        command_line(&args);
    }

    let authority =
        config::authority::authority_from_env().unwrap_or_else(|reason| startup_failure(&reason));

    if authority.is_some() {
        let wire_variables: Vec<_> = [WIRE_SNAPSHOT, WIRE_RUN_ID, WIRE_ROLE]
            .into_iter()
            .filter(|name| std::env::var_os(name).is_some())
            .collect();
        if !wire_variables.is_empty() {
            startup_failure(&format!(
                "{}: wire snapshot is not available in authority mode",
                wire_variables.join(", ")
            ));
        }
    }
    let authority = authority.map(|config| {
        let boot = host_boot_id().unwrap_or_else(|reason| startup_failure(&reason.to_string()));
        (config, boot)
    });

    let listen = required(LISTEN);
    let cert_path = required(TLS_CERT);
    let key_path = required(TLS_KEY);

    // PINNED rather than left to tokio's default, and the value is the
    // same one tokio would have picked. The verify permit count is
    // `workers - 1`, which only means "leave a worker free" if the two
    // figures are the SAME figure — a default read independently by the
    // runtime and by the service is two figures that agree by
    // coincidence, and a tokio release that moved its default would
    // break the relation with nothing anywhere saying so.
    let workers = worker_threads();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        // Both drivers, which `serve_and_exit` documents as a caller
        // obligation: the drain calls `tokio::time::timeout` and the
        // accept loop needs I/O.
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => startup_failure(&format!("building the runtime: {error}")),
    };

    let grant_host = {
        let _entered = runtime.enter();
        granary_server::DebugGrantHost::new(&mut OsSecureRandom::new()).unwrap_or_else(|error| {
            startup_failure(&format!("drawing server incarnation: {error}"))
        })
    };
    // The LOSSY stderr sink, not a bare `std::io::stderr`: every log
    // line here is written from a runtime worker, and a synchronous
    // write to a backpressured stderr blocks that worker — enough of
    // them and the time driver is stranded, the drain deadline never
    // fires, and the process is unkillable short of SIGKILL. Dropped
    // lines are counted and reported in-stream. Logs still land on
    // stderr (the process tests read the readiness line there).
    let sink = granary_server::lossy_stderr();
    let (capture, subscriber) = grant_host.subscriber(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
            .from_env_lossy(),
        sink,
        authority.is_some(),
    );
    tracing_subscriber::util::SubscriberInitExt::init(subscriber);

    // Inside a runtime context, and the guard is load-bearing rather than
    // tidy: `tokio::signal::unix::signal` PANICS outside one instead of
    // returning `Err`. Registered BEFORE the listener exists, so the
    // window in which the process is reachable but a signal would hit the
    // default disposition never opens.
    let signalled = {
        let _entered = runtime.enter();
        match shutdown_trigger() {
            Ok(trigger) => trigger,
            Err(error) => startup_failure(&format!("registering SIGTERM/SIGINT: {error}")),
        }
    };

    let clock = Arc::new(WallClock);
    let client_auth =
        authority
            .as_ref()
            .map_or(ClientAuth::None, |(config, _)| ClientAuth::Enrolled {
                ca: certificate_chain_for(&config.client_ca, config::authority::ENV_CLIENT_CA),
                clock: clock.clone(),
            });
    let tls = Arc::new(
        match server_tls_config(
            certificate_chain(&cert_path),
            private_key(&key_path),
            client_auth,
        ) {
            Ok(config) => config,
            Err(error) => {
                #[expect(
                    clippy::unnecessary_debug_formatting,
                    reason = "escape arbitrary path bytes in startup diagnostics"
                )]
                let reason = match (&error, authority.as_ref()) {
                    (
                        TlsConfigError::NoClientCa
                        | TlsConfigError::ClientCa { .. }
                        | TlsConfigError::Verifier(_),
                        Some((config, _)),
                    ) => format!(
                        "{}={:?}: {error}",
                        config::authority::ENV_CLIENT_CA,
                        config.client_ca
                    ),
                    _ => format!(
                        "the TLS configuration from {TLS_CERT} and {TLS_KEY} was refused: {error}"
                    ),
                };
                startup_failure(&reason);
            }
        },
    );

    // Read and BUILT inside the runtime context, for a milder version of
    // the trigger's reason above: the `s3:` form constructs an HTTP
    // client whose connection pool and credential refresher are reactor
    // objects, and building one with no runtime entered is a class of
    // failure that would surface as a panic in a composition root rather
    // than as this file's ordinary naming refusal. `memory:` needs none
    // of it; doing both under the guard keeps the discriminant the only
    // difference between the two paths.
    let store_config = {
        let _entered = runtime.enter();
        config::store_from_env().unwrap_or_else(|reason| startup_failure(&reason))
    };
    for variable in &store_config.ignored_proxy_variables {
        tracing::warn!(
            variable,
            "set in the environment and ignored: the store connects directly"
        );
    }

    if let Some((config, boot)) = authority {
        // Resolution may block, so finish it on the main thread before the
        // host is polled. Readiness still requires binding only in its callback.
        let addresses: Vec<_> = listen
            .to_socket_addrs()
            .unwrap_or_else(|error| startup_failure(&format!("{LISTEN}={listen:?}: {error}")))
            .collect();
        if addresses.is_empty() {
            startup_failure(&format!("{LISTEN}={listen:?}: no addresses resolved"));
        }
        let reader =
            EnrollmentReader::open(&config.enrollment_dir, config.accept_unsupported_filesystem)
                .unwrap_or_else(|error| {
                    startup_failure(&format!(
                        "{}: {error}",
                        config::authority::ENV_ENROLLMENT_DIR,
                    ))
                });
        let volumes: Vec<_> = config
            .volumes
            .iter()
            .map(|(volume, keys)| {
                let keys = TrustedKeys::new(keys.iter().copied()).unwrap_or_else(|error| {
                    startup_failure(&format!(
                        "{}: {error}",
                        config::authority::publisher_keys_variable(volume)
                    ))
                });
                VolumeConfig::new(volume.clone(), keys)
            })
            .collect();
        let controls = Arc::new(PrincipalControls::new(config.controls, clock.clone()));
        let counters = Arc::new(granary_server::refusals::RefusalCounters::default());
        let engine_reader = reader.clone();
        let state_dir = config.state_dir.clone();
        let accept_unsupported = config.accept_unsupported_filesystem;
        let engine_store = GranaryStore::new(Arc::clone(&store_config.store));
        let admission = store_config.admission;
        let budget = SHUTDOWN_DEADLINE;
        let support_path = config.enrollment_dir.join("SUPPORT");
        let support_configuration = granary_server::retain_configuration(
            &config,
            grant_host.incarnation(),
            workers,
            budget,
            store_config.dispatch_deadline,
        )
        .inspect_err(|error| {
            tracing::warn!(reason = error.0, "support configuration projection refused");
        })
        .ok();
        #[cfg(feature = "crash-points")]
        granary_server::install_host_test_plan()
            .unwrap_or_else(|error| startup_failure(&format!("host test plan: {error}")));
        let exit = runtime.block_on(run_authority_host(
            boot,
            move |seat| async move {
                let log = match FileLog::new(&state_dir, accept_unsupported) {
                    Ok(log) => log,
                    Err(error) => {
                        seat.not_built(format!("{}: {error}", config::authority::ENV_STATE_DIR));
                        return;
                    }
                };
                if let Err(error) = log.require_separate_enrollment(&engine_reader) {
                    seat.not_built(error);
                    return;
                }
                let intent_store = log.intent_store();
                let volumes = volumes
                    .into_iter()
                    .map(|v| v.with_intents(Arc::clone(&intent_store)))
                    .collect();
                let parts = AuthorityParts {
                    log,
                    store: engine_store,
                    admission,
                    clock: WallClock,
                    rng: ProcessRng::new(),
                    secure_random: OsSecureRandom::new(),
                    pause: TimerPause,
                };
                if let Some(driver) = seat.start(parts, volumes).await {
                    let _end = driver.run().await;
                }
            },
            move |handle, mut shutdown| {
                let service = GrainService::with_deadline(
                    Arc::new(GranaryStore::new(store_config.store)),
                    BASE,
                    workers,
                    store_config.dispatch_deadline,
                )
                .with_authority_writes(reader, controls, counters, &config, handle)
                .with_debug_grants(
                    &grant_host,
                    &config.enrollment_dir,
                    config.accept_unsupported_filesystem,
                    capture.clone(),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                // The callback is synchronous, already inside block_on's
                // runtime context. Conversion registers the nonblocking socket.
                let listener =
                    std::net::TcpListener::bind(addresses.as_slice()).map_err(|error| {
                        std::io::Error::new(error.kind(), format!("{LISTEN}={listen:?}: {error}"))
                    })?;
                listener.set_nonblocking(true)?;
                let listener = tokio::net::TcpListener::from_std(listener)?;
                let addr = listener.local_addr()?;
                let support = support_configuration.map(|configuration| {
                    granary_server::SupportWriter::new(
                        &support_path,
                        accept_unsupported,
                        granary_server::bound_configuration(configuration, addr),
                        clock,
                        service.clone(),
                    )
                });
                let draining = service.draining();
                let accept = AcceptConfig {
                    shutdown_deadline: budget,
                    ..AcceptConfig::default()
                };
                Ok::<_, std::io::Error>(async move {
                    #[cfg(feature = "crash-points")]
                    granary_server::hold_host_test_worker();
                    let maintenance = intent_maintenance(service.clone(), shutdown.clone()).await;
                    // Readiness proceeds even if intents are unavailable; publish is independent.
                    grant_host.ready(addr);
                    let support_shutdown = shutdown.clone();
                    let sampling = async move {
                        if let Some(writer) = support {
                            writer.run(support_shutdown).await;
                        }
                    };
                    let (transport, transport_shutdown) = tokio::sync::watch::channel(false);
                    let forward = async move {
                        while !*shutdown.borrow_and_update() {
                            if shutdown.changed().await.is_err() {
                                break;
                            }
                        }
                        draining.begin();
                        #[cfg(feature = "crash-points")]
                        granary_server::observe_host_test_forward(
                            &draining,
                            accept.shutdown_deadline,
                        );
                        let _sent = transport.send(true);
                    };
                    let serving = serve(listener, tls, service, transport_shutdown, accept);
                    tokio::pin!(serving, forward, sampling, maintenance);
                    let mut sampled = false;
                    let mut forwarded = false;
                    let mut maintained = false;
                    std::future::poll_fn(|cx| {
                        if !sampled && sampling.as_mut().poll(cx).is_ready() {
                            sampled = true;
                        }
                        if !forwarded && forward.as_mut().poll(cx).is_ready() {
                            forwarded = true;
                        }
                        if !maintained && maintenance.as_mut().poll(cx).is_ready() {
                            maintained = true;
                        }
                        serving.as_mut().poll(cx)
                    })
                    .await
                })
            },
            signalled,
            budget,
        ));
        if let Some(reason) = &exit.reason {
            tracing::error!(reason, "authority host stopped");
            let line = if exit.code == EXIT_STARTUP_FAILED {
                format!("startup failed: {reason}\n")
            } else {
                format!("authority host stopped (exit {}): {reason}\n", exit.code)
            };
            // Consistent with the host's immediate-exit contract: only a std
            // helper writes, with a wait capped at STARTUP_REPORT_BOUND (250 ms).
            // No join, runtime destruction or snapshot write delays process exit.
            report_bounded(line);
        }
        std::process::exit(exit.code);
    }

    // **The DEADLINE travels with the store it bounds.** A service built
    // with `new` takes `None`, which is right for a store that cannot
    // stop answering and wrong for one that can — so the two arrive
    // together, out of the one call that knows which store this is.
    let service = GrainService::with_deadline(
        Arc::new(GranaryStore::new(store_config.store)),
        BASE,
        workers,
        store_config.dispatch_deadline,
    )
    .with_capture(capture);

    // Taken from `service` BEFORE it moves into `serve_and_exit`
    // below — the same `Arc` every serving clone charges, so the totals
    // read at shutdown are the process's real ones.
    let wire_handle = service.wire_bytes();
    // Read here, once, before the listener binds: a malformed trio is a
    // startup refusal like any other misconfigured variable, not a
    // failure discovered only at shutdown after the process already
    // served.
    let wire_env = wire_snapshot_env();

    // **The trigger tells the WRITES before it tells the accept loop**,
    // and the order is the whole content of the wiring: `serve_and_exit`
    // raises the shutdown level the instant this future resolves, so
    // beginning the drain inside it — after the signal, before the
    // return — leaves no window in which the loop is draining and an
    // in-flight upload is still running a clock longer than the drain
    // deadline. A composition root that skipped this line would get a
    // server whose every SIGTERM during a publish takes the forced-exit
    // path instead of draining.
    let draining = service.draining();
    let trigger = async move {
        signalled.await;
        draining.begin();
    };

    let listener = match runtime.block_on(tokio::net::TcpListener::bind(&listen)) {
        Ok(listener) => listener,
        Err(error) => startup_failure(&format!("{LISTEN}={listen:?}: {error}")),
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(error) => startup_failure(&format!("the bound address of {listen:?}: {error}")),
    };

    // The readiness line. The BOUND address, not the requested one — with
    // a `0` port they differ, and the resolved port is the only thing
    // that proves a listener exists.
    grant_host.ready(addr);

    let wire_snapshot = wire_env.map(|(path, run_id, role)| WireSnapshotRequest {
        path: PathBuf::from(path),
        run_id,
        role,
        listen_addr: addr.to_string(),
        handle: wire_handle,
    });

    serve_and_exit(
        runtime,
        listener,
        tls,
        service,
        AcceptConfig::default(),
        trigger,
        wire_snapshot,
    );
}

/// Run enrollment and retention maintenance at startup and every minute.
async fn intent_maintenance<R>(
    service: GrainService<R>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> impl std::future::Future<Output = ()> {
    // The service reports enrollment failures and every volume's failure.
    let _result = service.maintain_intents().await;
    async move {
        let mut interval = tokio::time::interval(Duration::from_mins(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // startup pass already completed
        loop {
            interval.tick().await;
            if *shutdown.borrow() {
                break;
            }
            let _result = service.maintain_intents().await;
        }
    }
}

/// Run the command line and exit with its code. Local support diagnostics
/// use the bounded final reporter; the other verbs own their standard streams.
fn command_line(args: &[std::ffi::OsString]) -> ! {
    let (code, diagnostic) = command_line_code(
        args,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    if let Some(diagnostic) = diagnostic.filter(|text| !text.is_empty()) {
        report_bounded(diagnostic);
    }
    std::process::exit(code)
}

/// Dispatch local commands before serving configuration or runtime setup.
/// Support diagnostics are returned for bounded final reporting; other verbs
/// write directly to the supplied streams.
fn command_line_code(
    args: &[std::ffi::OsString],
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> (i32, Option<String>) {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("support-export") => {
            let mut diagnostic = Vec::new();
            let code =
                granary_server::run_support_export_command_line(args, &WallClock, &mut diagnostic);
            (
                code,
                Some(String::from_utf8_lossy(&diagnostic).into_owned()),
            )
        }
        Some("initialise" | "unfence") => (
            granary_server::run_lifecycle_command_line(
                args,
                &mut OsSecureRandom::new(),
                granary_server::host_boot_start,
                || host_boot_id().map_err(std::io::Error::other),
                out,
                err,
            ),
            None,
        ),
        Some("debug-grant") => (
            run_debug_grant_command_line(args, &WallClock, out, err),
            None,
        ),
        _ => (
            run_command_line(args, &mut OsSecureRandom::new(), out, err),
            None,
        ),
    }
}

/// Read a required variable, or refuse to start naming it.
fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(error) => startup_failure(&format!("{name}: {error}")),
    }
}

/// The certificate CHAIN, every certificate in the file.
///
/// `pem_file_iter(…).collect()` and deliberately not `from_pem_file`: on
/// a multi-certificate file the latter succeeds and yields exactly ONE
/// certificate, so an intermediate would be dropped with no error
/// anywhere and the failure would surface as clients that cannot build a
/// path.
fn certificate_chain(path: &str) -> Vec<CertificateDer<'static>> {
    certificate_chain_for(std::path::Path::new(path), TLS_CERT)
}

#[expect(
    clippy::unnecessary_debug_formatting,
    reason = "escape arbitrary path bytes in startup diagnostics"
)]
fn certificate_chain_for(path: &std::path::Path, variable: &str) -> Vec<CertificateDer<'static>> {
    let entries = match CertificateDer::pem_file_iter(path) {
        Ok(entries) => entries,
        Err(error) => startup_failure(&format!("{variable}={path:?}: {error}")),
    };
    match entries.collect() {
        Ok(chain) => chain,
        Err(error) => startup_failure(&format!("{variable}={path:?}: {error}")),
    }
}

/// The private key: the FIRST key section in the file.
///
/// Which key encodings are accepted is `PrivateKeyDer::from_pem_file`'s
/// business, not a granary contract — whatever it reads is what works
/// here, and rustls decides usability when the configuration is built.
fn private_key(path: &str) -> PrivateKeyDer<'static> {
    match PrivateKeyDer::from_pem_file(path) {
        Ok(key) => key,
        Err(error) => startup_failure(&format!("{TLS_KEY}={path:?}: {error}")),
    }
}

/// How long [`report_bounded`] waits for a failure reason to reach stderr
/// before the caller exits without it.
///
/// **Enormous against the write, invisible against a person.** The write
/// is a single unbuffered `write(2)` of well under a kilobyte — tens of
/// microseconds even on a loaded machine, four orders of magnitude inside
/// this figure, so nothing short of an actual BLOCK can reach the bound.
/// Against an operator it is below what anyone reads as a pause, and a
/// supervisor that respawns on exit `2` spends a quarter second inside
/// the noise of its own backoff.
///
/// **If the helper thread is not scheduled inside it** — a machine loaded
/// enough that a freshly spawned thread does not run for a quarter second
/// — the line is lost and the caller still exits with its chosen code.
const STARTUP_REPORT_BOUND: Duration = Duration::from_millis(250);

/// Refuse to start, saying why.
///
/// **The reason is written DIRECTLY to stderr, and deliberately NOT
/// through `tracing`.** The subscriber's writer is the lossy sink, which
/// hands each line to a bounded channel drained by a background thread —
/// and the `std::process::exit` below kills that thread with the
/// process, so a line still queued at exit is never written at all.
/// Measured on this binary refusing an unknown `GRANARY_STORE`: 200
/// spawns run sixteen at a time lost the reason on 144 of them, and the
/// same shape on the earlier `required` refusal lost 95. Serially on an
/// idle machine the loss is about one spawn in two hundred — which is
/// the worse number, because it is small enough to be dismissed as a
/// flake by whoever meets it.
///
/// **That measurement has a runnable counterpart**, and it needs one:
/// the single-spawn process row passed 20/20 with this function
/// reverted to `tracing::error!`, so the suite could not see the
/// regression at all. `every_startup_refusal_carries_its_reason_under_
/// parallel_spawns` in `tests/shipped_store_config.rs` races
/// thirty-two refusals and asserts the reason on every one; with the
/// revert applied it lost 11, 23 and 23 of 32 on three consecutive
/// runs.
///
/// **SHUTDOWN observability remains the exit CODE.**
/// It must not depend on a blocking log, and
/// `serve`'s deadline-expiry path keeps exactly the behaviour it has.
/// The asymmetry is the whole justification: shutdown has DISTINCT exit
/// codes carrying the outcome, whereas every startup failure exits the
/// same [`EXIT_STARTUP_FAILED`], so on this path the reason string is
/// the only discriminator there is. An operator holding exit `2` and an
/// empty stderr cannot tell which variable is wrong.
///
/// Losing the JSON structure on this one line is the accepted cost: the
/// process never served, so there is no request to correlate it with,
/// and an operator reading why a server would not boot is reading
/// stderr.
///
/// **The sink's rationale is not evaded here, it is BOUNDED.** The sink
/// exists for one stated reason (`sink`'s module docs): a synchronous
/// write to a backpressured stderr blocks the thread doing it, and on a
/// runtime worker enough of those strand the time driver, so the drain
/// deadline never fires and the process is unkillable short of SIGKILL.
/// None of that machinery is running yet — every call site here is on the
/// MAIN thread, before `serve_and_exit`, before a connection has ever
/// been accepted, so there is no worker to strand, no deadline to arm and
/// no peer able to provoke this line. But a blocked write is a blocked
/// PROCESS whichever thread it sits on, and that half does reach this
/// path: written synchronously and unbounded, a server that cannot start
/// HANGS on a wedged stderr instead of exiting, a supervisor watching for
/// the exit code sees a live process and never backs off, and an operator
/// sees a server that appears to be running and is not. Measured, stderr
/// a pipe holding 64 KiB someone else wrote with its reader open and
/// idle: queued through the sink, `exit=2` in 0.00 s with the line lost;
/// written synchronously, still running at 10 s and killed. Neither is
/// the answer, so the write goes on a helper thread and the WAIT for it
/// carries [`STARTUP_REPORT_BOUND`].
///
/// **The three properties that shape has to have.**
/// 1. *The normal case is unchanged.* `Stderr` is unbuffered, the line is
///    one syscall, it lands, the helper signals, and the wait returns
///    immediately — nothing is delayed and no clock is read. The 200-spawn
///    parallel counts stay at 200/200.
/// 2. *The wedged case is bounded.* A full pipe with a stalled reader
///    costs the bound and then exits [`EXIT_STARTUP_FAILED`] anyway — the
///    pre-regression behaviour with the line lost, which is the correct
///    trade: an exit code can be read off a process that exited and
///    nothing at all can be read off one that hangs. `std::process::exit`
///    takes the writer thread with it.
/// 3. *The exit code is the outcome record on every branch.* A refused
///    thread, a failed write, a failed send and a timed-out wait are all
///    best-effort; nothing here panics, because a panic would replace a
///    named refusal with `101` and a backtrace.
///
/// **Neither lint is dodged.** `std::thread::sleep` IS denied
/// workspace-wide ("wall time in disguise; use the Clock seam"), so
/// a watchdog that slept would need an `#[expect]` in the composition
/// root; `Receiver::recv_timeout` carries no such ban, and it is
/// legitimate here for the same reason `clippy.toml` deliberately leaves
/// `tokio::time::timeout` unbanned — a bound on how long a WAIT may take
/// reads no clock the caller can observe, and `main` is never driven by
/// the simulator. The std thread API is not banned either: the concurrency
/// bans are on `tokio::spawn` and its method forms, because the sim
/// cannot sequence runtime-ordered tasks, and a plain std thread is
/// outside the runtime by construction — which is why `sink.rs` already
/// runs its writer on one. Checked against `clippy.toml` rather than
/// remembered: `disallowed-methods` carries `std::thread::sleep` and the
/// six tokio spawn entries, and nothing from `std::thread`'s spawn side.
fn startup_failure(reason: &str) -> ! {
    report_bounded(format!("startup failed: {reason}\n"));
    std::process::exit(EXIT_STARTUP_FAILED)
}

/// Write a final diagnostic on a std thread, waiting at most
/// [`STARTUP_REPORT_BOUND`]. The caller exits immediately afterward, taking
/// any blocked writer with it; this function never joins the thread.
fn report_bounded(line: String) {
    // ONE `write_all` of a PRE-FORMATTED line, not a `writeln!` with
    // arguments: the latter issues a write per fragment, and a fragmented
    // line is one anything else sharing this stderr can interleave with —
    // the lossy sink's writer thread holds the very same handle.
    let (done, waited) = std::sync::mpsc::channel();
    // The write happens HERE, on a thread the process is free to walk
    // away from. Best-effort throughout: there is nowhere better to
    // report a failed write to than the exit code the caller ends on.
    //
    // `Builder::spawn` and NOT `thread::spawn`, which is the same rule as
    // everything else on this path rather than a preference: the free
    // function PANICS when the OS refuses a thread, and a panic here
    // would replace the named refusal with `101` and a backtrace. On
    // `Err` the closure is dropped with the sender in it, so the wait
    // below returns `Disconnected` at once and the process exits
    // with its chosen code having lost only the line — and if a future
    // std held the closure instead of dropping it, the wait is bounded
    // anyway and the exit is the same.
    let _writer = std::thread::Builder::new().spawn(move || {
        let mut stderr = std::io::stderr().lock();
        let _written = stderr.write_all(line.as_bytes());
        // A no-op today — `Stderr` is unbuffered — and kept because that
        // is a property of the handle, not a promise this function
        // extracted. It sits inside the bound along with the write.
        let _flushed = stderr.flush();
        let _signalled = done.send(());
    });
    // Returns the moment the line has landed, and costs the full bound
    // only when stderr is wedged. Both outcomes fall through to the same
    // exit; the `Err` arm is simply the one where the reason was lost.
    let _bounded = waited.recv_timeout(STARTUP_REPORT_BOUND);
}

/// The production Clock seam; consumers never read wall time themselves.
struct WallClock;

impl Clock for WallClock {
    #[expect(
        clippy::disallowed_methods,
        reason = "the Clock seam's production wall-time read"
    )]
    fn now(&self) -> Timestamp {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Timestamp {
                secs: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                nanos: d.subsec_nanos(),
            },
            Err(e) => {
                let d = e.duration();
                let whole = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                if d.subsec_nanos() == 0 {
                    Timestamp {
                        secs: -whole,
                        nanos: 0,
                    }
                } else {
                    Timestamp {
                        secs: (-whole).saturating_sub(1),
                        nanos: 1_000_000_000 - d.subsec_nanos(),
                    }
                }
            }
        }
    }
}

struct TimerPause;
impl Pause for TimerPause {
    #[expect(
        clippy::disallowed_methods,
        reason = "the Pause seam's production timer implementation"
    )]
    async fn pause(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[cfg(test)]
mod support_dispatch_tests;

#[cfg(test)]
mod lifecycle_dispatch_tests;

#[cfg(test)]
mod intent_maintenance_tests;
