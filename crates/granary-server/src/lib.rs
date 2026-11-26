// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The granary server's policy layer, as a library.
//!
//! This crate answers the grain protocol resources represented by [`Resource`].
//! What lives here is the part of that answer nobody else may make:
//! which invariant is checked in which order, what is a `400` rather than
//! a `413`, and what the wire says on a refusal. The HTTP plumbing that
//! carries it — sockets, framing, the `Service` impl — is a separate
//! layer and takes none of those decisions.
//!
//! **Why the crate has a lib target at all.** Without one, nothing can
//! call a handler: not this crate's own tests, not the shared conformance
//! bodies, not the simulator. A `#[path = "../src/…"]` include makes the
//! source a module of the *including* target, which does not compose
//! across crates, so the surface has to be a real library. The binary
//! does not consume it — a `[lib]` and a `[[bin]]` sit side by side and
//! the bin need not use the lib.
//!
//! **This moves no logic out of the AGPL crate.** The licence rule is
//! that server logic never migrates INTO an Apache-licensed crate; a
//! library target inside this crate migrates nothing.
//!
//! **The surface below is CURATED, not `pub mod wire;`.** The modules
//! stay `pub(crate)`; only the items named in the `pub use` block escape,
//! so what a caller outside this crate may depend on is decided here in
//! one place rather than by whichever item happened to need `pub` for a
//! sibling module.
//!
//! **[`config`] is the ONE `pub mod`, and the exception is deliberate.**
//! It is a SCHEMA — variable names, the two store discriminants, the
//! seam-dispatch deadline, the authority's variables and the constructors
//! that read them — so every item in
//! it is something a composition root has to be able to name, and a
//! curated re-export list would be a second copy of the same set to keep
//! in step. It takes no request-time decision: nothing in it is reachable
//! from a served request, and the policy the rest of this crate holds
//! stays behind the `pub use` block below.
//!
//! **There are exactly TWO ways in, and they compose in one order:
//! [`admit`] then [`dispatch`].** §5a.6 fixes the order of the five
//! admission checks and calls it normative — "an accept set that depends
//! on which check ran first is not an accept set" — and the nine
//! handlers are `pub(crate)` so that the order cannot be skipped by a
//! caller that has an [`Admitted`] and reaches past it. An [`Admitted`]
//! is evidence the gate ran; only routing it through [`dispatch`] makes
//! that evidence load-bearing.
//!
//! **[`GrainService`] is the third exported item and it composes those
//! two rather than widening them.** It is the hyper `Service` a
//! composition root hands to the accept loop: it extracts the request
//! head as plain strings, runs the same ordered gate, routes through the
//! policy, resolves a configured write principal, applies its controls,
//! bounds the request content, and transcribes the [`Outcome`]. No hyper
//! type reaches [`admit`] or the handlers through it.
//!
//! **[`Draining`] is the fourth, and it is a caller OBLIGATION rather
//! than a convenience.** The accept clock covers up to a maximal bin of
//! legitimate content and is necessarily longer than the transport's
//! drain deadline, whose expiry is a process exit — so a composition
//! root arms this from the same trigger that shuts the accept loop down,
//! and one that does not gets a server whose every signal landing during
//! a publish takes the forced-exit path.
//!
//! **[`serve_and_exit`] and [`shutdown_trigger`] are the fifth and sixth,
//! and they are here rather than in `main.rs` for one reason: the deadline-exit
//! process test has to drive the REAL exit path.** A `main`-private race
//! is testable only by running the shipped binary, which cannot supply a
//! trigger of its own or a service that refuses to drain — so the two
//! shutdown checks (the deadline kills the process; the signals reach the
//! channel) could not be separated, and neither could be driven. The exit
//! CODES are on this surface for the same reason they are named at all:
//! deploy tooling reads the code, not the logs.
//!
//! **The publication authority's decision engine is a separate surface**,
//! reached through [`start`] alone: it takes the run marker's gate and
//! every volume's recovery, and answers an [`AuthorityHandle`] and an
//! [`AuthorityDriver`] or a [`StartRefused`]. The handle's requests
//! (initialise, submit, report, stop) reach the log and the root store
//! only through the driver's one `run()` future, so nothing a caller holds
//! can make a log call or a PUT of its own. It serves no request on the
//! wire.
//!
//! **The authority's host is the engine's composition into a server**:
//! [`run_authority_host`] runs the lifecycle (the engine on a thread of
//! its own, readiness, one shutdown budget, the exit code) over
//! collaborators its caller supplies, the engine's start reaching it
//! through an [`AuthoritySeat`]. It requires the host's boot id
//! ([`host_boot_id`]). The shipped binary composes it in authority mode,
//! binding and announcing readiness only in its post-recovery serve callback.
//!
//! **Client enrollment is another separate surface**: the server's reader
//! of the enrollment set ([`EnrollmentReader`], whose lookup answers
//! enrolled, absent or unavailable), the local verbs that write the set
//! ([`mint`], [`attach`], [`revoke`], [`retire`], [`list`]) and their
//! command line ([`run_command_line`], which the binary runs when it is
//! given arguments). The protected-directory rule they share is exported
//! only as its errors and its one filesystem-type table
//! ([`filesystem_type_verdict`]), which other state directories reuse.
//!
//! **The principal a write bears is the last of these surfaces**:
//! [`resolve_write_principal`] takes a request's extensions, where the
//! accept loop puts its connection's verified identity, and the reader,
//! and answers a [`WritePrincipal`] or the [`PrincipalRefusal`] to send. It
//! looks the identity up on every call and caches nothing. Reads never
//! call it.

// `disallowed_types` is `allow` on the workspace line — legitimate
// `HashMap` use exists elsewhere — and each crate opts in individually.
// This crate opts in for the reason granary-core does: a response whose
// order or content depended on hash iteration would vary per process,
// and the simulator replays this layer.
#![deny(clippy::disallowed_types)]

// The `crash-points` feature's release wall. The sites it compiles in stop
// a process dead for a test harness to kill; nothing an operator runs may
// carry them. This wall closes the zero- and one-deliberate-opt-in
// accidents (the feature in a default list; `--release --features
// crash-points`). It is not total: CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true
// turns debug_assertions back on in a release profile, and even then a site
// does nothing until a test installs a plan.
#[cfg(all(feature = "crash-points", not(debug_assertions)))]
compile_error!(
    "crash-points must never compile into a release binary: its sites stop the authority dead \
     for the SIGKILL crash harness to kill, a test tool and never an operator-facing surface. \
     This wall is not total: CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true turns debug_assertions \
     back on in a release profile."
);

pub(crate) mod adapter;
pub(crate) mod admission;
pub(crate) mod authority;
pub mod config;
pub(crate) mod controls;
pub(crate) mod debug_grant;
pub(crate) mod diagnostics;
pub(crate) mod enrollment;
pub(crate) mod handlers;
pub(crate) mod host;
pub(crate) mod lifecycle;
pub(crate) mod policy;
pub(crate) mod principal;
pub(crate) mod protected_dir;
pub(crate) mod protected_replace;
pub(crate) mod serve;
pub(crate) mod sink;
pub(crate) mod support;
pub(crate) mod wire;
pub(crate) mod wire_snapshot;

// A module of the lib rather than a `tests/` target, and the reason is
// the curated surface above: an integration test is a separate crate and
// reaches only what is `pub`, so anything it came to need would have to
// be published to a composition root that could then reach it too.
#[cfg(test)]
pub(crate) mod fake;
// `pub(crate)` for two consumers: `conformance_http` and `stream_floor`
// both reuse this file's certificate factory and its ONE real-socket spawn
// exemption rather than opening a second and a third exemption site, or a
// `tests/` support crate.
#[cfg(test)]
pub(crate) mod loopback;
#[cfg(test)]
mod seam_drivable;

// The client and the server meeting over the wire. It sits beside the
// loopback battery for the licence boundary: the edge has to
// run granary-server -> granary-client (AGPL consuming Apache), so the run
// lives HERE and imports `HttpStore`, never the other way round.
#[cfg(test)]
mod conformance_http;

// The two-sided control on `granary_net`'s advertised HTTP/2 stream limit.
// Here for the same reason `conformance_http` is: it needs `granary-client`
// and `h2` in one target, and this is the only crate that dev-depends on
// both. Its other half — the derivation gate that pins hyper's optimistic
// default — lives beside the constant, in granary-net's accept-loop suite.
#[cfg(test)]
mod stream_floor;

pub use adapter::{Draining, GrainService, WireByteHandle, worker_threads};
pub use admission::{Admitted, Conditionals, Operation, Refusal, RequestHead, admit};
pub use authority::content::{
    PublicationValidator, ValidationAttempt, ValidationCandidate, ValidationError,
    ValidationLimits, ValidationObject, ValidationRead, ValidationReadError, VerifiedContent,
};
pub use authority::{
    Admission, AdmittedRefusal, Answer, ApplyError, AuthorityDriver, AuthorityHandle,
    AuthorityParts, Bound, Fence, FenceCause, FileLog, FileLogConfigError, HeadRef,
    InitialiseError, Initialised, IntentOperation, IntentRoot, IntentStore, InvalidCandidate,
    LogCall, Notices, Observation, OpenEntryRow, OpenPosition, Pause, Position, Receipt,
    RecordRefusal, ReportError, RunEnd, ShutdownCause, ShutdownObserved, StartRefused,
    StopObserved, StuckFlag, StuckState, Submission, TerminalState, VerifiedHead, VolumeConfig,
    VolumeRefusal, VolumeView, shutdown_exit_code, start, start_observed,
};
pub use debug_grant::reader::ReaderCounters as DebugGrantReaderCounters;
pub use debug_grant::{DebugGrantHost, DebugGrantSnapshot, run_debug_grant_command_line};
pub use diagnostics::{
    CaptureCapabilities, CaptureCounters, CaptureEntry, CaptureError, CaptureHandle, CaptureKind,
    CaptureRevision, CaptureSelector, CaptureSlot, CaptureSnapshot, CaptureUnsupported,
    host_subscriber,
};
pub use enrollment::{
    CredentialError, EXIT_IO_FAILED, EXIT_REFUSED, EXIT_USAGE, EXIT_VERB_DONE, EnrollmentReader,
    EnrollmentSnapshot, LOOKUP_DEADLINE, ListReport, Lookup, ReaderStartError, SnapshotCounters,
    SnapshotState, UnavailableReason, VerbError, VerbOptions, VerbRefusal, attach, list, mint,
    resolve_credential, retire, revoke, run_command_line,
};
pub use handlers::dispatch;
pub use host::boot_id::{BootIdError, Malformed, host_boot_id, parse_boot_id};
pub use host::{AuthoritySeat, HostExit, run_authority_host};
pub use policy::VerifyPolicy;
pub use principal::{PrincipalRefusal, WritePrincipal, resolve_write_principal};
pub use protected_dir::{
    FileRuleBroken, FsRole, ProtectionError, RuleBroken, filesystem_type_verdict,
};
pub use serve::{
    EXIT_DEADLINE_EXPIRED, EXIT_DRAINED, EXIT_FENCED, EXIT_SERVE_FAILED, EXIT_STARTUP_FAILED,
    WireSnapshotRequest, serve_and_exit,
};
pub use sink::{LossyStderr, lossy_stderr};
pub use support::{
    CONFIGURATION_MAX as SUPPORT_CONFIGURATION_MAX, SNAPSHOT_MAX as SUPPORT_SNAPSHOT_MAX,
    SUPPORT_INTERVAL, SupportConfiguration, SupportError, SupportExportError, SupportExportRequest,
    SupportGrant, SupportGrantRecord, SupportSnapshot, SupportWriter, bound_configuration,
    publish_support_export, read_support_export, retain_configuration,
    run_support_export_command_line, snapshot_from_observation,
};
pub use wire_snapshot::wire_snapshot_trio_is_valid;
// Gated exactly as its definition is: the server BINARY is unix-scoped
// (the design doc's Windows story is the Phase-4 client, never this
// process), but the LIB compiles everywhere the workspace does, and an
// ungated re-export of a `#[cfg(unix)]` item would be a compile error on
// any other target with the scoping decision visible nowhere near it.
#[cfg(unix)]
pub use serve::shutdown_trigger;
pub use wire::{
    Allow, CacheControl, ContentType, ETag, ErrorToken, Extent, Outcome, PublishConflict,
    PublishRefusal, Resource, Status, StatusRefusal,
};

pub mod refusals;

pub use controls::{ControlRefusal, ControlsConfig, PrincipalControls, WritePermit};

#[cfg(feature = "crash-points")]
pub use authority::crash::{
    hold_host_test_worker, install_host_test_plan, observe_host_test_forward,
};

pub use host::boot_start::{host_boot_start, parse_boot_start};
pub use lifecycle::{
    LifecycleError, StateTimes, initialise_log, run_lifecycle_command_line, unfence_log,
};
