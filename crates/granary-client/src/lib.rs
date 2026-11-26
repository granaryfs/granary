// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client library behind the `gran` binary: the local store, the
//! harvest walk, and the publish flow.
//!
//! **The surface below is CURATED, not `pub mod publish;`.**
//! The modules stay `pub(crate)`; only the items named in
//! the `pub use` blocks escape, so what a caller outside this crate may
//! depend on is decided here in one place rather than by whichever item
//! happened to need `pub` for a sibling module.
//!
//! **Why the lib exists at all.** Reaching the publish flow through
//! `#[path = "../src/publish.rs"]` makes the source a module of the TEST
//! crate. That does not compose across crates, so granary-sim could not
//! call publish that way at all. A lib target and such includes are also
//! mutually exclusive under CI: `unreachable_pub` is a workspace `warn`
//! and CI builds with `CARGO_BUILD_WARNINGS=deny`, so the moment an item
//! is promoted to `pub` for the lib, a `#[path]`-included copy inside a
//! test target fails the build. Every target consumes this lib.
//!
//! **The generic seam is [`prepare_from_manifest`], not [`prepare`].**
//! `prepare`'s first step is a harvest, which writes the local store
//! through a concrete `&Store`, so it cannot be generic over
//! [`granary_core::grainsource::GrainSource`] (a read-only trait with no
//! `put`). Harvest is hoisted out instead: `prepare_from_manifest` takes
//! the manifest root a harvest already produced and reads through the
//! pure seams, which is what lets a simulated publish need no filesystem
//! at all. `prepare` remains as the CLI's convenience wrapper over the
//! two.

// `disallowed_types` is `allow` on the workspace line — legitimate
// `HashMap` use exists elsewhere — and only granary-core opts in today.
// This crate opts in for the same reason core does: everything here is
// on the path the simulator replays, and hash-map iteration order is
// ambient per-process state.
#![deny(clippy::disallowed_types)]
// docs/coding-standards.md MUST-1 — every lint suppression in this crate
// is `#[expect(lint, reason = "...")]`, never a bare `#[allow]` — is
// enforced by the COMPILER, from `Cargo.toml`'s `[lints.clippy]`
// (`allow_attributes`, `allow_attributes_without_reason`). It is set
// there rather than here because a crate-root attribute covers only its
// own target: this file governs the lib and nothing else, so the eight
// `tests/*.rs` integration crates had no such refusal at all.
//
// What the compiler closes, exactly: every OUTER `#[allow]` and every
// reasonless `#[expect]`, across all targets, resolved after macro
// expansion — so an attribute assembled inside a `macro_rules!` or an
// attribute proc-macro, or arriving through an `include!`, is caught
// too.
//
// What it does NOT see is an INNER `#![allow(...)]` — measured, both as
// a module file's first line and inside an inline `mod { ... }`: it
// produces no diagnostic at all. For that shape
// `scripts/check-fsguard-sites.sh`'s scanner is not a second opinion,
// it is the only check there is.

// This wall rejects rendezvous with debug assertions disabled. It is not total:
// CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true bypasses it; the exclusion gate inspects the executable.
#[cfg(all(feature = "publish-restart-tests", not(debug_assertions)))]
compile_error!("publish-restart-tests must never compile into a release granary-client artifact");
#[cfg(feature = "publish-restart-tests")]
pub mod publish_restart;

#[cfg(any(test, feature = "overlay-fault-tests"))]
pub mod overlay_test_support;

pub(crate) mod intent_transport;
pub use intent_transport::{IntentReply, IntentTransportError};
mod signing_input;
pub use signing_input::{
    LoadedSigningKey, SigningSeedPaths, load_existing_signing_key,
    load_existing_signing_key_with_spare, signing_seed_paths, validate_signing_seed_ancestor,
};
mod writable_start;
#[doc(hidden)]
pub use writable_start::managed_path;
#[cfg(any(test, feature = "overlay-fault-tests"))]
pub use writable_start::start_faults_for_test;
pub use writable_start::{
    MountSyncContent, SyncProfile, ViewBinding, ViewMode, WritableAttachment, WritableAuthority,
    WritableMount, WritableProcess, WritableReadiness, WritableStart, WritableStartError,
    WritableSyncRuntime, recovery_prologue, start_writable, sync_mount_error,
};
pub(crate) mod writable_store;
pub use writable_store::{
    AcknowledgedRecovery, CaptureCompletion, CaptureCompletionWork, CaptureCoverageInput,
    CoordinationError, DEFAULT_MAX_COALESCE_DELAY, DEFAULT_QUIESCE_DELAY, DEFAULT_RESOLUTION_BOUND,
    ImmutableContent, IntentCompletion, MountViewContext, PendingIntent, RecoveryRule,
    ReopenedCapture, STARTUP_ATTEMPTS, SelectedRecovery, SharedWritableStore, StageMutation,
    StageProjection, SyncPayloadVerifier, SyncRefusalKind, ValidatedCaptureCompletions,
    VerifiedSyncPayload, WritableOverlay, WritableStore,
};
pub(crate) mod authority_transport;
pub(crate) mod publication_store;
pub(crate) mod recovery;
pub use publication_store::{
    AbandonAcknowledgement, Abandonment, ArchiveEvidence, DirectPublicationSelection,
    MayLandAcknowledgement, PinDifference, PublicationStore, PublicationStoreError,
    PublicationStoreErrorKind,
};

pub(crate) mod cache;
pub(crate) mod contention;
pub(crate) mod credential;
pub(crate) mod custody;
pub(crate) mod direct_deadline;
pub(crate) mod fetcher;
pub mod publication_config;
// NO module-wide fs-ban exemption here. `fsguard` is the module the ban
// points callers toward, so its own opens do call the banned entry
// points — but licensing the whole module from OUTSIDE it meant a NEW
// bare `OpenOptions::new().open(path)` added anywhere inside `fsguard.rs`
// compiled silently, with no site to review and no movement in the
// licensed-site count. The five guarded primitives carry their own
// per-site `#[expect]`s instead; see `fsguard.rs`.
pub(crate) mod fsguard;
// `pub`, not `pub(crate)` — the ONE deliberate exception to the curated
// surface above, mirroring `granary_store::fuzz_probe`: the fuzz
// workspace (`fuzz/`) is a SEPARATE crate and needs
// `granary_client::fuzz_probe::anchor_decode_probe` reachable from
// outside. No stability promise attaches to it.
pub mod fuzz_probe;
pub(crate) mod harvest;
pub(crate) mod head;
pub(crate) mod http_store;
pub(crate) mod metrics;
pub(crate) mod mount;
pub(crate) mod netid;
pub(crate) mod observe;
pub(crate) mod overlay_discard;
pub use overlay_discard::{
    ArchiveReconciliation, DiscardError, OverlayRefusal, ReconcileRow, discard_overlay,
};
mod overlay_store;
pub use overlay_store::{
    BoundaryCapture, BoundarySelection, CaptureToken, CapturedFile, CapturedPart, CapturedRange,
    ContentSource, DurableFile, FaultAction, FaultControl, FaultEvent, LandedProof,
    NamespaceEffect, OVERLAY_PAGE_ROWS, OverlayConfig, OverlayCursor, OverlayDirectoryQuery,
    OverlayDisk, OverlayEntry, OverlayError, OverlayIo, OverlayKind, OverlayObservation,
    OverlayPage, OverlayQuery, OverlayQueryEntry, OverlayReadiness, OverlayStore, OverlaySummary,
    OwnershipPermission, OwnershipStatus, PathChange, PreparedProjection, RecoveryCommit,
    RegisteredCapture, ReplacementPlan, SelectedWriter, SweepEntry, SyncBoundary, SyncFaultEvent,
    SyncTarget, UnmergedEntry, UnmergedInventory, ViewChange,
};
pub(crate) mod publish;
pub(crate) mod sync;
pub use sync::rebase::{HeadRelation, RebaseConflict, RebaseError, classify_head, merge_manifests};
pub use sync::{
    AcceptedSyncProjection, InstantClock, LiveEnd, MonotonicClock, MonotonicDomain, MonotonicToken,
    OperationContext, RechunkStats, RechunkedFile, Residue, RetainedCommit, ShutdownCause,
    ShutdownCut, ShutdownHandle, ShutdownOutcome, ShutdownReport, ShutdownTrigger, SyncContent,
    SyncEngine, SyncObjectSelection, SyncOptions, SyncProjectionQueue, SyncRemote, SyncRuntime,
    SyncRuntimeError, SyncWaiter, TokioSyncRuntime, VerifiedBase, accept_sync_projection,
    rechunk_captured,
};
pub(crate) mod resolve;
pub(crate) mod retry;
pub(crate) mod route;
pub(crate) mod store;
pub(crate) mod verify;
pub(crate) mod wire_snapshot;

pub use authority_transport::{
    AuthorityConfiguration, AuthorityError, CheckedBound, CheckedConflict, CheckedDecision,
    CheckedLanded, CheckedLost, CheckedStatus, OWNED_CANDIDATES_MAX, OwnedCandidate, ProtocolError,
    ProtocolErrorKind, PublishRefusal, PublishRequest, PublishResponse, RequestError,
    ServiceReason, StatusRefusal, StatusResponse, StatusServiceReason, TransportError,
    validate_publish_answer, validate_status_observation,
};
#[doc(hidden)]
pub use cache::CACHE_MARKER_VERSION;
pub use cache::{
    Cache, CacheError, CacheOrigin, FreeSpace, FreeSpaceInfo, HeadAnchor, HintUpdate, PersistedHint,
};
pub use contention::ContentionThreshold;
pub use credential::{ClientCredential, CredentialError, CredentialFile};
#[cfg(target_vendor = "apple")]
#[doc(hidden)]
pub use custody::acl as private_key_acl;
#[doc(hidden)]
pub use custody::{open_private_key, refuse_granting_acl_at_path};
pub use fsguard::{
    ArchiveSources, MountedNamespace, PrivateArchiveError, PrivateArchiveErrorClass,
    PrivateArchiveParent, PrivateArchiveRefusal, prepare_private_archive_parent, prove_mountpoint,
    publish_private_archive,
};
#[doc(hidden)]
pub use fsguard::{open_directory, open_regular_read, open_sole_regular_read};
pub use harvest::{
    FileIdentity, HarvestError, HarvestStats, harvest, harvest_excluding_file,
    harvest_excluding_files,
};
pub use head::HeadContext;
pub use http_store::{
    CONNECT_TIMEOUT, HttpStore, HttpStoreError, SEAM_DEADLINE_BASE, SEAM_FLOOR_RATE_BYTES_PER_SEC,
    WireByteHandle,
};
pub use metrics::{
    ByteDirection, CachePhase, CacheResult, ClientMetrics, CommitResult, FuseCallback,
    METRICS_CATALOGUE, METRICS_CONTENT_TYPE, METRICS_MAX_BYTES, METRICS_MAX_LINE,
    METRICS_MAX_SERIES, METRICS_SCHEMA_VERSION, MetricSpec, MetricsError, MetricsGroup,
    MetricsSnapshot, RegistrationResult, ScrapeResult, UploadObject,
};
pub use netid::AmbientNetwork;
pub use observe::{
    Age, BackoffCause, BackoffOutcome, BundleHistory, BundleRecord, BundleSnapshot,
    BundleSnapshotError, COMMIT_BACKOFF, COMMIT_STOPPED, CORRELATION_ID_LEN, CORRELATION_ID_PREFIX,
    CacheAction, ClientEvent, CommitStopCause, CorrelationId, EVENTS, EventSpec, FailureClass,
    FaultPhase, FilterDetail, FilterRejection, FilterSource, FuseConnection, HttpSeam,
    IndexFileKind, LOG_CONFIG, LOG_FILTER_REJECTED, LogDestination, LogFormat, LogName, LogPath,
    LogPaths, LogRecord, METRICS_EXPORT_FAILED, MOUNT_UNMOUNT, MOUNT_VIEW, MetricsFailureClass,
    MountListing, OP_BEGIN, OP_CONFLICT, OP_END, OP_FAILED, OP_RETRY, OPERATION_SPAN,
    OperationKind, OperatorDiagnostic, OperatorNotice, Outcome, OverlayFaultPoint, OverlayOwed,
    PUBLISH_BOUND, ProxyVariableName, PublishOperationId, PublishOperationRefusal, RecordWriter,
    RecoveryClass, RetryReason, SignalKind, SubsumedRelation, SyncFaultPhase, SyncFaultPoint,
    SyncObjectKind, TeardownCause, UnmountCause, UnmountOutcome, UnmountTrigger, ViewCause,
    ViewOutcome, WalkOutcome, WireRetryClass, closed_operation_span, closed_subscriber,
    closed_subscriber_with_paths, log_config, log_filter_rejected, op_begin, op_end, op_failed,
    op_retry, operation_span, publish_bound, subscriber,
};
// The CLI's surface: `mount` stays `pub(crate)` (a curated set
// — only these named items escape it), but the daemon that constructs the
// `fuser::Session`, the shutdown coordinator and `gran mount`/`gran
// umount` themselves live in the BIN crate (`main.rs`), a separate
// compilation unit from this lib — so `MountSession::open`, the trust-mode
// gate it enforces (`MountError`, `FloorKind` inside one of its variants)
// and its `allow_other`/`allow_root` input (`MountOptions`) all have to
// cross the crate boundary here, the same way `Cache`/`CacheOrigin` do two
// blocks up. `TrustMode` and `Preamble` do NOT escape: nothing outside
// `open`'s own body ever needs to name either.
pub use mount::{FloorKind, MountError, MountMetrics, MountOptions, MountSession};
pub use publish::{
    BinmapWork, Policy, Prepared, PublishError, PublishSummary, commit, prepare,
    prepare_excluding_file, prepare_excluding_files, prepare_from_manifest, publish,
    publish_excluding_file, publish_excluding_files,
};
pub use resolve::{
    AnchorError, EmitSink, ResolveError, ResolveOutcome, ResolveTarget, RootVerifier, resolve_at,
    resolve_at_collecting, resolve_at_verified, resolve_head, resolve_head_collecting,
    resolve_head_verified,
};
// Re-exported beside `route`'s items: it is the payload of the public
// `PublishRoute::DirectS3` variant, and a `pub(crate)` payload of a
// public enum is rustc's `private_interfaces` lint — an error under the
// deny-warnings gates.
pub use direct_deadline::DirectStoreDeadline;
pub use route::{
    ENV_AWS_ACCESS_KEY_ID, ENV_AWS_REGION, ENV_AWS_SECRET_ACCESS_KEY, ENV_AWS_SESSION_TOKEN,
    PublishRoute, RouteError, open_publish_route, open_publish_route_with_client_credential,
};
pub use store::{MARKER_NAME, Store, StoreError, is_store_marker};
pub use verify::run_verify;
pub use wire_snapshot::{
    ClientTotals, PublishFields, SnapshotError, wire_snapshot_trio_is_valid, write_client_snapshot,
};

pub use recovery::{
    AuthorityTransport, NeverLandedProof, NoWriteProof, ProbeOutcome, PublicationHandle,
    PublicationJournal, PublicationOutcome, PublicationResult, RecoveredObjects, RecoveryBackoff,
    RecoveryCommand, RecoveryCommandError, RecoveryConflictInventory, RecoveryConflictStage,
    RecoveryDelay, RecoveryError, RecoveryIntent, RecoveryJournal, RecoveryOutcome, RecoveryParts,
    RejectionProof, SelectedPublication, begin_exact_publication, begin_publication,
    begin_selected_publication, bootstrap_publication, probe_submission, resume_exact_publication,
    resume_publication, settle_recovery_boundary,
};

mod local_report;
pub use local_report::{
    CloseStage, ConflictPathTooLarge, EquivocationNotice, LocalConflictStatus, LocalRecord,
    LocalRecordWriter, LocalReport, LocalReporter, LocalReportsInstalled, install_local_reports,
};

#[cfg(test)]
mod q3_client_child;

#[cfg(any(test, feature = "overlay-fault-tests"))]
pub use overlay_store::RenameDirectoryFaultContext;
