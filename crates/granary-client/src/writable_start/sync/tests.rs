// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
// @file-disposition: STAYS — the mount-write-path gate inventories this file as one common mount helper and refuses submodules under it; the sync error tables and boundary rows share its fixtures.

use super::*;
use granary_core::rootstore::filter_above;
use granary_fuse::{MountError as M, MountSyncError as S};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table covers typed sync failures, diagnostic-text controls and errno values"
)]
fn sync_mount_error_table_rows() {
    use std::io::ErrorKind as I;
    let rows = [
        (
            CoordinationError::SyncRefusal(crate::SyncRefusalKind::Authorization),
            S::Backend(M::Access),
        ),
        (
            CoordinationError::SyncRefusal(crate::SyncRefusalKind::Other),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::SyncRefusal(crate::SyncRefusalKind::MissingReference {
                publication: [0; 16],
                uncertain: true,
            }),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::SyncRefusal(crate::SyncRefusalKind::InvalidReference {
                uncertain: false,
            }),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::SyncRefusal(crate::SyncRefusalKind::PublishWorkLimit {
                uncertain: false,
            }),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::Codec(granary_core::overlay_ownership::Error("SyncCancelled")),
            S::Backend(M::Corrupt),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::Invalid("SyncCancelled")),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::RemoteIntegrity("permission denied")),
            S::Backend(M::Corrupt),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::Remote(RootStoreError::NotFound)),
            S::Backend(M::Unavailable),
        ),
        (
            CoordinationError::Publication(crate::PublicationStoreError {
                path: "fixture".into(),
                reason: "SyncCancelled".into(),
                kind: crate::PublicationStoreErrorKind::Refused,
            }),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::Journal(
                crate::PublicationStoreError {
                    path: "fixture".into(),
                    reason: "publication belongs to an open mount commit".into(),
                    kind: crate::PublicationStoreErrorKind::Refused,
                },
            )),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::Journal(
                crate::PublicationStoreError {
                    path: "fixture".into(),
                    reason: "overlay journal exceeds cap".into(),
                    kind: crate::PublicationStoreErrorKind::Refused,
                },
            )),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::Journal(
                crate::PublicationStoreError {
                    path: "fixture".into(),
                    reason: "overlay journal requires recovery".into(),
                    kind: crate::PublicationStoreErrorKind::Refused,
                },
            )),
            S::Backend(M::Io),
        ),
        (
            OverlayError::Refused("sync file identity").into(),
            S::InvalidRequest,
        ),
        (
            OverlayError::Refused("sync directory identity").into(),
            S::InvalidRequest,
        ),
        (
            OverlayError::Refused("capture stage").into(),
            S::InvalidRequest,
        ),
        (
            OverlayError::Refused("PermissionDenied").into(),
            S::Backend(M::Io),
        ),
        (refused("SyncCancelled"), S::Cancelled),
        (refused("ViewPending"), S::ViewPending),
        (refused("IntentOverQuota"), S::Backend(M::Quota)),
        (refused("IntentCapExhausted"), S::Backend(M::NoSpace)),
        (refused("SyncWorkspaceExhausted"), S::Backend(M::NoSpace)),
        (refused("SyncDeadline"), S::Backend(M::Unavailable)),
        (refused("SyncSupervisorLost"), S::Backend(M::Io)),
        (refused("not an authorization refusal"), S::Backend(M::Io)),
        (
            CoordinationError::Fenced {
                recorded_generation: None,
            },
            S::Backend(M::Stale),
        ),
        (
            CoordinationError::CommitFenced {
                publication: [7; 16],
            },
            S::Backend(M::Stale),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::Journal(
                crate::PublicationStoreError {
                    path: "fixture".into(),
                    reason: "overlay journal missing from existing area".into(),
                    kind: crate::PublicationStoreErrorKind::Refused,
                },
            )),
            S::Backend(M::Io),
        ),
        (
            CoordinationError::Recovery(crate::RecoveryError::Journal(
                crate::PublicationStoreError {
                    path: "fixture".into(),
                    reason: "commit publication 07070707070707070707070707070707 fenced (ESTALE)"
                        .into(),
                    kind: crate::PublicationStoreErrorKind::Refused,
                },
            )),
            S::Backend(M::Io),
        ),
        (OverlayError::NoSpace.into(), S::Backend(M::NoSpace)),
        (OverlayError::MutationsClosed.into(), S::Backend(M::Closing)),
        (OverlayError::ContentCorrupt.into(), S::Backend(M::Corrupt)),
        (
            OverlayError::ContentUnavailable.into(),
            S::Backend(M::Unavailable),
        ),
        (OverlayError::Poisoned.into(), S::Backend(M::Io)),
        (
            OverlayError::CaptureCoverageLost.into(),
            S::Backend(M::Corrupt),
        ),
        (
            OverlayError::Io(I::StorageFull.into()).into(),
            S::Backend(M::NoSpace),
        ),
        (
            OverlayError::Io(I::PermissionDenied.into()).into(),
            S::Backend(M::Access),
        ),
        (
            OverlayError::Io(I::QuotaExceeded.into()).into(),
            S::Backend(M::Quota),
        ),
        (
            OverlayError::Io(std::io::Error::other("SyncCancelled")).into(),
            S::Backend(M::Io),
        ),
    ];
    assert_eq!(rows.len(), 39);
    for (error, expected) in rows {
        assert_eq!(sync_mount_error(&error), expected, "input: {error:?}");
    }
    #[cfg(target_os = "macos")]
    let (stale, quota) = (70, 69);
    #[cfg(target_os = "linux")]
    let (stale, quota) = (116, 122);
    for (error, errno) in [
        (S::Backend(M::Stale), stale),
        (S::Backend(M::NoSpace), 28),
        (S::Backend(M::Access), 13),
        (S::Backend(M::Quota), quota),
        (S::Backend(M::Io), 5),
        (S::Backend(M::Corrupt), 5),
        (S::Backend(M::Unavailable), 5),
        (S::Backend(M::Closing), 30),
        (S::Cancelled, 4),
        (S::InvalidHandle, 9),
        (S::InvalidRequest, 22),
        (S::ViewPending, 5),
    ] {
        assert_eq!(error.errno().code(), errno, "input: {error:?}");
    }
}

/// Rejects mapping a retry checked before its eligibility to generic I/O.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "source-checked refusal table includes the complete engine and mediator closure"
)]
fn sync_mount_error_engine_refusal_identifiers() {
    let coverage = std::process::Command::new("bash")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/check-mount-write-path.sh"),
        )
        .output()
        .unwrap();
    assert_eq!(
        (coverage.status.code(), coverage.stdout),
        (Some(0), b"mount write path: ok\n".to_vec()),
        "refusal source coverage: {}",
        String::from_utf8_lossy(&coverage.stderr)
    );
    let rows = [
        ("IntentAcquire", S::Backend(M::Io)),
        ("IntentAdoptionBesideEvidence", S::Backend(M::Io)),
        ("IntentAttemptNotStarted", S::Backend(M::Io)),
        ("IntentAttemptsExhausted", S::Backend(M::Unavailable)),
        ("IntentBackendDisagreement", S::Backend(M::Io)),
        ("IntentBound", S::Backend(M::Io)),
        ("IntentCapExhausted", S::Backend(M::NoSpace)),
        ("IntentCapOverflow", S::Backend(M::NoSpace)),
        ("IntentCaptureCompletionStale", S::Backend(M::Io)),
        ("IntentCaptureProvenanceUnavailable", S::Backend(M::Io)),
        ("IntentCaptureRecoveryBinding", S::Backend(M::Io)),
        ("IntentCaptureRecoveryFailed", S::Backend(M::Io)),
        ("IntentCaptureRegistrationRefused", S::Backend(M::Io)),
        ("IntentCarrierBinding", S::Backend(M::Io)),
        ("IntentCarrierCap", S::Backend(M::Io)),
        ("IntentCarrierChanged", S::Backend(M::Corrupt)),
        ("IntentCeilingBelowEvidence", S::Backend(M::Io)),
        ("IntentClockInvalid", S::Backend(M::Io)),
        ("IntentCompletionBinding", S::Backend(M::Io)),
        ("IntentCompletionOwner", S::Backend(M::Io)),
        ("IntentControlChanged", S::Backend(M::Io)),
        ("IntentCoveringRootUnknown", S::Backend(M::Io)),
        ("IntentCursorChanged", S::Backend(M::Stale)),
        ("IntentDeadlineOverflow", S::Backend(M::Io)),
        ("IntentDrainPending", S::Backend(M::Io)),
        ("IntentEntropyUnavailable", S::Backend(M::Unavailable)),
        ("IntentEpochExhausted", S::Backend(M::Io)),
        ("IntentExpiredRegisterUnresolved", S::Backend(M::Io)),
        ("IntentFenceReceipt", S::Backend(M::Io)),
        ("IntentForeignControl", S::Backend(M::Io)),
        ("IntentFreshInstanceRequired", S::Backend(M::Io)),
        ("IntentGenerationExhausted", S::Backend(M::Io)),
        ("IntentGrant", S::Backend(M::Io)),
        ("IntentLandedReplayInvalid", S::Backend(M::Corrupt)),
        ("IntentNotImplemented", S::Backend(M::Io)),
        ("IntentOverQuota", S::Backend(M::Quota)),
        ("OverlayCapacityExhausted", S::Backend(M::NoSpace)),
        ("IntentOwnershipPending", S::Backend(M::Io)),
        ("IntentOwnershipRequest", S::Backend(M::Io)),
        ("IntentOwnershipUnresolved", S::Backend(M::Io)),
        ("IntentPendingReconciliation", S::Backend(M::Io)),
        ("IntentPendingSignature", S::Backend(M::Corrupt)),
        ("IntentPersistencePoisoned", S::Backend(M::Io)),
        ("IntentPipelineFull", S::Backend(M::Io)),
        ("IntentPreparedRoot", S::Backend(M::Corrupt)),
        ("IntentPreparedSignature", S::Backend(M::Corrupt)),
        ("IntentPreparedWriter", S::Backend(M::Io)),
        ("IntentReadbackRefused", S::Backend(M::Io)),
        ("IntentReadbackScope", S::Backend(M::Io)),
        ("IntentReceipt", S::Backend(M::Io)),
        ("IntentRegister", S::Backend(M::Io)),
        ("IntentRelease", S::Backend(M::Io)),
        ("IntentReleaseGenerationZero", S::Backend(M::Io)),
        ("IntentReplacementReserve", S::Backend(M::Io)),
        ("IntentReplayPending", S::Backend(M::Io)),
        ("IntentRequestNotRetained", S::Backend(M::Io)),
        ("IntentRequestRetired", S::Backend(M::Io)),
        ("IntentRetryDeadline", S::Backend(M::Unavailable)),
        ("IntentRetryNotEligible", S::Backend(M::Unavailable)),
        ("IntentRevisionExhausted", S::Backend(M::Io)),
        ("IntentScope", S::Backend(M::Io)),
        ("IntentSelectedWriterMissing", S::Backend(M::Io)),
        ("IntentSelection", S::Backend(M::Io)),
        ("IntentSelectionAlreadyStarted", S::Backend(M::Io)),
        ("IntentSelectionBinding", S::Backend(M::Io)),
        ("IntentSelectionChanged", S::Backend(M::Stale)),
        ("IntentSnapshotMissing", S::Backend(M::Io)),
        ("IntentStagingChanged", S::Backend(M::Io)),
        ("IntentStartupAttemptsExhausted", S::Backend(M::Unavailable)),
        ("IntentSyncPayloadBinding", S::Backend(M::Io)),
        ("IntentTakeover", S::Backend(M::Io)),
        ("IntentTerminalRefusal", S::Backend(M::Io)),
        ("IntentTokenDisplaced", S::Backend(M::Stale)),
        ("IntentUnknownVolume", S::Backend(M::Io)),
        ("IntentUnmergedChanged", S::Backend(M::Io)),
        ("IntentUnmergedUnclassified", S::Backend(M::Io)),
        ("IntentVerdictMismatch", S::Backend(M::Io)),
        ("RecoveryLandedEvidenceMissing", S::Backend(M::Io)),
        ("RecoveryLandedUnowned", S::Backend(M::Io)),
        ("RecoveryResidualCaptureMissing", S::Backend(M::Io)),
        ("RecoveryResidualCaptureChanged", S::Backend(M::Io)),
        ("RecoveryResidualCaptureUnknown", S::Backend(M::Io)),
        ("RecoveryResidualExecChanged", S::Backend(M::Io)),
        ("RecoveryResidualInventoryCheck", S::Backend(M::Io)),
        ("RecoveryResidualInventoryCount", S::Backend(M::Io)),
        ("RecoveryResidualPayloadHeader", S::Backend(M::Io)),
        ("RecoveryResidualPayloadLength", S::Backend(M::Io)),
        ("RecoveryResidualSourceChanged", S::Backend(M::Io)),
        ("RecoveryResidualUnavailable", S::Backend(M::Unavailable)),
        ("RecoveryResidualUnrepresentable", S::Backend(M::Io)),
        ("RecoveryResidualWorkspace", S::Backend(M::NoSpace)),
        ("Store binding", S::Backend(M::Io)),
        ("SyncBase", S::Backend(M::Corrupt)),
        ("SyncBaseBinding", S::ViewPending),
        ("SyncBaseOverflow", S::Backend(M::Io)),
        ("SyncBasePoisoned", S::Backend(M::Io)),
        ("SyncCallerBinding", S::Backend(M::Io)),
        ("SyncCallerNotRetained", S::Backend(M::Io)),
        ("SyncCancelled", S::Cancelled),
        ("SyncCommitAlreadyRetained", S::Backend(M::Io)),
        ("SyncCommitBinmap", S::Backend(M::Io)),
        ("SyncCommitBootstrap", S::Backend(M::Io)),
        ("SyncCommitCandidateBinding", S::Backend(M::Io)),
        ("SyncCommitCapture", S::Backend(M::Io)),
        ("SyncCommitCheckpoint", S::Backend(M::Io)),
        ("SyncCommitConstructionPending", S::Backend(M::Io)),
        ("SyncCommitContainment", S::Backend(M::Corrupt)),
        ("SyncCommitContext", S::Backend(M::Io)),
        ("SyncCommitDrainPending", S::Backend(M::Io)),
        ("SyncCommitExhausted", S::Backend(M::Io)),
        ("SyncCommitIdentity", S::Backend(M::Io)),
        ("SyncCommitInFlight", S::Backend(M::Io)),
        ("SyncCommitInitialRecord", S::Backend(M::Io)),
        ("SyncCommitLandingBinding", S::Backend(M::Io)),
        ("SyncCommitLandingIdentity", S::Backend(M::Io)),
        ("SyncCommitLaneRequired", S::Backend(M::Io)),
        ("SyncCommitManifest", S::Backend(M::Corrupt)),
        ("SyncCommitNamespace", S::Backend(M::Io)),
        ("SyncCommitNotRetained", S::Backend(M::Io)),
        ("SyncCommitRebaseManifest", S::Backend(M::Corrupt)),
        ("SyncCommitRebaseUnavailable", S::Backend(M::Unavailable)),
        ("SyncCommitReadback", S::Backend(M::Io)),
        ("SyncCommitRecord", S::Backend(M::Io)),
        ("SyncCommitRecoveryRequired", S::Backend(M::Io)),
        ("SyncCommitRefresh", S::Backend(M::Io)),
        ("SyncCommitScope", S::Backend(M::Io)),
        ("SyncCommitSignature", S::Backend(M::Corrupt)),
        ("SyncCommitUnresolved", S::Backend(M::Unavailable)),
        ("SyncCompletionBinding", S::Backend(M::Io)),
        ("SyncContentDeadlineRequired", S::Backend(M::Io)),
        ("SyncDeadline", S::Backend(M::Unavailable)),
        ("SyncDeadlineOverflow", S::Backend(M::Io)),
        ("SyncDirectoryTarget", S::Backend(M::Io)),
        ("SyncEngineAlreadyAttached", S::Backend(M::Io)),
        ("SyncFaultSupervisorLost", S::Backend(M::Io)),
        ("SyncFileIndex", S::Backend(M::Io)),
        ("SyncGraphOverflow", S::Backend(M::Io)),
        ("SyncGraphPoisoned", S::Backend(M::Io)),
        ("SyncInjectedFault", S::Backend(M::Io)),
        ("SyncLeaseExhausted", S::Backend(M::Io)),
        ("SyncLeaseMissing", S::Backend(M::Io)),
        ("SyncLocalTransactionLost", S::Backend(M::Io)),
        ("SyncMaterializationLost", S::Backend(M::Io)),
        ("SyncMediatorPoisoned", S::Backend(M::Io)),
        ("SyncOwnerBinding", S::Backend(M::Stale)),
        ("SyncPreparedBase", S::Backend(M::Io)),
        ("SyncPreparedRoot", S::Backend(M::Io)),
        ("SyncProjectedBinding", S::Backend(M::Corrupt)),
        ("SyncRange", S::Backend(M::Io)),
        ("SyncRechunkContent", S::Backend(M::Corrupt)),
        ("SyncRecoveryRequired", S::Backend(M::Io)),
        ("SyncSelectionUnrepresentable", S::Backend(M::Io)),
        ("SyncStatePoisoned", S::Backend(M::Io)),
        ("SyncSupervisorLost", S::Backend(M::Io)),
        ("SyncWaiterConsumed", S::Backend(M::Io)),
        ("SyncWorkspaceExhausted", S::Backend(M::NoSpace)),
        ("ViewAdapterLost", S::Backend(M::Io)),
        ("ViewHeadRefused", S::Backend(M::Io)),
        ("ViewHookBound", S::Backend(M::Io)),
        ("ViewHookUnbound", S::Backend(M::Io)),
        ("ViewPending", S::ViewPending),
        ("ViewRootEquivocation", S::Backend(M::Io)),
        ("ViewRootMismatch", S::Backend(M::Io)),
        ("ViewRootNotAccepted", S::Backend(M::Io)),
        ("ViewRootUnavailable", S::Backend(M::Unavailable)),
        ("ViewRootUnpublished", S::Backend(M::Io)),
        ("ViewTimeUnrepresentable", S::Backend(M::Io)),
        ("ViewUnattendedUnsupported", S::Backend(M::Io)),
        ("ViewUnservable", S::Backend(M::Io)),
        ("WritableIntentDiscoveryInvalid", S::Backend(M::Io)),
        ("WritableRecoveryRequired", S::Backend(M::Io)),
        ("adoption journal not clean", S::Backend(M::Io)),
        ("base read missing", S::Backend(M::Io)),
        ("base read type", S::Backend(M::Io)),
        ("base root/sequence mismatch", S::Backend(M::Io)),
        ("bind base content", S::Backend(M::Io)),
        ("bind name missing", S::Backend(M::Io)),
        ("bind type or stage conflict", S::Backend(M::Io)),
        ("boundary capture context", S::Backend(M::Io)),
        ("boundary cursor mapping", S::Backend(M::Io)),
        ("capture buffer range", S::Backend(M::Io)),
        ("capture context", S::Backend(M::Io)),
        ("capture dirty version", S::Backend(M::Io)),
        ("capture exhaustion", S::Backend(M::Io)),
        ("capture extent mismatch", S::Backend(M::Io)),
        ("capture extent overflow", S::Backend(M::Io)),
        ("capture extent range", S::Backend(M::Io)),
        ("capture file index", S::Backend(M::Io)),
        ("capture partition", S::Backend(M::Io)),
        ("capture range context", S::Backend(M::Io)),
        ("capture stage", S::Backend(M::Io)),
        ("capture verified range", S::Backend(M::Io)),
        ("capture version changed", S::Backend(M::Io)),
        ("capture version missing", S::Backend(M::Io)),
        ("capture was not flushed", S::Backend(M::Io)),
        ("carried journal header", S::Backend(M::Io)),
        ("carried journal scan", S::Backend(M::Io)),
        ("checkpoint mark missing", S::Backend(M::Io)),
        ("checkpoint stage missing", S::Backend(M::Io)),
        ("clean file content", S::Backend(M::Io)),
        ("clean file identity", S::Backend(M::Io)),
        ("clean selection", S::Backend(M::Io)),
        ("close stage", S::Backend(M::Io)),
        ("close without handle", S::Backend(M::Io)),
        ("commit graph overflow", S::Backend(M::Io)),
        ("commit prefix binding", S::Backend(M::Io)),
        ("commit prefix replay", S::Backend(M::Io)),
        ("commit prefix scan", S::Backend(M::Io)),
        ("commit stage missing", S::Backend(M::Io)),
        ("complete tree payload", S::Backend(M::Io)),
        ("complete tree selection", S::Backend(M::Io)),
        ("completion boundary", S::Backend(M::Io)),
        ("copy-up content missing", S::Backend(M::Io)),
        ("copy-up missing", S::Backend(M::Io)),
        ("create destination exists", S::Backend(M::Io)),
        ("damaged mark evidence", S::Backend(M::Io)),
        ("data encode", S::Backend(M::Io)),
        ("data value rule", S::Backend(M::Io)),
        ("delete name missing", S::Backend(M::Io)),
        ("delete type/stage/nonempty refused", S::Backend(M::Io)),
        ("detached stage has no handle", S::Backend(M::Io)),
        ("dirty interval overflow", S::Backend(M::Io)),
        ("duplicate base entry", S::Backend(M::Io)),
        ("duplicate unmerged payload", S::Backend(M::Io)),
        ("durable landing/refresh required", S::Backend(M::Io)),
        ("durable projection identity/boundary", S::Backend(M::Io)),
        ("empty path", S::Backend(M::Io)),
        ("engine graph underflow", S::Backend(M::Io)),
        ("entry vanished", S::Backend(M::Io)),
        ("equal mark conflict", S::Backend(M::Io)),
        ("extent overflow", S::Backend(M::Io)),
        ("extent size", S::Backend(M::Io)),
        ("final journal missing", S::Backend(M::Io)),
        ("final source changed", S::Backend(M::Io)),
        ("foreign scope", S::Backend(M::Io)),
        ("foreign staging name", S::Backend(M::Io)),
        ("foreign unmerged name", S::Backend(M::Io)),
        ("foreign volume entry", S::Backend(M::Io)),
        ("foreign volume", S::Backend(M::Io)),
        ("fragment length", S::Backend(M::Io)),
        ("fragment supersession", S::Backend(M::Io)),
        ("graph effect encoding", S::Backend(M::Io)),
        ("graph extent encoding", S::Backend(M::Io)),
        ("handle exhaustion", S::Backend(M::Io)),
        ("immutable object size bound", S::Backend(M::Io)),
        ("incarnation exhaustion", S::Backend(M::Io)),
        ("initial journal header", S::Backend(M::Io)),
        ("initial journal scan", S::Backend(M::Io)),
        ("initial journal writer", S::Backend(M::Io)),
        ("inode exhausted", S::Backend(M::Io)),
        ("inode exhaustion", S::Backend(M::Io)),
        ("invalid base entry", S::Backend(M::Io)),
        ("journal fenced", S::Backend(M::Io)),
        ("journal input budget", S::Backend(M::Io)),
        (
            "journal input changed or exceeded budget",
            S::Backend(M::Io),
        ),
        ("journal missing beside staging", S::Backend(M::Io)),
        ("journal missing beside unmerged", S::Backend(M::Io)),
        ("journal missing", S::Backend(M::Io)),
        ("journal value rule", S::Backend(M::Io)),
        ("landing boundary missing", S::Backend(M::Io)),
        ("landing refers to absorbed boundary", S::Backend(M::Io)),
        ("landing scan", S::Backend(M::Io)),
        ("live extent bounds", S::Backend(M::Io)),
        ("live extent mismatch", S::Backend(M::Io)),
        ("live repair anchor", S::Backend(M::Io)),
        ("live repair bounds", S::Backend(M::Io)),
        ("mark above ceiling", S::Backend(M::Io)),
        ("mark block", S::Backend(M::Io)),
        ("mark encode", S::Backend(M::Io)),
        ("mark generation conflict", S::Backend(M::Io)),
        ("missing unanchored staging", S::Backend(M::Io)),
        ("move cycle or identity", S::Backend(M::Io)),
        ("move entry missing", S::Backend(M::Io)),
        ("move prefix", S::Backend(M::Io)),
        ("move source missing", S::Backend(M::Io)),
        ("name missing", S::Backend(M::Io)),
        ("named stage missing", S::Backend(M::Io)),
        ("namespace count overflow", S::Backend(M::Io)),
        ("namespace record kind", S::Backend(M::Io)),
        ("normalization header", S::Backend(M::Io)),
        ("normalization image", S::Backend(M::Io)),
        ("normalization scan", S::Backend(M::Io)),
        ("normalization writer", S::Backend(M::Io)),
        ("not extent", S::Backend(M::Io)),
        ("open stage", S::Backend(M::Io)),
        ("open unstaged/missing file", S::Backend(M::Io)),
        (
            "orphan capture has no prepared-root name",
            S::Backend(M::Io),
        ),
        ("overlay root", S::Backend(M::Io)),
        ("parent is not a directory", S::Backend(M::Io)),
        ("partial write range", S::Backend(M::Io)),
        ("path bounds", S::Backend(M::Io)),
        ("platform buffer bound", S::Backend(M::Io)),
        ("projected prefix binding", S::Backend(M::Io)),
        ("projected prefix scan", S::Backend(M::Io)),
        ("projected residual unsupported", S::Backend(M::Io)),
        ("projected selection unnamed", S::Backend(M::Io)),
        ("projection base missing", S::Backend(M::Io)),
        ("projection empty path", S::Backend(M::Io)),
        ("projection file lacks durable payload", S::Backend(M::Io)),
        ("projection parent count", S::Backend(M::Io)),
        ("projection parent identity", S::Backend(M::Io)),
        ("projection parent missing", S::Backend(M::Io)),
        ("projection source identity", S::Backend(M::Io)),
        ("provenance empty path", S::Backend(M::Io)),
        ("provenance identity mapping", S::Backend(M::Io)),
        ("provenance journal scan", S::Backend(M::Io)),
        ("provenance parent missing", S::Backend(M::Io)),
        ("provenance replay namespace", S::Backend(M::Io)),
        ("provenance source missing", S::Backend(M::Io)),
        ("read offset", S::Backend(M::Io)),
        ("read requires staged routing", S::Backend(M::Io)),
        ("rebind empty path", S::Backend(M::Io)),
        ("rebind parent", S::Backend(M::Io)),
        ("receipt ceiling", S::Backend(M::Io)),
        ("receipt writer/ceiling", S::Backend(M::Io)),
        ("record encode", S::Backend(M::Io)),
        ("recovery commit scan", S::Backend(M::Io)),
        ("refetched extent mismatch", S::Backend(M::Io)),
        ("rejection attempt evidence", S::Backend(M::Io)),
        ("rejection boundary binding", S::Backend(M::Io)),
        ("rejection boundary missing", S::Backend(M::Io)),
        ("rejection fenced", S::Backend(M::Io)),
        ("rejection final scan", S::Backend(M::Io)),
        ("rejection header", S::Backend(M::Io)),
        ("rejection scan", S::Backend(M::Io)),
        ("rejection source", S::Backend(M::Io)),
        ("rejection torn source", S::Backend(M::Io)),
        ("rejection writer", S::Backend(M::Io)),
        ("repair header", S::Backend(M::Io)),
        ("repair range", S::Backend(M::Io)),
        ("repair stage", S::Backend(M::Io)),
        ("repaired journal changed", S::Backend(M::Io)),
        ("repaired journal rescan", S::Backend(M::Io)),
        ("replace destination missing", S::Backend(M::Io)),
        ("replace destination refused", S::Backend(M::Io)),
        ("replacement completion scan", S::Backend(M::Io)),
        ("replacement cursor map", S::Backend(M::Io)),
        ("replacement encode", S::Backend(M::Io)),
        ("replacement fenced source", S::Backend(M::Io)),
        ("replacement final counters", S::Backend(M::Io)),
        ("replacement final rescan", S::Backend(M::Io)),
        ("replacement final writer", S::Backend(M::Io)),
        ("replacement header", S::Backend(M::Io)),
        ("replacement pending prefix boundary", S::Backend(M::Io)),
        ("replacement prefix scan", S::Backend(M::Io)),
        ("replacement prefix value", S::Backend(M::Io)),
        ("replacement retained scan", S::Backend(M::Io)),
        ("replacement source scan", S::Backend(M::Io)),
        ("replacement source", S::Backend(M::Io)),
        ("replacement temporary already exists", S::Backend(M::Io)),
        ("replacement temporary missing", S::Backend(M::Io)),
        ("replacement torn source", S::Backend(M::Io)),
        ("replacement unexpected control", S::Backend(M::Io)),
        ("replacement value rule", S::Backend(M::Io)),
        ("replacement writer", S::Backend(M::Io)),
        ("replay ceiling", S::Backend(M::Io)),
        ("replay would discard held stage", S::Backend(M::Io)),
        ("residual reconciliation changed", S::Backend(M::Io)),
        ("residual scan", S::Backend(M::Io)),
        ("retained orphan has no landed Location", S::Backend(M::Io)),
        ("retirement header", S::Backend(M::Io)),
        ("retirement mark range", S::Backend(M::Io)),
        ("retirement stage", S::Backend(M::Io)),
        ("retirement still held", S::Backend(M::Io)),
        ("scope", S::Backend(M::Io)),
        ("second scope for volume", S::Backend(M::Io)),
        ("selected consent missing", S::Backend(M::Io)),
        ("selected ownership", S::Backend(M::Io)),
        ("selected receipt", S::Backend(M::Io)),
        ("selected writer binding", S::Backend(M::Io)),
        ("setattr name missing", S::Backend(M::Io)),
        ("setattr type refused", S::Backend(M::Io)),
        ("short capture extent", S::Backend(M::Io)),
        ("short capture read", S::Backend(M::Io)),
        ("shrink identity", S::Backend(M::Io)),
        ("short live extent beyond anchor", S::Backend(M::Io)),
        ("short live extent without anchor", S::Backend(M::Io)),
        ("short staged read", S::Backend(M::Io)),
        ("stage encode", S::Backend(M::Io)),
        ("stage header", S::Backend(M::Io)),
        ("stage id", S::Backend(M::Io)),
        ("stage identity binding", S::Backend(M::Io)),
        ("stage missing", S::Backend(M::Io)),
        ("stage name missing", S::Backend(M::Io)),
        ("stage selection", S::Backend(M::Io)),
        ("stage vanished", S::Backend(M::Io)),
        ("staging binding", S::Backend(M::Io)),
        ("staging header encode", S::Backend(M::Io)),
        ("staging header", S::Backend(M::Io)),
        ("stale replacement plan", S::Backend(M::Io)),
        ("sync boundary context", S::Backend(M::Io)),
        ("sync boundary was not flushed", S::Backend(M::Io)),
        ("sync directory identity", S::Backend(M::Io)),
        ("sync file identity", S::Backend(M::Io)),
        ("sync graph missing", S::Backend(M::Io)),
        ("sync graph underflow", S::Backend(M::Io)),
        ("sync projection admission", S::Backend(M::Io)),
        ("sync stage missing", S::Backend(M::Io)),
        ("synced mark beyond journal", S::Backend(M::Io)),
        ("through cursor mapping", S::Backend(M::Io)),
        ("truncate fold", S::Backend(M::Io)),
        ("truncate size", S::Backend(M::Io)),
        ("unmerged capacity", S::Backend(M::Io)),
        ("unmerged current disposition evidence", S::Backend(M::Io)),
        ("unmerged custody deadline", S::Backend(M::Io)),
        ("unmerged custody", S::Backend(M::Io)),
        ("unmerged installed binding", S::Backend(M::Io)),
        ("unmerged installed stage id", S::Backend(M::Io)),
        ("unmerged inventory binding", S::Backend(M::Io)),
        ("unmerged listing binding", S::Backend(M::Io)),
        ("unmerged listing missing", S::Backend(M::Io)),
        ("unmerged listing", S::Backend(M::Io)),
        ("unmerged pair pending retirement", S::Backend(M::Io)),
        ("unmerged payload binding", S::Backend(M::Io)),
        ("unmerged payload check", S::Backend(M::Io)),
        ("unmerged payload header", S::Backend(M::Io)),
        ("unmerged payload length", S::Backend(M::Io)),
        ("unmerged payload missing", S::Backend(M::Io)),
        ("unmerged temporary mismatch", S::Backend(M::Io)),
        ("unmerged temporary missing final", S::Backend(M::Io)),
        ("unmerged unresolved disposition", S::Backend(M::Io)),
        ("unnamed synced staging evidence", S::Backend(M::Io)),
        ("unprovable short staging header", S::Backend(M::Io)),
        ("verified source range length", S::Backend(M::Io)),
        ("write bounds", S::Backend(M::Io)),
        ("write extent bound", S::Backend(M::Io)),
        ("writer ceiling or identity", S::Backend(M::Io)),
        ("writer ceiling rollback/exhaustion", S::Backend(M::Io)),
        ("writer changed", S::Backend(M::Io)),
        ("writer decode", S::Backend(M::Io)),
        ("writer encode", S::Backend(M::Io)),
        ("writer entropy unavailable", S::Backend(M::Io)),
        ("writer length changed or exceeded bound", S::Backend(M::Io)),
        ("writer missing beside evidence", S::Backend(M::Io)),
        ("writer missing", S::Backend(M::Io)),
        ("writer volume", S::Backend(M::Io)),
        ("writer volume/identity", S::Backend(M::Io)),
        ("zero bound", S::Backend(M::Io)),
    ];
    assert_eq!(rows.len(), 438);
    let mut mismatches = Vec::new();
    for (reason, expected) in rows {
        let expected_overlay = match reason {
            "sync file identity" | "sync directory identity" | "capture stage" => S::InvalidRequest,
            "capture extent mismatch" | "short capture extent" | "clean file content" => {
                S::Backend(M::Corrupt)
            }
            _ => expected,
        };
        let actual = (
            sync_mount_error(&refused(reason)),
            sync_mount_error(&CoordinationError::Overlay(OverlayError::Refused(reason))),
            sync_mount_error(&CoordinationError::Overlay(overlay_error(refused(reason)))),
        );
        let expected = (expected, expected_overlay, expected_overlay);
        if actual != expected {
            mismatches.push((reason, actual, expected));
        }
    }
    assert!(
        mismatches.is_empty(),
        "refusal mappings differ: {mismatches:?}"
    );
}

/// A directory a landing removed or replaced is the only path listed under
/// it, but each resident inode beneath it is detached by its own path. An
/// index read from the listed paths' old inodes alone would give those
/// inodes no metadata, and their `fstat` would answer `ENOENT`.
#[test]
fn displaced_metadata_covers_the_retired_descendants_of_a_replaced_directory() {
    use crate::{OverlayEntry, OverlayKind, PathChange, ViewChange};
    let name = |path: &str| -> Vec<manifest::Name> {
        path.split('/')
            .map(|part| manifest::Name::new(part.as_bytes().to_vec()).unwrap())
            .collect()
    };
    let entry = |path: &str, inode, kind, size| OverlayEntry {
        path: name(path),
        inode,
        kind,
        stage_id: None,
        size,
        exec: false,
    };
    let file = OverlayKind::File {
        content: Some(GrainId::of(b"held")),
    };
    let change = ViewChange {
        paths: vec![PathChange {
            path: name("d"),
            old: Some(7),
            new: Some(20),
        }],
        retired: [
            (7, entry("d", 7, OverlayKind::Directory, 0)),
            (8, entry("d/c", 8, file.clone(), 5)),
            (9, entry("d/e/f", 9, file, 11)),
        ]
        .into(),
    };
    let displaced = displaced(&change);
    let node = |path: &str| {
        displaced
            .get(&path_key(&name(path)))
            .map(|entry| super::super::overlay_node((*entry).clone()))
            .map(|node| (node.kind, node.size))
    };
    assert_eq!(
        (node("d"), node("d/c"), node("d/e/f"), node("g")),
        (
            Some((granary_vfs::NodeKind::Dir, 4096)),
            Some((granary_vfs::NodeKind::File, 5)),
            Some((granary_vfs::NodeKind::File, 11)),
            None
        )
    );
}

/// How the probe double answers one probe.
enum Probe {
    /// At once.
    Now(Result<Option<u64>, RootStoreError>),
    /// After the runtime's clock moves on by the duration.
    After(std::time::Duration, Result<Option<u64>, RootStoreError>),
    /// When the test sends the head.
    Held(tokio::sync::oneshot::Receiver<Option<u64>>),
    /// When the test sends the probe's answer.
    HeldAnswer(tokio::sync::oneshot::Receiver<Result<Option<u64>, RootStoreError>>),
    /// After running an action while the request is in the store.
    AtAnswer(
        Box<dyn FnOnce() + Send>,
        Result<Option<u64>, RootStoreError>,
    ),
}

/// The authority's head, as the test answers each probe of it.
#[derive(Default)]
struct ProbeStore {
    answers: Mutex<std::collections::VecDeque<Probe>>,
    probes: std::sync::atomic::AtomicUsize,
    completed_probes: std::sync::atomic::AtomicUsize,
    instants: Mutex<Vec<tokio::time::Instant>>,
    root_reads: std::sync::atomic::AtomicUsize,
    fail_root_read: std::sync::atomic::AtomicBool,
}

impl ProbeStore {
    fn answer(&self, probe: Probe) {
        self.answers.lock().unwrap().push_back(probe);
    }
    fn probes(&self) -> usize {
        self.probes.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn completed_probes(&self) -> usize {
        self.completed_probes
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl RootStore for ProbeStore {
    async fn put_root(&self, _: &str, _: u64, _: Vec<u8>) -> Result<(), RootStoreError> {
        unreachable!("a boundary publishes nothing")
    }
    async fn get_root(&self, _: &str, _: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.root_reads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self
            .fail_root_read
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(RootStoreError::Backend("root read down".to_owned()));
        }
        unreachable!("the adopter double reads no root")
    }
    async fn read_hint(
        &self,
        _: &str,
        _: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        unreachable!("a boundary probes the head, not the hint")
    }
    async fn write_hint(&self, _: &str, _: u64) -> Result<(), RootStoreError> {
        unreachable!("a boundary publishes nothing")
    }
    async fn max_seq(&self, _: &str) -> Result<Option<u64>, RootStoreError> {
        self.probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.instants.lock().unwrap().push(TokioSyncRuntime.now());
        let Some(answer) = self.answers.lock().unwrap().pop_front() else {
            panic!("a probe the row did not answer");
        };
        let result = match answer {
            Probe::Now(head) => head,
            Probe::After(wait, head) => {
                TokioSyncRuntime.sleep(wait).await;
                head
            }
            Probe::Held(head) => head.await.map_err(|_| RootStoreError::NotFound),
            Probe::HeldAnswer(answer) => answer.await.map_err(|_| RootStoreError::NotFound)?,
            Probe::AtAnswer(action, head) => {
                action();
                head
            }
        };
        self.completed_probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        result
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

/// A wall clock whose reading the test sets.
#[derive(Default)]
struct SetClock(std::sync::atomic::AtomicI64);

impl SetClock {
    fn set(&self, secs: i64) {
        self.0.store(secs, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for SetClock {
    fn now(&self) -> granary_core::root::Timestamp {
        granary_core::root::Timestamp {
            secs: self.0.load(std::sync::atomic::Ordering::SeqCst),
            nanos: 0,
        }
    }
}

/// The engine as a boundary drives it: every head above the pin installs,
/// once the test releases an adoption it holds.
struct Adopter {
    pin: Mutex<u64>,
    hold: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    /// Refuse the next head instead of installing it, the pin first raised
    /// to it when `true`, as the mount's own landing reaching it would.
    refuse: Mutex<Option<bool>>,
    /// Fail the next adoption once with a transient coordination error.
    transient: Mutex<Option<CoordinationError>>,
    /// Read the root through `store` on the next adoption so a root-read
    /// failure surfaces through `PublishedRoot::read`.
    store: Arc<ProbeStore>,
    /// Panic inside `adopt` after `hold` releases, so the observation task
    /// unwinds without `complete`.
    panic_in_adopt: std::sync::atomic::AtomicBool,
    blocked: std::sync::atomic::AtomicBool,
    /// The store dies while a refused adoption runs, when set: every pin
    /// read after the refusal refuses, as a poisoned store's does.
    dies_on_refusal: std::sync::atomic::AtomicBool,
    dies: std::sync::atomic::AtomicBool,
    /// How many adoptions and closes of the view ran.
    adopts: std::sync::atomic::AtomicUsize,
    closes: std::sync::atomic::AtomicUsize,
    answered: std::sync::atomic::AtomicUsize,
    answered_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl crate::sync::HeadAdopter for Adopter {
    fn pin(&self) -> Result<(GrainId, u64), CoordinationError> {
        if self.dies.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::sync::refused("IntentPersistencePoisoned"));
        }
        Ok((GrainId::of(b"pin"), *self.pin.lock().unwrap()))
    }
    fn adoption_blocked(&self) -> Result<bool, CoordinationError> {
        Ok(self.blocked.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn adopt(&self, seq: u64) -> crate::sync::AdopterFuture<'_, Adopted> {
        self.adopts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let hold = self.hold.lock().unwrap().take();
        Box::pin(async move {
            if let Some(hold) = hold {
                let _ = hold.await;
            }
            assert!(
                !self
                    .panic_in_adopt
                    .swap(false, std::sync::atomic::Ordering::SeqCst),
                "the adoption task panicked"
            );
            if self
                .store
                .fail_root_read
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                let volume = granary_core::root::VolumeName::new("volume".to_owned()).unwrap();
                let keys = TrustedKeys::new([[7; 32]]).unwrap();
                crate::sync::PublishedRoot::read(&*self.store, &volume, seq, None, &keys).await?;
            }
            if let Some(error) = self.transient.lock().unwrap().take() {
                return Err(error);
            }
            if let Some(reached) = self.refuse.lock().unwrap().take() {
                if self
                    .dies_on_refusal
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    self.dies.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if reached {
                    *self.pin.lock().unwrap() = seq;
                }
                return Ok(Adopted::Refused {
                    cause: crate::sync::refused("ViewHeadRefused"),
                });
            }
            *self.pin.lock().unwrap() = seq;
            Ok(Adopted::Installed)
        })
    }
    fn close(&self, _: CoordinationError) -> crate::sync::AdopterFuture<'_, ()> {
        self.closes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
    fn answered(&self) {
        self.answered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let hook = self.answered_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook();
        }
    }
}

struct ClockControl {
    frozen: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
    /// When `Some(n)`, the observer's runtime lets `n` more spawned tasks
    /// run, then drops the next one before its first poll, as a runtime
    /// shutting down does.
    drop_spawn: Mutex<Option<usize>>,
}

/// A task that releases the paused clock while it runs and freezes it
/// again when it ends. The clock is released only after the task's first
/// poll has registered its timers: released earlier, the idle runtime would
/// jump straight past them to a later one, such as a held probe's.
struct FreezeOnDrop<F> {
    inner: std::pin::Pin<Box<F>>,
    control: Arc<ClockControl>,
    released: bool,
}

impl<F> FreezeOnDrop<F> {
    fn new(inner: F, control: Arc<ClockControl>) -> Self {
        Self {
            inner: Box::pin(inner),
            control,
            released: false,
        }
    }
}

impl<F: Future> Future for FreezeOnDrop<F> {
    type Output = F::Output;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let polled = self.inner.as_mut().poll(cx);
        if !std::mem::replace(&mut self.released, true) {
            self.control
                .frozen
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        polled
    }
}

impl<F> Drop for FreezeOnDrop<F> {
    fn drop(&mut self) {
        self.control
            .frozen
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.control.notify.notify_one();
    }
}

struct TestRuntime {
    control: Arc<ClockControl>,
    boundary: bool,
}

impl SyncRuntime for TestRuntime {
    fn now(&self) -> tokio::time::Instant {
        TokioSyncRuntime.now()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = Result<T, crate::sync::SyncRuntimeError>> + Send {
        let dropped = !self.boundary && {
            let mut countdown = self.control.drop_spawn.lock().unwrap();
            match *countdown {
                Some(0) => {
                    *countdown = None;
                    true
                }
                Some(n) => {
                    *countdown = Some(n - 1);
                    false
                }
                None => false,
            }
        };
        let future: std::pin::Pin<Box<dyn Future<Output = T> + Send>> = if self.boundary {
            Box::pin(FreezeOnDrop::new(work, self.control.clone()))
        } else {
            Box::pin(work)
        };
        // A dropped task's future is dropped here, unpolled.
        let join = (!dropped).then(|| TokioSyncRuntime.spawn(future));
        async move {
            match join {
                Some(join) => join.await,
                None => Err(crate::sync::SyncRuntimeError),
            }
        }
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl Future<Output = Result<T, crate::sync::SyncRuntimeError>> + Send {
        TokioSyncRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl Future<Output = Result<T, crate::sync::SyncRuntimeError>> + Send {
        TokioSyncRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: std::time::Duration) -> impl Future<Output = ()> + Send {
        TokioSyncRuntime.sleep(duration)
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl Future<Output = T> + Send,
    ) -> impl Future<Output = Result<T, crate::sync::SyncRuntimeError>> + Send {
        TokioSyncRuntime.timeout_at(deadline, work)
    }
}

#[derive(Clone, Default)]
struct BoundaryEvents(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BoundaryEvents {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BoundaryEvents {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl BoundaryEvents {
    fn subscriber(&self) -> Box<dyn tracing::Subscriber + Send + Sync> {
        crate::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            self.clone(),
        )
    }
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// Wait, in real time, until `predicate` holds while allowing the paused
/// runtime to advance.
#[expect(
    clippy::disallowed_methods,
    reason = "a real-time bound for a test thread, outside the paused runtime it waits on"
)]
fn poll_until(control: &ClockControl, predicate: impl Fn() -> bool) -> bool {
    for _ in 0..20 {
        if predicate() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    control
        .frozen
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    let mut met = false;
    while !met {
        if predicate() {
            met = true;
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    control
        .frozen
        .store(true, std::sync::atomic::Ordering::SeqCst);
    control.notify.notify_one();
    met
}

type PausedObserver = HeadObserver<ProbeStore, TestRuntime>;

/// A production boundary over the probe and adopter doubles, its runtime
/// a paused current-thread one that a driver thread keeps running, as the
/// mount's sync thread does.
struct PausedBoundary {
    boundary: Arc<MountViewBoundary<ProbeStore, TestRuntime>>,
    observer: Arc<PausedObserver>,
    store: Arc<ProbeStore>,
    adopter: Arc<Adopter>,
    clock: Arc<SetClock>,
    metrics: ClientMetrics,
    events: BoundaryEvents,
    local_baseline: usize,
    origin: tokio::time::Instant,
    control: Arc<ClockControl>,
    /// How many times a boundary read the adapter's writers.
    writer_reads: Arc<std::sync::atomic::AtomicUsize>,
    handle: tokio::runtime::Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    driver: Option<std::thread::JoinHandle<()>>,
}

impl PausedBoundary {
    /// The boundary of a mount pinned at seq 1 in default view mode.
    fn new() -> Self {
        Self::with_mode(super::ViewMode::Default)
    }

    fn with_mode(mode: super::ViewMode) -> Self {
        Self::build(mode, None)
    }

    fn with_budget(mode: super::ViewMode, budget: std::time::Duration) -> Self {
        Self::build(mode, Some(budget))
    }

    fn build(mode: super::ViewMode, budget: Option<std::time::Duration>) -> Self {
        let local_baseline = crate::local_report::local_capture().len();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let origin = {
            let _entered = handle.enter();
            TokioSyncRuntime.now()
        };
        let control = Arc::new(ClockControl {
            frozen: std::sync::atomic::AtomicBool::new(true),
            notify: tokio::sync::Notify::new(),
            drop_spawn: Mutex::new(None),
        });
        let keeper = control.clone();
        let entered = handle.enter();
        drop(TokioSyncRuntime.spawn(async move {
            loop {
                if keeper.frozen.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                } else {
                    keeper.notify.notified().await;
                }
            }
        }));
        drop(entered);
        let store = Arc::new(ProbeStore::default());
        let adopter = Arc::new(Adopter {
            pin: Mutex::new(1),
            hold: Mutex::default(),
            refuse: Mutex::default(),
            transient: Mutex::default(),
            store: store.clone(),
            panic_in_adopt: std::sync::atomic::AtomicBool::default(),
            blocked: std::sync::atomic::AtomicBool::default(),
            dies_on_refusal: std::sync::atomic::AtomicBool::default(),
            dies: std::sync::atomic::AtomicBool::default(),
            adopts: std::sync::atomic::AtomicUsize::default(),
            closes: std::sync::atomic::AtomicUsize::default(),
            answered: std::sync::atomic::AtomicUsize::default(),
            answered_hook: Mutex::default(),
        });
        let clock = Arc::new(SetClock::default());
        let metrics = crate::metrics::tests::metrics();
        metrics.set_available(crate::MetricsGroup::Sync, true);
        let mk_rt = |boundary| {
            Arc::new(TestRuntime {
                control: control.clone(),
                boundary,
            })
        };
        let volume = granary_core::root::VolumeName::new("volume".to_owned()).unwrap();
        let observer = Arc::new(HeadObserver::new(
            store.clone(),
            mk_rt(false),
            volume,
            clock.clone(),
            mode,
            Some(metrics.clone()),
        ));
        assert!(observer.arm(adopter.clone()), "premise: the first arming");
        let boundary = Arc::new(match budget {
            Some(b) => MountViewBoundary::with_budget(
                observer.clone(),
                mk_rt(true),
                Some(handle.clone()),
                mode,
                b,
            ),
            None => {
                MountViewBoundary::new(observer.clone(), mk_rt(true), Some(handle.clone()), mode)
            }
        });
        let events = BoundaryEvents::default();
        let driver_events = events.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let driver = std::thread::spawn(move || {
            tracing::subscriber::with_default(driver_events.subscriber(), || {
                let _ = runtime.block_on(stopped);
            });
        });
        Self {
            boundary,
            observer,
            store,
            adopter,
            clock,
            metrics,
            events,
            local_baseline,
            origin,
            control,
            writer_reads: Arc::default(),
            handle,
            stop: Some(stop),
            driver: Some(driver),
        }
    }
    /// One OPEN boundary, waited for on its own thread: what it served and
    /// how far the runtime's clock moved meanwhile; `None` for a boundary
    /// that has not returned after ten seconds.
    fn wait(&self) -> Option<(granary_fuse::BoundaryOutcome, std::time::Duration)> {
        self.wait_with(false)
    }

    fn wait_with(
        &self,
        writers: bool,
    ) -> Option<(granary_fuse::BoundaryOutcome, std::time::Duration)> {
        use granary_fuse::ViewBoundary as _;
        let (boundary, handle, reads, events) = (
            self.boundary.clone(),
            self.handle.clone(),
            self.writer_reads.clone(),
            self.events.clone(),
        );
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tracing::subscriber::with_default(events.subscriber(), || {
                let _entered = handle.enter();
                let start = TokioSyncRuntime.now();
                let outcome = boundary.wait(granary_fuse::BoundaryKind::Open, &|| {
                    reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    writers
                });
                let _ = send.send((outcome, TokioSyncRuntime.now() - start));
            });
        });
        receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .ok()
    }

    fn poll_until(&self, predicate: impl Fn() -> bool) -> bool {
        poll_until(&self.control, predicate)
    }

    /// Wait, in real time, until `count` observations have completed.
    fn completed(&self, count: u64) -> bool {
        self.poll_until(|| self.observer.state_for_test().2 >= count)
    }

    fn probes_started(&self, count: usize) -> bool {
        self.poll_until(|| self.store.probes() >= count)
    }

    fn state_cleared(&self) -> bool {
        self.poll_until(|| !self.observer.unreachable_for_test())
    }

    fn prober_stopped(&self) -> bool {
        self.poll_until(|| !self.observer.prober_for_test())
    }

    fn advance(&self, duration: std::time::Duration) {
        let (send, receive) = std::sync::mpsc::channel();
        let control = self.control.clone();
        {
            let _entered = self.handle.enter();
            drop(TokioSyncRuntime.spawn(FreezeOnDrop::new(
                async move {
                    TokioSyncRuntime.sleep(duration).await;
                    let _ = send.send(());
                },
                control,
            )));
        }
        receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the paused runtime advanced by the requested duration");
    }

    fn elapsed(&self) -> std::time::Duration {
        let _entered = self.handle.enter();
        TokioSyncRuntime.now().duration_since(self.origin)
    }

    fn probe_instants(&self) -> Vec<std::time::Duration> {
        self.store
            .instants
            .lock()
            .unwrap()
            .iter()
            .map(|instant| instant.duration_since(self.origin))
            .collect()
    }

    fn label(&self) -> Option<Result<String, granary_fuse::MountError>> {
        use granary_fuse::ViewBoundary as _;
        self.boundary
            .label()
            .map(|result| result.map(|bytes| String::from_utf8(bytes).unwrap()))
    }

    fn gauge(&self) -> Option<u64> {
        let rendered = self
            .metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap();
        rendered
            .lines()
            .find_map(|line| line.strip_prefix("granary_client_mount_view_stale "))
            .and_then(|value| value.parse::<u64>().ok())
    }

    fn view_events(&self) -> Vec<(String, String, String, String)> {
        let field = |line: &str, key: &str| {
            line.split(&format!("\"{key}\":"))
                .nth(1)
                .map(|rest| rest.trim_start_matches('"'))
                .and_then(|rest| rest.split(['"', ',', '}']).next())
                .unwrap_or_default()
                .to_owned()
        };
        self.events
            .lines()
            .into_iter()
            .filter(|line| line.contains("\"event\":\"mount.view\""))
            .map(|line| {
                (
                    field(&line, "level"),
                    field(&line, "cause"),
                    field(&line, "outcome"),
                    field(&line, "seq"),
                )
            })
            .collect()
    }

    fn view_failures(&self) -> usize {
        self.events
            .lines()
            .into_iter()
            .filter(|line| {
                line.contains("\"event\":\"op.failed\"")
                    && line.contains("\"kind\":\"view\"")
                    && line.contains("\"class\":\"unavailable\"")
            })
            .count()
    }

    fn status_lines(&self) -> Vec<String> {
        crate::local_report::local_capture().since(self.local_baseline)
    }

    fn pin(&self) -> u64 {
        *self.adopter.pin.lock().unwrap()
    }

    fn start_observation(&self) {
        let Some(observation) = self.observer.observe(false) else {
            return;
        };
        let _entered = self.handle.enter();
        drop(TokioSyncRuntime.spawn(async move {
            let _ = observation.await;
        }));
    }
}

impl Drop for PausedBoundary {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(driver) = self.driver.take() {
            let _ = driver.join();
        }
    }
}

const BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
const AT_ONCE: std::time::Duration = std::time::Duration::ZERO;

/// Exactly the observation outcomes carrying an authority sequence notify the
/// adopter. The call is outside the observer state guard. Case count 10.
#[test]
fn answered_is_called_for_each_sequence_outcome_with_the_guard_dropped() {
    let fixture = PausedBoundary::new();
    let _entered = fixture.handle.enter();
    for outcome in [
        Observed::Installed(2),
        Observed::Unchanged,
        Observed::Deferred(2),
        Observed::StillDeferred,
        Observed::HeadRefused(2),
    ] {
        fixture.observer.complete_for_test(&Ok(outcome));
    }
    let sequence_answers = fixture
        .adopter
        .answered
        .load(std::sync::atomic::Ordering::SeqCst);
    for outcome in [
        Ok(Observed::Unreachable(1)),
        Ok(Observed::Discarded),
        Ok(Observed::Closed(Some(2))),
        Ok(Observed::Closed(None)),
        Err(crate::sync::refused("ViewRootUnavailable")),
    ] {
        fixture.observer.complete_for_test(&outcome);
    }
    let after_other_outcomes = fixture
        .adopter
        .answered
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        (sequence_answers, after_other_outcomes),
        (5, 5),
        "(calls after five sequence outcomes, calls after five other outcomes)"
    );

    let lock_order = PausedBoundary::new();
    let observer = Arc::downgrade(&lock_order.observer);
    *lock_order.adopter.answered_hook.lock().unwrap() = Some(Arc::new(move || {
        let observer = observer.upgrade().expect("observer remains alive");
        let _ = observer.unreachable_for_test();
    }));
    let target = lock_order.observer.clone();
    let (sent, completed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        target.complete_for_test(&Ok(Observed::Unchanged));
        let _ = sent.send(());
    });
    if completed
        .recv_timeout(std::time::Duration::from_secs(1))
        .is_err()
    {
        std::mem::forget(lock_order);
        std::mem::forget(worker);
        panic!("answered tried to take the observer lock while its guard was held");
    }
    worker.join().unwrap();
    assert_eq!(
        lock_order
            .adopter
            .answered
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the lock-taking answered callback completed once"
    );
}

/// A boundary is answered only by a probe that began after its request. The
/// first boundary's probe is held: it is served at the budget with one
/// probe sent. A second boundary while that probe is out is served at once
/// and sends none. The held probe, released, installs its head late. A third
/// boundary sends the second probe and installs that probe's head.
#[test]
fn boundary_observation_begins_after_the_request() {
    use granary_fuse::BoundaryOutcome::{Installed, Served};
    let fixture = PausedBoundary::new();
    let (release, held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::Held(held));
    let first = (fixture.wait(), fixture.store.probes());
    let second = (fixture.wait(), fixture.store.probes());
    release.send(Some(2)).unwrap();
    let late = (fixture.completed(1), fixture.pin());
    fixture.store.answer(Probe::Now(Ok(Some(3))));
    let third = (fixture.wait(), fixture.store.probes(), fixture.pin());
    assert_eq!(
        (first, second, late, third),
        (
            (Some((Served, BUDGET)), 1),
            (Some((Served, AT_ONCE)), 1),
            (true, 2),
            (Some((Installed, AT_ONCE)), 2, 3)
        ),
        "((boundary 1, probes), (boundary 2, probes), (late install done, pin), \
         (boundary 3, probes, pin))"
    );
}

/// A boundary waits at most its budget from its request, for the probe and
/// the adoption together. A held probe is served at the budget. A probe that
/// answers a head 1,500 ms in, whose adoption is held, is served at 2,000 ms
/// from the request; released, the adoption installs the head, and the next
/// boundary finds it unchanged. A refused connection is served when it
/// answers, with nothing latched: the next boundary probes again. Case
/// count 3.
#[test]
fn a_boundary_waits_at_most_its_budget_for_probe_and_adoption() {
    use granary_fuse::BoundaryOutcome::Served;
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for case in ["slow probe", "slow adoption", "503 at once"] {
        let fixture = PausedBoundary::new();
        let (mut probe, mut adoption) = (None, None);
        match case {
            "slow probe" => {
                let (send, held) = tokio::sync::oneshot::channel();
                fixture.store.answer(Probe::Held(held));
                probe = Some(send);
            }
            "slow adoption" => {
                fixture.store.answer(Probe::After(
                    std::time::Duration::from_millis(1_500),
                    Ok(Some(2)),
                ));
                let (send, held) = tokio::sync::oneshot::channel();
                *fixture.adopter.hold.lock().unwrap() = Some(held);
                adoption = Some(send);
            }
            _ => fixture
                .store
                .answer(Probe::Now(Err(RootStoreError::Unavailable {
                    operation: "GET max",
                    status: 503,
                }))),
        }
        let first = fixture.wait();
        // The held probe ends with no head, and the held adoption installs.
        drop(probe);
        if let Some(adoption) = adoption {
            // An adoption already ended has no receiver; the row then shows it.
            let _ = adoption.send(());
        }
        let later = (fixture.completed(1), fixture.pin());
        fixture.store.answer(Probe::Now(Ok(Some(2))));
        let next = (fixture.wait(), fixture.store.probes(), fixture.pin());
        observed.push((case, first, later, next));
        expected.push(match case {
            // The held probe ends without a head: no answer, nothing latched.
            "slow probe" => (
                case,
                Some((Served, BUDGET)),
                (true, 1),
                (
                    Some((granary_fuse::BoundaryOutcome::Installed, AT_ONCE)),
                    2,
                    2,
                ),
            ),
            "slow adoption" => (
                case,
                Some((Served, BUDGET)),
                (true, 2),
                (Some((Served, AT_ONCE)), 2, 2),
            ),
            _ => (
                case,
                Some((Served, AT_ONCE)),
                (true, 1),
                (
                    Some((granary_fuse::BoundaryOutcome::Installed, AT_ONCE)),
                    2,
                    2,
                ),
            ),
        });
    }
    assert_eq!(
        observed, expected,
        "(case, first boundary, (first observation done, pin), (next boundary, probes, pin))"
    );
    assert_eq!(observed.len(), 3);
}

/// A boundary returns within its bound even when the sync runtime never
/// polls its timer: a task holds the runtime's one thread, so the waiter is
/// never run, and the boundary serves the view it has once its budget and a
/// small margin have passed in real time.
#[test]
fn a_boundary_returns_within_its_bound_while_the_runtime_is_held() {
    use granary_fuse::BoundaryOutcome::Served;
    let fixture = PausedBoundary::new();
    let (entered, held) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    {
        let _context = fixture.handle.enter();
        drop(TokioSyncRuntime.spawn(async move {
            let _ = entered.send(());
            let _ = released.recv();
        }));
    }
    held.recv_timeout(std::time::Duration::from_secs(10))
        .expect("premise: the runtime's thread is held");
    fixture.store.answer(Probe::Now(Ok(Some(1))));
    let outcome = fixture.wait().map(|(outcome, _)| outcome);
    release.send(()).unwrap();
    assert_eq!(
        outcome,
        Some(Served),
        "(the boundary returned, what it served)"
    );
}

/// A head the mount's own landing reached between the observer's read of
/// the pin and its adoption is unchanged, not refused: nothing is latched,
/// and the same seq is not skipped. A head refused with the pin still below
/// it is latched. Case count 2.
#[test]
fn a_head_the_mounts_own_landing_reached_is_unchanged_not_refused() {
    let mut observed = Vec::new();
    for reached in [true, false] {
        let fixture = PausedBoundary::new();
        *fixture.adopter.refuse.lock().unwrap() = Some(reached);
        fixture.store.answer(Probe::Now(Ok(Some(2))));
        let outcome = fixture.wait().map(|(outcome, _)| outcome);
        observed.push((
            reached,
            outcome,
            fixture.observer.state_for_test().0,
            fixture.pin(),
        ));
    }
    let served = Some(granary_fuse::BoundaryOutcome::Served);
    assert_eq!(
        observed,
        vec![(true, served, 0, 2), (false, served, 2, 1)],
        "(the pin reached the head, boundary, highest refused seq, pin)"
    );
}

/// A boundary that observes nothing reads no writers, so it never takes the
/// adapter's gate: the first boundary, whose probe is held, reads them once,
/// and a second boundary while that probe is out reads none.
#[test]
fn a_boundary_that_observes_nothing_reads_no_writers() {
    let fixture = PausedBoundary::new();
    let (release, held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::Held(held));
    fixture.wait();
    let first = fixture
        .writer_reads
        .load(std::sync::atomic::Ordering::SeqCst);
    fixture.wait();
    let second = fixture
        .writer_reads
        .load(std::sync::atomic::Ordering::SeqCst);
    drop(release);
    assert_eq!(
        (first, second),
        (1, 1),
        "(writer reads after boundary 1, after boundary 2)"
    );
}

/// A store that dies while its adoption is refused closes the view: the
/// pin read that tells a refused head from one the mount's own landing
/// reached meets the dead store, and the observer closes rather than
/// latching the head as refused.
#[test]
fn a_store_that_dies_during_a_refused_adoption_closes_the_view() {
    let fixture = PausedBoundary::new();
    *fixture.adopter.refuse.lock().unwrap() = Some(false);
    fixture
        .adopter
        .dies_on_refusal
        .store(true, std::sync::atomic::Ordering::SeqCst);
    fixture.store.answer(Probe::Now(Ok(Some(2))));
    let outcome = fixture.wait().map(|(outcome, _)| outcome);
    let (refused_through, closed, _) = fixture.observer.state_for_test();
    assert_eq!(
        (
            outcome,
            refused_through,
            closed,
            fixture
                .adopter
                .closes
                .load(std::sync::atomic::Ordering::SeqCst)
        ),
        (Some(granary_fuse::BoundaryOutcome::Served), 0, true, 1),
        "(the boundary, highest refused seq, closed latch, closes run)"
    );
}

/// A transport-down head probe enters the unreachable state, and later
/// default boundaries return at once without probing or waiting. A silent
/// peer enters only when its probe elapses at 45 s, not when the boundary's
/// 2 s wait expires. Case count 2.
#[test]
fn unreachable_head_enters_the_state_and_later_boundaries_do_not_wait() {
    use granary_fuse::BoundaryOutcome::Served;
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    let stale_ev = vec![(
        "WARN".to_owned(),
        "adopted".to_owned(),
        "stale".to_owned(),
        "1".to_owned(),
    )];
    let stale_msg = vec![
        "gran mount: warning: STALE (pinned at seq 1, since 1000): the authority cannot be reached; this writable mount serves its pinned view of volume=volume\n"
            .to_owned(),
    ];
    let state_of = |f: &PausedBoundary| {
        (
            f.observer.unreachable_for_test(),
            f.view_events().len(),
            f.gauge(),
            f.status_lines().len(),
        )
    };
    let second_of = |f: &PausedBoundary| {
        (
            f.wait(),
            f.store.probes(),
            f.view_failures(),
            f.view_events().len(),
        )
    };
    for case in ["refused connect", "silent peer"] {
        let fixture = PausedBoundary::new();
        fixture.clock.set(1_000);
        let (_hold, held) = tokio::sync::oneshot::channel();
        if case == "refused connect" {
            for _ in 0..3 {
                fixture.store.answer(Probe::Now(Err(RootStoreError::Backend(
                    "connection refused".to_owned(),
                ))));
            }
            fixture.store.answer(Probe::Held(held));
            let first = fixture.wait();
            let entered = state_of(&fixture);
            fixture.clock.set(1_100);
            let label = fixture.label();
            let second = second_of(&fixture);
            fixture.advance(std::time::Duration::from_millis(500));
            let after_reprobe = (
                fixture.probes_started(2),
                fixture.view_events(),
                fixture.status_lines(),
            );
            observed.push((case, first, entered, label, second, after_reprobe));
            expected.push((
                case,
                Some((Served, AT_ONCE)),
                (true, 1, Some(1), 1),
                Some(Ok("stale:1:1000".to_owned())),
                (Some((Served, AT_ONCE)), 1, 0, 1),
                (true, stale_ev.clone(), stale_msg.clone()),
            ));
        } else {
            let elapsed_45s = std::time::Duration::from_secs(45);
            fixture.store.answer(Probe::After(
                elapsed_45s,
                Err(RootStoreError::Elapsed {
                    operation: "GET max",
                    after: elapsed_45s,
                }),
            ));
            fixture.store.answer(Probe::Held(held));
            let first = fixture.wait();
            let at_two_secs = state_of(&fixture);
            let label_at_two_secs = fixture.label();
            fixture.advance(std::time::Duration::from_secs(8));
            let second = second_of(&fixture);
            fixture.advance(std::time::Duration::from_secs(35));
            let entered = (
                fixture.completed(1) && fixture.observer.unreachable_for_test(),
                fixture.view_events(),
                fixture.status_lines(),
            );
            observed.push((case, first, at_two_secs, label_at_two_secs, second, entered));
            expected.push((
                case,
                Some((Served, BUDGET)),
                (false, 0, Some(0), 0),
                Some(Ok("fresh:1".to_owned())),
                (Some((Served, AT_ONCE)), 1, 0, 0),
                (true, stale_ev.clone(), stale_msg.clone()),
            ));
        }
    }
    assert_eq!(
        observed, expected,
        "(case, first boundary, state after first, label, second boundary, final state)"
    );
    assert_eq!(observed.len(), 2);
}

/// A landing ends an unreachable episode, and a boundary whose own down
/// answer is discarded serves in default mode or starts another observation
/// in strict mode. Case count 3.
#[test]
fn a_landing_clears_the_unreachable_state_and_a_stale_probe_is_discarded() {
    use granary_fuse::BoundaryOutcome::{Installed, Served};
    let fresh = |seq: &str| {
        (
            "INFO".to_owned(),
            "landed".to_owned(),
            "fresh".to_owned(),
            seq.to_owned(),
        )
    };
    let mut observed = Vec::new();

    let clear = PausedBoundary::new();
    clear
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    let (_hold, held) = tokio::sync::oneshot::channel();
    clear.store.answer(Probe::Held(held));
    let entered = clear.wait();
    tracing::subscriber::with_default(clear.events.subscriber(), || clear.observer.reached(7));
    clear.advance(std::time::Duration::from_millis(500));
    observed.push((
        "clear",
        entered,
        clear.observer.unreachable_for_test(),
        clear.view_events(),
        clear.gauge(),
        clear.observer.prober_for_test(),
        clear.observer.unconfirmed(),
    ));

    for (name, mode, seq) in [
        ("default starter", super::ViewMode::Default, 8),
        ("strict starter", super::ViewMode::Strict, 9),
    ] {
        let fixture = PausedBoundary::with_mode(mode);
        let (target, events) = (fixture.observer.clone(), fixture.events.clone());
        fixture.store.answer(Probe::AtAnswer(
            Box::new(move || {
                tracing::subscriber::with_default(events.subscriber(), || target.reached(seq));
            }),
            Err(RootStoreError::Backend("old down answer".to_owned())),
        ));
        fixture.store.answer(Probe::Now(Ok(Some(2))));
        let outcome = fixture.wait();
        observed.push((
            name,
            outcome,
            fixture.observer.unreachable_for_test(),
            fixture.view_events(),
            fixture.gauge(),
            fixture.observer.prober_for_test(),
            fixture.observer.unconfirmed(),
        ));
    }

    assert_eq!(
        observed,
        vec![
            (
                "clear",
                Some((Served, AT_ONCE)),
                false,
                vec![
                    (
                        "WARN".to_owned(),
                        "adopted".to_owned(),
                        "stale".to_owned(),
                        "1".to_owned(),
                    ),
                    fresh("7"),
                ],
                Some(0),
                false,
                false,
            ),
            (
                "default starter",
                Some((Served, AT_ONCE)),
                false,
                Vec::new(),
                Some(0),
                false,
                false,
            ),
            (
                "strict starter",
                Some((Installed, AT_ONCE)),
                false,
                vec![(
                    "INFO".to_owned(),
                    "adopted".to_owned(),
                    "installed".to_owned(),
                    "2".to_owned(),
                )],
                Some(0),
                false,
                false,
            ),
        ],
        "(case, boundary, unreachable, mount.view events, gauge, prober, unconfirmed)"
    );
    assert_eq!(observed.len(), 3);
}

/// A prober that receives an answer after a landing clears its running mark
/// before it returns. Case count 1.
#[test]
fn a_prober_cleared_by_a_landing_drops_its_running_mark_before_returning() {
    let fixture = PausedBoundary::new();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    let (answer, held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::HeldAnswer(held));
    fixture.wait();
    fixture.advance(std::time::Duration::from_millis(500));
    assert!(
        fixture.probes_started(2),
        "premise: the prober's max-seq request is out"
    );
    tracing::subscriber::with_default(fixture.events.subscriber(), || {
        fixture.observer.reached(7);
    });
    let (send, receive) = std::sync::mpsc::channel();
    let target = fixture.observer.clone();
    fixture.observer.before_prober_return_for_test(move || {
        let _ = send.send(target.prober_for_test());
    });
    answer.send(Ok(Some(1))).unwrap();
    let prober = receive
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("premise: the prober reached its Ok return");
    let results = [prober];
    assert_eq!(results, [false], "prober flag at the Ok return");
    assert_eq!(results.len(), 1);
}

/// An answer from a prober request sent before a landing cannot clear an
/// unreachable episode entered after that landing; the same prober continues
/// and its next answer clears the episode. Case count 1.
#[test]
fn a_pre_landing_prober_answer_keeps_a_newer_unreachable_episode() {
    let fixture = PausedBoundary::new();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    let (old_answer, old_held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::HeldAnswer(old_held));
    fixture.wait();
    fixture.advance(std::time::Duration::from_millis(500));
    assert!(
        fixture.probes_started(2),
        "premise: the pre-landing prober request is out"
    );

    tracing::subscriber::with_default(fixture.events.subscriber(), || {
        fixture.observer.reached(7);
    });
    let (new_answer, new_held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::HeldAnswer(new_held));
    fixture.start_observation();
    assert!(
        fixture.probes_started(3),
        "premise: the post-landing observation is out"
    );
    new_answer
        .send(Err(RootStoreError::Backend("down again".to_owned())))
        .unwrap();
    assert!(
        fixture.completed(2) && fixture.observer.unreachable_for_test(),
        "premise: the newer unreachable episode was entered"
    );

    old_answer.send(Ok(Some(1))).unwrap();
    assert!(
        fixture.poll_until(|| fixture.store.completed_probes() == 3),
        "premise: the stale prober answer returned"
    );
    let after_stale = (
        fixture.observer.unreachable_for_test(),
        fixture.observer.prober_for_test(),
        fixture.store.probes(),
    );
    fixture.store.answer(Probe::Now(Ok(Some(1))));
    fixture.advance(std::time::Duration::from_millis(500));
    let after_next = (
        fixture.observer.unreachable_for_test(),
        fixture.observer.prober_for_test(),
        fixture.store.probes(),
    );
    let observed = [(after_stale, after_next)];
    assert_eq!(
        observed,
        [((true, true, 3), (false, false, 4))],
        "((unreachable, one prober, probes) after stale Ok, after next Ok)"
    );
    assert_eq!(observed.len(), 1);
}

/// A landing counted by a closed observer changes no reachability state,
/// metric, or event. Case count 1.
#[test]
fn a_closed_observer_counts_a_landing_without_marking_the_view_fresh() {
    let fixture = PausedBoundary::new();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    let (_hold, held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::Held(held));
    fixture.wait();
    fixture.observer.close_for_test();
    let before = (
        fixture.observer.landings_for_test(),
        fixture.observer.unreachable_for_test(),
        fixture.gauge(),
        fixture.view_events(),
    );
    tracing::subscriber::with_default(fixture.events.subscriber(), || {
        fixture.observer.reached(7);
    });
    let after = (
        fixture.observer.landings_for_test(),
        fixture.observer.unreachable_for_test(),
        fixture.gauge(),
        fixture.view_events(),
    );
    let observed = [(before.clone(), after)];
    assert_eq!(
        observed,
        [(before.clone(), (before.0 + 1, before.1, before.2, before.3),)],
        "((landings, unreachable, gauge, events) before reached, after reached)"
    );
    assert_eq!(observed.len(), 1);
}

/// A boundary whose writer is held still probes the head so a lost
/// authority enters the unreachable state, without reading roots or ranges.
/// Case count 2.
#[test]
fn a_held_writer_still_enters_the_unreachable_state() {
    use granary_fuse::BoundaryOutcome::{Served, Unreachable};
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for (name, mode, third_outcome) in [
        ("default", super::ViewMode::Default, Served),
        ("strict", super::ViewMode::Strict, Unreachable),
    ] {
        let fixture = PausedBoundary::with_mode(mode);
        let (_hold, held) = tokio::sync::oneshot::channel();
        fixture.store.answer(Probe::Now(Ok(Some(2))));
        fixture.store.answer(Probe::Now(Ok(Some(2))));
        fixture.store.answer(Probe::Now(Err(RootStoreError::Backend(
            "connection refused".to_owned(),
        ))));
        fixture.store.answer(Probe::Held(held));
        let first = (fixture.wait_with(true), fixture.store.probes());
        let second = (
            fixture.wait_with(true),
            fixture.store.probes(),
            fixture
                .store
                .root_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            fixture
                .adopter
                .adopts
                .load(std::sync::atomic::Ordering::SeqCst),
        );
        let third = (
            fixture.wait_with(true),
            fixture.store.probes(),
            fixture.observer.unreachable_for_test(),
        );
        observed.push((name, first, second, third));
        expected.push((
            name,
            (Some((Served, AT_ONCE)), 1),
            (Some((Served, AT_ONCE)), 2, 0, 0),
            (Some((third_outcome, AT_ONCE)), 3, true),
        ));
    }
    assert_eq!(
        observed, expected,
        "(mode, (boundary 1, probes), (boundary 2, probes, root reads, adopts), \
         (boundary 3, probes, unreachable))"
    );
    assert_eq!(observed.len(), 2);
}

/// Slow or shedding heads never enter the unreachable state, in either
/// mode; only a transport-down probe does. Case count 4.
#[test]
fn a_slow_or_loaded_head_never_enters_the_unreachable_state() {
    use granary_fuse::BoundaryOutcome::{Installed, Served, Unreachable};
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    let snap = |f: &PausedBoundary, n, p| {
        (
            f.completed(n),
            p,
            f.observer.unreachable_for_test(),
            f.gauge(),
            f.label(),
        )
    };
    let unavail = || RootStoreError::Unavailable {
        operation: "GET max",
        status: 503,
    };
    let secs = std::time::Duration::from_secs;
    for case in [
        "default 30s 503",
        "strict two 30s 503s",
        "strict 40s then seq",
        "refused connect control",
    ] {
        match case {
            "default 30s 503" => {
                let f = PausedBoundary::with_mode(super::ViewMode::Default);
                f.store.answer(Probe::After(secs(30), Err(unavail())));
                let (first, second) = (f.wait(), f.wait());
                f.advance(secs(28));
                observed.push((case, first, second, snap(&f, 1, f.store.probes())));
                let fresh = Some(Ok("fresh:1".to_owned()));
                expected.push((
                    case,
                    Some((Served, BUDGET)),
                    Some((Served, AT_ONCE)),
                    (true, 1, false, Some(0), fresh),
                ));
            }
            "strict two 30s 503s" => {
                let f = PausedBoundary::with_mode(super::ViewMode::Strict);
                for _ in 0..2 {
                    f.store.answer(Probe::After(secs(30), Err(unavail())));
                }
                let (first, probes) = (f.wait(), f.store.probes());
                f.advance(std::time::Duration::from_millis(15_500));
                observed.push((case, first, None, snap(&f, 2, probes)));
                let fresh = Some(Ok("fresh:1".to_owned()));
                expected.push((
                    case,
                    Some((Unreachable, secs(45))),
                    None,
                    (true, 2, false, Some(0), fresh),
                ));
            }
            "strict 40s then seq" => {
                let f = PausedBoundary::with_mode(super::ViewMode::Strict);
                f.store.answer(Probe::After(secs(40), Ok(Some(2))));
                let first = f.wait();
                observed.push((case, first, None, snap(&f, 1, f.store.probes())));
                let fresh = Some(Ok("fresh:2".to_owned()));
                expected.push((
                    case,
                    Some((Installed, secs(40))),
                    None,
                    (true, 1, false, Some(0), fresh),
                ));
            }
            _ => {
                let f = PausedBoundary::with_mode(super::ViewMode::Strict);
                let (_hold, held) = tokio::sync::oneshot::channel();
                for _ in 0..2 {
                    f.store
                        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
                }
                f.store.answer(Probe::Held(held));
                let first = f.wait();
                observed.push((case, first, None, snap(&f, 1, f.store.probes())));
                let stale = Some(Ok("stale:1:0".to_owned()));
                expected.push((
                    case,
                    Some((Unreachable, AT_ONCE)),
                    None,
                    (true, 1, true, Some(1), stale),
                ));
            }
        }
    }
    assert_eq!(
        observed, expected,
        "(case, first, second, (completed, probes, unreachable, gauge, label))"
    );
    assert_eq!(observed.len(), 4);
}

/// Every transport-down `RootStoreError` enters the unreachable state, and
/// every answered refusal leaves it clear. Case count 15.
#[test]
fn transport_down_classes_enter_the_state_and_answered_refusals_do_not() {
    use granary_core::rootstore::RefusalKind;
    let unexpected = |status| RootStoreError::UnexpectedStatus {
        operation: "GET max",
        status,
        token: None,
    };
    let unavail = |status| RootStoreError::Unavailable {
        operation: "GET max",
        status,
    };
    let refused = |kind| RootStoreError::RefusedResponse {
        reason: "refused".to_owned(),
        kind,
    };
    let cases = [
        ("backend", RootStoreError::Backend("down".to_owned()), true),
        (
            "elapsed",
            RootStoreError::Elapsed {
                operation: "GET max",
                after: std::time::Duration::from_secs(45),
            },
            true,
        ),
        ("unexpected 502", unexpected(502), true),
        ("unexpected 504", unexpected(504), true),
        ("refused framing", refused(RefusalKind::Framing), true),
        (
            "refused no-progress",
            refused(RefusalKind::NoProgress),
            true,
        ),
        ("unavailable 503", unavail(503), false),
        ("unavailable 429", unavail(429), false),
        ("refused over-cap", refused(RefusalKind::OverCap), false),
        ("refused extent", refused(RefusalKind::Extent), false),
        ("not found", RootStoreError::NotFound, false),
        ("range overflow", RootStoreError::RangeOverflow, false),
        ("precondition", RootStoreError::Precondition, false),
        ("already exists", RootStoreError::AlreadyExists, false),
        (
            "invalid volume",
            RootStoreError::InvalidVolume {
                reason: "bad".to_owned(),
            },
            false,
        ),
    ];
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for (name, error, down) in cases {
        let fixture = PausedBoundary::new();
        let (_hold, held) = tokio::sync::oneshot::channel();
        fixture.store.answer(Probe::Now(Err(error)));
        fixture.store.answer(Probe::Held(held));
        fixture.wait();
        observed.push((
            name,
            fixture.observer.unreachable_for_test(),
            fixture.gauge(),
        ));
        expected.push((name, down, Some(u64::from(down))));
    }
    assert_eq!(observed, expected, "(case, unreachable, gauge)");
    assert_eq!(observed.len(), 15);
}

/// A refused TCP connect at the real `HttpStore` seam produces a
/// `RootStoreError::Backend` that `is_transport_down` classifies as down and
/// that enters the observer's unreachable state.
#[test]
fn a_refused_connect_is_transport_down_at_the_http_seam() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store = crate::http_store::HttpStore::new(
        "https://127.0.0.1:1",
        vec![[1; 32]],
        &crate::AmbientNetwork,
    )
    .unwrap();
    let result = runtime.block_on(store.max_seq("volume"));
    assert!(
        matches!(result, Err(RootStoreError::Backend(_))),
        "premise: refused connect is Backend, got {result:?}"
    );
    let error = result.unwrap_err();
    let down = crate::resolve::is_transport_down(&error);
    let fixture = PausedBoundary::new();
    let (_hold, held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::Now(Err(error)));
    fixture.store.answer(Probe::Held(held));
    fixture.wait();
    assert_eq!(
        (down, fixture.observer.unreachable_for_test()),
        (true, true),
        "(is_transport_down, observer entered unreachable state)"
    );
}

/// The background prober doubles its delay from 500 ms to the 5 s cap,
/// measured from the end of each probe, keeps probing through a 503, and
/// clears the state on the first seq without adopting it.
#[test]
fn prober_backs_off_and_clears_on_the_first_seq() {
    use granary_fuse::BoundaryOutcome::{Installed, Served};
    let fixture = PausedBoundary::new();
    fixture.store.answer(Probe::Now(Err(RootStoreError::Backend(
        "connection refused".to_owned(),
    ))));
    for _ in 0..6 {
        fixture.store.answer(Probe::After(
            std::time::Duration::from_secs(1),
            Err(RootStoreError::Backend("connection refused".to_owned())),
        ));
    }
    fixture.store.answer(Probe::After(
        std::time::Duration::from_secs(1),
        Err(RootStoreError::Unavailable {
            operation: "GET max",
            status: 503,
        }),
    ));
    let (send, held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::Held(held));

    let entry = fixture.wait();
    let started = fixture.probes_started(9);
    let held_through_503 = fixture.observer.unreachable_for_test();
    let instants: Vec<u64> = fixture.probe_instants()[1..]
        .iter()
        .map(|d| u64::try_from(d.as_millis()).unwrap())
        .collect();

    send.send(Some(2)).unwrap();
    let cleared = fixture.state_cleared() && fixture.prober_stopped();
    let after_clear = (
        fixture.observer.unreachable_for_test(),
        fixture.view_events(),
        fixture.gauge(),
        fixture.label(),
        fixture.store.probes(),
        fixture.pin(),
        fixture
            .adopter
            .answered
            .load(std::sync::atomic::Ordering::SeqCst),
    );

    fixture.store.answer(Probe::Now(Ok(Some(2))));
    let next = (fixture.wait(), fixture.pin(), fixture.label());

    assert_eq!(
        (
            entry,
            started,
            held_through_503,
            instants,
            cleared,
            after_clear,
            next,
        ),
        (
            Some((Served, AT_ONCE)),
            true,
            true,
            vec![500, 2_500, 5_500, 10_500, 16_500, 22_500, 28_500, 34_500],
            true,
            (
                false,
                vec![
                    (
                        "WARN".to_owned(),
                        "adopted".to_owned(),
                        "stale".to_owned(),
                        "1".to_owned(),
                    ),
                    (
                        "INFO".to_owned(),
                        "adopted".to_owned(),
                        "fresh".to_owned(),
                        "1".to_owned(),
                    ),
                ],
                Some(0),
                Some(Ok("fresh:1".to_owned())),
                9,
                1,
                1,
            ),
            (
                Some((Installed, AT_ONCE)),
                2,
                Some(Ok("fresh:2".to_owned())),
            ),
        ),
        "(entry, 8 prober probes started, held through 503, prober start instants ms, \
         cleared, after clear, next boundary)"
    );
}

/// A successful prober response is an authority answer even when the volume
/// has no head.
#[test]
fn prober_marks_an_empty_success_as_answered() {
    let fixture = PausedBoundary::new();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    fixture.store.answer(Probe::Now(Ok(None)));
    let _ = fixture.wait();
    assert!(
        fixture.state_cleared() && fixture.prober_stopped(),
        "premise: Ok(None) ended the unreachable episode"
    );
    assert_eq!(
        fixture
            .adopter
            .answered
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Ok(None) is an answered probe"
    );
}

/// Re-entering the unreachable state after the prober cleared it starts
/// exactly one new prober at the initial 500 ms backoff and emits the edges
/// in order.
#[test]
fn a_cleared_state_re_entered_starts_one_prober() {
    let fixture = PausedBoundary::new();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    fixture.store.answer(Probe::Now(Ok(Some(1))));
    fixture.wait();
    assert!(
        fixture.state_cleared() && fixture.prober_stopped(),
        "premise: first unreachable state cleared and prober stopped"
    );

    let re_entry_at = fixture.elapsed();
    let (_hold, held) = tokio::sync::oneshot::channel();
    fixture.store.answer(Probe::Now(Err(RootStoreError::Backend(
        "down again".to_owned(),
    ))));
    fixture.store.answer(Probe::Now(Err(RootStoreError::Backend(
        "still down".to_owned(),
    ))));
    fixture.store.answer(Probe::Held(held));
    fixture.wait();
    let started = fixture.probes_started(5);
    let after_re_entry: Vec<u64> = fixture
        .probe_instants()
        .get(3..)
        .unwrap_or_default()
        .iter()
        .map(|d| u64::try_from(d.checked_sub(re_entry_at).unwrap().as_millis()).unwrap())
        .collect();
    let outcomes: Vec<String> = fixture
        .view_events()
        .into_iter()
        .map(|(_, _, outcome, _)| outcome)
        .collect();
    assert_eq!(
        (
            started,
            outcomes,
            fixture.gauge(),
            fixture.observer.prober_for_test(),
            after_re_entry,
        ),
        (
            true,
            vec!["stale".to_owned(), "fresh".to_owned(), "stale".to_owned()],
            Some(1),
            true,
            vec![500, 1_500],
        ),
        "(probes started, event outcomes, gauge, prober flag, probe instants after re-entry ms)"
    );
}

/// If the background prober task unwinds while the mount is in the
/// unreachable state, `ProberGuard` clears the flag and the next boundary
/// re-arms the prober while still returning at once.
#[test]
fn a_lost_prober_is_re_armed_at_the_next_boundary() {
    use granary_fuse::BoundaryOutcome::Served;
    let fixture = PausedBoundary::new();
    fixture.clock.set(500);
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    fixture.wait();
    let stopped = fixture.prober_stopped();
    let prober_flag = fixture.observer.prober_for_test();
    assert!(
        stopped && !prober_flag,
        "premise: panicking prober cleared the prober flag (stopped={stopped}, flag={prober_flag})"
    );
    let stale_label = fixture.label();

    fixture.store.answer(Probe::Now(Ok(Some(1))));
    let re_armed_boundary = (fixture.wait(), fixture.store.probes());
    let cleared = fixture.state_cleared() && fixture.prober_stopped();
    assert_eq!(
        (
            stale_label,
            re_armed_boundary,
            cleared,
            fixture.label(),
            fixture.store.probes(),
        ),
        (
            Some(Ok("stale:1:500".to_owned())),
            (Some((Served, AT_ONCE)), 2),
            true,
            Some(Ok("fresh:1".to_owned())),
            3,
        ),
        "(stale label after lost prober, (next boundary, probes before 500 ms), \
         state cleared, fresh label, total probes)"
    );
}

/// A prober task the runtime drops before its first poll still clears the
/// prober flag, so the next boundary re-arms a prober that ends the state.
#[test]
fn a_prober_dropped_before_its_first_poll_is_re_armed() {
    use granary_fuse::BoundaryOutcome::Served;
    let fixture = PausedBoundary::new();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    // The observation's task runs; the prober's, spawned next, is dropped.
    *fixture.control.drop_spawn.lock().unwrap() = Some(1);
    let first = fixture.wait();
    let entered = fixture.observer.unreachable_for_test();
    let dropped = fixture.control.drop_spawn.lock().unwrap().is_none();
    let flag_after_drop = fixture.observer.prober_for_test();

    fixture.store.answer(Probe::Now(Ok(Some(1))));
    let next = fixture.wait();
    let cleared = fixture.state_cleared() && fixture.prober_stopped();
    assert_eq!(
        (
            first,
            entered,
            dropped,
            flag_after_drop,
            next,
            cleared,
            fixture.label(),
            fixture.store.probes(),
        ),
        (
            Some((Served, AT_ONCE)),
            true,
            true,
            false,
            Some((Served, AT_ONCE)),
            true,
            Some(Ok("fresh:1".to_owned())),
            2,
        ),
        "(first boundary, state entered, prober spawn dropped, prober flag after the drop, \
         next boundary, state cleared by the re-armed prober, label, probes)"
    );
}

/// A strict boundary waiting on an in-flight observation wakes and starts
/// its own probe both when that observation unwinds (`InFlight::drop`) and
/// when it completes between `begin` and the boundary task's spawn. Case
/// count 2.
#[test]
fn a_lost_observation_wakes_a_strict_waiter() {
    use granary_fuse::BoundaryOutcome::Installed;
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for case in ["panics in adopt", "ends before the subscription"] {
        let fixture = PausedBoundary::with_mode(super::ViewMode::Strict);
        let (release, held) = tokio::sync::oneshot::channel();
        *fixture.adopter.hold.lock().unwrap() = Some(held);
        if case == "panics in adopt" {
            fixture
                .adopter
                .panic_in_adopt
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        fixture.store.answer(Probe::Now(Ok(Some(2))));
        fixture.start_observation();
        assert!(
            fixture.poll_until(|| {
                fixture
                    .adopter
                    .adopts
                    .load(std::sync::atomic::Ordering::SeqCst)
                    == 1
            }),
            "premise: first observation is parked in adopt"
        );
        fixture.store.answer(Probe::Now(Ok(Some(3))));
        let target = fixture.observer.clone();
        let control = fixture.control.clone();
        fixture.boundary.before_spawn_for_test(move || {
            let _ = release.send(());
            poll_until(&control, || !target.in_flight_for_test());
        });
        let second = fixture.wait();
        observed.push((case, second, fixture.store.probes(), fixture.pin()));
        expected.push((case, Some((Installed, AT_ONCE)), 2, 3));
    }
    assert_eq!(observed, expected, "(case, strict boundary 2, probes, pin)");
    assert_eq!(observed.len(), 2);
}

/// A transport-down failure during adoption's root read is "no answer yet",
/// not an unreachable head; only `max_seq` enters the state. Case count 1.
#[test]
fn an_adoption_read_failure_is_no_answer_not_unreachable() {
    use granary_fuse::BoundaryOutcome::Served;
    let fixture = PausedBoundary::new();
    fixture
        .store
        .fail_root_read
        .store(true, std::sync::atomic::Ordering::SeqCst);
    fixture.store.answer(Probe::Now(Ok(Some(2))));
    let first = (
        fixture.wait(),
        fixture.observer.unreachable_for_test(),
        fixture.label(),
        fixture.pin(),
    );
    let (_hold, held) = tokio::sync::oneshot::channel();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    fixture.store.answer(Probe::Held(held));
    let second = (
        fixture.wait(),
        fixture.observer.unreachable_for_test(),
        fixture.label(),
    );
    assert_eq!(
        (first, second),
        (
            (
                Some((Served, AT_ONCE)),
                false,
                Some(Ok("fresh:1".to_owned())),
                1,
            ),
            (
                Some((Served, AT_ONCE)),
                true,
                Some(Ok("stale:1:0".to_owned())),
            ),
        ),
        "((boundary 1, unreachable, label, pin), (boundary 2, unreachable, label))"
    );
}

/// A strict boundary waits for an in-flight observation and then starts its
/// own probe, retries after a transient adoption error, fails at once in the
/// unreachable state, fails when the runtime is held past its backstop, and
/// reads `writers` lazily. Case count 6.
#[test]
fn strict_boundary_waits_for_its_own_probe_and_never_serves_no_answer() {
    use granary_fuse::BoundaryOutcome::{Installed, Served, Unreachable};
    let mut observed = Vec::new();
    let record = |name, f: &PausedBoundary, outcome| (name, outcome, f.store.probes(), f.pin());

    // 1. In flight: waits for the earlier observation, then runs its own probe.
    let in_flight = PausedBoundary::with_mode(super::ViewMode::Strict);
    in_flight
        .store
        .answer(Probe::After(std::time::Duration::from_secs(3), Ok(Some(2))));
    in_flight.start_observation();
    assert!(
        in_flight.probes_started(1),
        "premise: earlier probe started"
    );
    in_flight.store.answer(Probe::Now(Ok(Some(3))));
    let in_flight_outcome = in_flight.wait();
    let in_flight_writers = in_flight
        .writer_reads
        .load(std::sync::atomic::Ordering::SeqCst);
    observed.push(record("in flight", &in_flight, in_flight_outcome));

    // 2. Transient adoption: Err once, then Installed 500 ms later.
    let transient = PausedBoundary::with_mode(super::ViewMode::Strict);
    *transient.adopter.transient.lock().unwrap() =
        Some(crate::sync::refused("ViewRootUnavailable"));
    for _ in 0..2 {
        transient.store.answer(Probe::Now(Ok(Some(2))));
    }
    let transient_outcome = transient.wait();
    observed.push(record("transient adoption", &transient, transient_outcome));

    // 3. In the state: Unreachable at once, probe count unchanged, 0 writer reads.
    let in_state = PausedBoundary::with_mode(super::ViewMode::Strict);
    let (_hold, held) = tokio::sync::oneshot::channel();
    in_state
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    in_state.store.answer(Probe::Held(held));
    in_state.start_observation();
    assert!(
        in_state.completed(1),
        "premise: first observation completed"
    );
    let in_state_outcome = in_state.wait();
    let in_state_writers = in_state
        .writer_reads
        .load(std::sync::atomic::Ordering::SeqCst);
    observed.push(record("in the state", &in_state, in_state_outcome));

    // 4 & 5. Held runtime: strict returns Unreachable, default returns Served.
    for (name, mode) in [
        ("held runtime strict", super::ViewMode::Strict),
        ("held runtime default", super::ViewMode::Default),
    ] {
        let f = PausedBoundary::with_budget(mode, std::time::Duration::from_millis(200));
        let (entered, held_rx) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let context = f.handle.enter();
        drop(TokioSyncRuntime.spawn(async move {
            let _ = entered.send(());
            let _ = released.recv();
        }));
        drop(context);
        held_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("premise: the runtime's thread is held");
        f.store.answer(Probe::Now(Ok(Some(2))));
        let outcome = f.wait().map(|(outcome, _)| (outcome, AT_ONCE));
        // Read while the runtime is still held: once released, it runs the
        // boundary's queued task, whose observation probes and installs.
        let held_answer = record(name, &f, outcome);
        release.send(()).unwrap();
        observed.push(held_answer);
    }

    // 6. Lazy writers: 1 read at InFlight, 0 reads in the unreachable state.
    observed.push((
        "lazy writers",
        None,
        in_flight_writers,
        u64::try_from(in_state_writers).unwrap(),
    ));

    assert_eq!(
        observed,
        vec![
            (
                "in flight",
                Some((Installed, std::time::Duration::from_secs(3))),
                2,
                3
            ),
            (
                "transient adoption",
                Some((Installed, std::time::Duration::from_millis(500))),
                2,
                2
            ),
            ("in the state", Some((Unreachable, AT_ONCE)), 1, 1),
            ("held runtime strict", Some((Unreachable, AT_ONCE)), 0, 1),
            ("held runtime default", Some((Served, AT_ONCE)), 0, 1),
            ("lazy writers", None, 1, 0),
        ],
        "(case, outcome, probes or in-flight writer reads, pin or in-state writer reads)"
    );
    assert_eq!(observed.len(), 6);
}

/// The view label always names the served pin, never an un-installed head,
/// and flips to `stale:<pin>:<since>` only in the unreachable state. Case
/// count 7.
#[test]
fn view_label_names_the_served_pin_and_moves_only_on_completion() {
    let fixture = PausedBoundary::new();
    let mut observed = Vec::new();

    // 1. Start at pin 1.
    observed.push(("start", fixture.label()));

    // 2. Adoption of seq 2 held after its probe: still fresh:1.
    let (release, held) = tokio::sync::oneshot::channel();
    *fixture.adopter.hold.lock().unwrap() = Some(held);
    fixture.store.answer(Probe::Now(Ok(Some(2))));
    fixture.wait();
    observed.push(("held adoption", fixture.label()));

    // 3. Released adoption completes: fresh:2.
    release.send(()).unwrap();
    fixture.completed(1);
    observed.push(("released adoption", fixture.label()));

    // 4. Dirty overlay defers seq 3: still fresh:2.
    fixture
        .adopter
        .blocked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    fixture.store.answer(Probe::Now(Ok(Some(3))));
    fixture.wait();
    fixture.completed(2);
    observed.push(("deferred", fixture.label()));
    fixture
        .adopter
        .blocked
        .store(false, std::sync::atomic::Ordering::SeqCst);

    // 5. Corrupt seq 4 refused: still fresh:2.
    *fixture.adopter.refuse.lock().unwrap() = Some(false);
    fixture.store.answer(Probe::Now(Ok(Some(4))));
    fixture.wait();
    fixture.completed(3);
    observed.push(("refused", fixture.label()));

    // 6. Transport-down probe at wall time 900: stale:2:900.
    fixture.clock.set(900);
    let (_hold_prober, held_prober) = tokio::sync::oneshot::channel();
    fixture
        .store
        .answer(Probe::Now(Err(RootStoreError::Backend("down".to_owned()))));
    fixture.store.answer(Probe::Held(held_prober));
    fixture.wait();
    fixture.completed(4);
    observed.push(("down probe", fixture.label()));

    // 7. Closed view (Err(Io)) and unarmed observer (None).
    fixture
        .adopter
        .dies
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let closed_label = fixture.label();
    let unarmed = HeadObserver::new(
        fixture.store.clone(),
        Arc::new(TestRuntime {
            control: fixture.control.clone(),
            boundary: false,
        }),
        granary_core::root::VolumeName::new("volume".to_owned()).unwrap(),
        fixture.clock.clone(),
        super::ViewMode::Default,
        None,
    );
    assert_eq!(unarmed.label(), None, "unarmed observer has no label");
    observed.push(("closed", closed_label));

    assert_eq!(
        observed,
        vec![
            ("start", Some(Ok("fresh:1".to_owned()))),
            ("held adoption", Some(Ok("fresh:1".to_owned()))),
            ("released adoption", Some(Ok("fresh:2".to_owned()))),
            ("deferred", Some(Ok("fresh:2".to_owned()))),
            ("refused", Some(Ok("fresh:2".to_owned()))),
            ("down probe", Some(Ok("stale:2:900".to_owned()))),
            ("closed", Some(Err(granary_fuse::MountError::Io))),
        ],
        "(case, label)"
    );
    assert_eq!(observed.len(), 7);
}

#[test]
fn residual_refusal_identifiers() {
    use granary_fuse::{MountError as M, MountSyncError as S};
    let rows = [
        (
            "RecoveryResidualSourceMissing",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualCaptureChanged",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualCaptureSignature",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualLandingChanged",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualClosure",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualReadOnly",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualValidatedAwaitingExecution",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualUnavailable",
            S::Backend(M::Unavailable),
            crate::FailureClass::Unavailable,
        ),
        (
            "RecoveryResidualWorkspace",
            S::Backend(M::NoSpace),
            crate::FailureClass::Io,
        ),
        (
            "RecoveryResidualInventoryCheck",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualInventoryCount",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualPayloadHeader",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualPayloadLength",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualSourceChanged",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
        (
            "RecoveryResidualUnrepresentable",
            S::Backend(M::Io),
            crate::FailureClass::Refused,
        ),
    ];
    assert_eq!(rows.len(), 15);
    for (name, mount, class) in rows {
        let error = refused(name);
        assert_eq!(
            (
                sync_mount_error(&error),
                crate::sync::failure_class(&error),
                crate::writable_start::coordination_class(&error)
            ),
            (mount, class, class),
            "{name}"
        );
    }
}

#[test]
fn overlay_cap_refusals_and_storage_full_keep_distinct_classes_and_enospc() {
    use granary_fuse::{MountError as M, MountSyncError as S};
    let rows = [
        (
            CoordinationError::Overlay(OverlayError::NoSpace),
            crate::FailureClass::Refused,
        ),
        (
            CoordinationError::Overlay(OverlayError::Refused("OverlayCapacityExhausted")),
            crate::FailureClass::Refused,
        ),
        (
            CoordinationError::Overlay(OverlayError::Io(std::io::ErrorKind::StorageFull.into())),
            crate::FailureClass::Io,
        ),
    ];
    assert_eq!(rows.len(), 3);
    for (error, class) in rows {
        assert_eq!(
            (
                sync_mount_error(&error),
                crate::writable_start::coordination_class(&error),
            ),
            (S::Backend(M::NoSpace), class),
            "{error:?}"
        );
    }
}
