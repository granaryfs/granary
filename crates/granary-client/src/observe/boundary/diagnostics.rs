// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Fixed diagnostic templates and exhaustive scalar fields.

// @file-disposition: STAYS — The typed variants, constructors and scalar projections share one exhaustive diagnostic mapping. The schemas child owns callsite registration and field validation.

mod schemas;
use schemas::{
    A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_META,
    AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_META,
    ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_META,
    CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META,
    CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_META, CACHE_ANCHOR_WRITE_FAILED_META,
    CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_META,
    CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_META,
    CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_META,
    CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_META,
    CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_META,
    CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_META,
    CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META,
    CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_META,
    CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_META,
    CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_META,
    CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_META,
    CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_META,
    CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_META,
    CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_META,
    CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_META,
    CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
    CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_META,
    CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META,
    CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_META,
    CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_META,
    CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_META,
    CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
    CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_META,
    CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_META,
    CACHE_MAINTAIN_COMPACTION_FAILED_META,
    CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_META,
    CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META,
    CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_META,
    CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META,
    CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_META,
    CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_META,
    CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META,
    CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_META, CACHE_ROOT_WRITE_FAILED_META,
    CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_META,
    CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
    CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_META,
    CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_META,
    CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_META,
    CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META,
    CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_META,
    CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META,
    CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META,
    CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META,
    COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_META,
    COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_META,
    COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_META,
    COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_META,
    COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_META,
    COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_META,
    COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_META,
    COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_META,
    COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_META,
    COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_META,
    COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_META,
    GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_META,
    GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_META,
    GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_META,
    GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_META,
    GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_META,
    GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_META,
    GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_META,
    GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_META,
    GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_META,
    GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_META,
    GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_META,
    GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_META,
    GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_META,
    GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_META,
    GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_META,
    GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_META,
    GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_META,
    HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_META,
    HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_META,
    MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_META,
    MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_META,
    MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_META,
    MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_META,
    MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_META,
    REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_META,
    REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_META,
    REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_META, SEAM_ATTEMPT_FAILED_RETRYING_ONCE_META,
    SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_META,
    STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_META,
    STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_META,
    STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_META,
    STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_META,
    STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META,
    STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META,
    STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_META,
    STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META, STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_META,
    STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META, STRUCTURE_WALK_META,
    SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_META,
    THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_META,
    WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_META,
    WRITABLE_SHUTDOWN_COORDINATION_FAILED_META,
};
pub(super) use schemas::{SITES, domain, numeric, path_class};

use super::{
    ClientEvent, DefaultCallsite, FailureClass, FieldSet, Identifier, Level, Metadata, Payload,
    Scalar,
};
use crate::observe::{FuseConnection, MountListing};

const SESSION_DID_NOT_END_MESSAGE: &str =
    "gran mount: stopped waiting for the FUSE session to end after its unmount";
/// Closed `TeardownCause` labels.
#[derive(Clone, Copy, Debug)]
pub enum TeardownCause {
    /// The `shutdown` class.
    Shutdown,
    /// The `drop` class.
    Drop,
}
impl TeardownCause {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::Drop => "drop",
        }
    }
}
/// Closed `WalkOutcome` labels.
#[derive(Clone, Copy, Debug)]
pub enum WalkOutcome {
    /// The `done` class.
    Done,
    /// The `need` class.
    Need,
    /// The `error` class.
    Error,
}
impl WalkOutcome {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Need => "need",
            Self::Error => "error",
        }
    }
}
/// Closed `HttpSeam` labels.
#[derive(Clone, Copy, Debug)]
pub enum HttpSeam {
    /// The `put_bin` class.
    PutBin,
    /// The `get_bin` class.
    GetBin,
    /// The `get_bin_range` class.
    GetBinRange,
    /// The `put_root` class.
    PutRoot,
    /// The `get_root` class.
    GetRoot,
    /// The `max_seq` class.
    MaxSeq,
    /// The `read_hint` class.
    ReadHint,
    /// The `write_hint` class.
    WriteHint,
    /// The `probe_root` class.
    ProbeRoot,
    /// Metadata upload.
    PutMeta,
    /// Metadata read.
    GetMeta,
    /// The `other` class.
    Other,
}
impl HttpSeam {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::PutBin => "put_bin",
            Self::GetBin => "get_bin",
            Self::GetBinRange => "get_bin_range",
            Self::PutRoot => "put_root",
            Self::GetRoot => "get_root",
            Self::MaxSeq => "max_seq",
            Self::ReadHint => "read_hint",
            Self::WriteHint => "write_hint",
            Self::ProbeRoot => "probe_root",
            Self::PutMeta => "put_meta",
            Self::GetMeta => "get_meta",
            Self::Other => "other",
        }
    }
    /// Select a label at the audited producer adapter; unknown input stays a class.
    #[must_use]
    pub fn from_adapter(value: &str) -> Self {
        match value {
            "PUT bin" => Self::PutBin,
            "GET bin" => Self::GetBin,
            "get_bin_range" => Self::GetBinRange,
            "PUT root" => Self::PutRoot,
            "GET root" => Self::GetRoot,
            "GET max-seq" => Self::MaxSeq,
            "GET hint" => Self::ReadHint,
            "PUT hint" => Self::WriteHint,
            "probe_root" => Self::ProbeRoot,
            "PUT meta" => Self::PutMeta,
            "GET meta" => Self::GetMeta,
            _ => Self::Other,
        }
    }
}
/// Closed `WireRetryClass` labels.
#[derive(Clone, Copy, Debug)]
pub enum WireRetryClass {
    /// The `unsent` class.
    Unsent,
    /// The `stream_refused` class.
    StreamRefused,
    /// The `connection_failed` class.
    ConnectionFailed,
    /// The `not_retryable` class.
    NotRetryable,
}
impl WireRetryClass {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Unsent => "unsent",
            Self::StreamRefused => "stream_refused",
            Self::ConnectionFailed => "connection_failed",
            Self::NotRetryable => "not_retryable",
        }
    }
}
/// Closed `ProxyVariableName` labels.
#[derive(Clone, Copy, Debug)]
pub enum ProxyVariableName {
    /// The `HTTP_PROXY` class.
    HttpUpper,
    /// The `HTTPS_PROXY` class.
    HttpsUpper,
    /// The `ALL_PROXY` class.
    AllUpper,
    /// The `NO_PROXY` class.
    NoUpper,
    /// The `http_proxy` class.
    HttpLower,
    /// The `https_proxy` class.
    HttpsLower,
    /// The `all_proxy` class.
    AllLower,
    /// The `no_proxy` class.
    NoLower,
    /// The `other` class.
    Other,
}
impl ProxyVariableName {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::HttpUpper => "HTTP_PROXY",
            Self::HttpsUpper => "HTTPS_PROXY",
            Self::AllUpper => "ALL_PROXY",
            Self::NoUpper => "NO_PROXY",
            Self::HttpLower => "http_proxy",
            Self::HttpsLower => "https_proxy",
            Self::AllLower => "all_proxy",
            Self::NoLower => "no_proxy",
            Self::Other => "other",
        }
    }
    /// Select a label at the audited producer adapter; unknown input stays a class.
    #[must_use]
    pub fn from_adapter(value: &str) -> Self {
        match value {
            "HTTP_PROXY" => Self::HttpUpper,
            "HTTPS_PROXY" => Self::HttpsUpper,
            "ALL_PROXY" => Self::AllUpper,
            "NO_PROXY" => Self::NoUpper,
            "http_proxy" => Self::HttpLower,
            "https_proxy" => Self::HttpsLower,
            "all_proxy" => Self::AllLower,
            "no_proxy" => Self::NoLower,
            _ => Self::Other,
        }
    }
}
/// Closed `CacheAction` labels.
#[derive(Clone, Copy, Debug)]
pub enum CacheAction {
    /// The `cache evict` class.
    Evict,
    /// The `cache get: hash mismatch` class.
    HashMismatch,
    /// The `cache evict oversized` class.
    Oversized,
    /// The `other` class.
    Other,
}
impl CacheAction {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Evict => "cache evict",
            Self::HashMismatch => "cache get: hash mismatch",
            Self::Oversized => "cache evict oversized",
            Self::Other => "other",
        }
    }
    /// Select a label at the audited producer adapter; unknown input stays a class.
    #[must_use]
    pub fn from_adapter(value: &str) -> Self {
        match value {
            "cache eviction" => Self::Evict,
            "cache get: hash mismatch" => Self::HashMismatch,
            "cache evict oversized" => Self::Oversized,
            _ => Self::Other,
        }
    }
}
/// Closed `IndexFileKind` labels.
#[derive(Clone, Copy, Debug)]
pub enum IndexFileKind {
    /// The `snapshot` class.
    Snapshot,
    /// The `journal` class.
    Journal,
    /// The `other` class.
    Other,
}
impl IndexFileKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Journal => "journal",
            Self::Other => "other",
        }
    }
    /// Select a label at the audited producer adapter; unknown input stays a class.
    #[must_use]
    pub fn from_adapter(value: &str) -> Self {
        match value {
            "snapshot" => Self::Snapshot,
            "journal" => Self::Journal,
            _ => Self::Other,
        }
    }
}
/// Closed `SignalKind` labels.
#[derive(Clone, Copy, Debug)]
pub enum SignalKind {
    /// The `SIGINT` class.
    Interrupt,
    /// The `SIGTERM` class.
    Terminate,
    /// The `other` class.
    Other,
}
impl SignalKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
            Self::Other => "other",
        }
    }
    /// Select a label at the audited producer adapter; unknown input stays a class.
    #[must_use]
    pub fn from_adapter(value: &str) -> Self {
        match value {
            "SIGINT" => Self::Interrupt,
            "SIGTERM" => Self::Terminate,
            _ => Self::Other,
        }
    }
}
/// A known age in whole seconds, or an unavailable age.
#[derive(Clone, Copy, Debug)]
pub enum Age {
    /// No usable timestamp.
    Unknown,
    /// Elapsed whole seconds.
    Seconds(u64),
}
impl Age {
    fn scalar(self) -> Scalar {
        match self {
            Self::Unknown => Scalar::text("unknown"),
            Self::Seconds(n) => Scalar::Number(n),
        }
    }
}
/// An exhaustively typed diagnostic; no public payload or generic fields.
///
/// ```compile_fail,E0308
/// use granary_client::OperatorDiagnostic;
/// let event = OperatorDiagnostic::cache_journal_flush_failed_records_stay_buffered("synthetic-secret");
/// ```
#[derive(Debug)]
pub struct OperatorDiagnostic {
    inner: Diagnostic,
}
#[derive(Debug)]
pub(super) enum Diagnostic {
    CacheJournalIsBrokenAfterAFailedReopenMid,
    CacheJournalFlushFailedRecordsStayBuffered {
        error: FailureClass,
    },
    CacheCompactionFailedJournalLeftUncompacted {
        error: FailureClass,
    },
    CacheJournalBufferExceededItsCapUnderSustainedFree {
        dropped_records: u64,
        dropped_bytes: u64,
    },
    CacheJournalFlushRefusedByTheFreeSpaceWatermark,
    CacheCompactionRefusedByTheFreeSpaceWatermarkSnapshot,
    CacheCompactionRefusedByTheFreeSpaceWatermarkBefore,
    CacheEvictionFoundNothingLeftToEvictTheInsert {
        total_bytes: u64,
        quota: u64,
    },
    CacheInsertTheObjectPathHasNoFanoutParent,
    CacheInsertRefusedTheObjectFanoutIsNotA {
        error: FailureClass,
    },
    CacheInsertDeclinedADirectoryOccupiesTheObjectPath,
    CacheInsertAForeignEntrySitsAtTheObject,
    CacheInsertFailedToInspectTheObjectPath {
        error: FailureClass,
    },
    CacheInsertRefusedObjectIsLargerThanTheWhole {
        len: u64,
        quota: u64,
    },
    CacheInsertFailedToStageTheObjectNothingWas {
        error: FailureClass,
    },
    CacheInsertRefusedByTheFreeSpaceWatermark {
        len: u64,
    },
    CacheInsertFailedToCreateItsFanoutDirectory {
        error: FailureClass,
    },
    CacheInsertFailedToWriteTheObject {
        error: FailureClass,
    },
    CacheInsertObjectTooLargeToIndexTheFile {
        len: u64,
    },
    CacheRootWriteSkippedTheRootPathHasNo {
        seq: u64,
    },
    CacheRootWriteSkippedTheVolumeDirectoryIsNot {
        seq: u64,
        error: FailureClass,
    },
    CacheRootWriteSkippedADirectoryOccupiesTheDestination {
        seq: u64,
    },
    CacheRootWriteAForeignEntrySitsAtThe {
        seq: u64,
    },
    CacheRootWriteSkippedTheDestinationCouldNotBe {
        seq: u64,
        error: FailureClass,
    },
    CacheRootWriteRefusedByTheFreeSpaceWatermark {
        seq: u64,
        len: u64,
    },
    CacheRootWriteFailedToCreateItsVolumeDirectory {
        error: FailureClass,
    },
    CacheRootWriteFailed {
        seq: u64,
        error: FailureClass,
    },
    AnchorFloorCandidateIsAnAbsentClassSeqRefusing {
        candidate: u64,
    },
    HintTokenIsEmptyAnEtagLessBackendRetaining,
    HintIsUnpersistableTokenBytesLengthStampSignOr,
    CacheAnchorWriteFailedToCreateItsDirectory {
        error: FailureClass,
    },
    CacheAnchorWriteFailed {
        error: FailureClass,
    },
    MountAnchorFloorCandidateIsAnAbsentClassSeq {
        candidate: u64,
    },
    CacheRootEvictionSkippedTheRootPathHasNo {
        seq: u64,
    },
    CacheRootEvictionSkippedTheVolumeDirectoryIsNot {
        seq: u64,
        error: FailureClass,
    },
    CacheRootEvictionFailedToRemoveTheFile {
        seq: u64,
        error: FailureClass,
    },
    CacheGuardPresentAtOpenThePreviousWriterDid,
    CacheLockHeldByAnotherProcessOpeningReadOnly,
    CacheReadRefusedTheObjectFanoutIsNotA {
        error: FailureClass,
    },
    CacheObjectFailedHashVerificationUnlinkingAndEvicting,
    CacheObjectExceedsTheSizeBoundTreatingItAs {
        len: u64,
    },
    CachedRootExceedsTheSizeBoundTreatingItAs {
        seq: u64,
        len: u64,
    },
    CacheMaintainJournalFlushFailedSkippingCompactionThisCycle {
        error: FailureClass,
    },
    CacheMaintainCompactionFailed {
        error: FailureClass,
    },
    SetInTheEnvironmentAndIgnoredTheDirectS3 {
        variable: ProxyVariableName,
    },
    WireSnapshotPublishTheTempFileCouldNotBe {
        error: FailureClass,
    },
    ACacheDirIsPresentButATransportDown,
    TheTransportGaveNoAnswerFallingBackToThe {
        seq: u64,
        age: Age,
    },
    StoreAnObjectPathHasNoFanoutParentReporting,
    StoreAnObjectFanoutIsNotARealDirectory {
        error: FailureClass,
    },
    StoreAnObjectLeafIsNotARegularFile,
    StoreAnObjectLeafCouldNotBeClassifiedReporting {
        error: FailureClass,
    },
    StorePutTheObjectFanoutIsNotAReal {
        error: FailureClass,
    },
    StorePutAnObjectLeafIsNotARegular,
    StoreGetTheObjectFanoutIsNotAReal {
        error: FailureClass,
    },
    StoreEstablishedOpenTxnIsNotARealDirectory,
    StoreEstablishedOpenAnOrphanedTxnEntryCouldNot {
        error: FailureClass,
    },
    StoreEstablishedOpenSweptOrphanedTxnStagingFiles {
        swept: u64,
        skipped: u64,
    },
    SeamAttemptFailedRetryingOnce {
        seam: HttpSeam,
        class: WireRetryClass,
        error: FailureClass,
    },
    WritableShutdownCoordinationFailed {
        coordination: FailureClass,
        cache_closed: bool,
    },
    MountSessionShutdownClosingTheCacheFailedTheCrash {
        error: FailureClass,
    },
    MountTeardownReadPathCountersForTheReadPhase {
        via: TeardownCause,
        inflight_high_water: u64,
        window: u64,
        origin_requests: u64,
        origin_sheds: u64,
        origin_requests_total: u64,
        wants_bin: u64,
        wants_meta: u64,
        wants_total: u64,
        cache_hits: u64,
        cache_misses: u64,
    },
    MountSessionDropClosingTheCacheFailedTheCrash {
        error: FailureClass,
    },
    CacheAnchorFileExceedsTheSizeBoundTreatingIt {
        len: u64,
    },
    CacheAnchorFileFailedStrictParseTreatingItAs,
    MountAnchorFileCarriesAHintLineWhichIts,
    RefusingToUnlinkAnObjectPathThatHasNo {
        context: CacheAction,
    },
    RefusingToUnlinkAnObjectThroughAForeignFanout {
        context: CacheAction,
    },
    RefusingToUnlinkAnObjectUnderAFanoutThat {
        error: FailureClass,
        context: CacheAction,
    },
    AnObjectLeafCouldNotBeUnlinkedItStays {
        error: FailureClass,
        context: CacheAction,
    },
    ColdRebuildWalkSkippingANonDigestFileName,
    ColdRebuildWalkSkippingAFileWhoseNameDoes,
    ColdRebuildWalkSkippingAnEntryWhoseMetadataCould {
        error: FailureClass,
    },
    ColdRebuildWalkSkippingANonRegularFileEntry,
    ColdRebuildWalkSkippingAnOversizedForeignFile {
        len: u64,
    },
    ColdRebuildWalkSkippingASizeThatCannotFit {
        len: u64,
    },
    ColdRebuildWalkSkippingANonFanoutEntryUnder,
    ColdRebuildWalkSkippingAFanoutEntryWhoseType {
        error: FailureClass,
    },
    ColdRebuildWalkSkippingANonDirectoryEntryUnder,
    ColdRebuildWalkTheAdoptionCapWasReachedThe {
        dropped: u64,
        adoption_cap: u64,
    },
    ColdRebuildWalkSnapshotRewriteAndJournalResetRefused,
    CacheIndexFileExceedsTheSizeBoundTreatingIt {
        len: u64,
        what: IndexFileKind,
    },
    CacheIndexFileGrewPastTheSizeBoundBetween {
        len: u64,
        what: IndexFileKind,
    },
    CacheSnapshotPresentWithNoJournalACreationCrash,
    CacheWriterOpenAnOrphanedTxnEntryCouldNot {
        error: FailureClass,
    },
    CacheWriterOpenSweptOrphanedTxnStagingFiles {
        swept: u64,
        skipped: u64,
    },
    StructureWalk {
        round: u64,
        outcome: WalkOutcome,
        needs: u64,
        hints: u64,
        admits: u64,
        pool_len: u64,
        pool_used: u64,
    },
    GranMountUnmountFailedFallingBackToALazy {
        error: FailureClass,
    },
    GranMountTheMountWasLazilyDetachedMntDetach,
    GranMountBothThePlainUnmountAndTheMnt {
        unmount_error: FailureClass,
        detach_error: FailureClass,
    },
    GranMountASignalReadinessReportNeverArrivedBefore,
    GranMountACachedRootAndTheWireRoot,
    GranMountCouldNotBuildARuntimeForSigint,
    GranMountCouldNotRegisterASigintHandlerThis {
        error: FailureClass,
    },
    GranMountTheSigintStreamEndedWithoutDeliveringA,
    GranMountCouldNotBuildARuntimeForSigterm,
    GranMountCouldNotRegisterASigtermHandlerThis,
    GranMountDetachTargetUnavailableLazyDetachCannotBe {
        error: FailureClass,
    },
    GranMountReceivedSignalUnmounting {
        signal: SignalKind,
    },
    GranMountTheFuseSessionEndedWithAnError {
        error: FailureClass,
    },
    GranMountTheFuseSessionDidNotEndAfterItsUnmount {
        listed: MountListing,
        connection: FuseConnection,
    },
    GranMountTheFuseSessionThreadPanicked,
    GranMountCouldNotCaptureTheMountIdentity {
        error: FailureClass,
    },
    GranMountTheFuseSessionEndedEconnabortedRacingItsUnmount,
    SyncRegistrationTimingSampleUnavailable,
}
impl OperatorDiagnostic {
    pub(crate) fn emit_paths(self, slots: &[super::PathSlot<'_>]) {
        ClientEvent {
            payload: Payload::Diagnostic(self.inner),
        }
        .emit_paths(slots);
    }

    /// Emit only this diagnostic's approved scalars.
    pub fn emit(self) {
        ClientEvent {
            payload: Payload::Diagnostic(self.inner),
        }
        .emit();
    }
    /// cache journal is broken after a failed reopen mid-session.
    #[must_use]
    pub fn cache_journal_is_broken_after_a_failed_reopen_mid() -> Self {
        Self {
            inner: Diagnostic::CacheJournalIsBrokenAfterAFailedReopenMid,
        }
    }
    /// cache journal flush failed.
    #[must_use]
    pub fn cache_journal_flush_failed_records_stay_buffered(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheJournalFlushFailedRecordsStayBuffered { error },
        }
    }
    /// cache compaction failed.
    #[must_use]
    pub fn cache_compaction_failed_journal_left_uncompacted(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheCompactionFailedJournalLeftUncompacted { error },
        }
    }
    /// cache journal buffer exceeded its cap under sustained free-space refusal.
    #[must_use]
    pub fn cache_journal_buffer_exceeded_its_cap_under_sustained_free(
        dropped_records: u64,
        dropped_bytes: u64,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheJournalBufferExceededItsCapUnderSustainedFree {
                dropped_records,
                dropped_bytes,
            },
        }
    }
    /// cache journal flush refused by the free-space watermark.
    #[must_use]
    pub fn cache_journal_flush_refused_by_the_free_space_watermark() -> Self {
        Self {
            inner: Diagnostic::CacheJournalFlushRefusedByTheFreeSpaceWatermark,
        }
    }
    /// cache compaction refused by the free-space watermark.
    #[must_use]
    pub fn cache_compaction_refused_by_the_free_space_watermark_snapshot() -> Self {
        Self {
            inner: Diagnostic::CacheCompactionRefusedByTheFreeSpaceWatermarkSnapshot,
        }
    }
    /// cache compaction refused by the free-space watermark before truncating the journal.
    #[must_use]
    pub fn cache_compaction_refused_by_the_free_space_watermark_before() -> Self {
        Self {
            inner: Diagnostic::CacheCompactionRefusedByTheFreeSpaceWatermarkBefore,
        }
    }
    /// cache eviction found nothing left to evict.
    #[must_use]
    pub fn cache_eviction_found_nothing_left_to_evict_the_insert(
        total_bytes: u64,
        quota: u64,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheEvictionFoundNothingLeftToEvictTheInsert { total_bytes, quota },
        }
    }
    /// cache insert: the object path has no fanout parent.
    #[must_use]
    pub fn cache_insert_the_object_path_has_no_fanout_parent() -> Self {
        Self {
            inner: Diagnostic::CacheInsertTheObjectPathHasNoFanoutParent,
        }
    }
    /// cache insert refused: the object fanout is not a real directory.
    #[must_use]
    pub fn cache_insert_refused_the_object_fanout_is_not_a(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheInsertRefusedTheObjectFanoutIsNotA { error },
        }
    }
    /// cache insert declined: a DIRECTORY occupies the object path, which no write can replace.
    #[must_use]
    pub fn cache_insert_declined_a_directory_occupies_the_object_path() -> Self {
        Self {
            inner: Diagnostic::CacheInsertDeclinedADirectoryOccupiesTheObjectPath,
        }
    }
    /// cache insert: a foreign entry sits at the object path.
    #[must_use]
    pub fn cache_insert_a_foreign_entry_sits_at_the_object() -> Self {
        Self {
            inner: Diagnostic::CacheInsertAForeignEntrySitsAtTheObject,
        }
    }
    /// cache insert failed to inspect the object path.
    #[must_use]
    pub fn cache_insert_failed_to_inspect_the_object_path(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheInsertFailedToInspectTheObjectPath { error },
        }
    }
    /// cache insert refused: object is larger than the whole quota.
    #[must_use]
    pub fn cache_insert_refused_object_is_larger_than_the_whole(len: u64, quota: u64) -> Self {
        Self {
            inner: Diagnostic::CacheInsertRefusedObjectIsLargerThanTheWhole { len, quota },
        }
    }
    /// cache insert failed to stage the object.
    #[must_use]
    pub fn cache_insert_failed_to_stage_the_object_nothing_was(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheInsertFailedToStageTheObjectNothingWas { error },
        }
    }
    /// cache insert refused by the free-space watermark.
    #[must_use]
    pub fn cache_insert_refused_by_the_free_space_watermark(len: u64) -> Self {
        Self {
            inner: Diagnostic::CacheInsertRefusedByTheFreeSpaceWatermark { len },
        }
    }
    /// cache insert failed to create its fanout directory.
    #[must_use]
    pub fn cache_insert_failed_to_create_its_fanout_directory(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheInsertFailedToCreateItsFanoutDirectory { error },
        }
    }
    /// cache insert failed to write the object.
    #[must_use]
    pub fn cache_insert_failed_to_write_the_object(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheInsertFailedToWriteTheObject { error },
        }
    }
    /// cache insert: object too large to index.
    #[must_use]
    pub fn cache_insert_object_too_large_to_index_the_file(len: u64) -> Self {
        Self {
            inner: Diagnostic::CacheInsertObjectTooLargeToIndexTheFile { len },
        }
    }
    /// cache root write skipped: the root path has no volume parent.
    #[must_use]
    pub fn cache_root_write_skipped_the_root_path_has_no(seq: u64) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteSkippedTheRootPathHasNo { seq },
        }
    }
    /// cache root write skipped: the volume directory is not a real directory, so nothing below it describes this cache.
    #[must_use]
    pub fn cache_root_write_skipped_the_volume_directory_is_not(
        seq: u64,
        error: FailureClass,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteSkippedTheVolumeDirectoryIsNot { seq, error },
        }
    }
    /// cache root write skipped: a DIRECTORY occupies the destination, which no write can replace.
    #[must_use]
    pub fn cache_root_write_skipped_a_directory_occupies_the_destination(seq: u64) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteSkippedADirectoryOccupiesTheDestination { seq },
        }
    }
    /// cache root write: a foreign entry sits at the destination.
    #[must_use]
    pub fn cache_root_write_a_foreign_entry_sits_at_the(seq: u64) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteAForeignEntrySitsAtThe { seq },
        }
    }
    /// cache root write skipped: the destination could not be classified, so put-if-absent cannot know whether a root is already there.
    #[must_use]
    pub fn cache_root_write_skipped_the_destination_could_not_be(
        seq: u64,
        error: FailureClass,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteSkippedTheDestinationCouldNotBe { seq, error },
        }
    }
    /// cache root write refused by the free-space watermark.
    #[must_use]
    pub fn cache_root_write_refused_by_the_free_space_watermark(seq: u64, len: u64) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteRefusedByTheFreeSpaceWatermark { seq, len },
        }
    }
    /// cache root write failed to create its volume directory.
    #[must_use]
    pub fn cache_root_write_failed_to_create_its_volume_directory(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteFailedToCreateItsVolumeDirectory { error },
        }
    }
    /// cache root write failed.
    #[must_use]
    pub fn cache_root_write_failed(seq: u64, error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheRootWriteFailed { seq, error },
        }
    }
    /// anchor floor candidate is an absent-class seq.
    #[must_use]
    pub fn anchor_floor_candidate_is_an_absent_class_seq_refusing(candidate: u64) -> Self {
        Self {
            inner: Diagnostic::AnchorFloorCandidateIsAnAbsentClassSeqRefusing { candidate },
        }
    }
    /// hint token is empty (an ETag-less backend).
    #[must_use]
    pub fn hint_token_is_empty_an_etag_less_backend_retaining() -> Self {
        Self {
            inner: Diagnostic::HintTokenIsEmptyAnEtagLessBackendRetaining,
        }
    }
    /// hint is unpersistable (token bytes/length, stamp sign, or absent-class seq).
    #[must_use]
    pub fn hint_is_unpersistable_token_bytes_length_stamp_sign_or() -> Self {
        Self {
            inner: Diagnostic::HintIsUnpersistableTokenBytesLengthStampSignOr,
        }
    }
    /// cache anchor write failed to create its directory.
    #[must_use]
    pub fn cache_anchor_write_failed_to_create_its_directory(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheAnchorWriteFailedToCreateItsDirectory { error },
        }
    }
    /// cache anchor write failed.
    #[must_use]
    pub fn cache_anchor_write_failed(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheAnchorWriteFailed { error },
        }
    }
    /// mount anchor floor candidate is an absent-class seq.
    #[must_use]
    pub fn mount_anchor_floor_candidate_is_an_absent_class_seq(candidate: u64) -> Self {
        Self {
            inner: Diagnostic::MountAnchorFloorCandidateIsAnAbsentClassSeq { candidate },
        }
    }
    /// cache root eviction skipped: the root path has no volume parent.
    #[must_use]
    pub fn cache_root_eviction_skipped_the_root_path_has_no(seq: u64) -> Self {
        Self {
            inner: Diagnostic::CacheRootEvictionSkippedTheRootPathHasNo { seq },
        }
    }
    /// cache root eviction skipped: the volume directory is not a real directory.
    #[must_use]
    pub fn cache_root_eviction_skipped_the_volume_directory_is_not(
        seq: u64,
        error: FailureClass,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheRootEvictionSkippedTheVolumeDirectoryIsNot { seq, error },
        }
    }
    /// cache root eviction failed to remove the file.
    #[must_use]
    pub fn cache_root_eviction_failed_to_remove_the_file(seq: u64, error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheRootEvictionFailedToRemoveTheFile { seq, error },
        }
    }
    /// cache guard present at open: the previous writer did not close cleanly.
    #[must_use]
    pub fn cache_guard_present_at_open_the_previous_writer_did() -> Self {
        Self {
            inner: Diagnostic::CacheGuardPresentAtOpenThePreviousWriterDid,
        }
    }
    /// cache lock held by another process.
    #[must_use]
    pub fn cache_lock_held_by_another_process_opening_read_only() -> Self {
        Self {
            inner: Diagnostic::CacheLockHeldByAnotherProcessOpeningReadOnly,
        }
    }
    /// cache read refused: the object fanout is not a real directory, so nothing below it belongs to this cache.
    #[must_use]
    pub fn cache_read_refused_the_object_fanout_is_not_a(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheReadRefusedTheObjectFanoutIsNotA { error },
        }
    }
    /// cache object failed hash verification.
    #[must_use]
    pub fn cache_object_failed_hash_verification_unlinking_and_evicting() -> Self {
        Self {
            inner: Diagnostic::CacheObjectFailedHashVerificationUnlinkingAndEvicting,
        }
    }
    /// cache object exceeds the size bound.
    #[must_use]
    pub fn cache_object_exceeds_the_size_bound_treating_it_as(len: u64) -> Self {
        Self {
            inner: Diagnostic::CacheObjectExceedsTheSizeBoundTreatingItAs { len },
        }
    }
    /// cached root exceeds the size bound.
    #[must_use]
    pub fn cached_root_exceeds_the_size_bound_treating_it_as(seq: u64, len: u64) -> Self {
        Self {
            inner: Diagnostic::CachedRootExceedsTheSizeBoundTreatingItAs { seq, len },
        }
    }
    /// cache maintain: journal flush failed.
    #[must_use]
    pub fn cache_maintain_journal_flush_failed_skipping_compaction_this_cycle(
        error: FailureClass,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheMaintainJournalFlushFailedSkippingCompactionThisCycle { error },
        }
    }
    /// cache maintain: compaction failed.
    #[must_use]
    pub fn cache_maintain_compaction_failed(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheMaintainCompactionFailed { error },
        }
    }
    /// set in the environment and ignored: the direct-S3 route connects directly.
    #[must_use]
    pub fn set_in_the_environment_and_ignored_the_direct_s3(variable: ProxyVariableName) -> Self {
        Self {
            inner: Diagnostic::SetInTheEnvironmentAndIgnoredTheDirectS3 { variable },
        }
    }
    /// wire-snapshot publish: the temp file could not be removed after a successful `hard_link`.
    #[must_use]
    pub fn wire_snapshot_publish_the_temp_file_could_not_be(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::WireSnapshotPublishTheTempFileCouldNotBe { error },
        }
    }
    /// a cache dir is present, but a transport-down degraded serve requires the volume's root key to verify what it returns.
    #[must_use]
    pub fn a_cache_dir_is_present_but_a_transport_down() -> Self {
        Self {
            inner: Diagnostic::ACacheDirIsPresentButATransportDown,
        }
    }
    /// the transport gave no answer.
    #[must_use]
    pub fn the_transport_gave_no_answer_falling_back_to_the(seq: u64, age: Age) -> Self {
        Self {
            inner: Diagnostic::TheTransportGaveNoAnswerFallingBackToThe { seq, age },
        }
    }
    /// store: an object path has no fanout parent.
    #[must_use]
    pub fn store_an_object_path_has_no_fanout_parent_reporting() -> Self {
        Self {
            inner: Diagnostic::StoreAnObjectPathHasNoFanoutParentReporting,
        }
    }
    /// store: an object fanout is not a real directory.
    #[must_use]
    pub fn store_an_object_fanout_is_not_a_real_directory(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::StoreAnObjectFanoutIsNotARealDirectory { error },
        }
    }
    /// store: an object leaf is not a regular file.
    #[must_use]
    pub fn store_an_object_leaf_is_not_a_regular_file() -> Self {
        Self {
            inner: Diagnostic::StoreAnObjectLeafIsNotARegularFile,
        }
    }
    /// store: an object leaf could not be classified.
    #[must_use]
    pub fn store_an_object_leaf_could_not_be_classified_reporting(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::StoreAnObjectLeafCouldNotBeClassifiedReporting { error },
        }
    }
    /// store put: the object fanout is not a real directory.
    #[must_use]
    pub fn store_put_the_object_fanout_is_not_a_real(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::StorePutTheObjectFanoutIsNotAReal { error },
        }
    }
    /// store put: an object leaf is not a regular file.
    #[must_use]
    pub fn store_put_an_object_leaf_is_not_a_regular() -> Self {
        Self {
            inner: Diagnostic::StorePutAnObjectLeafIsNotARegular,
        }
    }
    /// store get: the object fanout is not a real directory.
    #[must_use]
    pub fn store_get_the_object_fanout_is_not_a_real(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::StoreGetTheObjectFanoutIsNotAReal { error },
        }
    }
    /// store established open: txn/ is not a real directory (symlink or other).
    #[must_use]
    pub fn store_established_open_txn_is_not_a_real_directory() -> Self {
        Self {
            inner: Diagnostic::StoreEstablishedOpenTxnIsNotARealDirectory,
        }
    }
    /// store established open: an orphaned txn/ entry could not be removed.
    #[must_use]
    pub fn store_established_open_an_orphaned_txn_entry_could_not(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::StoreEstablishedOpenAnOrphanedTxnEntryCouldNot { error },
        }
    }
    /// store established open: swept orphaned txn/ staging files.
    #[must_use]
    pub fn store_established_open_swept_orphaned_txn_staging_files(
        swept: u64,
        skipped: u64,
    ) -> Self {
        Self {
            inner: Diagnostic::StoreEstablishedOpenSweptOrphanedTxnStagingFiles { swept, skipped },
        }
    }
    /// seam attempt failed.
    #[must_use]
    pub fn seam_attempt_failed_retrying_once(
        seam: HttpSeam,
        class: WireRetryClass,
        error: FailureClass,
    ) -> Self {
        Self {
            inner: Diagnostic::SeamAttemptFailedRetryingOnce { seam, class, error },
        }
    }
    /// Coordination failed during writable shutdown.
    #[must_use]
    pub fn writable_shutdown_coordination_failed(
        coordination: FailureClass,
        cache_closed: bool,
    ) -> Self {
        Self {
            inner: Diagnostic::WritableShutdownCoordinationFailed {
                coordination,
                cache_closed,
            },
        }
    }
    /// mount session shutdown: closing the cache failed.
    #[must_use]
    pub fn mount_session_shutdown_closing_the_cache_failed_the_crash(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::MountSessionShutdownClosingTheCacheFailedTheCrash { error },
        }
    }
    /// mount teardown: read-path counters for the read phase.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "the read-path instrument preserves its complete named counter tuple"
    )]
    pub fn mount_teardown_read_path_counters_for_the_read_phase(
        via: TeardownCause,
        inflight_high_water: u64,
        window: u64,
        origin_requests: u64,
        origin_sheds: u64,
        origin_requests_total: u64,
        wants_bin: u64,
        wants_meta: u64,
        wants_total: u64,
        cache_hits: u64,
        cache_misses: u64,
    ) -> Self {
        Self {
            inner: Diagnostic::MountTeardownReadPathCountersForTheReadPhase {
                via,
                inflight_high_water,
                window,
                origin_requests,
                origin_sheds,
                origin_requests_total,
                wants_bin,
                wants_meta,
                wants_total,
                cache_hits,
                cache_misses,
            },
        }
    }
    /// mount session drop: closing the cache failed.
    #[must_use]
    pub fn mount_session_drop_closing_the_cache_failed_the_crash(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::MountSessionDropClosingTheCacheFailedTheCrash { error },
        }
    }
    /// cache anchor file exceeds the size bound.
    #[must_use]
    pub fn cache_anchor_file_exceeds_the_size_bound_treating_it(len: u64) -> Self {
        Self {
            inner: Diagnostic::CacheAnchorFileExceedsTheSizeBoundTreatingIt { len },
        }
    }
    /// cache anchor file failed strict parse.
    #[must_use]
    pub fn cache_anchor_file_failed_strict_parse_treating_it_as() -> Self {
        Self {
            inner: Diagnostic::CacheAnchorFileFailedStrictParseTreatingItAs,
        }
    }
    /// mount anchor file carries a hint line, which its grammar forbids.
    #[must_use]
    pub fn mount_anchor_file_carries_a_hint_line_which_its() -> Self {
        Self {
            inner: Diagnostic::MountAnchorFileCarriesAHintLineWhichIts,
        }
    }
    /// refusing to unlink an object path that has no fanout parent.
    #[must_use]
    pub fn refusing_to_unlink_an_object_path_that_has_no(context: CacheAction) -> Self {
        Self {
            inner: Diagnostic::RefusingToUnlinkAnObjectPathThatHasNo { context },
        }
    }
    /// refusing to unlink an object through a foreign fanout directory.
    #[must_use]
    pub fn refusing_to_unlink_an_object_through_a_foreign_fanout(context: CacheAction) -> Self {
        Self {
            inner: Diagnostic::RefusingToUnlinkAnObjectThroughAForeignFanout { context },
        }
    }
    /// refusing to unlink an object under a fanout that could not be classified.
    #[must_use]
    pub fn refusing_to_unlink_an_object_under_a_fanout_that(
        error: FailureClass,
        context: CacheAction,
    ) -> Self {
        Self {
            inner: Diagnostic::RefusingToUnlinkAnObjectUnderAFanoutThat { error, context },
        }
    }
    /// an object leaf could not be unlinked.
    #[must_use]
    pub fn an_object_leaf_could_not_be_unlinked_it_stays(
        error: FailureClass,
        context: CacheAction,
    ) -> Self {
        Self {
            inner: Diagnostic::AnObjectLeafCouldNotBeUnlinkedItStays { error, context },
        }
    }
    /// cold rebuild walk: skipping a non-digest file name.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_a_non_digest_file_name() -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingANonDigestFileName,
        }
    }
    /// cold rebuild walk: skipping a file whose name does not match its fanout directory.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_a_file_whose_name_does() -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingAFileWhoseNameDoes,
        }
    }
    /// cold rebuild walk: skipping an entry whose metadata could not be read.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_an_entry_whose_metadata_could(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingAnEntryWhoseMetadataCould { error },
        }
    }
    /// cold rebuild walk: skipping a non-regular-file entry.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_a_non_regular_file_entry() -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingANonRegularFileEntry,
        }
    }
    /// cold rebuild walk: skipping an oversized foreign file.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_an_oversized_foreign_file(len: u64) -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingAnOversizedForeignFile { len },
        }
    }
    /// cold rebuild walk: skipping a size that cannot fit the index format.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_a_size_that_cannot_fit(len: u64) -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingASizeThatCannotFit { len },
        }
    }
    /// cold rebuild walk: skipping a non-fanout entry under objects/.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_a_non_fanout_entry_under() -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingANonFanoutEntryUnder,
        }
    }
    /// cold rebuild walk: skipping a fanout entry whose type could not be read.
    #[must_use]
    pub fn cold_rebuild_walk_skipping_a_fanout_entry_whose_type(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingAFanoutEntryWhoseType { error },
        }
    }
    /// cold rebuild walk: skipping a non-directory entry under objects/ (a symlink to one included).
    #[must_use]
    pub fn cold_rebuild_walk_skipping_a_non_directory_entry_under() -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSkippingANonDirectoryEntryUnder,
        }
    }
    /// cold rebuild walk: the adoption cap was reached.
    #[must_use]
    pub fn cold_rebuild_walk_the_adoption_cap_was_reached_the(
        dropped: u64,
        adoption_cap: u64,
    ) -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkTheAdoptionCapWasReachedThe {
                dropped,
                adoption_cap,
            },
        }
    }
    /// cold rebuild walk: snapshot rewrite and journal reset refused together by the free-space watermark.
    #[must_use]
    pub fn cold_rebuild_walk_snapshot_rewrite_and_journal_reset_refused() -> Self {
        Self {
            inner: Diagnostic::ColdRebuildWalkSnapshotRewriteAndJournalResetRefused,
        }
    }
    /// cache index file exceeds the size bound.
    #[must_use]
    pub fn cache_index_file_exceeds_the_size_bound_treating_it(
        len: u64,
        what: IndexFileKind,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheIndexFileExceedsTheSizeBoundTreatingIt { len, what },
        }
    }
    /// cache index file grew past the size bound between the stat and the read.
    #[must_use]
    pub fn cache_index_file_grew_past_the_size_bound_between(
        len: u64,
        what: IndexFileKind,
    ) -> Self {
        Self {
            inner: Diagnostic::CacheIndexFileGrewPastTheSizeBoundBetween { len, what },
        }
    }
    /// cache snapshot present with no journal: a creation-crash window from the last compaction.
    #[must_use]
    pub fn cache_snapshot_present_with_no_journal_a_creation_crash() -> Self {
        Self {
            inner: Diagnostic::CacheSnapshotPresentWithNoJournalACreationCrash,
        }
    }
    /// cache writer open: an orphaned txn/ entry could not be removed.
    #[must_use]
    pub fn cache_writer_open_an_orphaned_txn_entry_could_not(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::CacheWriterOpenAnOrphanedTxnEntryCouldNot { error },
        }
    }
    /// cache writer open: swept orphaned txn/ staging files.
    #[must_use]
    pub fn cache_writer_open_swept_orphaned_txn_staging_files(swept: u64, skipped: u64) -> Self {
        Self {
            inner: Diagnostic::CacheWriterOpenSweptOrphanedTxnStagingFiles { swept, skipped },
        }
    }
    /// structure walk.
    #[must_use]
    pub fn structure_walk(
        round: u64,
        outcome: WalkOutcome,
        needs: u64,
        hints: u64,
        admits: u64,
        pool_len: u64,
        pool_used: u64,
    ) -> Self {
        Self {
            inner: Diagnostic::StructureWalk {
                round,
                outcome,
                needs,
                hints,
                admits,
                pool_len,
                pool_used,
            },
        }
    }
    /// gran mount: unmount failed.
    #[must_use]
    pub fn gran_mount_unmount_failed_falling_back_to_a_lazy(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::GranMountUnmountFailedFallingBackToALazy { error },
        }
    }
    /// gran mount: the mount was lazily detached (`MNT_DETACH`) after the plain unmount was refused.
    #[must_use]
    pub fn gran_mount_the_mount_was_lazily_detached_mnt_detach() -> Self {
        Self {
            inner: Diagnostic::GranMountTheMountWasLazilyDetachedMntDetach,
        }
    }
    /// gran mount: both the plain unmount and the `MNT_DETACH` fallback failed.
    #[must_use]
    pub fn gran_mount_both_the_plain_unmount_and_the_mnt(
        unmount_error: FailureClass,
        detach_error: FailureClass,
    ) -> Self {
        Self {
            inner: Diagnostic::GranMountBothThePlainUnmountAndTheMnt {
                unmount_error,
                detach_error,
            },
        }
    }
    /// gran mount: a signal-readiness report never arrived before `Session::new` (the producer thread ended before reporting, most likely a panic).
    #[must_use]
    pub fn gran_mount_a_signal_readiness_report_never_arrived_before() -> Self {
        Self {
            inner: Diagnostic::GranMountASignalReadinessReportNeverArrivedBefore,
        }
    }
    /// gran mount: a cached root and the wire root disagreed at open.
    #[must_use]
    pub fn gran_mount_a_cached_root_and_the_wire_root() -> Self {
        Self {
            inner: Diagnostic::GranMountACachedRootAndTheWireRoot,
        }
    }
    /// gran mount: could not build a runtime for SIGINT handling.
    #[must_use]
    pub fn gran_mount_could_not_build_a_runtime_for_sigint() -> Self {
        Self {
            inner: Diagnostic::GranMountCouldNotBuildARuntimeForSigint,
        }
    }
    /// gran mount: could not register a SIGINT handler.
    #[must_use]
    pub fn gran_mount_could_not_register_a_sigint_handler_this(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::GranMountCouldNotRegisterASigintHandlerThis { error },
        }
    }
    /// gran mount: the SIGINT stream ended without delivering a signal.
    #[must_use]
    pub fn gran_mount_the_sigint_stream_ended_without_delivering_a() -> Self {
        Self {
            inner: Diagnostic::GranMountTheSigintStreamEndedWithoutDeliveringA,
        }
    }
    /// gran mount: could not build a runtime for SIGTERM handling.
    #[must_use]
    pub fn gran_mount_could_not_build_a_runtime_for_sigterm() -> Self {
        Self {
            inner: Diagnostic::GranMountCouldNotBuildARuntimeForSigterm,
        }
    }
    /// gran mount: could not register a SIGTERM handler.
    #[must_use]
    pub fn gran_mount_could_not_register_a_sigterm_handler_this() -> Self {
        Self {
            inner: Diagnostic::GranMountCouldNotRegisterASigtermHandlerThis,
        }
    }
    /// gran mount: detach target unavailable.
    #[must_use]
    pub fn gran_mount_detach_target_unavailable_lazy_detach_cannot_be(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::GranMountDetachTargetUnavailableLazyDetachCannotBe { error },
        }
    }
    /// gran mount: received signal, unmounting.
    #[must_use]
    pub fn gran_mount_received_signal_unmounting(signal: SignalKind) -> Self {
        Self {
            inner: Diagnostic::GranMountReceivedSignalUnmounting { signal },
        }
    }
    /// gran mount: the FUSE session ended with an error.
    #[must_use]
    pub fn gran_mount_the_fuse_session_ended_with_an_error(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::GranMountTheFuseSessionEndedWithAnError { error },
        }
    }
    /// gran mount: stopped waiting for the FUSE session to end after its unmount
    #[must_use]
    pub fn gran_mount_the_fuse_session_did_not_end_after_its_unmount(
        listed: MountListing,
        connection: FuseConnection,
    ) -> Self {
        Self {
            inner: Diagnostic::GranMountTheFuseSessionDidNotEndAfterItsUnmount {
                listed,
                connection,
            },
        }
    }
    /// gran mount: the FUSE session thread panicked.
    #[must_use]
    pub fn gran_mount_the_fuse_session_thread_panicked() -> Self {
        Self {
            inner: Diagnostic::GranMountTheFuseSessionThreadPanicked,
        }
    }
    /// gran mount: the mount's identity could not be captured, so a session
    /// end that races its unmount cannot be told from a failure.
    #[must_use]
    pub fn gran_mount_could_not_capture_the_mount_identity(error: FailureClass) -> Self {
        Self {
            inner: Diagnostic::GranMountCouldNotCaptureTheMountIdentity { error },
        }
    }
    /// gran mount: the FUSE session ended `ECONNABORTED` racing its unmount's
    /// teardown, with the mount gone: a clean end, recorded for tracing.
    #[must_use]
    pub fn gran_mount_the_fuse_session_ended_econnaborted_racing_its_unmount() -> Self {
        Self {
            inner: Diagnostic::GranMountTheFuseSessionEndedEconnabortedRacingItsUnmount,
        }
    }
    /// sync: the registration timing sample was unavailable; the registration itself did not fail.
    #[must_use]
    pub fn sync_registration_timing_sample_unavailable() -> Self {
        Self {
            inner: Diagnostic::SyncRegistrationTimingSampleUnavailable,
        }
    }
}
impl Diagnostic {
    /// The registered static callsite of this diagnostic, without building its values.
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive projection audits every diagnostic callsite in one closed match"
    )]
    pub(super) fn meta(&self) -> &'static Metadata<'static> {
        match self {
            Self::CacheJournalIsBrokenAfterAFailedReopenMid => {
                &CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_META
            }
            Self::CacheJournalFlushFailedRecordsStayBuffered { .. } => {
                &CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_META
            }
            Self::CacheCompactionFailedJournalLeftUncompacted { .. } => {
                &CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_META
            }
            Self::CacheJournalBufferExceededItsCapUnderSustainedFree { .. } => {
                &CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_META
            }
            Self::CacheJournalFlushRefusedByTheFreeSpaceWatermark => {
                &CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META
            }
            Self::CacheCompactionRefusedByTheFreeSpaceWatermarkSnapshot => {
                &CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_META
            }
            Self::CacheCompactionRefusedByTheFreeSpaceWatermarkBefore => {
                &CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_META
            }
            Self::CacheEvictionFoundNothingLeftToEvictTheInsert { .. } => {
                &CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_META
            }
            Self::CacheInsertTheObjectPathHasNoFanoutParent => {
                &CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_META
            }
            Self::CacheInsertRefusedTheObjectFanoutIsNotA { .. } => {
                &CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META
            }
            Self::CacheInsertDeclinedADirectoryOccupiesTheObjectPath => {
                &CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_META
            }
            Self::CacheInsertAForeignEntrySitsAtTheObject => {
                &CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_META
            }
            Self::CacheInsertFailedToInspectTheObjectPath { .. } => {
                &CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_META
            }
            Self::CacheInsertRefusedObjectIsLargerThanTheWhole { .. } => {
                &CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_META
            }
            Self::CacheInsertFailedToStageTheObjectNothingWas { .. } => {
                &CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_META
            }
            Self::CacheInsertRefusedByTheFreeSpaceWatermark { .. } => {
                &CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META
            }
            Self::CacheInsertFailedToCreateItsFanoutDirectory { .. } => {
                &CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_META
            }
            Self::CacheInsertFailedToWriteTheObject { .. } => {
                &CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_META
            }
            Self::CacheInsertObjectTooLargeToIndexTheFile { .. } => {
                &CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_META
            }
            Self::CacheRootWriteSkippedTheRootPathHasNo { .. } => {
                &CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_META
            }
            Self::CacheRootWriteSkippedTheVolumeDirectoryIsNot { .. } => {
                &CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META
            }
            Self::CacheRootWriteSkippedADirectoryOccupiesTheDestination { .. } => {
                &CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_META
            }
            Self::CacheRootWriteAForeignEntrySitsAtThe { .. } => {
                &CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_META
            }
            Self::CacheRootWriteSkippedTheDestinationCouldNotBe { .. } => {
                &CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_META
            }
            Self::CacheRootWriteRefusedByTheFreeSpaceWatermark { .. } => {
                &CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META
            }
            Self::CacheRootWriteFailedToCreateItsVolumeDirectory { .. } => {
                &CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_META
            }
            Self::CacheRootWriteFailed { .. } => &CACHE_ROOT_WRITE_FAILED_META,
            Self::AnchorFloorCandidateIsAnAbsentClassSeqRefusing { .. } => {
                &ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_META
            }
            Self::HintTokenIsEmptyAnEtagLessBackendRetaining => {
                &HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_META
            }
            Self::HintIsUnpersistableTokenBytesLengthStampSignOr => {
                &HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_META
            }
            Self::CacheAnchorWriteFailedToCreateItsDirectory { .. } => {
                &CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_META
            }
            Self::CacheAnchorWriteFailed { .. } => &CACHE_ANCHOR_WRITE_FAILED_META,
            Self::MountAnchorFloorCandidateIsAnAbsentClassSeq { .. } => {
                &MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_META
            }
            Self::CacheRootEvictionSkippedTheRootPathHasNo { .. } => {
                &CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_META
            }
            Self::CacheRootEvictionSkippedTheVolumeDirectoryIsNot { .. } => {
                &CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META
            }
            Self::CacheRootEvictionFailedToRemoveTheFile { .. } => {
                &CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_META
            }
            Self::CacheGuardPresentAtOpenThePreviousWriterDid => {
                &CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_META
            }
            Self::CacheLockHeldByAnotherProcessOpeningReadOnly => {
                &CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_META
            }
            Self::CacheReadRefusedTheObjectFanoutIsNotA { .. } => {
                &CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META
            }
            Self::CacheObjectFailedHashVerificationUnlinkingAndEvicting => {
                &CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_META
            }
            Self::CacheObjectExceedsTheSizeBoundTreatingItAs { .. } => {
                &CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META
            }
            Self::CachedRootExceedsTheSizeBoundTreatingItAs { .. } => {
                &CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META
            }
            Self::CacheMaintainJournalFlushFailedSkippingCompactionThisCycle { .. } => {
                &CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_META
            }
            Self::CacheMaintainCompactionFailed { .. } => &CACHE_MAINTAIN_COMPACTION_FAILED_META,
            Self::SetInTheEnvironmentAndIgnoredTheDirectS3 { .. } => {
                &SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_META
            }
            Self::WireSnapshotPublishTheTempFileCouldNotBe { .. } => {
                &WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_META
            }
            Self::ACacheDirIsPresentButATransportDown => {
                &A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_META
            }
            Self::TheTransportGaveNoAnswerFallingBackToThe { .. } => {
                &THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_META
            }
            Self::StoreAnObjectPathHasNoFanoutParentReporting => {
                &STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_META
            }
            Self::StoreAnObjectFanoutIsNotARealDirectory { .. } => {
                &STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_META
            }
            Self::StoreAnObjectLeafIsNotARegularFile => {
                &STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_META
            }
            Self::StoreAnObjectLeafCouldNotBeClassifiedReporting { .. } => {
                &STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_META
            }
            Self::StorePutTheObjectFanoutIsNotAReal { .. } => {
                &STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META
            }
            Self::StorePutAnObjectLeafIsNotARegular => {
                &STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_META
            }
            Self::StoreGetTheObjectFanoutIsNotAReal { .. } => {
                &STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META
            }
            Self::StoreEstablishedOpenTxnIsNotARealDirectory => {
                &STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_META
            }
            Self::StoreEstablishedOpenAnOrphanedTxnEntryCouldNot { .. } => {
                &STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META
            }
            Self::StoreEstablishedOpenSweptOrphanedTxnStagingFiles { .. } => {
                &STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META
            }
            Self::SeamAttemptFailedRetryingOnce { .. } => &SEAM_ATTEMPT_FAILED_RETRYING_ONCE_META,
            Self::WritableShutdownCoordinationFailed { .. } => {
                &WRITABLE_SHUTDOWN_COORDINATION_FAILED_META
            }
            Self::MountSessionShutdownClosingTheCacheFailedTheCrash { .. } => {
                &MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_META
            }
            Self::MountTeardownReadPathCountersForTheReadPhase { .. } => {
                &MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_META
            }
            Self::MountSessionDropClosingTheCacheFailedTheCrash { .. } => {
                &MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_META
            }
            Self::CacheAnchorFileExceedsTheSizeBoundTreatingIt { .. } => {
                &CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META
            }
            Self::CacheAnchorFileFailedStrictParseTreatingItAs => {
                &CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_META
            }
            Self::MountAnchorFileCarriesAHintLineWhichIts => {
                &MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_META
            }
            Self::RefusingToUnlinkAnObjectPathThatHasNo { .. } => {
                &REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_META
            }
            Self::RefusingToUnlinkAnObjectThroughAForeignFanout { .. } => {
                &REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_META
            }
            Self::RefusingToUnlinkAnObjectUnderAFanoutThat { .. } => {
                &REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_META
            }
            Self::AnObjectLeafCouldNotBeUnlinkedItStays { .. } => {
                &AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_META
            }
            Self::ColdRebuildWalkSkippingANonDigestFileName => {
                &COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_META
            }
            Self::ColdRebuildWalkSkippingAFileWhoseNameDoes => {
                &COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_META
            }
            Self::ColdRebuildWalkSkippingAnEntryWhoseMetadataCould { .. } => {
                &COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_META
            }
            Self::ColdRebuildWalkSkippingANonRegularFileEntry => {
                &COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_META
            }
            Self::ColdRebuildWalkSkippingAnOversizedForeignFile { .. } => {
                &COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_META
            }
            Self::ColdRebuildWalkSkippingASizeThatCannotFit { .. } => {
                &COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_META
            }
            Self::ColdRebuildWalkSkippingANonFanoutEntryUnder => {
                &COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_META
            }
            Self::ColdRebuildWalkSkippingAFanoutEntryWhoseType { .. } => {
                &COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_META
            }
            Self::ColdRebuildWalkSkippingANonDirectoryEntryUnder => {
                &COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_META
            }
            Self::ColdRebuildWalkTheAdoptionCapWasReachedThe { .. } => {
                &COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_META
            }
            Self::ColdRebuildWalkSnapshotRewriteAndJournalResetRefused => {
                &COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_META
            }
            Self::CacheIndexFileExceedsTheSizeBoundTreatingIt { .. } => {
                &CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META
            }
            Self::CacheIndexFileGrewPastTheSizeBoundBetween { .. } => {
                &CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_META
            }
            Self::CacheSnapshotPresentWithNoJournalACreationCrash => {
                &CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_META
            }
            Self::CacheWriterOpenAnOrphanedTxnEntryCouldNot { .. } => {
                &CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META
            }
            Self::CacheWriterOpenSweptOrphanedTxnStagingFiles { .. } => {
                &CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META
            }
            Self::StructureWalk { .. } => &STRUCTURE_WALK_META,
            Self::GranMountUnmountFailedFallingBackToALazy { .. } => {
                &GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_META
            }
            Self::GranMountTheMountWasLazilyDetachedMntDetach => {
                &GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_META
            }
            Self::GranMountBothThePlainUnmountAndTheMnt { .. } => {
                &GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_META
            }
            Self::GranMountASignalReadinessReportNeverArrivedBefore => {
                &GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_META
            }
            Self::GranMountACachedRootAndTheWireRoot => {
                &GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_META
            }
            Self::GranMountCouldNotBuildARuntimeForSigint => {
                &GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_META
            }
            Self::GranMountCouldNotRegisterASigintHandlerThis { .. } => {
                &GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_META
            }
            Self::GranMountTheSigintStreamEndedWithoutDeliveringA => {
                &GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_META
            }
            Self::GranMountCouldNotBuildARuntimeForSigterm => {
                &GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_META
            }
            Self::GranMountCouldNotRegisterASigtermHandlerThis => {
                &GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_META
            }
            Self::GranMountDetachTargetUnavailableLazyDetachCannotBe { .. } => {
                &GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_META
            }
            Self::GranMountReceivedSignalUnmounting { .. } => {
                &GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_META
            }
            Self::GranMountTheFuseSessionEndedWithAnError { .. } => {
                &GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_META
            }
            Self::GranMountTheFuseSessionDidNotEndAfterItsUnmount { .. } => {
                &GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_META
            }
            Self::GranMountTheFuseSessionThreadPanicked => {
                &GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_META
            }
            Self::GranMountCouldNotCaptureTheMountIdentity { .. } => {
                &GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_META
            }
            Self::GranMountTheFuseSessionEndedEconnabortedRacingItsUnmount => {
                &GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_META
            }
            Self::SyncRegistrationTimingSampleUnavailable => {
                &SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_META
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive projection audits every diagnostic field in one closed match"
    )]
    pub(super) fn fields(&self) -> (&'static Metadata<'static>, Vec<Scalar>) {
        match self {
            Self::CacheJournalIsBrokenAfterAFailedReopenMid => (
                &CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_META,
                vec![
                    Scalar::text(CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_META.name()),
                    Scalar::text(
                        "cache journal is broken after a failed reopen mid-session; refusing to record further journal entries into the orphaned file. The in-memory index stays correct for this session and the objects on disk stay hash-verifiable; the next Cache::open will rebuild the index from the snapshot and lose journal records written since the failure.",
                    ),
                ],
            ),
            Self::CacheJournalFlushFailedRecordsStayBuffered { error } => (
                &CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_META,
                vec![
                    Scalar::text(CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_META.name()),
                    Scalar::text("cache journal flush failed; records stay buffered"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheCompactionFailedJournalLeftUncompacted { error } => (
                &CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_META,
                vec![
                    Scalar::text(CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_META.name()),
                    Scalar::text("cache compaction failed; journal left uncompacted"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheJournalBufferExceededItsCapUnderSustainedFree {
                dropped_records,
                dropped_bytes,
            } => (
                &CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_META,
                vec![
                    Scalar::text(
                        CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_META.name(),
                    ),
                    Scalar::text(
                        "cache journal buffer exceeded its cap under sustained free-space refusal; dropping buffered records. The OBJECTS on disk stay correct and hash-verifiable; the INDEX now under-counts them, and nothing repairs that automatically — ordinary reads do not adopt a healthy unindexed object, and `gran verify` reports the divergence without fixing it. A cold rebuild (or removing the cache directory) is what resolves it.",
                    ),
                    Scalar::Number(*dropped_records),
                    Scalar::Number(*dropped_bytes),
                ],
            ),
            Self::CacheJournalFlushRefusedByTheFreeSpaceWatermark => (
                &CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
                vec![
                    Scalar::text(
                        CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META.name(),
                    ),
                    Scalar::text(
                        "cache journal flush refused by the free-space watermark; records stay buffered",
                    ),
                ],
            ),
            Self::CacheCompactionRefusedByTheFreeSpaceWatermarkSnapshot => (
                &CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_META,
                vec![
                    Scalar::text(
                        CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_META.name(),
                    ),
                    Scalar::text(
                        "cache compaction refused by the free-space watermark; snapshot left stale",
                    ),
                ],
            ),
            Self::CacheCompactionRefusedByTheFreeSpaceWatermarkBefore => (
                &CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_META,
                vec![
                    Scalar::text(
                        CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_META.name(),
                    ),
                    Scalar::text(
                        "cache compaction refused by the free-space watermark before truncating the journal; the snapshot already advanced, so the next open safely replays a stale-but-idempotent journal",
                    ),
                ],
            ),
            Self::CacheEvictionFoundNothingLeftToEvictTheInsert { total_bytes, quota } => (
                &CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_META,
                vec![
                    Scalar::text(CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_META.name()),
                    Scalar::text(
                        "cache eviction found nothing left to evict; the insert that needed the room is declined rather than writing over quota",
                    ),
                    Scalar::Number(*total_bytes),
                    Scalar::Number(*quota),
                ],
            ),
            Self::CacheInsertTheObjectPathHasNoFanoutParent => (
                &CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_META,
                vec![
                    Scalar::text(CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_META.name()),
                    Scalar::text("cache insert: the object path has no fanout parent"),
                    Scalar::text("<object>"),
                ],
            ),
            Self::CacheInsertRefusedTheObjectFanoutIsNotA { error } => (
                &CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META,
                vec![
                    Scalar::text(CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META.name()),
                    Scalar::text("cache insert refused: the object fanout is not a real directory"),
                    Scalar::text("<object>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheInsertDeclinedADirectoryOccupiesTheObjectPath => (
                &CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_META,
                vec![
                    Scalar::text(
                        CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_META.name(),
                    ),
                    Scalar::text(
                        "cache insert declined: a DIRECTORY occupies the object path, which no write can replace; nothing is evicted and nothing is written",
                    ),
                    Scalar::text("<object>"),
                    Scalar::text("<file>"),
                ],
            ),
            Self::CacheInsertAForeignEntrySitsAtTheObject => (
                &CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_META,
                vec![
                    Scalar::text(CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_META.name()),
                    Scalar::text(
                        "cache insert: a foreign entry sits at the object path; if this write goes through, the atomic rename replaces that NAME (never what it points at) — the size, eviction and watermark gates below can still decline it",
                    ),
                    Scalar::text("<object>"),
                    Scalar::text("<file>"),
                ],
            ),
            Self::CacheInsertFailedToInspectTheObjectPath { error } => (
                &CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_META,
                vec![
                    Scalar::text(CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_META.name()),
                    Scalar::text("cache insert failed to inspect the object path"),
                    Scalar::text("<object>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheInsertRefusedObjectIsLargerThanTheWhole { len, quota } => (
                &CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_META,
                vec![
                    Scalar::text(CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_META.name()),
                    Scalar::text("cache insert refused: object is larger than the whole quota"),
                    Scalar::text("<object>"),
                    Scalar::Number(*len),
                    Scalar::Number(*quota),
                ],
            ),
            Self::CacheInsertFailedToStageTheObjectNothingWas { error } => (
                &CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_META,
                vec![
                    Scalar::text(CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_META.name()),
                    Scalar::text(
                        "cache insert failed to stage the object; nothing was evicted, and any staged bytes were removed or left under txn/ for the next sweep",
                    ),
                    Scalar::text("<object>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheInsertRefusedByTheFreeSpaceWatermark { len } => (
                &CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
                vec![
                    Scalar::text(CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META.name()),
                    Scalar::text("cache insert refused by the free-space watermark"),
                    Scalar::text("<object>"),
                    Scalar::Number(*len),
                ],
            ),
            Self::CacheInsertFailedToCreateItsFanoutDirectory { error } => (
                &CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_META,
                vec![
                    Scalar::text(CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_META.name()),
                    Scalar::text("cache insert failed to create its fanout directory"),
                    Scalar::text("<object>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheInsertFailedToWriteTheObject { error } => (
                &CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_META,
                vec![
                    Scalar::text(CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_META.name()),
                    Scalar::text("cache insert failed to write the object"),
                    Scalar::text("<object>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheInsertObjectTooLargeToIndexTheFile { len } => (
                &CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_META,
                vec![
                    Scalar::text(CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_META.name()),
                    Scalar::text(
                        "cache insert: object too large to index; the file is cached but stays UNINDEXED (the single-object crash window's own shape; gran verify REPORTS it, and nothing re-indexes it short of a cold rebuild)",
                    ),
                    Scalar::text("<object>"),
                    Scalar::Number(*len),
                ],
            ),
            Self::CacheRootWriteSkippedTheRootPathHasNo { seq } => (
                &CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_META,
                vec![
                    Scalar::text(CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_META.name()),
                    Scalar::text("cache root write skipped: the root path has no volume parent"),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                ],
            ),
            Self::CacheRootWriteSkippedTheVolumeDirectoryIsNot { seq, error } => (
                &CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META,
                vec![
                    Scalar::text(CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META.name()),
                    Scalar::text(
                        "cache root write skipped: the volume directory is not a real directory, so nothing below it describes this cache",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheRootWriteSkippedADirectoryOccupiesTheDestination { seq } => (
                &CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_META,
                vec![
                    Scalar::text(
                        CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_META.name(),
                    ),
                    Scalar::text(
                        "cache root write skipped: a DIRECTORY occupies the destination, which no write can replace",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::text("<file>"),
                ],
            ),
            Self::CacheRootWriteAForeignEntrySitsAtThe { seq } => (
                &CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_META,
                vec![
                    Scalar::text(CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_META.name()),
                    Scalar::text(
                        "cache root write: a foreign entry sits at the destination; if this write goes through, the atomic rename replaces that NAME (never what it points at) — the free-space watermark below can still decline it",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::text("<file>"),
                ],
            ),
            Self::CacheRootWriteSkippedTheDestinationCouldNotBe { seq, error } => (
                &CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_META,
                vec![
                    Scalar::text(CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_META.name()),
                    Scalar::text(
                        "cache root write skipped: the destination could not be classified, so put-if-absent cannot know whether a root is already there",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheRootWriteRefusedByTheFreeSpaceWatermark { seq, len } => (
                &CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
                vec![
                    Scalar::text(CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META.name()),
                    Scalar::text("cache root write refused by the free-space watermark"),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::Number(*len),
                ],
            ),
            Self::CacheRootWriteFailedToCreateItsVolumeDirectory { error } => (
                &CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_META,
                vec![
                    Scalar::text(
                        CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_META.name(),
                    ),
                    Scalar::text("cache root write failed to create its volume directory"),
                    Scalar::text("<volume>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheRootWriteFailed { seq, error } => (
                &CACHE_ROOT_WRITE_FAILED_META,
                vec![
                    Scalar::text(CACHE_ROOT_WRITE_FAILED_META.name()),
                    Scalar::text("cache root write failed"),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::AnchorFloorCandidateIsAnAbsentClassSeqRefusing { candidate } => (
                &ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_META,
                vec![
                    Scalar::text(
                        ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_META.name(),
                    ),
                    Scalar::text(
                        "anchor floor candidate is an absent-class seq; refusing to persist it",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*candidate),
                ],
            ),
            Self::HintTokenIsEmptyAnEtagLessBackendRetaining => (
                &HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_META,
                vec![
                    Scalar::text(HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_META.name()),
                    Scalar::text(
                        "hint token is empty (an ETag-less backend); retaining the prior persisted hint — expected, not a warning",
                    ),
                    Scalar::text("<volume>"),
                ],
            ),
            Self::HintIsUnpersistableTokenBytesLengthStampSignOr => (
                &HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_META,
                vec![
                    Scalar::text(
                        HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_META.name(),
                    ),
                    Scalar::text(
                        "hint is unpersistable (token bytes/length, stamp sign, or absent-class seq); retaining the prior persisted hint instead — the floor still writes",
                    ),
                    Scalar::text("<volume>"),
                ],
            ),
            Self::CacheAnchorWriteFailedToCreateItsDirectory { error } => (
                &CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_META,
                vec![
                    Scalar::text(CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_META.name()),
                    Scalar::text("cache anchor write failed to create its directory"),
                    Scalar::text("<volume>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheAnchorWriteFailed { error } => (
                &CACHE_ANCHOR_WRITE_FAILED_META,
                vec![
                    Scalar::text(CACHE_ANCHOR_WRITE_FAILED_META.name()),
                    Scalar::text("cache anchor write failed"),
                    Scalar::text("<volume>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::MountAnchorFloorCandidateIsAnAbsentClassSeq { candidate } => (
                &MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_META,
                vec![
                    Scalar::text(MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_META.name()),
                    Scalar::text(
                        "mount anchor floor candidate is an absent-class seq; refusing to persist it",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*candidate),
                ],
            ),
            Self::CacheRootEvictionSkippedTheRootPathHasNo { seq } => (
                &CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_META,
                vec![
                    Scalar::text(CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_META.name()),
                    Scalar::text("cache root eviction skipped: the root path has no volume parent"),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                ],
            ),
            Self::CacheRootEvictionSkippedTheVolumeDirectoryIsNot { seq, error } => (
                &CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META,
                vec![
                    Scalar::text(
                        CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META.name(),
                    ),
                    Scalar::text(
                        "cache root eviction skipped: the volume directory is not a real directory",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheRootEvictionFailedToRemoveTheFile { seq, error } => (
                &CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_META,
                vec![
                    Scalar::text(CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_META.name()),
                    Scalar::text("cache root eviction failed to remove the file"),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheGuardPresentAtOpenThePreviousWriterDid => (
                &CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_META,
                vec![
                    Scalar::text(CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_META.name()),
                    Scalar::text(
                        "cache guard present at open: the previous writer did not close cleanly; replaying the journal to reconcile",
                    ),
                    Scalar::text("<cache-root>"),
                ],
            ),
            Self::CacheLockHeldByAnotherProcessOpeningReadOnly => (
                &CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_META,
                vec![
                    Scalar::text(CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_META.name()),
                    Scalar::text("cache lock held by another process; opening read-only degraded"),
                    Scalar::text("<cache-root>"),
                ],
            ),
            Self::CacheReadRefusedTheObjectFanoutIsNotA { error } => (
                &CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META,
                vec![
                    Scalar::text(CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META.name()),
                    Scalar::text(
                        "cache read refused: the object fanout is not a real directory, so nothing below it belongs to this cache",
                    ),
                    Scalar::text("<object>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheObjectFailedHashVerificationUnlinkingAndEvicting => (
                &CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_META,
                vec![
                    Scalar::text(
                        CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_META.name(),
                    ),
                    Scalar::text("cache object failed hash verification; unlinking and evicting"),
                    Scalar::text("<object>"),
                ],
            ),
            Self::CacheObjectExceedsTheSizeBoundTreatingItAs { len } => (
                &CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META,
                vec![
                    Scalar::text(CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META.name()),
                    Scalar::text(
                        "cache object exceeds the size bound; treating it as a miss and unlinking",
                    ),
                    Scalar::text("<object>"),
                    Scalar::Number(*len),
                ],
            ),
            Self::CachedRootExceedsTheSizeBoundTreatingItAs { seq, len } => (
                &CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META,
                vec![
                    Scalar::text(CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META.name()),
                    Scalar::text("cached root exceeds the size bound; treating it as a miss"),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    Scalar::Number(*len),
                ],
            ),
            Self::CacheMaintainJournalFlushFailedSkippingCompactionThisCycle { error } => (
                &CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_META,
                vec![
                    Scalar::text(
                        CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_META
                            .name(),
                    ),
                    Scalar::text(
                        "cache maintain: journal flush failed; skipping compaction this cycle",
                    ),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheMaintainCompactionFailed { error } => (
                &CACHE_MAINTAIN_COMPACTION_FAILED_META,
                vec![
                    Scalar::text(CACHE_MAINTAIN_COMPACTION_FAILED_META.name()),
                    Scalar::text("cache maintain: compaction failed"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::SetInTheEnvironmentAndIgnoredTheDirectS3 { variable } => (
                &SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_META,
                vec![
                    Scalar::text(SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_META.name()),
                    Scalar::text(
                        "set in the environment and ignored: the direct-S3 route connects directly",
                    ),
                    Scalar::text(variable.as_str()),
                ],
            ),
            Self::WireSnapshotPublishTheTempFileCouldNotBe { error } => (
                &WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_META,
                vec![
                    Scalar::text(WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_META.name()),
                    Scalar::text(
                        "wire-snapshot publish: the temp file could not be removed after a successful hard_link — the destination is published and correct; the temp name is a leftover, not a failure",
                    ),
                    Scalar::text("<file>"),
                    Scalar::text("<file>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::ACacheDirIsPresentButATransportDown => (
                &A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_META,
                vec![
                    Scalar::text(A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_META.name()),
                    Scalar::text(
                        "a cache dir is present, but a transport-down degraded serve requires the volume's root key to verify what it returns; this reader holds none, so the transport failure is returned unchanged",
                    ),
                    Scalar::text("<volume>"),
                ],
            ),
            Self::TheTransportGaveNoAnswerFallingBackToThe { seq, age } => (
                &THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_META,
                vec![
                    Scalar::text(THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_META.name()),
                    Scalar::text(
                        "the transport gave no answer; falling back to the cache's last verified head for this volume (possibly stale) — the read fails closed if the cache cannot fully satisfy it",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::Number(*seq),
                    (*age).scalar(),
                ],
            ),
            Self::StoreAnObjectPathHasNoFanoutParentReporting => (
                &STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_META,
                vec![
                    Scalar::text(STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_META.name()),
                    Scalar::text(
                        "store: an object path has no fanout parent; reporting the object absent",
                    ),
                    Scalar::text("<file>"),
                ],
            ),
            Self::StoreAnObjectFanoutIsNotARealDirectory { error } => (
                &STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_META,
                vec![
                    Scalar::text(STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_META.name()),
                    Scalar::text(
                        "store: an object fanout is not a real directory; reporting the object absent",
                    ),
                    Scalar::text("<directory>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::StoreAnObjectLeafIsNotARegularFile => (
                &STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_META,
                vec![
                    Scalar::text(STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_META.name()),
                    Scalar::text(
                        "store: an object leaf is not a regular file; reporting it absent",
                    ),
                    Scalar::text("<file>"),
                ],
            ),
            Self::StoreAnObjectLeafCouldNotBeClassifiedReporting { error } => (
                &STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_META,
                vec![
                    Scalar::text(
                        STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_META.name(),
                    ),
                    Scalar::text(
                        "store: an object leaf could not be classified; reporting it absent",
                    ),
                    Scalar::text("<file>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::StorePutTheObjectFanoutIsNotAReal { error } => (
                &STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META,
                vec![
                    Scalar::text(STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META.name()),
                    Scalar::text(
                        "store put: the object fanout is not a real directory; refusing rather than writing or classifying through it",
                    ),
                    Scalar::text("<directory>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::StorePutAnObjectLeafIsNotARegular => (
                &STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_META,
                vec![
                    Scalar::text(STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_META.name()),
                    Scalar::text(
                        "store put: an object leaf is not a regular file; refusing rather than renaming over it",
                    ),
                    Scalar::text("<file>"),
                ],
            ),
            Self::StoreGetTheObjectFanoutIsNotAReal { error } => (
                &STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META,
                vec![
                    Scalar::text(STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META.name()),
                    Scalar::text(
                        "store get: the object fanout is not a real directory; refusing rather than reading through it",
                    ),
                    Scalar::text("<directory>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::StoreEstablishedOpenTxnIsNotARealDirectory => (
                &STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_META,
                vec![
                    Scalar::text(STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_META.name()),
                    Scalar::text(
                        "store established open: txn/ is not a real directory (symlink or other); refusing the open rather than sweeping through it",
                    ),
                    Scalar::text("<directory>"),
                ],
            ),
            Self::StoreEstablishedOpenAnOrphanedTxnEntryCouldNot { error } => (
                &STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META,
                vec![
                    Scalar::text(
                        STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META.name(),
                    ),
                    Scalar::text(
                        "store established open: an orphaned txn/ entry could not be removed; skipping it — the staging NAME it occupies stays wedged for the pid that would use it",
                    ),
                    Scalar::text("<directory>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::StoreEstablishedOpenSweptOrphanedTxnStagingFiles { swept, skipped } => (
                &STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META,
                vec![
                    Scalar::text(
                        STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META.name(),
                    ),
                    Scalar::text("store established open: swept orphaned txn/ staging files"),
                    Scalar::Number(*swept),
                    Scalar::Number(*skipped),
                ],
            ),
            Self::SeamAttemptFailedRetryingOnce { seam, class, error } => (
                &SEAM_ATTEMPT_FAILED_RETRYING_ONCE_META,
                vec![
                    Scalar::text(SEAM_ATTEMPT_FAILED_RETRYING_ONCE_META.name()),
                    Scalar::text("seam attempt failed; retrying once"),
                    Scalar::text(seam.as_str()),
                    Scalar::text(class.as_str()),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::WritableShutdownCoordinationFailed {
                coordination,
                cache_closed,
            } => (
                &WRITABLE_SHUTDOWN_COORDINATION_FAILED_META,
                vec![
                    Scalar::text(WRITABLE_SHUTDOWN_COORDINATION_FAILED_META.name()),
                    Scalar::text("WritableShutdownCoordinationFailed"),
                    Scalar::text(coordination.as_str()),
                    Scalar::Bool(*cache_closed),
                ],
            ),
            Self::MountSessionShutdownClosingTheCacheFailedTheCrash { error } => (
                &MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_META,
                vec![
                    Scalar::text(
                        MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_META.name(),
                    ),
                    Scalar::text(
                        "mount session shutdown: closing the cache failed; the crash guard may remain",
                    ),
                    Scalar::text("<cache-root>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::MountTeardownReadPathCountersForTheReadPhase {
                via,
                inflight_high_water,
                window,
                origin_requests,
                origin_sheds,
                origin_requests_total,
                wants_bin,
                wants_meta,
                wants_total,
                cache_hits,
                cache_misses,
            } => (
                &MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_META,
                vec![
                    Scalar::text(MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_META.name()),
                    Scalar::text("mount teardown: read-path counters for the read phase"),
                    Scalar::text(via.as_str()),
                    Scalar::Number(*inflight_high_water),
                    Scalar::Number(*window),
                    Scalar::Number(*origin_requests),
                    Scalar::Number(*origin_sheds),
                    Scalar::Number(*origin_requests_total),
                    Scalar::Number(*wants_bin),
                    Scalar::Number(*wants_meta),
                    Scalar::Number(*wants_total),
                    Scalar::Number(*cache_hits),
                    Scalar::Number(*cache_misses),
                ],
            ),
            Self::MountSessionDropClosingTheCacheFailedTheCrash { error } => (
                &MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_META,
                vec![
                    Scalar::text(MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_META.name()),
                    Scalar::text(
                        "mount session drop: closing the cache failed; the crash guard may remain",
                    ),
                    Scalar::text("<cache-root>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheAnchorFileExceedsTheSizeBoundTreatingIt { len } => (
                &CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META,
                vec![
                    Scalar::text(CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META.name()),
                    Scalar::text("cache anchor file exceeds the size bound; treating it as absent"),
                    Scalar::text("<volume>"),
                    Scalar::Number(*len),
                ],
            ),
            Self::CacheAnchorFileFailedStrictParseTreatingItAs => (
                &CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_META,
                vec![
                    Scalar::text(CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_META.name()),
                    Scalar::text("cache anchor file failed strict parse; treating it as absent"),
                    Scalar::text("<volume>"),
                ],
            ),
            Self::MountAnchorFileCarriesAHintLineWhichIts => (
                &MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_META,
                vec![
                    Scalar::text(MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_META.name()),
                    Scalar::text(
                        "mount anchor file carries a hint line, which its grammar forbids; treating it as absent",
                    ),
                    Scalar::text("<volume>"),
                ],
            ),
            Self::RefusingToUnlinkAnObjectPathThatHasNo { context } => (
                &REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_META,
                vec![
                    Scalar::text(REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_META.name()),
                    Scalar::text("refusing to unlink an object path that has no fanout parent"),
                    Scalar::text("<file>"),
                    Scalar::text(context.as_str()),
                ],
            ),
            Self::RefusingToUnlinkAnObjectThroughAForeignFanout { context } => (
                &REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_META,
                vec![
                    Scalar::text(REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_META.name()),
                    Scalar::text(
                        "refusing to unlink an object through a foreign fanout directory; nothing on disk is touched",
                    ),
                    Scalar::text("<directory>"),
                    Scalar::text(context.as_str()),
                ],
            ),
            Self::RefusingToUnlinkAnObjectUnderAFanoutThat { error, context } => (
                &REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_META,
                vec![
                    Scalar::text(REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_META.name()),
                    Scalar::text(
                        "refusing to unlink an object under a fanout that could not be classified; nothing on disk is touched and the object is still there",
                    ),
                    Scalar::text("<directory>"),
                    Scalar::text(error.as_str()),
                    Scalar::text(context.as_str()),
                ],
            ),
            Self::AnObjectLeafCouldNotBeUnlinkedItStays { error, context } => (
                &AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_META,
                vec![
                    Scalar::text(AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_META.name()),
                    Scalar::text(
                        "an object leaf could not be unlinked; it stays on disk as an unindexed residue, and this cache's accounting under-counts it until a cold rebuild re-adopts it or an operator removes it",
                    ),
                    Scalar::text("<file>"),
                    Scalar::text(error.as_str()),
                    Scalar::text(context.as_str()),
                ],
            ),
            Self::ColdRebuildWalkSkippingANonDigestFileName => (
                &COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_META.name()),
                    Scalar::text("cold rebuild walk: skipping a non-digest file name"),
                    Scalar::text("<name>"),
                ],
            ),
            Self::ColdRebuildWalkSkippingAFileWhoseNameDoes => (
                &COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_META.name()),
                    Scalar::text(
                        "cold rebuild walk: skipping a file whose name does not match its fanout directory",
                    ),
                    Scalar::text("<name>"),
                    Scalar::text("<name>"),
                ],
            ),
            Self::ColdRebuildWalkSkippingAnEntryWhoseMetadataCould { error } => (
                &COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_META,
                vec![
                    Scalar::text(
                        COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_META.name(),
                    ),
                    Scalar::text(
                        "cold rebuild walk: skipping an entry whose metadata could not be read",
                    ),
                    Scalar::text("<file>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::ColdRebuildWalkSkippingANonRegularFileEntry => (
                &COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_META.name()),
                    Scalar::text("cold rebuild walk: skipping a non-regular-file entry"),
                    Scalar::text("<file>"),
                ],
            ),
            Self::ColdRebuildWalkSkippingAnOversizedForeignFile { len } => (
                &COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_META.name()),
                    Scalar::text("cold rebuild walk: skipping an oversized foreign file"),
                    Scalar::text("<file>"),
                    Scalar::Number(*len),
                ],
            ),
            Self::ColdRebuildWalkSkippingASizeThatCannotFit { len } => (
                &COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_META.name()),
                    Scalar::text(
                        "cold rebuild walk: skipping a size that cannot fit the index format",
                    ),
                    Scalar::text("<file>"),
                    Scalar::Number(*len),
                ],
            ),
            Self::ColdRebuildWalkSkippingANonFanoutEntryUnder => (
                &COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_META.name()),
                    Scalar::text("cold rebuild walk: skipping a non-fanout entry under objects/"),
                    Scalar::text("<name>"),
                ],
            ),
            Self::ColdRebuildWalkSkippingAFanoutEntryWhoseType { error } => (
                &COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_META.name()),
                    Scalar::text(
                        "cold rebuild walk: skipping a fanout entry whose type could not be read",
                    ),
                    Scalar::text("<file>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::ColdRebuildWalkSkippingANonDirectoryEntryUnder => (
                &COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_META,
                vec![
                    Scalar::text(
                        COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_META.name(),
                    ),
                    Scalar::text(
                        "cold rebuild walk: skipping a non-directory entry under objects/ (a symlink to one included)",
                    ),
                    Scalar::text("<file>"),
                ],
            ),
            Self::ColdRebuildWalkTheAdoptionCapWasReachedThe {
                dropped,
                adoption_cap,
            } => (
                &COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_META,
                vec![
                    Scalar::text(COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_META.name()),
                    Scalar::text(
                        "cold rebuild walk: the adoption cap was reached; the dropped entries' files stay on disk and stay hash-verifiable by path, and a get() for one still HITS — but it is not re-indexed by that read (touch_id no-ops for an untracked id and insert() returns early because the file exists), so it stays outside quota and LRU accounting. gran verify reports it as `adopted`; nothing repairs it short of raising the cap or removing the cache directory.",
                    ),
                    Scalar::Number(*dropped),
                    Scalar::Number(*adoption_cap),
                ],
            ),
            Self::ColdRebuildWalkSnapshotRewriteAndJournalResetRefused => (
                &COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_META,
                vec![
                    Scalar::text(
                        COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_META.name(),
                    ),
                    Scalar::text(
                        "cold rebuild walk: snapshot rewrite and journal reset refused together by the free-space watermark; neither was touched and the next open will simply walk again",
                    ),
                ],
            ),
            Self::CacheIndexFileExceedsTheSizeBoundTreatingIt { len, what } => (
                &CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META,
                vec![
                    Scalar::text(CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META.name()),
                    Scalar::text(
                        "cache index file exceeds the size bound; treating it as untrustworthy",
                    ),
                    Scalar::text("<file>"),
                    Scalar::Number(*len),
                    Scalar::text(what.as_str()),
                ],
            ),
            Self::CacheIndexFileGrewPastTheSizeBoundBetween { len, what } => (
                &CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_META,
                vec![
                    Scalar::text(CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_META.name()),
                    Scalar::text(
                        "cache index file grew past the size bound between the stat and the read; treating it as untrustworthy",
                    ),
                    Scalar::text("<file>"),
                    Scalar::Number(*len),
                    Scalar::text(what.as_str()),
                ],
            ),
            Self::CacheSnapshotPresentWithNoJournalACreationCrash => (
                &CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_META,
                vec![
                    Scalar::text(
                        CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_META.name(),
                    ),
                    Scalar::text(
                        "cache snapshot present with no journal: a creation-crash window from the last compaction; recreating an empty journal",
                    ),
                    Scalar::text("<cache-root>"),
                ],
            ),
            Self::CacheWriterOpenAnOrphanedTxnEntryCouldNot { error } => (
                &CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META,
                vec![
                    Scalar::text(CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META.name()),
                    Scalar::text(
                        "cache writer open: an orphaned txn/ entry could not be removed; skipping it — the staging NAME it occupies stays wedged for the pid that would use it",
                    ),
                    Scalar::text("<directory>"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::CacheWriterOpenSweptOrphanedTxnStagingFiles { swept, skipped } => (
                &CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META,
                vec![
                    Scalar::text(CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META.name()),
                    Scalar::text("cache writer open: swept orphaned txn/ staging files"),
                    Scalar::Number(*swept),
                    Scalar::Number(*skipped),
                ],
            ),
            Self::StructureWalk {
                round,
                outcome,
                needs,
                hints,
                admits,
                pool_len,
                pool_used,
            } => (
                &STRUCTURE_WALK_META,
                vec![
                    Scalar::text(STRUCTURE_WALK_META.name()),
                    Scalar::text("structure walk"),
                    Scalar::Number(*round),
                    Scalar::text(outcome.as_str()),
                    Scalar::Number(*needs),
                    Scalar::Number(*hints),
                    Scalar::Number(*admits),
                    Scalar::Number(*pool_len),
                    Scalar::Number(*pool_used),
                ],
            ),
            Self::GranMountUnmountFailedFallingBackToALazy { error } => (
                &GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_META,
                vec![
                    Scalar::text(GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_META.name()),
                    Scalar::text(
                        "gran mount: unmount failed; falling back to a lazy detach — the session thread is presumed wedged (still blocked reading /dev/fuse, since unmounting is what would have let it return) and will NOT be joined — joining a wedged thread is exactly what would hang this coordinator forever",
                    ),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::GranMountTheMountWasLazilyDetachedMntDetach => (
                &GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_META,
                vec![
                    Scalar::text(GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_META.name()),
                    Scalar::text(
                        "gran mount: the mount was lazily detached (MNT_DETACH) after the plain unmount was refused; the FUSE connection itself may still outlive this process until every already-open file on it is closed",
                    ),
                ],
            ),
            Self::GranMountBothThePlainUnmountAndTheMnt {
                unmount_error,
                detach_error,
            } => (
                &GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_META,
                vec![
                    Scalar::text(GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_META.name()),
                    Scalar::text(
                        "gran mount: both the plain unmount and the MNT_DETACH fallback failed; the mount is likely still attached",
                    ),
                    Scalar::text(unmount_error.as_str()),
                    Scalar::text(detach_error.as_str()),
                ],
            ),
            Self::GranMountASignalReadinessReportNeverArrivedBefore => (
                &GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_META,
                vec![
                    Scalar::text(
                        GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_META.name(),
                    ),
                    Scalar::text(
                        "gran mount: a signal-readiness report never arrived before Session::new (the producer thread ended before reporting, most likely a panic); proceeding without waiting for the other one",
                    ),
                ],
            ),
            Self::GranMountACachedRootAndTheWireRoot => (
                &GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_META,
                vec![
                    Scalar::text(GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_META.name()),
                    Scalar::text(
                        "gran mount: a cached root and the wire root disagreed at open; served the wire root",
                    ),
                    Scalar::text("<volume>"),
                    Scalar::text("<equivocation>"),
                ],
            ),
            Self::GranMountCouldNotBuildARuntimeForSigint => (
                &GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_META,
                vec![
                    Scalar::text(GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_META.name()),
                    Scalar::text(
                        "gran mount: could not build a runtime for SIGINT handling; this daemon is now deaf to SIGINT (SIGTERM and an external `gran umount` are still live)",
                    ),
                ],
            ),
            Self::GranMountCouldNotRegisterASigintHandlerThis { error } => (
                &GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_META,
                vec![
                    Scalar::text(GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_META.name()),
                    Scalar::text(
                        "gran mount: could not register a SIGINT handler; this daemon is now deaf to SIGINT (SIGTERM and an external `gran umount` are still live)",
                    ),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::GranMountTheSigintStreamEndedWithoutDeliveringA => (
                &GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_META,
                vec![
                    Scalar::text(
                        GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_META.name(),
                    ),
                    Scalar::text(
                        "gran mount: the SIGINT stream ended without delivering a signal; this daemon is now deaf to SIGINT (SIGTERM and an external `gran umount` are still live)",
                    ),
                ],
            ),
            Self::GranMountCouldNotBuildARuntimeForSigterm => (
                &GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_META,
                vec![
                    Scalar::text(GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_META.name()),
                    Scalar::text(
                        "gran mount: could not build a runtime for SIGTERM handling; this daemon is now deaf to SIGTERM — under systemd this means TimeoutStopSec then SIGKILL, which skips destroy/Cache::close entirely",
                    ),
                ],
            ),
            Self::GranMountCouldNotRegisterASigtermHandlerThis => (
                &GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_META,
                vec![
                    Scalar::text(GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_META.name()),
                    Scalar::text(
                        "gran mount: could not register a SIGTERM handler; this daemon is now deaf to SIGTERM — under systemd this means TimeoutStopSec then SIGKILL, which skips destroy/Cache::close entirely",
                    ),
                ],
            ),
            Self::GranMountDetachTargetUnavailableLazyDetachCannotBe { error } => (
                &GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_META,
                vec![
                    Scalar::text(
                        GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_META.name(),
                    ),
                    Scalar::text(
                        "gran mount: detach target unavailable; lazy detach cannot be attempted",
                    ),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::GranMountReceivedSignalUnmounting { signal } => (
                &GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_META,
                vec![
                    Scalar::text(GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_META.name()),
                    Scalar::text("gran mount: received signal, unmounting"),
                    Scalar::text(signal.as_str()),
                ],
            ),
            Self::GranMountTheFuseSessionEndedWithAnError { error } => (
                &GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_META,
                vec![
                    Scalar::text(GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_META.name()),
                    Scalar::text("gran mount: the FUSE session ended with an error"),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::GranMountTheFuseSessionDidNotEndAfterItsUnmount { listed, connection } => (
                &GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_META,
                vec![
                    Scalar::text(
                        GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_META.name(),
                    ),
                    Scalar::text(SESSION_DID_NOT_END_MESSAGE),
                    Scalar::text(listed.as_str()),
                    Scalar::text(connection.as_str()),
                ],
            ),
            Self::GranMountTheFuseSessionThreadPanicked => (
                &GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_META,
                vec![
                    Scalar::text(GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_META.name()),
                    Scalar::text("gran mount: the FUSE session thread panicked"),
                ],
            ),
            Self::GranMountCouldNotCaptureTheMountIdentity { error } => (
                &GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_META,
                vec![
                    Scalar::text(GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_META.name()),
                    Scalar::text(
                        "gran mount: could not capture the mount identity; a session end that races its unmount will report a failure",
                    ),
                    Scalar::text(error.as_str()),
                ],
            ),
            Self::GranMountTheFuseSessionEndedEconnabortedRacingItsUnmount => (
                &GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_META,
                vec![
                    Scalar::text(
                        GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_META
                            .name(),
                    ),
                    Scalar::text(
                        "gran mount: the FUSE session ended ECONNABORTED racing its unmount and the mount is gone; a clean end",
                    ),
                ],
            ),
            Self::SyncRegistrationTimingSampleUnavailable => (
                &SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_META,
                vec![
                    Scalar::text(SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_META.name()),
                    Scalar::text("registration timing sample unavailable"),
                ],
            ),
        }
    }
}

#[cfg(test)]
mod tests;
