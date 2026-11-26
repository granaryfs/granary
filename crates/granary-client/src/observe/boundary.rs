// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Closed event construction, exact callsite admission, and scalar encoders.

// @file-disposition: STAYS — every stable event adds its callsite, its SITES row, its Payload arm and its encoder here together; the exact-callsite admission check needs the whole closed set in one table.

use super::{
    CorrelationId, FailureClass, FilterRejection, LogDestination, LogFormat, OperationKind,
    Outcome, RetryReason,
};
use granary_core::secure_random::SecureRandom;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use tracing::callsite::{DefaultCallsite, Identifier};
use tracing::field::{Field, FieldSet, Value, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer};

mod diagnostics;
mod notices;
mod paths;
pub use diagnostics::{
    Age, CacheAction, HttpSeam, IndexFileKind, OperatorDiagnostic, ProxyVariableName, SignalKind,
    TeardownCause, WalkOutcome, WireRetryClass,
};
pub use notices::OperatorNotice;
pub(crate) use paths::PathSlot;
pub use paths::{BundleHistory, BundleSnapshot, BundleSnapshotError, LogName, LogPath, LogPaths};

const TARGET: &str = "granary_client::event";
const RECORD_MAX: usize = 32768;

/// The least severe level bundle history keeps. The policy is fixed: it never
/// reads the telemetry filter, so a quiet filter cannot starve a bundle and a
/// verbose one cannot flood it.
const BUNDLE_LEVEL: Level = Level::INFO;

pub(crate) fn bundle_admits(meta: &Metadata<'_>) -> bool {
    *meta.level() <= BUNDLE_LEVEL
}

#[cfg(test)]
std::thread_local! {
    static ENCODER_ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

static CONFLICT_SITE: DefaultCallsite = DefaultCallsite::new(&CONFLICT_META);
static CONFLICT_META: Metadata<'static> = Metadata::new(
    "op.conflict",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "path", "class"], Identifier(&CONFLICT_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVERY_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVERY_META);
static RECOVERY_META: Metadata<'static> = Metadata::new(
    "overlay.recovery",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &[
            "event",
            "outcome",
            "files",
            "bytes",
            "record_index",
            "cap",
            "commit_requested",
            "owed",
            "stage_reserve",
            "projected_reserve",
            "ownership_reserve",
            "completion_reserve",
            "writer_reserve",
            "journal_reserve",
            "rolled_back_stages",
            "rolled_back_bytes",
        ],
        Identifier(&RECOVERY_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static REFUSED_SITE: DefaultCallsite = DefaultCallsite::new(&REFUSED_META);
static REFUSED_META: Metadata<'static> = Metadata::new(
    "overlay.refused",
    TARGET,
    Level::ERROR,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "class", "record_index", "files", "bytes"],
        Identifier(&REFUSED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static DISCARD_REFUSED_SITE: DefaultCallsite = DefaultCallsite::new(&DISCARD_REFUSED_META);
static DISCARD_REFUSED_META: Metadata<'static> = Metadata::new(
    "overlay.discard_refused",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "reason"], Identifier(&DISCARD_REFUSED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECONCILE_REFUSED_SITE: DefaultCallsite = DefaultCallsite::new(&RECONCILE_REFUSED_META);
static RECONCILE_REFUSED_META: Metadata<'static> = Metadata::new(
    "overlay.reconcile_refused",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "reason"], Identifier(&RECONCILE_REFUSED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static SWEEP_SITE: DefaultCallsite = DefaultCallsite::new(&SWEEP_META);
static SWEEP_META: Metadata<'static> = Metadata::new(
    "overlay.sweep",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "files", "bytes"], Identifier(&SWEEP_SITE)),
    tracing::metadata::Kind::EVENT,
);
static STAGE_ROLLED_BACK_SITE: DefaultCallsite = DefaultCallsite::new(&STAGE_ROLLED_BACK_META);
static STAGE_ROLLED_BACK_META: Metadata<'static> = Metadata::new(
    "overlay.stage_rolled_back",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &[
            "event",
            "rollback_seq",
            "stage_id",
            "old_size",
            "restored_size",
            "discarded_bytes",
            "path",
        ],
        Identifier(&STAGE_ROLLED_BACK_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static DETACHED_STAGE_ROLLED_BACK_SITE: DefaultCallsite =
    DefaultCallsite::new(&DETACHED_STAGE_ROLLED_BACK_META);
static DETACHED_STAGE_ROLLED_BACK_META: Metadata<'static> = Metadata::new(
    "overlay.stage_rolled_back",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &[
            "event",
            "rollback_seq",
            "stage_id",
            "old_size",
            "restored_size",
            "discarded_bytes",
        ],
        Identifier(&DETACHED_STAGE_ROLLED_BACK_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static FAULT_SITE: DefaultCallsite = DefaultCallsite::new(&FAULT_META);
static FAULT_META: Metadata<'static> = Metadata::new(
    "overlay.fault",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "point", "phase", "occurrence", "record_index"],
        Identifier(&FAULT_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static SYNC_FAULT_SITE: DefaultCallsite = DefaultCallsite::new(&SYNC_FAULT_META);
static SYNC_FAULT_META: Metadata<'static> = Metadata::new(
    "sync.fault",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "point", "phase", "occurrence", "object_kind"],
        Identifier(&SYNC_FAULT_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static BEGIN_SITE: DefaultCallsite = DefaultCallsite::new(&BEGIN_META);
static BEGIN_META: Metadata<'static> = Metadata::new(
    "op.begin",
    TARGET,
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "kind"], Identifier(&BEGIN_SITE)),
    tracing::metadata::Kind::EVENT,
);
static END_SITE: DefaultCallsite = DefaultCallsite::new(&END_META);
static END_META: Metadata<'static> = Metadata::new(
    "op.end",
    TARGET,
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "kind", "outcome"], Identifier(&END_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RETRY_SITE: DefaultCallsite = DefaultCallsite::new(&RETRY_META);
static RETRY_META: Metadata<'static> = Metadata::new(
    "op.retry",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "kind", "attempt", "reason"],
        Identifier(&RETRY_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static FAILED_SITE: DefaultCallsite = DefaultCallsite::new(&FAILED_META);
static FAILED_META: Metadata<'static> = Metadata::new(
    "op.failed",
    TARGET,
    Level::ERROR,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "kind", "class"], Identifier(&FAILED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static METRICS_EXPORT_FAILED_SITE: DefaultCallsite =
    DefaultCallsite::new(&METRICS_EXPORT_FAILED_META);
static METRICS_EXPORT_FAILED_META: Metadata<'static> = Metadata::new(
    super::METRICS_EXPORT_FAILED,
    TARGET,
    Level::ERROR,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "class"], Identifier(&METRICS_EXPORT_FAILED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static DROPPED_SITE: DefaultCallsite = DefaultCallsite::new(&DROPPED_META);
static DROPPED_META: Metadata<'static> = Metadata::new(
    "overlay.failures_dropped",
    TARGET,
    Level::ERROR,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "dropped"], Identifier(&DROPPED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static CONTENTION_SITE: DefaultCallsite = DefaultCallsite::new(&CONTENTION_META);
static CONTENTION_META: Metadata<'static> = Metadata::new(
    "commit.contention",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "commits", "conflicts"],
        Identifier(&CONTENTION_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static BACKOFF_ENTERED_SITE: DefaultCallsite = DefaultCallsite::new(&BACKOFF_ENTERED_META);
static BACKOFF_ENTERED_META: Metadata<'static> = Metadata::new(
    "commit.backoff",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "cause", "outcome"],
        Identifier(&BACKOFF_ENTERED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static BACKOFF_RECOVERED_SITE: DefaultCallsite = DefaultCallsite::new(&BACKOFF_RECOVERED_META);
static BACKOFF_RECOVERED_META: Metadata<'static> = Metadata::new(
    "commit.backoff",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "cause", "outcome", "attempts"],
        Identifier(&BACKOFF_RECOVERED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static WORKSPACE_SITE: DefaultCallsite = DefaultCallsite::new(&WORKSPACE_META);
static WORKSPACE_META: Metadata<'static> = Metadata::new(
    "sync.workspace_exhausted",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "reason", "needed", "limit"],
        Identifier(&WORKSPACE_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CAP_EXHAUSTED_SITE: DefaultCallsite = DefaultCallsite::new(&CAP_EXHAUSTED_META);
static CAP_EXHAUSTED_META: Metadata<'static> = Metadata::new(
    "overlay.cap_exhausted",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &[
            "event", "reason", "cap", "charged", "reserved", "captured", "needed",
        ],
        Identifier(&CAP_EXHAUSTED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static COMMIT_STOPPED_SITE: DefaultCallsite = DefaultCallsite::new(&COMMIT_STOPPED_META);
static COMMIT_STOPPED_META: Metadata<'static> = Metadata::new(
    "commit.stopped",
    TARGET,
    Level::ERROR,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "cause"], Identifier(&COMMIT_STOPPED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_NOTHING_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_NOTHING_META);
static RECOVER_NOTHING_META: Metadata<'static> = Metadata::new(
    "recover.nothing",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event"], Identifier(&RECOVER_NOTHING_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_SIGNING_KEY_REFUSED_SITE: DefaultCallsite =
    DefaultCallsite::new(&RECOVER_SIGNING_KEY_REFUSED_META);
static RECOVER_SIGNING_KEY_REFUSED_META: Metadata<'static> = Metadata::new(
    "recover.signing_key_refused",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event"], Identifier(&RECOVER_SIGNING_KEY_REFUSED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_SUBSUMED_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_SUBSUMED_META);
static RECOVER_SUBSUMED_META: Metadata<'static> = Metadata::new(
    "recover.subsumed",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "relation", "seq"],
        Identifier(&RECOVER_SUBSUMED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_STALE_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_STALE_META);
static RECOVER_STALE_META: Metadata<'static> = Metadata::new(
    "recover.stale",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event"], Identifier(&RECOVER_STALE_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_LANDED_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_LANDED_META);
static RECOVER_LANDED_META: Metadata<'static> = Metadata::new(
    "recover.landed",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "seq"], Identifier(&RECOVER_LANDED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_ARCHIVED_LANDED_SITE: DefaultCallsite =
    DefaultCallsite::new(&RECOVER_ARCHIVED_LANDED_META);
static RECOVER_ARCHIVED_LANDED_META: Metadata<'static> = Metadata::new(
    "recover.archived_landed",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "seq"], Identifier(&RECOVER_ARCHIVED_LANDED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_REBASED_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_REBASED_META);
static RECOVER_REBASED_META: Metadata<'static> = Metadata::new(
    "recover.rebased",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "chain_len"], Identifier(&RECOVER_REBASED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_CONFLICT_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_CONFLICT_META);
static RECOVER_CONFLICT_META: Metadata<'static> = Metadata::new(
    "recover.conflict",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "path"], Identifier(&RECOVER_CONFLICT_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_SELECTION_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_SELECTION_META);
static RECOVER_SELECTION_META: Metadata<'static> = Metadata::new(
    "recover.selection_changed",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "token"], Identifier(&RECOVER_SELECTION_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_UNOWNED_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_UNOWNED_META);
static RECOVER_UNOWNED_META: Metadata<'static> = Metadata::new(
    "recover.landed_unowned",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event"], Identifier(&RECOVER_UNOWNED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_FINISHED_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_FINISHED_META);
static RECOVER_FINISHED_META: Metadata<'static> = Metadata::new(
    "recover.journal_finished",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "base_seq"], Identifier(&RECOVER_FINISHED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_BLOCKED_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_BLOCKED_META);
static RECOVER_BLOCKED_META: Metadata<'static> = Metadata::new(
    "recover.journal_blocked",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "reason"], Identifier(&RECOVER_BLOCKED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_FENCE_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_FENCE_META);
static RECOVER_FENCE_META: Metadata<'static> = Metadata::new(
    "recover.fence_settled",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "how"], Identifier(&RECOVER_FENCE_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_UNRESOLVED_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_UNRESOLVED_META);
static RECOVER_UNRESOLVED_META: Metadata<'static> = Metadata::new(
    "recover.unresolved",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "seq"], Identifier(&RECOVER_UNRESOLVED_SITE)),
    tracing::metadata::Kind::EVENT,
);
static RECOVER_RESENT_SITE: DefaultCallsite = DefaultCallsite::new(&RECOVER_RESENT_META);
static RECOVER_RESENT_META: Metadata<'static> = Metadata::new(
    "recover.resent",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "seq"], Identifier(&RECOVER_RESENT_SITE)),
    tracing::metadata::Kind::EVENT,
);
static PUBLISH_SITE: DefaultCallsite = DefaultCallsite::new(&PUBLISH_META);
static PUBLISH_META: Metadata<'static> = Metadata::new(
    "op.publish_bound",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["event", "publish_operation"], Identifier(&PUBLISH_SITE)),
    tracing::metadata::Kind::EVENT,
);
static CONFIG_SITE: DefaultCallsite = DefaultCallsite::new(&CONFIG_META);
static CONFIG_META: Metadata<'static> = Metadata::new(
    "log.config",
    TARGET,
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "format", "destination"],
        Identifier(&CONFIG_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static FILTER_SITE: DefaultCallsite = DefaultCallsite::new(&FILTER_META);
static FILTER_META: Metadata<'static> = Metadata::new(
    "log.filter_rejected",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "source", "reason", "detail"],
        Identifier(&FILTER_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static VIEW_INSTALLED_SITE: DefaultCallsite = DefaultCallsite::new(&VIEW_INSTALLED_META);
static VIEW_INSTALLED_META: Metadata<'static> = Metadata::new(
    "mount.view",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "cause", "outcome", "seq"],
        Identifier(&VIEW_INSTALLED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static VIEW_REFUSED_SITE: DefaultCallsite = DefaultCallsite::new(&VIEW_REFUSED_META);
static VIEW_REFUSED_META: Metadata<'static> = Metadata::new(
    "mount.view",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "cause", "outcome", "seq"],
        Identifier(&VIEW_REFUSED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static UNMOUNTED_SITE: DefaultCallsite = DefaultCallsite::new(&UNMOUNTED_META);
static UNMOUNTED_META: Metadata<'static> = Metadata::new(
    "mount.unmount",
    TARGET,
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "trigger", "outcome", "seq", "elapsed_ms"],
        Identifier(&UNMOUNTED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static UNMOUNT_LEFT_SITE: DefaultCallsite = DefaultCallsite::new(&UNMOUNT_LEFT_META);
static UNMOUNT_LEFT_META: Metadata<'static> = Metadata::new(
    "mount.unmount",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &[
            "event",
            "trigger",
            "outcome",
            "cause",
            "files",
            "bytes",
            "operations",
            "elapsed_ms",
        ],
        Identifier(&UNMOUNT_LEFT_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static UNMOUNT_UNREAD_SITE: DefaultCallsite = DefaultCallsite::new(&UNMOUNT_UNREAD_META);
static UNMOUNT_UNREAD_META: Metadata<'static> = Metadata::new(
    "mount.unmount",
    TARGET,
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "trigger", "outcome", "cause", "elapsed_ms"],
        Identifier(&UNMOUNT_UNREAD_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static OPERATION_SITE: DefaultCallsite = DefaultCallsite::new(&OPERATION_META);
static OPERATION_META: Metadata<'static> = Metadata::new(
    "op",
    TARGET,
    Level::ERROR,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(&["op", "kind"], Identifier(&OPERATION_SITE)),
    tracing::metadata::Kind::SPAN,
);

static SITES: &[&Metadata<'static>] = &[
    &CONFLICT_META,
    &RECOVERY_META,
    &REFUSED_META,
    &DISCARD_REFUSED_META,
    &RECONCILE_REFUSED_META,
    &SWEEP_META,
    &STAGE_ROLLED_BACK_META,
    &DETACHED_STAGE_ROLLED_BACK_META,
    &FAULT_META,
    &SYNC_FAULT_META,
    &BEGIN_META,
    &END_META,
    &RETRY_META,
    &FAILED_META,
    &METRICS_EXPORT_FAILED_META,
    &DROPPED_META,
    &CONTENTION_META,
    &BACKOFF_ENTERED_META,
    &BACKOFF_RECOVERED_META,
    &WORKSPACE_META,
    &CAP_EXHAUSTED_META,
    &COMMIT_STOPPED_META,
    &RECOVER_NOTHING_META,
    &RECOVER_SIGNING_KEY_REFUSED_META,
    &RECOVER_SUBSUMED_META,
    &RECOVER_STALE_META,
    &RECOVER_LANDED_META,
    &RECOVER_ARCHIVED_LANDED_META,
    &RECOVER_REBASED_META,
    &RECOVER_CONFLICT_META,
    &RECOVER_SELECTION_META,
    &RECOVER_UNOWNED_META,
    &RECOVER_FINISHED_META,
    &RECOVER_BLOCKED_META,
    &RECOVER_FENCE_META,
    &RECOVER_UNRESOLVED_META,
    &RECOVER_RESENT_META,
    &PUBLISH_META,
    &CONFIG_META,
    &FILTER_META,
    &VIEW_INSTALLED_META,
    &VIEW_REFUSED_META,
    &UNMOUNTED_META,
    &UNMOUNT_LEFT_META,
    &UNMOUNT_UNREAD_META,
    &OPERATION_META,
];

/// The source of a refused optional filter, without its value.
#[derive(Clone, Copy, Debug)]
pub enum FilterSource {
    /// The optional `RUST_LOG` environment variable.
    RustLog,
}
impl FilterSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RustLog => "rust_log",
        }
    }
}

/// Fixed explanations for refused filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterDetail {
    /// The input could not be decoded.
    NotUnicode,
    /// The directive grammar refused the input.
    Malformed,
}
impl FilterDetail {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotUnicode => "filter value is not valid UTF-8",
            Self::Malformed => "filter directives were not understood",
        }
    }
}

/// Recovery's closed outcome domain.
#[derive(Clone, Copy, Debug)]
pub enum RecoveryClass {
    /// No repair was needed.
    Clean,
    /// Repair completed.
    Repaired,
    /// Work remains pending.
    Pending,
}
impl RecoveryClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Repaired => "repaired",
            Self::Pending => "pending",
        }
    }
}

/// What recorded overlay work owes above the cap, beside the reserve terms
/// that hold its room. A landing retires unheld stages' terms; held stages,
/// the ownership reserve, completion slots, the writer and the journal stay
/// until their handles close, a commit completes or the cap rises.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OverlayOwed {
    /// Charged, reserved and captured bytes beyond the cap; zero within it.
    pub owed: u64,
    /// Re-bind and completion reserve of every stage the journal binds.
    pub stages: u64,
    /// What a retained projected seal or boundary's residual replacement can
    /// add beyond the journal and the stages' re-binds.
    pub projected: u64,
    /// The ownership carrier's completion reserve.
    pub ownership: u64,
    /// Reserve for the completion frames of unresolved commits.
    pub completion: u64,
    /// The writer record's length.
    pub writer: u64,
    /// The journal's length, header included.
    pub journal: u64,
}

/// Which step of an injected operation was reached.
#[derive(Clone, Copy, Debug)]
pub enum FaultPhase {
    /// Before the operation.
    Before,
    /// After the operation.
    After,
    /// Part way through a write.
    Partial,
    /// After the journal tail was cut.
    AfterCut,
    /// After the file was synced.
    AfterSync,
    /// Before a replacement file was built.
    Build,
    /// Before a replacement file was synced.
    Sync,
    /// Before a replacement file was renamed into place.
    Rename,
    /// After a replacement file was renamed into place.
    AfterRename,
    /// Before the containing directory was synced.
    DirSync,
    /// After the containing directory was synced.
    AfterDirSync,
    /// Before syncing the overlay area.
    Area,
    /// Before syncing the staging directory.
    Staging,
    /// Before syncing the canonical journal.
    Journal,
}
impl FaultPhase {
    const ALL: &'static [Self] = &[
        Self::Before,
        Self::After,
        Self::Partial,
        Self::AfterCut,
        Self::AfterSync,
        Self::Build,
        Self::Sync,
        Self::Rename,
        Self::AfterRename,
        Self::DirSync,
        Self::AfterDirSync,
        Self::Area,
        Self::Staging,
        Self::Journal,
    ];

    /// The phase a seam names; hyphen and underscore spellings are one phase.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn from_seam(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|phase| phase.as_str() == name.replace('-', "_"))
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Partial => "partial",
            Self::AfterCut => "after_cut",
            Self::AfterSync => "after_sync",
            Self::Build => "build",
            Self::Sync => "sync",
            Self::Rename => "rename",
            Self::AfterRename => "after_rename",
            Self::DirSync => "dir_sync",
            Self::AfterDirSync => "after_dir_sync",
            Self::Area => "area",
            Self::Staging => "staging",
            Self::Journal => "journal",
        }
    }
}

/// A registered overlay fault seam; caller-supplied labels are unavailable.
#[derive(Clone, Copy, Debug)]
pub enum OverlayFaultPoint {
    /// The open-time overlay durability barrier.
    OpenBarrier,
    /// The `StageCreate` seam.
    StageCreate,
    /// The `StageWrite` seam.
    StageWrite,
    /// The `StageSync` seam.
    StageSync,
    /// The `StageDirSync` seam.
    StageDirSync,
    /// The `StageTruncate` seam.
    StageTruncate,
    /// The `JournalAppend` seam.
    JournalAppend,
    /// The `JournalPreSync` seam.
    JournalPreSync,
    /// The `JournalPostSync` seam.
    JournalPostSync,
    /// The `JournalCreate` seam.
    JournalCreate,
    /// The `JournalCarry` seam.
    JournalCarry,
    /// The journal rollback installation seam.
    JournalRollback,
    /// The stage rollback report seam.
    StageRollbackReport,
    /// The `MarkWrite` seam.
    MarkWrite,
    /// The `MarkSync` seam.
    MarkSync,
    /// The `AppendRollback` seam.
    AppendRollback,
    /// The `SweepRemove` seam.
    SweepRemove,
    /// The `TailCut` seam.
    TailCut,
    /// The `ReplaceBuild` seam.
    ReplaceBuild,
    /// The `ReplaceDirSync` seam.
    ReplaceDirSync,
    /// The `ReplaceQuiesced` seam.
    ReplaceQuiesced,
    /// The `ReplaceRename` seam.
    ReplaceRename,
    /// The `ReplaceSwitched` seam.
    ReplaceSwitched,
    /// The `ReplaceSync` seam.
    ReplaceSync,
    /// The `RetireMarkClear` seam.
    RetireMarkClear,
    /// The `CarryMarkClear` seam.
    CarryMarkClear,
    /// The `RetireUnlink` seam.
    RetireUnlink,
    /// The `Writer` seam.
    Writer,
}
impl OverlayFaultPoint {
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn from_seam(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == name)
    }

    const ALL: &'static [Self] = &[
        Self::OpenBarrier,
        Self::StageCreate,
        Self::StageWrite,
        Self::StageSync,
        Self::StageDirSync,
        Self::StageTruncate,
        Self::JournalAppend,
        Self::JournalPreSync,
        Self::JournalPostSync,
        Self::JournalCreate,
        Self::JournalCarry,
        Self::JournalRollback,
        Self::StageRollbackReport,
        Self::MarkWrite,
        Self::MarkSync,
        Self::AppendRollback,
        Self::SweepRemove,
        Self::TailCut,
        Self::ReplaceBuild,
        Self::ReplaceDirSync,
        Self::ReplaceQuiesced,
        Self::ReplaceRename,
        Self::ReplaceSwitched,
        Self::ReplaceSync,
        Self::RetireMarkClear,
        Self::CarryMarkClear,
        Self::RetireUnlink,
        Self::Writer,
    ];
    const fn as_str(self) -> &'static str {
        match self {
            Self::OpenBarrier => "overlay.open.barrier",
            Self::StageCreate => "overlay.stage.create",
            Self::StageWrite => "overlay.stage.write",
            Self::StageSync => "overlay.stage.sync",
            Self::StageDirSync => "overlay.stage.dir_sync",
            Self::StageTruncate => "overlay.stage.truncate",
            Self::JournalAppend => "overlay.journal.append",
            Self::JournalPreSync => "overlay.journal.pre_sync",
            Self::JournalPostSync => "overlay.journal.post_sync",
            Self::JournalCreate => "overlay.journal.create",
            Self::JournalCarry => "overlay.journal.carry",
            Self::JournalRollback => "overlay.journal.rollback",
            Self::StageRollbackReport => "overlay.stage.rollback_report",
            Self::MarkWrite => "overlay.mark.write",
            Self::MarkSync => "overlay.mark.sync",
            Self::AppendRollback => "overlay.append.rollback",
            Self::SweepRemove => "overlay.sweep.remove",
            Self::TailCut => "overlay.tail.cut",
            Self::ReplaceBuild => "overlay.replace.build",
            Self::ReplaceDirSync => "overlay.replace.dir_sync",
            Self::ReplaceQuiesced => "overlay.replace.quiesced",
            Self::ReplaceRename => "overlay.replace.rename",
            Self::ReplaceSwitched => "overlay.replace.switched",
            Self::ReplaceSync => "overlay.replace.sync",
            Self::RetireMarkClear => "overlay.retire.mark_clear",
            Self::CarryMarkClear => "overlay.carry.mark_clear",
            Self::RetireUnlink => "overlay.retire.unlink",
            Self::Writer => "overlay.writer",
        }
    }
}

/// A registered sync-engine fault seam; caller-supplied labels are unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncFaultPoint {
    /// A capture boundary was taken.
    Capture,
    /// A bin upload.
    Upload,
    /// A tree-node upload.
    NodeUpload,
    /// A write-intent registration.
    Registration,
    /// A reply to the waiting caller.
    Reply,
    /// A commit step.
    Commit,
    /// The wait before a commit.
    CommitWait,
    /// Stage-floor readiness check before awaiting a retained capture release.
    Floor,
    /// Mount view observation and cache-generation barrier.
    FuseSyncView,
    /// Directory sync admission after a journalled rename.
    FuseSyncRenameDirectory,
    /// Mount sync completion before FUSE reply delivery.
    FuseSyncReply,
    /// A landing's view install, around its switch.
    FuseViewInstall,
    /// A seam this build does not name.
    Other,
}
impl SyncFaultPoint {
    const ALL: &'static [Self] = &[
        Self::Capture,
        Self::Upload,
        Self::NodeUpload,
        Self::Registration,
        Self::Reply,
        Self::Commit,
        Self::CommitWait,
        Self::Floor,
        Self::FuseSyncView,
        Self::FuseSyncRenameDirectory,
        Self::FuseSyncReply,
        Self::FuseViewInstall,
        Self::Other,
    ];

    /// The point a seam names; an unnamed seam is [`Self::Other`], never silence.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn from_seam(name: &str) -> Self {
        Self::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == name)
            .unwrap_or(Self::Other)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "sync.capture",
            Self::Upload => "sync.upload",
            Self::NodeUpload => "sync.node_upload",
            Self::Registration => "sync.registration",
            Self::Reply => "sync.reply",
            Self::Commit => "sync.commit",
            Self::CommitWait => "sync.commit_wait",
            Self::Floor => "sync.floor",
            Self::FuseSyncView => "fuse.sync.view",
            Self::FuseSyncRenameDirectory => "fuse.sync.rename_directory",
            Self::FuseSyncReply => "fuse.sync.reply",
            Self::FuseViewInstall => "fuse.view.install",
            Self::Other => "other",
        }
    }
}

/// Which step of a sync-engine seam was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncFaultPhase {
    /// Before the step.
    Before,
    /// After the step.
    After,
    /// The remote accepted the object.
    Accepted,
    /// The candidate was captured.
    Captured,
    /// The commit boundary was recorded durably, before the submission is retained.
    BoundaryRecorded,
    /// Before the retained publication attempt is charged and saved.
    BeforeSubmit,
    /// Before a retained commit is merged onto a newer head.
    BeforeRebase,
    /// After a retained commit's rebased candidate was saved durably.
    AfterRebase,
    /// After the landed refresh was journaled, before the landed base replaces the overlay's.
    BeforeReplace,
    /// Before a registration was dispatched.
    BeforeDispatch,
    /// After a registration response arrived.
    AfterResponse,
    /// After the landed head was read back.
    LandedReadback,
    /// After the landed head was refreshed.
    LandedRefresh,
    /// Stage floor was checked after notification registration.
    Checked,
    /// Mount view context was observed.
    Observed,
    /// Mount completion tokens were admitted to the observed generation.
    Cleared,
    /// The session accepted the landed root, before the view switches.
    BeforeSwitch,
    /// The view switched, before held objects take their own material.
    AfterSwitch,
    /// A step this build does not name.
    Other,
}
impl SyncFaultPhase {
    const ALL: &'static [Self] = &[
        Self::Before,
        Self::After,
        Self::Accepted,
        Self::Captured,
        Self::BoundaryRecorded,
        Self::BeforeSubmit,
        Self::BeforeRebase,
        Self::AfterRebase,
        Self::BeforeReplace,
        Self::BeforeDispatch,
        Self::AfterResponse,
        Self::LandedReadback,
        Self::LandedRefresh,
        Self::Checked,
        Self::Observed,
        Self::Cleared,
        Self::BeforeSwitch,
        Self::AfterSwitch,
        Self::Other,
    ];

    /// The phase a seam names; an unnamed phase is [`Self::Other`], never silence.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn from_seam(name: &str) -> Self {
        Self::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == name)
            .unwrap_or(Self::Other)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Accepted => "accepted",
            Self::Captured => "captured",
            Self::BoundaryRecorded => "boundary_recorded",
            Self::BeforeSubmit => "before_submit",
            Self::BeforeRebase => "before_rebase",
            Self::AfterRebase => "after_rebase",
            Self::BeforeReplace => "before_replace",
            Self::BeforeDispatch => "before_dispatch",
            Self::AfterResponse => "after_response",
            Self::LandedReadback => "landed_readback",
            Self::LandedRefresh => "landed_refresh",
            Self::Checked => "checked",
            Self::Observed => "observed",
            Self::Cleared => "cleared",
            Self::BeforeSwitch => "before_switch",
            Self::AfterSwitch => "after_switch",
            Self::Other => "other",
        }
    }
}

/// The kind of object a sync-engine seam concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncObjectKind {
    /// No object.
    None,
    /// A bin.
    Bin,
    /// A directory manifest node.
    Manifest,
    /// A grain-list node.
    GrainList,
    /// A binmap node.
    Binmap,
    /// A sheaf.
    Sheaf,
    /// A directory sync target.
    Directory,
    /// A kind this build does not name.
    Other,
}
impl SyncObjectKind {
    const ALL: &'static [Self] = &[
        Self::None,
        Self::Bin,
        Self::Manifest,
        Self::GrainList,
        Self::Binmap,
        Self::Sheaf,
        Self::Directory,
        Self::Other,
    ];

    /// The kind a seam names; an unnamed kind is [`Self::Other`], never silence.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn from_seam(name: &str) -> Self {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == name)
            .unwrap_or(Self::Other)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bin => "bin",
            Self::Manifest => "manifest",
            Self::GrainList => "grain_list",
            Self::Binmap => "binmap",
            Self::Sheaf => "sheaf",
            Self::Directory => "directory",
            Self::Other => "other",
        }
    }
}

/// The wire operation identity, minted by its identity owner or the
/// retained-submission coordinator.
/// It has no conversion from strings, configuration, or caller-supplied bytes.
///
/// ```compile_fail,E0423
/// use granary_client::PublishOperationId;
/// let forged = PublishOperationId(vec![42]);
/// ```
pub struct PublishOperationId(Vec<u8>);
impl std::fmt::Debug for PublishOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<publish-operation>")
    }
}

/// Refusal to mint a wire identity.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishOperationRefusal {
    /// The wire requires between one and 255 bytes inclusive.
    Length,
    /// The identity owner could not obtain entropy.
    Entropy,
}
impl PublishOperationId {
    /// Mint a wire identity without truncation.
    ///
    /// # Errors
    /// Refuses zero or more than 255 bytes before drawing; refuses unavailable entropy.
    pub fn draw<R: SecureRandom + ?Sized>(
        random: &mut R,
        length: usize,
    ) -> Result<Self, PublishOperationRefusal> {
        if !(1..=255).contains(&length) {
            return Err(PublishOperationRefusal::Length);
        }
        let mut bytes = vec![0; length];
        random
            .fill(&mut bytes)
            .map_err(|_| PublishOperationRefusal::Entropy)?;
        Ok(Self(bytes))
    }

    /// The 16-byte operation identity the retained-submission coordinator holds.
    pub(crate) fn from_retained(operation: [u8; 16]) -> Self {
        Self(operation.to_vec())
    }
}

/// An event with an exhaustive schema and private payload.
/// No generic setter, string payload, formatted error, or serialization entry exists.
///
/// ```
/// use granary_client::{ClientEvent, FailureClass, OperationKind};
/// let event = ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io);
/// let (log, bundle) = event.project();
/// assert!(!log.as_bytes().is_empty());
/// assert!(!bundle.as_bytes().is_empty());
/// ```
/// ```compile_fail,E0308
/// use granary_client::{ClientEvent, OperationKind};
/// let event = ClientEvent::op_failed(OperationKind::Commit, "secret");
/// ```
/// ```compile_fail,E0308
/// use granary_client::{ClientEvent, OperationKind};
/// let event = ClientEvent::op_failed(OperationKind::Commit, &[42_u8]);
/// ```
/// ```compile_fail,E0308
/// use granary_client::{ClientEvent, OperationKind};
/// let credential_path = std::path::Path::new("synthetic-key");
/// let event = ClientEvent::op_failed(OperationKind::Commit, credential_path);
/// ```
/// ```compile_fail,E0560
/// use granary_client::ClientEvent;
/// let event = ClientEvent { unknown_field: 42 };
/// ```
/// ```compile_fail,E0616
/// use granary_client::{ClientEvent, FailureClass, OperationKind};
/// let mut event = ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io);
/// event.payload = unreachable!();
/// ```
#[derive(Debug)]
pub struct ClientEvent {
    payload: Payload,
}

#[derive(Debug)]
enum Payload {
    Conflict,
    Recovery(
        RecoveryClass,
        u64,
        u64,
        u64,
        u64,
        bool,
        OverlayOwed,
        [u64; 2],
    ),
    StageRolledBack(u64, u64, u64, u64, u64, bool),
    Refused(FailureClass, u64, u64, u64),
    DiscardRefused(crate::OverlayRefusal),
    ReconcileRefused(crate::OverlayRefusal),
    Sweep(u64, u64),
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    Fault(OverlayFaultPoint, FaultPhase, u64, u64),
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    SyncFault(SyncFaultPoint, SyncFaultPhase, u64, SyncObjectKind),
    Begin(OperationKind),
    End(OperationKind, Outcome),
    Retry(OperationKind, u32, RetryReason),
    Failed(OperationKind, FailureClass),
    MetricsExportFailed(super::MetricsFailureClass),
    FailuresDropped(u64),
    Contention(u64, u64),
    Backoff(super::BackoffCause, super::BackoffOutcome),
    Workspace(u64, u64),
    CapExhausted(u64, u64, u64, u64, u64),
    CommitStopped(super::CommitStopCause),
    Recover(super::RecoverEvent),
    Publish(PublishOperationId),
    Config(LogFormat, LogDestination),
    Filter(FilterSource, FilterRejection, FilterDetail),
    View(super::ViewCause, super::ViewOutcome, u64),
    Unmounted(super::UnmountTrigger, super::UnmountOutcome, u64, u64),
    UnmountLeft(
        super::UnmountTrigger,
        super::UnmountOutcome,
        super::UnmountCause,
        Option<[u64; 3]>,
        u64,
    ),
    Diagnostic(diagnostics::Diagnostic),
}

/// A telemetry projection, already encoded before storage.
///
/// ```compile_fail,E0308
/// use granary_client::{BundleRecord, LogRecord};
/// fn tee(log: LogRecord) -> BundleRecord { log }
/// ```
pub struct LogRecord(String);
impl std::fmt::Debug for LogRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<log-record>")
    }
}
impl LogRecord {
    /// Borrow only the approved encoded projection.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// An independently encoded, redacted bundle input. Its constructor is private.
///
/// ```compile_fail,E0423
/// use granary_client::BundleRecord;
/// let record = BundleRecord(String::from("synthetic local status"));
/// ```
#[derive(Clone)]
pub struct BundleRecord(String);
impl std::fmt::Debug for BundleRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<bundle-record>")
    }
}
impl BundleRecord {
    /// Borrow the redacted bundle projection as its original JSON record.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrow the redacted bundle projection, without a rendered-log input seam.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl ClientEvent {
    /// Report an operational refusal from overlay discard.
    #[must_use]
    pub fn overlay_discard_refused(reason: crate::OverlayRefusal) -> Self {
        Self {
            payload: Payload::DiscardRefused(reason),
        }
    }

    /// Report an operational refusal from overlay reconciliation.
    #[must_use]
    pub fn overlay_reconcile_refused(reason: crate::OverlayRefusal) -> Self {
        Self {
            payload: Payload::ReconcileRefused(reason),
        }
    }

    /// Report that explicit recovery could not use the existing signing seed.
    #[must_use]
    pub fn recovery_signing_key_refused() -> Self {
        Self::recover(super::RecoverEvent::SigningKeyRefused)
    }

    const fn bundle_event_tag(&self) -> Option<u8> {
        match self.payload {
            Payload::Failed(_, _) => Some(1),
            Payload::Refused(_, _, _, _) => Some(2),
            _ => None,
        }
    }

    fn bundle_failure(&self) -> Option<(u8, u8, u8)> {
        let event = self.bundle_event_tag()?;
        match self.payload {
            Payload::Failed(kind, class) => Some((event, kind.bundle_tag(), class.bundle_tag())),
            Payload::Refused(class, _, _, _) => Some((event, 0, class.bundle_tag())),
            _ => None,
        }
    }

    /// A namespace conflict detail with no raw path input.
    #[must_use]
    pub fn conflict_detail() -> Self {
        Self {
            payload: Payload::Conflict,
        }
    }

    /// Report a recovery outcome with counts, the journal index, the cap,
    /// whether the recovered overlay requests a commit, and what it owes above
    /// the cap with the reserve terms that hold it.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "recovery reports the full measured summary"
    )]
    pub fn overlay_recovery(
        outcome: RecoveryClass,
        files: u64,
        bytes: u64,
        record_index: u64,
        cap: u64,
        commit_requested: bool,
        owed: OverlayOwed,
        rollback_counts: [u64; 2],
    ) -> Self {
        Self {
            payload: Payload::Recovery(
                outcome,
                files,
                bytes,
                record_index,
                cap,
                commit_requested,
                owed,
                rollback_counts,
            ),
        }
    }
    /// Report a durable stage rollback. Named stages carry a redacted path slot.
    #[must_use]
    pub fn stage_rolled_back(
        seq: u64,
        stage_id: u64,
        old_size: u64,
        restored_size: u64,
        discarded_bytes: u64,
        named: bool,
    ) -> Self {
        Self {
            payload: Payload::StageRolledBack(
                seq,
                stage_id,
                old_size,
                restored_size,
                discarded_bytes,
                named,
            ),
        }
    }
    /// Report a refused overlay with counts and the journal index.
    #[must_use]
    pub fn overlay_refused(class: FailureClass, record_index: u64, files: u64, bytes: u64) -> Self {
        Self {
            payload: Payload::Refused(class, record_index, files, bytes),
        }
    }
    /// Report swept files and bytes.
    #[must_use]
    pub fn overlay_sweep(files: u64, bytes: u64) -> Self {
        Self {
            payload: Payload::Sweep(files, bytes),
        }
    }
    /// Report a typed, feature-gated fault seam.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    #[must_use]
    pub fn overlay_fault(
        point: OverlayFaultPoint,
        phase: FaultPhase,
        occurrence: u64,
        record_index: u64,
    ) -> Self {
        Self {
            payload: Payload::Fault(point, phase, occurrence, record_index),
        }
    }
    /// Report a typed, feature-gated sync-engine fault seam.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    #[must_use]
    pub fn sync_fault(
        point: SyncFaultPoint,
        phase: SyncFaultPhase,
        occurrence: u64,
        object_kind: SyncObjectKind,
    ) -> Self {
        Self {
            payload: Payload::SyncFault(point, phase, occurrence, object_kind),
        }
    }
    /// Report an operation beginning.
    #[must_use]
    pub fn op_begin(kind: OperationKind) -> Self {
        Self {
            payload: Payload::Begin(kind),
        }
    }
    /// Report an operation ending.
    #[must_use]
    pub fn op_end(kind: OperationKind, outcome: Outcome) -> Self {
        Self {
            payload: Payload::End(kind, outcome),
        }
    }
    /// Report a retry attempt and closed reason.
    #[must_use]
    pub fn op_retry(kind: OperationKind, attempt: u32, reason: RetryReason) -> Self {
        Self {
            payload: Payload::Retry(kind, attempt, reason),
        }
    }
    /// Report an operation failure with a closed class.
    #[must_use]
    pub fn op_failed(kind: OperationKind, class: FailureClass) -> Self {
        Self {
            payload: Payload::Failed(kind, class),
        }
    }
    /// Report a failure of the metrics exporter.
    #[must_use]
    pub fn metrics_export_failed(class: super::MetricsFailureClass) -> Self {
        Self {
            payload: Payload::MetricsExportFailed(class),
        }
    }
    /// Report deferred overlay failures exceeding the callback's buffer cap.
    #[must_use]
    pub(crate) fn overlay_failures_dropped(dropped: u64) -> Self {
        Self {
            payload: Payload::FailuresDropped(dropped),
        }
    }
    /// Report the rising edge of the advisory terminal contention rate.
    #[must_use]
    pub(crate) fn commit_contention(commits: u64, conflicts: u64) -> Self {
        Self {
            payload: Payload::Contention(commits, conflicts),
        }
    }
    /// Report a live commit retry episode's transition.
    #[must_use]
    pub(crate) fn commit_backoff(
        cause: super::BackoffCause,
        outcome: super::BackoffOutcome,
    ) -> Self {
        Self {
            payload: Payload::Backoff(cause, outcome),
        }
    }
    /// Report only the closed local workspace refusal and its byte counts.
    pub(crate) fn workspace_exhausted(needed: u64, limit: u64) -> Self {
        Self {
            payload: Payload::Workspace(needed, limit),
        }
    }
    /// Report a logical overlay-cap refusal and its closed byte accounting.
    pub(crate) fn overlay_cap_exhausted(
        cap: u64,
        charged: u64,
        reserved: u64,
        captured: u64,
        needed: u64,
    ) -> Self {
        Self {
            payload: Payload::CapExhausted(cap, charged, reserved, captured, needed),
        }
    }
    /// Report that a live commit loop stopped before shutdown.
    #[must_use]
    pub(crate) fn commit_stopped(cause: super::CommitStopCause) -> Self {
        Self {
            payload: Payload::CommitStopped(cause),
        }
    }
    /// Report what an explicit recovery found or did.
    #[must_use]
    pub(crate) fn recover(event: super::RecoverEvent) -> Self {
        Self {
            payload: Payload::Recover(event),
        }
    }
    /// Join an identity minted by the publication owner to the operation span.
    #[must_use]
    pub fn publish_bound(identity: PublishOperationId) -> Self {
        Self {
            payload: Payload::Publish(identity),
        }
    }
    /// Report the active log format and destination classes.
    #[must_use]
    pub fn log_config(format: LogFormat, destination: LogDestination) -> Self {
        Self {
            payload: Payload::Config(format, destination),
        }
    }
    /// Report a refused filter without retaining its input or parser chain.
    #[must_use]
    pub fn log_filter_rejected(
        source: FilterSource,
        reason: FilterRejection,
        detail: FilterDetail,
    ) -> Self {
        Self {
            payload: Payload::Filter(source, reason, detail),
        }
    }

    /// Report how a view change for `cause` at `seq` ended.
    #[must_use]
    pub(crate) fn mount_view(
        cause: super::ViewCause,
        outcome: super::ViewOutcome,
        seq: u64,
    ) -> Self {
        Self {
            payload: Payload::View(cause, outcome, seq),
        }
    }

    /// Report a shutdown `trigger` ran that ended as `outcome` on the base
    /// at `seq`.
    #[must_use]
    pub(crate) fn mount_unmounted(
        trigger: super::UnmountTrigger,
        outcome: super::UnmountOutcome,
        seq: u64,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            payload: Payload::Unmounted(trigger, outcome, seq, elapsed_ms),
        }
    }

    /// Report a shutdown `trigger` ran that ended as `outcome` for `cause`,
    /// with what it left when that could be read.
    #[must_use]
    pub(crate) fn mount_unmount_left(
        trigger: super::UnmountTrigger,
        outcome: super::UnmountOutcome,
        cause: super::UnmountCause,
        counts: Option<[u64; 3]>,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            payload: Payload::UnmountLeft(trigger, outcome, cause, counts, elapsed_ms),
        }
    }

    /// The registered static callsite this event emits from, without building its values.
    pub(crate) fn meta(&self) -> &'static Metadata<'static> {
        match &self.payload {
            Payload::Conflict => &CONFLICT_META,
            Payload::Diagnostic(d) => d.meta(),
            Payload::Recovery(..) => &RECOVERY_META,
            Payload::StageRolledBack(.., true) => &STAGE_ROLLED_BACK_META,
            Payload::StageRolledBack(.., false) => &DETACHED_STAGE_ROLLED_BACK_META,
            Payload::Refused(..) => &REFUSED_META,
            Payload::DiscardRefused(_) => &DISCARD_REFUSED_META,
            Payload::ReconcileRefused(_) => &RECONCILE_REFUSED_META,
            Payload::Sweep(..) => &SWEEP_META,
            #[cfg(any(test, feature = "overlay-fault-tests"))]
            Payload::Fault(..) => &FAULT_META,
            #[cfg(any(test, feature = "overlay-fault-tests"))]
            Payload::SyncFault(..) => &SYNC_FAULT_META,
            Payload::Begin(_) => &BEGIN_META,
            Payload::End(..) => &END_META,
            Payload::Retry(..) => &RETRY_META,
            Payload::Failed(..) => &FAILED_META,
            Payload::MetricsExportFailed(_) => &METRICS_EXPORT_FAILED_META,
            Payload::FailuresDropped(_) => &DROPPED_META,
            Payload::Contention(..) => &CONTENTION_META,
            Payload::Backoff(_, super::BackoffOutcome::Entered) => &BACKOFF_ENTERED_META,
            Payload::Backoff(_, super::BackoffOutcome::Recovered { .. }) => &BACKOFF_RECOVERED_META,
            Payload::Workspace(..) => &WORKSPACE_META,
            Payload::CapExhausted(..) => &CAP_EXHAUSTED_META,
            Payload::CommitStopped(_) => &COMMIT_STOPPED_META,
            Payload::Recover(event) => match event {
                super::RecoverEvent::JournalFinished(_) => &RECOVER_FINISHED_META,
                super::RecoverEvent::JournalBlocked(_) => &RECOVER_BLOCKED_META,
                super::RecoverEvent::Nothing => &RECOVER_NOTHING_META,
                super::RecoverEvent::SigningKeyRefused => &RECOVER_SIGNING_KEY_REFUSED_META,
                super::RecoverEvent::Subsumed(..) => &RECOVER_SUBSUMED_META,
                super::RecoverEvent::Stale => &RECOVER_STALE_META,
                super::RecoverEvent::Landed(_) => &RECOVER_LANDED_META,
                super::RecoverEvent::ArchivedLanded(_) => &RECOVER_ARCHIVED_LANDED_META,
                super::RecoverEvent::Rebased(_) => &RECOVER_REBASED_META,
                super::RecoverEvent::Conflict => &RECOVER_CONFLICT_META,
                super::RecoverEvent::SelectionChanged(_) => &RECOVER_SELECTION_META,
                super::RecoverEvent::LandedUnowned => &RECOVER_UNOWNED_META,
                super::RecoverEvent::FenceSettled(_) => &RECOVER_FENCE_META,
                super::RecoverEvent::Unresolved(_) => &RECOVER_UNRESOLVED_META,
                super::RecoverEvent::Resent(_) => &RECOVER_RESENT_META,
            },
            Payload::Publish(_) => &PUBLISH_META,
            Payload::Config(..) => &CONFIG_META,
            Payload::Filter(..) => &FILTER_META,
            Payload::View(
                _,
                super::ViewOutcome::Installed
                | super::ViewOutcome::Deferred
                | super::ViewOutcome::Fresh,
                _,
            ) => &VIEW_INSTALLED_META,
            Payload::View(_, super::ViewOutcome::Refused | super::ViewOutcome::Stale, _) => {
                &VIEW_REFUSED_META
            }
            Payload::Unmounted(..) => &UNMOUNTED_META,
            Payload::UnmountLeft(_, _, _, Some(_), _) => &UNMOUNT_LEFT_META,
            Payload::UnmountLeft(_, _, _, None, _) => &UNMOUNT_UNREAD_META,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one closed match encodes every event's fields in its schema order"
    )]
    fn fields(&self) -> (&'static Metadata<'static>, Vec<Scalar>) {
        let (meta, fields) = match &self.payload {
            Payload::DiscardRefused(reason) | Payload::ReconcileRefused(reason) => {
                (self.meta(), vec![Scalar::text(reason.as_str())])
            }
            Payload::Conflict => (
                &CONFLICT_META,
                vec![Scalar::text("<file>"), Scalar::text("conflict")],
            ),
            Payload::Diagnostic(d) => return d.fields(),
            Payload::Recovery(o, f, b, i, cap, requested, owed, [stages, bytes]) => (
                &RECOVERY_META,
                vec![
                    Scalar::text(o.as_str()),
                    Scalar::Number(*f),
                    Scalar::Number(*b),
                    Scalar::Number(*i),
                    Scalar::Number(*cap),
                    Scalar::Bool(*requested),
                    Scalar::Number(owed.owed),
                    Scalar::Number(owed.stages),
                    Scalar::Number(owed.projected),
                    Scalar::Number(owed.ownership),
                    Scalar::Number(owed.completion),
                    Scalar::Number(owed.writer),
                    Scalar::Number(owed.journal),
                    Scalar::Number(*stages),
                    Scalar::Number(*bytes),
                ],
            ),
            Payload::StageRolledBack(seq, id, old, restored, discarded, named) => {
                let mut fields = vec![
                    Scalar::Number(*seq),
                    Scalar::Number(*id),
                    Scalar::Number(*old),
                    Scalar::Number(*restored),
                    Scalar::Number(*discarded),
                ];
                if *named {
                    fields.push(Scalar::text("<file>"));
                }
                (self.meta(), fields)
            }
            Payload::Refused(c, i, f, b) => (
                &REFUSED_META,
                vec![
                    Scalar::text(c.as_str()),
                    Scalar::Number(*i),
                    Scalar::Number(*f),
                    Scalar::Number(*b),
                ],
            ),
            Payload::Sweep(f, b) => (&SWEEP_META, vec![Scalar::Number(*f), Scalar::Number(*b)]),
            #[cfg(any(test, feature = "overlay-fault-tests"))]
            Payload::Fault(p, phase, o, i) => (
                &FAULT_META,
                vec![
                    Scalar::text(p.as_str()),
                    Scalar::text(phase.as_str()),
                    Scalar::Number(*o),
                    Scalar::Number(*i),
                ],
            ),
            #[cfg(any(test, feature = "overlay-fault-tests"))]
            Payload::SyncFault(p, phase, o, k) => (
                &SYNC_FAULT_META,
                vec![
                    Scalar::text(p.as_str()),
                    Scalar::text(phase.as_str()),
                    Scalar::Number(*o),
                    Scalar::text(k.as_str()),
                ],
            ),
            Payload::Begin(k) => (&BEGIN_META, vec![Scalar::text(k.as_str())]),
            Payload::End(k, o) => (
                &END_META,
                vec![Scalar::text(k.as_str()), Scalar::text(o.as_str())],
            ),
            Payload::Retry(k, a, r) => (
                &RETRY_META,
                vec![
                    Scalar::text(k.as_str()),
                    Scalar::Number(u64::from(*a)),
                    Scalar::text(r.as_str()),
                ],
            ),
            Payload::Failed(k, c) => (
                &FAILED_META,
                vec![Scalar::text(k.as_str()), Scalar::text(c.as_str())],
            ),
            Payload::MetricsExportFailed(class) => (
                &METRICS_EXPORT_FAILED_META,
                vec![Scalar::text(class.as_str())],
            ),
            Payload::FailuresDropped(dropped) => (&DROPPED_META, vec![Scalar::Number(*dropped)]),
            Payload::Contention(commits, conflicts) => (
                &CONTENTION_META,
                vec![Scalar::Number(*commits), Scalar::Number(*conflicts)],
            ),
            Payload::Backoff(cause, outcome) => {
                let mut fields = vec![Scalar::text(cause.as_str()), Scalar::text(outcome.as_str())];
                if let super::BackoffOutcome::Recovered { attempts } = outcome {
                    fields.push(Scalar::Number(*attempts));
                }
                (self.meta(), fields)
            }
            Payload::Workspace(needed, limit) => (
                &WORKSPACE_META,
                vec![
                    Scalar::text("SyncWorkspaceExhausted"),
                    Scalar::Number(*needed),
                    Scalar::Number(*limit),
                ],
            ),
            Payload::CapExhausted(cap, charged, reserved, captured, needed) => (
                &CAP_EXHAUSTED_META,
                vec![
                    Scalar::text("OverlayCapacityExhausted"),
                    Scalar::Number(*cap),
                    Scalar::Number(*charged),
                    Scalar::Number(*reserved),
                    Scalar::Number(*captured),
                    Scalar::Number(*needed),
                ],
            ),
            Payload::CommitStopped(cause) => {
                (&COMMIT_STOPPED_META, vec![Scalar::text(cause.as_str())])
            }
            Payload::Recover(event) => (
                self.meta(),
                match event {
                    super::RecoverEvent::JournalFinished(seq) => vec![Scalar::Number(*seq)],
                    super::RecoverEvent::JournalBlocked(reason) => vec![Scalar::text(reason)],
                    super::RecoverEvent::Subsumed(relation, seq) => {
                        vec![Scalar::text(relation.as_str()), Scalar::Number(*seq)]
                    }
                    super::RecoverEvent::Landed(count) | super::RecoverEvent::Rebased(count) => {
                        vec![Scalar::Number(*count)]
                    }
                    super::RecoverEvent::Conflict => vec![Scalar::text("<file>")],
                    super::RecoverEvent::SelectionChanged(token) => vec![Scalar::text(token)],
                    super::RecoverEvent::FenceSettled(how) => vec![Scalar::text(how)],
                    super::RecoverEvent::ArchivedLanded(seq)
                    | super::RecoverEvent::Unresolved(seq)
                    | super::RecoverEvent::Resent(seq) => {
                        vec![Scalar::Number(*seq)]
                    }
                    super::RecoverEvent::SigningKeyRefused
                    | super::RecoverEvent::Nothing
                    | super::RecoverEvent::Stale
                    | super::RecoverEvent::LandedUnowned => vec![],
                },
            ),
            Payload::Publish(id) => {
                let mut hex = String::with_capacity(id.0.len() * 2);
                for byte in &id.0 {
                    let _ = write!(hex, "{byte:02x}");
                }
                (&PUBLISH_META, vec![Scalar::Text(hex)])
            }
            Payload::Config(f, d) => (
                &CONFIG_META,
                vec![Scalar::text(f.as_str()), Scalar::text(d.as_str())],
            ),
            Payload::Filter(s, r, d) => (
                &FILTER_META,
                vec![
                    Scalar::text(s.as_str()),
                    Scalar::text(r.as_str()),
                    Scalar::text(d.as_str()),
                ],
            ),
            Payload::View(cause, outcome, seq) => (
                self.meta(),
                vec![
                    Scalar::text(cause.as_str()),
                    Scalar::text(outcome.as_str()),
                    Scalar::Number(*seq),
                ],
            ),
            Payload::Unmounted(trigger, outcome, seq, elapsed) => (
                &UNMOUNTED_META,
                vec![
                    Scalar::text(trigger.as_str()),
                    Scalar::text(outcome.as_str()),
                    Scalar::Number(*seq),
                    Scalar::Number(*elapsed),
                ],
            ),
            Payload::UnmountLeft(trigger, outcome, cause, counts, elapsed) => {
                let mut fields = vec![
                    Scalar::text(trigger.as_str()),
                    Scalar::text(outcome.as_str()),
                    Scalar::text(cause.as_str()),
                ];
                fields.extend(counts.iter().flatten().map(|count| Scalar::Number(*count)));
                fields.push(Scalar::Number(*elapsed));
                (self.meta(), fields)
            }
        };
        let mut all = vec![Scalar::text(meta.name())];
        all.extend(fields);
        (meta, all)
    }

    /// Make separate opaque log and bundle projections synchronously.
    /// Neither projection accepts the other's rendered bytes.
    #[must_use]
    pub fn project(&self) -> (LogRecord, BundleRecord) {
        let (meta, fields) = self.fields();
        (
            LogRecord(encode(meta, &fields, &[], LogFormat::Json)),
            BundleRecord(encode(meta, &fields, &[], LogFormat::Json)),
        )
    }

    pub(crate) fn project_operation(
        &self,
        id: CorrelationId,
        kind: OperationKind,
    ) -> (LogRecord, BundleRecord) {
        let (meta, fields) = self.fields();
        let spans = [vec![
            Scalar::Text(id.to_string()),
            Scalar::text(kind.as_str()),
        ]];
        (
            LogRecord(encode(meta, &fields, &spans, LogFormat::Json)),
            BundleRecord(encode(meta, &fields, &spans, LogFormat::Json)),
        )
    }

    /// Emit approved scalars from this event's registered static callsite.
    pub fn emit(&self) {
        self.emit_paths(&[]);
    }

    pub(crate) fn emit_paths(&self, slots: &[PathSlot<'_>]) {
        let meta = self.meta();
        tracing::dispatcher::get_default(|dispatch| {
            let context = dispatch.downcast_ref::<ProjectionLayer>();
            if let (Some(layer), Some((event, kind, class))) = (context, self.bundle_failure()) {
                layer.0.history.record_failure(
                    event,
                    kind,
                    class,
                    layer.0.current_operation_correlation(),
                );
            }
            // Failure retention precedes filter admission so a quiet telemetry
            // policy cannot starve the session's failure ring.
            let telemetry = dispatch.enabled(meta);
            let bundled = context.is_some() && bundle_admits(meta);
            // Other projections are built only when their own policy admits them.
            if !telemetry && !bundled {
                return;
            }
            let (_, redacted) = self.fields();
            let policy = context.map_or(LogPaths::Redacted, |layer| layer.0.paths);
            let fields = telemetry.then(|| project_slots(meta, &redacted, slots, policy));
            if let (true, Some(layer)) = (bundled, context) {
                // The bundle always takes the redacted projection; it reuses the
                // telemetry one only when that is the same bytes.
                let owned;
                let bundle_fields = if let (Some(fields), LogPaths::Redacted) = (&fields, policy) {
                    fields
                } else {
                    owned = project_slots(meta, &redacted, slots, LogPaths::Redacted);
                    &owned
                };
                let scope = layer.0.scope();
                layer.0.history.record(BundleRecord(encode(
                    meta,
                    bundle_fields,
                    &scope,
                    LogFormat::Json,
                )));
            }
            if let Some(fields) = fields {
                let values: Vec<Option<&dyn Value>> =
                    fields.iter().map(|v| Some(v.value())).collect();
                dispatch.event(&Event::new(meta, &meta.fields().value_set_all(&values)));
            }
        });
    }
}

/// Open a registered operation span using scalar correlation fields.
#[must_use]
pub fn closed_operation_span(kind: OperationKind, id: &CorrelationId) -> tracing::Span {
    let op = id.to_string();
    let kind = kind.as_str();
    let values: [Option<&dyn Value>; 2] = [Some(&op), Some(&kind)];
    tracing::dispatcher::get_default(|dispatch| {
        // Bundle records carry the operation id whatever the telemetry filter
        // says, so the span exists whenever the bundle projection is installed.
        let span = if dispatch.enabled(&OPERATION_META)
            || dispatch.downcast_ref::<ProjectionLayer>().is_some()
        {
            tracing::Span::new_with(
                &OPERATION_META,
                &OPERATION_META.fields().value_set_all(&values),
                dispatch,
            )
        } else {
            tracing::Span::none()
        };
        if let (Some(layer), Some(span_id)) =
            (dispatch.downcast_ref::<ProjectionLayer>(), span.id())
        {
            layer
                .0
                .operation_correlations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(span_id.into_u64(), id.bytes());
        }
        span
    })
}

#[derive(Clone, Debug)]
enum Scalar {
    Text(String),
    Number(u64),
    Bool(bool),
}
impl Scalar {
    fn text(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}
impl Scalar {
    fn value(&self) -> &dyn Value {
        match self {
            Self::Text(s) => s,
            Self::Number(n) => n,
            Self::Bool(b) => b,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    UnregisteredCallsite,
    InvalidSchema,
    InvalidScalar,
    InvalidDomain,
    DebugField,
    RecordTooLarge,
}
impl Refusal {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UnregisteredCallsite => "unregistered_callsite",
            Self::InvalidSchema => "invalid_schema",
            Self::InvalidScalar => "invalid_scalar",
            Self::InvalidDomain => "invalid_domain",
            Self::DebugField => "debug_field",
            Self::RecordTooLarge => "record_too_large",
        }
    }
}

/// The address of the callsite a piece of metadata belongs to. `Identifier`
/// compares by this address but hashes the vtable pointer too, which two
/// codegen units may disagree on, so the address alone is the key.
fn identity(meta: &Metadata<'_>) -> usize {
    std::ptr::from_ref(meta.callsite().0).cast::<()>().addr()
}

/// The registered callsites, keyed by the callsite identity their static
/// metadata carries. A foreign callsite has another identity whatever it copies.
fn registry() -> &'static BTreeMap<usize, &'static Metadata<'static>> {
    static REGISTRY: std::sync::OnceLock<BTreeMap<usize, &'static Metadata<'static>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        SITES
            .iter()
            .chain(diagnostics::SITES.iter())
            .map(|site| (identity(site), *site))
            .collect()
    })
}

fn registered(meta: &Metadata<'_>) -> Option<&'static Metadata<'static>> {
    let site = *registry().get(&identity(meta))?;
    (meta.target() == site.target()
        && meta.file().is_some()
        && meta.line().is_some()
        && meta.file() == site.file()
        && meta.line() == site.line())
    .then_some(site)
}

fn same_schema(meta: &Metadata<'_>, site: &Metadata<'_>) -> bool {
    meta.name() == site.name()
        && meta.level() == site.level()
        && meta.is_span() == site.is_span()
        && meta
            .fields()
            .iter()
            .map(|f| f.name())
            .eq(site.fields().iter().map(|f| f.name()))
}

fn numeric(name: &str) -> bool {
    matches!(
        name,
        "needed"
            | "limit"
            | "charged"
            | "reserved"
            | "captured"
            | "files"
            | "bytes"
            | "record_index"
            | "rollback_seq"
            | "stage_id"
            | "old_size"
            | "restored_size"
            | "discarded_bytes"
            | "rolled_back_stages"
            | "rolled_back_bytes"
            | "cap"
            | "owed"
            | "stage_reserve"
            | "projected_reserve"
            | "ownership_reserve"
            | "completion_reserve"
            | "writer_reserve"
            | "journal_reserve"
            | "occurrence"
            | "attempt"
            | "commits"
            | "conflicts"
            | "operations"
            | "elapsed_ms"
            | "attempts"
            | "chain_len"
            | "base_seq"
    ) || diagnostics::numeric(name)
}

fn domain(meta: &Metadata<'_>, name: &str, text: &str) -> bool {
    if let Some(admitted) = diagnostics::domain(meta, name, text) {
        return admitted;
    }
    match name {
        "reason"
            if matches!(
                meta.name(),
                "overlay.discard_refused" | "overlay.reconcile_refused"
            ) =>
        {
            crate::OverlayRefusal::admits(text)
        }
        "token" if meta.name() == "recover.selection_changed" => matches!(
            text,
            "none" | "intent-changed" | "intent-superseded" | "intent-absent"
        ),
        "reason" if meta.name() == "recover.journal_blocked" => matches!(
            text,
            "replay"
                | "publication"
                | "obligations"
                | "namespace"
                | "limit"
                | "release"
                | "selected-root-not-proved-published"
        ),
        "how" if meta.name() == "recover.fence_settled" => {
            matches!(text, "landed" | "released" | "stripped")
        }
        "path"
            if matches!(
                meta.name(),
                "op.conflict" | "recover.conflict" | "overlay.stage_rolled_back"
            ) =>
        {
            text == "<file>"
        }
        "relation" if meta.name() == "recover.subsumed" => {
            super::SubsumedRelation::parse(text).is_some()
        }
        "event" => text == meta.name(),
        "kind" => OperationKind::parse(text).is_some(),
        "class" if meta.name() == "op.conflict" => text == "conflict",
        "class" if meta.name() == super::METRICS_EXPORT_FAILED => matches!(text, "io" | "internal"),
        "class" => FailureClass::parse(text).is_some(),
        "outcome" if meta.name() == "overlay.recovery" => {
            matches!(text, "clean" | "repaired" | "pending")
        }
        "cause" if meta.name() == "commit.backoff" => super::BackoffCause::parse(text).is_some(),
        "outcome" if meta.name() == "commit.backoff" => {
            super::BackoffOutcome::parse(text).is_some()
        }
        "cause" if meta.name() == "commit.stopped" => super::CommitStopCause::parse(text).is_some(),
        "cause" if meta.name() == "mount.view" => super::ViewCause::parse(text).is_some(),
        "outcome" if meta.name() == "mount.view" => super::ViewOutcome::parse(text).is_some(),
        "cause" if meta.name() == "mount.unmount" => super::UnmountCause::parse(text).is_some(),
        "outcome" if meta.name() == "mount.unmount" => super::UnmountOutcome::parse(text).is_some(),
        "trigger" if meta.name() == "mount.unmount" => super::UnmountTrigger::parse(text).is_some(),
        "outcome" => Outcome::parse(text).is_some(),
        "reason" if meta.name() == "overlay.cap_exhausted" => text == "OverlayCapacityExhausted",
        "reason" if meta.name() == "sync.workspace_exhausted" => text == "SyncWorkspaceExhausted",
        "reason" if meta.name() == "log.filter_rejected" => FilterRejection::parse(text).is_some(),
        "reason" => RetryReason::parse(text).is_some(),
        "format" => LogFormat::parse(text).is_some(),
        "destination" => LogDestination::parse(text).is_some(),
        "source" => text == FilterSource::RustLog.as_str(),
        "detail" => {
            text == FilterDetail::NotUnicode.as_str() || text == FilterDetail::Malformed.as_str()
        }
        "point" if meta.name() == "sync.fault" => {
            SyncFaultPoint::ALL.iter().any(|p| p.as_str() == text)
        }
        "phase" if meta.name() == "sync.fault" => {
            SyncFaultPhase::ALL.iter().any(|p| p.as_str() == text)
        }
        "object_kind" => SyncObjectKind::ALL.iter().any(|k| k.as_str() == text),
        "point" => OverlayFaultPoint::ALL.iter().any(|p| p.as_str() == text),
        "phase" => FaultPhase::ALL.iter().any(|p| p.as_str() == text),
        "publish_operation" => {
            !text.is_empty()
                && text.len() <= 510
                && text.len().is_multiple_of(2)
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        "op" => text
            .strip_prefix(super::CORRELATION_ID_PREFIX)
            .is_some_and(|hex| {
                hex.len() == 16
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }),
        _ => false,
    }
}

struct Checked<'a> {
    meta: &'a Metadata<'a>,
    values: BTreeMap<&'static str, Scalar>,
    refusal: Option<Refusal>,
    paths: LogPaths,
}
impl<'a> Checked<'a> {
    fn with_paths(meta: &'a Metadata<'a>, paths: LogPaths) -> Self {
        #[cfg(test)]
        VALIDATIONS.with(|count| count.set(count.get() + 1));
        Self {
            meta,
            values: BTreeMap::new(),
            refusal: None,
            paths,
        }
    }
    fn insert(&mut self, field: &Field, value: Scalar) {
        if !self.meta.fields().iter().any(|f| f.name() == field.name())
            || self.values.insert(field.name(), value).is_some()
        {
            self.refusal = Some(Refusal::InvalidSchema);
        }
    }
    fn finish(self, complete: bool) -> Result<Vec<Scalar>, Refusal> {
        if let Some(reason) = self.refusal {
            return Err(reason);
        }
        if complete && self.values.len() != self.meta.fields().len() {
            return Err(Refusal::InvalidSchema);
        }
        Ok(self
            .meta
            .fields()
            .iter()
            .filter_map(|f| self.values.get(f.name()).cloned())
            .collect())
    }
}
impl Visit for Checked<'_> {
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {
        self.refusal = Some(Refusal::DebugField);
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if numeric(field.name()) {
            self.refusal = Some(Refusal::InvalidScalar);
        } else if value.len() > RECORD_MAX {
            self.refusal = Some(Refusal::RecordTooLarge);
        } else if !(domain(self.meta, field.name(), value)
            || (self.paths == LogPaths::Full
                && path_class(self.meta, field.name())
                    .is_some_and(|class| paths::projected_domain(class, value))))
        {
            self.refusal = Some(Refusal::InvalidDomain);
        } else {
            self.insert(field, Scalar::text(value));
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        if numeric(field.name())
            || (field.name() == "age" && self.meta.name().starts_with("client."))
        {
            self.insert(field, Scalar::Number(value));
        } else {
            self.refusal = Some(Refusal::InvalidScalar);
        }
    }
    fn record_i64(&mut self, _: &Field, _: i64) {
        self.refusal = Some(Refusal::InvalidScalar);
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        if (field.name() == "cache_closed"
            && diagnostics::SITES
                .iter()
                .any(|m| m.name() == self.meta.name()))
            || (field.name() == "commit_requested" && self.meta.name() == "overlay.recovery")
        {
            self.insert(field, Scalar::Bool(value));
        } else {
            self.refusal = Some(Refusal::InvalidScalar);
        }
    }
    fn record_f64(&mut self, _: &Field, _: f64) {
        self.refusal = Some(Refusal::InvalidScalar);
    }
    fn record_error(&mut self, _: &Field, _: &(dyn std::error::Error + 'static)) {
        self.refusal = Some(Refusal::InvalidScalar);
    }
}

#[cfg(test)]
fn validate_for_test(
    meta: &'static tracing::Metadata<'static>,
    values: &[(&str, &str)],
) -> Result<(), &'static str> {
    let mut checked = Checked::with_paths(meta, LogPaths::Redacted);
    for &(name, value) in values {
        let field = meta.fields().field(name).ok_or("invalid_schema")?;
        checked.record_str(&field, value);
    }
    if let Some(field) = meta.fields().field("attempts") {
        checked.record_u64(&field, 1);
    }
    checked.finish(true).map(|_| ()).map_err(Refusal::as_str)
}

#[cfg(test)]
pub(super) fn validate_backoff_for_test(cause: &str, outcome: &str) -> Result<(), &'static str> {
    validate_for_test(
        if outcome == "recovered" {
            &BACKOFF_RECOVERED_META
        } else {
            &BACKOFF_ENTERED_META
        },
        &[
            ("event", "commit.backoff"),
            ("cause", cause),
            ("outcome", outcome),
        ],
    )
}

#[cfg(test)]
pub(super) fn validate_commit_stop_for_test(cause: &str) -> Result<(), &'static str> {
    validate_for_test(
        &COMMIT_STOPPED_META,
        &[("event", "commit.stopped"), ("cause", cause)],
    )
}

#[cfg(test)]
pub(super) fn validate_subsumed_for_test(relation: &str) -> Result<(), &'static str> {
    let mut checked = Checked::with_paths(&RECOVER_SUBSUMED_META, LogPaths::Redacted);
    for (name, value) in [("event", "recover.subsumed"), ("relation", relation)] {
        let field = RECOVER_SUBSUMED_META
            .fields()
            .field(name)
            .ok_or("invalid_schema")?;
        checked.record_str(&field, value);
    }
    let field = RECOVER_SUBSUMED_META
        .fields()
        .field("seq")
        .ok_or("invalid_schema")?;
    checked.record_u64(&field, 2);
    checked.finish(true).map(|_| ()).map_err(Refusal::as_str)
}

fn quoted(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn scalar(out: &mut String, value: &Scalar) {
    match value {
        Scalar::Text(s) => quoted(out, s),
        Scalar::Bool(b) => {
            let _ = write!(out, "{b}");
        }
        Scalar::Number(n) => {
            let _ = write!(out, "{n}");
        }
    }
}

fn quoted_size(text: &str) -> usize {
    2 + text
        .chars()
        .map(|c| match c {
            '"' | '\\' => 2,
            c if c.is_control() => 6,
            c => c.len_utf8(),
        })
        .sum::<usize>()
}
fn scalar_size(value: &Scalar) -> usize {
    match value {
        Scalar::Text(text) => quoted_size(text),
        Scalar::Bool(true) => 4,
        Scalar::Bool(false) => 5,
        Scalar::Number(number) => {
            if *number == 0 {
                1
            } else {
                number.ilog10() as usize + 1
            }
        }
    }
}
fn encoded_size(
    meta: &Metadata<'_>,
    values: &[Scalar],
    spans: &[Vec<Scalar>],
    format: LogFormat,
) -> usize {
    let fields_size = |meta: &Metadata<'_>, values: &[Scalar], json: bool| {
        meta.fields()
            .iter()
            .zip(values)
            .map(|(field, value)| {
                if json {
                    2 + quoted_size(field.name()) + scalar_size(value)
                } else {
                    field.name().len() + 2 + scalar_size(value)
                }
            })
            .sum::<usize>()
    };
    match format {
        LogFormat::Json => {
            let mut size = "{\"level\":".len()
                + quoted_size(meta.level().as_str())
                + ",\"target\":".len()
                + quoted_size(meta.target())
                + fields_size(meta, values, true)
                + 2;
            if !spans.is_empty() {
                size += ",\"spans\":[".len() + 1;
                for (index, fields) in spans.iter().enumerate() {
                    size += usize::from(index != 0)
                        + "{\"name\":\"op\"".len()
                        + fields_size(&OPERATION_META, fields, true)
                        + 1;
                }
            }
            size
        }
        LogFormat::Text => {
            let structure = meta.name() == "client.structure.walk";
            let mut size = meta.level().as_str().len()
                + 2
                + meta.target().len()
                + if structure {
                    ": structure walk ".len()
                } else {
                    1
                };
            for (field, value) in meta.fields().iter().zip(values) {
                if structure && matches!(field.name(), "event" | "message") {
                    continue;
                }
                let scalar = if structure && field.name() == "outcome" {
                    if let Scalar::Text(text) = value {
                        text.len()
                    } else {
                        scalar_size(value)
                    }
                } else {
                    scalar_size(value)
                };
                size += field.name().len() + 2 + scalar;
            }
            size + 1
                + spans
                    .iter()
                    .map(|fields| "op{} ".len() + fields_size(&OPERATION_META, fields, false))
                    .sum::<usize>()
        }
    }
}

fn encode(
    meta: &Metadata<'_>,
    values: &[Scalar],
    spans: &[Vec<Scalar>],
    format: LogFormat,
) -> String {
    let size = encoded_size(meta, values, spans, format);
    if size > RECORD_MAX {
        return refusal_record(Refusal::RecordTooLarge, format);
    }
    #[cfg(test)]
    ENCODER_ALLOCATIONS.with(|count| count.set(count.get() + 1));
    let mut out = String::with_capacity(size);
    match format {
        LogFormat::Json => {
            out.push_str("{\"level\":");
            quoted(&mut out, meta.level().as_str());
            out.push_str(",\"target\":");
            quoted(&mut out, meta.target());
            for (field, value) in meta.fields().iter().zip(values) {
                out.push(',');
                quoted(&mut out, field.name());
                out.push(':');
                scalar(&mut out, value);
            }
            if !spans.is_empty() {
                out.push_str(",\"spans\":[");
                for (i, fields) in spans.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    out.push_str("{\"name\":\"op\"");
                    for (field, value) in OPERATION_META.fields().iter().zip(fields) {
                        out.push(',');
                        quoted(&mut out, field.name());
                        out.push(':');
                        scalar(&mut out, value);
                    }
                    out.push('}');
                }
                out.push(']');
            }
            out.push('}');
        }
        LogFormat::Text => {
            let _ = write!(out, " {} ", meta.level());
            for fields in spans {
                out.push_str("op{");
                for (field, value) in OPERATION_META.fields().iter().zip(fields) {
                    out.push_str(field.name());
                    out.push('=');
                    scalar(&mut out, value);
                    out.push(' ');
                }
                out.push_str("} ");
            }
            if meta.name() == "client.structure.walk" {
                let _ = write!(out, "{}: structure walk ", meta.target());
            } else {
                let _ = write!(out, "{} ", meta.target());
            }
            for (field, value) in meta.fields().iter().zip(values) {
                if meta.name() == "client.structure.walk"
                    && matches!(field.name(), "event" | "message")
                {
                    continue;
                }
                out.push_str(field.name());
                out.push('=');
                if meta.name() == "client.structure.walk" && field.name() == "outcome" {
                    if let Scalar::Text(text) = value {
                        out.push_str(text);
                    }
                } else {
                    scalar(&mut out, value);
                }
                out.push(' ');
            }
        }
    }
    out.push('\n');
    if out.len() > RECORD_MAX {
        refusal_record(Refusal::RecordTooLarge, format)
    } else {
        out
    }
}

fn refusal_record(reason: Refusal, format: LogFormat) -> String {
    match format {
        LogFormat::Json => format!(
            "{{\"level\":\"WARN\",\"event\":\"log.record_refused\",\"reason\":\"{}\"}}\n",
            reason.as_str()
        ),
        LogFormat::Text => format!(
            " WARN event=\"log.record_refused\" reason=\"{}\"\n",
            reason.as_str()
        ),
    }
}

fn path_class(meta: &Metadata<'_>, field: &str) -> Option<&'static str> {
    if matches!(meta.name(), "op.conflict" | "overlay.stage_rolled_back") && field == "path" {
        return Some("<file>");
    }
    diagnostics::path_class(meta, field)
}

fn project_slots(
    meta: &Metadata<'_>,
    fields: &[Scalar],
    slots: &[PathSlot<'_>],
    policy: LogPaths,
) -> Vec<Scalar> {
    let mut fields = fields.to_vec();
    for slot in slots {
        if path_class(meta, slot.field()) != Some(slot.class()) {
            continue;
        }
        if let Some(index) = meta.fields().iter().position(|f| f.name() == slot.field())
            && let Some(value) = fields.get_mut(index)
        {
            *value = slot.project(policy);
        }
    }
    fields
}

std::thread_local! {
    /// The fields the admission boundary validated, handed to the encoder for the
    /// same event or span on this thread so they are validated once.
    static VALIDATED: std::cell::RefCell<Option<Vec<Scalar>>> = const { std::cell::RefCell::new(None) };
    static REUSE_SPAN: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
fn hand_off(fields: Option<Vec<Scalar>>) {
    VALIDATED.with(|slot| *slot.borrow_mut() = fields);
}
fn take_validated() -> Option<Vec<Scalar>> {
    VALIDATED.with(|slot| slot.borrow_mut().take())
}

type SpanFields = BTreeMap<u64, (Vec<Scalar>, Option<u64>)>;
fn scope_ids(current: Option<u64>, scopes: &SpanFields) -> impl Iterator<Item = u64> + '_ {
    std::iter::successors(current, move |id| {
        scopes.get(id).and_then(|(_, parent)| *parent)
    })
    .take(scopes.len().saturating_add(1))
}
struct ProjectionContext {
    paths: LogPaths,
    history: BundleHistory,
    scopes: Mutex<SpanFields>,
    entered: Mutex<Vec<(std::thread::ThreadId, Vec<u64>)>>,
    operation_correlations: Mutex<BTreeMap<u64, [u8; 8]>>,
}
struct ProjectionLayer(std::sync::Arc<ProjectionContext>);
impl<S: Subscriber> Layer<S> for ProjectionLayer {
    fn on_enter(&self, id: &Id, _: Context<'_, S>) {
        if self
            .0
            .scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&id.into_u64())
        {
            let thread = std::thread::current().id();
            let mut entered = self
                .0
                .entered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((_, stack)) = entered.iter_mut().find(|(t, _)| *t == thread) {
                stack.push(id.into_u64());
            } else {
                entered.push((thread, vec![id.into_u64()]));
            }
        }
    }
    fn on_exit(&self, id: &Id, _: Context<'_, S>) {
        let mut entered = self
            .0
            .entered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let thread = std::thread::current().id();
        if let Some(index) = entered.iter().position(|(t, _)| *t == thread)
            && let Some((_, stack)) = entered.get_mut(index)
        {
            if let Some(slot) = stack.iter().rposition(|span| *span == id.into_u64()) {
                stack.remove(slot);
            }
            if stack.is_empty() {
                entered.remove(index);
            }
        }
    }
}
impl ProjectionContext {
    fn current(&self) -> Option<u64> {
        self.entered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(thread, _)| *thread == std::thread::current().id())
            .and_then(|(_, stack)| stack.last().copied())
    }
    fn scope(&self) -> Vec<Vec<Scalar>> {
        let current = self.current();
        let scopes = self
            .scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = scope_ids(current, &scopes)
            .filter_map(|id| scopes.get(&id).map(|(fields, _)| fields.clone()))
            .collect::<Vec<_>>();
        out.reverse();
        out
    }

    fn current_operation_correlation(&self) -> Option<[u8; 8]> {
        let current = self.current();
        let scopes = self
            .scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let correlations = self
            .operation_correlations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        scope_ids(current, &scopes).find_map(|id| correlations.get(&id).copied())
    }
}

/// A destination accepting only an already encoded telemetry projection.
pub trait RecordWriter {
    /// Submit one whole approved record.
    fn write_record(&self, record: &LogRecord);
}
impl<W> RecordWriter for W
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a>,
{
    fn write_record(&self, record: &LogRecord) {
        let _ = std::io::Write::write_all(&mut self.make_writer(), record.as_bytes());
    }
}

struct Encoder<W> {
    format: LogFormat,
    paths: LogPaths,
    writer: W,
}
impl<W> Encoder<W>
where
    W: RecordWriter,
{
    fn write(&self, record: &LogRecord) {
        self.writer.write_record(record);
    }
}
impl<S, W> Layer<S> for Encoder<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: RecordWriter + Send + Sync + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let fields = take_validated().or_else(|| {
            let mut checked = Checked::with_paths(attrs.metadata(), self.paths);
            attrs.record(&mut checked);
            checked.finish(true).ok()
        });
        if let (Some(fields), Some(span)) = (fields, ctx.span(id)) {
            span.extensions_mut().insert(fields);
        }
    }
    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut checked = Checked::with_paths(span.metadata(), self.paths);
            values.record(&mut checked);
            if checked.refusal.is_none() {
                let mut extensions = span.extensions_mut();
                if let Some(fields) = extensions.get_mut::<Vec<Scalar>>() {
                    for (slot, field) in fields.iter_mut().zip(span.metadata().fields().iter()) {
                        if let Some(value) = checked.values.get(field.name()) {
                            *slot = value.clone();
                        }
                    }
                }
            }
        }
    }
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let fields = take_validated().or_else(|| {
            let mut checked = Checked::with_paths(event.metadata(), self.paths);
            event.record(&mut checked);
            checked.finish(true).ok()
        });
        if let Some(fields) = fields {
            let spans: Vec<Vec<Scalar>> = ctx
                .event_scope(event)
                .into_iter()
                .flat_map(tracing_subscriber::registry::Scope::from_root)
                .filter_map(|span| span.extensions().get::<Vec<Scalar>>().cloned())
                .collect();
            self.write(&LogRecord(encode(
                event.metadata(),
                &fields,
                &spans,
                self.format,
            )));
        }
    }
}

struct Admission<S, W> {
    inner: S,
    refused: Encoder<W>,
    context: std::sync::Arc<ProjectionContext>,
    spans: Mutex<BTreeMap<u64, &'static Metadata<'static>>>,
    /// Unregistered callsites already refused: each is refused once per session.
    unregistered: std::sync::RwLock<std::collections::BTreeSet<usize>>,
}
impl<S, W> Admission<S, W>
where
    S: Subscriber,
    W: RecordWriter,
{
    /// Bundle history always records the refusal; telemetry records it only when
    /// the filter admits a WARN event on this target, like any other warning.
    fn refuse(&self, reason: Refusal) {
        self.context
            .history
            .record(BundleRecord(refusal_record(reason, LogFormat::Json)));
        if self.inner.enabled(&RETRY_META) {
            self.refused
                .write(&LogRecord(refusal_record(reason, self.refused.format)));
        }
    }
    /// True the first time this session sees an unregistered callsite, false after,
    /// so a dependency emitting at any rate is refused once, not per event.
    fn first_sight(&self, meta: &Metadata<'_>) -> bool {
        // One locked insert decides it: `insert` is true only for the first
        // caller, whatever the interleaving.
        self.unregistered
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(identity(meta))
    }
    fn schema(meta: &Metadata<'_>) -> Result<(), Refusal> {
        let site = registered(meta).ok_or(Refusal::UnregisteredCallsite)?;
        if same_schema(meta, site) {
            Ok(())
        } else {
            Err(Refusal::InvalidSchema)
        }
    }
    fn known(&self, id: &Id) -> bool {
        self.spans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&id.into_u64())
    }
}
impl<S, W> Subscriber for Admission<S, W>
where
    S: Subscriber,
    W: RecordWriter + Send + Sync + 'static,
{
    fn register_callsite(&self, meta: &'static Metadata<'static>) -> Interest {
        if Self::schema(meta).is_ok() {
            self.inner.register_callsite(meta);
        }
        Interest::sometimes()
    }
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        match Self::schema(meta) {
            Ok(()) => self.inner.enabled(meta),
            // A dependency callsite the filter would admit is refused once, then
            // stays disabled; one the filter would drop is never seen at all.
            Err(Refusal::UnregisteredCallsite) => {
                self.inner.enabled(meta) && self.first_sight(meta)
            }
            Err(_) => true,
        }
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        if let Some(existing) = REUSE_SPAN.with(std::cell::Cell::take) {
            return self.inner.clone_span(&Id::from_u64(existing));
        }
        let result = Self::schema(attrs.metadata()).and_then(|()| {
            let mut checked = Checked::with_paths(attrs.metadata(), self.context.paths);
            attrs.record(&mut checked);
            checked.finish(true)
        });
        let fields = match result {
            Ok(fields) => fields,
            Err(reason) => {
                self.refuse(reason);
                return Id::from_u64(u64::MAX);
            }
        };
        if attrs.parent().is_some_and(|id| !self.known(id)) {
            self.refuse(Refusal::UnregisteredCallsite);
            return Id::from_u64(u64::MAX);
        }
        hand_off(Some(fields.clone()));
        let id = self.inner.new_span(attrs);
        hand_off(None);
        let parent = attrs.parent().map(Id::into_u64).or_else(|| {
            attrs
                .is_contextual()
                .then(|| self.context.current())
                .flatten()
        });
        self.context
            .scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.into_u64(), (fields, parent));
        self.spans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.into_u64(), attrs.metadata());
        id
    }
    fn record(&self, id: &Id, values: &Record<'_>) {
        let meta = self
            .spans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id.into_u64())
            .copied();
        let Some(meta) = meta else {
            self.refuse(Refusal::UnregisteredCallsite);
            return;
        };
        let mut checked = Checked::with_paths(meta, self.context.paths);
        values.record(&mut checked);
        let updates = checked.values.clone();
        match checked.finish(false) {
            Ok(_) if identity(meta) == identity(&OPERATION_META) && updates.contains_key("op") => {
                self.refuse(Refusal::InvalidDomain);
            }
            Ok(_) => {
                if let Some((fields, _)) = self
                    .context
                    .scopes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_mut(&id.into_u64())
                {
                    for (slot, field) in fields.iter_mut().zip(meta.fields().iter()) {
                        if let Some(value) = updates.get(field.name()) {
                            *slot = value.clone();
                        }
                    }
                }
                self.inner.record(id, values);
            }
            Err(reason) => self.refuse(reason),
        }
    }
    fn record_follows_from(&self, span: &Id, follows: &Id) {
        if self.known(span) && self.known(follows) {
            self.inner.record_follows_from(span, follows);
        }
    }
    fn event(&self, event: &Event<'_>) {
        let result = Self::schema(event.metadata()).and_then(|()| {
            let mut checked = Checked::with_paths(event.metadata(), self.context.paths);
            event.record(&mut checked);
            checked.finish(true)
        });
        match result {
            Ok(fields) if event.parent().is_none_or(|id| self.known(id)) => {
                hand_off(Some(fields));
                self.inner.event(event);
                hand_off(None);
            }
            Ok(_) => self.refuse(Refusal::UnregisteredCallsite),
            Err(reason) => self.refuse(reason),
        }
    }
    fn enter(&self, id: &Id) {
        if self.known(id) {
            self.inner.enter(id);
        }
    }
    fn exit(&self, id: &Id) {
        if self.known(id) {
            self.inner.exit(id);
        }
    }
    fn clone_span(&self, id: &Id) -> Id {
        if self.known(id) {
            self.inner.clone_span(id)
        } else {
            id.clone()
        }
    }
    fn try_close(&self, id: Id) -> bool {
        if !self.known(&id) {
            return true;
        }
        if self.inner.try_close(id.clone()) {
            self.context
                .scopes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id.into_u64());
            self.context
                .operation_correlations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id.into_u64());
            self.spans
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id.into_u64());
            true
        } else {
            false
        }
    }
}

/// Assemble the closed schema subscriber.
/// Admission precedes filtering, span storage, and hand-written scalar encoders.
/// Foreign/dependency filter targets are inert under callsite admission.
#[must_use]
pub fn closed_subscriber<W>(
    format: LogFormat,
    filter: EnvFilter,
    writer: W,
) -> Box<dyn Subscriber + Send + Sync>
where
    W: RecordWriter + Clone + Send + Sync + 'static,
{
    closed_subscriber_with_paths(
        format,
        filter,
        writer,
        LogPaths::Redacted,
        BundleHistory::default(),
    )
}

/// Assemble a fresh session with immutable log policy and independent typed history.
#[must_use]
pub fn closed_subscriber_with_paths<W>(
    format: LogFormat,
    filter: EnvFilter,
    writer: W,
    paths: LogPaths,
    history: BundleHistory,
) -> Box<dyn Subscriber + Send + Sync>
where
    W: RecordWriter + Clone + Send + Sync + 'static,
{
    let context = std::sync::Arc::new(ProjectionContext {
        paths,
        history,
        scopes: Mutex::new(BTreeMap::new()),
        entered: Mutex::new(Vec::new()),
        operation_correlations: Mutex::new(BTreeMap::new()),
    });
    let inner = tracing_subscriber::registry()
        .with(Encoder {
            format,
            paths,
            writer: writer.clone(),
        })
        .with(filter);
    for meta in SITES.iter().chain(diagnostics::SITES) {
        inner.register_callsite(meta);
    }
    Box::new(
        Admission {
            inner,
            refused: Encoder {
                format,
                paths,
                writer,
            },
            context: context.clone(),
            spans: Mutex::new(BTreeMap::new()),
            unregistered: std::sync::RwLock::new(std::collections::BTreeSet::new()),
        }
        .with(ProjectionLayer(context)),
    )
}

pub(crate) fn current_operation_id() -> Option<String> {
    tracing::dispatcher::get_default(|dispatch| {
        let context = &dispatch.downcast_ref::<ProjectionLayer>()?.0;
        let id = context.current()?;
        match context
            .scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)?
            .0
            .first()?
        {
            Scalar::Text(op) => Some(op.clone()),
            Scalar::Number(_) | Scalar::Bool(_) => None,
        }
    })
}

pub(crate) fn current_operation_span() -> tracing::Span {
    let current = tracing::Span::current();
    if !current.is_none() {
        return current;
    }
    tracing::dispatcher::get_default(|dispatch| {
        let Some(id) = dispatch
            .downcast_ref::<ProjectionLayer>()
            .and_then(|layer| layer.0.current())
        else {
            return tracing::Span::none();
        };
        REUSE_SPAN.with(|slot| slot.set(Some(id)));
        let values: [Option<&dyn Value>; 2] = [None, None];
        tracing::Span::new_with(
            &OPERATION_META,
            &OPERATION_META.fields().value_set_all(&values),
            dispatch,
        )
    })
}

#[cfg(test)]
mod tests;
