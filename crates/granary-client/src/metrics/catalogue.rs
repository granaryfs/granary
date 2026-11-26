// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Fixed metric identities and exhaustive label domains.

use super::MetricsError;

fn parse_label<T: Copy>(
    text: &str,
    domain: &[T],
    name: fn(T) -> &'static str,
) -> Result<T, MetricsError> {
    domain
        .iter()
        .copied()
        .find(|member| name(*member) == text)
        .ok_or(MetricsError::InvalidLabel)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitResult {
    Ok,
    Conflict,
    Exhausted,
    Failed,
    Cancelled,
    Unknown,
}

impl CommitResult {
    pub const ALL: &'static [Self] = &[
        Self::Ok,
        Self::Conflict,
        Self::Exhausted,
        Self::Failed,
        Self::Cancelled,
        Self::Unknown,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Conflict => "conflict",
            Self::Exhausted => "exhausted",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
    /// Refuse any value outside this closed domain without echoing it.
    /// # Errors
    /// Returns `InvalidLabel` for an unknown spelling.
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        parse_label(text, Self::ALL, Self::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationResult {
    Ok,
    Failed,
    Cancelled,
    Unknown,
}

impl RegistrationResult {
    pub const ALL: &'static [Self] = &[Self::Ok, Self::Failed, Self::Cancelled, Self::Unknown];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
    /// Refuse any value outside this closed domain without echoing it.
    /// # Errors
    /// Returns `InvalidLabel` for an unknown spelling.
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        parse_label(text, Self::ALL, Self::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsGroup {
    Cache,
    Transport,
    Sync,
    Commit,
    Contention,
    Fuse,
}

impl MetricsGroup {
    pub const ALL: &'static [Self] = &[
        Self::Cache,
        Self::Transport,
        Self::Sync,
        Self::Commit,
        Self::Contention,
        Self::Fuse,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Transport => "transport",
            Self::Sync => "sync",
            Self::Commit => "commit",
            Self::Contention => "contention",
            Self::Fuse => "fuse",
        }
    }
    /// Refuse any value outside this closed domain without echoing it.
    /// # Errors
    /// Returns `InvalidLabel` for an unknown spelling.
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        parse_label(text, Self::ALL, Self::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePhase {
    Startup,
    Read,
}

impl CachePhase {
    pub const ALL: &'static [Self] = &[Self::Startup, Self::Read];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Read => "read",
        }
    }
    /// Refuse any value outside this closed domain without echoing it.
    /// # Errors
    /// Returns `InvalidLabel` for an unknown spelling.
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        parse_label(text, Self::ALL, Self::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheResult {
    Hit,
    Miss,
}

impl CacheResult {
    pub const ALL: &'static [Self] = &[Self::Hit, Self::Miss];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
        }
    }
    /// Refuse any value outside this closed domain without echoing it.
    /// # Errors
    /// Returns `InvalidLabel` for an unknown spelling.
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        parse_label(text, Self::ALL, Self::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadObject {
    Bin,
    Meta,
}

impl UploadObject {
    pub const ALL: &'static [Self] = &[Self::Bin, Self::Meta];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Meta => "meta",
        }
    }
    /// Refuse any value outside this closed domain without echoing it.
    /// # Errors
    /// Returns `InvalidLabel` for an unknown spelling.
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        parse_label(text, Self::ALL, Self::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteDirection {
    Up,
    Down,
}

impl ByteDirection {
    pub const ALL: &'static [Self] = &[Self::Up, Self::Down];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }
    /// Refuse any value outside this closed domain without echoing it.
    /// # Errors
    /// Returns `InvalidLabel` for an unknown spelling.
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        parse_label(text, Self::ALL, Self::as_str)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Metric {
    SchemaVersion,
    Incarnation,
    Available,
    Overflow,
    Commits,
    CommitDuration,
    Retries,
    RebaseConflicts,
    Contention,
    Syncs,
    Registrations,
    RegistrationDuration,
    UploadedGrains,
    UploadedBytes,
    Rechunks,
    CacheLookups,
    CacheHitRatio,
    TransportBytes,
    ListenerUp,
    Scrapes,
    FuseRequests,
    MountViewStale,
}

/// Stable catalogue metadata, with no registration or arbitrary-label interface.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    pub(super) metric: Metric,
    pub code: &'static str,
    pub name: &'static str,
    pub kind: &'static str,
    pub help: &'static str,
}

pub const METRICS_CATALOGUE: &[MetricSpec] = &[
    MetricSpec {
        metric: Metric::SchemaVersion,
        code: "M01",
        name: "granary_client_metrics_schema_version",
        kind: "gauge",
        help: "Catalogue schema version.",
    },
    MetricSpec {
        metric: Metric::Incarnation,
        code: "M02",
        name: "granary_client_metrics_incarnation",
        kind: "gauge",
        help: "Store incarnation as four unsigned 32-bit words.",
    },
    MetricSpec {
        metric: Metric::Available,
        code: "M03",
        name: "granary_client_metrics_available",
        kind: "gauge",
        help: "Producer wired and usable.",
    },
    MetricSpec {
        metric: Metric::Overflow,
        code: "M04",
        name: "granary_client_metrics_overflow",
        kind: "gauge",
        help: "Sticky metric invalidity; missing series are not resets.",
    },
    MetricSpec {
        metric: Metric::Commits,
        code: "M05",
        name: "granary_client_commits_total",
        kind: "counter",
        help: "Local terminal observations per logical commit.",
    },
    MetricSpec {
        metric: Metric::CommitDuration,
        code: "M06",
        name: "granary_client_commit_duration_seconds",
        kind: "histogram",
        help: "Measured commit duration including retries and backoff.",
    },
    MetricSpec {
        metric: Metric::Retries,
        code: "M07",
        name: "granary_client_commit_retries_total",
        kind: "counter",
        help: "Additional commit attempts actually started.",
    },
    MetricSpec {
        metric: Metric::RebaseConflicts,
        code: "M08",
        name: "granary_client_rebase_conflicts_total",
        kind: "counter",
        help: "Rebase attempts detecting overlapping names.",
    },
    MetricSpec {
        metric: Metric::Contention,
        code: "M09",
        name: "granary_client_contention_flag",
        kind: "gauge",
        help: "Authoritative contention policy decision.",
    },
    MetricSpec {
        metric: Metric::Syncs,
        code: "M10",
        name: "granary_client_syncs_total",
        kind: "counter",
        help: "Completed sync engine calls.",
    },
    MetricSpec {
        metric: Metric::Registrations,
        code: "M11",
        name: "granary_client_intent_registrations_total",
        kind: "counter",
        help: "Terminal registration exchanges.",
    },
    MetricSpec {
        metric: Metric::RegistrationDuration,
        code: "M12",
        name: "granary_client_intent_registration_duration_seconds",
        kind: "histogram",
        help: "Measured registration exchange duration.",
    },
    MetricSpec {
        metric: Metric::UploadedGrains,
        code: "M13",
        name: "granary_client_sync_grains_uploaded_total",
        kind: "counter",
        help: "Grains in novel successful bin uploads.",
    },
    MetricSpec {
        metric: Metric::UploadedBytes,
        code: "M14",
        name: "granary_client_sync_uploaded_bytes_total",
        kind: "counter",
        help: "Encoded payload bytes in novel successful uploads.",
    },
    MetricSpec {
        metric: Metric::Rechunks,
        code: "M15",
        name: "granary_client_sync_rechunk_fallbacks_total",
        kind: "counter",
        help: "Whole-file rechunk fallbacks.",
    },
    MetricSpec {
        metric: Metric::CacheLookups,
        code: "M16",
        name: "granary_client_cache_lookups_total",
        kind: "counter",
        help: "Final cache hits and admitted misses per distinct want.",
    },
    MetricSpec {
        metric: Metric::CacheHitRatio,
        code: "M17",
        name: "granary_client_cache_hit_ratio",
        kind: "gauge",
        help: "Sampled hits divided by sampled hits plus misses.",
    },
    MetricSpec {
        metric: Metric::TransportBytes,
        code: "M18",
        name: "granary_client_transport_body_bytes_total",
        kind: "counter",
        help: "HTTP payload offered up or DATA observed down, not wire-exact.",
    },
    MetricSpec {
        metric: Metric::ListenerUp,
        code: "M19",
        name: "granary_client_metrics_listener_up",
        kind: "gauge",
        help: "Configured listener health; absent when never configured.",
    },
    MetricSpec {
        metric: Metric::Scrapes,
        code: "M20",
        name: "granary_client_metrics_scrapes_total",
        kind: "counter",
        help: "Terminal scrapes after completed TLS admission.",
    },
    MetricSpec {
        metric: Metric::FuseRequests,
        code: "M21",
        name: "granary_client_fuse_requests_total",
        kind: "counter",
        help: "Dispatched reply-bearing callback completions.",
    },
    MetricSpec {
        metric: Metric::MountViewStale,
        code: "M22",
        name: "granary_client_mount_view_stale",
        kind: "gauge",
        help: "Writable mount authority view in the unreachable state.",
    },
];
