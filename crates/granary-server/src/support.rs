// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Field-by-field server projections into the pure support formats.
#[cfg(test)]
mod tests;
use crate::{
    ControlsConfig,
    authority::Observation,
    config::{STORE_CLIENT_TIMEOUT, STORE_DISPATCH_DEADLINE, authority::AuthorityConfig},
    debug_grant::DebugGrantSnapshot,
    diagnostics::{CaptureEntry, CaptureKind, CaptureSelector},
};
pub use granary_core::support::{
    CONFIGURATION_MAX, SNAPSHOT_MAX, SupportConfiguration, SupportError, SupportGrant,
    SupportGrantRecord, SupportSnapshot,
};
use granary_core::{debug_grant::Incarnation, sheaf::Timestamp, support as data};
use std::{collections::BTreeMap, time::Duration};
type Result<T> = std::result::Result<T, SupportError>;
fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(SupportError(reason))
    }
}
// Pin the equivalence of the server's validated controls and the v1 accept set.
const _: () = assert!(granary_core::binfmt::BIN_MAX_BYTES == 268_435_456);
const _: () = assert!(crate::adapter::WRITE_BODY_BUDGET_BYTES == 2_147_483_648);
const _: () = assert!(crate::adapter::WRITE_BUDGET_GRANULE_BYTES == 65_536);
/// Copy only validated authority values and effective composition inputs.
/// The actual bound port is supplied by [`bound_configuration`].
/// # Errors
/// Refuses durations not exactly representable as u64 milliseconds or
/// inventories outside the validated configuration bounds.
pub fn retain_configuration(
    config: &AuthorityConfig,
    incarnation: Incarnation,
    workers: usize,
    budget: Duration,
    dispatch: Option<Duration>,
) -> Result<SupportConfiguration> {
    let volumes = config
        .volumes
        .iter()
        .map(|(name, keys)| {
            require(!keys.is_empty() && keys.len() <= 8, "publisher key count")?;
            Ok((
                name.clone(),
                u8::try_from(keys.len()).map_err(|_| SupportError("publisher key count"))?,
            ))
        })
        .collect::<Result<_>>()?;
    require(
        !config.volumes.is_empty() && config.volumes.len() <= 64,
        "volume count",
    )?;
    Ok(SupportConfiguration {
        incarnation,
        authority_profile: config.authority_profile,
        volumes,
        accept_unsupported_filesystem: config.accept_unsupported_filesystem,
        controls: project_controls(config.controls)?,
        listen_port: 0,
        tls_enabled: true,
        client_auth_required: true,
        worker_threads: u64::try_from(workers).map_err(|_| SupportError("worker count"))?,
        shutdown_budget_ms: millis(budget)?,
        dispatch_deadline_ms: dispatch.map(millis).transpose()?,
        network_dispatch_limit_ms: millis(STORE_DISPATCH_DEADLINE)?,
        network_client_timeout_ms: millis(STORE_CLIENT_TIMEOUT)?,
    })
}
/// Finish the projection from the listener's actual bound address.
#[must_use]
pub fn bound_configuration(
    mut value: SupportConfiguration,
    addr: std::net::SocketAddr,
) -> SupportConfiguration {
    value.listen_port = addr.port();
    value
}
fn millis(value: Duration) -> Result<u64> {
    require(
        value.subsec_nanos().is_multiple_of(1_000_000),
        "duration precision",
    )?;
    u64::try_from(value.as_millis()).map_err(|_| SupportError("duration overflow"))
}

fn project_controls(c: ControlsConfig) -> Result<data::SupportControls> {
    let (submission_rate, submission_burst, byte_rate, byte_burst, cap) = c.tuple();
    Ok(data::SupportControls([
        submission_rate,
        submission_burst,
        byte_rate,
        byte_burst,
        u64::try_from(cap).map_err(|_| SupportError("controls"))?,
    ]))
}
fn project_enrollment(s: crate::enrollment::EnrollmentSnapshot) -> data::EnrollmentSnapshot {
    let state = match s.state {
        crate::enrollment::SnapshotState::Ok {
            principals,
            credentials,
        } => data::SnapshotState::Ok {
            principals,
            credentials,
        },
        crate::enrollment::SnapshotState::Unavailable(r) => {
            data::SnapshotState::Unavailable(match r {
                crate::enrollment::UnavailableReason::Missing => data::UnavailableReason::Missing,
                crate::enrollment::UnavailableReason::Unreadable => {
                    data::UnavailableReason::Unreadable
                }
                crate::enrollment::UnavailableReason::Unprotected => {
                    data::UnavailableReason::Unprotected
                }
                crate::enrollment::UnavailableReason::Oversize => data::UnavailableReason::Oversize,
                crate::enrollment::UnavailableReason::Corrupt => data::UnavailableReason::Corrupt,
                crate::enrollment::UnavailableReason::Directory => {
                    data::UnavailableReason::Directory
                }
                crate::enrollment::UnavailableReason::Stalled => data::UnavailableReason::Stalled,
            })
        }
    };
    data::EnrollmentSnapshot {
        state,
        sequence: s.sequence,
        counters: data::SnapshotCounters {
            missing: s.counters.missing,
            unreadable: s.counters.unreadable,
            unprotected: s.counters.unprotected,
            oversize: s.counters.oversize,
            corrupt: s.counters.corrupt,
            directory: s.counters.directory,
            stalled: s.counters.stalled,
            reloads: s.counters.reloads,
            reload_failures: s.counters.reload_failures,
        },
    }
}
fn project_reason(r: crate::wire::ErrorToken) -> Option<data::RefusalReason> {
    // Frozen SUPPORT-SNAPSHOT v1 has 28 tags and cannot encode the seven intent
    // reasons. Keep their exact live counters; v2 projection is tracked in Task 8 evidence.
    let reason = match r {
        crate::wire::ErrorToken::IntentSuperseded
        | crate::wire::ErrorToken::IntentBound
        | crate::wire::ErrorToken::IntentChanged
        | crate::wire::ErrorToken::IntentAbsent
        | crate::wire::ErrorToken::IntentCursorChanged
        | crate::wire::ErrorToken::IntentEpochExhausted
        | crate::wire::ErrorToken::IntentQuota
        | crate::wire::ErrorToken::MissingReference
        | crate::wire::ErrorToken::InvalidReference
        | crate::wire::ErrorToken::PublishWorkLimit => return None,
        crate::wire::ErrorToken::NotFound => data::RefusalReason::NotFound,
        crate::wire::ErrorToken::UnknownTarget => data::RefusalReason::UnknownTarget,
        crate::wire::ErrorToken::AlreadyExists => data::RefusalReason::AlreadyExists,
        crate::wire::ErrorToken::AddressMismatch => data::RefusalReason::AddressMismatch,
        crate::wire::ErrorToken::VerifyFailed => data::RefusalReason::VerifyFailed,
        crate::wire::ErrorToken::LayoutInvalid => data::RefusalReason::LayoutInvalid,
        crate::wire::ErrorToken::BadRange => data::RefusalReason::BadRange,
        crate::wire::ErrorToken::ExtentTooWide => data::RefusalReason::ExtentTooWide,
        crate::wire::ErrorToken::BadRequest => data::RefusalReason::BadRequest,
        crate::wire::ErrorToken::MethodNotAllowed => data::RefusalReason::MethodNotAllowed,
        crate::wire::ErrorToken::TooLarge => data::RefusalReason::TooLarge,
        crate::wire::ErrorToken::Internal => data::RefusalReason::Internal,
        crate::wire::ErrorToken::Unavailable => data::RefusalReason::Unavailable,
        crate::wire::ErrorToken::NoPrincipal => data::RefusalReason::NoPrincipal,
        crate::wire::ErrorToken::NotEnrolled => data::RefusalReason::NotEnrolled,
        crate::wire::ErrorToken::RateLimited => data::RefusalReason::RateLimited,
        crate::wire::ErrorToken::AuthorityManaged => data::RefusalReason::AuthorityManaged,
        crate::wire::ErrorToken::InvalidCandidate => data::RefusalReason::InvalidCandidate,
        crate::wire::ErrorToken::NoLog => data::RefusalReason::NoLog,
        crate::wire::ErrorToken::UnknownVolume => data::RefusalReason::UnknownVolume,
        crate::wire::ErrorToken::StaleBase => data::RefusalReason::StaleBase,
        crate::wire::ErrorToken::OperationBound => data::RefusalReason::OperationBound,
        crate::wire::ErrorToken::NotDecided => data::RefusalReason::NotDecided,
        crate::wire::ErrorToken::EpochMismatch => data::RefusalReason::EpochMismatch,
        crate::wire::ErrorToken::VolumeDamaged => data::RefusalReason::VolumeDamaged,
        crate::wire::ErrorToken::Fenced => data::RefusalReason::Fenced,
        crate::wire::ErrorToken::Stopped => data::RefusalReason::Stopped,
        crate::wire::ErrorToken::EnrollmentUnavailable => {
            data::RefusalReason::EnrollmentUnavailable
        }
    };
    Some(reason)
}
fn project_refusals(s: &crate::refusals::RefusalSnapshot) -> data::RefusalSnapshot {
    let rows = |r: &BTreeMap<crate::wire::ErrorToken, u64>| {
        r.iter()
            .filter_map(|(&r, &n)| project_reason(r).map(|reason| (reason, n)))
            .collect()
    };
    data::RefusalSnapshot {
        totals: rows(&s.totals),
        principals: s.principals.iter().map(|(&p, r)| (p, rows(r))).collect(),
    }
}
fn project_record(record: &granary_core::debug_grant::DebugGrant) -> SupportGrantRecord {
    let f = record.fields();
    SupportGrantRecord {
        incarnation: f.incarnation,
        file_revision: f.file_revision,
        grant_generation: f.grant_generation,
        action: f.action,
        issuer_uid: f.issuer_uid,
        issued_at: f.issued_at,
        expires_at: f.expires_at,
        scope: f.scope.clone(),
        line_ceiling: f.line_ceiling,
        byte_ceiling: f.byte_ceiling,
    }
}
fn project_capture(s: &CaptureEntry) -> Result<data::SupportCapture> {
    require(
        s.level == tracing::Level::DEBUG && s.kind == CaptureKind::AuthenticatedRequest,
        "capture kind or level",
    )?;
    let scope = match &s.selector {
        CaptureSelector::Principal(p) => granary_core::debug_grant::GrantScope::Principal(*p),
        CaptureSelector::Volume(v) => granary_core::debug_grant::GrantScope::Volume(v.clone()),
        CaptureSelector::PrincipalAndVolume(p, v) => {
            granary_core::debug_grant::GrantScope::Conjunction {
                principal: *p,
                volume: v.clone(),
            }
        }
    };
    Ok(data::SupportCapture {
        slot: s.slot.0,
        scope,
        remaining_lines: s.remaining_lines,
        remaining_bytes: s.remaining_bytes,
        deadline: s.deadline,
        lease: s.lease,
    })
}
fn project_grant(s: &DebugGrantSnapshot) -> Result<SupportGrant> {
    Ok(SupportGrant {
        incarnation: s.incarnation,
        state: s.state,
        reason: s.reason,
        future_issued_lead_secs: s.future_issued_lead_secs,
        high_revision: s.high_revision,
        high_generation: s.high_generation,
        retired_generation: s.retired_generation,
        observed: s.observed.as_ref().map(project_record),
        accepted: s.accepted.as_ref().map(project_record),
        effective: s.effective.as_ref().map(project_capture).transpose()?,
        slot: s.slot.map(|s| s.0),
        capture_revision: s.capture_revision.0,
        reader_counters: data::ReaderCounters {
            refreshes: s.reader_counters.refreshes,
            reloads: s.reader_counters.reloads,
            refusals: s.reader_counters.refusals,
            unreadable: s.reader_counters.unreadable,
            stalled: s.reader_counters.stalled,
            applications: s.reader_counters.applications,
            retirements: s.reader_counters.retirements,
        },
        capture_counters: data::CaptureCounters {
            admitted: s.capture_counters.admitted,
            budget_suppressed: s.capture_counters.budget_suppressed,
            suppressed: s.capture_counters.suppressed,
            expiry_suppressed: s.capture_counters.expiry_suppressed,
            expired: s.capture_counters.expired,
            contention: s.capture_counters.contention,
            malformed: s.capture_counters.malformed,
            oversize: s.capture_counters.oversize,
            queued: s.capture_counters.queued,
            sink_drops: s.capture_counters.sink_drops,
        },
    })
}
/// Project all cached fields and reject unsupported capture kinds before encoding.
/// # Errors
/// Refuses effective capture outside the DEBUG authenticated-request profile.
pub fn snapshot_from_observation(
    incarnation: Incarnation,
    sampled_at: Timestamp,
    s: &Observation,
) -> Result<SupportSnapshot> {
    Ok(SupportSnapshot {
        incarnation,
        sampled_at,
        volumes: s
            .volumes
            .iter()
            .map(|(n, v)| {
                (
                    n.clone(),
                    v.status()
                        .map_or(data::VolumeView::NoLog, data::VolumeView::Log),
                )
            })
            .collect(),
        terminal: s.terminal.map(|t| match t {
            crate::authority::TerminalState::Fenced => data::TerminalState::Fenced,
            crate::authority::TerminalState::Stopped => data::TerminalState::Stopped,
        }),
        enrollment: project_enrollment(s.enrollment),
        refusals: project_refusals(&s.refusals),
        grant: s.debug_grant.as_ref().map(project_grant).transpose()?,
    })
}

mod cli;
pub use cli::run_support_export_command_line;
mod export;
mod publish;
pub use export::{
    SupportExportError, SupportExportRequest, publish_support_export, read_support_export,
};
mod writer;
pub use writer::{SUPPORT_INTERVAL, SupportWriter};
