// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Owner-authenticated control, with transport separate from shutdown custody.

use super::{MountOutcome, escaped_path};
use granary_core::mount_control::{
    self as wire, FailureClass as WireClass, ReportKind, ResultKind,
};

mod client;
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "production endpoint setup is Linux-only; portable tests exercise routing and custody predicates"
    )
)]
mod endpoint;
mod service;
mod support;
mod transport;

pub(super) use client::Failure;
#[cfg(target_os = "linux")]
pub(super) use client::umount;
pub(super) use service::Control;
#[cfg(any(test, target_os = "linux"))]
pub(super) use support::Producer as SupportProducer;
#[cfg(any(test, target_os = "linux"))]
pub(crate) use support::RequestFailure as SupportRequestFailure;
#[cfg(target_os = "linux")]
pub(super) use support::{Support, request_live};

#[cfg(all(test, target_os = "linux"))]
pub(super) fn support_fixture_path(
    owner: u32,
    namespace: (u64, u64),
    target: &std::path::Path,
) -> std::path::PathBuf {
    endpoint::directory_name(owner).join(endpoint::support_socket_name(namespace, target))
}

#[cfg(all(test, target_os = "linux"))]
pub(super) async fn request_support_fixture(
    stream: tokio::net::UnixStream,
    owner: u32,
    deadline: tokio::time::Instant,
) -> Result<
    (
        granary_core::support_trigger::Header,
        Option<granary_core::support::BundleArchive>,
    ),
    SupportRequestFailure,
> {
    support::request(
        stream,
        owner,
        owner,
        deadline,
        &granary_client::TokioSyncRuntime,
    )
    .await
}

fn wire_result(outcome: MountOutcome) -> ResultKind {
    match outcome {
        MountOutcome::Clean => ResultKind::Clean,
        MountOutcome::RuntimeFailure | MountOutcome::Usage => ResultKind::RuntimeFailure,
        MountOutcome::CacheCloseFailed => ResultKind::CacheCloseFailed,
        MountOutcome::Stopped => ResultKind::Stopped,
        MountOutcome::Fenced => ResultKind::Fenced,
    }
}
fn mount_result(result: ResultKind) -> MountOutcome {
    match result {
        ResultKind::Clean => MountOutcome::Clean,
        ResultKind::RuntimeFailure => MountOutcome::RuntimeFailure,
        ResultKind::CacheCloseFailed => MountOutcome::CacheCloseFailed,
        ResultKind::Stopped => MountOutcome::Stopped,
        ResultKind::Fenced => MountOutcome::Fenced,
    }
}
fn wire_report(report: granary_client::ShutdownReport) -> wire::Report {
    use granary_client::{FailureClass, ShutdownCause, ShutdownCut, ShutdownOutcome};
    let kind = match report.outcome {
        ShutdownOutcome::Committed(seq) => ReportKind::Committed(seq),
        ShutdownOutcome::Clean => ReportKind::Clean,
        ShutdownOutcome::Incomplete(ShutdownCause::Deadline) => match report.cut {
            Some(ShutdownCut::Bound) => ReportKind::Bound,
            Some(ShutdownCut::Signal) => ReportKind::Signal,
            None => ReportKind::UnknownCut,
        },
        ShutdownOutcome::Incomplete(ShutdownCause::Internal) => ReportKind::Internal,
        ShutdownOutcome::Incomplete(ShutdownCause::Failed(class)) => {
            ReportKind::Failed(match class {
                FailureClass::Io => WireClass::Io,
                FailureClass::Refused => WireClass::Refused,
                FailureClass::Conflict => WireClass::Conflict,
                FailureClass::Unavailable => WireClass::Unavailable,
                FailureClass::Corrupt => WireClass::Corrupt,
                FailureClass::Internal => WireClass::Internal,
            })
        }
        ShutdownOutcome::Fenced => ReportKind::Fenced,
    };
    wire::Report {
        kind,
        elapsed_ms: report.elapsed_ms,
        residue: report.residue.map(|left| wire::Residue {
            files: left.files,
            bytes: left.bytes,
            operations: left.operations,
        }),
    }
}

fn report_from_wire(report: wire::Report) -> granary_client::ShutdownReport {
    use granary_client::{FailureClass, ShutdownCause, ShutdownCut, ShutdownOutcome};
    let (outcome, cut) = match report.kind {
        ReportKind::Committed(seq) => (ShutdownOutcome::Committed(seq), None),
        ReportKind::Clean => (ShutdownOutcome::Clean, None),
        ReportKind::Bound => (
            ShutdownOutcome::Incomplete(ShutdownCause::Deadline),
            Some(ShutdownCut::Bound),
        ),
        ReportKind::Signal => (
            ShutdownOutcome::Incomplete(ShutdownCause::Deadline),
            Some(ShutdownCut::Signal),
        ),
        ReportKind::UnknownCut => (ShutdownOutcome::Incomplete(ShutdownCause::Deadline), None),
        ReportKind::Failed(class) => (
            ShutdownOutcome::Incomplete(ShutdownCause::Failed(match class {
                WireClass::Io => FailureClass::Io,
                WireClass::Refused => FailureClass::Refused,
                WireClass::Conflict => FailureClass::Conflict,
                WireClass::Unavailable => FailureClass::Unavailable,
                WireClass::Corrupt => FailureClass::Corrupt,
                WireClass::Internal => FailureClass::Internal,
            })),
            None,
        ),
        ReportKind::Internal => (ShutdownOutcome::Incomplete(ShutdownCause::Internal), None),
        ReportKind::Fenced => (ShutdownOutcome::Fenced, None),
    };
    granary_client::ShutdownReport {
        outcome,
        cut,
        elapsed_ms: report.elapsed_ms,
        residue: report.residue.map(|left| granary_client::Residue {
            files: left.files,
            bytes: left.bytes,
            operations: left.operations,
        }),
    }
}

fn peer_admitted(actual: std::io::Result<u32>, owner: u32, admitted: u32) -> bool {
    actual.is_ok_and(|actual| actual == owner && owner == admitted)
}

#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;
