// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;

pub(super) fn hello() -> wire::Hello {
    wire::Hello {
        instance: [7; 16],
        key: wire::MountKey {
            namespace_dev: 1,
            namespace_ino: 2,
            mount_id: 3,
            fuse_major: 0,
            fuse_minor: 4,
        },
        mode: wire::Mode::Writable {
            bound_seconds: 30,
            store: b"store".to_vec(),
        },
    }
}

#[test]
fn umount_result_and_report_conversion() {
    let report = granary_client::ShutdownReport {
        outcome: granary_client::ShutdownOutcome::Committed(9),
        cut: None,
        residue: None,
        elapsed_ms: 12,
    };
    let mut cases = 0;
    for outcome in [
        MountOutcome::Clean,
        MountOutcome::RuntimeFailure,
        MountOutcome::CacheCloseFailed,
        MountOutcome::Stopped,
        MountOutcome::Fenced,
    ] {
        assert_eq!(mount_result(wire_result(outcome)), outcome);
        cases += 1;
    }
    assert_eq!(report_from_wire(wire_report(report)), report);
    assert_eq!(cases, 5);
}

#[test]
fn control_report_conversion_is_lossless() {
    use granary_client::{
        FailureClass as C, ShutdownCause as Cause, ShutdownCut as Cut, ShutdownOutcome as O,
    };
    let mut cases = 0;
    for (outcome, cut, kind) in [
        (O::Committed(9), None, ReportKind::Committed(9)),
        (O::Clean, None, ReportKind::Clean),
        (
            O::Incomplete(Cause::Deadline),
            Some(Cut::Bound),
            ReportKind::Bound,
        ),
        (
            O::Incomplete(Cause::Deadline),
            Some(Cut::Signal),
            ReportKind::Signal,
        ),
        (O::Incomplete(Cause::Deadline), None, ReportKind::UnknownCut),
        (O::Incomplete(Cause::Internal), None, ReportKind::Internal),
        (O::Fenced, None, ReportKind::Fenced),
        (
            O::Incomplete(Cause::Failed(C::Io)),
            None,
            ReportKind::Failed(WireClass::Io),
        ),
        (
            O::Incomplete(Cause::Failed(C::Refused)),
            None,
            ReportKind::Failed(WireClass::Refused),
        ),
        (
            O::Incomplete(Cause::Failed(C::Conflict)),
            None,
            ReportKind::Failed(WireClass::Conflict),
        ),
        (
            O::Incomplete(Cause::Failed(C::Unavailable)),
            None,
            ReportKind::Failed(WireClass::Unavailable),
        ),
        (
            O::Incomplete(Cause::Failed(C::Corrupt)),
            None,
            ReportKind::Failed(WireClass::Corrupt),
        ),
        (
            O::Incomplete(Cause::Failed(C::Internal)),
            None,
            ReportKind::Failed(WireClass::Internal),
        ),
    ] {
        let kept = !matches!(kind, ReportKind::Committed(_) | ReportKind::Clean);
        let report = granary_client::ShutdownReport {
            outcome,
            cut,
            elapsed_ms: 12,
            residue: kept.then_some(granary_client::Residue {
                files: u64::MAX,
                bytes: u64::MAX,
                operations: u64::MAX,
            }),
        };
        let expected = wire::Report {
            kind,
            elapsed_ms: 12,
            residue: kept.then_some(wire::Residue {
                files: u64::MAX,
                bytes: u64::MAX,
                operations: u64::MAX,
            }),
        };
        assert_eq!(
            (wire_report(report), report_from_wire(expected)),
            (expected, report)
        );
        cases += 1;
    }
    assert_eq!(cases, 13);
}

#[test]
fn control_peer_policy() {
    let mut cases = 0;
    for (actual, owner, admitted, expected) in [
        (Some(5), 5, 5, true),
        (Some(0), 0, 0, true),
        (Some(0), 5, 0, false),
        (Some(0), 5, 5, false),
        (Some(6), 5, 5, false),
        (None, 5, 5, false),
    ] {
        assert_eq!(
            peer_admitted(
                actual.ok_or_else(|| std::io::Error::other("credential query failed")),
                owner,
                admitted
            ),
            expected,
            "actual={actual:?}, owner={owner}, admitted={admitted}"
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
    assert_eq!(escaped_path(b"a\n\x1b\xff"), "a\\n\\x1b\\xff");
}
