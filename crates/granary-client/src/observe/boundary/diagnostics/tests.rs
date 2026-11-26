// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
#[cfg(feature = "overlay-fault-tests")]
use crate::observe::boundary::{
    FaultPhase, OverlayFaultPoint, SyncFaultPhase, SyncFaultPoint, SyncObjectKind,
};
use crate::observe::boundary::{FilterDetail, FilterSource, PublishOperationId, RecoveryClass};
use crate::observe::{FilterRejection, LogDestination, OperationKind, Outcome, RetryReason};
use crate::{LogFormat, observe::tests::Capture};
use tracing_subscriber::EnvFilter;

mod fixtures;
mod scan;
mod seeded;

#[test]
fn the_detach_target_diagnostic_reports_its_class_and_never_the_path() {
    let output = Capture::default();
    let subscriber =
        super::super::closed_subscriber(LogFormat::Json, EnvFilter::new("warn"), output.clone());
    tracing::subscriber::with_default(subscriber, || {
        OperatorDiagnostic::gran_mount_detach_target_unavailable_lazy_detach_cannot_be(
            FailureClass::Unavailable,
        )
        .emit();
    });
    let lines = output.lines();
    assert_eq!(lines.len(), 1, "the diagnostic must emit");
    assert!(
        lines[0].contains("\"error\":\"unavailable\""),
        "the detach diagnostic lost its failure class: {}",
        lines[0]
    );
}

#[test]
fn every_diagnostic_names_the_callsite_its_values_are_built_for() {
    let diagnostics = fixtures::diagnostics();
    assert_eq!(diagnostics.len(), 106, "nonempty exhaustive inventory");
    for diagnostic in diagnostics {
        let event = ClientEvent {
            payload: Payload::Diagnostic(diagnostic.inner),
        };
        assert!(
            std::ptr::eq(event.meta(), event.fields().0),
            "meta and fields disagree for {:?}",
            event.meta().name()
        );
    }
}

#[test]
fn every_diagnostic_schema_admits_its_typed_constructor_in_both_formats() {
    for format in [LogFormat::Text, LogFormat::Json] {
        let output = Capture::default();
        let subscriber =
            super::super::closed_subscriber(format, EnvFilter::new("trace"), output.clone());
        tracing::subscriber::with_default(subscriber, || {
            let events = fixtures::diagnostics();
            assert_eq!(
                events.len(),
                106,
                "nonempty exhaustive constructor inventory"
            );
            for event in events {
                event.emit();
            }
        });
        let lines = output.lines();
        assert_eq!(lines.len(), 106, "no event lost or refused");
        assert!(
            lines
                .iter()
                .all(|line| !line.contains("log.record_refused")),
            "legitimate schemas admitted: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("dropped_records") && line.contains('7'))
        );
        assert!(lines.iter().any(
            |line| line.contains("structure walk") && line.contains("granary_client::resolve")
        ));
        if format == LogFormat::Text {
            assert!(lines.iter().any(|line| line.contains("INFO granary_client::resolve: structure walk round=7 outcome=need needs=7 hints=7 admits=7 pool_len=7 pool_used=7")), "structure instrument spelling");
        }
    }
}
