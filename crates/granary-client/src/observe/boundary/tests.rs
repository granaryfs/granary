// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::observe::tests::{Capture, Fixed, top_level_keys};
use granary_core::secure_random::EntropyUnavailable;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn recovery_cli_and_event_contract_match_observed_completion() {
    use crate::observe::RecoverEvent;
    let mut cases = 0;
    for reason in [
        "selected-root-not-proved-published",
        "replay",
        "publication",
        "obligations",
        "namespace",
        "limit",
        "release",
    ] {
        let lines = capture(LogFormat::Json, "trace", || {
            crate::observe::recover(RecoverEvent::JournalBlocked(reason));
        });
        assert_eq!(
            (
                lines.len(),
                lines
                    .first()
                    .is_some_and(|line| line.contains("\"event\":\"recover.journal_blocked\"")),
                lines
                    .first()
                    .is_some_and(|line| line.contains(&format!("\"reason\":\"{reason}\"")))
            ),
            (1, true, true),
            "{lines:?}"
        );
        cases += 1;
    }
    let lines = capture(LogFormat::Json, "trace", || {
        crate::observe::recover(RecoverEvent::JournalFinished(7));
        send(
            &RECOVER_BLOCKED_META,
            &[Some(&"recover.journal_blocked"), None],
        );
        send(
            &RECOVER_BLOCKED_META,
            &[Some(&"recover.journal_blocked"), Some(&"unknown")],
        );
        send(
            &RECOVER_FINISHED_META,
            &[Some(&"recover.journal_finished"), Some(&"7")],
        );
    });
    assert_eq!(
        (lines.len(), lines[0].contains("\"base_seq\":7")),
        (4, true),
        "{lines:?}"
    );
    for (line, refusal) in
        lines
            .iter()
            .skip(1)
            .zip(["invalid_schema", "invalid_domain", "invalid_scalar"])
    {
        assert!(
            line.contains(&format!("\"reason\":\"{refusal}\"")),
            "{line}"
        );
        cases += 1;
    }
    assert_eq!(cases, 10);
}

#[test]
fn stripped_settlement_requires_the_exact_event_schema() {
    let lines = capture(LogFormat::Json, "trace", || {
        send(
            &RECOVER_FENCE_META,
            &[Some(&"recover.fence_settled"), Some(&"stripped")],
        );
        send(&RECOVER_FENCE_META, &[Some(&"recover.fence_settled"), None]);
        send(
            &RECOVER_FENCE_META,
            &[
                Some(&"recover.fence_settled"),
                Some(&"PRIVATE_HOW_SENTINEL"),
            ],
        );
        send(
            &RECOVER_FENCE_META,
            &[Some(&"recover.fence_settled"), Some(&7u64)],
        );
    });
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert!(lines[0].contains("\"how\":\"stripped\""), "{lines:?}");
    for (line, refusal) in
        lines
            .iter()
            .skip(1)
            .zip(["invalid_schema", "invalid_domain", "invalid_scalar"])
    {
        assert!(
            line.contains(&format!("\"reason\":\"{refusal}\"")),
            "{line}"
        );
    }
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("PRIVATE_HOW_SENTINEL"))
    );
}

fn capture(format: LogFormat, filter: &str, body: impl FnOnce()) -> Vec<String> {
    let output = Capture::default();
    let subscriber = closed_subscriber(format, EnvFilter::try_new(filter).unwrap(), output.clone());
    tracing::subscriber::with_default(subscriber, body);
    output.lines()
}

fn all_events() -> Vec<ClientEvent> {
    vec![
        ClientEvent::commit_contention(4, 1),
        ClientEvent::conflict_detail(),
        ClientEvent::overlay_recovery(
            RecoveryClass::Repaired,
            7,
            800,
            9,
            4096,
            true,
            OverlayOwed {
                owed: 512,
                stages: 2048,
                projected: 256,
                ownership: 1024,
                completion: 1732,
                writer: 64,
                journal: 117,
            },
            [2, 12],
        ),
        ClientEvent::stage_rolled_back(9, 2, 10, 8, 6, true),
        ClientEvent::stage_rolled_back(10, 3, 6, 0, 6, false),
        ClientEvent::overlay_refused(FailureClass::Corrupt, 9, 7, 800),
        ClientEvent::overlay_discard_refused(crate::OverlayRefusal::ForeignCustody),
        ClientEvent::overlay_reconcile_refused(crate::OverlayRefusal::RemoteIntegrity),
        ClientEvent::recovery_signing_key_refused(),
        ClientEvent::overlay_sweep(7, 800),
        ClientEvent::overlay_failures_dropped(3),
        ClientEvent::overlay_fault(OverlayFaultPoint::StageWrite, FaultPhase::Before, 2, 9),
        ClientEvent::sync_fault(
            SyncFaultPoint::Capture,
            SyncFaultPhase::After,
            2,
            SyncObjectKind::None,
        ),
        ClientEvent::op_begin(OperationKind::Commit),
        ClientEvent::op_end(OperationKind::Commit, Outcome::Ok),
        ClientEvent::op_retry(OperationKind::Rebase, 3, RetryReason::Conflict),
        ClientEvent::op_failed(OperationKind::Fsync, FailureClass::Io),
        ClientEvent::metrics_export_failed(crate::MetricsFailureClass::Io),
        ClientEvent::publish_bound(PublishOperationId::draw(&mut Fixed(&[42; 8]), 8).unwrap()),
        ClientEvent::log_config(LogFormat::Json, LogDestination::File),
        ClientEvent::log_filter_rejected(
            FilterSource::RustLog,
            FilterRejection::Malformed,
            FilterDetail::Malformed,
        ),
    ]
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one independent inventory lists every closed event's fields"
)]
fn closed_events_match_the_independent_inventory_and_project_before_emission() {
    let inventory = [
        ("commit.contention", "WARN", vec!["commits", "conflicts"]),
        ("op.conflict", "WARN", vec!["path", "class"]),
        (
            "overlay.recovery",
            "INFO",
            vec![
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
        ),
        (
            "overlay.stage_rolled_back",
            "WARN",
            vec![
                "rollback_seq",
                "stage_id",
                "old_size",
                "restored_size",
                "discarded_bytes",
                "path",
            ],
        ),
        (
            "overlay.stage_rolled_back",
            "WARN",
            vec![
                "rollback_seq",
                "stage_id",
                "old_size",
                "restored_size",
                "discarded_bytes",
            ],
        ),
        (
            "overlay.refused",
            "ERROR",
            vec!["class", "record_index", "files", "bytes"],
        ),
        ("overlay.discard_refused", "WARN", vec!["reason"]),
        ("overlay.reconcile_refused", "WARN", vec!["reason"]),
        ("recover.signing_key_refused", "WARN", vec![]),
        ("overlay.sweep", "INFO", vec!["files", "bytes"]),
        ("overlay.failures_dropped", "ERROR", vec!["dropped"]),
        (
            "overlay.fault",
            "WARN",
            vec!["point", "phase", "occurrence", "record_index"],
        ),
        (
            "sync.fault",
            "WARN",
            vec!["point", "phase", "occurrence", "object_kind"],
        ),
        ("op.begin", "DEBUG", vec!["kind"]),
        ("op.end", "DEBUG", vec!["kind", "outcome"]),
        ("op.retry", "WARN", vec!["kind", "attempt", "reason"]),
        ("op.failed", "ERROR", vec!["kind", "class"]),
        ("metrics.export_failed", "ERROR", vec!["class"]),
        ("op.publish_bound", "INFO", vec!["publish_operation"]),
        ("log.config", "DEBUG", vec!["format", "destination"]),
        (
            "log.filter_rejected",
            "WARN",
            vec!["source", "reason", "detail"],
        ),
    ];
    let events = all_events();
    assert_eq!(
        events.len(),
        inventory.len(),
        "nonempty complete constructor inventory"
    );
    for (event, (name, level, fields)) in events.iter().zip(&inventory) {
        let (log, bundle) = event.project();
        let log_text = std::str::from_utf8(log.as_bytes()).unwrap();
        let bundle_text = std::str::from_utf8(bundle.as_bytes()).unwrap();
        assert!(
            log_text.contains(&format!("\"event\":\"{name}\"")),
            "safe event identity mismatch"
        );
        assert!(
            bundle_text.contains(&format!("\"event\":\"{name}\"")),
            "safe bundle identity mismatch"
        );
        assert!(
            log_text.contains(&format!("\"level\":\"{level}\"")),
            "safe level mismatch"
        );
        let mut expected = fields.clone();
        expected.extend(["level", "target", "event"]);
        expected.sort_unstable();
        let mut actual = top_level_keys(log_text);
        actual.sort();
        assert_eq!(actual, expected, "safe schema mismatch");
        assert_eq!(
            log_text, bundle_text,
            "independent projections of safe scalars"
        );
        assert_eq!(format!("{log:?}"), "<log-record>");
        assert_eq!(format!("{bundle:?}"), "<bundle-record>");
    }
    for format in [LogFormat::Text, LogFormat::Json] {
        let lines = capture(format, "trace", || {
            for event in &events {
                event.emit();
            }
        });
        assert_eq!(
            lines.len(),
            inventory.len(),
            "all registered sites must be admitted"
        );
        for (line, (name, _, _)) in lines.iter().zip(&inventory) {
            assert!(line.contains(name), "safe event identity mismatch");
            assert!(
                !line.contains("log.record_refused"),
                "legitimate event refused"
            );
        }
    }
}

#[test]
fn foreign_callsite_copying_target_name_and_fields_is_refused() {
    let lines = capture(LogFormat::Json, "trace", || {
        ClientEvent::op_begin(OperationKind::Commit).emit();
        tracing::event!(name: "op.begin", target: "granary_client::event", Level::DEBUG,
            event = "op.begin", kind = "commit");
    });
    assert_eq!(
        lines.len(),
        2,
        "legitimate and foreign premises must execute"
    );
    assert!(
        lines[0].contains("\"event\":\"op.begin\""),
        "legitimate site admitted"
    );
    assert!(
        lines[1].contains("\"reason\":\"unregistered_callsite\""),
        "foreign copied callsite must be refused"
    );
    assert!(
        !lines[1].contains("\"kind\""),
        "rejected fields must not be forwarded"
    );
}

#[test]
fn workspace_event_accepts_only_the_local_refusal_name() {
    let lines = capture(LogFormat::Json, "trace", || {
        ClientEvent::workspace_exhausted(2, 1).emit();
        send(
            &WORKSPACE_META,
            &[
                Some(&"sync.workspace_exhausted"),
                Some(&"remote-echo"),
                Some(&2_u64),
                Some(&1_u64),
            ],
        );
    });
    assert_eq!(
        (
            lines.len(),
            lines[0].contains("\"reason\":\"SyncWorkspaceExhausted\""),
            lines[1].contains("\"reason\":\"invalid_domain\"")
        ),
        (2, true, true),
        "{lines:?}"
    );
}

struct Bomb(AtomicUsize);
impl std::fmt::Debug for Bomb {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(std::fmt::Error)
    }
}
impl std::fmt::Display for Bomb {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(std::fmt::Error)
    }
}

fn send(meta: &'static Metadata<'static>, values: &[Option<&dyn Value>]) {
    tracing::dispatcher::get_default(|dispatch| {
        dispatch.event(&Event::new(meta, &meta.fields().value_set_all(values)));
    });
}

#[test]
fn registered_debug_display_and_message_wrappers_are_never_formatted() {
    let bomb = Bomb(AtomicUsize::new(0));
    let lines = capture(LogFormat::Json, "trace", || {
        let debug = tracing::field::debug(&bomb);
        send(&BEGIN_META, &[Some(&"op.begin"), Some(&debug)]);
        let display = tracing::field::display(&bomb);
        send(&BEGIN_META, &[Some(&"op.begin"), Some(&display)]);
        tracing::warn!(target: "granary_client::event", message = ?bomb);
        tracing::error_span!(target: "granary_client::event", "op", op = %bomb).in_scope(|| {
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        });
    });
    assert_eq!(
        bomb.0.load(Ordering::SeqCst),
        0,
        "boundary must not evaluate Debug or Display"
    );
    assert_eq!(
        lines.len(),
        5,
        "all rejection and legitimate event premises must execute"
    );
    assert_eq!(
        lines.iter().filter(|l| l.contains("debug_field")).count(),
        2
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("unregistered_callsite"))
            .count(),
        2
    );
    assert!(
        lines[4].contains("op.failed"),
        "foreign span cannot suppress legitimate child events"
    );
    assert!(
        !lines[4].contains("spans"),
        "foreign span never enters extensions"
    );
}

#[test]
fn registered_sites_require_complete_schemas_scalar_types_and_closed_domains() {
    let lines = capture(LogFormat::Json, "trace", || {
        send(&BEGIN_META, &[Some(&"op.begin"), None]);
        send(&BEGIN_META, &[Some(&"op.begin"), Some(&19_u64)]);
        send(
            &BEGIN_META,
            &[Some(&"op.begin"), Some(&"synthetic-scope-sentinel")],
        );
        send(
            &BEGIN_META,
            &[Some(&"op.begin"), Some(&"x".repeat(RECORD_MAX + 1))],
        );
        send(&BEGIN_META, &[Some(&"op.failed"), Some(&"commit")]);
        ClientEvent::op_begin(OperationKind::Commit).emit();
    });
    assert_eq!(
        lines.len(),
        6,
        "invalid and valid premises must all execute"
    );
    for (line, reason) in lines.iter().zip([
        "invalid_schema",
        "invalid_scalar",
        "invalid_domain",
        "record_too_large",
        "invalid_domain",
    ]) {
        assert!(line.contains(reason), "wrong closed refusal reason");
        assert!(
            !line.contains("synthetic-scope-sentinel"),
            "rejected value retained"
        );
        assert!(!line.contains("kind"), "rejected scalar fields retained");
    }
    assert!(lines[5].contains("op.begin"), "valid paired control");
}

#[test]
fn mount_session_warning_refuses_out_of_domain_observations() {
    use super::super::{FuseConnection, MOUNT_SESSION_DID_NOT_END, MountListing};

    let meta = diagnostics::SITES
        .iter()
        .find(|meta| meta.name() == MOUNT_SESSION_DID_NOT_END)
        .expect("missing session warning site");
    let message = "gran mount: stopped waiting for the FUSE session to end after its unmount";
    let lines = capture(LogFormat::Json, "warn", || {
        OperatorDiagnostic::gran_mount_the_fuse_session_did_not_end_after_its_unmount(
            MountListing::Gone,
            FuseConnection::Alive,
        )
        .emit();
        for (message, listed, connection) in [
            (message, "gone", "alive"),
            (message, "alive", "alive"),
            (message, "gone", "listed"),
            (
                "gran mount: stopped waiting for the FUSE session to end",
                "gone",
                "alive",
            ),
        ] {
            send(
                meta,
                &[
                    Some(&MOUNT_SESSION_DID_NOT_END),
                    Some(&message),
                    Some(&listed),
                    Some(&connection),
                ],
            );
        }
    });
    let message_field = format!(r#""message":"{message}""#);
    let observations: Vec<_> = lines
        .iter()
        .map(|line| {
            (
                line.contains(MOUNT_SESSION_DID_NOT_END) && line.contains(&message_field),
                line.contains("log.record_refused") && line.contains("invalid_domain"),
            )
        })
        .collect();
    assert_eq!(
        observations,
        [
            (true, false),
            (true, false),
            (false, true),
            (false, true),
            (false, true),
        ],
        "expected the warning and valid control, then one domain refusal per field: {lines:?}"
    );
}

#[test]
fn registry_keys_have_distinct_file_line_pairs_and_refuse_missing_locations() {
    let mut keys = Vec::new();
    for meta in SITES {
        let key = (meta.target(), meta.file(), meta.line());
        assert!(key.1.is_some() && key.2.is_some());
        assert!(!keys.contains(&key), "duplicate metadata triple");
        keys.push(key);
        assert!(registered(meta).is_some());
    }
    assert_eq!(keys.len(), 46, "forty-five event sites and one span");
    for (file, line) in [(None, BEGIN_META.line()), (BEGIN_META.file(), None)] {
        let meta = Metadata::new(
            "op.begin",
            TARGET,
            Level::DEBUG,
            file,
            line,
            None,
            FieldSet::new(&["event", "kind"], Identifier(&BEGIN_SITE)),
            tracing::metadata::Kind::EVENT,
        );
        assert!(registered(&meta).is_none(), "absent metadata must refuse");
    }
    let meta = Metadata::new(
        "op.begin",
        TARGET,
        Level::DEBUG,
        BEGIN_META.file(),
        BEGIN_META.line(),
        None,
        FieldSet::new(&["event", "kind", "unknown"], Identifier(&BEGIN_SITE)),
        tracing::metadata::Kind::EVENT,
    );
    assert!(!same_schema(&meta, &BEGIN_META), "extra fields must refuse");
}

#[test]
fn span_creation_updates_and_filtering_preserve_only_approved_context() {
    let id = CorrelationId::draw(&mut Fixed(&[11; 8])).unwrap();
    let bomb = Bomb(AtomicUsize::new(0));
    let lines = capture(LogFormat::Json, "warn", || {
        let span = closed_operation_span(OperationKind::Commit, &id);
        assert!(!span.is_disabled(), "ERROR span survives warn filter");
        span.record("kind", "rebase");
        span.record("op", tracing::field::display(&bomb));
        span.record("kind", "synthetic-volume-sentinel");
        span.in_scope(|| {
            ClientEvent::op_begin(OperationKind::Commit).emit();
            ClientEvent::op_retry(OperationKind::Commit, 2, RetryReason::Transient).emit();
        });
        ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
    });
    assert_eq!(
        bomb.0.load(Ordering::SeqCst),
        0,
        "span updates cannot invoke Display"
    );
    assert_eq!(lines.len(), 4, "two refusals and two admitted events");
    assert!(lines[0].contains("debug_field"));
    assert!(lines[1].contains("invalid_domain"));
    assert!(
        lines[2].contains("cor-0b0b0b0b0b0b0b0b"),
        "correlation must survive warn filtering"
    );
    assert!(
        lines[2].contains("\"kind\":\"rebase\""),
        "legitimate span update admitted"
    );
    assert!(
        !lines[2].contains("synthetic-volume-sentinel"),
        "invalid update must not replace context"
    );
    assert!(
        !lines[3].contains("spans"),
        "closed span cannot remain inherited"
    );
}

#[test]
fn unknown_callsite_is_rejected_before_dynamic_filter_observation() {
    let bomb = Bomb(AtomicUsize::new(0));
    let lines = capture(
        LogFormat::Json,
        "off,[foreign{value=observed}]=trace",
        || {
            tracing::error_span!("foreign", value = ?bomb).in_scope(|| {
                tracing::warn!(target: "dependency", value = %bomb);
            });
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        },
    );
    assert_eq!(
        bomb.0.load(Ordering::SeqCst),
        0,
        "EnvFilter must never see foreign values"
    );
    assert!(
        lines.is_empty(),
        "refusals obey the filter like any warning; the legitimate event is filtered OFF"
    );
}

#[test]
fn publish_identity_preserves_255_bytes_and_refuses_256_before_entropy() {
    struct Owner {
        calls: usize,
    }
    impl SecureRandom for Owner {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), EntropyUnavailable> {
            self.calls += 1;
            bytes.fill(42);
            Ok(())
        }
    }
    let mut owner = Owner { calls: 0 };
    let id = PublishOperationId::draw(&mut owner, 255).unwrap();
    assert_eq!(format!("{id:?}"), "<publish-operation>");
    assert_eq!(owner.calls, 1);
    let lines = capture(LogFormat::Json, "info", || {
        ClientEvent::publish_bound(id).emit();
    });
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains(&format!("\"publish_operation\":\"{}\"", "2a".repeat(255))),
        "exact unshortened join required"
    );
    assert!(matches!(
        PublishOperationId::draw(&mut owner, 256),
        Err(PublishOperationRefusal::Length)
    ));
    assert!(matches!(
        PublishOperationId::draw(&mut owner, 0),
        Err(PublishOperationRefusal::Length)
    ));
    assert_eq!(
        owner.calls, 1,
        "invalid lengths must refuse before draw or emission"
    );
}

#[test]
fn oversized_record_replaces_the_entire_projection_without_a_prefix() {
    let values = vec![Scalar::text("op.begin"), Scalar::text("commit")];
    let spans = vec![vec![Scalar::text("cor-0000000000000000"), Scalar::text("commit")]; 800];
    for format in [LogFormat::Json, LogFormat::Text] {
        let record = encode(&BEGIN_META, &values, &spans, format);
        assert!(
            record.contains("record_too_large"),
            "whole-record bound must refuse"
        );
        assert!(
            !record.contains("cor-"),
            "overflow must not emit a partially rendered prefix"
        );
        assert!(
            !record.contains("op.begin"),
            "overflow must replace original event"
        );
    }
}

#[test]
fn admission_refuses_extra_fields_and_metadata_schema_changes() {
    let meta = |name, level, kind, fields| {
        &*Box::leak(Box::new(Metadata::new(
            name,
            TARGET,
            level,
            BEGIN_META.file(),
            BEGIN_META.line(),
            None,
            FieldSet::new(fields, Identifier(&BEGIN_SITE)),
            kind,
        )))
    };
    let extra = meta(
        "op.begin",
        Level::DEBUG,
        tracing::metadata::Kind::EVENT,
        &["event", "kind", "unknown"],
    );
    let level = meta(
        "op.begin",
        Level::ERROR,
        tracing::metadata::Kind::EVENT,
        &["event", "kind"],
    );
    let name = meta(
        "foreign",
        Level::DEBUG,
        tracing::metadata::Kind::EVENT,
        &["event", "kind"],
    );
    let span_kind = meta(
        "op.begin",
        Level::DEBUG,
        tracing::metadata::Kind::SPAN,
        &["event", "kind"],
    );
    let lines = capture(LogFormat::Json, "trace", || {
        send(
            extra,
            &[
                Some(&"op.begin"),
                Some(&"commit"),
                Some(&"synthetic-token-sentinel"),
            ],
        );
        for schema in [level, name, span_kind] {
            send(schema, &[Some(&"op.begin"), Some(&"commit")]);
        }
        ClientEvent::op_begin(OperationKind::Commit).emit();
    });
    assert_eq!(
        lines.len(),
        5,
        "four invalid schemas and valid paired control {lines:?}"
    );
    assert!(
        lines
            .iter()
            .take(4)
            .all(|line| line.contains("invalid_schema")),
        "schema admission must refuse altered metadata {lines:?}"
    );
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("synthetic-token-sentinel")),
        "invalid schema values cannot be retained"
    );
    assert!(lines[4].contains("op.begin"));
}

#[test]
fn registered_dynamic_filter_observes_only_approved_span_scalars() {
    let id = CorrelationId::draw(&mut Fixed(&[12; 8])).unwrap();
    let lines = capture(LogFormat::Json, "off,[op{kind=commit}]=debug", || {
        let span = closed_operation_span(OperationKind::Commit, &id);
        assert!(
            !span.is_disabled(),
            "registered span must activate a matching dynamic directive"
        );
        span.in_scope(|| ClientEvent::op_begin(OperationKind::Commit).emit());
        ClientEvent::op_begin(OperationKind::Commit).emit();
    });
    assert_eq!(
        lines.len(),
        1,
        "dynamic directive applies only inside admitted span"
    );
    assert!(lines[0].contains("cor-0c0c0c0c0c0c0c0c"));
}

#[test]
fn registered_span_creation_refuses_debug_before_context_storage() {
    let bomb = Bomb(AtomicUsize::new(0));
    let lines = capture(LogFormat::Json, "trace", || {
        let debug = tracing::field::debug(&bomb);
        let fields: [Option<&dyn Value>; 2] = [Some(&debug), Some(&"commit")];
        tracing::dispatcher::get_default(|dispatch| {
            let id = dispatch.new_span(&Attributes::new(
                &OPERATION_META,
                &OPERATION_META.fields().value_set_all(&fields),
            ));
            dispatch.enter(&id);
            let (meta, values) = ClientEvent::op_begin(OperationKind::Commit).fields();
            let fields: Vec<Option<&dyn Value>> =
                values.iter().map(|value| Some(value.value())).collect();
            dispatch.event(&Event::new(meta, &meta.fields().value_set_all(&fields)));
            dispatch.exit(&id);
            dispatch.try_close(id);
        });
    });
    assert_eq!(
        bomb.0.load(Ordering::SeqCst),
        0,
        "registered span cannot evaluate Debug"
    );
    assert_eq!(
        lines.len(),
        2,
        "invalid registered span and legitimate event execute"
    );
    assert!(lines[0].contains("debug_field"));
    assert!(lines[1].contains("op.begin"));
    assert!(
        !lines[1].contains("spans"),
        "rejected attributes cannot enter context storage"
    );
}

#[test]
fn nested_operations_keep_their_context_and_restore_the_parent_after_close() {
    let session = CorrelationId::draw(&mut Fixed(&[1; 8])).unwrap();
    let operation = CorrelationId::draw(&mut Fixed(&[2; 8])).unwrap();
    let lines = capture(LogFormat::Json, "warn", || {
        let outer = closed_operation_span(OperationKind::Session, &session);
        let _entered = outer.enter();
        {
            let inner = closed_operation_span(OperationKind::Commit, &operation);
            let _entered = inner.enter();
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        }
        ClientEvent::op_failed(OperationKind::Session, FailureClass::Io).emit();
    });
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("cor-0101010101010101") && lines[0].contains("cor-0202020202020202"));
    assert!(
        lines[1].contains("cor-0101010101010101") && !lines[1].contains("cor-0202020202020202")
    );
}

fn session_with_history(
    filter: &str,
    history: &BundleHistory,
) -> (Capture, Box<dyn Subscriber + Send + Sync>) {
    let output = Capture::default();
    let subscriber = closed_subscriber_with_paths(
        LogFormat::Json,
        EnvFilter::try_new(filter).unwrap(),
        output.clone(),
        LogPaths::Redacted,
        history.clone(),
    );
    (output, subscriber)
}

fn refusals(history: &BundleHistory) -> usize {
    history
        .snapshot()
        .records()
        .iter()
        .filter(|r| String::from_utf8_lossy(r.as_bytes()).contains("log.record_refused"))
        .count()
}

#[test]
fn a_dependency_callsite_is_refused_once_not_once_per_event() {
    // Three dependency callsites at trace, debug and warn: a refusal is owed
    // only for those the filter admits, and only once each.
    for (filter, refused_callsites) in [("trace", 3), ("info", 1), ("off", 0)] {
        let history = BundleHistory::default();
        let (output, subscriber) = session_with_history(filter, &history);
        tracing::subscriber::with_default(subscriber, || {
            for round in 0..200_u64 {
                tracing::trace!(target: "h2::proto::connection", round, "frame");
                tracing::debug_span!(target: "hyper_util::client", "checkout", round).in_scope(
                    || {
                        tracing::warn!(target: "object_store::client", round, "retry");
                    },
                );
            }
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        });
        let lines = output.lines();
        let refused = lines
            .iter()
            .filter(|l| l.contains("unregistered_callsite"))
            .count();
        assert_eq!(refused, refused_callsites, "{filter}: telemetry refusals");
        assert_eq!(
            refusals(&history),
            refused_callsites,
            "{filter}: bundle history is not flooded either"
        );
        assert_eq!(
            lines.iter().filter(|l| l.contains("op.failed")).count(),
            usize::from(filter != "off"),
            "{filter}: the legitimate event is unaffected"
        );
    }
}

#[test]
fn an_admitted_event_is_validated_once() {
    let before = VALIDATIONS.with(std::cell::Cell::get);
    let lines = capture(LogFormat::Json, "warn", || {
        ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
    });
    assert_eq!(lines.len(), 1);
    assert_eq!(
        VALIDATIONS.with(std::cell::Cell::get) - before,
        1,
        "an event is validated once"
    );
    let before = VALIDATIONS.with(std::cell::Cell::get);
    let id = CorrelationId::draw(&mut Fixed(&[3; 8])).unwrap();
    let lines = capture(LogFormat::Json, "warn", || {
        let span = closed_operation_span(OperationKind::Commit, &id);
        span.in_scope(|| ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit());
    });
    assert_eq!(lines.len(), 1);
    assert_eq!(
        VALIDATIONS.with(std::cell::Cell::get) - before,
        2,
        "one validation for the span and one for the event"
    );
}

#[test]
fn registration_is_keyed_by_callsite_identity_not_by_copied_location() {
    // Another site's identity wearing BEGIN's target, file and line.
    let foreign: &'static Metadata<'static> = Box::leak(Box::new(Metadata::new(
        "op.begin",
        TARGET,
        Level::DEBUG,
        BEGIN_META.file(),
        BEGIN_META.line(),
        None,
        FieldSet::new(&["event", "kind"], Identifier(&END_SITE)),
        tracing::metadata::Kind::EVENT,
    )));
    assert!(
        registered(foreign).is_none(),
        "a callsite that copies a registered target, file and line is still foreign"
    );
    assert!(
        registered(&BEGIN_META).is_some(),
        "a registered site resolves by its own identity"
    );
}

#[test]
fn bundle_history_follows_its_own_policy_whatever_the_telemetry_filter() {
    let history = BundleHistory::default();
    let (output, subscriber) = session_with_history("off", &history);
    let before = ENCODER_ALLOCATIONS.with(std::cell::Cell::get);
    tracing::subscriber::with_default(subscriber, || {
        ClientEvent::op_begin(OperationKind::Commit).emit();
    });
    assert_eq!(
        ENCODER_ALLOCATIONS.with(std::cell::Cell::get),
        before,
        "an event neither the filter nor the bundle policy admits builds nothing"
    );
    assert!(output.lines().is_empty());
    assert!(history.snapshot().records().is_empty());

    let (output, subscriber) = session_with_history("off", &history);
    tracing::subscriber::with_default(subscriber, || {
        ClientEvent::op_retry(OperationKind::Commit, 2, RetryReason::Transient).emit();
    });
    assert!(
        output.lines().is_empty(),
        "the filter still governs telemetry"
    );
    let records = history.snapshot();
    assert_eq!(
        records.records().len(),
        1,
        "the bundle does not read the filter"
    );
    assert!(String::from_utf8_lossy(records.records()[0].as_bytes()).contains("op.retry"));
}

#[test]
fn bundle_records_carry_the_operation_id_when_the_filter_disables_the_span() {
    let history = BundleHistory::default();
    let (output, subscriber) = session_with_history("off", &history);
    let id = CorrelationId::draw(&mut Fixed(&[5; 8])).unwrap();
    tracing::subscriber::with_default(subscriber, || {
        let span = closed_operation_span(OperationKind::Commit, &id);
        span.in_scope(|| {
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        });
    });
    assert!(output.lines().is_empty());
    let snapshot = history.snapshot();
    let record = String::from_utf8_lossy(snapshot.records()[0].as_bytes()).into_owned();
    assert!(
        record.contains("cor-0505050505050505"),
        "bundle record lost its correlation scope: {record}"
    );
}

#[test]
fn operation_span_refuses_correlation_rerecord_and_keeps_failure_join() {
    let history = BundleHistory::default();
    let (output, subscriber) = session_with_history("warn", &history);
    let original = CorrelationId::draw(&mut Fixed(&[0x31; 8])).unwrap();
    let replacement = "cor-4242424242424242";
    tracing::subscriber::with_default(subscriber, || {
        let span = closed_operation_span(OperationKind::Commit, &original);
        span.record("op", replacement);
        span.in_scope(|| {
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        });
    });
    let lines = output.lines();
    let failures = history
        .try_failure_snapshot()
        .unwrap_or_else(|error| panic!("valid failure producer refused: {error}"));
    let records = history.snapshot();
    let retained = records
        .records()
        .iter()
        .map(|record| String::from_utf8_lossy(record.as_bytes()))
        .collect::<Vec<_>>();
    assert_eq!(
        (
            lines.len(),
            lines
                .iter()
                .filter(
                    |line| line.contains("log.record_refused") && line.contains("invalid_domain")
                )
                .count(),
            lines
                .iter()
                .filter(|line| line.contains("cor-3131313131313131"))
                .count(),
            lines.iter().any(|line| line.contains(replacement)),
            failures.entries.len(),
            failures
                .entries
                .first()
                .and_then(|failure| failure.correlation),
            retained.iter().any(|record| record.contains(replacement)),
        ),
        (2, 1, 1, false, 1, Some([0x31; 8]), false),
        "post-creation correlation update was not refused consistently: lines={lines:?}, records={retained:?}"
    );
}

#[test]
fn failure_numbering_matches_the_format_and_core_encoder() {
    let kinds = [
        (OperationKind::Session, 1),
        (OperationKind::OverlayWrite, 2),
        (OperationKind::JournalAppend, 3),
        (OperationKind::IntentRegister, 4),
        (OperationKind::Fsync, 5),
        (OperationKind::Commit, 6),
        (OperationKind::Rebase, 7),
        (OperationKind::Retry, 8),
        (OperationKind::Unmount, 9),
        (OperationKind::View, 10),
    ];
    let classes = [
        (FailureClass::Io, 1),
        (FailureClass::Refused, 2),
        (FailureClass::Conflict, 3),
        (FailureClass::Unavailable, 4),
        (FailureClass::Corrupt, 5),
        (FailureClass::Internal, 6),
    ];
    let history = BundleHistory::default();
    let (_, subscriber) = session_with_history("off", &history);
    tracing::subscriber::with_default(subscriber, || {
        for (kind, _) in kinds {
            ClientEvent::op_failed(kind, FailureClass::Io).emit();
        }
    });
    let snapshot = history
        .try_failure_snapshot()
        .unwrap_or_else(|error| panic!("valid failure producer refused: {error}"));
    let round_trip = snapshot
        .encode()
        .and_then(|bytes| granary_core::support::BundleFailures::decode(&bytes));
    assert_eq!(
        (
            kinds.map(|(kind, _)| kind.bundle_tag()),
            classes.map(|(class, _)| class.bundle_tag()),
            [
                ClientEvent::op_failed(OperationKind::Session, FailureClass::Io).bundle_event_tag(),
                ClientEvent::overlay_refused(FailureClass::Io, 0, 0, 0).bundle_event_tag(),
            ],
            snapshot
                .entries
                .iter()
                .map(|failure| failure.kind)
                .collect::<Vec<_>>(),
            round_trip,
        ),
        (
            kinds.map(|(_, tag)| tag),
            classes.map(|(_, tag)| tag),
            [Some(1), Some(2)],
            (1..=10).collect::<Vec<_>>(),
            Ok(snapshot),
        ),
        "failure event/kind/class numbering or core encoding drifted"
    );
}

#[test]
fn failure_ring_uses_the_innermost_operation_correlation() {
    let history = BundleHistory::default();
    let (_, subscriber) = session_with_history("off", &history);
    let outer_id = CorrelationId::draw(&mut Fixed(&[0x11; 8])).unwrap();
    let inner_id = CorrelationId::draw(&mut Fixed(&[0x22; 8])).unwrap();
    tracing::subscriber::with_default(subscriber, || {
        let outer = closed_operation_span(OperationKind::Session, &outer_id);
        outer.in_scope(|| {
            let inner = closed_operation_span(OperationKind::Commit, &inner_id);
            inner.in_scope(|| {
                ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
            });
            ClientEvent::op_failed(OperationKind::Session, FailureClass::Refused).emit();
        });
    });
    let snapshot = history
        .try_failure_snapshot()
        .unwrap_or_else(|error| panic!("valid failure producer refused: {error}"));
    assert_eq!(
        snapshot
            .entries
            .iter()
            .map(|failure| (failure.ordinal, failure.correlation))
            .collect::<Vec<_>>(),
        [(1, Some([0x22; 8])), (2, Some([0x11; 8]))],
        "failure correlation did not follow the innermost live operation span"
    );
}

#[test]
fn failure_ring_evicts_the_oldest_and_filtering_cannot_starve_it() {
    let history = BundleHistory::default();
    let (output, subscriber) = session_with_history("off", &history);
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..65 {
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        }
    });
    let snapshot = history
        .try_failure_snapshot()
        .unwrap_or_else(|error| panic!("valid failure producer refused: {error}"));
    let ordinals: Vec<_> = snapshot
        .entries
        .iter()
        .map(|failure| failure.ordinal)
        .collect();
    assert_eq!(
        (
            output.lines().len(),
            snapshot.entries.len(),
            ordinals.first(),
            ordinals.last()
        ),
        (0, 64, Some(&2), Some(&65)),
        "filter-off failures must retain the newest 64 in emission order: {ordinals:?}"
    );
}

#[test]
fn failure_construction_is_inert_and_retention_contains_only_scalars() {
    let history = BundleHistory::default();
    let (_, subscriber) = session_with_history("off", &history);
    tracing::subscriber::with_default(subscriber, || {
        let _constructed = ClientEvent::op_failed(OperationKind::Fsync, FailureClass::Corrupt);
        let id = CorrelationId::draw(&mut Fixed(&[0x5a; 8])).unwrap();
        closed_operation_span(OperationKind::OverlayWrite, &id).in_scope(|| {
            let hostile =
                std::io::Error::other("PRIVATE_ERROR_SENTINEL /private/PRIVATE_PATH_SENTINEL");
            let _failure = crate::OverlayError::from(hostile);
        });
    });
    let snapshot = history
        .try_failure_snapshot()
        .unwrap_or_else(|error| panic!("valid failure producer refused: {error}"));
    let bytes = snapshot
        .encode()
        .unwrap_or_else(|error| panic!("retained scalars did not encode: {error}"));
    assert_eq!(
        snapshot.entries.len(),
        1,
        "construction alone inserted a failure"
    );
    assert_eq!(
        snapshot.entries[0],
        granary_core::support::BundleFailure {
            ordinal: 1,
            event: 1,
            kind: 2,
            class: 1,
            correlation: Some([0x5a; 8]),
        },
        "failure projection did not preserve only the closed scalars"
    );
    assert!(
        !bytes
            .windows(b"PRIVATE_ERROR_SENTINEL".len())
            .any(|window| window == b"PRIVATE_ERROR_SENTINEL")
            && !bytes
                .windows(b"PRIVATE_PATH_SENTINEL".len())
                .any(|window| window == b"PRIVATE_PATH_SENTINEL"),
        "failure member leaked hostile error or path bytes"
    );
}

#[test]
fn deferred_failures_take_ordinals_once_and_dropped_entries_take_none() {
    let history = BundleHistory::default();
    let (_, subscriber) = session_with_history("off", &history);
    tracing::subscriber::with_default(subscriber, || {
        let _scope = super::super::overlay_callback_begin();
        for class in [
            FailureClass::Io,
            FailureClass::Refused,
            FailureClass::Conflict,
            FailureClass::Unavailable,
            FailureClass::Corrupt,
            FailureClass::Internal,
            FailureClass::Io,
            FailureClass::Refused,
            FailureClass::Unavailable,
        ] {
            super::super::op_failed(OperationKind::OverlayWrite, class);
        }
        super::super::overlay_callback_end(Outcome::Ok, None);
        ClientEvent::overlay_refused(FailureClass::Corrupt, 7, 3, 99).emit();
    });
    let snapshot = history
        .try_failure_snapshot()
        .unwrap_or_else(|error| panic!("valid failure producer refused: {error}"));
    let observed: Vec<_> = snapshot
        .entries
        .iter()
        .map(|failure| (failure.ordinal, failure.event, failure.kind, failure.class))
        .collect();
    assert_eq!(
        observed,
        [
            (1, 1, 2, 1),
            (2, 1, 2, 2),
            (3, 1, 2, 3),
            (4, 1, 2, 4),
            (5, 1, 2, 5),
            (6, 1, 2, 6),
            (7, 1, 2, 1),
            (8, 1, 2, 2),
            (9, 2, 0, 5),
        ],
        "deferred insertion was duplicated, reordered, or assigned an ordinal to the dropped ninth failure"
    );
}

#[test]
fn ordinal_exhaustion_makes_the_failure_producer_unavailable() {
    let history = BundleHistory::default();
    history.set_failure_ordinal_for_test(u64::MAX - 1);
    let (_, subscriber) = session_with_history("off", &history);
    tracing::subscriber::with_default(subscriber, || {
        ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
    });
    assert_eq!(
        history.try_failure_snapshot().unwrap_err().to_string(),
        "unavailable",
        "ordinal exhaustion wrapped or reused an ordinal"
    );
}

#[test]
fn a_busy_failure_ring_returns_timed_out_without_waiting() {
    let history = BundleHistory::default();
    let held = history.hold_failure_lock_for_test();
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let worker_history = history.clone();
    let worker = std::thread::spawn(move || {
        sent.send(
            worker_history
                .try_failure_snapshot()
                .err()
                .map(|error| error.to_string()),
        )
        .unwrap();
    });
    let refusal = received.recv_timeout(std::time::Duration::from_millis(200));
    drop(held);
    worker.join().unwrap();
    assert_eq!(
        refusal.as_ref().ok().and_then(|value| value.as_deref()),
        Some("timed-out"),
        "busy failure snapshot blocked or returned the wrong closed outcome: {refusal:?}"
    );
}

#[test]
fn contention_counts_accept_numbers_and_refuse_strings_without_echoing_them() {
    let mut cases = 0;
    for field in ["commits", "conflicts"] {
        let lines = capture(LogFormat::Json, "trace", || {
            ClientEvent::commit_contention(4, 1).emit();
            if field == "commits" {
                send(
                    &CONTENTION_META,
                    &[
                        Some(&"commit.contention"),
                        Some(&"private-sentinel"),
                        Some(&1_u64),
                    ],
                );
            } else {
                send(
                    &CONTENTION_META,
                    &[
                        Some(&"commit.contention"),
                        Some(&4_u64),
                        Some(&"private-sentinel"),
                    ],
                );
            }
        });
        assert_eq!(lines.len(), 2, "{field}: {lines:?}");
        assert_eq!(
            (
                lines[0].contains("\"event\":\"commit.contention\""),
                lines[0].contains("\"commits\":4,\"conflicts\":1"),
                lines[1].contains("invalid_scalar"),
                lines[1].contains("private-sentinel")
            ),
            (true, true, true, false),
            "{field}: {lines:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A shutdown's event at each ending: INFO with its outcome, seq and time
/// when the intent was released, WARN with its cause and what it left
/// otherwise, and WARN without the counts when they could not be read. A
/// value outside either closed domain is refused at the registered site.
#[test]
fn mount_unmount_event_fields_are_closed() {
    use super::super::{UnmountCause as C, UnmountOutcome as O, UnmountTrigger as T};
    let endings = [
        ClientEvent::mount_unmounted(T::SessionEnd, O::Committed, 4, 30),
        ClientEvent::mount_unmounted(T::SessionEnd, O::Clean, 3, 31),
        ClientEvent::mount_unmount_left(
            T::SessionEnd,
            O::Incomplete,
            C::Deadline,
            Some([2, 90, 5]),
            32,
        ),
        ClientEvent::mount_unmount_left(T::Start, O::Incomplete, C::Failed, Some([1, 10, 2]), 33),
        ClientEvent::mount_unmount_left(T::SessionEnd, O::Fenced, C::Failed, Some([0, 0, 1]), 34),
        ClientEvent::mount_unmount_left(T::Start, O::Incomplete, C::Internal, None, 35),
    ];
    let lines = capture(LogFormat::Json, "debug", || {
        for ending in &endings {
            ending.emit();
        }
        send(
            &UNMOUNTED_META,
            &[
                Some(&"mount.unmount"),
                Some(&"session_end"),
                Some(&"unmounted"),
                Some(&4_u64),
                Some(&30_u64),
            ],
        );
        send(
            &UNMOUNT_UNREAD_META,
            &[
                Some(&"mount.unmount"),
                Some(&"start"),
                Some(&"incomplete"),
                Some(&"timeout"),
                Some(&30_u64),
            ],
        );
    });
    let observed: Vec<(String, Vec<String>)> = lines
        .iter()
        .map(|line| {
            let level = line
                .split("\"level\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default()
                .to_owned();
            let mut keys = top_level_keys(line);
            keys.retain(|key| !matches!(key.as_str(), "event" | "level" | "target"));
            keys.sort();
            (level, keys)
        })
        .collect();
    let keys = |fields: &[&str]| {
        let mut keys: Vec<String> = fields.iter().map(|key| (*key).to_owned()).collect();
        keys.sort();
        keys
    };
    let done = (
        "INFO".to_owned(),
        keys(&["trigger", "outcome", "seq", "elapsed_ms"]),
    );
    let left = (
        "WARN".to_owned(),
        keys(&[
            "trigger",
            "outcome",
            "cause",
            "files",
            "bytes",
            "operations",
            "elapsed_ms",
        ]),
    );
    let unread = (
        "WARN".to_owned(),
        keys(&["trigger", "outcome", "cause", "elapsed_ms"]),
    );
    assert_eq!(
        observed[..endings.len()],
        [done.clone(), done, left.clone(), left.clone(), left, unread],
        "{lines:?}"
    );
    assert_eq!(
        (
            lines.len(),
            lines[endings.len()..]
                .iter()
                .filter(|line| line.contains("invalid_domain"))
                .count()
        ),
        (endings.len() + 2, 2),
        "{lines:?}"
    );
}

/// `trigger` is a closed domain: all members emit from the registered
/// site, and a value outside the domain is refused there, on the INFO and
/// the WARN schema alike.
#[test]
fn mount_unmount_trigger_is_closed() {
    use super::super::{UnmountCause as C, UnmountOutcome as O, UnmountTrigger as T};
    let lines = capture(LogFormat::Json, "debug", || {
        for trigger in T::ALL {
            ClientEvent::mount_unmounted(*trigger, O::Committed, 4, 30).emit();
            ClientEvent::mount_unmount_left(*trigger, O::Incomplete, C::Deadline, None, 30).emit();
        }
        send(
            &UNMOUNTED_META,
            &[
                Some(&"mount.unmount"),
                Some(&"restart"),
                Some(&"committed"),
                Some(&4_u64),
                Some(&30_u64),
            ],
        );
        send(
            &UNMOUNT_UNREAD_META,
            &[
                Some(&"mount.unmount"),
                Some(&"restart"),
                Some(&"incomplete"),
                Some(&"deadline"),
                Some(&30_u64),
            ],
        );
    });
    let triggers: Vec<String> = lines
        .iter()
        .filter_map(|line| line.split("\"trigger\":\"").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect();
    assert_eq!(
        (
            T::ALL.len(),
            triggers,
            lines
                .iter()
                .filter(|line| line.contains("invalid_domain"))
                .count(),
        ),
        (
            4,
            [
                "session_end",
                "session_end",
                "signal",
                "signal",
                "start",
                "start",
                "umount",
                "umount"
            ]
            .map(str::to_owned)
            .to_vec(),
            2
        ),
        "{lines:?}"
    );
}
