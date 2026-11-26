// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for [`super`]: the vocabulary is asserted by NAME and FIELD in
//! both renderings, never by a sentence, and the operator document is held to
//! the same table.

use super::*;
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

/// A writer a test reads back.
#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Capture {
    pub(super) fn lines(&self) -> Vec<String> {
        let bytes = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes)
            .unwrap_or_else(|e| panic!("log output was not UTF-8: {e}"))
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// Run `body` under a subscriber built by the production assembler.
fn capture(format: LogFormat, filter: &str, body: impl FnOnce()) -> Vec<String> {
    let out = Capture::default();
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|e| panic!("{e}"));
    let dispatch = subscriber(format, filter, out.clone());
    tracing::subscriber::with_default(dispatch, body);
    out.lines()
}

#[test]
fn recovery_selection_tokens_admit_only_the_closed_refusal_vocabulary() {
    let mut cases = 0;
    for (token, admitted) in [
        ("none", true),
        ("intent-changed", true),
        ("intent-superseded", true),
        ("intent-absent", true),
        ("PRIVATE_TOKEN_SENTINEL", false),
        ("", false),
    ] {
        let lines = capture(LogFormat::Json, "trace", || {
            recover(RecoverEvent::SelectionChanged(token));
        });
        assert_eq!(
            (
                lines.len(),
                lines
                    .iter()
                    .any(|line| line.contains("\"event\":\"recover.selection_changed\"")),
                lines.iter().any(|line| line.contains("log.record_refused")),
                lines
                    .iter()
                    .any(|line| line.contains("PRIVATE_TOKEN_SENTINEL"))
            ),
            (1, admitted, !admitted, false),
            "token={token:?}: {lines:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 6, "nonempty token controls");
}

#[test]
fn fence_settlement_labels_refuse_values_outside_the_closed_vocabulary() {
    let mut cases = 0;
    for (how, admitted) in [
        ("landed", true),
        ("released", true),
        ("stripped", true),
        ("PRIVATE_HOW_SENTINEL", false),
        ("", false),
    ] {
        let lines = capture(LogFormat::Json, "trace", || {
            recover(RecoverEvent::FenceSettled(how));
        });
        assert_eq!(
            (
                lines.len(),
                lines
                    .iter()
                    .any(|l| l.contains("\"event\":\"recover.fence_settled\"")),
                lines
                    .iter()
                    .any(|l| l.contains("\"reason\":\"invalid_domain\"")),
                lines.iter().any(|l| l.contains("PRIVATE_HOW_SENTINEL"))
            ),
            (1, admitted, !admitted, false),
            "how={how:?}: {lines:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[test]
fn overlay_callback_buffer_keeps_first_eight_and_counts_dropped() {
    let lines = capture(LogFormat::Json, "trace", || {
        let _scope = overlay_callback_begin();
        for _ in 0..DEFERRED_OVERLAY_FAILURE_LIMIT - 1 {
            op_failed(OperationKind::OverlayWrite, FailureClass::Io);
        }
        op_failed(OperationKind::OverlayWrite, FailureClass::Corrupt);
        for _ in 0..3 {
            op_failed(OperationKind::OverlayWrite, FailureClass::Unavailable);
        }
        OVERLAY_CALLBACKS.with(|callbacks| {
            let callbacks = callbacks.borrow();
            let (_, failures) = callbacks.last().unwrap();
            assert_eq!(failures.classes.len(), DEFERRED_OVERLAY_FAILURE_LIMIT);
            assert_eq!(failures.dropped, 3);
        });
        overlay_callback_end(Outcome::Ok, None);
    });
    assert_eq!(
        lines.iter().filter(|line| line.contains(OP_FAILED)).count(),
        8
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("\"class\":\"io\""))
            .count(),
        7
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("\"class\":\"corrupt\""))
            .count(),
        1
    );
    assert!(!lines.iter().any(|line| line.contains("unavailable")));
    assert_eq!(
        lines.len(),
        11,
        "begin, eight failures, summary, end: {lines:?}"
    );
    assert!(lines[9].contains("\"event\":\"overlay.failures_dropped\""));
    assert!(lines[9].contains("\"dropped\":3"));
    assert!(lines[10].contains(OP_END));
    OVERLAY_CALLBACKS.with(|callbacks| assert!(callbacks.borrow().is_empty()));
}

#[test]
fn overlay_callback_nested_scopes_finish_and_abandon_independently() {
    let lines = capture(LogFormat::Json, "trace", || {
        let _outer = overlay_callback_begin();
        op_failed(OperationKind::OverlayWrite, FailureClass::Refused);
        {
            let _inner = overlay_callback_begin();
            op_failed(OperationKind::OverlayWrite, FailureClass::Corrupt);
            overlay_callback_end(Outcome::Failed, Some(FailureClass::Io));
        }
        {
            let _abandoned = overlay_callback_begin();
            op_failed(OperationKind::OverlayWrite, FailureClass::Unavailable);
        }
        {
            let _inner = overlay_callback_begin();
            op_failed(OperationKind::OverlayWrite, FailureClass::Conflict);
            overlay_callback_end(Outcome::Ok, None);
        }
        OVERLAY_CALLBACKS.with(|callbacks| {
            let callbacks = callbacks.borrow();
            assert_eq!(callbacks.len(), 1);
            assert_eq!(callbacks[0].1.classes, [FailureClass::Refused]);
        });
        overlay_callback_end(Outcome::Ok, None);
    });
    let failures: Vec<_> = lines
        .iter()
        .filter(|line| line.contains(OP_FAILED))
        .collect();
    assert_eq!(failures.len(), 4);
    for (line, class) in failures
        .iter()
        .zip(["io", "unavailable", "conflict", "refused"])
    {
        assert!(line.contains(&format!("\"class\":\"{class}\"")), "{line}");
    }
    OVERLAY_CALLBACKS.with(|callbacks| assert!(callbacks.borrow().is_empty()));
}

/// A fixed-output randomness source.
pub(super) struct Fixed(pub(super) &'static [u8]);

impl SecureRandom for Fixed {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        dest.copy_from_slice(self.0.get(..dest.len()).ok_or(EntropyUnavailable)?);
        Ok(())
    }
}

/// A source that never draws.
struct Dry;

impl SecureRandom for Dry {
    fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        Err(EntropyUnavailable)
    }
}

/// The top-level keys of one JSON object line, and the string value of a key,
/// without a JSON dependency: a scan that tracks string and nesting state.
pub(super) fn top_level_keys(line: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut depth = 0_u32;
    let mut chars = line.chars().peekable();
    let mut expecting_key = false;
    while let Some(c) = chars.next() {
        match c {
            '{' | '[' => {
                depth += 1;
                if depth == 1 && c == '{' {
                    expecting_key = true;
                }
            }
            '}' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 1 => expecting_key = true,
            '"' => {
                let mut text = String::new();
                while let Some(d) = chars.next() {
                    match d {
                        '\\' => {
                            text.push(d);
                            if let Some(e) = chars.next() {
                                text.push(e);
                            }
                        }
                        '"' => break,
                        other => text.push(other),
                    }
                }
                if depth == 1 && expecting_key {
                    keys.push(text);
                    expecting_key = false;
                }
            }
            _ => {}
        }
    }
    keys
}

fn emit_all() {
    ClientEvent::commit_contention(4, 1).emit();
    commit_backoff(BackoffCause::Outage, BackoffOutcome::Entered);
    commit_backoff(
        BackoffCause::Stall,
        BackoffOutcome::Recovered { attempts: 9 },
    );
    commit_stopped(CommitStopCause::Fenced);
    ClientEvent::workspace_exhausted(1_073_741_825, 1_073_741_824).emit();
    ClientEvent::overlay_cap_exhausted(134_217_728, 96_624_009, 33_814_682, 34_180, 98_685_463)
        .emit();
    for event in [
        RecoverEvent::JournalFinished(7),
        RecoverEvent::JournalBlocked("release"),
        RecoverEvent::Nothing,
        RecoverEvent::Subsumed(SubsumedRelation::Later, 3),
        RecoverEvent::Stale,
        RecoverEvent::Landed(2),
        RecoverEvent::ArchivedLanded(2),
        RecoverEvent::Rebased(1),
        RecoverEvent::Conflict,
        RecoverEvent::SelectionChanged("none"),
        RecoverEvent::LandedUnowned,
        RecoverEvent::FenceSettled("released"),
        RecoverEvent::Unresolved(2),
        RecoverEvent::Resent(2),
    ] {
        recover(event);
    }
    ClientEvent::recovery_signing_key_refused().emit();
    ClientEvent::conflict_detail().emit();
    overlay_recovery(
        RecoveryOutcome::Clean,
        1,
        4096,
        crate::OverlaySummary {
            charged_bytes: 160,
            records: 2,
            ..crate::OverlaySummary::default()
        },
    );
    stage_rolled_back(
        2,
        1,
        Some(&[granary_core::manifest::Name::new(b"stage".to_vec()).unwrap()]),
        4,
        0,
        4,
    );
    stage_rolled_back(3, 2, None, 2, 0, 2);
    overlay_refused(FailureClass::Corrupt, 2, 1, 160);
    ClientEvent::overlay_discard_refused(crate::OverlayRefusal::ForeignCustody).emit();
    ClientEvent::overlay_reconcile_refused(crate::OverlayRefusal::RemoteIntegrity).emit();
    overlay_sweep(1, 160);
    ClientEvent::overlay_failures_dropped(3).emit();
    overlay_fault(OverlayFaultPoint::StageWrite, FaultPhase::Before, 1, 2);
    sync_fault("sync.capture", "after", 1, "none");
    op_begin(OperationKind::Commit);
    op_end(OperationKind::Commit, Outcome::Ok);
    op_retry(OperationKind::Commit, 2, RetryReason::Conflict);
    op_failed(OperationKind::Fsync, FailureClass::Io);
    ClientEvent::metrics_export_failed(MetricsFailureClass::Io).emit();
    publish_bound(PublishOperationId::draw(&mut Fixed(&[0xab, 0x01]), 2).unwrap());
    log_config(LogFormat::Json, LogDestination::File);
    log_filter_rejected(FilterRejection::Malformed, FilterDetail::Malformed);
    mount_view(ViewCause::Landed, ViewOutcome::Installed, 2);
    mount_view(ViewCause::Landed, ViewOutcome::Refused, 3);
    mount_unmounted(UnmountTrigger::SessionEnd, UnmountOutcome::Committed, 2, 40);
    mount_unmount_left(
        UnmountTrigger::SessionEnd,
        UnmountOutcome::Incomplete,
        UnmountCause::Deadline,
        Some([1, 160, 2]),
        40,
    );
    mount_unmount_left(
        UnmountTrigger::Start,
        UnmountOutcome::Incomplete,
        UnmountCause::Internal,
        None,
        40,
    );
    OperatorDiagnostic::gran_mount_the_fuse_session_did_not_end_after_its_unmount(
        MountListing::Gone,
        FuseConnection::Alive,
    )
    .emit();
}

/// The line among `lines` that `spec` describes: its name, its level and
/// exactly its fields, with the layer's envelope `extra`.
fn spec_line<'a>(lines: &'a [String], spec: &EventSpec, extra: &[&str]) -> &'a String {
    let mut want: Vec<String> = spec
        .fields
        .iter()
        .chain(["event", "level", "target"].iter())
        .chain(extra)
        .map(|k| (*k).to_owned())
        .collect();
    want.sort();
    lines
        .iter()
        .find(|l| {
            let mut keys = top_level_keys(l);
            keys.sort();
            l.contains(&format!("\"event\":\"{}\"", spec.name))
                && l.contains(&format!("\"level\":\"{}\"", spec.level))
                && keys == want
        })
        .unwrap_or_else(|| panic!("no JSON line for {}: {lines:?}", spec.name))
}

/// Every table entry is emitted under its name, at its level, with its fields
/// and no others: the JSON keys are the table's fields plus the layer's own
/// envelope. A function that renamed a field, or a table that lagged one,
/// fails here by name.
#[test]
fn every_event_in_the_table_is_emitted_with_its_name_level_and_fields_in_json() {
    let lines = capture(LogFormat::Json, "debug", emit_all);
    assert_eq!(lines.len(), EVENTS.len(), "one line per event: {lines:?}");
    for spec in EVENTS {
        let line = spec_line(&lines, spec, &[]);
        let mut keys = top_level_keys(line);
        keys.sort();
        let mut want: Vec<String> = spec
            .fields
            .iter()
            .chain(["event", "level", "target"].iter())
            .map(|k| (*k).to_owned())
            .collect();
        want.sort();
        assert_eq!(keys, want, "{}: {line}", spec.name);
        assert!(
            line.contains(&format!("\"level\":\"{}\"", spec.level)),
            "{}: {line}",
            spec.name
        );
    }
}

/// The support bundle's log member holds each event's key set in core. A key
/// the layer can emit and core lacks would make the member refuse a record the
/// client wrote; a key core adds would let an event's record carry a field it
/// never has. Compared per event, plain and span-wrapped.
#[test]
fn core_key_sets_equal_the_keys_the_layer_emits_per_event() {
    let core_keys = |event: &str, spans: bool| {
        let mut keys: Vec<String> = granary_core::support::bundle_record_keys(event)
            .unwrap_or_else(|| panic!("core has no key set for {event}"))
            .filter(|key| spans || *key != "spans")
            .map(str::to_owned)
            .collect();
        keys.sort();
        keys
    };
    let emitted = |line: &str| {
        let mut keys = top_level_keys(line);
        keys.sort();
        keys
    };
    let id = CorrelationId::draw(&mut Fixed(&[9; 8])).unwrap_or_else(|e| panic!("{e}"));
    let plain = capture(LogFormat::Json, "debug", emit_all);
    let wrapped = capture(LogFormat::Json, "debug", || {
        operation_span(OperationKind::Commit, &id).in_scope(emit_all);
    });
    for (lines, spans) in [(&plain, false), (&wrapped, true)] {
        assert_eq!(lines.len(), EVENTS.len(), "one line per event: {lines:?}");
        for spec in EVENTS {
            let line = spec_line(lines, spec, if spans { &["spans"] } else { &[] });
            let siblings: Vec<_> = EVENTS
                .iter()
                .filter(|other| other.name == spec.name)
                .collect();
            if siblings.iter().all(|other| other.fields == spec.fields) {
                assert_eq!(
                    emitted(line),
                    core_keys(spec.name, spans),
                    "{} (span-wrapped: {spans}): {line}",
                    spec.name
                );
            } else {
                // An event whose levels carry different fields: core holds
                // every field any of them carries, and no other.
                let core = core_keys(spec.name, spans);
                let mut union: Vec<String> = siblings
                    .iter()
                    .map(|other| spec_line(lines, other, if spans { &["spans"] } else { &[] }))
                    .flat_map(|line| emitted(line))
                    .collect();
                union.sort();
                union.dedup();
                assert_eq!(
                    (emitted(line).iter().all(|key| core.contains(key)), union),
                    (true, core),
                    "{} (span-wrapped: {spans}): {line}",
                    spec.name
                );
            }
        }
    }
    let notices = [
        (
            OperatorNotice::rotation_failed(FailureClass::Io),
            "log.line",
        ),
        (OperatorNotice::write_failed(FailureClass::Io), "log.line"),
        (OperatorNotice::sink_loss(1, 2, 3), "log.sink_loss"),
    ];
    for (notice, event) in notices {
        let record = String::from_utf8(notice.bundle_record().as_bytes().to_vec())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            record.contains(&format!("\"event\":\"{event}\"")),
            "{record}"
        );
        assert_eq!(emitted(&record), core_keys(event, false), "{record}");
    }
    let refused = capture(LogFormat::Json, "debug", || {
        tracing::warn!(target: "dependency", token = "unregistered");
    });
    let record = refused
        .iter()
        .find(|l| l.contains("\"event\":\"log.record_refused\""))
        .unwrap_or_else(|| panic!("no refusal record: {refused:?}"));
    assert_eq!(
        emitted(record),
        core_keys("log.record_refused", false),
        "{record}"
    );
}

/// A view change's event names its cause, its outcome and the seq, and
/// nothing that identifies a root, path or key: INFO when installed,
/// deferred or fresh, WARN when refused or stale. Every combination either
/// cause emits is registered: a landing installs or refuses, and an adoption
/// also defers or reports reachability edges.
#[test]
fn mount_view_event_carries_cause_outcome_and_seq_only() {
    let combinations = [
        (ViewCause::Landed, ViewOutcome::Installed, 7),
        (ViewCause::Landed, ViewOutcome::Refused, 8),
        (ViewCause::Adopted, ViewOutcome::Installed, 9),
        (ViewCause::Adopted, ViewOutcome::Deferred, 10),
        (ViewCause::Adopted, ViewOutcome::Refused, 11),
        (ViewCause::Adopted, ViewOutcome::Stale, 12),
        (ViewCause::Adopted, ViewOutcome::Fresh, 13),
    ];
    let lines = capture(LogFormat::Json, "debug", || {
        for (cause, outcome, seq) in combinations {
            mount_view(cause, outcome, seq);
        }
    });
    let observed: Vec<_> = lines
        .iter()
        .map(|line| {
            let mut keys = top_level_keys(line);
            keys.sort();
            let text = |key: &str, close: fn(char) -> bool| {
                line.split(&format!("\"{key}\":"))
                    .nth(1)
                    .map(|rest| rest.trim_start_matches('"'))
                    .and_then(|rest| rest.split(close).next())
                    .unwrap_or_default()
                    .to_owned()
            };
            let quote = |c: char| c == '"';
            (
                keys,
                [
                    text("level", quote),
                    text("cause", quote),
                    text("outcome", quote),
                    text("seq", |c| !c.is_ascii_digit()),
                ],
            )
        })
        .collect();
    let keys: Vec<String> = ["cause", "event", "level", "outcome", "seq", "target"]
        .map(str::to_owned)
        .to_vec();
    assert_eq!(
        observed,
        vec![
            (
                keys.clone(),
                ["INFO", "landed", "installed", "7"].map(str::to_owned)
            ),
            (
                keys.clone(),
                ["WARN", "landed", "refused", "8"].map(str::to_owned)
            ),
            (
                keys.clone(),
                ["INFO", "adopted", "installed", "9"].map(str::to_owned)
            ),
            (
                keys.clone(),
                ["INFO", "adopted", "deferred", "10"].map(str::to_owned)
            ),
            (
                keys.clone(),
                ["WARN", "adopted", "refused", "11"].map(str::to_owned)
            ),
            (
                keys.clone(),
                ["WARN", "adopted", "stale", "12"].map(str::to_owned)
            ),
            (keys, ["INFO", "adopted", "fresh", "13"].map(str::to_owned)),
        ],
        "{lines:?}"
    );
    assert_eq!(lines.len(), combinations.len(), "every combination emitted");
}

/// The support bundle's failure ring names an operation kind by its 1-based
/// position in [`OperationKind::ALL`], and accepts exactly that many.
#[test]
fn the_bundle_failure_ring_accepts_every_operation_kind() {
    assert_eq!(
        usize::from(granary_core::support::BUNDLE_OPERATION_KINDS),
        OperationKind::ALL.len()
    );
}

#[test]
fn every_event_in_the_table_is_emitted_with_its_name_level_and_fields_in_text() {
    let lines = capture(LogFormat::Text, "debug", emit_all);
    assert_eq!(lines.len(), EVENTS.len(), "one line per event: {lines:?}");
    for spec in EVENTS {
        let line = lines
            .iter()
            .find(|l| {
                l.contains(&format!("event=\"{}\"", spec.name))
                    && l.contains(&format!(" {} ", spec.level))
            })
            .unwrap_or_else(|| panic!("no text line for {}: {lines:?}", spec.name));
        assert!(
            line.contains(&format!(" {} ", spec.level)),
            "{}: {line}",
            spec.name
        );
        for field in spec.fields {
            assert!(
                line.contains(&format!("{field}=")),
                "{} lacks field {field}: {line}",
                spec.name
            );
        }
    }
}

/// The values, not just the names: a closed-domain member is spelled the
/// same in both renderings.
#[test]
fn field_values_are_the_domain_spellings_in_both_renderings() {
    let json = capture(LogFormat::Json, "debug", || {
        op_retry(OperationKind::Rebase, 3, RetryReason::Unavailable);
    });
    let text = capture(LogFormat::Text, "debug", || {
        op_retry(OperationKind::Rebase, 3, RetryReason::Unavailable);
    });
    for needle in [
        "\"kind\":\"rebase\"",
        "\"attempt\":3",
        "\"reason\":\"unavailable\"",
    ] {
        assert!(
            json.iter().any(|l| l.contains(needle)),
            "{needle}: {json:?}"
        );
    }
    for needle in ["kind=\"rebase\"", "attempt=3", "reason=\"unavailable\""] {
        assert!(
            text.iter().any(|l| l.contains(needle)),
            "{needle}: {text:?}"
        );
    }
}

/// Closed detail templates preserve the same event, source and reason fields.
#[test]
fn a_changed_message_changes_no_identifier() {
    let first = capture(LogFormat::Json, "warn", || {
        log_filter_rejected(FilterRejection::NotUnicode, FilterDetail::NotUnicode);
    });
    let second = capture(LogFormat::Json, "warn", || {
        log_filter_rejected(FilterRejection::NotUnicode, FilterDetail::Malformed);
    });
    for line in first.iter().chain(&second) {
        for needle in [
            "\"event\":\"log.filter_rejected\"",
            "\"source\":\"rust_log\"",
            "\"reason\":\"not_unicode\"",
        ] {
            assert!(line.contains(needle), "{needle}: {line}");
        }
    }
    assert_ne!(first, second, "the details differ, so the lines differ");
}

/// Every event of an operation carries its id and kind, in both renderings,
/// and an event outside the span carries none.
#[test]
fn every_event_inside_an_operation_span_carries_its_correlation_id() {
    let id = CorrelationId::draw(&mut Fixed(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(id.to_string(), "cor-0123456789abcdef");
    for format in [LogFormat::Json, LogFormat::Text] {
        let lines = capture(format, "debug", || {
            let span = operation_span(OperationKind::Commit, &id);
            span.in_scope(|| {
                op_begin(OperationKind::Commit);
                op_retry(OperationKind::Commit, 1, RetryReason::Transient);
                op_failed(OperationKind::Commit, FailureClass::Refused);
            });
            op_end(OperationKind::Commit, Outcome::Failed);
        });
        assert_eq!(lines.len(), 4, "{format:?}: {lines:?}");
        let (inside, outside) = lines.split_at(3);
        let needles: &[&str] = match format {
            LogFormat::Json => &["\"op\":\"cor-0123456789abcdef\"", "\"name\":\"op\""],
            LogFormat::Text => &["op{op=\"cor-0123456789abcdef\" kind=\"commit\" }"],
        };
        for line in inside {
            for needle in needles {
                assert!(line.contains(needle), "{format:?} {needle}: {line}");
            }
        }
        assert!(
            !outside.iter().any(|l| l.contains("cor-")),
            "{format:?}: an event after the span closed carried an id: {outside:?}"
        );
    }
}

/// The plausible wrong implementation: an INFO-level span. At `warn` it is
/// filtered away and the WARN and ERROR lines lose the id.
#[test]
fn the_correlation_id_survives_a_warn_filter() {
    let id = CorrelationId::draw(&mut Fixed(&[7; 8])).unwrap_or_else(|e| panic!("{e}"));
    let lines = capture(LogFormat::Json, "warn", || {
        operation_span(OperationKind::Commit, &id).in_scope(|| {
            op_begin(OperationKind::Commit);
            op_retry(OperationKind::Commit, 1, RetryReason::Transient);
            op_failed(OperationKind::Commit, FailureClass::Io);
        });
    });
    assert_eq!(lines.len(), 2, "debug event filtered, two kept: {lines:?}");
    for line in &lines {
        assert!(line.contains("\"op\":\"cor-0707070707070707\""), "{line}");
    }
}

#[test]
fn a_correlation_id_uses_every_drawn_byte_and_never_falls_back() {
    let a = CorrelationId::draw(&mut Fixed(&[0, 0, 0, 0, 0, 0, 0, 1]))
        .unwrap_or_else(|e| panic!("{e}"));
    let b = CorrelationId::draw(&mut Fixed(&[1, 0, 0, 0, 0, 0, 0, 0]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(a, b, "the first and the last byte both matter");
    assert_eq!(a.to_string(), "cor-0000000000000001");
    assert_eq!(b.to_string(), "cor-0100000000000000");
    assert_eq!(
        CorrelationId::draw(&mut Dry),
        Err(EntropyUnavailable),
        "no entropy is an error, not zeros or a counter"
    );
}

/// An id cannot be confused with the publish operation identity: the wire
/// spelling is lowercase hex alone, and the id always carries the prefix and
/// its separator, which no hex string has.
#[test]
fn a_correlation_id_cannot_spell_a_publish_operation_identity() {
    let id = CorrelationId::draw(&mut Fixed(&[0xaa; 8])).unwrap_or_else(|e| panic!("{e}"));
    let text = id.to_string();
    assert!(text.starts_with(CORRELATION_ID_PREFIX), "{text}");
    assert!(!text.bytes().all(|b| b.is_ascii_hexdigit()), "{text}");
    assert_eq!(
        text.len(),
        CORRELATION_ID_PREFIX.len() + 2 * CORRELATION_ID_LEN
    );
}

/// The join event names both identities in their own fields: the id from the
/// enclosing span, the wire identity as lowercase hex.
#[test]
fn publish_bound_joins_the_id_to_the_wire_identity() {
    let id = CorrelationId::draw(&mut Fixed(&[0x11; 8])).unwrap_or_else(|e| panic!("{e}"));
    let lines = capture(LogFormat::Json, "info", || {
        operation_span(OperationKind::Commit, &id).in_scope(|| {
            publish_bound(PublishOperationId::draw(&mut Fixed(&[0xde, 0xad, 0x00]), 3).unwrap());
        });
    });
    let [line] = lines.as_slice() else {
        panic!("one line expected: {lines:?}");
    };
    assert!(line.contains("\"publish_operation\":\"dead00\""), "{line}");
    assert!(line.contains("\"op\":\"cor-1111111111111111\""), "{line}");
}

#[test]
fn publish_bound_refuses_overlength_before_minting() {
    assert_eq!(
        PublishOperationId::draw(&mut Dry, 256).unwrap_err(),
        PublishOperationRefusal::Length
    );
}

/// A closed domain refuses a spelling outside it and round-trips its own.
#[test]
fn label_domains_are_closed() {
    fn check<T: Copy + PartialEq + std::fmt::Debug>(
        all: &[T],
        as_str: fn(T) -> &'static str,
        parse: fn(&str) -> Option<T>,
    ) {
        let mut seen = Vec::new();
        for member in all {
            let text = as_str(*member);
            assert!(!seen.contains(&text), "duplicate spelling {text}");
            seen.push(text);
            assert_eq!(parse(text), Some(*member));
            assert_eq!(
                parse(&text.to_uppercase()),
                None,
                "case is part of the spelling"
            );
        }
        assert_eq!(parse(""), None);
        assert_eq!(parse("unknown"), None);
    }
    check(
        OperationKind::ALL,
        OperationKind::as_str,
        OperationKind::parse,
    );
    check(Outcome::ALL, Outcome::as_str, Outcome::parse);
    check(RetryReason::ALL, RetryReason::as_str, RetryReason::parse);
    check(FailureClass::ALL, FailureClass::as_str, FailureClass::parse);
    check(BackoffCause::ALL, BackoffCause::as_str, BackoffCause::parse);
    check(
        BackoffOutcome::ALL,
        BackoffOutcome::as_str,
        BackoffOutcome::parse,
    );
    check(LogFormat::ALL, LogFormat::as_str, LogFormat::parse);
    check(
        LogDestination::ALL,
        LogDestination::as_str,
        LogDestination::parse,
    );
    check(
        FilterRejection::ALL,
        FilterRejection::as_str,
        FilterRejection::parse,
    );
    check(
        UnmountOutcome::ALL,
        UnmountOutcome::as_str,
        UnmountOutcome::parse,
    );
    check(UnmountCause::ALL, UnmountCause::as_str, UnmountCause::parse);
    check(
        UnmountTrigger::ALL,
        UnmountTrigger::as_str,
        UnmountTrigger::parse,
    );
}

/// Every pair from the two backoff label domains passes the production field
/// validator; an outside cause is refused with its stable reason. Case count 4.
#[test]
fn commit_backoff_label_pairs_are_validated() {
    let mut cases = 0;
    for cause in BackoffCause::ALL {
        for outcome in BackoffOutcome::ALL {
            let validated =
                super::boundary::validate_backoff_for_test(cause.as_str(), outcome.as_str());
            assert_eq!(validated, Ok(()), "pair=({cause:?}, {outcome:?})");
            cases += 1;
        }
    }
    let refusal = super::boundary::validate_backoff_for_test("outside", "entered");
    assert_eq!(refusal, Err("invalid_domain"), "outside cause: {refusal:?}");
    assert!(cases > 0, "the valid control exercised no label pairs");
}

/// Every commit-stop cause passes the production field validator; an outside
/// cause is refused with its stable reason. Case count 2.
#[test]
fn commit_stop_causes_are_validated() {
    let mut cases = 0;
    for cause in CommitStopCause::ALL {
        let validated = super::boundary::validate_commit_stop_for_test(cause.as_str());
        assert_eq!(validated, Ok(()), "cause={cause:?}: {validated:?}");
        cases += 1;
    }
    let refusal = super::boundary::validate_commit_stop_for_test("outside");
    assert_eq!(refusal, Err("invalid_domain"), "outside cause: {refusal:?}");
    assert!(cases > 0, "the valid control exercised no causes");
}

/// Every subsumed relation passes the production field validator; an outside
/// relation is refused with its stable reason. Case count 3.
#[test]
fn recover_subsumed_relations_are_validated() {
    let mut cases = 0;
    for relation in SubsumedRelation::ALL {
        let validated = super::boundary::validate_subsumed_for_test(relation.as_str());
        assert_eq!(validated, Ok(()), "relation={relation:?}: {validated:?}");
        cases += 1;
    }
    let refusal = super::boundary::validate_subsumed_for_test("outside");
    assert_eq!(
        refusal,
        Err("invalid_domain"),
        "outside relation: {refusal:?}"
    );
    assert_eq!(cases, 3, "the valid control exercised every relation");
}

/// The operator document and the table list the same events and the same
/// label members. A name added in code and not documented, or the reverse,
/// fails here.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one comparison of every event row and every closed domain row with the table"
)]
fn the_operator_document_lists_exactly_the_vocabulary() {
    let doc = include_str!("../../../../docs/operating-client-observability.md");
    let rows: Vec<&str> = doc
        .lines()
        .filter(|l| l.starts_with("| `") && l.contains("| `"))
        .collect();
    // Event table rows: | `name` | LEVEL | `field`, ... | ...
    let mut documented: Vec<(String, String, Vec<String>)> = Vec::new();
    for row in &rows {
        let cells: Vec<&str> = row.split('|').map(str::trim).collect();
        let name = cells.get(1).copied().unwrap_or_default().trim_matches('`');
        let level = cells.get(2).copied().unwrap_or_default();
        if matches!(level, "DEBUG" | "INFO" | "WARN" | "ERROR") {
            let fields = cells
                .get(3)
                .copied()
                .unwrap_or_default()
                .split(',')
                .map(|f| f.trim().trim_matches('`').to_owned())
                .filter(|f| !f.is_empty())
                .collect();
            documented.push((name.to_owned(), level.to_owned(), fields));
        }
    }
    let mut want: Vec<(String, String, Vec<String>)> = EVENTS
        .iter()
        .map(|e| {
            (
                e.name.to_owned(),
                e.level.to_owned(),
                e.fields.iter().map(|f| (*f).to_owned()).collect(),
            )
        })
        .collect();
    documented.sort();
    want.sort();
    assert!(!want.is_empty());
    assert_eq!(documented, want);
    let domains: [(&str, Vec<&str>); 19] = [
        (
            "kind",
            OperationKind::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        ("outcome", Outcome::ALL.iter().map(|m| m.as_str()).collect()),
        (
            "reason (retry)",
            RetryReason::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "class",
            FailureClass::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "format",
            LogFormat::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "destination",
            LogDestination::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "reason (filter)",
            FilterRejection::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "outcome (view)",
            ViewOutcome::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "cause (view)",
            ViewCause::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "cause (backoff)",
            BackoffCause::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "outcome (backoff)",
            BackoffOutcome::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "cause (commit stopped)",
            CommitStopCause::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "relation (recover)",
            SubsumedRelation::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "outcome (unmount)",
            UnmountOutcome::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "cause (unmount)",
            UnmountCause::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "trigger (unmount)",
            UnmountTrigger::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "listed",
            MountListing::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "connection",
            FuseConnection::ALL.iter().map(|m| m.as_str()).collect(),
        ),
        (
            "reason (journal recovery)",
            vec![
                "replay",
                "publication",
                "obligations",
                "namespace",
                "limit",
                "release",
                "selected-root-not-proved-published",
            ],
        ),
    ];
    let domains_doc = doc
        .split("### Closed label domains")
        .nth(1)
        .unwrap_or_else(|| panic!("no closed-domains section"));
    for (label, members) in domains {
        let row = domains_doc
            .lines()
            .find(|l| l.starts_with(&format!("| {label} |")))
            .unwrap_or_else(|| panic!("no domain row for {label}"));
        let listed: Vec<&str> = row
            .split('|')
            .nth(2)
            .unwrap_or_default()
            .split(',')
            .map(|m| m.trim().trim_matches('`'))
            .filter(|m| !m.is_empty())
            .collect();
        assert_eq!(listed, members, "domain {label}");
    }
}

#[test]
fn metrics_entropy_failure_emits_the_stable_session_event() {
    struct Broken;
    impl SecureRandom for Broken {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
            dest.fill(42);
            Err(EntropyUnavailable)
        }
    }
    let lines = capture(LogFormat::Json, "trace", || {
        let metrics = crate::ClientMetrics::new(&mut Broken);
        assert_eq!(
            metrics.snapshot().unwrap_err(),
            crate::MetricsError::Unavailable
        );
    });
    assert_eq!(lines.len(), 1);
    assert_eq!(
        (
            lines[0].contains("\"event\":\"op.failed\""),
            lines[0].contains("\"kind\":\"session\""),
            lines[0].contains("\"class\":\"unavailable\"")
        ),
        (true, true, true),
        "{lines:?}"
    );
}

#[test]
fn contention_event_only_rises_and_carries_current_window_counts() {
    use crate::CommitResult;
    use crate::contention::Window;
    let output = Capture::default();
    let subscriber = crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        output.clone(),
    );
    tracing::subscriber::with_default(subscriber, || {
        let mut window = Window::default();
        for _ in 0..5 {
            window.record(CommitResult::Conflict, None);
        }
        for _ in 0..16 {
            window.record(CommitResult::Ok, None);
        }
        for _ in 0..4 {
            window.record(CommitResult::Exhausted, None);
        }
    });
    let lines = output.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    for (line, expected) in lines.iter().zip([
        "\"commits\":4,\"conflicts\":4",
        "\"commits\":16,\"conflicts\":4",
    ]) {
        assert!(
            line.contains("\"event\":\"commit.contention\"") && line.contains(expected),
            "{line}"
        );
    }
}

#[test]
fn correlation_id_renders_twenty_wire_alphabet_characters_and_reads_from_current_span() {
    struct Fixed([u8; 8]);
    impl SecureRandom for Fixed {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
            dest.copy_from_slice(&self.0[..dest.len()]);
            Ok(())
        }
    }
    let output = Capture::default();
    let sub = crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        output,
    );
    tracing::subscriber::with_default(sub, || {
        assert_eq!(super::current_operation_id(), None);
        for (bytes, expected) in [
            ([0x00; 8], "cor-0000000000000000"),
            ([0xFF; 8], "cor-ffffffffffffffff"),
            (
                [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
                "cor-0123456789abcdef",
            ),
        ] {
            let id = CorrelationId::draw(&mut Fixed(bytes)).unwrap();
            let rendered = id.to_string();
            let span = crate::operation_span(OperationKind::Session, &id);
            let entered = span.enter();
            let current = super::current_operation_id();
            drop(entered);
            assert_eq!(
                (
                    rendered.as_str(),
                    rendered.len(),
                    rendered.starts_with(CORRELATION_ID_PREFIX),
                    rendered
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                    current.as_deref(),
                ),
                (expected, 20, true, true, Some(expected)),
            );
        }
        assert_eq!(super::current_operation_id(), None);
    });
}
