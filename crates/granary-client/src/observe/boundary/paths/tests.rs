// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::observe::boundary::{ClientEvent, OperatorDiagnostic, closed_subscriber_with_paths};
use crate::observe::tests::{Capture, Fixed};
use crate::{CorrelationId, FailureClass, LocalConflictStatus, LogFormat, OperationKind};
use std::os::unix::ffi::OsStringExt as _;
use tracing_subscriber::EnvFilter;

fn text(value: Scalar) -> String {
    let Scalar::Text(value) = value else {
        panic!("expected a path scalar")
    };
    value
}

#[test]
fn path_and_name_classes_debug_bounds_and_lossless_escaping() {
    let source = Path::new("synthetic-directory/synthetic-basename");
    for class in [
        "<file>",
        "<directory>",
        "<cache-root>",
        "<store-root>",
        "<mountpoint>",
        "<log-file>",
        "<unknown>",
    ] {
        let path = LogPath { source, class };
        assert!(
            format!("{path:?}") == class,
            "wrapper Debug disclosed bytes"
        );
        assert!(
            format!("{path:#?}") == class,
            "alternate Debug disclosed bytes"
        );
        assert!(
            text(path.project(LogPaths::Redacted)) == class,
            "default wrapper disclosed full path"
        );
        assert!(
            text(path.project(LogPaths::Full)) == source.to_str().unwrap(),
            "full wrapper lost supplied spelling"
        );
    }
    let name = LogName::entry(OsStr::new("synthetic-basename"));
    assert_eq!(format!("{name:?}"), "<name>");
    assert_eq!(
        text(PathSlot::Name("name", name).project(LogPaths::Redacted)),
        "<name>"
    );
    assert_eq!(
        text(PathSlot::Name("name", name).project(LogPaths::Full)),
        "synthetic-basename"
    );
    let hostile = std::ffi::OsString::from_vec(b"relative/\"\\\n\r\t\x1b\x00\xff".to_vec());
    assert!(
        text(LogPath::file(Path::new(&hostile)).project(LogPaths::Full))
            == "relative/\\\"\\\\\\x0a\\x0d\\x09\\x1b\\x00\\xff",
        "path escaping changed supplied bytes"
    );
    for size in [4095, 4096, 4097] {
        let input = "q".repeat(size);
        let path = LogPath::file(Path::new(&input));
        let rendered = text(path.project(LogPaths::Full));
        let name = text(
            PathSlot::Name("name", LogName::entry(OsStr::new(&input))).project(LogPaths::Full),
        );
        if size <= 4096 {
            assert!(rendered == input, "in-bound path was omitted");
            assert!(name == input, "in-bound name was omitted");
        } else {
            assert!(
                rendered == "<file>:path_too_large",
                "oversize path must omit identifying prefix"
            );
            assert!(
                name == "<name>:path_too_large",
                "oversize name must omit identifying prefix"
            );
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one text/JSON and redacted/full/fresh-session matrix asserts the exact local conflict tuple, eligible output and identical independently redacted history"
)]
fn full_paths_are_scoped_before_telemetry_and_never_reused_for_bundle_history() {
    let path = Path::new("synthetic-directory/synthetic-basename");
    let name = LogName::entry(OsStr::new("synthetic-entry"));
    for format in [LogFormat::Text, LogFormat::Json] {
        let mut bundles = Vec::new();
        for policy in [LogPaths::Redacted, LogPaths::Full, LogPaths::Redacted] {
            let output = Capture::default();
            let history = BundleHistory::default();
            let subscriber = closed_subscriber_with_paths(
                format,
                EnvFilter::new("trace"),
                output.clone(),
                policy,
                history.clone(),
            );
            tracing::subscriber::with_default(subscriber, || {
                let id = CorrelationId::draw(&mut Fixed(&[42; 8])).unwrap();
                let span = crate::operation_span(OperationKind::Commit, &id);
                let _entered = span.enter();
                OperatorDiagnostic::store_an_object_leaf_is_not_a_regular_file()
                    .emit_paths(&[PathSlot::Path("path", LogPath::file(path))]);
                OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_digest_file_name()
                    .emit_paths(&[PathSlot::Name("name", name)]);
                let status = LocalConflictStatus::new(path, id).unwrap();
                assert!(
                    status.errno() == libc::ESTALE && status.path() == path,
                    "full/default conflict lost exact local tuple"
                );
                status.emit_telemetry();
            });
            let lines = output.lines();
            assert!(lines.len() == 4, "eligible producer/event premise failed");
            assert!(
                !lines.iter().any(|line| line.contains("log.record_refused")),
                "eligible path schema refused"
            );
            let joined = lines.join("");
            if policy == LogPaths::Full {
                assert!(
                    joined.contains("synthetic-directory/synthetic-basename")
                        && joined.contains("synthetic-entry"),
                    "full opt-in did not reach eligible path/name slots"
                );
            } else {
                assert!(
                    !joined.contains("synthetic-directory")
                        && !joined.contains("synthetic-basename")
                        && !joined.contains("synthetic-entry"),
                    "default telemetry retained a path or basename"
                );
                assert!(
                    joined.contains("<file>") && joined.contains("<name>"),
                    "default classes missing"
                );
            }
            let snapshot = history.snapshot();
            assert!(
                snapshot.records().len() == 4,
                "facade did not feed independent history"
            );
            let records: Vec<_> = snapshot
                .records()
                .iter()
                .map(|record| record.0.clone())
                .collect();
            assert!(
                records
                    .iter()
                    .all(|record| record.contains("cor-2a2a2a2a2a2a2a2a")),
                "bundle operation join was lost"
            );
            assert!(
                !records.iter().any(|record| record.contains("synthetic-")),
                "bundle reused log policy or raw input"
            );
            bundles.push(records);
        }
        assert!(
            bundles.windows(2).all(|pair| pair[0] == pair[1]),
            "bundle policy inherited full-path authorization"
        );
    }
    let output = Capture::default();
    let history = BundleHistory::default();
    tracing::subscriber::with_default(
        closed_subscriber_with_paths(
            LogFormat::Json,
            EnvFilter::new("off"),
            output.clone(),
            LogPaths::Full,
            history.clone(),
        ),
        || {
            OperatorDiagnostic::store_an_object_leaf_is_not_a_regular_file()
                .emit_paths(&[PathSlot::Path("path", LogPath::file(path))]);
        },
    );
    assert!(output.lines().is_empty(), "OFF control failed");
    assert!(
        history.snapshot().records().len() == 1,
        "bundle history depended on logging enablement"
    );
}

#[test]
fn bundle_history_enforces_record_and_byte_caps_fifo_and_loss() {
    let history = BundleHistory::default();
    for index in 0..1025 {
        history.record(ClientEvent::overlay_sweep(index, 7).project().1);
    }
    let snapshot = history.snapshot();
    assert!(
        snapshot.records().len() == 1024 && snapshot.lost() == 1,
        "bundle record cap or loss failed"
    );
    assert!(
        snapshot
            .records()
            .first()
            .unwrap()
            .0
            .contains("\"files\":1,"),
        "bundle did not evict oldest whole record"
    );
    assert!(
        snapshot
            .records()
            .last()
            .unwrap()
            .0
            .contains("\"files\":1024,"),
        "bundle FIFO changed"
    );
    assert_eq!(
        snapshot.encoded_bytes(),
        snapshot
            .records()
            .iter()
            .map(|record| record.as_bytes().len())
            .sum::<usize>()
    );
    let history = BundleHistory::default();
    for index in 0..33 {
        let record = BundleRecord(format!("{index:02}{}", "x".repeat(32766)));
        history.record(record);
    }
    let snapshot = history.snapshot();
    assert!(
        snapshot.encoded_bytes() == 1_048_576
            && snapshot.records().len() == 32
            && snapshot.lost() == 1,
        "bundle encoded-byte cap or loss failed"
    );
    assert!(
        snapshot.records().first().unwrap().0.starts_with("01"),
        "byte-cap eviction was not FIFO"
    );
    // An over-cap projection cannot disturb admitted whole records.
    history.record(BundleRecord("x".repeat(1_048_577)));
    assert!(
        history.snapshot().lost() == 2 && history.snapshot().encoded_bytes() == 1_048_576,
        "oversize bundle input changed admitted bytes"
    );
    assert_eq!(format!("{history:?}"), "<bundle-history>");
    assert_eq!(format!("{snapshot:?}"), "<bundle-snapshot>");
}

#[test]
fn projected_record_bound_refuses_whole_record_before_encoding() {
    let event = ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io);
    let (meta, mut fields) = event.fields();
    for format in [LogFormat::Text, LogFormat::Json] {
        fields[0] = Scalar::text("");
        let empty_size = super::super::encoded_size(meta, &fields, &[], format);
        for size in [32767, 32768, 32769] {
            fields[0] = Scalar::Text("x".repeat(size - empty_size));
            let before = super::super::ENCODER_ALLOCATIONS.with(std::cell::Cell::get);
            let record = super::super::encode(meta, &fields, &[], format);
            if size <= 32768 {
                assert!(
                    record.len() == size && !record.contains("record_too_large"),
                    "in-bound record refused"
                );
            } else {
                assert!(
                    super::super::ENCODER_ALLOCATIONS.with(std::cell::Cell::get) == before,
                    "oversize projection reached encoder allocation"
                );
                assert!(
                    record.contains("record_too_large")
                        && record.len() < 128
                        && !record.contains("xxx"),
                    "record overflow retained a partial identifying prefix"
                );
            }
        }
    }
    let path = std::ffi::OsString::from_vec(vec![0xff; 4096]);
    let slots = [
        PathSlot::Path("from", LogPath::file(Path::new(&path))),
        PathSlot::Path("to", LogPath::file(Path::new(&path))),
    ];
    let output = Capture::default();
    tracing::subscriber::with_default(
        closed_subscriber_with_paths(
            LogFormat::Json,
            EnvFilter::new("trace"),
            output.clone(),
            LogPaths::Full,
            BundleHistory::default(),
        ),
        || {
            OperatorDiagnostic::wire_snapshot_publish_the_temp_file_could_not_be(FailureClass::Io)
                .emit_paths(&slots);
        },
    );
    let lines = output.lines();
    assert!(
        lines.len() == 1 && lines[0].contains("record_too_large") && !lines[0].contains("xff"),
        "hostile path pair bypassed whole-record bound"
    );
}

#[test]
fn independent_history_retains_nested_operation_joins_and_approved_updates() {
    let output = Capture::default();
    let history = BundleHistory::default();
    let subscriber = closed_subscriber_with_paths(
        LogFormat::Json,
        EnvFilter::new("trace"),
        output.clone(),
        LogPaths::Redacted,
        history.clone(),
    );
    tracing::subscriber::with_default(subscriber, || {
        let parent = CorrelationId::draw(&mut Fixed(&[42; 8])).unwrap();
        let child = CorrelationId::draw(&mut Fixed(&[43; 8])).unwrap();
        let parent = crate::operation_span(OperationKind::Commit, &parent);
        let _parent = parent.enter();
        {
            let child = crate::operation_span(OperationKind::Retry, &child);
            let _child = child.enter();
            parent.record("kind", "rebase");
            ClientEvent::overlay_sweep(7, 11).emit();
        }
        ClientEvent::overlay_sweep(13, 17).emit();
    });
    let lines = output.lines();
    let snapshot = history.snapshot();
    assert!(
        lines.len() == 2 && snapshot.records().len() == 2,
        "nested operation fixture was suppressed"
    );
    for (line, record) in lines.iter().zip(snapshot.records()) {
        assert!(
            line.as_bytes() == record.as_bytes().strip_suffix(b"\n").unwrap(),
            "bundle operation context differed from approved telemetry context"
        );
    }
    assert!(
        lines[0].contains("cor-2b2b2b2b2b2b2b2b") && lines[0].contains("\"kind\":\"rebase\""),
        "nested join or approved update was lost"
    );
    assert!(
        !lines[1].contains("cor-2b2b2b2b2b2b2b2b") && lines[1].contains("cor-2a2a2a2a2a2a2a2a"),
        "closed child contaminated later history"
    );
}

#[test]
fn bundle_try_snapshot_checks_bounds_before_copy_and_never_waits() {
    let history = BundleHistory::default();
    history.record(ClientEvent::overlay_sweep(17, 23).project().1);
    let result = history.try_snapshot();
    assert!(
        result.is_ok(),
        "valid bounded history was refused: {:?}",
        result.err()
    );
    let snapshot = result.unwrap();
    assert!(
        (
            snapshot.records().len(),
            snapshot.encoded_bytes(),
            snapshot.lost()
        ) == (1, snapshot.records()[0].as_bytes().len(), 0),
        "valid history snapshot lost its metadata"
    );
    let held = history.0.lock().unwrap();
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let worker_history = history.clone();
    let worker = std::thread::spawn(move || {
        sent.send(worker_history.try_snapshot().err().map(|e| e.to_string()))
            .unwrap();
    });
    let refusal = received.recv_timeout(std::time::Duration::from_millis(200));
    drop(held);
    worker.join().unwrap();
    assert!(
        (
            refusal.is_ok(),
            refusal.as_ref().ok().and_then(|r| r.as_deref())
        ) == (true, Some("unavailable")),
        "busy history waited for its producer: {refusal:?}"
    );
    let record = |length: usize| {
        let prefix = "{\"event\":\"op.conflict\",\"path\":\"";
        BundleRecord(format!(
            "{prefix}{}\"}}\n",
            "x".repeat(length - prefix.len() - 3)
        ))
    };
    let cases = [
        (1024, 1, true),
        (1025, 1, false),
        (1, 32768, true),
        (1, 32769, false),
        (32, 32768, true),
        (33, 32768, false),
        (1, 0, false),
    ];
    let mut refused = 0;
    for (count, length, accepted) in cases {
        let mut state = history.0.lock().unwrap();
        state.records = (0..count)
            .map(|_| {
                if length == 0 {
                    BundleRecord(String::new())
                } else if length == 1 {
                    ClientEvent::overlay_sweep(17, 23).project().1
                } else {
                    record(length)
                }
            })
            .collect();
        state.bytes = state.records.iter().map(|r| r.as_bytes().len()).sum();
        state.lost = 37;
        drop(state);
        SNAPSHOT_COPIES.set(0);
        let result = history.try_snapshot();
        assert!(
            (result.is_ok(), SNAPSHOT_COPIES.get() != 0) == (accepted, accepted),
            "history bound or pre-copy order mismatch: count={count}, length={length}, got=({}, {})",
            result.is_ok(),
            SNAPSHOT_COPIES.get()
        );
        if accepted {
            assert_eq!(result.unwrap().lost(), 37);
        } else {
            refused += 1;
            let expected = if count > 1024 {
                "support count bound"
            } else {
                "support size bound"
            };
            assert_eq!(result.unwrap_err().to_string(), expected);
        }
    }
    assert_eq!(refused, 4, "history refusal cases must execute");
}

#[test]
fn bundle_try_snapshot_refuses_inconsistent_accounting_before_copy() {
    let history = BundleHistory::default();
    history.record(ClientEvent::overlay_sweep(17, 23).project().1);
    assert!(history.try_snapshot().is_ok(), "valid accounting premise");
    history.0.lock().unwrap().bytes += 1;
    SNAPSHOT_COPIES.set(0);
    let refusal = history.try_snapshot().err().map(|e| e.to_string());
    assert!(
        (refusal.as_deref(), SNAPSHOT_COPIES.get()) == (Some("support size bound"), 0),
        "inconsistent accounting was copied: refusal={refusal:?}, copies={}",
        SNAPSHOT_COPIES.get()
    );
}

#[test]
fn bundle_try_snapshot_refuses_poison_without_recovering_or_copying() {
    let history = BundleHistory::default();
    history.record(ClientEvent::overlay_sweep(17, 23).project().1);
    assert!(history.try_snapshot().is_ok(), "valid history premise");
    let _ = std::panic::catch_unwind(|| {
        let _held = history.0.lock().unwrap();
        panic!("poison fixture");
    });
    SNAPSHOT_COPIES.set(0);
    let refusal = history.try_snapshot().err().map(|e| e.to_string());
    assert!(
        (refusal.as_deref(), SNAPSHOT_COPIES.get()) == (Some("unavailable"), 0),
        "poisoned history was recovered/copied: refusal={refusal:?}, copies={}",
        SNAPSHOT_COPIES.get()
    );
}
