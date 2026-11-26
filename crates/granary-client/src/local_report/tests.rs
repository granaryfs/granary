// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn workspace_reports_escape_paths_and_fall_back_to_the_boundary() {
    let mut cases = 0;
    for (path, suffix) in [
        (PathBuf::from("name\n\""), " path=\"name\\x0a\\\"\""),
        (PathBuf::from("a".repeat(4097)), ""),
    ] {
        let report = LocalReport::workspace_exhausted(
            WorkspaceSite::Boundary(7),
            Some(&path),
            1_073_741_825,
            1_073_741_824,
        )
        .render();
        assert_eq!(
            std::str::from_utf8(report.as_bytes()).unwrap(),
            format!(
                "gran mount: warning: SyncWorkspaceExhausted: needed=1073741825 limit=1073741824 boundary=7{suffix}\n"
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

struct Fixed;
impl SecureRandom for Fixed {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), EntropyUnavailable> {
        bytes.fill(0x73);
        Ok(())
    }
}
fn volume() -> VolumeName {
    VolumeName::new("synthetic-volume".into()).unwrap()
}
fn text(report: &LocalReport) -> String {
    String::from_utf8(report.render().0).unwrap()
}

#[test]
fn commit_stalled_reports_the_operator_action_and_cadence() {
    assert_eq!(
        text(&LocalReport::commit_stalled(&volume())),
        "gran mount: warning: COMMIT STALLED: a commit of volume=synthetic-volume has been refused eight times and is now retried every 10 minutes; fsync fails until it lands or the mount is restarted\n"
    );
}

#[test]
fn commit_stopped_reports_the_volume_and_terminal_effect() {
    assert_eq!(
        text(&LocalReport::commit_stopped(
            &volume(),
            crate::CommitStopCause::Fenced
        )),
        "gran mount: error: COMMIT STOPPED (fenced): new writes are refused; pending changes are kept in the store, but nothing more is committed while this mount runs; volume=synthetic-volume\n"
    );
    assert_eq!(
        text(&LocalReport::commit_stopped(
            &volume(),
            crate::CommitStopCause::Closed
        )),
        "gran mount: error: COMMIT STOPPED (closed): the served view is closed or its session has ended; pending changes are kept in the store, but nothing more is committed while this mount runs; volume=synthetic-volume\n"
    );
}

#[test]
fn typed_reports_keep_required_operator_information_and_class_only_debug() {
    let root = GrainId::of(b"synthetic wire root");
    let cached = GrainId::of(b"synthetic cached root");
    let evidence = EquivocationNotice::new(volume(), 42, root, cached);
    let reports = [
        LocalReport::pinned(volume(), 42, root, cached),
        LocalReport::history(),
        LocalReport::equivocation(evidence.clone()),
        LocalReport::cache_unverified(volume(), 42),
        LocalReport::cache_degraded(),
        LocalReport::signature_unchecked(),
        LocalReport::degraded(volume(), 42, Age::Seconds(123)),
        LocalReport::degraded(volume(), 42, Age::Unknown),
    ];
    let output: Vec<_> = reports.iter().map(text).collect();
    assert_eq!(
        output[0],
        format!(
            "gran mount: pinned volume=synthetic-volume seq=42 root={root} manifest-root={cached}\n"
        )
    );
    assert_eq!(output[1], "gran mount: history: not checked\n");
    assert_eq!(
        output[2],
        format!("gran mount: EQUIVOCATION: {}\n", evidence.render_finding())
    );
    assert!(
        output[3].contains("volume=synthetic-volume, seq=42") && output[3].contains("evicting")
    );
    assert!(output[4].contains("No floor is kept under --manifest-root"));
    assert!(output[5].contains("SIGNATURE is NOT checked"));
    assert!(output[6].contains("volume=synthetic-volume seq=42 age=123s"));
    assert!(output[7].contains("age=unknown"));
    assert_eq!(format!("{evidence:?}"), "<equivocation>");
    for report in reports {
        assert_eq!(format!("{report:?}"), "<local-report>");
        assert_eq!(format!("{:?}", report.render()), "<local-record>");
    }
}

#[test]
fn close_warning_projects_only_closed_class_and_optional_numeric_errno() {
    let cases = [
        (
            CacheError::Io {
                context: "synthetic-secret-context".into(),
                source: std::io::Error::from_raw_os_error(libc::ENOSPC),
            },
            Some(libc::ENOSPC),
            "io",
        ),
        (
            CacheError::Io {
                context: "synthetic-secret-context".into(),
                source: std::io::Error::other("synthetic-secret-provider-chain"),
            },
            None,
            "io",
        ),
        (
            CacheError::Incompatible {
                detail: "synthetic-secret-config".into(),
            },
            None,
            "refused",
        ),
    ];
    for (error, errno, class) in cases {
        for stage in [
            CloseStage::RefusedMount,
            CloseStage::Shutdown,
            CloseStage::Drop,
        ] {
            let report = LocalReport::cache_close_warning(stage, &error);
            let output = text(&report);
            assert!(
                !output.contains("synthetic-secret"),
                "close warning retained error text"
            );
            assert!(
                output.contains(&format!("class={class}"))
                    && output.contains("crash guard may remain")
            );
            match errno {
                Some(n) => assert!(output.contains(&format!("errno={n}"))),
                None => assert!(!output.contains("errno=")),
            }
        }
    }
}

#[test]
fn local_delivery_survives_logging_off_and_refuses_recipient_replacement() {
    let identity = "local_report::tests::local_delivery_survives_logging_off_and_refuses_recipient_replacement";
    if std::env::var("GRANARY_LOCAL_REPORT_TEST_CHILD")
        .ok()
        .as_deref()
        != Some(identity)
    {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", identity, "--nocapture"])
            .env("GRANARY_LOCAL_REPORT_TEST_CHILD", identity)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated local report control failed"
        );
        return;
    }

    let capture = Arc::new(Capture::default());
    install_local_reports(capture.clone()).unwrap();
    assert!(install_local_reports(Arc::new(Capture::default())).is_err());
    let subscriber = crate::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("off"),
        CaptureLog::default(),
    );
    tracing::subscriber::with_default(subscriber, || {
        LocalReport::pinned(volume(), 8, GrainId::of(b"wire"), GrainId::of(b"manifest")).emit();
        LocalReport::history().emit();
        LocalReport::cache_close_warning(
            CloseStage::Shutdown,
            &CacheError::Io {
                context: "synthetic-secret".into(),
                source: std::io::Error::from_raw_os_error(libc::EACCES),
            },
        )
        .emit();
    });
    let records = capture.0.lock().unwrap();
    assert_eq!(records.len(), 3);
    assert!(records[0].starts_with(b"gran mount: pinned volume=synthetic-volume"));
    assert_eq!(records[1], b"gran mount: history: not checked\n");
    assert!(
        !records[2]
            .windows(b"synthetic-secret".len())
            .any(|part| part == b"synthetic-secret")
    );
}
#[derive(Clone, Default)]
struct CaptureLog(Arc<Mutex<Vec<u8>>>);
impl crate::RecordWriter for CaptureLog {
    fn write_record(&self, record: &crate::LogRecord) {
        self.0.lock().unwrap().extend_from_slice(record.as_bytes());
    }
}

#[test]
fn conflict_status_retains_exact_path_errno_and_operation_without_a_recipient() {
    use std::os::unix::ffi::OsStrExt as _;
    let path = Path::new(std::ffi::OsStr::from_bytes(
        b"synthetic-conflict/quoted\"\n\x1b\xff",
    ));
    let operation = CorrelationId::draw(&mut Fixed).unwrap();
    let status = LocalConflictStatus::new(path, operation).unwrap();
    assert_eq!(status.path(), path);
    assert_eq!(status.errno(), libc::ESTALE, "local conflict errno changed");
    let report = LocalReport::conflict(status.clone());
    report.emit();
    let local = text(&report);
    assert_eq!(local.lines().count(), 1);
    assert!(local.contains("synthetic-conflict/quoted\\\"\\x0a\\x1b\\xff"));
    assert!(local.contains(&format!("ESTALE op={operation}")));
    assert_eq!(format!("{status:?}"), "<local-conflict>");
    assert!(
        LocalConflictStatus::new(Path::new(&"x".repeat(4097)), operation).is_err(),
        "oversize status must refuse before copy"
    );
    assert!(LocalConflictStatus::new(Path::new(&"x".repeat(4096)), operation).is_ok());
    let logs = CaptureLog::default();
    let subscriber = crate::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        logs.clone(),
    );
    tracing::subscriber::with_default(subscriber, || status.emit_telemetry());
    let rendered = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(rendered.contains("op.failed") && rendered.contains("op.conflict"));
    assert!(rendered.contains(&operation.to_string()) && rendered.contains("<file>"));
    assert!(!rendered.contains("synthetic-conflict"));
    let (projected_logs, bundles) = status.redacted_projections();
    for record in projected_logs {
        let text = std::str::from_utf8(record.as_bytes()).unwrap();
        assert!(text.contains(&operation.to_string()));
        assert!(!text.contains("synthetic-conflict"));
    }
    for record in &bundles {
        let text = std::str::from_utf8(record.as_bytes()).unwrap();
        assert!(text.contains(&operation.to_string()));
        assert!(!text.contains("synthetic-conflict"));
    }
    let bundle = &bundles[1];
    assert!(
        std::str::from_utf8(bundle.as_bytes())
            .unwrap()
            .contains("<file>")
    );
    assert!(
        !std::str::from_utf8(bundle.as_bytes())
            .unwrap()
            .contains("synthetic-conflict")
    );
}
