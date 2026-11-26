// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;

#[test]
fn exact_selection_and_authority_options() {
    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    let scope = "11".repeat(32);
    let writer = "22".repeat(16);
    let incarnation = "33".repeat(32);
    let public = format!("ed25519:{}", "44".repeat(32));
    let flags = [
        "--store-dir",
        "/store",
        "--scope",
        &scope,
        "--volume",
        "vol",
        "--writer",
        &writer,
        "--journal-incarnation",
        &incarnation,
        "--endpoint",
        "https://authority.example",
        "--pin",
        &pin,
        "--credential-context",
        "writer",
        "--publisher-key",
        &public,
    ]
    .map(OsString::from);
    assert!(parse(&flags, &|_| None).is_some());
    for index in (0..flags.len()).step_by(2) {
        let mut missing = flags.to_vec();
        missing.drain(index..index + 2);
        assert!(parse(&missing, &|_| None).is_none(), "{index}");
    }
    for extra in [
        vec!["--plan"],
        vec!["--acknowledge-may-land"],
        vec!["--force"],
        vec!["--writer", &writer],
        vec!["--endpoint", "https://other.example"],
        vec!["--credential-context", "other"],
        vec!["--client-cert", "/cert"],
        vec!["--pin", "garbage"],
        vec!["--publisher-key", "garbage"],
    ] {
        let mut bad = flags.to_vec();
        bad.extend(extra.into_iter().map(OsString::from));
        assert!(parse(&bad, &|_| None).is_none());
    }
}

#[test]
fn reconcile_row_refusals_preserve_tsv_and_report_events() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "overlay_discard::reconcile::tests::reconcile_row_output_probe",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stderr, concat!(
        "gran overlay reconcile: OverlayArchiveUnresolved\n",
        "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"overlay.reconcile_refused\",\"reason\":\"OverlayArchiveUnresolved\"}\n",
        "gran overlay reconcile: OverlayArchiveRemoteIntegrity\n",
        "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"overlay.reconcile_refused\",\"reason\":\"OverlayArchiveRemoteIntegrity\"}\n",
    ).as_bytes());
}

#[test]
fn reconcile_row_output_probe() {
    for (status, reason, exit) in [
        ("not-landed", None, ExitCode::SUCCESS),
        (
            "unresolved",
            Some(OverlayRefusal::Unresolved),
            ExitCode::FAILURE,
        ),
        (
            "integrity",
            Some(OverlayRefusal::RemoteIntegrity),
            ExitCode::FAILURE,
        ),
    ] {
        let scope = "11".repeat(32);
        let writer = "22".repeat(16);
        let incarnation = "33".repeat(32);
        let publication = "44".repeat(16);
        let row = format!(
            "overlay-reconcile-v1\t{scope}\tvol\t{writer}\t{incarnation}\t{publication}\t{status}\t-\t-\t-\n"
        );
        let mut output = Vec::new();
        assert_eq!(
            write_rows([(&row, reason)], &mut output, &std::io::stderr),
            Ok(exit)
        );
        assert_eq!(output, row.as_bytes());
    }
}
