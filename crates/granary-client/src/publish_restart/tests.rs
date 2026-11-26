// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::{ARCHIVE_CUTS, PHYSICAL_CUTS, handle_reply};

#[test]
fn fail_is_rejected_at_network_cuts() {
    const CHILD_CUT: &str = "GRANARY_RESTART_REPLY_TEST_CUT";
    if let Ok(cut) = std::env::var(CHILD_CUT) {
        let _ = handle_reply(&cut, "fail\n");
        panic!("observation fail did not terminate the child");
    }
    for cut in [
        "dispatch",
        "probe-delivered",
        "cache-repair",
        "hint-repair",
        "output-write",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env(CHILD_CUT, cut)
            .args([
                "--exact",
                "publish_restart::tests::fail_is_rejected_at_network_cuts",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("rendezvous protocol error") && stderr.contains(cut),
            "{stderr}"
        );
        println!("REFUSED fail at {cut}; child reaped and both pipes closed");
    }
}

#[test]
fn fail_remains_an_io_error_only_at_persistence_cuts() {
    for cut in [
        "load",
        "begin",
        "probe-save",
        "probe-result",
        "attempt-save",
        "answer-save",
        "epoch-save",
        "operation-save",
        "replacement-save",
        "complete-save",
        "abandon-save",
        "archive-rename",
        "archive-sync",
    ]
    .into_iter()
    .chain(PHYSICAL_CUTS.iter().copied())
    .chain(ARCHIVE_CUTS.iter().copied())
    {
        handle_reply(cut, "continue\n").unwrap();
        assert_eq!(
            handle_reply(cut, "fail\n").unwrap_err().to_string(),
            "restart rendezvous injected failure"
        );
    }
}
