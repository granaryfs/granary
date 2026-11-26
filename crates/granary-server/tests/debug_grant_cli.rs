// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shipped binary dispatch, before any serving configuration is read.

#[path = "process/output.rs"]
mod output;
mod process;
use output::CommandExt as _;

use std::process::Command;

#[test]
fn debug_grant_cli_is_dispatched_before_runtime_and_configuration() {
    for args in [
        vec!["debug-grant"],
        vec!["debug-grant", "unknown"],
        vec!["debug-grant", "issue"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env_clear()
            .args(args)
            .guarded_output()
            .unwrap();
        assert_eq!(output.status.code(), Some(64));
        let err = String::from_utf8(output.stderr).unwrap();
        assert!(err.contains("usage: granary-server debug-grant"));
        assert!(!err.contains("GRANARY_LISTEN"));
        assert!(output.stdout.is_empty());
    }
}
