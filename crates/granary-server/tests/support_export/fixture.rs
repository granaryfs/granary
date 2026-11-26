// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use granary_core::support::{SupportConfiguration, SupportSnapshot};
use std::{
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

pub(crate) fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub(crate) fn incarnation_text(value: granary_core::debug_grant::Incarnation) -> String {
    use std::fmt::Write as _;
    let mut text = String::from("incarnation:");
    for byte in value.as_bytes() {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}

pub(crate) fn vector(name: &str) -> Vec<u8> {
    include_str!("../../../granary-core/tests/vectors/support_v1.tsv")
        .lines()
        .find(|s| s.split('\t').next() == Some(name))
        .unwrap()
        .split('\t')
        .nth(1)
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect()
}

pub(crate) fn pair(support: &Path) -> (SupportSnapshot, SupportConfiguration) {
    let snapshot = SupportSnapshot::decode(&vector("snapshot")).unwrap();
    let mut config = SupportConfiguration::decode(&vector("configuration")).unwrap();
    config.volumes = snapshot.volumes.keys().map(|v| (v.clone(), 1)).collect();
    write_pair(support, &snapshot, &config);
    (snapshot, config)
}

pub(crate) fn write_pair(
    support: &Path,
    snapshot: &SupportSnapshot,
    config: &SupportConfiguration,
) {
    for (name, bytes) in [
        ("SUPPORT-SNAPSHOT", snapshot.encode().unwrap()),
        ("SUPPORT-CONFIGURATION", config.encode().unwrap()),
    ] {
        let path = support.join(name);
        std::fs::write(&path, bytes).unwrap();
        chmod(&path, 0o600);
    }
}

pub(crate) fn command(support: &Path, state: &Path, out: &Path, ack: bool) -> Command {
    // Cargo builds this executable in the integration test's own invocation.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_granary-server"));
    cmd.env_clear()
        .args(["support-export", "--support-dir"])
        .arg(support)
        .arg("--state-dir")
        .arg(state)
        .arg("--out")
        .arg(out);
    if ack {
        cmd.arg("--accept-unsupported-filesystem");
    }
    cmd
}

pub(crate) fn diagnostic(output: &Output) -> String {
    format!(
        "status={} stdout={:?} stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub(crate) fn outcome(output: &Output, code: i32, text: &str, exists: bool, out: &Path) {
    assert_eq!(
        (
            output.status.code(),
            output.stdout.as_slice(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            out.exists()
        ),
        (Some(code), &[][..], text.to_owned(), exists),
        "{}",
        diagnostic(output)
    );
}
