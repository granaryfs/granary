// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The shipped binary consults authority configuration before ordinary
//! serving setup, then requires production boot identity. Library parser tests
//! alone cannot see whether the binary asks the parser at all. Each child clears
//! inherited environment. Partial configurations must name the fault; complete
//! configurations reach `NotLinux` on macOS or the authority's client-CA read
//! on Linux, without altering state. Ordinary startup does not read that CA.
//! Run default and `crash-points` builds to exercise both compositions.

#![cfg(unix)]

mod process;

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use granary_server::EXIT_STARTUP_FAILED;
use granary_server::config::authority::{
    AUTHORITY_SINGLE_PROCESS, ENV_AUTHORITY, ENV_CLIENT_CA, ENV_ENROLLMENT_DIR, ENV_STATE_DIR,
    ENV_VOLUMES,
};

/// How long a refusing binary may take to exit.
const EXIT_BOUND: Duration = Duration::from_secs(20);

/// Run the shipped binary under exactly `vars`, bounded by
/// [`EXIT_BOUND`]: a binary that does not refuse would serve forever, and
/// an unbounded wait would report that as a hang rather than a failure.
fn refusal(vars: &[(&str, &str)]) -> (Option<i32>, String) {
    let child = Command::new(env!("CARGO_BIN_EXE_granary-server"))
        .env_clear()
        .envs(vars.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawning the binary: {error}"));
    let mut child = process::ChildGuard(child);
    let mut stderr = child
        .0
        .stderr
        .take()
        .unwrap_or_else(|| panic!("binary stderr pipe missing"));
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = child
        .wait_within(EXIT_BOUND)
        .unwrap_or_else(|error| panic!("waiting for the binary: {error}"))
        .unwrap_or_else(|| panic!("the binary did not refuse within {EXIT_BOUND:?}"));
    let bytes = reader
        .join()
        .unwrap_or_else(|_| panic!("stderr reader panicked"))
        .unwrap_or_else(|error| panic!("reading binary stderr: {error}"));
    (status.code(), String::from_utf8_lossy(&bytes).into_owned())
}

#[test]
fn the_predicate_alone_refuses_naming_what_it_lacks() {
    let (code, stderr) = refusal(&[(ENV_AUTHORITY, AUTHORITY_SINGLE_PROCESS)]);
    assert_eq!(code, Some(EXIT_STARTUP_FAILED), "{stderr}");
    for name in [
        ENV_STATE_DIR,
        ENV_ENROLLMENT_DIR,
        ENV_CLIENT_CA,
        ENV_VOLUMES,
    ] {
        assert!(
            stderr.contains(&format!("{name} (unset)")),
            "the refusal must name {name} as unset: {stderr}"
        );
    }
}

#[test]
fn a_fixed_name_without_the_predicate_refuses_naming_it() {
    let (code, stderr) = refusal(&[(ENV_STATE_DIR, "/var/lib/granary/authority")]);
    assert_eq!(code, Some(EXIT_STARTUP_FAILED), "{stderr}");
    assert!(
        stderr.contains(ENV_STATE_DIR) && stderr.contains(ENV_AUTHORITY),
        "the refusal must name the stray variable and the missing predicate: {stderr}"
    );
}

/// Supply the ordinary startup variables so a skipped authority reaches TLS
/// loading. A directory cannot supply PEM bytes: the refusal names the authority's
/// client CA or the ordinary server's certificate. Neither path needs a socket.
const SERVING: [(&str, &str); 4] = [
    ("GRANARY_LISTEN", "127.0.0.1:0"),
    ("GRANARY_TLS_CERT", "/"),
    ("GRANARY_TLS_KEY", "/"),
    ("GRANARY_STORE", "memory:"),
];

fn assert_authority_startup_refusal(vars: &[(&str, &str)]) {
    let vars: Vec<_> = vars.iter().chain(SERVING.iter()).copied().collect();
    let (code, stderr) = refusal(&vars);
    let authority_only = if cfg!(target_os = "linux") {
        stderr.contains(&format!("{ENV_CLIENT_CA}="))
    } else {
        stderr.contains("this platform has no boot id it reads")
    };
    assert_eq!(
        (code, authority_only),
        (Some(EXIT_STARTUP_FAILED), true),
        "complete configuration must reach authority-only startup: {stderr}"
    );
}

#[test]
fn a_complete_authority_configuration_reaches_boot_identity() {
    assert_authority_startup_refusal(&[
        (ENV_AUTHORITY, AUTHORITY_SINGLE_PROCESS),
        (ENV_STATE_DIR, "/var/lib/granary/authority"),
        (ENV_ENROLLMENT_DIR, "/etc/granary/enrollment"),
        (ENV_CLIENT_CA, "/"),
        (ENV_VOLUMES, "alpha"),
        (
            "GRANARY_AUTHORITY_VOLUME_ALPHA_PUBLISHER_KEYS",
            "ed25519:0101010101010101010101010101010101010101010101010101010101010101",
        ),
    ]);
}

fn authority_wire_refusal(wire: &[(&str, &str)]) {
    let mut vars = vec![
        (ENV_AUTHORITY, AUTHORITY_SINGLE_PROCESS),
        (ENV_STATE_DIR, "/var/lib/granary/authority"),
        (ENV_ENROLLMENT_DIR, "/etc/granary/enrollment"),
        (ENV_CLIENT_CA, "/etc/granary/client-ca.pem"),
        (ENV_VOLUMES, "alpha"),
        (
            "GRANARY_AUTHORITY_VOLUME_ALPHA_PUBLISHER_KEYS",
            "ed25519:0101010101010101010101010101010101010101010101010101010101010101",
        ),
    ];
    vars.extend_from_slice(wire);
    let (code, stderr) = refusal(&vars);
    assert_eq!(code, Some(EXIT_STARTUP_FAILED), "{stderr}");
    assert!(stderr.contains("startup failed:"), "{stderr}");
    assert!(
        stderr.contains("wire snapshot is not available in authority mode"),
        "{stderr}"
    );
    for (name, _) in wire {
        assert!(stderr.contains(name), "missing {name}: {stderr}");
    }
}

#[test]
fn any_wire_variable_in_authority_mode_refuses_before_boot_identity() {
    for name in [
        "GRANARY_WIRE_SNAPSHOT",
        "GRANARY_WIRE_RUN_ID",
        "GRANARY_WIRE_ROLE",
    ] {
        authority_wire_refusal(&[(name, "")]);
    }
}

#[test]
fn a_complete_wire_trio_in_authority_mode_refuses_before_boot_identity() {
    authority_wire_refusal(&[
        ("GRANARY_WIRE_SNAPSHOT", "/unused/snapshot.json"),
        ("GRANARY_WIRE_RUN_ID", "test-run"),
        ("GRANARY_WIRE_ROLE", "server"),
    ]);
}

#[test]
fn authority_configuration_preserves_existing_state_bytes() {
    use std::os::unix::fs::PermissionsExt as _;
    // Authority startup refuses before state access or listener binding.
    let dir = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|e| panic!("temp: {e}"))
        .join(format!("granary-authority-config-{}", test_pid()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("scratch: {e}"));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("mode: {e}"));
    let marker = dir.join("MARKER");
    std::fs::write(&marker, b"unchanged marker sentinel").unwrap_or_else(|e| panic!("write: {e}"));
    let log = dir.join("alpha.log");
    std::fs::write(&log, b"unchanged log sentinel").unwrap_or_else(|e| panic!("write: {e}"));
    let path = dir.to_str().unwrap_or_else(|| panic!("test path"));
    let vars = [
        (ENV_AUTHORITY, AUTHORITY_SINGLE_PROCESS),
        (ENV_STATE_DIR, path),
        (ENV_ENROLLMENT_DIR, path),
        (ENV_CLIENT_CA, "/"),
        (ENV_VOLUMES, "alpha"),
        (
            "GRANARY_AUTHORITY_VOLUME_ALPHA_PUBLISHER_KEYS",
            "ed25519:0101010101010101010101010101010101010101010101010101010101010101",
        ),
    ];
    assert_authority_startup_refusal(&vars);
    assert_eq!(
        std::fs::read(&marker).unwrap_or_else(|e| panic!("read: {e}")),
        b"unchanged marker sentinel"
    );
    assert_eq!(
        std::fs::read(&log).unwrap_or_else(|e| panic!("read: {e}")),
        b"unchanged log sentinel"
    );
    assert_eq!(
        std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("list: {e}"))
            .count(),
        2
    );
    std::fs::remove_dir_all(dir).unwrap_or_else(|e| panic!("cleanup: {e}"));
}

#[expect(
    clippy::disallowed_methods,
    reason = "test scratch name only, not ambient input to logic"
)]
fn test_pid() -> u32 {
    std::process::id()
}
