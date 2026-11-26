// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The shipping dispatcher consumes activated configuration and redacts values.

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test owns a seed under a scratch Store's txn directory and verifies refusal precedes its sweep"
)]
fn recovery_dispatch_uses_checked_flags_and_redacts_signing_paths() {
    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    let scratch =
        std::env::temp_dir().join(format!("gran-recover-dispatch-{}", std::process::id()));
    let store = scratch.join("store");
    drop(granary_client::Store::open(&store).unwrap());
    let seed = store.join("txn/PRIVATE_SEED_SENTINEL");
    std::fs::write(&seed, [0x55; 32]).unwrap();
    let mut cases = 0;
    for (writer, code, refusal) in [
        (
            "01010101010101010101010101010101",
            1,
            "RecoveryManagedPaths: signing material and store must not nest",
        ),
        (
            "bad",
            2,
            "--writer must contain exactly 32 lowercase hexadecimal digits",
        ),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_gran"))
            .env_clear()
            .arg("recover")
            .arg(&store)
            .args(["vol", "--writer", writer, "--key-seed"])
            .arg(&seed)
            .args([
                "--endpoint",
                "https://test.invalid",
                "--pin",
                &pin,
                "--credential-context",
                "operator",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            (
                output.status.code(),
                stdout.is_empty(),
                stderr.contains(refusal),
                stderr.contains("PRIVATE_SEED_SENTINEL"),
                std::fs::read(&seed).map_err(|error| error.kind())
            ),
            (Some(code), true, true, false, Ok(vec![0x55; 32])),
            "{stdout}{stderr}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn operational_publish_refusal_captures_stdout_and_stderr_without_values() {
    let sentinel = "PRIVATE_SENTINEL";
    for flag in ["--PRIVATE_SENTINEL", "--PRIVATE_SENTINEL=value"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_gran"))
            .env_clear()
            .args([
                "publish", "store", "source", "vol", flag, sentinel, "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.starts_with('{'));
        assert!(stdout.ends_with("}\n"));
        assert_eq!(stdout.lines().count(), 1);
        assert!(stdout.contains("unknown publish option"));
        for text in [stdout, String::from_utf8(output.stderr).unwrap()] {
            assert!(!text.contains(sentinel));
        }
    }
}
#[test]
fn activated_configuration_and_json_value_position_use_shipping_parser() {
    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    let base = [
        "publish",
        "store",
        "source",
        "vol",
        "--endpoint",
        "https://test.invalid",
        "--pin",
        &pin,
        "--key-seed",
        "seed",
    ];
    for (extra, expected_json, diagnostic) in [
        (
            vec!["--client-cert", "cert", "--json"],
            true,
            "must be supplied together",
        ),
        (vec!["--client-key", "--json"], false, "needs a value"),
        (
            vec![
                "--credential-context",
                "writer",
                "--publisher-key",
                "invalid",
                "--json",
            ],
            true,
            "--publisher-key",
        ),
        (
            vec!["--abandon", "07070707070707070707070707070707", "--json"],
            true,
            "requires --acknowledge-may-land",
        ),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_gran"))
            .env_clear()
            .args(base)
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stdout.starts_with('{'), expected_json);
        assert!(
            format!("{stdout}{stderr}").contains(diagnostic),
            "{stdout}{stderr}"
        );
        assert!(!format!("{stdout}{stderr}").contains("unknown publish option"));
    }
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "read the shipping shell parser and write only test-owned success-line fixtures"
)]
fn legacy_script_seq_parser_accepts_seam_marker_and_refuses_ambiguous_logs() {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let script = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/m10-propagate.sh"),
    )
    .unwrap();
    let function = script
        .split("parse_stack_seq() {\n")
        .nth(1)
        .unwrap()
        .split_once("\n}\n")
        .unwrap()
        .0;
    // Run the actual function, with the source log supplied on stdin. No
    // stack, credential generation, network or environment discovery runs.
    for (lines, expected) in [
        (
            "generated publishing key: public-fixture\n  seed fixture\n  pub fixture\npublished vol seq 41 epoch 1 route=server-seam\n",
            Some("41\n"),
        ),
        ("published vol seq 42 epoch 2\n", Some("42\n")),
        ("published vol seq 41 epoch 1 route=authority\n", None),
        (
            "published vol seq 41 epoch 1 route=server-seam extra\n",
            None,
        ),
        ("published other seq 41 epoch 1 route=server-seam\n", None),
        (
            "published vol seq 41 epoch 1\npublished vol seq 42 epoch 2 route=server-seam\n",
            None,
        ),
    ] {
        let program = format!(
            "set -eu\ndie() {{ printf '%s\\n' \"$*\" >&2; exit 1; }}\nparse_stack_seq() {{\n{function}\n}}\nlog=$(mktemp)\ntrap 'rm -f \"$log\"' EXIT\ncat > \"$log\"\nparse_stack_seq \"$log\" vol\n"
        );
        let mut child = Command::new("bash")
            .env_clear()
            .args(["-c", &program])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(lines.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.success(),
            expected.is_some(),
            "{lines}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(expected) = expected {
            assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
        }
    }
}
