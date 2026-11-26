// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::disallowed_methods,
        reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
    )
)]

use std::process::Command;

#[test]
fn offline_support_usage_errors_exit_two_with_closed_reasons() {
    let cases = [
        (
            vec!["support-bundle", "/mnt", "--output", "/unused", "--offline"],
            "live target cannot be combined with --offline",
        ),
        (
            vec![
                "support-bundle",
                "--output",
                "/first",
                "--output",
                "/second",
            ],
            "--output repeated option",
        ),
        (
            vec![
                "support-bundle",
                "--output",
                "/unused",
                "--offline",
                "--cache-dir",
                "none",
                "--overlay-dir",
                "none",
                "--mountpoint",
                "unknown",
            ],
            "--store-dir is required with --offline",
        ),
        (
            vec![
                "support-bundle",
                "--output",
                "/unused",
                "--offline",
                "--cache-dir",
                "/cache",
                "--overlay-dir",
                "none",
                "--store-dir",
                "none",
                "--mountpoint",
                "unknown",
            ],
            "unknown mountpoint cannot be mixed with a source path",
        ),
    ];
    let mut count = 0;
    for (arguments, reason) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_gran"))
            .args(arguments)
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            (output.status.code(), stderr.as_str()),
            (
                Some(2),
                format!("gran: support bundle: {reason}\n").as_str()
            ),
            "reason={reason}, status={:?}, stderr={stderr}",
            output.status.code()
        );
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn support_dispatch_precedes_logging_and_never_echoes_its_operands() {
    let secret = "/SUPPORT-OPERAND-MUST-NOT-APPEAR/missing/log";
    let output = Command::new(env!("CARGO_BIN_EXE_gran"))
        .args([
            "--log-filter",
            "private_operand=trace",
            "support-bundle",
            "-h",
        ])
        .env("GRANARY_LOG_FILE", secret)
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        (
            output.status.code(),
            stderr.as_str(),
            stderr.contains(secret)
        ),
        (Some(2), "gran: support bundle: unknown option\n", false)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn offline_support_cli_publishes_or_refuses_source_nesting() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "the lint row this licenses bans `std::process::id` as ambient input to hashed or signed values; here it only separates this test binary's scratch name from concurrent processes and reaches neither bundle bytes nor an assertion"
    )]
    let scratch = (0..128)
        .find_map(|_| {
            let path = temporary.join(format!(
                "granary-support-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).ok().map(|()| path)
        })
        .expect("unique support CLI scratch");
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output_parent = scratch.join("output");
    let source = scratch.join("source");
    let mountpoint = scratch.join("mountpoint");
    for directory in [&output_parent, &source, &mountpoint] {
        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let valid = output_parent.join("valid.gsb");
    let output = Command::new(env!("CARGO_BIN_EXE_gran"))
        .args([
            "support-bundle",
            "--output",
            valid.to_str().unwrap(),
            "--offline",
            "--cache-dir",
            "none",
            "--overlay-dir",
            "none",
            "--store-dir",
            "none",
            "--mountpoint",
            mountpoint.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        (output.status.code(), output.stderr),
        (Some(0), Vec::<u8>::new())
    );
    let bytes = std::fs::read(&valid).unwrap();
    assert!(granary_core::support::BundleArchive::decode(&bytes).is_ok());

    let refused = source.join("refused.gsb");
    let output = Command::new(env!("CARGO_BIN_EXE_gran"))
        .args([
            "support-bundle",
            "--output",
            refused.to_str().unwrap(),
            "--offline",
            "--cache-dir",
            source.to_str().unwrap(),
            "--overlay-dir",
            "none",
            "--store-dir",
            "none",
            "--mountpoint",
            mountpoint.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        (output.status.code(), stderr.as_str(), refused.exists()),
        (
            Some(1),
            "gran: support bundle: output inside source tree\n",
            false
        )
    );
    std::fs::remove_dir_all(scratch).unwrap();
}
