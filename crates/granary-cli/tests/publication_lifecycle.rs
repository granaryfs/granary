// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Successive compiled-binary invocations against persisted retained fixtures.

#![expect(
    clippy::unwrap_used,
    reason = "generated integration fixtures and compiled-binary assertions"
)]

use granary_client::Store;
use granary_core::{
    retained_submission::{self, Submission},
    root::VolumeName,
};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};
struct Fixture {
    path: PathBuf,
    store: PathBuf,
    record: Submission,
    uid: u32,
}
impl Fixture {
    #[expect(
        clippy::disallowed_methods,
        reason = "create a private fixture directory under a runtime-resolved physical root; no operator key or certificate is read"
    )]
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // A world-writable temp directory would fail the seed's ancestor
        // custody walk, so the fixture lives under the workspace's own target.
        let base = {
            let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
            cwd.ancestors()
                .find(|root| {
                    root.join("Cargo.lock").is_file() && root.join("crates/granary-client").is_dir()
                })
                .unwrap_or_else(|| panic!("physical workspace root"))
                .join("target")
        };
        let path = loop {
            let p = base.join(format!(
                "publication-cli-fixture-{}",
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => break p,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("{e}"),
            }
        };
        let uid = std::fs::symlink_metadata(&path).unwrap().uid();
        #[expect(
            clippy::disallowed_methods,
            reason = "read a committed generated retained-submission test vector, never a real key"
        )]
        let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../granary-core/tests/vectors/retained-submission/{name}.bin"
        )))
        .unwrap();
        let mut record = retained_submission::decode(&bytes).unwrap();
        record.scope.authority_base = b"https://test.invalid".to_vec();
        record.scope.pins = vec![[1; 32]];
        record.scope.credential_context = b"writer".to_vec();
        record.generation = 1;
        let store = path.join("store");
        let mut local = Store::open(&store).unwrap();
        local.publications(uid).unwrap().begin(&record).unwrap();
        drop(local);
        Self {
            path,
            store,
            record,
            uid,
        }
    }
    fn run(&self, extra: &[&str]) -> Output {
        let pin = granary_net::config::render_tls_pin(&[1; 32]);
        Command::new(env!("CARGO_BIN_EXE_gran"))
            .env_clear()
            .arg("publish")
            .arg(&self.store)
            .args([
                "-",
                self.record.volume.as_str(),
                "--endpoint",
                "https://test.invalid",
                "--pin",
                &pin,
                "--credential-context",
                "writer",
                "--key-seed",
                "/missing-test-seed",
                "--json",
            ])
            .args(extra)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    #[expect(
        clippy::disallowed_methods,
        reason = "remove only this test-owned fixture directory"
    )]
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}

fn json(output: Output, code: i32) -> String {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with('{'));
    assert!(text.ends_with("}\n"));
    assert!(text.contains(&format!("\"exit_code\":{code}")));
    text
}

#[test]
fn binary_first_run_key_generation_keeps_json_stdout_clean() {
    let fixture = Fixture::new("ready");
    let seed = fixture.path.join("generated-seed");
    let output = fixture.run(&["--key-seed", seed.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("generated publishing key:"), "{stderr}");
    let stdout = json(output, 1);
    assert!(stdout.contains("--client-cert"));
    assert!(std::fs::symlink_metadata(&seed).is_ok());
}

#[test]
fn binary_first_run_key_generation_with_closed_stdout_does_not_panic() {
    use std::io::Write as _;
    use std::process::Stdio;
    let fixture = Fixture::new("ready");
    let seed = fixture.path.join("generated-seed");
    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    // Close the pipe's reader before releasing the shell's stdin gate. This
    // deterministically gives stdout EPIPE without a vacant fd being reused
    // by a Store or seed open. Only generated fixture keys are involved.
    let mut shell = Command::new("sh")
        .env_clear()
        .args(["-s", "--", env!("CARGO_BIN_EXE_gran")])
        .arg(&fixture.store)
        .arg(fixture.record.volume.as_str())
        .arg(&pin)
        .arg(&seed)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(shell.stdout.take());
    shell.stdin.take().unwrap().write_all(
        b"exec \"$1\" publish \"$2\" - \"$3\" --endpoint https://test.invalid --pin \"$4\" --credential-context writer --key-seed \"$5\"\n"
    ).unwrap();
    let output = shell.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(
        stderr.contains("key announcement could not be written"),
        "{stderr}"
    );
    assert!(std::fs::symlink_metadata(&seed).is_ok());
}
#[test]
fn binary_abandon_is_local_pin_change_preserves_candidates_and_archive_refuses_rerun() {
    for phase in ["ready", "capacity", "unresolved", "catalogue"] {
        let fixture = Fixture::new(phase);
        let id = hex(&fixture.record.publication_id);
        let pin = granary_net::config::render_tls_pin(&[2; 32]);
        let text = json(
            fixture.run(&[
                "--abandon",
                &id,
                "--acknowledge-may-land",
                "--pin",
                &pin,
                "--client-cert",
                "/missing-test-cert",
                "--client-key",
                "/missing-test-key",
            ]),
            0,
        );
        assert!(text.contains("\"outcome\":\"abandoned\""));
        assert!(text.contains("\"pin_difference\":{\"retained\":["));
        let mut store = Store::open(&fixture.store).unwrap();
        let archives = store
            .publications(fixture.uid)
            .unwrap()
            .list_archives(&fixture.record.volume)
            .unwrap();
        assert_eq!(
            archives.first().unwrap().submission.candidates,
            fixture.record.candidates
        );
        drop(store);
        let text = json(fixture.run(&[]), 4);
        assert!(text.contains("\"retention\":\"archive\""));
        assert!(text.contains("--new"));
        assert!(json(fixture.run(&["--recover", &id]), 4).contains("\"outcome\":\"refused\""));
        assert!(
            json(
                fixture.run(&["--abandon", &id, "--acknowledge-may-land", "--pin", &pin]),
                0
            )
            .contains("\"outcome\":\"abandoned\"")
        );
    }
}
#[test]
fn binary_new_and_direct_selections_cannot_bypass_incomplete_state_or_read_source() {
    let fixture = Fixture::new("unresolved");
    assert!(json(fixture.run(&["--new"]), 4).contains("incomplete live"));
    assert!(
        json(fixture.run(&["--publish-mode", "legacy-server"]), 4).contains("authority recovery")
    );
    let volume = VolumeName::new(fixture.record.volume.as_str().into()).unwrap();
    let mut store = Store::open(&fixture.store).unwrap();
    assert_eq!(
        store
            .publications(fixture.uid)
            .unwrap()
            .load(&fixture.record.scope, &volume)
            .unwrap()
            .unwrap()
            .candidates,
        fixture.record.candidates
    );
}
