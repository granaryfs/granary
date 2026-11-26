// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "the guide fixture uses bare fs calls only inside its owned scratch directory"
)]

use super::*;
use std::os::unix::fs::PermissionsExt as _;

fn invoke_for_test(result: Result<RecoveryOutcome, String>) -> ExitCode {
    invoke_result(
        result.map_err(RecoverRunError::Message),
        LogPaths::Redacted,
        &mut Vec::new(),
    )
}

fn recovery_probe_stderr(probe: &str) -> (bool, String) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", probe, "--nocapture"])
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn construction_workspace_recover_flag_has_checked_local_policy() {
    let mut cases = 0;
    for (value, expected) in [
        ("1024", 1_073_741_824),
        ("2048", 2_147_483_648),
        ("16384", 17_179_869_184),
    ] {
        let mut argv = arguments();
        argv.extend(["--construction-workspace-mib", value].map(OsString::from));
        assert_eq!(
            parse(&argv, &|_| None)
                .unwrap()
                .construction_workspace_bytes,
            expected
        );
        cases += 1;
    }
    for value in ["1023", "16385"] {
        let mut argv = arguments();
        argv.extend(["--construction-workspace-mib", value].map(OsString::from));
        assert_eq!(
            parse(&argv, &|_| None).err().as_deref(),
            Some("--construction-workspace-mib must be between 1024 and 16384 MiB")
        );
        cases += 1;
    }
    for value in ["bad", "18446744073709551616"] {
        let mut argv = arguments();
        argv.extend(["--construction-workspace-mib", value].map(OsString::from));
        assert_eq!(
            parse(&argv, &|_| None).err(),
            Some(format!(
                "--construction-workspace-mib: {value:?} is not a u32"
            ))
        );
        cases += 1;
    }
    assert_eq!(
        parse(&arguments(), &|_| None)
            .unwrap()
            .construction_workspace_bytes,
        1_073_741_824
    );
    assert_eq!(cases, 7);
}

#[test]
fn overlay_cap_recover_flag_is_runtime_only_and_checked() {
    let parse_cap = |value: Option<&str>| {
        let mut argv = arguments();
        if let Some(value) = value {
            argv.extend(["--overlay-cap-bytes", value].map(OsString::from));
        }
        parse(&argv, &|_| None)
    };
    let configured = parse_cap(Some("268435456")).unwrap();
    let config = overlay_config(
        &configured,
        granary_core::retained_submission::Scope {
            authority_base: b"https://fixture.invalid".to_vec(),
            pins: vec![],
            credential_context: b"fixture".to_vec(),
        },
        501,
    );
    let later_default = parse_cap(None).unwrap();
    let minimum = parse_cap(Some("44938292")).unwrap();
    let below = parse_cap(Some("44938291")).err().unwrap();
    assert_eq!(
        (
            configured.overlay_cap_bytes,
            config.cap,
            later_default.overlay_cap_bytes,
            minimum.overlay_cap_bytes,
            below.as_str(),
        ),
        (
            268_435_456,
            268_435_456,
            134_217_728,
            44_938_292,
            "--overlay-cap-bytes must be at least 44938292 bytes",
        )
    );
}

#[test]
fn recovery_cli_and_event_contract_match_observed_completion() {
    let mut cases = 0;
    for outcome in [
        RecoveryOutcome::NothingOwed,
        RecoveryOutcome::JournalFinished { base_seq: 7 },
    ] {
        assert_eq!(
            invoke_for_test(Ok(outcome.clone())),
            ExitCode::SUCCESS,
            "{outcome:?}"
        );
        cases += 1;
    }
    for error in [
        "intent refused: RecoveryJournalBlocked",
        "intent refused: RecoveryConflict",
    ] {
        let text = remedy(error).unwrap_or("");
        assert_eq!(
            (
                invoke_for_test(Err(error.to_owned())),
                text.contains("Preserve this store"),
                text.contains("before retrying"),
                text.contains("Start the writable mount")
            ),
            (ExitCode::FAILURE, true, true, false),
            "{error}: {text:?}"
        );
        cases += 1;
    }
    let fresh_instance = "intent refused: IntentFreshInstanceRequired";
    assert_eq!(
        remedy(fresh_instance),
        Some(
            "Preserve this store; do not delete its overlay area. An earlier run prepared this writer's release and it is unconfirmed, so recovery cannot own the writer again. No in-place repair is available."
        )
    );
    cases += 1;
    let (success, stderr) = recovery_probe_stderr("recover::tests::recovery_outcome_output_probe");
    let lines = stderr.lines().collect::<Vec<_>>();
    assert_eq!((success, lines.len(), lines.first().copied(),
        lines.get(1).copied(), lines.get(2).is_some_and(|line| line.starts_with(
            "Preserve this store. Journal recovery is incomplete; inspect the reported reason before retrying.")),
        lines.get(3).copied(), lines.get(4).is_some_and(|line| line.contains("changes the conflict or head before retrying")),
        lines.get(5).copied(), lines.get(6).copied()),
        (true, 7, Some("JournalFinished: Journal recovery completed and the writer row was released. Start the writable mount with this store."),
            Some("gran recover: intent refused: RecoveryJournalBlocked"), true,
            Some("gran recover: intent refused: RecoveryConflict"), true,
            Some("gran recover: intent refused: IntentFreshInstanceRequired"),
            Some("Preserve this store; do not delete its overlay area. An earlier run prepared this writer's release and it is unconfirmed, so recovery cannot own the writer again. No in-place repair is available.")), "{stderr}");
    cases += 4;
    assert_eq!(cases, 9);
}

#[test]
fn b5_default_refuses_all_paths() {
    let conflict = "intent refused: RecoveryConflict";
    assert_eq!(
        (invoke_for_test(Err(conflict.to_owned())), remedy(conflict)),
        (
            ExitCode::from(1),
            Some(
                "Preserve this store and inspect the reported collision. Recovery requires a supported resolution that changes the conflict or head before retrying."
            )
        )
    );
}

fn inventory_names() -> Vec<Vec<granary_core::manifest::Name>> {
    vec![
        vec![
            granary_core::manifest::Name::new(b"safe".to_vec()).unwrap(),
            granary_core::manifest::Name::new(b"<detached>%\t\r\n\x01\xff".to_vec()).unwrap(),
        ],
        vec![granary_core::manifest::Name::new(b"<detached>".to_vec()).unwrap()],
    ]
}

fn conflict_inventory() -> RecoveryConflictInventory {
    let mut names = inventory_names().into_iter();
    RecoveryConflictInventory::new(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        vec![
            granary_client::RecoveryConflictStage::new(names.next(), 1, 3),
            granary_client::RecoveryConflictStage::new(names.next(), 2, 17),
            granary_client::RecoveryConflictStage::new(None, 3, 29),
        ],
    )
}

#[test]
fn b5_inventory_encoding_is_complete_lossless_and_redacted_by_default() {
    let inventory = conflict_inventory();
    let full = inventory.stdout_bytes(LogPaths::Full).unwrap();
    let redacted = inventory.stdout_bytes(LogPaths::Redacted).unwrap();
    assert_eq!(
        String::from_utf8(full).unwrap(),
        concat!(
            "B5-scope\t0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "B5-stage\tsafe/%3Cdetached%3E%25%09%0D%0A%01%FF\t0000000000000001\t3\n",
            "B5-stage\t%3Cdetached%3E\t0000000000000002\t17\n",
            "B5-stage\t<detached>\t0000000000000003\t29\n",
            "B5-stages\t3\n"
        )
    );
    assert_eq!(
        String::from_utf8(redacted).unwrap(),
        concat!(
            "B5-scope\t0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "B5-stage\t<file>\t0000000000000001\t3\n",
            "B5-stage\t<file>\t0000000000000002\t17\n",
            "B5-stage\t<detached>\t0000000000000003\t29\n",
            "B5-stages\t3\n"
        )
    );
}

#[test]
fn b5_conflict_error_writes_the_exact_inventory_with_the_selected_path_policy() {
    let expected = [
        (
            LogPaths::Redacted,
            concat!(
                "B5-scope\t0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
                "B5-stage\t<file>\t0000000000000001\t3\n",
                "B5-stage\t<file>\t0000000000000002\t17\n",
                "B5-stage\t<detached>\t0000000000000003\t29\n",
                "B5-stages\t3\n"
            ),
        ),
        (
            LogPaths::Full,
            concat!(
                "B5-scope\t0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
                "B5-stage\tsafe/%3Cdetached%3E%25%09%0D%0A%01%FF\t0000000000000001\t3\n",
                "B5-stage\t%3Cdetached%3E\t0000000000000002\t17\n",
                "B5-stage\t<detached>\t0000000000000003\t29\n",
                "B5-stages\t3\n"
            ),
        ),
    ];
    for (paths, expected) in expected {
        let mut stdout = Vec::new();
        let error = RecoverRunError::Command(RecoveryCommandError::Conflict {
            inventory: Some(conflict_inventory()),
        });
        assert_eq!(
            invoke_result(Err(error), paths, &mut stdout),
            ExitCode::FAILURE
        );
        assert_eq!(stdout, expected.as_bytes(), "paths={paths:?}");
    }

    for error in [
        RecoverRunError::Command(RecoveryCommandError::Conflict { inventory: None }),
        RecoverRunError::Message("intent refused: RecoveryConflict".to_owned()),
    ] {
        let mut stdout = Vec::new();
        assert_eq!(
            invoke_result(Err(error), LogPaths::Full, &mut stdout),
            ExitCode::FAILURE
        );
        assert!(stdout.is_empty());
    }
}

#[derive(Default)]
struct InventoryWriter {
    bytes: Vec<u8>,
    maximum: usize,
    fail_after: Option<usize>,
    fail_flush: bool,
    writes: usize,
    flushes: usize,
}

impl std::io::Write for InventoryWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        if self
            .fail_after
            .is_some_and(|limit| self.bytes.len() >= limit)
        {
            return Err(std::io::Error::other("write refused"));
        }
        let allowed = self.maximum.max(1).min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..allowed]);
        Ok(allowed)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(std::io::Error::other("flush refused"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn b5_conflict_reports_incomplete_inventory_output() {
    let (success, stderr) = recovery_probe_stderr("recover::tests::b5_inventory_output_probe");
    assert!(success, "{stderr}");
    let lines: Vec<_> = stderr.lines().collect();
    assert!(
        lines.contains(&concat!(
            "gran recover: RecoveryConflictInventoryOutput: B5 inventory output failed. ",
            "Treat the capture as incomplete and preserve the store."
        )),
        "{stderr}"
    );
    assert!(
        lines.contains(&"gran recover: intent refused: RecoveryConflict"),
        "{stderr}"
    );
}

#[test]
fn b5_inventory_output_probe() {
    let prefix = b"B5-scope\t";
    let mut stdout = InventoryWriter {
        maximum: prefix.len(),
        fail_after: Some(prefix.len()),
        ..InventoryWriter::default()
    };
    let error = RecoverRunError::Command(RecoveryCommandError::Conflict {
        inventory: Some(conflict_inventory()),
    });
    assert_eq!(
        invoke_result(Err(error), LogPaths::Redacted, &mut stdout),
        ExitCode::FAILURE
    );
    assert_eq!(stdout.bytes, prefix);
    assert_eq!((stdout.writes, stdout.flushes), (2, 0));
}

#[test]
fn b5_inventory_writer_completes_short_writes_and_stops_on_errors() {
    let report = b"B5-scope\tabc\nB5-stages\t0\n";
    let mut short = InventoryWriter {
        maximum: 2,
        ..InventoryWriter::default()
    };
    assert!(write_inventory_buffer(&mut short, report).is_ok());
    assert_eq!(short.bytes, report);
    assert!(short.writes > 1);
    assert_eq!(short.flushes, 1);

    let mut write_error = InventoryWriter {
        maximum: 2,
        fail_after: Some(4),
        ..InventoryWriter::default()
    };
    assert!(write_inventory_buffer(&mut write_error, report).is_err());
    assert_eq!(
        (
            write_error.bytes.len(),
            write_error.writes,
            write_error.flushes
        ),
        (4, 3, 0)
    );

    let mut flush_error = InventoryWriter {
        maximum: report.len(),
        fail_flush: true,
        ..InventoryWriter::default()
    };
    assert!(write_inventory_buffer(&mut flush_error, report).is_err());
    assert_eq!(
        (flush_error.bytes, flush_error.writes, flush_error.flushes),
        (report.to_vec(), 1, 1)
    );
}

fn guide_extraction_block() -> String {
    let guide = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/operating-disk-loss-recovery.md"),
    )
    .unwrap();
    let after = guide
        .split_once("Choose an absent `$RECOVERY_DIR`, then run this complete fenced block:")
        .unwrap()
        .1;
    after
        .split_once("```sh\n")
        .unwrap()
        .1
        .lines()
        .take_while(|line| line.trim() != "```")
        .map(|line| line.strip_prefix("   ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn guide_capture_block() -> String {
    let guide = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/operating-disk-loss-recovery.md"),
    )
    .unwrap();
    guide
        .split_once("confirm exit 1 plus `RecoveryConflict` on stderr:")
        .unwrap()
        .1
        .split_once("```sh\n")
        .unwrap()
        .1
        .lines()
        .take_while(|line| line.trim() != "```")
        .map(|line| line.strip_prefix("   ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_guide_block(
    block: &str,
    root: &std::path::Path,
    list: &[u8],
    label: &str,
) -> std::process::Output {
    let list_path = root.join(format!("{label}.tsv"));
    std::fs::write(&list_path, list).unwrap();
    std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(block)
        .env("OLD_STORE", root.join("old"))
        .env("VOLUME", "volume")
        .env("STAGE_LIST", list_path)
        .env("RECOVERY_DIR", root.join(format!("recovered-{label}")))
        .output()
        .unwrap()
}

fn assert_guide_capture_is_private(root: &std::path::Path) {
    let captured = root.join("captured.tsv");
    let capture_script = format!(
        "gran() {{ printf 'inventory'; return 1; }}\n{}",
        guide_capture_block()
    );
    let capture = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(capture_script)
        .env("OLD_STORE", root.join("old"))
        .env("VOLUME", "volume")
        .env("STAGE_LIST", &captured)
        .output()
        .unwrap();
    assert!(!capture.status.success());
    assert_eq!(
        std::fs::metadata(captured).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

fn assert_recovered_payloads_are_private(root: &std::path::Path, payloads: &[(u64, &[u8])]) {
    for (id, payload) in payloads {
        let output = root.join(format!("recovered-valid/{id:016x}"));
        assert_eq!(std::fs::read(&output).unwrap(), *payload);
        assert_eq!(
            std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        std::fs::metadata(root.join("recovered-valid"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn b5_guide_fence_extracts_every_stage_and_rejects_incomplete_reports() {
    let scratch = crate::tests::ScratchDir::new();
    let scope = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let staging = scratch
        .0
        .join("old/overlay")
        .join(scope)
        .join("volume/staging");
    std::fs::create_dir_all(&staging).unwrap();
    let payloads = [
        (1_u64, b"one".as_slice()),
        (2, b"second payload"),
        (3, b"third payload is distinct"),
    ];
    for (id, payload) in payloads {
        let mut staged = vec![0; 160];
        staged.extend_from_slice(payload);
        std::fs::write(staging.join(format!("{id:016x}")), staged).unwrap();
    }
    let mut names = inventory_names().into_iter();
    let valid = RecoveryConflictInventory::new(
        scope.to_owned(),
        vec![
            granary_client::RecoveryConflictStage::new(names.next(), 1, 3),
            granary_client::RecoveryConflictStage::new(names.next(), 2, 14),
            granary_client::RecoveryConflictStage::new(None, 3, 25),
        ],
    )
    .stdout_bytes(LogPaths::Full)
    .unwrap();
    let block = guide_extraction_block();
    assert_guide_capture_is_private(&scratch.0);
    let success = run_guide_block(&block, &scratch.0, &valid, "valid");
    assert!(success.status.success(), "{:?}", success.stderr);
    assert_recovered_payloads_are_private(&scratch.0, &payloads);

    let text = String::from_utf8(valid.clone()).unwrap();
    let lines = text.lines().collect::<Vec<_>>();
    let mutations = [
        ("cut", format!("{}\n", lines[0])),
        (
            "drop-row",
            format!("{}\n{}\n{}\n{}\n", lines[0], lines[1], lines[2], lines[4]),
        ),
        (
            "omit-trailer",
            format!("{}\n{}\n{}\n{}\n", lines[0], lines[1], lines[2], lines[3]),
        ),
        (
            "early-trailer",
            format!("{}\n{}\n{}\n", lines[0], lines[4], lines[1]),
        ),
        ("duplicate-trailer", format!("{text}{}\n", lines[4])),
        ("wrong-count", text.replace("B5-stages\t3", "B5-stages\t2")),
        (
            "wrong-id",
            text.replace("0000000000000002", "0000000000000004"),
        ),
        (
            "wrong-size",
            text.replace("0000000000000002\t14", "0000000000000002\t13"),
        ),
        ("scope-shape", text.replacen('0', "G", 1)),
        (
            "id-shape",
            text.replace("0000000000000002", "000000000000000G"),
        ),
        (
            "size-shape",
            text.replace("0000000000000002\t14", "0000000000000002\t+14"),
        ),
        ("count-shape", text.replace("B5-stages\t3", "B5-stages\t+3")),
    ];
    for (label, mutation) in mutations {
        let result = run_guide_block(&block, &scratch.0, mutation.as_bytes(), label);
        assert!(!result.status.success(), "mutation {label} passed");
    }
    let without_newline = valid.strip_suffix(b"\n").unwrap();
    assert!(
        !run_guide_block(&block, &scratch.0, without_newline, "no-newline")
            .status
            .success()
    );
}

#[test]
fn recovery_outcome_output_probe() {
    assert_eq!(
        invoke_for_test(Ok(RecoveryOutcome::JournalFinished { base_seq: 7 })),
        ExitCode::SUCCESS
    );
    for error in [
        "intent refused: RecoveryJournalBlocked",
        "intent refused: RecoveryConflict",
        "intent refused: IntentFreshInstanceRequired",
    ] {
        assert_eq!(invoke_for_test(Err(error.to_owned())), ExitCode::FAILURE);
    }
}

#[test]
fn recovery_archived_refusal_report_unavailable() {
    let (success, stderr) =
        recovery_probe_stderr("recover::tests::recovery_archived_refusal_report_unavailable_probe");
    assert_eq!(
        (success, stderr.lines().collect::<Vec<_>>()),
        (
            true,
            vec![
                "gran recover: archived publication refusal invalid-reference",
                "gran recover: archived publication refusal report unavailable: archive read failed",
                "JournalFinished: Journal recovery completed and the writer row was released. Start the writable mount with this store.",
            ],
        ),
        "{stderr}"
    );
}

#[test]
fn recovery_archived_refusal_report_unavailable_probe() {
    assert_eq!(
        invoke_for_test(Ok(
            RecoveryOutcome::JournalFinishedWithUnavailableRefusalReport {
                base_seq: 7,
                refusals: vec!["invalid-reference".to_owned()],
                reason: "archive read failed".to_owned(),
            }
        )),
        ExitCode::SUCCESS
    );
}

#[test]
fn archived_unresolved_remedy_never_offers_resend() {
    let mut cases = 0;
    for error in [
        "intent refused: RecoveryArchivedUnresolved",
        "intent refused: RecoveryUnresolved",
        "intent refused: Unknown",
    ] {
        let actual = remedy(error);
        let checks = actual.map(|text| {
            (
                text.contains("--acknowledge-resend"),
                text.contains("<old-store>"),
                text.contains("gran cat"),
                text.contains("<fresh-store>"),
            )
        });
        assert_eq!(
            checks,
            match cases {
                0 => Some((false, true, true, true)),
                1 => Some((true, false, false, false)),
                _ => None,
            },
            "{error}: {actual:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn archived_landing_remedies_preserve_evidence_and_require_a_trusted_chain() {
    let mut cases = 0;
    for (error, integrity) in [
        ("intent refused: RecoveryArchivedLanded", false),
        (
            "RecoveryRemoteIntegrity: archived non-landing contradicted",
            true,
        ),
    ] {
        let actual = remedy(error).unwrap_or("");
        assert_eq!(
            (
                actual.contains("<old-store>"),
                actual.contains("gran cat"),
                actual.contains("<fresh-store>"),
                actual.contains("--acknowledge-resend"),
                actual.contains("administrator")
            ),
            (true, true, true, false, integrity),
            "{error}: {actual:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn archived_recovery_refusals_exit_one_with_their_remedy() {
    let mut cases = 0;
    for error in [
        "intent refused: RecoveryArchivedLanded",
        "RecoveryRemoteIntegrity: archived non-landing contradicted",
        "intent refused: RecoveryArchivedUnresolved",
    ] {
        assert_eq!(
            (
                invoke_for_test(Err(error.to_owned())),
                remedy(error).is_some()
            ),
            (ExitCode::FAILURE, true),
            "{error}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn the_resend_remedy_distinguishes_an_attempt_from_a_probe_without_a_send() {
    let mut cases = 0;
    for name in [
        "RecoveryResendUnanswered",
        "RecoveryResendNoWrite",
        "RecoveryResendPending",
        "RecoveryResendInvalidAnswer",
    ] {
        let actual = remedy(&format!("intent refused: {name}"));
        assert_eq!(
            actual,
            Some(
                "one exact resend was sent; inspect its retained answer and fence before deciding what to do next"
            ),
            "{name}"
        );
        cases += 1;
    }
    assert!(
        remedy("intent refused: RecoveryUnresolved")
            .unwrap()
            .contains("--acknowledge-resend")
    );
    assert_eq!(remedy("intent refused: RecoveryResendCandidate"), None);
    assert_eq!(cases, 4);
}

fn arguments() -> Vec<OsString> {
    [
        "store",
        "v",
        "--writer",
        "01010101010101010101010101010101",
        "--key-seed",
        "seed",
        "--endpoint",
        "https://authority",
        "--credential-context",
        "operator",
        "--pin",
        "sha256/q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

#[test]
fn recovery_flags_keep_consent_explicit_and_share_credential_validation() {
    let args = arguments();
    let parsed = parse(&args, &|_| None).unwrap();
    assert_eq!(
        (
            parsed.writer,
            parsed.acknowledge_takeover,
            parsed.pins.len()
        ),
        ([1; 16], None, 1)
    );
    let mut acknowledged = args.clone();
    acknowledged
        .extend(["--acknowledge-takeover", "02020202020202020202020202020202"].map(OsString::from));
    assert_eq!(
        parse(&acknowledged, &|_| None)
            .unwrap()
            .acknowledge_takeover,
        Some([2; 16])
    );
    for (flags, refusal) in [
        (
            vec!["--writer", "bad"],
            "--writer must contain exactly 32 lowercase hexadecimal digits",
        ),
        (
            vec!["--client-cert", "certificate"],
            "--client-cert and --client-key must be supplied together",
        ),
        (vec!["--pin", ""], "--pin: names no pins"),
        (vec!["--direct-s3"], "unknown recover option"),
        (
            vec!["--recover", "01010101010101010101010101010101"],
            "unknown recover option",
        ),
    ] {
        let mut malformed = args.clone();
        malformed.extend(flags.into_iter().map(OsString::from));
        let error = parse(&malformed, &|_| None).err().unwrap();
        assert!(
            error.starts_with(refusal),
            "expected {refusal:?}, got {error:?}"
        );
    }
}

#[test]
fn resend_consent_names_a_publication_and_rejects_malformed_ids() {
    let mut cases = 0;
    for (id, expected) in [
        ("02020202020202020202020202020202", Some([2; 16])),
        ("bad", None),
        ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None),
    ] {
        let mut args = arguments();
        args.extend(["--acknowledge-resend", id].map(OsString::from));
        let result = parse(&args, &|_| None).map(|args| args.acknowledge_resend);
        assert_eq!(
            result,
            expected.map_or_else(
                || Err(
                    "--acknowledge-resend must contain exactly 32 lowercase hexadecimal digits"
                        .to_owned()
                ),
                |id| Ok(Some(id))
            )
        );
        cases += 1;
    }
    assert_eq!(
        (
            parse(&arguments(), &|_| None).unwrap().acknowledge_resend,
            cases
        ),
        (None, 3)
    );
}

#[test]
fn recovery_pin_environment_is_a_fallback_and_missing_fields_refuse() {
    let args = arguments();
    assert!(parse(&args, &|_| Some("bad ambient pin".into())).is_ok());
    let without_pin = &args[..args.len() - 2];
    let pin = "sha256/q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";
    assert_eq!(
        parse(without_pin, &|_| Some(pin.into()))
            .unwrap()
            .pins
            .len(),
        1
    );
    assert_eq!(
        parse(without_pin, &|_| None).err().unwrap(),
        "recovery requires --pin sha256/... (or GRANARY_TLS_PINS)"
    );
    for (flag, refusal) in [
        ("--writer", "--writer is required"),
        ("--key-seed", "--key-seed is required"),
        ("--endpoint", "--endpoint is required"),
        (
            "--credential-context",
            "--credential-context is required for recovery",
        ),
    ] {
        let mut malformed = args.clone();
        let index = malformed.iter().position(|value| value == flag).unwrap();
        malformed.drain(index..index + 2);
        assert_eq!(parse(&malformed, &|_| None).err().unwrap(), refusal);
    }
    assert!(crate::usage_text().contains(HELP));
}

#[test]
fn an_unacknowledged_run_on_a_missing_store_creates_nothing() {
    let scratch = crate::tests::ScratchDir::new();
    let euid = process_credentials().euid;
    let mut outcomes = Vec::new();
    for (label, acknowledge) in [
        ("none", None),
        ("other", Some([2; 16])),
        ("writer", Some([1; 16])),
    ] {
        let mut args = parse(&arguments(), &|_| None).unwrap();
        args.store_dir = scratch.0.join(label).join("store");
        args.acknowledge_takeover = acknowledge;
        let opened = local(&args, euid).unwrap().is_some();
        outcomes.push((
            label,
            opened,
            std::fs::symlink_metadata(scratch.0.join(label)).is_ok(),
        ));
    }
    assert_eq!(
        outcomes,
        [
            ("none", false, false),
            ("other", false, false),
            ("writer", true, true)
        ],
        "(acknowledgement, store opened, directory created)"
    );
}

#[test]
fn the_overlay_io_shares_the_root_a_leading_parent_store_resolves() {
    use granary_client::OverlayIo;
    // The overlay io refuses a symlinked ancestor, as the temporary
    // directory has on macOS, so the store sits in the workspace's target
    // directory, reached from this crate's directory through `..`.
    let name = crate::tests::ScratchDir::new();
    let scratch =
        crate::tests::ScratchDir(PathBuf::from("../../target").join(name.0.file_name().unwrap()));
    let mut args = parse(&arguments(), &|_| None).unwrap();
    args.store_dir = scratch.0.join("store");
    args.acknowledge_takeover = Some(args.writer);
    let (store, mut io) = local(&args, process_credentials().euid).unwrap().unwrap();
    let root = store.publication_root().to_owned();
    let probe = io.length(&root.join("absent"));
    assert!(
        matches!(probe, Ok(None)),
        "the io must be rooted at the store's root {}: {probe:?}",
        root.display()
    );
}
